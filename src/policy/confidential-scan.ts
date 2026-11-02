// Confidential-name scanning for model-facing text (MR-F; F4). PURE, deterministic, and
// linear in the input: no regular expression runs over model- or host-controlled text.
//
// 1. CANONICALIZE (one left-to-right pass, O(n)). Every original character maps to canonical
//    characters, with its span in the original text recorded:
//      - a separator RUN — any mix of `/`, `\` and escaped separators `/`/`\`
//        preceded by any number of backslashes (every JSON-escape depth) — becomes one `/`;
//      - a base character and the combining marks after it (at most MAX_CLUSTER code units)
//        are put in Unicode NFC, so composed and decomposed spellings (`Ä`, `A` + U+0308)
//        compare equal;
//      - every BMP code unit is case-folded by one fixed table: singleton NFC, then simple
//        upper case, then simple lower case, each step only where it yields one code unit.
//        Two names Windows treats as the same (NTFS compares the simple upper case of each
//        UTF-16 unit) always fold to the same text; a few more pairs fold together too (e.g.
//        KELVIN SIGN and `k`), which can only add redaction. Supplementary-plane characters
//        are compared as they are (NTFS does not fold them either);
//    in ESCAPE mode a backslash run followed by a JSON escape letter (`n r t b f " '`) or by
//    `uXXXX` (other than an escaped separator) becomes one boundary character instead, so a
//    JSON `\n` before a name does not glue the name to the previous word. Both modes are
//    scanned, because a backslash may be a Windows separator or a JSON escape.
//    Withheld paths go through the same canonicalizer, so both sides are normalized alike.
// 2. MATCH (Aho–Corasick over the canonical text). Patterns are the withheld paths in the
//    same canonical form, and withheld file hashes. Overlapping patterns can make the number
//    of candidate matches grow with (text length × patterns), so every scan has an explicit
//    budget of MAX_SCAN_CANDIDATES: past it the scan stops and reports the whole text as one
//    `limit` match — redaction withholds the whole text and the invariant rejects it (fail
//    closed). A scan is therefore O(n + MAX_SCAN_CANDIDATES) whatever the withheld set.
// 3. BOUNDARIES (O(1) per candidate; the facts are precomputed per scan in O(n)). A path
//    matches only as a whole name: the characters around it must not continue a file name.
//    Name characters are ASCII letters, digits and `- ~`, BMP Unicode letters, digits and
//    combining marks, and `. _`; a `.` or `_` counts as continuing the name only when a name
//    character follows it (so `db.env.ts`, `db.env_old`, `x.env`, `myconfig/…`, `äx.env` do
//    not match, while sentence periods, Markdown `_…_`/`**…**`, quotes, brackets, `=`, `#`,
//    `,`, `:` and `;` delimit). A `/` before or after the path is a boundary (segment-aligned
//    prefix/suffix). Hashes match anywhere.
// Redaction and the invariant both use `scan`; the invariant additionally checks a bounded
// number of JSON-unescaped views (each scanned with the same bounds).

export type ScanMode = "separator" | "escape";

interface Canonical {
  text: string;
  /** original start index of each canonical character */
  start: Int32Array;
  /** original end index (exclusive) of each canonical character */
  end: Int32Array;
}

const BACKSLASH = 0x5c;
const SLASH = 0x2f;

function isEscapedSeparator(t: string, at: number): boolean {
  // `u002f` / `u005c`, case-insensitive hex
  if (at + 5 > t.length || (t.charCodeAt(at) | 0x20) !== 0x75) return false;
  const h = t.slice(at + 1, at + 5).toLowerCase();
  return h === "002f" || h === "005c";
}

function isHex4(t: string, at: number): boolean {
  if (at + 4 > t.length) return false;
  for (let k = at; k < at + 4; k++) {
    const c = t.charCodeAt(k) | 0x20;
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return true;
}

const ESCAPE_LETTERS = new Set(["n", "r", "t", "b", "f", '"', "'"]);

// --- character tables (built once, lazily; 65,536 entries each) -------------------------

/** Longest base-plus-combining-marks cluster normalized as one unit (bounds the NFC work). */
export const MAX_CLUSTER = 32;
const NAME = 1;
const MARK = 2;
let CLS: Uint8Array | null = null;
let FOLD: Uint16Array | null = null;

function tables(): { cls: Uint8Array; fold: Uint16Array } {
  if (CLS && FOLD) return { cls: CLS, fold: FOLD };
  const cls = new Uint8Array(0x10000);
  const fold = new Uint16Array(0x10000);
  const nameRe = /^[\p{L}\p{N}\p{M}]$/u;
  const markRe = /^\p{M}$/u;
  const one = (s: string, otherwise: string) => (s.length === 1 ? s : otherwise);
  for (let c = 0; c < 0x10000; c++) {
    fold[c] = c;
    if (c < 0x80) {
      // ASCII: letters, digits, `-` and `~` are name characters; letters fold to lower case
      if ((c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2d || c === 0x7e) cls[c] = NAME;
      if (c >= 0x41 && c <= 0x5a) {
        cls[c] = NAME;
        fold[c] = c + 0x20;
      }
      continue;
    }
    if (c >= 0xd800 && c <= 0xdfff) continue; // surrogates: supplementary characters are kept as they are
    const ch = String.fromCharCode(c);
    if (markRe.test(ch)) cls[c] = NAME | MARK;
    else if (nameRe.test(ch)) cls[c] = NAME;
    const nfc = one(ch.normalize("NFC"), ch); // e.g. ANGSTROM SIGN -> Å
    const upper = one(nfc.toUpperCase(), nfc);
    fold[c] = one(upper.toLowerCase(), upper).charCodeAt(0);
  }
  CLS = cls;
  FOLD = fold;
  return { cls, fold };
}

export function canonicalize(t: string, mode: ScanMode): Canonical {
  const { cls, fold } = tables();
  const n = t.length;
  const out: number[] = [];
  let start = new Int32Array(n + 1);
  let end = new Int32Array(n + 1);
  let m = 0;
  const emit = (code: number, s: number, e: number) => {
    if (code === SLASH && m > 0 && out[m - 1] === SLASH && end[m - 1] === s) {
      end[m - 1] = e; // extend the separator run
      return;
    }
    if (m === start.length) {
      // NFC can lengthen a cluster (composition exclusions decompose), by a bounded factor
      const grow = (a: Int32Array) => {
        const b = new Int32Array(a.length * 2);
        b.set(a);
        return b;
      };
      start = grow(start);
      end = grow(end);
    }
    out.push(code);
    start[m] = s;
    end[m] = e;
    m++;
  };
  let i = 0;
  while (i < n) {
    const c = t.charCodeAt(i);
    if (c === SLASH) {
      emit(SLASH, i, i + 1);
      i++;
      continue;
    }
    if (c === BACKSLASH) {
      let j = i;
      while (j < n && t.charCodeAt(j) === BACKSLASH) j++;
      if (j < n && isEscapedSeparator(t, j)) {
        emit(SLASH, i, j + 5);
        i = j + 5;
        continue;
      }
      if (mode === "escape" && j < n) {
        const x = t[j]!;
        if (ESCAPE_LETTERS.has(x)) {
          emit(0x20, i, j + 1);
          i = j + 1;
          continue;
        }
        if (x === "u" && isHex4(t, j + 1)) {
          emit(0x20, i, j + 5);
          i = j + 5;
          continue;
        }
      }
      emit(SLASH, i, j);
      i = j;
      continue;
    }
    let j = i + 1;
    while (j < n && j - i < MAX_CLUSTER && (cls[t.charCodeAt(j)]! & MARK) !== 0) j++;
    if (j === i + 1) {
      emit(fold[c]!, i, i + 1);
    } else {
      // a base character and its combining marks: compose, then fold each unit of the
      // result; every unit maps to the whole cluster's span
      const nfc = t.slice(i, j).normalize("NFC");
      for (let k = 0; k < nfc.length; k++) emit(fold[nfc.charCodeAt(k)]!, i, j);
    }
    i = j;
  }
  return { text: codesToString(out), start: start.subarray(0, m), end: end.subarray(0, m) };
}

/** String.fromCharCode over large arrays without exceeding the argument limit. */
function codesToString(codes: number[]): string {
  let s = "";
  for (let k = 0; k < codes.length; k += 8192) s += String.fromCharCode(...codes.slice(k, k + 8192));
  return s;
}

/** Canonical form of a withheld path: separators normalized, NFC, case-folded, `./` dropped. */
export function canonicalPath(p: string): string {
  const c = canonicalize(p.trim(), "separator").text;
  return c.replace(/^(?:\.\/)+/, "").replace(/^\/+|\/+$/g, "");
}

// --- Aho–Corasick -------------------------------------------------------------------

interface Pattern {
  text: string;
  kind: "path" | "hash";
}

interface Automaton {
  next: Map<number, number>[];
  fail: Int32Array;
  /** pattern ids ending at this node (own), and the dictionary-suffix link */
  out: number[][];
  dict: Int32Array;
  patterns: Pattern[];
}

function build(patterns: Pattern[]): Automaton {
  const next: Map<number, number>[] = [new Map()];
  const out: number[][] = [[]];
  patterns.forEach((p, id) => {
    let s = 0;
    for (let k = 0; k < p.text.length; k++) {
      const c = p.text.charCodeAt(k);
      let t = next[s]!.get(c);
      if (t === undefined) {
        t = next.length;
        next.push(new Map());
        out.push([]);
        next[s]!.set(c, t);
      }
      s = t;
    }
    out[s]!.push(id);
  });
  const fail = new Int32Array(next.length);
  const dict = new Int32Array(next.length).fill(-1);
  const queue: number[] = [];
  for (const t of next[0]!.values()) queue.push(t);
  for (let q = 0; q < queue.length; q++) {
    const s = queue[q]!;
    for (const [c, t] of next[s]!) {
      let f = fail[s]!;
      while (f !== 0 && !next[f]!.has(c)) f = fail[f]!;
      const g = next[f]!.get(c);
      fail[t] = g !== undefined && g !== t ? g : 0;
      dict[t] = out[fail[t]!]!.length > 0 ? fail[t]! : dict[fail[t]!]!;
      queue.push(t);
    }
  }
  return { next, fail, out, dict, patterns };
}

// --- boundaries -----------------------------------------------------------------------

const DOT = 0x2e;
const UNDERSCORE = 0x5f;

/**
 * Per-position boundary facts for a canonical text, in two O(n) passes, so each candidate
 * is checked in O(1) however long the surrounding `.`/`_` runs are:
 *   right[i] = 1 when position i continues a file name looking right: a name character, or
 *              a `.`/`_` run followed by a name character;
 *   left[i]  = 1 when position i continues a file name looking left: a name character or
 *              `.`, or a `_` run preceded by a name character or `.`.
 * A `/` is never a continuation (0), so a segment-aligned prefix or suffix still matches.
 */
function boundaryFacts(t: string): { left: Uint8Array; right: Uint8Array } {
  const { cls } = tables();
  const n = t.length;
  const name = new Uint8Array(n);
  for (let i = 0; i < n; i++) name[i] = cls[t.charCodeAt(i)]! & NAME;
  const right = new Uint8Array(n);
  for (let i = n - 2; i >= 0; i--) {
    if (name[i]) right[i] = 1;
    else {
      const c = t.charCodeAt(i);
      const d = t.charCodeAt(i + 1);
      if ((c === DOT || c === UNDERSCORE) && (name[i + 1] || ((d === DOT || d === UNDERSCORE) && right[i + 1]))) right[i] = 1;
    }
  }
  if (n > 0 && name[n - 1]) right[n - 1] = 1;
  const left = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const c = t.charCodeAt(i);
    if (name[i] || c === DOT) left[i] = 1;
    else if (c === UNDERSCORE && i > 0) {
      const d = t.charCodeAt(i - 1);
      if (name[i - 1] || d === DOT || (d === UNDERSCORE && left[i - 1])) left[i] = 1;
    }
  }
  return { left, right };
}

// --- the scanner -----------------------------------------------------------------------

/**
 * Candidate matches one scan may examine (Aho–Corasick outputs followed). Past it the scan
 * stops and reports a single `limit` match over the whole text (fail closed).
 */
export const MAX_SCAN_CANDIDATES = 1 << 18;

export interface ScanMatch {
  /** `limit`: the candidate budget was exhausted; the span is the whole text */
  kind: "path" | "hash" | "limit";
  /** span in the ORIGINAL text */
  start: number;
  end: number;
}

export interface ConfidentialMatcher {
  readonly empty: boolean;
  scan(text: string, mode: ScanMode, firstOnly?: boolean): ScanMatch[];
}

const cache = new WeakMap<ReadonlySet<string>, WeakMap<ReadonlySet<string>, ConfidentialMatcher>>();
const NO_HASHES: ReadonlySet<string> = new Set();

export function confidentialMatcher(paths: ReadonlySet<string>, hashes: ReadonlySet<string> = NO_HASHES): ConfidentialMatcher {
  let inner = cache.get(paths);
  if (!inner) {
    inner = new WeakMap();
    cache.set(paths, inner);
  }
  const hit = inner.get(hashes);
  if (hit) return hit;
  const patterns: Pattern[] = [];
  const seen = new Set<string>();
  for (const p of paths) {
    const c = canonicalPath(p);
    if (c.length > 0 && !seen.has(`p:${c}`)) {
      seen.add(`p:${c}`);
      patterns.push({ text: c, kind: "path" });
    }
  }
  for (const h of hashes) {
    const c = h.toLowerCase();
    if (c.length > 0 && !seen.has(`h:${c}`)) {
      seen.add(`h:${c}`);
      patterns.push({ text: c, kind: "hash" });
    }
  }
  const ac = build(patterns);
  const hasPaths = patterns.some((p) => p.kind === "path");
  const matcher: ConfidentialMatcher = {
    empty: patterns.length === 0,
    scan(text: string, mode: ScanMode, firstOnly = false): ScanMatch[] {
      const found: ScanMatch[] = [];
      if (patterns.length === 0 || text.length === 0) return found;
      const can = canonicalize(text, mode);
      const t = can.text;
      const b = hasPaths ? boundaryFacts(t) : null;
      let budget = MAX_SCAN_CANDIDATES;
      let s = 0;
      for (let i = 0; i < t.length; i++) {
        const c = t.charCodeAt(i);
        for (;;) {
          const g = ac.next[s]!.get(c);
          if (g !== undefined) {
            s = g;
            break;
          }
          if (s === 0) break;
          s = ac.fail[s]!;
        }
        for (let o = ac.out[s]!.length > 0 ? s : ac.dict[s]!; o > 0; o = ac.dict[o]!) {
          for (const id of ac.out[o]!) {
            if (--budget < 0) return [{ kind: "limit", start: 0, end: text.length }];
            const p = ac.patterns[id]!;
            const from = i - p.text.length + 1;
            if (p.kind === "path" && ((from > 0 && b!.left[from - 1]) || (i + 1 < t.length && b!.right[i + 1]))) continue;
            found.push({ kind: p.kind, start: can.start[from]!, end: can.end[i]! });
            if (firstOnly) return found;
          }
        }
      }
      return found;
    },
  };
  inner.set(hashes, matcher);
  return matcher;
}

/** JSON-unescape rounds the invariant applies (covers nesting several layers deep). */
export const DECODE_LAYERS = 6;
/** Longest text the invariant decodes. */
const MAX_DECODE_CHARS = 8 * 1024 * 1024;

/** One round of JSON string unescaping, as a linear left-to-right pass. */
export function jsonUnescapeOnce(t: string): string {
  let out = "";
  let last = 0;
  for (let i = 0; i < t.length; i++) {
    if (t.charCodeAt(i) !== BACKSLASH || i + 1 >= t.length) continue;
    const x = t[i + 1]!;
    let rep: string;
    let skip = 2;
    if (x === "u" && isHex4(t, i + 2)) {
      rep = String.fromCharCode(parseInt(t.slice(i + 2, i + 6), 16));
      skip = 6;
    } else {
      rep = ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f" } as Record<string, string>)[x] ?? x;
    }
    out += t.slice(last, i) + rep;
    i += skip - 1;
    last = i + 1;
  }
  return last === 0 ? t : out + t.slice(last);
}

/** The text and up to DECODE_LAYERS successively JSON-unescaped views of it. */
export function decodedViews(text: string): string[] {
  const views = [text];
  let cur = text.length > MAX_DECODE_CHARS ? text.slice(0, MAX_DECODE_CHARS) : text;
  for (let i = 0; i < DECODE_LAYERS; i++) {
    const next = jsonUnescapeOnce(cur);
    if (next === cur) break;
    views.push(next);
    cur = next;
  }
  return views;
}

/**
 * Spans (original text) of every withheld path or hash, in either scan mode, merged. When a
 * scan exhausts its candidate budget the result is one `limit` span over the whole text.
 */
export function withheldSpans(text: string, m: ConfidentialMatcher): { start: number; end: number; limit?: true }[] {
  const sep = m.scan(text, "separator");
  const esc = sep[0]?.kind === "limit" ? [] : m.scan(text, "escape");
  if (sep[0]?.kind === "limit" || esc[0]?.kind === "limit") return [{ start: 0, end: text.length, limit: true }];
  const all = [...sep, ...esc].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: { start: number; end: number }[] = [];
  for (const s of all) {
    const last = merged.at(-1);
    if (last && s.start <= last.end) last.end = Math.max(last.end, s.end);
    else merged.push({ start: s.start, end: s.end });
  }
  return merged;
}

/**
 * Does the text — or any bounded JSON-unescaped view of it, in either mode — carry a withheld
 * name or hash? A view that exhausts the candidate budget is a violation (`limit`).
 */
export function violates(text: string, m: ConfidentialMatcher): ScanMatch | null {
  if (m.empty) return null;
  for (const v of decodedViews(text)) {
    for (const mode of ["separator", "escape"] as const) {
      const hit = m.scan(v, mode, true)[0];
      if (hit) return hit;
    }
  }
  return null;
}

