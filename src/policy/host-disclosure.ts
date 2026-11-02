// What may reach the HOST model through MCP tool results (plan §11, §16.2, MR-F; M1.5).
// Pure: no I/O. The engine supplies the withheld sets (from its own capture records) and
// the local paths that must not be shown; the MCP layer only formats what this returns.
//
// Two transformations, then one invariant:
//  1. Confidentiality (MR-F): every span carrying a withheld path name or file hash is
//     replaced, using the ONE M1.4 matcher (policy/confidential-scan.ts) — any spelling,
//     separator or escape depth; a text whose scan exhausts its budget is withheld whole.
//  2. Local paths: absolute paths outside the repository/allowed roots (the run store, the
//     user profile, the Codex installation, temp directories) are replaced by a label. The
//     repository root and allowed roots stay visible: the host already knows them and the
//     tool contract reports them.
//  3. The M1.4 hard invariant (`assertBundleConfidential`) over the transformed value — every
//     string, every key and the JSON encoding as a whole, in bounded decoded views. A result
//     that still carries a withheld name or hash is never returned (fail closed).

import { canonicalPath, confidentialMatcher, withheldSpans } from "./confidential-scan.js";
import { assertBundleConfidential, redactPaths, SCAN_LIMIT_REDACTION } from "./review-bundle.js";

export interface HostDisclosure {
  withheldPaths: ReadonlySet<string>;
  withheldHashes: ReadonlySet<string>;
  /** Canonical absolute roots whose paths may be shown (repository root, allowed roots). */
  keepRoots: readonly string[];
  /** Absolute local directories never shown; matched case-insensitively, any separator. */
  hiddenDirs: readonly { dir: string; label: string }[];
  /**
   * Linux (plan §1.13): also scrub POSIX absolute paths (`/…`) outside the kept roots, and
   * compare kept roots exactly (Linux names are case-sensitive). Windows leaves it unset: text
   * there carries `/`-options such as `/d /s /c` that are not paths.
   */
  posixPaths?: boolean;
}

export const NO_DISCLOSURE_LIMITS: HostDisclosure = { withheldPaths: new Set(), withheldHashes: new Set(), keepRoots: [], hiddenDirs: [] };

/** Replace withheld file hashes (MR-F) with a label. */
function redactHashes(text: string, hashes: ReadonlySet<string>, counter: { n: number }): string {
  if (hashes.size === 0) return text;
  const m = confidentialMatcher(new Set(), hashes);
  const spans = withheldSpans(text, m);
  if (spans.length === 0) return text;
  if (spans[0]!.limit) {
    counter.n++;
    return SCAN_LIMIT_REDACTION;
  }
  let out = "";
  let last = 0;
  for (const s of spans) {
    out += `${text.slice(last, s.start)}[withheld hash]`;
    last = s.end;
    counter.n++;
  }
  return out + text.slice(last);
}

const SEPARATORS = ["\\", "\\\\", "/"] as const;

function variants(dir: string): string[] {
  const d = dir.replace(/[\\/]+$/, "");
  const out = new Set<string>();
  for (const sep of SEPARATORS) out.add(d.split(/[\\/]+/).join(sep).toLowerCase());
  return [...out];
}

/** A kept POSIX root as written (exact case), with the separator spellings JSON may produce. */
function exactPosixVariants(dir: string): string[] {
  const d = dir.replace(/\/+$/, "");
  return [...new Set([d, d.split("/").join("\\/")])];
}

// The quote characters in this module's patterns are written as escapes (\x22 ", \x27 ', \x60 `)
// so that metric tools which do not parse regular-expression literals read the code correctly.
function isPathChar(c: string | undefined): boolean {
  return c !== undefined && !/[\s\x22\x27<>|*?\x60,;()[\]{}]/.test(c);
}

/**
 * Length of the kept root spelled at `text[at…]` (any separator spelling, case-insensitive,
 * ending at a separator or a non-path character), or 0. Literal comparison, so roots whose
 * names contain spaces are recognised.
 */
function keptPrefixAt(lower: string, text: string, at: number, keep: readonly string[]): number {
  let best = 0;
  for (const v of keep) {
    if (v.length > best && lower.startsWith(v, at)) {
      const after = text[at + v.length];
      if (after === undefined || after === "\\" || after === "/" || !isPathChar(after)) best = v.length;
    }
  }
  return best;
}

/** End of the path token starting at `i` (path characters up to a delimiter). */
function tokenEnd(text: string, i: number): number {
  let j = i;
  while (j < text.length && isPathChar(text[j])) j++;
  return j;
}

// Drive-letter (`C:\`, `C:\\`, `C:/`) or UNC (`\\server`, JSON-escaped `\\\\server`) path
// starts. A UNC start must follow a delimiter (so `]\\x` after a label, or an escaped
// separator inside a relative path, is not one). Fixed alternatives, no nested quantifiers:
// linear, no backtracking.
const ABS_START = /(?<![A-Za-z0-9])[A-Za-z]:(?:\\\\|\\|\/)|(?<=^|[\s\x22\x27\x60(=,;:<>{|])(?:\\\\\\\\|\\\\)(?=[A-Za-z0-9])/g;

// POSIX absolute path starts (Linux): a `/` (or a JSON-escaped `\/`) after a delimiter, before —
// possibly after further slashes (`//etc`) — any character a file name can start with (every
// path character, Unicode included: the dogfood review found `/資料/…` passing through an ASCII
// allowlist), or a `file://` URL. Not matched: `a/b` and `./x` (relative), `https://…` (the `/`
// follows `:`), `N/A`, a lone `/`, `// comment`. Fixed alternatives and one bounded run of
// slashes inside a lookahead: linear, no backtracking.
const POSIX_ABS_START = /(?<=^|[\s\x22\x27\x60(=,;<>{|[])\\?\/(?=\/*[^\s/\\\x22\x27\x60<>|*?,;()[\]{}])|file:\/\/\/?(?=[^\s\x22\x27\x60<>|*?,;()[\]{}])/g;

/**
 * Replace local absolute paths that are not under a kept root: first every hidden directory
 * (literal, case-insensitive, any separator spelling — so names with spaces are covered),
 * then any remaining absolute path token. Linear in the text length per hidden directory.
 */
export function scrubLocalPaths(text: string, d: Pick<HostDisclosure, "keepRoots" | "hiddenDirs" | "posixPaths">): string {
  if (!text) return text;
  let out = text;
  // Kept roots are compared case-insensitively on Windows (NTFS) and exactly on Linux.
  const keep = d.posixPaths ? [] : d.keepRoots.flatMap(variants);
  const keepExact = d.posixPaths ? d.keepRoots.flatMap(exactPosixVariants) : [];
  const keptAt = (s: string, lower: string, at: number) => Math.max(keptPrefixAt(lower, s, at, keep), keptExactAt(s, at, keepExact));
  // Longest directories first, so a data home inside the user profile gets its own label.
  const hidden = [...d.hiddenDirs].filter((h) => h.dir.length > 3).sort((a, b) => b.dir.length - a.dir.length);
  for (const h of hidden) for (const v of variants(h.dir)) out = replaceHidden(out, v, h.label, keptAt);
  out = scrubStarts(out, ABS_START, keptAt);
  if (d.posixPaths) out = scrubStarts(out, POSIX_ABS_START, keptAt);
  return out;
}

/**
 * Replace every occurrence of the hidden directory spelling `v` (lower case) in `out` that
 * stands as a path of its own — not inside a longer name, not under a kept root — by `label`.
 */
function replaceHidden(out: string, v: string, label: string, keptAt: (s: string, lower: string, at: number) => number): string {
  const lower = out.toLowerCase();
  let res = "";
  let last = 0;
  for (let at = lower.indexOf(v); at >= 0; at = lower.indexOf(v, at + v.length)) {
    if (standsAlone(out, at, v.length) && keptAt(out, lower, at) === 0) {
      res += out.slice(last, at) + label;
      last = at + v.length;
    }
  }
  return last > 0 ? res + out.slice(last) : out;
}

/** Is `out[at…at+len)` a path of its own: not preceded by a name character, and followed by a separator or a non-path character? */
function standsAlone(out: string, at: number, len: number): boolean {
  const after = out[at + len];
  const boundary = after === undefined || after === "\\" || after === "/" || !isPathChar(after);
  return boundary && (at === 0 || !isAsciiAlnum(out.charCodeAt(at - 1)));
}

/** Is the UTF-16 code unit `c` an ASCII letter or digit? */
function isAsciiAlnum(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
}

/** Length of a kept POSIX root spelled exactly at `text[at…]` (ending at a separator or a non-path character), or 0. */
function keptExactAt(text: string, at: number, keep: readonly string[]): number {
  let best = 0;
  for (const v of keep) {
    if (v.length > best && text.startsWith(v, at)) {
      const after = text[at + v.length];
      if (after === undefined || after === "\\" || after === "/" || !isPathChar(after)) best = v.length;
    }
  }
  return best;
}

/**
 * Replace every absolute-path token starting at a match of `starts` (one of this module's
 * fixed global patterns, used directly: its `lastIndex` is reset first) that is not under a
 * kept root.
 */
function scrubStarts(out: string, starts: RegExp, keptAt: (s: string, lower: string, at: number) => number): string {
  const lower = out.toLowerCase();
  const re = starts;
  re.lastIndex = 0;
  let res = "";
  let last = 0;
  for (let m = re.exec(out); m; m = re.exec(out)) {
    const kept = keptAt(out, lower, m.index);
    if (kept > 0) {
      re.lastIndex = m.index + kept;
      continue;
    }
    const end = tokenEnd(out, m.index);
    if (end <= m.index + m[0].length) continue;
    res += out.slice(last, m.index) + "[local path]";
    last = end;
    re.lastIndex = end;
  }
  return last > 0 ? res + out.slice(last) : out;
}

/** One string as the host may see it: withheld names and hashes redacted, local paths scrubbed. */
export function hostText(text: string, d: HostDisclosure, counter: { n: number } = { n: 0 }): string {
  let t = redactPaths(text, d.withheldPaths, counter);
  t = redactHashes(t, d.withheldHashes, counter);
  return scrubLocalPaths(t, d);
}

function mapStrings<T>(value: T, fn: (s: string) => string): T {
  const visit = (v: unknown): unknown => {
    if (typeof v === "string") return fn(v);
    if (Array.isArray(v)) return v.map(visit);
    if (v && typeof v === "object") {
      const o: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) o[k] = visit(x);
      return o;
    }
    return v;
  };
  return visit(value) as T;
}

/** Deep host view of a JSON-shaped value (strings transformed; keys must be engine-authored). */
export function hostValue<T>(value: T, d: HostDisclosure, counter: { n: number } = { n: 0 }): T {
  return mapStrings(value, (s) => hostText(s, d, counter));
}

/**
 * The CLI's default view (M1.6, `runs list` / `runs show`): withheld names and hashes are
 * redacted exactly as for the host — the CLI's output can end up in a model's context (a host
 * agent with shell access may run it) — while local paths stay visible, because the CLI is the
 * user's own channel (plan §16.4) and the user needs them to inspect the run store.
 */
export function localValue<T>(value: T, d: Pick<HostDisclosure, "withheldPaths" | "withheldHashes">, counter: { n: number } = { n: 0 }): T {
  return mapStrings(value, (s) => redactHashes(redactPaths(s, d.withheldPaths, counter), d.withheldHashes, counter));
}

/** The MR-F hard invariant over a host-facing value (throws when violated). */
export function assertHostConfidential(value: unknown, d: HostDisclosure): void {
  if (d.withheldPaths.size === 0 && d.withheldHashes.size === 0) return;
  assertBundleConfidential(value, d.withheldPaths, d.withheldHashes);
}

/** Canonical path key used to compare withheld names (exported for tests). */
export const withheldKey = canonicalPath;
