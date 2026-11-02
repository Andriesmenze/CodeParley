// Line-ending analysis from FULL raw bytes (plan §9.6, D-30, MR-I). Pure.
//
// - `eol_change`: base and current line-ending styles differ, reported even when the file
//   also has substantive hunks.
// - `eol_only_change`: raw bytes differ but the CRLF->LF normalized contents are equal.
// - Neither is ever inferred from a displayed patch (an `--ignore-cr-at-eol` diff of an
//   EOL-only change is empty), nor for binary, size-skipped or transformation_unsupported
//   paths: the caller passes `null` where full bytes are not available.
//
// `gitNormalizes` mirrors when git itself converts line endings on `git add` (text /
// eol / legacy crlf attributes, core.autocrlf). For such paths a working file whose
// CRLF->LF normalization equals the base blob is what git considers *unmodified* — the
// normal checkout result under `core.autocrlf=true`. Capture treats that case as
// unchanged (recorded as `eol_conversion_equivalent`); the raw bytes still bind the
// source identity, so any later change is detected.

export interface EolStats {
  crlf: number;
  /** LF not preceded by CR. */
  lf: number;
  /** CR not followed by LF. */
  loneCr: number;
  nul: number;
  printable: number;
  nonPrintable: number;
}

export type EolStyle = "none" | "lf" | "crlf" | "cr" | "mixed";

/** Streaming EOL/binary statistics, matching git's `gather_stats` classification. */
export class EolStatsAccumulator {
  private s: EolStats = { crlf: 0, lf: 0, loneCr: 0, nul: 0, printable: 0, nonPrintable: 0 };
  private pendingCr = false;
  private lastByte = -1;

  update(buf: Buffer): void {
    const s = this.s;
    for (let i = 0; i < buf.length; i++) {
      const c = buf[i]!;
      if (this.pendingCr) {
        this.pendingCr = false;
        if (c === 0x0a) {
          s.crlf++;
          this.lastByte = c;
          continue;
        }
        s.loneCr++;
      }
      if (c === 0x0d) {
        this.pendingCr = true;
      } else if (c === 0x0a) {
        s.lf++;
      } else if (c === 0x7f) {
        s.nonPrintable++;
      } else if (c < 0x20) {
        if (c === 0x08 || c === 0x09 || c === 0x1b || c === 0x0c) s.printable++;
        else {
          if (c === 0) s.nul++;
          s.nonPrintable++;
        }
      } else {
        s.printable++;
      }
      this.lastByte = c;
    }
  }

  finish(): EolStats {
    if (this.pendingCr) {
      this.pendingCr = false;
      this.s.loneCr++;
    }
    // git: a trailing DOS EOF (^Z) is not counted as non-printable.
    if (this.lastByte === 0x1a) this.s.nonPrintable = Math.max(0, this.s.nonPrintable - 1);
    return { ...this.s };
  }
}

export function eolStatsOf(buf: Buffer): EolStats {
  const a = new EolStatsAccumulator();
  a.update(buf);
  return a.finish();
}

/** Binary for capture purposes: any NUL byte anywhere in the full content. */
export function isBinaryStats(s: EolStats): boolean {
  return s.nul > 0;
}

/** git's `convert_is_binary` text heuristic (used by text=auto / core.autocrlf). */
export function gitAutoTextHeuristic(s: EolStats): boolean {
  if (s.loneCr > 0) return false;
  if (s.nul > 0) return false;
  if (s.printable >> 7 < s.nonPrintable) return false;
  return true;
}

export function eolStyleOf(s: EolStats): EolStyle {
  const kinds = (s.crlf > 0 ? 1 : 0) + (s.lf > 0 ? 1 : 0) + (s.loneCr > 0 ? 1 : 0);
  if (kinds === 0) return "none";
  if (kinds > 1) return "mixed";
  if (s.crlf > 0) return "crlf";
  if (s.lf > 0) return "lf";
  return "cr";
}

/** CRLF -> LF (lone CRs kept), i.e. what `--ignore-cr-at-eol` treats as equal. */
export function normalizeCrlf(buf: Buffer): Buffer {
  let crlf = 0;
  for (let i = 0; i + 1 < buf.length; i++) if (buf[i] === 0x0d && buf[i + 1] === 0x0a) crlf++;
  if (crlf === 0) return buf;
  const out = Buffer.allocUnsafe(buf.length - crlf);
  let o = 0;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i]!;
    if (c === 0x0d && i + 1 < buf.length && buf[i + 1] === 0x0a) continue;
    out[o++] = c;
  }
  return out;
}

/** Attribute values as reported by `git check-attr` ("set", "unset", "unspecified" or a value). */
export interface EolAttributes {
  text: string;
  eol: string;
  crlf: string;
}

export type AutoCrlf = "true" | "false" | "input";

/**
 * Would git normalize CRLF->LF for this path on `git add`? Follows gitattributes(5):
 * `text` set (or legacy `crlf` set/input, or `eol` set with `text` unspecified) always
 * normalizes; `text=auto`, or unspecified with core.autocrlf true/input, normalizes when
 * the content is detected as text; `-text`/`binary`/`-crlf` never does. Conservative by
 * construction: the caller additionally requires the normalized content to equal the
 * base blob exactly before treating a difference as "unchanged".
 */
export function gitNormalizes(attrs: EolAttributes, autocrlf: AutoCrlf, currentStats: EolStats): boolean {
  type Action = "text" | "binary" | "auto" | "undefined";
  let action: Action;
  if (attrs.text === "set") action = "text";
  else if (attrs.text === "unset") action = "binary";
  else if (attrs.text === "auto") action = "auto";
  else if (attrs.crlf === "set" || attrs.crlf === "input") action = "text";
  else if (attrs.crlf === "unset") action = "binary";
  else action = "undefined";

  if (action === "undefined" && (attrs.eol === "lf" || attrs.eol === "crlf")) action = "text";
  if (action === "undefined") action = autocrlf === "false" ? "binary" : "auto";

  if (action === "binary") return false;
  if (action === "text") return true;
  return gitAutoTextHeuristic(currentStats);
}

export interface EolComparison {
  base_style: EolStyle;
  current_style: EolStyle;
  /** Line-ending styles differ (both sides have line endings). */
  eol_change: boolean;
  /** Raw bytes differ but CRLF->LF normalized contents are equal. */
  eol_only_change: boolean;
}

/**
 * Compare two FULL text contents (MR-I). Returns null if either side is binary — EOL
 * facts are never inferred for binary content.
 */
export function compareEol(base: Buffer, current: Buffer): EolComparison | null {
  const bs = eolStatsOf(base);
  const cs = eolStatsOf(current);
  if (isBinaryStats(bs) || isBinaryStats(cs)) return null;
  const baseStyle = eolStyleOf(bs);
  const currentStyle = eolStyleOf(cs);
  const rawEqual = base.equals(current);
  const eolOnly = !rawEqual && normalizeCrlf(base).equals(normalizeCrlf(current));
  const stylesDiffer = baseStyle !== "none" && currentStyle !== "none" && baseStyle !== currentStyle;
  return {
    base_style: baseStyle,
    current_style: currentStyle,
    eol_change: eolOnly || stylesDiffer,
    eol_only_change: eolOnly,
  };
}
