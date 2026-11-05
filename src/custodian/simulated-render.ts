// Phase 4 Increment 3 — the simulated custodian's rendering of a held proposal (Ledger/FixRendering.cs; contract §3.5).
//
// The custodian renders the canonical patch ITSELF from the baseline bytes in its published capture and the postimage bytes
// it holds; the operator confirms exactly that text. This module renders the same bytes as the real custodian for the same
// records (the shared run corpus compares them): the header (run, repository, baseline source, digests), the boundary and
// its limits, the path list with the change kinds and the preimage and postimage SHA-256s, a unified line diff per text
// file, and the rendering's own SHA-256.
//
// What the operator's terminal shows must be what the bytes are: every control character but a tab, the C1 controls and the
// invisible and bidirectional formatting characters are shown escaped (`<U+XXXX>`), a line without a final newline is
// marked, and binary content (a NUL byte) or bytes that are not UTF-8 are shown as sizes and hashes only, flagged.

import { createHash } from "node:crypto";
import { escapeText } from "./render-escape.js";

export interface SimRenderChange {
  path: string;
  kind: "add" | "modify" | "delete";
  executable: boolean;
  preimage: { size: number; sha256: string } | null;
  postimage: { size: number; sha256: string; binary: boolean } | null;
  pre: Buffer | null;
  post: Buffer | null;
}

export interface SimRenderHeader {
  runId: string;
  repositoryPath: string;
  repoKey: string;
  fixId: string;
  operationId: string;
  reviewId: string;
  sourceId: string;
  taskDigest: string;
  proposalDigest: string;
  expiresAt: string;
  boundaryDigest: string;
  totalBytes: number;
}

export interface SimRendering {
  text: string;
  digest: string;
  changesDigest: string;
}

/** A diff compares at most this many line pairs (FixRendering.MaxCompareCells); a larger middle is a full replacement. */
export const MAX_COMPARE_CELLS = 4_000_000;
const CONTEXT = 3;

const sha256 = (s: string): string => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

export function renderProposal(h: SimRenderHeader, boundary: Record<string, unknown>, changes: readonly SimRenderChange[]): SimRendering {
  let head = "CodeParley delegated fix: the custodian's rendering of the proposal (what a confirmation binds)\n";
  head += `run: ${h.runId}\n`;
  head += `repository: ${escapeText(h.repositoryPath)}\n`;
  head += `repository identity: ${h.repoKey}\n`;
  head += `fix: ${h.fixId} (operation ${h.operationId})\n`;
  head += `baseline: review ${h.reviewId}, source ${h.sourceId}\n`;
  head += `task digest: ${h.taskDigest}\n`;
  head += `proposal digest: ${h.proposalDigest}\n`;
  head += `proposal expires: ${h.expiresAt}\n`;

  let tail = `boundary (digest ${h.boundaryDigest}):\n`;
  tail += `  permitted files: ${list(boundary["permittedFiles"])}\n`;
  tail += `  permitted directories: ${list(boundary["permittedDirs"])}\n`;
  tail += `  create: ${allowed(boundary["allowCreate"])}; delete: ${allowed(boundary["allowDelete"])}; binary: ${allowed(boundary["allowBinary"])}\n`;
  tail += `  limits: ${num(boundary["maxChangedFiles"])} changed files, ${num(boundary["maxFileBytes"])} bytes per file, ${num(boundary["maxTotalBytes"])} bytes in total\n`;
  tail += `  time limit: ${num(boundary["timeLimitSeconds"])} s; proposal lifetime: ${num(boundary["proposalLifetimeSeconds"])} s\n`;
  tail += `changes (${changes.length} files, ${h.totalBytes} bytes):\n`;
  for (const c of changes) {
    tail += `  ${c.kind} ${c.path}${c.executable ? " (executable)" : ""}\n`;
    tail += `    preimage: ${c.preimage ? `sha256 ${c.preimage.sha256} (${c.preimage.size} bytes)` : "none"}\n`;
    tail += `    postimage: ${c.postimage ? `sha256 ${c.postimage.sha256} (${c.postimage.size} bytes)${c.postimage.binary ? ", binary" : ""}` : "none"}\n`;
  }
  for (const c of changes) tail += fileSection(c);
  const body = head + tail;
  const digest = sha256(body);
  return { text: `${body}rendering sha256: ${digest}\n`, digest, changesDigest: sha256(tail) };
}

const list = (a: unknown): string => {
  const items = (Array.isArray(a) ? a : []).map((x) => escapeText(String(x)));
  return items.length === 0 ? "(none)" : items.join(", ");
};
const allowed = (v: unknown): string => (v === true ? "allowed" : "not allowed");
const num = (v: unknown): string => String(typeof v === "number" && Number.isInteger(v) ? v : 0);

function fileSection(c: SimRenderChange): string {
  let out = `=== ${c.kind} ${c.path} ===\n`;
  const binary = (c.pre !== null && c.pre.includes(0)) || (c.post !== null && c.post.includes(0));
  if (binary) return out + "(binary content: shown as sizes and hashes only) [FLAGGED: binary]\n";
  const pre = c.pre === null ? "" : decodeStrict(c.pre);
  const post = c.post === null ? "" : decodeStrict(c.post);
  if (pre === null || post === null) return out + "(not UTF-8 text: shown as sizes and hashes only) [FLAGGED: not text]\n";
  out += c.pre === null ? "--- /dev/null\n" : `--- a/${c.path}\n`;
  out += c.post === null ? "+++ /dev/null\n" : `+++ b/${c.path}\n`;
  const a = lines(pre);
  const b = lines(post);
  const { ops, full } = diff(a, b);
  if (full) out += "(too many lines to compare: shown as a full replacement)\n";
  return out + hunks(ops, a, b);
}

/** Strict UTF-8 (the custodian's UTF8Encoding(false, true)): invalid bytes are not text; a BOM is kept (and shown escaped). */
function decodeStrict(bytes: Buffer): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

interface Line {
  text: string;
  eol: boolean;
}

function lines(text: string): Line[] {
  if (text.length === 0) return [];
  const parts = text.split("\n");
  const lastEol = parts[parts.length - 1]!.length === 0;
  const count = lastEol ? parts.length - 1 : parts.length;
  const out: Line[] = [];
  for (let i = 0; i < count; i++) out.push({ text: parts[i]!, eol: i < count - 1 || lastEol });
  return out;
}

const same = (x: Line, y: Line): boolean => x.text === y.text && x.eol === y.eol;

interface Op {
  kind: "=" | "-" | "+";
  a: number;
  b: number;
}

/** The edit script: the common prefix and suffix kept, the middle compared by a longest common subsequence (a deletion
 * preferred before an insertion), or — over MAX_COMPARE_CELLS — replaced whole. */
function diff(a: Line[], b: Line[]): { ops: Op[]; full: boolean } {
  const n = a.length;
  const m = b.length;
  let p = 0;
  let s = 0;
  while (p < n && p < m && same(a[p]!, b[p]!)) p++;
  while (s < n - p && s < m - p && same(a[n - 1 - s]!, b[m - 1 - s]!)) s++;
  const ops: Op[] = [];
  for (let i = 0; i < p; i++) ops.push({ kind: "=", a: i, b: i });
  const an = n - p - s;
  const bm = m - p - s;
  const full = (an + 1) * (bm + 1) > MAX_COMPARE_CELLS;
  if (full) {
    for (let i = 0; i < an; i++) ops.push({ kind: "-", a: p + i, b: -1 });
    for (let j = 0; j < bm; j++) ops.push({ kind: "+", a: -1, b: p + j });
  } else {
    const w = bm + 1;
    const l = new Int32Array((an + 1) * w);
    for (let i = an - 1; i >= 0; i--) {
      for (let j = bm - 1; j >= 0; j--) {
        l[i * w + j] = same(a[p + i]!, b[p + j]!) ? l[(i + 1) * w + j + 1]! + 1 : Math.max(l[(i + 1) * w + j]!, l[i * w + j + 1]!);
      }
    }
    let x = 0;
    let y = 0;
    while (x < an && y < bm) {
      if (same(a[p + x]!, b[p + y]!)) {
        ops.push({ kind: "=", a: p + x, b: p + y });
        x++;
        y++;
      } else if (l[(x + 1) * w + y]! >= l[x * w + y + 1]!) {
        ops.push({ kind: "-", a: p + x, b: -1 });
        x++;
      } else {
        ops.push({ kind: "+", a: -1, b: p + y });
        y++;
      }
    }
    for (; x < an; x++) ops.push({ kind: "-", a: p + x, b: -1 });
    for (; y < bm; y++) ops.push({ kind: "+", a: -1, b: p + y });
  }
  for (let i = 0; i < s; i++) ops.push({ kind: "=", a: n - s + i, b: m - s + i });
  return { ops, full };
}

/** The hunks: each change with CONTEXT lines around it, changes at most 2×CONTEXT apart in one hunk; the header always
 * gives a start and a length (a start one before the first line when the length is 0). */
function hunks(ops: Op[], a: Line[], b: Line[]): string {
  const changed: number[] = [];
  ops.forEach((o, i) => {
    if (o.kind !== "=") changed.push(i);
  });
  if (changed.length === 0) return "(no line changes)\n";
  let out = "";
  let k = 0;
  while (k < changed.length) {
    const first = changed[k]!;
    let last = first;
    while (k + 1 < changed.length && changed[k + 1]! - last - 1 <= 2 * CONTEXT) last = changed[++k]!;
    k++;
    const start = Math.max(0, first - CONTEXT);
    const end = Math.min(ops.length - 1, last + CONTEXT);
    let aBefore = 0;
    let bBefore = 0;
    let aCount = 0;
    let bCount = 0;
    for (let i = 0; i < start; i++) {
      if (ops[i]!.kind !== "+") aBefore++;
      if (ops[i]!.kind !== "-") bBefore++;
    }
    for (let i = start; i <= end; i++) {
      if (ops[i]!.kind !== "+") aCount++;
      if (ops[i]!.kind !== "-") bCount++;
    }
    out += `@@ -${aCount === 0 ? aBefore : aBefore + 1},${aCount} +${bCount === 0 ? bBefore : bBefore + 1},${bCount} @@\n`;
    for (let i = start; i <= end; i++) {
      const o = ops[i]!;
      const line = o.kind === "+" ? b[o.b]! : a[o.a]!;
      out += `${o.kind === "=" ? " " : o.kind}${escapeText(line.text)}\n`;
      if (!line.eol) out += "\\ No newline at end of file\n";
    }
  }
  return out;
}

// The escaping rule itself is shared with the operator's `fix review` (render-escape.ts).
export { mustEscape, escapeText } from "./render-escape.js";
