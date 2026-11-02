// The simulated custodian's delegated-fix rules (Phase 4 Increment 2; custodian/…/Ledger/FixRules.cs): a faithful
// TypeScript re-implementation of the custodian's OWN validation of a delegated fix — the boundary it binds at op_begin
// and the proposal content it receives at op_finish — for the in-process SimulatedCustodianTransport. Both sides are held
// to one observable behaviour by the shared run corpus (test/fixtures/run-transition-corpus.json).
//
// Deliberately independent of the engine's policy/delegated-fix.ts: the custodian validates the content ITSELF and
// trusts no engine claim (contract §3.4), so it shares no code with the engine that submits it. A unit test holds the
// two path rule sets to the same verdicts (test/delegated-fix-custodian.test.ts).
//
// Pure: no I/O, no clock.

import { createHash } from "node:crypto";
import { sha256OfCanonicalJson } from "../common/hash.js";

/** The custodian's hard caps for a delegated fix (CustodianConstants.cs). A boundary is validated within them. */
export const SIM_FIX_LIMITS = Object.freeze({
  maxFixesPerRun: 10,
  maxPermittedFiles: 50,
  maxPermittedDirs: 20,
  maxChangedFiles: 50,
  maxFileBytes: 256 * 1024,
  maxTotalBytes: 512 * 1024,
  minTimeLimitSeconds: 30,
  maxTimeLimitSeconds: 3600,
  minLifetimeSeconds: 60,
  maxLifetimeSeconds: 7 * 24 * 3600,
  maxViolationsReported: 20,
  maxPathChars: 1024,
});

/** The boundary op_begin binds (held by the custodian; the engine's FixBoundary in the custodian's field names). */
export interface SimFixBoundary {
  permittedFiles: string[];
  permittedDirs: string[];
  allowCreate: boolean;
  allowDelete: boolean;
  allowBinary: boolean;
  maxChangedFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  timeLimitSeconds: number;
  proposalLifetimeSeconds: number;
}

/** One change of a submitted proposal, as the engine sends it (claims; `content` is base64 of the postimage bytes). */
export interface SimFixSubmittedChange {
  path: string;
  kind: "add" | "modify" | "delete";
  executable: boolean;
  content: string | null;
}

/** A baseline file as the custodian's own published capture manifest records it (area `tree`). */
export interface SimBaselineFile {
  size: number;
  sha256: string;
}

/** The custodian's read of a fix's baseline capture, taken before the hold (GrantLedger.Fix.cs ReadFixBaseline). */
export interface SimFixBaselineRead {
  reviewId: string;
  /** The export and capture record re-hashed equal to what the custodian recorded at publication. */
  unchanged: boolean;
  detail: string;
  /** The manifest's `tree` files by exact path (null: the export or its manifest could not be read). */
  tree: Map<string, SimBaselineFile> | null;
}

export type SimFixViolationKind =
  | "invalid_path"
  | "not_canonical_order"
  | "case_collision"
  | "outside_boundary"
  | "sensitive_path"
  | "content_mismatch"
  | "create_not_allowed"
  | "delete_not_allowed"
  | "not_in_baseline"
  | "present_in_baseline"
  | "binary_not_allowed"
  | "file_too_large"
  | "unchanged"
  | "too_many_changes"
  | "total_too_large"
  | "baseline_unavailable";

export interface SimFixViolation {
  kind: SimFixViolationKind;
  path: string | null;
}

/** A change the custodian accepted, in its canonical form: the preimage is the custodian's own baseline record. */
export interface SimFixCanonicalChange {
  path: string;
  kind: "add" | "modify" | "delete";
  executable: boolean;
  preimage: { size: number; sha256: string } | null;
  postimage: { size: number; sha256: string; binary: boolean } | null;
  content: string | null;
}

// ---------------------------------------------------------------------------------------------
// Portable path rules (FixRules.cs PathProblem): repository-relative, "/"-separated, safe on Windows AND POSIX.
// ---------------------------------------------------------------------------------------------

const RESERVED_DEVICE = /^(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$|CLOCK\$)$/i;
const SHORT_NAME = /^[^.~]{1,6}~\d{1,6}(\.[^.]{0,3})?$/;
const BAD_CHARS = /[\u0000-\u001f\u007f<>:"|?*\\/]/;

function segmentProblem(seg: string): string | null {
  if (seg.length === 0) return "empty segment";
  if (seg === "." || seg === "..") return "dot segment";
  if (seg.length > 255) return "segment too long";
  // Increment 2 restriction: delegated-fix paths are ASCII, so case folding is the same rule in every implementation (no
  // locale- or Unicode-version-dependent mapping decides whether two paths collide).
  if (/[^\u0000-\u007f]/.test(seg)) return "non-ASCII character (delegated-fix paths are limited to ASCII)";
  if (BAD_CHARS.test(seg)) return "control, reserved or separator character";
  if (/[ .]$/.test(seg)) return "ends with a space or a dot";
  if (seg.toLowerCase() === ".git") return "names git metadata";
  const base = (seg.split(".")[0] ?? seg).replace(/[ .]+$/, "");
  if (RESERVED_DEVICE.test(base)) return "reserved Windows device name";
  if (SHORT_NAME.test(seg)) return "shaped like an 8.3 short name";
  return null;
}

/** Why `rel` is not a portable, contained repository-relative path, or null. */
export function fixPathProblem(rel: string): string | null {
  if (rel.length === 0) return "empty path";
  if (rel.length > SIM_FIX_LIMITS.maxPathChars) return "path too long";
  if (rel.startsWith("/")) return "absolute path";
  for (const seg of rel.split("/")) {
    const p = segmentProblem(seg);
    if (p) return p;
  }
  return null;
}

// Paths that steer another trust domain change only when the boundary names the exact file (FixRules.cs Sensitive).
const SENSITIVE: readonly string[] = [
  ".gitmodules", ".gitattributes", ".lfsconfig", ".husky/", ".githooks/", ".pre-commit-config.yaml", ".github/", ".gitlab-ci.yml",
  ".circleci/", "azure-pipelines.yml", ".claude/", ".mcp.json", ".codex/", ".agents/", "claude.md", "agents.md", ".vscode/",
  ".code-parley/", ".ai-loop/", ".npmrc", ".yarnrc", ".yarnrc.yml",
];

/** Case folding of a path: ASCII letters only (FixRules.cs AsciiFold; a non-ASCII path is never a valid fix path, and a
 * non-ASCII baseline path folds to itself). */
export const asciiFold = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

/** Does a change to `rel` need an exact listing (case-folded comparison)? */
export function fixSensitive(rel: string): boolean {
  const p = asciiFold(rel);
  const name = p.split("/").pop() ?? p;
  return SENSITIVE.some((s) => (s.endsWith("/") ? p.startsWith(s) || p.includes(`/${s}`) : p === s || name === s));
}

/** Exact files; sensitive paths only when listed; directory grants cover their descendants. */
export function fixPermitted(rel: string, b: SimFixBoundary): boolean {
  if (b.permittedFiles.includes(rel)) return true;
  if (fixSensitive(rel)) return false;
  return b.permittedDirs.some((d) => rel.startsWith(`${d}/`));
}

/** The first reason a (syntactically valid) boundary is unusable, or null (FixRules.cs BoundaryProblem). */
export function fixBoundaryProblem(b: SimFixBoundary): string | null {
  if (b.permittedFiles.length === 0 && b.permittedDirs.length === 0) return "the boundary permits nothing";
  for (const f of b.permittedFiles) {
    const p = fixPathProblem(f);
    if (p) return `permitted file ${f}: ${p}`;
  }
  for (const d of b.permittedDirs) {
    const p = fixPathProblem(d);
    if (p) return `permitted directory ${d}: ${p}`;
    if (fixSensitive(`${d}/x`)) return `permitted directory ${d} is sensitive; list its files exactly`;
  }
  return null;
}

export const fixBoundaryDigest = (b: SimFixBoundary): string => sha256OfCanonicalJson({ schema: "codeparley.custodian-fix-boundary.v1", ...b });

/** The baseline tree's digest (sorted (path, size, sha256)): what the fix's op_begin bound. */
export function fixTreeDigest(tree: ReadonlyMap<string, SimBaselineFile>): string {
  const rows = [...tree.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([p, f]) => [p, f.size, f.sha256]);
  return sha256OfCanonicalJson({ schema: "codeparley.custodian-fix-tree.v1", files: rows });
}

// ---------------------------------------------------------------------------------------------
// Content validation (FixRules.cs Validate): the custodian's own verdict on what the engine submitted.
// ---------------------------------------------------------------------------------------------

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

/** Strict base64 (canonical: what it decodes to re-encodes to exactly it), or null. */
export function decodeStrictBase64(s: string): Buffer | null {
  if (s.length % 4 !== 0 || !BASE64.test(s)) return null;
  const b = Buffer.from(s, "base64");
  return b.toString("base64") === s ? b : null;
}

const ord = (a: string, b: string): boolean => a < b;

/**
 * Validate a submission against the boundary and the custodian's baseline tree, in the custodian's order: per change (in
 * the order submitted) its path, canonical order, case collision, the boundary, the content's presence, the kind
 * switches, the baseline, the bytes; then the aggregate limits. Every violation is reported (kind and path); the
 * canonical changes are returned only when there is none.
 */
export function validateFixSubmission(
  boundary: SimFixBoundary,
  tree: ReadonlyMap<string, SimBaselineFile>,
  changes: readonly SimFixSubmittedChange[],
): { violations: SimFixViolation[]; canonical: SimFixCanonicalChange[] | null; totalBytes: number } {
  const violations: SimFixViolation[] = [];
  const canonical: SimFixCanonicalChange[] = [];
  const v = (kind: SimFixViolationKind, path: string | null): void => void violations.push({ kind, path });
  const foldedTree = new Set([...tree.keys()].map(asciiFold));
  const seen = new Set<string>();
  let prev: string | null = null;
  let total = 0;
  for (const c of changes) {
    if (fixPathProblem(c.path) !== null) {
      v("invalid_path", c.path);
      continue;
    }
    if (prev !== null && !ord(prev, c.path)) v("not_canonical_order", c.path);
    prev = c.path;
    const fold = asciiFold(c.path);
    if (seen.has(fold)) v("case_collision", c.path);
    seen.add(fold);
    if (!fixPermitted(c.path, boundary)) v(fixSensitive(c.path) ? "sensitive_path" : "outside_boundary", c.path);
    const wantsContent = c.kind !== "delete";
    if (wantsContent !== (c.content !== null) || (c.kind === "delete" && c.executable)) {
      v("content_mismatch", c.path);
      continue;
    }
    if (c.kind === "add" && !boundary.allowCreate) v("create_not_allowed", c.path);
    if (c.kind === "delete" && !boundary.allowDelete) v("delete_not_allowed", c.path);
    const base = tree.get(c.path) ?? null;
    if (c.kind !== "add" && base === null) v("not_in_baseline", c.path);
    if (c.kind === "add" && foldedTree.has(fold)) v("present_in_baseline", c.path);
    let postimage: SimFixCanonicalChange["postimage"] = null;
    if (c.content !== null) {
      const bytes = decodeStrictBase64(c.content);
      if (bytes === null) {
        v("content_mismatch", c.path);
        continue;
      }
      const binary = bytes.includes(0);
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      if (binary && !boundary.allowBinary) v("binary_not_allowed", c.path);
      if (bytes.length > boundary.maxFileBytes) v("file_too_large", c.path);
      if (c.kind === "modify" && base !== null && base.sha256 === sha256 && base.size === bytes.length && !c.executable) v("unchanged", c.path);
      total += bytes.length;
      postimage = { size: bytes.length, sha256, binary };
    }
    canonical.push({
      path: c.path, kind: c.kind, executable: c.executable,
      preimage: c.kind === "add" || base === null ? null : { size: base.size, sha256: base.sha256 },
      postimage, content: c.content,
    });
  }
  if (changes.length > boundary.maxChangedFiles) v("too_many_changes", null);
  if (total > boundary.maxTotalBytes) v("total_too_large", null);
  return { violations, canonical: violations.length === 0 ? canonical : null, totalBytes: total };
}

/** The custodian-computed proposal digest (FixRules.cs ProposalDigest): over the custodian's own bindings and the
 * canonical changes (preimages from its baseline record, postimages from the bytes it received). */
export function fixProposalDigest(p: {
  runId: string;
  operationId: string;
  fixId: string;
  taskDigest: string;
  boundaryDigest: string;
  baseline: { reviewId: string; sourceId: string; exportDigest: string; manifestDigest: string };
  changes: readonly SimFixCanonicalChange[];
}): string {
  return sha256OfCanonicalJson({
    schema: "codeparley.custodian-fix-proposal.v1",
    runId: p.runId,
    operationId: p.operationId,
    fixId: p.fixId,
    taskDigest: p.taskDigest,
    boundaryDigest: p.boundaryDigest,
    baseline: { ...p.baseline },
    changes: p.changes.map((c) => ({ path: c.path, kind: c.kind, executable: c.executable, preimage: c.preimage, postimage: c.postimage })),
  });
}
