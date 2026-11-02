// Phase 4 foundation — delegated Codex fixes (D-03, D-26; plan §22.3): the pure rules for a delegated
// fix's task boundary and for the change set captured from its disposable workspace.
//
// A delegated fix is bounded twice. The OS confinement of the fixing process keeps its writes inside a
// disposable workspace that never contains the primary worktree (that mechanism is chosen elsewhere and
// is not modelled here). Afterwards THIS module decides whether what was written there is an eligible
// proposal: only regular files, only inside the task's permitted paths, within the limits, and no link,
// alias, special file or unsafe name anywhere in the workspace. Scope is enforced on the result, not on
// the writes: a workspace-write sandbox cannot enforce per-file scope (R-27).
//
// Nothing here applies a change. A proposal is inert data bound by digest to its boundary, its base and
// its content. `checkApplicationAuthorization` states the CONTRACT a future application step must meet —
// an operator confirmation from a non-model channel, bound to this exact proposal and target — but no
// module in src/ produces a confirmation or applies a proposal (test/delegated-fix-layering.test.ts).
//
// Paths are repository-relative with "/" separators and must be safe on BOTH Windows and POSIX: a
// delegated fix gains nothing from a name only one platform can represent, and rejecting it closes the
// device-name, stream, trailing-dot and short-name aliases at once. Pure: no I/O, no clock.

import { sha256OfCanonicalJson } from "../common/hash.js";

export const FIX_SCHEMA_VERSION = 1;

/** A file as a workspace manifest records it (the baseline, or a post-run scan). */
export interface FixFileEntry {
  /** Repository-relative, "/"-separated. */
  path: string;
  size: number;
  sha256: string;
  /** POSIX execute bit (always false on Windows). */
  executable: boolean;
}

/** A post-run file: as the manifest entry, plus whether its content is binary (a NUL byte anywhere). */
export interface FixPostFile extends FixFileEntry {
  binary: boolean;
}

export type ScanAnomalyKind =
  | "link" // symbolic link, junction, mount point or other reparse point (never followed)
  | "hard_link" // a regular file with more than one name
  | "special_file" // FIFO, socket, device
  | "alias" // the name resolves to another path (8.3 short name, other alias)
  | "unstable" // changed while it was being read
  | "unsafe_name" // a name that is unsafe on Windows or POSIX (see portableSegmentProblem)
  | "case_collision" // two names that are equal under case folding
  | "limit" // too many entries, too deep, or a file too large to capture
  | "unreadable";

export interface ScanAnomaly {
  path: string;
  kind: ScanAnomalyKind;
  detail: string;
}

/** What the workspace scanner found after the run. `complete` is false when the walk stopped early. */
export interface FixPostScan {
  files: FixPostFile[];
  anomalies: ScanAnomaly[];
  complete: boolean;
}

/** The task boundary of one delegated fix: what it may change, and how much. */
export interface FixBoundary {
  /** Opaque task identity (the future delegation record's id). */
  task_id: string;
  /** Exact files the fix may create, modify or delete. Sensitive paths are permitted only this way. */
  permitted_files: string[];
  /** Directories whose files the fix may change ("src/parser" covers "src/parser/a.ts", never "src/parser2/…"). */
  permitted_dirs: string[];
  allow_create: boolean;
  allow_delete: boolean;
  allow_binary: boolean;
  max_changed_files: number;
  max_file_bytes: number;
  max_total_bytes: number;
  /** How long a captured proposal stays confirmable. */
  proposal_lifetime_ms: number;
}

export type FixChangeKind = "add" | "modify" | "delete";

export interface FixChange {
  path: string;
  kind: FixChangeKind;
  /** The preimage an application must find (null for an added file). */
  base: { size: number; sha256: string; executable: boolean } | null;
  /** The content the proposal carries (null for a deleted file). */
  result: { size: number; sha256: string; executable: boolean; binary: boolean } | null;
}

export type FixViolationKind =
  | ScanAnomalyKind
  | "scan_incomplete"
  | "invalid_path"
  | "outside_boundary"
  | "sensitive_path"
  | "create_not_allowed"
  | "delete_not_allowed"
  | "binary_not_allowed"
  | "case_only_rename"
  | "too_many_changes"
  | "file_too_large"
  | "total_too_large";

export interface FixViolation {
  kind: FixViolationKind;
  path: string | null;
  detail: string;
}

/** eligible: may be offered for confirmation; empty: nothing changed; rejected: at least one violation. */
export type FixProposalStatus = "eligible" | "empty" | "rejected";

export interface FixEvaluation {
  status: FixProposalStatus;
  changes: FixChange[];
  violations: FixViolation[];
}

/** The bound, inert record of what a delegated fix proposes (written once, never applied by src/). */
export interface FixProposal {
  schema_version: typeof FIX_SCHEMA_VERSION;
  proposal_id: string;
  workspace_id: string;
  boundary: FixBoundary;
  boundary_digest: string;
  baseline_digest: string;
  status: FixProposalStatus;
  changes: FixChange[];
  violations: FixViolation[];
  created_at_ms: number;
  expires_at_ms: number;
  /** sha256 over every field above (proposalDigest). */
  digest: string;
}

// ---------------------------------------------------------------------------------------------
// Portable path rules
// ---------------------------------------------------------------------------------------------

const MAX_SEGMENT_CHARS = 255;
const MAX_PATH_CHARS = 1024;
// Control characters, the characters NTFS refuses, and both separators (a segment never holds one).
const BAD_CHARS = /[\u0000-\u001f\u007f<>:"|?*\\/]/;
// Device names Windows resolves in any directory, with or without an extension (incl. superscript digits).
const RESERVED_DEVICE = /^(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$|CLOCK\$)$/i;
// A segment shaped like an 8.3 short name (`GIT~1`, `PROGRA~1.TXT`) may alias another file (capture/enumerate.ts).
const SHORT_NAME = /^[^.~]{1,6}~\d{1,6}(\.[^.]{0,3})?$/;

/** Why one path segment is unsafe on Windows or POSIX, or null. */
export function portableSegmentProblem(seg: string): string | null {
  if (seg.length === 0) return "empty segment";
  if (seg === "." || seg === "..") return "dot segment";
  if (seg.length > MAX_SEGMENT_CHARS) return "segment too long";
  if (BAD_CHARS.test(seg)) return "control, reserved or separator character";
  if (/[ .]$/.test(seg)) return "ends with a space or a dot (Windows trims it to another name)";
  if (seg.toLowerCase() === ".git") return "names git metadata (.git)";
  const base = (seg.split(".")[0] ?? seg).replace(/[ .]+$/, "");
  if (RESERVED_DEVICE.test(base)) return "reserved Windows device name";
  if (SHORT_NAME.test(seg)) return "shaped like an 8.3 short name (may alias another file)";
  return null;
}

/** Why a repository-relative path is not a safe fix target, or null. */
export function portablePathProblem(rel: string): string | null {
  if (typeof rel !== "string" || rel.length === 0) return "empty path";
  if (rel.length > MAX_PATH_CHARS) return "path too long";
  if (rel.startsWith("/")) return "absolute path";
  for (const seg of rel.split("/")) {
    const p = portableSegmentProblem(seg);
    if (p) return `${p}: "${seg}"`;
  }
  return null;
}

/** Case-folded comparison key of a relative path (NTFS folds case; a portable change set must not collide). */
export const foldPath = (rel: string): string => rel.toLowerCase();

// Paths that steer another trust domain — the user's git client, CI with its secrets, other agents'
// instructions, CodeParley's own repository proposals — are never changed through a permitted directory,
// only when the boundary names the exact file. Prefixes end with "/".
const SENSITIVE_PATHS: readonly { match: string; reason: string }[] = [
  { match: ".gitmodules", reason: "git submodule URLs" },
  { match: ".gitattributes", reason: "git filter and merge-driver selection" },
  { match: ".lfsconfig", reason: "git LFS endpoints" },
  { match: ".husky/", reason: "git hooks" },
  { match: ".githooks/", reason: "git hooks" },
  { match: ".pre-commit-config.yaml", reason: "commit-time hooks" },
  { match: ".github/", reason: "CI workflows" },
  { match: ".gitlab-ci.yml", reason: "CI pipeline" },
  { match: ".circleci/", reason: "CI pipeline" },
  { match: "azure-pipelines.yml", reason: "CI pipeline" },
  { match: ".claude/", reason: "Claude Code settings and hooks" },
  { match: ".mcp.json", reason: "MCP server configuration" },
  { match: ".codex/", reason: "Codex configuration" },
  { match: ".agents/", reason: "agent configuration" },
  { match: "claude.md", reason: "agent instructions" },
  { match: "agents.md", reason: "agent instructions" },
  { match: ".vscode/", reason: "editor tasks (can run on folder open)" },
  { match: ".code-parley/", reason: "CodeParley repository proposals" },
  { match: ".ai-loop/", reason: "CodeParley repository proposals (legacy name)" },
  { match: ".npmrc", reason: "package-manager configuration" },
  { match: ".yarnrc", reason: "package-manager configuration" },
  { match: ".yarnrc.yml", reason: "package-manager configuration" },
];

/** Why a change to `rel` needs an exact listing in the boundary, or null. Compared case-folded. */
export function sensitivePathReason(rel: string): string | null {
  const p = foldPath(rel);
  const name = p.split("/").pop() ?? p;
  for (const s of SENSITIVE_PATHS) {
    if (s.match.endsWith("/") ? p.startsWith(s.match) || p.includes(`/${s.match}`) : p === s.match || name === s.match) return s.reason;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------------------------

/** Every reason this boundary is unusable (empty: usable). */
export function boundaryProblems(b: FixBoundary): string[] {
  const out: string[] = [];
  if (!b.task_id || typeof b.task_id !== "string") out.push("task_id is required");
  if (b.permitted_files.length === 0 && b.permitted_dirs.length === 0) out.push("the boundary permits nothing");
  for (const f of b.permitted_files) {
    const p = portablePathProblem(f);
    if (p) out.push(`permitted file "${f}": ${p}`);
  }
  for (const d of b.permitted_dirs) {
    const p = portablePathProblem(d);
    if (p) out.push(`permitted directory "${d}": ${p}`);
    // A directory grant never reaches sensitive files (isPermitted), so a sensitive directory grants nothing.
    else if (sensitivePathReason(`${d}/x`) !== null) out.push(`permitted directory "${d}" is sensitive; list its files exactly`);
  }
  for (const [name, v] of [
    ["max_changed_files", b.max_changed_files],
    ["max_file_bytes", b.max_file_bytes],
    ["max_total_bytes", b.max_total_bytes],
    ["proposal_lifetime_ms", b.proposal_lifetime_ms],
  ] as const) {
    if (!Number.isSafeInteger(v) || v <= 0) out.push(`${name} must be a positive integer`);
  }
  return out;
}

/** Does the boundary permit a change to `rel`? Exact, case-sensitive matching; sensitive paths only when listed. */
export function isPermitted(rel: string, b: FixBoundary): boolean {
  if (b.permitted_files.includes(rel)) return true;
  if (sensitivePathReason(rel) !== null) return false;
  return b.permitted_dirs.some((d) => rel.startsWith(`${d}/`));
}

/** Ordinal string order (locale-independent, so digests are stable everywhere). */
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export const boundaryDigest = (b: FixBoundary): string => sha256OfCanonicalJson({ schema: "codeparley.fix-boundary.v1", ...b });

export const manifestDigest = (entries: readonly FixFileEntry[]): string =>
  sha256OfCanonicalJson({
    schema: "codeparley.fix-manifest.v1",
    files: [...entries].sort((a, b) => cmp(a.path, b.path)).map((e) => [e.path, e.size, e.sha256, e.executable]),
  });

// ---------------------------------------------------------------------------------------------
// Changes and evaluation
// ---------------------------------------------------------------------------------------------

/** The file-level change set from the baseline to the post-run scan (exact paths; sorted). */
export function diffManifests(baseline: readonly FixFileEntry[], post: readonly FixPostFile[]): FixChange[] {
  const before = new Map(baseline.map((e) => [e.path, e]));
  const after = new Map(post.map((e) => [e.path, e]));
  const out: FixChange[] = [];
  for (const [path, a] of after) {
    const b = before.get(path);
    const result = { size: a.size, sha256: a.sha256, executable: a.executable, binary: a.binary };
    if (!b) out.push({ path, kind: "add", base: null, result });
    else if (b.sha256 !== a.sha256 || b.size !== a.size || b.executable !== a.executable) {
      out.push({ path, kind: "modify", base: { size: b.size, sha256: b.sha256, executable: b.executable }, result });
    }
  }
  for (const [path, b] of before) {
    if (!after.has(path)) out.push({ path, kind: "delete", base: { size: b.size, sha256: b.sha256, executable: b.executable }, result: null });
  }
  return out.sort((x, y) => cmp(x.path, y.path));
}

/**
 * Decide whether a post-run workspace is an eligible proposal under `boundary`. Every scan anomaly is a
 * violation wherever it is (a link outside the permitted paths still means the workspace was used to
 * stage an escape), and an incomplete scan never yields an eligible proposal.
 */
export function evaluateFix(input: { boundary: FixBoundary; baseline: readonly FixFileEntry[]; post: FixPostScan }): FixEvaluation {
  const { boundary: b, post } = input;
  const violations: FixViolation[] = [];
  for (const p of boundaryProblems(b)) violations.push({ kind: "outside_boundary", path: null, detail: `invalid boundary: ${p}` });
  for (const a of post.anomalies) violations.push({ kind: a.kind, path: a.path, detail: a.detail });
  if (!post.complete) violations.push({ kind: "scan_incomplete", path: null, detail: "the workspace scan stopped before the end; nothing it did not see can be vouched for" });

  const changes = diffManifests(input.baseline, post.files);
  const folded = new Map<string, FixChange[]>();
  for (const c of changes) folded.set(foldPath(c.path), [...(folded.get(foldPath(c.path)) ?? []), c]);
  for (const [, group] of folded) {
    if (group.length > 1) violations.push({ kind: "case_only_rename", path: group.map((c) => c.path).join(" | "), detail: "changes whose paths differ only in letter case are ambiguous on case-insensitive file systems" });
  }

  let total = 0;
  for (const c of changes) {
    const problem = portablePathProblem(c.path);
    if (problem) {
      violations.push({ kind: "invalid_path", path: c.path, detail: problem });
      continue;
    }
    if (!isPermitted(c.path, b)) {
      const reason = sensitivePathReason(c.path);
      violations.push(
        reason !== null
          ? { kind: "sensitive_path", path: c.path, detail: `${reason}: only an exactly listed file may change` }
          : { kind: "outside_boundary", path: c.path, detail: "not within the task's permitted paths" },
      );
    }
    if (c.kind === "add" && !b.allow_create) violations.push({ kind: "create_not_allowed", path: c.path, detail: "the boundary does not allow new files" });
    if (c.kind === "delete" && !b.allow_delete) violations.push({ kind: "delete_not_allowed", path: c.path, detail: "the boundary does not allow deletions" });
    if (c.result) {
      if (c.result.binary && !b.allow_binary) violations.push({ kind: "binary_not_allowed", path: c.path, detail: "binary content is not allowed by the boundary" });
      if (c.result.size > b.max_file_bytes) violations.push({ kind: "file_too_large", path: c.path, detail: `${c.result.size} bytes exceeds ${b.max_file_bytes}` });
      total += c.result.size;
    }
  }
  if (changes.length > b.max_changed_files) violations.push({ kind: "too_many_changes", path: null, detail: `${changes.length} changed files exceeds ${b.max_changed_files}` });
  if (total > b.max_total_bytes) violations.push({ kind: "total_too_large", path: null, detail: `${total} bytes of new content exceeds ${b.max_total_bytes}` });

  const status: FixProposalStatus = violations.length > 0 ? "rejected" : changes.length === 0 ? "empty" : "eligible";
  return { status, changes, violations };
}

/** The proposal's digest: over every field except `digest` itself. */
export function proposalDigest(p: Omit<FixProposal, "digest">): string {
  return sha256OfCanonicalJson({ schema: "codeparley.fix-proposal.v1", ...p });
}

// ---------------------------------------------------------------------------------------------
// The confirmation boundary (contract only)
// ---------------------------------------------------------------------------------------------

/**
 * Operator channels a confirmation may come from. Both are non-model channels (D-05): the Phase 2 local
 * CLI today, a custodian operator surface later. An MCP tool, a hook payload or model text is never one.
 */
export const FIX_CONFIRMATION_CHANNELS = ["local_cli", "custodian_operator"] as const;
export type FixConfirmationChannel = (typeof FIX_CONFIRMATION_CHANNELS)[number];

/** What an operator confirmation must bind. Produced only by a future operator channel — nothing in src/ creates one. */
export interface FixConfirmation {
  proposal_digest: string;
  /** pathKey of the primary worktree the operator confirmed the proposal for. */
  target_root_key: string;
  channel: FixConfirmationChannel;
  confirmed_at_ms: number;
}

/**
 * Every reason `confirmation` does not authorize applying `proposal` to the worktree keyed
 * `targetRootKey` at `nowMs` (empty: the contract is met). Meeting it is necessary, not sufficient:
 * an application step must still re-verify every preimage immediately before writing, and must verify
 * that the confirmation genuinely came from the channel it names (which this pure check cannot).
 */
export function checkApplicationAuthorization(
  proposal: FixProposal,
  confirmation: FixConfirmation,
  ctx: { targetRootKey: string; nowMs: number },
): string[] {
  const out: string[] = [];
  const { digest, ...core } = proposal;
  if (proposalDigest(core) !== digest) out.push("the proposal does not match its own digest");
  if (proposal.status !== "eligible") out.push(`the proposal is ${proposal.status}, not eligible`);
  if (confirmation.proposal_digest !== digest) out.push("the confirmation names another proposal");
  if (confirmation.target_root_key !== ctx.targetRootKey) out.push("the confirmation names another target worktree");
  if (!(FIX_CONFIRMATION_CHANNELS as readonly string[]).includes(confirmation.channel)) out.push("the confirmation did not come from an operator channel");
  if (confirmation.confirmed_at_ms < proposal.created_at_ms) out.push("the confirmation predates the proposal");
  if (ctx.nowMs > proposal.expires_at_ms) out.push("the proposal has expired");
  return out;
}
