// Trusted check configuration: normalization, approval digests and evaluation (plan §7.3,
// §14.1, §14.2; R-13, R-14, R-35, F8).
//
// Approval pins DEFINITIONS, not behaviour: approving a check is ongoing permission to run
// that configured project command at every future revision of the repository's code. It
// is not evidence that future code is safe (§14.2, §16.5).
//
// The approval record carries a digest over the whole entry (canonical worktree path, root
// commit, every check definition, profiles, the verification floor and test globs) and a
// digest per check. At use time both are recomputed. Any difference makes the WHOLE entry
// `approval_invalid` (nothing runs; re-approval through the CLI is required), and the
// per-check digests say which check was changed, added or removed. A hand edit of
// projects.json, including one made by repository code a check ran, therefore fails closed.

import { sha256OfCanonicalJson } from "../common/hash.js";
import { ENV_NAMES_CASE_INSENSITIVE, envNameKey, isDenied } from "../process/env.js";
import { PATH_RULES, pathKey, segmentProblem } from "../workspace/paths.js";
import { compileGlob } from "../capture/globs.js";
import {
  ApprovalRecordSchema,
  CheckDefinitionSchema,
  CheckNameSchema,
  type ApprovalRecord,
  type CheckDefinition,
} from "../schemas/checks.js";
import type { ProjectEntry, TrustProjects } from "../schemas/trust.js";

export const CHECK_DEFINITION_DIGEST_SCHEMA = "arl.check-definition.v1";
export const PROJECT_APPROVAL_DIGEST_SCHEMA = "arl.project-approval.v1";

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

export type NormalizeResult = { ok: true; def: CheckDefinition } | { ok: false; problems: string[] };

/** Validate a raw definition strictly and put it in canonical form (defaults explicit,
 * sets sorted, paths normalized). */
export function normalizeCheckDefinition(raw: unknown): NormalizeResult {
  const parsed = CheckDefinitionSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, problems: parsed.error.issues.map((i) => `${i.path.join(".") || "(definition)"}: ${i.message}`) };
  const d = parsed.data;
  const problems: string[] = [];

  const argv0 = d.argv[0]!;
  if (/["\r\n\t]/.test(argv0)) problems.push("argv[0] must not contain quotes or control characters");

  const cwd = normalizeRepoRelative(d.cwd, { allowRoot: true });
  if (!cwd.ok) problems.push(`cwd: ${cwd.reason}`);

  const freshness: string[] = [];
  for (const f of d.freshness_inputs) {
    const n = normalizeRepoRelative(f, { allowRoot: false });
    if (!n.ok) problems.push(`freshness_inputs "${f}": ${n.reason}`);
    else freshness.push(n.path);
  }

  // Variable names follow the platform's environment semantics (process/env.ts): one name per
  // case-insensitive spelling on Windows, exact names on Linux.
  const envKeys = Object.keys(d.env);
  const seenEnv = new Set<string>();
  for (const k of envKeys) {
    const key = envNameKey(k);
    if (seenEnv.has(key)) problems.push(`env: duplicate variable${ENV_NAMES_CASE_INSENSITIVE ? " (case-insensitive)" : ""}: ${k}`);
    seenEnv.add(key);
    if (/^ANTHROPIC_/i.test(k) || /^CLAUDE/i.test(k)) problems.push(`env: ${k} is never passed to check commands`);
  }
  const passthrough: string[] = [];
  const seenPass = new Set<string>();
  for (const n of d.env_passthrough) {
    if (isDenied(n)) problems.push(`env_passthrough: ${n} is refused (Claude/Anthropic credential or secret-shaped name)`);
    if (seenEnv.has(envNameKey(n))) problems.push(`env_passthrough: ${n} is also set in env`);
    if (!seenPass.has(envNameKey(n))) {
      seenPass.add(envNameKey(n));
      passthrough.push(n);
    }
  }
  if (problems.length > 0) return { ok: false, problems };

  const env: Record<string, string> = {};
  for (const k of [...envKeys].sort(byLower)) env[k] = d.env[k]!;
  return {
    ok: true,
    def: {
      argv: [...d.argv],
      cwd: cwd.ok ? cwd.path : ".",
      timeout_seconds: d.timeout_seconds,
      env,
      env_passthrough: passthrough.sort(byLower),
      freshness_inputs: [...new Set(freshness)].sort(),
      ...(d.description !== undefined ? { description: d.description } : {}),
    },
  };
}

/**
 * Normalize a repository-relative path (forward slashes, no "..", no ".git", valid names under
 * the platform's rules). A backslash is a separator on Windows and refused on Linux.
 */
export function normalizeRepoRelative(p: string, opts: { allowRoot: boolean }): { ok: true; path: string } | { ok: false; reason: string } {
  const s = (PATH_RULES === "win32" ? p.replace(/\\/g, "/") : p).trim();
  if (/^[A-Za-z]:/.test(s) || s.startsWith("/")) return { ok: false, reason: "must be relative to the repository" };
  const segs = s.split("/").filter((x) => x.length > 0 && x !== ".");
  if (segs.length === 0) return opts.allowRoot ? { ok: true, path: "." } : { ok: false, reason: "must name a file" };
  for (const seg of segs) {
    if (seg === "..") return { ok: false, reason: 'must not contain ".."' };
    if (seg.toLowerCase() === ".git") return { ok: false, reason: "must not name .git" };
    if (/[*?[\]{}]/.test(seg)) return { ok: false, reason: "wildcards are not supported (list each file)" };
    const problem = segmentProblem(seg);
    if (problem) return { ok: false, reason: problem };
  }
  return { ok: true, path: segs.join("/") };
}

export function checkDefinitionDigest(name: string, def: CheckDefinition): string {
  return sha256OfCanonicalJson({ schema: CHECK_DEFINITION_DIGEST_SCHEMA, name, def });
}

export interface ApprovalDigestInput {
  canonicalRoot: string;
  rootCommit: string | null;
  checkDigests: Readonly<Record<string, string>>;
  profiles: Readonly<Record<string, readonly string[]>>;
  requiredProfiles: readonly string[];
  noRequiredChecks: boolean;
  testGlobs: readonly string[];
}

/** Digest over everything an approval covers. The path is case-folded on Windows (NTFS), exact on Linux. */
export function projectApprovalDigest(i: ApprovalDigestInput): string {
  return sha256OfCanonicalJson({
    schema: PROJECT_APPROVAL_DIGEST_SCHEMA,
    worktree: pathKey(i.canonicalRoot),
    root_commit: i.rootCommit,
    checks: i.checkDigests,
    // Profile order is execution order and is part of the definition.
    profiles: i.profiles,
    required_profiles: [...i.requiredProfiles].sort(),
    no_required_checks: i.noRequiredChecks,
    test_globs: [...i.testGlobs],
  });
}

// ---------------------------------------------------------------------------
// Evaluation of a trusted project entry
// ---------------------------------------------------------------------------

export type ProjectStatus =
  | "approved" // approval record present and matching every definition
  | "no_entry" // no trusted entry for this worktree
  | "unapproved" // entry without an approval record (nothing runs)
  | "approval_invalid" // definitions differ from what was approved (nothing runs)
  | "root_commit_mismatch" // entry was recorded for a different repository at this path
  | "entry_invalid" // structurally unusable entry (nothing runs)
  // P3.4C-4: a protected run whose custodian-held configuration is not usable (nothing runs)
  | "config_not_held"
  | "config_lapsed";

export type CheckState = "approved" | "changed" | "added" | "invalid";

export interface EvaluatedCheck {
  name: string;
  state: CheckState;
  definition: CheckDefinition | null;
  digest: string | null;
  approvedDigest: string | null;
  problems: string[];
}

export interface ProjectEvaluation {
  key: string | null;
  status: ProjectStatus;
  problems: string[];
  checks: Map<string, EvaluatedCheck>;
  /** Approved names that no longer have a definition. */
  removed: string[];
  profiles: Record<string, string[]>;
  requiredProfiles: string[];
  noRequiredChecks: boolean;
  floorConfigured: boolean;
  testGlobs: string[];
  approval: ApprovalRecord | null;
  rootCommit: string | null;
}

/** Find and evaluate the trusted entry for a canonical worktree (case-insensitive key on Windows, exact on Linux). */
export function evaluateProject(projects: TrustProjects, canonicalRoot: string, currentRootCommit: string | null): ProjectEvaluation {
  const target = pathKey(canonicalRoot);
  const key = Object.keys(projects).find((k) => pathKey(k) === target) ?? null;
  if (key === null) return emptyEvaluation(null, "no_entry", []);
  return evaluateEntry(key, projects[key]!, canonicalRoot, currentRootCommit);
}

export function evaluateEntry(key: string, entry: ProjectEntry, canonicalRoot: string, currentRootCommit: string | null): ProjectEvaluation {
  const problems: string[] = [];
  const checks = new Map<string, EvaluatedCheck>();
  const approvalParsed = entry.approval === undefined ? null : ApprovalRecordSchema.safeParse(entry.approval);
  const approval = approvalParsed?.success ? approvalParsed.data : null;
  if (approvalParsed && !approvalParsed.success) problems.push("approval record is malformed");

  for (const [name, raw] of Object.entries(entry.checks ?? {})) {
    const nameOk = CheckNameSchema.safeParse(name).success;
    const n = normalizeCheckDefinition(raw);
    const approvedDigest = approval?.checks[name] ?? null;
    if (!nameOk || !n.ok) {
      checks.set(name, { name, state: "invalid", definition: null, digest: null, approvedDigest, problems: [...(nameOk ? [] : ["invalid check name"]), ...(n.ok ? [] : n.problems)] });
      continue;
    }
    const digest = checkDefinitionDigest(name, n.def);
    const state: CheckState = approvedDigest === null ? "added" : approvedDigest === digest ? "approved" : "changed";
    checks.set(name, { name, state, definition: n.def, digest, approvedDigest, problems: [] });
  }
  const removed = approval ? Object.keys(approval.checks).filter((n) => !checks.has(n)).sort() : [];

  const profiles: Record<string, string[]> = {};
  for (const [p, list] of Object.entries(entry.profiles ?? {})) {
    if (!CheckNameSchema.safeParse(p).success) problems.push(`invalid profile name: ${p}`);
    if (checks.has(p)) problems.push(`profile name collides with a check name: ${p}`);
    if (!Array.isArray(list) || list.length === 0) problems.push(`profile ${p} is empty`);
    for (const c of list ?? []) if (!checks.has(c)) problems.push(`profile ${p} references an undefined check: ${c}`);
    profiles[p] = [...(list ?? [])];
  }
  const requiredProfiles = [...(entry.required_profiles ?? [])];
  for (const r of requiredProfiles) if (!(r in profiles)) problems.push(`required profile is not defined: ${r}`);
  const noRequiredChecks = entry.no_required_checks === true;
  if (noRequiredChecks && requiredProfiles.length > 0) problems.push("no_required_checks is set together with required_profiles");
  const floorConfigured = noRequiredChecks !== (requiredProfiles.length > 0);
  const testGlobs = [...(entry.test_globs ?? [])];
  for (const g of testGlobs) {
    try {
      compileGlob(g);
    } catch {
      problems.push(`invalid test glob: ${g}`);
    }
  }

  const base = { key, checks, removed, profiles, requiredProfiles, noRequiredChecks, floorConfigured, testGlobs, approval, rootCommit: entry.root_commit ?? null };

  // R-35: an entry recorded for another repository at this path does not apply. A recorded root
  // with no current root (HEAD unborn) is a mismatch too: an empty repository put in the approved
  // one's place must not inherit its approval (PR #2 review).
  if (entry.root_commit != null && entry.root_commit !== currentRootCommit) {
    return { ...base, status: "root_commit_mismatch", problems: [...problems, `root commit differs (recorded ${entry.root_commit}, found ${currentRootCommit ?? "none: HEAD has no commit"})`] };
  }
  if ([...checks.values()].some((c) => c.state === "invalid") || problems.length > 0) {
    return { ...base, status: approval ? "approval_invalid" : "entry_invalid", problems };
  }
  if (!approval) return { ...base, status: "unapproved", problems: ["no approval record (approve with `code-parley checks approve`)"] };

  const recomputed = projectApprovalDigest({
    canonicalRoot,
    rootCommit: entry.root_commit ?? null,
    checkDigests: Object.fromEntries([...checks.values()].map((c) => [c.name, c.digest!])),
    profiles,
    requiredProfiles,
    noRequiredChecks,
    testGlobs,
  });
  const allChecksApproved = [...checks.values()].every((c) => c.state === "approved") && removed.length === 0;
  if (recomputed !== approval.digest || !allChecksApproved) {
    const changed = [...checks.values()].filter((c) => c.state !== "approved").map((c) => `${c.name} (${c.state})`);
    return {
      ...base,
      status: "approval_invalid",
      problems: [
        "trusted configuration differs from what was approved; re-approve with `code-parley checks approve`",
        ...(changed.length ? [`checks not matching their approval: ${changed.join(", ")}`] : []),
        ...(removed.length ? [`approved checks removed: ${removed.join(", ")}`] : []),
      ],
    };
  }
  return { ...base, status: "approved", problems: [] };
}

function emptyEvaluation(key: string | null, status: ProjectStatus, problems: string[]): ProjectEvaluation {
  return {
    key,
    status,
    problems,
    checks: new Map(),
    removed: [],
    profiles: {},
    requiredProfiles: [],
    noRequiredChecks: false,
    floorConfigured: false,
    testGlobs: [],
    approval: null,
    rootCommit: null,
  };
}

/** May this check run now? Only when the whole entry and the check itself are approved. */
export function isRunnable(ev: ProjectEvaluation, name: string): boolean {
  return ev.status === "approved" && ev.checks.get(name)?.state === "approved";
}

// ---------------------------------------------------------------------------
// Building an approved entry (CLI only)
// ---------------------------------------------------------------------------

export interface ApprovalRequest {
  canonicalRoot: string;
  rootCommit: string | null;
  checks: Readonly<Record<string, unknown>>;
  profiles: Readonly<Record<string, readonly string[]>>;
  requiredProfiles: readonly string[];
  noRequiredChecks: boolean;
  testGlobs: readonly string[];
}

export type BuildEntryResult =
  | { ok: true; entry: ProjectEntry; digest: string; definitions: Record<string, CheckDefinition> }
  | { ok: false; problems: string[] };

/** Validate everything that will be approved and produce the entry exactly as it will be
 * written (normalized definitions, approval record with digests). */
export function buildApprovedEntry(req: ApprovalRequest, now: string, toolVersion: string): BuildEntryResult {
  const problems: string[] = [];
  const definitions: Record<string, CheckDefinition> = {};
  const checkDigests: Record<string, string> = {};
  const names = Object.keys(req.checks).sort();
  if (names.length === 0 && !req.noRequiredChecks) problems.push("no checks to approve");
  for (const name of names) {
    if (!CheckNameSchema.safeParse(name).success) {
      problems.push(`invalid check name: ${name}`);
      continue;
    }
    const n = normalizeCheckDefinition(req.checks[name]);
    if (!n.ok) {
      problems.push(...n.problems.map((p) => `${name}: ${p}`));
      continue;
    }
    definitions[name] = n.def;
    checkDigests[name] = checkDefinitionDigest(name, n.def);
  }
  const profiles: Record<string, string[]> = {};
  for (const [p, list] of Object.entries(req.profiles)) {
    if (!CheckNameSchema.safeParse(p).success) problems.push(`invalid profile name: ${p}`);
    if (p in req.checks) problems.push(`profile name collides with a check name: ${p}`);
    if (list.length === 0) problems.push(`profile ${p} is empty`);
    for (const c of list) if (!(c in req.checks)) problems.push(`profile ${p} references an undefined check: ${c}`);
    profiles[p] = [...list];
  }
  for (const r of req.requiredProfiles) if (!(r in profiles)) problems.push(`required profile is not defined: ${r}`);
  if (req.noRequiredChecks && req.requiredProfiles.length > 0) problems.push("choose either required profiles or no_required_checks, not both");
  if (!req.noRequiredChecks && req.requiredProfiles.length === 0) {
    problems.push("a verification floor is required: name the required profile(s) or state explicitly that there are no required checks");
  }
  for (const g of req.testGlobs) {
    try {
      compileGlob(g);
    } catch {
      problems.push(`invalid test glob: ${g}`);
    }
  }
  if (problems.length > 0) return { ok: false, problems };

  const requiredProfiles = [...new Set(req.requiredProfiles)].sort();
  const testGlobs = [...req.testGlobs];
  const digest = projectApprovalDigest({
    canonicalRoot: req.canonicalRoot,
    rootCommit: req.rootCommit,
    checkDigests,
    profiles,
    requiredProfiles,
    noRequiredChecks: req.noRequiredChecks,
    testGlobs,
  });
  const entry: ProjectEntry = {
    ...(req.rootCommit !== null ? { root_commit: req.rootCommit } : {}),
    checks: definitions,
    profiles,
    ...(req.noRequiredChecks ? { no_required_checks: true } : { required_profiles: requiredProfiles }),
    test_globs: testGlobs,
    approval: { at: now, via: "cli", digest, checks: checkDigests, tool_version: toolVersion } satisfies ApprovalRecord,
  };
  return { ok: true, entry, digest, definitions };
}

// ---------------------------------------------------------------------------
// Repository proposals (.code-parley/config.json, legacy .ai-loop/config.json; untrusted, inert until approved)
// ---------------------------------------------------------------------------

export interface ParsedProposals {
  checks: Record<string, unknown>;
  profiles: Record<string, string[]>;
  warnings: string[];
}

/** Extract `proposed_checks` / `proposed_profiles` from parsed repository preferences JSON.
 * Never throws; proposals are data and grant nothing. */
export function parseProposals(json: unknown): ParsedProposals {
  const out: ParsedProposals = { checks: {}, profiles: {}, warnings: [] };
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    out.warnings.push("repository preferences are not a JSON object");
    return out;
  }
  const obj = json as Record<string, unknown>;
  const pc = obj["proposed_checks"];
  if (pc !== undefined) {
    if (pc && typeof pc === "object" && !Array.isArray(pc)) out.checks = { ...(pc as Record<string, unknown>) };
    else out.warnings.push("proposed_checks is not an object; ignored");
  }
  const pp = obj["proposed_profiles"];
  if (pp !== undefined) {
    if (pp && typeof pp === "object" && !Array.isArray(pp)) {
      for (const [k, v] of Object.entries(pp as Record<string, unknown>)) {
        if (Array.isArray(v) && v.every((x) => typeof x === "string")) out.profiles[k] = v as string[];
        else out.warnings.push(`proposed profile ${k} is not a list of check names; ignored`);
      }
    } else out.warnings.push("proposed_profiles is not an object; ignored");
  }
  return out;
}

export interface PendingApproval {
  name: string;
  state: "new" | "changed" | "invalid";
  argv_preview: string[];
  problems: string[];
}

/** Proposals that differ from (or are absent in) the approved configuration (plan §11.3). */
export function pendingApprovals(proposals: ParsedProposals, ev: ProjectEvaluation): PendingApproval[] {
  const out: PendingApproval[] = [];
  for (const [name, raw] of Object.entries(proposals.checks).sort(([a], [b]) => a.localeCompare(b))) {
    const n = normalizeCheckDefinition(raw);
    const preview = Array.isArray((raw as { argv?: unknown })?.argv) ? ((raw as { argv: unknown[] }).argv.map(String).slice(0, 16)) : [];
    if (!CheckNameSchema.safeParse(name).success || !n.ok) {
      out.push({ name, state: "invalid", argv_preview: preview, problems: n.ok ? ["invalid check name"] : n.problems });
      continue;
    }
    const current = ev.checks.get(name);
    if (ev.status === "approved" && current?.state === "approved" && current.digest === checkDefinitionDigest(name, n.def)) continue;
    out.push({ name, state: current?.definition ? "changed" : "new", argv_preview: n.def.argv.slice(0, 16), problems: [] });
  }
  return out;
}

function byLower(a: string, b: string): number {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  // Names that differ only in case are distinct on Linux (refused as duplicates on Windows):
  // order them exactly so the normalized definition stays deterministic.
  return x < y ? -1 : x > y ? 1 : a < b ? -1 : a > b ? 1 : 0;
}
