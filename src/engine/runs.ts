// Run creation and the `prepare` operation (plan §5.4, §5.5, §8.2, §11.3, §15; M1.5).
//
// Creation validates everything synchronously and from trusted inputs only:
//   1. the task envelope (strict, size-capped) and review target (ref syntax only);
//   2. scope (D-03): configured allowed roots are the authority; the repository argument or
//      the single in-scope client root only SELECTS inside them; client roots are advisory,
//      or enforce repository association in strict mode;
//   3. the verification floor: trusted configuration, raised (never lowered) by
//      `additional_required_checks` (D-29); budgets may only be lowered;
//   4. request_id idempotency (same id + same arguments = the same run).
// It then writes run.json and the initial state record (revision 0, run PREPARING, the
// `prepare` operation already committed as running), and starts the baseline capture in the
// background: the capture holds the worktree lock (kind "capture"), never runs filters and
// never writes the repository (M1.2). Its outcome is one commit that also leaves PREPARING.

import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { TOOL_VERSION } from "../common/version.js";
import { isValidRefSyntax, runCapture } from "../capture/capture.js";
import { readRootCommit } from "../capture/root-commit.js";
import { pendingApprovals } from "../checks/project-config.js";
import { readRepoProposals } from "../checks/proposals.js";
import { cancellationRecord } from "../agents/codex/adapter.js";
import { checkOperationTermination, snapshotProcessTable } from "../process/proc-table.js";
import { resolveRunFloor } from "../policy/verification-floor.js";
import { createRun, commitState, readMeta, readState } from "../store/state-store.js";
import { runPaths } from "../store/paths.js";
import { readTextIfExists } from "../store/atomic.js";
import { resolveArtifact } from "../store/artifacts.js";
import { canonicalizePath, caseKey, isContainedIn, samePath } from "../workspace/paths.js";
import { resolveGitTopLevel } from "../workspace/git-toplevel.js";
import { reevaluateScope, resolveScope, type ScopeWarning } from "../workspace/scope.js";
import { CaptureRecordSchema, ReviewTargetSchema, type Limitation, type ReviewTarget } from "../schemas/capture.js";
import { MAX_ENVELOPE_BYTES, TaskEnvelopeSchema, type CancellationRecord } from "../schemas/review.js";
import { STATE_SCHEMA_VERSION, newStateRecord, type RunMeta, type StateRecord } from "../schemas/run-state.js";
import { loadTrustedState } from "./checks-operation.js";
import { effectiveBudgets, gitExeOf, listRuns, repoKeyOf, type Loaded, type RunHandle } from "./engine-env.js";

export interface CreateRunRequest {
  task_envelope: unknown;
  repository_root?: string | undefined;
  review_target?: unknown;
  additional_required_checks?: readonly string[] | undefined;
  budget_overrides?: { max_reviews?: number | undefined; max_check_executions?: number | undefined } | undefined;
  request_id?: string | undefined;
}

/** The host session's client roots: raw local paths (advisory), or null when not consulted. */
export interface ClientRootsView {
  roots: readonly string[] | null;
}

export interface PrepareResult {
  operation_id: string;
  status: "completed" | "failed" | "cancelled" | "interrupted";
  baseline_source_id: string | null;
  limitations: Limitation[];
  failure: { code: string; detail: string } | null;
  cancellation: CancellationRecord | null;
}

export interface CreateRunOutcome {
  run: RunHandle;
  deduplicated: boolean;
  prepareOperationId: string;
  completion: Promise<PrepareResult>;
}

interface OwnedPrepare {
  controller: AbortController;
  completion: Promise<PrepareResult>;
}
const owned = new Map<string, OwnedPrepare>();

/** Canonicalize client roots; invalid entries are dropped (they are advisory only). */
export async function canonicalClientRoots(raw: readonly string[] | null): Promise<string[] | null> {
  if (raw === null) return null;
  const out: string[] = [];
  for (const r of raw) {
    try {
      out.push(await canonicalizePath(r));
    } catch {
      /* not a usable local directory: ignored (advisory) */
    }
  }
  return out;
}

/**
 * MR-H: before every operation on an existing run, scope is re-evaluated against the
 * configuration as it is now (step 1 and 3) and, in strict mode, the session's current
 * client roots (step 4). Throws SCOPE_REVOKED / REPO_OUTSIDE_SESSION_ROOTS.
 */
export async function assertRunInScope(le: Loaded, run: RunHandle, client: ClientRootsView): Promise<ScopeWarning[]> {
  const clientRoots = await canonicalClientRoots(client.roots);
  return reevaluateScope(run.meta.repository_root, { allowedRoots: le.allowedRoots, clientRoots, enforceClientRoots: le.cfg.config.client_roots.enforce });
}

export async function createReviewRun(le: Loaded, req: CreateRunRequest, client: ClientRootsView): Promise<CreateRunOutcome> {
  // 1. Arguments (model claims: validated, never trusted).
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) throw new DomainError("INVALID_ARGUMENT", "request_id must be 1 to 128 characters");
  const env = TaskEnvelopeSchema.safeParse(req.task_envelope);
  if (!env.success) throw new DomainError("INVALID_ARGUMENT", `task_envelope is invalid: ${env.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "$"}: ${i.message}`).join("; ")}`);
  if (Buffer.byteLength(JSON.stringify(env.data), "utf8") > MAX_ENVELOPE_BYTES) throw new DomainError("INVALID_ARGUMENT", `task_envelope is larger than ${MAX_ENVELOPE_BYTES} bytes`);
  const tgt = ReviewTargetSchema.safeParse(req.review_target ?? { kind: "uncommitted" });
  if (!tgt.success) throw new DomainError("INVALID_ARGUMENT", "review_target must be {kind:'uncommitted'}, {kind:'since_baseline'} or {kind:'base_ref', ref}");
  const target: ReviewTarget = tgt.data;
  if (target.kind === "base_ref" && !isValidRefSyntax(target.ref)) throw new DomainError("INVALID_ARGUMENT", "review_target.ref is not a valid ref name (no options, ranges or paths)");
  const additional = [...new Set(req.additional_required_checks ?? [])];
  const cfgBudgets = le.cfg.config.budgets;
  const overrides: { max_reviews_per_run?: number; max_check_executions_per_run?: number } = {};
  const bo = req.budget_overrides ?? {};
  if (bo.max_reviews !== undefined) {
    if (bo.max_reviews > cfgBudgets.max_reviews_per_run) throw new DomainError("INVALID_ARGUMENT", `budget_overrides may only lower budgets: max_reviews ${bo.max_reviews} exceeds the configured ${cfgBudgets.max_reviews_per_run}`);
    overrides.max_reviews_per_run = bo.max_reviews;
  }
  if (bo.max_check_executions !== undefined) {
    if (bo.max_check_executions > cfgBudgets.max_check_executions_per_run) throw new DomainError("INVALID_ARGUMENT", `budget_overrides may only lower budgets: max_check_executions ${bo.max_check_executions} exceeds the configured ${cfgBudgets.max_check_executions_per_run}`);
    overrides.max_check_executions_per_run = bo.max_check_executions;
  }

  // 2. Scope (plan §8.2). The repository argument is canonicalized (§8.3 rules) before git.
  const gitExe = await gitExeOf(le);
  const clientRoots = await canonicalClientRoots(client.roots);
  const repositoryRootArg = req.repository_root !== undefined ? await canonicalizePath(req.repository_root) : undefined;
  const scope = await resolveScope(
    {
      allowedRoots: le.allowedRoots,
      clientRoots, // null: the client supplies no roots (plan §8.2 step 4; M1.6-15)
      ...(repositoryRootArg !== undefined ? { repositoryRootArg } : {}),
      enforceClientRoots: le.cfg.config.client_roots.enforce,
    },
    { canonicalize: (p) => canonicalizePath(p), resolveGitTopLevel: (p) => resolveGitTopLevel(p, { gitExe }) },
  );
  const repositoryRoot = scope.repositoryRoot;

  // 4 (before any write). request_id idempotency across this repository's runs.
  const requestDigest = sha256OfCanonicalJson({
    schema: "arl.create-run-request.v1",
    envelope: env.data,
    repository_root: caseKey(repositoryRoot), // Windows: lower case, as before; Linux: exact
    target,
    additional_required_checks: [...additional].sort(),
    budget_overrides: overrides,
  });
  if (req.request_id !== undefined) {
    const same = (await listRuns(le, [repositoryRoot])).find((r) => (r.meta as { request_id?: unknown }).request_id === req.request_id && samePath(r.meta.repository_root, repositoryRoot));
    if (same) {
      if ((same.meta as { request_digest?: unknown }).request_digest !== requestDigest) throw new DomainError("REQUEST_ID_CONFLICT", `request_id ${req.request_id} was already used with different arguments`, { details: { run_id: same.runId } });
      const st = await readState(same.paths);
      const prep = st.operations.find((o) => o.kind === "prepare");
      if (!prep) throw new DomainError("INTERNAL", `run ${same.runId} has no prepare operation`);
      return { run: same, deduplicated: true, prepareOperationId: prep.operation_id, completion: owned.get(prep.operation_id)?.completion ?? waitForPrepare(same, prep.operation_id) };
    }
  }

  // 3. Verification floor from trusted configuration, raised by the arguments only.
  const runId = uuidv7();
  const repoKey = repoKeyOf(repositoryRoot);
  const paths = runPaths(le.dataHome, repoKey, runId);
  const rootCommit = await readRootCommit({ gitExe, repoRoot: repositoryRoot });
  const trusted = await loadTrustedState({ trustProjectsPath: le.layout.trustProjects, meta: { repository_root: repositoryRoot } as RunMeta, gitExe, dataHome: le.dataHome });
  const floor = resolveRunFloor(trusted.view, additional);
  if (!floor.ok) {
    const first = floor.errors[0]!;
    throw new DomainError(first.code, floor.errors.map((e) => e.detail).join("; "), { details: { errors: floor.errors, trusted_status: trusted.view.status } });
  }

  const now = new Date().toISOString();
  const operationId = uuidv7();
  const clientWarning = scope.warnings.find((w) => w.code === "REPO_OUTSIDE_SESSION_ROOTS")?.detail ?? null;
  const meta: RunMeta = {
    schema_version: STATE_SCHEMA_VERSION,
    run_id: runId,
    created_at: now,
    repository_root: repositoryRoot,
    root_commit: rootCommit,
    versions: { tool: TOOL_VERSION },
    scope: { allowed_snapshot: scope.allowedSnapshot, client_roots_snapshot: scope.clientRootsSnapshot, client_roots_consulted: clientRoots !== null, client_roots_warning: clientWarning },
    target,
    envelope: env.data,
    verification_floor: { ...floor.floor, approval_digest: trusted.evaluation.approval?.digest ?? null },
    budgets: overrides,
    ...(req.request_id !== undefined ? { request_id: req.request_id, request_digest: requestDigest } : {}),
  };
  const state: StateRecord = newStateRecord(runId, "PREPARING", now);
  state.operations.push({ operation_id: operationId, kind: "prepare", status: "running", owner: le.env.owner, input_identity: requestDigest, ...(req.request_id !== undefined ? { request_id: req.request_id } : {}), started_at: now, command_lines: ["baseline capture (read-only git queries)"] });
  state.events.push({ seq: 1, ts: now, type: "run.created", actor: "host", summary: `run created for ${target.kind === "base_ref" ? `base_ref ${target.ref}` : target.kind}; baseline capture started`, refs: { operation_id: operationId } });
  await createRun(paths, meta, state);
  const run: RunHandle = { runId, repoKey, paths, meta };

  const controller = new AbortController();
  const completion = executePrepare(le, run, operationId, controller.signal).finally(() => owned.delete(operationId));
  owned.set(operationId, { controller, completion });
  return { run, deduplicated: false, prepareOperationId: operationId, completion };
}

async function executePrepare(le: Loaded, run: RunHandle, operationId: string, signal: AbortSignal): Promise<PrepareResult> {
  const opStartMs = Date.now();
  let requestedAt: string | null = null;
  const onAbort = () => {
    requestedAt ??= new Date().toISOString();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  let outcome: Record<string, unknown>;
  let status: "completed" | "failed" | "cancelled";
  try {
    const cap = await runCapture({
      kind: "baseline",
      repoRoot: run.meta.repository_root,
      gitExe: await gitExeOf(le),
      target: { kind: "uncommitted" },
      rules: le.cfg.config.capture,
      runPaths: run.paths,
      operationId,
      lock: { dataHome: le.dataHome, owner: le.env.owner, ...(le.env.testHooks?.lockDeps ? { deps: le.env.testHooks.lockDeps } : {}) },
      signal,
    });
    if (signal.aborted) throw new DomainError("INTERNAL", "cancelled");
    status = "completed";
    outcome = {
      status,
      baseline_source_id: cap.record.source_id,
      capture_ref: cap.recordRef,
      stable: cap.record.stable,
      limitations: cap.record.model_limitations,
      head: cap.record.repository.head_commit,
      branch: cap.record.repository.branch,
    };
  } catch (e) {
    if (signal.aborted) {
      status = "cancelled";
      const snap = le.env.testHooks?.checks?.sweep === null ? null : await snapshotProcessTable().catch(() => null);
      outcome = { status, cancellation: cancellationRecord(requestedAt ?? new Date().toISOString(), snap ? checkOperationTermination(process.pid, opStartMs, snap) : null) };
    } else {
      status = "failed";
      outcome = { status, failure: { code: isDomainError(e) ? e.code : "INTERNAL", detail: e instanceof Error ? e.message : String(e) } };
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  await commitState(run.paths, le.env.owner, (st) => {
    const op = st.operations.find((o) => o.operation_id === operationId);
    if (op && op.status === "running") {
      op.status = status;
      op.ended_at = new Date().toISOString();
      op.outcome = outcome;
    }
    if (st.state === "PREPARING") st.state = "IDLE";
    const seq = (st.events.at(-1)?.seq ?? 0) + 1;
    const failure = outcome["failure"] as { code: string } | undefined;
    st.events.push({ seq, ts: new Date().toISOString(), type: "prepare.finished", actor: "engine", summary: `baseline capture ${status}${failure ? ` (${failure.code})` : ""}`, refs: { operation_id: operationId } });
    return st;
  });
  return prepareResult(run, operationId);
}

/** Request cancellation of a prepare operation owned by this process. */
export function requestPrepareCancel(operationId: string): "cancellation_requested" | "not_owned" {
  const o = owned.get(operationId);
  if (!o) return "not_owned";
  o.controller.abort();
  return "cancellation_requested";
}

/** Every prepare operation this process owns (shutdown cancels them). */
export function ownedPrepareOperations(): { operationId: string; completion: Promise<unknown> }[] {
  return [...owned.entries()].map(([operationId, o]) => ({ operationId, completion: o.completion }));
}

export async function waitForPrepare(run: RunHandle, operationId: string, pollMs = 250, signal?: AbortSignal): Promise<PrepareResult> {
  const mine = owned.get(operationId);
  if (mine) return mine.completion;
  for (;;) {
    if (signal?.aborted) throw new DomainError("INTERNAL", "the wait for the baseline capture was abandoned");
    const st = await readState(run.paths);
    const op = st.operations.find((o) => o.operation_id === operationId);
    if (!op) throw new DomainError("RUN_NOT_FOUND", `operation ${operationId} not found`);
    if (op.status !== "running") return prepareResult(run, operationId);
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/** The prepare operation's result from the committed state. */
export async function prepareResult(run: RunHandle, operationId: string, state?: StateRecord): Promise<PrepareResult> {
  const st = state ?? (await readState(run.paths));
  const op = st.operations.find((o) => o.operation_id === operationId);
  if (!op) throw new DomainError("RUN_NOT_FOUND", `operation ${operationId} not found`);
  const oc = (op.outcome ?? {}) as { baseline_source_id?: string; limitations?: Limitation[]; failure?: { code: string; detail: string }; cancellation?: CancellationRecord };
  const status = (["completed", "failed", "cancelled", "interrupted"] as const).find((s) => s === op.status) ?? "failed";
  return {
    operation_id: operationId,
    status,
    baseline_source_id: oc.baseline_source_id ?? null,
    limitations: oc.limitations ?? (status === "interrupted" ? [{ code: "baseline_interrupted", detail: "the server that ran the baseline capture exited first; target since_baseline is unavailable for this run" }] : []),
    failure: oc.failure ?? null,
    cancellation: oc.cancellation ?? null,
  };
}

// ---------------------------------------------------------------------------
// The run-created view (plan §11.3 output)
// ---------------------------------------------------------------------------

export interface RunCreatedView {
  run_id: string;
  state: string;
  repository: { root: string; branch: string | null; head: string | null };
  scope: { allowed_root: string | null; client_roots_warning: string | null; client_roots_consulted: boolean };
  target: ReviewTarget;
  verification_floor: { required: string[]; source: ("trusted_config" | "run_argument")[]; configured: boolean; no_required_checks: boolean };
  checks_available: { profiles: { name: string; checks: string[] }[]; pending_approval: { name: string; argv_preview: string[]; state: string }[] };
  budgets: { name: string; used: number; limit: number }[];
  warnings: Limitation[];
}

export async function runCreatedView(le: Loaded, run: RunHandle): Promise<RunCreatedView> {
  const st = await readState(run.paths);
  const meta = await readMeta(run.paths);
  const gitExe = await gitExeOf(le);
  const trusted = await loadTrustedState({ trustProjectsPath: le.layout.trustProjects, meta, gitExe, dataHome: le.dataHome });
  const warnings: Limitation[] = [];
  const scopeMeta = meta.scope as { client_roots_warning?: string | null; client_roots_consulted?: boolean };
  if (scopeMeta.client_roots_warning) warnings.push({ code: "REPO_OUTSIDE_SESSION_ROOTS", detail: scopeMeta.client_roots_warning });
  if (trusted.view.status !== "approved") warnings.push({ code: "checks_not_approved", detail: `trusted check configuration for this repository: ${trusted.view.status}; approve checks with the CLI (code-parley checks approve)` });
  for (const p of trusted.evaluation.problems.slice(0, 10)) warnings.push({ code: "trusted_configuration_problem", detail: p });
  const proposals = await readRepoProposals(meta.repository_root, { excludeGlobs: le.cfg.config.capture.exclude_globs }).catch(() => null);
  const pending = proposals ? pendingApprovals(proposals, trusted.evaluation) : [];
  for (const w of proposals?.warnings ?? []) warnings.push({ code: "repo_proposal_warning", detail: w });
  const floor = (meta as { verification_floor?: { required: { check: string; source: "trusted_config" | "run_argument" }[]; no_required_checks: boolean } }).verification_floor ?? { required: [], no_required_checks: false };
  if (!trusted.view.floorConfigured && !floor.no_required_checks) warnings.push({ code: "verification_floor_unconfigured", detail: "no verification floor is configured for this repository; checks are optional evidence only" });
  const prep = [...st.operations].reverse().find((o) => o.kind === "prepare");
  let head: string | null = null;
  let branch: string | null = null;
  const oc = (prep?.outcome ?? {}) as { head?: string | null; branch?: string | null };
  if (prep?.status === "completed") {
    head = oc.head ?? null;
    branch = oc.branch ?? null;
  }
  const b = effectiveBudgets(le, meta);
  const allowed = meta.scope.allowed_snapshot.filter((r) => isContainedIn(meta.repository_root, r)).sort((x, y) => y.length - x.length)[0] ?? null;
  return {
    run_id: run.runId,
    state: st.state,
    repository: { root: meta.repository_root, branch, head },
    scope: { allowed_root: allowed, client_roots_warning: scopeMeta.client_roots_warning ?? null, client_roots_consulted: scopeMeta.client_roots_consulted === true },
    target: ReviewTargetSchema.parse(meta.target ?? { kind: "uncommitted" }),
    verification_floor: {
      required: [...new Set(floor.required.map((r) => r.check))],
      source: [...new Set(floor.required.map((r) => r.source))],
      configured: trusted.view.floorConfigured,
      no_required_checks: floor.no_required_checks,
    },
    checks_available: {
      profiles: Object.entries(trusted.view.profiles).map(([name, checks]) => ({ name, checks: [...checks] })),
      pending_approval: pending.map((p) => ({ name: p.name, argv_preview: p.argv_preview, state: p.state })),
    },
    budgets: [
      { name: "reviews", used: st.counters["reviews"] ?? 0, limit: b.max_reviews_per_run },
      { name: "check_executions", used: st.counters["check_executions"] ?? 0, limit: b.max_check_executions_per_run },
    ],
    warnings,
  };
}

/** The local capture record of the run's completed baseline (engine use only; never shown). */
export async function baselineRecord(run: RunHandle, st: StateRecord) {
  const prep = [...st.operations].reverse().find((o) => o.kind === "prepare" && o.status === "completed");
  const ref = (prep?.outcome as { capture_ref?: string } | undefined)?.capture_ref;
  if (!ref) return null;
  const raw = await readTextIfExists(resolveArtifact(run.paths.runDir, ref));
  return raw ? CaptureRecordSchema.parse(JSON.parse(raw)) : null;
}
