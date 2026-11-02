// The `checks` operation (plan §5.4, §10.3, §10.4, §11.4, §14; MR-C, MR-G).
//
// Start (synchronous part, before any process runs):
//   1. evaluate trusted configuration for the run's worktree (root-commit consistency,
//      approval digests) and resolve the selection: explicit names must be approved;
//      with no names the run's verification floor is used (D-29);
//   2. recover dead owners' operations; apply request_id idempotency and running-operation
//      dedupe; refuse a terminal run, a busy run, or an exhausted budget;
//   3. take the per-worktree lock (kind "checks") — WORKTREE_BUSY at once if held; checks
//      are serialized per worktree, never queued and never run concurrently, whichever run
//      they belong to (§14.4, T14);
//   4. commit the operation as `running` (the single commit point, §15.3).
// Execution (background): checks run sequentially. Before and after each check the source
// identity is recomputed under the SAME lock, so each execution records the source it
// started and ended on. Each check's definition is re-validated immediately before it runs
// (a previous check's repository code may have rewritten trusted configuration). Artifacts
// are written before the commit that references them. The lock is released only after the
// last child and its surviving descendants are gone; if this process dies first, the lock
// stays (kind "checks") and becomes ownership_unresolved (MR-C).
//
// Approval is ongoing permission to run the configured command; a passing check is
// necessary evidence, never proof that a reviewer finding is wrong (§14.5).

import { readFile } from "node:fs/promises";
import { DomainError } from "../common/errors.js";
import { sha256OfCanonicalJson, sha256OfString } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { computeSourceIdentity, type CaptureRulesInput, type CaptureTestHooks, type SourceIdentityResult } from "../capture/capture.js";
import { readRootCommit } from "../capture/root-commit.js";
import { evaluateProject, isRunnable, type ProjectEvaluation } from "../checks/project-config.js";
import { executeCheck, prepareCheck, type CheckRunOutcome, type PreparedCheck } from "../checks/runner.js";
import { loadTrustProjects } from "../config/trusted-projects.js";
import { caseKey } from "../workspace/paths.js";
import {
  deriveCheckConditions,
  effectiveRequirements,
  evaluateFloor,
  checkStatus,
  resolveSelection,
  type CheckCondition,
  type CheckStatusView,
  type CurrentCheckInputs,
  type FloorEvaluation,
  type SelectionItem,
  type TrustedView,
} from "../policy/verification-floor.js";
import { checkOperationTermination, snapshotProcessTable, type SweepDeps, type TerminationCheck } from "../process/proc-table.js";
import { cancellationRecord } from "../agents/codex/adapter.js";
import type { CancellationRecord } from "../schemas/review.js";
import { publishArtifact, resolveArtifact } from "../store/artifacts.js";
import { readTextIfExists } from "../store/atomic.js";
import { acquireWorktreeLock, acquireWorktreeLockWaiting, isBusyWithBoundedRead, type LockDeps, type WorktreeLockHandle } from "../store/locks.js";
import { aliveIfOwnInstance, classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type Liveness, type OwnerRecord } from "../store/owner.js";
import { canonicalPathKey, worktreeLockPath, type RunPaths } from "../store/paths.js";
import { applyRecovery, planRecovery } from "../store/recovery.js";
import { commitState, readState } from "../store/state-store.js";
import type { Limitation } from "../schemas/capture.js";
import {
  CheckExecutionRecordSchema,
  RunVerificationFloorSchema,
  type CheckExecutionRecord,
  type RunVerificationFloor,
  type SkipReason,
} from "../schemas/checks.js";
import type { Operation, RunMeta, StateRecord } from "../schemas/run-state.js";
import { custodianPresence, type CustodianTestHooks } from "../custodian/protected-loops.js";
import type { CustodianPresence } from "../custodian/service-presence.js";
import { artifactDigest, bounded, custodianEvidenceFor, reconcileCustodianRun, type CustodianEvidence } from "./custodian-evidence.js";
import { awaitCustodianCheckStart, awaitCustodianExecution } from "./custodian-capture.js";
import { heldCaptureRules, heldConfigFor, heldEvaluation, requireUsableHeld, type HeldConfig } from "./protected-config.js";
import type { RunCheckExecution } from "../custodian/protocol.js";
import { HARD_MAX_EXECUTIONS_PER_RUN } from "./hard-limits.js";

export const CHECKS_POLICY_VERSION = "checks.v1";
const TERMINAL_RUN_STATES = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

export interface ChecksEngineContext {
  dataHome: string;
  /** trust/projects.json */
  trustProjectsPath: string;
  /** Other trusted files whose change during a check is reported (config.json, isolation.json). */
  watchedTrustedFiles?: readonly string[];
  runPaths: RunPaths;
  meta: RunMeta;
  gitExe: string;
  /** Capture rules for source identities (trusted capture configuration). */
  rules: CaptureRulesInput;
  owner: OwnerRecord;
  budgets: { max_check_executions_per_run: number };
  /** The server environment passthrough values come from. Default process.env. */
  sourceEnv?: NodeJS.ProcessEnv;
  lockDeps?: LockDeps;
  /** Liveness of operation owners for recovery (default: PID + creation time). */
  classify?: (owner: OwnerRecord) => Promise<Liveness>;
  /** P3.4C-3: the protected-loop gate's custodian hook (tests), through which a protected run's checks are recorded. */
  custodian?: CustodianTestHooks;
  /** P3.4C-3 (contract §5.4): whether the custodian service is registered on this host. A context built without it
   * (tests only) asks nothing of the host: registered with a custodian hook, else absent. */
  custodianPresence?: () => Promise<CustodianPresence>;
  /** P3.4C-4: a PROTECTED run's custodian-held configuration, read again on every call (fail closed); absent for an
   * attended run, whose trusted configuration stays trust/projects.json and config.json. */
  heldConfig?: () => Promise<HeldConfig>;
  /** P3.4C-4: the custodian surface this process reads a protected run's configuration on (default implementer). */
  custodianSurface?: "operator" | "implementer";
  testHooks?: ChecksTestHooks;
}

export interface ChecksTestHooks {
  /** Once the worktree lock is obtained, before the operation's first source-identity read. */
  afterLock?: (operationId: string) => Promise<void> | void;
  /** Capture hooks for the operation's source-identity reads. */
  sourceRead?: CaptureTestHooks;
  /** Before check `index` is re-validated and prepared (tests change configuration here). */
  beforeCheck?: (name: string, index: number) => Promise<void> | void;
  /** Right after a check's process was spawned. */
  afterSpawn?: (name: string, pid: number) => Promise<void> | void;
  sweep?: SweepDeps | null;
  wallMsOverride?: number;
  exitGraceMs?: number;
  streamCapBytes?: number;
}

export interface ChecksRequest {
  checks?: readonly string[];
  profiles?: readonly string[];
  request_id?: string;
}

export interface ChecksResultItem {
  check: string;
  execution_id: string;
  status: CheckExecutionRecord["status"];
  skip_reason: SkipReason | null;
  error: string | null;
  check_spec_id: string | null;
  execution_input_id: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  stdout_tail: string;
  stderr_tail: string;
  stdout_bytes: number;
  stderr_bytes: number;
  truncated: boolean;
  source_stable: boolean;
}

export interface ChecksOperationResult {
  summary: string;
  operation_id: string;
  operation_status: string;
  status: "passed" | "failed" | "error" | "timed_out" | "cancelled";
  execution_ids: string[];
  results: ChecksResultItem[];
  source_id_at_start: string | null;
  source_id_at_end: string | null;
  stable: boolean;
  floor: FloorEvaluation;
  conditions: CheckCondition[];
  limitations: Limitation[];
  budgets: { name: string; used: number; limit: number }[];
  /** Set when the operation was cancelled: terminated only on evidence (MR-J). */
  cancellation: CancellationRecord | null;
}

export interface ChecksStart {
  operation_id: string;
  deduplicated: boolean;
  completion: Promise<ChecksOperationResult>;
}

interface OwnedOperation {
  controller: AbortController;
  completion: Promise<ChecksOperationResult>;
}

/** Operations owned by this process (in-process cancellation; M1.5 adds the tools). */
const owned = new Map<string, OwnedOperation>();

// ---------------------------------------------------------------------------
// Trusted view
// ---------------------------------------------------------------------------

export interface TrustedState {
  evaluation: ProjectEvaluation;
  view: TrustedView;
  rootCommit: string | null;
  /** P3.4C-4: the custodian-held configuration this evaluation came from (null: an attended run's local files). */
  held: HeldConfig | null;
}

/**
 * The trusted check configuration as it is NOW: on a protected run the custodian's held record (P3.4C-4 §1.1; the local
 * trust file is never read), otherwise trust/projects.json (Phase 2).
 */
export async function loadTrustedState(ctx: Pick<ChecksEngineContext, "trustProjectsPath" | "meta" | "gitExe" | "dataHome" | "heldConfig">): Promise<TrustedState> {
  const rootCommit = await readRootCommit({ gitExe: ctx.gitExe, repoRoot: ctx.meta.repository_root });
  if (ctx.heldConfig) {
    const held = await ctx.heldConfig();
    const evaluation = heldEvaluation(held.section, ctx.meta.repository_root, rootCommit);
    return { evaluation, view: toView(evaluation), rootCommit, held };
  }
  const projects = await loadTrustProjects(ctx.trustProjectsPath);
  const evaluation = evaluateProject(projects, ctx.meta.repository_root, rootCommit);
  return { evaluation, view: toView(evaluation), rootCommit, held: null };
}

/**
 * P3.4C-4: the checks context of a protected run — its configuration from the custodian (read again on every use) and
 * the held capture rules for its source identities; an attended run's context is returned unchanged.
 */
export async function withHeldConfig(ctx: ChecksEngineContext): Promise<ChecksEngineContext> {
  if (ctx.heldConfig) return ctx;
  const sel = configSelectionOf(ctx);
  const held = await heldConfigFor(sel, await readState(ctx.runPaths));
  if (!held) return ctx;
  return { ...ctx, rules: heldCaptureRules(held.section), heldConfig: () => heldAgain(sel, ctx) };
}

/** A protected run's configuration, read again: once protected, a run stays so (an answer of "attended" is refused). */
async function heldAgain(sel: ReturnType<typeof configSelectionOf>, ctx: Pick<ChecksEngineContext, "runPaths">): Promise<HeldConfig> {
  const held = await heldConfigFor(sel, await readState(ctx.runPaths));
  if (!held) throw new DomainError("CUSTODIAN_UNAVAILABLE", "the custodian no longer reports this protected run's configuration; nothing proceeds (fail closed)", { retryable: false });
  return held;
}

function configSelectionOf(ctx: ChecksEngineContext) {
  return { ...evidenceSelection(ctx), ...(ctx.custodianSurface ? { surface: ctx.custodianSurface } : {}) };
}

export function toView(ev: ProjectEvaluation): TrustedView {
  const defined = new Map<string, string | null>();
  for (const [n, c] of ev.checks) defined.set(n, c.digest);
  const approved = new Set([...ev.checks.keys()].filter((n) => isRunnable(ev, n)));
  return {
    status: ev.status,
    defined,
    approved,
    profiles: ev.profiles,
    requiredProfiles: ev.requiredProfiles,
    noRequiredChecks: ev.noRequiredChecks,
    floorConfigured: ev.status === "approved" && ev.floorConfigured,
  };
}

export function runFloorOf(meta: RunMeta): RunVerificationFloor | null {
  const raw = (meta as { verification_floor?: unknown }).verification_floor;
  if (raw === undefined) return null;
  const p = RunVerificationFloorSchema.safeParse(raw);
  if (!p.success) throw new DomainError("CONFIG_INVALID", "run.json verification_floor is malformed");
  return p.data;
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

export async function startChecks(ctx: ChecksEngineContext, req: ChecksRequest): Promise<ChecksStart> {
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) {
    throw new DomainError("INVALID_ARGUMENT", "request_id must be 1 to 128 characters");
  }
  // P3.4C-4: a protected run's checks run on the custodian's configuration (definitions, floor, capture rules) only.
  ctx = await withHeldConfig(ctx);
  const trusted = await loadTrustedState(ctx);
  if (trusted.held) requireUsableHeld(trusted.held.section);
  const runFloor = runFloorOf(ctx.meta);
  const requirements = effectiveRequirements(runFloor, trusted.view);
  const sel = resolveSelection(trusted.view, { ...(req.checks ? { checks: req.checks } : {}), ...(req.profiles ? { profiles: req.profiles } : {}) }, requirements);
  if (!sel.ok) {
    const first = sel.errors[0]!;
    throw new DomainError(first.code, sel.errors.map((e) => e.detail).join("; "), { details: { errors: sel.errors, trusted_status: trusted.view.status, problems: trusted.evaluation.problems } });
  }
  if (sel.items.length === 0) {
    throw new DomainError("NO_CHECKS_CONFIGURED", trusted.view.status === "approved" ? "no checks selected and the verification floor requires none" : `no approved checks for this repository (trusted configuration: ${trusted.view.status})`, {
      details: { trusted_status: trusted.view.status, problems: trusted.evaluation.problems },
    });
  }
  const runnable = sel.items.filter((i) => i.disposition === "runnable");
  if (runnable.length === 0) {
    throw new DomainError("CHECK_NOT_APPROVED", `none of the required checks can run: ${sel.items.map((i) => `${i.check} (${i.disposition})`).join(", ")}`, {
      details: { items: sel.items, trusted_status: trusted.view.status, problems: trusted.evaluation.problems },
    });
  }

  const requestKey = { checks: [...(req.checks ?? [])].sort(), profiles: [...(req.profiles ?? [])].sort() };
  const inputIdentity = sha256OfCanonicalJson({
    schema: "arl.checks-op-input.v1",
    items: sel.items.map((i) => [i.check, i.disposition, trusted.view.defined.get(i.check) ?? null]),
  });

  // Recover operations whose owner died before deciding anything from the state record.
  await recoverDeadOwners(ctx);

  const st0 = await readState(ctx.runPaths);
  const pre = decideStart(st0, ctx, req, requestKey, inputIdentity, runnable.length);
  if (pre.kind === "existing") return existingStart(ctx, pre.op, true);
  // P3.4C-3: a protected run's checks are recorded with the custodian first (op_begin … record_execution … op_finish).
  const evidence = await custodianEvidenceFor(evidenceSelection(ctx), st0);

  const operationId = uuidv7();
  const lockPath = worktreeLockPath(ctx.dataHome, canonicalPathKey(ctx.meta.repository_root));
  const plannedLines = runnable.map((i) => `${i.check}: ${JSON.stringify(trusted.evaluation.checks.get(i.check)?.definition?.argv ?? [])}`);
  const lockRequest = { owner: ctx.owner, operationId, kind: "checks", commandLines: plannedLines };
  // One immediate attempt: a lock held for checks, or ownership_unresolved, is refused here at
  // once (D-31). A bounded read or capture holding it is waited for inside the operation, so
  // this call still returns within its own bound.
  const lock = await acquireWorktreeLock(lockPath, lockRequest, ctx.lockDeps ?? {}).catch((e: unknown) => {
    if (isBusyWithBoundedRead(e)) return null;
    throw e;
  });

  // The custodian begins the operation (it issues the id and records this process as its writer) after the lock is
  // ours, so a refused lock begins nothing, and before the local commit (custodian first).
  let custodianOp: CustodianOperation | null = null;
  if (evidence) {
    try {
      const required = new Set(requirements.map((r) => r.check));
      // P3.4C-4 (§3.3): every check that will run names the definition it runs (the custodian compares it with its
      // approved one); one recorded only as skipped names none. P3.4C-5 Increment 3 (§4): and the executable this
      // session resolves for it (a claim; the custodian measures its stat and the check's freshness inputs itself).
      const planned: { check: string; checkSpecId: null; definitionDigest: string | null; required: boolean; executable: string | null }[] = [];
      for (const i of sel.items) {
        const runnableItem = i.disposition === "runnable";
        planned.push({ check: i.check, checkSpecId: null, definitionDigest: runnableItem ? (trusted.view.defined.get(i.check) ?? null) : null, required: required.has(i.check), executable: runnableItem ? await resolvedExecutable(ctx, trusted, i.check) : null });
      }
      const begun = await evidence.transition("op_begin", { operationKind: "checks", planned, inputIdentity }, `${operationId}-begin`);
      custodianOp = { evidence, operationId: String(begun["operationId"]), measuring: begun["operationStatus"] === "measuring" };
    } catch (e) {
      await lock?.release();
      throw e;
    }
  }

  let existing: Operation | null = null;
  try {
    await commitState(ctx.runPaths, ctx.owner, (cur) => {
      const d = decideStart(cur, ctx, req, requestKey, inputIdentity, runnable.length);
      if (d.kind === "existing") {
        existing = d.op;
        return cur; // no logical change (revision still advances; harmless)
      }
      const now = new Date().toISOString();
      cur.operations.push({
        operation_id: operationId,
        kind: "checks",
        status: "running",
        owner: ctx.owner,
        input_identity: inputIdentity,
        ...(req.request_id !== undefined ? { request_id: req.request_id } : {}),
        request: requestKey,
        started_at: now,
        command_lines: plannedLines,
        planned: sel.items,
        used_floor: sel.usedFloor,
        ...(custodianOp ? { custodian_operation_id: custodianOp.operationId } : {}),
      });
      cur.state = "CHECKING";
      pushEvent(cur, "checks.started", `checks started: ${sel.items.map((i) => i.check).join(", ")}`, { operation_id: operationId });
      return cur;
    });
  } catch (e) {
    await abandonCustodianOperation(custodianOp, operationId, `the local start was refused: ${e instanceof Error ? e.message : String(e)}`);
    await lock?.release();
    throw e;
  }
  if (existing) {
    await abandonCustodianOperation(custodianOp, operationId, "another start of the same checks was recorded first");
    await lock?.release();
    return existingStart(ctx, existing, true);
  }

  const controller = new AbortController();
  const acquireLock = lock ? () => Promise.resolve(lock) : () => acquireWorktreeLockWaiting(lockPath, lockRequest, ctx.lockDeps ?? {}, controller.signal);
  const completion = executeOperation(ctx, operationId, sel.items, trusted, acquireLock, controller.signal, custodianOp, lock).finally(() => owned.delete(operationId));
  owned.set(operationId, { controller, completion });
  return { operation_id: operationId, deduplicated: false, completion };
}

type StartDecision = { kind: "new" } | { kind: "existing"; op: Operation };

/** A checks operation the custodian began for a protected run: its channel, the custodian-issued id, and whether the
 * custodian was still measuring its start (P3.4C-5 Increment 3). */
interface CustodianOperation {
  evidence: CustodianEvidence;
  operationId: string;
  measuring?: boolean;
}

/** The absolute path of the executable this session resolves for check `name` (the engine's own resolution in its
 * environment; null when it does not resolve) — the claim a protected checks operation names for the custodian. */
async function resolvedExecutable(ctx: ChecksEngineContext, trusted: TrustedState, name: string): Promise<string | null> {
  const c = trusted.evaluation.checks.get(name);
  if (!c?.definition || !c.digest) return null;
  const p = await prepareCheck(name, c.definition, c.digest, { repoRoot: ctx.meta.repository_root, sourceEnv: ctx.sourceEnv ?? process.env }).catch(() => null);
  if (!p) return null;
  return p.ok ? p.check.resolved.path : (p.partial.resolved?.path ?? null);
}

function evidenceSelection(ctx: ChecksEngineContext) {
  return { custodian: ctx.custodian, presence: ctx.custodianPresence ?? (() => custodianPresence(true, ctx.custodian)), repositoryRoot: ctx.meta.repository_root, runId: ctx.meta.run_id, runJson: { path: ctx.runPaths.runJson, meta: ctx.meta } };
}

/** Finish a custodian operation whose local start did not happen (best effort: a failure leaves it running until its
 * writer is gone and a later `recover`). */
async function abandonCustodianOperation(op: CustodianOperation | null, operationId: string, why: string): Promise<void> {
  if (!op) return;
  await op.evidence.transition("op_finish", { operationId: op.operationId, outcome: { status: "error", error: bounded(why) } }, `${operationId}-finish`).catch(() => undefined);
}

/** One execution as the custodian records it: the engine's claim, with the digests of its logs and result as they
 * were written (each verified against these before every later use on a protected run). */
async function executionClaim(ctx: ChecksEngineContext, e: CheckExecutionRecord): Promise<RunCheckExecution> {
  return {
    executionId: e.execution_id,
    check: e.check,
    definitionDigest: e.definition_digest,
    checkSpecId: e.check_spec_id,
    executionInputId: e.execution_input_id,
    envDigest: e.env_digest,
    freshnessDigest: e.freshness_digest,
    status: e.status,
    skipReason: e.skip_reason ?? null,
    exitCode: e.exit_code,
    timedOut: e.timed_out,
    cancelled: e.cancelled,
    startedAt: e.started_at,
    endedAt: e.ended_at,
    durationMs: e.duration_ms,
    sourceIdAtStart: e.source_id_at_start,
    sourceIdAtEnd: e.source_id_at_end,
    sourceStable: e.source_stable,
    stdoutDigest: await artifactDigest(ctx.runPaths.runDir, e.stdout?.artifact),
    stderrDigest: await artifactDigest(ctx.runPaths.runDir, e.stderr?.artifact),
    resultDigest: await artifactDigest(ctx.runPaths.runDir, e.result_artifact),
    limitations: e.limitations.slice(0, 20).map((l) => ({ code: l.code, detail: bounded(l.detail) })),
  };
}

function decideStart(state: StateRecord, ctx: ChecksEngineContext, req: ChecksRequest, requestKey: unknown, inputIdentity: string, runnableCount: number): StartDecision {
  if (req.request_id !== undefined) {
    const same = state.operations.find((o) => o.request_id === req.request_id);
    if (same) {
      if (same.kind === "checks" && sha256OfCanonicalJson(same["request"] ?? null) === sha256OfCanonicalJson(requestKey)) return { kind: "existing", op: same };
      throw new DomainError("REQUEST_ID_CONFLICT", `request_id ${req.request_id} was already used with different arguments`, { details: { operation_id: same.operation_id } });
    }
  }
  if (TERMINAL_RUN_STATES.has(state.state)) throw new DomainError("RUN_TERMINAL", `run is ${state.state}`);
  const active = state.operations.find((o) => o.status === "running");
  if (active) {
    if (active.kind === "checks" && active.input_identity === inputIdentity) return { kind: "existing", op: active };
    throw new DomainError("RUN_BUSY", `run has an active ${active.kind} operation ${active.operation_id}`, { retryable: true, details: { operation_id: active.operation_id } });
  }
  if (state.state === "PREPARING") throw new DomainError("RUN_BUSY", "run is still preparing", { retryable: true });
  const used = state.counters["check_executions"] ?? 0;
  const limit = Math.min(ctx.budgets.max_check_executions_per_run, HARD_MAX_EXECUTIONS_PER_RUN);
  if (used + runnableCount > limit) {
    throw new DomainError("BUDGET_EXHAUSTED", `check execution budget: ${used} used, ${runnableCount} requested, limit ${limit}`, { details: { used, requested: runnableCount, limit } });
  }
  return { kind: "new" };
}

function existingStart(ctx: ChecksEngineContext, op: Operation, deduplicated: boolean): ChecksStart {
  const mine = owned.get(op.operation_id);
  const completion = mine ? mine.completion : waitForOperation(ctx, op.operation_id);
  return { operation_id: op.operation_id, deduplicated, completion };
}

async function recoverDeadOwners(ctx: ChecksEngineContext): Promise<void> {
  const classify = aliveIfOwnInstance(ctx.owner, ctx.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)));
  const state = await readState(ctx.runPaths);
  if (state.operations.some((o) => o.status === "running")) {
    const plan = await planRecovery(state, classify);
    if (plan.changed) await applyRecovery(ctx.runPaths, ctx.owner, plan, worktreeLockPath(ctx.dataHome, canonicalPathKey(ctx.meta.repository_root)));
  }
  // P3.4C-3 §5.2: then the custodian's record of a protected run (a pending end, operations whose writer is gone).
  await reconcileCustodianRun(evidenceSelection(ctx), ctx.runPaths, ctx.owner);
}

/** Request cancellation of an operation owned by this process. */
export function requestChecksCancel(operationId: string): "cancellation_requested" | "not_owned" {
  const o = owned.get(operationId);
  if (!o) return "not_owned";
  o.controller.abort();
  return "cancellation_requested";
}

/** Every checks operation this process owns (shutdown cancels them). */
export function ownedChecksOperations(): { operationId: string; completion: Promise<unknown> }[] {
  return [...owned.entries()].map(([operationId, o]) => ({ operationId, completion: o.completion }));
}

/** Wait (unbounded; callers bound it) for an operation of this run to finish, then report. */
export async function waitForOperation(ctx: ChecksEngineContext, operationId: string, pollMs = 250, signal?: AbortSignal): Promise<ChecksOperationResult> {
  const mine = owned.get(operationId);
  if (mine) return mine.completion;
  for (let i = 0; ; i++) {
    if (signal?.aborted) throw new DomainError("INTERNAL", "the wait for this operation was abandoned");
    const st = await readState(ctx.runPaths);
    const op = st.operations.find((o) => o.operation_id === operationId);
    if (!op) throw new DomainError("RUN_NOT_FOUND", `operation ${operationId} not found`);
    if (op.status !== "running") return buildResult(ctx, operationId);
    // The owner may have died: recovery marks its operation interrupted (never completed).
    if (i > 0 && i % 20 === 0) await recoverDeadOwners(ctx);
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

async function executeOperation(
  ctx: ChecksEngineContext,
  operationId: string,
  items: readonly SelectionItem[],
  startTrusted: TrustedState,
  acquireLock: () => Promise<WorktreeLockHandle>,
  signal: AbortSignal,
  custodianOp: CustodianOperation | null = null,
  startLock: WorktreeLockHandle | null = null,
): Promise<ChecksOperationResult> {
  // Each execution: on a protected run the custodian records it first (a refusal ends the operation with an error),
  // then the local cache.
  const recordExecution = async (rec: CheckExecutionRecord): Promise<void> => {
    if (custodianOp) {
      const r = await custodianOp.evidence.transition("record_execution", { operationId: custodianOp.operationId, execution: await executionClaim(ctx, rec) }, `${rec.execution_id}-rec`);
      // P3.4C-5 Increment 3 (§4): an execution that ran is recorded once the custodian has measured the source after it.
      if (r["executionStatus"] === "measuring") await awaitCustodianExecution(custodianOp.evidence, custodianOp.operationId, rec.execution_id);
    }
    await commitExecution(ctx, operationId, rec);
  };
  // F-5-1: a lock taken at the start is this operation's to release from here on, also when it ends before the
  // checks run (the custodian refused or interrupted its start measurement); release is a no-op unless it is ours.
  let lock: WorktreeLockHandle | null = startLock;
  const heartbeat = setInterval(() => void lock?.heartbeat().catch(() => undefined), 10_000);
  heartbeat.unref?.();
  const opStartMs = Date.now();
  let requestedAt: string | null = null;
  const onAbort = () => {
    requestedAt ??= new Date().toISOString();
  };
  if (signal.aborted) onAbort();
  else signal.addEventListener("abort", onAbort, { once: true });
  let opStatus: "completed" | "cancelled" | "error" = "completed";
  let opError: string | null = null;
  let treeRead = false;
  try {
    // P3.4C-5 Increment 3 (§4): on a protected run the checks start once the custodian has measured the source and the
    // planned checks' inputs itself.
    if (custodianOp?.measuring) {
      const m = await awaitCustodianCheckStart(custodianOp.evidence, custodianOp.operationId, signal);
      if (m === "aborted") throw new Error("cancelled while the custodian measured the operation's start");
      if (!m.running) throw new Error(`the custodian could not measure the checks' start (${m.reason}); no check ran`);
    }
    // The worktree lock: held since the start, or waited for here while a bounded read or
    // capture held it (up to 30 s; cancellation ends the wait; D-31).
    const held = await acquireLock();
    if (signal.aborted) {
      // Cancelled while the lock was being obtained: nothing ran. Release it at once instead of
      // first reading the tree under it.
      await held.release();
      throw new Error("cancelled while waiting for the worktree lock");
    }
    lock = held;
    await ctx.testHooks?.afterLock?.(operationId);
    // The first read of the tree stops on a cancel, also one that landed while the read verified
    // the held lock: nothing has run yet. (Later reads run to the end: they record what a check
    // did to the tree, and the checks a cancel keeps from starting are recorded as skipped.)
    let before: SourceIdentityResult | null = await sourceIdentity(ctx, operationId, held, signal);
    treeRead = true;
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      if (signal.aborted) {
        await recordExecution(skipped(operationId, item.check, "operation_cancelled", before));
        continue;
      }
      if (item.disposition !== "runnable") {
        await recordExecution(skipped(operationId, item.check, item.disposition === "definition_removed" ? "definition_removed" : "approval_invalid", before));
        continue;
      }
      await ctx.testHooks?.beforeCheck?.(item.check, i);

      // Re-validate immediately before running: an earlier check (repository code) or the
      // user may have changed trusted configuration since the operation started.
      const now = await loadTrustedState(ctx);
      const startDigest = startTrusted.evaluation.checks.get(item.check)?.digest ?? null;
      const cur = now.evaluation.checks.get(item.check);
      if (!isRunnable(now.evaluation, item.check) || cur?.digest !== startDigest) {
        const reason: SkipReason = !cur ? "definition_removed" : cur.digest !== startDigest ? "definition_changed" : "approval_invalid";
        await recordExecution(skipped(operationId, item.check, reason, before));
        continue;
      }
      if (!before) before = await sourceIdentity(ctx, operationId, held);

      const prep = await prepareCheck(item.check, cur.definition!, cur.digest!, { repoRoot: ctx.meta.repository_root, sourceEnv: ctx.sourceEnv ?? process.env });
      const trustedBefore = await trustedFilesDigest(ctx);
      if (!prep.ok) {
        await recordExecution(prepError(operationId, item.check, cur.digest!, prep, before));
        continue;
      }
      if (signal.aborted) {
        // Cancelled before anything was spawned: nothing ran, so this is not an execution.
        await recordExecution(skipped(operationId, item.check, "operation_cancelled", before));
        continue;
      }

      const childCommits: Promise<unknown>[] = [];
      const outcome = await executeCheck(prep.check, {
        signal,
        sweep: ctx.testHooks?.sweep === undefined ? {} : ctx.testHooks.sweep,
        ...(ctx.testHooks?.wallMsOverride !== undefined ? { wallMsOverride: ctx.testHooks.wallMsOverride } : {}),
        ...(ctx.testHooks?.exitGraceMs !== undefined ? { exitGraceMs: ctx.testHooks.exitGraceMs } : {}),
        ...(ctx.testHooks?.streamCapBytes !== undefined ? { streamCapBytes: ctx.testHooks.streamCapBytes } : {}),
        onSpawn: (child) => {
          const identity = child.startIdentity ? { startIdentity: child.startIdentity } : {};
          const record = { pid: child.pid, startedAtMs: child.startedAtMs, ...identity, commandLine: prep.check.commandLine };
          childCommits.push(held.recordChild({ pid: child.pid, startedAtMs: child.startedAtMs, ...identity, command_line: prep.check.commandLine, check: item.check }).catch(() => undefined));
          childCommits.push(
            commitState(ctx.runPaths, ctx.owner, (st) => {
              const op = st.operations.find((o) => o.operation_id === operationId);
              if (op) op["child"] = record;
              return st;
            }).catch(() => undefined),
          );
          if (ctx.testHooks?.afterSpawn) childCommits.push(Promise.resolve(ctx.testHooks.afterSpawn(item.check, child.pid)).catch(() => undefined));
        },
      });
      await Promise.all(childCommits);

      const after = await sourceIdentity(ctx, operationId, held).catch(() => null);
      const trustedAfter = await trustedFilesDigest(ctx);
      const record = await finishedRecord(ctx, operationId, prep.check, outcome, before, after, trustedBefore !== trustedAfter, requestedAt);
      await recordExecution(record);
      before = after;
    }
    if (signal.aborted) opStatus = "cancelled";
  } catch (e) {
    if (!treeRead && signal.aborted) {
      opStatus = "cancelled"; // cancelled while obtaining the worktree lock or first reading the tree: nothing ran
    } else {
      opStatus = "error";
      opError = e instanceof Error ? e.message : String(e);
    }
  } finally {
    clearInterval(heartbeat);
    signal.removeEventListener("abort", onAbort);
  }

  // A cancelled operation is "terminated" only on evidence (MR-J, F3): the termination record
  // of every tree this operation killed, or — when no check was running — operation-level
  // evidence that nothing this server started since the operation began survives.
  let cancellation: CancellationRecord | null = null;
  if (opStatus === "cancelled" || requestedAt !== null) {
    const killed = (await readState(ctx.runPaths).catch(() => null))?.check_executions.filter((e) => e.operation_id === operationId && e["cancellation"]) ?? [];
    const evidence: TerminationCheck | null = killed.length
      ? combineTermination(killed.map((e) => e["cancellation"] as CancellationRecord))
      : ctx.testHooks?.sweep === null
        ? null
        : checkOperationTermination(process.pid, opStartMs, await (ctx.testHooks?.sweep?.snapshot ?? snapshotProcessTable)().catch(() => null));
    cancellation = cancellationRecord(requestedAt ?? new Date().toISOString(), evidence);
  }

  // The custodian finishes its operation first; if it cannot be reached, the local record still finishes (and the
  // custodian's operation stays running until its writer is gone and a later `recover`).
  let custodianFinish: string | null = null;
  if (custodianOp) {
    try {
      const outcome = { status: opStatus, error: opError === null ? null : bounded(opError) };
      await custodianOp.evidence.transition("op_finish", { operationId: custodianOp.operationId, outcome }, `${operationId}-finish`);
    } catch (e) {
      custodianFinish = e instanceof Error ? e.message : String(e);
    }
  }
  try {
    await commitState(ctx.runPaths, ctx.owner, (st) => {
      if (custodianFinish !== null) pushEvent(st, "checks.custodian_finish_failed", `the custodian did not record the end of this operation: ${custodianFinish}`, { operation_id: operationId });
      const op = st.operations.find((o) => o.operation_id === operationId);
      if (op) {
        const execs = st.check_executions.filter((e) => e.operation_id === operationId);
        op.status = opStatus;
        op.ended_at = new Date().toISOString();
        delete op["child"];
        op.outcome = { status: aggregateStatus(execs, opStatus), execution_ids: execs.map((e) => e.execution_id), ...(opError ? { error: opError } : {}), ...(cancellation ? { cancellation } : {}) };
      }
      if (st.state === "CHECKING") st.state = "IDLE";
      pushEvent(st, "checks.finished", `checks ${opStatus}${opError ? `: ${opError}` : ""}`, { operation_id: operationId });
      return st;
    });
  } finally {
    // Nothing of ours is running any more (the runner waited for each child and swept its
    // descendants), so the worktree can be released. If this process dies before this
    // point the lock stays (kind "checks") and becomes ownership_unresolved (MR-C).
    await lock?.release();
  }
  return buildResult(ctx, operationId);
}

async function sourceIdentity(ctx: ChecksEngineContext, operationId: string, lock: WorktreeLockHandle, signal?: AbortSignal): Promise<SourceIdentityResult> {
  return computeSourceIdentity({
    repoRoot: ctx.meta.repository_root,
    gitExe: ctx.gitExe,
    rules: ctx.rules,
    lock: { dataHome: ctx.dataHome, owner: ctx.owner, ...(ctx.lockDeps ? { deps: ctx.lockDeps } : {}) },
    operationId,
    heldLock: lock,
    ...(signal ? { signal } : {}),
    ...(ctx.testHooks?.sourceRead ? { testHooks: ctx.testHooks.sourceRead } : {}),
  });
}

async function trustedFilesDigest(ctx: ChecksEngineContext): Promise<string> {
  const files = [ctx.trustProjectsPath, ...(ctx.watchedTrustedFiles ?? [])];
  const parts: [string, string | null][] = [];
  for (const f of files) {
    const t = await readFile(f).catch(() => null);
    parts.push([caseKey(f), t ? sha256OfString(t.toString("base64")) : null]);
  }
  return sha256OfCanonicalJson(parts);
}

function baseRecord(operationId: string, check: string): CheckExecutionRecord {
  return {
    execution_id: uuidv7(),
    operation_id: operationId,
    check,
    status: "skipped",
    definition_digest: null,
    check_spec_id: null,
    execution_input_id: null,
    resolved_executable: null,
    env_digest: null,
    env_names: [],
    passthrough_missing: [],
    freshness_inputs: [],
    freshness_digest: null,
    source_id_at_start: null,
    source_id_at_end: null,
    source_stable: false,
    started_at: null,
    ended_at: null,
    duration_ms: null,
    exit_code: null,
    pid: null,
    timed_out: false,
    cancelled: false,
    stdout: null,
    stderr: null,
    stdio_held_after_exit: false,
    descendants: null,
    result_artifact: null,
    environment_bound: "partial",
    limitations: [],
  };
}

function skipped(operationId: string, check: string, reason: SkipReason, before: SourceIdentityResult | null): CheckExecutionRecord {
  return { ...baseRecord(operationId, check), status: "skipped", skip_reason: reason, source_id_at_start: before?.source_id ?? null, source_id_at_end: before?.source_id ?? null };
}

function prepError(
  operationId: string,
  check: string,
  definitionDigest: string,
  prep: Extract<Awaited<ReturnType<typeof prepareCheck>>, { ok: false }>,
  before: SourceIdentityResult,
): CheckExecutionRecord {
  const now = new Date().toISOString();
  const r = prep.partial.resolved;
  return {
    ...baseRecord(operationId, check),
    status: "error",
    error: prep.error,
    definition_digest: definitionDigest,
    resolved_executable: r ? { path: r.path, kind: r.kind, how: r.how, size: r.size, mtime_ms: r.mtimeMs } : null,
    env_digest: prep.partial.envDigest,
    env_names: prep.partial.envNames,
    freshness_inputs: prep.partial.freshness,
    freshness_digest: prep.partial.freshnessDigest,
    // Nothing ran: the source the attempt saw is the one before it.
    source_id_at_start: before.source_id,
    source_id_at_end: before.source_id,
    source_stable: before.stable,
    started_at: now,
    ended_at: now,
    duration_ms: 0,
  };
}

async function finishedRecord(
  ctx: ChecksEngineContext,
  operationId: string,
  c: PreparedCheck,
  o: CheckRunOutcome,
  before: SourceIdentityResult,
  after: SourceIdentityResult | null,
  trustedChanged: boolean,
  cancelRequestedAt: string | null,
): Promise<CheckExecutionRecord> {
  const base = baseRecord(operationId, c.name);
  const execId = base.execution_id;
  const dir = `checks/${execId}`;
  // Artifacts first (plan §15.3): logs and the result are fsynced before the commit.
  const stdoutRef = (await publishArtifact(ctx.runPaths.runDir, ctx.runPaths.opsDir, operationId, `${dir}/stdout.log`, o.stdout)).ref;
  const stderrRef = (await publishArtifact(ctx.runPaths.runDir, ctx.runPaths.opsDir, operationId, `${dir}/stderr.log`, o.stderr)).ref;

  const stable = before.stable && !!after && after.stable && after.source_id === before.source_id;
  const limitations: Limitation[] = [];
  if (!stable) {
    limitations.push({
      code: "check_source_unstable",
      detail: after
        ? "the working tree changed while the check ran (the check's own repository code, or another writer); this result is not fresh for any source"
        : "the source identity could not be recomputed after the check; this result is not fresh",
    });
  }
  if (trustedChanged) limitations.push({ code: "trusted_configuration_changed_during_check", detail: "trusted configuration files changed while the check ran; later checks are re-validated before they run" });
  if (o.stdoutTruncated || o.stderrTruncated) limitations.push({ code: "check_output_truncated", detail: "output exceeded the stored cap; the tail is the true end of the output" });
  if (o.stdioHeldAfterExit) limitations.push({ code: "check_stdio_held_after_exit", detail: "a descendant kept the check's output pipes open after the check exited" });
  if (o.descendants?.survivors.length) {
    limitations.push({
      code: "check_descendants_terminated",
      detail: `the check left ${o.descendants.survivors.length} process(es) running; they were terminated${o.descendants.terminated === true ? "" : " (termination not confirmed)"}`,
    });
  }
  if (o.descendants && !o.descendants.scanned) limitations.push({ code: "descendant_scan_unavailable", detail: "the process table could not be read; surviving descendants were not checked" });
  if (o.treeKillReason && o.termination?.established !== true) {
    const t = o.termination;
    const named = [...(t?.survivors ?? []).map((x) => `${x.name} (${x.pid})`), ...(t?.unattributable ?? []).map((x) => `${x.name} (${x.pid}, unattributable)`)];
    limitations.push({ code: "check_termination_unconfirmed", detail: `the check's process tree was killed (${o.treeKillReason}) but its termination was not established (${t?.reason ?? "no termination evidence is available"})${named.length ? `; possible survivors: ${named.join(", ")}` : ""}` });
  }
  // A cancelled execution carries the one cancellation record shape (F3): "terminated" only
  // when the termination evidence establishes it.
  const cancellation = o.cancelled ? cancellationRecord(cancelRequestedAt ?? new Date().toISOString(), o.termination) : null;
  if (c.passthroughMissing.length) limitations.push({ code: "passthrough_missing", detail: `configured passthrough variables absent from the server environment: ${c.passthroughMissing.join(", ")}` });

  const record: CheckExecutionRecord = {
    ...base,
    status: o.status,
    ...(o.error ? { error: o.error } : {}),
    definition_digest: c.definitionDigest,
    check_spec_id: c.checkSpecId,
    execution_input_id: c.executionInputId,
    resolved_executable: { path: c.resolved.path, kind: c.resolved.kind, how: c.resolved.how, size: c.resolved.size, mtime_ms: c.resolved.mtimeMs },
    env_digest: c.envDigest,
    env_names: c.envNames,
    passthrough_missing: c.passthroughMissing,
    freshness_inputs: c.freshness,
    freshness_digest: c.freshnessDigest,
    source_id_at_start: before.source_id,
    source_id_at_end: after?.source_id ?? null,
    source_stable: stable,
    started_at: new Date(o.startedAtMs).toISOString(),
    ended_at: new Date(o.startedAtMs + o.durationMs).toISOString(),
    duration_ms: o.durationMs,
    exit_code: o.exitCode,
    pid: o.pid,
    timed_out: o.timedOut,
    cancelled: o.cancelled,
    stdout: { bytes: o.stdoutBytes, stored_bytes: o.stdout.length, truncated: o.stdoutTruncated, artifact: stdoutRef },
    stderr: { bytes: o.stderrBytes, stored_bytes: o.stderr.length, truncated: o.stderrTruncated, artifact: stderrRef },
    stdio_held_after_exit: o.stdioHeldAfterExit,
    descendants: o.descendants,
    limitations,
    ...(cancellation ? { cancellation } : {}),
  };
  const resultRef = (
    await publishArtifact(
      ctx.runPaths.runDir,
      ctx.runPaths.opsDir,
      operationId,
      `${dir}/result.json`,
      JSON.stringify({ record, command_line: c.commandLine, stdout_tail: decodeTail(o.stdoutTail), stderr_tail: decodeTail(o.stderrTail) }, null, 2),
    )
  ).ref;
  return CheckExecutionRecordSchema.parse({ ...record, result_artifact: resultRef });
}

async function commitExecution(ctx: ChecksEngineContext, operationId: string, rec: CheckExecutionRecord): Promise<void> {
  await commitState(ctx.runPaths, ctx.owner, (st) => {
    st.check_executions.push(rec);
    if (rec.status !== "skipped") st.counters["check_executions"] = (st.counters["check_executions"] ?? 0) + 1;
    const op = st.operations.find((o) => o.operation_id === operationId);
    if (op) delete op["child"];
    pushEvent(st, "check.finished", `${rec.check}: ${rec.status}${rec.skip_reason ? ` (${rec.skip_reason})` : ""}`, { operation_id: operationId, execution_id: rec.execution_id });
    return st;
  });
}

/** Termination of every killed tree is established only if each one's record established it. */
function combineTermination(records: readonly CancellationRecord[]): TerminationCheck {
  const established = records.every((c) => c.outcome === "terminated");
  return {
    established,
    survivors: records.flatMap((c) => c.survivors),
    unattributable: records.flatMap((c) => c.unattributable),
    reason: established ? records.map((c) => c.detail).join("; ") : records.filter((c) => c.outcome !== "terminated").map((c) => c.detail).join("; "),
  };
}

function aggregateStatus(execs: readonly CheckExecutionRecord[], opStatus: string): ChecksOperationResult["status"] {
  if (opStatus === "cancelled" || execs.some((e) => e.status === "cancelled")) return "cancelled";
  if (opStatus === "error" || execs.some((e) => e.status === "error")) return "error";
  if (execs.some((e) => e.status === "timed_out")) return "timed_out";
  if (execs.some((e) => e.status === "failed")) return "failed";
  if (execs.some((e) => e.status === "skipped")) return "error";
  return "passed";
}

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor: "check", summary: summary.slice(0, 500), refs });
}

function decodeTail(b: Buffer): string {
  return b.toString("utf8").replace(/^�+/, "");
}

// ---------------------------------------------------------------------------
// Reporting: freshness, floor, conditions
// ---------------------------------------------------------------------------

/** Compute the current identity parts for each named check (I/O: resolution, env, files). */
export async function currentCheckInputs(ctx: ChecksEngineContext, trusted: TrustedState, names: Iterable<string>): Promise<Map<string, CurrentCheckInputs>> {
  const out = new Map<string, CurrentCheckInputs>();
  for (const name of new Set(names)) {
    const c = trusted.evaluation.checks.get(name);
    if (!c) {
      out.set(name, { check: name, state: "removed", definitionDigest: null, checkSpecId: null, envDigest: null, freshnessDigest: null, executionInputId: null });
      continue;
    }
    if (!isRunnable(trusted.evaluation, name) || !c.definition || !c.digest) {
      out.set(name, { check: name, state: "unapproved", definitionDigest: c.digest, checkSpecId: null, envDigest: null, freshnessDigest: null, executionInputId: null });
      continue;
    }
    const p = await prepareCheck(name, c.definition, c.digest, { repoRoot: ctx.meta.repository_root, sourceEnv: ctx.sourceEnv ?? process.env });
    if (p.ok) {
      out.set(name, { check: name, state: "runnable", definitionDigest: c.digest, checkSpecId: p.check.checkSpecId, envDigest: p.check.envDigest, freshnessDigest: p.check.freshnessDigest, executionInputId: p.check.executionInputId });
    } else {
      out.set(name, { check: name, state: "runnable", definitionDigest: c.digest, checkSpecId: null, envDigest: p.partial.envDigest, freshnessDigest: p.partial.freshnessDigest, executionInputId: null });
    }
  }
  return out;
}

export interface ChecksStatus {
  floor: FloorEvaluation;
  /** Status of every check that has executions or is required. */
  checks: CheckStatusView[];
  conditions: CheckCondition[];
  limitations: Limitation[];
  trusted_status: string;
}

/**
 * Evaluate check evidence against `currentSourceId` (null = unknown) and the trusted
 * configuration, environment and freshness inputs as they are NOW (plan §10.4).
 */
export async function evaluateChecksStatus(ctx: ChecksEngineContext, currentSourceId: string | null, state?: StateRecord): Promise<ChecksStatus> {
  const st = state ?? (await readState(ctx.runPaths));
  const trusted = await loadTrustedState(ctx);
  const runFloor = runFloorOf(ctx.meta);
  const requirements = effectiveRequirements(runFloor, trusted.view);
  const names = new Set<string>([...requirements.map((r) => r.check), ...st.check_executions.map((e) => e.check)]);
  const current = await currentCheckInputs(ctx, trusted, names);
  const floor = evaluateFloor(trusted.view.floorConfigured || (runFloor?.no_required_checks ?? false), trusted.view.noRequiredChecks || (runFloor?.no_required_checks ?? false), requirements, st.check_executions, currentSourceId, current);
  const required = new Set(requirements.map((r) => r.check));
  const optional: CheckStatusView[] = [...names]
    .filter((n) => !required.has(n))
    .map((n) => ({ ...checkStatus(n, st.check_executions, currentSourceId, current.get(n)), required: false, required_by: [], definition_changed_since_floor: false }));
  const limitations: Limitation[] = [
    { code: "environment_bound_partial", detail: "check freshness binds the check definition, resolved executable, child environment and configured freshness inputs only; other tools, services and network content are not bound" },
    { code: "checks_unsandboxed", detail: "approved checks run repository code with the user's privileges, outside any sandbox; Codex isolation guarantees do not apply to them" },
  ];
  if (!floor.configured) limitations.push({ code: "verification_floor_unconfigured", detail: `no verification floor is configured for this repository (trusted configuration: ${trusted.view.status})` });
  if (floor.removed.length) limitations.push({ code: "required_check_removed", detail: `required checks no longer defined in trusted configuration: ${floor.removed.join(", ")}` });
  if (floor.unapproved.length) limitations.push({ code: "required_check_unapproved", detail: `required checks not currently approved: ${floor.unapproved.join(", ")}` });
  return { floor, checks: [...floor.checks, ...optional], conditions: deriveCheckConditions(floor, optional), limitations, trusted_status: trusted.view.status };
}

/** Build the operation result from the committed state and artifacts. */
export async function buildResult(ctx: ChecksEngineContext, operationId: string): Promise<ChecksOperationResult> {
  const st = await readState(ctx.runPaths);
  const op = st.operations.find((o) => o.operation_id === operationId);
  if (!op) throw new DomainError("RUN_NOT_FOUND", `operation ${operationId} not found`);
  const execs = st.check_executions.filter((e) => e.operation_id === operationId);
  const results: ChecksResultItem[] = [];
  for (const e of execs) {
    let tails = { stdout_tail: "", stderr_tail: "" };
    if (e.result_artifact) {
      const raw = await readTextIfExists(resolveArtifact(ctx.runPaths.runDir, e.result_artifact)).catch(() => null);
      if (raw) {
        try {
          const j = JSON.parse(raw) as { stdout_tail?: string; stderr_tail?: string };
          tails = { stdout_tail: j.stdout_tail ?? "", stderr_tail: j.stderr_tail ?? "" };
        } catch {
          /* tails unavailable */
        }
      }
    }
    results.push({
      check: e.check,
      execution_id: e.execution_id,
      status: e.status,
      skip_reason: e.skip_reason ?? null,
      error: e.error ?? null,
      check_spec_id: e.check_spec_id,
      execution_input_id: e.execution_input_id,
      exit_code: e.exit_code,
      duration_ms: e.duration_ms,
      ...tails,
      stdout_bytes: e.stdout?.bytes ?? 0,
      stderr_bytes: e.stderr?.bytes ?? 0,
      truncated: !!(e.stdout?.truncated || e.stderr?.truncated),
      source_stable: e.source_stable,
    });
  }
  const ran = execs.filter((e) => e.status !== "skipped");
  const startId = execs.find((e) => e.source_id_at_start)?.source_id_at_start ?? null;
  const endId = [...execs].reverse().find((e) => e.source_id_at_end)?.source_id_at_end ?? null;
  const stable = ran.every((e) => e.source_stable) && startId !== null && startId === endId;
  const status = (op.outcome as { status?: ChecksOperationResult["status"] } | undefined)?.status ?? aggregateStatus(execs, op.status);
  const evaluation = await evaluateChecksStatus(ctx, endId, st);
  const limitations: Limitation[] = [...evaluation.limitations];
  for (const e of execs) for (const l of e.limitations) limitations.push({ ...l, detail: `${e.check}: ${l.detail}` });
  const limit = Math.min(ctx.budgets.max_check_executions_per_run, HARD_MAX_EXECUTIONS_PER_RUN);
  const counts = results.reduce<Record<string, number>>((a, r) => ((a[r.status] = (a[r.status] ?? 0) + 1), a), {});
  // An operation-level error (the worktree lock not obtained in time, a failed source read) is
  // shown; with no check run there is no working-tree change to report.
  const opError = (op.outcome as { error?: string } | undefined)?.error ?? null;
  const parts = [
    Object.entries(counts)
      .map(([k, v]) => `${v} ${k}`)
      .join(", "),
    opError ? `operation error: ${opError}` : "",
  ].filter(Boolean);
  const summary =
    `checks ${status}: ${parts.length ? parts.join("; ") : "no check ran"}` +
    `; verification floor ${evaluation.floor.satisfied_for_current_source ? "satisfied" : "NOT satisfied"} for the current source` +
    (stable || ran.length === 0 ? "" : "; the working tree changed during the checks") +
    ". A passing check is necessary evidence, not proof that a reported problem is absent.";
  return {
    summary,
    operation_id: operationId,
    operation_status: op.status,
    status,
    execution_ids: execs.map((e) => e.execution_id),
    results,
    source_id_at_start: startId,
    source_id_at_end: endId,
    stable,
    floor: evaluation.floor,
    conditions: evaluation.conditions,
    limitations,
    budgets: [{ name: "check_executions", used: st.counters["check_executions"] ?? 0, limit }],
    cancellation: (op.outcome as { cancellation?: CancellationRecord } | undefined)?.cancellation ?? null,
  };
}
