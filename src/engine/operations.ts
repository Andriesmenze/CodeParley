// Operations as the MCP layer sees them (plan §5.4, §11, MR-E, MR-J; M1.5). This is the ONE
// job system: it starts the engine's existing operations (prepare, checks, review), bounds
// how long a caller waits for them, and cancels them only on explicit, targeted request.
//
//  - Waiting is observation: a call's own cancellation (Esc, a host timeout) ends the wait
//    and nothing else (D-27). Operations keep running and keep their handle.
//  - Cancellation targets `expected_operation_id`. A request for an operation that already
//    ended returns that operation's outcome; a different active operation is never touched
//    (OPERATION_MISMATCH). The request is committed to the run state first, so it reaches
//    the owner even when the owner is another server process (each server watches the
//    operations it owns). `terminated` comes only from the engine's termination evidence
//    (the cancellation record the operation committed); otherwise `cancellation_requested`.
//  - Stop is always allowed (R-32), including on a run whose scope was revoked.

import { DomainError } from "../common/errors.js";
import { applyRecovery, planRecovery } from "../store/recovery.js";
import { aliveIfOwnInstance, classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type OwnerRecord } from "../store/owner.js";
import { canonicalPathKey, worktreeLockPath } from "../store/paths.js";
import { commitState, readState } from "../store/state-store.js";
import type { CancellationRecord } from "../schemas/review.js";
import type { Operation, StateRecord } from "../schemas/run-state.js";
import { buildResult, ownedChecksOperations, requestChecksCancel, startChecks, waitForOperation, type ChecksOperationResult, type ChecksRequest } from "./checks-operation.js";
import { buildReviewResult, ownedReviewOperations, requestReviewCancel, startReview, waitForReview, type KnownSource, type ReviewOperationResult, type ReviewRequest } from "./review-operation.js";
import { ownedPrepareOperations, prepareResult, requestPrepareCancel, waitForPrepare, type PrepareResult } from "./runs.js";
import { endCustodianLoopWithRun, endLoopWithRun } from "./continuation.js";
import type { CustodianSurface } from "../custodian/protocol.js";
import { checksContext, evidenceSelection, reviewContext, type Loaded, type RunHandle } from "./engine-env.js";
import { establishCustodianEnd, reconcileCustodianRun, type CustodianEndResult, type PendingEnd } from "./custodian-evidence.js";
import { locallyProtected } from "./protected-user-records.js";
import { destroyRunWorkspaces } from "../workspace/disposable-workspace.js";

const TERMINAL = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

export type OperationResult = { kind: "prepare"; result: PrepareResult } | { kind: "checks"; result: ChecksOperationResult } | { kind: "review"; result: ReviewOperationResult };

export interface Started {
  operation: Operation;
  deduplicated: boolean;
  completion: Promise<OperationResult>;
}

// ---------------------------------------------------------------------------
// Bounded waits (observation only)
// ---------------------------------------------------------------------------

export type WaitOutcome<T> = { done: true; value: T } | { done: false; why: "timeout" | "call_cancelled" };

/**
 * Wait for `p` until `deadlineMs` (epoch ms) or until `signal` (the CALL's cancellation)
 * fires. Neither ends the operation. `onTick` runs at most every `tickMs` while waiting.
 */
export async function waitBounded<T>(p: Promise<T>, deadlineMs: number, signal: AbortSignal | undefined, onTick?: () => void, tickMs = 10_000): Promise<WaitOutcome<T>> {
  if (signal?.aborted) return { done: false, why: "call_cancelled" };
  const remaining = deadlineMs - Date.now();
  let timer: NodeJS.Timeout | undefined;
  let ticker: NodeJS.Timeout | undefined;
  let onAbort: (() => void) | undefined;
  try {
    return await Promise.race<WaitOutcome<T>>([
      p.then((value) => ({ done: true as const, value })),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve({ done: false, why: "timeout" }), Math.max(0, remaining));
      }),
      new Promise((resolve) => {
        onAbort = () => resolve({ done: false, why: "call_cancelled" });
        signal?.addEventListener("abort", onAbort, { once: true });
      }),
      ...(onTick
        ? [
            new Promise<never>(() => {
              ticker = setInterval(() => {
                try {
                  onTick();
                } catch {
                  /* progress is best effort */
                }
              }, tickMs);
            }),
          ]
        : []),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    if (ticker) clearInterval(ticker);
    if (onAbort) signal?.removeEventListener("abort", onAbort);
  }
}

// ---------------------------------------------------------------------------
// Starting operations (the engine's own start functions; dedupe and idempotency are theirs)
// ---------------------------------------------------------------------------

export async function startChecksOperation(le: Loaded, run: RunHandle, req: ChecksRequest): Promise<Started> {
  const ctx = await checksContext(le, run);
  const s = await startChecks(ctx, req);
  if (!s.deduplicated) watchCancelRequests(le, run, s.operation_id, s.completion);
  return { operation: await operationOf(run, s.operation_id), deduplicated: s.deduplicated, completion: s.completion.then((result) => ({ kind: "checks" as const, result })) };
}

export async function startReviewOperation(le: Loaded, run: RunHandle, req: ReviewRequest): Promise<Started> {
  const ctx = await reviewContext(le, run);
  const s = await startReview(ctx, req);
  if (!s.deduplicated) watchCancelRequests(le, run, s.operation_id, s.completion);
  return { operation: await operationOf(run, s.operation_id), deduplicated: s.deduplicated, completion: s.completion.then((result) => ({ kind: "review" as const, result })) };
}

/** A prepare started by createReviewRun, adapted to the same shape. */
export async function prepareStarted(le: Loaded, run: RunHandle, operationId: string, completion: Promise<PrepareResult>, deduplicated: boolean): Promise<Started> {
  if (!deduplicated) watchCancelRequests(le, run, operationId, completion);
  return { operation: await operationOf(run, operationId), deduplicated, completion: completion.then((result) => ({ kind: "prepare" as const, result })) };
}

async function operationOf(run: RunHandle, operationId: string): Promise<Operation> {
  const st = await readState(run.paths);
  const op = st.operations.find((o) => o.operation_id === operationId);
  if (!op) throw new DomainError("INTERNAL", `operation ${operationId} vanished from the run state`);
  return op;
}

/**
 * The completion of any operation of the run (owned here or by another process). `signal`
 * stops the polling of an operation owned elsewhere once the caller's bounded wait is over
 * (otherwise the poll would outlive the call — and keep a CLI process alive).
 */
export async function completionOf(le: Loaded, run: RunHandle, op: Operation, signal?: AbortSignal): Promise<OperationResult> {
  if (op.kind === "checks") return { kind: "checks", result: await waitForOperation(await checksContext(le, run), op.operation_id, 250, signal) };
  if (op.kind === "review") return { kind: "review", result: await waitForReview(await reviewContext(le, run), op.operation_id, 250, signal) };
  if (op.kind === "prepare") return { kind: "prepare", result: await waitForPrepare(run, op.operation_id, 250, signal) };
  throw new DomainError("INTERNAL", `unknown operation kind ${op.kind}`);
}

/** Wait boundedly for `op` to finish; the poll stops with the wait. */
export async function waitForCompletion(le: Loaded, run: RunHandle, op: Operation, deadlineMs: number, signal: AbortSignal | undefined, onTick?: () => void, tickMs?: number): Promise<WaitOutcome<OperationResult>> {
  const stop = new AbortController();
  try {
    return await waitBounded(completionOf(le, run, op, stop.signal), deadlineMs, signal, onTick, tickMs);
  } finally {
    stop.abort();
  }
}

/**
 * The committed result of a finished (or interrupted) operation. `known`: the caller's own
 * current source identity (or "unavailable"), so a review's freshness now is not read again.
 */
export async function resultOf(le: Loaded, run: RunHandle, op: Operation, known?: KnownSource): Promise<OperationResult> {
  if (op.kind === "checks") return { kind: "checks", result: await buildResult(await checksContext(le, run), op.operation_id) };
  if (op.kind === "review") return { kind: "review", result: await buildReviewResult(await reviewContext(le, run), op.operation_id, undefined, known) };
  if (op.kind === "prepare") return { kind: "prepare", result: await prepareResult(run, op.operation_id) };
  throw new DomainError("INTERNAL", `unknown operation kind ${op.kind}`);
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

function cancelInProcess(kind: string, operationId: string): "cancellation_requested" | "not_owned" {
  if (kind === "checks") return requestChecksCancel(operationId);
  if (kind === "review") return requestReviewCancel(operationId);
  if (kind === "prepare") return requestPrepareCancel(operationId);
  return "not_owned";
}

/**
 * Watch the run state for a committed cancellation request of an operation this process
 * owns (it may have been committed by another server process) until the operation ends.
 */
function watchCancelRequests(le: Loaded, run: RunHandle, operationId: string, completion: Promise<unknown>): void {
  let done = false;
  void completion.finally(() => {
    done = true;
  });
  const tick = async () => {
    if (done) return;
    const st = await readState(run.paths).catch(() => null);
    const op = st?.operations.find((o) => o.operation_id === operationId);
    if (!op || op.status !== "running") {
      done = true;
      return;
    }
    if (op["cancel_requested"]) cancelInProcess(op.kind, operationId);
  };
  const timer = setInterval(() => {
    if (done) {
      clearInterval(timer);
      return;
    }
    void tick();
  }, le.env.testHooks?.cancelPollMs ?? 1000);
  timer.unref?.();
}

/** Mark dead owners' operations interrupted (plan §15.5) before deciding anything. */
export async function recoverRun(le: Loaded, run: RunHandle): Promise<void> {
  const st = await readState(run.paths);
  if (!st.operations.some((o) => o.status === "running")) return;
  const classify = aliveIfOwnInstance(le.env.owner, le.env.testHooks?.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)));
  const plan = await planRecovery(st, classify);
  if (plan.changed) await applyRecovery(run.paths, le.env.owner, plan, worktreeLockPath(le.dataHome, canonicalPathKey(run.meta.repository_root)));
}

/** Local recovery, then the custodian's record of a protected run (P3.4C-3 §5.2). */
async function recoverAll(le: Loaded, run: RunHandle): Promise<void> {
  await recoverRun(le, run);
  await reconcileCustodianRun(evidenceSelection(le, run), run.paths, le.env.owner);
}

/** The run ended locally (a reduction): the custodian's `end` follows, or stays pending (P3.4C-3 §5.4). The run's
 * delegated-fix workspaces go with it (Phase 4: a fixer killed mid-run leaves its workspace behind). */
async function endWithCustodian(le: Loaded, run: RunHandle, end: PendingEnd, surfaces: readonly CustodianSurface[]): Promise<CustodianEndResult> {
  const result = await establishCustodianEnd(evidenceSelection(le, run), run.paths, le.env.owner, end, surfaces);
  await destroyRunWorkspaces(le.dataHome, run.runId).catch(() => undefined);
  return result;
}

/** In the local stop's commit: mark the custodian's end pending for a run marked protected. */
function markEndPending(st: StateRecord, end: PendingEnd): void {
  if (locallyProtected(st) && !st.custodian_end_pending) st.custodian_end_pending = { status: end.status, reason: end.reason.slice(0, 500) };
}

export type StopMode = "cancel_active" | "abort" | "close";

export interface CancellationView {
  operation_id: string;
  kind: string;
  outcome: "cancellation_requested" | "terminated" | "already_finished";
  /** The operation's status when this call returned. */
  operation_status: string;
  /** The engine's termination evidence, when the operation committed one. */
  record: CancellationRecord | null;
  detail: string;
}

export interface StopOutcome {
  state: StateRecord;
  cancellation: CancellationView | null;
  /** What the custodian said about ending the run (null: this stop does not end a run). `state` is the local record. */
  custodian_end: CustodianEndResult | null;
}

export interface StopOptions {
  /** Who asked, for the run's events: the host model (MCP) or the user (CLI `runs stop`). */
  actor?: "host" | "user_cli";
  /** The custodian surfaces to try for the run's end, in order. The host's stop_review_loop stays on the implementer's. */
  custodianSurfaces?: readonly CustodianSurface[];
}

/** The committed cancellation record of an operation (checks/prepare outcome, or its review). */
function cancellationOf(st: StateRecord, op: Operation): CancellationRecord | null {
  const oc = op.outcome as { cancellation?: CancellationRecord; review_id?: string } | undefined;
  if (oc?.cancellation) return oc.cancellation;
  const reviewId = oc?.review_id ?? (op["review_id"] as string | undefined);
  return (reviewId ? st.reviews.find((r) => r.review_id === reviewId)?.cancellation : null) ?? null;
}

function finishedView(st: StateRecord, op: Operation, requestedByThisCall: boolean): CancellationView {
  const record = cancellationOf(st, op);
  if (op.status === "running") {
    return { operation_id: op.operation_id, kind: op.kind, outcome: "cancellation_requested", operation_status: "running", record: null, detail: "cancellation was requested; the operation has not ended yet (poll get_review_status). Termination is reported only on evidence." };
  }
  if (requestedByThisCall && record) {
    return {
      operation_id: op.operation_id,
      kind: op.kind,
      outcome: record.outcome,
      operation_status: op.status,
      record,
      detail: record.outcome === "terminated" ? `the process tree is confirmed gone: ${record.detail}` : `termination was NOT established: ${record.detail}`,
    };
  }
  return {
    operation_id: op.operation_id,
    kind: op.kind,
    outcome: "already_finished",
    operation_status: op.status,
    record,
    detail: requestedByThisCall ? `the operation ended (${op.status}) before the cancellation took effect` : `the operation had already ended (${op.status}); nothing was cancelled`,
  };
}

/**
 * stop_review_loop (plan §11.8). `waitMs` bounds how long this call waits for a cancelled
 * operation to commit its termination evidence; `signal` (the call's own cancellation) ends
 * only that wait — the committed request stands.
 */
export async function stopRun(le: Loaded, run: RunHandle, mode: StopMode, expected: string | undefined, reason: string | undefined, waitMs: number, signal?: AbortSignal, opts: StopOptions = {}): Promise<StopOutcome> {
  const actor = opts.actor ?? "host";
  await recoverAll(le, run);
  const st0 = await readState(run.paths);
  const endOf = (status: PendingEnd["status"]): PendingEnd => ({ status, reason: reason?.trim() ? reason.trim() : `${status === "closed" ? "closed" : "stopped"} by ${actor === "user_cli" ? "the user" : "the implementer"}` });
  const active = st0.operations.find((o) => o.status === "running") ?? null;
  const surfaces = opts.custodianSurfaces ?? (["implementer"] as const);

  if (mode === "close") {
    if (active) throw new DomainError("RUN_BUSY", `run has an active ${active.kind} operation ${active.operation_id}; cancel it first (stop_review_loop cancel_active with expected_operation_id)`, { retryable: true, details: { operation_id: active.operation_id } });
    // A terminal local record is a cache, not the custodian's answer: the end is still asked for.
    if (TERMINAL.has(st0.state)) return { state: st0, cancellation: null, custodian_end: await endWithCustodian(le, run, st0.custodian_end_pending ?? endOf("closed"), surfaces) };
    const state = await commitState(run.paths, le.env.owner, (st) => {
      if (st.operations.some((o) => o.status === "running")) throw new DomainError("RUN_BUSY", "an operation started while closing; cancel it first", { retryable: true });
      if (!TERMINAL.has(st.state)) st.state = "CLOSED";
      pushEvent(st, "run.closed", `run closed${reason ? `: ${reason.slice(0, 300)}` : ""}`, {}, actor);
      endLoopWithRun(st, "run_closed");
      markEndPending(st, endOf("closed"));
      return st;
    });
    const custodian_end = await endWithCustodian(le, run, endOf("closed"), surfaces);
    await endCustodianLoopWithRun(le, run, state, "run_closed");
    return { state, cancellation: null, custodian_end };
  }

  if (mode === "cancel_active" && !expected) throw new DomainError("INVALID_ARGUMENT", "expected_operation_id is required for cancel_active (MR-E)");
  let target: Operation | null;
  if (expected) {
    target = st0.operations.find((o) => o.operation_id === expected) ?? null;
    if (!target) throw new DomainError("OPERATION_MISMATCH", `operation ${expected} is not an operation of this run${active ? `; the active operation is ${active.operation_id}` : ""}`, { details: { expected_operation_id: expected, active_operation_id: active?.operation_id ?? null } });
    if (target.status !== "running") {
      // Already ended: report its outcome; never touch a newer active operation (MR-E).
      if (mode === "abort") {
        if (active) throw new DomainError("OPERATION_MISMATCH", `operation ${expected} already ended (${target.status}); the active operation is ${active.operation_id} and was not cancelled`, { details: { expected_operation_id: expected, active_operation_id: active.operation_id } });
        const state = await commitState(run.paths, le.env.owner, (st) => abortState(st, reason, actor, endOf("stopped")));
        const custodian_end = await endWithCustodian(le, run, endOf("stopped"), surfaces);
        await endCustodianLoopWithRun(le, run, state, "run_stopped");
        return { state, cancellation: finishedView(state, target, false), custodian_end };
      }
      return { state: st0, cancellation: finishedView(st0, target, false), custodian_end: null };
    }
  } else {
    target = active; // abort without an expected id: whatever is active now
  }

  // Commit the request (and, for abort, STOPPED) before anything is cancelled: a retry, a
  // crash or another server sees it; no new operation can start on a STOPPED run.
  const now = new Date().toISOString();
  const state1 = await commitState(run.paths, le.env.owner, (st) => {
    const op = target ? st.operations.find((o) => o.operation_id === target!.operation_id) : undefined;
    const curActive = st.operations.find((o) => o.status === "running");
    if (target && op && op.status !== "running") {
      // The target ended since it was read: its outcome is reported (below); a newer
      // operation is never touched (MR-E). abort with an explicit, ended target and a
      // different active operation is refused rather than stopping the newer one.
      if (mode === "abort" && curActive) throw new DomainError("OPERATION_MISMATCH", `operation ${op.operation_id} already ended (${op.status}); the active operation is ${curActive.operation_id} and was not cancelled`, { details: { expected_operation_id: op.operation_id, active_operation_id: curActive.operation_id } });
      return mode === "abort" ? abortState(st, reason, actor, endOf("stopped")) : st;
    }
    if (target && curActive && curActive.operation_id !== target.operation_id) {
      throw new DomainError("OPERATION_MISMATCH", `the active operation is ${curActive.operation_id}, not ${target.operation_id}; nothing was cancelled`, { details: { expected_operation_id: target.operation_id, active_operation_id: curActive.operation_id } });
    }
    if (op && op.status === "running" && !op["cancel_requested"]) {
      op["cancel_requested"] = { at: now, by: le.env.owner.serverInstanceId, mode, ...(reason ? { reason: reason.slice(0, 500) } : {}) };
      pushEvent(st, "operation.cancel_requested", `cancellation requested for ${op.kind} operation ${op.operation_id.slice(0, 8)} (${mode})`, { operation_id: op.operation_id }, actor);
    }
    return mode === "abort" ? abortState(st, reason, actor, endOf("stopped")) : st;
  });
  let custodian_end: CustodianEndResult | null = null;
  if (mode === "abort") {
    custodian_end = await endWithCustodian(le, run, endOf("stopped"), surfaces);
    await endCustodianLoopWithRun(le, run, state1, "run_stopped");
  }
  if (!target) return { state: state1, cancellation: null, custodian_end };
  const opNow = state1.operations.find((o) => o.operation_id === target!.operation_id)!;
  if (opNow.status !== "running") return { state: state1, cancellation: finishedView(state1, opNow, false), custodian_end };

  cancelInProcess(target.kind, target.operation_id); // owned here: at once; else the owner's watcher
  await waitForCompletion(le, run, opNow, Date.now() + waitMs, signal).catch(() => null);
  const st2 = await readState(run.paths);
  const opEnd = st2.operations.find((o) => o.operation_id === target!.operation_id)!;
  return { state: st2, cancellation: finishedView(st2, opEnd, true), custodian_end };
}

function abortState(st: StateRecord, reason: string | undefined, actor: "host" | "user_cli", end: PendingEnd): StateRecord {
  if (!TERMINAL.has(st.state)) {
    st.state = "STOPPED";
    pushEvent(st, "run.stopped", `run aborted${reason ? `: ${reason.slice(0, 300)}` : ""}`, {}, actor);
    endLoopWithRun(st, "run_stopped");
    markEndPending(st, end);
  } else if (st.custodian_end_pending) {
    st.custodian_end_pending = { status: end.status, reason: end.reason.slice(0, 500) }; // a refused close gives way to the abort
  }
  return st;
}

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>, actor: "host" | "user_cli"): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor, summary: summary.slice(0, 500), refs });
}

// ---------------------------------------------------------------------------
// Shutdown (stdin closed): cancel what this process owns, wait boundedly for evidence
// ---------------------------------------------------------------------------

export async function cancelOwnedOperations(waitMs: number): Promise<number> {
  const all = [
    ...ownedChecksOperations().map((o) => ({ ...o, kind: "checks" })),
    ...ownedReviewOperations().map((o) => ({ ...o, kind: "review" })),
    ...ownedPrepareOperations().map((o) => ({ ...o, kind: "prepare" })),
  ];
  for (const o of all) cancelInProcess(o.kind, o.operationId);
  await waitBounded(Promise.allSettled(all.map((o) => o.completion)), Date.now() + waitMs, undefined);
  return all.length;
}
