// Same-session continuation: the engine's controller (Phase 3.3a; P3.4C-2).
//
// The trusted side of the Claude Code continuation adapter. The hooks (src/hooks/) only collect
// host facts and print what this module decides; every rule lives here and in the pure policy
// (policy/continuation.ts):
//  - a run's LOOP: since P3.4C-2 the Windows CUSTODIAN owns it. start_review_loop asks the custodian,
//    which consumes one loop of an operator grant AND mints the run's loop record in one atomic write
//    (one loop per run, never resurrected); the custodian holds the loop's status, epoch, budgets,
//    deadline, the binding verdict, operation handles and wake claims, and computes every transition.
//    The run's own `state.continuation` is a CACHE of it plus what the custodian does not own (the
//    session correlation, the turn, interrupts, the last continuation, the waiter bookkeeping); every
//    decision overlays the custodian's authority onto it first (engine/custodian-loop.ts);
//  - the BINDING of a loop to the host session that received start_review_loop's result: the host's
//    PostToolUse hook supplies the session id, the result supplies the custodian's one-time nonce; the
//    custodian binds (first binding wins) and re-binds a resumed session in a new epoch; SessionEnd
//    closes the local binding when delivered;
//  - the PROCESS IDENTITY of that session: CLAUDE_PID, which the custodian checks itself (running, an
//    ancestor of the process connected to it) at bind and re-bind. Automation needs it verified and
//    unchanged; a missing, stale or inconsistent identity refuses every continuation and wake;
//  - CONTINUATIONS (Stop; the custodian spends each), idle WAKES (the asyncRewake waiter; the custodian
//    reserves a one-shot claim at arming and alone authorizes the dispatch), PAUSES (interrupts, the
//    user-decision hard pause, settings changes, operations that did not complete), the DEADLINE,
//    and the session index the hooks look bindings up in.
// Every decision is derived from CodeParley's own records — the derived completion, the run's
// operations and budgets — never from model narration, hook text, transcript text or a claim. The
// transcript is read only for the host's interrupt marker, and only ever to pause.
//
// Trust: the engine is an untrusted client of the custodian. A same-user process can edit the local
// cache, forge hook input or run the hook entry itself — which changes no budget, epoch, pause or
// binding the custodian holds; session ids and the process check stay correlation, not credentials
// (no L2/L3 claim). That limit is documented, not hidden (P3.3a result §8; P3.4C-2 contract §5).

import { mkdir } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DomainError, isDomainError } from "../common/errors.js";
import { isUuid, uuidv7 } from "../common/ids.js";
import { CustodianGrants, deliveryOutcomeOf } from "../custodian/grants.js";
import type { LoopTransitionOutcome, WakeConsumeOutcome } from "../custodian/loops.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import type { ConsumeResult } from "../custodian/protocol.js";
import { snapshotProcessTable } from "../process/proc-table.js";
import { readStatSync } from "../process/linux-proc.js";
import { atomicWriteFile, readTextIfExists } from "../store/atomic.js";
import { classifyOwnerLiveness, identityOf, OWNER_LIVENESS_DEPS, pidAlive, startTimeOf } from "../store/owner.js";
import { REPO_KEY_RE, runPaths } from "../store/paths.js";
import { sessionKey, sessionIndexPath, sessionsDir } from "../store/continuation-paths.js";
import { acquireRunLockWithRetry, commitState, readMeta, readState } from "../store/state-store.js";
import {
  BIND_NONCE_TTL_MS,
  decideStop,
  decideWake,
  identityMatches,
  instructionFor,
  isEnded,
  MAX_LOOP_LIST,
  NOT_USER,
  CONTROLLER_LABEL,
  progressDigest,
  promptKind,
  routeFromEngine,
  statusText,
  transcriptInterruptedSince,
  transitionOf,
  type ArmedWake,
  type LoopTransition,
  type NextAction,
  type OperationFact,
  type RoutingFacts,
  type StopDecision,
  type WakeDecision,
} from "../policy/continuation.js";
import {
  SESSION_INDEX_SCHEMA,
  SessionIndexSchema,
  type CustodianLoop,
  type LoopRecord,
  type PauseReason,
  type ProcessIdentity,
  type SessionIndex,
  type WakeRecord,
} from "../schemas/continuation.js";
import type { Operation, StateRecord } from "../schemas/run-state.js";
import { cacheOf, currentHandle, overlay, readCustodianDerivation, readCustodianLoop, recallNonce, refusalText, rememberNonce, requestEnd, requestPause, requestTransition, requestWakeConsume, reservedWakes, routeOfDerivation } from "./custodian-loop.js";
import { openCustodianRun } from "./custodian-run.js";
import { currentSource, knownSourceOf, observedState, runReport, SOURCE_BUDGET_MS, type RunReport, type SourceNow } from "./status.js";
import { withAuthoritativeUserRecords } from "./protected-user-records.js";
import type { Loaded, RunHandle } from "./engine-env.js";

const TERMINAL_RUN = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

/** TEST ONLY: identity, liveness and clock injected into the controller. */
export interface ContinuationTestHooks {
  identity?: (hp: HookProcess) => Promise<ProcessIdentity>;
  /** Is the bound process still the process that bound (full: start identity too)? */
  processAlive?: (p: ProcessIdentity, full: boolean) => Promise<boolean>;
  now?: () => number;
  /** Runs between a Stop decision's routing read and its commit (an operation may finish there). */
  afterRoute?: () => Promise<void>;
  /** P3.4C-5 Increment 4: how long SessionStart waits for the custodian's derivation (default SESSION_START_DERIVATION_MS). */
  sessionStartDerivationMs?: number;
  /** P3.4C-0: runs after the custodian consumed a granted loop, before the loop record is committed (a
   * failure here stands for a crash between the two). */
  afterConsume?: () => Promise<void>;
}

/** What a hook knows about its own process: the host's CLAUDE_PID and its own pid. */
export interface HookProcess {
  claudePid: number | null;
  hookPid: number;
}

/** Host facts every hook passes in (from the hook input and environment). */
export interface HookFacts extends HookProcess {
  session_id: string;
  transcript_path: string | null;
}

function nowMsOf(le: Loaded): number {
  return le.env.testHooks?.continuation?.now?.() ?? Date.now();
}
const isoOf = (ms: number): string => new Date(ms).toISOString();

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>, actor: "engine" | "host" = "engine"): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor, summary: summary.slice(0, 500), refs });
}

function capped<T>(list: T[], item: T): void {
  list.push(item);
  if (list.length > MAX_LOOP_LIST) list.splice(0, list.length - MAX_LOOP_LIST);
}

// ---------------------------------------------------------------------------
// Locations: the session index (lookup hints, verified against the run)
// ---------------------------------------------------------------------------

export { continuationDir, sessionKey, sessionIndexPath } from "../store/continuation-paths.js";

export async function readSessionIndex(dataHome: string, sessionId: string): Promise<SessionIndex | null> {
  const raw = await readTextIfExists(sessionIndexPath(dataHome, sessionId)).catch(() => null);
  if (raw === null) return null;
  try {
    const idx = SessionIndexSchema.parse(JSON.parse(raw));
    return idx.session_id === sessionId ? idx : null;
  } catch {
    return null;
  }
}

async function writeSessionIndex(dataHome: string, idx: SessionIndex): Promise<void> {
  await atomicWriteFile(sessionIndexPath(dataHome, idx.session_id), JSON.stringify(idx, null, 2));
}

/** Serialize binding changes of one session (bind, re-bind, hand-over). */
async function withSessionLock<T>(le: Loaded, sessionId: string, fn: () => Promise<T>): Promise<T> {
  const dir = sessionsDir(le.dataHome);
  await mkdir(dir, { recursive: true });
  const lock = await acquireRunLockWithRetry(join(dir, `${sessionKey(sessionId)}.lock`), le.env.owner, { ...(le.env.testHooks?.lockDeps ? { lockDeps: le.env.testHooks.lockDeps } : {}), lockAcquireMs: 10_000 });
  try {
    return await fn();
  } finally {
    await lock.release();
  }
}

/** A run named by repository key and id (both validated: never a path from input). */
async function runOf(le: Loaded, repoKey: string, runId: string): Promise<RunHandle | null> {
  if (!REPO_KEY_RE.test(repoKey) || !isUuid(runId)) return null;
  const paths = runPaths(le.dataHome, repoKey, runId);
  const meta = await readMeta(paths).catch(() => null);
  return meta && meta.run_id === runId ? { runId, repoKey, paths, meta } : null;
}

export interface BoundRun {
  run: RunHandle;
  st: StateRecord;
  loop: LoopRecord;
}

/** The run whose loop names this session (any binding state), verified against the run's record. */
export async function boundRunOf(le: Loaded, sessionId: string): Promise<BoundRun | null> {
  const idx = await readSessionIndex(le.dataHome, sessionId);
  if (!idx) return null;
  const run = await runOf(le, idx.repo_key, idx.run_id);
  if (!run) return null;
  const st = await readState(run.paths).catch(() => null);
  const loop = st?.continuation;
  if (!st || !loop || loop.loop_id !== idx.loop_id || loop.binding?.session_id !== sessionId) return null;
  return { run, st, loop };
}

// ---------------------------------------------------------------------------
// Process identity (CLAUDE_PID)
// ---------------------------------------------------------------------------

/** Parse CLAUDE_PID as the host passed it (null when absent or not a positive integer). */
export function claudePidOf(env: NodeJS.ProcessEnv): number | null {
  const raw = env["CLAUDE_PID"];
  if (raw === undefined || !/^\d{1,10}$/.test(raw.trim())) return null;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** Is `ancestor` an ancestor of `pid` (parent chain, each created no later than its child)? */
async function isAncestor(ancestor: number, pid: number): Promise<boolean | null> {
  if (process.platform === "linux") {
    let cur = pid;
    for (let depth = 0; depth < 16 && cur > 1; depth++) {
      const s = readStatSync(cur);
      if (!s) return null;
      if (s.ppid === ancestor) return true;
      cur = s.ppid;
    }
    return false;
  }
  const table = await snapshotProcessTable();
  if (!table) return null;
  const byPid = new Map(table.map((e) => [e.pid, e]));
  let cur = byPid.get(pid);
  for (let depth = 0; depth < 16 && cur; depth++) {
    const parent = byPid.get(cur.ppid);
    // A parent created after its child is a reused PID, not the parent.
    if (!parent || (parent.createdMs && cur.createdMs && parent.createdMs > cur.createdMs + 1000)) return false;
    if (parent.pid === ancestor) return true;
    cur = parent;
  }
  return false;
}

/** Capture and verify the session's process identity from a hook (bind and re-bind). */
export async function captureIdentity(le: Loaded, hp: HookProcess): Promise<ProcessIdentity> {
  const injected = le.env.testHooks?.continuation?.identity;
  if (injected) return injected(hp);
  const pid = hp.claudePid;
  if (pid === null) return { pid: null, started_at_ms: null, verified: false, detail: "CLAUDE_PID was not set for the hook" };
  if (!pidAlive(pid)) return { pid, started_at_ms: null, verified: false, detail: `CLAUDE_PID ${pid} is not a running process` };
  const startIdentity = identityOf(pid);
  const started = await startTimeOf(pid).catch(() => null);
  const ancestor = await isAncestor(pid, hp.hookPid).catch(() => null);
  const base = { pid, started_at_ms: started, ...(startIdentity ? { start_identity: startIdentity } : {}) };
  if (started === null) return { ...base, verified: false, detail: `the start time of process ${pid} could not be read` };
  if (ancestor === null) return { ...base, verified: false, detail: "the process table could not be read to check the hook's ancestry" };
  if (!ancestor) return { ...base, verified: false, detail: `CLAUDE_PID ${pid} is not an ancestor of the hook process` };
  return { ...base, verified: true, detail: `process ${pid}, an ancestor of the hook, started ${new Date(started).toISOString()}` };
}

/** Is the bound process still alive — and, when `full`, still the same process instance (no PID reuse)? */
export async function processStillAlive(le: Loaded, p: ProcessIdentity | null, full: boolean): Promise<boolean> {
  if (!p || p.pid === null || p.started_at_ms === null) return false;
  const injected = le.env.testHooks?.continuation?.processAlive;
  if (injected) return injected(p, full);
  if (!pidAlive(p.pid)) return false;
  if (!full) return true;
  const l = await classifyOwnerLiveness({ serverInstanceId: "claude", pid: p.pid, startedAtMs: p.started_at_ms, ...(p.start_identity ? { startIdentity: p.start_identity } : {}) }, OWNER_LIVENESS_DEPS);
  return l === "alive"; // "alive_unconfirmed" is not enough to wake anything
}

// ---------------------------------------------------------------------------
// Routing from the engine's records
// ---------------------------------------------------------------------------

export interface Routed {
  route: NextAction;
  digest: string;
  report: RunReport;
  src: SourceNow | null;
}

/**
 * An operation as routing and wakes judge it. A review's OPERATION completes even when its Codex
 * turn failed or timed out: the review record's status (in the outcome) is what happened.
 */
export function operationFactOf(o: Operation): OperationFact {
  const review = o.kind === "review" && o.status === "completed" ? (o.outcome as { status?: unknown } | undefined)?.status : undefined;
  return { kind: o.kind, operation_id: o.operation_id, status: typeof review === "string" ? review : o.status, started_at: o.started_at, ended_at: o.ended_at };
}

/** Routing facts from a run report and the observed state (shared by status and the hooks). */
export function routingFactsOf(st: StateRecord, observed: StateRecord, report: RunReport, nowIso: string): RoutingFacts {
  const active = observed.operations.find((o) => o.status === "running") ?? null;
  const loop = st.continuation;
  const ack = loop ? (loop.resumed_at && loop.resumed_at > loop.started_at ? loop.resumed_at : loop.started_at) : nowIso;
  const budget = (name: string) => report.budgets.find((b) => b.name === name) ?? { used: 0, limit: Number.MAX_SAFE_INTEGER };
  return {
    run_state: observed.state,
    active_operation: active ? { kind: active.kind, operation_id: active.operation_id } : null,
    operations: observed.operations.map(operationFactOf),
    acknowledged_before: ack,
    completion: { state: report.completion.state, counts: report.completion.counts, blockers: report.completion.blockers },
    budgets: { reviews: budget("reviews"), check_executions: budget("check_executions") },
  };
}

export function digestOf(st: StateRecord, report: RunReport, sourceId: string | null): string {
  return progressDigest({
    completion_state: report.completion.state,
    blockers: report.completion.blockers.map((b) => b.code),
    source_id: sourceId,
    reviews: st.reviews.length,
    responses: st.implementer_responses.length,
    check_executions: st.check_executions.length,
    operations: st.operations.length,
  });
}

/** The engine's next action for a run now: one bounded read of the working tree, the derived completion, the run's operations and budgets. */
export async function routeRun(le: Loaded, run: RunHandle, st: StateRecord, budgetMs: number = SOURCE_BUDGET_MS): Promise<Routed> {
  const { state: observed } = await observedState(le, st);
  const src = await currentSource(le, run, st, budgetMs);
  const report = await runReport(le, run, st, src.source_id, knownSourceOf(src), observed);
  const route = routeFromEngine(routingFactsOf(st, observed, report, isoOf(nowMsOf(le))));
  return { route, digest: digestOf(st, report, knownSourceOf(src) === "unavailable" ? null : src.source_id), report, src };
}

// ---------------------------------------------------------------------------
// Host views
// ---------------------------------------------------------------------------

export const CONTINUATION_NOTE =
  "Automation adds liveness, never authority: CodeParley's controller only keeps this session working within operator-granted budgets, from the engine's own records. needs_user_decision is a hard pause that only the user's own decision (code-parley decide) and the operator's resume end; ready ends automation and authorizes nothing — no commit, push, merge, tag or release.";

export interface LoopView {
  loop_id: string;
  status: LoopRecord["status"];
  pause: { reason: string; detail: string; at: string } | null;
  ended: { status: string; reason: string; at: string } | null;
  started_at: string;
  deadline_at: string;
  seconds_left: number;
  budgets: { continuations: { used: number; limit: number }; wakes: { used: number; limit: number; per_operation: number } };
  binding: { state: string; epoch: number; process_verified: boolean } | null;
  next_action: { code: string; kind: string; reason: string } | null;
  instruction: string | null;
  note: string;
}

export function loopView(runId: string, loop: LoopRecord, route: NextAction | null, nowMs: number): LoopView {
  const live = loop.status === "active" && loop.binding?.state === "live";
  return {
    loop_id: loop.loop_id,
    status: loop.status,
    pause: loop.pause,
    ended: loop.ended,
    started_at: loop.started_at,
    deadline_at: loop.deadline_at,
    seconds_left: Math.max(0, Math.round((Date.parse(loop.deadline_at) - nowMs) / 1000)),
    budgets: { continuations: { used: loop.used.continuations, limit: loop.limits.continuations }, wakes: { used: loop.used.wakes, limit: loop.limits.wakes_per_run, per_operation: loop.limits.wakes_per_operation } },
    binding: loop.binding ? { state: loop.binding.state, epoch: loop.binding.epoch, process_verified: loop.binding.process?.verified === true } : null,
    next_action: route ? { code: route.code, kind: route.kind, reason: route.reason } : null,
    instruction: route && (live || route.kind === "pause" || route.kind === "end") ? instructionFor(runId, route) : statusText(runId, loop, null, nowMs),
    note: CONTINUATION_NOTE,
  };
}

/** The loop view a status report shows (pure observer: nothing is committed). */
export function loopViewOf(le: Loaded, st: StateRecord, observed: StateRecord, report: RunReport): LoopView | null {
  const loop = st.continuation;
  if (!loop) return null;
  const now = nowMsOf(le);
  const route = isEnded(loop.status) ? null : routeFromEngine(routingFactsOf(st, observed, report, isoOf(now)));
  return loopView(st.run_id, loop, route, now);
}

// ---------------------------------------------------------------------------
// start_review_loop: the custodian consumes a granted loop AND mints the run's loop (P3.4C-2)
// ---------------------------------------------------------------------------

export interface StartedLoop {
  loop: LoopRecord;
  /** The one-time binding nonce (null when the loop is already bound or ended). */
  nonce: string | null;
  /** The run already had this loop (no grant was consumed). */
  existing: boolean;
}

const errText = (e: unknown): string => (e instanceof Error ? e.message : String(e)).slice(0, 240);

function lostStartError(runId: string, e: unknown): DomainError {
  return new DomainError(
    "LOOP_START_UNRECONCILED",
    `the custodian may have consumed one of the operator's granted loops and minted this run's automation loop, but its answer did not arrive (${errText(e)}), so the loop's one-time binding nonce is lost and the loop cannot be bound. A run gets one loop, never a second: stop it with \`code-parley loop stop ${runId}\` and automate a new run`,
    { retryable: false, details: { outcome: "unknown" } },
  );
}

function unbindableError(runId: string): DomainError {
  return new DomainError(
    "LOOP_START_UNRECONCILED",
    `this run's automation loop was started but never bound to a session, and its one-time binding nonce can no longer be given out (the custodian returns it once, and this server no longer holds it). A run gets one loop, never a second: stop it with \`code-parley loop stop ${runId}\` and automate a new run`,
    { retryable: false, details: { reason: "unbindable" } },
  );
}

/**
 * Start the run's automation loop (P3.4C-2). The CUSTODIAN decides: in one atomic ledger write it consumes one
 * loop of an operator grant AND mints the run's loop record — idempotently, one loop per run, never resurrected
 * — behind the protected-loop gate (no custodian, no loop; never a weaker source of authority). Crash safety is
 * the custodian's: a start that fails after the custodian minted leaves the custodian's record, which the next
 * start adopts instead of consuming again (no local start marker). The loop is minted unbound; its one-time
 * binding nonce comes back once and is kept only in this process's memory until it expires.
 */
export async function startLoop(le: Loaded, run: RunHandle): Promise<StartedLoop> {
  const st0 = await readState(run.paths);
  if (TERMINAL_RUN.has(st0.state)) throw new DomainError("RUN_TERMINAL", `run is ${st0.state}; no automation loop can start on it`);
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  const existing = await readCustodianLoop(le, run);
  if (existing) return adoptLoop(le, run, existing);
  // P3.4C-3 (§5.5): the custodian registers the run (idempotent on its declaration) before a loop is consumed for it.
  await openCustodianRun(le, run, gate.transport);

  const requestId = uuidv7();
  let use: ConsumeResult;
  try {
    use = await new CustodianGrants(gate.transport).consume(run.meta.repository_root, run.runId, requestId);
  } catch (e) {
    if (isDomainError(e) && e.code === "RUN_ALREADY_HAS_LOOP") {
      const c = await readCustodianLoop(le, run);
      if (c) return adoptLoop(le, run, c);
    }
    if (deliveryOutcomeOf(e) === "unknown") throw lostStartError(run.runId, e);
    throw e;
  }
  if (use.bindNonce) rememberNonce(run, use.loopId, use.bindNonce, nowMsOf(le) + BIND_NONCE_TTL_MS - 2_000);
  await le.env.testHooks?.continuation?.afterConsume?.();
  const c = await readCustodianLoop(le, run);
  if (!c) throw new DomainError("INTERNAL", "the custodian consumed a granted loop for this run but reports no loop for it");
  const loop = await recordLoop(le, run, c, requestId);
  if (isEnded(loop.status)) {
    // The operator stopped this run's automation while it was starting (the consumed loop stays spent).
    throw new DomainError("LOOP_NOT_AUTHORIZED", `the operator stopped this run's automation while it was starting; nothing was started (loop ${c.loopId.slice(0, 8)} of grant ${c.grantId.slice(0, 8)} was consumed and is spent)`);
  }
  return { loop, nonce: use.bindNonce, existing: false };
}

/** The run already has its custodian loop: adopt it (one loop per run, ever). An unbound one can be bound only
 * with the nonce this process still holds from the start that minted it. */
async function adoptLoop(le: Loaded, run: RunHandle, c: CustodianLoop): Promise<StartedLoop> {
  const loop = await recordLoop(le, run, c, "");
  if (c.status !== "unbound") return { loop, nonce: null, existing: true };
  const nonce = recallNonce(run, c.loopId, nowMsOf(le));
  if (!nonce) throw unbindableError(run.runId);
  return { loop, nonce, existing: true };
}

/** Record the custodian's loop in the run's local cache (created, or refreshed from the custodian). A start
 * marker of P3.4C-0 is superseded by the custodian's record and removed. */
async function recordLoop(le: Loaded, run: RunHandle, c: CustodianLoop, requestId: string): Promise<LoopRecord> {
  let ended = false;
  const st = await commitState(run.paths, le.env.owner, (cur) => {
    delete cur.loop_start;
    if (TERMINAL_RUN.has(cur.state)) {
      ended = true;
      return cur;
    }
    const prior = cur.continuation?.loop_id === c.loopId ? cur.continuation : undefined;
    cur.continuation = prior ? overlay(prior, c) : cacheOf(c, requestId, isoOf(nowMsOf(le)));
    if (!prior) {
      pushEvent(cur, "loop.started", `automation loop of custodian grant ${c.grantId.slice(0, 8)} (loop ${c.grantUse.loopsUsed} of ${c.grantUse.loopsTotal}; continuations ${c.limits.continuations}, wakes ${c.limits.wakesPerRun}, ${c.limits.runSeconds} s); ${c.status === "unbound" ? "waiting for the host to bind it" : c.status}`, { loop_id: c.loopId, grant_id: c.grantId });
    }
    return cur;
  });
  if (ended) {
    await requestEnd(le, run, "run_ended", "the run ended while its loop was starting");
    throw new DomainError("RUN_TERMINAL", `run is ${st.state}; no automation loop can start on it (the custodian's loop for it was ended)`);
  }
  return st.continuation!;
}

// ---------------------------------------------------------------------------
// Binding (PostToolUse on start_review_loop) and re-binding (SessionStart resume)
// ---------------------------------------------------------------------------

export interface BindOutcome {
  ok: boolean;
  reason: string;
  epoch?: number;
}

/** Find run_id / bind_nonce / operation_id in a host tool response, whatever shape the host passes. */
export function resultFieldsOf(resp: unknown): Record<string, unknown> | null {
  const queue: unknown[] = [resp];
  for (let i = 0; i < queue.length && i < 200; i++) {
    const v = queue[i];
    if (typeof v === "string") {
      const t = v.trim();
      if (t.startsWith("{") || t.startsWith("[")) {
        try {
          queue.push(JSON.parse(t));
        } catch {
          /* not JSON */
        }
      }
      continue;
    }
    if (Array.isArray(v)) {
      queue.push(...v);
      continue;
    }
    if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      if (typeof o["run_id"] === "string") return o;
      queue.push(...Object.values(o));
    }
  }
  return null;
}

export async function bindFromResult(le: Loaded, h: HookFacts, toolResponse: unknown): Promise<BindOutcome> {
  const r = resultFieldsOf(toolResponse);
  const runId = typeof r?.["run_id"] === "string" ? r["run_id"] : null;
  const nonce = typeof r?.["bind_nonce"] === "string" ? r["bind_nonce"] : null;
  if (!runId || !nonce) return { ok: false, reason: "the result carries no run and binding nonce" };
  if (!h.session_id) return { ok: false, reason: "the host supplied no session id" };
  const identity = await captureIdentity(le, h);
  return bindLoop(le, { run_id: runId, nonce, session_id: h.session_id, identity });
}

async function findRunAnywhere(le: Loaded, runId: string): Promise<RunHandle | null> {
  if (!isUuid(runId)) return null;
  const { findRun } = await import("./engine-env.js");
  return findRun(le, runId).catch(() => null);
}

export async function bindLoop(le: Loaded, b: { run_id: string; nonce: string; session_id: string; identity: ProcessIdentity }): Promise<BindOutcome> {
  const run = await findRunAnywhere(le, b.run_id);
  if (!run) return { ok: false, reason: "unknown run" };
  return withSessionLock(le, b.session_id, async () => {
    // One live loop per session: a loop that has not ended keeps its session until it ends or the
    // operator cancels it; an ended loop hands the session over (and loses its own access).
    const prior = await boundRunOf(le, b.session_id);
    if (prior && prior.run.runId !== run.runId && prior.loop.binding?.state === "live" && !isEnded(prior.loop.status)) {
      return { ok: false, reason: `this session already has a live loop (run ${prior.run.runId}, ${prior.loop.status})` };
    }
    // P3.4C-2: the CUSTODIAN binds — first bind wins against its one-time nonce, and it checks the session's
    // process itself (the verdict is its, never this hook's).
    const bound = await bindThroughCustodian(le, run, b);
    if (!bound.ok) {
      await commitState(run.paths, le.env.owner, (cur) => {
        if (cur.continuation) pushEvent(cur, "loop.bind_refused", `binding refused: ${bound.reason}`, { loop_id: cur.continuation.loop_id }, "host");
        return cur;
      });
      return { ok: false, reason: bound.reason };
    }
    const c = bound.loop;
    await commitState(run.paths, le.env.owner, (cur) => recordBinding(cur, c, b.session_id, { ...b.identity, verified: bound.verified }, nowMsOf(le)));
    if (!bound.verified) await pauseLoop(le, run, "process_identity", `the custodian could not verify the session's process identity (${b.identity.detail})`);
    if (prior && prior.run.runId !== run.runId && prior.loop.binding?.state === "live") await releaseBinding(le, prior.run, b.session_id, run.runId);
    await writeSessionIndex(le.dataHome, { schema: SESSION_INDEX_SCHEMA, session_id: b.session_id, run_id: run.runId, repo_key: run.repoKey, loop_id: c.loopId, updated_at: isoOf(nowMsOf(le)) });
    return { ok: true, reason: "bound", epoch: c.epoch };
  });
}

type CustodianBind = { ok: true; loop: CustodianLoop; verified: boolean } | { ok: false; reason: string };

/** The local record of the binding the custodian made: the session correlation, with the custodian's verdict. */
function recordBinding(cur: StateRecord, c: CustodianLoop, sessionId: string, process: ProcessIdentity, nowMs: number): StateRecord {
  const at = isoOf(nowMs);
  const local = cur.continuation?.loop_id === c.loopId ? cur.continuation : cacheOf(c, "", at);
  const loop = overlay(local, c);
  loop.binding = { session_id: sessionId, epoch: c.epoch, state: "live", bound_at: at, rebound_at: null, closed_at: null, close_reason: null, process };
  loop.bind_nonce = { ...loop.bind_nonce, used_at: at };
  loop.turn = { active: true, at };
  cur.continuation = loop;
  pushEvent(cur, "loop.bound", `loop bound to the host session that started it (epoch ${c.epoch}; the custodian ${process.verified ? "verified" : "could NOT verify"} the process identity)`, { loop_id: c.loopId });
  return cur;
}

/** An ended loop hands its session over: its local binding is released (and loses the session's access). */
async function releaseBinding(le: Loaded, prior: RunHandle, sessionId: string, toRunId: string): Promise<void> {
  await commitState(prior.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (loop?.binding?.session_id === sessionId && loop.binding.state === "live") {
      loop.binding.state = "released";
      loop.binding.closed_at = isoOf(nowMsOf(le));
      loop.binding.close_reason = `released to run ${toRunId}`;
      pushEvent(cur, "loop.binding_released", `the session was handed over to run ${toRunId}`, { loop_id: loop.loop_id });
    }
    return cur;
  });
}

/** The custodian's bind: the one-time nonce, first bind wins, its own process check. */
async function bindThroughCustodian(le: Loaded, run: RunHandle, b: { nonce: string; session_id: string; identity: ProcessIdentity }): Promise<CustodianBind> {
  // Not a custodian nonce at all (64 lowercase hex): it cannot match, and the custodian is not asked.
  if (!/^[0-9a-f]{64}$/.test(b.nonce)) return { ok: false, reason: "the binding nonce does not match (it is not a custodian nonce)" };
  let c: CustodianLoop | null;
  try {
    c = await readCustodianLoop(le, run);
  } catch (e) {
    return { ok: false, reason: `the custodian could not be asked (${errText(e)}); nothing was bound` };
  }
  if (!c) return { ok: false, reason: "the run has no automation loop" };
  let out: LoopTransitionOutcome;
  try {
    out = await requestTransition(le, run, c, "bind", { bindNonce: b.nonce, session_id: b.session_id, process: { pid: b.identity.pid } });
  } catch (e) {
    return { ok: false, reason: `the custodian did not bind the loop (${errText(e)})` };
  }
  if (!out.ok) {
    if (out.code === "INVALID_LOOP_TRANSITION" && c.binding) {
      const local = (await readState(run.paths).catch(() => null))?.continuation?.binding;
      return { ok: false, reason: local?.session_id === b.session_id ? "already bound to this session" : "conflict: the loop is already bound to another session (first binding wins)" };
    }
    return { ok: false, reason: refusalText(out, "not bound") };
  }
  const verified = (out.data["binding"] as { verified?: unknown } | undefined)?.verified === true;
  const after = await readCustodianLoop(le, run).catch(() => null);
  return { ok: true, verified, loop: after ?? { ...c, status: "active", binding: { state: "live", verified }, loopRevision: Number(out.data["loopRevision"]) || c.loopRevision } };
}

/** The custodian's rebind of a resumed session: the same session id, with the process identity it re-verifies
 * itself. It advances the epoch and changes neither the status nor a pause. */
async function rebindThroughCustodian(le: Loaded, run: RunHandle, sessionId: string, identity: ProcessIdentity): Promise<{ ok: boolean; loop: CustodianLoop | null; reason: string }> {
  let c: CustodianLoop | null;
  try {
    c = await readCustodianLoop(le, run);
  } catch (e) {
    return { ok: false, loop: null, reason: `the custodian could not be asked (${errText(e)})` };
  }
  if (!c) return { ok: false, loop: null, reason: "the custodian holds no loop for this run" };
  let out: LoopTransitionOutcome;
  try {
    out = await requestTransition(le, run, c, "rebind", { session_id: sessionId, process: { pid: identity.pid } });
  } catch (e) {
    return { ok: false, loop: c, reason: errText(e) };
  }
  if (!out.ok) return { ok: false, loop: c, reason: refusalText(out, "not re-bound") };
  const after = await readCustodianLoop(le, run).catch(() => null);
  return { ok: true, loop: after ?? { ...c, epoch: Number(out.data["epoch"]) || c.epoch + 1 }, reason: "re-bound" };
}

/** Pause automation (fail safe): the custodian's loop first, then the local cache — the local pause stands even
 * when the custodian could not record it (nothing automated proceeds without the custodian anyway). */
async function pauseLoop(le: Loaded, run: RunHandle, reason: PauseReason, detail: string): Promise<boolean> {
  const after = await requestPause(le, run, reason, detail);
  let paused = false;
  await commitState(run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop) return cur;
    const wasActive = loop.status === "active";
    // The local transition first (it records the event), then the custodian's authority over it.
    applyTransition(cur, loop, { status: "paused", pause: { reason, detail } }, nowMsOf(le));
    const next = after && after.loopId === loop.loop_id ? overlay(loop, after) : loop;
    cur.continuation = next;
    paused = wasActive && next.status === "paused";
    return cur;
  });
  return paused;
}

/** After the run itself ended (and its local loop with it): end the CUSTODIAN's loop too — best effort, and only
 * for a run that had a loop (an attended run never asks the custodian). Nothing automated proceeds on an ended
 * run either way; a terminal protected run stays protected. */
export async function endCustodianLoopWithRun(le: Loaded, run: RunHandle, st: StateRecord, why: string): Promise<void> {
  if (!st.continuation) return;
  await requestEnd(le, run, "run_ended", why).catch(() => null);
}

/** The run itself ended (stop_review_loop abort/close, runs stop): its loop ends in the same commit. */
export function endLoopWithRun(st: StateRecord, why: string): void {
  const loop = st.continuation;
  if (loop) applyTransition(st, loop, { status: "run_ended", reason: why }, Date.now());
}

function applyTransition(st: StateRecord, loop: LoopRecord, t: LoopTransition, nowMs: number): boolean {
  if (!t) return false;
  if (isEnded(loop.status)) return false;
  if (t.status === "paused") {
    if (loop.status === "paused") return false;
    loop.status = "paused";
    loop.pause = { reason: t.pause.reason, detail: t.pause.detail.slice(0, 500), at: isoOf(nowMs) };
    pushEvent(st, "loop.paused", `automation paused: ${t.pause.reason} (${t.pause.detail.slice(0, 200)})`, { loop_id: loop.loop_id });
    return true;
  }
  loop.status = t.status;
  loop.ended = { status: t.status, reason: t.reason.slice(0, 500), at: isoOf(nowMs) };
  pushEvent(st, "loop.ended", `automation ended: ${t.status} (${t.reason.slice(0, 200)})`, { loop_id: loop.loop_id });
  return true;
}

// ---------------------------------------------------------------------------
// Hook decisions
// ---------------------------------------------------------------------------

export interface HookOutcome {
  /** Text the hook prints for the host (additionalContext, a block reason, a deny reason). */
  text: string | null;
  /** The adapter's verdict: allow (nothing), context, block, deny or wake. */
  verdict: "none" | "context" | "block" | "deny" | "wake";
  /** One line for the hook log (never narration). */
  log: string;
}

const none = (log: string): HookOutcome => ({ text: null, verdict: "none", log });

/** SessionStart: a resumed session re-binds in a new epoch; any bound session gets the controller's status. */
export async function onSessionStart(le: Loaded, h: HookFacts, source: string | null): Promise<HookOutcome> {
  const b = await boundRunOf(le, h.session_id);
  if (!b) return none("no loop bound to this session");
  const resumable = source === "resume" && b.loop.binding?.state !== "released" && !isEnded(b.loop.status);
  if (resumable) {
    const identity = await captureIdentity(le, h);
    let rebound = false;
    await withSessionLock(le, h.session_id, async () => {
      // P3.4C-2: the CUSTODIAN re-binds — the same session, with the process identity it re-verifies itself;
      // it advances the epoch (wakes armed earlier become stale) and never changes the status or a pause.
      const rebind = await rebindThroughCustodian(le, b.run, h.session_id, identity);
      rebound = rebind.ok;
      return commitState(b.run.paths, le.env.owner, (cur) => {
        const loop0 = cur.continuation;
        if (!loop0?.binding || loop0.binding.session_id !== h.session_id || loop0.binding.state === "released" || isEnded(loop0.status)) return cur;
        const now = nowMsOf(le);
        const wasLive = loop0.binding.state === "live";
        const binding = { ...loop0.binding, state: "live" as const, rebound_at: isoOf(now), closed_at: null, close_reason: null, process: { ...identity, verified: rebind.ok } };
        const loop = rebind.loop && rebind.loop.loopId === loop0.loop_id ? { ...overlay({ ...loop0, binding }, rebind.loop) } : { ...loop0, binding };
        if (loop.binding) loop.binding.epoch = rebind.loop?.epoch ?? loop0.binding.epoch;
        loop.turn = { active: false, at: isoOf(now) };
        cur.continuation = loop;
        pushEvent(cur, "loop.rebound", `the resumed session ${rebind.ok ? `re-bound the loop in epoch ${loop.binding?.epoch}` : `could not re-bind the loop (${rebind.reason})`} (the previous binding was ${wasLive ? "still live: no SessionEnd was delivered" : "closed"}); wakes armed earlier are stale`, { loop_id: loop.loop_id });
        return cur;
      });
    });
    // Not re-bound (an unverified identity, or no custodian answer): nothing continues in the new epoch.
    if (!rebound) await pauseLoop(le, b.run, "process_identity", identity.verified ? "the custodian did not re-bind the resumed session" : identity.detail);
    const loop = (await readState(b.run.paths)).continuation!;
    return { text: await sessionStartText(le, b.run, loop), verdict: "context", log: `resume: re-bound epoch ${loop.binding?.epoch}; loop ${loop.status}` };
  }
  if (b.loop.binding?.state !== "live" || isEnded(b.loop.status)) return none(`binding ${b.loop.binding?.state}; loop ${b.loop.status}`);
  return { text: await sessionStartText(le, b.run, b.loop), verdict: "context", log: `${source ?? "start"}: status injected; loop ${b.loop.status}` };
}

/** §5.4: how long SessionStart waits for the custodian's derivation — below the host's 30 s SessionStart limit. */
export const SESSION_START_DERIVATION_MS = 20_000;

/**
 * P3.4C-5 Increment 4 (§5.4): the SessionStart status of a protected loop presents the CUSTODIAN's derivation — its next
 * action and completion, labelled — read within {@link SESSION_START_DERIVATION_MS}. When it is not available in time, the
 * status says so and offers no local derivation in its place; the next Stop decides on the custodian's derivation. This is
 * a presentation only: SessionStart spends nothing and decides nothing.
 */
async function sessionStartText(le: Loaded, run: RunHandle, loop: LoopRecord): Promise<string> {
  if (loop.status !== "active") return statusText(run.runId, loop, null, nowMsOf(le));
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<"late">((resolve) => {
    timer = setTimeout(() => resolve("late"), le.env.testHooks?.continuation?.sessionStartDerivationMs ?? SESSION_START_DERIVATION_MS);
    timer.unref?.();
  });
  const der = await Promise.race([readCustodianDerivation(le, run).catch((e: unknown) => (e instanceof Error ? e.message : String(e))), late]).finally(() => clearTimeout(timer));
  if (typeof der === "object" && der.available) {
    return `${statusText(run.runId, loop, routeOfDerivation(der), nowMsOf(le))} (The next action is the custodian's derivation ${der.derivationId}; completion ${der.completion.state}.)`;
  }
  const why = der === "late" ? `within ${Math.round((le.env.testHooks?.continuation?.sessionStartDerivationMs ?? SESSION_START_DERIVATION_MS) / 1000)} s` : typeof der === "object" ? `(${der.code})` : `(${der.slice(0, 160)})`;
  return `${statusText(run.runId, loop, null, nowMsOf(le))} (The custodian's derivation of the next action was not available ${why}; the next Stop decides on it.)`;
}

/** SessionEnd (when the host delivers it): the binding closes; a resume re-binds later. */
export async function onSessionEnd(le: Loaded, h: HookFacts, reason: string | null): Promise<HookOutcome> {
  const b = await boundRunOf(le, h.session_id);
  if (!b || b.loop.binding?.state !== "live") return none("no live binding");
  await commitState(b.run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop?.binding || loop.binding.session_id !== h.session_id || loop.binding.state !== "live") return cur;
    const now = nowMsOf(le);
    loop.binding.state = "closed";
    loop.binding.closed_at = isoOf(now);
    loop.binding.close_reason = `session ended (${(reason ?? "unknown").slice(0, 60)})`;
    loop.turn = { active: false, at: isoOf(now) };
    pushEvent(cur, "loop.binding_closed", `the session ended (${(reason ?? "unknown").slice(0, 60)}); nothing wakes or restarts it`, { loop_id: loop.loop_id }, "host");
    return cur;
  });
  return none("binding closed");
}

/** UserPromptSubmit: a person's prompt (not a host task notification) is user activity: it supersedes armed wakes; the host's interrupt marker pauses. */
export async function onUserPrompt(le: Loaded, h: HookFacts, prompt: string): Promise<HookOutcome> {
  const b0 = await boundRunOf(le, h.session_id);
  if (!b0 || b0.loop.binding?.state !== "live") return none("no live binding");
  const b = (b0.loop.status === "paused" ? await reconcileCustodianResume(le, b0) : null) ?? b0;
  if (!b.loop.binding || b.loop.binding.state !== "live") return none("no live binding");
  const kind = promptKind(prompt);
  if (isEnded(b.loop.status)) return none(`loop ${b.loop.status}`);
  // A paused loop wakes and continues nothing: only its status is shown (a prompt never clears a pause).
  if (b.loop.status !== "active") return kind === "user" ? { text: statusText(b.run.runId, b.loop, null, nowMsOf(le)), verdict: "context", log: `user prompt; loop ${b.loop.status} (unchanged)` } : none(`task notification; loop ${b.loop.status}`);
  const since = [b.loop.binding.rebound_at ?? b.loop.binding.bound_at, b.loop.resumed_at ?? ""].sort().at(-1)!;
  const interrupted = kind === "user" && b.loop.status === "active" && h.transcript_path ? await transcriptShowsInterrupt(h.transcript_path, since) : false;
  const st = await commitState(b.run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop?.binding || loop.binding.session_id !== h.session_id || loop.binding.state !== "live") return cur;
    const now = nowMsOf(le);
    loop.turn = { active: true, at: isoOf(now) };
    if (kind === "user") {
      loop.last_user_prompt_at = isoOf(now);
      for (const w of loop.wakes) if (!w.consumed && !w.superseded_at) w.superseded_at = isoOf(now);
      if (interrupted) {
        capped(loop.interrupts, { at: isoOf(now), via: "transcript_marker", detail: "the host's interrupt marker, seen at the next user prompt" });
        applyTransition(cur, loop, { status: "paused", pause: { reason: "user_interrupt", detail: "the host recorded a user interrupt in the session transcript" } }, now);
      }
    }
    return cur;
  });
  if (interrupted) await requestPause(le, b.run, "user_interrupt", "the host recorded a user interrupt in the session transcript");
  if (kind !== "user") return none("task notification (not user activity)");
  return { text: statusText(b.run.runId, st.continuation!, null, nowMsOf(le)), verdict: "context", log: `user prompt; loop ${st.continuation!.status}${interrupted ? " (interrupt marker: paused)" : ""}` };
}

async function transcriptShowsInterrupt(path: string, sinceIso: string): Promise<boolean> {
  try {
    const text = await readFile(path, "utf8");
    return transcriptInterruptedSince(text, sinceIso);
  } catch {
    return false;
  }
}

/**
 * PreToolUse on a CodeParley tool: correlation only. A call naming a run whose loop is LIVE-bound to
 * another session is denied; everything else is allowed (runs without a live binding keep their
 * Phase 2 behaviour: any session may continue them by run_id). Side-effect free: nothing is
 * written, so a prompt-suggestion fork or any other caller changes nothing. Not an access-control
 * boundary: a same-user process can call the server without this hook.
 */
export async function onPreToolUse(le: Loaded, h: HookFacts, toolInput: unknown): Promise<HookOutcome> {
  const runId = toolInput && typeof toolInput === "object" ? (toolInput as Record<string, unknown>)["run_id"] : undefined;
  if (typeof runId !== "string") return none("no run_id argument");
  const run = await findRunAnywhere(le, runId);
  if (!run) return none("unknown run (the server refuses it)");
  const st = await readState(run.paths).catch(() => null);
  if (!st) return { text: `[CodeParley correlation] the state of run ${runId} could not be read, so its session binding could not be checked; the call is refused`, verdict: "deny", log: "state unreadable: deny" };
  const b = st.continuation?.binding;
  if (!b || b.state !== "live") return none("no live binding");
  if (b.session_id === h.session_id) return none("bound to this session");
  return { text: `[CodeParley correlation] run ${runId} is bound to another Claude Code session; this session cannot operate it. Session ids are correlation identifiers, not credentials: this is not an access-control boundary.`, verdict: "deny", log: "cross-session call denied" };
}

/** PostToolUse on start_review_loop: bind the loop to this session (host session id + one-time nonce). */
export async function onLoopStarted(le: Loaded, h: HookFacts, toolResponse: unknown): Promise<HookOutcome> {
  const r = await bindFromResult(le, h, toolResponse);
  return none(r.ok ? `bound (epoch ${r.epoch})` : `not bound: ${r.reason}`);
}

/**
 * Phase 5 F-i2-5: a paused local cache whose loop the operator resumed through the custodian alone (`loop resume <run>
 * --repo`: on Linux the operator account cannot write this store). The custodian's loop is the authority, but a local
 * pause can be newer than anything the custodian holds (its pause request failed: fail closed), so the cache follows
 * only a resume the custodian recorded AFTER the local pause; anything else — or a custodian that cannot be read —
 * leaves the loop paused. Returns the reconciled run, or null.
 */
async function reconcileCustodianResume(le: Loaded, b: BoundRun): Promise<BoundRun | null> {
  const pausedAt = b.loop.status === "paused" ? b.loop.pause?.at : undefined;
  if (!pausedAt) return null;
  let c: CustodianLoop | null;
  try {
    c = await readCustodianLoop(le, b.run);
  } catch {
    return null;
  }
  if (!c || c.loopId !== b.loop.loop_id || c.status !== "active" || !c.resumedAt || !(Date.parse(c.resumedAt) > Date.parse(pausedAt))) return null;
  const held = c;
  const st = await commitState(b.run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop || loop.loop_id !== held.loopId || loop.status !== "paused" || loop.pause?.at !== pausedAt) return cur;
    const reason = loop.pause.reason;
    cur.continuation = overlay(loop, held);
    pushEvent(cur, "loop.resumed", `automation resumed by the operator through the custodian at ${held.resumedAt} (after ${reason})`, { loop_id: held.loopId });
    return cur;
  });
  const loop = st.continuation;
  return loop?.status === "active" && loop.loop_id === held.loopId ? { run: b.run, st, loop } : null;
}

/** Stop: continue the same session's turn only for an implementer step within the loop's budget. */
export async function onStop(le: Loaded, h: HookFacts, stopHookActive: boolean): Promise<HookOutcome> {
  const b0 = await boundRunOf(le, h.session_id);
  if (!b0 || b0.loop.binding?.state !== "live") return none("no live binding");
  // A paused or ended loop automates nothing: the stop is allowed and nothing is recorded — unless the operator resumed
  // it through the custodian alone, after the local pause (F-i2-5).
  const b = b0.loop.status === "active" ? b0 : await reconcileCustodianResume(le, b0);
  if (!b) return none(`allow: the loop is ${b0.loop.status}`);
  // P3.4C-2: the CUSTODIAN's loop is the authority (status, epoch, budgets, deadline, the binding verdict); the
  // local record supplies only the session correlation and liveness. The protected derivation reads the
  // custodian's user decisions & amendments (P3.4C-1; implementer projection, no raw text). Either being
  // unavailable FAILS CLOSED: automation pauses and nothing falls back to the local store.
  let c: CustodianLoop | null = null;
  let custodianDown: DomainError | null = null;
  try {
    c = await readCustodianLoop(le, b.run);
  } catch (e) {
    if (deliveryOutcomeOf(e) === null) throw e; // not a fail-closed custodian error: a real fault
    custodianDown = e as DomainError;
  }
  if (!custodianDown && !c) return none("allow: the custodian holds no automation loop for this run (a local loop record authorizes nothing)");
  const loop0 = c ? overlay(b.loop, c) : b.loop;
  const identity = identityMatches(loop0, h.claudePid);
  // P3.4C-5 Increment 3 (§5.2, §5.4): a protected run's route and progress are the CUSTODIAN's derivation — over its own
  // records and its own fresh measurement, never this process's local state. An unavailable derivation fails closed.
  let routed: { route: NextAction; digest: string; derivationId: string } | null = null;
  if (identity.ok && !custodianDown && loop0.status === "active") {
    try {
      const d = await readCustodianDerivation(le, b.run);
      if (!d.available) custodianDown = new DomainError(CUSTODIAN_UNAVAILABLE_CODE, `the custodian's derivation of this run is unavailable (${d.code}: ${d.detail})`, { retryable: false, details: { outcome: "not_delivered" } });
      else routed = { route: routeOfDerivation(d), digest: d.progressFingerprint, derivationId: d.derivationId };
    } catch (e) {
      if (deliveryOutcomeOf(e) === null) throw e;
      custodianDown = e as DomainError;
    }
  }
  // The operations this decision was derived from as finished: only their wakes it may supersede.
  // One that finished after the routing read is reported by its own wake (the turn ends now).
  const finishedWhenRouted = new Set(b.st.operations.filter((o) => o.status !== "running").map((o) => o.operation_id));
  await le.env.testHooks?.continuation?.afterRoute?.();
  if (custodianDown) return stopFailClosed(le, b, h, custodianDown);
  let route: NextAction = routed ? declineWhileStarting(routed.route, b.st) : { code: "pause", kind: "pause", pause: "process_identity", reason: "not routed" };
  let decision = decideStop(b.run.runId, loop0, route, { now_ms: nowMsOf(le), stop_hook_active: stopHookActive, digest: routed?.digest ?? "", identity });
  let applied = await applyStopDecision(le, b.run, c!, decision, route, h.session_id, routed?.derivationId ?? null);
  // §5.2: a derivation the custodian finds stale is derived again (a bounded number of times) and decided again on the new
  // route — which may now wait, pause or end; the last stale refusal pauses the loop.
  for (let retry = 0; retry < DERIVATION_RETRIES && applied.stale; retry++) {
    const again = await readCustodianDerivation(le, b.run).catch(() => null);
    if (!again?.available) break;
    route = declineWhileStarting(routeOfDerivation(again), await readState(b.run.paths));
    decision = decideStop(b.run.runId, loop0, route, { now_ms: nowMsOf(le), stop_hook_active: stopHookActive, digest: again.progressFingerprint, identity });
    applied = await applyStopDecision(le, b.run, c!, decision, route, h.session_id, again.derivationId, retry === DERIVATION_RETRIES - 1);
  }
  const digest = routed?.digest ?? "";
  // The custodian's authority to lay over the local record: its state after a transition it applied, or — only
  // when the decision changed nothing — the state the decision was taken on. (A transition the custodian has not
  // recorded yet, such as a passed deadline it derives on its next request, keeps the local result.)
  const authority = applied.after ?? (applied.transition ? null : c);
  await commitState(b.run.paths, le.env.owner, (cur) => recordStop(cur, { h, nowMs: nowMsOf(le), finishedWhenRouted, applied, route, digest, authority }));
  if (applied.continued) return { text: decision.text, verdict: "block", log: `block: continuation ${applied.continuationsUsed ?? "?"}/${loop0.limits.continuations} (${route.code})` };
  return none(`allow: ${applied.reason}`);
}

interface StopRecord {
  h: HookFacts;
  nowMs: number;
  finishedWhenRouted: ReadonlySet<string>;
  applied: AppliedStop;
  route: NextAction;
  digest: string;
  /** The custodian's loop to lay over the local record (null: keep the local result). */
  authority: CustodianLoop | null;
}

/** The local record of a Stop decision the custodian already applied (or refused). */
function recordStop(cur: StateRecord, r: StopRecord): StateRecord {
  const loop = cur.continuation;
  if (!loop?.binding || loop.binding.session_id !== r.h.session_id || loop.binding.state !== "live") return cur;
  const at = isoOf(r.nowMs);
  // A turn that ends after an operation finished reports that operation itself (by this
  // decision, derived from it as finished): its idle wake is no longer needed.
  for (const w of loop.wakes) if (!w.consumed && !w.superseded_at && r.finishedWhenRouted.has(w.operation_id)) w.superseded_at = at;
  if (r.applied.continued) {
    loop.used.continuations = r.applied.continuationsUsed ?? loop.used.continuations + 1;
    loop.last_continuation = { at, digest: r.digest, action: r.route.code };
    pushEvent(cur, "loop.continued", `automated continuation ${loop.used.continuations}/${loop.limits.continuations}: next action ${r.route.code} (${r.route.reason.slice(0, 120)})`, { loop_id: loop.loop_id });
    return cur;
  }
  loop.turn = { active: false, at };
  // The local transition first (it records the event), then the custodian's authority over it — its state
  // after the transition it applied, or (nothing applied) the state the decision was taken on.
  applyTransition(cur, loop, r.applied.transition, r.nowMs);
  if (r.authority && r.authority.loopId === loop.loop_id) cur.continuation = overlay(loop, r.authority);
  return cur;
}

/** The custodian being unavailable: automation pauses locally (operator_action_required); the stop is allowed. */
async function stopFailClosed(le: Loaded, b: BoundRun, h: HookFacts, custodianDown: DomainError): Promise<HookOutcome> {
  await commitState(b.run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop?.binding || loop.binding.session_id !== h.session_id || loop.binding.state !== "live") return cur;
    const now = nowMsOf(le);
    loop.turn = { active: false, at: isoOf(now) };
    applyTransition(cur, loop, { status: "paused", pause: { reason: "operator_action_required", detail: `the custodian is unavailable, so the authoritative loop and user records cannot be read; automation is paused (no fallback to the local store): ${custodianDown.message}` } }, now);
    return cur;
  });
  return none(`allow: automation paused (fail-closed — the custodian is unavailable: ${custodianDown.message.slice(0, 120)})`);
}

interface AppliedStop {
  /** The custodian granted the continuation (it spent one and issued the next operation). */
  continued: boolean;
  /** P3.4C-5 Increment 3: the custodian found the derivation stale; the caller derives and decides again. */
  stale?: boolean;
  continuationsUsed?: number;
  /** The local transition to record (null: none). */
  transition: LoopTransition;
  /** The custodian's loop after it acted (null: not re-read). */
  after: CustodianLoop | null;
  reason: string;
}

/**
 * Apply a Stop decision through the custodian FIRST. A continuation happens only when the custodian spends one
 * (reduce-only, epoch- and deadline-checked; a spend past the budget ends the loop custodian-side) — for the
 * session it is bound to, asked from that session's process tree: `sessionId` is the Stop hook's own session id
 * (its host input). A routed pause or end is the custodian's too; the deadline and a used-up continuation budget
 * are the custodian's own derivations, which a refused spend triggers.
 */
async function applyStopDecision(le: Loaded, run: RunHandle, c: CustodianLoop, decision: StopDecision, route: NextAction, sessionId: string, derivationId: string | null, lastTry = false): Promise<AppliedStop> {
  const t = decision.transition;
  const reason = decision.allow_reason ?? `custodian: ${route.code}`;
  if (decision.consume || isContinuationBudgetEnd(t)) return spendThroughCustodian(le, run, c, decision, sessionId, derivationId, lastTry);
  if (!t || t.status === "expired") return { continued: false, transition: t, after: null, reason };
  if (t.status === "paused") return { continued: false, transition: t, after: await requestPause(le, run, t.pause.reason, t.pause.detail), reason };
  return { continued: false, transition: t, after: await requestEnd(le, run, t.status, t.reason), reason };
}

/** The continuation budget used up: a refused spend makes the custodian derive the end itself. (The deadline
 * needs no request: the custodian refuses every action after it and records the expiry on the next one.) */
function isContinuationBudgetEnd(t: LoopTransition): boolean {
  return t !== null && t.status === "budget_exhausted" && "reason" in t && t.reason === "continuations";
}

/** Ask the custodian to spend a continuation: it grants one only within the budget, the deadline and the epoch,
 * and only for the bound session from the bound process's tree. */
async function spendThroughCustodian(le: Loaded, run: RunHandle, c: CustodianLoop, decision: StopDecision, sessionId: string, derivationId: string | null, lastTry = false): Promise<AppliedStop> {
  const out = await requestTransition(le, run, c, "spend_continuation", { session_id: sessionId, ...(derivationId ? { derivation_id: derivationId } : {}) }).catch(() => null);
  // P3.4C-5 Increment 3 (§5.2): a stale derivation is derived and decided again by the caller (onStop), bounded.
  if (out && !out.ok && out.code === "DERIVATION_STALE" && decision.consume && !lastTry) return { continued: false, transition: null, after: null, reason: refusalText(out, ""), stale: true };
  if (out?.ok && decision.consume) return { continued: true, continuationsUsed: Number(out.data["continuationsUsed"]) || undefined, transition: null, after: null, reason: "continued" };
  const after = await readCustodianLoop(le, run).catch(() => null);
  const reason = decision.consume ? `the custodian did not grant the continuation (${refusalText(out, "no answer")})` : (decision.allow_reason ?? "");
  return { continued: false, transition: spendRefusalTransition(out, decision.transition), after, reason };
}

/** The local transition after the custodian refused a spend (its own loop is re-read and overlaid). */
function spendRefusalTransition(out: LoopTransitionOutcome | null, wanted: LoopTransition): LoopTransition {
  if (!out) return { status: "paused", pause: { reason: "operator_action_required", detail: "the custodian could not be asked for the continuation; automation is paused (fail-closed)" } };
  if (out.ok) return wanted;
  if (out.code === "PROCESS_IDENTITY_UNVERIFIED") return { status: "paused", pause: { reason: "process_identity", detail: refusalText(out, "") } };
  // Not the bound session: this session's local record is not the custodian's binding; nothing changes for the
  // loop (the bound session keeps it), and this Stop continues nothing.
  if (out.code === "SESSION_NOT_BOUND") return null;
  if (out.code === "LOOP_BUDGET_EXHAUSTED") return { status: "budget_exhausted", reason: "continuations" };
  // P3.4C-5 Increment 3 (§5.2): the custodian's own derivation decides.
  if (out.code === "NO_PROGRESS") return { status: "paused", pause: { reason: "no_progress", detail: refusalText(out, "") } };
  if (out.code === "DERIVATION_STALE" || out.code === "ROUTE_NOT_IMPLEMENTER_STEP") return { status: "paused", pause: { reason: "operator_action_required", detail: `the custodian did not grant the continuation on its derivation: ${refusalText(out, "")}` } };
  return wanted;
}

/** §5.2: how many times a stale derivation is derived again before the loop pauses. */
const DERIVATION_RETRIES = 2;

/**
 * The custodian learns of an operation when its reservation lands, which happens moments after this engine records the
 * operation as started. While the engine's own record shows an operation running that the custodian's route does not
 * wait for, the Stop asks for no continuation and the session waits (its wake, or the next Stop, routes on the custodian's
 * derivation again). REDUCE-ONLY: the local record can withhold a continuation here, never cause one.
 */
function declineWhileStarting(route: NextAction, st: StateRecord): NextAction {
  if (route.kind !== "implementer_step" || route.code === "wait_for_operation") return route;
  const running = st.operations.find((o) => o.status === "running");
  return running ? { code: "await_review", kind: "await", reason: `${running.kind}_starting` } : route;
}
const CUSTODIAN_UNAVAILABLE_CODE = "CUSTODIAN_UNAVAILABLE";

/**
 * ConfigChange while automation is live: the change is blocked for the running session (exit 2 —
 * the host keeps its current settings) and automation pauses until the operator resumes it. A change
 * the host cannot block (managed policy) still pauses. Not a security boundary: a new session loads
 * the changed files, and a same-user process can edit hook scripts without any event.
 */
export async function onConfigChange(le: Loaded, h: HookFacts, source: string | null): Promise<HookOutcome> {
  const b = await boundRunOf(le, h.session_id);
  if (!b || b.loop.binding?.state !== "live" || b.loop.status !== "active") return none("no live automation");
  const detail = `settings changed (${(source ?? "unknown").slice(0, 60)}) while automation was live`;
  await commitState(b.run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop?.binding || loop.binding.session_id !== h.session_id || loop.binding.state !== "live") return cur;
    applyTransition(cur, loop, { status: "paused", pause: { reason: "config_change", detail } }, nowMsOf(le));
    return cur;
  });
  await requestPause(le, b.run, "config_change", detail); // the custodian's loop pauses too (fail safe)
  if (source === "policy_settings") return none("managed policy changed: paused (cannot be blocked)");
  return {
    text: `${CONTROLLER_LABEL} Run ${b.run.runId}: settings changed while automation was live. CodeParley blocked the change for this running session and paused automation; stop the loop (code-parley loop stop ${b.run.runId}) before changing settings, or resume it (code-parley loop resume ${b.run.runId}). ${NOT_USER}`,
    verdict: "block",
    log: `config change (${source}): blocked and paused`,
  };
}

/**
 * The host cancelled a call on this run (MCP notifications/cancelled: Esc, Desktop Stop, a host
 * timeout, or the transport closing). No hook reports such interrupts, so the server records it:
 * automation pauses (fail safe). Reason text is never relied on.
 */
export async function recordCallInterrupt(le: Loaded, run: RunHandle, detail: string): Promise<boolean> {
  const st0 = await readState(run.paths).catch(() => null);
  const l0 = st0?.continuation;
  if (!l0 || isEnded(l0.status) || l0.status === "unbound") return false;
  let paused = false;
  await commitState(run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop || isEnded(loop.status) || loop.status === "unbound") return cur;
    const now = nowMsOf(le);
    capped(loop.interrupts, { at: isoOf(now), via: "mcp_cancel", detail: detail.slice(0, 300) });
    paused = applyTransition(cur, loop, { status: "paused", pause: { reason: "user_interrupt", detail: "the host cancelled a call on this run (an interrupt, a host timeout or the session ending)" } }, now) || paused;
    return cur;
  });
  if (paused) await requestPause(le, run, "user_interrupt", "the host cancelled a call on this run (an interrupt, a host timeout or the session ending)");
  return paused;
}

// ---------------------------------------------------------------------------
// Idle wake (asyncRewake PostToolUse hook on review_with_codex)
// ---------------------------------------------------------------------------

export type ArmOutcome = { armed: ArmedWake; deadlineMs: number } | { skip: string };

/** Arm a wake for the review operation a review_with_codex result left running. */
export async function armWake(le: Loaded, h: HookFacts, toolResponse: unknown, instance: string): Promise<ArmOutcome> {
  const r = resultFieldsOf(toolResponse);
  const runId = typeof r?.["run_id"] === "string" ? r["run_id"] : null;
  const opId = typeof r?.["operation_id"] === "string" ? r["operation_id"] : null;
  if (!runId || !opId) return { skip: "the result names no run and operation" };
  if (r?.["status"] !== "running") return { skip: "the review did not leave an operation running (its result was returned inline)" };
  const b = await boundRunOf(le, h.session_id);
  if (!b || b.run.runId !== runId) return { skip: "the run is not bound to this session" };
  // P3.4C-2: the CUSTODIAN reserves the wake — against its CURRENT operation, spending the per-operation and
  // per-run wake budgets before anything is dispatched — and only it can later authorize the dispatch.
  let c: CustodianLoop | null;
  try {
    c = await readCustodianLoop(le, b.run);
  } catch (e) {
    return { skip: `the custodian could not be asked (${errText(e)})` };
  }
  if (!c) return { skip: "the custodian holds no automation loop for this run" };
  const pre = await readState(b.run.paths);
  const blocked = armBlocker(pre.continuation ? overlay(pre.continuation, c) : undefined, c, pre, h, opId, nowMsOf(le));
  if (blocked) return { skip: blocked };
  const handle = currentHandle(c);
  if (!handle) return { skip: "the custodian's loop has no current operation" };
  const out = await requestTransition(le, b.run, c, "wake_arm", { operationHandle: handle, session_id: h.session_id }).catch(() => null);
  if (!out?.ok) return { skip: `the custodian did not reserve a wake (${refusalText(out, "no answer")})` };
  const claimId = String(out.data["claimId"]);
  let result: ArmOutcome = { skip: "not armed" };
  await commitState(b.run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    const now = nowMsOf(le);
    if (!loop?.binding || loop.binding.session_id !== h.session_id || loop.binding.state !== "live") {
      result = { skip: "the run is not bound (live) to this session" };
      return cur;
    }
    let w = loop.wakes.find((x) => x.operation_id === opId);
    if (!w) {
      w = { operation_id: opId, armed: [], consumed: null, rejected: [], superseded_at: null } satisfies WakeRecord;
      capped(loop.wakes, w);
    }
    const a: ArmedWake = { run_id: runId, operation_id: opId, session_id: h.session_id, epoch: c.epoch, armed_at: isoOf(now), instance, claim_id: claimId };
    capped(w.armed, { instance, epoch: a.epoch, armed_at: a.armed_at, waiter_pid: process.pid, claim_id: claimId });
    pushEvent(cur, "loop.wake_armed", `idle wake armed for review operation ${opId.slice(0, 8)} (epoch ${a.epoch}, waiter ${instance}; custodian claim ${claimId})`, { loop_id: loop.loop_id, operation_id: opId });
    result = { armed: a, deadlineMs: Date.parse(c.deadlineAt) };
    return cur;
  });
  return result;
}

/** Why a wake must not be armed (or null), judged on the custodian-overlaid loop; the run's wake budget on the
 * custodian's own count (claims it reserved, consumed or not). */
function armBlocker(loop: LoopRecord | undefined, c: CustodianLoop, st: StateRecord, h: HookFacts, opId: string, nowMs: number): string | null {
  if (!loop?.binding || loop.binding.session_id !== h.session_id || loop.binding.state !== "live") return "the run is not bound (live) to this session";
  const identity = identityMatches(loop, h.claudePid);
  if (!identity.ok) return identity.detail;
  if (loop.status !== "active") return `the loop is ${loop.status}`;
  if (nowMs >= Date.parse(loop.deadline_at)) return "the automation window ended";
  const op = st.operations.find((o) => o.operation_id === opId);
  if (!op || op.kind !== "review") return "the operation is not a review of this run";
  if (reservedWakes(c) >= loop.limits.wakes_per_run) return "the idle-wake budget of this run is used up";
  if (loop.wakes.find((x) => x.operation_id === opId)?.consumed) return "the wake for this operation was already consumed";
  return null;
}

export interface WakeCheck {
  state: "wait" | "stop" | "ready";
  reason: string;
}

/**
 * The waiter's cheap poll (no commit): stop on any blocker, wait while the review runs or the
 * session is in a turn, ready when the review ended and the session is idle.
 */
export async function checkWake(le: Loaded, a: ArmedWake, claudePid: number | null, transcriptPath: string | null = null): Promise<WakeCheck> {
  const run = await findRunAnywhere(le, a.run_id);
  if (!run) return { state: "stop", reason: "the run no longer exists" };
  const st = await readState(run.paths).catch(() => null);
  if (!st) return { state: "wait", reason: "the run state could not be read" };
  const loop = st.continuation;
  const d = await pollDecision(le, st, a, claudePid);
  if (d.pending) return { state: "wait", reason: d.reason };
  if (!d.wake) return { state: "stop", reason: d.reason };
  if (loop!.turn.active) {
    // No Stop hook runs after an interrupt (Esc during generation or a non-CodeParley tool), so the
    // turn still looks active: the host's own interrupt marker since arming ends the wait — and pauses.
    if (transcriptPath && (await transcriptShowsInterrupt(transcriptPath, a.armed_at))) {
      await pauseForWaiterInterrupt(le, run);
      return { state: "stop", reason: "a user interrupt (the host's transcript marker) ended the turn: automation paused" };
    }
    return { state: "wait", reason: "the session is in a turn; its next Stop decision reports the finished review" };
  }
  return { state: "ready", reason: d.reason };
}

/** The waiter's cheap decision, on the local record only (the final one asks the custodian). */
async function pollDecision(le: Loaded, st: StateRecord, a: ArmedWake, claudePid: number | null): Promise<WakeDecision> {
  const loop = st.continuation;
  const op = st.operations.find((o) => o.operation_id === a.operation_id) ?? null;
  const identity = loop ? identityMatches(loop, claudePid) : { ok: false, detail: "no loop" };
  const alive = loop ? await processStillAlive(le, loop.binding?.process ?? null, false) : false;
  return decideWake(a.run_id, loop, a, { now_ms: nowMsOf(le), process_alive: alive, identity, operation: op ? operationFactOf(op) : null, transcript_interrupt: false });
}

/** The host's interrupt marker, seen by the waiter while the turn looked active: automation pauses (local, then
 * the custodian's loop). */
async function pauseForWaiterInterrupt(le: Loaded, run: RunHandle): Promise<void> {
  const detail = "the host recorded a user interrupt in the session transcript";
  await commitState(run.paths, le.env.owner, (cur) => {
    const l = cur.continuation;
    if (!l || l.status !== "active") return cur;
    const now = nowMsOf(le);
    capped(l.interrupts, { at: isoOf(now), via: "transcript_marker", detail: "the host's interrupt marker, seen by the waiter while the turn looked active" });
    applyTransition(cur, l, { status: "paused", pause: { reason: "user_interrupt", detail } }, now);
    return cur;
  });
  await requestPause(le, run, "user_interrupt", detail);
}

/**
 * The final wake decision. The engine decides from the custodian-overlaid loop (status, epoch, budgets, deadline)
 * and its own liveness facts; then ONLY the custodian authorizes the dispatch, by consuming the claim it reserved
 * at arming — persisted before it answers, at most once (TD correction B). A claim the custodian does not
 * authorize wakes nothing.
 */
export async function consumeWake(le: Loaded, a: ArmedWake, h: HookFacts): Promise<{ wake: boolean; text: string | null; reason: string }> {
  const run = await findRunAnywhere(le, a.run_id);
  if (!run) return { wake: false, text: null, reason: "the run no longer exists" };
  const w = await decideAndAuthorizeWake(le, run, a, h);
  let result = { wake: false, text: null as string | null, reason: "not decided" };
  await commitState(run.paths, le.env.owner, (cur) => {
    result = recordWake(cur, a, w, nowMsOf(le));
    return cur;
  });
  if (w.d.transition?.status === "paused") await requestPause(le, run, w.d.transition.pause.reason, w.d.transition.pause.detail);
  else if (w.routeTransition?.status === "paused") await requestPause(le, run, w.routeTransition.pause.reason, w.routeTransition.pause.detail);
  else if (w.routeTransition && "reason" in w.routeTransition) await requestEnd(le, run, w.routeTransition.status, w.routeTransition.reason);
  return result;
}

interface WakeJudgement {
  d: WakeDecision;
  granted: WakeConsumeOutcome | null;
  sinceArmed: boolean;
  reachable: boolean;
  /** P3.4C-5 Increment 3: the custodian's route when it is not an implementer step (pause or end), or a no-progress pause. */
  routeTransition: LoopTransition;
}

/** The engine's wake decision on the custodian-overlaid loop, then — only for a wake — the custodian's
 * authorization: it consumes the claim it reserved at arming. */
async function decideAndAuthorizeWake(le: Loaded, run: RunHandle, a: ArmedWake, h: HookFacts): Promise<WakeJudgement> {
  const f = await finalWakeFacts(le, run, a, h);
  const d = decideWake(a.run_id, f.loop, a, { now_ms: nowMsOf(le), process_alive: f.alive, identity: f.identity, operation: f.op, transcript_interrupt: f.sinceArmed });
  const local = f.local;
  const wanted = d.wake && local !== undefined && !local.turn.active && local.wakes.some((x) => x.operation_id === a.operation_id);
  if (!(wanted && f.c && a.claim_id)) return { d, granted: null, sinceArmed: f.sinceArmed, reachable: f.c !== null, routeTransition: null };
  // P3.4C-5 Increment 3 (§5.2): a wake is dispatched only on the custodian's own derivation — an implementer-step route
  // with moved progress; otherwise the loop pauses or ends as that route says (fail closed when it is unavailable).
  let der = await readCustodianDerivation(le, run).catch(() => null);
  if (!der?.available) return { d, granted: null, sinceArmed: f.sinceArmed, reachable: false, routeTransition: null };
  if (der.route.kind !== "implementer_step") {
    return { d, granted: { dispatchAuthorized: false, refusal: "ROUTE_NOT_IMPLEMENTER_STEP" } as WakeConsumeOutcome, sinceArmed: f.sinceArmed, reachable: true, routeTransition: transitionOf(routeOfDerivation(der)) };
  }
  let granted = await requestWakeConsume(le, run, f.c, a.claim_id, h.session_id, der.derivationId).catch(() => null);
  if (granted && !granted.dispatchAuthorized && granted.refusal === "DERIVATION_STALE") {
    der = await readCustodianDerivation(le, run).catch(() => null);
    if (der?.available && der.route.kind === "implementer_step") granted = await requestWakeConsume(le, run, f.c, a.claim_id, h.session_id, der.derivationId).catch(() => null);
  }
  const routeTransition: LoopTransition = granted && !granted.dispatchAuthorized && granted.refusal === "NO_PROGRESS"
    ? { status: "paused", pause: { reason: "no_progress", detail: "the custodian found no change in the work facts since the last continuation or wake" } }
    : null;
  return { d, granted, sinceArmed: f.sinceArmed, reachable: true, routeTransition };
}

interface FinalWakeFacts {
  local: LoopRecord | undefined;
  c: CustodianLoop | null;
  loop: LoopRecord | undefined;
  op: OperationFact | null;
  identity: { ok: boolean; detail: string };
  alive: boolean;
  sinceArmed: boolean;
}

/** The facts the final wake decision rests on: the local record, the custodian's loop laid over it, the
 * operation, the process identity and liveness, and the host's interrupt marker since arming. */
async function finalWakeFacts(le: Loaded, run: RunHandle, a: ArmedWake, h: HookFacts): Promise<FinalWakeFacts> {
  const pre = await readState(run.paths);
  const local = pre.continuation;
  const sinceArmed = h.transcript_path && local?.status === "active" ? await transcriptShowsInterrupt(h.transcript_path, a.armed_at) : false;
  const alive = await processStillAlive(le, local?.binding?.process ?? null, true);
  const c = await readCustodianLoop(le, run).catch(() => null);
  const loop = local && c ? overlay(local, c) : undefined;
  const opRecord = pre.operations.find((o) => o.operation_id === a.operation_id);
  const identity = loop ? identityMatches(loop, h.claudePid) : { ok: false, detail: c ? "no loop" : "the custodian could not be asked" };
  return { local, c, loop, op: opRecord ? operationFactOf(opRecord) : null, identity, alive, sinceArmed };
}

/** The local record of the wake decision: a wake only when the custodian authorized it and the session is idle. */
function recordWake(cur: StateRecord, a: ArmedWake, j: WakeJudgement, nowMs: number): { wake: boolean; text: string | null; reason: string } {
  const l = cur.continuation;
  if (!l) return { wake: false, text: null, reason: j.d.reason };
  const at = isoOf(nowMs);
  const w = l.wakes.find((x) => x.operation_id === a.operation_id);
  if (j.sinceArmed && j.d.transition) capped(l.interrupts, { at, via: "transcript_marker", detail: "the host's interrupt marker, seen by the waiter" });
  if (j.granted?.dispatchAuthorized && w && !l.turn.active) {
    w.consumed = { at, instance: a.instance, epoch: a.epoch };
    l.used.wakes += 1;
    l.turn = { active: true, at };
    pushEvent(cur, "loop.woke", `automated idle wake ${l.used.wakes}/${l.limits.wakes_per_run} for review operation ${a.operation_id.slice(0, 8)} (${j.d.reason}; waiter ${a.instance}; the custodian authorized claim ${a.claim_id})`, { loop_id: l.loop_id, operation_id: a.operation_id });
    applyTransition(cur, l, j.d.transition, nowMs);
    return { wake: true, text: j.d.text, reason: j.d.reason };
  }
  const reason = wakeRefusalReason(j.d, j.granted, a, j.reachable, l.turn.active);
  if (w) capped(w.rejected, { at, instance: a.instance, reason: reason.slice(0, 300) });
  // The engine's own pause first; otherwise the custodian route's pause or end (applied custodian-side by consumeWake).
  applyTransition(cur, l, j.d.transition ?? j.routeTransition, nowMs);
  return { wake: false, text: null, reason };
}

function wakeRefusalReason(d: WakeDecision, granted: WakeConsumeOutcome | null, a: ArmedWake, reachable: boolean, turnActive: boolean): string {
  if (!d.wake) return d.reason;
  if (turnActive) return granted?.dispatchAuthorized ? "the session started a turn meanwhile (the custodian's one authorization for this claim is spent)" : "the session started a turn meanwhile";
  if (!a.claim_id) return "no custodian wake claim was reserved for this wake";
  if (!reachable || !granted) return "the custodian could not be asked to authorize the wake (fail-closed)";
  return `the custodian did not authorize the wake (${granted.refusal ?? "refused"})`;
}

/** Record that a waiter gave up (its own deadline or a blocker seen while polling). */
export async function abandonWake(le: Loaded, a: ArmedWake, reason: string): Promise<void> {
  const run = await findRunAnywhere(le, a.run_id);
  if (!run) return;
  await commitState(run.paths, le.env.owner, (cur) => {
    const w = cur.continuation?.wakes.find((x) => x.operation_id === a.operation_id);
    if (w && !w.consumed) capped(w.rejected, { at: isoOf(nowMsOf(le)), instance: a.instance, reason: reason.slice(0, 300) });
    return cur;
  }).catch(() => undefined);
}
