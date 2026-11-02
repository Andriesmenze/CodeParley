// Same-session continuation policy (Phase 3.3a). PURE: no I/O and no clock — the caller passes the
// time and every fact.
//
// The engine derives, from its own records only, what the ORIGINATING Claude Code session may do
// next for a run that has an automation loop, and whether CodeParley may keep that session going:
//
//  - routing (`routeFromEngine`) maps the run's derived completion, its operations and its budgets to
//    one next action. It reads nothing the model wrote: no narration, no hook text, no claim;
//  - a Stop-hook continuation (`decideStop`) is given only for an implementer step, while the loop is
//    active, inside its deadline and budget, with a verified process identity and progress since the
//    previous continuation;
//  - an idle wake (`decideWake`) is delivered at most once per review operation and within the run's
//    wake budget, only to the live binding of the current epoch whose process is still the one that
//    bound, and never after a user prompt or interrupt;
//  - every text the controller injects starts with CONTROLLER_LABEL, carries only fixed phrases, the
//    run id and engine codes — never repository content, model text or a user decision.
//
// `needs_user_decision` is a hard pause and `ready` ends automation; neither authorizes anything.

import { sha256OfCanonicalJson } from "../common/hash.js";
import type { BlockerCategory, CompletionBlocker, CompletionState } from "./completion.js";
import { ENDED_LOOP_STATUSES, type LoopLimits, type LoopRecord, type LoopStatus, type PauseReason } from "../schemas/continuation.js";

export const CONTROLLER_LABEL = "[CodeParley controller — automated; not the user]";

/**
 * The P3.3a development limits (Technical Director): the controller never exceeds them, whatever a
 * grant, a tool argument or a hook says. A grant can only lower them.
 */
export const HARD_LOOP_LIMITS: Readonly<LoopLimits> = Object.freeze({ continuations: 2, wakes_per_operation: 1, wakes_per_run: 2, run_seconds: 900 });

/** A binding nonce is valid this long after start_review_loop returned it, and only once. */
export const BIND_NONCE_TTL_MS = 60_000;
// The bounds of an operator grant are the CUSTODIAN's (8 loops / 180 minutes, enforced and reported by
// it; custodian/protocol.ts mirrors them only to refuse early). The former 20-loop / 24-hour TypeScript
// bounds were removed with the user-writable grants file in P3.4C-0.
/** List bounds inside a loop record (each list only ever records events that also pause or refuse). */
export const MAX_LOOP_LIST = 50;

/** Limits for a new loop: the hard limits, lowered (never raised) by a grant's own. */
export function effectiveLimits(grant: Partial<LoopLimits> = {}): LoopLimits {
  const low = (k: keyof LoopLimits): number => {
    const v = grant[k];
    return Math.min(HARD_LOOP_LIMITS[k] as number, typeof v === "number" && v >= 0 ? v : (HARD_LOOP_LIMITS[k] as number));
  };
  return { continuations: low("continuations"), wakes_per_operation: low("wakes_per_operation"), wakes_per_run: low("wakes_per_run"), run_seconds: Math.max(1, low("run_seconds")) };
}

// ---------------------------------------------------------------------------
// Routing: the engine's next action for the implementer
// ---------------------------------------------------------------------------

export type ActionKind = "implementer_step" | "await" | "pause" | "end";
export type ActionCode = "run_checks" | "fix_checks" | "request_review" | "address_findings" | "wait_for_operation" | "refresh_status" | "await_review" | "await_fix_confirmation" | "await_fix_application" | "pause" | "end";

export interface NextAction {
  code: ActionCode;
  kind: ActionKind;
  /** Engine codes that led here (blocker codes, operation states). */
  reason: string;
  pause?: PauseReason;
  end?: Extract<LoopStatus, "ready" | "budget_exhausted" | "run_ended">;
}

export interface OperationFact {
  kind: string;
  operation_id: string;
  /** The operation's status; for a finished review, its review record's status (a review whose Codex turn failed ends as a completed operation). */
  status: string;
  started_at?: string | undefined;
  ended_at?: string | undefined;
}

export interface RoutingFacts {
  /** The run's state as observed (dead owners' operations shown as interrupted). */
  run_state: string;
  active_operation: { kind: string; operation_id: string } | null;
  /** The run's operations as observed (for operations that ended without completing). */
  operations: readonly OperationFact[];
  /** Operations that ended before this time are not routed on (the loop's start, or the operator's latest resume). */
  acknowledged_before: string;
  /** Phase 4 Increment 2 (§3.2, N4-11): delegated-fix proposals awaiting the owner's confirmation (not retired, not past
   * their lifetime). Absent: none. */
  pending_fix_proposals?: number;
  /** Phase 4 Increment 3 (§3.2): delegated fixes the owner confirmed whose application has not begun (unexpired). Absent: none. */
  confirmed_fix_proposals?: number;
  /** Phase 4 Increment 3 (§3.6.4): applications interrupted and not yet reconciled. Absent: none. */
  unreconciled_applications?: number;
  completion: { state: CompletionState; counts: Readonly<Record<BlockerCategory, number>>; blockers: readonly Pick<CompletionBlocker, "category" | "code">[] };
  budgets: { reviews: { used: number; limit: number }; check_executions: { used: number; limit: number } };
}

/** Conditions only the operator can resolve: configuration, approvals, incidents, damaged lineage, a withheld amendment. */
export const OPERATOR_CODES: ReadonlySet<string> = new Set([
  "run_configuration_error",
  "isolation_containment_incident",
  "lineage_anomaly",
  "floor_not_configured",
  "required_check_unapproved",
  "required_check_removed",
  "amendment_withheld",
]);

/** Operation (or, for a review, review-record) outcomes that did not complete: never retried automatically. */
// Phase 4 Increment 2: a delegated fix whose content the custodian rejected did not complete either; Increment 3: nor did
// an application that failed or was interrupted.
const UNSUCCESSFUL: ReadonlySet<string> = new Set(["interrupted", "failed", "cancelled", "timed_out", "invalid_output", "rejected", "apply_failed", "apply_interrupted"]);

/** Operations that ended without completing at or after `since` (newest first). Never retried automatically. */
export function unsuccessfulSince(ops: readonly OperationFact[], since: string): OperationFact[] {
  const t = Date.parse(since);
  return ops.filter((o) => UNSUCCESSFUL.has(o.status) && Date.parse(o.ended_at ?? o.started_at ?? since) >= t).reverse();
}

export function routeFromEngine(f: RoutingFacts): NextAction {
  if (f.run_state === "CLOSED" || f.run_state === "STOPPED") return { code: "end", kind: "end", end: "run_ended", reason: `run_${f.run_state.toLowerCase()}` };
  if (f.active_operation?.kind === "review") return { code: "await_review", kind: "await", reason: "review_running" };
  if (f.active_operation) return { code: "wait_for_operation", kind: "implementer_step", reason: `${f.active_operation.kind}_running` };
  // Phase 4 Increment 3 (§3.6.4): an interrupted application pauses the loop until it is reconciled (`code-parley fix
  // reconcile`) — whatever was acknowledged: the working tree may hold part of the confirmed content.
  if ((f.unreconciled_applications ?? 0) > 0) return { code: "pause", kind: "pause", pause: "operation_unsuccessful", reason: "apply_interrupted_unreconciled" };
  const failed = unsuccessfulSince(f.operations, f.acknowledged_before)[0];
  if (failed) return { code: "pause", kind: "pause", pause: "operation_unsuccessful", reason: `${failed.kind}_${failed.status}` };
  // Phase 4 Increment 2 (§3.2, N4-11): a delegated-fix proposal awaiting the owner's confirmation is not progress — an
  // await: no Stop-hook continuation (not an implementer step) and no wake (no review operation to wake on).
  if ((f.pending_fix_proposals ?? 0) > 0) return { code: "await_fix_confirmation", kind: "await", reason: "fix_proposal_pending" };
  // Phase 4 Increment 3: a confirmed fix awaits its application (apply_fix) — not an automated step either.
  if ((f.confirmed_fix_proposals ?? 0) > 0) return { code: "await_fix_application", kind: "await", reason: "fix_confirmed" };

  const c = f.completion;
  if (c.counts.needs_user_decision > 0) return { code: "pause", kind: "pause", pause: "user_decision_required", reason: codesOf(c.blockers.filter((b) => b.category === "needs_user_decision")) || "needs_user_decision" };
  const operator = c.blockers.filter((b) => OPERATOR_CODES.has(b.code));
  if (operator.length || f.run_state === "CONFIGURATION_ERROR") return { code: "pause", kind: "pause", pause: "operator_action_required", reason: codesOf(operator) || "run_configuration_error" };

  // An interruption that was acknowledged (it ended before the loop started or was resumed) is
  // recorded by the next operation; route on everything else.
  const blockers = c.blockers.filter((b) => b.code !== "run_interrupted");
  const has = (code: string) => blockers.some((b) => b.code === code);
  const inCat = (cat: BlockerCategory) => blockers.filter((b) => b.category === cat);
  if (has("run_preparing") || has("operation_running")) return { code: "wait_for_operation", kind: "implementer_step", reason: "operation_running" };
  if (has("current_source_unknown")) return { code: "refresh_status", kind: "implementer_step", reason: "current_source_unknown" };

  const checks = inCat("checks_not_satisfied");
  const checksLeft = f.budgets.check_executions.used < f.budgets.check_executions.limit;
  const reviewsLeft = f.budgets.reviews.used < f.budgets.reviews.limit;
  if (checks.some((b) => b.code === "required_check_failed")) return checksLeft ? { code: "fix_checks", kind: "implementer_step", reason: codesOf(checks) } : budgetEnd("check_budget");
  if (inCat("needs_implementer").length) return { code: "address_findings", kind: "implementer_step", reason: codesOf(inCat("needs_implementer")) };
  if (checks.length) return checksLeft ? { code: "run_checks", kind: "implementer_step", reason: codesOf(checks) } : budgetEnd("check_budget");
  const review = [...inCat("review_not_current"), ...inCat("needs_reviewer")];
  if (review.length) return reviewsLeft ? { code: "request_review", kind: "implementer_step", reason: codesOf(review) } : budgetEnd("review_budget");
  if (blockers.length === 0 && c.state === "ready") return { code: "end", kind: "end", end: "ready", reason: "completion_ready" };
  // Anything this version does not recognize stops automation (fail safe).
  return { code: "pause", kind: "pause", pause: "operator_action_required", reason: `unrecognized:${codesOf(blockers) || c.state}` };
}

function budgetEnd(which: string): NextAction {
  return { code: "end", kind: "end", end: "budget_exhausted", reason: which };
}

function codesOf(bs: readonly Pick<CompletionBlocker, "code">[]): string {
  return [...new Set(bs.map((b) => b.code))].join(",");
}

/**
 * What changed between two continuations: the engine's own facts only. A continuation is given
 * again only when one of them moved (no progress, no second continuation in the same chain).
 */
export function progressDigest(p: { completion_state: string; blockers: readonly string[]; source_id: string | null; reviews: number; responses: number; check_executions: number; operations: number }): string {
  return sha256OfCanonicalJson({ schema: "codeparley.loop-progress.v1", ...p, blockers: [...p.blockers].sort() }).slice(0, 32);
}

// ---------------------------------------------------------------------------
// Loop gates and transitions
// ---------------------------------------------------------------------------

export type LoopTransition =
  | { status: "paused"; pause: { reason: PauseReason; detail: string } }
  | { status: Exclude<LoopStatus, "paused" | "unbound" | "active">; reason: string }
  | null;

export function isEnded(status: LoopStatus): boolean {
  return ENDED_LOOP_STATUSES.has(status);
}

/** The transition a routed pause or end implies (null for steps and awaits). */
export function transitionOf(route: NextAction): LoopTransition {
  if (route.kind === "pause") return { status: "paused", pause: { reason: route.pause ?? "operator_action_required", detail: route.reason } };
  if (route.kind === "end") return { status: route.end ?? "run_ended", reason: route.reason };
  return null;
}

export interface IdentityCheck {
  ok: boolean;
  detail: string;
}

/**
 * Is the hook's process identity the binding's? The binding recorded CLAUDE_PID, verified, when the
 * session bound; a hook of that session runs under the same process. Missing, unverified or
 * different identities refuse automation (they never refuse a stop or a manual tool call).
 */
export function identityMatches(loop: LoopRecord, hookClaudePid: number | null): IdentityCheck {
  const p = loop.binding?.process ?? null;
  if (!p || p.pid === null) return { ok: false, detail: "the binding has no process identity (CLAUDE_PID was missing)" };
  if (!p.verified) return { ok: false, detail: `the binding's process identity is not verified: ${p.detail}` };
  if (hookClaudePid === null) return { ok: false, detail: "this hook received no CLAUDE_PID" };
  if (hookClaudePid !== p.pid) return { ok: false, detail: `inconsistent process identity: the binding is process ${p.pid}, this hook runs under ${hookClaudePid}` };
  return { ok: true, detail: `process ${p.pid}` };
}

/** Can the loop automate now (status and deadline)? */
export function loopGate(loop: LoopRecord, nowMs: number): { ok: true } | { ok: false; reason: string; expire: boolean } {
  if (loop.status !== "active") return { ok: false, reason: `the loop is ${loop.status}${loop.pause ? ` (${loop.pause.reason})` : ""}`, expire: false };
  if (nowMs >= Date.parse(loop.deadline_at)) return { ok: false, reason: "the loop's automation window ended", expire: true };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Stop: continue the same session's turn, or let it stop
// ---------------------------------------------------------------------------

export interface StopFacts {
  now_ms: number;
  stop_hook_active: boolean;
  /** progressDigest of the engine state this decision was derived from. */
  digest: string;
  identity: IdentityCheck;
}

export interface StopDecision {
  block: boolean;
  /** The controller's instruction when it blocks the stop. */
  text: string | null;
  /** Why the stop was allowed. */
  allow_reason: string | null;
  transition: LoopTransition;
  /** True when this decision spends one continuation. */
  consume: boolean;
}

const allow = (reason: string, transition: LoopTransition = null): StopDecision => ({ block: false, text: null, allow_reason: reason, transition, consume: false });

export function decideStop(runId: string, loop: LoopRecord, route: NextAction, s: StopFacts): StopDecision {
  if (loop.binding?.state !== "live") return allow("the loop's binding is not live");
  const gate = loopGate(loop, s.now_ms);
  if (!gate.ok) return allow(gate.reason, gate.expire ? { status: "expired", reason: "run_seconds" } : null);
  if (!s.identity.ok) return allow(s.identity.detail, { status: "paused", pause: { reason: "process_identity", detail: s.identity.detail } });
  if (route.kind === "end" || route.kind === "pause") return allow(`engine: ${route.code} (${route.reason})`, transitionOf(route));
  if (route.kind === "await") return allow("a review is running: the session waits and the controller wakes it when the review finishes");
  if (loop.used.continuations >= loop.limits.continuations) return allow("the continuation budget is used up", { status: "budget_exhausted", reason: "continuations" });
  if (s.stop_hook_active && loop.last_continuation?.digest === s.digest) return allow("no progress since the last automated continuation");
  const n = loop.used.continuations + 1;
  return { block: true, text: `${CONTROLLER_LABEL} Run ${runId}: automated continuation ${n} of ${loop.limits.continuations}. ${instructionFor(runId, route)} ${NOT_USER}`, allow_reason: null, transition: null, consume: true };
}

// ---------------------------------------------------------------------------
// Idle wake (asyncRewake): wake the same idle session once a review has finished
// ---------------------------------------------------------------------------

export interface ArmedWake {
  run_id: string;
  operation_id: string;
  session_id: string;
  epoch: number;
  armed_at: string;
  instance: string;
  /** P3.4C-2: the custodian's one-shot wake claim reserved for this wake; consuming it is the only thing
   * that authorizes the dispatch. */
  claim_id?: string;
}

export interface WakeFacts {
  now_ms: number;
  /** The bound process: still alive (and, for a final decision, the same process instance). */
  process_alive: boolean;
  identity: IdentityCheck;
  /** The armed operation in the run state as observed (null: not an operation of this run). */
  operation: OperationFact | null;
  /** The host's own interrupt marker appeared in the session transcript after arming. */
  transcript_interrupt: boolean;
}

export const TRANSCRIPT_INTERRUPT = "the host transcript records a user interrupt after the wake was armed";

/** Why an armed wake must not fire (or null). */
export function wakeBlocker(loop: LoopRecord | undefined, a: ArmedWake, f: WakeFacts): string | null {
  if (!loop) return "the run has no automation loop";
  const b = loop.binding;
  if (!b || b.session_id !== a.session_id) return "the run is not bound to this session";
  if (b.state !== "live") return "the binding is closed (the session ended or was released); no resurrection";
  if (b.epoch !== a.epoch) return `stale wake: armed in binding epoch ${a.epoch}, the current epoch is ${b.epoch}`;
  if (!f.identity.ok) return f.identity.detail;
  if (!f.process_alive) return "the session's claude process has ended (no resurrection)";
  const gate = loopGate(loop, f.now_ms);
  if (!gate.ok) return gate.reason;
  if (loop.interrupts.some((i) => i.at >= a.armed_at)) return "a user interrupt happened after the wake was armed";
  if (loop.last_user_prompt_at !== null && loop.last_user_prompt_at >= a.armed_at) return "the user prompted after the wake was armed (the user is in control)";
  const w = loop.wakes.find((x) => x.operation_id === a.operation_id);
  if (w?.superseded_at) return "the session already ran a turn after the operation finished";
  if (!f.operation || f.operation.kind !== "review") return "the armed operation is not a review of this run";
  if (f.transcript_interrupt) return TRANSCRIPT_INTERRUPT;
  return null;
}

export interface WakeDecision {
  wake: boolean;
  /** The operation is still running: keep waiting (nothing was decided). */
  pending: boolean;
  reason: string;
  text: string | null;
  transition: LoopTransition;
}

export function decideWake(runId: string, loop: LoopRecord | undefined, a: ArmedWake, f: WakeFacts): WakeDecision {
  const blocker = wakeBlocker(loop, a, f);
  if (blocker) {
    const pause: LoopTransition = blocker === TRANSCRIPT_INTERRUPT && loop && !isEnded(loop.status) ? { status: "paused", pause: { reason: "user_interrupt", detail: "the host's interrupt marker, seen by the waiter" } } : null;
    return { wake: false, pending: false, reason: blocker, text: null, transition: pause };
  }
  const op = f.operation!;
  if (op.status === "running") return { wake: false, pending: true, reason: "the operation has not finished", text: null, transition: null };
  const w = loop!.wakes.find((x) => x.operation_id === a.operation_id);
  if (w?.consumed) return { wake: false, pending: false, reason: `duplicate: the wake for this operation was already consumed by instance ${w.consumed.instance}`, text: null, transition: null };
  if (loop!.limits.wakes_per_operation < 1) return { wake: false, pending: false, reason: "this loop allows no idle wakes", text: null, transition: null };
  if (loop!.used.wakes >= loop!.limits.wakes_per_run) return { wake: false, pending: false, reason: "the idle-wake budget of this run is used up", text: null, transition: null };
  const ok = op.status === "completed";
  const n = loop!.used.wakes + 1;
  const what = ok
    ? `The review (operation ${op.operation_id}) finished. Call get_review_status with run_id="${runId}" and follow its continuation.next_action.`
    : `The review (operation ${op.operation_id}) ended ${op.status}. Automation is paused and does not retry it: tell the user and END YOUR TURN.`;
  return {
    wake: true,
    pending: false,
    reason: ok ? "review finished" : `review ${op.status}`,
    text: `${CONTROLLER_LABEL} Run ${runId}: automated wake ${n} of ${loop!.limits.wakes_per_run}. ${what} ${NOT_USER}`,
    transition: ok ? null : { status: "paused", pause: { reason: "operation_unsuccessful", detail: `review_${op.status}` } },
  };
}

// ---------------------------------------------------------------------------
// Host turns and transcripts
// ---------------------------------------------------------------------------

/** The host also submits its own task notifications (an asyncRewake wake, a finished background task) as a turn: those are not user activity. */
export function promptKind(prompt: string): "task_notification" | "user" {
  return /^\s*<task-notification>/.test(prompt) ? "task_notification" : "user";
}

const INTERRUPT_MARKER = /^\[Request interrupted by user( for tool use)?\]$/;

/**
 * Does this transcript (JSONL text) record a user interrupt at or after `sinceIso`? Claude Code
 * writes a user-role text entry when Esc or Stop interrupts a turn; a tool result quoting the
 * marker does not count. The transcript is a same-user file, so this signal can only PAUSE
 * automation (fail safe), never continue it.
 */
export function transcriptInterruptedSince(text: string, sinceIso: string): boolean {
  const since = Date.parse(sinceIso);
  for (const line of text.split("\n")) {
    if (!line.includes("interrupted by user")) continue;
    try {
      const e = JSON.parse(line) as { type?: string; timestamp?: string; message?: { content?: unknown } };
      if (e.type !== "user") continue;
      if (e.timestamp && Date.parse(e.timestamp) < since) continue;
      const c = e.message?.content;
      const texts = typeof c === "string" ? [c] : Array.isArray(c) ? c.filter((x: { type?: string }) => x?.type === "text").map((x: { text?: unknown }) => String(x.text ?? "")) : [];
      if (texts.some((t) => INTERRUPT_MARKER.test(t.trim()))) return true;
    } catch {
      /* a partial line */
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Controller texts (fixed phrases, the run id and engine codes only)
// ---------------------------------------------------------------------------

export const NOT_USER = "This text comes from CodeParley's controller, not from the user; it records and grants no user decision.";

const PAUSE_TEXT: Record<PauseReason, (runId: string) => string> = {
  user_interrupt: (r) => `The user interrupted the session. Automation of run ${r} is paused until the operator resumes it (code-parley loop resume ${r}).`,
  user_decision_required: (r) =>
    `A discussion thread of run ${r} needs a user decision: a hard pause. Only the user records it, with \`code-parley decide ${r}\` at a terminal; then the operator resumes automation (code-parley loop resume ${r}). Nothing you say or record can stand for that decision, and a prompt does not clear this pause.`,
  operator_action_required: (r) => `The engine reports a condition of run ${r} that only the operator can resolve (configuration, approvals, an isolation incident or a damaged thread). Automation is paused.`,
  operation_unsuccessful: (r) => `An operation of run ${r} ended without completing. Automation does not retry it; the operator can resume (code-parley loop resume ${r}).`,
  config_change: (r) => `The session's settings changed while automation of run ${r} was live. Automation is paused until the operator resumes it.`,
  process_identity: (r) => `The session's process identity could not be verified for run ${r}. Automation is paused; nothing continues or wakes this session automatically.`,
  no_progress: (r) => `The custodian found no change in the work facts of run ${r} since the last automated continuation (P3.4C-5). Automation is paused; the operator can resume it (code-parley loop resume ${r}).`,
};

/** The instruction for a next action (what the implementer does now). */
export function instructionFor(runId: string, a: NextAction): string {
  const id = `run_id="${runId}"`;
  switch (a.code) {
    case "run_checks":
      return `Call run_checks with ${id} (the approved verification floor), then follow get_review_status's continuation.next_action.`;
    case "fix_checks":
      return `A required check failed for the current source. Fix the code, call run_checks with ${id}, then follow get_review_status's continuation.next_action.`;
    case "address_findings":
      return `Address the open reviewer items of the run: fix the code or record your position with respond_to_review (fix_claimed after a fix). Then call run_checks with ${id}, request a re-review with review_with_codex (${id}, wait_seconds 0) and END YOUR TURN; the controller wakes this session when the review finishes.`;
    case "request_review":
      return `Call review_with_codex with ${id} and wait_seconds 0, then END YOUR TURN; the controller wakes this session when the review finishes.`;
    case "wait_for_operation":
      return `An operation of the run is still running: call get_review_status with ${id} and wait_seconds 45, then follow its continuation.next_action.`;
    case "refresh_status":
      return `Call get_review_status with ${id} and follow its continuation.next_action.`;
    case "await_review":
      return "A review is running. END YOUR TURN NOW; the controller wakes this session when it finishes.";
    case "await_fix_application":
      return `The owner confirmed a delegated fix of run ${runId}: apply it with apply_fix (it writes only the content the owner confirmed), then follow get_review_status's continuation.next_action. Nothing continues or wakes this session automatically.`;
    case "await_fix_confirmation":
      return `A delegated fix of run ${runId} is awaiting the owner's confirmation; only the owner confirms or rejects it, at the operator terminal. END YOUR TURN NOW; nothing continues or wakes this session automatically.`;
    case "pause":
      return `${PAUSE_TEXT[a.pause ?? "operator_action_required"](runId)} END YOUR TURN NOW and tell the user; do not continue on your own.`;
    case "end":
      return endText(runId, a.end ?? "run_ended");
  }
}

function endText(runId: string, status: LoopStatus): string {
  switch (status) {
    case "ready":
      return `The engine derives completion READY for run ${runId}; automation has ended. READY authorizes nothing: do not commit, push, merge, tag or release on that basis. Report to the user and END YOUR TURN.`;
    case "budget_exhausted":
      return `The automation budget of run ${runId} is used up; automation has ended. Report to the user and END YOUR TURN.`;
    case "expired":
      return `The automation window of run ${runId} ended; automation has ended. Report to the user and END YOUR TURN.`;
    case "cancelled":
      return `The operator cancelled automation of run ${runId}. END YOUR TURN.`;
    default:
      return `Run ${runId} is closed or stopped; automation has ended. END YOUR TURN.`;
  }
}

/** The one-line status the controller injects at SessionStart and UserPromptSubmit (informational). */
export function statusText(runId: string, loop: LoopRecord, route: NextAction | null, nowMs: number): string {
  const used = `continuations ${loop.used.continuations}/${loop.limits.continuations}, wakes ${loop.used.wakes}/${loop.limits.wakes_per_run}`;
  if (isEnded(loop.status)) return `${CONTROLLER_LABEL} Run ${runId}: automation has ended (${loop.status}; ${used}). Nothing continues automatically. ${NOT_USER}`;
  if (loop.status === "paused" && loop.pause) return `${CONTROLLER_LABEL} Run ${runId}: automation is paused (${loop.pause.reason}; ${used}). ${PAUSE_TEXT[loop.pause.reason](runId)} ${NOT_USER}`;
  if (loop.status === "unbound") return `${CONTROLLER_LABEL} Run ${runId}: the automation loop is not bound to a session. ${NOT_USER}`;
  const left = Math.max(0, Math.round((Date.parse(loop.deadline_at) - nowMs) / 1000));
  return `${CONTROLLER_LABEL} Run ${runId}: automation is active (binding epoch ${loop.binding?.epoch ?? "-"}; ${used}; ${left} s left).${route ? ` Next action: ${instructionFor(runId, route)}` : ""} ${NOT_USER}`;
}
