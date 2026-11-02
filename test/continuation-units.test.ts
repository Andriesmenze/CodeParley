// Phase 3.3a unit tests: the pure continuation policy (policy/continuation.ts). Routing comes only
// from the engine's facts (derived completion, operations, budgets); a Stop-hook continuation and an
// idle wake are given only inside the loop's budgets, deadline, binding epoch and process identity;
// every controller text is labelled, carries no model or repository text and grants nothing.

import { describe, it, expect } from "vitest";
import {
  CONTROLLER_LABEL,
  HARD_LOOP_LIMITS,
  NOT_USER,
  TRANSCRIPT_INTERRUPT,
  decideStop,
  decideWake,
  effectiveLimits,
  identityMatches,
  instructionFor,
  progressDigest,
  promptKind,
  routeFromEngine,
  statusText,
  transcriptInterruptedSince,
  unsuccessfulSince,
  type ArmedWake,
  type NextAction,
  type RoutingFacts,
  type StopFacts,
  type WakeFacts,
} from "../src/policy/continuation.js";
import { LoopRecordSchema, type LoopRecord } from "../src/schemas/continuation.js";
import type { BlockerCategory } from "../src/policy/completion.js";

const RUN = "01a10737-5c4b-7bd1-9ca4-57bf27dd42dc";
const T0 = Date.parse("2026-10-08T12:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

function loop(over: Partial<LoopRecord> = {}): LoopRecord {
  return LoopRecordSchema.parse({
    schema: "codeparley.loop.v1",
    loop_id: "loop-1",
    status: "active",
    started_at: iso(T0),
    deadline_at: iso(T0 + 900_000),
    grant_id: "grant-1",
    limits: { ...HARD_LOOP_LIMITS },
    used: { continuations: 0, wakes: 0 },
    bind_nonce: { sha256: "a".repeat(64), issued_at: iso(T0), expires_at: iso(T0 + 60_000), used_at: iso(T0 + 1000) },
    binding: { session_id: "sess-A", epoch: 1, state: "live", bound_at: iso(T0 + 1000), rebound_at: null, closed_at: null, close_reason: null, process: { pid: 4242, started_at_ms: T0 - 60_000, verified: true, detail: "test" } },
    pause: null,
    resumed_at: null,
    ended: null,
    wakes: [],
    interrupts: [],
    last_user_prompt_at: null,
    turn: { active: false, at: iso(T0 + 2000) },
    last_continuation: null,
    ...over,
  });
}

const counts = (over: Partial<Record<BlockerCategory, number>> = {}): Record<BlockerCategory, number> => ({ incomplete: 0, checks_not_satisfied: 0, review_not_current: 0, needs_user_decision: 0, needs_reviewer: 0, needs_implementer: 0, ...over });

function facts(blockers: { category: BlockerCategory; code: string }[], over: Partial<RoutingFacts> = {}): RoutingFacts {
  const c = counts();
  for (const b of blockers) c[b.category] += 1;
  return {
    run_state: "IDLE",
    active_operation: null,
    operations: [],
    acknowledged_before: iso(T0),
    completion: { state: blockers[0]?.category ?? "ready", counts: c, blockers },
    budgets: { reviews: { used: 1, limit: 5 }, check_executions: { used: 1, limit: 20 } },
    ...over,
  };
}

const step = (code: NextAction["code"]): NextAction => ({ code, kind: "implementer_step", reason: "test" });
const stopFacts = (over: Partial<StopFacts> = {}): StopFacts => ({ now_ms: T0 + 10_000, stop_hook_active: false, digest: "d1", identity: { ok: true, detail: "ok" }, ...over });
const armed = (over: Partial<ArmedWake> = {}): ArmedWake => ({ run_id: RUN, operation_id: "op-1", session_id: "sess-A", epoch: 1, armed_at: iso(T0 + 5000), instance: "w1", ...over });
const wakeFacts = (over: Partial<WakeFacts> = {}): WakeFacts => ({ now_ms: T0 + 30_000, process_alive: true, identity: { ok: true, detail: "ok" }, operation: { kind: "review", operation_id: "op-1", status: "completed" }, transcript_interrupt: false, ...over });

describe("routing from the engine's records (P3.3a)", () => {
  it("maps each derived-completion situation to one next action", () => {
    expect(routeFromEngine(facts([])).end).toBe("ready");
    expect(routeFromEngine(facts([{ category: "review_not_current", code: "no_accepted_review" }])).code).toBe("request_review");
    expect(routeFromEngine(facts([{ category: "review_not_current", code: "review_stale" }])).code).toBe("request_review");
    expect(routeFromEngine(facts([{ category: "needs_reviewer", code: "awaiting_reviewer" }])).code).toBe("request_review");
    expect(routeFromEngine(facts([{ category: "needs_implementer", code: "open_item" }])).code).toBe("address_findings");
    expect(routeFromEngine(facts([{ category: "checks_not_satisfied", code: "required_check_missing" }])).code).toBe("run_checks");
    expect(routeFromEngine(facts([{ category: "checks_not_satisfied", code: "required_check_stale" }])).code).toBe("run_checks");
    expect(routeFromEngine(facts([{ category: "checks_not_satisfied", code: "required_check_failed" }])).code).toBe("fix_checks");
    expect(routeFromEngine(facts([{ category: "incomplete", code: "current_source_unknown" }])).code).toBe("refresh_status");
    // Fixing comes before re-running the checks and before a re-review.
    expect(routeFromEngine(facts([{ category: "checks_not_satisfied", code: "required_check_stale" }, { category: "review_not_current", code: "review_stale" }, { category: "needs_implementer", code: "open_item" }])).code).toBe("address_findings");
  });

  it("needs_user_decision is a hard pause whatever else blocks (and ready never coexists with a blocker)", () => {
    const r = routeFromEngine(facts([{ category: "checks_not_satisfied", code: "required_check_stale" }, { category: "needs_user_decision", code: "escalated" }]));
    expect(r).toMatchObject({ kind: "pause", pause: "user_decision_required" });
    expect(routeFromEngine(facts([{ category: "needs_user_decision", code: "user_decision_lapsed" }])).pause).toBe("user_decision_required");
  });

  it("conditions only the operator can resolve pause automation", () => {
    for (const code of ["floor_not_configured", "required_check_unapproved", "required_check_removed", "isolation_containment_incident", "lineage_anomaly", "amendment_withheld", "run_configuration_error"]) {
      const cat: BlockerCategory = code.startsWith("required") || code === "floor_not_configured" ? "checks_not_satisfied" : code === "amendment_withheld" ? "review_not_current" : "incomplete";
      expect(routeFromEngine(facts([{ category: cat, code }])), code).toMatchObject({ kind: "pause", pause: "operator_action_required" });
    }
    expect(routeFromEngine(facts([{ category: "incomplete", code: "something_new_in_a_later_version" }])).pause).toBe("operator_action_required");
  });

  it("a running review is awaited; other running operations are polled by the implementer", () => {
    expect(routeFromEngine(facts([], { active_operation: { kind: "review", operation_id: "op" } }))).toMatchObject({ code: "await_review", kind: "await" });
    expect(routeFromEngine(facts([], { active_operation: { kind: "checks", operation_id: "op" } }))).toMatchObject({ code: "wait_for_operation", kind: "implementer_step" });
  });

  it("an operation that did not complete since automation started (or was resumed) pauses it: no automatic retry", () => {
    const ops = [{ kind: "review", operation_id: "op-old", status: "interrupted", started_at: iso(T0 - 600_000) }];
    expect(routeFromEngine(facts([{ category: "review_not_current", code: "no_accepted_review" }], { operations: ops })).code).toBe("request_review");
    const fresh = [...ops, { kind: "review", operation_id: "op-new", status: "failed", started_at: iso(T0 + 1000), ended_at: iso(T0 + 2000) }];
    expect(routeFromEngine(facts([], { operations: fresh }))).toMatchObject({ kind: "pause", pause: "operation_unsuccessful", reason: "review_failed" });
    // Acknowledged by the operator's resume: routed on the rest again.
    expect(routeFromEngine(facts([{ category: "review_not_current", code: "no_accepted_review" }], { operations: fresh, acknowledged_before: iso(T0 + 3000) })).code).toBe("request_review");
    expect(unsuccessfulSince(fresh, iso(T0)).map((o) => o.operation_id)).toEqual(["op-new"]);
  });

  it("budgets end automation rather than ask for work the engine would refuse", () => {
    expect(routeFromEngine(facts([{ category: "review_not_current", code: "review_stale" }], { budgets: { reviews: { used: 5, limit: 5 }, check_executions: { used: 0, limit: 9 } } }))).toMatchObject({ kind: "end", end: "budget_exhausted", reason: "review_budget" });
    expect(routeFromEngine(facts([{ category: "checks_not_satisfied", code: "required_check_missing" }], { budgets: { reviews: { used: 0, limit: 5 }, check_executions: { used: 9, limit: 9 } } }))).toMatchObject({ kind: "end", end: "budget_exhausted" });
  });

  it("a closed or stopped run ends automation", () => {
    expect(routeFromEngine(facts([], { run_state: "CLOSED" }))).toMatchObject({ kind: "end", end: "run_ended" });
    expect(routeFromEngine(facts([], { run_state: "STOPPED" }))).toMatchObject({ kind: "end", end: "run_ended" });
  });

  it("progress is a digest of engine facts only", () => {
    const base = { completion_state: "needs_implementer", blockers: ["open_item"], source_id: "s1", reviews: 1, responses: 0, check_executions: 1, operations: 3 };
    expect(progressDigest(base)).toBe(progressDigest({ ...base, blockers: ["open_item"] }));
    expect(progressDigest(base)).not.toBe(progressDigest({ ...base, source_id: "s2" }));
    expect(progressDigest(base)).not.toBe(progressDigest({ ...base, responses: 1 }));
  });
});

describe("Stop: continuation of the same session's turn (P3.3a)", () => {
  it("blocks only for an implementer step, within the durable budget (2), and never past it", () => {
    let l = loop();
    const d1 = decideStop(RUN, l, step("address_findings"), stopFacts());
    expect(d1).toMatchObject({ block: true, consume: true });
    expect(d1.text!.startsWith(CONTROLLER_LABEL)).toBe(true);
    expect(d1.text).toContain(`Run ${RUN}: automated continuation 1 of 2`);
    expect(d1.text).toContain(NOT_USER);
    l = loop({ used: { continuations: 1, wakes: 0 }, last_continuation: { at: iso(T0), digest: "d1", action: "address_findings" } });
    expect(decideStop(RUN, l, step("request_review"), stopFacts({ digest: "d2", stop_hook_active: true })).text).toContain("continuation 2 of 2");
    l = loop({ used: { continuations: 2, wakes: 0 } });
    expect(decideStop(RUN, l, step("request_review"), stopFacts({ digest: "d3" }))).toMatchObject({ block: false, transition: { status: "budget_exhausted" } });
  });

  it("no progress since the last continuation in the same chain: the stop is allowed and nothing is spent", () => {
    const l = loop({ used: { continuations: 1, wakes: 0 }, last_continuation: { at: iso(T0), digest: "same", action: "run_checks" } });
    expect(decideStop(RUN, l, step("run_checks"), stopFacts({ digest: "same", stop_hook_active: true }))).toMatchObject({ block: false, consume: false, allow_reason: "no progress since the last automated continuation" });
    // After the user's own prompt (no active stop-hook chain) a continuation is possible again.
    expect(decideStop(RUN, l, step("run_checks"), stopFacts({ digest: "same", stop_hook_active: false })).block).toBe(true);
  });

  it("hard stops: pause and end routes, a paused or ended loop, an expired window, a closed binding", () => {
    expect(decideStop(RUN, loop(), { code: "pause", kind: "pause", pause: "user_decision_required", reason: "escalated" }, stopFacts())).toMatchObject({ block: false, transition: { status: "paused", pause: { reason: "user_decision_required" } } });
    expect(decideStop(RUN, loop(), { code: "end", kind: "end", end: "ready", reason: "completion_ready" }, stopFacts())).toMatchObject({ block: false, transition: { status: "ready" } });
    expect(decideStop(RUN, loop(), { code: "await_review", kind: "await", reason: "review_running" }, stopFacts())).toMatchObject({ block: false, transition: null });
    expect(decideStop(RUN, loop({ status: "paused", pause: { reason: "user_interrupt", detail: "x", at: iso(T0) } }), step("run_checks"), stopFacts()).block).toBe(false);
    for (const status of ["ready", "budget_exhausted", "expired", "cancelled", "run_ended"] as const) expect(decideStop(RUN, loop({ status }), step("run_checks"), stopFacts()).block, status).toBe(false);
    expect(decideStop(RUN, loop(), step("run_checks"), stopFacts({ now_ms: T0 + 900_001 }))).toMatchObject({ block: false, transition: { status: "expired" } });
    const closed = loop();
    closed.binding!.state = "closed";
    expect(decideStop(RUN, closed, step("run_checks"), stopFacts()).block).toBe(false);
  });

  it("a missing, unverified or different process identity refuses automation and pauses it", () => {
    expect(decideStop(RUN, loop(), step("run_checks"), stopFacts({ identity: { ok: false, detail: "inconsistent" } }))).toMatchObject({ block: false, transition: { status: "paused", pause: { reason: "process_identity" } } });
    const l = loop();
    expect(identityMatches(l, 4242).ok).toBe(true);
    expect(identityMatches(l, 999).ok).toBe(false);
    expect(identityMatches(l, null).ok).toBe(false);
    const unverified = loop();
    unverified.binding!.process = { pid: 4242, started_at_ms: null, verified: false, detail: "no start time" };
    expect(identityMatches(unverified, 4242).ok).toBe(false);
    const missing = loop();
    missing.binding!.process = null;
    expect(identityMatches(missing, 4242).detail).toContain("no process identity");
  });
});

describe("idle wake (asyncRewake) (P3.3a)", () => {
  const withWake = (over: Partial<LoopRecord> = {}) => loop({ wakes: [{ operation_id: "op-1", armed: [{ instance: "w1", epoch: 1, armed_at: iso(T0 + 5000), waiter_pid: 1 }], consumed: null, rejected: [], superseded_at: null }], ...over });

  it("wakes once a finished review, within the run's wake budget", () => {
    const d = decideWake(RUN, withWake(), armed(), wakeFacts());
    expect(d).toMatchObject({ wake: true, pending: false, transition: null });
    expect(d.text!.startsWith(CONTROLLER_LABEL)).toBe(true);
    expect(d.text).toContain("get_review_status");
    expect(d.text).toContain(NOT_USER);
    expect(decideWake(RUN, withWake(), armed(), wakeFacts({ operation: { kind: "review", operation_id: "op-1", status: "running" } }))).toMatchObject({ wake: false, pending: true });
  });

  it("refuses duplicates, a spent budget, stale epochs, ended sessions and user activity", () => {
    const consumed = withWake();
    consumed.wakes[0]!.consumed = { at: iso(T0 + 20_000), instance: "w0", epoch: 1 };
    expect(decideWake(RUN, consumed, armed(), wakeFacts()).reason).toMatch(/^duplicate/);
    expect(decideWake(RUN, withWake({ used: { continuations: 0, wakes: 2 } }), armed(), wakeFacts()).reason).toContain("wake budget");
    expect(decideWake(RUN, withWake(), armed({ epoch: 0 }), wakeFacts()).reason).toContain("stale wake");
    expect(decideWake(RUN, withWake(), armed({ session_id: "sess-B" }), wakeFacts()).reason).toContain("not bound to this session");
    expect(decideWake(RUN, withWake(), armed(), wakeFacts({ process_alive: false })).reason).toContain("no resurrection");
    expect(decideWake(RUN, withWake(), armed(), wakeFacts({ identity: { ok: false, detail: "inconsistent process identity" } })).reason).toContain("inconsistent");
    expect(decideWake(RUN, withWake({ last_user_prompt_at: iso(T0 + 6000) }), armed(), wakeFacts()).reason).toContain("user prompted");
    expect(decideWake(RUN, withWake({ interrupts: [{ at: iso(T0 + 6000), via: "mcp_cancel", detail: "" }] }), armed(), wakeFacts()).reason).toContain("interrupt");
    const superseded = withWake();
    superseded.wakes[0]!.superseded_at = iso(T0 + 9000);
    expect(decideWake(RUN, superseded, armed(), wakeFacts()).reason).toContain("already ran a turn");
    expect(decideWake(RUN, withWake({ status: "cancelled" }), armed(), wakeFacts()).wake).toBe(false);
    expect(decideWake(RUN, withWake(), armed(), wakeFacts({ now_ms: T0 + 900_000 })).reason).toContain("window ended");
    expect(decideWake(RUN, withWake(), armed(), wakeFacts({ operation: { kind: "checks", operation_id: "op-1", status: "completed" } })).reason).toContain("not a review");
    const closed = withWake();
    closed.binding!.state = "closed";
    expect(decideWake(RUN, closed, armed(), wakeFacts()).reason).toContain("binding is closed");
  });

  it("the host's interrupt marker refuses the wake and pauses the loop (fail safe)", () => {
    const d = decideWake(RUN, withWake(), armed(), wakeFacts({ transcript_interrupt: true }));
    expect(d).toMatchObject({ wake: false, reason: TRANSCRIPT_INTERRUPT, transition: { status: "paused", pause: { reason: "user_interrupt" } } });
  });

  it("a review that ended without completing wakes once to report and pauses automation (no retry)", () => {
    const d = decideWake(RUN, withWake(), armed(), wakeFacts({ operation: { kind: "review", operation_id: "op-1", status: "failed" } }));
    expect(d).toMatchObject({ wake: true, transition: { status: "paused", pause: { reason: "operation_unsuccessful" } } });
    expect(d.text).toContain("does not retry");
  });
});

describe("host turns, transcripts and limits (P3.3a)", () => {
  it("a host task notification is not user activity", () => {
    expect(promptKind("<task-notification><summary>x</summary></task-notification>")).toBe("task_notification");
    expect(promptKind("  <task-notification>")).toBe("task_notification");
    expect(promptKind("please continue")).toBe("user");
    expect(promptKind("I approve: <task-notification>")).toBe("user");
  });

  it("only the host's own interrupt marker, as a user text entry after the time, counts", () => {
    const entry = (ts: string, content: unknown) => JSON.stringify({ type: "user", timestamp: ts, message: { role: "user", content } });
    const quoted = entry(iso(T0 + 10), [{ type: "tool_result", tool_use_id: "x", content: "[Request interrupted by user]" }]);
    const before = entry(iso(T0 - 10), [{ type: "text", text: "[Request interrupted by user for tool use]" }]);
    const after = entry(iso(T0 + 10), [{ type: "text", text: "[Request interrupted by user for tool use]" }]);
    const assistant = JSON.stringify({ type: "assistant", timestamp: iso(T0 + 10), message: { content: [{ type: "text", text: "[Request interrupted by user]" }] } });
    expect(transcriptInterruptedSince([quoted, before, assistant].join("\n"), iso(T0))).toBe(false);
    expect(transcriptInterruptedSince([quoted, after].join("\n"), iso(T0))).toBe(true);
    expect(transcriptInterruptedSince(entry(iso(T0 + 10), "[Request interrupted by user]"), iso(T0))).toBe(true);
  });

  it("a grant can only lower the P3.3a limits", () => {
    expect(effectiveLimits({})).toEqual(HARD_LOOP_LIMITS);
    expect(effectiveLimits({ continuations: 50, wakes_per_run: 9, wakes_per_operation: 3, run_seconds: 99_999 })).toEqual(HARD_LOOP_LIMITS);
    expect(effectiveLimits({ continuations: 1, run_seconds: 60 })).toMatchObject({ continuations: 1, run_seconds: 60, wakes_per_run: 2 });
    expect(HARD_LOOP_LIMITS).toEqual({ continuations: 2, wakes_per_operation: 1, wakes_per_run: 2, run_seconds: 900 });
  });

  it("controller texts are labelled, name only the run and engine codes, and never claim user authority", () => {
    const routes: NextAction[] = [
      step("run_checks"), step("fix_checks"), step("address_findings"), step("request_review"), step("wait_for_operation"), step("refresh_status"),
      { code: "await_review", kind: "await", reason: "r" },
      ...(["user_interrupt", "user_decision_required", "operator_action_required", "operation_unsuccessful", "config_change", "process_identity"] as const).map((p): NextAction => ({ code: "pause", kind: "pause", pause: p, reason: "r" })),
      ...(["ready", "budget_exhausted", "run_ended"] as const).map((e): NextAction => ({ code: "end", kind: "end", end: e, reason: "r" })),
    ];
    for (const r of routes) {
      const t = instructionFor(RUN, r);
      expect(t.length, r.code).toBeGreaterThan(20);
      expect(t, r.code).not.toMatch(/\b(user (has )?approved|approval granted|you may commit|permission to (commit|push|merge))\b/i);
    }
    expect(instructionFor(RUN, { code: "end", kind: "end", end: "ready", reason: "r" })).toContain("READY authorizes nothing");
    const hard = statusText(RUN, loop({ status: "paused", pause: { reason: "user_decision_required", detail: "escalated", at: iso(T0) } }), null, T0);
    expect(hard.startsWith(CONTROLLER_LABEL)).toBe(true);
    expect(hard).toContain(`code-parley decide ${RUN}`);
    expect(hard).toContain("a prompt does not clear this pause");
    expect(hard).toContain(NOT_USER);
  });
});
