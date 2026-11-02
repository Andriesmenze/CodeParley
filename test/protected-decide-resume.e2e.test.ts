// P3.4C-3 mandatory functional correction C1 (contract §6.5): after the operator records a PROTECTED decision on
// a protected run paused for a user decision, `loop resume` must succeed — and a decision that is not protected
// authority must not satisfy it.
//
// Before the correction, the operator's resume guard derives from the raw local state (loop-authority.ts), which
// holds no protected decision: after `decide --protected` the guard still sees the thread as needing a decision
// and refuses; and a LEGACY decision in state.json satisfies the guard although the protected Stop derivation
// ignores it. The guard must derive the need from the same authoritative inputs as the protected Stop derivation —
// the custodian's records — read on the operator surface (the only pipe the operator account can reach).
//
// End to end against the simulated custodian with two account-bound transports over one state: the session's
// hooks and the engine reach only the implementer pipe, the operator's CLI only the operator pipe. The guard's
// correction (increment 7: the custodian's records on the operator surface) makes the legacy-decision control pass;
// the protected decision the main case and the custodian-down control need is checked against the custodian's run
// record (§3.4(2)), which holds the review's items once the engine records its reviews there (increment 8), so those
// two run as expected failures until then (CODEPARLEY_SHOW_REGRESSIONS=1 runs them as ordinary tests).

import { describe, it, expect } from "vitest";
import { routeRun } from "../src/engine/continuation.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { cli, contFixture, grant, HostSession, inProcessTreeOf, loopOf, newRun, operatorIo, reviewCtx, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const ADD = "add() subtracts";

/** A protected run paused for a user decision: the review raises an established defect, the implementer asks to
 * defer it (a request, not a decision: the thread escalates), and the session's Stop pauses the loop. Every
 * model-side step runs inside the bound session's process tree. */
async function pausedForDecision(f: ContFixture, sessionId: string, pid: number): Promise<{ run: RunHandle; A: HostSession; itemId: string }> {
  const run = await newRun(f);
  const A = new HostSession(f, sessionId, pid);
  await grant(f, 1);
  await A.startLoop(run);
  const itemId = await inProcessTreeOf(pid, async () => {
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "deferred", rationale: "out of scope for this change" }] });
    return item.id;
  });
  const s = await A.stop(false);
  expect(s.verdict).toBe("none");
  expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
  return { run, A, itemId };
}

async function resume(f: ContFixture, run: RunHandle): Promise<{ code: number; err: string }> {
  return cli(f, ["loop", "resume", run.runId], operatorIo("resume"));
}

const scenario = () => okScenario(output({ findings: [defect()] }));

describe.skipIf(!supported)("C1 — a protected decision, then `loop resume` (P3.4C-3 §6.5)", () => {
  it("decide --protected on the escalated thread lets the operator resume, and the next Stop derives no user decision for it", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, A, itemId } = await pausedForDecision(f, "sess-c1", 9101);
    const decided = await cli(f, ["decide", run.runId, itemId, "defer", "--protected", "--note", "next sprint"], operatorIo("defer"));
    expect(decided.code, decided.err).toBe(0);
    expect((await readState(run.paths)).user_decisions).toHaveLength(0); // the custodian holds it, not state.json

    const resumed = await resume(f, run);
    expect(resumed.code, resumed.err).toBe(0);
    expect((await loopOf(run)).status).toBe("active");

    // The protected derivation (the custodian's records) no longer needs a user decision for the thread.
    const hydrated = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
    expect((await routeRun(f.le, run, hydrated)).report.completion.counts.needs_user_decision).toBe(0);
    await A.stop(false);
    const loop = await loopOf(run);
    expect(loop.status === "paused" && loop.pause?.reason === "user_decision_required").toBe(false);
  });

  it("control: with no decision the resume is refused and the loop stays paused", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await pausedForDecision(f, "sess-c1-none", 9102);
    const r = await resume(f, run);
    expect(r.code).toBe(1);
    expect(r.err).toContain("still needs a user decision");
    expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
  });

  it("control: a decision in the user-writable store (not protected authority) does not satisfy the guard", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-c1-legacy", 9103);
    const decided = await cli(f, ["decide", run.runId, itemId, "defer", "--note", "legacy channel"], operatorIo("defer"));
    expect(decided.code, decided.err).toBe(0);
    expect((await readState(run.paths)).user_decisions).toHaveLength(1);
    const r = await resume(f, run);
    expect(r.code).not.toBe(0);
    expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
  });

  it("control: with the custodian stopped the resume is refused, even after a protected decision", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-c1-down", 9104);
    const decided = await cli(f, ["decide", run.runId, itemId, "defer", "--protected"], operatorIo("defer"));
    expect(decided.code, decided.err).toBe(0);
    f.custodian.setUnavailable("the custodian service is stopped (test)");
    f.operatorCustodian!.setUnavailable("the custodian service is stopped (test)");
    const r = await resume(f, run);
    expect(r.code).not.toBe(0);
    expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
  });
});

describe.skipIf(!supported)("P3.4C-3 §2.4 U4 — waivers and deferrals recorded before a recovery lapse", () => {
  it("after a restart of the OS the earlier deferral no longer applies: the resume shows it lapsed and is refused until the operator decides again", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-u4", 9111);
    const decided = await cli(f, ["decide", run.runId, itemId, "defer", "--protected", "--note", "next sprint"], operatorIo("defer"));
    expect(decided.code, decided.err).toBe(0);
    f.custodian.simulateRecoveryAfterNewBoot();

    // The protected derivation no longer counts the deferral.
    const hydrated = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
    expect(hydrated.user_decisions).toEqual([]);

    // P3.4C-4 (D4-E): the recovery also lapsed the repository's protected configuration. `loop resume` offers its
    // re-confirmation first, as its own authorization; declined, the resume is refused (CONFIG_LAPSED) …
    const declined = operatorIo("no");
    const notReconfirmed = await cli(f, ["loop", "resume", run.runId], declined);
    expect(notReconfirmed.code).toBe(2);
    expect(declined.lines.join("\n")).toContain("AS IT SURVIVED");
    expect(declined.lines.join("\n")).toContain("the resume is refused (CONFIG_LAPSED)");
    // … confirmed, the resume's own confirmation follows separately — and the lapsed deferral still refuses it.
    const io = operatorIo("resume");
    const answers = ["confirm", "resume"];
    io.prompt = async () => answers.shift() ?? "";
    const refused = await cli(f, ["loop", "resume", run.runId], io);
    expect(refused.code).toBe(1);
    expect(io.lines.join("\n")).toContain("Recorded by the custodian: repository reconfirm");
    expect(io.lines.join("\n")).toContain("Lapsed by the recovery");
    expect(io.lines.join("\n")).toContain("recovered after a restart of the OS");
    expect(refused.err).toContain("still needs a user decision");

    // The operator records it again (after the recovery): it applies, and the resume goes through.
    const again = await cli(f, ["decide", run.runId, itemId, "defer", "--protected", "--note", "still next sprint"], operatorIo("defer"));
    expect(again.code, again.err).toBe(0);
    const resumed = await resume(f, run);
    expect(resumed.code, resumed.err).toBe(0);
    expect((await loopOf(run)).status).toBe("active");
  });
});
