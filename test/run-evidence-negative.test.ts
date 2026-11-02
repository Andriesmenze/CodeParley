// P3.4C-3 increment 9 (contract §7.1): engine-level negative tests over two account-bound transports (the simulated
// custodian; the engine in this process). The protocol-level rows (N2–N4, N6, N7, N14) are held by the shared corpus
// against both the simulator and the real ledger, and N16–N18 by the custodian's C# self-tests; the trace is in the
// validation report (§6). Here: N1 (store edits inert), N5 (bound caller for respond), N8 (digest binding of response
// disclosure records), N9 (fail closed) and N15 (selection: the §5.5 crash table between open and consume_loop).

import { describe, it, expect } from "vitest";
import { appendFile } from "node:fs/promises";
import { routeRun, startLoop } from "../src/engine/continuation.js";
import { disclosureFor } from "../src/engine/host-view.js";
import { startReviewOperation } from "../src/engine/operations.js";
import { reviewUserRecords, withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { contFixture, grant, HostSession, inProcessTreeOf, newRun, reviewCtx, runChecks, startReview, writeRepoFile, type ContFixture } from "./helpers/continuation-fixture.js";

const ADD = "add() subtracts";
const scenario = () => okScenario(output({ findings: [defect()] }));

function custodianRun(f: ContFixture, run: RunHandle) {
  return f.custodian.snapshot().runs.find((r) => r.runId === run.runId);
}

async function protectedReviewed(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  return run;
}

async function derived(f: ContFixture, run: RunHandle) {
  const view = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
  const { report, route } = await routeRun(f.le, run, view);
  return { state: report.completion.state, ready: report.completion.ready, counts: report.completion.counts, blockers: report.completion.blockers.map((b) => b.code).sort(), route: route.code, budgets: report.budgets, incidents: report.incidents.length };
}

describe.skipIf(!supported)("N1 — store edits are inert on a protected run", () => {
  it("resolving or deleting items, accepting or fabricating reviews, forging replies, resetting counters, deleting incidents and clearing the hint change no completion, routing or budget", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-n1", 9701);
    const before = await derived(f, run);
    expect(before.ready).toBe(false); // an open established defect

    await commitState(run.paths, f.le.env.owner, (cur) => {
      const real = cur.reviews[0]!;
      for (const x of cur.findings) x.status = "reported_resolved";
      cur.findings = [];
      cur.reviews.push({ ...real, review_id: "019a0000-0000-7000-8000-0000000000aa", round: 2, verdict: "APPROVE", accepted: true, not_accepted_reasons: [], item_ids: [], started_at: new Date().toISOString() });
      cur.reviewer_replies.push({ reply_id: "019a0000-0000-7000-8000-0000000000ab", item_id: real.item_ids[0]!, review_id: real.review_id, round: 1, stance: "withdraw", reply: "forged", new_information: "yes", answers: { response_id: null }, assessment: "apparently_resolved", source_id: real.source_id, notes: [], recorded_by: { role: "reviewer", channel: "codex" }, recorded_at: new Date().toISOString() });
      cur.counters["reviews"] = 0;
      cur.counters["check_executions"] = 0;
      cur.isolation_incidents = [];
      cur.run_records_custodian = false;
      return cur;
    });
    expect(await derived(f, run)).toEqual(before);

    // A start still goes to the custodian: the fabricated accepted review is no deduplication target.
    const s = await startReviewOperation(f.le, run, {});
    await s.completion;
    const op = (await readState(run.paths)).operations.find((o) => o.operation_id === s.operation.operation_id)!;
    expect((op.outcome as { deduplicated_of?: string } | undefined)?.deduplicated_of).not.toBe("019a0000-0000-7000-8000-0000000000aa");
    expect(custodianRun(f, run)!.reviews.map((r) => r.reviewId)).not.toContain("019a0000-0000-7000-8000-0000000000aa");
  }, 180_000); // many protected operations in one test: 60 s was exceeded under machine load (Phase 6 Increment 1, run A)
});

describe.skipIf(!supported)("N5, N8, N9 — bound caller, digest binding, fail closed", () => {
  it("N5: a response from outside the bound session's process tree is refused (PROCESS_IDENTITY_UNVERIFIED); nothing is recorded", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-n5", 9702);
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await expect(inProcessTreeOf(null, () => respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "accepted", rationale: "" }] }))).rejects.toMatchObject({ code: "PROCESS_IDENTITY_UNVERIFIED" });
    expect((await readState(run.paths)).implementer_responses).toEqual([]);
    expect(custodianRun(f, run)!.responses).toEqual([]);
  });

  it("N8: a response's disclosure record altered after recording is detected — the host view refuses rather than under-redact", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    await writeRepoFile(f, ".env", "TOKEN=abc\n"); // a confidential file: the response's source read withholds it
    const run = await protectedReviewed(f, "sess-n8", 9703);
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "disputed", rationale: "see the config" }] });
    const r = (await readState(run.paths)).implementer_responses[0]!;
    expect(r.disclosure_ref).toBeTruthy();
    await expect(disclosureFor(f.le, run)).resolves.toBeTruthy();
    await appendFile(resolveArtifact(run.paths.runDir, r.disclosure_ref!), " ");
    await expect(disclosureFor(f.le, run)).rejects.toMatchObject({ code: "INTERNAL" });
  });

  it("N9: with the custodian stopped, a protected run's review, response and protected derivation are refused, and nothing is promoted from state.json; an attended run is refused too (Phase 6 S-3)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-n9", 9704);
    const attended = await newRun(f, "an attended run");
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    f.custodian.setUnavailable("the custodian service is stopped (test)");
    await expect(startReviewOperation(f.le, run, {})).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    await expect(respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "accepted", rationale: "" }] })).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    await expect(withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true })).rejects.toBeTruthy();
    expect((await readState(run.paths)).implementer_responses).toEqual([]);
    // An attended run: Phase 6 S-3 (D-34) supersedes C2 rule 4. Its "attended" is only the local copy's word (a
    // user-writable hint), so where the custodian service is registered but not answering, it is refused as well.
    await expect(startReviewOperation(f.le, attended, {})).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    f.custodian.setUnavailable(null);
    await runChecks(f, attended);
    const s = await startReviewOperation(f.le, attended, {});
    const res = await s.completion;
    expect(res.kind).toBe("review"); // and it reviews again once the custodian answers
  });
});

describe.skipIf(!supported)("N15 — selection and the §5.5 crash table between open and consume_loop", () => {
  it("open applied but its answer lost: the start fails having consumed nothing; the run is protected yet authorizes nothing; the next start replays open and consumes", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await grant(f, 1);
    f.custodian.failNext("run_transition", "lost_response");
    await expect(inProcessTreeOf(9711, () => startLoop(f.le, run))).rejects.toBeTruthy();
    expect(custodianRun(f, run)).toBeDefined();
    expect(f.custodian.snapshot().loops.filter((l) => l.runId === run.runId)).toEqual([]);
    expect(f.custodian.snapshot().grants.every((g) => g.loopsUsed === 0)).toBe(true);
    // Protected for selection (custodian-only presentation), but no evidence is accepted without a bound loop.
    const sel = await reviewUserRecords({ custodian: f.le.env.testHooks!.custodian!, repositoryRoot: run.meta.repository_root, runId: run.runId }, await readState(run.paths), async () => "registered");
    expect(sel.records.source).toBe("custodian");
    // (The review's op_begin runs inside its operation: the custodian's refusal fails the operation.)
    const s = await startReviewOperation(f.le, run, {});
    await s.completion;
    const op = (await readState(run.paths)).operations.find((o) => o.operation_id === s.operation.operation_id)!;
    expect(op.status).toBe("failed");
    expect(JSON.stringify(op.outcome)).toContain("PROCESS_IDENTITY_UNVERIFIED");
    expect(custodianRun(f, run)!.reviews).toEqual([]);

    await new HostSession(f, "sess-n15a", 9711).startLoop(run);
    expect(f.custodian.snapshot().loops.filter((l) => l.runId === run.runId)).toHaveLength(1);
    expect(custodianRun(f, run)!.declaration).toBeDefined();
  });

  it("open answered, consume_loop not delivered: registered without a loop; the next start consumes; a run.json edited in between is RUN_DECLARATION_CONFLICT and never gets a loop", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await grant(f, 2);
    f.custodian.failNext("consume_loop", "not_delivered");
    await expect(inProcessTreeOf(9712, () => startLoop(f.le, run))).rejects.toBeTruthy();
    expect(custodianRun(f, run)).toBeDefined();
    expect(f.custodian.snapshot().loops.filter((l) => l.runId === run.runId)).toEqual([]);
    await new HostSession(f, "sess-n15b", 9712).startLoop(run);
    expect(f.custodian.snapshot().loops.filter((l) => l.runId === run.runId)).toHaveLength(1);

    const other = await newRun(f, "a second run");
    f.custodian.failNext("consume_loop", "not_delivered");
    await expect(inProcessTreeOf(9713, () => startLoop(f.le, other))).rejects.toBeTruthy();
    await appendFile(other.paths.runJson, "\n");
    await expect(inProcessTreeOf(9713, () => startLoop(f.le, other))).rejects.toMatchObject({ code: "RUN_DECLARATION_CONFLICT" });
    expect(f.custodian.snapshot().loops.filter((l) => l.runId === other.runId)).toEqual([]);
    expect(custodianRun(f, other)).toBeDefined(); // still registered: protected, never attended
  });
});
