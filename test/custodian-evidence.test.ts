// P3.4C-3 (contract §3.2, §4.2, §4.3, §5.4): on a protected run the engine records its evidence with the custodian
// FIRST — increment 8a: the checks operation (op_begin, one record_execution per execution with the digests of its logs
// and result, op_finish); 8b: reviews (op_begin with every binding, op_finish with the outcome, the custodian's
// acceptance) and responses (respond); 8c: the run's end and the recovery of operations whose writer is gone — and only
// then its local cache; an attended run's evidence stays in the TS store.
// Simulation: the custodian is the simulated one (two account-bound transports over one state), the engine and the
// session's tool calls run in this process.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { sha256OfBytes } from "../src/common/hash.js";
import { startChecksOperation, stopRun } from "../src/engine/operations.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import type { SimRun } from "../src/custodian/simulated-runs.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { contFixture, grant, HostSession, inProcessTreeOf, newRun, reviewCtx, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [] }));

function custodianRun(f: ContFixture, run: RunHandle): SimRun | undefined {
  return f.custodian.snapshot().runs.find((r) => r.runId === run.runId);
}

async function protectedRun(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  return run;
}

describe.skipIf(!supported)("P3.4C-3 increment 8a — a protected run's checks are recorded with the custodian first", () => {
  it("op_begin, one record_execution per execution with its digests, op_finish; the local cache follows and names the custodian's operation", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ev-1", 9101);
    await runChecks(f, run);

    const c = custodianRun(f, run)!;
    expect(c.operations.map((o) => `${o.kind}:${o.status}`)).toEqual(["checks:completed"]);
    expect(c.status).toBe("idle");
    const st = await readState(run.paths);
    const op = st.operations.find((o) => o.kind === "checks")!;
    expect(op["custodian_operation_id"]).toBe(c.operations[0]!.operationId);
    // Every local execution is the custodian's, with the digests of what was written.
    expect(c.checkExecutions.map((e) => e["executionId"])).toEqual(st.check_executions.map((e) => e.execution_id));
    for (const e of st.check_executions) {
      const held = c.checkExecutions.find((x) => x["executionId"] === e.execution_id)!;
      expect(held).toMatchObject({ check: e.check, status: e.status, sourceIdAtStart: e.source_id_at_start, sourceStable: e.source_stable });
      const digest = async (ref: string | null | undefined) => (ref ? sha256OfBytes(await readFile(resolveArtifact(run.paths.runDir, ref))) : null);
      expect(held["stdoutDigest"]).toBe(await digest(e.stdout?.artifact));
      expect(held["stderrDigest"]).toBe(await digest(e.stderr?.artifact));
      expect(held["resultDigest"]).toBe(await digest(e.result_artifact));
      expect(held["resultDigest"]).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("an attended run's checks stay in the TS store: the custodian records nothing", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await runChecks(f, run);
    expect(custodianRun(f, run)).toBeUndefined();
    expect((await readState(run.paths)).check_executions.length).toBeGreaterThan(0);
  });

  it("checks requested from outside the bound session's process tree are refused before anything runs (D7: correlation, not authentication)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ev-3", 9103);
    await expect(inProcessTreeOf(null, () => startChecksOperation(f.le, run, {}))).rejects.toMatchObject({ code: "PROCESS_IDENTITY_UNVERIFIED" });
    expect(custodianRun(f, run)!.operations).toEqual([]);
    expect((await readState(run.paths)).operations.filter((o) => o.kind === "checks")).toEqual([]);
  });

  it("a run marked protected whose custodian cannot be reached: the checks are refused (fail closed), never run attended", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ev-4", 9104);
    f.custodian.setUnavailable("the custodian service is stopped (test)");
    await expect(startChecksOperation(f.le, run, {})).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    expect((await readState(run.paths)).operations.filter((o) => o.kind === "checks")).toEqual([]);
  });

  it("the custodian's refusal of a start is the start's refusal: a run whose custodian record has ended runs no checks", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ev-5", 9105);
    // The custodian's run ended (an operator stop elsewhere); the local copy does not know yet.
    const ended = await f.operatorCustodian!.send("operator", "run_transition", { repositoryRoot: run.meta.repository_root, runId: run.runId, kind: "end", fields: { status: "stopped", reason: "test" } }, "end-ev-5");
    expect(ended.ok).toBe(true);
    await expect(startChecksOperation(f.le, run, {})).rejects.toMatchObject({ code: "RUN_TERMINAL" });
    expect((await readState(run.paths)).operations.filter((o) => o.kind === "checks")).toEqual([]);
  });

  it("a local copy edited to forget the protection changes nothing: the custodian's answer still routes the checks through it", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ev-6", 9106);
    await commitState(run.paths, f.le.env.owner, (cur) => {
      cur.run_records_custodian = false;
      delete cur.continuation;
      return cur;
    });
    await runChecks(f, run);
    expect(custodianRun(f, run)!.operations.map((o) => `${o.kind}:${o.status}`)).toEqual(["checks:completed"]);
  });
});

const ADD = "add() subtracts";
const findingScenario = (extra = {}) => okScenario(output({ findings: [defect()] }), extra);

async function review(f: ContFixture, run: RunHandle) {
  await (await startReview(f, run)).done;
  const st = await readState(run.paths);
  return { st, review: st.reviews.at(-1)! };
}

describe.skipIf(!supported)("P3.4C-3 increment 8b — a protected run's reviews and responses are recorded with the custodian first", () => {
  it("op_begin reserves, the custodian's capture binds the review's digests and ids (P3.4C-5); op_finish records its outcome and prompt digest; the custodian's acceptance and items are the local cache's", async () => {
    const f = await contFixture(findingScenario(), { accounts: true });
    const run = await protectedRun(f, "sess-rv-1", 9201);
    await runChecks(f, run);
    const { st, review: r } = await review(f, run);

    const c = custodianRun(f, run)!;
    const held = c.reviews.find((x) => x.reviewId === r.review_id)!;
    expect(held).toMatchObject({ accepted: true, round: r.round });
    expect(r.accepted).toBe(true);
    expect(st.operations.find((o) => o.kind === "review")!["custodian_operation_id"]).toBe(held.operationId);
    // The begin bindings are what the review was run from: the reservation's, then the custodian's own capture (P3.4C-5).
    const capture = r.artifacts["capture"]!;
    expect(held.begin).toMatchObject({
      sourceId: r.source_id,
      reviewInputId: r.review_input_id,
      captureId: r.capture_id,
      captureDigest: sha256OfBytes(await readFile(resolveArtifact(run.paths.runDir, capture))),
      exportDigest: r.export_digest,
      manifestDigest: r.manifest_digest,
      checkExecutionIds: r.check_execution_ids,
      checkEvidenceDigest: r.check_evidence_digest,
      isolation: { mode: r.effective_isolation.mode, profileDigest: r.effective_isolation.profile_digest },
    });
    // The prompt digest arrives with op_finish (never with the reservation).
    expect(held.begin["promptDigest"]).toBeUndefined();
    expect((held.outcome as Record<string, unknown>)["promptDigest"]).toBe(r.prompt.sha256);
    // The finish binds the artifacts as written, and the custodian holds the review's item under the local id.
    expect((held.outcome as { artifacts: Record<string, unknown> }).artifacts["result"]).toBe(sha256OfBytes(await readFile(resolveArtifact(run.paths.runDir, r.artifacts["result"]!))));
    expect(r.item_ids.length).toBeGreaterThan(0);
    expect(c.items.map((i) => i.itemId)).toEqual(r.item_ids);
    expect(c.items.map((i) => i.status)).toEqual(r.item_ids.map((id) => st.findings.find((x) => x.id === id)!.status));
  });

  it("a response is recorded with the custodian against the item revision it holds, and the next review presents it as held evidence", async () => {
    const f = await contFixture(findingScenario(), { accounts: true });
    const run = await protectedRun(f, "sess-rv-2", 9202);
    await runChecks(f, run);
    await review(f, run);
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    const out = await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "disputed", rationale: "a - b is intended here" }] });
    const responseId = out.recorded[0]!.response_id;
    const c1 = custodianRun(f, run)!;
    expect(c1.responses.map((x) => x["responseId"])).toEqual([responseId]);
    expect(c1.items.find((i) => i.itemId === item.id)!.itemRevision).toBe(2);

    const { review: r2 } = await review(f, run);
    const held = custodianRun(f, run)!.reviews.find((x) => x.reviewId === r2.review_id)!;
    // P3.4C-5: the reservation offered the turn; the finish names what the bundle presented (within the offer).
    expect((held.begin["discussion"] as { offered: unknown[] }).offered).toEqual([{ itemId: item.id, responseIds: [responseId], replyIds: [] }]);
    expect(((held.outcome as Record<string, unknown>)["presented"] as { discussion: { delivered: unknown[] } }).discussion.delivered).toEqual([{ itemId: item.id, responseIds: [responseId], replyIds: [] }]);
    expect(r2.accepted).toBe(true);
  });

  it("a response forged into the local copy is evidence the custodian does not hold: the protected review never presents it (8d-2 hydration; the custodian would refuse it, EVIDENCE_NOT_HELD)", async () => {
    const f = await contFixture(findingScenario(), { accounts: true });
    const run = await protectedRun(f, "sess-rv-3", 9203);
    await runChecks(f, run);
    await review(f, run);
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "accepted", rationale: "" }] });
    // A later "dispute" written straight into state.json (never recorded with the custodian).
    await commitState(run.paths, f.le.env.owner, (cur) => {
      const real = cur.implementer_responses.at(-1)!;
      cur.implementer_responses.push({ ...real, response_id: "019a0000-0000-7000-8000-00000000f0f0", disposition: "disputed", rationale: "forged", supersedes: real.response_id, response_set_id: "019a0000-0000-7000-8000-00000000f0f1", request_id: null, recorded_at: new Date().toISOString() });
      return cur;
    });
    const { st } = await review(f, run);
    const op = st.operations.filter((o) => o.kind === "review").at(-1)!;
    expect(op.status).toBe("completed");
    const delivered = custodianRun(f, run)!.reviews.flatMap((r) => [
      ...(r.begin["discussion"] as { offered: { responseIds: string[] }[] }).offered.flatMap((d) => d.responseIds),
      ...(((r.outcome as Record<string, unknown> | null)?.["presented"] as { discussion: { delivered: { responseIds: string[] }[] } } | undefined)?.discussion.delivered ?? []).flatMap((d) => d.responseIds),
    ]);
    expect(delivered).not.toContain("019a0000-0000-7000-8000-00000000f0f0");
  });

  it("the custodian's acceptance is the review's: a run the operator stopped while Codex ran accepts nothing (run_stopped)", async () => {
    const f = await contFixture(findingScenario({ sleep_ms: 3_000 }), { accounts: true });
    const run = await protectedRun(f, "sess-rv-4", 9204);
    await runChecks(f, run);
    const s = await startReview(f, run);
    // While Codex runs: the custodian has captured the review (P3.4C-5: `measuring` is the capture, before Codex).
    for (let i = 0; i < 800 && custodianRun(f, run)!.operations.filter((o) => o.kind === "review").at(-1)?.status !== "captured"; i++) await new Promise((r) => setTimeout(r, 25));
    const ended = await f.operatorCustodian!.send("operator", "run_transition", { repositoryRoot: run.meta.repository_root, runId: run.runId, kind: "end", fields: { status: "stopped", reason: "test" } }, "end-rv-4");
    expect(ended.ok).toBe(true);
    await s.done;
    const r = (await readState(run.paths)).reviews.at(-1)!;
    expect(r.status).toBe("completed");
    expect(r.accepted).toBe(false);
    expect(r.not_accepted_reasons).toContain("custodian:run_stopped");
    expect(r.item_ids).toEqual([]);
    expect(custodianRun(f, run)!.items).toEqual([]);
  });

  it("a second review of the same input in the same evidence epoch is the custodian's deduplication: no new review, no new round", async () => {
    const f = await contFixture(findingScenario(), { accounts: true });
    const run = await protectedRun(f, "sess-rv-5", 9205);
    await runChecks(f, run);
    const { review: r1 } = await review(f, run);
    await setScenario(f, okScenario(output({ findings: [] })));
    const st = (await review(f, run)).st;
    expect(st.reviews).toHaveLength(1);
    expect(st.operations.filter((o) => o.kind === "review").at(-1)!.outcome).toMatchObject({ deduplicated_of: r1.review_id });
    expect(custodianRun(f, run)!.reviews).toHaveLength(1);
  });

  it("an attended run's review and responses stay in the TS store: the custodian records nothing", async () => {
    const f = await contFixture(findingScenario(), { accounts: true });
    const run = await newRun(f);
    await runChecks(f, run);
    const { review: r } = await review(f, run);
    expect(r.accepted).toBe(true);
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "accepted", rationale: "" }] });
    expect(custodianRun(f, run)).toBeUndefined();
  });
});

async function stop(f: ContFixture, run: RunHandle, mode: "abort" | "close") {
  return stopRun(f.le, run, mode, undefined, undefined, 2_000);
}

describe.skipIf(!supported)("P3.4C-3 increment 8c — a protected run's end and recovery go to the custodian", () => {
  it("abort: the local stop applies and the custodian ends the run (stopped), deriving its loop's end; nothing stays pending", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-end-1", 9301);
    const out = await stop(f, run, "abort");
    expect(out.state.state).toBe("STOPPED");
    const c = custodianRun(f, run)!;
    expect(c.status).toBe("stopped");
    expect(f.custodian.snapshot().loops.find((l) => l.runId === run.runId)!.status).toBe("run_ended");
    expect((await readState(run.paths)).custodian_end_pending).toBeUndefined();
  });

  it("close: the custodian closes the run", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-end-2", 9302);
    await stop(f, run, "close");
    expect(custodianRun(f, run)!.status).toBe("closed");
  });

  it("a stop while the custodian cannot be reached still applies locally; the custodian's end stays pending and is sent at the next reconciliation", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-end-3", 9303);
    f.custodian.setUnavailable("the custodian service is stopped (test)");
    const out = await stop(f, run, "abort");
    expect(out.state.state).toBe("STOPPED");
    expect((await readState(run.paths)).custodian_end_pending).toMatchObject({ status: "stopped" });
    expect(custodianRun(f, run)!.status).toBe("idle");
    f.custodian.setUnavailable(null);
    await stop(f, run, "close"); // a terminal run: only the reconciliation runs
    expect(custodianRun(f, run)!.status).toBe("stopped");
    expect((await readState(run.paths)).custodian_end_pending).toBeUndefined();
  });

  it("an operation whose writer the custodian sees gone is recovered (interrupted) before new work; the run is usable again", async () => {
    // The engine that began the first operation is another process, which then dies; this engine is alive.
    const deadWriter = { pid: 999_001, startedAtMs: 1, imageName: "node.exe" };
    const self = { pid: process.pid, startedAtMs: 2, imageName: "node.exe" };
    const dead = { on: false, sender: self };
    const f = await contFixture(scenario(), { accounts: true, writer: () => dead.sender, writerGone: (w) => dead.on && w.pid === deadWriter.pid });
    const run = await protectedRun(f, "sess-rec-1", 9304);
    // An engine that died after the custodian began its checks (nothing was committed locally).
    dead.sender = deadWriter;
    const begun = await f.custodian.send("implementer", "run_transition", { repositoryRoot: run.meta.repository_root, runId: run.runId, kind: "op_begin", fields: { operationKind: "checks", planned: [{ check: "unit", checkSpecId: null, definitionDigest: null, required: true }], inputIdentity: null } }, "begin-rec-1");
    expect(begun.ok).toBe(true);
    await f.custodian.settleCaptures(); // the custodian measured its start
    dead.sender = self;
    dead.on = true;
    await runChecks(f, run);
    expect(custodianRun(f, run)!.operations.map((o) => `${o.kind}:${o.status}`)).toEqual(["checks:interrupted", "checks:completed"]);
  });

  it("while the custodian sees the writer alive nothing is recovered, and new work is refused (RUN_BUSY), never run attended", async () => {
    const f = await contFixture(scenario(), { accounts: true, writerGone: () => false });
    const run = await protectedRun(f, "sess-rec-2", 9305);
    const begun = await f.custodian.send("implementer", "run_transition", { repositoryRoot: run.meta.repository_root, runId: run.runId, kind: "op_begin", fields: { operationKind: "checks", planned: [{ check: "unit", checkSpecId: null, definitionDigest: null, required: true }], inputIdentity: null } }, "begin-rec-2");
    expect(begun.ok).toBe(true);
    await f.custodian.settleCaptures(); // P3.4C-5 Increment 3: the custodian measured the operation's start
    await expect(startChecksOperation(f.le, run, {})).rejects.toMatchObject({ code: "RUN_BUSY" });
    expect(custodianRun(f, run)!.operations.map((o) => `${o.kind}:${o.status}`)).toEqual(["checks:running"]);
    expect((await readState(run.paths)).operations.filter((o) => o.kind === "checks")).toEqual([]);
  });
});
