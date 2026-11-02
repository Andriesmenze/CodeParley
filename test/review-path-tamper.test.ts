// Phase 6 Increment 1, S-3 (TD review D-34): the production review path under local-marker tampering. A protected
// run's local copy (state.json, user-writable) carries only HINTS that the custodian holds the run
// (`run_records_custodian`, `continuation`, `user_records_custodian`). A review takes its authority from the custodian's
// answer, never from those hints, for every state of the custodian service:
//  - registered or unknown, and answering → the custodian's (protected) review, whatever the hints say;
//  - registered or unknown, but not answering → refused (CUSTODIAN_UNAVAILABLE), whatever the hints say: before this
//    correction a run whose hints were removed was reviewed as an attended run (the regression control below);
//  - absent (only an administrator can uninstall the service) → a run still marked protected is refused; with the
//    marks removed it is an attended run, because no custodian exists to hold anything (D-14).
// And the review's derived checks context uses the review context's own presence query (S-3 as first found).

import { describe, it, expect } from "vitest";
import { commitState, readState } from "../src/store/state-store.js";
import { isDomainError } from "../src/common/errors.js";
import { checksContextOf } from "../src/engine/review-operation.js";
import { withHeldConfig } from "../src/engine/checks-operation.js";
import type { CustodianPresence } from "../src/custodian/service-presence.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, newRun, reviewCtx, runChecks, startReview, writeRepoFile, type ContFixture } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [defect()] }));
const DOWN = "the custodian service is stopped (test)";

async function protectedReviewed(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  return run;
}

/** Remove every local hint that the custodian holds this run (what any writer of the user-writable store can do). */
async function stripMarkers(f: ContFixture, run: RunHandle): Promise<void> {
  await commitState(run.paths, f.le.env.owner, (cur) => {
    cur.run_records_custodian = false;
    cur.user_records_custodian = false;
    delete cur.continuation;
    return cur;
  });
  const st = await readState(run.paths);
  expect([st.run_records_custodian, st.user_records_custodian, st.continuation]).toEqual([false, false, undefined]);
}

function setPresence(f: ContFixture, presence: CustodianPresence): void {
  f.le.env.testHooks!.custodian!.presence = presence;
}

const custodianReviews = (f: ContFixture, run: RunHandle) => f.custodian.snapshot().runs.find((r) => r.runId === run.runId)?.reviews.length ?? 0;
const localReviews = async (run: RunHandle) => (await readState(run.paths)).reviews.length;

/** Start a review on a changed source (so it is a new review, not the deduplicated earlier one) and wait for it. */
async function review(f: ContFixture, run: RunHandle): Promise<{ refused: string | null; status: string | null }> {
  await writeRepoFile(f, "src/s3-probe.js", `export const probe = ${Date.now()};\n`);
  try {
    const r = await startReview(f, run);
    await r.done;
    const op = (await readState(run.paths)).operations.find((o) => o.operation_id === r.operationId);
    return { refused: null, status: op?.status ?? null };
  } catch (e) {
    if (!isDomainError(e)) throw e;
    return { refused: e.code, status: null };
  }
}

describe.skipIf(!supported)("S-3: the review path takes a protected run's authority from the custodian, not from local hints", () => {
  for (const presence of ["registered", "unknown"] as const) {
    it(`custodian ${presence} and answering, local marks removed: the review is the custodian's`, async () => {
      const f = await contFixture(scenario(), { accounts: true });
      const run = await protectedReviewed(f, `sess-s3-${presence}`, 9811);
      const held = custodianReviews(f, run);
      await stripMarkers(f, run);
      setPresence(f, presence);
      expect(await review(f, run)).toEqual({ refused: null, status: "completed" });
      expect(custodianReviews(f, run)).toBe(held + 1); // recorded by the custodian: a protected review
    }, 180_000);

    it(`custodian ${presence} but not answering, local marks removed: the review is refused, and nothing is reviewed`, async () => {
      const f = await contFixture(scenario(), { accounts: true });
      const run = await protectedReviewed(f, `sess-s3-down-${presence}`, 9812);
      const held = custodianReviews(f, run);
      const local = await localReviews(run);
      await stripMarkers(f, run);
      setPresence(f, presence);
      f.custodian.setUnavailable(DOWN);
      expect(await review(f, run)).toEqual({ refused: "CUSTODIAN_UNAVAILABLE", status: null });
      f.custodian.setUnavailable(null);
      expect(custodianReviews(f, run)).toBe(held);
      expect(await localReviews(run)).toBe(local); // no attended review either
    }, 180_000);

    it(`custodian ${presence} but not answering, local marks kept: the review is refused`, async () => {
      const f = await contFixture(scenario(), { accounts: true });
      const run = await protectedReviewed(f, `sess-s3-down-marked-${presence}`, 9814);
      setPresence(f, presence);
      f.custodian.setUnavailable(DOWN);
      expect((await review(f, run)).refused).toBe("CUSTODIAN_UNAVAILABLE");
    }, 180_000);
  }

  it("custodian absent, local marks kept: the review is refused (a run marked protected needs its custodian)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-s3-absent", 9813);
    const local = await localReviews(run);
    setPresence(f, "absent");
    expect((await review(f, run)).refused).toBe("CUSTODIAN_UNAVAILABLE");
    expect(await localReviews(run)).toBe(local);
  }, 180_000);

  it("an attended run on a host whose custodian is registered but not answering is refused too (the price of failing closed)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    f.custodian.setUnavailable(DOWN);
    expect((await review(f, run)).refused).toBe("CUSTODIAN_UNAVAILABLE");
  }, 180_000);

  it("the review's derived checks context uses the review context's presence query, not the fixture's", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-s3-ctx", 9815);
    const ctx = await reviewCtx(f, run);
    // The fixture's custodian hook says "registered" and answers; the review context's own query says "absent". Only
    // a derived context that carries the review context's query refuses this marked run as "no custodian installed".
    let asked = 0;
    const checksCtx = checksContextOf({ ...ctx, custodianPresence: async () => (asked++, "absent") });
    const { heldConfig: _drop, ...plain } = checksCtx;
    await expect(withHeldConfig(plain)).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE", message: expect.stringContaining("no CodeParley custodian service is installed") });
    expect(asked).toBe(1);
    // Control: the fixture's own answer (registered, answering) yields the held configuration.
    const own = checksContextOf(ctx);
    const { heldConfig: _drop2, ...plainOwn } = own;
    expect((await withHeldConfig(plainOwn)).heldConfig).toBeTypeOf("function");
  }, 180_000);
});
