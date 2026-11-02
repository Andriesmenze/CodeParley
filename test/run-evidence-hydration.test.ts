// P3.4C-3 (contract §1.3, §2.4 U3, §5.4), increment 8d-2: a protected run's reads derive from the custodian's run
// record. Only what it holds counts (nothing recorded before protection is promoted; a record forged into state.json
// counts for nothing), its claims replace the cache's, texts come only from artifacts whose digest it holds, and only
// the current evidence epoch's checks and accepted review count. Simulation: the simulated custodian, the engine in
// this process.

import { describe, it, expect } from "vitest";
import { appendFile } from "node:fs/promises";
import { routeRun } from "../src/engine/continuation.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { ITEM_TEXT_UNAVAILABLE } from "../src/engine/run-evidence.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, newRun, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [defect()] }));

async function protectedView(f: ContFixture, run: RunHandle) {
  return withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
}

async function reviewed(f: ContFixture, run: RunHandle): Promise<void> {
  await runChecks(f, run);
  await (await startReview(f, run)).done;
}

async function protectedReviewed(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  await reviewed(f, run);
  return run;
}

describe.skipIf(!supported)("P3.4C-3 increment 8d-2 — a protected run's evidence is the custodian's", () => {
  it("nothing recorded before protection is promoted (§1.3, D3-A): the protected view starts empty, and the loop's own checks and review count", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await reviewed(f, run); // attended evidence
    expect((await readState(run.paths)).reviews.filter((r) => r.accepted)).toHaveLength(1);
    await grant(f, 1);
    await new HostSession(f, "sess-hy-1", 9401).startLoop(run);

    let view = await protectedView(f, run);
    expect(view.reviews).toEqual([]);
    expect(view.findings).toEqual([]);
    expect(view.check_executions).toEqual([]);
    expect((await routeRun(f.le, run, view)).report.completion.ready).toBe(false);

    await reviewed(f, run); // the loop's own evidence
    view = await protectedView(f, run);
    expect(view.reviews.filter((r) => r.accepted)).toHaveLength(1);
    expect(view.findings.map((x) => x.status)).toEqual(["open"]);
    expect(view.check_executions.length).toBeGreaterThan(0);
  });

  it("the custodian's claims replace the cache's: an item resolved and a check passed in state.json stay open and failed", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-hy-2", 9402);
    const before = await protectedView(f, run);
    const exec = before.check_executions[0]!;
    await commitState(run.paths, f.le.env.owner, (cur) => {
      for (const x of cur.findings) x.status = "reported_resolved";
      for (const e of cur.check_executions) {
        e.status = "failed";
        e.exit_code = 1;
      }
      return cur;
    });
    const view = await protectedView(f, run);
    expect(view.findings.map((x) => x.status)).toEqual(["open"]);
    expect(view.check_executions.find((e) => e.execution_id === exec.execution_id)).toMatchObject({ status: exec.status, exit_code: exec.exit_code });
  });

  it("a review's items artifact altered after recording: the item still counts, its text is withheld", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-hy-3", 9403);
    const st = await readState(run.paths);
    await appendFile(resolveArtifact(run.paths.runDir, st.reviews[0]!.artifacts["items"]!), "\n");
    const view = await protectedView(f, run);
    expect(view.findings).toHaveLength(1);
    expect(view.findings[0]).toMatchObject({ status: "open", title: ITEM_TEXT_UNAVAILABLE, consequence: "" });
  });

  it("a check result artifact altered after recording: that execution does not count", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-hy-4", 9404);
    const st = await readState(run.paths);
    const e = st.check_executions.find((x) => x.result_artifact)!;
    await appendFile(resolveArtifact(run.paths.runDir, e.result_artifact!), " ");
    const view = await protectedView(f, run);
    expect(view.check_executions.map((x) => x.execution_id)).not.toContain(e.execution_id);
  });

  it("after a recovery (a new evidence epoch, §2.4 U3) the earlier checks and accepted review no longer count; items carry over", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-hy-5", 9405);
    expect((await protectedView(f, run)).reviews.filter((r) => r.accepted)).toHaveLength(1);
    f.custodian.simulateRecoveryAfterNewBoot();
    const view = await protectedView(f, run);
    expect(view.check_executions).toEqual([]);
    expect(view.reviews.map((r) => [r.accepted, r.not_accepted_reasons.includes("evidence_epoch_superseded")])).toEqual([[false, true]]);
    expect(view.findings.map((x) => x.status)).toEqual(["open"]);
    expect((await routeRun(f.le, run, view)).report.completion.ready).toBe(false);
  });

  it("status's engine conditions come from the custodian's record too: a check forged to failed in state.json lists no failed-check condition (VM run V2 finding)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-hy-6", 9406);
    await commitState(run.paths, f.le.env.owner, (cur) => {
      for (const e of cur.check_executions) {
        e.status = "failed";
        e.exit_code = 1;
      }
      return cur;
    });
    const view = await protectedView(f, run);
    const { report } = await routeRun(f.le, run, view);
    expect(report.conditions.map((c) => c.kind)).not.toContain("check_failed");
  });

  it("an attended run is read from the TS store as before", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await reviewed(f, run);
    const raw = await readState(run.paths);
    const view = await withAuthoritativeUserRecords(f.le, run, raw, { protected: false });
    expect(view.reviews).toEqual(raw.reviews);
    expect(view.findings).toEqual(raw.findings);
    expect(view.check_executions).toEqual(raw.check_executions);
  });
});
