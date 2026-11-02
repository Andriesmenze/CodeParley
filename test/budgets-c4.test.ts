// P3.4C-3 C4 (contract §6.5): reports and routing use the same effective limits as the starts — on an attended run
// min(config, run.json, hard caps), on a protected run the custodian's limits and use — so routing never requests an
// operation a start would refuse. Boundary: consistency only, not a security property.

import { describe, it, expect } from "vitest";
import { routeRun } from "../src/engine/continuation.js";
import { HARD_MAX_REVIEWS_PER_RUN } from "../src/engine/hard-limits.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { reportBudgets } from "../src/engine/status.js";
import { commitState, readState } from "../src/store/state-store.js";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, newRun, runChecks, startReview } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [] }));

describe.skipIf(!supported)("C4 — budgets in reports and routing", () => {
  it("a configured review limit above the hard cap: the report shows the cap, and routing ends at it instead of requesting a review", async () => {
    const f = await contFixture(scenario());
    f.le.cfg.config.budgets.max_reviews_per_run = HARD_MAX_REVIEWS_PER_RUN + 30;
    const run = await newRun(f);
    await runChecks(f, run);
    let st = await readState(run.paths);
    expect(reportBudgets(f.le, run, st).find((b) => b.name === "reviews")!.limit).toBe(HARD_MAX_REVIEWS_PER_RUN);
    expect((await routeRun(f.le, run, st)).route.code).toBe("request_review");

    st = await commitState(run.paths, f.le.env.owner, (cur) => {
      cur.counters["reviews"] = HARD_MAX_REVIEWS_PER_RUN;
      return cur;
    });
    const routed = await routeRun(f.le, run, st);
    expect(routed.route).toMatchObject({ code: "end", end: "budget_exhausted", reason: "review_budget" });
  });

  it("a protected run reports the custodian's limits and use: a local counter reset changes nothing", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await grant(f, 1);
    await new HostSession(f, "sess-c4", 9501).startLoop(run);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    await commitState(run.paths, f.le.env.owner, (cur) => {
      cur.counters["reviews"] = 0;
      cur.counters["check_executions"] = 0;
      return cur;
    });
    const view = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
    const c = f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!;
    const budgets = reportBudgets(f.le, run, view);
    expect(budgets.find((b) => b.name === "reviews")).toMatchObject({ used: 1 });
    expect(budgets.find((b) => b.name === "check_executions")!.used).toBe(c.checkExecutions.filter((e) => e["status"] !== "skipped").length);
    expect(budgets.find((b) => b.name === "reviews")!.limit).toBe(Math.min(c.declaration.budgets.maxReviews, HARD_MAX_REVIEWS_PER_RUN));
  });
});
