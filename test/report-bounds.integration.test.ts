// Report-time work stays inside host per-call limits (plan C4, M1.5-8; M1.6 fix). A status or
// stop report reads the working tree at most once, within what is left of the call's time,
// and the review's freshness reuses that read — or says "not rechecked" — instead of reading
// the tree a second time without a bound.

import { describe, it, expect } from "vitest";
import { buildReviewResult, reviewFreshnessNow, startReview } from "../src/engine/review-operation.js";
import { CALL_SOFT_LIMIT_MS, SOURCE_BUDGET_MS, knownSourceOf, shareWithinBudget, sourceBudgetFor, type SharedRun } from "../src/engine/status.js";
import { readState } from "../src/store/state-store.js";
import { clearProbeCache } from "../src/agents/codex/probe.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, makeReviewFixture, newReviewRun, okScenario, output, setScenario } from "./helpers/review-fixture.js";

describe("the call's time budget for a report (pure)", () => {
  it("a fresh call may spend the full source budget; a call whose wait used its time spends none", () => {
    const t0 = 1_000_000;
    expect(sourceBudgetFor(t0, t0)).toBe(SOURCE_BUDGET_MS);
    expect(sourceBudgetFor(t0, t0 + 45_000)).toBe(CALL_SOFT_LIMIT_MS - 45_000);
    expect(sourceBudgetFor(t0, t0 + CALL_SOFT_LIMIT_MS + 1)).toBe(0);
    expect(CALL_SOFT_LIMIT_MS).toBeLessThan(60_000); // Desktop Chat's limit for user-added servers
  });

  it("only a recomputed, stable-known identity is reused; anything else is 'unavailable'", () => {
    expect(knownSourceOf(null)).toBe("unavailable");
    expect(knownSourceOf({ source_id: "a".repeat(64), age_ms: 5000, recomputed: false, stable: null, note: "busy", entries: null })).toBe("unavailable");
    expect(knownSourceOf({ source_id: "a".repeat(64), age_ms: 0, recomputed: true, stable: true, note: null, entries: [] })).toEqual({ source_id: "a".repeat(64), stable: true });
  });
});

describe("one tree read shared by concurrent calls, each within its own budget (PR #2 review)", () => {
  type R = { recomputed: boolean; v: string };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const retryable = (r: R) => !r.recomputed;

  it("a call never waits past its own budget for another call's read", async () => {
    const runs = new Map<string, SharedRun<R>>();
    let computed = 0;
    const slow = async (): Promise<R> => {
      computed++;
      await sleep(1500);
      return { recomputed: true, v: "slow" };
    };
    const a = shareWithinBudget(runs, "repo", 10_000, slow, retryable);
    const t0 = Date.now();
    expect(await shareWithinBudget(runs, "repo", 200, slow, retryable)).toBeNull();
    expect(Date.now() - t0).toBeLessThan(1000);
    expect((await a)?.v).toBe("slow");
    expect(computed).toBe(1);
  });

  it("a call with more time reads again when the shared read ended early on a shorter budget", async () => {
    const runs = new Map<string, SharedRun<R>>();
    const budgets: number[] = [];
    const compute = async (budget: number): Promise<R> => {
      budgets.push(budget);
      await sleep(100);
      return budget < 1000 ? { recomputed: false, v: "ran out" } : { recomputed: true, v: "full" };
    };
    const a = shareWithinBudget(runs, "repo", 300, compute, retryable);
    const b = await shareWithinBudget(runs, "repo", 5000, compute, retryable);
    expect((await a)?.v).toBe("ran out");
    expect(b?.v).toBe("full");
    expect(budgets).toHaveLength(2);
  });

  it("calls with similar budgets share one read", async () => {
    const runs = new Map<string, SharedRun<R>>();
    let computed = 0;
    const compute = async (): Promise<R> => {
      computed++;
      await sleep(200);
      return { recomputed: true, v: "x" };
    };
    const [a, b] = await Promise.all([shareWithinBudget(runs, "repo", 5000, compute, retryable), shareWithinBudget(runs, "repo", 5000, compute, retryable)]);
    expect([a?.v, b?.v]).toEqual(["x", "x"]);
    expect(computed).toBe(1);
  });
});

describe.skipIf(!supported)("review freshness at report time never reads the tree a second time", () => {
  it("'unavailable' is reported as not rechecked; a report-time read is bounded; the result builder honours both", async () => {
    clearProbeCache();
    const f = await makeReviewFixture();
    await setScenario(f, okScenario(output({ findings: [defect()] })));
    const { review: ctx } = await newReviewRun(f, { envelope: { goal: "Implement add()" } });
    const r = await (await startReview(ctx, {})).completion;
    expect(r.status).toBe("completed");
    const review = (await readState(ctx.runPaths)).reviews.find((x) => x.review_id === r.review_id)!;

    const normal = await reviewFreshnessNow(ctx, review);
    expect(normal).toMatchObject({ source: true, current: true });

    const unavailable = await reviewFreshnessNow(ctx, review, "unavailable");
    expect(unavailable).toMatchObject({ source: null, current: false });
    expect(unavailable!.stale_reasons).toContain("source_not_rechecked:not_recomputed_in_this_report");

    const t0 = Date.now();
    const tiny = await reviewFreshnessNow(ctx, review, undefined, 1);
    expect(Date.now() - t0).toBeLessThan(10_000);
    expect(tiny!.current).toBe(false);
    expect(tiny!.stale_reasons.some((s) => s.startsWith("source_not_rechecked:"))).toBe(true);

    const built = await buildReviewResult(ctx, r.operation_id, undefined, "unavailable");
    expect(built.freshness).toMatchObject({ current: false });
    expect(built.freshness!.stale_reasons).toContain("source_not_rechecked:not_recomputed_in_this_report");
  }, 120_000);
});
