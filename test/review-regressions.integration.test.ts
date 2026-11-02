// Regression tests for the Codex implementation review of M1.4, on real git repositories
// with the fake Codex: F2 (only accepted reviews change reviewer state), F3 (termination
// established only when it can be), F5 (freshness now vs at completion), F6 (anchored export
// verification), F10 (interrupted self-tests are not cached), F11 (one completion commit),
// F12 (removed tests are an engine condition).

import { describe, it, expect } from "vitest";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { buildReviewResult, captureChangesOf, requestReviewCancel, startReview, type ReviewEngineContext } from "../src/engine/review-operation.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { readState } from "../src/store/state-store.js";
import { clearProbeCache } from "../src/agents/codex/probe.js";
import { canonicalize, sha256OfBytes } from "../src/common/hash.js";
import { approve } from "./helpers/checks-fixture.js";
import { win, supported } from "./helpers/git-fixture.js";
import { defect, fakeCalls, fakeSelfTestDeps, grandchildPid, makeReviewFixture, newReviewRun, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";

const pidAlive = (p: number) => {
  try {
    process.kill(p, 0);
    return true;
  } catch (e) {
    return (e as { code?: string }).code === "EPERM";
  }
};

async function fresh(files: Record<string, string> = {}, committed: Record<string, string> = {}): Promise<ReviewFixture> {
  clearProbeCache();
  return makeReviewFixture(files, committed);
}

async function review(ctx: ReviewEngineContext, req: Parameters<typeof startReview>[1] = {}) {
  return (await startReview(ctx, req)).completion;
}

const resolvedOutput = () => output({ verdict: "APPROVE", prior_findings: [{ id: "PF-1", assessment: "apparently_resolved", superseded_by_index: null, note: "fixed" }] });

/** Round 1 raises an open defect; the source then changes (so "resolved" would be eligible). */
async function withOpenDefect(f: ReviewFixture, ctx: ReviewEngineContext): Promise<string> {
  await setScenario(f, okScenario(output({ findings: [defect()] })));
  const r1 = await review(ctx);
  expect(r1).toMatchObject({ status: "completed", accepted: true });
  writeFileSync(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a + b; // fixed\n}\n");
  return r1.review_id!;
}

/** Forge an exported file AND the export-local manifest consistently (F6). */
function forgeExport(exportDir: string): void {
  const bytes = Buffer.from("export function add(a, b) { return a + b; } // forged\n");
  writeFileSync(join(exportDir, "tree", "src", "math.js"), bytes);
  const mpath = join(exportDir, "review", "manifest.json");
  const m = JSON.parse(readFileSync(mpath, "utf8"));
  const entry = m.files.find((x: { path: string }) => x.path === "src/math.js");
  entry.size = bytes.length;
  entry.sha256 = sha256OfBytes(bytes);
  const { manifest_digest: _d, ...rest } = m;
  m.manifest_digest = createHash("sha256").update(canonicalize(rest), "utf8").digest("hex");
  writeFileSync(mpath, JSON.stringify(m, null, 2));
}

describe.skipIf(!supported)("M1.4 review regressions (Codex implementation review)", () => {
  it("F2: a STALE review reporting apparently_resolved changes no reviewer item and is not the current review", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    const r1 = await withOpenDefect(f, ctx);
    await setScenario(f, okScenario(resolvedOutput()));
    ctx.testHooks!.afterCodex = () => writeFileSync(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a - b; // reverted during the review\n}\n");
    const r2 = await review(ctx);
    expect(r2).toMatchObject({ status: "completed", accepted: false, current_review_id: r1, verdict: "APPROVE" });
    expect(r2.not_accepted_reasons).toContain("stale:source_changed_during_review");
    const st = await readState(ctx.runPaths);
    expect(st.findings).toHaveLength(1);
    expect(st.findings[0]).toMatchObject({ status: "open", assessments: [] });
    expect(r2.open_findings.map((x) => x.id)).toEqual([st.findings[0]!.id]);
    expect(r2.limitations.map((l) => l.code)).toContain("review_not_accepted");
    expect(r2.summary).toMatch(/NOT ACCEPTED/);
    // The stale review is never handed out for an identical input: Codex runs again.
    ctx.testHooks!.afterCodex = undefined;
    const execs = (await fakeCalls(f, "exec")).length;
    const r3 = await review(ctx);
    expect(r3.deduplicated).toBe(false);
    expect((await fakeCalls(f, "exec")).length).toBe(execs + 1);
  }, 120_000);

  it("F2: a LATE-CANCELLED review (cancelled after Codex finished, before acceptance) changes nothing", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    const r1 = await withOpenDefect(f, ctx);
    await setScenario(f, okScenario(output({ ...resolvedOutput(), findings: [defect({ title: "new claim from a cancelled review" })] })));
    let opId = "";
    ctx.testHooks!.afterCodex = () => {
      expect(requestReviewCancel(opId)).toBe("cancellation_requested");
    };
    const s = await startReview(ctx, {});
    opId = s.operation_id;
    const r2 = await s.completion;
    expect(r2).toMatchObject({ status: "cancelled", operation_status: "cancelled", accepted: false, current_review_id: r1 });
    // No process table in this test (sweep: null): no termination evidence, so never "terminated" (F3 round 2).
    expect(r2.cancellation).toMatchObject({ outcome: "cancellation_requested" });
    expect(r2.incidents.map((i) => i.kind)).toContain("cancellation_unconfirmed");
    expect(r2.findings.every((x) => x.status === "not_accepted")).toBe(true);
    const st = await readState(ctx.runPaths);
    expect(st.findings.map((x) => [x.title, x.status])).toEqual([["add() subtracts", "open"]]);
  }, 120_000);

  it("F2: an isolation-invalid review (file_change item) changes nothing", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await withOpenDefect(f, ctx);
    await setScenario(f, okScenario(resolvedOutput(), { events: [{ type: "item.completed", item: { id: "f1", type: "file_change", changes: [{ path: "tree/src/math.js" }] } }] }));
    const r2 = await review(ctx);
    expect(r2).toMatchObject({ status: "completed", accepted: false });
    expect(r2.not_accepted_reasons).toContain("incident:isolation_violation_file_change");
    expect((await readState(ctx.runPaths)).findings[0]!.status).toBe("open");
  }, 120_000);

  it("F3: a detached grandchild behind an exited intermediate keeps cancellation unconfirmed and is reported", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f);
    ctx.testHooks!.sweep = {}; // the real process table
    await setScenario(f, { exec: { spawn_orphaned_grandchild: true, hang: "silent" } as never });
    const s = await startReview(ctx, {});
    for (let i = 0; i < 100 && grandchildPid(f) === null; i++) await new Promise((r) => setTimeout(r, 100));
    await new Promise((r) => setTimeout(r, 500));
    const gc = grandchildPid(f)!;
    expect(pidAlive(gc)).toBe(true);
    requestReviewCancel(s.operation_id);
    const r = await s.completion;
    try {
      expect(r.status).toBe("cancelled");
      expect(r.cancellation).toMatchObject({ outcome: "cancellation_requested" });
      expect(r.cancellation!.unattributable.map((p) => p.pid)).toContain(gc);
      expect(r.cancellation!.detail).toMatch(/untraceable ancestry/);
      const inc = r.incidents.find((i) => i.kind === "cancellation_unconfirmed")!;
      expect(inc.detail).toContain(`(${gc}, unattributable)`);
      expect(pidAlive(gc)).toBe(true); // unattributable processes are reported, never killed
    } finally {
      try {
        process.kill(gc);
      } catch {
        /* gone */
      }
    }
  }, 90_000);

  it("F5: a completed review reports freshness NOW, separately from freshness at completion (incl. request_id and dedupe retrieval)", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await setScenario(f, okScenario(output()));
    const r = await review(ctx, { request_id: "req-f5" });
    expect(r.freshness).toMatchObject({ current: true });
    expect(r.freshness_at_completion).toMatchObject({ current: true });
    const dup = await review(ctx);
    expect(dup).toMatchObject({ deduplicated: true, review_id: r.review_id, freshness: { current: true } });
    writeFileSync(join(f.repo, "src", "math.js"), "export const changed = true;\n");
    const later = await buildReviewResult(ctx, r.operation_id);
    expect(later.freshness).toMatchObject({ current: false, source: false });
    expect(later.freshness!.stale_reasons).toContain("source_changed_since_review");
    expect(later.freshness_at_completion).toMatchObject({ current: true });
    expect(later.summary).toMatch(/NOT current now/);
    const again = await (await startReview(ctx, { request_id: "req-f5" })).completion;
    expect(again.operation_id).toBe(r.operation_id);
    expect(again.freshness).toMatchObject({ current: false });
    expect(again.freshness_at_completion).toMatchObject({ current: true });
  }, 120_000);

  it("F6: forging an exported file together with the export-local manifest is detected before and after Codex", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await setScenario(f, okScenario(output()));
    let exportDir = "";
    ctx.testHooks!.beforeCodex = async () => {
      const st = await readState(ctx.runPaths);
      exportDir = join(ctx.runPaths.runDir, ...st.reviews.at(-1)!.export_ref.split("/"));
      forgeExport(exportDir);
    };
    const before = await review(ctx);
    expect(before).toMatchObject({ status: "failed", failure: { class: "INTERNAL" } });
    expect(before.failure!.detail).toMatch(/anchored export digest mismatch/);
    expect(await fakeCalls(f, "exec")).toHaveLength(0); // Codex never saw the forged export

    ctx.testHooks!.beforeCodex = undefined;
    ctx.testHooks!.afterCodex = async () => {
      const st = await readState(ctx.runPaths);
      forgeExport(join(ctx.runPaths.runDir, ...st.reviews.at(-1)!.export_ref.split("/")));
    };
    const after = await review(ctx, { force_new: true });
    expect(after).toMatchObject({ status: "completed", accepted: false });
    expect(after.incidents.map((i) => i.kind)).toContain("export_modified_during_review");
    expect(after.not_accepted_reasons).toContain("incident:export_modified_during_review");
  }, 120_000);

  it("F10: a self-test cancelled mid-way is not cached; the next review re-runs it", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await setScenario(f, okScenario(output()));
    const deps = fakeSelfTestDeps(f);
    let opId = "";
    let calls = 0;
    ctx.testHooks!.selfTestDeps = {
      ...deps,
      runCodex: async (argv, cwd, signal) => {
        if (++calls === 3) requestReviewCancel(opId);
        return deps.runCodex(argv, cwd, signal);
      },
    };
    const s = await startReview(ctx, {});
    opId = s.operation_id;
    const r = await s.completion;
    expect(r).toMatchObject({ status: "cancelled", operation_status: "cancelled" });
    // Probes were killed; without a process table there is no evidence they are gone.
    expect(r.cancellation).toMatchObject({ outcome: "cancellation_requested" });
    expect(r.incidents.map((i) => i.kind)).toContain("cancellation_unconfirmed");
    const { readdirSync, existsSync } = await import("node:fs");
    expect(existsSync(ctx.selftestDir) ? readdirSync(ctx.selftestDir) : []).toEqual([]);

    // A probe that timed out is not a determination either: not stored, S1 refused this time.
    ctx.testHooks!.selfTestDeps = { ...deps, runCodex: async (argv, cwd, signal) => ({ ...(await deps.runCodex(argv, cwd, signal)), incomplete: argv.join(" ").includes(win ? "TcpClient" : "/dev/tcp/") }) };
    const t = await review(ctx);
    expect(t.failure).toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    expect(t.failure!.detail).toMatch(/did not complete/);
    expect(existsSync(ctx.selftestDir) ? readdirSync(ctx.selftestDir) : []).toEqual([]);

    // The next review re-runs the self-test, stores it (complete) and reviews.
    ctx.testHooks!.selfTestDeps = deps;
    const before = (await fakeCalls(f, "sandbox")).length;
    const ok = await review(ctx);
    expect(ok.status).toBe("completed");
    expect((await fakeCalls(f, "sandbox")).length).toBeGreaterThan(before);
    expect(readdirSync(ctx.selftestDir)).toHaveLength(1);
  }, 120_000);

  it("F10: a COMPLETED self-test failure is cached (not re-run) under the same identity", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await setScenario(f, { sandbox: { mode: "reject" }, ...okScenario(output()) });
    expect((await review(ctx)).failure).toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    const n = (await fakeCalls(f, "sandbox")).length;
    expect((await review(ctx)).failure).toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    expect((await fakeCalls(f, "sandbox")).length).toBe(n);
  }, 90_000);

  it("F11: result publication, item lifecycle, operation completion and run state change in ONE commit", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await withOpenDefect(f, ctx);
    await setScenario(f, okScenario(output({ ...resolvedOutput(), findings: [defect({ title: "second" })] })));
    let before: Awaited<ReturnType<typeof readState>> | null = null;
    ctx.testHooks!.beforeCompletionCommit = async () => {
      before = await readState(ctx.runPaths);
    };
    const r = await review(ctx);
    const after = await readState(ctx.runPaths);
    const b = before!;
    const opB = b.operations.find((o) => o.operation_id === r.operation_id)!;
    const opA = after.operations.find((o) => o.operation_id === r.operation_id)!;
    expect([opB.status, b.reviews.at(-1)!.status, b.state, b.findings.map((x) => x.status)]).toEqual(["running", "running", "REVIEWING", ["open"]]);
    expect(after.revision).toBe(b.revision + 1); // exactly one commit
    expect([opA.status, after.reviews.at(-1)!.status, after.state]).toEqual(["completed", "completed", "IDLE"]);
    expect(after.findings.map((x) => [x.title, x.status])).toEqual([
      ["add() subtracts", "reported_resolved"],
      ["second", "open"],
    ]);
    // A failure injected at that boundary leaves no half-published result.
    await setScenario(f, okScenario(output({ findings: [defect({ title: "third" })] })));
    ctx.testHooks!.beforeCompletionCommit = () => {
      throw new Error("injected fault at the completion boundary");
    };
    const failed = await review(ctx, { force_new: true });
    const st = await readState(ctx.runPaths);
    expect(failed).toMatchObject({ status: "failed", operation_status: "failed", accepted: false });
    expect(st.state).toBe("IDLE");
    expect(st.findings.map((x) => x.title)).toEqual(["add() subtracts", "second"]);
  }, 120_000);

  it("a failed terminal commit is retried, never swallowed; past the retry window it is reported and still recorded later (PR #2 review)", async () => {
    const f = await fresh();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
    await setScenario(f, okScenario(output({ findings: [defect()] })));
    // Two transient failures (a lock, an antivirus-held file): retried, the review completes.
    ctx.testHooks!.terminalCommit = { failures: 2, retryMs: 10_000 };
    expect(await review(ctx)).toMatchObject({ status: "completed", operation_status: "completed" });
    expect(ctx.testHooks!.terminalCommit.failures).toBe(0);
    // Failing beyond the retry window: the caller gets the error, not a result read from a
    // record that still says "running"; once writes succeed again the background retry records
    // the outcome, so the run does not stay busy while this server lives.
    const hook = { failures: 1_000_000, retryMs: 300, backgroundMs: 200 };
    ctx.testHooks!.terminalCommit = hook;
    const s = await startReview(ctx, { force_new: true });
    await expect(s.completion).rejects.toSatisfy((e) => (e as { code?: string }).code === "STORE_LOCKED");
    expect((await readState(ctx.runPaths)).operations.find((o) => o.operation_id === s.operation_id)!.status).toBe("running");
    hook.failures = 0;
    let status = "running";
    for (let i = 0; i < 50 && status === "running"; i++) {
      await new Promise((res) => setTimeout(res, 100));
      status = (await readState(ctx.runPaths)).operations.find((o) => o.operation_id === s.operation_id)!.status;
    }
    expect(status).not.toBe("running");
  }, 120_000);

  it("F12: removed tests are an engine condition, derived from the capture whatever the reviewer says", async () => {
    const f = await fresh({}, { "test/math.test.js": "test('add', () => {});\n", "test/other.test.js": "x\n" });
    await approve(f, { checks: { unit: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"], test_globs: ["test/**"] });
    rmSync(join(f.repo, "test", "math.test.js"));
    writeFileSync(join(f.repo, "test", "other.test.js"), "y\n"); // modified: not a removal
    await setScenario(f, okScenario(output({ verdict: "APPROVE" })));
    const { review: ctx } = await newReviewRun(f);
    const r = await review(ctx);
    const c = r.conditions.find((x) => x.code === "tests_removed")!;
    expect(c).toMatchObject({ kind: "coverage", source: "engine" });
    expect(c.detail).toContain("test/math.test.js");
    expect(c.detail).not.toContain("test/other.test.js");

    // The record's deletions and renames are read once and kept (capture records are
    // immutable): a later report no longer depends on reading the record again. Other rows
    // cannot be removed tests and are not kept.
    const rec = (await readState(ctx.runPaths)).reviews.at(-1)!;
    const path = resolveArtifact(ctx.runPaths.runDir, rec.artifacts["capture"]!);
    const rows = await captureChangesOf(path);
    expect(rows?.map((x) => [x.path, x.status])).toEqual([["test/math.test.js", "deleted"]]);
    const saved = readFileSync(path);
    rmSync(path);
    try {
      expect(await captureChangesOf(path)).toBe(rows);
      expect(await captureChangesOf(`${path}.missing`)).toBeNull();
    } finally {
      writeFileSync(path, saved);
    }
  }, 90_000);

  it("F4 round 2: nested-escaped confidential paths in host text are redacted before Codex; undecodable-by-redaction forms fail closed", async () => {
    const f = await fresh({ "config/db.env": "DB_PASSWORD=swordfish\n" });
    const nested = JSON.stringify({ payload: JSON.stringify({ path: "config\\db.env" }) });
    const deeper = JSON.stringify(JSON.stringify(nested));
    const { review: ctx } = await newReviewRun(f, { maxReviews: 10, envelope: { goal: "Fix add()", background: `host notes: ${nested} and ${deeper} and **CONFIG/DB.ENV**` } });
    await setScenario(f, okScenario(output()));
    const r = await review(ctx);
    expect(r.status).toBe("completed");
    const prompt = (await import("./helpers/review-fixture.js")).lastExec(f).then((c) => c.prompt!);
    const text = await prompt;
    const { assertTextConfidential } = await import("../src/policy/review-bundle.js");
    // The whole prompt Codex received, decoded through the supported escape depth, names neither.
    expect(() => assertTextConfidential(text, new Set(["config/db.env", ".env"]), new Set())).not.toThrow();
    expect(text).toContain("[withheld path]");

    // An encoding redaction does not rewrite (an escaped letter) is caught by the invariant
    // on the rendered sections: the review fails closed and Codex is never started.
    const execs = (await fakeCalls(f, "exec")).length;
    const { review: ctx2 } = await newReviewRun(f, { envelope: { goal: "Fix add()", background: "see \\u0063onfig/db.env" } });
    const r2 = await review(ctx2);
    expect(r2.operation_status).toBe("failed");
    expect(r2.failure!.detail).toMatch(/MR-F/);
    expect((await fakeCalls(f, "exec")).length).toBe(execs);
  }, 120_000);
});
