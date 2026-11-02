// Cancellation evidence (F3, round 2): every path that reports `terminated` uses the same
// conservative termination evidence — during execution, right after Codex returns, during
// finalization (late), and before Codex starts. A scripted process table makes the evidence
// deterministic: a clean table establishes termination; a failed sweep, a known survivor or
// a missing table never does, and always records `cancellation_unconfirmed`.

import { describe, it, expect } from "vitest";
import { requestReviewCancel, startReview, type ReviewEngineContext } from "../src/engine/review-operation.js";
import { readState } from "../src/store/state-store.js";
import { clearProbeCache } from "../src/agents/codex/probe.js";
import type { ProcEntry } from "../src/process/proc-table.js";
import { supported } from "./helpers/git-fixture.js";
import { fakeSelfTestDeps, makeReviewFixture, newReviewRun, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";

const SURVIVOR = 999_991;

/**
 * A scripted process table. `codexPid` is learnt at spawn. Modes:
 *  clean        — only this server: nothing of the review survives;
 *  survivor     — a descendant of the Codex process that a kill cannot end;
 *  sweep_blind  — readable once, then unreadable (the sweep cannot confirm anything);
 *  op_survivor  — a process this server started during the operation still runs.
 */
function scriptedTable(mode: "clean" | "survivor" | "sweep_blind" | "op_survivor") {
  const t0 = Date.now();
  const state = { codexPid: 0, calls: 0 };
  const server: ProcEntry = { pid: process.pid, ppid: 1, createdMs: t0 - 3_600_000, name: "node.exe" };
  const snapshot = async (): Promise<ProcEntry[] | null> => {
    state.calls++;
    if (mode === "sweep_blind" && state.calls > 1) return null;
    const rows: ProcEntry[] = [server];
    if (mode === "survivor" && state.codexPid) rows.push({ pid: SURVIVOR, ppid: state.codexPid, createdMs: Date.now(), name: "survivor.exe" });
    if (mode === "sweep_blind" && state.codexPid) rows.push({ pid: SURVIVOR, ppid: state.codexPid, createdMs: Date.now(), name: "survivor.exe" });
    if (mode === "op_survivor") rows.push({ pid: SURVIVOR, ppid: process.pid, createdMs: Date.now(), name: "probe-survivor.exe" });
    return rows;
  };
  return { state, deps: { snapshot, kill: async () => false } };
}

async function setup(mode: Parameters<typeof scriptedTable>[0]): Promise<{ f: ReviewFixture; ctx: ReviewEngineContext; table: ReturnType<typeof scriptedTable> }> {
  clearProbeCache();
  const f = await makeReviewFixture();
  const { review: ctx } = await newReviewRun(f, { maxReviews: 10 });
  const table = scriptedTable(mode);
  ctx.testHooks!.sweep = table.deps;
  ctx.testHooks!.afterSpawn = (pid) => {
    table.state.codexPid = pid;
  };
  return { f, ctx, table };
}

async function cancelAt(ctx: ReviewEngineContext, hook: "afterSpawn" | "afterCodex" | "beforeCompletionCommit") {
  let opId = "";
  const prev = ctx.testHooks![hook] as ((pid: number) => void) | undefined;
  (ctx.testHooks as Record<string, unknown>)[hook] = (pid: number) => {
    prev?.(pid);
    requestReviewCancel(opId);
  };
  const s = await startReview(ctx, {});
  opId = s.operation_id;
  return s.completion;
}

function expectUnconfirmed(r: Awaited<ReturnType<typeof cancelAt>>) {
  expect(r.status).toBe("cancelled");
  expect(r.accepted).toBe(false);
  expect(r.cancellation).toMatchObject({ outcome: "cancellation_requested" });
  expect(r.cancellation!.detail.length).toBeGreaterThan(0);
  const inc = r.incidents.filter((i) => i.kind === "cancellation_unconfirmed");
  expect(inc).toHaveLength(1);
  return inc[0]!;
}

describe.skipIf(!supported)("cancellation evidence (F3 round 2)", () => {
  it("during execution: a clean table establishes termination; a known survivor does not", async () => {
    const a = await setup("clean");
    await setScenario(a.f, { exec: { hang: "silent" } });
    const ra = await cancelAt(a.ctx, "afterSpawn");
    expect(ra.cancellation).toMatchObject({ outcome: "terminated", survivors: [], unattributable: [] });
    expect(ra.incidents.filter((i) => i.kind === "cancellation_unconfirmed")).toEqual([]);

    const b = await setup("survivor");
    await setScenario(b.f, { exec: { hang: "silent" } });
    const rb = await cancelAt(b.ctx, "afterSpawn");
    const inc = expectUnconfirmed(rb);
    expect(rb.cancellation!.survivors.map((s) => s.pid)).toContain(SURVIVOR);
    expect(inc.detail).toContain(`(${SURVIVOR})`);
  }, 90_000);

  it("immediately after Codex returns (late): the same evidence decides — clean → terminated", async () => {
    const { f, ctx } = await setup("clean");
    await setScenario(f, okScenario(output()));
    const r = await cancelAt(ctx, "afterCodex");
    expect(r).toMatchObject({ status: "cancelled", accepted: false });
    expect(r.cancellation).toMatchObject({ outcome: "terminated", survivors: [], unattributable: [] });
    expect(r.cancellation!.detail).toMatch(/no process created during the run is untraceable/);
    expect(r.incidents.filter((i) => i.kind === "cancellation_unconfirmed")).toEqual([]);
  }, 90_000);

  it("during finalization (just before the completion commit): a known survivor → unconfirmed + incident", async () => {
    const { f, ctx } = await setup("survivor");
    await setScenario(f, okScenario(output()));
    const r = await cancelAt(ctx, "beforeCompletionCommit");
    const inc = expectUnconfirmed(r);
    expect(r.cancellation!.survivors.map((s) => s.pid)).toContain(SURVIVOR);
    expect(inc.detail).toContain("survivor.exe");
    const st = await readState(ctx.runPaths);
    expect(st.reviews.at(-1)!.incident_ids).toContain(inc.incident_id);
  }, 90_000);

  it("late cancellation with run.descendants.terminated = false (sweep could not confirm) → unconfirmed", async () => {
    const { f, ctx } = await setup("sweep_blind");
    await setScenario(f, okScenario(output()));
    const r = await cancelAt(ctx, "afterCodex");
    expectUnconfirmed(r);
    const st = await readState(ctx.runPaths);
    const rec = st.reviews.at(-1)!;
    const result = JSON.parse((await import("node:fs")).readFileSync((await import("../src/store/artifacts.js")).resolveArtifact(ctx.runPaths.runDir, rec.artifacts["result"]!), "utf8")) as { descendants: { terminated: boolean | null } };
    expect(result.descendants.terminated).not.toBe(true);
  }, 90_000);

  it("late cancellation with a known surviving descendant → unconfirmed, survivor named", async () => {
    const { f, ctx } = await setup("survivor");
    await setScenario(f, okScenario(output()));
    const r = await cancelAt(ctx, "afterCodex");
    const inc = expectUnconfirmed(r);
    expect(r.cancellation!.survivors).toEqual(expect.arrayContaining([{ pid: SURVIVOR, name: "survivor.exe" }]));
    expect(inc.detail).toContain(`survivor.exe (${SURVIVOR})`);
  }, 90_000);

  it("late cancellation without any process table → never terminated", async () => {
    clearProbeCache();
    const f = await makeReviewFixture();
    const { review: ctx } = await newReviewRun(f);
    ctx.testHooks!.sweep = null;
    await setScenario(f, okScenario(output()));
    const r = await cancelAt(ctx, "afterCodex");
    expectUnconfirmed(r);
    expect(r.cancellation!.detail).toMatch(/no termination evidence|could not be read/);
  }, 90_000);

  // --- timeouts (F3 round 3): the process layer's kill record carries the pre-kill evidence ---

  /** A table where, while Codex lives, a grandchild with unknown creation time hangs off an
   * intermediate that the kill ends; afterwards only the pre-kill snapshot can tell it is ours. */
  function hiddenDescendantTable() {
    const MID = 999_801;
    const DESC = 999_802;
    const state = { codexPid: 0 };
    const pidAlive = (p: number) => {
      try {
        process.kill(p, 0);
        return true;
      } catch (e) {
        return (e as { code?: string }).code === "EPERM";
      }
    };
    const server: ProcEntry = { pid: process.pid, ppid: 1, createdMs: Date.now() - 3_600_000, name: "node.exe" };
    const snapshot = async (): Promise<ProcEntry[]> =>
      state.codexPid && pidAlive(state.codexPid)
        ? [server, { pid: state.codexPid, ppid: process.pid, createdMs: Date.now() - 1000, name: "codex.exe" }, { pid: MID, ppid: state.codexPid, createdMs: Date.now() - 500, name: "pwsh.exe" }, { pid: DESC, ppid: MID, createdMs: 0, name: "sleeper.exe" }]
        : [server, { pid: DESC, ppid: MID, createdMs: 0, name: "sleeper.exe" }];
    return { state, deps: { snapshot, kill: async () => true }, DESC };
  }

  it("wall timeout followed by late cancellation: clean evidence → terminated, recorded as a wall-timeout kill", async () => {
    const { f, ctx } = await setup("clean");
    ctx.testHooks!.limits = { wallMs: 1500, idleMs: 60_000 };
    await setScenario(f, { exec: { hang: "chatty" } });
    const r = await cancelAt(ctx, "afterCodex");
    expect(r.status).toBe("cancelled");
    expect(r.cancellation).toMatchObject({ outcome: "terminated" });
    expect(r.incidents.filter((i) => /_unconfirmed$/.test(i.kind))).toEqual([]);
    const rec = (await readState(ctx.runPaths)).reviews.at(-1)!;
    expect(rec.termination).toMatchObject({ reason: "wall_timeout", established: true });
  }, 90_000);

  it("idle timeout followed by late cancellation: a descendant seen before the kill keeps it unconfirmed", async () => {
    clearProbeCache();
    const f = await makeReviewFixture();
    const { review: ctx } = await newReviewRun(f);
    const t = hiddenDescendantTable();
    ctx.testHooks!.sweep = t.deps;
    ctx.testHooks!.afterSpawn = (pid) => {
      t.state.codexPid = pid;
    };
    ctx.testHooks!.limits = { idleMs: 1500 };
    await setScenario(f, { exec: { hang: "silent" } });
    const r = await cancelAt(ctx, "afterCodex");
    const inc = expectUnconfirmed(r);
    expect(r.cancellation!.survivors.map((s) => s.pid)).toContain(t.DESC);
    expect(r.cancellation!.detail).toMatch(/seen before the kill are still running/);
    expect(inc.detail).toContain("sleeper.exe");
    expect((await readState(ctx.runPaths)).reviews.at(-1)!.termination).toMatchObject({ reason: "idle_timeout", established: false });
  }, 90_000);

  it("timeout with a surviving descendant (no cancellation): timed_out, termination unconfirmed, incident", async () => {
    const { f, ctx } = await setup("survivor");
    ctx.testHooks!.limits = { idleMs: 1500 };
    await setScenario(f, { exec: { hang: "silent" } });
    const r = await (await startReview(ctx, {})).completion;
    expect(r.status).toBe("timed_out");
    expect(r.cancellation).toBeNull();
    const inc = r.incidents.filter((i) => i.kind === "termination_unconfirmed");
    expect(inc).toHaveLength(1);
    expect(inc[0]!.detail).toMatch(/killed \(idle_timeout\)/);
    expect(inc[0]!.detail).toContain(`survivor.exe (${SURVIVOR})`);
    const rec = (await readState(ctx.runPaths)).reviews.at(-1)!;
    expect(rec.termination).toMatchObject({ reason: "idle_timeout", established: false });
  }, 90_000);

  it("timeout with an untraceable process created during the run: unconfirmed", async () => {
    clearProbeCache();
    const f = await makeReviewFixture();
    const { review: ctx } = await newReviewRun(f);
    const server: ProcEntry = { pid: process.pid, ppid: 1, createdMs: Date.now() - 3_600_000, name: "node.exe" };
    ctx.testHooks!.sweep = { snapshot: async () => [server, { pid: 999_803, ppid: 999_000, createdMs: Date.now(), name: "orphan.exe" }], kill: async () => true };
    ctx.testHooks!.limits = { wallMs: 1500, idleMs: 60_000 };
    await setScenario(f, { exec: { hang: "chatty" } });
    const r = await (await startReview(ctx, {})).completion;
    expect(r.status).toBe("timed_out");
    const inc = r.incidents.find((i) => i.kind === "termination_unconfirmed")!;
    expect(inc.detail).toContain("orphan.exe (999803, unattributable)");
  }, 90_000);

  it("timeout with fully confirmed termination: no incident, established", async () => {
    const { f, ctx } = await setup("clean");
    ctx.testHooks!.limits = { idleMs: 1500 };
    await setScenario(f, { exec: { hang: "silent" } });
    const r = await (await startReview(ctx, {})).completion;
    expect(r.status).toBe("timed_out");
    expect(r.incidents.filter((i) => /_unconfirmed$/.test(i.kind))).toEqual([]);
    expect((await readState(ctx.runPaths)).reviews.at(-1)!.termination).toMatchObject({ reason: "idle_timeout", established: true, survivors: [], unattributable: [] });
  }, 90_000);

  it("before Codex starts (cancelled during the self-test): the operation-level evidence decides", async () => {
    for (const [mode, expected] of [
      ["clean", "terminated"],
      ["op_survivor", "cancellation_requested"],
    ] as const) {
      const { f, ctx } = await setup(mode);
      await setScenario(f, okScenario(output()));
      const deps = fakeSelfTestDeps(f);
      let opId = "";
      let calls = 0;
      ctx.testHooks!.selfTestDeps = {
        ...deps,
        runCodex: async (argv, cwd, signal) => {
          if (++calls === 2) requestReviewCancel(opId);
          return deps.runCodex(argv, cwd, signal);
        },
      };
      const s = await startReview(ctx, {});
      opId = s.operation_id;
      const r = await s.completion;
      expect(r.status, mode).toBe("cancelled");
      expect(r.cancellation?.outcome, mode).toBe(expected);
      const unconfirmed = r.incidents.filter((i) => i.kind === "cancellation_unconfirmed");
      expect(unconfirmed.length, mode).toBe(expected === "terminated" ? 0 : 1);
      if (expected !== "terminated") expect(unconfirmed[0]!.detail).toContain("probe-survivor.exe");
    }
  }, 120_000);
});
