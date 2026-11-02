// Check-operation cancellation evidence (MR-J; M1.5). A cancelled checks operation reports
// `terminated` only on the same termination evidence as reviews (F3, confirmTreeTermination):
// a pre-kill snapshot, a readable post-exit table, no linked or untraceable survivor. A
// scripted process table makes the evidence deterministic; with no table there is no evidence
// and the outcome is always `cancellation_requested`.

import { describe, it, expect } from "vitest";
import { requestChecksCancel, startChecks, type ChecksEngineContext } from "../src/engine/checks-operation.js";
import { readState } from "../src/store/state-store.js";
import type { ProcEntry } from "../src/process/proc-table.js";
import { approve, makeFixture, newRun, node, type Fixture } from "./helpers/checks-fixture.js";
import { supported } from "./helpers/git-fixture.js";

const SURVIVOR = 999_983;

function scriptedTable(mode: "clean" | "survivor" | "op_survivor" | "blind") {
  const t0 = Date.now();
  const state = { childPid: 0 };
  const server: ProcEntry = { pid: process.pid, ppid: 1, createdMs: t0 - 3_600_000, name: "node.exe" };
  const snapshot = async (): Promise<ProcEntry[] | null> => {
    if (mode === "blind") return null;
    const rows: ProcEntry[] = [server];
    if (mode === "survivor" && state.childPid) rows.push({ pid: SURVIVOR, ppid: state.childPid, createdMs: Date.now(), name: "grandchild.exe" });
    if (mode === "op_survivor") rows.push({ pid: SURVIVOR, ppid: process.pid, createdMs: Date.now(), name: "git.exe" });
    return rows;
  };
  return { state, deps: { snapshot, kill: async () => false } };
}

async function setup(mode: Parameters<typeof scriptedTable>[0] | "none"): Promise<{ f: Fixture; ctx: ChecksEngineContext; table: ReturnType<typeof scriptedTable> | null }> {
  const f = await makeFixture();
  await approve(f, { checks: { slow: { argv: [node, "scripts/sleep.js", "30000"] }, pass: { argv: [node, "scripts/pass.js"] } }, profiles: { default: ["pass"] }, required_profiles: ["default"] });
  const ctx = await newRun(f);
  const table = mode === "none" ? null : scriptedTable(mode);
  ctx.testHooks = { ...(ctx.testHooks ?? {}), sweep: table ? table.deps : null, exitGraceMs: 1000 };
  return { f, ctx, table };
}

async function cancelDuringCheck(ctx: ChecksEngineContext, table: ReturnType<typeof scriptedTable> | null, names: string[]) {
  let opId = "";
  ctx.testHooks!.afterSpawn = (_name, pid) => {
    if (table) table.state.childPid = pid;
    setTimeout(() => requestChecksCancel(opId), 300);
  };
  const s = await startChecks(ctx, { checks: names });
  opId = s.operation_id;
  return s.completion;
}

describe.skipIf(!supported)("checks cancellation evidence (MR-J)", () => {
  it("clean table: the killed tree is established gone → terminated, on the execution and the operation", async () => {
    const { ctx, table } = await setup("clean");
    const r = await cancelDuringCheck(ctx, table, ["slow"]);
    expect(r.status).toBe("cancelled");
    expect(r.cancellation).toMatchObject({ outcome: "terminated", survivors: [], unattributable: [] });
    const st = await readState(ctx.runPaths);
    const exec = st.check_executions.find((e) => e.check === "slow")!;
    expect(exec.status).toBe("cancelled");
    expect(exec["cancellation"]).toMatchObject({ outcome: "terminated" });
    expect(exec.limitations.map((l) => l.code)).not.toContain("check_termination_unconfirmed");
  }, 60_000);

  it("a linked survivor the sweep cannot end → cancellation_requested naming it, with a limitation", async () => {
    const { ctx, table } = await setup("survivor");
    const r = await cancelDuringCheck(ctx, table, ["slow"]);
    expect(r.cancellation?.outcome).toBe("cancellation_requested");
    expect(r.cancellation?.survivors.map((s) => s.pid)).toContain(SURVIVOR);
    const exec = (await readState(ctx.runPaths)).check_executions.find((e) => e.check === "slow")!;
    expect(exec.limitations.map((l) => l.code)).toContain("check_termination_unconfirmed");
  }, 60_000);

  it("no process table (no evidence) is never read as terminated", async () => {
    const { ctx, table } = await setup("none");
    const r = await cancelDuringCheck(ctx, table, ["slow"]);
    expect(r.status).toBe("cancelled");
    expect(r.cancellation?.outcome).toBe("cancellation_requested");
    expect(r.cancellation?.detail).toContain("no termination evidence");
  }, 60_000);

  it("an unreadable table is never read as terminated", async () => {
    const { ctx, table } = await setup("blind");
    const r = await cancelDuringCheck(ctx, table, ["slow"]);
    expect(r.cancellation?.outcome).toBe("cancellation_requested");
  }, 60_000);

  it("cancelled before any check started: judged by operation-level evidence (a live process this server started → not established)", async () => {
    for (const [mode, expected] of [["clean", "terminated"], ["op_survivor", "cancellation_requested"]] as const) {
      const { ctx, table } = await setup(mode);
      let opId = "";
      ctx.testHooks!.beforeCheck = () => {
        requestChecksCancel(opId);
      };
      const s = await startChecks(ctx, { checks: ["pass"] });
      opId = s.operation_id;
      const r = await s.completion;
      expect(r.status, mode).toBe("cancelled");
      expect(r.cancellation?.outcome, mode).toBe(expected);
      void table;
    }
  }, 90_000);
});
