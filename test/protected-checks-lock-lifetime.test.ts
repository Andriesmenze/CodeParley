// P3.4C-5 F-5-1 (final gate, corrective): the worktree lock a protected checks operation takes at its start is released
// on every exit, also when the custodian refuses or interrupts the start measurement it waits for — no stuck lock, no
// `code-parley lock release` — while a successful operation still holds it for as long as its checks run.
//
// Before the correction the start lock was handed to the operation only after the custodian's start measurement, so a
// refused (runtime changed) or interrupted (custodian restart) measurement left it held: the next start was refused
// WORKTREE_BUSY, and WORKTREE_OWNERSHIP_UNRESOLVED once the owner was gone (VERIFIED on the VM, final gate §3).

import { describe, it, expect } from "vitest";
import { acquireWorktreeLock, readWorktreeLock } from "../src/store/locks.js";
import { selfOwner } from "../src/store/owner.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { readState } from "../src/store/state-store.js";
import { startChecksOperation } from "../src/engine/operations.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import type { ChecksOperationResult } from "../src/engine/checks-operation.js";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, newRun, type ContFixture } from "./helpers/continuation-fixture.js";

async function protectedRun(f: ContFixture): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, "sess-f51", 7351).startLoop(run);
  return run;
}

const lockOf = (f: ContFixture, run: RunHandle) => readWorktreeLock(worktreeLockPath(f.dataHome, canonicalPathKey(run.meta.repository_root)));

/** Start a protected checks operation; its local id, the custodian's id of it, and its completion. */
async function start(f: ContFixture, run: RunHandle) {
  const s = await startChecksOperation(f.le, run, {});
  const op = (await readState(run.paths)).operations.find((o) => o.operation_id === s.operation.operation_id);
  const custodianId = String(op?.["custodian_operation_id"] ?? "");
  expect(custodianId).not.toBe("");
  return { operationId: s.operation.operation_id, custodianId, completion: s.completion.then((c) => c.result as ChecksOperationResult) };
}

/** Run every check measurement the custodian reserves for `custodianId` (manual helper) until the operation ends. */
async function measureUntilDone(f: ContFixture, custodianId: string, done: Promise<unknown>): Promise<void> {
  let finished = false;
  void done.finally(() => (finished = true));
  while (!finished) {
    await f.custodian.runReservedCheckMeasurement(custodianId).catch(() => null);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Wait until the custodian has reserved the start measurement of `custodianId` (the engine is waiting for it). */
async function untilMeasuring(f: ContFixture, run: RunHandle, custodianId: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    const res = await f.custodian.send("implementer", "list_user_records", { repositoryRoot: run.meta.repository_root, runId: run.runId, sections: ["run"] }, `poll-${i}-${Math.random()}`);
    const ops = ((res.data?.["run"] as Record<string, unknown> | undefined)?.["record"] as { operations?: { operationId: string; status: string }[] } | undefined)?.operations ?? [];
    if (ops.find((o) => o.operationId === custodianId)?.status === "measuring") return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`the custodian never reported ${custodianId} measuring`);
}

describe.skipIf(!supported)("P3.4C-5 F-5-1 — a protected checks start's worktree lock is released on every exit", () => {
  it("runtime changed: the custodian refuses the start measurement; the operation fails closed, releases its lock, and the next operation starts without `lock release`", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true, measure: "manual" });
    const run = await protectedRun(f);

    const a = await start(f, run);
    expect((await lockOf(f, run))?.operation_id).toBe(a.operationId); // held while the custodian measures
    await untilMeasuring(f, run, a.custodianId);
    await f.custodian.runReservedCheckMeasurement(a.custodianId, { fail: "runtime" });
    const ra = await a.completion;
    expect(ra.operation_status).toBe("error"); // fail closed: no check ran
    expect(ra.execution_ids).toEqual([]);
    expect(await lockOf(f, run)).toBeNull(); // F-5-1: released

    const b = await start(f, run); // not WORKTREE_BUSY / WORKTREE_OWNERSHIP_UNRESOLVED
    await measureUntilDone(f, b.custodianId, b.completion);
    const rb = await b.completion;
    expect(rb.operation_status).toBe("completed");
    expect(rb.status).toBe("passed");
    expect(await lockOf(f, run)).toBeNull();
  }, 180_000);

  it("custodian restart while the start is measured: the measurement is interrupted, no lock survives, and the next operation starts without `lock release`", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true, measure: "manual" });
    const run = await protectedRun(f);

    const a = await start(f, run);
    await untilMeasuring(f, run, a.custodianId);
    expect(f.custodian.restartCustodian()).toBe(1); // the measuring operation is interrupted (N5-18)
    const ra = await a.completion;
    expect(ra.operation_status).toBe("error");
    expect(ra.execution_ids).toEqual([]);
    expect(await lockOf(f, run)).toBeNull();

    const b = await start(f, run);
    await measureUntilDone(f, b.custodianId, b.completion);
    expect((await b.completion).status).toBe("passed");
    expect(await lockOf(f, run)).toBeNull();
  }, 180_000);

  it("a successful protected operation holds its lock from the start through its checks (another operation is refused), then releases it", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    const run = await protectedRun(f);
    let during: { holder: string | null; second: string | null } | null = null;
    let operationId = "";
    f.le.env.testHooks!.checks = {
      ...f.le.env.testHooks!.checks,
      beforeCheck: async () => {
        // Another operation's attempt on the same worktree (exclusivity): refused while this one's checks run.
        const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(run.meta.repository_root));
        const second = await acquireWorktreeLock(lockPath, { owner: selfOwner(), operationId: "another-operation", kind: "checks", commandLines: [] }).then(
          async (h) => (await h.release(), null),
          (e: unknown) => (e as { code?: string }).code ?? "error",
        );
        during = { holder: (await lockOf(f, run))?.operation_id ?? null, second };
      },
    };
    const s = await startChecksOperation(f.le, run, {});
    operationId = s.operation.operation_id;
    const r = (await s.completion).result as ChecksOperationResult;
    expect(r.status).toBe("passed");
    expect(during).toEqual({ holder: operationId, second: "WORKTREE_BUSY" });
    expect(await lockOf(f, run)).toBeNull();
  }, 180_000);
});
