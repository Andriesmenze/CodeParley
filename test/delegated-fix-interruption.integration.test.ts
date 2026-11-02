// Phase 4 V4-4 — a delegated fixer whose engine is killed mid-run (no `finally`, no op_finish): its operation stays
// running in the custodian's records with its writer gone, and its disposable workspace — a copy of the sanitized export
// — stays in the data home. The next delegation recovers the operation (interrupted, so the run is not RUN_BUSY) and
// removes the stale workspace before creating its own; the run's end removes whatever is left. Simulated custodian,
// scripted fake Codex; the kill is the SimulatedKill seam (the real one is verified on the VM).

import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { delegateFix } from "../src/engine/fix-operation.js";
import { SimulatedKill } from "../src/engine/simulated-kill.js";
import { stopRun } from "../src/engine/operations.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1 } from "./helpers/review-fixture.js";
import { TASK, confirmFix, editing, opsOf, protectedRun, storeFixSelfTest_ } from "./helpers/delegated-fix.js";
import type { SimWriter } from "../src/custodian/simulated-runs.js";

const BOUND = { timeout: 240_000 };

describe.skipIf(!supported)("Phase 4 V4-4: a delegated fixer killed mid-run", BOUND, () => {
  it("leaves its operation and workspace; the next delegation recovers the operation and removes the stale workspace; the run's end removes the rest", async () => {
    const gone = new Set<number>();
    const { f, run } = await protectedRun(3, { writerGone: (w: SimWriter) => gone.has(w.pid) });
    await storeFixSelfTest_(f);
    await confirmFix(f);
    const work = join(f.dataHome, "work", run.runId);
    const dies = async (): Promise<never> => {
      throw new SimulatedKill();
    };

    // The engine dies while its fixer runs: no teardown, no op_finish.
    await expect(delegateFix(f.le, run, TASK, { launch: dies })).rejects.toBeInstanceOf(SimulatedKill);
    const stale = await readdir(work);
    expect(stale).toHaveLength(1);
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["running"]);

    // Its writer is gone (this test process plays the dead one): the next delegation recovers it and is not RUN_BUSY.
    gone.add(process.pid);
    const r = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
    gone.delete(process.pid);
    expect(r.status, r.detail ?? "").toBe("proposed");
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["interrupted", "proposed"]);
    // The stale workspace was removed before the new one was created, and the new one was destroyed as always.
    expect(existsSync(join(work, stale[0]!))).toBe(false);
    expect(await readdir(work).catch(() => [])).toEqual([]);

    // Killed again; then the run ends: its workspaces go with it.
    await expect(delegateFix(f.le, run, TASK, { launch: dies })).rejects.toBeInstanceOf(SimulatedKill);
    expect(await readdir(work)).toHaveLength(1);
    gone.add(process.pid);
    await stopRun(f.le, run, "abort", undefined, "V4-4 regression", 5000);
    gone.delete(process.pid);
    expect(existsSync(work)).toBe(false);
  });
});
