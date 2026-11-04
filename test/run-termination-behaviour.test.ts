// TD, candidate 3: the other callers of a run's end, and the behaviour controls. Part of the run-termination suite
// (Step 6: three files; see run-termination.test.ts).

import { describe, it, expect } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { stopRun } from "../src/engine/operations.js";
import { commitState, readState } from "../src/store/state-store.js";
import { supported } from "./helpers/git-fixture.js";
import { newRun } from "./helpers/continuation-fixture.js";
import { opsOf } from "./helpers/delegated-fix.js";
import { BOUND, atCustodian, confirmed, custodianRun, fromEmptyHome, implementerStop, operator, operatorStop, refusedForGood } from "./helpers/run-termination.js";

describe.skipIf(!supported)("TD candidate 3: the other callers", BOUND, () => {
  it("stop_review_loop stays on the implementer surface and carries the custodian's answer", async () => {
    const { f, run } = await confirmed();
    const out = await stopRun(f.le, run, "close", undefined, "host", 2_000);
    expect(out.custodian_end).toMatchObject({ outcome: "ended", surface: "implementer", applications: [] });
    expect(f.custodian.received.filter((x) => x.surface === "operator" && x.op === "run_transition")).toEqual([]);
  });

  it("the operator ends, then the implementer's pending end arrives: RUN_TERMINAL clears it, with no REQUEST_ID_CONFLICT", async () => {
    const { f, run } = await confirmed();
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.custodian_end_pending = { status: "closed", reason: "pending" };
      return st;
    });
    await operatorStop(f, run, "--abort");
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.custodian_end_pending = { status: "stopped", reason: "pending again" };
      return st;
    });
    const out = await stopRun(f.le, run, "close", undefined, undefined, 2_000);
    expect(out.custodian_end).toMatchObject({ outcome: "already_ended" });
    expect((await readState(run.paths)).custodian_end_pending).toBeUndefined();
  });

  it("apply_fix delivers a pending end before it consumes anything", async () => {
    const { f, run, op } = await confirmed();
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.custodian_end_pending = { status: "stopped", reason: "the operator's stop was not acknowledged" };
      return st;
    });
    await refusedForGood(f, run, op);
    expect(custodianRun(f, run).status).toBe("stopped");
    expect(opsOf(f, run, "fix").map((o) => o.status)).not.toContain("consumed");
  });
});

// The negative control: exit codes, the custodian's record and the application alone. No output wording and no new symbol,
// so on candidate 2's source these fail for what the code does. The two controls at the end pass on both.
describe.skipIf(!supported)("TD candidate 3: behaviour", BOUND, () => {
  it("the operator's stop reaches the custodian, and the confirmed fix is not applied", async () => {
    const { f, run, op } = await confirmed();
    expect((await operatorStop(f, run, "--close")).code).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
    await refusedForGood(f, run, op);
  });

  it("a stop the custodian never heard does not exit 0", async () => {
    const { f, run } = await confirmed();
    f.custodian.setUnavailable("stopped (test)");
    operator(f).setUnavailable("stopped (test)");
    expect((await operatorStop(f, run, "--close")).code).toBe(4);
  });

  it("an end still pending reaches the custodian before a confirmed fix is applied", async () => {
    const { f, run, op } = await confirmed();
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.custodian_end_pending = { status: "closed", reason: "pending" };
      return st;
    });
    await refusedForGood(f, run, op);
  });

  it("an operator with no run store ends the run, and the confirmed fix is not applied", async () => {
    const { f, run, op } = await confirmed();
    expect((await fromEmptyHome(f, ["runs", "stop", run.runId, "--repo", f.repo, "--close"])).code).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
    await refusedForGood(f, run, op);
  });

  it("a corrupted implementer record does not stop the operator", async () => {
    const { f, run, op } = await confirmed();
    const state = await readFile(run.paths.stateJson);
    await writeFile(run.paths.stateJson, "{ forged");
    expect((await atCustodian(f, run.runId, f.repo, "--close")).code).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
    await writeFile(run.paths.stateJson, state);
    await refusedForGood(f, run, op);
  });

  it("the wrong repository ends nothing and does not exit 0", async () => {
    const { f, run } = await confirmed();
    expect((await atCustodian(f, run.runId, f.scratch, "--close")).code).toBe(4);
    expect(custodianRun(f, run).status).not.toBe("closed");
  });

  it("an endpoint that is not the custodian ends nothing and does not exit 0", async () => {
    const { f, run } = await confirmed();
    operator(f).failNext("run_transition", "untrusted");
    expect((await atCustodian(f, run.runId, f.repo, "--close")).code).toBe(4);
    expect(custodianRun(f, run).status).not.toBe("closed");
  });

  it("control: the implementer's own stop ends the run", async () => {
    const { f, run, op } = await confirmed();
    expect((await implementerStop(f, run, "--close")).code).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
    await refusedForGood(f, run, op);
  });

  it("control: on a host with no custodian an attended run stops as it always did", async () => {
    const { f } = await confirmed();
    const attended = await newRun(f);
    f.le.env.testHooks!.custodian!.presence = "absent";
    expect((await implementerStop(f, attended, "--close")).code).toBe(0);
    expect((await readState(attended.paths)).state).toBe("CLOSED");
  });
});
