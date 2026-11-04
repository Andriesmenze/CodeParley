// TD, candidate 3: ending a run is established by the custodian's acknowledgment, never by the local record. On candidate 2
// the operator's `runs stop --close` printed CLOSED and exited 0 while the custodian kept the run open, and an unmodified
// engine still applied the confirmed fix. Simulation: two account-bound transports over one state, as the OS separates the
// pipes; the installed CLI and service are the native gates.
//
// Step 6: the suite is in three files, so that its tests can run in parallel: this one (the operator's stop, a stop
// that did not establish the end, S-3), run-termination-behaviour.test.ts (the other callers and the behaviour
// controls) and run-termination-repository.test.ts (the operator's stop by run and repository). Their fixture and
// helpers are in helpers/run-termination.ts.

import { describe, it, expect } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { applyFix } from "../src/engine/fix-apply.js";
import { establishCustodianEnd, endEstablished } from "../src/engine/custodian-evidence.js";
import { evidenceSelection } from "../src/engine/engine-env.js";
import { commitState, readState } from "../src/store/state-store.js";
import { supported } from "./helpers/git-fixture.js";
import { newRun } from "./helpers/continuation-fixture.js";
import { codeOf } from "./helpers/delegated-fix.js";
import { BOUND, busyRun, claimsNothing, confirmed, custodianRun, implementerStop, operator, operatorStop, refusedForGood, stopWithEveryAnswerLost } from "./helpers/run-termination.js";

describe.skipIf(!supported)("TD candidate 3: the operator's stop", BOUND, () => {
  it("the operator's process, implementer pipe denied: the run ends on the operator surface, and the confirmed fix can never begin", async () => {
    const { f, run, op } = await confirmed();
    const r = await operatorStop(f, run, "--close", "--reason", "gate");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("ended the run (operator surface)");
    expect(r.out).toContain("the run is closed");
    expect(custodianRun(f, run).status).toBe("closed");
    expect(custodianRun(f, run).ended).toMatchObject({ status: "closed", by: "operator" });
    await refusedForGood(f, run, op);
  });

  it("the implementer's process, operator pipe denied: the run ends on its own surface; the request never reached the operator's", async () => {
    const { f, run, op } = await confirmed();
    const r = await implementerStop(f, run, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("ended the run (implementer surface)");
    expect(custodianRun(f, run).ended).toMatchObject({ by: "implementer" });
    expect(f.custodian.received.filter((x) => x.op === "run_transition" && x.args.kind === "end").map((x) => x.surface)).toEqual(["implementer"]);
    await refusedForGood(f, run, op);
  });

  it("a forged local record, CLOSED with no pending mark, does not spare the custodian's end", async () => {
    const { f, run, op } = await confirmed();
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.state = "CLOSED";
      delete st.custodian_end_pending;
      return st;
    });
    const r = await operatorStop(f, run, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
    await refusedForGood(f, run, op);
  });

  it("a run.json changed since the custodian bound it does not block a reduction", async () => {
    const { f, run, op } = await confirmed();
    const bound = await readFile(run.paths.runJson, "utf8");
    await writeFile(run.paths.runJson, JSON.stringify({ ...(JSON.parse(bound) as Record<string, unknown>), goal: "changed" }));
    const r = await operatorStop(f, run, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("RUN_JSON_MISMATCH");
    // With the bound bytes back, what still refuses is the end the custodian holds, not the mismatch.
    await writeFile(run.paths.runJson, bound);
    await refusedForGood(f, run, op);
  });

  it("repeating an acknowledged stop, with another reason, reports the end it already made", async () => {
    const { f, run } = await confirmed();
    expect((await operatorStop(f, run, "--close", "--reason", "one")).code).toBe(0);
    const r = await operatorStop(f, run, "--close", "--reason", "two");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("the run had already ended");
  });
});

describe.skipIf(!supported)("TD candidate 3: a stop that did not establish the end says so, and exits 4", BOUND, () => {
  it("custodian stopped: nothing is claimed, the mark stays, and the repeated stop establishes it", async () => {
    const { f, run, op } = await confirmed();
    f.custodian.setUnavailable("stopped (test)");
    operator(f).setUnavailable("stopped (test)");
    const r = await operatorStop(f, run, "--close");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
    expect(r.out).toContain("local record: CLOSED");
    expect(r.out).toMatch(/did not reach it \(CUSTODIAN_UNAVAILABLE/);
    expect((await readState(run.paths)).custodian_end_pending).toMatchObject({ status: "closed" });
    expect(custodianRun(f, run).status).not.toBe("closed");

    f.custodian.setUnavailable(null);
    operator(f).setUnavailable(null);
    const again = await operatorStop(f, run, "--close");
    expect(again.code, again.out + again.err).toBe(0);
    expect((await readState(run.paths)).custodian_end_pending).toBeUndefined();
    await refusedForGood(f, run, op);
  });

  it("an answer lost once: the replay under the same request id gets the custodian's own result", async () => {
    const { f, run } = await confirmed();
    operator(f).failNext("run_transition", "lost_response");
    const r = await operatorStop(f, run, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("ended the run (operator surface)");
    const ends = operator(f).received.filter((x) => x.op === "run_transition" && x.args.kind === "end");
    expect(new Set(ends.map((x) => x.requestId)).size).toBe(1);
    expect(ends.length).toBeGreaterThan(1);
  });

  it("every answer lost on the only reachable surface: UNKNOWN, treated as not ended, not as not delivered", async () => {
    const { f, run } = await confirmed();
    const r = await stopWithEveryAnswerLost(f, run);
    expect(r.outcome).toBe("unknown");
    expect(endEstablished(r)).toBe(false);
  });

  it("an endpoint that is not the custodian: stops at once, no other surface tried, nothing sent again", async () => {
    const { f, run } = await confirmed();
    const before = f.custodian.received.length;
    operator(f).failNext("run_transition", "untrusted");
    const r = await operatorStop(f, run, "--close");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
    expect(r.out).toContain("SERVER_NOT_TRUSTED");
    expect(f.custodian.received.slice(before).filter((x) => x.op === "run_transition" && x.args.kind === "end")).toEqual([]);
    expect(custodianRun(f, run).status).not.toBe("closed");
  });

  it("--close refused RUN_BUSY, then --abort: the abort is sent, not the pending close", async () => {
    const { f, run } = await confirmed();
    await busyRun(f, run);
    const r = await operatorStop(f, run, "--close");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
    expect(r.out).toContain("refused RUN_BUSY");
    expect(r.out).toContain("--abort");
    const a = await operatorStop(f, run, "--abort");
    expect(custodianRun(f, run).status).toBe("stopped");
    expect(a.out).toContain("ended the run (operator surface)");
    expect((await readState(run.paths)).custodian_end_pending).toBeUndefined();
  });

  it("an application that had begun is reported: the end is acknowledged, but this stop did not prevent it (exit 4)", async () => {
    const { f, run } = await confirmed();
    await busyRun(f, run, "apply");
    const r = await operatorStop(f, run, "--abort");
    expect(r.code).toBe(4);
    expect(r.out).toContain("ended the run (operator surface)");
    expect(r.out).toMatch(/application \S+ had already begun \(running\) and is not recalled/);
  });
});

describe.skipIf(!supported)("TD candidate 3, S-3: no local marker makes a run safely stopped", BOUND, () => {
  it("custodian installed but unanswering, local mark removed: fails closed, it is not attended", async () => {
    const { f, run } = await confirmed();
    await commitState(run.paths, f.le.env.owner, (st) => {
      delete st.continuation;
      return st;
    });
    f.custodian.setUnavailable("stopped (test)");
    operator(f).setUnavailable("stopped (test)");
    const r = await operatorStop(f, run, "--abort");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
  });

  it("service presence unknown: the custodian is asked, and silence fails closed", async () => {
    const { f, run } = await confirmed();
    f.le.env.testHooks!.custodian!.presence = "unknown";
    f.operatorHooks!.custodian!.presence = "unknown";
    f.custodian.setUnavailable("stopped (test)");
    operator(f).setUnavailable("stopped (test)");
    const r = await operatorStop(f, run, "--close");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
  });

  it("RUN_NOT_OPEN proves nothing: a forged repository root that the custodian holds no run under is refused, and the real run stays open and is reported as not ended", async () => {
    const { f, run } = await confirmed();
    const r = await establishCustodianEnd({ ...evidenceSelection(f.le, run), repositoryRoot: f.scratch }, run.paths, f.le.env.owner, { status: "closed", reason: "forged" }, ["implementer"]);
    expect(r).toMatchObject({ outcome: "refused", code: "RUN_NOT_OPEN" });
    expect(endEstablished(r)).toBe(false);
    expect(custodianRun(f, run).status).not.toBe("closed");
  });

  it("an attended run with a custodian installed: closed locally, but the custodian's silence about it is not reported as proof", async () => {
    const { f } = await confirmed();
    const attended = await newRun(f);
    const r = await implementerStop(f, attended, "--close");
    expect(r.code).toBe(4);
    expect(r.out).toContain("refused RUN_NOT_OPEN");
    expect((await readState(attended.paths)).state).toBe("CLOSED");
  });

  it("a host independently confirmed to have no custodian: an attended run stops exactly as before", async () => {
    const { f } = await confirmed();
    const attended = await newRun(f);
    f.le.env.testHooks!.custodian!.presence = "absent";
    const r = await implementerStop(f, attended, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("none is installed on this host");
    expect(r.out).toContain("the run is closed");
  });

  it("no custodian installed, but the run is marked protected: fails closed", async () => {
    const { f, run } = await confirmed();
    f.le.env.testHooks!.custodian!.presence = "absent";
    const r = await implementerStop(f, run, "--abort");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
  });
});
