// TD, candidate 3: ending a run is established by the custodian's acknowledgment, never by the local record. On candidate 2
// the operator's `runs stop --close` printed CLOSED and exited 0 while the custodian kept the run open, and an unmodified
// engine still applied the confirmed fix. Simulation: two account-bound transports over one state, as the OS separates the
// pipes; the installed CLI and service are the native gates.

import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli } from "../src/cli/cli.js";
import { uuidv7 } from "../src/common/ids.js";
import { delegateFix } from "../src/engine/fix-operation.js";
import { applyFix, SimulatedKill } from "../src/engine/fix-apply.js";
import { establishCustodianEnd, endEstablished, type CustodianEndResult } from "../src/engine/custodian-evidence.js";
import { stopRun } from "../src/engine/operations.js";
import { evidenceSelection, type RunHandle } from "../src/engine/engine-env.js";
import { commitState, readState } from "../src/store/state-store.js";
import { SimulatedCustodianTransport } from "../src/custodian/transport.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1, MATH_V2 } from "./helpers/review-fixture.js";
import { cli, newRun, operatorIo, type ContFixture } from "./helpers/continuation-fixture.js";
import { TASK, codeOf, confirmFix, editing, opsOf, protectedRun, storeFixSelfTest_ } from "./helpers/delegated-fix.js";

const BOUND = { timeout: 300_000 };

/** A protected run with a confirmed delegated fix, unapplied: what an operator wants to stop. */
async function confirmed(): Promise<{ f: ContFixture; run: RunHandle; op: string }> {
  const { f, run } = await protectedRun(2, { accounts: true });
  await storeFixSelfTest_(f);
  await confirmFix(f);
  const r = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
  expect(r.status, r.detail ?? "").toBe("proposed");
  const c = await cli(f, ["fix", "confirm", run.runId, r.operation_id, "--repo", f.repo], operatorIo("confirm", true));
  expect(c.code, c.err).toBe(0);
  expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["confirmed"]);
  return { f, run, op: r.operation_id };
}

const custodianRun = (f: ContFixture, run: RunHandle) => f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!;
const math = (f: ContFixture): Promise<string> => readFile(join(f.repo, "src", "math.js"), "utf8");
const operatorStop = (f: ContFixture, run: RunHandle, ...flags: string[]) => cli(f, ["runs", "stop", run.runId, ...flags], operatorIo(""));
const implementerStop = (f: ContFixture, run: RunHandle, ...flags: string[]) => cli(f, ["runs", "stop", run.runId, ...flags], { ...operatorIo(""), engineTestHooks: f.le.env.testHooks! });
const operator = (f: ContFixture) => f.operatorCustodian!;

/** The application the engine would make: refused, and nothing written. */
async function refusedForGood(f: ContFixture, run: RunHandle, op: string): Promise<void> {
  expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("RUN_TERMINAL");
  expect(await math(f)).toBe(MATH_V2);
}

/** What candidate 2 printed when the custodian had not ended the run. */
function claimsNothing(out: string): void {
  expect(out).not.toMatch(/the run is closed/);
  expect(out).toMatch(/NOT ended|UNKNOWN/);
}

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

const atCustodian = (f: ContFixture, runId: string, repo: string, ...flags: string[]) => cli(f, ["runs", "stop", runId, "--repo", repo, ...flags], operatorIo(""));
const ends = (t: SimulatedCustodianTransport) => t.received.filter((x) => x.op === "run_transition" && x.args.kind === "end");

/** The command from an operator account's own home, which holds no run store. */
async function fromEmptyHome(f: ContFixture, args: string[]): Promise<{ code: number; out: string; err: string }> {
  const home = await mkdtemp(join(f.scratch, "operator-home-"));
  const io = operatorIo("", true, f.operatorHooks!);
  const code = await runCli([...args, "--home", home, "--git", f.git], io);
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

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

describe.skipIf(!supported)("TD candidate 3: the operator's stop by run and repository", BOUND, () => {
  it("runs as the operator, and the implementer's pipe is never used", async () => {
    const { f, run, op } = await confirmed();
    const before = f.custodian.received.length;
    const r = await atCustodian(f, run.runId, f.repo, "--abort", "--reason", "gate");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("ended the run (operator surface)");
    expect(r.out).toContain("not read and not changed");
    expect(custodianRun(f, run).ended).toMatchObject({ status: "stopped", by: "operator" });
    expect(f.custodian.received.slice(before).filter((x) => x.op === "run_transition")).toEqual([]);
    expect(ends(operator(f)).map((x) => x.args.repositoryRoot)).toEqual([f.repo]);
    await refusedForGood(f, run, op);
  });

  it("no run store: the run-addressed form ends the run where the local form cannot find it", async () => {
    const { f, run } = await confirmed();
    const local = await fromEmptyHome(f, ["runs", "stop", run.runId, "--close"]);
    expect(local.code).toBe(1);
    expect(local.err).toContain("RUN_NOT_FOUND");
    expect(ends(operator(f))).toEqual([]);

    const r = await fromEmptyHome(f, ["runs", "stop", run.runId, "--repo", f.repo, "--close"]);
    expect(r.code, r.out + r.err).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
  });

  it("no store of any kind is read: its run directory gone and its configuration corrupt, the end is still sent", async () => {
    const { f, run } = await confirmed();
    await writeFile(f.le.layout.configFile, "{ forged");
    await rm(run.paths.runDir, { recursive: true, force: true });
    const r = await atCustodian(f, run.runId, f.repo, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
  });

  it("a forged local record cannot stand in for the custodian: nothing answers, so nothing is claimed", async () => {
    const { f, run } = await confirmed();
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.state = "CLOSED";
      delete st.custodian_end_pending;
      return st;
    });
    f.custodian.setUnavailable("stopped (test)");
    operator(f).setUnavailable("stopped (test)");
    const r = await atCustodian(f, run.runId, f.repo, "--close");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
    expect(custodianRun(f, run).status).not.toBe("closed");
  });

  it("wrong identifiers end nothing, each is exit 4, and the right pair then ends the run under the same reason", async () => {
    const { f, run } = await confirmed();
    const attended = await newRun(f);
    for (const [id, repo] of [[run.runId, f.scratch], [uuidv7(), f.repo], [attended.runId, f.repo]] as const) {
      const r = await atCustodian(f, id, repo, "--close");
      expect(r.code, `${id} ${repo}`).toBe(4);
      expect(r.out).toContain("refused RUN_NOT_OPEN");
      expect(r.out).toContain("check both");
      claimsNothing(r.out);
    }
    expect((await atCustodian(f, run.runId, join(f.scratch, "no-such-repository"), "--close")).code).toBe(4);
    expect(custodianRun(f, run).status).not.toBe("closed");
    const good = await atCustodian(f, run.runId, f.repo, "--close");
    expect(good.code, good.out + good.err).toBe(0);
    expect(custodianRun(f, run).status).toBe("closed");
  });

  it("a malformed request is refused before anything is sent", async () => {
    const { f, run } = await confirmed();
    for (const flags of [[], ["--close", "--abort"], ["--close", "--operation", "x"], ["--abort", "--wait", "1"]]) {
      const r = await atCustodian(f, run.runId, f.repo, ...flags);
      expect(r.code, flags.join(" ")).toBe(1);
      expect(r.err).toContain("INVALID_ARGUMENT");
    }
    const prefix = await atCustodian(f, run.runId.slice(0, 13), f.repo, "--close");
    expect(prefix.code).toBe(1);
    expect(prefix.err).toContain("full run id");
    expect(ends(operator(f))).toEqual([]);
  });

  it.runIf(process.platform === "linux")("Linux: a repository path that is not plain absolute is refused before anything is sent", async () => {
    const { f, run } = await confirmed();
    const r = await atCustodian(f, run.runId, `${f.repo}/`, "--close");
    expect(r.code).toBe(1);
    expect(r.err).toContain("plain absolute path");
    expect(ends(operator(f))).toEqual([]);
  });

  it("--close refused RUN_BUSY: exit 4, and the hint repeats the form that works here", async () => {
    const { f, run } = await confirmed();
    await busyRun(f, run);
    const r = await atCustodian(f, run.runId, f.repo, "--close");
    expect(r.code).toBe(4);
    claimsNothing(r.out);
    expect(r.out).toContain(`--abort --repo ${f.repo}`);
    const a = await atCustodian(f, run.runId, f.repo, "--abort");
    expect(a.out).toContain("ended the run (operator surface)");
    expect(custodianRun(f, run).status).toBe("stopped");
  });

  it("an answer lost once is replayed under one request id; repeating the stop replays it again; another reason gets the end it made", async () => {
    const { f, run } = await confirmed();
    operator(f).failNext("run_transition", "lost_response");
    const r = await atCustodian(f, run.runId, f.repo, "--close", "--reason", "one");
    expect(r.code, r.out + r.err).toBe(0);
    expect(ends(operator(f)).length).toBeGreaterThan(1);
    expect((await atCustodian(f, run.runId, f.repo, "--close", "--reason", "one")).code).toBe(0);
    expect(new Set(ends(operator(f)).map((x) => x.requestId)).size).toBe(1);
    expect(custodianRun(f, run).events.filter((e) => e.kind === "end").length).toBe(1);
    const other = await atCustodian(f, run.runId, f.repo, "--close", "--reason", "two");
    expect(other.code).toBe(0);
    expect(other.out).toContain("the run had already ended");
  });

  it("every answer lost: UNKNOWN and exit 4, nothing claimed", async () => {
    const { f, run } = await confirmed();
    const transport = lossy(operator(f));
    const io = operatorIo("", true, { ...f.operatorHooks!, custodian: { ...f.operatorHooks!.custodian!, transport } });
    const code = await runCli(["runs", "stop", run.runId, "--repo", f.repo, "--close", "--home", f.dataHome], io);
    expect(code).toBe(4);
    expect(io.lines.join("\n")).toContain("UNKNOWN whether the run ended");
    claimsNothing(io.lines.join("\n"));
  });

  it("an endpoint that is not the custodian: stops at once, on no other surface", async () => {
    const { f, run } = await confirmed();
    const before = f.custodian.received.length;
    operator(f).failNext("run_transition", "untrusted");
    const r = await atCustodian(f, run.runId, f.repo, "--close");
    expect(r.code).toBe(4);
    expect(r.out).toContain("SERVER_NOT_TRUSTED");
    claimsNothing(r.out);
    expect(f.custodian.received.slice(before).filter((x) => x.op === "run_transition")).toEqual([]);
  });

  it("a custodian that is stopped, or whose presence is unknown, fails closed; and with none installed there is nothing to end", async () => {
    const { f, run } = await confirmed();
    f.custodian.setUnavailable("stopped (test)");
    operator(f).setUnavailable("stopped (test)");
    expect((await atCustodian(f, run.runId, f.repo, "--close")).code).toBe(4);
    f.operatorHooks!.custodian!.presence = "unknown";
    expect((await atCustodian(f, run.runId, f.repo, "--close")).code).toBe(4);
    f.operatorHooks!.custodian!.presence = "absent";
    const r = await atCustodian(f, run.runId, f.repo, "--close");
    expect(r.code).toBe(4);
    expect(r.out).not.toContain("attended run");
    claimsNothing(r.out);
  });

  it("an application that had begun: the end is acknowledged, the application is reported, and exit 4 keeps the two apart", async () => {
    const { f, run } = await confirmed();
    await busyRun(f, run, "apply");
    const r = await atCustodian(f, run.runId, f.repo, "--abort");
    expect(r.code).toBe(4);
    expect(r.out).toContain("ended the run (operator surface)");
    expect(r.out).toMatch(/application \S+ had already begun \(running\) and is not recalled/);
  });

  it("after the acknowledged end nothing new can begin, whatever the implementer's record says", async () => {
    const { f, run, op } = await confirmed();
    expect((await atCustodian(f, run.runId, f.repo, "--close")).code).toBe(0);
    expect((await readState(run.paths)).state).not.toBe("CLOSED");
    await refusedForGood(f, run, op);
    await refusedForGood(f, run, op);
    // The end retired the capture a delegation starts from, so the custodian refuses it before it reaches the run's status.
    expect(await codeOf(delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) }))).toBe("EVIDENCE_NOT_HELD");
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["confirmed"]);
    expect(opsOf(f, run, "apply")).toEqual([]);
  });

  it("the implementer's record catches up: its own stop closes locally on the end the operator made", async () => {
    const { f, run } = await confirmed();
    await atCustodian(f, run.runId, f.repo, "--close");
    const r = await implementerStop(f, run, "--close");
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("the run had already ended");
    expect((await readState(run.paths)).state).toBe("CLOSED");
  });

  it("ordinary implementer commands keep working: --repo changes only `runs stop`", async () => {
    const { f, run } = await confirmed();
    const io = { ...operatorIo(""), engineTestHooks: f.le.env.testHooks! };
    const r = await cli(f, ["runs", "list", "--repo", f.repo], io);
    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain(run.runId);
    expect(ends(f.custodian)).toEqual([]);
    expect(ends(operator(f))).toEqual([]);
  });
});

/** A transport that loses every reply to a run transition, after delivery. */
function lossy(t: SimulatedCustodianTransport): SimulatedCustodianTransport {
  return new Proxy(t, {
    get(target, k, r) {
      if (k === "send") return async (s: never, op: never, a: never, id: never) => {
        target.failNext("run_transition", "lost_response");
        return target.send(s, op, a, id);
      };
      return Reflect.get(target, k, r) as unknown;
    },
  });
}

/** The end with every answer lost after delivery: the transport drops each reply, so no attempt is acknowledged. */
async function stopWithEveryAnswerLost(f: ContFixture, run: RunHandle): Promise<CustodianEndResult> {
  return establishCustodianEnd({ ...evidenceSelection(f.le, run), custodian: { platform: process.platform, transport: lossy(operator(f)) } }, run.paths, f.le.env.owner, { status: "closed", reason: "lost" }, ["operator"]).then((r) => {
    if (r.outcome === "ended") throw new Error("the first attempt's reply was not lost");
    return r;
  });
}

/** An operation the custodian holds as running, as a writer that stays alive would leave it: checks, or an application
 * that stopped before its first write. */
async function busyRun(f: ContFixture, run: RunHandle, kind: "checks" | "apply" = "checks"): Promise<void> {
  if (kind === "apply") {
    await expect(applyFix(f.le, run, { proposal_id: opsOf(f, run, "fix")[0]!.operationId }, { beforeReplace: () => { throw new SimulatedKill(); } })).rejects.toBeInstanceOf(SimulatedKill);
    return;
  }
  const begun = await f.custodian.send("implementer", "run_transition", { repositoryRoot: run.meta.repository_root, runId: run.runId, kind: "op_begin", fields: { operationKind: "checks", planned: [{ check: "unit", checkSpecId: null, definitionDigest: null, required: true }], inputIdentity: null } }, "busy-1");
  expect(begun.ok, begun.error).toBe(true);
}
