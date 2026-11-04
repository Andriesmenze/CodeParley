// TD, candidate 3: the operator's stop by run and repository (`runs stop <run> --repo <repository>`). Part of the
// run-termination suite (Step 6: three files; see run-termination.test.ts).

import { describe, it, expect } from "vitest";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli } from "../src/cli/cli.js";
import { uuidv7 } from "../src/common/ids.js";
import { delegateFix } from "../src/engine/fix-operation.js";
import { commitState, readState } from "../src/store/state-store.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1 } from "./helpers/review-fixture.js";
import { cli, newRun, operatorIo } from "./helpers/continuation-fixture.js";
import { TASK, codeOf, editing, opsOf } from "./helpers/delegated-fix.js";
import { BOUND, atCustodian, busyRun, claimsNothing, confirmed, custodianRun, ends, fromEmptyHome, implementerStop, lossy, operator, refusedForGood } from "./helpers/run-termination.js";

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
