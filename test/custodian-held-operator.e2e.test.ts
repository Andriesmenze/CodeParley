// Phase 5 F-i2-5 (option A, [[D-28]]): the operator's run-scoped commands through the CUSTODIAN alone.
//
// On Linux the operator is a separate account that cannot read the implementer's run store (D5-B), so `decide`,
// `loop show`, `loop stop` and `loop resume` name the run by its repository and id (`--repo`) and act on the custodian's
// records only. These tests run every operator command from an EMPTY data home (no run store at all) through the
// operator account's transport, against a real paused protected run of the implementer's session; the operator's
// privileges (the operator surface; prepare → confirm → commit) are unchanged, and nothing is written to the
// implementer's store.

import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { runCli } from "../src/cli/cli.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import { heldRunOf, recordUserDecisionHeld, threadDecisionView } from "../src/engine/user-authority.js";
import { operatorLoopShape } from "../src/engine/custodian-loop.js";
import { CustodianLoopSchema } from "../src/schemas/continuation.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { commitAll, initRepo, supported, writeFiles } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { contFixture, grant, HostSession, inProcessTreeOf, loopOf, newRun, operatorIo, reviewCtx, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const ADD = "add() subtracts";
const scenario = () => okScenario(output({ findings: [defect()] }));

/** A protected run paused for a user decision (see protected-decide-resume.e2e.test.ts). */
async function pausedForDecision(f: ContFixture, sessionId: string, pid: number): Promise<{ run: RunHandle; A: HostSession; itemId: string }> {
  const run = await newRun(f);
  const A = new HostSession(f, sessionId, pid);
  await grant(f, 1);
  await A.startLoop(run);
  const itemId = await inProcessTreeOf(pid, async () => {
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "deferred", rationale: "out of scope for this change" }] });
    return item.id;
  });
  expect((await A.stop(false)).verdict).toBe("none");
  expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
  return { run, A, itemId };
}

/** The operator's CLI from an EMPTY data home (it has no run store), on the operator account's transport. */
async function opCli(f: ContFixture, home: string, args: string[], io = operatorIo("")): Promise<{ code: number; out: string; err: string }> {
  const code = await runCli([...args, "--home", home, "--git", f.git], { ...io, engineTestHooks: io.engineTestHooks ?? f.operatorHooks! });
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

async function emptyHome(f: ContFixture, name: string): Promise<string> {
  const home = join(f.scratch, name);
  await mkdir(home, { recursive: true });
  return home;
}

/** What the operator's (empty) data home holds afterwards: no run store was created or read. */
async function runsIn(home: string): Promise<string[]> {
  return readdir(join(home, "runs")).catch(() => []);
}

describe.skipIf(!supported)("F-i2-5 — operator commands through the custodian (`--repo`)", () => {
  it("a paused protected run receives the operator's decision through the custodian and continues", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, A, itemId } = await pausedForDecision(f, "sess-held-ok", 9201);
    const home = await emptyHome(f, "op-home-ok");

    // The listing and one thread: structure only, read from the custodian.
    const listed = await opCli(f, home, ["decide", run.runId, "--repo", f.repo]);
    expect(listed.code, listed.err).toBe(0);
    expect(listed.out).toContain("1 thread(s) with an open item");
    expect(listed.out).toContain("structure only");
    const listedJson = await opCli(f, home, ["decide", run.runId, "--repo", f.repo, "--json"]);
    expect(JSON.parse(listedJson.out)).toMatchObject({ run_id: run.runId, source: "custodian" });

    // While the decision is needed, the custodian-held resume is refused.
    const early = await opCli(f, home, ["loop", "resume", run.runId, "--repo", f.repo], operatorIo("resume"));
    expect(early.code).toBe(1);
    expect(early.err).toContain("still needs a user decision");
    // The refused transition changed nothing the session could act on: its next Stop stays paused (no local timestamp or
    // cached state stands in for the custodian's resume).
    expect((await A.stop(false)).log).toContain("allow: the loop is paused");
    expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });

    const io = operatorIo("defer");
    const decided = await opCli(f, home, ["decide", run.runId, itemId, "defer", "--repo", f.repo, "--note", "next sprint"], io);
    expect(decided.code, decided.err).toBe(0);
    expect(decided.out).toContain("The CodeParley custodian prepared this record");
    expect(decided.out).toContain("Recorded by the custodian: decision");
    // The custodian holds it; nothing reached the implementer's store or the operator's home.
    expect((await readState(run.paths)).user_decisions).toHaveLength(0);
    expect((await readState(run.paths)).user_records_custodian).toBeFalsy();
    expect(await runsIn(home)).toEqual([]);
    const held = await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId, ["user"]);
    expect(held.records).toHaveLength(1);
    expect(held.records[0]).toMatchObject({ recordKind: "decision", kind: "defer", note: "next sprint" });

    // The decision satisfies the guard; the custodian resumes the loop.
    const resumed = await opCli(f, home, ["loop", "resume", run.runId, "--repo", f.repo], operatorIo("resume"));
    expect(resumed.code, resumed.err).toBe(0);
    expect(resumed.out).toContain("resumed by the custodian");
    const shown = await opCli(f, home, ["loop", "show", run.runId, "--repo", f.repo, "--json"]);
    expect(shown.code, shown.err).toBe(0);
    expect(JSON.parse(shown.out)).toMatchObject({ source: "custodian", loop: { status: "active" } });

    // The session's next Stop derives no user decision for the thread: automation continues.
    await A.stop(false);
    const loop = await loopOf(run);
    expect((await readState(run.paths)).events.some((e) => e.type === "loop.resumed" && e.summary.includes("through the custodian"))).toBe(true);
    expect(loop.status === "paused" && loop.pause?.reason === "user_decision_required").toBe(false);
    expect(await runsIn(home)).toEqual([]);
  });

  it("control: a local pause newer than the custodian's resume is not undone by the reconciliation (fail closed)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, A, itemId } = await pausedForDecision(f, "sess-held-newer", 9207);
    const home = await emptyHome(f, "op-home-newer");
    expect((await opCli(f, home, ["decide", run.runId, itemId, "defer", "--repo", f.repo], operatorIo("defer"))).code).toBe(0);
    expect((await opCli(f, home, ["loop", "resume", run.runId, "--repo", f.repo], operatorIo("resume"))).code).toBe(0);
    // The engine paused the loop locally after the custodian's resume, and its pause request did not reach the custodian.
    await commitState(run.paths, f.le.env.owner, (cur) => {
      const loop = cur.continuation!;
      loop.status = "paused";
      loop.pause = { reason: "operator_action_required", detail: "a local fail-closed pause (test)", at: new Date(Date.now() + 1000).toISOString() };
      return cur;
    });
    const s = await A.stop(false);
    expect(s.log).toContain("allow: the loop is paused");
    expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "operator_action_required" } });
  });

  it("loop show and loop stop act on the custodian's loop", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await pausedForDecision(f, "sess-held-stop", 9202);
    const home = await emptyHome(f, "op-home-stop");
    const shown = await opCli(f, home, ["loop", "show", run.runId, "--repo", f.repo]);
    expect(shown.code, shown.err).toBe(0);
    expect(shown.out).toContain("as the custodian holds it");
    expect(shown.out).toContain("paused: user_decision_required");
    const stopped = await opCli(f, home, ["loop", "stop", run.runId, "--repo", f.repo, "--reason", "operator ends it"]);
    expect(stopped.code, stopped.err).toBe(0);
    expect(stopped.out).toContain("cancelled by the custodian");
    const after = await opCli(f, home, ["loop", "show", run.runId, "--repo", f.repo, "--json"]);
    expect(JSON.parse(after.out).loop.status).not.toMatch(/^(active|paused)$/);
    expect(await runsIn(home)).toEqual([]);
  });

  it("a wrong repository or run id, and a run the custodian never protected, are RUN_NOT_FOUND", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-held-wrong", 9203);
    const attended = await newRun(f); // the custodian holds no record of it
    const home = await emptyHome(f, "op-home-wrong");
    const other = join(f.scratch, "other-repo");
    await initRepo(other);
    await writeFiles(other, { "README.md": "another repository\n" });
    commitAll(other, "init");

    const cases: string[][] = [
      ["decide", run.runId, "--repo", other],
      ["decide", run.runId, itemId, "defer", "--repo", other],
      ["decide", "01900000-0000-7000-8000-000000000000", "--repo", f.repo],
      ["decide", attended.runId, "--repo", f.repo],
      ["loop", "show", run.runId, "--repo", other],
      ["loop", "stop", "01900000-0000-7000-8000-000000000000", "--repo", f.repo],
      ["loop", "resume", attended.runId, "--repo", f.repo],
    ];
    for (const args of cases) {
      const r = await opCli(f, home, args, operatorIo(args.includes("defer") ? "defer" : "resume"));
      expect(r.code, args.join(" ")).toBe(1);
      expect(r.err, args.join(" ")).toContain("RUN_NOT_FOUND");
    }
    // A malformed run id is refused before the custodian is asked.
    const bad = await opCli(f, home, ["decide", "../x", "--repo", f.repo]);
    expect(bad.code).toBe(1);
    expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
    expect(await runsIn(home)).toEqual([]);
  });

  it("a decision prepared against a stale view of the custodian's records is refused", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-held-stale", 9204);
    const cust = { operator: new CustodianOperator(f.operatorCustodian!), grants: new CustodianGrants(f.operatorCustodian!) };
    const stale = await heldRunOf(cust, f.repo, run.runId);
    const view = threadDecisionView(stale.state, itemId);
    // Another decision lands in between (the operator's own, through the custodian).
    const first = await recordUserDecisionHeld(cust, stale, { item_id: itemId, kind: "defer", note: "", token: view.token }, async () => true);
    expect("recorded" in first).toBe(true);
    await expect(recordUserDecisionHeld(cust, stale, { item_id: itemId, kind: "waive", note: "", token: view.token }, async () => true)).rejects.toThrow(/STALE|changed since/);
    const fresh = await heldRunOf(cust, f.repo, run.runId);
    expect(fresh.revision).toBe(stale.revision + 1);
    // A token from before the first decision no longer matches the thread either.
    await expect(recordUserDecisionHeld(cust, fresh, { item_id: itemId, kind: "waive", note: "", token: view.token }, async () => true)).rejects.toThrow(/changed since it was shown/);
  });

  it("the implementer cannot read the snapshot, prepare a record, or decide through the custodian", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-held-impl", 9205);
    const implGrants = new CustodianGrants(f.custodian);
    await expect(implGrants.listUserRecords("implementer", f.repo, run.runId, ["user", "snapshot"])).rejects.toThrow(/operator surface only|CALLER_NOT_AUTHORIZED/);
    const implOp = new CustodianOperator(f.custodian);
    await expect(implOp.prepareUserRecord(f.repo, run.runId, "decision", { kind: "defer", note: "", covered_items: [itemId] }, 0, "req-impl-1")).rejects.toThrow(/CALLER_NOT_AUTHORIZED|operator surface|cannot reach the operator pipe/);
    // The CLI on the implementer's own transport (the session's account) is refused as well.
    const home = await emptyHome(f, "op-home-impl");
    const r = await opCli(f, home, ["decide", run.runId, itemId, "defer", "--repo", f.repo], operatorIo("defer", true, f.le.env.testHooks));
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/CALLER_NOT_AUTHORIZED|cannot reach the operator pipe/);
    const held = await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId, ["user"]);
    expect(held.records).toHaveLength(0);
  });

  it("recording needs an interactive terminal", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await pausedForDecision(f, "sess-held-tty", 9206);
    const home = await emptyHome(f, "op-home-tty");
    const r = await opCli(f, home, ["decide", run.runId, itemId, "defer", "--repo", f.repo], operatorIo("defer", false));
    expect(r.code).toBe(1);
    expect(r.err).toContain("INTERACTIVE_TERMINAL_REQUIRED");
    const held = await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId, ["user"]);
    expect(held.records).toHaveLength(0);
  });
});

describe("F-i2-5 — the operator surface's loop record as the C# custodian serializes it", () => {
  it("a record whose null members are omitted (the C# serializer, VERIFIED on the VM) is read, not refused as malformed", () => {
    const at = "2026-10-24T23:41:21.6105856Z";
    const record: Record<string, unknown> = {
      loopId: "c10244cd-78ce-49ab-b077-16c452dc7493", repoKey: "fid2-x", runId: "01a17049-7250-7768-a3dd-9c33eee82090", status: "active", epoch: 1, loopRevision: 4,
      startedAt: at, deadlineAt: at, grantId: "4ca39458-5ef0-4108-988a-5ad62d5e85d0", grantUse: { loopsUsed: 1, loopsTotal: 4 },
      limits: { continuations: 2, wakesPerOperation: 1, wakesPerRun: 2, runSeconds: 900 }, used: { continuations: 1, wakes: 0 },
      bindNonce: { sha256: "a".repeat(64) }, requestId: "r", resumedAt: at,
      binding: { state: "live", sessionId: "S", process: { pid: 1, verified: true } },
      operations: [{ handle: "op-1", seq: 1, epoch: 1, wakesUsed: 0 }], events: [],
      // pause, ended and wakeClaims omitted, as the C# serializer omits nulls
    };
    expect(CustodianLoopSchema.safeParse(record).success).toBe(false);
    const parsed = CustodianLoopSchema.safeParse(operatorLoopShape(record));
    expect(parsed.success).toBe(true);
    expect(parsed.data).toMatchObject({ status: "active", pause: null, ended: null, wakeClaims: [], binding: { verified: true }, operations: [{ handle: "op-1", current: true }] });
  });
});
