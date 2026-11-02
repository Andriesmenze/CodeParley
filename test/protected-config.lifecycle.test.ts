// P3.4C-4 engine-level negative tests (contract §7.1) that complement the custodian's self-tests (RunSelfTest.Config,
// RunSelfTest.Recovery) and the increment-1 regressions (protected-config.regressions.test.ts):
//
//   M6   run.json edited after open: every protected read fails closed, not only the starts.
//   M7   after a new boot the first protected use refuses CONFIG_LAPSED; attended runs neither refuse nor prompt.
//   M11  (b) a check's approval changed between op_begin and record_execution: the execution is recorded under its pin,
//        and the derivation does not count it; (d) after acceptance the review's basis lost (the self-test confirmation
//        revoked, the capture rules changed): the review is no longer accepted or current and completion is not ready.
//   M13  the Codex image at the approved path replaced after the operator approved it: the protected review is refused
//        (CONFIG_MISMATCH) and nothing reaches Codex.
//
// Each runs over two account-bound simulated transports (the engine on the implementer pipe, the operator's CLI on the
// operator pipe). Evidence class: simulation.

import { describe, it, expect } from "vitest";
import { copyFile, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { findRun, loadEngine, type RunHandle } from "../src/engine/engine-env.js";
import { startChecksOperation, startReviewOperation } from "../src/engine/operations.js";
import { routeRun, startLoop } from "../src/engine/continuation.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { readState } from "../src/store/state-store.js";
import { storeLayout } from "../src/store/paths.js";
import { supported } from "./helpers/git-fixture.js";
import { approve } from "./helpers/checks-fixture.js";
import { defect, fakeCalls, minimalPe, okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, grant, HostSession, NODE, newRun, operatorIo, runChecks, setConfig, type ContFixture } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [defect()] }));

async function protectedRun(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  return run;
}

async function view(f: ContFixture, run: RunHandle) {
  return withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
}

async function reportOf(f: ContFixture, run: RunHandle) {
  return (await routeRun(f.le, run, await view(f, run))).report;
}

const custodianRun = (f: ContFixture, run: RunHandle) => f.custodian.snapshot().runs.find((r) => r.runId === run.runId);

/** A check that announces it started (after op_begin) and waits for `go` before it passes. */
function gatedCheck(f: ContFixture) {
  const started = join(f.scratch, "check-started.flag");
  const go = join(f.scratch, "check-go.flag");
  const script = `const fs=require("fs");fs.writeFileSync(${JSON.stringify(started)},"x");const t=Date.now();while(!fs.existsSync(${JSON.stringify(go)})&&Date.now()-t<60000){Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,25)}`;
  return { started, go, argv: [NODE, "-e", script] };
}

async function until(cond: () => boolean, ms = 60_000): Promise<void> {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe.skipIf(!supported)("P3.4C-4 M11 (b) — a check's approval changed while it runs", () => {
  it("a definition changed between op_begin and record_execution: recorded under its pin, and stale at derivation", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const g = gatedCheck(f);
    await approve(f, { checks: { unit: { argv: g.argv } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    const run = await protectedRun(f, "sess-m11b1", 9901);
    const s = await startChecksOperation(f.le, run, {});
    await until(() => existsSync(g.started));
    const pinned = (custodianRun(f, run)?.operations ?? []).at(-1) as Record<string, unknown> | undefined;
    expect(pinned).toBeTruthy();
    // The operator approves a changed definition for the custodian while the check runs.
    await approve(f, { checks: { unit: { argv: [...g.argv, "CHANGED"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    await setConfig(f);
    await writeFile(g.go, "x");
    await s.completion;
    // Recorded by the custodian under the operation's pin …
    const recorded = (custodianRun(f, run)?.checkExecutions ?? []) as Record<string, unknown>[];
    expect(recorded.filter((e) => e["check"] === "unit" && e["status"] === "passed")).toHaveLength(1);
    // … but the current approval is another definition: the execution does not satisfy the floor.
    const r = await reportOf(f, run);
    expect(r.floor.satisfied_for_current_source).toBe(false);
    expect([...r.floor.stale, ...r.floor.missing]).toContain("unit");
  }, 180_000);

  it("a check's approval revoked between op_begin and record_execution: recorded under its pin, not counted at derivation", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const g = gatedCheck(f);
    const gate = { argv: [NODE, "scripts/pass.js", "CHECK_TOKEN_3a"] };
    await approve(f, { checks: { unit: { argv: g.argv }, gate }, profiles: { default: ["gate", "unit"] }, required_profiles: ["default"] });
    const run = await protectedRun(f, "sess-m11b2", 9902);
    const s = await startChecksOperation(f.le, run, { checks: ["unit"] });
    await until(() => existsSync(g.started));
    // The operator withdraws `unit` from the protected configuration while it runs.
    await approve(f, { checks: { gate }, profiles: { default: ["gate"] }, required_profiles: ["default"] });
    await setConfig(f);
    await writeFile(g.go, "x");
    await s.completion;
    expect(((custodianRun(f, run)?.checkExecutions ?? []) as Record<string, unknown>[]).filter((e) => e["check"] === "unit" && e["status"] === "passed")).toHaveLength(1);
    await runChecks(f, run); // the current floor: gate only
    // `unit` counts toward nothing: its execution is reported as a check no longer approved (removed), never as
    // satisfying the floor the custodian now holds.
    const r = await reportOf(f, run);
    expect(r.floor.removed).toContain("unit");
    expect(r.floor.satisfied_for_current_source).toBe(false);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-4 M11 (d) — a review's basis lost after acceptance", () => {
  async function acceptedReview(f: ContFixture, session: string, pid: number): Promise<RunHandle> {
    const run = await protectedRun(f, session, pid);
    await runChecks(f, run);
    await (await startReviewOperation(f.le, run, {})).completion;
    const r = await reportOf(f, run);
    expect(r.latest_review?.freshness?.current).toBe(true);
    return run;
  }

  it("the S1 self-test confirmation revoked: the review is no longer accepted or current; completion is not ready", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await acceptedReview(f, "sess-m11d1", 9903);
    const confirmation = f.custodian.snapshot().config!.selftestConfirmations.find((c) => c.revokedAt === null && c.supersededAt === null)!;
    const revoked = await cli(f, ["config", "revoke-selftest", "--repo", f.repo, confirmation.confirmationId], operatorIo("confirm"));
    expect(revoked.code, revoked.err).toBe(0);
    expect(custodianRun(f, run)).toBeTruthy();
    const st = await view(f, run);
    const last = st.reviews.at(-1)!;
    expect(last.accepted).toBe(false);
    expect(last.not_accepted_reasons).toContain("custodian:isolation_basis_revoked");
    // No accepted review is left to be the run's current one (the shown latest review is marked not accepted), and
    // completion is not ready.
    const r = await reportOf(f, run);
    expect(r.latest_review?.accepted).toBe(false);
    expect(r.completion.ready).toBe(false);
  }, 180_000);

  it("the capture rules changed for the custodian: the review is no longer accepted (config_changed_since_review)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await acceptedReview(f, "sess-m11d2", 9904);
    await writeFile(storeLayout(f.dataHome).configFile, JSON.stringify({ capture: { exclude_globs: ["**/.env", "**/*.secret"] } }));
    await setConfig(f);
    const last = (await view(f, run)).reviews.at(-1)!;
    expect(last.accepted).toBe(false);
    expect(last.not_accepted_reasons).toContain("custodian:config_changed_since_review");
    expect((await reportOf(f, run)).completion.ready).toBe(false);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-4 M13 — the approved Codex image", () => {
  it("the image at the approved path replaced after approval: the protected review is refused (CONFIG_MISMATCH); nothing reaches Codex", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-m13", 9905);
    await runChecks(f, run);
    if (process.platform === "win32") await writeFile(f.codexExe, minimalPe(7));
    else await copyFile("/bin/false", f.codexExe);
    // Refused inside the operation, before anything reaches Codex: the engine hashes the image it would launch.
    const s = await startReviewOperation(f.le, run, {});
    const done = (await s.completion) as { kind: string; result: { failure: { code: string } | null; accepted: boolean } };
    expect(done.result.failure?.code).toBe("CONFIG_MISMATCH");
    expect(done.result.accepted).toBe(false);
    expect(await fakeCalls(f, "exec")).toHaveLength(0);
    expect((custodianRun(f, run)?.reviews ?? []).filter((r) => (r as { accepted?: unknown }).accepted === true)).toEqual([]);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-4 M6 — run.json edited after open", () => {
  it("every protected read fails closed (RUN_JSON_MISMATCH): the evidence view and the derived status, as well as the starts", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-m6", 9906);
    await runChecks(f, run);
    const meta = JSON.parse(await readFile(run.paths.runJson, "utf8")) as Record<string, unknown>;
    meta["envelope"] = { ...(meta["envelope"] as Record<string, unknown>), goal: "a goal a same-user process wrote after open" };
    await writeFile(run.paths.runJson, JSON.stringify(meta, null, 2));
    const edited = await findRun(f.le, run.runId);
    await expect(withAuthoritativeUserRecords(f.le, edited, await readState(edited.paths), { protected: true })).rejects.toMatchObject({ code: "RUN_JSON_MISMATCH" });
    await expect(startChecksOperation(f.le, edited, {})).rejects.toMatchObject({ code: "RUN_JSON_MISMATCH" });
    await expect(startReviewOperation(f.le, edited, {})).rejects.toMatchObject({ code: "RUN_JSON_MISMATCH" });
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-4 M7/M10 — after a new boot", () => {
  it("the first protected use refuses CONFIG_LAPSED; an attended run neither refuses nor prompts", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    await protectedRun(f, "sess-m7", 9907);
    f.custodian.simulateRecoveryAfterNewBoot();
    const le = await loadEngine(f.le.env);
    const second = await newRun(f, "a second protected run after the restart");
    await expect(startLoop(le, await findRun(le, second.runId))).rejects.toMatchObject({ code: "CONFIG_LAPSED" });
    // An attended run keeps the local files: its checks and review run as before.
    const attended = await newRun(f, "an attended run after the restart");
    await runChecks(f, attended);
    await (await startReviewOperation(f.le, attended, {})).completion;
    const st = await readState(attended.paths);
    expect(st.check_executions.filter((e) => e.status === "passed")).not.toHaveLength(0);
    expect(st.reviews.at(-1)?.accepted).toBe(true);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-4 M2/M8 — the configuration's writer and its storage", () => {
  it("M2: the implementer's pipe cannot prepare a configuration change; a commit after a concurrent change is STALE_CONFIG", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    await protectedRun(f, "sess-m2", 9908);
    const section = f.custodian.snapshot().config.repositories.find((r) => r.supersededAt === null)!;
    const args = { repositoryRoot: f.repo, recordKind: "repository", action: "revoke", baseRevision: section.configRevision };
    const refused = await f.custodian.send("implementer", "prepare_config_record", args, "m2-impl");
    expect(refused).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    // Two operator proposals against the same revision: the first commit wins, the second is stale and commits nothing.
    const op = f.operatorCustodian!;
    expect((await op.send("operator", "prepare_config_record", args, "m2-a")).ok).toBe(true);
    expect((await op.send("operator", "prepare_config_record", args, "m2-b")).ok).toBe(true);
    expect((await op.send("operator", "commit", { authorizationRequestId: "m2-a" }, "m2-ca")).ok).toBe(true);
    expect(await op.send("operator", "commit", { authorizationRequestId: "m2-b" }, "m2-cb")).toMatchObject({ ok: false, code: "STALE_CONFIG" });
    expect(f.custodian.snapshot().config.repositories.filter((r) => r.revokedAt !== null)).toHaveLength(1);
  }, 180_000);

  it("M8: config-records.json rolled back alone to a version with a revoked record in force, then a new boot: the restored record is lapsed until the operator re-confirms it", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    await protectedRun(f, "sess-m8", 9909);
    const before = f.custodian.snapshot().config;
    const revoked = await cli(f, ["config", "revoke", "--repo", f.repo], operatorIo("confirm"));
    expect(revoked.code, revoked.err).toBe(0);
    f.custodian.replaceConfigStore(before); // the storage rollback of the configuration file alone
    f.custodian.simulateRecoveryAfterNewBoot();
    const restored = f.custodian.snapshot().config.repositories.find((r) => r.supersededAt === null)!;
    expect(restored.revokedAt).toBeNull();
    expect(restored.lapsedAtRecoveryId).not.toBeNull();
    const le = await loadEngine(f.le.env);
    const run = await newRun(f, "a protected run after the rollback");
    await expect(startLoop(le, await findRun(le, run.runId))).rejects.toMatchObject({ code: "CONFIG_LAPSED" });
  }, 180_000);
});
