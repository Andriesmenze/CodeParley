// P3.4C-4 increment 1 (contract §10 step 1): the mandatory regressions, shown failing against the current code.
//
// M1 — the local trusted files decide a protected run today: a check approved, or a required check's definition
// changed, only in trust/projects.json; capture rules changed only in config.json; run.json edited after `open`.
// M3/M4 — what the custodian's configuration would not support is accepted today: a check whose definition the
// operator never approved for the custodian runs and is recorded (M3); a review's isolation rests on a self-test
// record the operator never confirmed, or on an acceptance held only in trust/isolation.json (M4).
//
// Each runs over two account-bound simulated transports: the engine reaches only the implementer pipe, the operator's
// CLI only the operator pipe. Committed as expected failures against the pre-correction code (increment 1, `3d75158`);
// since the correction they are ordinary tests. The controls held before and after it.

import { describe, it, expect } from "vitest";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { probeCodex } from "../src/agents/codex/probe.js";
import { REDUCED_ISOLATION_STATEMENT_SHA256 } from "../src/agents/codex/isolation.js";
import { findRun, loadEngine, type RunHandle } from "../src/engine/engine-env.js";
import { startChecksOperation, startReviewOperation } from "../src/engine/operations.js";
import { readState } from "../src/store/state-store.js";
import { storeLayout } from "../src/store/paths.js";
import { supported } from "./helpers/git-fixture.js";
import { approve } from "./helpers/checks-fixture.js";
import { defect, fakeCalls, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { contFixture, fixtureBackend, grant, HostSession, NODE, newRun, runChecks, type ContFixture } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [defect()] }));
const UNIT = { argv: [NODE, "scripts/pass.js", "CHECK_TOKEN_3a"] };
const FLOOR = { profiles: { default: ["unit"] }, required_profiles: ["default"] };

function fixtureLauncher(f: ContFixture) {
  return { file: process.execPath, prefixArgs: [f.fakeScript] };
}

/** A run the custodian protects: the operator imports its configuration (`config set`, `config confirm-selftest`; the
 * fixture's grant does it first), a grant, a bound loop. */
async function protectedRun(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  return run;
}

function custodianRun(f: ContFixture, run: RunHandle) {
  return f.custodian.snapshot().runs.find((r) => r.runId === run.runId);
}

const executionsOf = (f: ContFixture, run: RunHandle) => (custodianRun(f, run)?.checkExecutions ?? []) as Record<string, unknown>[];
const acceptedReviews = (f: ContFixture, run: RunHandle) => (custodianRun(f, run)?.reviews ?? []).filter((r) => (r as { accepted?: unknown }).accepted === true);

async function reviewOnce(f: ContFixture, run: RunHandle, le = f.le): Promise<void> {
  const s = await startReviewOperation(le, run, {});
  await s.completion;
}

describe.skipIf(!supported)("P3.4C-4 M1/M3 — local trusted check configuration on a protected run", () => {
  it("(a) a check approved only in trust/projects.json after the run became protected is refused (CHECK_NOT_APPROVED); nothing runs or is recorded", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4a", 9801);
    await approve(f, { checks: { unit: UNIT, evil: { argv: [NODE, "scripts/pass.js", "EVIL_TOKEN"] } }, ...FLOOR });
    await expect(startChecksOperation(f.le, run, { checks: ["evil"] })).rejects.toMatchObject({ code: "CHECK_NOT_APPROVED" });
    expect(executionsOf(f, run).filter((e) => e["check"] === "evil")).toEqual([]);
    expect((await readState(run.paths)).check_executions.filter((e) => e.check === "evil")).toEqual([]);
  }, 120_000);

  it("(b) a required check's definition changed only in trust/projects.json: the protected run keeps running the definition the operator approved for the custodian", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4b", 9802);
    await runChecks(f, run);
    const approved = (await readState(run.paths)).check_executions.find((e) => e.check === "unit")!.definition_digest;
    expect(approved).toMatch(/^[0-9a-f]{64}$/);
    await approve(f, { checks: { unit: { argv: [NODE, "scripts/pass.js", "CHANGED_LOCALLY"] } }, ...FLOOR });
    await runChecks(f, run);
    const latest = (await readState(run.paths)).check_executions.filter((e) => e.check === "unit" && e.status !== "skipped").at(-1)!;
    expect(latest.definition_digest).toBe(approved);
    expect(executionsOf(f, run).filter((e) => e["status"] !== "skipped").at(-1)!["definitionDigest"]).toBe(approved);
  }, 120_000);

  it("control: an attended run still follows trust/projects.json (Phase 2 behaviour)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const attended = await newRun(f, "an attended run");
    await approve(f, { checks: { unit: UNIT, extra: { argv: [NODE, "scripts/pass.js", "EXTRA_TOKEN"] } }, ...FLOOR });
    const s = await startChecksOperation(f.le, attended, { checks: ["extra"] });
    await s.completion;
    expect((await readState(attended.paths)).check_executions.filter((e) => e.check === "extra" && e.status === "passed")).toHaveLength(1);
  }, 120_000);

  it("control: the approved check runs on the protected run and is recorded by the custodian", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4c", 9803);
    await runChecks(f, run);
    expect(executionsOf(f, run).map((e) => [e["check"], e["status"]])).toEqual([["unit", "passed"]]);
  }, 120_000);
});

describe.skipIf(!supported)("P3.4C-4 M4 — a review's isolation basis on a protected run", () => {
  it("(c) a self-test record changed after the operator confirmed it gives no S1: the review is not accepted", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4d", 9804);
    await runChecks(f, run);
    const dir = storeLayout(f.dataHome).selftestDir;
    for (const name of await readdir(dir)) {
      const rec = JSON.parse(await readFile(join(dir, name), "utf8")) as { rows: { detail: string }[] };
      rec.rows = rec.rows.map((r) => ({ ...r, detail: `${r.detail} (rewritten by a same-user process)` }));
      await writeFile(join(dir, name), JSON.stringify(rec, null, 2));
    }
    await reviewOnce(f, run);
    expect(acceptedReviews(f, run)).toEqual([]);
    expect(await fakeCalls(f, "exec")).toHaveLength(0);
  }, 120_000);

  it("(d) a reduced-isolation acceptance written only to trust/isolation.json gives no S2: the review is not accepted", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4e", 9805);
    await runChecks(f, run);
    // S1 becomes unavailable (no stored self-test; the sandbox rejects the profile) …
    const dir = storeLayout(f.dataHome).selftestDir;
    for (const name of await readdir(dir)) await writeFile(join(dir, name), "{}");
    await setScenario(f, { sandbox: { mode: "reject" }, ...scenario() });
    // … and a same-user process writes an acceptance of reduced isolation the way the CLI would.
    const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: fixtureLauncher(f) });
    const acceptance = {
      acceptance_id: "019a0000-0000-7000-8000-00000000c4d0",
      accepted: ["unrestricted_reads", "advisory_network"],
      backend: await fixtureBackend(f),
      codex_version_range: probe.compat.versionPrefix,
      statement_sha256: REDUCED_ISOLATION_STATEMENT_SHA256,
      accepted_at: new Date().toISOString(),
      via: "cli",
      revoked_at: null,
    };
    await writeFile(storeLayout(f.dataHome).trustIsolation, JSON.stringify({ schema_version: 1, records: [acceptance] }, null, 2));
    await reviewOnce(f, run);
    expect(acceptedReviews(f, run)).toEqual([]);
    expect(await fakeCalls(f, "exec")).toHaveLength(0);
  }, 120_000);
});

describe.skipIf(!supported)("P3.4C-4 M1/M6 — config.json capture rules and run.json on a protected run", () => {
  it("(e) capture rules changed only in config.json do not change what a protected review exports: the confidential file stays withheld", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4f", 9806);
    await runChecks(f, run);
    // A same-user process empties the confidential exclusions; the server reads config.json again on its next call.
    await writeFile(storeLayout(f.dataHome).configFile, JSON.stringify({ capture: { exclude_globs: [] } }));
    const le = await loadEngine(f.le.env);
    await reviewOnce(f, await findRun(le, run.runId), le);
    const calls = await fakeCalls(f, "exec");
    for (const c of calls) expect(c.prompt ?? "").not.toContain("hunter3");
    const st = await readState(run.paths);
    const capture = st.reviews.at(-1)?.artifacts["capture"];
    expect(capture).toBeTruthy();
    const record = JSON.parse(await readFile(join(run.paths.runDir, capture!), "utf8")) as { entries: { path: string; class: string }[] };
    expect(record.entries.find((e) => e.path === ".env")?.class).toBe("excluded");
  }, 120_000);

  it("(f) run.json edited after open: the protected run's checks and review are refused (fail closed)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-c4g", 9807);
    const meta = JSON.parse(await readFile(run.paths.runJson, "utf8")) as Record<string, unknown>;
    meta["envelope"] = { ...(meta["envelope"] as Record<string, unknown>), goal: "a goal a same-user process wrote after open" };
    await writeFile(run.paths.runJson, JSON.stringify(meta, null, 2));
    const edited = await findRun(f.le, run.runId);
    await expect(startChecksOperation(f.le, edited, {})).rejects.toMatchObject({ code: "RUN_JSON_MISMATCH" });
    await expect(startReviewOperation(f.le, edited, {})).rejects.toMatchObject({ code: "RUN_JSON_MISMATCH" });
    expect(executionsOf(f, run)).toEqual([]);
  }, 120_000);
});
