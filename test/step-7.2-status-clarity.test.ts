// Step 7.2 (S1 status clarity; F-S71-2, O-1; TD STEP-7.2-CONTRACT-CONDITIONAL-PASS): `status` and `setup` count an S1 or
// FIX confirmation as current only for the stored self-test protected execution would use, judged with the execution
// path's own functions; what this account cannot read is `unverified` (not established), never ready or misconfigured.
//
//   T1–T10  the S1 and FIX rows, one case each (unit, with the evidence the production observation produces);
//   T9      observeStoredSelfTests: inaccessible, not compared, probe failure, Linux operator by design;
//   T11     the agreement table: on the simulated custodian, every row's "in force" equals the enforcement's decision;
//   T12     F-S71-2 end to end: S1 and FIX re-runs, a missing record, revocation, lapse, S2, setup's confirmations;
//   T13     Q4: an explicit Codex or backend protected execution cannot use is refused before anything is recorded;
//   T14     the Linux proposal handoff (which proposals the custodian already holds) and setup's exit 3;
//   T15     O-1: a re-confirmation refused CONFIG_MISMATCH is not retried; setup offers `config set` (typed);
//   T16     layering: the status module imports no fixer module; the FIX reader is the CLI's.
//
// Evidence class: simulation (the native VMs run the real custodians).

import { describe, it, expect } from "vitest";
import { copyFile, readdir, readFile, rename, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "../src/cli/cli.js";
import { proposalConfirmed } from "../src/cli/setup-commands.js";
import { observeStoredSelfTests, repositoryRecords, repositoryStateOf, type FixEvidence, type Observed, type RecordState, type S1Evidence } from "../src/engine/protected-status.js";
import { confirmedFixSelfTest, confirmedSelfTest, protectedIsolationDecision, reviewBackends, selfTestRecordDigest, storedS1SelfTest } from "../src/engine/protected-config.js";
import { storedFixSelfTest, fixBackendFor } from "../src/engine/fix-confirmation.js";
import { probeCodex } from "../src/agents/codex/probe.js";
import { configSectionOf, CustodianGrants } from "../src/custodian/grants.js";
import { CONFIG_VIEW_RUN, type ConfigSection, type HeldAcceptance, type HeldSelftestConfirmation } from "../src/custodian/protocol.js";
import type { SelfTestRecord } from "../src/schemas/review.js";
import type { IsolationDecision } from "../src/agents/codex/isolation.js";
import { backendsFor, type SandboxBackend } from "../src/agents/codex/argv.js";
import type { Loaded } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, fixtureBackend, operatorIo, storeFixtureSelfTest, syntheticRuntime, SYNTHETIC_RUNTIME_GIT, type ContFixture } from "./helpers/continuation-fixture.js";
import { storeFixSelfTest, fixSelfTestKey } from "../src/agents/codex/fix-selftest.js";
import { fixProfileDigest } from "../src/agents/codex/fix-profile.js";
import { fixProfileFor } from "../src/engine/fix-confirmation.js";
import { storeLayout } from "../src/store/paths.js";
import { sha } from "./helpers/delegated-fix.js";

// ---------------------------------------------------------------------------
// Unit: the rows against the evidence (T1–T10)
// ---------------------------------------------------------------------------

const H = (c: string) => c.repeat(64);
const rec = (over: Partial<SelfTestRecord> = {}): SelfTestRecord => ({
  schema: "arl.codex-selftest.v1", selftest_id: "st-1", key: H("a"), codex_version: "0.160.0", backend: "mxc", mode: "S1", profile_digest: H("b"), created_at: "2026-11-07T00:00:00Z",
  profile_runs: true, rejection_reason: null, rows: [], s1_available: true, complete: true, ...over,
});
const conf = (r: SelfTestRecord, over: Partial<HeldSelftestConfirmation> = {}): HeldSelftestConfirmation => ({
  confirmationId: "c-1", globalRevision: 1, recordedAt: "t", selftestId: r.selftest_id, codexVersion: r.codex_version, backend: r.backend, mode: "S1", profileDigest: r.profile_digest,
  s1Available: true, rowsSummary: { total: 1, passed: 1, failed: [] }, recordDigest: selfTestRecordDigest(r), revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true, ...over,
});
const fixConf = (over: Partial<HeldSelftestConfirmation> = {}): HeldSelftestConfirmation => ({
  confirmationId: "f-1", globalRevision: 1, recordedAt: "t", selftestId: "fx-1", codexVersion: "0.160.0", backend: "mxc", mode: "FIX", profileDigest: H("c"), s1Available: true,
  rowsSummary: { total: 1, passed: 1, failed: [] }, recordDigest: H("d"), codexSha256: H("e"), revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true, ...over,
});
const acceptance = (over: Partial<HeldAcceptance> = {}): HeldAcceptance => ({ acceptanceId: "a-1", globalRevision: 1, recordedAt: "t", accepted: ["unrestricted_reads", "advisory_network"], backend: "mxc", codexVersionRange: "0.160", statementSha256: H("f"), revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true, ...over });
const installation = { path: "C:\\codex\\codex.exe", form: "native_pe", fileId: "1-2", size: 10, sha256: H("9") };
const repository = { configRevision: 1, recordedAt: "t", usable: true, revoked: false, lapsed: false, lapsedAtRecoveryId: null, codexInstallation: installation } as unknown as NonNullable<ConfigSection["repository"]>;
const section = (selftestConfirmations: HeldSelftestConfirmation[], acceptances: HeldAcceptance[] = []): ConfigSection => ({ globalRevision: 1, repository, acceptances, selftestConfirmations, engineRuntime: null });

/** The review's decision for the evidence: S1 when a stored record is covered by a usable confirmation, else S2 by an
 * acceptance (as decideIsolation), else refused. */
const decisionFor = (s: ConfigSection, recs: (SelfTestRecord | null)[], backends: string[]): IsolationDecision => {
  for (const r of recs) if (r && r.s1_available && r.profile_runs && confirmedSelfTest(s, r)) return { ok: true, isolation: { mode: "S1", backend: r.backend, selftest_id: r.selftest_id, acceptance_id: null } } as unknown as IsolationDecision;
  const a = s.acceptances.find((x) => x.usable && backends.includes(x.backend));
  if (a) return { ok: true, isolation: { mode: "S2", backend: a.backend, selftest_id: null, acceptance_id: a.acceptanceId } } as unknown as IsolationDecision;
  return { ok: false, reasons: ["refused"], missingSelfTests: [] };
};
const s1ev = (s: ConfigSection, stored: (SelfTestRecord | null)[], backends = ["mxc"], codexVersion = "0.160.0"): Observed<S1Evidence> => ({
  ok: true, value: { codexVersion, backends: backends as SandboxBackend[], stored: backends.map((b, i) => ({ backend: b as SandboxBackend, record: stored[i] ?? null })), decision: decisionFor(s, stored, backends) },
});
const fixev = (local: FixEvidence["local"], why: string | null = null): Observed<FixEvidence> => ({ ok: true, value: { codexVersion: "0.160.0", backend: "mxc", local, why } });
const rows = async (s: ConfigSection, o: { s1?: Observed<S1Evidence>; fix?: Observed<FixEvidence>; platform?: NodeJS.Platform } = {}) =>
  repositoryRecords({ platform: o.platform ?? "win32", root: "C:\\r", repoKey: "k", section: s, grants: [], hashFile: async () => installation.sha256, nowMs: Date.now(), exists: async () => true, implementerHome: "C:\\impl", ...(o.s1 ? { s1: o.s1 } : {}), ...(o.fix ? { fix: o.fix } : {}) });
const row = async (s: ConfigSection, name: RecordState["record"], o: Parameters<typeof rows>[1] = {}) => (await rows(s, o)).find((r) => r.record === name)!;

describe("Step 7.2 — the S1 row against the stored record a protected review uses (T1–T7, T10)", () => {
  it("T1: an S1 self-test re-run under the same key after its confirmation is unconfirmed, not in force (F-S71-2)", async () => {
    const old = rec({ selftest_id: "st-old" });
    const now = rec({ selftest_id: "st-new" });
    const s = section([conf(old)]);
    expect(await row(s, "isolation", { s1: s1ev(s, [old]) })).toMatchObject({ state: "in_force", detail: expect.stringContaining("covers the stored self-test st-old") });
    const r = await row(s, "isolation", { s1: s1ev(s, [now]) });
    expect(r).toMatchObject({ state: "unconfirmed", reason: "record_changed", resumable: true, required: true, restore: 'code-parley setup --resume --repo C:\\r --home "C:\\impl"' });
    expect(r.detail).toMatch(/stored S1 self-test st-new .* is not the one confirmed \(confirmation c-1 covers self-test st-old/);
    expect(r.detail).toContain("CODEX_ISOLATION_UNAVAILABLE");
    expect(repositoryStateOf(await rows(s, { s1: s1ev(s, [now]) }))).toBe("misconfigured");
    // Linux: the implementer proposes the stored record; the operator confirms it (no new self-test needed).
    expect((await row(s, "isolation", { s1: s1ev(s, [now]), platform: "linux" })).restore).toBe("the implementer: code-parley config propose-selftest --repo C:\\r --out <file>; then /usr/local/sbin/code-parley-operator setup --resume --repo C:\\r --proposal-file <file>");
  });

  it("T2/T9b: a missing local record is unconfirmed (record_missing) and names the self-test to run; a failed one record_failed", async () => {
    const old = rec();
    const s = section([conf(old)]);
    expect(await row(s, "isolation", { s1: s1ev(s, [null]) })).toMatchObject({ state: "unconfirmed", reason: "record_missing", restore: expect.stringMatching(/^the implementer: code-parley codex selftest --backend mxc in an interactive desktop session; then code-parley setup --resume/) });
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ selftest_id: "st-2", s1_available: false })]) })).toMatchObject({ state: "unconfirmed", reason: "record_failed" });
  });

  it("T3: a Codex update (another version: no stored record for it) and another binary are not in force", async () => {
    const old = rec();
    const s = section([conf(old)]);
    const r = await row(s, "isolation", { s1: s1ev(s, [null], ["mxc"], "0.161.0") });
    expect(r).toMatchObject({ state: "unconfirmed", reason: "record_missing", detail: expect.stringContaining("Codex 0.161.0") });
    // FIX: the same version, another binary — the delegation's predicate (binary SHA-256) does not hold.
    const f = section([fixConf()]);
    expect(await row(f, "fix_confirmation", { fix: fixev({ selftestId: "fx-1", codexSha256: H("7"), profileDigest: H("c") }) })).toMatchObject({ state: "unconfirmed", reason: "record_changed", required: false });
  });

  it("T4: a backend or profile other than the confirmed one is unconfirmed (the review's backends decide)", async () => {
    const old = rec();
    const s = section([conf(old)]);
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ backend: "elevated" })], ["elevated"]) })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ profile_digest: H("8") })]) })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
  });

  it("T5: revocation is kept: the stored record's revoked confirmation is revoked (not resumable), even beside a usable non-matching one", async () => {
    const r1 = rec();
    const only = section([conf(r1, { revoked: true, usable: false })]);
    expect(await row(only, "isolation", { s1: s1ev(only, [r1]) })).toMatchObject({ state: "revoked", resumable: false, restore: 'code-parley setup --repo C:\\r --home "C:\\impl"' });
    const beside = section([conf(r1, { revoked: true, usable: false }), conf(rec({ selftest_id: "st-other" }), { confirmationId: "c-2" })]);
    expect(await row(beside, "isolation", { s1: s1ev(beside, [r1]) })).toMatchObject({ state: "revoked", resumable: false });
    // Without any stored record, revocations only: revoked (as the custodian reports), never in force.
    expect(await row(only, "isolation", { s1: s1ev(only, [null]) })).toMatchObject({ state: "revoked" });
  });

  it("T6: the stored record's lapsed confirmation is lapsed (resume re-confirms it); a lapsed one of another record is unconfirmed", async () => {
    const r1 = rec();
    const s = section([conf(r1, { lapsed: true, usable: false, lapsedAtRecoveryId: "rec-1" })]);
    expect(await row(s, "isolation", { s1: s1ev(s, [r1]) })).toMatchObject({ state: "lapsed", resumable: true });
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ selftest_id: "st-new" })]) })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
  });

  it("T7: explicitly accepted S2 is in force only where the review would use it, with the S1 state named beside it", async () => {
    const s = section([conf(rec({ selftest_id: "st-old" }))], [acceptance()]);
    const r = await row(s, "isolation", { s1: s1ev(s, [rec({ selftest_id: "st-new" })]) });
    expect(r).toMatchObject({ state: "in_force", detail: expect.stringMatching(/^reduced isolation \(S2\): the operator's acceptance a-1 for mxc; S1 is not established \(the stored S1 self-test st-new/) });
    // An acceptance for another backend is not used by the review: not in force.
    const other = section([conf(rec({ selftest_id: "st-old" }))], [acceptance({ backend: "elevated" })]);
    expect(await row(other, "isolation", { s1: s1ev(other, [rec({ selftest_id: "st-new" })]) })).toMatchObject({ state: "unconfirmed" });
    // Not compared from this account, but the review would use S2 anyway: in force by the acceptance, said so.
    const nc: Observed<S1Evidence> = { ok: false, reason: "not_compared", why: "x", verify: "v", s2: { acceptanceId: "a-1", backend: "mxc" } };
    expect(await row(s, "isolation", { s1: nc })).toMatchObject({ state: "in_force", detail: expect.stringContaining("whether a confirmed S1 self-test applies was not compared") });
  });

  it("T10: older or partial custodian responses never read as in force", async () => {
    // A FIX confirmation without codexSha256 (before Phase 4 Increment 2): the delegation's predicate cannot hold.
    const f = section([fixConf({ codexSha256: undefined } as Partial<HeldSelftestConfirmation>)]);
    expect(await row(f, "fix_confirmation", { fix: fixev({ selftestId: "fx-1", codexSha256: H("e"), profileDigest: H("c") }) })).toMatchObject({ state: "unconfirmed" });
    // A confirmation of an unknown mode is never an S1 basis.
    const r1 = rec();
    const m = section([conf(r1, { mode: "S9" })]);
    expect((await row(m, "isolation", { s1: s1ev(m, [r1]) })).state).not.toBe("in_force");
    // A section whose confirmations lack recordDigest is refused whole (status: unknown), as before.
    expect(configSectionOf({ globalRevision: 1, repository: null, acceptances: [], selftestConfirmations: [{ confirmationId: "x", usable: true }] })).toBeNull();
    // No engineRuntime (a custodian before P3.4C-5): the engine runtime row is missing, as before.
    expect((await rows(section([]))).find((x) => x.record === "engine_runtime")).toMatchObject({ state: "missing" });
  });
});

describe("Step 7.2 — the FIX row (T8) and the unverified rows (T9)", () => {
  it("T8: a FIX re-run is unconfirmed (optional: the repository's readiness is unaffected); its own lapse and revocation are kept", async () => {
    const local = { selftestId: "fx-1", codexSha256: H("e"), profileDigest: H("c") };
    const s = section([fixConf()]);
    expect(await row(s, "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "in_force", detail: expect.stringContaining("covers the stored FIX self-test fx-1") });
    const rerun = await row(s, "fix_confirmation", { fix: fixev({ ...local, selftestId: "fx-2" }) });
    expect(rerun).toMatchObject({ state: "unconfirmed", reason: "record_changed", required: false, restore: 'code-parley setup --resume --repo C:\\r --fix --home "C:\\impl"' });
    expect(await row(s, "fix_confirmation", { fix: fixev(null, "no stored cp_fix self-test of Codex 0.160.0") })).toMatchObject({ state: "unconfirmed", reason: "record_missing", detail: expect.stringContaining("no stored cp_fix self-test") });
    expect(await row(section([fixConf({ lapsed: true, usable: false })]), "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "lapsed" });
    expect(await row(section([fixConf({ revoked: true, usable: false })]), "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "revoked", resumable: false });
    expect(await row(section([]), "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "missing" });
  });

  it("T9: what this account cannot read is unverified with the command that compares it — the repository is unknown, never ready or misconfigured", async () => {
    const r1 = rec();
    const s = section([conf(r1), fixConf()]);
    const linux: Observed<S1Evidence> = { ok: false, reason: "store_inaccessible", why: "the implementer's self-test store is not readable from the operator account (by design)", verify: "the implementer: code-parley status --repo /r" };
    const all = await rows(s, { s1: linux, fix: linux as unknown as Observed<FixEvidence>, platform: "linux" });
    expect(all.find((x) => x.record === "isolation")).toMatchObject({ state: "unverified", reason: "store_inaccessible", restore: "the implementer: code-parley status --repo /r", resumable: false });
    expect(all.find((x) => x.record === "fix_confirmation")).toMatchObject({ state: "unverified", required: false });
    const inForce = (record: RecordState["record"]): RecordState => ({ record, state: "in_force", required: true, detail: "", restore: null, resumable: false });
    const selfTestRows = all.filter((x) => x.record === "isolation" || x.record === "fix_confirmation");
    expect(repositoryStateOf([inForce("engine_runtime"), inForce("repository"), ...selfTestRows])).toBe("unknown");
    // Not compared at all (no evidence): unverified too — never in force from the custodian's records alone.
    expect(await row(s, "isolation")).toMatchObject({ state: "unverified" });
    // Custodian-only facts need no local record: nothing usable at all is missing / lapsed as before.
    expect(await row(section([]), "isolation", { s1: linux })).toMatchObject({ state: "missing" });
    expect(await row(section([conf(r1, { lapsed: true, usable: false })]), "isolation", { s1: linux })).toMatchObject({ state: "lapsed" });
    // A known problem elsewhere decides: misconfigured, not unknown.
    expect(repositoryStateOf([{ record: "repository", state: "missing", required: true, detail: "", restore: null, resumable: false }, ...all])).toBe("misconfigured");
  });
});

// ---------------------------------------------------------------------------
// The observation itself, on the simulated custodian
// ---------------------------------------------------------------------------

function terminal(answers: string | string[] = "confirm") {
  const queue = Array.isArray(answers) ? [...answers] : null;
  const next = () => (queue ? (queue.shift() ?? "no") : (answers as string));
  const io = operatorIo("confirm");
  return { ...io, prompt: async (q: string) => { const a = next(); return /"allow"/.test(q) ? (a === "confirm" ? "allow" : a) : a; } };
}

async function setupArgs(f: ContFixture, backend = true): Promise<string[]> {
  return ["--codex", f.codexExe, ...(backend ? ["--backend", await fixtureBackend(f)] : []), "--runtime", await syntheticRuntime(f.scratch), "--runtime-git", SYNTHETIC_RUNTIME_GIT, "--loops", "1", "--minutes", "60"];
}

type Row = { record: string; state: string; detail: string; restore: string | null; reason?: string };
async function statusJson(f: ContFixture, home = f.dataHome) {
  const io = operatorIo("");
  const code = await runCli(["status", "--repo", f.repo, "--json", "--home", home, "--git", f.git], { ...io, engineTestHooks: f.le.env.testHooks! });
  return { code, s: JSON.parse(io.lines.join("\n")) as { state: string; repository: { state: string; read_on: string; records: Row[]; protected_path: { codex_path: string; s1_backends: string[]; fix_backend: string | null } | null } } };
}
const rowOf = (s: Awaited<ReturnType<typeof statusJson>>["s"], name: string) => s.repository.records.find((r) => r.record === name)!;

/** The custodian's config section as the implementer reads it (as protected execution does). */
async function heldSection(f: ContFixture): Promise<ConfigSection> {
  const listing = await new CustodianGrants(f.custodian).listUserRecords("implementer", f.repo, CONFIG_VIEW_RUN, ["config"]);
  return listing.config!;
}

/** T11: the enforcement's own decision — the review's S1 selection and isolation decision, and the delegation's stored
 * FIX record and predicate — over the custodian's records and the stored self-tests now. */
async function enforcement(f: ContFixture): Promise<{ s1: boolean; mode: string | null; fix: boolean }> {
  const section = await heldSection(f);
  const probe = await probeCodex({ configured: section.repository!.codexInstallation!.path, sourceEnv: process.env, testLauncher: f.le.env.testHooks!.review!.codexLauncher! });
  const backends = reviewBackends(process.platform, f.le.cfg.config.codex.windows_sandbox, probe);
  const selfTests = new Map<SandboxBackend, SelfTestRecord | null>();
  for (const b of backends) {
    const r = await storedS1SelfTest(f.le.layout.selftestDir, probe, b);
    selfTests.set(b, r && confirmedSelfTest(section, r) ? r : null);
  }
  const d = protectedIsolationDecision(section, probe, backends, selfTests);
  let fix = false;
  try {
    const l = await storedFixSelfTest(f.le.layout.selftestDir, f.le.dataHome, fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe), probe);
    fix = confirmedFixSelfTest(section, { selftestId: l.record.selftest_id, codexSha256: l.codexSha256, profileDigest: l.profileDigest }) !== undefined;
  } catch {
    fix = false;
  }
  return { s1: d.ok, mode: d.ok ? d.isolation.mode : null, fix };
}

/** T11: status's rows agree with the enforcement (in force exactly when protected execution would accept the basis). */
async function expectAgreement(f: ContFixture): Promise<Awaited<ReturnType<typeof statusJson>>["s"]> {
  const { s } = await statusJson(f);
  const e = await enforcement(f);
  expect(rowOf(s, "isolation").state === "in_force", `isolation row ${JSON.stringify(rowOf(s, "isolation"))} vs enforcement ${JSON.stringify(e)}`).toBe(e.s1);
  expect(rowOf(s, "fix_confirmation").state === "in_force", `FIX row ${JSON.stringify(rowOf(s, "fix_confirmation"))} vs enforcement ${JSON.stringify(e)}`).toBe(e.fix);
  return s;
}

/** Re-run the fixture's S1 self-test: a new record (another self-test id) under the same key. */
async function rerunS1(f: ContFixture): Promise<void> {
  await removeS1(f);
  await storeFixtureSelfTest(f);
}
async function removeS1(f: ContFixture): Promise<void> {
  const dir = f.le.layout.selftestDir;
  for (const n of await readdir(dir)) {
    if (!n.endsWith(".json")) continue;
    const o = JSON.parse(await readFile(join(dir, n), "utf8")) as { schema?: string };
    if (o.schema === "arl.codex-selftest.v1") await rm(join(dir, n));
  }
}
/** Store another cp_fix self-test record (a re-run: another self-test id) under the same key. */
async function rerunFix(f: ContFixture, id: string): Promise<void> {
  const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
  // The delegation's own backend rule (on a Linux host with the simulated Windows custodian it differs from the review's).
  const backend = fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe);
  const codexSha256 = sha(await readFile(f.codexExe));
  const profile = fixProfileFor(backend, probe, [join(f.dataHome, "fix-selftest-work", "tree"), join(f.dataHome, "fix-selftest-work", "scratch")], [probe.codexHome]);
  await storeFixSelfTest(storeLayout(f.dataHome).selftestDir, {
    schema: "arl.codex-fix-selftest.v1", selftest_id: id, key: fixSelfTestKey(probe.version, codexSha256, profile), codex_version: probe.version, codex_sha256: codexSha256, backend,
    profile_digest: fixProfileDigest(profile), created_at: new Date().toISOString(), profile_runs: true, rejection_reason: null,
    rows: [{ name: "native_edit_outside_denied", expectation: "denied", sandbox: "denied", positive_control: "ok", pass: true, detail: "test record" }], confinement_available: true, complete: true,
  });
}

describe.skipIf(!supported)("Step 7.2 — observeStoredSelfTests: missing, inaccessible, not compared, probe failure, Linux by design (T9)", () => {
  it("T9a–d: each reason from an observation; the Linux operator is told the store is inaccessible by design (nothing is probed)", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    const section = await heldSection(f);

    // Readable, with the record: observed.
    expect((await observeStoredSelfTests(f.le, { platform: "win32", root: f.repo, on: "implementer", section })).s1.ok).toBe(true);
    // T9a: a data home that does not exist is inaccessible (not "missing record").
    const gone = { ...f.le, dataHome: join(f.scratch, "no-such-home") } as Loaded;
    expect((await observeStoredSelfTests(gone, { platform: "win32", root: f.repo, on: "implementer", section })).s1).toMatchObject({ ok: false, reason: "store_inaccessible", why: expect.stringContaining("there is no CodeParley data home") });
    // T9c: a Windows operator without --home: not compared (another account's data home), with the command that compares.
    const noHome = { ...f.le, env: { ...f.le.env, launch: { ...f.le.env.launch, home: undefined } } } as unknown as Loaded;
    expect((await observeStoredSelfTests(noHome, { platform: "win32", root: f.repo, on: "operator", section })).s1).toMatchObject({ ok: false, reason: "not_compared", verify: expect.stringContaining('--home "<the implementer\'s data home>"') });
    // T9d: the approved Codex cannot be probed.
    const noProbe = { ...f.le, env: { ...f.le.env, testHooks: undefined } } as unknown as Loaded;
    const broken = { ...section, repository: { ...section.repository!, codexInstallation: { ...section.repository!.codexInstallation!, path: join(f.scratch, "no-codex.exe") } } };
    expect((await observeStoredSelfTests(noProbe, { platform: "win32", root: f.repo, on: "implementer", section: broken })).s1).toMatchObject({ ok: false, reason: "probe_failed" });
    // The Linux operator: inaccessible by design.
    expect((await observeStoredSelfTests(f.le, { platform: "linux", root: f.repo, on: "operator", section })).s1).toMatchObject({ ok: false, reason: "store_inaccessible", why: expect.stringContaining("by design") });
    // T9b through status: a readable store without the record is a missing record (unconfirmed), not inaccessible.
    await removeS1(f);
    expect(rowOf((await statusJson(f)).s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
    // T9a through status: a data home that does not exist is not established (Windows). On Linux the engine creates its
    // own private data home when it loads (ensurePrivateDataHome, unchanged), so it is an empty, readable store there.
    const s = (await statusJson(f, join(f.scratch, "no-such-home"))).s;
    if (process.platform === "linux") expect(rowOf(s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
    else {
      expect(rowOf(s, "isolation")).toMatchObject({ state: "unverified", reason: "store_inaccessible" });
      expect(s.repository.state).toBe("unknown");
    }
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T11 + T12: F-S71-2 end to end, with the agreement checked at every state
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("Step 7.2 — F-S71-2 end to end: status agrees with enforcement; setup confirms what protected execution uses (T11, T12)", () => {
  it("S1 and FIX re-runs, a missing record, a revocation, a lapse and an S2 acceptance", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    // The FIX legs need the delegation's backend to be one this host's operator CLI accepts. On a real host it always is;
    // with this fixture's simulated Windows custodian on a Linux host it is not (the delegation selects mxc), so there the
    // FIX legs are left to T8 (unit) and the Linux VM rows.
    const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
    const fixLegs = (backendsFor() as readonly string[]).includes(fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe));
    if (fixLegs) await rerunFix(f, "fix-selftest-1");
    // With --fix no --backend (Q4: each confirmation uses the backend its own execution path selects).
    const ok = await cli(f, ["setup", ...(fixLegs ? ["--fix"] : []), "--repo", f.repo, ...(await setupArgs(f, false))], terminal());
    expect(ok.code, ok.err).toBe(0);
    if (fixLegs) expect(ok.out).toMatch(/confirm the stored FIX self-test/);
    let s = await expectAgreement(f);
    expect(s.repository.state).toBe("ready");
    expect(rowOf(s, "fix_confirmation").state).toBe(fixLegs ? "in_force" : "missing");
    expect(s.repository.protected_path).toMatchObject({ codex_path: expect.any(String), s1_backends: [await fixtureBackend(f)] });

    // T12 (F-S71-2): the S1 self-test is re-run after its confirmation: status says so, and enforcement agrees.
    await rerunS1(f);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
    expect(s.repository.state).toBe("misconfigured");
    expect((await statusJson(f)).code).toBe(1);
    // A declined confirmation records nothing.
    const before = f.custodian.snapshot().config.selftestConfirmations.length;
    const declined = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal("no"));
    expect(declined.code).toBe(2);
    expect(declined.out).toMatch(/Step 1: confirm the stored S1 self-test/);
    expect(f.custodian.snapshot().config.selftestConfirmations.length).toBe(before);
    // setup --resume confirms the stored record — of the approved installation, on the review's backend, by default.
    const confirmed = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(confirmed.code, confirmed.err).toBe(0);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation").state).toBe("in_force");

    // T8: the FIX self-test is re-run: optional for readiness; setup --resume --fix confirms it.
    if (fixLegs) {
      await rerunFix(f, "fix-selftest-2");
      s = await expectAgreement(f);
      expect(rowOf(s, "fix_confirmation")).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
      expect(s.repository.state).toBe("ready");
      expect((await cli(f, ["setup", "--resume", "--fix", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
      expect(rowOf(await expectAgreement(f), "fix_confirmation").state).toBe("in_force");
    }

    // T2: the stored S1 record is gone: setup cannot confirm it and names the self-test to run (nothing recorded).
    await removeS1(f);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
    const blocked = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(blocked.code).toBe(2);
    expect(blocked.out).toMatch(/Not possible yet: .*The implementer runs `code-parley codex selftest --backend \S+` first/);
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);

    // T5: the operator revokes the confirmation of the stored record: revoked; --resume never restores it.
    const id = f.custodian.snapshot().config.selftestConfirmations.filter((c) => c.mode === "S1" && c.revokedAt === null && c.supersededAt === null).at(-1)!.confirmationId;
    expect((await cli(f, ["config", "revoke-selftest", "--repo", f.repo, id], terminal())).code).toBe(0);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "revoked" });
    const resumed = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(resumed.out).not.toMatch(/confirm the stored S1 self-test/);
    expect(resumed.code).toBe(1);
    // Without --resume, the operator may confirm it anew (a new typed confirmation).
    expect((await cli(f, ["setup", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("in_force");

    // T6: a restart of the OS lapses it: lapsed (not in force), as the custodian refuses it (CONFIG_LAPSED).
    f.custodian.simulateRecoveryAfterNewBoot();
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("lapsed");
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("in_force");

    // T7: an explicit acceptance of reduced isolation, then an S1 re-run: in force by S2, as the review would decide.
    expect((await cli(f, ["config", "accept-isolation", "--repo", f.repo, "--backend", await fixtureBackend(f), "--codex", f.codexExe], terminal())).code).toBe(0);
    await rerunS1(f);
    s = await expectAgreement(f);
    expect((await enforcement(f)).mode).toBe("S2");
    expect(rowOf(s, "isolation")).toMatchObject({ state: "in_force", detail: expect.stringContaining("reduced isolation (S2)") });
  }, 480_000);
});

// ---------------------------------------------------------------------------
// T13: Q4 — explicit selections protected execution cannot use
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("Step 7.2 — Q4: an explicit Codex or backend protected execution cannot use is refused before anything is recorded (T13)", () => {
  it("refuses another installation than the approved one, and a backend the review does not use; nothing is recorded", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    await rerunS1(f);
    const other = join(f.scratch, "other-codex.exe");
    await copyFile(f.codexExe, other);
    const snap = JSON.stringify(f.custodian.snapshot().config);
    const codex = await cli(f, ["setup", "--resume", "--repo", f.repo, "--codex", other, "--no-grant"], terminal());
    expect(codex.code).toBe(1);
    expect(codex.err).toMatch(/--codex .* is not the Codex installation the custodian approved for this repository .*protected reviews and delegated fixes launch only that one.*Nothing was recorded/);
    const wrong = process.platform === "win32" ? "bwrap" : "mxc";
    const backend = await cli(f, ["setup", "--resume", "--repo", f.repo, "--backend", wrong, "--no-grant"], terminal());
    expect(backend.code).toBe(1);
    expect(backend.err).toMatch(new RegExp(`--backend ${wrong} is not a backend a protected review uses with this Codex: ${await fixtureBackend(f)}`));
    expect(JSON.stringify(f.custodian.snapshot().config)).toBe(snap);
    // The approved installation and the review's backend, named explicitly, are accepted.
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--codex", f.codexExe, "--backend", await fixtureBackend(f), "--no-grant"], terminal())).code).toBe(0);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T14: the Linux proposal handoff and the end of an operator-only setup
// ---------------------------------------------------------------------------

describe("Step 7.2 — the Linux proposal handoff (T14)", () => {
  it("a proposal counts as confirmed only for a usable confirmation of exactly its record", () => {
    const r1 = rec();
    const p = { selftestId: r1.selftest_id, codexVersion: r1.codex_version, backend: r1.backend, mode: "S1", profileDigest: r1.profile_digest, recordDigest: selfTestRecordDigest(r1) };
    expect(proposalConfirmed(section([conf(r1)]), p)).toBe(true);
    expect(proposalConfirmed(section([conf(r1, { usable: false, lapsed: true })]), p)).toBe(false);
    expect(proposalConfirmed(section([conf(r1, { usable: false, revoked: true })]), p)).toBe(false);
    expect(proposalConfirmed(section([conf(r1)]), { ...p, recordDigest: H("0") })).toBe(false);
    expect(proposalConfirmed(section([conf(r1)]), { ...p, selftestId: "st-other" })).toBe(false);
    expect(proposalConfirmed(section([conf(r1)]), null)).toBe(false);
    const fp = { mode: "FIX", selftestId: "fx-1", codexSha256: H("e"), profileDigest: H("c") };
    expect(proposalConfirmed(section([fixConf()]), fp)).toBe(true);
    expect(proposalConfirmed(section([fixConf()]), { ...fp, codexSha256: H("7") })).toBe(false);
    // An S1 confirmation never covers a FIX proposal, nor the reverse.
    expect(proposalConfirmed(section([conf(r1)]), { ...fp, selftestId: r1.selftest_id })).toBe(false);
  });
});

describe.skipIf(!supported)("Step 7.2 — an operator whose account cannot read the implementer's store completes its steps with exit 3 (T14)", () => {
  it("setup records what the operator can, never loops, and ends 'not verified from this account' with the implementer's command", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    // The same custodian state, read as on Linux by the operator account: the implementer's store is inaccessible.
    const linuxOperator = { ...f.operatorHooks!, custodian: { ...f.operatorHooks!.custodian!, platform: "linux" as NodeJS.Platform } };
    const io = { ...terminal(), engineTestHooks: linuxOperator };
    const r = await cli(f, ["setup", "--repo", f.repo, "--no-grant"], io);
    expect(r.code, r.err + r.out).toBe(3);
    expect(r.out).toMatch(/Operator configuration is complete; it is NOT verified from this account .*Codex isolation \(S1\).*Verify: the implementer: code-parley status --repo/);
    expect(r.out).toMatch(/UNVERIFIED/);
    expect(r.out).not.toMatch(/Step \d+: confirm/);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T15: O-1 — a re-confirmation refused CONFIG_MISMATCH
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("Step 7.2 — O-1: after a refused re-confirmation setup offers `config set`, typed, and never retries it (T15)", () => {
  it("a Codex file replaced with the same bytes (a new file identity) after a restart: reconfirm refused → set again → ready; declining set records nothing", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    // The same bytes under a new file identity (a reinstall), then a restart of the OS.
    await copyFile(f.codexExe, `${f.codexExe}.new`);
    await rename(`${f.codexExe}.new`, f.codexExe);
    f.custodian.simulateRecoveryAfterNewBoot();
    const lapsed = await statusJson(f);
    expect(rowOf(lapsed.s, "repository").state).toBe("lapsed"); // the hash is unchanged: status cannot tell

    // Declined: the refused re-confirmation records nothing; the engine runtime that lapsed with the same restart is
    // re-confirmed (unchanged rule: before the repository record), and the operator declines the `set` step.
    const versions = f.custodian.snapshot().config.repositories.length;
    const declined = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal(["confirm", "no"]));
    expect(declined.code).toBe(2);
    expect(declined.err).toMatch(/error CONFIG_MISMATCH: the Codex installation measured now differs from the one held/);
    expect(declined.out).toMatch(/Step 1: re-confirm the repository's configuration/);
    expect(declined.out).toMatch(/Step 2: re-confirm the engine runtime approval/);
    expect(declined.out).toMatch(/Step 3: set the repository's protected configuration again \(the custodian refused its re-confirmation\)/);
    expect(declined.out).toContain("Stopped: not confirmed");
    expect(f.custodian.snapshot().config.repositories.length).toBe(versions);

    // Confirmed: the set step's own rendering and typed confirmation, then the remaining lapsed records; never a second re-confirmation.
    const ok = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(ok.code, ok.err).toBe(0);
    expect(ok.out.match(/re-confirm the repository's configuration/g)).toHaveLength(1);
    expect(ok.out).toMatch(/set the repository's protected configuration again/);
    expect(f.custodian.snapshot().config.repositories.length).toBe(versions + 1);
    expect((await statusJson(f)).s.repository.state).toBe("ready");
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T16: layering
// ---------------------------------------------------------------------------

describe("Step 7.2 — layering: the status path imports no fixer module; no new authority (T16)", () => {
  const srcDir = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src");
  const srcRel = (file: string): string => relative(srcDir, file).split(sep).join("/");
  const reachable = (entry: string): Set<string> => {
    const seen = new Set<string>();
    const stack = [entry];
    while (stack.length) {
      const rel = stack.pop()!;
      if (seen.has(rel)) continue;
      seen.add(rel);
      for (const m of readFileSync(join(srcDir, rel), "utf8").matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)) stack.push(srcRel(join(dirname(join(srcDir, rel)), m[1]! + ".ts")));
    }
    return seen;
  };
  const FIX = ["agents/codex/fix-profile.ts", "agents/codex/fix-selftest.ts", "agents/codex/fix-isolation.ts", "agents/codex/fix-launcher.ts", "engine/fix-operation.ts", "engine/fix-confirmation.ts", "engine/fix-apply.ts", "engine/fix-decision.ts"];

  it("engine/protected-status.ts and engine/protected-config.ts reach no fixer module; the shared FIX predicate is pure", () => {
    for (const m of ["engine/protected-status.ts", "engine/protected-config.ts"]) expect([...reachable(m)].filter((x) => FIX.includes(x)), m).toEqual([]);
    const text = readFileSync(join(srcDir, "engine", "protected-config.ts"), "utf8");
    const fn = /export function confirmedFixSelfTest[\s\S]*?\n}/.exec(text)![0];
    expect(fn).not.toMatch(/await|readFile|Date\.|process\./);
  });

  it("the FIX evidence reader is the CLI's only, and the hooks and the helper reach none of the Step 7.2 CLI modules", () => {
    const users = ["cli/cli.ts", "cli/setup-commands.ts"];
    for (const entry of ["hooks/main.ts", "hooks/adapter.ts", "helper/main.ts", "process/session-reaper-main.ts"]) {
      const r = reachable(entry);
      expect(r.has("cli/status-fix-evidence.ts") || r.has("cli/setup-commands.ts"), entry).toBe(false);
    }
    const importers = (target: string) => [...reachable("cli/main.ts")].filter((rel) => [...readFileSync(join(srcDir, rel), "utf8").matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)].some((m) => srcRel(join(dirname(join(srcDir, rel)), m[1]! + ".ts")) === target)).sort();
    expect(importers("cli/status-fix-evidence.ts")).toEqual(users);
  });
});
