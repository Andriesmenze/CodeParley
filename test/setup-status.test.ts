// Phase 6 Increment 3 (contract §5; [[D-41]]): setup, status and diagnostics.
//
//   - the remediation catalog: every top refusal has a cause and a fix, worded for its platform (the tested table);
//   - the CLI prints it under an error, the MCP error result carries it;
//   - status's states, each from an observation (not installed, stopped, unavailable, busy, untrusted, incompatible, ready);
//   - end to end on the simulated custodian (two account-bound transports): a new repository is ready after `init` +
//     `setup`; a declined step records nothing further; after a restart of the OS `status` names exactly the lapsed
//     records and `setup --resume` restores them with the operator's typed confirmations; after a Codex update the
//     repository record is reported changed and `setup --resume` sets it again.
//
// Evidence class: simulation (the native VMs run the real custodian).

import { describe, it, expect } from "vitest";
import { copyFile, cp, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { REMEDY_CODES, remedyFor, remedyLines } from "../src/common/remedies.js";
import { errorStructure } from "../src/server/result.js";
import { runCli } from "../src/cli/cli.js";
import { BUSY_LIMITATION, hostStateOf, protectedStatus, repositoryRecords, type SurfaceProbe } from "../src/engine/protected-status.js";
import type { ConfigSection, GrantSummary } from "../src/custodian/protocol.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { CustodianRuns } from "../src/custodian/runs.js";
import { nodeSupported } from "../src/engine/doctor.js";
import { CustodianBusy, CustodianNotTrusted, CustodianUnavailable, type CustodianTransport } from "../src/custodian/transport.js";
import type { Loaded } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output, minimalPe } from "./helpers/review-fixture.js";
import { cli, contFixture, fixtureBackend, operatorIo, storeFixtureSelfTest, syntheticRuntime, SYNTHETIC_RUNTIME_GIT, type ContFixture } from "./helpers/continuation-fixture.js";

describe("Phase 6 Increment 3 — the remediation catalog (the tested table)", () => {
  const TOP = [
    "CUSTODIAN_UNAVAILABLE", "CUSTODIAN_BUSY", "SERVER_NOT_TRUSTED", "CALLER_NOT_AUTHORIZED", "INTERACTIVE_TERMINAL_REQUIRED", "OPERATOR_CODE_UNTRUSTED",
    "LOOP_NOT_AUTHORIZED", "CONFIG_NOT_HELD", "CONFIG_LAPSED", "ISOLATION_NOT_ACCEPTED", "CONFIG_MISMATCH", "STALE_CONFIG", "RUNTIME_NOT_APPROVED",
    "HELPER_UNAVAILABLE", "REPOSITORY_NOT_READABLE", "CODEX_ISOLATION_UNAVAILABLE", "CHECK_NOT_APPROVED", "SCOPE_NOT_CONFIGURED",
    "FIX_DELEGATION_UNAVAILABLE", "STORE_VERSION_UNSUPPORTED",
  ];

  it("every top refusal has a cause and a fix on Windows and on Linux", () => {
    for (const code of TOP) {
      expect(REMEDY_CODES, code).toContain(code);
      for (const p of ["win32", "linux"] as const) {
        const r = remedyFor(code, p);
        expect(r?.cause.length, `${code} ${p}`).toBeGreaterThan(20);
        expect(r?.fix.length, `${code} ${p}`).toBeGreaterThan(20);
      }
    }
    expect(remedyFor("NO_SUCH_CODE")).toBeNull();
    // The Windows VM's case: the implementer reached for the operator pipe and the OS denied it: the operator's remedy.
    const denied = remedyFor("CUSTODIAN_UNAVAILABLE", "win32", 'the custodian could not be reached on the operator pipe ("Access to the path is denied.")');
    expect(denied?.cause).toMatch(/may not connect to its operator endpoint/);
    expect(denied?.fix).toMatch(/elevated terminal/);
    expect(remedyFor("CUSTODIAN_UNAVAILABLE", "linux", "connect EACCES /run/codeparley/operator.sock")?.fix).toContain("/usr/local/sbin/code-parley-operator");
    expect(remedyFor("CUSTODIAN_UNAVAILABLE", "win32", "no pipe")?.cause).toMatch(/no trusted answer/);
  });

  it("platform wording: no Windows command on Linux, no Linux command on Windows", () => {
    for (const code of REMEDY_CODES) {
      const lin = remedyFor(code, "linux")!;
      const win = remedyFor(code, "win32")!;
      expect(`${lin.cause} ${lin.fix}`, code).not.toMatch(/elevated|Run as administrator|\.ps1|\.exe\b|sc\.exe/);
      // OPERATOR_CODE_UNTRUSTED is raised on Linux only (the operator wrapper): its text is Linux's on every platform.
      if (code !== "OPERATOR_CODE_UNTRUSTED") expect(`${win.cause} ${win.fix}`, code).not.toMatch(/code-parley-operator|sudo |systemctl|\.sh\b/);
    }
    // The operator's command: the wrapper on Linux, the elevated terminal on Windows.
    expect(remedyFor("CONFIG_LAPSED", "linux")!.fix).toContain("/usr/local/sbin/code-parley-operator setup --resume");
    expect(remedyFor("CONFIG_LAPSED", "win32")!.fix).toMatch(/code-parley setup --resume .*elevated terminal/);
    expect(remedyFor("REPOSITORY_NOT_READABLE", "linux")!.fix).toContain("sudo bash codeparley-installer.sh grant-repository --path <repository>");
    expect(remedyFor("REPOSITORY_NOT_READABLE", "win32")!.fix).toContain("codeparley-installer.ps1 grant-repository -Path <repository>");
  });

  it("the busy refusal explains the accepted cold-start limitation, and that it fails closed", () => {
    const w = remedyFor("CUSTODIAN_BUSY", "win32")!;
    expect(w.cause).toContain("37.7 s");
    expect(w.fix).toMatch(/fails closed/);
    expect(BUSY_LIMITATION).toMatch(/first-release limitation: it fails closed/);
  });

  it("the CLI prints the cause and the fix under an error; the MCP error result carries it", async () => {
    expect(remedyLines("CONFIG_LAPSED", "linux")).toEqual([expect.stringMatching(/^ {2}cause: /), expect.stringMatching(/^ {2}fix: {3}/)]);
    const s = errorStructure({ code: "LOOP_NOT_AUTHORIZED", message: "no grant", retryable: false });
    expect(s["error"]).toMatchObject({ code: "LOOP_NOT_AUTHORIZED", remedy: { cause: expect.any(String), fix: expect.stringContaining("setup --repo") } });
    expect(String(s["summary"])).toMatch(/^error LOOP_NOT_AUTHORIZED: no grant — fix: /);
    expect(errorStructure({ code: "INTERNAL", message: "x", retryable: false })["error"]).not.toHaveProperty("remedy");
    // A real CLI path: a host without a validated custodian.
    const lines: string[] = [];
    const errors: string[] = [];
    const code = await runCli(["config", "show", "--repo", process.cwd()], { out: (l) => lines.push(l), err: (l) => errors.push(l), prompt: null, env: process.env, cwd: process.cwd(), engineTestHooks: { custodian: { platform: "freebsd" } } });
    expect(code).toBe(1);
    expect(errors[0]).toMatch(/^error CUSTODIAN_UNAVAILABLE: /);
    expect(errors.slice(1).join("\n")).toMatch(/cause: .*\n {2}fix: /);
  });

  it("doctor warns about an unsupported Node.js", () => {
    expect(nodeSupported("v22.12.0")).toBe(true);
    expect(nodeSupported("v24.1.0")).toBe(true);
    expect(nodeSupported("v22.11.0")).toBe(false);
    expect(nodeSupported("v20.18.0")).toBe(false);
    expect(nodeSupported("v23.0.0")).toBe(false);
  });
});

const probe = (surface: SurfaceProbe["surface"], result: SurfaceProbe["result"]): SurfaceProbe => ({ surface, result, detail: null, identity: null });

describe("Phase 6 Increment 3 — status's states, each from an observation", () => {
  it("hostStateOf: the decisive observation first", () => {
    const ans = [probe("implementer", "answers"), probe("operator", "refused")];
    expect(hostStateOf("darwin", "absent", null, [])).toBe("unsupported_platform");
    expect(hostStateOf("win32", "absent", null, [])).toBe("not_installed");
    expect(hostStateOf("win32", "registered", "RUNNING", ans)).toBe("ready");
    expect(hostStateOf("win32", "registered", "RUNNING", [probe("implementer", "busy"), probe("operator", "refused")])).toBe("busy");
    expect(hostStateOf("win32", "registered", "STOPPED", [probe("implementer", "unavailable"), probe("operator", "unavailable")])).toBe("stopped");
    expect(hostStateOf("win32", "registered", "RUNNING", [probe("implementer", "unavailable"), probe("operator", "unavailable")])).toBe("unavailable");
    expect(hostStateOf("win32", "unknown", null, [probe("implementer", "unavailable")])).toBe("unavailable"); // unknown presence: installed (fail closed)
    expect(hostStateOf("linux", "registered", "socket inactive, service inactive", [probe("implementer", "unavailable")])).toBe("stopped");
    expect(hostStateOf("linux", "registered", "socket active, service inactive", [probe("implementer", "unavailable")])).toBe("unavailable");
    // A squatter or another release outranks an answer: never reported ready.
    expect(hostStateOf("win32", "registered", "RUNNING", [probe("implementer", "answers"), probe("operator", "untrusted")])).toBe("untrusted");
    expect(hostStateOf("win32", "registered", "RUNNING", [probe("implementer", "incompatible")])).toBe("incompatible");
  });

  /** The probe over a scripted transport (no engine: protectedStatus reads only the test hooks). */
  async function statusWith(send: CustodianTransport["send"], presence: "registered" | "absent" = "registered", managerState: string | null = "RUNNING") {
    const le = { env: { testHooks: { custodian: { platform: "win32", presence, transport: { send } } } } } as unknown as Loaded;
    return protectedStatus(le, { hooks: { managerState: async () => managerState } });
  }

  it("the probe classifies the transport's own outcomes", async () => {
    const ready = await statusWith(async (surface) => (surface === "implementer" ? { ok: true, data: { pong: true, caller: "implementer", version: "0.3.0", build: "abc", protocol: 1, host: "windows" } } : { ok: false, code: "CALLER_NOT_AUTHORIZED", error: "no" }));
    expect(ready).toMatchObject({ state: "ready", custodian: { version: "0.3.0", protocol: 1 } });
    const busy = await statusWith(async () => {
      throw new CustodianBusy("the pipe stayed busy", "not_delivered", 12_000);
    });
    expect(busy.state).toBe("busy");
    expect(busy.explanation.join(" ")).toContain(BUSY_LIMITATION);
    const squat = await statusWith(async () => {
      throw new CustodianNotTrusted("the pipe's owner is not the custodian");
    });
    expect(squat.state).toBe("untrusted");
    const other = await statusWith(async () => ({ ok: true, data: { pong: true, protocol: 2 } }));
    expect(other.state).toBe("incompatible");
    const oldEngine = await statusWith(async () => ({ ok: false, code: "MALFORMED_REQUEST", error: "unsupported protocol version 1: this custodian speaks protocol 2; install …" }));
    expect(oldEngine.state).toBe("incompatible");
    const stopped = await statusWith(async () => {
      throw new CustodianUnavailable("no pipe", "not_delivered");
    }, "registered", "STOPPED");
    expect(stopped.state).toBe("stopped");
    expect(stopped.explanation[0]).toContain("sc.exe start CodeParleyCustodian");
    const absent = await statusWith(async () => {
      throw new Error("not called");
    }, "absent", null);
    expect(absent).toMatchObject({ state: "not_installed", surfaces: [] });
    expect(absent.next[0]).toMatch(/codeparley-installer\.ps1 install/);
  });
});

describe("Phase 6 Increment 3 — the repository's records as status names them", () => {
  const rt = { runtimeId: "rt-1", globalRevision: 1, recordedAt: "t", root: "C:\\gone\\engine", gitRelative: null, gitPath: "C:\\git.exe", entryRelative: "dist/helper/main.js", nodeSha256: "a".repeat(64), gitSha256: "b".repeat(64), entrySha256: "c".repeat(64), treeDigest: "d".repeat(64), fileCount: 10, totalBytes: 100, revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true };
  const section = (over: Partial<ConfigSection> = {}): ConfigSection => ({ globalRevision: 1, repository: null, acceptances: [], selftestConfirmations: [], engineRuntime: rt, ...over });
  const g = (over: Partial<GrantSummary>): GrantSummary => ({ grantId: "g1", repoKey: "k", repositoryRoot: "C:\\r", identity: "x", loopsUsed: 0, loopsTotal: 2, expiresAt: new Date(Date.now() + 60_000).toISOString(), revoked: false, suspended: false, active: true, assurance: "L1", ...over });
  const recs = (grants: GrantSummary[] | null, exists = true, platform: NodeJS.Platform = "win32", home: string | null = null, repoKey: string | null = "k") =>
    repositoryRecords({ platform, root: "C:\\r", repoKey, section: section(), grants, hashFile: async () => null, nowMs: Date.now(), exists: async () => exists, implementerHome: home });
  const of = async (p: ReturnType<typeof recs>, name: string) => (await p).find((r) => r.record === name)!;

  it("an approved runtime whose directory an upgrade removed is changed, not in force", async () => {
    expect(await of(recs([], true), "engine_runtime")).toMatchObject({ state: "in_force", restore: null });
    expect(await of(recs([], false), "engine_runtime")).toMatchObject({ state: "changed", resumable: true, restore: expect.stringContaining("setup --resume --repo C:\\r --runtime <the installed engine directory> --runtime-git-path") });
  });

  it("Windows: an upgrade that kept the approved version's directory is changed (VERIFIED on the Windows VM: vm.16 stayed approved after vm.18)", async () => {
    const at = (installed: string | null) =>
      repositoryRecords({ platform: "win32", root: "C:\\r", repoKey: "k", section: section({ engineRuntime: { ...rt, root: "C:\\Program Files\\CodeParley\\engine\\0.4.0-vm.16" } }), grants: [], hashFile: async () => null, nowMs: Date.now(), exists: async () => true, builtAt: async () => null, installedRuntime: async () => installed });
    // Paths compare without case on Windows.
    expect(await of(at("c:\\program files\\codeparley\\engine\\0.4.0-VM.16"), "engine_runtime")).toMatchObject({ state: "in_force" });
    expect(await of(at(null), "engine_runtime")).toMatchObject({ state: "in_force" });
    // setup defaults --runtime to the installed directory, so the restore names only the git.
    expect(await of(at("C:\\Program Files\\CodeParley\\engine\\0.4.0-vm.18"), "engine_runtime")).toMatchObject({ state: "changed", detail: expect.stringContaining("0.4.0-vm.18"), restore: "code-parley setup --resume --repo C:\\r --runtime-git-path <installed git.exe>" });
  });

  it("an engine at the approved path built after the approval (reinstalled in place) is changed — before lapsed", async () => {
    const at = (builtAt: number | null, lapsed = false) =>
      repositoryRecords({ platform: "linux", root: "/home/i/r", repoKey: "k", section: section({ engineRuntime: { ...rt, root: "/opt/codeparley/engine/0.4.0", recordedAt: "2026-10-29T10:00:00.000Z", lapsed, usable: !lapsed } }), grants: [], hashFile: async () => null, nowMs: Date.now(), exists: async () => true, builtAt: async () => builtAt, installedRuntime: async () => "/opt/codeparley/engine/0.4.0" });
    expect(await of(at(Date.parse("2026-10-29T09:00:00Z")), "engine_runtime")).toMatchObject({ state: "in_force" });
    expect(await of(at(null), "engine_runtime")).toMatchObject({ state: "in_force" });
    // On Linux setup approves what `current` names by default: the restore names no directory.
    expect(await of(at(Date.parse("2026-10-29T11:00:00Z")), "engine_runtime")).toMatchObject({ state: "changed", restore: "/usr/local/sbin/code-parley-operator setup --resume --repo /home/i/r" });
    // Upgraded AND rebooted: approved anew, never re-confirmed (the custodian would refuse the re-confirmation).
    expect(await of(at(Date.parse("2026-10-29T11:00:00Z"), true), "engine_runtime")).toMatchObject({ state: "changed" });
  });

  it("Linux: `current` naming another version than the approved one (an upgrade keeps the previous directory) is changed", async () => {
    // VERIFIED on the Ubuntu VM: the custodian measures without following links, so `current` itself is never the approved root.
    const at = (installed: string | null, lapsed = false) =>
      repositoryRecords({ platform: "linux", root: "/home/i/r", repoKey: "k", section: section({ engineRuntime: { ...rt, root: "/opt/codeparley/engine/0.4.0", recordedAt: "2026-10-29T10:00:00.000Z", lapsed, usable: !lapsed } }), grants: [], hashFile: async () => null, nowMs: Date.now(), exists: async () => true, builtAt: async () => null, installedRuntime: async () => installed });
    expect(await of(at("/opt/codeparley/engine/0.4.0"), "engine_runtime")).toMatchObject({ state: "in_force" });
    expect(await of(at(null), "engine_runtime")).toMatchObject({ state: "in_force" });
    expect(await of(at("/opt/codeparley/engine/0.5.0"), "engine_runtime")).toMatchObject({ state: "changed", resumable: true, detail: expect.stringContaining("the installed engine runtime is /opt/codeparley/engine/0.5.0"), restore: "/usr/local/sbin/code-parley-operator setup --resume --repo /home/i/r" });
    expect(await of(at("/opt/codeparley/engine/0.5.0", true), "engine_runtime")).toMatchObject({ state: "changed" });
  });

  it("the grant: in force, suspended by a restart, used up, expired, missing — or unknown when it could not be listed", async () => {
    expect(await of(recs([g({})]), "loop_grant")).toMatchObject({ state: "in_force" });
    expect(await of(recs([g({ active: false, suspended: true })]), "loop_grant")).toMatchObject({ state: "suspended", resumable: true });
    expect(await of(recs([g({ active: false, loopsUsed: 2 })]), "loop_grant")).toMatchObject({ state: "used_up" });
    expect(await of(recs([g({ active: false, expiresAt: new Date(0).toISOString() })]), "loop_grant")).toMatchObject({ state: "expired" });
    expect(await of(recs([g({ repoKey: "other", repositoryRoot: "C:\\other" })]), "loop_grant")).toMatchObject({ state: "missing", resumable: false });
    expect(await of(recs(null), "loop_grant")).toMatchObject({ state: "missing", detail: expect.stringContaining("could not be listed") });
  });

  it("F-S71-1: a grant is the directory's by the identity the custodian resolved it to, never by its path", async () => {
    // The same identity under another recorded spelling or location: the custodian authorizes it, so it is in force.
    expect(await of(recs([g({ repositoryRoot: "C:\\moved" })]), "loop_grant")).toMatchObject({ state: "in_force" });
    // Windows paths compare without case, but only for the display: a grant at "c:\R" for another identity is not ours.
    for (const at of ["C:\\r", "c:\\R"]) {
      const stale = await of(recs([g({ grantId: "old", repoKey: "replaced", repositoryRoot: at })]), "loop_grant");
      expect(stale).toMatchObject({ state: "missing", resumable: true, restore: "code-parley setup --repo C:\\r --loops <1-8> --minutes <1-180>" });
      expect(stale.detail).toMatch(/grant old was made for another directory at this path \(identity replaced; this directory is k\): it does not authorize loops here/);
    }
    // The current directory's own grant wins over an old one at the same path.
    expect(await of(recs([g({ grantId: "old", repoKey: "replaced" }), g({ grantId: "new" })]), "loop_grant")).toMatchObject({ state: "in_force", detail: expect.stringContaining("grant new") });
    // This directory's own grant, used up, is reported as such even while a replaced directory's grant is still active.
    expect(await of(recs([g({ grantId: "old", repoKey: "replaced" }), g({ grantId: "new", active: false, loopsUsed: 2 })]), "loop_grant")).toMatchObject({ state: "used_up" });
    // An old grant at the path that is no longer active is not presented as a replaced directory's authority.
    expect(await of(recs([g({ repoKey: "replaced", active: false, expiresAt: new Date(0).toISOString() })]), "loop_grant")).toMatchObject({ state: "missing", detail: expect.stringContaining("no loop is granted") });
    // A legacy grant (before P3.4C-0) is never active: never in force, never offered as this directory's.
    expect(await of(recs([g({ repoKey: "C:\\r", identity: "legacy_text", active: false })]), "loop_grant")).toMatchObject({ state: "missing", detail: expect.stringContaining("no loop is granted") });
  });

  it("F-S71-1: without the custodian's identity of the directory (an older custodian) no grant is shown as in force", async () => {
    expect(await of(recs([g({})], true, "win32", null, null), "loop_grant")).toMatchObject({ state: "missing", resumable: false, detail: expect.stringContaining("did not report this directory's identity") });
    expect(await of(recs([g({ repositoryRoot: "C:\\elsewhere" })], true, "win32", null, null), "loop_grant")).toMatchObject({ state: "missing", detail: expect.stringContaining("no loop is granted") });
    // Attended runs need no grant: the repository's required records decide readiness, not the grant.
    const all = await recs([], true, "win32", null, null);
    expect(all.find((r) => r.record === "loop_grant")).toMatchObject({ required: false });
  });

  it("Windows: the commands that read the implementer's approvals name its data home", async () => {
    expect((await of(recs([], true, "win32", "C:\\Users\\cpimpl\\AppData\\Local\\CodeParley"), "repository")).restore).toBe('code-parley setup --repo C:\\r --home "C:\\Users\\cpimpl\\AppData\\Local\\CodeParley"');
    expect((await of(recs([]), "isolation")).restore).toContain(`--home "<the implementer's data home>"`);
    expect((await of(recs([], true, "linux"), "isolation")).restore).toMatch(/^the implementer: code-parley codex selftest, then code-parley config propose-selftest .* --proposal-file <file>$/);
  });
});

// ---------------------------------------------------------------------------
// End to end on the simulated custodian
// ---------------------------------------------------------------------------

/** The operator at an interactive terminal: "allow" for a grant, else `answer`. */
function terminal(answer = "confirm") {
  const io = operatorIo(answer);
  return { ...io, prompt: async (q: string) => (/"allow"/.test(q) ? (answer === "confirm" ? "allow" : answer) : answer) };
}

async function setupArgs(f: ContFixture): Promise<string[]> {
  return ["--codex", f.codexExe, "--backend", await fixtureBackend(f), "--runtime", await syntheticRuntime(f.scratch), "--runtime-git", SYNTHETIC_RUNTIME_GIT, "--loops", "1", "--minutes", "60"];
}

/** status as the implementer (the engine's own transport) — JSON. */
async function statusJson(f: ContFixture) {
  const io = operatorIo("");
  const code = await runCli(["status", "--repo", f.repo, "--json", "--home", f.dataHome, "--git", f.git], { ...io, engineTestHooks: f.le.env.testHooks! });
  return { code, s: JSON.parse(io.lines.join("\n")) as { state: string; repository: { state: string; read_on: string; records: { record: string; state: string; detail: string; restore: string | null }[] } } };
}

const states = (s: Awaited<ReturnType<typeof statusJson>>["s"]) => Object.fromEntries(s.repository.records.map((r) => [r.record, r.state]));

describe.skipIf(!supported)("Phase 6 Increment 3 — init + setup + status end to end (simulated custodian)", () => {
  it("a new repository: init, then setup with one typed confirmation per record → ready; a declined step records nothing further", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);

    // init (the implementer): the repository is already an allowed root here; the fix budget is written explicitly.
    const init = await cli(f, ["init", "--repo", f.repo], operatorIo(""));
    expect(init.code, init.err).toBe(0);
    expect(init.out).toContain("budgets.max_fixes_per_run = 0");
    expect(init.out).toMatch(/checks: approved/);
    // The operator's step names a real Windows path (the VM showed its separators lost).
    if (process.platform === "win32") expect(init.out).toMatch(/--runtime "[^"]+\\CodeParley\\engine\\<version>"/);
    expect(JSON.parse(await readFile(join(f.dataHome, "config.json"), "utf8"))).toMatchObject({ budgets: { max_fixes_per_run: 0 } });

    // Before setup: the implementer sees exactly what is missing (read on its own surface).
    const before = await statusJson(f);
    expect(before.code).toBe(1);
    expect(before.s).toMatchObject({ state: "ready", repository: { state: "misconfigured", read_on: "implementer" } });
    expect(states(before.s)).toEqual({ engine_runtime: "missing", repository: "missing", isolation: "missing", fix_confirmation: "missing", loop_grant: "missing" });

    // A declined first step: nothing is recorded, and setup says so.
    const declined = await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal("no"));
    expect(declined.code).toBe(2);
    expect(declined.out).toContain("Stopped: not confirmed. Nothing further was recorded");
    expect(f.custodian.snapshot().config.repositories).toHaveLength(0);

    // setup refuses without an interactive terminal (no flag skips a confirmation).
    const batch = await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], operatorIo("confirm", false));
    expect(batch.code).toBe(1);
    expect(batch.err).toMatch(/INTERACTIVE_TERMINAL_REQUIRED/);

    // The operator confirms each record the custodian renders.
    const io = terminal();
    let prompts = 0;
    const counted = { ...io, prompt: async (q: string) => (prompts++, io.prompt(q)) };
    const ok = await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], counted);
    expect(ok.code, ok.err).toBe(0);
    expect(ok.out).toMatch(/Step 1: approve the engine runtime/);
    expect(ok.out).toMatch(/Step 2: set the repository's protected configuration/);
    expect(ok.out).toMatch(/Step 3: confirm the stored S1 self-test/);
    expect(ok.out).toMatch(/Step 4: grant automated loops/);
    expect(ok.out).toContain("is set up for protected runs");
    expect(prompts).toBe(4); // one typed confirmation per rendered record, no more
    const after = await statusJson(f);
    expect(after.code).toBe(0);
    expect(after.s.repository.state).toBe("ready");

    // Running setup again records nothing.
    const again = await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal());
    expect(again.code).toBe(0);
    expect(again.out).toContain("Nothing needed recording");
  }, 240_000);

  it("after a restart of the OS status names exactly the lapsed records, and setup --resume restores them; after a Codex update the repository record is changed", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);

    f.custodian.simulateRecoveryAfterNewBoot();
    const lapsed = await statusJson(f);
    expect(lapsed.s.repository.state).toBe("misconfigured");
    // Exactly the records that were in force: lapsed (or, for the grant, suspended); what was never set stays missing.
    expect(states(lapsed.s)).toEqual({ engine_runtime: "lapsed", repository: "lapsed", isolation: "lapsed", fix_confirmation: "missing", loop_grant: "suspended" });
    for (const r of lapsed.s.repository.records.filter((x) => x.state === "lapsed")) expect(r.restore).toContain("setup --resume --repo");

    // --resume: one re-confirmation (the repository with every global record that lapsed with it), then a new grant.
    const resumed = await cli(f, ["setup", "--resume", "--repo", f.repo, "--loops", "1", "--minutes", "60"], terminal());
    expect(resumed.code, resumed.err).toBe(0);
    expect(resumed.out).toMatch(/Step 1: re-confirm the repository's configuration/);
    expect(resumed.out).toMatch(/Step 2: grant automated loops/);
    expect(resumed.out).not.toMatch(/Step 3:/);
    expect(states((await statusJson(f)).s)).toMatchObject({ engine_runtime: "in_force", repository: "in_force", isolation: "in_force", loop_grant: "in_force" });

    // A Codex update replaces the approved file: reported as changed, restored by setting the configuration again.
    if (process.platform === "win32") await writeFile(f.codexExe, minimalPe(7));
    else await copyFile("/bin/false", f.codexExe);
    const changed = await statusJson(f);
    expect(states(changed.s)).toMatchObject({ repository: "changed" });
    const reset = await cli(f, ["setup", "--resume", "--repo", f.repo, "--codex", f.codexExe, "--no-grant"], terminal());
    expect(reset.code, reset.err).toBe(0);
    expect(reset.out).toMatch(/Step 1: set the repository's protected configuration/);
    expect(states((await statusJson(f)).s)).toMatchObject({ repository: "in_force" });
  }, 240_000);

  it("F-S71-1: a repository directory replaced at the same path is another directory: status names the old grant as another directory's, setup grants anew, and the new grant opens a run and is consumed", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    expect(states((await statusJson(f)).s)).toMatchObject({ repository: "in_force", loop_grant: "in_force" });
    const oldGrant = f.custodian.snapshot().grants[0]!;

    // The directory is replaced: the same path, the same content, another directory (the custodian's identity).
    await rename(f.repo, `${f.repo}-old`);
    await cp(`${f.repo}-old`, f.repo, { recursive: true });
    const after = await statusJson(f);
    const grant = after.s.repository.records.find((r) => r.record === "loop_grant")!;
    // Neither the old directory's configuration nor its grant is this directory's.
    expect(states(after.s)).toMatchObject({ repository: "missing", loop_grant: "missing" });
    expect(grant.detail).toContain(`grant ${oldGrant.grantId} was made for another directory at this path`);
    expect(grant.restore).toMatch(/setup --repo .* --loops <1-8> --minutes <1-180>/);

    // The custodian's refusal is unchanged: the old grant opens no run for the new directory.
    const OPEN = { runJsonDigest: "a".repeat(64), budgets: { maxReviews: 5, maxCheckExecutions: 50 }, baseline: null };
    f.custodian.seedConfig(f.repo); // its configuration in force, so only the grant decides
    const refused = await new CustodianRuns(f.custodian).transition("implementer", { repositoryRoot: f.repo, runId: "run-replaced" }, "open", OPEN);
    expect(refused).toMatchObject({ ok: false, code: "LOOP_NOT_AUTHORIZED" });

    // setup offers (and records) a new grant for the directory that is there now.
    const regrant = await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal());
    expect(regrant.code, regrant.err).toBe(0);
    expect(regrant.out).toMatch(/Step \d+: grant automated loops/);
    const fresh = f.custodian.snapshot().grants.at(-1)!;
    expect(fresh.repoKey).not.toBe(oldGrant.repoKey);
    expect(states((await statusJson(f)).s)).toMatchObject({ loop_grant: "in_force" });

    // The new grant opens a run and its one loop is consumed; then nothing is left.
    const opened = await new CustodianRuns(f.custodian).transition("implementer", { repositoryRoot: f.repo, runId: "run-new" }, "open", OPEN);
    expect(opened.ok).toBe(true);
    await new CustodianGrants(f.custodian).consume(f.repo, "run-new");
    expect(states((await statusJson(f)).s)).toMatchObject({ loop_grant: "used_up" });
  }, 240_000);
});
