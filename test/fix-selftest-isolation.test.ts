import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { sha256OfBytes } from "../src/common/hash.js";
import { readFileSync } from "node:fs";
import { fixExecArgv, fixProfileDigest, FIX_PROFILE_NAME, type FixProfileInput } from "../src/agents/codex/fix-profile.js";
import { UnsafeArgvError, type SandboxBackend } from "../src/agents/codex/argv.js";
import { runFixSelfTest, storeFixSelfTest, fixSelfTestKey, type FixSelfTestOptions } from "../src/agents/codex/fix-selftest.js";
import { decideFixIsolation } from "../src/agents/codex/fix-isolation.js";
import { launchFixer } from "../src/agents/codex/fix-launcher.js";
import type { SelfTestDeps } from "../src/agents/codex/selftest.js";
import type { CodexProbe } from "../src/agents/codex/probe.js";
import type { FixSelfTestRecord } from "../src/schemas/review.js";

const WIN = process.platform === "win32";
/** Phase 5 Increment 3: the platform's fixer backend (Windows mxc; Linux bwrap, whose grants are POSIX paths). */
const BACKEND: SandboxBackend = WIN ? "mxc" : "bwrap";
const INSTALL = WIN ? "C:\\Program Files\\Codex\\0.160.0" : "/opt/codex/0.160.0";
const base = (dirs: string[]): FixProfileInput => ({ backend: BACKEND, installDir: INSTALL, writableDirs: dirs, protectedPaths: [WIN ? "C:\\Users\\x\\.codex" : "/home/x/.codex"] });

describe("fixProfileDigest is a stable structural identity", () => {
  it("is independent of the concrete disposable-workspace paths", () => {
    const a = fixProfileDigest(base([WIN ? "C:\\w1\\tree" : "/w1/tree", WIN ? "C:\\w1\\scratch" : "/w1/scratch"]));
    const b = fixProfileDigest(base([WIN ? "C:\\w2\\other\\tree" : "/w2/other/tree", WIN ? "C:\\w2\\other\\scratch" : "/w2/other/scratch"]));
    expect(a).toBe(b);
  });
  it("is independent of the install dir path (the binary is bound by codex_sha256, not this digest)", () => {
    const a = fixProfileDigest(base([WIN ? "C:\\w\\tree" : "/w/tree", WIN ? "C:\\w\\scratch" : "/w/scratch"]));
    const other: FixProfileInput = { ...base([WIN ? "C:\\w\\tree" : "/w/tree", WIN ? "C:\\w\\scratch" : "/w/scratch"]), installDir: WIN ? "C:\\Other\\Codex" : "/other/codex" };
    expect(fixProfileDigest(other)).toBe(a);
  });
  it("changes with the number of writable grants and the backend", () => {
    const one = fixProfileDigest(base([WIN ? "C:\\w\\tree" : "/w/tree"]));
    const two = fixProfileDigest(base([WIN ? "C:\\w\\tree" : "/w/tree", WIN ? "C:\\w\\scratch" : "/w/scratch"]));
    expect(one).not.toBe(two);
  });
});

describe("fixExecArgv: a safe writable launch argv", () => {
  const i = { ...base([WIN ? "C:\\w\\tree" : "/w/tree", WIN ? "C:\\w\\scratch" : "/w/scratch"]), cwd: WIN ? "C:\\w\\tree" : "/w/tree", lastMessagePath: WIN ? "C:\\w\\last.txt" : "/w/last.txt" };
  it("selects the cp_fix profile and reads the prompt from stdin, never emitting a forbidden mode/flag", () => {
    const argv = fixExecArgv(i);
    expect(argv[0]).toBe("exec");
    expect(argv).toContain(`default_permissions="${FIX_PROFILE_NAME}"`);
    expect(argv[argv.length - 1]).toBe("-");
    const joined = argv.join(" ");
    expect(joined).not.toContain("workspace-write");
    expect(joined).not.toContain("danger-full-access");
    expect(joined).not.toContain("--add-dir");
    expect(joined).not.toContain("--worktree");
    expect(joined).not.toContain("--dangerously-bypass");
    // the write grant lives only in the permission profile
    expect(joined).toContain('="write"');
  });
  it("refuses a model name with shell-significant characters", () => {
    expect(() => fixExecArgv({ ...i, model: "a b; rm -rf" })).toThrow(UnsafeArgvError);
  });
  it("refuses a write grant that overlaps a protected path (fail closed, before any process)", () => {
    const bad: FixProfileInput & { cwd: string; lastMessagePath: string } = {
      backend: BACKEND,
      installDir: INSTALL,
      writableDirs: [WIN ? "C:\\Users\\x\\.codex\\w" : "/home/x/.codex/w"],
      protectedPaths: [WIN ? "C:\\Users\\x\\.codex" : "/home/x/.codex"],
      cwd: WIN ? "C:\\Users\\x\\.codex\\w" : "/home/x/.codex/w",
      lastMessagePath: WIN ? "C:\\w\\last.txt" : "/w/last.txt",
    };
    expect(() => fixExecArgv(bad)).toThrow(UnsafeArgvError);
  });
});

function matchingRecord(digest: string): FixSelfTestRecord {
  return {
    schema: "arl.codex-fix-selftest.v1",
    selftest_id: "ft-1",
    key: "a".repeat(64),
    codex_version: "0.160.0",
    codex_sha256: "b".repeat(64),
    backend: BACKEND,
    profile_digest: digest,
    created_at: "2026-10-19T00:00:00.000Z",
    profile_runs: true,
    rejection_reason: null,
    rows: [{ name: "write_in_workspace_tree", expectation: "allowed", sandbox: "wrote", positive_control: "n/a", pass: true, detail: "" }],
    confinement_available: true,
    complete: true,
  };
}

describe("decideFixIsolation: fail-closed launch gate", () => {
  const profile = base([WIN ? "C:\\w\\tree" : "/w/tree", WIN ? "C:\\w\\scratch" : "/w/scratch"]);
  const digest = fixProfileDigest(profile);
  const good = { codexVersion: "0.160.0", codexSha256: "b".repeat(64), backend: BACKEND, profile };

  it("accepts a complete, matching, confinement-available record", () => {
    const d = decideFixIsolation({ ...good, record: matchingRecord(digest) });
    expect(d.ok).toBe(true);
  });
  it("refuses when there is no record", () => {
    const d = decideFixIsolation({ ...good, record: null });
    expect(d.ok).toBe(false);
  });
  it("refuses a version mismatch", () => {
    const d = decideFixIsolation({ ...good, record: { ...matchingRecord(digest), codex_version: "0.161.0" } });
    expect(d.ok).toBe(false);
  });
  it("refuses a binary (SHA-256) mismatch", () => {
    const d = decideFixIsolation({ ...good, record: { ...matchingRecord(digest), codex_sha256: "c".repeat(64) } });
    expect(d.ok).toBe(false);
  });
  it("refuses a profile-digest mismatch", () => {
    const d = decideFixIsolation({ ...good, record: { ...matchingRecord(digest), profile_digest: "d".repeat(64) } });
    expect(d.ok).toBe(false);
  });
  it("refuses an incomplete record and a record whose confinement is unavailable", () => {
    expect(decideFixIsolation({ ...good, record: { ...matchingRecord(digest), complete: false } }).ok).toBe(false);
    expect(decideFixIsolation({ ...good, record: { ...matchingRecord(digest), confinement_available: false } }).ok).toBe(false);
  });
});

// A deterministic, offline fake Codex: in-workspace writes succeed, everything outside is denied, network
// blocked, a child write outside denied. This exercises runFixSelfTest end to end without a real Codex.
function fakeDeps(outsideWrites: "denied" | "wrote"): SelfTestDeps {
  return WIN ? windowsFakeDeps(outsideWrites) : linuxFakeDeps(outsideWrites);
}

/** Linux (Phase 5 Increment 3): a fake bwrap sandbox that performs a probe's write on the host exactly when the grant (or
 * the simulated leak) allows it — the Linux self-test judges the host, not the token — and reports an own user
 * namespace with no capability, the installation's own bwrap running in this process's tree. */
function linuxFakeDeps(outsideWrites: "denied" | "wrote"): SelfTestDeps {
  const bwrap = { path: "/opt/codex/0.160.0/codex-resources/bwrap", sha256: "e".repeat(64) };
  return {
    runCodex: async (argv) => {
      const script = String(argv[argv.length - 1] ?? "");
      if (script === "printf ALIVE") return { status: 0, stdout: "ALIVE", stderr: "" };
      if (script.includes("/dev/tcp/")) return { status: 0, stdout: "NET_FAIL:blocked", stderr: "" };
      if (script.includes("getent hosts")) return { status: 0, stdout: "DNS_FAIL:exit 2", stderr: "" };
      if (script.includes("CAPEFF")) return { status: 0, stdout: "CAPEFF=0000000000000000;USERNS=user:[4026599999];", stderr: "" };
      if (script.includes("unshare -rm")) return { status: 0, stdout: "UNSHARE_FAIL:Operation not permitted", stderr: "" };
      const m = /(\/[^'\s]+\.txt)/.exec(script); // the probe's one absolute target (also inside a nested, quoted script)
      const target = m?.[1] ?? "";
      const inWorkspace = target.includes("/tree/") || target.includes("/scratch/");
      const allowed = inWorkspace || (outsideWrites === "wrote" && !target.startsWith("/var/lib/") && !target.startsWith("/run/"));
      const child = script.startsWith("printf 'CHILD:'");
      if (allowed) writeFileSync(target, "arl");
      return { status: 0, stdout: `${child ? "CHILD:" : ""}${allowed ? "WRITE_OK" : "WRITE_FAIL:Read-only file system"}`, stderr: "" };
    },
    runPowerShell: async (script) => {
      if (script.includes("/dev/tcp/")) return { status: 0, stdout: "NET_OK", stderr: "" };
      if (script.includes("getent hosts")) return { status: 0, stdout: "DNS_OK:1.1.1.1 one.one.one.one", stderr: "" };
      if (script.includes("unshare -rm")) return { status: 0, stdout: "UNSHARE_FAIL:Operation not permitted", stderr: "" };
      return { status: 0, stdout: "", stderr: "" };
    },
    grantUsersRead: async () => true,
    bwrap: { installed: async () => bwrap, running: async () => [{ pid: 4242, ...bwrap }] },
  };
}

function windowsFakeDeps(outsideWrites: "denied" | "wrote"): SelfTestDeps {
  return {
    runCodex: async (argv) => {
      const script = String(argv[argv.length - 1] ?? "");
      if (script.includes("'ALIVE'")) return { status: 0, stdout: "ALIVE", stderr: "" };
      if (script.includes("TcpClient")) return { status: 0, stdout: "NET_FAIL:blocked", stderr: "" };
      if (script.includes("GetHostAddresses")) return { status: 0, stdout: "DNS_FAIL:blocked", stderr: "" };
      if (script.includes("ProcessStartInfo")) return { status: 0, stdout: "CHILD:WRITE_FAIL:UnauthorizedAccess", stderr: "" };
      const m = /LiteralPath '([^']+)'/.exec(script);
      const target = m?.[1] ?? "";
      const inWorkspace = target.includes(`${sep}tree${sep}`) || target.includes(`${sep}scratch${sep}`);
      if (inWorkspace) return { status: 0, stdout: "WRITE_OK", stderr: "" };
      return { status: 0, stdout: outsideWrites === "wrote" ? "WRITE_OK" : "WRITE_FAIL:UnauthorizedAccess", stderr: "" };
    },
    runPowerShell: async (script) => {
      if (script.includes("TcpClient")) return { status: 0, stdout: "NET_OK", stderr: "" };
      if (script.includes("GetHostAddresses")) return { status: 0, stdout: "DNS_OK:1.1.1.1", stderr: "" };
      return { status: 0, stdout: "", stderr: "" };
    },
    grantUsersRead: async () => true,
  };
}

describe("runFixSelfTest (offline, fake Codex)", () => {
  let dataHome: string;
  let codexExe: string;
  let probe: CodexProbe;
  beforeAll(() => {
    dataHome = mkdtempSync(join(tmpdir(), "cp-fixst-"));
    codexExe = join(dataHome, "codex.exe");
    writeFileSync(codexExe, "fake-codex-binary");
    probe = {
      launcher: { exe: codexExe, file: codexExe, prefixArgs: [] },
      how: "test",
      version: "0.160.0",
      versionRaw: "codex-cli 0.160.0",
      compat: { versionPrefix: "0.160.", webSearchDisabledValue: "disabled", backends: {} } as CodexProbe["compat"],
      installDir: INSTALL,
      missingFlags: [],
      codexHome: join(dataHome, "codexhome"),
      userHooksPresent: false,
    };
  });
  afterAll(() => rmSync(dataHome, { recursive: true, force: true }));

  const opts = (deps: SelfTestDeps): FixSelfTestOptions => ({ probe, backend: BACKEND, dataHome, deps, env: { PATH: process.env["PATH"] ?? "" }, now: () => "2026-10-19T00:00:00.000Z" });

  it("reports confinement available when in-workspace writes pass and all outside writes are denied", async () => {
    const rec = await runFixSelfTest(opts(fakeDeps("denied")));
    expect(rec.profile_runs).toBe(true);
    expect(rec.confinement_available).toBe(true);
    expect(rec.codex_sha256).toBe(sha256OfBytes(readFileSync(codexExe)));
    expect(rec.rows.some((r) => r.name.startsWith("write_in_workspace_") && r.pass)).toBe(true);
    expect(rec.rows.filter((r) => r.name.startsWith("write_outside_")).every((r) => r.pass)).toBe(true);
    // Linux (§4.12): the userns rows of S1, and the record names the boot, the Codex binary and the bundled bwrap.
    if (!WIN) {
      expect(rec.rows.map((r) => r.name)).toEqual(expect.arrayContaining(["userns_via_approved_profile", "restriction_effective_outside_profile", "nested_userns_noted", "write_outside_store", "write_outside_run_codeparley", "write_outside_home", "write_outside_temp", "child_process_write_outside"]));
      expect(rec.codex_path).toBe(codexExe);
      expect(rec.bwrap_sha256).toBe("e".repeat(64));
    }
  });

  it("reports confinement UNAVAILABLE when an out-of-workspace write succeeds (a leak)", async () => {
    const rec = await runFixSelfTest(opts(fakeDeps("wrote")));
    expect(rec.confinement_available).toBe(false);
    expect(rec.rows.filter((r) => r.name.startsWith("write_outside_")).some((r) => !r.pass)).toBe(true);
  });

  describe("launchFixer: gated fail-closed, then bounded launch", () => {
    const tree = () => join(dataHome, "ws", "tree");
    const scratch = () => join(dataHome, "ws", "scratch");
    const launchProfile = () => ({ backend: BACKEND, installDir: INSTALL, writableDirs: [tree(), scratch()], protectedPaths: [probe.codexHome] });

    it("refuses to launch (CODEX_ISOLATION_UNAVAILABLE) when there is no stored cp_fix self-test — nothing runs", async () => {
      let ran = false;
      const run = (async () => { ran = true; return {} as never; }) as never;
      await expect(
        launchFixer({ probe, backend: BACKEND, workspaceTree: tree(), workspaceScratch: scratch(), lastMessagePath: join(dataHome, "ws", "last.txt"), prompt: "fix it", selftestDir: join(dataHome, "selftest-none"), protectedPaths: [probe.codexHome], run }),
      ).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
      expect(ran).toBe(false);
    });

    it("launches the cp_fix exec (through the bounded runner) only after a matching passing self-test gates it", async () => {
      const selftestDir = join(dataHome, "selftest-ok");
      const sha = sha256OfBytes(readFileSync(codexExe));
      const profile = launchProfile();
      const rec: FixSelfTestRecord = {
        schema: "arl.codex-fix-selftest.v1",
        selftest_id: "ft-ok",
        key: fixSelfTestKey("0.160.0", sha, profile),
        codex_version: "0.160.0",
        codex_sha256: sha,
        backend: BACKEND,
        profile_digest: fixProfileDigest(profile),
        created_at: "2026-10-19T00:00:00.000Z",
        profile_runs: true,
        rejection_reason: null,
        rows: [{ name: "write_in_workspace_tree", expectation: "allowed", sandbox: "wrote", positive_control: "n/a", pass: true, detail: "" }],
        confinement_available: true,
        complete: true,
      };
      await storeFixSelfTest(selftestDir, rec);
      let seenArgv: readonly string[] = [];
      const run = (async (r: { argv: readonly string[] }) => { seenArgv = r.argv; return { outcome: { status: "completed" } } as never; }) as never;
      await launchFixer({ probe, backend: BACKEND, workspaceTree: tree(), workspaceScratch: scratch(), lastMessagePath: join(dataHome, "ws", "last.txt"), prompt: "fix it", selftestDir, protectedPaths: [probe.codexHome], env: { PATH: process.env["PATH"] ?? "" }, run });
      expect(seenArgv[0]).toBe("exec");
      expect(seenArgv).toContain(`default_permissions="${FIX_PROFILE_NAME}"`);
      expect(seenArgv.join(" ")).not.toContain("workspace-write");
    });
  });
});
