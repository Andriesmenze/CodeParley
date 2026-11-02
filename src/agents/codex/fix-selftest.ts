// Phase 4 Increment 1 — the offline self-test of the WRITABLE `cp_fix` fixer profile (contract
// plans/P4-delegated-fixes-contract.md §5; D-20). No model call.
//
// This is the writable-profile counterpart of the read-only S1 reviewer self-test (selftest.ts). It runs
// `codex sandbox -P cp_fix` with EXACTLY the flags a fixer launch uses (fix-profile.ts `fixIsolationFlags`)
// and checks, each paired with a positive control outside the sandbox:
//   - the in-workspace `tree`/`scratch` writes are ALLOWED (the positive controls that prove the writable
//     grant is effective — without them an "all denied" result would be meaningless);
//   - every out-of-workspace write (a sibling of the tree, the data home, %TEMP%, the user profile, a
//     primary-worktree canary), a sandboxed child-command write, and the network are DENIED/blocked.
// Confinement is available only when the profile runs, the in-workspace writes succeed, and every outside
// row is denied with a successful positive control and none is inconclusive. A `:root`/write-to-protected
// grant is never emitted (fix-profile.ts refuses it).
//
// The record binds the exact approved Codex binary (`codex_sha256`), its version, the backend and the
// fixer profile digest; the key includes all of them, so swapping the binary, bumping the version or
// changing the profile re-runs the self-test and, until it passes again, a fixer launch fails closed
// (fix-isolation.ts). The NATIVE-edit OS confinement that this profile's writes rely on was established
// separately by the Option B instrumented VM evidence (results/P4-increment-1-fix-confinement-addendum.md,
// P4-INC1-NATIVE-EDIT-CONFINEMENT-SCOPED-PASS); this self-test binds the profile those findings apply to.

import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { sha256OfBytes, sha256OfCanonicalJson } from "../../common/hash.js";
import { uuidv7 } from "../../common/ids.js";
import { readFile } from "node:fs/promises";
import { atomicWriteFile, readTextIfExists } from "../../store/atomic.js";
import { buildChildEnv } from "../../process/env.js";
import { isNoDesktopExit, NO_DESKTOP_REMEDY, NO_DESKTOP_SESSION } from "./isolation.js";
import { FixSelfTestRecordSchema, type FixSelfTestRecord, type SelfTestRow } from "../../schemas/review.js";
import { FIX_PROFILE_NAME, fixProfileDigest, fixSandboxArgv, type FixProfileInput } from "./fix-profile.js";
import { classifyRead, defaultSelfTestDeps, linuxBootId, LINUX_DNS_SCRIPT, LINUX_PROBE_SHELL, LINUX_TCP_SCRIPT, linuxUsernsRows, linuxWriteScript, powershellExe, REAL_BWRAP, sha256OfFile, shq, type SandboxRunResult, type SelfTestDeps } from "./selftest.js";
import type { CodexProbe } from "./probe.js";
import { grantRulesOf, type SandboxBackend } from "./argv.js";
import { existsSync } from "node:fs";

const NET_IP = "1.1.1.1";
const NET_PORT = 443;
const DNS_NAME = "example.com";

const psq = (p: string) => p.replace(/'/g, "''");
const writeScript = (p: string) =>
  `try { Set-Content -LiteralPath '${psq(p)}' -Value 'cp_fix_probe' -ErrorAction Stop; [Console]::Out.Write('WRITE_OK') } ` +
  `catch { [Console]::Out.Write('WRITE_FAIL:' + $_.Exception.GetType().Name + ':' + $_.Exception.Message) }`;
const TCP_SCRIPT =
  `try { $c=[System.Net.Sockets.TcpClient]::new(); $c.Connect('${NET_IP}',${NET_PORT}); [Console]::Out.Write('NET_OK'); $c.Close() } ` +
  `catch { [Console]::Out.Write('NET_FAIL:' + $_.Exception.Message) }`;
const DNS_SCRIPT =
  `try { $a=[System.Net.Dns]::GetHostAddresses('${DNS_NAME}'); [Console]::Out.Write('DNS_OK:' + ($a -join ',')) } ` +
  `catch { [Console]::Out.Write('DNS_FAIL:' + $_.Exception.Message) }`;

/** The self-test key: version + binary SHA-256 + backend + fixer profile digest (any change re-runs it). */
export function fixSelfTestKey(codexVersion: string, codexSha256: string, i: FixProfileInput): string {
  return sha256OfCanonicalJson({
    schema: "codeparley.fix-selftest-key.v1",
    codex_version: codexVersion,
    codex_sha256: codexSha256,
    backend: i.backend,
    profile_digest: fixProfileDigest(i),
  });
}

export function fixSelfTestPath(selftestDir: string, key: string): string {
  return join(selftestDir, `fix-${key}.json`);
}

/** A stored fix self-test for exactly this version/binary/backend/profile, or null. */
export async function loadFixSelfTest(selftestDir: string, codexVersion: string, codexSha256: string, i: FixProfileInput): Promise<FixSelfTestRecord | null> {
  const key = fixSelfTestKey(codexVersion, codexSha256, i);
  const raw = await readTextIfExists(fixSelfTestPath(selftestDir, key));
  if (raw == null) return null;
  try {
    const rec = FixSelfTestRecordSchema.parse(JSON.parse(raw));
    return rec.complete && rec.key === key && rec.profile_digest === fixProfileDigest(i) && rec.codex_version === codexVersion && rec.codex_sha256 === codexSha256 ? rec : null;
  } catch {
    return null;
  }
}

export async function storeFixSelfTest(selftestDir: string, rec: FixSelfTestRecord): Promise<void> {
  if (!rec.complete) return;
  await mkdir(selftestDir, { recursive: true });
  await atomicWriteFile(fixSelfTestPath(selftestDir, rec.key), JSON.stringify(FixSelfTestRecordSchema.parse(rec), null, 2));
}

export interface FixSelfTestOptions {
  probe: CodexProbe;
  backend: SandboxBackend;
  dataHome: string;
  deps?: SelfTestDeps;
  env?: Record<string, string>;
  signal?: AbortSignal;
  now?: () => string;
}

export class FixSelfTestInterruptedError extends Error {
  constructor() {
    super("the cp_fix sandbox self-test was cancelled before it finished");
  }
}

/** Run the offline `cp_fix` writable-profile self-test and return the record (Windows mxc backends; Linux bwrap: the
 * port of contract §4.12, runLinuxFixSelfTest). */
export async function runFixSelfTest(o: FixSelfTestOptions): Promise<FixSelfTestRecord> {
  if (grantRulesOf(o.backend) === "posix") return runLinuxFixSelfTest(o);
  const env = o.env ?? buildChildEnv({ includeCodexAuth: true }).env;
  const deps = o.deps ?? defaultSelfTestDeps(o.probe, env);
  const codexBytes = await readFile(o.probe.launcher.exe).catch(() => null);
  const codexSha256 = codexBytes ? sha256OfBytes(codexBytes) : "0".repeat(64);
  // The self-test workspace is a disposable root under the OS temp dir — deliberately NOT the data home or
  // the user profile, so the writable grant does not overlap a protected tree (P4.0 §5: workspace location
  // is a separate product decision; the self-test only needs a disposable writable root to validate the
  // profile). The data-home / %TEMP% / user-profile DENIALS are still verified at runtime by the rows below.
  const work = join(tmpdir(), "cp-fix-selftest", randomBytes(6).toString("hex"));
  const tree = join(work, "tree");
  const scratch = join(work, "scratch");
  const control = join(work, "control"); // a CodeParley-only sibling of tree (not granted)
  const primaryCanary = join(work, "primary-canary"); // stands in for the primary worktree
  const userProfile = process.env["USERPROFILE"] ?? join(work, "user-profile-fallback");
  const codexHome = o.probe.codexHome;
  const profileInput: FixProfileInput = {
    backend: o.backend,
    installDir: o.probe.installDir,
    writableDirs: [tree, scratch],
    // The build-time check refuses a write grant that overlaps one of these sensitive trees. They are
    // siblings of (not ancestors of) the disposable workspace, so the grant is accepted; the runtime rows
    // then prove the OS confines writes to exactly tree/scratch.
    protectedPaths: [primaryCanary, codexHome].filter((p, idx, a) => a.indexOf(p) === idx),
  };
  const key = fixSelfTestKey(o.probe.version, codexSha256, profileInput);
  const digest = fixProfileDigest(profileInput);

  const rows: SelfTestRow[] = [];
  let incomplete = false;
  const guard = <T extends { incomplete?: boolean }>(r: T): T => {
    if (o.signal?.aborted) throw new FixSelfTestInterruptedError();
    if (r.incomplete) incomplete = true;
    return r;
  };
  const sb = async (script: string) =>
    guard(await deps.runCodex(fixSandboxArgv({ ...profileInput, cwd: tree, command: [powershellExe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script] }), tree, o.signal));
  const ps = async (script: string) => guard(await deps.runPowerShell(script, o.signal));
  const pcWrite = async (p: string): Promise<boolean> => {
    try {
      await writeFile(p, "pc");
      await rm(p, { force: true }).catch(() => undefined);
      return true;
    } catch {
      return false;
    }
  };

  try {
    for (const d of [tree, scratch, control, primaryCanary]) await mkdir(d, { recursive: true });

    // 0. Does the writable profile run on this backend at all?
    const alive = await sb("[Console]::Out.Write('ALIVE')");
    if (alive.status !== 0 || !alive.stdout.includes("ALIVE")) {
      if (isNoDesktopExit(alive.status)) return finish(false, `${NO_DESKTOP_SESSION}: the cp_fix profile could not start (exit 0xC0000142): this process has no interactive desktop session; ${NO_DESKTOP_REMEDY}`);
      const reason = `${alive.stderr}\n${alive.stdout}`.trim().split(/\r?\n/).slice(-2).join(" | ").slice(0, 500);
      return finish(false, reason || `exit ${String(alive.status)}`);
    }

    // In-workspace writes: ALLOWED (positive controls that prove the grant is effective).
    for (const [name, p] of [["tree", join(tree, "in-scope.txt")], ["scratch", join(scratch, "in-scope.txt")]] as const) {
      const out = (await sb(writeScript(p))).stdout;
      const wrote = out.includes("WRITE_OK");
      rows.push({ name: `write_in_workspace_${name}`, expectation: "allowed", sandbox: wrote ? "wrote" : "denied", positive_control: "n/a", pass: wrote, detail: out.trim().slice(0, 120) });
    }

    // Out-of-workspace writes: DENIED (positive control: the same write succeeds outside the sandbox).
    const outside: Record<string, string> = {
      control_sibling: join(control, "forged.txt"),
      primary_canary: join(primaryCanary, "src.txt"),
      data_home: join(o.dataHome, `fix-selftest-forged-${randomBytes(4).toString("hex")}.txt`),
      temp: join(process.env["TEMP"] ?? work, `cp-fix-selftest-${randomBytes(4).toString("hex")}.txt`),
      user_profile: join(userProfile, `cp-fix-selftest-${randomBytes(4).toString("hex")}.txt`),
    };
    for (const [name, p] of Object.entries(outside)) {
      const out = (await sb(writeScript(p))).stdout;
      const wrote = out.includes("WRITE_OK");
      const denied = out.includes("WRITE_FAIL");
      const pc = await pcWrite(p);
      await rm(p, { force: true }).catch(() => undefined);
      rows.push({ name: `write_outside_${name}`, expectation: "denied", sandbox: wrote ? "wrote" : denied ? "denied" : "unknown", positive_control: pc ? "ok" : "failed", pass: denied && !wrote && pc, inconclusive: !pc, detail: out.trim().slice(0, 120) });
    }

    // Network off (for sandboxed commands): blocked.
    for (const [name, script, okTok, failTok] of [
      ["net_tcp", TCP_SCRIPT, "NET_OK", "NET_FAIL"],
      ["net_dns", DNS_SCRIPT, "DNS_OK", "DNS_FAIL"],
    ] as const) {
      const out = (await sb(script)).stdout;
      const blocked = out.includes(failTok);
      const connected = out.includes(okTok);
      const pc = (await ps(script)).stdout.includes(okTok);
      rows.push({ name, expectation: "blocked", sandbox: connected ? "connected" : blocked ? "blocked" : "unknown", positive_control: pc ? "ok" : "failed", pass: blocked && !connected && pc, inconclusive: !pc, detail: out.trim().slice(0, 160) });
    }

    // A sandboxed child process writing outside the workspace: denied.
    {
      const childScript = join(tree, "_child-write.ps1");
      const target = join(primaryCanary, "via-child.txt");
      await writeFile(childScript, writeScript(target));
      const outer =
        `try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = '${psq(powershellExe())}'; ` +
        `$psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${psq(childScript)}"'; $psi.UseShellExecute = $false; ` +
        `$psi.RedirectStandardOutput = $true; $p = [System.Diagnostics.Process]::Start($psi); $o = $p.StandardOutput.ReadToEnd(); $p.WaitForExit(); [Console]::Out.Write('CHILD:' + $o.Trim()) } ` +
        `catch { [Console]::Out.Write('CHILD_ERR:' + $_.Exception.Message) }`;
      const out = (await sb(outer)).stdout.trim();
      await rm(childScript, { force: true }).catch(() => undefined);
      const wrote = out.includes("WRITE_OK");
      const denied = out.includes("WRITE_FAIL") || out.includes("CHILD_ERR");
      rows.push({ name: "child_process_write_outside", expectation: "denied", sandbox: wrote ? "wrote" : denied ? "denied" : "unknown", positive_control: "n/a", pass: denied && !wrote, detail: out.slice(0, 200) });
    }
    return finish(true, null);
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => undefined);
  }

  function finish(profileRuns: boolean, rejection: string | null): FixSelfTestRecord {
    const inWorkspaceOk = rows.filter((r) => r.name.startsWith("write_in_workspace_")).every((r) => r.pass) && rows.some((r) => r.name.startsWith("write_in_workspace_"));
    const confinement = !incomplete && profileRuns && inWorkspaceOk && rows.length > 0 && rows.every((r) => r.pass) && !rows.some((r) => r.inconclusive);
    return FixSelfTestRecordSchema.parse({
      schema: "arl.codex-fix-selftest.v1",
      selftest_id: uuidv7(),
      key,
      codex_version: o.probe.version,
      codex_sha256: codexSha256,
      backend: o.backend,
      profile_digest: digest,
      created_at: (o.now ?? (() => new Date().toISOString()))(),
      profile_runs: profileRuns,
      rejection_reason: rejection,
      rows,
      confinement_available: confinement,
      complete: !incomplete,
    });
  }
}

/** Phase 5 (contract §4.12): where the custodian's own state lives on Linux — a fixer must never write there. */
const LINUX_CUSTODIAN_PATHS: Record<string, string> = { store: "/var/lib/codeparley", run_codeparley: "/run/codeparley" };

/**
 * Phase 5 Increment 3 (contract §4.12): the Linux port of the `cp_fix` self-test — `codex sandbox -P cp_fix` on Codex's
 * bundled bwrap with exactly a fixer's flags, as the implementer, with the approved Codex:
 *  - writable: the workspace `tree` and `scratch` (the positive controls that prove the grant is effective);
 *  - denied: a sibling, a primary-worktree canary, `$HOME`, the data home, `/tmp`, the custodian's store and
 *    `/run/codeparley` — judged on the HOST (a write into bwrap's own discarded root is contained, as in S1), each with a
 *    positive control where this account can write there; the custodian's paths, which this account cannot write
 *    anyway, are checked without one;
 *  - network blocked; a child process confined;
 *  - the user-namespace rows of S1 (linuxUsernsRows).
 * The record names the boot, the Codex binary and its bundled bwrap, which a custodian that binds a sandbox basis
 * measures itself before it confirms (§4.12). The workspace lives under the data home: Codex refuses to set up its
 * helpers under /tmp, and a production workspace lives there too (disposable-workspace.ts).
 */
async function runLinuxFixSelfTest(o: FixSelfTestOptions): Promise<FixSelfTestRecord> {
  const work = join(o.dataHome, "fix-selftest-work", randomBytes(6).toString("hex"));
  const tree = join(work, "tree");
  const scratch = join(work, "scratch");
  const control = join(work, "control");
  const primaryCanary = join(work, "primary-canary");
  const codexHome = join(work, "codex-home");
  const env = { ...(o.env ?? buildChildEnv({ includeCodexAuth: true }).env), CODEX_HOME: codexHome };
  const deps = o.deps ?? defaultSelfTestDeps(o.probe, env);
  const codexPath = o.probe.launcher.exe;
  const codexSha256 = (await sha256OfFile(codexPath)) ?? "0".repeat(64);
  const bwrap = deps.bwrap ?? REAL_BWRAP;
  const expectedBwrap = await bwrap.installed(o.probe.installDir);
  const bootId = linuxBootId();
  const profileInput: FixProfileInput = { backend: o.backend, installDir: o.probe.installDir, writableDirs: [tree, scratch], protectedPaths: [primaryCanary, codexHome] };
  const key = fixSelfTestKey(o.probe.version, codexSha256, profileInput);
  const digest = fixProfileDigest(profileInput);
  const rows: SelfTestRow[] = [];
  let incomplete = false;
  const guard = (r: SandboxRunResult): SandboxRunResult => {
    if (o.signal?.aborted) throw new FixSelfTestInterruptedError();
    if (r.incomplete) incomplete = true;
    return r;
  };
  const sb = async (script: string) => guard(await deps.runCodex(fixSandboxArgv({ ...profileInput, cwd: tree, command: [...LINUX_PROBE_SHELL, script] }), tree, o.signal));
  const outside = async (script: string) => guard(await deps.runPowerShell(script, o.signal));
  const canWrite = async (p: string): Promise<boolean> => {
    try {
      await writeFile(p, "pc");
      return true;
    } catch {
      return false;
    } finally {
      await rm(p, { force: true }).catch(() => undefined);
    }
  };

  try {
    for (const d of [tree, scratch, control, primaryCanary, codexHome]) await mkdir(d, { recursive: true });
    const alive = await sb("printf ALIVE");
    if (alive.status !== 0 || !alive.stdout.includes("ALIVE")) {
      const reason = `${alive.stderr}\n${alive.stdout}`.trim().split(/\r?\n/).slice(-2).join(" | ").slice(0, 500);
      return finish(false, reason || `exit ${String(alive.status)}`);
    }

    // In-workspace writes: ALLOWED — and they reach the host's workspace (the grant is effective, not a tmpfs).
    for (const [name, p] of [["tree", join(tree, "in-scope.txt")], ["scratch", join(scratch, "in-scope.txt")]] as const) {
      const out = (await sb(linuxWriteScript(p))).stdout;
      const reached = existsSync(p);
      await rm(p, { force: true }).catch(() => undefined);
      rows.push({ name: `write_in_workspace_${name}`, expectation: "allowed", sandbox: reached ? "wrote" : out.includes("WRITE_OK") ? "contained" : "denied", positive_control: "n/a", pass: reached && out.includes("WRITE_OK"), detail: out.trim().slice(0, 120) });
    }

    // Out-of-workspace writes: the HOST stays untouched.
    const tag = () => randomBytes(4).toString("hex");
    const writes: [string, string, boolean][] = [
      ["control_sibling", join(control, "forged.txt"), true],
      ["primary_canary", join(primaryCanary, "src.txt"), true],
      ["data_home", join(o.dataHome, `fix-selftest-forged-${tag()}.txt`), true],
      ["temp", join(tmpdir(), `cp-fix-selftest-${tag()}.txt`), true],
      ["home", join(process.env["HOME"] ?? work, `cp-fix-selftest-${tag()}.txt`), true],
      ...Object.entries(LINUX_CUSTODIAN_PATHS).map(([n, d]): [string, string, boolean] => [n, join(d, `cp-fix-selftest-${tag()}.txt`), false]),
    ];
    for (const [name, p, controlled] of writes) {
      const out = (await sb(linuxWriteScript(p))).stdout;
      const reached = existsSync(p);
      await rm(p, { force: true }).catch(() => undefined);
      const pc = controlled ? await canWrite(p) : null;
      const state = reached ? "wrote" : out.includes("WRITE_FAIL") ? "denied" : out.includes("WRITE_OK") ? "contained" : "unknown";
      const held = !reached && (state === "denied" || state === "contained");
      rows.push({
        name: `write_outside_${name}`, expectation: "denied", sandbox: state, positive_control: pc === null ? "n/a" : pc ? "ok" : "failed",
        pass: held && pc !== false, ...(pc === false ? { inconclusive: true } : {}),
        detail: `${out.trim().slice(0, 120)}${pc === null ? " (this account cannot write there either: no positive control)" : ""}`,
      });
    }

    // Network: blocked (positive control outside the sandbox).
    for (const [name, script, okTok, failTok] of [
      ["net_tcp", LINUX_TCP_SCRIPT, "NET_OK", "NET_FAIL"],
      ["net_dns", LINUX_DNS_SCRIPT, "DNS_OK", "DNS_FAIL"],
    ] as const) {
      const out = (await sb(script)).stdout;
      const blocked = out.includes(failTok);
      const connected = out.includes(okTok);
      const pc = (await outside(script)).stdout.includes(okTok);
      rows.push({ name, expectation: "blocked", sandbox: connected ? "connected" : blocked ? "blocked" : "unknown", positive_control: pc ? "ok" : "failed", pass: blocked && !connected && pc, inconclusive: !pc, detail: out.trim().slice(0, 160) });
    }

    // A child process of the sandboxed command writing outside the workspace: the host stays untouched.
    {
      const target = join(primaryCanary, "via-child.txt");
      const out = (await sb(`printf 'CHILD:'; ${LINUX_PROBE_SHELL.join(" ")} ${shq(linuxWriteScript(target))}`)).stdout.trim();
      const reached = existsSync(target);
      await rm(target, { force: true }).catch(() => undefined);
      const wrote = out.includes("WRITE_OK");
      rows.push({ name: "child_process_write_outside", expectation: "denied", sandbox: reached ? "wrote" : wrote ? "contained" : out.includes("WRITE_FAIL") ? "denied" : "unknown", positive_control: "n/a", pass: out.startsWith("CHILD:") && !reached && (wrote || out.includes("WRITE_FAIL")), detail: out.slice(0, 200) });
    }

    // The user-namespace rows, the same as S1's.
    rows.push(...(await linuxUsernsRows({ sb, control: outside, bwrap, expectedBwrap, ...(o.signal ? { signal: o.signal } : {}) })));
    return finish(true, null);
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => undefined);
  }

  function finish(profileRuns: boolean, rejection: string | null): FixSelfTestRecord {
    const inWorkspaceOk = rows.some((r) => r.name.startsWith("write_in_workspace_")) && rows.filter((r) => r.name.startsWith("write_in_workspace_")).every((r) => r.pass);
    const confinement = !incomplete && profileRuns && inWorkspaceOk && rows.every((r) => r.pass) && !rows.some((r) => r.inconclusive);
    return FixSelfTestRecordSchema.parse({
      schema: "arl.codex-fix-selftest.v1",
      selftest_id: uuidv7(),
      key,
      codex_version: o.probe.version,
      codex_sha256: codexSha256,
      backend: o.backend,
      profile_digest: digest,
      created_at: (o.now ?? (() => new Date().toISOString()))(),
      profile_runs: profileRuns,
      rejection_reason: rejection,
      rows,
      confinement_available: confinement,
      complete: !incomplete,
      ...(bootId ? { boot_id: bootId } : {}),
      codex_path: codexPath,
      ...(expectedBwrap ? { bwrap_sha256: expectedBwrap.sha256 } : {}),
    });
  }
}

export async function ensureFixSelfTest(o: FixSelfTestOptions & { selftestDir: string }): Promise<{ record: FixSelfTestRecord; ran: boolean }> {
  const codexBytes = await readFile(o.probe.launcher.exe).catch(() => null);
  const codexSha256 = codexBytes ? sha256OfBytes(codexBytes) : "0".repeat(64);
  const profileInput: FixProfileInput = { backend: o.backend, installDir: o.probe.installDir, writableDirs: [join(o.dataHome, "fix-selftest-work", "tree"), join(o.dataHome, "fix-selftest-work", "scratch")], protectedPaths: [o.probe.codexHome] };
  const existing = await loadFixSelfTest(o.selftestDir, o.probe.version, codexSha256, profileInput);
  if (existing) return { record: existing, ran: false };
  const record = await runFixSelfTest(o);
  await storeFixSelfTest(o.selftestDir, record);
  return { record, ran: true };
}
