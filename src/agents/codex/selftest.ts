// Offline sandbox self-test (plan §12.6 step 2; LV-ISO-1; Gate A). No model call.
//
// Runs `codex sandbox` with EXACTLY the isolation flags a review uses (argv.ts
// `isolationFlags`), pairing each probe with a positive control outside the sandbox. A row
// passes only when the sandboxed behaviour is right AND the control shows the probe was
// meaningful (the canary really is readable, the network really is reachable). A network
// row whose control fails is inconclusive, which counts as not passed. S1 is available
// only if the profile runs on the backend and every row passes (no `:root` is ever added
// to make a backend accept the profile: argv.ts refuses it).
//
// Canaries: one private to the user (under the data home), one granted to BUILTIN\Users
// (readable by every local user, the case that matters on Windows, X17/X19), one in %TEMP%.
// The result is stored as selftest/<key>.json, keyed by Codex version, backend, mode and
// profile digest, and re-run automatically when any of these change (§19.6).
//
// Re-homed from spike/lib/selftest.mjs + canaries.mjs (validated by Gate A on 0.160.0/mxc).
//
// Linux (`bwrap`, plan §1.13; Linux Gate A). The probes are bash scripts (the sandbox sees the
// system's /usr/bin), each again paired with a control run outside the sandbox. A canary
// outside the export must be unreadable — denied OR absent from the sandbox's view (bubblewrap
// builds a mount namespace that simply does not contain it), with the control proving it
// exists. A write must not reach the host: a write into the sandbox's private, discarded root
// tmpfs is contained, and the row checks the host side. Rows only Linux needs: the sandbox has
// its own network, PID, mount and user namespaces; it cannot signal, or read the environment
// of, a process outside; it inherits no file descriptor beyond stdio; on WSL it can neither
// read the Windows drives nor start a Windows program through interop. `codex sandbox` loads
// the user's Codex configuration, which `exec --ignore-user-config` does not, so the Linux
// self-test runs with an empty CODEX_HOME: it tests exactly the profile reviews use (a hostile
// config.toml was observed to merge read grants into the profile). The kernel release is part
// of the key, so a kernel update re-runs it.
//
// Phase 5 (contract §4.12): three Linux rows on the user-namespace basis. `userns_via_approved_profile`:
// the sandbox has its own user namespace, the workload holds no capability in it, and the bwrap
// that built it is the installation's own (its /proc/<pid>/exe hashed while it runs, found in the
// self-test's own process tree: bwrap stays outside the sandbox's PID namespace, so it is not
// visible from inside). `restriction_effective_outside_profile`: with AppArmor's user-namespace
// restriction on, a plain `unshare -rm` outside the sandbox is refused (the exception is scoped to
// the profiled bwrap); without the restriction the row is not applicable (a custodian refuses a
// protected review then). `nested_userns_noted`: whether a nested user namespace is possible
// inside is recorded, never passed or failed (the known residual). The boot id is part of the
// Linux key and of the record, so a self-test is valid on the boot it ran on only.

import { chmod, copyFile, mkdir, readdir, readFile, readlink, rm, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { release, tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { sha256OfCanonicalJson } from "../../common/hash.js";
import { uuidv7 } from "../../common/ids.js";
import { atomicWriteFile, readTextIfExists } from "../../store/atomic.js";
import { runProcess } from "../../process/spawn.js";
import { buildChildEnv } from "../../process/env.js";
import { isNoDesktopExit, NO_DESKTOP_REMEDY, NO_DESKTOP_SESSION } from "./isolation.js";
import { SelfTestRecordSchema, type IsolationMode, type SelfTestRecord, type SelfTestRow } from "../../schemas/review.js";
import { LINUX_BACKENDS, profileDigest, sandboxArgv, type IsolationArgvInput, type SandboxBackend } from "./argv.js";
import type { CodexProbe } from "./probe.js";

const NET_IP = "1.1.1.1";
const NET_PORT = 443;
const DNS_NAME = "example.com";

export interface SandboxRunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  /** The run was cancelled, timed out or could not be launched: it determined nothing. */
  incomplete?: boolean;
}

/** The self-test was cancelled before it finished; nothing about the backend was learned (F10). */
export class SelfTestInterruptedError extends Error {
  constructor() {
    super("the Codex sandbox self-test was cancelled before it finished");
  }
}

export interface SelfTestDeps {
  /** Run `codex <argv>` (sandbox subcommand) from `cwd`. */
  runCodex(argv: string[], cwd: string, signal?: AbortSignal): Promise<SandboxRunResult>;
  /** Run a probe script OUTSIDE any sandbox (positive controls): PowerShell on Windows, bash on Linux. */
  runPowerShell(script: string, signal?: AbortSignal): Promise<SandboxRunResult>;
  /** Make a directory readable by every local user (Windows: BUILTIN\Users ACL; Linux: mode 0755, files 0644). */
  grantUsersRead(dir: string): Promise<boolean>;
  /** Phase 5 (§4.12), Linux: the installation's bundled bwrap (its SHA-256; null when it cannot be read) and the bwrap
   * processes running in this process's own tree. Default: the real files and /proc (a test's fake Codex has none). */
  bwrap?: BwrapEvidence;
}

export interface BwrapEvidence {
  installed(installDir: string): Promise<{ path: string; sha256: string } | null>;
  running(): Promise<{ pid: number; path: string; sha256: string | null }[]>;
}

export function powershellExe(): string {
  return join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/** The shell the Linux probes run in (inside and outside the sandbox). */
export const LINUX_PROBE_SHELL: readonly string[] = ["/bin/bash", "--noprofile", "--norc", "-c"];

export function defaultSelfTestDeps(probe: CodexProbe, env: Record<string, string>): SelfTestDeps {
  if (process.platform !== "win32") {
    return {
      runCodex: async (argv, cwd, signal) => {
        const r = await runProcess(probe.launcher.file, [...probe.launcher.prefixArgs, ...argv], { cwd, env, wallMs: 90_000, ...(signal ? { signal } : {}) });
        return { status: r.status, stdout: r.stdout, stderr: r.stderr, incomplete: r.cancelled || r.timedOut || r.spawnError !== null };
      },
      runPowerShell: async (script, signal) => {
        const r = await runProcess(LINUX_PROBE_SHELL[0]!, [...LINUX_PROBE_SHELL.slice(1), script], { env, wallMs: 30_000, ...(signal ? { signal } : {}) });
        return { status: r.status, stdout: r.stdout, stderr: r.stderr, incomplete: r.cancelled || r.timedOut || r.spawnError !== null };
      },
      grantUsersRead: async (dir) => {
        try {
          await chmod(dir, 0o755);
          return true;
        } catch {
          return false;
        }
      },
    };
  }
  return {
    runCodex: async (argv, cwd, signal) => {
      const r = await runProcess(probe.launcher.file, [...probe.launcher.prefixArgs, ...argv], { cwd, env, wallMs: 90_000, ...(signal ? { signal } : {}) });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr, incomplete: r.cancelled || r.timedOut || r.spawnError !== null };
    },
    runPowerShell: async (script, signal) => {
      const r = await runProcess(powershellExe(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], { env, wallMs: 30_000, ...(signal ? { signal } : {}) });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr, incomplete: r.cancelled || r.timedOut || r.spawnError !== null };
    },
    grantUsersRead: async (dir) => {
      const icacls = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "icacls.exe");
      const r = await runProcess(icacls, [dir, "/grant", "*S-1-5-32-545:(OI)(CI)R"], { env, wallMs: 30_000 });
      return r.status === 0;
    },
  };
}

// --- probe scripts (each writes exactly one token to stdout) --------------------------

const psq = (p: string) => p.replace(/'/g, "''");

const readScript = (p: string) =>
  `try { $c = Get-Content -Raw -LiteralPath '${psq(p)}' -ErrorAction Stop; [Console]::Out.Write('READ_OK:' + $c.Trim()) } ` +
  `catch { [Console]::Out.Write('READ_FAIL:' + $_.Exception.GetType().Name + ':' + $_.CategoryInfo.Category + ':' + $_.Exception.Message) }`;

const writeScript = (p: string) =>
  `try { Set-Content -LiteralPath '${psq(p)}' -Value 'arl' -ErrorAction Stop; [Console]::Out.Write('WRITE_OK') } ` +
  `catch { [Console]::Out.Write('WRITE_FAIL:' + $_.Exception.GetType().Name + ':' + $_.Exception.Message) }`;

export const TCP_SCRIPT =
  `try { $c=[System.Net.Sockets.TcpClient]::new(); $c.Connect('${NET_IP}',${NET_PORT}); [Console]::Out.Write('NET_OK'); $c.Close() } ` +
  `catch { [Console]::Out.Write('NET_FAIL:' + $_.Exception.Message) }`;

export const DNS_SCRIPT =
  `try { $a=[System.Net.Dns]::GetHostAddresses('${DNS_NAME}'); [Console]::Out.Write('DNS_OK:' + ($a -join ',')) } ` +
  `catch { [Console]::Out.Write('DNS_FAIL:' + $_.Exception.Message) }`;

const childFileScript = (canary: string) =>
  `try { $c = Get-Content -Raw -LiteralPath '${psq(canary)}' -ErrorAction Stop; [Console]::Out.Write('C_OK:' + $c.Trim()) } ` +
  `catch { [Console]::Out.Write('C_DENIED:' + $_.Exception.GetType().Name) }`;

// The child is started through System.Diagnostics.Process: under S1 the drive root is not
// readable, so PowerShell's `&` operator and Start-Process fail with DriveNotFound before
// the child runs (observed M1.3 and M1.4 on C:), which would test nothing.
const childOuterScript = (childScript: string) =>
  `try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = '${psq(powershellExe())}'; ` +
  `$psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${psq(childScript)}"'; $psi.UseShellExecute = $false; ` +
  `$psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $p = [System.Diagnostics.Process]::Start($psi); ` +
  `$o = $p.StandardOutput.ReadToEnd(); $null = $p.StandardError.ReadToEnd(); $p.WaitForExit(); [Console]::Out.Write('CHILD:' + $o.Trim()) } ` +
  `catch { [Console]::Out.Write('CHILD_ERR:' + $_.Exception.Message) }`;

export function classifyRead(out: string): { result: "allowed" | "denied" | "not_found" | "other_error" | "unknown"; detail: string } {
  const t = out.trim();
  if (t.startsWith("READ_OK:")) return { result: "allowed", detail: t.slice(8, 60) };
  if (t.startsWith("READ_FAIL:")) {
    const rest = t.slice("READ_FAIL:".length);
    const low = rest.toLowerCase();
    if (low.includes("unauthorizedaccess") || low.includes("permissiondenied") || low.includes("access is denied") || low.includes("is denied")) return { result: "denied", detail: rest.slice(0, 120) };
    if (low.includes("notfound") || low.includes("does not exist") || low.includes("cannot find")) return { result: "not_found", detail: rest.slice(0, 120) };
    return { result: "other_error", detail: rest.slice(0, 120) };
  }
  return { result: "unknown", detail: t.slice(0, 120) };
}

// --- record storage ------------------------------------------------------------------

function isLinuxBackend(b: SandboxBackend): boolean {
  return (LINUX_BACKENDS as readonly string[]).includes(b);
}

/**
 * The self-test key. Linux backends also bind the kernel release: the sandbox is built from
 * kernel namespaces and seccomp, so a kernel update re-runs the self-test (Windows keys are
 * unchanged from M1).
 */
export function selfTestKey(codexVersion: string, iso: IsolationArgvInput, kernel: string = release(), bootId: string | null = linuxBootId()): string {
  return sha256OfCanonicalJson({
    schema: "arl.codex-selftest-key.v1",
    codex_version: codexVersion,
    backend: iso.backend,
    mode: iso.mode,
    profile_digest: profileDigest(iso),
    ...(isLinuxBackend(iso.backend) ? { kernel } : {}),
    ...(isLinuxBackend(iso.backend) && bootId ? { boot_id: bootId } : {}),
  });
}

/** Phase 5 (§4.12): this boot's id (Linux), or null where there is none. */
export function linuxBootId(): string | null {
  if (process.platform !== "linux") return null;
  try {
    const id = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) ? id : null;
  } catch {
    return null;
  }
}

/** The AppArmor user-namespace restriction ("1", "0"), or null where the kernel has none. */
function usernsRestriction(): string | null {
  try {
    return readFileSync("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "utf8").trim();
  } catch {
    return null;
  }
}

export async function sha256OfFile(p: string): Promise<string | null> {
  try {
    return createHash("sha256").update(await readFile(p)).digest("hex");
  } catch {
    return null;
  }
}

/** Is `pid` a descendant of `ancestor` (by the PPid chain in /proc)? */
async function descendsFrom(pid: number, ancestor: number): Promise<boolean> {
  for (let p = pid, n = 0; p > 1 && n < 64; n++) {
    let status: string;
    try {
      status = await readFile(`/proc/${p}/status`, "utf8");
    } catch {
      return false;
    }
    p = Number(/^PPid:\s*(\d+)/m.exec(status)?.[1] ?? 0);
    if (p === ancestor) return true;
  }
  return false;
}

export const REAL_BWRAP: BwrapEvidence = {
  installed: async (installDir) => {
    const path = join(installDir, "codex-resources", "bwrap");
    const sha256 = await sha256OfFile(path);
    return sha256 ? { path, sha256 } : null;
  },
  running: () => bwrapInOwnTree(),
};

/** Phase 5 (§4.12): the bwrap processes in this process's own tree, each with the SHA-256 of its /proc/<pid>/exe (null
 * when it cannot be read). */
async function bwrapInOwnTree(): Promise<{ pid: number; path: string; sha256: string | null }[]> {
  let entries: string[];
  try {
    entries = await readdir("/proc");
  } catch {
    return [];
  }
  const out: { pid: number; path: string; sha256: string | null }[] = [];
  for (const d of entries) {
    if (!/^\d+$/.test(d)) continue;
    let exe: string;
    try {
      exe = await readlink(`/proc/${d}/exe`);
    } catch {
      continue;
    }
    if (!exe.endsWith("/bwrap") || !(await descendsFrom(Number(d), process.pid))) continue;
    out.push({ pid: Number(d), path: exe, sha256: await sha256OfFile(`/proc/${d}/exe`) });
  }
  return out;
}

export function selfTestPath(selftestDir: string, key: string): string {
  return join(selftestDir, `${key}.json`);
}

/** A stored self-test for exactly this version/backend/mode/profile, or null. */
export async function loadSelfTest(selftestDir: string, codexVersion: string, iso: IsolationArgvInput): Promise<SelfTestRecord | null> {
  const key = selfTestKey(codexVersion, iso);
  const raw = await readTextIfExists(selfTestPath(selftestDir, key));
  if (raw == null) return null;
  try {
    const rec = SelfTestRecordSchema.parse(JSON.parse(raw));
    return rec.complete && rec.key === key && rec.profile_digest === profileDigest(iso) && rec.codex_version === codexVersion ? rec : null;
  } catch {
    return null;
  }
}

export async function storeSelfTest(selftestDir: string, rec: SelfTestRecord): Promise<void> {
  if (!rec.complete) return; // not a capability determination (F10)
  await mkdir(selftestDir, { recursive: true });
  await atomicWriteFile(selfTestPath(selftestDir, rec.key), JSON.stringify(SelfTestRecordSchema.parse(rec), null, 2));
}

// --- the self-test -------------------------------------------------------------------

export interface SelfTestOptions {
  probe: CodexProbe;
  backend: SandboxBackend;
  mode: IsolationMode;
  dataHome: string;
  /** Required by argv.ts for S2 flags; the self-test of an S2 profile is not used to grant S1. */
  acceptanceId?: string | null;
  deps?: SelfTestDeps;
  env?: Record<string, string>;
  signal?: AbortSignal;
  now?: () => string;
}

export async function runSelfTest(o: SelfTestOptions): Promise<SelfTestRecord> {
  if (isLinuxBackend(o.backend)) return runLinuxSelfTest(o);
  const env = o.env ?? buildChildEnv({ includeCodexAuth: true }).env;
  const deps = o.deps ?? defaultSelfTestDeps(o.probe, env);
  const iso: IsolationArgvInput = {
    mode: o.mode,
    backend: o.backend,
    installDir: o.probe.installDir,
    webSearchDisabledValue: o.probe.compat.webSearchDisabledValue,
    acceptanceId: o.acceptanceId ?? null,
  };
  const key = selfTestKey(o.probe.version, iso);
  const digest = profileDigest(iso);
  const work = join(o.dataHome, "selftest-work", randomBytes(6).toString("hex"));
  const exportRoot = join(work, "export");
  const tree = join(exportRoot, "tree");
  const inScope = join(tree, "in-scope.txt");
  const privDir = join(work, "private");
  const pubDir = join(work, "public");
  const otherDir = join(process.env["TEMP"] ?? work, `arl-selftest-${randomBytes(6).toString("hex")}`);
  const mark = (tag: string) => `ARL_SELFTEST_CANARY_${tag}_${randomBytes(4).toString("hex")}`;
  const canaries = {
    userprivate: { path: join(privDir, "up.txt"), marker: mark("PRIVATE") },
    publicReadable: { path: join(pubDir, "pub.txt"), marker: mark("PUBLIC") },
    otherRoot: { path: join(otherDir, "other.txt"), marker: mark("OTHER") },
  };
  const rows: SelfTestRow[] = [];
  let incomplete = false;
  /** Every probe and control goes through here: cancellation aborts, a timeout marks the result incomplete. */
  const guard = (r: SandboxRunResult): SandboxRunResult => {
    if (o.signal?.aborted) throw new SelfTestInterruptedError();
    if (r.incomplete) incomplete = true;
    return r;
  };
  const sb = async (script: string) =>
    guard(await deps.runCodex(sandboxArgv({ ...iso, cwd: exportRoot, command: [powershellExe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script] }), exportRoot, o.signal));
  const ps = async (script: string) => guard(await deps.runPowerShell(script, o.signal));
  const pcRead = async (p: string) => (await ps(readScript(p))).stdout.trim().startsWith("READ_OK:");

  try {
    await mkdir(tree, { recursive: true });
    await mkdir(privDir, { recursive: true });
    await mkdir(pubDir, { recursive: true });
    await mkdir(otherDir, { recursive: true });
    await writeFile(inScope, "ARL_SELFTEST_IN_SCOPE_OK\n");
    for (const c of Object.values(canaries)) await writeFile(c.path, `${c.marker}\n`);
    const granted = await deps.grantUsersRead(pubDir);

    // 0. Does the profile run on this backend at all? A rejection is a valid result.
    const alive = await sb("[Console]::Out.Write('ALIVE')");
    if (alive.status !== 0 || !alive.stdout.includes("ALIVE")) {
      // §6 (N5-9): a profile that cannot initialize for want of a desktop says so, with the remedy, instead of a bare code.
      if (isNoDesktopExit(alive.status)) return finish(false, `${NO_DESKTOP_SESSION}: the profile could not start (exit 0xC0000142, STATUS_DLL_INIT_FAILED): this process has no interactive desktop session; ${NO_DESKTOP_REMEDY}`);
      const reason = `${alive.stderr}\n${alive.stdout}`.trim().split(/\r?\n/).slice(-2).join(" | ").slice(0, 500);
      return finish(false, reason || `exit ${String(alive.status)}`);
    }

    {
      const r = classifyRead((await sb(readScript(inScope))).stdout);
      const pc = await pcRead(inScope);
      rows.push({ name: "read_in_scope", expectation: "allowed", sandbox: r.result, positive_control: pc ? "ok" : "failed", pass: r.result === "allowed" && pc, detail: r.detail });
    }
    for (const [name, c] of Object.entries(canaries)) {
      const out = (await sb(readScript(c.path))).stdout;
      const r = classifyRead(out);
      const pc = await pcRead(c.path);
      const leaked = out.includes(c.marker);
      const note = name === "publicReadable" && !granted ? " (BUILTIN\\Users grant failed)" : "";
      rows.push({
        name: `read_canary_${name}`,
        expectation: "denied",
        sandbox: leaked ? "leaked" : r.result,
        positive_control: pc ? "ok" : "failed",
        // Denied with an ACCESS error (not "not found"), the control read it, nothing leaked.
        pass: r.result === "denied" && pc && !leaked && (name !== "publicReadable" || granted),
        detail: `${r.detail}${note}`,
      });
    }
    const writes: Record<string, string> = {
      export_tree: join(tree, "arl-write-probe.txt"),
      export_sibling: join(work, "arl-write-sibling.txt"),
      temp: join(process.env["TEMP"] ?? work, `arl-write-temp-${randomBytes(4).toString("hex")}.txt`),
      userprofile: join(process.env["USERPROFILE"] ?? work, `arl-write-up-${randomBytes(4).toString("hex")}.txt`),
    };
    for (const [name, p] of Object.entries(writes)) {
      const out = (await sb(writeScript(p))).stdout;
      const wrote = out.includes("WRITE_OK");
      const denied = out.includes("WRITE_FAIL");
      let pc = false;
      try {
        await writeFile(p, "pc");
        pc = true;
      } catch {
        pc = false;
      }
      await rm(p, { force: true }).catch(() => undefined);
      // A denial counts only if the same write succeeds outside the sandbox: otherwise the
      // target itself refused it and the row proves nothing (inconclusive; PR #2 review).
      rows.push({ name: `write_${name}`, expectation: "denied", sandbox: wrote ? "wrote" : denied ? "denied" : "unknown", positive_control: pc ? "ok" : "failed", pass: denied && !wrote && pc, inconclusive: !pc, detail: out.trim().slice(0, 120) });
    }
    for (const [name, script, okTok, failTok] of [
      ["net_tcp_literal_ip", TCP_SCRIPT, "NET_OK", "NET_FAIL"],
      ["net_dns", DNS_SCRIPT, "DNS_OK", "DNS_FAIL"],
    ] as const) {
      const out = (await sb(script)).stdout;
      const blocked = out.includes(failTok);
      const connected = out.includes(okTok);
      const pc = (await ps(script)).stdout.includes(okTok);
      rows.push({ name, expectation: "blocked", sandbox: connected ? "connected" : blocked ? "blocked" : "unknown", positive_control: pc ? "ok" : "failed", pass: blocked && !connected && pc, inconclusive: !pc, detail: out.trim().slice(0, 160) });
    }
    {
      const childScript = join(tree, "_child-probe.ps1");
      await writeFile(childScript, childFileScript(canaries.userprivate.path));
      const out = (await sb(childOuterScript(childScript))).stdout.trim();
      await rm(childScript, { force: true }).catch(() => undefined);
      const ok = out.includes("C_OK");
      const denied = out.includes("C_DENIED");
      const leaked = out.includes(canaries.userprivate.marker);
      rows.push({ name: "child_process_read_canary", expectation: "denied", sandbox: ok || leaked ? "allowed" : denied ? "denied" : "unknown", positive_control: "n/a", pass: denied && !ok && !leaked, detail: out.slice(0, 200) });
    }
    return finish(true, null);
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => undefined);
    await rm(otherDir, { recursive: true, force: true }).catch(() => undefined);
  }

  function finish(profileRuns: boolean, rejection: string | null): SelfTestRecord {
    const s1 = !incomplete && o.mode === "S1" && profileRuns && rows.length > 0 && rows.every((r) => r.pass) && !rows.some((r) => r.inconclusive);
    return SelfTestRecordSchema.parse({
      schema: "arl.codex-selftest.v1",
      selftest_id: uuidv7(),
      key,
      codex_version: o.probe.version,
      backend: o.backend,
      mode: o.mode,
      profile_digest: digest,
      created_at: (o.now ?? (() => new Date().toISOString()))(),
      profile_runs: profileRuns,
      rejection_reason: rejection,
      rows,
      s1_available: s1,
      complete: !incomplete,
    });
  }
}

// --- Linux (bwrap) -------------------------------------------------------------------

/** POSIX single-quoting for a value embedded in a bash probe script. */
export const shq = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

export const linuxReadScript = (p: string) => `if c=$(cat -- ${shq(p)} 2>&1); then printf 'READ_OK:%s' "$c"; else printf 'READ_FAIL:%s' "$c"; fi`;
export const linuxWriteScript = (p: string) => `if e=$( (printf arl > ${shq(p)}) 2>&1 ); then printf WRITE_OK; else printf 'WRITE_FAIL:%s' "$e"; fi`;
export const LINUX_TCP_SCRIPT = `if e=$( (exec 3<>/dev/tcp/${NET_IP}/${NET_PORT}) 2>&1 ); then printf NET_OK; else printf 'NET_FAIL:%s' "$e"; fi`;
export const LINUX_DNS_SCRIPT = `if a=$(getent hosts ${DNS_NAME} 2>&1); then printf 'DNS_OK:%s' "$a"; else printf 'DNS_FAIL:exit %s %s' "$?" "$a"; fi`;
export const LINUX_NS_SCRIPT = `for n in net pid mnt user; do printf '%s=%s;' "$n" "$(readlink /proc/self/ns/$n 2>&1)"; done`;
export const LINUX_FD_SCRIPT = `printf 'FD:'; ls /proc/self/fd 2>&1 | tr '\\n' ' '`;
const linuxSignalScript = (pid: number) => `if kill -0 ${pid} 2>/dev/null; then printf KILL_OK; else printf KILL_FAIL; fi`;
const linuxEnvironScript = (pid: number, marker: string) =>
  `if [ -e /proc/${pid}/environ ]; then if grep -q -a ${shq(marker)} /proc/${pid}/environ 2>/dev/null; then printf ENV_LEAK; else printf ENV_FAIL:unreadable; fi; else printf ENV_FAIL:absent; fi`;
/** Inside the sandbox: the workload's effective capabilities and its user namespace — after a pause, so the bwrap that
 * built the sandbox is still running while the self-test looks for it in its own process tree. */
export const LINUX_USERNS_SCRIPT = `sleep 2; printf 'CAPEFF=%s;USERNS=%s;' "$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)" "$(readlink /proc/self/ns/user 2>&1)"`;
/** An unprivileged user and mount namespace, as a plain process would ask for one. */
export const LINUX_UNSHARE_SCRIPT = `if command -v unshare >/dev/null 2>&1; then if e=$(unshare -rm /bin/true 2>&1); then printf UNSHARE_OK; else printf 'UNSHARE_FAIL:%s' "$e"; fi; else printf UNSHARE_MISSING; fi`;
const linuxExecScript = (p: string) => `if o=$(${shq(p)} 2>&1); then printf 'EXEC_OK:%s' "$o"; else printf 'EXEC_FAIL:%s' "$o"; fi`;

/** Classify a Linux read probe: absent from the sandbox's view counts like a denial (bubblewrap). */
export function classifyLinuxRead(out: string): { result: "allowed" | "denied" | "not_found" | "other_error" | "unknown"; detail: string } {
  const t = out.trim();
  if (t.startsWith("READ_OK:")) return { result: "allowed", detail: t.slice(8, 60) };
  if (t.startsWith("READ_FAIL:")) {
    const rest = t.slice("READ_FAIL:".length);
    if (/permission denied|operation not permitted/i.test(rest)) return { result: "denied", detail: rest.slice(0, 120) };
    if (/no such file or directory|not a directory/i.test(rest)) return { result: "not_found", detail: rest.slice(0, 120) };
    return { result: "other_error", detail: rest.slice(0, 120) };
  }
  return { result: "unknown", detail: t.slice(0, 120) };
}

function wslInteropEnabled(): boolean {
  try {
    return readFileSync("/proc/sys/fs/binfmt_misc/WSLInterop", "utf8").split(/\r?\n/)[0]?.trim() === "enabled";
  } catch {
    return false;
  }
}

async function hostNamespaces(): Promise<Record<string, string | null>> {
  const out: Record<string, string | null> = {};
  for (const n of ["net", "pid", "mnt", "user"]) out[n] = await readlink(`/proc/self/ns/${n}`).catch(() => null);
  return out;
}

async function runLinuxSelfTest(o: SelfTestOptions): Promise<SelfTestRecord> {
  const iso: IsolationArgvInput = {
    mode: o.mode,
    backend: o.backend,
    installDir: o.probe.installDir,
    webSearchDisabledValue: o.probe.compat.webSearchDisabledValue,
    acceptanceId: o.acceptanceId ?? null,
  };
  const key = selfTestKey(o.probe.version, iso);
  const digest = profileDigest(iso);
  const work = join(o.dataHome, "selftest-work", randomBytes(6).toString("hex"));
  // `codex sandbox` would load $CODEX_HOME/config.toml, which reviews never do: test with an
  // empty one (under the data home — Codex refuses to set up its helpers under /tmp).
  const codexHome = join(work, "codex-home");
  const env = { ...(o.env ?? buildChildEnv({ includeCodexAuth: true }).env), CODEX_HOME: codexHome };
  const deps = o.deps ?? defaultSelfTestDeps(o.probe, env);
  const exportRoot = join(work, "export");
  const tree = join(exportRoot, "tree");
  const inScope = join(tree, "in-scope.txt");
  const privDir = join(work, "private");
  const pubDir = join(tmpdir(), `arl-selftest-pub-${randomBytes(6).toString("hex")}`);
  const otherDir = join(tmpdir(), `arl-selftest-${randomBytes(6).toString("hex")}`);
  const mark = (tag: string) => `ARL_SELFTEST_CANARY_${tag}_${randomBytes(4).toString("hex")}`;
  const canaries = {
    userprivate: { path: join(privDir, "up.txt"), marker: mark("PRIVATE") },
    publicReadable: { path: join(pubDir, "pub.txt"), marker: mark("PUBLIC") },
    otherRoot: { path: join(otherDir, "other.txt"), marker: mark("OTHER") },
  };
  const rows: SelfTestRow[] = [];
  let incomplete = false;
  // Phase 5 (§4.12): the binding facts — this boot, the native Codex binary and the installation's bundled bwrap.
  const bootId = linuxBootId();
  const codexPath = (o.probe.launcher as CodexProbe["launcher"] | undefined)?.exe ?? null;
  const codexSha256 = codexPath ? await sha256OfFile(codexPath) : null;
  const bwrap = deps.bwrap ?? REAL_BWRAP;
  const expectedBwrap = await bwrap.installed(o.probe.installDir);
  const bwrapSha256 = expectedBwrap?.sha256 ?? null;
  const guard = (r: SandboxRunResult): SandboxRunResult => {
    if (o.signal?.aborted) throw new SelfTestInterruptedError();
    if (r.incomplete) incomplete = true;
    return r;
  };
  const sb = async (script: string) => guard(await deps.runCodex(sandboxArgv({ ...iso, cwd: exportRoot, command: [...LINUX_PROBE_SHELL, script] }), exportRoot, o.signal));
  const control = async (script: string) => guard(await deps.runPowerShell(script, o.signal));
  const controlRead = async (p: string) => (await control(linuxReadScript(p))).stdout.trim().startsWith("READ_OK:");
  // A process outside the sandbox, with a marker in its environment, for the signal and /proc rows.
  const envMarker = mark("ENV");
  const canaryStop = new AbortController();
  let canaryPid: number | null = null;
  const canaryRun = runProcess("/bin/sleep", ["300"], { env: { ...buildChildEnv().env, ARL_SELFTEST_ENV_CANARY: envMarker }, wallMs: 300_000, signal: canaryStop.signal, onSpawn: (pid) => (canaryPid = pid) });

  try {
    await mkdir(tree, { recursive: true });
    await mkdir(join(codexHome), { recursive: true });
    await mkdir(privDir, { recursive: true, mode: 0o700 });
    await mkdir(pubDir, { recursive: true });
    await mkdir(otherDir, { recursive: true, mode: 0o700 });
    await writeFile(inScope, "ARL_SELFTEST_IN_SCOPE_OK\n");
    for (const c of Object.values(canaries)) await writeFile(c.path, `${c.marker}\n`, { mode: 0o600 });
    await chmod(canaries.publicReadable.path, 0o644);
    const granted = await deps.grantUsersRead(pubDir);

    // 0. Does the profile run on this backend at all? A rejection is a valid result.
    const alive = await sb("printf ALIVE");
    if (alive.status !== 0 || !alive.stdout.includes("ALIVE")) {
      const reason = `${alive.stderr}\n${alive.stdout}`.trim().split(/\r?\n/).slice(-2).join(" | ").slice(0, 500);
      return finishLinux(false, reason || `exit ${String(alive.status)}`);
    }

    {
      const r = classifyLinuxRead((await sb(linuxReadScript(inScope))).stdout);
      const pc = await controlRead(inScope);
      rows.push({ name: "read_in_scope", expectation: "allowed", sandbox: r.result, positive_control: pc ? "ok" : "failed", pass: r.result === "allowed" && pc, detail: r.detail });
    }
    const unreadable = async (name: string, path: string, marker: string | null, extraOk = true, note = "") => {
      const out = (await sb(linuxReadScript(path))).stdout;
      const r = classifyLinuxRead(out);
      const pc = await controlRead(path);
      const leaked = marker !== null ? out.includes(marker) : r.result === "allowed";
      const hidden = r.result === "denied" || r.result === "not_found";
      rows.push({ name, expectation: "denied", sandbox: leaked ? "leaked" : r.result === "not_found" ? "hidden" : r.result, positive_control: pc ? "ok" : "failed", pass: hidden && pc && !leaked && extraOk, detail: `${r.detail}${note}` });
    };
    await unreadable("read_canary_userprivate", canaries.userprivate.path, canaries.userprivate.marker);
    await unreadable("read_canary_publicReadable", canaries.publicReadable.path, canaries.publicReadable.marker, granted, granted ? "" : " (could not make the canary world-readable)");
    await unreadable("read_canary_otherRoot", canaries.otherRoot.path, canaries.otherRoot.marker);
    const winHosts = "/mnt/c/Windows/System32/drivers/etc/hosts";
    if (existsSync(winHosts)) await unreadable("read_windows_drive", winHosts, null);
    else rows.push({ name: "read_windows_drive", expectation: "denied", sandbox: "not_applicable", positive_control: "n/a", pass: true, detail: "no Windows drive is mounted at /mnt/c" });

    const writes: Record<string, string> = {
      export_tree: join(tree, "arl-write-probe.txt"),
      export_sibling: join(work, "arl-write-sibling.txt"),
      temp: join(tmpdir(), `arl-write-temp-${randomBytes(4).toString("hex")}.txt`),
      home: join(process.env["HOME"] ?? work, `arl-write-home-${randomBytes(4).toString("hex")}.txt`),
    };
    for (const [name, p] of Object.entries(writes)) {
      const out = (await sb(linuxWriteScript(p))).stdout;
      // The host is what must stay untouched; a write into the sandbox's own discarded root
      // tmpfs (bubblewrap) is contained.
      const reached = existsSync(p);
      await rm(p, { force: true }).catch(() => undefined);
      let pc = false;
      try {
        await writeFile(p, "pc");
        pc = true;
      } catch {
        pc = false;
      }
      await rm(p, { force: true }).catch(() => undefined);
      const state = reached ? "wrote" : out.includes("WRITE_FAIL") ? "denied" : out.includes("WRITE_OK") ? "contained" : "unknown";
      rows.push({ name: `write_${name}`, expectation: "denied", sandbox: state, positive_control: pc ? "ok" : "failed", pass: !reached && (state === "denied" || state === "contained") && pc, inconclusive: !pc, detail: out.trim().slice(0, 120) });
    }
    for (const [name, script, okTok, failTok] of [
      ["net_tcp_literal_ip", LINUX_TCP_SCRIPT, "NET_OK", "NET_FAIL"],
      ["net_dns", LINUX_DNS_SCRIPT, "DNS_OK", "DNS_FAIL"],
    ] as const) {
      const out = (await sb(script)).stdout;
      const blocked = out.includes(failTok);
      const connected = out.includes(okTok);
      const pc = (await control(script)).stdout.includes(okTok);
      rows.push({ name, expectation: "blocked", sandbox: connected ? "connected" : blocked ? "blocked" : "unknown", positive_control: pc ? "ok" : "failed", pass: blocked && !connected && pc, inconclusive: !pc, detail: out.trim().slice(0, 160) });
    }
    {
      // Own namespaces: the structural reason nothing outside is reachable (abstract unix
      // sockets live in the network namespace; /proc and signals in the PID namespace).
      const host = await hostNamespaces();
      const out = (await sb(LINUX_NS_SCRIPT)).stdout;
      // "net=net:[…];pid=…;" — one "name=value;" field per namespace.
      const fields = new Map(
        out
          .trim()
          .split(";")
          .filter((kv) => kv.includes("="))
          .map((kv) => [kv.slice(0, kv.indexOf("=")), kv.slice(kv.indexOf("=") + 1)] as const),
      );
      for (const n of ["net", "pid", "mnt", "user"]) {
        const inside = fields.get(n) ?? null;
        const ok = !!inside && /^[a-z]+:\[\d+\]$/.test(inside) && host[n] !== null && inside !== host[n];
        rows.push({ name: `namespace_${n}_isolated`, expectation: "denied", sandbox: inside === null ? "unknown" : inside === host[n] ? "shared" : "isolated", positive_control: host[n] ? "ok" : "failed", pass: ok, detail: `inside ${inside ?? "?"}, host ${host[n] ?? "?"}` });
      }
    }
    for (let i = 0; i < 50 && canaryPid === null; i++) await new Promise((r) => setTimeout(r, 20));
    if (canaryPid !== null) {
      const pid = canaryPid;
      const sig = (await sb(linuxSignalScript(pid))).stdout;
      const pcSig = (await control(linuxSignalScript(pid))).stdout.includes("KILL_OK");
      rows.push({ name: "signal_outside_process", expectation: "denied", sandbox: sig.includes("KILL_OK") ? "allowed" : sig.includes("KILL_FAIL") ? "denied" : "unknown", positive_control: pcSig ? "ok" : "failed", pass: sig.includes("KILL_FAIL") && pcSig, detail: sig.trim().slice(0, 120) });
      const envOut = (await sb(linuxEnvironScript(pid, envMarker))).stdout;
      const pcEnv = (await control(linuxEnvironScript(pid, envMarker))).stdout.includes("ENV_LEAK");
      rows.push({ name: "proc_environ_outside_process", expectation: "denied", sandbox: envOut.includes("ENV_LEAK") ? "leaked" : envOut.includes("ENV_FAIL") ? "denied" : "unknown", positive_control: pcEnv ? "ok" : "failed", pass: envOut.includes("ENV_FAIL") && !envOut.includes("ENV_LEAK") && pcEnv, detail: envOut.trim().slice(0, 120) });
    } else {
      rows.push({ name: "signal_outside_process", expectation: "denied", sandbox: "unknown", positive_control: "failed", pass: false, inconclusive: true, detail: "the canary process could not be started" });
    }
    {
      const out = (await sb(LINUX_FD_SCRIPT)).stdout.trim();
      const fds = out.startsWith("FD:") ? out.slice(3).trim().split(/\s+/).filter(Boolean) : null;
      // `ls` itself holds the directory it lists (fd 3); anything beyond stdio and that is inherited.
      const extra = fds === null ? null : fds.filter((f) => !["0", "1", "2", "3"].includes(f));
      rows.push({ name: "inherited_descriptors", expectation: "denied", sandbox: extra === null ? "unknown" : extra.length ? `inherited ${extra.join(",")}` : "none", positive_control: "n/a", pass: extra !== null && extra.length === 0, detail: out.slice(0, 120) });
    }
    if (wslInteropEnabled() && existsSync("/mnt/c/Windows/System32/whoami.exe")) {
      const exe = join(tree, "arl-interop-probe.exe");
      await copyFile("/mnt/c/Windows/System32/whoami.exe", exe);
      await chmod(exe, 0o755);
      const out = (await sb(linuxExecScript(exe))).stdout;
      const pc = (await control(linuxExecScript(exe))).stdout.startsWith("EXEC_OK:");
      await rm(exe, { force: true }).catch(() => undefined);
      rows.push({ name: "wsl_interop_exec", expectation: "denied", sandbox: out.startsWith("EXEC_OK:") ? "executed_on_windows" : out.includes("EXEC_FAIL") ? "denied" : "unknown", positive_control: pc ? "ok" : "failed", pass: out.includes("EXEC_FAIL") && !out.startsWith("EXEC_OK:") && pc, inconclusive: !pc, detail: out.trim().slice(0, 160) });
    } else {
      rows.push({ name: "wsl_interop_exec", expectation: "denied", sandbox: "not_applicable", positive_control: "n/a", pass: true, detail: "WSL interop is not enabled here" });
    }
    {
      const childOut = (await sb(`printf 'CHILD:'; ${LINUX_PROBE_SHELL.join(" ")} ${shq(linuxReadScript(canaries.userprivate.path))}`)).stdout.trim();
      const leaked = childOut.includes(canaries.userprivate.marker);
      const r = classifyLinuxRead(childOut.replace(/^CHILD:/, ""));
      const hidden = r.result === "denied" || r.result === "not_found";
      rows.push({ name: "child_process_read_canary", expectation: "denied", sandbox: leaked ? "allowed" : hidden ? "denied" : r.result, positive_control: "n/a", pass: childOut.startsWith("CHILD:") && hidden && !leaked, detail: childOut.slice(0, 200) });
    }
    rows.push(...(await linuxUsernsRows({ sb, control, bwrap, expectedBwrap, ...(o.signal ? { signal: o.signal } : {}) })));
    return finishLinux(true, null);
  } finally {
    canaryStop.abort();
    await canaryRun.catch(() => undefined);
    await rm(work, { recursive: true, force: true }).catch(() => undefined);
    await rm(otherDir, { recursive: true, force: true }).catch(() => undefined);
    await rm(pubDir, { recursive: true, force: true }).catch(() => undefined);
  }

  function finishLinux(profileRuns: boolean, rejection: string | null): SelfTestRecord {
    const s1 = !incomplete && o.mode === "S1" && profileRuns && rows.length > 0 && rows.every((r) => r.pass) && !rows.some((r) => r.inconclusive);
    return SelfTestRecordSchema.parse({
      schema: "arl.codex-selftest.v1",
      selftest_id: uuidv7(),
      key,
      codex_version: o.probe.version,
      backend: o.backend,
      mode: o.mode,
      profile_digest: digest,
      created_at: (o.now ?? (() => new Date().toISOString()))(),
      profile_runs: profileRuns,
      rejection_reason: rejection,
      rows,
      s1_available: s1,
      complete: !incomplete,
      ...(bootId ? { boot_id: bootId } : {}),
      ...(codexPath ? { codex_path: codexPath } : {}),
      ...(codexSha256 ? { codex_sha256: codexSha256 } : {}),
      ...(bwrapSha256 ? { bwrap_sha256: bwrapSha256 } : {}),
    });
  }
}

/**
 * Phase 5 (contract §4.12): the three Linux user-namespace rows, the same in the S1 and the FIX self-tests —
 * `userns_via_approved_profile` (an own user namespace, no capability, and the installation's own bwrap seen in this
 * process's tree by the hash of its /proc/<pid>/exe), `restriction_effective_outside_profile` (a plain `unshare -rm`
 * outside the sandbox is refused while the restriction is on) and `nested_userns_noted` (recorded, never passed or
 * failed: the known residual). `sb` runs a probe script in the sandbox under test, `control` outside it.
 */
export async function linuxUsernsRows(o: {
  sb: (script: string) => Promise<SandboxRunResult>;
  control: (script: string) => Promise<SandboxRunResult>;
  bwrap: BwrapEvidence;
  expectedBwrap: { path: string; sha256: string } | null;
  signal?: AbortSignal;
}): Promise<SelfTestRow[]> {
  const { sb, control, bwrap, expectedBwrap } = o;
  const collected: SelfTestRow[] = [];
  {
    // Phase 5 (§4.12) row 1: the user namespace exists, the workload holds no capability, and the bwrap that ran is
    // the installation's own — matched by path and by the hash of its /proc/<pid>/exe, read while the probe runs.
    const scan = (async () => {
      const found = new Map<number, { pid: number; path: string; sha256: string | null }>();
      for (let i = 0; i < 40 && found.size === 0 && !o.signal?.aborted; i++) {
        for (const b of await bwrap.running()) found.set(b.pid, b);
        if (found.size === 0) await new Promise((r) => setTimeout(r, 100));
      }
      return [...found.values()];
    })();
    const out = (await sb(LINUX_USERNS_SCRIPT)).stdout.trim();
    const fields = out.split(";").filter((kv) => kv.includes("="));
    const capEff = fields.find((kv) => kv.startsWith("CAPEFF="))?.slice(7) ?? null;
    const userns = fields.find((kv) => kv.startsWith("USERNS="))?.slice(7) ?? null;
    const seen = (await scan).map((b) => [b.path, b.sha256 ?? ""] as [string, string]);
    const hostUser = (await hostNamespaces())["user"] ?? null;
    const approved = expectedBwrap;
    const match = approved !== null && seen.some(([p, h]) => p === approved.path && h === approved.sha256);
    const noCaps = capEff !== null && /^0+$/.test(capEff);
    const ownNs = userns !== null && /^user:\[\d+\]$/.test(userns) && hostUser !== null && userns !== hostUser;
    const unreadable = approved !== null && seen.some(([p, h]) => p === approved.path && h === "");
    collected.push({
      name: "userns_via_approved_profile",
      expectation: "allowed",
      sandbox: !ownNs ? "no_user_namespace" : !noCaps ? `capabilities ${capEff ?? "?"}` : match ? "approved_bwrap" : seen.length ? "other_bwrap" : "bwrap_not_visible",
      positive_control: approved !== null && hostUser !== null ? "ok" : "failed",
      pass: ownNs && noCaps && match,
      ...(unreadable || approved === null || (seen.length === 0 && ownNs && noCaps) ? { inconclusive: true } : {}),
      detail: `userns ${userns ?? "?"} (host ${hostUser ?? "?"}), CapEff ${capEff ?? "?"}, bwrap seen ${seen.map(([p, h]) => `${p} ${h ? h.slice(0, 12) : "(hash unreadable)"}`).join(", ") || "none"}; approved ${approved ? `${approved.path} ${approved.sha256.slice(0, 12)}` : "unreadable"}`.slice(0, 500),
    });
  }
  {
    // Row 2: outside the sandbox, a plain unprivileged user namespace is refused while the restriction is on.
    const restriction = usernsRestriction();
    if (restriction === "1") {
      const out = (await control(LINUX_UNSHARE_SCRIPT)).stdout.trim();
      const refused = out.startsWith("UNSHARE_FAIL:");
      collected.push({ name: "restriction_effective_outside_profile", expectation: "denied", sandbox: out.startsWith("UNSHARE_OK") ? "allowed" : refused ? "denied" : "unknown", positive_control: "n/a", pass: refused, ...(out === "UNSHARE_MISSING" ? { inconclusive: true } : {}), detail: out.slice(0, 200) });
    } else {
      collected.push({ name: "restriction_effective_outside_profile", expectation: "denied", sandbox: "not_applicable", positive_control: "n/a", pass: true, detail: restriction === null ? "this kernel has no AppArmor user-namespace restriction" : `kernel.apparmor_restrict_unprivileged_userns is ${restriction}: no restriction to scope (a custodian refuses protected reviews)` });
    }
  }
  {
    // Row 3: recorded, never passed or failed — a nested user namespace inside the sandbox is the known residual.
    const out = (await sb(LINUX_UNSHARE_SCRIPT)).stdout.trim();
    const possible = out.startsWith("UNSHARE_OK") ? "yes" : out.startsWith("UNSHARE_FAIL:") ? "no" : "unknown";
    collected.push({ name: "nested_userns_noted", expectation: "denied", sandbox: possible === "yes" ? "allowed" : possible === "no" ? "denied" : "unknown", positive_control: "n/a", pass: true, detail: `nested user namespace possible: ${possible} (recorded, not passed or failed; the known residual) ${out.slice(0, 120)}` });
  }
  return collected;
}

/**
 * Load the stored S1 self-test or run (and store) a new one. Only a complete run is stored:
 * a cancelled self-test throws SelfTestInterruptedError and stores nothing; one with a
 * timed-out or unlaunchable probe is returned (it fails S1 now) but not stored, so the next
 * review re-runs it (F10). A completed failure is stored like any other result.
 */
export async function ensureSelfTest(o: SelfTestOptions & { selftestDir: string }): Promise<{ record: SelfTestRecord; ran: boolean }> {
  const iso: IsolationArgvInput = { mode: o.mode, backend: o.backend, installDir: o.probe.installDir, webSearchDisabledValue: o.probe.compat.webSearchDisabledValue, acceptanceId: o.acceptanceId ?? null };
  const existing = await loadSelfTest(o.selftestDir, o.probe.version, iso);
  if (existing) return { record: existing, ran: false };
  const record = await runSelfTest(o);
  await storeSelfTest(o.selftestDir, record);
  return { record, ran: true };
}

export async function readSelfTestFile(path: string): Promise<SelfTestRecord> {
  return SelfTestRecordSchema.parse(JSON.parse(await readFile(path, "utf8")));
}
