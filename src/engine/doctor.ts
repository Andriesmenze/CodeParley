// `doctor`: setup and host-validation diagnostics (plan §2.2 #10, §12.6, §19.4; M1.5). Read-
// only and offline: it probes the installed executables (`--version`, `exec --help`), reads
// the stored S1 self-test, configuration, roots and the store; it never runs a model call,
// the self-test or a check. Environment variable NAMES are reported, never values.

import { readFileSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { release } from "node:os";
import { join } from "node:path";
import { isDomainError } from "../common/errors.js";
import { isUuid } from "../common/ids.js";
import { TOOL_VERSION } from "../common/version.js";
import { probeCodex } from "../agents/codex/probe.js";
import { loadSelfTest } from "../agents/codex/selftest.js";
import { loadAcceptances } from "../agents/codex/isolation.js";
import { backendsFor } from "../agents/codex/argv.js";
import { runProcess } from "../process/spawn.js";
import { buildChildEnv, envNameKey } from "../process/env.js";
import { sessionReaperRunning } from "../process/session-reaper.js";
import { fsTypeOf } from "../workspace/fs-types.js";
import { readState } from "../store/state-store.js";
import { readWorktreeLock } from "../store/locks.js";
import { DATA_DIR_NAME, LEGACY_DATA_DIR_NAME, REPO_KEY_RE, runPaths } from "../store/paths.js";
import { readTextIfExists } from "../store/atomic.js";
import { gitExeOf, type Loaded } from "./engine-env.js";
import { protectedStatus, type ProtectedStatus } from "./protected-status.js";

/** Variables whose PRESENCE matters for hosts (C3, X13); values are never read out. */
const ENV_NAMES =
  process.platform === "win32"
    ? ["LOCALAPPDATA", "APPDATA", "USERPROFILE", "PATH", "PATHEXT", "SystemRoot", "TEMP", "TMP", "CODEX_HOME", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "HOMEDRIVE", "HOMEPATH", "MCP_PROTOCOL_NEGOTIATION", "CLAUDE_PROJECT_DIR"]
    : ["HOME", "PATH", "TMPDIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "LANG", "CODEX_HOME", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "WSL_DISTRO_NAME", "WSL_INTEROP", "SSH_AUTH_SOCK", "MCP_PROTOCOL_NEGOTIATION", "CLAUDE_PROJECT_DIR"];

export interface DoctorReport {
  tool_version: string;
  ok: boolean;
  problems: string[];
  /** Information that needs no action now (e.g. the legacy data-home name). */
  notes: string[];
  node: { version: string; exec_path: string; platform: string };
  data_home: { path: string; localappdata_fallback: boolean; legacy_name: boolean; exists: boolean };
  retention: {
    max_age_days: number;
    purge_on_startup: boolean;
    last_pass: { at: string; deleted: number; kept: number; skipped: number; incomplete: number; error: string | null } | null;
    pending_trash: number;
  };
  config: { path: string; client_roots: "advisory" | "strict"; waits: { default_seconds: number; max_seconds: number } };
  allowed_roots: { configured: string[]; launch: string[]; effective: string[] };
  git: { path: string | null; version: string | null; error: string | null };
  codex: {
    path: string | null;
    how: string | null;
    version: string | null;
    supported: boolean;
    error: string | null;
    install_dir: string | null;
    user_hooks_present: boolean | null;
    backends: { backend: string; gate_a: string | null; preferred: boolean; selftest: { stored: boolean; s1_available: boolean | null; profile_runs: boolean | null; failed_rows: string[]; at: string | null } }[];
    reduced_isolation_acceptances: number;
  };
  store: { runs: number; unreadable_runs: number; running_operations: number; worktree_locks: { key: string; kind: string; ownership_unresolved: boolean }[] };
  environment_names_present: string[];
  /** Linux: facts the sandbox and the store depend on (null on Windows). */
  linux: LinuxFacts | null;
}

export interface LinuxFacts {
  kernel: string;
  distribution: string | null;
  wsl: boolean;
  /** /proc/sys/user/max_user_namespaces (0 disables bubblewrap). */
  max_user_namespaces: number | null;
  /** Ubuntu: kernel.apparmor_restrict_unprivileged_userns (1 blocks unprofiled bubblewrap). */
  apparmor_restrict_unprivileged_userns: number | null;
  data_home_filesystem: string | null;
  session_reaper_running: boolean;
}

function envHas(env: NodeJS.ProcessEnv, name: string): boolean {
  const key = envNameKey(name);
  return Object.keys(env).some((k) => envNameKey(k) === key && env[k] !== undefined && env[k] !== "");
}

function readNumber(path: string): number | null {
  try {
    const n = Number(readFileSync(path, "utf8").trim());
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

/** The distribution's PRETTY_NAME from os-release(5), unquoted; null when it cannot be read. */
function osPrettyName(): string | null {
  let text: string;
  try {
    text = readFileSync("/etc/os-release", "utf8");
  } catch {
    return null;
  }
  const line = text.split("\n").find((l) => l.startsWith("PRETTY_NAME="));
  if (line === undefined) return null;
  const value = line.slice("PRETTY_NAME=".length).trim();
  const quoted = value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.endsWith(value[0]);
  return quoted ? value.slice(1, -1) : value;
}

async function linuxFacts(dataHome: string): Promise<LinuxFacts> {
  const distribution = osPrettyName();
  const kernel = release();
  const fsType = await fsTypeOf(dataHome).catch(() => null);
  return {
    kernel,
    distribution,
    wsl: /microsoft/i.test(kernel),
    max_user_namespaces: readNumber("/proc/sys/user/max_user_namespaces"),
    apparmor_restrict_unprivileged_userns: readNumber("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
    data_home_filesystem: fsType ? `${fsType.name} (${fsType.status})` : null,
    session_reaper_running: sessionReaperRunning(),
  };
}

/** package.json engines: ^22.12.0 || ^24.0.0 (an unsupported Node.js used to run silently). */
export function nodeSupported(version: string): boolean {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!m) return false;
  const [maj, min] = [Number(m[1]), Number(m[2])];
  return (maj === 22 && min >= 12) || maj === 24;
}

export async function doctor(le: Loaded): Promise<DoctorReport> {
  const problems: string[] = [];
  if (!nodeSupported(process.version)) problems.push(`Node.js ${process.version} is not supported (CodeParley needs ^22.12.0 or ^24.0.0): install a supported version`);
  const env = le.env.sourceEnv;
  if (le.allowedRoots.length === 0) problems.push("no allowed roots are configured (config.json allowed_roots or --allowed-root): every run is refused with SCOPE_NOT_CONFIGURED");

  let git: DoctorReport["git"] = { path: null, version: null, error: null };
  try {
    const p = await gitExeOf(le);
    const v = await runProcess(p, ["--version"], { env: buildChildEnv({ source: env }).env, wallMs: 15_000 });
    git = { path: p, version: v.stdout.trim() || null, error: v.status === 0 ? null : `git --version exited ${v.status}` };
  } catch (e) {
    git.error = isDomainError(e) ? `${e.code}: ${e.message}` : String(e);
    problems.push(`git: ${git.error}`);
  }

  const codexCfg = le.env.launch.codex ?? le.cfg.config.codex.executable;
  const codex: DoctorReport["codex"] = { path: null, how: null, version: null, supported: false, error: null, install_dir: null, user_hooks_present: null, backends: [], reduced_isolation_acceptances: 0 };
  try {
    const p = await probeCodex({ configured: codexCfg, sourceEnv: env, testLauncher: le.env.testHooks?.review?.codexLauncher ?? null });
    codex.path = p.launcher.exe;
    codex.how = p.how;
    codex.version = p.version;
    codex.supported = true;
    codex.install_dir = p.installDir;
    codex.user_hooks_present = p.userHooksPresent;
    const configured = process.platform === "win32" ? le.cfg.config.codex.windows_sandbox : null;
    for (const b of backendsFor()) {
      const facts = p.compat.backends[b];
      const rec = await loadSelfTest(le.layout.selftestDir, p.version, { mode: "S1", backend: b, installDir: p.installDir, webSearchDisabledValue: p.compat.webSearchDisabledValue, acceptanceId: null }).catch(() => null);
      codex.backends.push({
        backend: b,
        gate_a: facts ? `${facts.s1}: ${facts.note}` : null,
        preferred: configured ? configured === b : p.compat.preferredBackends.includes(b),
        selftest: { stored: !!rec, s1_available: rec?.s1_available ?? null, profile_runs: rec?.profile_runs ?? null, failed_rows: rec ? rec.rows.filter((r) => !r.pass).map((r) => r.name) : [], at: rec?.created_at ?? null },
      });
    }
    const pref = codex.backends.find((x) => x.preferred);
    if (pref && !pref.selftest.stored) problems.push(`no stored S1 self-test for backend ${pref.backend}: the first review runs it (about a minute) or run \`code-parley codex selftest --backend ${pref.backend}\``);
    else if (pref && pref.selftest.s1_available === false) problems.push(`the stored S1 self-test for backend ${pref.backend} FAILED (${pref.selftest.failed_rows.join(", ") || "profile rejected"}): reviews fail closed with CODEX_ISOLATION_UNAVAILABLE`);
  } catch (e) {
    codex.error = isDomainError(e) ? `${e.code}: ${e.message}` : String(e);
    // A Linux install keeps the administrator's Codex out of PATH (protected runs launch the copy the operator approved):
    // name it, so the remedy is the flag, not an installation.
    const admin = process.platform === "linux" ? await readdir("/opt/codeparley-codex").then((v) => v.filter((x) => /^\d+\.\d+\.\d+$/.test(x)).sort().at(-1), () => undefined) : undefined;
    problems.push(`codex: ${codex.error}${admin ? ` (the administrator's Codex is /opt/codeparley-codex/${admin}/bin/codex: pass --codex <it>, or set codex.executable in config.json)` : ""}`);
  }
  codex.reduced_isolation_acceptances = (await loadAcceptances(le.layout.trustIsolation).catch(() => null))?.file.records.length ?? 0;

  const store: DoctorReport["store"] = { runs: 0, unreadable_runs: 0, running_operations: 0, worktree_locks: [] };
  const runsDir = join(le.dataHome, "runs");
  for (const repoKey of (await readdir(runsDir).catch(() => [] as string[])).filter((k) => REPO_KEY_RE.test(k))) {
    for (const runId of await readdir(join(runsDir, repoKey)).catch(() => [] as string[])) {
      if (!isUuid(runId)) continue;
      store.runs++;
      const st = await readState(runPaths(le.dataHome, repoKey, runId)).catch(() => null);
      if (!st) store.unreadable_runs++;
      else store.running_operations += st.operations.filter((o) => o.status === "running").length;
    }
  }
  for (const f of await readdir(le.layout.locksDir).catch(() => [] as string[])) {
    if (!f.endsWith(".lock") || f === "retention.lock") continue;
    const l = await readWorktreeLock(join(le.layout.locksDir, f)).catch(() => null);
    if (l) store.worktree_locks.push({ key: f.replace(/\.lock$/, ""), kind: String(l.kind), ownership_unresolved: l.ownership_unresolved === true });
  }
  if (store.unreadable_runs) problems.push(`${store.unreadable_runs} run state record(s) could not be read`);
  for (const l of store.worktree_locks) if (l.ownership_unresolved) problems.push(`worktree lock ${l.key} is ownership_unresolved (a server died during checks): inspect and release with \`code-parley lock release\``);

  const notes: string[] = [];
  const linux = process.platform === "linux" ? await linuxFacts(le.dataHome) : null;
  if (linux?.max_user_namespaces === 0) problems.push("unprivileged user namespaces are disabled (user.max_user_namespaces = 0): Codex's bubblewrap sandbox cannot start, so S1 is unavailable");
  if (linux?.apparmor_restrict_unprivileged_userns === 1) notes.push("kernel.apparmor_restrict_unprivileged_userns = 1: AppArmor may stop Codex's bundled bubblewrap from creating namespaces; the S1 self-test decides (README: Linux troubleshooting)");
  if (le.cfg.legacyDataHome) notes.push(`the data home uses the legacy folder name ${LEGACY_DATA_DIR_NAME} (written by an earlier build). It keeps working; to move to the new name, close every host using CodeParley (Claude Code sessions, Claude Desktop), then rename the folder to ${DATA_DIR_NAME}`);
  const retentionCfg = le.cfg.config.retention;
  const lastRaw = await readTextIfExists(le.layout.retentionLast).catch(() => null);
  let lastPass: DoctorReport["retention"]["last_pass"] = null;
  try {
    const j = lastRaw ? (JSON.parse(lastRaw) as { at?: string; deleted?: unknown[]; kept?: unknown[]; skipped?: unknown[]; incomplete?: unknown[]; error?: string | null }) : null;
    if (j?.at) lastPass = { at: j.at, deleted: j.deleted?.length ?? 0, kept: j.kept?.length ?? 0, skipped: j.skipped?.length ?? 0, incomplete: j.incomplete?.length ?? 0, error: j.error ?? null };
  } catch {
    /* an unreadable summary is only a missing note */
  }
  const pendingTrash = (await readdir(le.layout.trashDir).catch(() => [] as string[])).length;
  if (lastPass?.error) problems.push(`the last retention pass failed: ${lastPass.error}`);
  if (pendingTrash) notes.push(`${pendingTrash} run folder(s) from an earlier purge could not be fully deleted yet (a file was held open); the next purge retries them`);

  return {
    tool_version: TOOL_VERSION,
    ok: problems.length === 0,
    problems,
    notes,
    node: { version: process.version, exec_path: process.execPath, platform: `${process.platform}-${process.arch}` },
    data_home: { path: le.dataHome, localappdata_fallback: le.cfg.usedLocalAppDataFallback, legacy_name: le.cfg.legacyDataHome, exists: !!(await stat(le.dataHome).catch(() => null)) },
    retention: { max_age_days: retentionCfg.max_age_days, purge_on_startup: retentionCfg.purge_on_startup, last_pass: lastPass, pending_trash: pendingTrash },
    config: { path: le.cfg.launch.configFile ?? le.layout.configFile, client_roots: le.cfg.config.client_roots.enforce ? "strict" : "advisory", waits: { default_seconds: le.waits.defaultSeconds, max_seconds: le.waits.maxSeconds } },
    allowed_roots: { configured: le.cfg.configuredRoots, launch: le.cfg.launchRoots, effective: le.allowedRoots },
    git,
    codex,
    store,
    environment_names_present: ENV_NAMES.filter((n) => envHas(env, n)),
    linux,
  };
}

// ---------------------------------------------------------------------------
// Phase 6 Increment 3 (contract §3.4): `doctor --protected [--repo]`
// ---------------------------------------------------------------------------

/** What the protected side adds: the status probe and the host facts the custodian depends on. Read-only, like the rest. */
export interface ProtectedDoctorFacts {
  status: ProtectedStatus;
  /** The repository-readers grant on the repository, as this account can see its access list (null: not checked / unknown). */
  readers_grant: { present: boolean | null; detail: string } | null;
  /** Linux: the custodian's admitted filesystems and the Codex bubblewrap AppArmor profile file. */
  linux: { admitted_filesystems: number | null; apparmor_profile_file: boolean } | null;
  problems: string[];
}

async function readersGrant(root: string): Promise<ProtectedDoctorFacts["readers_grant"]> {
  try {
    if (process.platform === "win32") {
      const icacls = join(process.env["SystemRoot"] ?? "C:\Windows", "System32", "icacls.exe");
      const r = await runProcess(icacls, [root], { wallMs: 15_000 });
      if (r.status !== 0) return { present: null, detail: `icacls could not read the access list (exit ${r.status})` };
      return /CodeParley Repository Readers:.*\(RX\)|CodeParley Repository Readers:\(OI\)\(CI\)\(RX\)/.test(r.stdout)
        ? { present: true, detail: "CodeParley Repository Readers may read the repository" }
        : { present: false, detail: "CodeParley Repository Readers has no read entry on the repository" };
    }
    if (process.platform === "linux") {
      const r = await runProcess("/usr/bin/getfacl", ["-p", "--omit-header", root], { wallMs: 15_000 });
      if (r.spawnError || r.status !== 0) return { present: null, detail: "getfacl could not read the access list (the acl package may be missing, or this account cannot read the repository)" };
      return /^group:codeparley-readers:r-x/m.test(r.stdout)
        ? { present: true, detail: "codeparley-readers may read the repository" }
        : { present: false, detail: "codeparley-readers has no read entry on the repository" };
    }
  } catch {
    /* unknown */
  }
  return { present: null, detail: "not checked on this platform" };
}

export async function protectedDoctor(le: Loaded, repositoryRoot: string | null): Promise<ProtectedDoctorFacts> {
  const status = await protectedStatus(le, { repositoryRoot });
  const problems: string[] = [];
  if (status.state !== "ready") problems.push(`custodian: ${status.state.replace("_", " ")} — ${status.explanation[0] ?? ""}`);
  for (const r of status.repository?.records ?? []) if (r.required && r.state !== "in_force") problems.push(`${r.record.replace("_", " ")}: ${r.state.replace("_", " ")} (${r.detail}) — ${r.restore ?? ""}`);
  const readers = repositoryRoot && status.state !== "not_installed" && status.state !== "unsupported_platform" ? await readersGrant(repositoryRoot) : null;
  if (readers?.present === false) problems.push(`repository readers grant: missing — an administrator runs ${process.platform === "linux" ? "sudo bash codeparley-installer.sh grant-repository --path <repository>" : "codeparley-installer.ps1 grant-repository -Path <repository> (elevated)"}`);
  let linux: ProtectedDoctorFacts["linux"] = null;
  if (process.platform === "linux" && status.state !== "not_installed") {
    let admitted: number | null = null;
    try {
      const o = JSON.parse(readFileSync("/etc/codeparley/filesystems.json", "utf8")) as { filesystems?: unknown[] };
      admitted = Array.isArray(o.filesystems) ? o.filesystems.length : null;
    } catch {
      /* unknown */
    }
    let profile = false;
    try {
      profile = readFileSync("/etc/apparmor.d/codeparley-codex-bwrap").length > 0;
    } catch {
      /* absent */
    }
    linux = { admitted_filesystems: admitted, apparmor_profile_file: profile };
    if (admitted === 0) problems.push("no filesystem is admitted for the custodian (/etc/codeparley/filesystems.json): the installer's grant-repository admits the repository's");
  }
  return { status, readers_grant: readers, linux, problems };
}
