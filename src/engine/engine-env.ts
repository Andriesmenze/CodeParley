// The engine's trusted environment for one call (plan §7, §8.2, §15; M1.5). Everything here
// comes from trusted configuration, launch arguments and the run store — never from tool
// arguments. Configuration is re-read on every call so a changed allowed root or client-roots
// mode takes effect at the next operation (MR-H); nothing depends on the working directory.

import { chmod, lstat, mkdir, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DomainError } from "../common/errors.js";
import { fsTypeOf } from "../workspace/fs-types.js";
import { isUuid } from "../common/ids.js";
import { loadConfig, type LoadedConfig } from "../config/load-config.js";
import type { LaunchArgs } from "../config/launch-args.js";
import { buildChildEnv, lookupEnv } from "../process/env.js";
import { resolveNativeExecutable } from "../process/native-resolve.js";
import { canonicalizePath, isContainedIn } from "../workspace/paths.js";
import { computeAllowedRoots, defaultHardExclusions } from "../workspace/scope.js";
import { REPO_KEY_RE, canonicalPathKey, defaultDataHomes, runPaths, type RunPaths, type StoreLayout } from "../store/paths.js";
import { readMeta } from "../store/state-store.js";
import type { LockDeps } from "../store/locks.js";
import type { Liveness, OwnerRecord } from "../store/owner.js";
import type { RunMeta } from "../schemas/run-state.js";
import type { HostDisclosure } from "../policy/host-disclosure.js";
import { withHeldConfig, type ChecksEngineContext, type ChecksTestHooks } from "./checks-operation.js";
import { withHeldReviewConfig, type ReviewEngineContext, type ReviewTestHooks } from "./review-operation.js";
import type { RespondTestHooks } from "./respond.js";
import type { ContinuationTestHooks } from "./continuation.js";
import { custodianPresence, type CustodianTestHooks } from "../custodian/protected-loops.js";
import type { EvidenceSelection } from "./custodian-evidence.js";
import { HARD_MAX_EXECUTIONS_PER_RUN, HARD_MAX_REVIEWS_PER_RUN } from "./hard-limits.js";

/** Hard bounds on how long a tool call may wait (plan D-22: 45 s default, 50 s max). */
export const HARD_MAX_WAIT_SECONDS = 50;
export const HARD_DEFAULT_WAIT_SECONDS = 45;

/** TEST ONLY hooks threaded into the engine contexts (fake Codex, scripted process tables). */
export interface EngineTestHooks {
  review?: ReviewTestHooks;
  checks?: ChecksTestHooks;
  /** respond_to_review fault injection (Phase 2.1). */
  respond?: RespondTestHooks;
  classify?: (owner: OwnerRecord) => Promise<Liveness>;
  lockDeps?: LockDeps;
  /** Interval of the cross-process cancellation-request watcher (default 1000 ms). */
  cancelPollMs?: number;
  /** Same-session continuation (Phase 3.3a): process identity, liveness and the controller clock. */
  continuation?: ContinuationTestHooks;
  /** P3.4C-0: the (simulated) grant custodian and the platform the protected-loop gate decides for. */
  custodian?: CustodianTestHooks;
  /** Phase 4: the fixer run of a delegated fix (the real one is Increment 1's launchFixer, verified on the VM). */
  // (Typed structurally: this module must not import the fixer, which no hook or helper path may reach.)
  fix?: { launch?: (req: never) => Promise<unknown> };
}

/** Process-wide inputs: launch arguments, the server environment and this server's identity. */
export interface EngineEnv {
  launch: LaunchArgs;
  sourceEnv: NodeJS.ProcessEnv;
  owner: OwnerRecord;
  testHooks?: EngineTestHooks;
  /** P3.4C-4: the custodian surface this process's account reads a protected run's configuration on — the operator's
   * own commands (decide, amend, loop resume) run as the operator account, which reaches only the operator pipe (the
   * P3.4C-3 `asOperator` rule); every engine and session process reads the implementer surface (the default). */
  custodianReadSurface?: "operator" | "implementer";
}

/** Trusted configuration as it is NOW (re-read per call). */
export interface Loaded {
  env: EngineEnv;
  cfg: LoadedConfig;
  layout: StoreLayout;
  dataHome: string;
  /** Canonical allowed roots after hard exclusions (the only scope authority, D-03). */
  allowedRoots: string[];
  waits: { defaultSeconds: number; maxSeconds: number };
}

export async function loadEngine(env: EngineEnv): Promise<Loaded> {
  const cfg = await loadConfig(env.launch, env.sourceEnv);
  if (process.platform === "linux") await ensurePrivateDataHome(cfg.dataHome);
  const allowedRoots = await computeAllowedRoots(cfg.configuredRoots, cfg.launchRoots, defaultHardExclusions(env.sourceEnv, cfg.dataHome, defaultDataHomes(env.sourceEnv)), (p) => canonicalizePath(p));
  const maxSeconds = Math.min(cfg.config.waits.max_wait_seconds, HARD_MAX_WAIT_SECONDS);
  const defaultSeconds = Math.min(cfg.config.waits.default_wait_seconds, maxSeconds, HARD_DEFAULT_WAIT_SECONDS);
  return { env, cfg, layout: cfg.layout, dataHome: cfg.dataHome, allowedRoots, waits: { defaultSeconds, maxSeconds } };
}

/**
 * Linux (plan §1.13): the data home holds repository content (exports), prompts, Codex output,
 * check logs and the trust records, so it must be private to this user — on Windows the per-user
 * %LOCALAPPDATA% ACLs give that. It is created with mode 0700; an existing one is refused when
 * it is not a directory owned by this user, is writable by others, or lies on a file system
 * whose semantics the store's commit point cannot rely on (workspace/fs-types.ts); one that is
 * readable by others is made private (it is ours: every file inside is CodeParley's).
 */
export async function ensurePrivateDataHome(dataHome: string): Promise<void> {
  const fsType = await fsTypeOf(dataHome);
  if (fsType && fsType.status === "refused") {
    throw new DomainError("CONFIG_INVALID", `the data home ${dataHome} is on a file system CodeParley does not support on Linux (${fsType.name}); use --home or XDG_STATE_HOME to put it on a local Linux file system`);
  }
  let st = await lstat(dataHome).catch(() => null);
  if (!st) {
    await mkdir(dataHome, { recursive: true, mode: 0o700 });
    st = await lstat(dataHome);
  }
  const uid = process.getuid?.();
  if (!st.isDirectory()) throw new DomainError("CONFIG_INVALID", `the data home ${dataHome} is not a directory`);
  if (uid !== undefined && st.uid !== uid) throw new DomainError("CONFIG_INVALID", `the data home ${dataHome} is owned by another user (uid ${st.uid}); it must belong to the user running CodeParley`);
  if ((st.mode & 0o022) !== 0) throw new DomainError("CONFIG_INVALID", `the data home ${dataHome} is writable by other users (mode ${(st.mode & 0o777).toString(8)}); run \`chmod 700 ${dataHome}\``);
  if ((st.mode & 0o077) !== 0) await chmod(dataHome, 0o700);
}

const gitCache = new Map<string, string>();

/** The native git executable (configured, else PATH). */
export async function gitExeOf(le: Loaded): Promise<string> {
  const configured = le.env.launch.git ?? null;
  const key = configured ?? "";
  const hit = gitCache.get(key);
  if (hit) return hit;
  const g = await resolveNativeExecutable("git", { configured, env: buildChildEnv({ source: le.env.sourceEnv }).env });
  if (!g.ok || !g.path) throw new DomainError("GIT_NOT_FOUND", g.error ?? "git was not found");
  gitCache.set(key, g.path);
  return g.path;
}

/** Wait bound for a call: the requested seconds, clamped to [0, max]; default when absent. */
export function waitMsFor(le: Loaded, requested: number | undefined): number {
  const s = requested === undefined ? le.waits.defaultSeconds : Math.max(0, Math.min(requested, le.waits.maxSeconds));
  return Math.round(s * 1000);
}

// ---------------------------------------------------------------------------
// Runs in the store
// ---------------------------------------------------------------------------

export interface RunHandle {
  runId: string;
  repoKey: string;
  paths: RunPaths;
  meta: RunMeta;
}

/** Run ids are UUIDs (never paths): anything else is refused before touching the store. */
export function assertRunId(runId: string): void {
  if (!isUuid(runId)) throw new DomainError("INVALID_ARGUMENT", "run_id must be a run id returned by create_review_run");
}

/** Locate a run by id under runs/<repo-key>/<run-id>. */
export async function findRun(le: Loaded, runId: string): Promise<RunHandle> {
  assertRunId(runId);
  const runsDir = join(le.dataHome, "runs");
  const keys = await readdir(runsDir).catch(() => [] as string[]);
  for (const repoKey of keys) {
    if (!REPO_KEY_RE.test(repoKey)) continue;
    const paths = runPaths(le.dataHome, repoKey, runId);
    const meta = await readMeta(paths).catch(() => null);
    if (meta && meta.run_id === runId) return { runId, repoKey, paths, meta };
  }
  throw new DomainError("RUN_NOT_FOUND", `run ${runId} was not found`);
}

/** Every run in the store whose repository lies inside `roots` (newest first). */
export async function listRuns(le: Loaded, roots: readonly string[]): Promise<RunHandle[]> {
  const runsDir = join(le.dataHome, "runs");
  const out: RunHandle[] = [];
  for (const repoKey of await readdir(runsDir).catch(() => [] as string[])) {
    if (!REPO_KEY_RE.test(repoKey)) continue;
    for (const runId of await readdir(join(runsDir, repoKey)).catch(() => [] as string[])) {
      if (!isUuid(runId)) continue;
      const paths = runPaths(le.dataHome, repoKey, runId);
      const meta = await readMeta(paths).catch(() => null);
      if (!meta || meta.run_id !== runId) continue;
      if (!roots.some((r) => isContainedIn(meta.repository_root, r))) continue;
      out.push({ runId, repoKey, paths, meta });
    }
  }
  return out.sort((a, b) => b.meta.created_at.localeCompare(a.meta.created_at));
}

export function repoKeyOf(repositoryRoot: string): string {
  return canonicalPathKey(repositoryRoot);
}

// ---------------------------------------------------------------------------
// Engine contexts for a run (one place builds them; tools never do)
// ---------------------------------------------------------------------------

interface RunBudgets {
  max_reviews_per_run?: number;
  max_check_executions_per_run?: number;
}

/** Budgets for a run: trusted configuration, lowered (never raised) by the run's own overrides. */
/**
 * P3.4C-3 C4: the limits the starts apply — the configuration lowered by the run's overrides and by the engine's hard
 * caps. Every report and the routing use these (on a protected run, the custodian's own limits instead), so routing
 * never requests an operation a start would refuse.
 */
export function effectiveBudgets(le: Loaded, meta: RunMeta): { max_reviews_per_run: number; max_check_executions_per_run: number } {
  const b = runBudgets(le, meta);
  return { max_reviews_per_run: Math.min(b.max_reviews_per_run, HARD_MAX_REVIEWS_PER_RUN), max_check_executions_per_run: Math.min(b.max_check_executions_per_run, HARD_MAX_EXECUTIONS_PER_RUN) };
}

/** The run's declared budgets: the configuration lowered by its overrides (the custodian's `open` declaration). */
export function runBudgets(le: Loaded, meta: RunMeta): { max_reviews_per_run: number; max_check_executions_per_run: number } {
  const b = ((meta as { budgets?: RunBudgets }).budgets ?? {}) as RunBudgets;
  const cfg = le.cfg.config.budgets;
  return {
    max_reviews_per_run: Math.min(cfg.max_reviews_per_run, b.max_reviews_per_run ?? Infinity),
    max_check_executions_per_run: Math.min(cfg.max_check_executions_per_run, b.max_check_executions_per_run ?? Infinity),
  };
}

/** P3.4C-3: how an engine call asks whether this run's evidence goes through the custodian (§5.4). */
export function evidenceSelection(le: Loaded, run: RunHandle): EvidenceSelection {
  const t = le.env.testHooks;
  return { custodian: t?.custodian, presence: () => custodianPresence(t !== undefined, t?.custodian), repositoryRoot: run.meta.repository_root, runId: run.runId, runJson: { path: run.paths.runJson, meta: run.meta } };
}

/**
 * The checks context of a run. P3.4C-4: on a PROTECTED run its trusted configuration — the checks, the floor, the capture
 * rules — is the custodian's (read again on every use; the local files are never read); an attended run's is the local
 * files (Phase 2).
 */
export async function checksContext(le: Loaded, run: RunHandle): Promise<ChecksEngineContext> {
  const t = le.env.testHooks;
  return withHeldConfig({
    dataHome: le.dataHome,
    trustProjectsPath: le.layout.trustProjects,
    watchedTrustedFiles: [le.cfg.launch.configFile ?? le.layout.configFile, le.layout.trustIsolation],
    runPaths: run.paths,
    meta: run.meta,
    gitExe: await gitExeOf(le),
    rules: le.cfg.config.capture,
    owner: le.env.owner,
    budgets: { max_check_executions_per_run: runBudgets(le, run.meta).max_check_executions_per_run },
    sourceEnv: le.env.sourceEnv,
    ...(t?.lockDeps ? { lockDeps: t.lockDeps } : {}),
    ...(t?.classify ? { classify: t.classify } : {}),
    ...(t?.custodian ? { custodian: t.custodian } : {}),
    custodianPresence: () => custodianPresence(t !== undefined, t?.custodian),
    ...(le.env.custodianReadSurface ? { custodianSurface: le.env.custodianReadSurface } : {}),
    ...(t?.checks ? { testHooks: t.checks } : {}),
  });
}

/** The review context of a run (P3.4C-4: protected-aware as `checksContext`, with the isolation basis and the approved
 * Codex installation the custodian holds). */
export async function reviewContext(le: Loaded, run: RunHandle): Promise<ReviewEngineContext> {
  const t = le.env.testHooks;
  const codex = { ...le.cfg.config.codex, ...(le.env.launch.codex ? { executable: le.env.launch.codex } : {}) };
  return withHeldReviewConfig({
    dataHome: le.dataHome,
    runPaths: run.paths,
    meta: run.meta,
    gitExe: await gitExeOf(le),
    rules: le.cfg.config.capture,
    owner: le.env.owner,
    trustProjectsPath: le.layout.trustProjects,
    trustIsolationPath: le.layout.trustIsolation,
    selftestDir: le.layout.selftestDir,
    codex,
    budgets: runBudgets(le, run.meta),
    sourceEnv: le.env.sourceEnv,
    ...(t?.lockDeps ? { lockDeps: t.lockDeps } : {}),
    ...(t?.classify ? { classify: t.classify } : {}),
    ...(t?.custodian ? { custodian: t.custodian } : {}),
    custodianPresence: () => custodianPresence(t !== undefined, t?.custodian),
    ...(le.env.custodianReadSurface ? { custodianSurface: le.env.custodianReadSurface } : {}),
    ...(t?.review ? { testHooks: t.review } : {}),
  });
}

// ---------------------------------------------------------------------------
// Local paths that host results never show (policy/host-disclosure.ts applies them)
// ---------------------------------------------------------------------------

const WINDOWS_HIDDEN: readonly (readonly [string, string])[] = [
  ["TEMP", "[temp]"],
  ["TMP", "[temp]"],
  ["LOCALAPPDATA", "[local app data]"],
  ["APPDATA", "[app data]"],
  ["USERPROFILE", "[user profile]"],
  ["ProgramFiles", "[program files]"],
  ["ProgramFiles(x86)", "[program files]"],
  ["SystemRoot", "[windows]"],
];

const LINUX_HIDDEN: readonly (readonly [string, string])[] = [
  ["TMPDIR", "[temp]"],
  ["XDG_STATE_HOME", "[state]"],
  ["XDG_CONFIG_HOME", "[config]"],
  ["XDG_CACHE_HOME", "[cache]"],
  ["XDG_DATA_HOME", "[data]"],
  ["XDG_RUNTIME_DIR", "[runtime dir]"],
  ["HOME", "[home]"],
];

/**
 * Directories never shown to the host, with their labels; roots that may be shown. Linux
 * also hides /tmp, and every other absolute path outside the kept roots is scrubbed by the
 * host-disclosure policy (`posixPaths`).
 */
export function pathDisclosure(le: Loaded, repositoryRoot: string | null): Pick<HostDisclosure, "keepRoots" | "hiddenDirs" | "posixPaths"> {
  const hiddenDirs: { dir: string; label: string }[] = [{ dir: le.dataHome, label: "[data home]" }];
  const linux = process.platform !== "win32";
  if (linux) hiddenDirs.push({ dir: dirname(le.cfg.layout.configFile), label: "[config]" }, { dir: "/tmp", label: "[temp]" });
  for (const [name, label] of linux ? LINUX_HIDDEN : WINDOWS_HIDDEN) {
    const v = lookupEnv(le.env.sourceEnv, name);
    if (v) hiddenDirs.push({ dir: v, label });
  }
  const codex = le.env.launch.codex ?? le.cfg.config.codex.executable;
  if (codex) hiddenDirs.push({ dir: codex, label: "[codex]" });
  return { keepRoots: [...le.allowedRoots, ...(repositoryRoot ? [repositoryRoot] : [])], hiddenDirs, posixPaths: linux };
}
