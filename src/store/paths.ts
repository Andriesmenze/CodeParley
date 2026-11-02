// Store layout and key derivation (plan §15.1, §15.2). Runtime state lives outside any
// repository so the extension never creates untracked files in the user's tree.
//
// Locations (plan §1.13):
//  - Windows: everything under %LOCALAPPDATA%\CodeParley (config.json included), as in M1.
//  - Linux (XDG Base Directory specification): the user-edited configuration at
//    $XDG_CONFIG_HOME/code-parley/config.json (default ~/.config/code-parley/config.json);
//    everything CodeParley writes — trust records, self-tests, locks, logs, runs — under
//    $XDG_STATE_HOME/code-parley (default ~/.local/state/code-parley), created private (0700).
//    An XDG variable that is not an absolute path is ignored, as the specification requires.
//  - `--home <dir>` (both platforms): one directory holding everything, config.json included.

import { statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { sha256OfString } from "../common/hash.js";
import { pathKey } from "../workspace/paths.js";

/** The data directory name (M1.6: CodeParley). */
export const DATA_DIR_NAME = "CodeParley";
/** The data directory name used by M1.0–M1.5 builds (before the rename, plan §1.12). */
export const LEGACY_DATA_DIR_NAME = "AIReviewLoop";
/** The directory name under the XDG configuration and state directories on Linux. */
export const XDG_DIR_NAME = "code-parley";

const WIN = process.platform === "win32";

/** An XDG base directory: the variable when it is an absolute path, else $HOME/<fallback>. */
function xdgBase(env: NodeJS.ProcessEnv, name: string, fallback: string): { dir: string; usedFallback: boolean } {
  const v = env[name];
  if (v && isAbsolute(v)) return { dir: v, usedFallback: false };
  const home = env["HOME"];
  if (home && isAbsolute(home)) return { dir: join(home, fallback), usedFallback: false };
  return { dir: join(homedir(), fallback), usedFallback: true };
}

/** Linux: the default configuration file and data (state) directory. */
export function linuxLocations(env: NodeJS.ProcessEnv = process.env): { configFile: string; dataHome: string; usedFallback: boolean } {
  const config = xdgBase(env, "XDG_CONFIG_HOME", ".config");
  const state = xdgBase(env, "XDG_STATE_HOME", join(".local", "state"));
  return { configFile: join(config.dir, XDG_DIR_NAME, "config.json"), dataHome: join(state.dir, XDG_DIR_NAME), usedFallback: config.usedFallback || state.usedFallback };
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** The local application-data base: %LOCALAPPDATA%, else %USERPROFILE%\AppData\Local. */
function localBase(env: NodeJS.ProcessEnv): { base: string; usedFallback: boolean } {
  const local = env["LOCALAPPDATA"];
  if (local) return { base: local, usedFallback: false };
  return { base: join(env["USERPROFILE"] ?? "C:\\Users\\Default", "AppData", "Local"), usedFallback: true };
}

/**
 * The default CodeParley locations that may never be, or contain, an allowed root, whether or
 * not they exist: Windows — the data home under both names (current and legacy); Linux — the
 * data (state) directory and the configuration directory.
 */
export function defaultDataHomes(env: NodeJS.ProcessEnv = process.env): string[] {
  if (!WIN) {
    const l = linuxLocations(env);
    return [l.dataHome, join(l.configFile, "..")];
  }
  const { base } = localBase(env);
  return [join(base, DATA_DIR_NAME), join(base, LEGACY_DATA_DIR_NAME)];
}

/**
 * Resolve the data home (plan §15.1, §1.12, §1.13): --home override; else, on Windows,
 * %LOCALAPPDATA%\CodeParley (USERPROFILE fallback when LOCALAPPDATA is missing), and on Linux
 * $XDG_STATE_HOME/code-parley with the configuration in $XDG_CONFIG_HOME/code-parley. For data
 * written by M1.0–M1.5 builds (Windows), an existing `AIReviewLoop` folder is used while no
 * `CodeParley` folder exists, so earlier runs, approvals and acceptances stay readable; `doctor`
 * reports it. Every process applies the same rule, so servers and the CLI always agree on one
 * store; renaming the folder (with no host running) moves every process to the new name at its
 * next call.
 */
export function resolveDataHome(opts: { home?: string | null; env?: NodeJS.ProcessEnv } = {}): {
  dataHome: string;
  /** The default configuration file (`<data home>/config.json` on Windows and with --home). */
  configFile: string;
  usedFallback: boolean;
  /** True when the legacy `AIReviewLoop` folder is in use. */
  legacyName: boolean;
} {
  if (opts.home) return { dataHome: opts.home, configFile: join(opts.home, "config.json"), usedFallback: false, legacyName: false };
  if (!WIN) {
    const l = linuxLocations(opts.env ?? process.env);
    return { dataHome: l.dataHome, configFile: l.configFile, usedFallback: l.usedFallback, legacyName: false };
  }
  const { base, usedFallback } = localBase(opts.env ?? process.env);
  const preferred = join(base, DATA_DIR_NAME);
  const legacy = join(base, LEGACY_DATA_DIR_NAME);
  if (!isDirectory(preferred) && isDirectory(legacy)) return { dataHome: legacy, configFile: join(legacy, "config.json"), usedFallback, legacyName: true };
  return { dataHome: preferred, configFile: join(preferred, "config.json"), usedFallback, legacyName: false };
}

export interface StoreLayout {
  dataHome: string;
  configFile: string;
  trustDir: string;
  trustProjects: string;
  trustIsolation: string;
  selftestDir: string;
  locksDir: string;
  logsDir: string;
  runsDir: string;
  /** Run directories being purged (renamed here first, then deleted; plan §15.6, §1.12). */
  trashDir: string;
  /** Summary of the last retention pass (written by the server at startup). */
  retentionLast: string;
}

/** The store layout; `configFile` defaults to `<data home>/config.json` (Windows, --home). */
export function storeLayout(dataHome: string, configFile: string = join(dataHome, "config.json")): StoreLayout {
  return {
    dataHome,
    configFile,
    trustDir: join(dataHome, "trust"),
    trustProjects: join(dataHome, "trust", "projects.json"),
    trustIsolation: join(dataHome, "trust", "isolation.json"),
    selftestDir: join(dataHome, "selftest"),
    locksDir: join(dataHome, "locks"),
    logsDir: join(dataHome, "logs"),
    runsDir: join(dataHome, "runs"),
    trashDir: join(dataHome, "runs", ".trash"),
    retentionLast: join(dataHome, "logs", "retention-last.json"),
  };
}

/**
 * A stable, filesystem-safe key for a canonical worktree/repository path: case-insensitive on
 * Windows (the M1 form, unchanged), exact on Linux.
 */
export function canonicalPathKey(canonicalPath: string): string {
  return sha256OfString(pathKey(canonicalPath)).slice(0, 16);
}

/** Repository keys are 16 lowercase hex characters (canonicalPathKey). */
export const REPO_KEY_RE = /^[0-9a-f]{16}$/;

export interface RunPaths {
  runDir: string;
  runJson: string;
  stateJson: string;
  lockDir: string;
  opsDir: string;
  exportsDir: string;
  baselineDir: string;
}

export function runPaths(dataHome: string, repoKey: string, runId: string): RunPaths {
  const runDir = join(dataHome, "runs", repoKey, runId);
  return {
    runDir,
    runJson: join(runDir, "run.json"),
    stateJson: join(runDir, "state.json"),
    lockDir: join(runDir, ".lock"),
    opsDir: join(runDir, "ops"),
    exportsDir: join(runDir, "exports"),
    baselineDir: join(runDir, "baseline"),
  };
}

/** Per-worktree execution lock file path (plan §15.4). */
export function worktreeLockPath(dataHome: string, worktreeKey: string): string {
  return join(dataHome, "locks", `${worktreeKey}.lock`);
}

/** The store-wide retention lock (one retention pass at a time across processes). */
export function retentionLockPath(dataHome: string): string {
  return join(dataHome, "locks", "retention.lock");
}
