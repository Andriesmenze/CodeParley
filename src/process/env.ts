// Build EXPLICIT child-process environments. Child processes never inherit the server's
// environment blindly (plan §12.3, §14.3, K3): we start from a small per-platform allowlist,
// add only explicitly configured passthrough names, and never pass Claude/Anthropic
// credentials or other unlisted secrets. This module performs no spawning.
//
// Variable names are case-insensitive on Windows and case-sensitive on Linux (plan §1.13):
// on Windows an extra `Path` replaces an inherited `PATH`; on Linux they are two variables.

/** Windows variables a normal console program needs; copied from the source env if present. */
export const BASE_WINDOWS_VARS: readonly string[] = [
  "SystemRoot",
  "windir",
  "ComSpec",
  "PATH",
  "PATHEXT",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "HOMEDRIVE",
  "HOMEPATH",
  "SYSTEMDRIVE",
  "PROCESSOR_ARCHITECTURE",
  "NUMBER_OF_PROCESSORS",
  "USERNAME",
  "USERDOMAIN",
  "COMPUTERNAME",
];

/**
 * Linux variables a normal non-interactive program needs (the counterpart of the Windows list:
 * the user's home and XDG base directories play the role of USERPROFILE/APPDATA/LOCALAPPDATA).
 * Deliberately absent: channels to other processes and agents — SSH_AUTH_SOCK, GPG_AGENT_INFO,
 * DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR, DISPLAY, WAYLAND_DISPLAY, XAUTHORITY — and WSL
 * interop (WSL_INTEROP, WSLENV, WSL_DISTRO_NAME). A check that needs one lists it in
 * env_passthrough.
 */
export const BASE_LINUX_VARS: readonly string[] = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_COLLATE",
  "LC_NUMERIC",
  "LC_TIME",
  "LC_MONETARY",
  "TZ",
  "TMPDIR",
  "XDG_CONFIG_HOME",
  "XDG_CACHE_HOME",
  "XDG_DATA_HOME",
  "XDG_STATE_HOME",
];

/** Are variable names case-insensitive here (Windows)? */
export const ENV_NAMES_CASE_INSENSITIVE = process.platform === "win32";

/** The allowlist for this platform. */
export const BASE_VARS: readonly string[] = ENV_NAMES_CASE_INSENSITIVE ? BASE_WINDOWS_VARS : BASE_LINUX_VARS;

/** Comparison key of a variable name: lower-cased on Windows, exact on Linux. */
export function envNameKey(name: string): string {
  return ENV_NAMES_CASE_INSENSITIVE ? name.toLowerCase() : name;
}

/** Names we refuse to pass through even if explicitly listed: Claude/Anthropic creds and
 * generic secret-shaped names. CODEX_* auth is handled separately and intentionally. */
const PASSTHROUGH_DENYLIST = [
  /^ANTHROPIC_/i,
  /^CLAUDE/i,
  /(^|_)(API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PASSWORD|PASSWD|TOKEN)($|_)/i,
];

const CODEX_AUTH_VARS = ["CODEX_HOME", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"] as const;

export interface BuildEnvOptions {
  /** The environment to copy allowlisted values from. Defaults to process.env. */
  source?: NodeJS.ProcessEnv;
  /** Explicitly configured passthrough variable names (plan §7.4 codex.env_passthrough). */
  passthrough?: readonly string[];
  /** Extra variables set by the caller (e.g. NO_COLOR, CI). Always included verbatim. */
  extra?: Record<string, string>;
  /** Include Codex auth variables (CODEX_HOME/CODEX_API_KEY/CODEX_ACCESS_TOKEN) if present. */
  includeCodexAuth?: boolean;
}

export interface BuildEnvResult {
  env: Record<string, string>;
  /** Passthrough names that were refused because they matched the secret denylist. */
  refusedPassthrough: string[];
}

/**
 * Construct an explicit child environment. Deterministic and side-effect free.
 */
export function buildChildEnv(opts: BuildEnvOptions = {}): BuildEnvResult {
  const source = opts.source ?? process.env;
  const env: Record<string, string> = {};
  const refusedPassthrough: string[] = [];

  // 1. Platform basics from the source.
  for (const name of BASE_VARS) {
    const v = lookup(source, name);
    if (v !== undefined) env[name] = v;
  }

  // 2. Sensible defaults.
  env["NO_COLOR"] = "1";

  // 3. Codex auth, only when asked and never as a blind secret copy.
  if (opts.includeCodexAuth) {
    for (const name of CODEX_AUTH_VARS) {
      const v = lookup(source, name);
      if (v !== undefined) env[name] = v;
    }
  }

  // 4. Explicit passthrough allowlist, screened against the denylist.
  for (const name of opts.passthrough ?? []) {
    if (isDenied(name)) {
      refusedPassthrough.push(name);
      continue;
    }
    const v = lookup(source, name);
    if (v !== undefined) setVar(env, name, v);
  }

  // 5. Caller extras win last. Windows names are case-insensitive: an extra `Path` replaces
  // an inherited `PATH` instead of producing two entries whose winner is unspecified.
  for (const [k, v] of Object.entries(opts.extra ?? {})) setVar(env, k, v);

  return { env, refusedPassthrough };
}

/** Is this variable name refused for passthrough (Claude creds / secret-shaped)? */
export function isDenied(name: string): boolean {
  // CODEX auth vars are allowed only via includeCodexAuth, never via passthrough.
  if ((CODEX_AUTH_VARS as readonly string[]).includes(name)) return true;
  return PASSTHROUGH_DENYLIST.some((re) => re.test(name));
}

function setVar(env: Record<string, string>, name: string, value: string): void {
  if (ENV_NAMES_CASE_INSENSITIVE) {
    const lower = name.toLowerCase();
    for (const k of Object.keys(env)) if (k !== name && k.toLowerCase() === lower) delete env[k];
  }
  env[name] = value;
}

/**
 * Look a variable up with the platform's semantics: on Windows case-insensitively (returning
 * the first non-empty match), on Linux by its exact name.
 */
export function lookupEnv(source: Readonly<Record<string, string | undefined>>, name: string): string | undefined {
  const direct = source[name];
  if (direct !== undefined) return direct;
  if (!ENV_NAMES_CASE_INSENSITIVE) return undefined;
  const lower = name.toLowerCase();
  for (const key of Object.keys(source)) {
    if (key.toLowerCase() === lower) {
      const v = source[key];
      if (v !== undefined) return v;
    }
  }
  return undefined;
}

const lookup = lookupEnv;
