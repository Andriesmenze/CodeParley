// PURE argv builders for Codex (plan §12.4, X19, D-25). No I/O.
//
// This is the one place that decides which flags reach Codex, so it is the one place that
// enforces the isolation contract:
//  - the S1 profile is an allowlist of read roots (`:minimal`, `:workspace_roots`, the
//    Codex installation) and NEVER grants `:root`, a drive root or the filesystem root;
//  - no danger/bypass flag, `workspace-write`, `danger-full-access`, `--add-dir` or
//    `--worktree` is ever emitted;
//  - S2 (`--sandbox read-only`, unrestricted reads) is emitted only when the caller passes
//    an acceptance id (the isolation decision, agents/codex/isolation.ts, requires a
//    CLI-written acceptance record for it).
// The flags are exactly the ones validated by Gate A on Codex 0.160.0 with the `mxc`
// backend (spike/lib/profiles.mjs) and, on Linux, by the Linux Gate A with the `bwrap`
// backend (plan §1.13): Codex's bubblewrap sandbox, pinned with
// `features.use_legacy_landlock=false` so that a changed default can never select the legacy
// Landlock path the self-test did not exercise. Version-specific values (the web_search enum)
// come from the compatibility table, never from here. The pure functions take the platform's
// path rules explicitly (default: this host's), so each platform's rules are testable anywhere.

import { sha256OfCanonicalJson } from "../../common/hash.js";
import type { IsolationMode } from "../../schemas/review.js";

export type GrantRules = "win32" | "posix";
const HOST_RULES: GrantRules = process.platform === "win32" ? "win32" : "posix";

/** Flags that must never appear in any Codex argv. */
export const FORBIDDEN_FLAGS: readonly string[] = [
  "--dangerously-bypass-approvals-and-sandbox",
  "--dangerously-bypass-hook-trust",
  "--approve-for-me",
  "--worktree",
  "--add-dir",
  "--search",
  "--yolo",
  "--full-auto",
  "-a",
  "--ask-for-approval",
];

/** Sandbox modes that are never emitted (unrestricted writes or no sandbox). */
export const FORBIDDEN_SANDBOX_MODES: readonly string[] = ["workspace-write", "danger-full-access"];

export const WINDOWS_BACKENDS = ["mxc", "elevated", "unelevated"] as const;
export type WindowsBackend = (typeof WINDOWS_BACKENDS)[number];
/** Linux backends: Codex's bubblewrap sandbox (plan §1.13). */
export const LINUX_BACKENDS = ["bwrap"] as const;
export type LinuxBackend = (typeof LINUX_BACKENDS)[number];
export type SandboxBackend = WindowsBackend | LinuxBackend;

/** The sandbox backends Codex offers on a platform. */
export function backendsFor(platform: NodeJS.Platform = process.platform): readonly SandboxBackend[] {
  return platform === "win32" ? WINDOWS_BACKENDS : platform === "linux" ? LINUX_BACKENDS : [];
}

/** The path rules a backend's grants are written in. */
export function grantRulesOf(backend: SandboxBackend): GrantRules {
  return (LINUX_BACKENDS as readonly string[]).includes(backend) ? "posix" : "win32";
}

export const PROFILE_NAME = "ai_review";

export class UnsafeArgvError extends Error {}

/** Throw if a filesystem grant map names the whole-disk root or any concrete path that is not a safe, canonical, non-root directory. */
export function assertNoRootRead(fsMap: Readonly<Record<string, string>>, rules: GrantRules = HOST_RULES): void {
  for (const key of Object.keys(fsMap)) {
    const k = key.trim().toLowerCase();
    if (k === ":root" || k === "root") throw new UnsafeArgvError("S1 profile must never grant `:root` read access (plan X19, D-25)");
    if (k.startsWith(":")) {
      if (k !== ":minimal" && k !== ":workspace_roots") throw new UnsafeArgvError(`S1 profile may not use the special grant ${key}`);
      continue;
    }
    const problem = readGrantProblem(key, rules);
    if (problem) throw new UnsafeArgvError(`S1 profile must not allowlist ${JSON.stringify(key)}: ${problem}`);
  }
}

/**
 * Security classification of a concrete read grant (F1). Pure and spelling-strict: any
 * spelling that is or could alias a filesystem root — `L:\`, `L:`, `L:\Tools\..`, `L:\.`,
 * `\\?\L:\`, `\\.\…`, `\??\…`, forward slashes, empty or dot segments, a UNC share root —
 * is refused rather than interpreted. Names are NOT judged by appearance: whether a
 * segment such as `PROGRA~1` is a short-name alias is a filesystem fact. The probe only
 * hands out grants that exist and are a fixed point of the OS's canonical resolution
 * (`resolveInstallDir`, `assertCanonicalGrant`), which expands genuine 8.3 aliases and
 * resolves junctions; a literal name like `Codex~2026.10` is then just a name.
 */
/** Does `s` contain a control character (U+0000 to U+001F; DEL too when `del`) or one of `chars`? */
function hasForbiddenChar(s: string, chars: string, del: boolean): boolean {
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (code <= 0x1f || (del && code === 0x7f) || chars.includes(c)) return true;
  }
  return false;
}

export function readGrantProblem(p: string, rules: GrantRules = HOST_RULES): string | null {
  if (rules === "posix") return posixGrantProblem(p);
  if (p.length === 0) return "empty path";
  if (hasForbiddenChar(p, "\"*?<>|'", false)) return "contains characters that are not allowed";
  if (/^\\\\[?.]\\|^\\\?\?\\/.test(p)) return "device or extended-length namespace prefix";
  if (p.includes("/")) return "not in canonical form (forward slash)";
  const split = windowsGrantSegments(p);
  if (typeof split === "string") return split;
  return windowsSegmentsProblem(split);
}

/** The segments below the drive or UNC share of a Windows grant, or why it has none. */
function windowsGrantSegments(p: string): string[] | string {
  if (/^[A-Za-z]:\\/.test(p)) {
    if (p.indexOf(":", 2) !== -1) return "':' after the drive designator";
    return p.slice(3).split("\\");
  }
  if (!/^\\\\[^\\]/.test(p)) return "not an absolute drive or UNC path";
  const parts = p.slice(2).split("\\");
  if (parts.length < 3) return "a UNC server or share root";
  if (p.indexOf(":") !== -1) return "':' in a UNC path";
  if (parts[0] === "" || parts[1] === "") return "malformed UNC path";
  return parts.slice(2);
}

/** Why these Windows grant segments could alias a root or another name (null: they cannot). */
function windowsSegmentsProblem(segments: readonly string[]): string | null {
  if (segments.length === 0 || (segments.length === 1 && segments[0] === "")) return "a filesystem root";
  for (const s of segments) {
    if (s === "") return "empty segment (doubled or trailing separator)";
    if (s === "." || s === "..") return "dot segment (may alias a parent or root)";
    if (/[ .]$/.test(s)) return "segment ends with a dot or space";
  }
  return null;
}

/**
 * POSIX (Linux) counterpart of the Windows classification: spelling-strict as well. Anything
 * that is or could alias the filesystem root — `/`, an empty, `.` or `..` segment, a doubled or
 * trailing separator, a relative path — is refused rather than interpreted; the probe hands
 * out only grants that are fixed points of realpath (`assertCanonicalGrant`).
 */
export function posixGrantProblem(p: string): string | null {
  if (p.length === 0) return "empty path";
  if (hasForbiddenChar(p, "\"'\\", true)) return "contains characters that are not allowed";
  if (!p.startsWith("/")) return "not an absolute path";
  if (p === "/") return "the filesystem root";
  const segments = p.slice(1).split("/");
  for (const s of segments) {
    if (s === "") return "empty segment (doubled or trailing separator)";
    if (s === "." || s === "..") return "dot segment (may alias a parent or root)";
  }
  return null;
}

function assertTomlLiteral(p: string, label: string): void {
  if (p.length === 0) throw new UnsafeArgvError(`${label} must be a non-empty path`);
  // Single-quoted TOML literals cannot contain a single quote or control characters.
  if (p.includes("'") || /[\u0000-\u001f]/.test(p)) throw new UnsafeArgvError(`${label} cannot be expressed safely as a TOML literal: ${JSON.stringify(p)}`);
}

/**
 * A read grant must not contain (be an ancestor of, or equal to) a protected path: the
 * user profile or home, the run store, the repository, the Codex home. Case-insensitive on
 * Windows, exact on Linux; separator-aware; both sides canonical. Returns the protected path
 * it would expose, or null.
 */
export function grantExposes(grant: string, protectedPaths: readonly string[], rules: GrantRules = HOST_RULES): string | null {
  if (rules === "posix") {
    const g = grant.replace(/\/+$/, "");
    for (const p of protectedPaths) {
      const q = p.replace(/\/+$/, "");
      if (q === g || q.startsWith(`${g}/`)) return p;
    }
    return null;
  }
  const g = grant.replace(/\\$/, "").toLowerCase();
  for (const p of protectedPaths) {
    const q = p.replace(/\\$/, "").toLowerCase();
    if (q === g || q.startsWith(`${g}\\`)) return p;
  }
  return null;
}

/** The S1 read allowlist (frozen; validated to contain no root grant). */
export function s1FilesystemMap(installDir: string, rules: GrantRules = HOST_RULES): Readonly<Record<string, "read">> {
  assertTomlLiteral(installDir, "installDir");
  const map: Record<string, "read"> = { ":minimal": "read", ":workspace_roots": "read", [installDir]: "read" };
  assertNoRootRead(map, rules);
  return Object.freeze(map);
}

/** The S1 map as a TOML inline table for `-c permissions.<name>=…`. */
export function s1PermissionsToml(installDir: string, rules: GrantRules = HOST_RULES): string {
  const parts = Object.entries(s1FilesystemMap(installDir, rules)).map(([k, v]) => `${k.startsWith(":") ? `"${k}"` : `'${k}'`}="${v}"`);
  return `{filesystem={${parts.join(",")}}}`;
}

export interface IsolationArgvInput {
  mode: IsolationMode;
  backend: SandboxBackend;
  installDir: string;
  /** Version-specific value that disables web search (compat table; 0.160.0: "disabled"). */
  webSearchDisabledValue: string;
  /** Required for S2: the acceptance record that allows unrestricted reads. */
  acceptanceId?: string | null;
}

/**
 * The isolation-relevant `-c` and sandbox flags, in order. Shared by `exec` and by the
 * self-test so that what was tested is what runs (§12.6: "exactly the profile and backend
 * flags of the chosen mode").
 */
export function isolationFlags(i: IsolationArgvInput): string[] {
  const windows = (WINDOWS_BACKENDS as readonly string[]).includes(i.backend);
  const linux = (LINUX_BACKENDS as readonly string[]).includes(i.backend);
  if (!windows && !linux) throw new UnsafeArgvError(`unknown sandbox backend: ${i.backend}`);
  if (!/^[a-z_]+$/.test(i.webSearchDisabledValue)) throw new UnsafeArgvError("invalid web_search value");
  const flags = [
    "-c",
    "features.unbounded_connection_retries=false",
    "-c",
    `web_search="${i.webSearchDisabledValue}"`,
    "-c",
    'approvals_reviewer="user"',
    "-c",
    'shell_environment_policy.inherit="core"',
    "-c",
    "project_doc_max_bytes=0",
    // The backend: Windows names it; on Linux bubblewrap is pinned by refusing the legacy path.
    "-c",
    windows ? `windows.sandbox="${i.backend}"` : "features.use_legacy_landlock=false",
  ];
  if (i.mode === "S1") {
    flags.push("-c", `permissions.${PROFILE_NAME}=${s1PermissionsToml(i.installDir, grantRulesOf(i.backend))}`, "-c", `default_permissions="${PROFILE_NAME}"`);
  } else if (i.mode === "S2") {
    if (!i.acceptanceId) throw new UnsafeArgvError("S2 (unrestricted reads) requires a recorded acceptance");
    flags.push("--sandbox", "read-only");
  } else {
    throw new UnsafeArgvError(`unknown isolation mode: ${String(i.mode)}`);
  }
  return flags;
}

/** Digest of the isolation flags (profile digest: part of effective isolation and the self-test key). */
export function profileDigest(i: IsolationArgvInput): string {
  return sha256OfCanonicalJson({ schema: "arl.codex-profile.v1", mode: i.mode, backend: i.backend, flags: isolationFlags(i) });
}

export interface ExecArgvInput extends IsolationArgvInput {
  exportRoot: string;
  outputSchemaPath: string;
  lastMessagePath: string;
  /** Trusted configuration only (never tool arguments). */
  model?: string | null;
  reasoningEffort?: string | null;
}

/** argv for `codex exec` under the isolation profile; the prompt is read from stdin ("-"). */
export function execArgv(i: ExecArgvInput): string[] {
  const argv = [
    "exec",
    "--json",
    "--ephemeral",
    "--color",
    "never",
    "--ignore-user-config",
    "--ignore-rules",
    "--skip-git-repo-check",
    "--cd",
    i.exportRoot,
    "--output-schema",
    i.outputSchemaPath,
    "--output-last-message",
    i.lastMessagePath,
  ];
  if (i.model) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(i.model)) throw new UnsafeArgvError(`invalid model name: ${JSON.stringify(i.model)}`);
    argv.push("-m", i.model);
  }
  if (i.reasoningEffort) {
    if (!/^[a-z]{1,32}$/.test(i.reasoningEffort)) throw new UnsafeArgvError(`invalid reasoning effort: ${JSON.stringify(i.reasoningEffort)}`);
    argv.push("-c", `model_reasoning_effort="${i.reasoningEffort}"`);
  }
  // Prompt content, not isolation: Codex would otherwise put its working directory (the
  // export path under the run store: user name, data directory, run ids) into the model
  // input through <environment_context> (M1.4-9; verified with `codex debug prompt-input`).
  argv.push("-c", "include_environment_context=false");
  argv.push(...isolationFlags(i), "-");
  assertArgvSafe(argv, i.mode);
  return argv;
}

/** argv for an offline `codex sandbox` command (self-test, X9; no model call). */
export function sandboxArgv(i: IsolationArgvInput & { cwd: string; command: readonly string[] }): string[] {
  if (i.command.length === 0) throw new UnsafeArgvError("sandbox command required");
  const iso = isolationFlags(i);
  // `codex sandbox` takes the profile with -P instead of default_permissions.
  const flags: string[] = [];
  for (let k = 0; k < iso.length; k++) {
    if (iso[k] === "-c" && iso[k + 1] === `default_permissions="${PROFILE_NAME}"`) {
      flags.push("-P", PROFILE_NAME);
      k++;
      continue;
    }
    if (iso[k] === "--sandbox") {
      k++; // `codex sandbox` has no read-only flag: S2 is the default full-disk read
      continue;
    }
    flags.push(iso[k]!);
  }
  const argv = ["sandbox", ...flags, "-C", i.cwd, "--", ...i.command];
  assertArgvSafe(argv.slice(0, argv.indexOf("--")), i.mode);
  return argv;
}

/** Refuse any forbidden flag, forbidden sandbox mode or root grant. */
export function assertArgvSafe(argv: readonly string[], mode: IsolationMode): void {
  for (const a of argv) {
    if (FORBIDDEN_FLAGS.includes(a)) throw new UnsafeArgvError(`refusing to emit forbidden flag: ${a}`);
    for (const m of FORBIDDEN_SANDBOX_MODES) if (a === m || a.includes(`"${m}"`)) throw new UnsafeArgvError(`refusing to emit sandbox mode ${m}`);
    if (/":root"|'?:root'?\s*=|(^|[{,])root\s*=/.test(a)) throw new UnsafeArgvError("refusing to emit a :root grant");
  }
  if (mode === "S1" && argv.includes("--sandbox")) throw new UnsafeArgvError("S1 must not pass --sandbox (it disables permission profiles, X7)");
}
