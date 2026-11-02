// Phase 4 foundation — the WRITABLE Codex launch profile for a delegated fix (plan §22.3, D-26). PURE.
//
// This is deliberately a SEPARATE builder from the reviewer argv (argv.ts), which must never emit a
// write grant. A delegated fixer is Codex running under its OWN `mxc` sandbox with the Phase-4 profile:
// read `:minimal` + the Codex install, WRITE only the disposable workspace's granted directories, and
// NO network. It never uses `--sandbox workspace-write` (the forbidden Codex mode, argv.ts
// FORBIDDEN_SANDBOX_MODES) — the write grant is a per-path `="write"` entry in the `mxc` permission
// profile, which the probe in docs/validation/results/P4.0-workspace-isolation.md showed confines
// writes to exactly the granted directories and denies the primary worktree, the data home and
// everything else, OS-enforced, with no elevation and no shared-ACL change.
//
// Invariants enforced here, so the one place that can emit a Codex write grant is also the place that
// bounds it:
//  - every WRITE grant is a concrete, canonical, non-root directory (argv.ts readGrantProblem);
//  - no write OR read grant exposes a protected path — the primary worktree, the data home, the Codex
//    home, the user profile (argv.ts grantExposes); a delegated fix that would grant write over the
//    worktree is refused here, before any process starts (defence in depth behind the OS confinement);
//  - network is always disabled; no forbidden flag or sandbox mode is ever emitted (assertArgvSafe).
// Nothing here spawns a process. Building the argv is not running it; the engine wiring that would run
// a delegated fix is a later, separately-authorized step (it is not part of this foundation).

import { sha256OfCanonicalJson } from "../../common/hash.js";
import {
  UnsafeArgvError,
  assertArgvSafe,
  grantExposes,
  grantRulesOf,
  readGrantProblem,
  type GrantRules,
  type SandboxBackend,
} from "./argv.js";

/** The profile name used for `-P` and `-c permissions.<name>` (distinct from the reviewer's `ai_review`). */
export const FIX_PROFILE_NAME = "cp_fix";

export interface FixProfileInput {
  backend: SandboxBackend;
  /** The Codex installation directory (read grant), canonical. */
  installDir: string;
  /** Directories the fixer may WRITE: the disposable workspace's tree and scratch, canonical. */
  writableDirs: readonly string[];
  /**
   * Paths no grant may contain or equal: the primary worktree, the data home, the Codex home, the user
   * profile — canonical. A write grant that exposes one is a refusal, not a warning (fail closed).
   */
  protectedPaths: readonly string[];
}

/** A single-quoted TOML literal path; refuses a quote or control character (cannot be escaped in a literal). */
function tomlLiteralPath(p: string, label: string): string {
  if (p.length === 0) throw new UnsafeArgvError(`${label} must be a non-empty path`);
  if (p.includes("'") || /[\u0000-\u001f]/.test(p)) throw new UnsafeArgvError(`${label} cannot be expressed as a TOML literal: ${JSON.stringify(p)}`);
  return `'${p}'`;
}

/** Do two canonical paths overlap (one contains or equals the other)? Separator-aware; case rules per platform. */
function pathsOverlap(a: string, b: string, rules: GrantRules): boolean {
  const norm = (p: string) => (rules === "posix" ? p.replace(/\/+$/, "") : p.replace(/\\$/, "").toLowerCase());
  const sep = rules === "posix" ? "/" : "\\";
  const x = norm(a);
  const y = norm(b);
  return x === y || x.startsWith(y + sep) || y.startsWith(x + sep);
}

/**
 * A protected path a WRITE grant would reach, in EITHER direction, or null: the grant is an ancestor of
 * the protected path (argv.ts grantExposes — can write INTO it) OR the grant lies inside the protected
 * path (writes land in a protected tree). A write grant must overlap no protected path at all.
 */
function writeGrantConflict(grant: string, protectedPaths: readonly string[], rules: GrantRules): string | null {
  const exposed = grantExposes(grant, protectedPaths, rules);
  if (exposed) return exposed;
  return protectedPaths.find((p) => pathsOverlap(grant, p, rules)) ?? null;
}

/**
 * The fixer's `permissions.<name>` TOML inline table: read `:minimal` + the install, write the granted
 * directories, network disabled. Validates every grant's safety and that none exposes a protected path.
 */
export function fixPermissionsToml(i: FixProfileInput): string {
  const rules: GrantRules = grantRulesOf(i.backend);
  if (i.writableDirs.length === 0) throw new UnsafeArgvError("a delegated fix must grant at least one writable directory");

  for (const w of i.writableDirs) {
    const problem = readGrantProblem(w, rules); // the same spelling-strict, non-root, canonical check as a read grant
    if (problem) throw new UnsafeArgvError(`refusing to grant write to ${JSON.stringify(w)}: ${problem}`);
    const conflict = writeGrantConflict(w, i.protectedPaths, rules);
    if (conflict) throw new UnsafeArgvError(`refusing to grant write to ${JSON.stringify(w)}: it would expose the protected path ${JSON.stringify(conflict)}`);
  }
  const installProblem = readGrantProblem(i.installDir, rules);
  if (installProblem) throw new UnsafeArgvError(`invalid Codex install read grant ${JSON.stringify(i.installDir)}: ${installProblem}`);
  const installExposed = grantExposes(i.installDir, i.protectedPaths, rules);
  if (installExposed) throw new UnsafeArgvError(`the Codex install read grant would expose the protected path ${JSON.stringify(installExposed)}`);

  const fsEntries = [
    `":minimal"="read"`,
    `${tomlLiteralPath(i.installDir, "installDir")}="read"`,
    ...i.writableDirs.map((w) => `${tomlLiteralPath(w, "writableDir")}="write"`),
  ];
  return `{filesystem={${fsEntries.join(",")}},network={enabled=false}}`;
}

/** The isolation `-c` flags for a fixer `codex sandbox` run (backend, no project doc, no web search). */
export function fixIsolationFlags(i: FixProfileInput): string[] {
  const windows = i.backend === "mxc" || i.backend === "elevated" || i.backend === "unelevated";
  const linux = i.backend === "bwrap";
  if (!windows && !linux) throw new UnsafeArgvError(`unknown sandbox backend: ${i.backend}`);
  return [
    "-c",
    "features.unbounded_connection_retries=false",
    "-c",
    'web_search="disabled"',
    "-c",
    "project_doc_max_bytes=0",
    "-c",
    windows ? `windows.sandbox="${i.backend}"` : "features.use_legacy_landlock=false",
    "-c",
    `permissions.${FIX_PROFILE_NAME}=${fixPermissionsToml(i)}`,
  ];
}

export interface FixSandboxArgvInput extends FixProfileInput {
  /** The fixer's working directory (the disposable workspace's tree), canonical. */
  cwd: string;
  /** The command to run inside the sandbox (e.g. codex exec, or a test command). Non-empty. */
  command: readonly string[];
}

/**
 * argv for an offline-shaped `codex sandbox -P cp_fix … -C <cwd> -- <command…>` that may write the
 * granted directories. Building it does not run it. Refuses every forbidden flag and sandbox mode, and
 * (for S1-style safety reuse) checks there is no `:root` grant. `mode: "S1"` in the safety check means
 * only "no `--sandbox` mode flag is present"; the write grant lives in the permission profile, not a mode.
 */
export function fixSandboxArgv(i: FixSandboxArgvInput): string[] {
  if (i.command.length === 0) throw new UnsafeArgvError("a fix sandbox command is required");
  const argv = ["sandbox", ...fixIsolationFlags(i), "-P", FIX_PROFILE_NAME, "-C", i.cwd, "--", ...i.command];
  // The part before "--" is CodeParley-controlled; the command after it is the fixer's own argv.
  assertArgvSafe(argv.slice(0, argv.indexOf("--")), "S1");
  return argv;
}

/**
 * Digest of the fixer profile's SECURITY STRUCTURE — stable across the per-fix disposable workspace paths,
 * so one stored self-test record binds every later fixer launch of the same shape (fix-selftest.ts). It
 * captures the backend, the fixed isolation `-c` flags, the read grants normalized to roles
 * (`:minimal` + `<install>`) and the NUMBER of writable grants; the concrete writable/install paths are
 * validated at build time by the grant checks above, not by this digest, and the exact binary is bound
 * separately by the self-test's `codex_sha256`. (The path-specific value recorded in the Option B addendum
 * was the probe's; Increment 1 pins this normalized structure.)
 */
export function fixProfileDigest(i: FixProfileInput): string {
  const rules: GrantRules = grantRulesOf(i.backend);
  // The fixed `-c` flags with the permission TOML's volatile paths replaced by role placeholders.
  const normalizedToml = `{filesystem={":minimal"="read","<install>"="read",${i.writableDirs.map((_, n) => `"<writable-${n}>"="write"`).join(",")}},network={enabled=false}}`;
  const flags = [
    "-c", "features.unbounded_connection_retries=false",
    "-c", 'web_search="disabled"',
    "-c", "project_doc_max_bytes=0",
    "-c", i.backend === "bwrap" ? "features.use_legacy_landlock=false" : `windows.sandbox="${i.backend}"`,
    "-c", `permissions.${FIX_PROFILE_NAME}=${normalizedToml}`,
  ];
  return sha256OfCanonicalJson({ schema: "codeparley.fix-profile.v2", backend: i.backend, rules, writable_grants: i.writableDirs.length, flags });
}

export interface FixExecArgvInput extends FixProfileInput {
  /** The fixer's working directory: the disposable workspace's writable `tree`, canonical. */
  cwd: string;
  /** Where Codex writes the final message (cross-checked against the event stream, as the reviewer does). */
  lastMessagePath: string;
  /** Trusted configuration only (never tool arguments). */
  model?: string | null;
  reasoningEffort?: string | null;
}

/**
 * argv for a model-driven `codex exec` running the delegated fixer under the writable `cp_fix` profile.
 * The prompt is read from stdin ("-"). This is the launch counterpart of the reviewer's `execArgv`
 * (argv.ts): the writable grant lives in the `cp_fix` permission profile (`fixIsolationFlags`), selected
 * with `default_permissions`, and NO `--sandbox workspace-write` / `danger-full-access` mode is ever
 * emitted — `assertArgvSafe` enforces that, so the OS sandbox (mxc) always applies. Building the argv does
 * not run it; the launcher (fix-selftest.ts / the engine) runs it under the bounded process controls.
 */
export function fixExecArgv(i: FixExecArgvInput): string[] {
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
    i.cwd,
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
  // Keep Codex's working directory and the data home out of the model input (as the reviewer does).
  argv.push("-c", "include_environment_context=false");
  argv.push(...fixIsolationFlags(i), "-c", `default_permissions="${FIX_PROFILE_NAME}"`, "-");
  // Everything up to the prompt sentinel is CodeParley-controlled: it must carry no forbidden flag or mode.
  assertArgvSafe(argv.slice(0, argv.length - 1), "S1");
  return argv;
}
