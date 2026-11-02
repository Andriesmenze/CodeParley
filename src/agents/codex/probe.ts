// Codex probe (plan §12.3, §12.6 step 1; X16, G7). Offline: no model call.
//
// Resolves the NATIVE codex.exe (a shim-only install is refused: launching through
// cmd.exe → node → codex leaves orphans when killed, G7), reads its version, checks it is
// in the compatibility table and that `exec --help` lists every flag the isolation profile
// uses, and reports whether user-level Codex hooks are present (they are not sandboxed and
// are reported in every review, §12.2). Results are cached per executable identity
// (path, size, mtime) for the life of the process.

import { existsSync } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DomainError } from "../../common/errors.js";
import { codexVendorCandidates, isElfExecutable, resolveNativeExecutable } from "../../process/native-resolve.js";
import { runProcess } from "../../process/spawn.js";
import { buildChildEnv, lookupEnv } from "../../process/env.js";
import { canonicalizePath, caseKey } from "../../workspace/paths.js";
import { compatRowFor, type CompatRow } from "./compat.js";
import { readGrantProblem } from "./argv.js";

const WIN = process.platform === "win32";

/**
 * How Codex is launched. Production: `file` is the resolved native codex.exe and
 * `prefixArgs` is empty. TEST ONLY: a fake Codex runs as `node <script>`, so `file` is
 * node.exe and `prefixArgs` holds the script; `exe` still names the identity under test.
 */
export interface CodexLauncher {
  exe: string;
  file: string;
  prefixArgs: readonly string[];
}

export interface CodexProbe {
  launcher: CodexLauncher;
  how: string;
  version: string;
  versionRaw: string;
  compat: CompatRow;
  /** The Codex installation directory granted read access by the S1 profile (§12.4). */
  installDir: string;
  missingFlags: string[];
  codexHome: string;
  userHooksPresent: boolean;
}

const cache = new Map<string, CodexProbe>();

export interface ProbeOptions {
  configured?: string | null;
  sourceEnv?: NodeJS.ProcessEnv;
  /** TEST ONLY: launch prefix for a scripted fake Codex. */
  testLauncher?: { file: string; prefixArgs: readonly string[] } | null;
  signal?: AbortSignal;
}

/** Resolve and probe Codex, or throw CODEX_NOT_FOUND / CODEX_UNSUPPORTED_VERSION. */
export async function probeCodex(o: ProbeOptions = {}): Promise<CodexProbe> {
  const env = buildChildEnv({ source: o.sourceEnv ?? process.env }).env;
  const resolved = await resolveNativeExecutable("codex", {
    configured: o.configured ?? null,
    refuseShim: true,
    shimVendorCandidates: codexVendorCandidates,
    env,
  });
  if (!resolved.ok || !resolved.path) throw new DomainError("CODEX_NOT_FOUND", resolved.error ?? "codex not found");
  if (WIN ? !/\.exe$/i.test(resolved.path) : !isElfExecutable(resolved.path)) {
    throw new DomainError("CODEX_NOT_FOUND", `codex must be a native ${WIN ? ".exe" : "(ELF) executable"}: ${resolved.path}`);
  }
  const exe = resolved.path;
  const st = await stat(exe).catch(() => null);
  if (!st) throw new DomainError("CODEX_NOT_FOUND", `codex executable not found: ${exe}`);
  const launcher: CodexLauncher = o.testLauncher ? { exe, file: o.testLauncher.file, prefixArgs: [...o.testLauncher.prefixArgs] } : { exe, file: exe, prefixArgs: [] };
  const codexHome = codexHomeOf(o.sourceEnv ?? process.env);
  const key = JSON.stringify([caseKey(exe), st.size, Math.floor(st.mtimeMs), launcher.file, launcher.prefixArgs, caseKey(codexHome)]);
  const hit = cache.get(key);
  if (hit) return { ...hit, userHooksPresent: hooksPresent(codexHome) };

  const v = await runProcess(launcher.file, [...launcher.prefixArgs, "--version"], { env, wallMs: 20_000, ...(o.signal ? { signal: o.signal } : {}) });
  const versionRaw = (v.stdout || v.stderr).trim();
  const version = /(\d+\.\d+\.\d+)/.exec(versionRaw)?.[1] ?? null;
  const compat = compatRowFor(version);
  if (!version || !compat) {
    throw new DomainError("CODEX_UNSUPPORTED_VERSION", `Codex ${version ?? "(unknown version)"} is not a supported version: CodeParley supports Codex 0.160.x`, {
      details: { version, raw: versionRaw.slice(0, 200), exe },
    });
  }
  const h = await runProcess(launcher.file, [...launcher.prefixArgs, "exec", "--help"], { env, wallMs: 20_000, ...(o.signal ? { signal: o.signal } : {}) });
  const help = `${h.stdout}\n${h.stderr}`;
  const missingFlags = compat.requiredExecFlags.filter((f) => !new RegExp(`(^|[\\s,\\[])${escapeRe(f)}([\\s,=<\\]]|$)`, "m").test(help));
  if (missingFlags.length > 0) {
    throw new DomainError("CODEX_UNSUPPORTED_VERSION", `codex exec --help lacks required flags: ${missingFlags.join(", ")}`, { details: { version, missingFlags } });
  }
  const installDir = await resolveInstallDir(exe);
  const probe: CodexProbe = { launcher, how: resolved.how ?? "path", version, versionRaw, compat, installDir, missingFlags, codexHome, userHooksPresent: hooksPresent(codexHome) };
  cache.set(key, probe);
  return probe;
}

/**
 * The S1 install-directory grant: `<installDir>\bin\codex.exe` → `<installDir>` (the Gate A
 * grant; on Linux `…/vendor/<triple>/bin/codex` → `…/vendor/<triple>`, the vendored Codex
 * installation with its helpers), resolved with the OS (junctions, `subst`, mapped drives, 8.3
 * names, symbolic links, `..`) BEFORE it is classified, so no spelling can turn it into a drive
 * or filesystem root (F1). The directory must
 * exist, and the result must be a fixed point of the OS resolution (resolving it again
 * yields exactly it): genuine 8.3 aliases are expanded to their long names, while a
 * literal long name that merely looks like one (`Codex~2026.10`, a directory named
 * `CODEX~1`) is kept as the name it is. Throws CODEX_ISOLATION_UNAVAILABLE when the
 * canonical directory is a root, missing, unstable or otherwise unsafe.
 */
export async function resolveInstallDir(exe: string): Promise<string> {
  const raw = dirname(dirname(exe));
  let canonical: string;
  try {
    canonical = await canonicalizePath(raw);
  } catch (e) {
    throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the Codex installation directory ${JSON.stringify(raw)} cannot be canonicalized: ${(e as Error).message}`);
  }
  const problem = readGrantProblem(canonical);
  if (problem) {
    throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the Codex installation directory resolves to ${JSON.stringify(canonical)} (${problem}); granting it under S1 could expose a whole drive, so S1 is refused`, { details: { raw, canonical } });
  }
  await assertCanonicalGrant(canonical);
  return canonical;
}

/**
 * The grant names an existing directory and is a fixed point of the OS's canonical
 * resolution (no junction, `subst`, mapped drive, short-name alias or case variant left).
 * Checked by the probe and again by the engine immediately before a grant is used.
 */
export async function assertCanonicalGrant(grant: string): Promise<void> {
  const st = await stat(grant).catch(() => null);
  if (!st || !st.isDirectory()) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the S1 read grant ${JSON.stringify(grant)} is not an existing directory`);
  const again = await realpath(grant).catch(() => null);
  if (again !== grant) {
    throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the S1 read grant ${JSON.stringify(grant)} is not in canonical form (it resolves to ${JSON.stringify(again)}); it is refused`);
  }
  const problem = readGrantProblem(grant);
  if (problem) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the S1 read grant ${JSON.stringify(grant)} is unsafe (${problem})`);
}

export function codexHomeOf(env: NodeJS.ProcessEnv): string {
  const explicit = lookupEnv(env, "CODEX_HOME");
  if (explicit) return explicit;
  if (!WIN) return join(lookupEnv(env, "HOME") ?? homedir(), ".codex");
  return join(lookupEnv(env, "USERPROFILE") ?? "C:\\Users\\Default", ".codex");
}

/** User-level Codex hooks are present (they run outside the sandbox when trusted; §12.2, M1.0-5). */
export function hooksPresent(codexHome: string): boolean {
  return existsSync(join(codexHome, "hooks.json")) || existsSync(join(codexHome, "hooks", "hooks.json"));
}

/** Forget cached probes (tests). */
export function clearProbeCache(): void {
  cache.clear();
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
