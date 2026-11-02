// Phase 4 Increment 2 — the FIX self-test confirmation the operator records with the custodian (FIX vs S1 separation).
//
// The Increment-1 cp_fix self-test produces a LOCAL record (agents/codex/fix-selftest.ts) that gates only a local launch.
// A delegated fix on a protected run needs more: the custodian begins a `fix` operation only on an operator-confirmed FIX
// self-test — a custodian-held confirmation of mode FIX, separate from the S1 reviewer confirmation, bound to the Codex
// version, the exact binary (SHA-256), the backend and the fixer profile structure. The operator confirms the record the
// custodian renders (`code-parley config confirm-selftest --fix`); the custodian does not re-run the self-test. An S1
// confirmation never satisfies a fix, nor a FIX confirmation a review (the custodian matches the mode).
//
// Imported only by the operator CLI (src/cli/config-commands.ts) and the delegation (engine/fix-operation.ts): it reaches
// the fixer-launch modules, which no MCP or hook entry point may (test/delegated-fix-layering.test.ts).

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DomainError } from "../common/errors.js";
import { sha256OfBytes, sha256OfCanonicalJson } from "../common/hash.js";
import { probeCodex, type CodexProbe } from "../agents/codex/probe.js";
import { loadFixSelfTest } from "../agents/codex/fix-selftest.js";
import { fixProfileDigest, type FixProfileInput } from "../agents/codex/fix-profile.js";
import type { SandboxBackend } from "../agents/codex/argv.js";
import type { FixSelfTestRecord } from "../schemas/review.js";
import type { Loaded } from "./engine-env.js";

/** The digest the operator confirms: over the whole stored fix self-test record. */
export const fixSelfTestRecordDigest = (rec: FixSelfTestRecord): string => sha256OfCanonicalJson({ schema: "codeparley.fix-selftest-record.v1", record: rec });

/** A self-test row name as the custodian bounds it (a code). */
const rowCode = (n: string): string => n.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 64) || "row";

/** Phase 5 Increment 3: the sandbox backend a delegated fixer runs on — Codex's bubblewrap on Linux (the only Linux
 * backend), else the configured Windows backend or the compatibility row's preference. */
export function fixBackendFor(platform: NodeJS.Platform, windowsSandbox: string | null, probe: CodexProbe): SandboxBackend {
  if (platform === "linux") return "bwrap";
  return (windowsSandbox ?? probe.compat.preferredBackends[0]) as SandboxBackend;
}

/** The fixer profile structure the self-test and every launch share (its digest depends only on the backend and the number
 * of writable grants — tree and scratch — never on their paths). */
export function fixProfileFor(backend: SandboxBackend, probe: CodexProbe, writableDirs: readonly [string, string], protectedPaths: readonly string[]): FixProfileInput {
  return { backend, installDir: probe.installDir, writableDirs: [...writableDirs], protectedPaths: [...protectedPaths] };
}

/** The stored, passing fix self-test of the Codex the engine would launch, with that binary's SHA-256. */
export async function storedFixSelfTest(selftestDir: string, dataHome: string, backend: SandboxBackend, probe: CodexProbe): Promise<{ record: FixSelfTestRecord; codexSha256: string; profileDigest: string }> {
  const bytes = await readFile(probe.launcher.exe).catch(() => null);
  if (!bytes) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the Codex executable ${probe.launcher.exe} cannot be read to bind its fix self-test`);
  const codexSha256 = sha256OfBytes(bytes);
  const profile = fixProfileFor(backend, probe, [join(dataHome, "fix-selftest-work", "tree"), join(dataHome, "fix-selftest-work", "scratch")], [probe.codexHome]);
  const record = await loadFixSelfTest(selftestDir, probe.version, codexSha256, profile);
  if (!record) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `no stored cp_fix self-test of Codex ${probe.version} (${codexSha256.slice(0, 12)}) on ${backend}: run \`code-parley codex fix-selftest --backend ${backend}\` first`);
  if (!record.confinement_available) {
    throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the stored cp_fix self-test of Codex ${probe.version} on ${backend} did not establish confinement (failed: ${record.rows.filter((r) => !r.pass || r.inconclusive).map((r) => r.name).join(", ") || "profile rejected"}); it cannot be confirmed or used`);
  }
  return { record, codexSha256, profileDigest: fixProfileDigest(profile) };
}

/**
 * The FIX confirmation `config confirm-selftest --fix` proposes: the stored, passing cp_fix self-test of this Codex version,
 * binary, backend and fixer profile — produced by the implementer's engine — identified by its digest.
 */
export async function fixSelftestPayload(le: Loaded, backend: SandboxBackend, codex: string | null): Promise<Record<string, unknown>> {
  const probe = await probeCodex({ configured: codex ?? le.env.launch.codex ?? le.cfg.config.codex.executable, sourceEnv: le.env.sourceEnv, testLauncher: le.env.testHooks?.review?.codexLauncher ?? null });
  const { record, codexSha256 } = await storedFixSelfTest(le.layout.selftestDir, le.dataHome, backend, probe);
  const failed = record.rows.filter((r) => !r.pass || r.inconclusive).map((r) => rowCode(r.name));
  return {
    selftestId: record.selftest_id,
    codexVersion: record.codex_version,
    backend: record.backend,
    mode: "FIX",
    profileDigest: record.profile_digest,
    s1Available: record.confinement_available,
    rowsSummary: { total: Math.min(record.rows.length, 1000), passed: Math.min(record.rows.filter((r) => r.pass && !r.inconclusive).length, 1000), failed: [...new Set(failed)].slice(0, 32) },
    recordDigest: fixSelfTestRecordDigest(record),
    codexSha256,
    // Phase 5 (§4.12): a Linux record names its boot and the Codex binary it ran; a custodian that binds a sandbox basis
    // measures that installation itself and confirms only a record of the current boot (as for S1).
    ...(record.boot_id && record.codex_path ? { host: { codexPath: record.codex_path, bootId: record.boot_id } } : {}),
  };
}
