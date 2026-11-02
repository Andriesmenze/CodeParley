// P3.4C-4 (contract §1.3, §3.1): the operator's side of the custodian-held trusted configuration. ONLY the CLI path
// (src/cli/config-commands.ts, and `loop resume`'s re-confirmation) imports this module; the custodian decides operator
// authority from the OS caller classification (the elevated operator token), so CLI-only reachability is layering, not
// the boundary.
//
// Migration is explicit: `config set` imports the repository's APPROVED local check configuration (trust/projects.json),
// the capture rules of config.json and the Codex installation the operator names; the custodian validates it, computes
// every digest, measures the Codex image through its own handle and renders the complete content, which the operator
// confirms by typing. Nothing local is promoted silently, and attended runs keep reading the local files.

import { realpath } from "node:fs/promises";
import { DomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import { CustodianGrants } from "../custodian/grants.js";
import { CustodianOperator } from "../custodian/operator.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import type { ConfigAction, ConfigCommit, ConfigRecordKind, ConfigSection, PreparedConfigRecord } from "../custodian/protocol.js";
import type { CustodianTransport } from "../custodian/transport.js";
import { loadTrustProjects } from "../config/trusted-projects.js";
import { evaluateProject } from "../checks/project-config.js";
import { readRootCommit } from "../capture/root-commit.js";
import { probeCodex, type CodexProbe } from "../agents/codex/probe.js";
import { REDUCED_ISOLATION_STATEMENT_SHA256 } from "../agents/codex/isolation.js";
import { loadSelfTest } from "../agents/codex/selftest.js";
import type { SandboxBackend } from "../agents/codex/argv.js";
import { resolveNativeExecutable, codexVendorCandidates } from "../process/native-resolve.js";
import { buildChildEnv } from "../process/env.js";
import { gitExeOf, type Loaded } from "./engine-env.js";
import { selfTestRecordDigest } from "./protected-config.js";

export { CONFIG_VIEW_RUN } from "../custodian/protocol.js";
import { CONFIG_VIEW_RUN } from "../custodian/protocol.js";

function custodianOf(le: Loaded): CustodianTransport {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  return gate.transport;
}

/** The custodian's configuration for the repository, as the OPERATOR surface reports it (the operator's own pipe). */
export async function operatorConfigSection(le: Loaded, repositoryRoot: string): Promise<ConfigSection> {
  const listing = await new CustodianGrants(custodianOf(le)).listUserRecords("operator", repositoryRoot, CONFIG_VIEW_RUN, ["config"]);
  if (!listing.config) throw new DomainError("CUSTODIAN_UNAVAILABLE", "the custodian did not report its configuration records", { retryable: false });
  return listing.config;
}

/** Phase 1 of a configuration change (operator surface): the custodian validates, measures, renders and binds it. */
export async function prepareConfigChange(le: Loaded, req: { repositoryRoot: string | null; recordKind: ConfigRecordKind; action: ConfigAction; recordId?: string | null; payload?: Record<string, unknown> | null; baseRevision: number }, requestId = uuidv7()): Promise<PreparedConfigRecord> {
  return new CustodianOperator(custodianOf(le)).prepareConfigRecord(req, requestId);
}

/** Phase 2: commit the prepared change the operator confirmed. */
export async function commitConfigChange(le: Loaded, authorizationRequestId: string): Promise<ConfigCommit> {
  return new CustodianOperator(custodianOf(le)).commitConfigRecord(authorizationRequestId);
}

/** The Codex probe of the installation the operator names (or the configured / resolved one). */
async function probeFor(le: Loaded, codex: string | null): Promise<CodexProbe> {
  return probeCodex({ configured: codex ?? le.env.launch.codex ?? le.cfg.config.codex.executable, sourceEnv: le.env.sourceEnv, testLauncher: le.env.testHooks?.review?.codexLauncher ?? null });
}

/**
 * The Codex installation to approve (TD clarification II): the path the operator names, as given (the custodian refuses
 * a path through a link); otherwise the native executable CodeParley resolves — configured or found on PATH — at its
 * real location, which is the path a protected review then launches. A launcher or script is never chosen: resolution
 * refuses a shim without its native executable.
 */
export async function codexInstallationPath(le: Loaded, codex: string | null): Promise<{ path: string; how: string }> {
  if (codex) return { path: codex, how: "named on the command line" };
  const configured = le.env.launch.codex ?? le.cfg.config.codex.executable ?? null;
  const resolved = await resolveNativeExecutable("codex", { configured, refuseShim: true, shimVendorCandidates: codexVendorCandidates, env: buildChildEnv({ source: le.env.sourceEnv }).env });
  if (!resolved.ok || !resolved.path) throw new DomainError("CODEX_NOT_FOUND", `${resolved.error ?? "codex was not found"}; name the native codex executable with --codex <path>`);
  const real = await realpath(resolved.path).catch(() => resolved.path!);
  return { path: real, how: real === resolved.path ? `resolved (${resolved.how})` : `resolved (${resolved.how}) at its real location ${real} (the path ${resolved.path} goes through a link)` };
}

/**
 * The repository record `config set` proposes: the repository's APPROVED local check configuration — its normalized
 * definitions, profiles, verification floor and test globs — with the capture rules of config.json and the Codex
 * installation. Refused unless the local entry is approved (nothing unapproved is promoted).
 */
export async function repositoryPayload(le: Loaded, repositoryRoot: string, codexPath: string | null): Promise<Record<string, unknown>> {
  const projects = await loadTrustProjects(le.layout.trustProjects);
  const rootCommit = await readRootCommit({ gitExe: await gitExeOf(le), repoRoot: repositoryRoot });
  const ev = evaluateProject(projects, repositoryRoot, rootCommit);
  if (ev.status !== "approved") {
    throw new DomainError("CHECK_NOT_APPROVED", `the repository's local check configuration is ${ev.status}: approve it first with \`code-parley checks approve --repo ${repositoryRoot}\`, then import it (${ev.problems.slice(0, 3).join("; ") || "no approved entry"})`);
  }
  const checks: Record<string, unknown> = {};
  for (const [name, c] of ev.checks) {
    const d = c.definition!;
    checks[name] = { argv: d.argv, cwd: d.cwd, timeout_seconds: d.timeout_seconds, env: d.env, env_passthrough: d.env_passthrough, freshness_inputs: d.freshness_inputs, ...(d.description !== undefined ? { description: d.description } : {}) };
  }
  const cap = le.cfg.config.capture;
  return {
    rootCommit: ev.rootCommit,
    checks,
    profiles: ev.profiles,
    requiredProfiles: [...ev.requiredProfiles].sort(),
    noRequiredChecks: ev.noRequiredChecks,
    testGlobs: ev.testGlobs,
    captureRules: { excludeGlobs: [...cap.exclude_globs], contextInclude: [...cap.context_include], maxFileBytes: cap.max_file_bytes, maxExportBytes: cap.max_export_bytes, maxDiffBytes: cap.max_diff_bytes },
    codexPath,
  };
}

/** The S2 acceptance `config accept-isolation` proposes for a backend and the installed Codex's version range. */
export async function acceptancePayload(le: Loaded, backend: SandboxBackend, codex: string | null): Promise<Record<string, unknown>> {
  const probe = await probeFor(le, codex);
  return { accepted: ["unrestricted_reads", "advisory_network"], backend, codexVersionRange: probe.compat.versionPrefix, statementSha256: REDUCED_ISOLATION_STATEMENT_SHA256 };
}

/** A self-test row name as the custodian bounds it (a code). */
const rowCode = (n: string): string => n.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 64) || "row";

/**
 * The confirmation `config confirm-selftest` proposes (D4-A): the stored S1 self-test record of this Codex version,
 * backend and production profile — produced by the implementer's engine — identified by its digest. The custodian does
 * not re-run it; the operator confirms the record the custodian renders.
 */
export async function selftestPayload(le: Loaded, backend: SandboxBackend, codex: string | null): Promise<Record<string, unknown>> {
  const probe = await probeFor(le, codex);
  const rec = await loadSelfTest(le.layout.selftestDir, probe.version, { mode: "S1", backend, installDir: probe.installDir, webSearchDisabledValue: probe.compat.webSearchDisabledValue, acceptanceId: null });
  if (!rec) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `no stored S1 self-test of Codex ${probe.version} on ${backend}: run \`code-parley codex selftest --backend ${backend}\` first`);
  if (!rec.s1_available) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the stored S1 self-test of Codex ${probe.version} on ${backend} did not pass (failed: ${rec.rows.filter((r) => !r.pass || r.inconclusive).map((r) => r.name).join(", ") || "profile rejected"}); it cannot be confirmed`);
  const failed = rec.rows.filter((r) => !r.pass || r.inconclusive).map((r) => rowCode(r.name));
  return {
    selftestId: rec.selftest_id,
    codexVersion: rec.codex_version,
    backend: rec.backend,
    mode: "S1",
    profileDigest: rec.profile_digest,
    s1Available: rec.s1_available,
    rowsSummary: { total: Math.min(rec.rows.length, 1000), passed: Math.min(rec.rows.filter((r) => r.pass && !r.inconclusive).length, 1000), failed: [...new Set(failed)].slice(0, 32) },
    recordDigest: selfTestRecordDigest(rec),
    // Phase 5 (§4.12): a Linux record names its boot and the Codex binary it ran; a custodian that binds a sandbox basis
    // measures that installation itself and confirms only a record of the current boot.
    ...(rec.codex_sha256 ? { codexSha256: rec.codex_sha256 } : {}),
    ...(rec.boot_id && rec.codex_path ? { host: { codexPath: rec.codex_path, bootId: rec.boot_id } } : {}),
  };
}

/** Is the repository's record lapsed (or a global record it rests on), as the operator surface reports it now? */
export function lapsedRecords(section: ConfigSection): { repository: boolean; globals: number } {
  return {
    repository: section.repository?.lapsed === true && !section.repository.revoked,
    globals:
      section.acceptances.filter((a) => a.lapsed && !a.revoked).length +
      section.selftestConfirmations.filter((c) => c.lapsed && !c.revoked).length +
      (section.engineRuntime?.lapsed && !section.engineRuntime.revoked ? 1 : 0),
  };
}
