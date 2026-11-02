// `code-parley codex …` commands (plan §5.1, §12.2, §12.6, §16.4). The CLI is the only
// channel that records an acceptance of reduced isolation: there is no MCP tool for it.
//
//   codex probe   [--codex <codex executable>]
//   codex selftest [--backend mxc|elevated|unelevated (Windows) | bwrap (Linux)] [--codex <codex executable>]
//   codex accept-reduced-isolation --backend <b> [--confirm <digest>]
//   codex revoke-reduced-isolation --acceptance <id> [--confirm <id>]
//
// The self-test is offline (no model call). Acceptance shows the exact consequences and is
// bound to the digest of what was shown (statement, backend, accepted reductions, Codex
// version range); a non-interactive acceptance must quote that digest.

import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { DomainError } from "../common/errors.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { atomicWriteFile } from "../store/atomic.js";
import { resolveDataHome, storeLayout } from "../store/paths.js";
import { buildChildEnv } from "../process/env.js";
import { backendsFor, type SandboxBackend } from "../agents/codex/argv.js";
import { probeCodex } from "../agents/codex/probe.js";
import { runSelfTest, storeSelfTest } from "../agents/codex/selftest.js";
import { runFixSelfTest, storeFixSelfTest } from "../agents/codex/fix-selftest.js";
import { REDUCED_ISOLATION_STATEMENT, REDUCED_ISOLATION_STATEMENT_SHA256, loadAcceptances } from "../agents/codex/isolation.js";
import { IsolationAcceptanceFileSchema, type IsolationAcceptance } from "../schemas/review.js";

export interface CodexCliIo {
  out(line: string): void;
  err(line: string): void;
  prompt: ((question: string) => Promise<string>) | null;
  env: NodeJS.ProcessEnv;
}

export interface CodexCliArgs {
  cmd: string | undefined;
  home: string | undefined;
  codex: string | undefined;
  backend: string | undefined;
  confirm: string | undefined;
  acceptance: string | undefined;
}

export async function runCodexCli(a: CodexCliArgs, io: CodexCliIo): Promise<number> {
  const { dataHome, configFile } = resolveDataHome({ home: a.home ?? null, env: io.env });
  const layout = storeLayout(dataHome, configFile);
  switch (a.cmd) {
    case "probe":
      return probeCmd(a, io);
    case "selftest":
      return selftestCmd(a, io, dataHome, layout.selftestDir);
    case "fix-selftest":
      return fixSelftestCmd(a, io, dataHome, layout.selftestDir);
    case "accept-reduced-isolation":
      return acceptCmd(a, io, layout.trustIsolation);
    case "revoke-reduced-isolation":
      return revokeCmd(a, io, layout.trustIsolation);
    default:
      io.err("usage: code-parley codex (probe | selftest | fix-selftest | accept-reduced-isolation | revoke-reduced-isolation) [options]");
      return 1;
  }
}

function backendOf(a: CodexCliArgs): SandboxBackend {
  const allowed = backendsFor();
  const b = a.backend ?? allowed[0];
  if (!b || !(allowed as readonly string[]).includes(b)) throw new DomainError("INVALID_ARGUMENT", `--backend must be one of ${allowed.join(", ") || "(no Codex sandbox backend on this platform)"}`);
  return b as SandboxBackend;
}

async function probeCmd(a: CodexCliArgs, io: CodexCliIo): Promise<number> {
  const p = await probeCodex({ configured: a.codex ?? null, sourceEnv: io.env });
  io.out(`codex: ${p.launcher.exe} (${p.how})`);
  io.out(`version: ${p.version} (${p.versionRaw})`);
  io.out(`install dir granted read access under S1: ${p.installDir}`);
  io.out(`required exec flags: all present`);
  io.out(`web_search disabled value: ${p.compat.webSearchDisabledValue}`);
  for (const [b, f] of Object.entries(p.compat.backends)) io.out(`backend ${b}: S1 ${f.s1} (${f.note})`);
  io.out(`CODEX_HOME: ${p.codexHome}; user hooks present: ${p.userHooksPresent ? "YES (trusted hooks run outside the sandbox)" : "no"}`);
  io.out("The S1 self-test decides availability on this machine: code-parley codex selftest");
  return 0;
}

async function selftestCmd(a: CodexCliArgs, io: CodexCliIo, dataHome: string, selftestDir: string): Promise<number> {
  const backend = backendOf(a);
  const probe = await probeCodex({ configured: a.codex ?? null, sourceEnv: io.env });
  io.out(`running the offline S1 self-test: codex ${probe.version}, backend ${backend} (no model call)`);
  const env = buildChildEnv({ source: io.env, includeCodexAuth: true }).env;
  const rec = await runSelfTest({ probe, backend, mode: "S1", dataHome, env });
  await storeSelfTest(selftestDir, rec);
  if (!rec.profile_runs) io.out(`profile rejected on ${backend}: ${rec.rejection_reason ?? "unknown"}`);
  for (const r of rec.rows) io.out(`  ${r.pass ? "PASS" : "FAIL"} ${r.name}: expected ${r.expectation}, sandbox ${r.sandbox}, positive control ${r.positive_control}${r.inconclusive ? " (inconclusive)" : ""}`);
  io.out(`S1 available on ${backend}: ${rec.s1_available ? "YES" : "no"} (self-test ${rec.selftest_id}, stored)`);
  return rec.s1_available ? 0 : 1;
}

async function fixSelftestCmd(a: CodexCliArgs, io: CodexCliIo, dataHome: string, selftestDir: string): Promise<number> {
  const backend = backendOf(a);
  const probe = await probeCodex({ configured: a.codex ?? null, sourceEnv: io.env });
  io.out(`running the offline cp_fix writable-profile self-test: codex ${probe.version}, backend ${backend} (no model call)`);
  const env = buildChildEnv({ source: io.env, includeCodexAuth: true }).env;
  const rec = await runFixSelfTest({ probe, backend, dataHome, env });
  await storeFixSelfTest(selftestDir, rec);
  if (!rec.profile_runs) io.out(`cp_fix profile rejected on ${backend}: ${rec.rejection_reason ?? "unknown"}`);
  for (const r of rec.rows) io.out(`  ${r.pass ? "PASS" : "FAIL"} ${r.name}: expected ${r.expectation}, sandbox ${r.sandbox}, positive control ${r.positive_control}${r.inconclusive ? " (inconclusive)" : ""}`);
  io.out(`cp_fix confinement available on ${backend}: ${rec.confinement_available ? "YES" : "no"} (self-test ${rec.selftest_id}, codex ${rec.codex_sha256.slice(0, 12)}, profile ${rec.profile_digest.slice(0, 12)}, stored)`);
  return rec.confinement_available ? 0 : 1;
}

function acceptanceDigest(backend: string, range: string): string {
  return sha256OfCanonicalJson({ statement: REDUCED_ISOLATION_STATEMENT_SHA256, backend, accepted: ["advisory_network", "unrestricted_reads"], range });
}

async function acceptCmd(a: CodexCliArgs, io: CodexCliIo, path: string): Promise<number> {
  const backend = backendOf(a);
  const probe = await probeCodex({ configured: a.codex ?? null, sourceEnv: io.env });
  const range = probe.compat.versionPrefix;
  const digest = acceptanceDigest(backend, range);
  io.out(`Accept reduced Codex isolation for backend ${backend}, Codex ${range}x:`);
  io.out(`  accepted reductions: unrestricted_reads, advisory_network`);
  io.out(`  ${REDUCED_ISOLATION_STATEMENT}`);
  io.out("  S1 is still used whenever its self-test passes; this acceptance applies only when it does not.");
  io.out(`acceptance digest: ${digest}`);
  let ok = !!a.confirm && a.confirm.length >= 12 && digest.startsWith(a.confirm.toLowerCase());
  if (!ok && io.prompt) ok = (await io.prompt('Type "accept" to record this acceptance: ')).trim() === "accept";
  if (!ok) {
    io.out(`Not recorded. Re-run with --confirm ${digest.slice(0, 16)}`);
    return 2;
  }
  const { file, problem } = await loadAcceptances(path);
  if (problem) throw new DomainError("CONFIG_INVALID", problem);
  const rec: IsolationAcceptance = {
    acceptance_id: uuidv7(),
    accepted: ["unrestricted_reads", "advisory_network"],
    backend,
    codex_version_range: range,
    statement_sha256: REDUCED_ISOLATION_STATEMENT_SHA256,
    accepted_at: new Date().toISOString(),
    via: "cli",
    revoked_at: null,
  };
  await mkdir(dirname(path), { recursive: true });
  await atomicWriteFile(path, JSON.stringify(IsolationAcceptanceFileSchema.parse({ ...file, records: [...file.records, rec] }), null, 2));
  io.out(`recorded acceptance ${rec.acceptance_id}; every review under it reports reduced isolation`);
  return 0;
}

async function revokeCmd(a: CodexCliArgs, io: CodexCliIo, path: string): Promise<number> {
  const { file, problem } = await loadAcceptances(path);
  if (problem) throw new DomainError("CONFIG_INVALID", problem);
  const live = file.records.filter((r) => r.revoked_at === null);
  if (!a.acceptance) {
    for (const r of live) io.out(`${r.acceptance_id}: ${r.backend} ${r.codex_version_range}x ${r.accepted.join(", ")} (accepted ${r.accepted_at})`);
    if (live.length === 0) io.out("no active acceptance");
    return 0;
  }
  const target = live.find((r) => r.acceptance_id.startsWith(a.acceptance!));
  if (!target) throw new DomainError("INVALID_ARGUMENT", `no active acceptance ${a.acceptance}`);
  const records = file.records.map((r) => (r.acceptance_id === target.acceptance_id ? { ...r, revoked_at: new Date().toISOString() } : r));
  await atomicWriteFile(path, JSON.stringify(IsolationAcceptanceFileSchema.parse({ ...file, records }), null, 2));
  io.out(`revoked acceptance ${target.acceptance_id}`);
  return 0;
}
