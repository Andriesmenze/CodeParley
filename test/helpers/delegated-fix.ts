// Phase 4 test helpers: a protected run with an accepted, custodian-captured review, the cp_fix self-test and its operator
// FIX confirmation, and the fixer as Codex would act in the disposable workspace (the real fixer is Increment 1's
// launchFixer, verified on the VM). Shared by the Increment 2 (delegation) and Increment 3 (application) engine tests.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { fixProfileFor } from "../../src/engine/fix-confirmation.js";
import { fixSelfTestKey, storeFixSelfTest } from "../../src/agents/codex/fix-selftest.js";
import { fixProfileDigest } from "../../src/agents/codex/fix-profile.js";
import { probeCodex } from "../../src/agents/codex/probe.js";
import { storeLayout } from "../../src/store/paths.js";
import type { FixLaunchRequest } from "../../src/agents/codex/fix-launcher.js";
import type { SandboxBackend } from "../../src/agents/codex/argv.js";
import type { DelegateFixInput } from "../../src/engine/fix-operation.js";
import type { RunHandle } from "../../src/engine/engine-env.js";
import { defect, okScenario, output } from "./review-fixture.js";
import { cli, contFixture, fixtureBackend, grant, HostSession, newRun, operatorIo, runChecks, startReview, type ContFixture, type ContFixtureOptions } from "./continuation-fixture.js";

export const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

export async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    return String((e as { code?: string }).code ?? (e as Error).message);
  }
}

export const TASK: DelegateFixInput = {
  task: "add() subtracts: make it return a + b.",
  boundary: { permitted_files: ["src/math.js"], max_changed_files: 1, max_file_bytes: 4096, max_total_bytes: 4096, time_limit_seconds: 120, proposal_lifetime_seconds: 3600 },
};

/** The fixer, as Codex would act in the workspace: write each file (repository-relative) in the writable tree. */
export const editingMany = (files: Record<string, string>, seen: FixLaunchRequest[] = []) => async (req: FixLaunchRequest) => {
  seen.push(req);
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(join(req.workspaceTree, ...rel.split("/"), ".."), { recursive: true });
    await writeFile(join(req.workspaceTree, ...rel.split("/")), text);
  }
  return { outcome: { status: "completed" as const, failureClass: null, detail: "" } };
};

export const editing = (rel: string, text: string, seen: FixLaunchRequest[] = []) => editingMany({ [rel]: text }, seen);

/** The cp_fix self-test of the fixture's Codex, stored as `code-parley codex fix-selftest` would (a passing record). */
export async function storeFixSelfTest_(f: ContFixture): Promise<void> {
  const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
  const backend = (await fixtureBackend(f)) as SandboxBackend;
  const codexSha256 = sha(await readFile(f.codexExe));
  const profile = fixProfileFor(backend, probe, [join(f.dataHome, "fix-selftest-work", "tree"), join(f.dataHome, "fix-selftest-work", "scratch")], [probe.codexHome]);
  await storeFixSelfTest(storeLayout(f.dataHome).selftestDir, {
    schema: "arl.codex-fix-selftest.v1", selftest_id: "fix-selftest-1", key: fixSelfTestKey(probe.version, codexSha256, profile), codex_version: probe.version,
    codex_sha256: codexSha256, backend, profile_digest: fixProfileDigest(profile), created_at: new Date().toISOString(), profile_runs: true, rejection_reason: null,
    rows: [{ name: "native_edit_outside_denied", expectation: "denied", sandbox: "denied", positive_control: "ok", pass: true, detail: "test record" }],
    confinement_available: true, complete: true,
  });
}

/** The operator confirms the stored cp_fix self-test as the FIX basis (`config confirm-selftest --fix`, typed). */
export async function confirmFix(f: ContFixture): Promise<{ code: number; out: string; err: string }> {
  const r = await cli(f, ["config", "confirm-selftest", "--fix", "--repo", f.repo, "--backend", await fixtureBackend(f), "--codex", f.codexExe], operatorIo("confirm"));
  if (r.code !== 0) throw new Error(`config confirm-selftest --fix exit ${r.code}: ${r.err}`);
  return r;
}

/** A protected run (loop bound, checks run) with one accepted review the custodian captured; delegated fixes budgeted. */
export async function protectedRun(maxFixes = 2, opts: ContFixtureOptions = {}, before?: (f: ContFixture) => Promise<void>): Promise<{ f: ContFixture; run: RunHandle; A: HostSession }> {
  // Phase 5 Increment 3: the host's own custodian platform (Windows or Linux), unless a test names another.
  const f = await contFixture(okScenario(output({ findings: [defect()] })), { custodianPlatform: process.platform, ...opts });
  await before?.(f);
  (f.le.cfg.config.budgets as { max_fixes_per_run: number }).max_fixes_per_run = maxFixes;
  const run = await newRun(f);
  const A = new HostSession(f, "sess-FIX", 4747);
  await grant(f, 1);
  await A.startLoop(run);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  return { f, run, A };
}

/** The run's operations of `kind` as the custodian holds them. */
export const opsOf = (f: ContFixture, run: RunHandle, kind: string) => (f.custodian.snapshot().runs ?? []).find((r) => r.runId === run.runId)?.operations.filter((o) => o.kind === kind) ?? [];
