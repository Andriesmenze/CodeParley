// Phase 4 Increment 2 — delegation of one scoped fix to a custodian-validated proposal, end to end against real git
// repositories, the simulated custodian (with its in-process helper capture and derivation) and the scripted fake Codex.
// The fixer run itself is the test seam (the real one is Increment 1's launchFixer, verified on the VM): it edits the
// disposable workspace as Codex would. Every assertion reads the engine's and the custodian's own records.
//
//   N4-3  delegation refused without the custodian, on Linux, or without a protected configuration (P4-A);
//   N4-5  maxFixes refuses a further delegation;
//   N4-11 a pending proposal authorizes no continuation or wake;
//   FIX vs S1: a local cp_fix self-test, or the S1 confirmation, confers nothing — only the operator's FIX confirmation.
// N4-4 (the custodian rejects submitted content) is the shared corpus (test/fixtures/run-transition-corpus.json), held by
// both the simulated and the real custodian.

import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { delegateFix, type DelegateFixInput } from "../src/engine/fix-operation.js";
import { fixProfileFor } from "../src/engine/fix-confirmation.js";
import { fixSelfTestKey, storeFixSelfTest } from "../src/agents/codex/fix-selftest.js";
import { fixProfileDigest } from "../src/agents/codex/fix-profile.js";
import { probeCodex } from "../src/agents/codex/probe.js";
import { custodianDerivationOf } from "../src/custodian/grants.js";
import { storeLayout } from "../src/store/paths.js";
import type { FixLaunchRequest } from "../src/agents/codex/fix-launcher.js";
import type { SandboxBackend } from "../src/agents/codex/argv.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, MATH_V1, MATH_V2, okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, fixtureBackend, grant, HostSession, newRun, operatorIo, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";
import type { RunHandle } from "../src/engine/engine-env.js";

const BOUND = { timeout: 240_000 };
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    return String((e as { code?: string }).code ?? (e as Error).message);
  }
}

const TASK: DelegateFixInput = {
  task: "add() subtracts: make it return a + b.",
  boundary: { permitted_files: ["src/math.js"], max_changed_files: 1, max_file_bytes: 4096, max_total_bytes: 4096, time_limit_seconds: 120, proposal_lifetime_seconds: 3600 },
};

/** The fixer, as Codex would act in the workspace: edit `rel` in the writable tree. */
const editing = (rel: string, text: string, seen: FixLaunchRequest[] = []) => async (req: FixLaunchRequest) => {
  seen.push(req);
  await mkdir(join(req.workspaceTree, ...rel.split("/"), ".."), { recursive: true });
  await writeFile(join(req.workspaceTree, ...rel.split("/")), text);
  return { outcome: { status: "completed" as const, failureClass: null, detail: "" } };
};

/** The cp_fix self-test of the fixture's Codex, stored as `code-parley codex fix-selftest` would (a passing record). */
async function storeFixSelfTest_(f: ContFixture): Promise<void> {
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
async function confirmFix(f: ContFixture): Promise<{ code: number; out: string; err: string }> {
  const r = await cli(f, ["config", "confirm-selftest", "--fix", "--repo", f.repo, "--backend", await fixtureBackend(f), "--codex", f.codexExe], operatorIo("confirm"));
  if (r.code !== 0) throw new Error(`config confirm-selftest --fix exit ${r.code}: ${r.err}`);
  return r;
}

/** A protected run (loop bound, checks run) with one accepted review the custodian captured; delegated fixes budgeted. */
async function protectedRun(maxFixes = 2): Promise<{ f: ContFixture; run: RunHandle; A: HostSession }> {
  const f = await contFixture(okScenario(output({ findings: [defect()] })), { custodianPlatform: process.platform }); // Phase 5 Increment 3: the host's own custodian platform
  (f.le.cfg.config.budgets as { max_fixes_per_run: number }).max_fixes_per_run = maxFixes;
  const run = await newRun(f);
  const A = new HostSession(f, "sess-FIX", 4747);
  await grant(f, 1);
  await A.startLoop(run);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  return { f, run, A };
}

/** The run's fix operations as the custodian holds them. */
const fixOps = (f: ContFixture, run: RunHandle) => (f.custodian.snapshot().runs ?? []).find((r) => r.runId === run.runId)?.operations.filter((o) => o.kind === "fix") ?? [];

describe.skipIf(!supported)("Phase 4 Increment 2: delegation to a custodian-validated proposal (engine)", BOUND, () => {
  it("delegates one scoped fix: seeded from the custodian's capture, the fixer's edit becomes the custodian's held proposal; the workspace is destroyed and the primary worktree untouched", async () => {
    const { f, run } = await protectedRun();
    await storeFixSelfTest_(f);
    expect((await confirmFix(f)).code).toBe(0);
    const seen: FixLaunchRequest[] = [];
    const r = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1, seen) });
    expect(r.status).toBe("proposed");
    expect(r.proposal).toMatchObject({ change_count: 1, total_bytes: Buffer.byteLength(MATH_V1) });
    expect(r.violations).toEqual([]);

    // The fixer ran in a disposable workspace under the data home, seeded from the custodian's published capture, with
    // the primary worktree among the protected paths; the task and the boundary are its instructions.
    const req = seen[0]!;
    expect(req.workspaceTree.startsWith(join(f.dataHome, "work", run.runId))).toBe(true);
    expect(req.workspaceTree.toLowerCase().startsWith(f.repo.toLowerCase())).toBe(false);
    expect(req.protectedPaths.map((p) => p.toLowerCase())).toContain((await import("node:fs")).realpathSync.native(f.repo).toLowerCase());
    expect(req.prompt).toContain(TASK.task);
    expect(req.prompt).toContain("file src/math.js");
    expect(req.limits?.wallMs).toBe(120_000);

    // The workspace is gone; the primary worktree still has the defect (nothing is applied in Increment 2).
    expect(existsSync(join(f.dataHome, "work", run.runId)) ? await readdir(join(f.dataHome, "work", run.runId)) : []).toEqual([]);
    expect(await readFile(join(f.repo, "src", "math.js"), "utf8")).toBe(MATH_V2);

    // The custodian holds the canonical content under ITS digest, with the preimage from its own baseline capture.
    const held = f.custodian.heldProposalForTest(f.repo, run.runId, r.operation_id);
    expect(held).toMatchObject({ held: true, proposalDigest: r.proposal!.proposal_digest, paths: ["src/math.js"], preimages: [{ size: Buffer.byteLength(MATH_V2), sha256: sha(MATH_V2) }] });
    expect(fixOps(f, run).map((o) => o.status)).toEqual(["proposed"]);
  });

  it("N4-11: a pending proposal authorizes no continuation or wake; the custodian's derivation routes it to an await", async () => {
    const { f, run, A } = await protectedRun();
    await storeFixSelfTest_(f);
    expect((await confirmFix(f)).code).toBe(0);
    // Before the delegation the open finding is an implementer step.
    const runJson = await readFile(run.paths.runJson);
    const before = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, runJson);
    expect(before.available && before.route.kind).toBe("implementer_step");
    expect((await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) })).status).toBe("proposed");
    const after = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, runJson);
    expect(after.available && after.route).toMatchObject({ code: "await_fix_confirmation", kind: "await", reason: "fix_proposal_pending" });
    // The Stop hook gives no continuation (the route is not an implementer step); the loop is not even paused by it.
    const s = await A.stop(false);
    expect(s.verdict).toBe("none");
    // Once the proposal's lifetime is over it is no longer pending: the route is the finding again.
    f.clock.now = Date.now() + 2 * 3600_000;
    const expired = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, runJson);
    expect(expired.available && expired.route.code).not.toBe("await_fix_confirmation");
  });

  it("FIX vs S1: neither the S1 confirmation nor a local cp_fix self-test confers anything; only the operator's FIX confirmation lets the custodian begin a fix", async () => {
    const { f, run } = await protectedRun();
    // The S1 reviewer confirmation is in force (protectConfig), but there is no cp_fix self-test.
    expect(await codeOf(delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) }))).toBe("CODEX_ISOLATION_UNAVAILABLE");
    // A passing local cp_fix self-test alone: still nothing (no custodian-held FIX confirmation).
    await storeFixSelfTest_(f);
    let launched = 0;
    expect(await codeOf(delegateFix(f.le, run, TASK, { launch: async (q) => { launched++; return editing("src/math.js", MATH_V1)(q); } }))).toBe("CODEX_ISOLATION_UNAVAILABLE");
    expect(launched).toBe(0);
    expect(fixOps(f, run)).toEqual([]);
    // The operator's rendering names it a FIX confirmation, separate from S1, bound to the Codex binary.
    const confirmed = await confirmFix(f);
    expect(confirmed.code).toBe(0);
    expect(confirmed.out).toContain("Confirm the FIX self-test record for delegated fixes (separate from the S1 review confirmation)");
    expect(confirmed.out).toContain(`Codex binary SHA-256 ${sha(await readFile(f.codexExe))}`);
    expect((await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) })).status).toBe("proposed");
  });

  it("N4-5: maxFixes refuses a further delegation (nothing begun); without a declared budget none is allowed", async () => {
    const { f, run } = await protectedRun(1);
    await storeFixSelfTest_(f);
    expect((await confirmFix(f)).code).toBe(0);
    expect((await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) })).status).toBe("proposed");
    let launched = 0;
    expect(await codeOf(delegateFix(f.le, run, TASK, { launch: async (q) => { launched++; return editing("src/math.js", MATH_V1)(q); } }))).toBe("BUDGET_EXHAUSTED");
    expect(launched).toBe(0);
    expect(fixOps(f, run)).toHaveLength(1);

    const none = await protectedRun(0);
    await storeFixSelfTest_(none.f);
    expect((await confirmFix(none.f)).code).toBe(0);
    expect(await codeOf(delegateFix(none.f.le, none.run, TASK, { launch: editing("src/math.js", MATH_V1) }))).toBe("BUDGET_EXHAUSTED");
  });

  it("the engine's scan rejects an edit outside the boundary, a timed-out fixer is recorded as such; the custodian holds nothing and every workspace is destroyed", async () => {
    const { f, run } = await protectedRun(3);
    await storeFixSelfTest_(f);
    expect((await confirmFix(f)).code).toBe(0);
    const outside = await delegateFix(f.le, run, TASK, { launch: editing("README.md", "# changed\n") });
    expect(outside.status).toBe("rejected");
    expect(outside.detail).toContain("outside_boundary README.md");
    expect(f.custodian.heldProposalForTest(f.repo, run.runId, outside.operation_id)).toEqual({ held: false });
    const slow = await delegateFix(f.le, run, TASK, { launch: async () => ({ outcome: { status: "timed_out" as const, failureClass: "wall_timeout", detail: "the fixer exceeded its time limit" } }) });
    expect(slow.status).toBe("timed_out");
    expect(fixOps(f, run).map((o) => o.status)).toEqual(["rejected", "timed_out"]);
    expect(existsSync(join(f.dataHome, "work", run.runId)) ? await readdir(join(f.dataHome, "work", run.runId)) : []).toEqual([]);
    expect(await readFile(join(f.repo, "src", "math.js"), "utf8")).toBe(MATH_V2);
  });

  it("N4-3: refused on an attended run (no custodian holds it), with the custodian unreachable, or without a protected configuration — before anything is begun", async () => {
    // An attended run: the custodian holds no record of it.
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { custodianPlatform: process.platform }); // Phase 5 Increment 3: the host's own custodian platform
    const attended = await newRun(f);
    expect(await codeOf(delegateFix(f.le, attended, TASK, { launch: editing("src/math.js", MATH_V1) }))).toBe("FIX_DELEGATION_UNAVAILABLE");

    const p = await protectedRun();
    await storeFixSelfTest_(p.f);
    expect((await confirmFix(p.f)).code).toBe(0);
    // The custodian unreachable: fail closed, never a local fallback.
    p.f.custodian.setUnavailable("simulated: the custodian service is stopped");
    expect(await codeOf(delegateFix(p.f.le, p.run, TASK, { launch: editing("src/math.js", MATH_V1) }))).toBe("CUSTODIAN_UNAVAILABLE");
    p.f.custodian.setUnavailable(null);
    // The repository's protected configuration revoked by the operator.
    const revoked = await cli(p.f, ["config", "revoke", "--repo", p.f.repo], operatorIo("confirm"));
    expect(revoked.code, revoked.err).toBe(0);
    expect(await codeOf(delegateFix(p.f.le, p.run, TASK, { launch: editing("src/math.js", MATH_V1) }))).toBe("FIX_DELEGATION_UNAVAILABLE");
    expect(fixOps(p.f, p.run)).toEqual([]);
  });

  it("N4-3: refused on a platform without the custodian (Phase 5 Increment 3: Windows and Linux only) — nothing is exchanged with the custodian", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { custodianPlatform: "darwin" });
    const run = await newRun(f);
    const before = f.custodian.received.length;
    const e = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) }).catch((x: unknown) => x as { code?: string; message?: string });
    expect((e as { code?: string }).code).toBe("FIX_DELEGATION_UNAVAILABLE");
    expect(String((e as { message?: string }).message)).toContain("on Windows or Linux");
    expect(f.custodian.received.length).toBe(before);
  });

  it("Phase 5 Increment 3: on Linux the platform admits a delegated fix; an attended run is still refused as not protected", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { custodianPlatform: "linux" });
    const run = await newRun(f);
    const e = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) }).catch((x: unknown) => x as { code?: string; message?: string });
    expect((e as { code?: string }).code).toBe("FIX_DELEGATION_UNAVAILABLE");
    expect(String((e as { message?: string }).message)).toContain("not protected");
  });
});
