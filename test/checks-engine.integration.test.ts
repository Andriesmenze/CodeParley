// M1.3 checks operation on real git repositories (shared contract, Windows and Linux): persistence, identities,
// freshness (MR-G), supersession (MR-D), approval changes, skipped/removed checks,
// idempotency, timeouts, cancellation, caps, worktree serialization, repository code that
// writes files or trusted configuration during a check, budgets.

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  buildResult,
  evaluateChecksStatus,
  requestChecksCancel,
  startChecks,
  type ChecksEngineContext,
  type ChecksRequest,
} from "../src/engine/checks-operation.js";
import { readState } from "../src/store/state-store.js";
import { acquireWorktreeLock, liveWorktreeWaiter, readWorktreeLock } from "../src/store/locks.js";
import { selfOwner, type OwnerRecord } from "../src/store/owner.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { approve, makeFixture, newRun, type Fixture } from "./helpers/checks-fixture.js";
import { win, supported, commitAll } from "./helpers/git-fixture.js";

async function run(ctx: ChecksEngineContext, req: ChecksRequest = {}) {
  const s = await startChecks(ctx, req);
  return s.completion;
}

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await expect(p).rejects.toSatisfy((e) => (e as { code?: string }).code === code);
}

const basic = (f: Fixture) => ({
  checks: {
    unit: { argv: ["node", "scripts/flag.js"] },
    lint: { argv: ["node", "scripts/pass.js", "lint"] },
  },
  profiles: { default: ["unit", "lint"] },
  required_profiles: ["default"],
});

describe.skipIf(!supported)("checks operation (M1.3)", () => {
  it("runs the floor, persists records and artifacts, and the floor is satisfied for the current source", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const r = await run(ctx);
    expect(r.status).toBe("passed");
    expect(r.results.map((x) => [x.check, x.status])).toEqual([
      ["unit", "passed"],
      ["lint", "passed"],
    ]);
    expect(r.results[1]!.stdout_tail).toBe("PASS lint");
    expect(r.stable).toBe(true);
    expect(r.source_id_at_start).toMatch(/^[0-9a-f]{64}$/);
    expect(r.floor.satisfied_for_current_source).toBe(true);
    expect(r.conditions).toEqual([]);
    expect(r.limitations.map((l) => l.code)).toEqual(expect.arrayContaining(["environment_bound_partial", "checks_unsandboxed"]));
    expect(r.summary).toMatch(/necessary evidence, not proof/);

    const st = await readState(ctx.runPaths);
    expect(st.state).toBe("IDLE");
    expect(st.counters["check_executions"]).toBe(2);
    const op = st.operations.find((o) => o.operation_id === r.operation_id)!;
    expect(op.status).toBe("completed");
    const e = st.check_executions[1]!;
    expect(e.check_spec_id).toMatch(/^[0-9a-f]{64}$/);
    expect(e.execution_input_id).toMatch(/^[0-9a-f]{64}$/);
    expect(e.resolved_executable?.path).toMatch(win ? /node\.exe$/i : /\/node$/);
    expect(e.environment_bound).toBe("partial");
    expect(readFileSync(resolveArtifact(ctx.runPaths.runDir, e.stdout!.artifact!), "utf8")).toBe("PASS lint");
    expect(JSON.parse(readFileSync(resolveArtifact(ctx.runPaths.runDir, e.result_artifact!), "utf8")).stdout_tail).toBe("PASS lint");
    // No environment VALUE is persisted, only names and a digest. (The resolved executable's
    // path is recorded on purpose — part of check_spec_id — and may lie under the profile, as
    // with nvm-windows, nvm, Volta or a portable Node; every other field must not carry a value.)
    const withoutExecutable = JSON.stringify({ ...st, check_executions: st.check_executions.map((x) => ({ ...x, resolved_executable: null })) });
    expect(withoutExecutable).not.toContain(process.env[win ? "USERPROFILE" : "HOME"]!.replace(/\\/g, "\\\\"));
    expect(JSON.stringify(st)).not.toContain(JSON.stringify(process.env["PATH"]!).slice(1, -1));
    // The worktree lock was released.
    expect(existsSync(worktreeLockPath(f.dataHome, canonicalPathKey(f.repo)))).toBe(false);
  }, 60_000);

  it("MR-D: a failure is superseded by a successful re-run on current inputs (fix, then same-source flake)", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    await writeFile(join(f.repo, "flag.txt"), "bad\n");
    const r1 = await run(ctx);
    expect(r1.status).toBe("failed");
    expect(r1.results[0]).toMatchObject({ check: "unit", status: "failed", exit_code: 1, stdout_tail: "flag=bad" });
    expect(r1.conditions.map((c) => `${c.check}:${c.kind}`)).toEqual(["unit:check_failed"]);
    await writeFile(join(f.repo, "flag.txt"), "good\n");
    // The fix changed the source: the earlier failure is now stale, not "failing".
    const mid = await evaluateChecksStatus(ctx, (await run(ctx, { checks: ["lint"] })).source_id_at_end);
    expect(mid.floor.stale).toEqual(["unit"]);
    const r2 = await run(ctx, { checks: ["unit"] });
    expect(r2.floor.satisfied_for_current_source).toBe(true);
    expect(r2.conditions).toEqual([]);

    // Same source: a flaky check fails then passes; the later fresh pass decides.
    const counter = join(f.scratch, "flaky-counter");
    await approve(f, { checks: { flaky: { argv: ["node", "scripts/flaky.js", counter] } }, profiles: { default: ["flaky"] }, required_profiles: ["default"] });
    const ctx2 = await newRun(f);
    const a = await run(ctx2);
    expect(a.status).toBe("failed");
    const b = await run(ctx2);
    expect(b.status).toBe("passed");
    expect(b.source_id_at_end).toBe(a.source_id_at_end);
    const flaky = b.floor.checks.find((c) => c.check === "flaky")!;
    expect(flaky.status).toBe("satisfied");
    expect(flaky.superseded_failures).toBe(1);
  }, 90_000);

  it("a changed approved command definition is not runnable until re-approved; earlier results become stale (spec)", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const r = await run(ctx);
    expect(r.floor.satisfied_for_current_source).toBe(true);

    // Hand-edit the trusted file (as a host agent or repository code might).
    const trust = JSON.parse(await readFile(f.trustProjectsPath, "utf8"));
    const key = Object.keys(trust)[0]!;
    trust[key].checks.lint.argv = ["node", "scripts/pass.js", "lint", "--fix"];
    await writeFile(f.trustProjectsPath, JSON.stringify(trust));
    await expectCode(run(ctx), "CHECK_NOT_APPROVED");
    await expectCode(run(ctx, { checks: ["lint"] }), "CHECK_NOT_APPROVED");
    const st = await evaluateChecksStatus(ctx, r.source_id_at_end);
    expect(st.trusted_status).toBe("approval_invalid");
    expect(st.floor.unapproved.sort()).toEqual(["lint", "unit"]);
    expect(st.floor.satisfied_for_current_source).toBe(false);

    // Re-approve the changed definition: the old lint result is stale (spec changed, same source).
    await approve(f, { ...basic(f), checks: { ...basic(f).checks, lint: { argv: ["node", "scripts/pass.js", "lint", "--fix"] } } });
    const st2 = await evaluateChecksStatus(ctx, r.source_id_at_end);
    const lint = st2.floor.checks.find((c) => c.check === "lint")!;
    expect(lint.status).toBe("stale");
    expect(lint.freshness).toMatchObject({ source: "fresh", spec: "changed", environment: "fresh" });
    expect(lint.definition_changed_since_floor).toBe(true);
    expect(st2.floor.checks.find((c) => c.check === "unit")!.status).toBe("satisfied");
  }, 90_000);

  it("same source, changed check spec (timeout only) makes the result stale for spec reasons only", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const r = await run(ctx);
    await approve(f, { ...basic(f), checks: { ...basic(f).checks, unit: { argv: ["node", "scripts/flag.js"], timeout_seconds: 60 } } });
    const st = await evaluateChecksStatus(ctx, r.source_id_at_end);
    const unit = st.floor.checks.find((c) => c.check === "unit")!;
    expect(unit.status).toBe("stale");
    expect(unit.freshness?.reasons).toEqual(["spec_changed"]);
    expect(st.conditions.map((c) => `${c.check}:${c.kind}`)).toEqual(["unit:check_stale"]);
  }, 60_000);

  it("MR-G: a changed passthrough value or freshness input makes the earlier result stale (environment), source unchanged", async () => {
    const f = await makeFixture();
    await writeFile(join(f.repo, "deps-placeholder"), "");
    await approve(f, {
      checks: { envcheck: { argv: ["node", "scripts/env.js", "CODEPARLEY_TEST_MODE"], env_passthrough: ["CODEPARLEY_TEST_MODE"], freshness_inputs: ["deps/lock.txt"] } },
      profiles: { default: ["envcheck"] },
      required_profiles: ["default"],
    });
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(f.repo, "deps"), { recursive: true });
    await writeFile(join(f.repo, "deps", "lock.txt"), "v1"); // ignored by .gitignore: not part of source_id
    const ctx = await newRun(f, { sourceEnv: { ...process.env, CODEPARLEY_TEST_MODE: "alpha" } });
    const r = await run(ctx);
    expect(r.results[0]!.stdout_tail).toBe("alpha");
    expect(r.floor.satisfied_for_current_source).toBe(true);
    const S = r.source_id_at_end;

    // 1. passthrough value changes
    const ctxEnv = { ...ctx, sourceEnv: { ...process.env, CODEPARLEY_TEST_MODE: "beta" } };
    const s1 = await evaluateChecksStatus(ctxEnv, S);
    const v1 = s1.floor.checks[0]!;
    expect(v1.status).toBe("stale");
    expect(v1.freshness).toMatchObject({ source: "fresh", spec: "fresh", environment: "changed", reasons: ["environment_values_changed"] });
    // the passthrough variable disappearing is also a change
    const s1b = await evaluateChecksStatus({ ...ctx, sourceEnv: { ...process.env, CODEPARLEY_TEST_MODE: undefined } }, S);
    expect(s1b.floor.checks[0]!.status).toBe("stale");

    // 2. freshness input changes (source_id unchanged: the file is ignored)
    await writeFile(join(f.repo, "deps", "lock.txt"), "v2");
    const s2 = await evaluateChecksStatus(ctx, S);
    expect(s2.floor.checks[0]!.freshness).toMatchObject({ source: "fresh", spec: "fresh", environment: "changed", reasons: ["freshness_inputs_changed"] });

    // 3. back to the original inputs: fresh again
    await writeFile(join(f.repo, "deps", "lock.txt"), "v1");
    expect((await evaluateChecksStatus(ctx, S)).floor.satisfied_for_current_source).toBe(true);
    // the execution input ids differ while the spec id is the same
    const st = await readState(ctx.runPaths);
    expect(st.check_executions[0]!.freshness_inputs).toEqual([{ path: "deps/lock.txt", state: "file", sha256: expect.stringMatching(/^[0-9a-f]{64}$/), size: 2 }]);
    expect(st.check_executions[0]!.env_names).toContain("CODEPARLEY_TEST_MODE");
    expect(JSON.stringify(st)).not.toContain("alpha"); // the value itself is never stored
  }, 60_000);

  it("retry/idempotency: same request_id returns the same operation; different arguments conflict; a running duplicate is deduplicated", async () => {
    const f = await makeFixture();
    // The first operation's check runs until the test releases it, so the duplicate finds it
    // running however long its own start takes. (On a loaded Windows runner that has outlasted
    // a fixed 2.5 s sleep.)
    const release = join(f.scratch, "release");
    const waiter = join(f.scratch, "wait-for-release.js");
    await writeFile(waiter, "const fs=require('fs');const p=process.argv[2];const k=setTimeout(()=>process.exit(2),50000);const t=setInterval(()=>{if(fs.existsSync(p)){clearInterval(t);clearTimeout(k);process.stdout.write('released');}},20);\n");
    await approve(f, { checks: { slow: { argv: ["node", waiter, release] }, lint: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["slow"] }, required_profiles: ["default"] });
    const ctx = await newRun(f);
    const a = await startChecks(ctx, { request_id: "req-1" });
    const dup = await startChecks(ctx, {}); // same selection (the floor), still running
    expect(dup.operation_id).toBe(a.operation_id);
    expect(dup.deduplicated).toBe(true);
    await expectCode(startChecks(ctx, { checks: ["lint"] }), "RUN_BUSY");
    await expectCode(startChecks(ctx, { request_id: "req-1", checks: ["lint"] }), "REQUEST_ID_CONFLICT");
    await writeFile(release, "");
    const r = await a.completion;
    const again = await startChecks(ctx, { request_id: "req-1" });
    expect(again.operation_id).toBe(a.operation_id);
    expect((await again.completion).execution_ids).toEqual(r.execution_ids);
    // Without a request_id a completed check is re-run (re-running detects flakiness).
    const fresh = await startChecks(ctx, {});
    expect(fresh.operation_id).not.toBe(a.operation_id);
    await fresh.completion;
    expect((await readState(ctx.runPaths)).counters["check_executions"]).toBe(2);
  }, 60_000);

  it("a duplicate start while this server's own operation runs is deduplicated without querying that owner's liveness", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { lint: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["lint"] }, required_profiles: ["default"] });
    // The first operation waits once it holds the worktree lock, until the test (or the query
    // below) lets it go on.
    let go!: () => void;
    const held = new Promise<void>((r) => (go = r));
    // A liveness query that outlasts the first operation, as PowerShell has on a loaded Windows
    // runner: it lets the operation finish and waits for it, so a duplicate whose start queried
    // this server's own owner would find nothing running and start a new operation.
    const queried: OwnerRecord[] = [];
    let first: Promise<unknown> = Promise.resolve();
    const ctx: ChecksEngineContext = {
      ...(await newRun(f)),
      classify: async (o) => {
        queried.push(o);
        go();
        await first;
        return "alive";
      },
    };
    ctx.testHooks = { sweep: null, afterLock: () => held };
    const a = await startChecks(ctx, {});
    first = a.completion;
    const dup = await startChecks(ctx, {});
    expect(queried).toEqual([]);
    expect(dup).toMatchObject({ operation_id: a.operation_id, deduplicated: true });
    go();
    expect((await a.completion).status).toBe("passed");
    expect((await readState(ctx.runPaths)).operations.map((o) => o.operation_id)).toEqual([a.operation_id]);
  }, 60_000);

  it("timeouts are recorded as timed_out (a failure on these inputs) and the tree is killed", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { hang: { argv: ["node", "scripts/sleep.js", "600000"], timeout_seconds: 2 } }, profiles: { default: ["hang"] }, required_profiles: ["default"] });
    const ctx = await newRun(f);
    const r = await run(ctx);
    expect(r.status).toBe("timed_out");
    // Windows: taskkill /F leaves exit code 1; Linux: the process ends by a signal (no exit code).
    expect(r.results[0]).toMatchObject({ status: "timed_out", exit_code: win ? 1 : null });
    expect(r.conditions.map((c) => `${c.check}:${c.kind}:${c.reason}`)).toEqual(["hang:check_failed:timed_out"]);
  }, 60_000);

  it("cancellation stops the running check and records the rest as skipped (operation_cancelled)", async () => {
    const f = await makeFixture();
    await approve(f, {
      checks: { slow: { argv: ["node", "scripts/sleep.js", "60000"] }, after: { argv: ["node", "scripts/pass.js"] } },
      profiles: { default: ["slow", "after"] },
      required_profiles: ["default"],
    });
    const ctx = await newRun(f);
    let spawned!: () => void;
    const started = new Promise<void>((r) => (spawned = r));
    ctx.testHooks = { sweep: null, afterSpawn: () => spawned() };
    const s = await startChecks(ctx, {});
    await started;
    expect(requestChecksCancel(s.operation_id)).toBe("cancellation_requested");
    const r = await s.completion;
    expect(r.status).toBe("cancelled");
    expect(r.operation_status).toBe("cancelled");
    expect(r.results.map((x) => [x.check, x.status, x.skip_reason])).toEqual([
      ["slow", "cancelled", null],
      ["after", "skipped", "operation_cancelled"],
    ]);
    expect(r.floor.missing).toEqual(["after"]);
    expect(r.floor.cancelled).toEqual(["slow"]);
    expect((await readState(ctx.runPaths)).counters["check_executions"]).toBe(1);
  }, 60_000);

  it("a cancel that lands while the worktree lock is being obtained releases it at once: nothing runs or is recorded (D-31)", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    const read = await acquireWorktreeLock(lockPath, { owner: selfOwner(), operationId: "status-1", kind: "capture" });
    // The lock layer stamps each attempt with deps.now(): cancelling from there makes the cancel
    // land while the attempt that obtains the lock is in flight.
    let cancelOnNextAttempt: string | null = null;
    ctx.lockDeps = {
      worktreeWaitPollMs: 1000,
      now: () => {
        if (cancelOnNextAttempt) {
          requestChecksCancel(cancelOnNextAttempt);
          cancelOnNextAttempt = null;
        }
        return Date.now();
      },
    };
    const s = await startChecks(ctx, {});
    for (let i = 0; i < 200 && !(await liveWorktreeWaiter(lockPath)); i++) await new Promise((r) => setTimeout(r, 25));
    expect((await liveWorktreeWaiter(lockPath))?.operation_id).toBe(s.operation_id);
    await read.release(); // free before the waiter's next attempt, about a second away
    cancelOnNextAttempt = s.operation_id;
    const r = await s.completion;
    expect(r.operation_status).toBe("cancelled");
    expect(r.execution_ids).toEqual([]);
    expect(r.summary).toContain("checks cancelled: no check ran;");
    expect(await readWorktreeLock(lockPath)).toBeNull();
  }, 60_000);

  it("a cancel that lands once the worktree lock is held, before the tree is read, stops that read: nothing runs or is recorded (D-31)", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    let gitQueries = 0;
    ctx.testHooks = {
      // After the check made right after obtaining the lock: the cancel is pending while the
      // read verifies the held lock.
      afterLock: (id) => void requestChecksCancel(id),
      sourceRead: { onGitQuery: () => void gitQueries++ },
    };
    const r = await (await startChecks(ctx, {})).completion;
    expect(r.operation_status).toBe("cancelled");
    expect(r.execution_ids).toEqual([]);
    expect(r.summary).toContain("checks cancelled: no check ran;");
    expect(gitQueries).toBe(0); // the tree was not read
    expect(await readWorktreeLock(lockPath)).toBeNull();
  }, 60_000);

  it("a cancel that lands while the tree is first read stops the read: nothing runs or is recorded (D-31)", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    let operationId: string | null = null;
    let cancelled = false;
    ctx.testHooks = {
      afterLock: (id) => {
        operationId = id;
      },
      sourceRead: {
        afterAttributeScan: () => {
          if (operationId && !cancelled) cancelled = requestChecksCancel(operationId) === "cancellation_requested";
        },
      },
    };
    const r = await (await startChecks(ctx, {})).completion;
    expect(cancelled).toBe(true);
    expect(r.operation_status).toBe("cancelled");
    expect(r.execution_ids).toEqual([]);
    expect(r.summary).toContain("checks cancelled: no check ran;");
    expect(await readWorktreeLock(lockPath)).toBeNull();
  }, 60_000);

  it("output caps: stored logs are capped, the result says truncated, the tail is the true end", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { flood: { argv: ["node", "scripts/flood.js"] } }, profiles: { default: ["flood"] }, required_profiles: ["default"] });
    const ctx = await newRun(f);
    ctx.testHooks = { sweep: null, streamCapBytes: 100_000 };
    const r = await run(ctx);
    expect(r.results[0]).toMatchObject({ status: "passed", truncated: true, stdout_bytes: 64 * 65536 + 3 });
    expect(r.results[0]!.stdout_tail.endsWith("END")).toBe(true);
    const e = (await readState(ctx.runPaths)).check_executions[0]!;
    expect(readFileSync(resolveArtifact(ctx.runPaths.runDir, e.stdout!.artifact!)).length).toBe(100_000);
    expect(r.limitations.map((l) => l.code)).toContain("check_output_truncated");
  }, 60_000);

  it("skipped and removed checks are recorded distinctly; a removed required check stays in the floor as removed", async () => {
    const f = await makeFixture();
    const defs = { checks: { a: { argv: ["node", "scripts/pass.js", "a"] }, b: { argv: ["node", "scripts/pass.js", "b"] }, c: { argv: ["node", "scripts/pass.js", "c"] } }, profiles: { default: ["a", "b", "c"] }, required_profiles: ["default"] };
    await approve(f, defs);
    const ctx = await newRun(f);
    ctx.testHooks = {
      sweep: null,
      beforeCheck: async (name) => {
        // While `a` ran, the user re-approved without `b` and with a changed `c`.
        if (name === "b") await approve(f, { checks: { a: defs.checks.a, c: { argv: ["node", "scripts/pass.js", "c2"] } }, profiles: { default: ["a", "c"] }, required_profiles: ["default"] });
      },
    };
    const r = await run(ctx);
    expect(r.results.map((x) => [x.check, x.status, x.skip_reason])).toEqual([
      ["a", "passed", null],
      ["b", "skipped", "definition_removed"],
      ["c", "skipped", "definition_changed"],
    ]);
    expect(r.status).toBe("error"); // requested verification did not all happen
    expect(r.floor.removed).toEqual(["b"]);
    expect(r.floor.missing).toEqual(["c"]);
    expect(r.limitations.map((l) => l.code)).toContain("required_check_removed");
    // The next default run records the removed requirement as skipped again (never dropped).
    const r2 = await run(ctx);
    expect(r2.results.map((x) => [x.check, x.status, x.skip_reason])).toEqual([
      ["a", "passed", null],
      ["b", "skipped", "definition_removed"],
      ["c", "passed", null],
    ]);
    expect(r2.floor.satisfied_for_current_source).toBe(false);
  }, 90_000);

  it("checks are serialized per worktree across runs (WORKTREE_BUSY) and per run (RUN_BUSY)", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { slow: { argv: ["node", "scripts/sleep.js", "3000"] }, quick: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["slow"] }, required_profiles: ["default"] });
    const runA = await newRun(f);
    const runB = await newRun(f);
    const a = await startChecks(runA, {});
    // A different review run on the same worktree does not make concurrent builds safe.
    await expectCode(startChecks(runB, { checks: ["quick"] }), "WORKTREE_BUSY");
    await expectCode(startChecks(runA, { checks: ["quick"] }), "RUN_BUSY");
    // A capture also waits for the check: it is refused, not interleaved.
    const { computeSourceIdentity } = await import("../src/capture/capture.js");
    await expectCode(
      computeSourceIdentity({ repoRoot: f.repo, gitExe: f.git, rules: runA.rules, lock: { dataHome: f.dataHome, owner: runA.owner }, operationId: "cap" }),
      "WORKTREE_BUSY",
    );
    await a.completion;
    const b = await run(runB, { checks: ["quick"] });
    expect(b.status).toBe("passed");
    // runB's state never recorded a refused operation.
    expect((await readState(runB.runPaths)).operations.length).toBe(1);
  }, 60_000);

  it("repository code that writes files during a check: the result is unstable and never fresh; ignored outputs are fine", async () => {
    const f = await makeFixture();
    await approve(f, {
      checks: { gen: { argv: ["node", "scripts/write.js", "src/generated.txt"] }, build: { argv: ["node", "scripts/write.js", "build/out.txt"] } },
      profiles: { default: ["gen", "build"] },
      required_profiles: ["default"],
    });
    const ctx = await newRun(f);
    const r = await run(ctx);
    expect(r.results.map((x) => [x.check, x.status, x.source_stable])).toEqual([
      ["gen", "passed", false],
      ["build", "passed", true],
    ]);
    expect(r.stable).toBe(false);
    const gen = r.floor.checks.find((c) => c.check === "gen")!;
    expect(gen.status).toBe("stale");
    expect(gen.freshness?.source).toBe("unstable");
    expect(r.floor.checks.find((c) => c.check === "build")!.status).toBe("satisfied");
    expect(r.limitations.some((l) => l.code === "check_source_unstable" && l.detail.startsWith("gen:"))).toBe(true);
    // Re-running on the now-stable tree (the file exists, the rewrite changes its content
    // again) still never yields fresh evidence for `gen`.
    const r2 = await run(ctx, { checks: ["gen"] });
    expect(r2.floor.checks.find((c) => c.check === "gen")!.status).toBe("stale");
  }, 60_000);

  it("repository code that rewrites trusted configuration: later checks are re-validated and skipped; reported", async () => {
    const f = await makeFixture();
    await approve(f, {
      checks: { evil: { argv: ["node", "scripts/edit-trust.js", "TRUST"] }, after: { argv: ["node", "scripts/pass.js"] } },
      profiles: { default: ["evil", "after"] },
      required_profiles: ["default"],
    });
    // The definition must name the trust file; re-approve with the real path.
    await approve(f, {
      checks: { evil: { argv: ["node", "scripts/edit-trust.js", f.trustProjectsPath] }, after: { argv: ["node", "scripts/pass.js"] } },
      profiles: { default: ["evil", "after"] },
      required_profiles: ["default"],
    });
    const ctx = await newRun(f);
    const r = await run(ctx);
    expect(r.results.map((x) => [x.check, x.status, x.skip_reason])).toEqual([
      ["evil", "passed", null],
      ["after", "skipped", "approval_invalid"],
    ]);
    expect(r.limitations.some((l) => l.code === "trusted_configuration_changed_during_check")).toBe(true);
    // The injected check is not runnable: the approval no longer matches.
    await expectCode(run(ctx, { checks: ["injected"] }), "CHECK_NOT_APPROVED");
  }, 60_000);

  it("budgets gate new operations; unconfigured repositories and unknown names are refused", async () => {
    const f = await makeFixture();
    const none = await newRun(f);
    await expectCode(run(none), "NO_CHECKS_CONFIGURED");
    const st0 = await evaluateChecksStatus(none, null);
    expect(st0.floor.configured).toBe(false);
    expect(st0.limitations.map((l) => l.code)).toContain("verification_floor_unconfigured");

    await approve(f, basic(f));
    const ctx = await newRun(f, { maxExecutions: 3 });
    await run(ctx); // 2 executions
    await expectCode(run(ctx), "BUDGET_EXHAUSTED"); // 2 + 2 > 3
    expect((await run(ctx, { checks: ["lint"] })).status).toBe("passed"); // 3
    await expectCode(run(ctx, { checks: ["lint"] }), "BUDGET_EXHAUSTED");
    await expectCode(run(ctx, { profiles: ["nope"] }), "UNKNOWN_PROFILE");
    await expectCode(run(ctx, { checks: ["nope"] }), "CHECK_NOT_APPROVED");
  }, 60_000);

  it("tool arguments cannot lower the floor: running a subset leaves the rest required", async () => {
    const f = await makeFixture();
    await approve(f, { ...basic(f), checks: { ...basic(f).checks, extra: { argv: ["node", "scripts/pass.js", "extra"] } } });
    const ctx = await newRun(f, { additionalRequired: ["extra"] });
    const r = await run(ctx, { checks: ["lint"] });
    expect(r.results.map((x) => x.check)).toEqual(["lint"]);
    expect(r.floor.satisfied_for_current_source).toBe(false);
    expect(r.floor.missing.sort()).toEqual(["extra", "unit"]);
    const full = await run(ctx);
    expect(full.results.map((x) => x.check)).toEqual(["unit", "lint", "extra"]);
    expect(full.floor.satisfied_for_current_source).toBe(true);
    expect(full.floor.checks.find((c) => c.check === "extra")!.required_by).toEqual([{ source: "run_argument", via: "check" }]);
  }, 60_000);

  it("a committed change of the source makes every result stale for source reasons only", async () => {
    const f = await makeFixture();
    await approve(f, basic(f));
    const ctx = await newRun(f);
    const r = await run(ctx);
    await writeFile(join(f.repo, "src", "app.js"), "module.exports = 2;\n");
    commitAll(f.repo, "edit");
    const { computeSourceIdentity } = await import("../src/capture/capture.js");
    const now = await computeSourceIdentity({ repoRoot: f.repo, gitExe: f.git, rules: ctx.rules, lock: { dataHome: f.dataHome, owner: ctx.owner }, operationId: "s" });
    expect(now.source_id).not.toBe(r.source_id_at_end);
    const st = await evaluateChecksStatus(ctx, now.source_id);
    expect(st.floor.stale.sort()).toEqual(["lint", "unit"]);
    for (const c of st.floor.checks) expect(c.freshness).toMatchObject({ source: "changed", spec: "fresh", environment: "fresh" });
    // buildResult re-reports a finished operation from the store at any time.
    expect((await buildResult(ctx, r.operation_id)).execution_ids).toEqual(r.execution_ids);
  }, 60_000);
});
