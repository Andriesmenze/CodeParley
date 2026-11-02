// Cross-process behaviour on the real machine (deferred M1.1 LV-WIN-STORE / LV-WIN-PROC
// items and the MR-C acceptance test, on Windows and Linux). Separate Node processes act as
// separate server sessions; they run the compiled engine from a scratch build of src/.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { startChecks, type ChecksEngineContext } from "../src/engine/checks-operation.js";
import { readState } from "../src/store/state-store.js";
import { readWorktreeLock } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { runCli } from "../src/cli/cli.js";
import { approve, captureIo, makeFixture, newRun, type Fixture } from "./helpers/checks-fixture.js";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { linux, supported, win } from "./helpers/git-fixture.js";
import { pidAlive } from "../src/store/owner.js";

const repoRootDir = join(dirname(fileURLToPath(import.meta.url)), "..");
let outDir = "";

const CHILD_CHECKS = `
import { readFileSync } from "node:fs";
import { startChecks } from "./engine/checks-operation.js";
import { selfOwner } from "./store/owner.js";
const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const ctx = { ...cfg, owner: selfOwner(), sourceEnv: process.env, testHooks: { sweep: null } };
try {
  const s = await startChecks(ctx, cfg.request ?? {});
  process.stdout.write(JSON.stringify({ operation_id: s.operation_id, pid: process.pid }) + "\\n");
  const r = await s.completion;
  process.stdout.write(JSON.stringify({ done: r.status }) + "\\n");
} catch (e) {
  process.stdout.write(JSON.stringify({ error: e.code ?? String(e) }) + "\\n");
}
`;

const CHILD_LOCK = `
import { acquireWorktreeLock } from "./store/locks.js";
import { selfOwner } from "./store/owner.js";
const [lockPath, goAt, holdMs] = process.argv.slice(2);
while (Date.now() < Number(goAt)) await new Promise((r) => setTimeout(r, 2));
try {
  const h = await acquireWorktreeLock(lockPath, { owner: selfOwner(), operationId: "op-" + process.pid, kind: "checks" });
  process.stdout.write("ACQUIRED\\n");
  await new Promise((r) => setTimeout(r, Number(holdMs)));
  await h.release();
} catch (e) {
  process.stdout.write((e.code ?? "ERR") + "\\n");
}
`;

async function waitFor(fn: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return fn();
}

function taskkill(pid: number, tree = false): void {
  spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(pid), ...(tree ? ["/T"] : []), "/F"], { stdio: "ignore", windowsHide: true });
}

interface ChildServer {
  proc: ChildProcess;
  lines: string[];
  next(): Promise<Record<string, unknown>>;
}

function childServer(script: string, args: string[]): ChildServer {
  const proc = spawn(process.execPath, [join(outDir, script), ...args], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const lines: string[] = [];
  let buf = "";
  const waiters: (() => void)[] = [];
  proc.stdout!.on("data", (b: Buffer) => {
    buf += b.toString("utf8");
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      lines.push(buf.slice(0, i).trim());
      buf = buf.slice(i + 1);
      waiters.splice(0).forEach((w) => w());
    }
  });
  let read = 0;
  return {
    proc,
    lines,
    next: async () => {
      while (read >= lines.length) await new Promise<void>((r) => waiters.push(r));
      return JSON.parse(lines[read++]!) as Record<string, unknown>;
    },
  };
}

async function childConfig(f: Fixture, ctx: ChecksEngineContext, request: unknown = {}): Promise<string> {
  const file = join(f.scratch, `ctx-${randomBytes(4).toString("hex")}.json`);
  const { dataHome, trustProjectsPath, runPaths, meta, gitExe, rules, budgets } = ctx;
  await writeFile(file, JSON.stringify({ dataHome, trustProjectsPath, runPaths, meta, gitExe, rules, budgets, request }));
  return file;
}

let ownBuild = false;
beforeAll(async () => {
  if (!supported) return;
  // The run-wide build of src/ (next to the repository's node_modules, so the children resolve
  // zod), or this file's own where there is none; the child scripts go beside it.
  const shared = sharedCompiledSrc();
  if (shared) outDir = shared;
  else {
    outDir = join(repoRootDir, ".tmp-test-dist", randomBytes(4).toString("hex"));
    await mkdir(outDir, { recursive: true });
    buildSrc(repoRootDir, outDir);
    ownBuild = true;
  }
  await writeFile(join(outDir, "child-checks.mjs"), CHILD_CHECKS);
  await writeFile(join(outDir, "child-lock.mjs"), CHILD_LOCK);
  void pathToFileURL;
}, 120_000);

afterAll(async () => {
  if (outDir && ownBuild) await rm(outDir, { recursive: true, force: true }).catch(() => undefined);
});

describe.skipIf(!supported)("cross-session worktree contention (LV-WIN-STORE, D-31)", () => {
  it("of several processes racing for one worktree lock exactly one acquires it; the rest get WORKTREE_BUSY", async () => {
    const f = await makeFixture();
    const lockPath = join(f.dataHome, "locks", "race.lock");
    const goAt = Date.now() + 1500;
    const kids = Array.from({ length: 6 }, () => childServer("child-lock.mjs", [lockPath, String(goAt), "4000"]));
    const results = await Promise.all(
      kids.map(
        (k) =>
          new Promise<string>((resolve) => {
            k.proc.on("exit", () => resolve(k.lines[0] ?? "NO_OUTPUT"));
          }),
      ),
    );
    expect(results.filter((r) => r === "ACQUIRED")).toHaveLength(1);
    expect(results.filter((r) => r === "WORKTREE_BUSY")).toHaveLength(5);
    expect(existsSync(lockPath)).toBe(false); // the winner released it
  }, 90_000);

  it("a check running in another server session blocks this session's checks (WORKTREE_BUSY names the holder)", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { slow: { argv: ["node", "scripts/sleep.js", "5000"] }, quick: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["slow"] }, required_profiles: ["default"] });
    const runA = await newRun(f);
    const runB = await newRun(f);
    const other = childServer("child-checks.mjs", [await childConfig(f, runA)]);
    const started = await other.next();
    expect(started["operation_id"]).toBeTruthy();
    const err = await startChecks(runB, { checks: ["quick"] }).then(
      () => null,
      (e: unknown) => e as { code: string; details?: { holder?: { operation_id: string; owner: { pid: number } } } },
    );
    expect(err?.code).toBe("WORKTREE_BUSY");
    expect(err?.details?.holder?.operation_id).toBe(started["operation_id"]);
    expect(err?.details?.holder?.owner.pid).toBe(started["pid"]);
    expect((await other.next())["done"]).toBe("passed");
    const r = await (await startChecks(runB, { checks: ["quick"] })).completion;
    expect(r.status).toBe("passed");
  }, 90_000);
});

describe.skipIf(!win)("MR-C acceptance: the server dies during a check whose test spawned a long-lived grandchild", () => {
  it("the worktree stays blocked (ownership_unresolved) until the user releases it through the CLI", async () => {
    const f = await makeFixture();
    const gcPidFile = join(f.scratch, "grandchild.pid");
    await approve(f, {
      checks: { spawner: { argv: ["node", "scripts/spawn-gc.js", gcPidFile] }, quick: { argv: ["node", "scripts/pass.js"] } },
      profiles: { default: ["spawner"] },
      required_profiles: ["default"],
    });
    const runA = await newRun(f);
    const runB = await newRun(f);
    const server = childServer("child-checks.mjs", [await childConfig(f, runA)]);
    const started = await server.next();
    const opId = String(started["operation_id"]);
    expect(await waitFor(() => existsSync(gcPidFile), 30_000)).toBe(true);
    const gc = Number(readFileSync(gcPidFile, "utf8"));
    const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    expect(await waitFor(() => (readFileSyncSafe(lockPath)?.children?.length ?? 0) > 0, 10_000)).toBe(true);
    const recordedChild = (await readWorktreeLock(lockPath))!.children![0]!;

    try {
      // Abrupt server death (Task Manager "End task"): kill ONLY the server process.
      taskkill(Number(started["pid"]));
      // Asserted, not just awaited (Phase 6 Increment 1, T1 run 8): under load the server can outlive a 10 s wait, and a
      // second session then rightly sees a worktree owned by a live operation (WORKTREE_BUSY).
      expect(await waitFor(() => (server.proc.exitCode !== null || server.proc.signalCode !== null) && !pidAlive(Number(started["pid"])), 30_000)).toBe(true);

      // G7 on this machine: the direct child sat in libuv's kill-on-close job and died with
      // the server; the detached grandchild was outside the job and survives.
      expect(await waitFor(() => !pidAlive(recordedChild.pid), 10_000)).toBe(true);
      expect(pidAlive(gc)).toBe(true);

      // Another session (even with the stale threshold at zero) is refused: not broken.
      await expectCodeEventually(() => startChecks({ ...runB, lockDeps: { staleMs: 0 } }, { checks: ["quick"] }), "WORKTREE_OWNERSHIP_UNRESOLVED");
      const lock = (await readWorktreeLock(lockPath))!;
      expect(lock.ownership_unresolved).toBe(true);
      expect(lock.operation_id).toBe(opId);
      expect(lock.command_lines?.join()).toContain("spawn-gc.js");

      // "Restart": a new session opens run A. Recovery marks the operation interrupted,
      // kills nothing it cannot confirm, sweeps nothing, and the worktree stays blocked.
      await expectCodeEventually(() => startChecks({ ...runA, lockDeps: { staleMs: 0 } }, { checks: ["quick"] }), "WORKTREE_OWNERSHIP_UNRESOLVED");
      const st = await readState(runA.runPaths);
      expect(st.state).toBe("INTERRUPTED");
      expect(st.operations.find((o) => o.operation_id === opId)!.status).toBe("interrupted");
      expect(pidAlive(gc)).toBe(true);
      // With the normal stale threshold the flagged lock is refused just the same.
      await expectCode(startChecks(runB, { checks: ["quick"] }), "WORKTREE_OWNERSHIP_UNRESOLVED");

      // The CLI shows the recorded command and the surviving grandchild, and refuses to
      // release while it runs.
      const show = captureIo();
      await runCli(["lock", "show", "--repo", f.repo, "--home", f.dataHome, "--git", f.git], show);
      const shown = show.lines.join("\n");
      expect(shown).toMatch(/ownership unresolved: YES/);
      expect(shown).toContain("spawn-gc.js");
      expect(shown).toMatch(new RegExp(`STILL RUNNING \\(descendant of ${recordedChild.pid}\\): pid ${gc}`));
      const refused = captureIo();
      expect(await runCli(["lock", "release", "--repo", f.repo, "--home", f.dataHome, "--git", f.git, "--confirm", opId], refused)).toBe(1);
      expect(existsSync(lockPath)).toBe(true);
    } finally {
      taskkill(gc, true);
    }
    expect(await waitFor(() => !pidAlive(gc), 10_000)).toBe(true);
    // The grandchild's console host (conhost.exe) can outlive it briefly and is still linked
    // to the check; the CLI rightly refuses while it runs. Wait, as a user would, until the
    // inspection shows nothing linked (observed under parallel test load, M1.5).
    expect(
      await waitFor(async () => {
        const io = captureIo();
        await runCli(["lock", "show", "--repo", f.repo, "--home", f.dataHome, "--git", f.git], io);
        return !io.lines.some((l) => l.includes("STILL RUNNING"));
      }, 20_000),
    ).toBe(true);

    // After the user ended the process and inspected the commands: deliberate release. The
    // release inspects again; under parallel load a liveness query can be inconclusive for a
    // moment and the CLI then (rightly) refuses — retry, as a user would.
    expect(
      await waitFor(async () => {
        const rel = captureIo();
        return (await runCli(["lock", "release", "--repo", f.repo, "--home", f.dataHome, "--git", f.git, "--confirm", opId], rel)) === 0;
      }, 20_000),
    ).toBe(true);
    expect(existsSync(lockPath)).toBe(false);
    const r = await (await startChecks(runB, { checks: ["quick"] })).completion;
    expect(r.status).toBe("passed");
  }, 120_000);
});

describe.skipIf(!linux)("MR-C acceptance (Linux): the server dies during a check whose test spawned a long-lived grandchild", () => {
  it("the session reaper ends the check's linked tree; the worktree still stays blocked (ownership_unresolved) until the user releases it through the CLI", async () => {
    const f = await makeFixture();
    const gcPidFile = join(f.scratch, "grandchild.pid");
    await approve(f, {
      checks: { spawner: { argv: ["node", "scripts/spawn-gc.js", gcPidFile] }, quick: { argv: ["node", "scripts/pass.js"] } },
      profiles: { default: ["spawner"] },
      required_profiles: ["default"],
    });
    const runA = await newRun(f);
    const runB = await newRun(f);
    const server = childServer("child-checks.mjs", [await childConfig(f, runA)]);
    const started = await server.next();
    const opId = String(started["operation_id"]);
    expect(await waitFor(() => existsSync(gcPidFile), 30_000)).toBe(true);
    const gc = Number(readFileSync(gcPidFile, "utf8"));
    const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    expect(await waitFor(() => (readFileSyncSafe(lockPath)?.children?.length ?? 0) > 0, 10_000)).toBe(true);
    const recordedChild = (await readWorktreeLock(lockPath))!.children![0]!;

    try {
      // Abrupt server death: SIGKILL ONLY the server process, so none of its handlers run.
      process.kill(Number(started["pid"]), "SIGKILL");
      // Asserted, not just awaited (Phase 6 Increment 1, T1 run 8): under load the server can outlive a 10 s wait, and a
      // second session then rightly sees a worktree owned by a live operation (WORKTREE_BUSY).
      expect(await waitFor(() => (server.proc.exitCode !== null || server.proc.signalCode !== null) && !pidAlive(Number(started["pid"])), 30_000)).toBe(true);

      // Plan §1.13: the server's session reaper sees it die and ends the check's session and
      // every process linked to it when it looked — the grandchild started a new session, but
      // its parent was still alive, so it is ended too (Windows: it survives the job object).
      expect(await waitFor(() => !pidAlive(recordedChild.pid), 15_000)).toBe(true);
      expect(await waitFor(() => !pidAlive(gc), 15_000)).toBe(true);

      // Nothing proves that no unlinkable descendant survives: another session (even with the
      // stale threshold at zero) is still refused.
      await expectCodeEventually(() => startChecks({ ...runB, lockDeps: { staleMs: 0 } }, { checks: ["quick"] }), "WORKTREE_OWNERSHIP_UNRESOLVED");
      const lock = (await readWorktreeLock(lockPath))!;
      expect(lock.ownership_unresolved).toBe(true);
      expect(lock.operation_id).toBe(opId);
      expect(lock.command_lines?.join()).toContain("spawn-gc.js");

      // "Restart": a new session opens run A. Recovery marks the operation interrupted and the
      // worktree stays blocked.
      await expectCodeEventually(() => startChecks({ ...runA, lockDeps: { staleMs: 0 } }, { checks: ["quick"] }), "WORKTREE_OWNERSHIP_UNRESOLVED");
      const st = await readState(runA.runPaths);
      expect(st.state).toBe("INTERRUPTED");
      expect(st.operations.find((o) => o.operation_id === opId)!.status).toBe("interrupted");
      await expectCode(startChecks(runB, { checks: ["quick"] }), "WORKTREE_OWNERSHIP_UNRESOLVED");

      // The CLI shows the recorded command; nothing linked to the check is still running.
      const show = captureIo();
      await runCli(["lock", "show", "--repo", f.repo, "--home", f.dataHome, "--git", f.git], show);
      const shown = show.lines.join("\n");
      expect(shown).toMatch(/ownership unresolved: YES/);
      expect(shown).toContain("spawn-gc.js");
      expect(shown).not.toContain("STILL RUNNING");
    } finally {
      if (pidAlive(gc)) process.kill(gc, "SIGKILL");
    }

    // After inspecting the commands: deliberate release, then the worktree is usable again.
    const rel = captureIo();
    expect(await runCli(["lock", "release", "--repo", f.repo, "--home", f.dataHome, "--git", f.git, "--confirm", opId], rel)).toBe(0);
    expect(existsSync(lockPath)).toBe(false);
    const r = await (await startChecks(runB, { checks: ["quick"] })).completion;
    expect(r.status).toBe("passed");
  }, 120_000);
});

function readFileSyncSafe(p: string): { children?: unknown[] } | null {
  try {
    return JSON.parse(readFileSync(p, "utf8")) as { children?: unknown[] };
  } catch {
    return null;
  }
}

/**
 * The restarted session's recovery decides whether the dead server's operation is over. On a
 * loaded machine the dead server's PID may already belong to another process whose start time
 * a query cannot read in time: recovery then (rightly) treats the owner as possibly alive and
 * the call is RUN_BUSY. Retry, as a user would; any other outcome fails at once.
 */
async function expectCodeEventually(start: () => Promise<unknown>, code: string, ms = 30_000): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    const got = await start().then(
      () => "no error",
      (e: unknown) => (e as { code?: string }).code ?? String(e),
    );
    if (got === code) return;
    // RUN_BUSY, STORE_LOCKED and WORKTREE_BUSY are retryable by contract (Phase 6 flake P-e: right after the server's
    // death its run's mutation lock can still be held while the recovery commits; and, T1 runs 8 and 9, the first
    // judgement of the dead owner can meet its reused PID and an unanswered start-time query — "possibly alive", so the
    // worktree is busy, fail-safe); anything else, or any of them past the window, fails.
    if (!["RUN_BUSY", "STORE_LOCKED", "WORKTREE_BUSY"].includes(got) || Date.now() > end) expect(got).toBe(code);
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await expect(p).rejects.toSatisfy((e) => (e as { code?: string }).code === code);
}
