// Operations wait for bounded reads holding the worktree lock (plan §14.4, D-31), through the
// real MCP server over stdio. A review capture, run creation's baseline capture and check
// startup that find the lock held by a status or freshness read (or another capture) wait for
// it, up to 30 s and cancellable, while the call still returns within its own bound; a lock held
// by checks is refused at once; reads stand aside while an operation waits, so polling cannot
// starve it, and get_review_status itself never waits. The test process holds the lock the way
// another session's read or checks would. Runs on Windows and Linux.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readdir } from "node:fs/promises";
import { dirname } from "node:path";
import { compileServer, removeCompiledServer, errorCode, sc, type Conn } from "./helpers/mcp-harness.js";
import { mcpFixture, newRunOver, open, slowReviewScenario, type McpFixture } from "./helpers/mcp-fixture.js";
import { supported } from "./helpers/git-fixture.js";
import { acquireWorktreeLock, liveWorktreeWaiter, readWorktreeLock, type WorktreeLockHandle } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { canonicalizePath } from "../src/workspace/paths.js";
import { selfOwner } from "../src/store/owner.js";

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

type Result = Record<string, unknown>;

async function lockPathOf(f: McpFixture): Promise<string> {
  return worktreeLockPath(f.dataHome, canonicalPathKey(await canonicalizePath(f.repo)));
}

/** Hold the worktree lock as another session would: a bounded read ("capture") or running checks. */
async function holdLock(f: McpFixture, kind: "capture" | "checks", operationId: string): Promise<WorktreeLockHandle> {
  return acquireWorktreeLock(await lockPathOf(f), { owner: selfOwner(), operationId, kind });
}

async function waiterMarkers(f: McpFixture): Promise<string[]> {
  return (await readdir(dirname(await lockPathOf(f))).catch(() => [] as string[])).filter((n) => n.includes(".waiter-"));
}

/** The operation the server reports waiting for the lock (its marker), once there is one. */
async function waiterOperation(f: McpFixture, ms = 90_000): Promise<string> {
  const lockPath = await lockPathOf(f);
  const end = Date.now() + ms;
  for (;;) {
    const w = await liveWorktreeWaiter(lockPath);
    if (w) return w.operation_id;
    if (Date.now() > end) throw new Error("no operation started waiting for the worktree lock");
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function status(c: Conn, runId: string, extra: Result = {}): Promise<Result> {
  return sc(await c.call("get_review_status", { run_id: runId, ...extra }));
}

/** Poll as fast as a host can, without waiting, until the run has no active operation; then its result. */
async function pollFlatOut(c: Conn, runId: string): Promise<Result> {
  let s = await status(c, runId);
  const end = Date.now() + 150_000;
  while (s["active_operation"] !== null && Date.now() < end) s = await status(c, runId);
  return (await status(c, runId, { wait_seconds: 1 }))["completed_operation"] as Result;
}

/** Wait (bounded polls) for the run's active operation to finish; its result. */
async function finished(c: Conn, runId: string, started: Result): Promise<Result> {
  if (started["status"] !== "running") return started;
  for (let i = 0; i < 8; i++) {
    const s = await status(c, runId, { wait_seconds: 30 });
    if (s["active_operation"] === null && s["completed_operation"]) return s["completed_operation"] as Result;
  }
  throw new Error(`run ${runId}: the operation did not finish`);
}

const sourceNote = (s: Result): string => (s["limitations"] as { code: string; detail: string }[]).find((l) => l.code === "current_source_note")?.detail ?? "";

describe.skipIf(!supported)("operations wait for bounded reads holding the worktree lock (D-31)", () => {
  it("get_review_status polled flat out while a review starts no longer fails the review (the CI race)", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(1000) });
    const c = await open(f, "v2-modern");
    try {
      for (let i = 0; i < 3; i++) {
        const runId = await newRunOver(c, f);
        const h = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 0 }));
        expect(h["status"]).toBe("running");
        const done = await pollFlatOut(c, runId);
        expect(done["status"], String(done["summary"])).toBe("completed");
        expect(done["accepted"], String(done["summary"])).toBe(true);
      }
    } finally {
      await c.close();
    }
  }, 400_000);

  it("a review waits for another session's read; status answers at once and stands aside; flat-out polling cannot starve the review", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(1000) });
    const c = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      const read = await holdLock(f, "capture", "status-other-session");
      let released = false;
      try {
        const h = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 1 }));
        expect(h["status"]).toBe("running");
        expect(await waiterOperation(f)).toBe(h["operation_id"]);
        for (let n = 0; n < 5; n++) {
          const t0 = Date.now();
          const s = await status(c, runId);
          expect(Date.now() - t0).toBeLessThan(10_000);
          expect(s["current_source_recomputed"]).toBe(false);
          expect(sourceNote(s)).toContain("an operation is waiting for the worktree lock");
        }
        await read.release();
        released = true;
        const done = await pollFlatOut(c, runId);
        expect(done["status"], String(done["summary"])).toBe("completed");
        expect(done["accepted"], String(done["summary"])).toBe(true);
        expect(await waiterMarkers(f)).toEqual([]);
      } finally {
        if (!released) await read.release();
      }
    } finally {
      await c.close();
    }
  }, 300_000);

  it("run creation's baseline capture waits for a read, and create_review_run still returns within its bound", async () => {
    const f = await mcpFixture();
    const c = await open(f, "v2-legacy");
    const read = await holdLock(f, "capture", "status-other-session");
    let released = false;
    try {
      const t0 = Date.now();
      const r = sc(await c.call("create_review_run", { task_envelope: { goal: "Review the add() change" }, repository_root: f.repo, wait_seconds: 2 }));
      expect(Date.now() - t0).toBeLessThan(2000 + 20_000);
      const runId = r["run_id"] as string;
      const prepare = r["prepare"] as Result;
      expect(prepare["status"]).toBe("running");
      expect(await waiterOperation(f)).toBe(prepare["operation_id"]);
      expect((await status(c, runId))["current_source_recomputed"]).toBe(false);
      await read.release();
      released = true;
      const done = await finished(c, runId, prepare);
      expect(done["operation_id"]).toBe(prepare["operation_id"]);
      expect(done["status"], String(done["summary"])).toBe("completed");
    } finally {
      if (!released) await read.release();
      await c.close();
    }
  }, 300_000);

  it("check startup waits for a status or freshness read, run_checks still returns within its bound, and checks started during flat-out polling run", async () => {
    const f = await mcpFixture();
    const c = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      const read = await holdLock(f, "capture", "status-other-session");
      let released = false;
      try {
        const t0 = Date.now();
        const h = sc(await c.call("run_checks", { run_id: runId, checks: ["unit"], wait_seconds: 2 }));
        expect(Date.now() - t0).toBeLessThan(2000 + 20_000);
        expect(h["status"]).toBe("running");
        expect(await waiterOperation(f)).toBe(h["operation_id"]);
        await read.release();
        released = true;
        const done = await finished(c, runId, h);
        expect(done["status"], String(done["summary"])).toBe("passed");
      } finally {
        if (!released) await read.release();
      }
      // Real reads, not a stand-in: status polled flat out while checks start, three times.
      for (let i = 0; i < 3; i++) {
        let stop = false;
        const poller = (async () => {
          while (!stop) await status(c, runId);
        })();
        try {
          const r = await c.call("run_checks", { run_id: runId, checks: ["unit"], wait_seconds: 30 });
          expect(errorCode(r)).toBeNull();
          const done = await finished(c, runId, sc(r));
          expect(done["status"], String(done["summary"])).toBe("passed");
        } finally {
          stop = true;
          await poller;
        }
      }
    } finally {
      await c.close();
    }
  }, 400_000);

  it("a lock held by running checks is still refused at once: run_checks, a review and run creation get WORKTREE_BUSY without waiting", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(0) });
    const c = await open(f, "v2-legacy");
    try {
      const runId = await newRunOver(c, f);
      const checks = await holdLock(f, "checks", "chk-other-session");
      try {
        const t0 = Date.now();
        expect(errorCode(await c.call("run_checks", { run_id: runId, checks: ["unit"], wait_seconds: 30 }))).toBe("WORKTREE_BUSY");
        expect(Date.now() - t0).toBeLessThan(15_000);

        const review = await finished(c, runId, sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 40 })));
        expect(review["status"]).toBe("not_started");
        expect(String(review["summary"])).toContain("WORKTREE_BUSY");
        expect(String(review["summary"])).toContain("chk-other-session (checks)");
        expect(String(review["summary"])).not.toContain("waited");

        const r2 = sc(await c.call("create_review_run", { task_envelope: { goal: "second run" }, repository_root: f.repo, wait_seconds: 30 }));
        const prepare = r2["prepare"] as { status: string; failure: { code: string; detail: string } | null };
        expect(prepare.status).toBe("failed");
        expect(prepare.failure?.code).toBe("WORKTREE_BUSY");
        expect(prepare.failure?.detail).not.toContain("waited");
        expect(await waiterMarkers(f)).toEqual([]);
      } finally {
        await checks.release();
      }
    } finally {
      await c.close();
    }
  }, 300_000);

  it("the wait is bounded: past it checks and a review end with WORKTREE_BUSY, saying how long they waited", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(0), worktreeWaitMs: 1500 });
    const c = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      const read = await holdLock(f, "capture", "status-stuck");
      try {
        const checks = await finished(c, runId, sc(await c.call("run_checks", { run_id: runId, checks: ["unit"], wait_seconds: 30 })));
        expect(checks["operation_status"]).toBe("error");
        expect(String(checks["summary"])).toContain("operation error: worktree is busy with operation status-stuck (capture); waited 2 s");

        const review = await finished(c, runId, sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 40 })));
        expect(review["status"]).toBe("not_started");
        expect(String(review["summary"])).toContain("WORKTREE_BUSY");
        expect(String(review["summary"])).toContain("waited 2 s");
        expect(await waiterMarkers(f)).toEqual([]);
        expect((await readWorktreeLock(await lockPathOf(f)))?.operation_id).toBe("status-stuck");
      } finally {
        await read.release();
      }
    } finally {
      await c.close();
    }
  }, 300_000);

  it("cancellation ends the wait at once: checks and a review waiting for a read are cancelled, and the reader's lock is untouched", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(0) });
    const c = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      const read = await holdLock(f, "capture", "status-other-session");
      try {
        const h = sc(await c.call("run_checks", { run_id: runId, checks: ["unit"], wait_seconds: 1 }));
        expect(h["status"]).toBe("running");
        expect(await waiterOperation(f)).toBe(h["operation_id"]);
        sc(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: h["operation_id"] as string }));
        const checks = await finished(c, runId, h);
        expect(checks["operation_status"]).toBe("cancelled");
        expect(String(checks["summary"])).toContain("no check ran");

        const rv = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 1 }));
        expect(rv["status"]).toBe("running");
        expect(await waiterOperation(f)).toBe(rv["operation_id"]);
        sc(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: rv["operation_id"] as string }));
        const review = await finished(c, runId, rv);
        expect(review["status"]).toBe("cancelled");

        expect(await waiterMarkers(f)).toEqual([]);
        expect((await readWorktreeLock(await lockPathOf(f)))?.operation_id).toBe("status-other-session");
      } finally {
        await read.release();
      }
    } finally {
      await c.close();
    }
  }, 300_000);
});
