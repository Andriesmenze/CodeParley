import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acquireWorktreeLock,
  acquireWorktreeLockWaiting,
  isBusyWithBoundedRead,
  liveWorktreeWaiter,
  readWorktreeLock,
  clearWorktreeOwnership,
  acquireRunLock,
  type RunLockHandle,
  type WorktreeLockHandle,
  type WorktreeLockInfo,
} from "../src/store/locks.js";
import type { OwnerRecord, Liveness } from "../src/store/owner.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "arl-locks-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const owner = (pid = 100): OwnerRecord => ({ serverInstanceId: `srv-${pid}`, pid, startedAtMs: 1000 });
const classifyConst = (v: Liveness) => async () => v;

describe("worktree execution lock", () => {
  it("grants, then refuses a second acquire while the holder is alive (WORKTREE_BUSY)", async () => {
    const lockPath = join(dir, "wt.lock");
    const h = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "op1", kind: "checks" }, { classify: classifyConst("alive") });
    expect(h.info.operation_id).toBe("op1");
    await expect(
      acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "op2", kind: "checks" }, { classify: classifyConst("alive") }),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_BUSY");
  });

  it("auto-breaks a stale CAPTURE lock whose owner is dead", async () => {
    const lockPath = join(dir, "wt.lock");
    const t0 = 1_000_000;
    await acquireWorktreeLock(
      lockPath,
      { owner: owner(1), operationId: "cap1", kind: "capture" },
      { now: () => t0, classify: classifyConst("alive") },
    );
    // Later, owner dead, heartbeat stale -> a new capture acquires.
    const h2 = await acquireWorktreeLock(
      lockPath,
      { owner: owner(2), operationId: "cap2", kind: "capture" },
      { now: () => t0 + 40_000, classify: classifyConst("dead") },
    );
    expect(h2.info.operation_id).toBe("cap2");
  });

  it("MR-C: a dead CHECK owner makes the lock ownership_unresolved and is NOT auto-released", async () => {
    const lockPath = join(dir, "wt.lock");
    const t0 = 2_000_000;
    await acquireWorktreeLock(
      lockPath,
      { owner: owner(1), operationId: "chk1", kind: "checks", commandLines: ["npm test"] },
      { now: () => t0, classify: classifyConst("alive") },
    );
    await expect(
      acquireWorktreeLock(
        lockPath,
        { owner: owner(2), operationId: "chk2", kind: "checks" },
        { now: () => t0 + 40_000, classify: classifyConst("dead") },
      ),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_OWNERSHIP_UNRESOLVED");

    const info = await readWorktreeLock(lockPath);
    expect(info?.ownership_unresolved).toBe(true);
    expect(info?.command_lines).toContain("npm test");

    // Still refused on the next attempt (no automatic sweep).
    await expect(
      acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "chk3", kind: "checks" }, { classify: classifyConst("dead") }),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_OWNERSHIP_UNRESOLVED");

    // Deliberate user recovery clears it; then a new acquire succeeds.
    const cleared = await clearWorktreeOwnership(lockPath);
    expect(cleared?.operation_id).toBe("chk1");
    const h = await acquireWorktreeLock(lockPath, { owner: owner(4), operationId: "chk4", kind: "checks" }, { classify: classifyConst("alive") });
    expect(h.info.operation_id).toBe("chk4");
  });

  it("does not break a lock whose owner liveness is unconfirmed", async () => {
    const lockPath = join(dir, "wt.lock");
    const t0 = 3_000_000;
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "cap1", kind: "capture" }, { now: () => t0, classify: classifyConst("alive") });
    await expect(
      acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "cap2", kind: "capture" }, { now: () => t0 + 40_000, classify: classifyConst("alive_unconfirmed") }),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_BUSY");
  });

  it("owner can release its own lock", async () => {
    const lockPath = join(dir, "wt.lock");
    const h = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "cap1", kind: "capture" }, { classify: classifyConst("alive") });
    await h.release();
    expect(await readWorktreeLock(lockPath)).toBeNull();
  });
});

describe("run mutation lock", () => {
  it("is exclusive and releasable", async () => {
    const lockDir = join(dir, "run.lock.d");
    const h = await acquireRunLock(lockDir, owner(1), { classify: classifyConst("alive") });
    await expect(acquireRunLock(lockDir, owner(2), { classify: classifyConst("alive") })).rejects.toSatisfy(
      (e) => (e as { code: string }).code === "STORE_LOCKED",
    );
    await h.release();
    const h2 = await acquireRunLock(lockDir, owner(3), { classify: classifyConst("alive") });
    await h2.release();
  });

  it("breaks a stale run lock whose owner is dead", async () => {
    const lockDir = join(dir, "run.lock.d");
    const t0 = 5_000_000;
    await acquireRunLock(lockDir, owner(1), { now: () => t0, classify: classifyConst("alive") });
    const h = await acquireRunLock(lockDir, owner(2), { now: () => t0 + 40_000, classify: classifyConst("dead") });
    expect(h).toBeDefined();
    await h.release();
  });
});

describe("stale-lock reclamation is compare-and-delete (PR #2 review)", () => {
  // While B judges the stale owner dead (in production a process-table query taking about a
  // second), A reclaims the same stale lock and takes it. B must then find the lock busy and
  // must not delete A's fresh lock.
  it("run lock: a lock taken while another writer judged the stale one survives, and that writer is refused", async () => {
    const lockDir = join(dir, "run.lock.d");
    const t0 = 5_000_000;
    await acquireRunLock(lockDir, owner(1), { now: () => t0, classify: classifyConst("alive") });
    let a: { release(): Promise<void> } | null = null;
    const judgeWhileAReclaims = async (): Promise<Liveness> => {
      a = await acquireRunLock(lockDir, owner(3), { now: () => t0 + 40_000, classify: classifyConst("dead") });
      return "dead";
    };
    await expect(acquireRunLock(lockDir, owner(2), { now: () => t0 + 40_000, classify: judgeWhileAReclaims })).rejects.toSatisfy((e) => (e as { code: string }).code === "STORE_LOCKED");
    expect(JSON.parse(await readFile(join(lockDir, "owner.json"), "utf8")).owner.pid).toBe(3);
    await a!.release();
  });

  it("worktree lock: a capture lock taken while another process judged the stale one survives, and that process is refused", async () => {
    const lockPath = join(dir, "wt.lock");
    const t0 = 1_000_000;
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "cap1", kind: "capture" }, { now: () => t0, classify: classifyConst("alive") });
    const judgeWhileAReclaims = async (): Promise<Liveness> => {
      await acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "cap3", kind: "capture" }, { now: () => t0 + 40_000, classify: classifyConst("dead") });
      return "dead";
    };
    await expect(
      acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "cap2", kind: "capture" }, { now: () => t0 + 40_000, classify: judgeWhileAReclaims }),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_BUSY");
    expect((await readWorktreeLock(lockPath))?.operation_id).toBe("cap3");
  });
});

describe("operations wait for bounded reads, not for checks (D-31)", () => {
  const alive = { classify: classifyConst("alive") };
  const code = (e: unknown) => (e as { code?: string }).code;
  const markers = async () => (await readdir(dir)).filter((n) => n.includes(".waiter-"));
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  // An operation is waiting once its marker is visible. The marker can appear well after the
  // operation starts on a loaded runner (on Windows CI, later than 300 ms), so tests wait for it
  // rather than for a fixed time. (performance.now(): one test freezes Date.)
  const waiterVisible = async (lockPath: string, operationId: string) => {
    const end = performance.now() + 10_000;
    while ((await liveWorktreeWaiter(lockPath))?.operation_id !== operationId) {
      if (performance.now() > end) throw new Error(`no waiter marker for ${operationId} after 10 s`);
      await sleep(5);
    }
  };

  it("an operation waits for a read holding the lock, then gets it; its waiter marker is removed", async () => {
    const lockPath = join(dir, "wt.lock");
    const read = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    const t0 = Date.now();
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 });
    await waiterVisible(lockPath, "rev-1");
    await sleep(300);
    await read.release();
    const h = await waiting;
    expect(h.info.operation_id).toBe("rev-1");
    expect(Date.now() - t0).toBeGreaterThanOrEqual(300);
    expect(await markers()).toEqual([]);
    await h.release();
  });

  it("a lock held for checks is refused at once: no wait, no marker", async () => {
    const lockPath = join(dir, "wt.lock");
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "chk-1", kind: "checks" }, alive);
    const t0 = Date.now();
    await expect(acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000 })).rejects.toSatisfy(
      (e) => code(e) === "WORKTREE_BUSY" && !String((e as Error).message).includes("waited"),
    );
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(await markers()).toEqual([]);
  });

  it("an ownership_unresolved lock is refused at once", async () => {
    const lockPath = join(dir, "wt.lock");
    await writeFile(lockPath, JSON.stringify({ owner: owner(1), operation_id: "chk-1", kind: "checks", acquired_at: new Date().toISOString(), heartbeat_at: new Date().toISOString(), ownership_unresolved: true }));
    const t0 = Date.now();
    await expect(acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "chk-2", kind: "checks" }, { ...alive, worktreeWaitMs: 10_000 })).rejects.toSatisfy((e) => code(e) === "WORKTREE_OWNERSHIP_UNRESOLVED");
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("the wait is bounded: WORKTREE_BUSY once it has waited worktreeWaitMs, and the marker is gone", async () => {
    const lockPath = join(dir, "wt.lock");
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "cap-1", kind: "capture" }, alive);
    const t0 = Date.now();
    await expect(acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 400, worktreeWaitPollMs: 20 })).rejects.toSatisfy(
      (e) => code(e) === "WORKTREE_BUSY" && String((e as Error).message).includes("waited 400 ms"),
    );
    expect(Date.now() - t0).toBeGreaterThanOrEqual(400);
    expect(await markers()).toEqual([]);
    expect((await readWorktreeLock(lockPath))?.operation_id).toBe("cap-1");
  });

  it("cancellation ends the wait at once and leaves the holder's lock alone", async () => {
    const lockPath = join(dir, "wt.lock");
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    const ac = new AbortController();
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "chk-1", kind: "checks" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 }, ac.signal);
    await waiterVisible(lockPath, "chk-1");
    const t0 = Date.now();
    ac.abort();
    await expect(waiting).rejects.toSatisfy((e) => (e as Error).name === "AbortError");
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(await markers()).toEqual([]);
    expect((await readWorktreeLock(lockPath))?.operation_id).toBe("status-1");
  });

  it("reads stand aside while an operation waits, even once the lock is free", async () => {
    const lockPath = join(dir, "wt.lock");
    const read = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    // Slow polling: the lock stays free between the release and the waiter's next attempt.
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "prep-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 1000 });
    await waiterVisible(lockPath, "prep-1");
    await read.release();
    expect(await readWorktreeLock(lockPath)).toBeNull();
    await expect(acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "status-2", kind: "capture" }, { ...alive }, { yieldToWaiters: true })).rejects.toSatisfy(
      (e) => code(e) === "WORKTREE_BUSY" && (e as { details?: { waiter?: { operation_id: string } } }).details?.waiter?.operation_id === "prep-1",
    );
    const h = await waiting;
    expect(h.info.operation_id).toBe("prep-1");
    await h.release();
    // No waiter any more: reads go through again.
    const again = await acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "status-3", kind: "capture" }, { ...alive }, { yieldToWaiters: true });
    await again.release();
  });

  it("repeated reads cannot starve a waiting operation", async () => {
    const lockPath = join(dir, "wt.lock");
    const first = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-0", kind: "capture" }, alive);
    let stop = false;
    let markerSeen = false;
    let readsWhileWaiting = 0;
    // A host polling as fast as it can: each read takes the lock, holds it briefly, releases it.
    // Every read that starts once the operation's marker is visible must stand aside.
    const poller = (async () => {
      for (let i = 1; !stop; i++) {
        const startedWhileWaiting = markerSeen;
        try {
          const r = await acquireWorktreeLock(lockPath, { owner: owner(3), operationId: `status-${i}`, kind: "capture" }, alive, { yieldToWaiters: true });
          if (startedWhileWaiting) readsWhileWaiting++;
          await sleep(5);
          await r.release();
        } catch {
          await sleep(1);
        }
      }
    })();
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 50 });
    await waiterVisible(lockPath, "rev-1");
    markerSeen = true;
    await sleep(300);
    const t0 = Date.now();
    await first.release();
    const h = await waiting;
    const waitedAfterRelease = Date.now() - t0;
    stop = true;
    await poller;
    expect(h.info.operation_id).toBe("rev-1");
    expect(readsWhileWaiting).toBe(0);
    expect(waitedAfterRelease).toBeLessThan(2000);
    await h.release();
  });

  it("a lock file that is not a lock record is not waited for: an unknown or corrupt lock state fails at once", async () => {
    const lockPath = join(dir, "wt.lock");
    await writeFile(lockPath, "");
    const once = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive).catch((e: unknown) => e);
    expect(code(once)).toBe("WORKTREE_BUSY");
    expect(isBusyWithBoundedRead(once)).toBe(false);
    const t0 = Date.now();
    await expect(acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 })).rejects.toSatisfy(
      (e) => code(e) === "WORKTREE_BUSY" && String((e as Error).message).includes("not a lock record") && !String((e as Error).message).includes("waited"),
    );
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(await markers()).toEqual([]);
  });

  // PR #11's CI: a status read creates its lock file and writes its record right after; an
  // operation whose two attempts both fell between the two (same process, flat-out polling) was
  // refused as "not a lock record" and its review failed. A record being written gets a short,
  // bounded moment; an unknown lock state is still refused (the test above).
  it("an operation that finds a read's lock file before its record is written waits for the read instead of failing", async () => {
    const lockPath = join(dir, "wt.lock");
    const op: { p: Promise<WorktreeLockHandle> | null } = { p: null };
    const read = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, {
      ...alive,
      afterCreate: async () => {
        // The operation tries while the read's file is still empty; the read writes 60 ms later.
        op.p = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 });
        op.p.catch(() => undefined);
        await sleep(60);
      },
    });
    await waiterVisible(lockPath, "rev-1");
    await read.release();
    const h = await op.p!;
    expect(h.info.operation_id).toBe("rev-1");
    expect(await markers()).toEqual([]);
    await h.release();
  });

  it("a holder that turns into checks while an operation waits ends the wait at once", async () => {
    const lockPath = join(dir, "wt.lock");
    const read = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 1000 });
    await waiterVisible(lockPath, "rev-1");
    await read.release();
    // Another session's checks take the lock between the waiter's attempts (checks do not yield).
    await acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "chk-9", kind: "checks" }, alive);
    const t0 = Date.now();
    await expect(waiting).rejects.toSatisfy((e) => code(e) === "WORKTREE_BUSY" && String((e as Error).message).includes("chk-9") && !String((e as Error).message).includes("waited"));
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(await markers()).toEqual([]);
  });

  it("a waiter that resumes after its deadline does not start late, even though the lock is free by then", async () => {
    // The waiter reads the time with Date.now(). Freezing that clock keeps the wait from running
    // out however long the marker takes to appear; moving it past deadline + one poll while the
    // waiter pauses stands for a waiter whose event loop was held up while the holder left.
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const lockPath = join(dir, "wt.lock");
      await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
      const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 1000, worktreeWaitPollMs: 1000 });
      const settled = waiting.then(
        (h) => ({ ok: true as const, h }),
        (e: unknown) => ({ ok: false as const, e }),
      );
      // Registered: its first attempt is done and its next one is 1 s away (in real time). Free
      // the lock and move the clock on, without yielding in between.
      await waiterVisible(lockPath, "rev-1");
      rmSync(lockPath, { force: true });
      vi.setSystemTime(Date.now() + 2500);
      const r = await settled;
      if (r.ok) await r.h.release();
      expect(r.ok).toBe(false);
      expect(!r.ok && code(r.e)).toBe("WORKTREE_BUSY");
      expect(!r.ok && String((r.e as Error).message)).toContain("waited 1 s");
      expect(await markers()).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("an expired waiter marker (a crashed waiter) is ignored by reads and removed by the next waiter", async () => {
    const lockPath = join(dir, "wt.lock");
    const stale = join(dir, "wt.lock.waiter-deadbeef.json");
    await writeFile(stale, JSON.stringify({ owner: owner(7), operation_id: "gone", kind: "capture", since: new Date(Date.now() - 60_000).toISOString(), until: new Date(Date.now() - 20_000).toISOString() }));
    expect(await liveWorktreeWaiter(lockPath)).toBeNull();
    const r = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive, { yieldToWaiters: true });
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 });
    await waiterVisible(lockPath, "rev-1");
    expect((await markers()).some((n) => n.includes("deadbeef"))).toBe(false);
    await r.release();
    await (await waiting).release();
  });
});

describe("torn lock records: a holder killed between creating the file and finishing its write (Phase 2.1 crash test)", () => {
  // The exclusive create is atomic; the content write is not. Before the fix such a record kept
  // the run (or the worktree) locked forever: it was always judged busy.
  const TORN = ["", '{"owner":{"serverInstanceId":"srv-1","pid":1', "{}", "null", '{"owner":{"pid":1},"heartbeat_at":"not a date"}'];

  it("run lock: an old torn owner record is reclaimed; a fresh one is busy (it may be a write in progress)", async () => {
    for (const [k, content] of TORN.entries()) {
      const lockDir = join(dir, `run-${k}.lock.d`);
      await mkdir(lockDir);
      await writeFile(join(lockDir, "owner.json"), content);
      const mtime = (await stat(join(lockDir, "owner.json"))).mtimeMs;
      await expect(acquireRunLock(lockDir, owner(2), { now: () => mtime + 1_000, classify: classifyConst("dead") }), JSON.stringify(content)).rejects.toSatisfy((e) => (e as { code: string }).code === "STORE_LOCKED");
      // Its owner is unknown, so liveness is not what decides: the record's own age does.
      const h = await acquireRunLock(lockDir, owner(3), { now: () => mtime + 40_000, classify: classifyConst("alive") });
      expect(JSON.parse(await readFile(join(lockDir, "owner.json"), "utf8")).owner.pid, JSON.stringify(content)).toBe(3);
      await h.release();
    }
  });

  it("worktree lock: the same — and a torn record is only ever a creation, so no recorded check process is released (MR-C)", async () => {
    for (const [k, content] of TORN.entries()) {
      const lockPath = join(dir, `wt-${k}.lock`);
      await writeFile(lockPath, content);
      const mtime = (await stat(lockPath)).mtimeMs;
      const fresh = await acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "cap2", kind: "capture" }, { now: () => mtime + 1_000, classify: classifyConst("dead") }).catch((e: unknown) => e);
      expect((fresh as { code?: string }).code, JSON.stringify(content)).toBe("WORKTREE_BUSY");
      // A fresh one is not waited for either (D-31): whether it clears soon is unknown.
      expect(isBusyWithBoundedRead(fresh), JSON.stringify(content)).toBe(false);
      const h = await acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "chk3", kind: "checks" }, { now: () => mtime + 40_000, classify: classifyConst("alive") });
      expect((await readWorktreeLock(lockPath))?.operation_id, JSON.stringify(content)).toBe("chk3");
      // Its later rewrites (children, heartbeat) are atomic: the record stays whole.
      await h.recordChild({ pid: 4242, startedAtMs: 1, command_line: "npm test" });
      expect((await readWorktreeLock(lockPath))?.children?.map((c) => c.pid)).toEqual([4242]);
      await h.release();
    }
  });

  it("a complete record of a dead CHECK holder is still never auto-released (MR-C unchanged)", async () => {
    const lockPath = join(dir, "wt.lock");
    const t0 = 7_000_000;
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "chk1", kind: "checks" }, { now: () => t0, classify: classifyConst("alive") });
    await expect(acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "chk2", kind: "checks" }, { now: () => t0 + 40_000, classify: classifyConst("dead") })).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_OWNERSHIP_UNRESOLVED");
  });

  // Codex review of PR #10: a creator stalled (sleep, a debugger) between creating its lock file
  // and writing it, past the stale threshold, has its still-empty file reclaimed by another
  // caller, and its own write lands in the reclaimed file. It must not then hold the lock too
  // (Windows and POSIX both let the reclaim move a file another caller still holds open).
  it("run lock: a creator stalled past the threshold before writing its record does not hold a lock another caller reclaimed", async () => {
    const lockDir = join(dir, "stall-run.lock.d");
    await mkdir(lockDir);
    const seen: { b: RunLockHandle | null; ran: boolean } = { b: null, ran: false };
    const a = acquireRunLock(lockDir, owner(1), {
      afterCreate: async (p) => {
        if (seen.ran) return;
        seen.ran = true;
        // While A stalls, its file is empty and, to B's clock, older than the threshold.
        const mtime = (await stat(p)).mtimeMs;
        seen.b = await acquireRunLock(lockDir, owner(2), { now: () => mtime + 40_000, classify: classifyConst("alive") }).catch(() => null);
      },
    }).then(
      (h) => ({ held: h }),
      (e: unknown) => ({ code: (e as { code?: string }).code }),
    );
    const outcome = await a;
    const holder = JSON.parse(await readFile(join(lockDir, "owner.json"), "utf8")) as { owner: { pid: number } };
    expect(seen.ran).toBe(true);
    expect(seen.b, "the other caller reclaimed the empty file and holds the lock").not.toBeNull();
    expect(outcome).toEqual({ code: "STORE_LOCKED" });
    expect(holder.owner.pid).toBe(2);
    await seen.b!.release();
  });

  it("worktree lock: a creator stalled past the threshold before writing its record does not hold a lock another caller reclaimed", async () => {
    const lockPath = join(dir, "stall-wt.lock");
    const seen: { b: WorktreeLockHandle | null; ran: boolean } = { b: null, ran: false };
    const outcome = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "cap-a", kind: "capture" }, {
      classify: classifyConst("alive"),
      afterCreate: async (p) => {
        if (seen.ran) return;
        seen.ran = true;
        const mtime = (await stat(p)).mtimeMs;
        seen.b = await acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "chk-b", kind: "checks" }, { now: () => mtime + 40_000, classify: classifyConst("alive") }).catch(() => null);
      },
    }).then(
      (h) => ({ held: h }),
      (e: unknown) => ({ code: (e as { code?: string }).code, holder: ((e as { details?: { holder?: WorktreeLockInfo } }).details?.holder ?? null)?.operation_id }),
    );
    expect(seen.ran).toBe(true);
    expect(seen.b, "the other caller reclaimed the empty file and holds the lock").not.toBeNull();
    expect(outcome).toEqual({ code: "WORKTREE_BUSY", holder: "chk-b" });
    expect((await readWorktreeLock(lockPath))?.operation_id).toBe("chk-b");
    await seen.b!.release();
  });
});
