// The worktree lock changing hands while an attempt is in flight (D-31, Codex review of PR #8).
// An attempt finds the lock file (EEXIST), then reads it: when the holder released it between
// those two steps, and another holder took it again, the attempt learns nothing about who holds
// it. Two such attempts end in a WORKTREE_BUSY without a holder. Under flat-out status polling
// that is ordinary contention between bounded reads, so an operation waits it out within its
// bound; a known checks holder is still refused at once. The read is intercepted here so the
// lock changes hands at exactly that point, as many times as a test asks.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const churn = vi.hoisted(() => ({ path: "", left: 0 }));

vi.mock("../src/store/atomic.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/store/atomic.js")>();
  return {
    ...real,
    readTextIfExists: async (path: string): Promise<string | null> => {
      if (path === churn.path && churn.left > 0) {
        churn.left--;
        return null; // released before this read; the file is back (another holder) for the next attempt
      }
      return real.readTextIfExists(path);
    },
  };
});

const { acquireWorktreeLock, acquireWorktreeLockWaiting, isBusyWithBoundedRead, liveWorktreeWaiter } = await import("../src/store/locks.js");

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cp-lock-churn-"));
  churn.path = "";
  churn.left = 0;
});
afterEach(async () => {
  churn.left = 0;
  await rm(dir, { recursive: true, force: true });
});

const owner = (pid: number) => ({ serverInstanceId: `srv-${pid}`, pid, startedAtMs: 1000 });
const alive = { classify: async () => "alive" as const };
const code = (e: unknown) => (e as { code?: string }).code;
const message = (e: unknown) => String((e as Error).message);
const markers = async () => (await readdir(dir)).filter((n) => n.includes(".waiter-"));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const waiterVisible = async (lockPath: string, operationId: string) => {
  const end = performance.now() + 10_000;
  while ((await liveWorktreeWaiter(lockPath))?.operation_id !== operationId) {
    if (performance.now() > end) throw new Error(`no waiter marker for ${operationId} after 10 s`);
    await sleep(5);
  }
};

describe("an operation waits out a lock that changes hands during its attempt (D-31)", () => {
  it("one attempt that saw the lock change hands twice ends without a holder, as contention an operation may wait out", async () => {
    const lockPath = join(dir, "wt.lock");
    const holder = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    churn.path = lockPath;
    churn.left = 2;
    const e = await acquireWorktreeLock(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, alive).catch((err: unknown) => err);
    expect(code(e)).toBe("WORKTREE_BUSY");
    expect((e as { details?: { contended?: boolean; holder?: unknown } }).details).toEqual({ contended: true });
    expect(isBusyWithBoundedRead(e)).toBe(true);
    await holder.release();
  });

  it("the operation keeps waiting through the churn, then for the holder it finds, and gets the lock", async () => {
    const lockPath = join(dir, "wt.lock");
    const holder = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    churn.path = lockPath;
    churn.left = 6; // three attempts learn nothing about the holder
    const waiting = acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 });
    const settled = waiting.then(
      (h) => ({ ok: true as const, h }),
      (err: unknown) => ({ ok: false as const, e: err }),
    );
    await waiterVisible(lockPath, "rev-1");
    while (churn.left > 0) await sleep(5);
    await sleep(100); // later attempts find status-1 and wait for it
    expect(await Promise.race([settled, sleep(0).then(() => "waiting")])).toBe("waiting");
    await holder.release();
    const r = await settled;
    expect(r.ok ? r.h.info.operation_id : message(r.e)).toBe("rev-1");
    if (r.ok) await r.h.release();
    expect(await markers()).toEqual([]);
  });

  it("the wait through churn is bounded: WORKTREE_BUSY once it has waited worktreeWaitMs", async () => {
    const lockPath = join(dir, "wt.lock");
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "status-1", kind: "capture" }, alive);
    churn.path = lockPath;
    churn.left = Number.POSITIVE_INFINITY;
    const t0 = Date.now();
    await expect(acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 400, worktreeWaitPollMs: 20 })).rejects.toSatisfy(
      (err) => code(err) === "WORKTREE_BUSY" && message(err).includes("kept changing hands; waited 400 ms"),
    );
    expect(Date.now() - t0).toBeGreaterThanOrEqual(400);
    expect(await markers()).toEqual([]);
  });

  it("a checks holder found after the churn is refused at once, without waiting for it", async () => {
    const lockPath = join(dir, "wt.lock");
    await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "chk-1", kind: "checks" }, alive);
    churn.path = lockPath;
    churn.left = 2; // the first attempt learns nothing; the next one finds the checks holder
    const t0 = Date.now();
    await expect(acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-1", kind: "capture" }, { ...alive, worktreeWaitMs: 10_000, worktreeWaitPollMs: 20 })).rejects.toSatisfy(
      (err) => code(err) === "WORKTREE_BUSY" && message(err).includes("chk-1 (checks)") && !message(err).includes("waited"),
    );
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(churn.left).toBe(0);
    expect(await markers()).toEqual([]);
  });
});
