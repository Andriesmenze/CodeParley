// A lock file its holder is deleting while another handle is still open ("delete pending" on
// Windows) refuses every open with EPERM, EACCES or EBUSY until the last handle closes. Seen on
// GitHub's Windows runners (PR #10 CI): an operation waiting for a bounded read failed with a raw
// EPERM instead of waiting. The open failures are injected here. On Windows they are contention,
// which the caller retries; elsewhere the same codes stay real errors.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acquireRunLock, acquireWorktreeLock, acquireWorktreeLockWaiting, isBusyWithBoundedRead } from "../src/store/locks.js";

const inject = vi.hoisted(() => ({ path: "", creates: 0, reads: 0 }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:fs/promises")>();
  const refused = (p: unknown) => Object.assign(new Error(`EPERM: operation not permitted, open '${String(p)}'`), { code: "EPERM", syscall: "open", path: String(p) });
  return {
    ...real,
    open: (async (p: unknown, flags?: unknown, mode?: unknown) => {
      if (inject.creates > 0 && String(p) === inject.path && flags === "wx") {
        inject.creates--;
        throw refused(p);
      }
      return (real.open as (...a: unknown[]) => Promise<unknown>)(p, flags, mode);
    }) as typeof real.open,
    readFile: (async (p: unknown, ...rest: unknown[]) => {
      if (inject.reads > 0 && String(p) === inject.path) {
        inject.reads--;
        throw refused(p);
      }
      return (real.readFile as (...a: unknown[]) => Promise<unknown>)(p, ...rest);
    }) as typeof real.readFile,
  };
});

const owner = (pid: number) => ({ serverInstanceId: `srv-${pid}`, pid, startedAtMs: 1000 });
const alive = { classify: async () => "alive" as const };
const code = (e: unknown) => (e as { code?: string }).code;

let dir = "";
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "arl-releasing-"));
  inject.creates = 0;
  inject.reads = 0;
});
afterEach(async () => {
  inject.creates = 0;
  inject.reads = 0;
  await rm(dir, { recursive: true, force: true });
});

describe("a lock file its holder is still deleting (Windows delete pending; PR #10 CI)", () => {
  it.runIf(process.platform === "win32")("is contention: one attempt reports the lock changing hands, and an operation's wait gets the lock once the file is gone", async () => {
    const lockPath = join(dir, "wt.lock");
    inject.path = lockPath;
    // Both attempts of one acquisition find the file still being deleted.
    inject.creates = 2;
    const once = await acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "rev-1", kind: "capture" }, alive).catch((e: unknown) => e);
    expect(code(once)).toBe("WORKTREE_BUSY");
    expect((once as { details?: { contended?: boolean } }).details?.contended).toBe(true);
    expect(isBusyWithBoundedRead(once)).toBe(true);
    // An operation waits it out.
    inject.creates = 3;
    const h = await acquireWorktreeLockWaiting(lockPath, { owner: owner(2), operationId: "rev-2", kind: "capture" }, { ...alive, worktreeWaitMs: 5000, worktreeWaitPollMs: 20 });
    expect(h.info.operation_id).toBe("rev-2");
    expect(inject.creates).toBe(0);
    // The existing record cannot be read while it is deleted: the attempt is retried, and the
    // holder found then is reported as usual.
    inject.reads = 1;
    const busy = await acquireWorktreeLock(lockPath, { owner: owner(3), operationId: "read-3", kind: "capture" }, alive).catch((e: unknown) => e);
    expect(code(busy)).toBe("WORKTREE_BUSY");
    expect((busy as { details?: { holder?: { operation_id?: string } } }).details?.holder?.operation_id).toBe("rev-2");
    await h.release();
  });

  it.runIf(process.platform === "win32")("the run lock is busy (STORE_LOCKED, retryable) while its owner record is being deleted", async () => {
    const lockDir = join(dir, "run.lock.d");
    const first = await acquireRunLock(lockDir, owner(4), alive);
    inject.path = join(lockDir, "owner.json");
    inject.reads = 1;
    await expect(acquireRunLock(lockDir, owner(5), alive)).rejects.toMatchObject({ code: "STORE_LOCKED", retryable: true });
    await first.release();
  });

  it.runIf(process.platform !== "win32")("elsewhere the same code stays an error", async () => {
    const lockPath = join(dir, "wt.lock");
    inject.path = lockPath;
    inject.creates = 1;
    await expect(acquireWorktreeLock(lockPath, { owner: owner(1), operationId: "rev-1", kind: "capture" }, alive)).rejects.toMatchObject({ code: "EPERM" });
  });
});
