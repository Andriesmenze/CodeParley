// Locking primitives (plan §15.4, D-31, MR-C).
//
//  - Per-run mutation lock: a short-held exclusive lock (atomic mkdir of <run>\.lock\)
//    guarding the read-modify-commit of state.json.
//  - Per-worktree execution lock: a cross-process exclusive lock held during checks and
//    captures. Stale handling differs by kind (MR-C): a CAPTURE lock whose owner died may
//    be broken automatically; a CHECK lock whose owner died becomes `ownership_unresolved`
//    and is NEVER broken automatically (check descendants may still run, G7) — new work is
//    refused until confirmed termination or a deliberate user release.
//  - An operation (a review or baseline capture, check startup) that finds the worktree lock
//    held by a bounded read or capture (kind "capture") waits for it, up to 30 s, cancellable;
//    a lock held for checks still fails at once. While it waits, a waiter marker beside the
//    lock makes status and freshness reads stand aside, so polling cannot starve it (D-31).
//
// Liveness and the clock for heartbeat ages are injected so the logic is unit-testable without
// real processes. An operation's wait runs on real time: its waiter markers are read by other
// processes, and a frozen test clock would never let the wait end.

import { randomBytes } from "node:crypto";
import { mkdir, open, readdir, rename, rm, stat, writeFile, rmdir, type FileHandle } from "node:fs/promises";
import { basename, join, dirname } from "node:path";
import { DomainError, isDomainError } from "../common/errors.js";
import { atomicWriteFile, readTextIfExists } from "./atomic.js";
import { type OwnerRecord, type Liveness, classifyOwnerLiveness, OWNER_LIVENESS_DEPS } from "./owner.js";

export const STALE_HEARTBEAT_MS = 30_000;
/** How long an operation waits for a bounded read or capture holding the worktree lock (D-31). */
export const WORKTREE_WAIT_MS = 30_000;
const WORKTREE_WAIT_POLL_MS = 100;
/**
 * How long an operation gives a lock file that is not yet a lock record before refusing it: its
 * creator writes the record right after the exclusive create, so such a file is most often one
 * whose record is being written (PR #11's CI: a status read in the same process, polled flat out).
 */
const NOT_A_RECORD_GRACE_MS = 250;

export interface LockDeps {
  now?: () => number;
  classify?: (owner: OwnerRecord) => Promise<Liveness>;
  staleMs?: number;
  /** Bound on an operation's wait for a bounded read or capture (default WORKTREE_WAIT_MS). */
  worktreeWaitMs?: number;
  /** Interval between an operation's attempts while it waits (default 100 ms). */
  worktreeWaitPollMs?: number;
  /** TEST ONLY: runs between a lock file's exclusive creation and the write of its record. */
  afterCreate?: (path: string) => Promise<void>;
}

function resolveDeps(deps: LockDeps = {}): Required<LockDeps> {
  return {
    now: deps.now ?? (() => Date.now()),
    classify: deps.classify ?? ((o) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)),
    staleMs: deps.staleMs ?? STALE_HEARTBEAT_MS,
    worktreeWaitMs: deps.worktreeWaitMs ?? WORKTREE_WAIT_MS,
    worktreeWaitPollMs: deps.worktreeWaitPollMs ?? WORKTREE_WAIT_POLL_MS,
    afterCreate: deps.afterCreate ?? (() => Promise.resolve()),
  };
}

/**
 * Windows refuses to open a file that is being deleted while another handle — a reader, an
 * antivirus scan — is still open ("delete pending"), with EPERM, EACCES or EBUSY until the last
 * handle closes. For a lock file that is its holder releasing it: contention that the caller
 * retries, not an error (seen on GitHub's Windows runners, PR #10). Elsewhere these codes are
 * real errors.
 */
function isReleasingLockFile(e: unknown): boolean {
  if (process.platform !== "win32") return false;
  const code = (e as { code?: string }).code;
  return code === "EPERM" || code === "EACCES" || code === "EBUSY";
}

/**
 * Create a lock file exclusively and write its record: true when this caller now holds it. The
 * create is atomic, the write is not. A creator stalled between the two for longer than the
 * stale threshold (system sleep, a debugger, a file-system stall) can have its still-empty file
 * reclaimed as torn (reclaimTorn) and the lock taken by another caller; its own write then lands
 * in the reclaimed file. So the record is read back after the write: the lock is this caller's
 * only if the file at the path still holds exactly that record (Codex review of PR #10).
 */
async function createLockFile(path: string, body: string, d: Required<LockDeps>): Promise<boolean> {
  let fh: FileHandle;
  try {
    fh = await open(path, "wx");
  } catch (e) {
    if ((e as { code?: string }).code === "EEXIST") return false;
    throw e;
  }
  try {
    await d.afterCreate(path);
    await fh.writeFile(body);
  } finally {
    await fh.close();
  }
  return (await readTextIfExists(path)) === body;
}

// ---------------------------------------------------------------------------
// Per-run mutation lock (atomic mkdir)
// ---------------------------------------------------------------------------

export interface RunLockHandle {
  release(): Promise<void>;
}

export interface RunLockOptions {
  /**
   * The lock protects a record inside an existing directory (a run): never create missing
   * parents. A missing parent means the record was removed (a purge), so acquisition fails
   * with RUN_NOT_FOUND instead of recreating an empty run directory (M1.6).
   */
  parentMustExist?: boolean;
}

/**
 * Acquire the per-run mutation lock, breaking it only if the holder is stale AND dead.
 * The mutex is a single exclusively-created owner file. Its creation is atomic, its content is
 * not: a holder killed between creating the file and finishing its write leaves an empty or
 * partial record, which is reclaimed once it is older than the stale threshold (breakIfStale).
 */
export async function acquireRunLock(lockDir: string, owner: OwnerRecord, deps: LockDeps = {}, opts: RunLockOptions = {}): Promise<RunLockHandle> {
  const d = resolveDeps(deps);
  const ensureLockDir = async (): Promise<void> => {
    if (!opts.parentMustExist) {
      await mkdir(lockDir, { recursive: true });
      return;
    }
    try {
      await mkdir(lockDir);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === "EEXIST") return;
      if (code === "ENOENT") throw new DomainError("RUN_NOT_FOUND", "the run no longer exists (its directory was removed)");
      throw e;
    }
  };
  await ensureLockDir();
  const ownerFile = join(lockDir, "owner.json");
  const createOwnerFile = async (body: string): Promise<boolean> => {
    // A lock directory removed by a releasing holder between our mkdir and our create is
    // recreated (for run records, only inside a parent that still exists) and the create retried.
    for (let i = 0; ; i++) {
      try {
        return await createLockFile(ownerFile, body, d);
      } catch (e) {
        if ((e as { code?: string }).code === "ENOENT" && i < 20) {
          await ensureLockDir();
          continue;
        }
        throw e;
      }
    }
  };

  for (let attempt = 0; attempt < 2; attempt++) {
    const body = JSON.stringify({ owner, heartbeat_at: new Date(d.now()).toISOString() });
    let created: boolean;
    try {
      created = await createOwnerFile(body);
    } catch (e) {
      // A directory pending deletion by a releasing holder (Windows EPERM/EACCES) is contention.
      const code = (e as { code?: string }).code ?? "";
      if (code === "EPERM" || code === "EACCES" || code === "EBUSY") throw new DomainError("STORE_LOCKED", "run state is locked by another writer", { retryable: true });
      throw e;
    }
    if (created) {
      return {
        release: async () => {
          await rm(ownerFile, { force: true }).catch(() => undefined);
          await rmdir(lockDir).catch(() => undefined);
        },
      };
    }
    const broke = await breakIfStale(ownerFile, d);
    if (!broke) {
      throw new DomainError("STORE_LOCKED", `run state is locked by another writer`, { retryable: true });
    }
    // broke a stale/released lock; loop once to re-create
  }
  throw new DomainError("STORE_LOCKED", "run state lock could not be acquired");
}

async function breakIfStale(ownerFile: string, d: Required<LockDeps>): Promise<boolean> {
  let raw: string | null;
  try {
    raw = await readTextIfExists(ownerFile);
  } catch (e) {
    if (isReleasingLockFile(e)) return false; // being deleted by its releasing holder: busy for now
    throw e;
  }
  if (raw == null) {
    // The holder released between our failed create and this read; retry immediately.
    return true;
  }
  const parsed = lockRecord<{ owner: OwnerRecord; heartbeat_at: string }>(raw);
  if (!parsed) return reclaimTorn(ownerFile, raw, d);
  const age = d.now() - Date.parse(parsed.heartbeat_at);
  if (age < d.staleMs) return false;
  const live = await d.classify(parsed.owner);
  if (live === "dead") return reclaimStale(ownerFile, raw);
  return false; // alive or alive_unconfirmed: do not break
}

/** A lock record with an owner and a readable heartbeat, or null when it is empty or torn. */
function lockRecord<T extends { owner: unknown; heartbeat_at: unknown }>(raw: string): T | null {
  try {
    const v = JSON.parse(raw) as Partial<T> | null;
    return v && typeof v === "object" && v.owner && typeof v.heartbeat_at === "string" && Number.isFinite(Date.parse(v.heartbeat_at)) ? (v as T) : null;
  } catch {
    return null;
  }
}

/**
 * An empty or torn lock record: its writer died between creating the file (exclusive, atomic)
 * and finishing the write of its content (found by the Phase 2.1 crash test: a run stayed
 * locked forever). Its owner is unknown, but a live writer completes the record within
 * microseconds, so once the FILE is older than the stale threshold it is reclaimed
 * (compare-and-delete). A younger one may be a write in progress: busy (fail safe). A writer
 * that did stall that long reads its record back after the write and finds the lock is not its
 * own (createLockFile), so a reclaim never leaves two holders. Every later rewrite of a lock
 * file is an atomic rename, so a torn record is always a creation — before any check process
 * was started under it (MR-C is unaffected).
 */
async function reclaimTorn(path: string, raw: string, d: Required<LockDeps>): Promise<boolean> {
  const st = await stat(path).catch(() => null);
  if (!st) return true; // gone meanwhile
  if (d.now() - st.mtimeMs < d.staleMs) return false;
  return reclaimStale(path, raw);
}

/**
 * Remove a stale lock file only if it still holds `observed`, the record judged stale (PR #2
 * review). Two processes can judge the same stale lock dead; judging takes a process-table
 * query, and the slower one must not delete the fresh lock the faster one created meanwhile.
 * The file is moved aside atomically and its content checked: the judged record is deleted;
 * anything else is someone's fresh lock and is put back by exclusive create, which never
 * replaces a lock created in the meantime. Returns true when the stale lock is gone (the caller
 * may create its own), false when the lock is busy. Residual: a holder that creates, finishes
 * and releases within the few microseconds the file is aside would see it restored.
 */
async function reclaimStale(path: string, observed: string): Promise<boolean> {
  const now = await readTextIfExists(path);
  if (now === null) return true; // already gone
  if (now !== observed) return false; // changed since it was judged: not ours to break
  const aside = `${path}.reclaim-${randomBytes(6).toString("hex")}`;
  try {
    await rename(path, aside);
  } catch (e) {
    return (e as { code?: string }).code === "ENOENT";
  }
  const moved = await readTextIfExists(aside);
  if (moved !== observed && moved !== null) {
    await writeFile(path, moved, { flag: "wx" }).catch(() => undefined);
    await rm(aside, { force: true }).catch(() => undefined);
    return false;
  }
  await rm(aside, { force: true }).catch(() => undefined);
  return true;
}

// ---------------------------------------------------------------------------
// Per-worktree execution lock (file with JSON body)
// ---------------------------------------------------------------------------

export type WorktreeLockKind = "capture" | "checks" | "fix_apply" | string;

/** A process a check operation started, recorded in the lock before it is waited on. */
export interface LockChildRecord {
  pid: number;
  startedAtMs: number;
  /** Linux: exact start identity (store/owner.ts). */
  startIdentity?: string;
  command_line: string;
  check?: string;
}

export interface WorktreeLockInfo {
  owner: OwnerRecord;
  operation_id: string;
  kind: WorktreeLockKind;
  acquired_at: string;
  heartbeat_at: string;
  command_lines?: string[];
  /** Direct children started under this lock (checks), newest last. */
  children?: LockChildRecord[];
  ownership_unresolved?: boolean;
}

export interface AcquireWorktreeRequest {
  owner: OwnerRecord;
  operationId: string;
  kind: WorktreeLockKind;
  commandLines?: string[];
}

export interface WorktreeLockHandle {
  info: WorktreeLockInfo;
  lockPath: string;
  heartbeat(): Promise<void>;
  /** Is the lock file still this holder's (same server instance and operation, not flagged)? */
  verify(): Promise<boolean>;
  /** Record a child process in the lock file (visible to recovery and `lock release`). */
  recordChild(child: LockChildRecord): Promise<void>;
  release(): Promise<void>;
}

export async function readWorktreeLock(lockPath: string): Promise<WorktreeLockInfo | null> {
  const raw = await readTextIfExists(lockPath);
  if (raw == null) return null;
  try {
    return JSON.parse(raw) as WorktreeLockInfo;
  } catch {
    return null;
  }
}

export interface AcquireWorktreeOptions {
  /**
   * A bounded read (status, freshness): refuse with WORKTREE_BUSY while an operation is waiting
   * for this lock, so that operation gets it next (D-31). The read falls back to what it knew.
   */
  yieldToWaiters?: boolean;
}

/** An operation waiting for the worktree lock (a marker beside the lock, D-31). */
export interface WorktreeWaiter {
  owner: OwnerRecord;
  operation_id: string;
  kind: WorktreeLockKind;
  since: string;
  /** The waiter is gone by then at the latest (its wait is bounded). */
  until: string;
}

/**
 * Acquire the per-worktree exclusive lock. Throws WORKTREE_BUSY (live holder),
 * WORKTREE_OWNERSHIP_UNRESOLVED (a dead check holder, or a lock already flagged), or returns
 * a handle. A dead CAPTURE holder is broken automatically (plan §15.4, MR-C). One attempt, no
 * waiting: operations use acquireWorktreeLockWaiting. A WORKTREE_BUSY without a holder means the
 * lock changed hands during the attempt (details.contended), or its file is not a lock record.
 */
export async function acquireWorktreeLock(
  lockPath: string,
  req: AcquireWorktreeRequest,
  deps: LockDeps = {},
  opts: AcquireWorktreeOptions = {},
): Promise<WorktreeLockHandle> {
  const d = resolveDeps(deps);
  await mkdir(dirname(lockPath), { recursive: true });
  if (opts.yieldToWaiters) {
    const waiter = await liveWorktreeWaiter(lockPath);
    if (waiter) {
      throw new DomainError("WORKTREE_BUSY", `an operation is waiting for the worktree: ${waiter.operation_id} (${waiter.kind})`, {
        details: { waiter },
        retryable: true,
      });
    }
  }

  let notARecord = false;
  for (let attempt = 0; attempt < 2; attempt++) {
    notARecord = false;
    const info: WorktreeLockInfo = {
      owner: req.owner,
      operation_id: req.operationId,
      kind: req.kind,
      acquired_at: new Date(d.now()).toISOString(),
      heartbeat_at: new Date(d.now()).toISOString(),
      ...(req.commandLines ? { command_lines: req.commandLines } : {}),
    };
    let created: boolean;
    try {
      created = await createLockFile(lockPath, JSON.stringify(info, null, 2), d);
    } catch (e) {
      if (isReleasingLockFile(e)) continue; // the previous holder's file is still being deleted
      throw e;
    }
    if (created) return makeHandle(lockPath, info, d);

    const raw = await readTextIfExists(lockPath).catch((e: unknown) => {
      if (isReleasingLockFile(e)) return null;
      throw e;
    });
    if (raw === null) continue; // released between the two steps: retry
    const existing = lockRecord<WorktreeLockInfo>(raw);
    if (!existing) {
      // Empty or torn (see reclaimTorn): reclaimed once older than the stale threshold. A younger
      // one is being written, or corrupt: retry once.
      if (await reclaimTorn(lockPath, raw, d)) continue;
      notARecord = true;
      continue;
    }

    if (existing.ownership_unresolved) {
      throw new DomainError("WORKTREE_OWNERSHIP_UNRESOLVED", worktreeUnresolvedMsg(existing), {
        details: { holder: existing },
      });
    }

    const age = d.now() - Date.parse(existing.heartbeat_at);
    // A fresh lock is busy whatever its owner's state: classify liveness (a process-table
    // query) only when the heartbeat is stale.
    const live = age < d.staleMs ? "alive_unconfirmed" : await d.classify(existing.owner);

    if (live === "alive" || live === "alive_unconfirmed" || age < d.staleMs) {
      // Holder is (or may be) alive, or the lock is fresh: refuse.
      throw new DomainError("WORKTREE_BUSY", `worktree is busy with operation ${existing.operation_id} (${existing.kind})`, {
        details: { holder: existing },
        retryable: true,
      });
    }

    // Holder is confirmed dead AND stale.
    if (existing.kind === "checks" || existing.kind === "fix_apply") {
      // MR-C: never auto-release; flag ownership_unresolved and refuse — but only the record
      // judged dead, never a lock that replaced it meanwhile. Phase 4 Increment 3 (§3.6.1): an
      // application's lock likewise — the worktree may hold part of the confirmed content until
      // `code-parley fix reconcile` has verified it.
      const flagged: WorktreeLockInfo = { ...existing, ownership_unresolved: true };
      if ((await readTextIfExists(lockPath)) !== raw) continue;
      await atomicWriteFile(lockPath, JSON.stringify(flagged, null, 2));
      throw new DomainError("WORKTREE_OWNERSHIP_UNRESOLVED", worktreeUnresolvedMsg(flagged), {
        details: { holder: flagged },
      });
    }

    // Capture lock with a dead owner: safe to break and retry (plan §15.4), if it is still
    // the record judged dead (compare-and-delete).
    await reclaimStale(lockPath, raw);
  }
  // The lock changed hands during both attempts (released, replaced or reclaimed between the
  // steps): transient contention, which an operation waits out (D-31). A file that is still not
  // a lock record is not: being written or corrupt, whether it clears is unknown (a torn one is
  // reclaimed only once it is older than the stale threshold).
  if (notARecord) throw new DomainError("WORKTREE_BUSY", "worktree lock could not be acquired: the lock file is not a lock record", { details: { not_a_record: true } });
  throw new DomainError("WORKTREE_BUSY", "worktree lock could not be acquired", { details: { contended: true }, retryable: true });
}

/**
 * Acquire the worktree lock for an operation: a review or baseline capture, or check startup
 * (plan §14.4, D-31). A lock held by a bounded read or capture (kind "capture": a status or
 * freshness read, or another capture, none of which modifies the worktree) is waited for, up to
 * `worktreeWaitMs` (30 s), as is a lock that changed hands during an attempt (contention between
 * such holders); the wait ends at once when `signal` aborts. A lock held for checks, flagged
 * ownership_unresolved, or whose file is not a lock record fails at once as in
 * acquireWorktreeLock: nothing queues behind work that may modify the worktree, or behind a lock
 * state that may never clear (a file that is not a lock record first gets NOT_A_RECORD_GRACE_MS
 * to become one: its record may be being written). This is not a FIFO queue: whoever asks first
 * after a release gets the lock. While it waits the operation keeps a marker beside the lock that
 * makes reads stand aside (yieldToWaiters), so repeated polling cannot keep re-taking the lock
 * between its attempts.
 */
export async function acquireWorktreeLockWaiting(
  lockPath: string,
  req: AcquireWorktreeRequest,
  deps: LockDeps = {},
  signal?: AbortSignal,
): Promise<WorktreeLockHandle> {
  const d = resolveDeps(deps);
  const deadline = Date.now() + d.worktreeWaitMs;
  const graceEnd = Date.now() + Math.min(NOT_A_RECORD_GRACE_MS, d.worktreeWaitMs);
  let marker: string | null = null;
  let busy: WaitableBusy | null = null;
  try {
    for (;;) {
      if (signal?.aborted) throw abortedWhileWaiting();
      // A retry starts by the deadline (allowing one poll interval of timer lateness): a waiter
      // that resumes later, its event loop held up while the holder left, does not start late.
      if (busy && Date.now() > deadline + d.worktreeWaitPollMs) throw waitedOut(busy.holder, d.worktreeWaitMs);
      try {
        return await acquireWorktreeLock(lockPath, req, deps);
      } catch (e) {
        busy = waitableBusy(e);
        if (!busy) {
          // Not yet a lock record: its record is most likely being written. Look again shortly,
          // within a short grace, then refuse it as an unknown lock state (not waited for).
          if (isNotARecord(e) && Date.now() < graceEnd) {
            await pause(Math.min(d.worktreeWaitPollMs, 25), signal);
            continue;
          }
          throw e;
        }
        if (Date.now() >= deadline) throw waitedOut(busy.holder, d.worktreeWaitMs);
        marker ??= await registerWaiter(lockPath, req, deadline + d.worktreeWaitPollMs);
        await pause(Math.min(d.worktreeWaitPollMs, Math.max(0, deadline - Date.now())), signal);
      }
    }
  } finally {
    if (marker) await rm(marker, { force: true }).catch(() => undefined);
  }
}

function waitedOut(holder: WorktreeLockInfo | null, waitMs: number): DomainError {
  const waited = waitMs >= 1000 ? `${Math.round(waitMs / 1000)} s` : `${waitMs} ms`;
  if (!holder) {
    return new DomainError("WORKTREE_BUSY", `worktree lock could not be acquired: it kept changing hands; waited ${waited}`, {
      details: { contended: true },
      retryable: true,
    });
  }
  return new DomainError("WORKTREE_BUSY", `worktree is busy with operation ${holder.operation_id} (${holder.kind}); waited ${waited} for it to finish`, {
    details: { holder },
    retryable: true,
  });
}

/**
 * A WORKTREE_BUSY refusal an operation may wait out: the holder is a bounded read or capture, or
 * the lock changed hands during the attempt (contention between such holders).
 */
export function isBusyWithBoundedRead(e: unknown): boolean {
  return waitableBusy(e) !== null;
}

/** The refusal of a lock file that is not a lock record (being written, or corrupt). */
function isNotARecord(e: unknown): boolean {
  return isDomainError(e) && e.code === "WORKTREE_BUSY" && e.details?.["not_a_record"] === true;
}

/** A refusal an operation may wait out, with its holder (null: the lock changed hands meanwhile). */
interface WaitableBusy {
  holder: WorktreeLockInfo | null;
}

function waitableBusy(e: unknown): WaitableBusy | null {
  if (!isDomainError(e) || e.code !== "WORKTREE_BUSY") return null;
  const holder = e.details?.["holder"] as WorktreeLockInfo | undefined;
  if (holder) return holder.kind === "capture" && !holder.ownership_unresolved ? { holder } : null;
  return e.details?.["contended"] === true ? { holder: null } : null;
}

function abortedWhileWaiting(): Error {
  const e = new Error("cancelled while waiting for the worktree lock");
  e.name = "AbortError";
  return e;
}

function pause(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    let timer: NodeJS.Timeout | undefined;
    const done = () => {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

const WAITER_INFIX = ".waiter-";

function waiterPrefix(lockPath: string): string {
  return `${basename(lockPath)}${WAITER_INFIX}`;
}

/** Write this operation's waiter marker (removing expired markers a crashed waiter left). */
async function registerWaiter(lockPath: string, req: AcquireWorktreeRequest, untilMs: number): Promise<string> {
  const dir = dirname(lockPath);
  const now = Date.now();
  for (const { path, waiter } of await waiterMarkers(lockPath)) {
    if (!waiter || Date.parse(waiter.until) <= now) await rm(path, { force: true }).catch(() => undefined);
  }
  const path = join(dir, `${waiterPrefix(lockPath)}${randomBytes(6).toString("hex")}.json`);
  const marker: WorktreeWaiter = { owner: req.owner, operation_id: req.operationId, kind: req.kind, since: new Date(now).toISOString(), until: new Date(untilMs).toISOString() };
  await atomicWriteFile(path, JSON.stringify(marker));
  return path;
}

async function waiterMarkers(lockPath: string): Promise<{ path: string; waiter: WorktreeWaiter | null }[]> {
  const dir = dirname(lockPath);
  const prefix = waiterPrefix(lockPath);
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const out: { path: string; waiter: WorktreeWaiter | null }[] = [];
  for (const name of names) {
    if (!name.startsWith(prefix) || !name.endsWith(".json")) continue;
    const path = join(dir, name);
    const raw = await readTextIfExists(path);
    if (raw === null) continue;
    try {
      out.push({ path, waiter: JSON.parse(raw) as WorktreeWaiter });
    } catch {
      out.push({ path, waiter: null });
    }
  }
  return out;
}

/** An operation currently waiting for this worktree lock, if any (expired markers are ignored). */
export async function liveWorktreeWaiter(lockPath: string): Promise<WorktreeWaiter | null> {
  const now = Date.now();
  for (const { waiter } of await waiterMarkers(lockPath)) {
    if (waiter && Date.parse(waiter.until) > now) return waiter;
  }
  return null;
}

function makeHandle(lockPath: string, info: WorktreeLockInfo, d: Required<LockDeps>): WorktreeLockHandle {
  const ours = (current: WorktreeLockInfo | null): current is WorktreeLockInfo =>
    !!current && current.owner.serverInstanceId === info.owner.serverInstanceId && current.operation_id === info.operation_id;
  // Serialize this holder's own rewrites (heartbeat vs recordChild) so neither loses the other's update.
  let chain: Promise<void> = Promise.resolve();
  let released = false;
  const rewrite = (fn: (cur: WorktreeLockInfo) => void): Promise<void> => {
    const next = chain.then(async () => {
      if (released) return; // a rewrite after release would recreate the lock file
      const current = await readWorktreeLock(lockPath);
      if (!ours(current)) return; // no longer our lock
      fn(current);
      await atomicWriteFile(lockPath, JSON.stringify(current, null, 2));
    });
    chain = next.catch(() => undefined);
    return next;
  };
  return {
    info,
    lockPath,
    heartbeat: () =>
      rewrite((cur) => {
        cur.heartbeat_at = new Date(d.now()).toISOString();
      }),
    verify: async () => {
      const current = await readWorktreeLock(lockPath);
      return ours(current) && !current.ownership_unresolved;
    },
    recordChild: (child) =>
      rewrite((cur) => {
        cur.children = [...(cur.children ?? []), child];
        info.children = cur.children;
      }),
    release: async () => {
      released = true;
      await chain;
      const current = await readWorktreeLock(lockPath);
      if (!current) return;
      if (ours(current) && !current.ownership_unresolved) {
        await rm(lockPath, { force: true }).catch(() => undefined);
      }
    },
  };
}

/**
 * Deliberate user recovery (CLI `code-parley lock release`): clear an
 * `ownership_unresolved` worktree lock after the recorded command lines were inspected and
 * the processes confirmed gone (plan §15.4, MR-C). No automatic sweep.
 */
export async function clearWorktreeOwnership(lockPath: string): Promise<WorktreeLockInfo | null> {
  const existing = await readWorktreeLock(lockPath);
  if (!existing) return null;
  await rm(lockPath, { force: true }).catch(() => undefined);
  return existing;
}

function worktreeUnresolvedMsg(info: WorktreeLockInfo): string {
  if (info.kind === "fix_apply") {
    return (
      `worktree ownership is unresolved: a delegated fix's application (${info.operation_id}) ended without finishing; the worktree may hold part of the confirmed content.` +
      " It will not be released automatically. Run `code-parley fix reconcile <run>` to see each file's state and restore or leave it."
    );
  }
  const cmds = info.command_lines?.length ? ` Recorded command lines: ${info.command_lines.join("; ")}.` : "";
  return (
    `worktree ownership is unresolved: a check operation's owner died and descendant processes may still be running.` +
    ` It will not be released automatically.${cmds} Confirm the processes are gone and run \`code-parley lock release\`.`
  );
}
