// Run purge and retention (plan §15.5, §15.6; M1.6).
//
// Purging is preview → confirm → execute (CLI `runs purge`), or the trusted retention policy
// at server start (`retention.max_age_days`, `retention.purge_on_startup`). Either way each
// run is deleted only through this protocol:
//  1. plan: read the store; policy/retention.ts decides per run (active, interrupted, locked,
//     unreadable, linked or inconsistent runs are kept, with the reason);
//  2. under the run's own mutation lock (no commit can be in progress): re-read the state,
//     re-decide, and require the revision the preview showed;
//  3. rename the run directory into runs\.trash\ (atomic on one volume): from then on no
//     reader or writer can see a half-deleted run; a locked file makes the rename fail and
//     leaves the run untouched;
//  4. delete the tombstone without following links (store/remove-tree.ts). What cannot be
//     deleted now (a file held open) stays in runs\.trash\ and is retried by the next purge.
// No process is ever killed or swept here, and nothing outside runs\ (and old server logs) is
// touched. A purge failure is recorded and reported; it never stops the server from starting.

import { mkdir, readdir, rename, rmdir, lstat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { atomicWriteFile } from "../store/atomic.js";
import { acquireWorktreeLock } from "../store/locks.js";
import { retentionLockPath } from "../store/paths.js";
import { readMeta, readState, acquireRunLockWithRetry } from "../store/state-store.js";
import { isPlainDirectory, removeTreeNoFollow, treeSize } from "../store/remove-tree.js";
import { oldEnough } from "../policy/retention.js";
import { samePath } from "../workspace/paths.js";
import { lastActivityOf, lockedOperationIds, scanRuns, verdictOf, type ScannedRun } from "./run-admin.js";
import type { Loaded } from "./engine-env.js";

export const DAY_MS = 86_400_000;
const TOMBSTONE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{8}$/;
const SERVER_LOG_RE = /^server-(\d{4}-\d{2}-\d{2})\.log$/;

export interface PurgeSelector {
  /** Explicit run ids (full ids). */
  runIds?: readonly string[];
  /** Only runs whose last activity is at least this old (ms). */
  minAgeMs?: number | null;
  /** Only runs of this canonical repository root. */
  repo?: string;
}

export interface PurgeCandidate {
  run_id: string;
  repository_root: string | null;
  state: string;
  revision: number | null;
  last_activity: string | null;
  bytes: number;
  files: number;
  keep_code: string | null;
  keep_reason: string | null;
}

export interface PurgePlan {
  delete: PurgeCandidate[];
  keep: PurgeCandidate[];
  /** Tombstones left by an earlier, partly failed purge (always retried). */
  pending_trash: string[];
  /** Binds exactly the runs and revisions to delete; `runs purge --confirm` quotes it. */
  token: string;
}

function candidateOf(s: ScannedRun, sized: { bytes: number; files: number }, keep: { code: string; reason: string } | null): PurgeCandidate {
  const last = lastActivityOf(s);
  return {
    run_id: s.runId,
    repository_root: s.meta?.repository_root ?? null,
    state: s.state?.state ?? "UNREADABLE",
    revision: s.state?.revision ?? null,
    last_activity: last === null ? null : new Date(last).toISOString(),
    bytes: sized.bytes,
    files: sized.files,
    keep_code: keep?.code ?? null,
    keep_reason: keep?.reason ?? null,
  };
}

export function purgeToken(del: readonly Pick<PurgeCandidate, "run_id" | "revision">[]): string {
  return sha256OfCanonicalJson({ schema: "codeparley.purge-plan.v1", runs: [...del].map((d) => [d.run_id, d.revision]).sort() }).slice(0, 16);
}

async function pendingTrash(le: Loaded): Promise<string[]> {
  return (await readdir(le.layout.trashDir).catch(() => [] as string[])).filter((n) => TOMBSTONE_RE.test(n)).sort();
}

/** Decide what a purge would delete and keep (reads only). */
export async function planPurge(le: Loaded, sel: PurgeSelector, nowMs = Date.now()): Promise<PurgePlan> {
  const locked = await lockedOperationIds(le);
  let runs = await scanRuns(le);
  if (sel.runIds) {
    const ids = new Set(sel.runIds);
    runs = runs.filter((s) => ids.has(s.runId));
  }
  // The platform's name rules: case-insensitive on Windows, exact on Linux (two repositories there).
  if (sel.repo) runs = runs.filter((s) => s.meta !== null && samePath(s.meta.repository_root, sel.repo!));
  if (sel.minAgeMs !== undefined && sel.minAgeMs !== null) {
    // Unreadable runs have no known age: they are listed as kept so they are noticed.
    runs = runs.filter((s) => s.readError !== null || oldEnough(lastActivityOf(s), nowMs, sel.minAgeMs!));
  }
  const del: PurgeCandidate[] = [];
  const keep: PurgeCandidate[] = [];
  for (const s of runs) {
    const v = verdictOf(s, locked);
    const sized = s.plainDirectory ? await treeSize(s.paths.runDir) : { bytes: 0, files: 0 };
    if (v.eligible) del.push(candidateOf(s, sized, null));
    else keep.push(candidateOf(s, sized, { code: v.code, reason: v.reason }));
  }
  return { delete: del, keep, pending_trash: await pendingTrash(le), token: purgeToken(del) };
}

export interface PurgeOutcome {
  deleted: { run_id: string; bytes: number; files: number }[];
  /** Not deleted, run untouched (it changed, became busy, or a file in it is held open). */
  skipped: { run_id: string; reason: string }[];
  /** Moved out of the store but not completely deleted: retried by the next purge. */
  incomplete: { run_id: string; tombstone: string; remaining: number }[];
  trash_cleaned: number;
  trash_remaining: string[];
}

export interface ExecuteOptions {
  /** Stop starting new deletions after this long (ms). Default: no limit. */
  budgetMs?: number;
}

async function renameWithRetry(from: string, to: string, retryMs = 2000): Promise<string | null> {
  const started = Date.now();
  for (;;) {
    try {
      await rename(from, to);
      return null;
    } catch (e) {
      const code = (e as { code?: string }).code ?? "UNKNOWN";
      if ((code === "EPERM" || code === "EACCES" || code === "EBUSY") && Date.now() - started < retryMs) {
        await new Promise((r) => setTimeout(r, 100));
        continue;
      }
      return code;
    }
  }
}

/** Delete one run by the protocol above. Returns null when deleted, else why not. */
async function purgeOne(le: Loaded, c: PurgeCandidate, out: PurgeOutcome): Promise<void> {
  const s = (await scanRuns(le)).find((x) => x.runId === c.run_id);
  if (!s) {
    out.skipped.push({ run_id: c.run_id, reason: "already gone" });
    return;
  }
  let lock;
  try {
    lock = await acquireRunLockWithRetry(s.paths.lockDir, le.env.owner, { lockAcquireMs: 3000, ...(le.env.testHooks?.lockDeps ? { lockDeps: le.env.testHooks.lockDeps } : {}) });
  } catch (e) {
    out.skipped.push({ run_id: c.run_id, reason: isDomainError(e) && e.code === "RUN_NOT_FOUND" ? "already gone" : "busy: another writer holds the run lock" });
    return;
  }
  let tombstone: string | null = null;
  try {
    // Re-decide under the lock with fresh records: nothing may have started meanwhile.
    let fresh: ScannedRun;
    try {
      fresh = { ...s, meta: await readMeta(s.paths), state: await readState(s.paths), readError: null, plainDirectory: await isPlainDirectory(s.paths.runDir) };
    } catch (e) {
      out.skipped.push({ run_id: c.run_id, reason: `its records cannot be read now (${isDomainError(e) ? e.code : "INTERNAL"})` });
      return;
    }
    const v = verdictOf(fresh, await lockedOperationIds(le));
    if (!v.eligible) {
      out.skipped.push({ run_id: c.run_id, reason: v.reason });
      return;
    }
    if (c.revision !== null && fresh.state!.revision !== c.revision) {
      out.skipped.push({ run_id: c.run_id, reason: `it changed since the preview (revision ${c.revision} → ${fresh.state!.revision})` });
      return;
    }
    if (!(await isPlainDirectory(le.layout.runsDir))) {
      out.skipped.push({ run_id: c.run_id, reason: "the runs directory is a link; nothing is deleted through it" });
      return;
    }
    await mkdir(le.layout.trashDir, { recursive: true });
    if (!(await isPlainDirectory(le.layout.trashDir))) {
      out.skipped.push({ run_id: c.run_id, reason: "the trash directory is a link; nothing is moved or deleted through it" });
      return;
    }
    const target = join(le.layout.trashDir, `${c.run_id}.${randomBytes(4).toString("hex")}`);
    const code = await renameWithRetry(s.paths.runDir, target);
    if (code) {
      // Windows refuses to move a directory while a file in it is open; Linux does not, so
      // there a failure is a permission or file-system problem.
      const why = process.platform === "win32" ? `a file in the run is in use (${code}; an editor, a terminal or antivirus)` : `the run could not be moved to the trash (${code})`;
      out.skipped.push({ run_id: c.run_id, reason: `${why}; the run is untouched` });
      return;
    }
    tombstone = target;
  } finally {
    await lock.release(); // the lock file moved with the directory: a no-op after the rename
  }
  if (!tombstone) return;
  const r = await removeTreeNoFollow(tombstone);
  if (r.failures.length > 0) out.incomplete.push({ run_id: c.run_id, tombstone, remaining: r.failures.length });
  else out.deleted.push({ run_id: c.run_id, bytes: r.bytes, files: r.removedFiles });
  await rmdir(join(le.layout.runsDir, s.repoKey)).catch(() => undefined); // only if now empty
}

/** Execute a plan: retry leftover tombstones, then delete each planned run by the protocol. */
export async function executePurge(le: Loaded, plan: PurgePlan, o: ExecuteOptions = {}): Promise<PurgeOutcome> {
  const started = Date.now();
  const out: PurgeOutcome = { deleted: [], skipped: [], incomplete: [], trash_cleaned: 0, trash_remaining: [] };
  // Leftover tombstones are deleted only through plain directories: per-entry checks cannot
  // see that `runs` or `runs\.trash` itself redirects elsewhere.
  if ((await isPlainDirectory(le.layout.runsDir)) && (await isPlainDirectory(le.layout.trashDir))) {
    for (const t of await pendingTrash(le)) {
      const r = await removeTreeNoFollow(join(le.layout.trashDir, t));
      if (r.failures.length === 0) out.trash_cleaned++;
    }
  }
  for (const c of plan.delete) {
    if (o.budgetMs !== undefined && Date.now() - started > o.budgetMs) {
      out.skipped.push({ run_id: c.run_id, reason: "time budget used up; retried at the next purge" });
      continue;
    }
    await purgeOne(le, c, out);
  }
  out.trash_remaining = await pendingTrash(le);
  if (out.trash_remaining.length === 0) await rmdir(le.layout.trashDir).catch(() => undefined);
  return out;
}

// ---------------------------------------------------------------------------
// Old server logs (logs\server-YYYY-MM-DD.log)
// ---------------------------------------------------------------------------

export async function pruneServerLogs(le: Loaded, minAgeMs: number, nowMs = Date.now()): Promise<number> {
  let n = 0;
  for (const f of await readdir(le.layout.logsDir).catch(() => [] as string[])) {
    const m = SERVER_LOG_RE.exec(f);
    if (!m) continue;
    const day = Date.parse(`${m[1]}T00:00:00Z`);
    if (!Number.isFinite(day) || nowMs - day < minAgeMs + DAY_MS) continue; // whole days only; never today's
    const p = join(le.layout.logsDir, f);
    const st = await lstat(p).catch(() => null);
    if (!st || !st.isFile()) continue; // never a link
    if (await unlink(p).then(() => true, () => false)) n++;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Retention at server start (plan §15.6)
// ---------------------------------------------------------------------------

export interface RetentionSummary {
  at: string;
  max_age_days: number;
  deleted: { run_id: string; bytes: number }[];
  kept: { run_id: string; code: string | null; reason: string | null }[];
  skipped: { run_id: string; reason: string }[];
  incomplete: { run_id: string; remaining: number }[];
  logs_removed: number;
  trash_remaining: number;
  error: string | null;
}

/**
 * Apply the trusted retention policy once (called by the server after it starts serving).
 * One pass at a time across processes (store-wide retention lock). Never throws.
 */
export async function applyRetention(le: Loaded, log: (line: string) => void, o: ExecuteOptions = {}): Promise<RetentionSummary | null> {
  const cfg = le.cfg.config.retention;
  if (!cfg.purge_on_startup) {
    log("retention: disabled (retention.purge_on_startup is false)");
    return null;
  }
  let lock;
  try {
    lock = await acquireWorktreeLock(retentionLockPath(le.dataHome), { owner: le.env.owner, operationId: `retention-${uuidv7()}`, kind: "retention" }, le.env.testHooks?.lockDeps ?? {});
  } catch (e) {
    log(`retention: skipped (${isDomainError(e) && e.code === "WORKTREE_BUSY" ? "another server is applying retention" : `lock: ${e instanceof Error ? e.message : String(e)}`})`);
    return null;
  }
  const summary: RetentionSummary = { at: new Date().toISOString(), max_age_days: cfg.max_age_days, deleted: [], kept: [], skipped: [], incomplete: [], logs_removed: 0, trash_remaining: 0, error: null };
  try {
    const minAgeMs = cfg.max_age_days * DAY_MS;
    const plan = await planPurge(le, { minAgeMs });
    const out = await executePurge(le, plan, { budgetMs: o.budgetMs ?? 60_000 });
    summary.deleted = out.deleted.map((d) => ({ run_id: d.run_id, bytes: d.bytes }));
    summary.kept = plan.keep.map((k) => ({ run_id: k.run_id, code: k.keep_code, reason: k.keep_reason }));
    summary.skipped = out.skipped;
    summary.incomplete = out.incomplete.map((i) => ({ run_id: i.run_id, remaining: i.remaining }));
    summary.trash_remaining = out.trash_remaining.length;
    summary.logs_removed = await pruneServerLogs(le, minAgeMs);
  } catch (e) {
    summary.error = e instanceof Error ? e.message : String(e);
  } finally {
    await lock.release().catch(() => undefined);
  }
  const mb = (summary.deleted.reduce((a, d) => a + d.bytes, 0) / 1_048_576).toFixed(1);
  log(
    `retention (${cfg.max_age_days} days): deleted ${summary.deleted.length} run(s) (${mb} MB), kept ${summary.kept.length}` +
      (summary.kept.length ? ` [${[...new Set(summary.kept.map((k) => k.code))].join(", ")}]` : "") +
      `, skipped ${summary.skipped.length}, incomplete ${summary.incomplete.length}, ${summary.logs_removed} old log file(s) removed` +
      (summary.error ? `; ERROR: ${summary.error}` : ""),
  );
  await atomicWriteFile(le.layout.retentionLast, JSON.stringify(summary, null, 2)).catch(() => undefined);
  return summary;
}

/** Guard for callers that pass a user-typed age. */
export function daysToMs(days: number): number {
  if (!Number.isFinite(days) || days < 0) throw new DomainError("INVALID_ARGUMENT", "the age must be a number of days (0 or more)");
  return Math.round(days * DAY_MS);
}
