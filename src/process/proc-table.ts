// Best-effort view of the process table, used to find descendants that a check or Codex left
// running after its direct child exited (plan §14.3, G7; M1.3-5), and to judge termination.
// Windows reads it through WMI (win-powershell.ts); Linux reads /proc (linux-proc.ts). The
// ownership and termination rules themselves are pure and live in tree.ts (re-exported here).
// Results are evidence of survivors, never proof that none exist; callers must not use an empty
// result to release a worktree whose owner died (MR-C).

import { runProcess } from "./spawn.js";
import { killTree, type RootIdentity } from "./kill-tree.js";
import { holdersOf, readProcTable } from "./linux-proc.js";
import { DMTF_TO_EPOCH_MS, powerShellEnv, powerShellExe } from "./win-powershell.js";
import { findDescendants, type DescendantSweep, type ProcEntry, type ProcRoot } from "./tree.js";

export {
  checkOperationTermination,
  confirmTreeTermination,
  findDescendants,
  NO_KILL,
  reaperCandidates,
  unattributableSince,
  type DescendantSweep,
  type ProcEntry,
  type ProcRoot,
  type TerminationCheck,
} from "./tree.js";

/** Snapshot every process (PID, parent PID, creation time, name; Linux: group, session, uid), or null on failure. */
export async function snapshotProcessTable(): Promise<ProcEntry[] | null> {
  if (process.platform === "win32") return snapshotWindows();
  if (process.platform === "linux") return snapshotLinux();
  return null; // not a supported platform: nothing is known, so nothing is ever confirmed
}

async function snapshotLinux(): Promise<ProcEntry[] | null> {
  const t = await readProcTable();
  if (!t) return null;
  return t.map((e) => ({ pid: e.pid, ppid: e.ppid, createdMs: e.createdMs, name: e.comm, pgid: e.pgrp, sid: e.session, uid: e.uid, startTicks: e.startTicks }));
}

async function snapshotWindows(): Promise<ProcEntry[] | null> {
  // No cmdlets (see win-powershell.ts): .NET's WMI searcher and language constructs only.
  const script =
    "$ErrorActionPreference='SilentlyContinue'; " +
    "foreach ($p in ([wmisearcher]'SELECT ProcessId,ParentProcessId,CreationDate,Name FROM Win32_Process').Get()) { " +
    `$c = 0; $v = $p.CreationDate; if ($v) { $c = ${DMTF_TO_EPOCH_MS} }; ` +
    "[Console]::Out.WriteLine(([string]$p.ProcessId) + \"`t\" + ([string]$p.ParentProcessId) + \"`t\" + ([string]$c) + \"`t\" + $p.Name) }";
  let self = -1;
  const r = await runProcess(powerShellExe(), ["-NoProfile", "-NonInteractive", "-Command", script], { env: powerShellEnv(), wallMs: 30_000, onSpawn: (pid) => (self = pid) });
  if (r.status !== 0 || r.spawnError) return null;
  const out: ProcEntry[] = [];
  for (const line of r.stdout.split(/\r?\n/)) {
    const [pid, ppid, created, ...name] = line.split("\t");
    const p = Number(pid);
    const pp = Number(ppid);
    if (!Number.isInteger(p) || !Number.isInteger(pp) || p <= 0) continue;
    // The snapshot's own PowerShell (and its console host) are not part of any tree under test.
    if (p === self || pp === self) continue;
    out.push({ pid: p, ppid: pp, createdMs: Number(created) || 0, name: name.join("\t").trim() });
  }
  return out.length > 0 ? out : null;
}

export interface SweepDeps {
  snapshot?: () => Promise<ProcEntry[] | null>;
  /** Kill the tree rooted at `pid`, matched by `start` (its creation time and, on Linux, its exact start ticks). */
  kill?: (pid: number, start: RootIdentity) => Promise<boolean>;
  /** Pauses before each re-read of the table after the kill (default RESCAN_DELAYS_MS). */
  rescanDelaysMs?: readonly number[];
  /** Linux: which of these processes hold any of these fd targets (default `holdersOf`). */
  holders?: (targets: ReadonlySet<string>, candidates: readonly number[]) => Promise<number[]>;
}

/**
 * Linux: the processes created since `root` started (same user, never this server or the root)
 * that hold one of the root's output endpoints — inherited from the root's tree, so its
 * descendants even when an exited intermediate left them unlinkable by parent or session.
 */
async function stdioHolders(table: readonly ProcEntry[], root: ProcRoot, endpoints: readonly string[], deps: SweepDeps): Promise<{ pid: number; startTicks: number }[]> {
  const selfUid = table.find((e) => e.pid === process.pid)?.uid ?? null;
  const candidates = table.filter(
    (e) => e.pid !== process.pid && e.pid !== root.pid && e.startTicks !== undefined && e.createdMs !== 0 && e.createdMs + 2000 >= root.startedAtMs && (selfUid === null || e.uid === selfUid),
  );
  if (candidates.length === 0) return [];
  const held = new Set(await (deps.holders ?? holdersOf)(new Set(endpoints), candidates.map((e) => e.pid)).catch(() => []));
  return candidates.filter((e) => held.has(e.pid)).map((e) => ({ pid: e.pid, startTicks: e.startTicks! }));
}

/**
 * A kill returns before the process is gone (TerminateProcess; a signal), so a table read right
 * after the kill can still list a process in teardown. The sweep re-reads the table after these
 * pauses (about 1.5 s in all, only while something is still listed) before concluding that a
 * killed survivor is still running (M1.6-14). A process still listed after the last read is
 * reported.
 */
export const RESCAN_DELAYS_MS: readonly number[] = [250, 500, 750];

/**
 * Find descendants of an exited direct child that are still alive, kill their trees, and
 * re-scan to confirm. Bounded execution: nothing a check started may keep running once the
 * worktree lock is released (T14). Best effort; see tree.ts for what it misses.
 *
 * `stdioEndpoints` (Linux; pass them when the child's output stayed open after it exited):
 * whoever holds one is linked as a descendant too (`ProcRoot.holders`).
 */
export async function sweepDescendants(start: ProcRoot, deps: SweepDeps = {}, stdioEndpoints: readonly string[] = []): Promise<DescendantSweep> {
  const snapshot = deps.snapshot ?? snapshotProcessTable;
  const kill = deps.kill ?? ((pid: number, start: RootIdentity) => killTree(pid, 10_000, start));
  const table = await snapshot();
  if (!table) return { scanned: false, survivors: [], terminated: null };
  const root: ProcRoot = stdioEndpoints.length > 0 ? { ...start, holders: await stdioHolders(table, start, stdioEndpoints, deps) } : start;
  const survivors = findDescendants(table, root);
  if (survivors.length === 0) return { scanned: true, survivors: [], terminated: true };
  for (const s of survivors) await kill(s.pid, identityOfEntry(s)).catch(() => false);
  const after = await rescanUntilGone(snapshot, root, survivors, deps.rescanDelaysMs ?? RESCAN_DELAYS_MS);
  return { scanned: true, survivors: survivors.map(pick), terminated: after === null ? null : remainingOf(after, root, survivors) === 0 };
}

/** What identifies a table row as a tree root: its creation time and, on Linux, its exact start ticks. */
function identityOfEntry(e: ProcEntry): RootIdentity {
  return { ...(e.createdMs ? { startedAtMs: e.createdMs } : {}), ...(e.startTicks !== undefined ? { startTicks: e.startTicks } : {}) };
}

/** How many of the killed survivors, or of the root's descendants, `t` still lists. */
function remainingOf(t: readonly ProcEntry[], root: ProcRoot, survivors: readonly ProcEntry[]): number {
  return t.filter((e) => survivors.some((s) => s.pid === e.pid && Math.abs(s.createdMs - e.createdMs) <= 2000)).length + findDescendants(t, root).length;
}

/** Re-read the table after each pause while something killed is still listed; the last read (null: unreadable). */
async function rescanUntilGone(snapshot: () => Promise<ProcEntry[] | null>, root: ProcRoot, survivors: readonly ProcEntry[], pauses: readonly number[]): Promise<ProcEntry[] | null> {
  let after = await snapshot();
  for (const pause of pauses) {
    if (!after || remainingOf(after, root, survivors) === 0) break;
    await new Promise((r) => setTimeout(r, pause));
    after = await snapshot();
  }
  return after;
}

function pick(e: ProcEntry): { pid: number; name: string } {
  return { pid: e.pid, name: e.name };
}
