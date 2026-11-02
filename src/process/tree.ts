// Process-tree ownership and termination evidence, as PURE functions over a process-table
// snapshot (plan §14.3, G7; M1.3-5, M1.4-17 F3; Linux milestone, plan §1.13). The snapshot
// itself comes from proc-table.ts (PowerShell/WMI on Windows, /proc on Linux).
//
// How a descendant is linked to the process CodeParley started (the "root"):
//  - Windows does not re-parent orphans: a process keeps its creator's PID as its parent PID
//    after the creator exits. A descendant is found by walking parent-PID links from the root,
//    and a PID-reuse false match is excluded by requiring every link to have been created no
//    earlier than its parent. A process whose chain passes through an exited intermediate
//    cannot be linked (its parent PID names nothing, or a newer process).
//  - Linux re-parents orphans to the nearest "subreaper" ancestor or to PID 1, so parent links
//    alone lose them. CodeParley therefore starts every child as the leader of a new session
//    and process group (spawn.ts), and on Linux the session/group id is the ownership tag of
//    the whole tree: every process whose session or group id is the root's PID (created after
//    the root) is the root's, wherever it was re-parented. A descendant that called setsid()
//    leaves the session; once its parent exits it is re-parented to a reaper and can no longer
//    be linked — it looks exactly like an unrelated process the reaper started.
// In both cases results are evidence of survivors, never proof that none exist: termination is
// "established" only when nothing created during the run is left that MIGHT be ours.

export interface ProcEntry {
  pid: number;
  ppid: number;
  /** Creation time, epoch ms (0 if unknown). */
  createdMs: number;
  name: string;
  /** Linux: process group id. */
  pgid?: number;
  /** Linux: session id. */
  sid?: number;
  /** Linux: owner uid (null when unreadable). */
  uid?: number | null;
  /** Linux: start time in clock ticks since boot (exact identity with the boot id). */
  startTicks?: number;
}

export interface ProcRoot {
  pid: number;
  /** Approximate start of the root (epoch ms); descendants must not predate it. */
  startedAtMs: number;
  /** Linux: the root's exact start ticks, when known — a process holding its PID with other ticks is a newer process. */
  startTicks?: number;
  /**
   * Linux: processes found holding the root's output pipes after it exited (exact by start
   * ticks). They inherited the pipes from the root's tree, so they are its descendants wherever
   * they were re-parented, and so is their own session.
   */
  holders?: readonly { pid: number; startTicks: number }[];
}

/** Does this table carry Linux session data (so the session rules apply)? */
function hasSessions(table: readonly ProcEntry[]): boolean {
  return table.some((e) => e.sid !== undefined);
}

/**
 * Live descendants of `root` (the root itself excluded): parent-PID links on every platform,
 * plus — on Linux — every member of the root's session or process group.
 *
 * PID reuse is excluded in both directions: a process created before its supposed parent
 * holds a reused parent PID; and when the root's PID now belongs to a NEWER live process (the
 * root exited and its PID was reassigned), children and session members created after that
 * process started are that process's, never the root's — the root was already gone (M1.6:
 * such children were otherwise reported as survivors, and a post-exit sweep would have killed
 * them).
 */
export function findDescendants(table: readonly ProcEntry[], root: ProcRoot, toleranceMs = 2000): ProcEntry[] {
  const w = new DescendantWalk(table, root, toleranceMs);
  if (hasSessions(table)) {
    w.addMembers(root.pid, root.startedAtMs, w.impostor ? w.impostor.createdMs : null);
    for (const h of root.holders ?? []) w.addHolder(h);
  }
  w.walkChildren();
  return w.found;
}

/** The state of one `findDescendants` walk. */
class DescendantWalk {
  readonly found: ProcEntry[] = [];
  /** A newer live process holding the root's PID (the root exited and its PID was reassigned), if any. */
  readonly impostor: ProcEntry | undefined;
  private readonly byParent = new Map<number, ProcEntry[]>();
  private readonly seen: Set<number>;
  private readonly queue: { pid: number; startedAtMs: number }[];

  constructor(
    private readonly table: readonly ProcEntry[],
    private readonly root: ProcRoot,
    private readonly toleranceMs: number,
  ) {
    for (const e of table) {
      const list = this.byParent.get(e.ppid) ?? [];
      list.push(e);
      this.byParent.set(e.ppid, list);
    }
    this.impostor = table.find((e) => e.pid === root.pid && this.isNewerThanRoot(e));
    this.seen = new Set<number>([root.pid]);
    this.queue = [{ pid: root.pid, startedAtMs: root.startedAtMs }];
  }

  /** Is `e` (holding the root's PID) a different, newer process? Exact by start ticks when both are known. */
  private isNewerThanRoot(e: ProcEntry): boolean {
    if (this.root.startTicks !== undefined && e.startTicks !== undefined) return e.startTicks !== this.root.startTicks;
    return e.createdMs !== 0 && this.root.startedAtMs !== 0 && e.createdMs > this.root.startedAtMs + this.toleranceMs;
  }

  private take(e: ProcEntry): void {
    this.seen.add(e.pid);
    this.found.push(e);
    this.queue.push({ pid: e.pid, startedAtMs: e.createdMs });
  }

  /** Linux: the members of session or group `leader` created since `sinceMs` (and before `notFrom`, when set). */
  addMembers(leader: number, sinceMs: number, notFrom: number | null): void {
    for (const e of this.table) {
      if (this.seen.has(e.pid) || (e.sid !== leader && e.pgid !== leader)) continue;
      if (e.createdMs !== 0 && sinceMs !== 0 && e.createdMs + this.toleranceMs < sinceMs) continue;
      if (notFrom !== null && e.createdMs !== 0 && e.createdMs >= notFrom) continue;
      this.take(e);
    }
  }

  /** Linux: a process found holding the root's output pipes (exact by start ticks), and its own session. */
  addHolder(h: { pid: number; startTicks: number }): void {
    const e = this.table.find((x) => x.pid === h.pid && x.startTicks === h.startTicks);
    if (!e || this.seen.has(e.pid)) return;
    this.take(e);
    if (e.sid === e.pid || e.pgid === e.pid) this.addMembers(e.pid, e.createdMs, null);
  }

  /** Follow parent-PID links from everything found so far. */
  walkChildren(): void {
    while (this.queue.length > 0) {
      const parent = this.queue.shift()!;
      for (const c of this.byParent.get(parent.pid) ?? []) if (!this.seen.has(c.pid) && this.isChildOf(c, parent)) this.take(c);
    }
  }

  private isChildOf(c: ProcEntry, parent: { pid: number; startedAtMs: number }): boolean {
    // A process created before its supposed parent holds a reused parent PID: not ours.
    if (c.createdMs !== 0 && parent.startedAtMs !== 0 && c.createdMs + this.toleranceMs < parent.startedAtMs) return false;
    // A child of the process that now holds the root's PID, created after it started (both
    // times come from the same process table, so no tolerance applies: the root was gone
    // before that process existed, and so cannot have created anything after it).
    return !(parent.pid === this.root.pid && this.impostor && c.createdMs !== 0 && c.createdMs >= this.impostor.createdMs);
  }
}

/**
 * Linux: the processes an orphan of a tree started by `selfPid` can be re-parented to — PID 1
 * and every ancestor of `selfPid` (any of them may be a subreaper; Linux does not expose which).
 */
export function reaperCandidates(table: readonly ProcEntry[], selfPid: number): Set<number> {
  const byPid = new Map(table.map((e) => [e.pid, e]));
  const out = new Set<number>([1]);
  let cur = byPid.get(selfPid);
  for (let i = 0; cur && i < 256; i++) {
    if (cur.ppid <= 0 || out.has(cur.ppid)) break;
    out.add(cur.ppid);
    cur = byPid.get(cur.ppid);
  }
  return out;
}

/**
 * Live processes created at or after `sinceMs` whose ancestry cannot be traced to anything but
 * a process that may have adopted them. A descendant of a tree whose intermediate exited looks
 * exactly like this, so while any such process exists, termination of a tree started at
 * `sinceMs` cannot be established (they may be unrelated; they are reported as
 * unattributable, never killed).
 *  - Windows: the parent PID names no live process, or a process created after the child (a
 *    reused PID).
 *  - Linux: the parent is a reaper candidate (PID 1 or an ancestor of this server,
 *    `reaperCandidates`) and the process runs as this user (a re-parented orphan of ours
 *    cannot have changed user without a set-uid program).
 */
export function unattributableSince(table: readonly ProcEntry[], sinceMs: number, toleranceMs = 2000, selfPid: number = process.pid): ProcEntry[] {
  const byPid = new Map(table.map((e) => [e.pid, e]));
  const linux = hasSessions(table);
  const reapers = linux ? reaperCandidates(table, selfPid) : null;
  const selfUid = linux ? (byPid.get(selfPid)?.uid ?? null) : null;
  return table.filter((e) => {
    if (e.createdMs === 0 || e.createdMs + toleranceMs < sinceMs) return false;
    if (e.pid === 0 || e.pid === 4 || e.ppid === 0) return false;
    if (e.pid === selfPid) return false;
    const parent = byPid.get(e.ppid);
    if (!parent || (parent.createdMs !== 0 && parent.createdMs > e.createdMs + toleranceMs)) return true;
    if (reapers?.has(e.ppid)) return selfUid === null || e.uid === undefined || e.uid === null || e.uid === selfUid;
    return false;
  });
}

export interface DescendantSweep {
  /** False when the process table could not be read (nothing is known). */
  scanned: boolean;
  /** Descendants found alive after the direct child had exited. */
  survivors: { pid: number; name: string }[];
  /** After killing: true if a re-scan found none of them (and no new ones) alive. */
  terminated: boolean | null;
}

export interface TerminationCheck {
  /** True only when termination of the whole tree is established (see confirmTreeTermination). */
  established: boolean;
  /** Linked survivors (killed and re-checked by the sweep). */
  survivors: { pid: number; name: string }[];
  /** Processes created during the run whose ancestry cannot be traced (possibly ours). */
  unattributable: { pid: number; name: string }[];
  reason: string;
}

/** `pre` value for a tree that was not killed (its root exited by itself). */
export const NO_KILL = "no_kill" as const;

/**
 * THE termination evidence rule (F3). Every path that reports a tree "terminated" uses it.
 * Established only if: the process table was read after the root exited (and, when the
 * tree was killed, also before the kill); every descendant seen before the kill is gone;
 * the post-exit sweep was readable and found no linked survivor, or killed every survivor
 * and confirmed it gone; and NO process created since the root started has an untraceable
 * parent — because a descendant behind an exited intermediate cannot be linked and would
 * otherwise be mistaken for "nothing left". Missing evidence is never read as success.
 */
export function confirmTreeTermination(root: ProcRoot, pre: readonly ProcEntry[] | null | typeof NO_KILL, post: readonly ProcEntry[] | null, sweep: DescendantSweep | null): TerminationCheck {
  const survivors = sweep?.survivors ?? [];
  if (!pre || !post || !sweep?.scanned) return { established: false, survivors, unattributable: [], reason: "the process table could not be read before and after the root ended" };
  const before = pre === NO_KILL ? [] : findDescendants(pre, root);
  const stillAlive = post.filter((e) => before.some((b) => b.pid === e.pid && Math.abs(b.createdMs - e.createdMs) <= 2000));
  const unattributable = unattributableSince(post, root.startedAtMs).map(pick);
  if (stillAlive.length > 0) return { established: false, survivors: [...survivors, ...stillAlive.map(pick)], unattributable, reason: "descendants seen before the kill are still running" };
  if (sweep.terminated !== true) return { established: false, survivors, unattributable, reason: "linked survivors could not be confirmed gone" };
  if (unattributable.length > 0) return { established: false, survivors, unattributable, reason: "processes created during the run have untraceable ancestry (a descendant behind an exited intermediate cannot be linked)" };
  const what = pre === NO_KILL ? "no descendant survives the exit" : "no descendant seen before the kill survives";
  return { established: true, survivors: [], unattributable: [], reason: `${what} and no process created during the run is untraceable` };
}

/**
 * Termination evidence for everything an operation may have started from this server
 * process since `sinceMs` (self-test probes, git queries), when no single root is known.
 * Established only if the table is readable, no live process created since `sinceMs`
 * descends from this server, and none has untraceable ancestry. Report only: nothing is
 * killed (a live descendant may belong to another operation of this server).
 */
export function checkOperationTermination(serverPid: number, sinceMs: number, table: readonly ProcEntry[] | null): TerminationCheck {
  if (!table) return { established: false, survivors: [], unattributable: [], reason: "the process table could not be read" };
  const live = findDescendants(table, { pid: serverPid, startedAtMs: sinceMs }).map(pick);
  const unattributable = unattributableSince(table, sinceMs, 2000, serverPid).map(pick);
  if (live.length > 0) return { established: false, survivors: live, unattributable, reason: "processes started by this server during the operation are still running" };
  if (unattributable.length > 0) return { established: false, survivors: [], unattributable, reason: "processes created during the operation have untraceable ancestry" };
  return { established: true, survivors: [], unattributable: [], reason: "no process started during the operation survives and none is untraceable" };
}

export function pick(e: ProcEntry): { pid: number; name: string } {
  return { pid: e.pid, name: e.name };
}
