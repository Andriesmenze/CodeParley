// Kill a process and its whole tree. This is one of the few modules permitted to import
// node:child_process (plan §5.3 rule 4).
//
// Windows: libuv turns Node's kill() into TerminateProcess, which does not reap grandchildren
// (plan G7). The reliable way to end a tree is `taskkill /T /F`.
//
// Linux (plan §1.13): every child CodeParley starts leads its own session and process group
// (spawn.ts), so the tree is the root plus every live process in the root's session or group
// plus anything still linked to it by parent PID (tree.ts). It is not `kill -9 <pid>` (that
// ends one process and orphans the rest): the members are asked to stop (SIGTERM — a test
// runner or Codex gets the chance to end its own children), and whatever is left after a grace
// period is killed (SIGKILL), the group atomically and every member individually. The root is
// matched by its exact identity (start ticks, recorded when it was started) — never by its PID
// or an approximate start time alone, so a reused PID is never taken for it; with no identity at
// all nothing is signalled. Each member is signalled only after re-reading its start ticks (an
// exited member's PID may already belong to another process), and the whole group only while the
// root itself — matched by its exact start ticks, re-read right before — still leads it (once the
// root is gone its group id could in principle be recycled; members are then signalled one by
// one). Nothing outside the tree is ever signalled. The result is true only when a final read
// finds no member left.

import { spawn } from "node:child_process";
import { join } from "node:path";
import { readProcClockSync, readProcTable, readStatSync, startMs } from "./linux-proc.js";
import { findDescendants, type ProcEntry, type ProcRoot } from "./tree.js";

function taskkillPath(): string {
  return join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe");
}

/** What is known of a tree root's identity. */
export interface RootIdentity {
  /** Creation time, epoch ms. */
  startedAtMs?: number;
  /** Linux: start ticks since boot — with the boot id, the exact identity (plan §1.13). */
  startTicks?: number;
}

/**
 * Terminate the process tree rooted at `pid`. Best effort and bounded by `timeoutMs`. Returns
 * whether the tree is known to be gone (Windows: taskkill reported success). On Linux the root
 * is matched by `start` (a creation time in ms, or an identity): exact start ticks when known,
 * otherwise the creation time within Windows' tolerance; it also lets a root that already exited
 * be matched to the session it led. Without any identity nothing is signalled (false).
 */
export function killTree(pid: number, timeoutMs = 10_000, start?: number | RootIdentity): Promise<boolean> {
  if (process.platform === "win32") return taskkillTree(pid, timeoutMs);
  const id: RootIdentity = typeof start === "number" ? { startedAtMs: start } : (start ?? {});
  return killTreePosix(pid, { timeoutMs, ...(id.startedAtMs !== undefined ? { startedAtMs: id.startedAtMs } : {}), ...(id.startTicks !== undefined ? { startTicks: id.startTicks } : {}) });
}

function taskkillTree(pid: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(taskkillPath(), ["/PID", String(pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
    } catch {
      resolve(false);
      return;
    }
    let settled = false;
    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      resolve(ok);
    };
    const t = setTimeout(() => done(false), timeoutMs);
    child.on("error", () => {
      clearTimeout(t);
      done(false);
    });
    child.on("close", (code) => {
      clearTimeout(t);
      done(code === 0);
    });
  });
}

export interface PosixKillOptions {
  timeoutMs?: number;
  /** The root's creation time (epoch ms); used to match it only when `startTicks` is unknown. */
  startedAtMs?: number;
  /** The root's exact start ticks (its identity with the boot id). */
  startTicks?: number;
  /** Time members get to exit after SIGTERM before SIGKILL (default 2000 ms). */
  graceMs?: number;
  /** TEST ONLY: the process table and the signal primitive. */
  deps?: { table?: () => Promise<ProcEntry[] | null>; signal?: (pid: number, sig: NodeJS.Signals) => void; stillSame?: (e: ProcEntry) => boolean };
}

const POLL_MS = 100;

async function linuxTable(): Promise<ProcEntry[] | null> {
  const t = await readProcTable();
  return t ? t.map((e) => ({ pid: e.pid, ppid: e.ppid, createdMs: e.createdMs, name: e.comm, pgid: e.pgrp, sid: e.session, uid: e.uid, startTicks: e.startTicks })) : null;
}

/** Is the process listed in `e` still that same process (same start ticks, not a zombie)? */
function stillSameProcess(e: ProcEntry): boolean {
  const now = readStatSync(e.pid);
  if (!now || now.state === "Z" || now.state === "X") return false;
  return e.startTicks === undefined || now.startTicks === e.startTicks;
}

function sendSignal(pid: number, sig: NodeJS.Signals): void {
  try {
    process.kill(pid, sig);
  } catch {
    /* already gone, or not ours to signal (EPERM): the final read decides */
  }
}

/** How the root is recognised in a process-table row (exact start ticks; else the creation time within Windows' tolerance). */
function rootMatcher(rootPid: number, o: PosixKillOptions): (e: ProcEntry) => boolean {
  const ticks = o.startTicks;
  if (ticks !== undefined) return (e) => e.pid === rootPid && e.startTicks === ticks;
  const at = o.startedAtMs;
  return (e) => at !== undefined && e.pid === rootPid && Math.abs(e.createdMs - at) <= 2000;
}

/** The root's creation time: given, derived from its start ticks, or read from the table; undefined when none of them is known. */
function rootStart(o: PosixKillOptions, t: readonly ProcEntry[], isRoot: (e: ProcEntry) => boolean): number | undefined {
  if (o.startedAtMs !== undefined) return o.startedAtMs;
  const clock = o.startTicks !== undefined ? readProcClockSync() : null;
  if (clock && o.startTicks !== undefined) return startMs(o.startTicks, clock);
  return t.find(isRoot)?.createdMs;
}

/** One tree kill in progress: the root, what has been found of its tree, and how to signal it. */
interface PosixKill {
  rootPid: number;
  root: ProcRoot;
  isRoot: (e: ProcEntry) => boolean;
  /** The root is known by its exact start ticks (only then may its group be signalled). */
  exact: boolean;
  targets: Map<number, ProcEntry>;
  signal: (pid: number, sig: NodeJS.Signals) => void;
  same: (e: ProcEntry) => boolean;
}

/** Add the root and every linked descendant found in `tab` to the targets. */
function collectTargets(k: PosixKill, tab: readonly ProcEntry[]): void {
  for (const e of tab) if (k.isRoot(e) && !k.targets.has(e.pid)) k.targets.set(e.pid, e);
  for (const d of findDescendants(tab, k.root)) if (!k.targets.has(d.pid)) k.targets.set(d.pid, d);
}

/** The targets still listed in `tab` as the same processes. */
function aliveTargets(k: PosixKill, tab: readonly ProcEntry[]): ProcEntry[] {
  return [...k.targets.values()].filter((x) => tab.some((e) => e.pid === x.pid && (x.startTicks === undefined || e.startTicks === x.startTicks)));
}

/**
 * Signal `list` (each member after re-checking its identity) and — atomically — the root's
 * group, but only while the root itself (exact start ticks, re-read right now) still leads it.
 */
function signalTargets(k: PosixKill, list: readonly ProcEntry[], sig: NodeJS.Signals, tab: readonly ProcEntry[]): void {
  if (k.exact && tab.some((e) => k.isRoot(e) && e.pgid === k.rootPid && k.same(e))) k.signal(-k.rootPid, sig);
  for (const e of list) if (k.same(e)) k.signal(e.pid, sig);
}

export async function killTreePosix(rootPid: number, o: PosixKillOptions = {}): Promise<boolean> {
  const table = o.deps?.table ?? linuxTable;
  const deadline = Date.now() + (o.timeoutMs ?? 10_000);
  const termUntil = Math.min(deadline, Date.now() + (o.graceMs ?? 2000));
  // Without any identity of the root nothing can be matched safely: nothing is signalled, and
  // nothing is known about its tree.
  if (o.startTicks === undefined && o.startedAtMs === undefined) return false;
  const t = await table();
  if (!t) return false;
  const k = startKill(rootPid, o, t);
  // An exited root whose creation time cannot be derived cannot be matched to its session.
  if (!k) return false;
  collectTargets(k, t);
  if (k.targets.size === 0) return true;
  signalTargets(k, [...k.targets.values()], "SIGTERM", t);
  return pursue(k, table, deadline, termUntil);
}

/** The state of a tree kill for `rootPid`, or null when the root's creation time is unknown. */
function startKill(rootPid: number, o: PosixKillOptions, t: readonly ProcEntry[]): PosixKill | null {
  const isRoot = rootMatcher(rootPid, o);
  const startedAtMs = rootStart(o, t, isRoot);
  if (startedAtMs === undefined) return null;
  const ticks = o.startTicks === undefined ? {} : { startTicks: o.startTicks };
  return {
    rootPid,
    root: { pid: rootPid, startedAtMs, ...ticks },
    isRoot,
    exact: o.startTicks !== undefined,
    targets: new Map(),
    signal: o.deps?.signal ?? sendSignal,
    same: o.deps?.stillSame ?? stillSameProcess,
  };
}

/** Re-read the table until every target is gone (true) or the deadline passes (false); SIGTERM, then SIGKILL after the grace period. */
async function pursue(k: PosixKill, table: () => Promise<ProcEntry[] | null>, deadline: number, termUntil: number): Promise<boolean> {
  let sig: NodeJS.Signals = "SIGTERM";
  for (;;) {
    await new Promise((r) => setTimeout(r, POLL_MS));
    const t = await table();
    if (!t) return false;
    const before = k.targets.size;
    collectTargets(k, t);
    const left = aliveTargets(k, t);
    if (left.length === 0) return true;
    if (Date.now() >= deadline) return false;
    if (sig === "SIGTERM" && Date.now() >= termUntil) sig = "SIGKILL";
    // Under SIGKILL every target left is re-hit; before that only new members (forked meanwhile).
    if (sig === "SIGKILL") signalTargets(k, left, sig, t);
    else if (k.targets.size > before) signalTargets(k, [...k.targets.values()].slice(before), sig, t);
  }
}
