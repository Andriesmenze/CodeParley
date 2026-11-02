// Process facts on Linux, read from /proc (Linux milestone, plan §1.13). No child processes:
// the process table, start times and liveness come straight from the kernel's own records.
//
//  - /proc/<pid>/stat gives the parent PID, process group, session, state and the start time
//    in clock ticks since boot. The command name is parsed between the FIRST "(" and the LAST
//    ")", because it may itself contain spaces and parentheses.
//  - A process's IDENTITY is (boot id, start ticks): exact, and immune to wall-clock steps
//    (NTP, or WSL resynchronizing its clock after the host slept). Wall-clock start times
//    (epoch ms) are derived per read from the process's age — /proc/uptime and Date.now() read
//    together — and are used only for ordering and display, with the same tolerance as on
//    Windows.
//  - A zombie (state Z) or dead (X) entry has terminated: it is never "alive".
//  - An open pipe or socket is named by its inode ("socket:[123]" in /proc/<pid>/fd), one
//    kernel object for as long as any process holds it: a process holding a child's output
//    endpoint inherited it from that child's tree (`holdersOf`).
// USER_HZ is 100 on every architecture CodeParley supports (x86-64, arm64).

import { readFileSync, readdirSync, readlinkSync, statSync } from "node:fs";
import { readFile, readdir, readlink, stat } from "node:fs/promises";

export const CLK_TCK = 100;

export interface LinuxStat {
  pid: number;
  comm: string;
  state: string;
  ppid: number;
  pgrp: number;
  session: number;
  /** Start time in clock ticks since boot. */
  startTicks: number;
}

/** Parse the text of /proc/<pid>/stat, or null when it is malformed. */
export function parseProcStat(text: string): LinuxStat | null {
  const open = text.indexOf("(");
  const close = text.lastIndexOf(")");
  if (open < 0 || close < open) return null;
  const pid = Number(text.slice(0, open).trim());
  const comm = text.slice(open + 1, close);
  const f = text.slice(close + 1).trim().split(/\s+/);
  // f[0] = state (field 3), f[1] = ppid (4), f[2] = pgrp (5), f[3] = session (6), f[19] = starttime (22)
  const state = f[0] ?? "";
  const ppid = Number(f[1]);
  const pgrp = Number(f[2]);
  const session = Number(f[3]);
  const startTicks = Number(f[19]);
  if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(ppid) || !Number.isInteger(pgrp) || !Number.isInteger(session) || !Number.isFinite(startTicks)) return null;
  return { pid, comm, state, ppid, pgrp, session, startTicks };
}

/** Has this entry terminated (zombie or dead)? */
export function isTerminated(s: Pick<LinuxStat, "state">): boolean {
  return s.state === "Z" || s.state === "X" || s.state === "x";
}

let bootIdCache: string | null = null;

/** The kernel's boot id (changes on every boot), or "" when unreadable. */
export function bootId(): string {
  if (bootIdCache === null) {
    try {
      bootIdCache = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    } catch {
      bootIdCache = "";
    }
  }
  return bootIdCache;
}

/** Exact identity token of a process start: "<boot id>:<start ticks>". */
export function identityToken(startTicks: number): string {
  return `${bootId()}:${startTicks}`;
}

/** The start ticks of an identity token of THIS boot (null for another boot's, a malformed or a missing token). */
export function ticksOfIdentity(token: string | undefined | null): number | null {
  if (!token) return null;
  const at = token.lastIndexOf(":");
  const boot = bootId();
  if (at <= 0 || !boot || token.slice(0, at) !== boot) return null;
  const ticks = Number(token.slice(at + 1));
  return Number.isSafeInteger(ticks) && ticks >= 0 ? ticks : null;
}

/** The read-time pair used to turn start ticks into wall-clock milliseconds. */
export interface ProcClock {
  nowMs: number;
  uptimeMs: number;
}

export function readProcClockSync(): ProcClock | null {
  try {
    const t = readFileSync("/proc/uptime", "utf8");
    const nowMs = Date.now();
    const up = Number(t.split(/\s+/)[0]);
    return Number.isFinite(up) ? { nowMs, uptimeMs: up * 1000 } : null;
  } catch {
    return null;
  }
}

/** Wall-clock start (epoch ms) of a process that started `startTicks` after boot. */
export function startMs(startTicks: number, clock: ProcClock): number {
  return Math.round(clock.nowMs - (clock.uptimeMs - (startTicks * 1000) / CLK_TCK));
}

/** /proc/<pid>/stat of one process, or null when it does not exist (or is unreadable). */
export function readStatSync(pid: number): LinuxStat | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    return parseProcStat(readFileSync(`/proc/${pid}/stat`, "utf8"));
  } catch {
    return null;
  }
}

/** Owner uid of a process (the owner of its /proc directory), or null. */
export function uidOfSync(pid: number): number | null {
  try {
    return statSync(`/proc/${pid}`).uid;
  } catch {
    return null;
  }
}

/** What a process's file descriptor refers to (e.g. "socket:[123]", "pipe:[45]", a path), or null. */
export function fdTargetSync(pid: number, fd: number): string | null {
  try {
    return readlinkSync(`/proc/${pid}/fd/${fd}`);
  } catch {
    return null;
  }
}

/** Is an fd target an anonymous pipe or socket (an inode that only inheritance or explicit passing can share)? */
export function isPipeEndpoint(target: string): boolean {
  return /^(?:pipe|socket):\[\d+\]$/.test(target);
}

/**
 * The processes among `candidates` that hold any of `targets` open. A process whose
 * descriptors cannot be read (another user's) is skipped: this finds holders, it never proves
 * that there are none.
 */
export async function holdersOf(targets: ReadonlySet<string>, candidates: readonly number[]): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < candidates.length; i += 64) {
    const batch = await Promise.all(candidates.slice(i, i + 64).map(async (pid) => ((await holds(pid, targets)) ? pid : null)));
    for (const pid of batch) if (pid !== null) out.push(pid);
  }
  return out;
}

/** Does process `pid` hold one of `targets` open? False when its descriptors cannot be read. */
async function holds(pid: number, targets: ReadonlySet<string>): Promise<boolean> {
  const fds = await readdir(`/proc/${pid}/fd`).catch(() => [] as string[]);
  for (const fd of fds) {
    const t = await readlink(`/proc/${pid}/fd/${fd}`).catch(() => null);
    if (t !== null && targets.has(t)) return true;
  }
  return false;
}

export interface LinuxProcEntry extends LinuxStat {
  /** Wall-clock start, epoch ms (derived; see the module comment). */
  createdMs: number;
  uid: number | null;
}

/**
 * Every live process visible in /proc (zombies excluded), or null when /proc cannot be read.
 * A process that exits while the table is read is simply absent.
 */
export async function readProcTable(): Promise<LinuxProcEntry[] | null> {
  let names: string[];
  try {
    names = await readdir("/proc");
  } catch {
    return null;
  }
  const clock = readProcClockSync();
  if (!clock) return null;
  const pids = names.filter((n) => /^[0-9]+$/.test(n));
  const out: LinuxProcEntry[] = [];
  for (let i = 0; i < pids.length; i += 64) {
    const batch = await Promise.all(
      pids.slice(i, i + 64).map(async (p) => {
        try {
          const [text, st] = await Promise.all([readFile(`/proc/${p}/stat`, "utf8"), stat(`/proc/${p}`)]);
          const s = parseProcStat(text);
          if (!s || isTerminated(s)) return null;
          return { ...s, createdMs: startMs(s.startTicks, clock), uid: st.uid };
        } catch {
          return null;
        }
      }),
    );
    for (const e of batch) if (e) out.push(e);
  }
  return out.length > 0 ? out : null;
}

/** Synchronous variant for the session reaper's exit path. */
export function readProcTableSync(): LinuxProcEntry[] | null {
  let names: string[];
  try {
    names = readdirSync("/proc");
  } catch {
    return null;
  }
  const clock = readProcClockSync();
  if (!clock) return null;
  const out: LinuxProcEntry[] = [];
  for (const p of names) {
    if (!/^[0-9]+$/.test(p)) continue;
    const s = readStatSync(Number(p));
    if (!s || isTerminated(s)) continue;
    out.push({ ...s, createdMs: startMs(s.startTicks, clock), uid: uidOfSync(s.pid) });
  }
  return out.length > 0 ? out : null;
}
