// Process identity for tests (M1.6-14). A PID alone does not identify a process: under the
// parallel suite Windows can hand a freed PID to a new process within milliseconds, so a
// PID-only "is it gone?" probe can report a killed process as alive. These helpers identify a
// process by PID plus creation time — the product's own rule (2 s tolerance) — captured while
// it is known to be running.

import { startTimeOf } from "../../src/store/owner.js";

export interface ProcIdentity {
  pid: number;
  /** Creation time (epoch ms) captured while the process ran; null if it could not be read. */
  at: number | null;
}

/** PID-only liveness (also true for a process that merely inherited the PID). */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as { code?: string }).code === "EPERM";
  }
}

/** Capture the identity of a process that is running now. */
export async function identify(pid: number): Promise<ProcIdentity> {
  return { pid, at: await startTimeOf(pid) };
}

/**
 * Is THAT process still running? A later process that reused its PID does not count. A creation time that cannot be read
 * (P3.4C-5 Increment 4 triage: on Windows the read is a WMI query that is slow under the parallel suite, and it finds no row
 * for a process that exited after the liveness probe) is not taken for a live process until the PID is re-checked: an
 * exited process is not running; one still alive is read once more, and only if it stays unknown is it not ruled out.
 */
export async function stillRunning(id: ProcIdentity): Promise<boolean> {
  if (!pidAlive(id.pid)) return false;
  if (id.at === null) return true; // identity unknown: it cannot be ruled out
  for (let attempt = 0; attempt < 2; attempt++) {
    const now = await startTimeOf(id.pid);
    if (now !== null) return Math.abs(now - id.at) <= 2000;
    if (!pidAlive(id.pid)) return false;
  }
  return true;
}
