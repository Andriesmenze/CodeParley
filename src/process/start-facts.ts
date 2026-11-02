// Start facts of a process this server just started (plan §15.4, §15.5; Linux milestone §1.13):
// the wall-clock start time recorded for recovery and termination evidence, and — on Linux —
// the exact start identity ("<boot id>:<start ticks>") that liveness checks compare.

import { identityToken, readProcClockSync, readStatSync, startMs } from "./linux-proc.js";

export interface StartFacts {
  startedAtMs: number;
  /** Linux: exact start identity. */
  startIdentity?: string;
}

/**
 * Start facts of the live process `pid`, from the OS where it records them exactly (Linux
 * /proc); `fallbackMs` (for example Date.now() taken right after spawning it) elsewhere.
 */
export function startFactsOf(pid: number, fallbackMs: number): StartFacts {
  if (process.platform !== "linux") return { startedAtMs: fallbackMs };
  const s = readStatSync(pid);
  const clock = readProcClockSync();
  if (!s || !clock) return { startedAtMs: fallbackMs };
  return { startedAtMs: startMs(s.startTicks, clock), startIdentity: identityToken(s.startTicks) };
}
