// Operation/lock ownership identity and liveness (plan §15.4, §15.5).
//
// An owner is (server instance id, PID, process start time). PID alone is not enough —
// Windows and Linux reuse PIDs — so staleness requires the PID to be gone, OR alive as a
// NEWER process (created after the recorded start, beyond the tolerance; see
// classifyOwnerLiveness). When the start time cannot be read, liveness is reported as
// "alive_unconfirmed" and the caller must NOT treat the owner as dead (fail safe).
//
// Linux (plan §1.13): records also carry `startIdentity` — the kernel's boot id plus the
// start time in clock ticks since boot — which is compared exactly. A wall-clock start time
// derived on Linux moves when the clock is stepped (NTP, or WSL resynchronizing after the host
// slept), and a live owner must never be judged dead because of that. A zombie has terminated.

import { uuidv7 } from "../common/ids.js";
import { runProcess } from "../process/spawn.js";
import { identityToken, isTerminated, readProcClockSync, readStatSync, startMs } from "../process/linux-proc.js";
import { startFactsOf } from "../process/start-facts.js";
import { DMTF_TO_EPOCH_MS, powerShellEnv, powerShellExe } from "../process/win-powershell.js";

export { startFactsOf, type StartFacts } from "../process/start-facts.js";

/** One id per server process; stable for this process's lifetime. */
export const SERVER_INSTANCE_ID = uuidv7();

export interface OwnerRecord {
  serverInstanceId: string;
  pid: number;
  /** Process start time in epoch ms (approximate for self on Windows). */
  startedAtMs: number;
  /** Linux: exact start identity ("<boot id>:<start ticks>"). */
  startIdentity?: string;
}

export type Liveness = "alive" | "alive_unconfirmed" | "dead";

export interface LivenessDeps {
  pidAlive(pid: number): boolean;
  /** Returns the process start time in epoch ms, or null if it cannot be determined. */
  startTimeOf(pid: number): Promise<number | null>;
  /** Linux: the exact start identity of a live process, or null. */
  identityOf?(pid: number): string | null;
  /** Tolerance in ms when comparing start times (clock granularity). */
  toleranceMs?: number;
}

const LINUX = process.platform === "linux";

/** This process's owner record. */
export function selfOwner(): OwnerRecord {
  const approx = Math.floor(Date.now() - process.uptime() * 1000);
  const facts = startFactsOf(process.pid, approx);
  return {
    serverInstanceId: SERVER_INSTANCE_ID,
    pid: process.pid,
    startedAtMs: facts.startedAtMs,
    ...(facts.startIdentity ? { startIdentity: facts.startIdentity } : {}),
  };
}

/** Does a PID exist (and, on Linux, has it not terminated)? EPERM => exists, ESRCH => gone. */
export function pidAlive(pid: number): boolean {
  if (LINUX && Number.isSafeInteger(pid) && pid > 0) {
    const s = readStatSync(pid);
    if (s) return !isTerminated(s);
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === "EPERM") return true;
    return false;
  }
}

/** Start time of a process (epoch ms): /proc on Linux, WMI (Win32_Process.CreationDate) on Windows. Null on failure. */
export async function startTimeOf(pid: number): Promise<number | null> {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  if (LINUX) {
    const s = readStatSync(pid);
    const clock = readProcClockSync();
    return s && clock && !isTerminated(s) ? startMs(s.startTicks, clock) : null;
  }
  if (process.platform !== "win32") return null;
  // No cmdlets (see process/win-powershell.ts): .NET's WMI searcher and language constructs only.
  const script =
    "$ErrorActionPreference='SilentlyContinue'; " +
    `foreach ($p in ([wmisearcher]'SELECT CreationDate FROM Win32_Process WHERE ProcessId=${pid}').Get()) { ` +
    `$v = $p.CreationDate; if ($v) { [Console]::Out.Write([int64]${DMTF_TO_EPOCH_MS}) } }`;
  const r = await runProcess(powerShellExe(), ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: powerShellEnv(),
    wallMs: 15_000,
  });
  const out = r.stdout.trim();
  if (!out) return null;
  const n = Number(out);
  return Number.isFinite(n) ? n : null;
}

/** Linux: exact start identity of the live process `pid`, or null (other platforms: null). */
export function identityOf(pid: number): string | null {
  if (!LINUX) return null;
  const s = readStatSync(pid);
  return s && !isTerminated(s) ? identityToken(s.startTicks) : null;
}

const DEFAULT_DEPS: LivenessDeps = { pidAlive, startTimeOf, identityOf, toleranceMs: 2000 };

/** Default liveness dependencies (tests inject their own). */
export const OWNER_LIVENESS_DEPS: LivenessDeps = DEFAULT_DEPS;

/** Classify an owner's liveness (plan §15.4 stale rule). */
export async function classifyOwnerLiveness(record: OwnerRecord, deps: LivenessDeps = DEFAULT_DEPS): Promise<Liveness> {
  if (!deps.pidAlive(record.pid)) return "dead";
  if (record.startIdentity && deps.identityOf) {
    const now = deps.identityOf(record.pid);
    if (now !== null) return now === record.startIdentity ? "alive" : "dead"; // PID reused by a different process
  }
  const start = await deps.startTimeOf(record.pid);
  if (start == null) return "alive_unconfirmed";
  const tol = deps.toleranceMs ?? 2000;
  // A recorded start is taken after the process was created (a server's own record is "now
  // minus uptime", which a slow start under load puts seconds after the OS creation time; a
  // child's is taken after spawning it), while a process that reuses the PID was created after
  // the recorded one was alive, i.e. after the recorded start. So the OS creation time decides
  // in one direction only: up to the recorded start (plus the tolerance) it is the same process.
  if (start <= record.startedAtMs + tol) return "alive";
  return "dead"; // PID reused by a newer process
}

/**
 * `classify` for recovery run by the server `self`: an owner record of that same server
 * instance is "alive" without a query (that server is running this code); other owners are
 * classified by `classify`. A query can be slow: on Windows it starts PowerShell for WMI, which
 * has taken seconds on a loaded machine.
 */
export function aliveIfOwnInstance(self: OwnerRecord, classify: (owner: OwnerRecord) => Promise<Liveness>): (owner: OwnerRecord) => Promise<Liveness> {
  return (owner) => (owner.serverInstanceId === self.serverInstanceId ? Promise.resolve<Liveness>("alive") : classify(owner));
}
