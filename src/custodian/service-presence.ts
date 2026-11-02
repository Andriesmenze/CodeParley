// P3.4C-3 (contract §5.4): is the CodeParley custodian service registered with this host's service manager? Whether
// the engine must ask the custodian which records are authoritative for a run follows from this OS fact, which a
// standard user can read but only an administrator can change — never from a user-writable field.
//
// The answer is THREE-valued, and only an explicit answer makes the service "absent":
//  - registered — the service manager opened the service (`sc.exe query` exits 0);
//  - absent     — the service manager answered that it does not exist (ERROR_SERVICE_DOES_NOT_EXIST, 1060), or the
//                 host is neither Windows nor Linux (no custodian exists there);
//  - unknown    — every other outcome (access denied, a timeout, an RPC or service-manager error, a helper that did
//                 not run). Callers treat unknown as registered (fail closed): an error is never read as "absent".
// "Absent" is never cached, so a custodian installed during a session is seen at the next query; "registered" is
// cached for the life of the process (uninstalling needs an administrator, and a stale "registered" only fails closed).

import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { runProcess } from "../process/spawn.js";

export type CustodianPresence = "registered" | "absent" | "unknown";

/** The custodian's service name (custodian/…/CustodianConstants.cs ServiceName). */
export const CUSTODIAN_SERVICE_NAME = "CodeParleyCustodian";

/** ERROR_SERVICE_DOES_NOT_EXIST: the only answer that makes the service absent. */
const ERROR_SERVICE_DOES_NOT_EXIST = 1060;

/** What a service-manager query returned: the helper's exit status (null when it did not exit normally) and whether
 * it could be started at all. */
export interface ServiceQueryResult {
  status: number | null;
  spawnError: boolean;
  timedOut: boolean;
}

/** The three-valued reading of one query: `sc.exe query` exits with the Win32 error of its OpenService call
 * (VERIFIED on Windows 11: 1060 for a service that does not exist, 0 for an installed one, whatever its state). */
export function presenceOf(r: ServiceQueryResult): CustodianPresence {
  if (r.spawnError || r.timedOut || r.status === null) return "unknown";
  if (r.status === 0) return "registered";
  if (r.status === ERROR_SERVICE_DOES_NOT_EXIST) return "absent";
  return "unknown";
}

/** This installation's service-control tool (never resolved through PATH). */
function scExe(): string {
  return join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "sc.exe");
}

async function queryService(): Promise<ServiceQueryResult> {
  try {
    const r = await runProcess(scExe(), ["query", CUSTODIAN_SERVICE_NAME], { wallMs: 15_000 });
    return { status: r.status, spawnError: r.spawnError !== null, timedOut: r.timedOut || r.idleTimedOut || r.cancelled };
  } catch {
    return { status: null, spawnError: true, timedOut: false };
  }
}

let registered = false;

/** The host's answer (cached once registered). `query` replaces the service-manager query (tests only). */
export async function custodianServicePresence(o: { platform?: NodeJS.Platform; query?: () => Promise<ServiceQueryResult>; unitPath?: string } = {}): Promise<CustodianPresence> {
  const platform = o.platform ?? process.platform;
  if (platform === "linux") return linuxPresence(o.unitPath ?? LINUX_UNIT);
  if (platform !== "win32") return "absent";
  if (registered && !o.query) return "registered";
  const p = presenceOf(await (o.query ?? queryService)());
  if (p === "registered" && !o.query) registered = true;
  return p;
}

/** Phase 5 (contract §4.14): on Linux the custodian is registered when root installed its socket unit — a file in
 * /etc/systemd/system only an administrator can create or remove. Three-valued like Windows: present → registered;
 * ENOENT → absent; any other outcome → unknown (callers treat unknown as registered: fail closed). */
export const LINUX_UNIT = "/etc/systemd/system/codeparley-implementer.socket";

async function linuxPresence(unit: string): Promise<CustodianPresence> {
  try {
    const s = await lstat(unit);
    return s.isFile() && s.uid === 0 ? "registered" : "unknown";
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ENOENT" ? "absent" : "unknown";
  }
}
