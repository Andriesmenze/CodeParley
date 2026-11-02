// Retention and purge eligibility (plan §15.5, §15.6; M1.6). Pure: the engine supplies what it
// read from the store (the run's records, the operation ids referenced by worktree locks,
// whether the run's directories are plain) and the clock.
//
// A run may be deleted only when nothing about it is active or unresolved:
//  - no operation is `running` — whether its server is alive or died before recovery was
//    recorded (deleting it would destroy the recorded processes recovery reports on);
//  - the run is not INTERRUPTED (recovery evidence; the user closes the run after inspection);
//  - no worktree lock references one of its operations (held, or ownership_unresolved: MR-C);
//  - its records are readable, of this schema version, and consistent with its folder;
//  - its directory (and the store directories above it) are plain directories, never links.
// Anything else is kept and reported with its reason. Refusing is always the safe direction.

export type KeepCode =
  | "link_in_store"
  | "unreadable"
  | "newer_schema"
  | "inconsistent"
  | "active_operation"
  | "interrupted"
  | "worktree_lock";

export interface RunFacts {
  /** The run's folder name. */
  runId: string;
  /** The run directory and the store directories above it are plain directories. */
  plainDirectory: boolean;
  /** Reading run.json / state.json failed (code: STORE_VERSION_UNSUPPORTED, RUN_NOT_FOUND, INTERNAL, …). */
  readError: { code: string; detail: string } | null;
  metaRunId: string | null;
  createdAt: string | null;
  state: { state: string; updated_at: string; operations: readonly { operation_id: string; kind: string; status: string }[] } | null;
}

export type PurgeVerdict = { eligible: true } | { eligible: false; code: KeepCode; reason: string };

const BUSY_STATES = new Set(["PREPARING", "CHECKING", "REVIEWING"]);

/** Last committed activity of a run (epoch ms), or null when unknown. */
export function lastActivityMs(f: Pick<RunFacts, "state" | "createdAt">): number | null {
  const times = [f.state?.updated_at, f.createdAt].map((t) => (t ? Date.parse(t) : NaN)).filter((t) => Number.isFinite(t));
  return times.length ? Math.max(...times) : null;
}

/** Is a run old enough for an age-based purge? Unknown age is never old enough. */
export function oldEnough(lastMs: number | null, nowMs: number, minAgeMs: number): boolean {
  return lastMs !== null && nowMs - lastMs >= minAgeMs;
}

/** Whether a run may be deleted now (independent of age). */
export function purgeVerdict(f: RunFacts, lockedOperationIds: ReadonlySet<string>): PurgeVerdict {
  const keep = (code: KeepCode, reason: string): PurgeVerdict => ({ eligible: false, code, reason });
  if (!f.plainDirectory) return keep("link_in_store", "the run directory, or a store directory above it, is a link or reparse point; it is never followed");
  if (f.readError) {
    if (f.readError.code === "STORE_VERSION_UNSUPPORTED") return keep("newer_schema", "written by a newer version; kept read-only");
    return keep("unreadable", `its records could not be read (${f.readError.code}); kept for inspection`);
  }
  if (!f.state || f.metaRunId !== f.runId) return keep("inconsistent", "run.json does not match its folder");
  const ops = f.state.operations;
  const running = ops.filter((o) => o.status === "running");
  if (running.length > 0) {
    return keep("active_operation", `operation ${running.map((o) => `${o.operation_id} (${o.kind})`).join(", ")} is running — or its server exited before recovery was recorded`);
  }
  if (f.state.state === "INTERRUPTED") return keep("interrupted", "an operation was interrupted; inspect it, then close the run (runs stop --close)");
  if (BUSY_STATES.has(f.state.state)) return keep("inconsistent", `state ${f.state.state} without a running operation`);
  const locked = ops.filter((o) => lockedOperationIds.has(o.operation_id));
  if (locked.length > 0) return keep("worktree_lock", `a worktree lock references operation ${locked.map((o) => o.operation_id).join(", ")} (inspect with lock show)`);
  return { eligible: true };
}
