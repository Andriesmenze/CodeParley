// Crash-recovery foundations (plan §15.5, MR-C). The engine never infers that an
// interrupted operation completed. On startup/next-use, a `running` operation whose owner
// is dead is marked `interrupted` and the run enters INTERRUPTED. If the dead operation was
// a CHECK, its worktree lock becomes `ownership_unresolved` (its descendants may survive,
// G7) and possible orphans are reported — there is NO automatic sweep.
//
// A dead REVIEW (M1.4, M1.3-11): on Windows codex.exe dies with the server (libuv
// kill-on-close job), but MXC does not end sandboxed commands when codex.exe alone is
// terminated, so they may still run. On Linux (plan §1.13) bubblewrap ends the sandboxed
// commands when Codex exits, but Codex itself may outlive a server that was killed (the
// session reaper normally ends it; recovery kills a recorded Codex that is still confirmed
// alive). Either way recovery records an append-only isolation incident
// (`possible_surviving_sandboxed_commands`) naming the recorded child and any live
// descendants it can still link to it, marks the review record `interrupted`, and kills
// nothing it cannot confirm. Cleanup is not assumed and nothing is swept.
//
// `planRecovery` is pure given an injected liveness classifier (unit-testable); `applyRecovery`
// performs the side effects (tree kills, lock flagging) and commits via the state store.

import { killTree, type RootIdentity } from "../process/kill-tree.js";
import { ticksOfIdentity } from "../process/linux-proc.js";
import { findDescendants, snapshotProcessTable } from "../process/proc-table.js";
import { uuidv7 } from "../common/ids.js";
import { atomicWriteFile } from "./atomic.js";
import { readWorktreeLock } from "./locks.js";
import { commitState } from "./state-store.js";
import { classifyOwnerLiveness, OWNER_LIVENESS_DEPS, pidAlive, type OwnerRecord, type Liveness } from "./owner.js";
import type { RunPaths } from "./paths.js";
import type { Operation, StateRecord } from "../schemas/run-state.js";

export interface RecordedChild {
  pid: number;
  startedAtMs?: number;
  /** Linux: exact start identity (store/owner.ts). */
  startIdentity?: string;
  commandLine?: string;
}

export interface OrphanReport {
  operation_id: string;
  kind: string;
  command_lines: string[];
  recorded_child?: RecordedChild;
}

export interface RecoveryPlan {
  changed: boolean;
  nextState: StateRecord;
  interrupted: string[];
  ownershipUnresolved: OrphanReport[];
  possibleOrphans: OrphanReport[];
  childrenToKill: RecordedChild[];
  /** Dead review operations: their sandboxed commands may survive (M1.3-11). */
  reviewOrphans: OrphanReport[];
}

const TERMINAL: ReadonlySet<string> = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

/** Decide what recovery should do. Pure given `classify`. Does not mutate `state`. */
export async function planRecovery(
  state: StateRecord,
  classify: (owner: OwnerRecord) => Promise<Liveness>,
): Promise<RecoveryPlan> {
  const next: StateRecord = structuredCloneSafe(state);
  const interrupted: string[] = [];
  const ownershipUnresolved: OrphanReport[] = [];
  const possibleOrphans: OrphanReport[] = [];
  const childrenToKill: RecordedChild[] = [];
  const reviewOrphans: OrphanReport[] = [];

  for (const op of next.operations) {
    if (op.status !== "running") continue;
    const live = op.owner ? await classify(op.owner) : "dead";
    if (live === "alive" || live === "alive_unconfirmed") continue; // leave running ops of live owners

    op.status = "interrupted";
    interrupted.push(op.operation_id);

    const child = recordedChild(op);
    const report: OrphanReport = {
      operation_id: op.operation_id,
      kind: op.kind,
      command_lines: commandLines(op),
      ...(child ? { recorded_child: child } : {}),
    };
    if (child) childrenToKill.push(child);
    if (op.kind === "checks") {
      ownershipUnresolved.push(report);
      possibleOrphans.push(report);
    }
    if (op.kind === "review") {
      possibleOrphans.push(report);
      reviewOrphans.push(report);
    }
  }

  if (interrupted.length > 0 && !TERMINAL.has(next.state)) {
    next.state = "INTERRUPTED";
  }

  return {
    changed: interrupted.length > 0,
    nextState: next,
    interrupted,
    ownershipUnresolved,
    possibleOrphans,
    childrenToKill,
    reviewOrphans,
  };
}

export interface ApplyRecoveryDeps {
  /** Liveness of a recorded child (PID + creation time). Default: owner.ts classification. */
  classifyChild?: (child: RecordedChild) => Promise<Liveness>;
  kill?: (pid: number, start: RootIdentity) => Promise<boolean>;
  /**
   * Live processes still linked to a dead review's recorded child (REPORT ONLY; nothing is
   * killed). Default: process-table walk; null when the table cannot be read.
   */
  linkedDescendants?: (child: RecordedChild) => Promise<{ pid: number; name: string }[] | null>;
}

/** Apply a recovery plan: kill recorded live children, flag worktree ownership, commit state. */
export async function applyRecovery(
  paths: RunPaths,
  owner: OwnerRecord,
  plan: RecoveryPlan,
  worktreeLockPath: string | null,
  deps: ApplyRecoveryDeps = {},
): Promise<StateRecord | null> {
  // Kill the tree of a recorded direct child only when it is CONFIRMED to be the same
  // process (PID and creation time match, plan §15.5). A bare PID may have been reused by
  // an unrelated process, and `taskkill /T` would end that process and its tree.
  const classifyChild =
    deps.classifyChild ??
    ((c: RecordedChild) =>
      c.startedAtMs === undefined
        ? Promise.resolve<Liveness>(pidAlive(c.pid) ? "alive_unconfirmed" : "dead")
        : classifyOwnerLiveness({ serverInstanceId: "child", pid: c.pid, startedAtMs: c.startedAtMs, ...(c.startIdentity ? { startIdentity: c.startIdentity } : {}) }, OWNER_LIVENESS_DEPS));
  const kill = deps.kill ?? ((pid: number, start: RootIdentity) => killTree(pid, 10_000, start));
  const killed = new Set<number>();
  for (const child of plan.childrenToKill) {
    if ((await classifyChild(child).catch(() => "alive_unconfirmed" as const)) === "alive") {
      // Matched by the recorded identity: the exact start ticks when recorded (Linux), else the creation time.
      const ticks = ticksOfIdentity(child.startIdentity);
      await kill(child.pid, { ...(child.startedAtMs !== undefined ? { startedAtMs: child.startedAtMs } : {}), ...(ticks !== null ? { startTicks: ticks } : {}) }).catch(() => undefined);
      killed.add(child.pid);
    }
  }

  // Dead reviews: report what may still run under the sandbox (never swept).
  const linked = deps.linkedDescendants ?? defaultLinkedDescendants;
  const reviewReports: { report: OrphanReport; live: { pid: number; name: string }[] | null; childKilled: boolean }[] = [];
  for (const r of plan.reviewOrphans) {
    const live = r.recorded_child ? await linked(r.recorded_child).catch(() => null) : null;
    reviewReports.push({ report: r, live, childKilled: r.recorded_child ? killed.has(r.recorded_child.pid) : false });
  }

  // Flag the worktree lock ownership_unresolved for dead check operations (MR-C). We never
  // break it here; a deliberate CLI release does that. Only a lock one of them holds: a check
  // operation that died while still waiting for the lock (D-31) never held it, and a lock held
  // by someone else (a read, a capture, another run's checks) is not its to flag. The recovery
  // event reports only such a lock, flagged now or before.
  let unresolvedLocks = 0;
  if (worktreeLockPath && plan.ownershipUnresolved.length > 0) {
    const existing = await readWorktreeLock(worktreeLockPath);
    const holders = existing ? plan.ownershipUnresolved.filter((o) => o.operation_id === existing.operation_id) : [];
    if (holders.length > 0) unresolvedLocks = 1;
    if (existing && holders.length > 0 && !existing.ownership_unresolved) {
      const merged = { ...existing, ownership_unresolved: true };
      const recordedCmds = holders.flatMap((o) => o.command_lines);
      if (recordedCmds.length) merged.command_lines = [...new Set([...(existing.command_lines ?? []), ...recordedCmds])];
      await atomicWriteFile(worktreeLockPath, JSON.stringify(merged, null, 2));
    }
  }

  if (!plan.changed) return null;

  return commitState(paths, owner, (cur) => {
    const updated: StateRecord = structuredCloneSafe(cur);
    const set = new Set(plan.interrupted);
    for (const op of updated.operations) {
      if (set.has(op.operation_id) && op.status === "running") op.status = "interrupted";
    }
    if (plan.interrupted.length > 0 && !TERMINAL.has(updated.state)) updated.state = "INTERRUPTED";
    const at = new Date().toISOString();
    for (const rr of reviewReports) {
      const op = updated.operations.find((o) => o.operation_id === rr.report.operation_id);
      const reviewId = typeof op?.["review_id"] === "string" ? (op["review_id"] as string) : null;
      const review = reviewId ? updated.reviews.find((x) => x.review_id === reviewId) : undefined;
      if (review && review.status === "running") {
        review.status = "interrupted";
        review.ended_at = at;
        review.failure = { class: "owner_died", detail: "the server that ran this review exited before recording an outcome" };
      }
      const child = rr.report.recorded_child;
      const liveText =
        rr.live === null
          ? "the process table could not be read; survivors unknown"
          : rr.live.length === 0
            ? "no live process could be linked to it (descendants whose chain passed through an exited process cannot be linked)"
            : `still running and linked to it: ${rr.live.map((p) => `${p.name} (${p.pid})`).join(", ")}`;
      updated.isolation_incidents.push({
        incident_id: uuidv7(),
        review_id: reviewId,
        operation_id: rr.report.operation_id,
        kind: "possible_surviving_sandboxed_commands",
        detail:
          (process.platform === "win32"
            ? "the review's owner died; Codex sandboxed commands may have survived (MXC does not end them when codex.exe alone is terminated). "
            : "the review's owner died; Codex and its sandboxed commands may have survived it (bubblewrap ends sandboxed commands when Codex exits, but Codex may have outlived the server). ") +
          (child ? `recorded codex child pid ${child.pid}${rr.childKilled ? " was still alive and its tree was killed" : ""}; ` : "no codex child was recorded; ") +
          `${liveText}. Nothing was swept; review ownership is unresolved until these are confirmed gone.`,
        at,
        source: "engine",
        possible_orphans: rr.live ?? [],
      });
    }
    const seq = (updated.events.at(-1)?.seq ?? 0) + 1;
    updated.events.push({
      seq,
      ts: new Date().toISOString(),
      type: "recovery.interrupted",
      actor: "engine",
      summary: `recovered ${plan.interrupted.length} interrupted operation(s)` +
        (unresolvedLocks ? `; ${unresolvedLocks} worktree ownership unresolved` : "") +
        (plan.reviewOrphans.length ? `; ${plan.reviewOrphans.length} review(s) with possible surviving sandboxed commands` : ""),
      refs: {},
    });
    return updated;
  });
}

async function defaultLinkedDescendants(child: RecordedChild): Promise<{ pid: number; name: string }[] | null> {
  const table = await snapshotProcessTable();
  if (!table) return null;
  // Linux: the child's exact start ticks, so a newer process holding its PID is never taken for it.
  const ticks = ticksOfIdentity(child.startIdentity);
  return findDescendants(table, { pid: child.pid, startedAtMs: child.startedAtMs ?? 0, ...(ticks !== null ? { startTicks: ticks } : {}) }).map((e) => ({ pid: e.pid, name: e.name }));
}

function recordedChild(op: Operation): RecordedChild | undefined {
  const c = (op as { child?: unknown }).child;
  if (c && typeof c === "object" && typeof (c as RecordedChild).pid === "number") {
    return c as RecordedChild;
  }
  return undefined;
}

function commandLines(op: Operation): string[] {
  const c = (op as { command_lines?: unknown }).command_lines;
  if (Array.isArray(c)) return c.filter((x): x is string => typeof x === "string");
  const child = recordedChild(op);
  return child?.commandLine ? [child.commandLine] : [];
}

function structuredCloneSafe<T>(v: T): T {
  try {
    return structuredClone(v);
  } catch {
    return JSON.parse(JSON.stringify(v)) as T;
  }
}
