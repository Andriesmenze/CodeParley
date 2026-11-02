import { describe, it, expect } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyRecovery, planRecovery, type RecoveryPlan } from "../src/store/recovery.js";
import { readWorktreeLock } from "../src/store/locks.js";
import { runPaths, type RunPaths } from "../src/store/paths.js";
import { createRun, readState } from "../src/store/state-store.js";
import { newStateRecord, type RunMeta, type StateRecord } from "../src/schemas/run-state.js";
import { aliveIfOwnInstance, classifyOwnerLiveness, selfOwner, type OwnerRecord, type Liveness } from "../src/store/owner.js";
import * as operations from "../src/engine/operations.js";
import type { Loaded, RunHandle } from "../src/engine/engine-env.js";

const owner = (pid: number): OwnerRecord => ({ serverInstanceId: `s${pid}`, pid, startedAtMs: 1 });

function stateWith(ops: StateRecord["operations"], state: StateRecord["state"] = "REVIEWING"): StateRecord {
  const s = newStateRecord("run-1", state);
  s.operations = ops;
  return s;
}

const classify = (map: Record<number, Liveness>) => async (o: OwnerRecord) => map[o.pid] ?? "dead";

describe("planRecovery", () => {
  it("marks a running op with a dead owner as interrupted and moves the run to INTERRUPTED", async () => {
    const s = stateWith([{ operation_id: "op1", kind: "review", status: "running", owner: owner(1) }]);
    const plan = await planRecovery(s, classify({ 1: "dead" }));
    expect(plan.changed).toBe(true);
    expect(plan.interrupted).toEqual(["op1"]);
    expect(plan.nextState.state).toBe("INTERRUPTED");
    expect(plan.nextState.operations[0]?.status).toBe("interrupted");
  });

  it("leaves a running op with a live (or unconfirmed) owner alone", async () => {
    const s = stateWith([
      { operation_id: "a", kind: "review", status: "running", owner: owner(1) },
      { operation_id: "b", kind: "review", status: "running", owner: owner(2) },
    ]);
    const plan = await planRecovery(s, classify({ 1: "alive", 2: "alive_unconfirmed" }));
    expect(plan.changed).toBe(false);
    expect(plan.nextState.state).toBe("REVIEWING");
  });

  it("a dead CHECK operation yields ownership-unresolved + possible orphans with command lines", async () => {
    const s = stateWith([
      { operation_id: "chk", kind: "checks", status: "running", owner: owner(9), command_lines: ["npm test"] },
    ]);
    const plan = await planRecovery(s, classify({ 9: "dead" }));
    expect(plan.ownershipUnresolved).toHaveLength(1);
    expect(plan.ownershipUnresolved[0]?.command_lines).toContain("npm test");
    expect(plan.possibleOrphans).toHaveLength(1);
  });

  it("schedules a recorded live child for tree-kill", async () => {
    const s = stateWith([
      { operation_id: "chk", kind: "checks", status: "running", owner: owner(9), child: { pid: 4242, startedAtMs: 1, commandLine: "node runner" } },
    ]);
    const plan = await planRecovery(s, classify({ 9: "dead" }));
    expect(plan.childrenToKill).toEqual([{ pid: 4242, startedAtMs: 1, commandLine: "node runner" }]);
  });

  it("does not downgrade a terminal run state", async () => {
    const s = stateWith([{ operation_id: "op1", kind: "review", status: "running", owner: owner(1) }], "CLOSED");
    const plan = await planRecovery(s, classify({ 1: "dead" }));
    expect(plan.nextState.operations[0]?.status).toBe("interrupted");
    expect(plan.nextState.state).toBe("CLOSED");
  });

  it("treats a running op with no recorded owner as interrupted", async () => {
    const s = stateWith([{ operation_id: "op1", kind: "prepare", status: "running" }]);
    const plan = await planRecovery(s, classify({}));
    expect(plan.interrupted).toEqual(["op1"]);
  });
});

describe("owner liveness by start time (plan §15.4)", () => {
  const T = 1_700_000_000_000;
  const deps = (start: number | null, alive = true) => ({ pidAlive: () => alive, startTimeOf: async () => start, toleranceMs: 2000 });
  const owner = { serverInstanceId: "s", pid: 4242, startedAtMs: T };
  it("a process created BEFORE its recorded start is the owner, however slow its start was (a server records now minus uptime)", async () => {
    expect(await classifyOwnerLiveness(owner, deps(T - 6000))).toBe("alive");
    expect(await classifyOwnerLiveness(owner, deps(T + 1500))).toBe("alive"); // clock granularity
  });
  it("a process created after the recorded start (beyond the tolerance) holds a reused PID; a gone PID is dead; an unreadable start is never dead", async () => {
    expect(await classifyOwnerLiveness(owner, deps(T + 2500))).toBe("dead");
    expect(await classifyOwnerLiveness(owner, deps(T, false))).toBe("dead");
    expect(await classifyOwnerLiveness(owner, deps(null))).toBe("alive_unconfirmed");
  });
});

describe("applyRecovery flags only a dead check operation's own worktree lock (D-31)", () => {
  // A check operation registered while a bounded read held the lock waits for it inside the
  // operation; if its server dies then, it never held the lock and must not flag the reader's.
  const plan = (): RecoveryPlan => ({
    changed: false,
    nextState: stateWith([]),
    interrupted: [],
    ownershipUnresolved: [
      { operation_id: "chk-dead", kind: "checks", command_lines: ["npm test"] },
      { operation_id: "chk-other", kind: "checks", command_lines: ["make other"] },
    ],
    possibleOrphans: [],
    childrenToKill: [],
    reviewOrphans: [],
  });
  const lockOf = (operationId: string, kind: string) => JSON.stringify({ owner: owner(5), operation_id: operationId, kind, acquired_at: new Date().toISOString(), heartbeat_at: new Date().toISOString() });

  it("leaves a lock held by someone else (a status read) as it is", async () => {
    const dir = await mkdtemp(join(tmpdir(), "arl-recovery-"));
    try {
      const lockPath = join(dir, "wt.lock");
      await writeFile(lockPath, lockOf("status-1", "capture"));
      await applyRecovery({} as RunPaths, owner(1), plan(), lockPath);
      const info = await readWorktreeLock(lockPath);
      expect(info?.operation_id).toBe("status-1");
      expect(info?.ownership_unresolved).toBeUndefined();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("flags the dead check operation's own lock ownership_unresolved, with its command lines only", async () => {
    const dir = await mkdtemp(join(tmpdir(), "arl-recovery-"));
    try {
      const lockPath = join(dir, "wt.lock");
      await writeFile(lockPath, lockOf("chk-dead", "checks"));
      await applyRecovery({} as RunPaths, owner(1), plan(), lockPath);
      const info = await readWorktreeLock(lockPath);
      expect(info?.ownership_unresolved).toBe(true);
      expect(info?.command_lines).toEqual(["npm test"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  // The recovery event (an append-only audit record) reports unresolved worktree ownership only
  // for a lock that a dead check operation held, not for one that was still waiting.
  const recoverRun = async (lockContent: string) => {
    const dir = await mkdtemp(join(tmpdir(), "arl-recovery-"));
    const paths = runPaths(dir, "repokey", "run-1");
    const meta: RunMeta = { schema_version: 1, run_id: "run-1", created_at: new Date().toISOString(), repository_root: dir, versions: { node: process.version }, scope: { allowed_snapshot: [dir], client_roots_snapshot: [] } };
    await createRun(paths, meta, stateWith([{ operation_id: "chk-dead", kind: "checks", status: "running", owner: owner(9), command_lines: ["npm test"] }], "CHECKING"));
    const lockPath = join(dir, "wt.lock");
    await writeFile(lockPath, lockContent);
    const recovered = await planRecovery(await readState(paths), classify({}));
    await applyRecovery(paths, selfOwner(), recovered, lockPath);
    const state = await readState(paths);
    const lock = await readWorktreeLock(lockPath);
    await rm(dir, { recursive: true, force: true });
    return { summary: state.events.at(-1)?.summary, operation: state.operations[0]?.status, lock };
  };

  it("a dead check operation that was still waiting (a read holds the lock) is recovered without reporting unresolved ownership", async () => {
    const r = await recoverRun(lockOf("status-1", "capture"));
    expect(r.operation).toBe("interrupted");
    expect(r.summary).toBe("recovered 1 interrupted operation(s)");
    expect(r.lock?.ownership_unresolved).toBeUndefined();
  });

  it("a dead check operation that held the lock is reported as unresolved ownership, also when the lock was already flagged", async () => {
    const own = await recoverRun(lockOf("chk-dead", "checks"));
    expect(own.summary).toBe("recovered 1 interrupted operation(s); 1 worktree ownership unresolved");
    expect(own.lock?.ownership_unresolved).toBe(true);
    const flagged = await recoverRun(JSON.stringify({ ...JSON.parse(lockOf("chk-dead", "checks")), ownership_unresolved: true }));
    expect(flagged.summary).toBe("recovered 1 interrupted operation(s); 1 worktree ownership unresolved");
    expect(flagged.lock?.ownership_unresolved).toBe(true);
  });
});

describe("recovery run by a server does not query the liveness of its own instance's operations", () => {
  // That server is running, so their owner is alive. Other owners are still classified.
  const asking = () => {
    const asked: string[] = [];
    const classify = async (o: OwnerRecord): Promise<Liveness> => {
      asked.push(o.serverInstanceId);
      return "dead";
    };
    return { asked, classify };
  };

  it("an owner of this server instance is alive without a query; any other owner is classified", async () => {
    const q = asking();
    const s = stateWith([
      { operation_id: "mine", kind: "checks", status: "running", owner: owner(1) },
      { operation_id: "theirs", kind: "prepare", status: "running", owner: owner(2) },
    ]);
    const plan = await planRecovery(s, aliveIfOwnInstance(owner(1), q.classify));
    expect(q.asked).toEqual(["s2"]);
    expect(plan.interrupted).toEqual(["theirs"]);
  });

  it("stop_review_loop's recovery (recoverRun) applies it with this server's owner", async () => {
    const dir = await mkdtemp(join(tmpdir(), "arl-recovery-"));
    try {
      const self = selfOwner();
      const paths = runPaths(dir, "repokey", "run-1");
      const meta: RunMeta = { schema_version: 1, run_id: "run-1", created_at: new Date().toISOString(), repository_root: dir, versions: { node: process.version }, scope: { allowed_snapshot: [dir], client_roots_snapshot: [] } };
      await createRun(paths, meta, stateWith([
        { operation_id: "mine", kind: "checks", status: "running", owner: self },
        { operation_id: "theirs", kind: "prepare", status: "running", owner: owner(2) },
      ]));
      const q = asking();
      await operations.recoverRun({ env: { owner: self, testHooks: { classify: q.classify } }, dataHome: dir } as unknown as Loaded, { paths, meta } as unknown as RunHandle);
      expect(q.asked).toEqual(["s2"]);
      expect((await readState(paths)).operations.map((o) => [o.operation_id, o.status])).toEqual([
        ["mine", "running"],
        ["theirs", "interrupted"],
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
