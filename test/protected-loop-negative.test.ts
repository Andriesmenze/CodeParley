// P3.4C-2: the negative security tests of the protected loop authority (proposal §6, contract §2–§7), with the
// TD's correction of the Inc 9 escalation (contract revision delta 4: automation requests are bound to the bound
// session AND its process).
//
// The custodian is enforced SEPARATELY per account, as on Windows: two account-bound SimulatedCustodianTransports
// over ONE shared ledger, each reaching only its own pipe (the modelled OS pipe DACLs; P3.4C-1). The session's
// server and hooks run as the IMPLEMENTER account; the operator's elevated terminal reaches only the OPERATOR
// pipe. The process CONNECTED to the pipe — the OS fact the custodian checks an automation request against — is
// modelled independently of every request field (helpers/continuation-fixture.ts treeCheck): a simulated host
// session's hooks run inside that session's Claude process tree; a test sending straight to the pipe is, by
// default, a same-user process outside every Claude Code session, or the process tree it names.
//
// A "same-user process" is modelled two ways: it edits the user-writable store (state.json, the session index),
// and it sends its own requests straight to the implementer pipe, bypassing the engine. What it must NOT be able
// to do (no effect on protected automation; fail-closed when the custodian is down): (1) bind, re-bind or drive
// the loop as another session — including through a forged local binding or a spoofed session id; (2) reset or
// extend budgets/deadline by editing the store; (3) over-spend a continuation or a wake; (4) revive a stale wake
// or continuation through the epoch; (5) resurrect an ended loop; (6) flip protected-vs-attended selection;
// (7) use a used, expired, wrong or foreign bind nonce; (8) cross the operator/implementer surfaces or read
// operator-only fields. What it CAN do, by design: REDUCE automation (pause or end the loop).
//
// RESIDUAL (D7, documented in test 1e): the session id is the client's claim and the process check is correlation,
// not authentication. A process INSIDE the bound session's own Claude process tree (the session's own tool
// commands, which inherit CLAUDE_PID; or a child a same-user process starts under the Claude process with a
// substituted parent) naming the bound session passes both checks — still only within the custodian's budgets,
// epoch and deadline. Closing that is the later operator/implementer authentication gate (L2/L3), not P3.4C-2.

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SimulatedCustodianTransport } from "../src/custodian/transport.js";
import type { SimLoop, SimProcessCheck } from "../src/custodian/simulated-loops.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { custodianDerivationOf } from "../src/custodian/grants.js";
import { CustodianLoops, type LoopTarget, type LoopTransitionOutcome } from "../src/custodian/loops.js";
import type { CustodianSurface, LoopTransitionFields, LoopTransitionKind } from "../src/custodian/protocol.js";
import { findRun } from "../src/engine/engine-env.js";
import { uuidv7 } from "../src/common/ids.js";
import { currentHandle, readCustodianLoop } from "../src/engine/custodian-loop.js";
import { sessionIndexPath, startLoop } from "../src/engine/continuation.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { EngineTestHooks, RunHandle } from "../src/engine/engine-env.js";
import { SESSION_INDEX_SCHEMA, type CustodianLoop } from "../src/schemas/continuation.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output, type FakeScenario } from "./helpers/review-fixture.js";
import { cli, contFixture, HostSession, inProcessTreeOf, loopOf, newRun, operatorIo, protectConfig, runChecks, startReview, treeCheck, waitForWake, writeRepoFile, type ContFixture } from "./helpers/continuation-fixture.js";

interface Separated {
  f: ContFixture;
  /** The implementer account (the session's server and hooks): reaches ONLY the implementer pipe. */
  implT: SimulatedCustodianTransport;
  /** The operator account (an elevated terminal): reaches ONLY the operator pipe. */
  opT: SimulatedCustodianTransport;
  /** The operator CLI's hooks (its own transport). */
  opHooks: EngineTestHooks;
  /** A CLI run from the implementer account (a terminal that is not the elevated operator). */
  implHooks: EngineTestHooks;
  dir: string;
}

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function separated(scenario: FakeScenario = okScenario(output({ findings: [] }))): Promise<Separated> {
  const f = await contFixture(scenario);
  const dir = mkdtempSync(join(tmpdir(), "cp-loopneg-"));
  dirs.push(dir);
  const statePath = join(dir, "custodian.json");
  const now = (): number => f.clock.now ?? Date.now();
  // The custodian checks the CLAUDE_PID a bind or re-bind names itself; here it reaches the fixture's verdicts.
  const processCheck = (pid: number | null): SimProcessCheck =>
    pid === null || f.unverifiable.has(pid)
      ? { pid, startedAtMs: null, clientPid: process.pid, verified: false, detail: pid === null ? "CLAUDE_PID was not supplied for the hook" : "the start time could not be read (test)" }
      : { pid, startedAtMs: 1_000, clientPid: process.pid, verified: true, detail: `test process ${pid}` };
  // An automation request's connected process, checked against the bound one (the OS fact, never a field).
  const clientCheck = (bound: Parameters<typeof treeCheck>[0]) => treeCheck(bound, f);
  // P3.4C-3: a run's evidence requests (op_begin, respond) a test makes without naming a process tree are the model's
  // own tool calls through the session's MCP server (the shared fixture's default).
  const runClientCheck = (bound: Parameters<typeof treeCheck>[0]) => treeCheck(bound, f, true);
  // P3.4C-5 Increment 3: the custodian measures checks and derives through its (in-process) helper; these tests are
  // about the loop's authority, not progress, so every derivation reports moved work facts.
  const helper = { exportsRoot: join(dir, "exports"), mode: "auto" as const, measure: "auto" as const, gitExe: f.git, freshProgress: true };
  const implT = new SimulatedCustodianTransport({ account: "implementer", statePath, now, processCheck, clientCheck, runClientCheck, helper });
  const opT = new SimulatedCustodianTransport({ account: "operator", statePath, now, processCheck, clientCheck, runClientCheck, helper });
  const hooks = f.le.env.testHooks!;
  hooks.custodian = { platform: "win32", transport: implT };
  return { f, implT, opT, dir, opHooks: { ...hooks, custodian: { platform: "win32", transport: opT } }, implHooks: { ...hooks, custodian: { platform: "win32", transport: implT } } };
}

/** The operator grants `loops` loops from the elevated terminal (the operator pipe). */
async function opGrant(s: Separated, loops: number): Promise<void> {
  await protectConfig(s.f, s.opHooks); // P3.4C-4: the repository's protected configuration, imported by the operator first
  const r = await cli(s.f, ["loop", "allow", "--repo", s.f.repo, "--loops", String(loops), "--minutes", "60"], operatorIo("allow", true, s.opHooks));
  expect(r.code, r.err).toBe(0);
}

/** The custodian's own record of the run's loop (ground truth; the test reads the shared ledger). */
function ledgerLoop(s: Separated, run: RunHandle): SimLoop {
  const l = s.implT.snapshot().loops.find((x) => x.runId === run.runId);
  if (!l) throw new Error(`the custodian holds no loop for run ${run.runId}`);
  return l;
}

const consumedLoops = (s: Separated): number => s.implT.snapshot().grants.reduce((n, g) => n + g.loopsUsed, 0);

/**
 * P3.4C-5 Increment 3 (§5.2): a spend or a wake consumption names the custodian's derivation. A test's direct request
 * that names none is given a fresh one, read just before it is sent — and the same one again when the request id is
 * re-sent, so a replay stays a replay.
 */
class DerivingLoops extends CustodianLoops {
  constructor(private readonly s: Separated) {
    super(s.implT);
  }

  override async transition<K extends LoopTransitionKind>(surface: CustodianSurface, target: LoopTarget, kind: K, fields: LoopTransitionFields[K], requestId: string = uuidv7()): Promise<LoopTransitionOutcome> {
    if ((kind === "spend_continuation" || kind === "wake_consume") && !("derivation_id" in (fields as object))) {
      const sent = derivationsSent.get(this.s) ?? new Map<string, string>();
      derivationsSent.set(this.s, sent);
      const id = sent.get(requestId) ?? (await freshDerivation(this.s, target));
      if (id) sent.set(requestId, id);
      return super.transition(surface, target, kind, { ...fields, ...(id ? { derivation_id: id } : {}) }, requestId);
    }
    return super.transition(surface, target, kind, fields, requestId);
  }
}

const derivationsSent = new WeakMap<Separated, Map<string, string>>();

/** The custodian's current derivation of the target's run (its id, or null when it is unavailable). */
async function freshDerivation(s: Separated, target: LoopTarget): Promise<string | null> {
  const run = await findRun(s.f.le, target.runId).catch(() => null);
  if (!run) return null;
  const d = await custodianDerivationOf(s.implT, "implementer", target.repositoryRoot, target.runId, await readFile(run.paths.runJson)).catch(() => null);
  return d?.available ? d.derivationId : null;
}

/** A same-user process on the implementer pipe, bypassing the engine (outside every Claude process tree unless
 * the call runs under inProcessTreeOf). */
const pipe = (s: Separated): CustodianLoops => new DerivingLoops(s);

/** The same, run from inside the tree of the Claude process `claudePid`. */
const inTree = <T>(claudePid: number, fn: () => Promise<T>): Promise<T> => inProcessTreeOf(claudePid, fn);

/** The loop as the implementer projection shows it now, and a request target at its current epoch/revision. */
async function at(s: Separated, run: RunHandle): Promise<{ c: CustodianLoop; t: LoopTarget }> {
  const c = await readCustodianLoop(s.f.le, run);
  if (!c) throw new Error("not protected");
  return { c, t: { repositoryRoot: run.meta.repository_root, runId: run.runId, loopId: c.loopId, epoch: c.epoch, baseLoopRevision: c.loopRevision } };
}

/** A same-user store edit: the run's local loop record and a session index now name `sessionId` (process `pid`). */
async function forgeBinding(s: Separated, run: RunHandle, sessionId: string, pid: number): Promise<void> {
  const st = await commitState(run.paths, s.f.le.env.owner, (cur) => {
    const loop = cur.continuation!;
    loop.binding = { ...loop.binding!, session_id: sessionId, state: "live", process: { pid, started_at_ms: 1_000, verified: true, detail: `forged ${pid}` } };
    return cur;
  });
  await forgeSessionIndex(s, run, sessionId, st.continuation!.loop_id);
}

async function forgeSessionIndex(s: Separated, run: RunHandle, sessionId: string, loopId: string): Promise<void> {
  await writeFile(sessionIndexPath(s.f.dataHome, sessionId), JSON.stringify({ schema: SESSION_INDEX_SCHEMA, session_id: sessionId, run_id: run.runId, repo_key: run.repoKey, loop_id: loopId, updated_at: new Date().toISOString() }));
}

/** The implementer projection's keys (GrantLedger.Loops.cs ImplementerLoopProjection; contract §6). */
const IMPLEMENTER_KEYS = ["binding", "deadlineAt", "ended", "epoch", "grantId", "grantUse", "limits", "loopId", "loopRevision", "operations", "pause", "progress", "remaining", "resumedAt", "startedAt", "status", "used", "wakeClaims"];

describe.skipIf(!supported)("P3.4C-2 protected loop authority: negative security tests (OS-separated custodian)", () => {
  it("1. binding: a second session can neither bind nor re-bind the loop — through its own hooks or straight on the pipe; first bind wins at the custodian", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    const A = new HostSession(s.f, "sess-A", 1111);
    const B = new HostSession(s.f, "sess-B", 2222);
    const { nonce, bound } = await A.startLoop(run);
    expect(bound).toBe("bound (epoch 1)");
    // B presents A's nonce through its own hook: the custodian refuses (first bind wins).
    expect((await B.bind(run.runId, nonce)).log).toContain("first binding wins");
    // The same request straight on the implementer pipe, no engine in the way: refused by the custodian.
    const { t } = await at(s, run);
    expect(await pipe(s).transition("implementer", t, "bind", { bindNonce: nonce!, session_id: "sess-B", process: { pid: 2222 } })).toMatchObject({ ok: false, code: "INVALID_LOOP_TRANSITION" });
    // A rebind naming B (whose process the custodian would verify): refused — a rebind never moves the binding.
    expect(await pipe(s).transition("implementer", t, "rebind", { session_id: "sess-B", process: { pid: 2222 } })).toMatchObject({ ok: false, code: "INVALID_LOOP_TRANSITION" });
    // A forged LOCAL binding for B, then B resumes: the custodian refuses to re-bind B, so B only pauses the loop.
    await forgeBinding(s, run, "sess-B", 2222);
    await B.sessionStart("resume");
    const l = ledgerLoop(s, run);
    expect(l.binding).toMatchObject({ sessionId: "sess-A", state: "live", process: { pid: 1111, verified: true } });
    expect(l.epoch).toBe(1);
    expect(l.events.map((e) => e.kind)).toEqual(["bind", "pause"]); // B's only effect: a pause (reduce-only)
    expect(l).toMatchObject({ status: "paused", pause: { reason: "process_identity", by: "implementer" } });
  });

  it("1b. a forged LOCAL binding moves nothing: the custodian refuses the other session's continuation and wake reservation, and its consumption of the bound session's claim (TD decision on the Inc 9 escalation)", async () => {
    const s = await separated(okScenario(output({ findings: [defect()] })));
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    // A same-user process names session B (another CodeParley-hooked Claude Code session) in the local cache, with
    // budgets of its own making: B's hooks now take the run for theirs.
    await forgeBinding(s, run, "sess-B", 2222);
    await commitState(run.paths, s.f.le.env.owner, (cur) => {
      cur.continuation!.limits.continuations = 50;
      return cur;
    });
    const B = new HostSession(s.f, "sess-B", 2222);
    // B's Stop: its hook asks for B's continuation; the custodian bound sess-A, so nothing is granted or spent.
    const stop = await B.stop(false);
    expect(stop.verdict).toBe("none");
    expect(stop.log).toContain("the request names a session the loop is not bound to");
    // B's wake reservation (a real review of the run): refused the same way.
    await runChecks(s.f, run);
    const review = await startReview(s.f, run);
    await review.done;
    expect(await B.arm(run.runId, review.operationId, "wB")).toMatchObject({ skip: expect.stringContaining("the request names a session the loop is not bound to") });
    // A claim the BOUND session reserved (from its own process tree): B's hook cannot consume it — not with its own
    // session id, nor with A's (B's process is not in A's tree); the claim stays A's.
    const { c, t } = await at(s, run);
    const armed = await inTree(1111, () => pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c)!, session_id: "sess-A" }));
    if (!armed.ok) throw new Error(`A's reservation was refused: ${armed.code}`);
    const claimId = String(armed.data["claimId"]);
    const { t: t2 } = await at(s, run);
    expect(await inTree(2222, () => pipe(s).wakeConsume("implementer", t2, claimId, "sess-B"))).toMatchObject({ dispatchAuthorized: false, refusal: "SESSION_NOT_BOUND" });
    expect(await inTree(2222, () => pipe(s).wakeConsume("implementer", t2, claimId, "sess-A"))).toMatchObject({ dispatchAuthorized: false, refusal: "PROCESS_IDENTITY_UNVERIFIED" });
    expect(await inTree(1111, () => pipe(s).wakeConsume("implementer", t2, claimId, "sess-A"))).toMatchObject({ dispatchAuthorized: true });
    // The custodian's record: A's binding, epoch 1, its own budget, nothing spent for B.
    const l = ledgerLoop(s, run);
    expect(l).toMatchObject({ status: "active", epoch: 1, limits: { continuations: 2 }, used: { continuations: 0, wakes: 1 }, binding: { sessionId: "sess-A", process: { pid: 1111 } } });
    expect(l.events.map((e) => e.kind)).toEqual(["bind", "wake_arm", "wake_consume"]);
  });

  it("1c. a spoofed bound session id is refused unless the request comes from the bound Claude process's tree; an ended or reused bound process and a missing session id are refused", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    let { c, t } = await at(s, run);
    const spend = { session_id: "sess-A" };
    // Outside every Claude Code session, naming the bound session: no continuation, no reservation.
    expect(await pipe(s).transition("implementer", t, "spend_continuation", spend)).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    expect(await pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c)!, session_id: "sess-A" })).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    // From another session's tree: naming the bound session fails the process check, naming its own the session check.
    expect(await inTree(2222, () => pipe(s).transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    expect(await inTree(2222, () => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-B" }))).toMatchObject({ ok: false, code: "SESSION_NOT_BOUND" });
    // The bound process ended, or its id now names a later process: refused even from "its" tree.
    s.f.gone.add(1111);
    expect(await inTree(1111, () => pipe(s).transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    s.f.gone.delete(1111);
    s.f.reused.add(1111);
    expect(await inTree(1111, () => pipe(s).transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    s.f.reused.delete(1111);
    // No session id at all: refused before anything is judged (the typed client cannot even send it).
    const raw = await s.implT.send("implementer", "loop_transition", { ...t, kind: "spend_continuation", fields: {} }, "no-session-1");
    expect(raw).toMatchObject({ ok: false, code: "INVALID_ARGUMENT" });
    expect(ledgerLoop(s, run).used).toEqual({ continuations: 0, wakes: 0 }); // none of these changed anything
    // The bound session's own tree, naming it: granted.
    ({ c, t } = await at(s, run));
    expect(await inTree(1111, () => pipe(s).transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: true, data: { continuationsUsed: 1 } });
    expect(c.status).toBe("active");
  });

  it("1d. past the budget, a refused caller cannot end the loop either: the binding checks come before any change", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    for (let i = 0; i < 2; i++) {
      const { t } = await at(s, run);
      expect(await inTree(1111, () => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-A" }))).toMatchObject({ ok: true });
    }
    const { t } = await at(s, run);
    const revision = ledgerLoop(s, run).loopRevision;
    expect(await inTree(2222, () => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-B" }))).toMatchObject({ ok: false, code: "SESSION_NOT_BOUND" });
    expect(await pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-A" })).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    expect(ledgerLoop(s, run)).toMatchObject({ status: "active", loopRevision: revision });
  });

  it("1e. RESIDUAL (D7, documented — not authentication): a process inside the bound session's own Claude tree that names the bound session passes, and is still held to the custodian's budgets", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    // E.g. the session's own tool commands (they inherit CLAUDE_PID and can learn the session id), or a child a
    // same-user process starts under the Claude process with a substituted parent: to the custodian, the same view.
    const insider = async (): Promise<unknown> => {
      const { t } = await at(s, run);
      return inTree(1111, () => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-A" }));
    };
    expect(await insider()).toMatchObject({ ok: true });
    expect(await insider()).toMatchObject({ ok: true });
    expect(await insider()).toMatchObject({ ok: false, code: "LOOP_BUDGET_EXHAUSTED" });
    expect(ledgerLoop(s, run)).toMatchObject({ status: "budget_exhausted", used: { continuations: 2 } });
  });

  it("2. editing the store's budgets, usage or deadline changes nothing: the custodian's values decide every Stop", async () => {
    const s = await separated();
    await opGrant(s, 2);
    const run = await newRun(s.f);
    const A = new HostSession(s.f, "sess-A", 1111);
    await A.startLoop(run);
    expect((await A.stop(false)).verdict).toBe("block");
    await writeRepoFile(s.f, "flag.txt", "changed\n");
    expect((await A.stop(true)).verdict).toBe("block");
    // The budget is spent. A same-user process resets it in the store: limits 50, usage 0, a year-long window.
    await commitState(run.paths, s.f.le.env.owner, (cur) => {
      const loop = cur.continuation!;
      loop.limits = { ...loop.limits, continuations: 50, run_seconds: 31_536_000 };
      loop.used = { continuations: 0, wakes: 0 };
      loop.deadline_at = new Date(Date.now() + 365 * 86_400_000).toISOString();
      return cur;
    });
    await writeRepoFile(s.f, "flag.txt", "changed again\n");
    const third = await A.stop(true);
    expect(third.verdict).toBe("none");
    expect(third.log).toContain("continuation budget is used up");
    expect(ledgerLoop(s, run)).toMatchObject({ status: "budget_exhausted", limits: { continuations: 2 }, used: { continuations: 2 } });
    expect(await loopOf(run)).toMatchObject({ status: "budget_exhausted", limits: { continuations: 2 }, used: { continuations: 2 } }); // the cache shows the custodian's values again

    // The deadline: a store edit extends the local window; past the custodian's window nothing continues.
    const run2 = await newRun(s.f, "deadline");
    const D = new HostSession(s.f, "sess-D", 3333);
    await D.startLoop(run2);
    await commitState(run2.paths, s.f.le.env.owner, (cur) => {
      cur.continuation!.deadline_at = new Date(Date.now() + 365 * 86_400_000).toISOString();
      return cur;
    });
    s.f.clock.now = Date.now() + 15 * 60_000 + 1_000;
    try {
      const late = await D.stop(false);
      expect(late.verdict).toBe("none");
      expect(late.log).toContain("automation window ended");
      expect((await loopOf(run2)).status).toBe("expired");
      // The custodian refuses every request past its deadline — even from the bound session — and records the
      // expiry itself.
      const { t } = await at(s, run2);
      expect(await inTree(3333, () => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-D" }))).toMatchObject({ ok: false, code: "LOOP_TERMINAL" });
      expect(ledgerLoop(s, run2)).toMatchObject({ status: "expired", used: { continuations: 0 }, ended: { reason: "run_seconds", by: "custodian" } });
    } finally {
      s.f.clock.now = null;
    }
  });

  it("3. over-spending is refused: even the bound session's own tree, naming it, can use the budgets up, never exceed them", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    const A = new HostSession(s.f, "sess-A", 1111);
    await A.startLoop(run);
    const P = pipe(s);
    const asA = <T>(fn: () => Promise<T>): Promise<T> => inTree(1111, fn);
    const handle = (h: string) => ({ operationHandle: h, session_id: "sess-A" });
    const spend = { session_id: "sess-A" };
    let { c, t } = await at(s, run);
    const op1 = currentHandle(c)!;
    // Wakes: reserved against the CURRENT custodian operation only; one per operation, two per run.
    expect(await asA(() => P.transition("implementer", t, "wake_arm", handle(op1)))).toMatchObject({ ok: true });
    ({ c, t } = await at(s, run));
    expect(await asA(() => P.transition("implementer", t, "wake_arm", handle(op1)))).toMatchObject({ ok: false, code: "LOOP_BUDGET_EXHAUSTED" });
    expect(await asA(() => P.transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: true, data: { continuationsUsed: 1 } });
    ({ c, t } = await at(s, run));
    expect(await asA(() => P.transition("implementer", t, "wake_arm", handle(op1)))).toMatchObject({ ok: false, code: "UNKNOWN_OPERATION_HANDLE" }); // an earlier operation
    expect(await asA(() => P.transition("implementer", t, "wake_arm", handle("op-invented")))).toMatchObject({ ok: false, code: "UNKNOWN_OPERATION_HANDLE" });
    expect(await asA(() => P.transition("implementer", t, "wake_arm", handle(currentHandle(c)!)))).toMatchObject({ ok: true });
    ({ c, t } = await at(s, run));
    const spendTarget = t;
    const spent = await asA(() => P.transition("implementer", spendTarget, "spend_continuation", spend, "spend-two"));
    expect(spent).toMatchObject({ ok: true, data: { continuationsUsed: 2 } });
    ({ c, t } = await at(s, run));
    expect(await asA(() => P.transition("implementer", t, "wake_arm", handle(currentHandle(c)!)))).toMatchObject({ ok: false, code: "LOOP_BUDGET_EXHAUSTED" }); // the run's two wakes
    // A replayed spend returns its stored answer and spends nothing more.
    expect(await asA(() => P.transition("implementer", spendTarget, "spend_continuation", spend, "spend-two"))).toEqual(spent);
    expect(ledgerLoop(s, run).used).toEqual({ continuations: 2, wakes: 2 });
    // Past the budget the custodian refuses and ends the loop itself; after that, the loop is terminal.
    expect(await asA(() => P.transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: false, code: "LOOP_BUDGET_EXHAUSTED" });
    ({ c, t } = await at(s, run));
    expect(c).toMatchObject({ status: "budget_exhausted", used: { continuations: 2, wakes: 2 } });
    expect(await asA(() => P.transition("implementer", t, "spend_continuation", spend))).toMatchObject({ ok: false, code: "LOOP_TERMINAL" });
    // The session's own Stop continues nothing more.
    expect((await A.stop(false)).verdict).toBe("none");
    expect(ledgerLoop(s, run).used).toEqual({ continuations: 2, wakes: 2 });
  });

  it("3b. the engine arms no wake past the custodian's count, whatever wake budget the store claims", async () => {
    const s = await separated(okScenario(output({ findings: [defect()] })));
    await opGrant(s, 1);
    const run = await newRun(s.f);
    const A = new HostSession(s.f, "sess-A", 1111);
    await A.startLoop(run);
    await runChecks(s.f, run);
    const review = await startReview(s.f, run);
    await review.done;
    // The run's two wakes are reserved (one per custodian operation) from the bound session's tree.
    const asA = <T>(fn: () => Promise<T>): Promise<T> => inTree(1111, fn);
    let { c, t } = await at(s, run);
    expect(await asA(() => pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c)!, session_id: "sess-A" }))).toMatchObject({ ok: true });
    ({ c, t } = await at(s, run));
    expect(await asA(() => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-A" }))).toMatchObject({ ok: true });
    ({ c, t } = await at(s, run));
    expect(await asA(() => pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c)!, session_id: "sess-A" }))).toMatchObject({ ok: true });
    // …and the store claims nine wakes, none used: the engine still judges arming on the custodian's count.
    await commitState(run.paths, s.f.le.env.owner, (cur) => {
      cur.continuation!.limits.wakes_per_run = 9;
      cur.continuation!.limits.wakes_per_operation = 9;
      cur.continuation!.used.wakes = 0;
      return cur;
    });
    const armed = await A.arm(run.runId, review.operationId, "w-forged");
    expect(armed).toMatchObject({ skip: expect.stringContaining("idle-wake budget of this run is used up") });
    expect(ledgerLoop(s, run).used.wakes).toBe(2);
  });

  it("4. the epoch is the custodian's: stale or raised epochs are refused, and a re-bind makes earlier wake claims dead for good", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    let { c, t } = await at(s, run);
    const arm = await inTree(1111, () => pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c)!, session_id: "sess-A" }));
    if (!arm.ok) throw new Error(`not armed: ${arm.code}`);
    const claimId = String(arm.data["claimId"]);
    // The session resumes in a new process: the custodian re-verifies it and advances the epoch.
    const A2 = new HostSession(s.f, "sess-A", 1112);
    expect((await A2.sessionStart("resume")).text).toContain("binding epoch 2");
    ({ c, t } = await at(s, run));
    expect(c.epoch).toBe(2);
    // The epoch-1 claim authorizes no dispatch, even from the re-bound session's own tree: at the current epoch,
    // at its own, or at a raised one.
    for (const epoch of [2, 1, 3]) {
      expect(await inTree(1112, () => pipe(s).wakeConsume("implementer", { ...t, epoch }, claimId, "sess-A"))).toMatchObject({ dispatchAuthorized: false, refusal: "STALE_LOOP_EPOCH" });
    }
    // Requests at a stale or a raised epoch: refused.
    expect(await inTree(1112, () => pipe(s).transition("implementer", { ...t, epoch: 1 }, "spend_continuation", { session_id: "sess-A" }))).toMatchObject({ ok: false, code: "STALE_LOOP_EPOCH" });
    expect(await inTree(1112, () => pipe(s).transition("implementer", { ...t, epoch: 99 }, "spend_continuation", { session_id: "sess-A" }))).toMatchObject({ ok: false, code: "STALE_LOOP_EPOCH" });
    // The old process (1111) is no longer the bound one: its tree is refused now.
    expect(await inTree(1111, () => pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-A" }))).toMatchObject({ ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" });
    // An edited local epoch changes nothing: the engine acts at the custodian's epoch.
    await commitState(run.paths, s.f.le.env.owner, (cur) => {
      cur.continuation!.binding!.epoch = 99;
      return cur;
    });
    expect((await A2.stop(false)).verdict).toBe("block");
    expect(ledgerLoop(s, run)).toMatchObject({ epoch: 2, used: { continuations: 1 } });
    expect(ledgerLoop(s, run).wakeClaims.find((w) => w.claimId === claimId)?.state).toBe("armed"); // never consumed
  });

  it("4b. a wake claim authorizes one dispatch at most: a replay of the consuming request, a new request or a consume after it authorize nothing", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    const asA = <T>(fn: () => Promise<T>): Promise<T> => inTree(1111, fn);
    let { c, t } = await at(s, run);
    const arm = await asA(() => pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c)!, session_id: "sess-A" }));
    if (!arm.ok) throw new Error(`not armed: ${arm.code}`);
    const claimId = String(arm.data["claimId"]);
    ({ c, t } = await at(s, run));
    const consumeTarget = t;
    expect(await asA(() => pipe(s).wakeConsume("implementer", consumeTarget, claimId, "sess-A", "consume-one"))).toMatchObject({ dispatchAuthorized: true, refusal: null });
    expect(await asA(() => pipe(s).wakeConsume("implementer", consumeTarget, claimId, "sess-A", "consume-one"))).toMatchObject({ dispatchAuthorized: false, refusal: "replayed" });
    ({ c, t } = await at(s, run));
    expect(await asA(() => pipe(s).wakeConsume("implementer", t, claimId, "sess-A"))).toMatchObject({ dispatchAuthorized: false, refusal: "WAKE_ALREADY_CONSUMED" });
    expect(await asA(() => pipe(s).wakeConsume("implementer", t, "wc-9-0000000000000000", "sess-A"))).toMatchObject({ dispatchAuthorized: false, refusal: "UNKNOWN_WAKE_CLAIM" });
    expect(ledgerLoop(s, run).wakeClaims.map((w) => w.state)).toEqual(["consumed"]);
    expect(c.status).toBe("active");
  });

  it("5. no resurrection: a stopped loop stays ended — no transition, no operator resume, no store edit and no new start revives it, and the run gets no second loop", async () => {
    const s = await separated();
    await opGrant(s, 2);
    const run = await newRun(s.f);
    const A = new HostSession(s.f, "sess-A", 1111);
    await A.startLoop(run);
    const stopped = await cli(s.f, ["loop", "stop", run.runId], operatorIo("", true, s.opHooks));
    expect(stopped.code, stopped.err).toBe(0);
    expect(stopped.out).toContain("the custodian cancelled the run's loop (operator surface)");
    expect(ledgerLoop(s, run)).toMatchObject({ status: "cancelled", ended: { by: "operator" } });
    // No transition leaves the terminal state, whatever it asks for — even from the bound session's tree.
    const { c, t } = await at(s, run);
    const attempts = await inTree(1111, () =>
      Promise.all([
        pipe(s).transition("implementer", t, "rebind", { session_id: "sess-A", process: { pid: 1111 } }),
        pipe(s).transition("implementer", t, "resume", {}),
        pipe(s).transition("implementer", t, "spend_continuation", { session_id: "sess-A" }),
        pipe(s).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c) ?? "op-none", session_id: "sess-A" }),
        pipe(s).transition("implementer", t, "pause", { reason: "user_interrupt" }),
        pipe(s).transition("implementer", t, "end", { status: "run_ended" }),
      ]),
    );
    for (const out of attempts) expect(out).toMatchObject({ ok: false, code: "LOOP_TERMINAL" });
    // A store edit marks the local loop active again: the operator's resume asks the custodian, which refuses…
    await commitState(run.paths, s.f.le.env.owner, (cur) => {
      cur.continuation!.status = "active";
      cur.continuation!.ended = null;
      return cur;
    });
    const resume = await cli(s.f, ["loop", "resume", run.runId], operatorIo("resume", true, s.opHooks));
    expect(resume.code).not.toBe(0);
    expect(resume.err).toContain("the custodian did not resume the loop");
    // …and the session's Stop takes the custodian's answer (and lays it back over the cache).
    expect((await A.stop(false)).verdict).toBe("none");
    expect((await loopOf(run)).status).toBe("cancelled");
    // A new start adopts the ended loop: nothing consumed, no second loop — even with a grant loop left. A direct
    // consume for the run is refused as terminal (contract §1: a run whose loop ended never gets another).
    const before = consumedLoops(s);
    expect(await startLoop(s.f.le, run)).toMatchObject({ existing: true, nonce: null, loop: { status: "cancelled" } });
    await expect(new CustodianGrants(s.implT).consume(run.meta.repository_root, run.runId)).rejects.toMatchObject({ code: "LOOP_TERMINAL" });
    expect(consumedLoops(s)).toBe(before);
    expect(ledgerLoop(s, run).status).toBe("cancelled");
  });

  it("6. protected-vs-attended is the custodian's answer: a forged local loop on an attended run automates nothing, and a protected run's loop cannot be swapped for a weaker one", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const prot = await newRun(s.f, "protected");
    const A = new HostSession(s.f, "sess-A", 1111);
    await A.startLoop(prot);
    const genuine = (await readState(prot.paths)).continuation!;

    // Forge-upgrade: an attended run (no custodian loop) gets a copied loop record, a session and the custodian flag.
    const attended = await newRun(s.f, "attended");
    await commitState(attended.paths, s.f.le.env.owner, (cur) => {
      cur.continuation = { ...structuredClone(genuine), limits: { ...genuine.limits, continuations: 50 }, binding: { ...genuine.binding!, session_id: "sess-X", process: { pid: 4444, started_at_ms: 1_000, verified: true, detail: "forged" } } };
      cur.user_records_custodian = true;
      return cur;
    });
    await forgeSessionIndex(s, attended, "sess-X", genuine.loop_id);
    const X = new HostSession(s.f, "sess-X", 4444);
    const sent = s.implT.received.length;
    const xs = await X.stop(false);
    expect(xs.verdict).toBe("none");
    expect(xs.log).toContain("the custodian holds no automation loop for this run");
    expect(await X.arm(attended.runId, "01999999-9999-7999-8999-999999999999", "x")).toMatchObject({ skip: expect.stringContaining("the custodian holds no automation loop") });
    expect(s.implT.received.slice(sent).map((r) => r.op)).toEqual(["list_user_records", "list_user_records"]); // asked; nothing spent or reserved
    const section = (await new CustodianGrants(s.implT).listUserRecords("implementer", attended.meta.repository_root, attended.runId)).loop;
    expect(section).toMatchObject({ protected: false, record: null });

    // Downgrade-substitution: the protected run's local loop is replaced by a weaker record (another loop id,
    // generous budgets, a long window, the custodian flag cleared) — the custodian's loop still decides.
    await commitState(prot.paths, s.f.le.env.owner, (cur) => {
      cur.continuation = { ...cur.continuation!, loop_id: "01999999-0000-7000-8000-000000000001", limits: { ...cur.continuation!.limits, continuations: 50 }, used: { continuations: 0, wakes: 0 }, deadline_at: new Date(Date.now() + 365 * 86_400_000).toISOString() };
      cur.user_records_custodian = false;
      return cur;
    });
    await forgeSessionIndex(s, prot, "sess-A", "01999999-0000-7000-8000-000000000001");
    for (let i = 0; i < 4; i++) {
      await writeRepoFile(s.f, "flag.txt", `substituted ${i}\n`);
      await A.stop(i > 0);
    }
    expect(ledgerLoop(s, prot)).toMatchObject({ loopId: genuine.loop_id, status: "budget_exhausted", limits: { continuations: 2 }, used: { continuations: 2 } });
    // Removing the local loop (and a forged legacy start marker) does not unprotect the run: a new start adopts the
    // custodian's loop and consumes nothing.
    await commitState(prot.paths, s.f.le.env.owner, (cur) => {
      delete cur.continuation;
      cur.loop_start = { request_id: "forged-start", loop_id: "forged-loop", started_at: new Date().toISOString(), status: "pending", detail: null };
      return cur;
    });
    const before = consumedLoops(s);
    expect(await startLoop(s.f.le, prot)).toMatchObject({ existing: true, loop: { loop_id: genuine.loop_id, status: "budget_exhausted" } });
    expect(consumedLoops(s)).toBe(before);
    expect((await readState(prot.paths)).loop_start).toBeUndefined();
  });

  it("7. a used, expired, wrong or foreign bind nonce binds nothing; a replayed bind is idempotent, never a second binding", async () => {
    const s = await separated();
    await opGrant(s, 3);
    const r1 = await newRun(s.f, "one");
    const { nonce: n1 } = await new HostSession(s.f, "sess-A", 1111).startLoop(r1);
    // The custodian hands the nonce out once and keeps its hash; nothing user-readable holds it.
    expect(JSON.stringify(await readState(r1.paths))).not.toContain(n1!);
    const { c: c1 } = await at(s, r1);
    expect(JSON.stringify(c1)).not.toContain(n1!);
    expect(c1).not.toHaveProperty("bindNonce");
    // Foreign (r1's used nonce on r2's unbound loop) and wrong (well-formed, not the custodian's): refused.
    const r2 = await newRun(s.f, "two");
    const s2 = await startLoop(s.f.le, r2);
    const { t: t2 } = await at(s, r2);
    const bindAs = (nonce: string, session: string, pid: number) => ({ bindNonce: nonce, session_id: session, process: { pid } });
    expect(await pipe(s).transition("implementer", t2, "bind", bindAs(n1!, "sess-B", 2222))).toMatchObject({ ok: false, code: "BIND_NONCE_INVALID" });
    expect(await pipe(s).transition("implementer", t2, "bind", bindAs("f".repeat(64), "sess-B", 2222))).toMatchObject({ ok: false, code: "BIND_NONCE_INVALID" });
    // Expired: a minute later the right nonce binds nothing, through the engine or on the pipe.
    s.f.clock.now = Date.now() + 61_000;
    try {
      expect((await new HostSession(s.f, "sess-B", 2222).bind(r2.runId, s2.nonce)).log).toContain("expired");
      expect(await pipe(s).transition("implementer", t2, "bind", bindAs(s2.nonce!, "sess-B", 2222))).toMatchObject({ ok: false, code: "BIND_NONCE_INVALID" });
    } finally {
      s.f.clock.now = null;
    }
    expect(ledgerLoop(s, r2)).toMatchObject({ status: "unbound", binding: null, bindNonce: { usedAt: null } });
    // Replay: a bind re-sent under its request id returns the stored answer (no new binding, epoch or revision);
    // the same id for another session is a conflict; a fresh request with the used nonce finds the loop bound.
    const r3 = await newRun(s.f, "three");
    const s3 = await startLoop(s.f.le, r3);
    const { t: t3 } = await at(s, r3);
    const body = bindAs(s3.nonce!, "sess-C", 3333);
    const first = await pipe(s).transition("implementer", t3, "bind", body, "bind-three");
    expect(first).toMatchObject({ ok: true, data: { status: "active", epoch: 1 } });
    const revision = ledgerLoop(s, r3).loopRevision;
    expect(await pipe(s).transition("implementer", t3, "bind", body, "bind-three")).toEqual(first);
    expect(ledgerLoop(s, r3).loopRevision).toBe(revision);
    expect(await pipe(s).transition("implementer", t3, "bind", { ...body, session_id: "sess-D" }, "bind-three")).toMatchObject({ ok: false, code: "REQUEST_ID_CONFLICT" });
    const { t: t3b } = await at(s, r3);
    expect(await pipe(s).transition("implementer", t3b, "bind", { ...body, session_id: "sess-D" })).toMatchObject({ ok: false, code: "INVALID_LOOP_TRANSITION" });
    expect(ledgerLoop(s, r3).binding).toMatchObject({ sessionId: "sess-C" });
  });

  it("8. the OS caller class decides: neither account reaches the other's pipe, the implementer cannot clear an operator-only pause, and its projection has no operator-only field", async () => {
    const s = await separated();
    await opGrant(s, 1);
    const run = await newRun(s.f);
    await new HostSession(s.f, "sess-A", 1111).startLoop(run);
    const repo = run.meta.repository_root;
    const { t } = await at(s, run);
    // Cross-account requests never reach the custodian (the modelled pipe DACLs): nothing is delivered.
    const sentImpl = s.implT.received.length;
    const sentOp = s.opT.received.length;
    await expect(new CustodianGrants(s.implT).listUserRecords("operator", repo, run.runId)).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    await expect(new CustodianLoops(s.implT).transition("operator", t, "resume", {})).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    await expect(new CustodianLoops(s.opT).transition("implementer", t, "spend_continuation", { session_id: "sess-A" })).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    expect([s.implT.received.length, s.opT.received.length]).toEqual([sentImpl, sentOp]);

    // An operator-only pause: the implementer may set it (it only reduces) but can never clear it — not by a resume,
    // a re-bind, or a weaker pause in its place.
    expect(await pipe(s).transition("implementer", t, "pause", { reason: "operator_action_required", detail: "test" })).toMatchObject({ ok: true });
    let { t: tp } = await at(s, run);
    expect(await pipe(s).transition("implementer", tp, "resume", {})).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    expect(await pipe(s).transition("implementer", tp, "rebind", { session_id: "sess-A", process: { pid: 1111 } })).toMatchObject({ ok: true, data: { status: "paused", pauseReason: "operator_action_required", epoch: 2 } });
    ({ t: tp } = await at(s, run));
    expect(await pipe(s).transition("implementer", tp, "pause", { reason: "user_interrupt" })).toMatchObject({ ok: false, code: "INVALID_LOOP_TRANSITION" });
    expect(await pipe(s).transition("implementer", tp, "resume", {})).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    // The CLI from the implementer account cannot resume it either; the elevated operator terminal can. (Since P3.4C-3
    // C1 the resume guard first reads the custodian's records on the operator surface, which this account cannot reach,
    // so the refusal comes before the custodian is asked to resume — the loop stays paused either way.)
    const notOperator = await cli(s.f, ["loop", "resume", run.runId], operatorIo("resume", true, s.implHooks));
    expect(notOperator.code).not.toBe(0);
    expect(notOperator.err).toMatch(/CALLER_NOT_AUTHORIZED|CUSTODIAN_UNAVAILABLE[^\n]*cannot reach the operator pipe/);
    expect(ledgerLoop(s, run)).toMatchObject({ status: "paused", pause: { reason: "operator_action_required" } });
    const operator = await cli(s.f, ["loop", "resume", run.runId], operatorIo("resume", true, s.opHooks));
    expect(operator.code, operator.err).toBe(0);
    expect(ledgerLoop(s, run)).toMatchObject({ status: "active", pause: null });

    // Projections: the implementer gets the structural allowlist; the operator the full record.
    const impl = (await new CustodianGrants(s.implT).listUserRecords("implementer", repo, run.runId)).loop!.record!;
    const full = (await new CustodianGrants(s.opT).listUserRecords("operator", repo, run.runId)).loop!.record!;
    expect(Object.keys(impl).sort()).toEqual(IMPLEMENTER_KEYS);
    expect(impl["binding"]).toEqual({ state: "live", verified: true });
    for (const k of ["bindNonce", "events", "requestId", "repoKey", "runId"]) {
      expect(impl).not.toHaveProperty(k);
      expect(full).toHaveProperty(k);
    }
    expect(full["binding"]).toMatchObject({ sessionId: "sess-A", process: { pid: 1111, verified: true } });
    expect(JSON.stringify(impl)).not.toContain("sess-A");
  });

  it("fail-closed: with the custodian stopped nothing automates — no start, no bind, no continuation, no wake — and nothing reads as unprotected", async () => {
    const s = await separated(okScenario(output({ findings: [defect()] }), { sleep_ms: 4_000 }));
    await opGrant(s, 2);
    const run = await newRun(s.f);
    const A = new HostSession(s.f, "sess-A", 1111);
    await A.startLoop(run);
    await runChecks(s.f, run);
    const review = await startReview(s.f, run);
    const armed = await A.arm(run.runId, review.operationId, "w1");
    if (!("armed" in armed)) throw new Error(`not armed: ${JSON.stringify(armed)}`);
    expect((await A.stop(false)).verdict).toBe("none"); // a review is running: the turn ends, no continuation
    const run2 = await newRun(s.f, "while down");
    // The custodian stops while Codex reviews — after the engine took up the custodian's capture (the review record
    // exists only then). A capture the engine has not yet seen is waited for, bounded, across an outage (P3.4C-5 §3).
    for (const end = Date.now() + 30_000; (await readState(run.paths)).reviews.length === 0 && Date.now() < end; ) await new Promise((r) => setTimeout(r, 50));
    s.implT.setUnavailable("the custodian service is stopped");
    s.opT.setUnavailable("the custodian service is stopped");
    try {
      // The finished review's wake: the waiter's cheap poll is local, but only the custodian authorizes a dispatch.
      await review.done;
      expect((await waitForWake(A, armed.armed)).state).toBe("ready");
      const woke = await A.consume(armed.armed);
      expect(woke.wake).toBe(false);
      // A Stop pauses automation (operator_action_required) and continues nothing.
      await writeRepoFile(s.f, "flag.txt", "progress while down\n");
      const stop = await A.stop(false);
      expect(stop.verdict).toBe("none");
      expect(stop.log).toContain("fail-closed");
      expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "operator_action_required" } });
      // No start and no bind; nothing is minted locally and the run is not treated as unprotected.
      await expect(startLoop(s.f.le, run2)).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
      expect((await readState(run2.paths)).continuation).toBeUndefined();
      expect((await new HostSession(s.f, "sess-B", 2222).bind(run2.runId, "a".repeat(64))).log).toContain("could not be asked");
      // Neither the operator's resume nor its stop is recorded by anything but the custodian.
      const resume = await cli(s.f, ["loop", "resume", run.runId], operatorIo("resume", true, s.opHooks));
      expect(resume.code).not.toBe(0);
      const stopCli = await cli(s.f, ["loop", "stop", run.runId], operatorIo("", true, s.opHooks));
      expect(stopCli.out).toContain("the custodian did NOT record the cancellation");
    } finally {
      s.implT.setUnavailable(null);
      s.opT.setUnavailable(null);
    }
    // Back up: the custodian's record shows exactly what it authorized — one claim reserved, none consumed, no spend.
    expect(ledgerLoop(s, run)).toMatchObject({ status: "active", used: { continuations: 0, wakes: 1 } });
    expect(ledgerLoop(s, run).wakeClaims.map((w) => w.state)).toEqual(["armed"]);
  }, 60_000);
});
