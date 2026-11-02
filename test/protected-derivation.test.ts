// P3.4C-5 Increment 3 (contract §5, §9): the protected derivation and its enforcement, over the custodian's in-process
// helper measurement (the helper's own `derive` workload: it measures the real repository) — not a synthetic one.
//
// N5-5  — on an honest run the custodian's derivation routes and completes as the engine's own derivation of the same
//         run does (the derivation core is single-sourced; the snapshot parity of the real and the simulated custodian is
//         the run corpus's: test/custodian-run.contract.test.ts).
// N5-15 — genuine work between two Stops (the source changed) earns the second continuation.
// N5-17 — a repository change after the derivation, with no custodian record revised, makes the derivation stale for a
//         spend and for a wake consumption: the custodian measures again before it spends.
// Forged derivations — an unknown id, another run's derivation, and a route claimed in the request authorize nothing.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { readState } from "../src/store/state-store.js";
import { CustodianLoops, type LoopTarget } from "../src/custodian/loops.js";
import { currentHandle, readCustodianLoop } from "../src/engine/custodian-loop.js";
import { routeRun } from "../src/engine/continuation.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output, setScenario, type FakeScenario } from "./helpers/review-fixture.js";
import { cli, contFixture, grant, HostSession, inProcessTreeOf, newRun, NODE, operatorIo, reviewCtx, runChecks, startReview, writeRepoFile, type ContFixture } from "./helpers/continuation-fixture.js";
import { approve } from "./helpers/checks-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { startChecksOperation, stopRun } from "../src/engine/operations.js";

const SESSION = "sess-derive";
const PID = 7401;

async function protectedRun(f: ContFixture, goal?: string): Promise<RunHandle> {
  const run = await newRun(f, goal);
  await grant(f, 1);
  await new HostSession(f, SESSION, PID).startLoop(run);
  return run;
}

async function target(f: ContFixture, run: RunHandle): Promise<LoopTarget> {
  const c = await readCustodianLoop(f.le, run);
  if (!c) throw new Error("not protected");
  return { repositoryRoot: run.meta.repository_root, runId: run.runId, loopId: c.loopId, epoch: c.epoch, baseLoopRevision: c.loopRevision };
}

interface Derivation {
  available: boolean;
  derivationId: string;
  route: { code: string; kind: string };
  completion: { state: string };
  progressFingerprint: string;
  code?: string;
}

async function derive(f: ContFixture, run: RunHandle): Promise<Derivation> {
  const runJson = (await readFile(run.paths.runJson)).toString("base64");
  const res = await f.custodian.send("implementer", "list_user_records", { repositoryRoot: run.meta.repository_root, runId: run.runId, sections: ["derivation"], runJson }, `derive-${Date.now()}-${Math.random()}`);
  if (!res.ok) throw new Error(`${res.code}: ${res.error}`);
  return res.data?.["derivation"] as unknown as Derivation;
}

/** The engine's own derivation of the same run (its held user records laid over its local state). */
async function engineDerivation(f: ContFixture, run: RunHandle) {
  const view = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
  const r = await routeRun(f.le, run, view);
  return { route: r.route, completion: r.report.completion.state };
}

function spend(f: ContFixture, t: LoopTarget, fields: Record<string, unknown>) {
  return inProcessTreeOf(PID, () => new CustodianLoops(f.custodian).transition("implementer", t, "spend_continuation", { session_id: SESSION, ...fields } as { session_id: string }));
}

const used = (f: ContFixture, run: RunHandle) => f.custodian.snapshot().loops.find((l) => l.runId === run.runId)!.used;

/** Wait (bounded) until the custodian holds the run's latest operation of `kind` in `status`. */
async function custodianOpIs(f: ContFixture, run: RunHandle, kind: string, status: string): Promise<void> {
  for (const end = Date.now() + 30_000; Date.now() < end; await new Promise((r) => setTimeout(r, 100))) {
    const op = f.custodian.snapshot().runs.find((r) => r.runId === run.runId)?.operations.filter((o) => o.kind === kind).at(-1);
    if (op?.status === status) return;
  }
  throw new Error(`the custodian never held a ${kind} operation ${status}`);
}

/** The repository's required check replaced (before the run is protected: the operator imports it then). */
const requireCheck = (argv: string[]) => async (f: ContFixture): Promise<void> => {
  await approve(f, { checks: { unit: { argv: [NODE, ...argv] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
};

const ADD = "add() subtracts";

/** A dispute of the finding (the implementer's response), with a reference so the reviewer can weigh it. */
async function dispute(f: ContFixture, run: RunHandle, rationale: string): Promise<void> {
  const ctx = await reviewCtx(f, run);
  const it = await itemNow(ctx, ADD);
  await respond(ctx, { responses: [{ finding_id: it.id, response_token: it.token!, disposition: "disputed", rationale, references: [{ path: "src/math.js", start_line: 1 }] }] });
}

type ParityState = [string, FakeScenario, (f: ContFixture, run: RunHandle) => Promise<{ inFlight: Promise<unknown> } | void>, ((f: ContFixture) => Promise<void>)?];

describe.skipIf(!supported)("P3.4C-5 N5-5 — the custodian's derivation of an honest run is the engine's", () => {
  // Every route the engine's router produces on a protected run that a session can reach (run_ended, await_review,
  // wait_for_operation, operation_unsuccessful, user_decision_required, fix_checks, address_findings, run_checks,
  // request_review, ready) and every completion state those runs pass through.
  const states: ParityState[] = [
    ["a new run (the floor first)", okScenario(output({ findings: [] })), async () => undefined],
    ["checks run (a review next)", okScenario(output({ findings: [] })), async (f, run) => runChecks(f, run)],
    ["a review with a finding (the implementer addresses it)", okScenario(output({ findings: [defect()] })), async (f, run) => {
      await runChecks(f, run);
      await (await startReview(f, run)).done;
    }],
    ["a clean review (ready: the loop ends)", okScenario(output({ findings: [] })), async (f, run) => {
      await runChecks(f, run);
      await (await startReview(f, run)).done;
    }],
    ["a failed review (automation pauses)", okScenario(output(), { turn: "failed", turn_failed_message: "model error" }), async (f, run) => {
      await runChecks(f, run);
      await (await startReview(f, run)).done;
    }],
    // P3.4C-5 Increment 4: the remaining routes and completion states.
    ["a stopped run (automation ends: run_ended)", okScenario(output({ findings: [] })), async (f, run) => {
      await runChecks(f, run);
      await stopRun(f.le, run, "abort", undefined, "parity", 10_000);
    }],
    ["a review running (the session awaits it)", okScenario(output({ findings: [] }), { sleep_ms: 8000 }), async (f, run) => {
      await runChecks(f, run);
      const r = await startReview(f, run);
      await custodianOpIs(f, run, "review", "captured");
      return { inFlight: r.done };
    }],
    ["checks running (the session waits for them)", okScenario(output({ findings: [] })), async (f, run) => {
      const s = await startChecksOperation(f.le, run, {});
      await custodianOpIs(f, run, "checks", "running");
      return { inFlight: s.completion };
    }, requireCheck(["scripts/sleep.js", "8000"])],
    ["a failing required check (fix it)", okScenario(output({ findings: [] })), async (f, run) => {
      await writeRepoFile(f, "flag.txt", "bad\n");
      await runChecks(f, run);
    }, requireCheck(["scripts/flag.js"])],
    ["a review gone stale after a fix (the checks again)", okScenario(output({ findings: [defect()] })), async (f, run) => {
      await runChecks(f, run);
      await (await startReview(f, run)).done;
      await writeRepoFile(f, "src/math.js", "export const add = (a, b) => a + b;\n");
    }],
    ["a disputed finding (the reviewer weighs it next)", okScenario(output({ findings: [defect()] })), async (f, run) => {
      await runChecks(f, run);
      await (await startReview(f, run)).done;
      await dispute(f, run, "Subtraction is intended here.");
    }],
    ["an escalated thread (a user decision: automation pauses)", okScenario(output({ findings: [defect()] })), async (f, run) => {
      await runChecks(f, run);
      await (await startReview(f, run)).done;
      await dispute(f, run, "Subtraction is intended here.");
      await setScenario(f, okScenario(output({ prior_findings: [{ id: "PF-1", assessment: "still_present", superseded_by_index: null, note: "" }], discussion_replies: [{ id: "PF-1", stance: "maintain", reply: "add() must add.", new_information: "not_applicable" }] })));
      await (await startReview(f, run)).done;
      await dispute(f, run, "As I said, subtraction is intended.");
    }],
  ];
  const seen = { routes: new Set<string>(), completions: new Set<string>() };
  it.each(states)("%s", async (_name, scenario, reach, prepare) => {
    const f = await contFixture(scenario, { accounts: true });
    await prepare?.(f);
    const run = await protectedRun(f);
    const reached = await reach(f, run);
    const mine = await derive(f, run);
    const engine = await engineDerivation(f, run);
    await reached?.inFlight;
    expect(mine.available, mine.code).toBe(true);
    expect({ code: mine.route.code, kind: mine.route.kind, completion: mine.completion.state }).toEqual({ code: engine.route.code, kind: engine.route.kind, completion: engine.completion });
    seen.routes.add(`${mine.route.code}:${mine.route.kind}`);
    seen.completions.add(mine.completion.state);
  }, 180_000);
  it("covers every reachable route and completion state", () => {
    if (seen.routes.size === 0) return; // filtered run
    expect([...seen.routes].sort()).toEqual(expect.arrayContaining(["address_findings:implementer_step", "await_review:await", "end:end", "fix_checks:implementer_step", "pause:pause", "request_review:implementer_step", "run_checks:implementer_step", "wait_for_operation:implementer_step"]));
    expect([...seen.completions].sort()).toEqual(expect.arrayContaining(["checks_not_satisfied", "needs_implementer", "needs_reviewer", "needs_user_decision", "ready", "review_not_current"]));
  });
});

describe.skipIf(!supported)("P3.4C-5 N5-15 — genuine progress earns the next continuation", () => {
  it("a second spend after the source changed is granted; its fingerprint moved", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const d1 = await derive(f, run);
    expect(await spend(f, await target(f, run), { derivation_id: d1.derivationId })).toMatchObject({ ok: true });
    await writeRepoFile(f, "src/add.js", "export const add = (a, b) => a + b; // fixed\n");
    const d2 = await derive(f, run);
    expect(d2.progressFingerprint).not.toBe(d1.progressFingerprint);
    expect(d2.route.kind).toBe("implementer_step");
    expect(await spend(f, await target(f, run), { derivation_id: d2.derivationId })).toMatchObject({ ok: true });
    expect(used(f, run).continuations).toBe(2);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 N5-17 — a repository change after the derivation makes it stale", () => {
  it("spend: the custodian measures again, finds the source changed, and refuses DERIVATION_STALE; nothing is spent", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const d = await derive(f, run);
    const revisionsBefore = f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!.runRevision;
    await writeRepoFile(f, "src/add.js", "export const add = (a, b) => a - b; // edited after the derivation\n");
    // No custodian record changed: only the repository did.
    expect(f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!.runRevision).toBe(revisionsBefore);
    expect(await spend(f, await target(f, run), { derivation_id: d.derivationId })).toMatchObject({ ok: false, code: "DERIVATION_STALE" });
    expect(used(f, run).continuations).toBe(0);
    // A derivation taken after the change is fresh.
    expect(await spend(f, await target(f, run), { derivation_id: (await derive(f, run)).derivationId })).toMatchObject({ ok: true });
  }, 180_000);

  it("wake_consume: a claim reserved before the change dispatches nothing on the earlier derivation", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] }), { sleep_ms: 1500 }), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    const review = await startReview(f, run);
    let t = await target(f, run);
    const c = await readCustodianLoop(f.le, run);
    const armed = await inProcessTreeOf(PID, () => new CustodianLoops(f.custodian).transition("implementer", t, "wake_arm", { operationHandle: currentHandle(c!)!, session_id: SESSION }));
    if (!armed.ok) throw new Error(`not armed: ${armed.code}`);
    await review.done;
    const d = await derive(f, run);
    expect(d.route.kind).toBe("implementer_step");
    await writeRepoFile(f, "src/add.js", "export const add = (a, b) => a * b; // edited after the derivation\n");
    t = await target(f, run);
    const consume = (id: string) => inProcessTreeOf(PID, () => new CustodianLoops(f.custodian).wakeConsume("implementer", t, String(armed.data["claimId"]), SESSION, undefined, id));
    expect(await consume(d.derivationId)).toMatchObject({ dispatchAuthorized: false, refusal: "DERIVATION_STALE" });
    expect(used(f, run).wakes).toBe(1); // reserved at arming, not dispatched
    expect(f.custodian.snapshot().loops.find((l) => l.runId === run.runId)!.wakeClaims[0]!.state).toBe("armed");
    expect(await consume((await derive(f, run)).derivationId)).toMatchObject({ dispatchAuthorized: true });
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 — a forged derivation or route authorizes nothing", () => {
  it("an unknown id, another run's derivation and a route claimed in the request are refused; nothing is spent", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    await grant(f, 2);
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const other = await newRun(f, "another run");
    await new HostSession(f, "sess-other", 7402).startLoop(other);
    const foreign = await derive(f, other);
    expect(foreign.available).toBe(true);
    const t = await target(f, run);
    expect(await spend(f, t, { derivation_id: "der-000000000000000000000000" })).toMatchObject({ ok: false, code: "DERIVATION_STALE" });
    expect(await spend(f, t, { derivation_id: foreign.derivationId })).toMatchObject({ ok: false, code: "DERIVATION_STALE" });
    const forgedRoute = await inProcessTreeOf(PID, () => f.custodian.send("implementer", "loop_transition", { ...t, kind: "spend_continuation", fields: { session_id: SESSION, derivation_id: foreign.derivationId, route: { kind: "implementer_step", code: "address_findings" } } }, `forged-route-${Date.now()}`));
    expect(forgedRoute).toMatchObject({ ok: false, code: "MALFORMED_REQUEST" }); // an unknown field: the request carries no route
    expect(used(f, run).continuations).toBe(0);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 Increment 4 (F-3-3) — the operator's loop view shows the custodian's counters", () => {
  it("a continuation spent by a request that bypasses this engine shows in loop show, labelled the custodian's counters", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    expect(await spend(f, await target(f, run), { derivation_id: (await derive(f, run)).derivationId })).toMatchObject({ ok: true });
    expect((await readState(run.paths)).continuation?.used.continuations).toBe(0); // the local cache never saw it
    const opHooks = { ...f.le.env.testHooks!, custodian: { platform: "win32" as const, transport: f.operatorCustodian! } };
    const shown = await cli(f, ["loop", "show", run.runId], operatorIo("", true, opHooks));
    expect(shown.code, shown.err).toBe(0);
    expect(shown.out).toContain("continuations 1/2; wakes 0/2 (1 per review) — the custodian's counters");
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 Increment 4 (§5.4) — SessionStart presents the custodian's derivation", () => {
  it("the status names the custodian's next action and completion; past the bound it says the derivation was not available and offers no local one", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await newRun(f);
    await grant(f, 1);
    const A = new HostSession(f, SESSION, PID);
    await A.startLoop(run);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const s = await A.sessionStart("startup");
    expect(s.verdict).toBe("context");
    expect(s.text).toMatch(/Next action: .*address_findings|Next action: .*respond_to_review/);
    expect(s.text).toMatch(/\(The next action is the custodian's derivation der-[0-9a-f]+; completion [a-z_]+\.\)/);
    f.le.env.testHooks!.continuation!.sessionStartDerivationMs = 1; // the custodian cannot answer within the bound
    const late = await A.sessionStart("startup");
    f.le.env.testHooks!.continuation!.sessionStartDerivationMs = undefined;
    expect(late.text).toContain("The custodian's derivation of the next action was not available within 0 s; the next Stop decides on it.");
    expect(late.text).not.toContain("Next action:");
  }, 180_000);
});
