// P3.4C-5 increment 1 (contract §10 step 1): the mandatory regressions, shown failing against the code before the
// correction; closed by Increment 3 (custodian-measured check inputs, the protected derivation and its enforcement), and
// kept as ordinary tests.
//
// N5-1  — an engine (or any process in the bound session's tree) decides by itself whether a continuation is spent: on
//         a run the custodian's own records show ready, a spend straight on the implementer pipe is granted.
// N5-2  — the custodian records the engine's capture claims as sent: a forged source id in a review's op_begin and in
//         a check execution is what the custodian holds. (Increment 2 corrected the review half — the custodian captures the
//         review itself; the check half is Increment 3's.)
// N5-4  — there is no custodian derivation at all; the route of a protected run is whatever the deriving process
//         computes from its local state.
// N5-14 — the custodian spends a second continuation although no work changed between the two.
//
// Each runs over two account-bound simulated transports (the engine and the session's hooks on the implementer pipe,
// the operator's CLI on the operator pipe). The interface they pin is the contract's: a `derivation` section of
// `list_user_records` (derivationId, route, completion, inputDigest, progressFingerprint; asked for with the run's run.json
// bytes, which the custodian verifies against its declaration) and `derivation_id` on `spend_continuation`. The controls
// pass before and after.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { readState, commitState } from "../src/store/state-store.js";
import { CustodianLoops, type LoopTarget } from "../src/custodian/loops.js";
import type { CustodianTransport } from "../src/custodian/transport.js";
import { readCustodianLoop } from "../src/engine/custodian-loop.js";
import { routeRun } from "../src/engine/continuation.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, inProcessTreeOf, newRun, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

/** A case that failed against the pre-correction code (Increment 1) and passes since Increment 3. */
const failsUntilCorrected = it;

const SESSION = "sess-p34c5";
const PID = 7301;

async function protectedRun(f: ContFixture): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, SESSION, PID).startLoop(run);
  return run;
}

async function target(f: ContFixture, run: RunHandle): Promise<LoopTarget> {
  const c = await readCustodianLoop(f.le, run);
  if (!c) throw new Error("not protected");
  return { repositoryRoot: run.meta.repository_root, runId: run.runId, loopId: c.loopId, epoch: c.epoch, baseLoopRevision: c.loopRevision };
}

const usedContinuations = (f: ContFixture, run: RunHandle): number => f.custodian.snapshot().loops.find((l) => l.runId === run.runId)!.used.continuations;

/** The custodian's derivation of the run (contract §5.1), as the bound session's hooks would read it. */
async function custodianDerivation(f: ContFixture, run: RunHandle): Promise<Record<string, unknown> | null> {
  const runJson = (await readFile(run.paths.runJson)).toString("base64");
  const res = await f.custodian.send("implementer", "list_user_records", { repositoryRoot: run.meta.repository_root, runId: run.runId, sections: ["derivation"], runJson }, `derive-${Date.now()}-${Math.random()}`);
  if (!res.ok) return null;
  return (res.data?.["derivation"] as Record<string, unknown> | undefined) ?? null;
}

/** The engine's own (local) derivation of the protected run: what decides today. */
async function localRoute(f: ContFixture, run: RunHandle) {
  const view = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
  return (await routeRun(f.le, run, view)).route;
}

/** A spend straight on the implementer pipe, from inside the bound session's Claude process tree. */
function spendInTree(f: ContFixture, t: LoopTarget, derivationId?: unknown) {
  const fields = derivationId === undefined ? { session_id: SESSION } : { session_id: SESSION, derivation_id: derivationId };
  return inProcessTreeOf(PID, () => new CustodianLoops(f.custodian).transition("implementer", t, "spend_continuation", fields as { session_id: string }));
}

/** A same-user process in the session's tree rewriting the capture claims of every request the engine sends. */
const FORGED = "f".repeat(64);
function forgeCaptureClaims(f: ContFixture): void {
  const inner: CustodianTransport = f.custodian;
  const forging: CustodianTransport = {
    send(surface, op, args, requestId) {
      if (op !== "run_transition") return inner.send(surface, op, args, requestId);
      const a = structuredClone(args) as Record<string, unknown>;
      const fields = a["fields"] as Record<string, unknown>;
      if (a["kind"] === "op_begin" && fields["operationKind"] === "review") {
        for (const k of ["sourceId", "exportDigest", "manifestDigest", "reviewInputId"]) fields[k] = FORGED;
      }
      if (a["kind"] === "record_execution") {
        const e = fields["execution"] as Record<string, unknown>;
        e["sourceIdAtStart"] = FORGED;
        e["sourceIdAtEnd"] = FORGED;
        e["freshnessDigest"] = FORGED;
      }
      return inner.send(surface, op, a, requestId);
    },
  };
  f.le.env.testHooks!.custodian = { platform: "win32", transport: forging };
}

describe.skipIf(!supported)("P3.4C-5 N5-1 — automation authority on a run the custodian's records show ready", () => {
  failsUntilCorrected("a spend without the custodian's implementer-step derivation is refused (ROUTE_NOT_IMPLEMENTER_STEP / DERIVATION_STALE); nothing is spent", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    // Precondition: the run is ready (the route ends the loop).
    expect((await localRoute(f, run)).kind).toBe("end");
    const t = await target(f, run);
    const out = await spendInTree(f, t);
    expect(out.ok).toBe(false);
    expect(["ROUTE_NOT_IMPLEMENTER_STEP", "DERIVATION_STALE"]).toContain((out as { code?: string }).code);
    expect(usedContinuations(f, run)).toBe(0);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 N5-2 — the custodian records its own capture measurements, not the engine's claims", () => {
  // P3.4C-5 Increment 2 corrected the review half: the custodian captures the review itself; capture claims an engine
  // sends with the reservation are ignored and named (ignoredClaims), never recorded.
  it("a forged source id, export, manifest and review input id sent with a review's op_begin are ignored: the custodian's own capture is what it holds", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    forgeCaptureClaims(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const held = f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!;
    const review = held.reviews.at(-1)?.begin;
    const st = await readState(run.paths);
    expect(review?.["sourceId"]).toBe(st.reviews.at(-1)?.source_id);
    for (const k of ["sourceId", "exportDigest", "manifestDigest", "reviewInputId"]) expect(review?.[k], k).not.toBe(FORGED);
    expect(held.reviews.at(-1)?.accepted).toBe(true);
    const begin = held.events.find((e) => e.kind === "op_begin" && (e.result as Record<string, unknown> | null)?.["reviewId"] !== undefined)?.result as Record<string, unknown>;
    expect(begin["ignoredClaims"]).toEqual(["sourceId", "reviewInputId", "exportDigest", "manifestDigest"]);
  }, 180_000);

  // The check half is the custodian-measured check inputs of Increment 3 (contract §4): still an expected failure.
  failsUntilCorrected("forged check source ids and freshness digest in record_execution are not what the custodian holds", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    forgeCaptureClaims(f);
    await runChecks(f, run);
    const held = f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!;
    const exec = held.checkExecutions.at(-1) as Record<string, unknown> | undefined;
    expect(exec?.["sourceIdAtStart"]).not.toBe(FORGED);
    expect(exec?.["freshnessDigest"]).not.toBe(FORGED);
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 N5-4 — the protected derivation is the custodian's, from its records only", () => {
  failsUntilCorrected("the custodian serves a derivation; local edits to state.json, run.json and the local loop record change neither its route nor its input digest", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const before = await custodianDerivation(f, run);
    expect(before).not.toBeNull();
    expect((before!["route"] as { kind: string }).kind).toBe("implementer_step");
    // A same-user process: every finding resolved, every review accepted APPROVE, the local loop's budget reset.
    await commitState(run.paths, f.le.env.owner, (cur) => {
      for (const it of cur.findings) it.status = "reported_resolved";
      for (const r of cur.reviews) r.verdict = "APPROVE";
      if (cur.continuation) cur.continuation.used.continuations = 0;
      return cur;
    });
    const after = await custodianDerivation(f, run);
    expect((after!["route"] as { code: string }).code).toBe((before!["route"] as { code: string }).code);
    expect(after!["inputDigest"]).toBe(before!["inputDigest"]);
    expect(after!["progressFingerprint"]).toBe(before!["progressFingerprint"]);
  }, 180_000);

  it("control: today the engine's local derivation of the same run routes the implementer to the finding", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    expect((await localRoute(f, run)).kind).toBe("implementer_step");
  }, 180_000);
});

describe.skipIf(!supported)("P3.4C-5 N5-14 — unchanged work does not earn a second continuation", () => {
  failsUntilCorrected("two spends with nothing but bookkeeping between them: the first is granted, the second refused NO_PROGRESS", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const d1 = await custodianDerivation(f, run);
    expect((d1!["route"] as { kind: string }).kind).toBe("implementer_step");
    expect(await spendInTree(f, await target(f, run), d1!["derivationId"])).toMatchObject({ ok: true });
    // Only bookkeeping changed (the loop's counters and revision): the work facts are the same.
    const d2 = await custodianDerivation(f, run);
    expect(d2!["progressFingerprint"]).toBe(d1!["progressFingerprint"]);
    expect(await spendInTree(f, await target(f, run), d2!["derivationId"])).toMatchObject({ ok: false, code: "NO_PROGRESS" });
    expect(usedContinuations(f, run)).toBe(1);
  }, 180_000);
});
