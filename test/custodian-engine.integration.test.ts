// P3.4C-0 increment 2: the engine's protected-loop path through the custodian, against a real git
// repository, approved checks and the scripted fake Codex, with the SIMULATED custodian (the real
// Windows custodian is exercised by custodian-pipe.test.ts and, as a service, on the disposable VM in
// increment 3). The operator acts through the real CLI; start_review_loop's engine path is called
// directly. Every assertion reads the engine's or the custodian's own records.
//
// Covered: the protected-loop capability gate (Option A: Windows with the custodian only; elsewhere
// refused up front, with nothing written or sent; manual review unaffected), the two-phase operator
// grant, consumption BEFORE a loop exists, a left-over grants.json never read, the crash/retry boundaries
// (before consume, a lost response, after consume before the loop record, a start that died mid-flight,
// an operator stop mid-start, custodian shutdown/restart, an impostor endpoint), revocation, expiry,
// ceilings and their reporting, and the custodian's caller classification.

import { describe, it, expect } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { startLoop } from "../src/engine/continuation.js";
import { SimulatedCustodianTransport } from "../src/custodian/transport.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, grant, loopOf, newRun, operatorIo, protectConfig, type ContFixture } from "./helpers/continuation-fixture.js";

interface Failure {
  code: string;
  retryable: boolean;
  details: Record<string, unknown>;
  message: string;
}

async function failure(p: Promise<unknown>): Promise<Failure> {
  try {
    await p;
  } catch (e) {
    const x = e as { code?: string; retryable?: boolean; details?: Record<string, unknown>; message?: string };
    return { code: x.code ?? `UNCODED:${String(e)}`, retryable: x.retryable === true, details: x.details ?? {}, message: x.message ?? "" };
  }
  return { code: "NO_ERROR", retryable: false, details: {}, message: "" };
}

const fixture = () => contFixture(okScenario(output({ findings: [] })));
const consumed = (f: ContFixture): number => f.custodian.snapshot().grants.reduce((n, g) => n + g.loopsUsed, 0);
const consumeRequests = (f: ContFixture): number => f.custodian.received.filter((r) => r.op === "consume_loop").length;
const marker = async (run: RunHandle) => (await readState(run.paths)).loop_start;

describe.skipIf(!supported)("P3.4C-0: protected loops through the custodian (engine)", () => {
  it("allow is two-phase (the custodian's rendering, a typed confirmation, then commit); a start consumes exactly one granted loop before the loop exists", async () => {
    const f = await fixture();
    const run = await newRun(f);
    await protectConfig(f); // P3.4C-4: the repository's protected configuration, imported by the operator
    const base = f.custodian.received.length;
    const r = await cli(f, ["loop", "allow", "--repo", f.repo, "--loops", "2", "--minutes", "30"], operatorIo("allow"));
    expect(r.code, r.err).toBe(0);
    expect(r.out).toContain("The CodeParley custodian prepared this grant (nothing is granted until you confirm)");
    expect(r.out).toMatch(/identity sim[12]-/);
    expect(r.out).toMatch(/Recorded by the custodian: grant \S+, 2 loop\(s\)/);
    expect(f.custodian.received.slice(base).map((x) => `${x.surface}:${x.op}`)).toEqual(["operator:prepare_grant", "operator:commit"]);

    const s = await startLoop(f.le, run);
    expect(s.existing).toBe(false);
    const loop = await loopOf(run);
    expect(loop.grant_use).toMatchObject({ source: "custodian", loops_used: 1, loops_total: 2 });
    expect(loop.limits).toEqual({ continuations: 2, wakes_per_operation: 1, wakes_per_run: 2, run_seconds: 900 });
    expect(await marker(run)).toBeUndefined();
    // P3.4C-2: the start asks the custodian whether the run has its loop, consumes+mints it, and reads it back;
    // P3.4C-3: it registers the run (run_transition open) before the loop is consumed. Phase 5 F-i2-5: right after the
    // registration it hands the custodian the baseline capture record the declaration binds (hold_evidence: redaction
    // evidence, no authority).
    expect(f.custodian.received.slice(base + 2).map((x) => `${x.surface}:${x.op}`)).toEqual(["implementer:list_user_records", "implementer:run_transition", "implementer:hold_evidence", "implementer:consume_loop", "implementer:list_user_records"]);
    // The engine sends the repository path and the run only; the custodian established the identity.
    expect(f.custodian.received.find((x) => x.op === "consume_loop")!.args).toEqual({ repositoryRoot: f.repo, runId: run.runId });
    // The run's declaration: the digest of its run.json, the effective budgets and its baseline, each a claim.
    const open = f.custodian.received.find((x) => x.op === "run_transition")!.args;
    expect(open).toMatchObject({ repositoryRoot: f.repo, runId: run.runId, kind: "open", fields: { runJsonDigest: expect.stringMatching(/^[0-9a-f]{64}$/), budgets: { maxReviews: expect.any(Number), maxCheckExecutions: expect.any(Number) } } });
    // Calling start_review_loop again: the same loop, no second consumption.
    expect(await startLoop(f.le, run)).toMatchObject({ existing: true });
    expect(consumeRequests(f)).toBe(1);
    expect(consumed(f)).toBe(1);
  });

  it("the gate (Option A): on a platform without a validated custodian, protected loops and grants are refused up front — nothing written, nothing sent — while independent review stays available", async () => {
    const f = await fixture();
    f.le.env.testHooks!.custodian!.platform = "darwin"; // Phase 5: Linux has a custodian now
    const run = await newRun(f); // a review run (manual, independent review) is unaffected
    const e = await failure(startLoop(f.le, run));
    expect(e).toMatchObject({ code: "CUSTODIAN_UNAVAILABLE", retryable: false });
    expect(e.details["reason"]).toBe("no_validated_custodian_for_platform");
    expect(e.message).toContain("nothing falls back to a weaker authority");
    expect(await marker(run)).toBeUndefined();
    expect((await readState(run.paths)).continuation).toBeUndefined();
    for (const args of [["loop", "allow", "--repo", f.repo], ["loop", "revoke", "--repo", f.repo], ["loop", "grants"]]) {
      const r = await cli(f, args, operatorIo("allow"));
      expect(r.code, args.join(" ")).toBe(1);
      expect(r.err).toContain("CUSTODIAN_UNAVAILABLE");
    }
    expect(f.custodian.received).toHaveLength(0);
  });

  it("Windows without a reachable custodian: fail-closed and retryable, nothing consumed, no marker left; once the custodian is back, the start succeeds", async () => {
    const f = await fixture();
    await grant(f, 1);
    const run = await newRun(f);
    f.custodian.setUnavailable("the custodian service is stopped");
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "CUSTODIAN_UNAVAILABLE", retryable: true });
    expect(await marker(run)).toBeUndefined();
    expect(consumed(f)).toBe(0);
    f.custodian.setUnavailable(null);
    await startLoop(f.le, run);
    expect(consumed(f)).toBe(1);
  });

  it("a grants.json left by an earlier version is never read: no import, no fallback", async () => {
    const f = await fixture();
    const run = await newRun(f);
    await mkdir(join(f.dataHome, "continuation"), { recursive: true });
    const now = Date.now();
    await protectConfig(f); // P3.4C-4: with the configuration held, the start is refused for the missing grant only
    await writeFile(join(f.dataHome, "continuation", "grants.json"), JSON.stringify({ schema: "codeparley.loop-grants.v1", grants: [{ grant_id: "legacy-grant", repository_root: f.repo, repo_key: run.repoKey, loops_total: 5, loops_used: 0, created_at: new Date(now).toISOString(), expires_at: new Date(now + 3_600_000).toISOString(), revoked_at: null, limits: { continuations: 2, wakes_per_operation: 1, wakes_per_run: 2, run_seconds: 900 }, recorded_by: { role: "user", channel: "local_cli", assurance: "local_operator" }, request_id: null, uses: [] }] }));
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "LOOP_NOT_AUTHORIZED" });
    const g = await cli(f, ["loop", "grants", "--json"]);
    expect(JSON.parse(g.out).grants).toEqual([]);
  });

  it("crash/retry (P3.4C-2): a request that never reached the custodian is retried safely; a lost response leaves the custodian's loop unbindable, and the run is never given a second loop", async () => {
    const f = await fixture();
    await grant(f, 3);
    const run = await newRun(f);
    f.custodian.failNext("consume_loop", "not_delivered");
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "CUSTODIAN_UNAVAILABLE", retryable: true });
    expect(await marker(run)).toBeUndefined();
    expect(consumed(f)).toBe(0);

    f.custodian.failNext("consume_loop", "lost_response");
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "LOOP_START_UNRECONCILED", retryable: false });
    expect(consumed(f)).toBe(1); // the custodian did consume it, and minted the run's loop in the same write
    expect(f.custodian.snapshot().loops.filter((l) => l.runId === run.runId).map((l) => l.status)).toEqual(["unbound"]);
    expect(await marker(run)).toBeUndefined(); // no local start marker: the custodian's record is the truth
    // Retrying adopts the custodian's loop, whose one-time nonce never arrived: it cannot be bound, and nothing
    // more is consumed.
    const requests = consumeRequests(f);
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "LOOP_START_UNRECONCILED", details: { reason: "unbindable" } });
    expect(consumeRequests(f)).toBe(requests);
    expect(consumed(f)).toBe(1);
    // The operator stops it — the custodian's loop too; a later start finds the ended loop and consumes nothing.
    const stop = await cli(f, ["loop", "stop", run.runId, "--reason", "lost response"]);
    expect(stop.out).toContain("cancelled");
    expect(stop.out).toContain("the custodian cancelled the run's loop");
    expect(f.custodian.snapshot().loops.find((l) => l.runId === run.runId)?.status).toBe("cancelled");
    expect(await startLoop(f.le, run)).toMatchObject({ existing: true, nonce: null, loop: { status: "cancelled" } });
    expect(consumed(f)).toBe(1);
  });

  it("crash/retry (P3.4C-2): a failure after the custodian minted and before the local record — the next start adopts the custodian's loop; nothing is consumed twice", async () => {
    const f = await fixture();
    await grant(f, 2);
    const run = await newRun(f);
    f.le.env.testHooks!.continuation!.afterConsume = async () => {
      throw new Error("simulated crash before the loop record");
    };
    expect((await failure(startLoop(f.le, run))).message).toContain("simulated crash");
    expect(consumed(f)).toBe(1);
    expect((await readState(run.paths)).continuation).toBeUndefined();
    delete f.le.env.testHooks!.continuation!.afterConsume;
    // The same server still holds the loop's one-time nonce (in memory only), so the start adopts the custodian's
    // loop and the host can still bind it; no second loop is consumed.
    const again = await startLoop(f.le, run);
    expect(again.existing).toBe(true);
    expect(again.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(consumed(f)).toBe(1);
    expect((await readState(run.paths)).continuation?.loop_id).toBe(f.custodian.snapshot().loops.find((l) => l.runId === run.runId)!.loopId);
  });

  it("crash/retry (P3.4C-2): an older version's start marker gates nothing — the custodian's record decides, and a run never gets a second loop", async () => {
    const f = await fixture();
    await grant(f, 2);
    const run = await newRun(f);
    const now = Date.now();
    await commitState(run.paths, f.le.env.owner, (st) => {
      st.loop_start = { request_id: "crashed-start", loop_id: "crashed-loop", started_at: new Date(now).toISOString(), status: "pending", detail: null };
      return st;
    });
    const s = await startLoop(f.le, run);
    expect(s.existing).toBe(false);
    expect(consumed(f)).toBe(1);
    expect(await marker(run)).toBeUndefined(); // superseded by the custodian's record and removed
    // Another start racing it (another server) asked the custodian too: it refuses a second loop for the run.
    const second = await new CustodianGrants(f.custodian).consume(f.repo, run.runId).catch((e: unknown) => e);
    expect(second).toMatchObject({ code: "RUN_ALREADY_HAS_LOOP" });
    expect(consumed(f)).toBe(1);
  });

  it("the operator stopping a start while the custodian consumes: no loop is created; the consumed loop is spent; the run gets no second loop", async () => {
    const f = await fixture();
    await grant(f, 2);
    const run = await newRun(f);
    f.le.env.testHooks!.continuation!.afterConsume = async () => {
      // P3.4C-2: the custodian's loop exists by now (minted with the consumption); the operator cancels it there.
      expect((await cli(f, ["loop", "stop", run.runId])).out).toContain("the custodian cancelled the run's loop");
    };
    const e = await failure(startLoop(f.le, run));
    expect(e.code).toBe("LOOP_NOT_AUTHORIZED");
    expect(e.message).toContain("the operator stopped this run's automation while it was starting");
    expect(e.message).toMatch(/was consumed and is spent/);
    expect((await readState(run.paths)).continuation?.status).toBe("cancelled");
    delete f.le.env.testHooks!.continuation!.afterConsume;
    // The run's loop has ended: a later start consumes nothing (one loop per run, never resurrected).
    expect(await startLoop(f.le, run)).toMatchObject({ existing: true, loop: { status: "cancelled" } });
    expect(consumed(f)).toBe(1);
  });

  it("an impostor endpoint: SERVER_NOT_TRUSTED, nothing sent or consumed, no marker left", async () => {
    const f = await fixture();
    await grant(f, 1);
    const run = await newRun(f);
    f.custodian.failNext("consume_loop", "untrusted");
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "SERVER_NOT_TRUSTED", retryable: false });
    expect(await marker(run)).toBeUndefined();
    expect(consumeRequests(f)).toBe(0);
    await startLoop(f.le, run);
    expect(consumed(f)).toBe(1);
  });

  it("a repository the custodian refuses to identify: INVALID_ARGUMENT from the custodian, nothing consumed, no marker left", async () => {
    const f = await fixture();
    const run = await newRun(f);
    f.le.env.testHooks!.custodian!.transport = new SimulatedCustodianTransport({ caller: "by_surface", identity: () => { const e = new Error("repository identity refused: 'repo': the custodian is denied access to it") as Error & { simCode: string }; e.simCode = "INVALID_ARGUMENT"; throw e; } });
    const e = await failure(startLoop(f.le, run));
    expect(e).toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(e.message).toContain("repository identity refused");
    expect(await marker(run)).toBeUndefined();
  });

  it("revocation and expiry: the custodian answers LOOP_NOT_AUTHORIZED; nothing is consumed", async () => {
    const f = await fixture();
    await grant(f, 1);
    expect((await cli(f, ["loop", "revoke", "--repo", f.repo])).out).toContain("revoked 1 grant(s)");
    const run = await newRun(f);
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "LOOP_NOT_AUTHORIZED" });
    expect(await marker(run)).toBeUndefined();
    expect((await cli(f, ["loop", "allow", "--repo", f.repo, "--minutes", "1"], operatorIo("allow"))).code).toBe(0);
    f.clock.now = Date.now() + 61_000;
    expect(await failure(startLoop(f.le, run))).toMatchObject({ code: "LOOP_NOT_AUTHORIZED" });
    f.clock.now = null;
    expect(consumed(f)).toBe(0);
  });

  it("effective limits: the custodian's ceilings are enforced before anything is sent and reported by `loop grants`; per-loop budgets stay CodeParley's", async () => {
    const f = await fixture();
    for (const args of [["--loops", "9"], ["--minutes", "181"]]) {
      const r = await cli(f, ["loop", "allow", "--repo", f.repo, ...args], operatorIo("allow"));
      expect(r.code).toBe(1);
      expect(r.err).toContain("the custodian's ceiling");
    }
    expect(f.custodian.received).toHaveLength(0);
    await grant(f, 8);
    const g = await cli(f, ["loop", "grants"]);
    expect(g.out).toContain("custodian ceilings (enforced by the custodian): at most 8 loop(s) and 180 minutes per grant");
    expect(g.out).toContain("per loop (CodeParley's limits): 2 automated continuation(s), 2 idle wake(s) (1 per review) and 15 minutes");
    expect(g.out).toMatch(/loops 0\/8; valid until/);
    const j = JSON.parse((await cli(f, ["loop", "grants", "--json"])).out);
    expect(j.custodian.ceilings).toEqual({ loops: 8, minutes: 180 });
    expect(j.per_loop_limits).toEqual({ continuations: 2, wakes_per_operation: 1, wakes_per_run: 2, run_seconds: 900 });
  });

  it("operator/implementer separation: the custodian's caller classification decides; the CLI explains a non-elevated refusal", async () => {
    const f = await fixture();
    f.custodian.setCaller("implementer"); // a non-elevated terminal: the operator surface classifies it as no operator
    const r = await cli(f, ["loop", "allow", "--repo", f.repo], operatorIo("allow"));
    expect(r.code).toBe(1);
    expect(r.err).toContain("CALLER_NOT_AUTHORIZED");
    expect(r.err).toContain("elevated terminal");
    expect((await cli(f, ["loop", "revoke", "--repo", f.repo])).err).toContain("CALLER_NOT_AUTHORIZED");
    f.custodian.setCaller("by_surface");
    await grant(f, 1);
    const run = await newRun(f);
    await startLoop(f.le, run);
    expect(f.custodian.received.filter((x) => x.op === "consume_loop").map((x) => x.surface)).toEqual(["implementer"]);
  });
});
