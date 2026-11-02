// Operations through MCP (plan §5.4, §11, §15.5, MR-E, MR-J, D-27, D-28; M1.5): bounded waits
// and polling, request-id and input dedupe, call cancellation (Esc / host timeout) versus
// explicit targeted cancellation, a stale expected_operation_id, concurrent read-only status
// calls, server restart and recovery during reviews and checks, and shutdown on stdin close.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { compileServer, removeCompiledServer, errorCode, sc, taskkillHard, waitUntil, type Conn, type Flavor } from "./helpers/mcp-harness.js";
import { mcpFixture, newRunOver, open, slowReviewScenario, type McpFixture } from "./helpers/mcp-fixture.js";
import { fakeCalls, setScenario } from "./helpers/review-fixture.js";
import { supported } from "./helpers/git-fixture.js";
import { STALE_HEARTBEAT_MS } from "../src/store/locks.js";
import { pidAlive } from "../src/store/owner.js";

// Flake P-e (Phase 6 Increment 1): a server killed inside a run-state commit leaves the run mutation lock fresh. It
// is broken only once its heartbeat is older than STALE_HEARTBEAT_MS and its holder is dead (fail-safe), and writes
// meanwhile answer the retryable STORE_LOCKED; under load a kill lands inside a commit more often. A client retries a
// retryable error, so the first write after the crash does too, for at most the stale threshold and a margin.
async function afterCrash<T>(call: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + STALE_HEARTBEAT_MS + 10_000;
  for (;;) {
    const r = await call();
    if (errorCode(r as Parameters<typeof errorCode>[0]) !== "STORE_LOCKED" || Date.now() > deadline) return r;
    await new Promise((res) => setTimeout(res, 500));
  }
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

const NEXT = "Cancelling this call does not stop the operation";

async function stateJson(f: McpFixture, runId: string): Promise<{ state: string; operations: { operation_id: string; kind: string; status: string }[]; reviews: { status: string; review_id: string; operation_id: string }[]; isolation_incidents: { kind: string }[]; events: { type: string }[] }> {
  const runs = join(f.dataHome, "runs");
  for (const k of await readdir(runs)) {
    const p = join(runs, k, runId, "state.json");
    if (existsSync(p)) return JSON.parse(await readFile(p, "utf8"));
  }
  throw new Error("state.json not found");
}

async function status(c: Conn, runId: string, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return sc(await c.call("get_review_status", { run_id: runId, ...extra }));
}

/**
 * Poll as a client does: get_review_status(wait_seconds) until the run has no active
 * operation; returns that status (its completed_operation is the finished result). Each
 * call is bounded; under parallel test load an operation may need more than one wait.
 */
async function pollUntilDone(c: Conn, runId: string, maxPolls = 8): Promise<Record<string, unknown>> {
  for (let i = 0; i < maxPolls; i++) {
    const s = await status(c, runId, { wait_seconds: 30 });
    if (s["active_operation"] === null && s["completed_operation"]) return s;
  }
  throw new Error(`run ${runId}: the operation did not finish within ${maxPolls} polls`);
}

/** A starting tool's result, or — if it returned a running handle — the polled result. */
async function finished(c: Conn, runId: string, r: Record<string, unknown>): Promise<Record<string, unknown>> {
  return r["status"] === "running" ? ((await pollUntilDone(c, runId))["completed_operation"] as Record<string, unknown>) : r;
}

describe.skipIf(!supported)("bounded waits, handles and polling (D-02, MR-J)", () => {
  for (const flavor of ["v2-legacy", "v2-modern"] as Flavor[]) {
    it(`${flavor}: a long review returns a handle within the bound, polling waits boundedly, and the result arrives as completed_operation`, async () => {
      const f = await mcpFixture({ scenario: slowReviewScenario(6000) });
      const c = await open(f, flavor);
      try {
        const runId = await newRunOver(c, f);
        const t0 = Date.now();
        const h = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 1 }));
        expect(Date.now() - t0).toBeLessThan(1000 + 20_000); // the wait bound plus work, with slack for parallel test load
        expect(h["status"]).toBe("running");
        expect(h["kind"]).toBe("review");
        expect(h["next"]).toContain(NEXT);
        expect(h["summary"]).toContain(NEXT);
        const opId = h["operation_id"] as string;
        const t1 = Date.now();
        const s1 = await status(c, runId, { wait_seconds: 1 });
        expect(Date.now() - t1).toBeLessThan(1000 + 20_000);
        expect((s1["active_operation"] as { operation_id: string; next: string }).operation_id).toBe(opId);
        expect((s1["active_operation"] as { next: string }).next).toContain(NEXT);
        expect(s1["state"]).toBe("REVIEWING");
        const s2 = await pollUntilDone(c, runId);
        const done = s2["completed_operation"] as { operation_id: string; status: string; accepted: boolean };
        expect(done.operation_id).toBe(opId);
        expect(done.status).toBe("completed");
        expect(done.accepted).toBe(true);
        expect(s2["active_operation"]).toBeNull();
        // wait_seconds with nothing active: the latest finished operation's result.
        const s3 = await status(c, runId, { wait_seconds: 1 });
        expect((s3["completed_operation"] as { operation_id: string }).operation_id).toBe(opId);
        const t2 = Date.now();
        await status(c, runId, { wait_seconds: 0 });
        expect(Date.now() - t2).toBeLessThan(20_000);
      } finally {
        await c.close();
      }
    }, 120_000);
  }
});

describe.skipIf(!supported)("idempotency and dedupe (D-28)", () => {
  it("request_id returns the same operation (running or completed), conflicts on different arguments; identical inputs dedupe", async () => {
    // Long enough to stay running across the quick calls below, even under parallel load.
    const f = await mcpFixture({ scenario: slowReviewScenario(15_000) });
    const c = await open(f, "v2-modern");
    try {
      // create_review_run idempotency
      const a = sc(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, request_id: "create-1", wait_seconds: 30 }));
      const b = sc(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, request_id: "create-1", wait_seconds: 30 }));
      expect(b["run_id"]).toBe(a["run_id"]);
      expect(b["deduplicated"]).toBe(true);
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "other" }, repository_root: f.repo, request_id: "create-1" }))).toBe("REQUEST_ID_CONFLICT");
      const runId = a["run_id"] as string;

      const r1 = sc(await c.call("review_with_codex", { run_id: runId, request_id: "rev-1", wait_seconds: 0 }));
      const r2 = sc(await c.call("review_with_codex", { run_id: runId, request_id: "rev-1", wait_seconds: 0 }));
      expect(r2["operation_id"]).toBe(r1["operation_id"]);
      expect(r2["deduplicated"]).toBe(true);
      // The same arguments without a request_id while it runs: the running operation (dedupe).
      const r3 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 0 }));
      expect(r3["operation_id"]).toBe(r1["operation_id"]);
      expect(errorCode(await c.call("review_with_codex", { run_id: runId, request_id: "rev-1", focus: "different" }))).toBe("REQUEST_ID_CONFLICT");
      // Different arguments without request_id while busy: RUN_BUSY (never a second operation).
      expect(errorCode(await c.call("review_with_codex", { run_id: runId, focus: "other", wait_seconds: 0 }))).toBe("RUN_BUSY");
      await pollUntilDone(c, runId);
      const done = sc(await c.call("review_with_codex", { run_id: runId, request_id: "rev-1", wait_seconds: 5 }));
      expect(done["status"]).toBe("completed");
      expect(done["operation_id"]).toBe(r1["operation_id"]);
      // Retrying a completed request_id returns the stored result.
      const again = sc(await c.call("review_with_codex", { run_id: runId, request_id: "rev-1", wait_seconds: 5 }));
      expect(again["review_id"]).toBe(done["review_id"]);
      // An identical input without request_id: the stored accepted review, no new Codex run.
      const execsBefore = (await fakeCalls(f, "exec")).length;
      const dup = await finished(c, runId, sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 30 })));
      expect(dup["deduplicated"]).toBe(true);
      expect(dup["review_id"]).toBe(done["review_id"]);
      expect((await fakeCalls(f, "exec")).length).toBe(execsBefore);
      expect((dup["budgets"] as { name: string; used: number }[]).find((x) => x.name === "reviews")!.used).toBe(1);
      // Checks request_id idempotency.
      const c1 = sc(await c.call("run_checks", { run_id: runId, request_id: "chk-1", wait_seconds: 30 }));
      const c2 = sc(await c.call("run_checks", { run_id: runId, request_id: "chk-1", wait_seconds: 30 }));
      expect(c2["operation_id"]).toBe(c1["operation_id"]);
      expect(errorCode(await c.call("run_checks", { run_id: runId, request_id: "chk-1", checks: ["flag"] }))).toBe("REQUEST_ID_CONFLICT");
    } finally {
      await c.close();
    }
  }, 150_000);
});

describe.skipIf(!supported)("call cancellation versus explicit cancellation (D-27, MR-E, MR-J)", () => {
  for (const flavor of ["v2-legacy", "v2-modern", "v1"] as Flavor[]) {
    it(`${flavor}: Esc ends only the wait; cancel_active(expected id) cancels exactly that operation`, async () => {
      const f = await mcpFixture({ scenario: slowReviewScenario(20_000) });
      const c = await open(f, flavor);
      try {
        const runId = await newRunOver(c, f);
        const ac = new AbortController();
        setTimeout(() => ac.abort("user-cancel"), 1500);
        await expect(c.call("review_with_codex", { run_id: runId, wait_seconds: 40 }, { signal: ac.signal })).rejects.toBeTruthy();
        // The operation keeps running after the call was cancelled.
        await new Promise((r) => setTimeout(r, 1500));
        const s = await status(c, runId);
        const active = s["active_operation"] as { operation_id: string; kind: string } | null;
        // Diagnostic messages: this test failed once under full-suite load (M1.6) without a captured reason.
        expect(active?.kind, `status after the cancelled call: ${JSON.stringify(s).slice(0, 600)}`).toBe("review");
        expect((await stateJson(f, runId)).operations.find((o) => o.operation_id === active!.operation_id)!.status).toBe("running");
        // Explicit, targeted cancellation.
        const stop = sc(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: active!.operation_id }));
        const can = stop["cancellation"] as { operation_id: string; outcome: string; operation_status: string; record: { outcome: string } | null };
        expect(can.operation_id).toBe(active!.operation_id);
        expect(["terminated", "cancellation_requested"]).toContain(can.outcome);
        expect(can.operation_status, `stop result: ${JSON.stringify(stop).slice(0, 800)}`).toBe("cancelled");
        // The outcome IS the engine's evidence record (never inferred by the MCP layer).
        expect(can.record?.outcome).toBe(can.outcome);
        expect(stop["state"], `stop result: ${JSON.stringify(stop).slice(0, 800)}`).toBe("IDLE");
        const st = await stateJson(f, runId);
        expect(st.operations.find((o) => o.operation_id === active!.operation_id)!.status).toBe("cancelled");
        // A review record exists only once the review got past capture and the isolation
        // self-test (on a slow machine the cancellation can land earlier); if it exists, it is
        // cancelled too.
        const rec = st.reviews.find((x) => x.operation_id === active!.operation_id);
        if (rec) expect(rec.status).toBe("cancelled");
        // Repeating the cancel returns that operation's outcome without touching anything.
        const again = sc(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: active!.operation_id }));
        expect((again["cancellation"] as { outcome: string }).outcome).toBe("already_finished");
      } finally {
        await c.close();
      }
    }, 150_000);
  }

  it("stale expected_operation_id: cancel A, start B, retry the cancel of A — B keeps running (MR-E acceptance)", async () => {
    const f = await mcpFixture();
    const c = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      const a = sc(await c.call("run_checks", { run_id: runId, checks: ["slow"], wait_seconds: 1 }));
      expect(a["status"]).toBe("running");
      const stopA = sc(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: a["operation_id"] as string }));
      expect((stopA["cancellation"] as { operation_status: string }).operation_status).toBe("cancelled");
      const b = sc(await c.call("run_checks", { run_id: runId, checks: ["slow2"], wait_seconds: 1 }));
      expect(b["status"]).toBe("running");
      // The response to "cancel A" was lost; the client retries it while B runs.
      const retry = sc(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: a["operation_id"] as string }));
      expect((retry["cancellation"] as { operation_id: string; outcome: string }).operation_id).toBe(a["operation_id"]);
      expect((retry["cancellation"] as { outcome: string }).outcome).toBe("already_finished");
      const s = await status(c, runId);
      expect((s["active_operation"] as { operation_id: string }).operation_id).toBe(b["operation_id"]);
      expect((await stateJson(f, runId)).operations.find((o) => o.operation_id === b["operation_id"])!.status).toBe("running");
      // An id that is not an operation of this run: OPERATION_MISMATCH, nothing cancelled.
      expect(errorCode(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: "01a10737-0000-7000-8000-000000000000" }))).toBe("OPERATION_MISMATCH");
      // abort with A's id while B runs: refused, B untouched.
      expect(errorCode(await c.call("stop_review_loop", { run_id: runId, mode: "abort", expected_operation_id: a["operation_id"] as string }))).toBe("OPERATION_MISMATCH");
      expect((await stateJson(f, runId)).operations.find((o) => o.operation_id === b["operation_id"])!.status).toBe("running");
      // close is refused while B runs.
      expect(errorCode(await c.call("stop_review_loop", { run_id: runId, mode: "close" }))).toBe("RUN_BUSY");
      // abort (no id): B cancelled and the run STOPPED; nothing new can start.
      const ab = sc(await c.call("stop_review_loop", { run_id: runId, mode: "abort", reason: "done" }));
      expect(ab["state"]).toBe("STOPPED");
      expect((ab["cancellation"] as { operation_id: string; operation_status: string }).operation_id).toBe(b["operation_id"]);
      expect((ab["cancellation"] as { operation_status: string }).operation_status).toBe("cancelled");
      expect(errorCode(await c.call("run_checks", { run_id: runId }))).toBe("RUN_TERMINAL");
      expect(errorCode(await c.call("review_with_codex", { run_id: runId }))).toBe("RUN_TERMINAL");
    } finally {
      await c.close();
    }
  }, 150_000);

  it("a cancellation request reaches an operation owned by ANOTHER server process (committed request + owner watcher)", async () => {
    const f = await mcpFixture();
    const owner = await open(f, "v2-legacy");
    const other = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(owner, f);
      const a = sc(await owner.call("run_checks", { run_id: runId, checks: ["slow"], wait_seconds: 1 }));
      const stop = sc(await other.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: a["operation_id"] as string }));
      expect((stop["cancellation"] as { operation_status: string }).operation_status).toBe("cancelled");
      expect(["terminated", "cancellation_requested"]).toContain((stop["cancellation"] as { outcome: string }).outcome);
    } finally {
      await owner.close();
      await other.close();
    }
  }, 120_000);
});

describe.skipIf(!supported)("concurrent read-only calls (K8)", () => {
  it("parallel get_review_status and get_review_history calls are consistent and side-effect free", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(15_000) });
    const c = await open(f, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      const h = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 0 }));
      const revBefore = (await stateJson(f, runId)).events.length;
      const results = await Promise.all([
        ...Array.from({ length: 6 }, () => c.call("get_review_status", { run_id: runId })),
        ...Array.from({ length: 3 }, () => c.call("get_review_history", { run_id: runId })),
        c.call("get_review_status", {}),
      ]);
      for (const r of results) expect(r.isError).not.toBe(true);
      const states = results.slice(0, 6).map((r) => sc(r)["state"]);
      expect(new Set(states)).toEqual(new Set(["REVIEWING"]));
      for (const r of results.slice(0, 6)) expect((sc(r)["active_operation"] as { operation_id: string }).operation_id).toBe(h["operation_id"]);
      // Observers committed nothing.
      const st = await stateJson(f, runId);
      expect(st.events.length).toBeGreaterThanOrEqual(revBefore);
      expect(st.events.filter((e) => e.type.startsWith("status") || e.type.startsWith("history"))).toEqual([]);
      await pollUntilDone(c, runId);
    } finally {
      await c.close();
    }
  }, 120_000);
});

describe.skipIf(!supported)("restart and recovery (§15.5, M1.4-11, MR-C)", () => {
  it("a server killed during a review: the restarted server shows it interrupted, records the possible-orphan incident on the next operation, and reviews continue", async () => {
    const f = await mcpFixture({ scenario: slowReviewScenario(60_000) });
    const c1 = await open(f, "v2-legacy");
    const runId = await newRunOver(c1, f);
    const h = sc(await c1.call("review_with_codex", { run_id: runId, wait_seconds: 3 }));
    expect(h["status"]).toBe("running");
    expect(await waitUntil(async () => (await fakeCalls(f, "exec")).length > 0, 20_000)).toBe(true);
    taskkillHard(c1.pid!);
    await c1.close().catch(() => undefined);
    // taskkill /F returns once termination is requested, not once the process has exited: observe only after it has
    // (Phase 6 Increment 1, T1 run 5 — a status read in that window rightly saw a live owner and REVIEWING).
    expect(await waitUntil(() => !pidAlive(c1.pid!), 15_000)).toBe(true);
    const c2 = await open(f, "v2-modern");
    try {
      // Pure observer: shown as interrupted, nothing committed by status.
      const s = await status(c2, runId);
      expect(s["state"]).toBe("INTERRUPTED");
      expect(s["active_operation"]).toBeNull();
      expect((s["limitations"] as { code: string }[]).map((l) => l.code)).toContain("operation_owner_died");
      expect((await stateJson(f, runId)).operations.find((o) => o.operation_id === h["operation_id"])!.status).toBe("running");
      // The retried cancel of the dead operation applies recovery and reports its outcome.
      const stop = sc(await afterCrash(() => c2.call("stop_review_loop", { run_id: runId, mode: "cancel_active", expected_operation_id: h["operation_id"] as string })));
      expect((stop["cancellation"] as { outcome: string; operation_status: string }).outcome).toBe("already_finished");
      expect((stop["cancellation"] as { operation_status: string }).operation_status).toBe("interrupted");
      expect((stop["incidents"] as { kind: string }[]).map((i) => i.kind)).toContain("possible_surviving_sandboxed_commands");
      const st = await stateJson(f, runId);
      expect(st.reviews.at(-1)!.status).toBe("interrupted");
      expect(st.events.map((e) => e.type)).toContain("recovery.interrupted");
      // History survives the restart; a new review runs (not blocked by the incident).
      const hist = sc(await c2.call("get_review_history", { run_id: runId }));
      expect((hist["events"] as { type: string }[]).map((e) => e.type)).toContain("review.started");
      await setScenario(f, slowReviewScenario(0));
      const r = sc(await c2.call("review_with_codex", { run_id: runId, wait_seconds: 40 }));
      expect(r["status"]).toBe("completed");
    } finally {
      await c2.close();
    }
  }, 180_000);

  it("a server killed during a check: the worktree stays ownership_unresolved (MR-C) and status falls back to the last known source", async () => {
    const f = await mcpFixture();
    const c1 = await open(f, "v2-legacy");
    const runId = await newRunOver(c1, f);
    const h = sc(await c1.call("run_checks", { run_id: runId, checks: ["slow"], wait_seconds: 2 }));
    expect(h["status"]).toBe("running");
    taskkillHard(c1.pid!);
    await c1.close().catch(() => undefined);
    // taskkill /F returns once termination is requested, not once the process has exited: observe only after it has
    // (Phase 6 Increment 1, T1 run 5 — a status read in that window rightly saw a live owner and REVIEWING).
    expect(await waitUntil(() => !pidAlive(c1.pid!), 15_000)).toBe(true);
    const c2 = await open(f, "v2-modern");
    try {
      expect(errorCode(await afterCrash(() => c2.call("run_checks", { run_id: runId, checks: ["unit"] })))).toBe("WORKTREE_OWNERSHIP_UNRESOLVED");
      const s = await status(c2, runId);
      expect(s["state"]).toBe("INTERRUPTED");
      expect(s["current_source_recomputed"]).toBe(false);
      expect(s["current_source_id"]).toEqual(expect.stringMatching(/^[0-9a-f]{64}$/));
      expect((s["limitations"] as { code: string; detail: string }[]).find((l) => l.code === "current_source_note")!.detail).toContain("ownership_unresolved");
      // Reviews do not need the worktree lock while Codex runs, but their capture does:
      expect(errorCode(await c2.call("review_with_codex", { run_id: runId, wait_seconds: 20 }))).toBeNull();
    } finally {
      await c2.close();
    }
  }, 180_000);

  it("stdin close (host ends the session) cancels owned operations and records their outcome before exit", async () => {
    const f = await mcpFixture({ shutdownWaitMs: 20_000 });
    const c1 = await open(f, "v2-modern");
    const runId = await newRunOver(c1, f);
    const h = sc(await c1.call("run_checks", { run_id: runId, checks: ["slow"], wait_seconds: 2 }));
    expect(h["status"]).toBe("running");
    // The host closes stdin and waits: the server's own shutdown bound (20 s here) decides when
    // it exits. The SDK's close() would kill it 2 s after closing stdin, which on a loaded runner
    // cut the shutdown short and left the operation "running".
    expect(await c1.endSession(30_000)).toBe(0);
    const st = await stateJson(f, runId);
    const op = st.operations.find((o) => o.operation_id === h["operation_id"])!;
    expect(op.status).toBe("cancelled");
    expect(st.state).toBe("IDLE");
    // The worktree is free again: the next session runs checks.
    const c2 = await open(f, "v2-legacy");
    try {
      expect(sc(await c2.call("run_checks", { run_id: runId, wait_seconds: 30 }))["status"]).toBe("passed");
    } finally {
      await c2.close();
    }
  }, 150_000);
});
