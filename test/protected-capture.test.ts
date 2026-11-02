// P3.4C-5 Increment 2 (contract §3.1–§3.3): a PROTECTED review is captured and published by the custodian. The engine
// reserves the review (op_begin: `measuring`), waits for the custodian's capture (`captured`: the source id, the capture,
// manifest and export digests and the review input identity are the custodian's), builds the prompt from the published
// capture, runs Codex on the PUBLISHED export, and finishes with the prompt digest and what it presented; the custodian
// re-hashes the export before deciding acceptance. Each case runs the real engine against the simulated custodian over
// two account-bound transports (the engine on the implementer pipe, the operator's CLI on the operator pipe); the
// simulated custodian captures with the engine's own helper capture code, in process.

import { describe, it, expect } from "vitest";
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { sha256OfBytes } from "../src/common/hash.js";
import { readState } from "../src/store/state-store.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { requestReviewCancel, type ReviewOperationResult } from "../src/engine/review-operation.js";
import { startChecksOperation } from "../src/engine/operations.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, lastExec, okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, grant, HostSession, newRun, operatorIo, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const key = (p: string): string => (process.platform === "win32" ? p.replace(/\//g, "\\").toLowerCase() : p);

async function protectedRun(f: ContFixture, pid = 7401): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, `sess-${pid}`, pid).startLoop(run);
  return run;
}

/** A review operation's completion carries its result. */
async function resultOf(done: Promise<unknown>): Promise<ReviewOperationResult> {
  return ((await done) as { result: ReviewOperationResult }).result;
}
async function reviewed(started: Promise<{ done: Promise<unknown> }>): Promise<ReviewOperationResult> {
  return resultOf((await started).done);
}

const held = (f: ContFixture, run: RunHandle) => f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!;

/** Wait until the custodian holds the run's latest review operation as measuring (manual helper). */
async function measuringOp(f: ContFixture, run: RunHandle): Promise<string> {
  for (let i = 0; i < 400; i++) {
    const op = held(f, run)?.operations.filter((o) => o.kind === "review").at(-1);
    if (op?.status === "measuring") return op.operationId;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("the review was never reserved");
}

describe.skipIf(!supported)("P3.4C-5 Increment 2 — the custodian captures and publishes a protected review", () => {
  it("§3.1: reserve → custodian capture and publication → captured → prompt from the published capture → Codex on the published export → op_finish re-hashes and accepts", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    const result = await reviewed(startReview(f, run));
    expect(result.status).toBe("completed");
    expect(result.accepted).toBe(true);

    const h = held(f, run);
    const review = h.reviews.at(-1)!;
    const begin = review.begin as Record<string, unknown>;
    const cc = begin["custodianCapture"] as Record<string, string>;
    expect(review.accepted).toBe(true);
    // The custodian committed the capture itself (a custodian event under its ticket), then the engine finished.
    expect(h.events.map((e) => [e.kind, e.caller])).toEqual(expect.arrayContaining([["op_begin", "implementer"], ["capture", "custodian"], ["op_finish", "implementer"]]));
    expect(h.events.find((e) => e.kind === "op_begin" && e.result?.["reviewId"])?.result?.["operationStatus"]).toBe("measuring");
    // The engine's record carries the custodian's identities and the published export.
    const local = (await readState(run.paths)).reviews.at(-1)!;
    expect(local.source_id).toBe(begin["sourceId"]);
    expect(local.review_input_id).toBe(begin["reviewInputId"]);
    expect(local.export_digest).toBe(begin["exportDigest"]);
    expect(local.manifest_digest).toBe(begin["manifestDigest"]);
    expect(key(local.export_ref)).toBe(key(cc["exportPath"]!));
    // The local capture record is the published one, byte for byte (its digest is the custodian's).
    expect(sha256OfBytes(readFileSync(resolveArtifact(run.paths.runDir, local.artifacts["capture"]!)))).toBe(begin["captureDigest"]);
    // Codex ran on the published export (D-17 production path; the reviewer's root is the custodian's export).
    const exec = await lastExec(f);
    expect(key(exec.argv[exec.argv.indexOf("--cd") + 1]!)).toBe(key(cc["exportPath"]!));
    expect(key(exec.cwd)).toBe(key(cc["exportPath"]!));
    // N5-16: the prompt digest arrived only with op_finish; the custodian re-hashed the export it published.
    expect(begin["promptDigest"]).toBeUndefined();
    const outcome = review.outcome as Record<string, unknown>;
    expect(outcome["promptDigest"]).toBe(local.prompt.sha256);
    expect((outcome["exportRehash"] as Record<string, unknown>)["unchanged"]).toBe(true);
    // The capture record sits beside the export, outside the reviewer's root.
    expect(key(join(cc["exportPath"]!, ".."))).toBe(key(join(cc["capturePath"]!, "..")));
  }, 240_000);

  it("N5-16: the same inputs again are deduplicated at the custodian's commit — nothing runs, the budget is released", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    const first = await reviewed(startReview(f, run));
    expect(first.accepted).toBe(true);
    const execs = (await readState(run.paths)).reviews.length;
    const second = await reviewed(startReview(f, run));
    expect(second.deduplicated || second.review_id === first.review_id).toBe(true);
    const h = held(f, run);
    expect(h.operations.filter((o) => o.kind === "review").map((o) => o.status)).toEqual(["completed", "deduplicated"]);
    expect(h.reviews.length).toBe(1);
    expect((await readState(run.paths)).reviews.length).toBe(execs);
  }, 240_000);

  it("N5-3: a published file changed during the review — the custodian's own re-hash at op_finish makes it not accepted", async () => {
    const f = await contFixture(okScenario(output({ findings: [defect()] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    f.le.env.testHooks!.review!.afterCodex = () => {
      const op = held(f, run).operations.filter((o) => o.kind === "review").at(-1)!;
      const exportPath = (op.begin["custodianCapture"] as Record<string, string>)["exportPath"]!;
      appendFileSync(join(exportPath, "review", "manifest.json"), " ");
    };
    const result = await reviewed(startReview(f, run));
    expect(result.accepted).toBe(false);
    const review = held(f, run).reviews.at(-1)!;
    expect(review.accepted).toBe(false);
    expect(review.notAcceptedReasons).toContain("incident:export_modified_during_review");
    expect(held(f, run).incidents.some((i) => i.kind === "export_modified_during_review" && i.source === "custodian")).toBe(true);
  }, 240_000);

  it("§6: without an approved engine runtime the reservation is refused (RUNTIME_NOT_APPROVED, with the operator command); nothing is reviewed", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    const run = await protectedRun(f);
    await runChecks(f, run);
    const listed = await cli(f, ["config", "show", "--repo", f.repo, "--json"]);
    const runtimeId = String((JSON.parse(listed.out) as { engineRuntime: { runtimeId: string } }).engineRuntime.runtimeId);
    const revoked = await cli(f, ["config", "revoke-runtime", "--repo", f.repo, runtimeId], operatorIo("confirm"));
    expect(revoked.code).toBe(0);
    const result = await reviewed(startReview(f, run));
    expect(result.failure?.code).toBe("RUNTIME_NOT_APPROVED");
    expect(result.failure?.detail).toContain("code-parley config approve-runtime");
    expect(held(f, run).reviews.length).toBe(0);
  }, 240_000);

  it("§6: a custodian without the capture helper refuses the reservation (HELPER_UNAVAILABLE); there is no fallback to the engine's capture", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true, helper: "none" });
    const run = await protectedRun(f);
    // P3.4C-5 Increment 3 (§4): a protected checks operation is measured by the same helper — refused too, nothing begun.
    await expect(startChecksOperation(f.le, run, {})).rejects.toMatchObject({ code: "HELPER_UNAVAILABLE" });
    expect(held(f, run).operations.length).toBe(0);
    const result = await reviewed(startReview(f, run));
    expect(result.failure?.code).toBe("HELPER_UNAVAILABLE");
    expect(held(f, run).reviews.length).toBe(0);
  }, 240_000);

  it("§2.4: a capture of another source than the one selected ends the operation (source_changed) and releases the budget; the engine reports it, retryable", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true, helper: "manual" });
    const run = await protectedRun(f);
    await runChecks(f, run);
    const s = await startReview(f, run);
    const op = await measuringOp(f, run);
    const committed = await f.custodian.runReservedCapture(op, { sourceId: "e".repeat(64) });
    expect(committed).toMatchObject({ operationStatus: "error", reason: "source_changed" });
    const result = await resultOf(s.done);
    expect(result.failure?.code).toBe("REVIEW_CAPTURE_FAILED");
    expect(held(f, run).reviews.length).toBe(0);
    expect(held(f, run).operations.at(-1)?.status).toBe("error");
  }, 240_000);

  it("§2.4: a review cancelled while the custodian captures is abandoned — the measurement is cancelled, the budget released, a late result not recorded", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true, helper: "manual" });
    const run = await protectedRun(f);
    await runChecks(f, run);
    const s = await startReview(f, run);
    const op = await measuringOp(f, run);
    expect(requestReviewCancel(s.operationId)).toBe("cancellation_requested");
    const result = await resultOf(s.done);
    expect(result.status === "cancelled" || result.operation_status === "cancelled").toBe(true);
    expect(held(f, run).operations.find((o) => o.operationId === op)?.status).toBe("cancelled");
    expect(held(f, run).reviews.length).toBe(0);
    expect(await f.custodian.runReservedCapture(op)).toEqual({ recorded: false });
  }, 240_000);
});
