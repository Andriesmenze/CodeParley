// Phase 2.1: implementer responses against real git repositories and the scripted fake Codex
// (shared contract: the same behaviour on Windows and Linux). Each disposition; what a response
// never changes; engine-owned records; stale tokens (a newer review, another response,
// concurrent callers); request_id replay; batch atomicity and fault injection; fix claims and
// the source they are bound to; re-review preserving the history (resolved, still present,
// superseded, new); a response recorded while a review runs; nothing new reaching Codex; caps;
// recovery and terminal runs.

import { describe, it, expect } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { startReview, buildReviewResult, type ReviewEngineContext, type ReviewRequest } from "../src/engine/review-operation.js";
import { startChecks } from "../src/engine/checks-operation.js";
import { responsesDocument } from "../src/engine/history.js";
import { clearProbeCache } from "../src/agents/codex/probe.js";
import { acquireWorktreeLock } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { applyRecovery, planRecovery } from "../src/store/recovery.js";
import { commitState, readState } from "../src/store/state-store.js";
import { uuidv7 } from "../src/common/ids.js";
import { RESPONSE_LIMITS, type ImplementerResponse } from "../src/schemas/responses.js";
import { approve } from "./helpers/checks-fixture.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, fakeCalls, lastExec, makeReviewFixture, newReviewRun, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";
import { aliasIn, itemNow, items, respond, respondContext, sourceNow } from "./helpers/respond-fixture.js";
import { respondToReview } from "../src/engine/respond.js";

async function review(ctx: ReviewEngineContext, req: ReviewRequest = {}) {
  return (await startReview(ctx, req)).completion;
}

async function expectCode(p: Promise<unknown>, code: string): Promise<Record<string, unknown>> {
  let err: unknown = null;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect((err as { code?: string } | null)?.code, `expected ${code}, got ${String((err as Error | null)?.message ?? "success")}`).toBe(code);
  return err as Record<string, unknown>;
}

async function fresh(): Promise<ReviewFixture> {
  clearProbeCache();
  return makeReviewFixture();
}

// Readers that await into a local first: an assignment from a parenthesized `(await f()).y`
// ends the enclosing function early in Lizard, Codacy's complexity tool.
async function revisionOf(ctx: ReviewEngineContext): Promise<number> {
  const st = await readState(ctx.runPaths);
  return st.revision;
}

async function recordedResponses(ctx: ReviewEngineContext) {
  const st = await readState(ctx.runPaths);
  return st.implementer_responses;
}

async function execCount(f: ReviewFixture): Promise<number> {
  const calls = await fakeCalls(f, "exec");
  return calls.length;
}

async function lastPrompt(f: ReviewFixture): Promise<string> {
  const call = await lastExec(f);
  return call.prompt!;
}

const ADD = "add() subtracts";
const OVERFLOW = "overflow risk";
const NIT = "naming nit";
const QUESTION = "Should add() accept strings?";

/** Round 1: an established defect, a serious risk, a style note (informational) and a blocking question. */
function round1() {
  return okScenario(
    output({
      findings: [defect(), defect({ title: OVERFLOW, severity: "high", claim_type: "risk", evidence: [] }), defect({ title: NIT, claim_type: "suggestion", category: "style", severity: "low", evidence: [] })],
      questions: [{ question: QUESTION, related_finding_index: 0, blocking: true }],
    }),
  );
}

async function setup(maxReviews = 10) {
  const f = await fresh();
  const { review: ctx, checks } = await newReviewRun(f, { maxReviews });
  await setScenario(f, round1());
  const r1 = await review(ctx);
  expect(r1.accepted).toBe(true);
  return { f, ctx, checks, r1 };
}

describe.skipIf(!supported)("implementer responses (Phase 2.1, shared contract)", () => {
  it("records each disposition as a separate implementer record and changes nothing else", async () => {
    const { f, ctx, r1 } = await setup();
    const before = await readState(ctx.runPaths);
    const execs = await execCount(f);
    const src0 = await sourceNow(ctx);
    const it = await items(ctx);
    // The review result itself carries the token and state of every tracked item.
    const fromResult = r1.findings.find((x) => x.title === ADD)!;
    expect(fromResult).toMatchObject({ discussion_state: "open", response_token: it.get(ADD)!.token, implementer_response: null });
    expect(r1.questions[0]).toMatchObject({ id: it.get(QUESTION)!.id, response_token: it.get(QUESTION)!.token, discussion_state: "open" });
    expect(r1.summary).toMatch(/respond_to_review/);

    const out = await respond(ctx, {
      responses: [
        { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "accepted", rationale: "" },
        { finding_id: it.get(OVERFLOW)!.id, response_token: it.get(OVERFLOW)!.token!, disposition: "disputed", rationale: "Inputs are bounded to 2^31 by the caller; no overflow can occur.", references: [{ path: "src\\math.js", start_line: 1, end_line: 3 }] },
        { finding_id: it.get(NIT)!.id, response_token: it.get(NIT)!.token!, disposition: "deferred", rationale: "Naming is out of scope for this change." },
        { finding_id: it.get(QUESTION)!.id, response_token: it.get(QUESTION)!.token!, disposition: "accepted", rationale: "No: numbers only; documented in the README." },
      ],
    });
    expect(out.deduplicated).toBe(false);
    // The result names items by id only (bounded: no reviewer text).
    const titleOf = new Map([...it].map(([title, x]) => [x.id, title]));
    expect(out.recorded.every((r) => !("title" in r))).toBe(true);
    expect(out.recorded.map((r) => [titleOf.get(r.finding_id), r.disposition, r.discussion_state])).toEqual([
      [ADD, "accepted", "accepted_unresolved"],
      [OVERFLOW, "disputed", "disputed"],
      [NIT, "deferred", "informational"],
      [QUESTION, "accepted", "accepted_unresolved"],
    ]);
    expect(out.summary).toContain("claim, not a resolution");
    expect(out.source.source_id).toBe(src0.source_id);
    for (const r of out.recorded) {
      expect(r.response_token).toMatch(/^[0-9a-f]{32}$/);
      expect(r.response_token).not.toBe(it.get(titleOf.get(r.finding_id)!)!.token); // the item's token moved on
      expect(r.answers_round).toBe(1);
      expect(r.source_id).toBe(src0.source_id);
    }

    const after = await readState(ctx.runPaths);
    // Separate records, recorded by the implementer through MCP, bound to round 1 and the source.
    expect(after.implementer_responses).toHaveLength(4);
    for (const rec of after.implementer_responses) {
      expect(rec).toMatchObject({ recorded_by: { role: "implementer", channel: "mcp" }, answers: { review_id: r1.review_id, round: 1 }, source: { source_id: src0.source_id, note: null }, supersedes: null, request_id: null });
    }
    expect(after.implementer_responses[1]!.references).toEqual([{ path: "src/math.js", start_line: 1, end_line: 3 }]);
    // Nothing else changed: reviewer items (text, triage, status, assessments), operations,
    // reviews, counters, run state; no Codex call; one event by the host; the tree untouched.
    expect(after.findings).toEqual(before.findings);
    expect(after.operations).toEqual(before.operations);
    expect(after.reviews).toEqual(before.reviews);
    expect(after.counters).toEqual(before.counters);
    expect(after.state).toBe(before.state);
    expect(after.revision).toBe(before.revision + 1);
    expect(after.events.slice(before.events.length)).toEqual([expect.objectContaining({ type: "review.responses_recorded", actor: "host" })]);
    expect((await fakeCalls(f, "exec")).length).toBe(execs);
    expect((await sourceNow(ctx)).source_id).toBe(src0.source_id);
    // Open items stay open: a response is a claim.
    expect((await buildReviewResult(ctx, r1.operation_id)).open_findings.map((x) => x.title).sort()).toEqual([ADD, OVERFLOW, QUESTION].sort());
  }, 120_000);

  it("fix claims are bound to the source they describe; a busy worktree refuses them, other responses record no source", async () => {
    const { f, ctx } = await setup();
    // Claimed without any change: recorded, and flagged — a review of that source cannot confirm it.
    let add = await itemNow(ctx, ADD);
    const same = await respond(ctx, { responses: [{ finding_id: add.id, response_token: add.token!, disposition: "fix_claimed", rationale: "fixed" }] });
    expect(same.recorded[0]!.notes.join(" ")).toMatch(/same source the reviewer last saw/);
    expect(same.recorded[0]!.discussion_state).toBe("fix_claimed_awaiting_verification");
    // The real fix: a new source, a new claim superseding the first one.
    await writeFile(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a + b;\n}\n");
    add = await itemNow(ctx, ADD);
    const fixed = await respond(ctx, { responses: [{ finding_id: add.id, response_token: add.token!, disposition: "fix_claimed", rationale: "return a + b" }] });
    expect(fixed.recorded[0]!.notes).toEqual([]);
    expect(fixed.recorded[0]!.supersedes).toBe(same.recorded[0]!.response_id);
    expect(fixed.recorded[0]!.source_id).not.toBe(same.recorded[0]!.source_id);

    // A check holds the worktree: the source cannot be read now.
    const lock = await acquireWorktreeLock(worktreeLockPath(ctx.dataHome, canonicalPathKey(ctx.meta.repository_root)), { owner: ctx.owner, operationId: "test-holds-the-worktree", kind: "checks" });
    try {
      const overflow = await itemNow(ctx, OVERFLOW);
      const revBefore = await revisionOf(ctx);
      await expectCode(respond(ctx, { responses: [{ finding_id: overflow.id, response_token: overflow.token!, disposition: "fix_claimed", rationale: "guarded" }] }), "SOURCE_UNAVAILABLE");
      expect((await readState(ctx.runPaths)).revision).toBe(revBefore); // nothing recorded
      const disputed = await respond(ctx, { responses: [{ finding_id: overflow.id, response_token: overflow.token!, disposition: "disputed", rationale: "bounded inputs" }] });
      expect(disputed.recorded[0]!.source_id).toBeNull();
      // The reason is reported once for the call, not repeated in every entry.
      expect(disputed.recorded[0]!.notes.join(" ")).toMatch(/source not recorded/);
      expect(disputed.source.note).toMatch(/not recomputed \(WORKTREE_BUSY\)/);
    } finally {
      await lock.release();
    }
  }, 120_000);

  it("stale tokens: another response, a newer review and concurrent callers are refused; nothing is applied to newer state", async () => {
    const { f, ctx } = await setup();
    const add0 = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: add0.id, response_token: add0.token!, disposition: "accepted", rationale: "" }] });
    // The same (now old) token again: the item changed (another response).
    const stale = await expectCode(respond(ctx, { responses: [{ finding_id: add0.id, response_token: add0.token!, disposition: "disputed", rationale: "changed my mind" }] }), "STALE_FINDING_STATE");
    expect(String(stale["message"])).toMatch(/read it again/);
    expect(JSON.stringify(stale["details"])).not.toContain((await itemNow(ctx, ADD)).token!); // never hands out the new token

    // Two callers race with the same token: exactly one is recorded.
    const ov = await itemNow(ctx, OVERFLOW);
    const race = await Promise.allSettled([
      respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "disputed", rationale: "caller A" }] }),
      respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "accepted", rationale: "caller B" }] }),
    ]);
    expect(race.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect((race.find((r) => r.status === "rejected") as PromiseRejectedResult).reason.code).toBe("STALE_FINDING_STATE");
    expect((await readState(ctx.runPaths)).implementer_responses.filter((r) => r.item_id === ov.id)).toHaveLength(1);

    // Round N+1 replaces the current review: round N's tokens are stale.
    const q = await itemNow(ctx, QUESTION);
    await setScenario(f, okScenario(output({ prior_findings: [] })));
    const r2 = await review(ctx, { force_new: true });
    expect(r2.accepted).toBe(true);
    await expectCode(respond(ctx, { responses: [{ finding_id: q.id, response_token: q.token!, disposition: "accepted", rationale: "" }] }), "STALE_FINDING_STATE");
    const q2 = await itemNow(ctx, QUESTION);
    expect(q2.token).not.toBe(q.token);
    const ok = await respond(ctx, { responses: [{ finding_id: q2.id, response_token: q2.token!, disposition: "accepted", rationale: "numbers only" }] });
    expect(ok.recorded[0]!.answers_round).toBe(2);
  }, 120_000);

  it("request_id: a retry returns the recorded result; other arguments conflict; a delayed duplicate never touches newer state", async () => {
    const { ctx } = await setup();
    const add = await itemNow(ctx, ADD);
    const req = { request_id: "resp-1", responses: [{ finding_id: add.id, response_token: add.token!, disposition: "disputed" as const, rationale: "intended" }] };
    const first = await respond(ctx, req);
    const rev = await revisionOf(ctx);
    const again = await respond(ctx, req);
    expect(again).toMatchObject({ deduplicated: true, response_set_id: first.response_set_id });
    expect(again.recorded.map((r) => r.response_id)).toEqual(first.recorded.map((r) => r.response_id));
    expect((await readState(ctx.runPaths)).revision).toBe(rev); // nothing written
    await expectCode(respond(ctx, { ...req, responses: [{ ...req.responses[0]!, rationale: "something else" }] }), "REQUEST_ID_CONFLICT");

    // A newer response; then the delayed duplicate arrives: still a replay, no new record, and the newer response stays the latest.
    const now = await itemNow(ctx, ADD);
    const newer = await respond(ctx, { responses: [{ finding_id: add.id, response_token: now.token!, disposition: "accepted", rationale: "convinced" }] });
    const late = await respond(ctx, req);
    expect(late.deduplicated).toBe(true);
    expect(late.recorded[0]!.superseded_by).toBe(newer.recorded[0]!.response_id);
    const st = await readState(ctx.runPaths);
    expect(st.implementer_responses.filter((r) => r.item_id === add.id).map((r) => r.disposition)).toEqual(["disputed", "accepted"]);
    expect((await itemNow(ctx, ADD)).state).toBe("accepted_unresolved");
  }, 120_000);

  it("a batch is atomic: one bad response refuses the whole call and every refusal is reported; fault injection before and after the commit", async () => {
    const { ctx } = await setup();
    const it = await items(ctx);
    const rev = await revisionOf(ctx);
    const err = await expectCode(
      respond(ctx, {
        responses: [
          { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "accepted", rationale: "" },
          { finding_id: it.get(OVERFLOW)!.id, response_token: "0".repeat(32), disposition: "disputed", rationale: "x" },
          { finding_id: uuidv7(), response_token: "x", disposition: "accepted", rationale: "" },
        ],
      }),
      "STALE_FINDING_STATE",
    );
    expect((err["details"] as { rejected: { index: number; code: string }[] }).rejected.map((r) => [r.index, r.code])).toEqual([
      [1, "STALE_FINDING_STATE"],
      [2, "FINDING_NOT_FOUND"],
    ]);
    expect((await readState(ctx.runPaths)).revision).toBe(rev);
    // Semantics the schema cannot express: INVALID_ARGUMENT, nothing recorded.
    await expectCode(respond(ctx, { responses: [{ finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "disputed", rationale: " " }] }), "INVALID_ARGUMENT");

    // A crash just before the commit point: nothing recorded.
    const add = { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "accepted" as const, rationale: "" };
    await expect(respond(ctx, { request_id: "crash-1", responses: [add] }, { hooks: { beforeWrite: () => { throw new Error("injected crash before the commit"); } } })).rejects.toThrow(/injected/);
    const st1 = await readState(ctx.runPaths);
    expect(st1.revision).toBe(rev);
    expect(st1.implementer_responses).toEqual([]);
    // A crash after the commit (the response is lost): the retry with the same request_id returns what was recorded.
    await expect(respond(ctx, { request_id: "crash-2", responses: [add] }, { hooks: { afterCommit: () => { throw new Error("injected crash after the commit"); } } })).rejects.toThrow(/injected/);
    expect((await readState(ctx.runPaths)).implementer_responses).toHaveLength(1);
    const retried = await respond(ctx, { request_id: "crash-2", responses: [add] });
    expect(retried.deduplicated).toBe(true);
    expect((await readState(ctx.runPaths)).implementer_responses).toHaveLength(1);
  }, 120_000);

  it("only reviewer items can be responded to: engine conditions, incidents, unaccepted reviews' items, superseded and resolved items are refused", async () => {
    const f = await fresh();
    const counter = join(f.scratch, "flaky-counter");
    await approve(f, { checks: { flaky: { argv: ["node", "scripts/flaky.js", counter] } }, profiles: { default: ["flaky"] }, required_profiles: ["default"] });
    const { review: ctx, checks } = await newReviewRun(f, { maxReviews: 10 });
    expect((await (await startChecks(checks, {})).completion).status).toBe("failed"); // an engine condition
    await setScenario(f, round1());
    const r1 = await review(ctx);
    expect(r1.conditions.map((c) => c.kind)).toContain("check_failed");
    // An isolation incident (engine-owned audit record), written as the engine writes them.
    const incidentId = uuidv7();
    await commitState(ctx.runPaths, ctx.owner, (st) => {
      st.isolation_incidents.push({ incident_id: incidentId, review_id: r1.review_id, operation_id: r1.operation_id, kind: "cancellation_unconfirmed", detail: "test incident", at: new Date().toISOString(), source: "engine" });
      return st;
    });
    for (const id of ["flaky", "check_failed", "check_failed:flaky", "excluded_changed_file", "PF-1", incidentId, uuidv7()]) {
      const e = await expectCode(respond(ctx, { responses: [{ finding_id: id, response_token: "x", disposition: "disputed", rationale: "the engine is wrong" }] }), "FINDING_NOT_FOUND");
      if (id === incidentId) expect(String(e["message"])).toMatch(/isolation incident/);
    }
    // A review that was not accepted (stale output): its items are audit-only and tracked nowhere.
    await setScenario(f, okScenario(output({ findings: [defect({ title: "from a stale review" })] }), { touch_on_start: join(f.repo, "src", "math.js") }));
    const stale = await review(ctx, { force_new: true });
    expect(stale.accepted).toBe(false);
    const notAccepted = stale.findings.find((x) => x.title === "from a stale review")!;
    expect(notAccepted.response_token).toBeUndefined(); // no discussion fields for untracked items
    await expectCode(respond(ctx, { responses: [{ finding_id: notAccepted.id, response_token: "x", disposition: "accepted", rationale: "" }] }), "FINDING_NOT_FOUND");

    // Superseded and reviewer-resolved items: closed for responses (no redirect to the new item).
    await writeFile(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a + b;\n}\n");
    const prompt = await lastPrompt(f);
    await setScenario(
      f,
      okScenario(
        output({
          findings: [defect({ title: "overflow for large ints", severity: "critical", evidence: [{ kind: "code_reference", detail: "a + b", path: "src/math.js", start_line: 2, end_line: 2 }] })],
          prior_findings: [
            { id: aliasIn(prompt, ADD), assessment: "apparently_resolved", superseded_by_index: null, note: "fixed" },
            { id: aliasIn(prompt, OVERFLOW), assessment: "superseded", superseded_by_index: 0, note: "more precise" },
          ],
        }),
      ),
    );
    const r3 = await review(ctx);
    expect(r3.accepted).toBe(true);
    const st = await readState(ctx.runPaths);
    const add = st.findings.find((x) => x.title === ADD)!;
    const ov = st.findings.find((x) => x.title === OVERFLOW)!;
    expect([add.status, ov.status]).toEqual(["reported_resolved", "superseded"]);
    const e1 = await expectCode(respond(ctx, { responses: [{ finding_id: ov.id, response_token: "x", disposition: "disputed", rationale: "x" }] }), "FINDING_NOT_RESPONDABLE");
    expect(String(e1["message"])).toContain(ov.superseded_by!);
    await expectCode(respond(ctx, { responses: [{ finding_id: add.id, response_token: "x", disposition: "fix_claimed", rationale: "x" }] }), "FINDING_NOT_RESPONDABLE");
    expect((await readState(ctx.runPaths)).implementer_responses).toEqual([]);
  }, 150_000);

  it("re-review preserves the response history: resolved after a fix claim, superseded with a dispute, still present, and a new finding inherits nothing", async () => {
    const { f, ctx } = await setup();
    // The implementer fixes add(), disputes the overflow risk and answers the question.
    await writeFile(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a + b;\n}\n");
    const it = await items(ctx);
    await respond(ctx, {
      responses: [
        { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "fix_claimed", rationale: "now returns a + b", references: [{ path: "src/math.js", start_line: 2 }] },
        { finding_id: it.get(OVERFLOW)!.id, response_token: it.get(OVERFLOW)!.token!, disposition: "disputed", rationale: "JavaScript numbers do not overflow here." },
        { finding_id: it.get(QUESTION)!.id, response_token: it.get(QUESTION)!.token!, disposition: "accepted", rationale: "numbers only" },
      ],
    });
    const responsesBefore = await recordedResponses(ctx);
    // Round 2 presents the open items oldest first (round, then the order round 1 listed them).
    await setScenario(
      f,
      okScenario(
        output({
          findings: [
            defect({ title: "overflow for large ints", severity: "critical", evidence: [{ kind: "code_reference", detail: "a + b", path: "src/math.js", start_line: 2, end_line: 2 }] }),
            defect({ title: "missing tests", severity: "high", claim_type: "risk", category: "testing", impacts: ["reliability"], evidence: [] }),
          ],
          prior_findings: [
            { id: "PF-1", assessment: "apparently_resolved", superseded_by_index: null, note: "now adds" },
            { id: "PF-2", assessment: "superseded", superseded_by_index: 0, note: "more precise" },
            { id: "PF-3", assessment: "still_present", superseded_by_index: null, note: "" },
          ],
        }),
      ),
    );
    const r2 = await review(ctx);
    expect(r2.accepted).toBe(true);
    const prompt2 = await lastPrompt(f);
    expect([aliasIn(prompt2, ADD), aliasIn(prompt2, OVERFLOW), aliasIn(prompt2, QUESTION)]).toEqual(["PF-1", "PF-2", "PF-3"]);
    const st = await readState(ctx.runPaths);
    // The review changed reviewer state only; every response is still there, unchanged.
    expect(st.implementer_responses).toEqual(responsesBefore);
    const byTitle = (t: string) => r2.prior_items.find((p) => p.title === t)!;
    expect(byTitle(ADD)).toMatchObject({ status: "reported_resolved", assessment: "apparently_resolved", discussion_state: "reviewer_resolved", response_before_review: { disposition: "fix_claimed" } });
    expect(byTitle(OVERFLOW)).toMatchObject({ status: "superseded", discussion_state: "superseded", response_before_review: { disposition: "disputed" } });
    expect(byTitle(QUESTION)).toMatchObject({ status: "open", assessment: "still_present", discussion_state: "accepted_unresolved", response_before_review: { disposition: "accepted" } });
    // Phase 2.2: round 2 was shown these responses (the fix claim and the dispute asked for a
    // reply, the question's answer was context); the scripted reviewer gave no discussion reply.
    expect(r2.limitations.map((l) => l.code)).not.toContain("responses_not_delivered");
    expect(r2.limitations.map((l) => l.code)).toContain("discussion_reply_missing");
    expect(byTitle(ADD)).toMatchObject({ presented_in_this_review: true, response_seen_by_reviewer: true, reviewer_reply: null });
    expect(r2.discussion).toMatchObject({ presented: 3, reply_sought: 2, context: 1, replies_recorded: true });
    // The superseding item is a new item: no response of its own, the predecessor's dispute shown beside it.
    const successor = r2.findings.find((x) => x.title === "overflow for large ints")!;
    expect(successor).toMatchObject({ discussion_state: "open", implementer_response: null });
    expect(successor.responses_to_superseded_items).toEqual([expect.objectContaining({ item_id: it.get(OVERFLOW)!.id, disposition: "disputed" })]);
    // A genuinely new finding starts open.
    expect(r2.findings.find((x) => x.title === "missing tests")).toMatchObject({ discussion_state: "open", implementer_response: null });
    // The question's acceptance predates the reviewer's later view: shown as such.
    const q = r2.open_findings.find((x) => x.title === QUESTION)!;
    expect(q.implementer_response).toMatchObject({ disposition: "accepted", stale_reasons: expect.arrayContaining(["reviewed_since_response"]) });

    // Round 3: the implementer claims the successor fixed; the reviewer still finds it present.
    await writeFile(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return Number(a) + Number(b);\n}\n");
    const succ = await itemNow(ctx, "overflow for large ints");
    await respond(ctx, { responses: [{ finding_id: succ.id, response_token: succ.token!, disposition: "fix_claimed", rationale: "coerced" }] });
    // Open now: the question (round 1) is PF-1, the successor (round 2) PF-2.
    await setScenario(f, okScenario(output({ prior_findings: [{ id: "PF-2", assessment: "still_present", superseded_by_index: null, note: "still unbounded" }] })));
    const r3 = await review(ctx);
    expect(r3.accepted).toBe(true);
    expect(aliasIn((await lastExec(f)).prompt!, "overflow for large ints")).toBe("PF-2");
    const after3 = r3.open_findings.find((x) => x.title === "overflow for large ints")!;
    expect(after3.discussion_state).toBe("fix_not_confirmed");
    expect(after3.implementer_response).toMatchObject({ disposition: "fix_claimed", stale_reasons: expect.arrayContaining(["reviewed_since_response"]) });
    expect(r3.prior_items.find((p) => p.title === "overflow for large ints")).toMatchObject({ response_before_review: { disposition: "fix_claimed" }, discussion_state: "fix_not_confirmed" });

    // The history document keeps every response with the reviewer's later view, oldest first.
    const doc = responsesDocument(await readState(ctx.runPaths)) as { items: { title: string; reviewer_status: string; responses: { disposition: string; reviewed_since: boolean }[]; reviewer_assessments: { assessment: string }[] }[] };
    const hist = (t: string) => doc.items.find((x) => x.title === t)!;
    expect(hist(ADD)).toMatchObject({ reviewer_status: "reported_resolved", responses: [{ disposition: "fix_claimed", reviewed_since: true }] });
    expect(hist(OVERFLOW).responses.map((r) => r.disposition)).toEqual(["disputed"]);
    expect(hist("overflow for large ints").reviewer_assessments.map((a) => a.assessment)).toEqual(["still_present"]);
    const lineage = responsesDocument(await readState(ctx.runPaths), it.get(OVERFLOW)!.id) as { items: { title: string }[] };
    expect(lineage.items.map((x) => x.title)).toEqual([OVERFLOW, "overflow for large ints"]);
  }, 180_000);

  it("race with a running review: refused with RUN_BUSY during Codex, right before the review's completion commit and after a slow source read; the completion keeps every earlier response", async () => {
    const { f, ctx } = await setup();
    // A response recorded before the review (with a request_id), which the review must not lose.
    const add0 = await itemNow(ctx, ADD);
    const before = { request_id: "before-review", responses: [{ finding_id: add0.id, response_token: add0.token!, disposition: "accepted" as const, rationale: "" }] };
    const r0 = await respond(ctx, before);
    const ov0 = await itemNow(ctx, OVERFLOW);
    const attempt = () => respond(ctx, { responses: [{ finding_id: ov0.id, response_token: ov0.token!, disposition: "disputed", rationale: "during the review" }] });
    // Round 2 presents the open items oldest first: add() is PF-1, the overflow risk PF-2.
    await setScenario(f, okScenario(output({ prior_findings: [{ id: "PF-1", assessment: "still_present", superseded_by_index: null, note: "" }, { id: "PF-2", assessment: "still_present", superseded_by_index: null, note: "" }] }), { sleep_ms: 2500 }));
    // The attempt that races the completion: issued right before the review's single completion commit.
    let atCompletion: string | null = "not attempted";
    ctx.testHooks!.beforeCompletionCommit = async () => {
      atCompletion = await attempt().then(() => null, (e: { code?: string }) => e.code ?? "error");
    };
    const started = await startReview(ctx, { force_new: true });
    for (let i = 0; i < 100 && (await readState(ctx.runPaths)).reviews.length < 2; i++) await new Promise((r) => setTimeout(r, 100));
    // While Codex runs: refused, nothing recorded; a replay of a recorded request records nothing and is answered.
    const during = await expectCode(attempt(), "RUN_BUSY");
    expect(during["retryable"]).toBe(true);
    expect((during["details"] as { operation_id: string }).operation_id).toBe(started.operation_id);
    expect((await respond(ctx, before)).deduplicated).toBe(true);
    const r2 = await started.completion;
    expect(r2.accepted).toBe(true);
    expect(atCompletion).toBe("RUN_BUSY");
    const st = await readState(ctx.runPaths);
    // Exactly the response recorded before the review; the completion commit lost and added nothing.
    expect(st.implementer_responses).toEqual((await readState(ctx.runPaths)).implementer_responses);
    expect(st.implementer_responses.map((r) => r.response_id)).toEqual([r0.recorded[0]!.response_id]);
    expect(r2.open_findings.find((x) => x.title === ADD)!.implementer_response).toMatchObject({ response_id: r0.recorded[0]!.response_id, stale_reasons: ["reviewed_since_response"] });
    expect(r2.open_findings.find((x) => x.title === OVERFLOW)!.implementer_response).toBeNull();
    // Afterwards the pre-review token is stale (the review assessed the item); the new one works.
    await expectCode(attempt(), "STALE_FINDING_STATE");
    const ov2 = await itemNow(ctx, OVERFLOW);
    expect((await respond(ctx, { responses: [{ finding_id: ov2.id, response_token: ov2.token!, disposition: "disputed", rationale: "after the review" }] })).recorded[0]!.answers_round).toBe(2);

    // A review that starts while a call reads the source (after its first check) is caught inside the commit.
    await setScenario(f, okScenario(output({ prior_findings: [] }), { sleep_ms: 1500 }));
    const q = await itemNow(ctx, QUESTION);
    let r3: Promise<unknown> = Promise.resolve();
    let startError: unknown = null;
    // The "source read" starts a review and returns once that review is past its capture (Codex
    // running). It does not read the tree itself: a read would hold the worktree lock and make
    // the review's capture fail (WORKTREE_BUSY, a known M1 collision between captures).
    const startsAReview = async (): Promise<{ source_id: string | null; note: string | null }> => {
      try {
        const s = await startReview(ctx, { force_new: true });
        r3 = s.completion;
        for (let i = 0; i < 100 && (await readState(ctx.runPaths)).reviews.length < 3; i++) await new Promise((r) => setTimeout(r, 100));
      } catch (e) {
        startError = e;
      }
      return { source_id: null, note: "not read in this test" };
    };
    const raced = respond(ctx, { responses: [{ finding_id: q.id, response_token: q.token!, disposition: "accepted", rationale: "" }] }, { source: startsAReview });
    await raced.catch(() => undefined);
    expect(startError).toBeNull();
    await expectCode(raced, "RUN_BUSY");
    await r3;
    expect((await readState(ctx.runPaths)).implementer_responses.filter((r) => r.item_id === q.id)).toEqual([]);
  }, 150_000);

  it("a review whose server died does not block responses; one whose server may still live does", async () => {
    const { ctx } = await setup();
    const opId = uuidv7();
    await commitState(ctx.runPaths, ctx.owner, (st) => {
      st.operations.push({ operation_id: opId, kind: "review", status: "running", owner: { serverInstanceId: "elsewhere", pid: 999_999, startedAtMs: 1 }, started_at: new Date().toISOString() });
      st.state = "REVIEWING";
      return st;
    });
    const add = await itemNow(ctx, ADD);
    const one = { responses: [{ finding_id: add.id, response_token: add.token!, disposition: "accepted" as const, rationale: "" }] };
    const unconfirmed = await expectCode(respondToReview({ ...respondContext(ctx), classify: async () => "alive_unconfirmed" }, one), "RUN_BUSY");
    expect((unconfirmed["details"] as { operation_id: string }).operation_id).toBe(opId);
    const out = await respondToReview({ ...respondContext(ctx), classify: async () => "dead" }, one);
    expect(out.recorded).toHaveLength(1);
    // The dead server's review is untouched by the response (recovery records it later).
    expect((await readState(ctx.runPaths)).operations.find((o) => o.operation_id === opId)!.status).toBe("running");
  }, 120_000);

  it("responses reach Codex only inside the next review: respond runs nothing, and the next review is a new input whose prompt carries them (Phase 2.2, P2.2-4, -5)", async () => {
    const { f, ctx, r1 } = await setup();
    const it = await items(ctx);
    const execs = await execCount(f);
    await respond(ctx, {
      responses: [
        { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "disputed", rationale: "ZEBRA-RATIONALE-MARKER the subtraction is intended" },
        { finding_id: it.get(OVERFLOW)!.id, response_token: it.get(OVERFLOW)!.token!, disposition: "deferred", rationale: "OKAPI-DEFERRAL-MARKER later" },
      ],
    });
    // Recording a response starts nothing (P2.2: no automatic rounds).
    expect((await fakeCalls(f, "exec")).length).toBe(execs);
    // Same source, same evidence, different discussion: a new input — no identical-input dedupe.
    await setScenario(f, okScenario(output({ prior_findings: [] })));
    const r2 = await review(ctx);
    expect(r2.deduplicated).toBe(false);
    expect(r2.review_input_id).not.toBe(r1.review_input_id);
    expect((await fakeCalls(f, "exec")).length).toBe(execs + 1);
    const prompt = await lastPrompt(f);
    for (const marker of ["ZEBRA-RATIONALE-MARKER", "OKAPI-DEFERRAL-MARKER"]) expect(prompt, marker).toContain(marker);
    // Engine bookkeeping never reaches the reviewer.
    for (const marker of ["response_token", "response_id", it.get(ADD)!.id]) expect(prompt, marker).not.toContain(marker);
  }, 120_000);

  it("limits: at most 20 responses per item and 1000 per run (BUDGET_EXHAUSTED, nothing recorded)", async () => {
    const { ctx } = await setup();
    const add = await itemNow(ctx, ADD);
    let token = add.token!;
    for (let i = 0; i < RESPONSE_LIMITS.perItem; i++) {
      const res = await respond(ctx, { responses: [{ finding_id: add.id, response_token: token, disposition: i % 2 ? "accepted" : "disputed", rationale: `round ${i}` }] });
      token = res.recorded[0]!.response_token!;
    }
    const e = await expectCode(respond(ctx, { responses: [{ finding_id: add.id, response_token: token, disposition: "accepted", rationale: "one too many" }] }), "BUDGET_EXHAUSTED");
    expect(e["details"]).toMatchObject({ limit: "responses_per_item", max: 20 });
    // Per run: fill up to the limit with synthetic records, then a batch that would cross it.
    await commitState(ctx.runPaths, ctx.owner, (st) => {
      const base = st.implementer_responses[0]!;
      const filler: ImplementerResponse[] = Array.from({ length: RESPONSE_LIMITS.perRun - st.implementer_responses.length - 1 }, () => ({ ...base, item_id: uuidv7(), response_id: uuidv7() }));
      st.implementer_responses.push(...filler);
      return st;
    });
    const ov = await itemNow(ctx, OVERFLOW);
    const q = await itemNow(ctx, QUESTION);
    const e2 = await expectCode(
      respond(ctx, {
        responses: [
          { finding_id: ov.id, response_token: ov.token!, disposition: "accepted", rationale: "" },
          { finding_id: q.id, response_token: q.token!, disposition: "accepted", rationale: "" },
        ],
      }),
      "BUDGET_EXHAUSTED",
    );
    expect(e2["details"]).toMatchObject({ limit: "responses_per_run" });
    expect((await readState(ctx.runPaths)).implementer_responses).toHaveLength(RESPONSE_LIMITS.perRun - 1);
  }, 120_000);

  it("recovery of a dead owner keeps every response; a terminal run refuses new ones", async () => {
    const { ctx } = await setup();
    const add = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: add.id, response_token: add.token!, disposition: "deferred", rationale: "next change" }] });
    // A review operation whose server died (as recovery finds it).
    await commitState(ctx.runPaths, ctx.owner, (st) => {
      st.operations.push({ operation_id: uuidv7(), kind: "review", status: "running", owner: { serverInstanceId: "gone", pid: 999_999, startedAtMs: 1 }, started_at: new Date().toISOString() });
      st.state = "REVIEWING";
      return st;
    });
    const before = await recordedResponses(ctx);
    const plan = await planRecovery(await readState(ctx.runPaths), async () => "dead");
    await applyRecovery(ctx.runPaths, ctx.owner, plan, null, { classifyChild: async () => "dead", linkedDescendants: async () => [] });
    const st = await readState(ctx.runPaths);
    expect(st.state).toBe("INTERRUPTED");
    expect(st.implementer_responses).toEqual(before);
    // INTERRUPTED is not terminal: responses can still be recorded.
    const ov = await itemNow(ctx, OVERFLOW);
    await respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "accepted", rationale: "" }] });
    await commitState(ctx.runPaths, ctx.owner, (s) => ({ ...s, state: "CLOSED" }));
    const q = await itemNow(ctx, QUESTION);
    await expectCode(respond(ctx, { responses: [{ finding_id: q.id, response_token: q.token!, disposition: "accepted", rationale: "" }] }), "RUN_TERMINAL");
  }, 120_000);
});
