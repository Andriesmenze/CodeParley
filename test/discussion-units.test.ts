// Phase 2.2 unit tests (platform-independent, plan §1.15): the discussion as pure policy —
// threads over lineage (supersession, restatement, consolidation; cycles, dangling links and
// bounds), "seen" only through accepted deliveries, exchange budgets that follow the lineage,
// the new-information gate, escalation, the reviewer's structured replies, response tokens that
// cover the thread, and what the bundle presents (and binds into its digest).

import { describe, it, expect } from "vitest";
import {
  buildDiscussionIndex,
  checkResultsDigest,
  gateBases,
  planDiscussion,
  processReplies,
  seenBy,
  stanceConflict,
  threadOfItem,
  type DiscussionIndex,
  type ReviewLike,
} from "../src/policy/discussion.js";
import { threadReport } from "../src/policy/discussion-reports.js";
import { buildThreads, itemPositions } from "../src/policy/threads.js";
import { responseToken, respondable } from "../src/policy/responses.js";
import { buildBundle, discussionDigest, type BundleInput } from "../src/policy/review-bundle.js";
import { DISCUSSION_LIMITS, type Delivery, type ReviewerReply } from "../src/schemas/discussion.js";
import type { ImplementerResponse } from "../src/schemas/responses.js";
import type { ReviewerItem } from "../src/schemas/review.js";
import type { ReviewManifest } from "../src/schemas/capture.js";
import { DiscussionReplyOutSchema, ReviewOutputSchema } from "../src/schemas/review.js";

const H = (c: string) => c.repeat(64);
const S1 = H("1");
const S2 = H("2");
const EV = H("e");

function item(id: string, over: Partial<ReviewerItem> = {}): ReviewerItem {
  return {
    id,
    item_kind: "finding",
    review_id: "r1",
    round: 1,
    source_id: S1,
    review_input_id: H("b"),
    title: `finding ${id}`,
    claim_type: "defect",
    severity: "high",
    category: "correctness",
    impacts: ["correctness"],
    consequence: "c",
    confidence: "high",
    evidence: [],
    investigation: "",
    recommended_change: "",
    triage: "established_defect",
    basis: "reviewer_evidence",
    policy_notes: [],
    status: "open",
    related_prior_id: null,
    supersedes: [],
    superseded_by: null,
    assessments: [],
    created_at: "2026-10-06T00:00:00Z",
    ...over,
  };
}

let n = 0;
function turn(itemId: string, over: Partial<ImplementerResponse> & { after?: string } = {}): ImplementerResponse {
  n++;
  const { after, ...rest } = over;
  return {
    response_id: `resp-${n}`,
    item_id: itemId,
    disposition: "disputed",
    rationale: `argument ${n}`,
    references: [],
    answers: { review_id: after ?? "r1", round: 1, token: "t", run_review_id: after ?? "r1", run_round: 1, reviewer_reply_id: null },
    source: { source_id: S1, note: null },
    disclosure_ref: null,
    text_withheld: false,
    supersedes: null,
    recorded_by: { role: "implementer", channel: "mcp" },
    response_set_id: `set-${n}`,
    request_id: null,
    request_digest: H("d"),
    recorded_at: "2026-10-06T00:00:00Z",
    ...rest,
  };
}

function reply(itemId: string, reviewId: string, round: number, answers: string | null, over: Partial<ReviewerReply> = {}): ReviewerReply {
  n++;
  return {
    reply_id: `reply-${n}`,
    item_id: itemId,
    review_id: reviewId,
    round,
    stance: "maintain",
    reply: `reply ${n}`,
    new_information: "not_applicable",
    answers: { response_id: answers },
    assessment: "still_present",
    source_id: S1,
    notes: [],
    recorded_by: { role: "reviewer", channel: "codex" },
    recorded_at: "2026-10-06T00:00:00Z",
    ...over,
  };
}

function review(id: string, round: number, over: Partial<ReviewLike> & { delivered?: Delivery[] } = {}): ReviewLike {
  const { delivered, ...rest } = over;
  return { review_id: id, round, accepted: true, source_id: S1, check_evidence_digest: EV, item_ids: [], discussion: { delivered: delivered ?? [], check_results_digest: EV }, ...rest };
}

function delivered(r: ImplementerResponse, reply_sought = true): Delivery {
  return { response_id: r.response_id, item_id: r.item_id, reply_sought, basis: [], truncated: false };
}

function ix(items: ReviewerItem[], responses: ImplementerResponse[] = [], replies: ReviewerReply[] = [], reviews: ReviewLike[] = [review("r1", 1)]): DiscussionIndex {
  return buildDiscussionIndex({ items, responses, replies, reviews });
}

const NOW = { sourceId: S1, checkResults: EV };

describe("threads over reviewer lineage (P2.2-1)", () => {
  it("supersession chains, restatements and consolidations each form one thread; 'related' never links", () => {
    const a = item("a", { status: "superseded", superseded_by: "b" });
    const b = item("b", { round: 2, review_id: "r2", supersedes: ["a"], status: "superseded", superseded_by: "c" });
    const c = item("c", { round: 3, review_id: "r3", supersedes: ["b"] });
    const restated = item("d", { round: 1 });
    const restating = item("e", { round: 2, review_id: "r2", restates: ["d"] });
    const related = item("f", { round: 2, review_id: "r2", related_prior_id: "d" });
    const t = buildThreads([a, b, c, restated, restating, related], new Map());
    expect(t.threadOf.get("c")).toBe("a");
    expect(t.threadOf.get("e")).toBe("d");
    expect(t.threadOf.get("f")).toBe("f");
    expect(t.threads.get("a")!.members.map((m) => m.id)).toEqual(["a", "b", "c"]);
    expect(t.anomalyCount).toBe(0);
  });

  it("a consolidation joins every predecessor's thread: the earliest root is its id, the others are merged ids", () => {
    const positions = itemPositions([{ item_ids: ["x2", "x1", "x3"] }]);
    const olds = ["x1", "x2", "x3"].map((id) => item(id, { status: "superseded", superseded_by: "m" }));
    const merged = item("m", { round: 2, review_id: "r2", supersedes: ["x1", "x2", "x3"] });
    const t = buildThreads([...olds, merged], positions);
    // x2 is listed first by round 1: it is the earliest root.
    expect(t.threadOf.get("m")).toBe("x2");
    expect(t.threads.get("x2")!.merged).toEqual(["x1", "x3"]);
  });

  it("cycles, dangling links and self-links never loop or throw; each is reported on its thread", () => {
    const cyc = [item("p", { supersedes: ["q"], superseded_by: "q" }), item("q", { supersedes: ["p"], superseded_by: "p" })];
    const t = buildThreads([...cyc, item("d", { supersedes: ["missing"] }), item("s", { restates: ["s"] })], new Map());
    expect(t.threadOf.get("p")).toBe(t.threadOf.get("q"));
    expect(t.threads.get(t.threadOf.get("p")!)!.anomalies).toContain("cycle");
    expect(t.threads.get("d")!.anomalies).toEqual(["dangling_link"]);
    expect(t.threads.get("s")!.anomalies).toEqual(["self_link"]);
    // A damaged restates value reads as no link.
    const bad = { ...item("z"), restates: "not-a-list" } as unknown as ReviewerItem;
    expect(buildThreads([bad], new Map()).threads.get("z")!.anomalies).toEqual([]);
  });

  it("is bounded: links per item and link operations in total are capped (truncation reported), and a large run stays fast", () => {
    const many = Array.from({ length: 5000 }, (_, k) => `i${k}`);
    const hub = item("hub", { supersedes: many });
    const t0 = Date.now();
    const t = buildThreads([hub, ...many.map((id) => item(id))], new Map(), { linksPerItem: 100, linkOperations: 50 });
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(t.threads.get(t.threadOf.get("hub")!)!.anomalies).toContain("links_truncated");
    // Only the links within the bounds were followed.
    expect(t.threads.get(t.threadOf.get("hub")!)!.members.length).toBeLessThanOrEqual(51);
  });
});

describe("seen by the reviewer: only through an accepted review's delivery record (P2.2-6)", () => {
  it("a later review does not make a turn seen; a delivery to a review that was not accepted does not count", () => {
    const a = item("a");
    const t1 = turn("a");
    // A later accepted review that did not present it, and one that presented it but was not accepted.
    const reviews = [review("r1", 1), review("r2", 2), review("r3", 3, { accepted: false, delivered: [delivered(t1)] })];
    expect(seenBy(ix([a], [t1], [], reviews), t1.response_id)).toBeNull();
    const accepted = [...reviews, review("r4", 4, { delivered: [delivered(t1)] }), review("r5", 5, { delivered: [delivered(t1)] })];
    expect(seenBy(ix([a], [t1], [], accepted), t1.response_id)).toEqual({ review_id: "r4", round: 4 });
  });
});

describe("the new-information gate and the exchange budgets (P2.2-7)", () => {
  it("first exchange; a repetition after a maintain is not presented; new references, a new source, new check evidence, a changed position, a question answered or a revision each earn an exchange", () => {
    const a = item("a");
    const t1 = turn("a", { references: [{ path: "src/a.ts", start_line: 1, end_line: 2 }] });
    expect(gateBases(ix([a], [t1]), threadOfItem(ix([a], [t1]), a), t1, NOW)).toEqual(["first_exchange"]);
    const reviews = [review("r1", 1), review("r2", 2, { delivered: [delivered(t1)] })];
    const answered = reply("a", "r2", 2, t1.response_id);
    const again = (over: Partial<ImplementerResponse> = {}, r: ReviewerReply = answered, now = NOW) => {
      const t2 = turn("a", { after: "r2", references: [{ path: "src/a.ts", start_line: 1, end_line: 2 }], ...over });
      const x = ix([a], [t1, t2], [r], reviews);
      return { bases: gateBases(x, threadOfItem(x, a), t2, now), plan: planDiscussion(x, now).items.get("a")! };
    };
    // Same position, same references, same source and evidence, reworded: a repetition.
    const rep = again({ rationale: "the same point, rephrased at length" });
    expect(rep.bases).toEqual([]);
    expect(rep.plan.turn).toBeNull();
    expect(rep.plan.not_delivered!.reason).toBe("no_new_information");
    expect(again({ references: [{ path: "src/b.ts", start_line: 3, end_line: 3 }] }).bases).toEqual(["new_references"]);
    expect(again({}, answered, { sourceId: S2, checkResults: EV }).bases).toEqual(["source_changed"]);
    expect(again({}, answered, { sourceId: S1, checkResults: H("f") }).bases).toEqual(["check_evidence_changed"]);
    expect(again({ disposition: "fix_claimed" }).bases).toEqual(["position_changed"]);
    expect(again({}, reply("a", "r2", 2, t1.response_id, { stance: "need_information" })).bases).toEqual(["answers_reviewer_question"]);
    expect(again({}, reply("a", "r2", 2, t1.response_id, { stance: "revise" })).bases).toEqual(["reviewer_revised"]);
  });

  it("check results count, not their timing; reference paths compare by the platform's key (PR #11 review)", () => {
    // Re-running unchanged checks is no new information: only the results enter the digest.
    const unit = { check: "unit", required: true, status: "passed", last_execution_status: "passed", exit_code: 0, duration_ms: 812, timed_out: false, cancelled: false, freshness: { fresh: true, source: true, spec: true, environment: true } };
    const floor = { configured: true, satisfied_for_current_source: true };
    const slower = { ...unit, duration_ms: 1907 };
    expect(checkResultsDigest([slower], floor)).toBe(checkResultsDigest([unit], floor));
    expect(checkResultsDigest([{ ...unit, status: "failed", last_execution_status: "failed", exit_code: 1 }], floor)).not.toBe(checkResultsDigest([unit], floor));
    expect(checkResultsDigest([unit], { ...floor, satisfied_for_current_source: false })).not.toBe(checkResultsDigest([unit], floor));

    const a = item("a");
    const t1 = turn("a", { references: [{ path: "src/Math.ts", start_line: 1, end_line: 2 }] });
    const answered = reply("a", "r2", 2, t1.response_id);
    const reviews = [review("r1", 1), review("r2", 2, { delivered: [delivered(t1)] })];
    const t2 = turn("a", { after: "r2", references: [{ path: "SRC/math.ts", start_line: 1, end_line: 2 }] });
    const x = ix([a], [t1, t2], [answered], reviews);
    // Windows rules (case-insensitive names): the same location; POSIX (the default): another file.
    expect(gateBases(x, threadOfItem(x, a), t2, { ...NOW, pathKey: (p) => p.toLowerCase() })).toEqual([]);
    expect(planDiscussion(x, { ...NOW, pathKey: (p) => p.toLowerCase() }).items.get("a")!.not_delivered!.reason).toBe("no_new_information");
    expect(gateBases(x, threadOfItem(x, a), t2, NOW)).toEqual(["new_references"]);

    // A review recorded without the results digest (written before it existed) is not compared.
    const old = [review("r1", 1), review("r2", 2, { discussion: { delivered: [delivered(t1)] } })];
    const t3 = turn("a", { after: "r2", references: [{ path: "src/Math.ts", start_line: 1, end_line: 2 }] });
    const y = ix([a], [t1, t3], [answered], old);
    expect(gateBases(y, threadOfItem(y, a), t3, { sourceId: S1, checkResults: H("f") })).toEqual([]);
  });

  it("an unanswered delivered turn is presented again and each presentation uses an exchange; at the budget nothing more is presented and the thread escalates", () => {
    const a = item("a");
    const t1 = turn("a");
    const run = (k: number) => [review("r1", 1), ...Array.from({ length: k }, (_, i) => review(`r${i + 2}`, i + 2, { delivered: [delivered(t1)] }))];
    const p1 = planDiscussion(ix([a], [t1], [], run(1)), NOW).items.get("a")!;
    expect(p1.turn).toMatchObject({ reply_sought: true, basis: ["unanswered"] });
    expect(p1.exchanges_used).toBe(1);
    const x3 = ix([a], [t1], [], run(DISCUSSION_LIMITS.exchangesPerThread));
    const p3 = planDiscussion(x3, NOW);
    expect(p3.items.get("a")!.turn).toBeNull();
    expect(p3.items.get("a")!.not_delivered!.reason).toBe("exchange_budget_exhausted");
    const rep = threadReport(x3, p3, threadOfItem(x3, a), () => null);
    expect(rep.escalation).toEqual({ needed: true, reasons: ["exchange_budget_exhausted"] });
    expect(rep.awaiting).toBe("user");
  });

  it("the budget follows the lineage: supersession, restatement and consolidation never reset it (uses add up)", () => {
    const a1 = item("a1", { status: "superseded", superseded_by: "m" });
    const a2 = item("a2", { status: "superseded", superseded_by: "m" });
    const t1 = turn("a1");
    const t2 = turn("a2");
    const reviews = [review("r1", 1), review("r2", 2, { delivered: [delivered(t1), delivered(t2)] }), review("r3", 3, { delivered: [delivered(t1)] })];
    // m consolidates a1 and a2 (two and one exchanges): 3 used — the budget is spent.
    const m = item("m", { round: 3, review_id: "r3", supersedes: ["a1", "a2"] });
    const t3 = turn("m", { after: "r3" });
    const x = ix([a1, a2, m], [t1, t2, t3], [], reviews);
    expect(threadOfItem(x, m).id).toBe(threadOfItem(x, a1).id);
    const p = planDiscussion(x, NOW).items.get("m")!;
    expect(p.exchanges_used).toBe(3);
    expect(p.not_delivered!.reason).toBe("exchange_budget_exhausted");
    // A restatement (a new finding id) joins the same budget.
    const r = item("r", { round: 3, review_id: "r3", restates: ["a1"] });
    const t4 = turn("r", { after: "r3" });
    const pr = planDiscussion(ix([a1, a2, m, r], [t1, t2, t3, t4], [], reviews), NOW).items.get("r")!;
    expect(pr.exchanges_used).toBe(3);
    expect(pr.turn).toBeNull();
  });

  it("per-review and per-run caps: the rest wait (review cap) or escalate (run budget)", () => {
    const items = Array.from({ length: DISCUSSION_LIMITS.replySoughtPerReview + 1 }, (_, k) => item(`i${k}`));
    const turns = items.map((it) => turn(it.id));
    const plan = planDiscussion(ix(items, turns), NOW);
    expect(plan.reply_sought).toBe(DISCUSSION_LIMITS.replySoughtPerReview);
    expect([...plan.items.values()].filter((p) => p.not_delivered?.reason === "review_reply_cap")).toHaveLength(1);
    const x = ix(items, turns);
    const full = { ...x, runExchanges: DISCUSSION_LIMITS.exchangesPerRun };
    expect([...planDiscussion(full, NOW).items.values()].every((p) => p.not_delivered?.reason === "run_exchange_budget_exhausted")).toBe(true);
  });

  it("context and withheld text: accepted/deferred on open items are context; informational context-only turns are not presented, answers to questions are; withheld text never is", () => {
    const open = item("o");
    const note = item("n", { status: "informational", triage: "note" });
    const q = item("q", { status: "informational", item_kind: "question", triage: "question" });
    const w = item("w");
    const turns = [turn("o", { disposition: "accepted" }), turn("n", { disposition: "accepted" }), turn("q", { disposition: "accepted", rationale: "numbers only" }), turn("w", { disposition: "disputed", text_withheld: true })];
    const p = planDiscussion(ix([open, note, q, w], turns), NOW).items;
    expect(p.get("o")!.turn).toMatchObject({ reply_sought: false, basis: ["context"] });
    expect(p.get("n")!.not_delivered!.reason).toBe("informational_context_only");
    expect(p.get("q")!.turn).toMatchObject({ reply_sought: false, basis: ["answer_to_question"] });
    expect(p.get("w")!.turn).toBeNull();
    expect(p.get("w")!.not_delivered!.reason).toBe("text_withheld");
  });
});

describe("escalation and who must act (P2.2-8)", () => {
  const a = item("a");
  it("a repeated dispute without new information escalates and requires new information; a deferral needs a user; a withdrawal on an open item needs one too", () => {
    const t1 = turn("a");
    const reviews = [review("r1", 1), review("r2", 2, { delivered: [delivered(t1)] })];
    const r = reply("a", "r2", 2, t1.response_id, { stance: "maintain", new_information: "not_applicable" });
    // The reviewer spoke last: the implementer must act; arguing on needs new information.
    let x = ix([a], [t1], [r], reviews);
    let rep = threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok");
    expect(rep).toMatchObject({ last_speaker: "reviewer", awaiting: "implementer", new_information_required: true, reviewer_seen_latest_implementer_turn: true, escalation: { needed: false } });
    // A repetition: recorded, not presented, escalated.
    const t2 = turn("a", { after: "r2" });
    x = ix([a], [t1, t2], [r], reviews);
    rep = threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok");
    expect(rep).toMatchObject({ last_speaker: "implementer", reviewer_seen_latest_implementer_turn: false, latest_stance_predates_latest_implementer_turn: true, awaiting: "user" });
    expect(rep.escalation.reasons).toContain("disagreement_without_new_information");
    expect(rep.latest_implementer).toMatchObject({ delivery: "not_delivered", delivery_reason: "no_new_information" });
    // Deferral requested.
    x = ix([a], [turn("a", { disposition: "deferred" })]);
    expect(threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok").escalation.reasons).toEqual(["deferral_requested"]);
    // The reviewer withdrew, the item stays open (unchanged source): a user decides, or a later review.
    x = ix([a], [t1], [reply("a", "r2", 2, t1.response_id, { stance: "withdraw" })], reviews);
    expect(threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok").escalation.reasons).toEqual(["withdrawn_but_open"]);
    // The reviewer judged a turn not new and maintains: escalated.
    x = ix([a], [t1], [reply("a", "r2", 2, t1.response_id, { stance: "maintain", new_information: "no" })], reviews);
    expect(threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok").escalation.reasons).toEqual(["reviewer_found_no_new_information"]);
  });

  it("a pending dispute awaits the reviewer; a thread without turns awaits the implementer", () => {
    let x = ix([a], [turn("a")]);
    expect(threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok")).toMatchObject({ awaiting: "reviewer", latest_implementer: { delivery: "pending", delivery_basis: ["first_exchange"] } });
    x = ix([a]);
    expect(threadReport(x, planDiscussion(x, NOW), threadOfItem(x, a), () => "tok")).toMatchObject({ awaiting: "implementer", last_speaker: null });
  });
});

describe("response tokens cover the thread (P2.2-11)", () => {
  it("a reviewer reply on any item of the thread, a new lineage link and a delivery make the token stale", () => {
    const a = item("a");
    const base = responseToken(a, ix([a]));
    const b = item("b", { round: 2, review_id: "r2", restates: ["a"] });
    expect(responseToken(a, ix([a, b]))).not.toBe(base);
    const t1 = turn("a");
    const withTurn = responseToken(a, ix([a], [t1]));
    expect(withTurn).not.toBe(base);
    expect(responseToken(a, ix([a], [t1], [], [review("r1", 1), review("r2", 2, { delivered: [delivered(t1)] })]))).not.toBe(withTurn);
    const onB = reply("b", "r2", 2, null);
    expect(responseToken(a, ix([a, b], [], [onB]))).not.toBe(responseToken(a, ix([a, b])));
    expect(respondable(a)).toBe(true);
  });
});

describe("taking the reviewer's replies (P2.2-3)", () => {
  it("only replies to items awaiting one are recorded, once each, with consistency notes; nothing is inferred from prose", () => {
    let k = 0;
    const out = processReplies({
      replies: [
        { id: "PF-1", stance: "maintain", reply: "still wrong", new_information: "no" },
        { id: "pf-1", stance: "withdraw", reply: "duplicate", new_information: "yes" },
        { id: "PF-2", stance: "withdraw", reply: "not awaited", new_information: "yes" },
        { id: "check_failed:unit", stance: "withdraw", reply: "engine condition", new_information: "yes" },
        { id: "IN-1", stance: "need_information", reply: "Which callers pass strings?", new_information: "not_applicable" },
      ],
      awaiting: [
        { item_id: "a", alias: "PF-1", response_id: "resp-a" },
        { item_id: "c", alias: "IN-1", response_id: "resp-c" },
        { item_id: "d", alias: "PF-3", response_id: "resp-d" },
      ],
      presented: new Map([["pf-1", "a"], ["pf-2", "b"], ["pf-3", "d"], ["in-1", "c"]]),
      assessments: new Map([["a", "apparently_resolved"]]),
      reviewId: "r2",
      round: 2,
      sourceId: S2,
      recordedAt: "2026-10-06T01:00:00Z",
      newId: () => `id-${++k}`,
      clampReply: (s) => s.slice(0, 10),
    });
    expect(out.records.map((r) => [r.item_id, r.stance, r.answers.response_id, r.recorded_by.role, r.recorded_by.channel])).toEqual([
      ["a", "maintain", "resp-a", "reviewer", "codex"],
      ["c", "need_information", "resp-c", "reviewer", "codex"],
    ]);
    expect(out.records[0]!.notes[0]).toMatch(/maintain conflicts with the assessment apparently_resolved/);
    expect(out.records[1]!.reply).toBe("Which call");
    expect(out.records[1]!.assessment).toBeNull();
    expect(out.missing).toEqual(["d"]);
    expect(out.notes.join(" ")).toMatch(/duplicate/);
    expect(out.notes.join(" ")).toMatch(/no reply was sought/);
    expect(out.notes.join(" ")).toMatch(/unknown id/);
    expect(stanceConflict("withdraw", "still_present")).toMatch(/conflicts/);
    expect(stanceConflict("revise", "superseded")).toBeNull();
  });

  it("the output schema has an explicit stance vocabulary and refuses anything else", () => {
    expect(DiscussionReplyOutSchema.safeParse({ id: "PF-1", stance: "maintain", reply: "x", new_information: "yes" }).success).toBe(true);
    for (const bad of [{ stance: "resolved" }, { stance: "approved_by_user" }, { new_information: "maybe" }, { extra: 1 }]) {
      expect(DiscussionReplyOutSchema.safeParse({ id: "PF-1", stance: "maintain", reply: "x", new_information: "yes", ...bad }).success, JSON.stringify(bad)).toBe(false);
    }
    expect(ReviewOutputSchema.shape.discussion_replies).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// The bundle (P2.2-4, -5, -9)
// ---------------------------------------------------------------------------

function manifest(): ReviewManifest {
  return {
    schema: "arl.review-manifest.v1",
    capture_id: "cap",
    target: { kind: "uncommitted", ref: null },
    base: { kind: "commit", commit: "a".repeat(40), baseline_capture_id: null },
    head: { commit: "a".repeat(40), branch: "main" },
    object_format: "sha1",
    source_id: S1,
    rules_digest: H("6"),
    limits: { max_file_bytes: 1, max_export_bytes: 1, max_diff_bytes: 1 },
    files: [{ path: "src/math.js", area: "tree", size: 10, sha256: H("7") }],
    changes: [],
    review_files: { diff_patch: { size: 1, sha256: H("8") }, base: [], head: [] },
    exclusions: { confidential: { count: 0, changed_count: 0 }, repository_context: { count: 0 }, size_skipped: [], context_reduced: [], link_skipped: [], path_unsupported: [], submodules: [] },
    eol_conversion_equivalent: { count: 0, paths: [] },
    limitations: [],
    stable: true,
    manifest_digest: H("9"),
  } as ReviewManifest;
}

function bundleWith(items: ReviewerItem[], x: DiscussionIndex, over: Partial<BundleInput> = {}, prepare?: (s: string) => string) {
  const plan = planDiscussion(x, NOW);
  const informational = items.filter((it) => it.status === "informational" && plan.items.get(it.id)?.turn);
  return buildBundle({
    nonce: "n0nce",
    envelope: null,
    focus: null,
    depth: "standard",
    manifest: manifest(),
    diffText: "",
    withheldPaths: new Set(["config/secret.env"]),
    withheldHashes: new Set(),
    checks: { evidence: [], floor: { configured: false, satisfied_for_reviewed_source: false, missing: [], stale: [], failed: [], removed: [], unapproved: [] }, engine_conditions: [] },
    openItems: items.filter((it) => it.status === "open"),
    testsRemoved: null,
    instructionFiles: null,
    discussion: { plans: plan.items, informational, ...(prepare ? { prepare } : {}) },
    ...over,
  });
}

describe("what the bundle presents (P2.2-4, -5, -9)", () => {
  it("presents the turn on its prior item and records exactly what was delivered; the digest moves with the discussion only", () => {
    const a = item("a");
    const b = item("b");
    const q = item("q", { status: "informational", item_kind: "question", triage: "question" });
    const items = [a, b, q];
    const quiet = bundleWith(items, ix(items));
    expect(quiet.discussion.delivered).toEqual([]);
    expect(quiet.sections["INFORMATIONAL_DISCUSSION"]).toBe("none");
    const ta = turn("a", { rationale: "ZEBRA the bound is enforced in the caller", references: [{ path: "src/math.js", start_line: 2, end_line: 2 }] });
    const tq = turn("q", { disposition: "accepted", rationale: "OKAPI numbers only" });
    const tb = turn("b", { disposition: "disputed", rationale: "WITHHELD-MARKER", text_withheld: true });
    const busy = bundleWith(items, ix(items, [ta, tq, tb]));
    expect(busy.discussion.delivered.map((d) => [d.item_id, d.reply_sought])).toEqual([
      ["a", true],
      ["q", false],
    ]);
    expect(busy.discussion.awaiting).toEqual([{ item_id: "a", alias: "PF-1", response_id: ta.response_id }]);
    expect(busy.sections["PRIOR_ITEMS"]).toContain("ZEBRA");
    expect(busy.sections["PRIOR_ITEMS"]).toContain('"awaiting_reply": true');
    expect(busy.sections["INFORMATIONAL_DISCUSSION"]).toContain("OKAPI");
    expect(busy.sections["INFORMATIONAL_DISCUSSION"]).toContain('"id": "IN-1"');
    // Withheld text never reaches the bundle, neither its text nor its position.
    expect(JSON.stringify(busy.sections)).not.toContain("WITHHELD-MARKER");
    expect(busy.discussion.digest).not.toBe(quiet.discussion.digest);
    // Identical input, identical digest; other text, another digest.
    expect(bundleWith(items, ix(items, [ta, tq, tb])).discussion.digest).toBe(busy.discussion.digest);
    const other = turn("a", { response_id: ta.response_id, rationale: "ZEBRA a different argument", references: ta.references });
    expect(bundleWith(items, ix(items, [other, tq, tb])).discussion.digest).not.toBe(busy.discussion.digest);
    expect(discussionDigest({ prior: [], informational: [] }, [])).toBe(quiet.discussion.digest);
    // The engine's bookkeeping is not shown to the reviewer.
    expect(JSON.stringify(busy.sections)).not.toContain(ta.response_id);
  });

  it("discussion text passes the preparation for the model (withheld names and local paths) and the capture's redaction; normal context stays", () => {
    const a = item("a");
    const t = turn("a", { rationale: "see config/secret.env and old/leak.key; /home/me/repo/src/math.js is fine", references: [{ path: "old/leak.key", start_line: 1, end_line: 1 }, { path: "src/math.js", start_line: 2, end_line: 2 }] });
    const prepare = (s: string) => s.replace(/old\/leak\.key/g, "[withheld path]").replace(/\/home\/me\/repo/g, "[repository]");
    const b = bundleWith([a], ix([a], [t]), {}, prepare);
    const text = b.sections["PRIOR_ITEMS"]!;
    expect(text).not.toContain("config/secret.env");
    expect(text).not.toContain("leak.key");
    expect(text).not.toContain("/home/me");
    expect(text).toContain("[repository]/src/math.js");
    expect(text).toContain('"path": "src/math.js"');
  });

  it("the discussion shrinks before prior items under the bundle cap, and says so", () => {
    const items = Array.from({ length: 6 }, (_, k) => item(`i${k}`));
    const turns = items.map((it) => turn(it.id, { rationale: "w".repeat(2000) }));
    const full = bundleWith(items, ix(items, turns));
    const capped = bundleWith(items, ix(items, turns), { limits: { maxBundleChars: JSON.stringify(full.sections).length - 6000 } });
    expect(capped.prior).toHaveLength(6);
    expect(capped.limitations.map((l) => l.code)).toContain("bundle_discussion_reduced");
    expect(capped.discussion.delivered.some((d) => d.truncated)).toBe(true);
    expect(capped.discussion.digest).not.toBe(full.discussion.digest);
  });
});
