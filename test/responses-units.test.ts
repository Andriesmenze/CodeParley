// Phase 2.1 unit tests (platform-independent): the implementer-response policy (tokens,
// respondability, discussion states, staleness, input validation, rejections), the strict tool
// input (no field can carry engine-owned data or an authority claim), and the persisted
// record's compatibility in both directions (older records gain an empty list; an older
// version's read-modify-write keeps the new list; a newer version's kinds do not break reading).

import { describe, it, expect } from "vitest";
import {
  checkResponses,
  discussionCounts,
  discussionState,
  discussionText,
  inputProblems,
  itemDiscussion,
  lastPresentSourceAt,
  normalizeReferencePath,
  RATIONALE_EXCERPT_CHARS,
  respondable,
  responseBeforeReview,
  responseToken,
  responseView,
  reviewedSince,
  type ResponseInput,
} from "../src/policy/responses.js";
import { ImplementerResponseSchema, RESPONSE_LIMITS, type ImplementerResponse } from "../src/schemas/responses.js";
import { buildDiscussionIndex, planDiscussion, type DiscussionIndex } from "../src/policy/discussion.js";
import type { DiscussionView } from "../src/policy/responses.js";
import { StateRecordSchema, newStateRecord } from "../src/schemas/run-state.js";
import type { ItemAssessment, ReviewerItem } from "../src/schemas/review.js";
import { GetReviewHistoryInput, RespondToReviewInput } from "../src/server/tool-schemas.js";
import { cutExcerpts, toHost, toLocal, viewWithheld, withheldParts, withheldOfEntries } from "../src/engine/host-view.js";
import { responsesDocument } from "../src/engine/history.js";
import type { SourceEntry } from "../src/schemas/capture.js";
import type { HostDisclosure } from "../src/policy/host-disclosure.js";

const H = (c: string) => c.repeat(64);
const RUN = "01a10737-5c4b-7bd1-9ca4-57bf27dd42dc";
const ID1 = "0199a1b2-0000-7000-8000-000000000001";
const ID2 = "0199a1b2-0000-7000-8000-000000000002";
const ID3 = "0199a1b2-0000-7000-8000-000000000003";

function item(id: string, over: Partial<ReviewerItem> = {}): ReviewerItem {
  return {
    id,
    item_kind: "finding",
    review_id: "r1",
    round: 1,
    source_id: H("a"),
    review_input_id: H("b"),
    title: "add() subtracts",
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
    created_at: "2026-10-05T00:00:00Z",
    ...over,
  };
}

function assessment(review_id: string, round: number, a: ItemAssessment["assessment"], source = H("c")): ItemAssessment {
  return { review_id, round, source_id: source, assessment: a, note: "", effect: a === "apparently_resolved" ? "status:reported_resolved" : "kept_open" };
}

let seq = 0;
function response(itemId: string, over: Partial<ImplementerResponse> = {}): ImplementerResponse {
  seq++;
  return {
    response_id: `resp-${seq}`,
    item_id: itemId,
    disposition: "accepted",
    rationale: "agreed",
    references: [],
    answers: { review_id: "r1", round: 1, token: "t" },
    source: { source_id: H("d"), note: null },
    disclosure_ref: null,
    text_withheld: false,
    supersedes: null,
    recorded_by: { role: "implementer", channel: "mcp" },
    response_set_id: `set-${seq}`,
    request_id: null,
    request_digest: H("e"),
    recorded_at: `2026-10-05T00:00:${String(seq % 60).padStart(2, "0")}Z`,
    ...over,
  };
}

/** The discussion index of a set of items and responses (Phase 2.2: tokens and views read it). */
function ixOf(items: readonly ReviewerItem[], records: readonly ImplementerResponse[] = []): DiscussionIndex {
  return buildDiscussionIndex({ items, responses: records, replies: [], reviews: [] });
}

function viewOf(items: readonly ReviewerItem[], records: readonly ImplementerResponse[] = []): DiscussionView {
  const ix = ixOf(items, records);
  return { ix, plan: planDiscussion(ix, { sourceId: null, checkResults: null }) };
}

/** The token of an item with (at most) one latest response. */
function tok(it: ReviewerItem, latest: ImplementerResponse | null = null): string {
  return responseToken(it, ixOf([it], latest ? [latest] : []));
}

function input(over: Partial<ResponseInput> = {}): ResponseInput {
  return { finding_id: ID1, response_token: "x", disposition: "accepted", rationale: "", ...over };
}

describe("response token (optimistic concurrency, plan §1.14)", () => {
  it("is a short digest of the item's engine state and its latest response", () => {
    const it0 = item(ID1);
    const t = tok(it0);
    expect(t).toMatch(/^[0-9a-f]{32}$/);
    expect(tok(item(ID1))).toBe(t); // deterministic
    // Any change the engine can make to the item, or a new response, changes it.
    expect(tok(item(ID1, { assessments: [assessment("r2", 2, "not_assessed")] }))).not.toBe(t);
    expect(tok(item(ID1, { assessments: [assessment("r2", 2, "still_present")] }))).not.toBe(t);
    expect(tok(item(ID1, { status: "informational" }))).not.toBe(t);
    expect(tok(item(ID1, { status: "superseded", superseded_by: ID2 }))).not.toBe(t);
    const r = response(ID1);
    expect(tok(it0, r)).not.toBe(t);
    expect(tok(it0, response(ID1))).not.toBe(tok(it0, r)); // every response
    // The working tree's source is not part of it: editing code does not invalidate responses.
    expect(tok(item(ID1))).toBe(t);
  });

  it("only open and informational reviewer items can be responded to", () => {
    expect(respondable(item(ID1))).toBe(true);
    expect(respondable(item(ID1, { status: "informational" }))).toBe(true);
    for (const status of ["superseded", "reported_resolved", "not_accepted"] as const) expect(respondable(item(ID1, { status })), status).toBe(false);
    expect(itemDiscussion(item(ID1, { status: "superseded", superseded_by: ID2 }), viewOf([]), null).response_token).toBeNull();
  });
});

describe("discussion states (plan §1.14: a response never resolves anything)", () => {
  it("follow the reviewer's status first, then the implementer's latest response", () => {
    const open = item(ID1);
    expect(discussionState(open, null)).toBe("open");
    expect(discussionState(open, response(ID1, { disposition: "accepted" }))).toBe("accepted_unresolved");
    expect(discussionState(open, response(ID1, { disposition: "disputed" }))).toBe("disputed");
    // The implementer's deferral is a request (its position), never an authoritative deferral: the item stays open.
    expect(discussionState(open, response(ID1, { disposition: "deferred" }))).toBe("deferral_requested");
    expect(discussionState(open, response(ID1, { disposition: "fix_claimed" }))).toBe("fix_claimed_awaiting_verification");
    // Reviewer-owned outcomes win over any response; none is ever turned into "resolved" by a response.
    const fix = response(ID1, { disposition: "fix_claimed" });
    expect(discussionState(item(ID1, { status: "reported_resolved", assessments: [assessment("r2", 2, "apparently_resolved")] }), fix)).toBe("reviewer_resolved");
    expect(discussionState(item(ID1, { status: "superseded", superseded_by: ID2 }), fix)).toBe("superseded");
    expect(discussionState(item(ID1, { status: "informational" }), response(ID1, { disposition: "deferred" }))).toBe("informational");
    // A kind written by a later version is not mistaken for one of ours.
    expect(discussionState(open, response(ID1, { disposition: "waived" }))).toBe("open");
  });

  it("fix claims: only a later still_present contradicts them; omissions and 'not assessable' do not", () => {
    const claim = response(ID1, { disposition: "fix_claimed", answers: { review_id: "r1", round: 1, token: "t" } });
    expect(discussionState(item(ID1, { assessments: [assessment("r2", 2, "not_assessed")] }), claim)).toBe("fix_claimed_awaiting_verification");
    expect(discussionState(item(ID1, { assessments: [assessment("r2", 2, "no_longer_assessable")] }), claim)).toBe("fix_claimed_awaiting_verification");
    const reasserted = item(ID1, { assessments: [assessment("r2", 2, "still_present")] });
    expect(discussionState(reasserted, claim)).toBe("fix_not_confirmed");
    // A new claim made after that review answers it: awaiting verification again.
    const again = response(ID1, { disposition: "fix_claimed", answers: { review_id: "r2", round: 2, token: "t" } });
    expect(discussionState(reasserted, again)).toBe("fix_claimed_awaiting_verification");
  });

  it("'reviewed since the response' ignores omissions and uses the item's own review order, never clocks", () => {
    const r = response(ID1, { answers: { review_id: "r2", round: 2, token: "t" }, recorded_at: "2099-01-01T00:00:00Z" });
    const it = item(ID1, { assessments: [assessment("r2", 2, "still_present"), assessment("r3", 3, "not_assessed")] });
    expect(reviewedSince(it, r)).toBe(false);
    expect(reviewedSince(item(ID1, { assessments: [...it.assessments, assessment("r4", 4, "still_present")] }), r)).toBe(true);
    // A response answering the raising review, then any assessment: reviewed since.
    expect(reviewedSince(it, response(ID1, { answers: { review_id: "r1", round: 1, token: "t" } }))).toBe(true);
    // An answered review the item does not know (corrupt or foreign): conservative.
    expect(reviewedSince(it, response(ID1, { answers: { review_id: "zz", round: 9, token: "t" } }))).toBe(true);
  });

  it("the source the reviewer last saw the item present on, as of a given review", () => {
    const it = item(ID1, { source_id: H("1"), assessments: [assessment("r2", 2, "still_present", H("2")), assessment("r3", 3, "not_assessed", H("3")), assessment("r4", 4, "still_present", H("4"))] });
    expect(lastPresentSourceAt(it, "r1")).toBe(H("1"));
    expect(lastPresentSourceAt(it, "r2")).toBe(H("2"));
    expect(lastPresentSourceAt(it, "r3")).toBe(H("2"));
    expect(lastPresentSourceAt(it, "r4")).toBe(H("4"));
  });

  it("the response recorded before a review assessed the item (the review result never rewrites it)", () => {
    const it = item(ID1, { assessments: [assessment("r2", 2, "still_present"), assessment("r3", 3, "apparently_resolved")], status: "reported_resolved" });
    const a = response(ID1, { disposition: "disputed", answers: { review_id: "r1", round: 1, token: "t" } });
    const b = response(ID1, { disposition: "fix_claimed", answers: { review_id: "r2", round: 2, token: "t" } });
    expect(responseBeforeReview(it, "r2", [a, b])).toMatchObject({ response_id: a.response_id, disposition: "disputed" });
    expect(responseBeforeReview(it, "r3", [a, b])).toMatchObject({ response_id: b.response_id, disposition: "fix_claimed" });
    expect(responseBeforeReview(it, "r1", [a, b])).toBeNull();
    expect(responseBeforeReview(it, "unknown", [a, b])).toBeNull();
  });
});

describe("response views (status, results, CLI)", () => {
  it("report staleness against the reviewer's later view and the fresh source only", () => {
    const r = response(ID1, { disposition: "fix_claimed", source: { source_id: H("5"), note: null }, rationale: "x".repeat(500) });
    const it = item(ID1, { assessments: [assessment("r2", 2, "still_present")] });
    const v = responseView(it, viewOf([it], [r]), H("6"))!;
    expect(v.stale_reasons).toEqual(["reviewed_since_response", "source_changed_since_response"]);
    expect(v.source_checked).toBe(true);
    // Whole here: every view cuts it, after redaction (below).
    expect(v.rationale_excerpt).toBe("x".repeat(500));
    expect(v.notes.join(" ")).toMatch(/still found the item present/);
    // Unknown current source: no source verdict either way.
    const unknown = responseView(item(ID1), viewOf([item(ID1)], [r]), null)!;
    expect(unknown.stale_reasons).toEqual([]);
    expect(unknown.source_checked).toBe(false);
    expect(responseView(item(ID2), viewOf([item(ID2)], [r]), null)).toBeNull();
  });

  it("excerpts are cut after redaction: a withheld name across the cut leaves no fragment (host and CLI views)", () => {
    const name = "config/secret-token.env";
    const rationale = `${"x".repeat(190)} ${name} and the rest of the rationale`;
    // A cut made before redaction would leave a fragment the matcher no longer recognizes.
    expect(rationale.slice(0, RATIONALE_EXCERPT_CHARS - 1)).toContain("config/s");
    const d: HostDisclosure = { withheldPaths: new Set([name]), withheldHashes: new Set(), keepRoots: [], hiddenDirs: [] };
    const report = { open_findings: [{ title: "t", implementer_response: { rationale_excerpt: rationale } }] };
    for (const view of [toHost(report, d).value, toLocal(report, d).value, cutExcerpts(report)]) {
      const excerpt = view.open_findings[0]!.implementer_response.rationale_excerpt;
      expect(excerpt.length).toBe(RATIONALE_EXCERPT_CHARS);
      expect(excerpt.endsWith("…")).toBe(true);
    }
    for (const view of [toHost(report, d).value, toLocal(report, d).value]) expect(view.open_findings[0]!.implementer_response.rationale_excerpt).not.toContain("config");
    // Short texts and other fields are left as they are.
    expect(cutExcerpts({ rationale_excerpt: "short", rationale: "y".repeat(500) })).toEqual({ rationale_excerpt: "short", rationale: "y".repeat(500) });
  });

  it("flag a fix claimed on the very source the reviewer last saw the item on", () => {
    const it = item(ID1, { source_id: H("7") });
    const same = responseView(it, viewOf([it], [response(ID1, { disposition: "fix_claimed", source: { source_id: H("7"), note: null } })]), H("7"))!;
    expect(same.notes.join(" ")).toMatch(/same source the reviewer last saw/);
    const changed = responseView(it, viewOf([it], [response(ID1, { disposition: "fix_claimed", source: { source_id: H("8"), note: null } })]), H("8"))!;
    expect(changed.notes).toEqual([]);
  });

  it("show who recorded a response when it is not the implementer (a later channel), and count discussion states", () => {
    const it = item(ID1);
    expect(responseView(it, viewOf([it], [response(ID1, { recorded_by: { role: "user", channel: "cli" } })]), null)!.notes.join(" ")).toMatch(/recorded by user via cli/);
    const items = [item(ID1), item(ID2), item(ID3, { status: "informational" })];
    const records = [response(ID1, { disposition: "disputed" }), response(ID3, { disposition: "accepted" })];
    const c = discussionCounts(items, records);
    expect(c).toMatchObject({ disputed: 1, open: 1, informational: 1, responses_recorded: 2, stale_responses: 0 });
    expect(discussionText(c)).toBe("1 without a response, 1 disputed");
  });

  it("show the responses to superseded predecessors next to the new item, without inheriting them", () => {
    const old = item(ID1, { status: "superseded", superseded_by: ID2 });
    const neu = item(ID2, { round: 2, review_id: "r2", supersedes: [ID1] });
    const d = itemDiscussion(neu, viewOf([old, neu], [response(ID1, { disposition: "disputed" })]), null);
    expect(d.discussion_state).toBe("open");
    expect(d.implementer_response).toBeNull();
    expect(d.responses_to_superseded_items).toEqual([expect.objectContaining({ item_id: ID1, disposition: "disputed", round: 1 })]);
  });
});

describe("validating a call", () => {
  it("rationale: required except for accepted, bounded, no control or bidirectional-override characters", () => {
    expect(inputProblems([input({ disposition: "accepted", rationale: "" })])).toEqual([]);
    for (const d of ["disputed", "deferred", "fix_claimed"] as const) expect(inputProblems([input({ disposition: d, rationale: "  " })]).join(), d).toMatch(/required/);
    expect(inputProblems([input({ rationale: "x".repeat(RESPONSE_LIMITS.rationaleChars + 1) })]).join()).toMatch(/at most/);
    expect(inputProblems([input({ rationale: "line one\nline two\r\n\tindented" })])).toEqual([]);
    for (const bad of ["a\u0000b", "a\u001bb", "a\u0085b", "a\u202eb", "a\u2066b"]) expect(inputProblems([input({ rationale: bad })]).join(), JSON.stringify(bad)).toMatch(/control/);
    // Every range boundary: C0 without tab and line breaks, DEL and C1, the bidirectional overrides and isolates.
    for (const bad of ["\u0001", "\u0008", "\u000b", "\u000c", "\u000e", "\u001f", "\u007f", "\u009f", "\u202a", "\u2069"]) expect(normalizeReferencePath(`a${bad}b`), JSON.stringify(bad)).toBeNull();
    for (const ok of ["\u0020", "\u007e", "\u00a0", "\u2029", "\u202f", "\u2065", "\u206a", "\u00e9"]) expect(normalizeReferencePath(`a${ok}b`), JSON.stringify(ok)).toBe(`a${ok}b`);
  });

  it("one response per item per call (ids compared case-insensitively); at least one, at most 50", () => {
    expect(inputProblems([input({ finding_id: ID1 }), input({ finding_id: ID1.toUpperCase() })]).join()).toMatch(/more than once/);
    expect(inputProblems([]).join()).toMatch(/at least one/);
    expect(inputProblems(Array.from({ length: 51 }, (_, i) => input({ finding_id: `${i}` }))).join()).toMatch(/at most 50/);
  });

  it("references are repository-relative claims: no absolute path, drive, UNC, '..', empty segment, colon or control character", () => {
    expect(normalizeReferencePath("src\\math.js")).toBe("src/math.js");
    expect(normalizeReferencePath("./src/math.js")).toBe("src/math.js");
    for (const bad of ["/etc/passwd", "C:\\x\\y", "c:x", "\\\\server\\share\\x", "//server/share", "../x", "a/../b", "a//b", "a/./b", "file.txt:stream", "a\u0000b", "", "   "]) {
      expect(normalizeReferencePath(bad), JSON.stringify(bad)).toBeNull();
    }
    const refs = (r: ResponseInput["references"]) => inputProblems([input({ references: r })]).join();
    expect(refs([{ path: "src/a.ts", start_line: 3, end_line: 5 }])).toBe("");
    expect(refs([{ path: "src/a.ts", end_line: 5 }])).toMatch(/needs start_line/);
    expect(refs([{ path: "src/a.ts", start_line: 5, end_line: 3 }])).toMatch(/must not precede/);
    expect(refs([{ path: "src/a.ts", start_line: 0 }])).toMatch(/from 1/);
    expect(refs(Array.from({ length: 9 }, () => ({ path: "a" })))).toMatch(/at most 8/);
  });

  it("checks every response against the current state and reports every refusal", () => {
    const items = [item(ID1), item(ID2, { status: "superseded", superseded_by: ID3 }), item(ID3, { status: "reported_resolved" })];
    const records: ImplementerResponse[] = [];
    const incidentIds = new Set(["0199ffff-0000-7000-8000-00000000abcd"]);
    const ix = ixOf(items, records);
    const ok = checkResponses({ ix, incidentIds, responses: [input({ finding_id: ID1.toUpperCase(), response_token: responseToken(items[0]!, ix) })] });
    expect(ok).toEqual([]);
    const rejected = checkResponses({
      ix,
      incidentIds,
      responses: [
        input({ finding_id: ID1, response_token: "0".repeat(32) }),
        input({ finding_id: ID2, response_token: "x" }),
        input({ finding_id: ID3, response_token: "x" }),
        input({ finding_id: "0199ffff-0000-7000-8000-00000000abcd", response_token: "x" }),
        input({ finding_id: "check_failed:unit", response_token: "x" }),
      ],
    });
    expect(rejected.map((r) => [r.index, r.code])).toEqual([
      [0, "STALE_FINDING_STATE"],
      [1, "FINDING_NOT_RESPONDABLE"],
      [2, "FINDING_NOT_RESPONDABLE"],
      [3, "FINDING_NOT_FOUND"],
      [4, "FINDING_NOT_FOUND"],
    ]);
    expect(rejected[1]!.detail).toContain(ID3); // points to the superseding item, never redirects to it
    expect(rejected[3]!.detail).toMatch(/isolation incident/);
    expect(rejected[4]!.detail).toMatch(/engine conditions/);
  });
});

describe("respond_to_review input (strict: no engine-owned data, no authority claim)", () => {
  const base = { run_id: RUN, responses: [{ finding_id: ID1, response_token: "a".repeat(32), disposition: "disputed", rationale: "the range check prevents it" }] };
  it("the plain call parses; every spoofed key is refused at both levels", () => {
    expect(RespondToReviewInput.safeParse(base).success).toBe(true);
    const top = ["actor", "authority", "user", "user_decision", "recorded_by", "status", "source_id", "findings", "check_results", "isolation", "verification_floor", "conditions", "incidents", "wait_seconds", "force"];
    for (const k of top) expect(RespondToReviewInput.safeParse({ ...base, [k]: "x" }).success, k).toBe(false);
    const nested = ["actor", "authority", "role", "channel", "user", "status", "triage", "title", "consequence", "evidence", "recommended_change", "source_id", "check_result", "resolved", "verified", "engine_condition", "response_id", "supersedes", "recorded_at", "item_id"];
    for (const k of nested) expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...base.responses[0], [k]: "x" }] }).success, `responses.${k}`).toBe(false);
    expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...base.responses[0], references: [{ path: "a.ts", content: "x" }] }] }).success).toBe(false);
  });
  it("bounds and vocabulary", () => {
    const one = base.responses[0]!;
    expect(RespondToReviewInput.safeParse({ ...base, responses: [] }).success).toBe(false);
    expect(RespondToReviewInput.safeParse({ ...base, responses: Array.from({ length: 51 }, () => one) }).success).toBe(false);
    expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...one, rationale: "x".repeat(2001) }] }).success).toBe(false);
    expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...one, references: Array.from({ length: 9 }, () => ({ path: "a" })) }] }).success).toBe(false);
    for (const d of ["resolved", "verified", "rejected", "fixed", "closed", "waived"]) expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...one, disposition: d }] }).success, d).toBe(false);
    for (const d of ["accepted", "disputed", "deferred", "fix_claimed"]) expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...one, disposition: d }] }).success, d).toBe(true);
    expect(RespondToReviewInput.safeParse({ ...base, responses: [{ finding_id: ID1, response_token: "t", disposition: "accepted" }] }).success).toBe(true); // rationale optional in the schema
    expect(RespondToReviewInput.safeParse({ ...base, responses: [{ ...one, references: [{ path: "a.ts", start_line: 0 }] }] }).success).toBe(false);
  });
  it("the history's responses part is strict too", () => {
    expect(GetReviewHistoryInput.safeParse({ run_id: RUN, responses: {} }).success).toBe(true);
    expect(GetReviewHistoryInput.safeParse({ run_id: RUN, responses: { finding_id: ID1, offset: 0, length: 1000 } }).success).toBe(true);
    expect(GetReviewHistoryInput.safeParse({ run_id: RUN, responses: { path: "x" } }).success).toBe(false);
    expect(GetReviewHistoryInput.safeParse({ run_id: RUN, responses: { length: 30_001 } }).success).toBe(false);
  });
});

describe("persisted compatibility (plan §1.14: additive, schema version unchanged)", () => {
  it("a record without the field (v0.1.0, v0.2.0) reads with an empty list", () => {
    const old = newStateRecord(RUN, "IDLE") as Record<string, unknown>;
    delete old["implementer_responses"];
    const parsed = StateRecordSchema.parse(old);
    expect(parsed.implementer_responses).toEqual([]);
    expect(parsed.schema_version).toBe(1);
  });

  it("an older version's read-modify-write keeps the responses (its schema has no such field: catchall)", () => {
    const withResponses = { ...newStateRecord(RUN, "IDLE"), implementer_responses: [response(ID1)] };
    const olderSchema = StateRecordSchema.omit({ implementer_responses: true });
    const rewritten = JSON.parse(JSON.stringify({ ...olderSchema.parse(JSON.parse(JSON.stringify(withResponses))), revision: 7 })) as Record<string, unknown>;
    expect(rewritten["implementer_responses"]).toEqual(withResponses.implementer_responses);
    expect(StateRecordSchema.parse(rewritten).implementer_responses).toHaveLength(1);
  });

  it("a record written by a later version (new kinds, roles, fields) does not make the run unreadable", () => {
    const later = { ...response(ID1), disposition: "waived", recorded_by: { role: "user", channel: "cli" }, waiver_reason: "accepted risk" };
    const parsed = StateRecordSchema.parse({ ...newStateRecord(RUN, "IDLE"), implementer_responses: [later] });
    expect(parsed.implementer_responses[0]).toMatchObject({ disposition: "waived", recorded_by: { role: "user" }, waiver_reason: "accepted risk" });
    expect(ImplementerResponseSchema.safeParse({ ...response(ID1), references: undefined }).success).toBe(true);
  });

  it("fields a later version adds inside a record's nested objects survive this version's read-modify-write", () => {
    const base = response(ID1);
    const later = {
      ...base,
      answers: { ...base.answers, reviewer_reply_id: "r-9" },
      source: { ...base.source, check_ids: ["c-1"] },
      recorded_by: { ...base.recorded_by, session: "s-1" },
      references: [{ path: "a.ts", start_line: 1, end_line: 2, excerpt_digest: "d" }],
    };
    const parsed = StateRecordSchema.parse(JSON.parse(JSON.stringify({ ...newStateRecord(RUN, "IDLE"), implementer_responses: [later] })));
    expect(JSON.parse(JSON.stringify(parsed.implementer_responses[0]))).toEqual(JSON.parse(JSON.stringify(later)));
    // A record written before the disclosure reference existed reads with none.
    const { disclosure_ref: _d, ...withoutRef } = base;
    expect(ImplementerResponseSchema.parse(withoutRef).disclosure_ref).toBeNull();
  });
});

describe("responses to superseded items in reports (PR #10 review)", () => {
  it("lists the latest response on every predecessor of a merged item, however many", () => {
    const olds = Array.from({ length: 8 }, (_, k) => item(`0199a1b2-0000-7000-8000-0000000001${String(k).padStart(2, "0")}`, { status: "superseded", superseded_by: ID3 }));
    const merged = item(ID3, { round: 2, supersedes: olds.map((o) => o.id) });
    const records = olds.map((o) => response(o.id, { disposition: "disputed" }));
    const shown = itemDiscussion(merged, viewOf([...olds, merged], records), null).responses_to_superseded_items;
    expect(shown.map((p) => p.item_id)).toEqual(olds.map((o) => o.id));
    expect(shown.every((p) => p.disposition === "disputed")).toBe(true);
  });
});

describe("the response history of one item: its whole thread (PR #10 review; Phase 2.2 threads)", () => {
  const uuid = (k: number) => `0199a1b2-0000-7000-8000-${String(k).padStart(12, "0")}`;

  it("follows every predecessor and every successor however many there are, once each, even through a cycle", () => {
    const st = newStateRecord(RUN, "IDLE");
    // One finding consolidates 60 earlier ones, each answered; the new finding is then superseded
    // along a chain of 55 more.
    const merged = uuid(1000);
    const olds = Array.from({ length: 60 }, (_, k) => item(uuid(k + 1), { round: 1, status: "superseded", superseded_by: merged }));
    const chain = Array.from({ length: 55 }, (_, k) => uuid(2000 + k));
    const mergedItem = item(merged, { round: 2, supersedes: olds.map((o) => o.id), status: "superseded", superseded_by: chain[0]! });
    const successors = chain.map((id, k) => item(id, { round: 3 + k, supersedes: [k === 0 ? merged : chain[k - 1]!], status: k === chain.length - 1 ? "open" : "superseded", superseded_by: chain[k + 1] ?? null }));
    st.findings = [...olds, mergedItem, ...successors];
    st.implementer_responses = olds.map((o) => response(o.id, { disposition: "disputed", rationale: `answer for ${o.id}` }));
    const doc = responsesDocument(st, merged) as { items: { finding_id: string; responses: unknown[] }[] };
    expect(doc.items).toHaveLength(60 + 1 + 55);
    expect(new Set(doc.items.map((x) => x.finding_id)).size).toBe(doc.items.length);
    expect(doc.items.filter((x) => x.responses.length === 1)).toHaveLength(60);
    // From the oldest item: Phase 2.2 (P2.2-1) — a consolidation joins its predecessors' threads,
    // so every item of the thread is shown, the merged item's other predecessors included.
    const fromOldest = responsesDocument(st, olds[0]!.id) as { items: { finding_id: string }[]; threads: { thread_id: string; merged_thread_ids: string[] }[] };
    expect(fromOldest.items.map((x) => x.finding_id)).toEqual([...olds.map((o) => o.id), merged, ...chain]);
    // One thread, identified by its earliest root; the other roots are its merged thread ids.
    expect(fromOldest.threads).toHaveLength(1);
    expect(fromOldest.threads[0]!.thread_id).toBe(olds[0]!.id);
    expect(fromOldest.threads[0]!.merged_thread_ids).toEqual(olds.slice(1).map((o) => o.id));

    // A malformed cycle (two items naming each other) ends: each appears once.
    const c = newStateRecord(RUN, "IDLE");
    c.findings = [item(ID1, { supersedes: [ID2], superseded_by: ID2 }), item(ID2, { supersedes: [ID1], superseded_by: ID1 })];
    expect((responsesDocument(c, ID1) as { items: unknown[] }).items).toHaveLength(2);
  });
});

describe("repository-context exclusions in host views (PR #10 review)", () => {
  const entry = (path: string, over: Partial<SourceEntry> = {}): SourceEntry => ({
    path,
    area: "tree",
    class: "permitted",
    disposition: "not_exported",
    size: 1,
    sha256: H(path.length.toString(16).slice(-1)),
    git_oid: "1".repeat(40),
    tracked: true,
    filter: null,
    working_tree_encoding: null,
    git_eol_normalized: false,
    ...over,
  });

  it("a read's repository-context files are withheld with both hashes unless a capture exported the name as a reviewed change; confidential names never are", () => {
    const read = withheldOfEntries([
      entry("notes/plan.md", { disposition: "excluded_repo_context", sha256: H("a"), git_oid: "b".repeat(40) }),
      entry("src/math.js", { disposition: "excluded_repo_context", sha256: H("c"), git_oid: "d".repeat(40) }),
      entry("config/db.env", { class: "excluded", sha256: H("e"), git_oid: "f".repeat(40) }),
      entry("src/other.js"),
    ]);
    expect(read.paths).toEqual(["config/db.env"]);
    expect(read.hashes.sort()).toEqual([H("e"), "f".repeat(40)]);
    expect(read.repoContext).toEqual([
      { path: "notes/plan.md", hashes: [H("a"), "b".repeat(40)] },
      { path: "src/math.js", hashes: [H("c"), "d".repeat(40)] },
    ]);
    // A capture of the run exported src/math.js as a reviewed change, and config/db.env too (a
    // confidential change is still withheld).
    const capture = withheldParts.emptyWithheld();
    capture.reviewedChanges.add("src/math.js");
    capture.reviewedChanges.add("config/db.env");
    const view = viewWithheld([capture, withheldParts.withheldOfRead(read)]);
    expect([...view.paths].sort()).toEqual(["config/db.env", "notes/plan.md"]);
    expect([...view.hashes].sort()).toEqual([H("a"), H("e"), "b".repeat(40), "f".repeat(40)].sort());
    // Without that capture nothing is exempt.
    expect([...viewWithheld([withheldParts.withheldOfRead(read)]).paths].sort()).toEqual(["config/db.env", "notes/plan.md", "src/math.js"]);
  });
});
