// Record builders for the Phase 2.3 policy unit tests (test/user-authority-units.test.ts): reviewer
// items, implementer turns, reviewer replies, reviews, user decisions and task amendments with
// valid defaults, each overridable per test.

import type { ReviewLike } from "../../src/policy/discussion.js";
import type { Delivery, ReviewerReply } from "../../src/schemas/discussion.js";
import type { ImplementerResponse } from "../../src/schemas/responses.js";
import type { ReviewerItem } from "../../src/schemas/review.js";
import type { TaskAmendment, UserDecision } from "../../src/schemas/user-authority.js";

const H = (c: string) => c.repeat(64);
export const S1 = H("1");
const EV = H("e");

export function item(id: string, over: Partial<ReviewerItem> = {}): ReviewerItem {
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
export function turn(itemId: string, over: Partial<ImplementerResponse> & { after?: string } = {}): ImplementerResponse {
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

export function reply(itemId: string, reviewId: string, round: number, answers: string | null, over: Partial<ReviewerReply> = {}): ReviewerReply {
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

export function review(id: string, round: number, over: Partial<ReviewLike> & { delivered?: Delivery[]; presented?: string[] } = {}): ReviewLike {
  const { delivered, presented, ...rest } = over;
  return {
    review_id: id,
    round,
    accepted: true,
    source_id: S1,
    check_evidence_digest: EV,
    item_ids: [],
    discussion: { delivered: delivered ?? [], check_results_digest: EV },
    ...(presented ? { amendments: { presented: presented.map((amendment_id) => ({ amendment_id })) } } : {}),
    ...rest,
  };
}

export function decision(id: string, covered: string[], over: Partial<UserDecision> = {}): UserDecision {
  return {
    decision_id: id,
    thread_id: covered[0] ?? "x",
    current_item_id: covered.at(-1) ?? "x",
    covered_items: covered,
    kind: "waive",
    note: "",
    decided_against: { token: "t", run_review_id: "r1", run_round: 1, latest_reply_id: null, latest_response_id: null, amendments_seq: 0 },
    context: { awaiting: "user", escalation_reasons: [], reviewer_stance: null, implementer_position: null },
    supersedes: [],
    source: null,
    disclosure_ref: null,
    recorded_by: { role: "user", channel: "local_cli", assurance: "local_operator", tool_version: "0.2.0" },
    request_id: null,
    request_digest: H("a"),
    recorded_at: "2026-10-06T00:00:00Z",
    ...over,
  };
}

export function amendment(id: string, seq: number, over: Partial<TaskAmendment> = {}): TaskAmendment {
  return {
    amendment_id: id,
    seq,
    kind: "constraint",
    text: `amendment ${seq}`,
    relates_to: [],
    replaces: null,
    source: { source_id: S1, note: null },
    disclosure_ref: null,
    recorded_by: { role: "user", channel: "local_cli", assurance: "local_operator", tool_version: "0.2.0" },
    request_id: null,
    request_digest: H("c"),
    recorded_at: "2026-10-06T00:00:00Z",
    ...over,
  };
}
