// The discussion's reports (Phase 2.2, plan §1.15: P2.2-6, -8, -10). PURE: no I/O, no clock.
//
// Per thread, derived from the discussion index and the preview of the next review
// (discussion.ts): who spoke last, whether the reviewer has seen the implementer's latest turn,
// the exchange budget, escalation and who must act next. Escalation is a reported state: it
// records nothing and is never a user decision.
//
// Phase 2.3 (plan §1.16, P2.3-6, -11, -12): the third layer — the user's decision on the thread,
// if any, and whether it still applies — beside the implementer's position and the reviewer's
// stance, never merged into them. An applicable decision answers an escalation (a waiver or a
// deferral settles the thread; require_resolution sends it back to the implementer and reviewer);
// a lapsed one escalates it again. Each thread says whether it still blocks task completion.

import { DISCUSSION_LIMITS, type ReviewerReply } from "../schemas/discussion.js";
import type { ImplementerResponse } from "../schemas/responses.js";
import type { ReviewerItem } from "../schemas/review.js";
import { decisionFactsOf, openItemsOf, threadUserState, type DecisionFacts, type DecisionStatus, type LapseReason, type ThreadUserState } from "./user-decisions.js";
import {
  freshAmendmentsFor,
  REPLY_SEEKING,
  respondableStatus,
  seenBy,
  threadReplies,
  threadTurns,
  turnAfter,
  turnReviewIdx,
  type DeliveryBasis,
  type DiscussionIndex,
  type DiscussionPlan,
  type EscalationReason,
  type ItemPlan,
  type Limits,
  type NotDeliveredReason,
} from "./discussion.js";
import { itemOrder, itemPositions, type Thread } from "./threads.js";

export type Awaiting = "reviewer" | "implementer" | "user" | "none";

export interface TurnSummary {
  response_id: string;
  item_id: string;
  position: string;
  recorded_at: string;
  answers_round: number;
  seen_by_reviewer: { review_id: string; round: number } | null;
  /** delivered (seen), pending (the next review presents it), not_delivered (reason). */
  delivery: "delivered" | "pending" | "not_delivered";
  delivery_reason: NotDeliveredReason | null;
  /** Why the next review would present it (pending only). */
  delivery_basis: DeliveryBasis[];
  text_withheld: boolean;
}

export interface ReplySummary {
  reply_id: string;
  item_id: string;
  review_id: string;
  round: number;
  stance: string;
  new_information: string;
  /** The reply whole: every view cuts it to an excerpt after redaction (host-view cutExcerpts). */
  reply_excerpt: string;
}

/** Who must act for the task, per thread with an open item (P2.3-11); a settled thread blocks nothing. */
export type CompletionCategory = "needs_user_decision" | "needs_reviewer" | "needs_implementer";
export type ThreadCompletion = CompletionCategory | "settled_by_waiver" | "settled_by_deferral";

/** The user's decision on a thread, as a report shows it (P2.3-12). */
export interface UserDecisionSummary {
  decision_id: string;
  kind: string;
  /** What CodeParley relied on for the record (USER_ASSURANCES: local_operator today). */
  assurance: string;
  status: DecisionStatus;
  lapse_reasons: LapseReason[];
  recorded_at: string;
  /** The note whole: every view cuts it to an excerpt after redaction (host-view cutExcerpts). */
  note_excerpt: string;
  covered_items: number;
  /** Other decisions recorded on this thread (the history lists them all). */
  earlier_decisions: number;
}

export interface ThreadReport {
  thread_id: string;
  merged_thread_ids: string[];
  /** Respondable items first (open, then informational), then closed ones; each with its token. */
  items: { id: string; kind: string; status: string; round: number; title_excerpt: string; response_token: string | null }[];
  item_count: number;
  /** The newest respondable item (null: every item is closed). */
  current_item_id: string | null;
  latest_implementer: TurnSummary | null;
  latest_reviewer: ReplySummary | null;
  last_speaker: "implementer" | "reviewer" | null;
  reviewer_seen_latest_implementer_turn: boolean | null;
  latest_stance_predates_latest_implementer_turn: boolean | null;
  exchanges: { used: number; limit: number; exhausted: boolean };
  new_information_required: boolean;
  escalation: { needed: boolean; reasons: EscalationReason[] };
  awaiting: Awaiting;
  lineage_anomalies: string[];
  /** Phase 2.3: the user's decision on the thread (null: none recorded), with whether it still applies. */
  user_decision: UserDecisionSummary | null;
  /** Phase 2.3: the thread has an open item that no applicable waiver or deferral settles. */
  blocks_completion: boolean;
  /** Phase 2.3: who must act for the task (null: nothing open). */
  completion_category: ThreadCompletion | null;
  /** Phase 2.3: the user's amendments naming this thread that Codex has not seen since it last replied (A-n). */
  user_information_pending: string[];
}

/** A turn's delivery as a report sees it now (`plan`: the preview of the next review). */
export function turnSummary(ix: DiscussionIndex, plan: DiscussionPlan, r: ImplementerResponse): TurnSummary {
  const seen = seenBy(ix, r.response_id);
  const p = plan.items.get(r.item_id);
  const latestOnItem = ix.responsesByItem.get(r.item_id)?.at(-1)?.response_id === r.response_id;
  let delivery: TurnSummary["delivery"] = "not_delivered";
  let reason: NotDeliveredReason | null = null;
  let basis: DeliveryBasis[] = [];
  if (p?.turn?.response.response_id === r.response_id) {
    // The next review presents it: new to the reviewer, or a seen reply-seeking turn still unanswered.
    delivery = "pending";
    basis = p.turn.basis;
  } else if (seen) delivery = "delivered";
  else if (!latestOnItem) reason = "superseded_before_delivery";
  else if (p?.not_delivered?.response_id === r.response_id) reason = p.not_delivered.reason;
  else if (!p) reason = "item_closed";
  return {
    response_id: r.response_id,
    item_id: r.item_id,
    position: r.disposition,
    recorded_at: r.recorded_at,
    answers_round: r.answers.round,
    seen_by_reviewer: seen,
    delivery,
    delivery_reason: reason,
    delivery_basis: basis,
    text_withheld: r.text_withheld,
  };
}

function replySummary(x: ReviewerReply): ReplySummary {
  return { reply_id: x.reply_id, item_id: x.item_id, review_id: x.review_id, round: x.round, stance: x.stance, new_information: x.new_information, reply_excerpt: x.reply };
}

/**
 * The report of one thread. `tokenOf` gives an item's current response token (null when it can
 * no longer be responded to).
 */
export function threadReport(ix: DiscussionIndex, plan: DiscussionPlan, t: Thread, tokenOf: (it: ReviewerItem) => string | null, limits: Limits = DISCUSSION_LIMITS, facts?: DecisionFacts): ThreadReport {
  const current = t.members.filter(respondableStatus);
  const turns = threadTurns(ix, t);
  const replies = threadReplies(ix, t);
  const lastTurn = turns.at(-1) ?? null;
  const lastReply = replies.at(-1) ?? null;
  const lastReplyIdx = lastReply ? (ix.reviewIdx.get(lastReply.review_id) ?? -1) : -1;
  const lastSpeaker: ThreadReport["last_speaker"] = lastTurn && lastReply ? (turnAfter(ix, lastTurn, lastReplyIdx) ? "implementer" : "reviewer") : lastTurn ? "implementer" : lastReply ? "reviewer" : null;
  const used = ix.exchanges.get(t.id) ?? 0;
  const exhausted = used >= limits.exchangesPerThread || ix.runExchanges >= limits.exchangesPerRun;
  const plans = current.map((it) => plan.items.get(it.id)).filter((p): p is ItemPlan => p !== undefined);
  const pendingReply = plans.some((p) => p.turn?.reply_sought === true);
  const notDelivered = plans.map((p) => p.not_delivered?.reason).filter((x): x is NotDeliveredReason => x !== undefined);
  const latestOn = (it: ReviewerItem) => ix.responsesByItem.get(it.id)?.at(-1) ?? null;
  const openItems = current.filter((it) => it.status === "open");
  // The implementer still argues (a dispute or a fix the reviewer has not confirmed) on a live item.
  const arguing = current.some((it) => {
    const r = latestOn(it);
    return r !== null && REPLY_SEEKING.has(r.disposition);
  });
  const reasons: EscalationReason[] = [];
  if (t.anomalies.length) reasons.push("lineage_anomaly");
  if (openItems.some((it) => latestOn(it)?.disposition === "deferred")) reasons.push("deferral_requested");
  if (lastReply?.stance === "withdraw" && ix.itemById.get(lastReply.item_id)?.status === "open") reasons.push("withdrawn_but_open");
  if (notDelivered.some((r) => r === "exchange_budget_exhausted" || r === "run_exchange_budget_exhausted") || (exhausted && arguing && !pendingReply && lastReply?.stance !== "withdraw")) reasons.push("exchange_budget_exhausted");
  if (notDelivered.includes("no_new_information")) reasons.push("disagreement_without_new_information");
  if (lastReply && lastReply.new_information === "no" && (lastReply.stance === "maintain" || lastReply.stance === "revise") && arguing && !pendingReply) reasons.push("reviewer_found_no_new_information");
  // Phase 2.3: a decision that no longer settles the thread escalates it again (P2.3-6).
  const user = threadUserState(ix, facts ?? decisionFactsOf(ix), t);
  if (user.lapsed) reasons.push("user_decision_lapsed");
  const uniqueReasons = [...new Set(reasons)];
  const newInformationRequired = notDelivered.includes("no_new_information") || (lastSpeaker === "reviewer" && lastReply?.stance === "maintain" && arguing);
  // An applicable decision answers the escalation: the user has decided (the reasons stay facts).
  const decided = user.settles !== null || user.requires_resolution;
  let awaiting: Awaiting = "none";
  if (user.settles !== null) awaiting = "none";
  else if (user.requires_resolution) awaiting = pendingReply || openItems.some((it) => !assessedByLatest(ix, it)) ? "reviewer" : "implementer";
  else if (uniqueReasons.length) awaiting = "user";
  else if (pendingReply) awaiting = "reviewer";
  else if (
    openItems.some((it) => latestOn(it) === null) ||
    (lastSpeaker === "reviewer" && current.length > 0 && lastReply?.stance !== "withdraw") ||
    openItems.some((it) => latestOn(it)?.disposition === "accepted") ||
    openItems.some((it) => {
      const r = latestOn(it);
      return r?.disposition === "fix_claimed" && it.assessments.some((a) => a.assessment === "still_present" && turnReviewIdx(ix, r) < (ix.reviewIdx.get(a.review_id) ?? -1));
    })
  )
    awaiting = "implementer";
  const escalationNeeded = uniqueReasons.length > 0 && !decided;
  const completion = threadCompletion(ix, t, user, escalationNeeded, awaiting);
  const sorted = [...t.members].sort((a, b) => rank(a) - rank(b));
  const newestCurrent = current.at(-1) ?? null;
  return {
    thread_id: t.id,
    merged_thread_ids: t.merged,
    items: sorted.slice(0, 10).map((it) => ({ id: it.id, kind: it.item_kind, status: it.status, round: it.round, title_excerpt: it.title, response_token: tokenOf(it) })),
    item_count: t.members.length,
    current_item_id: newestCurrent?.id ?? null,
    latest_implementer: lastTurn ? turnSummary(ix, plan, lastTurn) : null,
    latest_reviewer: lastReply ? replySummary(lastReply) : null,
    last_speaker: lastSpeaker,
    reviewer_seen_latest_implementer_turn: lastTurn ? seenBy(ix, lastTurn.response_id) !== null : null,
    latest_stance_predates_latest_implementer_turn: lastTurn && lastReply ? lastSpeaker === "implementer" : null,
    exchanges: { used, limit: limits.exchangesPerThread, exhausted },
    new_information_required: newInformationRequired,
    escalation: { needed: escalationNeeded, reasons: uniqueReasons },
    awaiting,
    lineage_anomalies: t.anomalies,
    user_decision: userDecisionSummary(user),
    blocks_completion: completion !== null && !completion.startsWith("settled_"),
    completion_category: completion,
    user_information_pending: pendingAmendments(ix, t, lastReply ? lastReplyIdx : ix.latestAccepted),
  };
}

function userDecisionSummary(user: ThreadUserState): UserDecisionSummary | null {
  const d = user.decision;
  if (!d || !user.state) return null;
  return {
    decision_id: d.decision_id,
    kind: d.kind,
    assurance: d.recorded_by.assurance ?? "",
    status: user.state.status,
    lapse_reasons: user.state.reasons,
    recorded_at: d.recorded_at,
    note_excerpt: d.note,
    covered_items: d.covered_items.length,
    earlier_decisions: user.earlier,
  };
}

/**
 * Who must act for the task on this thread (P2.3-11). Only an OPEN item blocks: an applicable
 * waiver or deferral settles it; otherwise a needed escalation (a lapsed decision included) waits
 * for the user, a pending reply or an open item the latest accepted review did not assess waits for
 * the reviewer, and anything else waits for the implementer (`require_resolution` included).
 */
function threadCompletion(ix: DiscussionIndex, t: Thread, user: ThreadUserState, escalationNeeded: boolean, awaiting: Awaiting): ThreadCompletion | null {
  const open = openItemsOf(t);
  if (open.length === 0) return null;
  if (user.settles === "waived") return "settled_by_waiver";
  if (user.settles === "deferred") return "settled_by_deferral";
  if (escalationNeeded) return "needs_user_decision";
  if (awaiting === "reviewer" || open.some((it) => !assessedByLatest(ix, it))) return "needs_reviewer";
  return "needs_implementer";
}

/** Raised by the run's latest accepted review, or assessed by it (an omission does not count). */
function assessedByLatest(ix: DiscussionIndex, it: ReviewerItem): boolean {
  const latest = ix.latestAccepted >= 0 ? ix.src.reviews[ix.latestAccepted] : undefined;
  if (!latest || it.review_id === latest.review_id) return true;
  return it.assessments.some((a) => a.review_id === latest.review_id && a.assessment !== "not_assessed" && a.assessment !== "no_longer_assessable");
}

/** The user's amendments naming this thread that Codex has not seen up to review `seenUpTo` (A-n labels). */
function pendingAmendments(ix: DiscussionIndex, t: Thread, seenUpTo: number): string[] {
  return freshAmendmentsFor(ix, t, seenUpTo).map((a) => `A-${a.seq}`);
}

function rank(it: ReviewerItem): number {
  return it.status === "open" ? 0 : it.status === "informational" ? 1 : 2;
}

const AWAITING_ORDER: Record<Awaiting, number> = { user: 0, implementer: 1, reviewer: 2, none: 3 };

/**
 * Every thread with a respondable item (open or informational: P2.2-10), ordered by who must
 * act (user, implementer, reviewer, then nobody), then by thread order.
 */
export function threadReports(ix: DiscussionIndex, plan: DiscussionPlan, tokenOf: (it: ReviewerItem) => string | null, limits: Limits = DISCUSSION_LIMITS): ThreadReport[] {
  const order = itemOrder(itemPositions(ix.src.reviews));
  const threads = [...ix.threads.threads.values()].filter((t) => t.members.some(respondableStatus));
  threads.sort((a, b) => order(a.members[0]!, b.members[0]!));
  const facts = decisionFactsOf(ix);
  const reports = threads.map((t) => threadReport(ix, plan, t, tokenOf, limits, facts));
  return reports.map((r, k) => ({ r, k })).sort((a, b) => AWAITING_ORDER[a.r.awaiting] - AWAITING_ORDER[b.r.awaiting] || a.k - b.k).map((x) => x.r);
}

/**
 * Threads whose open item needs the user's decision: completion's needs_user_decision category (a
 * damaged lineage is an engine condition instead). P3.3b: the operator's resume guard.
 */
export function threadsNeedingUserDecision(reports: readonly Pick<ThreadReport, "thread_id" | "blocks_completion" | "completion_category" | "lineage_anomalies">[]): string[] {
  return reports.filter((t) => t.blocks_completion && t.completion_category === "needs_user_decision" && t.lineage_anomalies.length === 0).map((t) => t.thread_id);
}

export interface ThreadCounts {
  threads_total: number;
  awaiting_reviewer: number;
  awaiting_implementer: number;
  awaiting_user: number;
  escalated: number;
  reviewer_replies_recorded: number;
  exchanges_used: number;
  exchanges_limit_per_run: number;
  /** Phase 2.3: threads that still block task completion, and threads a user waiver or deferral settles. */
  blocking_completion: number;
  settled_by_user: number;
}

export function threadCounts(ix: DiscussionIndex, reports: readonly ThreadReport[], limits: Limits = DISCUSSION_LIMITS): ThreadCounts {
  return {
    threads_total: reports.length,
    awaiting_reviewer: reports.filter((r) => r.awaiting === "reviewer").length,
    awaiting_implementer: reports.filter((r) => r.awaiting === "implementer").length,
    awaiting_user: reports.filter((r) => r.awaiting === "user").length,
    escalated: reports.filter((r) => r.escalation.needed).length,
    reviewer_replies_recorded: ix.src.replies.length,
    exchanges_used: ix.runExchanges,
    exchanges_limit_per_run: limits.exchangesPerRun,
    blocking_completion: reports.filter((r) => r.blocks_completion).length,
    settled_by_user: reports.filter((r) => r.completion_category === "settled_by_waiver" || r.completion_category === "settled_by_deferral").length,
  };
}
