// The bounded reviewer–implementer discussion (Phase 2.2, plan §1.15). PURE: no I/O, no clock.
//
// Layers stay apart: the reviewer's item lifecycle (findings: changed only by accepted reviews
// through the carry-forward rules), the implementer's turns (P2.1 responses), the reviewer's
// turns (replies, written only by accepted reviews), and what each review's bundle presented
// (delivery records). This module derives everything else on read:
//  - who has seen what: a turn is SEEN by the reviewer only through the delivery record of an
//    ACCEPTED review (P2.2-6); never because a later review happened;
//  - order without clocks: a turn comes after a reply when the run's current accepted review at
//    its recording is the reply's review or a later one (responses are never recorded while a
//    review runs, P2.1-7);
//  - the exchange budget per thread (P2.2-7): one exchange per reply-seeking turn delivered to an
//    accepted review, counted over every item of the thread's lineage — supersession,
//    restatement and consolidation never reset it;
//  - the NEW-INFORMATION GATE: which undelivered turn earns another exchange; a repetition of the
//    same position (rephrased text included) is recorded but not delivered;
//  - what a review presents (planDiscussion) and how its replies are taken (processReplies).
// The thread reports with escalation (P2.2-8) are in discussion-reports.ts.
// Phase 2.3 (plan §1.16): the index also carries the user's records — decisions (judged in
// user-decisions.ts) and task amendments, whose delivery is tracked like a turn's — and an
// amendment that names a thread is new information for it until Codex has replied having seen it
// (the gate's `user_amendment` basis, P2.3-10).

import { sha256OfCanonicalJson, sha256OfString } from "../common/hash.js";
import { DISCUSSION_LIMITS, type Delivery, type ReviewerReply, type Stance } from "../schemas/discussion.js";
import type { ImplementerResponse, ResponseReference } from "../schemas/responses.js";
import type { DiscussionReplyOut, ReviewerItem } from "../schemas/review.js";
import type { StateRecord } from "../schemas/run-state.js";
import type { TaskAmendment, UserDecision } from "../schemas/user-authority.js";
import { buildAmendmentFacts, newAmendmentsFor, type AmendmentFacts } from "./amendments.js";
import { buildThreads, itemOrder, itemPositions, type Thread, type ThreadIndex } from "./threads.js";

export const DISCUSSION_POLICY_VERSION = "discussion.v1";

/** Dispositions that ask the reviewer for a reply: each delivery is an exchange. */
export const REPLY_SEEKING: ReadonlySet<string> = new Set(["disputed", "fix_claimed"]);
/** Dispositions presented as context: no reply sought, no exchange used. */
const CONTEXT: ReadonlySet<string> = new Set(["accepted", "deferred"]);

export type Limits = typeof DISCUSSION_LIMITS;

/** Why a turn earns its delivery (the gate), or why it is presented as context. */
export type DeliveryBasis =
  | "first_exchange"
  | "no_reply_yet"
  | "unanswered"
  | "answers_reviewer_question"
  | "reviewer_revised"
  | "source_changed"
  | "check_evidence_changed"
  | "position_changed"
  | "new_references"
  // Phase 2.3: an amendment by the user that names the thread, not seen by the reviewer when it last replied.
  | "user_amendment"
  | "context"
  | "answer_to_question";

export type NotDeliveredReason =
  | "text_withheld"
  | "item_closed"
  | "unknown_disposition"
  | "informational_context_only"
  | "no_new_information"
  | "exchange_budget_exhausted"
  | "run_exchange_budget_exhausted"
  | "review_reply_cap"
  | "review_context_cap"
  | "bundle_size_cap"
  | "superseded_before_delivery";

export type EscalationReason =
  | "exchange_budget_exhausted"
  | "disagreement_without_new_information"
  | "reviewer_found_no_new_information"
  | "deferral_requested"
  | "withdrawn_but_open"
  | "lineage_anomaly"
  // Phase 2.3: the user's decision on the thread no longer settles it (P2.3-6).
  | "user_decision_lapsed";

/** The review fields this module reads (a ReviewRecord satisfies it). */
export interface ReviewLike {
  review_id: string;
  round: number;
  accepted: boolean | null;
  source_id: string;
  check_evidence_digest: string;
  item_ids: readonly string[];
  discussion?: { delivered: readonly Delivery[]; check_results_digest?: string | undefined } | undefined;
  /** Phase 2.3: the task amendments the review presented (P2.3-9). */
  amendments?: { presented: readonly { amendment_id: string }[] } | undefined;
}

export interface DiscussionSource {
  items: readonly ReviewerItem[];
  responses: readonly ImplementerResponse[];
  replies: readonly ReviewerReply[];
  reviews: readonly ReviewLike[];
  /** Phase 2.3: the user's decisions and task amendments (absent: none). */
  decisions?: readonly UserDecision[] | undefined;
  amendments?: readonly TaskAmendment[] | undefined;
}

interface Seen {
  review_id: string;
  round: number;
  reviewIdx: number;
  reply_sought: boolean;
  basis: readonly string[];
}

/** Everything derived once per call (a report, a review's bundle, a response check). */
export interface DiscussionIndex {
  src: DiscussionSource;
  threads: ThreadIndex;
  itemById: Map<string, ReviewerItem>;
  reviewIdx: Map<string, number>;
  /** Accepted deliveries of each response, oldest first. */
  seen: Map<string, Seen[]>;
  responsesByItem: Map<string, ImplementerResponse[]>;
  responseById: Map<string, ImplementerResponse>;
  repliesByItem: Map<string, ReviewerReply[]>;
  /** Exchanges used per thread id (reply-seeking deliveries to accepted reviews). */
  exchanges: Map<string, number>;
  runExchanges: number;
  /** Index of the run's latest accepted review (-1: none). */
  latestAccepted: number;
  /** Phase 2.3: the user's task amendments, their effective set and who has seen them. */
  amendments: AmendmentFacts;
}

/** The run-state fields a discussion is derived from (Phase 2.3's user records optional: none when absent). */
export type DiscussionStateFields = Pick<StateRecord, "findings" | "implementer_responses" | "reviewer_replies" | "reviews"> & Partial<Pick<StateRecord, "user_decisions" | "task_amendments">>;

/** The discussion source of a run state. */
export function discussionSourceOf(st: DiscussionStateFields): DiscussionSource {
  return { items: st.findings, responses: st.implementer_responses, replies: st.reviewer_replies, reviews: st.reviews, decisions: st.user_decisions ?? [], amendments: st.task_amendments ?? [] };
}

/** The discussion index of a run state. */
export function discussionIndexOf(st: DiscussionStateFields): DiscussionIndex {
  return buildDiscussionIndex(discussionSourceOf(st));
}

export function buildDiscussionIndex(src: DiscussionSource): DiscussionIndex {
  const threads = buildThreads(src.items, itemPositions(src.reviews));
  const itemById = new Map<string, ReviewerItem>();
  for (const it of src.items) if (!itemById.has(it.id)) itemById.set(it.id, it);
  const reviewIdx = new Map<string, number>();
  src.reviews.forEach((r, k) => {
    reviewIdx.set(r.review_id, k);
  });
  const seen = new Map<string, Seen[]>();
  const exchanges = new Map<string, number>();
  let runExchanges = 0;
  let latestAccepted = -1;
  src.reviews.forEach((r, k) => {
    if (r.accepted !== true) return;
    latestAccepted = k;
    for (const d of r.discussion?.delivered ?? []) {
      const list = seen.get(d.response_id) ?? [];
      list.push({ review_id: r.review_id, round: r.round, reviewIdx: k, reply_sought: d.reply_sought, basis: d.basis });
      seen.set(d.response_id, list);
      if (d.reply_sought) {
        const t = threads.threadOf.get(d.item_id) ?? d.item_id;
        exchanges.set(t, (exchanges.get(t) ?? 0) + 1);
        runExchanges++;
      }
    }
  });
  const responsesByItem = new Map<string, ImplementerResponse[]>();
  const responseById = new Map<string, ImplementerResponse>();
  for (const r of src.responses) {
    responseById.set(r.response_id, r);
    const l = responsesByItem.get(r.item_id);
    if (l) l.push(r);
    else responsesByItem.set(r.item_id, [r]);
  }
  const repliesByItem = new Map<string, ReviewerReply[]>();
  for (const r of src.replies) {
    const l = repliesByItem.get(r.item_id);
    if (l) l.push(r);
    else repliesByItem.set(r.item_id, [r]);
  }
  return { src, threads, itemById, reviewIdx, seen, responsesByItem, responseById, repliesByItem, exchanges, runExchanges, latestAccepted, amendments: buildAmendmentFacts(src.amendments ?? [], src.reviews) };
}

// ---------------------------------------------------------------------------
// Turns, replies and order
// ---------------------------------------------------------------------------

/** The thread of an item (a lone item is its own thread). */
export function threadOfItem(ix: DiscussionIndex, it: ReviewerItem): Thread {
  const id = ix.threads.threadOf.get(it.id);
  return (id ? ix.threads.threads.get(id) : undefined) ?? { id: it.id, members: [it], merged: [], anomalies: [] };
}

/** The review index a turn was recorded after (the run's current accepted review then; P2.1 records: the item's latest review). */
export function turnReviewIdx(ix: DiscussionIndex, r: ImplementerResponse): number {
  const id = r.answers.run_review_id ?? r.answers.review_id;
  return id ? (ix.reviewIdx.get(id) ?? -1) : -1;
}

/** Was the turn recorded after the review at `reviewIdx` completed? */
export function turnAfter(ix: DiscussionIndex, r: ImplementerResponse, reviewIdx: number): boolean {
  return turnReviewIdx(ix, r) >= reviewIdx;
}

/** Every turn on the thread's items, in record order. */
export function threadTurns(ix: DiscussionIndex, t: Thread): ImplementerResponse[] {
  const ids = new Set(t.members.map((m) => m.id));
  return ix.src.responses.filter((r) => ids.has(r.item_id));
}

/** Every reviewer reply on the thread's items, in record order (= review order). */
export function threadReplies(ix: DiscussionIndex, t: Thread): ReviewerReply[] {
  const ids = new Set(t.members.map((m) => m.id));
  return ix.src.replies.filter((r) => ids.has(r.item_id));
}

/** The first accepted review that presented the turn (null: not seen by the reviewer). */
export function seenBy(ix: DiscussionIndex, responseId: string): { review_id: string; round: number } | null {
  const s = ix.seen.get(responseId)?.[0];
  return s ? { review_id: s.review_id, round: s.round } : null;
}

/** The reply answering a turn, if any. */
function replyTo(ix: DiscussionIndex, r: ImplementerResponse): ReviewerReply | null {
  return (ix.repliesByItem.get(r.item_id) ?? []).find((x) => x.answers.response_id === r.response_id) ?? null;
}

/** The comparison form of a cited path (the platform's name rules). */
export type PathKey = (path: string) => string;

/** A cited location as the gate compares it: the path by the platform's name rules, and the lines. */
function refKey(x: ResponseReference, pathKey: PathKey): string {
  return `${pathKey(x.path)}\u0000${x.start_line ?? ""}\u0000${x.end_line ?? ""}`;
}

/** P3.4C-5 Increment 3: a cited location's comparison key as the custodian holds it (its text is never held): the SHA-256
 * of the gate's own comparison form, so equal keys are equal locations by the engine's name rules. */
export function referenceKey(x: Pick<ResponseReference, "path" | "start_line" | "end_line">, pathKey: PathKey): string {
  return sha256OfString(refKey(x as ResponseReference, pathKey));
}

const exactPath: PathKey = (p) => p;

/** One check's result as a review saw it (the engine's model-visible check evidence). */
export interface CheckResultLike {
  check: string;
  required: boolean;
  status: string;
  last_execution_status: string | null;
  exit_code: number | null;
  timed_out: boolean;
  cancelled: boolean;
}

/**
 * The digest of what the checks found (P2.2-7): per check its requirement, status, last
 * execution status, exit code, timeout and cancellation, and whether the floor is configured
 * and satisfied. Never durations or execution ids: running unchanged checks again is no new
 * information (PR #11 review).
 */
export function checkResultsDigest(items: readonly CheckResultLike[], floor: { configured: boolean; satisfied_for_current_source: boolean }): string {
  const rows = items.map((x) => [x.check, x.required, x.status, x.last_execution_status, x.exit_code, x.timed_out, x.cancelled]).sort((a, b) => (String(a[0]) < String(b[0]) ? -1 : String(a[0]) > String(b[0]) ? 1 : 0));
  return sha256OfCanonicalJson({ schema: "arl.check-results.v1", checks: rows, floor: [floor.configured, floor.satisfied_for_current_source] });
}

// ---------------------------------------------------------------------------
// The gate (P2.2-7)
// ---------------------------------------------------------------------------

export interface Now {
  /**
   * The source the (next) review looks at; null when unknown — a report then judges a turn
   * against the source recorded with it (a preview; the review decides with its own source).
   */
  sourceId: string | null;
  /**
   * What the checks found for that source (`checkResultsDigest`); null when unknown (not
   * compared). Compared with the digest the review of the latest reply recorded.
   */
  checkResults: string | null;
  /**
   * The comparison form of a cited path: the platform's name rules (the engine passes
   * `caseKey`: lower case on Windows, exact on POSIX). Default: exact.
   */
  pathKey?: PathKey;
  /**
   * Phase 2.3: the amendments the review can present (the bundle withholds one whose text the
   * confidentiality scan could not finish). Only these count as new information there. Absent:
   * every effective amendment counts (status and the response preview, which cannot tell).
   */
  deliverableAmendments?: ReadonlySet<string>;
}

/**
 * Why an undelivered reply-seeking turn earns an exchange — empty when it does not (a
 * repetition). Compared with the thread's latest answered exchange; rephrased text is never a
 * reason.
 */
export function gateBases(ix: DiscussionIndex, t: Thread, turn: ImplementerResponse, now: Now): DeliveryBasis[] {
  const last = threadReplies(ix, t).at(-1);
  if (!last) return [firstBasis(ix, t)];
  const rIdx = ix.reviewIdx.get(last.review_id) ?? -1;
  return [...reviewerBases(ix, turn, last, rIdx), ...evidenceBases(rIdx >= 0 ? ix.src.reviews[rIdx] : undefined, turn, now), ...turnBases(ix, t, turn, last, now.pathKey ?? exactPath), ...userBases(ix, t, rIdx, now)];
}

/**
 * Phase 2.3 (P2.3-10): an effective user amendment that names the thread and that Codex had not
 * seen — nor its content — when it gave the thread's latest reply (in review `rIdx`), and that the
 * review can present. One amendment earns at most one exchange per thread (planDiscussion grants a
 * thread one turn on this basis alone per review), and the thread's budget is never reset.
 */
function userBases(ix: DiscussionIndex, t: Thread, rIdx: number, now: Now): DeliveryBasis[] {
  const deliverable = now.deliverableAmendments;
  return freshAmendmentsFor(ix, t, rIdx).some((a) => !deliverable || deliverable.has(a.amendment_id)) ? ["user_amendment"] : [];
}

/**
 * The effective amendments that are new information for the thread (P2.3-10): they name it, Codex
 * had not seen them, nor their content, when it gave the thread's latest reply (in review `rIdx`),
 * and none of them has already unlocked an exchange of the thread. The gate and the thread report
 * (`user_information_pending`) both use this.
 */
export function freshAmendmentsFor(ix: DiscussionIndex, t: Thread, rIdx: number): TaskAmendment[] {
  const members = new Set(t.members.map((m) => m.id));
  const spent = amendmentsSpentOn(ix, members);
  return newAmendmentsFor(ix.amendments, members, rIdx).filter((a) => !spent.has(a.amendment_id));
}

/**
 * Amendments that already unlocked an exchange of this thread: an accepted review presented them
 * and delivered a turn of the thread on the amendment basis. That is their one exchange per
 * thread, also when Codex did not reply (the turn is then presented again as unanswered, P2.2).
 */
function amendmentsSpentOn(ix: DiscussionIndex, members: ReadonlySet<string>): Set<string> {
  const out = new Set<string>();
  for (const r of ix.src.reviews) {
    if (r.accepted !== true) continue;
    if (!(r.discussion?.delivered ?? []).some((d) => d.reply_sought && members.has(d.item_id) && d.basis.includes("user_amendment"))) continue;
    for (const p of r.amendments?.presented ?? []) out.add(p.amendment_id);
  }
  return out;
}

/** A reply-seeking turn whose only reason to be presented is a user amendment. */
function amendmentOnly(d: Classified): boolean {
  return d !== null && "basis" in d && d.reply_sought && d.basis.length > 0 && d.basis.every((b) => b === "user_amendment");
}

/**
 * The item's latest turn classified within a plan (P2.3-10): an amendment unlocks one exchange per
 * thread, so a second turn of the thread that only the amendment would let through is a
 * repetition — the review presents the amendment once, with the first.
 */
function classifyInPlan(ix: DiscussionIndex, it: ReviewerItem, t: Thread, latest: ImplementerResponse, now: Now, c: PlanCounts): Classified {
  const decided = classify(ix, it, t, latest, now);
  return amendmentOnly(decided) && c.amendmentThreads.has(t.id) ? { reason: "no_new_information" } : decided;
}

/** No reply in the thread yet: its first exchange, or a turn delivered earlier still awaits one. */
function firstBasis(ix: DiscussionIndex, t: Thread): DeliveryBasis {
  const members = new Set(t.members.map((m) => m.id));
  const asked = [...ix.seen.entries()].some(([id, s]) => s.some((x) => x.reply_sought) && members.has(ix.responseById.get(id)?.item_id ?? ""));
  return asked ? "no_reply_yet" : "first_exchange";
}

/** What the reviewer did with its latest reply (in review `rIdx`): asked for information the turn answers, or revised. */
function reviewerBases(ix: DiscussionIndex, turn: ImplementerResponse, last: ReviewerReply, rIdx: number): DeliveryBasis[] {
  const bases: DeliveryBasis[] = [];
  if (last.stance === "need_information" && turnAfter(ix, turn, rIdx)) bases.push("answers_reviewer_question");
  const item = ix.itemById.get(turn.item_id);
  const raisedAt = item ? (ix.reviewIdx.get(item.review_id) ?? -1) : -1;
  if (last.stance === "revise" || (rIdx >= 0 && raisedAt >= rIdx)) bases.push("reviewer_revised");
  return bases;
}

/** The evidence since the review of the latest reply: the source (judged by `now`, else the turn's own), else the check results. */
function evidenceBases(review: ReviewLike | undefined, turn: ImplementerResponse, now: Now): DeliveryBasis[] {
  if (!review) return [];
  const sourceNow = now.sourceId ?? turn.source.source_id;
  if (sourceNow !== null && sourceNow !== review.source_id) return ["source_changed"];
  // A review recorded before the results digest existed is not compared (no reply predates it in a released version).
  const reviewedResults = review.discussion?.check_results_digest;
  return reviewedResults !== undefined && now.checkResults !== null && now.checkResults !== reviewedResults ? ["check_evidence_changed"] : [];
}

/** What the turn itself brings: another position than the one the reply answered, or a location no delivered turn cited. */
function turnBases(ix: DiscussionIndex, t: Thread, turn: ImplementerResponse, last: ReviewerReply, pathKey: PathKey): DeliveryBasis[] {
  const bases: DeliveryBasis[] = [];
  const answered = last.answers.response_id ? ix.responseById.get(last.answers.response_id) : undefined;
  if (answered && answered.disposition !== turn.disposition) bases.push("position_changed");
  const cited = new Set<string>();
  for (const r of threadTurns(ix, t)) if (r.response_id !== turn.response_id && ix.seen.has(r.response_id) && !r.text_withheld) for (const x of r.references) cited.add(refKey(x, pathKey));
  if (turn.references.some((x) => !cited.has(refKey(x, pathKey)))) bases.push("new_references");
  return bases;
}

// ---------------------------------------------------------------------------
// What a review presents (P2.2-4)
// ---------------------------------------------------------------------------

export interface HistoryEntry {
  from: "implementer" | "reviewer";
  item_id: string;
  /** The round the item was raised in (labels an item the bundle does not present). */
  item_round: number;
  /** implementer: the response; reviewer: the reply. */
  id: string;
  /** implementer: the round of the accepted review it followed; reviewer: the reply's round. */
  round: number;
  position?: string;
  rationale?: string;
  references?: ResponseReference[];
  stance?: string;
  reply?: string;
  new_information?: string;
}

export interface TurnPlan {
  response: ImplementerResponse;
  reply_sought: boolean;
  basis: DeliveryBasis[];
}

export interface ItemPlan {
  item_id: string;
  thread_id: string;
  /** What this review presents for the item (null: nothing new). */
  turn: TurnPlan | null;
  /** The item's latest turn when it is not presented, with the reason (reports). */
  not_delivered: { response_id: string; reason: NotDeliveredReason } | null;
  /** Earlier delivered turns and replies of the thread, oldest first (bounded). */
  history: HistoryEntry[];
  /** The thread has turns or replies at all. */
  has_discussion: boolean;
  exchanges_used: number;
  exchanges_limit: number;
  budget_exhausted: boolean;
}

export interface DiscussionPlan {
  items: Map<string, ItemPlan>;
  reply_sought: number;
  context: number;
  run_exchanges_used: number;
}

export function respondableStatus(it: ReviewerItem): boolean {
  return it.status === "open" || it.status === "informational";
}

/**
 * Plan what a review presents: per respondable item, its latest turn when that turn is new to
 * the reviewer (or a delivered reply-seeking turn still unanswered), classified, gated and
 * budgeted — open items first, then informational ones, each in item order. Planned exchanges
 * count against the thread, run and review budgets as they are granted.
 */
export function planDiscussion(ix: DiscussionIndex, now: Now, limits: Limits = DISCUSSION_LIMITS): DiscussionPlan {
  const order = itemOrder(itemPositions(ix.src.reviews));
  const candidates = ix.src.items.filter((it) => ix.itemById.get(it.id) === it && respondableStatus(it));
  candidates.sort((a, b) => (a.status === b.status ? order(a, b) : a.status === "open" ? -1 : 1));
  const c: PlanCounts = { planned: new Map(), replySought: 0, context: 0, runUsed: ix.runExchanges, amendmentThreads: new Set() };
  const out = new Map<string, ItemPlan>();
  for (const it of candidates) {
    const t = threadOfItem(ix, it);
    const used = (ix.exchanges.get(t.id) ?? 0) + (c.planned.get(t.id) ?? 0);
    const base: ItemPlan = {
      item_id: it.id,
      thread_id: t.id,
      turn: null,
      not_delivered: null,
      history: [],
      has_discussion: threadTurns(ix, t).length > 0 || threadReplies(ix, t).length > 0,
      exchanges_used: used,
      exchanges_limit: limits.exchangesPerThread,
      budget_exhausted: used >= limits.exchangesPerThread,
    };
    const latest = ix.responsesByItem.get(it.id)?.at(-1);
    const decided = latest ? classifyInPlan(ix, it, t, latest, now, c) : null;
    if (latest && decided) admit(base, latest, decided, c, limits);
    base.history = historyOf(ix, t, base.turn?.response.response_id ?? null).slice(-limits.historyPerItem);
    out.set(it.id, base);
  }
  return { items: out, reply_sought: c.replySought, context: c.context, run_exchanges_used: c.runUsed };
}

type Classified = { reply_sought: boolean; basis: DeliveryBasis[] } | { reason: NotDeliveredReason } | null;

/** What a plan has granted so far: exchanges per thread, replies sought, context turns, the run's exchanges. */
interface PlanCounts {
  planned: Map<string, number>;
  replySought: number;
  context: number;
  runUsed: number;
  /** Threads that already have a turn presented on a user amendment alone (P2.3-10). */
  amendmentThreads: Set<string>;
}

/** Present the item's latest turn as classified, unless a budget or cap refuses it; counts what it grants. */
function admit(base: ItemPlan, latest: ImplementerResponse, decided: NonNullable<Classified>, c: PlanCounts, limits: Limits): void {
  if ("reason" in decided) base.not_delivered = { response_id: latest.response_id, reason: decided.reason };
  else if (!decided.reply_sought) {
    if (c.context >= limits.contextPerReview) base.not_delivered = { response_id: latest.response_id, reason: "review_context_cap" };
    else {
      base.turn = { response: latest, reply_sought: false, basis: decided.basis };
      c.context++;
    }
  } else {
    const refusal = budgetRefusal(base.exchanges_used, c, limits);
    if (refusal) base.not_delivered = { response_id: latest.response_id, reason: refusal };
    else {
      base.turn = { response: latest, reply_sought: true, basis: decided.basis };
      c.planned.set(base.thread_id, (c.planned.get(base.thread_id) ?? 0) + 1);
      c.replySought++;
      c.runUsed++;
      if (amendmentOnly(decided)) c.amendmentThreads.add(base.thread_id);
    }
  }
}

/** Why a reply-seeking turn is not presented now: its thread's budget, the run's, or this review's reply cap. */
function budgetRefusal(threadUsed: number, c: PlanCounts, limits: Limits): NotDeliveredReason | null {
  if (threadUsed >= limits.exchangesPerThread) return "exchange_budget_exhausted";
  if (c.runUsed >= limits.exchangesPerRun) return "run_exchange_budget_exhausted";
  return c.replySought >= limits.replySoughtPerReview ? "review_reply_cap" : null;
}

/** The delivery class of an item's latest turn (null: nothing to deliver — already seen and settled). */
function classify(ix: DiscussionIndex, it: ReviewerItem, t: Thread, r: ImplementerResponse, now: Now): Classified {
  if (r.text_withheld) return { reason: "text_withheld" };
  const deliveries = ix.seen.get(r.response_id) ?? [];
  if (REPLY_SEEKING.has(r.disposition)) {
    if (deliveries.some((d) => d.reply_sought)) return replyTo(ix, r) ? null : { reply_sought: true, basis: ["unanswered"] };
    if (deliveries.length) return null;
    const bases = gateBases(ix, t, r, now);
    return bases.length ? { reply_sought: true, basis: bases } : { reason: "no_new_information" };
  }
  if (!CONTEXT.has(r.disposition)) return { reason: "unknown_disposition" };
  if (deliveries.length) return null;
  if (it.status === "open") return { reply_sought: false, basis: ["context"] };
  if (it.item_kind === "question" && r.rationale.trim() !== "") return { reply_sought: false, basis: ["answer_to_question"] };
  return { reason: "informational_context_only" };
}

/** Delivered turns and replies of the thread, oldest first (the turn presented now excluded). */
export function historyOf(ix: DiscussionIndex, t: Thread, excludeResponseId: string | null): HistoryEntry[] {
  const entries: { key: [number, number, number]; e: HistoryEntry }[] = [];
  threadTurns(ix, t).forEach((r, k) => {
    const s = ix.seen.get(r.response_id)?.[0];
    if (!s || r.response_id === excludeResponseId || r.text_withheld) return;
    entries.push({
      key: [s.reviewIdx, 0, k],
      e: { from: "implementer", item_id: r.item_id, item_round: ix.itemById.get(r.item_id)?.round ?? 0, id: r.response_id, round: r.answers.run_round ?? r.answers.round, position: r.disposition, rationale: r.rationale, references: r.references },
    });
  });
  threadReplies(ix, t).forEach((x, k) => {
    const idx = ix.reviewIdx.get(x.review_id) ?? -1;
    entries.push({ key: [idx, 1, k], e: { from: "reviewer", item_id: x.item_id, item_round: ix.itemById.get(x.item_id)?.round ?? 0, id: x.reply_id, round: x.round, stance: x.stance, reply: x.reply, new_information: x.new_information } });
  });
  entries.sort((a, b) => a.key[0] - b.key[0] || a.key[1] - b.key[1] || a.key[2] - b.key[2]);
  return entries.map((x) => x.e);
}

// ---------------------------------------------------------------------------
// Taking a review's replies (P2.2-3)
// ---------------------------------------------------------------------------

export interface AwaitingReply {
  item_id: string;
  alias: string;
  response_id: string;
}

export interface ProcessRepliesInput {
  replies: readonly DiscussionReplyOut[];
  /** Items the bundle presented with awaiting_reply. */
  awaiting: readonly AwaitingReply[];
  /** Every alias and item id the bundle presented (lower case) → item id. */
  presented: ReadonlyMap<string, string>;
  /** This review's lifecycle assessment per item id (prior items only). */
  assessments: ReadonlyMap<string, string>;
  reviewId: string;
  round: number;
  sourceId: string;
  recordedAt: string;
  newId: () => string;
  clampReply: (s: string) => string;
}

export interface ProcessedReplies {
  records: ReviewerReply[];
  notes: string[];
  /** Item ids that awaited a reply and got none. */
  missing: string[];
}

export function processReplies(i: ProcessRepliesInput): ProcessedReplies {
  const awaiting = new Map(i.awaiting.map((a) => [a.item_id, a]));
  const records: ReviewerReply[] = [];
  const notes: string[] = [];
  const done = new Set<string>();
  for (const r of i.replies) {
    const itemId = i.presented.get(r.id.trim().toLowerCase());
    if (!itemId) {
      notes.push(`ignored discussion reply to unknown id ${JSON.stringify(r.id.slice(0, 64))}: only items presented with awaiting_reply can be replied to`);
      continue;
    }
    const a = awaiting.get(itemId);
    if (!a) {
      notes.push(`ignored discussion reply to ${r.id.slice(0, 64)}: no reply was sought for it`);
      continue;
    }
    if (done.has(itemId)) {
      notes.push(`ignored duplicate discussion reply to ${a.alias}`);
      continue;
    }
    done.add(itemId);
    const assessment = i.assessments.get(itemId) ?? null;
    const consistency = stanceConflict(r.stance, assessment);
    if (consistency) notes.push(`${a.alias}: ${consistency}`);
    records.push({
      reply_id: i.newId(),
      item_id: itemId,
      review_id: i.reviewId,
      round: i.round,
      stance: r.stance,
      reply: i.clampReply(r.reply),
      new_information: r.new_information,
      answers: { response_id: a.response_id },
      assessment,
      source_id: i.sourceId,
      notes: consistency ? [consistency] : [],
      recorded_by: { role: "reviewer", channel: "codex" },
      recorded_at: i.recordedAt,
    });
  }
  const missing = i.awaiting.filter((a) => !done.has(a.item_id)).map((a) => a.item_id);
  if (missing.length) notes.push(`${missing.length} item(s) presented with awaiting_reply got no discussion reply; their turns stay awaiting a reply (within the exchange budget)`);
  return { records, notes, missing };
}

/** A stance that contradicts the same review's lifecycle assessment (recorded, never acted on). */
export function stanceConflict(stance: string, assessment: string | null): string | null {
  if (stance === "maintain" && assessment === "apparently_resolved") return "stance maintain conflicts with the assessment apparently_resolved (the lifecycle follows the assessment)";
  if (stance === "withdraw" && assessment === "still_present") return "stance withdraw conflicts with the assessment still_present (the lifecycle follows the assessment)";
  return null;
}

/** The stance vocabulary, as policy facts for the reviewer prompt. */
export const STANCE_MEANINGS: Record<Stance, string> = {
  maintain: "you stand by the finding as it applies to the code now",
  withdraw: "you no longer believe the finding applies (this does not change your assessment in prior_findings, which follows the code)",
  revise: "you materially change the finding or its argument (a replacement finding is reported as a new finding and the old one assessed superseded)",
  need_information: "you cannot decide without specific information; say exactly what in reply",
};
