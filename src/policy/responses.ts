// Implementer responses to reviewer items (Phase 2.1, plan §1.14). PURE: no I/O, no clock.
//
// Four layers stay apart: the reviewer's text (immutable), the engine's item state (triage,
// status, assessments and supersession; changed only by accepted reviews), the implementer's
// responses (append-only records keyed by item id) and engine conditions and incidents (no
// item id at all, so nothing here can address them). This module decides
//  - which items can be responded to (open or informational reviewer items — never a
//    superseded or reviewer-resolved one, never anything engine-owned);
//  - the per-item RESPONSE TOKEN: a digest of the item's engine state and its latest response.
//    A response must present the token it saw; any change since (a review assessed or
//    superseded the item, another response was recorded) makes it stale. Optimistic
//    concurrency, never last-write-wins;
//  - the DISCUSSION STATE an item is in, from the reviewer's status and the implementer's
//    latest response. A response never changes the item's triage or lifecycle and never
//    resolves anything: "fix_claimed" waits for a later review, only a reviewer reports an item
//    resolved (not engine-verified), and "deferred" is the implementer's request, never an
//    authoritative deferral (that is the user's, through a later channel);
//  - whether a response still describes the current situation (stale reasons).
// Phase 2.2 (plan §1.15): the token also covers the item's discussion thread and every reviewer
// reply in it (P2.2-11), and response views say whether the reviewer has seen the response and
// whether the next review will present it (P2.2-6, policy/discussion.ts).

import { sha256OfCanonicalJson } from "../common/hash.js";
import type { ReviewerItem } from "../schemas/review.js";
import { DISPOSITIONS, RATIONALE_REQUIRED, RESPONSE_LIMITS, type DispositionKind, type ImplementerResponse, type ResponseReference } from "../schemas/responses.js";
import { discussionIndexOf, planDiscussion, seenBy, threadOfItem, threadReplies, type DeliveryBasis, type DiscussionIndex, type DiscussionPlan, type DiscussionStateFields, type NotDeliveredReason } from "./discussion.js";
import { turnSummary } from "./discussion-reports.js";
import { hasUnsafeChars } from "./text-safety.js";

export const RESPONSE_POLICY_VERSION = "responses.v1";

/** Discussion states of a reviewer item (reported; never stored). */
export const DISCUSSION_STATES = [
  "open", // tracked, no implementer response yet
  "accepted_unresolved", // the implementer agrees; not reported resolved by a reviewer
  "disputed", // the implementer disagrees: an unresolved disagreement
  // The implementer asks to leave it for later work. Its position, not an authoritative deferral:
  // the item stays open and outstanding (a user decision is a later, separate channel, P2.3).
  "deferral_requested",
  "fix_claimed_awaiting_verification", // the implementer claims a fix; no later review has assessed it
  "fix_not_confirmed", // a later review still found it present after the fix claim
  "reviewer_resolved", // a later reviewer reported it resolved (not engine-verified)
  "superseded", // replaced by a newer reviewer item
  "informational", // reported, not tracked as open (minor concern, note, non-blocking question)
] as const;
export type DiscussionState = (typeof DISCUSSION_STATES)[number];

const KNOWN_DISPOSITIONS: ReadonlySet<string> = new Set(DISPOSITIONS);
const RESPONDABLE_STATUS: ReadonlySet<string> = new Set(["open", "informational"]);

/** One response as a caller submits it (shape already validated by the tool schema). */
export interface ResponseInput {
  finding_id: string;
  response_token: string;
  disposition: DispositionKind;
  rationale: string;
  references?: readonly { path: string; start_line?: number | undefined; end_line?: number | undefined }[] | undefined;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** The responses to one item, oldest first (records are append-only). */
export function responsesOf(records: readonly ImplementerResponse[], itemId: string): ImplementerResponse[] {
  return records.filter((r) => r.item_id === itemId);
}

/** The latest response of every item that has one. */
export function latestResponses(records: readonly ImplementerResponse[]): Map<string, ImplementerResponse> {
  const out = new Map<string, ImplementerResponse>();
  for (const r of records) out.set(r.item_id, r);
  return out;
}

/** May a response be recorded for this item? Open or informational reviewer items only. */
export function respondable(it: ReviewerItem): boolean {
  return RESPONDABLE_STATUS.has(it.status);
}

/**
 * The item's response token: a digest of everything the engine may change about the item
 * (status, supersession, every reviewer assessment), of its latest response and — Phase 2.2
 * (P2.2-11) — of whether a review was shown that response, and of its discussion thread: the
 * thread's id and members and every reviewer reply in it. A reviewer reply, a new lineage link or a merge therefore makes a token stale, so nobody
 * responds against a reviewer state they have not seen. Reviewer text never changes, and the
 * working tree's source is deliberately not part of it (a response records its source instead).
 */
export function responseToken(it: ReviewerItem, ix: DiscussionIndex): string {
  const t = threadOfItem(ix, it);
  const latest = ix.responsesByItem.get(it.id)?.at(-1)?.response_id ?? null;
  return sha256OfCanonicalJson({
    schema: "arl.response-token.v2",
    item: it.id,
    status: it.status,
    superseded_by: it.superseded_by,
    assessments: it.assessments.map((a) => [a.review_id, a.assessment, a.effect]),
    latest_response: latest,
    // Which accepted reviews were shown that response (its delivery is discussion state too).
    latest_seen_by: latest ? (ix.seen.get(latest) ?? []).map((s) => s.review_id) : [],
    thread: t.id,
    members: t.members.map((m) => m.id),
    replies: threadReplies(ix, t).map((r) => r.reply_id),
  }).slice(0, 32);
}

/** The run's current accepted review (the latest accepted one), or null. */
export function currentReviewOf(ix: DiscussionIndex): { review_id: string; round: number } | null {
  const r = ix.latestAccepted >= 0 ? ix.src.reviews[ix.latestAccepted] : undefined;
  return r ? { review_id: r.review_id, round: r.round } : null;
}

/** The reviews that raised or assessed the item, in order (assessments are append-only). */
export function reviewSequence(it: ReviewerItem): string[] {
  return [it.review_id, ...it.assessments.map((a) => a.review_id)];
}

/** The review a new response answers: the latest that raised or assessed the item, and its round. */
export function answeredReview(it: ReviewerItem): { review_id: string; round: number } {
  const last = it.assessments.at(-1);
  return last ? { review_id: last.review_id, round: last.round } : { review_id: it.review_id, round: it.round };
}

/** Assessments made after the review a response answered (none when it answers the latest). */
function assessmentsAfter(it: ReviewerItem, r: ImplementerResponse): ReviewerItem["assessments"] {
  const seq = reviewSequence(it);
  const pos = seq.lastIndexOf(r.answers.review_id);
  // Unknown position (should not happen): every assessment counts as later (conservative).
  return pos < 0 ? it.assessments : it.assessments.slice(pos);
}

/** A later accepted review assessed the item after the response (an omission does not count). */
export function reviewedSince(it: ReviewerItem, r: ImplementerResponse): boolean {
  return assessmentsAfter(it, r).some((a) => a.assessment !== "not_assessed");
}

/** A later review still found the item present after the response. */
export function reassertedSince(it: ReviewerItem, r: ImplementerResponse): boolean {
  return assessmentsAfter(it, r).some((a) => a.assessment === "still_present");
}

/** The source on which the reviewer last saw the item present, as of the review `reviewId`. */
export function lastPresentSourceAt(it: ReviewerItem, reviewId: string): string {
  let s = it.source_id;
  if (reviewId === it.review_id) return s;
  for (const a of it.assessments) {
    if (a.assessment === "still_present") s = a.source_id;
    if (a.review_id === reviewId) break;
  }
  return s;
}

/** The item's discussion state from its reviewer status and the implementer's latest response. */
export function discussionState(it: ReviewerItem, latest: ImplementerResponse | null | undefined): DiscussionState {
  if (it.status === "superseded") return "superseded";
  if (it.status === "reported_resolved") return "reviewer_resolved";
  if (it.status !== "open") return "informational";
  if (!latest || !KNOWN_DISPOSITIONS.has(latest.disposition)) return "open";
  switch (latest.disposition as DispositionKind) {
    case "accepted":
      return "accepted_unresolved";
    case "disputed":
      return "disputed";
    case "deferred":
      return "deferral_requested";
    case "fix_claimed":
      return reassertedSince(it, latest) ? "fix_not_confirmed" : "fix_claimed_awaiting_verification";
  }
}

// ---------------------------------------------------------------------------
// Validating a call
// ---------------------------------------------------------------------------

/**
 * A repository-relative reference path in normal form (`/` separators, no leading `./`), or
 * null when it is absolute, escapes the repository or is malformed.
 */
export function normalizeReferencePath(p: string): string | null {
  let s = p.trim().replace(/\\/g, "/");
  while (s.startsWith("./")) s = s.slice(2);
  if (s === "" || s.length > RESPONSE_LIMITS.referencePathChars || hasUnsafeChars(s)) return null;
  if (s.startsWith("/") || /^[A-Za-z]:/.test(s) || s.includes(":")) return null;
  const segments = s.split("/");
  if (segments.some((g) => g === "" || g === "." || g === "..")) return null;
  return s;
}

/** Problems with the call itself, independent of the run's state (each an INVALID_ARGUMENT). */
export function inputProblems(responses: readonly ResponseInput[]): string[] {
  const problems: string[] = [];
  if (responses.length === 0) problems.push("responses: at least one response is required");
  // Every size is checked before any content is scanned.
  if (responses.length > RESPONSE_LIMITS.perCall) return [`responses: at most ${RESPONSE_LIMITS.perCall} per call`];
  const seen = new Set<string>();
  responses.forEach((r, i) => {
    const at = `responses.${i}`;
    const id = normalizeFindingId(r.finding_id);
    if (seen.has(id)) problems.push(`${at}.finding_id: the same finding appears more than once in this call`);
    seen.add(id);
    if (!KNOWN_DISPOSITIONS.has(r.disposition)) problems.push(`${at}.disposition: must be one of ${DISPOSITIONS.join(", ")}`);
    if (r.rationale.length > RESPONSE_LIMITS.rationaleChars) problems.push(`${at}.rationale: at most ${RESPONSE_LIMITS.rationaleChars} characters`);
    else if (hasUnsafeChars(r.rationale)) problems.push(`${at}.rationale: control or bidirectional-override characters are not allowed`);
    if (RATIONALE_REQUIRED.has(r.disposition) && r.rationale.trim() === "") problems.push(`${at}.rationale: required for ${r.disposition}`);
    const refs = r.references ?? [];
    if (refs.length > RESPONSE_LIMITS.referencesPerResponse) {
      problems.push(`${at}.references: at most ${RESPONSE_LIMITS.referencesPerResponse}`);
      return;
    }
    refs.forEach((ref, k) => {
      if (normalizeReferencePath(ref.path) === null) problems.push(`${at}.references.${k}.path: must be a repository-relative path (no absolute path, drive, "..", empty segment or control character)`);
      const s = ref.start_line;
      const e = ref.end_line;
      if (s !== undefined && (!Number.isInteger(s) || s < 1)) problems.push(`${at}.references.${k}.start_line: a line number from 1`);
      if (e !== undefined && (s === undefined || !Number.isInteger(e) || e < s)) problems.push(`${at}.references.${k}.end_line: needs start_line and must not precede it`);
    });
  });
  return problems;
}

/** Finding ids are engine UUIDs: compare in their canonical (lower-case) form. */
export function normalizeFindingId(id: string): string {
  return id.trim().toLowerCase();
}

/** The references of a response as stored (normal form; claims, not validated evidence). */
export function storedReferences(r: ResponseInput): ResponseReference[] {
  return (r.references ?? []).map((ref) => ({ path: normalizeReferencePath(ref.path) ?? ref.path, start_line: ref.start_line ?? null, end_line: ref.end_line ?? null }));
}

export type RejectionCode = "FINDING_NOT_FOUND" | "FINDING_NOT_RESPONDABLE" | "STALE_FINDING_STATE";

export interface Rejection {
  index: number;
  finding_id: string;
  code: RejectionCode;
  detail: string;
}

export interface CheckInput {
  /** The run's items, responses, replies and reviews (policy/discussion.ts). */
  ix: DiscussionIndex;
  /** Ids of engine-owned audit records (isolation incidents), named in the refusal. */
  incidentIds: ReadonlySet<string>;
  responses: readonly ResponseInput[];
}

/**
 * Check every response against the run's CURRENT state: the item must be a reviewer item of
 * this run, still open for responses, and in exactly the state the caller saw (its token).
 * Returns every rejection (the call records nothing if there is one).
 */
export function checkResponses(c: CheckInput): Rejection[] {
  const byId = c.ix.itemById;
  const out: Rejection[] = [];
  c.responses.forEach((r, index) => {
    const id = normalizeFindingId(r.finding_id);
    const it = byId.get(id);
    const reject = (code: RejectionCode, detail: string) => out.push({ index, finding_id: r.finding_id.slice(0, 64), code, detail });
    if (!it) {
      reject(
        "FINDING_NOT_FOUND",
        c.incidentIds.has(id)
          ? "this is an isolation incident: incidents are engine-owned audit records and cannot be responded to"
          : "not a reviewer item of this run (use an id from get_review_status or a review result; engine conditions, isolation incidents and items of a review that was not accepted cannot be responded to)",
      );
      return;
    }
    if (!respondable(it)) {
      reject(
        "FINDING_NOT_RESPONDABLE",
        it.status === "superseded"
          ? `superseded by reviewer item ${it.superseded_by ?? "(unknown)"}; respond to that item instead (responses are never moved between items)`
          : it.status === "reported_resolved"
            ? "a reviewer reported this item resolved; it is no longer outstanding"
            : `this item's status is ${it.status}`,
      );
      return;
    }
    if (r.response_token.trim() !== responseToken(it, c.ix)) {
      reject("STALE_FINDING_STATE", `this item changed since its response_token was read (${staleWhy(it, c.ix.responsesByItem.get(it.id)?.at(-1), c.ix.repliesByItem.get(it.id)?.at(-1))}); read it again with get_review_status or the review result and decide anew`);
    }
  });
  return out;
}

function staleWhy(it: ReviewerItem, latest: ImplementerResponse | undefined, reply: { stance: string; round: number } | undefined): string {
  const last = it.assessments.at(-1);
  const parts = [`status ${it.status}`];
  if (last) parts.push(`last assessed in round ${last.round} (${last.assessment})`);
  if (latest) parts.push(`latest response ${latest.disposition} recorded ${latest.recorded_at}`);
  if (reply) parts.push(`latest reviewer reply ${reply.stance} in round ${reply.round}`);
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/** How much of a rationale a report shows (the full text pages through get_review_history). */
export const RATIONALE_EXCERPT_CHARS = 200;

/**
 * What every view shows for the text of a response recorded without a read of the working tree
 * (`text_withheld`): its rationale and references were never checked for confidential names.
 */
export const WITHHELD_RESPONSE_TEXT = "[withheld: recorded while the working tree could not be read completely to check it for confidential names]";

export interface ResponseView {
  response_id: string;
  disposition: string;
  recorded_at: string;
  /** The round of the reviewer view the response answered. */
  answers_round: number;
  /**
   * The rationale, whole here: every view cuts it to RATIONALE_EXCERPT_CHARS after redaction
   * (engine/host-view.ts cutExcerpts), since a cut made first could split a withheld name.
   */
  rationale_excerpt: string;
  responses_on_item: number;
  /** Empty when the response still describes the current situation as far as this report knows. */
  stale_reasons: string[];
  /** Whether this report knew the current source (else source staleness is not judged). */
  source_checked: boolean;
  notes: string[];
  /** Phase 2.2: the first accepted review whose bundle presented it (null: the reviewer has not seen it). */
  seen_by_reviewer: { review_id: string; round: number } | null;
  /** delivered (seen), pending (the next review presents it), not_delivered (delivery_reason). */
  delivery: "delivered" | "pending" | "not_delivered";
  delivery_reason: NotDeliveredReason | null;
  delivery_basis: DeliveryBasis[];
}

/** What a report knows about the discussion: the index, and the preview of the next review. */
export interface DiscussionView {
  ix: DiscussionIndex;
  plan: DiscussionPlan;
}

/** What a report knows for the discussion fields: the run's discussion and the fresh source (null: unknown). */
export interface ReportDiscussion {
  view: DiscussionView;
  currentSourceId: string | null;
}

/**
 * The discussion of a run state as a report sees it: the index, and the preview of the next
 * review judged against `currentSourceId` (null: unknown) and `checkResults` (the check results
 * digest for that source; null: not compared), cited paths compared by `pathKey` (the engine
 * passes the platform's `caseKey`; default exact).
 */
export function reportDiscussion(
  st: DiscussionStateFields,
  currentSourceId: string | null,
  checkResults: string | null = null,
  pathKey?: (path: string) => string,
): ReportDiscussion {
  const ix = discussionIndexOf(st);
  return { view: { ix, plan: planDiscussion(ix, { sourceId: currentSourceId, checkResults, ...(pathKey ? { pathKey } : {}) }) }, currentSourceId };
}

/**
 * The latest response to an item, as reported now. `currentSourceId` is the working tree's
 * identity computed fresh by this report (null: unknown, so source staleness is not judged).
 */
export function responseView(it: ReviewerItem, d: DiscussionView, currentSourceId: string | null): ResponseView | null {
  const mine = d.ix.responsesByItem.get(it.id) ?? [];
  const r = mine.at(-1);
  if (!r) return null;
  const stale: string[] = [];
  if (reviewedSince(it, r)) stale.push("reviewed_since_response");
  if (currentSourceId !== null && r.source.source_id !== null && r.source.source_id !== currentSourceId) stale.push("source_changed_since_response");
  const notes: string[] = [];
  if (r.disposition === "fix_claimed" && r.source.source_id !== null && r.source.source_id === lastPresentSourceAt(it, r.answers.review_id)) {
    notes.push("fix claimed on the same source the reviewer last saw the item on: a review of that source cannot confirm it");
  }
  if (r.disposition === "fix_claimed" && reassertedSince(it, r)) notes.push("a later review still found the item present after this fix claim");
  if (r.recorded_by.role !== "implementer") notes.push(`recorded by ${r.recorded_by.role} via ${r.recorded_by.channel}`);
  if (r.text_withheld) notes.push("its text is withheld (recorded while the working tree could not be read completely); record the response again to make it visible");
  const t = turnSummary(d.ix, d.plan, r);
  return {
    response_id: r.response_id,
    disposition: r.disposition,
    recorded_at: r.recorded_at,
    answers_round: r.answers.round,
    rationale_excerpt: r.text_withheld ? WITHHELD_RESPONSE_TEXT : r.rationale,
    responses_on_item: mine.length,
    stale_reasons: stale,
    source_checked: currentSourceId !== null,
    notes,
    seen_by_reviewer: seenBy(d.ix, r.response_id),
    delivery: t.delivery,
    delivery_reason: t.delivery_reason,
    delivery_basis: t.delivery_basis,
  };
}

/** The latest response on every item `it` supersedes, however many (lineage made visible; never inherited). */
export function predecessorResponses(it: ReviewerItem, items: readonly ReviewerItem[], records: readonly ImplementerResponse[]): { item_id: string; round: number; disposition: string; recorded_at: string }[] {
  const latest = latestResponses(records);
  const byId = new Map(items.map((x) => [x.id, x]));
  const out: { item_id: string; round: number; disposition: string; recorded_at: string }[] = [];
  for (const id of it.supersedes) {
    const r = latest.get(id);
    const prev = byId.get(id);
    if (r && prev) out.push({ item_id: id, round: prev.round, disposition: r.disposition, recorded_at: r.recorded_at });
  }
  return out;
}

/**
 * The implementer's latest response to `it` that was recorded before review `reviewId` assessed
 * the item — ordered by the item's own review sequence, never by clocks. Null when none.
 */
export function responseBeforeReview(it: ReviewerItem, reviewId: string, records: readonly ImplementerResponse[]): { response_id: string; disposition: string; recorded_at: string } | null {
  const seq = reviewSequence(it);
  const at = seq.lastIndexOf(reviewId);
  if (at < 0) return null;
  const before = responsesOf(records, it.id).filter((r) => {
    const p = seq.lastIndexOf(r.answers.review_id);
    return p >= 0 && p < at;
  });
  const r = before.at(-1);
  return r ? { response_id: r.response_id, disposition: r.disposition, recorded_at: r.recorded_at } : null;
}

/** What every report shows per reviewer item about the discussion (Phase 2.1; thread_id Phase 2.2). */
export interface ItemDiscussion {
  /** Present this with a response (null: the item can no longer be responded to). */
  response_token: string | null;
  /** The item's discussion thread (P2.2-1): its turns and budget are shared by the thread. */
  thread_id: string;
  discussion_state: DiscussionState;
  implementer_response: ResponseView | null;
  /** Responses to the earlier items this one supersedes: shown, never inherited. */
  responses_to_superseded_items: { item_id: string; round: number; disposition: string; recorded_at: string }[];
}

export function itemDiscussion(it: ReviewerItem, d: DiscussionView, currentSourceId: string | null): ItemDiscussion {
  const latest = d.ix.responsesByItem.get(it.id)?.at(-1) ?? null;
  return {
    response_token: respondable(it) ? responseToken(it, d.ix) : null,
    thread_id: threadOfItem(d.ix, it).id,
    discussion_state: discussionState(it, latest),
    implementer_response: responseView(it, d, currentSourceId),
    responses_to_superseded_items: it.supersedes.length ? predecessorResponses(it, d.ix.src.items, d.ix.src.responses) : [],
  };
}

export type DiscussionCounts = Record<DiscussionState, number> & { responses_recorded: number; stale_responses: number };

/** Counts over the run's items, for summaries. Stale here means reviewed since the response. */
export function discussionCounts(items: readonly ReviewerItem[], records: readonly ImplementerResponse[]): DiscussionCounts {
  const latest = latestResponses(records);
  const counts = Object.fromEntries(DISCUSSION_STATES.map((s) => [s, 0])) as DiscussionCounts;
  counts.responses_recorded = records.length;
  counts.stale_responses = 0;
  for (const it of items) {
    const l = latest.get(it.id);
    counts[discussionState(it, l)]++;
    if (l && it.status === "open" && reviewedSince(it, l)) counts.stale_responses++;
  }
  return counts;
}

/** A short text for a summary line: the discussion states of the open items. */
export function discussionText(counts: DiscussionCounts): string {
  const parts: string[] = [];
  const label: Partial<Record<DiscussionState, string>> = {
    open: "without a response",
    accepted_unresolved: "accepted (unresolved)",
    disputed: "disputed",
    deferral_requested: "deferral requested (not a user decision)",
    fix_claimed_awaiting_verification: "fix claimed (awaiting verification)",
    fix_not_confirmed: "fix not confirmed by a later review",
  };
  for (const [state, text] of Object.entries(label)) {
    const n = counts[state as DiscussionState];
    if (n > 0) parts.push(`${n} ${text}`);
  }
  return parts.join(", ");
}
