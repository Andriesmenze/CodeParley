// Run history for the host (plan §11.7; M1.5): the event list, paged, and the engine's own
// result documents, paged by character range. Only engine-built views are available as
// "parts": raw check stdout/stderr, Codex event streams and stderr, the rendered prompt, the
// raw final message and the local capture record never are (M1.4-1, §16.2, MR-F). Every
// part is built first and then passed through the host view by the caller, so paging works
// on the text the host is allowed to see.

import { DomainError } from "../common/errors.js";
import { discussionState, latestResponses, normalizeFindingId, reportDiscussion, respondable, responsesOf, responseToken, reviewedSince, WITHHELD_RESPONSE_TEXT } from "../policy/responses.js";
import { seenBy, threadOfItem, threadReplies, threadTurns, turnReviewIdx, type DiscussionIndex } from "../policy/discussion.js";
import { threadReport, turnSummary } from "../policy/discussion-reports.js";
import { amendmentSeenBy, amendmentStatus } from "../policy/amendments.js";
import { decisionFactsOf, decisionsOnThread, decisionStatus, type DecisionFacts } from "../policy/user-decisions.js";
import type { Thread } from "../policy/threads.js";
import { caseKey } from "../workspace/paths.js";
import { resolveArtifact } from "../store/artifacts.js";
import { readTextIfExists } from "../store/atomic.js";
import type { ReviewerItem } from "../schemas/review.js";
import type { StateRecord } from "../schemas/run-state.js";
import { resultOf } from "./operations.js";
import { checksResultView, reviewResultView, prepareResultView } from "./views.js";
import type { Loaded, RunHandle } from "./engine-env.js";

export const HISTORY_PARTS = ["result", "review_output", "review_items"] as const;
export type HistoryPart = (typeof HISTORY_PARTS)[number];
export const MAX_EVENTS_PER_PAGE = 100;
export const MAX_ARTIFACT_CHARS = 30_000;

const ACTORS = new Set(["engine", "host", "codex", "check", "user_cli"]);

export interface EventView {
  seq: number;
  ts: string;
  type: string;
  actor: "engine" | "host" | "codex" | "check" | "user_cli";
  summary: string;
  refs: Record<string, string>;
}

export function eventsPage(st: StateRecord, afterSeq: number | undefined, limit: number | undefined): { events: EventView[]; next_after_seq: number | null; total: number } {
  const n = Math.max(1, Math.min(limit ?? 50, MAX_EVENTS_PER_PAGE));
  const after = afterSeq ?? 0;
  const rest = st.events.filter((e) => e.seq > after);
  const page = rest.slice(0, n);
  return {
    events: page.map((e) => ({ seq: e.seq, ts: e.ts, type: e.type, actor: (ACTORS.has(e.actor) ? e.actor : "engine") as EventView["actor"], summary: e.summary, refs: e.refs ?? {} })),
    next_after_seq: rest.length > n ? page.at(-1)!.seq : null,
    total: st.events.length,
  };
}

/** The full document of one part of one operation (before the host view and paging). */
export async function artifactDocument(le: Loaded, run: RunHandle, st: StateRecord, operationId: string, part: string): Promise<unknown> {
  if (!(HISTORY_PARTS as readonly string[]).includes(part)) throw new DomainError("INVALID_ARGUMENT", `part must be one of: ${HISTORY_PARTS.join(", ")}`);
  const op = st.operations.find((o) => o.operation_id === operationId);
  if (!op) throw new DomainError("OPERATION_MISMATCH", `operation ${operationId} is not an operation of this run`);
  if (part === "result") {
    const r = await resultOf(le, run, op);
    return r.kind === "checks" ? checksResultView(r.result) : r.kind === "review" ? reviewResultView(r.result) : prepareResultView(r.result);
  }
  if (op.kind !== "review") throw new DomainError("INVALID_ARGUMENT", `part ${part} exists only for review operations`);
  const reviewId = ((op.outcome as { review_id?: string; deduplicated_of?: string } | undefined)?.deduplicated_of ?? (op.outcome as { review_id?: string } | undefined)?.review_id ?? op["review_id"]) as string | undefined;
  const review = reviewId ? st.reviews.find((r) => r.review_id === reviewId) : undefined;
  const ref = review?.artifacts[part === "review_output" ? "output" : "items"];
  if (!ref) throw new DomainError("INVALID_ARGUMENT", `this review has no ${part} (it produced no valid output)`);
  const raw = await readTextIfExists(resolveArtifact(run.paths.runDir, ref));
  if (raw === null) throw new DomainError("INTERNAL", `the ${part} artifact of this review is missing`);
  return JSON.parse(raw) as unknown;
}

/**
 * The discussion history (Phase 2.1 responses; Phase 2.2 threads and reviewer replies): every
 * reviewer item that can be responded to (open or informational) or has a response or a reviewer
 * reply, with its current `response_token` (null when it can no longer be responded to) and the
 * reviewer's view of it over the rounds (assessments and supersession, which never rewrite a
 * turn), every response in order —
 * full rationale, references, the round and source it answered, who recorded it, which later
 * response superseded it, and whether and when the reviewer saw it — and every reviewer reply in
 * full; and each such thread's timeline (turns, deliveries, replies) with its budget and
 * escalation. With `findingId` (any item id, so also a thread id), that item's whole thread.
 * Built from the run state; paged by the caller. Whether a turn would be presented next is judged
 * without a source read here (status reads the source).
 *
 * Phase 2.3 (P2.3-12): every user decision on the chosen threads (all of them without
 * `findingId`) with its status now, provenance and the state it was decided against, a
 * `user_decision` event in each thread's timeline, and every task amendment of the run (task-wide,
 * so always all) with its status and whether an accepted review presented it. Records in the user
 * lists without a recognized provenance (P2.3-2) are counted, never shown as user authority.
 */
export function responsesDocument(st: StateRecord, findingId?: string): unknown {
  const { view } = reportDiscussion(st, null, null, caseKey);
  const ix = view.ix;
  const { chosen, threads } = historyScope(st, ix, findingId);
  const latest = latestResponses(st.implementer_responses);
  const facts = decisionFactsOf(ix);
  // The chosen threads' user decisions, in recording order (an audit trail).
  const onChosen = new Set(threads.flatMap((t) => decisionsOnThread(facts, t)).map((d) => d.decision_id));
  const decisions = facts.all.filter((d) => onChosen.has(d.decision_id));
  return {
    run_id: st.run_id,
    note: "Implementer responses are the implementer's claims (recorded through MCP), never user decisions; reviewer replies are the reviewer's stance (recorded from accepted reviews). Neither resolves an item: only accepted reviews' assessments change its lifecycle. A response counts as seen by the reviewer only when an accepted review presented it. User decisions and task amendments are operator-authoritative records, written only by CodeParley's local operator interface (code-parley decide / amend at an interactive terminal; assurance local_operator: CodeParley trusts the local OS user, its installation and its store, and does not verify human presence); a decision settles only its own thread and changes no reviewer item.",
    responses_recorded: st.implementer_responses.length,
    reviewer_replies_recorded: st.reviewer_replies.length,
    items: chosen.map((it) => {
      const mine = responsesOf(st.implementer_responses, it.id);
      return {
        finding_id: it.id,
        thread_id: threadOfItem(ix, it).id,
        response_token: respondable(it) ? responseToken(it, ix) : null,
        item_kind: it.item_kind,
        title: it.title,
        round: it.round,
        triage: it.triage,
        reviewer_status: it.status,
        discussion_state: discussionState(it, latest.get(it.id)),
        supersedes: it.supersedes,
        superseded_by: it.superseded_by,
        restates: (it as { restates?: string[] }).restates ?? [],
        reviewer_assessments: it.assessments.map((a) => ({ round: a.round, assessment: a.assessment, effect: a.effect })),
        reviewer_replies: (ix.repliesByItem.get(it.id) ?? []).map((x) => ({
          reply_id: x.reply_id,
          round: x.round,
          review_id: x.review_id,
          stance: x.stance,
          new_information: x.new_information,
          reply: x.reply,
          answers_response_id: x.answers.response_id,
          assessment: x.assessment,
          notes: x.notes,
          recorded_by: x.recorded_by,
        })),
        responses: mine.map((r, k) => ({ r, k, t: turnSummary(ix, view.plan, r) })).map(({ r, k, t }) => ({
          response_id: r.response_id,
          disposition: r.disposition,
          // Recorded without a read of the working tree: never checked for confidential names.
          rationale: r.text_withheld ? WITHHELD_RESPONSE_TEXT : r.rationale,
          references: r.text_withheld ? [] : r.references,
          text_withheld: r.text_withheld,
          answers_round: r.answers.round,
          recorded_at: r.recorded_at,
          recorded_by: r.recorded_by,
          source_id: r.source.source_id,
          source_note: r.source.note,
          supersedes: r.supersedes,
          superseded_by: mine[k + 1]?.response_id ?? null,
          reviewed_since: reviewedSince(it, r),
          seen_by_reviewer: seenBy(ix, r.response_id),
          delivery: t.delivery,
          delivery_reason: t.delivery_reason,
        })),
      };
    }),
    user_decisions: decisions.map((d) => userDecisionEntry(ix, facts, d)),
    task_amendments: ix.amendments.all.map((a) => amendmentEntry(ix, a)),
    ...(facts.unrecognized || ix.amendments.unrecognized ? { user_records_with_unrecognized_provenance: { decisions: facts.unrecognized, amendments: ix.amendments.unrecognized, note: "records in the user lists without a provenance CodeParley recognizes: never user authority, so not shown as such" } } : {}),
    threads: threads.map((t) => threadEntry(ix, view.plan, t, facts)),
  };
}

/** The items and threads the document lists: one thread with `findingId`, else every one with something to show. */
function historyScope(st: StateRecord, ix: DiscussionIndex, findingId: string | undefined): { chosen: ReviewerItem[]; threads: Thread[] } {
  if (findingId !== undefined) {
    const it = st.findings.find((f) => f.id === normalizeFindingId(findingId));
    if (!it) throw new DomainError("FINDING_NOT_FOUND", `${findingId.slice(0, 64)} is not a reviewer item of this run`);
    const t = threadOfItem(ix, it);
    return { chosen: t.members, threads: [t] };
  }
  // Every thread status can list, also those it left out for size (PR #11 review), and every
  // item with a turn: status names this document for whatever it did not show.
  // Phase 2.3: every item a user decision covers too, so that the full decision history is listed
  // (a decision on a thread a reviewer later resolved included).
  const active = new Set([...st.implementer_responses.map((r) => r.item_id), ...st.reviewer_replies.map((r) => r.item_id), ...st.user_decisions.flatMap((d) => d.covered_items)]);
  const chosen = st.findings.filter((f) => respondable(f) || active.has(f.id));
  const threads = new Map<string, Thread>();
  for (const it of chosen) {
    const t = threadOfItem(ix, it);
    threads.set(t.id, t);
  }
  return { chosen, threads: [...threads.values()] };
}

/** One task amendment as the history shows it: the record, its status now and its deliveries. */
function amendmentEntry(ix: DiscussionIndex, a: DiscussionIndex["amendments"]["all"][number]): Record<string, unknown> {
  return {
    amendment_id: a.amendment_id,
    id: `A-${a.seq}`,
    kind: a.kind,
    status: amendmentStatus(ix.amendments, a),
    text: a.text,
    relates_to: a.relates_to,
    replaces: a.replaces,
    replaced_by: ix.amendments.replacedBy.get(a.amendment_id) ?? null,
    seen_by_reviewer: amendmentSeenBy(ix.amendments, a.amendment_id),
    presented_in: (ix.amendments.seen.get(a.amendment_id) ?? []).map((x) => ({ review_id: x.review_id, round: x.round })),
    recorded_by: a.recorded_by,
    recorded_at: a.recorded_at,
  };
}

/** One thread as the history shows it: its budget, escalation, user layer and timeline. */
function threadEntry(ix: DiscussionIndex, plan: Parameters<typeof threadReport>[1], t: Thread, facts: DecisionFacts): Record<string, unknown> {
  const rep = threadReport(ix, plan, t, (x) => (respondable(x) ? responseToken(x, ix) : null), undefined, facts);
  return {
    thread_id: t.id,
    merged_thread_ids: t.merged,
    item_ids: t.members.map((m) => m.id),
    exchanges: rep.exchanges,
    last_speaker: rep.last_speaker,
    new_information_required: rep.new_information_required,
    escalation: rep.escalation,
    awaiting: rep.awaiting,
    lineage_anomalies: t.anomalies,
    user_decision: rep.user_decision,
    blocks_completion: rep.blocks_completion,
    completion_category: rep.completion_category,
    user_information_pending: rep.user_information_pending,
    timeline: timelineOf(ix, t, facts),
  };
}

/** One user decision as the history shows it: the record, its status now, and its provenance. */
function userDecisionEntry(ix: DiscussionIndex, facts: DecisionFacts, d: DecisionFacts["all"][number]): Record<string, unknown> {
  const s = decisionStatus(ix, facts, d);
  return {
    decision_id: d.decision_id,
    kind: d.kind,
    status: s.status,
    lapse_reasons: s.reasons,
    thread_id_now: s.thread_id,
    thread_id_at_recording: d.thread_id,
    current_item_id: d.current_item_id,
    covered_items: d.covered_items,
    note: d.note,
    decided_against: d.decided_against,
    context: d.context,
    supersedes: d.supersedes,
    replaced_by: facts.replacedBy.get(d.decision_id) ?? null,
    recorded_by: d.recorded_by,
    recorded_at: d.recorded_at,
  };
}

/**
 * A thread's turns, deliveries, replies and user decisions in order (review sequence, never clocks).
 * Within one review window, implementer turns come before user decisions (both are recorded
 * between reviews; their relative order there is not derived).
 */
function timelineOf(ix: DiscussionIndex, t: Thread, facts: DecisionFacts): Record<string, unknown>[] {
  const events: { key: [number, number, number]; e: Record<string, unknown> }[] = [];
  threadTurns(ix, t).forEach((r, k) => {
    events.push({ key: [turnReviewIdx(ix, r), 2, k], e: { event: "implementer_turn", response_id: r.response_id, item_id: r.item_id, position: r.disposition, recorded_at: r.recorded_at, text_withheld: r.text_withheld } });
    for (const s of ix.seen.get(r.response_id) ?? []) events.push({ key: [s.reviewIdx, 0, k], e: { event: "presented_to_reviewer", response_id: r.response_id, item_id: r.item_id, review_id: s.review_id, round: s.round, reply_sought: s.reply_sought, basis: s.basis } });
  });
  threadReplies(ix, t).forEach((x, k) => {
    events.push({ key: [ix.reviewIdx.get(x.review_id) ?? -1, 1, k], e: { event: "reviewer_reply", reply_id: x.reply_id, item_id: x.item_id, review_id: x.review_id, round: x.round, stance: x.stance, new_information: x.new_information, answers_response_id: x.answers.response_id } });
  });
  decisionsOnThread(facts, t).forEach((d, k) => {
    const idx = d.decided_against.run_review_id ? (ix.reviewIdx.get(d.decided_against.run_review_id) ?? -1) : -1;
    events.push({ key: [idx, 3, k], e: { event: "user_decision", decision_id: d.decision_id, kind: d.kind, after_round: d.decided_against.run_round, covered_items: d.covered_items.length, recorded_at: d.recorded_at } });
  });
  events.sort((a, b) => a.key[0] - b.key[0] || a.key[1] - b.key[1] || a.key[2] - b.key[2]);
  return events.map((x) => x.e);
}

/** One character range of a (host-view) document's JSON text. */
export function pageText(text: string, offset: number | undefined, length: number | undefined): { offset: number; length: number; total_length: number; content: string } {
  const off = Math.max(0, Math.min(offset ?? 0, text.length));
  const len = Math.max(0, Math.min(length ?? MAX_ARTIFACT_CHARS, MAX_ARTIFACT_CHARS));
  const content = text.slice(off, off + len);
  return { offset: off, length: content.length, total_length: text.length, content };
}
