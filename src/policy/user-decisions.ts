// User decisions on discussion threads (Phase 2.3, plan §1.16 P2.3-3 to -7). PURE: no I/O, no clock.
//
// A user decision is the USER's record, written only by the local operator interface (P2.3-1). It
// attaches to a discussion thread through the items it COVERS: every open item of the thread when
// it was recorded. It never changes a reviewer item, a response or a reply. This module derives:
//  - whether a thread can be decided (an open item, an intact lineage);
//  - the DECISION TOKEN of a thread (P2.3-5): a digest of everything the user was shown — the
//    thread's members and their lifecycle, its turns, their deliveries, its replies, the user
//    decisions on it and the run's amendment revision. A decision presents the token of the state
//    the user saw; any change since refuses it;
//  - each decision's STATUS on every read (P2.3-6): replaced, revoked, moot, lapsed or applies. A
//    decision never silently covers substance the user did not see: an open item it did not cover
//    (a successor, a restatement, a merged thread), a reviewer revision after it, or a damaged
//    lineage lapses it;
//  - a thread's user state: the decision in effect, if any, and what it settles.

import { sha256OfCanonicalJson } from "../common/hash.js";
import { DECISION_KINDS, USER_LIMITS, type UserDecision } from "../schemas/user-authority.js";
import type { ReviewerItem } from "../schemas/review.js";
import { isUserChannelRecord } from "./amendments.js";
import { threadOfItem, threadReplies, threadTurns, type DiscussionIndex } from "./discussion.js";
import { hasUnsafeChars } from "./text-safety.js";
import { restatesOf, type Thread } from "./threads.js";

export const DECISION_POLICY_VERSION = "decisions.v1";

const KNOWN_KINDS: ReadonlySet<string> = new Set(DECISION_KINDS);

export type DecisionStatus = "applies" | "lapsed" | "moot" | "replaced" | "revoked";
export type LapseReason = "open_item_not_covered" | "reviewer_revised" | "lineage_anomaly";

export interface DecisionFacts {
  /** Records with a recognized provenance, in recording order. */
  all: UserDecision[];
  /** Records in the list without a recognized provenance (never user authority; reported). */
  unrecognized: number;
  byId: Map<string, UserDecision>;
  /** decision id → the later decision that replaced it. */
  replacedBy: Map<string, string>;
}

export function buildDecisionFacts(records: readonly UserDecision[]): DecisionFacts {
  const all = records.filter(isUserChannelRecord);
  const byId = new Map<string, UserDecision>();
  for (const d of all) if (!byId.has(d.decision_id)) byId.set(d.decision_id, d);
  const replacedBy = new Map<string, string>();
  for (const d of all) for (const s of d.supersedes) if (byId.has(s) && s !== d.decision_id && !replacedBy.has(s)) replacedBy.set(s, d.decision_id);
  return { all, unrecognized: records.length - all.length, byId, replacedBy };
}

/** The decision facts of a discussion index (built from the run state it was derived from). */
export function decisionFactsOf(ix: DiscussionIndex): DecisionFacts {
  return buildDecisionFacts(ix.src.decisions ?? []);
}

/** The open (tracked) items of a thread: what can block, and what a decision covers. */
export function openItemsOf(t: Thread): ReviewerItem[] {
  return t.members.filter((m) => m.status === "open");
}

/** Whether the user can decide a thread now, and if not, why. */
export type Decidability = { ok: true } | { ok: false; reason: string };

/** Can the user decide this thread now? An open item and an intact lineage (P2.3-4). */
export function decidability(t: Thread): Decidability {
  if (t.anomalies.length > 0) return { ok: false, reason: `the thread's lineage is damaged (${t.anomalies.join(", ")}), so CodeParley cannot tell which items a decision would cover` };
  if (openItemsOf(t).length === 0) return { ok: false, reason: "nothing in this thread is open: it blocks nothing (informational items never block; a reviewer resolved or superseded the rest)" };
  return { ok: true };
}

/** The decisions whose covered items lie in the thread, in recording order. */
export function decisionsOnThread(f: DecisionFacts, t: Thread): UserDecision[] {
  const ids = new Set(t.members.map((m) => m.id));
  return f.all.filter((d) => d.covered_items.some((id) => ids.has(id)));
}

/**
 * The thread's decision token (`arl.decision-token.v1`, first 32 hex): everything a decision on it
 * is decided against. A reviewer reply, an assessment, a lineage change, a new or delivered turn,
 * another user decision or a new amendment makes it stale.
 */
export function decisionToken(ix: DiscussionIndex, f: DecisionFacts, t: Thread, amendmentsSeq: number): string {
  const turns = threadTurns(ix, t);
  return sha256OfCanonicalJson({
    schema: "arl.decision-token.v1",
    thread: t.id,
    merged: t.merged,
    anomalies: t.anomalies,
    members: t.members.map((m) => [m.id, m.status, m.superseded_by, m.supersedes, restatesOf(m), m.assessments.map((a) => [a.review_id, a.assessment, a.effect])]),
    turns: turns.map((r) => r.response_id),
    seen: turns.map((r) => (ix.seen.get(r.response_id) ?? []).map((s) => s.review_id)),
    replies: threadReplies(ix, t).map((r) => r.reply_id),
    decisions: decisionsOnThread(f, t).map((d) => d.decision_id),
    amendments: amendmentsSeq,
  }).slice(0, 32);
}

export interface DecisionState {
  status: DecisionStatus;
  reasons: LapseReason[];
  /** The thread that holds the covered items now (null: they are missing or split). */
  thread_id: string | null;
}

/** The thread holding all of a decision's covered items now; null when one is missing or they are split (fail safe). */
function threadOfDecision(ix: DiscussionIndex, d: UserDecision): Thread | null {
  let t: Thread | null = null;
  for (const id of d.covered_items) {
    const it = ix.itemById.get(id);
    if (!it) return null;
    const tt = threadOfItem(ix, it);
    if (t && tt.id !== t.id) return null;
    t = tt;
  }
  return t;
}

/** A reviewer `revise` on a covered item in a review after the one the decision was made against. */
function revisedAfter(ix: DiscussionIndex, t: Thread, d: UserDecision, covered: ReadonlySet<string>): boolean {
  const base = d.decided_against.run_review_id ? (ix.reviewIdx.get(d.decided_against.run_review_id) ?? -1) : -1;
  return threadReplies(ix, t).some((r) => covered.has(r.item_id) && r.stance === "revise" && (ix.reviewIdx.get(r.review_id) ?? -1) > base);
}

/** A decision's status now (P2.3-6). */
export function decisionStatus(ix: DiscussionIndex, f: DecisionFacts, d: UserDecision): DecisionState {
  const t = threadOfDecision(ix, d);
  const tid = t?.id ?? null;
  if (f.replacedBy.has(d.decision_id)) return { status: "replaced", reasons: [], thread_id: tid };
  if (d.kind === "revoke") return { status: "revoked", reasons: [], thread_id: tid };
  if (!t || t.anomalies.length > 0 || d.covered_items.length === 0) return { status: "lapsed", reasons: ["lineage_anomaly"], thread_id: tid };
  const open = openItemsOf(t);
  if (open.length === 0) return { status: "moot", reasons: [], thread_id: tid };
  const covered = new Set(d.covered_items);
  const reasons: LapseReason[] = [];
  if (open.some((it) => !covered.has(it.id))) reasons.push("open_item_not_covered");
  if (revisedAfter(ix, t, d, covered)) reasons.push("reviewer_revised");
  return { status: reasons.length ? "lapsed" : "applies", reasons, thread_id: tid };
}

export interface ThreadUserState {
  /** The decision in effect, else the latest one not replaced (null: none on this thread). */
  decision: UserDecision | null;
  state: DecisionState | null;
  /** Other decisions recorded on the thread's items (the history pages them all). */
  earlier: number;
  /** Not replaced, on the thread's items: what a new decision supersedes. */
  live: string[];
  /** An applicable waive or defer: the thread no longer blocks completion. */
  settles: "waived" | "deferred" | null;
  /** An applicable require_resolution: blocking until a reviewer reports it resolved; the user no longer awaited. */
  requires_resolution: boolean;
  /** The decision no longer settles the thread: the user is awaited again. */
  lapsed: boolean;
}

export function threadUserState(ix: DiscussionIndex, f: DecisionFacts, t: Thread): ThreadUserState {
  const mine = decisionsOnThread(f, t);
  const live = mine.filter((d) => !f.replacedBy.has(d.decision_id));
  const states = live.map((d) => ({ d, s: decisionStatus(ix, f, d) }));
  const chosen = states.find((x) => x.s.status === "applies") ?? states.at(-1) ?? null;
  const applies = chosen?.s.status === "applies";
  const kind = chosen?.d.kind;
  return {
    decision: chosen?.d ?? null,
    state: chosen?.s ?? null,
    earlier: mine.length - (chosen ? 1 : 0),
    live: live.map((d) => d.decision_id),
    settles: applies && kind === "waive" ? "waived" : applies && kind === "defer" ? "deferred" : null,
    requires_resolution: applies && kind === "require_resolution",
    lapsed: chosen?.s.status === "lapsed",
  };
}

// ---------------------------------------------------------------------------
// A new decision
// ---------------------------------------------------------------------------

/** Problems with a decision's own arguments (each an INVALID_ARGUMENT). */
export function decisionProblems(kind: string, note: string): string[] {
  const problems: string[] = [];
  if (!KNOWN_KINDS.has(kind)) problems.push(`kind must be one of ${DECISION_KINDS.join(", ")}`);
  if (note.length > USER_LIMITS.noteChars) problems.push(`the note is at most ${USER_LIMITS.noteChars} characters`);
  else if (hasUnsafeChars(note)) problems.push("the note may not contain control or bidirectional-override characters");
  return problems;
}

/**
 * The digest a request_id is bound to (`arl.decide-request.v1`): the item the user named, the kind
 * and the note — not the token, so a replay after a lost result is recognized.
 */
export function decideRequestDigest(runId: string, itemId: string, kind: string, note: string): string {
  return sha256OfCanonicalJson({ schema: "arl.decide-request.v1", run: runId, item: itemId, kind, note });
}

/** What each kind does, in words the CLI shows before the user confirms (P2.3-4). */
export const DECISION_MEANINGS: Record<(typeof DECISION_KINDS)[number], string> = {
  require_resolution:
    "the reviewer's concern must be addressed: the implementer's dispute or deferral request is overruled, and the thread keeps blocking task completion until a reviewer reports its items resolved",
  waive:
    "proceed despite the reviewer's open item(s) — overruling the disagreement or accepting the known risk: the thread no longer blocks task completion while this decision applies; the reviewer's finding stays open and visible, and Codex keeps assessing it",
  defer:
    "move the item(s) out of this task as follow-up work: the thread no longer blocks task completion while this decision applies and is reported as deferred; the reviewer's finding stays open and visible",
  revoke: "your previous decision on this thread no longer stands: the thread follows the discussion's default rules again",
};
