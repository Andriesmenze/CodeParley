// Derived task completion (Phase 2.3, plan §1.16 P2.3-11). PURE: no I/O, no clock.
//
// Completion is DERIVED on every report from engine records. Nothing stores it and nothing can set
// it: there is no argument, flag or record kind meaning "pass", for the user, the implementer or the
// reviewer. The state is the first of these that holds; every blocker is listed:
//  1. incomplete            — the engine cannot judge: an operation runs, the run is interrupted or
//                             misconfigured, the current source is unknown, an isolation containment
//                             incident is on record, or a thread's lineage is damaged;
//  2. checks_not_satisfied  — the verification floor is not configured or not met for the current source;
//  3. review_not_current    — no accepted review, or the latest is not current (source, check
//                             evidence, export: §10.4), or the user's amendments changed since it;
//  4. needs_user_decision   — a thread with an open item needs the user (escalation, or a lapsed decision);
//  5. needs_reviewer        — a thread with an open item waits for the reviewer;
//  6. needs_implementer     — any other thread with an open item;
//  7. ready                 — none of the above.
// A user decision changes only 4 to 6, and only through a thread's own applicable decision: it never
// makes a check pass, never erases an incident and never stands for a review. `ready` starts
// nothing — no review, check, close, commit or merge.

import type { Limitation } from "../schemas/capture.js";
import { amendmentDelta, amendmentWithheldDetail, type AmendmentFacts } from "./amendments.js";
import type { ThreadReport } from "./discussion-reports.js";

export const COMPLETION_POLICY_VERSION = "completion.v1";

export const COMPLETION_STATES = ["incomplete", "checks_not_satisfied", "review_not_current", "needs_user_decision", "needs_reviewer", "needs_implementer", "ready"] as const;
export type CompletionState = (typeof COMPLETION_STATES)[number];
export type BlockerCategory = Exclude<CompletionState, "ready">;

export interface CompletionBlocker {
  category: BlockerCategory;
  code: string;
  detail: string;
  /** Thread blockers are grouped by code: the threads (at most MAX_THREADS_PER_BLOCKER listed) and how many there are. */
  thread_ids?: string[];
  threads?: number;
  /** A summary of this many further containment incidents (the list names the first few one by one). */
  incidents?: number;
}

/** Isolation incidents that show the reviewer's containment failed; no decision can clear them (P2.3-7). */
export const CONTAINMENT_INCIDENTS: ReadonlySet<string> = new Set(["isolation_violation_file_change", "isolation_violation_mcp_tool_call", "isolation_violation_web_search", "export_modified_during_review"]);

export interface CompletionInput {
  /** The run's state as observed (dead owners' operations shown as interrupted). */
  run_state: string;
  active_operation: { kind: string; operation_id: string } | null;
  /** The working tree's source identity computed fresh and stable by this report (null: unknown). */
  current_source_id: string | null;
  floor: { configured: boolean; satisfied_for_current_source: boolean; missing: readonly string[]; stale: readonly string[]; failed: readonly string[]; removed: readonly string[]; unapproved: readonly string[] };
  /**
   * The run's latest accepted review, its freshness now (null: not computed), the amendments it
   * presented and those it withheld (their text could not be cleared for the model).
   */
  latest_accepted_review: { review_id: string; round: number; freshness: { current: boolean; stale_reasons: readonly string[] } | null; presented_amendments: readonly string[]; withheld_amendments: readonly string[] } | null;
  amendments: AmendmentFacts;
  incidents: readonly { incident_id: string; kind: string; review_id: string | null }[];
  /** EVERY thread report of the run (not only those a status lists). */
  threads: readonly Pick<ThreadReport, "thread_id" | "blocks_completion" | "completion_category" | "lineage_anomalies" | "user_decision" | "escalation">[];
  /** Limitations the caller knows (coverage, isolation, environment binding): listed, never blocking. */
  limitations: readonly Limitation[];
}

export interface CompletionReport {
  state: CompletionState;
  ready: boolean;
  /** The blockers, those that come first in the state order first (at most MAX_BLOCKERS; thread blockers grouped by code). */
  blockers: CompletionBlocker[];
  /** How many blockers there are: one per entry (a group of threads is one blocker), each containment incident counted, also those a summary entry stands for. */
  blockers_total: number;
  /** Per category: blocking conditions, each blocking thread counted. */
  counts: Record<BlockerCategory, number>;
  /** Threads an applicable user decision settles (at most MAX_THREADS_PER_BLOCKER listed each): their reviewer findings stay open. */
  settled_by_user: { waived: string[]; deferred: string[]; waived_total: number; deferred_total: number };
  limitations: Limitation[];
  note: string;
}

export const MAX_BLOCKERS = 40;
/** Thread ids a grouped blocker or a settled list names (the history and status threads have them all). */
export const MAX_THREADS_PER_BLOCKER = 10;

export const COMPLETION_NOTE =
  "Derived by the engine from its records on every report; nothing can set it. A user decision settles only its own thread's reviewer disagreement: it never makes a check pass, erases an isolation incident or stands for a review. Ready starts nothing: no review, check, close, commit or merge happens by itself.";

const list = (xs: readonly string[]): string => xs.slice(0, 10).join(", ") + (xs.length > 10 ? ` (+${xs.length - 10})` : "");

function engineBlockers(c: CompletionInput): CompletionBlocker[] {
  const out: CompletionBlocker[] = [];
  const b = (code: string, detail: string, threads?: string[]) => out.push({ category: "incomplete", code, detail, ...(threads ? grouped(threads) : {}) });
  if (c.run_state === "INTERRUPTED") b("run_interrupted", "the run is INTERRUPTED: an operation's server died before it committed an outcome; the next operation or a stop records the recovery");
  if (c.run_state === "CONFIGURATION_ERROR") b("run_configuration_error", "the run is in CONFIGURATION_ERROR");
  if (c.run_state === "PREPARING") b("run_preparing", "the baseline capture is still running");
  if (c.active_operation) b("operation_running", `a ${c.active_operation.kind} operation is running (${c.active_operation.operation_id}); completion is judged when it has ended`);
  if (c.current_source_id === null) b("current_source_unknown", "this report could not read the working tree fresh and stable, so no evidence can be judged current");
  const containment = c.incidents.filter((i) => CONTAINMENT_INCIDENTS.has(i.kind));
  for (const i of containment.slice(0, 5)) b("isolation_containment_incident", `${i.kind} in review ${i.review_id ?? "(none)"} (incident ${i.incident_id}): the reviewer's containment failed in this run; no user decision clears it, and a new run starts a clean record`);
  if (containment.length > 5) out.push({ category: "incomplete", code: "isolation_containment_incident", detail: `${containment.length - 5} more containment incident(s)`, incidents: containment.length - 5 });
  const damaged = c.threads.filter((t) => t.lineage_anomalies.length && t.blocks_completion);
  if (damaged.length) b("lineage_anomaly", "the lineage of these threads is damaged (a cycle, a dangling or self link, or truncated links): CodeParley cannot tell which items a decision would cover, so they cannot be decided", damaged.map((t) => t.thread_id));
  return out;
}

function grouped(threads: readonly string[]): { thread_ids: string[]; threads: number } {
  return { thread_ids: threads.slice(0, MAX_THREADS_PER_BLOCKER), threads: threads.length };
}

function checkBlockers(c: CompletionInput): CompletionBlocker[] {
  const f = c.floor;
  const out: CompletionBlocker[] = [];
  const b = (code: string, detail: string) => out.push({ category: "checks_not_satisfied", code, detail });
  if (!f.configured) {
    b("floor_not_configured", "the trusted project configuration sets no verification floor (required profiles or an explicit no_required_checks; `code-parley checks approve`)");
    return out;
  }
  if (f.failed.length) b("required_check_failed", `required check(s) failed or timed out for the current source: ${list(f.failed)}`);
  if (f.missing.length) b("required_check_missing", `required check(s) never ran for the current source: ${list(f.missing)}`);
  if (f.stale.length) b("required_check_stale", `required check result(s) are not current (source, specification or environment changed): ${list(f.stale)}`);
  if (f.removed.length) b("required_check_removed", `required check(s) were removed from the trusted configuration: ${list(f.removed)}`);
  if (f.unapproved.length) b("required_check_unapproved", `required check(s) are not approved: ${list(f.unapproved)}`);
  if (!f.satisfied_for_current_source && out.length === 0) b("floor_not_satisfied", "the verification floor is not satisfied for the current source");
  return out;
}

function reviewBlockers(c: CompletionInput): CompletionBlocker[] {
  const out: CompletionBlocker[] = [];
  const b = (code: string, detail: string) => out.push({ category: "review_not_current", code, detail });
  const r = c.latest_accepted_review;
  if (!r) {
    b("no_accepted_review", "no review of this run has been accepted yet");
    return out;
  }
  if (!r.freshness) b("review_freshness_unknown", `the freshness of the latest accepted review (round ${r.round}) could not be established now`);
  else if (!r.freshness.current) b("review_stale", `the latest accepted review (round ${r.round}) is not current now: ${list([...r.freshness.stale_reasons])}`);
  const delta = amendmentDelta(c.amendments, r.presented_amendments);
  const label = (id: string): string => `A-${c.amendments.byId.get(id)?.seq ?? "?"}`;
  // One the latest accepted review withheld is withheld again by a later review: only a replacement helps.
  const withheld = new Set(r.withheld_amendments);
  const pending = delta.not_presented.filter((id) => !withheld.has(id));
  const replace = delta.not_presented.filter((id) => withheld.has(id));
  if (pending.length) b("amendment_not_reviewed", `the user's amendment(s) ${list(pending.map(label))} were not presented to the latest accepted review; a later review you request presents them`);
  if (replace.length) b("amendment_withheld", amendmentWithheldDetail(replace.map(label), "the latest accepted review"));
  if (delta.no_longer_effective.length) b("amendment_changed_since_review", `amendment(s) ${list(delta.no_longer_effective.map(label))} presented to the latest accepted review were replaced or withdrawn since`);
  return out;
}

/** What a blocking thread needs, as a blocker code (each thread's own reasons are in its report). */
function threadCode(t: CompletionInput["threads"][number]): { category: BlockerCategory; code: string } | null {
  switch (t.completion_category) {
    case "needs_user_decision":
      return { category: "needs_user_decision", code: t.user_decision?.status === "lapsed" ? "user_decision_lapsed" : "escalated" };
    case "needs_reviewer":
      return { category: "needs_reviewer", code: "awaiting_reviewer" };
    case "needs_implementer":
      return { category: "needs_implementer", code: t.user_decision?.kind === "require_resolution" && t.user_decision.status === "applies" ? "user_required_resolution" : "open_item" };
    default:
      return null;
  }
}

const THREAD_DETAILS: Record<string, string> = {
  user_decision_lapsed: "the user's decision on these threads no longer settles them (a new open item, a reviewer revision or a damaged lineage since): the user decides again",
  escalated: "these discussions need a user decision (see each thread's escalation reasons)",
  awaiting_reviewer: "an open item in these threads waits for the reviewer (a reply, a fix to verify, or an assessment); a review you request does that",
  user_required_resolution: "the user required these threads' items to be resolved; they stay open until a reviewer reports them resolved",
  open_item: "an open reviewer item in these threads waits for the implementer (a fix, a response, or a user decision)",
};

/** Blocking threads, grouped by what they need (one blocker per code: the count and the first thread ids). */
function threadBlockers(c: CompletionInput): CompletionBlocker[] {
  const groups = new Map<string, { category: BlockerCategory; code: string; threads: string[] }>();
  for (const t of c.threads) {
    // A damaged lineage is an engine condition (incomplete), and such a thread cannot be decided.
    if (!t.blocks_completion || t.lineage_anomalies.length) continue;
    const k = threadCode(t);
    if (!k) continue;
    const g = groups.get(k.code) ?? { ...k, threads: [] };
    g.threads.push(t.thread_id);
    groups.set(k.code, g);
  }
  return [...groups.values()].map((g) => ({ category: g.category, code: g.code, detail: THREAD_DETAILS[g.code] ?? g.code, ...grouped(g.threads) }));
}

const ORDER: Record<BlockerCategory, number> = { incomplete: 0, checks_not_satisfied: 1, review_not_current: 2, needs_user_decision: 3, needs_reviewer: 4, needs_implementer: 5 };

export function deriveCompletion(c: CompletionInput): CompletionReport {
  const all = [...engineBlockers(c), ...checkBlockers(c), ...reviewBlockers(c), ...threadBlockers(c)].sort((a, b) => ORDER[a.category] - ORDER[b.category]);
  const counts = Object.fromEntries(Object.keys(ORDER).map((k) => [k, 0])) as Record<BlockerCategory, number>;
  for (const x of all) counts[x.category] += x.threads ?? x.incidents ?? 1;
  const waived = c.threads.filter((t) => t.completion_category === "settled_by_waiver").map((t) => t.thread_id);
  const deferred = c.threads.filter((t) => t.completion_category === "settled_by_deferral").map((t) => t.thread_id);
  const limitations: Limitation[] = [...c.limitations];
  if (waived.length || deferred.length) {
    limitations.push({ code: "user_settled_threads", detail: `${waived.length} thread(s) waived and ${deferred.length} deferred by the user: their reviewer findings stay open; a user decision is not a reviewer resolution`, count: waived.length + deferred.length });
  }
  return {
    state: all[0]?.category ?? "ready",
    ready: all.length === 0,
    blockers: all.slice(0, MAX_BLOCKERS),
    blockers_total: all.reduce((n, x) => n + (x.incidents ?? 1), 0),
    counts,
    settled_by_user: { waived: waived.slice(0, MAX_THREADS_PER_BLOCKER), deferred: deferred.slice(0, MAX_THREADS_PER_BLOCKER), waived_total: waived.length, deferred_total: deferred.length },
    limitations,
    note: COMPLETION_NOTE,
  };
}
