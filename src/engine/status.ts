// Run status and the shared run report (plan §11.6, §13.4, §10.4; M1.5).
//
// `get_review_status` is a PURE OBSERVER: it never commits anything. A running operation
// whose owner is dead is SHOWN as interrupted (recovery is planned as a view, not applied;
// the next operation or stop applies it). The current source identity is recomputed with
// the capture lock; when the worktree is busy (checks hold it) the last known value is
// returned with its age, as the plan requires. Concurrent status calls for one repository
// share a single recomputation.

import { isDomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import { computeSourceIdentity, type CaptureRulesInput } from "../capture/capture.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { planRecovery } from "../store/recovery.js";
import { classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type OwnerRecord } from "../store/owner.js";
import { discussionCounts, itemDiscussion, reportDiscussion, respondable, responseToken, type DiscussionCounts, type ItemDiscussion, type ReportDiscussion } from "../policy/responses.js";
import { threadCounts, threadReports, type ThreadCounts, type ThreadReport } from "../policy/discussion-reports.js";
import { amendmentSeenBy, type AmendmentFacts } from "../policy/amendments.js";
import { deriveCompletion, type CompletionInput, type CompletionReport } from "../policy/completion.js";
import { decisionFactsOf, decisionStatus, type DecisionStatus } from "../policy/user-decisions.js";
import { staleOnlyByEnvironment } from "../policy/verification-floor.js";
import { caseKey } from "../workspace/paths.js";
import type { Limitation, SourceEntry } from "../schemas/capture.js";
import type { IsolationIncident, ReviewerItem, ReviewRecord } from "../schemas/review.js";
import type { Operation, StateRecord } from "../schemas/run-state.js";
import { evaluateChecksStatus } from "./checks-operation.js";
import { engineConditions, evidenceOf, REPORT_SOURCE_BUDGET_MS, reviewFreshnessNow, type EngineConditionView, type KnownSource } from "./review-operation.js";
import { checksContext, effectiveBudgets, gitExeOf, reviewContext, type Loaded, type RunHandle } from "./engine-env.js";
import { evidenceViewOf, hydratedSectionOf } from "./run-evidence.js";


export const OPERATION_NEXT =
  "Cancelling this call does not stop the operation. Call get_review_status with wait_seconds to keep waiting; call stop_review_loop(cancel_active, expected_operation_id) to cancel it.";

export interface OperationHandle {
  operation_id: string;
  kind: string;
  status: "running";
  started_at: string;
  elapsed_ms: number;
  progress?: string;
  deduplicated?: boolean;
  next: string;
}

export function operationHandle(op: Operation, extra: { deduplicated?: boolean; progress?: string } = {}): OperationHandle {
  const started = op.started_at ?? new Date().toISOString();
  return {
    operation_id: op.operation_id,
    kind: op.kind,
    status: "running",
    started_at: started,
    elapsed_ms: Math.max(0, Date.now() - Date.parse(started)),
    ...(extra.progress ? { progress: extra.progress } : {}),
    ...(extra.deduplicated !== undefined ? { deduplicated: extra.deduplicated } : {}),
    next: OPERATION_NEXT,
  };
}

// ---------------------------------------------------------------------------
// Current source identity
// ---------------------------------------------------------------------------

export interface SourceNow {
  source_id: string | null;
  /** 0 when recomputed by this call; the age of the last known value otherwise. */
  age_ms: number | null;
  recomputed: boolean;
  stable: boolean | null;
  note: string | null;
  /** Entries of a recomputation (engine use: withheld names for the host view). */
  entries: SourceEntry[] | null;
}

/** Time budget for recomputing the source identity in a status report. */
export const SOURCE_BUDGET_MS = REPORT_SOURCE_BUDGET_MS;

/**
 * A host call's own time limit (M1.6): waits end at the wait bound (≤ 50 s), and any report
 * work after a wait must fit before this point, so a status or stop call stays inside the
 * strictest host per-call limit (Desktop Chat: 60 s while unconfigured, plan C4).
 */
export const CALL_SOFT_LIMIT_MS = 55_000;

/** The source-recomputation budget left for a call that started at `startedAtMs`. */
export function sourceBudgetFor(startedAtMs: number, nowMs = Date.now()): number {
  return Math.max(0, Math.min(SOURCE_BUDGET_MS, startedAtMs + CALL_SOFT_LIMIT_MS - nowMs));
}

/** What a report knows about the source, for review freshness (never a second tree read). */
export function knownSourceOf(src: SourceNow | null): KnownSource {
  return src && src.recomputed && src.source_id && src.stable !== null ? { source_id: src.source_id, stable: src.stable } : "unavailable";
}

const lastKnown = new Map<string, { sourceId: string; atMs: number }>();

/** A computation shared by concurrent callers, and the deadline it was started with. */
export interface SharedRun<T> {
  p: Promise<T>;
  deadlineMs: number;
}

/**
 * Run `compute(budgetMs)` for `key`, sharing one in-flight run between concurrent callers —
 * but each caller is bounded by its OWN deadline (PR #2 review): a caller never waits past it
 * (null then), and a caller whose deadline is at least `minUsefulMs` later than the shared
 * run's re-runs with its remaining time when the shared result is `retryable` (a run that
 * ended early on another caller's shorter budget).
 */
export async function shareWithinBudget<T>(
  runs: Map<string, SharedRun<T>>,
  key: string,
  budgetMs: number,
  compute: (budgetMs: number) => Promise<T>,
  retryable: (r: T) => boolean,
  minUsefulMs = 1000,
): Promise<T | null> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const left = deadline - Date.now();
    const pending = runs.get(key);
    if (!pending) {
      const p: Promise<T> = compute(left).finally(() => {
        if (runs.get(key)?.p === p) runs.delete(key);
      });
      runs.set(key, { p, deadlineMs: deadline });
      return p;
    }
    let timer: NodeJS.Timeout | undefined;
    const timeUp = new Promise<null>((resolve) => (timer = setTimeout(() => resolve(null), Math.max(0, left))));
    const r = await Promise.race([pending.p, timeUp]).finally(() => clearTimeout(timer));
    if (r === null) return null;
    const leftNow = deadline - Date.now();
    if (retryable(r) && pending.deadlineMs < deadline - minUsefulMs && leftNow >= minUsefulMs) continue;
    return r;
  }
}

const inflight = new Map<string, SharedRun<SourceNow>>();

function lastKnownFromState(st: StateRecord): { sourceId: string; atMs: number } | null {
  let best: { sourceId: string; atMs: number } | null = null;
  const consider = (id: string | null | undefined, at: string | null | undefined) => {
    if (!id || !at) return;
    const t = Date.parse(at);
    if (Number.isFinite(t) && (!best || t > best.atMs)) best = { sourceId: id, atMs: t };
  };
  for (const e of st.check_executions) consider(e.source_stable ? e.source_id_at_end : null, e.ended_at);
  for (const r of st.reviews) consider(r.source_id, r.ended_at ?? r.started_at);
  for (const op of st.operations) if (op.kind === "prepare") consider((op.outcome as { baseline_source_id?: string } | undefined)?.baseline_source_id, op.ended_at);
  return best;
}

export async function currentSource(le: Loaded, run: RunHandle, st: StateRecord, budgetMs: number = SOURCE_BUDGET_MS): Promise<SourceNow> {
  // P3.4C-4: a protected run's source identity is computed under the custodian's capture rules (the identities it
  // compares are made under them); the last known value is kept per rule set.
  let rules: CaptureRulesInput;
  try {
    rules = (await checksContext(le, run)).rules;
  } catch (e) {
    const why = `the protected run's capture rules could not be read from the custodian (${isDomainError(e) ? e.code : "error"})`;
    return { source_id: null, age_ms: null, recomputed: false, stable: null, note: why, entries: null };
  }
  const key = `${run.repoKey}\u0000${sha256OfCanonicalJson(rules)}`;
  const lastKnownValue = (why: string): SourceNow => {
    const known = lastKnown.get(key) ?? lastKnownFromState(st);
    return { source_id: known?.sourceId ?? null, age_ms: known ? Date.now() - known.atMs : null, recomputed: false, stable: null, note: known ? `${why}; this is the last known value` : why, entries: null };
  };
  // The call's own time is spent (its wait used it): report the last known value — also when
  // another call is re-reading the tree right now (that read is not this call's to wait for).
  if (budgetMs < 1000) return lastKnownValue("this call's time was used by its wait, so the source was not re-read");
  const shared = await shareWithinBudget(inflight, key, budgetMs, (b) => recompute(b), (r) => !r.recomputed);
  return shared ?? lastKnownValue(`re-reading the source took longer than the ${Math.round(budgetMs / 1000)} s this call had for it`);

  async function recompute(budgetMs: number): Promise<SourceNow> {
    const started = Date.now();
    try {
      const r = await computeSourceIdentity({
        repoRoot: run.meta.repository_root,
        gitExe: await gitExeOf(le),
        rules,
        lock: { dataHome: le.dataHome, owner: le.env.owner, ...(le.env.testHooks?.lockDeps ? { deps: le.env.testHooks.lockDeps } : {}) },
        operationId: `status-${uuidv7()}`,
        // Bounded: a status call must stay inside host per-call limits (C4) even on a large
        // tree; past the budget the last known value is reported with its age.
        signal: AbortSignal.timeout(budgetMs),
      });
      lastKnown.set(key, { sourceId: r.source_id, atMs: Date.now() });
      return { source_id: r.source_id, age_ms: 0, recomputed: true, stable: r.stable, note: r.stable ? null : "the working tree changed while it was being read; this identity is not stable", entries: r.entries };
    } catch (e) {
      const code = isDomainError(e) ? e.code : "INTERNAL";
      const timedOut = Date.now() - started >= budgetMs - 50;
      const known = lastKnown.get(key) ?? lastKnownFromState(st);
      const why = timedOut
        ? `recomputing the source identity took longer than the ${Math.round(budgetMs / 1000)} s this call had for it`
        : code === "WORKTREE_BUSY"
          ? isDomainError(e) && e.details?.["waiter"]
            ? "an operation is waiting for the worktree lock, so this read stood aside"
            : "the worktree is busy (a check or capture holds it)"
          : code === "WORKTREE_OWNERSHIP_UNRESOLVED"
            ? "the worktree lock is ownership_unresolved after a server died during checks (release it with the CLI after inspection)"
            : `the source identity could not be recomputed (${code})`;
      return { source_id: known?.sourceId ?? null, age_ms: known ? Date.now() - known.atMs : null, recomputed: false, stable: null, note: known ? `${why}; this is the last known value` : why, entries: null };
    }
  }
}

// ---------------------------------------------------------------------------
// The run report shared by status and stop (MR-D: three separate record kinds)
// ---------------------------------------------------------------------------

export interface CompactFinding extends ItemDiscussion {
  id: string;
  item_kind: ReviewerItem["item_kind"];
  round: number;
  triage: ReviewerItem["triage"];
  basis: "reviewer_evidence";
  status: ReviewerItem["status"];
  title: string;
  claim_type: ReviewerItem["claim_type"];
  severity: ReviewerItem["severity"];
  category: ReviewerItem["category"];
  confidence: ReviewerItem["confidence"];
  locations: { path: string | null; start_line: number | null; end_line: number | null; validation: string | null }[];
  last_assessment: string | null;
}

/** What a report knows for the discussion fields: the run's discussion and the fresh source (null: unknown). */
export type DiscussionInput = ReportDiscussion;

/** `checkResults`: what the checks found for the current source, for the next review's preview (null: not compared). */
export function discussionInputOf(st: StateRecord, currentSourceId: string | null, checkResults: string | null = null): DiscussionInput {
  return reportDiscussion(st, currentSourceId, checkResults, caseKey);
}

/** The source id a report may judge staleness against: only a fresh, stable identity. */
export function freshSourceId(known: KnownSource): string | null {
  return known !== "unavailable" && known.stable ? known.source_id : null;
}

export function compactFinding(it: ReviewerItem, d: DiscussionInput): CompactFinding {
  return {
    id: it.id,
    item_kind: it.item_kind,
    round: it.round,
    triage: it.triage,
    basis: it.basis,
    status: it.status,
    title: it.title,
    claim_type: it.claim_type,
    severity: it.severity,
    category: it.category,
    confidence: it.confidence,
    locations: it.evidence
      .filter((e) => e.path)
      .slice(0, 3)
      .map((e) => ({ path: e.path, start_line: e.start_line, end_line: e.end_line, validation: (e as { validation?: string }).validation ?? null })),
    last_assessment: it.assessments.at(-1)?.assessment ?? null,
    ...itemDiscussion(it, d.view, d.currentSourceId),
  };
}

/** Threads a report lists in full (the rest are counted; the history pages them all). */
export const MAX_REPORTED_THREADS = 40;

/**
 * The discussion part of a report (Phase 2.1 counts; Phase 2.2 threads, P2.2-10): every thread
 * with a respondable item — informational ones included, with their tokens — ordered by who must
 * act, at most MAX_REPORTED_THREADS of them. Fields that would be null, false or empty are left
 * out of a thread summary, so an idle thread costs little (the history pages the full reports).
 */
export interface DiscussionReport extends DiscussionCounts, ThreadCounts {
  threads: Partial<ThreadReport>[];
  threads_shown: number;
}

export function discussionReport(st: StateRecord, d: DiscussionInput, all?: ThreadReport[]): DiscussionReport {
  const { ix } = d.view;
  const reports = all ?? allThreadReports(d);
  const shown = reports.slice(0, MAX_REPORTED_THREADS);
  return { ...discussionCounts(st.findings, st.implementer_responses), ...threadCounts(ix, reports), threads: shown.map(compactThread), threads_shown: shown.length };
}

/** Every thread report of the run, ordered by who must act (status lists the first MAX_REPORTED_THREADS). */
export function allThreadReports(d: DiscussionInput): ThreadReport[] {
  const { ix, plan } = d.view;
  return threadReports(ix, plan, (it) => (respondable(it) ? responseToken(it, ix) : null));
}

/** The user layer of a report (Phase 2.3, P2.3-12): the user's decisions and task amendments. */
export interface UserReport {
  decisions: { recorded: number } & Partial<Record<DecisionStatus, number>> & { unrecognized_provenance?: number };
  amendments: {
    recorded: number;
    effective: number;
    latest_seq: number;
    not_seen_by_reviewer: number;
    unrecognized_provenance?: number;
    /** The effective amendments (at most 10), each with an excerpt and whether an accepted review presented it. */
    in_effect: { id: string; amendment_id: string; kind: string; text_excerpt: string; threads: number; seen_by_reviewer: { review_id: string; round: number } | null }[];
  };
  note: string;
}

export const USER_REPORT_NOTE =
  "User decisions and task amendments are operator-authoritative records: only CodeParley's local operator interface (code-parley decide / amend, at an interactive terminal) writes them, never MCP; an implementer response saying what the user decided is the implementer's claim. Their assurance, local_operator, means CodeParley trusts the local OS user, its installation and its store; it does not verify human presence. A decision settles only its own thread and never changes a reviewer finding, a check or an incident.";

export function userReport(d: DiscussionInput): UserReport {
  const ix = d.view.ix;
  const facts = decisionFactsOf(ix);
  const counts: Partial<Record<DecisionStatus, number>> = {};
  for (const x of facts.all) {
    const s = decisionStatus(ix, facts, x).status;
    counts[s] = (counts[s] ?? 0) + 1;
  }
  const a: AmendmentFacts = ix.amendments;
  return {
    decisions: { recorded: facts.all.length, ...counts, ...(facts.unrecognized ? { unrecognized_provenance: facts.unrecognized } : {}) },
    amendments: {
      recorded: a.all.length,
      effective: a.effective.length,
      latest_seq: a.seq,
      not_seen_by_reviewer: a.effective.filter((x) => amendmentSeenBy(a, x.amendment_id) === null).length,
      ...(a.unrecognized ? { unrecognized_provenance: a.unrecognized } : {}),
      in_effect: a.effective.slice(-10).map((x) => ({ id: `A-${x.seq}`, amendment_id: x.amendment_id, kind: x.kind, text_excerpt: x.text, threads: x.relates_to.length, seen_by_reviewer: amendmentSeenBy(a, x.amendment_id) })),
    },
    note: USER_REPORT_NOTE,
  };
}

/** A thread summary without the fields that carry nothing (null, false, empty, no escalation). */
export function compactThread(t: ThreadReport): Partial<ThreadReport> {
  const out: Partial<ThreadReport> = { ...t };
  for (const k of Object.keys(out) as (keyof ThreadReport)[]) {
    const v = out[k];
    if (v === null || v === false || (Array.isArray(v) && v.length === 0)) delete out[k];
  }
  if (!t.escalation.needed) delete out.escalation;
  return out;
}

export interface CompactIncident {
  incident_id: string;
  review_id: string | null;
  operation_id: string;
  kind: string;
  detail: string;
  at: string;
}

export function compactIncident(i: IsolationIncident): CompactIncident {
  return { incident_id: i.incident_id, review_id: i.review_id, operation_id: i.operation_id, kind: i.kind, detail: i.detail, at: i.at };
}

export interface LatestReviewView {
  review_id: string;
  round: number;
  source_id: string;
  verdict: ReviewRecord["verdict"];
  accepted: boolean;
  freshness: { source: boolean | null; inputs: boolean | null; current: boolean; stale_reasons: string[] } | null;
}

export interface RunReport {
  /** Phase 2.3: the derived task completion (P2.3-11); nothing can set it, and it starts nothing. */
  completion: CompletionReport;
  /** Phase 2.3: the user's decisions and task amendments (P2.3-12). */
  user: UserReport;
  floor: { configured: boolean; satisfied_for_current_source: boolean; missing: string[]; stale: string[]; failed: string[]; removed: string[]; unapproved: string[] };
  latest_review: LatestReviewView | null;
  open_findings: CompactFinding[];
  /** Discussion states over every reviewer item and the responses (Phase 2.1); threads and their state (Phase 2.2). */
  discussion: DiscussionReport;
  conditions: EngineConditionView[];
  incidents: CompactIncident[];
  limitations: Limitation[];
  budgets: { name: string; used: number; limit: number }[];
}

/**
 * Reviewer items, engine conditions and incidents for `sourceId` (null = unknown), now.
 * `known`: what this report already knows about the source (a fresh identity, or
 * "unavailable" when its own bounded read did not succeed) — the review's freshness reuses it
 * and never reads the tree a second time (M1.5-8).
 */
export async function runReport(le: Loaded, run: RunHandle, st: StateRecord, sourceId: string | null, known: KnownSource, observed?: StateRecord): Promise<RunReport> {
  const cctx = await checksContext(le, run);
  const rctx = await reviewContext(le, run);
  const checks = await evaluateChecksStatus(cctx, sourceId, st);
  const limitations: Limitation[] = [...checks.limitations];
  const { current, shown, latestView } = await latestReviewOf(rctx, st, known, limitations);
  const conditions = await engineConditions(rctx, sourceId, current, st).catch(() => [] as EngineConditionView[]);
  if (sourceId === null) limitations.push({ code: "current_source_unknown", detail: "the current source identity is unknown, so no check evidence can be shown as fresh" });
  limitations.push({ code: "triage_per_reviewer_evidence", detail: "reviewer findings are triaged per the reviewer's evidence (not engine-verified); completion is derived from them and the other evidence, and nothing can set it" });
  const envOnly = observerEnvironmentLimitation(checks.checks.filter(staleOnlyByEnvironment).map((v) => v.check));
  if (envOnly) limitations.push(envOnly);
  const fresh = freshSourceId(known);
  // The preview of the next review compares the current check results only for a fresh source.
  const d = discussionInputOf(st, fresh, fresh !== null && fresh === sourceId ? evidenceOf(checks, st).resultsDigest : null);
  const reports = allThreadReports(d);
  const discussion = discussionReport(st, d, reports);
  limitations.push(...discussionLimitations(discussion));
  const f = checks.floor;
  const budgets = reportBudgets(le, run, st);
  const floor = { configured: f.configured, satisfied_for_current_source: f.satisfied_for_current_source, missing: f.missing, stale: f.stale, failed: [...f.failed, ...f.timed_out], removed: f.removed, unapproved: f.unapproved };
  const obs = observed ?? (await observedState(le, st)).state;
  const completion = deriveCompletion({
    ...runCompletionFacts(obs, current, shown === current ? latestView : null),
    current_source_id: fresh,
    floor,
    amendments: d.view.ix.amendments,
    incidents: st.isolation_incidents,
    threads: reports,
    limitations: [...completionLimitations(conditions, current), ...(envOnly ? [envOnly] : [])],
  });
  return {
    completion,
    user: userReport(d),
    floor,
    latest_review: latestView,
    open_findings: st.findings.filter((x) => x.status === "open").map((x) => compactFinding(x, d)),
    discussion,
    conditions,
    incidents: st.isolation_incidents.map(compactIncident),
    limitations,
    budgets,
  };
}

/**
 * P3.4C-3 C4: the budgets a report and the routing use — the same limits as the starts: on a protected run (its state
 * hydrated from the custodian's run record) the custodian's limits and use; otherwise min(config, run.json, hard caps)
 * with the run's own counters.
 */
export function reportBudgets(le: Loaded, run: RunHandle, st: StateRecord): { name: string; used: number; limit: number }[] {
  const section = hydratedSectionOf(st);
  if (section?.registered) {
    const used = (section.record?.["used"] ?? {}) as Record<string, unknown>;
    const n = (v: unknown, d: number): number => (typeof v === "number" ? v : d);
    return [
      { name: "reviews", used: n(used["reviews"], 0), limit: n(section.limits["maxReviews"], 0) },
      { name: "check_executions", used: n(used["checkExecutions"], 0), limit: n(section.limits["maxCheckExecutions"], 0) },
    ];
  }
  const b = effectiveBudgets(le, run.meta);
  return [
    { name: "reviews", used: st.counters["reviews"] ?? 0, limit: b.max_reviews_per_run },
    { name: "check_executions", used: st.counters["check_executions"] ?? 0, limit: b.max_check_executions_per_run },
  ];
}

/** A report's limitation code when check results are stale only because of the deriving process's environment (P3.3b). */
export const OBSERVER_ENVIRONMENT_DIFFERS = "observer_environment_differs";

/**
 * Check freshness binds the effective child environment built from the DERIVING process's own
 * environment (plan §10.3), so a process whose PATH or other passed variables differ — an operator
 * terminal (PowerShell itself changes PATH and PATHEXT), a harness — derives these results stale,
 * and with them the review's check evidence and completion, where the session's server and hooks
 * derive them current. Listed so such a report says why; it never blocks or unblocks anything.
 */
export function observerEnvironmentLimitation(checks: readonly string[]): Limitation | null {
  if (checks.length === 0) return null;
  return {
    code: OBSERVER_ENVIRONMENT_DIFFERS,
    detail: `check result(s) ${checks.slice(0, 10).join(", ")} are stale here only because this process's environment (PATH and the other variables a check receives) differs from the one they ran in; check freshness, and with it review currency and completion, is derived for the deriving process's own environment, so a terminal or harness with another environment shows this evidence stale where the session's own server and hooks may show it current`,
    count: checks.length,
  };
}

/**
 * What completion lists even when ready (P2.3-11): what the evidence does not cover. Coverage
 * conditions of the latest accepted review's capture, its reduced isolation and user hooks, the
 * partly bound environment of checks, and triage per reviewer evidence. None of them blocks.
 */
/** The run's current (latest accepted) review, the review status shows, its view now, and their limitations. */
async function latestReviewOf(rctx: Awaited<ReturnType<typeof reviewContext>>, st: StateRecord, known: KnownSource, limitations: Limitation[]): Promise<{ current: ReviewRecord | null; shown: ReviewRecord | null; latestView: LatestReviewView | null }> {
  const current = [...st.reviews].reverse().find((r) => r.accepted === true) ?? null;
  const shown = current ?? st.reviews.at(-1) ?? null;
  if (!shown) return { current, shown, latestView: null };
  // A protected run's state was hydrated from the custodian's run record: its freshness reads the same evidence.
  const view = evidenceViewOf(hydratedSectionOf(st), rctx.runPaths.runDir);
  const f = shown.status === "completed" ? await reviewFreshnessNow(view ? { ...rctx, evidenceView: view } : rctx, shown, known).catch(() => null) : null;
  if (f && !f.current) limitations.push({ code: "stale_evidence", detail: `the latest review is not current now: ${f.stale_reasons.join(", ")}` });
  if (!current) limitations.push({ code: "no_accepted_review", detail: notAcceptedDetail(shown) });
  return { current, shown, latestView: reviewViewOf(shown, f) };
}

function reviewViewOf(r: ReviewRecord, f: Awaited<ReturnType<typeof reviewFreshnessNow>> | null): LatestReviewView {
  return {
    review_id: r.review_id,
    round: r.round,
    source_id: r.source_id,
    verdict: r.verdict,
    accepted: r.accepted === true,
    freshness: f ? { source: f.source, inputs: f.check_evidence, current: f.current, stale_reasons: f.stale_reasons } : null,
  };
}

function notAcceptedDetail(r: ReviewRecord): string {
  const why = r.not_accepted_reasons.length ? `, ${r.not_accepted_reasons.join(", ")}` : "";
  return `no review of this run has been accepted yet (latest: ${r.status}${why})`;
}

/** The discussion's limitations: responses older than a review, claims, escalations, threads not listed. */
function discussionLimitations(discussion: DiscussionReport): Limitation[] {
  const out: Limitation[] = [];
  if (discussion.stale_responses > 0) out.push({ code: "responses_predate_review", detail: `${discussion.stale_responses} open item(s) were assessed by a review after the implementer's latest response; respond again if the position changed`, count: discussion.stale_responses });
  if (discussion.responses_recorded > 0) out.push({ code: "responses_are_claims", detail: "implementer responses are the implementer's claims and reviewer replies the reviewer's stance: neither resolves anything; a later review you request presents a response to the reviewer only when it earns an exchange (new information, within the budget)" });
  if (discussion.escalated > 0) out.push({ code: "discussion_escalated", detail: `${discussion.escalated} discussion thread(s) need a user decision (see each thread's escalation reasons); CodeParley records no decision on anyone's behalf`, count: discussion.escalated });
  if (discussion.threads_total > discussion.threads_shown) out.push({ code: "discussion_threads_truncated", detail: `${discussion.threads_shown} of ${discussion.threads_total} discussion threads are listed (those needing action first); get_review_history(run_id, responses: {}) pages them all`, count: discussion.threads_total });
  return out;
}

/** Completion's facts about the run itself: its state, its running operation, and its current review with its freshness now (`currentView`: the view status shows of that same review, or null). */
function runCompletionFacts(obs: StateRecord, current: ReviewRecord | null, currentView: LatestReviewView | null): Pick<CompletionInput, "run_state" | "active_operation" | "latest_accepted_review"> {
  const activeOp = obs.operations.find((o) => o.status === "running") ?? null;
  const fr = currentView?.freshness ?? null;
  return {
    run_state: obs.state,
    active_operation: activeOp ? { kind: activeOp.kind, operation_id: activeOp.operation_id } : null,
    latest_accepted_review: current ? { review_id: current.review_id, round: current.round, freshness: fr ? { current: fr.current, stale_reasons: fr.stale_reasons } : null, presented_amendments: (current.amendments?.presented ?? []).map((p) => p.amendment_id), withheld_amendments: (current.amendments?.withheld ?? []).map((w) => w.amendment_id) } : null,
  };
}

function completionLimitations(conditions: readonly EngineConditionView[], current: ReviewRecord | null): Limitation[] {
  const out: Limitation[] = [];
  for (const c of conditions) if (c.kind === "coverage") out.push({ code: `coverage_${c.code ?? "condition"}`, detail: c.detail });
  if (current && current.effective_isolation.mode !== "S1") out.push({ code: "isolation_reduced", detail: `the latest accepted review ran with reduced isolation ${current.effective_isolation.mode} (accepted by the user through the CLI)` });
  if (current?.effective_isolation.user_hooks_present) out.push({ code: "user_hooks_present", detail: "user-level Codex hooks exist; trusted hooks run outside the sandbox (reported, not prevented)" });
  out.push({ code: "environment_bound_partial", detail: "check results bind the environment only through configured freshness inputs (section 10.5)" });
  out.push({ code: "triage_per_reviewer_evidence", detail: "reviewer findings are triaged per the reviewer's evidence, not verified by the engine" });
  return out;
}

/**
 * The state as an observer should see it: running operations of dead owners are shown as
 * interrupted (and the run as INTERRUPTED) without committing anything.
 */
export async function observedState(le: Loaded, st: StateRecord): Promise<{ state: StateRecord; recoveryPending: string[] }> {
  if (!st.operations.some((o) => o.status === "running")) return { state: st, recoveryPending: [] };
  const classify = le.env.testHooks?.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS));
  const plan = await planRecovery(st, classify);
  return plan.changed ? { state: plan.nextState, recoveryPending: plan.interrupted } : { state: st, recoveryPending: [] };
}
