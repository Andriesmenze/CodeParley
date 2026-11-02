// P3.4C-5 Increment 3 (contract §5.1–§5.3, Amendment A §A.5): the PROTECTED derivation — completion, the route and the
// progress fingerprint of a protected run, computed by the custodian's helper over the custodian's SCRUBBED snapshot of
// its held records and its own fresh measurement. Never from local state: state.json, run.json (except the run's own
// floor, read from run.json bytes the custodian verified against the digest it holds), local artifacts, local trusted
// files and the local continuation record are not inputs.
//
// PURE: no I/O. It composes the engine's own leaf functions exactly as the engine's local derivation (status.ts
// runReport) composes them — the held configuration evaluated as the trust file would be, the verification floor, the
// check evidence, the latest review's currency, the discussion threads, completion and routing — over a state rebuilt
// from held records only (texts are never held and never needed: a response's references arrive as comparison keys,
// its rationale as presence). N5-5 parity (equal completion and route) is tested against the engine's local derivation
// over the same records.
//
// What the custodian cannot measure stays an engine claim (D5-E, §8): a check's environment digest (the current
// environment of a check is the one its latest execution claimed), the executable path the session resolved (its STAT
// is measured), check outcomes and the reviewer's output.

import { DomainError } from "../common/errors.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { computeExecutionInputId } from "../checks/identity.js";
import type { CheckExecutionRecord, RunVerificationFloor } from "../schemas/checks.js";
import type { ReviewerItem, ReviewRecord } from "../schemas/review.js";
import type { StateRecord } from "../schemas/run-state.js";
import type { ConfigSection, UserRecordListing } from "../custodian/protocol.js";
import { deriveCompletion, type CompletionInput, type CompletionReport } from "../policy/completion.js";
import { routeFromEngine, type NextAction, type OperationFact, type RoutingFacts } from "../policy/continuation.js";
import { checkStatus, deriveCheckConditions, effectiveRequirements, evaluateFloor, type CheckStatusView, type CurrentCheckInputs } from "../policy/verification-floor.js";
import { reportDiscussion } from "../policy/responses.js";
import { toView, type ChecksStatus } from "./checks-operation.js";
import { heldEvaluation } from "./protected-config.js";
import { fromListing } from "./protected-user-records.js";
import { evidenceOf } from "./review-operation.js";
import { allThreadReports } from "./status.js";

export const DERIVATION_SNAPSHOT_SCHEMA = "arl.derivation-snapshot.v2";
export const PROTECTED_DERIVATION_SCHEMA = "arl.protected-derivation.v1";
export const PROGRESS_FINGERPRINT_SCHEMA = "arl.progress-fingerprint.v2";

// ---------------------------------------------------------------------------
// The snapshot (built by the custodian, C# and the TS simulator alike) and the measurement (by the helper)
// ---------------------------------------------------------------------------

export interface HeldExecution {
  executionId: string;
  operationId: string;
  check: string;
  status: string;
  exitCode: number | null;
  timedOut: boolean;
  cancelled: boolean;
  durationMs: number | null;
  definitionDigest: string | null;
  checkSpecId: string | null;
  envDigest: string | null;
  freshnessDigest: string | null;
  executionInputId: string | null;
  sourceIdAtStart: string | null;
  sourceIdAtEnd: string | null;
  sourceStable: boolean;
  evidenceEpoch: number;
}

export interface HeldReviewBindings {
  sourceId: string;
  reviewInputId: string;
  checkEvidenceDigest: string;
  checkResultsDigest: string | null;
  checkExecutionIds: string[];
  captureStable: boolean;
  manifestDigest: string;
  exportDigest: string;
  captureDigest: string;
}

export interface HeldReview {
  reviewId: string;
  operationId: string;
  round: number;
  /** The custodian's acceptance (null: not finished). */
  accepted: boolean | null;
  notAcceptedReasons: string[];
  evidenceEpoch: number;
  /** The finished review's status (null: not finished). */
  status: string | null;
  verdict: string | null;
  /** The custodian's read-time verdict on the pinned basis (§4.3). */
  basisUsable: boolean;
  isolationMode: string | null;
  bindings: HeldReviewBindings | null;
  /** The custodian published the export and its own re-hash at op_finish found it unchanged. */
  exportIntact: boolean;
  itemIds: string[];
  presented: { deliveries: { responseId: string; itemId: string; replySought: boolean; basis: string[] }[]; amendments: string[]; withheld: string[] } | null;
}

export interface HeldItem {
  itemId: string;
  reviewId: string;
  round: number;
  sourceId: string;
  itemKind: string;
  status: string;
  triage: string;
  severity: string | null;
  claimType: string | null;
  category: string | null;
  confidence: string | null;
  impacts: string[];
  relatedPriorId: string | null;
  relatedFindingId: string | null;
  supersedes: string[];
  supersededBy: string | null;
  restates: string[];
  assessments: { reviewId: string; round: number; sourceId: string; assessment: string; effect: string }[];
}

export interface HeldResponse {
  responseId: string;
  responseSetId: string;
  itemId: string;
  disposition: string;
  textWithheld: boolean;
  answers: { reviewId: string | null; round: number | null; runReviewId: string | null; runRound: number | null; reviewerReplyId: string | null };
  sourceId: string | null;
  supersedes: string | null;
  threadId: string;
  /** SHA-256 of each cited location in its comparison form (engine claim, P3.4C-5 Increment 3). */
  referenceKeys: string[];
  rationalePresent: boolean;
}

export interface HeldReply {
  replyId: string;
  reviewId: string;
  round: number;
  itemId: string;
  stance: string;
  newInformation: string;
  answersResponseId: string | null;
  assessment: string | null;
}

export interface DerivationSnapshot {
  schema: string;
  repositoryRoot: string;
  revision: { runRevision: number | null; loopRevision: number | null; evidenceEpoch: number | null; configRevision: number | null; globalRevision: number; userRevision: number };
  run: {
    status: string;
    evidenceEpoch: number;
    used: { reviews: number; checkExecutions: number };
    limits: { maxReviews: number; maxCheckExecutions: number };
    operations: { operationId: string; kind: string; status: string; beganAt: string; endedAt: string | null; planned: string[] }[];
    checkExecutions: HeldExecution[];
    reviews: HeldReview[];
    items: HeldItem[];
    responses: HeldResponse[];
    replies: HeldReply[];
    incidents: { incidentId: string; kind: string; reviewId: string | null; operationId: string }[];
  } | null;
  loop: { status: string; startedAt: string; resumedAt: string | null } | null;
  /** The custodian's user-record listing, implementer projection (no raw note or amendment text). */
  user: { governed: boolean; revision: number; recoveredAtRevision: number | null; records: Record<string, unknown>[] };
  /** The custodian-held repository configuration (the parts the trusted evaluation reads). */
  config: ConfigSection;
  /** The run's own verification floor, from run.json bytes the custodian verified against its declaration digest. */
  runFloor: RunVerificationFloor | null;
  /** Per check: the absolute executable path the session resolved when it last planned it (an engine claim). */
  executables: Record<string, string>;
}

export interface MeasuredCheck {
  name: string;
  freshnessDigest: string | null;
  executable: { path: string; kind: string; size: number; mtimeMs: number } | null;
  checkSpecId: string | null;
  problem: string | null;
}

export interface DerivationMeasurement {
  sourceId: string;
  stable: boolean;
  rootCommit: string | null;
  checks: MeasuredCheck[];
}

export interface ProtectedDerivation {
  schema: string;
  completion: { state: CompletionReport["state"]; ready: boolean; blockers: { category: string; code: string }[]; counts: CompletionReport["counts"] };
  route: { code: string; kind: string; reason: string; pause?: string; end?: string };
  floor: { configured: boolean; satisfied_for_current_source: boolean; missing: string[]; stale: string[]; failed: string[]; removed: string[]; unapproved: string[] };
  currentSourceId: string | null;
  progressFingerprint: string;
  inputDigest: string;
}

// ---------------------------------------------------------------------------
// The state the derivation reads, rebuilt from held records only
// ---------------------------------------------------------------------------

// Phase 4 Increment 2: a run that is `fixing` has a fix operation running; the operation (not the state) is what routes.
// Phase 4 Increment 3: so is a run that is `applying` (its application operation routes).
const RUN_STATE: Record<string, string> = { idle: "IDLE", checking: "CHECKING", reviewing: "REVIEWING", fixing: "IDLE", applying: "IDLE", stopped: "STOPPED", closed: "CLOSED" };
const HEX64 = /^[0-9a-f]{64}$/;
const isDigestOrNull = (v: unknown): boolean => v === null || (typeof v === "string" && HEX64.test(v));

/** A held operation's status as the engine's records name it (a measuring or captured review is running). */
function opStatusOf(status: string): string {
  return status === "measuring" || status === "captured" ? "running" : status;
}

/** The run's state as the engine would record it: interrupted while its latest operation was interrupted. */
function runStateOf(run: NonNullable<DerivationSnapshot["run"]>): string {
  const mapped = RUN_STATE[run.status] ?? "CONFIGURATION_ERROR";
  if (mapped !== "IDLE") return mapped;
  return run.operations.at(-1)?.status === "interrupted" ? "INTERRUPTED" : mapped;
}

/** An execution counts only when every identity freshness compares is present and well formed (fail closed). */
function executionOf(h: HeldExecution): CheckExecutionRecord | null {
  if (![h.definitionDigest, h.checkSpecId, h.envDigest, h.freshnessDigest, h.executionInputId].every(isDigestOrNull)) return null;
  return {
    execution_id: h.executionId,
    operation_id: h.operationId,
    check: h.check,
    status: h.status as CheckExecutionRecord["status"],
    definition_digest: h.definitionDigest,
    check_spec_id: h.checkSpecId,
    execution_input_id: h.executionInputId,
    resolved_executable: null,
    env_digest: h.envDigest,
    env_names: [],
    passthrough_missing: [],
    freshness_inputs: [],
    freshness_digest: h.freshnessDigest,
    source_id_at_start: h.sourceIdAtStart,
    source_id_at_end: h.sourceIdAtEnd,
    source_stable: h.sourceStable,
    started_at: null,
    ended_at: null,
    duration_ms: h.durationMs,
    exit_code: h.exitCode,
    pid: null,
    timed_out: h.timedOut,
    cancelled: h.cancelled,
    stdout: null,
    stderr: null,
    stdio_held_after_exit: false,
    descendants: null,
    result_artifact: null,
    environment_bound: "partial",
    limitations: [],
  };
}

function reviewOf(h: HeldReview, epoch: number): ReviewRecord {
  const b = h.bindings;
  const current = h.evidenceEpoch === epoch;
  const basisLost = h.accepted === true && current && !h.basisUsable;
  const reasons = !b ? [...h.notAcceptedReasons, "custodian_bindings_unreadable"]
    : h.accepted === true && !current ? [...h.notAcceptedReasons, "evidence_epoch_superseded"]
    : basisLost ? [...h.notAcceptedReasons, "custodian:basis_unusable"]
    : h.notAcceptedReasons.map((x) => `custodian:${x}`);
  return {
    review_id: h.reviewId,
    operation_id: h.operationId,
    round: h.round,
    status: (h.status ?? "running") as ReviewRecord["status"],
    failure: null,
    started_at: "",
    ended_at: null,
    duration_ms: null,
    source_id: b?.sourceId ?? "",
    review_input_id: b?.reviewInputId ?? "",
    capture_id: "",
    capture_stable: b?.captureStable ?? false,
    export_ref: "",
    manifest_digest: b?.manifestDigest ?? "",
    export_digest: b?.exportDigest ?? null,
    check_evidence_digest: b?.checkEvidenceDigest ?? "",
    check_execution_ids: b?.checkExecutionIds ?? [],
    effective_isolation: { mode: h.isolationMode ?? "S1" } as ReviewRecord["effective_isolation"],
    codex: { version: "", model: null, reasoning_effort: null },
    prompt: { template_id: "", template_version: "", sha256: "", bytes: 0, artifact: "" },
    output_schema_version: "",
    policy_version: "",
    depth: "standard" as ReviewRecord["depth"],
    focus_sha256: null,
    verdict: (h.verdict ?? null) as ReviewRecord["verdict"],
    summary: null,
    item_ids: h.itemIds,
    policy_notes: [],
    freshness: null,
    accepted: !b ? false : h.accepted === null ? null : h.accepted === true && current && !basisLost,
    not_accepted_reasons: reasons,
    audit: null,
    incident_ids: [],
    cancellation: null,
    termination: null,
    artifacts: {},
    discussion: {
      schema: "",
      digest: "",
      delivered: (h.presented?.deliveries ?? []).map((d) => ({ response_id: d.responseId, item_id: d.itemId, reply_sought: d.replySought, basis: d.basis, truncated: false })),
      informational_presented: [],
      ...(b?.checkResultsDigest ? { check_results_digest: b.checkResultsDigest } : {}),
      not_delivered: [],
    },
    amendments: {
      presented: (h.presented?.amendments ?? []).map((id) => ({ amendment_id: id })),
      withheld: (h.presented?.withheld ?? []).map((id) => ({ amendment_id: id })),
    } as unknown as ReviewRecord["amendments"],
  } as ReviewRecord;
}

function itemOf(h: HeldItem): ReviewerItem {
  return {
    id: h.itemId,
    item_kind: h.itemKind as ReviewerItem["item_kind"],
    review_id: h.reviewId,
    round: h.round,
    source_id: h.sourceId,
    review_input_id: h.sourceId,
    title: "",
    claim_type: h.claimType as ReviewerItem["claim_type"],
    severity: h.severity as ReviewerItem["severity"],
    category: h.category as ReviewerItem["category"],
    impacts: h.impacts as ReviewerItem["impacts"],
    consequence: "",
    confidence: h.confidence as ReviewerItem["confidence"],
    evidence: [],
    investigation: "",
    recommended_change: "",
    triage: h.triage as ReviewerItem["triage"],
    basis: "reviewer_evidence",
    policy_notes: [],
    status: h.status as ReviewerItem["status"],
    related_prior_id: h.relatedPriorId,
    ...(h.relatedFindingId ? { related_finding_id: h.relatedFindingId } : {}),
    supersedes: h.supersedes,
    superseded_by: h.supersededBy,
    ...(h.restates.length ? { restates: h.restates } : {}),
    assessments: h.assessments.map((a) => ({ review_id: a.reviewId, round: a.round, source_id: a.sourceId, assessment: a.assessment, note: "", effect: a.effect })) as ReviewerItem["assessments"],
    created_at: "",
  } as ReviewerItem;
}

/** Phase 5 F-i2-5: the held state of a run from a listing's `snapshot` section (operator surface): RUN_NOT_FOUND when the
 * custodian holds no run record; a snapshot not in the form this engine reads refuses (fail closed). */
export function heldStateOfListing(listing: Pick<UserRecordListing, "snapshot">, repositoryRoot: string, runId: string): StateRecord {
  const s = listing.snapshot;
  if (s === null || s === undefined) throw new DomainError("RUN_NOT_FOUND", `the custodian holds no run record of ${runId} for the repository ${repositoryRoot}`);
  if (s["schema"] !== "arl.derivation-snapshot.v2" || typeof s["run"] !== "object" || s["run"] === null || typeof s["user"] !== "object" || s["user"] === null) {
    throw new DomainError("CUSTODIAN_UNAVAILABLE", "the custodian's run snapshot is not in a form this engine reads; nothing was done");
  }
  return { ...heldState(s as unknown as DerivationSnapshot), run_id: runId };
}

/** The state the derivation reads, rebuilt from the snapshot's held records only (texts empty: never held, never read). */
export function heldState(s: DerivationSnapshot): StateRecord {
  const run = s.run;
  const epoch = run?.evidenceEpoch ?? 1;
  const user = fromListing({ ...s.user, protected: true, loop: s.loop ? { record: { status: s.loop.status } } : null, run: null } as unknown as UserRecordListing);
  const check_executions = (run?.checkExecutions ?? []).filter((e) => e.evidenceEpoch === epoch).map(executionOf).filter((e): e is CheckExecutionRecord => e !== null);
  return {
    schema_version: 1,
    run_id: "",
    state: run ? runStateOf(run) : "IDLE",
    revision: 0,
    created_at: "",
    updated_at: "",
    operations: (run?.operations ?? []).map((o) => ({ operation_id: o.operationId, kind: o.kind, status: opStatusOf(o.status), started_at: o.beganAt, ...(o.endedAt ? { ended_at: o.endedAt } : {}) })),
    findings: (run?.items ?? []).map(itemOf),
    implementer_responses: (run?.responses ?? []).map((r) => ({
      response_id: r.responseId,
      item_id: r.itemId,
      disposition: r.disposition,
      rationale: r.rationalePresent ? "(held)" : "",
      // The cited locations as comparison keys: equal keys are equal locations by the engine's own name rules.
      references: r.referenceKeys.map((k) => ({ path: k, start_line: null, end_line: null })),
      answers: { review_id: r.answers.reviewId ?? "", round: r.answers.round ?? 0, token: "", run_review_id: r.answers.runReviewId, run_round: r.answers.runRound, reviewer_reply_id: r.answers.reviewerReplyId },
      source: { source_id: r.sourceId, note: null },
      disclosure_ref: null,
      text_withheld: r.textWithheld,
      supersedes: r.supersedes,
      thread_id: r.threadId,
      recorded_by: { role: "implementer", channel: "mcp" },
      response_set_id: r.responseSetId,
      request_id: null,
      request_digest: "0".repeat(64),
      recorded_at: "",
    })),
    reviewer_replies: (run?.replies ?? []).map((r) => ({ reply_id: r.replyId, item_id: r.itemId, review_id: r.reviewId, round: r.round, stance: r.stance, reply: "", new_information: r.newInformation, answers: { response_id: r.answersResponseId }, assessment: r.assessment })),
    user_decisions: user.decisions,
    task_amendments: user.amendments,
    isolation_incidents: (run?.incidents ?? []).map((i) => ({ incident_id: i.incidentId, review_id: i.reviewId, operation_id: i.operationId, kind: i.kind, detail: "", at: "", source: "engine", recorded_by: "custodian" })),
    reviews: (run?.reviews ?? []).map((r) => reviewOf(r, epoch)),
    check_executions,
    counters: { reviews: run?.used.reviews ?? 0, check_executions: run?.used.checkExecutions ?? 0 },
    events: [],
  } as unknown as StateRecord;
}

// ---------------------------------------------------------------------------
// The derivation
// ---------------------------------------------------------------------------

/** The check inputs as they are now: the held configuration's state, the measured spec id and freshness digest, and —
 * unmeasurable — the environment the check's latest execution claimed. */
function currentInputs(st: StateRecord, evaluation: ReturnType<typeof heldEvaluation>, m: DerivationMeasurement, names: Iterable<string>): Map<string, CurrentCheckInputs> {
  const view = toView(evaluation);
  const measured = new Map(m.checks.map((c) => [c.name, c]));
  const out = new Map<string, CurrentCheckInputs>();
  for (const name of new Set(names)) {
    const c = evaluation.checks.get(name);
    if (!c) {
      out.set(name, { check: name, state: "removed", definitionDigest: null, checkSpecId: null, envDigest: null, freshnessDigest: null, executionInputId: null });
      continue;
    }
    if (!view.approved.has(name) || !c.definition || !c.digest) {
      out.set(name, { check: name, state: "unapproved", definitionDigest: c.digest, checkSpecId: null, envDigest: null, freshnessDigest: null, executionInputId: null });
      continue;
    }
    const mc = measured.get(name);
    const envDigest = [...st.check_executions].reverse().find((e) => e.check === name && e.status !== "skipped")?.env_digest ?? null;
    const specId = mc?.checkSpecId ?? null;
    const freshness = mc?.freshnessDigest ?? null;
    out.set(name, {
      check: name,
      state: "runnable",
      definitionDigest: c.digest,
      checkSpecId: specId,
      envDigest,
      freshnessDigest: freshness,
      executionInputId: specId && envDigest && freshness ? computeExecutionInputId({ checkSpecId: specId, envDigest, freshnessDigest: freshness }) : null,
    });
  }
  return out;
}

/** The checks status against `sourceId` (the engine's evaluateChecksStatus, over held records and measured inputs). */
function checksStatusFor(st: StateRecord, s: DerivationSnapshot, evaluation: ReturnType<typeof heldEvaluation>, m: DerivationMeasurement, sourceId: string | null): ChecksStatus {
  const view = toView(evaluation);
  const requirements = effectiveRequirements(s.runFloor, view);
  const names = new Set<string>([...requirements.map((r) => r.check), ...st.check_executions.map((e) => e.check)]);
  const current = currentInputs(st, evaluation, m, names);
  const floor = evaluateFloor(view.floorConfigured || (s.runFloor?.no_required_checks ?? false), view.noRequiredChecks || (s.runFloor?.no_required_checks ?? false), requirements, st.check_executions, sourceId, current);
  const required = new Set(requirements.map((r) => r.check));
  const optional: CheckStatusView[] = [...names]
    .filter((n) => !required.has(n))
    .map((n) => ({ ...checkStatus(n, st.check_executions, sourceId, current.get(n)), required: false, required_by: [], definition_changed_since_floor: false }));
  return { floor, checks: [...floor.checks, ...optional], conditions: deriveCheckConditions(floor, optional), limitations: [], trusted_status: view.status };
}

/** A completed review's currency now (the engine's freshnessNow rule over held facts). */
function reviewFreshness(st: StateRecord, s: DerivationSnapshot, evaluation: ReturnType<typeof heldEvaluation>, m: DerivationMeasurement, r: ReviewRecord, intact: boolean): { current: boolean; stale_reasons: string[] } {
  const reasons: string[] = [];
  if (!r.capture_stable) reasons.push("source_changed_during_capture");
  if (!intact) reasons.push("export_changed_since_review");
  const source = m.stable && m.sourceId === r.source_id;
  if (!source) reasons.push("source_changed_since_review");
  const evidence = evidenceOf(checksStatusFor(st, s, evaluation, m, r.source_id), st).digest === r.check_evidence_digest;
  if (!evidence) reasons.push("check_evidence_changed_since_review");
  return { current: reasons.length === 0 && source && evidence, stale_reasons: reasons };
}

/** The protected derivation of `s` with the custodian's fresh measurement `m` (§5.1 step 2). */
export function protectedDerive(s: DerivationSnapshot, m: DerivationMeasurement): ProtectedDerivation {
  const st = heldState(s);
  const evaluation = heldEvaluation(s.config, s.repositoryRoot, m.rootCommit);
  const fresh = m.stable ? m.sourceId : null;
  const checks = checksStatusFor(st, s, evaluation, m, fresh);
  const f = checks.floor;
  const floor = { configured: f.configured, satisfied_for_current_source: f.satisfied_for_current_source, missing: f.missing, stale: f.stale, failed: [...f.failed, ...f.timed_out], removed: f.removed, unapproved: f.unapproved };

  // The latest accepted review and its currency (an export the custodian published and found unchanged is intact).
  const heldById = new Map((s.run?.reviews ?? []).map((r) => [r.reviewId, r]));
  const current = [...st.reviews].reverse().find((r) => r.accepted === true) ?? null;
  const freshness = current && current.status === "completed" ? reviewFreshness(st, s, evaluation, m, current, heldById.get(current.review_id)?.exportIntact === true) : null;

  const d = reportDiscussion(st, fresh, fresh !== null ? evidenceOf(checks, st).resultsDigest : null, (p) => p);
  const threads = allThreadReports(d);
  const active = st.operations.find((o) => o.status === "running") ?? null;
  const input: CompletionInput = {
    run_state: st.state,
    active_operation: active ? { kind: active.kind, operation_id: active.operation_id } : null,
    current_source_id: fresh,
    floor,
    latest_accepted_review: current
      ? { review_id: current.review_id, round: current.round, freshness, presented_amendments: (current.amendments?.presented ?? []).map((p) => p.amendment_id), withheld_amendments: (current.amendments?.withheld ?? []).map((w) => w.amendment_id) }
      : null,
    amendments: d.view.ix.amendments,
    incidents: st.isolation_incidents,
    threads,
    limitations: [],
  };
  const completion = deriveCompletion(input);

  const loop = s.loop;
  const ack = loop ? (loop.resumedAt && loop.resumedAt > loop.startedAt ? loop.resumedAt : loop.startedAt) : "1970-01-01T00:00:00.000Z";
  const facts: RoutingFacts = {
    run_state: input.run_state,
    active_operation: input.active_operation,
    operations: st.operations.map((o): OperationFact => ({ kind: o.kind, operation_id: o.operation_id, status: o.status, started_at: o.started_at, ended_at: o.ended_at })),
    acknowledged_before: ack,
    // Phase 4 Increment 2 (§3.2, N4-11): a proposal awaiting the owner's confirmation is not progress.
    pending_fix_proposals: st.operations.filter((o) => o.kind === "fix" && o.status === "proposed").length,
    // Phase 4 Increment 3 (§3.2, §3.6.4): a confirmed fix awaits its application; an interrupted application is reconciled first.
    confirmed_fix_proposals: st.operations.filter((o) => o.kind === "fix" && o.status === "confirmed").length,
    unreconciled_applications: st.operations.filter((o) => o.kind === "apply" && o.status === "apply_interrupted").length,
    completion: { state: completion.state, counts: completion.counts, blockers: completion.blockers },
    budgets: {
      reviews: { used: s.run?.used.reviews ?? 0, limit: s.run?.limits.maxReviews ?? 0 },
      check_executions: { used: s.run?.used.checkExecutions ?? 0, limit: s.run?.limits.maxCheckExecutions ?? 0 },
    },
  };
  const route: NextAction = routeFromEngine(facts);

  return {
    schema: PROTECTED_DERIVATION_SCHEMA,
    completion: { state: completion.state, ready: completion.ready, blockers: completion.blockers.map((b) => ({ category: b.category, code: b.code })), counts: completion.counts },
    route: { code: route.code, kind: route.kind, reason: route.reason, ...(route.pause ? { pause: route.pause } : {}), ...(route.end ? { end: route.end } : {}) },
    floor,
    currentSourceId: fresh,
    progressFingerprint: progressFingerprint(s, st, fresh, checks, d.view.ix.amendments.effective.map((a) => a.amendment_id), completion),
    inputDigest: sha256OfCanonicalJson({ schema: "arl.derivation-input.v2", snapshot: s, measured: m }),
  };
}

/**
 * §5.3: the progress fingerprint — WORK FACTS ONLY: the measured source; per required and planned check the latest held
 * execution's (check, executionInputId, status); the latest accepted review's (reviewInputId, verdict); per item
 * (itemId, status, triage) and its latest response disposition; the effective user decisions and amendments by id and
 * kind; the completion state with its sorted blocker codes. Counters, budgets, deadlines, timestamps, revisions,
 * epochs and other ids do not move it, nor do attempts that recorded nothing.
 */
function progressFingerprint(s: DerivationSnapshot, st: StateRecord, source: string | null, checks: ChecksStatus, effectiveAmendments: readonly string[], completion: CompletionReport): string {
  const planned = new Set<string>();
  for (const o of s.run?.operations ?? []) for (const c of o.planned) planned.add(c);
  for (const v of checks.floor.checks) planned.add(v.check);
  const latest = [...planned].sort().map((c) => {
    const e = [...st.check_executions].reverse().find((x) => x.check === c);
    return [c, e?.execution_input_id ?? null, e?.status ?? null];
  });
  const accepted = [...st.reviews].reverse().find((r) => r.accepted === true) ?? null;
  const lastResponse = new Map<string, string>();
  for (const r of st.implementer_responses) lastResponse.set(r.item_id, r.disposition);
  const byId = (a: [string, ...unknown[]], b: [string, ...unknown[]]) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  return sha256OfCanonicalJson({
    schema: PROGRESS_FINGERPRINT_SCHEMA,
    source,
    checks: latest,
    review: accepted ? [accepted.review_input_id, accepted.verdict] : null,
    items: st.findings.map((i): [string, string, string] => [i.id, i.status, i.triage]).sort(byId),
    responses: [...lastResponse.entries()].sort(byId),
    decisions: (st.user_decisions ?? []).map((u): [string, string] => [u.decision_id, u.kind]).sort(byId),
    amendments: [...effectiveAmendments].sort().map((id) => [id, (st.task_amendments ?? []).find((a) => a.amendment_id === id)?.kind ?? null]),
    completion: [completion.state, [...new Set(completion.blockers.map((b) => b.code))].sort()],
  });
}
