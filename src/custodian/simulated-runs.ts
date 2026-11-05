// The simulated custodian's run records (P3.4C-3): a faithful TypeScript re-implementation of the custodian's
// custodian/…/Ledger/RunRequest.cs, GrantLedger.Runs.cs and RunLifecycle.cs, for the in-process
// SimulatedCustodianTransport (a test stand-in: only test code constructs it, never configuration). Both are held to
// one observable behaviour by the shared corpus test/fixtures/run-transition-corpus.json, which the TypeScript
// contract test runs here and the custodian's `self-test-run-corpus` runs against the real ledger.
//
// The custodian computes every run transition from the stored record and the request's validated fields; a client
// never sets a status, a revision, an operation id, a round, acceptance, an item's status or an assessment's effect.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { join } from "node:path";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { LIVE_STATUSES, SimLoopInvalid, SimLoopRefusal, deriveEnd, type SimClientCheck, type SimLoop } from "./simulated-loops.js";
import { currentOf, currentRuntime, isolationBasisProblem, requireFixBasis, requireIsolationBasis, requireUsableConfig, reviewBasisProblem, versionText, type SimConfigFile, type SimOperationPin } from "./simulated-config.js";
import {
  SIM_FIX_LIMITS, decodeStrictBase64, fixBoundaryDigest, fixBoundaryProblem, fixProposalDigest, fixTreeDigest, validateFixSubmission,
  type SimFixBaselineRead, type SimFixBoundary, type SimFixCanonicalChange, type SimFixSubmittedChange,
} from "./simulated-fix.js";
import { renderProposal, type SimRenderChange, type SimRendering } from "./simulated-render.js";
import { checkWorkload, measuredExecution, measurementReason, measurementRecord, recordUnmeasuredPending, skippedExecution, type SimCheckTicket, type SimMeasureOutcome } from "./simulated-derivation.js";

// ---------------------------------------------------------------------------
// Caps (CustodianConstants.cs, contract §2.3)
// ---------------------------------------------------------------------------

export const SIM_RUN_LIMITS = Object.freeze({
  maxReviewsPerRun: 20,
  maxCheckExecutionsPerRun: 100,
  maxAllExecutionsPerRun: 200,
  maxResponsesPerCall: 50,
  maxResponsesPerItem: 20,
  maxResponsesPerRun: 1000,
  maxNewItemsPerReview: 100,
  maxItemsPerRun: 500,
  maxRepliesPerRun: 1000,
  maxIncidentsPerRun: 200,
  maxRunEvents: 1024,
  maxImplementerProjectionBytes: 3 * 1024 * 1024,
});

export const RUN_KINDS = ["open", "op_begin", "record_execution", "op_finish", "recover", "respond", "end", "apply_reconcile"] as const;

// ---------------------------------------------------------------------------
// The record (RunRecords.cs; same field names as the custodian's JSON)
// ---------------------------------------------------------------------------

export interface SimWriter {
  pid: number;
  startedAtMs: number;
  imageName: string;
}

export interface SimRunOperation {
  operationId: string;
  seq: number;
  kind: "checks" | "review" | "fix" | "apply";
  status: string;
  beganAt: string;
  endedAt: string | null;
  writer: SimWriter;
  begin: Record<string, unknown>;
  outcome: Record<string, unknown> | null;
  /** P3.4C-4 (§4.3): the configuration the operation was begun under (custodian-assigned). */
  pin?: SimOperationPin | null;
  /** P3.4C-5 (§2.4): the measurement ticket of a review the custodian captures, or of a checks operation's start. */
  ticket?: string | null;
  /** P3.4C-5 Increment 3 (§4): a checks operation's latest custodian measurement (the next execution's start). */
  measured?: Record<string, unknown> | null;
  /** P3.4C-5 Increment 3 (§4): the execution whose end the custodian is measuring (its ticket and the engine's claim). */
  pending?: Record<string, unknown> | null;
}

export interface SimRunReview {
  reviewId: string;
  operationId: string;
  round: number;
  begin: Record<string, unknown>;
  outcome: Record<string, unknown> | null;
  accepted: boolean | null;
  notAcceptedReasons: string[];
  itemIds: string[];
  incidentIds: string[];
  evidenceEpoch: number;
}

export interface SimRunItemAssessment {
  reviewId: string;
  round: number;
  sourceId: string;
  assessment: string;
  effect: string;
}

export interface SimRunItem {
  itemId: string;
  itemKind: string;
  reviewId: string;
  round: number;
  sourceId: string;
  triage: string;
  severity: string | null;
  claimType: string | null;
  category: string | null;
  impacts: string[];
  confidence: string | null;
  status: string;
  supersededBy: string | null;
  supersedes: string[];
  restates: string[];
  relatedPriorId: string | null;
  relatedFindingId: string | null;
  assessments: SimRunItemAssessment[];
  itemRevision: number;
  createdAt: string;
}

export interface SimRunIncident {
  incidentId: string;
  kind: string;
  operationId: string;
  reviewId: string | null;
  detail: string;
  at: string;
  source: "engine" | "custodian";
}

export interface SimRunEvent {
  seq: number;
  kind: string;
  requestId: string;
  caller: string;
  clientPid: number | null;
  requestDigest: string;
  fromStatus: string;
  toStatus: string;
  at: string;
  result: Record<string, unknown> | null;
}

export interface SimRun {
  repoKey: string;
  runId: string;
  runRevision: number;
  openedAt: string;
  requestId: string;
  evidenceEpoch: number;
  declaration: { runJsonDigest: string; budgets: { maxReviews: number; maxCheckExecutions: number; maxFixes?: number }; baseline: { sourceId: string; digest: string } | null };
  status: string;
  ended: { status: string; reason: string; at: string; by: string } | null;
  operations: SimRunOperation[];
  checkExecutions: Record<string, unknown>[];
  reviews: SimRunReview[];
  items: SimRunItem[];
  replies: Record<string, unknown>[];
  responses: Record<string, unknown>[];
  incidents: SimRunIncident[];
  events: SimRunEvent[];
  lastRecoveryId?: string | null;
  /** P3.4C-4 (§3.3 open): the repository configuration record the run was opened under. */
  openedConfig?: { configRevision: number; configDigest: string } | null;
}

/** stopped and closed are terminal; so is any status the custodian does not know (RunStatuses.IsTerminal). */
const OPEN_STATUSES: ReadonlySet<string> = new Set(["idle", "checking", "reviewing", "fixing", "applying"]);
export const isRunTerminal = (r: SimRun): boolean => !OPEN_STATUSES.has(r.status);
/** P3.4C-5: an operation is active while running, or while the custodian captures (measuring) or has captured its review. */
export const isActiveOperation = (status: string): boolean => status === "running" || status === "measuring" || status === "captured";
const runningOperation = (r: SimRun): SimRunOperation | undefined => [...r.operations].reverse().find((o) => isActiveOperation(o.status));

// ---------------------------------------------------------------------------
// Enums (RunEnums)
// ---------------------------------------------------------------------------

const set = (...v: string[]): ReadonlySet<string> => new Set(v);
const E = {
  operationKinds: set("checks", "review", "fix", "apply"),
  // Phase 4 Increment 3: an application's finish, the state reported per file, a reconciliation's choice and observation.
  applyOutcome: set("applied", "apply_failed"),
  applyFileStates: set("postimage", "preimage", "absent", "other", "unknown"),
  reconcileChoices: set("restore", "leave"),
  reconcileObserved: set("none", "partial", "all_at_postimage"),
  // Phase 4 Increment 2: a fix's finish, as the engine reports it (the custodian decides proposed/rejected itself).
  fixOutcome: set("completed", "empty", "rejected", "failed", "timed_out", "cancelled"),
  fixChangeKinds: set("add", "modify", "delete"),
  endStatuses: set("stopped", "closed"),
  checkOutcome: set("completed", "cancelled", "error"),
  reviewOutcome: set("completed", "failed", "timed_out", "cancelled", "invalid_output"),
  execStatuses: set("passed", "failed", "error", "timed_out", "cancelled", "skipped"),
  skipReasons: set("operation_cancelled", "definition_removed", "definition_changed", "approval_invalid"),
  newItemStatuses: set("open", "informational"),
  isolation: set("S1", "S2"),
  depths: set("focused", "standard", "deep"),
  verdicts: set("APPROVE", "CHANGES_REQUIRED", "INCONCLUSIVE"),
  itemKinds: set("finding", "question"),
  triages: set("established_defect", "serious_concern", "minor_concern", "note", "blocking_question", "question"),
  openTriages: set("established_defect", "serious_concern", "blocking_question"),
  severities: set("critical", "high", "medium", "low"),
  claimTypes: set("defect", "risk", "suggestion"),
  categories: set("correctness", "security", "reliability", "performance", "compatibility", "maintainability", "testing", "documentation", "style", "architecture"),
  impacts: set("correctness", "security", "reliability", "performance", "compatibility", "maintainability", "acceptance_criteria"),
  confidences: set("high", "medium", "low"),
  assessmentEntries: set("still_present", "apparently_resolved", "no_longer_assessable", "superseded", "not_assessed", "not_presented"),
  replyAssessments: set("still_present", "apparently_resolved", "no_longer_assessable", "superseded", "not_assessed"),
  stances: set("maintain", "withdraw", "revise", "need_information"),
  newInformation: set("yes", "no", "not_applicable"),
  dispositions: set("accepted", "disputed", "deferred", "fix_claimed"),
  incidentKinds: set("isolation_violation_file_change", "isolation_violation_mcp_tool_call", "isolation_violation_web_search", "export_modified_during_review", "possible_surviving_sandboxed_commands", "cancellation_unconfirmed", "termination_unconfirmed", "isolation_reduced", "measurement_interrupted"),
  engineIncidents: set("isolation_violation_file_change", "isolation_violation_mcp_tool_call", "isolation_violation_web_search", "export_modified_during_review", "possible_surviving_sandboxed_commands", "cancellation_unconfirmed", "termination_unconfirmed"),
  invalidating: set("termination_unconfirmed", "isolation_violation_file_change", "isolation_violation_mcp_tool_call", "isolation_violation_web_search", "export_modified_during_review", "cancellation_unconfirmed"),
  recoverIncidents: set("possible_surviving_sandboxed_commands", "termination_unconfirmed"),
};
const FINDING_TRIAGES = set("established_defect", "serious_concern", "minor_concern", "note");
const QUESTION_TRIAGES = set("blocking_question", "question");
const RANK: Readonly<Record<string, number>> = { established_defect: 3, serious_concern: 2, blocking_question: 2, minor_concern: 1, question: 0, note: 0 };

// ---------------------------------------------------------------------------
// Request validation (RunRequest.cs: strict per-kind allowlists)
// ---------------------------------------------------------------------------

type Rule = (v: unknown, path: string) => unknown;
interface Shape {
  rules: Readonly<Record<string, Rule>>;
  optional?: readonly string[];
}

const invalid = (m: string): SimLoopInvalid => new SimLoopInvalid(m);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function apply(shape: Shape, v: unknown, path: string): Record<string, unknown> {
  if (!isObj(v)) throw invalid(`${path} must be an object`);
  if (Object.keys(v).some((k) => !(k in shape.rules))) throw new SimLoopRefusal("MALFORMED_REQUEST", `unexpected key in ${path} (no field conveys authority; unknown fields are refused, not ignored)`);
  const out: Record<string, unknown> = {};
  for (const [k, rule] of Object.entries(shape.rules)) {
    if (!(k in v)) {
      if (shape.optional?.includes(k)) continue;
      throw invalid(`${path}.${k} is required`);
    }
    out[k] = rule(v[k], `${path}.${k}`);
  }
  return out;
}

const str = (v: unknown, p: string): string => {
  if (typeof v !== "string") throw invalid(`${p} must be a string`);
  return v;
};
const token = (max: number): Rule => (v, p) => {
  const s = str(v, p);
  if (s.length < 1 || s.length > max || s === "." || s === ".." || !/^[A-Za-z0-9_-]+$/.test(s)) throw invalid(`${p} must be 1..${max} chars of [A-Za-z0-9-_]`);
  return s;
};
const orNull = (r: Rule): Rule => (v, p) => (v === null ? null : r(v, p));
const Id = token(128);
const IdOrNull = orNull(Id);
const OpId = token(64);
const Hex64: Rule = (v, p) => {
  const s = str(v, p);
  if (!/^[0-9a-f]{64}$/.test(s)) throw invalid(`${p} must be 64 lowercase hex characters`);
  return s;
};
const Hex64OrNull = orNull(Hex64);
const Bool: Rule = (v, p) => {
  if (typeof v !== "boolean") throw invalid(`${p} must be a boolean`);
  return v;
};
const CheckName: Rule = (v, p) => {
  const s = str(v, p);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(s)) throw invalid(`${p} must be a check name (1-64 of [A-Za-z0-9._-], starting alphanumeric)`);
  return s;
};
const Iso: Rule = (v, p) => {
  const s = str(v, p);
  if (s.length > 40 || Number.isNaN(Date.parse(s))) throw invalid(`${p} must be an ISO 8601 timestamp`);
  return s;
};
const IsoOrNull = orNull(Iso);
const Code: Rule = (v, p) => {
  const s = str(v, p);
  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(s)) throw invalid(`${p} must be a code of 1-64 of [A-Za-z0-9_.:-]`);
  return s;
};
const Int = (min: number, max: number): Rule => (v, p) => {
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw invalid(`${p} must be an integer from ${min} to ${max}`);
  return v;
};
const IntOrNull = (min: number, max: number): Rule => orNull(Int(min, max));
const Text = (max: number): Rule => (v, p) => {
  const s = str(v, p);
  if (s.length > max) throw invalid(`${p} must be at most ${max} characters`);
  return s.replace(/\p{Cc}/gu, " ");
};
const TextOrNull = (max: number): Rule => orNull(Text(max));
const Enum = (allowed: ReadonlySet<string>): Rule => (v, p) => {
  const s = str(v, p);
  if (!allowed.has(s)) throw invalid(`${p} must be one of: ${[...allowed].sort().join(", ")}`);
  return s;
};
const EnumOrNull = (allowed: ReadonlySet<string>): Rule => orNull(Enum(allowed));
const Obj = (shape: Shape): Rule => (v, p) => apply(shape, v, p);
const ObjOrNull = (shape: Shape): Rule => orNull(Obj(shape));
const Arr = (element: Rule, max: number, unique?: { by?: string; value?: boolean }): Rule => (v, p) => {
  if (!Array.isArray(v)) throw invalid(`${p} must be an array`);
  if (v.length > max) throw invalid(`${p} must have at most ${max} entries`);
  const seen = new Set<string>();
  return v.map((x, i) => {
    const e = element(x, `${p}[${i}]`);
    const key = unique?.by ? String((e as Record<string, unknown>)[unique.by]) : unique?.value ? JSON.stringify(e) : null;
    if (key !== null) {
      if (seen.has(key)) throw invalid(`${p} has a duplicate entry (${unique?.by ?? "value"})`);
      seen.add(key);
    }
    return e;
  });
};
const shape = (rules: Record<string, Rule>, optional?: string[]): Shape => ({ rules, ...(optional ? { optional } : {}) });

const OPEN = shape({
  runJsonDigest: Hex64,
  // Phase 4 Increment 2: maxFixes (optional; absent: no delegated fix is budgeted for the run).
  budgets: Obj(shape({ maxReviews: Int(0, 10_000), maxCheckExecutions: Int(0, 100_000), maxFixes: Int(0, 100) }, ["maxFixes"])),
  baseline: ObjOrNull(shape({ sourceId: Hex64, digest: Hex64 })),
});
/** P3.4C-5 Increment 3 (§4): the absolute path of the executable the session resolved for a planned check (an engine claim;
 * the custodian measures its stat). */
const ExecutablePath: Rule = (v, p) => {
  if (v === null) return null;
  const s = str(v, p);
  const absolute = /^[A-Za-z]:[\\/]/.test(s) || s.startsWith("\\\\") || s.startsWith("/");
  if (s.length > 1024 || !absolute || /\p{Cc}/u.test(s) || s.includes('"')) throw invalid(`${p} must be an absolute path (at most 1024 characters, no control character or quote)`);
  return s;
};
const CHECKS_BEGIN = shape({
  operationKind: Enum(E.operationKinds),
  planned: Arr(Obj(shape({ check: CheckName, checkSpecId: Hex64OrNull, definitionDigest: Hex64OrNull, required: Bool, executable: ExecutablePath }, ["executable"])), 50, { by: "check" }),
  inputIdentity: Hex64OrNull,
});
/** P3.4C-5 (§3.1): the capture claims of the P3.4C-3 shape, ignored (and named) when a reservation still sends them. */
export const IGNORED_CAPTURE_CLAIMS = ["sourceId", "reviewInputId", "captureId", "captureStable", "captureDigest", "exportDigest", "manifestDigest", "promptDigest"] as const;
/** The capture target a reservation names (RunFields.Target): uncommitted or base_ref; since_baseline is refused. */
const Target: Rule = (v, p) => {
  if (!isObj(v)) throw invalid(`${p} must be an object`);
  const kind = v["kind"];
  if (typeof kind !== "string") throw invalid(`${p}.kind must be a string`);
  if (kind === "since_baseline") throw refuse("INVALID_ARGUMENT", "a protected review of target since_baseline is not supported by the custodian's capture yet; use target uncommitted or base_ref");
  if (kind === "uncommitted") {
    if (Object.keys(v).length !== 1) throw refuse("MALFORMED_REQUEST", `unexpected key in ${p}`);
    return { kind: "uncommitted" };
  }
  if (kind === "base_ref") {
    if (Object.keys(v).length !== 2 || !("ref" in v)) throw refuse("MALFORMED_REQUEST", `unexpected or missing key in ${p}`);
    const r = str(v["ref"], `${p}.ref`);
    if (r.length === 0 || r.length > 256 || r.startsWith("-") || r.includes("..") || !/^[A-Za-z0-9._/@{}~^-]+$/.test(r)) throw invalid(`${p}.ref must be a plain git ref (no options, ranges or paths)`);
    return { kind: "base_ref", ref: r };
  }
  throw invalid(`${p}.kind must be uncommitted or base_ref`);
};
const OFFERED_ITEM = shape({ itemId: Id, responseIds: Arr(Id, 20, { value: true }), replyIds: Arr(Id, 20, { value: true }) });
const OFFERED_AMENDMENT = shape({ amendmentId: Id, disclosureDigest: Hex64OrNull });
const REVIEW_BEGIN = shape({
  operationKind: Enum(E.operationKinds),
  reviewId: Id,
  selectionSourceId: Hex64,
  target: Target,
  checkExecutionIds: Arr(Id, 200, { value: true }),
  checkEvidenceDigest: Hex64,
  checkResultsDigest: Hex64,
  discussion: Obj(shape({ offered: Arr(Obj(OFFERED_ITEM), 500, { by: "itemId" }) })),
  amendments: Obj(shape({ offered: Arr(Obj(OFFERED_AMENDMENT), 50, { by: "amendmentId" }) })),
  isolation: Obj(shape({ mode: Enum(E.isolation), profileDigest: Hex64, selftestId: IdOrNull, acceptanceId: IdOrNull, backend: Code, codexVersion: versionText })),
  captureRulesDigest: Hex64,
  codexSha256: Hex64,
  depth: Enum(E.depths),
  focusDigest: Hex64OrNull,
  versionsDigest: Hex64,
  sourceId: Hex64, reviewInputId: Hex64, captureId: Id, captureStable: Bool, captureDigest: Hex64, exportDigest: Hex64, manifestDigest: Hex64, promptDigest: Hex64,
}, [...IGNORED_CAPTURE_CLAIMS]);
// ---- Phase 4 Increment 2: a delegated fix (RunRequest.cs FixBeginShape / FixOutcomeShape) ----

/** A repository-relative path a boundary names (its length here; the portable-path rules in the boundary check). */
const FixPath: Rule = (v, p) => {
  const s = str(v, p);
  if (s.length < 1 || s.length > SIM_FIX_LIMITS.maxPathChars) throw invalid(`${p} must be 1 to ${SIM_FIX_LIMITS.maxPathChars} characters`);
  return s;
};
const FIX_BOUNDARY = shape({
  permittedFiles: Arr(FixPath, SIM_FIX_LIMITS.maxPermittedFiles, { value: true }),
  permittedDirs: Arr(FixPath, SIM_FIX_LIMITS.maxPermittedDirs, { value: true }),
  allowCreate: Bool,
  allowDelete: Bool,
  allowBinary: Bool,
  maxChangedFiles: Int(1, SIM_FIX_LIMITS.maxChangedFiles),
  maxFileBytes: Int(1, SIM_FIX_LIMITS.maxFileBytes),
  maxTotalBytes: Int(1, SIM_FIX_LIMITS.maxTotalBytes),
  timeLimitSeconds: Int(SIM_FIX_LIMITS.minTimeLimitSeconds, SIM_FIX_LIMITS.maxTimeLimitSeconds),
  proposalLifetimeSeconds: Int(SIM_FIX_LIMITS.minLifetimeSeconds, SIM_FIX_LIMITS.maxLifetimeSeconds),
});
const FIX_MODE: Rule = (v, p) => {
  if (str(v, p) !== "FIX") throw invalid(`${p} must be one of: FIX`);
  return "FIX";
};
const FIX_BEGIN = shape({
  operationKind: Enum(E.operationKinds),
  fixId: Id,
  taskDigest: Hex64,
  baselineReviewId: Id,
  boundary: (v, p) => {
    const b = apply(FIX_BOUNDARY, v, p) as unknown as SimFixBoundary;
    const problem = fixBoundaryProblem(b);
    if (problem) throw invalid(`${p}: ${problem}`);
    return b;
  },
  isolation: Obj(shape({ mode: FIX_MODE, profileDigest: Hex64, selftestId: Id, backend: Code, codexVersion: versionText })),
  codexSha256: Hex64,
});
/** A submitted postimage: strict base64 of at most the custodian's per-file cap (decoded and judged in the hold). */
const Base64OrNull: Rule = (v, p) => {
  if (v === null) return null;
  const s = str(v, p);
  if (s.length > Math.ceil(SIM_FIX_LIMITS.maxFileBytes / 3) * 4 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw invalid(`${p} must be base64 of at most ${SIM_FIX_LIMITS.maxFileBytes} bytes`);
  return s;
};
/** A submitted path is judged by the custodian in the hold (a bad one is a violation of the proposal, not a malformed request). */
const SubmittedPath: Rule = (v, p) => {
  const s = str(v, p);
  if (s.length > SIM_FIX_LIMITS.maxPathChars * 2) throw invalid(`${p} must be at most ${SIM_FIX_LIMITS.maxPathChars * 2} characters`);
  return s;
};
const FIX_CHANGE = shape({ path: SubmittedPath, kind: Enum(E.fixChangeKinds), executable: Bool, content: Base64OrNull });
const FIX_OUTCOME = shape({
  status: Enum(E.fixOutcome),
  scan: ObjOrNull(shape({ complete: Bool, files: Int(0, 1_000_000), anomalies: Int(0, 1_000_000), violations: Int(0, 1_000_000) })),
  detail: TextOrNull(500),
  changes: Arr(Obj(FIX_CHANGE), SIM_FIX_LIMITS.maxChangedFiles + 1),
});

// ---- Phase 4 Increment 3: the application of a confirmed fix (RunRequest.cs ApplyBeginShape / ApplyOutcomeShape) ----

/** An application's op_begin: the fix whose confirmed proposal is applied, and its digest — never a confirmation. */
const APPLY_BEGIN = shape({ operationKind: Enum(E.operationKinds), fixOperationId: OpId, proposalDigest: Hex64 });
const APPLY_FILE = shape({ path: SubmittedPath, state: Enum(E.applyFileStates) });
const APPLY_OUTCOME = shape({ status: Enum(E.applyOutcome), files: Arr(Obj(APPLY_FILE), SIM_FIX_LIMITS.maxChangedFiles, { by: "path" }), detail: TextOrNull(500) });
const APPLY_RECONCILE = shape({
  operationId: OpId, choice: Enum(E.reconcileChoices), observed: Enum(E.reconcileObserved), files: Arr(Obj(APPLY_FILE), SIM_FIX_LIMITS.maxChangedFiles, { by: "path" }), detail: TextOrNull(500),
});

const EXECUTION = shape({
  executionId: Id,
  check: CheckName,
  definitionDigest: Hex64OrNull,
  checkSpecId: Hex64OrNull,
  executionInputId: Hex64OrNull,
  envDigest: Hex64OrNull,
  freshnessDigest: Hex64OrNull,
  status: Enum(E.execStatuses),
  skipReason: EnumOrNull(E.skipReasons),
  exitCode: IntOrNull(-0x80000000, 0x7fffffff),
  timedOut: Bool,
  cancelled: Bool,
  startedAt: IsoOrNull,
  endedAt: IsoOrNull,
  durationMs: IntOrNull(0, 0x7fffffff),
  sourceIdAtStart: Hex64OrNull,
  sourceIdAtEnd: Hex64OrNull,
  sourceStable: Bool,
  stdoutDigest: Hex64OrNull,
  stderrDigest: Hex64OrNull,
  resultDigest: Hex64OrNull,
  limitations: Arr(Obj(shape({ code: Code, detail: Text(500) })), 20),
});
const RECORD_EXECUTION = shape({ operationId: OpId, execution: Obj(EXECUTION) });
const DELIVERY = shape({ responseId: Id, itemId: Id, replySought: Bool, basis: Arr(Code, 16, { value: true }) });
const PRESENTED = shape({
  discussion: Obj(shape({ digest: Hex64, delivered: Arr(Obj(OFFERED_ITEM), 500, { by: "itemId" }), notDeliveredCount: Int(0, 100_000), deliveries: Arr(Obj(DELIVERY), 1000, { by: "responseId" }) }, ["deliveries"])),
  amendments: Obj(shape({ digest: Hex64, presented: Arr(Obj(OFFERED_AMENDMENT), 50, { by: "amendmentId" }), withheld: Arr(Id, 50, { value: true }) })),
});
const OP_FINISH = shape({
  operationId: OpId,
  outcome: (v, p) => (isObj(v) ? structuredClone(v) : (() => { throw invalid(`${p} must be an object`); })()),
  promptDigest: Hex64OrNull,
  presented: ObjOrNull(PRESENTED),
}, ["promptDigest", "presented"]);
const CHECKS_OUTCOME = shape({ status: Enum(E.checkOutcome), error: TextOrNull(500) });
const NEW_ITEM = shape({
  itemId: Id,
  itemKind: Enum(E.itemKinds),
  triage: Enum(E.triages),
  severity: EnumOrNull(E.severities),
  claimType: EnumOrNull(E.claimTypes),
  category: EnumOrNull(E.categories),
  impacts: Arr(Enum(E.impacts), 14, { value: true }),
  confidence: EnumOrNull(E.confidences),
  status: Enum(E.newItemStatuses),
  relatedPriorId: IdOrNull,
  relatedFindingId: IdOrNull,
  restates: Arr(Id, 20, { value: true }),
});
const REPLY = shape({ replyId: Id, itemId: Id, stance: Enum(E.stances), newInformation: Enum(E.newInformation), answersResponseId: IdOrNull, assessment: EnumOrNull(E.replyAssessments) });
const DIGEST_OR_NULL = Hex64OrNull;
const REVIEW_OUTCOME = shape({
  status: Enum(E.reviewOutcome),
  outputValid: Bool,
  currentAtCompletion: Bool,
  verdict: EnumOrNull(E.verdicts),
  summaryDigest: Hex64OrNull,
  artifacts: Obj(shape({ rawOutput: DIGEST_OR_NULL, output: DIGEST_OR_NULL, items: DIGEST_OR_NULL, result: DIGEST_OR_NULL, events: DIGEST_OR_NULL, stderr: DIGEST_OR_NULL, lastMessage: DIGEST_OR_NULL })),
  newItems: Arr(Obj(NEW_ITEM), SIM_RUN_LIMITS.maxNewItemsPerReview, { by: "itemId" }),
  assessments: Arr(Obj(shape({ itemId: Id, assessment: Enum(E.assessmentEntries), supersededByItemId: IdOrNull })), SIM_RUN_LIMITS.maxItemsPerRun, { by: "itemId" }),
  replies: Arr(Obj(REPLY), SIM_RUN_LIMITS.maxRepliesPerRun, { by: "replyId" }),
  incidents: Arr(Obj(shape({ kind: Enum(E.engineIncidents), detail: Text(500) })), 50),
});
const RECOVER = shape({ operationId: OpId, incidents: Arr(Obj(shape({ kind: Enum(E.recoverIncidents), detail: Text(500) })), 10) });
const RESPONSE = shape({
  responseId: Id,
  itemId: Id,
  baseItemRevision: Int(1, 0x7fffffff),
  disposition: Enum(E.dispositions),
  textWithheld: Bool,
  answers: Obj(shape({ reviewId: IdOrNull, round: IntOrNull(1, 10_000), runReviewId: IdOrNull, runRound: IntOrNull(1, 10_000), reviewerReplyId: IdOrNull })),
  sourceId: Hex64OrNull,
  supersedes: IdOrNull,
  threadId: Id,
  // P3.4C-5 Increment 3 (§5.1): each cited location as a comparison key, and whether a rationale was given (claims).
  referenceKeys: Arr(Hex64, 20, { value: true }),
  rationalePresent: Bool,
}, ["referenceKeys", "rationalePresent"]);
const RESPOND = shape({ responseSetId: Id, disclosureDigest: Hex64OrNull, responses: Arr(Obj(RESPONSE), SIM_RUN_LIMITS.maxResponsesPerCall, { by: "responseId" }) });
const END = shape({ status: Enum(E.endStatuses), reason: Text(500) });

/** A validated run_transition request (RunRequest.cs). */
export interface SimRunRequest {
  runId: string;
  kind: string;
  requestId: string;
  digest: string;
  fields: Record<string, unknown>;
}

/** Validate a run_transition request in the custodian's order (CustodianCore.cs RunTransition, RunRequest.Parse): the
 * envelope's types, the run and request ids, the kind, the kind's fields, then the repository locator. */
export function parseRunRequest(args: Record<string, unknown>, requestId: string): SimRunRequest {
  const { runId, kind, fields } = args;
  if (typeof runId !== "string") throw invalid("'runId' must be a string");
  if (typeof kind !== "string") throw invalid("'kind' must be a string");
  if (!isObj(fields)) throw invalid("missing object 'fields'");
  token(128)(runId, "runId");
  token(128)(requestId, "request id");
  if (!(RUN_KINDS as readonly string[]).includes(kind)) throw invalid(`kind must be one of: ${[...RUN_KINDS].sort().join(", ")}`);
  const validated = validatedFields(kind, fields);
  if (typeof args["repositoryRoot"] !== "string") throw invalid("'repositoryRoot' must be a string");
  return { runId, kind, requestId, digest: sha256OfCanonicalJson({ kind, fields }), fields: validated };
}

function validatedFields(kind: string, fields: Record<string, unknown>): Record<string, unknown> {
  let validated: Record<string, unknown>;
  switch (kind) {
    case "open":
      validated = apply(OPEN, fields, "fields");
      break;
    case "op_begin": {
      const k = Enum(E.operationKinds)(fields["operationKind"], "fields.operationKind");
      validated = apply(k === "checks" ? CHECKS_BEGIN : k === "review" ? REVIEW_BEGIN : k === "apply" ? APPLY_BEGIN : FIX_BEGIN, fields, "fields");
      break;
    }
    case "record_execution":
      validated = apply(RECORD_EXECUTION, fields, "fields");
      break;
    case "op_finish":
      validated = apply(OP_FINISH, fields, "fields");
      break;
    case "recover":
      validated = apply(RECOVER, fields, "fields");
      break;
    case "respond": {
      validated = apply(RESPOND, fields, "fields");
      const responses = validated["responses"] as Record<string, unknown>[];
      if (responses.length === 0) throw invalid("fields.responses must have at least one response");
      if (new Set(responses.map((r) => r["itemId"])).size !== responses.length) throw invalid("fields.responses has more than one response for an item");
      break;
    }
    case "apply_reconcile":
      validated = apply(APPLY_RECONCILE, fields, "fields");
      break;
    default:
      validated = apply(END, fields, "fields");
  }
  return validated;
}

// ---------------------------------------------------------------------------
// The transition (GrantLedger.Runs.cs ApplyRunTransition)
// ---------------------------------------------------------------------------

export interface SimRunCaller {
  operator: boolean;
  clientPid: number | null;
  /** For op_begin and respond: the connected process checked against the run's BOUND process (null: no binding,
   * or it could not be checked). */
  client: SimClientCheck | null;
  /** The process that sent the request (the connected client's parent), as the custodian identifies it (null: it
   * could not be identified). */
  writer: SimWriter | null;
  /** For recover: is the operation's writer gone (null: the process table could not be read)? */
  writerGone: (w: SimWriter) => boolean | null;
}

/** The ledger state a run transition reads and writes (in one hold of the custodian's single lock). */
export interface SimRunStore {
  runs: Record<string, SimRun>;
  loops: SimLoop[];
  grants: { repoKey: string; revokedAt: string | null; expiresAt: string; loopsUsed: number; loopsTotal: number; suspendedAt?: string | null }[];
  /** The run's P3.4C-1 user-record amendments (for the op_begin cross-check). */
  amendmentsOf: (repoKey: string, runId: string) => { recordId: string; disclosureDigest: string | null }[];
  /** P3.4C-4: the custodian-held configuration, read in the same hold (config-records.json). */
  config: SimConfigFile;
  /** P3.4C-5: whether the custodian's capture helper is installed (without it every reservation is refused). */
  captureEnabled?: boolean;
  /** P3.4C-5: start a reserved capture (called after the reservation is written). */
  startCapture?: (t: SimCaptureTicket) => void;
  /** P3.4C-5: cancel a capture in progress. */
  cancelCapture?: (ticket: string | null | undefined) => void;
  /** P3.4C-5 (§3.1 step 7): the custodian's re-hash of a captured review's export, taken before the hold (op_finish). */
  rehash?: SimExportRehash | null;
  /** P3.4C-5 Increment 3: whether the custodian measures (a checks operation's start and executions; the derivation). */
  measureEnabled?: boolean;
  /** P3.4C-5 Increment 3: start a reserved check measurement (called after the reservation is written). */
  startCheckMeasurement?: (t: SimCheckTicket) => void;
  /** P3.4C-5 Increment 4: ticket directories retired in this hold, removed after it (GrantLedger._retired). */
  retired?: string[];
  /** P3.4C-5 Increment 4 (N5-8): refuse when the helper's group cannot read the request's repository. */
  requireRepositoryReadable?: () => void;
  /** Phase 4 Increment 2: the custodian's read of a fix's baseline capture, taken before the hold (op_begin and op_finish
   * of a fix; GrantLedger.Fix.cs ReadFixBaseline). */
  fixBaseline?: SimFixBaselineRead | null;
  /** Phase 4 Increment 2: the canonical proposal content the custodian holds in its private store, by proposalKey. */
  fixProposals?: Record<string, SimHeldProposal>;
  /** Phase 5 F-i2-5: the redaction evidence the custodian holds (GrantLedger.Evidence.cs), by evidenceKey. */
  evidence?: Record<string, string>;
  /** Phase 4 Increment 3: what an application's begin, finish or reconciliation read before the hold (ReadForApply). */
  applyPre?: SimApplyPre | null;
}

/** A proposal the custodian holds (its private store; FixProposalFile): the custodian-computed digest and the canonical
 * content it validated. Removed when the proposal is retired (expired, or its run ended). */
export interface SimHeldProposal {
  repoKey: string;
  runId: string;
  operationId: string;
  proposalDigest: string;
  changes: SimFixCanonicalChange[];
}

export const proposalKey = (repoKey: string, runId: string, operationId: string): string => [repoKey, runId, operationId].join("\u0000");

// ---------------------------------------------------------------------------
// P3.4C-5 Increment 4 (§3.2 retention; GrantLedger.Retention.cs)
// ---------------------------------------------------------------------------

/** A live run keeps the published exports of its latest captures only; older ones, and any older than the age bound,
 * are retired (CustodianConstants.MaxPublishedExportsPerRun / ExportRetention). */
export const SIM_EXPORT_RETENTION = { perRun: 2, maxAgeMs: 7 * 24 * 3600_000 };

const captureOf = (begin: Record<string, unknown>): Record<string, unknown> | null => {
  const c = begin["custodianCapture"];
  return c && typeof c === "object" && !Array.isArray(c) ? (c as Record<string, unknown>) : null;
};
const retiredCount = (run: SimRun): number => run.reviews.filter((r) => captureOf(r.begin)?.["retiredAt"] != null).length;

/** RetireExports: the run with every export the rules no longer keep marked retired, their directories queued in
 * `retired`; the same instance when nothing changes. A review still in flight keeps its export even on an ended run. */
export function retireExports(run: SimRun, nowMs: number, retired: string[] | undefined): SimRun {
  const live = run.reviews.filter((r) => { const c = captureOf(r.begin); return c !== null && c["retiredAt"] == null; });
  if (live.length === 0) return run;
  const expired = (r: SimRunReview): boolean => { const at = captureOf(r.begin)?.["capturedAt"]; return typeof at === "string" && nowMs - Date.parse(at) > SIM_EXPORT_RETENTION.maxAgeMs; };
  const keep = new Set<string>();
  for (const r of live) if (run.operations.find((o) => o.operationId === r.operationId)?.status === "captured") keep.add(r.reviewId);
  if (!isRunTerminal(run)) for (const r of live.slice(-SIM_EXPORT_RETENTION.perRun)) if (!expired(r)) keep.add(r.reviewId);
  // Phase 4 Increment 2 (§3.2 retention): a fix in flight, or a proposal not yet retired, keeps its baseline export.
  for (const id of fixBaselinesHeld(run)) keep.add(id);
  const why = new Map<string, string>();
  for (const r of live) if (!keep.has(r.reviewId)) why.set(r.operationId, isRunTerminal(run) ? "run_ended" : expired(r) ? "retention_age" : "retention_count");
  if (why.size === 0) return run;
  const mark = (begin: Record<string, unknown>, reason: string): Record<string, unknown> => {
    const b = structuredClone(begin);
    Object.assign(captureOf(b)!, { retiredAt: iso(nowMs), retiredReason: reason });
    return b;
  };
  for (const r of live) {
    const p = captureOf(r.begin)?.["exportPath"];
    if (why.has(r.operationId) && typeof p === "string") retired?.push(join(p, ".."));
  }
  return {
    ...run,
    reviews: run.reviews.map((r) => (why.has(r.operationId) ? { ...r, begin: mark(r.begin, why.get(r.operationId)!) } : r)),
    operations: run.operations.map((o) => (why.has(o.operationId) && captureOf(o.begin) ? { ...o, begin: mark(o.begin, why.get(o.operationId)!) } : o)),
  };
}

/** SweepExports (the hold part): every run's exports retired by the rules (an `export_retire` custodian event on each
 * run that changes); returns the directories the held, unretired captures reference. */
export function retentionSweep(store: SimRunStore, nowMs: number): { retired: number; referenced: Set<string>; proposalsRemoved: number } {
  let retired = 0;
  const referenced = new Set<string>();
  const proposals = new Set<string>();
  for (const [key, run] of Object.entries(store.runs)) {
    let next = retireExports(retireFixProposals(run, nowMs, store), nowMs, store.retired);
    if (next !== run) {
      const n = retiredCount(next) - retiredCount(run);
      const proposals = retiredProposals(next) - retiredProposals(run);
      retired += n;
      next = custodianEvent(next, run, "export_retire", `retention-${newId("r", retired)}`, { retired: n, ...(proposals > 0 ? { proposalsRetired: proposals } : {}) }, nowMs);
      store.runs[key] = next;
    }
    for (const r of next.reviews) {
      const c = captureOf(r.begin);
      if (c && c["retiredAt"] == null && typeof c["exportPath"] === "string") referenced.add(c["exportPath"]);
    }
    for (const k of referencedProposals(next)) proposals.add(k);
  }
  // Phase 4 Increment 2 (SweepOrphanProposals): held content no run references (a crash between its two writes) is removed.
  let proposalsRemoved = 0;
  for (const k of Object.keys(store.fixProposals ?? {})) {
    if (proposals.has(k)) continue;
    delete store.fixProposals![k];
    proposalsRemoved++;
  }
  return { retired, referenced, proposalsRemoved };
}

/** One reserved review capture (CaptureTicket). */
export interface SimCaptureTicket {
  ticket: string;
  repoKey: string;
  runId: string;
  operationId: string;
  target: Record<string, unknown>;
  runtimeId: string;
}

/** A capture the custodian published (PublishedCapture). */
export interface SimPublishedCapture {
  /** Phase 5 F-i2-5: the capture record's text, held as redaction evidence when the capture is committed. */
  recordText?: string;
  dir: string;
  exportPath: string;
  capturePath: string;
  sourceId: string;
  stable: boolean;
  captureId: string;
  captureDigest: string;
  manifestDigest: string;
  manifestContentDigest: string;
  exportDigest: string;
  fileCount: number;
  totalBytes: number;
}

/** How a measurement ended (CaptureEnd). */
export interface SimCaptureEnd {
  captured: boolean;
  reason: string | null;
  detail: string | null;
  capture: SimPublishedCapture | null;
}

/** The custodian's re-hash of a captured review's export (ExportRehash). */
export interface SimExportRehash {
  operationId: string;
  unchanged: boolean;
  detail: string;
}

export const runKey = (repoKey: string, runId: string): string => `${repoKey}\u0000${runId}`;

const iso = (ms: number): string => new Date(ms).toISOString();
const newId = (prefix: string, seq: number): string => `${prefix}-${seq}-${randomBytes(6).toString("hex")}`;
const refuse = (code: string, message: string): SimLoopRefusal => new SimLoopRefusal(code, message);
const callerName = (c: SimRunCaller): string => (c.operator ? "operator" : "implementer");

export function applyRunTransition(store: SimRunStore, repoKey: string, req: SimRunRequest, caller: SimRunCaller, nowMs: number): Record<string, unknown> {
  if (caller.operator && req.kind !== "recover" && req.kind !== "end" && req.kind !== "apply_reconcile") throw refuse("CALLER_NOT_AUTHORIZED", `${req.kind} is recorded only by the originating session's engine on the implementer surface`);
  const key = runKey(repoKey, req.runId);
  const run = store.runs[key] ?? null;
  const applyBeginReq = req.kind === "op_begin" && req.fields["operationKind"] === "apply";
  if (run) {
    const replayed = replayOf(run, caller, req);
    if (replayed) {
      // Phase 4 Increment 3: the confirmed content is never kept in the log; a replayed application begin gets it again
      // only while that application still runs.
      if (applyBeginReq && run.operations.find((o) => o.operationId === replayed["operationId"])?.status === "running") replayed["changes"] = contentForResult(store);
      return replayed;
    }
  }
  if (req.kind === "open") return open(store, repoKey, run, req, caller, nowMs);
  if (!run) throw refuse("RUN_NOT_OPEN", "the custodian holds no record of this run: it was never opened");
  if (run.events.length >= SIM_RUN_LIMITS.maxRunEvents && req.kind !== "end") throw refuse("BUDGET_EXHAUSTED", `the run's transition log is full (${SIM_RUN_LIMITS.maxRunEvents}); only end is accepted`);
  const step = stepOf(store, run, req, caller, nowMs);
  if ("deduplicatedOf" in step.result) return { runId: run.runId, kind: req.kind, runRevision: run.runRevision, status: run.status, ...step.result };
  // P3.4C-5 Increment 4 (§3.2 retention): an ended run retires every published export but a review's still in flight.
  if (isRunTerminal(step.next)) {
    const before = retiredProposals(step.next);
    step.next = retireFixProposals(step.next, nowMs, store);
    if (retiredProposals(step.next) > before) step.result["proposalsRetired"] = retiredProposals(step.next) - before;
    const retained = retireExports(step.next, nowMs, store.retired);
    if (retained !== step.next) step.result["exportsRetired"] = retiredCount(retained) - retiredCount(step.next);
    step.next = retained;
  }
  const { next, result } = recorded(step.next, run, caller, req, step.result, nowMs);
  requireProjectionWithinCap(next);
  store.runs[key] = next;
  step.afterWrite?.();
  if (applyBeginReq) result["changes"] = contentForResult(store); // returned, never stored in the run's log
  return result;
}

type RunStep = { next: SimRun; result: Record<string, unknown>; afterWrite?: () => void };

function stepOf(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  switch (req.kind) {
    case "op_begin":
      return opBegin(store, run, req, caller, nowMs);
    case "record_execution":
      return recordExecution(store, run, req, caller, nowMs);
    case "op_finish":
      return opFinish(store, run, req, caller, nowMs);
    case "recover":
      return recover(store, run, req, caller, nowMs);
    case "respond":
      return respond(store, run, req, caller, nowMs);
    case "apply_reconcile":
      return applyReconcile(store, run, req, nowMs);
    default:
      return end(store, run, req, caller, nowMs);
  }
}

function open(store: SimRunStore, repoKey: string, run: SimRun | null, req: SimRunRequest, caller: SimRunCaller, nowMs: number): Record<string, unknown> {
  const f = req.fields;
  const declaration = { runJsonDigest: f["runJsonDigest"] as string, budgets: structuredClone(f["budgets"]) as SimRun["declaration"]["budgets"], baseline: (f["baseline"] ?? null) as SimRun["declaration"]["baseline"] };
  if (run) {
    if (isRunTerminal(run)) throw refuse("RUN_TERMINAL", `run ${run.runId} has ended (${run.status}); it is not re-opened`);
    if (sha256OfCanonicalJson(run.declaration) !== sha256OfCanonicalJson(declaration)) {
      throw refuse("RUN_DECLARATION_CONFLICT", `run ${run.runId} was opened with another declaration (run.json, budgets or baseline); it cannot become protected with this one — a new run is needed`);
    }
    requireUsableConfig(store.config, repoKey, "the start");
    return { runId: run.runId, kind: "open", runRevision: run.runRevision, status: run.status, evidenceEpoch: run.evidenceEpoch };
  }
  // P3.4C-4 (§3.3, D4-F): the repository's configuration record in force (CONFIG_NOT_HELD / CONFIG_LAPSED).
  const config = requireUsableConfig(store.config, repoKey, "the start");
  const grantLeft = store.grants.some((g) => g.repoKey === repoKey && g.revokedAt === null && Date.parse(g.expiresAt) > nowMs && g.loopsUsed < g.loopsTotal && !g.suspendedAt);
  if (!grantLeft) throw refuse("LOOP_NOT_AUTHORIZED", "no automated loop is authorized for this repository; nothing was registered");
  const created: SimRun = {
    repoKey, runId: req.runId, runRevision: 0, openedAt: iso(nowMs), requestId: req.requestId, evidenceEpoch: 1, declaration,
    status: "idle", ended: null, operations: [], checkExecutions: [], reviews: [], items: [], replies: [], responses: [], incidents: [], events: [], lastRecoveryId: null,
    openedConfig: { configRevision: config.configRevision, configDigest: config.configDigest },
  };
  const { next, result } = recorded(created, null, caller, req, { evidenceEpoch: 1, configRevision: config.configRevision, configDigest: config.configDigest }, nowMs);
  store.runs[runKey(repoKey, req.runId)] = next;
  return result;
}

function opBegin(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  if (isRunTerminal(run)) throw refuse("RUN_TERMINAL", `the run has ended (${run.status})`);
  const running = runningOperation(run);
  if (running) throw refuse("RUN_BUSY", `the run has a running ${running.kind} operation ${running.operationId}`);
  requireBoundCaller(store, run, caller);
  const writer = requireWriter(caller);
  const f = req.fields;
  const seq = run.operations.length + 1;
  if (f["operationKind"] === "fix") return fixBegin(store, run, req, writer, seq, nowMs);
  if (f["operationKind"] === "apply") return applyBegin(store, run, req, writer, seq, nowMs);
  if (f["operationKind"] === "checks") {
    const used = nonSkipped(run);
    const limit = checkLimit(run);
    if (used >= limit) throw refuse("BUDGET_EXHAUSTED", `check executions: ${used} of ${limit} used`);
    // P3.4C-4 (§3.3): the current configuration gates the operation; every planned check that will run names the
    // definition the operator approved for the custodian.
    const cfg = requireUsableConfig(store.config, run.repoKey, "a protected checks operation");
    for (const p of f["planned"] as { check: string; definitionDigest: string | null }[]) {
      if (p.definitionDigest === null) continue;
      const approved = cfg.checks[p.check];
      if (!approved || approved.definitionDigest !== p.definitionDigest) {
        throw refuse("CHECK_NOT_APPROVED", !approved ? `check ${p.check} is not in the repository's protected configuration; nothing was begun` : `check ${p.check}'s definition is not the one approved in the repository's protected configuration (revision ${cfg.configRevision}); nothing was begun`);
      }
    }
    const pin: SimOperationPin = { configRevision: cfg.configRevision, configDigest: cfg.configDigest, isolationKind: null, isolationRecordId: null, isolationGlobalRevision: null, captureRulesDigest: null, codexSha256: null };
    // P3.4C-5 Increment 3 (§4, §2.4): the custodian measures the source and every planned check's inputs itself first.
    requireMeasureReady(store);
    store.requireRepositoryReadable?.(); // N5-8
    const ticket = `tkt-${randomBytes(12).toString("hex")}`;
    const op: SimRunOperation = { operationId: newId("cop", seq), seq, kind: "checks", status: "measuring", beganAt: iso(nowMs), endedAt: null, writer, begin: structuredClone(f), outcome: null, pin, ticket };
    const t: SimCheckTicket = { ticket, kind: "start", repoKey: run.repoKey, runId: run.runId, operationId: op.operationId, workload: checkWorkload(cfg, f) };
    return {
      next: { ...run, operations: [...run.operations, op], status: "checking" },
      result: { operationId: op.operationId, configRevision: cfg.configRevision, operationStatus: "measuring", ticket },
      afterWrite: () => store.startCheckMeasurement?.(t),
    };
  }
  // P3.4C-4 (§3.3): the configuration-derived identities the review claims, checked against the held records.
  const config = requireUsableConfig(store.config, run.repoKey, "a protected review");
  const install = config.codexInstallation;
  if (!install) throw refuse("CONFIG_NOT_HELD", "the repository's protected configuration has no approved Codex installation; a protected review is refused — the operator sets one with `code-parley config set --repo <path> --codex <codex.exe>`");
  const basis = requireIsolationBasis(store.config, f["isolation"] as Record<string, unknown>);
  if (f["captureRulesDigest"] !== config.captureRulesDigest) throw refuse("CONFIG_MISMATCH", "the review's capture rules are not the repository's protected capture rules; nothing was begun");
  if (f["codexSha256"] !== install.sha256) throw refuse("CONFIG_MISMATCH", "the Codex image the engine reports is not the approved installation; nothing was begun");
  const pin: SimOperationPin = { configRevision: config.configRevision, configDigest: config.configDigest, isolationKind: basis.kind, isolationRecordId: basis.id, isolationGlobalRevision: basis.globalRevision, captureRulesDigest: config.captureRulesDigest, codexSha256: install.sha256 };
  crossCheck(store, run, f["checkExecutionIds"] as string[], (f["amendments"] as { offered: { amendmentId: string; disclosureDigest: string | null }[] }).offered, (f["discussion"] as { offered: { itemId: string; responseIds: string[]; replyIds: string[] }[] }).offered);
  // P3.4C-5 (§3.1 step 2, §2.4): the custodian captures the review itself, through its helper and the approved runtime.
  const runtime = requireCaptureReady(store);
  store.requireRepositoryReadable?.(); // N5-8
  const limit = reviewLimit(run);
  if (run.reviews.length >= limit) throw refuse("BUDGET_EXHAUSTED", `review budget: ${run.reviews.length} of ${limit} used`);
  const reviewId = f["reviewId"] as string;
  if (run.reviews.some((r) => r.reviewId === reviewId)) throw invalid(`review id ${reviewId} was already used in this run`);
  const reserve = structuredClone(f);
  const ignored = IGNORED_CAPTURE_CLAIMS.filter((k) => k in reserve);
  for (const k of ignored) delete reserve[k];
  const ticket = `tkt-${randomBytes(12).toString("hex")}`;
  const op: SimRunOperation = { operationId: newId("rop", seq), seq, kind: "review", status: "measuring", beganAt: iso(nowMs), endedAt: null, writer, begin: reserve, outcome: null, pin, ticket };
  const round = run.reviews.length + 1;
  const review: SimRunReview = { reviewId, operationId: op.operationId, round, begin: structuredClone(reserve), outcome: null, accepted: null, notAcceptedReasons: [], itemIds: [], incidentIds: [], evidenceEpoch: run.evidenceEpoch };
  const result: Record<string, unknown> = { operationId: op.operationId, reviewId, round, configRevision: config.configRevision, operationStatus: "measuring", ticket };
  if (ignored.length) result["ignoredClaims"] = [...ignored];
  const t: SimCaptureTicket = { ticket, repoKey: run.repoKey, runId: run.runId, operationId: op.operationId, target: structuredClone(reserve["target"]) as Record<string, unknown>, runtimeId: runtime };
  return { next: { ...run, operations: [...run.operations, op], reviews: [...run.reviews, review], status: "reviewing" }, result, afterWrite: () => store.startCapture?.(t) };
}

/** The runtime a measurement runs under (RequireMeasureReady). */
function requireMeasureReady(store: SimRunStore): string {
  if (!store.measureEnabled) throw refuse("HELPER_UNAVAILABLE", "the custodian measures a protected run's source and checks through its helper, which is not installed or not enabled; nothing was begun — the operator installs it (`CodeParley.Custodian.exe install-helper`) and restarts the custodian");
  return requireCaptureReady(store);
}

/** The approved runtime a reservation runs under (RequireCaptureReady). */
function requireCaptureReady(store: SimRunStore): string {
  if (!store.captureEnabled) throw refuse("HELPER_UNAVAILABLE", "a protected review is captured by the custodian's helper, which is not installed or not enabled; nothing was begun — the operator installs it (`CodeParley.Custodian.exe install-helper`) and restarts the custodian");
  const rt = currentRuntime(store.config);
  if (!rt) throw refuse("RUNTIME_NOT_APPROVED", "no engine runtime is approved for the custodian's helper; nothing was begun — the operator approves one with `code-parley config approve-runtime --runtime <dir> --runtime-git <relative git.exe>`");
  if (rt.revokedAt !== null) throw refuse("RUNTIME_NOT_APPROVED", `the approved engine runtime ${rt.runtimeId} was revoked; nothing was begun — the operator approves one again (\`code-parley config approve-runtime\`)`);
  if (rt.lapsedAtRecoveryId !== null) throw refuse("CONFIG_LAPSED", `the engine runtime approval lapsed after a restart of the OS (recovery ${rt.lapsedAtRecoveryId}); nothing was begun — the operator re-confirms it (\`code-parley config reconfirm-runtime ${rt.runtimeId}\`)`);
  return rt.runtimeId;
}

function crossCheck(store: SimRunStore, run: SimRun, checkExecutionIds: string[], presented: { amendmentId: string; disclosureDigest: string | null }[], delivered: { itemId: string; responseIds: string[]; replyIds: string[] }[]): void {
  const executions = new Set(run.checkExecutions.map((e) => e["executionId"]));
  for (const id of checkExecutionIds) if (!executions.has(id)) throw refuse("EVIDENCE_NOT_HELD", `check execution ${id} is not an execution the custodian holds for this run`);
  if (presented.length) {
    const held = store.amendmentsOf(run.repoKey, run.runId);
    for (const p of presented) {
      const rec = held.find((a) => a.recordId === p.amendmentId);
      if (!rec || rec.disclosureDigest !== p.disclosureDigest) throw refuse("EVIDENCE_NOT_HELD", `amendment ${p.amendmentId} is not a protected amendment the custodian holds for this run with that disclosure digest`);
    }
  }
  const items = new Set(run.items.map((i) => i.itemId));
  for (const d of delivered) {
    if (!items.has(d.itemId)) throw refuse("EVIDENCE_NOT_HELD", `delivered item ${d.itemId} is not an item the custodian holds`);
    for (const r of d.responseIds) if (!run.responses.some((x) => x["responseId"] === r && x["itemId"] === d.itemId)) throw refuse("EVIDENCE_NOT_HELD", `delivered response ${r} is not a response the custodian holds on item ${d.itemId}`);
    for (const r of d.replyIds) if (!run.replies.some((x) => x["replyId"] === r && x["itemId"] === d.itemId)) throw refuse("EVIDENCE_NOT_HELD", `delivered reply ${r} is not a reply the custodian holds on item ${d.itemId}`);
  }
}

function recordExecution(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  const op = runningOp(run, req.fields["operationId"] as string);
  if (op.kind !== "checks") throw refuse("OPERATION_NOT_RUNNING", `operation ${op.operationId} is a ${op.kind} operation; executions belong to a checks operation`);
  if (op.status === "measuring") throw refuse("OPERATION_NOT_RUNNING", `operation ${op.operationId} is still being measured by the custodian; its checks start once it runs`);
  if (op.status !== "running") throw refuse("OPERATION_NOT_RUNNING", `operation ${op.operationId} is not running (${op.status})`);
  if (op.pending) throw refuse("RUN_BUSY", `the custodian is measuring the end of execution ${String((op.pending["execution"] as Record<string, unknown> | undefined)?.["executionId"])}; record the next one once it is recorded`);
  requireSameWriter(caller, op);
  const e = req.fields["execution"] as Record<string, unknown>;
  const check = e["check"] as string;
  const planned = (op.begin["planned"] as { check: string; definitionDigest?: string | null }[]).find((p) => p.check === check);
  if (!planned) throw invalid(`check ${check} is not planned by operation ${op.operationId}`);
  const executionId = e["executionId"] as string;
  if (run.checkExecutions.some((x) => x["executionId"] === executionId)) throw invalid(`execution ${executionId} is already recorded`);
  const skipped = e["status"] === "skipped";
  if (skipped !== (e["skipReason"] !== null)) throw invalid("a skipped execution names its skip reason, and only a skipped one");
  // P3.4C-4 (§3.3, §4.3): an execution that ran carries the definition its operation planned (and the custodian approved).
  if (!skipped && (typeof planned.definitionDigest !== "string" || e["definitionDigest"] !== planned.definitionDigest)) {
    throw refuse("EVIDENCE_NOT_HELD", `execution ${String(e["executionId"])} of ${check} does not carry the definition its operation planned and the custodian approved; nothing was recorded`);
  }
  if (run.checkExecutions.length >= SIM_RUN_LIMITS.maxAllExecutionsPerRun) throw refuse("BUDGET_EXHAUSTED", `a run keeps at most ${SIM_RUN_LIMITS.maxAllExecutionsPerRun} check executions`);
  const used = nonSkipped(run);
  const limit = checkLimit(run);
  if (!skipped && used >= limit) throw refuse("BUDGET_EXHAUSTED", `check executions: ${used} of ${limit} used`);
  if (skipped) return { next: { ...run, checkExecutions: [...run.checkExecutions, skippedExecution(run, op, e)] }, result: { operationId: op.operationId, executionId } };
  // P3.4C-5 Increment 3 (§4): one that ran is reserved; the custodian measures the source after it and records it then.
  requireMeasureReady(store);
  const cfg = currentOf(store.config, run.repoKey);
  if (!cfg) throw refuse("CONFIG_NOT_HELD", "the repository's protected configuration is no longer held; nothing was recorded");
  const ticket = `tkt-${randomBytes(12).toString("hex")}`;
  const pending = { ticket, reservedAt: iso(nowMs), execution: structuredClone(e) };
  const t: SimCheckTicket = { ticket, kind: "end", repoKey: run.repoKey, runId: run.runId, operationId: op.operationId, workload: checkWorkload(cfg, op.begin) };
  return {
    next: { ...run, operations: replaceOp(run, { ...op, pending }) },
    result: { operationId: op.operationId, executionId, executionStatus: "measuring", ticket },
    afterWrite: () => store.startCheckMeasurement?.(t),
  };
}

function opFinish(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  const op = runningOp(run, req.fields["operationId"] as string);
  requireSameWriter(caller, op);
  const outcome = apply(op.kind === "checks" ? CHECKS_OUTCOME : op.kind === "fix" ? FIX_OUTCOME : op.kind === "apply" ? APPLY_OUTCOME : REVIEW_OUTCOME, req.fields["outcome"], "fields.outcome");
  const opStatus = outcome["status"] as string;
  const runStatus = isRunTerminal(run) ? run.status : "idle";
  const promptDigest = (req.fields["promptDigest"] ?? null) as string | null;
  const presented = (req.fields["presented"] ?? null) as Record<string, unknown> | null;
  const custodianCapture = op.status === "measuring" || op.status === "captured";
  if (!custodianCapture && (promptDigest !== null || presented !== null)) throw refuse("MALFORMED_REQUEST", "promptDigest and presented belong to the finish of a review the custodian captured");
  // P3.4C-5 (§2.4): a review still being captured can only be abandoned; the measurement is cancelled, the budget released.
  if (op.status === "measuring") {
    if (opStatus !== "cancelled" && opStatus !== "failed" && opStatus !== "error") throw refuse("OPERATION_NOT_RUNNING", `operation ${op.operationId} is still being measured by the custodian; it can only be cancelled until the measurement completes`);
    const ended = opStatus === "cancelled" ? "cancelled" : "error";
    return {
      next: endMeasurement(run, op, ended, opStatus === "cancelled" ? "cancelled" : "abandoned", `the engine ended the ${op.kind} operation before the custodian's measurement completed`, nowMs),
      result: { operationId: op.operationId, operationStatus: ended, budgetReleased: true },
      afterWrite: () => store.cancelCapture?.(op.ticket),
    };
  }
  if (op.kind === "fix") return fixFinish(store, run, op, req, runStatus, nowMs);
  if (op.kind === "apply") return applyFinish(store, run, op, req, runStatus, nowMs);
  if (op.kind === "checks") {
    if (op.pending) throw refuse("RUN_BUSY", `the custodian is measuring the end of execution ${String((op.pending["execution"] as Record<string, unknown> | undefined)?.["executionId"])}; finish the operation once it is recorded`);
    const done = { ...op, status: opStatus, endedAt: iso(nowMs), outcome };
    return { next: { ...run, operations: replaceOp(run, done), status: runStatus }, result: { operationId: op.operationId, operationStatus: opStatus } };
  }
  const review = run.reviews.find((r) => r.operationId === op.operationId)!;
  if (custodianCapture) requirePresented(review, opStatus, promptDigest, presented);
  const reported = outcome["incidents"] as { kind: string; detail: string }[];
  const rehash = store.rehash ?? null;
  if (custodianCapture && (!rehash || rehash.operationId !== op.operationId)) throw new Error("a custodian-captured review is finished only after the custodian re-hashed its export");
  const exportModified = custodianCapture && rehash !== null && !rehash.unchanged;
  requireIncidentRoom(run, reported.length + (exportModified ? 1 : 0));
  const incidents = [...run.incidents];
  const newIds: string[] = [];
  for (const i of reported) {
    const inc: SimRunIncident = { incidentId: newId("inc", incidents.length + 1), kind: i.kind, operationId: op.operationId, reviewId: review.reviewId, detail: i.detail, at: iso(nowMs), source: "engine" };
    incidents.push(inc);
    newIds.push(inc.incidentId);
  }
  // P3.4C-5 (§3.1 step 7, N5-3): the custodian's own re-hash of the export it published; a change is an invalidating incident.
  if (exportModified) {
    const inc: SimRunIncident = { incidentId: newId("inc", incidents.length + 1), kind: "export_modified_during_review", operationId: op.operationId, reviewId: review.reviewId, detail: `the published export changed during the review (the custodian's re-hash: ${rehash!.detail})`, at: iso(nowMs), source: "custodian" };
    incidents.push(inc);
    newIds.push(inc.incidentId);
  }
  const reasons = notAcceptedReasons(outcome, isRunTerminal(run), incidents.filter((i) => i.operationId === op.operationId).map((i) => i.kind));
  // P3.4C-4 (§3.3, §4.3): acceptance also needs the pinned basis still usable at completion.
  if (isolationBasisProblem(store.config, op.pin?.isolationKind, op.pin?.isolationRecordId) !== null) reasons.push("isolation_basis_revoked");
  else if (reviewBasisProblem(store.config, run.repoKey, op.pin) !== null) reasons.push("config_changed_during_review");
  const accepted = reasons.length === 0;
  const sourceId = review.begin["sourceId"] as string;
  const applied = accepted ? applyAccepted(run, review, sourceId, outcome, iso(nowMs)) : null;
  const stored = storedReviewOutcome(outcome);
  if (custodianCapture) {
    stored["promptDigest"] = promptDigest;
    stored["presented"] = presented ? structuredClone(presented) : null;
    stored["exportRehash"] = { unchanged: !exportModified, detail: rehash!.detail };
  }
  const finished: SimRunReview = { ...review, outcome: stored, accepted, notAcceptedReasons: reasons, itemIds: applied?.newItemIds ?? [], incidentIds: [...review.incidentIds, ...newIds] };
  const next: SimRun = {
    ...run,
    operations: replaceOp(run, { ...op, status: opStatus, endedAt: iso(nowMs), outcome: structuredClone(stored) }),
    reviews: run.reviews.map((r) => (r.reviewId === review.reviewId ? finished : r)),
    incidents,
    items: applied?.items ?? run.items,
    replies: applied?.replies ?? run.replies,
    status: runStatus,
  };
  return {
    next,
    result: {
      operationId: op.operationId, operationStatus: opStatus, reviewId: review.reviewId, round: review.round, accepted, notAcceptedReasons: reasons,
      itemsChanged: (applied?.changed ?? []).map((i) => ({ itemId: i.itemId, status: i.status, itemRevision: i.itemRevision })), incidentIds: newIds,
    },
  };
}

function storedReviewOutcome(o: Record<string, unknown>): Record<string, unknown> {
  return {
    status: o["status"], outputValid: o["outputValid"], currentAtCompletion: o["currentAtCompletion"], verdict: o["verdict"] ?? null, summaryDigest: o["summaryDigest"] ?? null,
    artifacts: structuredClone(o["artifacts"]),
    reported: {
      newItems: (o["newItems"] as unknown[]).length, assessments: (o["assessments"] as unknown[]).length,
      replies: (o["replies"] as unknown[]).length, incidents: (o["incidents"] as unknown[]).length,
    },
  };
}

function recover(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  let op = runningOp(run, req.fields["operationId"] as string);
  const gone = caller.writerGone(op.writer);
  if (gone === true && op.status === "measuring") {
    // P3.4C-5: the writer died while the custodian captured: the measurement is cancelled, the reservation released.
    return {
      next: endMeasurement(run, op, "interrupted", "owner_died", "the operation's writer is gone", nowMs),
      result: { operationId: op.operationId, operationStatus: "interrupted", budgetReleased: true },
      afterWrite: () => store.cancelCapture?.(op.ticket),
    };
  }
  if (gone !== true) {
    throw refuse("OPERATION_WRITER_ALIVE", gone === null
      ? "the process table could not be read, so the operation's writer cannot be established as gone; nothing was recovered"
      : `the operation's writer (process ${op.writer.pid}) is still running; nothing was recovered`);
  }
  // Phase 4 Increment 3 (§3.6.4): an application whose writer is gone is apply_interrupted, never applied.
  if (op.kind === "apply") return applyInterrupted(store, run, op, nowMs);
  const reported = req.fields["incidents"] as { kind: string; detail: string }[];
  requireIncidentRoom(run, reported.length);
  const review = op.kind === "review" ? run.reviews.find((r) => r.operationId === op.operationId)! : null;
  const incidents = [...run.incidents];
  const newIds: string[] = [];
  for (const i of reported) {
    const inc: SimRunIncident = { incidentId: newId("inc", incidents.length + 1), kind: i.kind, operationId: op.operationId, reviewId: review?.reviewId ?? null, detail: i.detail, at: iso(nowMs), source: "engine" };
    incidents.push(inc);
    newIds.push(inc.incidentId);
  }
  // P3.4C-5 Increment 3: an execution whose end the custodian was measuring is recorded without its end.
  const pendingTicket = (op.pending?.["ticket"] ?? null) as string | null;
  if (op.pending) {
    run = recordUnmeasuredPending(run, op, "owner_died: the operation's writer is gone", nowMs);
    op = run.operations.find((o) => o.operationId === op.operationId)!;
  }
  const interrupted = { ...op, status: "interrupted", endedAt: iso(nowMs), outcome: { status: "interrupted" } };
  const reviews = review
    ? run.reviews.map((r) => (r.reviewId === review.reviewId ? { ...r, outcome: { status: "interrupted" }, accepted: false, notAcceptedReasons: ["owner_died"], incidentIds: [...r.incidentIds, ...newIds] } : r))
    : run.reviews;
  return { next: { ...run, operations: replaceOp(run, interrupted), reviews, incidents, status: isRunTerminal(run) ? run.status : "idle" }, result: { operationId: op.operationId, operationStatus: "interrupted" }, afterWrite: () => store.cancelCapture?.(pendingTicket) };
}

function respond(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  if (isRunTerminal(run)) throw refuse("RUN_TERMINAL", `the run has ended (${run.status})`);
  const running = runningOperation(run);
  if (running?.kind === "review") throw refuse("RUN_BUSY", `a review is running (${running.operationId}); respond after it finishes`);
  requireBoundCaller(store, run, caller);
  const f = req.fields;
  const responses = f["responses"] as Record<string, unknown>[];
  if (run.responses.length + responses.length > SIM_RUN_LIMITS.maxResponsesPerRun) throw refuse("BUDGET_EXHAUSTED", `a run keeps at most ${SIM_RUN_LIMITS.maxResponsesPerRun} responses`);
  const byId = new Map(run.items.map((i) => [i.itemId, i]));
  const existing = new Set(run.responses.map((r) => r["responseId"]));
  const stored: Record<string, unknown>[] = [];
  const revisions: Record<string, number> = {};
  const bumped = new Map<string, SimRunItem>();
  for (const r of responses) {
    const responseId = r["responseId"] as string;
    const itemId = r["itemId"] as string;
    if (existing.has(responseId)) throw invalid(`response ${responseId} is already recorded`);
    const item = byId.get(itemId);
    if (!item) throw refuse("FINDING_NOT_FOUND", `item ${itemId} is not an item of this run`);
    if (item.status !== "open" && item.status !== "informational") throw refuse("FINDING_NOT_RESPONDABLE", `item ${itemId} is ${item.status}; it takes no response`);
    const base = r["baseItemRevision"] as number;
    if (item.itemRevision !== base) throw refuse("STALE_FINDING_STATE", `item ${itemId} changed (revision ${item.itemRevision}, not ${base}); read the current state and respond again`);
    if (run.responses.filter((x) => x["itemId"] === itemId).length + 1 > SIM_RUN_LIMITS.maxResponsesPerItem) throw refuse("BUDGET_EXHAUSTED", `item ${itemId} keeps at most ${SIM_RUN_LIMITS.maxResponsesPerItem} responses`);
    const sup = r["supersedes"] as string | null;
    if (sup !== null && !run.responses.some((x) => x["responseId"] === sup && x["itemId"] === itemId)) throw refuse("EVIDENCE_NOT_HELD", `response ${responseId} supersedes ${sup}, which is not a response the custodian holds on item ${itemId}`);
    const reply = (r["answers"] as Record<string, unknown>)["reviewerReplyId"] as string | null;
    if (reply !== null && !run.replies.some((x) => x["replyId"] === reply && x["itemId"] === itemId)) throw refuse("EVIDENCE_NOT_HELD", `response ${responseId} answers reply ${reply}, which is not a reply the custodian holds on item ${itemId}`);
    const { baseItemRevision: _base, ...rest } = structuredClone(r);
    stored.push({ ...rest, responseSetId: f["responseSetId"], disclosureDigest: f["disclosureDigest"] ?? null, recordedAt: iso(nowMs) });
    const next = { ...item, itemRevision: item.itemRevision + 1 };
    bumped.set(itemId, next);
    revisions[itemId] = next.itemRevision;
  }
  return {
    next: { ...run, responses: [...run.responses, ...stored], items: run.items.map((i) => bumped.get(i.itemId) ?? i) },
    result: { responseIds: stored.map((s) => s["responseId"]), itemRevisions: revisions },
  };
}

function end(store: SimRunStore, run: SimRun, req: SimRunRequest, caller: SimRunCaller, nowMs: number): RunStep {
  if (isRunTerminal(run)) throw refuse("RUN_TERMINAL", `the run has already ended (${run.status})`);
  const status = req.fields["status"] as string;
  const running = runningOperation(run);
  if (status === "closed" && running) throw refuse("RUN_BUSY", `the run has a running ${running.kind} operation ${running.operationId}; it is closed only when none runs (stop it instead)`);
  const ended = { status, reason: req.fields["reason"] as string, at: iso(nowMs), by: callerName(caller) };
  // Whether the run's loop is still live is read in this same hold; in it, after the run is written, the loop's end is
  // derived (run_ended, by the custodian, §3.4(5)).
  const index = store.loops.findIndex((l) => l.repoKey === run.repoKey && l.runId === run.runId);
  const loopLive = index >= 0 && LIVE_STATUSES.has(store.loops[index]!.status);
  const measuringTicket = running?.status === "measuring" ? running.ticket : ((running?.pending?.["ticket"] ?? null) as string | null);
  const afterWrite = (): void => {
    if (loopLive) store.loops[index] = deriveEnd(store.loops[index]!, "run_ended", `run_${status}`, nowMs);
    store.cancelCapture?.(measuringTicket);
  };
  return { next: { ...run, status, ended }, result: { ended: { ...ended }, loopEnded: loopLive }, afterWrite };
}

// ---- guards ----

function requireBoundCaller(store: SimRunStore, run: SimRun, caller: SimRunCaller): void {
  const loop = store.loops.find((l) => l.repoKey === run.repoKey && l.runId === run.runId);
  const binding = loop?.binding;
  if (!binding || binding.process.verified !== true) throw refuse("PROCESS_IDENTITY_UNVERIFIED", "the run's automation loop has no custodian-verified binding; evidence is accepted only from the bound session's process tree");
  const c = caller.client;
  const same = c !== null && c.bound.pid === binding.process.pid && c.bound.startedAtMs === binding.process.startedAtMs;
  if (!c || !same || !c.verdict.verified) {
    const why = !c ? "the connected process could not be checked" : !same ? "the binding changed while the connected process was checked" : c.verdict.detail;
    throw refuse("PROCESS_IDENTITY_UNVERIFIED", `the request does not come from the bound session's process tree: ${why}`);
  }
}

function requireWriter(caller: SimRunCaller): SimWriter {
  if (!caller.writer) throw refuse("PROCESS_IDENTITY_UNVERIFIED", "the process that sent this request could not be identified");
  return caller.writer;
}

function requireSameWriter(caller: SimRunCaller, op: SimRunOperation): void {
  const w = caller.writer;
  if (!w || w.pid !== op.writer.pid || w.startedAtMs !== op.writer.startedAtMs) {
    throw refuse("WRITER_MISMATCH", `operation ${op.operationId} was begun by another process; only that process extends or finishes it`);
  }
}

function runningOp(run: SimRun, operationId: string): SimRunOperation {
  const op = run.operations.find((o) => o.operationId === operationId);
  if (!op || !isActiveOperation(op.status)) throw refuse("OPERATION_NOT_RUNNING", !op ? `the run has no operation ${operationId}` : `operation ${operationId} is not running (${op.status})`);
  return op;
}

function requireIncidentRoom(run: SimRun, adding: number): void {
  if (run.incidents.length + adding > SIM_RUN_LIMITS.maxIncidentsPerRun) throw refuse("BUDGET_EXHAUSTED", `a run keeps at most ${SIM_RUN_LIMITS.maxIncidentsPerRun} isolation incidents`);
}

function requireProjectionWithinCap(run: SimRun): void {
  if (Buffer.byteLength(JSON.stringify(implementerRunProjection(run, null)), "utf8") > SIM_RUN_LIMITS.maxImplementerProjectionBytes) {
    throw refuse("BUDGET_EXHAUSTED", `the run record would exceed its size cap (${SIM_RUN_LIMITS.maxImplementerProjectionBytes} bytes)`);
  }
}

const replaceOp = (run: SimRun, op: SimRunOperation): SimRunOperation[] => run.operations.map((o) => (o.operationId === op.operationId ? op : o));
const nonSkipped = (run: SimRun): number => run.checkExecutions.filter((e) => e["status"] !== "skipped").length;
export const reviewLimit = (run: SimRun): number => Math.min(run.declaration.budgets.maxReviews, SIM_RUN_LIMITS.maxReviewsPerRun);
export const checkLimit = (run: SimRun): number => Math.min(run.declaration.budgets.maxCheckExecutions, SIM_RUN_LIMITS.maxCheckExecutionsPerRun);
/** Phase 4 Increment 2: the run's fix budget — its declared maxFixes (none declared: 0) under the custodian's cap. */
export const fixLimit = (run: SimRun): number => Math.min(run.declaration.budgets.maxFixes ?? 0, SIM_FIX_LIMITS.maxFixesPerRun);
export const fixesBegun = (run: SimRun): number => run.operations.filter((o) => o.kind === "fix").length;

// ---- idempotency and evidence ----

function replayOf(run: SimRun, caller: SimRunCaller, req: SimRunRequest): Record<string, unknown> | null {
  const prior = run.events.find((e) => e.requestId === req.requestId);
  if (!prior) return null;
  if (prior.kind !== req.kind || prior.requestDigest !== req.digest || prior.caller !== callerName(caller)) throw refuse("REQUEST_ID_CONFLICT", "this request id was already used for a different run transition");
  return structuredClone(prior.result ?? {});
}

function recorded(next: SimRun, before: SimRun | null, caller: SimRunCaller, req: SimRunRequest, stepResult: Record<string, unknown>, nowMs: number): { next: SimRun; result: Record<string, unknown> } {
  const revision = (before?.runRevision ?? 0) + 1;
  const result: Record<string, unknown> = { runId: next.runId, kind: req.kind, runRevision: revision, status: next.status, ...structuredClone(stepResult) };
  const events = before?.events ?? [];
  const evidence: SimRunEvent = { seq: events.length + 1, kind: req.kind, requestId: req.requestId, caller: callerName(caller), clientPid: caller.clientPid, requestDigest: req.digest, fromStatus: before?.status ?? "none", toStatus: next.status, at: iso(nowMs), result: structuredClone(result) };
  return { next: { ...next, runRevision: revision, events: [...events, evidence] }, result };
}

// ---------------------------------------------------------------------------
// Acceptance and the item table (RunLifecycle.cs)
// ---------------------------------------------------------------------------

export function notAcceptedReasons(outcome: Record<string, unknown>, runTerminal: boolean, incidentKinds: readonly string[]): string[] {
  const reasons: string[] = [];
  const status = outcome["status"] as string;
  if (status !== "completed") reasons.push(`status:${status}`);
  else if (outcome["outputValid"] !== true) reasons.push("output_invalid");
  else if (outcome["currentAtCompletion"] !== true) reasons.push("not_current_at_completion");
  if (runTerminal) reasons.push("run_stopped");
  for (const kind of [...new Set(incidentKinds)].sort()) if (E.invalidating.has(kind)) reasons.push(`incident:${kind}`);
  return reasons;
}

export function lastPresentSource(it: SimRunItem): string {
  let s = it.sourceId;
  for (const a of it.assessments) if (a.assessment === "still_present") s = a.sourceId;
  return s;
}

const invalidTransition = (m: string): SimLoopRefusal => refuse("INVALID_ITEM_TRANSITION", m);

export function applyAccepted(run: SimRun, review: SimRunReview, sourceId: string, outcome: Record<string, unknown>, now: string): { items: SimRunItem[]; replies: Record<string, unknown>[]; newItemIds: string[]; changed: SimRunItem[] } {
  const byId = new Map(run.items.map((i) => [i.itemId, i]));
  const priorOpen = run.items.filter((i) => i.status === "open");
  const priorOpenIds = new Set(priorOpen.map((i) => i.itemId));

  const newArr = outcome["newItems"] as Record<string, unknown>[];
  if (run.items.length + newArr.length > SIM_RUN_LIMITS.maxItemsPerRun) throw refuse("BUDGET_EXHAUSTED", `a run keeps at most ${SIM_RUN_LIMITS.maxItemsPerRun} items`);
  const created: SimRunItem[] = [];
  const declared = new Map<string, string[]>();
  for (const n of newArr) {
    const id = n["itemId"] as string;
    if (byId.has(id)) throw invalidTransition(`item ${id} already exists`);
    const kind = n["itemKind"] as string;
    const triage = n["triage"] as string;
    const question = kind === "question";
    if (!(question ? QUESTION_TRIAGES : FINDING_TRIAGES).has(triage)) throw invalidTransition(`a ${kind} cannot be triaged ${triage}`);
    const status = E.openTriages.has(triage) ? "open" : "informational";
    if (n["status"] !== status) throw invalidTransition(`item ${id} is created ${status} (triage ${triage}), not ${String(n["status"])}`);
    const relatedPrior = (n["relatedPriorId"] ?? null) as string | null;
    const relatedFinding = (n["relatedFindingId"] ?? null) as string | null;
    if (question && (n["severity"] !== null || n["claimType"] !== null || n["category"] !== null || n["confidence"] !== null || (n["impacts"] as unknown[]).length > 0 || relatedPrior !== null)) {
      throw invalidTransition(`question ${id} carries finding fields`);
    }
    if (!question && relatedFinding !== null) throw invalidTransition(`finding ${id} names a related finding`);
    if (relatedPrior !== null && !priorOpenIds.has(relatedPrior)) throw invalidTransition(`item ${id} relates to ${relatedPrior}, which was not open before this review`);
    const restates = n["restates"] as string[];
    for (const r of restates) if (!byId.has(r)) throw invalidTransition(`item ${id} restates ${r}, which the custodian does not hold`);
    declared.set(id, restates);
    created.push({
      itemId: id, itemKind: kind, reviewId: review.reviewId, round: review.round, sourceId, triage,
      severity: (n["severity"] ?? null) as string | null, claimType: (n["claimType"] ?? null) as string | null, category: (n["category"] ?? null) as string | null,
      impacts: [...(n["impacts"] as string[])], confidence: (n["confidence"] ?? null) as string | null,
      status, supersededBy: null, supersedes: [], restates: [], relatedPriorId: relatedPrior, relatedFindingId: relatedFinding,
      assessments: [], itemRevision: 1, createdAt: now,
    });
  }
  const newById = new Map(created.map((i) => [i.itemId, i]));
  for (const q of created) {
    if (q.itemKind !== "question" || q.relatedFindingId === null) continue;
    if (newById.get(q.relatedFindingId)?.itemKind !== "finding") throw invalidTransition(`question ${q.itemId} relates to ${q.relatedFindingId}, which is not a finding of this review`);
  }

  const entries = new Map<string, { assessment: string; by: string | null }>();
  for (const a of outcome["assessments"] as Record<string, unknown>[]) entries.set(a["itemId"] as string, { assessment: a["assessment"] as string, by: (a["supersededByItemId"] ?? null) as string | null });
  if (entries.size !== priorOpenIds.size || [...entries.keys()].some((k) => !priorOpenIds.has(k))) {
    throw invalidTransition("the assessments must cover exactly the items open before this review, one entry each");
  }
  const supersedes = new Map<string, string[]>();
  const restatedBy = new Map<string, string[]>();
  const assessed = new Map<string, SimRunItem>();
  const push = (m: Map<string, string[]>, k: string, v: string): void => void m.set(k, [...(m.get(k) ?? []), v]);
  for (const it of priorOpen) {
    const { assessment: a, by } = entries.get(it.itemId)!;
    let status = it.status;
    let supersededBy = it.supersededBy;
    let effect: string;
    switch (a) {
      case "still_present":
        effect = "kept_open";
        break;
      case "no_longer_assessable":
        effect = "kept_open:not_assessable";
        break;
      case "not_assessed":
        effect = "kept_open:not_assessed";
        break;
      case "not_presented":
        effect = "kept_open:not_presented";
        break;
      case "apparently_resolved":
        if (lastPresentSource(it) === sourceId) effect = "ignored:same_source";
        else {
          status = "reported_resolved";
          effect = "status:reported_resolved";
        }
        break;
      default: {
        const sup = by !== null && newById.get(by)?.itemKind === "finding" ? newById.get(by)! : null;
        if (!sup) effect = "ignored:no_superseding_finding";
        else if (!E.openTriages.has(sup.triage) || RANK[sup.triage]! < RANK[it.triage]!) {
          effect = "ignored:weaker_superseding_finding";
          push(restatedBy, sup.itemId, it.itemId);
        } else {
          status = "superseded";
          supersededBy = sup.itemId;
          effect = `status:superseded_by:${sup.itemId}`;
          push(supersedes, sup.itemId, it.itemId);
        }
      }
    }
    const recordedAs = a === "not_presented" ? "not_assessed" : a;
    assessed.set(it.itemId, { ...it, status, supersededBy, assessments: [...it.assessments, { reviewId: review.reviewId, round: review.round, sourceId, assessment: recordedAs, effect }], itemRevision: it.itemRevision + 1 });
  }
  for (let k = 0; k < created.length; k++) {
    const n = created[k]!;
    const sup = supersedes.get(n.itemId) ?? [];
    const links = [...new Set([...(declared.get(n.itemId) ?? []), ...(restatedBy.get(n.itemId) ?? [])])].filter((x) => !sup.includes(x));
    created[k] = { ...n, supersedes: sup, restates: links };
  }

  const replyArr = outcome["replies"] as Record<string, unknown>[];
  if (run.replies.length + replyArr.length > SIM_RUN_LIMITS.maxRepliesPerRun) throw refuse("BUDGET_EXHAUSTED", `a run keeps at most ${SIM_RUN_LIMITS.maxRepliesPerRun} reviewer replies`);
  const existingReplies = new Set(run.replies.map((r) => r["replyId"]));
  const replies: Record<string, unknown>[] = [];
  const bumps = new Map<string, number>();
  for (const r of replyArr) {
    const replyId = r["replyId"] as string;
    const itemId = r["itemId"] as string;
    if (existingReplies.has(replyId)) throw invalidTransition(`reply ${replyId} already exists`);
    if (!byId.has(itemId)) throw invalidTransition(`reply ${replyId} answers on item ${itemId}, which the custodian did not hold before this review`);
    const answers = (r["answersResponseId"] ?? null) as string | null;
    if (answers !== null && !run.responses.some((x) => x["responseId"] === answers && x["itemId"] === itemId)) throw invalidTransition(`reply ${replyId} answers response ${answers}, which the custodian does not hold on item ${itemId}`);
    replies.push({ ...structuredClone(r), reviewId: review.reviewId, round: review.round, sourceId, recordedAt: now });
    bumps.set(itemId, (bumps.get(itemId) ?? 0) + 1);
  }
  const items: SimRunItem[] = [];
  const changed: SimRunItem[] = [];
  for (const it of run.items) {
    let cur = assessed.get(it.itemId) ?? it;
    const b = bumps.get(it.itemId);
    if (b) cur = { ...cur, itemRevision: cur.itemRevision + b };
    items.push(cur);
    if (cur !== it) changed.push(cur);
  }
  items.push(...created);
  changed.push(...created);
  return { items, replies: [...run.replies, ...replies], newItemIds: created.map((c) => c.itemId), changed };
}

// ---------------------------------------------------------------------------
// The run section of list_user_records (contract §3.3)
// ---------------------------------------------------------------------------

export function runLimits(run: SimRun | null): Record<string, number> {
  return {
    maxReviews: run ? reviewLimit(run) : SIM_RUN_LIMITS.maxReviewsPerRun,
    maxCheckExecutions: run ? checkLimit(run) : SIM_RUN_LIMITS.maxCheckExecutionsPerRun,
    maxFixes: run ? fixLimit(run) : 0,
    maxExecutions: SIM_RUN_LIMITS.maxAllExecutionsPerRun,
    maxResponsesPerCall: SIM_RUN_LIMITS.maxResponsesPerCall,
    maxResponsesPerItem: SIM_RUN_LIMITS.maxResponsesPerItem,
    maxResponsesPerRun: SIM_RUN_LIMITS.maxResponsesPerRun,
    maxNewItemsPerReview: SIM_RUN_LIMITS.maxNewItemsPerReview,
    maxItems: SIM_RUN_LIMITS.maxItemsPerRun,
    maxReplies: SIM_RUN_LIMITS.maxRepliesPerRun,
    maxIncidents: SIM_RUN_LIMITS.maxIncidentsPerRun,
    maxEvents: SIM_RUN_LIMITS.maxRunEvents,
  };
}

export function runSection(run: SimRun | null, repoKey: string, runId: string, operatorView: boolean, writerGone: ((w: SimWriter) => boolean | null) | null, config: SimConfigFile): Record<string, unknown> {
  const digest = sha256OfCanonicalJson({ repoKey, runId, runRevision: run?.runRevision ?? 0, status: run?.status ?? null });
  if (!run) return { registered: false, runRevision: 0, runDigest: digest, limits: runLimits(null), record: null };
  return {
    registered: true, runRevision: run.runRevision, runDigest: digest, limits: runLimits(run),
    record: operatorView ? structuredClone(run) : implementerRunProjection(run, writerGone, config),
    // P3.4C-4 (§3.3, §4.3): per review, whether its pinned basis is usable now (custodian-derived at read time).
    reviewBasis: reviewBasisOf(run, config),
  };
}

/** P3.4C-4: for each review, basisUsable and, when it is not, the reason (§4.3). */
export function reviewBasisOf(run: SimRun, config: SimConfigFile): Record<string, { basisUsable: boolean; basisReason: string | null }> {
  const out: Record<string, { basisUsable: boolean; basisReason: string | null }> = {};
  for (const r of run.reviews) {
    const problem = reviewBasisProblem(config, run.repoKey, run.operations.find((o) => o.operationId === r.operationId)?.pin);
    out[r.reviewId] = { basisUsable: problem === null, basisReason: problem };
  }
  return out;
}

/** The implementer projection (GrantLedger.Runs.cs ImplementerRunProjection): an independent allowlist — never the
 * writer process facts or the transition log; a running operation carries the custodian's writerAlive verdict. */
export function implementerRunProjection(run: SimRun, writerGone: ((w: SimWriter) => boolean | null) | null, config: SimConfigFile | null = null): Record<string, unknown> {
  const basis = config ? reviewBasisOf(run, config) : null;
  return {
    runId: run.runId, runRevision: run.runRevision, openedAt: run.openedAt, evidenceEpoch: run.evidenceEpoch,
    declaration: structuredClone(run.declaration), status: run.status, ended: run.ended ? { ...run.ended } : null,
    operations: run.operations.map((o) => {
      const p: Record<string, unknown> = { operationId: o.operationId, seq: o.seq, kind: o.kind, status: o.status, beganAt: o.beganAt, endedAt: o.endedAt, begin: structuredClone(o.begin), outcome: o.outcome ? structuredClone(o.outcome) : null, pin: o.pin ? structuredClone(o.pin) : null };
      if (isActiveOperation(o.status) && writerGone) {
        const gone = writerGone(o.writer);
        p["writerAlive"] = gone === null ? null : !gone;
      }
      // P3.4C-5 Increment 3 (§4): a checks operation's latest custodian measurement and the execution being measured.
      if (o.measured) p["measured"] = structuredClone(o.measured);
      if (o.pending) {
        const e = (o.pending["execution"] ?? {}) as Record<string, unknown>;
        p["pending"] = { ticket: o.pending["ticket"] ?? null, executionId: e["executionId"] ?? null, check: e["check"] ?? null };
      }
      return p;
    }),
    checkExecutions: structuredClone(run.checkExecutions),
    reviews: run.reviews.map((r) => ({ ...structuredClone(r), ...(basis ? { basisUsable: basis[r.reviewId]!.basisUsable, basisReason: basis[r.reviewId]!.basisReason } : {}) })),
    openedConfig: run.openedConfig ? { ...run.openedConfig } : null,
    items: structuredClone(run.items),
    replies: structuredClone(run.replies),
    responses: structuredClone(run.responses),
    incidents: structuredClone(run.incidents),
    used: {
      reviews: run.reviews.length, checkExecutions: nonSkipped(run), executions: run.checkExecutions.length, fixes: fixesBegun(run),
      responses: run.responses.length, items: run.items.length, replies: run.replies.length, incidents: run.incidents.length,
    },
  };
}

// ---------------------------------------------------------------------------
// P3.4C-5 Increment 2: the custodian's review capture (GrantLedger.Capture.cs)
// ---------------------------------------------------------------------------

const bounded = (t: string | null | undefined): string => {
  const x = t ?? "";
  return x.length > 400 ? x.slice(0, 400) : x;
};

/** A measuring operation that ends without a capture (EndMeasurement): its review removed (the budget released). */
function endMeasurement(run: SimRun, op: SimRunOperation, status: string, reason: string, detail: string | null, nowMs: number, extra: Record<string, unknown> | null = null, incident = false): SimRun {
  const outcome: Record<string, unknown> = { status, reason, detail: detail === null ? null : bounded(detail), ...(extra ? structuredClone(extra) : {}) };
  const ended: SimRunOperation = { ...op, status, endedAt: iso(nowMs), outcome };
  const incidents = incident && run.incidents.length < SIM_RUN_LIMITS.maxIncidentsPerRun
    ? [...run.incidents, { incidentId: newId("inc", run.incidents.length + 1), kind: "measurement_interrupted", operationId: op.operationId, reviewId: null, detail: detail === null ? "the custodian's measurement was interrupted" : bounded(detail), at: iso(nowMs), source: "custodian" as const }]
    : run.incidents;
  return { ...run, operations: replaceOp(run, ended), reviews: run.reviews.filter((r) => r.operationId !== op.operationId), incidents, status: isRunTerminal(run) ? run.status : "idle" };
}

/** A transition the custodian made itself (CustodianEvent). */
function custodianEvent(next: SimRun, before: SimRun, kind: string, requestId: string, stepResult: Record<string, unknown>, nowMs: number): SimRun {
  const revision = before.runRevision + 1;
  const result: Record<string, unknown> = { runId: next.runId, kind, runRevision: revision, status: next.status, ...structuredClone(stepResult) };
  const evidence: SimRunEvent = { seq: before.events.length + 1, kind, requestId, caller: "custodian", clientPid: null, requestDigest: sha256OfCanonicalJson(result), fromStatus: before.status, toStatus: next.status, at: iso(nowMs), result: structuredClone(result) };
  return { ...next, runRevision: revision, events: [...before.events, evidence] };
}

/** The custodian's review input identity (CustodianReviewInputId): its capture, the reservation's bindings and claims. */
export function custodianReviewInputId(begin: Record<string, unknown>, cap: Pick<SimPublishedCapture, "sourceId" | "manifestContentDigest">): string {
  const sorted = (a: unknown): string[] => [...((a as string[] | undefined) ?? [])].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const ord = (x: string, y: string): number => (x < y ? -1 : x > y ? 1 : 0);
  const offered = [...(((begin["discussion"] as Record<string, unknown> | undefined)?.["offered"] as Record<string, unknown>[] | undefined) ?? [])]
    .sort((a, b) => ord(String(a["itemId"]), String(b["itemId"])))
    .map((d) => ({ itemId: d["itemId"], responseIds: sorted(d["responseIds"]), replyIds: sorted(d["replyIds"]) }));
  const amendments = [...(((begin["amendments"] as Record<string, unknown> | undefined)?.["offered"] as Record<string, unknown>[] | undefined) ?? [])]
    .sort((a, b) => ord(String(a["amendmentId"]), String(b["amendmentId"])))
    .map((a) => ({ amendmentId: a["amendmentId"], disclosureDigest: a["disclosureDigest"] ?? null }));
  return sha256OfCanonicalJson({
    schema: "arl.custodian-review-input.v1",
    sourceId: cap.sourceId,
    manifestContentDigest: cap.manifestContentDigest,
    target: structuredClone(begin["target"] ?? null),
    checkExecutionIds: sorted(begin["checkExecutionIds"]),
    checkEvidenceDigest: begin["checkEvidenceDigest"] ?? null,
    checkResultsDigest: begin["checkResultsDigest"] ?? null,
    discussionOffered: offered,
    amendmentsOffered: amendments,
    isolation: structuredClone(begin["isolation"] ?? null),
    captureRulesDigest: begin["captureRulesDigest"] ?? null,
    codexSha256: begin["codexSha256"] ?? null,
    depth: begin["depth"] ?? null,
    focusDigest: begin["focusDigest"] ?? null,
    versionsDigest: begin["versionsDigest"] ?? null,
  });
}

/** What a captured review presented must be a subset of what its reservation offered (RequirePresented). */
function requirePresented(review: SimRunReview, opStatus: string, promptDigest: string | null, presented: Record<string, unknown> | null): void {
  if (opStatus === "completed" && (promptDigest === null || presented === null)) throw refuse("INVALID_ARGUMENT", "a completed review the custodian captured names its promptDigest and what it presented");
  if (!presented) return;
  const offered = new Map((((review.begin["discussion"] as Record<string, unknown>)?.["offered"] ?? []) as { itemId: string; responseIds: string[]; replyIds: string[] }[]).map((d) => [d.itemId, d]));
  for (const d of (presented["discussion"] as { delivered: { itemId: string; responseIds: string[]; replyIds: string[] }[] }).delivered) {
    const o = offered.get(d.itemId);
    if (!o) throw refuse("EVIDENCE_NOT_HELD", `delivered item ${d.itemId} was not offered by the review's reservation`);
    for (const r of d.responseIds) if (!o.responseIds.includes(r)) throw refuse("EVIDENCE_NOT_HELD", `delivered response ${r} on item ${d.itemId} was not offered by the review's reservation`);
    for (const r of d.replyIds) if (!o.replyIds.includes(r)) throw refuse("EVIDENCE_NOT_HELD", `delivered reply ${r} on item ${d.itemId} was not offered by the review's reservation`);
  }
  const amendments = new Map((((review.begin["amendments"] as Record<string, unknown>)?.["offered"] ?? []) as { amendmentId: string; disclosureDigest: string | null }[]).map((a) => [a.amendmentId, a.disclosureDigest]));
  const pa = presented["amendments"] as { presented: { amendmentId: string; disclosureDigest: string | null }[]; withheld: string[] };
  for (const a of pa.presented) {
    if (!amendments.has(a.amendmentId) || amendments.get(a.amendmentId) !== a.disclosureDigest) throw refuse("EVIDENCE_NOT_HELD", `presented amendment ${a.amendmentId} was not offered by the review's reservation with that disclosure digest`);
  }
  for (const w of pa.withheld) if (!amendments.has(w)) throw refuse("EVIDENCE_NOT_HELD", `withheld amendment ${w} was not offered by the review's reservation`);
}

/**
 * The commit of a measurement (CommitCapture), in one hold: the operation must still be measuring under this ticket; the
 * run open; the writer alive; the basis usable; the capture stable and of the selected source. Then the review input
 * identity and the deduplication. Returns whether the published export is kept and the commit's result (null when the
 * operation is no longer measuring under this ticket: nothing is recorded).
 */
export function commitCapture(store: SimRunStore, t: SimCaptureTicket, end: SimCaptureEnd, writerGone: (w: SimWriter) => boolean | null, nowMs: number): { keep: boolean; result: Record<string, unknown> | null } {
  const key = runKey(t.repoKey, t.runId);
  const run = store.runs[key];
  const op = run?.operations.find((o) => o.operationId === t.operationId);
  if (!run || !op || op.status !== "measuring" || op.ticket !== t.ticket) return { keep: false, result: null };
  const review = run.reviews.find((r) => r.operationId === op.operationId)!;
  let status = "error";
  let reason: string | null = null;
  let detail: string | null = null;
  let dedup: Record<string, unknown> | null = null;
  let reviewInputId: string | null = null;
  const cap = end.capture;
  if (isRunTerminal(run)) [status, reason, detail] = ["cancelled", "run_ended", `the run ended (${run.status}) while the custodian captured`];
  else if (!end.captured) [status, reason, detail] = [end.reason === "cancelled" ? "cancelled" : "error", end.reason, end.detail];
  else if (writerGone(op.writer) === true) [status, reason, detail] = ["interrupted", "owner_died", "the operation's writer ended while the custodian captured"];
  else if (review.evidenceEpoch !== run.evidenceEpoch) [reason, detail] = ["basis_changed", "the evidence epoch changed while the custodian captured"];
  else if (reviewBasisProblem(store.config, run.repoKey, op.pin) !== null) [reason, detail] = ["basis_changed", reviewBasisProblem(store.config, run.repoKey, op.pin)];
  else if (!cap!.stable) [reason, detail] = ["source_unstable", "the working tree changed during the capture (the two-pass stability check)"];
  else if (cap!.sourceId !== op.begin["selectionSourceId"]) [reason, detail] = ["source_changed", "the captured source is not the source the engine selected the check evidence and discussion for; begin the review again"];
  else {
    reviewInputId = custodianReviewInputId(op.begin, cap!);
    const dup = run.reviews.find((r) => r.accepted === true && r.evidenceEpoch === run.evidenceEpoch && r.begin["reviewInputId"] === reviewInputId
      && reviewBasisProblem(store.config, run.repoKey, run.operations.find((o) => o.operationId === r.operationId)?.pin) === null);
    if (dup) {
      status = "deduplicated";
      reason = "deduplicated";
      detail = `an accepted review of the same inputs (${dup.reviewId}, round ${dup.round}) exists in this evidence epoch`;
      dedup = { deduplicatedOf: dup.reviewId, round: dup.round };
    } else status = "captured";
  }
  let next: SimRun;
  const result: Record<string, unknown> = { operationId: op.operationId, ticket: t.ticket, operationStatus: status };
  if (status === "captured") {
    // Phase 5 F-i2-5 (GrantLedger.Capture.cs): the record is also held as redaction evidence, beyond the export's retention.
    if (cap!.recordText !== undefined) (store.evidence ??= {})[evidenceKey(t.repoKey, t.runId, cap!.captureDigest)] = cap!.recordText;
    const begin: Record<string, unknown> = {
      ...structuredClone(op.begin), sourceId: cap!.sourceId, captureId: cap!.captureId, captureStable: cap!.stable, captureDigest: cap!.captureDigest,
      manifestDigest: cap!.manifestDigest, exportDigest: cap!.exportDigest, reviewInputId,
      custodianCapture: { ticket: t.ticket, exportPath: cap!.exportPath, capturePath: cap!.capturePath, manifestContentDigest: cap!.manifestContentDigest, fileCount: cap!.fileCount, totalBytes: cap!.totalBytes, capturedAt: iso(nowMs) },
    };
    const incidents = [...run.incidents];
    const ids: string[] = [];
    if ((begin["isolation"] as Record<string, unknown> | undefined)?.["mode"] === "S2" && incidents.length < SIM_RUN_LIMITS.maxIncidentsPerRun) {
      const inc: SimRunIncident = { incidentId: newId("inc", incidents.length + 1), kind: "isolation_reduced", operationId: op.operationId, reviewId: review.reviewId, detail: "this review runs with reduced read isolation (S2)", at: iso(nowMs), source: "custodian" };
      incidents.push(inc);
      ids.push(inc.incidentId);
    }
    next = {
      ...run,
      operations: replaceOp(run, { ...op, status: "captured", begin: structuredClone(begin) }),
      reviews: run.reviews.map((r) => (r.reviewId === review.reviewId ? { ...r, begin, incidentIds: [...r.incidentIds, ...ids] } : r)),
      incidents,
    };
    Object.assign(result, { sourceId: cap!.sourceId, reviewInputId, exportDigest: cap!.exportDigest });
    // §3.2 retention: the new capture may push the run's oldest published export out (removed after the hold).
    const retained = retireExports(next, nowMs, store.retired);
    if (retained !== next) result["exportsRetired"] = retiredCount(retained) - retiredCount(next);
    next = retained;
  } else {
    next = endMeasurement(run, op, status, reason!, detail, nowMs, dedup);
    result["reason"] = reason;
    if (dedup) Object.assign(result, dedup);
  }
  next = custodianEvent(next, run, "capture", t.ticket, result, nowMs);
  requireProjectionWithinCap(next);
  store.runs[key] = next;
  return { keep: status === "captured", result: structuredClone(next.events.at(-1)!.result) };
}

/** N5-18 (ReconcileCapturesAtStart): every persisted measuring operation is interrupted (an incident; budget released).
 * Returns the number interrupted and the export directories the held captured reviews reference. */
export function reconcileCapturesAtStart(store: SimRunStore, nowMs: number): { interrupted: number; referenced: Set<string> } {
  let interrupted = 0;
  const referenced = new Set<string>();
  for (const [key, run] of Object.entries(store.runs)) {
    let cur = run;
    // P3.4C-5 Increment 3: an execution whose end the previous instance was measuring is recorded without its end.
    for (const op of run.operations.filter((o) => o.pending)) {
      let recorded = recordUnmeasuredPending(cur, cur.operations.find((o) => o.operationId === op.operationId)!, "measurement_interrupted: the custodian restarted while it measured", nowMs);
      if (recorded.incidents.length < SIM_RUN_LIMITS.maxIncidentsPerRun) {
        recorded = { ...recorded, incidents: [...recorded.incidents, { incidentId: newId("inc", recorded.incidents.length + 1), kind: "measurement_interrupted", operationId: op.operationId, reviewId: null, detail: "the custodian restarted while it measured the end of a check execution; it was recorded without its end", at: iso(nowMs), source: "custodian" }] };
      }
      cur = custodianEvent(recorded, cur, "reconcile", `reconcile-pending-${op.operationId}`, { operationId: op.operationId, reason: "measurement_interrupted" }, nowMs);
      interrupted++;
    }
    for (const op of run.operations.filter((o) => o.status === "measuring")) {
      const ended = endMeasurement(cur, cur.operations.find((o) => o.operationId === op.operationId)!, "interrupted", "measurement_interrupted",
        "the custodian restarted while it measured (the measurement's ticket belonged to the previous service instance)", nowMs, null, true);
      cur = custodianEvent(ended, cur, "reconcile", `reconcile-${op.operationId}`, { operationId: op.operationId, operationStatus: "interrupted", reason: "measurement_interrupted" }, nowMs);
      interrupted++;
    }
    if (cur !== run) store.runs[key] = cur;
    for (const r of cur.reviews) {
      const p = (r.begin["custodianCapture"] as Record<string, unknown> | undefined)?.["exportPath"];
      if (typeof p === "string") referenced.add(p);
    }
  }
  return { interrupted, referenced };
}

// ---------------------------------------------------------------------------
// P3.4C-5 Increment 3 (§4): the commits of a checks operation's measurements (GrantLedger.Checks.cs)
// ---------------------------------------------------------------------------

/** The commit of a checks operation's START measurement (CommitCheckStart); returns its event's result, or null. */
export function commitCheckStart(store: SimRunStore, t: SimCheckTicket, o: SimMeasureOutcome, writerGone: (w: SimWriter) => boolean | null, nowMs: number): Record<string, unknown> | null {
  const key = runKey(t.repoKey, t.runId);
  const run = store.runs[key];
  const op = run?.operations.find((x) => x.operationId === t.operationId);
  if (!run || !op || op.status !== "measuring" || op.ticket !== t.ticket) return null;
  let status: string;
  let reason: string | null = null;
  let detail: string | null = null;
  if (isRunTerminal(run)) [status, reason, detail] = ["cancelled", "run_ended", `the run ended (${run.status}) while the custodian measured`];
  else if (!o.ok) [status, reason, detail] = [o.code === "MEASUREMENT_CANCELLED" ? "cancelled" : "error", measurementReason(o.code), `${o.code}: ${(o.detail ?? "").slice(0, 400)}`];
  else if (writerGone(op.writer) === true) [status, reason, detail] = ["interrupted", "owner_died", "the operation's writer ended while the custodian measured"];
  else if (checkBasisProblem(store.config, t.repoKey, op) !== null) [status, reason, detail] = ["error", "basis_changed", checkBasisProblem(store.config, t.repoKey, op)];
  else status = "running";
  const result: Record<string, unknown> = { operationId: op.operationId, ticket: t.ticket, operationStatus: status, measurement: "start" };
  let next: SimRun;
  if (status === "running") {
    const m = measurementRecord(o.measured!, t.ticket, nowMs);
    next = { ...run, operations: replaceOp(run, { ...op, status: "running", begin: { ...structuredClone(op.begin), custodianMeasurement: structuredClone(m) }, measured: m }) };
    result["sourceId"] = m["sourceId"];
    result["stable"] = m["stable"];
  } else {
    next = endMeasurement(run, op, status, reason!, detail, nowMs);
    result["reason"] = reason;
  }
  next = custodianEvent(next, run, "check_measure", t.ticket, result, nowMs);
  requireProjectionWithinCap(next);
  store.runs[key] = next;
  return structuredClone(next.events.at(-1)!.result);
}

/** §2.4 revalidation of a checks operation's start (GrantLedger.Checks.cs CheckBasisProblem): the repository's record in
 * force, not lapsed, still approving every planned definition. */
export function checkBasisProblem(config: SimConfigFile, repoKey: string, op: SimRunOperation): string | null {
  const cur = currentOf(config, repoKey);
  if (!cur || cur.revokedAt !== null) return "the repository's protected configuration was revoked while the custodian measured; no check ran";
  if (cur.lapsedAtRecoveryId !== null) return "the repository's protected configuration lapsed while the custodian measured; no check ran";
  for (const p of (op.begin["planned"] as Record<string, unknown>[] | undefined) ?? []) {
    const digest = p["definitionDigest"];
    if (typeof digest === "string" && cur.checks[String(p["check"])]?.definitionDigest !== digest) {
      return `check ${String(p["check"])} is no longer approved with the definition the operation planned (the configuration changed while the custodian measured); no check ran`;
    }
  }
  return null;
}

/** The commit of an execution's END measurement (CommitCheckEnd); returns its event's result, or null. */
export function commitCheckEnd(store: SimRunStore, t: SimCheckTicket, o: SimMeasureOutcome, nowMs: number): Record<string, unknown> | null {
  const key = runKey(t.repoKey, t.runId);
  const run = store.runs[key];
  const op = run?.operations.find((x) => x.operationId === t.operationId);
  if (!run || !op?.pending || op.pending["ticket"] !== t.ticket || isRunTerminal(run)) return null;
  const end = o.ok ? measurementRecord(o.measured!, t.ticket, nowMs) : null;
  const { stored, mismatched } = measuredExecution(run, op, op.pending["execution"] as Record<string, unknown>, op.measured ?? null, end, o.ok ? null : `${measurementReason(o.code)}: ${(o.detail ?? "").slice(0, 400)}`, t.ticket, nowMs);
  const done: SimRunOperation = { ...op, pending: null, measured: end ?? op.measured ?? null };
  let next: SimRun = { ...run, checkExecutions: [...run.checkExecutions, stored], operations: replaceOp(run, done) };
  const result: Record<string, unknown> = { operationId: op.operationId, ticket: t.ticket, measurement: "end", executionId: stored["executionId"] ?? null, measured: o.ok, sourceStable: stored["sourceStable"] };
  if (!o.ok) result["reason"] = measurementReason(o.code);
  if (mismatched.length) result["ignoredClaims"] = [...mismatched];
  next = custodianEvent(next, run, "check_record", t.ticket, result, nowMs);
  requireProjectionWithinCap(next);
  store.runs[key] = next;
  return structuredClone(next.events.at(-1)!.result);
}

// ---------------------------------------------------------------------------
// Phase 4 Increment 2: the delegated fix (GrantLedger.Fix.cs; contract §3.2, §3.4)
// ---------------------------------------------------------------------------

const proposalOf = (o: SimRunOperation): Record<string, unknown> | null => {
  const p = o.outcome?.["proposal"];
  return p && typeof p === "object" && !Array.isArray(p) ? (p as Record<string, unknown>) : null;
};

/** The reviews whose published capture a fix still needs: one in flight, or one whose proposal is not retired and still
 * waits for the owner or its application (Increment 3 renders and applies from it). */
function fixBaselinesHeld(run: SimRun): string[] {
  const out: string[] = [];
  for (const o of run.operations) {
    if (o.kind !== "fix") continue;
    const p = proposalOf(o);
    if (isActiveOperation(o.status) || (isFixAwaiting(o) && p !== null && p["retiredAt"] == null)) {
      out.push(String((o.begin["custodianBaseline"] as Record<string, unknown> | undefined)?.["reviewId"]));
    }
  }
  return out;
}

/**
 * Begin a delegated fix (op_begin, operationKind fix): P4-A — the repository's protected configuration in force with an
 * approved Codex installation; the FIX vs S1 separation — an operator-confirmed FIX self-test for this Codex version,
 * binary, backend and fixer profile; the engine's Codex image the approved one; the run's fix budget; then the baseline —
 * a finished review of this run whose published capture the custodian still holds and found unchanged (read before the
 * hold). The custodian binds the boundary (by digest), the task digest and its own record of the baseline capture.
 */
function fixBegin(store: SimRunStore, run: SimRun, req: SimRunRequest, writer: SimWriter, seq: number, nowMs: number): RunStep {
  const f = req.fields;
  const cfg = requireUsableConfig(store.config, run.repoKey, "a delegated fix");
  const install = cfg.codexInstallation;
  if (!install) throw refuse("CONFIG_NOT_HELD", "the repository's protected configuration has no approved Codex installation; a delegated fix is refused — the operator sets one with `code-parley config set --repo <path> --codex <codex.exe>`");
  const basis = requireFixBasis(store.config, f["isolation"] as Record<string, unknown>, install.sha256);
  if (f["codexSha256"] !== install.sha256) throw refuse("CONFIG_MISMATCH", "the Codex image the engine reports is not the approved installation; nothing was begun");
  const used = fixesBegun(run);
  const limit = fixLimit(run);
  if (used >= limit) throw refuse("BUDGET_EXHAUSTED", `fixes: ${used} of ${limit} used`);
  const fixId = f["fixId"] as string;
  if (run.operations.some((o) => o.kind === "fix" && o.begin["fixId"] === fixId)) throw invalid(`fix id ${fixId} was already used in this run`);
  const reviewId = f["baselineReviewId"] as string;
  const review = run.reviews.find((r) => r.reviewId === reviewId);
  const cap = review ? captureOf(review.begin) : null;
  const reviewOp = review ? run.operations.find((o) => o.operationId === review.operationId) : undefined;
  if (!review || !cap || cap["retiredAt"] != null || !reviewOp || isActiveOperation(reviewOp.status)) {
    throw refuse("EVIDENCE_NOT_HELD", `review ${reviewId} is not a finished review of this run whose published capture the custodian still holds; nothing was begun`);
  }
  const read = store.fixBaseline ?? null;
  if (!read || read.reviewId !== reviewId || !read.unchanged || !read.tree) {
    throw refuse("EVIDENCE_NOT_HELD", `the published capture of review ${reviewId} cannot be vouched for as the fix's baseline (${read?.detail ?? "it was not read"}); nothing was begun`);
  }
  const boundary = f["boundary"] as SimFixBoundary;
  const boundaryDigest = fixBoundaryDigest(boundary);
  const baseline = {
    reviewId, reviewOperationId: review.operationId, sourceId: review.begin["sourceId"], captureId: review.begin["captureId"], exportDigest: review.begin["exportDigest"],
    manifestDigest: review.begin["manifestDigest"], captureDigest: review.begin["captureDigest"], treeFiles: read.tree.size, treeDigest: fixTreeDigest(read.tree),
  };
  const pin: SimOperationPin = { configRevision: cfg.configRevision, configDigest: cfg.configDigest, isolationKind: basis.kind, isolationRecordId: basis.id, isolationGlobalRevision: basis.globalRevision, captureRulesDigest: null, codexSha256: install.sha256 };
  const op: SimRunOperation = { operationId: newId("fop", seq), seq, kind: "fix", status: "running", beganAt: iso(nowMs), endedAt: null, writer, begin: { ...structuredClone(f), boundaryDigest, custodianBaseline: baseline }, outcome: null, pin };
  return {
    next: { ...run, operations: [...run.operations, op], status: "fixing" },
    result: {
      operationId: op.operationId, fixId, configRevision: cfg.configRevision, operationStatus: "running", boundaryDigest,
      baseline: { reviewId, sourceId: baseline.sourceId, treeFiles: baseline.treeFiles }, fixesUsed: used + 1, maxFixes: limit,
    },
  };
}

/**
 * Finish a delegated fix (op_finish of a fix): what the engine reports is recorded as its claim; only a `completed` fix
 * submits content, which the custodian validates ITSELF against the boundary it bound and its own baseline capture (read
 * again before the hold, and still the one bound) — trusting no engine digest or preimage. Valid content is held in the
 * custodian's private store under the custodian-computed proposal digest (`proposed`); anything else is `rejected` with
 * the custodian's violations. A proposal awaiting confirmation is not progress (the derivation routes it to an await).
 */
function fixFinish(store: SimRunStore, run: SimRun, op: SimRunOperation, req: SimRunRequest, runStatus: string, nowMs: number): RunStep {
  const outcome = apply(FIX_OUTCOME, req.fields["outcome"], "fields.outcome");
  const reported = outcome["status"] as string;
  const changes = outcome["changes"] as SimFixSubmittedChange[];
  if ((reported === "completed") !== (changes.length > 0)) throw invalid("fields.outcome.changes are submitted with a completed fix, and only with one");
  const begin = op.begin;
  const boundary = begin["boundary"] as SimFixBoundary;
  const baseline = begin["custodianBaseline"] as Record<string, unknown>;
  const stored: Record<string, unknown> = {
    status: reported, reportedStatus: reported, scan: structuredClone(outcome["scan"] ?? null), detail: outcome["detail"] ?? null, proposal: null, violations: [], violationCount: 0,
  };
  let opStatus = reported;
  let held: SimHeldProposal | null = null;
  // The basis the fix was begun under, re-checked at its finish (as a review's at its completion).
  const basisProblem = reported === "completed" ? fixBasisProblem(store.config, run.repoKey, op.pin) : null;
  if (basisProblem !== null) {
    opStatus = "rejected";
    Object.assign(stored, { status: "rejected", violations: [{ kind: "basis_changed", path: null }], violationCount: 1, basisProblem });
  } else if (reported === "completed") {
    const read = store.fixBaseline ?? null;
    const intact = read !== null && read.reviewId === baseline["reviewId"] && read.unchanged && read.tree !== null && fixTreeDigest(read.tree) === baseline["treeDigest"];
    const verdict = intact ? validateFixSubmission(boundary, read!.tree!, changes) : { violations: [{ kind: "baseline_unavailable" as const, path: null }], canonical: null, totalBytes: 0 };
    if (verdict.canonical === null) {
      opStatus = "rejected";
      Object.assign(stored, { status: "rejected", violations: verdict.violations.slice(0, SIM_FIX_LIMITS.maxViolationsReported), violationCount: verdict.violations.length });
    } else {
      opStatus = "proposed";
      const proposalDigest = fixProposalDigest({
        runId: run.runId, operationId: op.operationId, fixId: String(begin["fixId"]), taskDigest: String(begin["taskDigest"]), boundaryDigest: String(begin["boundaryDigest"]),
        baseline: { reviewId: String(baseline["reviewId"]), sourceId: String(baseline["sourceId"]), exportDigest: String(baseline["exportDigest"]), manifestDigest: String(baseline["manifestDigest"]) },
        changes: verdict.canonical,
      });
      stored["status"] = "proposed";
      stored["proposal"] = {
        proposalDigest, createdAt: iso(nowMs), expiresAt: iso(nowMs + boundary.proposalLifetimeSeconds * 1000), changeCount: verdict.canonical.length, totalBytes: verdict.totalBytes,
        changes: verdict.canonical.map((c) => ({ path: c.path, kind: c.kind, executable: c.executable, preimage: c.preimage, postimage: c.postimage })),
        retiredAt: null, retiredReason: null,
      };
      held = { repoKey: run.repoKey, runId: run.runId, operationId: op.operationId, proposalDigest, changes: verdict.canonical };
    }
  }
  // The canonical content goes to the custodian's private store in this hold, before the record that names it.
  if (held) (store.fixProposals ??= {})[proposalKey(run.repoKey, run.runId, op.operationId)] = held;
  const p = stored["proposal"] as Record<string, unknown> | null;
  return {
    next: { ...run, operations: replaceOp(run, { ...op, status: opStatus, endedAt: iso(nowMs), outcome: stored }), status: runStatus },
    result: {
      operationId: op.operationId, operationStatus: opStatus,
      proposal: p ? { proposalDigest: p["proposalDigest"], changeCount: p["changeCount"], totalBytes: p["totalBytes"], expiresAt: p["expiresAt"] } : null,
      violations: structuredClone(stored["violations"]), violationCount: stored["violationCount"],
    },
  };
}

/** Is the basis a fix was begun under still in force (FixBasisProblem)? null: yes; else why not. */
function fixBasisProblem(config: SimConfigFile, repoKey: string, pin: SimOperationPin | null | undefined): string | null {
  if (!pin) return "isolation_basis_revoked";
  const iso = isolationBasisProblem(config, pin.isolationKind, pin.isolationRecordId);
  if (iso !== null) return iso;
  const cur = currentOf(config, repoKey);
  if (!cur || cur.revokedAt !== null) return "config_changed_since_fix";
  if (cur.lapsedAtRecoveryId !== null) return "config_lapsed";
  if (cur.codexInstallation?.sha256 !== pin.codexSha256) return "config_changed_since_fix";
  return null;
}

/** The held proposals a run still references: a fix whose proposal is not retired — proposed, confirmed, or consumed by an
 * application that has not ended. */
const referencedProposals = (run: SimRun): string[] =>
  run.operations.filter((o) => o.kind === "fix" && (o.status === "proposed" || o.status === FIX_CONFIRMED || o.status === FIX_CONSUMED) && proposalOf(o)?.["retiredAt"] == null).map((o) => proposalKey(run.repoKey, run.runId, o.operationId));

/** Retire every proposal whose run ended or whose lifetime is over (the record says when and why; the held content is
 * removed). The same instance when nothing changes. */
// ---- Phase 5 F-i2-5: redaction evidence (GrantLedger.Evidence.cs) ----

export const evidenceKey = (repoKey: string, runId: string, sha256: string): string => `${repoKey}\u0000${runId}\u0000${sha256}`;

/** A user record as the redaction basis reads it (the custodian's user-record log). */
export interface BasisUserRecord {
  recordKind: string;
  seq: number;
  payload: Record<string, unknown>;
  disclosureDigest: string | null;
}

/** Every record the run's withheld names come from, as the run record and its user-record log bind them
 * (GrantLedger.EvidenceOf): Phase 5 OI-1 adds each custodian-redacted amendment's read disclosure record. */
export function evidenceRefsOf(run: SimRun, userRecords: readonly BasisUserRecord[] = []): { kind: "capture" | "disclosure"; sha256: string; label: string }[] {
  const out: { kind: "capture" | "disclosure"; sha256: string; label: string }[] = [];
  const seen = new Set<string>();
  const add = (kind: "capture" | "disclosure", sha: unknown, label: string) => {
    if (typeof sha === "string" && sha.length === 64 && !seen.has(`${kind}:${sha}`)) {
      seen.add(`${kind}:${sha}`);
      out.push({ kind, sha256: sha, label });
    }
  };
  add("capture", run.declaration.baseline?.digest, "the baseline capture record");
  for (const r of run.reviews) add("capture", r.begin["captureDigest"], `the capture record of review ${r.reviewId}`);
  for (const x of run.responses) add("disclosure", x["disclosureDigest"], `the disclosure record of response set ${String(x["responseSetId"])}`);
  for (const r of userRecords) if (r.recordKind === "amendment") add("disclosure", r.payload["read_disclosure_digest"], `the read disclosure record of amendment A-${r.seq}`);
  return out;
}

/** Phase 5 OI-1 (GrantLedger.UnestablishedAmendment): an amendment with reviewer-visible text whose read disclosure the
 * custodian does not hold, or null. */
export function unestablishedAmendment(userRecords: readonly BasisUserRecord[]): BasisUserRecord | null {
  return userRecords.find((r) => r.recordKind === "amendment" && r.disclosureDigest !== null && r.payload["read_disclosure_digest"] == null) ?? null;
}

/** The digest of a redaction basis (GrantLedger.BasisDigest). */
export function redactionBasisDigest(repoKey: string, runId: string, refs: readonly { kind: string; sha256: string }[]): string {
  return sha256OfCanonicalJson({ schema: "codeparley.redaction-basis.v1", repoKey, runId, evidence: refs.map((r) => [r.kind, r.sha256]) });
}

export function retireFixProposals(run: SimRun, nowMs: number, store: Pick<SimRunStore, "fixProposals">): SimRun {
  const terminal = isRunTerminal(run);
  const due = new Set(run.operations.filter((o) => {
    const p = proposalOf(o);
    // Phase 4 Increment 3: a confirmed proposal expires as a proposed one; an ended run also retires a consumed one.
    return (isFixAwaiting(o) || (terminal && o.kind === "fix" && o.status === FIX_CONSUMED)) && p !== null && p["retiredAt"] == null && (terminal || Date.parse(String(p["expiresAt"])) <= nowMs);
  }).map((o) => o.operationId));
  if (due.size === 0) return run;
  for (const id of due) delete store.fixProposals?.[proposalKey(run.repoKey, run.runId, id)];
  return {
    ...run,
    operations: run.operations.map((o) => (due.has(o.operationId)
      ? { ...o, outcome: { ...structuredClone(o.outcome!), proposal: { ...structuredClone(proposalOf(o)!), retiredAt: iso(nowMs), retiredReason: terminal ? "run_ended" : "expired" } } }
      : o)),
  };
}

/** The number of proposals of `run` retired (for a retention event's result). */
export const retiredProposals = (run: SimRun): number => run.operations.filter((o) => proposalOf(o)?.["retiredAt"] != null).length;

// ---------------------------------------------------------------------------
// Phase 4 Increment 3: the owner's confirmation and the application (GrantLedger.FixApply.cs; contract §3.5, §3.6)
// ---------------------------------------------------------------------------

export const FIX_DECISION_ACTION = "fix_decision";
/** CustodianConstants.FixConfirmationTtlSeconds: how long a confirmation can be used (never past its proposal's lifetime). */
export const SIM_FIX_CONFIRMATION_TTL_MS = 30 * 60 * 1000;
const FIX_CONFIRMED = "confirmed";
const FIX_CONSUMED = "consumed";
const FIX_DECLINED = "declined";
const APPLY_INTERRUPTED = "apply_interrupted";

/** The custodian's read of a held proposal, taken outside the hold (HeldProposalRead). */
export interface SimHeldRead {
  operationId: string;
  problem: string | null;
  status: string | null;
  proposalDigest: string | null;
  boundaryDigest: string | null;
  baselineDigest: string | null;
  rendering: SimRendering | null;
  content: Record<string, unknown>[] | null;
}

/** A measurement of the primary source taken outside the hold (ApplyMeasure). */
export interface SimApplyMeasure {
  sourceId: string | null;
  stable: boolean;
  code: string | null;
  detail: string | null;
}

/** What an application transition reads before the hold (ApplyPre). */
export interface SimApplyPre {
  held: SimHeldRead | null;
  measured: SimApplyMeasure | null;
}

/** What the transport read (under its lock, then from the export) to build a held-proposal read. */
export interface SimHeldInputs {
  run: SimRun | null;
  held: SimHeldProposal | null;
  tree: SimFixBaselineRead | null;
  /** The export's `tree` bytes of each modified or deleted path (null: unreadable). */
  pre: Map<string, Buffer | null>;
}

const isFixAwaiting = (o: SimRunOperation): boolean => o.kind === "fix" && (o.status === "proposed" || o.status === FIX_CONFIRMED);

/** The digest of the baseline a fix bound (BaselineDigestOf). */
export function baselineDigestOf(b: Record<string, unknown>): string {
  return sha256OfCanonicalJson({
    schema: "codeparley.custodian-fix-baseline.v1", reviewId: b["reviewId"] ?? null, sourceId: b["sourceId"] ?? null, exportDigest: b["exportDigest"] ?? null,
    manifestDigest: b["manifestDigest"] ?? null, treeDigest: b["treeDigest"] ?? null,
  });
}

const summaryOf = (c: { path: unknown; kind: unknown; executable: unknown; preimage: unknown; postimage: unknown }): Record<string, unknown> => ({
  path: c.path, kind: c.kind, executable: c.executable, preimage: c.preimage ?? null, postimage: c.postimage ?? null,
});

/** The fix operations of a run whose baseline review the transport must read for a held-proposal read. */
export function heldReadTarget(run: SimRun | null, operationId: string): { reviewId: string; reviewOperationId: string; reviewBegin: Record<string, unknown> | null; paths: string[] } | null {
  const op = run?.operations.find((o) => o.operationId === operationId && o.kind === "fix");
  if (!run || !op) return null;
  const reviewId = String((op.begin["custodianBaseline"] as Record<string, unknown> | undefined)?.["reviewId"] ?? "");
  const review = run.reviews.find((r) => r.reviewId === reviewId);
  return { reviewId, reviewOperationId: review?.operationId ?? "", reviewBegin: review ? structuredClone(review.begin) : null, paths: [] };
}

/** ReadHeldProposal: re-verify the held content against the record and the baseline capture, and render it. */
export function heldProposalRead(id: { canonicalPath: string; key: string }, runId: string, operationId: string, input: SimHeldInputs): SimHeldRead {
  const op = input.run?.operations.find((o) => o.operationId === operationId && o.kind === "fix") ?? null;
  const none: SimHeldRead = { operationId, problem: "the run has no such delegated fix", status: null, proposalDigest: null, boundaryDigest: null, baselineDigest: null, rendering: null, content: null };
  if (!op) return none;
  const begin = op.begin;
  const baseline = begin["custodianBaseline"] as Record<string, unknown>;
  const proposal = proposalOf(op);
  const recordDigest = (proposal?.["proposalDigest"] ?? null) as string | null;
  const fail = (why: string): SimHeldRead => ({ operationId, problem: why, status: op.status, proposalDigest: recordDigest, boundaryDigest: (begin["boundaryDigest"] ?? null) as string | null, baselineDigest: baselineDigestOf(baseline), rendering: null, content: null });
  if (!proposal || recordDigest === null) return fail("the fix holds no proposal");
  if (proposal["retiredAt"] != null) return fail(`the proposal was retired (${String(proposal["retiredReason"])}); its content is no longer held`);
  const tree = input.tree;
  if (!tree || !tree.unchanged || !tree.tree) return fail(`the baseline capture cannot be vouched for (${tree?.detail ?? "it was not read"})`);
  if (fixTreeDigest(tree.tree) !== baseline["treeDigest"]) return fail("the baseline capture is not the tree the fix bound");
  const held = input.held;
  if (!held || held.proposalDigest !== recordDigest) return fail("the held content is not the proposal the record names");
  const canonical: SimFixCanonicalChange[] = [];
  const render: SimRenderChange[] = [];
  const content: Record<string, unknown>[] = [];
  for (const c of held.changes) {
    const post = c.content === null ? null : decodeStrictBase64(c.content);
    if ((c.content === null) !== (c.kind === "delete") || (c.content !== null && post === null)) return fail(`the held content of ${c.path} is malformed`);
    const pre = c.kind === "add" ? null : tree.tree.get(c.path) ?? null;
    if (c.kind !== "add" && !pre) return fail(`${c.path} is not in the baseline capture`);
    if (c.kind === "add" && tree.tree.has(c.path)) return fail(`${c.path} is in the baseline capture`);
    const postimage = post ? { size: post.length, sha256: createHash("sha256").update(post).digest("hex"), binary: post.includes(0) } : null;
    const cc: SimFixCanonicalChange = { path: c.path, kind: c.kind, executable: c.executable, preimage: pre ? { size: pre.size, sha256: pre.sha256 } : null, postimage, content: c.content };
    if (sha256OfCanonicalJson(summaryOf(cc)) !== sha256OfCanonicalJson(summaryOf(c))) return fail(`the held content of ${c.path} does not hash to its record`);
    let preBytes: Buffer | null = null;
    if (pre) {
      preBytes = input.pre.get(c.path) ?? null;
      if (!preBytes) return fail(`the baseline bytes of ${c.path} could not be read`);
      if (preBytes.length !== pre.size || createHash("sha256").update(preBytes).digest("hex") !== pre.sha256) return fail(`the baseline bytes of ${c.path} differ from its preimage`);
    }
    canonical.push(cc);
    render.push({ path: c.path, kind: c.kind, executable: c.executable, preimage: cc.preimage, postimage, pre: preBytes, post });
    content.push({ ...summaryOf(cc), content: c.content });
  }
  const bound = { reviewId: String(baseline["reviewId"]), sourceId: String(baseline["sourceId"]), exportDigest: String(baseline["exportDigest"]), manifestDigest: String(baseline["manifestDigest"]) };
  const recomputed = fixProposalDigest({ runId, operationId, fixId: String(begin["fixId"]), taskDigest: String(begin["taskDigest"]), boundaryDigest: String(begin["boundaryDigest"]), baseline: bound, changes: canonical });
  if (recomputed !== recordDigest) return fail("the held content does not recompute to the proposal digest");
  const rendering = renderProposal(
    {
      runId, repositoryPath: id.canonicalPath, repoKey: id.key, fixId: String(begin["fixId"]), operationId, reviewId: String(baseline["reviewId"]), sourceId: String(baseline["sourceId"] ?? ""),
      taskDigest: String(begin["taskDigest"]), proposalDigest: recordDigest, expiresAt: String(proposal["expiresAt"]), boundaryDigest: String(begin["boundaryDigest"]), totalBytes: Number(proposal["totalBytes"] ?? 0),
    },
    begin["boundary"] as Record<string, unknown>,
    render,
  );
  return { operationId, problem: null, status: op.status, proposalDigest: recordDigest, boundaryDigest: String(begin["boundaryDigest"]), baselineDigest: baselineDigestOf(baseline), rendering, content };
}

const fixOperationOf = (run: SimRun, operationId: string): SimRunOperation => {
  const op = run.operations.find((o) => o.operationId === operationId && o.kind === "fix");
  if (!op) throw refuse("EVIDENCE_NOT_HELD", `the run has no delegated fix ${operationId}`);
  return op;
};

/** RequirePending: a proposal awaiting the owner — proposed, not retired, inside its lifetime, on an open run. */
export function requirePendingProposal(run: SimRun, op: SimRunOperation, nowMs: number): void {
  if (isRunTerminal(run)) throw refuse("RUN_TERMINAL", `the run has ended (${run.status}); nothing was prepared`);
  const p = proposalOf(op);
  if (op.status !== "proposed" || !p) throw refuse("PROPOSAL_NOT_PENDING", `delegated fix ${op.operationId} has no proposal awaiting the owner (it is ${op.status})`);
  if (p["retiredAt"] != null || Date.parse(String(p["expiresAt"])) <= nowMs) throw refuse("PROPOSAL_NOT_PENDING", `the proposal of delegated fix ${op.operationId} has expired; nothing was prepared`);
}

/** FixDecisionStateDigest: the "state shown" a fix decision's commit re-derives (with the rendering produced now). */
export function fixDecisionStateDigest(run: SimRun | null, operationId: string, renderingDigest: string | null): string {
  const op = run?.operations.find((o) => o.operationId === operationId && o.kind === "fix") ?? null;
  const p = op ? proposalOf(op) : null;
  const b = op?.begin["custodianBaseline"] as Record<string, unknown> | undefined;
  return sha256OfCanonicalJson({
    schema: "codeparley.custodian-fix-decision-state.v1",
    runTerminal: run ? isRunTerminal(run) : null, status: op?.status ?? null, proposalDigest: p?.["proposalDigest"] ?? null, retiredAt: p?.["retiredAt"] ?? null,
    boundaryDigest: op?.begin["boundaryDigest"] ?? null, baseline: b ? baselineDigestOf(b) : null, renderingDigest,
  });
}

/** PrepareFixDecision (the hold part): the intent's args, state digest and rendering text. */
export function prepareFixDecision(store: SimRunStore, id: { canonicalPath: string; key: string }, runId: string, operationId: string, decision: string, read: SimHeldRead | null, nowMs: number, expected: SimFixSelection | null = null): { args: Record<string, unknown>; stateDigest: string; rendering: string; facts: Record<string, unknown> } {
  if (decision !== "confirm" && decision !== "reject") throw invalid("decision must be 'confirm' or 'reject'");
  // Step 7.1: the path the operator's selection reached must still be the repository identity that was listed.
  if (expected && id.key !== expected.repoKey) {
    throw refuse("SELECTION_STALE", `the repository path now resolves to identity ${id.key}, not the identity that was selected (${expected.repoKey}); nothing was prepared — list and review again`);
  }
  const run = store.runs[runKey(id.key, runId)];
  if (!run) throw refuse("RUN_NOT_OPEN", "the custodian holds no record of this run");
  const op = fixOperationOf(run, operationId);
  requirePendingProposal(run, op, nowMs);
  if (!read || read.problem !== null || !read.rendering) throw refuse("EVIDENCE_NOT_HELD", `the custodian cannot render delegated fix ${operationId}, so nothing can be confirmed: ${read?.problem ?? "it was not read"}`);
  const p = proposalOf(op)!;
  const baseline = op.begin["custodianBaseline"] as Record<string, unknown>;
  if (p["proposalDigest"] !== read.proposalDigest || op.begin["boundaryDigest"] !== read.boundaryDigest || baselineDigestOf(baseline) !== read.baselineDigest) {
    throw refuse("CONFIRMATION_CONTENT_MISMATCH", "the proposal changed while the custodian rendered it; nothing was prepared — prepare it again");
  }
  // Step 7.1: a guided selection is prepared only for the proposal and the exact rendering the operator reviewed.
  if (expected && read.proposalDigest !== expected.proposalDigest) {
    throw refuse("SELECTION_STALE", `delegated fix ${operationId} now holds another proposal than the one that was selected; nothing was prepared — list and review again`);
  }
  if (expected && read.rendering.digest !== expected.renderingDigest) {
    throw refuse("SELECTION_STALE", `the custodian's rendering of delegated fix ${operationId} is not the one that was reviewed; nothing was prepared — review it again`);
  }
  const args = {
    repositoryRoot: id.canonicalPath, repoKey: id.key, runId, operationId, decision, proposalDigest: read.proposalDigest, renderingDigest: read.rendering.digest, boundaryDigest: read.boundaryDigest,
    baselineDigest: read.baselineDigest, baselineSourceId: baseline["sourceId"] ?? null,
  };
  const authority = fixDecisionAuthority(decision, runId, operationId);
  const rendering = authority.header + read.rendering.text + authority.footer;
  const facts = {
    schema: FIX_DECISION_FACTS_SCHEMA, decision, repoKey: id.key, repositoryRoot: id.canonicalPath, runId, operationId, proposalDigest: read.proposalDigest,
    renderingDigest: read.rendering.digest, baselineSourceId: baseline["sourceId"] ?? null, authorityHeader: authority.header, authorityFooter: authority.footer,
    consequences: authority.consequences,
  };
  return { args, stateDigest: fixDecisionStateDigest(run, operationId, read.rendering.digest), rendering, facts };
}

/** Step 7.1 (GrantLedger.FixDecisionFactsSchema): the structured facts of a prepared fix decision. */
export const FIX_DECISION_FACTS_SCHEMA = "codeparley.custodian-fix-decision-prepared.v1";

/** FixDecisionAuthority: the authority text around the custodian's rendering (header + rendering + footer) and its
 * consequences as codes. */
export function fixDecisionAuthority(decision: string, runId: string, operationId: string): { header: string; footer: string; consequences: string[] } {
  return decision === "confirm"
    ? {
        header: `Confirm delegated fix ${operationId} of run ${runId}: CodeParley may apply EXACTLY the content below, once.\n\n`,
        footer: "\nThe confirmation is single use and bound to this rendering (sha256 above), the proposal digest, this repository and run, and the baseline source.\n"
          + "The application re-checks that the working tree still matches the baseline (FIX_STALE otherwise) and writes only this content.\n"
          + "It authorizes no commit, push, merge, tag or release.",
        consequences: ["applies_exactly_this_content_once", "bound_to_this_rendering", "rechecks_the_baseline", "authorizes_no_commit_push_merge_tag_or_release"],
      }
    : {
        header: `Reject delegated fix ${operationId} of run ${runId}: the proposal below is closed and its content removed; nothing is applied.\n\n`,
        footer: "",
        consequences: ["closes_the_proposal", "removes_its_content", "applies_nothing"],
      };
}

/** Step 7.1 (GrantLedger.FixSelection): a guided selection's expected values. */
export interface SimFixSelection {
  repoKey: string;
  proposalDigest: string;
  renderingDigest: string;
}

const SELECTION_KEYS = ["expectedRepoKey", "expectedProposalDigest", "expectedRenderingDigest"] as const;

/** CustodianCore.ExpectedSelectionOf: all three or none; one or two, or a value of the wrong type or form, is MALFORMED_REQUEST. */
export function expectedSelectionOf(args: Record<string, unknown>): SimFixSelection | null {
  const present = SELECTION_KEYS.filter((k) => k in args).length;
  if (present === 0) return null;
  if (present !== SELECTION_KEYS.length) throw refuse("MALFORMED_REQUEST", "a guided selection names all three expected values (expectedRepoKey, expectedProposalDigest, expectedRenderingDigest), or none");
  const hex = (s: string) => /^[0-9a-f]{64}$/.test(s);
  const key = (s: string) => s.length > 0 && s.length <= 256 && /^[\x21-\x7e]+$/.test(s);
  const value = (k: (typeof SELECTION_KEYS)[number], ok: (s: string) => boolean, what: string): string => {
    const v = args[k];
    if (typeof v !== "string" || !ok(v)) throw refuse("MALFORMED_REQUEST", `'${k}' must be ${what}`);
    return v;
  };
  return {
    repoKey: value("expectedRepoKey", key, "a repository identity of this custodian's scheme"),
    proposalDigest: value("expectedProposalDigest", hex, "64 lowercase hex digits"),
    renderingDigest: value("expectedRenderingDigest", hex, "64 lowercase hex digits"),
  };
}

// ---- Step 7.1: the operator's listing of the delegated fixes (GrantLedger.ListFixProposals) ----

export const FIX_LISTING_SCHEMA = "codeparley.custodian-fix-listing.v1";
export const MAX_LISTED_FIXES = 50;
export const MAX_LISTED_PATHS = 10;
export const LISTED_FIX_STATES = ["pending", "unavailable", "waiting", "expired", "ineligible"];

/** A fix the listing considers, with the run it belongs to. */
export interface SimListedFix {
  run: SimRun;
  op: SimRunOperation;
}

/** The fixes a listing considers: proposed or confirmed, with a proposal, of `only` (a repoKey) if given. */
export function listableFixes(runs: SimRun[], only: string | null): SimListedFix[] {
  const out: SimListedFix[] = [];
  for (const run of runs) {
    if (only !== null && run.repoKey !== only) continue;
    for (const op of run.operations) if (op.kind === "fix" && proposalOf(op) !== null && (op.status === "proposed" || op.status === "confirmed")) out.push({ run, op });
  }
  return out;
}

/** CandidatePaths: the configuration history's paths for a run's identity — the latest version's, the pinned one, the others. */
export function fixCandidatePaths(config: SimConfigFile | null, run: SimRun): string[] {
  const versions = (config?.repositories ?? []).filter((r) => r.repoKey === run.repoKey).sort((a, b) => b.configRevision - a.configRevision);
  const ordered: string[] = [];
  const add = (p: string | null | undefined) => {
    if (p && !ordered.includes(p)) ordered.push(p);
  };
  if (versions.length > 0) add(versions[0]!.repositoryRoot);
  if (run.openedConfig) add(versions.find((v) => v.configRevision === run.openedConfig!.configRevision)?.repositoryRoot);
  for (const v of versions) add(v.repositoryRoot);
  return ordered;
}

/** One listing row before the held proposals are read (GrantLedger.ListFixProposals). `located`: the identity the path
 * resolved to (null: none of the run's recorded paths reaches its identity) and the last recorded path. */
export function listingEntry(f: SimListedFix, located: { id: { key: string; canonicalPath: string } | null; last: string | null }, nowMs: number, escape: (s: string) => string): { rank: number; expiresAt: string; entry: Record<string, unknown> } {
  const p = proposalOf(f.op)!;
  const c = (f.op.outcome?.["confirmation"] ?? null) as Record<string, unknown> | null;
  const expiresAt = typeof p["expiresAt"] === "string" ? p["expiresAt"] : "";
  let state: string;
  let reason: string | null = null;
  if (f.op.status === "confirmed") {
    const lapsed = typeof c?.["expiresAt"] === "string" && Date.parse(c["expiresAt"]) <= nowMs;
    [state, reason] = isRunTerminal(f.run) ? ["ineligible", "run_ended"] : lapsed ? ["ineligible", "confirmation_expired"] : ["waiting", null];
  } else if (isRunTerminal(f.run)) [state, reason] = ["ineligible", "run_ended"];
  else if (p["retiredAt"] != null || Date.parse(expiresAt) <= nowMs) [state, reason] = ["expired", "proposal_expired"];
  else state = "pending";
  if (state === "pending" && located.id === null) [state, reason] = ["unavailable", "repository_unavailable"];
  const changed = (Array.isArray(p["changes"]) ? (p["changes"] as Record<string, unknown>[]) : []).map((x) => String(x["path"] ?? ""));
  return {
    rank: LISTED_FIX_STATES.indexOf(state),
    expiresAt,
    entry: {
      state, selectable: false, reasonCode: reason, repoKey: f.run.repoKey,
      repositoryRoot: located.id?.canonicalPath ?? null, repositoryDisplay: located.id ? escape(located.id.canonicalPath) : null,
      lastKnownPath: located.id === null && located.last !== null ? escape(located.last) : null,
      runId: f.run.runId, operationId: f.op.operationId, proposalDigest: p["proposalDigest"] ?? null, renderingDigest: null,
      changeCount: typeof p["changeCount"] === "number" ? p["changeCount"] : changed.length, totalBytes: typeof p["totalBytes"] === "number" ? p["totalBytes"] : 0,
      paths: changed.slice(0, MAX_LISTED_PATHS).map(escape), pathCount: changed.length,
      proposedAt: p["createdAt"] ?? null, expiresAt,
      confirmationExpiresAt: state === "waiting" ? (c?.["expiresAt"] ?? null) : null,
    },
  };
}

/** The listing's order: state (pending first), expiry, repository identity, run, fix. */
export function compareListingRows(a: { rank: number; expiresAt: string; entry: Record<string, unknown> }, b: { rank: number; expiresAt: string; entry: Record<string, unknown> }): number {
  const ord = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0);
  return a.rank - b.rank || ord(a.expiresAt, b.expiresAt) || ord(String(a.entry["repoKey"]), String(b.entry["repoKey"])) || ord(String(a.entry["runId"]), String(b.entry["runId"]))
    || ord(String(a.entry["operationId"]), String(b.entry["operationId"]));
}

/** RequireFreshFixDecision: the commit's freshness (the rendering again, the state digest, the proposal still pending). */
export function requireFreshFixDecision(store: SimRunStore, args: Record<string, unknown>, recordedState: string, rerendered: string | null, nowMs: number): void {
  const run = store.runs[runKey(String(args["repoKey"]), String(args["runId"]))] ?? null;
  if (run && isRunTerminal(run)) throw refuse("RUN_TERMINAL", `the run has ended (${run.status}) since this was prepared; nothing was committed`);
  if (rerendered === null || fixDecisionStateDigest(run, String(args["operationId"]), rerendered) !== recordedState) {
    throw refuse("CONFIRMATION_CONTENT_MISMATCH", "the proposal, its boundary, its baseline or the custodian's rendering changed since it was prepared; nothing was committed — show and decide again");
  }
  requirePendingProposal(run!, fixOperationOf(run!, String(args["operationId"])), nowMs);
}

/** ApplyFixDecision: record the owner's decision on the fix operation (and an operator event on the run). */
export function applyFixDecision(store: SimRunStore, args: Record<string, unknown>, requestId: string, recordedBy: Record<string, unknown>, nowMs: number): Record<string, unknown> {
  const repoKey = String(args["repoKey"]);
  const runId = String(args["runId"]);
  const operationId = String(args["operationId"]);
  const decision = String(args["decision"]);
  const key = runKey(repoKey, runId);
  const run = store.runs[key]!;
  const op = fixOperationOf(run, operationId);
  const outcome = structuredClone(op.outcome!);
  const p = outcome["proposal"] as Record<string, unknown>;
  const confirmationId = randomUUID();
  const expiresMs = Math.min(Date.parse(String(p["expiresAt"])), nowMs + SIM_FIX_CONFIRMATION_TTL_MS);
  const expiresAt = decision === "confirm" ? iso(expiresMs) : null;
  outcome["confirmation"] = {
    confirmationId, decision, renderingDigest: args["renderingDigest"] ?? null, proposalDigest: args["proposalDigest"] ?? null, repoKey, runId,
    baselineSourceId: args["baselineSourceId"] ?? null, baselineDigest: args["baselineDigest"] ?? null, boundaryDigest: args["boundaryDigest"] ?? null,
    recordedAt: iso(nowMs), expiresAt, recordedBy: structuredClone(recordedBy), consumedAt: null, consumedBy: null,
  };
  const status = decision === "confirm" ? FIX_CONFIRMED : FIX_DECLINED;
  if (decision === "reject") {
    Object.assign(p, { retiredAt: iso(nowMs), retiredReason: FIX_DECLINED });
    delete store.fixProposals?.[proposalKey(repoKey, runId, operationId)];
  }
  const next: SimRun = { ...run, operations: replaceOp(run, { ...op, status, outcome }) };
  const result = { operationId, decision, operationStatus: status, confirmationId, renderingDigest: args["renderingDigest"] ?? null, proposalDigest: args["proposalDigest"] ?? null, expiresAt, assurance: "local_admin_elevation" };
  const revision = run.runRevision + 1;
  const stored = { runId, kind: FIX_DECISION_ACTION, runRevision: revision, status: next.status, ...structuredClone(result) };
  const evidence: SimRunEvent = { seq: run.events.length + 1, kind: FIX_DECISION_ACTION, requestId, caller: "operator", clientPid: null, requestDigest: sha256OfCanonicalJson(stored), fromStatus: run.status, toStatus: next.status, at: iso(nowMs), result: structuredClone(stored) };
  store.runs[key] = { ...next, runRevision: revision, events: [...run.events, evidence] };
  return stored;
}

/** The application operations of the repository in progress — running, or interrupted and not yet reconciled. */
function applicationsInProgress(store: SimRunStore, repoKey: string): { runId: string; operationId: string; status: string }[] {
  const found: { runId: string; operationId: string; status: string }[] = [];
  for (const run of Object.values(store.runs)) {
    if (run.repoKey !== repoKey) continue;
    for (const o of run.operations) if (o.kind === "apply" && (o.status === "running" || o.status === APPLY_INTERRUPTED)) found.push({ runId: run.runId, operationId: o.operationId, status: o.status });
  }
  return found.sort((a, b) => (a.runId < b.runId ? -1 : a.runId > b.runId ? 1 : 0));
}

/** ApplyBeginStep: consume the confirmation of a confirmed fix and return the confirmed content. */
function applyBegin(store: SimRunStore, run: SimRun, req: SimRunRequest, writer: SimWriter, seq: number, nowMs: number): RunStep {
  const f = req.fields;
  const fixOperationId = String(f["fixOperationId"]);
  const fix = fixOperationOf(run, fixOperationId);
  const confirmation = (fix.outcome?.["confirmation"] ?? null) as Record<string, unknown> | null;
  if (fix.status === FIX_CONSUMED) throw refuse("CONFIRMATION_CONSUMED", `the confirmation of delegated fix ${fixOperationId} was already used by application ${String(confirmation?.["consumedBy"])}; a confirmation is single use`);
  if (fix.status === FIX_DECLINED) throw refuse("FIX_DECLINED", `the owner rejected delegated fix ${fixOperationId}; nothing is applied`);
  if (fix.status !== FIX_CONFIRMED) throw refuse("FIX_NOT_CONFIRMED", `delegated fix ${fixOperationId} has no owner confirmation (${fix.status}); the owner confirms the custodian's rendering with \`code-parley fix confirm\``);
  const p = proposalOf(fix)!;
  if (!confirmation || confirmation["decision"] !== "confirm" || confirmation["repoKey"] !== run.repoKey || confirmation["runId"] !== run.runId) {
    throw refuse("FIX_NOT_CONFIRMED", `delegated fix ${fixOperationId} has no confirmation for this repository and run`);
  }
  if (Date.parse(String(confirmation["expiresAt"])) <= nowMs || p["retiredAt"] != null) {
    throw refuse("CONFIRMATION_EXPIRED", `the confirmation of delegated fix ${fixOperationId} has expired; the owner confirms it again (\`code-parley fix confirm\`) while the proposal lives`);
  }
  const digest = String(p["proposalDigest"]);
  if (f["proposalDigest"] !== digest || confirmation["proposalDigest"] !== digest) throw refuse("EVIDENCE_NOT_HELD", `proposal ${String(f["proposalDigest"])} is not the confirmed proposal of delegated fix ${fixOperationId}`);
  const busy = applicationsInProgress(store, run.repoKey);
  if (busy.length > 0) {
    throw refuse("APPLY_IN_PROGRESS", `another application is in progress for this repository (run ${busy[0]!.runId}, ${busy[0]!.operationId}: ${busy[0]!.status}); one application at a time, and an interrupted one is reconciled first (\`code-parley fix reconcile\`)`);
  }
  const held = store.applyPre?.held ?? null;
  if (!held || held.operationId !== fixOperationId || held.problem !== null || !held.rendering || !held.content) {
    throw refuse("EVIDENCE_NOT_HELD", `the custodian cannot vouch for the confirmed content of delegated fix ${fixOperationId} (${held?.problem ?? "it was not read"}); nothing was applied`);
  }
  if (held.proposalDigest !== digest || held.rendering.digest !== confirmation["renderingDigest"]) {
    throw refuse("CONFIRMATION_CONTENT_MISMATCH", "the held content no longer renders the bytes the owner confirmed; nothing was applied");
  }
  const m = store.applyPre?.measured ?? { sourceId: null, stable: false, code: "MEASUREMENT_FAILED", detail: "not measured" };
  if (m.sourceId === null) throw refuse(m.code ?? "MEASUREMENT_FAILED", `the custodian could not measure the working tree before the application (${m.detail}); nothing was applied`);
  const b = fix.begin["custodianBaseline"] as Record<string, unknown>;
  if (!m.stable || m.sourceId !== b["sourceId"]) {
    throw refuse("FIX_STALE", m.stable
      ? "the working tree is no longer the baseline the fix was made against (the custodian's re-measurement differs); nothing was applied and the confirmation is unused"
      : "the working tree was changing while the custodian measured it; nothing was applied and the confirmation is unused");
  }
  const applyId = newId("aop", seq);
  const apply: SimRunOperation = {
    operationId: applyId, seq, kind: "apply", status: "running", beganAt: iso(nowMs), endedAt: null, writer,
    begin: { operationKind: "apply", fixOperationId, proposalDigest: digest, confirmationId: confirmation["confirmationId"] ?? null, renderingDigest: held.rendering.digest, sourceIdAtBegin: m.sourceId },
    outcome: null, pin: fix.pin ?? null,
  };
  const outcome = structuredClone(fix.outcome!);
  outcome["confirmation"] = { ...structuredClone(confirmation), consumedAt: iso(nowMs), consumedBy: applyId };
  const consumed: SimRunOperation = { ...fix, status: FIX_CONSUMED, outcome };
  return {
    next: { ...run, operations: [...replaceOp(run, consumed), apply], status: "applying" },
    result: {
      operationId: applyId, operationStatus: "running", fixOperationId, proposalDigest: digest, renderingDigest: held.rendering.digest, sourceIdAtBegin: m.sourceId,
      bindings: {
        runId: run.runId, operationId: fixOperationId, fixId: fix.begin["fixId"] ?? null, taskDigest: fix.begin["taskDigest"] ?? null, boundaryDigest: fix.begin["boundaryDigest"] ?? null,
        baseline: { reviewId: b["reviewId"] ?? null, sourceId: b["sourceId"] ?? null, exportDigest: b["exportDigest"] ?? null, manifestDigest: b["manifestDigest"] ?? null },
      },
    },
  };
}

/** The confirmed content an application's begin returns (never stored in the run's transition log). */
const contentForResult = (store: SimRunStore): Record<string, unknown>[] => structuredClone(store.applyPre?.held?.content ?? []);

/** RetireProposalOf: retire the fix's proposal (its held content removed). */
function retireProposalOf(run: SimRun, fixOperationId: string, reason: string, nowMs: number, store: SimRunStore): SimRun {
  const fix = run.operations.find((o) => o.operationId === fixOperationId && o.kind === "fix");
  const p = fix ? proposalOf(fix) : null;
  if (!fix || !p || p["retiredAt"] != null) return run;
  delete store.fixProposals?.[proposalKey(run.repoKey, run.runId, fixOperationId)];
  return { ...run, operations: replaceOp(run, { ...fix, outcome: { ...structuredClone(fix.outcome!), proposal: { ...structuredClone(p), retiredAt: iso(nowMs), retiredReason: reason } } }) };
}

/** ApplyFinishStep: applied or apply_failed (the engine's claim), with the custodian's post-apply measurement. */
function applyFinish(store: SimRunStore, run: SimRun, op: SimRunOperation, req: SimRunRequest, runStatus: string, nowMs: number): RunStep {
  const outcome = apply(APPLY_OUTCOME, req.fields["outcome"], "fields.outcome");
  const status = outcome["status"] as string;
  const m = store.applyPre?.measured ?? null;
  const stored = {
    status, files: structuredClone(outcome["files"]), detail: outcome["detail"] ?? null,
    sourceIdAfter: m?.sourceId ?? null, sourceStableAfter: m?.sourceId ? m.stable : null, measurementProblem: m?.sourceId ? null : `${m?.code ?? ""}: ${m?.detail ?? ""}`,
  };
  const next = retireProposalOf({ ...run, operations: replaceOp(run, { ...op, status, endedAt: iso(nowMs), outcome: stored }), status: runStatus }, String(op.begin["fixOperationId"]), status, nowMs, store);
  return { next, result: { operationId: op.operationId, operationStatus: status, sourceIdAfter: m?.sourceId ?? null } };
}

/** ApplyInterruptedStep: an application whose writer is gone is apply_interrupted (an incident), never applied. */
function applyInterrupted(store: SimRunStore, run: SimRun, op: SimRunOperation, nowMs: number): RunStep {
  requireIncidentRoom(run, 1);
  const inc: SimRunIncident = {
    incidentId: newId("inc", run.incidents.length + 1), kind: APPLY_INTERRUPTED, operationId: op.operationId, reviewId: null,
    detail: "the application's writer is gone before it finished; the working tree may hold some of the confirmed content — reconcile it (`code-parley fix reconcile`)", at: iso(nowMs), source: "custodian",
  };
  const interrupted: SimRunOperation = { ...op, status: APPLY_INTERRUPTED, endedAt: iso(nowMs), outcome: { status: APPLY_INTERRUPTED, incidentId: inc.incidentId } };
  const next = retireProposalOf({ ...run, operations: replaceOp(run, interrupted), incidents: [...run.incidents, inc], status: isRunTerminal(run) ? run.status : "idle" }, String(op.begin["fixOperationId"]), APPLY_INTERRUPTED, nowMs, store);
  return { next, result: { operationId: op.operationId, operationStatus: APPLY_INTERRUPTED, incidentId: inc.incidentId } };
}

/** ApplyReconcileStep: record the reconciliation of an interrupted application (restore or leave). */
function applyReconcile(store: SimRunStore, run: SimRun, req: SimRunRequest, nowMs: number): RunStep {
  const f = req.fields;
  const operationId = String(f["operationId"]);
  const op = run.operations.find((o) => o.operationId === operationId && o.kind === "apply");
  if (!op) throw refuse("EVIDENCE_NOT_HELD", `the run has no application ${operationId}`);
  if (op.status !== APPLY_INTERRUPTED) {
    throw refuse("OPERATION_NOT_RUNNING", op.status === "running"
      ? `application ${operationId} is still running; it is reconciled only once its writer is gone and it is recorded interrupted (recover)`
      : `application ${operationId} is ${op.status}; only an interrupted application is reconciled`);
  }
  const status = f["choice"] === "restore" ? "apply_interrupted_restored" : "apply_interrupted_left";
  const m = store.applyPre?.measured ?? null;
  const outcome = {
    ...structuredClone(op.outcome!), status,
    reconciliation: {
      choice: f["choice"], observed: f["observed"], files: structuredClone(f["files"]), detail: f["detail"] ?? null, at: iso(nowMs),
      sourceIdAfter: m?.sourceId ?? null, measurementProblem: m?.sourceId ? null : `${m?.code ?? ""}: ${m?.detail ?? ""}`,
    },
  };
  return { next: { ...run, operations: replaceOp(run, { ...op, status, outcome }) }, result: { operationId, operationStatus: status, sourceIdAfter: m?.sourceId ?? null } };
}
