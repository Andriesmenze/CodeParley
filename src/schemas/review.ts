// Review schemas (plan §11.2, §11.5, §12.2, §12.7, §13; MR-D, MR-F, MR-K). Source of truth
// (§5.3 rule 5).
//
// Three audiences:
//  - CODEX OUTPUT (`ReviewOutputSchema`): what the reviewer must return. Sent to Codex as a
//    strict JSON Schema generated from this zod schema (agents/codex/output-schema.ts) and
//    validated locally, because Codex does not validate it (X3). Hard caps here are generous
//    structural limits; display clamps are applied afterwards (policy/triage.ts).
//  - STORED RECORDS (`ReviewRecordSchema`, `ReviewerItemSchema`, incidents): persisted in
//    state.json. Reviewer items are reviewer-owned claims; engine-owned conditions (checks,
//    coverage) are never stored as items and are derived at report time (MR-D).
//  - ISOLATION RECORDS (`SelfTestRecordSchema`, `IsolationAcceptanceFileSchema`,
//    `EffectiveIsolationSchema`): what a review ran under (§12.2).

import { z } from "zod";
import { NEW_INFORMATION, ReviewDiscussionSchema, STANCES } from "./discussion.js";
import { ReviewAmendmentsSchema } from "./user-authority.js";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

// ---------------------------------------------------------------------------
// Policy vocabularies (single source; rendered into the prompt as data, §17)
// ---------------------------------------------------------------------------

export const CLAIM_TYPES = ["defect", "risk", "suggestion"] as const;
export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const CATEGORIES = [
  "correctness",
  "security",
  "reliability",
  "performance",
  "compatibility",
  "maintainability",
  "testing",
  "documentation",
  "style",
  "architecture",
] as const;
export const IMPACTS = ["correctness", "security", "reliability", "performance", "compatibility", "maintainability", "acceptance_criteria"] as const;
export const CONFIDENCES = ["high", "medium", "low"] as const;
export const EVIDENCE_KINDS = ["code_reference", "counterexample", "check_output", "spec_reference", "reasoning"] as const;
export const VERDICTS = ["APPROVE", "CHANGES_REQUIRED", "INCONCLUSIVE"] as const;
/** Assessments a later review may give a prior reviewer item (carry-forward, §13.4). */
export const PRIOR_ASSESSMENTS = ["still_present", "apparently_resolved", "no_longer_assessable", "superseded"] as const;

/** Bumped whenever ReviewOutputSchema changes shape (part of review_input_id). 3: discussion replies and restatements (Phase 2.2). */
export const REVIEW_OUTPUT_SCHEMA_VERSION = "3";

// ---------------------------------------------------------------------------
// Codex output (strict-mode subset: every object strict, every key required, nullable as
// [T,"null"] after normalization). No optional keys anywhere.
// ---------------------------------------------------------------------------

const text = (max: number) => z.string().max(max);

export const EvidenceOutSchema = z.strictObject({
  kind: z.enum(EVIDENCE_KINDS),
  detail: text(8000),
  path: z.string().max(1024).nullable(),
  start_line: z.number().nullable(),
  end_line: z.number().nullable(),
});
export type EvidenceOut = z.infer<typeof EvidenceOutSchema>;

export const FindingOutSchema = z.strictObject({
  title: text(1000),
  claim_type: z.enum(CLAIM_TYPES),
  severity: z.enum(SEVERITIES),
  category: z.enum(CATEGORIES),
  impacts: z.array(z.enum(IMPACTS)).max(IMPACTS.length * 2),
  consequence: text(8000),
  confidence: z.enum(CONFIDENCES),
  evidence: z.array(EvidenceOutSchema).max(30),
  investigation: text(8000),
  recommended_change: text(8000),
  related_prior_id: z.string().max(64).nullable(),
  /**
   * Phase 2.2: the presented prior item (alias) this finding is the SAME underlying issue as. It
   * joins that item's discussion thread (P2.2-1, -3); unlike related_prior_id, which never links.
   */
  restates_prior_id: z.string().max(64).nullable(),
});
export type FindingOut = z.infer<typeof FindingOutSchema>;

export const PriorAssessmentOutSchema = z.strictObject({
  id: z.string().max(64),
  assessment: z.enum(PRIOR_ASSESSMENTS),
  /** Index into this review's `findings` when `assessment` is "superseded". */
  superseded_by_index: z.number().nullable(),
  note: text(4000),
});
export type PriorAssessmentOut = z.infer<typeof PriorAssessmentOutSchema>;

export const QuestionOutSchema = z.strictObject({
  question: text(4000),
  related_finding_index: z.number().nullable(),
  blocking: z.boolean(),
});

export const TitledTextSchema = z.strictObject({ title: text(1000), detail: text(8000) });

export const ContextRequestOutSchema = z.strictObject({ what: text(2000), why: text(2000) });

/**
 * Phase 2.2: the reviewer's structured reply to the implementer on one item presented with
 * awaiting_reply (P2.2-3). The stance is a claim by the reviewer; it never changes the item's
 * lifecycle, which follows prior_findings and the carry-forward rules.
 */
export const DiscussionReplyOutSchema = z.strictObject({
  id: z.string().max(64),
  stance: z.enum(STANCES),
  reply: text(4000),
  new_information: z.enum(NEW_INFORMATION),
});
export type DiscussionReplyOut = z.infer<typeof DiscussionReplyOutSchema>;

export const CoverageOutSchema = z.strictObject({
  files_reviewed: z.array(z.string().max(1024)).max(5000),
  files_not_reviewed: z.array(z.string().max(1024)).max(5000),
  limitations: text(8000),
});

export const ReviewOutputSchema = z.strictObject({
  verdict: z.enum(VERDICTS),
  summary: text(8000),
  assessment: text(40000),
  findings: z.array(FindingOutSchema).max(100),
  prior_findings: z.array(PriorAssessmentOutSchema).max(200),
  questions: z.array(QuestionOutSchema).max(50),
  positive_observations: z.array(TitledTextSchema).max(30),
  suggestions: z.array(TitledTextSchema).max(50),
  context_requests: z.array(ContextRequestOutSchema).max(20),
  coverage: CoverageOutSchema,
  discussion_replies: z.array(DiscussionReplyOutSchema).max(100),
});
export type ReviewOutput = z.infer<typeof ReviewOutputSchema>;

// ---------------------------------------------------------------------------
// Task envelope (§11.2), host-provided and untrusted for security
// ---------------------------------------------------------------------------

const envText = (max: number) => z.string().max(max);
export const TaskEnvelopeSchema = z.strictObject({
  goal: z.string().min(1).max(2000),
  background: envText(8000).optional(),
  user_request_excerpt: envText(4000).optional(),
  work_completed: z.array(envText(1000)).max(50).optional(),
  current_focus: z.array(envText(1000)).max(50).optional(),
  constraints: z.array(envText(1000)).max(50).optional(),
  out_of_scope: z.array(envText(1000)).max(50).optional(),
  acceptance_criteria: z.array(envText(1000)).max(50).optional(),
  references: z.array(z.strictObject({ path: z.string().min(1).max(1024), note: envText(1000).optional() })).max(50).optional(),
});
export type TaskEnvelope = z.infer<typeof TaskEnvelopeSchema>;
export const MAX_ENVELOPE_BYTES = 32 * 1024;

export const ReviewDepthEnum = z.enum(["focused", "standard", "deep"]);
export type ReviewDepth = z.infer<typeof ReviewDepthEnum>;

// ---------------------------------------------------------------------------
// Isolation (§11.2 EffectiveIsolation, §12.2, §12.6)
// ---------------------------------------------------------------------------

export const IsolationModeEnum = z.enum(["S1", "S2"]);
export type IsolationMode = z.infer<typeof IsolationModeEnum>;

export const EffectiveIsolationSchema = z.object({
  mode: IsolationModeEnum,
  backend: z.string(),
  reads: z.enum(["restricted", "unrestricted"]),
  network: z.enum(["os_enforced", "env_advisory"]),
  /** The self-test whose rows established this mode (S1), or null. */
  selftest_id: z.string().nullable(),
  /** The acceptance record that allows a reduced mode (S2 / env_advisory), or null. */
  acceptance_id: z.string().nullable(),
  user_hooks_present: z.boolean(),
  /** Digest of the exact isolation argv fragment (profile, backend, side-channel flags). */
  profile_digest: Sha256,
  codex_version: z.string(),
});
export type EffectiveIsolation = z.infer<typeof EffectiveIsolationSchema>;

export const SelfTestRowSchema = z.object({
  name: z.string(),
  expectation: z.enum(["allowed", "denied", "blocked"]),
  sandbox: z.string(),
  positive_control: z.enum(["ok", "failed", "n/a"]),
  pass: z.boolean(),
  inconclusive: z.boolean().optional(),
  detail: z.string(),
});
export type SelfTestRow = z.infer<typeof SelfTestRowSchema>;

export const SelfTestRecordSchema = z.object({
  schema: z.literal("arl.codex-selftest.v1"),
  selftest_id: z.string(),
  key: Sha256,
  codex_version: z.string(),
  backend: z.string(),
  mode: IsolationModeEnum,
  profile_digest: Sha256,
  created_at: z.string(),
  profile_runs: z.boolean(),
  rejection_reason: z.string().nullable(),
  rows: z.array(SelfTestRowSchema),
  /** Every S1 row passed with a successful positive control and none was inconclusive. */
  s1_available: z.boolean(),
  /**
   * False when a probe was cancelled, timed out or could not be launched: such a result is
   * not a capability determination, is never stored, and the next review re-runs it (F10).
   */
  complete: z.boolean().default(true),
  /**
   * Phase 5 (contract §4.12), Linux only: the boot the self-test ran on, the native Codex binary it ran and its bundled
   * bwrap. A custodian that binds a sandbox basis confirms only a record of the current boot whose binary it measures.
   */
  boot_id: z.string().optional(),
  codex_path: z.string().optional(),
  codex_sha256: Sha256.optional(),
  bwrap_sha256: Sha256.optional(),
});
export type SelfTestRecord = z.infer<typeof SelfTestRecordSchema>;

/**
 * Phase 4 Increment 1 (contract plans/P4-delegated-fixes-contract.md §5; D-20; the Option B addendum
 * P4-INC1-NATIVE-EDIT-CONFINEMENT-SCOPED-PASS). The offline self-test of the WRITABLE `cp_fix` fixer
 * profile — distinct from the read-only S1 reviewer self-test above. It is bound to the exact approved
 * Codex binary (`codex_sha256`), its version, the mxc backend and the fixer profile digest, so a change to
 * any of them invalidates it and a fixer launch fails closed. A row where the in-workspace write is allowed
 * is the positive control; every out-of-workspace write, sandboxed command write and network attempt must
 * be denied/blocked. No model call.
 */
export const FixSelfTestRecordSchema = z.object({
  schema: z.literal("arl.codex-fix-selftest.v1"),
  selftest_id: z.string(),
  key: Sha256,
  codex_version: z.string(),
  /** The SHA-256 of the exact codex.exe the self-test ran (binds the record to the approved binary). */
  codex_sha256: Sha256,
  backend: z.string(),
  /** The fixer profile digest (agents/codex/fix-profile.ts fixProfileDigest). */
  profile_digest: Sha256,
  created_at: z.string(),
  profile_runs: z.boolean(),
  rejection_reason: z.string().nullable(),
  rows: z.array(SelfTestRowSchema),
  /** The in-workspace write was allowed (positive control), and every out-of-workspace write, command and
   * network row was denied/blocked with a successful positive control, and none was inconclusive. */
  confinement_available: z.boolean(),
  complete: z.boolean().default(true),
  /** Phase 5 (contract §4.12), Linux only: the boot the self-test ran on, the native Codex binary it ran and its bundled
   * bwrap — what a custodian that binds a sandbox basis measures before it confirms (as for S1). */
  boot_id: z.string().optional(),
  codex_path: z.string().optional(),
  bwrap_sha256: Sha256.optional(),
});
export type FixSelfTestRecord = z.infer<typeof FixSelfTestRecordSchema>;

export const ReducedIsolationEnum = z.enum(["unrestricted_reads", "advisory_network"]);
export type ReducedIsolation = z.infer<typeof ReducedIsolationEnum>;

export const IsolationAcceptanceSchema = z.object({
  acceptance_id: z.string(),
  accepted: z.array(ReducedIsolationEnum).min(1),
  backend: z.string(),
  /** Version prefix the acceptance applies to (e.g. "0.160."). */
  codex_version_range: z.string(),
  statement_sha256: Sha256,
  accepted_at: z.string(),
  via: z.literal("cli"),
  revoked_at: z.string().nullable().default(null),
});
export type IsolationAcceptance = z.infer<typeof IsolationAcceptanceSchema>;

export const IsolationAcceptanceFileSchema = z.object({
  schema_version: z.literal(1),
  records: z.array(IsolationAcceptanceSchema).default([]),
});
export type IsolationAcceptanceFile = z.infer<typeof IsolationAcceptanceFileSchema>;

// ---------------------------------------------------------------------------
// Stored reviewer items (§13.2) — reviewer-owned claims only (MR-D)
// ---------------------------------------------------------------------------

export const TriageEnum = z.enum(["established_defect", "serious_concern", "minor_concern", "note", "blocking_question", "question"]);
export type Triage = z.infer<typeof TriageEnum>;

export const EvidenceValidationEnum = z.enum(["valid", "no_location", "path_not_in_export", "path_withheld", "line_out_of_range", "invalid_line", "not_applicable"]);

export const StoredEvidenceSchema = z.object({
  kind: z.enum(EVIDENCE_KINDS),
  detail: z.string(),
  path: z.string().nullable(),
  start_line: z.number().nullable(),
  end_line: z.number().nullable(),
  /** Which version the reference targets: current (tree/, review/head/) or base (review/base/). */
  version: z.enum(["current", "base"]).nullable().default(null),
  /** The location names a file in the reviewed export, within its line range (§8.3 rule 7). */
  in_scope: z.boolean(),
  validation: EvidenceValidationEnum,
});
export type StoredEvidence = z.infer<typeof StoredEvidenceSchema>;

export const ItemAssessmentSchema = z.object({
  review_id: z.string(),
  round: z.number().int(),
  source_id: Sha256,
  assessment: z.enum([...PRIOR_ASSESSMENTS, "not_assessed"]),
  note: z.string(),
  /** What the engine did with it (e.g. "status:reported_resolved", "ignored:same_source"). */
  effect: z.string(),
});
export type ItemAssessment = z.infer<typeof ItemAssessmentSchema>;

export const ItemStatusEnum = z.enum(["open", "reported_resolved", "superseded", "informational", "not_accepted"]);
export type ItemStatus = z.infer<typeof ItemStatusEnum>;

export const ReviewerItemSchema = z
  .object({
    id: z.string(),
    item_kind: z.enum(["finding", "question"]),
    review_id: z.string(),
    round: z.number().int(),
    source_id: Sha256,
    review_input_id: Sha256,
    title: z.string(),
    claim_type: z.enum(CLAIM_TYPES).nullable(),
    severity: z.enum(SEVERITIES).nullable(),
    category: z.enum(CATEGORIES).nullable(),
    impacts: z.array(z.enum(IMPACTS)),
    consequence: z.string(),
    confidence: z.enum(CONFIDENCES).nullable(),
    evidence: z.array(StoredEvidenceSchema),
    investigation: z.string(),
    recommended_change: z.string(),
    triage: TriageEnum,
    /** Always "reviewer_evidence": triage is per the reviewer's evidence, not engine-verified (MR-K). */
    basis: z.literal("reviewer_evidence"),
    policy_notes: z.array(z.string()),
    status: ItemStatusEnum,
    related_prior_id: z.string().nullable(),
    supersedes: z.array(z.string()),
    superseded_by: z.string().nullable(),
    /**
     * Phase 2.2: earlier items this one restates — the same underlying issue, declared by the
     * reviewer (restates_prior_id), or a supersession the carry-forward ignored for being
     * weaker. A lineage link for the discussion thread only: it changes no lifecycle state.
     * Absent on items written before Phase 2.2 and on items that restate nothing.
     */
    restates: z.array(z.string()).optional(),
    assessments: z.array(ItemAssessmentSchema),
    created_at: z.string(),
  })
  .catchall(z.unknown());
export type ReviewerItem = z.infer<typeof ReviewerItemSchema>;

// ---------------------------------------------------------------------------
// Isolation incidents (§12.7, §13.4): append-only audit history; never reviewer-resolvable
// ---------------------------------------------------------------------------

export const IsolationIncidentKindEnum = z.enum([
  "isolation_violation_file_change",
  "isolation_violation_mcp_tool_call",
  "isolation_violation_web_search",
  "export_modified_during_review",
  "possible_surviving_sandboxed_commands",
  "cancellation_unconfirmed",
  "termination_unconfirmed",
  "isolation_reduced",
]);
export type IsolationIncidentKind = z.infer<typeof IsolationIncidentKindEnum>;

export const IsolationIncidentSchema = z
  .object({
    incident_id: z.string(),
    review_id: z.string().nullable(),
    operation_id: z.string(),
    kind: IsolationIncidentKindEnum,
    detail: z.string(),
    at: z.string(),
    source: z.literal("engine"),
  })
  .catchall(z.unknown());
export type IsolationIncident = z.infer<typeof IsolationIncidentSchema>;

// ---------------------------------------------------------------------------
// Review record (state.json `reviews[]`); large content lives in artifacts
// ---------------------------------------------------------------------------

export const ReviewStatusEnum = z.enum(["running", "completed", "failed", "timed_out", "cancelled", "invalid_output", "interrupted"]);
export type ReviewStatus = z.infer<typeof ReviewStatusEnum>;

/** Model-visible check evidence: structured metadata only, never raw output (rev 0.7). */
export const CheckEvidenceItemSchema = z.object({
  check: z.string(),
  required: z.boolean(),
  /** Floor/check status for the reviewed source (satisfied, failed, stale, missing, …). */
  status: z.string(),
  last_execution_status: z.string().nullable(),
  exit_code: z.number().int().nullable(),
  duration_ms: z.number().int().nullable(),
  timed_out: z.boolean(),
  cancelled: z.boolean(),
  freshness: z
    .object({ fresh: z.boolean(), source: z.string(), spec: z.string(), environment: z.string() })
    .nullable(),
});
export type CheckEvidenceItem = z.infer<typeof CheckEvidenceItemSchema>;

export const ReviewFreshnessSchema = z.object({
  /** Recomputed source_id equals the reviewed one (null: could not be recomputed). */
  source: z.boolean().nullable(),
  /** The check evidence evaluated now equals the evidence that was supplied (null: unknown). */
  check_evidence: z.boolean().nullable(),
  /** Presented as current only when both are true and the capture was stable. */
  current: z.boolean(),
  stale_reasons: z.array(z.string()),
  checked_at: z.string(),
});
export type ReviewFreshness = z.infer<typeof ReviewFreshnessSchema>;

export const CodexAuditSchema = z.object({
  events_total: z.number().int(),
  events_malformed: z.number().int(),
  events_oversize: z.number().int(),
  events_unknown_type: z.number().int(),
  stream_bytes: z.number().int(),
  stream_truncated: z.boolean(),
  thread_started: z.boolean(),
  turn_completed: z.boolean(),
  turn_failed: z.string().nullable(),
  error_events: z.array(z.string()),
  commands_run: z.number().int(),
  commands: z.array(z.object({ command: z.string(), exit_code: z.number().int().nullable(), status: z.string().nullable() })),
  file_changes: z.number().int(),
  mcp_tool_calls: z.number().int(),
  web_searches: z.number().int(),
  item_types: z.record(z.string(), z.number().int()),
  usage: z
    .object({ input_tokens: z.number().nullable(), cached_input_tokens: z.number().nullable(), output_tokens: z.number().nullable(), reasoning_output_tokens: z.number().nullable() })
    .nullable(),
  isolation_violations: z.array(z.object({ kind: z.string(), detail: z.string() })),
  /** A retention cap was reached: counts stay exact (or over-count), retained detail is partial (F8). */
  audit_truncated: z.boolean().default(false),
});
export type CodexAudit = z.infer<typeof CodexAuditSchema>;

export const CancellationRecordSchema = z.object({
  requested_at: z.string(),
  /** terminated: the process tree is confirmed gone; cancellation_requested: not confirmed. */
  outcome: z.enum(["terminated", "cancellation_requested"]),
  survivors: z.array(z.object({ pid: z.number().int(), name: z.string() })),
  /** Processes created during the run whose ancestry could not be traced (possibly ours). */
  unattributable: z.array(z.object({ pid: z.number().int(), name: z.string() })).default([]),
  /** Why termination is, or is not, established. */
  detail: z.string().default(""),
});
export type CancellationRecord = z.infer<typeof CancellationRecordSchema>;

export const ReviewRecordSchema = z
  .object({
    review_id: z.string(),
    operation_id: z.string(),
    round: z.number().int(),
    status: ReviewStatusEnum,
    failure: z.object({ class: z.string(), detail: z.string() }).nullable(),
    started_at: z.string(),
    ended_at: z.string().nullable(),
    duration_ms: z.number().int().nullable(),
    // Bindings (§10.2): exactly what this review was given.
    source_id: Sha256,
    review_input_id: Sha256,
    capture_id: z.string(),
    capture_stable: z.boolean(),
    export_ref: z.string(),
    manifest_digest: Sha256,
    /** Engine-held digest over every exported file (anchors export verification, F6). */
    export_digest: Sha256.nullable().default(null),
    check_evidence_digest: Sha256,
    check_execution_ids: z.array(z.string()),
    effective_isolation: EffectiveIsolationSchema,
    codex: z.object({ version: z.string(), model: z.string().nullable(), reasoning_effort: z.string().nullable() }),
    prompt: z.object({ template_id: z.string(), template_version: z.string(), sha256: Sha256, bytes: z.number().int(), artifact: z.string() }),
    output_schema_version: z.string(),
    policy_version: z.string(),
    depth: ReviewDepthEnum,
    focus_sha256: Sha256.nullable(),
    // Outcome (reviewer claims: advisory).
    verdict: z.enum(VERDICTS).nullable(),
    summary: z.string().nullable(),
    item_ids: z.array(z.string()),
    policy_notes: z.array(z.string()),
    /** Freshness AT COMPLETION (historical; reports recompute freshness now, F5). */
    freshness: ReviewFreshnessSchema.nullable(),
    /**
     * Whether the result was accepted as the current review (F2): completed, valid output,
     * current at completion, not cancelled, no isolation-invalidating incident. Only an
     * accepted review changes reviewer-item state or becomes the current review result.
     */
    accepted: z.boolean().nullable().default(null),
    not_accepted_reasons: z.array(z.string()).default([]),
    audit: CodexAuditSchema.nullable(),
    incident_ids: z.array(z.string()),
    cancellation: CancellationRecordSchema.nullable(),
    /**
     * Termination evidence whenever the Codex tree was killed, for any reason (cancellation,
     * wall or idle timeout): the same rule decides `established` in every case (F3).
     */
    termination: z
      .object({
        reason: z.string(),
        established: z.boolean(),
        survivors: z.array(z.object({ pid: z.number().int(), name: z.string() })),
        unattributable: z.array(z.object({ pid: z.number().int(), name: z.string() })),
        detail: z.string(),
      })
      .nullable()
      .default(null),
    artifacts: z.record(z.string(), z.string()),
    /**
     * Phase 2.2: which implementer turns this review's bundle presented (P2.2-2, -6). They count
     * as seen by the reviewer only if the review was accepted. Absent on reviews written before
     * Phase 2.2: those presented none.
     */
    discussion: ReviewDiscussionSchema.optional(),
    /**
     * Phase 2.3: which task amendments this review's bundle presented (P2.3-9). They count as seen by
     * the reviewer only if the review was accepted. Absent on reviews written before Phase 2.3: those
     * presented none.
     */
    amendments: ReviewAmendmentsSchema.optional(),
  })
  .catchall(z.unknown());
export type ReviewRecord = z.infer<typeof ReviewRecordSchema>;
