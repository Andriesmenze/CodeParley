// The custodian wire protocol and grant result shapes, mirrored in TypeScript (P3.4C-0).
//
// The custodian (custodian/CodeParley.Custodian) is the OWNER of loop-grant authority. This module
// defines the request/response contract its two named-pipe surfaces speak (Ipc/Protocol.cs,
// Ipc/CustodianCore.cs), the deterministic service SID used to verify a connection is the real
// custodian (the anti-squat trust anchor, computed HERE so the value the client enforces originates in
// TypeScript), and how custodian error codes map to engine DomainErrors. PURE: no I/O.

import { createHash } from "node:crypto";
import { DomainError, type ErrorCode } from "../common/errors.js";

export const CUSTODIAN_PROTOCOL_VERSION = 1;

/** The two named-pipe surfaces (Ipc/CustodianConstants.cs). The OS classifies the caller; the surface
 * selects which identity may connect (operator = elevated operator SID; implementer = implementer SID). */
export const CUSTODIAN_PIPES = {
  implementer: "CodeParley.Custodian.v1.implementer",
  operator: "CodeParley.Custodian.v1.operator",
} as const;
export type CustodianSurface = keyof typeof CUSTODIAN_PIPES;

/** Phase 5 (contract §4.2, §4.4): the Linux custodian's surfaces — two pathname Unix sockets PID 1 creates in the
 * root-owned runtime directory (socket units codeparley-implementer.socket / codeparley-operator.socket), owned by the
 * custodian's own account. The kernel classifies the caller (SO_PEERCRED uid); the socket selects the surface. */
export const CUSTODIAN_SOCKETS: Readonly<Record<CustodianSurface, string>> = Object.freeze({
  implementer: "/run/codeparley/implementer.sock",
  operator: "/run/codeparley/operator.sock",
});
export const CUSTODIAN_RUNTIME_DIR = "/run/codeparley";
/** The Linux custodian's system account: the owner every socket the client accepts must have (the trust anchor). */
export const CUSTODIAN_LINUX_ACCOUNT = "codeparley";

/** Operations and their accepted argument keys (Ipc/CustodianCore.cs AllowedArgs). Any other key in
 * `args` is rejected (MALFORMED_REQUEST), never ignored — no field conveys authority. */
export type CustodianOp =
  | "ping" | "list_grants" | "consume_loop" | "prepare_grant" | "prepare_revoke" | "commit" | "service_identity"
  // P3.4C-1: protected user decisions & amendments.
  | "prepare_user_record" | "list_user_records"
  // P3.4C-2: the custodian-computed loop lifecycle.
  | "loop_transition"
  // P3.4C-3: the custodian-computed run lifecycle and evidence.
  | "run_transition"
  // P3.4C-4: the operator's configuration changes (committed by the existing `commit`).
  | "prepare_config_record"
  // Phase 4 Increment 3: the owner's decision on a held proposal (operator; committed by `commit`) and its rendering (read).
  | "prepare_fix_decision" | "render_fix_proposal"
  // Step 7.1: the operator's listing of the delegated fixes the custodian holds (operator only).
  | "list_fix_proposals"
  // Phase 5 F-i2-5: the bytes of a baseline capture or response disclosure record the run binds by digest (implementer).
  | "hold_evidence";

/** Phase 5 F-i2-5 (GrantLedger.EvidencePartBytes): the bytes one `hold_evidence` part carries at most (base64-decoded). */
export const EVIDENCE_PART_BYTES = 512 * 1024;

/** P3.4C-5: the operations whose answer waits for a measurement the custodian makes inside the request — an engine runtime
 * approval measures the whole runtime tree at `prepare_config_record` and again at `commit` (thousands of files hashed;
 * F-I4). A client gives them a longer response deadline. */
export const CUSTODIAN_MEASURING_OPS: ReadonlySet<CustodianOp> = new Set<CustodianOp>(["prepare_config_record", "commit", "list_fix_proposals"]);

export interface CustodianRequest {
  v: number;
  requestId: string;
  op: CustodianOp;
  args: Record<string, unknown>;
}

/** The custodian's response envelope (Ipc/Protocol.cs). */
export interface CustodianResponse {
  ok: boolean;
  data?: Record<string, unknown>;
  code?: string;
  error?: string;
}

/** Custodian error codes (Ipc/Protocol.cs ErrorCodes) plus the two client-side codes. */
export const CUSTODIAN_UNAVAILABLE = "CUSTODIAN_UNAVAILABLE";
export const SERVER_NOT_TRUSTED = "SERVER_NOT_TRUSTED";

/** A grant mint result. `grantId` is null only on a deduplicated replay the custodian will not re-mint. */
export interface MintResult {
  grantId: string | null;
  loopsTotal: number | null;
  expiresAt: string | null;
  assurance: string;
  deduplicated: boolean;
}

/** One consumed loop: the grant loop spent AND the custodian-owned loop record minted for the run in the same
 * atomic ledger write (P3.4C-2, contract §1). The loop starts unbound, in epoch 1, at its own revision 1. */
export interface ConsumeResult {
  grantId: string;
  loopId: string;
  loopsUsed: number;
  loopsTotal: number;
  runId: string;
  loopEpoch: number;
  loopRevision: number;
  /** The one-time bind-nonce preimage the host presents at bind. Returned ONLY by the call that minted the
   * loop — never by an idempotent replay (the custodian keeps only its hash). */
  bindNonce: string | null;
}

// ---------------------------------------------------------------------------
// P3.4C-2: the custodian-owned loop lifecycle (loop_transition; contract §2–§7)
// ---------------------------------------------------------------------------

/** The closed set of loop_transition kinds. The client sends a kind and its typed fields; the custodian
 * computes the new state (status, epoch, budgets, binding verdict, operation handles, wake claims). */
export const LOOP_TRANSITION_KINDS = ["bind", "rebind", "spend_continuation", "wake_arm", "wake_consume", "pause", "resume", "end"] as const;
export type LoopTransitionKind = (typeof LOOP_TRANSITION_KINDS)[number];

/** The typed fields each kind sends (Ledger/LoopRequest.cs allowlists them; any other key is refused). The
 * process facts are only the pid the host gave the hook: the custodian checks it itself (D7). An automation
 * request (spend_continuation, wake_arm, wake_consume) carries the session id of the hook invocation that asks;
 * the custodian compares it with its binding and checks the connected process against the bound one. */
export interface LoopTransitionFields {
  bind: { bindNonce: string; session_id: string; process: { pid: number | null } };
  rebind: { session_id: string; process: { pid: number | null } };
  /** P3.4C-5 Increment 3 (§5.2): the custodian derivation the continuation is asked on. */
  spend_continuation: { session_id: string; derivation_id?: string };
  wake_arm: { operationHandle: string; session_id: string };
  wake_consume: { claimId: string; session_id: string; derivation_id?: string };
  pause: { reason: string; detail?: string };
  resume: Record<string, never>;
  end: { status: "cancelled" | "run_ended"; reason?: string };
}

/** The codes with which the custodian refuses a loop transition (or a loop-minting consume). Each is a
 * decided refusal — nothing was applied — and the engine reacts to it; any other code is a fault. */
export const LOOP_REFUSAL_CODES = [
  "LOOP_TERMINAL", "RUN_ALREADY_HAS_LOOP", "STALE_LOOP_EPOCH", "STALE_LOOP_STATE", "UNKNOWN_OPERATION_HANDLE", "UNKNOWN_LOOP",
  "INVALID_LOOP_TRANSITION", "BIND_NONCE_INVALID", "PROCESS_IDENTITY_UNVERIFIED", "LOOP_BUDGET_EXHAUSTED", "UNKNOWN_WAKE_CLAIM",
  "WAKE_ALREADY_CONSUMED", "CALLER_NOT_AUTHORIZED", "REQUEST_ID_CONFLICT", "SESSION_NOT_BOUND",
  // P3.4C-5 Increment 3 (§5.2): the custodian's enforcement of its own derivation.
  "DERIVATION_STALE", "ROUTE_NOT_IMPLEMENTER_STEP", "NO_PROGRESS",
] as const;
export type LoopRefusalCode = (typeof LOOP_REFUSAL_CODES)[number];

/**
 * The loop section of `list_user_records` (contract §6): the run's custodian loop record from the ledger,
 * with the loop record's OWN revision and snapshot digest — never combined with the user-record log's
 * revision. `protected` is the custodian's protected-vs-attended answer (§7): true once a loop was minted
 * for the run, and still true after it ended. `record` is the caller's projection: the OPERATOR surface
 * gets the full record; the IMPLEMENTER surface an allowlisted projection without the session id, process
 * facts, nonce or history.
 */
export interface LoopSection {
  protected: boolean;
  loopRevision: number;
  loopDigest: string;
  record: Record<string, unknown> | null;
}

/** A grant as `list_grants` reports it. `repoKey` is the custodian's own identity of the directory
 * (`fid1-…`: volume serial + file id); `repositoryRoot` is its canonical path, for the operator only;
 * `identity` is `legacy_text` for a grant recorded before P3.4C-0, which is never active. */
export interface GrantSummary {
  grantId: string;
  repoKey: string;
  repositoryRoot: string | null;
  identity: string;
  loopsUsed: number;
  loopsTotal: number;
  expiresAt: string;
  revoked: boolean;
  /** P3.4C-3 (§2.4 U2): suspended by the custodian's recovery after a new boot; never active again. */
  suspended: boolean;
  active: boolean;
  assurance: string;
}

/** `list_grants`: the grants and the ceilings the custodian enforces (null from a custodian that does not
 * report them). The custodian's ceilings are the authoritative, effective grant limits. */
export interface GrantListing {
  grants: GrantSummary[];
  ceilings: { loops: number; minutes: number } | null;
}

/** A prepared (not yet committed) grant: what the custodian will grant, as it renders it for the operator. */
export interface PreparedGrant {
  authorizationRequestId: string;
  rendering: string;
  expiresAt: string;
}

// ---------------------------------------------------------------------------
// P3.4C-1: protected user decisions & amendments
// ---------------------------------------------------------------------------

/** The two protected user-record kinds. */
export type UserRecordKind = "decision" | "amendment";

/** A prepared (not yet committed) user record, as the custodian renders it for the operator. */
export interface PreparedUserRecord {
  authorizationRequestId: string;
  rendering: string;
  expiresAt: string;
}

/** The result of committing a user record: the custodian-assigned identity, sequence and new log revision. */
export interface UserRecordCommit {
  recordId: string;
  seq: number;
  revision: number;
  recordKind: UserRecordKind;
}

/**
 * A per-run user-record log as `list_user_records` returns it. The `records` are OPAQUE objects whose
 * shape depends on the surface the engine asked on (D-C'): the OPERATOR surface returns the complete
 * records (full decision note / amendment text); the IMPLEMENTER surface returns an allowlisted structural
 * projection WITHOUT raw private text — for an amendment it carries `contentKeyHash`, `textBytes` and
 * `disclosureDigest` instead. `governed` is true once the custodian holds a log for the run; `revision`
 * and `logDigest` identify the snapshot (a successful empty log has `governed:false`/`revision:0`, which is
 * NOT the same as the custodian being unavailable — that throws). */
export interface UserRecordListing {
  governed: boolean;
  revision: number;
  logDigest: string;
  records: Record<string, unknown>[];
  /** P3.4C-2: the run's loop section, separately revisioned (null from a custodian that reports none). */
  loop: LoopSection | null;
  /** P3.4C-3 (contract §5.4): the custodian's selection answer — it holds the run's loop record OR its run record.
   * null from a custodian that does not report it (before P3.4C-3). */
  protected: boolean | null;
  /** P3.4C-3 (§2.4 U4): the log revision a recovery after a new boot ran at — earlier waivers and deferrals lapse on a
   * run whose loop is not terminal until the operator re-confirms them (null: no recovery touched this log). */
  recoveredAtRevision: number | null;
  /** P3.4C-3: the run section, when it was asked for (null otherwise). */
  run: RunSection | null;
  /** P3.4C-4: the config section, when it was asked for (null otherwise, or malformed: no answer). */
  config: ConfigSection | null;
  /** P3.4C-5 Increment 3 (§5.1): the custodian's protected derivation, when it was asked for (null otherwise). */
  derivation?: CustodianDerivation | null;
  /** Phase 5 F-i2-5: the run's held records as the protected derivation reads them (`arl.derivation-snapshot.v2`; operator
   * surface only), when it was asked for; null when the custodian holds no run record. Opaque here: the engine reads it. */
  snapshot?: Record<string, unknown> | null;
}

/** P3.4C-5 Increment 3 (§5.1): the custodian's protected derivation of a run — completion, the route and the progress
 * fingerprint its helper computed over its own records and fresh measurement, cached under `derivationId` (never
 * authority by itself: a continuation or wake names it and the custodian re-checks it, §5.2). Unavailable: why (every
 * automation decision then fails closed). */
export type CustodianDerivation =
  | {
      available: true;
      authority: "custodian";
      derivationId: string;
      at: string;
      ttlSeconds: number;
      revision: Record<string, unknown>;
      completion: { state: string; ready: boolean; blockers: { category: string; code: string }[]; counts: Record<string, number> };
      route: { code: string; kind: string; reason: string; pause?: string; end?: string };
      floor: { configured: boolean; satisfied_for_current_source: boolean; missing: string[]; stale: string[]; failed: string[]; removed: string[]; unapproved: string[] } | null;
      currentSourceId: string | null;
      inputDigest: string;
      progressFingerprint: string;
      measured: Record<string, unknown>;
    }
  | { available: false; authority: "custodian"; code: string; detail: string };

// ---------------------------------------------------------------------------
// P3.4C-3: the custodian-owned run records (run_transition; contract §2–§5)
// ---------------------------------------------------------------------------

/** The closed set of run_transition kinds. The client sends a kind and its typed fields (every one a claim the
 * custodian validates); the custodian computes the status, the revision, the operation id, the round, acceptance, the
 * items' statuses and the assessments' effects. */
export const RUN_TRANSITION_KINDS = ["open", "op_begin", "record_execution", "op_finish", "recover", "respond", "end", "apply_reconcile"] as const;
export type RunTransitionKind = (typeof RUN_TRANSITION_KINDS)[number];

/** The sections list_user_records can return (default: user and loop, the P3.4C-2 response). */
export type UserRecordSection = "user" | "loop" | "run" | "config" | "derivation" | "snapshot";

/** The run section of list_user_records (contract §3.3): the run record with its OWN revision and a digest of that
 * snapshot, and the maxima the custodian enforces for it. `record` is the caller's projection: the operator surface
 * gets the full record; the implementer surface a projection without the writers' process facts or the transition
 * log, where a running operation carries the custodian's `writerAlive` verdict. */
export interface RunSection {
  registered: boolean;
  runRevision: number;
  runDigest: string;
  limits: Record<string, number>;
  record: Record<string, unknown> | null;
  /** P3.4C-4 (§3.3, §4.3): per review id, whether its pinned configuration basis is usable now (custodian-derived at
   * read time); null from a custodian that does not report it. */
  reviewBasis: Record<string, { basisUsable: boolean; basisReason: string | null }> | null;
}

// ---------------------------------------------------------------------------
// P3.4C-4: the custodian-held trusted configuration (prepare_config_record; the config section)
// ---------------------------------------------------------------------------

export type ConfigRecordKind = "repository" | "isolation_acceptance" | "selftest_confirmation" | "engine_runtime";

/** The run id the config section is read under: list_user_records names a run; the config section ignores it. */
export const CONFIG_VIEW_RUN = "config-view";
export type ConfigAction = "set" | "revoke" | "reconfirm";

/** A check definition as the custodian holds it (the engine's canonical form) with its custodian-computed digest. */
export interface HeldCheck {
  definition: {
    argv: string[];
    cwd: string;
    timeout_seconds: number;
    env: Record<string, string>;
    env_passthrough: string[];
    freshness_inputs: string[];
    description?: string;
  };
  definitionDigest: Hex64;
}

/** A repository's configuration record as the config section reports it. */
export interface HeldRepositoryConfig {
  configRevision: number;
  configDigest: Hex64;
  recordedAt: string;
  action: string;
  revoked: boolean;
  lapsed: boolean;
  lapsedAtRecoveryId: string | null;
  usable: boolean;
  rootCommit: string | null;
  checks: Record<string, HeldCheck>;
  profiles: Record<string, string[]>;
  requiredProfiles: string[];
  noRequiredChecks: boolean;
  testGlobs: string[];
  captureRules: { excludeGlobs: string[]; contextInclude: string[]; maxFileBytes: number; maxExportBytes: number; maxDiffBytes: number };
  captureRulesDigest: Hex64;
  codexInstallation: { path: string; form: string; fileId: string; size: number; sha256: Hex64 } | null;
  /** Operator projection only. */
  repositoryRoot?: string;
  recordedBy?: Record<string, unknown>;
}

export interface HeldAcceptance {
  acceptanceId: string;
  globalRevision: number;
  recordedAt: string;
  accepted: string[];
  backend: string;
  codexVersionRange: string;
  statementSha256: Hex64;
  revoked: boolean;
  lapsed: boolean;
  lapsedAtRecoveryId: string | null;
  usable: boolean;
}

export interface HeldSelftestConfirmation {
  confirmationId: string;
  globalRevision: number;
  recordedAt: string;
  selftestId: string;
  codexVersion: string;
  backend: string;
  mode: string;
  profileDigest: Hex64;
  s1Available: boolean;
  rowsSummary: { total: number; passed: number; failed: string[] };
  recordDigest: Hex64;
  /** Phase 4 Increment 2: a FIX confirmation's Codex binary (absent on an S1 confirmation). */
  codexSha256?: Hex64;
  revoked: boolean;
  lapsed: boolean;
  lapsedAtRecoveryId: string | null;
  usable: boolean;
}

/** P3.4C-5 (contract §2.1): the operator's approval of the engine runtime the custodian's helper runs, as the custodian
 * measured it (root, node.exe, the approved git, the helper entry and a digest over the whole tree). */
export interface HeldEngineRuntime {
  runtimeId: string;
  globalRevision: number;
  recordedAt: string;
  root: string;
  /** The git inside the runtime tree, or (Phase 6, §7 b) null with `gitPath` naming an installed git outside it. */
  gitRelative: string | null;
  gitPath?: string | null;
  entryRelative: string;
  nodeSha256: Hex64;
  gitSha256: Hex64;
  entrySha256: Hex64;
  treeDigest: Hex64;
  fileCount: number;
  totalBytes: number;
  revoked: boolean;
  lapsed: boolean;
  lapsedAtRecoveryId: string | null;
  usable: boolean;
}

/** The config section of list_user_records (contract §3.3): the repository's current record (null: none committed) and
 * the global records, with the shared global revision. `engineRuntime` (P3.4C-5) is absent from custodians before it. */
export interface ConfigSection {
  globalRevision: number;
  repository: HeldRepositoryConfig | null;
  acceptances: HeldAcceptance[];
  selftestConfirmations: HeldSelftestConfirmation[];
  engineRuntime?: HeldEngineRuntime | null;
}

/** A prepared (not yet committed) configuration change, as the custodian renders it for the operator. */
export interface PreparedConfigRecord {
  authorizationRequestId: string;
  rendering: string;
  expiresAt: string;
}

/** The result of committing a configuration change. */
export interface ConfigCommit {
  recordKind: ConfigRecordKind;
  action: ConfigAction;
  repoKey: string | null;
  configRevision: number | null;
  recordId: string | null;
  globalRevision: number | null;
  globalsReconfirmed: number | null;
}

/** The result of one run transition: the run's revision and status after it, and the kind's own fields (an
 * operation id, a review's round and acceptance, the items it changed, ...). */
export type RunTransitionResult = Record<string, unknown> & { runId: string; kind: RunTransitionKind; runRevision: number; status: string };

type Hex64 = string;

/** One check execution as the engine reports it (record_execution; Ledger/RunRequest.cs ExecutionShape). */
export interface RunCheckExecution {
  executionId: string;
  check: string;
  definitionDigest: Hex64 | null;
  checkSpecId: Hex64 | null;
  executionInputId: Hex64 | null;
  envDigest: Hex64 | null;
  freshnessDigest: Hex64 | null;
  status: "passed" | "failed" | "error" | "timed_out" | "cancelled" | "skipped";
  skipReason: "operation_cancelled" | "definition_removed" | "definition_changed" | "approval_invalid" | null;
  exitCode: number | null;
  timedOut: boolean;
  cancelled: boolean;
  startedAt: string | null;
  endedAt: string | null;
  durationMs: number | null;
  sourceIdAtStart: Hex64 | null;
  sourceIdAtEnd: Hex64 | null;
  sourceStable: boolean;
  stdoutDigest: Hex64 | null;
  stderrDigest: Hex64 | null;
  resultDigest: Hex64 | null;
  limitations: { code: string; detail: string }[];
}

/** P3.4C-5 (contract §3.1 step 2): a protected review's op_begin RESERVES. It carries everything the engine selects
 * without the capture — the source it selected the evidence and discussion for (a claim the custodian's capture must
 * match), the target, the presented check executions, the discussion turns and amendments it offers the reviewer, and the
 * isolation, configuration and version claims — and never a capture field or the prompt digest: the custodian captures
 * the review itself (the operation is `measuring`, then `captured`), and the prompt digest arrives with op_finish. */
export interface RunReviewReserve {
  operationKind: "review";
  reviewId: string;
  selectionSourceId: Hex64;
  target: { kind: "uncommitted" } | { kind: "base_ref"; ref: string };
  checkExecutionIds: string[];
  checkEvidenceDigest: Hex64;
  checkResultsDigest: Hex64;
  discussion: { offered: { itemId: string; responseIds: string[]; replyIds: string[] }[] };
  amendments: { offered: { amendmentId: string; disclosureDigest: Hex64 | null }[] };
  /** P3.4C-4: the isolation claim names its backend and the Codex version; the custodian checks it names a held record. */
  isolation: { mode: "S1" | "S2"; profileDigest: Hex64; selftestId: string | null; acceptanceId: string | null; backend: string; codexVersion: string };
  /** P3.4C-4: the digest of the held capture rules the custodian captures under. */
  captureRulesDigest: Hex64;
  /** P3.4C-4: the SHA-256 of the Codex image the engine launches (an engine claim, compared with the approved one). */
  codexSha256: Hex64;
  depth: "focused" | "standard" | "deep";
  focusDigest: Hex64 | null;
  versionsDigest: Hex64;
}

/** P3.4C-5 (§3.1 step 7): what a finished custodian-captured review presented (engine claims, each a subset of what the
 * reservation offered). */
export interface RunReviewPresented {
  discussion: {
    digest: Hex64;
    delivered: { itemId: string; responseIds: string[]; replyIds: string[] }[];
    notDeliveredCount: number;
    /** P3.4C-5 Increment 3 (§5.1): per delivered response, whether a reply was sought and why (the exchange count and the
     * amendment gate read them). */
    deliveries?: { responseId: string; itemId: string; replySought: boolean; basis: string[] }[];
  };
  amendments: { digest: Hex64; presented: { amendmentId: string; disclosureDigest: Hex64 | null }[]; withheld: string[] };
}

/** P3.4C-5: the operation statuses of a review the custodian captures (the run section's operation `status`). */
export const CAPTURE_ENDED_STATUSES = ["error", "cancelled", "deduplicated", "interrupted"] as const;

/** A finished review's outcome (op_finish of a review operation): what it reported, as claims the custodian
 * validates; acceptance, statuses and effects are the custodian's. */
export interface RunReviewOutcome {
  status: "completed" | "failed" | "timed_out" | "cancelled" | "invalid_output";
  outputValid: boolean;
  currentAtCompletion: boolean;
  verdict: "APPROVE" | "CHANGES_REQUIRED" | "INCONCLUSIVE" | null;
  summaryDigest: Hex64 | null;
  artifacts: { rawOutput: Hex64 | null; output: Hex64 | null; items: Hex64 | null; result: Hex64 | null; events: Hex64 | null; stderr: Hex64 | null; lastMessage: Hex64 | null };
  newItems: {
    itemId: string;
    itemKind: "finding" | "question";
    triage: string;
    severity: string | null;
    claimType: string | null;
    category: string | null;
    impacts: string[];
    confidence: string | null;
    status: "open" | "informational";
    relatedPriorId: string | null;
    relatedFindingId: string | null;
    restates: string[];
  }[];
  /** Exactly one entry for every item open before the review. */
  assessments: { itemId: string; assessment: "still_present" | "apparently_resolved" | "no_longer_assessable" | "superseded" | "not_assessed" | "not_presented"; supersededByItemId: string | null }[];
  replies: { replyId: string; itemId: string; stance: string; newInformation: string; answersResponseId: string | null; assessment: string | null }[];
  incidents: { kind: string; detail: string }[];
}

/** One implementer response (respond), written against the item revision it answers. */
export interface RunResponse {
  responseId: string;
  itemId: string;
  baseItemRevision: number;
  disposition: "accepted" | "disputed" | "deferred" | "fix_claimed";
  textWithheld: boolean;
  answers: { reviewId: string | null; round: number | null; runReviewId: string | null; runRound: number | null; reviewerReplyId: string | null };
  sourceId: Hex64 | null;
  supersedes: string | null;
  threadId: string;
  /** P3.4C-5 Increment 3 (§5.1): each cited location as a comparison key, and whether a rationale was given — what the
   * discussion's new-information gate reads of a response's text, held without the text (claims). */
  referenceKeys?: Hex64[];
  rationalePresent?: boolean;
}

/** Phase 4 Increment 2 (contract §3.2): a delegated fix's op_begin — the task digest, the boundary (bound by the custodian),
 * the baseline review whose published capture seeds the workspace, the FIX isolation claim (an operator-confirmed FIX
 * self-test, never S1) and the Codex image the engine launches. Never file contents. */
export interface RunFixBegin {
  operationKind: "fix";
  fixId: string;
  taskDigest: Hex64;
  baselineReviewId: string;
  boundary: {
    permittedFiles: string[];
    permittedDirs: string[];
    allowCreate: boolean;
    allowDelete: boolean;
    allowBinary: boolean;
    maxChangedFiles: number;
    maxFileBytes: number;
    maxTotalBytes: number;
    timeLimitSeconds: number;
    proposalLifetimeSeconds: number;
  };
  isolation: { mode: "FIX"; profileDigest: Hex64; selftestId: string; backend: string; codexVersion: string };
  codexSha256: Hex64;
}

/** Phase 4 Increment 2 (§3.4): a delegated fix's finish — the engine's report and, for a completed fix, the proposal CONTENT
 * (per path in canonical order: the change kind and, for an add or a modify, the postimage bytes as base64), which the
 * custodian validates itself; it trusts no engine digest or preimage. */
export interface RunFixOutcome {
  status: "completed" | "empty" | "rejected" | "failed" | "timed_out" | "cancelled";
  scan: { complete: boolean; files: number; anomalies: number; violations: number } | null;
  detail: string | null;
  changes: { path: string; kind: "add" | "modify" | "delete"; executable: boolean; content: string | null }[];
}

/** Phase 4 Increment 3 (contract §3.6): an application's op_begin — the fix whose CONFIRMED proposal is applied, and its
 * digest. Never a confirmation: the custodian holds it (a confirmation-shaped field is refused as an unknown key). */
export interface RunApplyBegin {
  operationKind: "apply";
  fixOperationId: string;
  proposalDigest: Hex64;
}

/** The state of one file of an application, as the engine reports it (a claim). */
export type ApplyFileState = "postimage" | "preimage" | "absent" | "other" | "unknown";

/** Phase 4 Increment 3 (§3.6.1 step 6, §3.6.3): an application's finish — applied, or failed with what was restored. */
export interface RunApplyOutcome {
  status: "applied" | "apply_failed";
  files: { path: string; state: ApplyFileState }[];
  detail: string | null;
}

/** The typed fields each run_transition kind sends (Ledger/RunRequest.cs allowlists them; any other key is refused). */
export interface RunTransitionFields {
  open: { runJsonDigest: Hex64; budgets: { maxReviews: number; maxCheckExecutions: number; maxFixes?: number }; baseline: { sourceId: Hex64; digest: Hex64 } | null };
  op_begin: { operationKind: "checks"; planned: { check: string; checkSpecId: Hex64 | null; definitionDigest: Hex64 | null; required: boolean; executable?: string | null }[]; inputIdentity: Hex64 | null } | RunReviewReserve | RunFixBegin | RunApplyBegin;
  record_execution: { operationId: string; execution: RunCheckExecution };
  op_finish: {
    operationId: string;
    outcome: { status: "completed" | "cancelled" | "error"; error: string | null } | RunReviewOutcome | RunFixOutcome | RunApplyOutcome;
    /** P3.4C-5: a custodian-captured review's prompt digest (required when it completed) and what it presented. */
    promptDigest?: Hex64 | null;
    presented?: RunReviewPresented | null;
  };
  recover: { operationId: string; incidents: { kind: "possible_surviving_sandboxed_commands" | "termination_unconfirmed"; detail: string }[] };
  respond: { responseSetId: string; disclosureDigest: Hex64 | null; responses: RunResponse[] };
  end: { status: "stopped" | "closed"; reason: string };
  /** Phase 4 Increment 3 (§3.6.4): what the reconciliation of an interrupted application did (restore or leave). */
  apply_reconcile: { operationId: string; choice: "restore" | "leave"; observed: "none" | "partial" | "all_at_postimage"; files: { path: string; state: ApplyFileState }[]; detail: string | null };
}

/** The codes with which the custodian refuses a run transition: each a decided refusal — nothing was applied — the
 * engine reacts to; any other code is a fault. */
export const RUN_REFUSAL_CODES = [
  "RUN_NOT_OPEN", "RUN_TERMINAL", "RUN_DECLARATION_CONFLICT", "RUN_BUSY", "OPERATION_NOT_RUNNING", "WRITER_MISMATCH",
  "OPERATION_WRITER_ALIVE", "EVIDENCE_NOT_HELD", "BUDGET_EXHAUSTED", "FINDING_NOT_FOUND", "FINDING_NOT_RESPONDABLE",
  "INVALID_ITEM_TRANSITION", "PROCESS_IDENTITY_UNVERIFIED", "STALE_FINDING_STATE", "REQUEST_ID_CONFLICT", "CALLER_NOT_AUTHORIZED",
  "LOOP_NOT_AUTHORIZED",
  // P3.4C-4 (contract §3.3).
  "CONFIG_NOT_HELD", "CONFIG_LAPSED", "CHECK_NOT_APPROVED", "ISOLATION_NOT_ACCEPTED", "CONFIG_MISMATCH",
  // P3.4C-5 (contract §3.1, §6): the custodian's capture helper is not installed, or no usable runtime is approved.
  "HELPER_UNAVAILABLE", "RUNTIME_NOT_APPROVED",
  // P3.4C-5 Increment 4 (§2.3, §6, N5-8): the helper's group cannot read the repository.
  "REPOSITORY_NOT_READABLE",
  // Phase 4 Increment 3 (contract §3.5, §3.6): the owner's confirmation and the application of a delegated fix — and the
  // custodian's measurement before an application, when it did not succeed (nothing was applied).
  "CONFIRMATION_CONTENT_MISMATCH", "PROPOSAL_NOT_PENDING", "FIX_NOT_CONFIRMED", "FIX_DECLINED", "CONFIRMATION_EXPIRED", "CONFIRMATION_CONSUMED",
  "APPLY_IN_PROGRESS", "FIX_STALE", "MEASUREMENT_FAILED", "MEASUREMENT_TIMEOUT", "MEASUREMENT_CANCELLED",
] as const;
export type RunRefusalCode = (typeof RUN_REFUSAL_CODES)[number];

/**
 * The grant ceilings the custodian enforces (CustodianConstants.cs MaxGrantLoops / MaxGrantMinutes),
 * mirrored ONLY to refuse an out-of-range request before it is sent and to describe a grant before the
 * custodian has been asked. The custodian enforces its own values and reports them (`list_grants`); a
 * client never states a higher limit than those.
 */
export const CUSTODIAN_GRANT_CEILINGS = Object.freeze({ loops: 8, minutes: 180 });

/**
 * The deterministic NT SERVICE\CodeParleyCustodian SID: SHA-1 of the upper-cased name encoded UTF-16LE,
 * as five little-endian uint32 sub-authorities (the standard virtual-service-account derivation, matching
 * Security/ServiceSid.cs and `sc showsid CodeParleyCustodian`). Computed in TypeScript so the trust
 * anchor the client enforces is not taken on faith from a helper.
 */
export function custodianServiceSid(): string {
  const h = createHash("sha1").update(Buffer.from("CODEPARLEYCUSTODIAN", "utf16le")).digest();
  const subs: number[] = [];
  for (let i = 0; i < 5; i++) subs.push(h.readUInt32LE(i * 4));
  return "S-1-5-80-" + subs.join("-");
}

// Decision 3: the repository's identity is the CUSTODIAN's own (handle-backed FILE_ID_INFO, refused
// rather than guessed; custodian/…/Security/RepoIdentity.cs). The client sends the repository path only
// as a locator and never computes, sends or compares a key.

const ENGINE_CODES: ReadonlySet<string> = new Set<ErrorCode>([
  "LOOP_NOT_AUTHORIZED", "REQUEST_ID_CONFLICT", "STALE_FINDING_STATE", "INVALID_ARGUMENT",
  "CALLER_NOT_AUTHORIZED", "AUTHORIZATION_INVALID", "AUTHORIZATION_EXPIRED", "OPERATOR_PROOF_REQUIRED",
  "MALFORMED_REQUEST", "CUSTODIAN_UNAVAILABLE", "SERVER_NOT_TRUSTED", "INTERNAL",
  // P3.4C-2: a run's loop is minted once and never resurrected.
  "RUN_ALREADY_HAS_LOOP", "LOOP_TERMINAL",
  // P3.4C-3: the custodian's run records (contract §3.2): consume_loop needs an open run; run_transition's refusals.
  "RUN_NOT_OPEN", "RUN_TERMINAL", "RUN_DECLARATION_CONFLICT", "RUN_BUSY", "OPERATION_NOT_RUNNING", "WRITER_MISMATCH",
  "OPERATION_WRITER_ALIVE", "EVIDENCE_NOT_HELD", "BUDGET_EXHAUSTED", "FINDING_NOT_FOUND", "FINDING_NOT_RESPONDABLE",
  "INVALID_ITEM_TRANSITION", "PROCESS_IDENTITY_UNVERIFIED",
  // P3.4C-4: the custodian-held trusted configuration (contract §3).
  "CONFIG_NOT_HELD", "CONFIG_LAPSED", "CHECK_NOT_APPROVED", "ISOLATION_NOT_ACCEPTED", "CONFIG_MISMATCH", "STALE_CONFIG", "CODEX_INSTALLATION_UNSUPPORTED",
  // P3.4C-5: the custodian's review capture (contract §3.1, §6).
  "HELPER_UNAVAILABLE", "RUNTIME_NOT_APPROVED",
  // P3.4C-5 Increment 4 (N5-8).
  "REPOSITORY_NOT_READABLE",
  // Phase 4 Increment 3 (contract §3.5, §3.6).
  "CONFIRMATION_CONTENT_MISMATCH", "PROPOSAL_NOT_PENDING", "FIX_NOT_CONFIRMED", "FIX_DECLINED", "CONFIRMATION_EXPIRED", "CONFIRMATION_CONSUMED",
  "APPLY_IN_PROGRESS", "FIX_STALE", "MEASUREMENT_FAILED", "MEASUREMENT_TIMEOUT", "MEASUREMENT_CANCELLED",
  // Step 7.1: a guided selection that no longer matches the custodian's evidence.
  "SELECTION_STALE",
  // Phase 5 (contract §4.12): the Linux custodian's Codex sandbox basis is not approvable or changed since its confirmation.
  "CODEX_ISOLATION_UNAVAILABLE",
  // Phase 5 F-i2-5: the custodian's redaction of an amendment could not be established.
  "REDACTION_REFUSED",
]);

/** Map a custodian response/transport error to a DomainError. Unknown codes collapse to INTERNAL so a
 * custodian can never widen the engine's error surface by returning a novel code. */
export function custodianError(code: string | undefined, message: string, retryable = false): DomainError {
  const c = code && ENGINE_CODES.has(code) ? (code as ErrorCode) : "INTERNAL";
  return new DomainError(c, message, { retryable, details: code && c === "INTERNAL" && code !== "INTERNAL" ? { custodian_code: code } : undefined });
}
