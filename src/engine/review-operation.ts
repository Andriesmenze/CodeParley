// The `review` operation (plan §5.4, §10.2, §10.4, §11.5, §12, §13; MR-D, MR-F, MR-K).
//
// Start (synchronous part, before any process runs):
//   1. validate arguments; recover dead owners' operations (a dead review leaves an
//      isolation incident: MXC sandboxed commands may have survived, M1.3-11);
//   2. request_id idempotency; refuse a terminal or busy run, a preparing run, an exhausted
//      review budget; probe Codex (native exe, supported version, required flags);
//   3. take a Codex concurrency slot (per server instance) and commit the operation as
//      `running` (the single commit point, §15.3).
// Execution (background):
//   a. effective isolation: S1 from a stored self-test of the exact profile (the self-test
//      runs now if there is none), S2 only with a CLI-written acceptance; else fail closed;
//   b. capture a sanitized export (under the worktree lock, released afterwards — reviews
//      never hold the lock while Codex runs, §14.4);
//   c. check evidence for the reviewed source: structured metadata only (rev 0.7);
//   d. the bundle from engine-owned data (policy/review-bundle.ts), the MR-F invariant,
//      the rendered prompt; review_input_id; an identical completed review is returned
//      instead of starting Codex (unless force_new);
//   e. commit the review record (`running`) and budget use, verify the export, run Codex;
//   f. verify the export again, recompute the source identity and the check evidence:
//      a result whose source or evidence changed during the review is kept for audit but
//      marked stale, never presented as current;
//   g. validate the output (zod, size caps), triage (MR-K), carry reviewer items forward
//      (MR-D), record isolation incidents; artifacts first, then one commit.
// Reviewer statements never touch engine-owned conditions: check and coverage conditions
// are derived from engine records when reported; incidents are append-only.
//
// Phase 2.2 (plan §1.15): the discussion. Step d also plans what of the implementer's turns this
// review presents (policy/discussion.ts: the new-information gate and the exchange budgets),
// prepares their text for the model with every withheld name and hash of the run (P2.2-9), and
// binds the presented discussion into review_input_id (P2.2-5); the review record carries the
// delivery record from step e on. Step g takes the reviewer's structured replies and restatement
// links: only an accepted review records them (in the same single commit), and a reply never
// changes an item's lifecycle. Nothing here starts another review, a response or a check.
//
// Phase 2.3 (plan §1.16, P2.3-9): step d also presents the user's effective task amendments in
// their own section (prepared for the model like the discussion, P2.3-14), binds the presented
// section into review_input_id, and the review record carries the amendment delivery record from
// step e on. An amendment counts as seen by the reviewer only through an accepted review's record.

import { readFile, rm } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { randomBytes } from "node:crypto";
import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfBytes, sha256OfCanonicalJson, sha256OfString } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { runCapture, loadBaseline, type CaptureRulesInput, type CaptureResult } from "../capture/capture.js";
import { verifyReviewExport, type ExportAnchor } from "../capture/export-writer.js";
import { withheldPaths } from "../capture/manifest.js";
import { compileGlobs, matchesAny } from "../capture/globs.js";
import { computeSourceIdentity } from "../capture/capture.js";
import { cancellationRecord, runCodexReview, DEFAULT_RUN_LIMITS, type ReviewRunLimits, type ReviewRunResult } from "../agents/codex/adapter.js";
import { execArgv, grantExposes, type IsolationArgvInput, type SandboxBackend } from "../agents/codex/argv.js";
import { canonicalizePath, caseKey } from "../workspace/paths.js";
import type { EventLimits } from "../agents/codex/events.js";
import { decideIsolation, isolationUnavailableError, loadAcceptances } from "../agents/codex/isolation.js";
import { reviewOutputJsonSchema } from "../agents/codex/output-schema.js";
import { assertCanonicalGrant, probeCodex, type CodexProbe } from "../agents/codex/probe.js";
import { ensureSelfTest, loadSelfTest, SelfTestInterruptedError, type SelfTestDeps } from "../agents/codex/selftest.js";
import { approvedCodexImage, confirmedSelfTest, heldAcceptances, heldCaptureRules, heldCaptureRulesDigest, heldConfigFor, requireUsableHeld, type HeldConfig } from "./protected-config.js";
import { buildChildEnv, lookupEnv } from "../process/env.js";
import { checkOperationTermination, snapshotProcessTable, type SweepDeps, type TerminationCheck } from "../process/proc-table.js";
import { carryForward } from "../policy/carry-forward.js";
import { discussionState, itemDiscussion, latestResponses, reportDiscussion, responseBeforeReview, type DiscussionState, type ItemDiscussion, type ReportDiscussion } from "../policy/responses.js";
import { checkResultsDigest, discussionIndexOf, planDiscussion, processReplies, threadOfItem } from "../policy/discussion.js";
import { amendmentDelta, amendmentWithheldDetail } from "../policy/amendments.js";
import { itemOrder, itemPositions } from "../policy/threads.js";
import { hostText } from "../policy/host-disclosure.js";
import { REVIEW_DISCUSSION_SCHEMA, type ReviewerReply } from "../schemas/discussion.js";
import { REVIEW_AMENDMENTS_SCHEMA } from "../schemas/user-authority.js";
import {
  assertBundleConfidential,
  assertTextConfidential,
  buildBundle,
  BundleTooLargeError,
  coverageConditions,
  BUNDLE_POLICY_VERSION,
  DEFAULT_BUNDLE_LIMITS,
  deliverableAmendmentIds,
  ENGINE_AUTHORED_SECTIONS,
  type BundleAmendmentsInput,
  type BundleLimits,
} from "../policy/review-bundle.js";
import {
  CLAMP,
  OPEN_TRIAGE,
  TRIAGE_POLICY_VERSION,
  clamp,
  countLines,
  normalizeReportedPath,
  triageFinding,
  verdictConflicts,
  type ExportIndex,
} from "../policy/triage.js";
import { testsRemoved, type ChangeLike } from "../policy/verification-floor.js";
import { loadTemplate, promptDigest, renderTemplate } from "../prompts/render.js";
import { publishArtifact, resolveArtifact } from "../store/artifacts.js";
import { readTextIfExists } from "../store/atomic.js";
import type { LockDeps } from "../store/locks.js";
import { aliveIfOwnInstance, classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type Liveness, type OwnerRecord } from "../store/owner.js";
import { canonicalPathKey, worktreeLockPath, type RunPaths } from "../store/paths.js";
import { applyRecovery, planRecovery } from "../store/recovery.js";
import { commitState, readState } from "../store/state-store.js";
import type { Limitation, ReviewManifest } from "../schemas/capture.js";
import { CaptureRecordSchema, ReviewTargetSchema } from "../schemas/capture.js";
import type { UserConfig } from "../schemas/config.js";
import {
  ReviewOutputSchema,
  REVIEW_OUTPUT_SCHEMA_VERSION,
  TaskEnvelopeSchema,
  MAX_ENVELOPE_BYTES,
  ReviewDepthEnum,
  type CheckEvidenceItem,
  type EffectiveIsolation,
  type IsolationIncident,
  type ReviewDepth,
  type ReviewFreshness,
  type ReviewOutput,
  type ReviewRecord,
  type ReviewStatus,
  type ReviewerItem,
  type TaskEnvelope,
  type CancellationRecord,
  type CodexAudit,
} from "../schemas/review.js";
import type { Operation, RunMeta, StateRecord } from "../schemas/run-state.js";
import { evaluateChecksStatus, loadTrustedState, type ChecksEngineContext } from "./checks-operation.js";
import { modelWithheld } from "./host-view.js";
import { reviewUserRecords } from "./protected-user-records.js";
import { evidenceViewOf, hydrateRunEvidence } from "./run-evidence.js";
import { loadAmendmentTexts, type WithheldAmendment } from "./disclosure-artifact.js";
import { custodianPresence, type CustodianTestHooks } from "../custodian/protected-loops.js";
import type { RunReviewOutcome, RunReviewPresented, RunReviewReserve } from "../custodian/protocol.js";
import { awaitCustodianCapture, capturedIdentities, loadPublishedCapture, presentedOf, presentedWithinOffered, type Reservation } from "./custodian-capture.js";
import { artifactDigest, bounded, custodianEvidenceFor, reconcileCustodianRun, type CustodianEvidence, type EvidenceSelection } from "./custodian-evidence.js";
import type { CustodianPresence } from "../custodian/service-presence.js";
import { computeReviewInputId } from "./identities.js";
import { HARD_MAX_REVIEWS_PER_RUN } from "./hard-limits.js";

export const REVIEW_POLICY_VERSION = `review.v1+${TRIAGE_POLICY_VERSION}+${BUNDLE_POLICY_VERSION}`;
const HARD_MAX_CONCURRENT = 4;
const HARD_MAX_WALL_SECONDS = 3600;
const TERMINAL_RUN_STATES = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

export interface ReviewEngineContext {
  dataHome: string;
  runPaths: RunPaths;
  meta: RunMeta;
  gitExe: string;
  rules: CaptureRulesInput;
  owner: OwnerRecord;
  trustProjectsPath: string;
  trustIsolationPath: string;
  selftestDir: string;
  codex: UserConfig["codex"];
  budgets: { max_reviews_per_run: number; max_check_executions_per_run: number };
  /** The server environment explicit child environments are built from. Default process.env. */
  sourceEnv?: NodeJS.ProcessEnv;
  lockDeps?: LockDeps;
  classify?: (owner: OwnerRecord) => Promise<Liveness>;
  /** P3.4C-1: the protected-loop gate's custodian hook, so a review of a GOVERNED run reads the
   * authoritative user records (and the reviewer-visible amendment disclosure artifacts) from the
   * custodian. Absent on a never-governed run / custodian-less host (then the TS store is used). */
  custodian?: CustodianTestHooks;
  /** P3.4C-3 (contract §5.4): whether the custodian service is registered on this host (the engine's query). A
   * context built without it (tests only) asks nothing of the host: registered with a custodian hook, else absent. */
  custodianPresence?: () => Promise<CustodianPresence>;
  /** P3.4C-3: a protected run's evidence as the custodian holds it (`hydrateRunEvidence`), applied wherever this
   * context re-reads the run's check evidence (a review's freshness); absent: the TS store. */
  evidenceView?: (st: StateRecord) => Promise<StateRecord>;
  /** P3.4C-4: a PROTECTED run's custodian-held configuration, read again on every use (fail closed): the checks and
   * floor, the capture rules, the isolation basis and the approved Codex installation. Absent for an attended run. */
  heldConfig?: () => Promise<HeldConfig>;
  /** P3.4C-4: the custodian surface this process reads a protected run's configuration on (default implementer). */
  custodianSurface?: "operator" | "implementer";
  testHooks?: ReviewTestHooks;
}

/**
 * P3.4C-4: the review context of a protected run — its configuration from the custodian (read again on every use) and
 * the held capture rules; an attended run's context is returned unchanged.
 */
export async function withHeldReviewConfig(ctx: ReviewEngineContext): Promise<ReviewEngineContext> {
  if (ctx.heldConfig) return ctx;
  const sel = { ...evidenceSelectionOf(ctx), ...(ctx.custodianSurface ? { surface: ctx.custodianSurface } : {}) };
  const held = await heldConfigFor(sel, await readState(ctx.runPaths));
  if (!held) return ctx;
  const again = async (): Promise<HeldConfig> => {
    const h = await heldConfigFor(sel, await readState(ctx.runPaths));
    if (!h) throw new DomainError("CUSTODIAN_UNAVAILABLE", "the custodian no longer reports this protected run's configuration; nothing proceeds (fail closed)", { retryable: false });
    return h;
  };
  return { ...ctx, rules: heldCaptureRules(held.section), heldConfig: again };
}

export interface ReviewTestHooks {
  /** TEST ONLY: run a scripted fake Codex as `<file> <prefixArgs…> <codex args…>`. */
  codexLauncher?: { file: string; prefixArgs: readonly string[] };
  selfTestDeps?: SelfTestDeps;
  sweep?: SweepDeps | null;
  limits?: Partial<ReviewRunLimits>;
  eventLimits?: Partial<EventLimits>;
  bundleLimits?: Partial<BundleLimits>;
  /** After the prompt is rendered, before Codex starts. */
  beforeCodex?: () => Promise<void> | void;
  afterSpawn?: (pid: number) => Promise<void> | void;
  /** After Codex exited, before freshness is re-checked (tests change source or evidence here). */
  afterCodex?: () => Promise<void> | void;
  /** Immediately before the single completion commit (fault injection, F11). */
  beforeCompletionCommit?: () => Promise<void> | void;
  /** TEST ONLY: the next `failures` terminal commits fail as a transient lock would; shorter retry timing. */
  terminalCommit?: { failures: number; retryMs?: number; backgroundMs?: number };
}

export interface ReviewRequest {
  focus?: string;
  depth?: ReviewDepth;
  force_new?: boolean;
  request_id?: string;
}

export interface FindingView extends Partial<ItemDiscussion> {
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
  impacts: ReviewerItem["impacts"];
  consequence: string;
  confidence: ReviewerItem["confidence"];
  evidence: ReviewerItem["evidence"];
  investigation: string;
  recommended_change: string;
  policy_notes: string[];
  related_prior_id: string | null;
  supersedes: string[];
  superseded_by: string | null;
}

export interface EngineConditionView {
  kind: "check_failed" | "check_stale" | "check_missing" | "coverage";
  detail: string;
  source: "engine";
  check?: string;
  code?: string;
}

export interface ReviewOperationResult {
  summary: string;
  operation_id: string;
  operation_status: string;
  review_id: string | null;
  round: number | null;
  status: ReviewStatus | "not_started";
  failure: { class: string; detail: string; code?: string } | null;
  deduplicated: boolean;
  source_id: string | null;
  review_input_id: string | null;
  /** Freshness NOW (recomputed when reported, F5); null when not a completed review. */
  freshness: ReviewFreshness | null;
  /** Freshness when the review completed (historical). */
  freshness_at_completion: ReviewFreshness | null;
  /** Whether this review was accepted as a current review result (F2). */
  accepted: boolean;
  not_accepted_reasons: string[];
  /** The run's current review: its latest ACCEPTED review, or null. */
  current_review_id: string | null;
  effective_isolation: EffectiveIsolation | null;
  verdict: ReviewOutput["verdict"] | null;
  assessment: string | null;
  findings: FindingView[];
  /**
   * Earlier rounds' items this review assessed (accepted reviews only; M1.6), with the
   * implementer's latest response recorded before this review assessed the item (Phase 2.1:
   * the reviewer's result never rewrites it) and the item's discussion state now.
   */
  prior_items: {
    id: string;
    round: number;
    title: string;
    triage: ReviewerItem["triage"];
    status: ReviewerItem["status"];
    assessment: string;
    response_before_review: { response_id: string; disposition: string; recorded_at: string } | null;
    /** Phase 2.2: the reviewer had seen that response by this review. */
    response_seen_by_reviewer: boolean;
    /** Phase 2.2: this review's bundle presented it. */
    presented_in_this_review: boolean;
    /** Phase 2.2: this review's discussion reply on the item. */
    reviewer_reply: { stance: string; new_information: string; reply_excerpt: string } | null;
    discussion_state: DiscussionState;
  }[];
  open_findings: FindingView[];
  conditions: EngineConditionView[];
  incidents: IsolationIncident[];
  /** `id` is the question's own item id; `finding_id` the finding it relates to. */
  questions: ({ id: string; question: string; finding_id: string | null; blocking: boolean } & Partial<ItemDiscussion>)[];
  positive_observations: { title: string; detail: string }[];
  suggestions: { title: string; detail: string }[];
  context_requests: { what: string; why: string }[];
  coverage: { files_reviewed: string[]; files_not_reviewed: string[]; reviewer_limitations: string; excluded_changed: { confidential_count: number; named: string[] } } | null;
  limitations: Limitation[];
  policy_notes: string[];
  reviewer: { cli_version: string | null; model: string | null; duration_ms: number | null; usage: CodexAudit["usage"]; commands_run: number; isolation_violations: string[] } | null;
  cancellation: CancellationRecord | null;
  budgets: { name: string; used: number; limit: number }[];
  /** Phase 2.2: what this review presented of the discussion and what the reviewer replied (P2.2-6, -10). */
  discussion: ReviewDiscussionView | null;
  /** Phase 2.3: the user's task amendments this review presented, and those it did not (P2.3-9, -12). */
  amendments: ReviewAmendmentsView | null;
}

export interface ReviewAmendmentsView {
  /** Presented to Codex as the user's own task context (A-n). */
  presented: { id: string; amendment_id: string }[];
  /** Effective then, but not presented: their text could not be prepared safely. */
  withheld: { id: string; amendment_id: string; reason: string }[];
  /** Effective NOW but not presented by this review: recorded since (the next review you request presents them), or withheld (to be replaced). */
  not_presented_now: string[];
  /** Presented by this review, but replaced or withdrawn since. */
  no_longer_effective: string[];
  note: string;
}

export interface ReviewDiscussionView {
  /** Implementer turns the bundle presented: reply-seeking (exchanges) and context. */
  presented: number;
  reply_sought: number;
  context: number;
  /** The reviewer's replies (recorded only if the review was accepted). */
  replies: { item_id: string; stance: string; new_information: string; reply_excerpt: string }[];
  replies_recorded: boolean;
  /** Items that awaited a reply and got none. */
  awaiting_without_reply: string[];
  /** Latest implementer turns the review did not present, and why (bounded). */
  not_delivered: { response_id: string; item_id: string; reason: string }[];
  not_delivered_total: number;
  note: string;
}

export interface ReviewStart {
  operation_id: string;
  deduplicated: boolean;
  completion: Promise<ReviewOperationResult>;
}

interface OwnedReview {
  controller: AbortController;
  completion: Promise<ReviewOperationResult>;
}
const owned = new Map<string, OwnedReview>();
let activeCodex = 0;

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

export async function startReview(ctx: ReviewEngineContext, req: ReviewRequest): Promise<ReviewStart> {
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) throw new DomainError("INVALID_ARGUMENT", "request_id must be 1 to 128 characters");
  if (req.focus !== undefined && req.focus.length > 4000) throw new DomainError("INVALID_ARGUMENT", "focus must be at most 4000 characters");
  const depth = ReviewDepthEnum.safeParse(req.depth ?? "standard");
  if (!depth.success) throw new DomainError("INVALID_ARGUMENT", "depth must be focused, standard or deep");
  const requestKey = { focus: req.focus ?? null, depth: depth.data, force_new: req.force_new === true };

  await recoverDeadOwners(ctx);
  const st0 = await readState(ctx.runPaths);
  const pre = decideStart(st0, ctx, req, requestKey);
  if (pre.kind === "existing") return existingStart(ctx, pre.op);
  // P3.4C-3: a protected run's review is recorded with the custodian first (op_begin with every binding, op_finish
  // with its outcome; acceptance is the custodian's). Refused here, before anything is committed, when the custodian
  // cannot answer for a run marked protected.
  const custodianEv = await custodianEvidenceFor(evidenceSelectionOf(ctx), st0);
  // P3.4C-4: a protected run reviews on the custodian's configuration only, and launches exactly the approved Codex
  // installation (TD clarification II): it is the probe's configured executable, whatever config.json or --codex say.
  ctx = await withHeldReviewConfig(ctx);
  const held = ctx.heldConfig ? await ctx.heldConfig() : null;
  let configured = ctx.codex.executable;
  if (held) {
    const r = requireUsableHeld(held.section);
    if (!r.codexInstallation) throw new DomainError("CONFIG_NOT_HELD", "the repository's protected configuration has no approved Codex installation; a protected review is refused — the operator sets one with code-parley config set --repo <path> --codex <codex.exe>", { retryable: false });
    configured = r.codexInstallation.path;
  }

  // Offline probe: refuse an unusable Codex before anything is committed.
  const probe = await probeCodex({ configured, sourceEnv: ctx.sourceEnv ?? process.env, testLauncher: ctx.testHooks?.codexLauncher ?? null });
  // The image a protected review hashes is the image it launches (only the test-only launcher hook separates them).
  const launch = probe.launcher;
  if (held && !ctx.testHooks?.codexLauncher && launch.file !== launch.exe) throw new DomainError("INTERNAL", "the Codex launcher is not the probed executable; a protected review is refused");

  const cap = Math.min(ctx.codex.max_concurrent, HARD_MAX_CONCURRENT);
  if (activeCodex >= cap) throw new DomainError("CODEX_BUSY", `this server already runs ${activeCodex} Codex review(s) (limit ${cap})`, { retryable: true });
  activeCodex++;
  let slotHeld = true;
  const releaseSlot = () => {
    if (slotHeld) {
      slotHeld = false;
      activeCodex--;
    }
  };

  const operationId = uuidv7();
  let existing: Operation | null = null;
  try {
    await commitState(ctx.runPaths, ctx.owner, (cur) => {
      const d = decideStart(cur, ctx, req, requestKey);
      if (d.kind === "existing") {
        existing = d.op;
        return cur;
      }
      cur.operations.push({
        operation_id: operationId,
        kind: "review",
        status: "running",
        owner: ctx.owner,
        input_identity: sha256OfCanonicalJson({ schema: "arl.review-op-request.v1", ...requestKey }),
        ...(req.request_id !== undefined ? { request_id: req.request_id } : {}),
        request: requestKey,
        started_at: new Date().toISOString(),
        command_lines: [`codex exec (review) ${probe.launcher.exe}`],
      });
      cur.state = "REVIEWING";
      pushEvent(cur, "review.started", `review started (depth ${requestKey.depth})`, { operation_id: operationId });
      return cur;
    });
  } catch (e) {
    releaseSlot();
    throw e;
  }
  if (existing) {
    releaseSlot();
    return existingStart(ctx, existing);
  }
  const controller = new AbortController();
  const completion = executeReview(ctx, operationId, requestKey, probe, controller.signal, custodianEv).finally(() => {
    releaseSlot();
    owned.delete(operationId);
  });
  owned.set(operationId, { controller, completion });
  return { operation_id: operationId, deduplicated: false, completion };
}

type StartDecision = { kind: "new" } | { kind: "existing"; op: Operation };

function evidenceSelectionOf(ctx: ReviewEngineContext): EvidenceSelection {
  return { custodian: ctx.custodian, presence: ctx.custodianPresence ?? (() => custodianPresence(true, ctx.custodian)), repositoryRoot: ctx.meta.repository_root, runId: ctx.meta.run_id, runJson: { path: ctx.runPaths.runJson, meta: ctx.meta } };
}

/** A review operation the custodian began for a protected run: its channel and the custodian-issued operation id. */
interface CustodianReview {
  evidence: CustodianEvidence;
  operationId: string;
}

/** Finish a custodian review whose local execution failed before an outcome existed (best effort: an unreachable
 * custodian leaves it running until its writer is gone and a later `recover`). */
async function failCustodianReview(op: CustodianReview | null, operationId: string, cancelled: boolean, incidents: readonly IsolationIncident[]): Promise<void> {
  if (!op) return;
  const outcome: RunReviewOutcome = {
    status: cancelled ? "cancelled" : "failed",
    outputValid: false,
    currentAtCompletion: false,
    verdict: null,
    summaryDigest: null,
    artifacts: { rawOutput: null, output: null, items: null, result: null, events: null, stderr: null, lastMessage: null },
    newItems: [],
    assessments: [],
    replies: [],
    incidents: incidents.map((i) => ({ kind: i.kind, detail: bounded(i.detail) })),
  };
  await op.evidence.transition("op_finish", { operationId: op.operationId, outcome }, `${operationId}-finish`).catch(() => undefined);
}

function decideStart(state: StateRecord, ctx: ReviewEngineContext, req: ReviewRequest, requestKey: unknown): StartDecision {
  if (req.request_id !== undefined) {
    const same = state.operations.find((o) => o.request_id === req.request_id);
    if (same) {
      if (same.kind === "review" && sha256OfCanonicalJson(same["request"] ?? null) === sha256OfCanonicalJson(requestKey)) return { kind: "existing", op: same };
      throw new DomainError("REQUEST_ID_CONFLICT", `request_id ${req.request_id} was already used with different arguments`, { details: { operation_id: same.operation_id } });
    }
  }
  if (TERMINAL_RUN_STATES.has(state.state)) throw new DomainError("RUN_TERMINAL", `run is ${state.state}`);
  const active = state.operations.find((o) => o.status === "running");
  if (active) {
    if (active.kind === "review" && sha256OfCanonicalJson(active["request"] ?? null) === sha256OfCanonicalJson(requestKey)) return { kind: "existing", op: active };
    throw new DomainError("RUN_BUSY", `run has an active ${active.kind} operation ${active.operation_id}`, { retryable: true, details: { operation_id: active.operation_id } });
  }
  if (state.state === "PREPARING") throw new DomainError("RUN_BUSY", "run is still preparing", { retryable: true });
  const used = state.counters["reviews"] ?? 0;
  const limit = reviewLimit(ctx);
  if (used >= limit) throw new DomainError("BUDGET_EXHAUSTED", `review budget: ${used} of ${limit} used`, { details: { used, limit } });
  return { kind: "new" };
}

function reviewLimit(ctx: ReviewEngineContext): number {
  return Math.min(ctx.budgets.max_reviews_per_run, HARD_MAX_REVIEWS_PER_RUN);
}

function existingStart(ctx: ReviewEngineContext, op: Operation): ReviewStart {
  const mine = owned.get(op.operation_id);
  return { operation_id: op.operation_id, deduplicated: true, completion: mine ? mine.completion : waitForReview(ctx, op.operation_id) };
}

async function recoverDeadOwners(ctx: ReviewEngineContext, custodian = true): Promise<void> {
  const classify = aliveIfOwnInstance(ctx.owner, ctx.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)));
  const state = await readState(ctx.runPaths);
  if (state.operations.some((o) => o.status === "running")) {
    const plan = await planRecovery(state, classify);
    if (plan.changed) await applyRecovery(ctx.runPaths, ctx.owner, plan, worktreeLockPath(ctx.dataHome, canonicalPathKey(ctx.meta.repository_root)));
  }
  // P3.4C-3 §5.2: then the custodian's record of a protected run (a pending end, operations whose writer is gone).
  if (custodian) await reconcileCustodianRun(evidenceSelectionOf(ctx), ctx.runPaths, ctx.owner);
}

/** Request cancellation of a review owned by this process (explicit only, D-27). */
export function requestReviewCancel(operationId: string): "cancellation_requested" | "not_owned" {
  const o = owned.get(operationId);
  if (!o) return "not_owned";
  o.controller.abort();
  return "cancellation_requested";
}

/** Every review operation this process owns (shutdown cancels them). */
export function ownedReviewOperations(): { operationId: string; completion: Promise<unknown> }[] {
  return [...owned.entries()].map(([operationId, o]) => ({ operationId, completion: o.completion }));
}

/** Wait (unbounded; callers bound it) for a review of this run to finish, then report. */
export async function waitForReview(ctx: ReviewEngineContext, operationId: string, pollMs = 250, signal?: AbortSignal): Promise<ReviewOperationResult> {
  const mine = owned.get(operationId);
  if (mine) return mine.completion;
  for (let i = 0; ; i++) {
    if (signal?.aborted) throw new DomainError("INTERNAL", "the wait for this review was abandoned");
    const st = await readState(ctx.runPaths);
    const op = st.operations.find((o) => o.operation_id === operationId);
    if (!op) throw new DomainError("RUN_NOT_FOUND", `operation ${operationId} not found`);
    if (op.status !== "running") return buildReviewResult(ctx, operationId);
    if (i > 0 && i % 20 === 0) await recoverDeadOwners(ctx, false);
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

class ReviewAbort extends Error {}

interface RequestKey {
  focus: string | null;
  depth: ReviewDepth;
  force_new: boolean;
}

async function executeReview(ctx: ReviewEngineContext, operationId: string, rk: RequestKey, probe: CodexProbe, signal: AbortSignal, custodianEv: CustodianEvidence | null = null): Promise<ReviewOperationResult> {
  const opDir = join(ctx.runPaths.opsDir, operationId);
  const opStartMs = Date.now();
  let capture: CaptureResult | null = null;
  let reviewId: string | null = null;
  let custodianOp: CustodianReview | null = null;
  let reservedRound: number | null = null;
  try {
    // a. Effective isolation (self-test now if none is stored for this exact profile).
    const iso = await resolveIsolation(ctx, probe, signal);
    if (signal.aborted) throw new ReviewAbort();

    // b. The run's records first (structured metadata only): a protected review selects what it presents before the
    // custodian captures (P3.4C-5, §3.1 step 1).
    const checksCtx = checksContextOf(ctx);
    let st0 = await readState(ctx.runPaths);
    // P3.4C-3 C2: the user records this review presents are selected by the CUSTODIAN's answer, never by a local
    // hint (reviewUserRecords): a protected run presents the custodian's records only; a custodian that cannot answer
    // refuses a run marked protected and otherwise presents none. Custodian amendments are presented from their
    // reviewer-visible disclosure artifacts, validated against the digests the custodian bound (a missing or altered
    // artifact withholds that amendment — fail closed, no raw-text fallback). A host without the custodian service
    // uses the TS store with no custodian exchange.
    const amendmentWithheld: WithheldAmendment[] = [];
    let heldAmendments: { amendment_id: string; disclosure_digest?: string | null }[] = [];
    {
      const presence = ctx.custodianPresence ?? (() => custodianPresence(true, ctx.custodian));
      const sel = await reviewUserRecords({ ...(ctx.custodian ? { custodian: ctx.custodian } : {}), repositoryRoot: ctx.meta.repository_root, runId: ctx.meta.run_id }, st0, presence);
      let amendments = sel.records.amendments;
      if (sel.records.source === "custodian") {
        heldAmendments = amendments as typeof heldAmendments;
        const loaded = await loadAmendmentTexts(ctx.runPaths, amendments);
        amendmentWithheld.push(...loaded.withheld);
        amendments = loaded.amendments;
      }
      st0 = { ...st0, user_decisions: sel.records.decisions, task_amendments: amendments };
      // A protected run's evidence is the custodian's (hydrateRunEvidence): only what it holds is presented and
      // assessed, and its check evidence is the current epoch's.
      st0 = await hydrateRunEvidence(st0, sel.records.run, ctx.runPaths.runDir);
      const view = evidenceViewOf(sel.records.run, ctx.runPaths.runDir);
      if (view) ctx = { ...ctx, evidenceView: view };
    }
    const template = await loadTemplate();

    // c. The sanitized export. Attended: the engine captures it (worktree lock held only during the capture). Protected
    // (P3.4C-5): the custodian captures and publishes it — the engine reserves the review and waits for the commit.
    let reservation: Reservation | null = null;
    if (custodianEv) {
      const p = await reserveAndAwaitCapture(ctx, operationId, rk, probe, iso.isolation, st0, heldAmendments, template, custodianEv, signal);
      if (p.kind === "deduplicated") {
        await finishOperation(ctx, operationId, "completed", { deduplicated_of: p.deduplicatedOf, review_id: p.deduplicatedOf });
        return buildReviewResult(ctx, operationId);
      }
      custodianOp = p.op;
      reviewId = p.reviewId;
      if (p.kind === "aborted") throw new ReviewAbort();
      reservation = p.reservation;
      reservedRound = p.round;
      capture = p.capture;
    } else {
      capture = await runCapture({
        kind: "review",
        repoRoot: ctx.meta.repository_root,
        gitExe: ctx.gitExe,
        target: targetOf(ctx.meta),
        rules: ctx.rules,
        runPaths: ctx.runPaths,
        operationId,
        lock: { dataHome: ctx.dataHome, owner: ctx.owner, ...(ctx.lockDeps ? { deps: ctx.lockDeps } : {}) },
        ...(await baselineFor(ctx)),
        signal,
      });
    }
    if (signal.aborted) throw new ReviewAbort();
    const manifest = capture.manifest!;
    const exportDir = capture.exportDir!;
    const sourceId = capture.record.source_id;

    // The check evidence for the reviewed source. A protected review's capture is of the source it selected its evidence
    // for (the custodian refuses another), so this is the evidence it reserved.
    const evidence = evidenceOf(await evaluateChecksStatus(checksCtx, sourceId, st0), st0);
    if (reservation && JSON.stringify([...evidence.executionIds].sort()) !== JSON.stringify([...reservation.fields.checkExecutionIds].sort())) {
      throw new DomainError("REVIEW_CAPTURE_FAILED", "the check evidence for the captured source is not the evidence the review reserved; begin the review again", { retryable: true, details: { reason: "evidence_changed" } });
    }
    const trusted = await loadTrustedState(checksCtx);
    const testGlobs = compileGlobs(trusted.evaluation.testGlobs ?? []);
    const removed = trusted.evaluation.testGlobs?.length ? testsRemoved(capture.record.changes, (p) => matchesAny(testGlobs, p)) : null;

    // d. Bundle, confidentiality invariant, prompt, review_input_id.
    // Oldest first (round, then the order the raising review listed them): PF-1 is the
    // earliest outstanding item. UUIDv7 ids are not ordered within one millisecond.
    const position = new Map<string, number>();
    for (const r of st0.reviews) r.item_ids.forEach((id, k) => position.set(id, k));
    const openItems = st0.findings.filter((f) => f.status === "open").sort((a, b) => a.round - b.round || (position.get(a.id) ?? 0) - (position.get(b.id) ?? 0));
    const withheld = withheldPaths(capture.record.entries, capture.record.changes);
    const withheldHashes = new Set<string>();
    for (const e of capture.record.entries) if (withheld.has(e.path) && e.sha256) withheldHashes.add(e.sha256);
    for (const c of capture.record.changes) if (c.confidential && c.base?.oid) withheldHashes.add(c.base.oid);
    const diffText = await readFile(join(exportDir, "review", "diff.patch"), "utf8").catch(() => "");
    // Phase 2.2: what of the implementer's turns this review presents (P2.2-4: the gate and the
    // budgets against the reviewed source and evidence), their text prepared for the model with
    // every withheld name and hash of the run, local paths scrubbed (P2.2-9).
    const dix0 = discussionIndexOf(st0);
    const forModel = await discussionWithheld(ctx, st0, manifest, capture, withheld, withheldHashes);
    const modelDisclosure = { withheldPaths: forModel.paths, withheldHashes: forModel.hashes, keepRoots: [], hiddenDirs: [{ dir: ctx.dataHome, label: "[data home]" }, { dir: ctx.meta.repository_root, label: "[repository]" }], posixPaths: process.platform !== "win32" };
    // Phase 2.3: the user's effective amendments, prepared like the discussion (P2.3-14).
    const amendmentsInput: BundleAmendmentsInput = {
      effective: dix0.amendments.effective,
      prepare: (t: string) => hostText(t, modelDisclosure),
      threadOf: (id: string) => {
        const it = dix0.itemById.get(id);
        return it ? threadOfItem(dix0, it).id : null;
      },
      seqOf: (id: string) => dix0.amendments.byId.get(id)?.seq ?? null,
    };
    // Only an amendment this bundle can present is new information for the gate (P2.3-10).
    const dplan = planDiscussion(dix0, { sourceId, checkResults: evidence.resultsDigest, pathKey: caseKey, deliverableAmendments: deliverableAmendmentIds(amendmentsInput, withheld) });
    const informational = st0.findings.filter((f) => f.status === "informational" && dplan.items.get(f.id)?.turn).sort(itemOrder(itemPositions(st0.reviews)));
    const bundleInput = {
      nonce: randomBytes(8).toString("hex"),
      envelope: envelopeOf(ctx.meta),
      focus: rk.focus,
      depth: rk.depth,
      manifest,
      diffText,
      withheldPaths: withheld,
      withheldHashes,
      checks: evidence.bundle,
      openItems,
      testsRemoved: removed,
      instructionFiles: ctx.codex.load_project_instructions ? await instructionFiles(exportDir, manifest) : null,
      discussion: { plans: dplan.items, informational, prepare: (t: string) => hostText(t, modelDisclosure) },
      amendments: amendmentsInput,
      ...(ctx.testHooks?.bundleLimits ? { limits: ctx.testHooks.bundleLimits } : {}),
    };
    // The cap applies to the FINAL rendered prompt (F9): the bundle is measured by rendering it.
    let bundle: ReturnType<typeof buildBundle>;
    try {
      bundle = buildBundle(bundleInput, (sections) => renderTemplate(template, sections).length);
    } catch (e) {
      if (e instanceof BundleTooLargeError) throw new DomainError("REVIEW_BUNDLE_TOO_LARGE", e.message, { details: { required_chars: e.requiredChars, max_chars: e.maxChars } });
      throw e;
    }
    assertBundleConfidential(bundle.data, withheld, withheldHashes);
    // P2.2-9: the presented discussion against every withheld name and hash of the run (fail closed).
    assertBundleConfidential(bundle.discussion.data, forModel.paths, forModel.hashes);
    // P2.3-14: the user's amendments likewise (their text is user-authored, like the envelope).
    assertBundleConfidential(bundle.amendments.data, forModel.paths, forModel.hashes);
    const prompt = renderTemplate(template, bundle.sections);
    const maxChars = { ...DEFAULT_BUNDLE_LIMITS, ...(ctx.testHooks?.bundleLimits ?? {}) }.maxBundleChars;
    if (prompt.length > maxChars) throw new DomainError("REVIEW_BUNDLE_TOO_LARGE", `the rendered prompt has ${prompt.length} characters, over the cap of ${maxChars}`);
    // MR-F invariant on the rendered, engine-authored text (any spelling, JSON escaping
    // included, F4). Repository content (the diff, quoted instruction files) is excluded.
    assertTextConfidential(ENGINE_AUTHORED_SECTIONS.map((k) => bundle.sections[k] ?? "").join("\n"), withheld, withheldHashes);

    // P3.4C-5 (§3.1 step 4): a protected review's input identity is the custodian's (from its capture and the reserved
    // bindings); the engine's own is the attended identity.
    const reviewInputId = reservation ? reservation.captured!.reviewInputId : computeReviewInputId({
      source_id: sourceId,
      target: manifest.target,
      base_id: manifest.base.kind === "baseline" ? manifest.base.baseline_capture_id : manifest.base.commit,
      // The manifest digest covers the per-capture id; the identity binds the content.
      export_manifest_digest: manifestContentDigest(manifest),
      check_execution_ids: evidence.executionIds,
      check_evidence_digest: evidence.digest,
      focus: rk.focus,
      depth: rk.depth,
      discussion_digest: bundle.discussion.digest,
      amendments_digest: bundle.amendments.digest,
      prompt_template: { id: template.id, version: template.version },
      output_schema_version: REVIEW_OUTPUT_SCHEMA_VERSION,
      policy_version: REVIEW_POLICY_VERSION,
      codex: { version: probe.version, model: ctx.codex.model, reasoning_effort: ctx.codex.reasoning_effort },
      isolation: iso.isolation,
    });

    // Unchanged-review guard (§5.4, F10): an identical ACCEPTED review is returned. A stale,
    // cancelled or otherwise non-accepted result is never handed out as current (F2).
    if (!rk.force_new && !custodianEv) {
      const dup = st0.reviews.find((r) => r.review_input_id === reviewInputId && r.status === "completed" && r.accepted === true);
      if (dup) {
        await rm(exportDir, { recursive: true, force: true }).catch(() => undefined);
        await finishOperation(ctx, operationId, "completed", { deduplicated_of: dup.review_id, review_id: dup.review_id });
        return buildReviewResult(ctx, operationId);
      }
    }
    if (signal.aborted) throw new ReviewAbort();

    // e. Artifacts first, then the review record (running) and the budget use.
    reviewId ??= uuidv7();
    const promptRef = (await publishArtifact(ctx.runPaths.runDir, ctx.runPaths.opsDir, operationId, "review/prompt.md", prompt)).ref;
    const schemaPath = (await publishArtifact(ctx.runPaths.runDir, ctx.runPaths.opsDir, operationId, "review/output-schema.json", JSON.stringify(reviewOutputJsonSchema(), null, 2))).absolute;
    // The discussion as presented (audit), and what was not presented, with why (P2.2-10).
    const presentedTurns = new Set(bundle.discussion.delivered.map((d) => d.response_id));
    const notDelivered = [...dplan.items.values()].flatMap((p) =>
      p.not_delivered ? [{ response_id: p.not_delivered.response_id, item_id: p.item_id, reason: p.not_delivered.reason }] : p.turn && !presentedTurns.has(p.turn.response.response_id) ? [{ response_id: p.turn.response.response_id, item_id: p.item_id, reason: "bundle_size_cap" }] : [],
    );
    // P3.4C-5 (§3.1 step 7): what the bundle presents, claimed at op_finish — within what the reservation offered.
    const presented = reservation
      ? presentedOf(bundle.discussion, notDelivered.length, bundle.amendments, new Map(st0.task_amendments.map((a) => [a.amendment_id, (a as { disclosure_digest?: string }).disclosure_digest ?? null])), amendmentWithheld.map((w) => w.amendment_id))
      : null;
    if (reservation && presented) {
      const problem = presentedWithinOffered(presented, reservation.fields);
      if (problem) throw new DomainError("REVIEW_CAPTURE_FAILED", `the bundle would present what the review did not reserve (${problem}); begin the review again`, { retryable: true, details: { reason: "presentation_changed" } });
    }
    const discussionRef = bundle.discussion.delivered.length || bundle.discussion.data.prior.length || bundle.discussion.data.informational.length
      ? (await publishArtifact(ctx.runPaths.runDir, ctx.runPaths.opsDir, operationId, "review/discussion.json", JSON.stringify({ digest: bundle.discussion.digest, presented: bundle.discussion.data, delivered: bundle.discussion.delivered, awaiting_reply: bundle.discussion.awaiting, not_delivered: notDelivered }, null, 2))).ref
      : null;
    const lastMessagePath = join(opDir, "review", "last-message.json");
    const record: ReviewRecord = {
      review_id: reviewId,
      operation_id: operationId,
      round: st0.reviews.length + 1,
      status: "running",
      failure: null,
      started_at: new Date().toISOString(),
      ended_at: null,
      duration_ms: null,
      source_id: sourceId,
      review_input_id: reviewInputId,
      capture_id: capture.record.capture_id,
      capture_stable: capture.record.stable,
      export_ref: reservation ? exportDir.replace(/\\/g, "/") : relRef(ctx.runPaths.runDir, exportDir),
      manifest_digest: manifest.manifest_digest,
      export_digest: capture.record.export!.export_digest,
      check_evidence_digest: evidence.digest,
      check_execution_ids: evidence.executionIds,
      effective_isolation: iso.isolation,
      codex: { version: probe.version, model: ctx.codex.model, reasoning_effort: ctx.codex.reasoning_effort },
      prompt: { template_id: template.id, template_version: template.version, sha256: promptDigest(prompt), bytes: Buffer.byteLength(prompt, "utf8"), artifact: promptRef },
      output_schema_version: REVIEW_OUTPUT_SCHEMA_VERSION,
      policy_version: REVIEW_POLICY_VERSION,
      depth: rk.depth,
      focus_sha256: rk.focus ? sha256OfString(rk.focus) : null,
      verdict: null,
      summary: null,
      item_ids: [],
      policy_notes: [],
      freshness: null,
      accepted: null,
      not_accepted_reasons: [],
      audit: null,
      incident_ids: [],
      cancellation: null,
      termination: null,
      artifacts: { prompt: promptRef, capture: capture.recordRef, ...(discussionRef ? { discussion: discussionRef } : {}) },
      bundle_limitations: [
        ...bundle.limitations,
        ...amendmentWithheld.map((w) => ({ code: "amendment_disclosure_unavailable", detail: `amendment ${w.amendment_id.slice(0, 8)} was not presented: its reviewer-visible disclosure artifact is ${w.reason === "disclosure_artifact_missing_or_altered" ? "missing or altered" : w.reason} (fail closed; no raw-text fallback)` })),
      ],
      discussion: {
        schema: REVIEW_DISCUSSION_SCHEMA,
        digest: bundle.discussion.digest,
        check_results_digest: evidence.resultsDigest,
        delivered: bundle.discussion.delivered,
        informational_presented: bundle.discussion.informationalPresented,
        not_delivered: notDelivered.slice(0, MAX_NOT_DELIVERED_RECORDED),
        ...(notDelivered.length > MAX_NOT_DELIVERED_RECORDED ? { not_delivered_total: notDelivered.length } : {}),
      },
      // Phase 2.3: the user's amendments it presents (counts only if the review is accepted, P2.3-9).
      amendments: { schema: REVIEW_AMENDMENTS_SCHEMA, digest: bundle.amendments.digest, presented: bundle.amendments.presented, withheld: bundle.amendments.withheld },
    };
    // P3.4C-5: a protected review was reserved before its capture (its round is the custodian's).
    if (reservation && reservedRound !== null) record.round = reservedRound;
    await commitState(ctx.runPaths, ctx.owner, (st) => {
      const used = st.counters["reviews"] ?? 0;
      if (used >= reviewLimit(ctx)) throw new DomainError("BUDGET_EXHAUSTED", `review budget: ${used} of ${reviewLimit(ctx)} used`);
      st.counters["reviews"] = used + 1;
      st.reviews.push(record);
      const op = st.operations.find((o) => o.operation_id === operationId);
      if (op) {
        op["review_id"] = reviewId!;
        if (custodianOp) op["custodian_operation_id"] = custodianOp.operationId;
      }
      if (iso.isolation.mode !== "S1") {
        st.isolation_incidents.push(incident(reviewId!, operationId, "isolation_reduced", `review runs with reduced isolation ${iso.isolation.mode} (reads ${iso.isolation.reads}, network ${iso.isolation.network}) under acceptance ${iso.isolation.acceptance_id}`));
      }
      pushEvent(st, "review.codex_starting", `review ${reviewId!.slice(0, 8)} round ${record.round}: Codex starting (${iso.isolation.mode}/${iso.isolation.backend})`, { operation_id: operationId, review_id: reviewId! });
      return st;
    });

    await ctx.testHooks?.beforeCodex?.();
    // Verify the export immediately before handing it to Codex (CG5), against what the
    // engine itself published — not against the manifest inside the export (F6).
    const anchor = { export_digest: capture.record.export!.export_digest, manifest_digest: capture.record.export!.manifest_digest };
    const v0 = await verifyReviewExport(exportDir, anchor);
    if (!v0.ok) throw new DomainError("INTERNAL", `the review export failed verification before Codex started: ${v0.problems.slice(0, 5).join("; ")}`);
    if (signal.aborted) throw new ReviewAbort();

    const env = buildChildEnv({ source: ctx.sourceEnv ?? process.env, includeCodexAuth: true, passthrough: ctx.codex.env_passthrough }).env;
    const argv = execArgv({ ...iso.argv, exportRoot: exportDir, outputSchemaPath: schemaPath, lastMessagePath, model: ctx.codex.model, reasoningEffort: ctx.codex.reasoning_effort });
    const wallSeconds = Math.min(rk.depth === "focused" ? 600 : rk.depth === "deep" ? 2400 : ctx.codex.review_timeout_seconds, HARD_MAX_WALL_SECONDS);
    const childCommits: Promise<unknown>[] = [];
    const run = await runCodexReview({
      launcher: probe.launcher,
      argv,
      exportRoot: exportDir,
      prompt,
      env,
      lastMessagePath,
      limits: {
        ...DEFAULT_RUN_LIMITS,
        wallMs: wallSeconds * 1000,
        idleMs: ctx.codex.idle_timeout_seconds * 1000,
        ...(ctx.testHooks?.eventLimits ? { events: ctx.testHooks.eventLimits } : {}),
        ...(ctx.testHooks?.limits ?? {}),
      },
      signal,
      sweep: ctx.testHooks?.sweep === undefined ? {} : ctx.testHooks.sweep,
      onSpawn: (child) => {
        childCommits.push(
          commitState(ctx.runPaths, ctx.owner, (st) => {
            const op = st.operations.find((o) => o.operation_id === operationId);
            if (op) op["child"] = { pid: child.pid, startedAtMs: child.startedAtMs, ...(child.startIdentity ? { startIdentity: child.startIdentity } : {}), commandLine: `codex exec (review ${reviewId})` };
            return st;
          }).catch(() => undefined),
        );
        if (ctx.testHooks?.afterSpawn) childCommits.push(Promise.resolve(ctx.testHooks.afterSpawn(child.pid)).catch(() => undefined));
      },
    });
    await Promise.all(childCommits);
    await ctx.testHooks?.afterCodex?.();
    const freshNow = await finalizeReview(ctx, operationId, record, run, capture, exportDir, anchor, evidence.digest, bundle.prior, bundle.notPresented, bundle.discussion, signal, custodianOp, presented ? { promptDigest: record.prompt.sha256, presented } : null);
    custodianOp = null;
    return buildReviewResult(ctx, operationId, freshNow);
  } catch (e) {
    const aborted = e instanceof ReviewAbort || e instanceof SelfTestInterruptedError || signal.aborted;
    const failure = aborted
      ? { class: "cancelled", detail: "cancelled on request before Codex ran" }
      : { class: isDomainError(e) ? e.code : "internal", detail: e instanceof Error ? e.message : String(e), ...(isDomainError(e) ? { code: e.code } : {}) };
    // Cancelled before (or while) Codex ran, outside the adapter: self-test probes or git
    // queries may have been killed. The same rule applies: "terminated" only with evidence
    // that nothing this operation started survives (F3).
    const cancellation: CancellationRecord | null = aborted ? cancellationRecord(new Date().toISOString(), await operationTermination(ctx, opStartMs)) : null;
    const extra = cancellation && cancellation.outcome !== "terminated" ? [unconfirmedCancellationIncident(reviewId, operationId, cancellation)] : [];
    await failCustodianReview(custodianOp, operationId, aborted, extra);
    // One commit point: the review record, the operation and the run state together (F11).
    // Retried, and never swallowed: a lost terminal commit would leave the run busy (PR #2 review).
    await commitTerminal(ctx, operationId, (st) => {
      if (reviewId) {
        const r = st.reviews.find((x) => x.review_id === reviewId);
        if (r && r.status === "running") {
          r.status = aborted ? "cancelled" : "failed";
          r.failure = failure;
          r.ended_at = new Date().toISOString();
          r.accepted = false;
          r.not_accepted_reasons = [aborted ? "cancelled" : "failed"];
          if (cancellation) r.cancellation = cancellation;
          r.incident_ids = [...r.incident_ids, ...extra.map((i) => i.incident_id)];
        }
      }
      for (const inc of extra) st.isolation_incidents.push(inc);
      completeOperation(st, operationId, aborted ? "cancelled" : "failed", { failure, ...(cancellation ? { cancellation } : {}) });
      return st;
    });
    return buildReviewResult(ctx, operationId);
  }
}

/** How a protected review's reservation and capture ended (P3.4C-5, §3.1 steps 2–4). */
type ReservedCapture =
  | { kind: "captured"; op: CustodianReview; reviewId: string; round: number | null; reservation: Reservation; capture: CaptureResult }
  | { kind: "deduplicated"; deduplicatedOf: string }
  | { kind: "aborted"; op: CustodianReview; reviewId: string };

/**
 * P3.4C-5 (contract §3.1 steps 1–4): reserve a protected review with the custodian and wait for its capture. Without the
 * capture, the engine selects what the review presents for the source it reads now (a claim the custodian's capture must
 * match: otherwise the custodian ends the operation `source_changed`): the check executions it would present, the
 * discussion turns its plan would deliver and every amendment the custodian holds for the run — and the isolation,
 * configuration and version claims. The custodian validates and reserves (`measuring`), captures through its helper,
 * publishes, and commits (`captured`) or ends the operation. On a capture, the published capture record and manifest are
 * read and checked against what the custodian committed. A failure after the reservation finishes the custodian's
 * operation (`failed`) before it is reported.
 */
async function reserveAndAwaitCapture(
  ctx: ReviewEngineContext,
  operationId: string,
  rk: RequestKey,
  probe: CodexProbe,
  isolation: EffectiveIsolation,
  st0: StateRecord,
  heldAmendments: readonly { amendment_id: string; disclosure_digest?: string | null }[],
  template: Awaited<ReturnType<typeof loadTemplate>>,
  ev: CustodianEvidence,
  signal: AbortSignal,
): Promise<ReservedCapture> {
  const target = targetOf(ctx.meta);
  if (target.kind === "since_baseline") throw new DomainError("INVALID_ARGUMENT", "a protected review of target since_baseline is not supported by the custodian's capture yet; use target uncommitted or base_ref");
  // The source the review selects its evidence and discussion for: a read of the working tree now (a claim).
  const selection = await computeSourceIdentity({
    repoRoot: ctx.meta.repository_root, gitExe: ctx.gitExe, rules: ctx.rules, operationId, operationStep: true,
    lock: { dataHome: ctx.dataHome, owner: ctx.owner, ...(ctx.lockDeps ? { deps: ctx.lockDeps } : {}) }, signal,
  });
  const evidence = evidenceOf(await evaluateChecksStatus(checksContextOf(ctx), selection.source_id, st0), st0);
  const dix = discussionIndexOf(st0);
  const offeredAmendments = new Set(dix.amendments.effective.map((a) => a.amendment_id));
  const plan = planDiscussion(dix, { sourceId: selection.source_id, checkResults: evidence.resultsDigest, pathKey: caseKey, deliverableAmendments: offeredAmendments });
  const offeredTurns = [...plan.items.values()].flatMap((p) => (p.turn ? [{ itemId: p.item_id, responseIds: [p.turn.response.response_id], replyIds: [] as string[] }] : []));
  if (!ctx.heldConfig) throw new DomainError("INTERNAL", "a protected review has no custodian-held configuration to claim (fail closed)");
  const held = await ctx.heldConfig();
  const { sha256: codexSha256 } = await approvedCodexImage(held.section, probe.launcher.exe, (a, b) => caseKey(a) === caseKey(b));
  const codex = { version: probe.version, model: ctx.codex.model, reasoning_effort: ctx.codex.reasoning_effort };
  const reviewId = uuidv7();
  const fields: RunReviewReserve = {
    operationKind: "review",
    reviewId,
    selectionSourceId: selection.source_id,
    target: target.kind === "base_ref" ? { kind: "base_ref", ref: target.ref } : { kind: "uncommitted" },
    checkExecutionIds: evidence.executionIds,
    checkEvidenceDigest: evidence.digest,
    checkResultsDigest: evidence.resultsDigest,
    discussion: { offered: offeredTurns },
    amendments: { offered: heldAmendments.map((a) => ({ amendmentId: a.amendment_id, disclosureDigest: a.disclosure_digest ?? null })) },
    isolation: { mode: isolation.mode, profileDigest: isolation.profile_digest, selftestId: isolation.selftest_id, acceptanceId: isolation.acceptance_id, backend: isolation.backend, codexVersion: isolation.codex_version },
    captureRulesDigest: heldCaptureRulesDigest(held.section),
    codexSha256,
    depth: rk.depth,
    focusDigest: rk.focus ? sha256OfString(rk.focus) : null,
    versionsDigest: sha256OfCanonicalJson({ codex, prompt: { id: template.id, version: template.version }, output_schema_version: REVIEW_OUTPUT_SCHEMA_VERSION, policy_version: REVIEW_POLICY_VERSION }),
  };
  const begun = await ev.transition("op_begin", fields, `${operationId}-begin`);
  const op: CustodianReview = { evidence: ev, operationId: String(begun["operationId"]) };
  const round = typeof begun["round"] === "number" ? begun["round"] : null;
  await commitState(ctx.runPaths, ctx.owner, (st) => {
    const local = st.operations.find((o) => o.operation_id === operationId);
    if (local) local["custodian_operation_id"] = op.operationId;
    pushEvent(st, "review.capture_reserved", `review ${reviewId.slice(0, 8)}: reserved with the custodian, which captures it (${op.operationId})`, { operation_id: operationId });
    return st;
  });
  try {
    const outcome = await awaitCustodianCapture(ev, op.operationId, signal);
    if (outcome === "aborted") return { kind: "aborted", op, reviewId };
    if (outcome.kind === "deduplicated") return { kind: "deduplicated", deduplicatedOf: outcome.deduplicatedOf };
    if (outcome.kind === "ended") {
      const err = new DomainError("REVIEW_CAPTURE_FAILED", `the custodian did not capture this review (${outcome.status}: ${outcome.reason}${outcome.detail ? ` — ${outcome.detail.slice(0, 300)}` : ""}); nothing was reviewed`, {
        retryable: outcome.reason === "source_changed" || outcome.reason === "source_unstable" || outcome.reason === "measurement_timeout",
        details: { reason: outcome.reason, operation_status: outcome.status },
      });
      (err as { custodianEnded?: boolean }).custodianEnded = true;
      throw err;
    }
    const captured = capturedIdentities(outcome.begin);
    const capture = await loadPublishedCapture(ctx.runPaths, operationId, captured);
    return { kind: "captured", op, reviewId, round, reservation: { fields, captured }, capture };
  } catch (e) {
    // The custodian's operation is still open unless the custodian ended it: finish it (failed) before reporting.
    if (!(e as { custodianEnded?: boolean }).custodianEnded) await failCustodianReview(op, operationId, signal.aborted, []);
    throw e;
  }
}

/** Undelivered turns a review's record names (the rest are counted). */
const MAX_NOT_DELIVERED_RECORDED = 100;

/**
 * The names and hashes discussion text sent to Codex must not carry (P2.2-9): this capture's
 * withheld set (content SHA-256 and git object id) and every earlier record of the run, minus the
 * names this export shows. A record that cannot be read fails the review before anything is sent.
 */
async function discussionWithheld(ctx: ReviewEngineContext, st0: StateRecord, manifest: ReviewManifest, capture: CaptureResult, withheld: ReadonlySet<string>, withheldHashes: ReadonlySet<string>): Promise<{ paths: Set<string>; hashes: Set<string> }> {
  const exported = new Set<string>();
  for (const f of manifest.files) exported.add(caseKey(f.path));
  for (const c of manifest.changes) {
    exported.add(caseKey(c.path));
    if (c.old_path) exported.add(caseKey(c.old_path));
  }
  for (const w of withheld) exported.delete(caseKey(w));
  const hashes = new Set(withheldHashes);
  for (const e of capture.record.entries) if (withheld.has(e.path) && e.git_oid) hashes.add(e.git_oid);
  try {
    return await modelWithheld(ctx.runPaths.runDir, st0, { paths: withheld, hashes }, exported, caseKey);
  } catch (e) {
    throw new DomainError("INTERNAL", `a confidentiality record of this run could not be read, so the implementer's text cannot be checked before it is sent: nothing was sent to Codex (${(e instanceof Error ? e.message : String(e)).slice(0, 160)})`);
  }
}

async function resolveIsolation(ctx: ReviewEngineContext, probe: CodexProbe, signal: AbortSignal): Promise<{ isolation: EffectiveIsolation; argv: IsolationArgvInput }> {
  // Windows: the configured backend or the probe-confirmed preference (mxc); Linux: the compatibility row's (bwrap).
  const backends: SandboxBackend[] = process.platform === "win32" && ctx.codex.windows_sandbox ? [ctx.codex.windows_sandbox] : [...probe.compat.preferredBackends];
  // The install-directory grant must not contain the user profile, the run store or the
  // repository (all canonical): such a grant would widen S1 far beyond the export (F1).
  const protectedPaths: string[] = [];
  // The Codex home holds the login (auth.json): no S1 grant may cover it either.
  for (const p of [lookupEnv(ctx.sourceEnv ?? process.env, process.platform === "win32" ? "USERPROFILE" : "HOME"), ctx.dataHome, ctx.meta.repository_root, probe.codexHome]) {
    if (p) protectedPaths.push(await canonicalizePath(p).catch(() => p));
  }
  // The probe result may be cached: re-establish, right before use, that the grant is still
  // an existing directory and a fixed point of the OS's canonical resolution (F1).
  await assertCanonicalGrant(probe.installDir);
  const exposed = grantExposes(probe.installDir, protectedPaths);
  if (exposed) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the Codex installation directory ${JSON.stringify(probe.installDir)} contains ${JSON.stringify(exposed)}; granting it under S1 would expose it, so S1 is refused`);
  const env = buildChildEnv({ source: ctx.sourceEnv ?? process.env, includeCodexAuth: true }).env;
  const selfTests = new Map<SandboxBackend, Awaited<ReturnType<typeof ensureSelfTest>>["record"] | null>();
  // P3.4C-4 (§1.1, D4-A): on a protected run the isolation basis is the custodian's — only a stored S1 self-test record
  // the operator confirmed (by its digest) counts, and no self-test runs here; acceptances of reduced isolation are the
  // custodian's records, never trust/isolation.json.
  const held = ctx.heldConfig ? await ctx.heldConfig() : null;
  if (held) {
    for (const b of backends) {
      const rec = await loadSelfTest(ctx.selftestDir, probe.version, { mode: "S1", backend: b, installDir: probe.installDir, webSearchDisabledValue: probe.compat.webSearchDisabledValue, acceptanceId: null });
      selfTests.set(b, rec && confirmedSelfTest(held.section, rec) ? rec : null);
    }
    const d = decideIsolation({ compat: probe.compat, codexVersion: probe.version, installDir: probe.installDir, backends, selfTests, acceptances: heldAcceptances(held.section), userHooksPresent: probe.userHooksPresent });
    if (!d.ok) throw isolationUnavailableError([...d.reasons, "on a protected run only an S1 self-test the operator confirmed with the custodian (code-parley config confirm-selftest) or a custodian-held acceptance (code-parley config accept-isolation) counts"]);
    return { isolation: d.isolation, argv: d.argv };
  }
  for (const b of backends) {
    const { record } = await ensureSelfTest({
      probe,
      backend: b,
      mode: "S1",
      dataHome: ctx.dataHome,
      selftestDir: ctx.selftestDir,
      env,
      signal,
      ...(ctx.testHooks?.selfTestDeps ? { deps: ctx.testHooks.selfTestDeps } : {}),
    });
    selfTests.set(b, record);
    if (record.s1_available) break;
  }
  const acceptances = await loadAcceptances(ctx.trustIsolationPath);
  const d = decideIsolation({
    compat: probe.compat,
    codexVersion: probe.version,
    installDir: probe.installDir,
    backends,
    selfTests,
    acceptances: acceptances.file.records,
    userHooksPresent: probe.userHooksPresent,
  });
  if (!d.ok) throw isolationUnavailableError(acceptances.problem ? [...d.reasons, acceptances.problem] : d.reasons);
  return { isolation: d.isolation, argv: d.argv };
}

/** The checks context a review derives (exported for the S-3 regression tests). */
export function checksContextOf(ctx: ReviewEngineContext): ChecksEngineContext {
  return {
    ...(ctx.heldConfig ? { heldConfig: ctx.heldConfig } : {}),
    ...(ctx.custodianSurface ? { custodianSurface: ctx.custodianSurface } : {}),
    dataHome: ctx.dataHome,
    trustProjectsPath: ctx.trustProjectsPath,
    runPaths: ctx.runPaths,
    meta: ctx.meta,
    gitExe: ctx.gitExe,
    rules: ctx.rules,
    owner: ctx.owner,
    budgets: { max_check_executions_per_run: ctx.budgets.max_check_executions_per_run },
    ...(ctx.sourceEnv ? { sourceEnv: ctx.sourceEnv } : {}),
    ...(ctx.lockDeps ? { lockDeps: ctx.lockDeps } : {}),
    ...(ctx.classify ? { classify: ctx.classify } : {}),
    // Phase 6 S-3: the derived context carries the engine's own presence query, so no production checks context lacks it
    // (the fallback in checks-operation.ts is for contexts tests build by hand).
    ...(ctx.custodian ? { custodian: ctx.custodian } : {}),
    ...(ctx.custodianPresence ? { custodianPresence: ctx.custodianPresence } : {}),
  };
}

interface EvidenceBundle {
  items: CheckEvidenceItem[];
  executionIds: string[];
  digest: string;
  /** What the checks found, without timing (Phase 2.2: the gate's "check evidence changed"). */
  resultsDigest: string;
  bundle: Parameters<typeof buildBundle>[0]["checks"];
}

/** Model-visible check evidence for `sourceId`: structured metadata only (rev 0.7). */
async function checkEvidence(checksCtx: ChecksEngineContext, sourceId: string, view?: (st: StateRecord) => Promise<StateRecord>): Promise<EvidenceBundle> {
  const raw = await readState(checksCtx.runPaths);
  const st = view ? await view(raw) : raw;
  return evidenceOf(await evaluateChecksStatus(checksCtx, sourceId, st), st);
}

/**
 * The model-visible check evidence of an evaluated checks status, and its digest. Shared with
 * reports (Phase 2.2): a report compares the digest for the current source with the one a review
 * saw (the "check evidence changed" basis of the new-information gate, P2.2-7).
 */
export function evidenceOf(status: Awaited<ReturnType<typeof evaluateChecksStatus>>, st: Pick<StateRecord, "check_executions">): EvidenceBundle {
  const byId = new Map(st.check_executions.map((e) => [e.execution_id, e]));
  const items: CheckEvidenceItem[] = status.checks.map((v) => {
    const e = v.execution_id ? byId.get(v.execution_id) : undefined;
    return {
      check: v.check,
      required: v.required,
      status: v.status,
      last_execution_status: v.last_status,
      exit_code: e?.exit_code ?? null,
      duration_ms: e?.duration_ms ?? null,
      timed_out: e?.timed_out ?? false,
      cancelled: e?.cancelled ?? false,
      freshness: v.freshness ? { fresh: v.freshness.fresh, source: v.freshness.source, spec: v.freshness.spec, environment: v.freshness.environment } : null,
    };
  });
  const executionIds = status.checks.map((v) => v.execution_id).filter((x): x is string => x !== null);
  const f = status.floor;
  return {
    items,
    executionIds,
    digest: sha256OfCanonicalJson({ schema: "arl.check-evidence.v1", items, floor: [f.configured, f.satisfied_for_current_source] }),
    resultsDigest: checkResultsDigest(items, f),
    bundle: {
      evidence: items,
      floor: { configured: f.configured, satisfied_for_reviewed_source: f.satisfied_for_current_source, missing: f.missing, stale: f.stale, failed: [...f.failed, ...f.timed_out], removed: f.removed, unapproved: f.unapproved },
      engine_conditions: status.conditions.map((c) => ({ kind: c.kind, check: c.check, detail: c.detail })),
    },
  };
}

/** Incident kinds that make a review's result unacceptable (its isolation is in doubt). */
const INVALIDATING_INCIDENTS: ReadonlySet<IsolationIncident["kind"]> = new Set([
  "termination_unconfirmed",
  "isolation_violation_file_change",
  "isolation_violation_mcp_tool_call",
  "isolation_violation_web_search",
  "export_modified_during_review",
  "cancellation_unconfirmed",
]);

/**
 * Finish a review whose Codex process has exited. Immutable artifacts are written first;
 * then ONE commit (F11) publishes the review result, the reviewer-item lifecycle changes,
 * the incidents, the operation outcome and the run-state transition together, so no crash
 * can leave a published result with a running operation or the reverse.
 *
 * Only an ACCEPTED review (F2) — completed with valid output, current at completion (source,
 * check evidence, stable capture, intact export), free of isolation-invalidating incidents,
 * and not cancelled by the time of the commit — adds reviewer items or changes the state of
 * prior ones. Any other review is kept for audit (its triaged items in an artifact) and
 * changes nothing; it never becomes the current review result. Returns the freshness at
 * completion (null if there was no valid output).
 */
async function finalizeReview(
  ctx: ReviewEngineContext,
  operationId: string,
  record: ReviewRecord,
  run: ReviewRunResult,
  capture: CaptureResult,
  exportDir: string,
  anchor: ExportAnchor,
  evidenceDigest: string,
  prior: ReturnType<typeof buildBundle>["prior"],
  notPresented: ReviewerItem[],
  discussion: ReturnType<typeof buildBundle>["discussion"],
  signal: AbortSignal,
  custodianOp: CustodianReview | null = null,
  finish: { promptDigest: string; presented: RunReviewPresented } | null = null,
): Promise<ReviewFreshness | null> {
  const reviewId = record.review_id;
  const manifest = capture.manifest!;
  const art = async (name: string, data: string | Buffer) => (await publishArtifact(ctx.runPaths.runDir, ctx.runPaths.opsDir, operationId, `review/${name}`, data)).ref;
  const artifacts: Record<string, string> = { ...record.artifacts };
  artifacts["events"] = await art("events.jsonl", run.eventsJsonl);
  artifacts["stderr"] = await art("stderr.log", run.stderr);

  const incidents: IsolationIncident[] = [];
  for (const v of run.audit.isolation_violations) {
    incidents.push(incident(reviewId, operationId, `isolation_violation_${v.kind}` as IsolationIncident["kind"], `Codex emitted a ${v.kind} item under ${record.effective_isolation.mode}: ${v.detail}`));
  }
  const counted = { file_change: run.audit.file_changes, mcp_tool_call: run.audit.mcp_tool_calls, web_search: run.audit.web_searches };
  for (const [kind, n] of Object.entries(counted)) {
    // Violations beyond the retained detail cap still produce an incident (F8).
    if (n > 0 && !incidents.some((i) => i.kind === `isolation_violation_${kind}`)) incidents.push(incident(reviewId, operationId, `isolation_violation_${kind}` as IsolationIncident["kind"], `Codex emitted ${n} ${kind} item(s) under ${record.effective_isolation.mode}`));
  }
  const v1 = await verifyReviewExport(exportDir, anchor);
  if (!v1.ok) incidents.push(incident(reviewId, operationId, "export_modified_during_review", `the export no longer matches what the engine published: ${v1.problems.slice(0, 5).join("; ")}`));
  if (run.cancellation && run.cancellation.outcome !== "terminated") incidents.push(unconfirmedCancellationIncident(reviewId, operationId, run.cancellation));
  // A tree killed for another reason (wall or idle timeout) is held to the same evidence.
  if (run.treeKill && !run.cancellation && run.termination?.established !== true) {
    const t = run.termination;
    const named = [...(t?.survivors ?? []).map((x) => `${x.name} (${x.pid})`), ...(t?.unattributable ?? []).map((x) => `${x.name} (${x.pid}, unattributable)`)];
    incidents.push(incident(reviewId, operationId, "termination_unconfirmed", `the Codex process tree was killed (${run.treeKill.reason}), but its termination was not established (${t?.reason ?? "no termination evidence is available"}); possible surviving processes: ${named.join(", ") || "unknown"}`));
  }

  const notes: string[] = [];
  if (run.descendants?.survivors.length && !run.cancellation) notes.push(`Codex left ${run.descendants.survivors.length} process(es) running after it exited; they were terminated${run.descendants.terminated === true ? "" : " (not confirmed)"}`);
  if (run.audit.events_malformed) notes.push(`${run.audit.events_malformed} malformed event line(s)`);
  if (run.audit.events_oversize) notes.push(`${run.audit.events_oversize} event line(s) over the line cap were dropped`);
  if (run.audit.stream_truncated) notes.push("the stored event stream was truncated at its cap");
  if (run.audit.audit_truncated) notes.push("an audit retention cap was reached; counts are kept, retained detail is partial");
  if (run.audit.events_unknown_type) notes.push(`${run.audit.events_unknown_type} event(s) or item(s) of unknown type`);

  // Status from the process outcome, then the output contract.
  let status: ReviewStatus;
  let failure: ReviewRecord["failure"] = null;
  let output: ReviewOutput | null = null;
  if (run.outcome.status === "completed" || run.outcome.status === "no_output") {
    if (run.lastMessageMismatch) {
      // C5: the -o file is not what Codex streamed (overwritten after it exited, or written without a final message).
      status = "invalid_output";
      failure = { class: "final_message_mismatch", detail: "the final-message file does not match the final message in Codex's event stream; the output is not trusted" };
    } else if (run.lastMessageTooLarge) {
      status = "invalid_output";
      failure = { class: "output_too_large", detail: `final message is ${run.lastMessageBytes} bytes (cap ${DEFAULT_RUN_LIMITS.maxLastMessageBytes})` };
    } else if (run.outcome.status === "no_output" || !run.lastMessage) {
      status = "invalid_output";
      failure = { class: "no_output", detail: run.outcome.detail };
    } else {
      const parsed = parseOutput(run.lastMessage);
      if (parsed.ok) {
        status = "completed";
        output = parsed.output;
      } else {
        status = "invalid_output";
        failure = { class: parsed.class, detail: parsed.detail };
      }
    }
    if (run.lastMessage !== null) artifacts["raw_output"] = await art("raw-output.json", run.lastMessage);
  } else if (run.outcome.status === "cancelled") {
    status = "cancelled";
    failure = { class: "cancelled", detail: run.outcome.detail };
  } else if (run.outcome.status === "timed_out") {
    status = "timed_out";
    failure = { class: run.outcome.failureClass ?? "timeout", detail: run.outcome.detail };
  } else {
    status = "failed";
    failure = { class: run.outcome.failureClass ?? "failed", detail: run.outcome.detail };
  }

  // Freshness at completion, triage and the PROPOSED carry-forward (applied only if accepted).
  let freshness: ReviewFreshness | null = null;
  const newItems: ReviewerItem[] = [];
  let carried: ReturnType<typeof carryForward> | null = null;
  let replies: { records: ReviewerReply[]; notes: string[]; missing: string[] } = { records: [], notes: [], missing: [] };
  const clampCount = { n: 0 };
  let normalized: Record<string, unknown> | null = null;
  if (output) {
    freshness = await freshnessNow(ctx, operationId, record, capture.record.stable, evidenceDigest, v1.ok, "completion", undefined, undefined, signal);
    const index = await exportIndex(exportDir, manifest, output, withheldPaths(capture.record.entries, capture.record.changes));
    const now = new Date().toISOString();
    const findingRefs: { index: number; id: string; triage: ReviewerItem["triage"] }[] = [];
    const aliasToId = new Map(prior.flatMap((p) => [[p.alias.toLowerCase(), p.item.id] as const, [p.item.id.toLowerCase(), p.item.id] as const]));
    // Phase 2.2: restatement links (P2.2-1, -3), to a presented prior or informational item.
    const restated = new Map<string, string[]>();
    output.findings.forEach((f, k) => {
      const t = triageFinding(f, index);
      const relatedRaw = f.related_prior_id?.trim().toLowerCase() ?? null;
      const related = relatedRaw ? (aliasToId.get(relatedRaw) ?? null) : null;
      const itemNotes = [...t.notes];
      if (relatedRaw && !related) itemNotes.push(`related_prior_id ${JSON.stringify(f.related_prior_id)} is not a listed prior item; ignored`);
      const restatesRaw = f.restates_prior_id?.trim().toLowerCase() ?? null;
      const restates = restatesRaw ? (discussion.presented.get(restatesRaw) ?? null) : null;
      if (restatesRaw && !restates) itemNotes.push(`restates_prior_id ${JSON.stringify(f.restates_prior_id)} is not a presented item; ignored`);
      const id = uuidv7();
      if (restates) restated.set(id, [restates]);
      findingRefs.push({ index: k, id, triage: t.triage });
      newItems.push({
        id,
        item_kind: "finding",
        review_id: reviewId,
        round: record.round,
        source_id: record.source_id,
        review_input_id: record.review_input_id,
        title: clamp(f.title, CLAMP.title, clampCount),
        claim_type: f.claim_type,
        severity: f.severity,
        category: f.category,
        impacts: [...new Set(f.impacts)],
        consequence: clamp(f.consequence, CLAMP.text, clampCount),
        confidence: f.confidence,
        evidence: t.evidence.map((e) => ({ ...e, detail: clamp(e.detail, CLAMP.evidenceDetail, clampCount) })),
        investigation: clamp(f.investigation, CLAMP.text, clampCount),
        recommended_change: clamp(f.recommended_change, CLAMP.text, clampCount),
        triage: t.triage,
        basis: "reviewer_evidence",
        policy_notes: itemNotes,
        status: OPEN_TRIAGE.has(t.triage) ? "open" : "informational",
        related_prior_id: related,
        supersedes: [],
        superseded_by: null,
        assessments: [],
        created_at: now,
      });
    });
    output.questions.forEach((q) => {
      const rel = q.related_finding_index !== null && Number.isInteger(q.related_finding_index) ? findingRefs.find((r) => r.index === q.related_finding_index)?.id ?? null : null;
      newItems.push({
        id: uuidv7(),
        item_kind: "question",
        review_id: reviewId,
        round: record.round,
        source_id: record.source_id,
        review_input_id: record.review_input_id,
        title: clamp(q.question, CLAMP.text, clampCount),
        claim_type: null,
        severity: null,
        category: null,
        impacts: [],
        consequence: "",
        confidence: null,
        evidence: [],
        investigation: "",
        recommended_change: "",
        triage: q.blocking ? "blocking_question" : "question",
        basis: "reviewer_evidence",
        policy_notes: [],
        status: q.blocking ? "open" : "informational",
        related_prior_id: null,
        related_finding_id: rel,
        supersedes: [],
        superseded_by: null,
        assessments: [],
        created_at: now,
      });
    });
    carried = carryForward({ reviewId, round: record.round, sourceId: record.source_id, prior, notPresented, assessments: output.prior_findings, newFindings: findingRefs });
    for (const [by, olds] of carried.supersedes) {
      const it = newItems.find((n) => n.id === by);
      if (it) it.supersedes.push(...olds);
    }
    for (const [by, olds] of carried.restates) restated.set(by, [...(restated.get(by) ?? []), ...olds]);
    for (const it of newItems) {
      const links = [...new Set(restated.get(it.id) ?? [])].filter((x) => !it.supersedes.includes(x));
      if (links.length) it.restates = links;
    }
    notes.push(...carried.notes);
    // Phase 2.2: the reviewer's structured replies (P2.2-3), recorded only if this review is accepted.
    const assessed = new Map<string, string>();
    for (const u of carried.updated) {
      const a = u.assessments.filter((x) => x.review_id === reviewId).at(-1);
      if (a) assessed.set(u.id, a.assessment);
    }
    replies = processReplies({
      replies: output.discussion_replies,
      awaiting: discussion.awaiting,
      presented: discussion.presented,
      assessments: assessed,
      reviewId,
      round: record.round,
      sourceId: record.source_id,
      recordedAt: now,
      newId: uuidv7,
      clampReply: (t) => clamp(t, CLAMP.text, clampCount),
    });
    notes.push(...replies.notes);
    const updatedById = new Map(carried.updated.map((u) => [u.id, u]));
    const priorStillOpen = [...prior.map((p) => p.item), ...notPresented].filter((it) => (updatedById.get(it.id) ?? it).status === "open").length;
    const openCount = newItems.filter((n) => n.status === "open").length + priorStillOpen;
    notes.push(...verdictConflicts(output, openCount, output.findings.length));
    if (clampCount.n) notes.push(`${clampCount.n} reviewer text field(s) clamped for display`);

    const files = new Set([...index.current.keys(), ...index.base.keys()]);
    const reviewed = output.coverage.files_reviewed.map(normalizeReportedPath);
    const knownReviewed = reviewed.filter((p) => files.has(caseKey(p)) || manifest.files.some((f) => caseKey(f.path) === caseKey(p)));
    if (knownReviewed.length < reviewed.length) notes.push(`${reviewed.length - knownReviewed.length} files_reviewed entr(y/ies) do not name exported files; ignored`);
    normalized = {
      verdict: output.verdict,
      summary: clamp(output.summary, CLAMP.summary, clampCount),
      assessment: clamp(output.assessment, CLAMP.assessment, clampCount),
      positive_observations: output.positive_observations.map((p) => ({ title: clamp(p.title, CLAMP.title, clampCount), detail: clamp(p.detail, CLAMP.text, clampCount) })),
      suggestions: output.suggestions.map((p) => ({ title: clamp(p.title, CLAMP.title, clampCount), detail: clamp(p.detail, CLAMP.text, clampCount) })),
      context_requests: output.context_requests.map((c) => ({ what: clamp(c.what, CLAMP.note, clampCount), why: clamp(c.why, CLAMP.note, clampCount) })),
      coverage: { files_reviewed: knownReviewed, files_not_reviewed: output.coverage.files_not_reviewed.map(normalizeReportedPath).slice(0, 2000), reviewer_limitations: clamp(output.coverage.limitations, CLAMP.text, clampCount) },
      prior_findings: output.prior_findings,
      discussion_replies: output.discussion_replies,
    };
    artifacts["output"] = await art("output.json", JSON.stringify(normalized, null, 2));
    // Triaged items, the proposed carry-forward and replies, kept for audit whatever the acceptance.
    artifacts["items"] = await art("items.json", JSON.stringify({ items: newItems, proposed_updates: carried.updated, proposed_replies: replies.records, replies_missing: replies.missing }, null, 2));
  }

  artifacts["result"] = await art(
    "result.json",
    JSON.stringify({ review_id: reviewId, status, failure, outcome: run.outcome, audit: run.audit, cancellation: run.cancellation, descendants: run.descendants, exit_status: run.exitStatus, stdio_held_after_exit: run.stdioHeldAfterExit }, null, 2),
  );

  await ctx.testHooks?.beforeCompletionCommit?.();
  // Acceptance is decided at the commit point: a cancellation that arrived at any time before it (even after Codex
  // finished) makes the result non-accepted. On a protected run that point is the custodian's op_finish, and its
  // answer is the acceptance (P3.4C-3).
  const decide = () => {
    let finalStatus = status;
    let finalFailure = failure;
    if (signal.aborted && finalStatus !== "cancelled") {
      finalStatus = "cancelled";
      finalFailure = { class: "cancelled", detail: "cancelled on request before the result was accepted" };
    }
    // A cancellation that arrived after Codex returned (late) is judged on the same
    // termination evidence as one during execution: no "late means terminated" shortcut.
    const finalCancellation = run.cancellation ?? (signal.aborted ? cancellationRecord(new Date().toISOString(), run.termination) : null);
    const allIncidents = [...incidents];
    if (finalCancellation && finalCancellation.outcome !== "terminated" && !allIncidents.some((i) => i.kind === "cancellation_unconfirmed")) {
      allIncidents.push(unconfirmedCancellationIncident(reviewId, operationId, finalCancellation));
    }
    const reasons: string[] = [];
    if (finalStatus !== "completed" || !output) reasons.push(finalStatus === "completed" ? "no_valid_output" : finalStatus);
    if (output && freshness && !freshness.current) reasons.push(...freshness.stale_reasons.map((x) => `stale:${x}`));
    for (const i of allIncidents) if (INVALIDATING_INCIDENTS.has(i.kind)) reasons.push(`incident:${i.kind}`);
    return { finalStatus, finalFailure, finalCancellation, allIncidents, reasons };
  };
  let custodianDecision: { accepted: boolean; reasons: string[]; statuses: Map<string, string> } | null = null;
  let decided: ReturnType<typeof decide> | null = null;
  if (custodianOp) {
    decided = decide();
    const outcome = await reviewOutcome(ctx, operationId, decided.finalStatus, output, freshness, normalized, artifacts, newItems, carried, replies.records, decided.allIncidents, reviewId);
    try {
      const fields = finish ? { operationId: custodianOp.operationId, outcome, promptDigest: finish.promptDigest, presented: finish.presented } : { operationId: custodianOp.operationId, outcome };
      const done = await custodianOp.evidence.transition("op_finish", fields, `${operationId}-finish`);
      const changed = Array.isArray(done["itemsChanged"]) ? (done["itemsChanged"] as { itemId: string; status: string }[]) : [];
      custodianDecision = {
        accepted: done["accepted"] === true,
        reasons: Array.isArray(done["notAcceptedReasons"]) ? (done["notAcceptedReasons"] as string[]).map((x) => `custodian:${x}`) : [],
        statuses: new Map(changed.map((c) => [c.itemId, c.status])),
      };
    } catch (e) {
      // Not recorded by the custodian: never accepted (fail closed). An unreachable custodian keeps its operation
      // running until its writer is gone and a later `recover`.
      custodianDecision = { accepted: false, reasons: [isDomainError(e) ? `custodian_refused:${e.code}` : "custodian_unreachable"], statuses: new Map() };
    }
  }
  await commitTerminal(ctx, operationId, (st) => {
    const r = st.reviews.find((x) => x.review_id === reviewId);
    if (!r) throw new DomainError("INTERNAL", `review ${reviewId} vanished from the run state`);
    const { finalStatus, finalFailure, finalCancellation, allIncidents, reasons: localReasons } = decided ?? decide();
    const reasons = custodianDecision ? (custodianDecision.accepted ? [] : [...localReasons, ...custodianDecision.reasons]) : localReasons;
    const accepted = custodianDecision ? custodianDecision.accepted : reasons.length === 0;

    r.status = finalStatus;
    r.failure = finalFailure;
    r.ended_at = new Date().toISOString();
    r.duration_ms = run.durationMs;
    r.audit = run.audit;
    r.cancellation = finalCancellation;
    r.termination =
      run.treeKill || finalCancellation
        ? {
            reason: run.treeKill?.reason ?? "cancelled_after_exit",
            established: run.termination?.established === true,
            survivors: run.termination?.survivors ?? [],
            unattributable: run.termination?.unattributable ?? [],
            detail: run.termination?.reason ?? "no termination evidence is available",
          }
        : null;
    r.freshness = freshness;
    r.artifacts = artifacts;
    r.policy_notes = accepted ? notes : [...notes, `not accepted (${[...new Set(reasons)].join(", ")}): reviewer items and prior-item assessments were kept for audit only and changed nothing`];
    r.accepted = accepted;
    r.not_accepted_reasons = [...new Set(reasons)];
    if (output) {
      r.verdict = output.verdict;
      r.summary = String(normalized?.["summary"] ?? "");
    }
    for (const inc of allIncidents) st.isolation_incidents.push(inc);
    r.incident_ids = [...r.incident_ids, ...allIncidents.map((i) => i.incident_id)];
    if (accepted && carried) {
      r.item_ids = newItems.map((n) => n.id);
      for (const u of carried.updated) {
        const k = st.findings.findIndex((f) => f.id === u.id);
        if (k >= 0) st.findings[k] = u;
      }
      st.findings.push(...newItems);
      // Same commit as the carry-forward (F11): replies never exist without their review's items.
      st.reviewer_replies.push(...replies.records);
      // The custodian's item statuses are authoritative; the local cache follows them.
      for (const [id, status] of custodianDecision?.statuses ?? []) {
        const f = st.findings.find((x) => x.id === id);
        if (f && f.status !== status) f.status = status as ReviewerItem["status"];
      }
    }
    pushEvent(st, "review.finished", `review ${reviewId.slice(0, 8)}: ${finalStatus}${accepted ? " (accepted)" : " (not accepted)"}${output ? ` (${output.verdict}, ${newItems.length} item(s)${replies.records.length ? `, ${replies.records.length} discussion repl${replies.records.length === 1 ? "y" : "ies"}` : ""})` : finalFailure ? `: ${finalFailure.class}` : ""}`, { operation_id: operationId, review_id: reviewId });
    completeOperation(st, operationId, finalStatus === "cancelled" ? "cancelled" : "completed", { review_id: reviewId, status: finalStatus, accepted });
    return st;
  });
  return freshness;
}

/** A finished review's outcome for the custodian (contract §3.2 op_finish): claims it validates; acceptance, the
 * items' statuses and the assessments' effects are its own. Artifacts are bound by the digest of what was written. */
async function reviewOutcome(
  ctx: ReviewEngineContext,
  operationId: string,
  status: ReviewStatus,
  output: ReviewOutput | null,
  freshness: ReviewFreshness | null,
  normalized: Record<string, unknown> | null,
  artifacts: Record<string, string>,
  newItems: readonly ReviewerItem[],
  carried: ReturnType<typeof carryForward> | null,
  replies: readonly ReviewerReply[],
  incidents: readonly IsolationIncident[],
  reviewId: string,
): Promise<RunReviewOutcome> {
  const dig = (k: string) => artifactDigest(ctx.runPaths.runDir, artifacts[k]);
  const lastMessage = await readFile(join(ctx.runPaths.opsDir, operationId, "review", "last-message.json")).catch(() => null);
  const supersededBy = new Map<string, string>();
  for (const [by, olds] of carried?.restates ?? []) for (const o of olds) supersededBy.set(o, by);
  return {
    status: status as RunReviewOutcome["status"],
    outputValid: output !== null,
    currentAtCompletion: freshness?.current === true,
    verdict: output?.verdict ?? null,
    summaryDigest: normalized ? sha256OfString(String(normalized["summary"] ?? "")) : null,
    artifacts: {
      rawOutput: await dig("raw_output"),
      output: await dig("output"),
      items: await dig("items"),
      result: await dig("result"),
      events: await dig("events"),
      stderr: await dig("stderr"),
      lastMessage: lastMessage ? sha256OfBytes(lastMessage) : null,
    },
    newItems: newItems.map((n) => ({
      itemId: n.id,
      itemKind: n.item_kind,
      triage: n.triage,
      severity: n.severity,
      claimType: n.claim_type,
      category: n.category,
      impacts: [...n.impacts],
      confidence: n.confidence,
      status: n.status as "open" | "informational",
      relatedPriorId: n.related_prior_id ?? null,
      relatedFindingId: typeof n.related_finding_id === "string" ? n.related_finding_id : null,
      restates: [...(n.restates ?? [])],
    })),
    assessments: (carried?.updated ?? []).flatMap((u) => {
      const a = u.assessments.filter((x) => x.review_id === reviewId).at(-1);
      if (!a) return [];
      const assessment = a.effect === "kept_open:not_presented" ? "not_presented" : a.assessment;
      const by = a.effect.startsWith("status:superseded_by:") ? a.effect.slice("status:superseded_by:".length) : a.assessment === "superseded" ? (supersededBy.get(u.id) ?? null) : null;
      return [{ itemId: u.id, assessment: assessment as RunReviewOutcome["assessments"][number]["assessment"], supersededByItemId: by }];
    }),
    replies: replies.map((r) => ({ replyId: r.reply_id, itemId: r.item_id, stance: r.stance, newInformation: r.new_information, answersResponseId: r.answers.response_id ?? null, assessment: r.assessment })),
    incidents: incidents.map((i) => ({ kind: i.kind, detail: bounded(i.detail) })),
  };
}

type ParseOutcome = { ok: true; output: ReviewOutput } | { ok: false; class: string; detail: string };

export function parseOutput(text: string): ParseOutcome {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (e) {
    return { ok: false, class: "invalid_json", detail: `final message is not JSON: ${String((e as Error).message).slice(0, 200)}` };
  }
  const p = ReviewOutputSchema.safeParse(json);
  if (!p.success) {
    return { ok: false, class: "schema_violation", detail: p.error.issues.slice(0, 10).map((i) => `${i.path.join(".") || "$"}: ${i.message}`).join("; ").slice(0, 2000) };
  }
  return { ok: true, output: p.data };
}

/**
 * Freshness of a review's inputs, checked NOW: the export still equals what the engine
 * published, the working tree's source identity is still the reviewed one, and the check
 * evidence for the reviewed source is unchanged. `when` only names the stale reasons:
 * "completion" (during the review) or "now" (since the review; F5).
 */
async function freshnessNow(
  ctx: ReviewEngineContext,
  operationId: string,
  record: ReviewRecord,
  captureStable: boolean,
  evidenceDigest: string,
  exportIntact: boolean,
  when: "completion" | "now" = "completion",
  known?: KnownSource,
  budgetMs?: number,
  signal?: AbortSignal,
): Promise<ReviewFreshness> {
  const span = when === "completion" ? "during_review" : "since_review";
  const reasons: string[] = [];
  if (!captureStable) reasons.push("source_changed_during_capture");
  if (!exportIntact) reasons.push(`export_changed_${span}`);
  let source: boolean | null = null;
  if (known === "unavailable") {
    // The report already tried to read the tree within its budget and could not: say so,
    // rather than reading it a second time (host per-call limits, M1.5-8).
    reasons.push("source_not_rechecked:not_recomputed_in_this_report");
  } else {
    try {
      // A full read of the working tree made moments ago by the same report (status) is the
      // same evidence as a new one: reuse it rather than reading the tree twice. A report-time
      // read is bounded; the completion check inside the operation is not. The completion check
      // is a step of the review operation: it waits for a bounded read holding the worktree lock
      // (reads stand aside for it) and cancellation ends the wait; a report-time read is an
      // observer that never waits (D-31).
      const readSignal = budgetMs !== undefined ? AbortSignal.timeout(budgetMs) : signal;
      const now = known ?? await computeSourceIdentity({
        repoRoot: ctx.meta.repository_root,
        gitExe: ctx.gitExe,
        rules: ctx.rules,
        lock: { dataHome: ctx.dataHome, owner: ctx.owner, ...(ctx.lockDeps ? { deps: ctx.lockDeps } : {}) },
        operationId,
        ...(when === "completion" ? { operationStep: true } : {}),
        ...(readSignal ? { signal: readSignal } : {}),
      });
      source = now.stable && now.source_id === record.source_id;
      if (!source) reasons.push(`source_changed_${span}`);
    } catch (e) {
      reasons.push(`source_not_rechecked:${isDomainError(e) ? e.code : "error"}`);
    }
  }
  let evidence: boolean | null = null;
  try {
    const ev = await checkEvidence(checksContextOf(ctx), record.source_id, ctx.evidenceView);
    evidence = ev.digest === evidenceDigest;
    if (!evidence) reasons.push(`check_evidence_changed_${span}`);
  } catch {
    reasons.push("check_evidence_not_rechecked");
  }
  return { source, check_evidence: evidence, current: reasons.length === 0 && source === true && evidence === true, stale_reasons: reasons, checked_at: new Date().toISOString() };
}

/** Time budget of a report-time source recomputation (status, history, results; M1.5-8). */
export const REPORT_SOURCE_BUDGET_MS = 20_000;

/**
 * What a report already knows about the current source: a full identity computed moments ago
 * in the same report, or "unavailable" when that report's bounded recomputation did not
 * succeed — then it is not read a second time (M1.5-8; M1.6 fix).
 */
export type KnownSource = { source_id: string; stable: boolean } | "unavailable";

/**
 * Recompute a stored review's freshness for reporting now (F5). With `known`, the report's own
 * source identity is reused (or, when "unavailable", the source is reported as not rechecked);
 * otherwise the source is read within `budgetMs`. The freshness rule is unchanged.
 */
export async function reviewFreshnessNow(ctx: ReviewEngineContext, review: ReviewRecord, known?: KnownSource, budgetMs = REPORT_SOURCE_BUDGET_MS): Promise<ReviewFreshness | null> {
  if (review.status !== "completed") return null;
  const exportDir = exportDirOf(ctx.runPaths.runDir, review.export_ref);
  const intact = review.export_digest ? (await verifyReviewExport(exportDir, { export_digest: review.export_digest, manifest_digest: review.manifest_digest }).catch(() => ({ ok: false }))).ok : false;
  return freshnessNow(ctx, `report-${review.review_id}`, review, review.capture_stable, review.check_evidence_digest, intact, "now", known, budgetMs);
}

/** Line counts for the export files a reviewer's evidence refers to (lazy; MR-K). */
async function exportIndex(exportDir: string, manifest: ReviewManifest, output: ReviewOutput, withheld: ReadonlySet<string>): Promise<ExportIndex> {
  // Keyed by the platform's name rules (Windows: lower case; Linux: exact).
  const wanted = new Set<string>();
  for (const f of output.findings) for (const e of f.evidence) if (e.path) wanted.add(caseKey(normalizeReportedPath(e.path)));
  for (const p of output.coverage.files_reviewed) wanted.add(caseKey(normalizeReportedPath(p)));
  const current = new Map<string, { path: string; lines: number }>();
  const base = new Map<string, { path: string; lines: number }>();
  for (const f of manifest.files) {
    const k = caseKey(f.path);
    if (!wanted.has(k)) continue;
    const bytes = await readFile(join(exportDir, f.area, ...f.path.split("/"))).catch(() => null);
    if (bytes) current.set(k, { path: f.path, lines: countLines(bytes) });
  }
  for (const f of manifest.review_files.base) {
    const k = caseKey(f.path);
    if (!wanted.has(k)) continue;
    const bytes = await readFile(join(exportDir, "review", "base", ...f.path.split("/"))).catch(() => null);
    if (bytes) base.set(k, { path: f.path, lines: countLines(bytes) });
  }
  return { current, base, withheld, key: caseKey };
}

async function instructionFiles(exportDir: string, manifest: ReviewManifest): Promise<{ path: string; text: string }[]> {
  const out: { path: string; text: string }[] = [];
  for (const name of ["AGENTS.md", "AGENTS.override.md"]) {
    const f = manifest.files.find((x) => x.area === "tree" && x.path === name);
    if (!f) continue;
    const t = await readFile(join(exportDir, "tree", name), "utf8").catch(() => null);
    if (t !== null) out.push({ path: name, text: t });
  }
  return out;
}

/** Digest of the model-facing manifest's content (everything except its capture id and own digest). */
export function manifestContentDigest(m: ReviewManifest): string {
  const { capture_id: _c, manifest_digest: _d, ...content } = m;
  return sha256OfCanonicalJson({ digest_schema: "arl.manifest-content.v1", content });
}

function targetOf(meta: RunMeta) {
  const p = ReviewTargetSchema.safeParse(meta.target ?? { kind: "uncommitted" });
  if (!p.success) throw new DomainError("CONFIG_INVALID", "run.json target is malformed");
  return p.data;
}

function envelopeOf(meta: RunMeta): TaskEnvelope | null {
  if (meta.envelope === undefined || meta.envelope === null) return null;
  const p = TaskEnvelopeSchema.safeParse(meta.envelope);
  if (!p.success || Buffer.byteLength(JSON.stringify(p.data), "utf8") > MAX_ENVELOPE_BYTES) throw new DomainError("CONFIG_INVALID", "run.json task envelope is malformed or too large");
  return p.data;
}

async function baselineFor(ctx: ReviewEngineContext): Promise<{ baseline?: Awaited<ReturnType<typeof loadBaseline>> }> {
  if (targetOf(ctx.meta).kind !== "since_baseline") return {};
  const st = await readState(ctx.runPaths);
  const prep = [...st.operations].reverse().find((o) => o.kind === "prepare" && o.status === "completed");
  if (!prep) throw new DomainError("BASE_UNAVAILABLE", "target since_baseline needs the run's baseline capture");
  return { baseline: await loadBaseline(join(ctx.runPaths.baselineDir, prep.operation_id)) };
}

/** The operation-completion part of a commit: operation outcome and run-state transition. */
function completeOperation(st: StateRecord, operationId: string, status: "completed" | "failed" | "cancelled", outcome: Record<string, unknown>): void {
  const op = st.operations.find((o) => o.operation_id === operationId);
  if (op) {
    op.status = status;
    op.ended_at = new Date().toISOString();
    delete op["child"];
    op.outcome = outcome;
  }
  if (st.state === "REVIEWING") st.state = "IDLE";
  pushEvent(st, "review.operation_finished", `review operation ${status}`, { operation_id: operationId });
}

async function finishOperation(ctx: ReviewEngineContext, operationId: string, status: "completed" | "failed" | "cancelled", outcome: Record<string, unknown>): Promise<void> {
  await commitTerminal(ctx, operationId, (st) => {
    completeOperation(st, operationId, status, outcome);
    return st;
  });
}

/** How long a failed terminal commit is retried before the failure is reported. */
const TERMINAL_COMMIT_RETRY_MS = 30_000;

/**
 * An operation's terminal commit (PR #2 review). Were it lost, the record would keep the
 * operation running under this live server while the server has forgotten it, and the run
 * would stay busy until the server exits. Retryable failures (a lock, an antivirus-held file)
 * are retried with backoff; past the retry window the failure is reported to the caller and
 * the same commit keeps being retried in the background while the server runs (every 15 s, at
 * most an hour; not for a purged run). The mutation applies only while the operation is still
 * running, so no retry can record a second outcome.
 */
async function commitTerminal(ctx: ReviewEngineContext, operationId: string, mutate: (st: StateRecord) => StateRecord): Promise<StateRecord> {
  const hook = ctx.testHooks?.terminalCommit;
  const once = (): Promise<StateRecord> => {
    if (hook && hook.failures > 0) {
      hook.failures--;
      return Promise.reject(new DomainError("STORE_LOCKED", "run state is locked by another writer (injected)", { retryable: true }));
    }
    return commitState(ctx.runPaths, ctx.owner, (st) => {
      const op = st.operations.find((o) => o.operation_id === operationId);
      return op && op.status !== "running" ? st : mutate(st);
    });
  };
  const retryable = (e: unknown): boolean => (isDomainError(e) ? e.retryable === true : true);
  const deadline = Date.now() + (hook?.retryMs ?? TERMINAL_COMMIT_RETRY_MS);
  for (let delay = 250; ; delay = Math.min(delay * 2, 4000)) {
    try {
      return await once();
    } catch (e) {
      if (!retryable(e)) throw e;
      if (Date.now() + delay > deadline) {
        let tries = 0;
        const timer = setInterval(() => {
          if (++tries > 240) return clearInterval(timer);
          once().then(
            () => clearInterval(timer),
            (err: unknown) => {
              if (!retryable(err)) clearInterval(timer);
            },
          );
        }, hook?.backgroundMs ?? 15_000);
        timer.unref();
        throw e;
      }
      await new Promise((r) => setTimeout(r, delay));
    }
  }
}

/** The incident every unconfirmed cancellation records, whichever path reported it. */
function unconfirmedCancellationIncident(reviewId: string | null, operationId: string, c: CancellationRecord): IsolationIncident {
  const named = [...c.survivors.map((x) => `${x.name} (${x.pid})`), ...c.unattributable.map((x) => `${x.name} (${x.pid}, unattributable)`)];
  return incident(reviewId, operationId, "cancellation_unconfirmed", `cancellation requested, but termination was not established (${c.detail}); possible surviving processes: ${named.join(", ") || "unknown"}`);
}

/** Termination evidence for what this operation started outside the adapter (null table: no evidence). */
async function operationTermination(ctx: ReviewEngineContext, opStartMs: number): Promise<TerminationCheck | null> {
  if (ctx.testHooks?.sweep === null) return null;
  const snapshot = ctx.testHooks?.sweep?.snapshot ?? snapshotProcessTable;
  return checkOperationTermination(process.pid, opStartMs, await snapshot().catch(() => null));
}

function incident(reviewId: string | null, operationId: string, kind: IsolationIncident["kind"], detail: string): IsolationIncident {
  return { incident_id: uuidv7(), review_id: reviewId, operation_id: operationId, kind, detail: detail.slice(0, 2000), at: new Date().toISOString(), source: "engine" };
}

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor: type.startsWith("review.codex") ? "codex" : "engine", summary: summary.slice(0, 500), refs });
}

/** A review's export directory: inside the run (an attended capture's relative ref) or, for a protected review, the
 * export the custodian published (an absolute path, P3.4C-5). */
function exportDirOf(runDir: string, exportRef: string): string {
  return isAbsolute(exportRef) ? exportRef : join(runDir, ...exportRef.split("/"));
}

function relRef(runDir: string, abs: string): string {
  const base = runDir.replace(/\\$/, "");
  return (abs.startsWith(base) ? abs.slice(base.length) : abs).replace(/^[\\/]/, "").replace(/\\/g, "/");
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/**
 * A reviewer item as a review result shows it. With `d` (items tracked in the run state), the
 * discussion fields are added: its response token, thread, discussion state and latest
 * implementer response. Items of a review that was not accepted are tracked nowhere and get none.
 */
export function findingView(it: ReviewerItem, d?: ReportDiscussion): FindingView {
  return {
    ...findingFields(it),
    ...(d ? itemDiscussion(it, d.view, d.currentSourceId) : {}),
  };
}

function findingFields(it: ReviewerItem): FindingView {
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
    impacts: it.impacts,
    consequence: it.consequence,
    confidence: it.confidence,
    evidence: it.evidence,
    investigation: it.investigation,
    recommended_change: it.recommended_change,
    policy_notes: it.policy_notes,
    related_prior_id: it.related_prior_id,
    supersedes: it.supersedes,
    superseded_by: it.superseded_by,
  };
}

/** Engine-owned conditions derived NOW from engine records (MR-D): checks for `sourceId`, coverage of the review's capture. */
export async function engineConditions(ctx: ReviewEngineContext, sourceId: string | null, review: ReviewRecord | null, state?: StateRecord): Promise<EngineConditionView[]> {
  const out: EngineConditionView[] = [];
  // P3.4C-3 (§5.4): the check conditions of the state the report derives from — on a protected run hydrated from the
  // custodian's record (`state`, or this context's evidence view) — never the raw cache alone.
  const st = state ?? (ctx.evidenceView ? await ctx.evidenceView(await readState(ctx.runPaths)) : undefined);
  const status = await evaluateChecksStatus(checksContextOf(ctx), sourceId, st);
  for (const c of status.conditions) out.push({ kind: c.kind, check: c.check, detail: c.detail, source: "engine" });
  if (review) {
    const raw = await readTextIfExists(join(exportDirOf(ctx.runPaths.runDir, review.export_ref), "review", "manifest.json"));
    if (raw) {
      // P3.4C-3 C6: coverage conditions only from a manifest whose digest is the one the review recorded (on a
      // protected run, the custodian's), and removed tests only from a capture record with the custodian's digest. A
      // mismatch fails closed: one condition says the coverage cannot be established (the review is not current
      // either: its export no longer verifies).
      const m = verifiedManifest(raw, review.manifest_digest);
      const removed = m ? await testsRemovedFor(ctx, review) : null;
      if (!m || removed === UNVERIFIED) out.push({ kind: "coverage", code: "coverage_unverifiable", detail: `the review's ${m ? "capture record" : "export manifest"} no longer has the digest recorded for it, so its coverage cannot be established`, source: "engine" });
      else for (const c of coverageConditions(m, removed)) out.push({ kind: "coverage", code: c.code, detail: c.detail, source: "engine" });
    }
  }
  return out;
}

/** A capture record that does not have the digest the custodian holds for it. */
const UNVERIFIED = Symbol("unverified");

/** The manifest, when its canonical digest (its own `manifest_digest` rule) equals `expected`; else null. */
function verifiedManifest(raw: string, expected: string): ReviewManifest | null {
  try {
    const m = JSON.parse(raw) as ReviewManifest & Record<string, unknown>;
    const { manifest_digest, ...rest } = m;
    return manifest_digest === expected && sha256OfCanonicalJson(rest) === expected ? m : null;
  } catch {
    return null;
  }
}

/**
 * Removed tests of a review's capture, recomputed from the engine's own capture record and
 * the trusted test globs now (F12): never from reviewer output. Confidential paths are
 * counted, not named (MR-F).
 */
async function testsRemovedFor(ctx: ReviewEngineContext, review: ReviewRecord): Promise<{ paths: string[]; confidential_count: number } | null | typeof UNVERIFIED> {
  const ref = review.artifacts["capture"];
  if (!ref) return null;
  const bound = (review as { capture_digest?: unknown }).capture_digest;
  if (typeof bound === "string" && (await artifactDigest(ctx.runPaths.runDir, ref)) !== bound) return UNVERIFIED;
  const trusted = await loadTrustedState(checksContextOf(ctx));
  const globs = trusted.evaluation.testGlobs ?? [];
  if (globs.length === 0) return null;
  const changes = await captureChangesOf(resolveArtifact(ctx.runPaths.runDir, ref));
  if (!changes) return null;
  const compiled = compileGlobs(globs);
  return testsRemoved(changes, (p) => matchesAny(compiled, p));
}

/**
 * Capture records are immutable artifacts: keep, by absolute path, the change rows
 * `testsRemoved` can use — deletions and renames, nothing else — so that reporting conditions
 * (every status call) does not re-read and re-validate a possibly large record each time. The
 * trusted test globs are still read every time, and nothing is loaded when none apply. Only a
 * successfully parsed record is cached; the cache keeps the most recent records, at most
 * `CAPTURE_CHANGE_CACHE_ROWS` rows in all.
 */
const captureChangeCache = new Map<string, ChangeLike[]>();
const CAPTURE_CHANGE_CACHE_ROWS = 100_000;
let captureChangeCacheRows = 0;

/** The deleted and renamed change rows of the capture record at `path` (null when it is missing or empty). */
export async function captureChangesOf(path: string): Promise<ChangeLike[] | null> {
  const hit = captureChangeCache.get(path);
  if (hit) return hit;
  const raw = await readTextIfExists(path);
  if (!raw) return null;
  const rec = CaptureRecordSchema.parse(JSON.parse(raw));
  const rows: ChangeLike[] = rec.changes
    .filter((c) => c.status === "deleted" || c.status === "renamed")
    .map((c) => ({ path: c.path, status: c.status, ...(c.old_path !== undefined ? { old_path: c.old_path } : {}), confidential: c.confidential }));
  if (rows.length > CAPTURE_CHANGE_CACHE_ROWS) return rows; // too large to keep
  while (captureChangeCache.size > 0 && captureChangeCacheRows + rows.length > CAPTURE_CHANGE_CACHE_ROWS) {
    const oldest = captureChangeCache.keys().next().value!;
    captureChangeCacheRows -= captureChangeCache.get(oldest)!.length;
    captureChangeCache.delete(oldest);
  }
  captureChangeCache.set(path, rows);
  captureChangeCacheRows += rows.length;
  return rows;
}

export async function buildReviewResult(ctx: ReviewEngineContext, operationId: string, justComputedFreshness?: ReviewFreshness | null, known?: KnownSource): Promise<ReviewOperationResult> {
  const st = await readState(ctx.runPaths);
  const op = st.operations.find((o) => o.operation_id === operationId);
  if (!op) throw new DomainError("RUN_NOT_FOUND", `operation ${operationId} not found`);
  const oc = (op.outcome ?? {}) as { review_id?: string; deduplicated_of?: string; failure?: { class: string; detail: string; code?: string }; cancellation?: CancellationRecord };
  const reviewId = oc.deduplicated_of ?? oc.review_id ?? (op["review_id"] as string | undefined) ?? null;
  const review = reviewId ? (st.reviews.find((r) => r.review_id === reviewId) ?? null) : null;
  const limit = reviewLimit(ctx);
  const budgets = [{ name: "reviews", used: st.counters["reviews"] ?? 0, limit }];
  const incidents = st.isolation_incidents;
  const accepted = review?.accepted === true;
  const currentReview = [...st.reviews].reverse().find((r) => r.accepted === true) ?? null;

  // F5: never report freshness at completion as if it described the present. A result
  // returned straight after its own completion uses the freshness computed moments ago.
  const freshness = review
    ? justComputedFreshness !== undefined && review.status === "completed" && !oc.deduplicated_of
      ? justComputedFreshness
      : await reviewFreshnessNow(ctx, review, known).catch(() => null)
    : null;
  // The working tree's source now, as far as this report knows it fresh: the caller's own read,
  // or the review's source when its freshness check just found the tree unchanged.
  const currentSourceId = known !== undefined ? (known !== "unavailable" && known.stable ? known.source_id : null) : review && freshness?.source === true ? review.source_id : null;
  // The preview judges the next review against the source known now and compares its check
  // results, as status does; with the source unknown, each turn is judged by its own recorded
  // source, as status does too, never by the reviewed one, which can be older (PR #11 review).
  const resultsNow = currentSourceId !== null ? await evaluateChecksStatus(checksContextOf(ctx), currentSourceId, st).then((s) => evidenceOf(s, st).resultsDigest).catch(() => null) : null;
  const discussion = reportDiscussion(st, currentSourceId, resultsNow, caseKey);
  const dix = discussion.view.ix;
  const open = st.findings.filter((f) => f.status === "open").map((f) => findingView(f, discussion));

  let normalized: Record<string, unknown> | null = null;
  if (review?.artifacts["output"]) {
    const raw = await readTextIfExists(resolveArtifact(ctx.runPaths.runDir, review.artifacts["output"]));
    if (raw) normalized = JSON.parse(raw) as Record<string, unknown>;
  }
  const conditions = await engineConditions(ctx, review?.source_id ?? null, review).catch(() => []);
  // An accepted review's items live in the run state; a non-accepted review's triaged items
  // are shown from its audit artifact, marked not_accepted, and tracked nowhere (F2).
  let mine: ReviewerItem[] = review ? st.findings.filter((f) => f.review_id === review.review_id) : [];
  if (review && !accepted && review.artifacts["items"]) {
    const raw = await readTextIfExists(resolveArtifact(ctx.runPaths.runDir, review.artifacts["items"]));
    if (raw) mine = (JSON.parse(raw) as { items: ReviewerItem[] }).items.map((i) => ({ ...i, status: "not_accepted" as const }));
  }
  // Only items tracked in the run state (an accepted review's) carry discussion fields.
  const tracked = accepted ? discussion : undefined;
  const findings = mine.filter((f) => f.item_kind === "finding").map((f) => findingView(f, tracked));
  const questions = mine
    .filter((f) => f.item_kind === "question")
    .map((q) => ({
      id: q.id,
      question: q.title,
      finding_id: typeof q["related_finding_id"] === "string" ? (q["related_finding_id"] as string) : null,
      blocking: q.triage === "blocking_question",
      ...(tracked ? itemDiscussion(q, tracked.view, tracked.currentSourceId) : {}),
    }));
  // Carry-forward made visible (M1.6): the earlier rounds' items this (accepted) review
  // assessed, with its assessment and their status afterwards. A review that was not accepted
  // changed no item (F2), so it lists none. Phase 2.1: the implementer's latest response
  // recorded before this review assessed the item stays visible next to the reviewer's view.
  const latestNow = latestResponses(st.implementer_responses);
  // Phase 2.2: what this review presented and what the reviewer replied (P2.2-6, -10).
  const reviewIdx = review ? (dix.reviewIdx.get(review.review_id) ?? -1) : -1;
  const presentedHere = new Set((review?.discussion?.delivered ?? []).map((d) => d.response_id));
  const repliesHere = review && accepted ? st.reviewer_replies.filter((r) => r.review_id === review.review_id) : [];
  const priorItems =
    review && accepted
      ? st.findings
          .filter((f) => f.review_id !== review.review_id && f.assessments.some((a) => a.review_id === review.review_id))
          .map((f) => {
            const before = responseBeforeReview(f, review.review_id, st.implementer_responses);
            const reply = repliesHere.find((r) => r.item_id === f.id) ?? null;
            return {
              id: f.id,
              round: f.round,
              title: f.title,
              triage: f.triage,
              status: f.status,
              assessment: f.assessments.filter((a) => a.review_id === review.review_id).at(-1)!.assessment,
              response_before_review: before,
              /** The reviewer had seen that response by this review (this review or an earlier one presented it). */
              response_seen_by_reviewer: before !== null && (dix.seen.get(before.response_id) ?? []).some((x) => x.reviewIdx <= reviewIdx),
              presented_in_this_review: before !== null && presentedHere.has(before.response_id),
              reviewer_reply: reply ? { stance: reply.stance, new_information: reply.new_information, reply_excerpt: reply.reply } : null,
              discussion_state: discussionState(f, latestNow.get(f.id)),
            };
          })
      : [];
  const priorResolved = priorItems.filter((p) => p.status === "reported_resolved").length;
  const priorText = priorItems.length ? `; ${priorItems.length} earlier item(s) assessed: ${priorResolved} reported resolved, ${priorItems.filter((p) => p.status === "open").length} still open, ${priorItems.filter((p) => p.status === "superseded").length} superseded` : "";

  let manifest: ReviewManifest | null = null;
  if (review) {
    const raw = await readTextIfExists(join(exportDirOf(ctx.runPaths.runDir, review.export_ref), "review", "manifest.json"));
    if (raw) manifest = JSON.parse(raw) as ReviewManifest;
  }
  const limitations: Limitation[] = [...(manifest?.limitations ?? [])];
  for (const l of ((review as { bundle_limitations?: Limitation[] } | null)?.bundle_limitations ?? [])) limitations.push(l);
  if (review) {
    const iso = review.effective_isolation;
    if (iso.mode !== "S1") limitations.push({ code: "isolation_reduced", detail: `reduced isolation ${iso.mode}: reads ${iso.reads}, network ${iso.network} (acceptance ${iso.acceptance_id})` });
    if (iso.user_hooks_present) limitations.push({ code: "user_hooks_present", detail: "user-level Codex hooks exist; trusted hooks run outside the sandbox (reported, not prevented)" });
    if (accepted) {
      const notAssessed = st.findings.filter((f) => f.assessments.some((a) => a.review_id === review.review_id && a.assessment === "not_assessed")).length;
      if (notAssessed) limitations.push({ code: "prior_item_not_assessed", detail: `${notAssessed} open reviewer item(s) were not assessed by this review; they stay open`, count: notAssessed });
      const notAssessable = st.findings.filter((f) => f.assessments.some((a) => a.review_id === review.review_id && a.assessment === "no_longer_assessable")).length;
      if (notAssessable) limitations.push({ code: "prior_item_not_assessable", detail: `${notAssessable} open reviewer item(s) were reported no longer assessable; they stay open`, count: notAssessable });
    } else if (review.status !== "running") {
      limitations.push({ code: "review_not_accepted", detail: `this review was not accepted (${review.not_accepted_reasons.join(", ") || review.status}); it is kept for audit, changed no reviewer item and is not the current review` });
    }
    if (freshness && !freshness.current) limitations.push({ code: "stale_evidence", detail: `this review is not current now: ${freshness.stale_reasons.join(", ")}` });
  }
  limitations.push({ code: "triage_per_reviewer_evidence", detail: "triage is per the reviewer's supplied evidence (validated where practical), not engine-verified; the verdict is advisory and there is no task-level PASS" });
  const unseen = priorItems.filter((p) => p.response_before_review !== null && !p.response_seen_by_reviewer).length;
  if (unseen > 0) {
    limitations.push({
      code: "responses_not_delivered",
      detail: `${unseen} assessed item(s) had an implementer response the reviewer had not seen by this review (not presented: a repetition without new information, an exhausted exchange budget, withheld text, or a review by an earlier version); its assessment did not consider them — see discussion.not_delivered`,
      count: unseen,
    });
  }
  const awaitingHere = (review?.discussion?.delivered ?? []).filter((d) => d.reply_sought);
  const missing = accepted ? awaitingHere.filter((d) => !repliesHere.some((r) => r.answers.response_id === d.response_id)) : [];
  if (missing.length) limitations.push({ code: "discussion_reply_missing", detail: `${missing.length} item(s) awaited a discussion reply and got none; their turns stay awaiting a reply in the next review (within the exchange budget)`, count: missing.length });

  const failure = review?.failure ?? oc.failure ?? null;
  const status: ReviewOperationResult["status"] = review ? review.status : op.status === "cancelled" ? "cancelled" : op.status === "running" ? "running" : op.status === "interrupted" ? "interrupted" : "not_started";
  const deduplicated = oc.deduplicated_of !== undefined;
  const coverage = normalized
    ? {
        ...(normalized["coverage"] as { files_reviewed: string[]; files_not_reviewed: string[]; reviewer_limitations: string }),
        excluded_changed: { confidential_count: manifest?.exclusions.confidential.changed_count ?? 0, named: [] },
      }
    : null;
  const summary = review
    ? `review round ${review.round} ${review.status}${deduplicated ? " (identical input: earlier result returned)" : ""}` +
      (accepted ? "; accepted" : review.status === "running" ? "" : `; NOT ACCEPTED (${review.not_accepted_reasons.join(", ") || review.status}), kept for audit only`) +
      (review.verdict ? `; advisory verdict ${review.verdict}` : "") +
      (failure ? `; ${failure.class}: ${failure.detail.slice(0, 200)}` : "") +
      `; ${findings.length} finding(s) this round${priorText}, ${open.length} open reviewer item(s) overall; ${conditions.length} engine condition(s); ${incidents.length} isolation incident(s)` +
      (freshness ? (freshness.current ? "; current now for the source and check evidence" : `; NOT current now (${freshness.stale_reasons.join(", ")})`) : "") +
      (accepted && open.length ? ". Record your response to each finding with respond_to_review (response_token per item)" : "") +
      ". Triage is per reviewer evidence; no task-level PASS."
    : `review operation ${op.status}${failure ? `: ${failure.class}: ${failure.detail.slice(0, 300)}` : ""}`;

  return {
    summary,
    operation_id: operationId,
    operation_status: op.status,
    review_id: review?.review_id ?? null,
    round: review?.round ?? null,
    status,
    failure,
    deduplicated,
    source_id: review?.source_id ?? null,
    review_input_id: review?.review_input_id ?? null,
    freshness,
    freshness_at_completion: review?.freshness ?? null,
    accepted,
    not_accepted_reasons: review?.not_accepted_reasons ?? [],
    current_review_id: currentReview?.review_id ?? null,
    effective_isolation: review?.effective_isolation ?? null,
    verdict: review?.verdict ?? null,
    assessment: normalized ? String(normalized["assessment"] ?? "") : null,
    findings,
    prior_items: priorItems,
    open_findings: open,
    conditions,
    incidents,
    questions,
    positive_observations: (normalized?.["positive_observations"] as { title: string; detail: string }[] | undefined) ?? [],
    suggestions: (normalized?.["suggestions"] as { title: string; detail: string }[] | undefined) ?? [],
    context_requests: (normalized?.["context_requests"] as { what: string; why: string }[] | undefined) ?? [],
    coverage,
    limitations,
    policy_notes: review?.policy_notes ?? [],
    reviewer: review
      ? {
          cli_version: review.codex.version,
          model: review.codex.model,
          duration_ms: review.duration_ms,
          usage: review.audit?.usage ?? null,
          commands_run: review.audit?.commands_run ?? 0,
          isolation_violations: (review.audit?.isolation_violations ?? []).map((v) => v.kind),
        }
      : null,
    cancellation: review?.cancellation ?? oc.cancellation ?? null,
    budgets,
    discussion: review ? await reviewDiscussionView(ctx, review, accepted, repliesHere, missing.map((d) => d.item_id)) : null,
    amendments: review ? reviewAmendmentsView(review, dix, limitations) : null,
  };
}

/** A review's amendments as its result shows them (P2.3-12); adds the limitation when the user's current amendments differ. */
function reviewAmendmentsView(review: ReviewRecord, ix: ReturnType<typeof discussionIndexOf>, limitations: Limitation[]): ReviewAmendmentsView {
  const a = ix.amendments;
  const label = (id: string) => `A-${a.byId.get(id)?.seq ?? "?"}`;
  const presented = (review.amendments?.presented ?? []).map((p) => ({ id: `A-${p.seq}`, amendment_id: p.amendment_id }));
  const delta = amendmentDelta(a, presented.map((p) => p.amendment_id));
  const withheld = new Set((review.amendments?.withheld ?? []).map((w) => w.amendment_id));
  const pending = delta.not_presented.filter((id) => !withheld.has(id));
  const replace = delta.not_presented.filter((id) => withheld.has(id));
  if (pending.length) limitations.push({ code: "amendment_not_presented", detail: `the user's amendment(s) ${pending.map(label).join(", ")} were not presented to this review (recorded since); the next review you request presents them`, count: pending.length });
  if (replace.length) limitations.push({ code: "amendment_withheld", detail: amendmentWithheldDetail(replace.map(label), "this review"), count: replace.length });
  return {
    presented,
    withheld: (review.amendments?.withheld ?? []).map((w) => ({ id: label(w.amendment_id), amendment_id: w.amendment_id, reason: w.reason })),
    not_presented_now: delta.not_presented.map(label),
    no_longer_effective: delta.no_longer_effective.map(label),
    note: "Task amendments are recorded only through CodeParley's local operator interface (code-parley amend). A review presents the effective ones as the user's task context; they count as seen by the reviewer only through an accepted review.",
  };
}

/** A review's discussion as its result shows it (accepted: recorded replies; otherwise the proposed ones, recorded nowhere). */
async function reviewDiscussionView(ctx: ReviewEngineContext, review: ReviewRecord, accepted: boolean, recorded: readonly ReviewerReply[], missing: string[]): Promise<ReviewDiscussionView> {
  const d = review.discussion;
  let replies: readonly ReviewerReply[] = recorded;
  if (!accepted && review.artifacts["items"]) {
    const raw = await readTextIfExists(resolveArtifact(ctx.runPaths.runDir, review.artifacts["items"]));
    replies = raw ? ((JSON.parse(raw) as { proposed_replies?: ReviewerReply[] }).proposed_replies ?? []) : [];
  }
  const delivered = d?.delivered ?? [];
  const notDelivered = d?.not_delivered ?? [];
  return {
    presented: delivered.length,
    reply_sought: delivered.filter((x) => x.reply_sought).length,
    context: delivered.filter((x) => !x.reply_sought).length,
    replies: replies.map((r) => ({ item_id: r.item_id, stance: r.stance, new_information: r.new_information, reply_excerpt: r.reply })),
    replies_recorded: accepted,
    awaiting_without_reply: missing,
    not_delivered: notDelivered.slice(0, 50).map((x) => ({ response_id: x.response_id, item_id: x.item_id, reason: x.reason })),
    not_delivered_total: typeof d?.["not_delivered_total"] === "number" ? d["not_delivered_total"] : notDelivered.length,
    note: d
      ? accepted
        ? "Implementer turns are claims and arguments; the reviewer's replies are its stance, which changes no item's lifecycle (only its assessments do, under the carry-forward rules)."
        : "This review was not accepted: what it presented does not count as seen by the reviewer, and its replies were recorded nowhere."
      : "This review was made by a version before Phase 2.2: it presented no implementer response.",
  };
}

