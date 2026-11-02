// The M1 MCP tool surface (plan §11; M1.5). Each handler adapts one protocol request to
// engine calls and nothing more: argument validation (strict zod), the bounded wait, and
// the host view of the engine's result. Security, capture, checks, review, confidentiality,
// cancellation and persistence policy all live in the engine.

import type { z } from "zod";
import { DomainError } from "../common/errors.js";
import { shortHash } from "../common/hash.js";
import { shortId } from "../common/ids.js";
import { TOOL_VERSION } from "../common/version.js";
import { evidenceSelection, findRun, listRuns, loadEngine, waitMsFor, type EngineEnv, type Loaded, type RunHandle } from "../engine/engine-env.js";
import { disclosureFor, toHost, withheldOfEntries } from "../engine/host-view.js";
import { artifactDocument, eventsPage, pageText, responsesDocument } from "../engine/history.js";
import { prepareStarted, resultOf, startChecksOperation, startReviewOperation, stopRun, waitBounded, waitForCompletion, type OperationResult, type Started, type WaitOutcome } from "../engine/operations.js";
import { respondToReview, type SourceForResponse } from "../engine/respond.js";
import { assertRunInScope, createReviewRun, runCreatedView } from "../engine/runs.js";
import { currentSource, knownSourceOf, observedState, operationHandle, runReport, sourceBudgetFor, type SourceNow } from "../engine/status.js";
import { checksResultView, prepareResultView, reviewResultView } from "../engine/views.js";
import { loopViewOf, loopView, recordCallInterrupt, routeRun, startLoop } from "../engine/continuation.js";
import { locallyProtected, withAuthoritativeUserRecords } from "../engine/protected-user-records.js";
import { derivationForDisplay, routeOfDerivation } from "../engine/custodian-loop.js";
import { instructionFor, isEnded } from "../policy/continuation.js";
import { doctor } from "../engine/doctor.js";
import { delegateFix, type DelegateFixResult } from "../engine/fix-operation.js";
import { endEstablished } from "../engine/custodian-evidence.js";
import { applyFix } from "../engine/fix-apply.js";
import { fixesOf } from "../engine/fix-view.js";
import { readState } from "../store/state-store.js";
import type { Operation, StateRecord } from "../schemas/run-state.js";
import type { SourceEntry } from "../schemas/capture.js";
import { NO_DISCLOSURE_LIMITS } from "../policy/host-disclosure.js";
import { discussionText } from "../policy/responses.js";
import type { CallContext, ToolDefinition, ToolOutcome } from "./sdk.js";
import { fail, invalidArgument, ok, toToolError } from "./result.js";
import {
  ApplyFixToolInput,
  CreateReviewRunInput,
  DelegateFixToolInput,
  DiagEchoInput,
  GetReviewHistoryInput,
  GetReviewStatusInput,
  OUTPUT_SCHEMAS,
  RespondToReviewInput,
  ReviewWithCodexInput,
  RunChecksInput,
  StartReviewLoopInput,
  StopReviewLoopInput,
  inputJsonSchema,
} from "./tool-schemas.js";

export const SERVER_NAME = "code-parley";

export const SERVER_INSTRUCTIONS =
  "CodeParley: independent Codex reviews and user-approved checks for a local git repository inside the user's configured allowed roots. " +
  "Flow: create_review_run → run_checks → review_with_codex → get_review_status / get_review_history → respond_to_review → stop_review_loop. " +
  "Long work runs as an operation: a call waits at most about 45 s, then returns a handle with operation_id; keep polling get_review_status(run_id, wait_seconds). " +
  "Cancelling or timing out a call ends only that wait: the operation keeps running until stop_review_loop(mode: cancel_active, expected_operation_id). " +
  "Never pass file contents, diffs, check output or findings: the engine captures and assembles all evidence itself, and unknown arguments are rejected. " +
  "Checks run only if the user approved them with the CLI (code-parley checks approve); their raw output stays local. " +
  "Task completion is derived by the engine (get_review_status: completion) and nothing can set it; engine conditions (failed, stale or missing checks; coverage) and isolation incidents are reported separately and can be resolved by no reviewer or decision. " +
  "respond_to_review records your position on each finding (accepted, disputed, deferred, fix_claimed) with the response_token shown for it: a claim that resolves nothing. A later review_with_codex that you request presents it to Codex when it earns an exchange; Codex's reply is a stance that resolves nothing either. " +
  "User decisions (require_resolution, waive, defer, revoke) and task amendments come only from CodeParley's local operator interface (the user runs code-parley decide / amend at a terminal); no tool records them, and telling CodeParley what the user decided is your claim. Nothing runs by itself: you decide when to review again, unless the operator allowed automation (start_review_loop): then follow continuation.next_action; controller texts are not the user. " +
  "Delegated fixes (delegate_fix, apply_fix): only the owner confirms one (code-parley fix confirm).";

const NEXT = "Cancelling this call does not stop the operation.";

/** The derived completion in a summary line (Phase 2.3): its state and the blockers by category. */
function completionText(c: { state: string; counts: Record<string, number> }): string {
  if (c.state === "ready") return "; completion: READY (derived; nothing was started)";
  const parts = Object.entries(c.counts).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`);
  return `; completion: ${c.state} (${parts.join(", ")})`;
}

/** The discussion threads in a summary line (Phase 2.2): who must act. */
function threadText(d: { awaiting_reviewer: number; awaiting_implementer: number; awaiting_user: number }): string {
  const parts: string[] = [];
  if (d.awaiting_implementer) parts.push(`${d.awaiting_implementer} awaiting you`);
  if (d.awaiting_reviewer) parts.push(`${d.awaiting_reviewer} with a turn the next review presents to Codex`);
  if (d.awaiting_user) parts.push(`${d.awaiting_user} needing a user decision (escalation)`);
  return parts.length ? `; discussion threads: ${parts.join(", ")}` : "";
}

export interface Session {
  env: EngineEnv;
  diagnostics: boolean;
  /** 2025 era: the client's roots as last fetched (null: none / unsupported). */
  legacyRoots: string[] | null;
  log(line: string): void;
}

interface Run<I> {
  le: Loaded;
  args: I;
  ctx: CallContext;
  session: Session;
  startedAtMs: number;
}

/** What a handler returns: the host-facing value and the run (for its disclosure limits). */
interface Produced {
  value: Record<string, unknown>;
  run: RunHandle | null;
  entries?: readonly SourceEntry[] | null;
  state?: StateRecord;
}
const NEED_ROOTS = Symbol("need_roots");
type HandlerResult = Produced | typeof NEED_ROOTS;

interface ToolSpec<S extends z.ZodType> {
  def: Omit<ToolDefinition, "inputSchema" | "outputSchema" | "name">;
  input: S;
  run(r: Run<z.infer<S>>): Promise<HandlerResult>;
  /** Where a shortened result's complete content can be read (default: an operation's result document). */
  truncationNext?: string;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * The session's client roots for this call (advisory). 2025 era: as last fetched, or fetched
 * now in strict mode (MR-H: re-checked before every operation). 2026 era: only via a
 * multi-round-trip request, and only when needed and the client declared the roots capability.
 */
async function rootsFor(r: Run<unknown>, needed: boolean): Promise<string[] | null | typeof NEED_ROOTS> {
  if (r.ctx.era === "legacy") {
    if (needed && r.le.cfg.config.client_roots.enforce) {
      const fresh = await r.ctx.listRootsNow();
      // Strict mode fails closed: a client that declares roots but cannot list them now is
      // not treated as having none (which would skip the association check).
      if (fresh === null && r.ctx.clientSupportsRoots) throw new DomainError("REPO_OUTSIDE_SESSION_ROOTS", "strict client roots: the client's roots could not be read, so repository association cannot be checked; the operation is refused", { retryable: true });
      r.session.legacyRoots = fresh;
    }
    return r.session.legacyRoots;
  }
  if (r.ctx.rootsResponse) return r.ctx.rootsResponse;
  if (needed && r.ctx.clientSupportsRoots) return NEED_ROOTS;
  return null;
}

/**
 * The client cancelled this call (Esc, a host timeout): only the wait ends (D-27, MR-J). The
 * reason text is logged for diagnostics only — nothing depends on it (P4, K5).
 */
function noteWaitEnd(r: Run<unknown>, w: WaitOutcome<unknown>, what: string): void {
  if (w.done || w.why !== "call_cancelled") return;
  const reason: unknown = r.ctx.signal.reason;
  const text = (reason instanceof Error ? `${reason.name}: ${reason.message}` : String(reason ?? "")).replace(/[\u0000-\u001f]/g, " ").slice(0, 160);
  r.session.log(`call cancelled by the client after ${Date.now() - r.startedAtMs} ms while waiting for the ${what} operation (${text || "no reason given"}); the operation continues`);
}

function tick(r: Run<unknown>, what: string): () => void {
  let n = 0;
  return () => {
    n++;
    r.ctx.progress(`still waiting for the ${what} operation (${Math.round((Date.now() - r.startedAtMs) / 1000)} s); ${NEXT}`, n);
  };
}

async function handleFor(run: RunHandle, operationId: string, deduplicated: boolean): Promise<Record<string, unknown>> {
  const st = await readState(run.paths);
  const op = st.operations.find((o) => o.operation_id === operationId);
  const last = [...st.events].reverse().find((e) => e.refs?.["operation_id"] === operationId);
  return op ? { ...operationHandle(op, { deduplicated, ...(last ? { progress: last.summary } : {}) }) } : { operation_id: operationId, status: "running", next: NEXT };
}

function resultView(r: OperationResult): Record<string, unknown> {
  return r.kind === "checks" ? checksResultView(r.result) : r.kind === "review" ? reviewResultView(r.result) : prepareResultView(r.result);
}

/** Start → bounded wait → finished result or running handle (the common shape of starting tools). */
async function startAndWait(r: Run<{ wait_seconds?: number | undefined }>, run: RunHandle, started: Started, what: string): Promise<Record<string, unknown>> {
  const deadline = r.startedAtMs + waitMsFor(r.le, r.args.wait_seconds);
  const w = await waitBounded(started.completion, deadline, r.ctx.signal, tick(r, what), 8_000);
  noteWaitEnd(r, w, what);
  if (w.done) {
    // `deduplicated` keeps the engine's meaning where it has one (a review: an identical earlier
    // input's result was returned); `operation_deduplicated`: this call joined an existing
    // operation (same request_id, or the same request while it was running).
    const view = resultView(w.value);
    return { run_id: run.runId, ...view, deduplicated: (view as { deduplicated?: boolean }).deduplicated ?? started.deduplicated, operation_deduplicated: started.deduplicated };
  }
  const handle = await handleFor(run, started.operation.operation_id, started.deduplicated);
  return {
    summary: `${what} operation ${shortId(started.operation.operation_id)} is running${started.deduplicated ? " (an identical request was already running or recorded; this is its handle)" : ""}. ${handle["next"] ?? NEXT}`,
    run_id: run.runId,
    ...handle,
  };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const createReviewRunTool: ToolSpec<typeof CreateReviewRunInput> = {
  def: {
    title: "Create review run",
    description:
      "Create a review run for a local git repository and capture its baseline. Inputs: task_envelope (goal required; background, constraints, acceptance_criteria etc. are context for the reviewer, never instructions to the engine); repository_root (optional; must lie inside the user's configured allowed roots — without it, the single client root inside them is used); review_target: uncommitted (default) | since_baseline | base_ref{ref}; additional_required_checks (can only ADD to the trusted verification floor); budget_overrides (can only LOWER the configured budgets); request_id (idempotent: the same id with the same arguments returns the same run). " +
      "The baseline capture is an operation: the call waits at most wait_seconds (default 45, max 50) and returns the baseline or a running handle. Cancelling this call does not stop the operation. Only the server's own run store is written; repository files are never modified. " +
      "Result: run_id, state, repository, scope, verification_floor, checks_available (approved profiles; pending_approval lists repository proposals only the user can approve with the CLI), budgets, warnings, prepare.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  input: CreateReviewRunInput,
  async run(r) {
    const roots = await rootsFor(r, r.args.repository_root === undefined || r.le.cfg.config.client_roots.enforce);
    if (roots === NEED_ROOTS) return NEED_ROOTS;
    const created = await createReviewRun(
      r.le,
      {
        task_envelope: r.args.task_envelope,
        repository_root: r.args.repository_root,
        review_target: r.args.review_target,
        additional_required_checks: r.args.additional_required_checks,
        budget_overrides: r.args.budget_overrides,
        request_id: r.args.request_id,
      },
      { roots },
    );
    const started = await prepareStarted(r.le, created.run, created.prepareOperationId, created.completion, created.deduplicated);
    const deadline = r.startedAtMs + waitMsFor(r.le, r.args.wait_seconds);
    const w = await waitBounded(started.completion, deadline, r.ctx.signal, tick(r, "baseline capture"), 8_000);
    noteWaitEnd(r, w, "baseline capture");
    const view = await runCreatedView(r.le, created.run);
    const prepare = w.done ? resultView(w.value) : await handleFor(created.run, created.prepareOperationId, created.deduplicated);
    const floor = view.verification_floor.required.length ? `verification floor: ${view.verification_floor.required.join(", ")}` : view.verification_floor.no_required_checks ? "no required checks (explicitly configured)" : "no verification floor configured";
    const summary =
      `run ${shortId(view.run_id)} ${created.deduplicated ? "(existing run for this request_id) " : ""}for ${view.repository.root} (target ${view.target.kind}); ${floor}; ` +
      (w.done ? String((prepare as { summary?: string }).summary ?? "") : `baseline capture still running (operation ${shortId(created.prepareOperationId)}); ${NEXT}`) +
      (view.warnings.length ? `; ${view.warnings.length} warning(s)` : "");
    return { value: { summary, ...view, deduplicated: created.deduplicated, prepare }, run: created.run };
  },
};

const runChecksTool: ToolSpec<typeof RunChecksInput> = {
  def: {
    title: "Run approved checks",
    description:
      "Run user-approved deterministic checks for a run: by default the run's verification floor, or the named approved checks/profiles. Approved commands execute this repository's code with the user's privileges, outside any sandbox; only the CLI (code-parley checks approve) can approve them, never this tool. Checks are serialized per worktree (WORKTREE_BUSY when another operation holds it). " +
      "The call waits at most wait_seconds (default 45, max 50), then returns a handle; cancelling this call does not stop the checks — use stop_review_loop(mode: cancel_active, expected_operation_id). request_id makes the start idempotent. " +
      "Result per check: status, exit_code, duration, identities and stability; plus the verification floor for the current source. Raw stdout/stderr stay in the local run store and are never returned. A passing check is necessary evidence, never proof that a reported problem is absent. Errors include CHECK_NOT_APPROVED, UNKNOWN_PROFILE, NO_CHECKS_CONFIGURED, WORKTREE_BUSY, BUDGET_EXHAUSTED, RUN_BUSY.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
  input: RunChecksInput,
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    const roots = await rootsFor(r, r.le.cfg.config.client_roots.enforce);
    if (roots === NEED_ROOTS) return NEED_ROOTS;
    await assertRunInScope(r.le, run, { roots });
    const started = await startChecksOperation(r.le, run, { ...(r.args.checks ? { checks: r.args.checks } : {}), ...(r.args.profiles ? { profiles: r.args.profiles } : {}), ...(r.args.request_id !== undefined ? { request_id: r.args.request_id } : {}) });
    return { value: await startAndWait(r, run, started, "checks"), run };
  },
};

const reviewWithCodexTool: ToolSpec<typeof ReviewWithCodexInput> = {
  def: {
    title: "Independent Codex review",
    description:
      "Request an independent Codex review of the run's current changes. The engine captures a sanitized snapshot itself (confidential files withheld), assembles the review bundle from its own records (diff, manifest, structured check metadata, open findings) and runs Codex under verified read isolation (S1; fails closed with CODEX_ISOLATION_UNAVAILABLE). Codex sends the review content to OpenAI. Repository files are never modified. " +
      "Inputs: focus (optional, ≤4000 chars, context only), depth (focused | standard | deep), force_new (ignore an identical earlier review), request_id (idempotent start). Reviews take minutes: the call waits at most wait_seconds (default 45, max 50) and returns a handle; poll get_review_status(run_id, wait_seconds). Cancelling this call does not stop the review — use stop_review_loop(mode: cancel_active, expected_operation_id). " +
      "Implementer responses recorded since (respond_to_review) are presented to Codex with their discussion thread when they earn an exchange; Codex replies with a structured stance (maintain, withdraw, revise, need_information) that never changes a finding's lifecycle — only its assessments do. The user's task amendments (recorded through the local operator interface, code-parley amend) are presented as the user's task context and bound into the review input; amendments lists what was presented. " +
      "Result: advisory verdict, assessment, triaged findings (established per reviewer evidence, not engine-verified), open findings carried across rounds, engine conditions, isolation incidents, coverage, limitations, freshness now and at completion, effective isolation; each tracked item carries its response_token, thread_id and discussion state for respond_to_review; discussion lists what was presented, Codex's replies and what was not presented, with why. Completion is reported by get_review_status, never by a review.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  input: ReviewWithCodexInput,
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    const roots = await rootsFor(r, r.le.cfg.config.client_roots.enforce);
    if (roots === NEED_ROOTS) return NEED_ROOTS;
    await assertRunInScope(r.le, run, { roots });
    const started = await startReviewOperation(r.le, run, {
      ...(r.args.focus !== undefined ? { focus: r.args.focus } : {}),
      ...(r.args.depth !== undefined ? { depth: r.args.depth } : {}),
      ...(r.args.force_new !== undefined ? { force_new: r.args.force_new } : {}),
      ...(r.args.request_id !== undefined ? { request_id: r.args.request_id } : {}),
    });
    const value = await startAndWait(r, run, started, "review");
    // Phase 3.3a: with a live automation loop, a running review is awaited by ending the turn;
    // the controller wakes this session when it finishes (the next action itself comes from status).
    const loop = (await readState(run.paths)).continuation;
    if (loop && !isEnded(loop.status)) {
      const running = value["status"] === "running";
      const live = loop.status === "active" && loop.binding?.state === "live";
      value["continuation"] = {
        status: loop.status,
        instruction: running && live ? instructionFor(run.runId, { code: "await_review", kind: "await", reason: "review_running" }) : `Call get_review_status with run_id="${run.runId}" and follow its continuation.next_action.`,
      };
      if (running && live) value["next"] = "END YOUR TURN: CodeParley's controller wakes this session when the review finishes (cancelling a call does not stop the operation).";
    }
    return { value, run };
  },
};

const startReviewLoopTool: ToolSpec<typeof StartReviewLoopInput> = {
  def: {
    title: "Start automated review loop",
    description:
      "Start same-session automation for a run, only after the operator allowed it: the operator's grants are held by the CodeParley custodian (Windows: code-parley loop allow --repo <path>, elevated; Linux: code-parley-operator loop allow --repo <path>, as the operator). Each new loop consumes one granted loop before anything automated runs; without one the call fails with LOOP_NOT_AUTHORIZED. Without a validated custodian installed on this host (Windows or Linux) the call fails closed with CUSTODIAN_UNAVAILABLE: there is no weaker substitute, and review, checks and responses are unaffected. One loop per run, ever: calling again returns the same loop. A start whose answer (and one-time bind_nonce) was lost fails with LOOP_START_UNRECONCILED: stop that loop (code-parley loop stop <run>) and use a new run. Budgets come from the grant and CodeParley's limits (per run at most 2 automated continuations, 2 idle wakes — 1 per review — and 15 minutes); no argument can raise them, and no tool accepts a session identity. " +
      "The CodeParley Claude Code plugin binds the loop to the session that receives this result (bind_nonce is one-time and consumed by the host's hook; nothing for you to do with it). Then CodeParley's controller may continue this session when it tries to stop while the engine's next action is yours, and wake it once when a review it awaits finishes. Follow continuation.next_action and continuation.instruction (get_review_status shows them too). " +
      "Controller texts start with [CodeParley controller — automated; not the user]: they are not the user and grant no user decision. Automation pauses on a user interrupt, a needed user decision (a hard pause that only code-parley decide and the operator's code-parley loop resume end), an operation that did not complete, or a settings change; it ends at ready, at its budget or deadline, when the run ends, or when the operator runs code-parley loop stop. Ready authorizes nothing: no commit, push, merge, tag or release.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  input: StartReviewLoopInput,
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    const roots = await rootsFor(r, r.le.cfg.config.client_roots.enforce);
    if (roots === NEED_ROOTS) return NEED_ROOTS;
    await assertRunInScope(r.le, run, { roots });
    const started = await startLoop(r.le, run);
    const st = await readState(run.paths);
    const routed = await routeRun(r.le, run, st, sourceBudgetFor(r.startedAtMs));
    // P3.4C-5 Increment 3 (§5.4): the protected run's route is the custodian's derivation when it serves one.
    const derived = await derivationForDisplay(r.le, run, true).catch(() => null);
    const route = derived?.available ? routeOfDerivation(derived) : routed.route;
    const view = loopView(run.runId, started.loop, route, Date.now());
    // A fresh nonce: the host's hook binds the loop to this session right after this result.
    if (started.nonce) view.instruction = instructionFor(run.runId, route);
    const summary =
      `run ${shortId(run.runId)}: automation loop ${started.existing ? "already exists" : "started"} (${started.loop.status}; continuations ${started.loop.used.continuations}/${started.loop.limits.continuations}, wakes ${started.loop.used.wakes}/${started.loop.limits.wakes_per_run}, until ${started.loop.deadline_at})` +
      (started.nonce ? "; the host binds it to this session now" : started.loop.binding ? "; it is already bound to a session" : "; it is not bound") +
      `; next action ${route.code}${derived?.available ? " (the custodian's derivation)" : ""}. Controller texts are not the user; ready authorizes nothing.`;
    return {
      value: {
        summary,
        run_id: run.runId,
        continuation: view,
        bind_nonce: started.nonce,
        existing: started.existing,
        note: "bind_nonce is consumed by the CodeParley plugin's PostToolUse hook in this session; it is single-use and expires within 60 s. Without the plugin the loop stays unbound and nothing continues automatically.",
      },
      run,
      entries: routed.src?.entries ?? null,
      state: st,
    };
  },
};

/**
 * The status report. At most ONE read of the working tree, bounded by what is left of this
 * call's time (a wait may have used most of it), and reused for the finished operation's
 * result and the review's freshness (M1.5-8; M1.6: the call stays inside host limits).
 */
async function statusOf(r: Run<unknown>, run: RunHandle, extra: Record<string, unknown>, finished: Operation | null = null): Promise<Produced> {
  // Attended status: a custodian-governed run derives from the authoritative custodian projection
  // (P3.4C-1); a never-governed run (the marker is unset) uses the TS store with no custodian exchange.
  const raw = await withAuthoritativeUserRecords(r.le, run, await readState(run.paths), { protected: false });
  const { state: st, recoveryPending } = await observedState(r.le, raw);
  const active = st.operations.find((o) => o.status === "running") ?? null;
  const src: SourceNow = await currentSource(r.le, run, raw, sourceBudgetFor(r.startedAtMs));
  const known = knownSourceOf(src);
  if (finished) extra["completed_operation"] = resultView(await resultOf(r.le, run, finished, known));
  const report = await runReport(r.le, run, raw, src.source_id, known, st);
  // P3.4C-5 Increment 3 (§5.4): a protected run presents the CUSTODIAN's derivation (its completion and route), labelled
  // as such; this server's own derivation stays as an explicitly non-authoritative detail, and is the only one shown —
  // labelled so — when the custodian serves none (every automation decision then fails closed).
  const derived = await derivationForDisplay(r.le, run, locallyProtected(raw)).catch(() => null);
  // Phase 3.3a: the run's automation loop and the engine's next action (observed, never committed).
  const localContinuation = loopViewOf(r.le, raw, st, report);
  const continuation = localContinuation && derived?.available && raw.continuation
    ? loopView(run.runId, raw.continuation, isEnded(raw.continuation.status) ? null : routeOfDerivation(derived), Date.now())
    : localContinuation;
  const completion = derived?.available
    ? { ...derived.completion, authority: "custodian", derivation_id: derived.derivationId, derived_at: derived.at }
    : derived ? { ...report.completion, authority: "local_non_authoritative" } : report.completion;
  const limitations = [...report.limitations];
  if (derived && !derived.available) limitations.push({ code: "custodian_derivation_unavailable", detail: `the custodian's derivation of this protected run is unavailable (${derived.code}: ${derived.detail}); the completion shown is this server's own, NOT authoritative, and automation fails closed` });
  if (src.note) limitations.push({ code: "current_source_note", detail: src.note });
  if (recoveryPending.length) limitations.push({ code: "operation_owner_died", detail: `${recoveryPending.length} operation(s) whose server exited are shown as interrupted; recovery is recorded by the next operation or stop` });
  const f = report.floor;
  const summary =
    `run ${shortId(run.runId)} ${st.state}` +
    (active ? `; ${active.kind} operation ${shortId(active.operation_id)} running` : "") +
    `; source ${src.source_id ? shortHash(src.source_id) : "unknown"}${src.recomputed ? "" : " (last known)"}` +
    `; floor ${f.configured ? (f.satisfied_for_current_source ? "satisfied" : "NOT satisfied") : "not configured"}` +
    `; ${report.open_findings.length} open reviewer item(s)${report.open_findings.length ? ` (${discussionText(report.discussion)})` : ""}${threadText(report.discussion)}, ${report.conditions.length} engine condition(s), ${report.incidents.length} isolation incident(s)` +
    (report.latest_review ? `; latest review round ${report.latest_review.round} ${report.latest_review.accepted ? "accepted" : "not accepted"}${report.latest_review.freshness ? (report.latest_review.freshness.current ? ", current now" : ", NOT current now") : ""}` : "; no review yet") +
    completionText(report.completion) +
    (derived?.available ? ` (the custodian's derivation: ${derived.completion.state}, route ${derived.route.code})` : derived ? " (local, not authoritative: the custodian's derivation is unavailable)" : "") +
    (continuation ? `; automation ${continuation.status}${continuation.next_action ? `, next action ${continuation.next_action.code}` : ""}` : "") +
    ". Responses and Codex replies are claims and resolve nothing; user decisions and amendments come only from the local operator CLI.";
  return {
    value: {
      summary,
      run_id: run.runId,
      state: st.state,
      active_operation: active ? operationHandle(active) : null,
      ...extra,
      completion,
      ...(derived?.available ? { local_completion: { ...report.completion, authority: "local_non_authoritative" } } : {}),
      user: report.user,
      current_source_id: src.source_id,
      current_source_id_age_ms: src.age_ms,
      current_source_recomputed: src.recomputed,
      floor: report.floor,
      latest_review: report.latest_review,
      open_findings: report.open_findings,
      discussion: report.discussion,
      conditions: report.conditions,
      incidents: report.incidents,
      limitations,
      budgets: report.budgets,
      ...(continuation ? { continuation } : {}),
    },
    run,
    entries: src.entries,
    state: raw,
  };
}

/** Where a shortened status or stop report's complete content can be read (it is not an operation result). */
const REPORT_TRUNCATION_NEXT =
  "The result was shortened to stay within host limits. Every discussion thread with its items, tokens and timeline: get_review_history(run_id, responses: {}) (paged; responses: {finding_id} for one thread). A finished operation's complete result: get_review_history(run_id, artifact: {operation_id, part: \"result\"}).";

const getReviewStatusTool: ToolSpec<typeof GetReviewStatusInput> = {
  def: {
    title: "Review status",
    description:
      "Read-only status of a run, or without run_id the runs in the allowed scope. With wait_seconds (max 50) it waits for the run's active operation and returns that operation's full result as completed_operation; with wait_seconds and no active operation, completed_operation is the latest finished operation's result. Cancelling this call ends only its wait (never the operation). " +
      "Reports: state, active_operation handle, current_source_id (recomputed; the last known value with its age when the worktree is busy), verification floor for the current source, latest review and its freshness now, open reviewer findings — each with its response_token, discussion state and your latest response (respond_to_review) —, discussion counts and discussion.threads (every thread with a respondable item, informational ones included: its items' response_tokens, latest implementer position and whether Codex has seen it, Codex's latest stance, last speaker, exchange budget, whether new information is required, escalation when a user decision is needed, and who must act), engine conditions (failed, stale or missing checks; coverage), isolation incidents, limitations and budgets. completion is derived (ready, or every blocker: engine conditions, checks, review freshness, threads needing the user, the reviewer or you; settled threads); nothing can set it and ready starts nothing. user: the user's decisions and amendments (operator-authoritative: only the local operator CLI writes them); each thread adds user_decision (its kind, assurance and whether it still applies), blocks_completion and completion_category.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  input: GetReviewStatusInput,
  truncationNext: REPORT_TRUNCATION_NEXT,
  async run(r) {
    if (r.args.run_id === undefined) {
      const runs = (await listRuns(r.le, r.le.allowedRoots)).slice(0, 50);
      const rows = [];
      for (const h of runs) {
        const st = await readState(h.paths).catch(() => null);
        const env = (h.meta.envelope ?? {}) as { goal?: string };
        const active = st?.operations.find((o) => o.status === "running");
        const row = { run_id: h.runId, state: st?.state ?? "UNREADABLE", created_at: h.meta.created_at, goal_excerpt: (env.goal ?? "").slice(0, 160) as string | null, goal_withheld: false, repository_root: h.meta.repository_root, active_operation: active ? { operation_id: active.operation_id, kind: active.kind } : null };
        // A row carries its own run's text (the goal): redact it with THAT run's withheld names
        // and hashes, as the run's own status does (MR-F; the list result itself has no run).
        // Without readable confidentiality records the goal is withheld, never shown unfiltered.
        let shown = { ...row, goal_excerpt: null as string | null, goal_withheld: true };
        if (st) {
          try {
            shown = toHost(row, await disclosureFor(r.le, h, { state: st })).value;
          } catch {
            /* fail closed: the goal stays withheld */
          }
        }
        rows.push(shown);
      }
      return { value: { summary: `${rows.length} run(s) in the allowed scope${rows.length === 50 ? " (newest 50)" : ""}`, runs: rows }, run: null };
    }
    const run = await findRun(r.le, r.args.run_id);
    await assertRunInScope(r.le, run, { roots: r.ctx.era === "legacy" ? r.session.legacyRoots : r.ctx.rootsResponse });
    const extra: Record<string, unknown> = {};
    let finished: Operation | null = null;
    if (r.args.wait_seconds !== undefined) {
      const st = await readState(run.paths);
      // Observe only: an operation whose owner already died is shown as interrupted, not awaited.
      const active = (await observedState(r.le, st)).state.operations.find((o) => o.status === "running");
      if (active) {
        const deadline = r.startedAtMs + waitMsFor(r.le, r.args.wait_seconds);
        const w = await waitForCompletion(r.le, run, active, deadline, r.ctx.signal, tick(r, active.kind), 8_000);
        noteWaitEnd(r, w, active.kind);
        if (w.done) extra["completed_operation"] = resultView(w.value);
        else {
          // The operation may have committed its outcome just before the deadline while its
          // result was still being assembled: report it from the committed record.
          const op = (await readState(run.paths)).operations.find((o) => o.operation_id === active.operation_id);
          if (op && op.status !== "running") finished = op;
        }
      } else {
        finished = [...st.operations].reverse().find((o) => o.status !== "running") ?? null;
      }
    }
    // Phase 4 Increment 3: a delegated fix this server process runs is waited for too, and the run's fixes are reported
    // as the custodian holds them (a protected run only; never their content).
    const fix = runningFixes.get(run.runId);
    if (fix && r.args.wait_seconds !== undefined) {
      const w = await waitBounded(fix.completion, r.startedAtMs + waitMsFor(r.le, r.args.wait_seconds), r.ctx.signal);
      if (w.done) extra["completed_fix"] = w.value;
    }
    if (locallyProtected(await readState(run.paths))) extra["fixes"] = await fixesOf(r.le, run).catch(() => null);
    return statusOf(r, run, extra, finished);
  },
};

// ---------------------------------------------------------------------------
// Phase 4 Increment 3: delegated fixes (contract §3.1)
// ---------------------------------------------------------------------------

/** The delegations this server process runs, by run (the custodian allows one running operation per run). */
const runningFixes = new Map<string, { operationId: string; completion: Promise<DelegateFixResult | { error: { code: string; message: string } }> }>();

const FIX_OWNER_NEXT = "Inspect the proposal (get_review_status: fixes; the owner sees the custodian's exact rendering with `code-parley fix show <run> <proposal>`), then ask the OWNER to confirm or reject it at an operator terminal (`code-parley fix confirm|reject <run> <proposal>`). No tool can confirm. Once confirmed, apply it with apply_fix.";

const delegateFixTool: ToolSpec<typeof DelegateFixToolInput> = {
  def: {
    title: "Delegate one scoped fix",
    description:
      "Delegate ONE scoped fix of a protected run to Codex (Windows or Linux, the validated CodeParley custodian, a protected run whose configuration is in force, an operator-confirmed FIX self-test and a fix budget; FIX_DELEGATION_UNAVAILABLE / CODEX_ISOLATION_UNAVAILABLE / BUDGET_EXHAUSTED otherwise). " +
      "Codex edits a disposable copy of the custodian's sanitized capture of the latest accepted review under an OS-confined profile; the custodian validates what it wrote against the boundary and its own baseline and holds it as a proposal (status proposed), or rejects it. NOTHING is written to the worktree. " +
      "Input: the task text and a boundary (permitted_files / permitted_dirs, allow_create / allow_delete / allow_binary, file and byte limits, time limit, proposal lifetime) — never contents, diffs or a confirmation. " +
      "A proposal waits for the OWNER: only the owner confirms or rejects the custodian's rendering at an operator terminal (code-parley fix confirm|reject); then apply_fix applies exactly that content. The call waits up to about 45 s; then poll get_review_status(run_id, wait_seconds) (its fixes section).",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  input: DelegateFixToolInput,
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    await assertRunInScope(r.le, run, { roots: r.ctx.era === "legacy" ? r.session.legacyRoots : r.ctx.rootsResponse });
    if (runningFixes.has(run.runId)) throw new DomainError("RUN_BUSY", `a delegated fix of this run is still running (${runningFixes.get(run.runId)!.operationId}): poll get_review_status(run_id, wait_seconds)`, { retryable: true });
    const { run_id: _id, wait_seconds: _w, ...input } = r.args;
    let begun!: (v: { operationId: string; fixId: string }) => void;
    const begunP = new Promise<{ operationId: string; fixId: string }>((res) => (begun = res));
    const completion = delegateFix(r.le, run, input, { onBegun: (operationId, fixId) => begun({ operationId, fixId }) });
    // A refusal before the custodian began anything is this call's error; after that the fix runs on in this process.
    const first = await Promise.race([begunP.then((b) => ({ begun: b })), completion.then((done) => ({ done }))]);
    const settled = completion.catch((e: unknown) => ({ error: { code: String((e as { code?: string }).code ?? "INTERNAL"), message: e instanceof Error ? e.message : String(e) } }));
    const view = (d: DelegateFixResult): Record<string, unknown> => ({
      summary: `delegated fix ${shortId(d.operation_id)}: ${d.status}${d.proposal ? ` (${d.proposal.change_count} file(s), ${d.proposal.total_bytes} bytes, expires ${d.proposal.expires_at})` : ""}${d.violation_count ? `; ${d.violation_count} violation(s)` : ""}`,
      run_id: run.runId, status: d.status, proposal_id: d.operation_id, fix_id: d.fix_id, proposal: d.proposal, violations: d.violations, baseline_review_id: d.baseline_review_id, detail: d.detail,
      next: d.status === "proposed" ? FIX_OWNER_NEXT : "No proposal is held: nothing can be confirmed or applied. Address the finding yourself or delegate again with a corrected task or boundary.",
    });
    if ("done" in first) return { value: view(first.done), run };
    runningFixes.set(run.runId, { operationId: first.begun.operationId, completion: settled });
    void settled.finally(() => runningFixes.delete(run.runId));
    const w = await waitBounded(completion, r.startedAtMs + waitMsFor(r.le, r.args.wait_seconds), r.ctx.signal);
    if (w.done) return { value: view(w.value), run };
    return {
      value: {
        summary: `delegated fix ${shortId(first.begun.operationId)}: running (the fixer works in a disposable copy; nothing is written to the worktree)`,
        run_id: run.runId, status: "running", proposal_id: first.begun.operationId, fix_id: first.begun.fixId,
        next: "Poll get_review_status(run_id, wait_seconds): its fixes section shows the custodian's verdict. " + NEXT,
      },
      run,
    };
  },
};

const applyFixTool: ToolSpec<typeof ApplyFixToolInput> = {
  def: {
    title: "Apply an owner-confirmed fix",
    description:
      "Apply the OWNER-CONFIRMED proposal of a delegated fix (proposal_id: the fix's id from delegate_fix / get_review_status fixes) to the worktree. The custodian consumes the owner's single-use confirmation — refused without one (FIX_NOT_CONFIRMED), after a rejection (FIX_DECLINED), expiry (CONFIRMATION_EXPIRED) or a previous application (CONFIRMATION_CONSUMED) — re-measures the worktree against the fix's baseline (FIX_STALE: nothing written, the confirmation unused) and hands back exactly the confirmed content. " +
      "Every target is checked at use (no link or junction on its way, the preimage unchanged, an added path absent); only that content is written, one file at a time (no atomic multi-file write is claimed); a failure restores what was written (apply_failed). The result is never `ready`: run fresh checks and request a distinct review (review_with_codex) afterwards. It takes no contents, diff or confirmation.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  input: ApplyFixToolInput,
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    await assertRunInScope(r.le, run, { roots: r.ctx.era === "legacy" ? r.session.legacyRoots : r.ctx.rootsResponse });
    const out = await applyFix(r.le, run, { proposal_id: r.args.proposal_id });
    return {
      value: {
        summary: `delegated fix ${shortId(out.fix_operation_id)}: ${out.status} (${out.files.map((f) => `${f.path}: ${f.state}`).join(", ")})`,
        run_id: run.runId, status: out.status, proposal_id: out.fix_operation_id, apply_operation_id: out.apply_operation_id, files: out.files, detail: out.detail,
        source_id_after: out.source_id_after, next: out.next,
      },
      run,
    };
  },
};

const getReviewHistoryTool: ToolSpec<typeof GetReviewHistoryInput> = {
  def: {
    title: "Review history",
    description:
      "Read-only run history. Without artifact: the run's events, paged with after_seq and limit (max 100). With artifact {operation_id, part, offset?, length? (max 30000)}: one character range of an operation's result document. Parts: result (the full operation result, for results that were shortened), review_output (the normalized reviewer output), review_items (triaged items, including those of a review that was not accepted). With responses {finding_id?, offset?, length?}: the discussion history — every response and Codex reply in full, the reviewer's assessments, and each thread's timeline (turns, presentations to Codex, replies) with its budget and escalation; finding_id (any item of a thread) selects that whole thread. It also holds every user decision (status, provenance, what it was decided against) and task amendment (effective or replaced, seen by the reviewer). " +
      "Raw check output, Codex event streams, prompts and local capture records are never available through this tool.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  input: GetReviewHistoryInput,
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    await assertRunInScope(r.le, run, { roots: r.ctx.era === "legacy" ? r.session.legacyRoots : r.ctx.rootsResponse });
    const st = await readState(run.paths);
    if (r.args.artifact && r.args.responses) throw new DomainError("INVALID_ARGUMENT", "ask for either an artifact or the responses history, not both");
    if (r.args.responses) {
      const q = r.args.responses;
      // Page the HOST VIEW of the response history (rationales are redacted like all host text).
      const hostDoc = toHost(responsesDocument(st, q.finding_id), await disclosureFor(r.le, run, { state: st })).value;
      const page = pageText(JSON.stringify(hostDoc), q.offset, q.length);
      return {
        value: {
          summary: `implementer-response history${q.finding_id ? ` of item ${q.finding_id} and its lineage` : ""} (${st.implementer_responses.length} response(s) in the run): characters ${page.offset}–${page.offset + page.length} of ${page.total_length}${page.offset + page.length < page.total_length ? " (more: increase offset)" : ""}`,
          run_id: run.runId,
          responses: { finding_id: q.finding_id ?? null, ...page },
        },
        run,
        state: st,
      };
    }
    if (r.args.artifact) {
      const a = r.args.artifact;
      const doc = await artifactDocument(r.le, run, st, a.operation_id, a.part);
      // Page the HOST VIEW of the document, never the raw text.
      const hostDoc = toHost(doc, await disclosureFor(r.le, run, { state: st })).value;
      const page = pageText(JSON.stringify(hostDoc), a.offset, a.length);
      return {
        value: {
          summary: `${a.part} of operation ${shortId(a.operation_id)}: characters ${page.offset}–${page.offset + page.length} of ${page.total_length}${page.offset + page.length < page.total_length ? " (more: increase offset)" : ""}`,
          run_id: run.runId,
          artifact: { operation_id: a.operation_id, part: a.part, ...page },
        },
        run,
        state: st,
      };
    }
    const page = eventsPage(st, r.args.after_seq, r.args.limit);
    return {
      value: { summary: `${page.events.length} of ${page.total} event(s)${page.next_after_seq !== null ? `; more after seq ${page.next_after_seq}` : ""}`, run_id: run.runId, events: page.events, next_after_seq: page.next_after_seq },
      run,
      state: st,
    };
  },
};

/**
 * Phase 2.1: record the implementer's responses to current reviewer items. The engine checks
 * them against the run's current state (each item's response token) and records all or none;
 * it binds every response to the source identity read once in this call (bounded like a status
 * call; a fix claim needs it fresh). Nothing else changes, nothing is sent to Codex.
 */
const respondToReviewTool: ToolSpec<typeof RespondToReviewInput> = {
  def: {
    title: "Respond to review findings",
    description:
      "Record your response to current reviewer findings of a run: up to 50 per call, all or none. Each names finding_id (an item id from get_review_status — open findings or discussion.threads, which list informational items too — or a review result) and the response_token shown with it; if the item or its thread changed since (a newer review, a Codex reply, another response), the call fails with STALE_FINDING_STATE: read it again and decide anew. disposition: accepted (valid; open work until a later review reports it resolved), disputed (you disagree), deferred (you ask to defer: a request, not a decision; it stays open) or fix_claimed (a claim awaiting a later review; needs the current source, else SOURCE_UNAVAILABLE). rationale: at most 2000 characters, required except for accepted. references: optional repository-relative locations (claims). request_id makes a retry return the recorded result. Refused with RUN_BUSY while a review of the run runs. " +
      "A response is the implementer's claim, never the user's decision: it changes no finding, triage or status, resolves nothing, starts no review or check and modifies no file. A later review_with_codex that you request presents it to Codex (disputes and fix claims ask for a reply) only when it earns an exchange: 3 per thread, and a repeat of the same position without new evidence, references, source or check changes is recorded but not presented. delivery_preview says what the next review would do. Engine conditions and incidents cannot be responded to.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  input: RespondToReviewInput,
  // No operation: what a shortened result left out is in the status and the response history.
  truncationNext: "The result was shortened to stay within host limits; the responses are recorded. Every item's current response_token and discussion state: get_review_status(run_id). The recorded responses: get_review_history(run_id, responses: {}).",
  async run(r) {
    const run = await findRun(r.le, r.args.run_id);
    const roots = await rootsFor(r, r.le.cfg.config.client_roots.enforce);
    if (roots === NEED_ROOTS) return NEED_ROOTS;
    await assertRunInScope(r.le, run, { roots });
    // The source is read at most once, and only when the call gets past the checks that need no tree read.
    const read: { src: SourceNow | null } = { src: null };
    const currentSourceNow = async (): Promise<SourceForResponse> => {
      const src = await currentSource(r.le, run, await readState(run.paths), sourceBudgetFor(r.startedAtMs));
      read.src = src;
      // Every name the read had to withhold is kept with the responses, stable or not (host disclosure).
      const withheld = src.entries ? withheldOfEntries(src.entries) : undefined;
      if (src.recomputed && src.stable === true && src.source_id) return { source_id: src.source_id, note: null, withheld };
      return { source_id: null, note: src.recomputed ? "the working tree changed while it was being read" : (src.note ?? "the source identity was not recomputed"), withheld };
    };
    const out = await respondToReview(
      {
        runId: run.runId,
        runPaths: run.paths,
        owner: r.le.env.owner,
        currentSource: currentSourceNow,
        evidence: evidenceSelection(r.le, run),
        ...(r.le.env.testHooks?.lockDeps ? { lockDeps: r.le.env.testHooks.lockDeps } : {}),
        ...(r.le.env.testHooks?.classify ? { classify: r.le.env.testHooks.classify } : {}),
        ...(r.le.env.testHooks?.respond ? { testHooks: r.le.env.testHooks.respond } : {}),
      },
      { responses: r.args.responses.map((x) => ({ ...x, rationale: x.rationale ?? "" })), request_id: r.args.request_id },
    );
    return { value: { ...out }, run, entries: read.src?.entries ?? null };
  },
};

const stopReviewLoopTool: ToolSpec<typeof StopReviewLoopInput> = {
  def: {
    title: "Stop review work",
    description:
      "Stop work on a run. mode cancel_active requires expected_operation_id and cancels exactly that operation (its process tree is killed); if that operation already ended, its outcome is returned, and a different active operation is never cancelled (OPERATION_MISMATCH). mode abort cancels the active operation and ends the run (STOPPED). mode close ends an idle run (CLOSED) and reports the final open findings, engine conditions, incidents, limitations and the derived completion at closing (close does not need it to be ready). " +
      "cancellation.outcome is terminated only when the engine confirmed that the process tree is gone; otherwise cancellation_requested (possible survivors are named) or already_finished. The call waits up to about 45 s for that evidence; cancelling the call ends only the wait. Repository files are not modified by this tool. No mode sets completion.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
  input: StopReviewLoopInput,
  truncationNext: REPORT_TRUNCATION_NEXT,
  async run(r) {
    // Stop is always allowed (R-32), even when the run's scope was revoked.
    const run = await findRun(r.le, r.args.run_id);
    const deadline = r.startedAtMs + waitMsFor(r.le, undefined);
    const out = await stopRun(r.le, run, r.args.mode, r.args.expected_operation_id, r.args.reason, Math.max(0, deadline - Date.now()), r.ctx.signal);
    let src: SourceNow | null = null;
    const limitations = [];
    try {
      await assertRunInScope(r.le, run, { roots: r.ctx.era === "legacy" ? r.session.legacyRoots : r.ctx.rootsResponse });
      src = await currentSource(r.le, run, out.state, sourceBudgetFor(r.startedAtMs));
      if (src.note) limitations.push({ code: "current_source_note", detail: src.note });
    } catch {
      limitations.push({ code: "scope_revoked", detail: "the repository is no longer in scope; the source was not re-read" });
    }
    const report = await runReport(r.le, run, out.state, src?.source_id ?? null, knownSourceOf(src));
    const c = out.cancellation;
    const summary =
      `run ${shortId(run.runId)} ${out.state.state}` +
      (c ? `; ${c.kind} operation ${shortId(c.operation_id)}: ${c.outcome}${c.outcome === "terminated" ? " (process tree confirmed gone)" : c.outcome === "cancellation_requested" ? " (termination NOT confirmed)" : ` (${c.operation_status})`}` : "") +
      (out.custodian_end && !endEstablished(out.custodian_end) ? `; NOT established at the custodian (${out.custodian_end.outcome}${"code" in out.custodian_end ? ` ${out.custodian_end.code}` : ""})` : "") +
      `; ${report.open_findings.length} open reviewer item(s)${report.open_findings.length ? ` (${discussionText(report.discussion)})` : ""}${threadText(report.discussion)}, ${report.conditions.length} engine condition(s), ${report.incidents.length} isolation incident(s)${completionText(report.completion)}.`;
    return {
      value: {
        summary,
        run_id: run.runId,
        state: out.state.state,
        cancellation: c,
        custodian_end: out.custodian_end,
        completion: report.completion,
        user: report.user,
        open_findings: report.open_findings,
        discussion: report.discussion,
        conditions: report.conditions,
        incidents: report.incidents,
        floor: report.floor,
        latest_review: report.latest_review,
        limitations: [...report.limitations, ...limitations],
        note: "Repository files were not modified by this tool.",
      },
      run,
      entries: src?.entries ?? null,
      state: out.state,
    };
  },
};

const diagEchoTool: ToolSpec<typeof DiagEchoInput> = {
  def: {
    title: "Diagnostics echo",
    description:
      "Diagnostics (registered only with --diagnostics): echoes text and reports the negotiated protocol revision, the client's identity and roots, and the server's setup diagnostics — Node runtime, data home, configured and effective allowed roots, git, Codex version and support, S1 self-test status per sandbox backend, store health, and the NAMES (never values) of relevant environment variables. Read-only; runs no review, check or self-test.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  input: DiagEchoInput,
  async run(r) {
    const report = await doctor(r.le);
    return {
      value: {
        summary: `diag_echo: ${TOOL_VERSION}, protocol ${r.ctx.protocolVersion ?? "unknown"} (${r.ctx.era} era), client ${r.ctx.clientInfo ? `${r.ctx.clientInfo.name} ${r.ctx.clientInfo.version}` : "unknown"}; doctor ${report.ok ? "ok" : `${report.problems.length} problem(s)`}`,
        echo: r.args.text ?? null,
        protocol: { version: r.ctx.protocolVersion, era: r.ctx.era },
        client: { info: r.ctx.clientInfo, supports_roots: r.ctx.clientSupportsRoots, roots: r.ctx.era === "legacy" ? r.session.legacyRoots : r.ctx.rootsResponse, roots_note: r.ctx.era === "modern" ? "2026-07-28: roots are requested only when a tool needs them" : null },
        server: { pid: process.pid, cwd_used: false },
        doctor: report,
      },
      run: null,
    };
  },
};

// ---------------------------------------------------------------------------
// Registry and dispatch
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const TOOLS: Record<string, ToolSpec<any>> = {
  create_review_run: createReviewRunTool,
  run_checks: runChecksTool,
  review_with_codex: reviewWithCodexTool,
  get_review_status: getReviewStatusTool,
  get_review_history: getReviewHistoryTool,
  respond_to_review: respondToReviewTool,
  start_review_loop: startReviewLoopTool,
  stop_review_loop: stopReviewLoopTool,
  // Phase 4 Increment 3 (contract §3.1): delegated fixes — no tool confirms; the owner does, at the operator terminal.
  delegate_fix: delegateFixTool,
  apply_fix: applyFixTool,
};

/** The registered tools: the six of Milestone 1, respond_to_review (Phase 2.1), start_review_loop (Phase 3.3a) and delegate_fix /
 * apply_fix (Phase 4 Increment 3); diag_echo only with --diagnostics. */
export const TOOL_NAMES = Object.keys(TOOLS);

export function toolDefinitions(diagnostics: boolean): ToolDefinition[] {
  const entries = Object.entries(TOOLS);
  if (diagnostics) entries.push(["diag_echo", diagEchoTool]);
  return entries.map(([name, t]) => ({ name, ...t.def, inputSchema: inputJsonSchema(t.input), outputSchema: OUTPUT_SCHEMAS[name]! }));
}

export async function callTool(session: Session, name: string, args: unknown, ctx: CallContext): Promise<ToolOutcome> {
  const startedAtMs = Date.now();
  const spec = TOOLS[name] ?? (session.diagnostics && name === "diag_echo" ? diagEchoTool : undefined);
  if (!spec) return fail({ code: "INVALID_ARGUMENT", message: `unknown tool ${JSON.stringify(name.slice(0, 64))}`, retryable: false });
  const parsed = spec.input.safeParse(args);
  if (!parsed.success) {
    session.log(`tool ${name}: INVALID_ARGUMENT`);
    return fail(invalidArgument(parsed.error));
  }
  let le: Loaded | null = null;
  let run: RunHandle | null = null;
  // Phase 3.3a: no hook reports a user interrupt of an MCP call; the host's cancellation of this
  // call (Esc, Desktop's Stop, a host timeout, the session ending) pauses the run's automation.
  const runId = typeof (parsed.data as { run_id?: unknown }).run_id === "string" ? (parsed.data as { run_id: string }).run_id : null;
  let interrupt: Promise<void> | null = null;
  const onAbort = () => {
    if (!le || !runId) return;
    const loaded = le;
    const why = describeReason(ctx.signal.reason);
    interrupt = findRun(loaded, runId)
      .then((h) => recordCallInterrupt(loaded, h, `${name}: ${why}`))
      .then((paused) => {
        if (paused) session.log(`tool ${name}: the host cancelled the call; automation of run ${shortId(runId)} paused`);
      })
      .catch(() => undefined);
  };
  ctx.signal.addEventListener("abort", onAbort, { once: true });
  try {
    le = await loadEngine(session.env);
    const out = await spec.run({ le, args: parsed.data, ctx, session, startedAtMs }).finally(() => ctx.signal.removeEventListener("abort", onAbort));
    if (interrupt) await waitBounded(interrupt, Date.now() + 5_000, undefined);
    if (out === NEED_ROOTS) {
      session.log(`tool ${name}: requesting client roots (multi-round-trip)`);
      return { kind: "need_roots" };
    }
    run = out.run;
    const d = await disclosureFor(le, out.run, { ...(out.entries ? { entries: out.entries } : {}), ...(out.state ? { state: out.state } : {}) });
    const host = toHost(out.value, d);
    session.log(`tool ${name}: ok in ${Date.now() - startedAtMs} ms${host.redactions ? ` (${host.redactions} redaction(s))` : ""}`);
    return ok(host.value, spec.truncationNext);
  } catch (e) {
    const te = toToolError(e);
    session.log(`tool ${name}: ${te.code} in ${Date.now() - startedAtMs} ms`);
    // Errors are host-facing text too: the same disclosure limits apply (fail closed).
    try {
      const d = le ? await disclosureFor(le, run ?? (await runOf(le, args))).catch(() => disclosureFor(le!, null)) : NO_DISCLOSURE_LIMITS;
      return fail(toHost(te, d).value);
    } catch {
      return fail({ code: te.code, message: "the error details were withheld (confidentiality)", retryable: te.retryable });
    }
  }
}

/** The cancellation reason, for the log and the interrupt record only (nothing depends on it, P4/K5). */
function describeReason(reason: unknown): string {
  return (reason instanceof Error ? `${reason.name}: ${reason.message}` : String(reason ?? "")).replace(/[\u0000-\u001f]/g, " ").slice(0, 120) || "no reason given";
}

async function runOf(le: Loaded, args: unknown): Promise<RunHandle | null> {
  const id = (args as { run_id?: unknown } | null)?.run_id;
  return typeof id === "string" ? findRun(le, id).catch(() => null) : null;
}
