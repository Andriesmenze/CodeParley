// The operator side of same-session continuation (Phase 3.3a; P3.4C-0): loop grants, operator
// cancellation and resume, and the loop listing.
//
// ONLY the CLI (src/cli/loop-commands.ts) imports this module; the MCP server and the hooks have no
// import path to it (test/layering.test.ts) and no tool for it. A GRANT is the operator's permission
// for CodeParley to automate a bounded number of loops in one repository until it expires:
// start_review_loop consumes one, and nothing a model, a tool argument or a hook supplies can create
// or enlarge one.
//
// Since P3.4C-0 the grants are OWNED BY THE WINDOWS CUSTODIAN (src/custodian/): minting and revoking
// are two-phase operator actions the custodian accepts only from the operator surface with an elevated
// operator token (its OS caller classification is the security, assurance L1 — a development-stage
// vehicle, not a production boundary); the custodian establishes the repository's identity itself and
// enforces its own ceilings. The former user-writable grants file is never read: nothing is imported
// from it and nothing falls back to it. The CLI still asks for the confirmation at an interactive
// terminal (as Phase 2.3's decide/amend) — that is layering, not the security boundary. Stopping
// automation is always allowed. Where no validated custodian exists (every platform but Windows today),
// grants are refused up front (custodian/protected-loops.ts).

import { DomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import { CustodianGrants } from "../custodian/grants.js";
import { CustodianOperator } from "../custodian/operator.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import { CUSTODIAN_GRANT_CEILINGS, type CustodianDerivation, type GrantListing, type MintResult, type PreparedGrant } from "../custodian/protocol.js";
import type { CustodianTransport } from "../custodian/transport.js";
import { commitState, readState } from "../store/state-store.js";
import { isEnded, routeFromEngine } from "../policy/continuation.js";
import { threadReports, threadsNeedingUserDecision } from "../policy/discussion-reports.js";
import { reportDiscussion, respondable, responseToken } from "../policy/responses.js";
import type { StateRecord } from "../schemas/run-state.js";
import { caseKey } from "../workspace/paths.js";
import { loopView, routingFactsOf, type LoopView } from "./continuation.js";
import { custodianLoopForDisplay, derivationForDisplay, operatorEndLoop, operatorResumeLoopAt, overlay, routeOfDerivation, type CustodianRunRef } from "./custodian-loop.js";
import { custodianEquipped, fromListing, withAuthoritativeUserRecords } from "./protected-user-records.js";
import { heldStateOfListing } from "./protected-derivation.js";
import { lapsedRecords, operatorConfigSection } from "./config-authority.js";
import { currentSource, freshSourceId, knownSourceOf, observedState, OBSERVER_ENVIRONMENT_DIFFERS, runReport, SOURCE_BUDGET_MS } from "./status.js";
import { assertRunId, type Loaded, type RunHandle } from "./engine-env.js";

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor: "user_cli", summary: summary.slice(0, 500), refs });
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

export interface GrantRequest {
  /** The repository's canonical root (the CLI resolves it with git); the custodian establishes the
   * directory's identity from it itself. */
  repository_root: string;
  loops: number;
  minutes: number;
  /** The operator's idempotency key (default: a fresh id). */
  request_id?: string | undefined;
}

/** Refuse a request outside the custodian's ceilings before anything is sent (the custodian enforces its
 * own; these mirror them only to answer early). */
export function grantProblems(req: GrantRequest): string[] {
  const p: string[] = [];
  const C = CUSTODIAN_GRANT_CEILINGS;
  if (!Number.isInteger(req.loops) || req.loops < 1 || req.loops > C.loops) p.push(`--loops must be an integer from 1 to ${C.loops} (the custodian's ceiling)`);
  if (!Number.isInteger(req.minutes) || req.minutes < 1 || req.minutes > C.minutes) p.push(`--minutes must be an integer from 1 to ${C.minutes} (the custodian's ceiling)`);
  if (req.request_id !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(req.request_id)) p.push("the request id has 1 to 128 characters from A-Z, a-z, 0-9, '-' and '_'");
  return p;
}

/** The custodian for an operator action, behind the protected-loop gate (no custodian: refused). */
function custodianFor(le: Loaded): CustodianTransport {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  return gate.transport;
}

/** Phase 1 of a grant: the custodian resolves the repository's identity and renders exactly what it
 * will grant; nothing is granted until `commitGrant`. */
export async function prepareGrant(le: Loaded, req: GrantRequest): Promise<PreparedGrant> {
  const problems = grantProblems(req);
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", problems.join("; "));
  return new CustodianOperator(custodianFor(le)).prepareGrant(req.repository_root, req.loops, req.minutes, req.request_id ?? uuidv7());
}

/** Phase 2: commit the prepared grant the operator confirmed. */
export async function commitGrant(le: Loaded, authorizationRequestId: string): Promise<MintResult> {
  return new CustodianOperator(custodianFor(le)).commitGrant(authorizationRequestId);
}

/** Revoke every active grant of the repository's directory (it only reduces automation; the custodian
 * still requires the operator surface). */
export async function revokeGrants(le: Loaded, repositoryRoot: string): Promise<number> {
  return new CustodianOperator(custodianFor(le)).revoke(repositoryRoot);
}

/** The custodian's grants and the ceilings it enforces. */
export async function listGrants(le: Loaded): Promise<GrantListing> {
  return new CustodianGrants(custodianFor(le)).list();
}

// ---------------------------------------------------------------------------
// Operator stop and resume
// ---------------------------------------------------------------------------

/**
 * Operator cancellation: automation of the run ends (cancelled); armed wakes are refused. Always allowed.
 * P3.4C-2: the CUSTODIAN's loop is cancelled too (it only reduces automation: the operator surface first, the
 * implementer surface after it); the local record is cancelled whatever the custodian answers, and the
 * custodian's answer is reported. A run whose custodian loop exists without a local record (a start that did
 * not finish) is cancelled custodian-side. A P3.4C-0 start marker left by an older version is acknowledged.
 */
export async function operatorStopLoop(le: Loaded, run: RunHandle, reason: string | undefined): Promise<{ stopped: boolean; status: string; custodian: string | null }> {
  let stopped = false;
  const st = await commitState(run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop) {
      const m = cur.loop_start;
      if (m && m.status !== "abandoned") {
        m.status = "abandoned";
        m.detail = `${m.detail ? m.detail + "; " : ""}acknowledged by the operator${reason ? `: ${reason.slice(0, 200)}` : ""}`.slice(0, 500);
        stopped = true;
        pushEvent(cur, "loop.start_abandoned", `the operator acknowledged automation start ${m.request_id.slice(0, 8)}${reason ? `: ${reason.slice(0, 200)}` : ""}`, { loop_start: m.request_id });
      }
      return cur;
    }
    if (isEnded(loop.status)) return cur;
    const now = new Date().toISOString();
    loop.status = "cancelled";
    loop.ended = { status: "cancelled", reason: `operator: ${(reason ?? "no reason given").slice(0, 300)}`, at: now };
    stopped = true;
    pushEvent(cur, "loop.ended", `automation cancelled by the operator${reason ? `: ${reason.slice(0, 200)}` : ""}`, { loop_id: loop.loop_id });
    return cur;
  });
  const c = await operatorEndLoop(le, run, reason ?? "no reason given");
  const custodian = c.applied
    ? `the custodian cancelled the run's loop (${c.surface} surface)`
    : c.code === "INVALID_LOOP_TRANSITION" || c.reason.includes("holds no automation loop")
      ? `custodian: ${c.reason}`
      : `the custodian did NOT record the cancellation (${c.reason}); nothing continues locally, and the custodian refuses any automation past the loop's deadline`;
  if (!st.continuation) {
    if (c.applied) return { stopped: true, status: "cancelled", custodian };
    if (st.loop_start) return { stopped, status: `start_${st.loop_start.status}`, custodian };
    throw new DomainError("INVALID_ARGUMENT", `run ${run.runId} has no automation loop`);
  }
  return { stopped: stopped || c.applied, status: st.continuation.status, custodian };
}

/** Threads needing a user decision in one discussion view (a null source or check results: not compared). */
function decisionThreadsIn(st: StateRecord, sourceId: string | null): string[] {
  const { view } = reportDiscussion(st, sourceId, null, caseKey);
  return threadsNeedingUserDecision(threadReports(view.ix, view.plan, (x) => (respondable(x) ? responseToken(x, view.ix) : null)));
}

/**
 * A resume never ends a needed user decision, whatever pause it clears (P3.3b). This terminal does
 * not share the session's environment, and check freshness is bound to the deriving process's
 * environment, so whether new check evidence lets a disputed turn reach the reviewer — instead of
 * escalating to the user — can differ between this terminal and the session. A needed decision in
 * ANY view CodeParley can derive here refuses the resume:
 *  - the current source with check evidence not compared: check evidence can only ADD new
 *    information, so this view escalates whenever any environment's view does (an upper bound);
 *  - the view `code-parley decide` lists (no source, no check evidence);
 *  - this terminal's own full derivation.
 * Without a fresh, stable read of the working tree nothing is resumed.
 *
 * P3.4C-3 C1: the run has a custodian loop, so it is protected, and the need is derived from the same
 * authoritative user records as the protected Stop derivation — the custodian's, read on the OPERATOR surface (the
 * only pipe this account can reach); a decision in the user-writable store never satisfies it, and a custodian that
 * cannot be reached refuses the resume (fail closed).
 */
async function refuseWhileUserDecisionNeeded(le: Loaded, run: RunHandle, raw: StateRecord): Promise<void> {
  const st0 = await withAuthoritativeUserRecords(le, run, raw, { protected: true, asOperator: true });
  const src = await currentSource(le, run, st0, SOURCE_BUDGET_MS);
  const known = knownSourceOf(src);
  const fresh = freshSourceId(known);
  if (fresh === null) {
    throw new DomainError("SOURCE_UNAVAILABLE", `the working tree could not be read fresh and stable now (${src.note ?? "the read was not stable"}), so CodeParley cannot tell whether a thread needs a user decision. Nothing was resumed; try again when the worktree is free`, { retryable: true });
  }
  const { state: observed } = await observedState(le, st0);
  const report = await runReport(le, run, st0, src.source_id, known, observed);
  const route = routeFromEngine(routingFactsOf(st0, observed, report, new Date().toISOString()));
  const threads = [...new Set([...decisionThreadsIn(st0, fresh), ...decisionThreadsIn(st0, null)])];
  if (threads.length || report.completion.counts.needs_user_decision > 0 || route.pause === "user_decision_required") {
    const which = threads.length ? `thread(s) ${threads.slice(0, 5).join(", ")}${threads.length > 5 ? ", …" : ""}` : route.reason;
    throw new DomainError("INVALID_ARGUMENT", `a thread of this run still needs a user decision (${which}); record it with \`code-parley decide ${run.runId}\` first. Automation stays paused`);
  }
}

/**
 * Phase 5 F-i2-5 (option A, [[D-28]]): a run the operator names by its repository and id, confirmed with the custodian.
 * On Linux the operator is a separate account that cannot read the implementer's run store, so the run is never looked
 * up there: the custodian resolves the repository's identity itself and must hold this run (its loop or run record) for
 * that repository — a wrong repository, an unknown run id or an unprotected run is RUN_NOT_FOUND. Read on the operator
 * surface (operator-only authority unchanged); nothing is stored.
 */
export async function custodianRunOf(le: Loaded, repositoryRoot: string, runId: string): Promise<CustodianRunRef> {
  assertRunId(runId);
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  const listing = await new CustodianGrants(gate.transport).listUserRecords("operator", repositoryRoot, runId, ["loop", "run"]);
  if (listing.protected !== true) {
    throw new DomainError("RUN_NOT_FOUND", `the custodian holds no protected run ${runId} for the repository ${repositoryRoot} (a wrong repository or run id, or a run that was never protected)`);
  }
  return { runId, meta: { repository_root: repositoryRoot } };
}

/**
 * Phase 5 F-i2-5: the resume guard for a run named through the custodian (`loop resume <run> --repo`). This account
 * cannot read the working tree or the implementer's run store, so of the views refuseWhileUserDecisionNeeded derives it
 * has the one `code-parley decide` lists (no source, no check evidence) — over the custodian's held records, the same
 * ones its protected derivation reads. A needed decision there refuses the resume; the derivation at the session's next
 * step still pauses again for a need only a source read shows (ROUTE_NOT_IMPLEMENTER_STEP).
 */
export async function refuseWhileHeldDecisionNeeded(le: Loaded, run: CustodianRunRef): Promise<void> {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  const listing = await new CustodianGrants(gate.transport).listUserRecords("operator", run.meta.repository_root, run.runId, ["user", "snapshot"]);
  const threads = decisionThreadsIn(heldStateOfListing(listing, run.meta.repository_root, run.runId), null);
  if (threads.length) {
    throw new DomainError("INVALID_ARGUMENT", `a thread of this run still needs a user decision (thread(s) ${threads.slice(0, 5).join(", ")}${threads.length > 5 ? ", …" : ""}); record it with \`code-parley decide ${run.runId} --repo ${run.meta.repository_root}\` first. Automation stays paused`);
  }
}

/** What a resume accepts (contract §2.4 U1), as the CUSTODIAN holds it on the operator surface — after a recovery,
 * possibly restored budgets, and the decisions that lapsed. */
export interface ResumeOverview {
  /** The custodian's loop: its budgets as recorded (a rollback may have restored spent ones). */
  loop: { status: string; pause: string | null; used: { continuations: number; wakes: number }; limits: { continuations: number; wakesPerRun: number }; deadlineAt: string } | null;
  decisions: { id: string; kind: string; thread: string }[];
  lapsed: { id: string; kind: string; thread: string }[];
  amendments: number;
  /** The custodian recorded a recovery for this run's user records (a restart of the OS). */
  recovered: boolean;
  /** Why the custodian's records could not be shown (the resume will then be refused), or null. */
  unavailable: string | null;
}

export async function resumeOverview(le: Loaded, run: CustodianRunRef): Promise<ResumeOverview> {
  const empty: ResumeOverview = { loop: null, decisions: [], lapsed: [], amendments: 0, recovered: false, unavailable: null };
  try {
    const gate = protectedLoopGate(le.env.testHooks?.custodian);
    if (!gate.available) throw gate.error;
    const listing = await new CustodianGrants(gate.transport).listUserRecords("operator", run.meta.repository_root, run.runId, ["user", "loop"]);
    const a = fromListing(listing);
    const l = listing.loop?.record ?? null;
    const num = (v: unknown): number => (typeof v === "number" ? v : 0);
    const used = (l?.["used"] ?? {}) as Record<string, unknown>;
    const limits = (l?.["limits"] ?? {}) as Record<string, unknown>;
    const pause = l?.["pause"] as { reason?: unknown } | null | undefined;
    const view = (d: { decision_id: string; kind: string; thread_id: string }) => ({ id: d.decision_id, kind: d.kind, thread: d.thread_id });
    return {
      loop: l ? { status: String(l["status"] ?? ""), pause: typeof pause?.reason === "string" ? pause.reason : null, used: { continuations: num(used["continuations"]), wakes: num(used["wakes"]) }, limits: { continuations: num(limits["continuations"]), wakesPerRun: num(limits["wakesPerRun"]) }, deadlineAt: String(l["deadlineAt"] ?? "") } : null,
      decisions: a.decisions.map(view),
      lapsed: a.lapsed.map(view),
      amendments: a.amendments.length,
      recovered: listing.recoveredAtRevision !== null,
      unavailable: null,
    };
  } catch (e) {
    return { ...empty, unavailable: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Operator resume of a paused loop. It resumes only when no thread needs a user decision (the user
 * decides first, with `code-parley decide`), whatever the pause's reason. Budgets, deadline and
 * binding are unchanged: a resume never enlarges anything. P3.4C-2: the CUSTODIAN resumes its loop first —
 * a pause only the operator may clear (operator_action_required, user_decision_required) on the operator
 * surface only, with the elevated operator token; nothing is resumed locally unless the custodian did.
 */
export async function operatorResumeLoop(le: Loaded, run: RunHandle): Promise<{ status: string; detail: string }> {
  const st0 = await readState(run.paths);
  const loop0 = st0.continuation;
  if (!loop0) throw new DomainError("INVALID_ARGUMENT", `run ${run.runId} has no automation loop`);
  if (isEnded(loop0.status)) throw new DomainError("INVALID_ARGUMENT", `the loop is ${loop0.status}, not paused; nothing to resume`);
  if (Date.now() >= Date.parse(loop0.deadline_at)) throw new DomainError("INVALID_ARGUMENT", "the loop's automation window has ended; it cannot be resumed (a new run and grant are needed)");
  await refuseWhileUserDecisionNeeded(le, run, st0);
  // P3.4C-4 (D4-E): a protected run's configuration that lapsed after a restart of the OS is re-confirmed before the loop
  // resumes (loop resume offers it as its own authorization); until then the resume is refused.
  if (custodianEquipped(le)) {
    const lapsed = lapsedRecords(await operatorConfigSection(le, run.meta.repository_root));
    if (lapsed.repository) throw new DomainError("CONFIG_LAPSED", `the repository's protected configuration lapsed after a restart of the OS; re-confirm it first (code-parley config reconfirm --repo ${run.meta.repository_root}, or code-parley loop resume ${run.runId}); nothing was resumed`, { retryable: false });
  }
  // The guard judged revision st0.revision: a run that changed since is judged again, not resumed.
  if ((await readState(run.paths)).revision !== st0.revision) throw new DomainError("RUN_BUSY", "the run changed while the resume was being checked; nothing was resumed. Run the command again", { retryable: true });
  const c = await operatorResumeLoopAt(le, run);
  // The custodian already shows the loop active (an earlier resume whose local record did not follow): sync it.
  const alreadyActive = !c.applied && c.status === "active";
  if (!c.applied && !alreadyActive) {
    const hint = c.code === "CALLER_NOT_AUTHORIZED" ? " Resuming this pause needs the operator surface: run the command in an elevated terminal as the operator." : "";
    throw new DomainError(c.code === "CALLER_NOT_AUTHORIZED" ? "CALLER_NOT_AUTHORIZED" : c.code === "CUSTODIAN_UNAVAILABLE" ? "CUSTODIAN_UNAVAILABLE" : "INVALID_ARGUMENT", `the custodian did not resume the loop (${c.reason}); nothing was resumed.${hint}`);
  }
  let detail = "";
  const st = await commitState(run.paths, le.env.owner, (cur) => {
    const loop = cur.continuation;
    if (!loop || isEnded(loop.status)) return cur;
    const now = new Date().toISOString();
    detail = `resumed after ${loop.pause?.reason ?? "a pause"}${c.applied ? ` (the custodian resumed it on the ${c.surface} surface)` : " (the custodian's loop was already active)"}`;
    loop.status = "active";
    loop.pause = null;
    loop.resumed_at = now;
    pushEvent(cur, "loop.resumed", `automation resumed by the operator (${detail})`, { loop_id: loop.loop_id });
    return cur;
  });
  return { status: st.continuation!.status, detail };
}

// ---------------------------------------------------------------------------
// The operator's view of a loop
// ---------------------------------------------------------------------------

export interface LoopDetails {
  run_id: string;
  repository_root: string;
  view: LoopView;
  binding: { session_id: string; epoch: number; state: string; bound_at: string; rebound_at: string | null; closed_at: string | null; close_reason: string | null; process: { pid: number | null; verified: boolean; detail: string; alive: boolean | null } | null } | null;
  grant_id: string;
  /** P3.4C-0: the custodian's record of the consumption this loop started from (absent on older loops). */
  grant_use: { loop_id: string; loops_used: number; loops_total: number } | null;
  wakes: { operation_id: string; armed: number; consumed: string | null; rejected: string[]; superseded_at: string | null }[];
  interrupts: { at: string; via: string; detail: string }[];
  last_user_prompt_at: string | null;
  turn: { active: boolean; at: string };
  /**
   * P3.3b: set when check results look stale to THIS process only because its environment differs
   * from the one they ran in. The next action above is then derived for this terminal; the session's
   * own server and hooks derive theirs (get_review_status in the session shows it).
   */
  observer_environment: string | null;
  /** P3.4C-5 Increment 3 (§5.4): the custodian's derivation the next action comes from (null: the loop ended). */
  derivation: CustodianDerivation | null;
  /** P3.4C-5 Increment 4 (F-3-3): where the status and budgets shown come from — the custodian's own counters, the local
   * record (an unprotected run), or the local cache because the custodian could not be asked (not authoritative). */
  budgets_source: "custodian" | "local" | "local_cache_unverified";
}

export async function loopDetails(le: Loaded, run: RunHandle, alive: (pid: number) => boolean): Promise<LoopDetails | null> {
  const st = await readState(run.paths);
  const loop = st.continuation;
  if (!loop) return null;
  const { state: observed } = await observedState(le, st);
  const src = await currentSource(le, run, st, SOURCE_BUDGET_MS);
  const report = await runReport(le, run, st, src.source_id, knownSourceOf(src), observed);
  // P3.4C-5 Increment 3 (§5.4): the custodian's derivation decides a protected loop; this terminal's own is shown only
  // when the custodian serves none (labelled non-authoritative).
  const derived = isEnded(loop.status) ? null : await derivationForDisplay(le, run, true).catch(() => null);
  const route = isEnded(loop.status) ? null : derived?.available ? routeOfDerivation(derived) : routeFromEngine(routingFactsOf(st, observed, report, new Date().toISOString()));
  // P3.4C-5 Increment 4 (F-3-3): the status and budgets shown are the custodian's own counters (a display correction; the
  // local loop record is only a cache a request that bypasses this engine does not update).
  const held = await custodianLoopForDisplay(le, run).catch(() => undefined);
  const shown = held ? overlay(loop, held) : loop;
  const b = loop.binding;
  return {
    run_id: run.runId,
    repository_root: run.meta.repository_root,
    derivation: derived,
    budgets_source: held ? "custodian" : held === null ? "local" : "local_cache_unverified",
    view: loopView(run.runId, shown, route, Date.now()),
    binding: b
      ? { session_id: b.session_id, epoch: b.epoch, state: b.state, bound_at: b.bound_at, rebound_at: b.rebound_at, closed_at: b.closed_at, close_reason: b.close_reason, process: b.process ? { pid: b.process.pid, verified: b.process.verified, detail: b.process.detail, alive: b.process.pid !== null ? alive(b.process.pid) : null } : null }
      : null,
    grant_id: loop.grant_id,
    grant_use: loop.grant_use ? { loop_id: loop.grant_use.loop_id, loops_used: loop.grant_use.loops_used, loops_total: loop.grant_use.loops_total } : null,
    wakes: loop.wakes.map((w) => ({ operation_id: w.operation_id, armed: w.armed.length, consumed: w.consumed ? `${w.consumed.at} (${w.consumed.instance}, epoch ${w.consumed.epoch})` : null, rejected: w.rejected.map((r) => `${r.at} ${r.instance}: ${r.reason}`), superseded_at: w.superseded_at })),
    interrupts: loop.interrupts.map((i) => ({ at: i.at, via: i.via, detail: i.detail })),
    last_user_prompt_at: loop.last_user_prompt_at,
    turn: loop.turn,
    observer_environment: report.limitations.find((l) => l.code === OBSERVER_ENVIRONMENT_DIFFERS)?.detail ?? null,
  };
}
