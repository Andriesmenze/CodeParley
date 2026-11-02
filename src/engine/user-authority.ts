// The engine side of the local operator interface (Phase 2.3, plan §1.16): user decisions and
// task amendments.
//
// ONLY the interactive CLI (src/cli/user-commands.ts) calls the writers here; the MCP server has
// no import path to this module (test/layering.test.ts) and no tool for it (P2.3-1). The CLI checks
// that its stdin and stdout are terminals and that the operator typed the confirmation there; this
// module then writes the record with the provenance the engine sets — role user, channel local_cli,
// assurance local_operator — and nothing in any request can set or change it (P2.3-2). The writers
// themselves do not authenticate their caller: under the local trust model a same-user process that
// calls them can create such a record (adversarial evidence A6), as it can forge any store record.
//
// One record per call, in ONE commit, or nothing (P2.3-15):
//  1. the arguments are checked; a request_id replay returns the recorded record (same arguments),
//     or REQUEST_ID_CONFLICT;
//  2. a decision: the thread must be decidable, the token the CLI showed must still be the thread's
//     token (STALE_FINDING_STATE otherwise), and no review of the run may be running (RUN_BUSY);
//  3. text (a decision's note, an amendment's text) needs a complete, stable source read: its
//     withheld names and hashes are published as an immutable artifact before the commit that
//     references it (P2.3-14); without such a read the call is refused (SOURCE_UNAVAILABLE);
//  4. under the run's mutation lock everything is checked again against the CURRENT state, then
//     the record and one event are appended.
// Nothing else changes: no reviewer item, response, reply, operation or run state. Nothing starts.

import { rm } from "node:fs/promises";
import { join } from "node:path";
import { DomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import { TOOL_VERSION } from "../common/version.js";
import { CustodianOperator } from "../custodian/operator.js";
import { CustodianGrants } from "../custodian/grants.js";
import { protectedLoopGate, type CustodianTestHooks } from "../custodian/protected-loops.js";
import type { PreparedUserRecord, UserRecordCommit } from "../custodian/protocol.js";
import { withListedUserRecords } from "./protected-user-records.js";
import { heldStateOfListing } from "./protected-derivation.js";
import { assertRunId } from "./engine-env.js";
import { publishArtifactInRun } from "../store/artifacts.js";
import { commitState, readState } from "../store/state-store.js";
import type { LockDeps } from "../store/locks.js";
import { classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type Liveness, type OwnerRecord } from "../store/owner.js";
import type { RunPaths } from "../store/paths.js";
import { amendmentProblems, amendRequestDigest, isUserChannelRecord, type AmendmentInput } from "../policy/amendments.js";
import { discussionIndexOf, threadOfItem, threadReplies, threadTurns, type DiscussionIndex } from "../policy/discussion.js";
import { threadReport, type ThreadReport } from "../policy/discussion-reports.js";
import { currentReviewOf, normalizeFindingId, reportDiscussion, respondable, responseToken } from "../policy/responses.js";
import type { Thread } from "../policy/threads.js";
import { decideRequestDigest, decidability, decisionFactsOf, decisionProblems, decisionsOnThread, decisionStatus, decisionToken, openItemsOf, threadUserState, type Decidability, type DecisionFacts } from "../policy/user-decisions.js";
import { caseKey } from "../workspace/paths.js";
import type { StateRecord } from "../schemas/run-state.js";
import { USER_ASSURANCE, USER_CHANNEL, USER_LIMITS, USER_ROLE, type DecisionKind, type TaskAmendment, type UserDecision } from "../schemas/user-authority.js";
import type { SourceForResponse, WithheldOfRead } from "./respond.js";

const TERMINAL = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

/** The provenance of every user record: set here, from the channel, never from a request (P2.3-2). */
function userProvenance(): UserDecision["recorded_by"] {
  return { role: USER_ROLE, channel: USER_CHANNEL, assurance: USER_ASSURANCE, tool_version: TOOL_VERSION };
}

export interface UserChannelHooks {
  /** TEST ONLY: after the disclosure record is written, before the commit. */
  afterPublish?: () => Promise<void> | void;
  /** TEST ONLY: inside the commit, after every check passed, before the state is written. */
  beforeWrite?: () => void;
  /** TEST ONLY: after the commit, before the result is built. */
  afterCommit?: () => Promise<void> | void;
}

export interface UserChannelContext {
  runId: string;
  runPaths: RunPaths;
  owner: OwnerRecord;
  /** The working tree's source identity now; called only when the record carries text. */
  currentSource(): Promise<SourceForResponse>;
  lockDeps?: LockDeps;
  /** Liveness of a running review's server (default: the process table). */
  classify?: (owner: OwnerRecord) => Promise<Liveness>;
  testHooks?: UserChannelHooks;
}

// ---------------------------------------------------------------------------
// Resolving references (the CLI accepts unique prefixes)
// ---------------------------------------------------------------------------

/** The run's reviewer item named by an id or a unique prefix of at least 8 characters. */
export function resolveItemRef(st: StateRecord, ref: string): string {
  const r = normalizeFindingId(ref);
  if (st.findings.some((f) => f.id === r)) return r;
  if (r.length < 8) throw new DomainError("FINDING_NOT_FOUND", `${ref.slice(0, 64)}: give a thread or item id, or a unique prefix of at least 8 characters`);
  const hits = st.findings.filter((f) => f.id.startsWith(r));
  if (hits.length === 1) return hits[0]!.id;
  if (hits.length > 1) throw new DomainError("INVALID_ARGUMENT", `${ref} matches ${hits.length} items; give more characters (${hits.slice(0, 5).map((h) => h.id).join(", ")})`);
  throw new DomainError("FINDING_NOT_FOUND", `${ref.slice(0, 64)} is not a reviewer item or thread of this run (engine conditions and isolation incidents cannot be decided)`);
}

/** The run's amendment named by an id, a unique prefix (8+) or its label A-<seq>. */
export function resolveAmendmentRef(st: StateRecord, ref: string): string {
  const r = ref.trim().toLowerCase();
  const bySeq = /^a-(\d{1,4})$/.exec(r);
  // Only the user channel's records have a label (a record with another provenance is not an amendment).
  const all = st.task_amendments.filter(isUserChannelRecord);
  if (bySeq) {
    const a = all.find((x) => x.seq === Number(bySeq[1]));
    if (a) return a.amendment_id;
  }
  const exact = all.find((x) => x.amendment_id === r);
  if (exact) return exact.amendment_id;
  const hits = r.length >= 8 ? all.filter((x) => x.amendment_id.startsWith(r)) : [];
  if (hits.length === 1) return hits[0]!.amendment_id;
  throw new DomainError("INVALID_ARGUMENT", `${ref.slice(0, 64)} names no amendment of this run (use its label such as A-1, an id or a unique prefix)`);
}

// ---------------------------------------------------------------------------
// Views (what the CLI shows before the user decides; also the listing)
// ---------------------------------------------------------------------------

export interface ThreadDecisionView {
  run_id: string;
  thread_id: string;
  /** The item the user named (its thread is the subject). */
  named_item_id: string;
  report: ThreadReport;
  /** The thread's items with their reviewer text (titles) and lifecycle. */
  items: { id: string; kind: string; status: string; round: number; triage: string; severity: string | null; category: string | null; title: string; last_assessment: string | null }[];
  /** The open items a decision now would cover. */
  covered_items: string[];
  current_item_id: string | null;
  decidable: Decidability;
  /** Every user decision on the thread, oldest first, with its status now. */
  decisions: { decision_id: string; kind: string; status: string; reasons: string[]; recorded_at: string; note: string }[];
  /** The user's amendment revision the view was built against. */
  amendments_seq: number;
  /** The decision token of this exact state (P2.3-5). */
  token: string;
}

interface ThreadContext {
  ix: DiscussionIndex;
  facts: DecisionFacts;
  thread: Thread;
  report: ThreadReport;
}

function threadContext(st: StateRecord, itemId: string): ThreadContext {
  const { view } = reportDiscussion(st, null, null, caseKey);
  const ix = view.ix;
  const it = ix.itemById.get(itemId);
  if (!it) throw new DomainError("FINDING_NOT_FOUND", `${itemId} is not a reviewer item of this run`);
  const thread = threadOfItem(ix, it);
  const facts = decisionFactsOf(ix);
  const report = threadReport(ix, view.plan, thread, (x) => (respondable(x) ? responseToken(x, ix) : null), undefined, facts);
  return { ix, facts, thread, report };
}

export function threadDecisionView(st: StateRecord, itemId: string): ThreadDecisionView {
  const c = threadContext(st, itemId);
  const open = openItemsOf(c.thread);
  return {
    run_id: st.run_id,
    thread_id: c.thread.id,
    named_item_id: itemId,
    report: c.report,
    items: c.thread.members.map((m) => ({ id: m.id, kind: m.item_kind, status: m.status, round: m.round, triage: m.triage, severity: m.severity, category: m.category, title: m.title, last_assessment: m.assessments.at(-1)?.assessment ?? null })),
    covered_items: open.map((m) => m.id),
    current_item_id: open.at(-1)?.id ?? null,
    decidable: decidability(c.thread),
    decisions: decisionsOnThread(c.facts, c.thread).map((d) => {
      const s = decisionStatus(c.ix, c.facts, d);
      return { decision_id: d.decision_id, kind: d.kind, status: s.status, reasons: s.reasons, recorded_at: d.recorded_at, note: d.note };
    }),
    amendments_seq: c.ix.amendments.seq,
    token: decisionToken(c.ix, c.facts, c.thread, c.ix.amendments.seq),
  };
}

/** Every thread with an open item, with its three layers (the CLI's `decide <run>` listing). */
export function decidableThreads(st: StateRecord): ThreadReport[] {
  const { view } = reportDiscussion(st, null, null, caseKey);
  const ix = view.ix;
  const facts = decisionFactsOf(ix);
  return [...ix.threads.threads.values()].filter((t) => openItemsOf(t).length > 0).map((t) => threadReport(ix, view.plan, t, (x) => (respondable(x) ? responseToken(x, ix) : null), undefined, facts));
}

// ---------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------

function refuseTerminal(st: StateRecord): void {
  if (TERMINAL.has(st.state)) throw new DomainError("RUN_TERMINAL", `run is ${st.state}; its records are read-only`);
}

async function deadReviewOperations(st: StateRecord, classify: (owner: OwnerRecord) => Promise<Liveness>): Promise<Set<string>> {
  const dead = new Set<string>();
  for (const op of st.operations) {
    if (op.kind !== "review" || op.status !== "running") continue;
    if (!op.owner || (await classify(op.owner).catch((): Liveness => "alive_unconfirmed")) === "dead") dead.add(op.operation_id);
  }
  return dead;
}

/** Decisions are made between reviews: a running review is about to change the thread (P2.3-5). */
function refuseActiveReview(st: StateRecord, dead: ReadonlySet<string>): void {
  const active = st.operations.find((o) => o.kind === "review" && o.status === "running" && !dead.has(o.operation_id));
  if (!active) return;
  throw new DomainError("RUN_BUSY", `a review of this run is running (operation ${active.operation_id}); decide when it has finished, against its result. Nothing was recorded`, { retryable: true, details: { operation_id: active.operation_id } });
}

/** The text of a record needs a complete, stable read of the working tree (P2.3-14). */
async function sourceForText(ctx: UserChannelContext): Promise<{ source_id: string; withheld: WithheldOfRead }> {
  const s = await ctx.currentSource().catch((e: unknown): SourceForResponse => ({ source_id: null, note: (e instanceof Error ? e.message : String(e)).slice(0, 160) }));
  if (s.source_id === null || s.withheld === undefined) {
    throw new DomainError("SOURCE_UNAVAILABLE", `your text can be recorded only together with a complete read of the working tree, which checks it for confidential names, and that read did not succeed now (${s.note ?? "unknown reason"}). Nothing was recorded; try again when the worktree is free`, { retryable: true });
  }
  return { source_id: s.source_id, withheld: s.withheld };
}

/** The disclosure record of a read's withheld set (`arl.response-disclosure.v1`, P2.1-15's format), or null when it withheld nothing. */
function disclosureOf(w: WithheldOfRead): string | null {
  const repoContext = [...(w.repoContext ?? [])].map((r) => ({ path: r.path, hashes: [...r.hashes].sort() })).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (w.paths.length === 0 && w.hashes.length === 0 && repoContext.length === 0) return null;
  return JSON.stringify({ schema: "arl.response-disclosure.v1", withheld_paths: [...w.paths].sort(), withheld_hashes: [...w.hashes].sort(), repo_context: repoContext }, null, 2);
}

/** Remove a disclosure record no commit came to reference (only once the state confirms it). */
async function removeUnreferenced(paths: RunPaths, recordId: string, ref: string): Promise<void> {
  const st = await readState(paths).catch(() => null);
  if (!st || st.user_decisions.some((d) => d.disclosure_ref === ref) || st.task_amendments.some((a) => a.disclosure_ref === ref)) return;
  await rm(join(paths.opsDir, recordId), { recursive: true, force: true }).catch(() => undefined);
}

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor: "user_cli", summary: summary.slice(0, 500), refs });
}

class ReplayFound extends Error {
  constructor(readonly id: string) {
    super("replay");
  }
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

export interface DecideRequest {
  /** The reviewer item the user named (resolved by resolveItemRef); its thread is decided. */
  item_id: string;
  kind: DecisionKind;
  note: string;
  /** The token of the state the CLI showed (threadDecisionView). */
  token: string;
  request_id?: string | undefined;
}

export interface DecideResult {
  decision: UserDecision;
  deduplicated: boolean;
}

/**
 * The decision this request id recorded, if the request repeats it: the same kind and note on the
 * same thread, named through any of the thread's items (P2.3-5: decisions are per thread, and the
 * CLI accepts any of its items). The same id for anything else is REQUEST_ID_CONFLICT.
 */
function decisionReplay(st: StateRecord, runId: string, req: Pick<DecideRequest, "item_id" | "kind" | "note" | "request_id">): UserDecision | null {
  if (req.request_id === undefined) return null;
  const prior = st.user_decisions.find((d) => d.request_id === req.request_id && isUserChannelRecord(d));
  if (!prior) return null;
  if (prior.request_digest === decideRequestDigest(runId, req.item_id, req.kind, req.note)) return prior;
  if (prior.kind === req.kind && prior.note === req.note && onThreadOf(st, prior, req.item_id)) return prior;
  throw new DomainError("REQUEST_ID_CONFLICT", `request id ${req.request_id} was already used for another decision`, { details: { decision_id: prior.decision_id } });
}

/** Does the item lie in the thread that holds the decision's covered items (or its recorded thread)? */
function onThreadOf(st: StateRecord, d: UserDecision, itemId: string): boolean {
  const ix = discussionIndexOf(st);
  const it = ix.itemById.get(itemId);
  if (!it) return false;
  const members = new Set(threadOfItem(ix, it).members.map((m) => m.id));
  return members.has(d.thread_id) || d.covered_items.some((id) => members.has(id));
}

/**
 * The decision this request id already recorded (a replay of the same request), or null; the same
 * id with other arguments is REQUEST_ID_CONFLICT. A replay records nothing, so the operator
 * interface answers it before requiring a terminal or a thread that can still be decided (P2.3-15).
 */
export function replayedDecision(st: StateRecord, runId: string, req: Pick<DecideRequest, "item_id" | "kind" | "note" | "request_id">): UserDecision | null {
  return decisionReplay(st, runId, req);
}

/** Every check a decision needs against one state (repeated inside the commit). */
function checkDecision(st: StateRecord, req: DecideRequest): ThreadContext {
  refuseTerminal(st);
  if (!st.findings.some((f) => f.id === req.item_id)) throw new DomainError("FINDING_NOT_FOUND", `${req.item_id} is not a reviewer item of this run`);
  const c = threadContext(st, req.item_id);
  const d = decidability(c.thread);
  if (!d.ok) throw new DomainError("FINDING_NOT_RESPONDABLE", `this thread cannot be decided: ${d.reason}. Nothing was recorded`);
  if (decisionToken(c.ix, c.facts, c.thread, c.ix.amendments.seq) !== req.token) {
    throw new DomainError("STALE_FINDING_STATE", "the thread changed since it was shown to you (a review, a response, a reply, another decision or an amendment); nothing was recorded. Run the command again to see the current state and decide anew");
  }
  const u = threadUserState(c.ix, c.facts, c.thread);
  if (req.kind === "revoke" && (u.live.length === 0 || u.state?.status === "revoked")) throw new DomainError("INVALID_ARGUMENT", "there is no decision of yours on this thread to revoke");
  if (st.user_decisions.length + 1 > USER_LIMITS.decisionsPerRun) throw new DomainError("BUDGET_EXHAUSTED", `a run keeps at most ${USER_LIMITS.decisionsPerRun} user decisions`);
  if (u.earlier + (u.decision ? 1 : 0) + 1 > USER_LIMITS.decisionsPerThread) throw new DomainError("BUDGET_EXHAUSTED", `a thread keeps at most ${USER_LIMITS.decisionsPerThread} user decisions`);
  return c;
}

/** The state a decision was made against: its token, the run's current review and the thread's latest turns. */
function decidedAgainst(c: ThreadContext, token: string): UserDecision["decided_against"] {
  const run = currentReviewOf(c.ix);
  return {
    token,
    run_review_id: run?.review_id ?? null,
    run_round: run?.round ?? null,
    latest_reply_id: threadReplies(c.ix, c.thread).at(-1)?.reply_id ?? null,
    latest_response_id: threadTurns(c.ix, c.thread).at(-1)?.response_id ?? null,
    amendments_seq: c.ix.amendments.seq,
  };
}

/**
 * The decision record, built inside the commit against the state checked there: it covers the
 * thread's open items now, supersedes its live decisions, and keeps what the user was shown.
 */
function decisionRecord(c: ThreadContext, req: DecideRequest, ids: Pick<UserDecision, "decision_id" | "request_digest" | "source" | "disclosure_ref">): UserDecision {
  const open = openItemsOf(c.thread);
  return {
    decision_id: ids.decision_id,
    thread_id: c.thread.id,
    current_item_id: open.at(-1)!.id,
    covered_items: open.map((m) => m.id),
    kind: req.kind,
    note: req.note,
    decided_against: decidedAgainst(c, req.token),
    context: {
      awaiting: c.report.awaiting,
      escalation_reasons: c.report.escalation.reasons,
      reviewer_stance: c.report.latest_reviewer?.stance ?? null,
      implementer_position: c.report.latest_implementer?.position ?? null,
    },
    supersedes: threadUserState(c.ix, c.facts, c.thread).live,
    source: ids.source,
    disclosure_ref: ids.disclosure_ref,
    recorded_by: userProvenance(),
    request_id: req.request_id ?? null,
    request_digest: ids.request_digest,
    recorded_at: new Date().toISOString(),
  };
}

export async function recordUserDecision(ctx: UserChannelContext, req: DecideRequest): Promise<DecideResult> {
  const problems = decisionProblems(req.kind, req.note);
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) problems.push("the request id has 1 to 128 characters");
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", problems.join("; "));
  const digest = decideRequestDigest(ctx.runId, req.item_id, req.kind, req.note);
  const st0 = await readState(ctx.runPaths);
  const replay0 = decisionReplay(st0, ctx.runId, req);
  if (replay0) return { decision: replay0, deduplicated: true };
  const dead = await deadReviewOperations(st0, ctx.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)));
  refuseActiveReview(st0, dead);
  checkDecision(st0, req);

  const decisionId = uuidv7();
  const text = req.note.trim() !== "";
  const read = text ? await sourceForText(ctx) : null;
  const disclosure = read ? disclosureOf(read.withheld) : null;
  const disclosureRef = disclosure ? (await publishArtifactInRun(ctx.runPaths.runDir, ctx.runPaths.opsDir, decisionId, "user/disclosure.json", disclosure)).ref : null;
  await ctx.testHooks?.afterPublish?.();
  let recorded: UserDecision | null = null;
  try {
    await commitState(ctx.runPaths, ctx.owner, (cur) => {
      const replay = decisionReplay(cur, ctx.runId, req);
      if (replay) throw new ReplayFound(replay.decision_id);
      refuseActiveReview(cur, dead);
      const c = checkDecision(cur, req);
      const d = decisionRecord(c, req, { decision_id: decisionId, request_digest: digest, source: read ? { source_id: read.source_id, note: null } : null, disclosure_ref: disclosureRef });
      recorded = d;
      cur.user_decisions.push(d);
      pushEvent(cur, "user.decision_recorded", `the user decided ${req.kind} on thread ${c.thread.id.slice(0, 8)} (${d.covered_items.length} open item(s))`, { decision_id: decisionId, thread_id: c.thread.id });
      ctx.testHooks?.beforeWrite?.();
      return cur;
    }, ctx.lockDeps ? { lockDeps: ctx.lockDeps } : {});
  } catch (e) {
    if (disclosureRef) await removeUnreferenced(ctx.runPaths, decisionId, disclosureRef);
    if (e instanceof ReplayFound) {
      const st = await readState(ctx.runPaths);
      return { decision: st.user_decisions.find((d) => d.decision_id === e.id)!, deduplicated: true };
    }
    throw e;
  }
  await ctx.testHooks?.afterCommit?.();
  return { decision: recorded!, deduplicated: false };
}

// ---------------------------------------------------------------------------
// Protected records (P3.4C-1): the Windows custodian is the authoritative store
// ---------------------------------------------------------------------------

/** The custodian surfaces an operator-channel protected write uses: the authority-creating WRITE
 * (CustodianOperator, CLI-only) and the READ of the current per-run log revision (CustodianGrants). */
export interface ProtectedCustodian {
  operator: CustodianOperator;
  grants: CustodianGrants;
}

/** The custodian behind the protected-loop gate, for a protected operator write (no custodian: refused,
 * exactly as a grant is). Built here, in the CLI-only engine module, so the CLI needs no custodian import. */
export function protectedCustodianFor(hooks?: CustodianTestHooks): ProtectedCustodian {
  const gate = protectedLoopGate(hooks);
  if (!gate.available) throw gate.error;
  return { operator: new CustodianOperator(gate.transport), grants: new CustodianGrants(gate.transport) };
}

/** Set the run's local governed hint so the ATTENDED read path reads the custodian for this run too.
 * Not a security boundary (user-writable; plan §3.5); the protected controller path never consults it. */
async function markRunGoverned(ctx: UserChannelContext): Promise<void> {
  await commitState(
    ctx.runPaths,
    ctx.owner,
    (cur) => {
      cur.user_records_custodian = true;
      return cur;
    },
    ctx.lockDeps ? { lockDeps: ctx.lockDeps } : {},
  );
}

/**
 * Record a user decision as PROTECTED authority (`decide --protected`): the Windows custodian owns the
 * record (operator surface), not the TS state. The engine validates the thread lifecycle exactly as the
 * attended path does and builds the structural payload plus the raw note; the custodian is driven
 * prepare → (the operator confirms the rendering, via `confirm`) → commit, assigns the ordering and the
 * provenance, and rechecks its own per-run log revision. The note is NEVER sent to Codex and the
 * implementer projection drops it, so a decision needs no disclosure artifact (plan §13). On commit the
 * run's local governed hint is set (plan §3.5). The engine keeps NO authoritative copy in `state.json`.
 *
 * The thread-state the decision summarizes is validated at prepare time only (advisory until P3.4C-3,
 * plan §5/§8): the custodian does not yet own run identity or run-state freshness.
 */
export async function recordUserDecisionProtected(
  ctx: UserChannelContext,
  cust: ProtectedCustodian,
  repositoryRoot: string,
  req: DecideRequest,
  confirm: (prepared: PreparedUserRecord) => Promise<boolean>,
): Promise<{ recorded: UserRecordCommit } | { cancelled: true }> {
  const problems = decisionProblems(req.kind, req.note);
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) problems.push("the request id has 1 to 128 characters");
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", problems.join("; "));
  const digest = decideRequestDigest(ctx.runId, req.item_id, req.kind, req.note);
  const raw = await readState(ctx.runPaths);
  // Validate the new decision against the AUTHORITATIVE custodian records (decidability, token, supersedes),
  // from the SAME snapshot whose revision the prepare binds. A never-governed run's custodian log is empty,
  // so this equals the raw state — the first protected decision validates exactly as the legacy path does.
  // The OPERATOR validates against its OWN surface: the operator pipe, which only an OS-authorized operator
  // can reach (the caller classification is authoritative; a request-supplied surface name grants nothing).
  // The implementer pipe is not the operator's to read; the controller/Stop-hook derivation keeps it (D-C').
  const listing = await cust.grants.listUserRecords("operator", repositoryRoot, ctx.runId);
  const st = withListedUserRecords(raw, listing);
  const dead = await deadReviewOperations(st, ctx.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)));
  refuseActiveReview(st, dead);
  const c = checkDecision(st, req);
  const read = req.note.trim() !== "" ? await sourceForText(ctx) : null;
  const payload = protectedDecisionPayload(c, req, digest, read ? { source_id: read.source_id } : null);
  const prepared = await cust.operator.prepareUserRecord(repositoryRoot, ctx.runId, "decision", payload, listing.revision, req.request_id ?? uuidv7());
  if (!(await confirm(prepared))) return { cancelled: true };
  const recorded = await cust.operator.commitUserRecord(prepared.authorizationRequestId);
  await markRunGoverned(ctx);
  return { recorded };
}

/** The structural payload of a protected decision (plus the raw note, operator surface only), built against `c`. */
function protectedDecisionPayload(c: ThreadContext, req: DecideRequest, digest: string, source: { source_id: string } | null): Record<string, unknown> {
  const open = openItemsOf(c.thread);
  return {
    kind: req.kind,
    note: req.note,
    thread_id: c.thread.id,
    current_item_id: open.at(-1)!.id,
    covered_items: open.map((m) => m.id),
    decided_against: decidedAgainst(c, req.token),
    context: {
      awaiting: c.report.awaiting,
      escalation_reasons: c.report.escalation.reasons,
      reviewer_stance: c.report.latest_reviewer?.stance ?? null,
      implementer_position: c.report.latest_implementer?.position ?? null,
    },
    supersedes: threadUserState(c.ix, c.facts, c.thread).live,
    source,
    request_digest: digest,
  };
}

// ---------------------------------------------------------------------------
// Phase 5 F-i2-5 (option A, [[D-28]]): a protected run as the CUSTODIAN holds it
// ---------------------------------------------------------------------------

/** A protected run's structure as the custodian holds it, read on the operator surface: the state the protected
 * derivation reads (texts empty — never held there) and the user-record log revision a prepare binds. */
export interface HeldRun {
  runId: string;
  repositoryRoot: string;
  state: StateRecord;
  revision: number;
}

/**
 * Read a protected run from the custodian alone (`decide|amend <run> --repo <path>`): on a host where the operator account
 * cannot read the implementer's run store (Linux, D5-B), the decision is built over the custodian's held records — the
 * same records, in the same projection, its protected derivation later evaluates the decision against — so the token,
 * the covered items and the supersessions agree with what governs the run. One read (one hold of the custodian's lock):
 * the user log revision and the snapshot belong together. RUN_NOT_FOUND when the custodian holds no run record.
 */
export async function heldRunOf(cust: ProtectedCustodian, repositoryRoot: string, runId: string): Promise<HeldRun> {
  assertRunId(runId);
  const listing = await cust.grants.listUserRecords("operator", repositoryRoot, runId, ["user", "snapshot"]);
  return { runId, repositoryRoot, state: heldStateOfListing(listing, repositoryRoot, runId), revision: listing.revision };
}

/**
 * Record a protected decision over the custodian-held run (see heldRunOf). The engine's checks are the attended
 * protected path's (decidability, token, budgets) over the held state; the custodian then re-validates it against its
 * own run record at prepare and in the commit's hold (ValidateProtectedDecision), and the operator confirms the
 * custodian's rendering. A review the custodian holds as running refuses (RUN_BUSY): its owner is the custodian's to
 * judge, not this account's. The note is recorded without a source read (this account cannot read the working tree; a
 * decision note is never presented to Codex). Nothing is written to the implementer's run store.
 */
export async function recordUserDecisionHeld(
  cust: ProtectedCustodian,
  held: HeldRun,
  req: DecideRequest,
  confirm: (prepared: PreparedUserRecord) => Promise<boolean>,
): Promise<{ recorded: UserRecordCommit } | { cancelled: true }> {
  const problems = decisionProblems(req.kind, req.note);
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) problems.push("the request id has 1 to 128 characters");
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", problems.join("; "));
  refuseActiveReview(held.state, new Set());
  const c = checkDecision(held.state, req);
  const payload = protectedDecisionPayload(c, req, decideRequestDigest(held.runId, req.item_id, req.kind, req.note), null);
  const prepared = await cust.operator.prepareUserRecord(held.repositoryRoot, held.runId, "decision", payload, held.revision, req.request_id ?? uuidv7());
  if (!(await confirm(prepared))) return { cancelled: true };
  return { recorded: await cust.operator.commitUserRecord(prepared.authorizationRequestId) };
}

// ---------------------------------------------------------------------------
// Amendments
// ---------------------------------------------------------------------------

export interface AmendRequest extends AmendmentInput {
  request_id?: string | undefined;
}

/**
 * Record a task amendment as PROTECTED authority (`amend --protected`): the Windows custodian stores the
 * COMPLETE raw text (operator surface only), plus the structural fields, a non-reversible content-
 * equivalence key, the original byte length, and — bound into the record — the digest of the
 * operator-confirmed reviewer-visible disclosure artifact the caller already published engine-side
 * (constrained Option A). The engine and the implementer projection never receive the raw text from the
 * custodian; a review presents only the digest-validated redacted artifact. Validates (duplicate/ordering/
 * budget) against the authoritative custodian records from the same snapshot whose revision it binds.
 */
export async function recordAmendmentProtected(
  ctx: UserChannelContext,
  cust: ProtectedCustodian,
  repositoryRoot: string,
  req: AmendRequest,
  disclosure: { digest: string; source_id: string | null },
  confirm: (prepared: PreparedUserRecord) => Promise<boolean>,
): Promise<{ recorded: UserRecordCommit } | { cancelled: true }> {
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) throw new DomainError("INVALID_ARGUMENT", "the request id has 1 to 128 characters");
  const relates = [...new Set(req.relates_to)];
  const input: AmendRequest = { ...req, relates_to: relates };
  const digest = amendRequestDigest(ctx.runId, input);
  const raw = await readState(ctx.runPaths);
  // The operator validates against its OWN surface (the operator pipe; see recordUserDecisionProtected). The
  // implementer pipe is not the operator's to read, and the protected derivation keeps the implementer surface.
  const listing = await cust.grants.listUserRecords("operator", repositoryRoot, ctx.runId);
  const st = withListedUserRecords(raw, listing);
  checkAmendment(st, input);
  const hasText = input.text.trim() !== "";
  // P3.4C-1 confidentiality correction: the custodian DERIVES the content-equivalence key (a keyed HMAC)
  // and the byte length from the authoritative text; the engine supplies neither (and the custodian rejects
  // them if it did). Only the operator-confirmed redacted-artifact digest is engine-supplied.
  const payload: Record<string, unknown> = {
    kind: input.kind,
    text: input.text,
    relates_to: relates,
    replaces: input.replaces,
    source: disclosure.source_id ? { source_id: disclosure.source_id } : null,
    request_digest: digest,
    ...(hasText ? { disclosure_digest: disclosure.digest } : {}),
  };
  const prepared = await cust.operator.prepareUserRecord(repositoryRoot, ctx.runId, "amendment", payload, listing.revision, req.request_id ?? uuidv7());
  if (!(await confirm(prepared))) return { cancelled: true };
  const recorded = await cust.operator.commitUserRecord(prepared.authorizationRequestId);
  await markRunGoverned(ctx);
  return { recorded };
}

/**
 * Phase 5 F-i2-5: record a protected amendment over the custodian-held run (see heldRunOf). The engine's checks are the
 * protected path's (budgets, threads, replacement) over the held state; the CUSTODIAN produces the reviewer-visible
 * redaction (its helper over its own fresh read: this account cannot read the working tree) and holds it with the
 * record, and the operator confirms the custodian's rendering, which shows exactly that representation. Nothing is
 * written to the implementer's run store.
 */
export async function recordAmendmentHeld(
  cust: ProtectedCustodian,
  held: HeldRun,
  req: AmendRequest,
  confirm: (prepared: PreparedUserRecord) => Promise<boolean>,
): Promise<{ recorded: UserRecordCommit } | { cancelled: true }> {
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) throw new DomainError("INVALID_ARGUMENT", "the request id has 1 to 128 characters");
  const relates = [...new Set(req.relates_to)];
  const input: AmendRequest = { ...req, relates_to: relates };
  checkAmendment(held.state, input);
  const payload: Record<string, unknown> = {
    kind: input.kind,
    text: input.text,
    relates_to: relates,
    replaces: input.replaces,
    request_digest: amendRequestDigest(held.runId, input),
    custodian_redaction: true,
  };
  const prepared = await cust.operator.prepareUserRecord(held.repositoryRoot, held.runId, "amendment", payload, held.revision, req.request_id ?? uuidv7());
  if (!(await confirm(prepared))) return { cancelled: true };
  return { recorded: await cust.operator.commitUserRecord(prepared.authorizationRequestId) };
}

export interface AmendResult {
  amendment: TaskAmendment;
  deduplicated: boolean;
}

/**
 * The amendment this request id recorded, if the request repeats it: the same kind, text and
 * replacement, naming the same threads as they are now (a review may since have consolidated a
 * thread under another root). The same id for anything else is REQUEST_ID_CONFLICT.
 */
function amendmentReplay(st: StateRecord, runId: string, req: AmendRequest): TaskAmendment | null {
  if (req.request_id === undefined) return null;
  const prior = st.task_amendments.find((a) => a.request_id === req.request_id && isUserChannelRecord(a));
  if (!prior) return null;
  const relates = [...new Set(req.relates_to)];
  if (prior.request_digest === amendRequestDigest(runId, { ...req, relates_to: relates })) return prior;
  if (prior.kind === req.kind && prior.text === req.text && prior.replaces === req.replaces && sameThreadsNow(st, prior.relates_to, relates)) return prior;
  throw new DomainError("REQUEST_ID_CONFLICT", `request id ${req.request_id} was already used for another amendment`, { details: { amendment_id: prior.amendment_id } });
}

/** Do two lists of thread references name the same threads as the lineage stands now? */
function sameThreadsNow(st: StateRecord, a: readonly string[], b: readonly string[]): boolean {
  const ix = discussionIndexOf(st);
  const threadsOf = (ids: readonly string[]) =>
    new Set(
      ids.map((id) => {
        const it = ix.itemById.get(id);
        return it ? threadOfItem(ix, it).id : id;
      }),
    );
  const x = threadsOf(a);
  const y = threadsOf(b);
  return x.size === y.size && [...x].every((t) => y.has(t));
}

/** The amendment this request id already recorded (a replay), or null; another use of the id is REQUEST_ID_CONFLICT. */
export function replayedAmendment(st: StateRecord, runId: string, req: AmendRequest): TaskAmendment | null {
  return amendmentReplay(st, runId, req);
}

/** Every check an amendment needs against one state (repeated inside the commit). */
function checkAmendment(st: StateRecord, req: AmendRequest): void {
  refuseTerminal(st);
  if (st.task_amendments.length + 1 > USER_LIMITS.amendmentsPerRun) throw new DomainError("BUDGET_EXHAUSTED", `a run keeps at most ${USER_LIMITS.amendmentsPerRun} task amendments. Nothing was recorded`);
  for (const t of req.relates_to) if (!st.findings.some((f) => f.id === t)) throw new DomainError("FINDING_NOT_FOUND", `${t} is not a thread of this run`);
  const ix = discussionIndexOf(st);
  const threadOf = (id: string) => {
    const it = ix.itemById.get(id);
    return it ? threadOfItem(ix, it).id : id;
  };
  const problems = amendmentProblems(req, ix.amendments, threadOf);
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", `${problems.join("; ")}. Nothing was recorded`);
}

export async function recordAmendment(ctx: UserChannelContext, req: AmendRequest): Promise<AmendResult> {
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) throw new DomainError("INVALID_ARGUMENT", "the request id has 1 to 128 characters");
  const relates = [...new Set(req.relates_to)];
  const input: AmendRequest = { ...req, relates_to: relates };
  const digest = amendRequestDigest(ctx.runId, input);
  const st0 = await readState(ctx.runPaths);
  const replay0 = amendmentReplay(st0, ctx.runId, input);
  if (replay0) return { amendment: replay0, deduplicated: true };
  checkAmendment(st0, input);

  const amendmentId = uuidv7();
  const read = input.text.trim() !== "" ? await sourceForText(ctx) : null;
  const disclosure = read ? disclosureOf(read.withheld) : null;
  const disclosureRef = disclosure ? (await publishArtifactInRun(ctx.runPaths.runDir, ctx.runPaths.opsDir, amendmentId, "user/disclosure.json", disclosure)).ref : null;
  await ctx.testHooks?.afterPublish?.();
  let recorded: TaskAmendment | null = null;
  try {
    await commitState(ctx.runPaths, ctx.owner, (cur) => {
      const replay = amendmentReplay(cur, ctx.runId, input);
      if (replay) throw new ReplayFound(replay.amendment_id);
      checkAmendment(cur, input);
      const seq = discussionIndexOf(cur).amendments.seq + 1;
      recorded = {
        amendment_id: amendmentId,
        seq,
        kind: input.kind,
        text: input.text,
        relates_to: relates,
        replaces: input.replaces,
        source: read ? { source_id: read.source_id, note: null } : null,
        disclosure_ref: disclosureRef,
        recorded_by: userProvenance(),
        request_id: req.request_id ?? null,
        request_digest: digest,
        recorded_at: new Date().toISOString(),
      };
      cur.task_amendments.push(recorded);
      pushEvent(cur, "user.amendment_recorded", `the user recorded task amendment A-${seq} (${input.kind}${input.replaces ? `, replacing ${input.replaces.slice(0, 8)}` : ""})`, { amendment_id: amendmentId });
      ctx.testHooks?.beforeWrite?.();
      return cur;
    }, ctx.lockDeps ? { lockDeps: ctx.lockDeps } : {});
  } catch (e) {
    if (disclosureRef) await removeUnreferenced(ctx.runPaths, amendmentId, disclosureRef);
    if (e instanceof ReplayFound) {
      const st = await readState(ctx.runPaths);
      return { amendment: st.task_amendments.find((a) => a.amendment_id === e.id)!, deduplicated: true };
    }
    throw e;
  }
  await ctx.testHooks?.afterCommit?.();
  return { amendment: recorded!, deduplicated: false };
}

/** The thread id an item belongs to now (for an amendment's relates_to). */
export function threadIdOfItem(st: StateRecord, itemId: string): string {
  const ix = discussionIndexOf(st);
  const it = ix.itemById.get(itemId);
  if (!it) throw new DomainError("FINDING_NOT_FOUND", `${itemId} is not a reviewer item of this run`);
  return threadOfItem(ix, it).id;
}
