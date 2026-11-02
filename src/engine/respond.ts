// `respond_to_review`: the implementer's responses to reviewer items (Phase 2.1, plan §1.14).
//
// One call records a batch of responses in ONE commit, or nothing:
//  1. the call is validated (its shape by the strict tool schema, its semantics here);
//  2. a `request_id` replay returns the recorded result; the same id with other arguments is
//     REQUEST_ID_CONFLICT;
//  3. the working tree's source identity is computed once by the caller (bounded, like a status
//     call) and recorded with every response; a fix claim needs it fresh and stable, since a
//     claim must name the source it is about (SOURCE_UNAVAILABLE, retryable). The withheld
//     names and hashes that read saw are published as an immutable artifact before the commit
//     that references it, so every later host view of the response text keeps them withheld;
//     every check that needs no tree read (the limits included) runs before that, and a record
//     no commit came to reference is removed again;
//  4. under the run's mutation lock every response is checked against the CURRENT state — the
//     item exists in this run, is still open for responses, and is exactly in the state the
//     caller saw (its response token) — then all are appended and one event is added.
// Responses are recorded BETWEEN reviews, never while a review of the run is running
// (RUN_BUSY): a running review read the items when it started and commits its carry-forward at
// the end, so a response in between would answer a state that review is about to replace, and
// would be missing from that review's input. A review whose server died will never commit and
// does not block. The check runs before anything else is done and again inside the commit.
// Nothing else changes: no reviewer item (text, triage, status, assessments), no operation, no
// run state. No review or check starts, nothing is sent to Codex, and repository files are
// never touched. Who recorded a response is set here from the channel (the MCP path is always
// the implementer), never taken from the arguments.
//
// Phase 2.2 (plan §1.15): a response is the implementer's turn in a discussion thread. It is
// presented to Codex only inside a later review that the host or user requests (never by this
// call), when it earns an exchange (the new-information gate and the budgets, P2.2-7). Each
// record notes the run's current accepted review and the latest reviewer reply in its thread
// (order without clocks, P2.2-6); the result previews whether the next review would present it.

import { DomainError } from "../common/errors.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import {
  answeredReview,
  checkResponses,
  currentReviewOf,
  discussionState,
  inputProblems,
  latestResponses,
  normalizeFindingId,
  normalizeReferencePath,
  respondable,
  responseToken,
  responsesOf,
  storedReferences,
  lastPresentSourceAt,
  type DiscussionState,
  type Rejection,
  type ResponseInput,
} from "../policy/responses.js";
import { discussionIndexOf, planDiscussion, referenceKey, threadOfItem, threadReplies, type NotDeliveredReason } from "../policy/discussion.js";
import { turnSummary } from "../policy/discussion-reports.js";
import { caseKey } from "../workspace/paths.js";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { publishArtifactInRun } from "../store/artifacts.js";
import { commitState, readState } from "../store/state-store.js";
import type { LockDeps } from "../store/locks.js";
import { classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type Liveness, type OwnerRecord } from "../store/owner.js";
import type { RunPaths } from "../store/paths.js";
import { RESPONSE_LIMITS } from "../schemas/responses.js";
import type { StateRecord } from "../schemas/run-state.js";
import { sha256OfString } from "../common/hash.js";
import type { RunResponse } from "../custodian/protocol.js";
import { custodianEvidenceFor, type CustodianEvidence, type EvidenceSelection } from "./custodian-evidence.js";

const TERMINAL = new Set(["CLOSED", "STOPPED", "CONFIGURATION_ERROR"]);

/** The only recorder this engine path knows: the host agent, through MCP. */
const IMPLEMENTER_VIA_MCP = { role: "implementer", channel: "mcp" } as const;

export const RESPONSE_NOTE =
  "A response records the implementer's position; it is a claim, not a resolution. Nothing was sent to Codex, no review or check was started, no finding was resolved or closed, and repository files were not modified. A later review that you request presents it to Codex when it earns an exchange (delivery_preview); a fix claim waits for that review, and only a reviewer can report an item resolved.";

export interface RespondRequest {
  responses: ResponseInput[];
  request_id?: string | undefined;
}

/** The working tree's source identity now: fresh and stable, else null with the reason. */
export interface SourceForResponse {
  source_id: string | null;
  note: string | null;
  /**
   * What the read had to withhold, whatever its stability: confidential names and hashes, and
   * the files the repository's review.exclude_paths keep out of a review (with their hashes).
   */
  withheld?: WithheldOfRead | undefined;
}

/** A source read's withheld set (engine/host-view.ts withheldOfEntries). */
export interface WithheldOfRead {
  paths: readonly string[];
  hashes: readonly string[];
  repoContext?: readonly { path: string; hashes: readonly string[] }[];
}

export interface RespondTestHooks {
  /** TEST ONLY: after the disclosure record is written, before the commit (a purge can win here). */
  afterPublish?: () => Promise<void> | void;
  /** TEST ONLY: inside the commit, after every check passed, before the state is written (nothing is recorded). */
  beforeWrite?: () => void;
  /** TEST ONLY: after the commit, before the result is built (recorded, but the caller sees a failure). */
  afterCommit?: () => Promise<void> | void;
}

export interface RespondContext {
  runId: string;
  runPaths: RunPaths;
  owner: OwnerRecord;
  currentSource(): Promise<SourceForResponse>;
  lockDeps?: LockDeps;
  /** Liveness of a running review's server (default: the process table). */
  classify?: (owner: OwnerRecord) => Promise<Liveness>;
  testHooks?: RespondTestHooks;
  /** P3.4C-3: how to ask whether the run's evidence goes through the custodian (absent: an attended-only context). */
  evidence?: EvidenceSelection;
}

/**
 * One recorded response as the call reports it. Bounded by design: no reviewer text (a question's
 * text can be 4000 characters) and no per-entry copy of the source note, so even a full batch
 * stays far below the host result limit (Codex review of PR #10).
 */
export interface RecordedResponse {
  response_id: string;
  finding_id: string;
  disposition: string;
  /** The earlier response to the same item that this one supersedes. */
  supersedes: string | null;
  /** A response recorded after this one (a replay can find its own records superseded). */
  superseded_by: string | null;
  discussion_state: DiscussionState | null;
  /** The item's token NOW (null when it can no longer be responded to). */
  response_token: string | null;
  answers_round: number;
  source_id: string | null;
  notes: string[];
}

/**
 * Phase 2.2: what the next review that the host or user requests would do with this call's
 * responses — a preview, once per call (entries stay bounded): the review decides when it builds
 * its bundle, with its own source and check evidence (P2.2-4, -7). reply_sought: an exchange (Codex
 * is asked to reply); context: presented without seeking a reply; not_presented: recorded, but not
 * shown to Codex, with why (a repetition without new information, an exhausted budget, withheld
 * text, …). Status (discussion.threads) shows the same per thread.
 */
export interface DeliveryPreview {
  reply_sought: number;
  context: number;
  not_presented: { finding_id: string; reason: NotDeliveredReason | null }[];
  not_presented_total: number;
  note: string;
}

/** Responses a preview names (the rest are counted). */
const MAX_PREVIEW_LISTED = 20;

export interface RespondResult {
  summary: string;
  run_id: string;
  response_set_id: string;
  /** This call's request_id had already been recorded: nothing new was recorded. */
  deduplicated: boolean;
  recorded_at: string;
  recorded: RecordedResponse[];
  source: SourceForResponse;
  note: string;
  /** Phase 2.2: what the next review would present of these responses. */
  delivery_preview: DeliveryPreview;
}

/** A response recorded without a read of the working tree (its text is withheld from every view). */
const TEXT_WITHHELD_NOTE = "text withheld from every view: the working tree could not be read completely to check it for confidential names";
const TEXT_WITHHELD_SUMMARY =
  "The working tree could not be read completely now (see source.note), so the text of these responses could not be checked for confidential names: every view withholds their rationale and references, while the dispositions stand. Record them again when the worktree is free to make the text visible.";

/** A replay found inside the commit (a concurrent call with the same request_id won). */
class ReplayFound extends Error {
  constructor(readonly setId: string) {
    super("replay");
  }
}

export async function respondToReview(ctx: RespondContext, req: RespondRequest): Promise<RespondResult> {
  const problems = inputProblems(req.responses);
  if (req.request_id !== undefined && (req.request_id.length < 1 || req.request_id.length > 128)) problems.push("request_id: 1 to 128 characters");
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", `invalid responses: ${problems.slice(0, 20).join("; ")}`, { details: { issues: problems.slice(0, 50) } });
  const digest = requestDigest(req.responses);

  // A replay needs neither the source nor any check: it returns what was recorded.
  const st0 = await readState(ctx.runPaths);
  const replay0 = replayOf(st0, req.request_id, digest);
  if (replay0) return resultFor(ctx.runId, st0, replay0, true, null);
  refuseTerminal(st0);
  const deadReviews = await deadReviewOperations(st0, ctx.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS)));
  refuseActiveReview(st0, deadReviews);
  refuseRejections(checkFor(st0, req.responses), req.responses.length);
  refuseOverLimits(st0, req.responses);
  // P3.4C-3: a protected run's responses are recorded with the custodian first, against the item revisions it holds;
  // refused here, before the tree is read, when the custodian cannot answer for a run marked protected.
  const custodianEv = ctx.evidence ? await custodianEvidenceFor(ctx.evidence, st0) : null;

  const source = await ctx.currentSource().catch((e: unknown): SourceForResponse => ({ source_id: null, note: `the source identity could not be computed (${(e instanceof Error ? e.message : String(e)).slice(0, 160)})` }));
  if (source.source_id === null && req.responses.some((r) => r.disposition === "fix_claimed")) {
    throw new DomainError("SOURCE_UNAVAILABLE", `a fix claim must be bound to the source it describes, and the current source identity could not be computed fresh: ${source.note ?? "unknown reason"}. Nothing was recorded; retry when the worktree is free.`, { retryable: true });
  }

  // Only a complete, stable read of the working tree knows everything confidential now. Without
  // one — no read, or a read that saw the tree change and may have missed a file created
  // meanwhile (Codex review of PR #10) — the responses are recorded, but every view withholds
  // their text whole (fail closed).
  const textWithheld = source.source_id === null || source.withheld === undefined;
  const setId = uuidv7();
  const recordedAt = new Date().toISOString();
  // Artifacts first (§15.3): what the read had to withhold, before the commit that refers to it.
  // Never into a run that was purged meanwhile: nothing of the run is recreated.
  const disclosure = disclosureOf(source.withheld);
  const disclosureRef = disclosure ? (await publishArtifactInRun(ctx.runPaths.runDir, ctx.runPaths.opsDir, setId, "responses/disclosure.json", disclosure)).ref : null;
  await ctx.testHooks?.afterPublish?.();
  let prebuilt: StateRecord["implementer_responses"] | null = null;
  if (custodianEv) {
    try {
      const st1 = await readState(ctx.runPaths);
      if (replayOf(st1, req.request_id, digest) === null) {
        refuseTerminal(st1);
        refuseActiveReview(st1, deadReviews);
        refuseRejections(checkFor(st1, req.responses), req.responses.length);
        refuseOverLimits(st1, req.responses);
        prebuilt = buildResponses(st1, req, source, { setId, recordedAt, disclosureRef, textWithheld, digest });
        await recordWithCustodian(custodianEv, prebuilt, setId, disclosure);
      }
    } catch (e) {
      if (disclosureRef) await removeUnreferenced(ctx.runPaths, setId, disclosureRef);
      throw e;
    }
  }
  let committed: StateRecord;
  try {
    committed = await commitState(ctx.runPaths, ctx.owner, (cur) => {
      const replay = replayOf(cur, req.request_id, digest);
      if (replay) throw new ReplayFound(replay);
      refuseTerminal(cur);
      // A review that started since the first check (the source read can take seconds).
      refuseActiveReview(cur, deadReviews);
      refuseRejections(checkFor(cur, req.responses), req.responses.length);
      refuseOverLimits(cur, req.responses);
      // The custodian recorded the responses built from the state it was sent (the checks above passed on this one).
      cur.implementer_responses.push(...(prebuilt ?? buildResponses(cur, req, source, { setId, recordedAt, disclosureRef, textWithheld, digest })));
      pushEvent(cur, "review.responses_recorded", `implementer recorded ${req.responses.length} response(s): ${countText(req.responses.map((r) => r.disposition))}`, { response_set_id: setId });
      ctx.testHooks?.beforeWrite?.();
      return cur;
    }, ctx.lockDeps ? { lockDeps: ctx.lockDeps } : {});
  } catch (e) {
    if (disclosureRef) await removeUnreferenced(ctx.runPaths, setId, disclosureRef);
    if (e instanceof ReplayFound) {
      const st = await readState(ctx.runPaths);
      return resultFor(ctx.runId, st, e.setId, true, null);
    }
    throw e;
  }
  await ctx.testHooks?.afterCommit?.();
  return resultFor(ctx.runId, committed, setId, false, source);
}

/** This call's response records against `st` (its checks passed on it). */
function buildResponses(
  st: StateRecord,
  req: RespondRequest,
  source: SourceForResponse,
  o: { setId: string; recordedAt: string; disclosureRef: string | null; textWithheld: boolean; digest: string },
): StateRecord["implementer_responses"] {
  const latest = latestResponses(st.implementer_responses);
  const items = new Map(st.findings.map((f) => [f.id, f]));
  // Checked against this same state, so the index describes what the tokens covered.
  const ix = discussionIndexOf(st);
  const runReview = currentReviewOf(ix);
  return req.responses.map((r) => {
    const it = items.get(normalizeFindingId(r.finding_id))!;
    const answered = answeredReview(it);
    const thread = threadOfItem(ix, it);
    return {
      response_id: uuidv7(),
      item_id: it.id,
      disposition: r.disposition,
      rationale: r.rationale,
      references: storedReferences(r),
      answers: {
        review_id: answered.review_id,
        round: answered.round,
        token: r.response_token.trim(),
        run_review_id: runReview?.review_id ?? null,
        run_round: runReview?.round ?? null,
        reviewer_reply_id: threadReplies(ix, thread).at(-1)?.reply_id ?? null,
      },
      source: { source_id: source.source_id, note: source.source_id === null ? source.note : null },
      disclosure_ref: o.disclosureRef,
      text_withheld: o.textWithheld,
      supersedes: latest.get(it.id)?.response_id ?? null,
      thread_id: thread.id,
      recorded_by: { ...IMPLEMENTER_VIA_MCP },
      response_set_id: o.setId,
      request_id: req.request_id ?? null,
      request_digest: o.digest,
      recorded_at: o.recordedAt,
    };
  });
}

/**
 * Record a response set with the custodian (contract §3.2 respond): each response against the revision of its item
 * the custodian holds now (a change in between is STALE_FINDING_STATE: nothing is recorded), with the digest of the
 * disclosure record. The responses' text stays in the local store; the custodian holds their claims.
 */
async function recordWithCustodian(ev: CustodianEvidence, records: StateRecord["implementer_responses"], setId: string, disclosure: string | null): Promise<void> {
  const held = ((await ev.runSection())?.record?.["items"] ?? []) as { itemId?: unknown; itemRevision?: unknown }[];
  const revision = new Map(held.map((i) => [String(i.itemId), typeof i.itemRevision === "number" ? i.itemRevision : 1]));
  const responses: RunResponse[] = records.map((r) => ({
    responseId: r.response_id,
    itemId: r.item_id,
    baseItemRevision: revision.get(r.item_id) ?? 1,
    disposition: r.disposition as RunResponse["disposition"],
    textWithheld: r.text_withheld,
    answers: { reviewId: r.answers.review_id, round: r.answers.round, runReviewId: r.answers.run_review_id ?? null, runRound: r.answers.run_round ?? null, reviewerReplyId: r.answers.reviewer_reply_id ?? null },
    sourceId: r.source.source_id,
    supersedes: r.supersedes,
    threadId: r.thread_id ?? r.item_id,
    // P3.4C-5 Increment 3 (§5.1): what the new-information gate reads of the text, held without it.
    referenceKeys: [...new Set(r.references.map((x) => referenceKey(x, caseKey)))].slice(0, 20),
    rationalePresent: r.rationale.trim() !== "",
  }));
  await ev.transition("respond", { responseSetId: setId, disclosureDigest: disclosure === null ? null : sha256OfString(disclosure), responses }, `${setId}-respond`);
  // Phase 5 F-i2-5: the custodian holds the record's bytes as redaction evidence, so an amendment it redacts covers the
  // names this read withheld even after the files are gone. Best effort: the responses are recorded; without the record
  // the custodian refuses such an amendment (REDACTION_REFUSED) rather than redact against less.
  if (disclosure !== null) await ev.holdEvidence(Buffer.from(disclosure, "utf8")).catch(() => undefined);
}

/** The disclosure record of a read's withheld set (`arl.response-disclosure.v1`), or null when it withheld nothing. */
function disclosureOf(w: WithheldOfRead | undefined): string | null {
  const repoContext = [...(w?.repoContext ?? [])].map((r) => ({ path: r.path, hashes: [...r.hashes].sort() })).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (!w || (w.paths.length === 0 && w.hashes.length === 0 && repoContext.length === 0)) return null;
  return JSON.stringify({ schema: "arl.response-disclosure.v1", withheld_paths: [...w.paths].sort(), withheld_hashes: [...w.hashes].sort(), repo_context: repoContext }, null, 2);
}

/**
 * Remove this call's disclosure record after a refused commit, so that retries cannot grow the
 * store (Codex review of PR #10) — but only once the state confirms no response refers to it:
 * a failure after the state was written must never lose a record a response depends on.
 */
async function removeUnreferenced(paths: RunPaths, setId: string, ref: string): Promise<void> {
  const st = await readState(paths).catch(() => null);
  if (!st || st.implementer_responses.some((r) => r.disclosure_ref === ref)) return;
  await rm(join(paths.opsDir, setId), { recursive: true, force: true }).catch(() => undefined);
}

/** The digest a request_id is bound to: the responses in their stored form. */
function requestDigest(responses: readonly ResponseInput[]): string {
  return sha256OfCanonicalJson({
    schema: "arl.respond-request.v1",
    responses: responses.map((r) => ({
      finding_id: normalizeFindingId(r.finding_id),
      response_token: r.response_token.trim(),
      disposition: r.disposition,
      rationale: r.rationale,
      references: (r.references ?? []).map((x) => ({ path: normalizeReferencePath(x.path) ?? x.path, start_line: x.start_line ?? null, end_line: x.end_line ?? null })),
    })),
  });
}

/** The response set recorded under this request_id (same arguments), or null; a mismatch throws. */
function replayOf(st: StateRecord, requestId: string | undefined, digest: string): string | null {
  if (requestId === undefined) return null;
  const prior = st.implementer_responses.find((r) => r.request_id === requestId);
  if (!prior) return null;
  if (prior.request_digest !== digest) throw new DomainError("REQUEST_ID_CONFLICT", `request_id ${requestId} was already used with different responses`, { details: { response_set_id: prior.response_set_id } });
  return prior.response_set_id;
}

function refuseTerminal(st: StateRecord): void {
  if (TERMINAL.has(st.state)) throw new DomainError("RUN_TERMINAL", `run is ${st.state}; its records are read-only`);
}

/** Review operations recorded as running whose server is gone: they will never commit, so they do not block responses. */
async function deadReviewOperations(st: StateRecord, classify: (owner: OwnerRecord) => Promise<Liveness>): Promise<Set<string>> {
  const dead = new Set<string>();
  for (const op of st.operations) {
    if (op.kind !== "review" || op.status !== "running") continue;
    if (!op.owner || (await classify(op.owner).catch((): Liveness => "alive_unconfirmed")) === "dead") dead.add(op.operation_id);
  }
  return dead;
}

/** No response while a review of the run is running (its server alive, or not known to be dead). */
function refuseActiveReview(st: StateRecord, dead: ReadonlySet<string>): void {
  const active = st.operations.find((o) => o.kind === "review" && o.status === "running" && !dead.has(o.operation_id));
  if (!active) return;
  throw new DomainError(
    "RUN_BUSY",
    `a review of this run is running (operation ${active.operation_id}); responses are recorded between reviews. Wait for it (get_review_status with wait_seconds), read the findings again and respond to what that review left; nothing was recorded`,
    { retryable: true, details: { operation_id: active.operation_id } },
  );
}

function checkFor(st: StateRecord, responses: readonly ResponseInput[]): Rejection[] {
  return checkResponses({ ix: discussionIndexOf(st), incidentIds: new Set(st.isolation_incidents.map((i) => i.incident_id)), responses });
}

/** Every rejection, in one error; the call's code is the first one's (all are in details). */
function refuseRejections(rejected: Rejection[], total: number): void {
  if (rejected.length === 0) return;
  const first = rejected[0]!;
  const list = rejected.slice(0, 10).map((r) => `#${r.index} ${r.finding_id}: ${r.code} — ${r.detail}`);
  throw new DomainError(first.code, `${rejected.length} of ${total} response(s) refused; nothing was recorded. ${list.join(" | ")}`, { details: { rejected } });
}

function refuseOverLimits(st: StateRecord, responses: readonly ResponseInput[]): void {
  if (st.implementer_responses.length + responses.length > RESPONSE_LIMITS.perRun) {
    throw new DomainError("BUDGET_EXHAUSTED", `a run keeps at most ${RESPONSE_LIMITS.perRun} implementer responses (${st.implementer_responses.length} recorded)`, { details: { limit: "responses_per_run", used: st.implementer_responses.length, max: RESPONSE_LIMITS.perRun } });
  }
  for (const r of responses) {
    const id = normalizeFindingId(r.finding_id);
    const n = responsesOf(st.implementer_responses, id).length;
    if (n + 1 > RESPONSE_LIMITS.perItem) throw new DomainError("BUDGET_EXHAUSTED", `item ${id} already has ${n} responses (at most ${RESPONSE_LIMITS.perItem} per item)`, { details: { limit: "responses_per_item", finding_id: id, used: n, max: RESPONSE_LIMITS.perItem } });
  }
}

/** What the next review would do with a call's responses (P2.2-4, -7), as far as this call can tell. */
function deliveryPreview(ix: ReturnType<typeof discussionIndexOf>, plan: ReturnType<typeof planDiscussion>, mine: readonly StateRecord["implementer_responses"][number][]): DeliveryPreview {
  let replySought = 0;
  let context = 0;
  const notPresented: DeliveryPreview["not_presented"] = [];
  for (const r of mine) {
    const t = turnSummary(ix, plan, r);
    if (t.delivery === "pending") {
      if (plan.items.get(r.item_id)?.turn?.reply_sought) replySought++;
      else context++;
    } else if (t.delivery !== "delivered") notPresented.push({ finding_id: r.item_id, reason: t.delivery_reason });
  }
  return {
    reply_sought: replySought,
    context,
    not_presented: notPresented.slice(0, MAX_PREVIEW_LISTED),
    not_presented_total: notPresented.length,
    note: "A preview: the next review you request decides what it presents to Codex, with its own source and check evidence. Disputes and fix claims ask Codex for a reply (an exchange: 3 per thread); a repeat of the same position without new information is recorded but not presented. Nothing is sent now.",
  };
}

function countText(kinds: readonly string[]): string {
  const n = new Map<string, number>();
  for (const k of kinds) n.set(k, (n.get(k) ?? 0) + 1);
  return [...n.entries()].map(([k, v]) => `${v} ${k}`).join(", ");
}

function pushEvent(st: StateRecord, type: string, summary: string, refs: Record<string, string>): void {
  const seq = (st.events.at(-1)?.seq ?? 0) + 1;
  st.events.push({ seq, ts: new Date().toISOString(), type, actor: "host", summary: summary.slice(0, 500), refs });
}

function resultFor(runId: string, st: StateRecord, setId: string, deduplicated: boolean, source: SourceForResponse | null): RespondResult {
  const mine = st.implementer_responses.filter((r) => r.response_set_id === setId);
  const items = new Map(st.findings.map((f) => [f.id, f]));
  const latest = latestResponses(st.implementer_responses);
  const ix = discussionIndexOf(st);
  // The preview takes this call's source as the source the next review would see; the check
  // evidence is compared only when that review builds its bundle.
  const plan = planDiscussion(ix, { sourceId: source?.source_id ?? mine[0]?.source.source_id ?? null, checkResults: null, pathKey: caseKey });
  const recorded: RecordedResponse[] = mine.map((r) => {
    const it = items.get(r.item_id);
    const l = latest.get(r.item_id);
    const notes: string[] = [];
    if (it && r.disposition === "fix_claimed" && r.source.source_id !== null && r.source.source_id === lastPresentSourceAt(it, r.answers.review_id)) {
      notes.push("fix claimed on the same source the reviewer last saw the item on: a review of that source cannot confirm it");
    }
    if (r.source.source_id === null) notes.push("source not recorded (the reason is in source.note)");
    if (r.text_withheld) notes.push(TEXT_WITHHELD_NOTE);
    return {
      response_id: r.response_id,
      finding_id: r.item_id,
      disposition: r.disposition,
      supersedes: r.supersedes,
      superseded_by: l && l.response_id !== r.response_id ? l.response_id : null,
      discussion_state: it ? discussionState(it, l) : null,
      response_token: it && respondable(it) ? responseToken(it, ix) : null,
      answers_round: r.answers.round,
      source_id: r.source.source_id,
      notes,
    };
  });
  const first = mine[0];
  const recordedAt = first?.recorded_at ?? new Date().toISOString();
  const shownSource = { source_id: source?.source_id ?? first?.source.source_id ?? null, note: source ? source.note : (first?.source.note ?? null) };
  const withheldText = mine.some((r) => r.text_withheld) ? ` ${TEXT_WITHHELD_SUMMARY}` : "";
  const summary = deduplicated
    ? `this request_id was already recorded at ${recordedAt} (${mine.length} response(s): ${countText(mine.map((r) => r.disposition))}); nothing new was recorded. Tokens and states below are current.${withheldText}`
    : `recorded ${mine.length} implementer response(s) on run ${runId.slice(0, 8)}: ${countText(mine.map((r) => r.disposition))}. ${RESPONSE_NOTE}${withheldText}`;
  return { summary, run_id: runId, response_set_id: setId, deduplicated, recorded_at: recordedAt, recorded, source: shownSource, note: RESPONSE_NOTE, delivery_preview: deliveryPreview(ix, plan, mine) };
}
