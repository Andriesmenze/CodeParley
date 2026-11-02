// The simulated custodian's loop lifecycle (P3.4C-2): a faithful TypeScript re-implementation of the
// custodian's custodian/…/Ledger/GrantLedger.Loops.cs, LoopRequest.cs and LoopRecords.cs, for the in-process
// SimulatedCustodianTransport (a test stand-in: only test code constructs it, never configuration). Both are
// held to one observable behaviour by the shared corpus test/fixtures/loop-transition-corpus.json, which the
// TypeScript contract test runs here and the custodian's `self-test-loop-corpus` runs against the real ledger.
//
// The custodian computes every transition from the stored record and the request's typed fields; a client
// never replaces a record or sets a status, epoch, budget, binding verdict, operation handle or wake claim.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { sha256OfCanonicalJson } from "../common/hash.js";

/** The budgets a minted loop carries (custodian/…/CustodianConstants.cs; mirrors HARD_LOOP_LIMITS). */
export const SIM_LOOP_LIMITS = Object.freeze({ continuations: 2, wakesPerOperation: 1, wakesPerRun: 2, runSeconds: 900 });
export const SIM_BIND_NONCE_TTL_MS = 60_000;
export const SIM_MAX_LOOP_EVENTS = 128;

export const LIVE_STATUSES: ReadonlySet<string> = new Set(["unbound", "active", "paused"]);
const CLIENT_END: ReadonlySet<string> = new Set(["cancelled", "run_ended"]);
const PAUSE_REASONS: ReadonlySet<string> = new Set(["user_interrupt", "user_decision_required", "operator_action_required", "operation_unsuccessful", "config_change", "process_identity", "no_progress"]);
const OPERATOR_ONLY_PAUSES: ReadonlySet<string> = new Set(["operator_action_required", "user_decision_required"]);
const KIND_FIELDS: Readonly<Record<string, readonly string[]>> = {
  bind: ["bindNonce", "session_id", "process"],
  rebind: ["session_id", "process"],
  spend_continuation: ["session_id", "derivation_id"],
  wake_arm: ["operationHandle", "session_id"],
  wake_consume: ["claimId", "session_id", "derivation_id"],
  pause: ["reason", "detail"],
  resume: [],
  end: ["status", "reason"],
};
const CUSTODIAN = "custodian";

/** The custodian's verdict on the process the client named (CLAUDE_PID) — computed by the custodian, never
 * taken from the client (D7: correlation only). The simulator receives it from its injected check. */
export interface SimProcessCheck {
  pid: number | null;
  startedAtMs: number | null;
  clientPid: number | null;
  verified: boolean;
  detail: string;
}

export interface SimLoopOperation {
  handle: string;
  seq: number;
  epoch: number;
  issuedAt: string;
  issuedBy: string;
  wakesUsed: number;
}

export interface SimWakeClaim {
  claimId: string;
  operationHandle: string;
  epoch: number;
  state: "armed" | "consumed";
  armedAt: string;
  armRequestId: string;
  consumedAt: string | null;
  consumeRequestId: string | null;
}

export interface SimLoopEvent {
  seq: number;
  kind: string;
  requestId: string;
  caller: string;
  at: string;
  requestDigest: string;
  fromStatus: string;
  toStatus: string;
  epoch: number;
  result: Record<string, unknown> | null;
}

/** The simulated loop record (the custodian's LoopRecord, same field names as its JSON). */
export interface SimLoop {
  loopId: string;
  repoKey: string;
  runId: string;
  status: string;
  epoch: number;
  loopRevision: number;
  startedAt: string;
  deadlineAt: string;
  grantId: string;
  grantUse: { source: "custodian"; loopId: string; requestId: string; loopsUsed: number; loopsTotal: number };
  limits: { continuations: number; wakesPerOperation: number; wakesPerRun: number; runSeconds: number };
  used: { continuations: number; wakes: number };
  bindNonce: { sha256: string; issuedAt: string; expiresAt: string; usedAt: string | null };
  requestId: string;
  binding: { sessionId: string; state: string; boundAt: string; reboundAt: string | null; process: SimProcessCheck & { checkedAt: string } } | null;
  pause: { reason: string; detail: string; at: string; by: string } | null;
  resumedAt: string | null;
  ended: { status: string; reason: string; at: string; by: string } | null;
  operations: SimLoopOperation[];
  wakeClaims: SimWakeClaim[];
  events: SimLoopEvent[];
  /** P3.4C-3 (§2.4): the recovery that last changed the record (a resumed recovery changes nothing twice). */
  lastRecoveryId?: string | null;
  /** P3.4C-5 Increment 3 (§5.2–§5.3): what the latest continuation or wake was spent on (LoopProgress). */
  progress?: { fingerprint: string; derivationId: string; at: string; kind: string } | null;
}

/** A refusal the simulated custodian decided (the custodian's CustodianRefusal). */
export class SimLoopRefusal extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(`${message} (${code})`);
  }
}

/** An invalid argument (the custodian's ArgumentException → INVALID_ARGUMENT). */
export class SimLoopInvalid extends Error {}

/** A validated loop_transition request (LoopRequest.cs). */
export interface SimLoopRequest {
  runId: string;
  loopId: string;
  epoch: number;
  baseLoopRevision: number;
  kind: string;
  requestId: string;
  digest: string;
  bindNonce?: string;
  sessionId?: string;
  claimedPid?: number | null;
  operationHandle?: string;
  claimId?: string;
  reason?: string;
  detail?: string;
  endStatus?: string;
  /** P3.4C-5 Increment 3 (§5.2): the custodian derivation a continuation or wake is asked on. */
  derivationId?: string;
}

const iso = (ms: number): string => new Date(ms).toISOString();
const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const TOKEN = /^[A-Za-z0-9_-]{1,128}$/;
const ID_TOKEN = /^[A-Za-z0-9-]{1,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SESSION = /^[A-Za-z0-9._:-]{1,256}$/;
const HEX64 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// Minting (consume_loop's loop half) and the consume result
// ---------------------------------------------------------------------------

/** Mint the UNBOUND loop for a consumed grant loop; returns the record and the one-time nonce preimage. */
export function mintLoop(a: { repoKey: string; runId: string; requestId: string; grantId: string; loopsUsed: number; loopsTotal: number; loopId: string; nowMs: number }): { loop: SimLoop; nonce: string } {
  const nonce = randomBytes(32).toString("hex");
  const loop: SimLoop = {
    loopId: a.loopId, repoKey: a.repoKey, runId: a.runId, status: "unbound", epoch: 1, loopRevision: 1,
    startedAt: iso(a.nowMs), deadlineAt: iso(a.nowMs + SIM_LOOP_LIMITS.runSeconds * 1000), grantId: a.grantId,
    grantUse: { source: "custodian", loopId: a.loopId, requestId: a.requestId, loopsUsed: a.loopsUsed, loopsTotal: a.loopsTotal },
    limits: { ...SIM_LOOP_LIMITS }, used: { continuations: 0, wakes: 0 },
    bindNonce: { sha256: sha256(nonce), issuedAt: iso(a.nowMs), expiresAt: iso(a.nowMs + SIM_BIND_NONCE_TTL_MS), usedAt: null },
    requestId: a.requestId, binding: null, pause: null, resumedAt: null, ended: null, operations: [], wakeClaims: [], events: [],
  };
  return { loop, nonce };
}

/** The consume_loop result (contract §1); the nonce preimage only on the minting call. */
export function consumeResultOf(l: SimLoop): Record<string, unknown> {
  return { grantId: l.grantId, loopId: l.loopId, loopsUsed: l.grantUse.loopsUsed, loopsTotal: l.grantUse.loopsTotal, runId: l.runId, loopEpoch: l.epoch, loopRevision: l.loopRevision };
}

// ---------------------------------------------------------------------------
// Request validation (LoopRequest.Parse)
// ---------------------------------------------------------------------------

function str(fields: Record<string, unknown>, key: string): string {
  const v = fields[key];
  if (typeof v !== "string") throw new SimLoopInvalid(`fields.${key} must be a string`);
  return v;
}

function rejectUnknown(o: Record<string, unknown>, allowed: readonly string[], where: string): void {
  if (Object.keys(o).some((k) => !allowed.includes(k))) throw new SimLoopRefusal("MALFORMED_REQUEST", `unexpected key in ${where} (no field conveys authority; unknown fields are refused, not ignored)`);
}

function pidOf(fields: Record<string, unknown>): number | null {
  const p = fields["process"];
  if (!p || typeof p !== "object" || Array.isArray(p)) throw new SimLoopInvalid("fields.process must be an object");
  rejectUnknown(p as Record<string, unknown>, ["pid"], "fields.process");
  if (!("pid" in p)) throw new SimLoopInvalid("fields.process.pid is required (null when the host gave none)");
  const pid = (p as Record<string, unknown>)["pid"];
  if (pid === null) return null;
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0 || pid > 0x7fffffff) throw new SimLoopInvalid("fields.process.pid must be a positive integer or null");
  return pid;
}

function oneOf(fields: Record<string, unknown>, key: string, allowed: ReadonlySet<string>): string {
  const s = str(fields, key);
  if (!allowed.has(s)) throw new SimLoopInvalid(`fields.${key} must be one of: ${[...allowed].sort().join(", ")}`);
  return s;
}

function text(fields: Record<string, unknown>, key: string): string {
  if (!(key in fields) || fields[key] === null) return "";
  const s = str(fields, key);
  if (s.length > 500) throw new SimLoopInvalid(`fields.${key} must be at most 500 characters`);
  return s.replace(/\p{Cc}/gu, " ");
}

function idOf(fields: Record<string, unknown>, key: string): string {
  const s = str(fields, key);
  if (!ID_TOKEN.test(s)) throw new SimLoopInvalid(`fields.${key} must be 1..64 chars of [A-Za-z0-9-]`);
  return s;
}

export function parseLoopRequest(args: Record<string, unknown>, requestId: string): SimLoopRequest {
  const r = envelopeOf(args, requestId);
  return typedFields(r, args["fields"] as Record<string, unknown>);
}

/** The addressing and concurrency part of a request (validated) and its digest. */
function envelopeOf(args: Record<string, unknown>, requestId: string): SimLoopRequest {
  const { runId, loopId, kind, epoch, baseLoopRevision: base, fields } = args;
  if (typeof args["repositoryRoot"] !== "string") throw new SimLoopInvalid("'repositoryRoot' must be a string");
  if (typeof runId !== "string" || !TOKEN.test(runId)) throw new SimLoopInvalid("runId must be 1..128 chars of [A-Za-z0-9-_]");
  if (!TOKEN.test(requestId)) throw new SimLoopInvalid("request id must be 1..128 chars of [A-Za-z0-9-_]");
  if (typeof loopId !== "string" || !UUID.test(loopId)) throw new SimLoopInvalid("loopId must be a custodian-assigned loop id");
  if (typeof kind !== "string" || !(kind in KIND_FIELDS)) throw new SimLoopInvalid(`kind must be one of: ${Object.keys(KIND_FIELDS).sort().join(", ")}`);
  if (!positiveInts(epoch, base)) throw new SimLoopInvalid("epoch and baseLoopRevision must be positive integers");
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) throw new SimLoopInvalid("missing object 'fields'");
  rejectUnknown(fields as Record<string, unknown>, KIND_FIELDS[kind]!, "fields");
  return { runId, loopId, epoch: epoch as number, baseLoopRevision: base as number, kind, requestId, digest: sha256OfCanonicalJson({ kind, fields, epoch, baseLoopRevision: base }) };
}

const positiveInts = (...v: unknown[]): boolean => v.every((x) => Number.isInteger(x) && (x as number) >= 1);

/** The kind's typed fields (LoopRequest.Parse's per-kind readers). */
function typedFields(r: SimLoopRequest, f: Record<string, unknown>): SimLoopRequest {
  switch (r.kind) {
    case "bind":
      return { ...r, bindNonce: nonceOf(f), sessionId: sessionOf(f), claimedPid: pidOf(f) };
    case "rebind":
      return { ...r, sessionId: sessionOf(f), claimedPid: pidOf(f) };
    case "spend_continuation":
      return { ...r, sessionId: sessionOf(f), ...derivationIdOf(f) };
    case "wake_arm":
      return { ...r, operationHandle: idOf(f, "operationHandle"), sessionId: sessionOf(f) };
    case "wake_consume":
      return { ...r, claimId: idOf(f, "claimId"), sessionId: sessionOf(f), ...derivationIdOf(f) };
    case "pause":
      return { ...r, reason: oneOf(f, "reason", PAUSE_REASONS), detail: text(f, "detail") };
    case "end":
      return { ...r, endStatus: oneOf(f, "status", CLIENT_END), reason: text(f, "reason") };
    default:
      return r;
  }
}

/** The custodian-issued derivation id an automation request names (absent: refused DERIVATION_STALE by the ledger). */
function derivationIdOf(fields: Record<string, unknown>): { derivationId?: string } {
  if (fields["derivation_id"] === undefined || fields["derivation_id"] === null) return {};
  return { derivationId: idOf(fields, "derivation_id") };
}

function nonceOf(fields: Record<string, unknown>): string {
  const nonce = str(fields, "bindNonce");
  if (!HEX64.test(nonce)) throw new SimLoopInvalid("fields.bindNonce must be 64 lowercase hex characters");
  return nonce;
}

function sessionOf(fields: Record<string, unknown>): string {
  const s = str(fields, "session_id");
  if (!SESSION.test(s)) throw new SimLoopInvalid("fields.session_id must be 1..256 chars of [A-Za-z0-9._:-]");
  return s;
}

// ---------------------------------------------------------------------------
// The transition (GrantLedger.Loops.cs ApplyLoopTransition)
// ---------------------------------------------------------------------------

/** The bound Claude process as the binding records it (its pid and the start time the custodian verified). */
export interface SimBoundProcess {
  pid: number | null;
  startedAtMs: number | null;
}

/** The custodian's check of the process connected to the pipe against the BOUND process — an OS fact, computed
 * by the custodian, never taken from the request (D7: correlation only). The simulator gets it from its injected
 * check, for the binding it read before the transition. */
export interface SimClientCheck {
  bound: SimBoundProcess;
  verdict: SimProcessCheck;
}

/** P3.4C-3 (contract §3.4(3)): the run record as a loop transition reads it in the same hold — null when the custodian
 * holds none (the run was never opened, a rollback removed its record, or the loop was minted before P3.4C-3). */
export interface SimRunView {
  status: string;
  terminal: boolean;
}

export interface SimLoopCaller {
  operator: boolean;
  /** For an automation request (spend_continuation, wake_arm, wake_consume): the connected process checked
   * against the bound one; null when it could not be checked. */
  client?: SimClientCheck | null;
  /** P3.4C-5 Increment 3 (§5.2): the derivation rules of a continuation or wake, and in the commit step the
   * re-measurement (absent: a refusal — every automation request is decided on the custodian's derivation). Returns the
   * derivation it checked. */
  automation?: { phase: "precheck" | "commit"; check: (loop: SimLoop, req: SimLoopRequest) => { derivationId: string; fingerprint: string; routeCode: string } };
}

type Step = { next: SimLoop; result: Record<string, unknown> } | { derived: SimLoop; refusal: SimLoopRefusal };

/**
 * Apply one transition to `loops` (mutated in place on success or on a custodian-derived end, like the
 * custodian's single ledger write). Refusals throw SimLoopRefusal, except wake_consume, which answers every
 * call that does not consume its claim with dispatchAuthorized:false (TD correction B).
 */
export function applyLoopTransition(loops: SimLoop[], repoKey: string, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number, observed: SimProcessCheck | null, runOf: (runId: string) => SimRunView | null): Record<string, unknown> {
  try {
    return apply(loops, repoKey, req, caller, nowMs, observed, runOf);
  } catch (e) {
    if (!(e instanceof SimLoopRefusal) || req.kind !== "wake_consume") throw e;
    const loop = loops.find((l) => l.repoKey === repoKey && l.runId === req.runId && l.loopId === req.loopId);
    const consumed = loop?.wakeClaims.some((c) => c.claimId === req.claimId && c.state === "consumed") === true;
    return { loopId: req.loopId, kind: "wake_consume", dispatchAuthorized: false, claimId: req.claimId, consumed, refusal: e.code, reason: e.message };
  }
}

function apply(loops: SimLoop[], repoKey: string, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number, observed: SimProcessCheck | null, runOf: (runId: string) => SimRunView | null): Record<string, unknown> {
  const index = loops.findIndex((l) => l.repoKey === repoKey && l.runId === req.runId);
  if (index < 0 || loops[index]!.loopId !== req.loopId) throw new SimLoopRefusal("UNKNOWN_LOOP", "this run has no automation loop with that id");
  const loop = loops[index]!;
  const replayed = replayOf(loop, caller, req);
  if (replayed) return replayed;
  if (LIVE_STATUSES.has(loop.status) && nowMs >= Date.parse(loop.deadlineAt)) {
    loops[index] = deriveEnd(loop, "expired", "run_seconds", nowMs);
    throw new SimLoopRefusal("LOOP_TERMINAL", "the loop's automation window ended; the loop is now expired");
  }
  // P3.4C-3 (§3.4(3)): a terminal or MISSING run record ends a live loop by derivation first; nothing is authorized.
  const run = LIVE_STATUSES.has(loop.status) ? runOf(req.runId) : undefined;
  if (run === null || run?.terminal === true) {
    loops[index] = deriveEnd(loop, "run_ended", run ? `run_${run.status}` : "run_record_missing", nowMs);
    throw new SimLoopRefusal("LOOP_TERMINAL", run
      ? `the run has ended (${run.status}); the loop ended with it and authorizes nothing`
      : "the custodian holds no run record for this loop's run; the loop ended and authorizes nothing");
  }
  guard(loop, req, caller);
  const step = stepOf(loop, req, caller, nowMs, observed);
  if ("derived" in step) {
    loops[index] = step.derived;
    throw step.refusal;
  }
  if (caller.automation?.phase === "precheck") return { precheck: true }; // every rule passed; nothing is written yet
  const revision = loop.loopRevision + 1;
  const result: Record<string, unknown> = { loopId: step.next.loopId, kind: req.kind, status: step.next.status, epoch: step.next.epoch, loopRevision: revision, ...step.result };
  const evidence: SimLoopEvent = { seq: loop.events.length + 1, kind: req.kind, requestId: req.requestId, caller: caller.operator ? "operator" : "implementer", at: iso(nowMs), requestDigest: req.digest, fromStatus: loop.status, toStatus: step.next.status, epoch: step.next.epoch, result: structuredClone(result) };
  loops[index] = { ...step.next, loopRevision: revision, events: [...loop.events, evidence] };
  return result;
}

/** The checks every transition passes before its kind is judged, in the custodian's order: terminal, the
 * operator-only resume, the epoch, the revision, the evidence cap. */
function guard(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller): void {
  if (!LIVE_STATUSES.has(loop.status)) throw new SimLoopRefusal("LOOP_TERMINAL", `the loop has ended (${loop.status}); no transition leaves a terminal state`);
  if (req.kind === "resume" && loop.pause && OPERATOR_ONLY_PAUSES.has(loop.pause.reason) && !caller.operator) {
    throw new SimLoopRefusal("CALLER_NOT_AUTHORIZED", `a loop paused for ${loop.pause.reason} resumes only on the operator surface with verified operator authority`);
  }
  if (req.epoch !== loop.epoch) throw new SimLoopRefusal("STALE_LOOP_EPOCH", `the loop is in epoch ${loop.epoch}, not ${req.epoch}`);
  if (req.baseLoopRevision !== loop.loopRevision) throw new SimLoopRefusal("STALE_LOOP_STATE", `the loop is at revision ${loop.loopRevision}, not ${req.baseLoopRevision}`);
  if (loop.events.length >= SIM_MAX_LOOP_EVENTS && req.kind !== "end") throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", `the loop's transition log is full (${SIM_MAX_LOOP_EVENTS}); only end is accepted`);
}

function stepOf(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number, observed: SimProcessCheck | null): Step {
  switch (req.kind) {
    case "bind":
      return bindStep(loop, req, nowMs, observed);
    case "rebind":
      return rebindStep(loop, req, nowMs, observed);
    case "spend_continuation":
      return spendStep(loop, req, caller, nowMs);
    case "wake_arm":
      return wakeArmStep(loop, req, caller, nowMs);
    case "wake_consume":
      return wakeConsumeStep(loop, req, caller, nowMs);
    case "pause":
      return pauseStep(loop, req, caller, nowMs);
    case "resume":
      return resumeStep(loop, nowMs);
    default:
      return endStep(loop, req, caller, nowMs);
  }
}

function bindStep(loop: SimLoop, req: SimLoopRequest, nowMs: number, observed: SimProcessCheck | null): Step {
  if (loop.status !== "unbound" || loop.binding) throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", loop.binding ? "the loop is already bound (the first binding wins)" : `the loop is ${loop.status}`);
  if (loop.bindNonce.usedAt !== null) throw new SimLoopRefusal("BIND_NONCE_INVALID", "the binding nonce was already used");
  if (nowMs > Date.parse(loop.bindNonce.expiresAt)) throw new SimLoopRefusal("BIND_NONCE_INVALID", "the binding nonce expired");
  const presented = Buffer.from(sha256(req.bindNonce!), "utf8");
  const stored = Buffer.from(loop.bindNonce.sha256, "utf8");
  if (presented.length !== stored.length || !timingSafeEqual(presented, stored)) throw new SimLoopRefusal("BIND_NONCE_INVALID", "the binding nonce does not match");
  const facts = processFacts(observed, req.claimedPid ?? null, nowMs);
  const op = newOperation(1, loop.epoch, "bind", nowMs);
  const next: SimLoop = { ...loop, status: "active", binding: { sessionId: req.sessionId!, state: "live", boundAt: iso(nowMs), reboundAt: null, process: facts }, bindNonce: { ...loop.bindNonce, usedAt: iso(nowMs) }, operations: [op] };
  return { next, result: { operationHandle: op.handle, binding: { state: "live", verified: facts.verified } } };
}

function rebindStep(loop: SimLoop, req: SimLoopRequest, nowMs: number, observed: SimProcessCheck | null): Step {
  if (!loop.binding || loop.status === "unbound") throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", "the loop is not bound; a rebind needs an earlier binding");
  if (loop.binding.sessionId !== req.sessionId) throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", "the loop is bound to another session; a rebind does not move it (the first binding wins)");
  const facts = processFacts(observed, req.claimedPid ?? null, nowMs);
  if (!facts.verified) throw new SimLoopRefusal("PROCESS_IDENTITY_UNVERIFIED", `the session's process identity could not be re-verified: ${facts.detail}`);
  const next: SimLoop = { ...loop, epoch: loop.epoch + 1, binding: { ...loop.binding, state: "live", reboundAt: iso(nowMs), process: facts } };
  const result: Record<string, unknown> = { binding: { state: "live", verified: true } };
  if (next.pause) result["pauseReason"] = next.pause.reason;
  return { next, result };
}

function spendStep(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number): Step {
  requireActiveVerified(loop);
  requireBoundCaller(loop, req, caller);
  if (loop.used.continuations >= loop.limits.continuations) {
    return { derived: deriveEnd(loop, "budget_exhausted", "continuations", nowMs), refusal: new SimLoopRefusal("LOOP_BUDGET_EXHAUSTED", `the continuation budget (${loop.limits.continuations}) is used up; the loop ended (budget_exhausted)`) };
  }
  const d = requireAutomation(loop, req, caller);
  const op = newOperation(loop.operations.length + 1, loop.epoch, "spend_continuation", nowMs);
  const next: SimLoop = { ...loop, used: { ...loop.used, continuations: loop.used.continuations + 1 }, operations: [...loop.operations, op], progress: { fingerprint: d.fingerprint, derivationId: d.derivationId, at: iso(nowMs), kind: "spend_continuation" } };
  return { next, result: { operationHandle: op.handle, continuationsUsed: next.used.continuations, continuationsLimit: next.limits.continuations, derivationId: d.derivationId, route: d.routeCode } };
}

/** §5.2: a continuation or wake is decided on the custodian's own derivation (RequireAutomationDerivation). */
function requireAutomation(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller): { derivationId: string; fingerprint: string; routeCode: string } {
  if (!caller.automation) throw new SimLoopRefusal("DERIVATION_STALE", "no custodian derivation is named: read the run's derivation section (list_user_records, sections [derivation]) and name its derivationId");
  return caller.automation.check(loop, req);
}

function wakeArmStep(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number): Step {
  requireActiveVerified(loop);
  requireBoundCaller(loop, req, caller);
  const op = loop.operations.at(-1);
  if (!op || op.handle !== req.operationHandle) throw new SimLoopRefusal("UNKNOWN_OPERATION_HANDLE", "the operation handle is not the loop's current custodian-issued operation");
  if (op.wakesUsed >= loop.limits.wakesPerOperation) throw new SimLoopRefusal("LOOP_BUDGET_EXHAUSTED", `this operation has used its idle-wake budget (${loop.limits.wakesPerOperation})`);
  if (loop.used.wakes >= loop.limits.wakesPerRun) throw new SimLoopRefusal("LOOP_BUDGET_EXHAUSTED", `the run's idle-wake budget (${loop.limits.wakesPerRun}) is used up`);
  const claim: SimWakeClaim = { claimId: newId("wc", loop.wakeClaims.length + 1), operationHandle: op.handle, epoch: loop.epoch, state: "armed", armedAt: iso(nowMs), armRequestId: req.requestId, consumedAt: null, consumeRequestId: null };
  const spent = { ...op, wakesUsed: op.wakesUsed + 1 };
  const next: SimLoop = { ...loop, used: { ...loop.used, wakes: loop.used.wakes + 1 }, operations: [...loop.operations.slice(0, -1), spent], wakeClaims: [...loop.wakeClaims, claim] };
  return { next, result: { claimId: claim.claimId, operationHandle: op.handle, wakesUsedOperation: spent.wakesUsed, wakesUsedRun: next.used.wakes } };
}

function wakeConsumeStep(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number): Step {
  const claim = loop.wakeClaims.find((c) => c.claimId === req.claimId);
  if (!claim) throw new SimLoopRefusal("UNKNOWN_WAKE_CLAIM", "no such wake claim");
  if (claim.state !== "armed") throw new SimLoopRefusal("WAKE_ALREADY_CONSUMED", "the wake claim was already consumed (one dispatch authorization per claim)");
  if (claim.epoch !== loop.epoch) throw new SimLoopRefusal("STALE_LOOP_EPOCH", `the wake claim was armed in epoch ${claim.epoch}; the loop is in epoch ${loop.epoch}`);
  if (loop.operations.at(-1)?.handle !== claim.operationHandle) throw new SimLoopRefusal("UNKNOWN_OPERATION_HANDLE", "the wake claim belongs to an earlier operation");
  requireActiveVerified(loop);
  requireBoundCaller(loop, req, caller);
  // P3.4C-5 Increment 3 (§5.2): a wake is dispatched only on the custodian's own derivation, as a continuation is.
  const d = requireAutomation(loop, req, caller);
  const consumed: SimWakeClaim = { ...claim, state: "consumed", consumedAt: iso(nowMs), consumeRequestId: req.requestId };
  const next: SimLoop = { ...loop, wakeClaims: loop.wakeClaims.map((c) => (c.claimId === claim.claimId ? consumed : c)), progress: { fingerprint: d.fingerprint, derivationId: d.derivationId, at: iso(nowMs), kind: "wake_consume" } };
  return { next, result: { dispatchAuthorized: true, claimId: claim.claimId, consumed: true, operationHandle: claim.operationHandle, derivationId: d.derivationId, route: d.routeCode } };
}

function pauseStep(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number): Step {
  if (loop.status !== "active") throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", `only an active loop pauses; this loop is ${describe(loop)}`);
  return { next: { ...loop, status: "paused", pause: { reason: req.reason!, detail: req.detail ?? "", at: iso(nowMs), by: caller.operator ? "operator" : "implementer" } }, result: { pauseReason: req.reason } };
}

function resumeStep(loop: SimLoop, nowMs: number): Step {
  if (loop.status !== "paused" || !loop.pause) throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", `only a paused loop resumes; this loop is ${describe(loop)}`);
  const next: SimLoop = { ...loop, status: "active", pause: null, resumedAt: iso(nowMs) };
  return { next, result: { resumedFrom: loop.pause.reason, resumedAt: next.resumedAt } };
}

function endStep(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller, nowMs: number): Step {
  const next: SimLoop = { ...loop, status: req.endStatus!, ended: { status: req.endStatus!, reason: req.reason ?? "", at: iso(nowMs), by: caller.operator ? "operator" : "implementer" } };
  return { next, result: { endReason: next.ended!.reason } };
}

/** TD decision on the Inc 9 escalation (GrantLedger.Loops.cs RequireBoundCaller): an automation request names
 * the BOUND session and comes from the bound Claude process's tree — that process still the instance the custodian
 * verified (same start time) and an ancestor of the connected process. Checked before the request changes
 * anything. Correlation, not authentication. */
function requireBoundCaller(loop: SimLoop, req: SimLoopRequest, caller: SimLoopCaller): void {
  const binding = loop.binding!;
  if (binding.sessionId !== req.sessionId) throw new SimLoopRefusal("SESSION_NOT_BOUND", "the request names a session the loop is not bound to");
  const c = caller.client ?? null;
  const same = c !== null && c.bound.pid === binding.process.pid && c.bound.startedAtMs === binding.process.startedAtMs;
  if (!c || !same || !c.verdict.verified) {
    const why = !c ? "the connected process could not be checked" : !same ? "the binding changed while the connected process was checked" : c.verdict.detail;
    throw new SimLoopRefusal("PROCESS_IDENTITY_UNVERIFIED", `the request does not come from the bound session's process: ${why}`);
  }
}

function requireActiveVerified(loop: SimLoop): void {
  if (loop.status !== "active") throw new SimLoopRefusal("INVALID_LOOP_TRANSITION", `the loop is ${describe(loop)}; it automates nothing`);
  if (loop.binding?.state !== "live" || loop.binding.process.verified !== true) throw new SimLoopRefusal("PROCESS_IDENTITY_UNVERIFIED", "the loop's binding has no custodian-verified process identity; it automates nothing");
}

function replayOf(loop: SimLoop, caller: SimLoopCaller, req: SimLoopRequest): Record<string, unknown> | null {
  if (req.requestId === loop.requestId) throw new SimLoopRefusal("REQUEST_ID_CONFLICT", "this request id minted the loop");
  const prior = loop.events.find((e) => e.caller !== CUSTODIAN && e.requestId === req.requestId);
  if (!prior) return null;
  if (prior.kind !== req.kind || prior.requestDigest !== req.digest || prior.caller !== (caller.operator ? "operator" : "implementer")) {
    throw new SimLoopRefusal("REQUEST_ID_CONFLICT", "this request id was already used for a different loop transition");
  }
  const result = structuredClone(prior.result ?? {});
  if (req.kind === "wake_consume") {
    result["dispatchAuthorized"] = false;
    result["replayed"] = true;
  }
  return result;
}

/** A custodian-derived end (GrantLedger.Loops.cs DeriveEnd): by the custodian, with its own evidence entry. */
export function deriveEnd(loop: SimLoop, status: string, reason: string, nowMs: number): SimLoop {
  const evidence: SimLoopEvent = { seq: loop.events.length + 1, kind: "derive", requestId: "", caller: CUSTODIAN, at: iso(nowMs), requestDigest: "", fromStatus: loop.status, toStatus: status, epoch: loop.epoch, result: { status, reason } };
  return { ...loop, status, ended: { status, reason, at: iso(nowMs), by: CUSTODIAN }, loopRevision: loop.loopRevision + 1, events: [...loop.events, evidence] };
}

/** Recovery U1 after a new boot (P3.4C-3 §2.4, GrantLedger.Recovery.cs RecoveredLoop) for one live loop: an active loop
 * pauses for the operator; a pause the implementer may clear becomes that operator-only pause (an operator-only pause
 * keeps its reason); an unbound loop ends — its one-time nonce lived only in the memory of the server that asked for
 * it, so it can never be bound now. */
export function recoveredLoop(loop: SimLoop, recoveryId: string, nowMs: number): SimLoop {
  let next: SimLoop;
  if (loop.status === "unbound") {
    next = { ...loop, status: "cancelled", ended: { status: "cancelled", reason: "unbindable after an OS restart", at: iso(nowMs), by: CUSTODIAN } };
  } else if (loop.status === "paused" && loop.pause && OPERATOR_ONLY_PAUSES.has(loop.pause.reason)) {
    next = loop;
  } else {
    const detail = loop.pause ? `recovered_after_os_restart (was ${loop.pause.reason})` : "recovered_after_os_restart";
    next = { ...loop, status: "paused", pause: { reason: "operator_action_required", detail, at: iso(nowMs), by: CUSTODIAN } };
  }
  const evidence: SimLoopEvent = { seq: loop.events.length + 1, kind: "recover", requestId: "", caller: CUSTODIAN, at: iso(nowMs), requestDigest: "", fromStatus: loop.status, toStatus: next.status, epoch: loop.epoch, result: { recoveryId, status: next.status } };
  return { ...next, loopRevision: loop.loopRevision + 1, events: [...loop.events, evidence], lastRecoveryId: recoveryId };
}

function processFacts(p: SimProcessCheck | null, claimedPid: number | null, nowMs: number): SimProcessCheck & { checkedAt: string } {
  const r = p ?? { pid: claimedPid, startedAtMs: null, clientPid: null, verified: false, detail: "no process check was available" };
  return { ...r, checkedAt: iso(nowMs) };
}

function newOperation(seq: number, epoch: number, issuedBy: string, nowMs: number): SimLoopOperation {
  return { handle: newId("op", seq), seq, epoch, issuedAt: iso(nowMs), issuedBy, wakesUsed: 0 };
}

function newId(prefix: string, seq: number): string {
  return `${prefix}-${seq}-${randomBytes(6).toString("hex")}`;
}

function describe(loop: SimLoop): string {
  return loop.pause ? `${loop.status} (${loop.pause.reason})` : loop.status;
}

// ---------------------------------------------------------------------------
// The loop section of list_user_records (contract §6) and selection (§7)
// ---------------------------------------------------------------------------

export function loopSection(loops: readonly SimLoop[], repoKey: string, runId: string, operatorView: boolean): Record<string, unknown> {
  const loop = loops.find((l) => l.repoKey === repoKey && l.runId === runId);
  const digest = sha256OfCanonicalJson({ repoKey, runId, loopId: loop?.loopId ?? null, loopRevision: loop?.loopRevision ?? 0, epoch: loop?.epoch ?? 0, status: loop?.status ?? null });
  if (!loop) return { protected: false, loopRevision: 0, loopDigest: digest, record: null };
  return { protected: true, loopRevision: loop.loopRevision, loopDigest: digest, record: operatorView ? structuredClone(loop) : implementerProjection(loop) };
}

/** The implementer projection (GrantLedger.Loops.cs ImplementerLoopProjection): an independent allowlist —
 * never the session id, the process facts, the nonce or the history. */
export function implementerProjection(l: SimLoop): Record<string, unknown> {
  const current = l.operations.at(-1)?.handle;
  return {
    loopId: l.loopId, status: l.status, epoch: l.epoch, loopRevision: l.loopRevision, startedAt: l.startedAt, deadlineAt: l.deadlineAt, grantId: l.grantId,
    grantUse: { loopsUsed: l.grantUse.loopsUsed, loopsTotal: l.grantUse.loopsTotal },
    limits: { ...l.limits },
    used: { ...l.used },
    remaining: { continuations: Math.max(0, l.limits.continuations - l.used.continuations), wakes: Math.max(0, l.limits.wakesPerRun - l.used.wakes) },
    binding: l.binding ? { state: l.binding.state, verified: l.binding.process.verified } : null,
    pause: l.pause ? { reason: l.pause.reason, at: l.pause.at } : null,
    resumedAt: l.resumedAt,
    progress: l.progress ? { fingerprint: l.progress.fingerprint, derivationId: l.progress.derivationId, at: l.progress.at, kind: l.progress.kind } : null,
    ended: l.ended ? { status: l.ended.status, reason: l.ended.reason, at: l.ended.at } : null,
    operations: l.operations.map((o) => ({ handle: o.handle, seq: o.seq, epoch: o.epoch, wakesUsed: o.wakesUsed, current: o.handle === current })),
    wakeClaims: l.wakeClaims.map((c) => ({ claimId: c.claimId, state: c.state, epoch: c.epoch, operationHandle: c.operationHandle })),
  };
}
