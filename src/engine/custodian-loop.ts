// P3.4C-2: the engine's access to the CUSTODIAN-owned loop record (contract §2–§7).
//
// The custodian holds the loop's authority — its status, epoch, budgets, deadline, the binding verdict, the
// operation handles and the wake claims — and computes every transition itself. The engine is an untrusted
// client: it reads the custodian's IMPLEMENTER projection and requests typed transitions. The run's local
// `state.continuation` stays a CACHE for what the custodian does not own — the session correlation (session
// id, binding state, the CLAUDE_PID it bound with), the turn, interrupts, the last continuation and the wake
// waiter bookkeeping — and every automation decision first overlays the custodian's authority onto it, so an
// edited local record (a forged loop, reset budgets, a cleared pause, a raised epoch) has no effect.
//
// Fail-closed: every exchange goes through the protected-loop gate; a custodian that cannot be reached, that
// reports no loop section or whose projection is malformed is never read as "not protected".

import { readFile } from "node:fs/promises";
import { DomainError } from "../common/errors.js";
import { CustodianGrants, custodianDerivationOf } from "../custodian/grants.js";
import { CustodianLoops, type LoopTarget, type LoopTransitionOutcome, type WakeConsumeOutcome } from "../custodian/loops.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import { CUSTODIAN_UNAVAILABLE, type CustodianDerivation, type CustodianSurface, type LoopTransitionFields, type LoopTransitionKind } from "../custodian/protocol.js";
import type { NextAction } from "../policy/continuation.js";
import { CustodianLoopSchema, LOOP_SCHEMA, type CustodianLoop, type LoopRecord, type LoopStatus } from "../schemas/continuation.js";
import type { Loaded, RunHandle } from "./engine-env.js";

/** The prefix of an end reason the ENGINE gives the custodian. The custodian records such a loop `run_ended`
 * (it attests no completion); the engine's own label (ready, a run budget) survives in the reason. */
const ENGINE_END = "engine:";
const LIVE: ReadonlySet<string> = new Set(["unbound", "active", "paused"]);

function clients(le: Loaded): { grants: CustodianGrants; loops: CustodianLoops } {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  return { grants: new CustodianGrants(gate.transport), loops: new CustodianLoops(gate.transport) };
}

const failClosed = (why: string): DomainError => new DomainError(CUSTODIAN_UNAVAILABLE, `${why}; nothing automated proceeds`, { retryable: false, details: { outcome: "not_delivered" } });

/**
 * The run's custodian loop (the implementer projection); null when the custodian holds no loop for the run —
 * the run is not protected. Throws fail-closed when no trusted custodian answers, when it reports no loop
 * section, or when the projection is malformed: none of these means "not protected".
 */
export async function readCustodianLoop(le: Loaded, run: RunHandle): Promise<CustodianLoop | null> {
  const listing = await clients(le).grants.listUserRecords("implementer", run.meta.repository_root, run.runId);
  const section = listing.loop;
  if (!section) throw failClosed("the custodian did not report this run's loop section, so whether the run is protected cannot be established");
  if (!section.protected) return null;
  const parsed = CustodianLoopSchema.safeParse(section.record);
  if (!parsed.success) throw failClosed("the custodian's loop projection is malformed");
  return parsed.data;
}

/**
 * P3.4C-5 Increment 4 (F-3-3): the custodian's own loop record for a DISPLAY, on whichever surface this account reaches
 * (the operator's `loop show` reaches only the operator pipe). Null: the run is not protected. A display correction only —
 * every decision still reads the implementer projection (readCustodianLoop). The operator's projection is the full record:
 * its latest operation is the current one, and its binding's verification is its process's.
 */
/**
 * The operator surface's loop record (the complete LoopRecord, serialized by the custodian) in the shape of the implementer
 * projection the display reads: each operation's `current`, the binding's verdict from its process facts, and — the C#
 * custodian omits a null member (Phase 5 F-i2-5, VERIFIED on the VM) — the optional members as null or empty.
 */
export function operatorLoopShape(record: Record<string, unknown>): Record<string, unknown> {
  const ops = Array.isArray(record["operations"]) ? (record["operations"] as Record<string, unknown>[]) : [];
  const binding = record["binding"] as Record<string, unknown> | null | undefined;
  return {
    ...record,
    pause: record["pause"] ?? null,
    resumedAt: record["resumedAt"] ?? null,
    ended: record["ended"] ?? null,
    wakeClaims: record["wakeClaims"] ?? [],
    operations: ops.map((o, i) => ({ ...o, current: i === ops.length - 1 })),
    binding: binding ? { ...binding, verified: (binding["process"] as Record<string, unknown> | null | undefined)?.["verified"] === true } : null,
  };
}

export async function custodianLoopForDisplay(le: Loaded, run: CustodianRunRef): Promise<CustodianLoop | null> {
  let last: unknown = null;
  for (const surface of ["implementer", "operator"] as const) {
    try {
      const listing = await clients(le).grants.listUserRecords(surface, run.meta.repository_root, run.runId);
      const section = listing.loop;
      if (!section) throw failClosed("the custodian did not report this run's loop section");
      if (!section.protected) return null;
      const record = section.record as Record<string, unknown>;
      const parsed = CustodianLoopSchema.safeParse(surface === "operator" ? operatorLoopShape(record) : record);
      if (!parsed.success) throw failClosed("the custodian's loop projection is malformed");
      return parsed.data;
    } catch (e) {
      last = e;
      if (!wrongSurface(e)) throw e;
    }
  }
  throw last;
}

/** Phase 5 F-i2-5: what the custodian needs to name a run — its id and the repository root it resolves itself. A local
 * run handle is one; a run the Linux operator names by `--repo` and id (the operator cannot read the implementer's run
 * store) is one too. */
export type CustodianRunRef = Pick<RunHandle, "runId"> & { meta: Pick<RunHandle["meta"], "repository_root"> };

function target(run: RunHandle, c: CustodianLoop): LoopTarget {
  return { repositoryRoot: run.meta.repository_root, runId: run.runId, loopId: c.loopId, epoch: c.epoch, baseLoopRevision: c.loopRevision };
}

/** One transition against the loop's current epoch and revision (implementer surface). */
export function requestTransition<K extends LoopTransitionKind>(le: Loaded, run: RunHandle, c: CustodianLoop, kind: K, fields: LoopTransitionFields[K]): Promise<LoopTransitionOutcome> {
  return clients(le).loops.transition("implementer", target(run, c), kind, fields);
}

/** Consume a wake claim: only the call that consumed it authorizes a dispatch (TD correction B). `sessionId` is
 * the asking hook invocation's own session id, from its host input — never the run's local record. */
export function requestWakeConsume(le: Loaded, run: RunHandle, c: CustodianLoop, claimId: string, sessionId: string, derivationId?: string): Promise<WakeConsumeOutcome> {
  return clients(le).loops.wakeConsume("implementer", target(run, c), claimId, sessionId, undefined, derivationId);
}

/**
 * P3.4C-5 Increment 3 (§5.1, §5.4): the custodian's protected derivation of the run — the authority for a protected run's
 * route and progress. The run's run.json bytes go with the request (the custodian verifies them against its declaration
 * digest). An unavailable derivation says why; every automation decision then fails closed.
 */
export async function readCustodianDerivation(le: Loaded, run: RunHandle, surface: CustodianSurface = "implementer"): Promise<CustodianDerivation> {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  const runJson = await readFile(run.paths.runJson).catch(() => null);
  if (!runJson) return { available: false, authority: "custodian", code: "RUN_JSON_UNREADABLE", detail: "the run's run.json could not be read; the custodian derives nothing without it" };
  return custodianDerivationOf(gate.transport, surface, run.meta.repository_root, run.runId, runJson);
}

/**
 * §5.4: the derivation a display presents for a run the local copy marks protected (null: not protected — the local
 * derivation is the attended one). Read on whichever surface this account reaches; a custodian that cannot be asked
 * yields an unavailable derivation (the display then labels its local derivation non-authoritative).
 */
export async function derivationForDisplay(le: Loaded, run: RunHandle, protectedRun: boolean): Promise<CustodianDerivation | null> {
  if (!protectedRun) return null;
  let last = "no custodian surface could be reached";
  for (const surface of ["implementer", "operator"] as const) {
    try {
      return await readCustodianDerivation(le, run, surface);
    } catch (e) {
      last = e instanceof Error ? e.message : String(e);
      if (!wrongSurface(e)) break;
    }
  }
  return { available: false, authority: "custodian", code: CUSTODIAN_UNAVAILABLE, detail: last.slice(0, 300) };
}

/** The custodian derivation's route as a next action. */
export function routeOfDerivation(d: Extract<CustodianDerivation, { available: true }>): NextAction {
  return { code: d.route.code, kind: d.route.kind as NextAction["kind"], reason: d.route.reason, ...(d.route.pause ? { pause: d.route.pause as NextAction["pause"] } : {}), ...(d.route.end ? { end: d.route.end as NextAction["end"] } : {}) } as NextAction;
}

/** A custodian refusal or failure, as one line (the custodian's trailing "(CODE)" dropped). */
export function refusalText(out: LoopTransitionOutcome | null | undefined, fallback: string): string {
  if (!out) return fallback;
  return out.ok ? "applied" : out.message.replace(/ \([A-Z_]{3,64}\)$/, "") || out.code;
}

/** A fail-safe pause: it only reduces automation, so a stale state is re-read once; a paused or ended loop is
 * fine. Returns the custodian loop after it, or null when the custodian could not be asked. */
export async function requestPause(le: Loaded, run: RunHandle, reason: string, detail: string): Promise<CustodianLoop | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const c = await readCustodianLoop(le, run).catch(() => null);
    if (!c || c.status !== "active") return c;
    const out = await requestTransition(le, run, c, "pause", { reason, detail: detail.slice(0, 500) }).catch(() => null);
    if (out?.ok) return readCustodianLoop(le, run).catch(() => null);
    if (out && out.code !== "STALE_LOOP_STATE" && out.code !== "STALE_LOOP_EPOCH") return c;
  }
  return null;
}

/** End the loop (terminal, irreversible): the engine's own label rides in the reason. A stale state is re-read
 * once; an ended loop is fine. */
export async function requestEnd(le: Loaded, run: RunHandle, label: string, reason: string, status: "cancelled" | "run_ended" = "run_ended"): Promise<CustodianLoop | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const c = await readCustodianLoop(le, run).catch(() => null);
    if (!c || !LIVE.has(c.status)) return c;
    const out = await requestTransition(le, run, c, "end", { status, reason: `${ENGINE_END}${label}:${reason}`.slice(0, 500) }).catch(() => null);
    if (out?.ok) return readCustodianLoop(le, run).catch(() => null);
    if (out && out.code !== "STALE_LOOP_STATE" && out.code !== "STALE_LOOP_EPOCH") return c;
  }
  return null;
}

/** The local status for a custodian status: an engine-ended loop is `run_ended` custodian-side, and the engine's
 * own label (ready, a run budget) is in its reason. */
function localStatusOf(c: CustodianLoop): LoopStatus {
  const r = c.ended?.reason ?? "";
  if (c.status === "run_ended" && r.startsWith(ENGINE_END)) {
    const label = r.slice(ENGINE_END.length).split(":")[0];
    if (label === "ready" || label === "budget_exhausted") return label;
  }
  return c.status;
}

function localEndReason(reason: string): string {
  return reason.startsWith(ENGINE_END) ? reason.split(":").slice(2).join(":") : reason;
}

/**
 * The engine's working loop: the local cache with the custodian's AUTHORITY laid over it. The local binding
 * keeps its correlation (session id, binding state, the CLAUDE_PID it bound with) but takes the custodian's
 * epoch and verdict; a binding the custodian does not hold is dropped.
 */
export function overlay(local: LoopRecord, c: CustodianLoop): LoopRecord {
  const binding = c.binding && local.binding
    ? { ...local.binding, epoch: c.epoch, process: local.binding.process ? { ...local.binding.process, verified: c.binding.verified } : null }
    : null;
  const status = localStatusOf(c);
  return {
    ...local,
    loop_id: c.loopId,
    status,
    started_at: c.startedAt,
    deadline_at: c.deadlineAt,
    grant_id: c.grantId,
    grant_use: { source: "custodian", loop_id: c.loopId, request_id: local.grant_use?.request_id ?? "", loops_used: c.grantUse.loopsUsed, loops_total: c.grantUse.loopsTotal },
    limits: { continuations: c.limits.continuations, wakes_per_operation: c.limits.wakesPerOperation, wakes_per_run: c.limits.wakesPerRun, run_seconds: c.limits.runSeconds },
    // `used.wakes` is the wakes DELIVERED (the claims the custodian authorized); the custodian's own count also
    // includes claims reserved and not yet consumed — that is the budget arming is judged against (reservedWakes).
    used: { continuations: c.used.continuations, wakes: c.wakeClaims.filter((w) => w.state === "consumed").length },
    binding,
    pause: c.pause ? { reason: c.pause.reason, detail: local.pause?.reason === c.pause.reason ? local.pause.detail : "", at: c.pause.at } : null,
    resumed_at: c.resumedAt,
    ended: c.ended ? { status, reason: localEndReason(c.ended.reason), at: c.ended.at } : null,
  };
}

/** A fresh local cache for a custodian loop the engine holds no local record of. */
export function cacheOf(c: CustodianLoop, requestId: string, nowIso: string): LoopRecord {
  const blank: LoopRecord = {
    schema: LOOP_SCHEMA,
    loop_id: c.loopId,
    status: c.status,
    started_at: c.startedAt,
    deadline_at: c.deadlineAt,
    grant_id: c.grantId,
    grant_use: { source: "custodian", loop_id: c.loopId, request_id: requestId, loops_used: c.grantUse.loopsUsed, loops_total: c.grantUse.loopsTotal },
    limits: { continuations: 0, wakes_per_operation: 0, wakes_per_run: 0, run_seconds: 1 },
    used: { continuations: 0, wakes: 0 },
    // The binding nonce is the custodian's (it keeps only its hash); this cache holds none of it.
    bind_nonce: { sha256: "0".repeat(64), issued_at: c.startedAt, expires_at: c.startedAt, used_at: null },
    binding: null,
    pause: null,
    resumed_at: null,
    ended: null,
    wakes: [],
    interrupts: [],
    last_user_prompt_at: null,
    turn: { active: true, at: nowIso },
    last_continuation: null,
  };
  return overlay(blank, c);
}

/** The custodian's current operation handle (the one a wake is armed against), or null before bind. */
export function currentHandle(c: CustodianLoop): string | null {
  return c.operations.find((o) => o.current)?.handle ?? null;
}

/** The run's wake budget as the custodian spends it: every claim it reserved, consumed or not. */
export function reservedWakes(c: CustodianLoop): number {
  return c.used.wakes;
}

// ---------------------------------------------------------------------------
// Operator actions (the CLI: code-parley loop stop / resume)
// ---------------------------------------------------------------------------

/** The few loop facts an operator transition needs, from either surface's projection (the operator projection
 * is the full record, the implementer projection its allowlist; both carry these). */
interface LoopHead {
  loopId: string;
  status: string;
  epoch: number;
  loopRevision: number;
  pauseReason: string | null;
}

async function readLoopHead(le: Loaded, run: CustodianRunRef, surface: CustodianSurface): Promise<LoopHead | null> {
  const section = (await clients(le).grants.listUserRecords(surface, run.meta.repository_root, run.runId)).loop;
  if (!section) throw failClosed("the custodian did not report this run's loop section");
  if (!section.protected || !section.record) return null;
  const r = section.record;
  const pause = r["pause"] as { reason?: unknown } | null | undefined;
  if (typeof r["loopId"] !== "string" || typeof r["status"] !== "string" || !Number.isInteger(r["epoch"]) || !Number.isInteger(r["loopRevision"])) throw failClosed("the custodian's loop projection is malformed");
  return { loopId: r["loopId"], status: r["status"], epoch: r["epoch"] as number, loopRevision: r["loopRevision"] as number, pauseReason: typeof pause?.reason === "string" ? pause.reason : null };
}

/** Did this surface refuse the caller, or was it unreachable without delivering anything (try the next one)? */
function wrongSurface(e: unknown): boolean {
  if (!(e instanceof DomainError)) return false;
  return e.code === "CALLER_NOT_AUTHORIZED" || (e.code === CUSTODIAN_UNAVAILABLE && e.details?.["outcome"] === "not_delivered");
}

export type OperatorLoopOutcome =
  | { applied: true; status: string; surface: CustodianSurface }
  | { applied: false; code: string; reason: string; status: string | null };

/**
 * An operator action on the custodian's loop. It goes to the OPERATOR surface (the pipe an elevated operator
 * reaches; the custodian's OS caller classification is the authority). Only an action the implementer may take
 * as well — ending a loop, or resuming a pause that is not operator-only — falls back to the implementer surface
 * (the pipe a same-account, non-elevated operator reaches). Resuming an operator-only pause never falls back.
 */
async function operatorTransition(le: Loaded, run: CustodianRunRef, decide: (head: LoopHead) => { kind: "end"; fields: LoopTransitionFields["end"] } | { kind: "resume"; fields: LoopTransitionFields["resume"]; operatorOnly: boolean } | string): Promise<OperatorLoopOutcome> {
  let last: OperatorLoopOutcome = { applied: false, code: CUSTODIAN_UNAVAILABLE, reason: "the custodian could not be reached", status: null };
  for (const surface of ["operator", "implementer"] as const) {
    let head: LoopHead | null;
    try {
      head = await readLoopHead(le, run, surface);
    } catch (e) {
      last = { applied: false, code: e instanceof DomainError ? e.code : "INTERNAL", reason: e instanceof Error ? e.message : String(e), status: null };
      if (wrongSurface(e)) continue;
      return last;
    }
    if (!head) return { applied: false, code: "INVALID_ARGUMENT", reason: "the custodian holds no automation loop for this run", status: null };
    const d = decide(head);
    if (typeof d === "string") return { applied: false, code: "INVALID_LOOP_TRANSITION", reason: d, status: head.status };
    const t: LoopTarget = { repositoryRoot: run.meta.repository_root, runId: run.runId, loopId: head.loopId, epoch: head.epoch, baseLoopRevision: head.loopRevision };
    let out: LoopTransitionOutcome;
    try {
      out = d.kind === "end" ? await clients(le).loops.transition(surface, t, "end", d.fields) : await clients(le).loops.transition(surface, t, "resume", d.fields);
    } catch (e) {
      last = { applied: false, code: e instanceof DomainError ? e.code : "INTERNAL", reason: e instanceof Error ? e.message : String(e), status: head.status };
      if (wrongSurface(e) && !(d.kind === "resume" && d.operatorOnly)) continue;
      return last;
    }
    if (out.ok) return { applied: true, status: String(out.data["status"]), surface };
    last = { applied: false, code: out.code, reason: refusalText(out, out.code), status: head.status };
    if (out.code !== "CALLER_NOT_AUTHORIZED" || (d.kind === "resume" && d.operatorOnly)) return last;
  }
  return last;
}

/** The operator cancels the run's custodian loop (terminal, irreversible). An ended loop is left as it is. */
export function operatorEndLoop(le: Loaded, run: CustodianRunRef, reason: string): Promise<OperatorLoopOutcome> {
  return operatorTransition(le, run, (head) => (LIVE.has(head.status) ? { kind: "end", fields: { status: "cancelled", reason: `operator: ${reason}`.slice(0, 500) } } : `the loop has already ended (${head.status})`));
}

/** The operator resumes the run's paused custodian loop. A pause the implementer may not clear
 * (operator_action_required, user_decision_required) is resumed on the operator surface only. */
export function operatorResumeLoopAt(le: Loaded, run: CustodianRunRef): Promise<OperatorLoopOutcome> {
  return operatorTransition(le, run, (head) =>
    head.status === "paused"
      ? { kind: "resume", fields: {}, operatorOnly: head.pauseReason === "operator_action_required" || head.pauseReason === "user_decision_required" }
      : `the custodian's loop is ${head.status}, not paused; nothing to resume`,
  );
}

// ---------------------------------------------------------------------------
// The one-time binding nonce, held IN MEMORY only
// ---------------------------------------------------------------------------

/**
 * The custodian returns a loop's binding nonce once, to the start that minted it, and keeps only its hash. This
 * process keeps the preimage in memory — never on disk — until the nonce expires, so start_review_loop called
 * again in the same server (before the host's hook bound the loop) can hand the same nonce back, as the former
 * re-issued one did. Another process, or a later call, cannot recover it: the loop then cannot be bound.
 */
const nonces = new Map<string, { nonce: string; expiresAtMs: number }>();

export function rememberNonce(run: RunHandle, loopId: string, nonce: string, expiresAtMs: number): void {
  for (const [k, v] of nonces) if (v.expiresAtMs <= expiresAtMs - 3_600_000) nonces.delete(k);
  nonces.set(`${run.repoKey}\u0000${run.runId}\u0000${loopId}`, { nonce, expiresAtMs });
}

export function recallNonce(run: RunHandle, loopId: string, nowMs: number): string | null {
  const key = `${run.repoKey}\u0000${run.runId}\u0000${loopId}`;
  const v = nonces.get(key);
  if (!v) return null;
  if (nowMs >= v.expiresAtMs) {
    nonces.delete(key);
    return null;
  }
  return v.nonce;
}
