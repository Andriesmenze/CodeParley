// The custodian loop client (P3.4C-2): the engine's typed access to the custodian-owned loop lifecycle
// (loop_transition, contract §2–§5). The custodian computes every transition — status, epoch, budgets, the
// binding verdict, operation handles and wake claims — from its own record; this client only names the loop,
// the state it acted on (epoch + loop revision), the kind and its typed fields.
//
// A refusal with a loop code is RETURNED, not thrown: nothing was applied and the engine reacts to it (re-read
// a stale state, end a terminal loop, pause on an unverified identity…). A transport failure is fail-closed
// (CUSTODIAN_UNAVAILABLE / SERVER_NOT_TRUSTED, never a weaker fallback), and any other refusal is a fault.

import { uuidv7 } from "../common/ids.js";
import { toUnavailable } from "./grants.js";
import { custodianError, LOOP_REFUSAL_CODES, type CustodianSurface, type LoopRefusalCode, type LoopTransitionFields, type LoopTransitionKind } from "./protocol.js";
import type { CustodianTransport } from "./transport.js";

/** Which loop a transition addresses, and the state the caller acted on. */
export interface LoopTarget {
  repositoryRoot: string;
  runId: string;
  loopId: string;
  epoch: number;
  baseLoopRevision: number;
}

export type LoopTransitionOutcome = { ok: true; data: Record<string, unknown> } | { ok: false; code: LoopRefusalCode; message: string };

/** A wake_consume answer. `dispatchAuthorized` is true ONLY for the call that consumed the claim. */
export interface WakeConsumeOutcome {
  dispatchAuthorized: boolean;
  /** Why no dispatch was authorized (a refusal code, or "replayed"), or null when it was. */
  refusal: string | null;
  data: Record<string, unknown>;
}

const REFUSALS: ReadonlySet<string> = new Set(LOOP_REFUSAL_CODES);

export function isLoopRefusal(code: string | undefined): code is LoopRefusalCode {
  return code !== undefined && REFUSALS.has(code);
}

export class CustodianLoops {
  constructor(private readonly transport: CustodianTransport) {}

  /** One loop transition on `surface`. Idempotent on `requestId`: a retry of the same request returns the
   * stored result (a replayed wake_consume never authorizes again). */
  async transition<K extends LoopTransitionKind>(surface: CustodianSurface, target: LoopTarget, kind: K, fields: LoopTransitionFields[K], requestId: string = uuidv7()): Promise<LoopTransitionOutcome> {
    const args = { repositoryRoot: target.repositoryRoot, runId: target.runId, loopId: target.loopId, epoch: target.epoch, baseLoopRevision: target.baseLoopRevision, kind, fields };
    const res = await this.transport.send(surface, "loop_transition", args, requestId).catch(toUnavailable);
    if (res.ok) return { ok: true, data: res.data ?? {} };
    if (isLoopRefusal(res.code)) return { ok: false, code: res.code, message: res.error ?? "" };
    throw custodianError(res.code, res.error ?? "loop_transition failed");
  }

  /** Consume a wake claim (TD correction B): a dispatch is authorized ONLY by an ok answer whose
   * `dispatchAuthorized` is literally true. Every other answer — a replay, a refusal, a malformed or partial
   * response — authorizes nothing. `sessionId` is the asking hook invocation's own session id. */
  async wakeConsume(surface: CustodianSurface, target: LoopTarget, claimId: string, sessionId: string, requestId: string = uuidv7(), derivationId?: string): Promise<WakeConsumeOutcome> {
    const out = await this.transition(surface, target, "wake_consume", { claimId, session_id: sessionId, ...(derivationId ? { derivation_id: derivationId } : {}) }, requestId);
    if (!out.ok) return { dispatchAuthorized: false, refusal: out.code, data: {} };
    const authorized = out.data["dispatchAuthorized"] === true && out.data["replayed"] !== true;
    const refusal = authorized ? null : typeof out.data["refusal"] === "string" ? (out.data["refusal"] as string) : out.data["replayed"] === true ? "replayed" : "not_authorized";
    return { dispatchAuthorized: authorized, refusal, data: out.data };
  }
}
