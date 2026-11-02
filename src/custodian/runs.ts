// The custodian run client (P3.4C-3): the engine's typed access to the custodian-owned run records (run_transition,
// contract §2–§5). The custodian computes every transition — the run's status and revision, operation ids, rounds,
// review acceptance, the items' statuses and the assessments' effects — from its own records; this client only names
// the run, the kind and its typed fields, each a claim the custodian validates.
//
// A refusal with a run code is RETURNED, not thrown: nothing was applied and the engine reacts to it (a terminal run,
// a busy run, evidence the custodian does not hold, a stale item revision…). A transport failure is fail-closed
// (CUSTODIAN_UNAVAILABLE / SERVER_NOT_TRUSTED, never a weaker fallback), and any other refusal is a fault.
//
// Digest binding does not authenticate evidence producers: the custodian holds what the engine reported and the
// digests bind its artifacts, but a process in the bound session's tree can still report false evidence (R1).

import { createHash } from "node:crypto";
import { uuidv7 } from "../common/ids.js";
import { toUnavailable } from "./grants.js";
import { custodianError, EVIDENCE_PART_BYTES, RUN_REFUSAL_CODES, type CustodianSurface, type RunRefusalCode, type RunTransitionFields, type RunTransitionKind, type RunTransitionResult } from "./protocol.js";
import type { CustodianTransport } from "./transport.js";

/** Which run a transition addresses: the repository (a locator; the custodian establishes its identity) and the run. */
export interface RunTarget {
  repositoryRoot: string;
  runId: string;
}

export type RunTransitionOutcome = { ok: true; data: RunTransitionResult } | { ok: false; code: RunRefusalCode; message: string };

const REFUSALS: ReadonlySet<string> = new Set(RUN_REFUSAL_CODES);

export function isRunRefusal(code: string | undefined): code is RunRefusalCode {
  return code !== undefined && REFUSALS.has(code);
}

export class CustodianRuns {
  constructor(private readonly transport: CustodianTransport) {}

  /** One run transition on `surface` (the implementer's, except recover and end, which the operator may also send).
   * Idempotent on `requestId`: a retry of the same request returns the stored result and applies nothing again. */
  async transition<K extends RunTransitionKind>(surface: CustodianSurface, target: RunTarget, kind: K, fields: RunTransitionFields[K], requestId: string = uuidv7()): Promise<RunTransitionOutcome> {
    const args = { repositoryRoot: target.repositoryRoot, runId: target.runId, kind, fields };
    const res = await this.transport.send(surface, "run_transition", args, requestId).catch(toUnavailable);
    if (res.ok) return { ok: true, data: (res.data ?? {}) as RunTransitionResult };
    if (isRunRefusal(res.code)) return { ok: false, code: res.code, message: res.error ?? "" };
    throw custodianError(res.code, res.error ?? "run_transition failed");
  }

  /**
   * Phase 5 F-i2-5: hand the custodian the bytes of a record its run record binds by digest (the baseline capture record,
   * a response set's disclosure record), in parts under the request limit (GrantLedger.HoldEvidence). The custodian keeps
   * it as redaction evidence only when the digest is one it binds; idempotent (a record already held answers at once).
   */
  async holdEvidence(surface: CustodianSurface, target: RunTarget, bytes: Buffer): Promise<void> {
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const parts = Math.max(1, Math.ceil(bytes.length / EVIDENCE_PART_BYTES));
    for (let part = 0; part < parts; part++) {
      const data = bytes.subarray(part * EVIDENCE_PART_BYTES, (part + 1) * EVIDENCE_PART_BYTES).toString("base64");
      const res = await this.transport.send(surface, "hold_evidence", { repositoryRoot: target.repositoryRoot, runId: target.runId, sha256, part, parts, data }, uuidv7()).catch(toUnavailable);
      if (!res.ok) throw custodianError(res.code, res.error ?? "hold_evidence failed");
      if ((res.data as { held?: unknown } | undefined)?.held === true) return;
    }
  }
}
