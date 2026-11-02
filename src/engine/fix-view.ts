// Phase 4 Increment 3 — what the originating session and the owner READ of a delegated fix (contract §3.7): the custodian's
// rendering of a held proposal and the run's fix and application records. Reads only — the owner's decision is
// engine/fix-decision.ts (operator surface, CLI only); the application is engine/fix-apply.ts.

import { isDomainError } from "../common/errors.js";
import { CustodianGrants, type FixRendering } from "../custodian/grants.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import type { CustodianSurface, UserRecordListing } from "../custodian/protocol.js";
import type { CustodianTransport } from "../custodian/transport.js";
import type { Loaded, RunHandle } from "./engine-env.js";

export function custodianTransportOf(le: Loaded): CustodianTransport {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  return gate.transport;
}

/** A read on the surface this account reaches: the implementer's pipe (the MCP server, an implementer's CLI), else the
 * operator's (an operator's CLI; its account reaches only that pipe) — the same records either way. */
async function onReachableSurface<T>(le: Loaded, read: (s: CustodianSurface) => Promise<T>): Promise<T> {
  const surfaces: CustodianSurface[] = le.env.custodianReadSurface === "operator" ? ["operator"] : le.env.custodianReadSurface === "implementer" ? ["implementer"] : ["implementer", "operator"];
  let last: unknown = null;
  for (const s of surfaces) {
    try {
      return await read(s);
    } catch (e) {
      if (!(isDomainError(e) && e.code === "CUSTODIAN_UNAVAILABLE")) throw e;
      last = e;
    }
  }
  throw last;
}

/** The custodian's rendering of proposal `operationId` (the same bytes on either surface). */
/** A run as the fix views address it: its id and repository (a local handle, or one the operator names with `--repo`:
 * the custodian resolves the repository and holds the run under it). */
export type FixRunRef = Pick<RunHandle, "runId"> & { meta: Pick<RunHandle["meta"], "repository_root"> };

export async function fixRenderingOf(le: Loaded, run: FixRunRef, operationId: string): Promise<FixRendering> {
  const grants = new CustodianGrants(custodianTransportOf(le));
  return onReachableSurface(le, (s) => grants.renderFixProposal(s, run.meta.repository_root, run.runId, operationId));
}

/** The run's custodian records (the run section), for listing its delegated fixes. */
export async function fixRunSectionOf(le: Loaded, run: FixRunRef): Promise<UserRecordListing> {
  const grants = new CustodianGrants(custodianTransportOf(le));
  return onReachableSurface(le, (s) => grants.listUserRecords(s, run.meta.repository_root, run.runId, ["run"]));
}

export interface FixSummary {
  proposal_id: string;
  status: string;
  proposal: { proposal_digest: string; change_count: number; total_bytes: number; expires_at: string; retired: string | null; changes: { path: string; kind: string }[] } | null;
  owner_decision: { decision: string; expires_at: string | null; consumed_by: string | null } | null;
  violations: { kind: string; path: string | null }[];
  applications: { apply_operation_id: string; status: string }[];
}

/** The run's delegated fixes as the custodian holds them (no content), for get_review_status. Null: not a protected run. */
export async function fixesOf(le: Loaded, run: RunHandle): Promise<FixSummary[] | null> {
  const ops = ((await fixRunSectionOf(le, run)).run?.record as { operations?: Record<string, unknown>[] } | null)?.operations ?? null;
  if (ops === null) return null;
  const applies = ops.filter((o) => o["kind"] === "apply");
  return ops.filter((o) => o["kind"] === "fix").map((o): FixSummary => {
    const outcome = (o["outcome"] ?? null) as Record<string, unknown> | null;
    const p = (outcome?.["proposal"] ?? null) as Record<string, unknown> | null;
    const c = (outcome?.["confirmation"] ?? null) as Record<string, unknown> | null;
    const id = String(o["operationId"]);
    return {
      proposal_id: id,
      status: String(o["status"]),
      proposal: p
        ? {
            proposal_digest: String(p["proposalDigest"]), change_count: Number(p["changeCount"]), total_bytes: Number(p["totalBytes"]), expires_at: String(p["expiresAt"]),
            retired: typeof p["retiredReason"] === "string" ? p["retiredReason"] : null,
            changes: ((p["changes"] ?? []) as Record<string, unknown>[]).map((x) => ({ path: String(x["path"]), kind: String(x["kind"]) })),
          }
        : null,
      owner_decision: c ? { decision: String(c["decision"]), expires_at: typeof c["expiresAt"] === "string" ? c["expiresAt"] : null, consumed_by: typeof c["consumedBy"] === "string" ? c["consumedBy"] : null } : null,
      violations: ((outcome?.["violations"] ?? []) as { kind: string; path: string | null }[]).slice(0, 20),
      applications: applies.filter((a) => (a["begin"] as Record<string, unknown>)["fixOperationId"] === id).map((a) => ({ apply_operation_id: String(a["operationId"]), status: String(a["status"]) })),
    };
  });
}
