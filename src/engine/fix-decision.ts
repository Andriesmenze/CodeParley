// Phase 4 Increment 3 — the owner's decision on a delegated fix (contract §3.5).
//
// The custodian renders the proposal ITSELF (from the baseline bytes of its published capture and the postimage bytes it
// holds) and binds an owner's confirmation to the digest of exactly that rendering. The decision is the operator's: it is
// prepared and committed only on the operator surface (CustodianOperator; the custodian refuses any other caller class),
// from the CLI (`code-parley fix confirm|reject`) — never from the MCP server or the hooks (test/delegated-fix-layering).
//
// Phase 5 G-OP (contract §4.5, F5-17): the decision reads nothing from an engine data home. The operator names the
// repository and the run; the custodian holds the run under the repository's identity (a run of another repository is
// not found), and the proposal, its rendering and the intent all come from the custodian.

import { uuidv7 } from "../common/ids.js";
import { CustodianOperator } from "../custodian/operator.js";
import type { CustodianTransport } from "../custodian/transport.js";

/** Phase 1 of the owner's decision (operator surface): the custodian renders and prepares; nothing is recorded yet. */
export async function prepareFixDecision(transport: CustodianTransport, repositoryRoot: string, runId: string, operationId: string, decision: "confirm" | "reject"): Promise<{ authorizationRequestId: string; rendering: string; expiresAt: string }> {
  return new CustodianOperator(transport).prepareFixDecision(repositoryRoot, runId, operationId, decision, uuidv7());
}

/** Phase 2 (operator surface): the custodian renders again and commits only if nothing the operator was shown changed. */
export async function commitFixDecision(transport: CustodianTransport, authorizationRequestId: string): Promise<{ decision: string; operationStatus: string; confirmationId: string; renderingDigest: string; expiresAt: string | null }> {
  return new CustodianOperator(transport).commitFixDecision(authorizationRequestId);
}
