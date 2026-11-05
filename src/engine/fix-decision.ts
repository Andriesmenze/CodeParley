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

import { DomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import { CustodianGrants, type FixRendering } from "../custodian/grants.js";
import { CustodianOperator, type FixListing, type FixListingEntry, type PreparedFixDecision } from "../custodian/operator.js";
import type { CustodianTransport } from "../custodian/transport.js";

/** Step 7.1: the listing's and the prepared decision's types, for `fix review` (which reaches the operator client only through
 * this module). */
export type { FixDecisionFacts, FixListing, FixListingEntry, PreparedFixDecision } from "../custodian/operator.js";

/** Phase 1 of the owner's decision (operator surface): the custodian renders and prepares; nothing is recorded yet. */
export async function prepareFixDecision(transport: CustodianTransport, repositoryRoot: string, runId: string, operationId: string, decision: "confirm" | "reject"): Promise<{ authorizationRequestId: string; rendering: string; expiresAt: string }> {
  return new CustodianOperator(transport).prepareFixDecision(repositoryRoot, runId, operationId, decision, uuidv7());
}

/** Phase 2 (operator surface): the custodian renders again and commits only if nothing the operator was shown changed. */
export async function commitFixDecision(transport: CustodianTransport, authorizationRequestId: string): Promise<{ decision: string; operationStatus: string; confirmationId: string; renderingDigest: string; expiresAt: string | null }> {
  return new CustodianOperator(transport).commitFixDecision(authorizationRequestId);
}

// ---- Step 7.1 (`fix review`, operator surface only): the listing, the rendering for review, the guided preparation ----

/** The delegated fixes the custodian holds (all repositories, or the identity `repositoryRoot` resolves to). */
export async function listFixProposals(transport: CustodianTransport, repositoryRoot: string | null): Promise<FixListing> {
  return new CustodianOperator(transport).listFixProposals(repositoryRoot);
}

/** The custodian's rendering of a listed fix, read on the operator surface (the operator's account reaches only that). */
export async function renderListedFix(transport: CustodianTransport, entry: FixListingEntry): Promise<FixRendering> {
  if (entry.repositoryRoot === null) throw new DomainError("INVALID_ARGUMENT", "this fix has no repository path that resolves to its identity");
  return new CustodianGrants(transport).renderFixProposal("operator", entry.repositoryRoot, entry.runId, entry.operationId);
}

/** Phase 1 of a guided decision: prepared only for the listed proposal and the rendering reviewed (all three expected
 * values; the custodian refuses SELECTION_STALE otherwise). */
export async function prepareGuidedFixDecision(transport: CustodianTransport, entry: FixListingEntry, reviewedRenderingDigest: string, decision: "confirm" | "reject"): Promise<PreparedFixDecision> {
  if (entry.repositoryRoot === null) throw new DomainError("INVALID_ARGUMENT", "this fix has no repository path that resolves to its identity");
  return new CustodianOperator(transport).prepareFixDecision(entry.repositoryRoot, entry.runId, entry.operationId, decision, uuidv7(), {
    repoKey: entry.repoKey, proposalDigest: entry.proposalDigest, renderingDigest: reviewedRenderingDigest,
  });
}
