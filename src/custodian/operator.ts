// The operator side of the custodian grant store (P3.4C-0): minting a grant (two-phase prepare→commit),
// revoking, and listing. ONLY the CLI path (src/cli/loop-commands.ts → engine/loop-authority.ts) imports
// this module; neither the MCP server nor the hooks can reach it (test/layering.test.ts). CLI-only
// reachability is layering, not the security boundary — the custodian decides operator authority from the
// OS caller classification (an elevated operator token, assurance L1); a non-operator caller is refused
// CALLER_NOT_AUTHORIZED whatever imports this (decision 5).

import { uuidv7 } from "../common/ids.js";
import { custodianError, type ConfigAction, type ConfigCommit, type ConfigRecordKind, type GrantListing, type MintResult, type PreparedConfigRecord, type PreparedGrant, type PreparedUserRecord, type UserRecordCommit, type UserRecordKind } from "./protocol.js";
import { grantListingOf, toUnavailable } from "./grants.js";
import type { CustodianResponse, CustodianOp } from "./protocol.js";
import type { CustodianTransport } from "./transport.js";

export class CustodianOperator {
  constructor(private readonly transport: CustodianTransport) {}

  private async op(op: CustodianOp, args: Record<string, unknown>, requestId: string): Promise<CustodianResponse> {
    return this.transport.send("operator", op, args, requestId).catch(toUnavailable);
  }

  /** Phase 1 of a grant: the custodian establishes the repository's identity and records a time-boxed
   * intent. Its `rendering` is what the operator confirms; nothing is granted until `commit`.
   * REQUEST_ID_CONFLICT when the request id is pending or was already committed. */
  async prepareGrant(repositoryRoot: string, loops: number, minutes: number, requestId: string): Promise<PreparedGrant> {
    const prep = await this.op("prepare_grant", { repositoryRoot, loops, minutes }, requestId);
    if (!prep.ok) throw custodianError(prep.code, prep.error ?? "prepare_grant failed");
    const d = prep.data ?? {};
    return { authorizationRequestId: String(d["authorizationRequestId"] ?? requestId), rendering: String(d["rendering"] ?? ""), expiresAt: String(d["expiresAt"] ?? "") };
  }

  /** Phase 2: commit a prepared grant (the custodian re-validates the intent, the ledger state it was
   * prepared against, and that the repository is still the same directory). */
  async commitGrant(authorizationRequestId: string): Promise<MintResult> {
    const com = await this.op("commit", { authorizationRequestId }, uuidv7());
    if (!com.ok) throw custodianError(com.code, com.error ?? "commit (grant) failed");
    const d = com.data ?? {};
    return { grantId: String(d["grantId"]), loopsTotal: Number(d["loopsTotal"]), expiresAt: String(d["expiresAt"]), assurance: String(d["assurance"] ?? "local_admin_elevation"), deduplicated: false };
  }

  /**
   * Mint a grant: prepare then commit, both on the operator surface. `requestId` is the operator's
   * idempotency key (a stable id dedupes; a fresh one always mints). Crash/retry safe (decision 4):
   *  - a fresh prepare → commit mints once;
   *  - a retry whose intent is still pending (REQUEST_ID_CONFLICT "already pending") is finished by
   *    committing the same id — no second intent, no extra authority;
   *  - a retry whose grant was already committed (REQUEST_ID_CONFLICT "already committed", or a commit
   *    that finds no pending intent) is a deduplicated replay: nothing new is minted.
   */
  async mint(repositoryRoot: string, loops: number, minutes: number, requestId: string): Promise<MintResult> {
    const prep = await this.op("prepare_grant", { repositoryRoot, loops, minutes }, requestId);
    if (!prep.ok) {
      if (prep.code === "REQUEST_ID_CONFLICT" && /already committed/i.test(prep.error ?? "")) return dedup();
      if (prep.code !== "REQUEST_ID_CONFLICT") throw custodianError(prep.code, prep.error ?? "prepare_grant failed");
      // "already pending": fall through and commit the existing intent for this request id.
    }
    const com = await this.op("commit", { authorizationRequestId: requestId }, uuidv7());
    if (!com.ok) {
      // The intent is gone (committed earlier under this id, or swept after expiry): a replay mints nothing.
      if (com.code === "AUTHORIZATION_INVALID") return dedup();
      throw custodianError(com.code, com.error ?? "commit (grant) failed");
    }
    const d = com.data ?? {};
    return { grantId: String(d["grantId"]), loopsTotal: Number(d["loopsTotal"]), expiresAt: String(d["expiresAt"]), assurance: String(d["assurance"] ?? "local_admin_elevation"), deduplicated: false };
  }

  /** Revoke every active grant for the repository's directory (prepare→commit on the operator surface).
   * Idempotent: a second revoke revokes 0. Returns how many were revoked. */
  async revoke(repositoryRoot: string): Promise<number> {
    const rid = uuidv7();
    const prep = await this.op("prepare_revoke", { repositoryRoot }, rid);
    if (!prep.ok) throw custodianError(prep.code, prep.error ?? "prepare_revoke failed");
    const com = await this.op("commit", { authorizationRequestId: rid }, uuidv7());
    if (!com.ok) throw custodianError(com.code, com.error ?? "commit (revoke) failed");
    return Number(com.data?.["revoked"] ?? 0);
  }

  /** The operator's view of the ledger (operator surface), with the custodian's ceilings. */
  async list(): Promise<GrantListing> {
    const res = await this.op("list_grants", {}, uuidv7());
    if (!res.ok) throw custodianError(res.code, res.error ?? "list_grants failed");
    return grantListingOf(res.data);
  }

  // P3.4C-1: protected user decisions & amendments. Recording is an authority-creating operator action,
  // so it lives here (CLI-only, like mint/revoke); the READ (`listUserRecords`) is on CustodianGrants,
  // which the engine may reach. The CLI drives prepare → operator confirms → commit.

  /** Phase 1: the custodian validates the repository identity and the payload, binds the payload and the
   * current per-run log revision, and renders exactly what it will record; nothing is recorded until commit. */
  async prepareUserRecord(repositoryRoot: string, runId: string, recordKind: UserRecordKind, payload: Record<string, unknown>, baseRevision: number, requestId: string): Promise<PreparedUserRecord> {
    const res = await this.op("prepare_user_record", { repositoryRoot, runId, recordKind, payload, baseRevision }, requestId);
    if (!res.ok) throw custodianError(res.code, res.error ?? "prepare_user_record failed");
    const d = res.data ?? {};
    return { authorizationRequestId: String(d["authorizationRequestId"] ?? requestId), rendering: String(d["rendering"] ?? ""), expiresAt: String(d["expiresAt"] ?? "") };
  }

  /** Phase 2: commit the prepared user record the operator confirmed (the custodian re-checks the log
   * revision and the directory identity, then appends under a custodian-assigned sequence and provenance). */
  async commitUserRecord(authorizationRequestId: string): Promise<UserRecordCommit> {
    const com = await this.op("commit", { authorizationRequestId }, uuidv7());
    if (!com.ok) throw custodianError(com.code, com.error ?? "commit (user_record) failed");
    const d = com.data ?? {};
    return { recordId: String(d["recordId"]), seq: Number(d["seq"]), revision: Number(d["revision"]), recordKind: String(d["recordKind"]) as UserRecordKind };
  }

  // P3.4C-4: the custodian-held trusted configuration. Writing it is an authority-creating operator action (CLI-only,
  // like mint/revoke); the config section is read by the engine through CustodianGrants.

  /** Phase 1: the custodian validates the payload, computes every digest, measures the Codex installation through its
   * own handle and renders the complete change; it binds the state of every record the change affects. */
  async prepareConfigRecord(req: { repositoryRoot: string | null; recordKind: ConfigRecordKind; action: ConfigAction; recordId?: string | null; payload?: Record<string, unknown> | null; baseRevision: number }, requestId: string): Promise<PreparedConfigRecord> {
    const args: Record<string, unknown> = { recordKind: req.recordKind, action: req.action, baseRevision: req.baseRevision };
    if (req.repositoryRoot !== null) args["repositoryRoot"] = req.repositoryRoot;
    if (req.recordId) args["recordId"] = req.recordId;
    if (req.payload) args["payload"] = req.payload;
    const res = await this.op("prepare_config_record", args, requestId);
    if (!res.ok) throw custodianError(res.code, res.error ?? "prepare_config_record failed");
    const d = res.data ?? {};
    return { authorizationRequestId: String(d["authorizationRequestId"] ?? requestId), rendering: String(d["rendering"] ?? ""), expiresAt: String(d["expiresAt"] ?? "") };
  }

  /** Phase 4 Increment 3 (§3.5): the owner's decision on a held proposal — the custodian renders the proposal itself and
   * binds the intent to exactly that rendering; nothing is recorded until `commitFixDecision`. */
  async prepareFixDecision(repositoryRoot: string, runId: string, operationId: string, decision: "confirm" | "reject", requestId: string, expected?: FixSelection): Promise<PreparedFixDecision> {
    const args: Record<string, unknown> = { repositoryRoot, runId, operationId, decision };
    // Step 7.1: a guided selection always names all three expected values (the custodian refuses fewer).
    if (expected) Object.assign(args, { expectedRepoKey: expected.repoKey, expectedProposalDigest: expected.proposalDigest, expectedRenderingDigest: expected.renderingDigest });
    const res = await this.op("prepare_fix_decision", args, requestId);
    if (!res.ok) throw custodianError(res.code, res.error ?? "prepare_fix_decision failed");
    const d = res.data ?? {};
    return {
      authorizationRequestId: String(d["authorizationRequestId"] ?? requestId), rendering: String(d["rendering"] ?? ""), expiresAt: String(d["expiresAt"] ?? ""),
      facts: fixDecisionFactsOf(d["fixDecision"]),
    };
  }

  /** Step 7.1 (`fix review`): the delegated fixes the custodian holds, across repositories or of one (operator only). */
  async listFixProposals(repositoryRoot: string | null): Promise<FixListing> {
    const res = await this.op("list_fix_proposals", repositoryRoot === null ? {} : { repositoryRoot }, uuidv7());
    if (!res.ok) throw custodianError(res.code, res.error ?? "list_fix_proposals failed");
    return fixListingOf(res.data ?? {});
  }

  /** Phase 2 of a fix decision: the custodian renders again and refuses CONFIRMATION_CONTENT_MISMATCH when anything the
   * operator was shown changed; a confirmation is single use and expires. */
  async commitFixDecision(authorizationRequestId: string): Promise<{ decision: string; operationStatus: string; confirmationId: string; renderingDigest: string; expiresAt: string | null }> {
    const com = await this.op("commit", { authorizationRequestId }, uuidv7());
    if (!com.ok) throw custodianError(com.code, com.error ?? "commit (fix decision) failed");
    const d = com.data ?? {};
    return { decision: String(d["decision"] ?? ""), operationStatus: String(d["operationStatus"] ?? ""), confirmationId: String(d["confirmationId"] ?? ""), renderingDigest: String(d["renderingDigest"] ?? ""), expiresAt: typeof d["expiresAt"] === "string" ? d["expiresAt"] : null };
  }

  /** Phase 2: commit the prepared change the operator confirmed (the custodian re-checks every affected record's state
   * in the same hold as its write; any change refuses it STALE_CONFIG, and nothing is committed). */
  async commitConfigRecord(authorizationRequestId: string): Promise<ConfigCommit> {
    const com = await this.op("commit", { authorizationRequestId }, uuidv7());
    if (!com.ok) throw custodianError(com.code, com.error ?? "commit (config_record) failed");
    const d = com.data ?? {};
    const int = (k: string): number | null => (Number.isInteger(d[k]) ? (d[k] as number) : null);
    return {
      recordKind: String(d["recordKind"]) as ConfigRecordKind, action: String(d["action"]) as ConfigAction,
      repoKey: typeof d["repoKey"] === "string" ? d["repoKey"] : null, configRevision: int("configRevision"),
      recordId: typeof d["recordId"] === "string" ? d["recordId"] : null, globalRevision: int("globalRevision"), globalsReconfirmed: int("globalsReconfirmed"),
    };
  }
}

function dedup(): MintResult {
  return { grantId: null, loopsTotal: null, expiresAt: null, assurance: "local_admin_elevation", deduplicated: true };
}

// ---- Step 7.1 (`fix review`): the listing and the guided decision's structured facts ----

/** A guided selection's expected values (GrantLedger.FixSelection). */
export interface FixSelection {
  repoKey: string;
  proposalDigest: string;
  renderingDigest: string;
}

export const FIX_LISTING_SCHEMA = "codeparley.custodian-fix-listing.v1";
export const FIX_DECISION_FACTS_SCHEMA = "codeparley.custodian-fix-decision-prepared.v1";

export type FixListingState = "pending" | "unavailable" | "waiting" | "expired" | "ineligible";

/** One listed fix: custodian-held facts only (text the implementer wrote is never part of it). Display fields are the
 * custodian's escaped forms. */
export interface FixListingEntry {
  state: FixListingState;
  selectable: boolean;
  reasonCode: string | null;
  repoKey: string;
  repositoryRoot: string | null;
  repositoryDisplay: string | null;
  lastKnownPath: string | null;
  runId: string;
  operationId: string;
  proposalDigest: string;
  renderingDigest: string | null;
  changeCount: number;
  totalBytes: number;
  paths: string[];
  pathCount: number;
  proposedAt: string | null;
  expiresAt: string;
  confirmationExpiresAt: string | null;
}

export interface FixListing {
  snapshotAt: string;
  total: number;
  truncated: boolean;
  listingDigest: string;
  entries: FixListingEntry[];
}

/** A prepared fix decision as the custodian reports it (GrantLedger.FixDecisionFactsSchema). */
export interface FixDecisionFacts {
  decision: "confirm" | "reject";
  repoKey: string;
  repositoryRoot: string;
  runId: string;
  operationId: string;
  proposalDigest: string;
  renderingDigest: string;
  baselineSourceId: string | null;
  authorityHeader: string;
  authorityFooter: string;
  consequences: string[];
}

export interface PreparedFixDecision {
  authorizationRequestId: string;
  rendering: string;
  expiresAt: string;
  /** Null from a custodian that predates Step 7.1 (the guided workflow refuses to continue without it). */
  facts: FixDecisionFacts | null;
}

const STATES: ReadonlySet<string> = new Set(["pending", "unavailable", "waiting", "expired", "ineligible"]);
const malformed = (what: string) => custodianError("INTERNAL", `the custodian's ${what} is malformed; nothing was decided`);
const str = (v: unknown, what: string): string => (typeof v === "string" ? v : (() => { throw malformed(what); })());
const optStr = (v: unknown, what: string): string | null => (v === null || v === undefined ? null : str(v, what));
const num = (v: unknown, what: string): number => (typeof v === "number" && Number.isFinite(v) ? v : (() => { throw malformed(what); })());

/** The listing, checked field by field (a malformed or other-schema answer is refused, never guessed at). */
export function fixListingOf(d: Record<string, unknown>): FixListing {
  if (d["schema"] !== FIX_LISTING_SCHEMA) throw malformed(`listing (schema ${JSON.stringify(d["schema"] ?? null)})`);
  if (!Array.isArray(d["entries"])) throw malformed("listing");
  const entries = (d["entries"] as unknown[]).map((x): FixListingEntry => {
    if (!x || typeof x !== "object") throw malformed("listing entry");
    const e = x as Record<string, unknown>;
    const state = str(e["state"], "listing state");
    if (!STATES.has(state)) throw malformed("listing state");
    if (typeof e["selectable"] !== "boolean" || !Array.isArray(e["paths"])) throw malformed("listing entry");
    return {
      state: state as FixListingState, selectable: e["selectable"], reasonCode: optStr(e["reasonCode"], "reason"), repoKey: str(e["repoKey"], "repository identity"),
      repositoryRoot: optStr(e["repositoryRoot"], "repository path"), repositoryDisplay: optStr(e["repositoryDisplay"], "repository path"), lastKnownPath: optStr(e["lastKnownPath"], "repository path"),
      runId: str(e["runId"], "run id"), operationId: str(e["operationId"], "fix id"), proposalDigest: str(e["proposalDigest"], "proposal digest"),
      renderingDigest: optStr(e["renderingDigest"], "rendering digest"), changeCount: num(e["changeCount"], "change count"), totalBytes: num(e["totalBytes"], "size"),
      paths: (e["paths"] as unknown[]).map((p) => str(p, "path")), pathCount: num(e["pathCount"], "path count"), proposedAt: optStr(e["proposedAt"], "time"),
      expiresAt: str(e["expiresAt"], "expiry"), confirmationExpiresAt: optStr(e["confirmationExpiresAt"], "expiry"),
    };
  });
  return { snapshotAt: str(d["snapshotAt"], "listing time"), total: num(d["total"], "listing total"), truncated: d["truncated"] === true, listingDigest: str(d["listingDigest"], "listing digest"), entries };
}

/** A prepared decision's facts, checked; null when the custodian sent none (one that predates Step 7.1). */
export function fixDecisionFactsOf(v: unknown): FixDecisionFacts | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "object") throw malformed("prepared decision");
  const f = v as Record<string, unknown>;
  if (f["schema"] !== FIX_DECISION_FACTS_SCHEMA) throw malformed(`prepared decision (schema ${JSON.stringify(f["schema"] ?? null)})`);
  const decision = str(f["decision"], "prepared decision");
  if (decision !== "confirm" && decision !== "reject") throw malformed("prepared decision");
  if (!Array.isArray(f["consequences"])) throw malformed("prepared decision");
  return {
    decision, repoKey: str(f["repoKey"], "prepared decision"), repositoryRoot: str(f["repositoryRoot"], "prepared decision"), runId: str(f["runId"], "prepared decision"),
    operationId: str(f["operationId"], "prepared decision"), proposalDigest: str(f["proposalDigest"], "prepared decision"), renderingDigest: str(f["renderingDigest"], "prepared decision"),
    baselineSourceId: optStr(f["baselineSourceId"], "prepared decision"), authorityHeader: str(f["authorityHeader"], "prepared decision"),
    authorityFooter: str(f["authorityFooter"], "prepared decision"), consequences: (f["consequences"] as unknown[]).map((c) => str(c, "prepared decision")),
  };
}
