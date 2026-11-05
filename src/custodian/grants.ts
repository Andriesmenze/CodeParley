// The implementer side of the custodian grant store (P3.4C-0): consuming a granted loop and reading the
// grants. These are the only custodian operations the ENGINE uses, so this module is reachable from the
// MCP server's import graph; the operator operations (mint/revoke) live in operator.ts, which only the
// CLI path imports (test/layering.test.ts keeps the server and the hooks off that path). Security is the
// custodian's OS caller classification, not this layering (decision 5).
//
// Reduce-only: consuming never creates or enlarges authority, and a failed custodian connection is
// fail-closed — there is no grants.json fallback and no weaker mode for a protected loop (decision 7).

import { DomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import {
  CUSTODIAN_UNAVAILABLE, SERVER_NOT_TRUSTED, custodianError,
  type ConfigSection, type ConsumeResult, type CustodianDerivation, type CustodianSurface, type GrantListing, type GrantSummary, type LoopSection, type RunSection, type UserRecordListing, type UserRecordSection,
} from "./protocol.js";
import { CustodianBusy, CustodianNotTrusted, CustodianUnavailable, type CustodianTransport } from "./transport.js";

/**
 * Map a transport-level failure to a fail-closed engine error carrying whether the request can have
 * reached the custodian (`details.outcome`): retryable only when it provably was not delivered. Anything
 * else is re-thrown. There is no fallback to user-writable grants.
 */
export function toUnavailable(e: unknown): never {
  if (e instanceof CustodianNotTrusted) {
    throw new DomainError(SERVER_NOT_TRUSTED, `the CodeParley custodian could not be authenticated, so a protected automated run cannot proceed (${e.message})`, { retryable: false, details: { outcome: e.outcome, ...e.evidence } });
  }
  if (e instanceof CustodianBusy) {
    const unknown = e.outcome === "unknown";
    throw new DomainError("CUSTODIAN_BUSY", `the custodian is busy serving another request, so a protected automated run cannot proceed now (${e.message}). Nothing falls back to a weaker authority${unknown ? "; the request may have reached the custodian, so it is not retried automatically" : ""}`, { retryable: !unknown, details: { outcome: e.outcome, reason: "busy", waited_ms: e.waitedMs } });
  }
  if (e instanceof CustodianUnavailable) {
    const unknown = e.outcome === "unknown";
    throw new DomainError(CUSTODIAN_UNAVAILABLE, `the grant custodian is unavailable, so a protected automated run cannot proceed (${e.message}). There is no grants.json fallback${unknown ? "; the request may have reached the custodian, so it is not retried automatically" : ""}`, { retryable: !unknown, details: { outcome: e.outcome } });
  }
  throw e;
}

/** The delivery outcome a fail-closed custodian error carries ("not_delivered" | "unknown"), or null. */
export function deliveryOutcomeOf(e: unknown): "not_delivered" | "unknown" | null {
  if (e instanceof DomainError && (e.code === CUSTODIAN_UNAVAILABLE || e.code === "CUSTODIAN_BUSY" || e.code === SERVER_NOT_TRUSTED)) {
    const o = e.details?.["outcome"];
    return o === "unknown" ? "unknown" : "not_delivered";
  }
  return null;
}

/** Parse a `list_grants` response body. */
export function grantListingOf(data: Record<string, unknown> | undefined): GrantListing {
  const arr = Array.isArray(data?.["grants"]) ? (data!["grants"] as Record<string, unknown>[]) : [];
  const c = data?.["ceilings"] as Record<string, unknown> | undefined;
  const grants: GrantSummary[] = arr.map((g) => ({
    grantId: String(g["grantId"]),
    repoKey: String(g["repoKey"]),
    repositoryRoot: typeof g["repositoryRoot"] === "string" ? (g["repositoryRoot"] as string) : null,
    identity: typeof g["identity"] === "string" ? (g["identity"] as string) : "legacy_text",
    loopsUsed: Number(g["loopsUsed"]),
    loopsTotal: Number(g["loopsTotal"]),
    expiresAt: String(g["expiresAt"]),
    revoked: Boolean(g["revoked"]),
    suspended: g["suspended"] === true,
    active: Boolean(g["active"]),
    assurance: String(g["assurance"]),
  }));
  const ceilings = c && Number.isInteger(c["loops"]) && Number.isInteger(c["minutes"]) ? { loops: Number(c["loops"]), minutes: Number(c["minutes"]) } : null;
  return { grants, ceilings };
}

export class CustodianGrants {
  constructor(private readonly transport: CustodianTransport) {}

  /** Spend one loop of an active grant for the repository AND mint the run's custodian-owned loop record in the
   * same atomic custodian write (implementer surface; P3.4C-2 contract §1). The custodian establishes the
   * repository's identity itself; the path is only a locator. Idempotent on `requestId`: a replay returns the
   * same loop and consumes nothing again (but carries no bind nonce). LOOP_NOT_AUTHORIZED when no grant is
   * active; RUN_ALREADY_HAS_LOOP when the run already has a live loop; LOOP_TERMINAL when its loop ended (a run
   * gets one loop, never a resurrected one); INVALID_ARGUMENT when the custodian refuses the repository's
   * identity; CUSTODIAN_UNAVAILABLE / SERVER_NOT_TRUSTED (with the delivery outcome) when no trusted custodian
   * answered. */
  async consume(repositoryRoot: string, runId: string, requestId: string = uuidv7()): Promise<ConsumeResult> {
    const res = await this.transport.send("implementer", "consume_loop", { repositoryRoot, runId }, requestId).catch(toUnavailable);
    if (!res.ok) throw custodianError(res.code, res.error ?? "consume_loop failed");
    return consumeResultOf(res.data);
  }

  /** The grants and the custodian's ceilings (read-only). Tries the implementer surface, then the operator
   * surface (a distinct operator account can reach only its own pipe). */
  async list(): Promise<GrantListing> {
    let first: unknown = null;
    for (const surface of ["implementer", "operator"] as CustodianSurface[]) {
      try {
        const res = await this.transport.send(surface, "list_grants", {}, uuidv7()).catch(toUnavailable);
        if (res.ok) return grantListingOf(res.data);
        first ??= custodianError(res.code, res.error ?? "list_grants failed");
        if (res.code !== "CALLER_NOT_AUTHORIZED") break;
      } catch (e) {
        first ??= e;
        if (deliveryOutcomeOf(e) !== "not_delivered") break;
      }
    }
    throw first;
  }

  /** P3.4C-1: the per-run protected user-record log, read-only on the given surface. The ENGINE reads on
   * the IMPLEMENTER surface and receives only the structural projection (never a raw decision note or
   * amendment text); the operator's attended view may read on the OPERATOR surface for the full records.
   * The projection is chosen by the custodian from the OS caller class, never from this request. Fail-closed
   * (CUSTODIAN_UNAVAILABLE / SERVER_NOT_TRUSTED) when no trusted custodian answered — a reachable custodian
   * with no log for the run returns `{governed:false, records:[]}`, which is NOT the same as unavailable.
   * P3.4C-3: `sections` names what to return (default: the user log and the loop section; "run" adds the run
   * section) — every section from one consistent custodian snapshot. */
  async listUserRecords(surface: CustodianSurface, repositoryRoot: string, runId: string, sections?: readonly UserRecordSection[]): Promise<UserRecordListing> {
    const args: Record<string, unknown> = sections ? { repositoryRoot, runId, sections: [...sections] } : { repositoryRoot, runId };
    const res = await this.transport.send(surface, "list_user_records", args, uuidv7()).catch(toUnavailable);
    if (!res.ok) throw custodianError(res.code, res.error ?? "list_user_records failed");
    return userRecordListingOf(res.data);
  }

  /** Phase 4 Increment 3 (§3.5, §3.7): the custodian's rendering of a held proposal — what `fix show` prints and what the
   * originating session inspects. Read only; served on both surfaces. */
  async renderFixProposal(surface: CustodianSurface, repositoryRoot: string, runId: string, operationId: string): Promise<FixRendering> {
    const res = await this.transport.send(surface, "render_fix_proposal", { repositoryRoot, runId, operationId }, uuidv7()).catch(toUnavailable);
    if (!res.ok) throw custodianError(res.code, res.error ?? "render_fix_proposal failed");
    const d = res.data ?? {};
    const c = (d["confirmation"] ?? null) as Record<string, unknown> | null;
    return {
      operationId: String(d["operationId"] ?? operationId), status: String(d["status"] ?? ""), proposalDigest: String(d["proposalDigest"] ?? ""),
      expiresAt: typeof d["expiresAt"] === "string" ? d["expiresAt"] : null, rendering: String(d["rendering"] ?? ""), renderingDigest: String(d["renderingDigest"] ?? ""),
      confirmation: c ? { confirmationId: String(c["confirmationId"] ?? ""), decision: String(c["decision"] ?? ""), expiresAt: typeof c["expiresAt"] === "string" ? c["expiresAt"] : null, consumedAt: typeof c["consumedAt"] === "string" ? c["consumedAt"] : null } : null,
    };
  }
}

/** Phase 4 Increment 3: a held proposal as the custodian renders it. */
export interface FixRendering {
  operationId: string;
  status: string;
  proposalDigest: string;
  expiresAt: string | null;
  /** The custodian's exact text (its last line names its own SHA-256). */
  rendering: string;
  renderingDigest: string;
  confirmation: { confirmationId: string; decision: string; expiresAt: string | null; consumedAt: string | null } | null;
}

/** P3.4C-5 Increment 3 (§5.1): the custodian's protected derivation of a run, asked for with the run's run.json bytes
 * (the custodian verifies them against its declaration digest). A malformed answer is "unavailable" (fail closed). */
export async function custodianDerivationOf(transport: CustodianTransport, surface: CustodianSurface, repositoryRoot: string, runId: string, runJson: Buffer): Promise<CustodianDerivation> {
  const res = await transport.send(surface, "list_user_records", { repositoryRoot, runId, sections: ["derivation"], runJson: runJson.toString("base64") }, uuidv7()).catch(toUnavailable);
  if (!res.ok) throw custodianError(res.code, res.error ?? "list_user_records failed");
  return derivationSectionOf(res.data?.["derivation"]);
}

/** Parse the derivation section; anything malformed is an unavailable derivation (never a usable one). */
export function derivationSectionOf(v: unknown): CustodianDerivation {
  const bad = (detail: string): CustodianDerivation => ({ available: false, authority: "custodian", code: "MALFORMED_RESPONSE", detail });
  if (!isRec(v)) return bad("the custodian reported no derivation section");
  if (v["available"] !== true) return { available: false, authority: "custodian", code: typeof v["code"] === "string" ? v["code"] : "UNAVAILABLE", detail: typeof v["detail"] === "string" ? v["detail"] : "" };
  const route = v["route"], completion = v["completion"];
  if (typeof v["derivationId"] !== "string" || !isRec(route) || typeof route["code"] !== "string" || typeof route["kind"] !== "string" || typeof route["reason"] !== "string"
    || !isRec(completion) || typeof completion["state"] !== "string" || !isHex64(v["progressFingerprint"]) || !isHex64(v["inputDigest"])) return bad("the custodian's derivation is malformed");
  return v as unknown as CustodianDerivation;
}

/** Parse a `list_user_records` response body; the records stay opaque (their shape is the surface's). */
export function userRecordListingOf(data: Record<string, unknown> | undefined): UserRecordListing {
  const records = Array.isArray(data?.["records"]) ? (data!["records"] as Record<string, unknown>[]) : [];
  const recovered = data?.["recoveredAtRevision"];
  return {
    // Absent, empty or not a string: unknown (null) — never matched against a record.
    repoKey: typeof data?.["repoKey"] === "string" && data["repoKey"] !== "" ? (data["repoKey"] as string) : null,
    governed: Boolean(data?.["governed"]),
    revision: Number.isInteger(data?.["revision"]) ? Number(data!["revision"]) : 0,
    logDigest: typeof data?.["logDigest"] === "string" ? (data!["logDigest"] as string) : "",
    records,
    loop: loopSectionOf(data?.["loop"]),
    // Absent or malformed: no answer (null) — never read as "not protected".
    protected: typeof data?.["protected"] === "boolean" ? (data["protected"] as boolean) : null,
    recoveredAtRevision: Number.isInteger(recovered) ? (recovered as number) : null,
    run: runSectionOf(data?.["run"]),
    config: configSectionOf(data?.["config"]),
    ...(data && "derivation" in data ? { derivation: derivationSectionOf(data["derivation"]) } : {}),
    ...(data && "snapshot" in data ? { snapshot: isRec(data["snapshot"]) ? structuredClone(data["snapshot"]) : null } : {}),
  };
}

const isRec = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const isHex64 = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);

/** Parse the config section of a listing (P3.4C-4 contract §3.3). Absent or malformed in any part: null — no answer,
 * which a protected run treats as a refusal (fail closed), never as "no configuration". */
export function configSectionOf(v: unknown): ConfigSection | null {
  if (!isRec(v) || !Number.isInteger(v["globalRevision"]) || !Array.isArray(v["acceptances"]) || !Array.isArray(v["selftestConfirmations"])) return null;
  const r = v["repository"];
  if (r !== null) {
    if (!isRec(r) || !Number.isInteger(r["configRevision"]) || !isHex64(r["configDigest"]) || typeof r["usable"] !== "boolean" || typeof r["revoked"] !== "boolean" || typeof r["lapsed"] !== "boolean") return null;
    if (!isRec(r["checks"]) || !isRec(r["profiles"]) || !isStrArr(r["requiredProfiles"]) || typeof r["noRequiredChecks"] !== "boolean" || !isStrArr(r["testGlobs"])) return null;
    for (const c of Object.values(r["checks"])) {
      if (!isRec(c) || !isHex64(c["definitionDigest"]) || !isRec(c["definition"]) || !isStrArr(c["definition"]["argv"])) return null;
    }
    const rules = r["captureRules"];
    if (!isRec(rules) || !isStrArr(rules["excludeGlobs"]) || !isStrArr(rules["contextInclude"]) || ![rules["maxFileBytes"], rules["maxExportBytes"], rules["maxDiffBytes"]].every((n) => Number.isInteger(n)) || !isHex64(r["captureRulesDigest"])) return null;
    const i = r["codexInstallation"];
    if (i !== null && (!isRec(i) || typeof i["path"] !== "string" || !isHex64(i["sha256"]))) return null;
  }
  for (const a of v["acceptances"]) if (!isRec(a) || typeof a["acceptanceId"] !== "string" || typeof a["usable"] !== "boolean" || !isStrArr(a["accepted"])) return null;
  for (const c of v["selftestConfirmations"]) if (!isRec(c) || typeof c["confirmationId"] !== "string" || typeof c["usable"] !== "boolean" || !isHex64(c["recordDigest"])) return null;
  return structuredClone(v) as unknown as ConfigSection;
}

/** Parse the run section of a listing (P3.4C-3 contract §3.3). Absent or malformed: null (no answer, fail-closed). */
export function runSectionOf(v: unknown): RunSection | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const record = o["record"];
  const limits = o["limits"];
  if (typeof o["registered"] !== "boolean" || !Number.isInteger(o["runRevision"]) || typeof o["runDigest"] !== "string") return null;
  if (record !== null && (typeof record !== "object" || Array.isArray(record))) return null;
  if (o["registered"] !== (record !== null)) return null;
  if (!limits || typeof limits !== "object" || Array.isArray(limits) || !Object.values(limits).every((n) => Number.isInteger(n))) return null;
  const basis = o["reviewBasis"];
  const reviewBasis = isRec(basis) && Object.values(basis).every((b) => isRec(b) && typeof b["basisUsable"] === "boolean")
    ? (structuredClone(basis) as Record<string, { basisUsable: boolean; basisReason: string | null }>)
    : null;
  return { registered: o["registered"], runRevision: o["runRevision"] as number, runDigest: o["runDigest"], limits: { ...(limits as Record<string, number>) }, record: record as Record<string, unknown> | null, reviewBasis };
}

/** Parse the loop section of a listing (contract §6). A section that is absent or malformed is null — never
 * read as "not protected": a caller that needs the selection treats null as no answer (fail-closed). */
export function loopSectionOf(v: unknown): LoopSection | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const record = o["record"];
  if (typeof o["protected"] !== "boolean" || !Number.isInteger(o["loopRevision"]) || typeof o["loopDigest"] !== "string") return null;
  if (record !== null && (typeof record !== "object" || Array.isArray(record))) return null;
  if (o["protected"] !== (record !== null)) return null;
  return { protected: o["protected"], loopRevision: o["loopRevision"] as number, loopDigest: o["loopDigest"], record: record as Record<string, unknown> | null };
}

/** Parse a `consume_loop` result (contract §1). */
export function consumeResultOf(data: Record<string, unknown> | undefined): ConsumeResult {
  const d = data ?? {};
  return {
    grantId: String(d["grantId"]),
    loopId: String(d["loopId"]),
    loopsUsed: Number(d["loopsUsed"]),
    loopsTotal: Number(d["loopsTotal"]),
    runId: String(d["runId"]),
    loopEpoch: Number(d["loopEpoch"]),
    loopRevision: Number(d["loopRevision"]),
    bindNonce: typeof d["bindNonce"] === "string" ? (d["bindNonce"] as string) : null,
  };
}
