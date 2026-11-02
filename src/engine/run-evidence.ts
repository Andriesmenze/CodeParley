// P3.4C-3 (contract §1.3, §2.4 U3, §5.4): a PROTECTED run's evidence as the custodian holds it. The engine's
// state.json is a cache; every protected read — the Stop derivation, the resume guard, displays, the review bundle —
// derives from the custodian's run record instead:
//  - only what the custodian holds counts: check executions, reviews, items, responses and replies it does not hold
//    are dropped (nothing recorded before protection is promoted, §1.3; a record forged into the cache counts for
//    nothing);
//  - the custodian's claims replace the cache's (an item's status and supersession, a review's acceptance, an
//    execution's outcome);
//  - texts come from the cache only where the artifact they were written to still has the digest the custodian holds
//    (a review's items.json; an execution's result, stdout and stderr). An item whose text cannot be verified is kept
//    (it may block completion) with its text withheld; an execution whose artifacts do not verify does not count;
//  - the current evidence epoch (§2.4 U3): completion relies only on check executions and an accepted review recorded
//    in it; a review accepted in an earlier epoch is shown as not accepted. Items and threads carry over.
//
// Digest binding proves integrity since recording, not who produced the evidence (the custodian validates and orders
// what the engine reports; it does not authenticate it).

import { readFile } from "node:fs/promises";
import { sha256OfBytes } from "../common/hash.js";
import type { RunSection } from "../custodian/protocol.js";
import { resolveArtifact } from "../store/artifacts.js";
import type { ReviewerItem } from "../schemas/review.js";
import type { StateRecord } from "../schemas/run-state.js";

type Rec = Record<string, unknown>;

/** The text of an item whose items artifact is missing or does not match the custodian's digest. */
export const ITEM_TEXT_UNAVAILABLE = "[text unavailable: the review's items artifact is missing or does not match the digest the custodian holds]";

const arr = (v: unknown): Rec[] => (Array.isArray(v) ? (v.filter((x) => x !== null && typeof x === "object") as Rec[]) : []);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const strOr = <T>(v: unknown, d: T): string | T => (typeof v === "string" ? v : d);

const HEX64 = /^[0-9a-f]{64}$/;
/** A held digest: present, and a 64-hex string or null (undefined: missing or malformed). */
const heldDigest = (v: unknown): string | null | undefined => (v === null ? null : typeof v === "string" && HEX64.test(v) ? v : undefined);

/** The identities freshness compares, as the custodian recorded them (null: any one missing or malformed). */
function heldIdentities(h: Rec): Pick<StateRecord["check_executions"][number], "definition_digest" | "check_spec_id" | "env_digest" | "freshness_digest" | "execution_input_id"> | null {
  const d = heldDigest(h["definitionDigest"]);
  const s = heldDigest(h["checkSpecId"]);
  const env = heldDigest(h["envDigest"]);
  const fr = heldDigest(h["freshnessDigest"]);
  const x = heldDigest(h["executionInputId"]);
  if (d === undefined || s === undefined || env === undefined || fr === undefined || x === undefined) return null;
  return { definition_digest: d, check_spec_id: s, env_digest: env, freshness_digest: fr, execution_input_id: x };
}

/** A review's op_begin bindings that its currency and C6 checks read (null: any one missing or malformed). */
function heldReviewBindings(b: Rec | null): { source_id: string; review_input_id: string; check_evidence_digest: string; check_execution_ids: string[]; capture_stable: boolean; manifest_digest: string; export_digest: string; capture_digest: string } | null {
  if (!b) return null;
  const hex = (k: string) => (typeof b[k] === "string" && HEX64.test(b[k] as string) ? (b[k] as string) : null);
  const source = hex("sourceId"), input = hex("reviewInputId"), evidence = hex("checkEvidenceDigest");
  const manifest = hex("manifestDigest"), exp = hex("exportDigest"), capture = hex("captureDigest");
  const ids = b["checkExecutionIds"];
  if (!source || !input || !evidence || !manifest || !exp || !capture || typeof b["captureStable"] !== "boolean" || !Array.isArray(ids) || !ids.every((i) => typeof i === "string")) return null;
  return { source_id: source, review_input_id: input, check_evidence_digest: evidence, check_execution_ids: ids as string[], capture_stable: b["captureStable"] as boolean, manifest_digest: manifest, export_digest: exp, capture_digest: capture };
}

async function digestOf(runDir: string, ref: string | null | undefined): Promise<string | null> {
  if (!ref) return null;
  const bytes = await readFile(resolveArtifact(runDir, ref)).catch(() => null);
  return bytes ? sha256OfBytes(bytes) : null;
}

/** The item texts of one review's items artifact, when its digest is the one the custodian holds (else null). */
async function verifiedItemTexts(runDir: string, ref: string | undefined, held: unknown): Promise<Map<string, ReviewerItem> | null> {
  if (!ref || typeof held !== "string") return null;
  const bytes = await readFile(resolveArtifact(runDir, ref)).catch(() => null);
  if (!bytes || sha256OfBytes(bytes) !== held) return null;
  try {
    const items = (JSON.parse(bytes.toString("utf8")) as { items?: ReviewerItem[] }).items ?? [];
    return new Map(items.map((i) => [i.id, i]));
  } catch {
    return null;
  }
}

/** The run section a hydrated state was built from (in memory only; never serialized), so a later read of the same
 * run's evidence — a review's freshness — derives from the same custodian record. */
const HYDRATED_FROM: unique symbol = Symbol("codeparley.hydratedFrom");
/** The cache a hydrated state was built from (in memory only). */
const HYDRATED_RAW: unique symbol = Symbol("codeparley.hydratedRaw");

export function hydratedSectionOf(st: StateRecord): RunSection | null {
  return (st as { [HYDRATED_FROM]?: RunSection })[HYDRATED_FROM] ?? null;
}

/**
 * The local cache behind a (possibly hydrated) state. Redaction reads its records from here: hydration drops what the
 * custodian does not hold (a capture or a response recorded before protection), but every name any record of the run
 * withheld stays withheld — the withheld set may only grow.
 */
export function rawStateOf(st: StateRecord): StateRecord {
  return (st as { [HYDRATED_RAW]?: StateRecord })[HYDRATED_RAW] ?? st;
}

/**
 * `st` with its evidence replaced by the custodian's run record (`section`, either projection). A section without a
 * registered record leaves `st` unchanged (the run is not protected by its run record). `runDir` locates the artifacts
 * whose digests are verified.
 */
export async function hydrateRunEvidence(st: StateRecord, section: RunSection | null, runDir: string): Promise<StateRecord> {
  if (!section?.registered) return st;
  const rec = section.record ?? {};
  const epoch = typeof rec["evidenceEpoch"] === "number" ? (rec["evidenceEpoch"] as number) : 1;

  // Check executions: held, of the current epoch, with artifacts that verify — in the CUSTODIAN's order (the floor's
  // decisive execution is the last fresh conclusive one) and with every field freshness and the floor read taken from
  // its record: the outcome, the source ids and the identities (P3.4C-3 corrective). An execution whose held identity
  // data is missing or malformed does not count (fail closed); the local cache supplies only artifact references.
  const localEx = new Map(st.check_executions.map((e) => [e.execution_id, e]));
  const check_executions: StateRecord["check_executions"] = [];
  for (const h of arr(rec["checkExecutions"])) {
    const e = localEx.get(String(h["executionId"]));
    if (!e || h["evidenceEpoch"] !== epoch) continue;
    const ids = heldIdentities(h);
    if (!ids) continue;
    const [res, out, err] = await Promise.all([digestOf(runDir, e.result_artifact), digestOf(runDir, e.stdout?.artifact), digestOf(runDir, e.stderr?.artifact)]);
    if (res !== (h["resultDigest"] ?? null) || out !== (h["stdoutDigest"] ?? null) || err !== (h["stderrDigest"] ?? null)) continue;
    check_executions.push({
      ...e,
      ...ids,
      check: strOr(h["check"], e.check),
      status: strOr(h["status"], e.status) as typeof e.status,
      exit_code: typeof h["exitCode"] === "number" ? (h["exitCode"] as number) : null,
      timed_out: h["timedOut"] === true,
      cancelled: h["cancelled"] === true,
      started_at: strOr(h["startedAt"], null) as typeof e.started_at,
      ended_at: strOr(h["endedAt"], null) as typeof e.ended_at,
      duration_ms: typeof h["durationMs"] === "number" ? (h["durationMs"] as number) : null,
      source_id_at_start: strOr(h["sourceIdAtStart"], null) as typeof e.source_id_at_start,
      source_id_at_end: strOr(h["sourceIdAtEnd"], null) as typeof e.source_id_at_end,
      source_stable: h["sourceStable"] === true,
    });
  }

  // Reviews: held only, in the custodian's order; acceptance is the custodian's, and only in the current epoch. Review
  // currency compares the review's source and check evidence with now: both, and what the review was run from, come
  // from the custodian's op_begin bindings (P3.4C-3 corrective; C6 for the export, manifest and capture). A review
  // whose bindings are missing or malformed is never accepted (fail closed).
  const localRv = new Map(st.reviews.map((r) => [r.review_id, r]));
  const reviews: StateRecord["reviews"] = [];
  const itemTexts = new Map<string, Map<string, ReviewerItem> | null>();
  for (const h of arr(rec["reviews"])) {
    const r = localRv.get(String(h["reviewId"]));
    if (!r) continue;
    const accepted = h["accepted"];
    const current = h["evidenceEpoch"] === epoch;
    const reasons = strs(h["notAcceptedReasons"]);
    const bound = heldReviewBindings((h["begin"] ?? null) as Rec | null);
    // P3.4C-4 (§4.3): a review counts as accepted and current only while the configuration basis it was pinned under is
    // still usable NOW (its isolation record, the capture rules and the Codex installation) — the custodian's verdict at
    // read time. A custodian that reports no verdict for it vouches for no basis (fail closed).
    const basis = section.reviewBasis?.[String(h["reviewId"])] ?? null;
    const basisLost = accepted === true && current && basis?.basisUsable !== true;
    const notAccepted = !bound ? [...new Set([...r.not_accepted_reasons, "custodian_bindings_unreadable"])]
      : accepted === true && !current ? [...r.not_accepted_reasons, "evidence_epoch_superseded"]
      : basisLost ? [...new Set([...r.not_accepted_reasons, `custodian:${basis?.basisReason ?? "basis_unreported"}`])]
      : accepted === false ? [...new Set([...r.not_accepted_reasons, ...reasons.map((x) => `custodian:${x}`)])] : r.not_accepted_reasons;
    reviews.push({
      ...r,
      ...(bound ?? {}),
      round: typeof h["round"] === "number" ? (h["round"] as number) : r.round,
      accepted: !bound ? false : accepted === null ? r.accepted : accepted === true && current && !basisLost,
      not_accepted_reasons: notAccepted,
      item_ids: strs(h["itemIds"]),
    });
    const outcome = (h["outcome"] ?? null) as Rec | null;
    itemTexts.set(r.review_id, await verifiedItemTexts(runDir, r.artifacts["items"], (outcome?.["artifacts"] as Rec | undefined)?.["items"]));
  }

  // Items: every item the custodian holds (an open one may block completion), its claims and lifecycle; texts only
  // from a verified items artifact.
  const localItems = new Map(st.findings.map((f) => [f.id, f]));
  const findings: ReviewerItem[] = arr(rec["items"]).map((h) => {
    const id = String(h["itemId"]);
    const reviewId = String(h["reviewId"]);
    const local = localItems.get(id);
    const text = itemTexts.get(reviewId)?.get(id) ?? null;
    const heldAssessments = arr(h["assessments"]).map((a) => ({ review_id: String(a["reviewId"]), round: Number(a["round"]), source_id: String(a["sourceId"]), assessment: String(a["assessment"]), note: "", effect: String(a["effect"]) }));
    const assessments = local && local.assessments.length === heldAssessments.length && local.assessments.every((a, k) => a.review_id === heldAssessments[k]!.review_id && a.effect === heldAssessments[k]!.effect) ? local.assessments : heldAssessments;
    const base = text ?? local;
    return {
      ...(base ?? {}),
      id,
      item_kind: String(h["itemKind"]) as ReviewerItem["item_kind"],
      review_id: reviewId,
      round: Number(h["round"]),
      source_id: String(h["sourceId"]),
      review_input_id: base?.review_input_id ?? String(h["sourceId"]),
      title: text?.title ?? ITEM_TEXT_UNAVAILABLE,
      claim_type: (h["claimType"] ?? null) as ReviewerItem["claim_type"],
      severity: (h["severity"] ?? null) as ReviewerItem["severity"],
      category: (h["category"] ?? null) as ReviewerItem["category"],
      impacts: strs(h["impacts"]) as ReviewerItem["impacts"],
      consequence: text?.consequence ?? "",
      confidence: (h["confidence"] ?? null) as ReviewerItem["confidence"],
      evidence: text?.evidence ?? [],
      investigation: text?.investigation ?? "",
      recommended_change: text?.recommended_change ?? "",
      triage: String(h["triage"]) as ReviewerItem["triage"],
      basis: "reviewer_evidence",
      policy_notes: text?.policy_notes ?? [],
      status: String(h["status"]) as ReviewerItem["status"],
      related_prior_id: (h["relatedPriorId"] ?? null) as string | null,
      ...(h["relatedFindingId"] ? { related_finding_id: String(h["relatedFindingId"]) } : {}),
      supersedes: strs(h["supersedes"]),
      superseded_by: (h["supersededBy"] ?? null) as string | null,
      ...(strs(h["restates"]).length ? { restates: strs(h["restates"]) } : {}),
      assessments: assessments as ReviewerItem["assessments"],
      created_at: strOr(h["createdAt"], base?.created_at ?? ""),
    } as ReviewerItem;
  });

  // Responses and replies: held only; the custodian's claims (a disposition, a stance), the cache's text.
  const heldResp = new Map(arr(rec["responses"]).map((x) => [String(x["responseId"]), x]));
  const implementer_responses = st.implementer_responses
    .filter((x) => heldResp.has(x.response_id))
    .map((x) => ({ ...x, disposition: strOr(heldResp.get(x.response_id)!["disposition"], x.disposition) as typeof x.disposition }));
  const heldReply = new Map(arr(rec["replies"]).map((x) => [String(x["replyId"]), x]));
  const reviewer_replies = st.reviewer_replies
    .filter((x) => heldReply.has(x.reply_id))
    .map((x) => {
      const h = heldReply.get(x.reply_id)!;
      return { ...x, stance: strOr(h["stance"], x.stance), new_information: strOr(h["newInformation"], x.new_information), assessment: (h["assessment"] ?? null) as string | null };
    });

  // Isolation incidents: the custodian's for every operation it tracks (deleting or editing a local copy changes
  // nothing); a local one only for an operation the custodian never tracked (recorded before protection) — incidents
  // only ever restrict.
  const tracked = new Map<string, string>();
  for (const o of st.operations) if (typeof o["custodian_operation_id"] === "string") tracked.set(o["custodian_operation_id"] as string, o.operation_id);
  const trackedLocal = new Set(tracked.values());
  const isolation_incidents: StateRecord["isolation_incidents"] = [
    ...st.isolation_incidents.filter((i) => !trackedLocal.has(i.operation_id)),
    ...arr(rec["incidents"]).map((h) => ({
      incident_id: String(h["incidentId"]),
      review_id: (h["reviewId"] ?? null) as string | null,
      operation_id: tracked.get(String(h["operationId"])) ?? String(h["operationId"]),
      kind: String(h["kind"]) as StateRecord["isolation_incidents"][number]["kind"],
      detail: String(h["detail"] ?? ""),
      at: String(h["at"] ?? ""),
      source: "engine" as const,
      recorded_by: String(h["source"] ?? "custodian"),
    })),
  ];

  const out: StateRecord = { ...st, check_executions, reviews, findings, implementer_responses, reviewer_replies, isolation_incidents };
  Object.defineProperty(out, HYDRATED_FROM, { value: section, enumerable: false });
  Object.defineProperty(out, HYDRATED_RAW, { value: rawStateOf(st), enumerable: false });
  return out;
}

/**
 * C6, N8: the custodian's digest of every record of a protected run it bound that redaction reads — each review's
 * `capture.json` (`op_begin` captureDigest), the baseline's (`open`) and each response set's disclosure record
 * (`respond`) — by the local artifact ref. A record made before the run was protected has no custodian digest and is
 * absent (it was recorded attended).
 */
export function captureDigestsOf(section: RunSection | null, st: StateRecord): Map<string, string> {
  const out = new Map<string, string>();
  if (!section?.registered) return out;
  const rec = section.record ?? {};
  const byReview = new Map(arr(rec["reviews"]).map((r) => [String(r["reviewId"]), ((r["begin"] ?? {}) as Rec)["captureDigest"]]));
  for (const r of st.reviews) {
    const d = byReview.get(r.review_id);
    const ref = r.artifacts["capture"];
    if (ref && typeof d === "string") out.set(ref, d);
  }
  // N8: each response set's disclosure record (`respond` disclosureDigest), by the local ref.
  const bySet = new Map<string, unknown>();
  for (const x of arr(rec["responses"])) bySet.set(String(x["responseSetId"]), x["disclosureDigest"]);
  for (const r of st.implementer_responses) {
    const d = bySet.get(r.response_set_id);
    if (r.disclosure_ref && typeof d === "string") out.set(r.disclosure_ref, d);
  }
  const baseline = ((rec["declaration"] ?? {}) as Rec)["baseline"] as Rec | null | undefined;
  const prep = [...st.operations].reverse().find((o) => o.kind === "prepare" && o.status === "completed");
  const ref = (prep?.outcome as { capture_ref?: unknown } | undefined)?.capture_ref;
  if (baseline && typeof baseline["digest"] === "string" && typeof ref === "string") out.set(ref, baseline["digest"]);
  return out;
}

/** A view of the run's evidence through `section` (for a context that re-reads the state; null: not protected). */
export function evidenceViewOf(section: RunSection | null, runDir: string): ((st: StateRecord) => Promise<StateRecord>) | undefined {
  return section?.registered ? (st) => hydrateRunEvidence(st, section, runDir) : undefined;
}
