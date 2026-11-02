// P3.4C-5 Increment 2 (contract §3.1, §3.3): a PROTECTED review is captured by the custodian, not by the engine. The engine
//  1. selects, without the capture, what the review presents — the check evidence and the discussion turns for the
//     source it reads now (a claim: `selectionSourceId`), the amendments it may present — and RESERVES the review with
//     the custodian (op_begin returns `measuring`);
//  2. waits on the run section until the custodian's helper has captured and the custodian has published, validated and
//     committed the capture (`captured`: the source id, the capture, manifest and export digests and the review input
//     identity are the custodian's) — or ended the operation (`deduplicated`, `error`, `cancelled`, `interrupted`);
//  3. reads the published capture record and manifest (read-only, digest-checked against what the custodian committed),
//     builds the bundle and prompt from them, and runs Codex on the PUBLISHED export (`--cd`);
//  4. finishes with op_finish, which now carries the prompt digest and what the bundle presented; the custodian
//     re-hashes the export it published before deciding acceptance.
// No pipe call waits for the measurement: the reservation returns at once and the engine polls the existing run section.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DomainError } from "../common/errors.js";
import { sha256OfBytes, sha256OfCanonicalJson } from "../common/hash.js";
import { CaptureRecordSchema, type CaptureRecord, type ReviewManifest } from "../schemas/capture.js";
import type { CaptureResult } from "../capture/capture.js";
import { publishArtifact } from "../store/artifacts.js";
import type { RunPaths } from "../store/paths.js";
import type { RunReviewPresented, RunReviewReserve } from "../custodian/protocol.js";
import type { CustodianEvidence } from "./custodian-evidence.js";

/** How long the engine waits for the custodian's capture (its helper's request deadline, the attach wait and a margin). */
export const CUSTODIAN_CAPTURE_WAIT_MS = 15 * 60_000;

/** How a reserved review's capture ended, as the run section shows the operation. */
export type CustodianCaptureOutcome =
  | { kind: "captured"; begin: Record<string, unknown> }
  | { kind: "deduplicated"; deduplicatedOf: string; round: number | null }
  | { kind: "ended"; status: string; reason: string; detail: string };

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Wait (bounded, cancellable) until the custodian's operation leaves `measuring`. Polls the run section; an unreachable
 * custodian is retried until the deadline. */
export async function awaitCustodianCapture(ev: CustodianEvidence, operationId: string, signal: AbortSignal, waitMs = CUSTODIAN_CAPTURE_WAIT_MS, pollMs = 250): Promise<CustodianCaptureOutcome | "aborted"> {
  const deadline = Date.now() + waitMs;
  let delay = pollMs;
  for (;;) {
    if (signal.aborted) return "aborted";
    const section = await ev.runSection().catch(() => null);
    const ops = (section?.record?.["operations"] ?? []) as unknown[];
    const op = ops.find((o): o is Record<string, unknown> => isObj(o) && o["operationId"] === operationId);
    if (op && op["status"] !== "measuring") {
      if (op["status"] === "captured" && isObj(op["begin"])) return { kind: "captured", begin: op["begin"] };
      const outcome = isObj(op["outcome"]) ? op["outcome"] : {};
      if (op["status"] === "deduplicated" && typeof outcome["deduplicatedOf"] === "string") {
        return { kind: "deduplicated", deduplicatedOf: outcome["deduplicatedOf"], round: typeof outcome["round"] === "number" ? outcome["round"] : null };
      }
      return { kind: "ended", status: String(op["status"]), reason: String(outcome["reason"] ?? op["status"]), detail: String(outcome["detail"] ?? "") };
    }
    if (Date.now() > deadline) throw new DomainError("REVIEW_CAPTURE_FAILED", `the custodian did not finish capturing this review within ${Math.round(waitMs / 60_000)} minutes; nothing was reviewed`, { retryable: true, details: { reason: "capture_wait_timeout" } });
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 2_000);
  }
}

/** P3.4C-5 Increment 3 (§4): how long the engine waits for one of the custodian's check measurements. */
export const CUSTODIAN_MEASURE_WAIT_MS = 15 * 60_000;

/** Wait (bounded, cancellable) until the custodian has measured a checks operation's START: the operation runs (true) or
 * ended without running (its reason). Polls the run section, like the capture wait. */
export async function awaitCustodianCheckStart(ev: CustodianEvidence, operationId: string, signal: AbortSignal, waitMs = CUSTODIAN_MEASURE_WAIT_MS, pollMs = 200): Promise<{ running: true } | { running: false; status: string; reason: string } | "aborted"> {
  const deadline = Date.now() + waitMs;
  let delay = pollMs;
  for (;;) {
    if (signal.aborted) return "aborted";
    const section = await ev.runSection().catch(() => null);
    const op = ((section?.record?.["operations"] ?? []) as unknown[]).find((o): o is Record<string, unknown> => isObj(o) && o["operationId"] === operationId);
    if (op && op["status"] !== "measuring") {
      if (op["status"] === "running") return { running: true };
      const outcome = isObj(op["outcome"]) ? op["outcome"] : {};
      return { running: false, status: String(op["status"]), reason: String(outcome["reason"] ?? op["status"]) };
    }
    if (Date.now() > deadline) throw new DomainError("CHECKS_MEASUREMENT_FAILED", `the custodian did not measure this checks operation's start within ${Math.round(waitMs / 60_000)} minutes; no check ran`, { retryable: true, details: { reason: "measure_wait_timeout" } });
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 2_000);
  }
}

/** Wait (bounded) until the custodian has measured the END of execution `executionId` and recorded it (its held record),
 * or no longer measures it without recording it (null). An abandoned wait leaves the custodian to record it. */
export async function awaitCustodianExecution(ev: CustodianEvidence, operationId: string, executionId: string, waitMs = CUSTODIAN_MEASURE_WAIT_MS, pollMs = 200): Promise<Record<string, unknown> | null> {
  const deadline = Date.now() + waitMs;
  let delay = pollMs;
  for (;;) {
    const section = await ev.runSection().catch(() => null);
    const record = section?.record ?? null;
    if (record) {
      const held = ((record["checkExecutions"] ?? []) as unknown[]).find((e): e is Record<string, unknown> => isObj(e) && e["executionId"] === executionId);
      if (held) return held;
      const op = ((record["operations"] ?? []) as unknown[]).find((o): o is Record<string, unknown> => isObj(o) && o["operationId"] === operationId);
      if (!op || !isObj(op["pending"]) || op["pending"]["executionId"] !== executionId) return null;
    }
    if (Date.now() > deadline) throw new DomainError("CHECKS_MEASUREMENT_FAILED", `the custodian did not record execution ${executionId} within ${Math.round(waitMs / 60_000)} minutes`, { retryable: true, details: { reason: "measure_wait_timeout" } });
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 2_000);
  }
}

const HEX64 = /^[0-9a-f]{64}$/;
const hexOf = (b: Record<string, unknown>, k: string): string => {
  const v = b[k];
  if (typeof v !== "string" || !HEX64.test(v)) throw new DomainError("INTERNAL", `the custodian's captured review has no valid ${k} (fail closed)`);
  return v;
};

/** The custodian-measured identities of a captured review (its op_begin bindings after the commit). */
export interface CustodianCaptured {
  sourceId: string;
  reviewInputId: string;
  captureId: string;
  captureStable: boolean;
  captureDigest: string;
  manifestDigest: string;
  exportDigest: string;
  exportPath: string;
  capturePath: string;
}

export function capturedIdentities(begin: Record<string, unknown>): CustodianCaptured {
  const cc = isObj(begin["custodianCapture"]) ? begin["custodianCapture"] : null;
  if (!cc || typeof cc["exportPath"] !== "string" || typeof cc["capturePath"] !== "string") throw new DomainError("INTERNAL", "the custodian's captured review names no published export (fail closed)");
  return {
    sourceId: hexOf(begin, "sourceId"), reviewInputId: hexOf(begin, "reviewInputId"), captureDigest: hexOf(begin, "captureDigest"),
    manifestDigest: hexOf(begin, "manifestDigest"), exportDigest: hexOf(begin, "exportDigest"),
    captureId: String(begin["captureId"] ?? ""), captureStable: begin["captureStable"] === true,
    exportPath: cc["exportPath"], capturePath: cc["capturePath"],
  };
}

/**
 * The capture the custodian published, read-only: its capture record (bytes with the digest it committed) and its
 * manifest (with the manifest digest it committed). The record is copied, byte for byte, into the run's artifacts, where
 * the engine's readers find a review's capture record (their digest checks bind it to the custodian's capture digest).
 * The returned capture's export directory is the PUBLISHED export, and its export identities are the custodian's.
 */
export async function loadPublishedCapture(paths: RunPaths, operationId: string, c: CustodianCaptured): Promise<CaptureResult> {
  const recordBytes = await readFile(c.capturePath).catch((e: unknown) => {
    throw new DomainError("REVIEW_CAPTURE_FAILED", `the custodian's published capture record cannot be read (${e instanceof Error ? e.message : String(e)}); nothing was reviewed`, { details: { reason: "capture_unreadable" } });
  });
  if (sha256OfBytes(recordBytes) !== c.captureDigest) throw new DomainError("REVIEW_CAPTURE_FAILED", "the published capture record does not have the digest the custodian committed; nothing was reviewed (fail closed)", { details: { reason: "capture_modified" } });
  let record: CaptureRecord;
  try {
    record = CaptureRecordSchema.parse(JSON.parse(recordBytes.toString("utf8")));
  } catch (e) {
    throw new DomainError("REVIEW_CAPTURE_FAILED", `the published capture record is not a capture record (${e instanceof Error ? e.message.slice(0, 200) : String(e)})`, { details: { reason: "capture_invalid" } });
  }
  if (record.source_id !== c.sourceId) throw new DomainError("REVIEW_CAPTURE_FAILED", "the published capture record is not of the source the custodian committed (fail closed)", { details: { reason: "capture_inconsistent" } });
  const rawManifest = await readFile(join(c.exportPath, "review", "manifest.json"), "utf8").catch(() => null);
  let manifest: ReviewManifest | null = null;
  try {
    const m = rawManifest ? (JSON.parse(rawManifest) as ReviewManifest & Record<string, unknown>) : null;
    if (m) {
      const { manifest_digest, ...rest } = m;
      if (manifest_digest === c.manifestDigest && sha256OfCanonicalJson(rest) === c.manifestDigest) manifest = m;
    }
  } catch {
    manifest = null;
  }
  if (!manifest) throw new DomainError("REVIEW_CAPTURE_FAILED", "the published manifest is missing or does not have the digest the custodian committed; nothing was reviewed (fail closed)", { details: { reason: "manifest_modified" } });
  const recordRef = (await publishArtifact(paths.runDir, paths.opsDir, operationId, "capture.json", recordBytes)).ref;
  const withCustodianExport: CaptureRecord = { ...record, export: { ...(record.export ?? { ref: "custodian-published" }), ref: c.exportPath.replace(/\\/g, "/"), export_digest: c.exportDigest, manifest_digest: c.manifestDigest } as CaptureRecord["export"] };
  return { record: withCustodianExport, recordRef, exportDir: c.exportPath, manifest, baselineDir: null, baseline: null };
}

/** What a reservation offers and binds (kept to check the bundle against it after the capture). */
export interface Reservation {
  fields: RunReviewReserve;
  /** The custodian's identities, once it committed the capture. */
  captured: CustodianCaptured | null;
}

/** The bundle's presentation, as op_finish claims it (each a subset of what the reservation offered). */
export function presentedOf(
  discussion: { digest: string; delivered: readonly { item_id: string; response_id: string; reply_sought?: boolean; basis?: readonly string[] }[] },
  notDeliveredCount: number,
  amendments: { digest: string; presented: readonly { amendment_id: string }[]; withheld: readonly { amendment_id: string }[] },
  disclosure: ReadonlyMap<string, string | null>,
  extraWithheld: readonly string[],
): RunReviewPresented {
  const delivered = new Map<string, string[]>();
  for (const d of discussion.delivered) delivered.set(d.item_id, [...new Set([...(delivered.get(d.item_id) ?? []), d.response_id])]);
  return {
    discussion: {
      digest: discussion.digest,
      delivered: [...delivered].map(([itemId, responseIds]) => ({ itemId, responseIds, replyIds: [] })),
      notDeliveredCount,
      // P3.4C-5 Increment 3 (§5.1): per delivered response, whether a reply was sought and why.
      deliveries: discussion.delivered.map((d) => ({ responseId: d.response_id, itemId: d.item_id, replySought: d.reply_sought === true, basis: [...new Set(d.basis ?? [])].slice(0, 16) })),
    },
    amendments: {
      digest: amendments.digest,
      presented: amendments.presented.map((a) => ({ amendmentId: a.amendment_id, disclosureDigest: disclosure.get(a.amendment_id) ?? null })),
      withheld: [...new Set([...amendments.withheld.map((w) => w.amendment_id), ...extraWithheld])],
    },
  };
}

/** The presentation must stay within what the reservation offered (the custodian refuses anything else). */
export function presentedWithinOffered(p: RunReviewPresented, offered: RunReviewReserve): string | null {
  const turns = new Map(offered.discussion.offered.map((d) => [d.itemId, new Set(d.responseIds)]));
  for (const d of p.discussion.delivered) {
    const allowed = turns.get(d.itemId);
    if (!allowed) return `item ${d.itemId} was not offered`;
    for (const r of d.responseIds) if (!allowed.has(r)) return `response ${r} on item ${d.itemId} was not offered`;
  }
  const amendments = new Map(offered.amendments.offered.map((a) => [a.amendmentId, a.disclosureDigest]));
  for (const a of p.amendments.presented) if (!amendments.has(a.amendmentId) || amendments.get(a.amendmentId) !== a.disclosureDigest) return `amendment ${a.amendmentId} was not offered`;
  for (const w of p.amendments.withheld) if (!amendments.has(w)) return `withheld amendment ${w} was not offered`;
  return null;
}
