// P3.4C-1 (constrained Option A): the operator-confirmed, reviewer-visible REDACTED representation of a
// protected task amendment. The RAW amendment text lives ONLY in the Windows custodian (operator surface);
// this engine-side artifact holds exactly the approved redacted representation a review may present, and
// nothing else. It is immutable and CONTENT-ADDRESSED by the SHA-256 of its own bytes, which is the
// `disclosure_digest` the custodian binds into the authoritative amendment record.
//
// At review time the artifact is validated against that digest before use; a missing or altered artifact
// FAILS CLOSED (the review withholds the amendment) — there is never a fallback to raw text or a legacy
// record. The original protected text is never written here, to the TS store, a review artifact, a log or
// an error (TD confidentiality requirement 4).

import { sha256OfString } from "../common/hash.js";
import { join } from "node:path";
import { publishArtifactInRun } from "../store/artifacts.js";
import { readTextIfExists } from "../store/atomic.js";
import type { RunPaths } from "../store/paths.js";
import type { TaskAmendment } from "../schemas/user-authority.js";

/** One amendment the review/listing could not present because its reviewer-visible disclosure artifact
 * was missing or altered (fail closed). */
export interface WithheldAmendment {
  amendment_id: string;
  reason: "disclosure_artifact_missing_or_altered";
}

/** The run-relative directory the content-addressed disclosure artifacts live in. */
const DIR = "user-disclosures";

/** Publish the reviewer-visible redacted text as an immutable, content-addressed artifact; returns its
 * SHA-256 (the id the custodian record binds) and the run-relative ref. The digest IS the content address,
 * so the stored file is self-validating. Published BEFORE the custodian prepare that binds the digest. */
export async function publishDisclosureArtifact(runPaths: RunPaths, redactedText: string): Promise<{ digest: string; ref: string }> {
  const digest = sha256OfString(redactedText);
  const a = await publishArtifactInRun(runPaths.runDir, runPaths.opsDir, DIR, digest, redactedText);
  return { digest, ref: a.ref };
}

/** Load and VALIDATE the artifact for `digest`: returns the text iff the stored bytes hash to `digest`
 * (integrity), else null — missing or altered, so the caller fails closed. No fallback to any other source. */
export async function loadDisclosureArtifact(runPaths: RunPaths, digest: string): Promise<string | null> {
  if (!/^[0-9a-f]{64}$/.test(digest)) return null;
  const raw = await readTextIfExists(join(runPaths.opsDir, DIR, digest)).catch(() => null);
  if (raw === null) return null;
  return sha256OfString(raw) === digest ? raw : null;
}

/**
 * Replace each custodian-backed amendment's (empty) `text` with its validated reviewer-visible disclosure
 * artifact, for a consumer that presents or displays amendment text (the review bundle, the `amend`
 * listing). A legacy amendment (no `disclosure_digest`) and a custodian amendment with no text pass through
 * unchanged. An amendment whose artifact is missing or altered is WITHHELD (dropped, reported) — fail
 * closed, never a fallback to raw text or a legacy record.
 */
export async function loadAmendmentTexts(runPaths: RunPaths, amendments: readonly TaskAmendment[]): Promise<{ amendments: TaskAmendment[]; withheld: WithheldAmendment[] }> {
  const out: TaskAmendment[] = [];
  const withheld: WithheldAmendment[] = [];
  for (const a of amendments) {
    if (typeof a.disclosure_digest !== "string") {
      out.push(a); // legacy text already present, or a custodian amendment with no text
      continue;
    }
    // Phase 5 F-i2-5: an amendment the custodian redacted has no artifact in the run store (the operator account cannot
    // write it); the representation the custodian holds with the record is used instead — under the same digest check.
    const held = typeof a.disclosure_text === "string" && sha256OfString(a.disclosure_text) === a.disclosure_digest ? a.disclosure_text : null;
    const text = (await loadDisclosureArtifact(runPaths, a.disclosure_digest)) ?? held;
    if (text === null) {
      withheld.push({ amendment_id: a.amendment_id, reason: "disclosure_artifact_missing_or_altered" });
      continue;
    }
    out.push({ ...a, text });
  }
  return { amendments: out, withheld };
}
