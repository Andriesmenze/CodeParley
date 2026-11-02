// Review input identity (plan §10.2, §10.4, MR-G review part). Pure.
//
// `review_input_id` binds a review to exactly what it was given: the source identity,
// the target and its base, the digest of the model-facing export manifest (which itself
// binds every exported file, the prepared diff, base/head copies, selected ignored
// context, exclusion counts and limitations), the included check evidence, focus and
// depth, prompt/schema/policy versions, Codex version and settings, and the effective
// isolation. Any change produces a new identity, so a new review is allowed (F10), and
// `freshness.inputs` compares this identity with the one a new review would have now.
//
// M1.2 produces the capture parts (source_id, target/base, manifest digest); M1.4 fills
// the reviewer parts; Phase 2.2 adds the presented discussion.

import { sha256OfCanonicalJson } from "../common/hash.js";

export const REVIEW_INPUT_ID_SCHEMA = "arl.review-input-id.v1";

export interface ReviewInputParts {
  source_id: string;
  target: { kind: "uncommitted" | "base_ref" | "since_baseline"; ref: string | null };
  /** Commit id, or baseline capture id, or null for an empty base. */
  base_id: string | null;
  export_manifest_digest: string;
  check_execution_ids: readonly string[];
  /**
   * Digest of the model-visible check evidence (status, exit code, freshness of each
   * check for the reviewed source, M1.4). The execution ids alone do not change when the
   * same executions become stale for a changed specification or environment.
   */
  check_evidence_digest?: string;
  focus: string | null;
  depth: string | null;
  /**
   * Phase 2.2 (plan §1.15, P2.2-5): SHA-256 of the discussion exactly as the bundle presented it
   * (both sections, after redaction and bounding) and of which turns it delivered. Reviews with
   * identical source and evidence but different discussion input get different identities, so the
   * unchanged-review guard never returns a review that saw other discussion.
   */
  discussion_digest?: string;
  /**
   * Phase 2.3 (plan §1.16, P2.3-9): SHA-256 of the user's task amendments exactly as the bundle
   * presented them, and of which it presented. Reviews that differ only in their effective user
   * amendments get different identities, so the unchanged-review guard never returns a review that
   * saw other amendments.
   */
  amendments_digest?: string;
  prompt_template: { id: string; version: string };
  output_schema_version: string;
  policy_version: string;
  codex: { version: string; model: string | null; reasoning_effort: string | null };
  /** EffectiveIsolation (plan §11.2), or any canonical description of it. */
  isolation: unknown;
}

export function computeReviewInputId(parts: ReviewInputParts): string {
  return sha256OfCanonicalJson({
    schema: REVIEW_INPUT_ID_SCHEMA,
    ...parts,
    // Evidence is a set: order of inclusion must not change the identity.
    check_execution_ids: [...parts.check_execution_ids].sort(),
  });
}
