// Capture records (plan §9.3–§9.5, §10.1, MR-F). Source of truth (§5.3 rule 5).
//
// Two audiences, two schemas:
//  - LOCAL (run store only, never exported): the capture record and baseline record keep
//    every path, class, size and hash, including confidential exclusions.
//  - MODEL-FACING (`review/manifest.json` in the export): permitted and context files
//    with hashes; confidential and repository-context exclusions as counts only — no
//    names, no per-file hashes, no exclusion patterns (MR-F).

import { z } from "zod";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const Oid = z.string().regex(/^[0-9a-f]{40}$|^[0-9a-f]{64}$/);

export const SourceClassEnum = z.enum([
  "permitted",
  "context",
  "excluded",
  "link_skipped",
  "size_skipped",
  "path_unsupported",
  "submodule",
]);
export type SourceClass = z.infer<typeof SourceClassEnum>;

/** What happened to a source entry in a review export (part of the review input, not the source). */
export const DispositionEnum = z.enum(["exported", "excluded_confidential", "excluded_repo_context", "context_reduced", "not_exported"]);
export type Disposition = z.infer<typeof DispositionEnum>;

export const ReviewTargetSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("uncommitted") }),
  z.object({ kind: z.literal("base_ref"), ref: z.string().min(1).max(256) }),
  z.object({ kind: z.literal("since_baseline") }),
]);
export type ReviewTarget = z.infer<typeof ReviewTargetSchema>;

export const TargetBaseSchema = z.object({
  kind: z.enum(["commit", "empty", "baseline"]),
  commit: Oid.nullable(),
  baseline_capture_id: z.string().nullable(),
});
export type TargetBase = z.infer<typeof TargetBaseSchema>;

export const LimitationSchema = z.object({
  code: z.string(),
  detail: z.string(),
  paths: z.array(z.string()).optional(),
  count: z.number().int().nonnegative().optional(),
});
export type Limitation = z.infer<typeof LimitationSchema>;

export const SourceEntrySchema = z.object({
  path: z.string(),
  area: z.enum(["tree", "context"]),
  class: SourceClassEnum,
  disposition: DispositionEnum,
  reason: z.string().optional(),
  size: z.number().int().nonnegative().nullable(),
  sha256: Sha256.nullable(),
  git_oid: Oid.nullable(),
  tracked: z.boolean(),
  index_flags: z.object({ assume_unchanged: z.boolean(), skip_worktree: z.boolean() }).optional(),
  filter: z.string().nullable(),
  working_tree_encoding: z.string().nullable(),
  git_eol_normalized: z.boolean(),
});
export type SourceEntry = z.infer<typeof SourceEntrySchema>;

export const EolInfoSchema = z.object({
  base_style: z.enum(["none", "lf", "crlf", "cr", "mixed"]),
  current_style: z.enum(["none", "lf", "crlf", "cr", "mixed"]),
  eol_change: z.boolean(),
  eol_only_change: z.boolean(),
  git_eol_normalized: z.boolean(),
});
export type EolInfo = z.infer<typeof EolInfoSchema>;

export const ChangeStatusEnum = z.enum(["added", "modified", "deleted", "type_changed", "renamed"]);
export type ChangeStatus = z.infer<typeof ChangeStatusEnum>;

export const DiffStateEnum = z.enum(["included", "truncated", "omitted", "binary", "note", "none"]);
export type DiffState = z.infer<typeof DiffStateEnum>;

export const ChangeEntrySchema = z.object({
  path: z.string(),
  status: ChangeStatusEnum,
  old_path: z.string().optional(),
  /** Matches a trusted confidentiality exclusion (never model-facing). */
  confidential: z.boolean(),
  /** Current-side class, or "absent" for a deletion. */
  class: z.union([SourceClassEnum, z.literal("absent")]),
  base: z
    .object({
      oid: Oid.nullable(),
      mode: z.string().nullable(),
      size: z.number().int().nonnegative().nullable(),
      source: z.enum(["commit", "baseline_copy", "baseline_commit"]),
      available: z.boolean(),
      reason: z.string().optional(),
    })
    .nullable(),
  current: z.object({ sha256: Sha256.nullable(), size: z.number().int().nonnegative().nullable() }).nullable(),
  binary: z.boolean().nullable(),
  eol: EolInfoSchema.nullable(),
  transformation_unsupported: z.boolean(),
  change_uncertain: z.boolean(),
  index_flag_hidden: z.boolean(),
  committed: z.boolean().nullable(),
  uncommitted: z.boolean().nullable(),
  in_export: z.object({ base: z.boolean(), head: z.boolean() }),
  diff: DiffStateEnum,
});
export type ChangeEntry = z.infer<typeof ChangeEntrySchema>;

export const RepoSupportSchema = z.object({
  git_version: z.string(),
  object_format: z.enum(["sha1", "sha256"]),
  unborn_head: z.boolean(),
  shallow: z.boolean(),
  partial_clone: z.boolean(),
  linked_worktree: z.boolean(),
  external_git_dir: z.boolean(),
  submodules: z.number().int().nonnegative(),
  index_flags: z.object({ assume_unchanged: z.number().int().nonnegative(), skip_worktree: z.number().int().nonnegative() }),
  filters_in_use: z.array(z.string()),
  transformation_unsupported: z.number().int().nonnegative(),
  in_progress: z.array(z.string()),
});
export type RepoSupport = z.infer<typeof RepoSupportSchema>;

export const CaptureRulesSchema = z.object({
  exclude_globs: z.array(z.string()),
  context_include: z.array(z.string()),
  repo_exclude_paths: z.array(z.string()),
  max_file_bytes: z.number().int().positive(),
  max_export_bytes: z.number().int().positive(),
  max_diff_bytes: z.number().int().positive(),
});
export type CaptureRules = z.infer<typeof CaptureRulesSchema>;

export const InstabilitySchema = z.object({ path: z.string(), reason: z.string() });

/** LOCAL capture record: `ops/<capture-id>/capture.json`. Never exported. */
export const CaptureRecordSchema = z.object({
  schema: z.literal("arl.capture-record.v1"),
  capture_id: z.string(),
  kind: z.enum(["review", "baseline"]),
  started_at: z.string(),
  completed_at: z.string(),
  repository: z.object({
    root: z.string(),
    git_dir: z.string(),
    common_dir: z.string(),
    head_commit: Oid.nullable(),
    branch: z.string().nullable(),
  }),
  git: z.object({ exe: z.string(), version: z.string() }),
  target: ReviewTargetSchema,
  base: TargetBaseSchema,
  rules: CaptureRulesSchema,
  rules_digest: Sha256,
  support: RepoSupportSchema,
  source_id: Sha256,
  entries: z.array(SourceEntrySchema),
  changes: z.array(ChangeEntrySchema),
  eol_conversion_equivalent: z.array(z.string()),
  limitations: z.array(LimitationSchema),
  /** The same limitations in model-facing form (MR-F: withheld paths counted, never named; M1.5). */
  model_limitations: z.array(LimitationSchema).default([]),
  stable: z.boolean(),
  instability: z.array(InstabilitySchema),
  neutralized_filters: z.array(z.string()),
  export: z
    .object({
      ref: z.string(),
      manifest_digest: Sha256,
      export_digest: Sha256,
      file_count: z.number().int().nonnegative(),
      total_bytes: z.number().int().nonnegative(),
    })
    .nullable(),
  baseline: z.object({ ref: z.string(), copied: z.number().int().nonnegative() }).nullable(),
  timings_ms: z.record(z.string(), z.number()),
});
export type CaptureRecord = z.infer<typeof CaptureRecordSchema>;

/** MODEL-FACING manifest: `review/manifest.json` in the export (MR-F). */
export const ReviewManifestSchema = z.object({
  schema: z.literal("arl.review-manifest.v1"),
  capture_id: z.string(),
  target: z.object({ kind: z.enum(["uncommitted", "base_ref", "since_baseline"]), ref: z.string().nullable() }),
  base: TargetBaseSchema,
  head: z.object({ commit: Oid.nullable(), branch: z.string().nullable() }),
  object_format: z.enum(["sha1", "sha256"]),
  source_id: Sha256,
  /** Opaque digest of the trusted capture rules; the patterns themselves are not disclosed. */
  rules_digest: Sha256,
  limits: z.object({ max_file_bytes: z.number().int(), max_export_bytes: z.number().int(), max_diff_bytes: z.number().int() }),
  files: z.array(z.object({ path: z.string(), area: z.enum(["tree", "context"]), size: z.number().int().nonnegative(), sha256: Sha256 })),
  changes: z.array(
    z.object({
      path: z.string(),
      status: ChangeStatusEnum,
      old_path: z.string().optional(),
      class: z.union([SourceClassEnum, z.literal("absent")]),
      binary: z.boolean().nullable(),
      eol: EolInfoSchema.nullable(),
      transformation_unsupported: z.boolean(),
      change_uncertain: z.boolean(),
      index_flag_hidden: z.boolean(),
      committed: z.boolean().nullable(),
      uncommitted: z.boolean().nullable(),
      base_in_export: z.boolean(),
      head_in_export: z.boolean(),
      diff: DiffStateEnum,
    }),
  ),
  review_files: z.object({
    diff_patch: z.object({ size: z.number().int().nonnegative(), sha256: Sha256 }),
    base: z.array(z.object({ path: z.string(), size: z.number().int().nonnegative(), sha256: Sha256 })),
    head: z.array(z.object({ path: z.string(), size: z.number().int().nonnegative(), sha256: Sha256 })),
  }),
  exclusions: z.object({
    confidential: z.object({ count: z.number().int().nonnegative(), changed_count: z.number().int().nonnegative() }),
    repository_context: z.object({ count: z.number().int().nonnegative() }),
    size_skipped: z.array(z.object({ path: z.string(), size: z.number().int().nonnegative().nullable(), changed: z.boolean() })),
    context_reduced: z.array(z.object({ path: z.string(), size: z.number().int().nonnegative().nullable() })),
    link_skipped: z.array(z.object({ path: z.string(), reason: z.string() })),
    path_unsupported: z.array(z.object({ path: z.string(), reason: z.string() })),
    submodules: z.array(z.object({ path: z.string(), changed: z.boolean() })),
  }),
  eol_conversion_equivalent: z.object({ count: z.number().int().nonnegative(), paths: z.array(z.string()) }),
  limitations: z.array(LimitationSchema),
  stable: z.boolean(),
  manifest_digest: Sha256,
});
export type ReviewManifest = z.infer<typeof ReviewManifestSchema>;

/** LOCAL baseline record: `baseline/<capture-id>/baseline.json` (plan §9.4 "Baseline capture"). */
export const BaselineEntrySchema = z.object({
  path: z.string(),
  class: SourceClassEnum,
  size: z.number().int().nonnegative().nullable(),
  sha256: Sha256.nullable(),
  git_oid: Oid.nullable(),
  /** Where since_baseline gets this path's base content. */
  base: z.enum(["commit_blob", "copy", "unavailable"]),
  reason: z.string().optional(),
});
export type BaselineEntry = z.infer<typeof BaselineEntrySchema>;

export const BaselineRecordSchema = z.object({
  schema: z.literal("arl.baseline.v1"),
  capture_id: z.string(),
  object_format: z.enum(["sha1", "sha256"]),
  head_commit: Oid.nullable(),
  source_id: Sha256,
  entries: z.array(BaselineEntrySchema),
});
export type BaselineRecord = z.infer<typeof BaselineRecordSchema>;
