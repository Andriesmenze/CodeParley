// Check definitions, approvals, execution records and the run verification floor
// (plan §7.3, §10.3, §14; MR-C, MR-G). Source of truth (§5.3 rule 5).
//
// The trust file itself is parsed leniently (schemas/trust.ts) so one bad check cannot make
// every project unreadable. A definition is RUNNABLE only after it passes the strict schema
// below: unknown keys are refused, because an unknown key may be a constraint this version
// does not honour (for example a future `concurrent` or `sandbox` flag). Fail closed.

import { z } from "zod";
import { LimitationSchema } from "./capture.js";

/** Check and profile names: short, path-safe, unambiguous in argv previews. */
export const CheckNameSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/, "check/profile names are 1-64 of [A-Za-z0-9._-], starting alphanumeric");

/** Environment variable names (Windows-safe; no '=' and no control characters). */
export const EnvNameSchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_.()-]{0,127}$/, "invalid environment variable name");

/** Repository-relative path written with forward slashes; validated further at use. */
export const RepoRelPathSchema = z
  .string()
  .min(1)
  .max(1024)
  .refine((p) => !/[\0\r\n]/.test(p), "control characters are not allowed");

export const DEFAULT_CHECK_TIMEOUT_SECONDS = 900;
export const MAX_CHECK_TIMEOUT_SECONDS = 3600;

export const CheckDefinitionSchema = z.strictObject({
  argv: z
    .array(z.string().max(32_767).refine((a) => !a.includes("\0"), "NUL is not allowed in argv"))
    .min(1)
    .max(256)
    .refine((a) => (a[0] ?? "").length > 0, "argv[0] must not be empty"),
  cwd: RepoRelPathSchema.default("."),
  timeout_seconds: z.number().int().min(1).max(MAX_CHECK_TIMEOUT_SECONDS).default(DEFAULT_CHECK_TIMEOUT_SECONDS),
  env: z.record(EnvNameSchema, z.string().max(32_767).refine((v) => !v.includes("\0"), "NUL is not allowed")).default({}),
  env_passthrough: z.array(EnvNameSchema).max(64).default([]),
  freshness_inputs: z.array(RepoRelPathSchema).max(64).default([]),
  description: z.string().max(500).optional(),
});
export type CheckDefinitionInput = z.input<typeof CheckDefinitionSchema>;
export type CheckDefinition = z.infer<typeof CheckDefinitionSchema>;

/** The approval record written only by `code-parley checks approve` (plan §14.2). */
export const ApprovalRecordSchema = z.object({
  at: z.string(),
  via: z.literal("cli"),
  /** Digest over the whole approved entry (path, root commit, checks, profiles, floor). */
  digest: z.string().regex(/^[0-9a-f]{64}$/),
  /** Per-check definition digests, to say WHICH check changed or disappeared. */
  checks: z.record(z.string(), z.string().regex(/^[0-9a-f]{64}$/)),
  tool_version: z.string().optional(),
});
export type ApprovalRecord = z.infer<typeof ApprovalRecordSchema>;

/** Definitions a user file (`--file`) or repository proposals provide for approval. */
export const ApprovalInputSchema = z.strictObject({
  checks: z.record(CheckNameSchema, z.unknown()),
  profiles: z.record(CheckNameSchema, z.array(CheckNameSchema).min(1).max(64)).default({}),
  required_profiles: z.array(CheckNameSchema).max(32).optional(),
  no_required_checks: z.boolean().optional(),
  test_globs: z.array(z.string().min(1).max(256)).max(64).optional(),
});
export type ApprovalInput = z.infer<typeof ApprovalInputSchema>;

// ---------------------------------------------------------------------------
// Execution records (persisted in state.json; tails live in artifacts)
// ---------------------------------------------------------------------------

export const CheckExecutionStatusEnum = z.enum(["passed", "failed", "error", "timed_out", "cancelled", "skipped"]);
export type CheckExecutionStatus = z.infer<typeof CheckExecutionStatusEnum>;

export const SkipReasonEnum = z.enum([
  "operation_cancelled", // the operation was cancelled before this check started
  "definition_removed", // the check is no longer defined in trusted configuration
  "definition_changed", // the definition changed since approval / since the operation started
  "approval_invalid", // the project's approval record does not match its definitions
]);
export type SkipReason = z.infer<typeof SkipReasonEnum>;

export const FreshnessInputDigestSchema = z.object({
  path: z.string(),
  /** file: regular file read and hashed; others: recorded state (still part of the identity). */
  state: z.enum(["file", "missing", "link", "not_regular", "alias", "unstable", "invalid_path"]),
  sha256: z.string().nullable(),
  size: z.number().int().nonnegative().nullable(),
});
export type FreshnessInputDigest = z.infer<typeof FreshnessInputDigestSchema>;

export const ResolvedExecutableSchema = z.object({
  path: z.string(),
  /** native (.exe/.com; Linux ELF), batch (Windows .cmd/.bat through cmd.exe), script (Linux "#!" file). */
  kind: z.enum(["native", "batch", "script"]),
  how: z.enum(["absolute", "relative", "path"]),
  size: z.number().int().nonnegative(),
  mtime_ms: z.number().int(),
});
export type ResolvedExecutableRecord = z.infer<typeof ResolvedExecutableSchema>;

export const StreamRecordSchema = z.object({
  bytes: z.number().int().nonnegative(),
  stored_bytes: z.number().int().nonnegative(),
  truncated: z.boolean(),
  /** Run-relative artifact reference of the stored (capped) log. */
  artifact: z.string().nullable(),
});

export const CheckExecutionRecordSchema = z
  .object({
    execution_id: z.string(),
    operation_id: z.string(),
    check: z.string(),
    status: CheckExecutionStatusEnum,
    skip_reason: SkipReasonEnum.optional(),
    error: z.string().optional(),
    definition_digest: z.string().nullable(),
    check_spec_id: z.string().nullable(),
    execution_input_id: z.string().nullable(),
    resolved_executable: ResolvedExecutableSchema.nullable(),
    /** Digest of the effective child environment (names and values; values never stored). */
    env_digest: z.string().nullable(),
    env_names: z.array(z.string()),
    /** Configured passthrough names that were absent from the server environment. */
    passthrough_missing: z.array(z.string()),
    freshness_inputs: z.array(FreshnessInputDigestSchema),
    freshness_digest: z.string().nullable(),
    source_id_at_start: z.string().nullable(),
    source_id_at_end: z.string().nullable(),
    /** Both source reads were internally stable and start == end. */
    source_stable: z.boolean(),
    started_at: z.string().nullable(),
    ended_at: z.string().nullable(),
    duration_ms: z.number().int().nonnegative().nullable(),
    exit_code: z.number().int().nullable(),
    pid: z.number().int().nullable(),
    timed_out: z.boolean(),
    cancelled: z.boolean(),
    stdout: StreamRecordSchema.nullable(),
    stderr: StreamRecordSchema.nullable(),
    stdio_held_after_exit: z.boolean(),
    descendants: z
      .object({ scanned: z.boolean(), survivors: z.array(z.object({ pid: z.number().int(), name: z.string() })), terminated: z.boolean().nullable() })
      .nullable(),
    /** Run-relative artifact reference of this execution's result.json (tails included). */
    result_artifact: z.string().nullable(),
    environment_bound: z.literal("partial"),
    limitations: z.array(LimitationSchema),
  })
  .catchall(z.unknown());
export type CheckExecutionRecord = z.infer<typeof CheckExecutionRecordSchema>;

// ---------------------------------------------------------------------------
// Verification floor (plan §7.3, D-29)
// ---------------------------------------------------------------------------

export const FloorRequirementSchema = z.object({
  check: z.string(),
  source: z.enum(["trusted_config", "run_argument"]),
  /** The profile that required it, or "check" when named directly. */
  via: z.string(),
  /** The check's definition digest when the floor was fixed (detects later changes). */
  definition_digest: z.string().nullable(),
});
export type FloorRequirement = z.infer<typeof FloorRequirementSchema>;

/** Fixed at run creation and stored in run.json; later trusted additions are unioned in at
 * evaluation time, and a later removal is REPORTED (never silently drops the requirement). */
export const RunVerificationFloorSchema = z.object({
  required: z.array(FloorRequirementSchema),
  no_required_checks: z.boolean(),
  approval_digest: z.string().nullable(),
});
export type RunVerificationFloor = z.infer<typeof RunVerificationFloorSchema>;
