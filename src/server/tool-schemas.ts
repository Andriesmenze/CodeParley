// Tool input and output schemas for the M1 surface (plan §11.2–§11.8). zod is the source of
// truth (D-08); the JSON Schemas advertised in tools/list are generated from it.
//
// Inputs are STRICT: an unknown key is INVALID_ARGUMENT. That is how this layer refuses
// model-supplied copies of engine-owned data — source files, diffs, manifests, check results,
// findings, isolation settings, roots, budgets above the configuration, a lowered floor —
// there is simply no field that could carry them (plan §4.1 R-12, D-29, T2).
//
// Outputs have an object root (2025-11-25 requires it) and stay permissive: the
// structuredContent is the complete result (K7), and its shape varies between a running
// operation handle, a finished result and an error.

import { z } from "zod";
import { DISPOSITIONS, RESPONSE_LIMITS } from "../schemas/responses.js";
import { TaskEnvelopeSchema } from "../schemas/review.js";
import { DelegateFixInputSchema } from "../engine/fix-operation.js";

const Id = z.string().min(1).max(64);
const RequestId = z.string().min(1).max(128);
const WaitSeconds = z.number().min(0).max(3600);
const CheckName = z.string().min(1).max(128);

export const CreateReviewRunInput = z.strictObject({
  task_envelope: TaskEnvelopeSchema,
  repository_root: z.string().min(1).max(1024).optional(),
  review_target: z
    .discriminatedUnion("kind", [
      z.strictObject({ kind: z.literal("uncommitted") }),
      z.strictObject({ kind: z.literal("since_baseline") }),
      z.strictObject({ kind: z.literal("base_ref"), ref: z.string().min(1).max(256) }),
    ])
    .optional(),
  additional_required_checks: z.array(CheckName).max(50).optional(),
  budget_overrides: z.strictObject({ max_reviews: z.number().int().min(1).optional(), max_check_executions: z.number().int().min(1).optional() }).optional(),
  request_id: RequestId.optional(),
  wait_seconds: WaitSeconds.optional(),
});

export const RunChecksInput = z.strictObject({
  run_id: Id,
  checks: z.array(CheckName).max(100).optional(),
  profiles: z.array(CheckName).max(50).optional(),
  request_id: RequestId.optional(),
  wait_seconds: WaitSeconds.optional(),
});

export const ReviewWithCodexInput = z.strictObject({
  run_id: Id,
  focus: z.string().max(4000).optional(),
  depth: z.enum(["focused", "standard", "deep"]).optional(),
  force_new: z.boolean().optional(),
  request_id: RequestId.optional(),
  wait_seconds: WaitSeconds.optional(),
});

/** Phase 4 Increment 3: delegate ONE scoped fix — a task and a boundary, never contents, a diff or a confirmation. */
export const DelegateFixToolInput = DelegateFixInputSchema.extend({ run_id: Id, wait_seconds: WaitSeconds.optional() }).strict();

/** Phase 4 Increment 3: apply the owner-confirmed proposal of a delegated fix — its id only (no contents, no confirmation). */
export const ApplyFixToolInput = z.strictObject({ run_id: Id, proposal_id: Id });

export const GetReviewStatusInput = z.strictObject({
  run_id: Id.optional(),
  wait_seconds: WaitSeconds.optional(),
});

export const GetReviewHistoryInput = z.strictObject({
  run_id: Id,
  after_seq: z.number().int().min(0).optional(),
  limit: z.number().int().min(1).max(100).optional(),
  artifact: z
    .strictObject({
      operation_id: Id,
      part: z.string().min(1).max(64),
      offset: z.number().int().min(0).optional(),
      length: z.number().int().min(1).max(30_000).optional(),
    })
    .optional(),
  /** The implementer-response history (Phase 2.1), optionally of one item and its lineage. */
  responses: z
    .strictObject({
      finding_id: Id.optional(),
      offset: z.number().int().min(0).optional(),
      length: z.number().int().min(1).max(30_000).optional(),
    })
    .optional(),
});

/**
 * Phase 2.1: the implementer's responses to reviewer items. Only an engine item id, the token
 * the engine showed for it, a disposition, a bounded rationale and optional claimed locations
 * can be supplied — no reviewer text, status, source id, check result, isolation setting or
 * authority label (there is no field for any of them, and unknown keys are refused).
 */
export const RespondToReviewInput = z.strictObject({
  run_id: Id,
  responses: z
    .array(
      z.strictObject({
        finding_id: Id,
        response_token: z.string().min(1).max(64),
        disposition: z.enum(DISPOSITIONS),
        rationale: z.string().max(RESPONSE_LIMITS.rationaleChars).optional(),
        references: z
          .array(
            z.strictObject({
              path: z.string().min(1).max(RESPONSE_LIMITS.referencePathChars),
              start_line: z.number().int().min(1).optional(),
              end_line: z.number().int().min(1).optional(),
            }),
          )
          .max(RESPONSE_LIMITS.referencesPerResponse)
          .optional(),
      }),
    )
    .min(1)
    .max(RESPONSE_LIMITS.perCall),
  request_id: RequestId.optional(),
});

/**
 * Phase 3.3a: start same-session continuation for a run. Only the run: budgets come from the
 * operator's grant and the engine's limits, the session from the host's own hook — no field could
 * carry a budget, a session or binding identity, or an authority.
 */
export const StartReviewLoopInput = z.strictObject({
  run_id: Id,
});

export const StopReviewLoopInput = z.strictObject({
  run_id: Id,
  mode: z.enum(["cancel_active", "abort", "close"]),
  expected_operation_id: Id.optional(),
  reason: z.string().max(1000).optional(),
});

export const DiagEchoInput = z.strictObject({
  text: z.string().max(1000).optional(),
});

/** JSON Schema for tools/list (input form, unknown keys refused). */
export function inputJsonSchema(schema: z.ZodType): Record<string, unknown> {
  const j = z.toJSONSchema(schema, { io: "input", target: "draft-2020-12" }) as Record<string, unknown>;
  delete j["$schema"];
  return j;
}

const Limitation = z.looseObject({ code: z.string(), detail: z.string(), paths: z.array(z.string()).optional(), count: z.number().optional() });
const ErrorObject = z.looseObject({ code: z.string(), message: z.string(), retryable: z.boolean(), details: z.record(z.string(), z.unknown()).optional() });

/** Fields every result may carry; tool-specific fields are documented in the descriptions. */
function outputSchema(fields: Record<string, z.ZodType>): Record<string, unknown> {
  const j = z.toJSONSchema(
    z.looseObject({
      summary: z.string().describe("Human-readable summary for the model; the rest of this object is the complete result"),
      error: ErrorObject.optional().describe("Present only on error results (isError: true)"),
      truncation: z.looseObject({ truncated: z.boolean() }).optional(),
      ...fields,
    }),
    { io: "output", target: "draft-2020-12" },
  ) as Record<string, unknown>;
  delete j["$schema"];
  return j;
}

const Handle = {
  operation_id: z.string().optional(),
  kind: z.string().optional(),
  status: z.string().optional().describe('"running" for an operation still in progress (a handle), else the final status'),
  started_at: z.string().optional(),
  elapsed_ms: z.number().optional(),
  progress: z.string().optional(),
  deduplicated: z.boolean().optional(),
  next: z.string().optional(),
};

export const OUTPUT_SCHEMAS: Record<string, Record<string, unknown>> = {
  create_review_run: outputSchema({ run_id: z.string().optional(), state: z.string().optional(), repository: z.unknown().optional(), scope: z.unknown().optional(), verification_floor: z.unknown().optional(), checks_available: z.unknown().optional(), budgets: z.unknown().optional(), warnings: z.array(Limitation).optional(), prepare: z.unknown().optional() }),
  run_checks: outputSchema({ run_id: z.string().optional(), ...Handle, results: z.unknown().optional(), floor: z.unknown().optional(), limitations: z.array(Limitation).optional() }),
  review_with_codex: outputSchema({ run_id: z.string().optional(), ...Handle, review_id: z.string().nullable().optional(), findings: z.unknown().optional(), open_findings: z.unknown().optional(), conditions: z.unknown().optional(), incidents: z.unknown().optional(), limitations: z.array(Limitation).optional(), discussion: z.unknown().optional(), amendments: z.unknown().optional(), continuation: z.unknown().optional() }),
  get_review_status: outputSchema({ run_id: z.string().optional(), state: z.string().optional(), active_operation: z.unknown().optional(), completed_operation: z.unknown().optional(), completion: z.unknown().optional(), user: z.unknown().optional(), open_findings: z.unknown().optional(), discussion: z.unknown().optional(), continuation: z.unknown().optional(), runs: z.unknown().optional(), fixes: z.unknown().optional() }),
  get_review_history: outputSchema({ run_id: z.string().optional(), events: z.unknown().optional(), next_after_seq: z.number().nullable().optional(), artifact: z.unknown().optional(), responses: z.unknown().optional() }),
  respond_to_review: outputSchema({ run_id: z.string().optional(), response_set_id: z.string().optional(), deduplicated: z.boolean().optional(), recorded: z.unknown().optional(), source: z.unknown().optional(), note: z.string().optional(), delivery_preview: z.unknown().optional() }),
  start_review_loop: outputSchema({ run_id: z.string().optional(), continuation: z.unknown().optional(), bind_nonce: z.string().nullable().optional(), existing: z.boolean().optional(), note: z.string().optional() }),
  stop_review_loop: outputSchema({ run_id: z.string().optional(), state: z.string().optional(), cancellation: z.unknown().optional(), custodian_end: z.unknown().optional(), completion: z.unknown().optional(), user: z.unknown().optional(), discussion: z.unknown().optional(), note: z.string().optional() }),
  diag_echo: outputSchema({ echo: z.string().nullable().optional(), protocol: z.unknown().optional(), client: z.unknown().optional() }),
  delegate_fix: outputSchema({ run_id: z.string().optional(), status: z.string().optional(), proposal_id: z.string().optional(), fix_id: z.string().optional(), proposal: z.unknown().optional(), violations: z.unknown().optional(), next: z.string().optional() }),
  apply_fix: outputSchema({ run_id: z.string().optional(), status: z.string().optional(), proposal_id: z.string().optional(), apply_operation_id: z.string().optional(), files: z.unknown().optional(), source_id_after: z.string().nullable().optional(), next: z.string().optional() }),
};
