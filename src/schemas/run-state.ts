// Zod schemas for the authoritative run-state record (plan §15.3) and immutable run meta
// (§15.2). Schemas are the source of truth (plan §5.3 rule 5). Objects use `.catchall` so a
// newer writer's unknown fields survive a read-modify-write by this version (plan §5.6:
// open, versioned records; readers ignore unknown event types but must not drop them).

import { z } from "zod";
import { CheckExecutionRecordSchema } from "./checks.js";
import { LoopRecordSchema, LoopStartSchema } from "./continuation.js";
import { ReviewerReplySchema } from "./discussion.js";
import { ImplementerResponseSchema } from "./responses.js";
import { IsolationIncidentSchema, ReviewRecordSchema, ReviewerItemSchema } from "./review.js";
import { TaskAmendmentSchema, UserDecisionSchema } from "./user-authority.js";

/** Current on-disk schema version for run-state and run-meta records. */
export const STATE_SCHEMA_VERSION = 1;

/** Run states present in M1 (plan §5.5). Future phases add states via schema_version. */
export const RunStateEnum = z.enum([
  "PREPARING",
  "IDLE",
  "CHECKING",
  "REVIEWING",
  "INTERRUPTED",
  "CLOSED",
  "STOPPED",
  "CONFIGURATION_ERROR",
]);
export type RunState = z.infer<typeof RunStateEnum>;

export const OwnerSchema = z.object({
  serverInstanceId: z.string(),
  pid: z.number().int(),
  startedAtMs: z.number().int(),
  /** Linux: exact start identity ("<boot id>:<start ticks>", store/owner.ts); absent on Windows. */
  startIdentity: z.string().optional(),
});
export type Owner = z.infer<typeof OwnerSchema>;

export const OperationSchema = z
  .object({
    operation_id: z.string(),
    kind: z.string(), // "prepare" | "checks" | "review" (lenient for later kinds)
    status: z.string(), // running | completed | failed | timed_out | cancelled | interrupted
    owner: OwnerSchema.optional(),
    input_identity: z.string().optional(),
    request_id: z.string().optional(),
    started_at: z.string().optional(),
    ended_at: z.string().optional(),
    heartbeat_at: z.string().optional(),
    outcome: z.unknown().optional(),
    artifacts: z.array(z.string()).optional(),
  })
  .catchall(z.unknown());
export type Operation = z.infer<typeof OperationSchema>;

export const EventSchema = z
  .object({
    seq: z.number().int(),
    ts: z.string(),
    type: z.string(),
    actor: z.string(),
    summary: z.string(),
    refs: z.record(z.string(), z.string()).optional(),
  })
  .catchall(z.unknown());
export type RunEvent = z.infer<typeof EventSchema>;

export const StateRecordSchema = z
  .object({
    schema_version: z.number().int(),
    run_id: z.string(),
    state: RunStateEnum,
    revision: z.number().int().nonnegative(),
    created_at: z.string(),
    updated_at: z.string(),
    operations: z.array(OperationSchema).default([]),
    /** Reviewer items (findings and questions) from every review round (M1.4, MR-D). */
    findings: z.array(ReviewerItemSchema).default([]),
    /**
     * Implementer responses to reviewer items (Phase 2.1): append-only, keyed by item id, never
     * part of the items themselves. Additive: records written before Phase 2.1 have none, and an
     * older version keeps the field through its read-modify-write (catchall).
     */
    implementer_responses: z.array(ImplementerResponseSchema).default([]),
    /**
     * Reviewer replies to the implementer (Phase 2.2): append-only, written only by an accepted
     * review's completion commit, keyed by item id; never part of the items. Additive like the
     * responses: older records have none, and an older version keeps the field (catchall).
     */
    reviewer_replies: z.array(ReviewerReplySchema).default([]),
    /**
     * User decisions on discussion threads (Phase 2.3): append-only, written only through the user's
     * interactive CLI channel, never part of reviewer items, responses or replies. Additive like the
     * responses: older records have none, and an older version keeps the field (catchall).
     */
    user_decisions: z.array(UserDecisionSchema).default([]),
    /** The user's amendments to the immutable task envelope (Phase 2.3): append-only, same channel. */
    task_amendments: z.array(TaskAmendmentSchema).default([]),
    /**
     * P3.4C-1 selection hint (NOT a security boundary; a non-authoritative cache since P3.4C-2): set once the
     * first user decision/amendment for this run is recorded through the Windows custodian (`decide`/`amend
     * --protected`). Only the ATTENDED read path (status, history, operator views) consults it, to decide
     * whether to read the records from the custodian (governed) or from the TS arrays above (never-governed,
     * custodian-less Phase 2). Protected automation never consults it: whether a run is protected is the
     * custodian's own answer — its loop record for the run (P3.4C-2 contract §7) — and every automated action
     * requires the custodian and fails closed ([[D-14]]). Additive (catchall): older runs have none (false).
     */
    user_records_custodian: z.boolean().default(false),
    /**
     * P3.4C-3 hint (NOT a security boundary; contract §5.4): set once the custodian acknowledged the run's `open`. It
     * never selects records or decides authority; it can only add a refusal — a display read consults the custodian,
     * an unreachable custodian refuses instead of an attended fallback (C2 rule 4), and a run the custodian holds no
     * record of is refused (RUN_RECORD_MISSING). Additive: older runs have none (false).
     */
    run_records_custodian: z.boolean().default(false),
    /**
     * P3.4C-3 (contract §5.4): a run end the local stop applied that the custodian has not acknowledged yet; the next
     * engine call that reconciles the run sends it again. Additive and optional (absent when nothing is pending).
     */
    custodian_end_pending: z.object({ status: z.enum(["stopped", "closed"]), reason: z.string() }).optional(),
    engine_conditions: z.array(z.unknown()).default([]),
    /** Append-only isolation audit history (M1.4, §13.4). */
    isolation_incidents: z.array(IsolationIncidentSchema).default([]),
    /** Review records (M1.4); validated output, prompt and events live in artifacts. */
    reviews: z.array(ReviewRecordSchema).default([]),
    /** Check execution records (M1.3); tails and logs live in artifacts. */
    check_executions: z.array(CheckExecutionRecordSchema).default([]),
    counters: z.record(z.string(), z.number()).default({}),
    events: z.array(EventSchema).default([]),
    /**
     * Same-session continuation (Phase 3.3a): the run's automation loop, written only by the
     * engine's continuation controller. Additive: runs without a loop have none, and an older
     * version keeps the field through its read-modify-write (catchall).
     */
    continuation: LoopRecordSchema.optional(),
    /**
     * P3.4C-0: a protected loop start in progress or unreconciled (the consume intent, decision 4),
     * written only by the engine before it asks the custodian for a granted loop. Additive (catchall).
     */
    loop_start: LoopStartSchema.optional(),
  })
  .catchall(z.unknown());
export type StateRecord = z.infer<typeof StateRecordSchema>;

export const RunMetaSchema = z
  .object({
    schema_version: z.number().int(),
    run_id: z.string(),
    created_at: z.string(),
    repository_root: z.string(),
    root_commit: z.string().nullable().optional(),
    versions: z.record(z.string(), z.string()).default({}),
    scope: z
      .object({
        allowed_snapshot: z.array(z.string()),
        client_roots_snapshot: z.array(z.string()).default([]),
      })
      .catchall(z.unknown()),
    target: z.unknown().optional(),
    envelope: z.unknown().optional(),
  })
  .catchall(z.unknown());
export type RunMeta = z.infer<typeof RunMetaSchema>;

/** Build a fresh state record at revision 0. */
export function newStateRecord(runId: string, state: RunState = "PREPARING", now: string = new Date().toISOString()): StateRecord {
  return {
    schema_version: STATE_SCHEMA_VERSION,
    run_id: runId,
    state,
    revision: 0,
    created_at: now,
    updated_at: now,
    operations: [],
    findings: [],
    implementer_responses: [],
    reviewer_replies: [],
    user_decisions: [],
    task_amendments: [],
    user_records_custodian: false,
    run_records_custodian: false,
    engine_conditions: [],
    isolation_incidents: [],
    reviews: [],
    check_executions: [],
    counters: {},
    events: [],
  };
}
