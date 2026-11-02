// Zod schemas for same-session continuation (Phase 3.3a): the loop record a run carries, the
// protected loop-start marker (P3.4C-0) and the session index.
//
// A loop is CodeParley's trusted controller state for keeping the ORIGINATING Claude Code session
// working on one run: its budgets, its deadline, its binding to the host session and the wakes it
// armed. It is written only by the engine (engine/continuation.ts, engine/loop-authority.ts) and
// never by an MCP argument, hook text or model narration. It adds liveness, never authority:
// nothing here records a user decision, completion or permission to commit, push or release.
// The operator's loop GRANTS are not here: since P3.4C-0 they are owned by the Windows custodian
// (src/custodian/); the former user-writable grants file is no longer read by anything.
//
// Records are open (`.catchall`) so a newer writer's fields survive a read-modify-write by this
// version (plan §5.6), like every other run-state record.

import { z } from "zod";

export const LOOP_SCHEMA = "codeparley.loop.v1";
export const SESSION_INDEX_SCHEMA = "codeparley.session-binding.v1";

/**
 * unbound — started, waiting for the host to bind it to the session that received the result;
 * active  — automation may continue within its budgets;
 * paused  — automation stopped until the operator resumes it (`pause.reason` says why);
 * the rest have ended: the run's session is released and nothing continues automatically.
 */
export const LOOP_STATUSES = ["unbound", "active", "paused", "ready", "budget_exhausted", "expired", "cancelled", "run_ended"] as const;
export type LoopStatus = (typeof LOOP_STATUSES)[number];

export const ENDED_LOOP_STATUSES: ReadonlySet<LoopStatus> = new Set(["ready", "budget_exhausted", "expired", "cancelled", "run_ended"]);

export const PAUSE_REASONS = [
  // the user interrupted a turn or a call (host cancellation, or the host's interrupt marker)
  "user_interrupt",
  // a discussion thread needs a user decision (the Phase 2.3 hard pause)
  "user_decision_required",
  // the engine reports a condition only the operator can resolve (configuration, incident)
  "operator_action_required",
  // an operation ended interrupted, failed, cancelled or timed out: never retried automatically
  "operation_unsuccessful",
  // the session's settings changed while automation was live
  "config_change",
  // the session's process identity was missing, stale or inconsistent
  "process_identity",
  // P3.4C-5 Increment 3 (§5.2): the custodian refused a continuation or wake because no work fact changed since the last
  "no_progress",
] as const;
export type PauseReason = (typeof PAUSE_REASONS)[number];

const Iso = z.string().min(1).max(64);

/** The originating Claude Code process as observed when the session bound (or re-bound) the loop. */
export const ProcessIdentitySchema = z
  .object({
    /** CLAUDE_PID as the host passed it to the hook (null: absent or not a pid). */
    pid: z.number().int().nullable(),
    /** The process's start time (epoch ms) read from the OS, or null. */
    started_at_ms: z.number().int().nullable(),
    /** Linux: exact start identity ("<boot id>:<start ticks>"). */
    start_identity: z.string().max(128).optional(),
    /** True only when the pid was present, alive, an ancestor of the hook process, and its start time was read. */
    verified: z.boolean(),
    detail: z.string().max(500),
  })
  .catchall(z.unknown());
export type ProcessIdentity = z.infer<typeof ProcessIdentitySchema>;

export const BINDING_STATES = ["live", "closed", "released"] as const;

export const BindingSchema = z
  .object({
    /** The host's session id: a correlation identifier, never a credential (it is not secret). */
    session_id: z.string().min(1).max(256),
    /** Starts at 1; every re-binding (a resumed session) adds 1, so a wake armed before it is stale. */
    epoch: z.number().int().min(1),
    state: z.enum(BINDING_STATES),
    bound_at: Iso,
    rebound_at: Iso.nullable(),
    closed_at: Iso.nullable(),
    close_reason: z.string().max(300).nullable(),
    process: ProcessIdentitySchema.nullable(),
  })
  .catchall(z.unknown());
export type Binding = z.infer<typeof BindingSchema>;

export const WakeArmSchema = z.object({ instance: z.string().max(64), epoch: z.number().int(), armed_at: Iso, waiter_pid: z.number().int() }).catchall(z.unknown());
export type WakeArm = z.infer<typeof WakeArmSchema>;

/** The wake CodeParley may deliver for one review operation: at most one is ever consumed. */
export const WakeRecordSchema = z
  .object({
    operation_id: z.string().min(1).max(64),
    armed: z.array(WakeArmSchema),
    consumed: z.object({ at: Iso, instance: z.string().max(64), epoch: z.number().int() }).catchall(z.unknown()).nullable(),
    rejected: z.array(z.object({ at: Iso, instance: z.string().max(64), reason: z.string().max(300) }).catchall(z.unknown())),
    /** The session ran a turn (or the user prompted) after the operation finished: a wake is not needed. */
    superseded_at: Iso.nullable(),
  })
  .catchall(z.unknown());
export type WakeRecord = z.infer<typeof WakeRecordSchema>;

export const LoopLimitsSchema = z
  .object({
    continuations: z.number().int().min(0),
    wakes_per_operation: z.number().int().min(0),
    wakes_per_run: z.number().int().min(0),
    run_seconds: z.number().int().min(1),
  })
  .catchall(z.unknown());
export type LoopLimits = z.infer<typeof LoopLimitsSchema>;

export const LoopRecordSchema = z
  .object({
    schema: z.literal(LOOP_SCHEMA),
    loop_id: z.string().min(1).max(64),
    status: z.enum(LOOP_STATUSES),
    started_at: Iso,
    /** Wall-clock end of automation (started_at + limits.run_seconds). */
    deadline_at: Iso,
    /** The operator grant this loop consumed. */
    grant_id: z.string().min(1).max(64),
    /**
     * P3.4C-0: the custodian's record of that consumption — the loop it counted and how much of the grant
     * was used then. Absent on loops started from the former grants file (they carry grant_id only).
     */
    grant_use: z
      .object({ source: z.literal("custodian"), loop_id: z.string().max(64), request_id: z.string().max(128), loops_used: z.number().int().min(0), loops_total: z.number().int().min(0) })
      .catchall(z.unknown())
      .optional(),
    limits: LoopLimitsSchema,
    used: z.object({ continuations: z.number().int().min(0), wakes: z.number().int().min(0) }).catchall(z.unknown()),
    /** The one-time binding nonce, stored as a hash only; valid for a short time, used once. */
    bind_nonce: z.object({ sha256: z.string().length(64), issued_at: Iso, expires_at: Iso, used_at: Iso.nullable() }).catchall(z.unknown()),
    binding: BindingSchema.nullable(),
    pause: z.object({ reason: z.enum(PAUSE_REASONS), detail: z.string().max(500), at: Iso }).catchall(z.unknown()).nullable(),
    /** The operator's latest resume: operations that ended before it no longer pause the loop. */
    resumed_at: Iso.nullable(),
    ended: z.object({ status: z.enum(LOOP_STATUSES), reason: z.string().max(500), at: Iso }).catchall(z.unknown()).nullable(),
    wakes: z.array(WakeRecordSchema),
    interrupts: z.array(z.object({ at: Iso, via: z.string().max(64), detail: z.string().max(300) }).catchall(z.unknown())),
    /** The latest prompt a person typed in the bound session (task notifications excluded). */
    last_user_prompt_at: Iso.nullable(),
    /**
     * Whether the bound session is in a turn, as its hooks report it: a prompt or a wake starts
     * one, an allowed stop ends it. A wake is delivered only to an idle session; a finished
     * operation is otherwise reported by the next Stop decision.
     */
    turn: z.object({ active: z.boolean(), at: Iso }).catchall(z.unknown()),
    /** The latest automated continuation: what the engine state was when it was given. */
    last_continuation: z.object({ at: Iso, digest: z.string().max(64), action: z.string().max(64) }).catchall(z.unknown()).nullable(),
  })
  .catchall(z.unknown());
export type LoopRecord = z.infer<typeof LoopRecordSchema>;

/**
 * P3.4C-0 crash safety (decision 4): a protected loop start in progress. Written to the run's state in
 * its own commit BEFORE the custodian is asked to consume a granted loop, and removed in the same commit
 * that creates the loop. A start that finds one it did not write never consumes again on its own:
 * `pending` and recent — another start is in flight (RUN_BUSY); `pending` and stale, or `unreconciled` —
 * whether that start consumed a granted loop cannot be established, so automation is refused until the
 * operator acknowledges it (`code-parley loop stop <run>` sets `abandoned`).
 */
export const LoopStartSchema = z
  .object({
    request_id: z.string().min(1).max(128),
    loop_id: z.string().min(1).max(64),
    started_at: Iso,
    status: z.enum(["pending", "unreconciled", "abandoned"]),
    detail: z.string().max(500).nullable(),
  })
  .catchall(z.unknown());
export type LoopStart = z.infer<typeof LoopStartSchema>;

/**
 * P3.4C-2: the CUSTODIAN's implementer projection of a run's loop (custodian/…/Ledger/GrantLedger.Loops.cs
 * ImplementerLoopProjection; contract §6) — the authority the engine overlays onto its local cache: status,
 * epoch, revision, budgets, deadline, the binding verdict, the pause, the end, the operation handles and the
 * wake claims. It carries no session id, process facts, nonce or history. Open (`.catchall`) like the other
 * records, so a newer custodian's extra fields are kept; a missing or mistyped field fails the parse, and the
 * engine then fails closed.
 */
export const CustodianLoopSchema = z
  .object({
    loopId: z.string().min(1).max(64),
    status: z.enum(LOOP_STATUSES),
    epoch: z.number().int().min(1),
    loopRevision: z.number().int().min(1),
    startedAt: Iso,
    deadlineAt: Iso,
    grantId: z.string().min(1).max(64),
    grantUse: z.object({ loopsUsed: z.number().int().min(0), loopsTotal: z.number().int().min(0) }).catchall(z.unknown()),
    limits: z.object({ continuations: z.number().int().min(0), wakesPerOperation: z.number().int().min(0), wakesPerRun: z.number().int().min(0), runSeconds: z.number().int().min(1) }).catchall(z.unknown()),
    used: z.object({ continuations: z.number().int().min(0), wakes: z.number().int().min(0) }).catchall(z.unknown()),
    binding: z.object({ state: z.string().max(32), verified: z.boolean() }).catchall(z.unknown()).nullable(),
    pause: z.object({ reason: z.enum(PAUSE_REASONS), at: Iso }).catchall(z.unknown()).nullable(),
    resumedAt: Iso.nullable(),
    ended: z.object({ status: z.enum(LOOP_STATUSES), reason: z.string().max(500), at: Iso }).catchall(z.unknown()).nullable(),
    operations: z.array(z.object({ handle: z.string().min(1).max(64), seq: z.number().int().min(1), epoch: z.number().int().min(1), wakesUsed: z.number().int().min(0), current: z.boolean() }).catchall(z.unknown())).max(256),
    wakeClaims: z.array(z.object({ claimId: z.string().min(1).max(64), state: z.string().max(32), epoch: z.number().int().min(1), operationHandle: z.string().min(1).max(64) }).catchall(z.unknown())).max(256),
  })
  .catchall(z.unknown());
export type CustodianLoop = z.infer<typeof CustodianLoopSchema>;

/** Where a session's binding lives: a lookup hint, always verified against the run's loop record. */
export const SessionIndexSchema = z
  .object({
    schema: z.literal(SESSION_INDEX_SCHEMA),
    session_id: z.string().min(1).max(256),
    run_id: z.string().min(1).max(64),
    repo_key: z.string().min(1).max(64),
    loop_id: z.string().min(1).max(64),
    updated_at: Iso,
  })
  .catchall(z.unknown());
export type SessionIndex = z.infer<typeof SessionIndexSchema>;
