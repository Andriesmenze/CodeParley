// Domain errors with stable codes. The MCP layer (M1.5) maps these to isError results
// with a stable `error.code` (plan §11.9); M1.1 foundations throw them internally.

/** Stable error codes used by the foundations and capture (subset of plan §11.9). */
export type ErrorCode =
  // arguments and scope
  | "INVALID_ARGUMENT"
  | "SCOPE_NOT_CONFIGURED"
  | "REPOSITORY_NOT_SPECIFIED"
  | "SCOPE_REPO_ROOT_OUTSIDE_ALLOWED"
  | "REPO_OUTSIDE_SESSION_ROOTS"
  | "SCOPE_REVOKED"
  // paths
  | "INVALID_PATH"
  | "PATH_NOT_ALLOWED"
  | "LINK_NOT_ALLOWED"
  // repository
  | "NOT_A_GIT_WORKTREE"
  | "GIT_NOT_FOUND"
  | "GIT_UNSAFE_DIRECTORY"
  | "GIT_TOO_OLD"
  | "UNSUPPORTED_REPO_STATE"
  | "BASE_UNAVAILABLE"
  // runs / store / locks
  | "RUN_NOT_FOUND"
  | "RUN_TERMINAL"
  | "RUN_BUSY"
  | "REQUEST_ID_CONFLICT"
  | "BUDGET_EXHAUSTED"
  | "OPERATION_MISMATCH"
  | "WORKTREE_BUSY"
  | "WORKTREE_OWNERSHIP_UNRESOLVED"
  | "STORE_LOCKED"
  | "STORE_VERSION_UNSUPPORTED"
  | "STORE_REVISION_CONFLICT"
  // checks
  | "UNKNOWN_PROFILE"
  | "CHECK_NOT_APPROVED"
  | "NO_CHECKS_CONFIGURED"
  // implementer responses (Phase 2.1)
  | "FINDING_NOT_FOUND"
  | "FINDING_NOT_RESPONDABLE"
  | "STALE_FINDING_STATE"
  | "SOURCE_UNAVAILABLE"
  // the local operator interface (Phase 2.3; CLI only, never an MCP result)
  | "INTERACTIVE_TERMINAL_REQUIRED"
  // Phase 5 G-OP: an operator command not run from the approved runtime through the operator wrapper (Linux; CLI only)
  | "OPERATOR_CODE_UNTRUSTED"
  // same-session continuation (Phase 3.3a)
  | "LOOP_NOT_AUTHORIZED"
  // P3.4C-0: an earlier loop start may have consumed a granted loop; it is never retried automatically
  | "LOOP_START_UNRECONCILED"
  // P3.4C-2: the custodian mints one loop per run and never resurrects an ended one
  | "RUN_ALREADY_HAS_LOOP"
  | "LOOP_TERMINAL"
  // P3.4C-3: the custodian's run records (run_transition refusals; contract §3.2) and the engine's fail-closed
  // selection (a run the local copy marks protected without any custodian record, §5.4)
  | "RUN_NOT_OPEN"
  | "RUN_DECLARATION_CONFLICT"
  | "RUN_RECORD_MISSING"
  | "OPERATION_NOT_RUNNING"
  | "WRITER_MISMATCH"
  | "OPERATION_WRITER_ALIVE"
  | "EVIDENCE_NOT_HELD"
  | "INVALID_ITEM_TRANSITION"
  | "PROCESS_IDENTITY_UNVERIFIED"
  // P3.4C-4: the custodian-held trusted configuration (contract §3) and the engine's run.json re-verification (§1.1)
  | "CONFIG_NOT_HELD"
  | "CONFIG_LAPSED"
  | "ISOLATION_NOT_ACCEPTED"
  | "CONFIG_MISMATCH"
  | "STALE_CONFIG"
  | "CODEX_INSTALLATION_UNSUPPORTED"
  | "RUN_JSON_MISMATCH"
  // P3.4C-5: the custodian's review capture (contract §3.1, §6): its helper is not installed, no usable engine runtime is
  // approved, or the custodian's measurement of a reserved review ended without a capture
  | "HELPER_UNAVAILABLE"
  | "RUNTIME_NOT_APPROVED"
  | "REPOSITORY_NOT_READABLE"
  | "REVIEW_CAPTURE_FAILED"
  // P3.4C-5 Increment 3: the custodian's measurement of a protected checks operation did not complete in time; and its
  // enforcement of its own derivation (contract §5.2)
  | "CHECKS_MEASUREMENT_FAILED"
  | "DERIVATION_STALE"
  | "ROUTE_NOT_IMPLEMENTER_STEP"
  | "NO_PROGRESS"
  // custodian grant integration (P3.4C-0): the TS client of the Windows grant custodian. Reaching a
  // trusted custodian is required for a protected run; there is no grants.json fallback (fail-closed).
  | "CUSTODIAN_UNAVAILABLE"
  // Phase 6 (contract §7 a): the custodian is present but stayed busy serving another request for longer than the call
  // (a hook, within its deadline) could wait. Fail closed, never a fallback.
  | "CUSTODIAN_BUSY"
  | "SERVER_NOT_TRUSTED"
  | "CALLER_NOT_AUTHORIZED"
  | "AUTHORIZATION_INVALID"
  | "AUTHORIZATION_EXPIRED"
  | "OPERATOR_PROOF_REQUIRED"
  | "MALFORMED_REQUEST"
  // codex (M1.4)
  | "CODEX_NOT_FOUND"
  | "CODEX_UNSUPPORTED_VERSION"
  | "CODEX_ISOLATION_UNAVAILABLE"
  | "CODEX_AUTH_MISSING"
  | "CODEX_BUSY"
  | "REVIEW_BUNDLE_TOO_LARGE"
  // config
  | "CONFIG_INVALID"
  | "CONFIGURATION_ERROR"
  // Phase 4 foundation: disposable writable workspaces for a delegated fix (workspace/disposable-workspace.ts).
  // Reachable only through the Phase 4 engine/CLI path, never the MCP tool surface.
  | "WORKSPACE_OVERLAPS_PRIMARY"
  | "WORKSPACE_LINK_PRESENT"
  // Phase 4 Increment 2 (P4-A): a delegated fix needs Windows, the validated custodian and a protected configuration.
  | "FIX_DELEGATION_UNAVAILABLE"
  // Phase 4 Increment 3 (contract §3.5, §3.6): the owner's confirmation and the application of a delegated fix.
  | "CONFIRMATION_CONTENT_MISMATCH"
  | "PROPOSAL_NOT_PENDING"
  // Step 7.1: a guided selection (complete, well-formed) that no longer matches the custodian's evidence.
  | "SELECTION_STALE"
  | "FIX_NOT_CONFIRMED"
  | "FIX_DECLINED"
  | "CONFIRMATION_EXPIRED"
  | "CONFIRMATION_CONSUMED"
  | "APPLY_IN_PROGRESS"
  | "FIX_STALE"
  /** A confirmed proposal that cannot be applied faithfully on this platform (nothing was begun). */
  | "FIX_NOT_APPLICABLE"
  /** The application was refused at use: a target or its parent is not what was confirmed (nothing more is written). */
  | "APPLY_TARGET_REFUSED"
  | "MEASUREMENT_FAILED"
  | "MEASUREMENT_TIMEOUT"
  | "MEASUREMENT_CANCELLED"
  /** Phase 5 F-i2-5: the custodian could not establish an amendment's reviewer-visible redaction (its evidence history is
   * not complete or intact, or the text cannot be made reviewer-visible); nothing was prepared. */
  | "REDACTION_REFUSED"
  | "INTERNAL";

export interface DomainErrorDetails {
  readonly [k: string]: unknown;
}

/** An error carrying a stable, machine-readable code and optional structured details. */
export class DomainError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly details: DomainErrorDetails | undefined;

  constructor(code: ErrorCode, message: string, opts?: { retryable?: boolean; details?: DomainErrorDetails; cause?: unknown }) {
    super(message, opts?.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = "DomainError";
    this.code = code;
    this.retryable = opts?.retryable ?? false;
    this.details = opts?.details;
  }

  toJSON(): { code: ErrorCode; message: string; retryable: boolean; details?: DomainErrorDetails } {
    return {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      ...(this.details !== undefined ? { details: this.details } : {}),
    };
  }
}

export function isDomainError(e: unknown): e is DomainError {
  return e instanceof DomainError;
}
