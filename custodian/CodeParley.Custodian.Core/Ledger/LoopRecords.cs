using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ledger;

// ---- P3.4C-2: the custodian-owned loop record (co-located in ledger.json; Option A) ----

/// <summary>A loop's budgets (custodian-assigned; mirrors src/schemas/continuation.ts LoopLimitsSchema).</summary>
internal sealed record LoopLimits(int Continuations, int WakesPerOperation, int WakesPerRun, int RunSeconds);

/// <summary>How much of a loop's budgets has been spent.</summary>
internal sealed record LoopUsed(int Continuations, int Wakes);

/// <summary>The custodian's record of the grant consumption this loop represents (source is always
/// <c>custodian</c>: a loop minted here is never from the former user-writable grants file).</summary>
internal sealed record LoopGrantUse(string Source, string LoopId, string RequestId, int LoopsUsed, int LoopsTotal);

/// <summary>The one-time binding nonce: only its SHA-256 is stored. The preimage is returned exactly once, in
/// the <c>consume_loop</c> result that mints the loop, and is the credential the host presents at bind
/// (first-bind-wins; marked used). The custodian never keeps the preimage.</summary>
internal sealed record BindNonce(string Sha256, string IssuedAt, string ExpiresAt, string? UsedAt);

/// <summary>The process the client named as the originating session's (CLAUDE_PID), as the CUSTODIAN
/// checked it (D7): its OS start time, the process connected to the pipe, and whether the check passed. A
/// client's own "verified" is never accepted. Operator projection only.</summary>
internal sealed record LoopProcessFacts(int? Pid, long? StartedAtMs, int? ClientPid, bool Verified, string Detail, string CheckedAt);

/// <summary>The loop's binding to the originating Claude Code session. <see cref="SessionId"/> is the host's
/// correlation identifier, never a credential. The binding's generation is the loop's custodian-owned
/// epoch (<see cref="LoopRecord.Epoch"/>), not a field here.</summary>
internal sealed record LoopBinding(string SessionId, string State, string BoundAt, string? ReboundAt, LoopProcessFacts Process);

/// <summary>Why and when the loop paused, and which caller class paused it.</summary>
internal sealed record LoopPause(string Reason, string Detail, string At, string By);

/// <summary>How the loop ended (terminal, irreversible). <see cref="By"/> is <c>custodian</c> for a
/// custodian-derived end (deadline or continuation budget).</summary>
internal sealed record LoopEnded(string Status, string Reason, string At, string By);

/// <summary>A custodian-issued operation allocation — the trusted operation identity wake budgets are
/// counted against (TD correction 3). Issued at <c>bind</c> (operation 1) and at each
/// <c>spend_continuation</c>; only the latest is current. <see cref="WakesUsed"/> is its own persisted
/// per-operation wake counter, which nothing can reset.</summary>
/// <summary>P3.4C-5 (§5.2–§5.3): the progress fingerprint of the derivation the loop's latest continuation or wake was
/// spent on; the next one needs a different fingerprint (NO_PROGRESS otherwise).</summary>
internal sealed record LoopProgress(string Fingerprint, string DerivationId, string At, string Kind);

internal sealed record LoopOperation(string Handle, int Seq, int Epoch, string IssuedAt, string IssuedBy, int WakesUsed);

/// <summary>A one-shot, epoch-bound wake claim (D6; TD correction B). Reserved by <c>wake_arm</c> against
/// the current operation (both wake budgets are spent then); consumed at most once by
/// <c>wake_consume</c>, persisted before the consuming call returns.</summary>
internal sealed record WakeClaim(
    string ClaimId, string OperationHandle, int Epoch, string State, string ArmedAt, string ArmRequestId,
    string? ConsumedAt = null, string? ConsumeRequestId = null);

/// <summary>Append-only evidence of one applied transition (or a custodian-derived end). A client
/// transition records its request id and request digest (idempotency: a replay returns
/// <see cref="Result"/>; a different request under the same id is a conflict) and the caller class the OS
/// assigned. <see cref="Caller"/> is <c>custodian</c> for a derived transition, which has no request.</summary>
internal sealed record LoopEvent(
    int Seq, string Kind, string RequestId, string Caller, string? ProofDigest, string At,
    string RequestDigest, string FromStatus, string ToStatus, int Epoch, JsonObject? Result);

/// <summary>
/// The custodian-owned, per-(repository identity, run) loop record (P3.4C-2, Option A: co-located in
/// ledger.json). It carries the authority fields of src/schemas/continuation.ts <c>LoopRecordSchema</c>, and
/// the custodian ASSIGNS every one of them — a client never supplies <see cref="LoopId"/>,
/// <see cref="Status"/>, <see cref="Epoch"/>, <see cref="Limits"/>, <see cref="Used"/>, the binding, the
/// nonce, the operation handles or the wake claims. Minted UNBOUND by <see cref="GrantLedger.ConsumeLoop"/>
/// in the same atomic ledger write that consumes the grant; changed afterwards ONLY by
/// <c>loop_transition</c>, which computes the new state itself. <see cref="Epoch"/> is the custodian-owned
/// monotonic int (1 at mint; +1 only on an eligible rebind) and <see cref="LoopRevision"/> is this record's
/// own optimistic-concurrency revision (1 at mint; +1 on each applied or derived transition) — distinct from
/// the P3.4C-1 user-record log revision. <see cref="RequestId"/> is the minting request, for idempotency.
/// The lifecycle fields default to absent so a ledger written by increment 5 still reads.
/// </summary>
internal sealed record LoopRecord(
    string LoopId, string RepoKey, string RunId, string Status, int Epoch, int LoopRevision,
    string StartedAt, string DeadlineAt, string GrantId, LoopGrantUse GrantUse, LoopLimits Limits,
    LoopUsed Used, BindNonce BindNonce, string RequestId,
    LoopBinding? Binding = null, LoopPause? Pause = null, string? ResumedAt = null, LoopEnded? Ended = null,
    List<LoopOperation>? Operations = null, List<WakeClaim>? WakeClaims = null, List<LoopEvent>? Events = null,
    string? LastRecoveryId = null, LoopProgress? Progress = null)
{
    /// <summary>The current operation (the latest issued), or null before bind.</summary>
    internal LoopOperation? CurrentOperation => Operations is { Count: > 0 } ops ? ops[^1] : null;
}

/// <summary>Loop statuses (contract §4; mirrors LOOP_STATUSES). Transitions start only from a LIVE status;
/// every other status — the contract's terminal set, or anything unrecognized — is terminal (fail-closed):
/// no transition leaves it, and a run whose loop is terminal is never given a second loop (LOOP_TERMINAL).</summary>
internal static class LoopStatuses
{
    internal const string Unbound = "unbound", Active = "active", Paused = "paused";
    internal const string BudgetExhausted = "budget_exhausted", Expired = "expired", Cancelled = "cancelled", RunEnded = "run_ended";

    internal static readonly IReadOnlySet<string> Live = new HashSet<string>(StringComparer.Ordinal) { Unbound, Active, Paused };
    internal static readonly IReadOnlySet<string> Terminal =
        new HashSet<string>(StringComparer.Ordinal) { BudgetExhausted, Expired, Cancelled, RunEnded };

    /// <summary>The statuses a client may END a loop with (contract §4). <c>expired</c> and
    /// <c>budget_exhausted</c> are custodian-derived only, and the custodian never records an engine-claimed
    /// completion (<c>ready</c>): it attests no completion.</summary>
    internal static readonly IReadOnlySet<string> ClientEnd = new HashSet<string>(StringComparer.Ordinal) { Cancelled, RunEnded };

    internal static bool IsTerminal(string status) => !Live.Contains(status);
}

/// <summary>Why a loop pauses (mirrors PAUSE_REASONS).</summary>
internal static class PauseReasons
{
    internal const string UserInterrupt = "user_interrupt", UserDecisionRequired = "user_decision_required",
        OperatorActionRequired = "operator_action_required", OperationUnsuccessful = "operation_unsuccessful",
        ConfigChange = "config_change", ProcessIdentity = "process_identity",
        // P3.4C-5 Increment 3 (§5.2): the custodian refused a continuation or wake because no work fact changed.
        NoProgress = "no_progress";

    internal static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        UserInterrupt, UserDecisionRequired, OperatorActionRequired, OperationUnsuccessful, ConfigChange, ProcessIdentity, NoProgress,
    };

    /// <summary>Pauses only independently verified operator authority clears (contract §3/§4): a
    /// <c>resume</c> from these on the implementer surface is CALLER_NOT_AUTHORIZED, and no implementer
    /// sequence (rebind, another pause, bind) changes or clears them.</summary>
    internal static readonly IReadOnlySet<string> OperatorOnly = new HashSet<string>(StringComparer.Ordinal) { OperatorActionRequired, UserDecisionRequired };
}

/// <summary>The closed set of <c>loop_transition</c> kinds (contract §2).</summary>
internal static class LoopKinds
{
    internal const string Bind = "bind", Rebind = "rebind", SpendContinuation = "spend_continuation", WakeArm = "wake_arm",
        WakeConsume = "wake_consume", Pause = "pause", Resume = "resume", End = "end";

    internal static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Bind, Rebind, SpendContinuation, WakeArm, WakeConsume, Pause, Resume, End,
    };
}
