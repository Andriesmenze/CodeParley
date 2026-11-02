using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ledger;

// ---- P3.4C-3: the custodian-owned run record (one protected file per run; contract §2) ----
//
// A field the engine supplies is a CLAIM the custodian validated (allowlisted keys, closed enums, bounded strings,
// safe ids, digest syntax — Ledger/RunRequest.cs); every other field is the custodian's own. The bulky client claims
// (an operation's begin fields and outcome, check executions, replies, responses) are kept as validated JSON objects
// holding only allowlisted keys; the fields the custodian decides on (statuses, the item lifecycle, revisions, the
// writer, acceptance, the evidence epoch) are typed.

/// <summary>The budget overrides the run declared at <c>open</c> (frozen; the custodian applies them under its own
/// hard caps, §2.3).</summary>
internal sealed record RunBudgets(
    int MaxReviews, int MaxCheckExecutions,
    // Phase 4 Increment 2: the delegated fixes the run declared (absent: none).
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] int? MaxFixes = null);

/// <summary>The run's baseline capture, digest-bound at <c>open</c> (null: the run has no baseline).</summary>
internal sealed record RunBaseline(string SourceId, string Digest);

/// <summary>What the run was opened with: the digest of its <c>run.json</c>, its budgets and its baseline. Frozen: a
/// replayed <c>open</c> must declare the same (else RUN_DECLARATION_CONFLICT).</summary>
internal sealed record RunDeclaration(string RunJsonDigest, RunBudgets Budgets, RunBaseline? Baseline);

/// <summary>How the run ended (terminal, irreversible): <c>stopped</c> or <c>closed</c>.</summary>
internal sealed record RunEnded(string Status, string Reason, string At, string By);

/// <summary>The process that began an operation — the parent of the pipe client that sent <c>op_begin</c>, from the
/// custodian's own process-table snapshot (§4.3). Only that instance (same pid, same creation time) extends or
/// finishes the operation. OS facts: operator projection only.</summary>
internal sealed record OperationWriter(int Pid, long StartedAtMs, string ImageName);

/// <summary>P3.4C-4 (§4.3): the configuration an operation was begun under, assigned by the custodian at <c>op_begin</c>
/// (never a client field): the repository record's revision and digest; for a review also the isolation record it rests
/// on (its kind, id and global revision), the capture-rules digest and the Codex installation's SHA-256. Executions
/// inherit their operation's pin; acceptance and currency are judged against it.</summary>
internal sealed record OperationPin(
    int ConfigRevision, string ConfigDigest, string? IsolationKind = null, string? IsolationRecordId = null, int? IsolationGlobalRevision = null,
    string? CaptureRulesDigest = null, string? CodexSha256 = null);

/// <summary>P3.4C-4 (§3.3 <c>open</c>): the repository configuration record the run was opened under.</summary>
internal sealed record ConfigPin(int ConfigRevision, string ConfigDigest);

/// <summary>One operation of the run (checks or a review), with a custodian-issued id. <see cref="Begin"/> and
/// <see cref="Outcome"/> hold the validated begin fields and outcome; <see cref="Pin"/> (P3.4C-4) the configuration it was
/// begun under. <see cref="Ticket"/> (P3.4C-5, §2.4) is the measurement ticket of a review the custodian captures: the
/// operation is <c>measuring</c> while the custodian's helper captures, then <c>captured</c>; the ticket correlates the
/// measurement with the operation and lives in memory only (a restart interrupts the operation, N5-18). For a checks
/// operation (P3.4C-5 Increment 3, §4) the same ticket names the measurement of its start; <see cref="Measured"/> is the
/// custodian's latest measurement of the run's source and the planned checks' inputs (the next execution's start), and
/// <see cref="Pending"/> the one execution whose end the custodian is measuring (its ticket and the engine's claim).</summary>
internal sealed record RunOperation(
    string OperationId, int Seq, string Kind, string Status, string BeganAt, string? EndedAt,
    OperationWriter Writer, JsonObject Begin, JsonObject? Outcome, OperationPin? Pin = null, string? Ticket = null,
    JsonObject? Measured = null, JsonObject? Pending = null);

/// <summary>One review of the run: its begin bindings, its outcome, and the custodian-derived acceptance (§4.4).
/// <see cref="Accepted"/> is null while the review runs. <see cref="EvidenceEpoch"/> is the epoch it was begun in:
/// completion relies only on evidence of the current epoch (§2.4 U3).</summary>
internal sealed record RunReview(
    string ReviewId, string OperationId, int Round, JsonObject Begin, JsonObject? Outcome,
    bool? Accepted, List<string> NotAcceptedReasons, List<string> ItemIds, List<string> IncidentIds, int EvidenceEpoch);

/// <summary>One assessment of an item by a later accepted review, with the effect the custodian computed (§4.5).</summary>
internal sealed record RunItemAssessment(string ReviewId, int Round, string SourceId, string Assessment, string Effect);

/// <summary>A reviewer item (finding or question) — the structured fields the derivation reads; its text stays in
/// the review's digest-bound artifacts. <see cref="Status"/> and <see cref="Assessments"/> are the custodian's
/// (the §4.5 table); <see cref="ItemRevision"/> is the freshness token for responses and protected decisions
/// (1 at creation, +1 on each assessment, response or reply touching the item).</summary>
internal sealed record RunItem(
    string ItemId, string ItemKind, string ReviewId, int Round, string SourceId, string Triage,
    string? Severity, string? ClaimType, string? Category, List<string> Impacts, string? Confidence,
    string Status, string? SupersededBy, List<string> Supersedes, List<string> Restates, string? RelatedPriorId, string? RelatedFindingId,
    List<RunItemAssessment> Assessments, int ItemRevision, string CreatedAt);

/// <summary>An isolation incident (closed kinds, append-only). <see cref="Source"/> is <c>engine</c> for one the
/// engine reported, <c>custodian</c> for one the custodian recorded itself (S2's isolation_reduced).</summary>
internal sealed record RunIncident(string IncidentId, string Kind, string OperationId, string? ReviewId, string Detail, string At, string Source);

/// <summary>Append-only evidence of one applied transition. A replay of the same request returns
/// <see cref="Result"/>; a different request under the same id is a conflict. OS facts and the log are operator-only.</summary>
internal sealed record RunEvent(
    int Seq, string Kind, string RequestId, string Caller, int? ClientPid, string RequestDigest,
    string FromStatus, string ToStatus, string At, JsonObject? Result);

/// <summary>
/// The custodian-owned record of one protected run (P3.4C-3, contract §2.2), keyed by the custodian's own repository
/// identity and the run id, created by <c>run_transition open</c> and changed only by <c>run_transition</c>, which
/// computes every transition itself. <see cref="RunRevision"/> orders every applied transition (1 at open).
/// <see cref="EvidenceEpoch"/> is 1 at open and rises once per recovery (§2.4 U3). <see cref="LastRecoveryId"/>
/// stamps the recovery that last changed the record, so a resumed recovery changes nothing twice.
/// </summary>
internal sealed record RunRecord(
    string RepoKey, string RunId, int RunRevision, string OpenedAt, string RequestId, int EvidenceEpoch,
    RunDeclaration Declaration, string Status, RunEnded? Ended,
    List<RunOperation> Operations, List<JsonObject> CheckExecutions, List<RunReview> Reviews, List<RunItem> Items,
    List<JsonObject> Replies, List<JsonObject> Responses, List<RunIncident> Incidents, List<RunEvent> Events,
    string? LastRecoveryId = null, ConfigPin? OpenedConfig = null)
{
    /// <summary>The run's active operation: running, or (P3.4C-5) a review the custodian is capturing or has captured.</summary>
    internal RunOperation? RunningOperation => Operations.LastOrDefault(o => RunOperationStatuses.IsActive(o.Status));
    internal bool IsTerminal => RunStatuses.IsTerminal(Status);
}

/// <summary>Run statuses (contract §1.1). <c>checking</c>/<c>reviewing</c> follow the running operation;
/// <c>stopped</c> and <c>closed</c> are terminal and irreversible.</summary>
internal static class RunStatuses
{
    internal const string Idle = "idle", Checking = "checking", Reviewing = "reviewing", Fixing = "fixing", Applying = "applying", Stopped = "stopped", Closed = "closed";
    internal static readonly IReadOnlySet<string> Terminal = new HashSet<string>(StringComparer.Ordinal) { Stopped, Closed };
    internal static bool IsTerminal(string status) => Terminal.Contains(status) || status is not (Idle or Checking or Reviewing or Fixing or Applying);
}

/// <summary>An operation's status: <c>running</c>, then its outcome's status, or <c>interrupted</c> (recovered once
/// its writer was gone, §5.2). P3.4C-5 (§2.4, §3.1): a review the custodian captures is <c>measuring</c> (reserved; the
/// helper captures), then <c>captured</c> (the export is published; Codex may run), then its outcome's status; a
/// measurement that does not end in a capture ends the operation <c>error</c>, <c>cancelled</c>, <c>deduplicated</c> or
/// <c>interrupted</c>, with the reason in its outcome.</summary>
internal static class RunOperationStatuses
{
    internal const string Running = "running", Interrupted = "interrupted", Measuring = "measuring", Captured = "captured",
        Error = "error", Cancelled = "cancelled", Deduplicated = "deduplicated",
        // Phase 4 Increment 2: a fix whose content the custodian holds awaiting the owner, or whose content it rejected.
        Proposed = "proposed", Rejected = "rejected";

    internal static bool IsActive(string status) => status is Running or Measuring or Captured;
}

/// <summary>The closed set of <c>run_transition</c> kinds (contract §3.2).</summary>
internal static class RunKinds
{
    internal const string Open = "open", OpBegin = "op_begin", RecordExecution = "record_execution", OpFinish = "op_finish",
        Recover = "recover", Respond = "respond", End = "end",
        // Phase 4 Increment 3: the record of an interrupted application's reconciliation (restore or leave).
        ApplyReconcile = "apply_reconcile";

    internal static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Open, OpBegin, RecordExecution, OpFinish, Recover, Respond, End, ApplyReconcile,
    };
}

/// <summary>The engine's closed enums the custodian validates against (mirrored from src/schemas; the shared corpus
/// holds the two sides together).</summary>
internal static class RunEnums
{
    private static IReadOnlySet<string> Set(params string[] values) => new HashSet<string>(values, StringComparer.Ordinal);

    internal static readonly IReadOnlySet<string> OperationKinds = Set("checks", "review", "fix", "apply");
    /// <summary>Phase 4 Increment 3: an application's finish as the engine reports it, the state it reports per file, and a
    /// reconciliation's choice and observation.</summary>
    internal static readonly IReadOnlySet<string> ApplyOutcomeStatuses = Set("applied", "apply_failed");
    internal static readonly IReadOnlySet<string> ApplyFileStates = Set("postimage", "preimage", "absent", "other", "unknown");
    internal static readonly IReadOnlySet<string> ReconcileChoices = Set("restore", "leave");
    internal static readonly IReadOnlySet<string> ReconcileObserved = Set("none", "partial", "all_at_postimage");
    /// <summary>Phase 4 Increment 2: a fix's finish as the engine reports it (the custodian decides proposed/rejected).</summary>
    internal static readonly IReadOnlySet<string> FixOutcomeStatuses = Set("completed", "empty", "rejected", "failed", "timed_out", "cancelled");
    internal static readonly IReadOnlySet<string> FixChangeKinds = Set("add", "modify", "delete");
    internal static readonly IReadOnlySet<string> EndStatuses = Set(RunStatuses.Stopped, RunStatuses.Closed);
    internal static readonly IReadOnlySet<string> CheckOutcomeStatuses = Set("completed", "cancelled", "error");
    internal static readonly IReadOnlySet<string> ReviewOutcomeStatuses = Set("completed", "failed", "timed_out", "cancelled", "invalid_output");
    internal static readonly IReadOnlySet<string> CheckExecutionStatuses = Set("passed", "failed", "error", "timed_out", "cancelled", "skipped");
    internal static readonly IReadOnlySet<string> SkipReasons = Set("operation_cancelled", "definition_removed", "definition_changed", "approval_invalid");
    /// <summary>The status a new item is created with (§4.5): open for an open-class triage, else informational.</summary>
    internal static readonly IReadOnlySet<string> NewItemStatuses = Set("open", "informational");
    internal static readonly IReadOnlySet<string> IsolationModes = Set("S1", "S2");
    internal static readonly IReadOnlySet<string> Depths = Set("focused", "standard", "deep");
    internal static readonly IReadOnlySet<string> Verdicts = Set("APPROVE", "CHANGES_REQUIRED", "INCONCLUSIVE");
    internal static readonly IReadOnlySet<string> ItemKinds = Set("finding", "question");
    internal static readonly IReadOnlySet<string> Triages = Set("established_defect", "serious_concern", "minor_concern", "note", "blocking_question", "question");
    internal static readonly IReadOnlySet<string> OpenTriages = Set("established_defect", "serious_concern", "blocking_question");
    internal static readonly IReadOnlySet<string> Severities = Set("critical", "high", "medium", "low");
    internal static readonly IReadOnlySet<string> ClaimTypes = Set("defect", "risk", "suggestion");
    internal static readonly IReadOnlySet<string> Categories = Set(
        "correctness", "security", "reliability", "performance", "compatibility", "maintainability", "testing",
        "documentation", "style", "architecture");
    internal static readonly IReadOnlySet<string> Impacts = Set("correctness", "security", "reliability", "performance", "compatibility", "maintainability", "acceptance_criteria");
    internal static readonly IReadOnlySet<string> Confidences = Set("high", "medium", "low");
    internal static readonly IReadOnlySet<string> PriorAssessments = Set("still_present", "apparently_resolved", "no_longer_assessable", "superseded");
    /// <summary>What an <c>op_finish</c> assessment entry may say about an item open before the review: the four
    /// prior assessments, or that the reviewer was shown it and did not assess it, or that the bundle did not show it.</summary>
    internal static readonly IReadOnlySet<string> AssessmentEntries = Set("still_present", "apparently_resolved", "no_longer_assessable", "superseded", "not_assessed", "not_presented");
    /// <summary>The assessment a reviewer reply may carry (the item's assessment in the same review).</summary>
    internal static readonly IReadOnlySet<string> ReplyAssessments = Set("still_present", "apparently_resolved", "no_longer_assessable", "superseded", "not_assessed");
    internal static readonly IReadOnlySet<string> Stances = Set("maintain", "withdraw", "revise", "need_information");
    internal static readonly IReadOnlySet<string> NewInformation = Set("yes", "no", "not_applicable");
    internal static readonly IReadOnlySet<string> Dispositions = Set("accepted", "disputed", "deferred", "fix_claimed");
    internal static readonly IReadOnlySet<string> IncidentKinds = Set(
        "isolation_violation_file_change", "isolation_violation_mcp_tool_call", "isolation_violation_web_search",
        "export_modified_during_review", "possible_surviving_sandboxed_commands", "cancellation_unconfirmed",
        "termination_unconfirmed", "isolation_reduced", "measurement_interrupted", "apply_interrupted");
    /// <summary>The incidents the engine reports at a review's finish: every kind except <c>isolation_reduced</c>,
    /// which the custodian records itself when an S2 review begins.</summary>
    internal static readonly IReadOnlySet<string> EngineIncidentKinds = Set(
        "isolation_violation_file_change", "isolation_violation_mcp_tool_call", "isolation_violation_web_search",
        "export_modified_during_review", "possible_surviving_sandboxed_commands", "cancellation_unconfirmed",
        "termination_unconfirmed");
    /// <summary>The incidents that invalidate a review (the engine's rule, review-operation.ts): a review with one of
    /// these recorded for its operation is never accepted.</summary>
    internal static readonly IReadOnlySet<string> InvalidatingIncidents = Set(
        "termination_unconfirmed", "isolation_violation_file_change", "isolation_violation_mcp_tool_call",
        "isolation_violation_web_search", "export_modified_during_review", "cancellation_unconfirmed");
    /// <summary>The incidents the engine may report on <c>recover</c> (§3.2).</summary>
    internal static readonly IReadOnlySet<string> RecoverIncidents = Set("possible_surviving_sandboxed_commands", "termination_unconfirmed");
}
