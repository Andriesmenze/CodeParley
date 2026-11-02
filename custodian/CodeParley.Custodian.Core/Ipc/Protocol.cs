using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ipc;

/// <summary>The caller class the OS assigned a pipe connection (never request content). <see cref="Helper"/> (P3.4C-5,
/// §A.2) is the dedicated helper service, recognised on the helper pipe by its SID alone: it is served measurement
/// requests on that channel and nothing else, anywhere.</summary>
internal enum CallerClass { Unknown, Implementer, Operator, Helper }

/// <summary>The pipe a connection arrived on. Each surface admits one configured identity (its DACL and the classifier).</summary>
internal enum PipeSurface { Implementer, Operator, Helper }

internal static class ErrorCodes
{
    internal const string CallerNotAuthorized = "CALLER_NOT_AUTHORIZED";
    internal const string MalformedRequest = "MALFORMED_REQUEST";
    internal const string UnknownOperation = "UNKNOWN_OPERATION";
    internal const string OperatorProofRequired = "OPERATOR_PROOF_REQUIRED";
    internal const string AuthorizationExpired = "AUTHORIZATION_EXPIRED";
    internal const string AuthorizationInvalid = "AUTHORIZATION_INVALID";
    internal const string StaleState = "STALE_FINDING_STATE";
    internal const string RequestIdConflict = "REQUEST_ID_CONFLICT";
    internal const string InvalidArgument = "INVALID_ARGUMENT";
    internal const string LoopNotAuthorized = "LOOP_NOT_AUTHORIZED";
    // P3.4C-2 loop/continuation authority.
    internal const string RunAlreadyHasLoop = "RUN_ALREADY_HAS_LOOP";
    internal const string LoopTerminal = "LOOP_TERMINAL";
    internal const string StaleLoopEpoch = "STALE_LOOP_EPOCH";
    internal const string StaleLoopState = "STALE_LOOP_STATE";
    internal const string UnknownOperationHandle = "UNKNOWN_OPERATION_HANDLE";
    // P3.4C-2 loop_transition refusals (increment 6).
    internal const string UnknownLoop = "UNKNOWN_LOOP";
    internal const string InvalidLoopTransition = "INVALID_LOOP_TRANSITION";
    internal const string BindNonceInvalid = "BIND_NONCE_INVALID";
    internal const string ProcessIdentityUnverified = "PROCESS_IDENTITY_UNVERIFIED";
    internal const string LoopBudgetExhausted = "LOOP_BUDGET_EXHAUSTED";
    internal const string UnknownWakeClaim = "UNKNOWN_WAKE_CLAIM";
    internal const string WakeAlreadyConsumed = "WAKE_ALREADY_CONSUMED";
    // P3.4C-2 TD decision on the Inc 9 escalation: an automation request names a session other than the bound one.
    internal const string SessionNotBound = "SESSION_NOT_BOUND";
    // P3.4C-3 run_transition refusals (contract §3.2).
    internal const string RunTerminal = "RUN_TERMINAL";
    internal const string RunDeclarationConflict = "RUN_DECLARATION_CONFLICT";
    internal const string RunBusy = "RUN_BUSY";
    internal const string RunNotOpen = "RUN_NOT_OPEN";
    internal const string OperationNotRunning = "OPERATION_NOT_RUNNING";
    internal const string WriterMismatch = "WRITER_MISMATCH";
    internal const string OperationWriterAlive = "OPERATION_WRITER_ALIVE";
    internal const string EvidenceNotHeld = "EVIDENCE_NOT_HELD";
    internal const string BudgetExhausted = "BUDGET_EXHAUSTED";
    internal const string FindingNotFound = "FINDING_NOT_FOUND";
    internal const string FindingNotRespondable = "FINDING_NOT_RESPONDABLE";
    internal const string InvalidItemTransition = "INVALID_ITEM_TRANSITION";
    // P3.4C-4 trusted configuration (contract §3).
    internal const string ConfigNotHeld = "CONFIG_NOT_HELD";
    internal const string ConfigLapsed = "CONFIG_LAPSED";
    internal const string CheckNotApproved = "CHECK_NOT_APPROVED";
    internal const string IsolationNotAccepted = "ISOLATION_NOT_ACCEPTED";
    internal const string ConfigMismatch = "CONFIG_MISMATCH";
    internal const string StaleConfig = "STALE_CONFIG";
    internal const string CodexInstallationUnsupported = "CODEX_INSTALLATION_UNSUPPORTED";
    /// <summary>Phase 5 (§4.12): the host's Codex sandbox basis is not approvable (the bwrap image, the AppArmor profile or
    /// the user-namespace restriction), or it changed since the operator confirmed the self-test.</summary>
    internal const string CodexIsolationUnavailable = "CODEX_ISOLATION_UNAVAILABLE";
    // P3.4C-5 (Amendment A): the helper principal and its channel.
    internal const string HelperUnavailable = "HELPER_UNAVAILABLE";
    internal const string HelperChannelRefused = "HELPER_CHANNEL_REFUSED";
    internal const string MeasurementFailed = "MEASUREMENT_FAILED";
    internal const string MeasurementTimeout = "MEASUREMENT_TIMEOUT";
    internal const string MeasurementCancelled = "MEASUREMENT_CANCELLED";
    internal const string RuntimeNotApproved = "RUNTIME_NOT_APPROVED";
    // P3.4C-5 Increment 4 (§2.3, §6, N5-8): the helper's narrow read grant on the repository is missing.
    internal const string RepositoryNotReadable = "REPOSITORY_NOT_READABLE";
    // P3.4C-5 Increment 3 (§5.2): the custodian's enforcement of its own derivation.
    internal const string DerivationStale = "DERIVATION_STALE";
    internal const string RouteNotImplementerStep = "ROUTE_NOT_IMPLEMENTER_STEP";
    internal const string NoProgress = "NO_PROGRESS";
    internal const string RunJsonMismatch = "RUN_JSON_MISMATCH";
    // Phase 4 Increment 3 (contract §3.5, §3.6): the owner's confirmation and the application of a delegated fix.
    internal const string ConfirmationContentMismatch = "CONFIRMATION_CONTENT_MISMATCH";
    internal const string ProposalNotPending = "PROPOSAL_NOT_PENDING";
    internal const string FixNotConfirmed = "FIX_NOT_CONFIRMED";
    internal const string FixDeclined = "FIX_DECLINED";
    internal const string ConfirmationExpired = "CONFIRMATION_EXPIRED";
    internal const string ConfirmationConsumed = "CONFIRMATION_CONSUMED";
    internal const string ApplyInProgress = "APPLY_IN_PROGRESS";
    internal const string FixStale = "FIX_STALE";
    // Phase 5 F-i2-5: the custodian could not produce the reviewer-visible redaction of an amendment text.
    internal const string RedactionRefused = "REDACTION_REFUSED";
    internal const string Internal = "INTERNAL";
}

/// <summary>
/// A refusal the custodian decided, carrying its protocol code STRUCTURALLY. The dispatcher classifies it
/// by type before any message matching, so a client-supplied value quoted in the message (a run id may
/// spell <c>REQUEST_ID_CONFLICT</c>) can never select another code. The message ends with the code in
/// parentheses for readability only.
/// </summary>
internal sealed class CustodianRefusal(string code, string message) : InvalidOperationException($"{message} ({code})")
{
    internal string Code { get; } = code;
}

/// <summary>A parsed request: a protocol version, a caller-supplied request id (bounded), an operation
/// name and an opaque argument object. Unknown top-level fields are rejected by the parser.</summary>
internal sealed record Request(int V, string RequestId, string Op, JsonObject Args)
{
    internal static Request Parse(string line)
    {
        JsonNode? node = JsonNode.Parse(line) ?? throw new FormatException("empty request");
        if (node is not JsonObject o) throw new FormatException("request is not an object");
        foreach (string key in o.Select(kv => kv.Key))
            if (key is not ("v" or "requestId" or "op" or "args"))
                throw new FormatException($"unknown request field '{key}'");
        int v = (int?)o["v"] ?? throw new FormatException("missing v");
        // Phase 6 Increment 1: a mismatched engine is refused (INVALID_ARGUMENT, nothing done) with the remedy.
        if (v != CustodianConstants.ProtocolVersion)
            throw new FormatException($"unsupported protocol version {v}: this custodian speaks protocol {CustodianConstants.ProtocolVersion}; install the engine and the custodian from the same CodeParley release (code-parley doctor and the custodian's version verb report each one's version)");
        string op = (string?)o["op"] ?? throw new FormatException("missing op");
        string reqId = (string?)o["requestId"] ?? throw new FormatException("missing requestId");
        if (reqId.Length is < 1 or > 128) throw new FormatException("requestId must be 1..128 chars");
        var args = o["args"] as JsonObject ?? new JsonObject();
        return new Request(v, reqId, op, args);
    }
}

internal sealed record Response(bool Ok, JsonObject? Data, string? Code, string? Error)
{
    internal static Response Success(JsonObject data) => new(true, data, null, null);
    internal static Response Fail(string code, string error) => new(false, null, code, error);

    internal string ToJson()
    {
        var o = new JsonObject { ["ok"] = Ok };
        if (Data is not null) o["data"] = Data.DeepClone();
        if (Code is not null) o["code"] = Code;
        if (Error is not null) o["error"] = Error;
        return o.ToJsonString();
    }
}
