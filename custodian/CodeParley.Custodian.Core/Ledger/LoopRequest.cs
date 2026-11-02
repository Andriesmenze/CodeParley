using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// A validated <c>loop_transition</c> request (P3.4C-2, contract §2). The client supplies only the loop it
/// addresses, the epoch and loop revision it acted on, the transition <c>kind</c> (a closed enum) and that
/// kind's minimal typed <c>fields</c>; the custodian computes the new state itself. Every <c>fields</c> key is
/// allowlisted per kind — any other key, including an authority-shaped one such as a client "verified", is
/// REFUSED (MALFORMED_REQUEST), never ignored (TD amendment 2a). <see cref="Digest"/> binds the whole request,
/// so a replay under the same request id must be the same request.
/// </summary>
internal sealed record LoopRequest
{
    internal required string RunId { get; init; }
    internal required string LoopId { get; init; }
    internal required int Epoch { get; init; }
    internal required int BaseLoopRevision { get; init; }
    internal required string Kind { get; init; }
    internal required string RequestId { get; init; }
    internal required string Digest { get; init; }

    internal string? BindNonce { get; init; }
    internal string? SessionId { get; init; }
    internal int? ClaimedPid { get; init; }
    internal string? OperationHandle { get; init; }
    internal string? ClaimId { get; init; }
    internal string? Reason { get; init; }
    internal string? Detail { get; init; }
    internal string? EndStatus { get; init; }
    /// <summary>P3.4C-5 Increment 3 (§5.2): the custodian derivation a continuation or wake is asked on.</summary>
    internal string? DerivationId { get; init; }

    private const int MaxTextChars = 500;

    /// <summary>The <c>fields</c> keys each kind accepts (contract §2/§5). An automation request
    /// (<c>spend_continuation</c>, <c>wake_arm</c>, <c>wake_consume</c>) REQUIRES the <c>session_id</c> of the hook
    /// invocation that asks; the custodian compares it with its binding (a correlation fact, never a credential).</summary>
    private static readonly IReadOnlyDictionary<string, string[]> KindFields = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        [LoopKinds.Bind] = ["bindNonce", "session_id", "process"],
        [LoopKinds.Rebind] = ["session_id", "process"],
        [LoopKinds.SpendContinuation] = ["session_id", "derivation_id"],
        [LoopKinds.WakeArm] = ["operationHandle", "session_id"],
        [LoopKinds.WakeConsume] = ["claimId", "session_id", "derivation_id"],
        [LoopKinds.Pause] = ["reason", "detail"],
        [LoopKinds.Resume] = [],
        [LoopKinds.End] = ["status", "reason"],
    };

    /// <summary>The process facts a client may state: only the pid the host gave the hook (CLAUDE_PID). The
    /// start time and the verdict are the custodian's own (D7).</summary>
    private static readonly string[] ProcessFields = ["pid"];

    internal static LoopRequest Parse(string runId, string loopId, int epoch, int baseLoopRevision, string kind, JsonObject fields, string requestId)
    {
        RequireToken("runId", runId, 128, allowUnderscore: true);
        RequireToken("request id", requestId, 128, allowUnderscore: true);
        if (!Guid.TryParseExact(loopId, "D", out _)) throw new ArgumentException("loopId must be a custodian-assigned loop id");
        if (!LoopKinds.All.Contains(kind)) throw new ArgumentException($"kind must be one of: {string.Join(", ", LoopKinds.All.Order(StringComparer.Ordinal))}");
        if (epoch < 1 || baseLoopRevision < 1) throw new ArgumentException("epoch and baseLoopRevision must be positive integers");
        RejectUnknown(fields, KindFields[kind], "fields");
        string digest = Ledger.Digest.Sha256Hex(Ledger.Digest.Canonical(new JsonObject
        {
            ["kind"] = kind, ["fields"] = fields.DeepClone(), ["epoch"] = epoch, ["baseLoopRevision"] = baseLoopRevision,
        }));
        var request = new LoopRequest
        {
            RunId = runId, LoopId = loopId, Epoch = epoch, BaseLoopRevision = baseLoopRevision, Kind = kind, RequestId = requestId, Digest = digest,
        };
        return kind switch
        {
            LoopKinds.Bind => request with { BindNonce = Hex64(fields, "bindNonce"), SessionId = Session(fields), ClaimedPid = Pid(fields) },
            LoopKinds.Rebind => request with { SessionId = Session(fields), ClaimedPid = Pid(fields) },
            LoopKinds.SpendContinuation => request with { SessionId = Session(fields), DerivationId = OptionalDerivationId(fields) },
            LoopKinds.WakeArm => request with { OperationHandle = Id(fields, "operationHandle"), SessionId = Session(fields) },
            LoopKinds.WakeConsume => request with { ClaimId = Id(fields, "claimId"), SessionId = Session(fields), DerivationId = OptionalDerivationId(fields) },
            LoopKinds.Pause => request with { Reason = OneOf(fields, "reason", PauseReasons.All), Detail = Text(fields, "detail") },
            LoopKinds.End => request with { EndStatus = OneOf(fields, "status", LoopStatuses.ClientEnd), Reason = Text(fields, "reason") },
            _ => request,
        };
    }

    // ---- typed field readers (strict: wrong types are refused, never coerced) ----

    private static void RejectUnknown(JsonObject o, string[] allowed, string where)
    {
        foreach (string key in o.Select(kv => kv.Key))
            if (!allowed.Contains(key))
                throw new CustodianRefusal(ErrorCodes.MalformedRequest, $"unexpected key in {where} (no field conveys authority; unknown fields are refused, not ignored)");
    }

    private static string RequiredString(JsonObject o, string key)
        => o[key] is JsonValue v && v.TryGetValue(out string? s) && s is not null ? s : throw new ArgumentException($"fields.{key} must be a string");

    private static string Hex64(JsonObject o, string key)
    {
        string s = RequiredString(o, key);
        if (s.Length != 64 || !s.All(char.IsAsciiHexDigitLower)) throw new ArgumentException($"fields.{key} must be 64 lowercase hex characters");
        return s;
    }

    private static string Session(JsonObject o)
    {
        string s = RequiredString(o, "session_id");
        if (s.Length is < 1 or > 256 || !s.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '-'))
            throw new ArgumentException("fields.session_id must be 1..256 chars of [A-Za-z0-9._:-]");
        return s;
    }

    /// <summary>A custodian-issued identifier the client hands back (an operation handle or a wake claim id).</summary>
    private static string Id(JsonObject o, string key)
    {
        string s = RequiredString(o, key);
        RequireToken($"fields.{key}", s, 64, allowUnderscore: false);
        return s;
    }

    /// <summary>The custodian-issued derivation id an automation request names (absent: the request names none and is
    /// refused DERIVATION_STALE by the ledger).</summary>
    private static string? OptionalDerivationId(JsonObject o)
    {
        if (!o.ContainsKey("derivation_id") || o["derivation_id"] is null) return null;
        string s = RequiredString(o, "derivation_id");
        RequireToken("fields.derivation_id", s, 64, allowUnderscore: false);
        return s;
    }

    private static int? Pid(JsonObject o)
    {
        if (o["process"] is not JsonObject p) throw new ArgumentException("fields.process must be an object");
        RejectUnknown(p, ProcessFields, "fields.process");
        if (!p.TryGetPropertyValue("pid", out JsonNode? pid)) throw new ArgumentException("fields.process.pid is required (null when the host gave none)");
        if (pid is null) return null;
        return pid is JsonValue v && v.TryGetValue(out int n) && n > 0 ? n : throw new ArgumentException("fields.process.pid must be a positive integer or null");
    }

    private static string OneOf(JsonObject o, string key, IReadOnlySet<string> allowed)
    {
        string s = RequiredString(o, key);
        return allowed.Contains(s) ? s : throw new ArgumentException($"fields.{key} must be one of: {string.Join(", ", allowed.Order(StringComparer.Ordinal))}");
    }

    /// <summary>Optional free text (an engine reason or detail): bounded, control characters replaced, so it
    /// cannot forge a line in the audit log or the evidence.</summary>
    private static string Text(JsonObject o, string key)
    {
        if (!o.ContainsKey(key) || o[key] is null) return "";
        string s = RequiredString(o, key);
        if (s.Length > MaxTextChars) throw new ArgumentException($"fields.{key} must be at most {MaxTextChars} characters");
        return new string(s.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
    }

    private static void RequireToken(string name, string s, int max, bool allowUnderscore)
    {
        if (s.Length < 1 || s.Length > max || !s.All(c => char.IsAsciiLetterOrDigit(c) || c == '-' || (allowUnderscore && c == '_')))
            throw new ArgumentException($"{name} must be 1..{max} chars of [A-Za-z0-9-{(allowUnderscore ? "_" : "")}]");
    }
}
