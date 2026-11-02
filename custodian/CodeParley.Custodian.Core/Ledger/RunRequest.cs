using System.Globalization;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// A validated <c>run_transition</c> request (P3.4C-3, contract §3.1–§3.2). The client names the run, a closed
/// <c>kind</c> and that kind's <c>fields</c>; every key is allowlisted per kind (another key — including an
/// authority-shaped one such as <c>accepted</c>, <c>status</c> of a record, <c>round</c>, <c>verified</c>,
/// <c>writer</c> or a revision the custodian assigns — is MALFORMED_REQUEST, never ignored), and every value is
/// checked: ids are 1–128 chars of <c>[A-Za-z0-9-_]</c>, digests 64 lowercase hex, enums closed, free text bounded
/// with control characters replaced. A missing, mistyped or out-of-range value is INVALID_ARGUMENT. Every field is a
/// CLAIM the custodian validates; none conveys authority. <see cref="Digest"/> binds the whole request, so a replay
/// under the same request id must be the same request.
/// </summary>
internal sealed record RunRequest
{
    internal required string RunId { get; init; }
    internal required string Kind { get; init; }
    internal required string RequestId { get; init; }
    internal required string Digest { get; init; }
    /// <summary>The validated fields: only allowlisted keys, every value checked. For <c>op_finish</c> the
    /// <c>outcome</c> is validated against the operation's kind, which only the custodian knows
    /// (<see cref="RunFields.Outcome"/>).</summary>
    internal required JsonObject Fields { get; init; }

    internal static RunRequest Parse(string runId, string kind, JsonObject fields, string requestId)
    {
        RunFields.RequireToken("runId", runId, 128);
        RunFields.RequireToken("request id", requestId, 128);
        if (!RunKinds.All.Contains(kind)) throw new ArgumentException($"kind must be one of: {string.Join(", ", RunKinds.All.Order(StringComparer.Ordinal))}");
        JsonObject validated = kind switch
        {
            RunKinds.Open => RunFields.OpenShape.Apply(fields, "fields"),
            RunKinds.OpBegin => RunFields.OpBegin(fields),
            RunKinds.RecordExecution => RunFields.RecordExecutionShape.Apply(fields, "fields"),
            RunKinds.OpFinish => RunFields.OpFinishShape.Apply(fields, "fields"),
            RunKinds.Recover => RunFields.RecoverShape.Apply(fields, "fields"),
            RunKinds.Respond => RunFields.Respond(fields),
            RunKinds.End => RunFields.EndShape.Apply(fields, "fields"),
            RunKinds.ApplyReconcile => RunFields.ApplyReconcileShape.Apply(fields, "fields"),
            _ => throw new ArgumentException("unknown run transition kind"),
        };
        string digest = Ledger.Digest.Sha256Hex(Ledger.Digest.Canonical(new JsonObject { ["kind"] = kind, ["fields"] = fields.DeepClone() }));
        return new RunRequest { RunId = runId, Kind = kind, RequestId = requestId, Digest = digest, Fields = validated };
    }
}

/// <summary>The per-kind field shapes of <c>run_transition</c> and the strict value rules they are built from.</summary>
internal static class RunFields
{
    internal delegate JsonNode? Rule(JsonNode? value, string path);

    internal const int MaxText = 500;

    /// <summary>An allowlisted object: every key must be one of <see cref="Rules"/> (else MALFORMED_REQUEST), every
    /// rule's key must be present unless optional (else INVALID_ARGUMENT); the result holds only the validated keys.</summary>
    internal sealed class Shape(IReadOnlyDictionary<string, Rule> rules, params string[] optional)
    {
        internal IReadOnlyDictionary<string, Rule> Rules { get; } = rules;
        private readonly HashSet<string> _optional = new(optional, StringComparer.Ordinal);

        internal JsonObject Apply(JsonNode? value, string path)
        {
            if (value is not JsonObject o) throw new ArgumentException($"{path} must be an object");
            foreach (string key in o.Select(kv => kv.Key))
                if (!Rules.ContainsKey(key))
                    throw new CustodianRefusal(ErrorCodes.MalformedRequest, $"unexpected key in {path} (no field conveys authority; unknown fields are refused, not ignored)");
            var result = new JsonObject();
            foreach ((string key, Rule rule) in Rules)
            {
                if (!o.TryGetPropertyValue(key, out JsonNode? v))
                {
                    if (_optional.Contains(key)) continue;
                    throw new ArgumentException($"{path}.{key} is required");
                }
                result[key] = rule(v, $"{path}.{key}");
            }
            return result;
        }
    }

    private static Dictionary<string, Rule> Fields(params (string Key, Rule Rule)[] rules) => rules.ToDictionary(r => r.Key, r => r.Rule, StringComparer.Ordinal);

    // ---- value rules (strict: wrong types are refused, never coerced) ----

    internal static readonly Rule Id = (v, p) => Token(v, p, 128);
    internal static readonly Rule IdOrNull = OrNull(Id);
    /// <summary>A custodian-issued operation id the client hands back.</summary>
    internal static readonly Rule OperationId = (v, p) => Token(v, p, 64);
    internal static readonly Rule Hex64 = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length != 64 || !s.All(char.IsAsciiHexDigitLower)) throw new ArgumentException($"{p} must be 64 lowercase hex characters");
        return s;
    };
    internal static readonly Rule Hex64OrNull = OrNull(Hex64);
    internal static readonly Rule Bool = (v, p) => v is JsonValue j && j.TryGetValue(out bool b) ? b : throw new ArgumentException($"{p} must be a boolean");
    internal static readonly Rule CheckName = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length is < 1 or > 64 || !char.IsAsciiLetterOrDigit(s[0]) || !s.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'))
            throw new ArgumentException($"{p} must be a check name (1-64 of [A-Za-z0-9._-], starting alphanumeric)");
        return s;
    };
    internal static readonly Rule Iso = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length > 40 || !DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _))
            throw new ArgumentException($"{p} must be an ISO 8601 timestamp");
        return s;
    };
    internal static readonly Rule IsoOrNull = OrNull(Iso);
    /// <summary>A short machine code (a limitation's code).</summary>
    internal static readonly Rule Code = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length is < 1 or > 64 || !s.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':'))
            throw new ArgumentException($"{p} must be a code of 1-64 of [A-Za-z0-9_.:-]");
        return s;
    };

    internal static Rule Int(long min, long max) => (v, p) =>
        Integer(v) is long n && n >= min && n <= max ? n : throw new ArgumentException($"{p} must be an integer from {min} to {max}");

    /// <summary>An integral JSON number (never a string, a fraction or a boolean), whether parsed from the wire or
    /// built in process; null for anything else.</summary>
    internal static long? Integer(JsonNode? node)
    {
        if (node is not JsonValue j) return null;
        if (j.TryGetValue(out long l)) return l;
        if (j.TryGetValue(out int i)) return i;
        if (j.TryGetValue(out System.Text.Json.JsonElement e) && e.ValueKind == System.Text.Json.JsonValueKind.Number && e.TryGetInt64(out long el)) return el;
        return null;
    }
    internal static Rule IntOrNull(long min, long max) => OrNull(Int(min, max));
    internal static Rule Text(int max) => (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length > max) throw new ArgumentException($"{p} must be at most {max} characters");
        return new string(s.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
    };
    internal static Rule TextOrNull(int max) => OrNull(Text(max));
    internal static Rule Enum(IReadOnlySet<string> allowed) => (v, p) =>
    {
        string s = Str(v, p);
        return allowed.Contains(s) ? s : throw new ArgumentException($"{p} must be one of: {string.Join(", ", allowed.Order(StringComparer.Ordinal))}");
    };
    internal static Rule EnumOrNull(IReadOnlySet<string> allowed) => OrNull(Enum(allowed));
    internal static Rule Obj(Shape shape) => (v, p) => shape.Apply(v, p);
    internal static Rule ObjOrNull(Shape shape) => OrNull(Obj(shape));

    /// <summary>An array of at most <paramref name="max"/> elements, each validated by <paramref name="element"/>;
    /// with <paramref name="uniqueBy"/>, no two elements may share that key (or, for a scalar array, that value).</summary>
    internal static Rule Array(Rule element, int max, string? uniqueBy = null, bool unique = false) => (v, p) =>
    {
        if (v is not JsonArray a) throw new ArgumentException($"{p} must be an array");
        if (a.Count > max) throw new ArgumentException($"{p} must have at most {max} entries");
        var result = new JsonArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < a.Count; i++)
        {
            JsonNode? e = element(a[i], $"{p}[{i}]");
            string? key = uniqueBy is not null ? (string?)e?[uniqueBy] : unique ? e?.ToJsonString() : null;
            if (key is not null && !seen.Add(key)) throw new ArgumentException($"{p} has a duplicate entry ({(uniqueBy ?? "value")})");
            result.Add(e);
        }
        return result;
    };

    private static Rule OrNull(Rule rule) => (v, p) => v is null ? null : rule(v, p);

    private static string Str(JsonNode? v, string p)
        => v is JsonValue j && j.TryGetValue(out string? s) && s is not null ? s : throw new ArgumentException($"{p} must be a string");

    private static string Token(JsonNode? v, string p, int max)
    {
        string s = Str(v, p);
        RequireToken(p, s, max);
        return s;
    }

    internal static void RequireToken(string name, string s, int max)
    {
        if (s.Length < 1 || s.Length > max || s is "." or ".." || !s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new ArgumentException($"{name} must be 1..{max} chars of [A-Za-z0-9-_]");
    }

    // ---- open ----

    internal static readonly Shape OpenShape = new(Fields(
        ("runJsonDigest", Hex64),
        // Phase 4 Increment 2: maxFixes (optional; absent: no delegated fix is budgeted for the run).
        ("budgets", Obj(new Shape(Fields(("maxReviews", Int(0, 10_000)), ("maxCheckExecutions", Int(0, 100_000)), ("maxFixes", Int(0, 100))), "maxFixes"))),
        ("baseline", ObjOrNull(new Shape(Fields(("sourceId", Hex64), ("digest", Hex64)))))));

    // ---- op_begin ----

    /// <summary>P3.4C-5 Increment 3 (§4): the absolute path of the executable the session resolved for a planned check — an
    /// engine claim (resolved in the session's environment, like the environment digest); the custodian measures its STAT.</summary>
    internal static readonly Rule ExecutablePath = (v, p) =>
    {
        if (v is null) return null;
        string s = Str(v, p);
        bool absolute = (s.Length >= 3 && char.IsAsciiLetter(s[0]) && s[1] == ':' && s[2] is '\\' or '/') || s.StartsWith(@"\\", StringComparison.Ordinal) || s.StartsWith('/');
        if (s.Length > 1024 || !absolute || s.Any(char.IsControl) || s.Contains('"'))
            throw new ArgumentException($"{p} must be an absolute path (at most 1024 characters, no control character or quote)");
        return s;
    };

    private static readonly Shape ChecksBeginShape = new(Fields(
        ("operationKind", Enum(RunEnums.OperationKinds)),
        // P3.4C-4 (§3.3): every planned check carries the definition digest it will run (null: it will only be recorded
        // as skipped); the custodian compares it with its approved definition. P3.4C-5 Increment 3: and the executable the
        // session resolved for it (the custodian measures its stat and the check's freshness inputs itself).
        ("planned", Array(Obj(new Shape(Fields(("check", CheckName), ("checkSpecId", Hex64OrNull), ("definitionDigest", Hex64OrNull), ("required", Bool), ("executable", ExecutablePath)), "executable")), 50, uniqueBy: "check")),
        ("inputIdentity", Hex64OrNull)));

    /// <summary>The capture claims a P3.4C-3 review <c>op_begin</c> carried. P3.4C-5 (§3.1): the custodian measures them
    /// itself, so a reservation that still sends them has them syntax-checked, IGNORED and audited — never recorded.</summary>
    internal static readonly IReadOnlyList<string> IgnoredCaptureClaims =
        ["sourceId", "reviewInputId", "captureId", "captureStable", "captureDigest", "exportDigest", "manifestDigest", "promptDigest"];

    /// <summary>The capture target a reservation names (an engine claim from run.json, bound into the custodian's review
    /// input identity): the uncommitted changes, or the changes since a base ref. <c>since_baseline</c> is refused (the
    /// custodian's helper does not capture it yet).</summary>
    internal static readonly Rule Target = (v, p) =>
    {
        if (v is not JsonObject o) throw new ArgumentException($"{p} must be an object");
        string kind = o["kind"] is JsonValue k && k.TryGetValue(out string? ks) && ks is not null ? ks : throw new ArgumentException($"{p}.kind must be a string");
        if (kind == "since_baseline")
            throw new CustodianRefusal(ErrorCodes.InvalidArgument, "a protected review of target since_baseline is not supported by the custodian's capture yet; use target uncommitted or base_ref");
        if (kind == "uncommitted")
        {
            if (o.Count != 1) throw new CustodianRefusal(ErrorCodes.MalformedRequest, $"unexpected key in {p}");
            return new JsonObject { ["kind"] = "uncommitted" };
        }
        if (kind == "base_ref")
        {
            if (o.Count != 2 || o["ref"] is null) throw new CustodianRefusal(ErrorCodes.MalformedRequest, $"unexpected or missing key in {p}");
            string r = Str(o["ref"], $"{p}.ref");
            if (r.Length is 0 or > 256 || r.StartsWith('-') || r.Contains("..") || !r.All(c => char.IsAsciiLetterOrDigit(c) || "._/@{}~^-".Contains(c)))
                throw new ArgumentException($"{p}.ref must be a plain git ref (no options, ranges or paths)");
            return new JsonObject { ["kind"] = "base_ref", ["ref"] = r };
        }
        throw new ArgumentException($"{p}.kind must be uncommitted or base_ref");
    };

    private static readonly Shape OfferedItemShape = new(Fields(("itemId", Id), ("responseIds", Array(Id, 20, unique: true)), ("replyIds", Array(Id, 20, unique: true))));
    private static readonly Shape OfferedAmendmentShape = new(Fields(("amendmentId", Id), ("disclosureDigest", Hex64OrNull)));

    /// <summary>
    /// P3.4C-5 (§3.1 step 2): a protected review's <c>op_begin</c> RESERVES — it carries everything the engine selects
    /// without the capture: the source it selected the check evidence and discussion for (<c>selectionSourceId</c>, a
    /// claim the capture must match), the target, the presented check executions, the discussion turns and amendments it
    /// offers the reviewer, the isolation claim, the configuration identities and the focus, depth and versions. The
    /// capture fields and the prompt digest are not part of it (the custodian measures the capture; the prompt digest
    /// arrives with <c>op_finish</c>).
    /// </summary>
    private static readonly Shape ReviewReserveShape = new(Fields(
        ("operationKind", Enum(RunEnums.OperationKinds)),
        ("reviewId", Id),
        ("selectionSourceId", Hex64),
        ("target", Target),
        ("checkExecutionIds", Array(Id, 200, unique: true)),
        ("checkEvidenceDigest", Hex64),
        ("checkResultsDigest", Hex64),
        ("discussion", Obj(new Shape(Fields(("offered", Array(Obj(OfferedItemShape), 500, uniqueBy: "itemId")))))),
        ("amendments", Obj(new Shape(Fields(("offered", Array(Obj(OfferedAmendmentShape), 50, uniqueBy: "amendmentId")))))),
        ("isolation", Obj(new Shape(Fields(("mode", Enum(RunEnums.IsolationModes)), ("profileDigest", Hex64), ("selftestId", IdOrNull), ("acceptanceId", IdOrNull),
            ("backend", Code), ("codexVersion", ConfigValidation.VersionText))))),
        ("captureRulesDigest", Hex64),
        ("codexSha256", Hex64),
        ("depth", Enum(RunEnums.Depths)),
        ("focusDigest", Hex64OrNull),
        ("versionsDigest", Hex64),
        // Ignored claims (validated for syntax, then dropped): see IgnoredCaptureClaims.
        ("sourceId", Hex64), ("reviewInputId", Hex64), ("captureId", Id), ("captureStable", Bool), ("captureDigest", Hex64),
        ("exportDigest", Hex64), ("manifestDigest", Hex64), ("promptDigest", Hex64)),
        "sourceId", "reviewInputId", "captureId", "captureStable", "captureDigest", "exportDigest", "manifestDigest", "promptDigest");

    /// <summary><c>op_begin</c>: the begin fields of the operation kind the request names. A review is a P3.4C-5
    /// reservation (<see cref="ReviewReserveShape"/>); the P3.4C-3 shape that carried the engine's capture is gone — its
    /// capture claims are ignored, and its other bindings are refused as unknown keys (a review is never begun on the
    /// engine's capture).</summary>
    internal static JsonObject OpBegin(JsonObject fields)
    {
        string kind = (string)Enum(RunEnums.OperationKinds)(fields["operationKind"], "fields.operationKind")!;
        return (kind == "checks" ? ChecksBeginShape : kind == "review" ? ReviewReserveShape : kind == "apply" ? ApplyBeginShape : FixBeginShape).Apply(fields, "fields");
    }

    // ---- Phase 4 Increment 2: a delegated fix (contract §3.2, §3.4) ----

    /// <summary>A repository-relative path a boundary names (its length here; the portable-path rules in the boundary check).</summary>
    private static readonly Rule FixPath = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length < 1 || s.Length > CustodianConstants.MaxFixPathChars) throw new ArgumentException($"{p} must be 1 to {CustodianConstants.MaxFixPathChars} characters");
        return s;
    };

    private static readonly Shape FixBoundaryShape = new(Fields(
        ("permittedFiles", Array(FixPath, CustodianConstants.MaxFixPermittedFiles, unique: true)),
        ("permittedDirs", Array(FixPath, CustodianConstants.MaxFixPermittedDirs, unique: true)),
        ("allowCreate", Bool),
        ("allowDelete", Bool),
        ("allowBinary", Bool),
        ("maxChangedFiles", Int(1, CustodianConstants.MaxFixChangedFiles)),
        ("maxFileBytes", Int(1, CustodianConstants.MaxFixFileBytes)),
        ("maxTotalBytes", Int(1, CustodianConstants.MaxFixTotalBytes)),
        ("timeLimitSeconds", Int(CustodianConstants.MinFixTimeLimitSeconds, CustodianConstants.MaxFixTimeLimitSeconds)),
        ("proposalLifetimeSeconds", Int(CustodianConstants.MinFixLifetimeSeconds, CustodianConstants.MaxFixLifetimeSeconds))));

    /// <summary>The boundary the custodian binds: syntax, then the portable-path and sensitive-directory rules (FixRules).</summary>
    private static readonly Rule FixBoundary = (v, p) =>
    {
        JsonObject b = FixBoundaryShape.Apply(v, p);
        if (FixRules.BoundaryProblem(b) is { } problem) throw new ArgumentException($"{p}: {problem}");
        return b;
    };

    /// <summary>
    /// A delegated fix's <c>op_begin</c>: the fix id, the task digest, the baseline review whose published capture seeds the
    /// workspace, the boundary, the FIX isolation claim (an operator-confirmed FIX self-test — mode FIX only, never S1) and
    /// the Codex image the engine launches. Never file contents.
    /// </summary>
    private static readonly Shape FixBeginShape = new(Fields(
        ("operationKind", Enum(RunEnums.OperationKinds)),
        ("fixId", Id),
        ("taskDigest", Hex64),
        ("baselineReviewId", Id),
        ("boundary", FixBoundary),
        ("isolation", Obj(new Shape(Fields(("mode", Enum(new HashSet<string>(StringComparer.Ordinal) { "FIX" })), ("profileDigest", Hex64), ("selftestId", Id),
            ("backend", Code), ("codexVersion", ConfigValidation.VersionText))))),
        ("codexSha256", Hex64)));

    /// <summary>A submitted postimage: strict base64 of at most the per-file cap (decoded and judged in the hold).</summary>
    private static readonly Rule Base64OrNull = (v, p) =>
    {
        if (v is null) return null;
        string s = Str(v, p);
        if (s.Length > (CustodianConstants.MaxFixFileBytes + 2) / 3 * 4 || s.Length % 4 != 0 || !FixRules.IsBase64Alphabet(s))
            throw new ArgumentException($"{p} must be base64 of at most {CustodianConstants.MaxFixFileBytes} bytes");
        return s;
    };

    /// <summary>A submitted path is judged by the custodian in the hold (a bad one is a violation, not a malformed request).</summary>
    private static readonly Rule SubmittedPath = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length > CustodianConstants.MaxFixPathChars * 2) throw new ArgumentException($"{p} must be at most {CustodianConstants.MaxFixPathChars * 2} characters");
        return s;
    };

    private static readonly Shape FixOutcomeShape = new(Fields(
        ("status", Enum(RunEnums.FixOutcomeStatuses)),
        ("scan", ObjOrNull(new Shape(Fields(("complete", Bool), ("files", Int(0, 1_000_000)), ("anomalies", Int(0, 1_000_000)), ("violations", Int(0, 1_000_000)))))),
        ("detail", TextOrNull(MaxText)),
        ("changes", Array(Obj(new Shape(Fields(("path", SubmittedPath), ("kind", Enum(RunEnums.FixChangeKinds)), ("executable", Bool), ("content", Base64OrNull)))), CustodianConstants.MaxFixChangedFiles + 1))));

    // ---- Phase 4 Increment 3: the application of a confirmed fix (contract §3.6) ----

    /// <summary>An application's <c>op_begin</c>: the fix whose confirmed proposal is applied, and its digest. Never a
    /// confirmation: the custodian holds it, and a confirmation-shaped field is an unknown key (MALFORMED_REQUEST).</summary>
    private static readonly Shape ApplyBeginShape = new(Fields(("operationKind", Enum(RunEnums.OperationKinds)), ("fixOperationId", OperationId), ("proposalDigest", Hex64)));

    private static readonly Shape ApplyFileShape = new(Fields(("path", SubmittedPath), ("state", Enum(RunEnums.ApplyFileStates))));

    private static readonly Shape ApplyOutcomeShape = new(Fields(
        ("status", Enum(RunEnums.ApplyOutcomeStatuses)),
        ("files", Array(Obj(ApplyFileShape), CustodianConstants.MaxFixChangedFiles, uniqueBy: "path")),
        ("detail", TextOrNull(MaxText))));

    /// <summary><c>apply_reconcile</c>: what the implementer's reconciliation of an interrupted application did.</summary>
    internal static readonly Shape ApplyReconcileShape = new(Fields(
        ("operationId", OperationId),
        ("choice", Enum(RunEnums.ReconcileChoices)),
        ("observed", Enum(RunEnums.ReconcileObserved)),
        ("files", Array(Obj(ApplyFileShape), CustodianConstants.MaxFixChangedFiles, uniqueBy: "path")),
        ("detail", TextOrNull(MaxText))));

    // ---- record_execution ----

    private static readonly Shape ExecutionShape = new(Fields(
        ("executionId", Id),
        ("check", CheckName),
        ("definitionDigest", Hex64OrNull),
        ("checkSpecId", Hex64OrNull),
        ("executionInputId", Hex64OrNull),
        ("envDigest", Hex64OrNull),
        ("freshnessDigest", Hex64OrNull),
        ("status", Enum(RunEnums.CheckExecutionStatuses)),
        ("skipReason", EnumOrNull(RunEnums.SkipReasons)),
        ("exitCode", IntOrNull(int.MinValue, int.MaxValue)),
        ("timedOut", Bool),
        ("cancelled", Bool),
        ("startedAt", IsoOrNull),
        ("endedAt", IsoOrNull),
        ("durationMs", IntOrNull(0, int.MaxValue)),
        ("sourceIdAtStart", Hex64OrNull),
        ("sourceIdAtEnd", Hex64OrNull),
        ("sourceStable", Bool),
        ("stdoutDigest", Hex64OrNull),
        ("stderrDigest", Hex64OrNull),
        ("resultDigest", Hex64OrNull),
        ("limitations", Array(Obj(new Shape(Fields(("code", Code), ("detail", Text(MaxText))))), 20))));

    internal static readonly Shape RecordExecutionShape = new(Fields(("operationId", OperationId), ("execution", Obj(ExecutionShape))));

    // ---- op_finish (the outcome is validated against the operation's kind: Outcome) ----

    /// <summary>P3.4C-5 (§3.1 step 7): what a finished custodian-captured review presented, as the engine claims it — the
    /// discussion turns and amendments the rendered bundle carried (each a subset of what the reservation offered), with
    /// their digests.</summary>
    internal static readonly Shape PresentedShape = new(Fields(
        ("discussion", Obj(new Shape(Fields(
            ("digest", Hex64),
            ("delivered", Array(Obj(OfferedItemShape), 500, uniqueBy: "itemId")),
            ("notDeliveredCount", Int(0, 100_000)),
            // P3.4C-5 Increment 3 (§5.1): per delivered response, whether the reviewer was asked to reply and why (the
            // discussion's exchange count and amendment gate read them); each names a delivered response.
            ("deliveries", Array(Obj(new Shape(Fields(("responseId", Id), ("itemId", Id), ("replySought", Bool), ("basis", Array(Code, 16, unique: true))))), 1000, uniqueBy: "responseId"))),
            "deliveries"))),
        ("amendments", Obj(new Shape(Fields(
            ("digest", Hex64),
            ("presented", Array(Obj(OfferedAmendmentShape), 50, uniqueBy: "amendmentId")),
            ("withheld", Array(Id, 50, unique: true))))))));

    /// <summary>Any object, kept as sent (the op_finish outcome, validated later against the operation's kind).</summary>
    private static readonly Rule AnyObject = (v, p) => v is JsonObject o ? o.DeepClone() : throw new ArgumentException($"{p} must be an object");

    internal static readonly Shape OpFinishShape = new(Fields(
        ("operationId", OperationId),
        ("outcome", AnyObject),
        // P3.4C-5: a custodian-captured review's prompt digest (moved here from op_begin) and what it presented.
        ("promptDigest", Hex64OrNull),
        ("presented", ObjOrNull(PresentedShape))),
        "promptDigest", "presented");

    private static readonly Shape ChecksOutcomeShape = new(Fields(("status", Enum(RunEnums.CheckOutcomeStatuses)), ("error", TextOrNull(MaxText))));

    private static readonly Shape NewItemShape = new(Fields(
        ("itemId", Id),
        ("itemKind", Enum(RunEnums.ItemKinds)),
        ("triage", Enum(RunEnums.Triages)),
        ("severity", EnumOrNull(RunEnums.Severities)),
        ("claimType", EnumOrNull(RunEnums.ClaimTypes)),
        ("category", EnumOrNull(RunEnums.Categories)),
        ("impacts", Array(Enum(RunEnums.Impacts), 14, unique: true)),
        ("confidence", EnumOrNull(RunEnums.Confidences)),
        ("status", Enum(RunEnums.NewItemStatuses)),
        ("relatedPriorId", IdOrNull),
        ("relatedFindingId", IdOrNull),
        ("restates", Array(Id, 20, unique: true))));

    private static readonly Shape ReplyShape = new(Fields(
        ("replyId", Id),
        ("itemId", Id),
        ("stance", Enum(RunEnums.Stances)),
        ("newInformation", Enum(RunEnums.NewInformation)),
        ("answersResponseId", IdOrNull),
        ("assessment", EnumOrNull(RunEnums.ReplyAssessments))));

    private static readonly Shape ReviewOutcomeShape = new(Fields(
        ("status", Enum(RunEnums.ReviewOutcomeStatuses)),
        ("outputValid", Bool),
        ("currentAtCompletion", Bool),
        ("verdict", EnumOrNull(RunEnums.Verdicts)),
        ("summaryDigest", Hex64OrNull),
        ("artifacts", Obj(new Shape(Fields(
            ("rawOutput", Hex64OrNull), ("output", Hex64OrNull), ("items", Hex64OrNull), ("result", Hex64OrNull),
            ("events", Hex64OrNull), ("stderr", Hex64OrNull), ("lastMessage", Hex64OrNull))))),
        ("newItems", Array(Obj(NewItemShape), CustodianConstants.MaxNewItemsPerReview, uniqueBy: "itemId")),
        ("assessments", Array(Obj(new Shape(Fields(("itemId", Id), ("assessment", Enum(RunEnums.AssessmentEntries)), ("supersededByItemId", IdOrNull)))), CustodianConstants.MaxItemsPerRun, uniqueBy: "itemId")),
        ("replies", Array(Obj(ReplyShape), CustodianConstants.MaxRepliesPerRun, uniqueBy: "replyId")),
        ("incidents", Array(Obj(new Shape(Fields(("kind", Enum(RunEnums.EngineIncidentKinds)), ("detail", Text(MaxText))))), 50))));

    /// <summary>An <c>op_finish</c> outcome, validated against the kind of the operation the custodian holds.</summary>
    internal static JsonObject Outcome(string operationKind, JsonNode? outcome)
        => (operationKind == "checks" ? ChecksOutcomeShape : operationKind == "fix" ? FixOutcomeShape : operationKind == "apply" ? ApplyOutcomeShape : ReviewOutcomeShape).Apply(outcome, "fields.outcome");

    // ---- recover / respond / end ----

    internal static readonly Shape RecoverShape = new(Fields(
        ("operationId", OperationId),
        ("incidents", Array(Obj(new Shape(Fields(("kind", Enum(RunEnums.RecoverIncidents)), ("detail", Text(MaxText))))), 10))));

    private static readonly Shape ResponseShape = new(Fields(
        ("responseId", Id),
        ("itemId", Id),
        ("baseItemRevision", Int(1, int.MaxValue)),
        ("disposition", Enum(RunEnums.Dispositions)),
        ("textWithheld", Bool),
        ("answers", Obj(new Shape(Fields(
            ("reviewId", IdOrNull), ("round", IntOrNull(1, 10_000)), ("runReviewId", IdOrNull), ("runRound", IntOrNull(1, 10_000)), ("reviewerReplyId", IdOrNull))))),
        ("sourceId", Hex64OrNull),
        ("supersedes", IdOrNull),
        ("threadId", Id),
        // P3.4C-5 Increment 3 (§5.1): what the discussion's new-information gate reads of a response's text, held without
        // the text — each cited location as a comparison key, and whether a rationale was given (engine claims).
        ("referenceKeys", Array(Hex64, 20, unique: true)),
        ("rationalePresent", Bool)),
        "referenceKeys", "rationalePresent");

    private static readonly Shape RespondShape = new(Fields(
        ("responseSetId", Id),
        ("disclosureDigest", Hex64OrNull),
        ("responses", Array(Obj(ResponseShape), CustodianConstants.MaxResponsesPerCall, uniqueBy: "responseId"))));

    /// <summary><c>respond</c>: at least one response, at most one per item.</summary>
    internal static JsonObject Respond(JsonObject fields)
    {
        JsonObject r = RespondShape.Apply(fields, "fields");
        JsonArray responses = r["responses"]!.AsArray();
        if (responses.Count == 0) throw new ArgumentException("fields.responses must have at least one response");
        if (responses.Select(x => (string)x!["itemId"]!).Distinct(StringComparer.Ordinal).Count() != responses.Count)
            throw new ArgumentException("fields.responses has more than one response for an item");
        return r;
    }

    internal static readonly Shape EndShape = new(Fields(("status", Enum(RunEnums.EndStatuses)), ("reason", Text(MaxText))));
}
