using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>What a measurement is launched with: the approved runtime record (re-measured before the launch), the
/// repository the custodian validated, the custodian's read-only per-request directory, the <c>derive</c> workload (its
/// checks and, for a derivation, the scrubbed snapshot) and its deadline.</summary>
internal sealed record MeasureLaunch(EngineRuntimeRecord Runtime, RepoIdentity Repo, string CfgDir, JsonObject Workload, TimeSpan Timeout);

/// <summary>How a measurement ended: its validated measurement and, for a derivation, the derivation (or why not); for a
/// redaction (Phase 5 F-i2-5), the reviewer-visible representation the helper produced from the same read.</summary>
internal sealed record MeasureOutcome(bool Ok, string? Code, string? Detail, JsonObject? Measured, JsonObject? Derivation, JsonObject? Redaction = null)
{
    internal static MeasureOutcome Failed(string code, string? detail) => new(false, code, detail, null, null);
}

/// <summary>P3.4C-5 Increment 3 (§4, §5.1, N5-17): runs a <c>derive</c> workload — a measurement of the source and the
/// checks' inputs, with the protected derivation when a snapshot is given. The service's runner re-measures the approved
/// runtime and runs the workload through the helper service; the self-tests substitute a synthetic one.</summary>
internal interface IMeasurementRunner
{
    Task<MeasureOutcome> RunAsync(MeasureLaunch launch, CancellationToken ct);
}

/// <summary>The service's measurement runner: the approved runtime measured again (a difference refuses, never another
/// computation), then the helper service's <c>derive</c> workload; its result validated (<see cref="DeriveJob"/>).</summary>
internal sealed class HelperMeasurementRunner(HelperBroker broker) : IMeasurementRunner
{
    public async Task<MeasureOutcome> RunAsync(MeasureLaunch l, CancellationToken ct)
    {
        MeasuredRuntime m;
        try { m = EngineRuntime.Measure(l.Runtime.Root, l.Runtime.GitRelative, l.Runtime.GitPath); }
        catch (CustodianRefusal e) { return MeasureOutcome.Failed(ErrorCodes.ConfigMismatch, e.Message); }
        List<string> diff = EngineRuntime.Differences(l.Runtime.Measured, m);
        if (diff.Count > 0) return MeasureOutcome.Failed(ErrorCodes.ConfigMismatch, $"the engine runtime differs from the one approved ({string.Join(", ", diff)}); the operator approves it again");
        var job = new DeriveJob();
        JsonObject launch = GrantLedger.Launch(m, l.CfgDir, l.Repo, job.MaxFrameBody);
        HelperJobOutcome o = await broker.RunAsync("derive", new JsonObject { ["launch"] = launch, ["workload"] = l.Workload.DeepClone() }, job, l.Timeout, ct).ConfigureAwait(false);
        if (!o.Ok) return MeasureOutcome.Failed(o.Code ?? ErrorCodes.MeasurementFailed, o.Detail);
        try
        {
            JsonObject r = job.Consume();
            return new MeasureOutcome(true, null, null, (JsonObject)r["measured"]!.DeepClone(), r["derivation"] as JsonObject is { } d ? (JsonObject)d.DeepClone() : null,
                r["redaction"] as JsonObject is { } x ? (JsonObject)x.DeepClone() : null);
        }
        catch (HelperFrameError e) { return MeasureOutcome.Failed(ErrorCodes.MeasurementFailed, e.Message); }
    }
}

/// <summary>One derivation the custodian computed (§5.1 step 3): in memory only, lost on restart, never authority by itself.
/// <see cref="Workload"/> is what was measured (re-measured before a spend or wake, N5-17).</summary>
internal sealed record DerivationEntry(
    string DerivationId, string RepoKey, string RunId, DateTime At, JsonObject Revision, string RouteKind, string RouteCode,
    string Fingerprint, string InputDigest, string MeasuredDigest, JsonObject Workload, RepoIdentity Repo, JsonObject Section);

internal sealed partial class GrantLedger
{
    /// <summary>Phase 4 Increment 2: an operation's status as the derivation snapshot reports it — a proposal that is retired
    /// or past its lifetime is <c>expired</c> (no longer pending the owner's confirmation; Increment 3: nor, once confirmed,
    /// its application).</summary>
    private static string SnapshotOperationStatus(RunOperation o, DateTime now)
    {
        if (o.Kind != "fix" || o.Status is not (RunOperationStatuses.Proposed or FixConfirmed)) return o.Status;
        JsonObject? p = o.Outcome?["proposal"] as JsonObject;
        return p is null || p["retiredAt"] is not null || ParseTime((string)p["expiresAt"]!) <= now ? "expired" : o.Status;
    }

    /// <summary>§5.2: how long a derivation may authorize a continuation or a wake (it must also still match every revision).</summary>
    internal static readonly TimeSpan DerivationTtl = TimeSpan.FromSeconds(120);
    private const int MaxCachedDerivations = 256;
    private static readonly IReadOnlySet<string> ReplySeeking = new HashSet<string>(StringComparer.Ordinal) { "disputed", "fix_claimed" };

    private IMeasurementRunner? _measureRunner;
    private readonly ConcurrentDictionary<string, DerivationEntry> _derivations = new(StringComparer.Ordinal);

    /// <summary>P3.4C-5 Increment 3: enable the custodian's measurements (a checks operation's start and executions, the
    /// derivation section, a spend's re-measurement). Without it every protected checks operation is refused and no
    /// derivation is served (fail closed).</summary>
    internal void AttachMeasurement(IMeasurementRunner runner) => _measureRunner = runner;

    /// <summary>The runtime a measurement runs under; refuses (actionable, fail closed) without the helper or a usable
    /// runtime approval. Callers hold <see cref="Gate"/>.</summary>
    private EngineRuntimeRecord RequireMeasureReady()
    {
        if (_measureRunner is null || _captureHelper is null)
            throw new CustodianRefusal(ErrorCodes.HelperUnavailable, $"the custodian measures a protected run's source and checks through its helper, which is not installed or not enabled; nothing was begun — the operator installs it ({OperatorWording.InstallHelper}) and restarts the custodian");
        return RequireCaptureReady();
    }

    // ---- the revision vector (§5.1 step 1, §5.2) ----

    /// <summary>The revisions a derivation depends on: the run's revision and evidence epoch, the loop's revision, the
    /// repository's configuration revision, the global configuration revision and the user-record log's revision. Any
    /// intervening transition changes one of them (the derivation is then stale). Callers hold <see cref="Gate"/>.</summary>
    private JsonObject RevisionVector(string repoKey, string runId)
    {
        RunRecord? run = ReadRun(repoKey, runId);
        LoopRecord? loop = Read().Loops!.FirstOrDefault(l => l.RepoKey == repoKey && l.RunId == runId);
        ConfigRecordsFile cfg = ReadConfigRecords();
        return new JsonObject
        {
            ["runRevision"] = run?.RunRevision, ["loopRevision"] = loop?.LoopRevision, ["evidenceEpoch"] = run?.EvidenceEpoch,
            ["configRevision"] = cfg.CurrentOf(repoKey)?.ConfigRevision, ["globalRevision"] = cfg.GlobalRevision,
            ["userRevision"] = ReadUserLog(repoKey, runId)?.Revision ?? 0,
        };
    }

    // ---- the snapshot (§5.1 step 1, §A.5) ----

    /// <summary>
    /// §A.5: the custodian's held records of the run, SCRUBBED to what the protected derivation consumes — identities,
    /// statuses and digests (the user records in their implementer projection: no raw note or amendment text; the
    /// responses without text, their cited locations as comparison keys), the configuration the trusted evaluation reads,
    /// the run's own floor (from run.json bytes verified against the declaration), and the executables the session claimed.
    /// No content key or other secret, no recorder or OS facts, no event log. Callers hold <see cref="Gate"/>.
    /// </summary>
    private JsonObject DerivationSnapshot(RepoIdentity id, RunRecord run, JsonNode? runFloor)
    {
        LoopRecord? loop = Read().Loops!.FirstOrDefault(l => l.RepoKey == run.RepoKey && l.RunId == run.RunId);
        UserRecordLog? users = ReadUserLog(run.RepoKey, run.RunId);
        ConfigRecordsFile cfg = ReadConfigRecords();
        static JsonNode? S(JsonNode? v) => v?.DeepClone();
        static JsonArray Strs(JsonNode? n) => new([.. (n as JsonArray ?? []).Select(x => (JsonNode?)(string?)x)]);
        var dispositions = run.Responses.ToDictionary(r => (string)r["responseId"]!, r => (string?)r["disposition"], StringComparer.Ordinal);
        var executables = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (RunOperation o in run.Operations.Where(o => o.Kind == "checks"))
            foreach (JsonObject p in (o.Begin["planned"] as JsonArray ?? []).OfType<JsonObject>())
                if ((string?)p["executable"] is { } exe) executables[(string)p["check"]!] = exe;

        JsonObject? Presented(RunReview r)
        {
            if (r.Outcome?["presented"] is not JsonObject p) return null;
            var deliveries = new JsonArray();
            if (p["discussion"]?["deliveries"] is JsonArray ds)
                foreach (JsonObject d in ds.OfType<JsonObject>())
                    deliveries.Add(new JsonObject { ["responseId"] = S(d["responseId"]), ["itemId"] = S(d["itemId"]), ["replySought"] = S(d["replySought"]), ["basis"] = Strs(d["basis"]) });
            else
                // A review recorded before the presentation carried its deliveries: each delivered response was presented
                // for a reply exactly when its disposition seeks one (the discussion's own rule).
                foreach (JsonObject d in (p["discussion"]?["delivered"] as JsonArray ?? []).OfType<JsonObject>())
                    foreach (string rid in (d["responseIds"] as JsonArray ?? []).Select(x => (string)x!))
                        deliveries.Add(new JsonObject { ["responseId"] = rid, ["itemId"] = S(d["itemId"]), ["replySought"] = ReplySeeking.Contains(dispositions.GetValueOrDefault(rid) ?? ""), ["basis"] = new JsonArray() });
            return new JsonObject
            {
                ["deliveries"] = deliveries,
                ["amendments"] = new JsonArray([.. (p["amendments"]?["presented"] as JsonArray ?? []).OfType<JsonObject>().Select(a => (JsonNode?)(string?)a["amendmentId"])]),
                ["withheld"] = Strs(p["amendments"]?["withheld"]),
            };
        }

        JsonObject? Bindings(RunReview r)
        {
            JsonObject b = r.Begin;
            string[] hex = ["sourceId", "reviewInputId", "checkEvidenceDigest", "manifestDigest", "exportDigest", "captureDigest"];
            if (hex.Any(k => (string?)b[k] is not { Length: 64 }) || b["captureStable"] is not JsonValue || b["checkExecutionIds"] is not JsonArray) return null;
            return new JsonObject
            {
                ["sourceId"] = S(b["sourceId"]), ["reviewInputId"] = S(b["reviewInputId"]), ["checkEvidenceDigest"] = S(b["checkEvidenceDigest"]),
                ["checkResultsDigest"] = S(b["checkResultsDigest"]), ["checkExecutionIds"] = Strs(b["checkExecutionIds"]), ["captureStable"] = S(b["captureStable"]),
                ["manifestDigest"] = S(b["manifestDigest"]), ["exportDigest"] = S(b["exportDigest"]), ["captureDigest"] = S(b["captureDigest"]),
            };
        }

        JsonObject? repository = cfg.CurrentOf(run.RepoKey) is null ? null : (ConfigSection(run.RepoKey, operatorView: false)["repository"] as JsonObject)?.DeepClone() as JsonObject;
        return new JsonObject
        {
            ["schema"] = "arl.derivation-snapshot.v2",
            ["repositoryRoot"] = id.CanonicalPath,
            ["revision"] = RevisionVector(run.RepoKey, run.RunId),
            ["run"] = new JsonObject
            {
                ["status"] = run.Status,
                ["evidenceEpoch"] = run.EvidenceEpoch,
                ["used"] = new JsonObject { ["reviews"] = run.Reviews.Count, ["checkExecutions"] = NonSkippedExecutions(run) },
                ["limits"] = new JsonObject { ["maxReviews"] = ReviewLimit(run), ["maxCheckExecutions"] = CheckExecutionLimit(run) },
                ["operations"] = new JsonArray([.. run.Operations.Select(o => (JsonNode)new JsonObject
                {
                    ["operationId"] = o.OperationId, ["kind"] = o.Kind, ["status"] = SnapshotOperationStatus(o, _clock()), ["beganAt"] = o.BeganAt, ["endedAt"] = o.EndedAt,
                    ["planned"] = new JsonArray([.. (o.Kind == "checks" ? (o.Begin["planned"] as JsonArray ?? []) : []).OfType<JsonObject>().Select(p => (JsonNode?)(string?)p["check"])]),
                })]),
                ["checkExecutions"] = new JsonArray([.. run.CheckExecutions.Select(e => (JsonNode)new JsonObject
                {
                    ["executionId"] = S(e["executionId"]), ["operationId"] = S(e["operationId"]), ["check"] = S(e["check"]), ["status"] = S(e["status"]),
                    ["exitCode"] = S(e["exitCode"]), ["timedOut"] = S(e["timedOut"]), ["cancelled"] = S(e["cancelled"]), ["durationMs"] = S(e["durationMs"]),
                    ["definitionDigest"] = S(e["definitionDigest"]), ["checkSpecId"] = S(e["checkSpecId"]), ["envDigest"] = S(e["envDigest"]),
                    ["freshnessDigest"] = S(e["freshnessDigest"]), ["executionInputId"] = S(e["executionInputId"]),
                    ["sourceIdAtStart"] = S(e["sourceIdAtStart"]), ["sourceIdAtEnd"] = S(e["sourceIdAtEnd"]), ["sourceStable"] = S(e["sourceStable"]),
                    ["evidenceEpoch"] = S(e["evidenceEpoch"]) ?? run.EvidenceEpoch,
                })]),
                ["reviews"] = new JsonArray([.. run.Reviews.Select(r => (JsonNode)new JsonObject
                {
                    ["reviewId"] = r.ReviewId, ["operationId"] = r.OperationId, ["round"] = r.Round, ["accepted"] = r.Accepted,
                    ["notAcceptedReasons"] = new JsonArray([.. r.NotAcceptedReasons.Select(x => (JsonNode)x)]), ["evidenceEpoch"] = r.EvidenceEpoch,
                    ["status"] = S(r.Outcome?["status"]), ["verdict"] = S(r.Outcome?["verdict"]),
                    ["basisUsable"] = ReviewBasisProblem(cfg, run.RepoKey, run.Operations.FirstOrDefault(o => o.OperationId == r.OperationId)?.Pin) is null,
                    ["isolationMode"] = S(r.Begin["isolation"]?["mode"]),
                    ["bindings"] = Bindings(r),
                    ["exportIntact"] = r.Begin["custodianCapture"] is JsonObject && (bool?)r.Outcome?["exportRehash"]?["unchanged"] == true,
                    ["itemIds"] = new JsonArray([.. r.ItemIds.Select(x => (JsonNode)x)]),
                    ["presented"] = Presented(r),
                })]),
                ["items"] = new JsonArray([.. run.Items.Select(i => (JsonNode)new JsonObject
                {
                    ["itemId"] = i.ItemId, ["reviewId"] = i.ReviewId, ["round"] = i.Round, ["sourceId"] = i.SourceId, ["itemKind"] = i.ItemKind, ["status"] = i.Status,
                    ["triage"] = i.Triage, ["severity"] = i.Severity, ["claimType"] = i.ClaimType, ["category"] = i.Category, ["confidence"] = i.Confidence,
                    ["impacts"] = new JsonArray([.. i.Impacts.Select(x => (JsonNode)x)]), ["relatedPriorId"] = i.RelatedPriorId, ["relatedFindingId"] = i.RelatedFindingId,
                    ["supersedes"] = new JsonArray([.. i.Supersedes.Select(x => (JsonNode)x)]), ["supersededBy"] = i.SupersededBy,
                    ["restates"] = new JsonArray([.. i.Restates.Select(x => (JsonNode)x)]),
                    ["assessments"] = new JsonArray([.. i.Assessments.Select(a => (JsonNode)new JsonObject
                    {
                        ["reviewId"] = a.ReviewId, ["round"] = a.Round, ["sourceId"] = a.SourceId, ["assessment"] = a.Assessment, ["effect"] = a.Effect,
                    })]),
                })]),
                ["responses"] = new JsonArray([.. run.Responses.Select(r => (JsonNode)new JsonObject
                {
                    ["responseId"] = S(r["responseId"]), ["responseSetId"] = S(r["responseSetId"]), ["itemId"] = S(r["itemId"]), ["disposition"] = S(r["disposition"]),
                    ["textWithheld"] = S(r["textWithheld"]),
                    ["answers"] = new JsonObject
                    {
                        ["reviewId"] = S(r["answers"]?["reviewId"]), ["round"] = S(r["answers"]?["round"]), ["runReviewId"] = S(r["answers"]?["runReviewId"]),
                        ["runRound"] = S(r["answers"]?["runRound"]), ["reviewerReplyId"] = S(r["answers"]?["reviewerReplyId"]),
                    },
                    ["sourceId"] = S(r["sourceId"]), ["supersedes"] = S(r["supersedes"]), ["threadId"] = S(r["threadId"]),
                    ["referenceKeys"] = Strs(r["referenceKeys"]),
                    // A response recorded before the presence was held: its rationale is taken as present (a required one always is).
                    ["rationalePresent"] = (bool?)r["rationalePresent"] ?? true,
                })]),
                ["replies"] = new JsonArray([.. run.Replies.Select(r => (JsonNode)new JsonObject
                {
                    ["replyId"] = S(r["replyId"]), ["reviewId"] = S(r["reviewId"]), ["round"] = S(r["round"]), ["itemId"] = S(r["itemId"]), ["stance"] = S(r["stance"]),
                    ["newInformation"] = S(r["newInformation"]), ["answersResponseId"] = S(r["answersResponseId"]), ["assessment"] = S(r["assessment"]),
                })]),
                ["incidents"] = new JsonArray([.. run.Incidents.Select(i => (JsonNode)new JsonObject
                {
                    ["incidentId"] = i.IncidentId, ["kind"] = i.Kind, ["reviewId"] = i.ReviewId, ["operationId"] = i.OperationId,
                })]),
            },
            ["loop"] = loop is null ? null : new JsonObject { ["status"] = loop.Status, ["startedAt"] = loop.StartedAt, ["resumedAt"] = loop.ResumedAt },
            ["user"] = new JsonObject
            {
                ["governed"] = users is not null, ["revision"] = users?.Revision ?? 0, ["recoveredAtRevision"] = users?.RecoveredAtRevision,
                ["records"] = new JsonArray([.. (users?.Records ?? []).Select(e => (JsonNode)ImplementerProjection(e))]),
            },
            ["config"] = new JsonObject { ["globalRevision"] = cfg.GlobalRevision, ["repository"] = repository, ["acceptances"] = new JsonArray(), ["selftestConfirmations"] = new JsonArray() },
            ["runFloor"] = runFloor?.DeepClone(),
            ["executables"] = new JsonObject([.. executables.Select(kv => new KeyValuePair<string, JsonNode?>(kv.Key, kv.Value))]),
        };
    }

    /// <summary>The checks a derivation measures (§5.1 step 2): every check the repository's configuration holds and every
    /// check the run executed, each with its held definition and the executable the session last claimed for it. A check
    /// without a held definition (removed) is not measured. Callers hold <see cref="Gate"/>.</summary>
    private static JsonArray DerivationChecks(RunRecord run, RepositoryConfig? cfg, JsonObject executables)
    {
        var names = new SortedSet<string>(StringComparer.Ordinal);
        if (cfg is not null) foreach (string n in cfg.Checks.Keys) names.Add(n);
        foreach (JsonObject e in run.CheckExecutions) if ((string?)e["check"] is { } c) names.Add(c);
        var arr = new JsonArray();
        foreach (string n in names)
            if (cfg is not null && cfg.Checks.TryGetValue(n, out ConfigCheck? c))
                arr.Add(new JsonObject { ["name"] = n, ["definition"] = c.Definition.DeepClone(), ["definitionDigest"] = c.DefinitionDigest, ["executable"] = (string?)executables[n] });
        return arr;
    }

    private static JsonObject RulesJson(ConfigCaptureRules r) => new()
    {
        ["exclude_globs"] = new JsonArray([.. r.ExcludeGlobs.Select(g => (JsonNode)g)]),
        ["context_include"] = new JsonArray([.. r.ContextInclude.Select(g => (JsonNode)g)]),
        ["max_file_bytes"] = r.MaxFileBytes, ["max_export_bytes"] = r.MaxExportBytes, ["max_diff_bytes"] = r.MaxDiffBytes,
    };

    /// <summary>Run one measurement outside the lock (§2.4): the custodian's read-only per-request directory, the runner,
    /// the directory removed again. A failure is an outcome, never an exception.</summary>
    private MeasureOutcome Measure(EngineRuntimeRecord runtime, RepoIdentity repo, JsonObject workload, CancellationToken ct)
    {
        if (Monitor.IsEntered(Gate)) throw new InvalidOperationException("the ledger lock is held across a helper invocation"); // §2.4
        string cfgDir;
        try { cfgDir = TicketDirs.Create("msr-" + HelperBroker.NewToken()[..20] + ".cfg", _captureHelper!); }
        catch (Exception e) when (e is CustodianRefusal or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return MeasureOutcome.Failed(ErrorCodes.HelperUnavailable, Bounded(e.Message));
        }
        try
        {
            MeasureOutcome o = _measureRunner!.RunAsync(new MeasureLaunch(runtime, repo, cfgDir, workload, TimeSpan.FromSeconds(CustodianConstants.HelperRequestSeconds)), ct).GetAwaiter().GetResult();
            if (!o.Ok) return o;
            string? problem = MeasuredProblem(o.Measured, workload["checks"] as JsonArray ?? []);
            return problem is null ? o : MeasureOutcome.Failed(ErrorCodes.MeasurementFailed, problem);
        }
        catch (Exception e) { return MeasureOutcome.Failed(ct.IsCancellationRequested ? ErrorCodes.MeasurementCancelled : ErrorCodes.MeasurementFailed, $"{e.GetType().Name}: {Bounded(e.Message)}"); }
        finally { TicketDirs.Remove(cfgDir); }
    }

    /// <summary>A measurement as the custodian accepts it: a source id, its stability, the root commit, and exactly one entry
    /// per requested check (digests well formed). Null when acceptable.</summary>
    private static string? MeasuredProblem(JsonObject? m, JsonArray requested)
    {
        static bool Hex(JsonNode? v) => v is JsonValue j && j.TryGetValue(out string? s) && s is { Length: 64 } && s.All(char.IsAsciiHexDigitLower);
        static bool HexOrNull(JsonNode? v) => v is null || Hex(v);
        if (m is null || !Hex(m["sourceId"]) || m["stable"] is not JsonValue st || !st.TryGetValue(out bool _) || m["checks"] is not JsonArray checks) return "a malformed measurement";
        if (m["rootCommit"] is not null && (m["rootCommit"] is not JsonValue rc || !rc.TryGetValue(out string? _))) return "a malformed root commit";
        var want = requested.OfType<JsonObject>().Select(c => (string)c["name"]!).ToList();
        var got = checks.OfType<JsonObject>().Select(c => (string?)c["name"]).ToList();
        if (got.Count != want.Count || !got.SequenceEqual(want)) return "the measurement does not cover exactly the requested checks";
        foreach (JsonObject c in checks.OfType<JsonObject>())
            if (!HexOrNull(c["freshnessDigest"]) || !HexOrNull(c["checkSpecId"])) return $"a malformed measurement of check {(string?)c["name"]}";
        return null;
    }

    /// <summary>
    /// Phase 5 F-i2-5: the reviewer-visible redaction of a protected amendment's text, produced by the custodian (the
    /// operator cannot read the working tree). Its helper runs the engine's own redaction (engine/host-view.ts, the
    /// accepted Windows workflow's rules) over the run's whole redaction basis — every capture and disclosure record the
    /// run binds, as the custodian holds them (GrantLedger.Evidence.cs) — together with a fresh, stable read of the
    /// repository under the held capture rules, local paths scrubbed; the custodian holds the result the operator
    /// confirms, and the read's disclosure record (what it withheld) for the run's later redactions. Outside the lock (§2.4). Refuses (fail closed) without a usable helper, runtime or configuration, without
    /// the complete basis, on an unstable read, or when the text would still disclose a withheld name.
    /// </summary>
    private (string Redacted, string SourceId, string BasisDigest, string ReadDisclosure) RedactForReview(RepoIdentity id, string runId, string text)
    {
        EngineRuntimeRecord runtime;
        JsonObject rules;
        lock (EnterGate())
        {
            runtime = RequireMeasureReady();
            RequireRepositoryReadable(id);
            rules = RulesJson(RequireUsableConfig(id.Key, "a protected amendment's redaction").CaptureRules);
        }
        (JsonArray evidence, string basisDigest) = RedactionBasisOf(id, runId);
        var workload = new JsonObject
        {
            ["rules"] = rules, ["checks"] = new JsonArray(), ["snapshot"] = null,
            ["redact"] = new JsonObject { ["text"] = text, ["keepRoots"] = new JsonArray(id.CanonicalPath), ["evidence"] = evidence },
        };
        MeasureOutcome o = Measure(runtime, id, workload, CancellationToken.None);
        if (!o.Ok) throw new CustodianRefusal(o.Code ?? ErrorCodes.MeasurementFailed, $"the custodian could not read the repository to redact the amendment text ({Bounded(o.Detail ?? "")}); nothing was prepared");
        JsonObject r = o.Redaction ?? throw new CustodianRefusal(ErrorCodes.RedactionRefused, "the helper produced no redaction; nothing was prepared");
        if ((bool?)r["ok"] != true)
            throw new CustodianRefusal(ErrorCodes.RedactionRefused, $"the amendment text cannot be made reviewer-visible ({Bounded((string?)r["error"] ?? "no reason given")}); nothing was prepared");
        if (o.Measured?["stable"] is not JsonValue st || !st.TryGetValue(out bool stable) || !stable || (string?)r["sourceId"] != (string?)o.Measured!["sourceId"])
            throw new CustodianRefusal(ErrorCodes.RedactionRefused, "the working tree changed while it was being read, so the redaction is not established; nothing was prepared — try again when the worktree is free");
        string redacted = (string)r["redacted"]!;
        if (redacted.Length > CustodianConstants.MaxAmendmentTextChars * 2) throw new CustodianRefusal(ErrorCodes.RedactionRefused, "the redaction is unexpectedly long; nothing was prepared");
        // Phase 5 OI-1: what this read withheld (the helper's disclosure record of it), held as evidence for the run's
        // later redactions; without it the amendment is refused.
        if (r["disclosure"] is not JsonValue dv || !dv.TryGetValue(out string? readDisclosure) || readDisclosure.Length == 0)
            throw new CustodianRefusal(ErrorCodes.RedactionRefused, "the helper did not report what its read withheld, so later redactions could not cover it; nothing was prepared");
        return (redacted, (string)r["sourceId"]!, basisDigest, readDisclosure);
    }

    /// <summary>The comparison digest of a measurement (N5-17: a spend's re-measurement must equal the derivation's).</summary>
    private static string MeasuredDigest(JsonObject measured) => EngineJson.Digest(measured);

    // ---- the derivation section (§5.1) ----

    /// <summary>
    /// P3.4C-5 Increment 3 (§5.1): the <c>derivation</c> section of <c>list_user_records</c>, on both surfaces. Under the
    /// gate the custodian takes its snapshot (the held run, loop, user and configuration records, the run's own floor from
    /// run.json bytes it verifies against its declaration digest, and the revision vector); outside the gate its helper
    /// measures the source and the checks' inputs and runs the engine's pure derivation over the snapshot; the result is
    /// cached under a fresh <c>derivationId</c> (in memory; never authority by itself). A run, helper, runtime or run.json
    /// that is not usable yields <c>available:false</c> with the reason — every automation decision then fails closed.
    /// </summary>
    internal JsonObject DerivationSection(string repositoryRoot, string runId, string? runJsonBase64)
    {
        LastDerivationSnapshotForTest = null;
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        EngineRuntimeRecord runtime;
        JsonObject workload;
        DateTime at;
        try
        {
            if (runJsonBase64 is null) throw new CustodianRefusal(ErrorCodes.InvalidArgument, "the derivation needs the run's run.json (runJson, base64): the custodian verifies it against the declaration it holds and reads the run's own floor from it");
            byte[] runJson;
            try { runJson = Convert.FromBase64String(runJsonBase64); }
            catch (FormatException) { throw new CustodianRefusal(ErrorCodes.InvalidArgument, "runJson must be base64"); }
            if (runJson.Length > 256 * 1024) throw new CustodianRefusal(ErrorCodes.InvalidArgument, "runJson is larger than 256 KiB");
            lock (EnterGate())
            {
                RunRecord run = ReadRun(id.Key, runId) ?? throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run; there is no protected derivation");
                if (Convert.ToHexStringLower(SHA256.HashData(runJson)) != run.Declaration.RunJsonDigest)
                    throw new CustodianRefusal(ErrorCodes.RunJsonMismatch, "run.json differs from the one the run was opened with (the custodian's declaration digest); nothing is derived");
                JsonNode? runFloor;
                try { runFloor = (JsonNode.Parse(runJson) as JsonObject ?? throw new FormatException())["verification_floor"]; }
                catch (Exception e) when (e is FormatException or System.Text.Json.JsonException) { throw new CustodianRefusal(ErrorCodes.RunJsonMismatch, "run.json is not a JSON object"); }
                runtime = RequireMeasureReady();
                RequireRepositoryReadable(id);
                RepositoryConfig cfg = RequireUsableConfig(id.Key, "a protected derivation");
                JsonObject snapshot = DerivationSnapshot(id, run, runFloor is JsonObject ? runFloor : null);
                LastDerivationSnapshotForTest = (JsonObject)snapshot.DeepClone();
                workload = new JsonObject
                {
                    ["rules"] = RulesJson(cfg.CaptureRules),
                    ["checks"] = DerivationChecks(run, cfg, snapshot["executables"]!.AsObject()),
                    ["snapshot"] = snapshot,
                };
                at = _clock();
            }
        }
        catch (CustodianRefusal r) { return Unavailable(r.Code, r.Message); }

        MeasureOutcome o = Measure(runtime, id, workload, CancellationToken.None);
        if (!o.Ok) return Unavailable(o.Code ?? ErrorCodes.MeasurementFailed, o.Detail ?? "");
        JsonObject d = o.Derivation ?? new JsonObject();
        if ((string?)d["route"]?["kind"] is not { } kind || (string?)d["route"]?["code"] is not { } code || (string?)d["progressFingerprint"] is not { Length: 64 } fingerprint
            || (string?)d["inputDigest"] is not { Length: 64 } inputDigest || (string?)d["completion"]?["state"] is null)
            return Unavailable(ErrorCodes.MeasurementFailed, "the helper returned no well-formed derivation");
        JsonObject snapshotRevision = workload["snapshot"]!["revision"]!.AsObject();
        string derivationId = "der-" + HelperBroker.NewToken()[..24];
        var section = new JsonObject
        {
            ["available"] = true,
            ["authority"] = "custodian",
            ["derivationId"] = derivationId,
            ["at"] = Iso(at),
            ["ttlSeconds"] = (int)DerivationTtl.TotalSeconds,
            ["revision"] = snapshotRevision.DeepClone(),
            ["completion"] = d["completion"]!.DeepClone(),
            ["route"] = d["route"]!.DeepClone(),
            ["floor"] = d["floor"]?.DeepClone(),
            ["currentSourceId"] = d["currentSourceId"]?.DeepClone(),
            ["inputDigest"] = inputDigest,
            ["progressFingerprint"] = fingerprint,
            ["measured"] = o.Measured!.DeepClone(),
        };
        var measureWorkload = new JsonObject { ["rules"] = workload["rules"]!.DeepClone(), ["checks"] = workload["checks"]!.DeepClone(), ["snapshot"] = null };
        PruneDerivations(at);
        _derivations[derivationId] = new DerivationEntry(derivationId, id.Key, runId, at, (JsonObject)snapshotRevision.DeepClone(), kind, code, fingerprint, inputDigest,
            MeasuredDigest(o.Measured!), measureWorkload, id, (JsonObject)section.DeepClone());
        Audit($"derivation runId={runId} derivationId={derivationId} route={code} ({kind}) completion={(string?)d["completion"]!["state"]} fingerprint={fingerprint[..16]}");
        return section;
    }

    private static JsonObject Unavailable(string code, string detail) => new() { ["available"] = false, ["authority"] = "custodian", ["code"] = code, ["detail"] = Bounded(detail) };

    private void PruneDerivations(DateTime now)
    {
        foreach (KeyValuePair<string, DerivationEntry> kv in _derivations)
            if (now - kv.Value.At > DerivationTtl + DerivationTtl) _derivations.TryRemove(kv.Key, out _);
        if (_derivations.Count >= MaxCachedDerivations)
            foreach (string oldest in _derivations.Values.OrderBy(d => d.At).Take(_derivations.Count - MaxCachedDerivations + 1).Select(d => d.DerivationId).ToList())
                _derivations.TryRemove(oldest, out _);
    }

    // ---- enforcement (§5.2, N5-17) ----

    /// <summary>
    /// §5.2: the derivation a continuation or wake names must be CURRENT — the custodian's own (in its cache, for this run),
    /// fresher than the TTL, of the current revision vector (any intervening transition makes it stale); otherwise
    /// <c>DERIVATION_STALE</c>. Its route and progress are judged only once it is known current, re-measurement included
    /// (<see cref="RequireRouteAndProgress"/>): a stale derivation is derived again, never refused on its route or progress.
    /// Callers hold <see cref="Gate"/>.
    /// </summary>
    private DerivationEntry RequireCurrentDerivation(string repoKey, LoopRequest req, DateTime now)
    {
        if (req.DerivationId is null)
            throw new CustodianRefusal(ErrorCodes.DerivationStale, "no custodian derivation is named: read the run's derivation section (list_user_records, sections [derivation]) and name its derivationId");
        if (!_derivations.TryGetValue(req.DerivationId, out DerivationEntry? d) || d.RepoKey != repoKey || d.RunId != req.RunId)
            throw new CustodianRefusal(ErrorCodes.DerivationStale, "the custodian holds no such derivation of this run (it may have expired, or the custodian restarted); derive again");
        if (now - d.At > DerivationTtl)
            throw new CustodianRefusal(ErrorCodes.DerivationStale, $"the derivation is older than {(int)DerivationTtl.TotalSeconds} s; derive again");
        if (!JsonNode.DeepEquals(d.Revision, RevisionVector(repoKey, req.RunId)))
            throw new CustodianRefusal(ErrorCodes.DerivationStale, "a custodian record of the run changed since the derivation (run, loop, configuration or user records); derive again");
        return d;
    }

    /// <summary>§5.2, after the derivation is known current: an implementer-step route, and a progress fingerprint different
    /// from the one the loop's previous continuation or wake was spent on. Refused <c>ROUTE_NOT_IMPLEMENTER_STEP</c> or
    /// <c>NO_PROGRESS</c>. A <c>ready</c> run's route ends the loop: it never authorizes anything.</summary>
    private static void RequireRouteAndProgress(DerivationEntry d, LoopRecord loop)
    {
        if (d.RouteKind != "implementer_step")
            throw new CustodianRefusal(ErrorCodes.RouteNotImplementerStep, $"the custodian's derivation routes {d.RouteCode} ({d.RouteKind}), not an implementer step: nothing is spent; the loop pauses or ends as the route says");
        if (loop.Progress?.Fingerprint == d.Fingerprint)
            throw new CustodianRefusal(ErrorCodes.NoProgress, $"no work fact changed since the loop's previous {loop.Progress.Kind.Replace('_', ' ')} (the same progress fingerprint): nothing is spent; the loop pauses (no_progress)");
    }

    /// <summary>N5-17 (TD binding requirement 1), outside the gate: the source and the checks' inputs the derivation measured,
    /// measured again. Null when the measurement did not succeed (the spend is then refused stale).</summary>
    private JsonObject? Remeasure(DerivationEntry d, EngineRuntimeRecord runtime)
    {
        MeasureOutcome o = Measure(runtime, d.Repo, (JsonObject)d.Workload.DeepClone(), CancellationToken.None);
        if (!o.Ok)
        {
            Audit($"derivation_remeasure_failed runId={d.RunId} derivationId={d.DerivationId} code={o.Code}");
            return null;
        }
        return o.Measured;
    }

    /// <summary>The re-measurement must equal the derivation's measurement (N5-17); otherwise DERIVATION_STALE.</summary>
    private static void RequireSameMeasurement(DerivationEntry d, JsonObject? measured)
    {
        if (measured is null)
            throw new CustodianRefusal(ErrorCodes.DerivationStale, "the custodian could not measure the source and the checks' inputs again before granting it; derive again");
        if (MeasuredDigest(measured) != d.MeasuredDigest)
            throw new CustodianRefusal(ErrorCodes.DerivationStale, "the working tree or a check's inputs changed since the derivation (the custodian's re-measurement differs); derive again");
    }

    /// <summary>SELF-TEST ONLY: the cached derivation (null when absent).</summary>
    internal DerivationEntry? DerivationForTest(string derivationId) => _derivations.GetValueOrDefault(derivationId);

    /// <summary>SELF-TEST: the snapshot the last derivation section built (null when it built none) — the corpus's N5-5
    /// parity oracle compares it with the simulated custodian's.</summary>
    internal JsonObject? LastDerivationSnapshotForTest { get; private set; }
}
