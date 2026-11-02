using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>What a review capture is launched with: the approved runtime record (re-measured before the launch), the
/// repository the custodian validated, the custodian's read-only per-request directory, the workload and its deadline.</summary>
internal sealed record CaptureLaunch(EngineRuntimeRecord Runtime, RepoIdentity Repo, string CfgDir, JsonObject Workload, TimeSpan Timeout);

/// <summary>P3.4C-5 (§3.1 step 3): runs a review capture whose frames feed <paramref name="job"/>. The service's runner
/// re-measures the approved runtime and runs the capture workload through the helper service
/// (<see cref="HelperCaptureRunner"/>); the self-tests substitute a synthetic one. Everything else — the reservation, the
/// validation and publication of what arrives, the commit — is the ledger's, the same in both.</summary>
internal interface IReviewCaptureRunner
{
    Task<HelperJobOutcome> RunAsync(CaptureLaunch launch, CaptureJob job, CancellationToken ct);
}

/// <summary>The service's capture runner: the runtime the operator approved is measured again (outside the lock; a
/// difference refuses, never another computation), then the helper service runs the capture workload.</summary>
internal sealed class HelperCaptureRunner(HelperBroker broker) : IReviewCaptureRunner
{
    public async Task<HelperJobOutcome> RunAsync(CaptureLaunch l, CaptureJob job, CancellationToken ct)
    {
        MeasuredRuntime m;
        try { m = EngineRuntime.Measure(l.Runtime.Root, l.Runtime.GitRelative, l.Runtime.GitPath); }
        catch (CustodianRefusal e) { return new HelperJobOutcome(false, ErrorCodes.ConfigMismatch, e.Message, "", null); }
        List<string> diff = EngineRuntime.Differences(l.Runtime.Measured, m);
        if (diff.Count > 0)
            return new HelperJobOutcome(false, ErrorCodes.ConfigMismatch, $"the engine runtime differs from the one approved ({string.Join(", ", diff)}); the operator approves it again", "", null);
        JsonObject launch = GrantLedger.Launch(m, l.CfgDir, l.Repo, job.MaxFrameBody);
        return await broker.RunAsync("capture", new JsonObject { ["launch"] = launch, ["workload"] = l.Workload.DeepClone() }, job, l.Timeout, ct).ConfigureAwait(false);
    }
}

/// <summary>One reserved review capture: its ticket and the operation it belongs to, the repository identity the
/// reservation validated, the runtime record and capture rules it was reserved under, and the target. In memory only.</summary>
internal sealed record CaptureTicket(
    string Ticket, string RepoKey, string RunId, string OperationId, RepoIdentity Repo, EngineRuntimeRecord Runtime,
    JsonObject Target, ConfigCaptureRules Rules, DateTime ReservedAt);

/// <summary>How a measurement ended: captured (with the published capture), or not (a reason and a detail).</summary>
internal sealed record CaptureEnd(bool Captured, string? Reason, string? Detail, PublishedCapture? Capture)
{
    internal static CaptureEnd Failed(string reason, string? detail) => new(false, reason, detail, null);
}

/// <summary>A capture the custodian published: where (the ticket's directory, its <c>export</c> and its
/// <c>capture.json</c>) and what it measured.</summary>
internal sealed record PublishedCapture(
    string Dir, string ExportPath, string CapturePath, string SourceId, bool Stable, string CaptureId, string CaptureDigest,
    string ManifestDigest, string ManifestContentDigest, string ExportDigest, int FileCount, long TotalBytes);

/// <summary>The custodian's re-hash of a custodian-captured review's export, taken before the gate at <c>op_finish</c>.</summary>
internal sealed record ExportRehash(string OperationId, bool Unchanged, string Detail);

internal sealed partial class GrantLedger
{
    private IReviewCaptureRunner? _captureRunner;
    private Principal? _captureHelper;
    private Principal? _captureReader;
    private bool _manualCapture;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _captureCancels = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CaptureTicket> _manualTickets = new(StringComparer.Ordinal);

    /// <summary>
    /// P3.4C-5 (§3.1, §A.2): enable the custodian's review capture. <paramref name="helper"/> is the helper service's SID
    /// (it reads the ticket's staging while it captures, never after); <paramref name="reader"/> is the bound session's
    /// user — the implementer account — who reads the published export and nothing else. Without this, every protected
    /// review is refused (HELPER_UNAVAILABLE): a review is never begun on the engine's capture. <paramref name="manual"/>
    /// (self-tests only) runs a reserved capture only when the test asks (<see cref="RunReservedCapture"/>).
    /// </summary>
    internal void AttachCapture(IReviewCaptureRunner runner, Principal helper, Principal reader, bool manual = false)
    {
        _captureRunner = runner;
        _captureHelper = helper;
        _captureReader = reader;
        _manualCapture = manual;
    }

    /// <summary>SELF-TEST ONLY: replace the runner a manual capture uses (a corpus step's synthetic capture).</summary>
    internal void SetCaptureRunnerForTest(IReviewCaptureRunner runner) => _captureRunner = runner;

    /// <summary>The approved runtime a reservation runs under; refuses (actionable, fail closed) without the helper or
    /// without a usable runtime approval. Callers hold <see cref="Gate"/>.</summary>
    private EngineRuntimeRecord RequireCaptureReady()
    {
        if (_captureRunner is null || _captureHelper is null || _captureReader is null)
            throw new CustodianRefusal(ErrorCodes.HelperUnavailable, $"a protected review is captured by the custodian's helper, which is not installed or not enabled; nothing was begun — the operator installs it ({OperatorWording.InstallHelper}) and restarts the custodian");
        ConfigRecordsFile file = ReadConfigRecords();
        EngineRuntimeRecord rt = file.CurrentRuntime
            ?? throw new CustodianRefusal(ErrorCodes.RuntimeNotApproved, $"no engine runtime is approved for the custodian's helper; nothing was begun — the operator approves one with {OperatorWording.ApproveRuntime}");
        if (rt.RevokedAt is not null)
            throw new CustodianRefusal(ErrorCodes.RuntimeNotApproved, $"the approved engine runtime {rt.RuntimeId} was revoked; nothing was begun — the operator approves one again ({OperatorWording.ApproveRuntime})");
        if (rt.LapsedAtRecoveryId is not null)
            throw new CustodianRefusal(ErrorCodes.ConfigLapsed, $"the engine runtime approval lapsed after a restart of the OS (recovery {rt.LapsedAtRecoveryId}); nothing was begun — the operator re-confirms it (`{OperatorWording.Cli} config reconfirm-runtime --repo <path> {rt.RuntimeId}`, or `{OperatorWording.Cli} setup --resume --repo <path>`)");
        return rt;
    }

    /// <summary>Start a reserved capture (called once the reservation is written, inside the hold; the measurement itself
    /// runs outside it, §2.4).</summary>
    private void StartCapture(CaptureTicket t)
    {
        var cts = new CancellationTokenSource();
        _captureCancels[t.Ticket] = cts;
        if (_manualCapture)
        {
            _manualTickets[t.Ticket] = t;
            return;
        }
        _ = Task.Run(() => MeasureAndCommitAsync(t, cts.Token));
    }

    /// <summary>Cancel a capture in progress (the engine abandoned the review, its writer died, or the run ended). Its
    /// commit then ends the operation; a measurement that already ended is unaffected.</summary>
    private void CancelCapture(string? ticket)
    {
        if (ticket is not null && _captureCancels.TryGetValue(ticket, out CancellationTokenSource? cts))
        {
            try { cts.Cancel(); } catch (ObjectDisposedException) { /* already ended */ }
        }
    }

    /// <summary>SELF-TEST ONLY (manual capture): run the capture reserved for <paramref name="operationId"/> now, to its
    /// commit. Returns false when no reserved capture of that operation is waiting.</summary>
    internal bool RunReservedCapture(string operationId)
    {
        CaptureTicket? t = _manualTickets.Values.FirstOrDefault(x => x.OperationId == operationId);
        if (t is null || !_manualTickets.TryRemove(t.Ticket, out _)) return false;
        CancellationToken ct = _captureCancels.TryGetValue(t.Ticket, out CancellationTokenSource? cts) ? cts.Token : CancellationToken.None;
        MeasureAndCommitAsync(t, ct).GetAwaiter().GetResult();
        return true;
    }

    /// <summary>
    /// The measurement of one reserved review (§2.4 step 2, §3.2), outside the lock: the custodian creates the ticket's
    /// staging (the helper may read it while it captures) and its read-only configuration directory; the runner streams
    /// the capture into the staging (every file validated and written by the custodian, <see cref="CaptureJob"/>); the
    /// custodian validates the manifest against what it wrote, computes the export digest itself and seals the export (the
    /// helper loses its access), writes the capture record, gives the bound session's user read-only access to the whole
    /// ticket directory, renames it to its published name and hashes everything again. Then the commit (§2.4 step 3).
    /// </summary>
    private async Task MeasureAndCommitAsync(CaptureTicket t, CancellationToken ct)
    {
        if (Monitor.IsEntered(Gate)) throw new InvalidOperationException("the ledger lock is held across a helper invocation"); // §2.4
        string root = StorePaths.ExportsRoot;
        string staging = Path.Combine(root, t.Ticket + ".staging"), cfgDir = Path.Combine(root, t.Ticket + ".cfg"), final = Path.Combine(root, t.Ticket);
        CaptureEnd end;
        try
        {
            end = await MeasureAsync(t, staging, cfgDir, final, ct).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            end = CaptureEnd.Failed(ct.IsCancellationRequested ? "cancelled" : "measurement_failed", $"{e.GetType().Name}: {Bounded(e.Message)}");
        }
        finally
        {
            TicketDirs.Remove(cfgDir);
        }
        bool keep;
        try { keep = CommitCapture(t, end); }
        catch (Exception e)
        {
            Audit($"capture_commit_failed ticket={t.Ticket} runId={t.RunId} operationId={t.OperationId} error={e.GetType().Name}: {Bounded(e.Message)}");
            keep = false;
        }
        if (!keep)
        {
            TicketDirs.Remove(staging);
            TicketDirs.Remove(final);
        }
        // Committed (its record references it) or removed: the measurement no longer owns its directories.
        TicketDirs.Release(staging);
        TicketDirs.Release(final);
        DrainRetiredExports(); // the exports this capture's commit retired (§3.2 retention)
        if (_captureCancels.TryRemove(t.Ticket, out CancellationTokenSource? cts)) cts.Dispose();
    }

    private async Task<CaptureEnd> MeasureAsync(CaptureTicket t, string staging, string cfgDir, string final, CancellationToken ct)
    {
        Principal helper = _captureHelper!, reader = _captureReader!;
        TicketDirs.Create(Path.GetFileName(staging), helper);
        TicketDirs.Create(Path.GetFileName(cfgDir), helper);
        var job = new CaptureJob(Path.Combine(staging, "export"), t.Rules);
        var rules = new JsonObject
        {
            ["exclude_globs"] = new JsonArray([.. t.Rules.ExcludeGlobs.Select(g => (JsonNode)g)]),
            ["context_include"] = new JsonArray([.. t.Rules.ContextInclude.Select(g => (JsonNode)g)]),
            ["max_file_bytes"] = t.Rules.MaxFileBytes, ["max_export_bytes"] = t.Rules.MaxExportBytes, ["max_diff_bytes"] = t.Rules.MaxDiffBytes,
        };
        var workload = new JsonObject { ["operationId"] = t.OperationId, ["target"] = t.Target.DeepClone(), ["rules"] = rules };
        HelperJobOutcome o = await _captureRunner!.RunAsync(new CaptureLaunch(t.Runtime, t.Repo, cfgDir, workload, TimeSpan.FromSeconds(CustodianConstants.HelperRequestSeconds)), job, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) return CaptureEnd.Failed("cancelled", "the capture was cancelled");
        if (!o.Ok)
        {
            string reason = o.Code switch
            {
                ErrorCodes.MeasurementTimeout => "measurement_timeout",
                ErrorCodes.MeasurementCancelled => "cancelled",
                ErrorCodes.ConfigMismatch => "runtime_changed",
                ErrorCodes.HelperUnavailable => "helper_unavailable",
                _ => "measurement_failed",
            };
            return CaptureEnd.Failed(reason, $"{o.Code}: {Bounded(o.Detail)}");
        }
        JsonObject published;
        try { published = job.Publish(helper); }
        catch (HelperFrameError e) { return CaptureEnd.Failed("measurement_failed", "publication refused: " + Bounded(e.Message)); }
        JsonObject record = job.Record!, manifest = job.Manifest!;
        byte[] recordBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record, IndentedJson));
        string captureDigest = Convert.ToHexStringLower(SHA256.HashData(recordBytes));
        // Phase 5 F-i2-5: the record is also held as redaction evidence, which outlives the export's retention — a name it
        // withheld stays withheld from an amendment the custodian redacts, even after the file is deleted.
        try { RetainEvidence(t.RepoKey, t.RunId, captureDigest, recordBytes); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return CaptureEnd.Failed("measurement_failed", "the capture record could not be held as redaction evidence: " + Bounded(e.Message));
        }
        using (var fs = new FileStream(Path.Combine(staging, "capture.json"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            fs.Write(recordBytes);
            fs.Flush(flushToDisk: true);
        }
        TicketDirs.Publish(staging, reader);
        TicketDirs.MarkLive(final);
        MoveWithRetry(staging, final);
        // Everything published is hashed again, from its published place.
        string exportDir = Path.Combine(final, "export");
        var reread = new List<(string, long, string)>();
        foreach (string f in Directory.EnumerateFiles(exportDir, "*", SearchOption.AllDirectories))
        {
            byte[] bytes = File.ReadAllBytes(f);
            reread.Add((Path.GetRelativePath(exportDir, f).Replace('\\', '/'), bytes.LongLength, Convert.ToHexStringLower(SHA256.HashData(bytes))));
        }
        string exportDigest = (string)published["exportDigest"]!;
        if (ExportPaths.ExportDigest(reread) != exportDigest) return CaptureEnd.Failed("measurement_failed", "the published export differs from what was validated");
        if (Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(final, "capture.json")))) != captureDigest)
            return CaptureEnd.Failed("measurement_failed", "the published capture record differs from what was written");
        string captureId = (string?)record["capture_id"] ?? (string?)manifest["capture_id"] ?? t.OperationId;
        return new CaptureEnd(true, null, null, new PublishedCapture(
            final, exportDir, Path.Combine(final, "capture.json"), (string)published["sourceId"]!, (bool)published["stable"]!, captureId, captureDigest,
            (string)published["manifestDigest"]!, ManifestContentDigest(manifest), exportDigest, (int)published["fileCount"]!, (long)published["totalBytes"]!));
    }

    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    /// <summary>A directory move fails while anything (an indexer, a scanner) still holds a file in it: retried, bounded.</summary>
    private static void MoveWithRetry(string from, string to)
    {
        for (int attempt = 1; ; attempt++)
        {
            try { Directory.Move(from, to); return; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException && attempt < 20) { Thread.Sleep(50 * attempt); }
        }
    }

    /// <summary>The engine's <c>manifestContentDigest</c>: the manifest without its capture id and own digest.</summary>
    internal static string ManifestContentDigest(JsonObject manifest)
    {
        var content = (JsonObject)manifest.DeepClone();
        content.Remove("capture_id");
        content.Remove("manifest_digest");
        return EngineJson.Digest(new JsonObject { ["digest_schema"] = "arl.manifest-content.v1", ["content"] = content });
    }

    /// <summary>
    /// The commit of a measurement (§2.4 step 3, §3.1 step 4), under the gate: the ticket must still be its operation's
    /// and the operation still <c>measuring</c>; the run not ended; the writer alive; the pinned basis usable; the capture
    /// stable and of the source the engine selected its evidence for. The custodian then computes the review input
    /// identity from its own capture, the held bindings and the claimed focus, depth, versions and isolation, and
    /// deduplicates on it. Captured: the measured identities become the review's (M), the operation <c>captured</c>.
    /// Otherwise the operation ends (<c>error</c>, <c>cancelled</c>, <c>interrupted</c> or <c>deduplicated</c>), the
    /// reserved budget is released and the export removed. Returns whether the published export is kept.
    /// </summary>
    private bool CommitCapture(CaptureTicket t, CaptureEnd end)
    {
        lock (EnterGate())
        {
            RunRecord? run = ReadRun(t.RepoKey, t.RunId);
            RunOperation? op = run?.Operations.FirstOrDefault(o => o.OperationId == t.OperationId);
            if (run is null || op is null || op.Status != RunOperationStatuses.Measuring || op.Ticket != t.Ticket)
            {
                Audit($"capture_result_refused ticket={t.Ticket} runId={t.RunId} operationId={t.OperationId} (the operation is no longer measuring under this ticket; nothing was recorded)");
                return false;
            }
            DateTime now = _clock();
            RunReview review = run.Reviews.Single(r => r.OperationId == op.OperationId);
            string status = RunOperationStatuses.Error;
            string? reason = null, detail = null;
            JsonObject? dedup = null;
            PublishedCapture? cap = end.Capture;
            string? reviewInputId = null;
            if (run.IsTerminal) (status, reason, detail) = (RunOperationStatuses.Cancelled, "run_ended", $"the run ended ({run.Status}) while the custodian captured");
            else if (!end.Captured) (status, reason, detail) = (end.Reason == "cancelled" ? RunOperationStatuses.Cancelled : RunOperationStatuses.Error, end.Reason, end.Detail);
            else if (ProcessIdentityCheck.IsGone(op.Writer.Pid, op.Writer.StartedAtMs, _processes) == true)
                (status, reason, detail) = (RunOperationStatuses.Interrupted, "owner_died", "the operation's writer ended while the custodian captured");
            else if (review.EvidenceEpoch != run.EvidenceEpoch) (reason, detail) = ("basis_changed", "the evidence epoch changed while the custodian captured");
            else if (ReviewBasisProblem(ReadConfigRecords(), run.RepoKey, op.Pin) is { } problem) (reason, detail) = ("basis_changed", problem);
            else if (!cap!.Stable) (reason, detail) = ("source_unstable", "the working tree changed during the capture (the two-pass stability check)");
            else if (cap.SourceId != (string)op.Begin["selectionSourceId"]!)
                (reason, detail) = ("source_changed", "the captured source is not the source the engine selected the check evidence and discussion for; begin the review again");
            else
            {
                reviewInputId = CustodianReviewInputId(op.Begin, cap);
                // §3.1 step 4 (deduplication, P3.4C-4 §4.3): an accepted review of the current evidence epoch with the same
                // inputs whose pinned basis is still usable. The operation ends deduplicated and the budget is released.
                ConfigRecordsFile held = ReadConfigRecords();
                RunReview? dup = run.Reviews.FirstOrDefault(r => r.Accepted == true && r.EvidenceEpoch == run.EvidenceEpoch && (string?)r.Begin["reviewInputId"] == reviewInputId
                    && ReviewBasisProblem(held, run.RepoKey, run.Operations.FirstOrDefault(o => o.OperationId == r.OperationId)?.Pin) is null);
                if (dup is not null)
                {
                    status = RunOperationStatuses.Deduplicated;
                    reason = "deduplicated";
                    detail = $"an accepted review of the same inputs ({dup.ReviewId}, round {dup.Round}) exists in this evidence epoch";
                    dedup = new JsonObject { ["deduplicatedOf"] = dup.ReviewId, ["round"] = dup.Round };
                }
                else status = RunOperationStatuses.Captured;
            }

            RunRecord next;
            var result = new JsonObject { ["operationId"] = op.OperationId, ["ticket"] = t.Ticket, ["operationStatus"] = status };
            if (status == RunOperationStatuses.Captured)
            {
                var begin = (JsonObject)op.Begin.DeepClone();
                begin["sourceId"] = cap!.SourceId;
                begin["captureId"] = cap.CaptureId;
                begin["captureStable"] = cap.Stable;
                begin["captureDigest"] = cap.CaptureDigest;
                begin["manifestDigest"] = cap.ManifestDigest;
                begin["exportDigest"] = cap.ExportDigest;
                begin["reviewInputId"] = reviewInputId;
                begin["custodianCapture"] = new JsonObject
                {
                    ["ticket"] = t.Ticket, ["exportPath"] = cap.ExportPath, ["capturePath"] = cap.CapturePath, ["manifestContentDigest"] = cap.ManifestContentDigest,
                    ["fileCount"] = cap.FileCount, ["totalBytes"] = cap.TotalBytes, ["capturedAt"] = Iso(now),
                };
                var incidents = new List<RunIncident>(run.Incidents);
                var incidentIds = new List<string>();
                if ((string?)begin["isolation"]?["mode"] == "S2" && incidents.Count < CustodianConstants.MaxIncidentsPerRun)
                {
                    var reduced = new RunIncident(NewId("inc", incidents.Count + 1), "isolation_reduced", op.OperationId, review.ReviewId,
                        "this review runs with reduced read isolation (S2)", Iso(now), "custodian");
                    incidents.Add(reduced);
                    incidentIds.Add(reduced.IncidentId);
                }
                RunOperation captured = op with { Status = RunOperationStatuses.Captured, Begin = (JsonObject)begin.DeepClone() };
                RunReview capturedReview = review with { Begin = begin, IncidentIds = [.. review.IncidentIds, .. incidentIds] };
                next = run with
                {
                    Operations = ReplaceOperation(run, captured),
                    Reviews = [.. run.Reviews.Select(r => r.ReviewId == review.ReviewId ? capturedReview : r)],
                    Incidents = incidents,
                };
                result["sourceId"] = cap.SourceId;
                result["reviewInputId"] = reviewInputId;
                result["exportDigest"] = cap.ExportDigest;
                // §3.2 retention: the new capture may push the run's oldest published export out (removed after the hold).
                RunRecord retained = RetireExports(next, now);
                if (!ReferenceEquals(retained, next)) result["exportsRetired"] = retained.Reviews.Count(r => r.Begin["custodianCapture"]?["retiredAt"] is not null) - next.Reviews.Count(r => r.Begin["custodianCapture"]?["retiredAt"] is not null);
                next = retained;
            }
            else
            {
                next = EndMeasurement(run, op, status, reason!, detail, now, extra: dedup);
                result["reason"] = reason;
                if (dedup is not null) foreach (KeyValuePair<string, JsonNode?> kv in dedup) result[kv.Key] = kv.Value?.DeepClone();
            }
            next = CustodianEvent(next, run, "capture", t.Ticket, result, now);
            RequireProjectionWithinCap(next);
            WriteRun(next);
            Audit($"capture_commit runId={run.RunId} operationId={op.OperationId} ticket={t.Ticket} -> {status}{(reason is null ? "" : $" ({reason})")} rev={next.RunRevision}");
            return status == RunOperationStatuses.Captured;
        }
    }

    /// <summary>A measuring operation that ends without a capture: its status and the reason in its outcome; its review
    /// is removed (the reserved budget is released — the review never began); the run is idle again unless it ended.
    /// With <paramref name="incident"/> the custodian also records <c>measurement_interrupted</c> (N5-18).</summary>
    private static RunRecord EndMeasurement(RunRecord run, RunOperation op, string status, string reason, string? detail, DateTime now, JsonObject? extra = null, bool incident = false)
    {
        var outcome = new JsonObject { ["status"] = status, ["reason"] = reason, ["detail"] = detail is null ? null : Bounded(detail) };
        if (extra is not null) foreach (KeyValuePair<string, JsonNode?> kv in extra) outcome[kv.Key] = kv.Value?.DeepClone();
        RunOperation ended = op with { Status = status, EndedAt = Iso(now), Outcome = outcome };
        var incidents = run.Incidents;
        if (incident && run.Incidents.Count < CustodianConstants.MaxIncidentsPerRun)
            incidents = [.. run.Incidents, new RunIncident(NewId("inc", run.Incidents.Count + 1), "measurement_interrupted", op.OperationId, null,
                detail is null ? "the custodian's measurement was interrupted" : Bounded(detail), Iso(now), "custodian")];
        return run with
        {
            Operations = ReplaceOperation(run, ended),
            Reviews = [.. run.Reviews.Where(r => r.OperationId != op.OperationId)],
            Incidents = incidents,
            Status = run.IsTerminal ? run.Status : RunStatuses.Idle,
        };
    }

    /// <summary>A transition the custodian made itself (a capture's commit, a start reconciliation): the run's revision
    /// rises and one evidence entry records it, under the ticket or reconciliation id, by <c>custodian</c>.</summary>
    private static RunRecord CustodianEvent(RunRecord next, RunRecord before, string kind, string requestId, JsonObject stepResult, DateTime now)
    {
        int revision = before.RunRevision + 1;
        var result = new JsonObject { ["runId"] = next.RunId, ["kind"] = kind, ["runRevision"] = revision, ["status"] = next.Status };
        foreach (KeyValuePair<string, JsonNode?> kv in stepResult) result[kv.Key] = kv.Value?.DeepClone();
        var evidence = new RunEvent(before.Events.Count + 1, kind, requestId, "custodian", null, Digest.Sha256Hex(Digest.Canonical(result)),
            before.Status, next.Status, Iso(now), (JsonObject)result.DeepClone());
        return next with { RunRevision = revision, Events = [.. before.Events, evidence] };
    }

    /// <summary>
    /// The custodian's review input identity (§3.1 step 4, C): computed from its own capture (the source and the manifest's
    /// content) and what the reservation bound — the target, the presented check executions with their digests, the
    /// discussion turns and amendments offered, the isolation and configuration identities — and the claimed focus, depth
    /// and versions. Order-insensitive in the sets.
    /// </summary>
    internal static string CustodianReviewInputId(JsonObject begin, PublishedCapture cap)
    {
        static JsonArray Sorted(JsonNode? a) => new([.. (a as JsonArray ?? []).Select(x => (string)x!).Order(StringComparer.Ordinal).Select(x => (JsonNode)x)]);
        var offered = new JsonArray([.. (begin["discussion"]?["offered"] as JsonArray ?? []).Cast<JsonObject>().OrderBy(d => (string)d["itemId"]!, StringComparer.Ordinal)
            .Select(d => (JsonNode)new JsonObject { ["itemId"] = (string)d["itemId"]!, ["responseIds"] = Sorted(d["responseIds"]), ["replyIds"] = Sorted(d["replyIds"]) })]);
        var amendments = new JsonArray([.. (begin["amendments"]?["offered"] as JsonArray ?? []).Cast<JsonObject>().OrderBy(a => (string)a["amendmentId"]!, StringComparer.Ordinal)
            .Select(a => (JsonNode)new JsonObject { ["amendmentId"] = (string)a["amendmentId"]!, ["disclosureDigest"] = (string?)a["disclosureDigest"] })]);
        return EngineJson.Digest(new JsonObject
        {
            ["schema"] = "arl.custodian-review-input.v1",
            ["sourceId"] = cap.SourceId,
            ["manifestContentDigest"] = cap.ManifestContentDigest,
            ["target"] = begin["target"]?.DeepClone(),
            ["checkExecutionIds"] = Sorted(begin["checkExecutionIds"]),
            ["checkEvidenceDigest"] = (string?)begin["checkEvidenceDigest"],
            ["checkResultsDigest"] = (string?)begin["checkResultsDigest"],
            ["discussionOffered"] = offered,
            ["amendmentsOffered"] = amendments,
            ["isolation"] = begin["isolation"]?.DeepClone(),
            ["captureRulesDigest"] = (string?)begin["captureRulesDigest"],
            ["codexSha256"] = (string?)begin["codexSha256"],
            ["depth"] = (string?)begin["depth"],
            ["focusDigest"] = (string?)begin["focusDigest"],
            ["versionsDigest"] = (string?)begin["versionsDigest"],
        });
    }

    /// <summary>§3.1 step 7: what a finished custodian-captured review presented must be what its reservation offered (a
    /// subset), and a completed review names its prompt digest and what it presented.</summary>
    private static void RequirePresented(RunReview review, string opStatus, string? promptDigest, JsonObject? presented)
    {
        if (opStatus == "completed" && (promptDigest is null || presented is null))
            throw new CustodianRefusal(ErrorCodes.InvalidArgument, "a completed review the custodian captured names its promptDigest and what it presented");
        if (presented is null) return;
        var offeredTurns = (review.Begin["discussion"]?["offered"] as JsonArray ?? []).Cast<JsonObject>().ToDictionary(d => (string)d["itemId"]!, StringComparer.Ordinal);
        foreach (JsonObject d in presented["discussion"]!["delivered"]!.AsArray().Cast<JsonObject>())
        {
            string itemId = (string)d["itemId"]!;
            if (!offeredTurns.TryGetValue(itemId, out JsonObject? o)) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"delivered item {itemId} was not offered by the review's reservation");
            foreach (string key in new[] { "responseIds", "replyIds" })
            {
                var allowed = o[key]!.AsArray().Select(x => (string)x!).ToHashSet(StringComparer.Ordinal);
                foreach (JsonNode? x in d[key]!.AsArray())
                    if (!allowed.Contains((string)x!)) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"delivered {key[..^3]} {(string)x!} on item {itemId} was not offered by the review's reservation");
            }
        }
        var offeredAmendments = (review.Begin["amendments"]?["offered"] as JsonArray ?? []).Cast<JsonObject>().ToDictionary(a => (string)a["amendmentId"]!, a => (string?)a["disclosureDigest"], StringComparer.Ordinal);
        foreach (JsonObject a in presented["amendments"]!["presented"]!.AsArray().Cast<JsonObject>())
            if (!offeredAmendments.TryGetValue((string)a["amendmentId"]!, out string? digest) || digest != (string?)a["disclosureDigest"])
                throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"presented amendment {(string)a["amendmentId"]!} was not offered by the review's reservation with that disclosure digest");
        foreach (JsonNode? w in presented["amendments"]!["withheld"]!.AsArray())
            if (!offeredAmendments.ContainsKey((string)w!)) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"withheld amendment {(string)w!} was not offered by the review's reservation");
    }

    /// <summary>
    /// §3.1 step 7, outside the gate: for the finish of a custodian-captured review, the export it published is hashed
    /// again from disk and compared with the export digest and capture digest it recorded. Null when the request is not
    /// the finish of a captured review (the transition decides everything else under the gate).
    /// </summary>
    private ExportRehash? RehashForFinish(string repoKey, RunRequest req)
    {
        string operationId = (string?)req.Fields["operationId"] ?? "";
        JsonObject? begin;
        lock (EnterGate())
        {
            RunOperation? op = ReadRun(repoKey, req.RunId)?.Operations.FirstOrDefault(o => o.OperationId == operationId);
            if (op is null || op.Status != RunOperationStatuses.Captured) return null;
            begin = (JsonObject)op.Begin.DeepClone();
        }
        if (Monitor.IsEntered(Gate)) throw new InvalidOperationException("the ledger lock is held across an export re-hash"); // §2.4
        return RehashExport(operationId, begin);
    }

    /// <summary>
    /// N5-18 (TD binding requirement 2), at EVERY start, before anything is served: every persisted <c>measuring</c>
    /// operation is interrupted (<c>measurement_interrupted</c>, an incident; its reserved budget released) — the
    /// measurement's ticket belonged to the previous service instance, so a late result is refused — and the export root
    /// is swept of every directory no held captured review references (staging, configuration directories, orphans).
    /// Returns the number of interrupted operations.
    /// </summary>
    internal int ReconcileCapturesAtStart()
    {
        int interrupted = 0;
        lock (EnterGate())
        {
            if (Directory.Exists(StorePaths.RunsDir))
            {
                foreach (string file in Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                {
                    RunRecord run = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new InvalidDataException($"a run record is unreadable ({Path.GetFileName(file)})");
                    RunRecord cur = run;
                    foreach (RunOperation op in run.Operations.Where(o => o.Pending is not null))
                    {
                        DateTime now = _clock();
                        RunRecord recorded = RecordUnmeasuredPending(cur, cur.Operations.First(o => o.OperationId == op.OperationId), "measurement_interrupted: the custodian restarted while it measured", now);
                        if (recorded.Incidents.Count < CustodianConstants.MaxIncidentsPerRun)
                            recorded = recorded with { Incidents = [.. recorded.Incidents, new RunIncident(NewId("inc", recorded.Incidents.Count + 1), "measurement_interrupted", op.OperationId, null,
                                "the custodian restarted while it measured the end of a check execution; it was recorded without its end", Iso(now), "custodian")] };
                        cur = CustodianEvent(recorded, cur, "reconcile", "reconcile-pending-" + op.OperationId, new JsonObject { ["operationId"] = op.OperationId, ["reason"] = "measurement_interrupted" }, now);
                        interrupted++;
                    }
                    foreach (RunOperation op in run.Operations.Where(o => o.Status == RunOperationStatuses.Measuring))
                    {
                        DateTime now = _clock();
                        RunRecord ended = EndMeasurement(cur, cur.Operations.First(o => o.OperationId == op.OperationId), RunOperationStatuses.Interrupted, "measurement_interrupted",
                            "the custodian restarted while it measured (the measurement's ticket belonged to the previous service instance)", now, incident: true);
                        cur = CustodianEvent(ended, cur, "reconcile", "reconcile-" + op.OperationId, new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = RunOperationStatuses.Interrupted, ["reason"] = "measurement_interrupted" }, now);
                        interrupted++;
                    }
                    if (!ReferenceEquals(cur, run))
                    {
                        WriteRun(cur);
                        Audit($"reconcile runId={cur.RunId}: measuring operations interrupted at start (N5-18) rev={cur.RunRevision}");
                    }
                }
            }
        }
        // P3.4C-5 Increment 4: the full retention sweep — exports the rules no longer keep are retired, and everything no held
        // capture references (staging, configuration directories, orphans) is removed (outside the gate).
        SweepExports();
        return interrupted;
    }

    private static string Bounded(string? s) => s is null ? "" : s.Length > 400 ? s[..400] : s;
}
