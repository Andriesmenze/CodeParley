using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>One reserved measurement of a protected checks operation (§4): its start (<c>op_begin</c>) or the end of one
/// execution (<c>record_execution</c>) — its ticket, the operation, the repository identity the reservation validated,
/// the runtime record and the <c>derive</c> workload (the planned checks; no snapshot). In memory only.</summary>
internal sealed record CheckTicket(string Ticket, string Kind, string RepoKey, string RunId, string OperationId, RepoIdentity Repo, EngineRuntimeRecord Runtime, JsonObject Workload, DateTime ReservedAt);

internal sealed partial class GrantLedger
{
    internal const string CheckStart = "start", CheckEnd = "end";

    /// <summary>The identities an execution claim carries that the custodian measures or computes itself (§4, N5-2):
    /// ignored as claims, replaced by the custodian's values, a difference audited.</summary>
    internal static readonly IReadOnlyList<string> MeasuredExecutionKeys = ["sourceIdAtStart", "sourceIdAtEnd", "sourceStable", "freshnessDigest", "checkSpecId", "executionInputId"];

    private readonly ConcurrentDictionary<string, CheckTicket> _manualChecks = new(StringComparer.Ordinal);

    /// <summary>The measurement workload of a checks operation: the capture rules (for the source identity) and every
    /// planned check that will run, with the definition the operator approved and the executable the session claimed.</summary>
    private static JsonObject CheckWorkload(RepositoryConfig cfg, JsonObject begin)
    {
        var checks = new JsonArray();
        foreach (JsonObject p in (begin["planned"] as JsonArray ?? []).OfType<JsonObject>().OrderBy(p => (string)p["check"]!, StringComparer.Ordinal))
        {
            if ((string?)p["definitionDigest"] is null) continue; // recorded only as skipped
            string name = (string)p["check"]!;
            if (!cfg.Checks.TryGetValue(name, out ConfigCheck? c)) continue;
            checks.Add(new JsonObject { ["name"] = name, ["definition"] = c.Definition.DeepClone(), ["definitionDigest"] = c.DefinitionDigest, ["executable"] = (string?)p["executable"] });
        }
        return new JsonObject { ["rules"] = RulesJson(cfg.CaptureRules), ["checks"] = checks, ["snapshot"] = null };
    }

    /// <summary>Start a reserved check measurement (called once the reservation is written, inside the hold; the
    /// measurement itself runs outside it, §2.4).</summary>
    private void StartCheckMeasurement(CheckTicket t)
    {
        var cts = new CancellationTokenSource();
        _captureCancels[t.Ticket] = cts;
        if (_manualCapture)
        {
            _manualChecks[t.Ticket] = t;
            return;
        }
        _ = Task.Run(() => MeasureCheckAndCommit(t, cts.Token));
    }

    /// <summary>SELF-TEST ONLY (manual mode): run the check measurement reserved for <paramref name="operationId"/> now, to
    /// its commit. Returns false when none is waiting.</summary>
    internal bool RunReservedCheckMeasurement(string operationId)
    {
        CheckTicket? t = _manualChecks.Values.FirstOrDefault(x => x.OperationId == operationId);
        if (t is null || !_manualChecks.TryRemove(t.Ticket, out _)) return false;
        CancellationToken ct = _captureCancels.TryGetValue(t.Ticket, out CancellationTokenSource? cts) ? cts.Token : CancellationToken.None;
        MeasureCheckAndCommit(t, ct);
        return true;
    }

    /// <summary>The measurement (outside the lock), then its commit (under it).</summary>
    private void MeasureCheckAndCommit(CheckTicket t, CancellationToken ct)
    {
        MeasureOutcome o = ct.IsCancellationRequested ? MeasureOutcome.Failed(ErrorCodes.MeasurementCancelled, "the measurement was cancelled") : Measure(t.Runtime, t.Repo, t.Workload, ct);
        try
        {
            if (t.Kind == CheckStart) CommitCheckStart(t, o);
            else CommitCheckEnd(t, o);
        }
        catch (Exception e)
        {
            Audit($"check_measure_commit_failed ticket={t.Ticket} runId={t.RunId} operationId={t.OperationId} error={e.GetType().Name}: {Bounded(e.Message)}");
        }
        if (_captureCancels.TryRemove(t.Ticket, out CancellationTokenSource? cts)) cts.Dispose();
    }

    private static string MeasurementReason(string? code) => code switch
    {
        ErrorCodes.MeasurementTimeout => "measurement_timeout",
        ErrorCodes.MeasurementCancelled => "cancelled",
        ErrorCodes.ConfigMismatch => "runtime_changed",
        ErrorCodes.HelperUnavailable => "helper_unavailable",
        _ => "measurement_failed",
    };

    /// <summary>
    /// §2.4 revalidation of a checks operation's START: the repository's protected configuration must still be in force,
    /// not lapsed, and still approve every definition the operation planned — otherwise a revocation or change committed
    /// while the custodian measured ends the operation <c>basis_changed</c> and no check runs. (An execution's END is not
    /// revalidated: the check ran under the pinned basis, and whether it counts is decided at derivation — P3.4C-4.)
    /// Callers hold <see cref="Gate"/>.
    /// </summary>
    private static string? CheckBasisProblem(ConfigRecordsFile file, string repoKey, RunOperation op)
    {
        RepositoryConfig? cur = file.CurrentOf(repoKey);
        if (cur is null || cur.IsRevoked) return "the repository's protected configuration was revoked while the custodian measured; no check ran";
        if (cur.IsLapsed) return "the repository's protected configuration lapsed while the custodian measured; no check ran";
        foreach (JsonNode? p in op.Begin["planned"]?.AsArray() ?? [])
            if ((string?)p?["definitionDigest"] is { } digest && (!cur.Checks.TryGetValue((string)p!["check"]!, out ConfigCheck? c) || c.DefinitionDigest != digest))
                return $"check {(string)p!["check"]!} is no longer approved with the definition the operation planned (the configuration changed while the custodian measured); no check ran";
        return null;
    }

    /// <summary>The measurement as recorded: what the helper measured, with its ticket and time.</summary>
    private static JsonObject MeasurementRecord(JsonObject measured, string ticket, DateTime at)
    {
        var m = (JsonObject)measured.DeepClone();
        m["ticket"] = ticket;
        m["at"] = Iso(at);
        return m;
    }

    /// <summary>
    /// The commit of a checks operation's START measurement (§4, §2.4 step 3), under the gate: the ticket must still be the
    /// operation's and the operation <c>measuring</c>; the run not ended; the writer alive. Measured: the operation runs,
    /// with the custodian's measurement of the source and every planned check's inputs as its start (the first execution's
    /// start). Otherwise the operation ends (<c>error</c>, <c>cancelled</c> or <c>interrupted</c>) and the run is idle.
    /// </summary>
    private void CommitCheckStart(CheckTicket t, MeasureOutcome o)
    {
        lock (EnterGate())
        {
            RunRecord? run = ReadRun(t.RepoKey, t.RunId);
            RunOperation? op = run?.Operations.FirstOrDefault(x => x.OperationId == t.OperationId);
            if (run is null || op is null || op.Status != RunOperationStatuses.Measuring || op.Ticket != t.Ticket)
            {
                Audit($"check_measure_refused ticket={t.Ticket} runId={t.RunId} operationId={t.OperationId} (the operation is no longer measuring under this ticket; nothing was recorded)");
                return;
            }
            DateTime now = _clock();
            string status;
            string? reason = null, detail = null;
            if (run.IsTerminal) (status, reason, detail) = (RunOperationStatuses.Cancelled, "run_ended", $"the run ended ({run.Status}) while the custodian measured");
            else if (!o.Ok) (status, reason, detail) = (o.Code == ErrorCodes.MeasurementCancelled ? RunOperationStatuses.Cancelled : RunOperationStatuses.Error, MeasurementReason(o.Code), $"{o.Code}: {Bounded(o.Detail)}");
            else if (ProcessIdentityCheck.IsGone(op.Writer.Pid, op.Writer.StartedAtMs, _processes) == true)
                (status, reason, detail) = (RunOperationStatuses.Interrupted, "owner_died", "the operation's writer ended while the custodian measured");
            else if (CheckBasisProblem(ReadConfigRecords(), run.RepoKey, op) is { } problem) (status, reason, detail) = (RunOperationStatuses.Error, "basis_changed", problem);
            else status = RunOperationStatuses.Running;

            var result = new JsonObject { ["operationId"] = op.OperationId, ["ticket"] = t.Ticket, ["operationStatus"] = status, ["measurement"] = CheckStart };
            RunRecord next;
            if (status == RunOperationStatuses.Running)
            {
                JsonObject m = MeasurementRecord(o.Measured!, t.Ticket, now);
                var begin = (JsonObject)op.Begin.DeepClone();
                begin["custodianMeasurement"] = m.DeepClone();
                next = run with { Operations = ReplaceOperation(run, op with { Status = RunOperationStatuses.Running, Begin = begin, Measured = m }) };
                result["sourceId"] = m["sourceId"]?.DeepClone();
                result["stable"] = m["stable"]?.DeepClone();
            }
            else
            {
                next = EndMeasurement(run, op, status, reason!, detail, now);
                result["reason"] = reason;
            }
            next = CustodianEvent(next, run, "check_measure", t.Ticket, result, now);
            RequireProjectionWithinCap(next);
            WriteRun(next);
            Audit($"check_measure runId={run.RunId} operationId={op.OperationId} ticket={t.Ticket} start -> {status}{(reason is null ? "" : $" ({reason})")} rev={next.RunRevision}");
        }
    }

    /// <summary>
    /// The commit of an execution's END measurement (§4), under the gate: the ticket must still be the operation's pending
    /// execution. The execution is recorded with the custodian's own start (its latest measurement before the execution)
    /// and end source ids, the stability of both, the freshness-input digest and check-spec id it measured at the start,
    /// and the execution input id computed from them and the CLAIMED environment digest (D5-E). A failed end measurement
    /// records the execution without an end (it never counts as fresh: fail closed) and says why. The claimed values of
    /// those identities are ignored; a difference is audited (N5-2). The end measurement is the next execution's start.
    /// </summary>
    private void CommitCheckEnd(CheckTicket t, MeasureOutcome o)
    {
        lock (EnterGate())
        {
            RunRecord? run = ReadRun(t.RepoKey, t.RunId);
            RunOperation? op = run?.Operations.FirstOrDefault(x => x.OperationId == t.OperationId);
            if (run is null || op?.Pending is not { } pending || (string?)pending["ticket"] != t.Ticket)
            {
                Audit($"check_measure_refused ticket={t.Ticket} runId={t.RunId} operationId={t.OperationId} (no execution of this operation is pending under this ticket; nothing was recorded)");
                return;
            }
            DateTime now = _clock();
            if (run.IsTerminal)
            {
                Audit($"check_measure_dropped ticket={t.Ticket} runId={t.RunId} operationId={t.OperationId} (the run ended while the custodian measured; nothing was recorded)");
                return;
            }
            JsonObject? end = o.Ok ? MeasurementRecord(o.Measured!, t.Ticket, now) : null;
            (JsonObject stored, List<string> mismatched) = MeasuredExecution(run, op, pending["execution"]!.AsObject(), op.Measured, end, o.Ok ? null : $"{MeasurementReason(o.Code)}: {Bounded(o.Detail)}", t.Ticket, now);
            RunOperation done = op with { Pending = null, Measured = end ?? op.Measured };
            RunRecord next = run with { CheckExecutions = [.. run.CheckExecutions, stored], Operations = ReplaceOperation(run, done) };
            var result = new JsonObject
            {
                ["operationId"] = op.OperationId, ["ticket"] = t.Ticket, ["measurement"] = CheckEnd, ["executionId"] = stored["executionId"]?.DeepClone(),
                ["measured"] = o.Ok, ["sourceStable"] = stored["sourceStable"]?.DeepClone(),
            };
            if (!o.Ok) result["reason"] = MeasurementReason(o.Code);
            if (mismatched.Count > 0) result["ignoredClaims"] = new JsonArray([.. mismatched.Select(k => (JsonNode)k)]);
            next = CustodianEvent(next, run, "check_record", t.Ticket, result, now);
            RequireProjectionWithinCap(next);
            WriteRun(next);
            if (mismatched.Count > 0) Audit($"record_execution_claims_ignored runId={run.RunId} operationId={op.OperationId} executionId={(string?)stored["executionId"]} keys={string.Join(',', mismatched)} (the custodian measures them itself)");
            Audit($"check_measure runId={run.RunId} operationId={op.OperationId} ticket={t.Ticket} end -> recorded {(string?)stored["executionId"]} measured={o.Ok} rev={next.RunRevision}");
        }
    }

    /// <summary>An execution as the custodian records it (§4): the validated claim with the identities it measures or
    /// computes itself in place of the claimed ones, and which of those claims differed.</summary>
    private static (JsonObject Stored, List<string> Mismatched) MeasuredExecution(RunRecord run, RunOperation op, JsonObject claim, JsonObject? start, JsonObject? end, string? failure, string? endTicket, DateTime now)
    {
        var s = (JsonObject)claim.DeepClone();
        string check = (string)s["check"]!;
        JsonObject? mc = (start?["checks"] as JsonArray ?? []).OfType<JsonObject>().FirstOrDefault(c => (string?)c["name"] == check);
        string? startSource = (string?)start?["sourceId"], endSource = (string?)end?["sourceId"];
        s["sourceIdAtStart"] = startSource;
        s["sourceIdAtEnd"] = endSource;
        s["sourceStable"] = start is not null && end is not null && (bool?)start["stable"] == true && (bool?)end["stable"] == true && startSource == endSource;
        string? freshness = (string?)mc?["freshnessDigest"], spec = (string?)mc?["checkSpecId"], env = (string?)claim["envDigest"];
        s["freshnessDigest"] = freshness;
        s["checkSpecId"] = spec;
        s["executionInputId"] = spec is not null && env is not null && freshness is not null
            ? EngineJson.Digest(new JsonObject { ["schema"] = "arl.execution-input-id.v1", ["check_spec_id"] = spec, ["env_digest"] = env, ["freshness_digest"] = freshness })
            : null;
        s["operationId"] = op.OperationId;
        s["evidenceEpoch"] = run.EvidenceEpoch;
        s["configRevision"] = op.Pin?.ConfigRevision;
        s["custodianMeasurement"] = new JsonObject
        {
            ["startTicket"] = (string?)start?["ticket"], ["endTicket"] = endTicket, ["measuredAt"] = Iso(now), ["endMeasured"] = end is not null, ["failure"] = failure,
        };
        if (failure is not null && s["limitations"] is JsonArray lim)
        {
            if (lim.Count >= 20) lim.RemoveAt(lim.Count - 1);
            lim.Add(new JsonObject { ["code"] = "custodian_end_measurement_failed", ["detail"] = $"the custodian could not measure the source after this execution ({failure}); it does not count as fresh" });
        }
        // Phase 6 Increment 3: the helper's own reason it measured no check-spec identity, surfaced (it was dropped before).
        if ((string?)mc?["problem"] is { } helperProblem && s["limitations"] is JsonArray hl)
        {
            if (hl.Count >= 20) hl.RemoveAt(hl.Count - 1);
            hl.Add(new JsonObject { ["code"] = $"helper_{helperProblem}", ["detail"] = HelperProblemDetail(helperProblem) });
        }
        var mismatched = MeasuredExecutionKeys.Where(k => !JsonNode.DeepEquals(claim[k], s[k])).ToList();
        return (s, mismatched);
    }

    /// <summary>What the helper's measurement problem means for the operator (src/helper/workloads.ts measureCheck).</summary>
    internal static string HelperProblemDetail(string problem) => problem switch
    {
        "executable_unresolvable" => "the custodian's helper could not resolve this check's executable to an absolute file it can read (it runs under its own account, without your PATH): name the executable by an absolute path outside your user profile, approve the checks again and set the configuration again; this execution does not count as fresh",
        "no_executable_claim" => "the check's executable was not resolved when it ran, so the helper had nothing to measure; this execution does not count as fresh",
        "definition_invalid" => "the helper refused the check definition the custodian holds; approve the checks again and set the configuration again; this execution does not count as fresh",
        _ => $"the helper measured no check-spec identity ({problem}); this execution does not count as fresh",
    };

    /// <summary>A skipped execution as the custodian records it: nothing ran, so nothing is measured — its source ids are the
    /// custodian's latest measurement, and it counts for nothing.</summary>
    private static JsonObject SkippedExecution(RunRecord run, RunOperation op, JsonObject claim)
    {
        var s = (JsonObject)claim.DeepClone();
        s["sourceIdAtStart"] = (string?)op.Measured?["sourceId"];
        s["sourceIdAtEnd"] = (string?)op.Measured?["sourceId"];
        s["sourceStable"] = false;
        s["freshnessDigest"] = null;
        s["checkSpecId"] = null;
        s["executionInputId"] = null;
        s["operationId"] = op.OperationId;
        s["evidenceEpoch"] = run.EvidenceEpoch;
        s["configRevision"] = op.Pin?.ConfigRevision;
        return s;
    }

    /// <summary>A pending execution whose end could not be measured because the operation ended (its writer gone) or the
    /// custodian restarted: recorded without an end (it counts for nothing as fresh). Returns the run with it recorded.</summary>
    private static RunRecord RecordUnmeasuredPending(RunRecord run, RunOperation op, string reason, DateTime now)
    {
        if (op.Pending is not { } pending) return run;
        (JsonObject stored, _) = MeasuredExecution(run, op, pending["execution"]!.AsObject(), op.Measured, null, reason, (string?)pending["ticket"], now);
        return run with
        {
            CheckExecutions = [.. run.CheckExecutions, stored],
            Operations = ReplaceOperation(run, op with { Pending = null }),
        };
    }
}
