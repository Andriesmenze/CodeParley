using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// P3.4C-5 Increment 4 (contract §3.2 retention; TD disposition of F-2-2): the custodian's own lifecycle of published
/// exports. A captured review's export is <b>retired</b> — the record says when and why, the directory is removed — when
/// its run ends (<c>run_ended</c>), when it is no longer among the run's latest <see cref="CustodianConstants.MaxPublishedExportsPerRun"/>
/// captures (<c>retention_count</c>), or when it is older than <see cref="CustodianConstants.ExportRetention"/>
/// (<c>retention_age</c>). Exports of failed, cancelled, interrupted or deduplicated captures are removed at their commit;
/// abandoned staging and configuration directories, and anything no held capture references, are swept at every start and
/// whenever a run is opened. Deletion happens outside the ledger gate. The export ACLs are unchanged (no new access for
/// anybody); retention does not depend on <c>uninstall-helper</c>. Retiring an export changes no derivation input: the
/// derivation reads the integrity the custodian recorded at <c>op_finish</c>, not the directory.
/// </summary>
internal sealed partial class GrantLedger
{
    // ---- P3.4C-5 Increment 4 (§2.3, §6, N5-8): the helper's narrow read grant on the repository ----

    /// <summary>The group the helper reads repositories through (<c>CodeParley Repository Readers</c>), when a helper is
    /// installed; null: no check (no helper, nothing is measured).</summary>
    private Principal? _repositoryReaders;
    private string _repositoryReadersName = CustodianConstants.RepositoryReadersGroup;

    internal void AttachRepositoryReaders(Principal readers, string? name = null)
    {
        _repositoryReaders = readers;
        _repositoryReadersName = name ?? CustodianConstants.RepositoryReadersGroup;
    }

    /// <summary>
    /// Is the repository readable by the helper's group — an allow ACE for it on the repository root granting read and
    /// list, inherited by files and folders? Otherwise <c>REPOSITORY_NOT_READABLE</c> with the operator's exact remedy: an
    /// <c>icacls</c> grant on the repository directory alone (it adds no ACE on any parent or on the user profile). Read
    /// before the helper is asked anything, so the failure names its cause instead of a measurement failure.
    /// </summary>
    private void RequireRepositoryReadable(RepoIdentity id)
    {
        if (_repositoryReaders is null) return;
        if (Platform.Access.RepositoryReadersProblem(id.CanonicalPath, _repositoryReaders) is { } problem)
            throw new CustodianRefusal(ErrorCodes.RepositoryNotReadable,
                $"the repository {id.CanonicalPath} is not readable by '{_repositoryReadersName}' ({problem}); nothing was begun — {Platform.Access.RepositoryReadersRemedy(id.CanonicalPath, _repositoryReaders)}");
    }

    /// <summary>Ticket directories retired under the gate, removed once it is released (<see cref="DrainRetiredExports"/>).</summary>
    private readonly ConcurrentQueue<string> _retired = new();

    internal const string RetiredRunEnded = "run_ended", RetiredCount = "retention_count", RetiredAge = "retention_age";

    /// <summary>
    /// The run with every published export the retention rules no longer keep marked retired (<c>custodianCapture.retiredAt</c>,
    /// <c>retiredReason</c>, on the review and its operation), and their directories queued for removal. A terminal run
    /// keeps none but a review still in flight; a live run keeps its latest <see cref="CustodianConstants.MaxPublishedExportsPerRun"/> captures younger than
    /// <see cref="CustodianConstants.ExportRetention"/>. Returns the same instance when nothing changes. Callers hold
    /// <see cref="Gate"/>.
    /// </summary>
    private RunRecord RetireExports(RunRecord run, DateTime now)
    {
        List<RunReview> live = [.. run.Reviews.Where(r => r.Begin["custodianCapture"] is JsonObject c && c["retiredAt"] is null)];
        if (live.Count == 0) return run;
        var keep = new HashSet<string>(StringComparer.Ordinal);
        // A review still in flight (captured, not finished) keeps its export even on an ended run: its op_finish re-hashes
        // it; it is retired once the operation ends.
        foreach (RunReview r in live)
            if (run.Operations.FirstOrDefault(o => o.OperationId == r.OperationId)?.Status == RunOperationStatuses.Captured) keep.Add(r.ReviewId);
        if (!run.IsTerminal)
            foreach (RunReview r in live.TakeLast(CustodianConstants.MaxPublishedExportsPerRun))
                if (!Expired(r, now)) keep.Add(r.ReviewId);
        // Phase 4 Increment 2 (§3.2 retention): a fix in flight, or a proposal not yet retired, keeps its baseline export.
        foreach (string id in FixBaselinesHeld(run)) keep.Add(id);
        var retired = new Dictionary<string, string>(StringComparer.Ordinal); // operationId → reason
        foreach (RunReview r in live)
            if (!keep.Contains(r.ReviewId)) retired[r.OperationId] = run.IsTerminal ? RetiredRunEnded : Expired(r, now) ? RetiredAge : RetiredCount;
        if (retired.Count == 0) return run;
        JsonObject Mark(JsonObject begin, string reason)
        {
            var b = (JsonObject)begin.DeepClone();
            var c = (JsonObject)b["custodianCapture"]!;
            c["retiredAt"] = Iso(now);
            c["retiredReason"] = reason;
            return b;
        }
        foreach (RunReview r in live.Where(r => retired.ContainsKey(r.OperationId)))
            if ((string?)r.Begin["custodianCapture"]?["exportPath"] is { } p && Path.GetDirectoryName(p) is { } dir) _retired.Enqueue(dir);
        return run with
        {
            Reviews = [.. run.Reviews.Select(r => retired.TryGetValue(r.OperationId, out string? why) ? r with { Begin = Mark(r.Begin, why) } : r)],
            Operations = [.. run.Operations.Select(o => retired.TryGetValue(o.OperationId, out string? why) && o.Begin["custodianCapture"] is JsonObject ? o with { Begin = Mark(o.Begin, why) } : o)],
        };
    }

    private static bool Expired(RunReview r, DateTime now) =>
        (string?)r.Begin["custodianCapture"]?["capturedAt"] is { } at && DateTime.TryParse(at, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime t)
        && now - t.ToUniversalTime() > CustodianConstants.ExportRetention;

    /// <summary>Remove the ticket directories retired under the gate. Called only OUTSIDE the gate; a directory that cannot
    /// be removed now is no longer referenced and is swept at the next start or run opening.</summary>
    internal void DrainRetiredExports()
    {
        if (Monitor.IsEntered(Gate)) throw new InvalidOperationException("retired exports are removed outside the ledger lock");
        while (_retired.TryDequeue(out string? dir))
        {
            TicketDirs.Remove(dir);
            Audit($"export_removed dir={Path.GetFileName(dir)} (retired)");
        }
        DrainRetiredProposals(); // Phase 4 Increment 2
    }

    /// <summary>
    /// The full retention sweep (at every start, after the N5-18 reconciliation, and whenever a run is opened): every held
    /// run's exports are retired by the rules above (a custodian event, <c>export_retire</c>, on each run that changes), then —
    /// outside the gate — every directory under the export root that no held, unretired capture references and no measurement
    /// in progress owns (staging, configuration directories, leftovers of failed or deduplicated captures, orphans) is
    /// removed. Returns the number of exports retired and of directories removed.
    /// </summary>
    internal (int Retired, int Removed, int ProposalsRemoved) SweepExports()
    {
        int retiredCount = 0, proposalsRemoved = 0;
        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var heldProposals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        lock (EnterGate())
        {
            if (Directory.Exists(StorePaths.RunsDir))
                foreach (string file in Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                {
                    RunRecord run = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new InvalidDataException($"a run record is unreadable ({Path.GetFileName(file)})");
                    DateTime now = _clock();
                    // Phase 4 Increment 2: proposals past their lifetime are retired first (their baseline is then released).
                    RunRecord next = RetireExports(RetireFixProposals(run, now), now);
                    if (!ReferenceEquals(next, run))
                    {
                        int n = next.Reviews.Count(r => r.Begin["custodianCapture"]?["retiredAt"] is not null) - run.Reviews.Count(r => r.Begin["custodianCapture"]?["retiredAt"] is not null);
                        int proposals = RetiredProposals(next) - RetiredProposals(run);
                        retiredCount += n;
                        var retireResult = new JsonObject { ["retired"] = n };
                        if (proposals > 0) retireResult["proposalsRetired"] = proposals;
                        next = CustodianEvent(next, run, "export_retire", "retention-" + HelperBroker.NewToken()[..12], retireResult, now);
                        WriteRun(next);
                        Audit($"export_retire runId={run.RunId} retired={n} rev={next.RunRevision}");
                    }
                    foreach (RunReview r in next.Reviews)
                        if (r.Begin["custodianCapture"] is JsonObject c && c["retiredAt"] is null && (string?)c["exportPath"] is { } p)
                            referenced.Add(Path.GetFullPath(Path.GetDirectoryName(p)!));
                    foreach (string f in ReferencedProposals(next)) heldProposals.Add(f);
                }
            // Phase 4 Increment 2: proposal content no held run references (a crash between its two writes) is removed.
            proposalsRemoved = SweepOrphanProposals(heldProposals);
        }
        DrainRetiredExports();
        int removed = 0;
        if (Directory.Exists(StorePaths.ExportsRoot))
            foreach (string dir in Directory.EnumerateDirectories(StorePaths.ExportsRoot))
                if (!referenced.Contains(Path.GetFullPath(dir)) && !TicketDirs.IsLive(dir))
                {
                    TicketDirs.Remove(dir);
                    removed++;
                }
        if (removed > 0) Audit($"export_sweep removed={removed}");
        return (retiredCount, removed, proposalsRemoved);
    }
}
