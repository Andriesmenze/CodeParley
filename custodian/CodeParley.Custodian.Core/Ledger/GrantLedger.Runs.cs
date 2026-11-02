using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// P3.4C-3: the custodian-owned run records (contract §2–§5) — one protected file per run, read and written only under
/// the ledger's single lock (<see cref="Gate"/>, §2.5) and replaced through the write-through path (§2.4). Every
/// <c>run_transition</c> is computed HERE from the stored records and the request's validated fields: a client never
/// replaces a record or sets a status, a revision, an operation id, a round, acceptance, an item's status or an
/// assessment's effect. Each applied transition bumps the run's own revision and appends evidence; requests are
/// idempotent on their request id (a replay returns the stored result).
/// </summary>
internal sealed partial class GrantLedger
{
    /// <summary>One kind's outcome: the next record, its kind-specific result, and work to do in the same hold
    /// after the run file is written (<c>end</c> derives the loop's end, §3.4(5)).</summary>
    private sealed record RunStep(RunRecord Next, JsonObject Result, Action? AfterWrite = null);

    /// <summary>The run's record, or null when the custodian holds none. Callers hold <see cref="Gate"/>.</summary>
    internal static RunRecord? ReadRun(string repoKey, string runId)
    {
        string path = StorePaths.RunPath(repoKey, runId);
        if (!File.Exists(path)) return null;
        return JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(path), Json)
            ?? throw new InvalidDataException("the run record is unreadable (fail closed)");
    }

    /// <summary>Persist one version of a run record (one atomic, write-through replacement). Callers hold
    /// <see cref="Gate"/>.</summary>
    internal static void WriteRun(RunRecord run) => AtomicWrite(StorePaths.RunPath(run.RepoKey, run.RunId), JsonSerializer.Serialize(run, Json));

    /// <summary>The run's record, read in a hold of the lock (for callers outside it: the self-tests).</summary>
    internal static RunRecord? ReadRunLocked(string repoKey, string runId)
    {
        lock (EnterGate()) return ReadRun(repoKey, runId);
    }

    /// <summary>The ledger file, read in a hold of the lock (for callers outside it: the self-tests).</summary>
    internal LedgerFile ReadLocked()
    {
        lock (EnterGate()) return Read();
    }

    /// <summary>Apply one <c>run_transition</c> for the run of the directory <paramref name="repositoryRoot"/> names
    /// (the custodian's own identity of it). Refusals are <see cref="CustodianRefusal"/>s; nothing is applied.</summary>
    internal JsonObject RunTransition(LoopCaller caller, string repositoryRoot, RunRequest req)
    {
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        // P3.4C-5 (§3.1 step 7): before the gate, a custodian-captured review's published export is hashed again.
        ExportRehash? rehash = req.Kind == RunKinds.OpFinish ? RehashForFinish(id.Key, req) : null;
        // Phase 4 Increment 2 (§3.2, §3.4): before the gate, a fix's baseline capture is read from the custodian's own export.
        FixBaselineRead? fixBaseline = req.Kind is RunKinds.OpBegin or RunKinds.OpFinish ? ReadFixBaseline(id.Key, req) : null;
        // Phase 4 Increment 3 (§3.6): before the gate, an application's confirmed content is read and the primary source measured.
        ApplyPre? applyPre = req.Kind is RunKinds.OpBegin or RunKinds.OpFinish or RunKinds.ApplyReconcile ? ReadForApply(id, req) : null;
        // Phase 5 (§4.12): before the gate, the host's Codex sandbox basis is measured again for a review or fix begin.
        IsolationBasisRead? basisNow = ReadIsolationBasis(id.Key, req);
        JsonObject result;
        lock (EnterGate())
        {
            result = ApplyRunTransition(caller, id, req, _clock(), rehash, fixBaseline, applyPre, basisNow);
        }
        DrainRetiredProposals();
        // P3.4C-5 Increment 4 (§3.2 retention), outside the gate: the exports a terminal transition retired are removed, and
        // opening a run sweeps the export root.
        DrainRetiredExports();
        if (req.Kind == RunKinds.Open && _captureHelper is not null) SweepExports();
        return result;
    }

    private JsonObject ApplyRunTransition(LoopCaller caller, RepoIdentity id, RunRequest req, DateTime now, ExportRehash? rehash, FixBaselineRead? fixBaseline = null, ApplyPre? applyPre = null, IsolationBasisRead? basisNow = null)
    {
        string repoKey = id.Key;
        AuthorizeRunKind(caller, req.Kind);
        RunRecord? run = ReadRun(repoKey, req.RunId);
        bool applyBegin = req.Kind == RunKinds.OpBegin && (string?)req.Fields["operationKind"] == "apply";
        if (run is not null && RunReplayOf(run, caller, req) is { } replayed)
        {
            // Phase 4 Increment 3: the confirmed content is never kept in the transition log; a replayed application begin is
            // answered with it again only while that application still runs.
            if (applyBegin && run.Operations.FirstOrDefault(o => o.OperationId == (string?)replayed["operationId"]) is { Status: RunOperationStatuses.Running })
                replayed["changes"] = ContentForResult(applyPre);
            return replayed;
        }
        if (req.Kind == RunKinds.Open) return OpenRun(caller, repoKey, run, req, now);
        if (run is null) throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run: it was never opened");
        if (run.Events.Count >= CustodianConstants.MaxRunEvents && req.Kind != RunKinds.End)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"the run's transition log is full ({CustodianConstants.MaxRunEvents}); only end is accepted");

        RunStep step = req.Kind switch
        {
            RunKinds.OpBegin => OpBeginStep(caller, run, req, now, id, fixBaseline, applyPre, basisNow),
            RunKinds.RecordExecution => RecordExecutionStep(caller, run, req, id, now),
            RunKinds.OpFinish => OpFinishStep(caller, run, req, now, rehash, fixBaseline, applyPre),
            RunKinds.Recover => RecoverStep(run, req, now),
            RunKinds.Respond => RespondStep(caller, run, req, now),
            RunKinds.End => EndStep(caller, run, req, now),
            RunKinds.ApplyReconcile => ApplyReconcileStep(run, req, now, applyPre),
            _ => throw new ArgumentException("unknown run transition kind"),
        };
        if (step.Result.TryGetPropertyValue("deduplicatedOf", out _)) return WithRunHeader(step.Result, run, req.Kind); // begins nothing
        // P3.4C-5 Increment 4 (§3.2 retention): an ended run retires every published export but a review's still in flight,
        // whose export goes once its operation ends (removed after the hold).
        if (step.Next.IsTerminal)
        {
            // Phase 4 Increment 2: an ended run retires its pending proposals (their content is removed after the hold).
            int proposalsBefore = RetiredProposals(step.Next);
            step = step with { Next = RetireFixProposals(step.Next, now) };
            if (RetiredProposals(step.Next) > proposalsBefore) step.Result["proposalsRetired"] = RetiredProposals(step.Next) - proposalsBefore;
            RunRecord retained = RetireExports(step.Next, now);
            if (!ReferenceEquals(retained, step.Next))
                step.Result["exportsRetired"] = retained.Reviews.Count(r => r.Begin["custodianCapture"]?["retiredAt"] is not null) - step.Next.Reviews.Count(r => r.Begin["custodianCapture"]?["retiredAt"] is not null);
            step = step with { Next = retained };
        }
        RunRecord next = RecordedRun(step.Next, run, caller, req, step.Result, now, out JsonObject result);
        RequireProjectionWithinCap(next);
        Hold(HoldPoints.RunApplied + req.Kind);
        WriteRun(next); // persisted BEFORE the result is returned
        if (req.Kind == RunKinds.End) Hold(HoldPoints.EndRunWritten);
        step.AfterWrite?.Invoke();
        Audit($"run_transition kind={req.Kind} runId={next.RunId} {run.Status}->{next.Status} rev={next.RunRevision} caller={caller.Name} requestId={req.RequestId}");
        if (applyBegin) result["changes"] = ContentForResult(applyPre); // returned, never stored in the run's log
        return result;
    }

    // ---- open ----

    /// <summary>Register the run (contract §3.2 <c>open</c>): only while the repository has an unexpired, unsuspended
    /// grant with a loop left — nothing is consumed — so a start refused for lack of a grant registers nothing.
    /// Idempotent on the declaration, whatever the request id; a terminal run is never re-opened; a changed
    /// declaration is RUN_DECLARATION_CONFLICT. From then on the run is protected for selection (§5.4).</summary>
    private JsonObject OpenRun(LoopCaller caller, string repoKey, RunRecord? run, RunRequest req, DateTime now)
    {
        RunDeclaration declaration = DeclarationOf(req.Fields);
        if (run is not null)
        {
            if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"run {run.RunId} has ended ({run.Status}); it is not re-opened");
            if (!SameDeclaration(run.Declaration, declaration))
                throw new CustodianRefusal(ErrorCodes.RunDeclarationConflict, $"run {run.RunId} was opened with another declaration (run.json, budgets or baseline); it cannot become protected with this one — a new run is needed");
            RequireUsableConfig(repoKey, "the start"); // P3.4C-4 (§3.3): a replayed start is refused too while the configuration is not usable
            return WithRunHeader(new JsonObject { ["evidenceEpoch"] = run.EvidenceEpoch }, run, RunKinds.Open);
        }
        // P3.4C-4 (§3.3, D4-F): a protected run needs the repository's configuration record in force (CONFIG_NOT_HELD /
        // CONFIG_LAPSED; nothing registered); the run is opened under it.
        RepositoryConfig config = RequireUsableConfig(repoKey, "the start");
        if (!HasGrantWithLoopLeft(repoKey, now))
            throw new CustodianRefusal(ErrorCodes.LoopNotAuthorized, "no automated loop is authorized for this repository; nothing was registered");
        var created = new RunRecord(
            RepoKey: repoKey, RunId: req.RunId, RunRevision: 0, OpenedAt: Iso(now), RequestId: req.RequestId, EvidenceEpoch: 1,
            Declaration: declaration, Status: RunStatuses.Idle, Ended: null,
            Operations: [], CheckExecutions: [], Reviews: [], Items: [], Replies: [], Responses: [], Incidents: [], Events: [],
            OpenedConfig: new ConfigPin(config.ConfigRevision, config.ConfigDigest));
        RunRecord next = RecordedRun(created, null, caller, req, new JsonObject { ["evidenceEpoch"] = 1, ["configRevision"] = config.ConfigRevision, ["configDigest"] = config.ConfigDigest }, now, out JsonObject result);
        WriteRun(next);
        Audit($"run_transition kind=open runId={next.RunId} none->idle rev=1 caller={caller.Name} requestId={req.RequestId}");
        return result;
    }

    private bool HasGrantWithLoopLeft(string repoKey, DateTime now)
        => Read().Grants.Any(g => g.RepoKey == repoKey && g.RevokedAt is null && ParseTime(g.ExpiresAt) > now && g.LoopsUsed < g.LoopsTotal && !IsSuspended(g));

    /// <summary>Recovery U2 (§2.4) suspends every unexpired grant after a new boot; a suspended grant authorizes nothing
    /// (LOOP_NOT_AUTHORIZED) and automation needs a new operator grant.</summary>
    private static bool IsSuspended(Grant g) => g.SuspendedAt is not null;

    private static RunDeclaration DeclarationOf(JsonObject f)
    {
        JsonObject b = f["budgets"]!.AsObject();
        RunBaseline? baseline = f["baseline"] is JsonObject bl ? new RunBaseline((string)bl["sourceId"]!, (string)bl["digest"]!) : null;
        int? maxFixes = RunFields.Integer(b["maxFixes"]) is long mf ? (int)mf : null;
        return new RunDeclaration((string)f["runJsonDigest"]!, new RunBudgets((int)(long)b["maxReviews"]!, (int)(long)b["maxCheckExecutions"]!, maxFixes), baseline);
    }

    private static bool SameDeclaration(RunDeclaration a, RunDeclaration b)
        => a.RunJsonDigest == b.RunJsonDigest && a.Budgets == b.Budgets && a.Baseline == b.Baseline;

    // ---- op_begin ----

    /// <summary>Begin an operation (§3.2 <c>op_begin</c>): only on an open, idle run, from the bound session's process
    /// tree (D7), within the budget. The custodian issues the operation id, records the writer (the request's sender),
    /// and for a review assigns the round, cross-checks every binding it holds, deduplicates itself and records an
    /// S2 review's reduced isolation.</summary>
    private RunStep OpBeginStep(LoopCaller caller, RunRecord run, RunRequest req, DateTime now, RepoIdentity repo, FixBaselineRead? fixBaseline, ApplyPre? applyPre, IsolationBasisRead? basisNow)
    {
        if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({run.Status})");
        if (run.RunningOperation is { } running) throw new CustodianRefusal(ErrorCodes.RunBusy, $"the run has a running {running.Kind} operation {running.OperationId}");
        RequireRunBoundCaller(caller, run);
        Hold(HoldPoints.OpBeginBoundChecked);
        OperationWriter writer = WriterOf(caller);
        JsonObject f = req.Fields;
        int seq = run.Operations.Count + 1;
        if ((string)f["operationKind"]! == "fix") return FixBeginStep(run, req, now, writer, seq, fixBaseline, basisNow);
        if ((string)f["operationKind"]! == "apply") return ApplyBeginStep(run, req, now, writer, seq, applyPre);
        if ((string)f["operationKind"]! == "checks")
        {
            int used = NonSkippedExecutions(run);
            int limit = CheckExecutionLimit(run);
            if (used >= limit) throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"check executions: {used} of {limit} used");
            // P3.4C-4 (§3.3): the current configuration gates the operation; every planned check that will run names the
            // definition the operator approved for the custodian. The operation is pinned to the record's revision.
            RepositoryConfig cfg = RequireUsableConfig(run.RepoKey, "a protected checks operation");
            foreach (JsonObject p in f["planned"]!.AsArray().Cast<JsonObject>())
            {
                if ((string?)p["definitionDigest"] is not { } d) continue; // recorded only as skipped (record_execution refuses anything else)
                string check = (string)p["check"]!;
                if (!cfg.Checks.TryGetValue(check, out ConfigCheck? approved) || approved.DefinitionDigest != d)
                    throw new CustodianRefusal(ErrorCodes.CheckNotApproved, approved is null
                        ? $"check {check} is not in the repository's protected configuration; nothing was begun"
                        : $"check {check}'s definition is not the one approved in the repository's protected configuration (revision {cfg.ConfigRevision}); nothing was begun");
            }
            // P3.4C-5 Increment 3 (§4, §2.4): the custodian measures the source and every planned check's inputs itself
            // before the checks start — through its helper and the approved runtime; without them nothing is begun.
            EngineRuntimeRecord checksRuntime = RequireMeasureReady();
            RequireRepositoryReadable(repo); // N5-8
            string checksTicket = "tkt-" + HelperBroker.NewToken()[..24];
            var op = new RunOperation(NewId("cop", seq), seq, "checks", RunOperationStatuses.Measuring, Iso(now), null, writer, (JsonObject)f.DeepClone(), null,
                new OperationPin(cfg.ConfigRevision, cfg.ConfigDigest), checksTicket);
            var startTicket = new CheckTicket(checksTicket, CheckStart, run.RepoKey, run.RunId, op.OperationId, repo, checksRuntime, CheckWorkload(cfg, f), now);
            return new RunStep(run with { Operations = [.. run.Operations, op], Status = RunStatuses.Checking },
                new JsonObject { ["operationId"] = op.OperationId, ["configRevision"] = cfg.ConfigRevision, ["operationStatus"] = RunOperationStatuses.Measuring, ["ticket"] = checksTicket },
                () => StartCheckMeasurement(startTicket));
        }

        // P3.4C-4 (§3.3): the configuration-derived identities the review claims, checked in this hold against the held
        // records: the repository record in force with an approved Codex installation; the isolation basis an operator
        // record; the capture rules and the Codex image the approved ones. The operation is pinned to all of them.
        RepositoryConfig config = RequireUsableConfig(run.RepoKey, "a protected review");
        if (config.CodexInstallation is not { } install)
            throw new CustodianRefusal(ErrorCodes.ConfigNotHeld, $"the repository's protected configuration has no approved Codex installation; a protected review is refused — the operator sets one with `{OperatorWording.Cli} setup --repo <path>`");
        (string isoKind, string isoId, int isoRevision) = RequireIsolationBasis(f["isolation"]!.AsObject(), install.Sha256, basisNow);
        if ((string)f["captureRulesDigest"]! != config.CaptureRulesDigest)
            throw new CustodianRefusal(ErrorCodes.ConfigMismatch, "the review's capture rules are not the repository's protected capture rules; nothing was begun");
        if ((string)f["codexSha256"]! != install.Sha256)
            throw new CustodianRefusal(ErrorCodes.ConfigMismatch, "the Codex image the engine reports is not the approved installation; nothing was begun");
        var pin = new OperationPin(config.ConfigRevision, config.ConfigDigest, isoKind, isoId, isoRevision, config.CaptureRulesDigest, install.Sha256);
        CrossCheckReviewBindings(run, f["checkExecutionIds"]!.AsArray(), f["amendments"]!["offered"]!.AsArray(), f["discussion"]!["offered"]!.AsArray());
        // P3.4C-5 (§3.1 step 2, §2.4): the custodian captures the review itself, through its helper and the approved runtime:
        // without them nothing is reserved (actionable, fail closed — never the engine's capture).
        EngineRuntimeRecord runtime = RequireCaptureReady();
        RequireRepositoryReadable(repo); // N5-8
        int begun = run.Reviews.Count;
        int reviewLimit = ReviewLimit(run);
        if (begun >= reviewLimit) throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"review budget: {begun} of {reviewLimit} used");
        string reviewId = (string)f["reviewId"]!;
        if (run.Reviews.Any(r => r.ReviewId == reviewId)) throw new ArgumentException($"review id {reviewId} was already used in this run");
        // The capture claims of the P3.4C-3 shape are ignored, never recorded (N5-2), and the mismatch is audited.
        var reserve = (JsonObject)f.DeepClone();
        List<string> ignored = [.. RunFields.IgnoredCaptureClaims.Where(k => reserve.Remove(k))];
        string ticket = "tkt-" + HelperBroker.NewToken()[..24];
        var opReview = new RunOperation(NewId("rop", seq), seq, "review", RunOperationStatuses.Measuring, Iso(now), null, writer, reserve, null, pin, ticket);
        int round = run.Reviews.Count + 1;
        var review = new RunReview(reviewId, opReview.OperationId, round, (JsonObject)reserve.DeepClone(), null, null, [], [], [], run.EvidenceEpoch);
        RunRecord next = run with { Operations = [.. run.Operations, opReview], Reviews = [.. run.Reviews, review], Status = RunStatuses.Reviewing };
        var result = new JsonObject
        {
            ["operationId"] = opReview.OperationId, ["reviewId"] = reviewId, ["round"] = round, ["configRevision"] = config.ConfigRevision,
            ["operationStatus"] = RunOperationStatuses.Measuring, ["ticket"] = ticket,
        };
        if (ignored.Count > 0) result["ignoredClaims"] = new JsonArray([.. ignored.Select(k => (JsonNode)k)]);
        var measurement = new CaptureTicket(ticket, run.RepoKey, run.RunId, opReview.OperationId, repo, runtime, (JsonObject)reserve["target"]!.DeepClone(), config.CaptureRules, now);
        return new RunStep(next, result, () =>
        {
            if (ignored.Count > 0) Audit($"op_begin_claims_ignored runId={run.RunId} operationId={opReview.OperationId} keys={string.Join(',', ignored)} (the custodian measures the capture itself)");
            StartCapture(measurement);
        });
    }

    /// <summary>Every binding a review names that the custodian holds must be its own record (EVIDENCE_NOT_HELD
    /// otherwise): the check executions, the offered amendments (each a record of the run's P3.4C-1 log with that
    /// disclosure digest) and the offered discussion (items, responses, replies).</summary>
    private void CrossCheckReviewBindings(RunRecord run, JsonArray checkExecutionIds, JsonArray presented, JsonArray delivered)
    {
        var executions = run.CheckExecutions.Select(e => (string)e["executionId"]!).ToHashSet(StringComparer.Ordinal);
        foreach (JsonNode? id in checkExecutionIds)
            if (!executions.Contains((string)id!)) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"check execution {(string)id!} is not an execution the custodian holds for this run");

        if (presented.Count > 0)
        {
            UserRecordLog? log = ReadUserLog(run.RepoKey, run.RunId);
            foreach (JsonObject p in presented.Cast<JsonObject>())
            {
                string id = (string)p["amendmentId"]!;
                string? digest = (string?)p["disclosureDigest"];
                UserRecordEntry? rec = log?.Records.FirstOrDefault(r => r.RecordKind == "amendment" && r.RecordId == id);
                if (rec is null || rec.DisclosureDigest != digest)
                    throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"amendment {id} is not a protected amendment the custodian holds for this run with that disclosure digest");
            }
        }

        var items = run.Items.Select(i => i.ItemId).ToHashSet(StringComparer.Ordinal);
        foreach (JsonObject d in delivered.Cast<JsonObject>())
        {
            string itemId = (string)d["itemId"]!;
            if (!items.Contains(itemId)) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"delivered item {itemId} is not an item the custodian holds");
            foreach (JsonNode? r in d["responseIds"]!.AsArray())
                if (!run.Responses.Any(x => (string?)x["responseId"] == (string)r! && (string?)x["itemId"] == itemId))
                    throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"delivered response {(string)r!} is not a response the custodian holds on item {itemId}");
            foreach (JsonNode? r in d["replyIds"]!.AsArray())
                if (!run.Replies.Any(x => (string?)x["replyId"] == (string)r! && (string?)x["itemId"] == itemId))
                    throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"delivered reply {(string)r!} is not a reply the custodian holds on item {itemId}");
        }
    }

    // ---- record_execution ----

    /// <summary>Append one check execution (§3.2 <c>record_execution</c>) to the running checks operation, from the
    /// process that began it, for a planned check, within the budgets. P3.4C-5 Increment 3 (§4): a skipped execution is
    /// recorded at once; one that ran is RESERVED — the custodian measures the source after it, outside the gate, and its
    /// commit records it with the custodian's own start and end measurements (<see cref="CommitCheckEnd"/>).</summary>
    private RunStep RecordExecutionStep(LoopCaller caller, RunRecord run, RunRequest req, RepoIdentity repo, DateTime now)
    {
        RunOperation op = RunningOperation(run, (string)req.Fields["operationId"]!);
        if (op.Kind != "checks") throw new CustodianRefusal(ErrorCodes.OperationNotRunning, $"operation {op.OperationId} is a {op.Kind} operation; executions belong to a checks operation");
        if (op.Status == RunOperationStatuses.Measuring) throw new CustodianRefusal(ErrorCodes.OperationNotRunning, $"operation {op.OperationId} is still being measured by the custodian; its checks start once it runs");
        if (op.Status != RunOperationStatuses.Running) throw new CustodianRefusal(ErrorCodes.OperationNotRunning, $"operation {op.OperationId} is not running ({op.Status})");
        if (op.Pending is not null) throw new CustodianRefusal(ErrorCodes.RunBusy, $"the custodian is measuring the end of execution {(string?)op.Pending["execution"]?["executionId"]}; record the next one once it is recorded");
        RequireSameWriter(caller, op);
        JsonObject e = req.Fields["execution"]!.AsObject();
        string check = (string)e["check"]!;
        JsonNode? planned = op.Begin["planned"]!.AsArray().FirstOrDefault(p => (string?)p!["check"] == check);
        if (planned is null) throw new ArgumentException($"check {check} is not planned by operation {op.OperationId}");
        string executionId = (string)e["executionId"]!;
        if (run.CheckExecutions.Any(x => (string?)x["executionId"] == executionId)) throw new ArgumentException($"execution {executionId} is already recorded");
        bool skipped = (string)e["status"]! == "skipped";
        if (skipped != (e["skipReason"] is not null)) throw new ArgumentException("a skipped execution names its skip reason, and only a skipped one");
        // P3.4C-4 (§3.3, §4.3): an execution that ran carries the definition its operation planned (and the custodian
        // approved at op_begin). A change or revocation since op_begin does not refuse the recording — the check ran under
        // the pinned basis; whether it counts is decided against the current configuration at derivation.
        if (!skipped && ((string?)planned["definitionDigest"] is not { } plannedDigest || (string?)e["definitionDigest"] != plannedDigest))
            throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"execution {(string)e["executionId"]!} of {check} does not carry the definition its operation planned and the custodian approved; nothing was recorded");
        if (run.CheckExecutions.Count >= CustodianConstants.MaxAllExecutionsPerRun)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"a run keeps at most {CustodianConstants.MaxAllExecutionsPerRun} check executions");
        int used = NonSkippedExecutions(run);
        int limit = CheckExecutionLimit(run);
        if (!skipped && used >= limit) throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"check executions: {used} of {limit} used");
        if (skipped)
        {
            JsonObject stored = SkippedExecution(run, op, e); // P3.4C-4: with the configuration revision the operation ran under
            return new RunStep(run with { CheckExecutions = [.. run.CheckExecutions, stored] }, new JsonObject { ["operationId"] = op.OperationId, ["executionId"] = executionId });
        }
        EngineRuntimeRecord runtime = RequireMeasureReady();
        RepositoryConfig cfg = ReadConfigRecords().CurrentOf(run.RepoKey) ?? throw new CustodianRefusal(ErrorCodes.ConfigNotHeld, "the repository's protected configuration is no longer held; nothing was recorded");
        string ticket = "tkt-" + HelperBroker.NewToken()[..24];
        var pending = new JsonObject { ["ticket"] = ticket, ["reservedAt"] = Iso(now), ["execution"] = e.DeepClone() };
        var endTicket = new CheckTicket(ticket, CheckEnd, run.RepoKey, run.RunId, op.OperationId, repo, runtime, CheckWorkload(cfg, op.Begin), now);
        return new RunStep(run with { Operations = ReplaceOperation(run, op with { Pending = pending }) },
            new JsonObject { ["operationId"] = op.OperationId, ["executionId"] = executionId, ["executionStatus"] = RunOperationStatuses.Measuring, ["ticket"] = ticket },
            () => StartCheckMeasurement(endTicket));
    }

    // ---- op_finish ----

    /// <summary>Finish the running operation (§3.2 <c>op_finish</c>), from the process that began it. For a review the
    /// custodian derives acceptance itself (§4.4), records the engine's incidents, and ONLY IF ACCEPTED applies the
    /// items, assessments and replies (§4.5).</summary>
    private RunStep OpFinishStep(LoopCaller caller, RunRecord run, RunRequest req, DateTime now, ExportRehash? rehash, FixBaselineRead? fixBaseline, ApplyPre? applyPre)
    {
        RunOperation op = RunningOperation(run, (string)req.Fields["operationId"]!);
        RequireSameWriter(caller, op);
        JsonObject outcome = RunFields.Outcome(op.Kind, req.Fields["outcome"]);
        string opStatus = (string)outcome["status"]!;
        string runStatus = run.IsTerminal ? run.Status : RunStatuses.Idle;
        string? promptDigest = (string?)req.Fields["promptDigest"];
        JsonObject? presented = req.Fields["presented"] as JsonObject;
        bool custodianCapture = op.Status is RunOperationStatuses.Measuring or RunOperationStatuses.Captured;
        if (!custodianCapture && (promptDigest is not null || presented is not null))
            throw new CustodianRefusal(ErrorCodes.MalformedRequest, "promptDigest and presented belong to the finish of a review the custodian captured");
        // P3.4C-5 (§2.4): a review still being captured can only be abandoned; the measurement is cancelled and the
        // reserved budget released (the review never began).
        if (op.Status == RunOperationStatuses.Measuring)
        {
            if (opStatus is not ("cancelled" or "failed" or "error"))
                throw new CustodianRefusal(ErrorCodes.OperationNotRunning, $"operation {op.OperationId} is still being measured by the custodian; it can only be cancelled until the measurement completes");
            string ended = opStatus == "cancelled" ? RunOperationStatuses.Cancelled : RunOperationStatuses.Error;
            return new RunStep(EndMeasurement(run, op, ended, opStatus == "cancelled" ? "cancelled" : "abandoned", $"the engine ended the {op.Kind} operation before the custodian's measurement completed", now),
                new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = ended, ["budgetReleased"] = true },
                () => CancelCapture(op.Ticket));
        }
        if (op.Kind == "fix") return FixFinishStep(run, op, outcome, runStatus, now, fixBaseline);
        if (op.Kind == "apply") return ApplyFinishStep(run, op, outcome, runStatus, now, applyPre);
        if (op.Kind == "checks")
        {
            if (op.Pending is not null)
                throw new CustodianRefusal(ErrorCodes.RunBusy, $"the custodian is measuring the end of execution {(string?)op.Pending["execution"]?["executionId"]}; finish the operation once it is recorded");
            RunOperation done = op with { Status = opStatus, EndedAt = Iso(now), Outcome = outcome };
            return new RunStep(run with { Operations = ReplaceOperation(run, done), Status = runStatus },
                new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = opStatus });
        }

        RunReview review = run.Reviews.Single(r => r.OperationId == op.OperationId);
        if (custodianCapture) RequirePresented(review, opStatus, promptDigest, presented);
        JsonArray reported = outcome["incidents"]!.AsArray();
        bool exportModified = custodianCapture && rehash is { } rh && rh.OperationId == op.OperationId && !rh.Unchanged;
        RequireIncidentRoom(run, reported.Count + (exportModified ? 1 : 0));
        var incidents = new List<RunIncident>(run.Incidents);
        var newIncidentIds = new List<string>();
        foreach (JsonObject i in reported.Cast<JsonObject>())
        {
            var inc = new RunIncident(NewId("inc", incidents.Count + 1), (string)i["kind"]!, op.OperationId, review.ReviewId, (string)i["detail"]!, Iso(now), "engine");
            incidents.Add(inc);
            newIncidentIds.Add(inc.IncidentId);
        }
        // P3.4C-5 (§3.1 step 7, N5-3): the custodian's own re-hash of the export it published. A changed (or unreadable)
        // export means the review is not accepted: an invalidating incident the custodian records itself.
        if (custodianCapture && (rehash is null || rehash.OperationId != op.OperationId))
            throw new InvalidOperationException("a custodian-captured review is finished only after the custodian re-hashed its export");
        if (exportModified)
        {
            var inc = new RunIncident(NewId("inc", incidents.Count + 1), "export_modified_during_review", op.OperationId, review.ReviewId,
                $"the published export changed during the review (the custodian's re-hash: {rehash!.Detail})", Iso(now), "custodian");
            incidents.Add(inc);
            newIncidentIds.Add(inc.IncidentId);
        }
        List<string> reasons = RunLifecycle.NotAcceptedReasons(outcome, run.IsTerminal, incidents.Where(i => i.OperationId == op.OperationId).Select(i => i.Kind));
        // P3.4C-4 (§3.3, §4.3): acceptance also needs the pinned basis still usable at completion, read in this hold — the
        // isolation record not revoked or lapsed, the repository record in force with the capture rules and Codex image
        // the review was pinned under. Otherwise the review is recorded as not accepted (an outcome, not a refusal).
        ConfigRecordsFile config = ReadConfigRecords();
        if (IsolationBasisProblem(config, op.Pin?.IsolationKind, op.Pin?.IsolationRecordId) is not null) reasons.Add("isolation_basis_revoked");
        else if (ReviewBasisProblem(config, run.RepoKey, op.Pin) is not null) reasons.Add("config_changed_during_review");
        bool accepted = reasons.Count == 0;
        string sourceId = (string)review.Begin["sourceId"]!;
        AppliedReview? applied = accepted ? RunLifecycle.ApplyAccepted(run, review, sourceId, outcome, Iso(now)) : null;
        JsonObject stored = StoredReviewOutcome(outcome);
        if (custodianCapture)
        {
            stored["promptDigest"] = promptDigest;
            stored["presented"] = presented?.DeepClone();
            stored["exportRehash"] = new JsonObject { ["unchanged"] = !exportModified, ["detail"] = rehash!.Detail };
        }
        RunReview finished = review with
        {
            Outcome = stored, Accepted = accepted, NotAcceptedReasons = reasons,
            ItemIds = applied?.NewItemIds ?? [], IncidentIds = [.. review.IncidentIds, .. newIncidentIds],
        };
        RunOperation doneOp = op with { Status = opStatus, EndedAt = Iso(now), Outcome = (JsonObject)stored.DeepClone() };
        RunRecord next = run with
        {
            Operations = ReplaceOperation(run, doneOp),
            Reviews = [.. run.Reviews.Select(r => r.ReviewId == review.ReviewId ? finished : r)],
            Incidents = incidents,
            Items = applied?.Items ?? run.Items,
            Replies = applied?.Replies ?? run.Replies,
            Status = runStatus,
        };
        var changed = new JsonArray((applied?.Changed ?? []).Select(i => (JsonNode)new JsonObject { ["itemId"] = i.ItemId, ["status"] = i.Status, ["itemRevision"] = i.ItemRevision }).ToArray());
        return new RunStep(next, new JsonObject
        {
            ["operationId"] = op.OperationId, ["operationStatus"] = opStatus, ["reviewId"] = review.ReviewId, ["round"] = review.Round,
            ["accepted"] = accepted, ["notAcceptedReasons"] = new JsonArray(reasons.Select(r => (JsonNode)r).ToArray()),
            ["itemsChanged"] = changed, ["incidentIds"] = new JsonArray(newIncidentIds.Select(x => (JsonNode)x).ToArray()),
        });
    }

    /// <summary>A review's outcome as stored: the result fields and artifact digests, with the counts of the items,
    /// assessments, replies and incidents it reported (what an accepted review applied is in the run's items and
    /// replies; a review that was not accepted changed nothing).</summary>
    private static JsonObject StoredReviewOutcome(JsonObject o) => new()
    {
        ["status"] = (string?)o["status"], ["outputValid"] = (bool)o["outputValid"]!, ["currentAtCompletion"] = (bool)o["currentAtCompletion"]!,
        ["verdict"] = (string?)o["verdict"], ["summaryDigest"] = (string?)o["summaryDigest"], ["artifacts"] = o["artifacts"]!.DeepClone(),
        ["reported"] = new JsonObject
        {
            ["newItems"] = o["newItems"]!.AsArray().Count, ["assessments"] = o["assessments"]!.AsArray().Count,
            ["replies"] = o["replies"]!.AsArray().Count, ["incidents"] = o["incidents"]!.AsArray().Count,
        },
    };

    // ---- recover ----

    /// <summary>Mark a running operation interrupted (§3.2 <c>recover</c>) — only once the custodian's OWN process table
    /// shows its writer gone (not running, or its id now names a later process). Reduce-only: a review is not accepted
    /// (<c>owner_died</c>); the engine's incidents are recorded. The custodian never kills anything.</summary>
    private RunStep RecoverStep(RunRecord run, RunRequest req, DateTime now)
    {
        RunOperation op = RunningOperation(run, (string)req.Fields["operationId"]!);
        bool? gone = ProcessIdentityCheck.IsGone(op.Writer.Pid, op.Writer.StartedAtMs, _processes);
        if (gone == true && op.Status == RunOperationStatuses.Measuring)
        {
            // P3.4C-5: the writer died while the custodian captured: the measurement is cancelled and the reservation
            // released; nothing was presented to anyone.
            return new RunStep(EndMeasurement(run, op, RunOperationStatuses.Interrupted, "owner_died", "the operation's writer is gone", now),
                new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = RunOperationStatuses.Interrupted, ["budgetReleased"] = true },
                () => CancelCapture(op.Ticket));
        }
        if (gone != true)
            throw new CustodianRefusal(ErrorCodes.OperationWriterAlive, gone is null
                ? "the process table could not be read, so the operation's writer cannot be established as gone; nothing was recovered"
                : $"the operation's writer (process {op.Writer.Pid}) is still running; nothing was recovered");
        // Phase 4 Increment 3 (§3.6.4): an application whose writer is gone is apply_interrupted, never applied.
        if (op.Kind == "apply") return ApplyInterruptedStep(run, op, now);
        JsonArray reported = req.Fields["incidents"]!.AsArray();
        RequireIncidentRoom(run, reported.Count);
        RunReview? review = op.Kind == "review" ? run.Reviews.Single(r => r.OperationId == op.OperationId) : null;
        var incidents = new List<RunIncident>(run.Incidents);
        var newIds = new List<string>();
        foreach (JsonObject i in reported.Cast<JsonObject>())
        {
            var inc = new RunIncident(NewId("inc", incidents.Count + 1), (string)i["kind"]!, op.OperationId, review?.ReviewId, (string)i["detail"]!, Iso(now), "engine");
            incidents.Add(inc);
            newIds.Add(inc.IncidentId);
        }
        // P3.4C-5 Increment 3: an execution whose end the custodian was measuring is recorded without its end (it counts
        // for nothing as fresh), and that measurement is cancelled.
        string? pendingTicket = (string?)op.Pending?["ticket"];
        if (op.Pending is not null)
        {
            run = RecordUnmeasuredPending(run, op, "owner_died: the operation's writer is gone", now);
            op = run.Operations.First(o => o.OperationId == op.OperationId);
        }
        RunOperation interrupted = op with { Status = RunOperationStatuses.Interrupted, EndedAt = Iso(now), Outcome = new JsonObject { ["status"] = RunOperationStatuses.Interrupted } };
        List<RunReview> reviews = review is null ? run.Reviews
            : [.. run.Reviews.Select(r => r.ReviewId == review.ReviewId
                ? r with { Outcome = new JsonObject { ["status"] = RunOperationStatuses.Interrupted }, Accepted = false, NotAcceptedReasons = ["owner_died"], IncidentIds = [.. r.IncidentIds, .. newIds] }
                : r)];
        RunRecord next = run with { Operations = ReplaceOperation(run, interrupted), Reviews = reviews, Incidents = incidents, Status = run.IsTerminal ? run.Status : RunStatuses.Idle };
        return new RunStep(next, new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = RunOperationStatuses.Interrupted }, () => CancelCapture(pendingTicket));
    }

    // ---- respond ----

    /// <summary>Record implementer responses (§3.2 <c>respond</c>), all or nothing, from the bound session's process
    /// tree, each against the item revision it was written for. A response is a claim: it bumps its item's revision
    /// and never changes an item's status (D-04).</summary>
    private RunStep RespondStep(LoopCaller caller, RunRecord run, RunRequest req, DateTime now)
    {
        if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({run.Status})");
        if (run.RunningOperation is { Kind: "review" } running) throw new CustodianRefusal(ErrorCodes.RunBusy, $"a review is running ({running.OperationId}); respond after it finishes");
        RequireRunBoundCaller(caller, run);
        JsonObject f = req.Fields;
        JsonArray responses = f["responses"]!.AsArray();
        if (run.Responses.Count + responses.Count > CustodianConstants.MaxResponsesPerRun)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"a run keeps at most {CustodianConstants.MaxResponsesPerRun} responses");
        var byId = run.Items.ToDictionary(i => i.ItemId, StringComparer.Ordinal);
        var existing = run.Responses.Select(r => (string)r["responseId"]!).ToHashSet(StringComparer.Ordinal);
        var stored = new List<JsonObject>();
        var revisions = new JsonObject();
        var bumped = new Dictionary<string, RunItem>(StringComparer.Ordinal);
        foreach (JsonObject r in responses.Cast<JsonObject>())
        {
            string responseId = (string)r["responseId"]!;
            string itemId = (string)r["itemId"]!;
            if (existing.Contains(responseId)) throw new ArgumentException($"response {responseId} is already recorded");
            if (!byId.TryGetValue(itemId, out RunItem? item)) throw new CustodianRefusal(ErrorCodes.FindingNotFound, $"item {itemId} is not an item of this run");
            if (item.Status is not ("open" or "informational")) throw new CustodianRefusal(ErrorCodes.FindingNotRespondable, $"item {itemId} is {item.Status}; it takes no response");
            int baseRevision = (int)(long)r["baseItemRevision"]!;
            if (item.ItemRevision != baseRevision)
                throw new CustodianRefusal(ErrorCodes.StaleState, $"item {itemId} changed (revision {item.ItemRevision}, not {baseRevision}); read the current state and respond again");
            if (run.Responses.Count(x => (string?)x["itemId"] == itemId) + 1 > CustodianConstants.MaxResponsesPerItem)
                throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"item {itemId} keeps at most {CustodianConstants.MaxResponsesPerItem} responses");
            if ((string?)r["supersedes"] is { } sup && !run.Responses.Any(x => (string?)x["responseId"] == sup && (string?)x["itemId"] == itemId))
                throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"response {responseId} supersedes {sup}, which is not a response the custodian holds on item {itemId}");
            if ((string?)r["answers"]!["reviewerReplyId"] is { } reply && !run.Replies.Any(x => (string?)x["replyId"] == reply && (string?)x["itemId"] == itemId))
                throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"response {responseId} answers reply {reply}, which is not a reply the custodian holds on item {itemId}");
            var s = (JsonObject)r.DeepClone();
            s.Remove("baseItemRevision");
            s["responseSetId"] = (string)f["responseSetId"]!;
            s["disclosureDigest"] = (string?)f["disclosureDigest"];
            s["recordedAt"] = Iso(now);
            stored.Add(s);
            RunItem next = item with { ItemRevision = item.ItemRevision + 1 };
            bumped[itemId] = next;
            revisions[itemId] = next.ItemRevision;
        }
        RunRecord updated = run with
        {
            Responses = [.. run.Responses, .. stored],
            Items = [.. run.Items.Select(i => bumped.GetValueOrDefault(i.ItemId) ?? i)],
        };
        return new RunStep(updated, new JsonObject
        {
            ["responseIds"] = new JsonArray(stored.Select(x => (JsonNode)(string)x["responseId"]!).ToArray()), ["itemRevisions"] = revisions,
        });
    }

    // ---- end ----

    /// <summary>End the run (§3.2 <c>end</c>): terminal and irreversible; <c>closed</c> only when no operation runs.
    /// Reduce-only, either surface. In the same hold the run's loop, if still live, ends by derivation (run_ended,
    /// by the custodian, §3.4(5)); if that ledger write fails, the loop's next transition derives it (§3.4(3)).</summary>
    private RunStep EndStep(LoopCaller caller, RunRecord run, RunRequest req, DateTime now)
    {
        if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has already ended ({run.Status})");
        string status = (string)req.Fields["status"]!;
        if (status == RunStatuses.Closed && run.RunningOperation is { } running)
            throw new CustodianRefusal(ErrorCodes.RunBusy, $"the run has a running {running.Kind} operation {running.OperationId}; it is closed only when none runs (stop it instead)");
        var ended = new RunEnded(status, (string)req.Fields["reason"]!, Iso(now), caller.Name);
        // Whether the run's loop is still live is read in this same hold, so nothing can change it before the
        // derivation below.
        bool loopLive = Read().Loops!.FirstOrDefault(l => l.RepoKey == run.RepoKey && l.RunId == run.RunId) is { } loop && !LoopStatuses.IsTerminal(loop.Status);
        var result = new JsonObject
        {
            ["ended"] = new JsonObject { ["status"] = ended.Status, ["reason"] = ended.Reason, ["at"] = ended.At, ["by"] = ended.By },
            ["loopEnded"] = loopLive,
        };
        string? measuringTicket = run.RunningOperation is { Status: RunOperationStatuses.Measuring } m ? m.Ticket : (string?)run.RunningOperation?.Pending?["ticket"];
        return new RunStep(run with { Status = status, Ended = ended }, result, () =>
        {
            if (loopLive) EndLoopForRun(run.RepoKey, run.RunId, status, now);
            CancelCapture(measuringTicket); // the measurement's commit then finds the run ended (cancelled, budget released)
        });
    }

    /// <summary>Derive the end of the run's loop, if it is still live (run_ended, by the custodian). Callers hold
    /// <see cref="Gate"/>.</summary>
    private void EndLoopForRun(string repoKey, string runId, string runStatus, DateTime now)
    {
        LedgerFile file = Read();
        int index = file.Loops!.FindIndex(l => l.RepoKey == repoKey && l.RunId == runId);
        if (index < 0) return;
        LoopRecord loop = Normalized(file.Loops[index]);
        if (LoopStatuses.IsTerminal(loop.Status)) return;
        PersistDerived(file, index, DeriveEnd(loop, LoopStatuses.RunEnded, $"run_{runStatus}", now));
    }

    // ---- guards ----

    /// <summary>§3.5: <c>recover</c> and <c>end</c> (reduce-only) are open to both surfaces — and (Phase 4 Increment 3) the
    /// record of an interrupted application's reconciliation, which records and authorizes nothing; every other kind is the
    /// implementer's (the originating session's engine).</summary>
    private static void AuthorizeRunKind(LoopCaller caller, string kind)
    {
        if (caller.IsOperator && kind is not (RunKinds.Recover or RunKinds.End or RunKinds.ApplyReconcile))
            throw new CustodianRefusal(ErrorCodes.CallerNotAuthorized, $"{kind} is recorded only by the originating session's engine on the implementer surface");
    }

    /// <summary>
    /// The bound caller (§3.5, D7): the run's loop must have a custodian-verified binding, and its bound process must
    /// still run as the instance the custodian verified and be an ancestor of the process connected to the pipe. Once
    /// the bound session's process has ended, nothing can record evidence for the run (D3-B / D-15: completed protected
    /// runs are frozen). Correlation, not authentication: a process inside the bound tree passes (residual R1).
    /// </summary>
    private void RequireRunBoundCaller(LoopCaller caller, RunRecord run)
    {
        LoopRecord? loop = Read().Loops!.FirstOrDefault(l => l.RepoKey == run.RepoKey && l.RunId == run.RunId);
        if (loop?.Binding is not { Process.Verified: true } binding)
            throw new CustodianRefusal(ErrorCodes.ProcessIdentityUnverified, "the run's automation loop has no custodian-verified binding; evidence is accepted only from the bound session's process tree");
        ProcessCheckResult r = ProcessIdentityCheck.VerifyBound(binding.Process.Pid, binding.Process.StartedAtMs, caller.ClientProcessId, _processes);
        if (!r.Verified)
            throw new CustodianRefusal(ErrorCodes.ProcessIdentityUnverified, $"the request does not come from the bound session's process tree: {r.Detail}");
    }

    /// <summary>The process that sent this request (§4.3): the parent of the connected pipe client, from the
    /// custodian's own process-table snapshot.</summary>
    private OperationWriter WriterOf(LoopCaller caller)
    {
        (ProcEntry? writer, long startedAtMs, string detail) = ProcessIdentityCheck.WriterOf(caller.ClientProcessId, _processes);
        if (writer is null) throw new CustodianRefusal(ErrorCodes.ProcessIdentityUnverified, $"the process that sent this request could not be identified: {detail}");
        return new OperationWriter(writer.Pid, startedAtMs, writer.ImageName ?? "");
    }

    /// <summary>Only the process instance that began an operation extends or finishes it (§4.3).</summary>
    private void RequireSameWriter(LoopCaller caller, RunOperation op)
    {
        (ProcEntry? writer, long startedAtMs, string detail) = ProcessIdentityCheck.WriterOf(caller.ClientProcessId, _processes);
        if (writer is null || writer.Pid != op.Writer.Pid || startedAtMs != op.Writer.StartedAtMs)
            throw new CustodianRefusal(ErrorCodes.WriterMismatch, $"operation {op.OperationId} was begun by another process; only that process extends or finishes it{(writer is null ? $" ({detail})" : "")}");
    }

    private static RunOperation RunningOperation(RunRecord run, string operationId)
    {
        RunOperation? op = run.Operations.FirstOrDefault(o => o.OperationId == operationId);
        if (op is null || !RunOperationStatuses.IsActive(op.Status))
            throw new CustodianRefusal(ErrorCodes.OperationNotRunning, op is null ? $"the run has no operation {operationId}" : $"operation {operationId} is not running ({op.Status})");
        return op;
    }

    private static void RequireIncidentRoom(RunRecord run, int adding)
    {
        if (run.Incidents.Count + adding > CustodianConstants.MaxIncidentsPerRun)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"a run keeps at most {CustodianConstants.MaxIncidentsPerRun} isolation incidents");
    }

    private static void RequireProjectionWithinCap(RunRecord run)
    {
        int bytes = System.Text.Encoding.UTF8.GetByteCount(ImplementerRunProjection(run, null, null).ToJsonString());
        if (bytes > CustodianConstants.MaxImplementerProjectionBytes)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"the run record would exceed its size cap ({CustodianConstants.MaxImplementerProjectionBytes} bytes)");
    }

    private static List<RunOperation> ReplaceOperation(RunRecord run, RunOperation op) => [.. run.Operations.Select(o => o.OperationId == op.OperationId ? op : o)];

    private static int NonSkippedExecutions(RunRecord run) => run.CheckExecutions.Count(e => (string?)e["status"] != "skipped");
    private static int ReviewLimit(RunRecord run) => Math.Min(run.Declaration.Budgets.MaxReviews, CustodianConstants.MaxReviewsPerRun);
    private static int CheckExecutionLimit(RunRecord run) => Math.Min(run.Declaration.Budgets.MaxCheckExecutions, CustodianConstants.MaxCheckExecutionsPerRun);

    // ---- idempotency and evidence ----

    /// <summary>A request id already applied to this run returns its stored result, provided it is the same request
    /// (kind and fields) from the same caller class; otherwise REQUEST_ID_CONFLICT.</summary>
    private static JsonObject? RunReplayOf(RunRecord run, LoopCaller caller, RunRequest req)
    {
        RunEvent? prior = run.Events.FirstOrDefault(e => e.RequestId == req.RequestId);
        if (prior is null) return null;
        if (prior.Kind != req.Kind || prior.RequestDigest != req.Digest || prior.Caller != caller.Name)
            throw new CustodianRefusal(ErrorCodes.RequestIdConflict, "this request id was already used for a different run transition");
        return (JsonObject)(prior.Result?.DeepClone() ?? new JsonObject());
    }

    /// <summary>The applied record: revision + 1 and one evidence entry carrying the full result (for replays).</summary>
    private static RunRecord RecordedRun(RunRecord next, RunRecord? before, LoopCaller caller, RunRequest req, JsonObject stepResult, DateTime now, out JsonObject result)
    {
        int revision = (before?.RunRevision ?? 0) + 1;
        result = new JsonObject { ["runId"] = next.RunId, ["kind"] = req.Kind, ["runRevision"] = revision, ["status"] = next.Status };
        foreach (KeyValuePair<string, JsonNode?> kv in stepResult) result[kv.Key] = kv.Value?.DeepClone();
        List<RunEvent> events = before?.Events ?? [];
        var evidence = new RunEvent(events.Count + 1, req.Kind, req.RequestId, caller.Name, caller.ClientProcessId, req.Digest,
            before?.Status ?? "none", next.Status, Iso(now), (JsonObject)result.DeepClone());
        return next with { RunRevision = revision, Events = [.. events, evidence] };
    }

    /// <summary>A result that applied nothing (an <c>open</c> replay by declaration, a deduplicated review): the run's
    /// current revision and status.</summary>
    private static JsonObject WithRunHeader(JsonObject stepResult, RunRecord run, string kind)
    {
        var result = new JsonObject { ["runId"] = run.RunId, ["kind"] = kind, ["runRevision"] = run.RunRevision, ["status"] = run.Status };
        foreach (KeyValuePair<string, JsonNode?> kv in stepResult) result[kv.Key] = kv.Value?.DeepClone();
        return result;
    }

    // ---- the run section of list_user_records (contract §3.3) ----

    /// <summary>The run's record as the caller's surface may see it, with the run record's OWN revision and a digest of
    /// that snapshot. Callers hold <see cref="Gate"/>.</summary>
    private JsonObject RunSection(string repoKey, string runId, bool operatorView)
    {
        RunRecord? run = ReadRun(repoKey, runId);
        if (run is null)
            return new JsonObject { ["registered"] = false, ["runRevision"] = 0, ["runDigest"] = RunDigest(repoKey, runId, null), ["limits"] = Limits(null), ["record"] = null };
        return new JsonObject
        {
            ["registered"] = true,
            ["runRevision"] = run.RunRevision,
            ["runDigest"] = RunDigest(repoKey, runId, run),
            ["limits"] = Limits(run),
            ["record"] = operatorView ? JsonSerializer.SerializeToNode(run, WireJson) : ImplementerRunProjection(run, _processes, ReadConfigRecords()),
            // P3.4C-4 (§3.3, §4.3): per review, whether its pinned basis is usable now (custodian-derived at read time).
            ["reviewBasis"] = ReviewBasisOf(run, ReadConfigRecords()),
        };
    }

    /// <summary>P3.4C-4: for each review, <c>basisUsable</c> and, when it is not, the reason (§4.3).</summary>
    private static JsonObject ReviewBasisOf(RunRecord run, ConfigRecordsFile config)
    {
        var o = new JsonObject();
        foreach (RunReview r in run.Reviews)
        {
            string? problem = ReviewBasisProblem(config, run.RepoKey, run.Operations.FirstOrDefault(x => x.OperationId == r.OperationId)?.Pin);
            o[r.ReviewId] = new JsonObject { ["basisUsable"] = problem is null, ["basisReason"] = problem };
        }
        return o;
    }

    private static string RunDigest(string repoKey, string runId, RunRecord? run) => Digest.Sha256Hex(Digest.Canonical(new JsonObject
    {
        ["repoKey"] = repoKey, ["runId"] = runId, ["runRevision"] = run?.RunRevision ?? 0, ["status"] = run?.Status,
    }));

    /// <summary>The effective maxima the custodian enforces for the run (§2.3): the review and check-execution budgets
    /// are the run's declared ones under the custodian's hard caps.</summary>
    private static JsonObject Limits(RunRecord? run) => new()
    {
        ["maxReviews"] = run is null ? CustodianConstants.MaxReviewsPerRun : ReviewLimit(run),
        ["maxCheckExecutions"] = run is null ? CustodianConstants.MaxCheckExecutionsPerRun : CheckExecutionLimit(run),
        ["maxFixes"] = run is null ? 0 : FixLimit(run),
        ["maxExecutions"] = CustodianConstants.MaxAllExecutionsPerRun,
        ["maxResponsesPerCall"] = CustodianConstants.MaxResponsesPerCall,
        ["maxResponsesPerItem"] = CustodianConstants.MaxResponsesPerItem,
        ["maxResponsesPerRun"] = CustodianConstants.MaxResponsesPerRun,
        ["maxNewItemsPerReview"] = CustodianConstants.MaxNewItemsPerReview,
        ["maxItems"] = CustodianConstants.MaxItemsPerRun,
        ["maxReplies"] = CustodianConstants.MaxRepliesPerRun,
        ["maxIncidents"] = CustodianConstants.MaxIncidentsPerRun,
        ["maxEvents"] = CustodianConstants.MaxRunEvents,
    };

    /// <summary>Implementer projection: an INDEPENDENT allowlist built field by field — the record without the writer
    /// process facts and without the transition log. A running operation carries the custodian's <c>writerAlive</c>
    /// verdict from its own process table (a boolean, no process fact), as the loop's <c>binding.verified</c>.</summary>
    private static JsonObject ImplementerRunProjection(RunRecord run, IProcessTable? processes, ConfigRecordsFile? config)
    {
        JsonNode? Node<T>(T value) => JsonSerializer.SerializeToNode(value, WireJson);
        // P3.4C-4: each review carries whether its pinned basis is usable now (not computed for the size cap).
        JsonArray reviews = (JsonArray)Node(run.Reviews)!;
        if (config is not null)
        {
            JsonObject basis = ReviewBasisOf(run, config);
            foreach (JsonObject r in reviews.Cast<JsonObject>())
            {
                JsonObject b = basis[(string)r["reviewId"]!]!.AsObject();
                r["basisUsable"] = b["basisUsable"]!.DeepClone();
                r["basisReason"] = b["basisReason"]?.DeepClone();
            }
        }
        return new JsonObject
        {
            ["runId"] = run.RunId,
            ["runRevision"] = run.RunRevision,
            ["openedAt"] = run.OpenedAt,
            ["evidenceEpoch"] = run.EvidenceEpoch,
            ["declaration"] = Node(run.Declaration),
            ["status"] = run.Status,
            ["ended"] = run.Ended is null ? null : Node(run.Ended),
            ["operations"] = new JsonArray(run.Operations.Select(o =>
            {
                var p = new JsonObject
                {
                    ["operationId"] = o.OperationId, ["seq"] = o.Seq, ["kind"] = o.Kind, ["status"] = o.Status,
                    ["beganAt"] = o.BeganAt, ["endedAt"] = o.EndedAt, ["begin"] = o.Begin.DeepClone(), ["outcome"] = o.Outcome?.DeepClone(),
                    ["pin"] = o.Pin is null ? null : Node(o.Pin),
                };
                // P3.4C-5 Increment 3 (§4): a checks operation's latest custodian measurement and the execution being measured.
                if (o.Measured is not null) p["measured"] = o.Measured.DeepClone();
                if (o.Pending is not null) p["pending"] = new JsonObject { ["ticket"] = o.Pending["ticket"]?.DeepClone(), ["executionId"] = o.Pending["execution"]?["executionId"]?.DeepClone(), ["check"] = o.Pending["execution"]?["check"]?.DeepClone() };
                if (RunOperationStatuses.IsActive(o.Status) && processes is not null)
                    p["writerAlive"] = ProcessIdentityCheck.IsGone(o.Writer.Pid, o.Writer.StartedAtMs, processes) is bool gone ? !gone : null;
                return (JsonNode)p;
            }).ToArray()),
            ["checkExecutions"] = new JsonArray(run.CheckExecutions.Select(e => e.DeepClone()).ToArray()),
            ["reviews"] = reviews,
            ["openedConfig"] = run.OpenedConfig is null ? null : Node(run.OpenedConfig),
            ["items"] = Node(run.Items),
            ["replies"] = new JsonArray(run.Replies.Select(r => r.DeepClone()).ToArray()),
            ["responses"] = new JsonArray(run.Responses.Select(r => r.DeepClone()).ToArray()),
            ["incidents"] = Node(run.Incidents),
            ["used"] = new JsonObject
            {
                ["reviews"] = run.Reviews.Count, ["checkExecutions"] = NonSkippedExecutions(run), ["executions"] = run.CheckExecutions.Count, ["fixes"] = FixesBegun(run),
                ["responses"] = run.Responses.Count, ["items"] = run.Items.Count, ["replies"] = run.Replies.Count, ["incidents"] = run.Incidents.Count,
            },
        };
    }
}
