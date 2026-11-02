using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED self-test of the P3.4C-3 run-state authority, run by <c>self-test-ledger</c> against its scratch
/// store. Increment 2: the write-through store path (contract §2.4) — a writer killed at each step of a replacement
/// leaves one complete old or new version, and the temporaries it leaves are swept — and the run record's storage.
/// Increment 3: <c>run_transition</c> (§3) — every kind's effects and refusals, the bound caller and the writer, the
/// custodian-derived acceptance and item table, idempotency, budgets, validation and the projections. The process
/// table is a fixed one, so every branch is deterministic.
/// </summary>
internal static partial class RunSelfTest
{
    // A fixed process table: 100 the originating Claude process; 200 its MCP server (the engine, the WRITER of the
    // operations it begins); 300 the engine's pipe helper (the connected client); 250 a shell of the model, inside the
    // session's tree; 350 that shell's helper; 400 an unrelated process; 450 its helper.
    private const long Second = 10_000_000;
    private static readonly long T0 = DateTime.UtcNow.AddMinutes(-10).ToFileTimeUtc();
    private const int Claude = 100, Server = 200, Helper = 300, Shell = 250, ShellHelper = 350, Unrelated = 400, UnrelatedHelper = 450;

    private sealed class Table : IProcessTable
    {
        internal readonly Dictionary<int, ProcEntry> Entries = new()
        {
            [Claude] = new(Claude, 1, T0, "claude.exe"),
            [Server] = new(Server, Claude, T0 + 10 * Second, "node.exe"),
            [Helper] = new(Helper, Server, T0 + 11 * Second, "powershell.exe"),
            [Shell] = new(Shell, Claude, T0 + 12 * Second, "pwsh.exe"),
            [ShellHelper] = new(ShellHelper, Shell, T0 + 13 * Second, "powershell.exe"),
            [Unrelated] = new(Unrelated, 1, T0 + 5 * Second, "evil.exe"),
            [UnrelatedHelper] = new(UnrelatedHelper, Unrelated, T0 + 6 * Second, "powershell.exe"),
        };
        public IReadOnlyDictionary<int, ProcEntry>? Snapshot() => new Dictionary<int, ProcEntry>(Entries);
    }

    private static readonly LoopCaller Engine = new(false, "proof-implementer", Helper);
    private static readonly LoopCaller ShellCaller = new(false, "proof-implementer", ShellHelper);
    private static readonly LoopCaller Outsider = new(false, "proof-implementer", UnrelatedHelper);
    private static readonly LoopCaller Oper = new(true, "proof-operator", null);

    private const string SrcA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string SrcB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private sealed record Fx(GrantLedger Led, Table Procs, string Repo, string Run, string LoopId);

    private static int _seq;

    internal static int Run(string repos)
    {
        int failed = 0;
        failed += WritePathCases();
        failed += RunStorageCases();
        failed += OpenCases(repos);
        failed += ChecksCases(repos);
        failed += ReviewCases(repos);
        failed += CarryForwardCases(repos);
        failed += NotAcceptedAndDedupCases(repos);
        failed += RespondCases(repos);
        failed += RecoverCases(repos);
        failed += EndCases(repos);
        failed += FrozenRunCases(repos);
        failed += ValidationCases(repos);
        failed += ProjectionCases(repos);
        failed += AmendmentRedactionCases(repos); // Phase 5 F-i2-5: the custodian redacts and holds an amendment's representation
        failed += AmendmentReadDisclosureCases(repos); // Phase 5 OI-1: an amendment's read disclosure is held and redacts later amendments
        // Increment 4: the changes inside existing operations, and the interleavings across the stores (N17, N18).
        failed += ConsumePreconditionCases(repos);
        failed += LoopReadsRunCases(repos);
        failed += DecisionFreshnessCases(repos);
        failed += RefusalAuditCases(repos);
        failed += FixDecisionSurfaceCases(repos); // Phase 4 Increment 3 (N4-6): only the operator surface confirms
        failed += InterleavingCases(repos);
        failed += DecisionConcurrencyCases(repos);
        // Increment 5: recovery after a new boot (N16), each case on a store of its own.
        failed += RecoveryCases(repos);
        // P3.4C-4: the custodian-held trusted configuration (M2, I, M3–M5, M7–M9, M11, M13; M12 is in the recovery cases).
        failed += ConfigCases(repos);
        // P3.4C-5 Increment 2: the custodian's review capture (readiness refusals; the N5-18 start reconciliation).
        failed += CaptureCases(repos);
        // P3.4C-5 Increment 4: the measurements' lifecycle (N5-13 hold points, N5-11 helper crashes, N5-18 for checks).
        failed += MeasurementLifecycleCases(repos);
        return failed;
    }

    // ---- increment 2: the write path and the run storage ----

    /// <summary>N16 (e), the write path: a crash injected after each step of a replacement leaves the previous
    /// version intact (before the replacement) or the new one complete (after it) — never a partial file.</summary>
    private static int WritePathCases()
    {
        int failed = 0;
        string dir = Path.Combine(StorePaths.Root, "write-path");
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, "probe.json");
        string v1 = new JsonObject { ["version"] = 1, ["pad"] = new string('a', 4096) }.ToJsonString();
        string v2 = new JsonObject { ["version"] = 2, ["pad"] = new string('b', 8192) }.ToJsonString();

        DurableStore.Replace(file, v1);
        failed += Check("write path: a replacement writes the version and leaves no temporary", File.ReadAllText(file) == v1 && Temporaries(dir) == 0);

        foreach ((string step, bool newVisible) in new[] { (DurableStore.StepTempWritten, false), (DurableStore.StepReplaced, true), (DurableStore.StepFlushed, true) })
        {
            DurableStore.Replace(file, v1);
            bool crashed = false;
            DurableStore.FaultHook = (s, _) => { if (s == step) throw new SimulatedCrash(); };
            try { DurableStore.Replace(file, v2); }
            catch (SimulatedCrash) { crashed = true; }
            finally { DurableStore.FaultHook = null; }
            string now = File.ReadAllText(file);
            failed += Check($"write path: killed after '{step}' leaves {(newVisible ? "the new" : "the old")} version, complete and parseable",
                crashed && now == (newVisible ? v2 : v1) && JsonNode.Parse(now) is JsonObject);
        }

        // An interrupted replacement can leave its temporary behind; it is never a live version and is swept.
        DurableStore.SweepTemporaries(dir);
        DurableStore.Replace(file, v1);
        DurableStore.FaultHook = (s, _) => { if (s == DurableStore.StepTempWritten) throw new SimulatedCrash(); };
        try { DurableStore.Replace(file, v2); } catch (SimulatedCrash) { } finally { DurableStore.FaultHook = null; }
        int left = Temporaries(dir);
        int swept = DurableStore.SweepTemporaries(StorePaths.Root);
        failed += Check($"write path: the temporary of an interrupted replacement is swept ({left} left, {swept} swept), the live file untouched",
            left == 1 && swept >= 1 && Temporaries(dir) == 0 && File.ReadAllText(file) == v1);

        // Create-once (the content-key secret): never overwritten.
        string once = Path.Combine(dir, "once.json");
        DurableStore.CreateNew(once, "{\"first\":true}");
        failed += Check("write path: a create-once file is never overwritten", Throws<IOException>(() => DurableStore.CreateNew(once, "{\"second\":true}")) && File.ReadAllText(once) == "{\"first\":true}");
        return failed;
    }

    /// <summary>A run record round-trips through its protected file (typed fields and the validated JSON claims).</summary>
    private static int RunStorageCases()
    {
        int failed = 0;
        const string repoKey = "fid1-0000000000000001-00000000000000000000000000000002";
        const string runId = "01a13561-b44f-79d2-a067-885bac440b52";
        var begin = new JsonObject { ["operationKind"] = "checks", ["planned"] = new JsonArray(new JsonObject { ["check"] = "unit", ["checkSpecId"] = new string('c', 64), ["required"] = true }) };
        var run = new RunRecord(
            RepoKey: repoKey, RunId: runId, RunRevision: 1, OpenedAt: DateTime.UtcNow.ToString("o"), RequestId: "open-1", EvidenceEpoch: 1,
            Declaration: new RunDeclaration(new string('d', 64), new RunBudgets(5, 50), new RunBaseline(new string('e', 64), new string('f', 64))),
            Status: RunStatuses.Idle, Ended: null,
            Operations: [new RunOperation("cop-1-abcdef012345", 1, "checks", RunOperationStatuses.Running, DateTime.UtcNow.ToString("o"), null, new OperationWriter(4242, 1_700_000_000_000, "node.exe"), begin, null)],
            CheckExecutions: [], Reviews: [], Items: [], Replies: [], Responses: [], Incidents: [], Events: []);
        GrantLedger.WriteRun(run);
        RunRecord? back = GrantLedger.ReadRun(repoKey, runId);
        failed += Check("run storage: one file per run under runs\\<repoKey>\\<runId>.json", File.Exists(Path.Combine(StorePaths.RunsDir, repoKey, runId + ".json")));
        failed += Check("run storage: the record round-trips (typed fields and validated claims)",
            back is not null && back.RunRevision == 1 && back.Declaration.Budgets.MaxReviews == 5 && back.Declaration.Baseline?.SourceId == new string('e', 64)
            && back.Operations.Single().Writer.Pid == 4242 && (string?)back.Operations.Single().Begin["planned"]![0]!["check"] == "unit"
            && back.RunningOperation?.OperationId == "cop-1-abcdef012345" && !back.IsTerminal);
        failed += Check("run storage: a run the custodian does not hold reads as none", GrantLedger.ReadRun(repoKey, "no-such-run") is null);
        failed += Check("run storage: an unsafe run id never becomes a path", Throws<ArgumentException>(() => StorePaths.RunPath(repoKey, "..\\escape")) && Throws<ArgumentException>(() => StorePaths.RunPath("..", runId)));
        return failed;
    }

    // ---- increment 3: run_transition ----

    /// <summary><c>open</c>: only under a grant with a loop left (nothing consumed); idempotent on the declaration;
    /// a changed declaration conflicts; the implementer's only.</summary>
    private static int OpenCases(string repos)
    {
        int failed = 0;
        var procs = new Table();
        var led = new GrantLedger("cust-selftest", procs);
        string repo = Directory.CreateDirectory(Path.Combine(repos, "RunOpen")).FullName;
        const string run = "run-open-1";
        failed += Check("open (P3.4C-4): with no protected configuration → CONFIG_NOT_HELD, and nothing is registered",
            Refused(() => Do(led, Engine, repo, run, "open", OpenFields()), ErrorCodes.ConfigNotHeld) && !IsProtected(led, repo, run));
        ConfigFixture.Hold(led, repo, repos);
        failed += Check("open: with no grant → LOOP_NOT_AUTHORIZED, and nothing is registered",
            Refused(() => Do(led, Engine, repo, run, "open", OpenFields()), ErrorCodes.LoopNotAuthorized) && !IsProtected(led, repo, run));
        Grant(led, repo, 1);
        string rid = Rid("open");
        JsonObject r1 = Do(led, Engine, repo, run, "open", OpenFields(), rid);
        failed += Check("open: registers the run (idle, revision 1, evidence epoch 1); the grant is not consumed",
            (string?)r1["status"] == "idle" && (int)r1["runRevision"]! == 1 && (int)r1["evidenceEpoch"]! == 1 && LoopsUsed(led, repo) == 0);
        failed += Check("open: the run is protected for selection from registration (custodian answer, no loop yet)", IsProtected(led, repo, run));
        JsonObject replay = Do(led, Engine, repo, run, "open", OpenFields(), rid);
        failed += Check("open: a replay of the same request returns the same result", replay.ToJsonString() == r1.ToJsonString());
        JsonObject again = Do(led, Engine, repo, run, "open", OpenFields());
        failed += Check("open: another request with the same declaration returns the run, unchanged (I5)", (int)again["runRevision"]! == 1 && Events(led, repo, run) == 1);
        failed += Check("open: a changed declaration → RUN_DECLARATION_CONFLICT", Refused(() => Do(led, Engine, repo, run, "open", OpenFields(runJson: Hex)), ErrorCodes.RunDeclarationConflict));
        failed += Check("open: the same request id for another request → REQUEST_ID_CONFLICT", Refused(() => Do(led, Engine, repo, run, "open", OpenFields(maxReviews: 3), rid), ErrorCodes.RequestIdConflict));
        failed += Check("open: the operator surface does not register runs → CALLER_NOT_AUTHORIZED", Refused(() => Do(led, Oper, repo, "run-open-2", "open", OpenFields()), ErrorCodes.CallerNotAuthorized));
        failed += Check("a kind on a run the custodian never opened → RUN_NOT_OPEN", Refused(() => Do(led, Engine, repo, "run-never", "end", EndFields()), ErrorCodes.RunNotOpen));
        return failed;
    }

    /// <summary>A checks operation: begun only from the bound tree; extended and finished only by its writer; planned
    /// checks only; budgets; one running operation per run.</summary>
    private static int ChecksCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunChecks", maxCheckExecutions: 2);
        failed += Check("op_begin from outside the bound session's tree → PROCESS_IDENTITY_UNVERIFIED", Refused(() => Do(fx, Outsider, "op_begin", ChecksBegin()), ErrorCodes.ProcessIdentityUnverified));
        string rid = Rid("begin");
        JsonObject b = Do(fx, Engine, "op_begin", ChecksBegin(), rid);
        string op = (string)b["operationId"]!;
        failed += Check("op_begin (checks): a custodian-issued operation id; status checking; the writer is the request's sender (the engine)",
            op.StartsWith("cop-1-", StringComparison.Ordinal) && (string?)b["status"] == "checking" && Run(fx).Operations.Single().Writer.Pid == Server);
        failed += Check("op_begin replay: the same operation, nothing begun again", (string?)Do(fx, Engine, "op_begin", ChecksBegin(), rid)["operationId"] == op && Run(fx).Operations.Count == 1);
        failed += Check("a second op_begin while one runs → RUN_BUSY", Refused(() => Do(fx, Engine, "op_begin", ChecksBegin()), ErrorCodes.RunBusy));
        failed += Check("record_execution from another process of the session (the model's shell) → WRITER_MISMATCH",
            Refused(() => Do(fx, ShellCaller, "record_execution", Exec(op, "e1")), ErrorCodes.WriterMismatch));
        failed += Check("record_execution of a check the operation did not plan → INVALID_ARGUMENT", Refused(() => Do(fx, Engine, "record_execution", Exec(op, "e0", check: "lint")), ErrorCodes.InvalidArgument));
        Do(fx, Engine, "record_execution", Exec(op, "e1"));
        failed += Check("record_execution: appended with the operation and the evidence epoch",
            Run(fx).CheckExecutions.Single() is { } e && (string?)e["operationId"] == op && (int?)e["evidenceEpoch"] == 1);
        failed += Check("record_execution: a recorded execution id again → INVALID_ARGUMENT", Refused(() => Do(fx, Engine, "record_execution", Exec(op, "e1")), ErrorCodes.InvalidArgument));
        failed += Check("record_execution: a skipped execution needs its reason → INVALID_ARGUMENT", Refused(() => Do(fx, Engine, "record_execution", Exec(op, "e9", status: "skipped")), ErrorCodes.InvalidArgument));
        Do(fx, Engine, "record_execution", Exec(op, "e2"));
        failed += Check("record_execution past the declared budget (2) → BUDGET_EXHAUSTED; a skipped one is still recorded",
            Refused(() => Do(fx, Engine, "record_execution", Exec(op, "e3")), ErrorCodes.BudgetExhausted) && Ok(() => Do(fx, Engine, "record_execution", Exec(op, "e4", status: "skipped", skipReason: "definition_changed"))));
        failed += Check("op_finish from another process → WRITER_MISMATCH", Refused(() => Do(fx, ShellCaller, "op_finish", Finish(op, ChecksOutcome())), ErrorCodes.WriterMismatch));
        JsonObject fin = Do(fx, Engine, "op_finish", Finish(op, ChecksOutcome()));
        failed += Check("op_finish (checks): completed; the run is idle again", (string?)fin["operationStatus"] == "completed" && (string?)fin["status"] == "idle");
        failed += Check("op_finish of a finished operation → OPERATION_NOT_RUNNING", Refused(() => Do(fx, Engine, "op_finish", Finish(op, ChecksOutcome())), ErrorCodes.OperationNotRunning));
        failed += Check("record_execution on a finished operation → OPERATION_NOT_RUNNING", Refused(() => Do(fx, Engine, "record_execution", Exec(op, "e5")), ErrorCodes.OperationNotRunning));
        failed += Check("op_begin (checks) with the budget used up → BUDGET_EXHAUSTED", Refused(() => Do(fx, Engine, "op_begin", ChecksBegin()), ErrorCodes.BudgetExhausted));
        return failed;
    }

    /// <summary>A review: the custodian cross-checks the bindings it holds, assigns the round, records S2's reduced
    /// isolation itself, derives acceptance and creates the items by the table.</summary>
    private static int ReviewCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunReview");
        string checksOp = (string)Do(fx, Engine, "op_begin", ChecksBegin())["operationId"]!;
        Do(fx, Engine, "record_execution", Exec(checksOp, "x1"));
        Do(fx, Engine, "op_finish", Finish(checksOp, ChecksOutcome()));

        failed += Check("op_begin (review) naming an execution the custodian does not hold → EVIDENCE_NOT_HELD",
            Refused(() => Do(fx, Engine, "op_begin", ReviewBegin("r1", executions: ["x1", "forged"])), ErrorCodes.EvidenceNotHeld));
        failed += Check("op_begin (review) presenting an amendment the custodian does not hold → EVIDENCE_NOT_HELD (C2 case d)",
            Refused(() => Do(fx, Engine, "op_begin", ReviewBegin("r1", amendment: "01999999-0000-7000-8000-00000000f0f0")), ErrorCodes.EvidenceNotHeld));
        failed += Check("op_begin (review) delivering an item the custodian does not hold → EVIDENCE_NOT_HELD",
            Refused(() => Do(fx, Engine, "op_begin", ReviewBegin("r1", deliveredItem: "no-such-item")), ErrorCodes.EvidenceNotHeld));
        JsonObject b = Do(fx, Engine, "op_begin", ReviewBegin("r1", executions: ["x1"], isolation: "S2"));
        string op = (string)b["operationId"]!;
        RunRecord run = Run(fx);
        failed += Check("op_begin (review): round 1 assigned by the custodian, status reviewing, rop- id",
            (int)b["round"]! == 1 && (string?)b["status"] == "reviewing" && op.StartsWith("rop-2-", StringComparison.Ordinal) && run.Reviews.Single().Accepted is null);
        failed += Check("op_begin (review, S2): the custodian records isolation_reduced itself", run.Incidents.Any(i => i.Kind == "isolation_reduced" && i.Source == "custodian" && i.ReviewId == "r1"));
        failed += Check("respond while a review runs → RUN_BUSY", Refused(() => Do(fx, Engine, "respond", Respond(("any", 1))), ErrorCodes.RunBusy));

        JsonObject wrong = ReviewOutcome(newItems: [NewItem("f1", "finding", "established_defect", "informational")]);
        failed += Check("op_finish whose new item contradicts the table (an established defect created informational) → INVALID_ITEM_TRANSITION, nothing applied",
            Refused(() => Do(fx, Engine, "op_finish", Finish(op, wrong)), ErrorCodes.InvalidItemTransition) && Run(fx).RunningOperation?.OperationId == op && Run(fx).Items.Count == 0);
        failed += Check("op_finish: a client cannot state acceptance — an `accepted` field in the outcome is refused (MALFORMED_REQUEST)",
            Refused(() => Do(fx, Engine, "op_finish", Finish(op, ReviewOutcome(extra: ("accepted", true)))), ErrorCodes.MalformedRequest));
        JsonObject fin = Do(fx, Engine, "op_finish", Finish(op, ReviewOutcome(newItems:
        [
            NewItem("f1", "finding", "established_defect", "open"),
            NewItem("f2", "finding", "note", "informational"),
            NewItem("q1", "question", "blocking_question", "open", relatedFinding: "f1"),
        ])));
        run = Run(fx);
        failed += Check("op_finish (review): accepted by the custodian; the items created by the table (revision 1, the review's round and source)",
            (bool)fin["accepted"]! && run.Reviews.Single().Accepted == true && run.Items.Count == 3
            && run.Items.All(i => i.ItemRevision == 1 && i.Round == 1 && i.SourceId == SrcA && i.ReviewId == "r1")
            && run.Items.Single(i => i.ItemId == "f2").Status == "informational" && run.Items.Single(i => i.ItemId == "q1").Status == "open");
        return failed;
    }

    /// <summary>§4.5 on a second review: exactly one assessment per item open before it; same-source resolution
    /// ignored; supersession only by a new open-class finding at least as strong (a weaker one restates); omitted and
    /// not-presented items stay open; every assessment raises the item's revision.</summary>
    private static int CarryForwardCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunCarry");
        string op1 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r1"))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op1, ReviewOutcome(newItems:
        [
            NewItem("a1", "finding", "established_defect", "open"), NewItem("a2", "finding", "serious_concern", "open"),
            NewItem("a3", "finding", "serious_concern", "open"), NewItem("a4", "finding", "established_defect", "open"),
            NewItem("a5", "finding", "established_defect", "open"), NewItem("a6", "finding", "serious_concern", "open"),
        ])));

        string op2 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r2", source: SrcA, reviewInput: SrcB))["operationId"]!;
        JsonObject missing = ReviewOutcome(assessments: [Assess("a1", "still_present")]);
        failed += Check("op_finish whose assessments do not cover every item open before the review → INVALID_ITEM_TRANSITION",
            Refused(() => Do(fx, Engine, "op_finish", Finish(op2, missing)), ErrorCodes.InvalidItemTransition));
        Do(fx, Engine, "op_finish", Finish(op2, ReviewOutcome(
            newItems: [NewItem("n1", "finding", "established_defect", "open"), NewItem("n2", "finding", "minor_concern", "informational")],
            assessments:
            [
                Assess("a1", "apparently_resolved"), Assess("a2", "superseded", "n1"), Assess("a3", "superseded", "n2"),
                Assess("a4", "superseded", "n2"), Assess("a5", "not_presented"), Assess("a6", "no_longer_assessable"),
            ])));
        RunRecord run = Run(fx);
        RunItem I(string id) => run.Items.Single(i => i.ItemId == id);
        failed += Check("apparently_resolved on the source the item was raised on → ignored:same_source (stays open)",
            I("a1").Status == "open" && I("a1").Assessments.Single().Effect == "ignored:same_source");
        failed += Check("superseded by a new, at least as strong open-class finding → superseded (and the new item supersedes it)",
            I("a2").Status == "superseded" && I("a2").SupersededBy == "n1" && I("n1").Supersedes.SequenceEqual(["a2"]));
        failed += Check("superseded by a weaker finding → ignored:weaker_superseding_finding, stays open, and the new item restates it",
            I("a3").Status == "open" && I("a3").Assessments.Single().Effect == "ignored:weaker_superseding_finding" && I("n2").Restates.SequenceEqual(["a3", "a4"]));
        failed += Check("an item the bundle did not present → kept_open:not_presented, recorded as not_assessed",
            I("a5").Status == "open" && I("a5").Assessments.Single() is { Assessment: "not_assessed", Effect: "kept_open:not_presented" });
        failed += Check("every assessment raises the item's revision (1 → 2); new items start at 1",
            new[] { "a1", "a2", "a3", "a4", "a5", "a6" }.All(id => I(id).ItemRevision == 2) && I("n1").ItemRevision == 1);

        string op3 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r3", source: SrcB, reviewInput: Hex))["operationId"]!;
        var open3 = run.Items.Where(i => i.Status == "open").Select(i => i.ItemId).ToList();
        Do(fx, Engine, "op_finish", Finish(op3, ReviewOutcome(assessments: [.. open3.Select(id => Assess(id, id == "a1" ? "apparently_resolved" : "still_present"))])));
        failed += Check("apparently_resolved on another source → reported_resolved (terminal for assessments)",
            Run(fx).Items.Single(i => i.ItemId == "a1").Status == "reported_resolved");
        return failed;
    }

    /// <summary>A review that is not accepted changes no item; the custodian deduplicates by the review input within
    /// the current evidence epoch, spending nothing (P3.4C-5: at the capture's commit — the reservation's budget is
    /// released); the review budget.</summary>
    private static int NotAcceptedAndDedupCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunNotAccepted", maxReviews: 4);
        string op1 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r1"))["operationId"]!;
        JsonObject f1 = Do(fx, Engine, "op_finish", Finish(op1, ReviewOutcome(status: "timed_out", newItems: [NewItem("t1", "finding", "established_defect", "open")])));
        failed += Check("a timed-out review is not accepted (status:timed_out) and creates no item",
            !(bool)f1["accepted"]! && f1["notAcceptedReasons"]!.AsArray().Select(x => (string)x!).SequenceEqual(["status:timed_out"]) && Run(fx).Items.Count == 0);
        string op2 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r2", reviewInput: SrcB))["operationId"]!;
        JsonObject f2 = Do(fx, Engine, "op_finish", Finish(op2, ReviewOutcome(incidents: [("termination_unconfirmed", "the tree was killed")])));
        failed += Check("a review with an invalidating incident is not accepted (incident:termination_unconfirmed)",
            !(bool)f2["accepted"]! && f2["notAcceptedReasons"]!.AsArray().Any(x => (string?)x == "incident:termination_unconfirmed"));
        string op3 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r3", reviewInput: Hex))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op3, ReviewOutcome()));
        JsonObject dup = Do(fx, Engine, "op_begin", ReviewBegin("r4", reviewInput: Hex));
        failed += Check("a review with the inputs of an accepted review of this epoch → deduplicated at its capture (deduplicatedOf r3), its budget released, nothing running",
            (string?)dup["deduplicatedOf"] == "r3" && (string?)dup["operationStatus"] == RunOperationStatuses.Deduplicated && Run(fx).Reviews.Count == 3 && Run(fx).RunningOperation is null);
        string op5 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r5", reviewInput: new string('8', 64)))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op5, ReviewOutcome()));
        failed += Check("op_begin of a new review past the declared review budget (4) → BUDGET_EXHAUSTED",
            Refused(() => Do(fx, Engine, "op_begin", ReviewBegin("r6", reviewInput: new string('9', 64))), ErrorCodes.BudgetExhausted));
        return failed;
    }

    /// <summary><c>respond</c>: from the bound tree, all or nothing, each against the item's current revision; a
    /// response is a claim that never changes a status. Replies answer responses the custodian holds.</summary>
    private static int RespondCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunRespond");
        string op1 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r1"))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op1, ReviewOutcome(newItems: [NewItem("i1", "finding", "established_defect", "open"), NewItem("i2", "finding", "serious_concern", "open")])));
        failed += Check("respond from outside the bound tree → PROCESS_IDENTITY_UNVERIFIED", Refused(() => Do(fx, Outsider, "respond", Respond(("i1", 1))), ErrorCodes.ProcessIdentityUnverified));
        failed += Check("respond to an item the run does not have → FINDING_NOT_FOUND", Refused(() => Do(fx, Engine, "respond", Respond(("zz", 1))), ErrorCodes.FindingNotFound));
        failed += Check("respond with one stale revision among two → STALE_FINDING_STATE, nothing recorded",
            Refused(() => Do(fx, Engine, "respond", Respond(("i1", 1), ("i2", 7))), ErrorCodes.StaleState) && Run(fx).Responses.Count == 0);
        JsonObject r = Do(fx, Engine, "respond", Respond(("i1", 1)));
        failed += Check("respond: recorded; the item's revision rises (1 → 2); its status is unchanged (a claim)",
            (int)r["itemRevisions"]!["i1"]! == 2 && Run(fx).Items.Single(i => i.ItemId == "i1") is { Status: "open", ItemRevision: 2 });
        failed += Check("respond against the old revision now → STALE_FINDING_STATE", Refused(() => Do(fx, Engine, "respond", Respond(("i1", 1))), ErrorCodes.StaleState));

        string resp = (string)Run(fx).Responses.Single()["responseId"]!;
        string op2 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r2", reviewInput: SrcB, deliveredItem: "i1", deliveredResponse: resp))["operationId"]!;
        failed += Check("op_begin (review) delivering a response the custodian holds is accepted", op2.StartsWith("rop-", StringComparison.Ordinal));
        JsonObject withForgedReply = ReviewOutcome(assessments: [Assess("i1", "still_present"), Assess("i2", "superseded", "s1")],
            newItems: [NewItem("s1", "finding", "established_defect", "open")], replies: [Reply("rp1", "i1", "not-a-response")]);
        failed += Check("a reply answering a response the custodian does not hold → INVALID_ITEM_TRANSITION",
            Refused(() => Do(fx, Engine, "op_finish", Finish(op2, withForgedReply)), ErrorCodes.InvalidItemTransition));
        Do(fx, Engine, "op_finish", Finish(op2, ReviewOutcome(assessments: [Assess("i1", "still_present"), Assess("i2", "superseded", "s1")],
            newItems: [NewItem("s1", "finding", "established_defect", "open")], replies: [Reply("rp1", "i1", resp)])));
        RunRecord run = Run(fx);
        failed += Check("a reply is recorded and raises its item's revision (assessment +1, reply +1: 2 → 4)",
            run.Replies.Single() is { } rp && (string?)rp["answersResponseId"] == resp && run.Items.Single(i => i.ItemId == "i1").ItemRevision == 4);
        failed += Check("respond to a superseded item → FINDING_NOT_RESPONDABLE", Refused(() => Do(fx, Engine, "respond", Respond(("i2", 2))), ErrorCodes.FindingNotRespondable));
        return failed;
    }

    /// <summary><c>recover</c>: only once the custodian's own process table shows the writer gone; a review is then
    /// not accepted (owner_died); either surface.</summary>
    private static int RecoverCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunRecover");
        string op = (string)Do(fx, Engine, "op_begin", ReviewBegin("r1"))["operationId"]!;
        failed += Check("recover while the writer runs → OPERATION_WRITER_ALIVE", Refused(() => Do(fx, Engine, "recover", Recover(op)), ErrorCodes.OperationWriterAlive));
        fx.Procs.Entries.Remove(Helper);
        fx.Procs.Entries.Remove(Server); // the engine's server died
        JsonObject r = Do(fx, Oper, "recover", Recover(op, ("termination_unconfirmed", "the server exited")));
        RunRecord run = Run(fx);
        failed += Check("recover (operator surface) once the writer is gone: interrupted; the review is not accepted (owner_died); the run is idle",
            (string?)r["operationStatus"] == "interrupted" && run.Reviews.Single() is { Accepted: false } rv && rv.NotAcceptedReasons.SequenceEqual(["owner_died"])
            && run.Status == "idle" && run.Incidents.Any(i => i.Kind == "termination_unconfirmed"));
        // A reused process id is another process: the writer is gone even though the id runs again.
        Fx fx2 = Protected(repos, "RunRecoverReuse");
        string op2 = (string)Do(fx2, Engine, "op_begin", ChecksBegin())["operationId"]!;
        fx2.Procs.Entries[Server] = new ProcEntry(Server, Claude, T0 + 60 * Second, "node.exe");
        failed += Check("recover when the writer's process id names a later process → interrupted", (string?)Do(fx2, Engine, "recover", Recover(op2))["operationStatus"] == "interrupted");
        return failed;
    }

    /// <summary><c>end</c>: terminal and irreversible; <c>closed</c> only with no running operation; the run's loop ends
    /// by derivation in the same hold; nothing begins on a terminal run, which is never re-opened.</summary>
    private static int EndCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunEnd");
        string op = (string)Do(fx, Engine, "op_begin", ChecksBegin())["operationId"]!;
        failed += Check("end (closed) with a running operation → RUN_BUSY", Refused(() => Do(fx, Engine, "end", EndFields("closed")), ErrorCodes.RunBusy));
        JsonObject e = Do(fx, Oper, "end", EndFields("stopped"));
        failed += Check("end (stopped, operator surface): terminal; the run's live loop ended in the same hold (run_ended, by the custodian)",
            (string?)e["status"] == "stopped" && (bool)e["loopEnded"]! && Loop(fx) is { Status: "run_ended", Ended.By: "custodian" });
        failed += Check("a running operation of a stopped run still finishes, and the run stays stopped",
            (string?)Do(fx, Engine, "op_finish", Finish(op, ChecksOutcome()))["status"] == "stopped");
        failed += Check("op_begin on an ended run → RUN_TERMINAL", Refused(() => Do(fx, Engine, "op_begin", ChecksBegin()), ErrorCodes.RunTerminal));
        failed += Check("open of an ended run → RUN_TERMINAL (never re-opened)", Refused(() => Do(fx, Engine, "open", OpenFields()), ErrorCodes.RunTerminal));
        failed += Check("end of an ended run → RUN_TERMINAL", Refused(() => Do(fx, Engine, "end", EndFields()), ErrorCodes.RunTerminal));
        return failed;
    }

    /// <summary>D3-B / D-15: once the loop is terminal, the bound session may still record evidence while its process
    /// runs; once that process has ended, nothing can — the completed protected run is frozen.</summary>
    private static int FrozenRunCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunFrozen");
        fx.Led.LoopTransition(Engine, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, 1, Loop(fx).LoopRevision, "end", new JsonObject { ["status"] = "cancelled", ["reason"] = "done" }, Rid("le")));
        failed += Check("after the loop ended, the bound session (still running) can still begin an operation",
            Ok(() => Do(fx, Engine, "op_begin", ChecksBegin())));
        Fx fx2 = Protected(repos, "RunFrozen2");
        fx2.Led.LoopTransition(Engine, fx2.Repo, LoopRequest.Parse(fx2.Run, fx2.LoopId, 1, Loop(fx2).LoopRevision, "end", new JsonObject { ["status"] = "cancelled", ["reason"] = "done" }, Rid("le")));
        fx2.Procs.Entries.Remove(Claude); // the bound session's process ended
        failed += Check("once the bound session's process ended, op_begin and respond → PROCESS_IDENTITY_UNVERIFIED (frozen)",
            Refused(() => Do(fx2, Engine, "op_begin", ChecksBegin()), ErrorCodes.ProcessIdentityUnverified)
            && Refused(() => Do(fx2, Engine, "respond", Respond(("x", 1))), ErrorCodes.ProcessIdentityUnverified));
        return failed;
    }

    /// <summary>Closed kinds, allowlisted keys per kind (an authority-shaped field is refused), bounded and typed values.</summary>
    private static int ValidationCases(string repos)
    {
        int failed = 0;
        failed += Check("an unknown kind → INVALID_ARGUMENT", Refused(() => RunRequest.Parse("run-v", "close", new JsonObject(), Rid("v")), ErrorCodes.InvalidArgument));
        failed += Check("an unknown field (a client `status`) → MALFORMED_REQUEST", Refused(() => RunRequest.Parse("run-v", "open", OpenFields(extra: ("status", "idle")), Rid("v")), ErrorCodes.MalformedRequest));
        failed += Check("a client revision field → MALFORMED_REQUEST", Refused(() => RunRequest.Parse("run-v", "end", new JsonObject { ["status"] = "closed", ["reason"] = "r", ["runRevision"] = 3 }, Rid("v")), ErrorCodes.MalformedRequest));
        failed += Check("a digest that is not 64 lowercase hex → INVALID_ARGUMENT", Refused(() => RunRequest.Parse("run-v", "open", OpenFields(runJson: Hex.ToUpperInvariant()), Rid("v")), ErrorCodes.InvalidArgument));
        failed += Check("an unsafe run id → INVALID_ARGUMENT", Refused(() => RunRequest.Parse("..", "open", OpenFields(), Rid("v")), ErrorCodes.InvalidArgument));
        failed += Check("an end reason over 500 characters → INVALID_ARGUMENT", Refused(() => RunRequest.Parse("run-v", "end", EndFields("closed", new string('x', 501)), Rid("v")), ErrorCodes.InvalidArgument));
        failed += Check("free text has its control characters replaced", (string?)RunRequest.Parse("run-v", "end", EndFields("closed", "a\nb\u0007c"), Rid("v")).Fields["reason"] == "a b c");
        failed += Check("a mistyped value (a string budget) → INVALID_ARGUMENT", Refused(() => RunRequest.Parse("run-v", "open", new JsonObject { ["runJsonDigest"] = Hex, ["budgets"] = new JsonObject { ["maxReviews"] = "5", ["maxCheckExecutions"] = 5 }, ["baseline"] = null }, Rid("v")), ErrorCodes.InvalidArgument));
        failed += Check("two responses for one item in a call → INVALID_ARGUMENT", Refused(() => RunRequest.Parse("run-v", "respond", Respond(("i1", 1), ("i1", 1)), Rid("v")), ErrorCodes.InvalidArgument));
        return failed;
    }

    /// <summary>The run section: the implementer projection has no writer process facts and no transition log (a
    /// running operation carries the custodian's writerAlive verdict); the operator projection has both; the default
    /// listing is today's; the custodian's `protected` answer counts the run record.</summary>
    private static int ProjectionCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunProjection");
        Do(fx, Engine, "op_begin", ChecksBegin());
        JsonObject impl = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false, GrantLedger.AllSections);
        JsonObject? rec = impl["run"]!["record"] as JsonObject;
        string implJson = impl["run"]!.ToJsonString();
        failed += Check("implementer run projection: no writer, no transition log, no process fact; the running operation carries writerAlive",
            rec is not null && rec["events"] is null && !implJson.Contains("\"writer\"", StringComparison.Ordinal) && !implJson.Contains("node.exe", StringComparison.Ordinal)
            && (bool?)rec["operations"]![0]!["writerAlive"] == true);
        JsonObject op = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true, GrantLedger.AllSections);
        failed += Check("operator run projection: the full record with the writer and the transition log",
            op["run"]!["record"]!["operations"]![0]!["writer"]!["pid"] is not null && op["run"]!["record"]!["events"]!.AsArray().Count >= 2);
        JsonObject def = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false);
        failed += Check("the default listing is today's (user + loop) plus the custodian's protected answer; no run section",
            def["run"] is null && def["loop"] is not null && def["records"] is not null && (bool)def["protected"]!);
        failed += Check("the run section reports the effective limits (the declared budget under the hard cap)",
            (int)impl["run"]!["limits"]!["maxReviews"]! == 5 && (int)impl["run"]!["limits"]!["maxCheckExecutions"]! == 50 && (bool)impl["run"]!["registered"]!);
        // Phase 5 F-i2-5: the snapshot section — the run's held structure, on the operator surface only, from the same
        // hold as the user section (its revision vector names the log revision listed beside it).
        var snapSections = new HashSet<string>(StringComparer.Ordinal) { "user", "snapshot" };
        JsonObject snap = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true, snapSections);
        failed += Check("operator snapshot section: the derivation snapshot of the held run, in the listing's revision",
            (string?)snap["snapshot"]?["schema"] == "arl.derivation-snapshot.v2" && snap["snapshot"]!["run"] is JsonObject
            && (int?)snap["snapshot"]!["revision"]!["userRevision"] == (int?)snap["revision"] && snap["snapshot"]!["runFloor"] is null);
        failed += Check("operator snapshot section of a run the custodian holds no record of: null",
            fx.Led.ListUserRecords(fx.Repo, "run-never-opened", operatorView: true, snapSections)["snapshot"] is null);
        string? refused = null;
        try { fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false, snapSections); }
        catch (CustodianRefusal e) { refused = e.Code; }
        failed += Check("implementer snapshot section: refused (CALLER_NOT_AUTHORIZED)", refused == ErrorCodes.CallerNotAuthorized);
        return failed;
    }

    /// <summary>Phase 5 F-i2-5: an amendment the custodian redacts — its helper's redaction of a fresh read is shown in
    /// the rendering the operator confirms, bound by digest, and held with the record (the implementer projection carries
    /// the representation, never the raw text); a client-supplied digest or source, an unstable read or a failed helper
    /// refuses.</summary>
    private static int AmendmentRedactionCases(string repos)
    {
        int failed = 0;
        // The run's baseline capture record: 600 KiB of text, so it is handed over in two parts.
        byte[] baselineRecord = System.Text.Encoding.UTF8.GetBytes("{\"schema\":\"synthetic-baseline\",\"pad\":\"" + new string('a', 600 * 1024) + "\"}");
        string baselineSha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(baselineRecord));
        Fx fx = Protected(repos, "Redaction", baseline: new JsonObject { ["sourceId"] = SrcA, ["digest"] = baselineSha });
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement();
        JsonObject Payload(string text) => new()
        {
            ["kind"] = "clarification", ["text"] = text, ["relates_to"] = new JsonArray(), ["replaces"] = null,
            ["request_digest"] = new string('0', 64), ["custodian_redaction"] = true,
        };
        // Phase 5 F-i2-5 (historical redaction): without the baseline record the basis is not complete — refused, never a
        // redaction against the current repository alone.
        failed += Check("redaction basis: a baseline capture record the custodian does not hold refuses the amendment (REDACTION_REFUSED)",
            ThrowsWith(() => fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload("a note"), 0, Rid("amend-nobase")), "does not hold the baseline capture record"));
        string Part(int i) => Convert.ToBase64String(baselineRecord.AsSpan(i * GrantLedger.EvidencePartBytes, Math.Min(GrantLedger.EvidencePartBytes, baselineRecord.Length - i * GrantLedger.EvidencePartBytes)));
        failed += Check("hold_evidence: a record whose digest this run does not bind is refused (EVIDENCE_NOT_HELD)",
            ThrowsWith(() => fx.Led.HoldEvidence(fx.Repo, fx.Run, Hex, 0, 1, Convert.ToBase64String("{}"u8.ToArray())), ErrorCodes.EvidenceNotHeld));
        failed += Check("hold_evidence: parts out of order are refused",
            ThrowsWith(() => fx.Led.HoldEvidence(fx.Repo, fx.Run, baselineSha, 1, 2, Part(1)), "does not follow"));
        JsonObject h0 = fx.Led.HoldEvidence(fx.Repo, fx.Run, baselineSha, 0, 2, Part(0));
        JsonObject h1 = fx.Led.HoldEvidence(fx.Repo, fx.Run, baselineSha, 1, 2, Part(1));
        failed += Check("hold_evidence: the baseline capture record, in two parts, is held content-addressed (and again at once)",
            (bool?)h0["held"] == false && (bool?)h1["held"] == true && File.Exists(StorePaths.RedactionEvidencePath(RepoIdentities.Resolve(fx.Repo).Key, fx.Run, baselineSha))
            && (bool?)fx.Led.HoldEvidence(fx.Repo, fx.Run, baselineSha, 0, 2, Part(0))["held"] == true);
        string rid = Rid("amend");
        PreparedAuthorization p = fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload("keep the confidential module as it is"), 0, rid);
        failed += Check("custodian redaction: the rendering shows exactly the representation Codex will see",
            p.Rendering.Contains("\"keep the [withheld] module as it is\"", StringComparison.Ordinal));
        fx.Led.Commit(rid, null);
        JsonObject impl = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false);
        JsonObject rec = (JsonObject)impl["records"]![0]!;
        string want = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("keep the [withheld] module as it is")));
        failed += Check("custodian redaction: the implementer projection holds the representation and its digest, never the raw text",
            (string?)rec["disclosureText"] == "keep the [withheld] module as it is" && (string?)rec["disclosureDigest"] == want
            && !impl.ToJsonString().Contains("confidential", StringComparison.Ordinal) && (string?)rec["source_id"] == SrcA);
        JsonObject op = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true);
        failed += Check("custodian redaction: the operator projection keeps the raw text beside the representation",
            (string?)op["records"]![0]!["text"] == "keep the confidential module as it is" && (string?)op["records"]![0]!["disclosureText"] == "keep the [withheld] module as it is");

        JsonObject forged = Payload("x");
        forged["disclosure_digest"] = Hex;
        failed += Check("custodian redaction: a client-supplied disclosure digest is refused",
            ThrowsWith(() => fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", forged, 1, Rid("amend-forged")), "disclosure_digest"));
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement(Stable: false);
        failed += Check("custodian redaction: an unstable read refuses (REDACTION_REFUSED); nothing is prepared",
            ThrowsWith(() => fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload("another note"), 1, Rid("amend-unstable")), ErrorCodes.RedactionRefused));
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement(Fail: "helper");
        failed += Check("custodian redaction: a failed helper refuses (MEASUREMENT_FAILED); nothing is prepared",
            ThrowsWith(() => fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload("another note"), 1, Rid("amend-failed")), ErrorCodes.MeasurementFailed));
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement();
        failed += Check("custodian redaction: a text-less amendment needs no read and records no representation",
            !fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload(""), 1, Rid("amend-empty")).Rendering.Contains("Codex will see", StringComparison.Ordinal));
        // A review's capture record is the custodian's own: held as evidence when the capture is published.
        string pending = Rid("amend-pending");
        fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload("another note"), 1, pending);
        Do(fx, Engine, "op_begin", ReviewBegin("rv-redaction"));
        string repoKey = RepoIdentities.Resolve(fx.Repo).Key;
        string? captureSha = (string?)Run(fx).Reviews.Last().Begin["captureDigest"];
        failed += Check("redaction evidence: a published review capture's record is held under its captureDigest",
            captureSha is { Length: 64 } && File.Exists(StorePaths.RedactionEvidencePath(repoKey, fx.Run, captureSha)));
        failed += Check("redaction basis: a capture recorded between the prepare and the commit refuses the commit (STALE_FINDING_STATE)",
            ThrowsWith(() => fx.Led.Commit(pending, null), "STALE_FINDING_STATE"));
        if (captureSha is { Length: 64 }) File.Delete(StorePaths.RedactionEvidencePath(repoKey, fx.Run, captureSha));
        failed += Check("redaction basis: a review capture record the custodian no longer holds refuses the amendment (REDACTION_REFUSED)",
            ThrowsWith(() => fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", Payload("a note"), 1, Rid("amend-nocap")), "does not hold the capture record of review"));
        return failed;
    }

    /// <summary>Phase 5 OI-1: an amendment the custodian redacts keeps its read's disclosure record as protected evidence
    /// of the run, and a later amendment is redacted against it — a confidential file only that read saw (introduced
    /// after the last review, deleted before the later amendment) stays withheld. Missing, altered, unbound and stale
    /// evidence refuses; another run's history does not count; the implementer cannot hold or replace the record.</summary>
    private static int AmendmentReadDisclosureCases(string repos)
    {
        int failed = 0;
        // Each run holds its baseline capture record (the basis is complete without the reads under test).
        Fx WithBaseline(string name)
        {
            byte[] record = System.Text.Encoding.UTF8.GetBytes("{\"schema\":\"synthetic-baseline\",\"run\":\"" + name + "\"}");
            string sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(record));
            Fx f = Protected(repos, name, baseline: new JsonObject { ["sourceId"] = SrcA, ["digest"] = sha });
            f.Led.HoldEvidence(f.Repo, f.Run, sha, 0, 1, Convert.ToBase64String(record));
            return f;
        }
        Fx fx = WithBaseline("ReadDisclosure");
        string repoKey = RepoIdentities.Resolve(fx.Repo).Key;
        JsonObject Payload(string text) => new()
        {
            ["kind"] = "clarification", ["text"] = text, ["relates_to"] = new JsonArray(), ["replaces"] = null,
            ["request_digest"] = new string('0', 64), ["custodian_redaction"] = true,
        };
        string Rendered(Fx f, string text, int rev, string rid) => f.Led.PrepareUserRecord(f.Repo, f.Run, "amendment", Payload(text), rev, rid).Rendering;
        // A1: the read withholds deploy/new.pem, a confidential file no review or baseline captured.
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement(ReadWithheld: ["confidential", "deploy/new.pem"]);
        string a1 = Rid("a1");
        failed += Check("A1: its read withholds the new confidential file",
            Rendered(fx, "rotate deploy/new.pem soon", 0, a1).Contains("\"rotate [withheld] soon\"", StringComparison.Ordinal));
        fx.Led.Commit(a1, null);
        string? a1Sha = (string?)fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true)["records"]![0]!["read_disclosure_digest"];
        string a1Path = a1Sha is { Length: 64 } ? StorePaths.RedactionEvidencePath(repoKey, fx.Run, a1Sha) : "";
        failed += Check("A1: the record binds its read disclosure, held as the run's protected evidence (content-addressed)",
            a1Sha is { Length: 64 } && File.Exists(a1Path) && Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(a1Path))) == a1Sha);
        failed += Check("A1: the implementer projection does not carry the read disclosure digest",
            !fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false).ToJsonString().Contains("read_disclosure_digest", StringComparison.Ordinal));
        // The file is deleted: the current read no longer knows it.
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement();
        string a2 = Rid("a2");
        failed += Check("A2 (the file deleted): its path stays withheld — A1's read disclosure is in the basis",
            Rendered(fx, "deploy/new.pem is gone", 1, a2).Contains("\"[withheld] is gone\"", StringComparison.Ordinal));
        fx.Led.Commit(a2, null);
        Fx other = WithBaseline("ReadDisclosureOther");
        failed += Check("another run: A1's read disclosure is not in its basis (the evidence is bound to its run)",
            Rendered(other, "deploy/new.pem is gone", 0, Rid("other")).Contains("\"deploy/new.pem is gone\"", StringComparison.Ordinal));
        failed += Check("the implementer cannot hold (or replace) an amendment's read disclosure: EVIDENCE_NOT_HELD",
            ThrowsWith(() => fx.Led.HoldEvidence(fx.Repo, fx.Run, a1Sha ?? Hex, 0, 1, Convert.ToBase64String("{}"u8.ToArray())), ErrorCodes.EvidenceNotHeld)
            && Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(a1Path))) == a1Sha);
        JsonObject forged = Payload("x");
        forged["read_disclosure_digest"] = Hex;
        failed += Check("a client-supplied read_disclosure_digest is refused",
            ThrowsWith(() => fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", forged, 2, Rid("forged")), "read_disclosure_digest"));
        byte[] a1Bytes = File.ReadAllBytes(a1Path);
        File.WriteAllText(a1Path, "{\"schema\":\"arl.response-disclosure.v1\",\"withheld_paths\":[],\"withheld_hashes\":[],\"repo_context\":[]}");
        failed += Check("altered A1 read disclosure: the next amendment is refused (REDACTION_REFUSED)",
            ThrowsWith(() => Rendered(fx, "a note", 2, Rid("tampered")), "the read disclosure record of amendment A-1"));
        File.Delete(a1Path);
        failed += Check("missing A1 read disclosure: the next amendment is refused (REDACTION_REFUSED)",
            ThrowsWith(() => Rendered(fx, "a note", 2, Rid("missing")), "the read disclosure record of amendment A-1"));
        File.WriteAllBytes(a1Path, a1Bytes);
        // The race: an amendment committed between another's prepare and its commit refuses that commit.
        string pending = Rid("a3-pending");
        Rendered(fx, "first note", 2, pending);
        string a3 = Rid("a3");
        Rendered(fx, "second note", 2, a3);
        fx.Led.Commit(a3, null);
        failed += Check("prepare/commit race: an amendment committed in between refuses the other's commit (STALE_FINDING_STATE)",
            ThrowsWith(() => fx.Led.Commit(pending, null), "STALE_FINDING_STATE"));
        // Commit without the evidence: the read disclosure removed after the prepare refuses the commit; nothing is recorded.
        string a4 = Rid("a4");
        Rendered(fx, "a fourth note", 3, a4);
        string? heldSha = (string?)fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true)["records"]![2]!["read_disclosure_digest"];
        string heldPath = StorePaths.RedactionEvidencePath(repoKey, fx.Run, heldSha ?? Hex);
        byte[] heldBytes = File.ReadAllBytes(heldPath);
        File.Delete(heldPath);
        failed += Check("commit: an amendment whose read disclosure is no longer held is not recorded (REDACTION_REFUSED)",
            ThrowsWith(() => fx.Led.Commit(a4, null), "read disclosure record") && (int?)fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true)["revision"] == 3);
        File.WriteAllBytes(heldPath, heldBytes);
        // An amendment whose read the custodian never received (the engine redacted it) makes the basis unestablished.
        Fx engineRedacted = WithBaseline("ReadDisclosureEngine");
        JsonObject engine = new()
        {
            ["kind"] = "clarification", ["text"] = "engine-redacted", ["relates_to"] = new JsonArray(), ["replaces"] = null,
            ["request_digest"] = new string('0', 64), ["disclosure_digest"] = Hex,
        };
        string e1 = Rid("e1");
        engineRedacted.Led.PrepareUserRecord(engineRedacted.Repo, engineRedacted.Run, "amendment", engine, 0, e1);
        engineRedacted.Led.Commit(e1, null);
        failed += Check("an earlier amendment with text whose read the custodian does not hold: a custodian redaction is refused",
            ThrowsWith(() => Rendered(engineRedacted, "a note", 1, Rid("after-engine")), "holds no record of what its read withheld"));
        return failed;
    }

    // ---- fixture ----

    /// <summary>Register a run with the custodian as the engine does before it consumes a loop (P3.4C-3 §1.3): a
    /// <c>run_transition open</c> on the implementer surface with a default declaration. Shared with the P3.4C-2 loop
    /// self-tests and corpus, whose loops are now minted only for an open run.</summary>
    internal static JsonObject Open(GrantLedger led, string repo, string run)
    {
        EnsureConfig(led, repo);
        return led.RunTransition(new LoopCaller(false, "proof-implementer", null), repo, RunRequest.Parse(run, "open", OpenFields(), Rid("open")));
    }

    /// <summary>P3.4C-4: a run is opened only under the repository's protected configuration; the fixture holds the default
    /// one (<see cref="ConfigFixture"/>) unless the repository already has a record — revoked or lapsed included, which a
    /// test set up on purpose.</summary>
    internal static void EnsureConfig(GrantLedger led, string repo)
    {
        if (GrantLedger.ReadConfigRecordsLocked().CurrentOf(RepoIdentities.Resolve(repo).Key) is not null) return;
        ConfigFixture.Hold(led, repo, Path.Combine(Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(repo)))!, "codex-fixture"));
    }

    /// <summary>The <c>open</c> fields of the default declaration, for a request sent over the pipe.</summary>
    internal static JsonObject DefaultOpenFields() => OpenFields();

    /// <summary>A protected, bound run: a grant, <c>open</c>, <c>consume_loop</c> (the loop is minted), <c>bind</c> from
    /// the engine's helper naming the Claude process.</summary>
    private static Fx Protected(string repos, string name, int maxReviews = 5, int maxCheckExecutions = 50, JsonObject? baseline = null)
    {
        var procs = new Table();
        var led = new GrantLedger("cust-selftest", procs);
        string repo = Directory.CreateDirectory(Path.Combine(repos, name)).FullName;
        string run = "run-" + name.ToLowerInvariant();
        ConfigFixture.Hold(led, repo, repos);
        Grant(led, repo, 2);
        Do(led, Engine, repo, run, "open", OpenFields(maxReviews: maxReviews, maxCheckExecutions: maxCheckExecutions, extra: baseline is null ? null : ("baseline", baseline)));
        JsonObject c = led.ConsumeLoop(repo, run, Rid("consume"));
        string loopId = (string)c["loopId"]!;
        led.LoopTransition(Engine, repo, LoopRequest.Parse(run, loopId, 1, 1, "bind",
            new JsonObject { ["bindNonce"] = (string)c["bindNonce"]!, ["session_id"] = "session-1", ["process"] = new JsonObject { ["pid"] = Claude } }, Rid("bind")));
        return new Fx(led, procs, repo, run, loopId);
    }

    private static void Grant(GrantLedger led, string repo, int loops)
    {
        string rid = Rid("grant");
        led.PrepareGrant(repo, loops, 60, rid);
        led.Commit(rid, null);
    }

    /// <summary>One run transition. P3.4C-5: a review's reservation is captured at once (the synthetic capture of its
    /// selected source; the commit's operationStatus, reason or deduplicatedOf are merged into the result), and the finish
    /// of a captured review names a prompt digest and an empty presentation unless the caller gave them.</summary>
    private static JsonObject Do(GrantLedger led, LoopCaller caller, string repo, string run, string kind, JsonObject fields, string? rid = null)
    {
        if (kind == "op_finish" && !fields.ContainsKey("promptDigest") && CapturedOp(repo, run, (string?)fields["operationId"]))
        {
            fields = (JsonObject)fields.DeepClone();
            fields["promptDigest"] = Hex;
            fields["presented"] = EmptyPresented();
        }
        JsonObject result = led.RunTransition(caller, repo, RunRequest.Parse(run, kind, fields, rid ?? Rid(kind)));
        bool checks = (string?)fields["operationKind"] == "checks";
        if (kind == "op_begin" && !checks && (string?)result["operationStatus"] == RunOperationStatuses.Measuring
            && CaptureFixture.Run(led, repo, run, (string)result["operationId"]!) is { } captured)
            foreach (string k in new[] { "operationStatus", "reason", "deduplicatedOf", "reviewInputId", "sourceId" })
                if (captured[k] is { } v) result[k] = v.DeepClone();
        // P3.4C-5 Increment 3 (§4): the custodian's measurement of a checks operation's start and of each execution's end.
        if (((kind == "op_begin" && checks && (string?)result["operationStatus"] == RunOperationStatuses.Measuring) || (kind == "record_execution" && (string?)result["executionStatus"] == RunOperationStatuses.Measuring))
            && CaptureFixture.Measure(led, repo, run, (string)result["operationId"]!) is { } measured)
            foreach (string k in new[] { "operationStatus", "reason", "ignoredClaims", "sourceStable", "measured" })
                if (measured[k] is { } v) result[k] = v.DeepClone();
        return result;
    }

    private static bool CapturedOp(string repo, string run, string? operationId)
        => operationId is not null && GrantLedger.ReadRunLocked(RepoIdentities.Resolve(repo).Key, run)?.Operations.FirstOrDefault(o => o.OperationId == operationId)?.Status == RunOperationStatuses.Captured;

    internal static JsonObject EmptyPresented() => new()
    {
        ["discussion"] = new JsonObject { ["digest"] = Hex, ["delivered"] = new JsonArray(), ["notDeliveredCount"] = 0 },
        ["amendments"] = new JsonObject { ["digest"] = Hex, ["presented"] = new JsonArray(), ["withheld"] = new JsonArray() },
    };
    private static JsonObject Do(Fx fx, LoopCaller caller, string kind, JsonObject fields, string? rid = null) => Do(fx.Led, caller, fx.Repo, fx.Run, kind, fields, rid);
    private static RunRecord Run(Fx fx) => GrantLedger.ReadRunLocked(RepoIdentities.Resolve(fx.Repo).Key, fx.Run)!;
    private static LoopRecord Loop(Fx fx) => fx.Led.ReadLocked().Loops!.Single(l => l.LoopId == fx.LoopId);
    private static bool IsProtected(GrantLedger led, string repo, string run) => (bool)led.ListUserRecords(repo, run, false)["protected"]!;
    private static int Events(GrantLedger led, string repo, string run) => led.ListUserRecords(repo, run, true, GrantLedger.AllSections)["run"]!["record"]!["events"]!.AsArray().Count;
    private static int LoopsUsed(GrantLedger led, string repo) => led.ReadLocked().Grants.Where(g => g.RepoKey == RepoIdentities.Resolve(repo).Key).Sum(g => g.LoopsUsed);

    /// <summary>P3.4C-5 Increment 3: the run.json bytes the self-tests' runs are opened with (their digest is the declaration's
    /// runJsonDigest), sent with a derivation request.</summary>
    internal const string RunJsonText = "{\"schema\":\"selftest\"}";
    internal static readonly string RunJsonDigest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(RunJsonText)));
    internal static string RunJsonBase64 => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(RunJsonText));

    private static JsonObject OpenFields(string? runJson = null, int maxReviews = 5, int maxCheckExecutions = 50, (string, JsonNode)? extra = null)
    {
        var o = new JsonObject
        {
            ["runJsonDigest"] = runJson ?? RunJsonDigest,
            ["budgets"] = new JsonObject { ["maxReviews"] = maxReviews, ["maxCheckExecutions"] = maxCheckExecutions },
            ["baseline"] = new JsonObject { ["sourceId"] = SrcA, ["digest"] = SrcB },
        };
        if (extra is { } x) o[x.Item1] = x.Item2;
        return o;
    }

    private static JsonObject ChecksBegin() => new()
    {
        ["operationKind"] = "checks",
        ["planned"] = new JsonArray(new JsonObject { ["check"] = "unit", ["checkSpecId"] = Hex, ["definitionDigest"] = ConfigFixture.Digest("unit"), ["required"] = true }),
        ["inputIdentity"] = Hex,
    };

    private static JsonObject Exec(string op, string id, string check = "unit", string status = "passed", string? skipReason = null) => new()
    {
        ["operationId"] = op,
        ["execution"] = new JsonObject
        {
            ["executionId"] = id, ["check"] = check, ["definitionDigest"] = ConfigFixture.Digest(check), ["checkSpecId"] = Hex, ["executionInputId"] = Hex,
            ["envDigest"] = Hex, ["freshnessDigest"] = Hex, ["status"] = status, ["skipReason"] = skipReason, ["exitCode"] = status == "passed" ? 0 : null,
            ["timedOut"] = false, ["cancelled"] = false, ["startedAt"] = "2026-10-13T10:00:00.000Z", ["endedAt"] = "2026-10-13T10:00:01.000Z",
            ["durationMs"] = 1000, ["sourceIdAtStart"] = SrcA, ["sourceIdAtEnd"] = SrcA, ["sourceStable"] = true,
            ["stdoutDigest"] = Hex, ["stderrDigest"] = Hex, ["resultDigest"] = Hex, ["limitations"] = new JsonArray(),
        },
    };

    private static JsonObject Finish(string op, JsonObject outcome) => new() { ["operationId"] = op, ["outcome"] = outcome };
    private static JsonObject ChecksOutcome(string status = "completed") => new() { ["status"] = status, ["error"] = null };

    /// <summary>A review's reservation (P3.4C-5). <paramref name="source"/> is the source the engine selected its evidence for
    /// (the synthetic capture measures it); <paramref name="reviewInput"/> distinguishes reviews' inputs (it is the claimed
    /// versions digest, part of the custodian's review input identity).</summary>
    private static JsonObject ReviewBegin(string reviewId, string source = SrcA, string reviewInput = SrcA, string[]? executions = null,
        string? amendment = null, string? deliveredItem = null, string? deliveredResponse = null, string isolation = "S1")
    {
        var offered = new JsonArray();
        if (deliveredItem is not null)
            offered.Add(new JsonObject { ["itemId"] = deliveredItem, ["responseIds"] = deliveredResponse is null ? new JsonArray() : new JsonArray(deliveredResponse), ["replyIds"] = new JsonArray() });
        var amendments = new JsonArray();
        if (amendment is not null) amendments.Add(new JsonObject { ["amendmentId"] = amendment, ["disclosureDigest"] = Hex });
        return new JsonObject
        {
            ["operationKind"] = "review", ["reviewId"] = reviewId, ["selectionSourceId"] = source, ["target"] = new JsonObject { ["kind"] = "uncommitted" },
            ["checkExecutionIds"] = new JsonArray((executions ?? []).Select(e => (JsonNode)e).ToArray()),
            ["checkEvidenceDigest"] = Hex, ["checkResultsDigest"] = Hex,
            ["discussion"] = new JsonObject { ["offered"] = offered },
            ["amendments"] = new JsonObject { ["offered"] = amendments },
            ["isolation"] = ConfigFixture.Isolation(isolation),
            ["captureRulesDigest"] = ConfigFixture.CaptureRulesDigest, ["codexSha256"] = ConfigFixture.CodexSha256,
            ["depth"] = "standard", ["focusDigest"] = null, ["versionsDigest"] = reviewInput,
        };
    }

    private static JsonObject ReviewOutcome(string status = "completed", JsonObject[]? newItems = null, JsonObject[]? assessments = null,
        JsonObject[]? replies = null, (string Kind, string Detail)[]? incidents = null, (string, JsonNode)? extra = null)
    {
        var o = new JsonObject
        {
            ["status"] = status, ["outputValid"] = status == "completed", ["currentAtCompletion"] = true, ["verdict"] = "CHANGES_REQUIRED",
            ["summaryDigest"] = Hex,
            ["artifacts"] = new JsonObject { ["rawOutput"] = Hex, ["output"] = Hex, ["items"] = Hex, ["result"] = Hex, ["events"] = Hex, ["stderr"] = Hex, ["lastMessage"] = Hex },
            ["newItems"] = new JsonArray((newItems ?? []).Select(x => (JsonNode)x).ToArray()),
            ["assessments"] = new JsonArray((assessments ?? []).Select(x => (JsonNode)x).ToArray()),
            ["replies"] = new JsonArray((replies ?? []).Select(x => (JsonNode)x).ToArray()),
            ["incidents"] = new JsonArray((incidents ?? []).Select(i => (JsonNode)new JsonObject { ["kind"] = i.Kind, ["detail"] = i.Detail }).ToArray()),
        };
        if (extra is { } x) o[x.Item1] = x.Item2;
        return o;
    }

    private static JsonObject NewItem(string id, string kind, string triage, string status, string? relatedFinding = null)
    {
        bool q = kind == "question";
        return new JsonObject
        {
            ["itemId"] = id, ["itemKind"] = kind, ["triage"] = triage,
            ["severity"] = q ? null : "high", ["claimType"] = q ? null : "defect", ["category"] = q ? null : "correctness",
            ["impacts"] = q ? new JsonArray() : new JsonArray("correctness"), ["confidence"] = q ? null : "high",
            ["status"] = status, ["relatedPriorId"] = null, ["relatedFindingId"] = relatedFinding, ["restates"] = new JsonArray(),
        };
    }

    private static JsonObject Assess(string itemId, string assessment, string? by = null) => new() { ["itemId"] = itemId, ["assessment"] = assessment, ["supersededByItemId"] = by };

    private static JsonObject Reply(string id, string itemId, string? answers) => new()
    {
        ["replyId"] = id, ["itemId"] = itemId, ["stance"] = "maintain", ["newInformation"] = "no", ["answersResponseId"] = answers, ["assessment"] = "still_present",
    };

    private static JsonObject Respond(params (string ItemId, int Base)[] responses) => new()
    {
        ["responseSetId"] = Rid("set"),
        ["disclosureDigest"] = Hex,
        ["responses"] = new JsonArray(responses.Select(r => (JsonNode)new JsonObject
        {
            ["responseId"] = Rid("resp"), ["itemId"] = r.ItemId, ["baseItemRevision"] = r.Base, ["disposition"] = "disputed", ["textWithheld"] = false,
            ["answers"] = new JsonObject { ["reviewId"] = "r1", ["round"] = 1, ["runReviewId"] = "r1", ["runRound"] = 1, ["reviewerReplyId"] = null },
            ["sourceId"] = SrcA, ["supersedes"] = null, ["threadId"] = r.ItemId,
        }).ToArray()),
    };

    private static JsonObject Recover(string op, params (string Kind, string Detail)[] incidents) => new()
    {
        ["operationId"] = op,
        ["incidents"] = new JsonArray(incidents.Select(i => (JsonNode)new JsonObject { ["kind"] = i.Kind, ["detail"] = i.Detail }).ToArray()),
    };

    private static JsonObject EndFields(string status = "closed", string reason = "done") => new() { ["status"] = status, ["reason"] = reason };

    /// <summary>A request id unique within the shared scratch store (the other self-tests use their own prefixes).</summary>
    private static string Rid(string tag) => $"rst-{tag}-{Interlocked.Increment(ref _seq)}";

    // ---- assertions ----

    /// <summary>Did <paramref name="a"/> refuse with <paramref name="code"/> (a custodian refusal's code, or
    /// INVALID_ARGUMENT for an argument exception)?</summary>
    private static bool Refused(Action a, string code)
    {
        try { a(); return false; }
        catch (CustodianRefusal r) { return r.Code == code; }
        catch (ArgumentException) { return code == ErrorCodes.InvalidArgument; }
    }

    private static bool Ok(Action a)
    {
        try { a(); return true; }
        catch (Exception e) { Console.WriteLine($"    unexpected: {e.Message}"); return false; }
    }

    private static int Temporaries(string dir) => Directory.EnumerateFiles(dir, "*.tmp-*").Count();

    private sealed class SimulatedCrash : Exception;

    private static bool Throws<T>(Action a) where T : Exception
    {
        try { a(); return false; }
        catch (T) { return true; }
    }

    private static int Check(string name, bool ok) { Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}"); return ok ? 0 : 1; }
}
