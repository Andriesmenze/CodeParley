using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-3 increment 4: the changes inside existing operations (contract §3.4) — <c>consume_loop</c> needs an open run,
/// every loop transition reads the run record, protected decisions are bound to the covered items' revisions, refusals
/// are audited — and the deterministic interleavings across the run and ledger stores (N17) and of protected decisions
/// with run transitions (N18): a self-test-only hook pauses a holder at a named point inside its hold of the single
/// lock while another thread issues the competing request.
/// </summary>
internal static partial class RunSelfTest
{
    /// <summary>A second instance of the session's host (the Claude process restarted, same session id): 110 → 210 →
    /// 310 (its helper), for a rebind of another process.</summary>
    private const int Claude2 = 110, Server2 = 210, Helper2 = 310;
    private static readonly LoopCaller Engine2 = new(false, "proof-implementer", Helper2);

    private static void AddSecondHost(Table procs)
    {
        procs.Entries[Claude2] = new(Claude2, 1, T0 + 20 * Second, "claude.exe");
        procs.Entries[Server2] = new(Server2, Claude2, T0 + 21 * Second, "node.exe");
        procs.Entries[Helper2] = new(Helper2, Server2, T0 + 22 * Second, "powershell.exe");
    }

    // ---- §3.4(1): consume_loop ----

    private static int ConsumePreconditionCases(string repos)
    {
        int failed = 0;
        var led = new GrantLedger("cust-selftest", new Table());
        string repo = Directory.CreateDirectory(Path.Combine(repos, "RunConsume")).FullName;
        Grant(led, repo, 2);
        failed += Check("consume_loop for a run the custodian never opened → RUN_NOT_OPEN, nothing consumed",
            Refused(() => led.ConsumeLoop(repo, "run-unopened", Rid("c")), ErrorCodes.RunNotOpen) && LoopsUsed(led, repo) == 0);
        Open(led, repo, "run-ended");
        Do(led, Engine, repo, "run-ended", "end", EndFields());
        failed += Check("consume_loop for a run that has ended → RUN_TERMINAL, nothing consumed",
            Refused(() => led.ConsumeLoop(repo, "run-ended", Rid("c")), ErrorCodes.RunTerminal) && LoopsUsed(led, repo) == 0);
        Open(led, repo, "run-open");
        failed += Check("consume_loop for an open run mints its loop (1 of 2)", (int)led.ConsumeLoop(repo, "run-open", Rid("c"))["loopsUsed"]! == 1);
        return failed;
    }

    // ---- §3.4(3): loop_transition reads the run record ----

    private static int LoopReadsRunCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunLoopMissing");
        File.Delete(StorePaths.RunPath(RepoIdentities.Resolve(fx.Repo).Key, fx.Run)); // a rollback, or a loop minted before P3.4C-3
        failed += Check("a loop transition whose run record is missing ends the loop by derivation (run_ended) and authorizes nothing (LOOP_TERMINAL)",
            Refused(() => Spend(fx, Engine), ErrorCodes.LoopTerminal) && Loop(fx) is { Status: "run_ended", Ended: { By: "custodian", Reason: "run_record_missing" } });
        Fx fx2 = Protected(repos, "RunLoopWake");
        string op = (string)Do(fx2, Engine, "op_begin", ChecksBegin())["operationId"]!;
        JsonObject armed = Loop(fx2) is var l ? fx2.Led.LoopTransition(Engine, fx2.Repo, LoopRequest.Parse(fx2.Run, fx2.LoopId, l.Epoch, l.LoopRevision, "wake_arm",
            new JsonObject { ["operationHandle"] = l.CurrentOperation!.Handle, ["session_id"] = "session-1" }, Rid("arm"))) : null!;
        WriteRunEndedWithoutLoopEnd(fx2);
        JsonObject consumed = WakeConsume(fx2, (string)armed["claimId"]!);
        failed += Check("a wake consume once the run has ended answers dispatchAuthorized:false and the loop ends (run_ended)",
            (bool?)consumed["dispatchAuthorized"] == false && Loop(fx2).Status == "run_ended" && op.Length > 0);
        return failed;
    }

    // ---- §3.4(2): protected decisions ----

    private static int DecisionFreshnessCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RunDecide");
        string op = (string)Do(fx, Engine, "op_begin", ReviewBegin("r1"))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op, ReviewOutcome(newItems: [NewItem("d1", "finding", "established_defect", "open"), NewItem("d2", "finding", "serious_concern", "open")])));

        failed += Check("prepare: a covered item that is not open → STALE_FINDING_STATE", RefusedAny(() => Prepare(fx, ["nope"], "r1", 1), ErrorCodes.StaleState));
        failed += Check("prepare: naming another review than the run's latest accepted one → STALE_FINDING_STATE", RefusedAny(() => Prepare(fx, ["d1"], "r0", 1), ErrorCodes.StaleState));
        string resp = (string)Do(fx, Engine, "respond", Respond(("d1", 1)))["responseIds"]![0]!;
        failed += Check("prepare: a response on a covered item newer than the one named (none) → STALE_FINDING_STATE",
            RefusedAny(() => Prepare(fx, ["d1"], "r1", 1), ErrorCodes.StaleState));
        failed += Check("prepare: the decision's view is current (latest response named) → prepared", OkAny(() => Prepare(fx, ["d1"], "r1", 1, latestResponse: resp)));

        string stale = Prepare(fx, ["d1"], "r1", 1, latestResponse: resp);
        Do(fx, Engine, "respond", Respond(("d1", 2)));
        failed += Check("commit after a transition touched a covered item (a response: revision 2 → 3) → STALE_FINDING_STATE",
            RefusedAny(() => fx.Led.Commit(stale, null), ErrorCodes.StaleState));
        string other = Prepare(fx, ["d2"], "r1", 1);
        Do(fx, Engine, "respond", Respond(("d1", 3)));
        failed += Check("commit after a transition touching NO covered item → committed", OkAny(() => fx.Led.Commit(other, null)));

        string ended = Prepare(fx, ["d2"], "r1", 1);
        Do(fx, Engine, "end", EndFields("stopped"));
        failed += Check("commit after the run ended between prepare and commit → RUN_TERMINAL", Refused(() => fx.Led.Commit(ended, null), ErrorCodes.RunTerminal));
        failed += Check("prepare on an ended run → RUN_TERMINAL", Refused(() => Prepare(fx, ["d2"], "r1", 1), ErrorCodes.RunTerminal));

        Fx legacy = Protected(repos, "RunDecideLegacy");
        File.Delete(StorePaths.RunPath(RepoIdentities.Resolve(legacy.Repo).Key, legacy.Run));
        failed += Check("prepare on a protected run whose run record is missing → RUN_NOT_OPEN (its state cannot be verified)",
            Refused(() => Prepare(legacy, ["x"], null, null), ErrorCodes.RunNotOpen));
        return failed;
    }

    // ---- §3.4(4): refusal audit ----

    private static int RefusalAuditCases(string repos)
    {
        int failed = 0;
        var core = new CustodianCore("cust-selftest");
        string repo = Directory.CreateDirectory(Path.Combine(repos, "RunAudit")).FullName.Replace('\\', '/');
        string run = "run-audit-" + Guid.NewGuid().ToString("N")[..8];
        Request Req(string rid) => Request.Parse("{\"v\":1,\"requestId\":\"" + rid + "\",\"op\":\"run_transition\",\"args\":{\"repositoryRoot\":\"" + repo + "\",\"runId\":\"" + run + "\",\"kind\":\"end\",\"fields\":{\"status\":\"closed\",\"reason\":\"SECRET-PAYLOAD\"}}}");
        int before = AuditLines(run);
        Response r1 = core.Handle(CallerClass.Implementer, Req(Rid("a")), null, 4242);
        Response r2 = core.Handle(CallerClass.Implementer, Req(Rid("a")), null, 4242);
        List<string> lines = File.ReadAllLines(StorePaths.AuditPath).Where(l => l.Contains(run, StringComparison.Ordinal)).ToList();
        failed += Check("a refused run_transition is audited once per (run, code) per minute: code, kind, caller, client pid, run id — never the payload",
            !r1.Ok && !r2.Ok && r1.Code == ErrorCodes.RunNotOpen && AuditLines(run) == before + 1
            && lines[^1].Contains("code=RUN_NOT_OPEN", StringComparison.Ordinal) && lines[^1].Contains("kind=end", StringComparison.Ordinal)
            && lines[^1].Contains("clientPid=4242", StringComparison.Ordinal) && !lines[^1].Contains("SECRET-PAYLOAD", StringComparison.Ordinal));
        return failed;
    }

    private static int AuditLines(string run) => File.Exists(StorePaths.AuditPath) ? File.ReadAllLines(StorePaths.AuditPath).Count(l => l.Contains(run, StringComparison.Ordinal) && l.Contains("refused", StringComparison.Ordinal)) : 0;

    // ---- N17: interleavings across the run and ledger stores ----

    private static int InterleavingCases(string repos)
    {
        int failed = 0;

        // (a) op_begin paused after its binding check while a rebind of another process arrives: the rebind waits; the
        // operation is recorded under the binding it checked; the next request is judged against the new binding.
        Fx a = Protected(repos, "N17a");
        AddSecondHost(a.Procs);
        var (begin, rebind, rebindWaited) = Interleave(HoldPoints.OpBeginBoundChecked, () => Do(a, Engine, "op_begin", ChecksBegin()), () => Rebind(a, Engine2, Claude2));
        failed += Check("N17 (a): a rebind waits for an op_begin paused after its binding check; the op_begin commits with the binding it checked",
            rebindWaited && begin.Code is null && rebind.Code is null && Run(a).Operations.Single().Writer.Pid == Server);
        failed += Check("N17 (a): the next request is judged against the new binding (the old process tree is refused)",
            Refused(() => Do(a, Engine, "respond", Respond(("x", 1))), ErrorCodes.ProcessIdentityUnverified));

        // (b) end paused between its run write and its ledger write: a concurrent spend waits, then authorizes nothing.
        Fx b = Protected(repos, "N17b");
        var (endB, spendB, spendWaited) = Interleave(HoldPoints.EndRunWritten, () => Do(b, Engine, "end", EndFields("stopped")), () => Spend(b, Engine));
        failed += Check("N17 (b): a spend waits for an end paused between its two writes, then authorizes nothing (LOOP_TERMINAL)",
            spendWaited && endB.Code is null && spendB.Code == ErrorCodes.LoopTerminal && Loop(b).Used.Continuations == 0 && Loop(b).Status == "run_ended");

        // (c) a spend paused after authorizing: a concurrent end waits and commits after it.
        Fx c = Protected(repos, "N17c");
        var (spendC, endC, endWaited) = Interleave(HoldPoints.LoopAuthorized + "spend_continuation", () => Spend(c, Engine), () => Do(c, Engine, "end", EndFields("stopped")));
        failed += Check("N17 (c): an end waits for a spend paused after authorizing, and commits after it (the spend counted, then the loop ends)",
            endWaited && spendC.Code is null && endC.Code is null && (bool)endC.Result!["loopEnded"]! && Loop(c) is { Status: "run_ended", Used.Continuations: 1 });

        // (d) the service stops between end's two writes: the next loop transition derives the loop's end.
        Fx d = Protected(repos, "N17d");
        var (endD, _, _) = Interleave(HoldPoints.EndRunWritten, () => Do(d, Engine, "end", EndFields("stopped")), () => new JsonObject(), crashAtPoint: true);
        bool loopStillLive = Loop(d).Status == "active";
        failed += Check("N17 (d): after a stop between end's two writes the run is terminal and the loop not yet ended; the next spend derives its end and authorizes nothing",
            endD.Code == "CRASH" && Run(d).Status == "stopped" && loopStillLive
            && Refused(() => Spend(d, Engine), ErrorCodes.LoopTerminal) && Loop(d) is { Status: "run_ended", Used.Continuations: 0 });

        // (e) consume_loop against a concurrent end, in both orders.
        var proc = new Table();
        var led = new GrantLedger("cust-selftest", proc);
        string repo = Directory.CreateDirectory(Path.Combine(repos, "N17e")).FullName;
        Grant(led, repo, 2);
        Open(led, repo, "run-e1");
        var (consume1, end1, end1Waited) = Interleave(HoldPoints.ConsumeChecked, () => led.ConsumeLoop(repo, "run-e1", Rid("c")), () => Do(led, Engine, repo, "run-e1", "end", EndFields("stopped")));
        failed += Check("N17 (e1): an end waits for a consume paused after its checks; the loop is minted, then ended with the run",
            end1Waited && consume1.Code is null && end1.Code is null && (bool)end1.Result!["loopEnded"]! && led.ReadLocked().Loops!.Single(l => l.RunId == "run-e1").Status == "run_ended");
        Open(led, repo, "run-e2");
        int used = LoopsUsed(led, repo);
        var (end2, consume2, consume2Waited) = Interleave(HoldPoints.EndRunWritten, () => Do(led, Engine, repo, "run-e2", "end", EndFields("stopped")), () => led.ConsumeLoop(repo, "run-e2", Rid("c")));
        failed += Check("N17 (e2): a consume waits for an end paused after its run write, then is refused (RUN_TERMINAL) and consumes nothing",
            consume2Waited && end2.Code is null && consume2.Code == ErrorCodes.RunTerminal && LoopsUsed(led, repo) == used);

        // (f) randomized stress: in the custodian's single commit order, nothing is authorized after the run's terminal
        // transition.
        failed += StressCase(repos);
        return failed;
    }

    /// <summary>N17 (f): threads spend, arm wakes and end the run concurrently. The hold points record the single
    /// commit order (they run inside the lock); after the run's terminal write, no spend or wake is authorized.</summary>
    private static int StressCase(string repos)
    {
        int violations = 0, trials = 0, unexpected = 0;
        for (int trial = 0; trial < 8; trial++)
        {
            Fx fx = Protected(repos, $"N17f{trial}");
            var order = new System.Collections.Concurrent.ConcurrentQueue<string>();
            GrantLedger.HoldHook = p => order.Enqueue(p);
            try
            {
                var rnd = new Random(trial);
                int endAt = rnd.Next(0, 6);
                var tasks = Enumerable.Range(0, 8).Select(i => Task.Run(() =>
                {
                    for (int k = 0; k < 6; k++)
                    {
                        try
                        {
                            if (i == 0 && k == endAt) Do(fx, Engine, "end", EndFields("stopped"));
                            else if ((i + k) % 2 == 0) Spend(fx, Engine);
                            else if (Loop(fx) is { CurrentOperation: { } op } l && l.Status == "active")
                                fx.Led.LoopTransition(Engine, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, l.Epoch, l.LoopRevision, "wake_arm",
                                    new JsonObject { ["operationHandle"] = op.Handle, ["session_id"] = "session-1" }, Rid("arm")));
                        }
                        catch (CustodianRefusal) { }
                        catch (Exception) { Interlocked.Increment(ref unexpected); }
                    }
                })).ToArray();
                if (!Task.WaitAll(tasks, TimeSpan.FromSeconds(30))) violations++;
            }
            finally { GrantLedger.HoldHook = null; }
            List<string> seq = [.. order];
            int endIndex = seq.IndexOf(HoldPoints.EndRunWritten);
            if (endIndex >= 0 && seq.Skip(endIndex + 1).Any(p => p.StartsWith(HoldPoints.LoopAuthorized, StringComparison.Ordinal))) violations++;
            trials++;
        }
        return Check($"N17 (f): {trials} randomized trials — no spend or wake authorized after the run's terminal write, no deadlock ({violations} violations, {unexpected} unexpected errors)", violations == 0 && unexpected == 0);
    }

    // ---- N18: protected decision concurrency ----

    private static int DecisionConcurrencyCases(string repos)
    {
        int failed = 0;

        // (a) commit paused after its freshness check: an op_finish assessing a covered item waits; the decision commits
        // first, the assessment after it.
        Fx a = ReviewedRun(repos, "N18a", out string opA);
        string ridA = Prepare(a, ["n1"], "r1", 1);
        var (commitA, finishA, finishWaited) = Interleave(HoldPoints.CommitFresh, () => a.Led.Commit(ridA, null), () => Do(a, Engine, "op_finish", Finish(opA, ReviewOutcome(assessments: [Assess("n1", "still_present"), Assess("n2", "still_present")]))));
        failed += Check("N18 (a): an op_finish assessing a covered item waits for a commit paused after its freshness check; the decision commits first",
            finishWaited && commitA.Code is null && finishA.Code is null && Run(a).Items.Single(i => i.ItemId == "n1").ItemRevision == 2 && Decisions(a) == 1);

        // (b) the assessment first: the commit is refused.
        Fx b = ReviewedRun(repos, "N18b", out string opB);
        string ridB = Prepare(b, ["n1"], "r1", 1);
        Do(b, Engine, "op_finish", Finish(opB, ReviewOutcome(assessments: [Assess("n1", "still_present"), Assess("n2", "still_present")])));
        failed += Check("N18 (b): the assessment first → the commit refuses STALE_FINDING_STATE", RefusedAny(() => b.Led.Commit(ridB, null), ErrorCodes.StaleState) && Decisions(b) == 0);

        // (c) an end between prepare and commit → RUN_TERMINAL; (d) a transition touching no covered item → committed.
        Fx c = ReviewedRun(repos, "N18c", out _);
        string ridC = Prepare(c, ["n1"], "r1", 1);
        Do(c, Engine, "end", EndFields("stopped"));
        failed += Check("N18 (c): an end between prepare and commit → RUN_TERMINAL", Refused(() => c.Led.Commit(ridC, null), ErrorCodes.RunTerminal));
        Fx d = ReviewedRun(repos, "N18d", out string opD);
        Do(d, Engine, "op_finish", Finish(opD, ReviewOutcome(assessments: [Assess("n1", "still_present"), Assess("n2", "still_present")])));
        string ridD = Prepare(d, ["n1"], "r2", 2);
        Do(d, Engine, "respond", Respond(("n2", 2))); // n2 was assessed by r2 (revision 2)
        failed += Check("N18 (d): a transition touching no covered item between prepare and commit → committed", OkAny(() => d.Led.Commit(ridD, null)) && Decisions(d) == 1);

        // (e) stress: concurrent decisions (on varying items), responses and protected amendments (which take the
        // content-key validation lock inside the ledger lock): no deadlock, no lock-order violation, and every
        // committed decision was fresh at its commit (the commit re-derives the covered items' revisions).
        failed += DecisionStressCase(repos);
        return failed;
    }

    private static int DecisionStressCase(string repos)
    {
        // A store of its own: an earlier self-test deliberately corrupts the shared store's content-key secret, which
        // fails protected amendments closed there.
        string original = StorePaths.Root;
        StorePaths.OverrideRootForSelfTest(Path.Combine(Path.GetDirectoryName(original.TrimEnd('\\'))!, "n18e-store", "Custodian"));
        Directory.CreateDirectory(StorePaths.IntentsDir);
        try { return DecisionStress(repos); }
        finally { StorePaths.OverrideRootForSelfTest(original); }
    }

    private static int DecisionStress(string repos)
    {
        Fx fx = ReviewedRun(repos, "N18e", out string op);
        Do(fx, Engine, "op_finish", Finish(op, ReviewOutcome(assessments: [Assess("n1", "still_present"), Assess("n2", "still_present")])));
        int committed = 0, stale = 0, other = 0;
        var errors = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var tasks = new List<Task>();
        for (int i = 0; i < 4; i++)
        {
            int t = i;
            tasks.Add(Task.Run(() =>
            {
                for (int k = 0; k < 6; k++)
                {
                    try
                    {
                        string item = (t + k) % 2 == 0 ? "n1" : "n2";
                        RunRecord now = Run(fx);
                        string? latest = now.Responses.LastOrDefault(r => (string?)r["itemId"] == item)?["responseId"]?.ToString();
                        string rid = Prepare(fx, [item], "r2", 2, latestResponse: latest);
                        fx.Led.Commit(rid, null);
                        Interlocked.Increment(ref committed);
                    }
                    catch (CustodianRefusal r) when (r.Code == ErrorCodes.StaleState) { Interlocked.Increment(ref stale); }
                    catch (InvalidOperationException e) when (e.Message.Contains("STALE_FINDING_STATE", StringComparison.Ordinal)) { Interlocked.Increment(ref stale); }
                    catch (Exception e) { Interlocked.Increment(ref other); errors.Enqueue(e.Message); }
                }
            }));
        }
        tasks.Add(Task.Run(() =>
        {
            for (int k = 0; k < 8; k++)
            {
                try
                {
                    RunItem it = Run(fx).Items.Single(i => i.ItemId == (k % 2 == 0 ? "n1" : "n2"));
                    Do(fx, Engine, "respond", Respond((it.ItemId, it.ItemRevision)));
                }
                catch (CustodianRefusal) { }
            }
        }));
        tasks.Add(Task.Run(() =>
        {
            for (int k = 0; k < 3; k++)
            {
                try
                {
                    string rid = Rid("amd");
                    int rev = fx.Led.ListUserRecords(fx.Repo, fx.Run, true)["revision"]!.GetValue<int>();
                    fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "amendment", new JsonObject { ["kind"] = "clarification", ["text"] = $"guidance {k}", ["disclosure_digest"] = Hex }, rev, rid);
                    fx.Led.Commit(rid, null);
                }
                catch (InvalidOperationException e) when (e.Message.Contains("STALE_FINDING_STATE", StringComparison.Ordinal)) { }
                catch (Exception e) { errors.Enqueue("amendment: " + e.Message); }
            }
        }));
        bool done = Task.WaitAll([.. tasks], TimeSpan.FromSeconds(60));
        foreach (string e in errors.Take(5)) Console.WriteLine($"    unexpected: {e}");
        if (Decisions(fx) != committed) Console.WriteLine($"    decisions recorded {Decisions(fx)}, committed {committed}");
        return Check($"N18 (e): concurrent decisions, responses and amendments — no deadlock, no lock-order violation ({committed} committed, {stale} refused stale, {other} other)",
            done && other == 0 && errors.IsEmpty && committed > 0 && Decisions(fx) == committed);
    }

    // ---- helpers ----

    /// <summary>A protected run with an accepted first review (items n1, n2 open) and a second review running.</summary>
    private static Fx ReviewedRun(string repos, string name, out string runningReviewOp)
    {
        Fx fx = Protected(repos, name);
        string op1 = (string)Do(fx, Engine, "op_begin", ReviewBegin("r1"))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op1, ReviewOutcome(newItems: [NewItem("n1", "finding", "established_defect", "open"), NewItem("n2", "finding", "serious_concern", "open")])));
        runningReviewOp = (string)Do(fx, Engine, "op_begin", ReviewBegin("r2", source: SrcB, reviewInput: SrcB))["operationId"]!;
        return fx;
    }

    /// <summary>Prepare a protected decision on <paramref name="covered"/> against the named review; returns the request id.</summary>
    private static string Prepare(Fx fx, string[] covered, string? reviewId, int? round, string? latestResponse = null, string? latestReply = null)
    {
        string rid = Rid("dec");
        int rev = fx.Led.ListUserRecords(fx.Repo, fx.Run, true)["revision"]!.GetValue<int>();
        var payload = new JsonObject
        {
            ["kind"] = "defer", ["note"] = "", ["thread_id"] = covered[0], ["current_item_id"] = covered[^1],
            ["covered_items"] = new JsonArray(covered.Select(x => (JsonNode)x).ToArray()),
            ["decided_against"] = new JsonObject
            {
                ["token"] = "t", ["run_review_id"] = reviewId, ["run_round"] = round, ["latest_reply_id"] = latestReply,
                ["latest_response_id"] = latestResponse, ["amendments_seq"] = 0,
            },
            ["request_digest"] = "d",
        };
        fx.Led.PrepareUserRecord(fx.Repo, fx.Run, "decision", payload, rev, rid);
        return rid;
    }

    private static int Decisions(Fx fx) => fx.Led.ListUserRecords(fx.Repo, fx.Run, true)["records"]!.AsArray().Count(r => (string?)r!["recordKind"] == "decision");

    private static JsonObject Spend(Fx fx, LoopCaller caller)
    {
        LoopRecord l = Loop(fx);
        return fx.Led.LoopTransition(caller, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, l.Epoch, l.LoopRevision, "spend_continuation", LoopSelfTest.WithDerivation(fx.Led, fx.Repo, fx.Run, new JsonObject { ["session_id"] = "session-1" }), Rid("spend")));
    }

    private static JsonObject Rebind(Fx fx, LoopCaller caller, int pid)
    {
        LoopRecord l = Loop(fx);
        return fx.Led.LoopTransition(caller, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, l.Epoch, l.LoopRevision, "rebind",
            new JsonObject { ["session_id"] = "session-1", ["process"] = new JsonObject { ["pid"] = pid } }, Rid("rebind")));
    }

    private static JsonObject WakeConsume(Fx fx, string claimId)
    {
        LoopRecord l = Loop(fx);
        return fx.Led.LoopTransition(Engine, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, l.Epoch, l.LoopRevision, "wake_consume",
            LoopSelfTest.WithDerivation(fx.Led, fx.Repo, fx.Run, new JsonObject { ["claimId"] = claimId, ["session_id"] = "session-1" }), Rid("consume")));
    }

    /// <summary>Make the run terminal on disk without the loop's derived end — what a stop between end's two writes leaves.</summary>
    private static void WriteRunEndedWithoutLoopEnd(Fx fx)
    {
        RunRecord run = Run(fx);
        GrantLedger.WriteRun(run with { Status = RunStatuses.Stopped, Ended = new RunEnded(RunStatuses.Stopped, "test", DateTime.UtcNow.ToString("o"), "implementer") });
    }

    private sealed record Outcome(JsonObject? Result, string? Code);

    /// <summary>Run <paramref name="first"/> on its own thread until it reaches <paramref name="point"/> inside its hold
    /// of the ledger lock (it pauses there — or, with <paramref name="crashAtPoint"/>, fails there as a stopped service
    /// would), then start <paramref name="second"/> and observe whether it had to wait, release the first, and return
    /// both outcomes.</summary>
    private static (Outcome First, Outcome Second, bool SecondWaited) Interleave(string point, Func<JsonObject> first, Func<JsonObject> second, bool crashAtPoint = false)
    {
        using var reached = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        int firstThread = -1;
        GrantLedger.HoldHook = p =>
        {
            if (p != point || Environment.CurrentManagedThreadId != Volatile.Read(ref firstThread)) return;
            reached.Set();
            if (crashAtPoint) throw new SimulatedCrash();
            release.Wait(TimeSpan.FromSeconds(10));
        };
        try
        {
            var a = Task.Factory.StartNew(() => { Volatile.Write(ref firstThread, Environment.CurrentManagedThreadId); return Capture(first); }, TaskCreationOptions.LongRunning);
            if (!reached.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException($"the hold point {point} was not reached");
            if (crashAtPoint)
            {
                a.Wait(TimeSpan.FromSeconds(10));
                return (a.Result, new Outcome(null, null), false);
            }
            var b = Task.Factory.StartNew(() => Capture(second), TaskCreationOptions.LongRunning);
            bool waited = !b.Wait(TimeSpan.FromMilliseconds(400));
            release.Set();
            if (!Task.WaitAll([a, b], TimeSpan.FromSeconds(20))) throw new TimeoutException("an interleaved request did not complete (deadlock?)");
            return (a.Result, b.Result, waited);
        }
        finally { GrantLedger.HoldHook = null; }
    }

    private static Outcome Capture(Func<JsonObject> f)
    {
        try { return new Outcome(f(), null); }
        catch (CustodianRefusal r) { return new Outcome(null, r.Code); }
        catch (SimulatedCrash) { return new Outcome(null, "CRASH"); }
        catch (InvalidOperationException e) when (e.Message.Contains("STALE_FINDING_STATE", StringComparison.Ordinal)) { return new Outcome(null, ErrorCodes.StaleState); }
        catch (ArgumentException) { return new Outcome(null, ErrorCodes.InvalidArgument); }
    }

    /// <summary>As <see cref="Refused"/>, also for the ledger's message-coded refusals (STALE_FINDING_STATE at commit).</summary>
    private static bool RefusedAny(Action a, string code)
    {
        try { a(); return false; }
        catch (CustodianRefusal r) { return r.Code == code; }
        catch (InvalidOperationException e) { return e.Message.Contains($"({code})", StringComparison.Ordinal); }
        catch (ArgumentException) { return code == ErrorCodes.InvalidArgument; }
    }

    private static bool OkAny(Action a) => Ok(a);
}
