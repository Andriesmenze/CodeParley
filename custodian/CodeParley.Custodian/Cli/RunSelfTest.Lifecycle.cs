using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 Increment 4 — the lifecycle of the custodian's measurements beyond the shared corpus:
/// <list type="bullet">
/// <item>N5-13 lock discipline: with a hold point INSIDE a measurement (a capture, a checks operation's start, a spend's
/// re-measurement), other runs' transitions, the operator's configuration writes and reads all proceed — the gate is not
/// held across a helper invocation; a revocation committed meanwhile ends the commit <c>basis_changed</c>; a cancellation
/// ends it <c>cancelled</c> with nothing recorded; a transition on the run makes the spend's derivation stale.</item>
/// <item>N5-11: a helper that crashes mid-measurement leaves no partial authority (<c>measurement_failed</c>, nothing
/// published or recorded).</item>
/// <item>N5-18 for checks: a restart with a checks operation measuring its start and one with an execution pending interrupt
/// the first and record the second without its end; the previous instance's late results are refused.</item>
/// </list>
/// </summary>
internal static partial class RunSelfTest
{
    private static readonly TimeSpan HoldWait = TimeSpan.FromSeconds(20);

    private static int MeasurementLifecycleCases(string repos)
    {
        int failed = 0;
        failed += WithFreshStore("lifecycle-capture-hold", () => CaptureHoldCases(repos));
        failed += WithFreshStore("lifecycle-capture-cancel", () => CaptureCancelHoldCases(repos));
        failed += WithFreshStore("lifecycle-checks-hold", () => ChecksHoldCases(repos));
        failed += WithFreshStore("lifecycle-spend-hold", () => SpendHoldCases(repos));
        failed += WithFreshStore("lifecycle-helper-crash", () => HelperCrashCases(repos));
        failed += WithFreshStore("lifecycle-checks-restart", () => ChecksRestartCases(repos));
        failed += WithFreshStore("lifecycle-runtime-drift", () => RuntimeDriftCases(repos));
        failed += WithFreshStore("lifecycle-repository-readers", () => RepositoryReadersCases(repos));
        return failed;
    }

    /// <summary>
    /// N5-8: a repository the helper's group cannot read is refused when the operator protects it (<c>config set</c>), at a
    /// protected reservation and at a derivation — <c>REPOSITORY_NOT_READABLE</c> with the exact <c>icacls</c> remedy, nothing
    /// begun. Granting it as instructed (the real <c>icacls</c>, on the repository only) changes no parent folder's access
    /// control, and the repository is then accepted.
    /// </summary>
    private static int RepositoryReadersCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "Readers");
        var readers = new System.Security.Principal.SecurityIdentifier("S-1-5-32-547"); // a stand-in for the group (no ACE on the test tree)
        fx.Led.AttachRepositoryReaders(new Principal(readers.Value, readers.Value), "Test Repository Readers");
        string? message = null;
        bool begin = false;
        try { fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ChecksBegin(), Rid("op_begin"))); }
        catch (CustodianRefusal e) { begin = e.Code == ErrorCodes.RepositoryNotReadable; message = e.Message; }
        failed += Check("N5-8: a protected reservation on a repository the helper's group cannot read → REPOSITORY_NOT_READABLE with the icacls remedy on the repository only; nothing begun",
            begin && message!.Contains($"icacls \"{RepoIdentities.Resolve(fx.Repo).CanonicalPath}\" /grant \"*S-1-5-32-547:(OI)(CI)(RX)\"", StringComparison.Ordinal) && Run(fx).Operations.Count == 0);
        failed += Check("N5-8: the operator's config set of that repository is refused the same way",
            Refused(() => ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(repos, variant: 7))), ErrorCodes.RepositoryNotReadable));
        JsonObject d = fx.Led.DerivationSection(fx.Repo, fx.Run, RunJsonBase64);
        failed += Check("N5-8: ... and no derivation is served (unavailable, REPOSITORY_NOT_READABLE)", (bool?)d["available"] == false && (string?)d["code"] == ErrorCodes.RepositoryNotReadable);

        string root = RepoIdentities.Resolve(fx.Repo).CanonicalPath;
        string Sddl(string p) => new DirectoryInfo(p).GetAccessControl().GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
        string parent = Path.GetDirectoryName(root)!, grand = Path.GetDirectoryName(parent)!;
        (string p0, string g0) = (Sddl(parent), Sddl(grand));
        var icacls = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("icacls.exe", $"\"{root}\" /grant \"*S-1-5-32-547:(OI)(CI)(RX)\"") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        icacls.StandardOutput.ReadToEnd();
        icacls.WaitForExit();
        failed += Check("N5-8: the remedy (icacls on the repository) adds no ACE on any parent folder",
            icacls.ExitCode == 0 && Sddl(parent) == p0 && Sddl(grand) == g0 && new WindowsAccessPublisher().RepositoryReadersProblem(root, new Principal(readers.Value, readers.Value)) is null);
        JsonObject ok = fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ChecksBegin(), Rid("op_begin")));
        failed += Check("N5-8: once granted, the reservation is accepted (the custodian measures its start)", (string?)ok["operationStatus"] == RunOperationStatuses.Measuring);
        return failed;
    }

    /// <summary>
    /// N5-6 at use: the REAL helper runners re-measure the approved runtime before they launch anything. A file changed in
    /// the runtime's <c>dist/</c> since its approval refuses a checks operation's start and a capture (<c>runtime_changed</c>,
    /// with the operator's remedy); the broker is never reached and there is no fallback.
    /// </summary>
    private static int RuntimeDriftCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "RuntimeDrift");
        string root = GrantLedger.ReadConfigRecordsLocked().CurrentRuntime!.Root;
        File.AppendAllText(Path.Combine(root, "dist", "helper", "main.js"), "// changed after the approval\n");
        fx.Led.AttachMeasurement(new HelperMeasurementRunner(null!)); // the broker is never reached
        string cop = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ChecksBegin(), Rid("op_begin")))["operationId"]!;
        fx.Led.RunReservedCheckMeasurement(cop);
        RunOperation co = Run(fx).Operations.First(x => x.OperationId == cop);
        failed += Check("N5-6 (use): a runtime file changed since the approval refuses a checks operation's start (runtime_changed, the remedy named); no check runs",
            co.Status == RunOperationStatuses.Error && (string?)co.Outcome?["reason"] == "runtime_changed" && ((string?)co.Outcome?["detail"] ?? "").Contains("approves it again", StringComparison.Ordinal));
        fx.Led.SetCaptureRunnerForTest(new HelperCaptureRunner(null!));
        string rop = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("rd1"), Rid("op_begin")))["operationId"]!;
        fx.Led.RunReservedCapture(rop);
        RunOperation ro = Run(fx).Operations.First(x => x.OperationId == rop);
        failed += Check("N5-6 (use): ... and a capture (runtime_changed); nothing is captured or published",
            ro.Status == RunOperationStatuses.Error && (string?)ro.Outcome?["reason"] == "runtime_changed" && ExportDirs().Length == 0);
        fx.Led.AttachMeasurement(CaptureFixture.Measurements);
        return failed;
    }

    /// <summary>A hold point inside a measurement: the runner signals it entered, then waits for the release (or the
    /// cancellation) before it measures.</summary>
    private sealed class Hold
    {
        internal readonly ManualResetEventSlim Entered = new(false), Release = new(false);
        internal bool Wait(CancellationToken ct)
        {
            Entered.Set();
            try { Release.Wait(TimeSpan.FromSeconds(60), ct); return true; }
            catch (OperationCanceledException) { return false; }
        }
    }

    private sealed class HoldingCaptureRunner(IReviewCaptureRunner inner, Hold hold) : IReviewCaptureRunner
    {
        public async Task<HelperJobOutcome> RunAsync(CaptureLaunch l, CaptureJob job, CancellationToken ct)
        {
            if (Monitor.IsEntered(LockProbe.Gate)) throw new InvalidOperationException("the ledger lock is held across a helper invocation");
            if (!hold.Wait(ct)) return new HelperJobOutcome(false, ErrorCodes.MeasurementCancelled, "cancelled at the hold point", "", null);
            return await inner.RunAsync(l, job, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Holds the <paramref name="holdOn"/>-th measurement (1-based); the others measure at once.</summary>
    private sealed class HoldingMeasurementRunner(IMeasurementRunner inner, Hold hold, int holdOn = 1) : IMeasurementRunner
    {
        private int _calls;
        public Task<MeasureOutcome> RunAsync(MeasureLaunch l, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _calls) == holdOn && !hold.Wait(ct)) return Task.FromResult(MeasureOutcome.Failed(ErrorCodes.MeasurementCancelled, "cancelled at the hold point"));
            return inner.RunAsync(l, ct);
        }
    }

    private sealed class CrashingCaptureRunner : IReviewCaptureRunner
    {
        public Task<HelperJobOutcome> RunAsync(CaptureLaunch l, CaptureJob job, CancellationToken ct) => throw new IOException("the helper's channel closed (the helper process ended)");
    }

    private sealed class CrashingMeasurementRunner : IMeasurementRunner
    {
        public Task<MeasureOutcome> RunAsync(MeasureLaunch l, CancellationToken ct) => throw new IOException("the helper's channel closed (the helper process ended)");
    }

    /// <summary>The gate object, for the runners' assertion that it is not held (the same object the ledger locks).</summary>
    private static class LockProbe
    {
        internal static object Gate => typeof(GrantLedger).GetField("Gate", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!.GetValue(null)!;
    }

    /// <summary>Runs <paramref name="a"/> on another thread and reports whether it finished within the wait (it would not if
    /// the gate were held across the measurement).</summary>
    private static bool Proceeds(Action a) => Task.Run(a).Wait(HoldWait);

    private static string[] ExportDirs() => Directory.Exists(StorePaths.ExportsRoot) ? Directory.GetDirectories(StorePaths.ExportsRoot) : [];

    private static int CaptureHoldCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "HoldCapture");
        string op = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("hc1"), Rid("op_begin")))["operationId"]!;
        var hold = new Hold();
        fx.Led.SetCaptureRunnerForTest(new HoldingCaptureRunner(new SyntheticCaptureRunner(new SyntheticCapture(), SrcA), hold));
        Task<bool> capture = Task.Run(() => fx.Led.RunReservedCapture(op));
        bool entered = hold.Entered.Wait(HoldWait);
        // While the helper "runs": another run's transitions, a read, and the operator's configuration write.
        bool otherRun = Proceeds(() => Do(fx.Led, Engine, fx.Repo, "run-holdcapture-2", "open", OpenFields()));
        bool read = Proceeds(() => fx.Led.ListUserRecords(fx.Repo, fx.Run, true, GrantLedger.AllSections));
        bool revoked = Proceeds(() => ConfigFixture.Revoke(fx.Led, fx.Repo));
        hold.Release.Set();
        bool ran = capture.Wait(HoldWait) && capture.Result;
        RunRecord r = Run(fx);
        RunOperation o = r.Operations.First(x => x.OperationId == op);
        failed += Check("N5-13: while a capture is held inside the helper, another run opens, the records are read and the operator revokes the configuration — the gate is free",
            entered && otherRun && read && revoked);
        failed += Check("N5-13: the revocation committed during the measurement ends the commit basis_changed; nothing is captured; the budget is released; no export remains",
            ran && o.Status == RunOperationStatuses.Error && (string?)o.Outcome?["reason"] == "basis_changed" && r.Reviews.All(x => x.OperationId != op)
            && ExportDirs().Length == 0);
        return failed;
    }

    private static int CaptureCancelHoldCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "HoldCancel");
        string op = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("hx1"), Rid("op_begin")))["operationId"]!;
        var hold = new Hold();
        fx.Led.SetCaptureRunnerForTest(new HoldingCaptureRunner(new SyntheticCaptureRunner(new SyntheticCapture(), SrcA), hold));
        Task<bool> capture = Task.Run(() => fx.Led.RunReservedCapture(op));
        bool entered = hold.Entered.Wait(HoldWait);
        int eventsBefore = Run(fx).Events.Count;
        bool cancelled = Proceeds(() => fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_finish", Finish(op, ReviewOutcome("cancelled")), Rid("op_finish"))));
        bool done = capture.Wait(HoldWait);
        RunRecord r = Run(fx);
        RunOperation o = r.Operations.First(x => x.OperationId == op);
        failed += Check("N5-13: a cancellation while the capture is held kills the job: the operation ends cancelled, the late result records nothing, no export remains",
            entered && cancelled && done && o.Status == RunOperationStatuses.Cancelled && r.Events.Count == eventsBefore + 1 && ExportDirs().Length == 0);
        return failed;
    }

    private static int ChecksHoldCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "HoldChecks");
        string op = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ChecksBegin(), Rid("op_begin")))["operationId"]!;
        var hold = new Hold();
        fx.Led.AttachMeasurement(new HoldingMeasurementRunner(new SyntheticMeasurementRunner(), hold));
        Task<bool> measure = Task.Run(() => fx.Led.RunReservedCheckMeasurement(op));
        bool entered = hold.Entered.Wait(HoldWait);
        bool otherRun = Proceeds(() => Do(fx.Led, Engine, fx.Repo, "run-holdchecks-2", "open", OpenFields()));
        bool revoked = Proceeds(() => ConfigFixture.Revoke(fx.Led, fx.Repo));
        hold.Release.Set();
        bool ran = measure.Wait(HoldWait) && measure.Result;
        RunRecord r = Run(fx);
        RunOperation o = r.Operations.First(x => x.OperationId == op);
        failed += Check("N5-13 (checks): while a checks operation's start is measured, another run opens and the operator revokes the configuration; the commit ends basis_changed and no check runs",
            entered && otherRun && revoked && ran && o.Status == RunOperationStatuses.Error && (string?)o.Outcome?["reason"] == "basis_changed" && o.Measured is null
            && r.Status == RunStatuses.Idle);
        return failed;
    }

    private static int SpendHoldCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "HoldSpend");
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement(Fingerprint: new string('7', 64));
        JsonObject d;
        try { d = fx.Led.DerivationSection(fx.Repo, fx.Run, RunJsonBase64); }
        finally { CaptureFixture.Measurements.Spec = new SyntheticMeasurement(); }
        var hold = new Hold();
        fx.Led.AttachMeasurement(new HoldingMeasurementRunner(new SyntheticMeasurementRunner(), hold));
        LoopRecord loop = Loop(fx);
        LoopRequest spend = LoopRequest.Parse(fx.Run, fx.LoopId, loop.Epoch, loop.LoopRevision, "spend_continuation",
            new JsonObject { ["session_id"] = "session-1", ["derivation_id"] = (string)d["derivationId"]! }, Rid("spend"));
        Task<JsonObject?> spent = Task.Run<JsonObject?>(() =>
        {
            try { return fx.Led.LoopTransition(Engine, fx.Repo, spend); }
            catch (CustodianRefusal e) { return new JsonObject { ["refused"] = e.Code }; }
        });
        bool entered = hold.Entered.Wait(HoldWait);
        // While the spend's re-measurement runs, a transition on the same run (its revision moves) and another run's.
        bool sameRun = Proceeds(() => Do(fx, Engine, "op_begin", ChecksBegin()));
        bool otherRun = Proceeds(() => Do(fx.Led, Engine, fx.Repo, "run-holdspend-2", "open", OpenFields()));
        hold.Release.Set();
        bool done = spent.Wait(HoldWait);
        failed += Check("N5-13/§5.2: while a spend's re-measurement is held, the run and another run proceed; the run's revision moved, so the spend is refused DERIVATION_STALE and nothing is spent",
            entered && sameRun && otherRun && done && (string?)spent.Result?["refused"] == ErrorCodes.DerivationStale && Loop(fx).Used.Continuations == 0);
        return failed;
    }

    private static int HelperCrashCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "HelperCrash");
        string op = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("cr1"), Rid("op_begin")))["operationId"]!;
        fx.Led.SetCaptureRunnerForTest(new CrashingCaptureRunner());
        bool ran = fx.Led.RunReservedCapture(op);
        RunRecord r = Run(fx);
        RunOperation o = r.Operations.First(x => x.OperationId == op);
        failed += Check("N5-11: a helper that crashes during a capture leaves no partial authority — measurement_failed, nothing captured, the budget released, no export",
            ran && o.Status == RunOperationStatuses.Error && (string?)o.Outcome?["reason"] == "measurement_failed" && r.Reviews.All(x => x.OperationId != op) && ExportDirs().Length == 0);

        string cop = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ChecksBegin(), Rid("op_begin")))["operationId"]!;
        fx.Led.AttachMeasurement(new CrashingMeasurementRunner());
        bool measured = fx.Led.RunReservedCheckMeasurement(cop);
        RunOperation co = Run(fx).Operations.First(x => x.OperationId == cop);
        failed += Check("N5-11: a helper that crashes while measuring a checks operation's start ends it measurement_failed; no check runs; no measurement is recorded",
            measured && co.Status == RunOperationStatuses.Error && (string?)co.Outcome?["reason"] == "measurement_failed" && co.Measured is null
            && ExportDirs().All(x => !x.EndsWith(".cfg", StringComparison.Ordinal)));
        fx.Led.AttachMeasurement(CaptureFixture.Measurements);
        return failed;
    }

    private static int ChecksRestartCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "ChecksRestart");
        // A checks operation measuring its start, persisted.
        string op1 = (string)fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ChecksBegin(), Rid("op_begin")))["operationId"]!;
        var restarted = new GrantLedger("cust-selftest", fx.Procs);
        int interrupted = restarted.ReconcileCapturesAtStart();
        RunRecord r = Run(fx);
        RunOperation o1 = r.Operations.First(x => x.OperationId == op1);
        failed += Check("N5-18 (checks): a restart interrupts a checks operation measuring its start (measurement_interrupted, a custodian incident); the run is idle",
            interrupted == 1 && o1.Status == RunOperationStatuses.Interrupted && (string?)o1.Outcome?["reason"] == "measurement_interrupted"
            && r.Incidents.Any(i => i.Kind == "measurement_interrupted" && i.OperationId == op1) && r.Status == RunStatuses.Idle);
        int events = r.Events.Count;
        bool late = fx.Led.RunReservedCheckMeasurement(op1);
        failed += Check("N5-18 (checks): the previous instance's late start measurement is refused — nothing recorded",
            late && Run(fx).Events.Count == events && Run(fx).Operations.First(x => x.OperationId == op1).Status == RunOperationStatuses.Interrupted);

        // A running checks operation with an execution whose end is being measured, persisted; the restarted instance serves.
        CaptureFixture.Enable(restarted, repos);
        string op2 = (string)Do(restarted, Engine, fx.Repo, fx.Run, "op_begin", ChecksBegin())["operationId"]!;
        JsonObject pend = restarted.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "record_execution", Exec(op2, "x1"), Rid("record_execution")));
        var again = new GrantLedger("cust-selftest", fx.Procs);
        again.ReconcileCapturesAtStart();
        RunRecord r2 = Run(fx);
        JsonObject? x1 = r2.CheckExecutions.OfType<JsonObject>().FirstOrDefault(e => (string?)e["executionId"] == "x1");
        failed += Check("N5-18 (checks): a restart records the pending execution without its end (endMeasured false; it never counts as fresh) and clears the pending measurement",
            (string?)pend["executionStatus"] == RunOperationStatuses.Measuring && x1 is not null && (bool?)x1["custodianMeasurement"]?["endMeasured"] == false
            && (bool?)x1["sourceStable"] == false && r2.Operations.First(o => o.OperationId == op2).Pending is null);
        int events2 = r2.Events.Count;
        bool late2 = restarted.RunReservedCheckMeasurement(op2);
        failed += Check("N5-18 (checks): the previous instance's late end measurement is refused — nothing recorded twice",
            late2 && Run(fx).Events.Count == events2 && Run(fx).CheckExecutions.Count(e => (string?)e["executionId"] == "x1") == 1);
        return failed;
    }
}
