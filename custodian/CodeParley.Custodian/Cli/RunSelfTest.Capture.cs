using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 Increment 2 — the custodian's review capture (contract §3.1, §2.4) beyond the shared corpus: a reservation is
/// refused without the helper or without a usable runtime approval (actionable, nothing reserved); and the start
/// reconciliation of N5-18 interrupts a persisted measuring operation, releases its budget, refuses the previous instance's
/// late result and sweeps every export directory no captured review references, keeping the ones that are.
/// </summary>
internal static partial class RunSelfTest
{
    private static int CaptureCases(string repos)
    {
        int failed = 0;
        failed += WithFreshStore("capture-readiness", () => CaptureReadinessCases(repos));
        failed += WithFreshStore("capture-reconcile", () => CaptureReconcileCases(repos));
        return failed;
    }

    private static int CaptureReadinessCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "CaptureReady");
        var bare = new GrantLedger("cust-selftest", fx.Procs);
        failed += Check("a reservation on a custodian without the helper → HELPER_UNAVAILABLE (with the install command), nothing reserved",
            Refused(() => bare.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("h1"), Rid("op_begin"))), ErrorCodes.HelperUnavailable)
            && Run(fx).Operations.Count == 0);
        string runtime = GrantLedger.ReadConfigRecordsLocked().CurrentRuntime!.RuntimeId;
        ConfigFixture.RevokeGlobal(fx.Led, ConfigKinds.EngineRuntime, runtime);
        failed += Check("a reservation after the runtime approval was revoked → RUNTIME_NOT_APPROVED, nothing reserved",
            Refused(() => fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("h2"), Rid("op_begin"))), ErrorCodes.RuntimeNotApproved)
            && Run(fx).Operations.Count == 0);
        CaptureFixture.ApproveRuntime(fx.Led, repos, variant: 4);
        JsonObject b = Do(fx, Engine, "op_begin", ReviewBegin("h3"));
        failed += Check("once the operator approves a runtime again, the reservation is accepted and captured", (string?)b["operationStatus"] == RunOperationStatuses.Captured);
        return failed;
    }

    private static int CaptureReconcileCases(string repos)
    {
        int failed = 0;
        Fx fx = Protected(repos, "CaptureReconcile");
        // A finished, captured review whose export stays published.
        string op0 = (string)Do(fx, Engine, "op_begin", ReviewBegin("c0"))["operationId"]!;
        Do(fx, Engine, "op_finish", Finish(op0, ReviewOutcome()));
        string kept = Path.GetDirectoryName((string)Run(fx).Operations.First(o => o.OperationId == op0).Begin["custodianCapture"]!["exportPath"]!)!;
        // A reservation left measuring (its capture never ran), and directories an interrupted measurement could leave.
        JsonObject b = fx.Led.RunTransition(Engine, fx.Repo, RunRequest.Parse(fx.Run, "op_begin", ReviewBegin("c1", reviewInput: SrcB), Rid("op_begin")));
        string op1 = (string)b["operationId"]!;
        string[] orphans = ["tkt-orphan.staging", "tkt-orphan.cfg", "tkt-orphan"];
        foreach (string o in orphans) Directory.CreateDirectory(Path.Combine(StorePaths.ExportsRoot, o));
        int eventsBefore = Run(fx).Events.Count;

        var restarted = new GrantLedger("cust-selftest", fx.Procs);
        int interrupted = restarted.ReconcileCapturesAtStart();
        RunRecord r = Run(fx);
        RunOperation o1 = r.Operations.First(o => o.OperationId == op1);
        failed += Check("N5-18: a restart interrupts the persisted measuring operation (measurement_interrupted), records the incident and releases its budget",
            interrupted == 1 && o1.Status == RunOperationStatuses.Interrupted && (string?)o1.Outcome?["reason"] == "measurement_interrupted"
            && r.Incidents.Any(i => i.Kind == "measurement_interrupted" && i.Source == "custodian" && i.OperationId == op1)
            && r.Reviews.All(x => x.OperationId != op1) && r.Status == RunStatuses.Idle && r.EvidenceEpoch == 1);
        failed += Check("N5-18: the start sweeps every export directory no captured review references, and keeps the published one",
            orphans.All(o => !Directory.Exists(Path.Combine(StorePaths.ExportsRoot, o))) && Directory.Exists(kept));
        int eventsAfterRestart = Run(fx).Events.Count;
        bool ran = fx.Led.RunReservedCapture(op1);
        failed += Check("N5-18: the previous instance's late capture result is refused — nothing recorded, its staging removed",
            ran && Run(fx).Events.Count == eventsAfterRestart && eventsAfterRestart == eventsBefore + 1
            && Directory.GetDirectories(StorePaths.ExportsRoot).All(d => d == kept || Path.GetFileName(d).StartsWith("tkt-", StringComparison.Ordinal) && !d.EndsWith(".staging", StringComparison.Ordinal) && !d.EndsWith(".cfg", StringComparison.Ordinal)));
        CaptureFixture.Enable(restarted, repos);
        JsonObject again = Do(restarted, Engine, fx.Repo, fx.Run, "op_begin", ReviewBegin("c2", reviewInput: SrcB));
        failed += Check("N5-18: after the restart a new review can begin and is captured", (string?)again["operationStatus"] == RunOperationStatuses.Captured);
        return failed;
    }
}
