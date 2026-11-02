using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 6 Increment 2 (contract §6.1, L-5): the restored epoch — no authority resurrection after the installer's
/// `rollback`. The store a backup returns holds authority that was spent, expired or decided after the backup; at the next
/// start the restore marker makes the custodian (a) lapse every boot- and time-bound approval, (b) suspend every grant,
/// (c) void every unconsumed fix confirmation and prepared intent, (d) end every open protected run "restored" — once per
/// marker, resumably, before anything is served.
/// </summary>
internal static partial class RunSelfTest
{
    private static int RestoredEpochCases(string repos)
    {
        int failed = 0;
        failed += WithFreshStore("restored-epoch", () =>
        {
            var boot = new Boot(B1);
            RestoreFx s = RestoreStore(repos, "Restore", boot);
            var marker = new RestoreMarker("rst-0001", DateTime.UtcNow.ToString("o"), new string('a', 64), StoreFormat.Current);
            RecoveryOutcome o = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker); // same boot: no OS restart
            int f = 0;
            f += Check("L-5: a restore marker starts the restored epoch even without an OS restart (reason restored:<id>)", o is { Recovered: true } && o.Reason == GrantLedger.RestoredPrefix + "rst-0001");
            f += Check("L-5 (a): every repository configuration in force lapses until the operator re-confirms it", ConfigLapsed(o.RecoveryId!));
            f += Check("L-5 (b): every grant is suspended or expired — none is active (an expiry passed after the backup stays passed)", NoActiveGrant(s.Restore.Run));
            f += Check("L-5 (c): the fix confirmation not consumed in the backup is void (its expiry is now, never later) — it cannot be used",
                PlantedConfirmationVoid(s));
            f += Check("L-5 (c): the prepared intent is void", !File.Exists(Path.Combine(StorePaths.IntentsDir, s.Restore.PendingIntent + ".json")));
            f += Check("L-5 (d): every protected run open at the backup is ended \"restored\", and its loop with it",
                RunEndedRestored(s.Restore.Run.Repo, s.Restore.Run.Run) && RunEndedRestored(s.Restore.Run.Repo, s.Restore.OpenRunId) && LoopStatuses.IsTerminal(Loop(s.Restore.Run).Status));
            f += Check("L-5: the session marker records the applied restore only once every step is durable",
                Marker<SessionMarker>(StorePaths.SessionPath)?.LastRestoreId == "rst-0001" && Marker<RecoveryMarker>(StorePaths.RecoveryPath) is { State: "complete" });
            RecoveryOutcome again = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker);
            f += Check("L-5: the same marker is applied once — a later start in the same boot recovers nothing", again is { Recovered: false, Reason: "same_boot" });
            RecoveryOutcome next = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker with { RestoreId = "rst-0002" });
            f += Check("L-5: a new restore (a new marker id) starts its own restored epoch", next is { Recovered: true } && next.Reason == GrantLedger.RestoredPrefix + "rst-0002");
            return f;
        });
        foreach (string point in new[] { GrantLedger.RecoveryPoints.U3Run, GrantLedger.RecoveryPoints.U3, GrantLedger.RecoveryPoints.U3c, GrantLedger.RecoveryPoints.U6Session })
        {
            failed += WithFreshStore($"restored-epoch-crash-{point.Replace(':', '-')}", () =>
            {
                var boot = new Boot(B1);
                RestoreFx s = RestoreStore(repos, "RestoreCrash" + point.GetHashCode(StringComparison.Ordinal).ToString("x8", System.Globalization.CultureInfo.InvariantCulture), boot);
                var marker = new RestoreMarker("rst-crash", DateTime.UtcNow.ToString("o"), new string('b', 64), StoreFormat.Current);
                bool crashed = false;
                GrantLedger.HoldHook = p => { if (p == point && !crashed) { crashed = true; throw new SimulatedCrash(); } };
                try { new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker); } catch (SimulatedCrash) { } finally { GrantLedger.HoldHook = null; }
                bool pending = Marker<RecoveryMarker>(StorePaths.RecoveryPath) is { State: "pending" } m && m.Reason == GrantLedger.RestoredPrefix + "rst-crash";
                RecoveryOutcome resumed = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker);
                return Check($"L-5: a crash at {point} leaves the restored epoch pending; the restart resumes it under the same reason and completes every step once",
                    crashed && pending && resumed is { Recovered: true, Resumed: true } && resumed.Reason == "resumed: " + GrantLedger.RestoredPrefix + "rst-crash"
                    && PlantedConfirmationVoid(s) && RunEndedRestored(s.Restore.Run.Repo, s.Restore.Run.Run) && LoopStatuses.IsTerminal(Loop(s.Restore.Run).Status)
                    && Marker<SessionMarker>(StorePaths.SessionPath)?.LastRestoreId == "rst-crash");
            });
        }
        // The Windows host believes a marker only from an administrator: this process's own (non-elevated) file is refused.
        string own = Path.Combine(Path.GetTempPath(), "cp-restore-marker-" + Guid.NewGuid().ToString("N")[..8] + ".json");
        try
        {
            File.WriteAllText(own, "{}");
            bool elevated = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            failed += elevated
                ? Check("L-5 (Windows): skipped the user-owned marker case — this self-test runs elevated, so its files are administrator-owned", true)
                : Check("L-5 (Windows): a restore marker a non-administrator wrote is refused (fail closed), and an absent one is none",
                    ThrowsWith(() => WindowsRestoreMarker.Read(own), "is owned by") && WindowsRestoreMarker.Read(own + ".absent") is null);
        }
        finally { File.Delete(own); }
        failed += WithFreshStore("restored-epoch-new-boot", () =>
        {
            var boot = new Boot(B1);
            RestoreFx s = RestoreStore(repos, "RestoreBoot", boot);
            var marker = new RestoreMarker("rst-boot", DateTime.UtcNow.ToString("o"), new string('c', 64), StoreFormat.Current);
            GrantLedger.HoldHook = p => { if (p == GrantLedger.RecoveryPoints.U1) throw new SimulatedCrash(); };
            try { new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker); } catch (SimulatedCrash) { } finally { GrantLedger.HoldHook = null; }
            boot.Value = B2; // an OS restart before the restored epoch completed
            RecoveryOutcome next = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker);
            return Check("L-5: a restored epoch superseded by another boot keeps its reason, so its steps still apply (under a new id)",
                next is { Recovered: true, Resumed: false } && next.Reason == GrantLedger.RestoredPrefix + "rst-boot"
                && PlantedConfirmationVoid(s) && RunEndedRestored(s.Restore.Run.Repo, s.Restore.Run.Run) && Marker<SessionMarker>(StorePaths.SessionPath)?.LastRestoreId == "rst-boot");
        });
        failed += WithFreshStore("restored-epoch-after-pending", () =>
        {
            var boot = new Boot(B1);
            RestoreFx s = RestoreStore(repos, "RestorePending", boot);
            boot.Value = B2;
            GrantLedger.HoldHook = p => { if (p == GrantLedger.RecoveryPoints.U3) throw new SimulatedCrash(); };
            try { new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot); } catch (SimulatedCrash) { } finally { GrantLedger.HoldHook = null; }
            var marker = new RestoreMarker("rst-late", DateTime.UtcNow.ToString("o"), new string('d', 64), StoreFormat.Current);
            RecoveryOutcome next = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot, marker);
            return Check("L-5: a restore marker found while an ordinary recovery is pending: that recovery completes, then the restored epoch runs at once",
                next is { Recovered: true } && next.Reason == GrantLedger.RestoredPrefix + "rst-late"
                && PlantedConfirmationVoid(s) && RunEndedRestored(s.Restore.Run.Repo, s.Restore.Run.Run) && Marker<SessionMarker>(StorePaths.SessionPath)?.LastRestoreId == "rst-late");
        });
        return failed;
    }

    /// <summary>The recovery fixture (a bound protected run, a second open run, a grant, a waiver, a pending intent) plus a fix
    /// confirmation the owner gave and that was not consumed when the backup was taken, and a grant whose expiry passed after
    /// it.</summary>
    private sealed record RestoreFx(RecoveryFx Restore, string FixOperationId);

    private static RestoreFx RestoreStore(string repos, string name, Boot boot)
    {
        RecoveryFx r = RecoveryStore(repos, name, boot);
        RunRecord run = RunOf(r.Run);
        string fixOp = "fop-" + run.Operations.Count + "-restore00000";
        var confirmation = new JsonObject
        {
            ["confirmationId"] = Guid.NewGuid().ToString(), ["decision"] = "confirm", ["repoKey"] = run.RepoKey, ["runId"] = run.RunId,
            ["recordedAt"] = DateTime.UtcNow.ToString("o"), ["expiresAt"] = DateTime.UtcNow.AddMinutes(25).ToString("o"), ["consumedAt"] = null, ["consumedBy"] = null,
        };
        RunOperation writerOf = run.Operations[0];
        var fix = new RunOperation(fixOp, run.Operations.Count + 1, "fix", GrantLedger.FixConfirmed, DateTime.UtcNow.ToString("o"), DateTime.UtcNow.ToString("o"),
            writerOf.Writer, new JsonObject(), new JsonObject { ["confirmation"] = confirmation });
        GrantLedger.WriteRun(run with { Operations = [.. run.Operations, fix] });
        // A grant whose expiry passed after the backup: the absolute time stays passed.
        var ledger = JsonNode.Parse(File.ReadAllText(StorePaths.LedgerPath))!.AsObject();
        ledger["grants"]![0]!["expiresAt"] = DateTime.UtcNow.AddMinutes(-5).ToString("o");
        File.WriteAllText(StorePaths.LedgerPath, ledger.ToJsonString());
        return new RestoreFx(r, fixOp);
    }

    private static bool PlantedConfirmationVoid(RestoreFx s)
    {
        RunOperation? op = RunOf(s.Restore.Run).Operations.FirstOrDefault(o => o.OperationId == s.FixOperationId);
        if (op?.Outcome?["confirmation"] is not JsonObject c) return false;
        return DateTime.Parse((string)c["expiresAt"]!).ToUniversalTime() <= DateTime.UtcNow && (string?)c["voidedReason"] == "restored" && c["consumedAt"] is null;
    }

    private static bool RunEndedRestored(string repo, string runId)
        => GrantLedger.ReadRunLocked(RepoIdentities.Resolve(repo).Key, runId) is { Status: RunStatuses.Stopped, Ended.Reason: "restored" };

    private static bool NoActiveGrant(Fx fx)
        => fx.Led.ListGrants()["grants"]!.AsArray().All(g => g!["active"]?.GetValue<bool>() != true);

    private static bool ConfigLapsed(string recoveryId)
    {
        ConfigRecordsFile config = GrantLedger.ReadConfigRecords();
        var current = config.Repositories.Where(r => r.IsCurrent && !r.IsRevoked).ToList();
        return current.Count > 0 && current.All(r => r.LapsedAtRecoveryId == recoveryId);
    }
}
