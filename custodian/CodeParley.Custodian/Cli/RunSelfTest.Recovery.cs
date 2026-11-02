using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-3 increment 5 — N16, durability, rollback and recovery (contract §2.4), deterministic: the boot identity is
/// injected, crashes are injected at the recovery's points through the self-test-only hold hook, and a power loss is
/// modelled by restoring earlier versions of store files. Every case runs on a store of its own (recovery acts on the
/// whole store).
/// </summary>
internal static partial class RunSelfTest
{
    private sealed class Boot(DateTime? value) : IBootIdentity
    {
        internal DateTime? Value { get; set; } = value;
        public DateTime? BootTimeUtc() => Value;
    }

    private static readonly DateTime B1 = new(2026, 10, 13, 8, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime B2 = B1.AddHours(3);
    private static readonly DateTime B3 = B1.AddHours(6);

    private static int RecoveryCases(string repos)
    {
        int failed = 0;
        DateTime? b1 = new KernelBootIdentity().BootTimeUtc();
        Thread.Sleep(50);
        DateTime? b2 = new KernelBootIdentity().BootTimeUtc();
        Console.WriteLine($"    kernel boot time: {b1:o}");
        failed += Check("the kernel boot identity reads on this machine: in the past, and stable between readings",
            b1 is { } x && b2 is { } y && x < DateTime.UtcNow && (x - y).Duration() <= GrantLedger.BootTolerance);
        failed += InterruptedRecoveryCases(repos);
        failed += StaleMarkerCases(repos);
        failed += RolledBackFilesCases(repos);
        failed += SelectionAfterRollbackCases(repos);
        failed += SameBootCases(repos);
        failed += RestoredEpochCases(repos);
        return failed;
    }

    /// <summary>A protected, bound run with evidence, a second open run, a grant with a loop left, a waiver on the run
    /// and a pending intent — first started in boot B1.</summary>
    private sealed record RecoveryFx(Fx Run, string OpenRunId, string AttendedRunId, string PendingIntent);

    private static RecoveryFx RecoveryStore(string repos, string name, Boot boot)
    {
        var first = new GrantLedger("cust-selftest", new Table());
        Check($"recovery fixture ({name}): first start of an empty store records the boot, nothing to recover", first.StartupRecovery(boot) is { Recovered: false, Reason: "first_start" });
        Fx fx = Protected(repos, name);
        string op = (string)Do(fx, Engine, "op_begin", ChecksBegin())["operationId"]!;
        Do(fx, Engine, "record_execution", Exec(op, "rx1"));
        Do(fx, Engine, "op_finish", Finish(op, ChecksOutcome()));
        string openRun = "run-" + name.ToLowerInvariant() + "-2";
        Open(fx.Led, fx.Repo, openRun);
        // A waiver on an attended run (no run record: the decision is not run-bound), whose revocation a rollback can undo.
        string attended = "run-" + name.ToLowerInvariant() + "-att";
        string amd = Rid("amd");
        fx.Led.PrepareUserRecord(fx.Repo, attended, "decision", new JsonObject { ["kind"] = "waive", ["note"] = "", ["thread_id"] = "t", ["request_digest"] = "d" }, 0, amd);
        fx.Led.Commit(amd, null);
        string pending = Rid("pending");
        fx.Led.PrepareGrant(fx.Repo, 1, 60, pending);
        return new RecoveryFx(fx, openRun, attended, pending);
    }

    /// <summary>N16 (a), M12: a crash after U0, after U1+U2, in the middle of and after U3, after U4, after U4b, after U5 and between U6's
    /// two writes, then a restart in the same boot: the pending recovery is resumed under its id and completed, and every
    /// step applied exactly once. A start in another boot supersedes a pending recovery with a new one.</summary>
    private static int InterruptedRecoveryCases(string repos)
    {
        int failed = 0;
        string[] points = [GrantLedger.RecoveryPoints.U0, GrantLedger.RecoveryPoints.U1, GrantLedger.RecoveryPoints.U3Run, GrantLedger.RecoveryPoints.U3,
            GrantLedger.RecoveryPoints.U4, GrantLedger.RecoveryPoints.U4b, GrantLedger.RecoveryPoints.U5, GrantLedger.RecoveryPoints.U6Session];
        foreach (string point in points)
        {
            failed += WithFreshStore($"recovery-{point.Replace(':', '-').Replace('+', '-')}", () =>
            {
                var boot = new Boot(B1);
                RecoveryFx r = RecoveryStore(repos, "Rec" + point.GetHashCode(StringComparison.Ordinal).ToString("x8", System.Globalization.CultureInfo.InvariantCulture), boot);
                boot.Value = B2; // an OS restart
                var led = new GrantLedger("cust-selftest", new Table());
                bool crashed = false;
                GrantLedger.HoldHook = p => { if (p == point && !crashed) { crashed = true; throw new SimulatedCrash(); } };
                try { led.StartupRecovery(boot); } catch (SimulatedCrash) { } finally { GrantLedger.HoldHook = null; }
                RecoveryMarker? midway = Marker<RecoveryMarker>(StorePaths.RecoveryPath);
                RecoveryOutcome resumed = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot); // the restart, same boot
                return Check($"N16 (a): a crash at {point}, then a same-boot restart → the pending recovery is resumed (same id) and every step applied once",
                    crashed && midway is { State: "pending" } && resumed is { Recovered: true, Resumed: true } && resumed.RecoveryId == midway.RecoveryId
                    && RecoveredOnce(r, resumed.RecoveryId!));
            });
        }
        failed += WithFreshStore("recovery-supersede", () =>
        {
            var boot = new Boot(B1);
            RecoveryFx r = RecoveryStore(repos, "RecSupersede", boot);
            boot.Value = B2;
            GrantLedger.HoldHook = p => { if (p == GrantLedger.RecoveryPoints.U3) throw new SimulatedCrash(); };
            try { new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot); } catch (SimulatedCrash) { } finally { GrantLedger.HoldHook = null; }
            string first = Marker<RecoveryMarker>(StorePaths.RecoveryPath)!.RecoveryId;
            boot.Value = B3; // another OS restart before the recovery completed
            RecoveryOutcome next = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
            return Check("N16 (a): a start in another boot supersedes the pending recovery with a new one (a new id), whose steps apply once more",
                next is { Recovered: true, Resumed: false } && next.RecoveryId != first && Marker<RecoveryMarker>(StorePaths.RecoveryPath) is { State: "complete" } m && m.RecoveryId == next.RecoveryId
                && RunOf(r.Run).EvidenceEpoch == 3 && Marker<SessionMarker>(StorePaths.SessionPath)?.BootTime == B3.ToString("o"));
        });
        return failed;
    }

    /// <summary>After a completed recovery: every live loop paused for the operator or ended, every unexpired grant
    /// suspended (consume refused), the evidence epoch risen exactly once, the log's recovered revision recorded, no
    /// pending intent, the session marker on this boot, the recovery complete.</summary>
    private static bool RecoveredOnce(RecoveryFx r, string recoveryId)
    {
        Fx fx = r.Run;
        LoopRecord loop = Loop(fx);
        bool loopPaused = loop is { Status: "paused", Pause.Reason: PauseReasons.OperatorActionRequired } && loop.LastRecoveryId == recoveryId;
        bool grantsSuspended = fx.Led.ReadLocked().Grants.Where(g => g.RevokedAt is null).All(g => g.SuspendedAt is not null && g.LastRecoveryId == recoveryId);
        bool epochOnce = RunOf(fx).EvidenceEpoch == 2 && GrantLedger.ReadRunLocked(RepoIdentities.Resolve(fx.Repo).Key, r.OpenRunId)!.EvidenceEpoch == 2;
        JsonObject users = fx.Led.ListUserRecords(fx.Repo, r.AttendedRunId, true);
        bool logStamped = (int?)users["recoveredAtRevision"] == 1;
        bool intentsVoid = !Directory.Exists(StorePaths.IntentsDir) || !Directory.EnumerateFiles(StorePaths.IntentsDir, "*.json").Any();
        bool markers = Marker<RecoveryMarker>(StorePaths.RecoveryPath) is { State: "complete" } m && m.RecoveryId == recoveryId
            && Marker<SessionMarker>(StorePaths.SessionPath) is { } s && s.BootTime == B2.ToString("o") && s.LastRecoveryId == recoveryId;
        // P3.4C-4 U4b: every configuration record in force lapsed, once, by this recovery.
        ConfigRecordsFile cfg = GrantLedger.ReadConfigRecordsLocked();
        bool configLapsed = cfg.Repositories.Where(x => x.IsCurrent && !x.IsRevoked).All(x => x.LapsedAtRecoveryId == recoveryId && x.LastRecoveryId == recoveryId)
            && cfg.Acceptances.Where(a => a.RevokedAt is null).All(a => a.LapsedAtRecoveryId == recoveryId && a.LastRecoveryId == recoveryId)
            && cfg.SelftestConfirmations.Where(c => c.RevokedAt is null && c.SupersededAt is null).All(c => c.LapsedAtRecoveryId == recoveryId && c.LastRecoveryId == recoveryId)
            && cfg.Repositories.Any(x => x.IsCurrent);
        // A new start is refused: first for the lapsed configuration; once the operator re-confirmed it, for the suspended grant.
        bool consumeRefused = Refused(() => { Open(fx.Led, fx.Repo, "run-after-recovery"); }, ErrorCodes.ConfigLapsed)
            && Ok(() => ConfigFixture.Reconfirm(fx.Led, fx.Repo))
            && Refused(() => { Open(fx.Led, fx.Repo, "run-after-recovery"); }, ErrorCodes.LoopNotAuthorized);
        bool ok = loopPaused && grantsSuspended && epochOnce && logStamped && intentsVoid && configLapsed && consumeRefused && markers;
        if (!ok) Console.WriteLine($"    loopPaused={loopPaused} grantsSuspended={grantsSuspended} epochOnce={epochOnce} logStamped={logStamped} intentsVoid={intentsVoid} configLapsed={configLapsed} consumeRefused={consumeRefused} markers={markers}");
        return ok;
    }

    /// <summary>N16 (b): a stale session marker cannot skip recovery — an older marker (clean stop, earlier boot) in a new
    /// boot recovers; an unreadable boot, a missing marker with records present or an unreadable marker recovers; a
    /// marker naming the current boot does not, unless a recovery is pending; an unreadable recovery marker serves
    /// nothing.</summary>
    private static int StaleMarkerCases(string repos)
    {
        int failed = 0;
        failed += WithFreshStore("stale-clean", () =>
        {
            var boot = new Boot(B1);
            RecoveryStore(repos, "StaleClean", boot);
            new GrantLedger("cust-selftest", new Table()).MarkCleanStop();
            string earlier = File.ReadAllText(StorePaths.SessionPath); // cleanStop:true, boot B1
            boot.Value = B2;
            File.WriteAllText(StorePaths.SessionPath, earlier);
            return Check("N16 (b): an older session marker (cleanStop true, an earlier boot) in a new boot → recovery runs",
                earlier.Contains("\"cleanStop\": true", StringComparison.Ordinal) && new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot) is { Recovered: true, Reason: "new_boot" });
        });
        failed += WithFreshStore("stale-unreadable-boot", () =>
        {
            var boot = new Boot(B1);
            RecoveryStore(repos, "StaleBoot", boot);
            new GrantLedger("cust-selftest", new Table()).MarkCleanStop();
            boot.Value = null;
            return Check("N16 (b): an unreadable boot identity → recovery runs (even after a clean stop)",
                new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot) is { Recovered: true, Reason: "boot_identity_unreadable" });
        });
        failed += WithFreshStore("stale-missing", () =>
        {
            var boot = new Boot(B1);
            RecoveryStore(repos, "StaleMissing", boot);
            File.Delete(StorePaths.SessionPath);
            return Check("N16 (b): a missing session marker while the store holds records → recovery runs (same boot)",
                new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot) is { Recovered: true, Reason: "session_marker_missing" });
        });
        failed += WithFreshStore("stale-corrupt", () =>
        {
            var boot = new Boot(B1);
            RecoveryStore(repos, "StaleCorrupt", boot);
            File.WriteAllText(StorePaths.SessionPath, "{not json");
            return Check("N16 (b): an unreadable session marker → recovery runs",
                new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot) is { Recovered: true, Reason: "session_marker_unreadable" });
        });
        failed += WithFreshStore("stale-current", () =>
        {
            var boot = new Boot(B1);
            RecoveryStore(repos, "StaleCurrent", boot);
            bool none = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot) is { Recovered: false, Reason: "same_boot" };
            File.WriteAllText(StorePaths.RecoveryPath, $"{{\"recoveryId\":\"rec-0000000000000001\",\"state\":\"pending\",\"reason\":\"new_boot\",\"bootTime\":\"{B1:o}\",\"startedAt\":\"{B1:o}\"}}");
            bool resumed = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot) is { Recovered: true, Resumed: true, RecoveryId: "rec-0000000000000001" };
            File.WriteAllText(StorePaths.RecoveryPath, "{corrupt");
            bool failsClosed = Throws<InvalidDataException>(() => new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot));
            return Check("N16 (b): a marker naming the current boot → no recovery; unless one is pending (resumed); an unreadable recovery marker serves nothing",
                none && resumed && failsClosed);
        });
        return failed;
    }

    /// <summary>N16 (c): each combination of the ledger, the user-record log and a run file restored to an earlier version
    /// (spent budgets back, an operator stop, a revocation and the run's end undone): after the recovery of the new boot,
    /// nothing restored takes effect without an operator action, and cross-file references fail closed.</summary>
    private static int RolledBackFilesCases(string repos)
    {
        int failed = 0;
        for (int mask = 1; mask < 8; mask++)
        {
            bool ledger = (mask & 1) != 0, users = (mask & 2) != 0, runFile = (mask & 4) != 0;
            failed += WithFreshStore($"rollback-{mask}", () =>
            {
                var boot = new Boot(B1);
                RecoveryFx r = RecoveryStore(repos, $"Rollback{mask}", boot);
                Fx fx = r.Run;
                string runPath = StorePaths.RunPath(RepoIdentities.Resolve(fx.Repo).Key, fx.Run);
                var snapshot = new Dictionary<string, string>
                {
                    [StorePaths.LedgerPath] = File.ReadAllText(StorePaths.LedgerPath),
                    [StorePaths.UserRecordsPath] = File.ReadAllText(StorePaths.UserRecordsPath),
                    [runPath] = File.ReadAllText(runPath),
                };
                // After the snapshot: a continuation spent, the waiver revoked, the run ended (its loop ended with it).
                Spend(fx, Engine);
                string revoke = Rid("revoke");
                fx.Led.PrepareUserRecord(fx.Repo, r.AttendedRunId, "decision", new JsonObject { ["kind"] = "revoke", ["note"] = "", ["thread_id"] = "t", ["request_digest"] = "d2" }, 1, revoke);
                fx.Led.Commit(revoke, null);
                Do(fx, Oper, "end", EndFields("stopped"));
                // A power loss: the selected files revert independently.
                if (ledger) File.WriteAllText(StorePaths.LedgerPath, snapshot[StorePaths.LedgerPath]);
                if (users) File.WriteAllText(StorePaths.UserRecordsPath, snapshot[StorePaths.UserRecordsPath]);
                if (runFile) File.WriteAllText(runPath, snapshot[runPath]);
                boot.Value = B2;
                RecoveryOutcome rec = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
                LoopRecord loop = Loop(fx);
                RunRecord run = RunOf(fx);
                bool loopSafe = LoopStatuses.IsTerminal(loop.Status) || loop is { Status: "paused", Pause.Reason: PauseReasons.OperatorActionRequired };
                string? spendCode = RefusalCode(() => Spend(fx, Engine)); // a paused loop automates nothing; a terminal run ends it
                bool noSpend = spendCode is ErrorCodes.LoopTerminal or ErrorCodes.InvalidLoopTransition;
                loop = Loop(fx);
                bool grantsOff = fx.Led.ReadLocked().Grants.Where(g => g.RevokedAt is null).All(g => g.SuspendedAt is not null);
                JsonObject log = fx.Led.ListUserRecords(fx.Repo, r.AttendedRunId, true);
                bool waiverLapses = (int?)log["recoveredAtRevision"] == log["revision"]!.GetValue<int>(); // every earlier waive/defer lapses
                // An operator resume of the restored loop, if the run's end survived, is caught up by the run record.
                bool crossFile = run.IsTerminal || run.EvidenceEpoch == 2;
                if (!LoopStatuses.IsTerminal(loop.Status) && run.IsTerminal)
                    crossFile = Refused(() => fx.Led.LoopTransition(Oper, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, loop.Epoch, loop.LoopRevision, "resume", [], Rid("resume"))), ErrorCodes.LoopTerminal)
                        && Loop(fx).Status == "run_ended";
                bool ok = rec.Recovered && loopSafe && noSpend && grantsOff && waiverLapses && crossFile;
                if (!ok) Console.WriteLine($"    mask={mask} recovered={rec.Recovered} loop={loop.Status}/{loop.Pause?.Reason} noSpend={noSpend} grantsOff={grantsOff} waiverLapses={waiverLapses} crossFile={crossFile} run={run.Status}/{run.EvidenceEpoch}");
                return Check($"N16 (c): rolled back [{(ledger ? "ledger " : "")}{(users ? "user-records " : "")}{(runFile ? "run" : "")}] → nothing restored takes effect without an operator action; cross-file references fail closed", ok);
            });
        }
        return failed;
    }

    /// <summary>N16 (d), the custodian side of the selection after a rollback (§2.4 table): a run record without its loop
    /// keeps the run protected; a loop without its run record ends at its next transition; with neither, the custodian
    /// does not answer protected (the engine's local hint then refuses — increment 7).</summary>
    private static int SelectionAfterRollbackCases(string repos)
    {
        int failed = 0;
        failed += WithFreshStore("select-run-only", () =>
        {
            var boot = new Boot(B1);
            RecoveryFx r = RecoveryStore(repos, "SelectRunOnly", boot);
            LedgerFile l = r.Run.Led.ReadLocked();
            l.Loops!.RemoveAll(x => x.RunId == r.Run.Run);
            File.WriteAllText(StorePaths.LedgerPath, System.Text.Json.JsonSerializer.Serialize(l, new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase }));
            return Check("N16 (d): the run record only (its loop rolled back) → still protected; no evidence without a bound loop",
                IsProtected(r.Run.Led, r.Run.Repo, r.Run.Run) && Refused(() => Do(r.Run, Engine, "op_begin", ChecksBegin()), ErrorCodes.ProcessIdentityUnverified));
        });
        failed += WithFreshStore("select-loop-only", () =>
        {
            var boot = new Boot(B1);
            RecoveryFx r = RecoveryStore(repos, "SelectLoopOnly", boot);
            File.Delete(StorePaths.RunPath(RepoIdentities.Resolve(r.Run.Repo).Key, r.Run.Run));
            return Check("N16 (d): the loop only (its run record rolled back) → protected until its next transition, which ends it and authorizes nothing",
                IsProtected(r.Run.Led, r.Run.Repo, r.Run.Run) && Refused(() => Spend(r.Run, Engine), ErrorCodes.LoopTerminal) && Loop(r.Run).Status == "run_ended");
        });
        failed += WithFreshStore("select-neither", () =>
        {
            var boot = new Boot(B1);
            RecoveryFx r = RecoveryStore(repos, "SelectNeither", boot);
            LedgerFile l = r.Run.Led.ReadLocked();
            l.Loops!.RemoveAll(x => x.RunId == r.Run.Run);
            File.WriteAllText(StorePaths.LedgerPath, System.Text.Json.JsonSerializer.Serialize(l, new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase }));
            File.Delete(StorePaths.RunPath(RepoIdentities.Resolve(r.Run.Repo).Key, r.Run.Run));
            return Check("N16 (d): neither record → the custodian does not answer protected (it holds no authority for the run)", !IsProtected(r.Run.Led, r.Run.Repo, r.Run.Run));
        });
        return failed;
    }

    /// <summary>N16 (e): a restart in the same boot (a process crash, a service stop or restart) runs no recovery and
    /// keeps every acknowledged transition, loop and grant as they were.</summary>
    private static int SameBootCases(string repos) => WithFreshStore("same-boot", () =>
    {
        var boot = new Boot(B1);
        RecoveryFx r = RecoveryStore(repos, "SameBoot", boot);
        string ledgerBefore = File.ReadAllText(StorePaths.LedgerPath);
        string runBefore = File.ReadAllText(StorePaths.RunPath(RepoIdentities.Resolve(r.Run.Repo).Key, r.Run.Run));
        new GrantLedger("cust-selftest", new Table()).MarkCleanStop();
        RecoveryOutcome a = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot); // a service restart
        RecoveryOutcome b = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot); // a process crash and restart
        return Check("N16 (e): same-boot restarts run no recovery; the loop stays active, the grants and the run unchanged",
            a is { Recovered: false, Reason: "same_boot" } && b is { Recovered: false } && Loop(r.Run).Status == "active"
            && File.ReadAllText(StorePaths.LedgerPath) == ledgerBefore && File.ReadAllText(StorePaths.RunPath(RepoIdentities.Resolve(r.Run.Repo).Key, r.Run.Run)) == runBefore);
    });

    // ---- helpers ----

    private static RunRecord RunOf(Fx fx) => GrantLedger.ReadRunLocked(RepoIdentities.Resolve(fx.Repo).Key, fx.Run)!;

    /// <summary>The refusal code <paramref name="a"/> ended with (null: it succeeded).</summary>
    private static string? RefusalCode(Action a)
    {
        try { a(); return null; }
        catch (CustodianRefusal r) { return r.Code; }
        catch (ArgumentException) { return ErrorCodes.InvalidArgument; }
    }

    private static T? Marker<T>(string path) where T : class
        => File.Exists(path) ? System.Text.Json.JsonSerializer.Deserialize<T>(File.ReadAllText(path), new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase }) : null;

    /// <summary>Run <paramref name="body"/> against a store of its own, then return to the shared scratch store.</summary>
    private static int WithFreshStore(string name, Func<int> body)
    {
        string original = StorePaths.Root;
        string root = Path.Combine(Path.GetDirectoryName(original.TrimEnd('\\'))!, "recovery", name, "Custodian");
        StorePaths.OverrideRootForSelfTest(root);
        Directory.CreateDirectory(StorePaths.IntentsDir);
        try { return body(); }
        catch (Exception e) { return Check($"{name}: unexpected {e.GetType().Name}: {e.Message}", false); }
        finally { GrantLedger.HoldHook = null; StorePaths.OverrideRootForSelfTest(original); }
    }
}
