using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>The OS boot the custodian runs in. Windows: the kernel's boot time (UTC; null when it cannot be read), recorded
/// as ISO-8601 and compared within <see cref="GrantLedger.BootTolerance"/>. Phase 5 (§4.8): a host may instead identify the
/// boot by an opaque key (Linux: <c>/proc/sys/kernel/random/boot_id</c>) compared exactly — it overrides
/// <see cref="BootKey"/> and <see cref="SameBoot"/>. An unreadable boot never matches (every start then recovers).</summary>
internal interface IBootIdentity
{
    DateTime? BootTimeUtc();

    /// <summary>The key a session or recovery marker records for this boot (null: unreadable).</summary>
    string? BootKey() => BootTimeUtc()?.ToString("o");

    /// <summary>Is the boot a marker recorded the current one?</summary>
    bool SameBoot(string? recorded, string? current)
    {
        if (recorded is null || current is null) return false;
        if (!DateTime.TryParse(recorded, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime r)) return false;
        if (!DateTime.TryParse(current, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime c)) return false;
        return (r.ToUniversalTime() - c.ToUniversalTime()).Duration() <= GrantLedger.BootTolerance;
    }
}

/// <summary>The protected session marker (§2.4): the boot the custodian last completed a recovery in (or first started
/// in) and, as a diagnostic only, whether it last stopped gracefully. <see cref="BootTime"/> is null when the boot
/// could not be read (it then never matches, so every start recovers).</summary>
internal sealed record SessionMarker(string? BootTime, string RecordedAt, bool CleanStop, string? LastRecoveryId, string? LastRestoreId = null);

/// <summary>Phase 6 Increment 2 (contract §6.1, L-5): the marker the installer's <c>rollback</c> writes after restoring the
/// store from a backup, in a location only an administrator can write (the host reads and validates it). Its id is
/// applied once: the restored epoch runs, and the session marker records the id only after every step is durable.</summary>
internal sealed record RestoreMarker(string RestoreId, string RestoredAt, string BackupSha256, int StoreFormat);

/// <summary>The recovery marker (§2.4 U0/U6): a recovery is <c>pending</c> from before its first step until all its steps
/// are done (<c>complete</c>). <see cref="BootTime"/> is the boot it started in.</summary>
internal sealed record RecoveryMarker(string RecoveryId, string State, string Reason, string? BootTime, string StartedAt, string? CompletedAt);

/// <summary>What a start decided and did about recovery.</summary>
internal sealed record RecoveryOutcome(bool Recovered, string? RecoveryId, string Reason, bool Resumed);

/// <summary>
/// P3.4C-3 (contract §2.4): the recovery a new boot requires, resumable and idempotent; nothing is served until it
/// completes. A store file may revert to an earlier version across an OS crash or power loss, independently of the
/// others, and a rollback can increase authority (spent budgets restored, a stop or revocation undone) — so at every
/// start in a new boot, whatever the session marker says, the custodian fails closed before serving: U1 live loops are
/// paused for the operator (an unbound one, which can no longer bind, ends); U2 every unexpired grant is suspended; U3
/// every open run gets a new evidence epoch; U4 every user-record log records the revision recovery ran at (earlier
/// waivers and deferrals lapse on runs whose loop is not terminal, until the operator re-confirms them); U4b (P3.4C-4)
/// every configuration record in force lapses until the operator re-confirms it; U5 every pending intent is void. U0 records the recovery pending before any step and U6 moves the session marker to this
/// boot, then marks it complete; every step stamps what it changed with the recovery id and skips what it already
/// stamped, so a recovery interrupted at any point is resumed — at the next start, in the same boot or not — and
/// changes nothing twice.
/// </summary>
internal sealed partial class GrantLedger
{
    /// <summary>Two readings of one boot's time agree within this (the kernel's value is fixed for a boot; the tolerance
    /// only absorbs representation). Consecutive boots are always further apart than this.</summary>
    internal static readonly TimeSpan BootTolerance = TimeSpan.FromSeconds(2);

    /// <summary>The recovery points (N16, M12): after U0, after each of U1–U5 (and U4b), per run file in U3, and between U6's two
    /// writes. A self-test throws from the hold hook at one to model a crash there.</summary>
    internal static class RecoveryPoints
    {
        internal const string U0 = "recovery:U0", U1 = "recovery:U1+U2", U3Run = "recovery:U3:run", U3 = "recovery:U3", U3c = "recovery:U3c", U4 = "recovery:U4", U4b = "recovery:U4b", U5 = "recovery:U5", U6Session = "recovery:U6:session";
    }

    /// <summary>
    /// Run at every start, before the pipe server starts (§2.4): (1) a PENDING recovery is completed first — resumed under
    /// its id if it started in this boot, else superseded by a new one; (2) a NEW boot — the boot time differs from the
    /// session marker's, or cannot be read, or the marker is missing or unreadable while the store holds records — starts
    /// a recovery whatever else the marker says; (3) otherwise (the same boot: a process crash, a service stop or restart)
    /// nothing is recovered. Throws when recovery cannot complete: the caller then serves nothing (fail closed).
    /// Phase 6 (L-5): an installer restore marker not yet applied (<paramref name="restore"/>) starts the restored epoch, in
    /// any boot: a recovery whose reason is <c>restored:&lt;id&gt;</c> also ends every open run (<c>restored</c>) and voids
    /// every unconsumed fix confirmation.
    /// </summary>
    internal RecoveryOutcome StartupRecovery(IBootIdentity boot, RestoreMarker? restore = null)
    {
        lock (EnterGate())
        {
            string? bootIso = boot.BootKey();
            RecoveryMarker? pending = ReadMarker<RecoveryMarker>(StorePaths.RecoveryPath, out bool recoveryUnreadable) is { State: "pending" } p ? p : null;
            if (recoveryUnreadable) throw new InvalidDataException("the recovery marker is unreadable; nothing is served until an operator repairs or reinstalls the custodian (fail closed)");
            string? restoredReason = restore is null ? null : RestoredPrefix + restore.RestoreId;
            if (pending is not null)
            {
                RecoveryOutcome resumed = CompletePending(pending, boot, bootIso);
                // A restore marker that arrived while another recovery was pending: its restored epoch follows at once.
                if (restoredReason is null || resumed.Reason.EndsWith(restoredReason, StringComparison.Ordinal)) return resumed;
            }
            SessionMarker? session = ReadMarker<SessionMarker>(StorePaths.SessionPath, out bool sessionUnreadable);
            if (restoredReason is not null && session?.LastRestoreId != restore!.RestoreId)
                return Recover(restoredReason, bootIso);
            string? reason =
                bootIso is null ? "boot_identity_unreadable"
                : sessionUnreadable ? "session_marker_unreadable"
                : session is null ? (StoreHoldsRecords() ? "session_marker_missing" : null)
                : !boot.SameBoot(session.BootTime, bootIso) ? "new_boot"
                : null;
            if (reason is null)
            {
                // First start of an empty store, or a start in the same boot: nothing can have been rolled back.
                WriteMarker(StorePaths.SessionPath, new SessionMarker(bootIso, NowIso(), false, session?.LastRecoveryId, session?.LastRestoreId));
                return new RecoveryOutcome(false, null, session is null ? "first_start" : "same_boot", false);
            }
            return Recover(reason, bootIso);
        }
    }

    private RecoveryOutcome Recover(string reason, string? bootIso)
    {
        string recoveryId = NewRecoveryId();
        RunRecovery(recoveryId, reason, bootIso, resume: false);
        return new RecoveryOutcome(true, recoveryId, reason, false);
    }

    /// <summary>A pending recovery is resumed under its id in its own boot; in another boot a new one supersedes it. A
    /// restored epoch superseded keeps its reason, so its steps (L-5) still apply, under the new id.</summary>
    private RecoveryOutcome CompletePending(RecoveryMarker pending, IBootIdentity boot, string? bootIso)
    {
        if (boot.SameBoot(pending.BootTime, bootIso))
        {
            RunRecovery(pending.RecoveryId, pending.Reason, bootIso, resume: true);
            return new RecoveryOutcome(true, pending.RecoveryId, $"resumed: {pending.Reason}", true);
        }
        return Recover(pending.Reason.StartsWith(RestoredPrefix, StringComparison.Ordinal) ? pending.Reason : "pending_recovery_from_an_earlier_boot", bootIso);
    }

    /// <summary>Record a graceful stop in the session marker — a diagnostic only: it never establishes that the latest
    /// state survived (§2.4).</summary>
    internal void MarkCleanStop()
    {
        lock (EnterGate())
        {
            SessionMarker? s = ReadMarker<SessionMarker>(StorePaths.SessionPath, out bool unreadable);
            if (s is null || unreadable) return;
            WriteMarker(StorePaths.SessionPath, s with { CleanStop = true, RecordedAt = NowIso() });
        }
    }

    /// <summary>L-5 (d): an open run ends "restored" — its loop first, so a crash between the two leaves no live loop behind
    /// a resumed recovery (which skips this run, already stamped, only after the run itself is written).</summary>
    private RunRecord EndRestored(RunRecord run, DateTime now)
    {
        EndLoopForRun(run.RepoKey, run.RunId, RunStatuses.Stopped, now);
        return run with { Status = RunStatuses.Stopped, Ended = new RunEnded(RunStatuses.Stopped, "restored", Iso(now), CustodianActor) };
    }

    /// <summary>U3c (L-5 c): every fix confirmation not yet consumed, on any run, is void (its expiry becomes now, never later).</summary>
    private static void VoidUnconsumedConfirmations(DateTime now)
    {
        if (!Directory.Exists(StorePaths.RunsDir)) return;
        foreach (string file in Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            RunRecord run = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new InvalidDataException($"a run record is unreadable ({Path.GetFileName(file)})");
            var open = run.Operations.Where(op => op.Status == FixConfirmed).Select(op => op.Outcome?["confirmation"]).OfType<JsonObject>().Where(c => c["voidedAt"] is null).ToList();
            foreach (JsonObject c in open)
            {
                if (c["expiresAt"] is JsonValue exp && ParseTime((string)exp!) > now) c["expiresAt"] = Iso(now);
                c["voidedAt"] = Iso(now);
                c["voidedReason"] = "restored";
            }
            if (open.Count > 0) WriteRun(run);
        }
    }

    /// <summary>The reason of a restored epoch's recovery: this prefix and the restore marker's id.</summary>
    internal const string RestoredPrefix = "restored:";

    private void RunRecovery(string recoveryId, string reason, string? bootIso, bool resume)
    {
        DateTime now = _clock();
        // Phase 6 (L-5): a restored epoch is the recovery plus (d) every open run ended "restored" and (c) every unconsumed fix
        // confirmation void; (a) the lapses (U4b), (b) the suspended grants (U2) and the void intents (U5) are the recovery's.
        string? restoreId = reason.StartsWith(RestoredPrefix, StringComparison.Ordinal) ? reason[RestoredPrefix.Length..] : null;
        if (!resume) WriteMarker(StorePaths.RecoveryPath, new RecoveryMarker(recoveryId, "pending", reason, bootIso, Iso(now), null)); // U0
        Hold(RecoveryPoints.U0);
        Audit($"recovery {(resume ? "resumed" : "started")} recoveryId={recoveryId} reason={reason}");

        // U1 (loops) and U2 (grants): one ledger write.
        LedgerFile ledger = Read();
        bool ledgerChanged = false;
        for (int i = 0; i < ledger.Loops!.Count; i++)
        {
            LoopRecord loop = Normalized(ledger.Loops[i]);
            if (loop.LastRecoveryId == recoveryId || LoopStatuses.IsTerminal(loop.Status)) continue;
            ledger.Loops[i] = RecoveredLoop(loop, recoveryId, now);
            ledgerChanged = true;
        }
        for (int i = 0; i < ledger.Grants.Count; i++)
        {
            Grant g = ledger.Grants[i];
            if (g.LastRecoveryId == recoveryId || g.RevokedAt is not null || ParseTime(g.ExpiresAt) <= now) continue;
            ledger.Grants[i] = g with { SuspendedAt = g.SuspendedAt ?? Iso(now), LastRecoveryId = recoveryId };
            ledgerChanged = true;
        }
        if (ledgerChanged) Write(ledger);
        Hold(RecoveryPoints.U1);

        // U3 (evidence): every open run gets a new evidence epoch, once per recovery.
        if (Directory.Exists(StorePaths.RunsDir))
        {
            foreach (string file in Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                RunRecord run = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new InvalidDataException($"a run record is unreadable ({Path.GetFileName(file)})");
                if (run.LastRecoveryId == recoveryId || run.IsTerminal) continue;
                RunRecord next = run with { EvidenceEpoch = run.EvidenceEpoch + 1, LastRecoveryId = recoveryId };
                WriteRun(restoreId is null ? next : EndRestored(next, now));
                Hold(RecoveryPoints.U3Run);
            }
        }
        Hold(RecoveryPoints.U3);

        // U3c (L-5 c): every fix confirmation not yet consumed, on any run, is void: its expiry becomes now (never later), so
        // its application is refused CONFIRMATION_EXPIRED and the owner confirms the custodian's rendering again.
        if (restoreId is not null) VoidUnconsumedConfirmations(now);
        Hold(RecoveryPoints.U3c);

        // U4 (decisions): every user-record log records the revision recovery ran at.
        UserRecordsFile users = ReadUserRecords();
        bool usersChanged = false;
        for (int i = 0; i < users.Logs.Count; i++)
        {
            UserRecordLog log = users.Logs[i];
            if (log.LastRecoveryId == recoveryId) continue;
            users.Logs[i] = log with { RecoveredAtRevision = log.Revision, LastRecoveryId = recoveryId };
            usersChanged = true;
        }
        if (usersChanged) WriteUserRecords(users);
        Hold(RecoveryPoints.U4);

        // U4b (P3.4C-4, §2.4): every configuration record in force — each repository's current record, every isolation
        // acceptance and every self-test confirmation not revoked or superseded — lapses until the operator re-confirms it,
        // so a record a rollback restored takes effect only after an operator action. One write; records already stamped
        // with this recovery are skipped, so a resumed recovery lapses each record exactly once.
        if (File.Exists(StorePaths.ConfigRecordsPath))
        {
            ConfigRecordsFile config;
            try { config = ReadConfigRecords(); }
            catch (InvalidDataException)
            {
                // An unreadable file serves nothing (every configuration read refuses); it is left for an administrator.
                Audit($"recovery U4b recoveryId={recoveryId}: config-records.json is unreadable; it serves nothing (fail closed)");
                config = null!;
            }
            if (config is not null)
            {
                bool configChanged = false;
                for (int i = 0; i < config.Repositories.Count; i++)
                {
                    RepositoryConfig r = config.Repositories[i];
                    if (!r.IsCurrent || r.IsRevoked || r.LastRecoveryId == recoveryId) continue;
                    config.Repositories[i] = r with { LapsedAtRecoveryId = recoveryId, LastRecoveryId = recoveryId };
                    configChanged = true;
                }
                for (int i = 0; i < config.Acceptances.Count; i++)
                {
                    IsolationAcceptanceRecord a = config.Acceptances[i];
                    if (a.RevokedAt is not null || a.LastRecoveryId == recoveryId) continue;
                    config.Acceptances[i] = a with { LapsedAtRecoveryId = recoveryId, LastRecoveryId = recoveryId };
                    configChanged = true;
                }
                for (int i = 0; i < config.SelftestConfirmations.Count; i++)
                {
                    SelfTestConfirmationRecord c = config.SelftestConfirmations[i];
                    if (c.RevokedAt is not null || c.SupersededAt is not null || c.LastRecoveryId == recoveryId) continue;
                    config.SelftestConfirmations[i] = c with { LapsedAtRecoveryId = recoveryId, LastRecoveryId = recoveryId };
                    configChanged = true;
                }
                // P3.4C-5 (contract §2.1): the engine runtime approval lapses with the other global records.
                if (config.EngineRuntimes is { } runtimes)
                    for (int i = 0; i < runtimes.Count; i++)
                    {
                        EngineRuntimeRecord rt = runtimes[i];
                        if (rt.RevokedAt is not null || rt.SupersededAt is not null || rt.LastRecoveryId == recoveryId) continue;
                        runtimes[i] = rt with { LapsedAtRecoveryId = recoveryId, LastRecoveryId = recoveryId };
                        configChanged = true;
                    }
                if (configChanged) WriteConfigRecords(config);
            }
        }
        Hold(RecoveryPoints.U4b);

        // U5 (intents): every pending intent is void.
        if (Directory.Exists(StorePaths.IntentsDir))
            foreach (string f in Directory.EnumerateFiles(StorePaths.IntentsDir, "*.json")) File.Delete(f);
        Hold(RecoveryPoints.U5);

        // U6: the session marker names this boot (and, for a restored epoch, the restore it applied — only now, after every
        // step above is durable); then the recovery is complete — only then does the pipe server start.
        string? lastRestore = restoreId ?? ReadMarker<SessionMarker>(StorePaths.SessionPath, out _)?.LastRestoreId;
        WriteMarker(StorePaths.SessionPath, new SessionMarker(bootIso, Iso(now), false, recoveryId, lastRestore));
        Hold(RecoveryPoints.U6Session);
        RecoveryMarker done = ReadMarker<RecoveryMarker>(StorePaths.RecoveryPath, out _) is { RecoveryId: var id } m && id == recoveryId
            ? m with { State = "complete", CompletedAt = Iso(now) }
            : new RecoveryMarker(recoveryId, "complete", reason, bootIso, Iso(now), Iso(now));
        WriteMarker(StorePaths.RecoveryPath, done);
        Audit($"recovery complete recoveryId={recoveryId} reason={reason}");
    }

    /// <summary>U1 for one live loop: an active loop pauses for the operator; a pause the implementer may clear becomes
    /// that operator-only pause (an operator-only pause keeps its reason); an unbound loop ends — its one-time nonce lived
    /// only in the memory of the server that asked for it, so it can never be bound now.</summary>
    private static LoopRecord RecoveredLoop(LoopRecord loop, string recoveryId, DateTime now)
    {
        LoopRecord next;
        if (loop.Status == LoopStatuses.Unbound)
            next = loop with { Status = LoopStatuses.Cancelled, Ended = new LoopEnded(LoopStatuses.Cancelled, "unbindable after an OS restart", Iso(now), CustodianActor) };
        else if (loop.Status == LoopStatuses.Paused && loop.Pause is { } p && PauseReasons.OperatorOnly.Contains(p.Reason))
            next = loop;
        else
            next = loop with
            {
                Status = LoopStatuses.Paused,
                Pause = new LoopPause(PauseReasons.OperatorActionRequired, loop.Pause is { } prior ? $"recovered_after_os_restart (was {prior.Reason})" : "recovered_after_os_restart", Iso(now), CustodianActor),
            };
        var evidence = new LoopEvent(loop.Events!.Count + 1, "recover", "", CustodianActor, null, Iso(now), "", loop.Status, next.Status, loop.Epoch,
            new JsonObject { ["recoveryId"] = recoveryId, ["status"] = next.Status });
        return next with { LoopRevision = loop.LoopRevision + 1, Events = [.. loop.Events, evidence], LastRecoveryId = recoveryId };
    }

    /// <summary>Does the store hold any record a rollback could restore (a grant, a loop, a user record, a run, a
    /// configuration record)?</summary>
    private bool StoreHoldsRecords()
        => File.Exists(StorePaths.LedgerPath) || File.Exists(StorePaths.UserRecordsPath) || File.Exists(StorePaths.ConfigRecordsPath)
           || (Directory.Exists(StorePaths.RunsDir) && Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories).Any());

    private static string NewRecoveryId() => "rec-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));

    private static T? ReadMarker<T>(string path, out bool unreadable) where T : class
    {
        unreadable = false;
        if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json) ?? throw new JsonException("empty"); }
        catch (Exception e) when (e is JsonException or IOException or NotSupportedException) { unreadable = true; return null; }
    }

    private static void WriteMarker<T>(string path, T marker) => AtomicWrite(path, JsonSerializer.Serialize(marker, Json));
}
