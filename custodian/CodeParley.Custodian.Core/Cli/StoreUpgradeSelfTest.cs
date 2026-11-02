using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 6 Increment 2 (contract §6.1, L-2 to L-4, L-6): the store migration, against scratch stores (both hosts). A 0.3.x
/// store (format 1) is migrated after a backup hash, every record carried byte for byte; a crash after the journal and
/// after each step leaves a journal the service refuses to serve past, and `--resume` completes it once; an upgrade
/// needs the backup hash, a resume keeps its own; a newer or unreadable store, or a record this build cannot read, is
/// never migrated; the store is one process's at a time.
/// </summary>
internal static class StoreUpgradeSelfTest
{
    private const string Backup = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private sealed class SimulatedCrash : Exception;

    internal static int Run()
    {
        int failed = 0;
        failed += InStore(MigratesAndCarries);
        foreach (string point in new[] { "journal", "1to2:read-every-record", "1to2:mark-format-2" })
            failed += InStore(() => CrashAndResume(point));
        failed += InStore(Refusals);
        failed += InStore(UnreadableRecord);
        failed += InStore(OneOwner);
        Console.WriteLine($"\nstore-upgrade self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    private static int MigratesAndCarries()
    {
        int f = 0;
        LegacyStore();
        Dictionary<string, string> before = Hashes();
        f += Check("a 0.3.x store is refused before the upgrade", Refused(StoreFormat.RequireServable, "upgrade"));
        JsonObject r = StoreUpgrade.Run(Backup, resume: false);
        f += Check("L-2: the upgrade migrates format 1 to 2 and reads every record (ledger, user records, configuration, the run, the held content)",
            (string?)r["status"] == "upgraded" && (int?)r["format"] == StoreFormat.Current && (int?)r["recordFilesRead"] == 5);
        Dictionary<string, string> after = Hashes();
        f += Check("L-2: state is carried as it is — every record file byte for byte (no expiry, counter, consumption or revocation changed)",
            before.All(kv => after.TryGetValue(kv.Key, out string? h) && h == kv.Value));
        return f + AfterUpgrade(after.Count);
    }

    private static int AfterUpgrade(int records)
    {
        int f = 0;
        StoreUpgrade.Journal? j = StoreUpgrade.ReadJournal();
        f += Check("L-4: the journal holds the backup's hash, every step complete", j is { State: StoreUpgrade.Complete } && j.BackupSha256 == Backup && j.Steps.All(s => s.State == StoreUpgrade.Complete));
        f += Check("the migrated store is served", NoThrow(StoreFormat.RequireServable));
        f += Check("L-2: idempotent — an upgrade of a current store changes nothing", (string?)StoreUpgrade.Run(Backup, resume: false)["status"] == "current" && Hashes().Count == records);
        f += Check("L-1: store-status reports the format and the completed upgrade",
            StoreUpgrade.Status() is { } st && (string?)st["kind"] == "current" && (string?)st["upgrade"]?["state"] == StoreUpgrade.Complete);
        return f;
    }

    private static int CrashAndResume(string point)
    {
        LegacyStore();
        Dictionary<string, string> before = Hashes();
        StoreUpgrade.HoldHook = p => { if (p == point) throw new SimulatedCrash(); };
        try { StoreUpgrade.Run(Backup, resume: false); } catch (SimulatedCrash) { } finally { StoreUpgrade.HoldHook = null; }
        bool refusesServe = Refused(StoreFormat.RequireServable, "upgrade --resume");
        bool refusesNew = Refused(() => StoreUpgrade.Run(Backup, resume: false), "is incomplete");
        bool refusesOtherBackup = Refused(() => StoreUpgrade.Run(Backup.Replace('0', 'f'), resume: true), "another backup");
        JsonObject r = StoreUpgrade.Run(null, resume: true);
        Dictionary<string, string> after = Hashes();
        return Check($"L-3: a crash after {point} → the service refuses to serve (naming `upgrade --resume` / `rollback`), a new upgrade and another backup are refused, and `--resume` completes it with every record unchanged",
            refusesServe && refusesNew && refusesOtherBackup && (string?)r["status"] == "resumed" && StoreUpgrade.ReadJournal() is { State: StoreUpgrade.Complete }
            && before.All(kv => after.TryGetValue(kv.Key, out string? h) && h == kv.Value) && NoThrow(StoreFormat.RequireServable));
    }

    private static int Refusals()
    {
        int f = 0;
        LegacyStore();
        f += Check("L-4: an upgrade without the backup's hash is refused, and changes nothing", Refused(() => StoreUpgrade.Run(null, resume: false), "--backup-sha256") && !File.Exists(StoreUpgrade.JournalPath) && !File.Exists(StoreFormat.MarkerPath));
        f += Check("a malformed backup hash is refused", Refused(() => StoreUpgrade.Run("ABC", resume: false), "64 lowercase hex"));
        f += Check("L-3: a resume without an incomplete upgrade is refused", Refused(() => StoreUpgrade.Run(null, resume: true), "no incomplete"));
        File.WriteAllText(StoreFormat.MarkerPath, $"{{\"format\":{StoreFormat.Current + 1},\"writtenBy\":\"a later build\",\"writtenAt\":\"2027-01-01T00:00:00Z\"}}");
        f += Check("L-6: a newer store is never migrated (no downgrade)", Refused(() => StoreUpgrade.Run(Backup, resume: false), "rollback") && !File.Exists(StoreUpgrade.JournalPath));
        File.WriteAllText(StoreUpgrade.JournalPath, "{\"upgradeId\":\"x\"");
        f += Check("an unreadable journal refuses to serve (fail closed)", Refused(StoreFormat.RequireServable, "upgrade-journal.json is unreadable"));
        return f;
    }

    private static int UnreadableRecord()
    {
        LegacyStore();
        File.WriteAllText(StorePaths.LedgerPath, "{\"version\":2,\"grants\":[],\"loops\":[]}");
        bool refused = Refused(() => StoreUpgrade.Run(Backup, resume: false), "stopped at step 1to2:read-every-record");
        StoreUpgrade.Journal? j = StoreUpgrade.ReadJournal();
        return Check("L-2: a record this build cannot read stops the upgrade before the store is marked; the journal records why and the service refuses",
            refused && j is { State: StoreUpgrade.Pending, LastError: not null } && !File.Exists(StoreFormat.MarkerPath) && Refused(StoreFormat.RequireServable, "ledger.json is version 2"));
    }

    private static int OneOwner()
    {
        LegacyStore();
        using (StoreLock.Acquire("self-test service"))
        {
            if (Check("L-2: the store is one process's at a time — an upgrade while the service holds it is refused", Refused(() => StoreUpgrade.Run(Backup, resume: false), "in use")) != 0) return 1;
        }
        return Check("... and runs once the service let go", (string?)StoreUpgrade.Run(Backup, resume: false)["status"] == "upgraded");
    }

    /// <summary>A store CodeParley 0.3.x-era builds wrote (no format marker): a grant with loops used and one revoked, the
    /// user records, the configuration records, a run record and a held fix-proposal content.</summary>
    private static void LegacyStore()
    {
        File.WriteAllText(StorePaths.LedgerPath, "{\"version\":1,\"grants\":[" +
            "{\"grantId\":\"g-1\",\"repoKey\":\"rk\",\"repositoryRoot\":null,\"loopsTotal\":4,\"loopsUsed\":2,\"createdAt\":\"2026-10-01T00:00:00.0000000Z\",\"expiresAt\":\"2026-10-01T01:00:00.0000000Z\",\"revokedAt\":null,\"recordedBy\":{\"role\":\"operator\",\"channel\":\"cli\",\"assurance\":\"verified\",\"proofDigest\":\"d\",\"requestId\":\"r\"},\"requestId\":\"r1\",\"uses\":[],\"suspendedAt\":\"2026-10-01T00:30:00.0000000Z\"}," +
            "{\"grantId\":\"g-2\",\"repoKey\":\"rk\",\"repositoryRoot\":null,\"loopsTotal\":1,\"loopsUsed\":0,\"createdAt\":\"2026-10-01T00:00:00.0000000Z\",\"expiresAt\":\"2026-12-01T00:00:00.0000000Z\",\"revokedAt\":\"2026-10-02T00:00:00.0000000Z\",\"recordedBy\":{\"role\":\"operator\",\"channel\":\"cli\",\"assurance\":\"verified\",\"proofDigest\":\"d\",\"requestId\":\"r\"},\"requestId\":\"r2\",\"uses\":[]}],\"loops\":[]}");
        File.WriteAllText(StorePaths.UserRecordsPath, "{\"version\":1,\"logs\":[]}");
        File.WriteAllText(StorePaths.ConfigRecordsPath, "{\"version\":1,\"globalRevision\":0,\"repositories\":[],\"acceptances\":[],\"confirmations\":[]}");
        GrantLedger.WriteRun(new RunRecord("rk", "run-1", 1, "2026-10-01T00:00:00.0000000Z", "req-1", 1, new RunDeclaration(new string('a', 64), new RunBudgets(3, 3), null),
            RunStatuses.Stopped, new RunEnded(RunStatuses.Stopped, "operator", "2026-10-01T00:10:00.0000000Z", "op"), [], [], [], [], [], [], [], []));
        string held = Path.Combine(StorePaths.FixProposalsDir, "rk", "run-1", "fop-1.json");
        Directory.CreateDirectory(Path.GetDirectoryName(held)!);
        File.WriteAllText(held, "{\"schema\":\"" + GrantLedger.FixProposalContentSchema + "\",\"orphan\":true}");
    }

    /// <summary>Every store file except the ones the upgrade itself writes (marker, journal, lock).</summary>
    private static Dictionary<string, string> Hashes()
    {
        string[] own = [StoreFormat.MarkerPath, StoreUpgrade.JournalPath, StoreLock.LockPath];
        return Directory.EnumerateFiles(StorePaths.Root, "*", SearchOption.AllDirectories).Where(p => !own.Contains(p))
            .ToDictionary(p => Path.GetRelativePath(StorePaths.Root, p), p => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))), StringComparer.Ordinal);
    }

    private static int InStore(Func<int> body)
    {
        string scratch = Path.Combine(Path.GetTempPath(), "cp-storeupg-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        try
        {
            StorePaths.OverrideRootForSelfTest(scratch);
            Directory.CreateDirectory(scratch);
            return body();
        }
        catch (Exception e)
        {
            Console.WriteLine($"[FAIL] unexpected: {e.GetType().Name}: {e.Message}");
            return 1;
        }
        finally
        {
            StoreUpgrade.HoldHook = null;
            try { Directory.Delete(Path.GetDirectoryName(scratch)!, true); } catch { /* best effort */ }
        }
    }

    private static bool Refused(Action a, string mustSay)
    {
        try { a(); return false; }
        catch (InvalidDataException e) { return e.Message.Contains(mustSay, StringComparison.Ordinal); }
    }

    private static bool NoThrow(Action a)
    {
        try { a(); return true; }
        catch { return false; }
    }

    private static int Check(string name, bool ok)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        return ok ? 0 : 1;
    }
}
