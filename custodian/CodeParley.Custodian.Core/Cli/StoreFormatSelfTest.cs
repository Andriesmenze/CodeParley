using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 6 Increment 2 (contract §6.1, L-1 and L-6): the store format check, against a scratch store (both hosts). A fresh
/// store is marked and served; a 0.3.x store (records, no marker) waits for `upgrade`; a newer, unreadable or
/// over-specified marker is refused with its remedy; a versioned store file at a version this build does not read is
/// refused when it is read.
/// </summary>
internal static class StoreFormatSelfTest
{
    internal static int Run()
    {
        string scratch = Path.Combine(Path.GetTempPath(), "cp-storefmt-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        int failed = 0;
        try
        {
            StorePaths.OverrideRootForSelfTest(scratch);
            Directory.CreateDirectory(scratch);

            failed += Check("an empty store is fresh", StoreFormat.Read().Kind == StoreFormat.Kind.Fresh);
            Directory.CreateDirectory(Path.Combine(scratch, "runs"));
            failed += Check("empty record directories do not make it a used store", StoreFormat.Read().Kind == StoreFormat.Kind.Fresh);
            StoreFormat.RequireServable();
            StoreFormat.Reading marked = StoreFormat.Read();
            failed += Check($"a fresh store is marked with this build's format ({StoreFormat.Current}) and served", marked.Kind == StoreFormat.Kind.Current && marked.Format == StoreFormat.Current);
            StoreFormat.RequireServable();
            failed += Check("a current store is served again", StoreFormat.Read().Kind == StoreFormat.Kind.Current);

            File.Delete(StoreFormat.MarkerPath);
            File.WriteAllText(StorePaths.LedgerPath, "{\"version\":1,\"grants\":[],\"loops\":[]}");
            StoreFormat.Reading legacy = StoreFormat.Read();
            failed += Check("a store with records and no marker is the 0.3.x format 1", legacy.Kind == StoreFormat.Kind.Older && legacy.Format == StoreFormat.Legacy);
            failed += Check("... and it is refused until `upgrade` migrates it", Refused(() => StoreFormat.RequireServable(), "upgrade"));
            failed += Check("... and nothing was written to it (no marker)", !File.Exists(StoreFormat.MarkerPath));

            File.WriteAllText(StoreFormat.MarkerPath, $"{{\"format\":{StoreFormat.Current + 1},\"writtenBy\":\"a later build\",\"writtenAt\":\"2027-01-01T00:00:00Z\"}}");
            failed += Check("a newer format is refused, naming the matching build or `rollback` (no downgrade)", StoreFormat.Read().Kind == StoreFormat.Kind.Newer && Refused(() => StoreFormat.RequireServable(), "rollback"));
            File.WriteAllText(StoreFormat.MarkerPath, $"{{\"format\":{StoreFormat.Current - 1},\"writtenBy\":\"an earlier build\",\"writtenAt\":\"2026-01-01T00:00:00Z\"}}");
            failed += Check("an older marked format is refused until `upgrade`", StoreFormat.Read().Kind == StoreFormat.Kind.Older && Refused(() => StoreFormat.RequireServable(), "upgrade"));
            File.WriteAllText(StoreFormat.MarkerPath, "not json");
            failed += Check("an unreadable marker is refused, naming `rollback`", StoreFormat.Read().Kind == StoreFormat.Kind.Unreadable && Refused(() => StoreFormat.RequireServable(), "rollback"));
            File.WriteAllText(StoreFormat.MarkerPath, $"{{\"format\":{StoreFormat.Current},\"writtenBy\":\"x\",\"writtenAt\":\"x\",\"migrated\":true}}");
            failed += Check("a marker with an unknown field is unreadable (no field is ignored)", StoreFormat.Read().Kind == StoreFormat.Kind.Unreadable);
            File.WriteAllText(StoreFormat.MarkerPath, "{\"format\":0,\"writtenBy\":\"x\",\"writtenAt\":\"x\"}");
            failed += Check("format 0 is unreadable", StoreFormat.Read().Kind == StoreFormat.Kind.Unreadable);

            StoreFormat.WriteCurrent();
            var ledger = new GrantLedger("cust-storefmt");
            failed += Check("a ledger of the version this build reads is read", NoThrow(() => ledger.Read()));
            File.WriteAllText(StorePaths.LedgerPath, "{\"version\":2,\"grants\":[],\"loops\":[]}");
            failed += Check("a ledger of another version is refused when read (L-1)", Refused(() => ledger.Read(), "ledger.json is version 2"));
            File.WriteAllText(StorePaths.ConfigRecordsPath, "{\"version\":7,\"globalRevision\":0,\"repositories\":[],\"acceptances\":[],\"confirmations\":[]}");
            failed += Check("configuration records of another version are refused when read", Refused(() => GrantLedger.ReadConfigRecords(), "config-records.json is version 7"));

            // L-5: the restore marker's shape (each host checks who wrote it before this).
            string sha = new('0', 64);
            string M(string fields) => "{" + fields + "}";
            string good = $"\"restoreId\":\"rst-20261028-0001\",\"restoredAt\":\"2026-10-28T20:00:00.0000000Z\",\"backupSha256\":\"{sha}\",\"storeFormat\":{StoreFormat.Current}";
            failed += Check("L-5: a well-formed restore marker is read", RestoreMarkers.Parse(M(good), "m") is { RestoreId: "rst-20261028-0001" } r && r.StoreFormat == StoreFormat.Current);
            failed += Check("L-5: a marker with an unknown field is refused", Refused(() => RestoreMarkers.Parse(M(good + ",\"keepGrants\":true"), "m"), "unexpected field"));
            failed += Check("L-5: a marker for another store format is refused", Refused(() => RestoreMarkers.Parse(M(good.Replace($"\"storeFormat\":{StoreFormat.Current}", "\"storeFormat\":1", StringComparison.Ordinal)), "m"), "store format 1"));
            failed += Check("L-5: a marker whose backup hash is not 64 lowercase hex digits is refused", Refused(() => RestoreMarkers.Parse(M(good.Replace(sha, sha.ToUpperInvariant()[..63] + "A", StringComparison.Ordinal)), "m"), "backupSha256"));
            failed += Check("L-5: a marker without a restore id, or with one outside a-z0-9-, is refused",
                Refused(() => RestoreMarkers.Parse(M(good.Replace("\"restoreId\":\"rst-20261028-0001\",", "", StringComparison.Ordinal)), "m"), "restoreId")
                && Refused(() => RestoreMarkers.Parse(M(good.Replace("rst-20261028-0001", "../rst-0001", StringComparison.Ordinal)), "m"), "restoreId"));
            failed += Check("L-5: a marker whose time is not UTC, or that is not JSON, is refused",
                Refused(() => RestoreMarkers.Parse(M(good.Replace("Z\"", "+01:00\"", StringComparison.Ordinal)), "m"), "restoredAt")
                && Refused(() => RestoreMarkers.Parse("not json", "m"), "not JSON"));
        }
        catch (Exception e)
        {
            Console.WriteLine($"[FAIL] unexpected: {e.GetType().Name}: {e.Message}");
            failed++;
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(scratch)!, true); } catch { /* best effort */ }
        }
        Console.WriteLine($"\nstore-format self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
        return failed == 0 ? 0 : 1;
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
