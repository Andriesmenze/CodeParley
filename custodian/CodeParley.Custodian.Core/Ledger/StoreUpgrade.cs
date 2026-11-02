using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// Phase 6 Increment 2 (contract §6.1, L-2 to L-4 and L-6): the store migration the installer's <c>upgrade</c> runs, with
/// the service stopped, after it backed the store up. It is journaled in <c>upgrade-journal.json</c> at the store root —
/// the backup's SHA-256 first, then each step — atomic per file (the durable replacement) and idempotent: a step that
/// completed is never run again, and every step carries state as it is (no expiry is extended, no counter reset, nothing
/// consumed, revoked or suspended is undone). While a journal is incomplete the custodian serves nothing
/// (<see cref="StoreFormat.RequireServable"/>); <c>--resume</c> completes it, or the installer's <c>rollback</c> restores
/// the backup. A store newer than this build is never migrated (no downgrade).
/// </summary>
internal static class StoreUpgrade
{
    internal static string JournalPath => Path.Combine(StorePaths.Root, "upgrade-journal.json");

    internal const string Pending = "pending", Complete = "complete";

    internal sealed record Step(string Id, string State, string? At);

    internal sealed record Journal(string UpgradeId, int FromFormat, int ToFormat, string BackupSha256, string StartedAt, string StartedBy,
        List<Step> Steps, string State, string? CompletedAt, string? LastError);

    /// <summary>SELF-TEST ONLY: called after the journal is written and after each step (crash injection).</summary>
    internal static Action<string>? HoldHook;

    /// <summary>TEST HOOK (the native VM gate's interrupted upgrade): seconds to hold after the journal is written and after
    /// each step, so the gate can kill the migration between two of them. Read from <c>CODEPARLEY_TEST_UPGRADE_HOLD_SECONDS</c>
    /// (1 to 60; anything else is ignored). The verb runs as the administrator (Windows) or root's chosen account (Linux),
    /// who can change the store anyway; it only delays and changes no decision.</summary>
    private static void TestHold()
    {
        if (int.TryParse(Environment.GetEnvironmentVariable("CODEPARLEY_TEST_UPGRADE_HOLD_SECONDS"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int s) && s is >= 1 and <= 60)
        {
            Console.Error.WriteLine($"TEST HOOK: holding the store upgrade {s} s (CODEPARLEY_TEST_UPGRADE_HOLD_SECONDS)");
            Thread.Sleep(TimeSpan.FromSeconds(s));
        }
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>The migration's steps from each format to the next. Format 1 → 2: the store is read whole at the versions
    /// this build reads (nothing is rewritten), then marked format 2.</summary>
    private static IReadOnlyList<(string Id, Func<int> Run)> StepsFrom(int format) => format switch
    {
        1 => [("1to2:read-every-record", () => new GrantLedger("store-upgrade").ReadEveryRecordForUpgrade()), ("1to2:mark-format-2", () => { StoreFormat.WriteCurrent(); return 0; })],
        _ => throw new InvalidDataException($"no migration from store format {format} is known to this build"),
    };

    /// <summary>The journal, or null when there is none; an unreadable journal refuses (fail closed).</summary>
    internal static Journal? ReadJournal()
    {
        if (!File.Exists(JournalPath)) return null;
        try { return JsonSerializer.Deserialize<Journal>(File.ReadAllText(JournalPath), Json) ?? throw new JsonException("empty"); }
        catch (Exception e) when (e is JsonException or NotSupportedException)
        {
            throw new InvalidDataException($"upgrade-journal.json is unreadable ({e.Message}); restore the store with the installer's `rollback`. Nothing is served");
        }
    }

    /// <summary>The refusal while a journal is incomplete, or null.</summary>
    internal static string? IncompleteRefusal()
        => ReadJournal() is { State: not Complete } j
            ? $"the store upgrade {j.UpgradeId} (format {j.FromFormat} → {j.ToFormat}) is incomplete{(j.LastError is null ? "" : $" ({j.LastError})")}; the installer's `upgrade --resume` completes it, or `rollback` restores the backup taken before it. Nothing is served until then"
            : null;

    /// <summary>
    /// Run (or, with <paramref name="resume"/>, complete) the migration. A new upgrade needs the SHA-256 of the backup the
    /// installer took first; a resumed one keeps its journal's (and refuses another). Throws InvalidDataException with the
    /// remedy when it refuses or a step fails (the journal then records the error and stays incomplete).
    /// </summary>
    internal static JsonObject Run(string? backupSha256, bool resume)
    {
        if (backupSha256 is not null && !IsSha256(backupSha256)) throw new InvalidDataException("--backup-sha256 must be the 64 lowercase hex digits of the backup's SHA-256");
        using StoreLock _ = StoreLock.Acquire("store-upgrade");
        Journal? journal = ReadJournal();
        if (journal is { State: not Complete })
        {
            if (!resume) throw new InvalidDataException(IncompleteRefusal()!);
            if (backupSha256 is not null && backupSha256 != journal.BackupSha256) throw new InvalidDataException($"the incomplete upgrade {journal.UpgradeId} was journaled with another backup ({journal.BackupSha256}); it resumes only with its own");
            return Continue(journal, resumed: true);
        }
        if (resume) throw new InvalidDataException("there is no incomplete store upgrade to resume");
        StoreFormat.Reading r = StoreFormat.Read();
        switch (r.Kind)
        {
            case StoreFormat.Kind.Current: return Result("current", r.Format, files: 0, upgradeId: null);
            case StoreFormat.Kind.Fresh: StoreFormat.WriteCurrent(); return Result("fresh", StoreFormat.Current, files: 0, upgradeId: null);
            case StoreFormat.Kind.Older: break;
            default: throw new InvalidDataException(StoreFormat.Refusal(r)); // newer or unreadable: never migrated (L-6)
        }
        if (backupSha256 is null) throw new InvalidDataException($"{r.Detail}: the upgrade needs --backup-sha256 <hex>, the SHA-256 of the backup the installer took first (L-4)");
        int from = r.Format!.Value;
        var steps = new List<Step>();
        for (int f = from; f < StoreFormat.Current; f++) steps.AddRange(StepsFrom(f).Select(s => new Step(s.Id, Pending, null)));
        journal = new Journal("upg-" + Guid.NewGuid().ToString("N")[..12], from, StoreFormat.Current, backupSha256, Now(), Writer(), steps, Pending, null, null);
        Write(journal);
        HoldHook?.Invoke("journal");
        TestHold();
        return Continue(journal, resumed: false);
    }

    private static JsonObject Continue(Journal journal, bool resumed)
    {
        var actions = new Dictionary<string, Func<int>>(StringComparer.Ordinal);
        for (int f = journal.FromFormat; f < journal.ToFormat; f++)
            foreach ((string id, Func<int> run) in StepsFrom(f)) actions[id] = run;
        int files = 0;
        for (int i = 0; i < journal.Steps.Count; i++)
        {
            Step step = journal.Steps[i];
            if (step.State == Complete) continue;
            try { files += actions[step.Id](); }
            catch (Exception e) when (e is InvalidDataException or JsonException or IOException or UnauthorizedAccessException)
            {
                Write(journal with { LastError = $"step {step.Id}: {e.Message}" });
                throw new InvalidDataException($"the store upgrade {journal.UpgradeId} stopped at step {step.Id}: {e.Message}. Nothing was changed by that step; restore the store with the installer's `rollback` (or repair the file and `upgrade --resume`). Nothing is served until then");
            }
            journal.Steps[i] = step with { State = Complete, At = Now() };
            Write(journal with { LastError = null });
            HoldHook?.Invoke(step.Id);
            TestHold();
        }
        Write(journal with { State = Complete, CompletedAt = Now(), LastError = null });
        return Result(resumed ? "resumed" : "upgraded", journal.ToFormat, files, journal.UpgradeId);
    }

    /// <summary>What the installer reads before it upgrades, rolls back or uninstalls (L-1): the format and the journal.</summary>
    internal static JsonObject Status()
    {
        StoreFormat.Reading r = StoreFormat.Read();
        var o = new JsonObject { ["format"] = r.Format, ["kind"] = r.Kind.ToString().ToLowerInvariant(), ["serves"] = StoreFormat.Current, ["detail"] = r.Detail };
        try
        {
            Journal? j = ReadJournal();
            o["upgrade"] = j is null ? null : new JsonObject { ["upgradeId"] = j.UpgradeId, ["state"] = j.State, ["fromFormat"] = j.FromFormat, ["toFormat"] = j.ToFormat, ["backupSha256"] = j.BackupSha256, ["lastError"] = j.LastError };
        }
        catch (InvalidDataException e) { o["upgrade"] = new JsonObject { ["state"] = "unreadable", ["lastError"] = e.Message }; }
        return o;
    }

    private static JsonObject Result(string status, int? format, int files, string? upgradeId)
        => new() { ["status"] = status, ["format"] = format, ["recordFilesRead"] = files, ["upgradeId"] = upgradeId };

    private static void Write(Journal j) => DurableStore.Replace(JournalPath, JsonSerializer.Serialize(j, Json));

    private static bool IsSha256(string s) => s.Length == 64 && s.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static string Now() => DateTime.UtcNow.ToString("o");

    private static string Writer() => StoreFormat.WriterName();
}
