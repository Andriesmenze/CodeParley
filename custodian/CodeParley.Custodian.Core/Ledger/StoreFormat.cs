using System.Reflection;
using System.Text.Json;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// Phase 6 Increment 2 (contract §6.1, L-1 and L-6): the protected store's format, checked before any state is accepted.
/// The format is recorded in <c>store-format.json</c> at the store root; a store CodeParley 0.3.x wrote has no marker and
/// is format 1. This build serves only a store of its own format (or a fresh, empty one, which it marks): an older store
/// is accepted only through the installer's <c>upgrade</c> (the migration path, L-2), a newer or unknown one is refused —
/// nothing is served — with the remedy. Each versioned store file is also checked when it is read
/// (<see cref="RequireFileVersion"/>); the files without a version field of their own are versioned by the store format.
/// </summary>
internal static class StoreFormat
{
    /// <summary>The format this build reads and writes.</summary>
    internal const int Current = 2;

    /// <summary>A store without a marker that holds records: written by CodeParley 0.3.x.</summary>
    internal const int Legacy = 1;

    /// <summary>The <c>Version</c> every versioned store file of formats 1 and 2 carries.</summary>
    internal const int FileVersion = 1;

    internal static string MarkerPath => Path.Combine(StorePaths.Root, "store-format.json");

    internal sealed record Marker(int Format, string WrittenBy, string WrittenAt);

    internal enum Kind { Current, Fresh, Older, Newer, Unreadable }

    internal readonly record struct Reading(Kind Kind, int? Format, string Detail);

    private static readonly string[] RecordFiles = ["ledger.json", "user-records.json", "config-records.json", "session.json", "recovery.json", "content-key.secret"];
    private static readonly string[] RecordDirs = ["runs", "fix-proposals", "evidence", "intents"];

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };

    /// <summary>What the store is, without changing it.</summary>
    internal static Reading Read()
    {
        string path = MarkerPath;
        if (!File.Exists(path))
            return HoldsRecords()
                ? new Reading(Kind.Older, Legacy, "the store has no format marker but holds records: CodeParley 0.3.x wrote it (format 1)")
                : new Reading(Kind.Fresh, null, "the store is empty");
        Marker? m;
        try { m = JsonSerializer.Deserialize<Marker>(File.ReadAllText(path), Json); }
        catch (Exception e) when (e is JsonException or IOException or NotSupportedException) { return new Reading(Kind.Unreadable, null, $"store-format.json is unreadable ({e.Message})"); }
        if (m is null || m.Format < 1) return new Reading(Kind.Unreadable, null, "store-format.json holds no valid format");
        if (m.Format > Current) return new Reading(Kind.Newer, m.Format, $"the store is format {m.Format}, written by {m.WrittenBy}");
        if (m.Format < Current) return new Reading(Kind.Older, m.Format, $"the store is format {m.Format}, written by {m.WrittenBy}");
        return new Reading(Kind.Current, m.Format, $"the store is format {m.Format}");
    }

    /// <summary>Before the custodian accepts any state: a current store is served, a fresh one is marked and served, anything
    /// else refuses (the caller serves nothing).</summary>
    internal static void RequireServable()
    {
        // L-3: an incomplete upgrade journal refuses before the format is looked at (its remedy is the journal's).
        if (StoreUpgrade.IncompleteRefusal() is { } incomplete) throw new InvalidDataException(incomplete);
        Reading r = Read();
        if (r.Kind == Kind.Fresh) { WriteCurrent(); return; }
        if (r.Kind != Kind.Current) throw new InvalidDataException(Refusal(r));
    }

    /// <summary>The refusal, with its remedy.</summary>
    internal static string Refusal(Reading r) => r.Kind switch
    {
        Kind.Older => $"{r.Detail}; this custodian serves format {Current} only after the installer's `upgrade` migrates the store (it backs the store up first). Nothing is served until then",
        Kind.Newer => $"{r.Detail}, newer than this build supports (format {Current}); install the CodeParley build that matches the store, or `rollback` to the build that wrote it. Nothing is served (a downgrade is refused)",
        Kind.Unreadable => $"{r.Detail}; restore the store with the installer's `rollback`, or reinstall. Nothing is served",
        _ => r.Detail,
    };

    /// <summary>Record this build's format (the durable write-through replacement).</summary>
    internal static void WriteCurrent()
        => DurableStore.Replace(MarkerPath, JsonSerializer.Serialize(new Marker(Current, WriterName(), DateTime.UtcNow.ToString("o")), Json));

    /// <summary>A versioned store file is read only at the version this build reads (L-1).</summary>
    internal static void RequireFileVersion(string file, int version)
    {
        if (version != FileVersion)
            throw new InvalidDataException($"{file} is version {version}; this build reads version {FileVersion} (store format {Current}). Install the CodeParley build that matches the store, or restore it with the installer's `rollback`. Nothing is served from it");
    }

    private static bool HoldsRecords()
    {
        string root = StorePaths.Root;
        if (RecordFiles.Any(f => File.Exists(Path.Combine(root, f)))) return true;
        return RecordDirs.Any(d => Directory.Exists(Path.Combine(root, d)) && Directory.EnumerateFileSystemEntries(Path.Combine(root, d), "*", SearchOption.AllDirectories).Any());
    }

    internal static string WriterName()
    {
        string v = (Assembly.GetEntryAssembly() ?? typeof(StoreFormat).Assembly).GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        return "CodeParley Custodian " + v;
    }
}
