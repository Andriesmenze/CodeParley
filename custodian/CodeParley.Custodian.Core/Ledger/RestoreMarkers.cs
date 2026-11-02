using System.Globalization;
using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// Phase 6 Increment 2 (contract §6.1, L-5): the restore marker the installer's <c>rollback</c> writes after it restored the
/// store from a protected backup. It lives outside the store (so no backup carries one) in a place only an administrator can
/// write; each host checks that place and hands the text here. A marker that is present but not exactly this shape fails
/// the start (fail closed): a restore whose restored epoch cannot be established is never served.
/// </summary>
internal static class RestoreMarkers
{
    internal const string FileName = "restore-marker.json";

    internal static RestoreMarker Parse(string json, string source)
    {
        InvalidDataException Bad(string why) => new($"{source} is not a valid restore marker ({why}); nothing is served until an administrator repeats `rollback` or removes it (fail closed)");
        JsonObject o;
        try { o = JsonNode.Parse(json) as JsonObject ?? throw Bad("not a JSON object"); }
        catch (System.Text.Json.JsonException) { throw Bad("not JSON"); }
        foreach ((string k, _) in o)
            if (k is not ("restoreId" or "restoredAt" or "backupSha256" or "storeFormat")) throw Bad($"unexpected field '{k}'");
        string id = Str(o, "restoreId") is { } i && ValidId(i) ? i : throw Bad("restoreId must be 8 to 80 of a-z, 0-9 and '-'");
        string at = Str(o, "restoredAt") is { } t && IsUtc(t) ? t : throw Bad("restoredAt must be a UTC ISO 8601 time");
        string sha = Str(o, "backupSha256") is { Length: 64 } h && h.All(IsLowerHex) ? h : throw Bad("backupSha256 must be 64 lowercase hex digits");
        int format = o["storeFormat"] is JsonValue fv && fv.TryGetValue(out int f) ? f : throw Bad("storeFormat must be a whole number");
        // The restored store was checked by StoreFormat before this is read: a marker naming another format belongs to
        // another restore (or another build), and the epoch it would start is not this store's.
        if (format != StoreFormat.Current) throw Bad($"it names store format {format}, this build serves format {StoreFormat.Current}");
        return new RestoreMarker(id, at, sha, format);
    }

    private static bool ValidId(string id) => id.Length is >= 8 and <= 80 && id.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');
    private static bool IsLowerHex(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'f');
    private static bool IsUtc(string at) => DateTime.TryParse(at, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime when) && when.Kind == DateTimeKind.Utc;

    private static string? Str(JsonObject o, string key) => o[key] is JsonValue v && v.TryGetValue(out string? s) ? s : null;
}
