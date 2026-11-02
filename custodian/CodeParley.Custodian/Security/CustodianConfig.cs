using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Security;

/// <summary>
/// Trusted install-time configuration: the two caller identities the custodian recognizes from the OS.
/// Written by <c>provision</c> under the protected store (custodian/Admin-only), read by the service to
/// classify pipe clients. Neither SID is ever taken from request content.
///
/// For the P3.4B mechanics proof on a single-account host these may be the SAME account: the operator
/// surface additionally requires an elevated, High-integrity token (assurance L1), which is explicitly
/// a protocol vehicle and NOT a production security boundary (TD amendment 3). L3 (a distinct operator
/// principal) is a later milestone; when the two SIDs differ, this same config expresses it.
/// </summary>
internal sealed class CustodianConfig
{
    public int Version { get; init; } = 1;

    /// <summary>The account whose elevated token authorizes operator actions.</summary>
    public string OperatorSid { get; init; } = "";
    public string? OperatorAccount { get; init; }

    /// <summary>The account whose processes are classified as the (untrusted) implementer.</summary>
    public string ImplementerSid { get; init; } = "";
    public string? ImplementerAccount { get; init; }

    /// <summary>P3.4C-5 (§A.1): the dedicated helper service's SID, written by <c>install-helper</c>. Absent: no helper is
    /// installed, the helper pipe is not hosted and every measurement refuses (fail closed). Present, it must be exactly
    /// the deterministic SID of <c>NT SERVICE\CodeParleyHelper</c> and differ from both caller identities, so the helper
    /// class can never be pointed at another principal through this file.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] // a config without a helper stays readable by earlier builds
    public string? HelperSid { get; init; }

    // Self-test only (never set by the service): lets the in-process IPC self-tests classify the current account as the
    // helper on the helper surface, as they already do for the implementer and operator surfaces.
    private static bool _selfTestHelperSid;
    internal static void AllowAnyHelperSidForSelfTest() => _selfTestHelperSid = true;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    // Group/well-known SIDs that would broaden a caller identity to many principals; refused.
    private static readonly HashSet<string> Forbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0", "S-1-5-11", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-18", "S-1-5-7", "S-1-5-32-546",
    };

    internal static SecurityIdentifier Resolve(string account)
    {
        if (string.IsNullOrWhiteSpace(account))
            throw new ArgumentException("an account or SID is required (no default is assumed)");
        account = account.Trim();
        SecurityIdentifier sid = account.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
            ? new SecurityIdentifier(account)
            : (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
        Validate(sid);
        return sid;
    }

    internal static void Validate(SecurityIdentifier sid)
    {
        if (Forbidden.Contains(sid.Value))
            throw new InvalidOperationException(
                $"'{sid.Value}' is a built-in/group SID; a caller identity must be a specific account, not a group");
    }

    internal void Save()
    {
        Validate(new SecurityIdentifier(OperatorSid));
        Validate(new SecurityIdentifier(ImplementerSid));
        ValidateHelper(this);
        Directory.CreateDirectory(Path.GetDirectoryName(StorePaths.ConfigPath)!);
        File.WriteAllText(StorePaths.ConfigPath, JsonSerializer.Serialize(this, JsonOptions));
    }

    /// <summary>The helper SID, when present, is the helper service's own deterministic SID (self-tests aside) and is
    /// neither caller identity.</summary>
    private static void ValidateHelper(CustodianConfig cfg)
    {
        if (cfg.HelperSid is null) return;
        var sid = new SecurityIdentifier(cfg.HelperSid);
        Validate(sid);
        if (!_selfTestHelperSid && sid != ServiceSid.Of(CustodianConstants.HelperServiceName))
            throw new InvalidOperationException($"custodian config helperSid {sid.Value} is not {CustodianConstants.HelperVirtualAccount}");
        if (!_selfTestHelperSid && (sid.Value == cfg.OperatorSid || sid.Value == cfg.ImplementerSid))
            throw new InvalidOperationException("the helper identity must differ from the operator and implementer identities");
    }

    /// <summary>The configured helper SID, or null when no helper is installed.</summary>
    internal SecurityIdentifier? HelperSecurityIdentifier() => HelperSid is null ? null : new(HelperSid);

    internal static CustodianConfig Load()
    {
        if (!File.Exists(StorePaths.ConfigPath))
            throw new InvalidOperationException(
                $"custodian is not provisioned ({StorePaths.ConfigPath} is missing); run `provision` first");
        CustodianConfig cfg = JsonSerializer.Deserialize<CustodianConfig>(File.ReadAllText(StorePaths.ConfigPath), JsonOptions)
            ?? throw new InvalidOperationException("custodian config is empty");
        StoreFormat.RequireFileVersion("custodian-config.json", cfg.Version); // Phase 6 L-1
        Validate(new SecurityIdentifier(RequireSid(cfg.OperatorSid, "operatorSid")));
        Validate(new SecurityIdentifier(RequireSid(cfg.ImplementerSid, "implementerSid")));
        ValidateHelper(cfg);
        return cfg;
    }

    private static string RequireSid(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException($"custodian config has no {field}");
        return value;
    }

    internal SecurityIdentifier OperatorSecurityIdentifier() => new(OperatorSid);
    internal SecurityIdentifier ImplementerSecurityIdentifier() => new(ImplementerSid);
}
