using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodeParley.Broker.Security;

/// <summary>
/// Trusted install-time broker configuration (hardening 4A). It names the single explicitly trusted
/// controller/operator SID that may drive the broker IPC. It is written by `provision` (SYSTEM) under
/// the SYSTEM/Administrators-only trusted state root, and read by the broker to build the named-pipe
/// ACL and to authorize the connected client by its exact SID — never "any administrator".
/// </summary>
internal sealed class BrokerConfig
{
    public int Version { get; init; } = 1;

    /// <summary>The trusted controller/operator account SID (e.g. S-1-5-21-…-1001), as a string.</summary>
    public string ControllerSid { get; init; } = "";

    /// <summary>Informational: the account name the SID was resolved from at provision time.</summary>
    public string? ControllerAccount { get; init; }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    // Well-known SIDs that would broaden controller authority to a whole group; refused as a controller.
    private static readonly HashSet<string> ForbiddenControllerSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",        // Everyone
        "S-1-5-11",       // Authenticated Users
        "S-1-5-32-544",   // BUILTIN\Administrators
        "S-1-5-32-545",   // BUILTIN\Users
        "S-1-5-18",       // LocalSystem (the broker itself; implicitly trusted, never the "controller")
        "S-1-5-7",        // Anonymous
        "S-1-5-32-546",   // BUILTIN\Guests
    };

    /// <summary>Resolve an operator-supplied account (e.g. "DOMAIN\\user" or ".\\user") to a user SID,
    /// refusing broadening group SIDs. Throws with a clear message if it cannot be resolved or is forbidden.</summary>
    internal static SecurityIdentifier ResolveControllerSid(string account)
    {
        if (string.IsNullOrWhiteSpace(account))
            throw new ArgumentException("a controller account or SID is required (no default is assumed)");

        SecurityIdentifier sid;
        account = account.Trim();
        if (account.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
        {
            sid = new SecurityIdentifier(account);
        }
        else
        {
            sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
        }
        ValidateControllerSid(sid);
        return sid;
    }

    internal static void ValidateControllerSid(SecurityIdentifier sid)
    {
        if (ForbiddenControllerSids.Contains(sid.Value))
            throw new InvalidOperationException(
                $"'{sid.Value}' is a built-in/group SID; the controller must be a specific trusted operator account, " +
                "not a group (do not grant all administrators controller authority)");
    }

    internal static BrokerConfig CreateFor(SecurityIdentifier controllerSid, string? account) =>
        new() { Version = 1, ControllerSid = controllerSid.Value, ControllerAccount = account };

    internal void Save()
    {
        ValidateControllerSid(new SecurityIdentifier(ControllerSid));
        Directory.CreateDirectory(Path.GetDirectoryName(BrokerConstants.ConfigPath)!);
        File.WriteAllText(BrokerConstants.ConfigPath, JsonSerializer.Serialize(this, JsonOptions));
    }

    /// <summary>Load and validate the trusted config; throws if missing/invalid (launch then fails closed).</summary>
    internal static BrokerConfig Load()
    {
        if (!File.Exists(BrokerConstants.ConfigPath))
            throw new InvalidOperationException(
                $"broker is not provisioned with a trusted controller SID ({BrokerConstants.ConfigPath} is missing); " +
                "run `provision --controller <account>` first");
        BrokerConfig cfg = JsonSerializer.Deserialize<BrokerConfig>(File.ReadAllText(BrokerConstants.ConfigPath), JsonOptions)
            ?? throw new InvalidOperationException("broker config is empty");
        if (string.IsNullOrWhiteSpace(cfg.ControllerSid))
            throw new InvalidOperationException("broker config has no controllerSid");
        SecurityIdentifier sid;
        try { sid = new SecurityIdentifier(cfg.ControllerSid); }
        catch (Exception e) { throw new InvalidOperationException("broker config controllerSid is malformed: " + e.Message); }
        ValidateControllerSid(sid);
        return cfg;
    }

    internal SecurityIdentifier ControllerSecurityIdentifier() => new(ControllerSid);
}
