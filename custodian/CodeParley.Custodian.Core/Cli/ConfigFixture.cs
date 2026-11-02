using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED self-test fixture (P3.4C-4): the protected configuration a run needs, committed through the operator's
/// prepare→commit path of the ledger under test — a repository record with the checks <c>unit</c>, <c>lint</c> and
/// <c>test</c>, the default capture rules and a Codex installation (a small synthetic PE image the fixture writes; the
/// custodian measures it like any other), a confirmed S1 self-test (<c>st-1</c> / <c>st1</c>) and an acceptance of reduced
/// isolation. The claims a run's operations make (definition digests, capture-rules digest, Codex SHA-256, the isolation
/// claim) are taken from the held records, so every run self-test begins its operations under a usable configuration.
/// </summary>
internal static class ConfigFixture
{
    internal const string CodexVersion = "0.160.0";
    internal const string Backend = "mxc";
    internal const string ProfileHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static int _seq;

    internal static JsonObject Definition(string token, int timeout = 900) => new()
    {
        ["argv"] = new JsonArray("node", "scripts/pass.js", token), ["cwd"] = ".", ["timeout_seconds"] = timeout,
        ["env"] = new JsonObject(), ["env_passthrough"] = new JsonArray(), ["freshness_inputs"] = new JsonArray(),
    };

    internal static JsonObject DefaultRules() => new()
    {
        ["excludeGlobs"] = new JsonArray("**/.env", "**/*.pem"), ["contextInclude"] = new JsonArray(),
        ["maxFileBytes"] = 2_097_152, ["maxExportBytes"] = 536_870_912, ["maxDiffBytes"] = 400_000,
    };

    /// <summary>A minimal PE image: an MZ header whose e_lfanew points at a PE signature. Deterministic bytes (the corpus
    /// pins their SHA-256); never executed.</summary>
    internal static byte[] PeBytes(byte variant = 0)
    {
        byte[] b = new byte[512];
        b[0] = (byte)'M'; b[1] = (byte)'Z';
        b[0x3C] = 0x80;
        b[0x80] = (byte)'P'; b[0x81] = (byte)'E';
        b[0x84] = 0x64; b[0x85] = 0x86; // machine: x64
        b[0x100] = variant;
        return b;
    }

    /// <summary>Phase 5: the host's synthetic Codex image (Windows: <c>codex.exe</c>, a PE image — identical to
    /// <see cref="WritePe"/>; Linux: <c>codex</c>, an ELF image).</summary>
    internal static string WriteNativeCodex(string dir, byte variant = 0)
    {
        string bin = Directory.CreateDirectory(Path.Combine(dir, "codex-install", "bin")).FullName;
        string path = Path.Combine(bin, Platform.Images.FixtureCodexName);
        File.WriteAllBytes(path, Platform.Images.FixtureImage(variant));
        return path;
    }

    internal static string WritePe(string dir, string name = "codex.exe", byte variant = 0)
    {
        string bin = Directory.CreateDirectory(Path.Combine(dir, "codex-install", "bin")).FullName;
        string path = Path.Combine(bin, name);
        File.WriteAllBytes(path, PeBytes(variant));
        return path;
    }

    internal static JsonObject RepositoryPayload(string? codexPath, JsonObject? checks = null, JsonObject? rules = null) => new()
    {
        ["rootCommit"] = null,
        ["checks"] = checks ?? new JsonObject { ["lint"] = Definition("LINT"), ["test"] = Definition("TEST"), ["unit"] = Definition("UNIT") },
        ["profiles"] = new JsonObject { ["default"] = new JsonArray("unit") },
        ["requiredProfiles"] = new JsonArray("default"),
        ["noRequiredChecks"] = false,
        ["testGlobs"] = new JsonArray("test/**"),
        ["captureRules"] = rules ?? DefaultRules(),
        ["codexPath"] = codexPath,
    };

    internal static string Rid(string tag) => $"cfx-{tag}-{Interlocked.Increment(ref _seq)}";

    /// <summary>Set the repository's record (prepare at its current revision, commit). Returns the commit result.</summary>
    internal static JsonObject Set(GrantLedger led, string repo, JsonObject payload)
    {
        string rid = Rid("set");
        led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, payload, RepoRevision(led, repo), rid);
        return led.Commit(rid, null);
    }

    internal static JsonObject Revoke(GrantLedger led, string repo)
    {
        string rid = Rid("revoke");
        led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Revoke, null, null, RepoRevision(led, repo), rid);
        return led.Commit(rid, null);
    }

    internal static JsonObject Reconfirm(GrantLedger led, string repo)
    {
        string rid = Rid("reconfirm");
        led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Reconfirm, null, null, RepoRevision(led, repo), rid);
        return led.Commit(rid, null);
    }

    internal static string Confirm(GrantLedger led, string selftestId = "st-1", string version = CodexVersion, string backend = Backend, string profile = ProfileHex)
    {
        string rid = Rid("confirm");
        var p = new JsonObject
        {
            ["selftestId"] = selftestId, ["codexVersion"] = version, ["backend"] = backend, ["mode"] = "S1", ["profileDigest"] = profile,
            ["s1Available"] = true, ["rowsSummary"] = new JsonObject { ["total"] = 6, ["passed"] = 6, ["failed"] = new JsonArray() },
            ["recordDigest"] = new string('5', 64),
        };
        led.PrepareConfigRecord(null, ConfigKinds.SelftestConfirmation, ConfigKinds.Set, null, p, GlobalRevision(), rid);
        return (string)led.Commit(rid, null)["recordId"]!;
    }

    internal static string Accept(GrantLedger led, string backend = Backend, string range = "0.160.")
    {
        string rid = Rid("accept");
        var p = new JsonObject
        {
            ["accepted"] = new JsonArray("unrestricted_reads", "advisory_network"), ["backend"] = backend, ["codexVersionRange"] = range,
            ["statementSha256"] = new string('7', 64),
        };
        led.PrepareConfigRecord(null, ConfigKinds.IsolationAcceptance, ConfigKinds.Set, null, p, GlobalRevision(), rid);
        return (string)led.Commit(rid, null)["recordId"]!;
    }

    internal static JsonObject RevokeGlobal(GrantLedger led, string kind, string id)
    {
        string rid = Rid("revoke-global");
        led.PrepareConfigRecord(null, kind, ConfigKinds.Revoke, id, null, GlobalRevision(), rid);
        return led.Commit(rid, null);
    }

    /// <summary>The whole protected configuration a run's self-tests need: the repository record (with a Codex
    /// installation written into <paramref name="scratch"/>), and — once per store — a self-test confirmation of
    /// <c>st-1</c> and <c>st1</c> and an acceptance. Returns the acceptance id (an S2 claim names it).</summary>
    internal static string Hold(GrantLedger led, string repo, string scratch)
    {
        Set(led, repo, RepositoryPayload(WriteNativeCodex(scratch)));
        ConfigRecordsFile f = GrantLedger.ReadConfigRecordsLocked();
        // st-1 for the self-tests' S1 claims; st1 (profile a…a) for the shared run corpus's.
        if (!f.SelftestConfirmations.Any(c => c.IsUsable && c.SelftestId == "st-1")) Confirm(led, selftestId: "st-1");
        if (!f.SelftestConfirmations.Any(c => c.IsUsable && c.SelftestId == "st1")) Confirm(led, selftestId: "st1", profile: new string('a', 64));
        IsolationAcceptanceRecord? a = GrantLedger.ReadConfigRecordsLocked().Acceptances.LastOrDefault(x => x.IsUsable && x.Backend == Backend);
        LastAcceptanceId = a?.AcceptanceId ?? Accept(led);
        // P3.4C-5: a protected review is captured by the custodian: an approved runtime and the (synthetic) capture.
        CaptureFixture.Enable(led, scratch);
        return LastAcceptanceId;
    }

    /// <summary>The acceptance the last <see cref="Hold"/> made or found.</summary>
    internal static string LastAcceptanceId { get; private set; } = "";

    private static readonly Dictionary<string, string> Tokens = new(StringComparer.Ordinal) { ["lint"] = "LINT", ["test"] = "TEST", ["unit"] = "UNIT" };

    /// <summary>The definition digest of a fixture check (what the held record computes for it).</summary>
    internal static string Digest(string check) => ConfigValidation.DefinitionDigest(check, Definition(Tokens.GetValueOrDefault(check, check.ToUpperInvariant())));

    internal static string CaptureRulesDigest => ConfigValidation.CaptureRulesDigest(DefaultRules());

    internal static string CodexSha256 => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Platform.Images.FixtureImage(0)));

    /// <summary>The isolation claim of a review on the fixture configuration (S1: the confirmed self-test; S2: the acceptance).</summary>
    internal static JsonObject Isolation(string mode = "S1", string selftestId = "st-1") => new()
    {
        ["mode"] = mode, ["profileDigest"] = ProfileHex, ["selftestId"] = mode == "S1" ? selftestId : null, ["acceptanceId"] = mode == "S2" ? LastAcceptanceId : null,
        ["backend"] = Backend, ["codexVersion"] = CodexVersion,
    };

    internal static int RepoRevision(GrantLedger led, string repo)
        => GrantLedger.ReadConfigRecordsLocked().CurrentOf(Security.RepoIdentities.Resolve(repo).Key)?.ConfigRevision ?? 0;

    internal static int GlobalRevision() => GrantLedger.ReadConfigRecordsLocked().GlobalRevision;
}
