using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;

namespace CodeParley.Custodian.Ledger;

// ---- P3.4C-4: the custodian-held trusted configuration (contract §2) ----
//
// Field provenance (§2.2): P = proposed by the operator's CLI and validated here; C = computed here from what is held,
// with the engine's canonical schemes (EngineJson, pinned byte for byte by the shared corpus); M = measured by the
// custodian through its own handle; A = assigned by the custodian (ids, revisions, times, the recorder, lapse and
// revocation state). Nothing the custodian cannot compute or measure is labelled C or M.

/// <summary>One approved check: its definition in the engine's canonical form (P: <c>argv</c>, <c>cwd</c>,
/// <c>timeout_seconds</c>, <c>env</c>, <c>env_passthrough</c>, <c>freshness_inputs</c>, optional <c>description</c>)
/// and the definition digest (C: <c>arl.check-definition.v1</c>).</summary>
internal sealed record ConfigCheck(JsonObject Definition, string DefinitionDigest);

/// <summary>The capture rules a protected run's captures use (P), with their digest (C).</summary>
internal sealed record ConfigCaptureRules(List<string> ExcludeGlobs, List<string> ContextInclude, long MaxFileBytes, long MaxExportBytes, long MaxDiffBytes);

/// <summary>The approved Codex installation: the path the operator named (P) and what the custodian measured through its
/// own no-follow handle (M): the form (<c>native_pe</c>), the file identity (volume serial + file id), size and SHA-256.</summary>
internal sealed record CodexInstallation(string Path, string Form, string FileId, long Size, string Sha256);

/// <summary>
/// One version of a repository's configuration record (§2.2). The current version of a repository is the one not
/// superseded; every committed change appends a version (set, revoke, reconfirm) and supersedes the previous one, which
/// stays readable. <see cref="ConfigRevision"/> rises by one per committed change. <see cref="LapsedAtRecoveryId"/> is set
/// by recovery U4b after a new boot and cleared only by a <c>reconfirm</c>; <see cref="LastRecoveryId"/> stamps the
/// recovery that last changed the version (idempotence).
/// </summary>
internal sealed record RepositoryConfig(
    string RepoKey, string RepositoryRoot, int ConfigRevision, string RecordedAt, RecordedBy RecordedBy, string RequestId, string Action,
    string? RootCommit, Dictionary<string, ConfigCheck> Checks, Dictionary<string, List<string>> Profiles, List<string> RequiredProfiles,
    bool NoRequiredChecks, List<string> TestGlobs, ConfigCaptureRules CaptureRules, string CaptureRulesDigest,
    CodexInstallation? CodexInstallation, string ConfigDigest,
    string? RevokedAt = null, string? SupersededAt = null, string? LapsedAtRecoveryId = null, string? LastRecoveryId = null)
{
    internal bool IsCurrent => SupersededAt is null;
    internal bool IsRevoked => RevokedAt is not null;
    internal bool IsLapsed => LapsedAtRecoveryId is not null;
    /// <summary>Usable (§3.3): present, not revoked and not lapsed.</summary>
    internal bool IsUsable => IsCurrent && !IsRevoked && !IsLapsed;
}

/// <summary>An operator's acceptance of reduced isolation (S2), global (§2.2). <see cref="GlobalRevision"/> is the shared
/// global revision at the record's last change.</summary>
internal sealed record IsolationAcceptanceRecord(
    string AcceptanceId, int GlobalRevision, string RecordedAt, RecordedBy RecordedBy, string RequestId,
    List<string> Accepted, string Backend, string CodexVersionRange, string StatementSha256,
    string? RevokedAt = null, string? LapsedAtRecoveryId = null, string? LastRecoveryId = null)
{
    internal bool IsUsable => RevokedAt is null && LapsedAtRecoveryId is null;
}

/// <summary>An operator's confirmation of an implementer-produced self-test record, by its digest (D4-A; global): mode S1
/// (the read-only reviewer) or, Phase 4 Increment 2, mode FIX (the delegated fixer's cp_fix self-test, bound to the exact
/// Codex binary in <see cref="CodexSha256"/>). The two never stand in for each other. The record lives in the implementer's
/// data home, which the service does not read: every field but the custodian's own is a claim the operator confirmed
/// against the custodian's rendering (residual, contract §8.2).</summary>
internal sealed record SelfTestConfirmationRecord(
    string ConfirmationId, int GlobalRevision, string RecordedAt, RecordedBy RecordedBy, string RequestId,
    string SelftestId, string CodexVersion, string Backend, string Mode, string ProfileDigest, bool S1Available, JsonObject RowsSummary, string RecordDigest,
    string? RevokedAt = null, string? SupersededAt = null, string? LapsedAtRecoveryId = null, string? LastRecoveryId = null, string? CodexSha256 = null,
    JsonObject? HostBasis = null)
{
    internal bool IsUsable => RevokedAt is null && SupersededAt is null && LapsedAtRecoveryId is null;
}

/// <summary>P3.4C-5 (contract §2.1): the operator's approval of the engine runtime the helper runs — global; one in force at
/// a time (a new approval supersedes the previous one). Every field but the custodian's own is what it measured (M):
/// the root's canonical path and directory id, node.exe and the approved git (native PE: SHA-256, file id), the helper
/// entry's SHA-256 and the digest over every file of the tree. It lapses after a new boot like every global record.</summary>
internal sealed record EngineRuntimeRecord(
    string RuntimeId, int GlobalRevision, string RecordedAt, RecordedBy RecordedBy, string RequestId, JsonObject Measured,
    string? RevokedAt = null, string? SupersededAt = null, string? LapsedAtRecoveryId = null, string? LastRecoveryId = null)
{
    internal bool IsUsable => RevokedAt is null && SupersededAt is null && LapsedAtRecoveryId is null;
    internal string Root => (string)Measured["root"]!;
    internal string? GitRelative => (string?)Measured["gitRelative"];
    /// <summary>Phase 6 (§7 b): an installed git outside the runtime (null: the git is inside it).</summary>
    internal string? GitPath => (string?)Measured["gitPath"];
}

/// <summary>The store file <c>config-records.json</c> (§2.1). <see cref="GlobalRevision"/> is shared by the global records
/// and rises once per committed global change; repository records keep their own revisions. <see cref="EngineRuntimes"/>
/// (P3.4C-5) is absent in files written before it.</summary>
internal sealed record ConfigRecordsFile(
    int Version, int GlobalRevision, List<RepositoryConfig> Repositories, List<IsolationAcceptanceRecord> Acceptances,
    List<SelfTestConfirmationRecord> SelftestConfirmations, List<EngineRuntimeRecord>? EngineRuntimes = null)
{
    internal static ConfigRecordsFile Empty() => new(1, 0, [], [], []);
    internal RepositoryConfig? CurrentOf(string repoKey) => Repositories.LastOrDefault(r => r.RepoKey == repoKey && r.IsCurrent);
    internal List<EngineRuntimeRecord> Runtimes => EngineRuntimes ?? [];
    /// <summary>The runtime approval not superseded (revoked or lapsed ones included: their state is reported).</summary>
    internal EngineRuntimeRecord? CurrentRuntime => Runtimes.LastOrDefault(r => r.SupersededAt is null);
}

/// <summary>The kinds and actions of <c>prepare_config_record</c> (§3.1).</summary>
internal static class ConfigKinds
{
    internal const string Repository = "repository", IsolationAcceptance = "isolation_acceptance", SelftestConfirmation = "selftest_confirmation";
    /// <summary>P3.4C-5 (§2.1): the approved engine runtime (global).</summary>
    internal const string EngineRuntime = "engine_runtime";
    internal const string Set = "set", Revoke = "revoke", Reconfirm = "reconfirm";
    internal static readonly IReadOnlySet<string> Kinds = new HashSet<string>(StringComparer.Ordinal) { Repository, IsolationAcceptance, SelftestConfirmation, EngineRuntime };
    internal static readonly IReadOnlySet<string> Actions = new HashSet<string>(StringComparer.Ordinal) { Set, Revoke, Reconfirm };
    internal static readonly IReadOnlySet<string> ReducedIsolation = new HashSet<string>(StringComparer.Ordinal) { "unrestricted_reads", "advisory_network" };
    /// <summary>The digest schemes the engine uses (src/checks/project-config.ts, the capture rules and the record).</summary>
    internal const string CheckDefinitionSchema = "arl.check-definition.v1";
    internal const string CaptureRulesSchema = "arl.capture-rules-config.v1";
    internal const string RepositoryConfigSchema = "arl.repository-config.v1";
}

/// <summary>The §2.3 caps (each refused BUDGET_EXHAUSTED with the limit named).</summary>
internal static class ConfigCaps
{
    internal const int Checks = 64, Argv = 64, Env = 64, FreshnessInputs = 128, Globs = 256, Acceptances = 64, SelftestConfirmations = 256, EngineRuntimes = 64;
    internal const int Profiles = 64, ProfileEntries = 64, RepositoryVersions = 256, Text = RunFields.MaxText, PathChars = 1024;
    internal const long MaxCaptureBytes = 1L << 40;
}

/// <summary>
/// The engine's canonical JSON (src/common/hash.ts <c>canonicalize</c>: <c>JSON.stringify</c> of a key-sorted value),
/// reproduced byte for byte: strings escaped as <c>JSON.stringify</c> escapes them (only <c>"</c>, <c>\</c>, the
/// control characters and lone surrogates; everything else literal UTF-8), integers in decimal, and object keys in the
/// order JavaScript enumerates a sorted object — integer-like keys (array indices) first in numeric order, then the
/// others in UTF-16 code-unit order. Held to the TypeScript side by the shared corpus (self-test-config-corpus).
/// </summary>
internal static class EngineJson
{
    internal static string Canonical(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(node, sb);
        return sb.ToString();
    }

    internal static string Digest(JsonNode? node) => Ledger.Digest.Sha256Hex(Canonical(node));

    private static void Write(JsonNode? node, StringBuilder sb)
    {
        switch (node)
        {
            case null: sb.Append("null"); break;
            case JsonObject o:
                sb.Append('{');
                bool first = true;
                foreach (KeyValuePair<string, JsonNode?> kv in o.OrderBy(k => k.Key, KeyOrder.Instance))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(kv.Key, sb);
                    sb.Append(':');
                    Write(kv.Value, sb);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (int i = 0; i < a.Count; i++) { if (i > 0) sb.Append(','); Write(a[i], sb); }
                sb.Append(']');
                break;
            case JsonValue v:
                if (v.TryGetValue(out string? s)) WriteString(s!, sb);
                else if (v.TryGetValue(out bool b)) sb.Append(b ? "true" : "false");
                else if (RunFields.Integer(v) is long n) sb.Append(n.ToString(CultureInfo.InvariantCulture));
                else throw new ArgumentException("only strings, booleans, integers, null, arrays and objects are canonicalized");
                break;
        }
    }

    private static void WriteString(string s, StringBuilder sb)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>JavaScript's own-property order for a key-sorted object: array indices (canonical decimal integers below
    /// 2^32 − 1) first, ascending numerically; then every other key in UTF-16 code-unit order.</summary>
    private sealed class KeyOrder : IComparer<string>
    {
        internal static readonly KeyOrder Instance = new();
        public int Compare(string? x, string? y)
        {
            bool xi = IsIndex(x!, out uint xn), yi = IsIndex(y!, out uint yn);
            if (xi && yi) return xn.CompareTo(yn);
            if (xi != yi) return xi ? -1 : 1;
            return string.CompareOrdinal(x, y);
        }

        private static bool IsIndex(string s, out uint n)
        {
            n = 0;
            if (s.Length is 0 or > 10 || (s.Length > 1 && s[0] == '0') || !s.All(char.IsAsciiDigit)) return false;
            return uint.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out n) && n != uint.MaxValue;
        }
    }
}

/// <summary>
/// Validation of a proposed configuration payload (§3.1): closed kinds, allowlisted fields, bounded strings, safe
/// repository-relative paths, 64-hex digests and the §2.3 caps. A definition must already be in the engine's canonical
/// form (the CLI normalizes it); the custodian checks that form, it does not silently re-normalize.
/// </summary>
internal static class ConfigValidation
{
    private static readonly System.Text.RegularExpressions.Regex EnvName = new("^[A-Za-z_][A-Za-z0-9_.()-]{0,127}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    private static readonly System.Text.RegularExpressions.Regex SecretShaped = new("(^|_)(API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PASSWORD|PASSWD|TOKEN)($|_)", System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private static readonly HashSet<string> CodexAuthVars = new(StringComparer.Ordinal) { "CODEX_HOME", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN" };
    private static readonly HashSet<string> DosDevices = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM\u00B9", "COM\u00B2", "COM\u00B3",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT\u00B9", "LPT\u00B2", "LPT\u00B3",
    };

    private static CustodianRefusal Cap(string what, int limit) => new(ErrorCodes.BudgetExhausted, $"{what}: at most {limit}");

    /// <summary>The validated repository payload (§2.2 P fields), canonical; throws INVALID_ARGUMENT / BUDGET_EXHAUSTED.</summary>
    internal static JsonObject RepositoryPayload(JsonObject? payload)
    {
        if (payload is null) throw new ArgumentException("payload is required for a repository set");
        var shape = new RunFields.Shape(new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["rootCommit"] = (v, p) => v is null ? null : CommitId(v, p),
            ["checks"] = (v, p) => Checks(v, p),
            ["profiles"] = (v, p) => Profiles(v, p),
            ["requiredProfiles"] = (v, p) => NameList(v, p, ConfigCaps.Profiles, sorted: true),
            ["noRequiredChecks"] = RunFields.Bool,
            ["testGlobs"] = (v, p) => Globs(v, p),
            ["captureRules"] = (v, p) => CaptureRules(v, p),
            ["codexPath"] = (v, p) => v is null ? null : WindowsPath(v, p),
        });
        JsonObject o = shape.Apply(payload, "payload");
        var checks = o["checks"]!.AsObject();
        var profiles = o["profiles"]!.AsObject();
        foreach ((string name, JsonNode? list) in profiles)
        {
            if (checks.ContainsKey(name)) throw new ArgumentException($"profile name collides with a check name: {name}");
            foreach (JsonNode? c in list!.AsArray())
                if (!checks.ContainsKey((string)c!)) throw new ArgumentException($"profile {name} references an undefined check: {(string)c!}");
        }
        foreach (JsonNode? r in o["requiredProfiles"]!.AsArray())
            if (!profiles.ContainsKey((string)r!)) throw new ArgumentException($"required profile is not defined: {(string)r!}");
        bool none = (bool)o["noRequiredChecks"]!;
        int required = o["requiredProfiles"]!.AsArray().Count;
        if (none == (required > 0)) throw new ArgumentException("a verification floor is required: name the required profile(s) or state that there are no required checks, not both");
        if (checks.Count == 0 && !none) throw new ArgumentException("no checks to approve");
        return o;
    }

    private static string CommitId(JsonNode v, string p)
    {
        string s = Str(v, p);
        if (s.Length is not (40 or 64) || !s.All(char.IsAsciiHexDigitLower)) throw new ArgumentException($"{p} must be a 40- or 64-hex commit id");
        return s;
    }

    private static JsonObject Checks(JsonNode? v, string p)
    {
        if (v is not JsonObject o) throw new ArgumentException($"{p} must be an object");
        if (o.Count > ConfigCaps.Checks) throw Cap("checks per repository", ConfigCaps.Checks);
        var result = new JsonObject();
        foreach ((string name, JsonNode? def) in o)
        {
            RunFields.CheckName(JsonValue.Create(name), $"{p} name");
            result[name] = Definition(def, $"{p}.{name}");
        }
        return result;
    }

    /// <summary>A check definition in the engine's canonical form (src/checks/project-config.ts normalizeCheckDefinition).</summary>
    internal static JsonObject Definition(JsonNode? v, string p)
    {
        if (v is not JsonObject o) throw new ArgumentException($"{p} must be an object");
        foreach (string key in o.Select(kv => kv.Key))
            if (key is not ("argv" or "cwd" or "timeout_seconds" or "env" or "env_passthrough" or "freshness_inputs" or "description"))
                throw new CustodianRefusal(ErrorCodes.MalformedRequest, $"unexpected key in {p} (a definition has argv, cwd, timeout_seconds, env, env_passthrough, freshness_inputs and description only)");
        if (o["argv"] is not JsonArray argv || argv.Count == 0) throw new ArgumentException($"{p}.argv must be a non-empty array");
        if (argv.Count > ConfigCaps.Argv) throw Cap($"{p}.argv entries", ConfigCaps.Argv);
        var argvOut = new JsonArray();
        for (int i = 0; i < argv.Count; i++)
        {
            string a = Str(argv[i], $"{p}.argv[{i}]");
            if (a.Length > ConfigCaps.Text) throw new ArgumentException($"{p}.argv[{i}] must be at most {ConfigCaps.Text} characters");
            if (a.Contains('\0')) throw new ArgumentException($"{p}.argv[{i}] must not contain NUL");
            if (i == 0 && (a.Length == 0 || a.IndexOfAny(['"', '\r', '\n', '\t']) >= 0)) throw new ArgumentException($"{p}.argv[0] must be non-empty without quotes or control characters");
            argvOut.Add(a);
        }
        string cwd = RepoRelative(o["cwd"], $"{p}.cwd", allowRoot: true);
        long timeout = RunFields.Integer(o["timeout_seconds"]) is long t && t is >= 1 and <= 3600 ? t : throw new ArgumentException($"{p}.timeout_seconds must be an integer from 1 to 3600");
        if (o["env"] is not JsonObject env) throw new ArgumentException($"{p}.env must be an object");
        if (env.Count > ConfigCaps.Env) throw Cap($"{p}.env entries", ConfigCaps.Env);
        var envOut = new JsonObject();
        // The engine's rule: names differing only in case are one variable on Windows, two on Linux (Phase 5).
        var seen = new HashSet<string>(Platform.CaseInsensitiveEnvironment ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach ((string name, JsonNode? value) in env)
        {
            RequireEnvName(name, $"{p}.env");
            if (!seen.Add(name)) throw new ArgumentException($"{p}.env: duplicate variable (case-insensitive): {name}");
            if (name.StartsWith("ANTHROPIC_", StringComparison.OrdinalIgnoreCase) || name.StartsWith("CLAUDE", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"{p}.env: {name} is never passed to check commands");
            string s = Str(value, $"{p}.env.{name}");
            if (s.Length > ConfigCaps.Text || s.Contains('\0')) throw new ArgumentException($"{p}.env.{name} must be at most {ConfigCaps.Text} characters without NUL");
            envOut[name] = s;
        }
        if (o["env_passthrough"] is not JsonArray pass) throw new ArgumentException($"{p}.env_passthrough must be an array");
        if (pass.Count > ConfigCaps.Env) throw Cap($"{p}.env_passthrough entries", ConfigCaps.Env);
        var passOut = new JsonArray();
        string? prev = null;
        foreach (JsonNode? n in pass)
        {
            string name = Str(n, $"{p}.env_passthrough");
            RequireEnvName(name, $"{p}.env_passthrough");
            if (CodexAuthVars.Contains(name) || name.StartsWith("ANTHROPIC_", StringComparison.OrdinalIgnoreCase) || name.StartsWith("CLAUDE", StringComparison.OrdinalIgnoreCase) || SecretShaped.IsMatch(name))
                throw new ArgumentException($"{p}.env_passthrough: {name} is refused (Claude/Anthropic credential or secret-shaped name)");
            if (seen.Contains(name)) throw new ArgumentException($"{p}.env_passthrough: {name} is also set in env or listed twice");
            if (prev is not null && ByLower(prev, name) >= 0) throw new ArgumentException($"{p}.env_passthrough must be sorted case-insensitively without duplicates (the engine's canonical form)");
            seen.Add(name);
            prev = name;
            passOut.Add(name);
        }
        if (o["freshness_inputs"] is not JsonArray fresh) throw new ArgumentException($"{p}.freshness_inputs must be an array");
        if (fresh.Count > ConfigCaps.FreshnessInputs) throw Cap($"{p}.freshness_inputs entries", ConfigCaps.FreshnessInputs);
        var freshOut = new JsonArray();
        string? prevPath = null;
        foreach (JsonNode? n in fresh)
        {
            string path = RepoRelative(n, $"{p}.freshness_inputs", allowRoot: false);
            if (prevPath is not null && string.CompareOrdinal(prevPath, path) >= 0) throw new ArgumentException($"{p}.freshness_inputs must be sorted without duplicates (the engine's canonical form)");
            prevPath = path;
            freshOut.Add(path);
        }
        var result = new JsonObject
        {
            ["argv"] = argvOut, ["cwd"] = cwd, ["timeout_seconds"] = timeout, ["env"] = envOut, ["env_passthrough"] = passOut, ["freshness_inputs"] = freshOut,
        };
        if (o.TryGetPropertyValue("description", out JsonNode? d))
        {
            string desc = Str(d, $"{p}.description");
            if (desc.Length > ConfigCaps.Text) throw new ArgumentException($"{p}.description must be at most {ConfigCaps.Text} characters");
            result["description"] = desc;
        }
        return result;
    }

    /// <summary>The engine's byLower: case-insensitive first, then exact (names that differ only in case are distinct
    /// on Linux; on Windows they are refused as duplicates).</summary>
    private static int ByLower(string a, string b)
    {
        int c = string.CompareOrdinal(a.ToLowerInvariant(), b.ToLowerInvariant());
        return c != 0 ? c : string.CompareOrdinal(a, b);
    }

    private static void RequireEnvName(string name, string p)
    {
        if (!EnvName.IsMatch(name)) throw new ArgumentException($"{p}: invalid environment variable name");
    }

    /// <summary>A repository-relative path in the engine's canonical form: forward slashes, no empty, <c>.</c> or
    /// <c>..</c> segment, no <c>.git</c>, no wildcard, every segment a valid Windows name; <c>.</c> alone is the root.</summary>
    internal static string RepoRelative(JsonNode? v, string p, bool allowRoot)
    {
        string s = Str(v, p);
        if (s.Length is 0 || s.Length > ConfigCaps.PathChars) throw new ArgumentException($"{p} must be 1 to {ConfigCaps.PathChars} characters");
        if (s == ".") return allowRoot ? s : throw new ArgumentException($"{p} must name a file");
        foreach (string seg in s.Split('/'))
        {
            if (seg.Length == 0 || seg is "." or "..") throw new ArgumentException($"{p} must be a canonical repository-relative path (no empty, '.' or '..' segment)");
            if (seg.Equals(".git", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException($"{p} must not name .git");
            if (seg.IndexOfAny(['*', '?', '[', ']', '{', '}']) >= 0) throw new ArgumentException($"{p}: wildcards are not supported");
            if (seg.Any(c => c < 0x20 || c is '<' or '>' or ':' or '"' or '|' or '\\')) throw new ArgumentException($"{p}: a segment has a character that is not allowed");
            if (seg.EndsWith(' ') || seg.EndsWith('.')) throw new ArgumentException($"{p}: a segment ends with a space or dot");
            if (DosDevices.Contains(seg.Split('.')[0])) throw new ArgumentException($"{p}: a segment is a reserved device name");
        }
        return s;
    }

    private static JsonObject Profiles(JsonNode? v, string p)
    {
        if (v is not JsonObject o) throw new ArgumentException($"{p} must be an object");
        if (o.Count > ConfigCaps.Profiles) throw Cap("profiles", ConfigCaps.Profiles);
        var result = new JsonObject();
        foreach ((string name, JsonNode? list) in o)
        {
            RunFields.CheckName(JsonValue.Create(name), $"{p} name");
            JsonArray entries = NameList(list, $"{p}.{name}", ConfigCaps.ProfileEntries, sorted: false);
            if (entries.Count == 0) throw new ArgumentException($"profile {name} is empty");
            result[name] = entries;
        }
        return result;
    }

    /// <summary>Distinct check/profile names. A profile's order is its execution order; the required profiles are a set
    /// (sorted, as the engine writes them).</summary>
    private static JsonArray NameList(JsonNode? v, string p, int max, bool sorted)
    {
        if (v is not JsonArray a) throw new ArgumentException($"{p} must be an array");
        if (a.Count > max) throw Cap(p, max);
        var result = new JsonArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? prev = null;
        for (int i = 0; i < a.Count; i++)
        {
            string s = (string)RunFields.CheckName(a[i], $"{p}[{i}]")!;
            if (!seen.Add(s)) throw new ArgumentException($"{p} has a duplicate entry");
            if (sorted && prev is not null && string.CompareOrdinal(prev, s) >= 0) throw new ArgumentException($"{p} must be sorted (the engine's canonical form)");
            prev = s;
            result.Add(s);
        }
        return result;
    }

    private static JsonArray Globs(JsonNode? v, string p)
    {
        if (v is not JsonArray a) throw new ArgumentException($"{p} must be an array");
        if (a.Count > ConfigCaps.Globs) throw Cap(p, ConfigCaps.Globs);
        var result = new JsonArray();
        for (int i = 0; i < a.Count; i++)
        {
            string s = Str(a[i], $"{p}[{i}]");
            if (s.Length is 0 || s.Length > ConfigCaps.Text || s.Any(char.IsControl)) throw new ArgumentException($"{p}[{i}] must be 1 to {ConfigCaps.Text} characters without control characters");
            result.Add(s);
        }
        return result;
    }

    private static JsonObject CaptureRules(JsonNode? v, string p)
    {
        Func<long, long, RunFields.Rule> bytes = (min, max) => RunFields.Int(min, max);
        var shape = new RunFields.Shape(new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["excludeGlobs"] = (x, q) => Globs(x, q),
            ["contextInclude"] = (x, q) => Globs(x, q),
            ["maxFileBytes"] = bytes(1, ConfigCaps.MaxCaptureBytes),
            ["maxExportBytes"] = bytes(1, ConfigCaps.MaxCaptureBytes),
            ["maxDiffBytes"] = bytes(1, ConfigCaps.MaxCaptureBytes),
        });
        return shape.Apply(v, p);
    }

    /// <summary>An absolute local Windows path (X:\…), the strict syntax of the repository identity (no UNC, device or
    /// traversal form); the no-follow walk then refuses every link.</summary>
    internal static string WindowsPath(JsonNode v, string p)
    {
        string s = Str(v, p);
        if (s.Length is 0 || s.Length > ConfigCaps.PathChars) throw new ArgumentException($"{p} must be 1 to {ConfigCaps.PathChars} characters");
        return s;
    }

    internal static string Str(JsonNode? v, string p)
        => v is JsonValue j && j.TryGetValue(out string? s) && s is not null ? s : throw new ArgumentException($"{p} must be a string");

    // ---- the global records ----

    /// <summary>P3.4C-5 (§2.1): the engine runtime an operator approves — its directory and the approved git inside it
    /// (<c>git</c>), or (Phase 6, §7 b) an installed git outside it (<c>gitPath</c>); exactly one.</summary>
    internal static JsonObject EngineRuntimePayload(JsonObject? payload)
    {
        if (payload is null) throw new ArgumentException("payload is required for an engine runtime");
        var shape = new RunFields.Shape(new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["path"] = (v, p) => WindowsPath(v!, p),
            ["git"] = (v, p) => Security.EngineRuntime.GitRelative(Str(v, p)),
            ["gitPath"] = (v, p) => WindowsPath(v!, p),
        }, "git", "gitPath");
        JsonObject o = shape.Apply(payload, "payload");
        if ((o["git"] is null) == (o["gitPath"] is null)) throw new ArgumentException("payload names the runtime's git inside it (git) or an installed git outside it (gitPath), exactly one");
        return o;
    }

    internal static JsonObject AcceptancePayload(JsonObject? payload)
    {
        if (payload is null) throw new ArgumentException("payload is required for an isolation acceptance");
        var shape = new RunFields.Shape(new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["accepted"] = RunFields.Array(RunFields.Enum(ConfigKinds.ReducedIsolation), 2, unique: true),
            ["backend"] = RunFields.Code,
            ["codexVersionRange"] = VersionText,
            ["statementSha256"] = RunFields.Hex64,
        });
        JsonObject o = shape.Apply(payload, "payload");
        if (o["accepted"]!.AsArray().Count == 0) throw new ArgumentException("payload.accepted must name the accepted reductions");
        return o;
    }

    internal static JsonObject SelftestPayload(JsonObject? payload)
    {
        if (payload is null) throw new ArgumentException("payload is required for a self-test confirmation");
        // Phase 4 Increment 2: a FIX confirmation is separate from S1 and is bound to the exact Codex binary its self-test ran.
        bool fix = payload["mode"] is JsonValue mv && mv.TryGetValue(out string? m) && m == "FIX";
        var rows = new RunFields.Shape(new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["total"] = RunFields.Int(0, 1000),
            ["passed"] = RunFields.Int(0, 1000),
            ["failed"] = RunFields.Array(RunFields.Code, 32, unique: true),
        });
        var rules = new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["selftestId"] = RunFields.Id,
            ["codexVersion"] = VersionText,
            ["backend"] = RunFields.Code,
            ["mode"] = RunFields.Enum(new HashSet<string>(StringComparer.Ordinal) { "S1", "FIX" }),
            ["profileDigest"] = RunFields.Hex64,
            ["s1Available"] = RunFields.Bool,
            ["rowsSummary"] = RunFields.Obj(rows),
            ["recordDigest"] = RunFields.Hex64,
        };
        // Phase 5 (§4.12): the Codex binary the self-test ran (required for FIX, optional for S1) and, on a host that binds a
        // sandbox basis, that installation's path and the boot the record was produced on (claims the custodian measures).
        rules["codexSha256"] = RunFields.Hex64;
        rules["host"] = RunFields.Obj(new RunFields.Shape(new Dictionary<string, RunFields.Rule>(StringComparer.Ordinal)
        {
            ["codexPath"] = PosixAbsolutePath,
            ["bootId"] = BootId,
        }));
        JsonObject o = new RunFields.Shape(rules, fix ? ["host"] : ["codexSha256", "host"]).Apply(payload, "payload");
        // An S1 confirmation names its binary only with the host binding (P4: the binary binds FIX, not S1, elsewhere).
        if (!fix && o.ContainsKey("codexSha256") && !o.ContainsKey("host"))
            throw new CustodianRefusal(ErrorCodes.MalformedRequest, "unexpected key in payload (no field conveys authority; unknown fields are refused, not ignored)");
        if (!(bool)o["s1Available"]!)
            throw new ArgumentException(fix ? "only a fix self-test that established confinement can be confirmed (s1Available is false)" : "only a self-test whose S1 rows all passed can be confirmed (s1Available is false)");
        return o;
    }

    /// <summary>An absolute POSIX path: '/', then up to <see cref="ConfigCaps.PathChars"/> characters in all, no control
    /// character (the measurement then refuses every link and traversal itself).</summary>
    internal static readonly RunFields.Rule PosixAbsolutePath = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length is < 2 or > ConfigCaps.PathChars || s[0] != '/' || s.Any(char.IsControl)) throw new ArgumentException($"{p} must be an absolute path of at most {ConfigCaps.PathChars} characters");
        return s;
    };

    /// <summary>A Linux boot id (<c>/proc/sys/kernel/random/boot_id</c>): a lowercase hyphenated UUID.</summary>
    internal static readonly RunFields.Rule BootId = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length != 36 || !Guid.TryParseExact(s, "D", out _) || s.Any(char.IsAsciiLetterUpper)) throw new ArgumentException($"{p} must be a lowercase boot id (UUID)");
        return s;
    };

    /// <summary>A Codex version or version prefix: 1–64 of [0-9A-Za-z.+-].</summary>
    internal static readonly RunFields.Rule VersionText = (v, p) =>
    {
        string s = Str(v, p);
        if (s.Length is < 1 or > 64 || !s.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '+' or '-'))
            throw new ArgumentException($"{p} must be a version of 1-64 of [0-9A-Za-z.+-]");
        return s;
    };

    // ---- digests (C) ----

    /// <summary><c>arl.check-definition.v1</c> (src/checks/project-config.ts checkDefinitionDigest).</summary>
    internal static string DefinitionDigest(string name, JsonObject definition)
        => EngineJson.Digest(new JsonObject { ["schema"] = ConfigKinds.CheckDefinitionSchema, ["name"] = name, ["def"] = definition.DeepClone() });

    /// <summary><c>arl.capture-rules-config.v1</c> (src/engine/protected-config.ts captureRulesConfigDigest).</summary>
    internal static string CaptureRulesDigest(JsonObject rules)
        => EngineJson.Digest(new JsonObject
        {
            ["schema"] = ConfigKinds.CaptureRulesSchema,
            ["exclude_globs"] = rules["excludeGlobs"]!.DeepClone(),
            ["context_include"] = rules["contextInclude"]!.DeepClone(),
            ["max_file_bytes"] = rules["maxFileBytes"]!.DeepClone(),
            ["max_export_bytes"] = rules["maxExportBytes"]!.DeepClone(),
            ["max_diff_bytes"] = rules["maxDiffBytes"]!.DeepClone(),
        });

    /// <summary><c>arl.repository-config.v1</c>: every P, C and M field of the record (§2.2 configDigest).</summary>
    internal static string ConfigDigest(JsonObject canonicalContent) => EngineJson.Digest(canonicalContent);
}
