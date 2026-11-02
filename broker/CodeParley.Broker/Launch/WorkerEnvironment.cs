using System.Runtime.InteropServices;
using System.Text;

namespace CodeParley.Broker.Launch;

/// <summary>Parse/build a Win32 environment block (double-null-terminated UTF-16 "K=V" list).</summary>
internal static class EnvBlock
{
    internal static Dictionary<string, string> Parse(IntPtr block)
    {
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int off = 0;
        while (true)
        {
            var sb = new StringBuilder();
            while (true)
            {
                char c = (char)Marshal.ReadInt16(block, off);
                off += 2;
                if (c == '\0') break;
                sb.Append(c);
            }
            if (sb.Length == 0) break;               // double null -> end
            string s = sb.ToString();
            int eq = s.IndexOf('=');
            if (eq > 0) env[s[..eq]] = s[(eq + 1)..]; // skip "=X:" per-drive cwd entries
        }
        return env;
    }

    internal static IntPtr Build(IReadOnlyDictionary<string, string> env)
    {
        var sb = new StringBuilder();
        foreach (var kv in env) { sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0'); }
        sb.Append('\0');
        return Marshal.StringToHGlobalUni(sb.ToString());
    }
}

/// <summary>
/// Composes the explicit worker environment: the profile-derived base (hardening #3), with
/// controller/Anthropic secrets stripped, deterministic absolute tool dirs on PATH, and worker
/// tooling hygiene. Asserts the required worker-owned variables are present.
/// </summary>
internal static class WorkerEnvironment
{
    private static readonly string[] DenyPrefixes = ["ANTHROPIC_", "CLAUDE"];

    private static readonly string[] RequiredWorkerOwned =
        ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "HOMEDRIVE", "HOMEPATH", "USERNAME", "USERDOMAIN"];

    internal static Dictionary<string, string> Compose(Dictionary<string, string> baseEnv, string account, IReadOnlyList<string> absoluteToolDirs, string gitConfigGlobalPath)
    {
        var env = new Dictionary<string, string>(baseEnv, StringComparer.OrdinalIgnoreCase);

        // Defense in depth: the profile-derived base should not carry controller secrets; make sure.
        foreach (string key in env.Keys.ToList())
            if (DenyPrefixes.Any(p => key.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                env.Remove(key);

        // CreateEnvironmentBlock supplies USERPROFILE/APPDATA/LOCALAPPDATA/TEMP/TMP/USERNAME/USERDOMAIN
        // but not HOMEDRIVE/HOMEPATH (set at interactive logon). Derive any missing worker-owned
        // variable from the worker's OWN profile/machine -- never the controller.
        if (!env.TryGetValue("USERPROFILE", out string? profile) || string.IsNullOrEmpty(profile))
            throw new InvalidOperationException("worker environment has no USERPROFILE (profile not loaded?)");

        string localTemp = Path.Combine(profile, "AppData", "Local", "Temp");
        SetIfMissing(env, "APPDATA", Path.Combine(profile, "AppData", "Roaming"));
        SetIfMissing(env, "LOCALAPPDATA", Path.Combine(profile, "AppData", "Local"));
        SetIfMissing(env, "TEMP", localTemp);
        SetIfMissing(env, "TMP", localTemp);
        string root = Path.GetPathRoot(profile) ?? "";       // e.g. "C:\"
        if (root.Length >= 2)
        {
            string drive = root.TrimEnd('\\');               // "C:"
            SetIfMissing(env, "HOMEDRIVE", drive);
            SetIfMissing(env, "HOMEPATH", profile.Length > drive.Length ? profile[drive.Length..] : "\\");
        }
        SetIfMissing(env, "USERNAME", account);
        SetIfMissing(env, "USERDOMAIN", Environment.MachineName);

        // Deterministic tool resolution by absolute trusted paths, prepended to the worker PATH.
        string existingPath = env.TryGetValue("Path", out string? p) ? p : "";
        string prefix = string.Join(';', absoluteToolDirs.Where(Directory.Exists));
        env["Path"] = prefix.Length > 0 ? (existingPath.Length > 0 ? prefix + ";" + existingPath : prefix) : existingPath;

        env["NO_COLOR"] = "1";
        env["GIT_CONFIG_NOSYSTEM"] = "1";
        env["GIT_TERMINAL_PROMPT"] = "0";
        // Per-run git config that marks ONLY this run's exact clone safe (hardening 4B; never `*`).
        env["GIT_CONFIG_GLOBAL"] = gitConfigGlobalPath;

        return env;
    }

    private static void SetIfMissing(Dictionary<string, string> env, string key, string value)
    {
        if (!env.TryGetValue(key, out string? v) || string.IsNullOrEmpty(v)) env[key] = value;
    }

    /// <summary>Hardening #3 guarantee: the required worker-owned variables resolve to the worker.</summary>
    internal static void AssertWorkerOwned(IReadOnlyDictionary<string, string> env)
    {
        foreach (string key in RequiredWorkerOwned)
            if (!env.ContainsKey(key) || string.IsNullOrEmpty(env[key]))
                throw new InvalidOperationException($"worker environment is missing required variable {key}");
    }
}
