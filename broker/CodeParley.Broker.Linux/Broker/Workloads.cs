using System.Text.Json.Nodes;
using CodeParley.Broker.Linux.Host;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Broker;

internal sealed record WorkloadDef(string Key, string Script, int DefaultTimeoutSeconds, int MaxTimeoutSeconds, bool IsProof);

/// <summary>
/// The fixed, allowlisted workloads. The broker chooses the interpreter (its root-owned Node), the
/// root-owned script and every argument; the caller only names the key. The scripts live in the
/// install tree (never in the worker-writable workspace).
/// </summary>
internal static class Workloads
{
    internal static readonly IReadOnlyDictionary<string, WorkloadDef> All = new Dictionary<string, WorkloadDef>(StringComparer.Ordinal)
    {
        ["proof-battery"] = new("proof-battery", "proof-battery.js", 300, 900, IsProof: true),
        ["lifecycle-tree"] = new("lifecycle-tree", "lifecycle-tree.js", 600, 3600, IsProof: false),
        ["lifecycle-detached"] = new("lifecycle-detached", "lifecycle-detached.js", 120, 600, IsProof: false),
    };

    internal static string ScriptPath(WorkloadDef d) => Layout.WorkloadsDir + "/" + d.Script;

    internal const string ResultFile = "result.json";

    /// <summary>Paths the proof battery must be unable to write (directories: create a canary;
    /// files: open for writing). Only existing paths are used, so every "denied" is meaningful.
    /// <paramref name="SharedDirs"/> are shared world-writable host locations (/dev/shm, /run/lock,
    /// /tmp, …): the worker may write its OWN private view of some of them, so the authoritative test
    /// is the broker checking the HOST afterward for any canary — none must leak out of the sandbox.</summary>
    internal sealed record DenyTargets(Dictionary<string, List<string>> Dirs, List<string> Files, List<string> SharedDirs);

    /// <summary>Shared/world-writable host locations the worker must not be able to leak into.</summary>
    internal static readonly string[] SharedWritableCandidates =
        ["/dev/shm", "/run/lock", "/run", "/dev/mqueue", "/var/crash", "/tmp", "/var/tmp"];

    internal static DenyTargets ComputeDenyTargets(BrokerSettings s)
    {
        var dirs = new Dictionary<string, List<string>>(StringComparer.Ordinal)
        {
            ["trusted"] =
            [
                Layout.StateRoot,
                $"{Layout.StateRoot}/{Layout.StateDirName}",
                $"{Layout.StateRoot}/{Layout.RunsDirName}",
                $"{Layout.StateRoot}/{Layout.WorkDirName}",
            ],
            ["install"] =
            [
                Layout.InstallRoot, Layout.InstallRoot + "/bin", Layout.WorkloadsDir, Layout.NodeBinDir,
                Layout.ConfigDir, "/etc/systemd/system",
            ],
            ["controller"] = [],
            ["siblings"] = [],
        };
        var files = new List<string>
        {
            Layout.BrokerExe, Layout.NodeExe, Layout.WorkloadsDir + "/proof-battery.js",
            Layout.ConfigDir + "/" + Layout.ConfigFileName,
            "/etc/systemd/system/" + Layout.SocketUnit, "/etc/systemd/system/codeparley-broker@.service",
            "/etc/passwd",
        };

        Libc.PasswdEntry? ctl = Libc.GetPasswdByUid(s.ControllerUid);
        if (ctl is not null && ctl.Home.StartsWith('/'))
            foreach (string p in new[] { ctl.Home, ctl.Home + "/.local/state/code-parley", ctl.Home + "/.config/code-parley", ctl.Home + "/src/CodeParley" })
                if (IsDirNoFollow(p)) dirs["controller"].Add(p);

        foreach (string sib in s.ProofSiblings)
        {
            if (IsDirNoFollow(sib)) dirs["siblings"].Add(sib);
            foreach (string f in new[] { sib + "/a.txt", sib + "/.git/config", sib + "/.git/HEAD" })
                if (IsFileNoFollow(f)) files.Add(f);
            if (IsDirNoFollow(sib + "/.git/hooks")) dirs["siblings"].Add(sib + "/.git/hooks");
        }
        files.RemoveAll(f => !IsFileNoFollow(f));
        foreach (List<string> list in dirs.Values) list.RemoveAll(d => !IsDirNoFollow(d));
        List<string> shared = SharedWritableCandidates.Where(IsDirNoFollow).ToList();
        return new DenyTargets(dirs, files, shared);
    }

    private static bool IsDirNoFollow(string p) => new FileInfo(p) is { Exists: false } && Directory.Exists(p) && !IsLink(p);
    private static bool IsFileNoFollow(string p) => File.Exists(p) && !IsLink(p);
    private static bool IsLink(string p) => new FileInfo(p).LinkTarget is not null;

    /// <summary>The workload's specification, handed to the root-owned script as one base64 argument
    /// (no quoting, $-expansion or %-specifier hazards on the unit's command line).</summary>
    internal static JsonObject BuildSpec(string runId, WorkloadDef d, WorkerIdentity w, BrokerSettings s, DenyTargets? deny)
    {
        string ws = Layout.WorkspacePath(runId);
        var spec = new JsonObject
        {
            ["runId"] = runId,
            ["workloadKey"] = d.Key,
            ["workspace"] = ws,
            ["repo"] = ws + "/repo",
            ["nested"] = ws + "/repo/sub/nested",
            ["resultPath"] = ws + "/" + ResultFile,
            ["tmp"] = ws + "/tmp",
            ["git"] = s.GitPath,
            ["node"] = Layout.NodeExe,
            ["socketPath"] = Layout.SocketPath,
            ["expected"] = new JsonObject { ["user"] = w.User, ["uid"] = w.Uid, ["gid"] = w.Gid, ["home"] = w.Home },
        };
        if (deny is not null)
        {
            var dirs = new JsonObject();
            foreach ((string k, List<string> v) in deny.Dirs) dirs[k] = new JsonArray(v.Select(x => (JsonNode?)x).ToArray());
            spec["denyDirs"] = dirs;
            spec["denyFiles"] = new JsonArray(deny.Files.Select(x => (JsonNode?)x).ToArray());
            spec["sharedDirs"] = new JsonArray(deny.SharedDirs.Select(x => (JsonNode?)x).ToArray());
        }
        return spec;
    }
}

/// <summary>The worker's explicit environment: derived from the worker account only, never from
/// the controller or the broker, and free of agent/session channels and Anthropic credentials.</summary>
internal static class WorkerEnvironment
{
    internal static List<KeyValuePair<string, string>> Build(WorkerIdentity w, string runId)
    {
        string home = w.Home;
        string shell = File.Exists("/bin/bash") ? "/bin/bash" : "/bin/sh";
        var env = new List<KeyValuePair<string, string>>
        {
            new("HOME", home),
            new("USER", w.User),
            new("LOGNAME", w.User),
            new("SHELL", shell),
            new("PATH", Layout.NodeBinDir + ":/usr/local/bin:/usr/bin:/bin"),
            new("LANG", "C.UTF-8"),
            new("TMPDIR", Layout.WorkspacePath(runId) + "/tmp"),
            new("XDG_CONFIG_HOME", home + "/.config"),
            new("XDG_CACHE_HOME", home + "/.cache"),
            new("XDG_DATA_HOME", home + "/.local/share"),
            new("XDG_STATE_HOME", home + "/.local/state"),
            new("NO_COLOR", "1"),
            new("GIT_CONFIG_NOSYSTEM", "1"),
            new("GIT_TERMINAL_PROMPT", "0"),
            new("npm_config_update_notifier", "false"),
            new("npm_config_fund", "false"),
            new("npm_config_audit", "false"),
            new("CODEPARLEY_RUN_ID", runId),
        };
        foreach ((string k, string v) in env) RequireUnitSafe(k, v);
        return env;
    }

    /// <summary>A value is placed into a unit property; refuse anything systemd would interpret
    /// (whitespace, quotes, backslash, $-expansion, %-specifiers, control characters).</summary>
    internal static void RequireUnitSafe(string key, string value)
    {
        foreach (char c in key + value)
            if (c <= 0x20 || c == 0x7F || c is '"' or '\'' or '\\' or '$' or '%' or ';')
                throw new InvalidOperationException($"unsafe character in environment entry {key}");
    }
}
