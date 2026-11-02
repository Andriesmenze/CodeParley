using System.Text.Json;
using System.Text.RegularExpressions;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux;

/// <summary>
/// The broker's fixed, trusted filesystem and unit layout (FHS locations). None of it is
/// caller-supplied: the IPC carries only a runId and a workload key.
/// </summary>
internal static class Layout
{
    internal const int ProtocolVersion = 1;

    internal const string InstallRoot = "/opt/codeparley-broker";
    internal const string BrokerExe = InstallRoot + "/bin/codeparley-broker";
    internal const string WorkloadsDir = InstallRoot + "/workloads";
    internal const string NodeBinDir = InstallRoot + "/toolchain/node/bin";
    internal const string NodeExe = NodeBinDir + "/node";

    internal const string ConfigDir = "/etc/codeparley-broker";
    internal const string ConfigFileName = "broker.json";

    internal const string StateRoot = "/var/lib/codeparley-broker";   // root 0755
    internal const string StateDirName = "state";                      // root 0700: broker-private state
    internal const string RunsDirName = "runs";                        // root 0700: per-run records + worker logs
    internal const string WorkDirName = "work";                        // root 0711: per-run workspaces

    internal const string SocketPath = "/run/codeparley-broker.sock";
    internal const string SocketUnit = "codeparley-broker.socket";
    internal const string Slice = "codeparley.slice";
    internal const string RunUnitPrefix = "codeparley-run-";

    internal static string RunUnit(string runId) => RunUnitPrefix + runId + ".service";
    internal static string WorkspacePath(string runId) => $"{StateRoot}/{WorkDirName}/{runId}";
    internal static string RepoPath(string runId) => WorkspacePath(runId) + "/repo";
    internal static string RunsPath(string runId) => $"{StateRoot}/{RunsDirName}/{runId}";

    // Worker unit settings shared by launch and capability reporting.
    internal const int StopTimeoutSeconds = 8;
    internal const int TasksMax = 1024;
    internal const string WorkerUMask = "0077";
}

/// <summary>Install-time trusted settings from /etc/codeparley-broker/broker.json (root-owned, not
/// group/other-writable; refused otherwise).</summary>
internal sealed partial class BrokerSettings
{
    public uint ControllerUid { get; init; }
    public string ControllerGroup { get; init; } = "codeparley";
    public string WorkerUser { get; init; } = "cp-worker";
    public string GitPath { get; init; } = "/usr/bin/git";
    public int MaxConcurrentRuns { get; init; } = 1;   // Phase 3: single active worker (enforced; must be 1)
    public int MaxTimeoutSeconds { get; init; } = 3600;
    public string[] ProofSiblings { get; init; } = [];

    /// <summary>Development only: let the broker run on a WSL host (which is never a valid worker
    /// host — see HostCheck). Reported in every capability report.</summary>
    public bool TestOnlyAllowWslHost { get; init; }

    [GeneratedRegex("^[a-z_][a-z0-9_-]{0,31}$")]
    private static partial Regex PosixName();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
    };

    internal static BrokerSettings Load()
    {
        using Fd dir = SafeFs.OpenAbsoluteDir(Layout.ConfigDir);
        Trust.RequireRootOwnedNotWritable(SafeFs.Stat(dir), Layout.ConfigDir);
        using Fd? f = SafeFs.OpenBeneath(dir, Layout.ConfigFileName, Libc.O_RDONLY | Libc.O_NONBLOCK)
            ?? throw new InvalidOperationException($"missing {Layout.ConfigDir}/{Layout.ConfigFileName}");
        Libc.Statx st = SafeFs.Stat(f);
        if (!st.IsRegular) throw new InvalidOperationException("broker.json is not a regular file");
        Trust.RequireRootOwnedNotWritable(st, $"{Layout.ConfigDir}/{Layout.ConfigFileName}");
        byte[] bytes = SafeFs.ReadFileBeneath(dir, Layout.ConfigFileName, 64 * 1024, out bool truncated)
            ?? throw new InvalidOperationException("broker.json vanished");
        if (truncated) throw new InvalidOperationException("broker.json too large");
        BrokerSettings s = JsonSerializer.Deserialize<BrokerSettings>(bytes, JsonOptions)
            ?? throw new InvalidOperationException("broker.json is empty");
        s.Validate();
        return s;
    }

    private void Validate()
    {
        if (ControllerUid == 0) throw new InvalidOperationException("controllerUid must name the (non-root) controller account");
        if (!PosixName().IsMatch(WorkerUser)) throw new InvalidOperationException("invalid workerUser");
        if (!PosixName().IsMatch(ControllerGroup)) throw new InvalidOperationException("invalid controllerGroup");
        if (!GitPath.StartsWith('/')) throw new InvalidOperationException("gitPath must be absolute");
        if (MaxConcurrentRuns != 1) throw new InvalidOperationException("maxConcurrentRuns must be 1 (Phase 3 enforces a single active worker)");
        if (MaxTimeoutSeconds is < 10 or > 86400) throw new InvalidOperationException("maxTimeoutSeconds must be 10..86400");
        foreach (string p in ProofSiblings)
            if (!p.StartsWith('/') || p.Contains("..") || p.Contains('\0')) throw new InvalidOperationException($"invalid proof sibling path {p}");
    }
}

/// <summary>Ownership/mode rules for anything the broker treats as trusted.</summary>
internal static class Trust
{
    internal static void RequireRootOwnedNotWritable(Libc.Statx st, string what)
    {
        if (st.Uid != 0) throw new InvalidOperationException($"{what} is not owned by root (uid {st.Uid})");
        if ((st.Perm & 0b000_010_010) != 0) throw new InvalidOperationException($"{what} is group/other-writable ({Convert.ToString(st.Perm, 8)})");
    }

    /// <summary>Every component of an absolute path, from "/", is a non-symlink owned by root and not
    /// group/other-writable; returns the final component's stat. Used for every executable the broker
    /// runs or hands to the worker, so nothing it executes resolves through a writable location.</summary>
    internal static Libc.Statx VerifyRootChain(string absPath)
    {
        if (!absPath.StartsWith('/')) throw new InvalidOperationException($"not absolute: {absPath}");
        string[] comps = absPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        int cur = Libc.Openat(Libc.AT_FDCWD, "/", Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_CLOEXEC, 0);
        if (cur < 0) throw new SafeFsException("open /", Libc.Errno);
        try
        {
            if (Libc.StatxFd(cur, out Libc.Statx rootSt) != 0) throw new SafeFsException("stat /", Libc.Errno);
            RequireRootOwnedNotWritable(rootSt, "/");
            Libc.Statx st = rootSt;
            for (int i = 0; i < comps.Length; i++)
            {
                if (comps[i] is "." or "..") throw new InvalidOperationException($"path component '{comps[i]}' in {absPath}");
                bool last = i == comps.Length - 1;
                int next = Libc.Openat(cur, comps[i], (last ? Libc.O_RDONLY | Libc.O_NONBLOCK : Libc.O_RDONLY | Libc.O_DIRECTORY) | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, 0);
                if (next < 0) throw new SafeFsException($"open {absPath} (component '{comps[i]}', symlinks refused)", Libc.Errno);
                Libc.close(cur);
                cur = next;
                if (Libc.StatxFd(cur, out st) != 0) throw new SafeFsException($"stat {comps[i]}", Libc.Errno);
                RequireRootOwnedNotWritable(st, "/" + string.Join('/', comps, 0, i + 1));
            }
            return st;
        }
        finally { Libc.close(cur); }
    }
}
