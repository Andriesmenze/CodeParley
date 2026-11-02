using CodeParley.Broker.Linux.Host;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Broker;

/// <summary>
/// Per-run workspaces under the fixed root /var/lib/codeparley-broker/work (root, 0711: the worker
/// can traverse to a name it is given but cannot list or create entries). A run directory is
/// created root-only (0700), filled while no other principal can reach it (standalone clone from a
/// broker-made bundle, self-contained .git, no origin, no template hooks), handed to the worker
/// (tree chowned without following links; the run directory itself stays root-owned with the
/// worker's primary group, 0770), relocked to 0700 the moment the run ends, and removed
/// descriptor-relative. The caller never supplies a path.
/// </summary>
internal static class Workspace
{
    internal static Fd OpenStateRoot()
    {
        Fd fd = SafeFs.OpenAbsoluteDir(Layout.StateRoot);
        Trust.RequireRootOwnedNotWritable(SafeFs.Stat(fd), Layout.StateRoot);
        return fd;
    }

    /// <summary>Open a fixed subdirectory of the state root and require root ownership + exact mode.</summary>
    internal static Fd OpenFixedDir(string name, uint expectedPerm)
    {
        using Fd root = OpenStateRoot();
        Fd d = SafeFs.OpenDirBeneath(root, name);
        Libc.Statx st = SafeFs.Stat(d);
        if (st.Uid != 0 || st.Perm != expectedPerm)
        {
            d.Dispose();
            throw new InvalidOperationException($"{Layout.StateRoot}/{name} must be root-owned {Convert.ToString(expectedPerm, 8)} (is {SafeFs.Describe(st)})");
        }
        return d;
    }

    internal static Fd OpenWorkRoot() => OpenFixedDir(Layout.WorkDirName, 0b111_001_001);   // 0711
    internal static Fd OpenRunsRoot() => OpenFixedDir(Layout.RunsDirName, 0b111_000_000);   // 0700
    internal static Fd OpenStateDir() => OpenFixedDir(Layout.StateDirName, 0b111_000_000);  // 0700

    /// <summary>Create, fill and hand over the run's workspace. Throws <see cref="RunExistsException"/>
    /// if a workspace with that runId already exists.</summary>
    internal static void Provision(string runId, WorkerIdentity w, BrokerSettings s)
    {
        using Fd work = OpenWorkRoot();
        try { SafeFs.MakeDir(work, runId, 0b111_000_000); }
        catch (SafeFsException e) when (e.Errno == Libc.EEXIST) { throw new RunExistsException(runId); }

        using Fd ws = SafeFs.OpenDirBeneath(work, runId);
        SafeFs.Chmod(ws, 0b111_000_000);
        Libc.Statx wst = SafeFs.Stat(ws);
        if (!wst.IsDir || wst.Uid != 0) throw new InvalidOperationException("fresh workspace is not a root-owned directory");

        // Path-based git is safe here only because every component of this path is root-owned and
        // not writable by any other principal at this moment (work/ is 0711, the run dir is 0700).
        string bundle = ProofSource.EnsureBundle(s);
        string repoPath = Layout.RepoPath(runId);
        Git(s, ["clone", "-q", "--template=", "--no-hardlinks", bundle, repoPath]);
        Git(s, ["-C", repoPath, "remote", "remove", "origin"]);

        using (Fd repo = SafeFs.OpenDirBeneath(ws, "repo"))
        {
            if (!SafeFs.TryStatEntry(repo, ".git", out Libc.Statx gst) || !gst.IsDir)
                throw new InvalidOperationException("clone is not standalone: .git is not a directory");
            SafeFs.ChownTree(repo, w.Uid, w.Gid);
        }
        SafeFs.MakeDir(ws, "tmp", 0b111_000_000);
        using (Fd tmp = SafeFs.OpenDirBeneath(ws, "tmp")) SafeFs.Chown(tmp, w.Uid, w.Gid);

        // Hand-over: the run directory stays root-owned (the worker cannot chmod/rename it), the
        // worker reaches it through its own primary group only.
        SafeFs.Chown(ws, 0, w.Gid);
        SafeFs.Chmod(ws, 0b111_111_000);   // 0770
    }

    /// <summary>Make an ended run's workspace unreachable for the worker identity (0700, root-owned).</summary>
    internal static bool Relock(string runId)
    {
        using Fd work = OpenWorkRoot();
        using Fd? ws = SafeFs.OpenBeneath(work, runId, Libc.O_RDONLY | Libc.O_DIRECTORY);
        if (ws is null) return false;
        Libc.Statx st = SafeFs.Stat(ws);
        if (st.Uid != 0) throw new InvalidOperationException($"workspace {runId} is not root-owned; refusing to touch it");
        SafeFs.Chmod(ws, 0b111_000_000);
        return true;
    }

    /// <summary>Crash recovery: relock (to root 0700) every workspace whose run no longer has a
    /// systemd unit and that is still group-accessible (0770) — so a workspace left behind by a host
    /// crash or a handler killed mid-run can never be reached by a later worker. Returns the runIds
    /// relocked.</summary>
    internal static List<string> RelockOrphans(IReadOnlySet<string> runIdsWithUnits)
    {
        var relocked = new List<string>();
        using Fd work = OpenWorkRoot();
        foreach ((string name, byte type) in Libc.ReadDirectory(work.Value))
        {
            if (runIdsWithUnits.Contains(name)) continue;
            bool isDir = type == Libc.DT_DIR || (type == Libc.DT_UNKNOWN && SafeFs.TryStatEntry(work, name, out Libc.Statx s) && s.IsDir);
            if (!isDir) continue;
            try
            {
                using Fd d = SafeFs.OpenDirBeneath(work, name);
                Libc.Statx st = SafeFs.Stat(d);
                if (st.Uid == 0 && (st.Perm & 0b000_111_111) != 0)   // root-owned but group/other-accessible
                {
                    SafeFs.Chmod(d, 0b111_000_000);
                    relocked.Add(name);
                }
            }
            catch (IOException) { /* skip an entry that vanished or cannot be opened */ }
        }
        return relocked;
    }

    internal static RemoveReport Remove(string runId)
    {
        using Fd work = OpenWorkRoot();
        if (!SafeFs.TryStatEntry(work, runId, out _)) return new RemoveReport(true, 0, []);
        Relock(runId);
        return SafeFs.RemoveTree(work, runId, TimeSpan.FromMinutes(5));
    }

    internal static bool Exists(string runId)
    {
        using Fd work = OpenWorkRoot();
        return SafeFs.TryStatEntry(work, runId, out _);
    }

    /// <summary>Read a file the worker wrote, beneath its workspace, without following links.</summary>
    internal static string? ReadWorkerFile(string runId, string rel, int maxBytes)
    {
        using Fd work = OpenWorkRoot();
        using Fd? ws = SafeFs.OpenBeneath(work, runId, Libc.O_RDONLY | Libc.O_DIRECTORY);
        if (ws is null) return null;
        try
        {
            byte[]? b = SafeFs.ReadFileBeneath(ws, rel, maxBytes, out bool truncated);
            if (b is null) return null;
            string text = System.Text.Encoding.UTF8.GetString(b);
            return truncated ? text + "\n…[truncated]" : text;
        }
        catch (IOException e) { return $"(unreadable: {e.Message})"; }
    }

    internal static void Git(BrokerSettings s, IReadOnlyList<string> args) =>
        ProcessRunner.RunChecked(s.GitPath, args, GitEnvironment, 120_000);

    /// <summary>Root's git never reads system/global config, never prompts, and has a root-only HOME.</summary>
    internal static readonly IReadOnlyDictionary<string, string> GitEnvironment = new Dictionary<string, string>
    {
        ["PATH"] = "/usr/bin:/bin",
        ["LANG"] = "C.UTF-8",
        ["HOME"] = $"{Layout.StateRoot}/{Layout.StateDirName}",
        ["GIT_CONFIG_NOSYSTEM"] = "1",
        ["GIT_CONFIG_GLOBAL"] = "/dev/null",
        ["GIT_ATTR_NOSYSTEM"] = "1",
        ["GIT_TERMINAL_PROMPT"] = "0",
        ["GIT_AUTHOR_NAME"] = "codeparley-broker",
        ["GIT_AUTHOR_EMAIL"] = "broker@localhost",
        ["GIT_COMMITTER_NAME"] = "codeparley-broker",
        ["GIT_COMMITTER_EMAIL"] = "broker@localhost",
        ["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:00Z",
        ["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:00Z",
    };
}

internal sealed class RunExistsException(string runId) : Exception($"run '{runId}' already exists");

/// <summary>
/// The deterministic proof source (Phase 3.1B, like the Windows proof: a broker-made throwaway
/// repository, never a real checkout). It is published as a git bundle: a bundle carries objects
/// and refs only — no config, no hooks — so a clone of it inherits nothing executable. In the
/// controller-integration milestone the controller supplies the bundle bytes instead.
/// </summary>
internal static class ProofSource
{
    private const string RepoDir = "proof-src";
    private const string BundleName = "proof-src.bundle";

    internal static string EnsureBundle(BrokerSettings s)
    {
        using Fd state = Workspace.OpenStateDir();
        string stateDir = $"{Layout.StateRoot}/{Layout.StateDirName}";
        string bundlePath = $"{stateDir}/{BundleName}";
        if (SafeFs.TryStatEntry(state, BundleName, out Libc.Statx bst) && bst.IsRegular && bst.Uid == 0) return bundlePath;

        if (SafeFs.TryStatEntry(state, RepoDir, out _)) SafeFs.RemoveTree(state, RepoDir, TimeSpan.FromMinutes(1));
        SafeFs.MakeDir(state, RepoDir, 0b111_000_000);
        string src = $"{stateDir}/{RepoDir}";
        Workspace.Git(s, ["init", "-q", src]);
        Workspace.Git(s, ["-C", src, "symbolic-ref", "HEAD", "refs/heads/main"]);
        File.WriteAllText($"{src}/a.txt", "hello\n");
        Directory.CreateDirectory($"{src}/sub/nested");
        File.WriteAllText($"{src}/sub/nested/b.txt", "nested\n");
        File.WriteAllText($"{src}/package.json",
            "{\n  \"name\": \"cp-proof\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n" +
            "  \"scripts\": { \"noop\": \"node -e \\\"process.stdout.write('noop-ok:' + process.cwd())\\\"\" }\n}\n");
        Workspace.Git(s, ["-C", src, "add", "a.txt", "sub/nested/b.txt", "package.json"]);
        Workspace.Git(s, ["-C", src, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "seed"]);
        string tmp = $"{stateDir}/.{BundleName}.tmp";
        if (File.Exists(tmp)) File.Delete(tmp);
        Workspace.Git(s, ["-C", src, "bundle", "create", tmp, "--all"]);
        File.Move(tmp, bundlePath, overwrite: true);
        return bundlePath;
    }
}
