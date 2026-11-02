using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using CodeParley.Broker.Linux.Host;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Broker;

/// <summary>
/// Live verification of the host properties the worker boundary depends on. Every fact is measured
/// on each request (nothing is assumed from installation); any "problem" makes the host unverified
/// and LaunchWorkload is refused (fail closed). The same object is the Capabilities report.
/// </summary>
internal static class HostCheck
{
    // 239 guarantees the write-containment directives the worker unit depends on (ProtectSystem=strict
    // v232, ReadWritePaths v231, TemporaryFileSystem v238, InaccessiblePaths v233, RestrictNamespaces
    // v233, LockPersonality v235). Newer extras (RestrictSUIDSGID v242, ProtectClock v245, ProtectProc
    // v247) are applied only where supported. 239 = RHEL 8 / Debian 10 / Ubuntu 20.04 and up.
    internal const int MinSystemdVersion = 239;

    internal sealed record Report(JsonObject Facts, List<string> Problems, WorkerIdentity? Worker)
    {
        internal bool Verified => Problems.Count == 0;
    }

    internal static Report Verify(BrokerSettings s)
    {
        var problems = new List<string>();
        var f = new JsonObject
        {
            ["platform"] = "linux",
            ["architecture"] = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            ["kernel"] = ReadTrim("/proc/sys/kernel/osrelease"),
            ["distribution"] = OsRelease(),
        };

        // Service manager + cgroups (the lifetime boundary).
        var lifecycle = new JsonObject();
        try
        {
            if (!Systemd.IsInit) problems.Add("systemd is not the running init (required: PID 1 owns every run)");
            int v = Systemd.Version;
            lifecycle["systemdVersion"] = v;
            if (v < MinSystemdVersion) problems.Add($"systemd {v} is older than {MinSystemdVersion}");
            lifecycle["cgroupMode"] = Systemd.CgroupMode();
            lifecycle["owner"] = "service manager (PID 1): one transient unit = one cgroup per run";
            lifecycle["slice"] = Layout.Slice;
            lifecycle["killMode"] = "control-group";
            lifecycle["stopTimeoutSec"] = Layout.StopTimeoutSeconds;
            lifecycle["boundTo"] = Layout.SocketUnit;
            lifecycle["runtimeLimit"] = "RuntimeMaxSec (enforced by PID 1)";
            lifecycle["tasksMax"] = Layout.TasksMax;
        }
        catch (Exception e) { problems.Add("service manager: " + e.Message); }
        f["lifecycle"] = lifecycle;

        // Trusted executables: everything the broker runs or hands to the worker resolves through
        // root-owned, non-writable paths only.
        var tools = new JsonObject();
        foreach ((string name, string path) in new[]
                 {
                     ("broker", Layout.BrokerExe), ("node", Layout.NodeExe), ("git", s.GitPath),
                     ("env", "/usr/bin/env"), ("systemctl", SafePath(() => Systemd.Systemctl)),
                     ("systemd-run", SafePath(() => Systemd.SystemdRun)),
                 })
        {
            try { Trust.VerifyRootChain(path); tools[name] = path; }
            catch (Exception e) { problems.Add($"untrusted or missing {name} ({path}): {e.Message}"); }
        }
        foreach (WorkloadDef d in Workloads.All.Values)
        {
            try { Trust.VerifyRootChain(Workloads.ScriptPath(d)); }
            catch (Exception e) { problems.Add($"workload {d.Key}: {e.Message}"); }
        }
        f["toolchain"] = tools;

        // Filesystem layout + resolver.
        var fs = new JsonObject { ["resolver"] = SafeFs.ResolverDescription };
        try
        {
            using (Fd root = Workspace.OpenStateRoot()) fs["stateRoot"] = $"{Layout.StateRoot} {SafeFs.Describe(SafeFs.Stat(root))}";
            using (Fd d = Workspace.OpenStateDir()) fs["state"] = SafeFs.Describe(SafeFs.Stat(d));
            using (Fd d = Workspace.OpenRunsRoot()) fs["runs"] = SafeFs.Describe(SafeFs.Stat(d));
            using (Fd d = Workspace.OpenWorkRoot()) fs["work"] = SafeFs.Describe(SafeFs.Stat(d));
        }
        catch (Exception e) { problems.Add("state layout: " + e.Message); }
        f["filesystem"] = fs;

        // Worker identity.
        WorkerIdentity? w = null;
        var wi = new JsonObject();
        try
        {
            w = Identity.ResolveWorker(s);
            wi["user"] = w.User;
            wi["uid"] = w.Uid;
            wi["gid"] = w.Gid;
            wi["groups"] = new JsonArray(w.Groups.Select(g => (JsonNode?)Identity.GroupLabel(g)).ToArray());
            wi["supplementaryGroups"] = new JsonArray(w.SupplementaryGroups.Select(g => (JsonNode?)Identity.GroupLabel(g)).ToArray());
            wi["home"] = w.Home;
            wi["loginShell"] = w.Shell;
            List<string> wp = Identity.WorkerProblems(w, s);
            problems.AddRange(wp);
            wi["verified"] = wp.Count == 0;
            wi["cronDenied"] = ListedIn("/etc/cron.deny", w.User) || (File.Exists("/etc/cron.allow") && !ListedIn("/etc/cron.allow", w.User));
            wi["atDenied"] = ListedIn("/etc/at.deny", w.User) || (File.Exists("/etc/at.allow") && !ListedIn("/etc/at.allow", w.User));
        }
        catch (Exception e) { problems.Add("worker identity: " + e.Message); }
        f["workerIdentity"] = wi;

        // Controller identity + IPC.
        var ipc = new JsonObject
        {
            ["transport"] = "unix-stream-socket (systemd socket activation, Accept=yes)",
            ["path"] = Layout.SocketPath,
            ["peerAuthentication"] = "SO_PEERCRED (kernel-verified uid), checked by the handler",
            ["allowedUids"] = new JsonArray(0, s.ControllerUid),
        };
        try
        {
            Libc.PasswdEntry? ctl = Libc.GetPasswdByUid(s.ControllerUid);
            ipc["controllerUser"] = ctl?.Name;
            if (ctl is null) problems.Add($"controller uid {s.ControllerUid} does not exist");
            Libc.GroupEntry? g = Libc.GetGroupByName(s.ControllerGroup);
            if (g is null) problems.Add($"controller group '{s.ControllerGroup}' does not exist");
            else
            {
                ipc["socketGroup"] = $"{g.Name}({g.Gid})";
                if (Libc.StatxAt(Libc.AT_FDCWD, Layout.SocketPath, Libc.AT_SYMLINK_NOFOLLOW, out Libc.Statx st) == 0)
                {
                    ipc["socketMode"] = SafeFs.Describe(st);
                    if (st.Type != 0xC000) problems.Add($"{Layout.SocketPath} is not a socket");
                    if (st.Uid != 0 || st.Gid != g.Gid || (st.Perm & 0b000_000_111) != 0)
                        problems.Add($"{Layout.SocketPath} must be root:{g.Name} without other access (is {SafeFs.Describe(st)})");
                }
                else problems.Add($"{Layout.SocketPath} does not exist ({Libc.ErrText(Libc.Errno)})");
                if (w is not null && (w.Groups.Contains(g.Gid) || g.Members.Contains(w.User)))
                    problems.Add("worker can reach the broker socket through the controller group");
            }
        }
        catch (Exception e) { problems.Add("controller/IPC: " + e.Message); }
        f["ipc"] = ipc;

        var extras = new JsonArray();
        if (Systemd.Version >= 242) extras.Add("RestrictSUIDSGID");
        if (Systemd.Version >= 245) extras.Add("ProtectClock");
        if (Systemd.Version >= 247) extras.Add("ProtectProc=invisible");
        f["workerUnit"] = new JsonObject
        {
            ["noNewPrivileges"] = true,
            ["umask"] = Layout.WorkerUMask,
            ["environment"] = "explicit (HOME/XDG/TMPDIR from the worker account; no controller variables)",
            ["workingDirectory"] = "the run's standalone clone",
            ["filesystemContainment"] = "ProtectSystem=strict + ReadWritePaths=(run workspace, worker home)",
            ["isolatedTemp"] = "PrivateTmp (/tmp,/var/tmp) + private /dev/shm (TemporaryFileSystem)",
            ["sharedWritableDenied"] = "InaccessiblePaths=/run/lock,/var/crash,/dev/mqueue; /run read-only",
            ["cgroupProtected"] = "ProtectControlGroups=yes (no cgroup-escape write)",
            ["otherHardening"] = new JsonArray("PrivateDevices", "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules", "RestrictNamespaces", "LockPersonality", "RestrictRealtime", "RestrictAddressFamilies=AF_UNIX/AF_INET/AF_INET6"),
            ["versionGatedExtras"] = extras,
            ["notApplied"] = "MemoryDenyWriteExecute (breaks the V8 JIT), ProcSubset=pid (hides /proc/cpuinfo from libuv)",
        };
        f["concurrency"] = new JsonObject
        {
            ["model"] = "single active worker (Phase 3): a launch is rejected while any run is active",
            ["enforcedIn"] = "trusted broker state (systemd unit list), under the broker lock -- not controller scheduling",
            ["crossRunIsolation"] = "all runs share one worker UID; single-active replaces per-run identities",
            ["staleWorkspaceRecovery"] = "orphaned run workspaces are relocked to root 0700 on the next launch",
        };
        f["limits"] = new JsonObject { ["maxConcurrentRuns"] = s.MaxConcurrentRuns, ["maxTimeoutSeconds"] = s.MaxTimeoutSeconds };
        f["informational"] = new JsonObject
        {
            ["lsm"] = ReadTrim("/sys/kernel/security/lsm"),
            ["yamaPtraceScope"] = ReadTrim("/proc/sys/kernel/yama/ptrace_scope"),
            ["protectedSymlinks"] = ReadTrim("/proc/sys/fs/protected_symlinks"),
            ["protectedHardlinks"] = ReadTrim("/proc/sys/fs/protected_hardlinks"),
            ["protectedRegular"] = ReadTrim("/proc/sys/fs/protected_regular"),
            ["wslInterop"] = File.Exists("/proc/sys/fs/binfmt_misc/WSLInterop") ? ReadTrim("/proc/sys/fs/binfmt_misc/WSLInterop")?.Split('\n')[0] : null,
        };
        if (IsWsl())
        {
            // WSL bridges the Linux uid boundary into the Windows host (interop process creation as the
            // Windows user, drvfs mounts of Windows volumes): never a valid worker host. A root-owned
            // test-only setting lets the broker run there for development; reports say so.
            const string why = "WSL host: interop and drvfs bridge any Linux uid into the Windows user's session and volumes";
            if (s.TestOnlyAllowWslHost) f["testOnlyWslHost"] = why + " — ALLOWED FOR TESTING ONLY, not a security proof";
            else problems.Add(why + " (not a valid worker host)");
        }

        f["verified"] = problems.Count == 0;
        f["problems"] = new JsonArray(problems.Select(p => (JsonNode?)p).ToArray());
        return new Report(f, problems, w);
    }

    internal static bool IsWsl() =>
        File.Exists("/proc/sys/fs/binfmt_misc/WSLInterop")
        || (ReadTrim("/proc/sys/kernel/osrelease")?.Contains("microsoft", StringComparison.OrdinalIgnoreCase) ?? false);

    private static string SafePath(Func<string> f)
    {
        try { return f(); } catch { return "(unresolved)"; }
    }

    private static bool ListedIn(string file, string user)
    {
        try { return File.ReadLines(file).Any(l => l.Trim() == user); }
        catch (IOException) { return false; }
    }

    internal static string? ReadTrim(string path)
    {
        try { return File.ReadAllText(path).Trim(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    private static string? OsRelease()
    {
        try
        {
            foreach (string line in File.ReadLines("/etc/os-release"))
                if (line.StartsWith("PRETTY_NAME=", StringComparison.Ordinal)) return line[12..].Trim('"');
        }
        catch (IOException) { }
        return null;
    }
}
