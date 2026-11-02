using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CodeParley.Broker.Linux.Host;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Broker;

/// <summary>
/// The semantic run operations. Launch/Terminate/Cleanup are serialized by the broker lock; status
/// is read-only. All state lives in the service manager (units) and in root-only records; the
/// handler process itself holds nothing across requests.
/// </summary>
internal static partial class RunOps
{
    // Same runId rule as the Windows broker: starts alphanumeric; [A-Za-z0-9_-]; 8..64 characters.
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")]
    private static partial Regex RunIdPattern();

    internal static bool IsValidRunId(string? runId) => runId is not null && RunIdPattern().IsMatch(runId);

    /// <summary>The runId inside a `codeparley-run-&lt;id&gt;.service` unit name, or null.</summary>
    internal static string? RunIdOfUnit(string unit)
    {
        const string suffix = ".service";
        if (!unit.StartsWith(Layout.RunUnitPrefix, StringComparison.Ordinal) || !unit.EndsWith(suffix, StringComparison.Ordinal)) return null;
        string id = unit[Layout.RunUnitPrefix.Length..^suffix.Length];
        return IsValidRunId(id) ? id : null;
    }

    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(60);
    private const string CanaryPrefix = "cp_probe_";

    internal static BrokerResponse Launch(BrokerRequest req, BrokerSettings s, uint callerUid)
    {
        if (!IsValidRunId(req.RunId)) return BrokerResponse.Fail(ErrorCodes.InvalidRunId, "runId must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$");
        string runId = req.RunId!;
        if (req.WorkloadKey is null || !Workloads.All.TryGetValue(req.WorkloadKey, out WorkloadDef? def))
            return BrokerResponse.Fail(ErrorCodes.UnknownWorkload, "workloadKey is not an allowlisted workload", runId);
        int max = Math.Min(def.MaxTimeoutSeconds, s.MaxTimeoutSeconds);
        int timeout = req.TimeoutSeconds ?? Math.Min(def.DefaultTimeoutSeconds, max);
        if (timeout < 3 || timeout > max) return BrokerResponse.Fail(ErrorCodes.InvalidTimeout, $"timeoutSeconds must be 3..{max}", runId);

        using BrokerLock? held = BrokerLock.TryAcquire(LockWait);
        if (held is null) return BrokerResponse.Fail(ErrorCodes.Busy, "another launch/terminate/cleanup is in progress", runId);

        HostCheck.Report host = HostCheck.Verify(s);
        if (!host.Verified) return BrokerResponse.Fail(ErrorCodes.HostUnverified, string.Join("; ", host.Problems), runId);
        WorkerIdentity w = host.Worker!;

        // Crash recovery: all runs share one worker UID, so cross-run isolation is provided by the
        // SINGLE-ACTIVE-WORKER invariant (Phase 3), not by per-run identities. Before enforcing it,
        // relock any workspace left group-accessible by a crashed run whose unit is gone, so a stale
        // workspace can never be reached by a later worker.
        List<(string Unit, string Active, string Sub)> runUnits = Systemd.ListRunUnits();
        var activeRunIds = runUnits
            .Where(u => u.Active is "active" or "activating" or "deactivating" or "reloading")
            .Select(u => RunIdOfUnit(u.Unit)).Where(id => id is not null).Select(id => id!).ToHashSet(StringComparer.Ordinal);
        try { Workspace.RelockOrphans(runUnits.Select(u => RunIdOfUnit(u.Unit)).Where(id => id is not null).Select(id => id!).ToHashSet(StringComparer.Ordinal)); }
        catch (Exception e) { Log.Error("orphan-workspace recovery: " + e.Message); }

        // Single active worker: reject if any run is already active (enforced in trusted broker state
        // under the broker lock, not by controller scheduling).
        if (activeRunIds.Count > 0)
            return BrokerResponse.Fail(ErrorCodes.CapacityExceeded,
                $"a worker run is already active ({string.Join(",", activeRunIds)}); Phase 3 allows one active worker at a time", runId);

        string unit = Layout.RunUnit(runId);
        if (RunStore.Exists(runId) || Workspace.Exists(runId) || Systemd.Show(unit, ["LoadState"]).GetValueOrDefault("LoadState") == "loaded")
            return BrokerResponse.Fail(ErrorCodes.RunExists, $"run '{runId}' already exists (Cleanup it first)", runId);

        try { RunStore.Create(runId); }
        catch (RunExistsException) { return BrokerResponse.Fail(ErrorCodes.RunExists, $"run '{runId}' already exists", runId); }

        var rec = new RunRecord
        {
            RunId = runId, WorkloadKey = def.Key, Unit = unit, TimeoutSeconds = timeout,
            State = "provisioning", CreatedAt = DateTimeOffset.UtcNow, RequestedByUid = callerUid,
        };
        RunStore.WriteRun(rec);

        bool unitCreated = false;
        try
        {
            Workspace.Provision(runId, w, s);
            Workloads.DenyTargets? deny = def.IsProof ? Workloads.ComputeDenyTargets(s) : null;
            if (deny is not null)
            {
                rec.DenyDirs = deny.Dirs;
                rec.SharedDirs = deny.SharedDirs;
                rec.FileStamps = deny.Files.ToDictionary(f => f, f => StampOf(f) ?? new FileStamp(0, 0, 0, 0));
            }
            string spec = Convert.ToBase64String(Encoding.UTF8.GetBytes(Workloads.BuildSpec(runId, def, w, s, deny).ToJsonString()));
            List<string> args = UnitArguments(runId, def, timeout, w, spec);
            ProcessRunner.Result r = ProcessRunner.Run(Systemd.SystemdRun, args, timeoutMs: 90_000);
            unitCreated = true;
            if (r.ExitCode != 0) throw new InvalidOperationException("systemd-run failed: " + r.Combined);

            Dictionary<string, string> show = Systemd.Show(unit, ["MainPID", "InvocationID"]);
            rec.State = "started";
            rec.StartedAt = DateTimeOffset.UtcNow;
            rec.MainPid = int.TryParse(show.GetValueOrDefault("MainPID"), NumberStyles.None, CultureInfo.InvariantCulture, out int pid) && pid > 0 ? pid : null;
            rec.InvocationId = show.GetValueOrDefault("InvocationID") is { Length: > 0 } inv ? inv : null;
            RunStore.WriteRun(rec);
            return new BrokerResponse { Ok = true, RunId = runId, State = "running", Pid = rec.MainPid };
        }
        catch (Exception e)
        {
            Log.Error($"launch {runId} failed: {e.Message}");
            rec.State = "launch_failed";
            rec.LaunchError = e.Message;
            try { RunStore.WriteRun(rec); } catch (Exception we) { Log.Error("recording the launch failure: " + we.Message); }
            if (unitCreated) { try { Systemd.Ctl(["stop", unit], 90_000); } catch (Exception se) { Log.Error("stop after failed launch: " + se.Message); } }
            try { Workspace.Remove(runId); } catch (Exception ce) { Log.Error("workspace cleanup after failed launch: " + ce.Message); }
            return BrokerResponse.Fail(ErrorCodes.LaunchFailed, e.Message, runId);
        }
    }

    /// <summary>The transient unit: PID 1 switches to the worker identity, applies the explicit
    /// environment, cwd and limits, and owns the whole process tree in one cgroup.</summary>
    internal static List<string> UnitArguments(string runId, WorkloadDef def, int timeoutSeconds, WorkerIdentity w, string specBase64)
    {
        string unit = Layout.RunUnit(runId);
        string group = Libc.GetGroupByGid(w.Gid)?.Name ?? w.Gid.ToString(CultureInfo.InvariantCulture);
        string recordExit =
            "+/usr/bin/env -i DOTNET_EnableDiagnostics=0 SERVICE_RESULT=${SERVICE_RESULT} EXIT_CODE=${EXIT_CODE} EXIT_STATUS=${EXIT_STATUS} "
            + Layout.BrokerExe + " record-exit " + runId;
        var a = new List<string>
        {
            "--unit=" + unit, "--slice=" + Layout.Slice, "--collect", "--no-ask-password", "--quiet",
            "--description=CodeParley worker run " + runId,
            P("Type", Systemd.Version >= 240 ? "exec" : "simple"),
            P("User", w.User), P("Group", group),
            P("NoNewPrivileges", "yes"),
            P("UMask", Layout.WorkerUMask),
            P("WorkingDirectory", Layout.RepoPath(runId)),
            P("KillMode", "control-group"), P("SendSIGKILL", "yes"),
            P("TimeoutStopSec", Layout.StopTimeoutSeconds + "s"),
            P("RuntimeMaxSec", timeoutSeconds + "s"),
            P("TasksMax", Layout.TasksMax.ToString(CultureInfo.InvariantCulture)),
            P("BindsTo", Layout.SocketUnit), P("After", Layout.SocketUnit),
            P("StandardInput", "null"), P("StandardOutput", "journal"), P("StandardError", "journal"),
            P("SyslogIdentifier", unit[..^".service".Length]),
            P("ExecStopPost", recordExit),
        };
        a.AddRange(HardeningProperties(runId, w));
        foreach ((string k, string v) in WorkerEnvironment.Build(w, runId)) a.Add(P("Environment", k + "=" + v));
        a.Add("--");
        a.Add(Layout.NodeExe);
        a.Add(Workloads.ScriptPath(def));
        a.Add(specBase64);
        return a;
    }

    /// <summary>
    /// Write-containment by systemd sandboxing (the smallest conventional correction, no bubblewrap/
    /// userns): the whole filesystem read-only except the run workspace and the worker home; private
    /// /tmp, /var/tmp and /dev/shm (isolated temp, no host leak); the shared world-writable tmpfs
    /// locations ProtectSystem=strict does not cover (/run/lock, /dev/mqueue, /var/crash) made
    /// inaccessible; the cgroup tree, kernel tunables/modules and clock protected. All proven on WSL2
    /// to deny every shared host write while keeping Git/Node/npm and nested child processes working.
    /// Version-sensitive directives are applied only where the host's systemd supports them.
    /// </summary>
    private static IEnumerable<string> HardeningProperties(string runId, WorkerIdentity w)
    {
        int v = Systemd.Version;
        string workspace = Layout.WorkspacePath(runId);
        yield return P("ProtectSystem", "strict");                       // v232
        yield return P("ReadWritePaths", workspace + " " + w.Home);      // v231
        yield return P("PrivateTmp", "yes");                             // private /tmp + /var/tmp
        yield return P("TemporaryFileSystem", "/dev/shm:mode=1777,size=64M"); // v238: private /dev/shm
        yield return P("PrivateDevices", "yes");                         // v209: minimal private /dev
        yield return P("InaccessiblePaths", "-/run/lock -/var/crash -/dev/mqueue"); // leading '-': ok if absent
        yield return P("ProtectHome", "yes");                            // hide other users' homes
        yield return P("ProtectControlGroups", "yes");                   // /sys/fs/cgroup read-only (no cgroup escape)
        yield return P("ProtectKernelTunables", "yes");
        yield return P("ProtectKernelModules", "yes");
        yield return P("RestrictNamespaces", "yes");                     // v233: no new namespaces
        yield return P("LockPersonality", "yes");                        // v235
        yield return P("RestrictRealtime", "yes");                       // v231
        yield return P("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"); // v211
        // Deliberately NOT MemoryDenyWriteExecute (breaks the V8 JIT) and NOT ProcSubset=pid
        // (hides /proc/cpuinfo, which libuv reads for the CPU count).
        if (v >= 242) yield return P("RestrictSUIDSGID", "yes");
        if (v >= 245) yield return P("ProtectClock", "yes");
        if (v >= 247) yield return P("ProtectProc", "invisible");        // hide other processes in /proc
    }

    private static string P(string key, string value) => "--property=" + key + "=" + value;

    internal static BrokerResponse Status(string runId)
    {
        RunRecord? rec = RunStore.ReadRun(runId);
        if (rec is null)
        {
            return Workspace.Exists(runId)
                ? new BrokerResponse { Ok = true, RunId = runId, State = "lost", Notes = ["workspace exists without a run record"] }
                : new BrokerResponse { Ok = true, RunId = runId, State = "none" };
        }

        var resp = new BrokerResponse { Ok = true, RunId = runId, Pid = rec.MainPid };
        var notes = new List<string>();
        ExitRecord? exit = RunStore.ReadExit(runId);
        if (rec.State == "launch_failed")
        {
            resp.State = "failed";
            notes.Add("launch failed: " + rec.LaunchError);
        }
        else if (exit is not null)
        {
            Classify(rec, exit, resp, notes, descendantsRemain: exit.StragglersAtStop.Length > 0);
            if (exit.StragglersAtStop.Length > 0) resp.Members = exit.StragglersAtStop;
        }
        else if (rec.State == "provisioning")
        {
            // Handler-crash recovery: the record was never advanced to "started", but the unit may in
            // fact be running (the handler was killed after systemd-run but before it recorded the
            // state). Trust the service manager, not the stale record.
            Dictionary<string, string> show = Systemd.Show(rec.Unit, ["LoadState", "ActiveState"]);
            if (show.GetValueOrDefault("LoadState") == "loaded" && show.GetValueOrDefault("ActiveState") is "active" or "activating" or "reloading")
            {
                resp.State = "running";
                notes.Add("recovered: the launch handler ended before recording the run, but the unit is active");
            }
            else
            {
                resp.State = DateTimeOffset.UtcNow - rec.CreatedAt > TimeSpan.FromMinutes(5) ? "failed" : "starting";
                if (resp.State == "failed") notes.Add("provisioning never completed (handler ended mid-launch; no unit)");
            }
        }
        else
        {
            Dictionary<string, string> show = Systemd.Show(rec.Unit, ["LoadState", "ActiveState", "SubState", "MainPID", "ControlGroup"]);
            string load = show.GetValueOrDefault("LoadState", ""), active = show.GetValueOrDefault("ActiveState", "");
            if (load == "loaded" && active is "active" or "activating" or "reloading") resp.State = "running";
            else if (load == "loaded" && active == "deactivating") resp.State = "stopping";
            else
            {
                resp.State = "lost";
                notes.Add($"unit is {load}/{active} and no exit was recorded (host restart?)");
            }
            if (int.TryParse(show.GetValueOrDefault("MainPID"), NumberStyles.None, CultureInfo.InvariantCulture, out int pid) && pid > 0) resp.Pid = pid;
            string cg = show.GetValueOrDefault("ControlGroup", "");
            if (cg.Length > 0)
                resp.Members = Systemd.CgroupPids(cg).Select(Systemd.ProcessIdentity).Where(x => x is not null).Select(x => x!).ToArray();
        }

        bool terminal = resp.State is not ("running" or "starting" or "stopping");
        if (terminal)
        {
            // Relock the ended workspace to root 0700 (the worker UID can no longer reach it). Done by
            // the broker, not the sandboxed ExecStopPost hook; idempotent; RelockOrphans on the next
            // launch is the authoritative safety net if no status is ever read.
            try { Workspace.Relock(runId); } catch (Exception e) { Log.Error($"relock {runId}: {e.Message}"); }
        }
        resp.ResultJson = Workspace.ReadWorkerFile(runId, Workloads.ResultFile, 1024 * 1024);
        if (terminal)
        {
            resp.WorkerLog = RunStore.WorkerLogTail(runId, rec.InvocationId);
            if (rec.DenyDirs is not null) resp.Verification = Verify(runId, rec);
        }
        resp.Notes = notes.Count > 0 ? notes.ToArray() : null;
        return resp;
    }

    /// <summary>
    /// Map the service manager's own exit facts (SERVICE_RESULT/EXIT_CODE/EXIT_STATUS, recorded by the
    /// root ExecStopPost hook — never anything the worker wrote) to a host-execution state, with a
    /// deterministic precedence. Crucially, a run whose host cleanup was not clean (stragglers had to
    /// be SIGKILLed after the stop timeout, or descendants remained) is NEVER classified as a clean
    /// success: it is `unclean`. And no host-execution state — not even `exited` code 0 — is a
    /// task-level PASS, `ready`, or user authorization (see HOST-CONTRACT.md).
    ///
    /// Precedence: terminated (we asked) > remaining descendants (unclean) > execution timeout
    /// (timed_out) > unclean stop (stragglers) > stopped-from-outside (interrupted) > clean exit.
    /// Execution timeout (main ran to RuntimeMaxSec and was killed, or exited on its SIGTERM at the
    /// limit) is distinguished from a shutdown/cleanup timeout (main finished early but stragglers
    /// forced a SIGKILL) by EXIT_CODE and the elapsed time vs the run's limit.
    /// </summary>
    private static void Classify(RunRecord rec, ExitRecord e, BrokerResponse r, List<string> notes, bool descendantsRemain)
    {
        r.Result = e.ServiceResult;
        bool mainKilled = e.ExitCode is "killed" or "dumped";
        if (e.ExitCode == "exited" && int.TryParse(e.ExitStatus, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int code)) r.ExitCode = code;
        else if (mainKilled && e.ExitStatus.Length > 0) r.Signal = "SIG" + e.ExitStatus;

        // Did the run reach its own wall-clock limit? Only the elapsed time decides this — NOT the
        // fact that the main process was killed, because an external stop (broker-socket shutdown,
        // systemctl stop) also kills the main and, when children ignore SIGTERM, also yields
        // SERVICE_RESULT=timeout from the STOP phase. elapsed ≈ RuntimeMaxSec ⟹ it ran to the limit.
        double elapsed = rec.StartedAt is { } started ? (e.RecordedAt - started).TotalSeconds : double.NaN;
        bool ranToLimit = !double.IsNaN(elapsed) && elapsed >= rec.TimeoutSeconds - 3;

        if (descendantsRemain)
        {
            r.State = "unclean";   // the cgroup should be empty by ExecStopPost; it was not
            notes.Add("descendants remained in the run's cgroup after termination; host containment was not clean");
        }
        else if (e.TerminateRequested)
        {
            r.State = "terminated";   // we requested the stop; the run was cut short on purpose
        }
        else
        {
            switch (e.ServiceResult)
            {
                case "success":
                    if (e.ExitCode == "exited") r.State = "exited";             // clean: main exited, cgroup emptied cleanly
                    else { r.State = "interrupted"; notes.Add($"stopped from outside the broker by {r.Signal ?? "a signal"} (service-manager or broker-socket shutdown)"); }
                    break;
                case "exit-code":
                    r.State = "exited";                                         // clean, but the workload itself exited non-zero
                    notes.Add("the workload exited with a non-zero status (clean host execution, failed workload)");
                    break;
                case "timeout":
                    if (ranToLimit)
                    {
                        r.State = "timed_out";                                  // execution wall-clock limit (RuntimeMaxSec)
                        notes.Add("execution reached the run's time limit (RuntimeMaxSec); the worker tree was killed");
                    }
                    else if (e.ExitCode == "exited")
                    {
                        r.State = "unclean";                                    // main finished early; STOP phase timed out on stragglers
                        notes.Add("host cleanup was not clean: the main process finished but descendant(s) ignored SIGTERM and were SIGKILLed after the stop timeout");
                    }
                    else
                    {
                        r.State = "interrupted";                                // main killed early by an external stop (socket/broker shutdown)
                        notes.Add("stopped from outside the broker before its time limit (broker-socket shutdown or systemctl stop); descendants SIGKILLed after the stop timeout");
                    }
                    break;
                case "signal":
                case "core-dump":
                    r.State = "interrupted";
                    notes.Add($"the main process was ended by {r.Signal ?? "a signal"} not initiated by the broker");
                    break;
                case "oom-kill":
                    r.State = "failed";
                    notes.Add("killed by the out-of-memory killer");
                    break;
                default:
                    r.State = "failed";
                    notes.Add("service manager result: " + e.ServiceResult);
                    break;
            }
        }
        if (e.BrokerSocketState is { Length: > 0 } sock && sock != "active") notes.Add("broker socket at exit: " + sock);
    }

    internal static BrokerResponse Terminate(string runId)
    {
        using BrokerLock? held = BrokerLock.TryAcquire(LockWait);
        if (held is null) return BrokerResponse.Fail(ErrorCodes.Busy, "another launch/terminate/cleanup is in progress", runId);
        RunRecord? rec = RunStore.ReadRun(runId);
        if (rec is null) return Status(runId);
        RunStore.MarkTerminate(runId);
        Dictionary<string, string> show = Systemd.Show(rec.Unit, ["LoadState", "ActiveState"]);
        if (show.GetValueOrDefault("LoadState") == "loaded" && show.GetValueOrDefault("ActiveState") is not ("inactive" or "failed"))
        {
            ProcessRunner.Result r = Systemd.Ctl(["stop", rec.Unit], 120_000);
            if (r.ExitCode != 0) Log.Error($"stop {rec.Unit}: {r.Combined}");
        }
        return Status(runId);
    }

    internal static BrokerResponse Cleanup(string runId)
    {
        using BrokerLock? held = BrokerLock.TryAcquire(LockWait);
        if (held is null) return BrokerResponse.Fail(ErrorCodes.Busy, "another launch/terminate/cleanup is in progress", runId);
        string unit = Layout.RunUnit(runId);
        Dictionary<string, string> show = Systemd.Show(unit, ["LoadState", "ActiveState"]);
        bool stopped = false;
        if (show.GetValueOrDefault("LoadState") == "loaded" && show.GetValueOrDefault("ActiveState") is not ("inactive" or "failed"))
        {
            if (RunStore.Exists(runId)) RunStore.MarkTerminate(runId);
            ProcessRunner.Result r = Systemd.Ctl(["stop", unit], 120_000);
            if (r.ExitCode != 0) Log.Error($"stop {unit}: {r.Combined}");
            stopped = true;
        }
        Systemd.Ctl(["reset-failed", unit], 30_000);   // a failed unit that was not collected

        RemoveReport ws = Workspace.Remove(runId);
        RemoveReport rr = RunStore.Exists(runId) ? RunStore.Remove(runId) : new RemoveReport(true, 0, []);
        bool complete = ws.Complete && rr.Complete && !Workspace.Exists(runId) && !RunStore.Exists(runId);
        var c = new JsonObject
        {
            ["stoppedRunningUnit"] = stopped,
            ["workspaceRemoved"] = ws.Complete && !Workspace.Exists(runId),
            ["recordRemoved"] = rr.Complete && !RunStore.Exists(runId),
            ["entriesRemoved"] = ws.Removed + rr.Removed,
            ["failures"] = new JsonArray(ws.Failures.Concat(rr.Failures).Select(f => (JsonNode?)f).ToArray()),
        };
        return complete
            ? new BrokerResponse { Ok = true, RunId = runId, State = "none", Cleanup = c }
            : new BrokerResponse { Ok = false, RunId = runId, ErrorCode = ErrorCodes.Internal, Error = "cleanup incomplete", State = "cleanup_incomplete", Cleanup = c };
    }

    /// <summary>Root-side post-run check of the proof battery's denied targets, independent of
    /// anything the worker reports: no canary in any denied directory; every denied file unchanged;
    /// and — the Issue-3 check — no canary left in any shared world-writable host location
    /// (/dev/shm, /run/lock, /tmp, …), proving the worker's writes stayed inside the sandbox (its
    /// private tmpfs) and never reached the shared host.</summary>
    private static JsonObject Verify(string runId, RunRecord rec)
    {
        string fileCanary = CanaryPrefix + runId + ".txt", dirCanary = CanaryPrefix + runId + ".d";
        bool dirsClean = true, filesUnchanged = true;
        var leaks = new JsonArray();
        foreach ((string category, List<string> dirs) in rec.DenyDirs ?? [])
            foreach (string d in dirs)
                if (LExists(d + "/" + fileCanary) || LExists(d + "/" + dirCanary)) { dirsClean = false; leaks.Add($"{category}: {d}"); }
        var changed = new JsonArray();
        foreach ((string file, FileStamp before) in rec.FileStamps ?? [])
            if (StampOf(file) != before) { filesUnchanged = false; changed.Add(file); }

        // Shared world-writable host locations: a canary here means a write escaped the sandbox.
        bool sharedClean = true;
        var sharedLeaks = new JsonArray();
        foreach (string d in rec.SharedDirs ?? [])
            if (LExists(d + "/" + fileCanary) || LExists(d + "/" + dirCanary)) { sharedClean = false; sharedLeaks.Add(d); leaks.Add($"shared: {d}"); }

        return new JsonObject
        {
            ["by"] = "broker (root), after the run",
            ["deniedDirectoriesChecked"] = rec.DenyDirs?.Values.Sum(v => v.Count) ?? 0,
            ["deniedDirectoriesClean"] = dirsClean,
            ["deniedFilesChecked"] = rec.FileStamps?.Count ?? 0,
            ["deniedFilesUnchanged"] = filesUnchanged,
            ["sharedWritableChecked"] = (rec.SharedDirs?.Count ?? 0),
            ["sharedWritableHostClean"] = sharedClean,
            ["sharedLeaks"] = sharedLeaks,
            ["leaks"] = leaks,
            ["changedFiles"] = changed,
        };
    }

    private static bool LExists(string path) => Libc.StatxAt(Libc.AT_FDCWD, path, Libc.AT_SYMLINK_NOFOLLOW, out _) == 0;

    private static FileStamp? StampOf(string path) =>
        Libc.StatxAt(Libc.AT_FDCWD, path, Libc.AT_SYMLINK_NOFOLLOW, out Libc.Statx st) == 0
            ? new FileStamp(st.Ino, st.Size, st.MtimeSec, st.MtimeNsec)
            : null;
}
