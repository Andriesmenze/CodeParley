using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using CodeParley.Broker.Interop;
using CodeParley.Broker.Security;
using Microsoft.Win32.SafeHandles;

namespace CodeParley.Broker.Launch;

/// <summary>A live/finished worker run and the OS resources it owns. Disposing terminates the worker
/// tree (Job Object), unloads the profile, destroys the private station, closes tokens, removes the
/// workspace and the per-run git config.</summary>
internal sealed class WorkerRun : IDisposable
{
    internal required string RunId { get; init; }
    internal required string WorkloadKey { get; init; }
    internal bool IsProof { get; init; }
    internal int Pid { get; set; }
    internal int? ExitCode { get; set; }
    internal volatile string State = RunState.Starting;
    internal string? Note { get; set; }
    internal string ResultPath { get; set; } = "";
    internal string LogPath { get; set; } = "";
    internal string GitConfigPath { get; set; } = "";
    internal DateTimeOffset StartedAtUtc { get; set; }
    internal int TimeoutSeconds { get; set; }

    // Trusted lifecycle facts set by the broker (never by the worker).
    internal volatile bool TerminateRequested;
    internal volatile bool TimedOut;
    internal volatile bool StoppedExternally;
    internal bool DescendantsRemained;

    internal IntPtr Process, Thread;
    internal JobObjectOwner? Job;
    internal WindowStationScope? Station;
    internal WorkspaceProvisioner? Workspace;
    internal WorkerToken? Token;
    internal WorkerProfile? Profile;

    // Negative-write-boundary targets captured at launch, for the broker's own post-run verification.
    internal Dictionary<string, List<string>>? DenyDirs;
    internal List<string>? DenyFiles;
    internal Dictionary<string, (long Size, long MtimeTicks)>? FileStamps;

    internal readonly object FinalizeLock = new();
    internal bool Finalized;
    internal RegisteredWaitHandle? WaitReg;
    internal ManualResetEvent? WaitEvent;
    internal Timer? TimeoutTimer;
    private bool _disposed;

    internal int[] JobPids() { try { return Job?.ProcessIds() ?? []; } catch { return []; } }
    internal string[] Members() => Array.ConvertAll(JobPids(), id => id.ToString());

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { TimeoutTimer?.Dispose(); } catch { }
        try { WaitReg?.Unregister(null); } catch { }
        try { WaitEvent?.Dispose(); } catch { }
        try { Job?.Terminate(); } catch { /* best effort */ }
        if (Process != IntPtr.Zero) Native.WaitForSingleObject(Process, 2000);
        if (Thread != IntPtr.Zero) { Native.CloseHandle(Thread); Thread = IntPtr.Zero; }
        if (Process != IntPtr.Zero) { Native.CloseHandle(Process); Process = IntPtr.Zero; }
        try { Station?.Dispose(); } catch { }
        try { Profile?.Dispose(); } catch { }   // unload worker hive (worker is dead by now)
        try { Token?.Dispose(); } catch { }
        try { Job?.Dispose(); } catch { }
        try { Workspace?.Cleanup(); } catch { }
        try { if (GitConfigPath.Length > 0 && File.Exists(GitConfigPath)) File.Delete(GitConfigPath); } catch { }
    }
}

/// <summary>
/// Sequences the privileged launch (credential → dual-SID restricted token → profile + explicit env →
/// handle-safe workspace + standalone clone → private window station → Job Object →
/// CreateProcessAsUser(SUSPENDED) → assign → resume), then owns the run's lifetime autonomously: a
/// wall-clock timer and a main-exit wait drive termination and the terminal-state classification
/// WITHOUT relying on the controller polling. The restricted-token / workspace / Job Object security
/// model from Phase 3.1A is preserved unchanged.
/// </summary>
internal sealed class WorkerLauncher(RunRegistry registry)
{
    private const uint StillActive = 259;

    internal WorkerRun Launch(string runId, string workloadKey)
    {
        if (!BrokerConstants.Workloads.TryGetValue(workloadKey, out WorkloadDef? def))
            throw new InvalidOperationException($"unknown workload '{workloadKey}'");
        return Launch(runId, def, def.DefaultTimeoutSeconds);
    }

    internal WorkerRun Launch(string runId, WorkloadDef def, int timeoutSeconds)
    {
        string account = BrokerConstants.WorkerAccount;
        string accountSid = ((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value;

        WorkerToken? token = null;
        WorkerProfile? profile = null;
        WorkspaceProvisioner? ws = null;
        WindowStationScope? station = null;
        JobObjectOwner? job = null;
        IntPtr envBlock = IntPtr.Zero, hLog = IntPtr.Zero, hNul = IntPtr.Zero;
        var run = new WorkerRun
        {
            RunId = runId, WorkloadKey = def.Key, IsProof = def.IsProof,
            StartedAtUtc = DateTimeOffset.UtcNow, TimeoutSeconds = timeoutSeconds,
        };

        try
        {
            // 1. logon + dual restricting-SID WRITE_RESTRICTED token (UNCHANGED from Phase 3.1A).
            IntPtr pw = WorkerCredential.RetrievePasswordLpwstr();
            try { token = TokenBuilder.LogonAndRestrict(account, pw, accountSid); }
            finally { WorkerCredential.ZeroFreeLpwstr(pw); }

            // 2. handle-safe workspace + standalone clone (hardening #1).
            ws = WorkspaceProvisioner.Create(runId, token.LogonSid);
            string source = WorkloadStager.EnsureSourceRepo();
            string repo = ws.CloneStandalone(HostTools.GitExe, source);

            // Hardening 4B: a per-run git config marking ONLY this exact clone safe (never `*`). Lives
            // in the Users-readable broker dir so the worker can read, but not rewrite, it.
            run.GitConfigPath = WorkspaceProvisioner.WritePerRunGitConfig(runId, repo);

            // 3. worker profile + explicit environment (hardening #3), pinned to the per-run git config.
            profile = WorkerProfile.Load(token.Logon, account);
            Dictionary<string, string> baseEnv = profile.DeriveBaseEnvironment();
            Dictionary<string, string> env = WorkerEnvironment.Compose(baseEnv, account, HostTools.WorkerPathDirs, run.GitConfigPath);
            WorkerEnvironment.AssertWorkerOwned(env);
            envBlock = EnvBlock.Build(env);

            // 4. private, non-interactive station/desktop (hardening #4).
            station = WindowStationScope.CreatePrivate(runId, token.LogonSid);

            // 5. Job Object (kill-on-close, no breakaway).
            job = new JobObjectOwner("cp-job-" + runId);

            // 6. stage workload + negative-write targets; suspended launch → assign → resume (hardening #2).
            DenyTargets? deny = def.IsProof ? WorkloadStager.ComputeDenyTargets() : null;
            if (deny is not null)
            {
                run.DenyDirs = deny.Dirs;
                run.DenyFiles = deny.Files;
                run.FileStamps = deny.Files.ToDictionary(f => f, StampOf);
            }
            (string cmd, string cwd, string resultPath) = WorkloadStager.BuildCommand(def.Key, repo, ws.Path, runId, deny);
            run.ResultPath = resultPath;

            run.LogPath = Path.Combine(ws.Path, "console.log");
            hLog = OpenInheritable(run.LogPath, Native.GENERIC_WRITE, Native.CREATE_ALWAYS);
            hNul = OpenInheritable("NUL", Native.GENERIC_READ, Native.OPEN_EXISTING);

            var si = default(Native.STARTUPINFO);
            si.cb = Marshal.SizeOf<Native.STARTUPINFO>();
            si.lpDesktop = station.Desktop;
            si.dwFlags = (int)Native.STARTF_USESTDHANDLES;
            si.hStdInput = hNul; si.hStdOutput = hLog; si.hStdError = hLog;
            if (!Native.CreateProcessAsUserW(token.Restricted, null, cmd, IntPtr.Zero, IntPtr.Zero, true,
                    Native.CREATE_SUSPENDED | Native.CREATE_UNICODE_ENVIRONMENT | Native.CREATE_NO_WINDOW,
                    envBlock, cwd, ref si, out Native.PROCESS_INFORMATION pi))
                Native.ThrowLastError("CreateProcessAsUser");

            job.Assign(pi.hProcess);                                   // inside the job before any code runs
            if (Native.ResumeThread(pi.hThread) == unchecked((uint)-1)) Native.ThrowLastError("ResumeThread");

            run.Process = pi.hProcess; run.Thread = pi.hThread; run.Pid = pi.dwProcessId;
            run.Job = job; run.Station = station; run.Workspace = ws; run.Token = token; run.Profile = profile;
            run.State = RunState.Running;

            token = null; profile = null; ws = null; station = null; job = null; // ownership -> run
            if (!registry.TryAdd(run)) { run.Dispose(); throw new InvalidOperationException($"duplicate runId '{runId}'"); }

            // Durable record for restart recovery (`lost`), and the autonomous lifetime drivers.
            RunStore.WriteRun(new RunRecord
            {
                RunId = runId, WorkloadKey = def.Key, Pid = run.Pid,
                TimeoutSeconds = timeoutSeconds, StartedAtUtc = run.StartedAtUtc, State = "started",
            });
            ArmLifecycle(run);
            return run;
        }
        catch
        {
            station?.Dispose();
            profile?.Dispose();
            token?.Dispose();
            job?.Dispose();
            ws?.Cleanup();
            try { RunStore.WriteExit(runId, new ExitRecord { State = RunState.Failed, RecordedAtUtc = DateTimeOffset.UtcNow, Note = "launch failed" }); } catch { }
            throw;
        }
        finally
        {
            if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
            if (hLog != IntPtr.Zero) Native.CloseHandle(hLog);
            if (hNul != IntPtr.Zero) Native.CloseHandle(hNul);
        }
    }

    /// <summary>Arm the broker-enforced wall-clock timeout and the main-exit wait (so lifecycle does not
    /// depend on the controller polling).</summary>
    private void ArmLifecycle(WorkerRun run)
    {
        run.WaitEvent = new ManualResetEvent(false) { SafeWaitHandle = new SafeWaitHandle(run.Process, ownsHandle: false) };
        run.WaitReg = ThreadPool.RegisterWaitForSingleObject(run.WaitEvent, (_, _) => OnMainExited(run), null, Timeout.Infinite, executeOnlyOnce: true);
        run.TimeoutTimer = new Timer(_ => OnTimeout(run), null, TimeSpan.FromSeconds(run.TimeoutSeconds), Timeout.InfiniteTimeSpan);
    }

    private void OnMainExited(WorkerRun run) { try { Finalize(run); } catch { /* threadpool: never throw */ } }

    private void OnTimeout(WorkerRun run)
    {
        try
        {
            lock (run.FinalizeLock) { if (run.Finalized) return; run.TimedOut = true; }
            try { run.Job?.Terminate(); } catch { }   // kill the whole tree at the deadline
            Finalize(run);
        }
        catch { /* threadpool: never throw */ }
    }

    /// <summary>Resolve the run's terminal state from trusted broker/OS facts only, once. A natural main
    /// exit waits briefly for descendants to finish; any that remain are force-killed and the run is
    /// `unclean` (success is never inferred from the exit code when descendant cleanup is not established).</summary>
    private void Finalize(WorkerRun run)
    {
        lock (run.FinalizeLock)
        {
            if (run.Finalized) return;

            if (run.Process != IntPtr.Zero && Native.GetExitCodeProcess(run.Process, out uint code) && code != StillActive)
                run.ExitCode = (int)code;

            bool deliberateStop = run.TerminateRequested || run.TimedOut || run.StoppedExternally;
            if (!deliberateStop)
            {
                if (!WaitDescendantsGone(run, TimeSpan.FromSeconds(BrokerConstants.StopGraceSeconds)))
                {
                    run.DescendantsRemained = true;
                    try { run.Job?.Terminate(); } catch { }   // force-kill the leaked descendants
                }
            }

            var facts = new TerminalFacts(
                LaunchFailed: false, Lost: false,
                TerminateRequested: run.TerminateRequested, TimedOut: run.TimedOut,
                StoppedExternally: run.StoppedExternally, DescendantsRemained: run.DescendantsRemained,
                ExitCode: run.ExitCode);
            TerminalVerdict v = TerminalClassifier.Classify(facts);
            run.State = v.State;
            run.ExitCode = v.ExitCode;
            run.Note = v.Note;
            try
            {
                RunStore.WriteExit(run.RunId, new ExitRecord
                {
                    State = v.State, ExitCode = v.ExitCode, RecordedAtUtc = DateTimeOffset.UtcNow,
                    TerminateRequested = run.TerminateRequested, TimedOut = run.TimedOut,
                    StoppedExternally = run.StoppedExternally, DescendantsRemained = run.DescendantsRemained, Note = v.Note,
                });
            }
            catch { /* durable record is best-effort; in-memory state is authoritative while the broker lives */ }
            run.Finalized = true;
        }
    }

    /// <summary>Poll the Job Object for any live descendant (anything other than the already-exited main
    /// PID, which can linger in the list while the broker still holds its handle).</summary>
    private static bool WaitDescendantsGone(WorkerRun run, TimeSpan grace)
    {
        DateTime deadline = DateTime.UtcNow + grace;
        while (true)
        {
            if (!run.JobPids().Any(pid => pid != run.Pid)) return true;
            if (DateTime.UtcNow >= deadline) return false;
            Thread.Sleep(150);
        }
    }

    /// <summary>Make sure a run's terminal state is settled before it is counted for admission: if the
    /// main process has exited but the wait callback has not run yet, finalize now.</summary>
    internal void Refresh(WorkerRun run)
    {
        if (run.Finalized) return;
        if (run.Process != IntPtr.Zero && Native.WaitForSingleObject(run.Process, 0) == 0) Finalize(run);
    }

    internal void UpdateStatus(WorkerRun run) => Refresh(run);

    internal static string? ReadResult(WorkerRun run)
    {
        try { return run.ResultPath.Length > 0 && File.Exists(run.ResultPath) ? File.ReadAllText(run.ResultPath) : null; }
        catch { return null; }
    }

    internal static string? ReadLog(WorkerRun run)
    {
        try { return run.LogPath.Length > 0 && File.Exists(run.LogPath) ? File.ReadAllText(run.LogPath) : null; }
        catch { return null; }
    }

    /// <summary>Broker-side (SYSTEM) post-run verification of the denied targets, independent of the
    /// worker's own report: no canary left in any denied directory, and every denied file unchanged.</summary>
    internal static JsonObject Verify(WorkerRun run)
    {
        string fileCanary = "cp_probe_" + run.RunId + ".txt", dirCanary = "cp_probe_" + run.RunId + ".d";
        bool dirsClean = true; var leaks = new JsonArray();
        int dirCount = 0;
        foreach ((string category, List<string> dirs) in run.DenyDirs ?? [])
            foreach (string d in dirs)
            {
                dirCount++;
                if (File.Exists(Path.Combine(d, fileCanary)) || Directory.Exists(Path.Combine(d, dirCanary)))
                { dirsClean = false; leaks.Add($"{category}: {d}"); }
            }
        bool filesUnchanged = true; var changed = new JsonArray();
        foreach ((string file, (long Size, long MtimeTicks) before) in run.FileStamps ?? [])
            if (StampOf(file) != before) { filesUnchanged = false; changed.Add(file); }

        return new JsonObject
        {
            ["by"] = "broker (SYSTEM), after the run",
            ["deniedDirectoriesChecked"] = dirCount,
            ["deniedDirectoriesClean"] = dirsClean,
            ["deniedFilesChecked"] = run.FileStamps?.Count ?? 0,
            ["deniedFilesUnchanged"] = filesUnchanged,
            ["leaks"] = leaks,
            ["changedFiles"] = changed,
        };
    }

    private static (long Size, long MtimeTicks) StampOf(string path)
    {
        try { var fi = new FileInfo(path); return fi.Exists ? (fi.Length, fi.LastWriteTimeUtc.Ticks) : (0, 0); }
        catch { return (0, 0); }
    }

    /// <summary>Broker-requested stop: record intent, kill the whole tree, settle the terminal state.</summary>
    internal void Terminate(WorkerRun run)
    {
        lock (run.FinalizeLock) { if (!run.Finalized) run.TerminateRequested = true; }
        try { run.Job?.Terminate(); } catch { }
        Finalize(run);
    }

    /// <summary>External stop (broker/host shutdown) of a still-active run → `interrupted`.</summary>
    internal void Interrupt(WorkerRun run)
    {
        lock (run.FinalizeLock) { if (!run.Finalized) run.StoppedExternally = true; }
        try { run.Job?.Terminate(); } catch { }
        Finalize(run);
    }

    internal void Cleanup(WorkerRun run)
    {
        run.Dispose();
        registry.Remove(run.RunId);
        RunStore.Remove(run.RunId);
    }

    private static IntPtr OpenInheritable(string path, uint access, uint disposition)
    {
        var sa = new Native.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<Native.SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = IntPtr.Zero,
            bInheritHandle = 1,
        };
        IntPtr pSa = Marshal.AllocHGlobal(Marshal.SizeOf<Native.SECURITY_ATTRIBUTES>());
        try
        {
            Marshal.StructureToPtr(sa, pSa, false);
            IntPtr h = Native.CreateFileW(path, access, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE,
                pSa, disposition, Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (h == Native.INVALID_HANDLE_VALUE) Native.ThrowLastError($"CreateFile('{path}')");
            return h;
        }
        finally { Marshal.FreeHGlobal(pSa); }
    }
}
