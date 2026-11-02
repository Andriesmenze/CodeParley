using CodeParley.Broker.Launch;
using CodeParley.Broker.Security;

namespace CodeParley.Broker.Ipc;

/// <summary>
/// Handles validated broker operations over the launcher + registry. The only semantic verbs are
/// Ping/Capabilities/LaunchWorkload/GetStatus/Terminate/Cleanup; every request is validated (runId
/// charset, workload allowlist, timeout bounds) and the broker derives all paths/identities itself.
/// Admission enforces the Phase-3 single-active-worker invariant from trusted OS state, under a lock.
/// </summary>
internal sealed class BrokerCore : IDisposable
{
    private readonly RunRegistry _registry = new();
    private readonly WorkerLauncher _launcher;
    private readonly object _admissionGate = new();
    private bool _disposed;

    internal BrokerCore()
    {
        _launcher = new WorkerLauncher(_registry);
        WorkspaceProvisioner.EnsureTrustedRoots();
        RunStore.EnsureRoot();
        ReconcileOnStartup();
    }

    /// <summary>After a broker/host restart the kill-on-close Job Objects are already gone (no worker
    /// survives), so any durable record still marked "started" is a run whose outcome was never
    /// recorded: report it `lost` and remove its stale workspace before any new launch. This prevents
    /// stale state from being mistaken for an active worker or from blocking reuse after Cleanup.</summary>
    private void ReconcileOnStartup()
    {
        foreach (string runId in RunStore.AllRunIds())
        {
            RunRecord? rec = RunStore.ReadRun(runId);
            if (rec is null) continue;
            if (RunStore.ReadExit(runId) is not null) continue;          // already has a recorded outcome
            if (rec.State == "started")
            {
                RunStore.WriteExit(runId, new ExitRecord { State = RunState.Lost, RecordedAtUtc = DateTimeOffset.UtcNow, Note = "broker/host restarted mid-run; no recorded outcome" });
                TryRemoveStaleWorkspace(runId);
            }
        }
    }

    private static void TryRemoveStaleWorkspace(string runId)
    {
        try { string ws = Path.Combine(BrokerConstants.TrustedWorkspaceRoot, runId); if (Directory.Exists(ws)) Directory.Delete(ws, recursive: true); } catch { }
        try { string gc = BrokerConstants.WorkerGitConfig(runId); if (File.Exists(gc)) File.Delete(gc); } catch { }
    }

    internal BrokerResponse Handle(BrokerRequest request)
    {
        if (request.Version != BrokerConstants.ProtocolVersion)
            return BrokerResponse.Fail(ErrorCodes.UnsupportedVersion, $"unsupported protocol version {request.Version} (expected {BrokerConstants.ProtocolVersion})");
        if (request.Op is null)
            return BrokerResponse.Fail(ErrorCodes.MalformedRequest, "op is required");

        try
        {
            return request.Op.Value switch
            {
                BrokerOp.Ping => new BrokerResponse { Ok = true, State = "ready" },
                BrokerOp.Capabilities => CapabilitiesResponse(),
                BrokerOp.LaunchWorkload => Launch(request),
                BrokerOp.GetStatus => Status(request),
                BrokerOp.Terminate => TerminateRun(request),
                BrokerOp.Cleanup => CleanupRun(request),
                _ => BrokerResponse.Fail(ErrorCodes.MalformedRequest, "unknown operation"),
            };
        }
        catch (Exception e)
        {
            return BrokerResponse.Fail(ErrorCodes.Internal, e.Message);
        }
    }

    private static BrokerResponse CapabilitiesResponse()
    {
        WindowsHostCheck.Report r = WindowsHostCheck.Verify();
        return new BrokerResponse { Ok = true, Capabilities = r.Facts };
    }

    private BrokerResponse Launch(BrokerRequest req)
    {
        if (!Validation.IsValidRunId(req.RunId)) return BrokerResponse.Fail(ErrorCodes.InvalidRunId, "runId must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$");
        if (req.WorkloadKey is null || !BrokerConstants.Workloads.TryGetValue(req.WorkloadKey, out WorkloadDef? def))
            return BrokerResponse.Fail(ErrorCodes.UnknownWorkload, "workloadKey is not an allowlisted workload", req.RunId);
        int max = Math.Min(def.MaxTimeoutSeconds, BrokerConstants.MaxTimeoutSeconds);
        int timeout = req.TimeoutSeconds ?? Math.Min(def.DefaultTimeoutSeconds, max);
        if (timeout < BrokerConstants.MinTimeoutSeconds || timeout > max)
            return BrokerResponse.Fail(ErrorCodes.InvalidTimeout, $"timeoutSeconds must be {BrokerConstants.MinTimeoutSeconds}..{max}", req.RunId);

        // Fail closed: the host must verify before any worker is launched.
        WindowsHostCheck.Report host = WindowsHostCheck.Verify();
        if (!host.Verified) return BrokerResponse.Fail(ErrorCodes.HostUnverified, string.Join("; ", host.Problems), req.RunId);

        lock (_admissionGate)
        {
            string runId = req.RunId!;

            // Single active worker (Phase 3): reject while any run is still active, decided from trusted
            // OS state (process-exit + Job Object membership), refreshed now — not from stale records
            // and not from controller scheduling.
            var active = new List<string>();
            foreach (WorkerRun r in _registry.All)
            {
                _launcher.Refresh(r);
                if (!r.Finalized) active.Add(r.RunId);
            }
            if (active.Count >= BrokerConstants.MaxConcurrentRuns)
                return BrokerResponse.Fail(ErrorCodes.CapacityExceeded,
                    $"a worker run is already active ({string.Join(",", active)}); Phase 3 allows one active worker at a time", runId);

            // A runId whose registry entry, durable record or workspace still exists must be Cleaned up first.
            if (_registry.Get(runId) is not null || RunStore.Exists(runId) || Directory.Exists(Path.Combine(BrokerConstants.TrustedWorkspaceRoot, runId)))
                return BrokerResponse.Fail(ErrorCodes.RunExists, $"run '{runId}' already exists (Cleanup it first)", runId);

            try
            {
                WorkerRun run = _launcher.Launch(runId, def, timeout);
                return new BrokerResponse { Ok = true, RunId = run.RunId, State = run.State, Pid = run.Pid };
            }
            catch (Exception e)
            {
                return BrokerResponse.Fail(ErrorCodes.LaunchFailed, e.Message, runId);
            }
        }
    }

    private BrokerResponse Status(BrokerRequest req)
    {
        if (!Validation.IsValidRunId(req.RunId)) return BrokerResponse.Fail(ErrorCodes.InvalidRunId, "invalid runId");
        string runId = req.RunId!;
        WorkerRun? run = _registry.Get(runId);
        if (run is null)
        {
            // Not live in this broker instance: consult the durable record (recovery / lost).
            ExitRecord? exit = RunStore.ReadExit(runId);
            if (exit is not null) return new BrokerResponse { Ok = true, RunId = runId, State = exit.State, ExitCode = exit.ExitCode, Notes = exit.Note is null ? null : [exit.Note] };
            RunRecord? rec = RunStore.ReadRun(runId);
            if (rec is not null && rec.State == "started") return new BrokerResponse { Ok = true, RunId = runId, State = RunState.Lost, Notes = ["a run record exists without an outcome (broker/host restart)"] };
            return new BrokerResponse { Ok = true, RunId = runId, State = RunState.None };
        }

        _launcher.Refresh(run);
        bool terminal = RunState.IsTerminal(run.State);
        return new BrokerResponse
        {
            Ok = true,
            RunId = run.RunId,
            State = run.State,
            Pid = run.Pid,
            ExitCode = run.ExitCode,
            Members = run.Members(),
            Notes = run.Note is null ? null : [run.Note],
            ResultJson = terminal ? WorkerLauncher.ReadResult(run) : null,
            WorkerLog = terminal ? WorkerLauncher.ReadLog(run) : null,
            Verification = terminal && run.IsProof && run.DenyDirs is not null ? WorkerLauncher.Verify(run) : null,
        };
    }

    private BrokerResponse TerminateRun(BrokerRequest req)
    {
        if (!Validation.IsValidRunId(req.RunId)) return BrokerResponse.Fail(ErrorCodes.InvalidRunId, "invalid runId");
        WorkerRun? run = _registry.Get(req.RunId!);
        if (run is null) return Status(req);
        _launcher.Terminate(run);
        return Status(req);
    }

    private BrokerResponse CleanupRun(BrokerRequest req)
    {
        if (!Validation.IsValidRunId(req.RunId)) return BrokerResponse.Fail(ErrorCodes.InvalidRunId, "invalid runId");
        string runId = req.RunId!;
        WorkerRun? run = _registry.Get(runId);
        if (run is not null) _launcher.Cleanup(run);
        else { TryRemoveStaleWorkspace(runId); RunStore.Remove(runId); }
        bool complete = _registry.Get(runId) is null && !RunStore.Exists(runId) && !Directory.Exists(Path.Combine(BrokerConstants.TrustedWorkspaceRoot, runId));
        return new BrokerResponse { Ok = complete, RunId = runId, State = RunState.None, ErrorCode = complete ? null : ErrorCodes.Internal, Error = complete ? null : "cleanup incomplete" };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Broker shutdown: stop every still-active run (records `interrupted`) and release its resources.
        foreach (WorkerRun r in _registry.All)
        {
            try { if (!r.Finalized) _launcher.Interrupt(r); } catch { }
            try { r.Dispose(); } catch { }
        }
    }
}
