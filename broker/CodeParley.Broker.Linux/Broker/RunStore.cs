using System.Text;
using System.Text.Json;
using CodeParley.Broker.Linux.Host;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Broker;

internal sealed record FileStamp(ulong Ino, ulong Size, long MtimeSec, uint MtimeNsec);

/// <summary>What the broker launched (written by the request handler).</summary>
internal sealed class RunRecord
{
    public string RunId { get; set; } = "";
    public string WorkloadKey { get; set; } = "";
    public string Unit { get; set; } = "";
    public int TimeoutSeconds { get; set; }
    /// <summary>provisioning | started | launch_failed</summary>
    public string State { get; set; } = "provisioning";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public int? MainPid { get; set; }
    public string? InvocationId { get; set; }
    public uint RequestedByUid { get; set; }
    public string? LaunchError { get; set; }
    public Dictionary<string, List<string>>? DenyDirs { get; set; }
    public Dictionary<string, FileStamp>? FileStamps { get; set; }
    public List<string>? SharedDirs { get; set; }
}

/// <summary>How the run ended (written by the root ExecStopPost hook, from the service manager's
/// SERVICE_RESULT/EXIT_CODE/EXIT_STATUS — never from anything the worker wrote).</summary>
internal sealed class ExitRecord
{
    public string ServiceResult { get; set; } = "";
    public string ExitCode { get; set; } = "";
    public string ExitStatus { get; set; } = "";
    public DateTimeOffset RecordedAt { get; set; }
    public bool TerminateRequested { get; set; }
    public string BrokerSocketState { get; set; } = "";

    /// <summary>Identities of any process left in the run's cgroup when the stop hook ran, other than
    /// the hook itself (should be empty: KillMode=control-group empties the cgroup before ExecStopPost).</summary>
    public string[] StragglersAtStop { get; set; } = [];
}

/// <summary>Root-only per-run records under /var/lib/codeparley-broker/runs/&lt;runId&gt;/.</summary>
internal static class RunStore
{
    private const string RunFile = "run.json";
    private const string ExitFile = "exit.json";
    private const string TerminateMarker = "terminate";

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    internal static bool Exists(string runId)
    {
        using Fd runs = Workspace.OpenRunsRoot();
        return SafeFs.TryStatEntry(runs, runId, out _);
    }

    internal static void Create(string runId)
    {
        using Fd runs = Workspace.OpenRunsRoot();
        try { SafeFs.MakeDir(runs, runId, 0b111_000_000); }
        catch (SafeFsException e) when (e.Errno == Libc.EEXIST) { throw new RunExistsException(runId); }
    }

    internal static void WriteRun(RunRecord r) => Write(r.RunId, RunFile, r);
    internal static RunRecord? ReadRun(string runId) => Read<RunRecord>(runId, RunFile);
    internal static void WriteExit(string runId, ExitRecord e) => Write(runId, ExitFile, e);
    internal static ExitRecord? ReadExit(string runId) => Read<ExitRecord>(runId, ExitFile);

    internal static void MarkTerminate(string runId)
    {
        using Fd? dir = OpenRunDir(runId);
        if (dir is null) return;
        SafeFs.WriteFileAtomic(dir, TerminateMarker, Encoding.UTF8.GetBytes(DateTimeOffset.UtcNow.ToString("O")), 0b110_000_000);
    }

    internal static bool TerminateRequested(string runId)
    {
        using Fd? dir = OpenRunDir(runId);
        return dir is not null && SafeFs.TryStatEntry(dir, TerminateMarker, out _);
    }

    internal static RemoveReport Remove(string runId)
    {
        using Fd runs = Workspace.OpenRunsRoot();
        return SafeFs.RemoveTree(runs, runId, TimeSpan.FromMinutes(1));
    }

    private static Fd? OpenRunDir(string runId)
    {
        using Fd runs = Workspace.OpenRunsRoot();
        return SafeFs.OpenBeneath(runs, runId, Libc.O_RDONLY | Libc.O_DIRECTORY);
    }

    private static void Write<T>(string runId, string name, T value)
    {
        using Fd dir = OpenRunDir(runId) ?? throw new InvalidOperationException($"run record directory for '{runId}' is missing");
        SafeFs.WriteFileAtomic(dir, name, JsonSerializer.SerializeToUtf8Bytes(value, Json), 0b110_000_000);
    }

    private static T? Read<T>(string runId, string name) where T : class
    {
        using Fd? dir = OpenRunDir(runId);
        if (dir is null) return null;
        byte[]? b = SafeFs.ReadFileBeneath(dir, name, 4 * 1024 * 1024, out _);
        return b is null ? null : JsonSerializer.Deserialize<T>(b, Json);
    }

    /// <summary>The last lines the worker wrote to stdout/stderr (journald: rate-limited and
    /// size-capped by the journal, so a hostile worker cannot fill the disk through its output).</summary>
    internal static string? WorkerLogTail(string runId, string? invocationId, int lines = 200)
    {
        string journalctl = File.Exists("/usr/bin/journalctl") ? "/usr/bin/journalctl" : "/bin/journalctl";
        try
        {
            Trust.VerifyRootChain(journalctl);
            var args = new List<string> { "--no-pager", "--quiet", "--output=cat", "--lines=" + lines, "_SYSTEMD_UNIT=" + Layout.RunUnit(runId) };
            // A runId can be reused after Cleanup: match this run's invocation only.
            if (invocationId is { Length: 32 } && invocationId.All(char.IsAsciiHexDigit)) args.Add("_SYSTEMD_INVOCATION_ID=" + invocationId);
            ProcessRunner.Result r = ProcessRunner.Run(journalctl, args, timeoutMs: 20_000);
            string text = r.StdOut;
            return text.Length > 64 * 1024 ? "…" + text[^(64 * 1024)..] : text;
        }
        catch (Exception e) { return $"(worker log unavailable: {e.Message})"; }
    }
}

/// <summary>Serializes mutating requests (launch/terminate/cleanup) across handler processes.</summary>
internal sealed class BrokerLock : IDisposable
{
    private readonly Fd _fd;
    private BrokerLock(Fd fd) { _fd = fd; }

    internal static BrokerLock? TryAcquire(TimeSpan wait)
    {
        using Fd state = Workspace.OpenStateDir();
        int fd = Libc.Openat(state.Value, "broker.lock", Libc.O_RDONLY | Libc.O_CREAT | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, 0b110_000_000);
        if (fd < 0) throw new SafeFsException("open broker.lock", Libc.Errno);
        var owned = new Fd(fd);
        DateTime deadline = DateTime.UtcNow + wait;
        while (true)
        {
            if (Libc.flock(fd, Libc.LOCK_EX | Libc.LOCK_NB) == 0) return new BrokerLock(owned);
            int e = Libc.Errno;
            if (e is not (Libc.EAGAIN or Libc.EINTR)) { owned.Dispose(); throw new SafeFsException("flock", e); }
            if (DateTime.UtcNow > deadline) { owned.Dispose(); return null; }
            Thread.Sleep(100);
        }
    }

    public void Dispose() => _fd.Dispose();   // closing the descriptor releases the lock
}
