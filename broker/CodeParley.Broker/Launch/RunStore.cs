using System.Text.Json;

namespace CodeParley.Broker.Launch;

/// <summary>What the broker launched (written at launch, under the trusted runs root).</summary>
internal sealed class RunRecord
{
    public string RunId { get; set; } = "";
    public string WorkloadKey { get; set; } = "";
    public int Pid { get; set; }
    public int TimeoutSeconds { get; set; }
    public DateTimeOffset StartedAtUtc { get; set; }
    /// <summary>started | launch_failed</summary>
    public string State { get; set; } = "started";
    public string? LaunchError { get; set; }
    public string? ControllerSid { get; set; }
}

/// <summary>How a run ended (written by the broker when it finalizes the run, from its own and the
/// OS's facts — never from anything the worker wrote).</summary>
internal sealed class ExitRecord
{
    /// <summary>A terminal <see cref="RunState"/>.</summary>
    public string State { get; set; } = "";
    public int? ExitCode { get; set; }
    public DateTimeOffset RecordedAtUtc { get; set; }
    public bool TerminateRequested { get; set; }
    public bool TimedOut { get; set; }
    public bool StoppedExternally { get; set; }
    public bool DescendantsRemained { get; set; }
    public string? Note { get; set; }
}

/// <summary>
/// The durable per-run registry under <see cref="BrokerConstants.RunsRoot"/> (SYSTEM/Administrators
/// only, inherited from the trusted state root). It exists so that after a broker/host restart — which,
/// because the Job Object is kill-on-close, has already killed every worker tree — a run that was
/// in flight is reported `lost` rather than silently forgotten, and its stale workspace is cleaned
/// up before the next launch. It never makes a dead run look active.
/// </summary>
internal static class RunStore
{
    private const string RunFile = "run.json";
    private const string ExitFile = "exit.json";

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    internal static void EnsureRoot() => Directory.CreateDirectory(BrokerConstants.RunsRoot);

    private static string Dir(string runId) => Path.Combine(BrokerConstants.RunsRoot, runId);

    internal static bool Exists(string runId) => Directory.Exists(Dir(runId));

    internal static void Create(string runId) => Directory.CreateDirectory(Dir(runId));

    internal static void WriteRun(RunRecord r)
    {
        Create(r.RunId);
        File.WriteAllText(Path.Combine(Dir(r.RunId), RunFile), JsonSerializer.Serialize(r, Json));
    }

    internal static RunRecord? ReadRun(string runId) => Read<RunRecord>(Path.Combine(Dir(runId), RunFile));
    internal static void WriteExit(string runId, ExitRecord e) => File.WriteAllText(Path.Combine(Dir(runId), ExitFile), JsonSerializer.Serialize(e, Json));
    internal static ExitRecord? ReadExit(string runId) => Read<ExitRecord>(Path.Combine(Dir(runId), ExitFile));

    internal static void Remove(string runId)
    {
        try { if (Directory.Exists(Dir(runId))) Directory.Delete(Dir(runId), recursive: true); }
        catch { /* best effort; the broker runs as SYSTEM */ }
    }

    internal static IReadOnlyList<string> AllRunIds()
    {
        try { return Directory.Exists(BrokerConstants.RunsRoot) ? Directory.GetDirectories(BrokerConstants.RunsRoot).Select(Path.GetFileName).Where(n => n is not null).Select(n => n!).ToArray() : []; }
        catch { return []; }
    }

    private static T? Read<T>(string path) where T : class
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json) : null; }
        catch { return null; }
    }
}
