using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace CodeParley.Broker.Linux.Broker;

/// <summary>
/// The semantic broker verbs (same wire names as the Windows broker, plus Capabilities). There is
/// no generic privileged filesystem, process, user or path operation.
/// </summary>
internal enum BrokerOp
{
    Ping,
    Capabilities,
    LaunchWorkload,
    GetStatus,
    Terminate,
    Cleanup,
}

/// <summary>One request per connection. Unknown members are rejected (no hidden parameters).</summary>
internal sealed class BrokerRequest
{
    public int Version { get; set; }
    public BrokerOp? Op { get; set; }

    /// <summary>Caller-chosen opaque run identifier (strict charset); the broker derives every path and unit name from it.</summary>
    public string? RunId { get; set; }

    /// <summary>Allowlisted workload key; selects a fixed broker-owned workload, never an arbitrary command.</summary>
    public string? WorkloadKey { get; set; }

    /// <summary>Optional wall-clock limit, at most the workload's and the broker's trusted maximum.</summary>
    public int? TimeoutSeconds { get; set; }
}

internal sealed class BrokerResponse
{
    public int Version { get; set; } = Layout.ProtocolVersion;
    public bool Ok { get; set; }
    public string? ErrorCode { get; set; }
    public string? Error { get; set; }

    public string? RunId { get; set; }

    /// <summary>none | starting | running | stopping | exited | timed_out | terminated | interrupted | failed | lost</summary>
    public string? State { get; set; }
    public int? ExitCode { get; set; }
    public string? Signal { get; set; }

    /// <summary>The service manager's raw result for the run (e.g. success, exit-code, timeout).</summary>
    public string? Result { get; set; }
    public int? Pid { get; set; }

    /// <summary>Identity lines of the processes currently inside the run's lifetime boundary (cgroup).</summary>
    public string[]? Members { get; set; }

    /// <summary>The worker-written result payload (untrusted content, read without following links).</summary>
    public string? ResultJson { get; set; }

    /// <summary>The tail of the worker's stdout/stderr (untrusted content).</summary>
    public string? WorkerLog { get; set; }

    /// <summary>Broker-side (root) post-run checks of the denied targets, independent of the worker.</summary>
    public JsonObject? Verification { get; set; }

    public JsonObject? Capabilities { get; set; }
    public JsonObject? Cleanup { get; set; }
    public string[]? Notes { get; set; }

    internal static BrokerResponse Fail(string code, string message, string? runId = null) =>
        new() { Ok = false, ErrorCode = code, Error = message, RunId = runId };
}

internal static class ErrorCodes
{
    internal const string Unauthorized = "unauthorized";
    internal const string UnsupportedVersion = "unsupported_version";
    internal const string MalformedRequest = "malformed_request";
    internal const string InvalidRunId = "invalid_run_id";
    internal const string UnknownWorkload = "unknown_workload";
    internal const string InvalidTimeout = "invalid_timeout";
    internal const string RunExists = "run_exists";
    internal const string CapacityExceeded = "capacity_exceeded";
    internal const string HostUnverified = "host_unverified";
    internal const string LaunchFailed = "launch_failed";
    internal const string Busy = "busy";
    internal const string Internal = "internal";
}

internal static class ProtocolJson
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
        MaxDepth = 8,
    };

    internal static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    internal static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}
