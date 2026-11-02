using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace CodeParley.Broker.Ipc;

/// <summary>
/// The semantic broker operations (same wire names as the Linux broker, plus Capabilities). No
/// generic/privileged filesystem or process verbs are exposed.
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
    public int Version { get; set; } = BrokerConstants.ProtocolVersion;
    public BrokerOp? Op { get; set; }

    /// <summary>Caller-chosen opaque run identifier (strict charset). The broker derives the workspace from it.</summary>
    public string? RunId { get; set; }

    /// <summary>Allowlisted workload key; selects a fixed deterministic workload, never an arbitrary command.</summary>
    public string? WorkloadKey { get; set; }

    /// <summary>Optional wall-clock limit, at most the workload's and the broker's trusted maximum.</summary>
    public int? TimeoutSeconds { get; set; }
}

internal sealed class BrokerResponse
{
    public int Version { get; set; } = BrokerConstants.ProtocolVersion;
    public bool Ok { get; set; }

    /// <summary>A stable machine code (see <see cref="ErrorCodes"/>); parity with the Linux broker's error behaviour.</summary>
    public string? ErrorCode { get; set; }
    public string? Error { get; set; }

    public string? RunId { get; set; }

    /// <summary>none | starting | running | stopping | exited | timed_out | terminated | interrupted | unclean | failed | lost</summary>
    public string? State { get; set; }
    public int? ExitCode { get; set; }
    public int? Pid { get; set; }

    /// <summary>Identity lines of the processes currently inside the run's lifetime boundary (Job Object).</summary>
    public string[]? Members { get; set; }

    /// <summary>The worker-written result payload (untrusted content), when present.</summary>
    public string? ResultJson { get; set; }

    /// <summary>The worker's captured console output (untrusted diagnostics), when present.</summary>
    public string? WorkerLog { get; set; }

    /// <summary>Broker-side (SYSTEM) post-run checks of the denied targets, independent of the worker.</summary>
    public JsonObject? Verification { get; set; }

    /// <summary>The verified host facts, or the problems that make the host unfit (Capabilities).</summary>
    public JsonObject? Capabilities { get; set; }

    /// <summary>Cleanup completeness report.</summary>
    public JsonObject? Cleanup { get; set; }

    public string[]? Notes { get; set; }

    internal static BrokerResponse Fail(string code, string message, string? runId = null) =>
        new() { Ok = false, ErrorCode = code, Error = message, RunId = runId };
}

/// <summary>Stable machine-readable error codes (mirrors the Linux broker, so the controller routes on one set).</summary>
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
