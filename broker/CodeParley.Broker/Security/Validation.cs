using System.Text.RegularExpressions;

namespace CodeParley.Broker.Security;

/// <summary>
/// Request-shape validation (hardening #1, the non-filesystem half). Path/reparse/TOCTOU-safe
/// workspace handling is enforced separately by handle in the workspace provisioner.
/// </summary>
internal static partial class Validation
{
    // runId: starts alphanumeric; alphanumeric/underscore/hyphen; 8..64 chars; no separators, no "..".
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")]
    private static partial Regex RunIdPattern();

    internal static bool IsValidRunId(string? runId) => runId is not null && RunIdPattern().IsMatch(runId);

    internal static bool IsValidWorkload(string? workloadKey) =>
        workloadKey is not null && BrokerConstants.Workloads.ContainsKey(workloadKey);
}
