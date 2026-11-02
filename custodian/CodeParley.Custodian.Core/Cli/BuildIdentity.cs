using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 6 Increment 1: the custodian's version identity, printed by the `version` verb of both hosts as one JSON line —
/// the release version (custodian/Directory.Build.props, pinned to package.json), the build (the informational version
/// the SDK stamps with the source commit), the IPC protocol version the engine must speak, and the host. It reads only
/// the executable's own metadata; it creates and consults no authority.
/// </summary>
internal static class BuildIdentity
{
    internal static JsonObject Of(string host)
    {
        Assembly a = Assembly.GetEntryAssembly() ?? typeof(BuildIdentity).Assembly;
        string informational = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        int plus = informational.IndexOf('+');
        return new JsonObject
        {
            ["product"] = "CodeParley Custodian",
            ["version"] = plus < 0 ? informational : informational[..plus],
            ["build"] = plus < 0 ? null : informational[(plus + 1)..],
            ["protocol"] = CustodianConstants.ProtocolVersion,
            ["host"] = host,
            ["framework"] = RuntimeInformation.FrameworkDescription,
            ["architecture"] = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
        };
    }

    internal static int Print(string host)
    {
        Console.WriteLine(Of(host).ToJsonString());
        return 0;
    }
}
