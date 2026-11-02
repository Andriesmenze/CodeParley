using System.Text.Json;
using CodeParley.Broker.Linux;
using CodeParley.Broker.Linux.Broker;
using CodeParley.Broker.Linux.Host;
using CodeParley.Broker.Linux.Native;

// CodeParley Broker for Linux. Verbs:
//   handle                 one socket-activated request (codeparley-broker@.service, stdin = connection)
//   record-exit <runId>    the root ExecStopPost hook of a worker unit: record the exit, relock the workspace
//   capabilities           print the verified host capability report (operator diagnostic, root)
//   selftest-fs            descriptor-relative filesystem self-test (any user; uses a private temp dir)
//   version
try { Libc.EnsureSupportedArchitecture(); }
catch (PlatformNotSupportedException e) { Console.Error.WriteLine(e.Message); return 64; }

string verb = args.Length > 0 ? args[0] : "";
switch (verb)
{
    case "handle":
        return Handler.Serve();
    case "record-exit":
        return RecordExit.Run(args);
    case "capabilities":
        try
        {
            HostCheck.Report report = HostCheck.Verify(BrokerSettings.Load());
            Console.WriteLine(report.Facts.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            return report.Verified ? 0 : 3;
        }
        catch (Exception e) { Console.Error.WriteLine("capabilities: " + e.Message); return 1; }
    case "selftest-fs":
        return SelfTest.RunFs(args.Skip(1).ToArray());
    case "version":
        Console.WriteLine($"codeparley-broker (linux) protocol {Layout.ProtocolVersion}");
        return 0;
    default:
        Console.Error.WriteLine("usage: codeparley-broker handle | record-exit <runId> | capabilities | selftest-fs [--force-walk] | version");
        return 64;
}

/// <summary>
/// ExecStopPost=+ hook (root, started by PID 1 after every process of the run is gone). It trusts only
/// the service manager's SERVICE_RESULT / EXIT_CODE / EXIT_STATUS (passed through `env -i`), records
/// them, and relocks the workspace so the worker identity can no longer reach it. It always exits 0
/// so it can never wedge the unit's stop sequence.
/// </summary>
internal static class RecordExit
{
    internal static int Run(string[] args)
    {
        try { Directory.SetCurrentDirectory("/"); } catch { /* best effort */ }
        Libc.umask(0b000_111_111);
        if (Libc.geteuid() != 0) { Log.Error("record-exit must run as root"); return 0; }
        if (args.Length < 2 || !RunOps.IsValidRunId(args[1])) { Log.Error("record-exit: invalid runId"); return 0; }
        string runId = args[1];

        var exit = new ExitRecord
        {
            ServiceResult = Clean(Environment.GetEnvironmentVariable("SERVICE_RESULT")),
            ExitCode = Clean(Environment.GetEnvironmentVariable("EXIT_CODE")),
            ExitStatus = Clean(Environment.GetEnvironmentVariable("EXIT_STATUS")),
            RecordedAt = DateTimeOffset.UtcNow,
        };
        try { exit.TerminateRequested = RunStore.TerminateRequested(runId); } catch (Exception e) { Log.Error("record-exit marker: " + e.Message); }
        try { exit.BrokerSocketState = Clean(Systemd.IsActive(Layout.SocketUnit)); } catch (Exception e) { Log.Error("record-exit socket state: " + e.Message); }
        try { exit.StragglersAtStop = StragglersInOwnCgroup(); } catch (Exception e) { Log.Error("record-exit straggler scan: " + e.Message); }
        // The workspace is relocked by the broker handler (GetStatus/Cleanup) and by RelockOrphans on
        // the next launch — NOT here: this hook runs inside the worker unit's sandbox, whose
        // ProtectSystem=strict makes /var/lib read-only, so a chmod here would fail.
        try { RunStore.WriteExit(runId, exit); } catch (Exception e) { Log.Error("record-exit write: " + e.Message); }
        Log.Info($"run {runId} ended: result={exit.ServiceResult} code={exit.ExitCode} status={exit.ExitStatus} terminate={exit.TerminateRequested} stragglers={exit.StragglersAtStop.Length}");
        return 0;
    }

    private static string Clean(string? v) =>
        new((v ?? "").Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_').Take(32).ToArray());

    /// <summary>Processes still in this hook's own cgroup (= the run's cgroup; ExecStopPost runs inside
    /// it) other than this hook and its parent. KillMode=control-group should have emptied it, so a
    /// non-empty result means the host did not cleanly contain the worker tree.</summary>
    private static string[] StragglersInOwnCgroup()
    {
        string? line = File.ReadLines("/proc/self/cgroup").FirstOrDefault();
        // cgroup v2: "0::/path"
        int c = line?.LastIndexOf("::", StringComparison.Ordinal) ?? -1;
        if (line is null || c < 0) return [];
        string path = line[(c + 2)..];
        int self = Environment.ProcessId;
        int parent = ParentPid(self);
        return Systemd.CgroupPids(path)
            .Where(pid => pid != self && pid != parent)
            .Select(Systemd.ProcessIdentity).Where(x => x is not null).Select(x => x!)
            .ToArray();
    }

    private static int ParentPid(int pid)
    {
        try
        {
            string stat = File.ReadAllText($"/proc/{pid}/stat");
            int close = stat.LastIndexOf(')');
            return close >= 0 ? int.Parse(stat[(close + 2)..].Split(' ')[1]) : 0;
        }
        catch (Exception e) when (e is IOException or FormatException) { return 0; }
    }
}
