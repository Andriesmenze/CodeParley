using System.Diagnostics;
using System.Security.Principal;
using CodeParley.Broker.Launch;
using CodeParley.Broker.Security;

namespace CodeParley.Broker.Cli;

/// <summary>
/// Operator/dev command verbs (run elevated / as SYSTEM). These are the administrative,
/// credential-bearing entry points kept out of the semantic IPC surface.
/// </summary>
internal static class BrokerCli
{
    /// <summary>Lock the trusted roots, ensure the worker account + random password + LSA secret, and
    /// set the explicitly trusted controller SID (hardening 4A). Without <c>--controller &lt;account|SID&gt;</c>
    /// and no existing config, it STOPS for operator input rather than defaulting to any administrator.</summary>
    internal static int Provision(string[] args)
    {
        try
        {
            string? controller = GetArg(args, "--controller");
            WorkspaceProvisioner.EnsureTrustedRoots();
            RunStore.EnsureRoot();
            WorkerCredential.Provision();

            if (controller is not null)
            {
                SecurityIdentifier sid = BrokerConfig.ResolveControllerSid(controller);
                BrokerConfig.CreateFor(sid, controller).Save();
                Console.WriteLine($"controller SID set to {sid.Value} ({controller})");
            }
            else if (!File.Exists(BrokerConstants.ConfigPath))
            {
                Console.Error.WriteLine(
                    "no controller configured. Pass --controller <account|SID> (e.g. --controller DESKTOP\\\\operator). " +
                    "The broker authorizes exactly this SID and does NOT default to all administrators, so it will not " +
                    "serve any caller until a specific controller SID is set.");
                return 3;
            }

            Console.WriteLine($"provisioned: worker account '{BrokerConstants.WorkerAccount}', LSA secret, trusted roots locked, controller SID set");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("provision failed: " + e.Message); return 1; }
    }

    /// <summary>Remove the LSA secret, the worker account, and the trusted controller config.</summary>
    internal static int Deprovision(string[] args)
    {
        try
        {
            WorkerCredential.Deprovision();
            try { if (File.Exists(BrokerConstants.ConfigPath)) File.Delete(BrokerConstants.ConfigPath); } catch { }
            Console.WriteLine("deprovisioned");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("deprovision failed: " + e.Message); return 1; }
    }

    /// <summary>Register this executable as a LocalSystem Windows service (manual start).</summary>
    internal static int Install(string[] args)
    {
        string exe = Environment.ProcessPath ?? "";
        if (exe.Length == 0) { Console.Error.WriteLine("cannot resolve the broker executable path"); return 1; }
        int rc = Sc($"create {BrokerConstants.ServiceName} binPath= \"{exe}\" start= demand obj= LocalSystem DisplayName= \"{BrokerConstants.ServiceDisplayName}\"");
        if (rc == 0) Console.WriteLine($"installed service '{BrokerConstants.ServiceName}' (LocalSystem, manual) -> {exe}");
        return rc;
    }

    /// <summary>Stop and remove the Windows service.</summary>
    internal static int Uninstall(string[] args)
    {
        Sc($"stop {BrokerConstants.ServiceName}");
        int rc = Sc($"delete {BrokerConstants.ServiceName}");
        if (rc == 0) Console.WriteLine($"removed service '{BrokerConstants.ServiceName}'");
        return rc;
    }

    /// <summary>Print the host capability report (verified facts, or the problems that fail it closed).
    /// Fully verified only when run as the LocalSystem service identity.</summary>
    internal static int Capabilities(string[] args)
    {
        WindowsHostCheck.Report r = WindowsHostCheck.Verify();
        Console.WriteLine(r.Facts.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return r.Verified ? 0 : 4;
    }

    /// <summary>Deterministic, NON-privileged self-test of the terminal-state classifier: it checks that
    /// trusted facts map to the documented states with the right precedence, so the mapping can be
    /// verified without elevation or a live worker. Prints each case and a PASS/FAIL summary.</summary>
    internal static int SelfTestClassify(string[] args)
    {
        (string Name, TerminalFacts Facts, string State, int? Code)[] cases =
        [
            ("launch failed",                 new(LaunchFailed: true, false, false, false, false, false, null), RunState.Failed, null),
            ("lost (restart)",                new(false, Lost: true, false, false, false, false, null),          RunState.Lost, null),
            ("broker terminate",              new(false, false, TerminateRequested: true, false, false, false, null), RunState.Terminated, null),
            ("execution timeout",             new(false, false, false, TimedOut: true, false, false, null),      RunState.TimedOut, null),
            ("external stop (shutdown)",      new(false, false, false, false, StoppedExternally: true, false, null), RunState.Interrupted, null),
            ("descendants leaked, exit 0",    new(false, false, false, false, false, DescendantsRemained: true, 0), RunState.Unclean, 0),
            ("descendants leaked, exit 5",    new(false, false, false, false, false, DescendantsRemained: true, 5), RunState.Unclean, 5),
            ("clean exit 0",                  new(false, false, false, false, false, false, 0),                  RunState.Exited, 0),
            ("clean non-zero exit 3",         new(false, false, false, false, false, false, 3),                  RunState.Exited, 3),
            // precedence: a deliberate stop wins over a straggler flag (terminate kills the whole job).
            ("terminate + descendants",       new(false, false, true, false, false, true, 0),                    RunState.Terminated, null),
            ("timeout + descendants",         new(false, false, false, true, false, true, 0),                    RunState.TimedOut, null),
            ("terminate beats timeout",       new(false, false, true, true, false, false, null),                 RunState.Terminated, null),
            ("lost beats everything else",    new(false, true, true, true, true, true, 9),                       RunState.Lost, null),
            ("failed beats lost",             new(true, true, false, false, false, false, null),                 RunState.Failed, null),
        ];

        int failed = 0;
        foreach ((string name, TerminalFacts facts, string expectState, int? expectCode) in cases)
        {
            TerminalVerdict v = TerminalClassifier.Classify(facts);
            bool ok = v.State == expectState && v.ExitCode == expectCode;
            if (!ok) failed++;
            Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name,-28} -> state={v.State} code={(v.ExitCode?.ToString() ?? "-")}" +
                              (ok ? "" : $"  (expected state={expectState} code={(expectCode?.ToString() ?? "-")})"));
        }
        Console.WriteLine($"\nclassifier self-test: {cases.Length - failed}/{cases.Length} passed");
        return failed == 0 ? 0 : 1;
    }

    private static int Sc(string rawArguments)
    {
        var psi = new ProcessStartInfo("sc.exe")
        {
            Arguments = rawArguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("failed to start sc.exe");
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) Console.Error.WriteLine($"sc.exe {rawArguments.Split(' ')[0]} failed ({p.ExitCode}): {output.Trim()}");
        return p.ExitCode;
    }

    /// <summary>Exercise the full privileged launch path once, in-process, without the pipe/service
    /// (must run as LocalSystem). Prints the worker's result JSON, then cleans the run up.</summary>
    internal static int SelfTest(string[] args)
    {
        string runId = "selftest" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        var registry = new RunRegistry();
        var launcher = new WorkerLauncher(registry);
        WorkerRun? run = null;
        try
        {
            WorkspaceProvisioner.EnsureTrustedRoots();
            RunStore.EnsureRoot();
            WorkerCredential.Provision();
            run = launcher.Launch(runId, "proof-battery");
            Console.WriteLine($"launched runId={runId} pid={run.Pid} (restricted token, private desktop, in Job Object)");

            DateTime deadline = DateTime.UtcNow.AddSeconds(120);
            while (!RunState.IsTerminal(run.State) && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(500);
                launcher.UpdateStatus(run);
            }
            Console.WriteLine($"state={run.State} exit={run.ExitCode} members=[{string.Join(",", run.Members())}]");
            Console.WriteLine("---- worker RESULT JSON ----");
            Console.WriteLine(WorkerLauncher.ReadResult(run) ?? "(no result file produced)");
            Console.WriteLine("----------------------------");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("self-test failed: " + e); return 1; }
        finally { if (run is not null) launcher.Cleanup(run); }
    }

    private static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
