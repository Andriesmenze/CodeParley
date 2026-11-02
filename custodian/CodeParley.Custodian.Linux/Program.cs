using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian;
using CodeParley.Custodian.Cli;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Linux;
using CodeParley.Custodian.Linux.Ipc;
using CodeParley.Custodian.Linux.Ledger;
using CodeParley.Custodian.Linux.Security;
using CodeParley.Custodian.Security;

// Phase 5 (contract §4): the Linux host of the portable custodian core. With no verb (how systemd starts it) it serves the
// two caller sockets; the other verbs are diagnostics and the shared self-tests. None of them creates authority.
LinuxPlatform.Configure();
string verb = args.Length > 0 ? args[0].ToLowerInvariant() : "run";
switch (verb)
{
    case "run": return Service.Run();
    case "helper": return LinuxHelperAgent.Run();
    case "host-check": return Diagnostics.HostCheck();
    case "version": return CodeParley.Custodian.Cli.BuildIdentity.Print("linux");
    case "store-check": return Diagnostics.StoreCheck();
    case "identity": return Diagnostics.Identity(args);
    case "fsid": return Diagnostics.Fsid(args);
    case "self-test-content-key": return ContentKeySelfTest.Run(args);
    case "self-test-store-format": return StoreFormatSelfTest.Run();
    case "self-test-store-upgrade": return StoreUpgradeSelfTest.Run();
    case "self-test-runtime-git": return RuntimeGitSelfTest.Run();
    case "store-status": return StoreUpgradeCli.Status();
    case "store-upgrade": return StoreUpgradeCli.Upgrade(args);
    case "self-test-identity": return IdentitySelfTest.Run();
    case "self-test-durable": return DurableSelfTest.Run();
    case "self-test-isolation-basis": return IsolationBasisSelfTest.Run();
    // The shared corpora fix the portable semantics on every platform; they carry no host sandbox basis (the Linux basis,
    // §4.12, is exercised against the real installation on the VM: NL-15), and their synthetic Codex and runtime trees are
    // the test user's, which the §4.9 ownership rules refuse (exercised on the VM: NL-14).
    case "self-test-loop-corpus": LinuxRepoIdentities.AcceptUnprovisionedFilesystemsForSelfTest(); LinuxImages.SkipOwnershipChecksForSelfTest(); Platform.Isolation = new NoIsolationBasis(); return LoopCorpusSelfTest.Run(args);
    case "self-test-run-corpus":
        // The shared run corpus's fixed process table models the engine sending through a short-lived helper (its writer is
        // the connected process's parent); it runs with that topology. The Linux writer rule (the connected process itself,
        // F5-2) is exercised against real processes on the VM (NL-5).
        LinuxRepoIdentities.AcceptUnprovisionedFilesystemsForSelfTest(); LinuxImages.AcceptCorpusPeForSelfTest(); LinuxImages.SkipOwnershipChecksForSelfTest();
        Platform.Isolation = new NoIsolationBasis();
        Platform.WriterIsConnectedProcess = false;
        Platform.OperatorAssurance = "local_admin_elevation"; // the corpus's expectations carry the Windows label
        return RunCorpusSelfTest.Run(args);
    case "self-test-config-corpus": LinuxRepoIdentities.AcceptUnprovisionedFilesystemsForSelfTest(); LinuxImages.SkipOwnershipChecksForSelfTest(); Platform.Isolation = new NoIsolationBasis(); return ConfigCorpusSelfTest.Run(args);
    default:
        Console.Error.WriteLine($"unknown verb '{verb}' (run|helper|version|host-check|store-check|identity <path>|fsid <mountpoint>|self-test-content-key|self-test-store-format|self-test-store-upgrade|self-test-runtime-git|store-status|store-upgrade|self-test-identity|self-test-durable|self-test-isolation-basis|self-test-loop-corpus|self-test-run-corpus|self-test-config-corpus)");
        return 2;
}

/// <summary>The service: configuration, host preconditions and the whole store validated, the inherited sockets identified
/// and verified, the new-boot recovery completed — all BEFORE readiness is reported and before the first accept (connections
/// made earlier wait in the backlog); anything failing serves nothing (fail closed) and names the cause in the journal.</summary>
internal static class Service
{
    private static StoreLock? _storeLock;

    internal static int Run()
    {
        void Log(string m) => Console.Error.WriteLine(m);
        Log("CodeParley Custodian (Linux) starting");
        try { AmendmentContentKey.SelfValidate(); }
        catch (Exception e) { Log($"Unicode globalization self-validation FAILED; protected amendment operations will fail closed: {e.Message}"); }

        LinuxConfig cfg;
        Dictionary<string, int> fds;
        CustodianCore core;
        try
        {
            cfg = LinuxConfig.Load();
            fds = SocketServer.InheritedDescriptors();
            LinuxHostCheck.EnsurePrivateDirectories();
            List<string> problems = LinuxHostCheck.Preconditions(cfg);
            if (problems.Count > 0)
            {
                foreach (string p in problems) Log("host check FAILED: " + p);
                Log($"{problems.Count} host precondition(s) failed; serving nothing (fail closed)");
                return 3;
            }
            // Phase 6 L-2: the store is this process's until it exits (a store upgrade cannot run meanwhile).
            _storeLock = StoreLock.Acquire("custodian service");
            int swept = DurableStore.SweepTemporaries(StorePaths.Root);
            if (swept > 0) Log($"swept {swept} temporary store file(s) of interrupted writes");
            // Phase 6 L-1: the store's format before any state is accepted (an older store waits for `upgrade`).
            StoreFormat.RequireServable();
            // Increment 2 (§4.10, D5-C): the helper channel — the custodian connects to the socket-activated helper. Without a
            // helper account every helper measurement (capture, checks, derivation) refuses HELPER_UNAVAILABLE.
            HelperBroker? broker = null;
            Principal? helper = null, readersGroup = null;
            if (cfg.HelperUid is { } helperUid)
            {
                var starter = new LinuxHelperStarter(cfg, Log);
                broker = new HelperBroker(starter);
                starter.Broker = broker;
                helper = new Principal(helperUid.ToString(System.Globalization.CultureInfo.InvariantCulture), cfg.HelperName);
                if (CodeParley.Custodian.Linux.Native.Libc.GetGroupByName(LinuxHostCheck.ReadersGroup) is { } g)
                    readersGroup = new Principal(g.Gid.ToString(System.Globalization.CultureInfo.InvariantCulture), g.Name);
            }
            var implementer = new Principal(cfg.ImplementerUid.ToString(System.Globalization.CultureInfo.InvariantCulture), cfg.ImplementerName);
            core = new CustodianCore(Libc_UidName(), broker, helper, implementer, readersGroup is null ? null : (readersGroup, readersGroup.Display));
            if (LinuxConfig.TestHoldRecoverySeconds() is > 0 and int hold)
            {
                Log($"TEST HOOK: holding the start for {hold} s before recovery ({LinuxConfig.TestHoldRecoveryPath}); nothing is served meanwhile");
                Thread.Sleep(TimeSpan.FromSeconds(hold));
            }
            // Phase 6 L-5: the installer's restore marker (root-owned, in /etc/codeparley), validated or fail closed.
            RecoveryOutcome recovery = core.StartupRecovery(new LinuxBootIdentity(), LinuxConfig.ReadRestoreMarker());
            Log(recovery.Reason.Contains(GrantLedger.RestoredPrefix, StringComparison.Ordinal)
                ? $"restored epoch {recovery.RecoveryId} completed before serving ({recovery.Reason}): every open protected run ended \"restored\", every unconsumed fix confirmation void, grants suspended, configuration lapsed, intents void"
                : recovery.Recovered
                ? $"recovery {recovery.RecoveryId} completed before serving ({recovery.Reason}): live loops paused, grants suspended, a new evidence epoch for open runs, earlier waivers and deferrals lapse until re-confirmed, configuration lapses, pending intents void"
                : $"no recovery needed ({recovery.Reason})");
        }
        catch (Exception e)
        {
            Log($"the custodian could not start safely; serving nothing (fail closed): {e.Message}");
            return 3;
        }

        using var cts = new CancellationTokenSource();
        using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; cts.Cancel(); });
        using var intr = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; cts.Cancel(); });
        SocketServer server = SocketServer.Create(core, cfg, fds);
        Notify("READY=1\nSTATUS=serving the implementer and operator sockets");
        Log($"serving: implementer uid {cfg.ImplementerUid} ({cfg.ImplementerName}), operator uid {cfg.OperatorUid} ({cfg.OperatorName})");
        try { server.RunAsync(Log, cts.Token).GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { }
        catch (Exception e) { Log($"custodian service faulted: {e.Message}"); }
        Notify("STOPPING=1");
        try { core.MarkCleanStop(); } catch (Exception e) { Log($"the clean-stop diagnostic could not be recorded: {e.Message}"); }
        Log("CodeParley Custodian (Linux) stopping");
        return 0;
    }

    private static string Libc_UidName() => "uid-" + CodeParley.Custodian.Linux.Native.Libc.geteuid().ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>sd_notify(3): one datagram to <c>$NOTIFY_SOCKET</c> (a path, or an abstract name starting with '@').</summary>
    private static void Notify(string state)
    {
        string? path = Environment.GetEnvironmentVariable("NOTIFY_SOCKET");
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            using var s = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            s.SendTo(Encoding.UTF8.GetBytes(state), new UnixDomainSocketEndPoint(path[0] == '@' ? "\0" + path[1..] : path));
        }
        catch (Exception e) when (e is SocketException or ArgumentException) { Console.Error.WriteLine($"sd_notify failed: {e.Message}"); }
    }
}

/// <summary>Diagnostics (no authority): the host check, the store check, and a repository identity as this custodian
/// derives it (for the acceptance probes).</summary>
internal static class Diagnostics
{
    internal static int HostCheck()
    {
        try
        {
            LinuxConfig cfg = LinuxConfig.Load();
            List<string> p = LinuxHostCheck.Preconditions(cfg);
            Console.WriteLine(new JsonObject { ["ok"] = p.Count == 0, ["problems"] = new JsonArray([.. p.Select(x => (JsonNode)x)]) }.ToJsonString());
            return p.Count == 0 ? 0 : 1;
        }
        catch (Exception e) { Console.WriteLine(new JsonObject { ["ok"] = false, ["problems"] = new JsonArray(e.Message) }.ToJsonString()); return 1; }
    }

    internal static int StoreCheck()
    {
        uint? helperUid = null, implementerUid = null;
        try { LinuxConfig c = LinuxConfig.Load(); helperUid = c.HelperUid; implementerUid = c.ImplementerUid; } catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException) { }
        List<string> p = LinuxHostCheck.ValidateStore(helperUid, implementerUid);
        Console.WriteLine(new JsonObject { ["ok"] = p.Count == 0, ["problems"] = new JsonArray([.. p.Select(x => (JsonNode)x)]) }.ToJsonString());
        return p.Count == 0 ? 0 : 1;
    }

    /// <summary>The filesystem magic and <c>f_fsid</c> of a path exactly as the identity and the store check read them (for
    /// provisioning: the operator's privileged step records this fsid after checking metadata_csum and the inode size).</summary>
    internal static int Fsid(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("fsid <mountpoint>"); return 2; }
        int fd = CodeParley.Custodian.Linux.Native.Libc.Openat(CodeParley.Custodian.Linux.Native.Libc.AT_FDCWD, args[1], CodeParley.Custodian.Linux.Native.Libc.O_PATH | CodeParley.Custodian.Linux.Native.Libc.O_CLOEXEC, 0);
        if (fd < 0) { Console.WriteLine(new JsonObject { ["ok"] = false, ["refused"] = "cannot be opened" }.ToJsonString()); return 1; }
        try
        {
            if (CodeParley.Custodian.Linux.Native.Libc.FsOf(fd) is not { } fs) { Console.WriteLine(new JsonObject { ["ok"] = false, ["refused"] = "fstatfs failed" }.ToJsonString()); return 1; }
            Console.WriteLine(new JsonObject { ["ok"] = true, ["magic"] = $"0x{fs.Type:x}", ["ext4"] = fs.Type == CodeParley.Custodian.Linux.Native.Libc.EXT4_SUPER_MAGIC, ["fsid"] = fs.Fsid.ToString("x16", System.Globalization.CultureInfo.InvariantCulture) }.ToJsonString());
            return 0;
        }
        finally { CodeParley.Custodian.Linux.Native.Libc.close(fd); }
    }

    internal static int Identity(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("identity <path> [--any-ext4]"); return 2; }
        if (args.Contains("--any-ext4")) LinuxRepoIdentities.AcceptUnprovisionedFilesystemsForSelfTest();
        try
        {
            RepoIdentity id = RepoIdentities.Resolve(args[1]);
            Console.WriteLine(new JsonObject { ["ok"] = true, ["key"] = id.Key, ["canonical"] = id.CanonicalPath, ["filesystem"] = id.FileSystem }.ToJsonString());
            return 0;
        }
        catch (Exception e) when (e is ArgumentException or CustodianRefusal)
        {
            Console.WriteLine(new JsonObject { ["ok"] = false, ["refused"] = e.Message }.ToJsonString());
            return 1;
        }
    }
}
