using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED self-test of the P3.4C-5 helper principal's custodian side (Amendment A): the trusted configuration's
/// helper identity, and (in later cases) the caller classification, the helper pipe, the channel framing, mutual
/// authentication and ticket correlation. Runs against a scratch store; touches no service.
/// </summary>
internal static class HelperChannelSelfTest
{
    internal static int Run(string[] args)
    {
        string scratch = Path.Combine(Path.GetTempPath(), "cp-helper-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        StorePaths.OverrideRootForSelfTest(scratch);
        Directory.CreateDirectory(scratch);
        int failed = 0;
        try
        {
            failed += ConfigCases();
            failed += ClassifierCases();
            failed += SurfaceCases();
            failed += CorrelationCases();
            failed += AgentCases(Path.GetDirectoryName(scratch.TrimEnd('\\'))!);
            failed += RuntimeSelfTest.Run(Path.GetDirectoryName(scratch.TrimEnd('\\'))!);
            Console.WriteLine($"\nhelper-channel self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
            return failed == 0 ? 0 : 1;
        }
        finally { TryDeleteTree(Path.GetDirectoryName(scratch.TrimEnd('\\'))!); }
    }

    /// <summary>Sub-step 1: the helper identity in the trusted configuration.</summary>
    private static int ConfigCases()
    {
        int failed = 0;
        string me = WindowsIdentity.GetCurrent().User!.Value;
        string helper = ServiceSid.Of(CustodianConstants.HelperServiceName).Value;

        new CustodianConfig { OperatorSid = me, ImplementerSid = me }.Save();
        string json = File.ReadAllText(StorePaths.ConfigPath);
        failed += Check("a config without a helper writes no helperSid key (earlier builds still read it)", !json.Contains("helperSid", StringComparison.Ordinal));
        CustodianConfig loaded = CustodianConfig.Load();
        failed += Check("a config without a helper loads with no helper identity", loaded.HelperSid is null && loaded.HelperSecurityIdentifier() is null);

        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = helper }.Save();
        failed += Check("the helper identity round-trips as NT SERVICE\\CodeParleyHelper's deterministic SID", CustodianConfig.Load().HelperSid == helper);
        failed += Check("the helper SID is the S-1-5-80 service SID of 'CodeParleyHelper'", helper.StartsWith("S-1-5-80-", StringComparison.Ordinal) && helper != ServiceSid.Custodian().Value);

        failed += Check("a helper SID that is not the helper service's is refused at save",
            Throws(() => new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save(), "is not NT SERVICE\\CodeParleyHelper"));
        failed += Check("a group SID as the helper identity is refused",
            Throws(() => new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = "S-1-1-0" }.Save(), "built-in/group SID"));
        File.WriteAllText(StorePaths.ConfigPath, json.TrimEnd().TrimEnd('}') + $",\n  \"helperSid\": \"{ServiceSid.Custodian().Value}\"\n}}");
        failed += Check("a config whose helperSid names another principal (the custodian) is refused at load (fail closed)",
            Throws(() => CustodianConfig.Load(), "is not NT SERVICE\\CodeParleyHelper"));
        File.WriteAllText(StorePaths.ConfigPath, json.TrimEnd().TrimEnd('}') + ",\n  \"helperRole\": \"operator\"\n}");
        failed += Check("an unknown config field is refused at load", Throws(() => CustodianConfig.Load(), "helperRole"));
        return failed;
    }

    /// <summary>Sub-step 2: the helper class is decided by SID on the helper surface only; integrity confers nothing; the
    /// helper SID is neither caller identity.</summary>
    private static int ClassifierCases()
    {
        int failed = 0;
        const string impl = "S-1-5-21-1000-2000-3000-1001", op = "S-1-5-21-1000-2000-3000-500";
        string helper = ServiceSid.Of(CustodianConstants.HelperServiceName).Value;
        var cfg = new CustodianConfig { OperatorSid = op, ImplementerSid = impl, HelperSid = helper };
        var noHelper = new CustodianConfig { OperatorSid = op, ImplementerSid = impl };
        const int high = 0x3000;
        CallerClass C(PipeSurface s, CustodianConfig c, string sid, int elevation = 1, int integrity = high)
            => CallerClassifier.Decide(s, c, new CallerClassifier.TokenFacts(sid, elevation, integrity)).Class;

        failed += Check("helper surface: the helper service SID is the helper class", C(PipeSurface.Helper, cfg, helper) == CallerClass.Helper);
        failed += Check("helper surface: with no helper configured, even the helper SID is refused", C(PipeSurface.Helper, noHelper, helper) == CallerClass.Unknown);
        failed += Check("helper surface: an elevated, High-integrity operator token is NOT the helper (integrity confers nothing)",
            C(PipeSurface.Helper, cfg, op, Native.TokenElevationTypeFull, high) == CallerClass.Unknown);
        failed += Check("helper surface: a System-integrity token that is not the helper SID is refused", C(PipeSurface.Helper, cfg, "S-1-5-18", Native.TokenElevationTypeFull, 0x4000) == CallerClass.Unknown);
        failed += Check("helper surface: the implementer is refused", C(PipeSurface.Helper, cfg, impl, 1, 0x2000) == CallerClass.Unknown);
        failed += Check("helper surface: a low-integrity helper token is refused", C(PipeSurface.Helper, cfg, helper, 1, 0x1000) == CallerClass.Unknown);
        CallerClassifier.Result onImpl = CallerClassifier.Decide(PipeSurface.Implementer, cfg, new CallerClassifier.TokenFacts(helper, 1, high));
        failed += Check("implementer surface: the High-integrity helper SID has no implementer capability", onImpl.Class == CallerClass.Unknown && onImpl.Detail.Contains("no implementer capability", StringComparison.Ordinal));
        failed += Check("operator surface: the High-integrity, elevated helper SID has no operator capability", C(PipeSurface.Operator, cfg, helper, Native.TokenElevationTypeFull, high) == CallerClass.Unknown);
        // Phase 6 Increment 1: the elevation gate itself, independent of the token this self-test runs under (the pipe
        // cases in self-test-ipc see one token only; CI's Windows runner is elevated).
        failed += Check("operator surface: the configured operator with a non-elevated, Medium-integrity token is refused",
            C(PipeSurface.Operator, cfg, op, 1, 0x2000) == CallerClass.Unknown);
        failed += Check("operator surface: the configured operator with a UAC-limited token is refused",
            C(PipeSurface.Operator, cfg, op, 3, 0x2000) == CallerClass.Unknown);
        failed += Check("implementer/operator surfaces unchanged: the implementer and the elevated operator are still classified",
            C(PipeSurface.Implementer, cfg, impl, 1, 0x2000) == CallerClass.Implementer && C(PipeSurface.Operator, cfg, op, Native.TokenElevationTypeFull, high) == CallerClass.Operator);
        string legacy = CallerClassifier.Decide(PipeSurface.Implementer, cfg, new CallerClassifier.TokenFacts(impl, 1, 0x2000)).ProofDigest;
        failed += Check("the implementer proof digest keeps its P3.4C-4 form (held proofs stay comparable)",
            legacy == Ledger.Digest.Sha256Hex($"sid={impl};elevationType=1;integrity=8192;operatorSurface=False"));

        // The dispatcher refuses the helper class every operation (defence in depth) and audits it.
        var core = new CustodianCore("cust-selftest");
        Response r = core.Handle(CallerClass.Helper, new Request(1, "h1", "ping", new JsonObject()), null, 4242);
        Response r2 = core.Handle(CallerClass.Helper, new Request(1, "h2", "commit", new JsonObject { ["authorizationRequestId"] = "x" }), null, 4242);
        failed += Check("the core refuses the helper class every operation (ping, commit) with CALLER_NOT_AUTHORIZED",
            !r.Ok && r.Code == ErrorCodes.CallerNotAuthorized && !r2.Ok && r2.Code == ErrorCodes.CallerNotAuthorized);
        failed += Check("the refused helper-class operation is audited", AuditHas("caller=helper"));
        return failed;
    }

    /// <summary>Sub-step 2: the three-surface pipe server in-process. The current account plays the helper (self-test
    /// override); a second run configures the real helper SID, so the current account is the custodian identity the DACL
    /// admits but not the helper the classifier accepts.</summary>
    private static int SurfaceCases()
    {
        int failed = 0;
        string me = WindowsIdentity.GetCurrent().User!.Value;
        CustodianConfig.AllowAnyHelperSidForSelfTest();
        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save();
        using (var cts = new CancellationTokenSource())
        {
            var server = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), new HelperBroker(new NoStarter()));
            Task run = server.RunAsync(cts.Token);
            Thread.Sleep(800);
            try
            {
                failed += Check("the helper pipe is hosted beside the implementer and operator pipes",
                    File.Exists(PipePath(CustodianConstants.HelperPipe)) && File.Exists(PipePath(CustodianConstants.ImplementerPipe)));
                JsonObject? bye = HelperClient.Exchange(new JsonObject { ["t"] = "hello", ["v"] = 1 });
                failed += Check("an authenticated helper with no job waiting is told goodbye", (string?)bye?["t"] == "bye");
                JsonObject? opFrame = HelperClient.Exchange(new JsonObject { ["t"] = "hello", ["v"] = 1, ["op"] = "decide" });
                failed += Check("an authority operation frame on the helper pipe is refused (HELPER_CHANNEL_REFUSED)",
                    (string?)opFrame?["t"] == "refused" && (string?)opFrame["code"] == ErrorCodes.HelperChannelRefused && ((string?)opFrame["detail"] ?? "").Contains("decide", StringComparison.Ordinal));
                failed += Check("... and audited (authority_frame_refused)", AuditHas("event=authority_frame_refused"));
                string line = new JsonObject { ["v"] = 1, ["requestId"] = "x", ["op"] = "spend_continuation", ["args"] = new JsonObject() }.ToJsonString() + "\n";
                JsonObject? lineReq = HelperClient.Raw(Encoding.UTF8.GetBytes(line));
                failed += Check("an implementer-protocol request line on the helper pipe is refused and audited (malformed_frame)",
                    (string?)lineReq?["t"] == "refused" && AuditHas("event=malformed_frame"));
                JsonObject? wrongType = HelperClient.Exchange(new JsonObject { ["t"] = "result", ["v"] = 1 });
                failed += Check("a first frame that is not a hello is refused and audited (frame_type_refused)", (string?)wrongType?["t"] == "refused" && AuditHas("event=frame_type_refused"));
                string ping = LineClient.Send(CustodianConstants.ImplementerPipe, new JsonObject { ["v"] = 1, ["requestId"] = "p1", ["op"] = "ping", ["args"] = new JsonObject() }.ToJsonString());
                failed += Check("the implementer surface still serves (ping as the implementer)", ping.Contains("\"caller\":\"implementer\"", StringComparison.Ordinal));
            }
            finally { cts.Cancel(); try { run.Wait(3000); } catch { } }
        }

        // The real helper SID configured: the current account (the custodian identity here) may open the pipe by its DACL
        // but is refused by the classifier, and audited.
        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = ServiceSid.Of(CustodianConstants.HelperServiceName).Value }.Save();
        using (var cts = new CancellationTokenSource())
        {
            var server = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), new HelperBroker(new NoStarter()));
            Task run = server.RunAsync(cts.Token);
            Thread.Sleep(800);
            try
            {
                JsonObject? notHelper = HelperClient.Exchange(new JsonObject { ["t"] = "hello", ["v"] = 1 });
                failed += Check("a client whose SID is not the helper service SID is refused on the helper pipe",
                    (string?)notHelper?["t"] == "refused" && ((string?)notHelper["detail"] ?? "").Contains("is not the helper service", StringComparison.Ordinal));
                failed += Check("... and audited (caller_refused)", AuditHas("event=caller_refused"));
            }
            finally { cts.Cancel(); try { run.Wait(3000); } catch { } }
        }

        // Anti-squat: another server already holds the helper pipe name, so the custodian's first-instance creation fails
        // and its helper surface does not serve (fail closed).
        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save();
        using (var squat = new NamedPipeServerStream(CustodianConstants.HelperPipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
        using (var cts = new CancellationTokenSource())
        {
            var server = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), new HelperBroker(new NoStarter()));
            Task run = server.RunAsync(cts.Token);
            Thread.Sleep(800);
            try { failed += Check("anti-squat: with the helper pipe name pre-created, the custodian refuses to serve the helper surface", server.HelperSurfaceFailed); }
            finally { cts.Cancel(); try { run.Wait(3000); } catch { } }
        }
        return failed;
    }

    /// <summary>Sub-step 3: ticket/instance correlation and the channel caps, against a scripted fake helper (no Node).</summary>
    private static int CorrelationCases()
    {
        int failed = 0;
        string me = WindowsIdentity.GetCurrent().User!.Value;
        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save();
        var broker = new HelperBroker(new NoStarter()) { AttachTimeout = TimeSpan.FromSeconds(5) };
        using var cts = new CancellationTokenSource();
        var server = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), broker);
        Task run = server.RunAsync(cts.Token);
        Thread.Sleep(800);
        try
        {
            // The fake helper answers the request with `reply(request header)` frames, then closes.
            HelperJobOutcome Job(Func<JsonObject, List<(JsonObject H, byte[] B)>> reply, long maxBody = 1 << 16, int timeoutSeconds = 10)
            {
                var handler = new RecordingHandler(maxBody);
                Task<HelperJobOutcome> job = broker.RunAsync("derive", new JsonObject { ["probe"] = true }, handler, TimeSpan.FromSeconds(timeoutSeconds), CancellationToken.None);
                using (NamedPipeClientStream c = HelperClient.Connect())
                {
                    HelperFrames.WriteAsync(c, new JsonObject { ["t"] = "hello", ["v"] = 1 }, CancellationToken.None).GetAwaiter().GetResult();
                    HelperFrame req = HelperFrames.ReadAsync(c, 1 << 20, CancellationToken.None).GetAwaiter().GetResult()!;
                    try { foreach ((JsonObject h, byte[] b) in reply(req.Header)) HelperFrames.WriteAsync(c, h, b, CancellationToken.None).GetAwaiter().GetResult(); }
                    catch (IOException) { /* the custodian may close first after a refusal */ }
                    job.Wait(TimeSpan.FromSeconds(timeoutSeconds + 40));
                }
                return job.Result;
            }
            static JsonObject H(string t, JsonObject req, string? ticket = null, string? instance = null)
                => new() { ["t"] = t, ["ticket"] = ticket ?? (string?)req["ticket"], ["instance"] = instance ?? (string?)req["instance"] };
            static byte[] J(string json) => Encoding.UTF8.GetBytes(json);
            static (JsonObject, byte[]) Exit(JsonObject req, int code = 0) { var e = H("exit", req); e["exitCode"] = code; return (e, []); }

            HelperJobOutcome ok = Job(req => [(H("result", req), J("{\"x\":1}")), Exit(req)]);
            failed += Check("a correlated result and a clean exit: the job succeeds", ok.Ok);
            HelperJobOutcome previous = Job(req => [(H("result", req, instance: HelperBroker.NewToken()), J("{}")), Exit(req)]);
            failed += Check("a response bound to another (previous) service instance is rejected, nothing accepted",
                !previous.Ok && previous.Code == ErrorCodes.HelperChannelRefused && AuditHas("event=instance_mismatch"));
            HelperJobOutcome wrongTicket = Job(req => [(H("result", req, ticket: HelperBroker.NewToken()), J("{}")), Exit(req)]);
            failed += Check("a response bearing a ticket that is not outstanding is rejected and audited", !wrongTicket.Ok && AuditHas("event=ticket_mismatch"));
            HelperJobOutcome dup = Job(req => [(H("result", req), J("{}")), (H("result", req), J("{}")), Exit(req)]);
            failed += Check("a duplicate result for one ticket is rejected", !dup.Ok && (dup.Detail ?? "").Contains("second result", StringComparison.Ordinal));
            HelperJobOutcome op = Job(req => { var h = H("result", req); h["op"] = "spend_continuation"; return [(h, J("{}")), Exit(req)]; });
            failed += Check("an authority operation frame mid-job is refused and audited", !op.Ok && AuditHas("event=authority_frame_refused"));
            HelperJobOutcome big = Job(req => [(H("file", req), new byte[70_000]), Exit(req)], maxBody: 65_536);
            failed += Check("a frame body over the job's cap is rejected", !big.Ok && big.Code == ErrorCodes.HelperChannelRefused && (big.Detail ?? "").Contains("exceeds the cap", StringComparison.Ordinal));
            HelperJobOutcome noResult = Job(req => [Exit(req)]);
            failed += Check("an exit without a result is a failure (nothing to accept)", !noResult.Ok && noResult.Code == ErrorCodes.MeasurementFailed);
            HelperJobOutcome late = Job(req => [], timeoutSeconds: 2);
            failed += Check("a helper that never answers ends the job at its deadline (MEASUREMENT_TIMEOUT)", !late.Ok && late.Code == ErrorCodes.MeasurementTimeout);

            var unattended = new HelperBroker(new NoStarter()) { AttachTimeout = TimeSpan.FromSeconds(2) };
            HelperJobOutcome none = unattended.RunAsync("derive", new JsonObject(), new RecordingHandler(1024), TimeSpan.FromSeconds(5), CancellationToken.None).GetAwaiter().GetResult();
            failed += Check("no helper attaches within the attach deadline: HELPER_UNAVAILABLE (fail closed)", !none.Ok && none.Code == ErrorCodes.HelperUnavailable);
            var refusing = new HelperBroker(new RefusingStarter()) { AttachTimeout = TimeSpan.FromSeconds(2) };
            HelperJobOutcome cannot = refusing.RunAsync("derive", new JsonObject(), new RecordingHandler(1024), TimeSpan.FromSeconds(5), CancellationToken.None).GetAwaiter().GetResult();
            failed += Check("the helper service cannot be started: HELPER_UNAVAILABLE with the operator's remedy", !cannot.Ok && cannot.Code == ErrorCodes.HelperUnavailable && (cannot.Detail ?? "").Contains("install-helper", StringComparison.Ordinal));
        }
        finally { cts.Cancel(); try { run.Wait(3000); } catch { } }
        return failed;
    }

    /// <summary>Sub-step 3: the real helper agent (as the current account) attached to the in-process custodian, running real
    /// Node children: the request reaches the workload, frames are relayed with the ticket and instance, the staging notice
    /// round-trips, and every refusal path ends the job fail-closed.</summary>
    private static int AgentCases(string work)
    {
        int failed = 0;
        string me = WindowsIdentity.GetCurrent().User!.Value;
        string? node = FindOnPath("node.exe");
        string? git = FindOnPath("git.exe");
        if (node is null || git is null) { Console.WriteLine("[skip] agent cases: node.exe and git.exe must be on PATH"); return 0; }
        string dir = Directory.CreateDirectory(Path.Combine(work, "runtime")).FullName;
        string home = Directory.CreateDirectory(Path.Combine(work, "cfg", "home")).FullName;
        string gitconfig = Path.Combine(work, "cfg", "gitconfig");
        File.WriteAllText(gitconfig, "");
        string repo = Directory.CreateDirectory(Path.Combine(work, "repo")).FullName;
        string entry = Path.Combine(dir, "entry.js");
        File.WriteAllText(entry, AgentScript);
        string nodeSha = Sha256File(node), entrySha = Sha256File(entry);

        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save();
        var broker = new HelperBroker(new NoStarter()) { AttachTimeout = TimeSpan.FromSeconds(15) };
        using var cts = new CancellationTokenSource();
        var server = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), broker);
        Task run = server.RunAsync(cts.Token);
        Thread.Sleep(800);
        var agent = new HelperAgent(new SecurityIdentifier(me), TimeSpan.FromSeconds(60), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        Task agentRun = agent.RunAsync(cts.Token);
        try
        {
            JsonObject Launch(string mode, string? entrySha256 = null, string? safe = null, long maxBody = 1 << 20) => new()
            {
                ["launch"] = new JsonObject
                {
                    ["node"] = node, ["nodeSha256"] = nodeSha, ["entry"] = entry, ["entrySha256"] = entrySha256 ?? entrySha, ["git"] = git,
                    ["home"] = home, ["gitconfig"] = gitconfig, ["hooks"] = home, ["repository"] = repo, ["safeDirectory"] = safe ?? repo.Replace('\\', '/'),
                    ["maxFrameBody"] = maxBody,
                },
                ["workload"] = new JsonObject { ["mode"] = mode },
            };
            (HelperJobOutcome O, RecordingHandler R) Do(string kind, JsonObject p, int seconds = 30)
            {
                var h = new RecordingHandler(1 << 20) { StageDir = @"C:\staged-for-test" };
                return (broker.RunAsync(kind, p, h, TimeSpan.FromSeconds(seconds), CancellationToken.None).GetAwaiter().GetResult(), h);
            }

            (HelperJobOutcome derive, RecordingHandler dr) = Do("derive", Launch("result"));
            JsonObject? echoed = dr.Result is null ? null : JsonNode.Parse(dr.Result) as JsonObject;
            failed += Check("a real Node workload under the agent returns a correlated result (derive)", derive.Ok && (string?)echoed?["kind"] == "derive");
            failed += Check("the workload saw the allowlisted environment: one safe.directory (the repository), no system/global git config, read-only home as TEMP",
                (string?)echoed?["env"]?["GIT_CONFIG_COUNT"] == "1" && (string?)echoed?["env"]?["GIT_CONFIG_VALUE_0"] == repo.Replace('\\', '/')
                && (string?)echoed?["env"]?["GIT_CONFIG_NOSYSTEM"] == "1" && (string?)echoed?["env"]?["TEMP"] == home && echoed?["env"]?["NODE_OPTIONS"] is null);
            (HelperJobOutcome cap, RecordingHandler cr) = Do("capture", Launch("stage"));
            failed += Check("capture: files, stage-complete, the custodian's staged directory back to the workload, late review files, result",
                cap.Ok && cr.Files.SequenceEqual(["tree/a.txt", "review/diff.patch"]) && cr.Result is not null && Encoding.UTF8.GetString(cr.Result).Contains("staged-for-test", StringComparison.Ordinal));
            (HelperJobOutcome exitFrame, _) = Do("derive", Launch("forge-exit"));
            failed += Check("the workload cannot send the helper-owned 'exit' frame (not relayed; the job is stopped)", !exitFrame.Ok);
            (HelperJobOutcome ticketFrame, _) = Do("derive", Launch("forge-ticket"));
            failed += Check("the workload cannot set its own ticket (not relayed; the job is stopped)", !ticketFrame.Ok);
            (HelperJobOutcome badHash, _) = Do("derive", Launch("result", entrySha256: new string('0', 64)));
            failed += Check("an entry whose hash differs from the custodian's measurement is refused before launch", !badHash.Ok && (badHash.Detail ?? "").Contains("REQUEST_REFUSED", StringComparison.Ordinal));
            (HelperJobOutcome star, _) = Do("derive", Launch("result", safe: "*"));
            failed += Check("safe.directory=* is refused (exactly the validated repository only)", !star.Ok && (star.Detail ?? "").Contains("safeDirectory", StringComparison.Ordinal));
            (HelperJobOutcome parent, _) = Do("derive", Launch("result", safe: work.Replace('\\', '/')));
            failed += Check("a parent directory as safe.directory is refused", !parent.Ok);
            (HelperJobOutcome big, _) = Do("derive", Launch("big", maxBody: 1 << 20));
            failed += Check("a workload frame over the request's frame cap is not relayed (the job is stopped)", !big.Ok);
            (HelperJobOutcome hang, _) = Do("derive", Launch("hang"), seconds: 3);
            failed += Check("a workload that never finishes is killed at the deadline (fail closed)", !hang.Ok && hang.Code is ErrorCodes.MeasurementTimeout or ErrorCodes.MeasurementFailed);
            (HelperJobOutcome after, _) = Do("derive", Launch("result"));
            failed += Check("the agent keeps serving after failures (a new request succeeds)", after.Ok && agent.Served >= 9);
        }
        finally { cts.Cancel(); try { Task.WaitAll([run, agentRun], 5000); } catch { } }

        // Server authentication: an agent that expects the real custodian service SID refuses this pipe (owned by the current
        // account) and sends nothing, so a job here never gets a helper.
        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save();
        using var cts2 = new CancellationTokenSource();
        var broker2 = new HelperBroker(new NoStarter()) { AttachTimeout = TimeSpan.FromSeconds(6) };
        var server2 = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), broker2);
        Task run2 = server2.RunAsync(cts2.Token);
        Thread.Sleep(800);
        try
        {
            using (NamedPipeClientStream probe = HelperClient.Connect())
            {
                string? problem = HelperAgent.ServerProblem(probe, ServiceSid.Custodian());
                failed += Check("server authentication: a pipe not owned by the custodian service SID is refused before anything is sent",
                    problem is not null && problem.Contains("not by the custodian identity", StringComparison.Ordinal));
                failed += Check("server authentication: the same pipe passes for its real owner (owner + access list)", HelperAgent.ServerProblem(probe, new SecurityIdentifier(me)) is null);
            }
            var impostorCheck = new HelperAgent(ServiceSid.Custodian(), TimeSpan.FromSeconds(10), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            Task a2 = impostorCheck.RunAsync(cts2.Token);
            HelperJobOutcome refusedServer = broker2.RunAsync("derive", new JsonObject(), new RecordingHandler(1024), TimeSpan.FromSeconds(5), CancellationToken.None).GetAwaiter().GetResult();
            failed += Check("... so a job finds no helper (HELPER_UNAVAILABLE) — the agent never attached to a pipe it could not authenticate",
                !refusedServer.Ok && refusedServer.Code == ErrorCodes.HelperUnavailable && impostorCheck.Served == 0);
        }
        finally { cts2.Cancel(); try { run2.Wait(3000); } catch { } }
        return failed;
    }

    /// <summary>The scripted workload the agent cases run (a stand-in for dist/helper/main.js): it reads the request line,
    /// then behaves per <c>workload.mode</c>.</summary>
    private const string AgentScript = """
        const frame = (h, body = Buffer.alloc(0)) => {
          const hb = Buffer.from(JSON.stringify(h), "utf8");
          const a = Buffer.alloc(4); a.writeUInt32LE(hb.length);
          const b = Buffer.alloc(4); b.writeUInt32LE(body.length);
          process.stdout.write(Buffer.concat([a, hb, b, body]));
        };
        let buf = ""; const lines = []; let waiter = null;
        process.stdin.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); } if (waiter && lines.length) { const w = waiter; waiter = null; w(); } });
        const next = () => new Promise((r) => { if (lines.length) r(); else waiter = r; }).then(() => lines.shift());
        (async () => {
          const req = JSON.parse(await next());
          const mode = req.workload.mode;
          const env = Object.fromEntries(["GIT_CONFIG_COUNT", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_NOSYSTEM", "TEMP", "NODE_OPTIONS"].filter((k) => k in process.env).map((k) => [k, process.env[k]]));
          if (mode === "result") frame({ t: "result" }, Buffer.from(JSON.stringify({ kind: process.argv[2], env })));
          else if (mode === "stage") {
            frame({ t: "file", area: "tree", path: "a.txt", size: 2, sha256: "x" }, Buffer.from("hi"));
            frame({ t: "stage_complete" });
            const staged = JSON.parse(await next());
            frame({ t: "file", area: "review", path: "diff.patch", size: 0, sha256: "x" });
            frame({ t: "result" }, Buffer.from(JSON.stringify({ staged: staged.dir })));
          }
          else if (mode === "forge-exit") frame({ t: "exit", exitCode: 0 });
          else if (mode === "forge-ticket") frame({ t: "result", ticket: "0".repeat(32) }, Buffer.from("{}"));
          else if (mode === "big") frame({ t: "file", area: "tree", path: "b", size: 0, sha256: "x" }, Buffer.alloc(2 * 1024 * 1024));
          else if (mode === "hang") await new Promise(() => {});
          process.stdout.end(() => process.exit(0));
        })();
        """;

    private sealed class RecordingHandler(long maxBody) : IHelperJobHandler
    {
        internal List<string> Files { get; } = [];
        internal byte[]? Result { get; private set; }
        internal string StageDir { get; init; } = @"C:\staged";
        public long MaxFrameBody => maxBody;
        public void OnFile(HelperFrame file) => Files.Add($"{file.Str("area")}/{file.Str("path")}");
        public string OnStageComplete() => StageDir;
        public void OnResult(byte[] json) => Result = json;
    }

    private sealed class RefusingStarter : IHelperStarter
    {
        public void EnsureRunning() => throw new CustodianRefusal(ErrorCodes.HelperUnavailable, "the helper service CodeParleyHelper could not be started (test); the operator installs it, elevated, with `CodeParley.Custodian.exe install-helper`");
    }

    private static string? FindOnPath(string exe)
        => (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries).Select(d => Path.Combine(d.Trim(), exe)).FirstOrDefault(File.Exists);

    private static string Sha256File(string path)
    {
        using FileStream fs = File.OpenRead(path);
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(fs));
    }

    private static string PipePath(string name) => @"\\.\pipe\" + name;

    private sealed class NoStarter : IHelperStarter { public void EnsureRunning() { } }

    private static bool AuditHas(string fragment)
        => File.Exists(StorePaths.AuditPath) && File.ReadAllText(StorePaths.AuditPath).Contains(fragment, StringComparison.Ordinal);

    /// <summary>A minimal helper-channel client: send one frame (or raw bytes), read one frame back.</summary>
    internal static class HelperClient
    {
        internal static JsonObject? Exchange(JsonObject header)
        {
            using NamedPipeClientStream c = Connect();
            HelperFrames.WriteAsync(c, header, CancellationToken.None).GetAwaiter().GetResult();
            return HelperFrames.ReadAsync(c, 1 << 20, CancellationToken.None).GetAwaiter().GetResult()?.Header;
        }

        internal static JsonObject? Raw(byte[] bytes)
        {
            using NamedPipeClientStream c = Connect();
            // Not awaited: the pipe is unbuffered, so the write completes only once the server consumed every byte, and the
            // server stops reading after the bad length. Disposing the client cancels the rest.
            _ = c.WriteAsync(bytes, 0, bytes.Length);
            try { return HelperFrames.ReadAsync(c, 1 << 20, CancellationToken.None).GetAwaiter().GetResult()?.Header; }
            catch (Exception) { return null; }
        }

        internal static NamedPipeClientStream Connect()
        {
            var c = new NamedPipeClientStream(".", CustodianConstants.HelperPipe, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
            c.Connect(4000);
            return c;
        }
    }

    private static class LineClient
    {
        internal static string Send(string pipe, string request)
        {
            using var c = new NamedPipeClientStream(".", pipe, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Identification);
            c.Connect(4000);
            byte[] payload = Encoding.UTF8.GetBytes(request + "\n");
            c.Write(payload, 0, payload.Length);
            c.Flush();
            return new StreamReader(c, Encoding.UTF8).ReadLine() ?? "";
        }
    }

    internal static int Check(string name, bool ok) { Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}"); return ok ? 0 : 1; }

    private static bool Throws(Action a, string expect)
    {
        try { a(); return false; }
        catch (Exception e) { return e.Message.Contains(expect, StringComparison.Ordinal); }
    }

    private static void TryDeleteTree(string dir) { try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { } }
}
