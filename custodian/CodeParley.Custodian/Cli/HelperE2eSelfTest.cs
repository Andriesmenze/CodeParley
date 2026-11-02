using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED, development host: the P3.4C-5 Increment-1 flow end to end in one process, as the current account —
/// the custodian's real dispatcher, ledger, pipe server and broker, the real helper agent attached over the real helper
/// pipe, and the real engine runtime (node.exe, the built dist/helper/main.js and git, approved and measured) capturing and
/// deriving a real repository through <c>helper_check</c>. The administrator-control check of the runtime tree is off
/// (a scratch tree cannot be administrator-owned without elevation); the VM gate runs the same flow through the installed
/// services, as the real <c>NT SERVICE\CodeParleyHelper</c>, with that check on.
///
///   self-test-helper-e2e --runtime &lt;root&gt; --git &lt;relative path of git.exe&gt; --repo &lt;repository&gt; [--out &lt;result.json&gt;]
/// </summary>
internal static class HelperE2eSelfTest
{
    internal static int Run(string[] args)
    {
        string? runtime = Arg(args, "--runtime"), git = Arg(args, "--git"), repo = Arg(args, "--repo"), outPath = Arg(args, "--out");
        if (runtime is null || git is null || repo is null) { Console.Error.WriteLine("usage: self-test-helper-e2e --runtime <root> --git <rel> --repo <repository> [--out <file>]"); return 2; }
        string scratch = Path.Combine(Path.GetTempPath(), "cp-e2e-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        StorePaths.OverrideRootForSelfTest(scratch);
        Directory.CreateDirectory(StorePaths.IntentsDir);
        Directory.CreateDirectory(StorePaths.ExportsRoot);
        string me = WindowsIdentity.GetCurrent().User!.Value;
        CustodianConfig.AllowAnyHelperSidForSelfTest();
        WindowsEngineRuntime.SkipAclCheckForSelfTest();
        new CustodianConfig { OperatorSid = me, ImplementerSid = me, HelperSid = me }.Save();
        int failed = 0;
        using var cts = new CancellationTokenSource();
        try
        {
            var led = new GrantLedger("cust-e2e");
            var checks = new JsonObject { ["test"] = ConfigFixture.Definition("TEST"), ["unit"] = ConfigFixture.Definition("UNIT") };
            ((JsonArray)((JsonObject)checks["unit"]!)["freshness_inputs"]!).Add("package.json");
            ConfigFixture.Set(led, repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(Path.GetDirectoryName(scratch)!), checks));
            ConfigFixture.Confirm(led, selftestId: "st-1");
            string rid = "e2e-runtime";
            led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Set, null, new JsonObject { ["path"] = runtime, ["git"] = git }, GrantLedger.ReadConfigRecordsLocked().GlobalRevision, rid);
            led.Commit(rid, "proof-e2e");

            var broker = new HelperBroker(new NoStarter()) { AttachTimeout = TimeSpan.FromSeconds(30) };
            var core = new CustodianCore(me, broker, new Principal(me, me));
            var server = new PipeServer(core, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load(), broker);
            Task serving = server.RunAsync(cts.Token);
            Thread.Sleep(800);
            var agent = new HelperAgent(new SecurityIdentifier(me), TimeSpan.FromMinutes(5), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            Task agentRun = agent.RunAsync(cts.Token);

            Response refusedImpl = core.Handle(CallerClass.Implementer, new Request(1, "e2e-impl", "helper_check", new JsonObject { ["repositoryRoot"] = repo }), null);
            failed += HelperChannelSelfTest.Check("helper_check is operator-only (the implementer is refused)", !refusedImpl.Ok && refusedImpl.Code == ErrorCodes.CallerNotAuthorized);

            Response r = core.Handle(CallerClass.Operator, new Request(1, "e2e-1", "helper_check", new JsonObject { ["repositoryRoot"] = repo, ["keep"] = true }), "proof-e2e");
            if (!r.Ok) Console.WriteLine($"helper_check refused: {r.Code}: {r.Error}");
            JsonObject d = r.Data ?? new JsonObject();
            if (outPath is not null) File.WriteAllText(outPath, d.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            JsonNode? cap = d["capture"], der = d["derive"];
            failed += HelperChannelSelfTest.Check($"a real capture through the helper is published by the custodian ({(string?)cap?["code"]} {(string?)cap?["detail"]})", (bool?)cap?["ok"] == true);
            string? exportPath = (string?)cap?["published"]?["exportPath"];
            failed += HelperChannelSelfTest.Check("the published export holds the manifest and the prepared diff the helper computed over the custodian's staging",
                exportPath is not null && File.Exists(Path.Combine(exportPath, "review", "manifest.json")) && File.Exists(Path.Combine(exportPath, "review", "diff.patch")));
            failed += HelperChannelSelfTest.Check("the helper's read access to the published export was removed", (bool?)cap?["published"]?["helperReadRemoved"] == true);
            failed += HelperChannelSelfTest.Check($"a real derivation through the helper is consumed ({(string?)der?["code"]} {(string?)der?["detail"]})", (bool?)der?["ok"] == true);
            failed += HelperChannelSelfTest.Check("the derivation measured the same source identity the capture recorded (unchanged repository)",
                (string?)der?["result"]?["measured"]?["sourceId"] is { Length: 64 } s && s == (string?)cap?["published"]?["sourceId"]);
            failed += HelperChannelSelfTest.Check("the derivation declares itself non-authoritative and nothing was committed",
                (bool?)der?["result"]?["scope"]?["authoritative"] == false && (bool?)d["committed"] == false);
            failed += HelperChannelSelfTest.Check("the per-request directories were removed (only the kept export remains)",
                Directory.GetDirectories(StorePaths.ExportsRoot).All(x => !x.EndsWith(".cfg", StringComparison.Ordinal)));

            // A changed runtime file refuses every measurement until it is approved again (no fallback).
            string entry = Path.Combine(runtime, "dist", "helper", "main.js");
            string original = File.ReadAllText(entry);
            File.AppendAllText(entry, "\n// tampered\n");
            try
            {
                Response t = core.Handle(CallerClass.Operator, new Request(1, "e2e-2", "helper_check", new JsonObject { ["repositoryRoot"] = repo }), "proof-e2e");
                failed += HelperChannelSelfTest.Check("a changed runtime file refuses the measurement (CONFIG_MISMATCH), nothing runs", !t.Ok && t.Code == ErrorCodes.ConfigMismatch);
            }
            finally { File.WriteAllText(entry, original); }

            failed += ProtectedReviewCases(broker, repo, (string?)cap?["published"]?["sourceId"]);

            Console.WriteLine($"\nhelper e2e self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
            return failed == 0 ? 0 : 1;
        }
        finally
        {
            cts.Cancel();
            try { Directory.Delete(Path.GetDirectoryName(scratch)!, true); } catch { }
        }
    }

    private sealed class NoStarter : IHelperStarter { public void EnsureRunning() { } }

    // ---- P3.4C-5 Increment 2: a protected review captured by the custodian through the real helper ----

    private const long Second = 10_000_000;
    private static readonly long T0 = DateTime.UtcNow.AddMinutes(-10).ToFileTimeUtc();

    /// <summary>A fixed process table (the session's Claude process 100, the engine 200 that writes, its pipe client 300).</summary>
    private sealed class Procs : IProcessTable
    {
        public IReadOnlyDictionary<int, ProcEntry>? Snapshot() => new Dictionary<int, ProcEntry>
        {
            [100] = new(100, 1, T0, "claude.exe"), [200] = new(200, 100, T0 + 10 * Second, "node.exe"), [300] = new(300, 200, T0 + 11 * Second, "powershell.exe"),
        };
    }

    /// <summary>
    /// §3.1 end to end with the real capture: a reservation on a protected run; the custodian's background measurement runs
    /// the REAL capture workload through the helper (the approved runtime, re-measured), validates and publishes it to the
    /// reader, commits it (captured: the custodian's source id, digests and review input id); the finish re-hashes the
    /// export and accepts. The same inputs again are deduplicated at the commit (the export removed, the budget released);
    /// a published file changed during a review makes it not accepted; a reservation abandoned while it is captured is
    /// cancelled and commits nothing.
    /// </summary>
    private static int ProtectedReviewCases(HelperBroker broker, string repo, string? selection)
    {
        int failed = 0;
        var me = WindowsIdentity.GetCurrent().User!;
        var led = new GrantLedger("cust-e2e", new Procs());
        led.AttachCapture(new HelperCaptureRunner(broker), new Principal(me.Value, me.Value), new Principal(me.Value, me.Value));
        var engine = new LoopCaller(false, "proof-implementer", 300);
        const string Run = "run-e2e-review";
        string grant = "e2e-grant";
        led.PrepareGrant(repo, 2, 60, grant);
        led.Commit(grant, "proof-e2e");
        JsonObject Do(string kind, JsonObject f) => led.RunTransition(engine, repo, RunRequest.Parse(Run, kind, f, "e2e-" + kind + "-" + Guid.NewGuid().ToString("N")[..8]));
        Do("open", RunSelfTest.DefaultOpenFields());
        JsonObject c = led.ConsumeLoop(repo, Run, "e2e-consume");
        led.LoopTransition(engine, repo, LoopRequest.Parse(Run, (string)c["loopId"]!, 1, 1, "bind",
            new JsonObject { ["bindNonce"] = (string)c["bindNonce"]!, ["session_id"] = "s-e2e", ["process"] = new JsonObject { ["pid"] = 100 } }, "e2e-bind"));
        string hex = new('6', 64);
        JsonObject Reserve(string reviewId, string versions) => new()
        {
            ["operationKind"] = "review", ["reviewId"] = reviewId, ["selectionSourceId"] = selection ?? hex, ["target"] = new JsonObject { ["kind"] = "uncommitted" },
            ["checkExecutionIds"] = new JsonArray(), ["checkEvidenceDigest"] = hex, ["checkResultsDigest"] = hex,
            ["discussion"] = new JsonObject { ["offered"] = new JsonArray() }, ["amendments"] = new JsonObject { ["offered"] = new JsonArray() },
            ["isolation"] = ConfigFixture.Isolation(), ["captureRulesDigest"] = ConfigFixture.CaptureRulesDigest, ["codexSha256"] = ConfigFixture.CodexSha256,
            ["depth"] = "standard", ["focusDigest"] = null, ["versionsDigest"] = versions,
        };
        JsonObject Finish(string op, string status = "completed") => new()
        {
            ["operationId"] = op,
            ["outcome"] = new JsonObject
            {
                ["status"] = status, ["outputValid"] = status == "completed", ["currentAtCompletion"] = true, ["verdict"] = "APPROVE", ["summaryDigest"] = hex,
                ["artifacts"] = new JsonObject { ["rawOutput"] = hex, ["output"] = hex, ["items"] = hex, ["result"] = hex, ["events"] = hex, ["stderr"] = null, ["lastMessage"] = null },
                ["newItems"] = new JsonArray(), ["assessments"] = new JsonArray(), ["replies"] = new JsonArray(), ["incidents"] = new JsonArray(),
            },
            ["promptDigest"] = status == "completed" ? hex : null,
            ["presented"] = status == "completed" ? RunSelfTest.EmptyPresented() : null,
        };
        RunOperation Await(string op)
        {
            string key = RepoIdentities.Resolve(repo).Key;
            for (int i = 0; i < 1200; i++)
            {
                RunOperation o = GrantLedger.ReadRunLocked(key, Run)!.Operations.First(x => x.OperationId == op);
                if (o.Status != RunOperationStatuses.Measuring) return o;
                Thread.Sleep(250);
            }
            return GrantLedger.ReadRunLocked(key, Run)!.Operations.First(x => x.OperationId == op);
        }
        int Dirs() => Directory.GetDirectories(StorePaths.ExportsRoot).Length;
        bool NoStaging() => Directory.GetDirectories(StorePaths.ExportsRoot).All(x => !x.EndsWith(".staging", StringComparison.Ordinal) && !x.EndsWith(".cfg", StringComparison.Ordinal));

        int before = Dirs();
        JsonObject b1 = Do("op_begin", Reserve("rv-1", hex));
        string op1 = (string)b1["operationId"]!;
        failed += HelperChannelSelfTest.Check("a protected review reserves: op_begin returns measuring with a ticket, at once", (string?)b1["operationStatus"] == RunOperationStatuses.Measuring && b1["ticket"] is not null);
        RunOperation o1 = Await(op1);
        JsonObject? cc = o1.Begin["custodianCapture"] as JsonObject;
        failed += HelperChannelSelfTest.Check($"the custodian captured it through the real helper: captured, its own source id (= the selected source), digests and review input id ({o1.Status} {o1.Outcome?.ToJsonString()})",
            o1.Status == RunOperationStatuses.Captured && (string?)o1.Begin["sourceId"] == selection && o1.Begin["reviewInputId"] is not null && o1.Begin["exportDigest"] is not null && cc is not null);
        string? export = (string?)cc?["exportPath"], capture = (string?)cc?["capturePath"];
        failed += HelperChannelSelfTest.Check("the published export holds the manifest and the prepared diff; the capture record sits beside it (outside the reviewer's root) with the digest the custodian recorded",
            export is not null && File.Exists(Path.Combine(export, "review", "manifest.json")) && File.Exists(Path.Combine(export, "review", "diff.patch"))
            && capture is not null && Path.GetDirectoryName(capture) == Path.GetDirectoryName(export)
            && Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(capture))) == (string?)o1.Begin["captureDigest"]);
        failed += HelperChannelSelfTest.Check("no staging or per-request directory remains (one published capture added)", Dirs() == before + 1 && NoStaging());
        JsonObject f1 = Do("op_finish", Finish(op1));
        failed += HelperChannelSelfTest.Check("the finish re-hashes the published export (unchanged) and the custodian accepts the review", (bool?)f1["accepted"] == true);

        JsonObject b2 = Do("op_begin", Reserve("rv-2", hex));
        RunOperation o2 = Await((string)b2["operationId"]!);
        failed += HelperChannelSelfTest.Check($"the same inputs again: deduplicated at the commit (of rv-1), the export removed, the budget released ({o2.Status})",
            o2.Status == RunOperationStatuses.Deduplicated && (string?)o2.Outcome?["deduplicatedOf"] == "rv-1" && Dirs() == before + 1
            && GrantLedger.ReadRunLocked(RepoIdentities.Resolve(repo).Key, Run)!.Reviews.Count == 1);

        JsonObject b3 = Do("op_begin", Reserve("rv-3", new string('7', 64)));
        RunOperation o3 = Await((string)b3["operationId"]!);
        string? export3 = (string?)o3.Begin["custodianCapture"]?["exportPath"];
        if (export3 is not null) File.AppendAllText(Path.Combine(export3, "review", "manifest.json"), " ");
        JsonObject f3 = Do("op_finish", Finish((string)b3["operationId"]!));
        failed += HelperChannelSelfTest.Check("a published file changed during the review: the custodian's re-hash makes it not accepted (export_modified_during_review, a custodian incident)",
            o3.Status == RunOperationStatuses.Captured && (bool?)f3["accepted"] == false
            && f3["notAcceptedReasons"]!.AsArray().Any(x => (string?)x == "incident:export_modified_during_review"));

        JsonObject b4 = Do("op_begin", Reserve("rv-4", new string('8', 64)));
        JsonObject f4 = Do("op_finish", Finish((string)b4["operationId"]!, "cancelled"));
        for (int i = 0; i < 480 && !NoStaging(); i++) Thread.Sleep(250);
        RunOperation o4 = GrantLedger.ReadRunLocked(RepoIdentities.Resolve(repo).Key, Run)!.Operations.First(x => x.OperationId == (string)b4["operationId"]!);
        failed += HelperChannelSelfTest.Check($"a review abandoned while it is captured is cancelled; nothing is committed later, no staging is left ({o4.Status})",
            (string?)f4["operationStatus"] == RunOperationStatuses.Cancelled && o4.Status == RunOperationStatuses.Cancelled && NoStaging());
        return failed;
    }


    private static string? Arg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
