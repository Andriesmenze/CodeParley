using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>What a synthetic capture produces (self-tests and the shared run corpus): the measured source (default: the
/// source the reservation selected), whether the tree was stable, and a failure to model instead of a capture —
/// <c>timeout</c>, <c>helper</c> (the workload failed), <c>runtime</c> (the runtime differs from the approved one),
/// <c>cancelled</c>, <c>frame_outside_manifest</c> / <c>frame_hash</c> / <c>withheld</c> (frames the custodian's validation
/// refuses: a file the manifest does not list, a claimed hash that is not the bytes', a withheld path in the export) and
/// <c>export_digest</c> (the helper claims an export digest that is not the custodian's for the same bytes; N5-12). With
/// <c>Tree</c> (Phase 4 Increment 2) the export also carries <see cref="CaptureFixture.TreeFiles"/> (a delegated fix's baseline).</summary>
internal sealed record SyntheticCapture(string? SourceId = null, bool Stable = true, string? Fail = null, bool Tree = false);

/// <summary>
/// NON-PRIVILEGED self-test fixture (P3.4C-5 Increment 2): the custodian's review capture without the helper service. The
/// ledger under test reserves, validates, publishes, re-hashes and commits exactly as in the service; only the runner is
/// synthetic — it streams a minimal, deterministic capture (a manifest listing one context file, the file, a record) into
/// the custodian's <see cref="CaptureJob"/> as the helper's frames would. The same capture is built by the TypeScript
/// simulator for the shared corpus, so the custodian's review input identity is the same on both sides.
/// </summary>
internal static class CaptureFixture
{
    internal static string RuntimeGit => Platform.Images.FixtureRuntimeGit;

    /// <summary>The synthetic capture's one exported file (<c>context/README.md</c>).</summary>
    internal static readonly byte[] ContextFile = Encoding.UTF8.GetBytes("# corpus\n");

    /// <summary>Phase 4 Increment 2: the synthetic capture's <c>tree</c> files, exported with <c>Tree</c> (the TypeScript
    /// simulator's SYNTHETIC_TREE_FILES).</summary>
    internal static readonly (string Path, byte[] Bytes)[] TreeFiles =
    [
        (".github/workflows/ci.yml", Encoding.UTF8.GetBytes("on: push\n")),
        ("docs/guide.md", Encoding.UTF8.GetBytes("# Guide\n")),
        ("src/app.ts", Encoding.UTF8.GetBytes("export const answer = 41;\n")),
        ("src/util.ts", Encoding.UTF8.GetBytes("export const twice = (n: number): number => n * 2;\n")),
    ];

    /// <summary>Approve a synthetic engine runtime in <paramref name="scratch"/> (once per store) and attach the manual,
    /// synthetic capture to <paramref name="led"/>: a reservation waits until <see cref="Run"/> captures it.</summary>
    internal static void Enable(GrantLedger led, string scratch)
    {
        Platform.Images.SkipOwnershipChecksForSelfTest();
        Directory.CreateDirectory(StorePaths.ExportsRoot);
        if (GrantLedger.ReadConfigRecordsLocked().CurrentRuntime is not { RevokedAt: null, LapsedAtRecoveryId: null }) ApproveRuntime(led, scratch);
        Principal me = Platform.CurrentUser();
        led.AttachCapture(new SyntheticCaptureRunner(new SyntheticCapture(), null), me, me, manual: true);
        Measurements = new SyntheticMeasurementRunner();
        led.AttachMeasurement(Measurements);
    }

    /// <summary>The synthetic measurement runner the latest <see cref="Enable"/> attached (P3.4C-5 Increment 3): what it
    /// measures and derives is set through its <see cref="SyntheticMeasurementRunner.Spec"/>.</summary>
    internal static SyntheticMeasurementRunner Measurements { get; private set; } = new();

    /// <summary>Run the check measurement reserved for <paramref name="operationId"/> (a checks operation's start or an
    /// execution's end); returns the commit's result (the run's last <c>check_measure</c>/<c>check_record</c> event), or null
    /// when none was waiting.</summary>
    internal static JsonObject? Measure(GrantLedger led, string repo, string run, string operationId)
    {
        if (!led.RunReservedCheckMeasurement(operationId)) return null;
        RunEvent? e = GrantLedger.ReadRunLocked(RepoIdentities.Resolve(repo).Key, run)?.Events.LastOrDefault(x => x.Kind is "check_measure" or "check_record");
        return (JsonObject?)e?.Result?.DeepClone();
    }

    /// <summary>A synthetic runtime tree (node.exe and git as PE images, the helper entry) approved through the operator's
    /// prepare→commit. Returns the runtime id.</summary>
    internal static string ApproveRuntime(GrantLedger led, string scratch, byte variant = 0)
    {
        string root = Directory.CreateDirectory(Path.Combine(scratch, "engine-runtime-" + variant)).FullName;
        File.WriteAllBytes(Path.Combine(root, Platform.Images.NodeName), Platform.Images.FixtureImage(variant));
        string git = Path.Combine(root, RuntimeGit.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(git)!);
        File.WriteAllBytes(git, Platform.Images.FixtureImage((byte)(variant + 1)));
        Directory.CreateDirectory(Path.Combine(root, "dist", "helper"));
        File.WriteAllText(Path.Combine(root, "dist", "helper", "main.js"), "// synthetic helper entry\n");
        string rid = ConfigFixture.Rid("runtime");
        led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Set, null, new JsonObject { ["path"] = root, ["git"] = RuntimeGit }, ConfigFixture.GlobalRevision(), rid);
        return (string)led.Commit(rid, null)["recordId"]!;
    }

    /// <summary>Capture the review reserved as <paramref name="operationId"/> with <paramref name="spec"/>; returns the
    /// commit's result (the run's last <c>capture</c> event), or null when no capture of that operation was waiting.</summary>
    internal static JsonObject? Run(GrantLedger led, string repo, string run, string operationId, SyntheticCapture? spec = null)
    {
        string key = RepoIdentities.Resolve(repo).Key;
        RunRecord? rec = GrantLedger.ReadRunLocked(key, run);
        string? selection = (string?)rec?.Operations.FirstOrDefault(o => o.OperationId == operationId)?.Begin["selectionSourceId"];
        led.SetCaptureRunnerForTest(new SyntheticCaptureRunner(spec ?? new SyntheticCapture(), selection));
        if (!led.RunReservedCapture(operationId)) return null;
        RunEvent? e = GrantLedger.ReadRunLocked(key, run)?.Events.LastOrDefault(x => x.Kind == "capture");
        return (JsonObject?)e?.Result?.DeepClone();
    }

    /// <summary>Change one published file of a captured review (a bypass of the export's access control, modelled by
    /// the custodian's own identity).</summary>
    internal static void Tamper(string repo, string run, string operationId)
    {
        RunRecord rec = GrantLedger.ReadRunLocked(RepoIdentities.Resolve(repo).Key, run)!;
        string export = (string)rec.Operations.First(o => o.OperationId == operationId).Begin["custodianCapture"]!["exportPath"]!;
        File.AppendAllText(Path.Combine(export, "context", "README.md"), "tampered\n");
    }

    /// <summary>The synthetic manifest of a capture of <paramref name="sourceId"/> (as the TypeScript simulator builds it).</summary>
    internal static JsonObject Manifest(string captureId, string sourceId, bool tree = false)
    {
        var files = new JsonArray(new JsonObject
        {
            ["area"] = "context", ["path"] = "README.md", ["size"] = (long)ContextFile.Length, ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(ContextFile)),
        });
        if (tree)
            foreach ((string path, byte[] bytes) in TreeFiles)
                files.Add(new JsonObject { ["area"] = "tree", ["path"] = path, ["size"] = (long)bytes.Length, ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(bytes)) });
        var m = new JsonObject
        {
            ["schema"] = "arl.corpus-capture.v1",
            ["capture_id"] = captureId,
            ["source_id"] = sourceId,
            ["files"] = files,
            ["review_files"] = new JsonObject { ["base"] = new JsonArray(), ["head"] = new JsonArray() },
        };
        m["manifest_digest"] = EngineJson.Digest(m);
        return m;
    }
}

/// <summary>The synthetic capture runner: the helper's frames for <see cref="CaptureFixture.Manifest"/>, or the failure
/// the spec names.</summary>
internal sealed class SyntheticCaptureRunner(SyntheticCapture spec, string? selectionSource) : IReviewCaptureRunner
{
    public Task<HelperJobOutcome> RunAsync(CaptureLaunch l, CaptureJob job, CancellationToken ct)
    {
        switch (spec.Fail)
        {
            case "timeout": return Task.FromResult(new HelperJobOutcome(false, ErrorCodes.MeasurementTimeout, "synthetic: the helper did not finish", "t-synthetic", null));
            case "helper": return Task.FromResult(new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, "synthetic: the workload failed", "t-synthetic", null));
            case "runtime": return Task.FromResult(new HelperJobOutcome(false, ErrorCodes.ConfigMismatch, "synthetic: the engine runtime differs from the one approved", "", null));
            case "cancelled": return Task.FromResult(new HelperJobOutcome(false, ErrorCodes.MeasurementCancelled, "synthetic: cancelled", "t-synthetic", null));
        }
        string captureId = (string)l.Workload["operationId"]!;
        string source = spec.SourceId ?? selectionSource ?? new string('0', 64);
        JsonObject manifest = CaptureFixture.Manifest(captureId, source, spec.Tree);
        byte[] file = CaptureFixture.ContextFile;
        string fileSha = spec.Fail == "frame_hash" ? new string('e', 64) : Convert.ToHexStringLower(SHA256.HashData(file));
        string path = spec.Fail == "frame_outside_manifest" ? "OTHER.md" : "README.md";
        Feed(job, "context", path, file, fileSha);
        var exported = new List<(string, long, string)> { ("context/" + path, file.LongLength, Convert.ToHexStringLower(SHA256.HashData(file))) };
        if (spec.Tree)
            foreach ((string tp, byte[] tb) in CaptureFixture.TreeFiles)
            {
                string sha = Convert.ToHexStringLower(SHA256.HashData(tb));
                Feed(job, "tree", tp, tb, sha);
                exported.Add(("tree/" + tp, tb.LongLength, sha));
            }
        job.OnStageComplete();
        byte[] mbytes = Encoding.UTF8.GetBytes(manifest.ToJsonString());
        Feed(job, "review", "manifest.json", mbytes, Convert.ToHexStringLower(SHA256.HashData(mbytes)));
        var entries = new JsonArray();
        if (spec.Fail == "withheld") entries.Add(new JsonObject { ["path"] = "README.md", ["class"] = "excluded" });
        var record = new JsonObject
        {
            ["capture_id"] = captureId, ["source_id"] = source, ["stable"] = spec.Stable, ["entries"] = entries, ["changes"] = new JsonArray(),
        };
        exported.Add(("review/manifest.json", mbytes.LongLength, Convert.ToHexStringLower(SHA256.HashData(mbytes))));
        string exportDigest = ExportPaths.ExportDigest(exported);
        var result = new JsonObject
        {
            // export_digest (N5-12): the helper claims another export digest for the very bytes it sent.
            ["record"] = record, ["sourceId"] = source, ["exportDigest"] = spec.Fail == "export_digest" ? new string('e', 64) : exportDigest, ["manifestDigest"] = (string)manifest["manifest_digest"]!,
        };
        job.OnResult(Encoding.UTF8.GetBytes(result.ToJsonString()));
        return Task.FromResult(new HelperJobOutcome(true, null, null, "t-synthetic", new JsonObject { ["exitCode"] = 0 }));
    }

    private static void Feed(CaptureJob job, string area, string path, byte[] body, string sha)
        => job.OnFile(new HelperFrame(new JsonObject { ["t"] = "file", ["area"] = area, ["path"] = path, ["size"] = (long)body.Length, ["sha256"] = sha }, body));
}

/// <summary>What a synthetic measurement produces (P3.4C-5 Increment 3): the measured source and its stability, a failure
/// to model (<c>timeout</c>, <c>helper</c>, <c>runtime</c>, <c>cancelled</c>), per-check freshness digests (default: one
/// per check name), and for a derivation its route and progress fingerprint (default: an implementer step, and a digest
/// of the snapshot's work facts).</summary>
internal sealed record SyntheticMeasurement(
    string SourceId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", bool Stable = true, string? Fail = null,
    string RouteKind = "implementer_step", string RouteCode = "address_findings", string? Fingerprint = null, IReadOnlyDictionary<string, string>? Freshness = null,
    IReadOnlyList<string>? ReadWithheld = null);

/// <summary>The synthetic measurement runner: a measurement of every requested check (and, with a snapshot, a derivation)
/// as the helper's <c>derive</c> workload would return it, or the failure the spec names.</summary>
internal sealed class SyntheticMeasurementRunner : IMeasurementRunner
{
    internal SyntheticMeasurement Spec { get; set; } = new();
    internal int Runs { get; private set; }

    internal static string FreshnessOf(string check) => Ledger.Digest.Sha256Hex("synthetic-freshness:" + check);
    internal static string SpecOf(string check) => Ledger.Digest.Sha256Hex("synthetic-spec:" + check);

    public Task<MeasureOutcome> RunAsync(MeasureLaunch l, CancellationToken ct)
    {
        Runs++;
        SyntheticMeasurement s = Spec;
        switch (s.Fail)
        {
            case "timeout": return Task.FromResult(MeasureOutcome.Failed(ErrorCodes.MeasurementTimeout, "synthetic: the helper did not finish"));
            case "helper": return Task.FromResult(MeasureOutcome.Failed(ErrorCodes.MeasurementFailed, "synthetic: the workload failed"));
            case "runtime": return Task.FromResult(MeasureOutcome.Failed(ErrorCodes.ConfigMismatch, "synthetic: the engine runtime differs from the one approved"));
            case "cancelled": return Task.FromResult(MeasureOutcome.Failed(ErrorCodes.MeasurementCancelled, "synthetic: cancelled"));
        }
        var checks = new JsonArray();
        foreach (JsonObject c in (l.Workload["checks"] as JsonArray ?? []).OfType<JsonObject>())
        {
            string name = (string)c["name"]!;
            string? exe = (string?)c["executable"];
            checks.Add(new JsonObject
            {
                ["name"] = name, ["freshnessDigest"] = s.Freshness?.GetValueOrDefault(name) ?? FreshnessOf(name),
                ["executable"] = exe is null ? null : new JsonObject { ["path"] = exe, ["kind"] = "native", ["size"] = 1, ["mtimeMs"] = 1 },
                ["checkSpecId"] = SpecOf(name), ["problem"] = null,
            });
        }
        var measured = new JsonObject { ["sourceId"] = s.SourceId, ["stable"] = s.Stable, ["rootCommit"] = null, ["checks"] = checks };
        JsonObject? derivation = null;
        if (l.Workload["snapshot"] is JsonObject snap)
        {
            JsonObject? run = snap["run"] as JsonObject;
            string fingerprint = s.Fingerprint ?? EngineJson.Digest(new JsonObject
            {
                ["source"] = s.Stable ? s.SourceId : null,
                ["executions"] = new JsonArray([.. (run?["checkExecutions"] as JsonArray ?? []).OfType<JsonObject>().Select(e => (JsonNode)new JsonArray((string?)e["check"], (string?)e["executionInputId"], (string?)e["status"]))]),
                ["items"] = new JsonArray([.. (run?["items"] as JsonArray ?? []).OfType<JsonObject>().Select(i => (JsonNode)new JsonArray((string?)i["itemId"], (string?)i["status"], (string?)i["triage"]))]),
                ["responses"] = new JsonArray([.. (run?["responses"] as JsonArray ?? []).OfType<JsonObject>().Select(r => (JsonNode)new JsonArray((string?)r["itemId"], (string?)r["disposition"]))]),
                ["reviews"] = new JsonArray([.. (run?["reviews"] as JsonArray ?? []).OfType<JsonObject>().Where(r => (bool?)r["accepted"] == true).Select(r => (JsonNode)new JsonArray((string?)r["bindings"]?["reviewInputId"], (string?)r["verdict"]))]),
                ["user"] = new JsonArray([.. (snap["user"]?["records"] as JsonArray ?? []).OfType<JsonObject>().Select(u => (JsonNode)new JsonArray((string?)u["recordId"], (string?)u["kind"]))]),
            });
            derivation = new JsonObject
            {
                ["schema"] = "arl.protected-derivation.v1",
                ["completion"] = new JsonObject { ["state"] = s.RouteKind == "end" ? "ready" : "needs_implementer", ["ready"] = s.RouteKind == "end", ["blockers"] = new JsonArray(), ["counts"] = new JsonObject() },
                ["route"] = new JsonObject { ["code"] = s.RouteCode, ["kind"] = s.RouteKind, ["reason"] = "synthetic" },
                ["floor"] = null,
                ["currentSourceId"] = s.Stable ? s.SourceId : null,
                ["progressFingerprint"] = fingerprint,
                ["inputDigest"] = EngineJson.Digest(new JsonObject { ["snapshot"] = snap.DeepClone(), ["measured"] = measured.DeepClone() }),
            };
        }
        // Phase 5 F-i2-5: a synthetic redaction withholds the names the read withholds (default: the word "confidential", a
        // stand-in for a withheld name) and every name a held disclosure record withholds; it returns the read's
        // disclosure record as the helper does.
        JsonObject? redaction = l.Workload["redact"] is JsonObject rq
            ? s.Stable
                ? SyntheticRedaction(rq, s)
                : new JsonObject { ["ok"] = false, ["error"] = "the working tree changed while it was being read" }
            : null;
        return Task.FromResult(new MeasureOutcome(true, null, null, measured, derivation, redaction));
    }

    private static JsonObject SyntheticRedaction(JsonObject rq, SyntheticMeasurement s)
    {
        IReadOnlyList<string> read = s.ReadWithheld ?? ["confidential"];
        var names = new SortedSet<string>(read, StringComparer.Ordinal);
        foreach (JsonObject e in (rq["evidence"] as JsonArray ?? []).OfType<JsonObject>())
            if ((string?)e["kind"] == "disclosure" && JsonNode.Parse((string)e["text"]!)?["withheld_paths"] is JsonArray paths)
                foreach (JsonNode? p in paths) names.Add((string)p!);
        string text = (string?)rq["text"] ?? "";
        foreach (string n in names.OrderByDescending(n => n.Length)) text = text.Replace(n, "[withheld]", StringComparison.Ordinal);
        string disclosure = new JsonObject
        {
            ["schema"] = "arl.response-disclosure.v1", ["withheld_paths"] = new JsonArray([.. read.Order(StringComparer.Ordinal).Select(p => (JsonNode)p)]),
            ["withheld_hashes"] = new JsonArray(), ["repo_context"] = new JsonArray(),
        }.ToJsonString();
        return new JsonObject { ["ok"] = true, ["redacted"] = text, ["sourceId"] = s.SourceId, ["redactions"] = 0, ["disclosure"] = disclosure };
    }
}
