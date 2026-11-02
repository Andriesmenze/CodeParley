using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>The engine's export path rules (src/capture/export-writer.ts exportPathProblem, src/workspace/win-paths.ts
/// windowsSegmentProblem, src/capture/enumerate.ts looksLikeShortName), enforced again by the custodian on every file the
/// helper streams.</summary>
internal static partial class ExportPaths
{
    [GeneratedRegex("[<>\"|*?\\u0000-\\u001f]")] private static partial Regex InvalidChars();
    [GeneratedRegex("^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]|CONIN\\$|CONOUT\\$)$", RegexOptions.IgnoreCase)] private static partial Regex ReservedDevice();
    [GeneratedRegex("^[^.~]{1,6}~\\d{1,6}(\\.[^.]{0,3})?$")] private static partial Regex ShortName();

    internal static string? Problem(string repoRel)
    {
        if (repoRel.Length is 0 or > 4096) return "empty or too long";
        foreach (string seg in repoRel.Split('/'))
        {
            if (seg.Length == 0) return "empty segment";
            if (seg is "." or "..") return "dot segment";
            if (InvalidChars().IsMatch(seg)) return "control or invalid character";
            if (seg.Contains(':')) return "':' (alternate data stream)";
            if (seg.Contains('\\')) return "backslash";
            if (seg.EndsWith(' ') || seg.EndsWith('.')) return "ends with space or dot";
            if (ReservedDevice().IsMatch(seg.Split('.')[0])) return "reserved device name";
            if (seg.Equals(".git", StringComparison.OrdinalIgnoreCase)) return ".git segment";
            if (ShortName().IsMatch(seg)) return "possible 8.3 short-name alias";
        }
        return null;
    }

    /// <summary>The engine's export digest (<c>exportDigestOf</c>): SHA-256 over the canonical JSON of every file's
    /// export-relative path, size and SHA-256, sorted by path in UTF-16 code-unit order.</summary>
    internal static string ExportDigest(IEnumerable<(string Rel, long Size, string Sha256)> files)
    {
        var rows = new JsonArray();
        foreach (var f in files.OrderBy(f => f.Rel, StringComparer.Ordinal)) rows.Add(new JsonArray(f.Rel, f.Size, f.Sha256));
        return Digest.Sha256Hex(EngineJson.Canonical(new JsonObject { ["schema"] = "arl.export-digest.v1", ["files"] = rows }));
    }
}

/// <summary>
/// P3.4C-5 (§3.2, §A.2): the custodian side of a helper capture. Every streamed file is validated (area, path rules,
/// uniqueness, its claimed size and SHA-256 against the custodian's own hash of the bytes, the per-file and total caps)
/// and written by the CUSTODIAN into the ticket's staging directory (the helper writes nothing). The helper then reads
/// <c>review/base</c> and <c>review/head</c> there (read-only) for the prepared diff and streams the diff and the manifest.
/// <see cref="Publish"/> checks the manifest against what the custodian wrote (every listed file present with its size and
/// hash, nothing unlisted, no withheld path), computes the export digest itself, removes the helper's read access and
/// re-hashes everything it published.
/// </summary>
internal sealed class CaptureJob(string stagingDir, ConfigCaptureRules rules) : IHelperJobHandler
{
    private static readonly HashSet<string> Areas = new(StringComparer.Ordinal) { "tree", "context", "review/base", "review/head", "review" };
    private readonly Dictionary<string, (string Rel, long Size, string Sha256)> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _areaBytes = new(StringComparer.Ordinal);
    private bool _staged;

    internal string StagingDir { get; } = stagingDir;
    internal byte[]? Result { get; private set; }
    /// <summary>After <see cref="Publish"/>: the capture record and the manifest the custodian validated.</summary>
    internal JsonObject? Record { get; private set; }
    internal JsonObject? Manifest { get; private set; }

    public long MaxFrameBody => FrameCap(rules);

    internal static long FrameCap(ConfigCaptureRules r)
        => Math.Min(CustodianConstants.MaxHelperBodyBytes, Math.Max(Math.Max(r.MaxFileBytes, r.MaxDiffBytes + (1L << 20)), 64L << 20));

    public void OnFile(HelperFrame f)
    {
        string area = f.Str("area") ?? throw new HelperFrameError("a file frame names no area");
        string path = f.Str("path") ?? throw new HelperFrameError("a file frame names no path");
        if (!Areas.Contains(area)) throw new HelperFrameError($"a file in an unknown area '{area}'");
        if (ExportPaths.Problem(path) is { } problem) throw new HelperFrameError($"refused export path: {problem}");
        if (area == "review" && path is not ("diff.patch" or "manifest.json")) throw new HelperFrameError("review/ holds only diff.patch and manifest.json");
        if (_staged && area != "review") throw new HelperFrameError("an export file after the staging was published");
        long size = f.Long("size") ?? -1;
        if (size != f.Body.Length) throw new HelperFrameError("a file's claimed size differs from its bytes");
        string sha = Convert.ToHexStringLower(SHA256.HashData(f.Body));
        if (f.Str("sha256") != sha) throw new HelperFrameError("a file's claimed SHA-256 differs from the custodian's hash of its bytes");
        long cap = (area, path) switch
        {
            ("review", "diff.patch") => rules.MaxDiffBytes + (1L << 20),
            ("review", _) => 64L << 20,
            _ => rules.MaxFileBytes,
        };
        if (size > cap) throw new HelperFrameError($"{area}/{path} is over its cap ({cap} bytes)");
        string bucket = area is "tree" or "context" ? "export" : area;
        long total = (_areaBytes.TryGetValue(bucket, out long t) ? t : 0) + size;
        if (bucket != "review" && total > rules.MaxExportBytes) throw new HelperFrameError($"the {bucket} files exceed max_export_bytes");
        _areaBytes[bucket] = total;
        string rel = area + "/" + path;
        if (!_files.TryAdd(rel, (rel, size, sha))) throw new HelperFrameError($"a duplicate export path: {rel}");
        if (_files.Count > 200_000) throw new HelperFrameError("too many export files");
        string full = Path.GetFullPath(Path.Combine(StagingDir, rel.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(StagingDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new HelperFrameError("an export path outside the staging");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        using var fs = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        fs.Write(f.Body);
        fs.Flush(flushToDisk: true);
    }

    public string OnStageComplete()
    {
        _staged = true;
        return StagingDir;
    }

    public void OnResult(byte[] json) => Result = json;

    /// <summary>Validate the capture against what the custodian wrote and publish it (see the class summary).</summary>
    internal JsonObject Publish(Principal helper)
    {
        if (Result is null) throw new HelperFrameError("no capture result");
        JsonObject res = JsonNode.Parse(Result) as JsonObject ?? throw new HelperFrameError("the capture result is not an object");
        var record = res["record"] as JsonObject ?? throw new HelperFrameError("the capture result carries no record");
        if (!_files.TryGetValue("review/manifest.json", out var manifestFile)) throw new HelperFrameError("the export has no manifest");
        JsonObject manifest = JsonNode.Parse(File.ReadAllBytes(Path.Combine(StagingDir, "review", "manifest.json"))) as JsonObject ?? throw new HelperFrameError("the manifest is not an object");
        string claimedManifestDigest = (string?)manifest["manifest_digest"] ?? throw new HelperFrameError("the manifest has no digest");
        var rest = (JsonObject)manifest.DeepClone();
        rest.Remove("manifest_digest");
        if (EngineJson.Digest(rest) != claimedManifestDigest) throw new HelperFrameError("the manifest's digest does not match its content");

        // Every listed file is present with its size and hash; nothing else is (the manifest itself aside).
        var expected = new Dictionary<string, (long Size, string Sha)>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonObject e in (manifest["files"] as JsonArray ?? []).OfType<JsonObject>()) expected[$"{(string?)e["area"]}/{(string?)e["path"]}"] = ((long?)e["size"] ?? -1, (string?)e["sha256"] ?? "");
        JsonObject rf = manifest["review_files"] as JsonObject ?? throw new HelperFrameError("the manifest has no review files");
        foreach (JsonObject e in (rf["base"] as JsonArray ?? []).OfType<JsonObject>()) expected[$"review/base/{(string?)e["path"]}"] = ((long?)e["size"] ?? -1, (string?)e["sha256"] ?? "");
        foreach (JsonObject e in (rf["head"] as JsonArray ?? []).OfType<JsonObject>()) expected[$"review/head/{(string?)e["path"]}"] = ((long?)e["size"] ?? -1, (string?)e["sha256"] ?? "");
        if (rf["diff_patch"] is JsonObject dp) expected["review/diff.patch"] = ((long?)dp["size"] ?? -1, (string?)dp["sha256"] ?? "");
        var written = _files.Values.Where(v => !v.Rel.Equals("review/manifest.json", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var (rel, size, sha) in written)
            if (!expected.TryGetValue(rel, out var want) || want.Size != size || want.Sha != sha) throw new HelperFrameError($"an export file is not in the manifest as written: {rel}");
        if (expected.Count != written.Count) throw new HelperFrameError("the manifest lists files that were not streamed");

        // No withheld (confidential) path appears anywhere in the export.
        var withheld = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonObject e in (record["entries"] as JsonArray ?? []).OfType<JsonObject>()) if ((string?)e["class"] == "excluded" && (string?)e["path"] is { } p) withheld.Add(p);
        foreach (JsonObject c in (record["changes"] as JsonArray ?? []).OfType<JsonObject>())
            if ((bool?)c["confidential"] == true) { if ((string?)c["path"] is { } p) withheld.Add(p); if ((string?)c["old_path"] is { } o) withheld.Add(o); }
        foreach (var (rel, _, _) in _files.Values)
        {
            string repoRel = rel.StartsWith("review/base/", StringComparison.Ordinal) || rel.StartsWith("review/head/", StringComparison.Ordinal) ? rel[12..] : rel[(rel.IndexOf('/') + 1)..];
            if (withheld.Contains(repoRel)) throw new HelperFrameError("a withheld (confidential) path is in the export");
        }

        string sourceId = (string?)record["source_id"] ?? "";
        if (sourceId.Length != 64 || (string?)manifest["source_id"] != sourceId || (string?)res["sourceId"] != sourceId) throw new HelperFrameError("the capture's source identity is inconsistent");
        string exportDigest = ExportPaths.ExportDigest(_files.Values);
        if ((string?)res["exportDigest"] != exportDigest) throw new HelperFrameError("the helper's export digest differs from the custodian's");
        if ((string?)res["manifestDigest"] != claimedManifestDigest) throw new HelperFrameError("the helper's manifest digest differs from the manifest");

        // Publish: the helper loses its read access; then everything published is hashed again from disk.
        bool helperRemoved = TicketDirs.Seal(StagingDir, helper);
        var reread = new List<(string, long, string)>();
        foreach (var (rel, _, _) in _files.Values)
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(StagingDir, rel.Replace('/', Path.DirectorySeparatorChar)));
            reread.Add((rel, bytes.LongLength, Convert.ToHexStringLower(SHA256.HashData(bytes))));
        }
        if (ExportPaths.ExportDigest(reread) != exportDigest) throw new HelperFrameError("the published export differs from what was written");
        Record = record;
        Manifest = manifest;
        return new JsonObject
        {
            ["sourceId"] = sourceId,
            ["stable"] = (bool?)record["stable"] ?? false,
            ["manifestDigest"] = claimedManifestDigest,
            ["exportDigest"] = exportDigest,
            ["recordSha256"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(record.ToJsonString()))),
            ["fileCount"] = _files.Count,
            ["totalBytes"] = _files.Values.Sum(f => f.Size),
            ["changes"] = (record["changes"] as JsonArray)?.Count ?? 0,
            ["entries"] = (record["entries"] as JsonArray)?.Count ?? 0,
            ["exportPath"] = StagingDir,
            ["helperReadRemoved"] = helperRemoved,
            ["captureTimingsMs"] = record["timings_ms"]?.DeepClone(),
            ["workloadIdentity"] = res["identity"]?.DeepClone(),
        };
    }
}

/// <summary>P3.4C-5 (§4, §5.1, §A.5): the custodian side of a <c>derive</c> workload — a measurement, with the protected
/// derivation when the custodian sent its snapshot: no file and no staging; one result, validated.</summary>
internal sealed class DeriveJob : IHelperJobHandler
{
    internal byte[]? Result { get; private set; }
    public long MaxFrameBody => 16L << 20;
    public void OnFile(HelperFrame file) => throw new HelperFrameError("a derivation streams no files");
    public string OnStageComplete() => throw new HelperFrameError("a derivation has no staging");
    public void OnResult(byte[] json) => Result = json;

    internal JsonObject Consume()
    {
        JsonObject r = JsonNode.Parse(Result ?? throw new HelperFrameError("no derivation result")) as JsonObject ?? throw new HelperFrameError("the derivation result is not an object");
        JsonObject m = r["measured"] as JsonObject ?? throw new HelperFrameError("the derivation has no measurement");
        static bool Hex(JsonNode? v) => v is JsonValue j && j.TryGetValue(out string? s) && s is { Length: 64 } && s.All(char.IsAsciiHexDigitLower);
        if (!Hex(m["sourceId"]) || m["stable"] is not JsonValue || m["checks"] is not JsonArray) throw new HelperFrameError("a malformed derivation measurement");
        if (r["derivation"] is JsonObject d)
        {
            if (d["completion"]?["state"] is not JsonValue || d["route"]?["code"] is not JsonValue || d["route"]?["kind"] is not JsonValue || !Hex(d["progressFingerprint"]) || !Hex(d["inputDigest"]))
                throw new HelperFrameError("a malformed derivation");
            if ((bool?)r["scope"]?["authoritative"] != true) throw new HelperFrameError("a protected derivation declares itself authoritative");
        }
        else if (r["derivation"] is not null) throw new HelperFrameError("a malformed derivation");
        // Phase 5 F-i2-5: a redaction is either produced (its text and the read it was produced against) or refused (why).
        if (r["redaction"] is JsonObject x)
        {
            bool produced = x["ok"] is JsonValue ok && ok.TryGetValue(out bool b) && b;
            if (produced ? x["redacted"] is not JsonValue || !Hex(x["sourceId"]) : x["error"] is not JsonValue)
                throw new HelperFrameError("a malformed redaction");
        }
        else if (r["redaction"] is not null) throw new HelperFrameError("a malformed redaction");
        return (JsonObject)r.DeepClone();
    }
}

/// <summary>The custodian's per-request directories under the export root: created by the custodian with a protected
/// DACL — SYSTEM, Administrators and the custodian full control, the helper read-and-execute only.</summary>
internal static class TicketDirs
{
    /// <summary>P3.4C-5 Increment 4: the directories a measurement in progress owns (created and not yet removed or
    /// committed); the retention sweep never removes them.</summary>
    private static readonly ConcurrentDictionary<string, byte> Live = new(StringComparer.OrdinalIgnoreCase);

    internal static string Create(string name, Principal helper)
    {
        if (!Directory.Exists(StorePaths.ExportsRoot))
            throw new CustodianRefusal(ErrorCodes.HelperUnavailable, $"the export root {StorePaths.ExportsRoot} does not exist; the operator installs the helper with {OperatorWording.InstallHelper}");
        string full = new DirectoryInfo(Path.Combine(StorePaths.ExportsRoot, name)).FullName;
        if (Directory.Exists(full)) throw new InvalidOperationException($"{full} already exists");
        Live[full] = 0;
        return Platform.Access.CreateExportDirectory(full, helper);
    }

    /// <summary>A directory a measurement in progress owns (it is about to be renamed into place, or not yet committed).</summary>
    internal static void MarkLive(string path) => Live[Path.GetFullPath(path)] = 0;

    /// <summary>The measurement no longer owns it: it is committed (and referenced by its record) or removed.</summary>
    internal static void Release(string path) => Live.TryRemove(Path.GetFullPath(path), out _);

    internal static bool IsLive(string path) => Live.ContainsKey(Path.GetFullPath(path));

    /// <summary>Drop the helper's access (publication) and verify the published files grant no one else (the host's ACL
    /// model, <see cref="IAccessPublisher.Seal"/>).</summary>
    internal static bool Seal(string path, Principal helper) => Platform.Access.Seal(path, helper);

    /// <summary>P3.4C-5 (§3.2): publish a ticket directory to the bound session's user read-only (the host's ACL model,
    /// <see cref="IAccessPublisher.Publish"/>).</summary>
    internal static void Publish(string path, Principal reader) => Platform.Access.Publish(path, reader);

    internal static void Remove(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch { /* no longer referenced: the retention sweep removes it at the next start or run opening */ }
        Release(path);
    }
}

internal sealed partial class GrantLedger
{
    /// <summary>
    /// P3.4C-5 Increment 1 (Amendment A §A.7): the operator-only diagnostic <c>helper_check</c>. On a repository with a
    /// usable protected configuration and an approved engine runtime it runs, through the real helper service, a REAL
    /// sanitizing review capture (published, validated and re-hashed by the custodian) and a REAL derivation (its
    /// measurement read and the engine's pure completion/routing core over the custodian's scrubbed snapshot of the
    /// run). It commits nothing — no record changes, no budget is used, no authority results — and takes the ledger lock
    /// only to read what it needs: the helper runs outside it (§2.4). The production triggers (op_begin reservations,
    /// the derivation section) are later increments.
    /// </summary>
    internal JsonObject HelperCheck(HelperBroker broker, Principal helper, string repositoryRoot, string? runId, JsonObject? target, bool keep)
    {
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        if (runId is not null) RunFields.RequireToken("runId", runId, 128);
        JsonObject captureTarget = target is null ? new JsonObject { ["kind"] = "uncommitted" } : ValidTarget(target);
        RepositoryConfig cfg;
        EngineRuntimeRecord rt;
        JsonObject? snapshot;
        JsonArray derChecks;
        lock (EnterGate())
        {
            ConfigRecordsFile file = ReadConfigRecords();
            cfg = RequireUsableConfig(id.Key, "a helper measurement");
            rt = file.CurrentRuntime ?? throw new CustodianRefusal(ErrorCodes.RuntimeNotApproved, "no engine runtime is approved; the operator approves one (prepare_config_record engine_runtime set) before any helper measurement");
            if (rt.RevokedAt is not null) throw new CustodianRefusal(ErrorCodes.RuntimeNotApproved, "the approved engine runtime was revoked; the operator approves one again");
            if (rt.LapsedAtRecoveryId is not null) throw new CustodianRefusal(ErrorCodes.ConfigLapsed, $"the engine runtime approval lapsed after a restart of the OS (recovery {rt.LapsedAtRecoveryId}); the operator re-confirms it (engine_runtime reconfirm {rt.RuntimeId})");
            // P3.4C-5 Increment 3: the derivation snapshot of the named run (its own floor unknown here: no run.json is
            // given to a diagnostic), or a measurement only without a run.
            RunRecord? run = runId is null ? null : ReadRun(id.Key, runId);
            snapshot = run is null ? null : DerivationSnapshot(id, run, null);
            derChecks = run is null
                ? new JsonArray([.. cfg.Checks.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => (JsonNode)new JsonObject { ["name"] = kv.Key, ["definition"] = kv.Value.Definition.DeepClone(), ["definitionDigest"] = kv.Value.DefinitionDigest, ["executable"] = null })])
                : DerivationChecks(run, cfg, snapshot!["executables"]!.AsObject());
        }
        if (Monitor.IsEntered(Gate)) throw new InvalidOperationException("the ledger lock is held across a helper invocation"); // §2.4

        var timer = System.Diagnostics.Stopwatch.StartNew();
        MeasuredRuntime m = EngineRuntime.Measure(rt.Root, rt.GitRelative, rt.GitPath);
        List<string> diff = EngineRuntime.Differences(rt.Measured, m);
        if (diff.Count > 0) throw new CustodianRefusal(ErrorCodes.ConfigMismatch, $"the engine runtime differs from the one approved ({string.Join(", ", diff)}); nothing was run — the operator approves it again");
        long runtimeMs = timer.ElapsedMilliseconds;

        var rules = new JsonObject
        {
            ["exclude_globs"] = new JsonArray([.. cfg.CaptureRules.ExcludeGlobs.Select(g => (JsonNode)g)]),
            ["context_include"] = new JsonArray([.. cfg.CaptureRules.ContextInclude.Select(g => (JsonNode)g)]),
            ["max_file_bytes"] = cfg.CaptureRules.MaxFileBytes, ["max_export_bytes"] = cfg.CaptureRules.MaxExportBytes, ["max_diff_bytes"] = cfg.CaptureRules.MaxDiffBytes,
        };
        string capId = "cap-" + HelperBroker.NewToken()[..20], derId = "der-" + HelperBroker.NewToken()[..20];
        var result = new JsonObject
        {
            ["repoKey"] = id.Key, ["repositoryRoot"] = id.CanonicalPath, ["runId"] = runId, ["instance"] = broker.InstanceId,
            ["runtime"] = new JsonObject { ["runtimeId"] = rt.RuntimeId, ["root"] = m.Root, ["treeDigest"] = m.TreeDigest, ["fileCount"] = m.FileCount, ["measureMs"] = runtimeMs },
            ["committed"] = false,
        };

        // 1. The real capture.
        string capCfg = TicketDirs.Create(capId + ".cfg", helper), staging = TicketDirs.Create(capId, helper);
        try
        {
            JsonObject launch = Launch(m, capCfg, id, CaptureJob.FrameCap(cfg.CaptureRules));
            var job = new CaptureJob(staging, cfg.CaptureRules);
            timer.Restart();
            HelperJobOutcome o = broker.RunAsync("capture", new JsonObject { ["launch"] = launch, ["workload"] = new JsonObject { ["operationId"] = capId, ["target"] = captureTarget, ["rules"] = rules.DeepClone() } },
                job, TimeSpan.FromSeconds(CustodianConstants.HelperRequestSeconds), CancellationToken.None).GetAwaiter().GetResult();
            var cap = new JsonObject { ["ok"] = false, ["ticket"] = o.Ticket, ["ms"] = timer.ElapsedMilliseconds, ["exit"] = o.Exit?.DeepClone() };
            if (o.Ok)
            {
                try { cap["published"] = job.Publish(helper); cap["ok"] = true; }
                catch (HelperFrameError e) { cap["code"] = ErrorCodes.MeasurementFailed; cap["detail"] = "publication refused: " + e.Message; }
            }
            else { cap["code"] = o.Code; cap["detail"] = o.Detail; }
            result["capture"] = cap;
        }
        finally
        {
            TicketDirs.Remove(capCfg);
            if (!keep || result["capture"]?["ok"]?.GetValue<bool>() != true) TicketDirs.Remove(staging);
        }

        // 2. The real derivation (measurement read + the pure core over the scrubbed snapshot).
        string derCfg = TicketDirs.Create(derId + ".cfg", helper);
        try
        {
            var job = new DeriveJob();
            timer.Restart();
            HelperJobOutcome o = broker.RunAsync("derive", new JsonObject { ["launch"] = Launch(m, derCfg, id, job.MaxFrameBody), ["workload"] = new JsonObject { ["rules"] = rules, ["checks"] = derChecks, ["snapshot"] = snapshot?.DeepClone() } },
                job, TimeSpan.FromSeconds(300), CancellationToken.None).GetAwaiter().GetResult();
            var der = new JsonObject { ["ok"] = false, ["ticket"] = o.Ticket, ["ms"] = timer.ElapsedMilliseconds, ["snapshotDigest"] = snapshot is null ? null : EngineJson.Digest(snapshot), ["exit"] = o.Exit?.DeepClone() };
            if (o.Ok)
            {
                try { der["result"] = job.Consume(); der["ok"] = true; }
                catch (HelperFrameError e) { der["code"] = ErrorCodes.MeasurementFailed; der["detail"] = e.Message; }
            }
            else { der["code"] = o.Code; der["detail"] = o.Detail; }
            result["derive"] = der;
        }
        finally { TicketDirs.Remove(derCfg); }

        Audit($"helper_check repoKey={id.Key} capture={(result["capture"]?["ok"]?.GetValue<bool>() == true ? "ok" : (string?)result["capture"]?["code"])} derive={(result["derive"]?["ok"]?.GetValue<bool>() == true ? "ok" : (string?)result["derive"]?["code"])} instance={broker.InstanceId} committed=false");
        return result;
    }

    private static JsonObject ValidTarget(JsonObject t)
    {
        string kind = (string?)t["kind"] ?? throw new ArgumentException("target.kind is required");
        if (kind == "uncommitted" && t.Count == 1) return new JsonObject { ["kind"] = "uncommitted" };
        if (kind == "base_ref" && t.Count == 2 && (string?)t["ref"] is { Length: > 0 and <= 256 } r && r.All(c => char.IsAsciiLetterOrDigit(c) || "._/@{}~^-".Contains(c)) && !r.StartsWith('-') && !r.Contains(".."))
            return new JsonObject { ["kind"] = "base_ref", ["ref"] = r };
        throw new ArgumentException("target must be {kind: uncommitted} or {kind: base_ref, ref}");
    }

    /// <summary>The helper's launch section: the measured runtime, the custodian's read-only per-request directories, and
    /// git's single safe.directory — the canonical path of the repository the custodian validated (§A.4).</summary>
    internal static JsonObject Launch(MeasuredRuntime m, string cfgDir, RepoIdentity id, long maxFrameBody)
    {
        Directory.CreateDirectory(Path.Combine(cfgDir, "home"));
        Directory.CreateDirectory(Path.Combine(cfgDir, "hooks"));
        File.WriteAllBytes(Path.Combine(cfgDir, "gitconfig"), []);
        return new JsonObject
        {
            ["node"] = Path.Combine(m.Root, EngineRuntime.NodeName), ["nodeSha256"] = m.Node.Sha256,
            ["entry"] = Path.Combine(m.Root, EngineRuntime.EntryRelative.Replace('/', Path.DirectorySeparatorChar)), ["entrySha256"] = m.EntrySha256,
            ["git"] = EngineRuntime.GitExecutable(m),
            ["home"] = Path.Combine(cfgDir, "home"), ["hooks"] = Path.Combine(cfgDir, "hooks"), ["gitconfig"] = Path.Combine(cfgDir, "gitconfig"),
            ["repository"] = id.CanonicalPath, ["safeDirectory"] = id.CanonicalPath.Replace('\\', '/'),
            ["maxFrameBody"] = maxFrameBody,
        };
    }
}
