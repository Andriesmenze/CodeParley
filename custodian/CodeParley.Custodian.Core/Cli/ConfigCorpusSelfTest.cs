using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-4 M9: the custodian's configuration validation and digests against the shared corpus
/// (test/fixtures/config-digest-corpus.json), which the engine and the simulated custodian are held to as well
/// (test/config-digest-corpus.test.ts). Every accepted payload must validate and produce exactly the pinned definition,
/// capture-rules and repository-configuration digests; every refused payload must be refused; every canonical entry
/// must serialize to the pinned digest (EngineJson against JavaScript's sorted <c>JSON.stringify</c>).
/// </summary>
internal static class ConfigCorpusSelfTest
{
    internal static int Run(string[] args)
    {
        int at = Array.IndexOf(args, "--corpus");
        string? path = at >= 0 && at + 1 < args.Length ? args[at + 1] : null;
        if (path is null || !File.Exists(path))
        {
            Console.Error.WriteLine("self-test-config-corpus requires --corpus <path to test/fixtures/config-digest-corpus.json>");
            return 2;
        }
        JsonObject corpus = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        int failed = 0, total = 0;

        foreach (JsonNode? n in corpus["canonical"]!.AsArray())
        {
            total++;
            string got = EngineJson.Digest(n!["value"]);
            failed += Report($"canonical: {(string)n["name"]!}", got == (string)n["digest"]!, got);
        }

        foreach (JsonNode? n in corpus["accepted"]!.AsArray())
        {
            total++;
            string name = $"accepted: {(string)n!["name"]!}";
            try
            {
                JsonObject p = ConfigValidation.RepositoryPayload((JsonObject)n["payload"]!.DeepClone());
                JsonObject content = GrantLedger.RepositoryContent(p, null);
                var problems = new List<string>();
                JsonObject checks = content["checks"]!.AsObject();
                JsonObject want = n["digests"]!.AsObject();
                if (checks.Count != want.Count) problems.Add($"{checks.Count} checks, the corpus has {want.Count}");
                foreach ((string check, JsonNode? digest) in want)
                    if ((string?)checks[check]?["definitionDigest"] != (string?)digest) problems.Add($"definition digest of {check} is {(string?)checks[check]?["definitionDigest"]}");
                if ((string?)content["captureRulesDigest"] != (string?)n["captureRulesDigest"]) problems.Add($"capture-rules digest is {(string?)content["captureRulesDigest"]}");
                if ((string?)content["configDigest"] != (string?)n["configDigest"]) problems.Add($"configuration digest is {(string?)content["configDigest"]}");
                failed += Report(name, problems.Count == 0, string.Join("; ", problems));
            }
            catch (Exception e) when (e is ArgumentException or CustodianRefusal or InvalidOperationException)
            {
                failed += Report(name, false, $"refused: {e.Message}");
            }
        }

        foreach (JsonNode? n in corpus["refused"]!.AsArray())
        {
            total++;
            string name = $"refused: {(string)n!["name"]!}";
            string? why = null;
            try
            {
                ConfigValidation.RepositoryPayload((JsonObject)n["payload"]!.DeepClone());
            }
            catch (Exception e) when (e is ArgumentException or CustodianRefusal or InvalidOperationException)
            {
                why = e.Message;
            }
            failed += Report(name, why is not null, why ?? "accepted");
        }

        Console.WriteLine($"\nconfig corpus self-test: {(failed == 0 ? $"all {total} entries passed" : $"{failed} of {total} FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    private static int Report(string name, bool ok, string detail)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(ok ? "" : $" — {detail}")}");
        return ok ? 0 : 1;
    }
}
