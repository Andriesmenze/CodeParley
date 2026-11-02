using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED (P3.4C-2): run the shared loop_transition corpus (test/fixtures/loop-transition-corpus.json)
/// against the REAL ledger. The TypeScript contract test runs the same corpus against the simulated custodian,
/// so both are held to one observable behaviour (the TS↔C# parity oracle, as the amendment content-key corpus
/// is for P3.4C-1). Each scenario gets a fresh scratch store, an 8-loop grant, the fixed process table of
/// <see cref="LoopSelfTest"/> and a controllable clock.
/// </summary>
internal static class LoopCorpusSelfTest
{
    private const string InventedHandle = "op-1-000000000000", InventedClaim = "wc-1-000000000000";

    /// <summary>One scenario's state: its ledger and clock, each run's nonce, captured claims, and the exact
    /// requests sent (for replays).</summary>
    private sealed class Scenario(GrantLedger ledger, string repo, Func<DateTime> now, Action<int> advance)
    {
        internal GrantLedger Ledger { get; } = ledger;
        internal string Repo { get; } = repo;
        internal Func<DateTime> Now { get; } = now;
        internal Action<int> Advance { get; } = advance;
        internal Dictionary<string, string> Nonces { get; } = [];
        internal Dictionary<string, string> Claims { get; } = [];
        internal Dictionary<string, string> Derivations { get; } = [];
        internal Dictionary<string, (LoopCaller Caller, LoopRequest Request)> Sent { get; } = [];
        internal int Generated { get; set; }
    }

    internal static int Run(string[] args)
    {
        string? path = GetArg(args, "--corpus");
        if (path is null || !File.Exists(path))
        {
            Console.Error.WriteLine("self-test-loop-corpus requires --corpus <path to test/fixtures/loop-transition-corpus.json>");
            return 2;
        }
        JsonArray scenarios = JsonNode.Parse(File.ReadAllText(path))!["scenarios"]!.AsArray();
        int failed = 0, steps = 0;
        foreach (JsonNode? s in scenarios)
        {
            (int n, int bad) = RunScenario(s!.AsObject());
            steps += n;
            failed += bad;
            Console.WriteLine($"[{(bad == 0 ? "PASS" : "FAIL")}] {(string?)s["name"]} ({n} steps{(bad == 0 ? "" : $", {bad} failed")})");
        }
        Console.WriteLine($"\nloop corpus self-test: {(failed == 0 ? $"all {scenarios.Count} scenarios ({steps} steps) passed" : failed + " step(s) FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    private static (int Steps, int Failed) RunScenario(JsonObject scenario)
    {
        string root = Path.Combine(Path.GetTempPath(), "cp-corpus-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            StorePaths.OverrideRootForSelfTest(Path.Combine(root, "Custodian"));
            Directory.CreateDirectory(StorePaths.IntentsDir);
            DateTime clock = DateTime.UtcNow;
            var ledger = new GrantLedger("cust-corpus", CorpusFixtures.Table, () => clock);
            string repo = Directory.CreateDirectory(Path.Combine(root, "repos", "Corpus")).FullName;
            ledger.PrepareGrant(repo, 8, 60, "corpus-grant");
            ledger.Commit("corpus-grant", null);
            var ctx = new Scenario(ledger, repo, () => clock, seconds => clock = clock.AddSeconds(seconds));
            int n = 0, bad = 0;
            foreach (JsonNode? step in scenario["steps"]!.AsArray())
            {
                n++;
                string? problem = RunStep(ctx, step!.AsObject());
                if (problem is null) continue;
                bad++;
                Console.WriteLine($"    step {n} ({(string?)step["op"]} {(string?)step["kind"] ?? (string?)step["of"] ?? ""}): {problem}");
            }
            return (n, bad);
        }
        finally { try { Directory.Delete(root, true); } catch { /* best effort */ } }
    }

    private static string? RunStep(Scenario ctx, JsonObject step)
    {
        string op = (string)step["op"]!;
        if (op == "advance") { ctx.Advance((int)step["seconds"]!); return null; }
        if (op == "measurement")
        {
            // P3.4C-5 Increment 3 (N5-17): what the custodian's (synthetic) measurement measures from now on.
            CaptureFixture.Measurements.Spec = CaptureFixture.Measurements.Spec with { SourceId = (string?)step["sourceId"] ?? new SyntheticMeasurement().SourceId };
            return null;
        }
        JsonObject expect = step["expect"]!.AsObject();
        (JsonObject? result, string? code) = op switch
        {
            "mint" => Execute(() => Mint(ctx, step)),
            "t" => Execute(() => Transition(ctx, step)),
            "replay" => Execute(() => Replay(ctx, (string)step["of"]!)),
            "list" => Execute(() => ctx.Ledger.ListUserRecords(ctx.Repo, (string)step["run"]!, operatorView: (string?)step["view"] == "operator")["loop"]!.AsObject()),
            "derive" => Execute(() => Derive(ctx, step)),
            _ => throw new InvalidOperationException($"unknown corpus op '{op}'"),
        };
        if (result is not null && step["capture"]?["claim"] is JsonNode name) ctx.Claims[(string)name!] = (string)result["claimId"]!;
        return Compare(expect, result, code);
    }

    private static (JsonObject?, string?) Execute(Func<JsonObject> act)
    {
        try { return (act(), null); }
        catch (CustodianRefusal r) { return (null, r.Code); }
        catch (ArgumentException) { return (null, ErrorCodes.InvalidArgument); }
    }

    private static JsonObject Mint(Scenario ctx, JsonObject step)
    {
        string run = (string)step["run"]!;
        // P3.4C-3: the engine registers the run (run_transition open, idempotent on its declaration) before it consumes
        // a loop; a refused open is the step's refusal.
        CorpusFixtures.Open(ctx.Ledger, ctx.Repo, run);
        JsonObject r = ctx.Ledger.ConsumeLoop(ctx.Repo, run, (string)step["requestId"]!);
        if (r["bindNonce"] is JsonNode nonce) ctx.Nonces[run] = (string)nonce!;
        return r;
    }

    /// <summary>P3.4C-5 Increment 3 (§5.1): the derivation section, with the corpus's synthetic derivation (its route and
    /// progress fingerprint); <c>as</c> names its id for a later <c>$der:</c> placeholder.</summary>
    private static JsonObject Derive(Scenario ctx, JsonObject step)
    {
        string run = (string)step["run"]!;
        JsonObject? spec = step["derivation"] as JsonObject;
        SyntheticMeasurement before = CaptureFixture.Measurements.Spec;
        CaptureFixture.Measurements.Spec = before with
        {
            RouteKind = (string?)spec?["routeKind"] ?? "implementer_step", RouteCode = (string?)spec?["routeCode"] ?? "address_findings",
            Fingerprint = (string?)spec?["fingerprint"] is { } fp ? Ledger.Digest.Sha256Hex("corpus-fingerprint:" + fp) : null,
        };
        try
        {
            JsonObject d = ctx.Ledger.DerivationSection(ctx.Repo, run, CorpusFixtures.RunJsonBase64);
            if ((string?)step["as"] is { } alias && (string?)d["derivationId"] is { } id) ctx.Derivations[alias] = id;
            return d;
        }
        finally { CaptureFixture.Measurements.Spec = before; }
    }

    private static JsonObject Transition(Scenario ctx, JsonObject step)
    {
        string run = (string)step["run"]!;
        LoopRecord? loop = ctx.Ledger.Read().Loops!.FirstOrDefault(l => l.RunId == run);
        string requestId = (string?)step["requestId"] ?? $"corpus-{++ctx.Generated}";
        var fields = (JsonObject)Resolve(ctx, run, loop, step["fields"]!.DeepClone())!;
        // P3.4C-5 Increment 3 (§5.2): a continuation or wake that names no derivation is asked on a fresh one with moved
        // progress (the P3.4C-2 scenarios test the loop's own rules) — unless the step says "derivation": "none".
        if ((string)step["kind"]! is LoopKinds.SpendContinuation or LoopKinds.WakeConsume && !fields.ContainsKey("derivation_id") && (string?)step["derivation"] != "none")
        {
            SyntheticMeasurement before = CaptureFixture.Measurements.Spec;
            CaptureFixture.Measurements.Spec = before with { Fingerprint = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) };
            try
            {
                JsonObject d = ctx.Ledger.DerivationSection(ctx.Repo, run, CorpusFixtures.RunJsonBase64);
                if ((string?)d["derivationId"] is { } id) fields["derivation_id"] = id;
            }
            finally { CaptureFixture.Measurements.Spec = before; }
        }
        LoopRequest req = LoopRequest.Parse(run, (string?)step["loopId"] ?? loop?.LoopId ?? Guid.NewGuid().ToString(),
            Relative(step["epoch"], loop?.Epoch ?? 1), Relative(step["rev"], loop?.LoopRevision ?? 1),
            (string)step["kind"]!, fields, requestId);
        (GrantLedger ledger, LoopCaller caller) = Connection(ctx, step);
        ctx.Sent[requestId] = (caller, req);
        return ledger.LoopTransition(caller, ctx.Repo, req);
    }

    /// <summary>The process connected to the pipe for a step — an OS fact, independent of every request field: by
    /// default the bound session's hook helper (a descendant of the Claude process); <c>outsider</c> a process
    /// outside that tree; <c>ended</c> the Claude process has exited; <c>reused</c> its pid names a later-created
    /// process. The last two read another process table over the same store.</summary>
    private static (GrantLedger Ledger, LoopCaller Caller) Connection(Scenario ctx, JsonObject step)
    {
        if ((string?)step["caller"] == "operator") return (ctx.Ledger, CorpusFixtures.Oper);
        return (string?)step["client"] switch
        {
            null => (ctx.Ledger, CorpusFixtures.Impl),
            "outsider" => (ctx.Ledger, CorpusFixtures.Outsider),
            "ended" => (new GrantLedger("cust-corpus", CorpusFixtures.WithoutClaude, ctx.Now), CorpusFixtures.Impl),
            "reused" => (new GrantLedger("cust-corpus", CorpusFixtures.ClaudeReused, ctx.Now), CorpusFixtures.Impl),
            string other => throw new InvalidOperationException($"unknown corpus client '{other}'"),
        };
    }

    private static JsonObject Replay(Scenario ctx, string of)
    {
        (LoopCaller caller, LoopRequest req) = ctx.Sent[of];
        return ctx.Ledger.LoopTransition(caller, ctx.Repo, req);
    }

    /// <summary>An epoch or revision: absent = the loop's current value; a number = itself; "+N"/"-N" relative.</summary>
    private static int Relative(JsonNode? spec, int current) => spec switch
    {
        null => current,
        JsonValue v when v.TryGetValue(out int n) => n,
        _ => current + int.Parse((string)spec!, System.Globalization.CultureInfo.InvariantCulture),
    };

    /// <summary>Replace the corpus placeholders in a fields tree.</summary>
    private static JsonNode? Resolve(Scenario ctx, string run, LoopRecord? loop, JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (string key in o.Select(kv => kv.Key).ToList()) o[key] = Resolve(ctx, run, loop, o[key]?.DeepClone());
                return o;
            case JsonValue v when v.TryGetValue(out string? s) && s.StartsWith('$'):
                return Placeholder(ctx, run, loop, s);
            default:
                return node;
        }
    }

    private static JsonNode Placeholder(Scenario ctx, string run, LoopRecord? loop, string token) => token switch
    {
        "$nonce" => ctx.Nonces[run],
        "$wrongNonce" => new string('0', 64),
        "$claude" => CorpusFixtures.Claude,
        "$unrelated" => CorpusFixtures.Unrelated,
        "$handle" => loop?.Operations?.LastOrDefault()?.Handle ?? InventedHandle,
        "$previousHandle" => loop?.Operations is { Count: > 1 } ops ? ops[^2].Handle : InventedHandle,
        "$inventedHandle" => InventedHandle,
        "$inventedClaim" => InventedClaim,
        _ when token.StartsWith("$claim:", StringComparison.Ordinal) => ctx.Claims[token["$claim:".Length..]],
        _ when token.StartsWith("$der:", StringComparison.Ordinal) => ctx.Derivations.GetValueOrDefault(token["$der:".Length..], "der-unknown000000000000000000"),
        _ => throw new InvalidOperationException($"unknown corpus placeholder '{token}'"),
    };

    // ---- expectations ----

    private static string? Compare(JsonObject expect, JsonObject? result, string? code)
    {
        bool wantOk = (bool)expect["ok"]!;
        string? wantCode = (string?)expect["code"];
        if (result is null) return wantOk ? $"expected ok, got {code}" : wantCode == code ? null : $"expected {wantCode}, got {code}";
        if (!wantOk) return $"expected {wantCode}, got ok: {result.ToJsonString()}";
        if (expect["data"] is JsonObject data && Mismatch(data, result, "") is string m) return m;
        return PresenceProblem(expect, result) ?? RecordKeysProblem(expect, result);
    }

    /// <summary>Top-level keys that must be present; strings that must not appear anywhere in the result.</summary>
    private static string? PresenceProblem(JsonObject expect, JsonObject result)
    {
        string json = result.ToJsonString();
        string? missing = (expect["present"]?.AsArray() ?? []).Select(p => (string)p!).FirstOrDefault(p => !result.ContainsKey(p));
        if (missing is not null) return $"'{missing}' missing from {json}";
        string? leaked = (expect["absent"]?.AsArray() ?? []).Select(a => (string)a!).FirstOrDefault(a => json.Contains(a, StringComparison.Ordinal));
        return leaked is null ? null : $"'{leaked}' must not appear in {json}";
    }

    /// <summary>The exact key set of a list step's projected record.</summary>
    private static string? RecordKeysProblem(JsonObject expect, JsonObject result)
    {
        if (expect["recordKeys"] is not JsonArray keys) return null;
        string want = string.Join(",", keys.Select(k => (string)k!).Order(StringComparer.Ordinal));
        IEnumerable<string> recordKeys = (result["record"] as JsonObject)?.Select(kv => kv.Key) ?? [];
        string got = string.Join(",", recordKeys.Order(StringComparer.Ordinal));
        return want == got ? null : $"record keys [{got}] are not [{want}]";
    }

    /// <summary>A partial deep match: every key the expectation names must equal (objects recursively).</summary>
    private static string? Mismatch(JsonObject want, JsonObject got, string path)
    {
        foreach ((string key, JsonNode? w) in want)
        {
            JsonNode? g = got[key];
            if (w is JsonObject wo)
            {
                if (g is not JsonObject go) return $"{path}{key}: expected an object, got {g?.ToJsonString() ?? "null"}";
                if (Mismatch(wo, go, $"{path}{key}.") is string m) return m;
            }
            else if (!JsonNode.DeepEquals(w, g)) return $"{path}{key}: expected {w?.ToJsonString() ?? "null"}, got {g?.ToJsonString() ?? "null"}";
        }
        return null;
    }

    private static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
