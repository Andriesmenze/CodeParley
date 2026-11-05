using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED (P3.4C-3): run the shared run_transition corpus (test/fixtures/run-transition-corpus.json) against the
/// REAL ledger. The TypeScript contract test (test/custodian-run.contract.test.ts) runs the same corpus against the
/// simulated custodian, so both are held to one observable behaviour. Each scenario gets a fresh scratch store, an
/// operator grant (unless it says otherwise), a fixed clock and the fixed process table of <see cref="RunSelfTest"/>,
/// switched per step by the step's process facts (the connected client, the writer, the writers' liveness).
/// </summary>
internal static class RunCorpusSelfTest
{
    private const long Second = 10_000_000;
    private static readonly long T0 = DateTime.UtcNow.AddMinutes(-10).ToFileTimeUtc();
    private const int Claude = 100, Server = 200, Helper = 300, Shell = 250, ShellHelper = 350, Unrelated = 400, UnrelatedHelper = 450;

    /// <summary>100 the Claude process; 200 the engine (the writer of what it sends) and 300 its pipe helper; 250 a shell
    /// inside the session's tree and 350 its helper; 400 an unrelated process and 450 its helper. Switched by the step:
    /// client ended (the Claude process exited) or reused (its id names a later process); writerState gone (the engine
    /// exited) or unreadable (no table).</summary>
    private sealed class Table : IProcessTable
    {
        internal string? Client;
        internal string? WriterState;

        private static readonly Dictionary<int, ProcEntry> Base = new()
        {
            [Claude] = new(Claude, 1, T0, "claude.exe"),
            [Server] = new(Server, Claude, T0 + 10 * Second, "node.exe"),
            [Helper] = new(Helper, Server, T0 + 11 * Second, "powershell.exe"),
            [Shell] = new(Shell, Claude, T0 + 12 * Second, "pwsh.exe"),
            [ShellHelper] = new(ShellHelper, Shell, T0 + 13 * Second, "powershell.exe"),
            [Unrelated] = new(Unrelated, 1, T0 + 5 * Second, "evil.exe"),
            [UnrelatedHelper] = new(UnrelatedHelper, Unrelated, T0 + 6 * Second, "powershell.exe"),
        };

        public IReadOnlyDictionary<int, ProcEntry>? Snapshot()
        {
            if (WriterState == "unreadable") return null;
            var t = new Dictionary<int, ProcEntry>(Base);
            if (Client == "ended") t.Remove(Claude);
            if (Client == "reused") t[Claude] = new(Claude, 1, T0 + 60 * Second, "claude.exe");
            if (WriterState == "gone") t.Remove(Server);
            return t;
        }
    }

    /// <summary>A request as sent, with the process facts it was sent under (for replays).</summary>
    private sealed record Sent(LoopCaller Caller, RunRequest Request, string? Client, string? WriterState);

    private sealed class Scenario(GrantLedger ledger, Table table, string repo, JsonObject templates, JsonObject? config, string root, Func<DateTime> clock)
    {
        internal GrantLedger Ledger { get; set; } = ledger;
        /** P3.4C-5: the ledger instance before the last restart (its reserved captures belong to the previous instance). */
        internal GrantLedger? Previous { get; set; }
        internal Func<DateTime> Clock { get; } = clock;
        internal Table Table { get; } = table;
        internal string Repo { get; } = repo;
        internal JsonObject Templates { get; } = templates;
        /** P3.4C-4: the corpus's protected configuration (config.*) and the scenario's scratch root. */
        internal JsonObject? Config { get; } = config;
        internal string Root { get; } = root;
        internal string? AcceptanceId { get; set; }
        internal string? ConfirmationId { get; set; }
        /** Phase 4 Increment 2: the FIX self-test confirmation (fixConfirm), separate from the S1 one. */
        internal string? FixConfirmationId { get; set; }
        internal DateTime Boot { get; set; } = new(2026, 10, 13, 8, 0, 0, DateTimeKind.Utc);
        internal Dictionary<string, string> Nonces { get; } = [];
        /** P3.4C-5 Increment 3: the scenario's index in the corpus and the current step's number (from 1), for --dump. */
        internal int Index { get; init; }
        /** P3.4C-5 Increment 4: the scenario's clock (the `advance` step moves it). */
        internal DateTime[] ClockBox { get; init; } = [DateTime.UtcNow];
        internal int Step { get; set; }
        internal Dictionary<string, string> Ops { get; } = [];
        internal Dictionary<string, string> Derivations { get; } = [];
        internal Dictionary<string, string> Amendments { get; } = [];
        internal Dictionary<string, string> Intents { get; } = [];
        internal Dictionary<string, Sent> SentRequests { get; } = [];
        /** Step 7.1: the scenario's named repository directories (main: <see cref="Repo"/>; other; moved) with the canonical
         * path each had when it was named, and the listing entries captured as selections. */
        internal Dictionary<string, (string Path, string Canonical)> Paths { get; } = [];
        internal Dictionary<string, JsonObject> Selections { get; } = [];
        internal int Generated { get; set; }
        internal string Next(string prefix) => $"{prefix}-{++Generated}";
    }

    internal static int Run(string[] args)
    {
        string? path = GetArg(args, "--corpus");
        if (path is null || !File.Exists(path))
        {
            Console.Error.WriteLine("self-test-run-corpus requires --corpus <path to test/fixtures/run-transition-corpus.json>");
            return 2;
        }
        JsonObject corpus = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        JsonObject templates = corpus["templates"]!.AsObject();
        JsonArray scenarios = corpus["scenarios"]!.AsArray();
        JsonObject? config = corpus["config"] as JsonObject;
        _dumpDir = GetArg(args, "--dump");
        if (_dumpDir is not null) Directory.CreateDirectory(_dumpDir);
        int failed = 0, steps = 0, index = 0;
        foreach (JsonNode? s in scenarios)
        {
            (int n, int bad) = RunScenario(s!.AsObject(), templates, config, index++);
            steps += n;
            failed += bad;
            Console.WriteLine($"[{(bad == 0 ? "PASS" : "FAIL")}] {(string?)s["name"]} ({n} steps{(bad == 0 ? "" : $", {bad} failed")})");
        }
        Console.WriteLine($"\nrun corpus self-test: {(failed == 0 ? $"all {scenarios.Count} scenarios ({steps} steps) passed" : failed + " step(s) FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    /// <summary>P3.4C-5 Increment 3 (N5-5): where each derive step's snapshot is written (--dump), as
    /// <c>&lt;scenario&gt;-&lt;step&gt;.json</c>; the TypeScript contract test compares them with the simulated custodian's.</summary>
    private static string? _dumpDir;

    private static (int Steps, int Failed) RunScenario(JsonObject scenario, JsonObject templates, JsonObject? config, int index)
    {
        string root = Path.Combine(Path.GetTempPath(), "cp-runcorpus-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            StorePaths.OverrideRootForSelfTest(Path.Combine(root, "Custodian"));
            Directory.CreateDirectory(StorePaths.IntentsDir);
            var clock = new DateTime[] { DateTime.UtcNow }; // P3.4C-5 Increment 4: `advance` moves it
            var table = new Table();
            var ledger = new GrantLedger("cust-run-corpus", table, () => clock[0]);
            string repo = Directory.CreateDirectory(Path.Combine(root, "repos", "Corpus")).FullName;
            var ctx = new Scenario(ledger, table, repo, templates, config, root, () => clock[0]) { Index = index, ClockBox = clock };
            ledger.StartupRecovery(new FixedBoot(ctx.Boot)); // the first start of the store records its boot
            JsonNode? grant = scenario["grant"];
            bool noGrant = grant is JsonValue gv && gv.TryGetValue(out bool b) && !b;
            if (!noGrant) Grant(ctx, RunFields.Integer(grant) is long loops ? (int)loops : 8);
            int n = 0, bad = 0;
            bool noConfig = scenario["config"] is JsonValue cv && cv.TryGetValue(out bool c) && !c;
            if (!noConfig && config is not null && HoldConfig(ctx) is string parity)
            {
                bad++;
                Console.WriteLine($"    config: {parity}");
            }
            // P3.4C-5: the custodian captures protected reviews itself (an approved synthetic runtime; manual capture).
            if (!noConfig && config is not null) CaptureFixture.Enable(ledger, root);
            foreach (JsonNode? step in scenario["steps"]!.AsArray())
            {
                n++;
                ctx.Step = n;
                string? problem = RunStep(ctx, step!.AsObject());
                if (problem is null) continue;
                bad++;
                Console.WriteLine($"    step {n} ({(string?)step["op"]} {(string?)step["kind"] ?? (string?)step["of"] ?? (string?)step["intent"] ?? ""}): {problem}");
            }
            return (n, bad);
        }
        finally { try { Directory.Delete(root, true); } catch { /* best effort */ } }
    }

    /// <summary>The boot the corpus's recovery steps run in.</summary>
    private sealed class FixedBoot(DateTime value) : IBootIdentity
    {
        public DateTime? BootTimeUtc() => value;
    }

    /// <summary>P3.4C-4: the corpus's Codex installation (config.pe; <paramref name="variant"/> at 0x100) in the scenario's root.</summary>
    private static string Pe(Scenario ctx, int variant)
    {
        string dir = Directory.CreateDirectory(Path.Combine(ctx.Root, "codex", "v" + variant)).FullName;
        // The corpus defines this image (config.pe, a PE image whose SHA-256 the corpus pins) on every platform.
        string path = Path.Combine(dir, "codex.exe");
        File.WriteAllBytes(path, ConfigFixture.PeBytes((byte)variant));
        return path;
    }

    private static JsonObject PayloadOf(Scenario ctx, JsonObject? overlay, string? codex)
    {
        var p = (JsonObject)ctx.Config!["payload"]!.DeepClone();
        foreach ((string key, JsonNode? value) in overlay ?? [])
        {
            if (key != "checks") { p[key] = value?.DeepClone(); continue; }
            var checks = new JsonObject();
            foreach ((string name, JsonNode? def) in value!.AsObject())
                checks[name] = def is JsonObject o && o["$from"] is JsonValue from ? ctx.Config!["payload"]!["checks"]![(string)from!]!.DeepClone() : def?.DeepClone();
            p[key] = checks;
        }
        p["codexPath"] = codex == "none" ? null : codex is not null && codex.StartsWith("variant:", StringComparison.Ordinal) ? Pe(ctx, int.Parse(codex[8..], System.Globalization.CultureInfo.InvariantCulture)) : Pe(ctx, 0);
        return p;
    }

    private static JsonObject ConfigSection(Scenario ctx) => ctx.Ledger.ListUserRecords(ctx.Repo, "config-view", true, new HashSet<string> { "config" })["config"]!.AsObject();

    private static JsonObject PrepareAndCommit(Scenario ctx, string? repositoryRoot, string kind, string action, string? recordId, JsonObject? payload, int baseRevision)
    {
        string rid = ctx.Next("cfg");
        ctx.Ledger.PrepareConfigRecord(repositoryRoot, kind, action, recordId, payload, baseRevision, rid);
        return ctx.Ledger.Commit(rid, null);
    }

    /// <summary>The corpus's protected configuration, set as the operator would; returns a digest-parity problem (null: none).</summary>
    private static string? HoldConfig(Scenario ctx)
    {
        PrepareAndCommit(ctx, ctx.Repo, ConfigKinds.Repository, ConfigKinds.Set, null, PayloadOf(ctx, null, null), 0);
        ctx.ConfirmationId = (string)PrepareAndCommit(ctx, null, ConfigKinds.SelftestConfirmation, ConfigKinds.Set, null, (JsonObject)ctx.Config!["selftest"]!.DeepClone(), (int)ConfigSection(ctx)["globalRevision"]!)["recordId"]!;
        ctx.AcceptanceId = (string)PrepareAndCommit(ctx, null, ConfigKinds.IsolationAcceptance, ConfigKinds.Set, null, (JsonObject)ctx.Config!["acceptance"]!.DeepClone(), (int)ConfigSection(ctx)["globalRevision"]!)["recordId"]!;
        // The digest parity oracle: what the real custodian computed is exactly the corpus's pinned digests.
        JsonObject r = ConfigSection(ctx)["repository"]!.AsObject();
        foreach ((string name, JsonNode? want) in ctx.Config!["digests"]!.AsObject())
            if ((string?)r["checks"]![name]?["definitionDigest"] != (string?)want) return $"definition digest of {name} is {(string?)r["checks"]![name]?["definitionDigest"]}, not the corpus's {(string?)want}";
        if ((string?)r["captureRulesDigest"] != (string?)ctx.Config["captureRulesDigest"]) return $"capture-rules digest {(string?)r["captureRulesDigest"]} is not the corpus's";
        if ((string?)r["codexInstallation"]?["sha256"] != (string?)ctx.Config["codexSha256"]) return $"Codex SHA-256 {(string?)r["codexInstallation"]?["sha256"]} is not the corpus's";
        return null;
    }

    private static void Grant(Scenario ctx, int loops)
    {
        string rid = ctx.Next("grant");
        ctx.Ledger.PrepareGrant(ctx.Repo, loops, 60, rid);
        ctx.Ledger.Commit(rid, null);
    }

    private static string? RunStep(Scenario ctx, JsonObject step)
    {
        string op = (string)step["op"]!;
        switch (op)
        {
            case "grant": Grant(ctx, (int)(RunFields.Integer(step["loops"]) ?? 1)); return null;
            case "dropRun": File.Delete(StorePaths.RunPath(RepoIdentities.Resolve(ctx.Repo).Key, (string)step["run"]!)); return null;
        }
        ctx.Table.Client = (string?)step["client"];
        ctx.Table.WriterState = (string?)step["writerState"];
        try
        {
            (JsonObject? result, string? code) = Execute(() => Act(ctx, op, step));
            if (result is not null && step["capture"] is JsonObject capture)
            {
                if (capture["op"] is JsonValue c) ctx.Ops[(string)c!] = (string)result["operationId"]!;
                if (capture["amendment"] is JsonValue a) ctx.Amendments[(string)a!] = (string)result["recordId"]!;
                if (capture["intent"] is JsonValue i) ctx.Intents[(string)i!] = (string)result["authorizationRequestId"]!;
            }
            return Compare(Resolve(ctx, step["expect"]!.DeepClone())!.AsObject(), result, code, op == "list");
        }
        finally
        {
            ctx.Table.Client = null;
            ctx.Table.WriterState = null;
        }
    }

    private static (JsonObject?, string?) Execute(Func<JsonObject> act)
    {
        try { return (act(), null); }
        catch (Exception e) when (e is not OutOfMemoryException) { return (null, CustodianCore.CodeOf(e)); }
    }

    private static JsonObject Act(Scenario ctx, string op, JsonObject step)
    {
        string run = (string?)step["run"] ?? "";
        bool operatorView = (string?)step["view"] == "operator";
        switch (op)
        {
            case "t":
            {
                string rid = (string?)step["requestId"] ?? ctx.Next("corpus");
                LoopCaller caller = CallerOf(step);
                RunRequest req = RunRequest.Parse(run, (string)step["kind"]!, Resolve(ctx, step["fields"]!.DeepClone())!.AsObject(), rid);
                // A replay re-sends the FIRST request sent under the id (a later conflicting one does not replace it).
                ctx.SentRequests.TryAdd(rid, new Sent(caller, req, ctx.Table.Client, ctx.Table.WriterState));
                // Phase 4 Increment 3: what the custodian's measurement of the source gives during this transition (an
                // application's begin, finish or reconciliation; default: the corpus's source, stable).
                if (step["source"] is JsonObject src) CaptureFixture.Measurements.Spec = MeasurementOf(ctx, src);
                JsonObject result;
                try { result = ctx.Ledger.RunTransition(caller, ctx.Repo, req); }
                finally { if (step["source"] is JsonObject) CaptureFixture.Measurements.Spec = new SyntheticMeasurement(); }
                // P3.4C-5 Increment 3 (§4): the custodian's measurement of a checks operation's start and of each execution's
                // end runs at once (the corpus's synthetic measurement), unless the step leaves it pending (measure: false).
                bool measuring = ((string)step["kind"]! == "op_begin" && (string?)req.Fields["operationKind"] == "checks" && (string?)result["operationStatus"] == RunOperationStatuses.Measuring)
                    || ((string)step["kind"]! == "record_execution" && (string?)result["executionStatus"] == RunOperationStatuses.Measuring);
                if (measuring && (step["measure"] is not JsonValue mv || mv.GetValue<bool>()))
                    SettleMeasurement(ctx, run, (string)result["operationId"]!, step["measured"] as JsonObject);
                return result;
            }
            case "measure":
            {
                // P3.4C-5 Increment 3: run the pending check measurement of `of` (a step that left it pending).
                JsonObject? r = SettleMeasurement(ctx, run, ctx.Ops[(string)step["of"]!], step["measured"] as JsonObject);
                return r ?? throw new InvalidOperationException("no check measurement is pending");
            }
            case "derive":
            {
                // P3.4C-5 Increment 3 (§5.1): the derivation section, with the corpus's synthetic derivation (route, progress).
                JsonObject? spec = step["derivation"] as JsonObject;
                CaptureFixture.Measurements.Spec = new SyntheticMeasurement(
                    SourceId: (string?)Resolve(ctx, spec?["sourceId"]?.DeepClone()) ?? new SyntheticMeasurement().SourceId,
                    RouteKind: (string?)spec?["routeKind"] ?? "implementer_step", RouteCode: (string?)spec?["routeCode"] ?? "address_findings",
                    Fingerprint: (string?)Resolve(ctx, spec?["fingerprint"]?.DeepClone()),
                    Freshness: (Resolve(ctx, spec?["freshness"]?.DeepClone()) as JsonObject)?.ToDictionary(kv => kv.Key, kv => (string)kv.Value!));
                JsonObject d = ctx.Ledger.DerivationSection(ctx.Repo, run, (string?)step["runJson"] is { } text ? Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text)) : CorpusFixtures.RunJsonBase64);
                if (_dumpDir is not null)
                    File.WriteAllText(Path.Combine(_dumpDir, $"{ctx.Index:D2}-{ctx.Step:D3}.json"), ctx.Ledger.LastDerivationSnapshotForTest?.ToJsonString() ?? "null");
                if ((string?)step["as"] is { } alias && (string?)d["derivationId"] is { } did) ctx.Derivations[alias] = did;
                CaptureFixture.Measurements.Spec = new SyntheticMeasurement();
                return d;
            }
            case "replay":
            {
                Sent prior = ctx.SentRequests[(string)step["of"]!];
                ctx.Table.Client = prior.Client;
                ctx.Table.WriterState = prior.WriterState;
                return ctx.Ledger.RunTransition(prior.Caller, ctx.Repo, prior.Request);
            }
            case "mint":
            {
                JsonObject r = ctx.Ledger.ConsumeLoop(ctx.Repo, run, ctx.Next("mint"));
                if (r["bindNonce"] is JsonNode nonce) ctx.Nonces[run] = (string)nonce!;
                return r;
            }
            case "bind":
            case "loop":
            {
                LoopRecord? loop = ctx.Ledger.ReadLocked().Loops!.FirstOrDefault(l => l.RunId == run);
                JsonObject fields = op == "bind"
                    ? new JsonObject { ["bindNonce"] = ctx.Nonces.GetValueOrDefault(run), ["session_id"] = "s-1", ["process"] = new JsonObject { ["pid"] = Claude } }
                    : Resolve(ctx, step["fields"]!.DeepClone())!.AsObject();
                LoopRequest req = LoopRequest.Parse(run, loop?.LoopId ?? Guid.NewGuid().ToString(), loop?.Epoch ?? 1, loop?.LoopRevision ?? 1, op == "bind" ? "bind" : (string)step["kind"]!, fields, ctx.Next("loop"));
                return ctx.Ledger.LoopTransition(new LoopCaller(false, "proof-implementer", Helper), ctx.Repo, req);
            }
            case "list":
                return ctx.Ledger.ListUserRecords(ctx.Repo, run, operatorView, ListedSections);
            case "config":
            {
                string action = (string)step["action"]!;
                int revision = (int?)ConfigSection(ctx)["repository"]?["configRevision"] ?? 0;
                return PrepareAndCommit(ctx, ctx.Repo, ConfigKinds.Repository, action, null,
                    action == ConfigKinds.Set ? PayloadOf(ctx, step["payload"] as JsonObject, (string?)step["codex"]) : null, revision);
            }
            case "revokeGlobal":
            {
                string kind = (string)step["kind"]!;
                if (kind == "fix_confirmation") return PrepareAndCommit(ctx, null, ConfigKinds.SelftestConfirmation, ConfigKinds.Revoke, ctx.FixConfirmationId, null, (int)ConfigSection(ctx)["globalRevision"]!);
                return PrepareAndCommit(ctx, null, kind, ConfigKinds.Revoke, kind == ConfigKinds.IsolationAcceptance ? ctx.AcceptanceId : ctx.ConfirmationId, null, (int)ConfigSection(ctx)["globalRevision"]!);
            }
            // ---- Phase 4 Increment 2: the delegated fix ----
            case "fixConfirm":
            {
                JsonObject r = PrepareAndCommit(ctx, null, ConfigKinds.SelftestConfirmation, ConfigKinds.Set, null, (JsonObject)ctx.Config!["fixSelftest"]!.DeepClone(), (int)ConfigSection(ctx)["globalRevision"]!);
                ctx.FixConfirmationId = (string)r["recordId"]!;
                return r;
            }
            case "orphanProposal":
            {
                // A proposal file no run references (the custodian stopped between writing the content and the run record).
                string id = "fop-0-" + (string)step["name"]!;
                GrantLedger.WriteOrphanProposalForTest(RepoIdentities.Resolve(ctx.Repo).Key, run, id);
                ctx.Ops[(string)step["name"]!] = id;
                return new JsonObject();
            }
            case "held":
                return GrantLedger.HeldProposalForTest(RepoIdentities.Resolve(ctx.Repo).Key, run, ctx.Ops[(string)step["of"]!]);
            // ---- Phase 4 Increment 3: the owner's decision and the custodian's rendering ----
            case "fixPrepare":
            {
                string rid = ctx.Next("fixdecision");
                // Step 7.1: `repo` names the directory the request names; `expected` the selection fields exactly as sent (the
                // dispatcher's own validation of them runs first, as on the pipe and the socket).
                string path = step["repo"] is JsonValue rv ? NamedPath(ctx, (string)rv!) : ctx.Repo;
                GrantLedger.FixSelection? expected = step["expected"] is JsonObject raw ? CustodianCore.ExpectedSelectionOf(Resolve(ctx, raw.DeepClone())!.AsObject()) : null;
                PreparedAuthorization p = ctx.Ledger.PrepareFixDecision(path, run, ctx.Ops[(string)step["of"]!], (string)step["decision"]!, rid, expected);
                return new JsonObject { ["authorizationRequestId"] = p.RequestId, ["action"] = p.Action, ["rendering"] = p.Rendering, ["fixDecision"] = p.Facts?.DeepClone() };
            }
            // ---- Step 7.1: the operator's listing (`fix review`) ----
            case "fixList":
            {
                NamedPath(ctx, "main");
                JsonObject listing = ctx.Ledger.ListFixProposals(step["repo"] is JsonValue rv ? NamedPath(ctx, (string)rv!) : null);
                if (step["select"] is JsonObject sel)
                {
                    string id = ctx.Ops[(string)sel["of"]!];
                    ctx.Selections[(string)sel["as"]!] = (JsonObject)(listing["entries"]!.AsArray().OfType<JsonObject>().FirstOrDefault(e => (string?)e["operationId"] == id)
                        ?? throw new InvalidOperationException($"the listing has no entry for {id}")).DeepClone();
                }
                return ListingSummary(ctx, listing);
            }
            case "repo":
                NamedPath(ctx, (string)step["name"]!);
                return new JsonObject();
            case "moveRepo":
            {
                // The repository directory moves (its identity follows it); with `reuse`, a new directory takes its old path.
                NamedPath(ctx, "main");
                string to = ctx.Repo + "-" + (string)step["to"]!;
                Directory.Move(ctx.Repo, to);
                ctx.Paths[(string)step["to"]!] = (to, RepoIdentities.Resolve(to).CanonicalPath);
                if (step["reuse"] is JsonValue reuse && reuse.GetValue<bool>()) Directory.CreateDirectory(ctx.Repo);
                return new JsonObject();
            }
            case "unpin":
            {
                // A run opened before P3.4C-4 pinned no configuration (OpenedConfig absent): the record as such a run has it.
                string key = RepoIdentities.Resolve(NamedPath(ctx, "main")).Key;
                RunRecord r = GrantLedger.ReadRunLocked(key, run) ?? throw new InvalidOperationException($"no run {run}");
                GrantLedger.WriteRunForTest(r with { OpenedConfig = null });
                return new JsonObject();
            }
            case "fixRender":
                return ctx.Ledger.RenderFixProposal(ctx.Repo, run, ctx.Ops[(string)step["of"]!]);
            case "recover":
            {
                ctx.Boot = ctx.Boot.AddHours(3); // an OS restart
                RecoveryOutcome o = ctx.Ledger.StartupRecovery(new FixedBoot(ctx.Boot));
                return new JsonObject { ["recovered"] = o.Recovered };
            }
            case "amend":
            {
                var payload = new JsonObject { ["kind"] = "clarification", ["text"] = "a corpus amendment", ["disclosure_digest"] = Resolve(ctx, step["disclosure"]?.DeepClone()) };
                string rid = PrepareUserRecord(ctx, run, "amendment", payload);
                return ctx.Ledger.Commit(rid, null);
            }
            case "decide":
            {
                var payload = new JsonObject
                {
                    ["kind"] = "waive", ["note"] = "", ["covered_items"] = step["covered"]?.DeepClone(), ["decided_against"] = Resolve(ctx, step["decidedAgainst"]?.DeepClone()),
                };
                string rid = PrepareUserRecord(ctx, run, "decision", payload);
                return new JsonObject { ["authorizationRequestId"] = rid };
            }
            case "commit":
                return ctx.Ledger.Commit(ctx.Intents[(string)step["intent"]!], null);
            case "capture":
            {
                // P3.4C-5: capture the reserved review `of` with the corpus's synthetic capture (late: on the ledger instance
                // before the last restart — its result must not be recorded).
                string opId = ctx.Ops[(string)step["of"]!];
                var spec = new SyntheticCapture((string?)Resolve(ctx, step["sourceId"]?.DeepClone()), step["stable"] is not JsonValue sv || sv.GetValue<bool>(), (string?)step["fail"],
                    step["tree"] is JsonValue tv && tv.GetValue<bool>());
                bool late = step["late"] is JsonValue lv && lv.GetValue<bool>();
                GrantLedger led = late ? ctx.Previous ?? throw new InvalidOperationException("no earlier ledger instance") : ctx.Ledger;
                int before = Events(ctx, run);
                JsonObject? result = CaptureFixture.Run(led, ctx.Repo, run, opId, spec);
                if (result is null) throw new InvalidOperationException($"no capture of {opId} is reserved");
                return Events(ctx, run) == before ? new JsonObject { ["recorded"] = false } : result;
            }
            case "tamper":
                CaptureFixture.Tamper(ctx.Repo, run, ctx.Ops[(string)step["of"]!]);
                return new JsonObject { ["tampered"] = true };
            case "restart":
            {
                // P3.4C-5 (N5-18): the custodian restarts in the same boot: a new instance over the same store, whose start
                // reconciles every measuring operation before anything is served.
                ctx.Previous = ctx.Ledger;
                var next = new GrantLedger("cust-run-corpus", ctx.Table, ctx.Clock);
                next.StartupRecovery(new FixedBoot(ctx.Boot));
                int interrupted = next.ReconcileCapturesAtStart();
                CaptureFixture.Enable(next, ctx.Root);
                ctx.Ledger = next;
                return new JsonObject { ["interrupted"] = interrupted };
            }
            // ---- P3.4C-5 Increment 4: export retention (§3.2) ----
            case "exports":
            {
                // What the export root holds now: published ticket directories, and staging / configuration directories.
                string[] dirs = Directory.Exists(StorePaths.ExportsRoot) ? [.. Directory.GetDirectories(StorePaths.ExportsRoot).Select(Path.GetFileName).OfType<string>()] : [];
                return new JsonObject
                {
                    ["published"] = dirs.Count(d => !d.EndsWith(".staging", StringComparison.Ordinal) && !d.EndsWith(".cfg", StringComparison.Ordinal)),
                    ["staging"] = dirs.Count(d => d.EndsWith(".staging", StringComparison.Ordinal) || d.EndsWith(".cfg", StringComparison.Ordinal)),
                };
            }
            case "orphan":
                // Directories an interrupted or failed measurement could leave behind (not owned by any measurement).
                foreach (JsonNode? n in step["names"]!.AsArray()) Directory.CreateDirectory(Path.Combine(StorePaths.ExportsRoot, (string)n!));
                return new JsonObject();
            case "sweep":
            {
                (int retired, int removed, int proposalsRemoved) = ctx.Ledger.SweepExports();
                return new JsonObject { ["retired"] = retired, ["removed"] = removed, ["proposalsRemoved"] = proposalsRemoved };
            }
            case "advance":
                ctx.ClockBox[0] = ctx.ClockBox[0].AddHours((double)step["hours"]!);
                return new JsonObject();
            default:
                throw new InvalidOperationException($"unknown corpus op '{op}'");
        }
    }

    private static int Events(Scenario ctx, string run) => GrantLedger.ReadRunLocked(RepoIdentities.Resolve(ctx.Repo).Key, run)?.Events.Count ?? 0;

    /// <summary>The sections a corpus listing compares (the derivation section has its own step).</summary>
    private static readonly IReadOnlySet<string> ListedSections = new HashSet<string>(StringComparer.Ordinal) { "user", "loop", "run", "config" };

    /// <summary>Run the pending check measurement of <paramref name="operationId"/> with the step's synthetic measurement
    /// (<c>sourceId</c>, <c>stable</c>, <c>fail</c>; default: the corpus's source, stable); returns its commit's result.</summary>
    private static JsonObject? SettleMeasurement(Scenario ctx, string run, string operationId, JsonObject? spec)
    {
        CaptureFixture.Measurements.Spec = new SyntheticMeasurement(
            SourceId: (string?)Resolve(ctx, spec?["sourceId"]?.DeepClone()) ?? new SyntheticMeasurement().SourceId,
            Stable: spec?["stable"] is not JsonValue sv || sv.GetValue<bool>(), Fail: (string?)spec?["fail"]);
        try { return CaptureFixture.Measure(ctx.Ledger, ctx.Repo, run, operationId); }
        finally { CaptureFixture.Measurements.Spec = new SyntheticMeasurement(); }
    }

    /// <summary>A step's synthetic measurement of the source (<c>sourceId</c>, <c>stable</c>, <c>fail</c>).</summary>
    private static SyntheticMeasurement MeasurementOf(Scenario ctx, JsonObject spec) => new(
        SourceId: (string?)Resolve(ctx, spec["sourceId"]?.DeepClone()) ?? new SyntheticMeasurement().SourceId,
        Stable: spec["stable"] is not JsonValue sv || sv.GetValue<bool>(), Fail: (string?)spec["fail"]);

    /// <summary>Prepare a user record at the run's current log revision; returns its request id.</summary>
    private static string PrepareUserRecord(Scenario ctx, string run, string recordKind, JsonObject payload)
    {
        int revision = (int)(RunFields.Integer(ctx.Ledger.ListUserRecords(ctx.Repo, run, operatorView: true)["revision"]) ?? 0);
        string rid = ctx.Next("record");
        ctx.Ledger.PrepareUserRecord(ctx.Repo, run, recordKind, payload, revision, rid);
        return rid;
    }

    /// <summary>The connected client for a step (an OS fact, independent of every field): the operator surface; a
    /// process outside the session's tree; a shell inside it (another writer); by default the engine's helper.</summary>
    private static LoopCaller CallerOf(JsonObject step) => (string?)step["caller"] == "operator"
        ? new LoopCaller(true, "proof-operator", null)
        : new LoopCaller(false, "proof-implementer", (string?)step["client"] == "outsider" ? UnrelatedHelper : (string?)step["writer"] == "other" ? ShellHelper : Helper);

    // ---- templates and placeholders ----

    /// <summary>Templates ($template, overlaid shallowly), $omit and the placeholders, resolved recursively.</summary>
    private static JsonNode? Resolve(Scenario ctx, JsonNode? node)
    {
        switch (node)
        {
            case JsonArray a:
                return new JsonArray(a.Select(x => Resolve(ctx, x?.DeepClone())).ToArray());
            case JsonObject o:
            {
                JsonObject result = o["$template"] is JsonValue t ? Resolve(ctx, ctx.Templates[(string)t!]!.DeepClone())!.AsObject() : new JsonObject();
                foreach ((string key, JsonNode? value) in o.ToList())
                {
                    if (key == "$template") continue;
                    if (value is JsonValue v && v.TryGetValue(out string? s) && s == "$omit") result.Remove(key);
                    else result[key] = Resolve(ctx, value?.DeepClone());
                }
                return result;
            }
            case JsonValue v when v.TryGetValue(out string? s) && s.StartsWith('$'):
                return Placeholder(ctx, s);
            default:
                return node;
        }
    }

    /// <summary>Step 7.1: the scenario's directory named <paramref name="name"/> (main is the scenario's repository; any other
    /// name a new directory beside it), recorded with its canonical path the first time it is named.</summary>
    private static string NamedPath(Scenario ctx, string name)
    {
        if (ctx.Paths.TryGetValue(name, out var known)) return known.Path;
        string path = name == "main" ? ctx.Repo : Directory.CreateDirectory(Path.Combine(ctx.Root, "repos", name)).FullName;
        ctx.Paths[name] = (path, RepoIdentities.Resolve(path).CanonicalPath);
        return path;
    }

    /// <summary>Step 7.1: a listing as the corpus compares it (mirrored in test/custodian-run.contract.test.ts): the total,
    /// whether it was cut, and per entry "state selectable|- fix-alias reason|- path-name", the path named by the scenario
    /// directory it is (repositoryRoot, else "last:" and the last recorded path's, else "-").</summary>
    private static JsonObject ListingSummary(Scenario ctx, JsonObject listing)
    {
        string NameOf(string? path)
        {
            if (path is null) return "-";
            foreach ((string name, (string _, string canonical)) in ctx.Paths)
                if (string.Equals(canonical, path, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) return name;
            return "?";
        }
        var entries = new JsonArray();
        foreach (JsonObject e in listing["entries"]!.AsArray().OfType<JsonObject>())
        {
            string alias = ctx.Ops.FirstOrDefault(kv => kv.Value == (string?)e["operationId"]).Key ?? "?";
            string where = e["repositoryRoot"] is JsonValue rr ? NameOf((string?)rr) : e["lastKnownPath"] is JsonValue lk ? "last:" + NameOf((string?)lk) : "-";
            if (e["repositoryRoot"] is JsonValue r2 && (string?)e["repositoryDisplay"] != FixRendering.Escape((string)r2!)) where += "!display";
            if ((bool)e["selectable"]! != (e["renderingDigest"] is JsonValue)) where += "!digest";
            entries.Add($"{(string)e["state"]!} {((bool)e["selectable"]! ? "selectable" : "-")} {alias} {(string?)e["reasonCode"] ?? "-"} {where}");
        }
        return new JsonObject
        {
            ["schema"] = listing["schema"]?.DeepClone(), ["total"] = listing["total"]?.DeepClone(), ["truncated"] = listing["truncated"]?.DeepClone(),
            ["omittedPending"] = listing["omittedPending"]?.DeepClone(), ["entries"] = entries,
        };
    }

    private static JsonNode? Placeholder(Scenario ctx, string token) => token switch
    {
        // Step 7.1: a field of the listing entry captured as <alias> ($sel:alias:field), and a named directory's identity.
        _ when token.StartsWith("$sel:", StringComparison.Ordinal) => ctx.Selections[token["$sel:".Length..].Split(':')[0]][token["$sel:".Length..].Split(':')[1]]?.DeepClone(),
        _ when token.StartsWith("$key:", StringComparison.Ordinal) => RepoIdentities.Resolve(NamedPath(ctx, token["$key:".Length..])).Key,
        _ when token.StartsWith("$hex:", StringComparison.Ordinal) => string.Concat(Enumerable.Repeat(token["$hex:".Length..], 64)),
        _ when token.StartsWith("$sha:", StringComparison.Ordinal) => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token["$sha:".Length..]))),
        _ when token.StartsWith("$op:", StringComparison.Ordinal) => ctx.Ops[token["$op:".Length..]],
        // Phase 4 Increment 3: the proposal digest the custodian computed for the fix captured as <alias>.
        _ when token.StartsWith("$proposal:", StringComparison.Ordinal) => ProposalDigestOf(ctx, token["$proposal:".Length..]),
        _ when token.StartsWith("$der:", StringComparison.Ordinal) => ctx.Derivations[token["$der:".Length..]],
        _ when token.StartsWith("$amendment:", StringComparison.Ordinal) => ctx.Amendments[token["$amendment:".Length..]],
        "$claude" => Claude,
        "$runJson" => CorpusFixtures.RunJsonDigest,
        _ when token.StartsWith("$def:", StringComparison.Ordinal) => (string?)ctx.Config!["digests"]![token["$def:".Length..]],
        "$captureRules" => (string?)ctx.Config!["captureRulesDigest"],
        "$codexSha" => (string?)ctx.Config!["codexSha256"],
        "$acceptance" => ctx.AcceptanceId,
        _ => throw new InvalidOperationException($"unknown corpus placeholder '{token}'"),
    };

    private static string? ProposalDigestOf(Scenario ctx, string alias)
    {
        string id = ctx.Ops[alias];
        foreach (string file in Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories))
        {
            RunRecord? r = System.Text.Json.JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase });
            if (r?.Operations.FirstOrDefault(o => o.OperationId == id) is { } op) return (string?)op.Outcome?["proposal"]?["proposalDigest"];
        }
        return null;
    }

    // ---- expectations ----

    private static string? Compare(JsonObject expect, JsonObject? result, string? code, bool list)
    {
        bool wantOk = (bool)expect["ok"]!;
        string? wantCode = (string?)expect["code"];
        if (result is null) return wantOk ? $"expected ok, got {code}" : wantCode == code ? null : $"expected {wantCode}, got {code}";
        if (!wantOk) return $"expected {wantCode}, got ok: {result.ToJsonString()}";
        if (expect["data"] is JsonObject data && Mismatch(data, result, "") is string m) return m;
        string json = result.ToJsonString();
        string? missing = (expect["present"]?.AsArray() ?? []).Select(p => (string)p!).FirstOrDefault(p => !result.ContainsKey(p));
        if (missing is not null) return $"'{missing}' missing from {json}";
        string? leaked = (expect["absent"]?.AsArray() ?? []).Select(a => (string)a!).FirstOrDefault(a => json.Contains(a, StringComparison.Ordinal));
        if (leaked is not null) return $"'{leaked}' must not appear in {json}";
        // Phase 4 Increment 3: the rendering's text (the custodian's exact bytes) has — and lacks — these lines or fragments.
        if (expect["rendering"] is JsonObject re)
        {
            string text = (string?)result["rendering"] ?? "";
            string? lacking0 = (re["has"]?.AsArray() ?? []).Select(x => (string)x!).FirstOrDefault(x => !text.Contains(x, StringComparison.Ordinal));
            if (lacking0 is not null) return $"the rendering lacks {System.Text.Json.JsonSerializer.Serialize(lacking0)}:\n{text}";
            string? having = (re["lacks"]?.AsArray() ?? []).Select(x => (string)x!).FirstOrDefault(x => text.Contains(x, StringComparison.Ordinal));
            if (having is not null) return $"the rendering must not contain {System.Text.Json.JsonSerializer.Serialize(having)}:\n{text}";
        }
        if (!list) return null;
        JsonObject? record = result["run"]?["record"] as JsonObject;
        if (expect["recordKeys"] is JsonArray keys)
        {
            string want = string.Join(",", keys.Select(k => (string)k!).Order(StringComparer.Ordinal));
            string got = string.Join(",", (record?.Select(kv => kv.Key) ?? []).Order(StringComparer.Ordinal));
            if (want != got) return $"record keys [{got}] are not [{want}]";
        }
        string? lacking = (expect["recordHas"]?.AsArray() ?? []).Select(k => (string)k!).FirstOrDefault(k => record is null || !record.ContainsKey(k));
        if (lacking is not null) return $"run.record has no '{lacking}'";
        if (expect.ContainsKey("summary"))
        {
            JsonObject? got = Summary(record, result["run"]?["reviewBasis"] as JsonObject);
            if (expect["summary"] is not JsonObject want || got is null)
                return (expect["summary"] is null && got is null) ? null : $"summary: expected {expect["summary"]?.ToJsonString() ?? "null"}, got {got?.ToJsonString() ?? "null"}";
            if (Mismatch(want, got, "summary.") is string sm) return sm;
        }
        return null;
    }

    /// <summary>A list step's run record, summarized (the corpus's <c>summary</c>; mirrors the TypeScript runner).</summary>
    private static JsonObject? Summary(JsonObject? record, JsonObject? reviewBasis)
    {
        if (record is null) return null;
        IEnumerable<JsonObject> Arr(string key) => (record[key] as JsonArray ?? []).OfType<JsonObject>();
        static string Str(JsonNode? n) => n is null ? "null" : n is JsonValue v && v.TryGetValue(out string? s) ? s : n.ToJsonString();
        static IEnumerable<string> Strs(JsonNode? n) => (n as JsonArray ?? []).Select(x => (string)x!);
        static string ReviewState(JsonObject r)
        {
            string round = Str(r["round"]);
            return r["accepted"] is JsonValue a && a.TryGetValue(out bool accepted)
                ? accepted ? $"{round}:accepted" : $"{round}:not:{string.Join("+", Strs(r["notAcceptedReasons"]))}"
                : $"{round}:running";
        }
        static JsonArray Strings(IEnumerable<string> s) => new(s.Select(x => (JsonNode)x).ToArray());
        static JsonObject Map(IEnumerable<(string Key, JsonNode Value)> pairs)
        {
            var o = new JsonObject();
            foreach ((string k, JsonNode v) in pairs) o[k] = v;
            return o;
        }
        return new JsonObject
        {
            ["status"] = record["status"]?.DeepClone(),
            ["runRevision"] = record["runRevision"]?.DeepClone(),
            ["evidenceEpoch"] = record["evidenceEpoch"]?.DeepClone(),
            ["operations"] = Strings(Arr("operations").Select(o => $"{Str(o["kind"])}:{Str(o["status"])}")),
            ["writerAlive"] = new JsonArray(Arr("operations").Where(o => o.ContainsKey("writerAlive")).Select(o => o["writerAlive"]?.DeepClone()).ToArray()),
            ["reviews"] = Map(Arr("reviews").Select(r => (Str(r["reviewId"]), (JsonNode)ReviewState(r)))),
            ["items"] = Map(Arr("items").Select(i => (Str(i["itemId"]), (JsonNode)$"{Str(i["status"])}@{Str(i["itemRevision"])}"))),
            ["effects"] = Map(Arr("items").Select(i => (Str(i["itemId"]), (JsonNode)Strings((i["assessments"] as JsonArray ?? []).OfType<JsonObject>().Select(a => $"{Str(a["assessment"])}={Str(a["effect"])}"))))),
            ["links"] = Map(Arr("items").Select(i => (Str(i["itemId"]), (JsonNode)$"by={(i["supersededBy"] is JsonValue by && by.TryGetValue(out string? b) ? b : "-")};sup={string.Join(",", Strs(i["supersedes"]))};re={string.Join(",", Strs(i["restates"]))}"))),
            ["incidents"] = Strings(Arr("incidents").Select(i => $"{Str(i["kind"])}:{Str(i["source"])}")),
            ["executions"] = Strings(Arr("checkExecutions").Select(e => $"{Str(e["executionId"])}:{Str(e["status"])}")),
            ["responses"] = Strings(Arr("responses").Select(r => $"{Str(r["responseId"])}:{Str(r["itemId"])}")),
            ["replies"] = Strings(Arr("replies").Select(r => $"{Str(r["replyId"])}:{Str(r["itemId"])}")),
            // P3.4C-4: each review's basis now (usable, or why not) from the run section's reviewBasis.
            ["basis"] = Map((reviewBasis ?? []).Select(kv => (kv.Key, (JsonNode)(kv.Value?["basisUsable"] is JsonValue u && u.GetValue<bool>() ? "usable" : Str(kv.Value?["basisReason"]))))),
        };
    }

    /// <summary>A partial deep match: every key the expectation names must equal (objects recursively, anything else
    /// exactly).</summary>
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
