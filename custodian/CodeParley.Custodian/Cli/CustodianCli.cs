using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Administrative and self-test verbs. The privileged ones (install/provision) run only from the
/// operator's elevated install script. The self-tests marked NON-PRIVILEGED run without elevation and
/// are the evidence the implementer session can produce directly; the privileged adversarial battery is
/// an operator-run script (prefer a disposable VM, TD amendment 2).
/// </summary>
internal static class CustodianCli
{
    // ---- privileged: service lifecycle + provisioning ----

    /// <summary>Create the service under the VIRTUAL account NT SERVICE\CodeParleyCustodian (never
    /// LocalSystem), as a write-restricted service SID with only SeChangeNotifyPrivilege.</summary>
    internal static int Install(string[] args)
    {
        string exe = Environment.ProcessPath ?? "";
        if (exe.Length == 0) { Console.Error.WriteLine("cannot resolve the custodian executable path"); return 1; }
        int rc = Sc($"create {CustodianConstants.ServiceName} binPath= \"{exe}\" obj= \"{CustodianConstants.VirtualAccount}\" start= demand DisplayName= \"{CustodianConstants.ServiceDisplayName}\"");
        if (rc != 0) return rc;
        Sc($"sidtype {CustodianConstants.ServiceName} restricted");
        Sc($"privs {CustodianConstants.ServiceName} SeChangeNotifyPrivilege");
        Console.WriteLine($"installed service '{CustodianConstants.ServiceName}' as {CustodianConstants.VirtualAccount} (restricted SID, SeChangeNotifyPrivilege only) -> {exe}");
        return 0;
    }

    internal static int Uninstall(string[] args)
    {
        Sc($"stop {CustodianConstants.ServiceName}");
        int rc = Sc($"delete {CustodianConstants.ServiceName}");
        if (rc == 0) Console.WriteLine($"removed service '{CustodianConstants.ServiceName}'");
        return rc;
    }

    /// <summary>Create/re-protect the store, write the trusted config (operator + implementer SIDs,
    /// defaulting to the invoking account) and the custodian-only private probe. Runs elevated.</summary>
    internal static int Provision(string[] args)
    {
        try
        {
            string self = $"{Environment.UserDomainName}\\{Environment.UserName}";
            SecurityIdentifier op = CustodianConfig.Resolve(GetArg(args, "--operator") ?? self);
            SecurityIdentifier impl = CustodianConfig.Resolve(GetArg(args, "--implementer") ?? self);
            SecurityIdentifier custodian = ServiceSid.Custodian();
            bool repair = HasFlag(args, "--repair-store");

            SecureStore.EnsureStore(custodian, op, impl, repair);
            SecureStore.EnsurePrivateProbe(custodian);
            new CustodianConfig
            {
                OperatorSid = op.Value, OperatorAccount = GetArg(args, "--operator") ?? self,
                ImplementerSid = impl.Value, ImplementerAccount = GetArg(args, "--implementer") ?? self,
            }.Save();
            Console.WriteLine($"provisioned: store protected (custodian SID {custodian.Value}), operator={op.Value}, implementer={impl.Value}");
            if (op.Value == impl.Value) Console.WriteLine("note: operator and implementer are the same account; the operator surface relies on token elevation (L1), which is NOT a production boundary");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("provision failed: " + e.Message); return 1; }
    }

    internal static int Deprovision(string[] args)
    {
        try
        {
            if (File.Exists(StorePaths.ConfigPath)) File.Delete(StorePaths.ConfigPath);
            Console.WriteLine("deprovisioned config (the store tree is left for the operator to remove)");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("deprovision failed: " + e.Message); return 1; }
    }

    internal static int Capabilities(string[] args)
    {
        HostCheck.Report r = HostCheck.Verify();
        Console.WriteLine(r.Facts.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        return r.MechanicsHealthy ? 0 : 4;
    }

    // ---- NON-PRIVILEGED self-tests (runnable by the implementer session directly) ----

    /// <summary>Verify the deterministic service-SID derivation against sc.exe's own value.</summary>
    internal static int SelfTestSid(string[] args)
    {
        string computed = ServiceSid.Custodian().Value;
        Console.WriteLine($"computed  NT SERVICE\\{CustodianConstants.ServiceName} = {computed}");
        string? sc = ShowSid(CustodianConstants.ServiceName);
        Console.WriteLine($"sc showsid                                  = {sc ?? "(unavailable)"}");
        bool ok = sc is null || string.Equals(sc, computed, StringComparison.OrdinalIgnoreCase);
        Console.WriteLine(ok ? "[PASS] service SID derivation matches" : "[FAIL] service SID mismatch");
        return ok ? 0 : 1;
    }

    /// <summary>Exercise the authorization digest + stale-state logic deterministically.</summary>
    internal static int SelfTestDigest(string[] args)
    {
        int failed = 0;
        var a1 = new JsonObject { ["repositoryRoot"] = "L:/x", ["repoKey"] = "k", ["loops"] = 2, ["minutes"] = 60 };
        string d1 = Digest.AuthorizationDigest("grant", a1, "state0", "cust", "req1", "nonce1", "2026-01-01T00:00:00Z");
        string d1b = Digest.AuthorizationDigest("grant", a1, "state0", "cust", "req1", "nonce1", "2026-01-01T00:00:00Z");
        failed += Check("digest is deterministic", d1 == d1b);
        failed += Check("digest changes with state (stale)", d1 != Digest.AuthorizationDigest("grant", a1, "state1", "cust", "req1", "nonce1", "2026-01-01T00:00:00Z"));
        failed += Check("digest changes with args", d1 != Digest.AuthorizationDigest("grant", new JsonObject { ["repositoryRoot"] = "L:/y" }, "state0", "cust", "req1", "nonce1", "2026-01-01T00:00:00Z"));
        failed += Check("digest changes with nonce", d1 != Digest.AuthorizationDigest("grant", a1, "state0", "cust", "req1", "nonce2", "2026-01-01T00:00:00Z"));
        failed += Check("canonical sorts keys", Digest.Canonical(new JsonObject { ["b"] = 1, ["a"] = 2 }) == "{\"a\":2,\"b\":1}");
        failed += Check("a fid1 key is a current identity", RepoIdentities.IsCurrent("fid1-ca0eadbe0eada3c3-10b95300000010000000000000000000"));
        failed += Check("a pre-P3.4C-0 textual key is not a current identity", !RepoIdentities.IsCurrent("0123456789abcdef"));
        Exception? mismatch = null;
        try { Request.Parse("{\"v\":" + (CustodianConstants.ProtocolVersion + 1) + ",\"requestId\":\"r\",\"op\":\"list_grants\",\"args\":{}}"); } catch (Exception e) { mismatch = e; }
        failed += Check("an engine speaking another protocol is refused (INVALID_ARGUMENT) with the remedy", mismatch is not null && CustodianCore.CodeOf(mismatch) == ErrorCodes.InvalidArgument
            && mismatch.Message.Contains($"this custodian speaks protocol {CustodianConstants.ProtocolVersion}") && mismatch.Message.Contains("same CodeParley release"));
        Console.WriteLine($"\ndigest self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    /// <summary>Exercise the grant ledger end to end (prepare/commit/consume, request-id conflict,
    /// stale-state refusal, exhaustion, revoke, and concurrent consumption) against a scratch store.</summary>
    internal static int SelfTestLedger(string[] args)
    {
        string scratch = GetArg(args, "--scratch") ?? Path.Combine(Path.GetTempPath(), "cp-ledger-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        StorePaths.OverrideRootForSelfTest(scratch);
        Directory.CreateDirectory(StorePaths.IntentsDir);
        int failed = 0;
        try
        {
            var led = new GrantLedger("cust-selftest");
            // Real directories: the custodian establishes a repository's identity from the filesystem.
            string repos = Path.Combine(Path.GetDirectoryName(scratch.TrimEnd('\\'))!, "repos");
            string repo = Directory.CreateDirectory(Path.Combine(repos, "Demo")).FullName;

            led.PrepareGrant(repo, 2, 60, "req-A");
            led.Commit("req-A", "proof-A");
            failed += Check("grant committed and active", (bool)led.ListGrants()["grants"]!.AsArray()[0]!["active"]!);
            // P3.4C-3: the engine registers a run (run_transition open) before it consumes a loop for it.
            RunSelfTest.Open(led, repo, "run-a");
            failed += Check("consume loop 1 of 2 (run a)", (int)led.ConsumeLoop(repo, "run-a", "c-a")["loopsUsed"]! == 1);
            RunSelfTest.Open(led, repo, "run-b");
            failed += Check("consume loop 2 of 2 (run b)", (int)led.ConsumeLoop(repo, "run-b", "c-b")["loopsUsed"]! == 2);
            failed += Check("a 3rd run (run c) is not even registered once the grant is used up (LOOP_NOT_AUTHORIZED), and consumes nothing (RUN_NOT_OPEN)",
                Throws(() => RunSelfTest.Open(led, repo, "run-c"), "LOOP_NOT_AUTHORIZED") && Throws(() => led.ConsumeLoop(repo, "run-c", "c-c"), "RUN_NOT_OPEN"));
            failed += Check("duplicate committed request id refused", Throws(() => led.PrepareGrant(repo, 1, 10, "req-A"), "REQUEST_ID_CONFLICT"));
            failed += Check("commit of unknown authorization refused", Throws(() => led.Commit("never-prepared", null), "AUTHORIZATION_INVALID"));

            // Stale: two authorizations prepared against the same state; the first to commit wins, the
            // second is refused because the ledger state it was shown has changed.
            string repo2 = Directory.CreateDirectory(Path.Combine(repos, "Stale")).FullName;
            led.PrepareGrant(repo2, 1, 60, "req-B");
            led.PrepareGrant(repo2, 1, 60, "req-C");
            led.Commit("req-B", null);
            failed += Check("stale authorization refused (STALE_FINDING_STATE)", Throws(() => led.Commit("req-C", null), "STALE_FINDING_STATE"));

            // Identity, not spelling: a grant made through one spelling is consumed and revoked through
            // another spelling of the same directory; a link to it is refused and consumes nothing.
            string aliased = Directory.CreateDirectory(Path.Combine(repos, "Aliased")).FullName;
            led.PrepareGrant(aliased, 3, 60, "req-alias");
            led.Commit("req-alias", null);
            RunSelfTest.Open(led, aliased.Replace('\\', '/'), "run-alias");
            failed += Check("consume through another spelling (slashes, case, trailing separator)", (int)led.ConsumeLoop(aliased.Replace('\\', '/').ToUpperInvariant() + "/", "run-alias", "c-alias")["loopsUsed"]! == 1);
            string link = Path.Combine(repos, "link-to-aliased");
            var mk = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{aliased}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(mk)!) { p.WaitForExit(); }
            if (Directory.Exists(link))
            {
                failed += Check("consume through a junction refused (INVALID_ARGUMENT, nothing consumed)", ThrowsType<RepoIdentityRefused>(() => led.ConsumeLoop(link, "run-j", "c-j")) && LoopsUsed(led, aliased) == 1);
                Directory.Delete(link);
            }
            led.PrepareRevoke(aliased.ToLowerInvariant(), "req-alias-revoke");
            failed += Check("revoke through another spelling revokes the grant", (int)led.Commit("req-alias-revoke", null)["revoked"]! == 1 && !AnyActive(led, aliased));

            // Replacement between prepare and commit: the operator was shown another object.
            string replaced = Directory.CreateDirectory(Path.Combine(repos, "Replaced")).FullName;
            led.PrepareGrant(replaced, 1, 60, "req-repl");
            Directory.Delete(replaced);
            Directory.CreateDirectory(replaced);
            failed += Check("a directory replaced between prepare and commit is refused (STALE_FINDING_STATE)", Throws(() => led.Commit("req-repl", null), "STALE_FINDING_STATE") && !AnyActive(led, replaced));

            // A pre-P3.4C-0 grant (textual key) is inert: listed as legacy, never active, never consumed.
            string legacyRepo = Directory.CreateDirectory(Path.Combine(repos, "Legacy")).FullName;
            LedgerFile withLegacy = led.Read();
            withLegacy.Grants.Add(new Grant(Guid.NewGuid().ToString(), "0123456789abcdef", legacyRepo, 5, 0, DateTime.UtcNow.ToString("o"),
                DateTime.UtcNow.AddHours(1).ToString("o"), null, new RecordedBy("user", "local_cli", "local_operator", "legacy", "req-legacy"), "req-legacy", []));
            File.WriteAllText(StorePaths.LedgerPath, JsonSerializer.Serialize(withLegacy, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
            JsonNode legacyRow = led.ListGrants()["grants"]!.AsArray().First(g => (string?)g!["repoKey"] == "0123456789abcdef")!;
            failed += Check("a legacy textual-key grant is listed as legacy_text and inactive", (string?)legacyRow["identity"] == "legacy_text" && !(bool)legacyRow["active"]!);
            failed += Check("a legacy textual-key grant authorizes nothing: no run is registered under it (LOOP_NOT_AUTHORIZED) and nothing is consumed",
                Throws(() => RunSelfTest.Open(led, legacyRepo, "run-legacy"), "LOOP_NOT_AUTHORIZED") && Throws(() => led.ConsumeLoop(legacyRepo, "run-legacy", "c-legacy"), "RUN_NOT_OPEN"));

            JsonNode? ceilings = led.ListGrants()["ceilings"];
            failed += Check("list_grants reports the enforced ceilings (8 loops / 180 min)", (int?)ceilings?["loops"] == CustodianConstants.MaxGrantLoops && (int?)ceilings?["minutes"] == CustodianConstants.MaxGrantMinutes);

            // Revoke.
            led.PrepareRevoke(repo2, "req-D");
            failed += Check("revoke committed", (int)led.Commit("req-D", null)["revoked"]! >= 1);
            failed += Check("revoked grant is inactive", !AnyActive(led, repo2));

            failed += ConcurrencyCase(repos);
            failed += ConsumeMintCase(repos);
            failed += UserRecordCase(repos);
            failed += LoopSelfTest.Run(repos); // P3.4C-2 increment 6: the loop_transition lifecycle
            failed += RunSelfTest.Run(repos); // P3.4C-3: the write-through store path and the run records
            Console.WriteLine($"\nledger self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
            return failed == 0 ? 0 : 1;
        }
        finally { TryDeleteTree(Path.GetDirectoryName(scratch.TrimEnd('\\'))!); }
    }

    /// <summary>A 1-loop grant consumed by many threads at once: exactly one must succeed.</summary>
    private static int ConcurrencyCase(string repos)
    {
        var led = new GrantLedger("cust-selftest");
        string repo = Directory.CreateDirectory(Path.Combine(repos, "Race")).FullName;
        led.PrepareGrant(repo, 1, 60, "req-race");
        led.Commit("req-race", null);
        int ok = 0, denied = 0;
        for (int i = 0; i < 12; i++) RunSelfTest.Open(led, repo, $"race-{i}"); // registering a run consumes nothing
        Parallel.For(0, 12, i =>
        {
            // Distinct runs, so the single-loop GRANT cap (not the one-loop-per-run rule) is what limits them.
            try { led.ConsumeLoop(repo, $"race-{i}", $"c-race-{i}"); Interlocked.Increment(ref ok); }
            catch { Interlocked.Increment(ref denied); }
        });
        return Check($"concurrent consume: exactly 1 of 12 succeeded (got {ok} ok, {denied} denied)", ok == 1 && denied == 11);
    }

    /// <summary>P3.4C-2: <c>consume_loop</c> atomically mints the custodian-owned UNBOUND loop record, is
    /// idempotent per request, allows one non-terminal loop per run, and returns the one-time bind-nonce
    /// preimage only on the minting call (only its hash is stored; no operation handle until bind).</summary>
    private static int ConsumeMintCase(string repos)
    {
        var led = new GrantLedger("cust-selftest");
        string repo = Directory.CreateDirectory(Path.Combine(repos, "Mint")).FullName;
        led.PrepareGrant(repo, 2, 60, "req-mint");
        led.Commit("req-mint", null);
        int failed = 0;

        RunSelfTest.Open(led, repo, "run-1");
        JsonObject r1 = led.ConsumeLoop(repo, "run-1", "cm-1");
        string loopId = (string)r1["loopId"]!;
        failed += Check("mint: result carries runId, epoch 1, revision 1", (string?)r1["runId"] == "run-1" && (int)r1["loopEpoch"]! == 1 && (int)r1["loopRevision"]! == 1);
        failed += Check("mint: one loop consumed (1 of 2)", (int)r1["loopsUsed"]! == 1 && (int)r1["loopsTotal"]! == 2);
        failed += Check("mint: one-time bind-nonce preimage returned (64 hex)", System.Text.RegularExpressions.Regex.IsMatch((string?)r1["bindNonce"] ?? "", "^[0-9a-f]{64}$"));

        LoopRecord? rec = led.Read().Loops!.FirstOrDefault(l => l.RunId == "run-1");
        failed += Check("mint: an UNBOUND loop record is co-located in the ledger (epoch 1, rev 1)", rec is { Status: "unbound", Epoch: 1, LoopRevision: 1 });
        failed += Check("mint: the loop carries the custodian's default limits", rec is not null && rec.Limits.Continuations == CustodianConstants.LoopContinuations && rec.Limits.RunSeconds == CustodianConstants.LoopRunSeconds);
        failed += Check("mint: only the nonce HASH is stored, never the preimage", rec is not null && System.Text.RegularExpressions.Regex.IsMatch(rec.BindNonce.Sha256, "^[0-9a-f]{64}$") && rec.BindNonce.Sha256 != (string?)r1["bindNonce"]);

        JsonObject r1b = led.ConsumeLoop(repo, "run-1", "cm-1");
        failed += Check("idempotent replay: same loopId, grant not re-consumed, no new preimage", (string?)r1b["loopId"] == loopId && (int)r1b["loopsUsed"]! == 1 && !r1b.ContainsKey("bindNonce"));
        failed += Check("idempotent replay: still exactly one loop for the run", led.Read().Loops!.Count(l => l.RunId == "run-1") == 1);

        failed += Check("a different request for the same live run → RUN_ALREADY_HAS_LOOP", Throws(() => led.ConsumeLoop(repo, "run-1", "cm-1-other"), "RUN_ALREADY_HAS_LOOP"));
        failed += Check("the refused second loop consumed nothing (loopsUsed still 1)", LoopsUsed(led, repo) == 1);

        RunSelfTest.Open(led, repo, "run-2");
        failed += Check("a second RUN consumes the second loop (2 of 2)", (int)led.ConsumeLoop(repo, "run-2", "cm-2")["loopsUsed"]! == 2);
        failed += Check("a third run is refused — grant exhausted (LOOP_NOT_AUTHORIZED at registration; nothing consumed)",
            Throws(() => RunSelfTest.Open(led, repo, "run-3"), "LOOP_NOT_AUTHORIZED") && Throws(() => led.ConsumeLoop(repo, "run-3", "cm-3"), "RUN_NOT_OPEN"));
        return failed;
    }

    /// <summary>P3.4C-1: the protected user-record log — decision/amendment records keyed by (repository
    /// identity, run), the operator/implementer projection split (the implementer never sees a raw note or
    /// amendment text), custodian-set provenance, the amendment correctness metadata, strict payload
    /// validation and the per-run revision stale check.</summary>
    private static int UserRecordCase(string repos)
    {
        var led = new GrantLedger("cust-selftest");
        string repo = Directory.CreateDirectory(Path.Combine(repos, "UserRec")).FullName;
        const string run = "run-selftest-1";
        const string hex64 = "abababababababababababababababababababababababababababababababab";
        int failed = 0;

        failed += Check("user-record log empty before any record (governed=false)", !(bool)led.ListUserRecords(repo, run, true)["governed"]!);

        // A decision: the operator surface keeps the note; the implementer projection never does, and the
        // custodian sets the provenance from the classified operator token (never from the request).
        led.PrepareUserRecord(repo, run, "decision", new JsonObject { ["kind"] = "waive", ["note"] = "operator-only note", ["thread_id"] = "t1", ["request_digest"] = "d1" }, 0, "ur-dec");
        JsonObject dc = led.Commit("ur-dec", "proof-dec");
        failed += Check("decision committed at seq 1, revision 1", (int)dc["seq"]! == 1 && (int)dc["revision"]! == 1);
        JsonObject opList = led.ListUserRecords(repo, run, true);
        failed += Check("governed after the first record", (bool)opList["governed"]!);
        JsonObject opDec = opList["records"]!.AsArray()[0]!.AsObject();
        failed += Check("operator projection carries the raw note", (string?)opDec["note"] == "operator-only note");
        failed += Check("custodian sets provenance (custodian_operator / local_admin_elevation)", (string?)opDec["recorded_by"]!["channel"] == "custodian_operator" && (string?)opDec["recorded_by"]!["assurance"] == "local_admin_elevation");
        JsonObject implDec = led.ListUserRecords(repo, run, false)["records"]!.AsArray()[0]!.AsObject();
        failed += Check("implementer projection drops the raw note", implDec["note"] is null);

        // An amendment with text: the custodian DERIVES the content-equivalence key (a keyed HMAC) and the
        // byte length from its authoritative text; the disclosure digest is engine-supplied. The raw text and
        // the HMAC secret stay off the implementer surface. (P3.4C-1 confidentiality correction.)
        string amd = "Prefer an explicit loop";
        led.PrepareUserRecord(repo, run, "amendment", new JsonObject { ["kind"] = "clarification", ["text"] = amd, ["disclosure_digest"] = hex64 }, 1, "ur-amd");
        JsonObject ac = led.Commit("ur-amd", null);
        failed += Check("amendment committed at seq 2, revision 2", (int)ac["seq"]! == 2 && (int)ac["revision"]! == 2);
        JsonObject opAmd = led.ListUserRecords(repo, run, true)["records"]!.AsArray()[1]!.AsObject();
        failed += Check("operator projection carries the raw amendment text", (string?)opAmd["text"] == amd);
        JsonObject implAmd = led.ListUserRecords(repo, run, false)["records"]!.AsArray()[1]!.AsObject();
        string? keyed = (string?)implAmd["contentKeyHash"];
        failed += Check("implementer projection drops the raw text, keeps the custodian-derived metadata",
            implAmd["text"] is null && keyed is not null && System.Text.RegularExpressions.Regex.IsMatch(keyed, "^[0-9a-f]{64}$")
            && (int?)implAmd["textBytes"] == System.Text.Encoding.UTF8.GetByteCount(amd) && (string?)implAmd["disclosureDigest"] == hex64);
        // Neither the raw text nor the secret leaks to the implementer surface.
        string implJson = led.ListUserRecords(repo, run, false).ToJsonString();
        failed += Check("implementer projection carries neither the raw amendment text nor the secret", !implJson.Contains(amd) && !implJson.Contains("secret"));
        // Dictionary attack: the keyed value is NOT the unkeyed SHA-256 of the normalized content an attacker
        // could compute offline without the secret.
        string unkeyed = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{AmendmentContentKey.Domain}\u0000{AmendmentContentKey.ContentKeyInput("clarification", amd)}")));
        failed += Check("the keyed content key is not reproducible by an offline unkeyed hash (dictionary-resistant)", keyed != unkeyed);

        // Equivalent normalized content → identical keys; different content/kind → distinct keys. A separate
        // run keeps the same secret, so equal content yields the same key (restart stability is covered below).
        string run2 = "run-selftest-2";
        string KeyFor(string r, string kind, string text, string rid, int rev)
        {
            led.PrepareUserRecord(repo, r, "amendment", new JsonObject { ["kind"] = kind, ["text"] = text, ["disclosure_digest"] = hex64 }, rev, rid);
            led.Commit(rid, null);
            var recs = led.ListUserRecords(repo, r, false)["records"]!.AsArray();
            return (string)recs[^1]!.AsObject()["contentKeyHash"]!;
        }
        string kA = KeyFor(run2, "clarification", "Prefer An  Explicit   LOOP", "ur-eqA", 0); // NFC/ws/case-equivalent to `amd`
        string kB = KeyFor(run2, "clarification", "totally different guidance", "ur-eqB", 1);
        string kC = KeyFor(run2, "scope", "Prefer an explicit loop", "ur-eqC", 2); // same text, different kind
        failed += Check("equivalent normalized content produces identical keys", kA == keyed);
        failed += Check("different content produces a distinct key", kB != keyed);
        failed += Check("a different kind produces a distinct key", kC != keyed);

        // Restart stability: a fresh ledger instance over the SAME store reads the persisted secret, so equal
        // content still yields the same key.
        var led2 = new GrantLedger("cust-selftest");
        led2.PrepareUserRecord(repo, "run-selftest-3", "amendment", new JsonObject { ["kind"] = "clarification", ["text"] = amd, ["disclosure_digest"] = hex64 }, 0, "ur-restart");
        led2.Commit("ur-restart", null);
        string kRestart = (string)led2.ListUserRecords(repo, "run-selftest-3", false)["records"]!.AsArray()[^1]!.AsObject()["contentKeyHash"]!;
        failed += Check("the keyed content key is stable across a custodian restart (persisted secret)", kRestart == keyed);

        // Strict payload validation.
        failed += Check("client-supplied provenance rejected", Throws(() => led.PrepareUserRecord(repo, run, "decision", new JsonObject { ["kind"] = "waive", ["recorded_by"] = new JsonObject() }, 2, "ur-forge"), "recorded_by"));
        failed += Check("a client-supplied content_key_hash is rejected", Throws(() => led.PrepareUserRecord(repo, run, "amendment", new JsonObject { ["kind"] = "scope", ["text"] = "x", ["content_key_hash"] = hex64, ["disclosure_digest"] = hex64 }, 2, "ur-cch"), "content_key_hash"));
        failed += Check("a client-supplied text_bytes is rejected", Throws(() => led.PrepareUserRecord(repo, run, "amendment", new JsonObject { ["kind"] = "scope", ["text"] = "x", ["text_bytes"] = 1, ["disclosure_digest"] = hex64 }, 2, "ur-ctb"), "text_bytes"));

        // Per-run revision stale check: two prepared against revision 2; the first to commit wins.
        led.PrepareUserRecord(repo, run, "decision", new JsonObject { ["kind"] = "defer", ["note"] = "" }, 2, "ur-r1");
        led.PrepareUserRecord(repo, run, "decision", new JsonObject { ["kind"] = "defer", ["note"] = "" }, 2, "ur-r2");
        led.Commit("ur-r1", null);
        failed += Check("a stale per-run base revision is refused at commit (STALE_FINDING_STATE)", Throws(() => led.Commit("ur-r2", null), "STALE_FINDING_STATE"));

        // Key loss / corruption fails closed (never silently regenerated while records depend on it). The secret is put
        // back afterwards: later self-tests record amendments in this store.
        byte[] secret = File.ReadAllBytes(StorePaths.ContentKeySecretPath);
        File.WriteAllText(StorePaths.ContentKeySecretPath, "{\"keyId\":\"zz\",\"secret\":\"not-base64-32-bytes\"}");
        failed += Check("a corrupt content-key secret fails closed", Throws(() => led.PrepareUserRecord(repo, "run-selftest-4", "amendment", new JsonObject { ["kind"] = "scope", ["text"] = "y", ["disclosure_digest"] = hex64 }, 0, "ur-corrupt"), "corrupt") || Throws(() => led.Commit("ur-corrupt", null), "corrupt"));
        File.WriteAllBytes(StorePaths.ContentKeySecretPath, secret);
        return failed;
    }

    /// <summary>NON-PRIVILEGED (P3.4C-1): assert the custodian's amendment content-equivalence NORMALIZATION
    /// reproduces TypeScript's `amendmentContentKey` exactly, against the shared golden corpus the TS test
    /// generates (test/fixtures/amendment-content-key-corpus.json). Cross-runtime parity oracle: NFC,
    /// JavaScript whitespace trim/collapse, JS toLowerCase (incl. İ and Greek Final_Sigma), kind/domain
    /// separation, empty/boundary inputs, and UTF-8 byte lengths.</summary>
    /// <summary>Phase 5: the content-key self-test is the portable core's (both hosts run it).</summary>
    internal static int SelfTestContentKey(string[] args) => ContentKeySelfTest.Run(args);

    private static bool AnyActive(GrantLedger led, string repo)
    {
        string key = RepoIdentities.Resolve(repo).Key;
        foreach (JsonNode? g in led.ListGrants()["grants"]!.AsArray())
            if ((string?)g!["repoKey"] == key && (bool)g["active"]!) return true;
        return false;
    }

    private static int LoopsUsed(GrantLedger led, string repo)
    {
        string key = RepoIdentities.Resolve(repo).Key;
        return led.ListGrants()["grants"]!.AsArray().Where(g => (string?)g!["repoKey"] == key).Sum(g => (int)g!["loopsUsed"]!);
    }

    private static bool Throws(Action a, string expectCode)
    {
        try { a(); return false; }
        catch (Exception e) { return e.Message.Contains(expectCode); }
    }

    private static bool ThrowsType<T>(Action a) where T : Exception
    {
        try { a(); return false; }
        catch (T) { return true; }
        catch { return false; }
    }

    /// <summary>Build a link/junction/hardlink/traversal corpus in a scratch root and prove the
    /// no-follow resolver reads a normal file but refuses every redirection vector.</summary>
    internal static int SelfTestNoFollow(string[] args)
    {
        string root = GetArg(args, "--scratch") ?? Path.Combine(Path.GetTempPath(), "cp-nofollow-" + Guid.NewGuid().ToString("N")[..8]);
        string outside = Path.Combine(Path.GetTempPath(), "cp-outside-" + Guid.NewGuid().ToString("N")[..8]);
        int failed = 0;
        try
        {
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(outside);
            string secret = Path.Combine(outside, "secret.txt");
            File.WriteAllText(secret, "OUTSIDE-SECRET");
            File.WriteAllText(Path.Combine(root, "normal.txt"), "INSIDE-OK");

            failed += Check("reads a normal file beneath the root", NoFollow.TryReadBeneath(root, "normal.txt", 1 << 20) is { Opened: true });
            failed += Check("refuses a parent traversal (..)", !NoFollow.TryReadBeneath(root, "../" + Path.GetFileName(outside) + "/secret.txt", 1 << 20).Opened);
            failed += Vector(root, secret, "file symlink", (link, tgt) => File.CreateSymbolicLink(link, tgt));
            failed += Vector(root, outside, "dir junction", (link, tgt) => Cmd($"/c mklink /J \"{link}\" \"{tgt}\""), viaDir: true);
            failed += Vector(root, secret, "hard link", (link, tgt) => Cmd($"/c mklink /H \"{link}\" \"{tgt}\""));

            // Contrast (the broker regression case): the vulnerable pattern (naive File.ReadAllText of a
            // path) FOLLOWS a symlink and leaks the outside secret, where the custodian's resolver refuses.
            string contrast = Path.Combine(root, "contrast_symlink");
            try { File.CreateSymbolicLink(contrast, secret); } catch { /* needs dev mode / privilege */ }
            if (File.Exists(contrast))
            {
                string naive = ""; try { naive = File.ReadAllText(contrast); } catch { }
                bool naiveLeaks = naive.Contains("OUTSIDE-SECRET");
                bool resolverRefuses = !NoFollow.TryReadBeneath(root, "contrast_symlink", 1 << 20).Opened;
                Console.WriteLine($"[{(naiveLeaks && resolverRefuses ? "PASS" : "INFO")}] contrast     -> naive File.ReadAllText {(naiveLeaks ? "FOLLOWS the link (broker pattern, leaks)" : "did not leak")}; resolver {(resolverRefuses ? "refuses" : "FOLLOWED")}" );
                failed += (resolverRefuses ? 0 : 1);
            }

            Console.WriteLine($"\nno-follow self-test: {(failed == 0 ? "all vectors refused, normal read OK" : failed + " FAILED")}");
            return failed == 0 ? 0 : 1;
        }
        finally
        {
            TryDeleteTree(root); TryDeleteTree(outside);
        }
    }

    /// <summary>Exercise the pipe server + caller classifier + core end to end in-process (NON-privileged,
    /// requires the real service not to be running). Confirms the implementer surface serves reduce-only
    /// ops and refuses operator ops, and the operator surface refuses this token when it is not elevated (and classifies
    /// it as the operator when it is: CI's Windows runner is elevated; the gate's refusal of a non-elevated operator token
    /// is also checked independently of the running token in self-test-helper-channel).</summary>
    internal static int SelfTestIpc(string[] args)
    {
        string scratch = Path.Combine(Path.GetTempPath(), "cp-ipc-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        StorePaths.OverrideRootForSelfTest(scratch);
        Directory.CreateDirectory(scratch);
        string me = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
        CallerClassifier.TokenFacts self = CallerClassifier.ReadFacts();
        bool elevated = CallerClassifier.IsElevated(self.ElevationType, self.Integrity);
        Console.WriteLine($"[INFO] this token is {(elevated ? "elevated: the operator pipe must classify it as the operator" : "not elevated: the operator pipe must refuse it")}");
        new CustodianConfig { OperatorSid = me, OperatorAccount = "self", ImplementerSid = me, ImplementerAccount = "self" }.Save();
        var cts = new CancellationTokenSource();
        int failed = 0;
        try
        {
            var core = new CustodianCore(me);
            Microsoft.Extensions.Logging.ILogger log = Environment.GetEnvironmentVariable("CP_IPC_DEBUG") == "1"
                ? new ConsoleLogger() : Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
            var server = new PipeServer(core, log, CustodianConfig.Load());
            Task run = server.RunAsync(cts.Token);
            Thread.Sleep(1000); // let both pipes begin listening

            var ping = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r1\",\"op\":\"ping\",\"args\":{}}");
            if (Environment.GetEnvironmentVariable("CP_IPC_DEBUG") == "1") Console.WriteLine("  ping -> " + ping);
            failed += Check("implementer ping ok", ping.Contains("\"pong\":true") && ping.Contains("\"caller\":\"implementer\""));
            var prep = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r2\",\"op\":\"prepare_grant\",\"args\":{\"repositoryRoot\":\"L:/x\",\"loops\":1,\"minutes\":10}}");
            failed += Check("prepare_grant on implementer pipe refused", prep.Contains(ErrorCodes.CallerNotAuthorized));
            var opPrep = IpcClient.Send("CodeParley.Custodian.v1.operator", "{\"v\":1,\"requestId\":\"r3\",\"op\":\"prepare_grant\",\"args\":{\"repositoryRoot\":\"L:/x\",\"loops\":1,\"minutes\":10}}");
            failed += elevated
                ? Check("operator pipe serves the elevated configured operator (not CALLER_NOT_AUTHORIZED)", !opPrep.Contains(ErrorCodes.CallerNotAuthorized) && opPrep.Length > 0)
                : Check("operator pipe refuses non-elevated caller", opPrep.Contains(ErrorCodes.CallerNotAuthorized));
            var bad = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r4\",\"op\":\"ping\",\"args\":{},\"role\":\"operator\"}");
            failed += Check("unknown top-level field rejected", bad.Contains(ErrorCodes.MalformedRequest));
            var forged = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r5\",\"op\":\"consume_loop\",\"args\":{\"repositoryRoot\":\"L:/x\",\"role\":\"operator\",\"assurance\":\"local_operator\"}}");
            failed += Check("forged authority field in args rejected (not ignored)", forged.Contains(ErrorCodes.MalformedRequest));
            // P3.4C-5 (§A.2): with no helper identity configured the helper pipe is not hosted at all (fail closed); the
            // helper surface itself is covered by self-test-helper-channel.
            failed += Check("no helper configured: the helper pipe is not hosted", !File.Exists(@"\\.\pipe\" + CustodianConstants.HelperPipe));
            var svc = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r6\",\"op\":\"service_identity\",\"args\":{}}");
            failed += Check("service_identity (write-probing diagnostic) refused on implementer surface", svc.Contains(ErrorCodes.CallerNotAuthorized));
            // P3.4C-1: prepare_user_record is operator-authority (refused on the implementer pipe); the READ
            // list_user_records is served on the implementer pipe (the engine's protected derivation reads it).
            var urPrep = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r7\",\"op\":\"prepare_user_record\",\"args\":{\"repositoryRoot\":\"L:/x\",\"runId\":\"run-ipc-1\",\"recordKind\":\"decision\",\"payload\":{\"kind\":\"waive\"},\"baseRevision\":0}}");
            failed += Check("prepare_user_record on implementer pipe refused (operator-only)", urPrep.Contains(ErrorCodes.CallerNotAuthorized));
            string repoJson = scratch.Replace('\\', '/');
            var urList = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"r8\",\"op\":\"list_user_records\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-1\"}}");
            failed += Check("list_user_records served on the implementer pipe (governed:false for an undecided run)", urList.Contains("\"governed\":false") && !urList.Contains(ErrorCodes.CallerNotAuthorized));
            // P3.4C-2: the loop lifecycle through the real pipe, classifier and dispatch.
            failed += LoopSelfTest.IpcCases(scratch, IpcClient.Send, elevated);
            // P3.4C-3: run_transition and the run section through the real pipe, classifier and dispatch.
            var rtNoGrant = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rt1\",\"op\":\"run_transition\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-2\",\"kind\":\"open\",\"fields\":{\"runJsonDigest\":\"" + new string('a', 64) + "\",\"budgets\":{\"maxReviews\":5,\"maxCheckExecutions\":50},\"baseline\":null}}}");
            failed += Check("run_transition open with no protected configuration (and no grant) → CONFIG_NOT_HELD over the pipe", rtNoGrant.Contains(ErrorCodes.ConfigNotHeld));
            // P3.4C-4 (M2): configuration is written only on the operator surface; the implementer reads the config section.
            var cfgPrep = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rc1\",\"op\":\"prepare_config_record\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"recordKind\":\"repository\",\"action\":\"revoke\",\"baseRevision\":0}}");
            failed += Check("prepare_config_record on the implementer pipe → CALLER_NOT_AUTHORIZED (M2)", cfgPrep.Contains(ErrorCodes.CallerNotAuthorized));
            var cfgPrepOp = IpcClient.Send("CodeParley.Custodian.v1.operator", "{\"v\":1,\"requestId\":\"rc2\",\"op\":\"prepare_config_record\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"recordKind\":\"repository\",\"action\":\"revoke\",\"baseRevision\":0}}");
            failed += elevated
                ? Check("prepare_config_record on the operator pipe from the elevated configured operator is not CALLER_NOT_AUTHORIZED", !cfgPrepOp.Contains(ErrorCodes.CallerNotAuthorized) && cfgPrepOp.Length > 0)
                : Check("prepare_config_record on the operator pipe from a non-elevated caller → CALLER_NOT_AUTHORIZED", cfgPrepOp.Contains(ErrorCodes.CallerNotAuthorized));
            var cfgList = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rc3\",\"op\":\"list_user_records\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-2\",\"sections\":[\"config\"]}}");
            failed += Check("list_user_records sections [config] served on the implementer pipe (no record held: repository null)", cfgList.Contains("\"config\":{") && cfgList.Contains("\"repository\":null"));
            var rtForged = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rt2\",\"op\":\"run_transition\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-2\",\"kind\":\"end\",\"fields\":{\"status\":\"closed\",\"reason\":\"x\",\"accepted\":true}}}");
            failed += Check("run_transition with an authority-shaped field → MALFORMED_REQUEST over the pipe", rtForged.Contains(ErrorCodes.MalformedRequest));
            var rtExtra = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rt3\",\"op\":\"run_transition\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-2\",\"kind\":\"end\",\"fields\":{},\"runRevision\":3}}");
            failed += Check("run_transition with an unknown argument → MALFORMED_REQUEST over the pipe", rtExtra.Contains(ErrorCodes.MalformedRequest));
            var runList = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rt4\",\"op\":\"list_user_records\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-2\",\"sections\":[\"run\"]}}");
            failed += Check("list_user_records sections [run]: the run section (not registered) and the protected answer over the pipe",
                runList.Contains("\"registered\":false") && runList.Contains("\"protected\":false") && !runList.Contains("\"loop\":"));
            var badSection = IpcClient.Send("CodeParley.Custodian.v1.implementer", "{\"v\":1,\"requestId\":\"rt5\",\"op\":\"list_user_records\",\"args\":{\"repositoryRoot\":\"" + repoJson + "\",\"runId\":\"run-ipc-2\",\"sections\":[\"run\",\"secrets\"]}}");
            failed += Check("list_user_records with an unknown section → INVALID_ARGUMENT over the pipe", badSection.Contains(ErrorCodes.InvalidArgument));
            // An argument error can quote client-chosen text (an id, a check name): it is classified by its type, so an id
            // that spells a code never selects that code; other errors keep their message classification.
            failed += Check("error classification: an argument error quoting a code-like id is INVALID_ARGUMENT; a stale commit stays STALE_FINDING_STATE",
                CustodianCore.CodeOf(new ArgumentException("review id STALE_FINDING_STATE was already used in this run")) == ErrorCodes.InvalidArgument
                && CustodianCore.CodeOf(new ArgumentException("check LOOP_TERMINAL is not planned by operation cop-1-000000000000")) == ErrorCodes.InvalidArgument
                && CustodianCore.CodeOf(new InvalidOperationException("the ledger changed since this was prepared; nothing was committed (STALE_FINDING_STATE)")) == ErrorCodes.StaleState
                && CustodianCore.CodeOf(new CustodianRefusal(ErrorCodes.RunBusy, "LOOP_TERMINAL in the text")) == ErrorCodes.RunBusy);
            Console.WriteLine($"\nipc self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
            return failed == 0 ? 0 : 1;
        }
        finally { cts.Cancel(); TryDeleteTree(Path.GetDirectoryName(scratch.TrimEnd('\\'))!); }
    }

    /// <summary>NON-PRIVILEGED, dev only: serve the real pipe server + core in-process for a bounded time,
    /// as the current user (operator = implementer = this account; the operator surface still requires an
    /// elevated token), against a scratch store, so a client — the TypeScript transport — can be exercised
    /// against the custodian's actual IPC code. The pipes are owned by this user, not by the custodian's
    /// service SID: a client expecting the real service identity must refuse them. Refuses to start when
    /// the custodian's pipes already exist (FirstPipeInstance: a running service keeps its names).</summary>
    internal static int SelfTestServe(string[] args)
    {
        int seconds = int.TryParse(GetArg(args, "--seconds"), out int s) ? Math.Clamp(s, 1, 600) : 60;
        string scratch = Path.Combine(Path.GetTempPath(), "cp-serve-" + Guid.NewGuid().ToString("N")[..8], "Custodian");
        if (File.Exists(@"\\.\pipe\" + CustodianConstants.ImplementerPipe) || File.Exists(@"\\.\pipe\" + CustodianConstants.OperatorPipe))
        {
            Console.Error.WriteLine("the custodian's pipes already exist (a custodian is running); not serving");
            return 3;
        }
        StorePaths.OverrideRootForSelfTest(scratch);
        Directory.CreateDirectory(scratch);
        string me = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
        new CustodianConfig { OperatorSid = me, OperatorAccount = "self", ImplementerSid = me, ImplementerAccount = "self" }.Save();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            var server = new PipeServer(new CustodianCore(me), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, CustodianConfig.Load());
            Task run = server.RunAsync(cts.Token);
            Thread.Sleep(500); // both pipes listening
            Console.WriteLine($"SERVING owner={me} seconds={seconds}");
            Console.Out.Flush();
            try { run.GetAwaiter().GetResult(); } catch (OperationCanceledException) { }
            return 0;
        }
        finally { cts.Cancel(); TryDeleteTree(Path.GetDirectoryName(scratch.TrimEnd('\\'))!); }
    }

    /// <summary>Run the capture-helper probe against a representative operator repo file (operator-run:
    /// the store and the private probe must already exist).</summary>
    internal static int ProbeCapture(string[] args)
    {
        string? repoFile = GetArg(args, "--repo-file");
        if (repoFile is null) { Console.Error.WriteLine("--repo-file <path to a representative operator-owned file> is required"); return 2; }
        Console.WriteLine(RestrictedReader.Probe(repoFile).ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    /// <summary>P3.4C-4 (TD clarification II): measure a Codex installation exactly as <c>config set</c> does at prepare and
    /// commit (no-follow walk, own handle, native PE only). Read-only and non-privileged; it measures with the caller's
    /// identity, so run it as the service account to learn what the service can measure.</summary>
    internal static int MeasureCodex(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("usage: measure-codex <path to codex.exe>"); return 2; }
        try
        {
            Console.WriteLine(CodexImage.Describe(CodexImage.Measure(args[1])));
            return 0;
        }
        catch (CustodianRefusal r)
        {
            Console.WriteLine($"refused {r.Code}: {r.Message}");
            return 1;
        }
    }

    // ---- helpers ----

    private static int Vector(string root, string target, string name, Action<string, string> make, bool viaDir = false)
    {
        string link = Path.Combine(root, name.Replace(' ', '_'));
        try { make(link, target); }
        catch (Exception e) { Console.WriteLine($"[skip] {name}: could not create vector ({e.Message.Split('\n')[0]})"); return 0; }
        if (!File.Exists(link) && !Directory.Exists(link)) { Console.WriteLine($"[skip] {name}: vector not created (mklink unavailable?)"); return 0; }
        string rel = viaDir ? name.Replace(' ', '_') + "/secret.txt" : name.Replace(' ', '_');
        NoFollow.Attempt a = NoFollow.TryReadBeneath(root, rel, 1 << 20);
        bool refused = !a.Opened;
        Console.WriteLine($"[{(refused ? "PASS" : "FAIL")}] {name,-14} -> {(refused ? "refused: " + a.Detail : "FOLLOWED (leak!)")}");
        return refused ? 0 : 1;
    }

    private static int Check(string name, bool ok) { Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}"); return ok ? 0 : 1; }

    private static string? ShowSid(string service)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", $"showsid {service}") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            string o = p.StandardOutput.ReadToEnd(); p.WaitForExit();
            foreach (string ln in o.Split('\n'))
                if (ln.Contains("SERVICE SID:", StringComparison.OrdinalIgnoreCase) || ln.TrimStart().StartsWith("S-1-5-80", StringComparison.OrdinalIgnoreCase))
                    return ln.Split(':').Last().Trim();
            return null;
        }
        catch { return null; }
    }

    private static void Cmd(string arguments)
    {
        var psi = new ProcessStartInfo("cmd.exe", arguments) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        using var p = Process.Start(psi)!;
        p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException($"cmd exited {p.ExitCode}");
    }

    private static int Sc(string rawArguments)
    {
        var psi = new ProcessStartInfo("sc.exe", rawArguments) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("failed to start sc.exe");
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) Console.Error.WriteLine($"sc.exe {rawArguments.Split(' ')[0]} -> {p.ExitCode}: {output.Trim()}");
        return p.ExitCode;
    }

    private sealed class ConsoleLogger : Microsoft.Extensions.Logging.ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? e, Func<TState, Exception?, string> fmt)
            => Console.WriteLine($"  [svc {logLevel}] {fmt(state, e)}{(e is null ? "" : " :: " + e.GetType().Name + ": " + e.Message + " @ " + (e.StackTrace?.Split('\n')[0]?.Trim()))}");
    }

    /// <summary>Minimal one-shot pipe client for the in-process IPC self-test.</summary>
    private static class IpcClient
    {
        internal static string Send(string pipe, string request)
        {
            var c = new System.IO.Pipes.NamedPipeClientStream(".", pipe, System.IO.Pipes.PipeDirection.InOut,
                System.IO.Pipes.PipeOptions.None, System.Security.Principal.TokenImpersonationLevel.Identification);
            try
            {
                c.Connect(4000);
                byte[] payload = System.Text.Encoding.UTF8.GetBytes(request + "\n");
                c.Write(payload, 0, payload.Length);
                c.Flush();
                var r = new StreamReader(c, System.Text.Encoding.UTF8);
                return r.ReadLine() ?? ""; // the server disconnects after one response; do not flush again
            }
            finally { try { c.Dispose(); } catch { } }
        }
    }

    private static void TryDeleteTree(string dir) { try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { } }
    private static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
    private static bool HasFlag(string[] args, string name) => args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
}
