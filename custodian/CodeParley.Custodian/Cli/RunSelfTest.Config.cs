using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-4 — the custodian-held trusted configuration (contract §2–§4), deterministic and non-privileged, each case on a
/// store of its own (global records are shared within a store). The rows of contract §7.1 the ledger can show on its own:
/// M2 (stale commits; the operator-only surface is the IPC self-test), TD clarification I (a re-confirmation binds every
/// record it clears), M3, M4, M5, M7, M8, M9 (validation and caps; digest parity is the shared corpus), M11 (a)–(e) on
/// the custodian's side, M12 (interrupted recovery with U4b: the recovery self-tests) and M13 (the Codex installation's
/// forms). The engine's side of M1, M6, M10 and M11 is in the TypeScript suite.
/// </summary>
internal static partial class RunSelfTest
{
    private static int ConfigCases(string repos)
    {
        int failed = 0;
        failed += ConfigStoreCases(repos);
        failed += ReconfirmBindingCases(repos);
        failed += PlannedCheckCases(repos);
        failed += IsolationBasisCases(repos);
        failed += LifecycleCases(repos);
        failed += ConfigRecoveryCases(repos);
        failed += ConfigRollbackCases(repos);
        failed += ConfigValidationCases(repos);
        failed += CodexFormCases(repos);
        return failed;
    }

    private static ConfigRecordsFile Cfg() => GrantLedger.ReadConfigRecordsLocked();
    private static RepositoryConfig? RepoCfg(string repo) => Cfg().CurrentOf(RepoIdentities.Resolve(repo).Key);

    /// <summary>A repository directory for one case (its own name, below the shared repos folder).</summary>
    private static string CaseRepo(string repos, string name) => Directory.CreateDirectory(Path.Combine(repos, "cfg", name)).FullName;

    // ---- the store, the operator path, M2, M5 ----

    private static int ConfigStoreCases(string repos) => WithFreshStore("config-store", () =>
    {
        int failed = 0;
        var led = new GrantLedger("cust-selftest", new Table());
        string repo = CaseRepo(repos, "Store");
        string pe = ConfigFixture.WritePe(repo + "-x");
        string rid = ConfigFixture.Rid("set");
        PreparedAuthorization prep = led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, ConfigFixture.RepositoryPayload(pe), 0, rid);
        failed += Check("prepare_config_record (set): nothing is recorded until commit; the rendering shows every check's argv, the floor, the capture rules and the measured Codex image",
            RepoCfg(repo) is null && prep.Rendering.Contains("\"scripts/pass.js\"") && prep.Rendering.Contains("required profiles default")
            && prep.Rendering.Contains("**/.env") && prep.Rendering.Contains(ConfigFixture.CodexSha256) && prep.Rendering.Contains("passthrough names"));
        JsonObject c = led.Commit(rid, "proof-op");
        RepositoryConfig r = RepoCfg(repo)!;
        failed += Check("commit: revision 1; the custodian computed every definition digest, the capture-rules digest and the record digest; the installation is as measured",
            (int)c["configRevision"]! == 1 && r.ConfigRevision == 1 && r.Checks["unit"].DefinitionDigest == ConfigFixture.Digest("unit")
            && r.CaptureRulesDigest == ConfigFixture.CaptureRulesDigest && r.CodexInstallation is { Form: "native_pe", Size: 512 } i && i.Sha256 == ConfigFixture.CodexSha256
            && r.ConfigDigest.Length == 64 && r.RecordedBy.Assurance == "local_admin_elevation" && r.RecordedBy.ProofDigest == "proof-op");
        failed += Check("commit replay: the authorization is spent (AUTHORIZATION_INVALID); the request id cannot be prepared again (REQUEST_ID_CONFLICT)",
            ThrowsWith(() => led.Commit(rid, null), "AUTHORIZATION_INVALID")
            && ThrowsWith(() => led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Revoke, null, null, 1, rid), "REQUEST_ID_CONFLICT"));

        // M2: a commit after a concurrent change is STALE_CONFIG; nothing of it is recorded.
        string a = ConfigFixture.Rid("set-a"), b = ConfigFixture.Rid("set-b");
        led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, ConfigFixture.RepositoryPayload(pe, rules: ConfigFixture.DefaultRules()), 1, a);
        led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Revoke, null, null, 1, b);
        led.Commit(b, null);
        failed += Check("M2: a set committed after a concurrent revoke → STALE_CONFIG; the revocation stands",
            RefusalCode(() => led.Commit(a, null)) == ErrorCodes.StaleConfig && RepoCfg(repo) is { IsRevoked: true, ConfigRevision: 2 });
        failed += Check("M2: a prepare against an old revision → STALE_CONFIG",
            RefusalCode(() => led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, ConfigFixture.RepositoryPayload(pe), 1, ConfigFixture.Rid("old"))) == ErrorCodes.StaleConfig);
        failed += Check("history: every version is kept (set, revoke), the earlier one marked superseded",
            Cfg().Repositories.Count(x => x.RepoKey == r.RepoKey) == 2 && Cfg().Repositories.First(x => x.RepoKey == r.RepoKey).SupersededAt is not null);

        // M5: a revoked record is not usable; the start is refused CONFIG_NOT_HELD, nothing registered or consumed.
        Grant(led, repo, 1);
        failed += Check("M5: a revoked configuration → open CONFIG_NOT_HELD; nothing registered or consumed",
            RefusalCode(() => Do(led, Engine, repo, "run-cfg-m5", "open", OpenFields())) == ErrorCodes.ConfigNotHeld
            && !IsProtected(led, repo, "run-cfg-m5") && LoopsUsed(led, repo) == 0);
        ConfigFixture.Set(led, repo, ConfigFixture.RepositoryPayload(pe));
        JsonObject opened = Do(led, Engine, repo, "run-cfg-m5", "open", OpenFields());
        failed += Check("open under a usable record: the run pins the record's revision and digest",
            (int)opened["configRevision"]! == 3 && GrantLedger.ReadRunLocked(r.RepoKey, "run-cfg-m5")!.OpenedConfig is { ConfigRevision: 3 });

        // The config section: both projections; the implementer's carries no operator identity facts (D-C').
        JsonObject impl = led.ListUserRecords(repo, "run-cfg-m5", false, new HashSet<string> { "config" });
        JsonObject oper = led.ListUserRecords(repo, "run-cfg-m5", true, new HashSet<string> { "config" });
        failed += Check("the config section: the record, its revision and state; the implementer projection without recordedBy, the operator's with it",
            (int)impl["config"]!["repository"]!["configRevision"]! == 3 && (bool)impl["config"]!["repository"]!["usable"]! && !impl.ToJsonString().Contains("recordedBy")
            && !impl.ToJsonString().Contains("proof-op") && oper["config"]!["repository"]!["recordedBy"] is not null);
        failed += Check("the config section on a repository with no record: repository null; the global records listed",
            led.ListUserRecords(CaseRepo(repos, "Empty"), "r-x", false, new HashSet<string> { "config" })["config"]!["repository"] is null);
        return failed;
    });

    // ---- TD clarification I: a re-confirmation binds every record it clears ----

    private static int ReconfirmBindingCases(string repos) => WithFreshStore("config-reconfirm-binding", () =>
    {
        int failed = 0;
        var boot = new Boot(B1);
        var led = new GrantLedger("cust-selftest", new Table());
        led.StartupRecovery(boot);
        string repo = CaseRepo(repos, "Binding");
        ConfigFixture.Hold(led, repo, repo + "-x");
        string extra = ConfigFixture.Accept(led, backend: "elevated");
        boot.Value = B2;
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        ConfigRecordsFile lapsed = Cfg();
        failed += Check("I: after a new boot the repository record and every global record are lapsed",
            RepoCfg(repo)!.IsLapsed && lapsed.Acceptances.All(x => x.LapsedAtRecoveryId is not null) && lapsed.SelftestConfirmations.Where(x => x.SupersededAt is null).All(x => x.LapsedAtRecoveryId is not null));

        string rid = ConfigFixture.Rid("reconfirm");
        PreparedAuthorization p = led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Reconfirm, null, null, RepoCfg(repo)!.ConfigRevision, rid);
        failed += Check("I: the re-confirmation renders the surviving record and every lapsed global record it clears",
            p.Rendering.Contains("AS IT SURVIVED") && p.Rendering.Contains(extra) && p.Rendering.Contains("self-test confirmation") && p.Rendering.Contains("isolation acceptance"));
        // A concurrent change to ONE affected global record (the operator revokes it elsewhere) makes the whole prepared
        // re-confirmation stale: nothing is committed — not the repository record, not the other globals.
        ConfigFixture.RevokeGlobal(led, ConfigKinds.IsolationAcceptance, extra);
        failed += Check("I: one affected global record changed between prepare and commit → STALE_CONFIG; no partial commit",
            RefusalCode(() => led.Commit(rid, null)) == ErrorCodes.StaleConfig && RepoCfg(repo)!.IsLapsed
            && Cfg().Acceptances.Where(x => x.RevokedAt is null).All(x => x.LapsedAtRecoveryId is not null)
            && Cfg().SelftestConfirmations.Where(x => x.SupersededAt is null).All(x => x.LapsedAtRecoveryId is not null));
        JsonObject done = ConfigFixture.Reconfirm(led, repo);
        failed += Check("I: prepared again and committed, the one commit clears the repository record and every lapsed global record, with new revisions",
            !RepoCfg(repo)!.IsLapsed && RepoCfg(repo)!.Action == ConfigKinds.Reconfirm && (int)done["globalsReconfirmed"]! >= 2
            && Cfg().Acceptances.Where(x => x.RevokedAt is null).All(x => x.LapsedAtRecoveryId is null)
            && Cfg().SelftestConfirmations.Where(x => x.SupersededAt is null).All(x => x.LapsedAtRecoveryId is null));
        failed += Check("I: nothing left to re-confirm → INVALID_ARGUMENT",
            RefusalCode(() => led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Reconfirm, null, null, RepoCfg(repo)!.ConfigRevision, ConfigFixture.Rid("again"))) == ErrorCodes.InvalidArgument);
        return failed;
    });

    // ---- M3: planned and executed definitions ----

    private static int PlannedCheckCases(string repos) => WithFreshStore("config-planned", () =>
    {
        int failed = 0;
        Fx fx = Protected(repos, "CfgPlanned");
        JsonObject Plan(string check, string? digest) => new()
        {
            ["operationKind"] = "checks",
            ["planned"] = new JsonArray(new JsonObject { ["check"] = check, ["checkSpecId"] = null, ["definitionDigest"] = digest, ["required"] = true }),
            ["inputIdentity"] = null,
        };
        failed += Check("M3: a planned check the held record does not approve → CHECK_NOT_APPROVED; nothing begun",
            RefusalCode(() => Do(fx, Engine, "op_begin", Plan("evil", Hex))) == ErrorCodes.CheckNotApproved && Run(fx).Operations.Count == 0);
        failed += Check("M3: a planned check whose definition differs from the approved one → CHECK_NOT_APPROVED",
            RefusalCode(() => Do(fx, Engine, "op_begin", Plan("unit", Hex))) == ErrorCodes.CheckNotApproved);
        string op = (string)Do(fx, Engine, "op_begin", ChecksBegin())["operationId"]!;
        failed += Check("op_begin (checks) pins the operation to the record's revision", Run(fx).Operations.Single().Pin is { ConfigRevision: 1 });
        JsonObject forged = Exec(op, "e-forged");
        forged["execution"]!["definitionDigest"] = Hex;
        failed += Check("M3: an execution whose definition digest differs from the planned one → EVIDENCE_NOT_HELD; nothing recorded",
            RefusalCode(() => Do(fx, Engine, "record_execution", forged)) == ErrorCodes.EvidenceNotHeld && Run(fx).CheckExecutions.Count == 0);
        Do(fx, Engine, "record_execution", Exec(op, "e1"));
        failed += Check("record_execution: the execution carries the configuration revision it ran under", (int?)Run(fx).CheckExecutions.Single()["configRevision"] == 1);
        Do(fx, Engine, "op_finish", Finish(op, ChecksOutcome()));
        // A check planned without a definition (it will only be skipped) begins; running it is refused.
        string op2 = (string)Do(fx, Engine, "op_begin", Plan("gone", null))["operationId"]!;
        JsonObject ranGone = Exec(op2, "e-gone", check: "gone");
        failed += Check("a check planned with no definition may only be skipped: a run execution of it → EVIDENCE_NOT_HELD; a skipped one is recorded",
            RefusalCode(() => Do(fx, Engine, "record_execution", ranGone)) == ErrorCodes.EvidenceNotHeld
            && Ok(() => Do(fx, Engine, "record_execution", Exec(op2, "e-gone-s", check: "gone", status: "skipped", skipReason: "definition_removed"))));
        return failed;
    });

    // ---- M4: the isolation basis, capture rules and Codex image of a review ----

    private static int IsolationBasisCases(string repos) => WithFreshStore("config-isolation", () =>
    {
        int failed = 0;
        Fx fx = Protected(repos, "CfgIsolation");
        JsonObject Begin(string id, Action<JsonObject>? change = null)
        {
            JsonObject b = ReviewBegin(id, reviewInput: Digest.Sha256Hex(id));
            change?.Invoke(b);
            return b;
        }
        failed += Check("M4: an S1 claim naming a self-test the operator never confirmed → ISOLATION_NOT_ACCEPTED",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri1", b => b["isolation"]!["selftestId"] = "st-forged"))) == ErrorCodes.IsolationNotAccepted);
        failed += Check("M4: an S1 claim for another Codex version or backend than the confirmation's → ISOLATION_NOT_ACCEPTED",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri2", b => b["isolation"]!["codexVersion"] = "0.161.0"))) == ErrorCodes.IsolationNotAccepted
            && RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri3", b => b["isolation"]!["backend"] = "unelevated"))) == ErrorCodes.IsolationNotAccepted);
        failed += Check("M4: an S2 claim naming an acceptance the custodian does not hold → ISOLATION_NOT_ACCEPTED",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri4", b => { b["isolation"] = ConfigFixture.Isolation("S2"); b["isolation"]!["acceptanceId"] = Guid.NewGuid().ToString(); }))) == ErrorCodes.IsolationNotAccepted);
        failed += Check("M4: a capture-rules digest other than the held rules' → CONFIG_MISMATCH",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri5", b => b["captureRulesDigest"] = Hex))) == ErrorCodes.ConfigMismatch);
        failed += Check("M4/M13: a Codex SHA-256 other than the approved installation's → CONFIG_MISMATCH",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri6", b => b["codexSha256"] = Hex))) == ErrorCodes.ConfigMismatch);
        failed += Check("an S2 review on a held acceptance begins; its pin names the acceptance", Ok(() => Do(fx, Engine, "op_begin", Begin("ri7", b => b["isolation"] = ConfigFixture.Isolation("S2"))))
            && Run(fx).Operations.Last().Pin is { IsolationKind: ConfigKinds.IsolationAcceptance } pin && pin.IsolationRecordId == ConfigFixture.LastAcceptanceId);
        string op = Run(fx).Operations.Last().OperationId;
        Do(fx, Engine, "op_finish", Finish(op, ReviewOutcome()));
        ConfigFixture.RevokeGlobal(fx.Led, ConfigKinds.SelftestConfirmation, Cfg().SelftestConfirmations.First(c => c.SelftestId == "st-1" && c.IsUsable).ConfirmationId);
        failed += Check("M4: an S1 claim naming a REVOKED confirmation → ISOLATION_NOT_ACCEPTED",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri8"))) == ErrorCodes.IsolationNotAccepted);
        // M13: a repository record with no Codex installation refuses protected reviews.
        ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(null));
        failed += Check("M13: a protected review on a record with no approved Codex installation → CONFIG_NOT_HELD",
            RefusalCode(() => Do(fx, Engine, "op_begin", Begin("ri9", b => b["isolation"] = ConfigFixture.Isolation("S2")))) == ErrorCodes.ConfigNotHeld);
        return failed;
    });

    // ---- M11: pinned versus current (§4.3), the custodian's side ----

    private static int LifecycleCases(string repos)
    {
        int failed = 0;
        // (a) before op_begin: the current record gates.
        failed += WithFreshStore("config-lifecycle-a", () =>
        {
            Fx fx = Protected(repos, "CfgLifeA");
            JsonObject checks = new() { ["lint"] = ConfigFixture.Definition("LINT"), ["test"] = ConfigFixture.Definition("TEST"), ["unit"] = ConfigFixture.Definition("UNIT-CHANGED") };
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-x"), checks));
            int f = Check("M11 (a): a definition changed before op_begin → the old one is CHECK_NOT_APPROVED", RefusalCode(() => Do(fx, Engine, "op_begin", ChecksBegin())) == ErrorCodes.CheckNotApproved);
            ConfigFixture.RevokeGlobal(fx.Led, ConfigKinds.IsolationAcceptance, ConfigFixture.LastAcceptanceId);
            JsonObject s2 = ReviewBegin("rla", reviewInput: Hex);
            s2["isolation"] = ConfigFixture.Isolation("S2");
            return f + Check("M11 (a): an acceptance revoked before op_begin → ISOLATION_NOT_ACCEPTED", RefusalCode(() => Do(fx, Engine, "op_begin", s2)) == ErrorCodes.IsolationNotAccepted);
        });
        // (b) a check's approval changes between op_begin and record_execution: recorded under the pin.
        failed += WithFreshStore("config-lifecycle-b", () =>
        {
            Fx fx = Protected(repos, "CfgLifeB");
            string op = (string)Do(fx, Engine, "op_begin", ChecksBegin())["operationId"]!;
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-x"), new JsonObject { ["unit"] = ConfigFixture.Definition("UNIT-CHANGED") }));
            return Check("M11 (b): a definition changed between op_begin and record_execution → the execution is still recorded under its pin (revision 1); its currency is the engine's derivation",
                Ok(() => Do(fx, Engine, "record_execution", Exec(op, "eb1"))) && (int?)Run(fx).CheckExecutions.Single()["configRevision"] == 1 && RepoCfg(fx.Repo)!.ConfigRevision == 2);
        });
        // (c) between op_begin and op_finish: the review is not accepted.
        failed += WithFreshStore("config-lifecycle-c", () =>
        {
            Fx fx = Protected(repos, "CfgLifeC");
            string Begin(string id, string mode)
            {
                JsonObject b = ReviewBegin(id, reviewInput: Digest.Sha256Hex(id));
                b["isolation"] = ConfigFixture.Isolation(mode);
                return (string)Do(fx, Engine, "op_begin", b)["operationId"]!;
            }
            string op1 = Begin("rc1", "S2");
            ConfigFixture.RevokeGlobal(fx.Led, ConfigKinds.IsolationAcceptance, ConfigFixture.LastAcceptanceId);
            JsonObject r1 = Do(fx, Engine, "op_finish", Finish(op1, ReviewOutcome()));
            int f = Check("M11 (c): the acceptance revoked during the review → not accepted (isolation_basis_revoked)",
                (bool)r1["accepted"]! == false && r1["notAcceptedReasons"]!.AsArray().Any(x => (string?)x == "isolation_basis_revoked"));
            string op2 = Begin("rc2", "S1");
            JsonObject rules = ConfigFixture.DefaultRules();
            rules["excludeGlobs"] = new JsonArray("**/.env");
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-x"), rules: rules));
            JsonObject r2 = Do(fx, Engine, "op_finish", Finish(op2, ReviewOutcome()));
            f += Check("M11 (c): the capture rules changed during the review → not accepted (config_changed_during_review)",
                (bool)r2["accepted"]! == false && r2["notAcceptedReasons"]!.AsArray().Any(x => (string?)x == "config_changed_during_review"));
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-x"))); // the default rules again
            string op3 = Begin("rc3", "S1");
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-y", variant: 7)));
            JsonObject r3 = Do(fx, Engine, "op_finish", Finish(op3, ReviewOutcome()));
            return f + Check("M11 (c): the Codex installation changed during the review → not accepted (config_changed_during_review)",
                (bool)r3["accepted"]! == false && r3["notAcceptedReasons"]!.AsArray().Any(x => (string?)x == "config_changed_during_review"));
        });
        // (d) after acceptance: basisUsable false, the reason named; (e) after recovery: lapsed.
        failed += WithFreshStore("config-lifecycle-d", () =>
        {
            var boot = new Boot(B1);
            new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
            Fx fx = Protected(repos, "CfgLifeD");
            JsonObject b1 = ReviewBegin("rd1", reviewInput: Digest.Sha256Hex("rd1"));
            b1["isolation"] = ConfigFixture.Isolation("S2");
            string op1 = (string)Do(fx, Engine, "op_begin", b1)["operationId"]!;
            Do(fx, Engine, "op_finish", Finish(op1, ReviewOutcome()));
            string op2 = (string)Do(fx, Engine, "op_begin", ReviewBegin("rd2", reviewInput: Digest.Sha256Hex("rd2")))["operationId"]!;
            Do(fx, Engine, "op_finish", Finish(op2, ReviewOutcome()));
            JsonObject Basis() => fx.Led.ListUserRecords(fx.Repo, fx.Run, false, new HashSet<string> { "run" })["run"]!["reviewBasis"]!.AsObject();
            int f = Check("M11 (d): accepted reviews on a usable basis → basisUsable true", (bool)Basis()["rd1"]!["basisUsable"]! && (bool)Basis()["rd2"]!["basisUsable"]!);
            ConfigFixture.RevokeGlobal(fx.Led, ConfigKinds.IsolationAcceptance, ConfigFixture.LastAcceptanceId);
            f += Check("M11 (d): the acceptance revoked after acceptance → that review's basisUsable false (isolation_basis_revoked); the S1 one unaffected",
                !(bool)Basis()["rd1"]!["basisUsable"]! && (string?)Basis()["rd1"]!["basisReason"] == "isolation_basis_revoked" && (bool)Basis()["rd2"]!["basisUsable"]!);
            JsonObject review = fx.Led.ListUserRecords(fx.Repo, fx.Run, false, new HashSet<string> { "run" })["run"]!["record"]!["reviews"]!.AsArray().Cast<JsonObject>().Single(r => (string?)r["reviewId"] == "rd1");
            f += Check("M11 (d): the implementer projection carries basisUsable on the review itself", review["basisUsable"] is JsonValue v && !v.GetValue<bool>());
            JsonObject rules = ConfigFixture.DefaultRules();
            rules["maxDiffBytes"] = 1000;
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-x"), rules: rules));
            f += Check("M11 (d): the capture rules changed after acceptance → basisUsable false (config_changed_since_review)",
                (string?)Basis()["rd2"]!["basisReason"] == "config_changed_since_review");
            ConfigFixture.Set(fx.Led, fx.Repo, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(fx.Repo + "-x")));
            f += Check("M11 (d): restoring the rules the review was pinned under → usable again (the pin compares content, not revision)", (bool)Basis()["rd2"]!["basisUsable"]!);
            boot.Value = B2;
            new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
            f += Check("M11 (e): after recovery the configuration lapsed → basisUsable false (config_lapsed); the evidence epoch rose",
                (string?)Basis()["rd2"]!["basisReason"] == "config_lapsed" && RunOf(fx).EvidenceEpoch == 2);
            return f;
        });
        return failed;
    }

    // ---- M7: U4b and the lazy, per-repository re-confirmation ----

    private static int ConfigRecoveryCases(string repos) => WithFreshStore("config-recovery", () =>
    {
        int failed = 0;
        var boot = new Boot(B1);
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        Fx a = Protected(repos, "CfgRecA");
        string repoB = CaseRepo(repos, "RecB");
        ConfigFixture.Set(a.Led, repoB, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(repoB + "-x")));
        Grant(a.Led, repoB, 2);
        // Ordinary operation never lapses anything: a configuration change and a same-boot restart.
        ConfigFixture.Set(a.Led, repoB, ConfigFixture.RepositoryPayload(ConfigFixture.WritePe(repoB + "-x")));
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        failed += Check("M7: a configuration change and a same-boot restart lapse nothing", !RepoCfg(a.Repo)!.IsLapsed && !RepoCfg(repoB)!.IsLapsed && Cfg().Acceptances.All(x => x.LapsedAtRecoveryId is null));

        boot.Value = B2;
        RecoveryOutcome rec = new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        failed += Check("M7: a new boot lapses every repository record, acceptance and confirmation (U4b), stamped with the recovery",
            RepoCfg(a.Repo)!.LapsedAtRecoveryId == rec.RecoveryId && RepoCfg(repoB)!.LapsedAtRecoveryId == rec.RecoveryId
            && Cfg().Acceptances.All(x => x.LapsedAtRecoveryId == rec.RecoveryId) && Cfg().SelftestConfirmations.Where(x => x.SupersededAt is null).All(x => x.LapsedAtRecoveryId == rec.RecoveryId));
        var led = new GrantLedger("cust-selftest", new Table());
        string start = RefusalCode(() => Do(led, Engine, repoB, "run-recb", "open", OpenFields()))!;
        failed += Check("M7: the first protected use refuses CONFIG_LAPSED and names the one command that re-confirms the repository",
            start == ErrorCodes.ConfigLapsed && ThrowsWith(() => Do(led, Engine, repoB, "run-recb", "open", OpenFields()), "setup --resume --repo"));
        // One re-confirmation for repository A clears its record and every lapsed global; B then needs only its own.
        JsonObject ra = ConfigFixture.Reconfirm(led, a.Repo);
        failed += Check("M7: one reconfirm (repository A) clears A's record and the lapsed global records; B stays lapsed",
            !RepoCfg(a.Repo)!.IsLapsed && (int)ra["globalsReconfirmed"]! >= 2 && RepoCfg(repoB)!.IsLapsed && Cfg().Acceptances.All(x => x.LapsedAtRecoveryId is null));
        string ridB = ConfigFixture.Rid("reconfirm-b");
        PreparedAuthorization pb = led.PrepareConfigRecord(repoB, ConfigKinds.Repository, ConfigKinds.Reconfirm, null, null, RepoCfg(repoB)!.ConfigRevision, ridB);
        failed += Check("M7: repository B's re-confirmation renders only its own record (no lapsed global left)", pb.Rendering.Contains("Lapsed global records: none"));
        led.Commit(ridB, null);
        failed += Check("M7: after its re-confirmation B starts (the grant suspended by U2 is the next refusal, not the configuration)",
            RefusalCode(() => Do(led, Engine, repoB, "run-recb", "open", OpenFields())) == ErrorCodes.LoopNotAuthorized);
        // A re-measured installation that differs refuses the re-confirmation.
        boot.Value = B3;
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        File.WriteAllBytes(RepoCfg(repoB)!.CodexInstallation!.Path, ConfigFixture.PeBytes(9));
        failed += Check("M7: a re-measured Codex installation that differs → CONFIG_MISMATCH (set it again instead); the record stays lapsed",
            RefusalCode(() => led.PrepareConfigRecord(repoB, ConfigKinds.Repository, ConfigKinds.Reconfirm, null, null, RepoCfg(repoB)!.ConfigRevision, ConfigFixture.Rid("rb2"))) == ErrorCodes.ConfigMismatch
            && RepoCfg(repoB)!.IsLapsed);
        return failed;
    });

    // ---- M8: rollback of config-records.json; same-boot durability; catastrophic loss ----

    private static int ConfigRollbackCases(string repos) => WithFreshStore("config-rollback", () =>
    {
        int failed = 0;
        var boot = new Boot(B1);
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        Fx fx = Protected(repos, "CfgRollback");
        byte[] before = File.ReadAllBytes(StorePaths.ConfigRecordsPath); // the acceptance in force
        ConfigFixture.RevokeGlobal(fx.Led, ConfigKinds.IsolationAcceptance, ConfigFixture.LastAcceptanceId);
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot); // a same-boot restart
        failed += Check("M8: a same-boot restart keeps every acknowledged commit (the revocation) and lapses nothing",
            Cfg().Acceptances.Single(x => x.AcceptanceId == ConfigFixture.LastAcceptanceId).RevokedAt is not null && !RepoCfg(fx.Repo)!.IsLapsed);
        // The file alone rolls back to the version before the revocation (power loss), then the machine boots again.
        File.WriteAllBytes(StorePaths.ConfigRecordsPath, before);
        boot.Value = B2;
        new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot);
        IsolationAcceptanceRecord restored = Cfg().Acceptances.Single(x => x.AcceptanceId == ConfigFixture.LastAcceptanceId);
        JsonObject s2 = ReviewBegin("rr1", reviewInput: Hex);
        s2["isolation"] = ConfigFixture.Isolation("S2");
        failed += Check("M8: the restored (revoked) acceptance is back but lapsed: a review resting on it is refused until the operator re-confirms",
            restored.RevokedAt is null && restored.LapsedAtRecoveryId is not null && RefusalCode(() => Do(fx, Engine, "op_begin", s2)) == ErrorCodes.ConfigLapsed);
        // Catastrophic loss: an unreadable file serves nothing; a missing one holds no records.
        File.WriteAllText(StorePaths.ConfigRecordsPath, "{ not json");
        var led = new GrantLedger("cust-selftest", new Table());
        failed += Check("M8: an unreadable config-records.json → starts, checks, reviews and the config section are refused (fail closed)",
            ThrowsWith(() => Do(led, Engine, fx.Repo, "run-cfg-lost", "open", OpenFields()), "unreadable")
            && ThrowsWith(() => Do(fx, Engine, "op_begin", ChecksBegin()), "unreadable")
            && ThrowsWith(() => Do(fx, Engine, "op_begin", s2), "unreadable")
            && ThrowsWith(() => led.ListUserRecords(fx.Repo, fx.Run, false, new HashSet<string> { "config" }), "unreadable"));
        boot.Value = B3;
        failed += Check("M8: recovery after a new boot with an unreadable file still completes (the file serves nothing)",
            Ok(() => new GrantLedger("cust-selftest", new Table()).StartupRecovery(boot)) && File.ReadAllText(StorePaths.ConfigRecordsPath) == "{ not json");
        File.Delete(StorePaths.ConfigRecordsPath);
        failed += Check("M8: a missing config-records.json holds no records → CONFIG_NOT_HELD",
            RefusalCode(() => Do(led, Engine, fx.Repo, "run-cfg-lost", "open", OpenFields())) == ErrorCodes.ConfigNotHeld);
        return failed;
    });

    // ---- M9: validation and caps ----

    private static int ConfigValidationCases(string repos) => WithFreshStore("config-validation", () =>
    {
        int failed = 0;
        var led = new GrantLedger("cust-selftest", new Table());
        string repo = CaseRepo(repos, "Validation");
        string? Prep(JsonObject payload) => RefusalCode(() => led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, payload, 0, ConfigFixture.Rid("v")));
        JsonObject With(Action<JsonObject> change) { JsonObject p = ConfigFixture.RepositoryPayload(null); change(p); return p; }
        JsonObject Def(Action<JsonObject> change) { JsonObject d = ConfigFixture.Definition("UNIT"); change(d); return d; }
        failed += Check("M9: closed kinds and actions", RefusalCode(() => led.PrepareConfigRecord(repo, "grant", ConfigKinds.Set, null, null, 0, ConfigFixture.Rid("k"))) == ErrorCodes.InvalidArgument
            && RefusalCode(() => led.PrepareConfigRecord(repo, ConfigKinds.Repository, "delete", null, null, 0, ConfigFixture.Rid("k"))) == ErrorCodes.InvalidArgument);
        failed += Check("M9: an unknown payload field → MALFORMED_REQUEST (never ignored)", Prep(With(p => p["recordedBy"] = "user")) == ErrorCodes.MalformedRequest);
        failed += Check("M9: an unknown definition field → MALFORMED_REQUEST", Prep(With(p => p["checks"]!["unit"] = Def(d => d["sandbox"] = false))) == ErrorCodes.MalformedRequest);
        failed += Check("M9: unsafe paths are refused: '..', '.git', absolute, wildcard, backslash",
            new[] { "../x", ".git/hooks", "C:/x", "a/*", "a\\b", "a/./b" }.All(cwd => Prep(With(p => p["checks"]!["unit"] = Def(d => d["cwd"] = cwd))) == ErrorCodes.InvalidArgument));
        failed += Check("M9: secret-shaped or Claude/Codex passthrough names and Claude env names are refused",
            new[] { "GITHUB_TOKEN", "ANTHROPIC_API_KEY", "CODEX_API_KEY", "MY_SECRET" }.All(n => Prep(With(p => p["checks"]!["unit"] = Def(d => d["env_passthrough"] = new JsonArray(n)))) == ErrorCodes.InvalidArgument)
            && Prep(With(p => p["checks"]!["unit"] = Def(d => d["env"] = new JsonObject { ["CLAUDE_X"] = "1" }))) == ErrorCodes.InvalidArgument);
        failed += Check("M9: a definition not in the engine's canonical form (unsorted passthrough names or freshness inputs) is refused, not re-normalized",
            Prep(With(p => p["checks"]!["unit"] = Def(d => d["env_passthrough"] = new JsonArray("ZED", "ALPHA")))) == ErrorCodes.InvalidArgument
            && Prep(With(p => p["checks"]!["unit"] = Def(d => d["freshness_inputs"] = new JsonArray("b.txt", "a.txt")))) == ErrorCodes.InvalidArgument);
        failed += Check("M9: a floor is required, and only one kind of it", Prep(With(p => { p["requiredProfiles"] = new JsonArray(); })) == ErrorCodes.InvalidArgument
            && Prep(With(p => p["noRequiredChecks"] = true)) == ErrorCodes.InvalidArgument);
        failed += Check("M9: a profile naming an undefined check, a required profile that is not defined → INVALID_ARGUMENT",
            Prep(With(p => p["profiles"] = new JsonObject { ["default"] = new JsonArray("nope") })) == ErrorCodes.InvalidArgument
            && Prep(With(p => p["requiredProfiles"] = new JsonArray("other"))) == ErrorCodes.InvalidArgument);
        failed += Check("M9: bounded strings — an argv entry over the text bound → INVALID_ARGUMENT",
            Prep(With(p => p["checks"]!["unit"] = Def(d => d["argv"] = new JsonArray("node", new string('x', 501))))) == ErrorCodes.InvalidArgument);
        var many = new JsonObject();
        for (int i = 0; i < 65; i++) many[$"c{i}"] = ConfigFixture.Definition($"C{i}");
        var argv = new JsonArray();
        for (int i = 0; i < 65; i++) argv.Add("a");
        failed += Check("M9: caps — 65 checks, 65 argv entries → BUDGET_EXHAUSTED with the limit named",
            Prep(With(p => { p["checks"] = many; p["profiles"] = new JsonObject { ["default"] = new JsonArray("c0") }; })) == ErrorCodes.BudgetExhausted
            && Prep(With(p => p["checks"]!["unit"] = Def(d => d["argv"] = argv))) == ErrorCodes.BudgetExhausted);
        failed += Check("M9: global records — a confirmation with s1Available false, an unknown reduction, a repository named on a global record → INVALID_ARGUMENT",
            RefusalCode(() => led.PrepareConfigRecord(null, ConfigKinds.SelftestConfirmation, ConfigKinds.Set, null, new JsonObject
            {
                ["selftestId"] = "st-x", ["codexVersion"] = "0.160.0", ["backend"] = "mxc", ["mode"] = "S1", ["profileDigest"] = Hex, ["s1Available"] = false,
                ["rowsSummary"] = new JsonObject { ["total"] = 1, ["passed"] = 0, ["failed"] = new JsonArray("read_canary") }, ["recordDigest"] = Hex,
            }, 0, ConfigFixture.Rid("g"))) == ErrorCodes.InvalidArgument
            && RefusalCode(() => led.PrepareConfigRecord(null, ConfigKinds.IsolationAcceptance, ConfigKinds.Set, null, new JsonObject
            {
                ["accepted"] = new JsonArray("unrestricted_writes"), ["backend"] = "mxc", ["codexVersionRange"] = "0.160.", ["statementSha256"] = Hex,
            }, 0, ConfigFixture.Rid("g"))) == ErrorCodes.InvalidArgument
            && RefusalCode(() => led.PrepareConfigRecord(repo, ConfigKinds.IsolationAcceptance, ConfigKinds.Revoke, "x", null, 0, ConfigFixture.Rid("g"))) == ErrorCodes.InvalidArgument);
        // Digests the custodian computes equal the engine's schemes on fixed inputs (the shared corpus holds the rest).
        failed += Check("M9: a canonical-JSON key order like JavaScript's — integer-like keys first, numerically",
            EngineJson.Canonical(new JsonObject { ["b"] = 1, ["10"] = 2, ["9"] = 3, ["a"] = 4, ["01"] = 5 }) == "{\"9\":3,\"10\":2,\"01\":5,\"a\":4,\"b\":1}"
            && EngineJson.Canonical(JsonValue.Create("\u2028<é>\"\\\n\u0001")) == "\"\u2028<é>\\\"\\\\\\n\\u0001\"");
        return failed;
    });

    // ---- M13: the Codex installation's forms ----

    private static int CodexFormCases(string repos) => WithFreshStore("config-codex", () =>
    {
        int failed = 0;
        string dir = Directory.CreateDirectory(Path.Combine(repos, "cfg", "codex-forms")).FullName;
        string Code(string path) => RefusalCode(() => CodexImage.Measure(path)) ?? "ok";
        string pe = ConfigFixture.WritePe(Path.Combine(dir, "native"));
        MeasuredImage m = CodexImage.Measure(pe);
        failed += Check("M13: a native PE image (.exe, MZ/PE) is accepted and measured by the custodian's own handle: size, SHA-256, file id",
            m is { Form: "native_pe", Size: 512 } && m.Sha256 == ConfigFixture.CodexSha256 && m.FileId.Contains('-'));
        // A native image inside an npm package directory qualifies when selected directly (TD clarification II).
        string npmExe = Path.Combine(Directory.CreateDirectory(Path.Combine(dir, "npm", "node_modules", "@openai", "codex", "vendor", "x86_64-pc-windows-msvc", "bin")).FullName, "codex.exe");
        File.WriteAllBytes(npmExe, ConfigFixture.PeBytes(3));
        failed += Check("M13 / TD II: a native codex.exe inside an npm package, selected directly → accepted", Code(npmExe) == "ok");
        foreach (string shim in new[] { "codex.cmd", "codex.ps1", "codex.js", "codex.bat", "codex.sh" })
        {
            string p = Path.Combine(dir, shim);
            File.WriteAllText(p, "@echo off\r\nnode codex.js %*\r\n");
            failed += Check($"M13: a launcher or script ({shim}) → CODEX_INSTALLATION_UNSUPPORTED", Code(p) == ErrorCodes.CodexInstallationUnsupported);
        }
        string pkg = Path.Combine(dir, "npm", "node_modules", "@openai", "codex", "bin", "codex.js");
        Directory.CreateDirectory(Path.GetDirectoryName(pkg)!);
        File.WriteAllText(pkg, "#!/usr/bin/env node\nrequire('../lib/codex');\n");
        failed += Check("M13: a Node-package installation (its interpreter entry script) → CODEX_INSTALLATION_UNSUPPORTED", Code(pkg) == ErrorCodes.CodexInstallationUnsupported);
        string notPe = Path.Combine(dir, "fake.exe");
        File.WriteAllText(notPe, "#!/bin/sh\necho not a PE\n");
        failed += Check("M13: a non-PE file named .exe → CODEX_INSTALLATION_UNSUPPORTED", Code(notPe) == ErrorCodes.CodexInstallationUnsupported);
        failed += Check("M13: a directory, or a path that does not exist → CODEX_INSTALLATION_UNSUPPORTED",
            Code(Directory.CreateDirectory(Path.Combine(dir, "dir.exe")).FullName) == ErrorCodes.CodexInstallationUnsupported && Code(Path.Combine(dir, "none.exe")) == ErrorCodes.CodexInstallationUnsupported);
        string hard = Path.Combine(dir, "hard.exe");
        if (Interop.Native.CreateHardLinkW(hard, pe, IntPtr.Zero))
            failed += Check("M13: a file with a second hard link → CODEX_INSTALLATION_UNSUPPORTED", Code(pe) == ErrorCodes.CodexInstallationUnsupported);
        else failed += Check("M13: hard link fixture created", false);
        // A path through a junction (a link in an intermediate component) is refused, not followed.
        string target = Directory.CreateDirectory(Path.Combine(dir, "real")).FullName;
        File.WriteAllBytes(Path.Combine(target, "codex.exe"), ConfigFixture.PeBytes(4));
        string junction = Path.Combine(dir, "linked");
        failed += Check("M13: a path through a junction → CODEX_INSTALLATION_UNSUPPORTED (the real path is accepted)",
            MakeJunction(junction, target) && Code(Path.Combine(junction, "codex.exe")) == ErrorCodes.CodexInstallationUnsupported && Code(Path.Combine(target, "codex.exe")) == "ok");
        // A file the measuring account cannot read: deny this account read access to it.
        string locked = Path.Combine(dir, "locked.exe");
        File.WriteAllBytes(locked, ConfigFixture.PeBytes(5));
        var fi = new FileInfo(locked);
        FileSecurity sec = fi.GetAccessControl();
        sec.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.ReadData, AccessControlType.Deny));
        fi.SetAccessControl(sec);
        failed += Check("M13: a file the custodian cannot read → CODEX_INSTALLATION_UNSUPPORTED", Code(locked) == ErrorCodes.CodexInstallationUnsupported);
        sec.RemoveAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.ReadData, AccessControlType.Deny));
        fi.SetAccessControl(sec);
        // The operator's set refuses an unsupported form before anything is prepared.
        var led = new GrantLedger("cust-selftest", new Table());
        string repo = CaseRepo(repos, "Forms");
        failed += Check("M13: set with an unsupported installation → CODEX_INSTALLATION_UNSUPPORTED; nothing prepared or recorded",
            RefusalCode(() => led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, ConfigFixture.RepositoryPayload(Path.Combine(dir, "codex.cmd")), 0, ConfigFixture.Rid("f"))) == ErrorCodes.CodexInstallationUnsupported
            && RepoCfg(repo) is null);
        // A commit re-measures: an image swapped between prepare and commit is stale.
        string rid = ConfigFixture.Rid("swap");
        led.PrepareConfigRecord(repo, ConfigKinds.Repository, ConfigKinds.Set, null, ConfigFixture.RepositoryPayload(Path.Combine(target, "codex.exe")), 0, rid);
        File.WriteAllBytes(Path.Combine(target, "codex.exe"), ConfigFixture.PeBytes(6));
        failed += Check("M13 / TD II: the image replaced between prepare and commit → STALE_CONFIG; nothing recorded",
            RefusalCode(() => led.Commit(rid, null)) == ErrorCodes.StaleConfig && RepoCfg(repo) is null);
        return failed;
    });

    /// <summary>Did <paramref name="a"/> throw an exception whose message contains <paramref name="text"/>?</summary>
    private static bool ThrowsWith(Action a, string text)
    {
        try { a(); return false; }
        catch (Exception e) when (e is not OutOfMemoryException) { return e.Message.Contains(text, StringComparison.Ordinal); }
    }

    /// <summary>Create a directory junction (mklink /J) at <paramref name="link"/> pointing at <paramref name="target"/>.</summary>
    private static bool MakeJunction(string link, string target)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.WaitForExit(10_000);
        return Directory.Exists(link);
    }
}
