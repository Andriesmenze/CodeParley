using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// P3.4C-4: the custodian-held trusted configuration (contract §2–§3). One store file, <c>config-records.json</c>, read and
/// written only under the ledger's single lock and replaced through the write-through path. It is written only by the
/// elevated operator, through the existing two-phase path: <c>prepare_config_record</c> (set, revoke, reconfirm) records a
/// time-boxed intent bound to the custodian's rendering and to the state of every record it affects; <c>commit</c>
/// re-derives that state in the same hold as its write and refuses any drift (STALE_CONFIG). Nothing on the implementer
/// surface creates, changes or revokes configuration: the implementer reads it (the <c>config</c> section) and the
/// custodian checks the engine's claims against it inside the existing run transitions (GrantLedger.Runs.cs).
/// </summary>
internal sealed partial class GrantLedger
{
    internal const string ConfigRecordAction = "config_record";

    // ---- the store ----

    /// <summary>The store file (callers hold <see cref="Gate"/>). A missing file holds no records; an unreadable one serves
    /// nothing — every configuration read, start, check and review is refused (fail closed; §2.4 catastrophic loss).</summary>
    internal static ConfigRecordsFile ReadConfigRecords()
    {
        if (!File.Exists(StorePaths.ConfigRecordsPath)) return ConfigRecordsFile.Empty();
        ConfigRecordsFile f;
        try
        {
            f = JsonSerializer.Deserialize<ConfigRecordsFile>(File.ReadAllText(StorePaths.ConfigRecordsPath), Json)
                ?? throw new JsonException("empty");
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or IOException)
        {
            throw new InvalidDataException("config-records.json is unreadable; no protected configuration is served until an administrator restores or re-imports it (fail closed)");
        }
        StoreFormat.RequireFileVersion("config-records.json", f.Version); // Phase 6 L-1
        return f;
    }

    private static void WriteConfigRecords(ConfigRecordsFile file) => AtomicWrite(StorePaths.ConfigRecordsPath, JsonSerializer.Serialize(file, Json));

    /// <summary>The store file, read in a hold of the lock (the self-tests).</summary>
    internal static ConfigRecordsFile ReadConfigRecordsLocked()
    {
        lock (EnterGate()) return ReadConfigRecords();
    }

    private static CustodianRefusal StaleConfig(string why) => new(ErrorCodes.StaleConfig, $"{why}; nothing was recorded — prepare it again against the current configuration");

    // ---- operator: prepare ----

    /// <summary>
    /// Prepare a configuration change (§3.1). The custodian validates the payload, computes every digest, measures the Codex
    /// installation through its own handle, renders the complete content the operator confirms, and binds the intent to
    /// the state of every record the commit would change (TD clarification I): the repository record's revision and
    /// state, and for a repository <c>reconfirm</c> each lapsed global record it clears. Nothing is recorded until
    /// <see cref="Commit"/>.
    /// </summary>
    internal PreparedAuthorization PrepareConfigRecord(string? repositoryRoot, string recordKind, string action, string? recordId, JsonObject? payload, int baseRevision, string requestId)
    {
        if (!ConfigKinds.Kinds.Contains(recordKind)) throw new ArgumentException("recordKind must be repository, isolation_acceptance, selftest_confirmation or engine_runtime");
        if (!ConfigKinds.Actions.Contains(action)) throw new ArgumentException("action must be set, revoke or reconfirm");
        if (action != ConfigKinds.Set && payload is not null) throw new ArgumentException("a revoke or reconfirm carries no payload");
        return recordKind == ConfigKinds.Repository
            ? PrepareRepositoryConfig(repositoryRoot ?? throw new ArgumentException("repositoryRoot is required for a repository record"), action, recordId, payload, baseRevision, requestId)
            : PrepareGlobalConfig(repositoryRoot, recordKind, action, recordId, payload, baseRevision, requestId);
    }

    private PreparedAuthorization PrepareRepositoryConfig(string repositoryRoot, string action, string? recordId, JsonObject? payload, int baseRevision, string requestId)
    {
        if (recordId is not null) throw new ArgumentException("a repository record is named by its repository, not by a recordId");
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        JsonObject? content = null;
        MeasuredImage? codex = null;
        if (action == ConfigKinds.Set)
        {
            RequireRepositoryReadable(id); // N5-8: the operator learns of a missing read grant when protecting the repository
            JsonObject p = ConfigValidation.RepositoryPayload(payload);
            if ((string?)p["codexPath"] is { } codexPath) codex = CodexImage.Measure(codexPath); // outside the lock: hashing takes time
            content = RepositoryContent(p, codex);
        }
        else if (action == ConfigKinds.Reconfirm)
        {
            // §3.1: the installation is re-measured now; a difference from the held one refuses the re-confirmation.
            string? held;
            lock (EnterGate()) held = ReadConfigRecords().CurrentOf(id.Key)?.CodexInstallation?.Path;
            if (held is not null) codex = CodexImage.Measure(held);
        }

        lock (EnterGate())
        {
            ConfigRecordsFile file = ReadConfigRecords();
            RepositoryConfig? cur = file.CurrentOf(id.Key);
            int current = cur?.ConfigRevision ?? 0;
            if (baseRevision != current) throw StaleConfig($"the repository's configuration changed since it was read (revision {current}, prepared against {baseRevision})");
            var args = new JsonObject
            {
                ["recordKind"] = ConfigKinds.Repository, ["action"] = action, ["repositoryRoot"] = id.CanonicalPath, ["repoKey"] = id.Key, ["baseRevision"] = baseRevision,
            };
            string rendering;
            switch (action)
            {
                case ConfigKinds.Set:
                    if (cur is not null && file.Repositories.Count(r => r.RepoKey == id.Key) >= ConfigCaps.RepositoryVersions)
                        throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"a repository keeps at most {ConfigCaps.RepositoryVersions} configuration versions");
                    args["content"] = content!.DeepClone();
                    rendering = RenderRepositorySet(id, content!, current);
                    break;
                case ConfigKinds.Revoke:
                    if (cur is null || cur.IsRevoked) throw new ArgumentException("the repository has no configuration record in force to revoke");
                    rendering = $"Revoke the protected configuration of repository:\n  {id.CanonicalPath}\n  identity {id.Key}\n  (revision {current} → {current + 1}; its protected runs can start, run checks and review only after a new configuration is set)";
                    break;
                default: // reconfirm
                    if (cur is null || cur.IsRevoked) throw new ArgumentException("the repository has no configuration record in force to re-confirm");
                    if (cur.CodexInstallation is { } heldInstall && !SameInstallation(heldInstall, codex!))
                        throw new CustodianRefusal(ErrorCodes.ConfigMismatch, $"the Codex installation measured now differs from the one held ({DescribeDifference(heldInstall, codex!)}); nothing was re-confirmed — set the configuration again to approve the installation as it is now");
                    List<JsonObject> globals = LapsedGlobals(file);
                    if (!cur.IsLapsed && globals.Count == 0) throw new ArgumentException("nothing is lapsed: the repository's configuration and the global records are in force");
                    args["affected"] = new JsonArray([RecordState(cur), .. globals.Select(g => (JsonNode)g)]);
                    rendering = RenderReconfirm(id, cur, file, globals);
                    break;
            }
            return PrepareIntent(ConfigRecordAction, args, ConfigStateDigest(file, args), requestId, rendering);
        }
    }

    private PreparedAuthorization PrepareGlobalConfig(string? repositoryRoot, string recordKind, string action, string? recordId, JsonObject? payload, int baseRevision, string requestId)
    {
        if (repositoryRoot is not null) throw new ArgumentException($"a {recordKind.Replace('_', ' ')} is global: it names no repository");
        bool runtime = recordKind == ConfigKinds.EngineRuntime;
        JsonObject? validated = action == ConfigKinds.Set
            ? recordKind switch
            {
                ConfigKinds.IsolationAcceptance => ConfigValidation.AcceptancePayload(payload),
                ConfigKinds.EngineRuntime => ConfigValidation.EngineRuntimePayload(payload),
                _ => ConfigValidation.SelftestPayload(payload),
            }
            : null;
        if (action == ConfigKinds.Set && recordId is not null) throw new ArgumentException("a new record's id is assigned by the custodian");
        if (action != ConfigKinds.Set && recordId is null) throw new ArgumentException("recordId names the record to revoke or re-confirm");
        if (recordId is not null) RunFields.RequireToken("recordId", recordId, 128);
        // Phase 5 (§4.12): on a host that binds a sandbox basis, the custodian measures it now, outside the lock.
        JsonObject? hostBasis = recordKind == ConfigKinds.SelftestConfirmation && action == ConfigKinds.Set && Platform.Isolation.Binds
            ? MeasureConfirmedBasis(validated!) : null;
        // P3.4C-5 (§2.1): the runtime is measured now, outside the lock (hashing the tree takes time): a set approves what
        // is measured; a re-confirmation must find the held tree unchanged.
        MeasuredRuntime? measured = null;
        if (runtime && action == ConfigKinds.Set) measured = Security.EngineRuntime.Measure((string)validated!["path"]!, (string?)validated["git"], (string?)validated["gitPath"]);
        else if (runtime && action == ConfigKinds.Reconfirm)
        {
            EngineRuntimeRecord? held;
            lock (EnterGate()) held = ReadConfigRecords().Runtimes.FirstOrDefault(r => r.RuntimeId == recordId);
            if (held is not null)
            {
                measured = Security.EngineRuntime.Measure(held.Root, held.GitRelative, held.GitPath);
                List<string> diff = Security.EngineRuntime.Differences(held.Measured, measured);
                if (diff.Count > 0) throw new CustodianRefusal(ErrorCodes.ConfigMismatch, $"the engine runtime measured now differs from the one approved ({string.Join(", ", diff)}); nothing was re-confirmed - approve the runtime again as it is now");
            }
        }
        lock (EnterGate())
        {
            ConfigRecordsFile file = ReadConfigRecords();
            if (baseRevision != file.GlobalRevision) throw StaleConfig($"the global configuration records changed since they were read (revision {file.GlobalRevision}, prepared against {baseRevision})");
            var args = new JsonObject { ["recordKind"] = recordKind, ["action"] = action, ["baseRevision"] = baseRevision };
            string rendering;
            if (action == ConfigKinds.Set)
            {
                if (recordKind == ConfigKinds.IsolationAcceptance && file.Acceptances.Count >= ConfigCaps.Acceptances)
                    throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"isolation acceptances: at most {ConfigCaps.Acceptances}");
                if (recordKind == ConfigKinds.SelftestConfirmation && file.SelftestConfirmations.Count >= ConfigCaps.SelftestConfirmations)
                    throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"self-test confirmations: at most {ConfigCaps.SelftestConfirmations}");
                if (runtime && file.Runtimes.Count >= ConfigCaps.EngineRuntimes)
                    throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"engine runtime approvals: at most {ConfigCaps.EngineRuntimes}");
                // An engine runtime's payload is what the custodian measured (M), never the operator's claim.
                args["payload"] = runtime ? Security.EngineRuntime.Content(measured!) : validated!.DeepClone();
                if (hostBasis is not null) args["hostBasis"] = hostBasis.DeepClone();
                rendering = recordKind switch
                {
                    ConfigKinds.IsolationAcceptance => RenderAcceptance(validated!),
                    ConfigKinds.EngineRuntime => Security.EngineRuntime.Render(measured!),
                    _ => RenderSelftest(validated!) + (hostBasis is null ? "" : RenderHostBasis(hostBasis)),
                };
            }
            else
            {
                JsonObject state = GlobalState(file, recordKind, recordId!) ?? throw new ArgumentException($"no {recordKind.Replace('_', ' ')} {recordId}");
                if (state["revoked"]!.GetValue<bool>() || state["superseded"]!.GetValue<bool>()) throw new ArgumentException($"{recordKind.Replace('_', ' ')} {recordId} is not in force");
                if (action == ConfigKinds.Reconfirm && state["lapsedAtRecoveryId"] is null) throw new ArgumentException($"{recordKind.Replace('_', ' ')} {recordId} is not lapsed");
                if (action == ConfigKinds.Reconfirm && file.SelftestConfirmations.FirstOrDefault(c => c.ConfirmationId == recordId) is { HostBasis: not null })
                    throw BootBoundLapsed();
                args["recordId"] = recordId;
                args["affected"] = new JsonArray(state);
                rendering = $"{(action == ConfigKinds.Revoke ? "Revoke" : "Re-confirm after a restart of the OS")} {recordKind.Replace('_', ' ')} {recordId}:\n{RenderGlobal(file, recordKind, recordId!)}";
            }
            return PrepareIntent(ConfigRecordAction, args, ConfigStateDigest(file, args), requestId, rendering);
        }
    }

    // ---- the state a prepared change is bound to (re-derived by the commit in the same hold as its write) ----

    /// <summary>
    /// The "state shown" of a configuration change: the repository record's revision, digest and state for a repository
    /// set or revoke; every affected record's id, revision and state for a re-confirmation (the repository record and
    /// each lapsed global record it clears) or a global revoke; the global revision for a new global record. Any changed
    /// member makes the prepared authorization stale — no partial commit (TD clarification I).
    /// </summary>
    private static string ConfigStateDigest(ConfigRecordsFile file, JsonObject args)
    {
        string kind = (string)args["recordKind"]!;
        string action = (string)args["action"]!;
        var state = new JsonObject { ["recordKind"] = kind, ["action"] = action };
        if (kind == ConfigKinds.Repository && action != ConfigKinds.Reconfirm)
        {
            RepositoryConfig? cur = file.CurrentOf((string)args["repoKey"]!);
            state["repository"] = cur is null ? null : RecordState(cur);
        }
        else if (action == ConfigKinds.Set) state["globalRevision"] = file.GlobalRevision;
        else
        {
            var now = new JsonArray();
            foreach (JsonObject a in args["affected"]!.AsArray().Cast<JsonObject>())
            {
                string k = (string)a["kind"]!;
                now.Add(k == ConfigKinds.Repository
                    ? file.CurrentOf((string)a["id"]!) is { } r ? RecordState(r) : new JsonObject { ["kind"] = k, ["id"] = (string?)a["id"], ["missing"] = true }
                    : GlobalState(file, k, (string)a["id"]!) ?? new JsonObject { ["kind"] = k, ["id"] = (string?)a["id"], ["missing"] = true });
            }
            state["affected"] = now;
        }
        return Digest.Sha256Hex(Digest.Canonical(state));
    }

    private static JsonObject RecordState(RepositoryConfig r) => new()
    {
        ["kind"] = ConfigKinds.Repository, ["id"] = r.RepoKey, ["revision"] = r.ConfigRevision, ["configDigest"] = r.ConfigDigest,
        ["revoked"] = r.IsRevoked, ["superseded"] = !r.IsCurrent, ["lapsedAtRecoveryId"] = r.LapsedAtRecoveryId,
    };

    private static JsonObject? GlobalState(ConfigRecordsFile file, string kind, string id)
    {
        if (kind == ConfigKinds.EngineRuntime)
            return file.Runtimes.FirstOrDefault(r => r.RuntimeId == id) is { } rt
                ? new JsonObject { ["kind"] = kind, ["id"] = id, ["revision"] = rt.GlobalRevision, ["revoked"] = rt.RevokedAt is not null, ["superseded"] = rt.SupersededAt is not null, ["lapsedAtRecoveryId"] = rt.LapsedAtRecoveryId, ["treeDigest"] = (string?)rt.Measured["treeDigest"] }
                : null;
        if (kind == ConfigKinds.IsolationAcceptance)
            return file.Acceptances.FirstOrDefault(a => a.AcceptanceId == id) is { } a
                ? new JsonObject { ["kind"] = kind, ["id"] = id, ["revision"] = a.GlobalRevision, ["revoked"] = a.RevokedAt is not null, ["superseded"] = false, ["lapsedAtRecoveryId"] = a.LapsedAtRecoveryId }
                : null;
        return file.SelftestConfirmations.FirstOrDefault(c => c.ConfirmationId == id) is { } c
            ? new JsonObject { ["kind"] = kind, ["id"] = id, ["revision"] = c.GlobalRevision, ["revoked"] = c.RevokedAt is not null, ["superseded"] = c.SupersededAt is not null, ["lapsedAtRecoveryId"] = c.LapsedAtRecoveryId }
            : null;
    }

    /// <summary>Every lapsed global record in force — the records a repository's protected reviews may rest on, which its
    /// re-confirmation clears together (§2.4 usability rules).</summary>
    private static List<JsonObject> LapsedGlobals(ConfigRecordsFile file)
        => [
            .. file.Acceptances.Where(a => a.RevokedAt is null && a.LapsedAtRecoveryId is not null).Select(a => GlobalState(file, ConfigKinds.IsolationAcceptance, a.AcceptanceId)!),
            .. file.SelftestConfirmations.Where(c => c.RevokedAt is null && c.SupersededAt is null && c.LapsedAtRecoveryId is not null && c.HostBasis is null).Select(c => GlobalState(file, ConfigKinds.SelftestConfirmation, c.ConfirmationId)!),
            .. file.Runtimes.Where(r => r.RevokedAt is null && r.SupersededAt is null && r.LapsedAtRecoveryId is not null).Select(r => GlobalState(file, ConfigKinds.EngineRuntime, r.RuntimeId)!),
        ];

    /// <summary>Was this request id committed as a configuration change? (Its intent is gone; a second prepare under it is
    /// REQUEST_ID_CONFLICT, so a retried operator command records nothing twice.)</summary>
    private static bool ConfigRequestCommitted(string requestId)
    {
        if (!File.Exists(StorePaths.ConfigRecordsPath)) return false;
        ConfigRecordsFile f = ReadConfigRecords();
        return f.Repositories.Any(r => r.RequestId == requestId) || f.Acceptances.Any(a => a.RequestId == requestId) || f.SelftestConfirmations.Any(c => c.RequestId == requestId)
            || f.Runtimes.Any(r => r.RequestId == requestId);
    }

    // ---- operator: commit (called by Commit in its hold, after the state digest, the authorization digest and the
    //      repository's identity were re-checked) ----

    private JsonObject ApplyConfigRecord(JsonObject args, string requestId, string digest, string? proof)
    {
        ConfigRecordsFile file = ReadConfigRecords();
        string kind = (string)args["recordKind"]!;
        string action = (string)args["action"]!;
        string now = NowIso();
        var by = new RecordedBy("user", "custodian_operator", Platform.OperatorAssurance, proof ?? digest, requestId);
        JsonObject result = new() { ["recordKind"] = kind, ["action"] = action };

        if (kind == ConfigKinds.Repository)
        {
            string repoKey = (string)args["repoKey"]!;
            RepositoryConfig? cur = file.CurrentOf(repoKey);
            int next = (cur?.ConfigRevision ?? 0) + 1;
            RepositoryConfig version;
            if (action == ConfigKinds.Set)
            {
                var content = (JsonObject)args["content"]!;
                // A Codex installation is committed only as the custodian measures it now (TD clarification II: never one
                // image measured and another approved).
                if (content["codexInstallation"] is JsonObject bound && !SameInstallation(InstallationOf(bound)!, CodexImage.Measure((string)bound["path"]!)))
                    throw StaleConfig("the Codex installation changed since this was prepared");
                version = FromContent(repoKey, (string)args["repositoryRoot"]!, next, now, by, requestId, content);
            }
            else if (action == ConfigKinds.Revoke) version = cur! with { ConfigRevision = next, RecordedAt = now, RecordedBy = by, RequestId = requestId, Action = action, RevokedAt = now };
            else
            {
                if (cur!.CodexInstallation is { } held && !SameInstallation(held, CodexImage.Measure(held.Path)))
                    throw StaleConfig("the Codex installation changed since this was prepared");
                version = cur.IsLapsed ? cur with { ConfigRevision = next, RecordedAt = now, RecordedBy = by, RequestId = requestId, Action = action, LapsedAtRecoveryId = null } : cur;
            }
            if (!ReferenceEquals(version, cur))
            {
                if (cur is not null) file.Repositories[file.Repositories.IndexOf(cur)] = cur with { SupersededAt = now };
                file.Repositories.Add(version);
            }
            result["repoKey"] = repoKey;
            result["configRevision"] = version.ConfigRevision;
            result["configDigest"] = version.ConfigDigest;
            if (action == ConfigKinds.Reconfirm)
            {
                int g = file.GlobalRevision + 1;
                int cleared = 0;
                foreach (JsonObject a in args["affected"]!.AsArray().Cast<JsonObject>().Where(a => (string?)a["kind"] != ConfigKinds.Repository))
                {
                    ClearGlobalLapse(file, (string)a["kind"]!, (string)a["id"]!, g);
                    cleared++;
                }
                if (cleared > 0) file = file with { GlobalRevision = g };
                result["globalsReconfirmed"] = cleared;
                result["globalRevision"] = file.GlobalRevision;
            }
        }
        else
        {
            int g = file.GlobalRevision + 1;
            if (action == ConfigKinds.Set)
            {
                var p = (JsonObject)args["payload"]!;
                string id = Guid.NewGuid().ToString();
                if (kind == ConfigKinds.EngineRuntime)
                {
                    // Committed only as the custodian measures it now (never one tree measured and another approved).
                    MeasuredRuntime measuredNow = Security.EngineRuntime.Measure((string)p["root"]!, (string?)p["gitRelative"], (string?)p["gitPath"]);
                    if (Security.EngineRuntime.Differences(p, measuredNow).Count > 0) throw StaleConfig("the engine runtime changed since this was prepared");
                    List<EngineRuntimeRecord> runtimes = file.Runtimes;
                    for (int i = 0; i < runtimes.Count; i++)
                        if (runtimes[i].SupersededAt is null) runtimes[i] = runtimes[i] with { SupersededAt = now, GlobalRevision = g };
                    runtimes.Add(new EngineRuntimeRecord(id, g, now, by, requestId, (JsonObject)p.DeepClone()));
                    file = file with { EngineRuntimes = runtimes };
                }
                else if (kind == ConfigKinds.IsolationAcceptance)
                {
                    file.Acceptances.Add(new IsolationAcceptanceRecord(id, g, now, by, requestId,
                        [.. p["accepted"]!.AsArray().Select(x => (string)x!).Order(StringComparer.Ordinal)], (string)p["backend"]!, (string)p["codexVersionRange"]!, (string)p["statementSha256"]!));
                }
                else
                {
                    // Phase 5 (§4.12): a host basis is committed only as the custodian measures it now.
                    JsonObject? basis = args["hostBasis"] as JsonObject;
                    if (basis is not null && BasisDifferences(basis, Platform.Isolation.Measure((string)basis["codexPath"]!)) is { Count: > 0 } changed)
                        throw StaleConfig($"the Codex sandbox basis changed since this was prepared ({string.Join(", ", changed)})");
                    var c = new SelfTestConfirmationRecord(id, g, now, by, requestId, (string)p["selftestId"]!, (string)p["codexVersion"]!, (string)p["backend"]!,
                        (string)p["mode"]!, (string)p["profileDigest"]!, (bool)p["s1Available"]!, (JsonObject)p["rowsSummary"]!.DeepClone(), (string)p["recordDigest"]!)
                    { CodexSha256 = (string?)p["codexSha256"], HostBasis = (JsonObject?)basis?.DeepClone() };
                    // A newer confirmation of the same profile, version and backend supersedes the earlier ones.
                    for (int i = 0; i < file.SelftestConfirmations.Count; i++)
                    {
                        SelfTestConfirmationRecord o = file.SelftestConfirmations[i];
                        if (o.SupersededAt is null && o.RevokedAt is null && o.Backend == c.Backend && o.Mode == c.Mode && o.CodexVersion == c.CodexVersion && o.ProfileDigest == c.ProfileDigest)
                            file.SelftestConfirmations[i] = o with { SupersededAt = now, GlobalRevision = g };
                    }
                    file.SelftestConfirmations.Add(c);
                }
                result["recordId"] = id;
            }
            else
            {
                string id = (string)args["recordId"]!;
                if (action == ConfigKinds.Revoke)
                {
                    if (kind == ConfigKinds.EngineRuntime)
                    {
                        List<EngineRuntimeRecord> runtimes = file.Runtimes;
                        int i = runtimes.FindIndex(r => r.RuntimeId == id);
                        runtimes[i] = runtimes[i] with { RevokedAt = now, GlobalRevision = g };
                        file = file with { EngineRuntimes = runtimes };
                    }
                    else if (kind == ConfigKinds.IsolationAcceptance)
                    {
                        int i = file.Acceptances.FindIndex(a => a.AcceptanceId == id);
                        file.Acceptances[i] = file.Acceptances[i] with { RevokedAt = now, GlobalRevision = g };
                    }
                    else
                    {
                        int i = file.SelftestConfirmations.FindIndex(c => c.ConfirmationId == id);
                        file.SelftestConfirmations[i] = file.SelftestConfirmations[i] with { RevokedAt = now, GlobalRevision = g };
                    }
                }
                else ClearGlobalLapse(file, kind, id, g);
                result["recordId"] = id;
            }
            file = file with { GlobalRevision = g };
            result["globalRevision"] = g;
        }
        WriteConfigRecords(file);
        Audit($"config_record committed kind={kind} action={action} {(result["repoKey"] is { } rk ? $"repoKey={(string)rk!} configRevision={(int)result["configRevision"]!}" : $"recordId={(string?)result["recordId"]}")} globalRevision={file.GlobalRevision} requestId={requestId} assurance={Platform.OperatorAssurance}");
        return result;
    }

    private static void ClearGlobalLapse(ConfigRecordsFile file, string kind, string id, int globalRevision)
    {
        if (kind == ConfigKinds.EngineRuntime)
        {
            // A re-confirmation clears the lapse only for the tree as approved: it is measured again here.
            List<EngineRuntimeRecord> runtimes = file.EngineRuntimes!;
            int i = runtimes.FindIndex(r => r.RuntimeId == id);
            MeasuredRuntime now = Security.EngineRuntime.Measure(runtimes[i].Root, runtimes[i].GitRelative, runtimes[i].GitPath);
            if (Security.EngineRuntime.Differences(runtimes[i].Measured, now).Count > 0) throw StaleConfig("the engine runtime changed since this was prepared");
            runtimes[i] = runtimes[i] with { LapsedAtRecoveryId = null, GlobalRevision = globalRevision };
            return;
        }
        if (kind == ConfigKinds.IsolationAcceptance)
        {
            int i = file.Acceptances.FindIndex(a => a.AcceptanceId == id);
            file.Acceptances[i] = file.Acceptances[i] with { LapsedAtRecoveryId = null, GlobalRevision = globalRevision };
        }
        else
        {
            int i = file.SelftestConfirmations.FindIndex(c => c.ConfirmationId == id);
            file.SelftestConfirmations[i] = file.SelftestConfirmations[i] with { LapsedAtRecoveryId = null, GlobalRevision = globalRevision };
        }
    }

    // ---- the record's content (P and C fields), its digests and the measured installation (M) ----

    /// <summary>The canonical content of a repository record: every P field, the custodian-computed digests (C) and the
    /// measured installation (M); its <c>configDigest</c> binds all of it.</summary>
    internal static JsonObject RepositoryContent(JsonObject p, MeasuredImage? codex)
    {
        var checks = new JsonObject();
        foreach ((string name, JsonNode? def) in p["checks"]!.AsObject())
            checks[name] = new JsonObject { ["definition"] = def!.DeepClone(), ["definitionDigest"] = ConfigValidation.DefinitionDigest(name, (JsonObject)def) };
        var rules = (JsonObject)p["captureRules"]!;
        var content = new JsonObject
        {
            ["rootCommit"] = (string?)p["rootCommit"],
            ["checks"] = checks,
            ["profiles"] = p["profiles"]!.DeepClone(),
            ["requiredProfiles"] = p["requiredProfiles"]!.DeepClone(),
            ["noRequiredChecks"] = (bool)p["noRequiredChecks"]!,
            ["testGlobs"] = p["testGlobs"]!.DeepClone(),
            ["captureRules"] = rules.DeepClone(),
            ["captureRulesDigest"] = ConfigValidation.CaptureRulesDigest(rules),
            ["codexInstallation"] = codex is null ? null : new JsonObject { ["path"] = codex.Path, ["form"] = codex.Form, ["fileId"] = codex.FileId, ["size"] = codex.Size, ["sha256"] = codex.Sha256 },
        };
        content["configDigest"] = ConfigDigestOf(content);
        return content;
    }

    /// <summary><c>arl.repository-config.v1</c> over the content without its own digest.</summary>
    private static string ConfigDigestOf(JsonObject content)
    {
        var c = (JsonObject)content.DeepClone();
        c.Remove("configDigest");
        c["schema"] = ConfigKinds.RepositoryConfigSchema;
        return ConfigValidation.ConfigDigest(c);
    }

    private static RepositoryConfig FromContent(string repoKey, string root, int revision, string now, RecordedBy by, string requestId, JsonObject c)
    {
        var checks = new Dictionary<string, ConfigCheck>(StringComparer.Ordinal);
        foreach ((string name, JsonNode? v) in c["checks"]!.AsObject())
            checks[name] = new ConfigCheck((JsonObject)v!["definition"]!.DeepClone(), (string)v["definitionDigest"]!);
        var profiles = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach ((string name, JsonNode? list) in c["profiles"]!.AsObject()) profiles[name] = [.. list!.AsArray().Select(x => (string)x!)];
        var r = (JsonObject)c["captureRules"]!;
        var rules = new ConfigCaptureRules([.. r["excludeGlobs"]!.AsArray().Select(x => (string)x!)], [.. r["contextInclude"]!.AsArray().Select(x => (string)x!)],
            RunFields.Integer(r["maxFileBytes"])!.Value, RunFields.Integer(r["maxExportBytes"])!.Value, RunFields.Integer(r["maxDiffBytes"])!.Value);
        return new RepositoryConfig(repoKey, root, revision, now, by, requestId, ConfigKinds.Set, (string?)c["rootCommit"], checks, profiles,
            [.. c["requiredProfiles"]!.AsArray().Select(x => (string)x!)], (bool)c["noRequiredChecks"]!, [.. c["testGlobs"]!.AsArray().Select(x => (string)x!)],
            rules, (string)c["captureRulesDigest"]!, c["codexInstallation"] is JsonObject i ? InstallationOf(i) : null, (string)c["configDigest"]!);
    }

    private static CodexInstallation? InstallationOf(JsonObject? i)
        => i is null ? null : new CodexInstallation((string)i["path"]!, (string)i["form"]!, (string)i["fileId"]!, RunFields.Integer(i["size"])!.Value, (string)i["sha256"]!);

    private static bool SameInstallation(CodexInstallation held, MeasuredImage now)
        => held.Form == now.Form && held.FileId == now.FileId && held.Size == now.Size && held.Sha256 == now.Sha256
           && string.Equals(held.Path, now.Path, StringComparison.OrdinalIgnoreCase);

    private static string DescribeDifference(CodexInstallation held, MeasuredImage now)
    {
        var parts = new List<string>();
        if (held.Sha256 != now.Sha256) parts.Add($"SHA-256 {held.Sha256[..12]}… held, {now.Sha256[..12]}… now");
        if (held.Size != now.Size) parts.Add($"size {held.Size} held, {now.Size} now");
        if (held.FileId != now.FileId) parts.Add("another file at the path");
        return parts.Count == 0 ? "path spelling" : string.Join("; ", parts);
    }

    /// <summary>The content of the held record as the canonical object its digest was computed over.</summary>
    private static JsonObject ContentOf(RepositoryConfig r)
    {
        var checks = new JsonObject();
        foreach ((string name, ConfigCheck c) in r.Checks) checks[name] = new JsonObject { ["definition"] = c.Definition.DeepClone(), ["definitionDigest"] = c.DefinitionDigest };
        var profiles = new JsonObject();
        foreach ((string name, List<string> list) in r.Profiles) profiles[name] = new JsonArray([.. list.Select(x => (JsonNode)x)]);
        return new JsonObject
        {
            ["rootCommit"] = r.RootCommit,
            ["checks"] = checks,
            ["profiles"] = profiles,
            ["requiredProfiles"] = new JsonArray([.. r.RequiredProfiles.Select(x => (JsonNode)x)]),
            ["noRequiredChecks"] = r.NoRequiredChecks,
            ["testGlobs"] = new JsonArray([.. r.TestGlobs.Select(x => (JsonNode)x)]),
            ["captureRules"] = new JsonObject
            {
                ["excludeGlobs"] = new JsonArray([.. r.CaptureRules.ExcludeGlobs.Select(x => (JsonNode)x)]),
                ["contextInclude"] = new JsonArray([.. r.CaptureRules.ContextInclude.Select(x => (JsonNode)x)]),
                ["maxFileBytes"] = r.CaptureRules.MaxFileBytes, ["maxExportBytes"] = r.CaptureRules.MaxExportBytes, ["maxDiffBytes"] = r.CaptureRules.MaxDiffBytes,
            },
            ["captureRulesDigest"] = r.CaptureRulesDigest,
            ["codexInstallation"] = r.CodexInstallation is { } i ? new JsonObject { ["path"] = i.Path, ["form"] = i.Form, ["fileId"] = i.FileId, ["size"] = i.Size, ["sha256"] = i.Sha256 } : null,
            ["configDigest"] = r.ConfigDigest,
        };
    }

    // ---- renderings: the complete content the operator confirms (§3.1) ----

    private static string RenderRepositorySet(RepoIdentity id, JsonObject content, int current)
    {
        var sb = new StringBuilder();
        sb.Append($"Set the protected configuration of repository:\n  {id.CanonicalPath}\n  identity {id.Key} ({id.FileSystem})\n  (revision {current} → {current + 1}; operator-authoritative on protected runs; attended runs keep the local files)\n");
        AppendContent(sb, content);
        return sb.ToString().TrimEnd('\n');
    }

    private static void AppendContent(StringBuilder sb, JsonObject c)
    {
        sb.Append($"root commit: {(string?)c["rootCommit"] ?? "(none recorded)"}\n");
        JsonObject checks = c["checks"]!.AsObject();
        sb.Append($"checks ({checks.Count}):\n");
        foreach ((string name, JsonNode? v) in checks.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            JsonObject d = v!["definition"]!.AsObject();
            sb.Append($"  {name}  (definition {(string)v["definitionDigest"]!})\n");
            sb.Append($"    argv: {d["argv"]!.ToJsonString()}\n    cwd: {(string)d["cwd"]!}  timeout: {RunFields.Integer(d["timeout_seconds"])} s\n");
            JsonObject env = d["env"]!.AsObject();
            sb.Append(env.Count == 0 ? "    env: (none)\n" : $"    env: {string.Join(", ", env.Select(kv => $"{kv.Key}={(string)kv.Value!}"))}\n");
            JsonArray pass = d["env_passthrough"]!.AsArray();
            sb.Append($"    passthrough names (values come from the environment at run time and are never stored): {(pass.Count == 0 ? "(none)" : string.Join(", ", pass.Select(x => (string)x!)))}\n");
            JsonArray fresh = d["freshness_inputs"]!.AsArray();
            sb.Append($"    freshness inputs: {(fresh.Count == 0 ? "(none)" : string.Join(", ", fresh.Select(x => (string)x!)))}\n");
        }
        JsonObject profiles = c["profiles"]!.AsObject();
        sb.Append($"profiles: {(profiles.Count == 0 ? "(none)" : string.Join("; ", profiles.Select(kv => $"{kv.Key} = {string.Join(", ", kv.Value!.AsArray().Select(x => (string)x!))}")))}\n");
        bool none = (bool)c["noRequiredChecks"]!;
        JsonArray required = c["requiredProfiles"]!.AsArray();
        sb.Append($"verification floor: {(none ? "no required checks" : $"required profiles {string.Join(", ", required.Select(x => (string)x!))}")}\n");
        JsonArray tests = c["testGlobs"]!.AsArray();
        sb.Append($"test globs: {(tests.Count == 0 ? "(none)" : string.Join(", ", tests.Select(x => (string)x!)))}\n");
        JsonObject r = c["captureRules"]!.AsObject();
        sb.Append($"capture rules (digest {(string)c["captureRulesDigest"]!}):\n");
        sb.Append($"  exclude: {string.Join(", ", r["excludeGlobs"]!.AsArray().Select(x => (string)x!))}\n");
        JsonArray ctx = r["contextInclude"]!.AsArray();
        sb.Append($"  context include: {(ctx.Count == 0 ? "(none)" : string.Join(", ", ctx.Select(x => (string)x!)))}\n");
        sb.Append($"  limits: file {RunFields.Integer(r["maxFileBytes"])} bytes, export {RunFields.Integer(r["maxExportBytes"])} bytes, diff {RunFields.Integer(r["maxDiffBytes"])} bytes\n");
        sb.Append(c["codexInstallation"] is JsonObject i
            ? $"Codex installation (measured by the custodian now): {(string)i["path"]!}\n  {CodexImage.KindOf((string?)i["form"])} image, {RunFields.Integer(i["size"])} bytes, SHA-256 {(string)i["sha256"]!}, file id {(string)i["fileId"]!}\n"
            : "Codex installation: none (protected reviews are refused until one is set)\n");
        sb.Append($"configuration digest: {(string?)c["configDigest"]}\n");
    }

    private static string RenderReconfirm(RepoIdentity id, RepositoryConfig cur, ConfigRecordsFile file, List<JsonObject> globals)
    {
        var sb = new StringBuilder();
        sb.Append($"Re-confirm the protected configuration of repository:\n  {id.CanonicalPath}\n  identity {id.Key} ({id.FileSystem})\n");
        sb.Append($"The custodian recovered after a restart of the OS; this is the configuration AS IT SURVIVED — check that it is what you expect (a restored older version is shown as it is):\n");
        sb.Append($"  revision {cur.ConfigRevision} ({cur.Action}), recorded {cur.RecordedAt}{(cur.IsLapsed ? $", lapsed by recovery {cur.LapsedAtRecoveryId}" : ", in force")}\n");
        AppendContent(sb, ContentOf(cur));
        if (cur.CodexInstallation is not null) sb.Append("The Codex installation was measured again now and is unchanged.\n");
        sb.Append(globals.Count == 0 ? "Lapsed global records: none.\n" : $"Lapsed global records this re-confirmation also restores ({globals.Count}):\n");
        foreach (JsonObject g in globals) sb.Append(RenderGlobal(file, (string)g["kind"]!, (string)g["id"]!)).Append('\n');
        return sb.ToString().TrimEnd('\n');
    }

    private static string RenderAcceptance(JsonObject p)
        => $"Accept reduced Codex isolation (S2) for protected reviews:\n  backend {(string)p["backend"]!}, Codex {(string)p["codexVersionRange"]!}x\n  accepted reductions: {string.Join(", ", p["accepted"]!.AsArray().Select(x => (string)x!))}\n  statement SHA-256 {(string)p["statementSha256"]!}\n  (S1 is still used whenever a confirmed self-test passes; this applies only when it does not)";

    private static string RenderSelftest(JsonObject p)
    {
        JsonObject rows = p["rowsSummary"]!.AsObject();
        JsonArray failed = rows["failed"]!.AsArray();
        if ((string?)p["mode"] == "FIX")
            return $"Confirm the FIX self-test record for delegated fixes (separate from the S1 review confirmation):\n  self-test {(string)p["selftestId"]!}: Codex {(string)p["codexVersion"]!}, backend {(string)p["backend"]!}, mode FIX\n  Codex binary SHA-256 {(string)p["codexSha256"]!}\n  fixer profile digest {(string)p["profileDigest"]!}\n  rows: {RunFields.Integer(rows["passed"])} of {RunFields.Integer(rows["total"])} passed{(failed.Count == 0 ? "" : $"; failed: {string.Join(", ", failed.Select(x => (string)x!))}")}; confinement established: {((bool)p["s1Available"]! ? "yes" : "no")}\n  record digest {(string)p["recordDigest"]!}\n  (the custodian does not re-run the self-test: you confirm this record as your engine produced it; it authorizes no review and applies no patch)";
        return $"Confirm the S1 self-test record for protected reviews:\n  self-test {(string)p["selftestId"]!}: Codex {(string)p["codexVersion"]!}, backend {(string)p["backend"]!}, mode {(string)p["mode"]!}\n  profile digest {(string)p["profileDigest"]!}\n  rows: {RunFields.Integer(rows["passed"])} of {RunFields.Integer(rows["total"])} passed{(failed.Count == 0 ? "" : $"; failed: {string.Join(", ", failed.Select(x => (string)x!))}")}; S1 available: {((bool)p["s1Available"]! ? "yes" : "no")}\n  record digest {(string)p["recordDigest"]!}\n  (the custodian does not re-run the self-test: you confirm this record as your engine produced it)";
    }

    private static string RenderGlobal(ConfigRecordsFile file, string kind, string id)
    {
        if (kind == ConfigKinds.IsolationAcceptance && file.Acceptances.FirstOrDefault(a => a.AcceptanceId == id) is { } a)
            return $"  isolation acceptance {a.AcceptanceId}: backend {a.Backend}, Codex {a.CodexVersionRange}x, {string.Join(", ", a.Accepted)}; recorded {a.RecordedAt}{(a.LapsedAtRecoveryId is null ? "" : $"; lapsed by recovery {a.LapsedAtRecoveryId}")}";
        if (file.SelftestConfirmations.FirstOrDefault(c => c.ConfirmationId == id) is { } c)
            return $"  self-test confirmation {c.ConfirmationId}: self-test {c.SelftestId}, Codex {c.CodexVersion}, backend {c.Backend}, record digest {c.RecordDigest}; recorded {c.RecordedAt}{(c.LapsedAtRecoveryId is null ? "" : $"; lapsed by recovery {c.LapsedAtRecoveryId}")}";
        return $"  {kind} {id}: not held";
    }

    // ---- the config section of list_user_records (§3.3) ----

    /// <summary>The repository's current record and the global records, each with its revision and lapse state. The
    /// implementer projection carries the content without the operator's identity facts (D-C′). Callers hold
    /// <see cref="Gate"/>.</summary>
    private static JsonObject ConfigSection(string repoKey, bool operatorView)
    {
        ConfigRecordsFile file = ReadConfigRecords();
        RepositoryConfig? cur = file.CurrentOf(repoKey);
        JsonObject? repository = null;
        if (cur is not null)
        {
            repository = ContentOf(cur);
            repository["configRevision"] = cur.ConfigRevision;
            repository["recordedAt"] = cur.RecordedAt;
            repository["action"] = cur.Action;
            repository["revoked"] = cur.IsRevoked;
            repository["lapsed"] = cur.IsLapsed;
            repository["lapsedAtRecoveryId"] = cur.LapsedAtRecoveryId;
            repository["usable"] = cur.IsUsable;
            if (operatorView)
            {
                repository["repositoryRoot"] = cur.RepositoryRoot;
                repository["recordedBy"] = RecordedByJson(cur.RecordedBy);
                repository["revokedAt"] = cur.RevokedAt;
            }
        }
        var acceptances = new JsonArray();
        foreach (IsolationAcceptanceRecord a in file.Acceptances)
        {
            var o = new JsonObject
            {
                ["acceptanceId"] = a.AcceptanceId, ["globalRevision"] = a.GlobalRevision, ["recordedAt"] = a.RecordedAt,
                ["accepted"] = new JsonArray([.. a.Accepted.Select(x => (JsonNode)x)]), ["backend"] = a.Backend, ["codexVersionRange"] = a.CodexVersionRange,
                ["statementSha256"] = a.StatementSha256, ["revoked"] = a.RevokedAt is not null, ["lapsed"] = a.LapsedAtRecoveryId is not null,
                ["lapsedAtRecoveryId"] = a.LapsedAtRecoveryId, ["usable"] = a.IsUsable,
            };
            if (operatorView) { o["recordedBy"] = RecordedByJson(a.RecordedBy); o["revokedAt"] = a.RevokedAt; }
            acceptances.Add(o);
        }
        var confirmations = new JsonArray();
        foreach (SelfTestConfirmationRecord c in file.SelftestConfirmations.Where(c => c.SupersededAt is null))
        {
            var o = new JsonObject
            {
                ["confirmationId"] = c.ConfirmationId, ["globalRevision"] = c.GlobalRevision, ["recordedAt"] = c.RecordedAt,
                ["selftestId"] = c.SelftestId, ["codexVersion"] = c.CodexVersion, ["backend"] = c.Backend, ["mode"] = c.Mode, ["profileDigest"] = c.ProfileDigest,
                ["s1Available"] = c.S1Available, ["rowsSummary"] = c.RowsSummary.DeepClone(), ["recordDigest"] = c.RecordDigest,
                ["revoked"] = c.RevokedAt is not null, ["lapsed"] = c.LapsedAtRecoveryId is not null, ["lapsedAtRecoveryId"] = c.LapsedAtRecoveryId, ["usable"] = c.IsUsable,
            };
            if (c.CodexSha256 is not null) o["codexSha256"] = c.CodexSha256; // Phase 4 Increment 2: a FIX confirmation's binary
            if (operatorView) { o["recordedBy"] = RecordedByJson(c.RecordedBy); o["revokedAt"] = c.RevokedAt; }
            confirmations.Add(o);
        }
        JsonObject? engineRuntime = null;
        if (file.CurrentRuntime is { } rt)
        {
            engineRuntime = (JsonObject)rt.Measured.DeepClone();
            engineRuntime["runtimeId"] = rt.RuntimeId;
            engineRuntime["globalRevision"] = rt.GlobalRevision;
            engineRuntime["recordedAt"] = rt.RecordedAt;
            engineRuntime["revoked"] = rt.RevokedAt is not null;
            engineRuntime["lapsed"] = rt.LapsedAtRecoveryId is not null;
            engineRuntime["lapsedAtRecoveryId"] = rt.LapsedAtRecoveryId;
            engineRuntime["usable"] = rt.IsUsable;
            if (operatorView) { engineRuntime["recordedBy"] = RecordedByJson(rt.RecordedBy); engineRuntime["revokedAt"] = rt.RevokedAt; }
        }
        return new JsonObject
        {
            ["globalRevision"] = file.GlobalRevision, ["repository"] = repository, ["acceptances"] = acceptances, ["selftestConfirmations"] = confirmations,
            ["engineRuntime"] = engineRuntime,
        };
    }

    // ---- the checks inside the run transitions (§3.3) ----

    /// <summary>The repository's usable configuration record, read in the caller's hold: CONFIG_NOT_HELD when it has none in
    /// force (none committed, or revoked), CONFIG_LAPSED when recovery lapsed it (the refusal names the one command that
    /// re-confirms it).</summary>
    private static RepositoryConfig RequireUsableConfig(string repoKey, string forWhat)
    {
        RepositoryConfig? cur = ReadConfigRecords().CurrentOf(repoKey);
        if (cur is null || cur.IsRevoked)
            throw new CustodianRefusal(ErrorCodes.ConfigNotHeld, $"the custodian holds no protected configuration for this repository{(cur is null ? "" : " in force (it was revoked)")}; {forWhat} is refused — the operator sets it with `{OperatorWording.Cli} setup --repo <path>` (nothing was registered or consumed)");
        if (cur.IsLapsed)
            throw new CustodianRefusal(ErrorCodes.ConfigLapsed, $"the repository's protected configuration lapsed when the custodian recovered after a restart of the OS (recovery {cur.LapsedAtRecoveryId}); {forWhat} is refused until the operator re-confirms it: `{OperatorWording.Cli} setup --resume --repo {cur.RepositoryRoot}` (or `{OperatorWording.Cli} loop resume <run>`)");
        return cur;
    }

    /// <summary>The isolation record a review's claim names, checked in the caller's hold (§3.3): S1 a usable self-test
    /// confirmation of that self-test, Codex version, backend and profile; S2 a usable acceptance of that backend covering
    /// the version. A record that exists and would match but lapsed is CONFIG_LAPSED; anything else ISOLATION_NOT_ACCEPTED.
    /// Returns the record's kind, id and global revision (the pin).</summary>
    private static (string Kind, string Id, int GlobalRevision) RequireIsolationBasis(JsonObject isolation, string approvedCodexSha256, IsolationBasisRead? basisNow)
    {
        ConfigRecordsFile file = ReadConfigRecords();
        string mode = (string)isolation["mode"]!;
        string backend = (string)isolation["backend"]!;
        string version = (string)isolation["codexVersion"]!;
        if (mode == "S1")
        {
            string? selftestId = (string?)isolation["selftestId"];
            SelfTestConfirmationRecord? c = selftestId is null ? null : file.SelftestConfirmations.LastOrDefault(x =>
                x.SupersededAt is null && x.RevokedAt is null && x.SelftestId == selftestId && x.CodexVersion == version && x.Backend == backend
                && x.Mode == "S1" && x.ProfileDigest == (string)isolation["profileDigest"]! && x.S1Available);
            if (c is null) throw new CustodianRefusal(ErrorCodes.IsolationNotAccepted, "the review's S1 isolation rests on a self-test the operator has not confirmed for this Codex version, backend and profile (or the confirmation was revoked); nothing was begun");
            if (c.LapsedAtRecoveryId is not null && c.HostBasis is not null) throw BootBoundLapsed();
            if (c.LapsedAtRecoveryId is not null) throw new CustodianRefusal(ErrorCodes.ConfigLapsed, $"the self-test confirmation the review's S1 isolation rests on lapsed after a restart of the OS (recovery {c.LapsedAtRecoveryId}); the operator re-confirms it with `{OperatorWording.Cli} setup --resume --repo <path>`");
            RequireHostBasisUnchanged(c, approvedCodexSha256, basisNow, "review");
            return (ConfigKinds.SelftestConfirmation, c.ConfirmationId, c.GlobalRevision);
        }
        string? acceptanceId = (string?)isolation["acceptanceId"];
        IsolationAcceptanceRecord? a = acceptanceId is null ? null : file.Acceptances.FirstOrDefault(x =>
            x.AcceptanceId == acceptanceId && x.RevokedAt is null && x.Backend == backend && version.StartsWith(x.CodexVersionRange, StringComparison.Ordinal)
            && x.Accepted.Contains("unrestricted_reads") && x.Accepted.Contains("advisory_network"));
        if (a is null) throw new CustodianRefusal(ErrorCodes.IsolationNotAccepted, "the review's reduced isolation (S2) rests on an acceptance the custodian does not hold for this backend and Codex version (or it was revoked); nothing was begun");
        if (a.LapsedAtRecoveryId is not null) throw new CustodianRefusal(ErrorCodes.ConfigLapsed, $"the isolation acceptance the review rests on lapsed after a restart of the OS (recovery {a.LapsedAtRecoveryId}); the operator re-confirms it with `{OperatorWording.Cli} setup --resume --repo <path>`");
        return (ConfigKinds.IsolationAcceptance, a.AcceptanceId, a.GlobalRevision);
    }

    /// <summary>
    /// Phase 4 Increment 2 (FIX vs S1 separation): the operator-confirmed FIX self-test a delegated fix rests on — mode FIX,
    /// for this Codex version, backend, fixer profile and the approved installation's binary. An S1 confirmation never
    /// satisfies it (nor a FIX confirmation an S1 review: <see cref="RequireIsolationBasis"/> matches mode S1 only).
    /// </summary>
    private static (string Kind, string Id, int GlobalRevision) RequireFixBasis(JsonObject isolation, string approvedCodexSha256, IsolationBasisRead? basisNow)
    {
        ConfigRecordsFile file = ReadConfigRecords();
        string? selftestId = (string?)isolation["selftestId"];
        SelfTestConfirmationRecord? c = file.SelftestConfirmations.LastOrDefault(x =>
            x.SupersededAt is null && x.RevokedAt is null && x.SelftestId == selftestId && x.Mode == "FIX" && x.CodexVersion == (string?)isolation["codexVersion"]
            && x.Backend == (string?)isolation["backend"] && x.ProfileDigest == (string?)isolation["profileDigest"] && x.S1Available && x.CodexSha256 == approvedCodexSha256);
        if (c is null) throw new CustodianRefusal(ErrorCodes.IsolationNotAccepted, $"the delegated fix rests on a FIX self-test the operator has not confirmed for this Codex version, binary, backend and fixer profile (an S1 confirmation does not count; or the confirmation was revoked); nothing was begun — the operator confirms it with `{OperatorWording.Cli} setup --fix --repo <path>`");
        if (c.LapsedAtRecoveryId is not null && c.HostBasis is not null) throw BootBoundLapsed();
        if (c.LapsedAtRecoveryId is not null) throw new CustodianRefusal(ErrorCodes.ConfigLapsed, $"the FIX self-test confirmation the delegated fix rests on lapsed after a restart of the OS (recovery {c.LapsedAtRecoveryId}); the operator re-confirms it with `{OperatorWording.Cli} setup --resume --fix --repo <path>`");
        RequireHostBasisUnchanged(c, approvedCodexSha256, basisNow, "delegated fix");
        return (ConfigKinds.SelftestConfirmation, c.ConfirmationId, c.GlobalRevision);
    }

    // ---- Phase 5 (contract §4.9, §4.12): the host's Codex sandbox basis ----

    /// <summary>
    /// The host basis a self-test confirmation binds, measured by the custodian now. The record must name its Codex
    /// installation and boot (on such a host the payload's <c>host</c> and <c>codexSha256</c> are required); the custodian
    /// refuses unless the binary it measures is the one the record names, the record is from the current boot, and every
    /// row passed. Profile presence alone never establishes confinement: the measurement is what the confirmation binds.
    /// </summary>
    private static JsonObject MeasureConfirmedBasis(JsonObject p)
    {
        if (p["host"] is not JsonObject host || (string?)p["codexSha256"] is not { } claimedSha)
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, "on this host a self-test confirmation binds the Codex sandbox basis: the self-test record must name its Codex installation, binary and boot (run the self-test again with this CodeParley version); nothing was prepared");
        JsonObject rows = p["rowsSummary"]!.AsObject();
        if (rows["failed"]!.AsArray().Count > 0 || RunFields.Integer(rows["passed"]) != RunFields.Integer(rows["total"]))
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, "the self-test record has a failed or inconclusive row; only a self-test whose every row passed can be confirmed on this host; nothing was prepared");
        JsonObject basis = Platform.Isolation.Measure((string)host["codexPath"]!);
        if ((string?)basis["codexSha256"] != claimedSha)
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, $"the Codex binary at {(string?)basis["codexPath"]} is not the one the self-test ran (measured {(string?)basis["codexSha256"]}, the record names {claimedSha}); run the self-test again; nothing was prepared");
        if ((string?)basis["bootId"] != (string)host["bootId"]!)
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, "the self-test record was produced before the last restart of the OS; run the self-test again on this boot; nothing was prepared");
        return basis;
    }

    /// <summary>The members of two basis measurements that differ (empty: the same).</summary>
    private static List<string> BasisDifferences(JsonObject held, JsonObject now)
        => [.. held.Select(kv => kv.Key).Union(now.Select(kv => kv.Key), StringComparer.Ordinal).Order(StringComparer.Ordinal)
            .Where(k => !JsonNode.DeepEquals(held[k], now[k]))];

    /// <summary>At the begin of a review or fix on a host that binds a sandbox basis: the confirmation must carry one, the
    /// basis measured again before the gate must equal it, and its Codex binary must be the repository's approved one.</summary>
    private static void RequireHostBasisUnchanged(SelfTestConfirmationRecord c, string approvedCodexSha256, IsolationBasisRead? basisNow, string what)
    {
        if (!Platform.Isolation.Binds) return;
        if (c.HostBasis is null)
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, $"the self-test confirmation the {what} rests on binds no Codex sandbox basis (it predates this host's basis); run the self-test again and confirm it; nothing was begun");
        if (basisNow?.Refusal is { } refused)
            throw new CustodianRefusal(refused.Code, $"the Codex sandbox basis cannot be approved now: {refused.Message}; nothing was begun");
        if (basisNow?.Basis is not { } now) throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, $"the Codex sandbox basis was not measured for this {what}; nothing was begun");
        if ((string?)c.HostBasis["codexSha256"] != approvedCodexSha256)
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, "the confirmed self-test ran a Codex binary other than the repository's approved installation; run the self-test with the approved Codex and confirm it; nothing was begun");
        if (BasisDifferences(c.HostBasis, now) is { Count: > 0 } changed)
            throw new CustodianRefusal(ErrorCodes.CodexIsolationUnavailable, $"the Codex sandbox basis changed since the operator confirmed the self-test ({string.Join(", ", changed)}); run the self-test again and confirm it; nothing was begun");
    }

    private static CustodianRefusal BootBoundLapsed()
        => new(ErrorCodes.CodexIsolationUnavailable, "the self-test confirmation is bound to the boot it was produced on and lapsed after a restart of the OS; it cannot be re-confirmed — the implementer runs the self-test again on this boot (`code-parley codex selftest`, then `code-parley config propose-selftest --repo <path> --out <file>`) and the operator confirms it (`/usr/local/sbin/code-parley-operator setup --resume --repo <path> --proposal-file <file>`)");

    /// <summary>For the begin of a review or fix on a host that binds a sandbox basis: the basis of the repository's approved
    /// Codex installation, measured before the gate (hashing takes time). Null when the request is neither or no
    /// installation is held (the transition refuses that itself under the gate).</summary>
    private static IsolationBasisRead? ReadIsolationBasis(string repoKey, RunRequest req)
    {
        if (!Platform.Isolation.Binds || req.Kind != RunKinds.OpBegin || (string?)req.Fields["operationKind"] is not ("review" or "fix")) return null;
        string? codexPath;
        lock (EnterGate()) codexPath = ReadConfigRecords().CurrentOf(repoKey)?.CodexInstallation?.Path;
        if (codexPath is null) return null;
        try { return new IsolationBasisRead(Platform.Isolation.Measure(codexPath), null); }
        catch (CustodianRefusal e) { return new IsolationBasisRead(null, e); }
    }

    private static string RenderHostBasis(JsonObject b)
        => "\n  measured by the custodian now (the confirmation binds these; each review and fix measures them again and refuses on any change):"
         + $"\n    Codex {(string?)b["codexPath"]} SHA-256 {(string?)b["codexSha256"]}"
         + $"\n    bwrap {(string?)b["bwrapPath"]} SHA-256 {(string?)b["bwrapSha256"]}"
         + $"\n    AppArmor profile {(string?)b["profilePath"]} SHA-256 {(string?)b["profileSha256"]}"
         + $"\n    kernel.apparmor_restrict_unprivileged_userns = {(string?)b["usernsRestriction"]}; boot {(string?)b["bootId"]}";

    /// <summary>Is the isolation record a review pinned still usable? null: usable; else why not.</summary>
    private static string? IsolationBasisProblem(ConfigRecordsFile file, string? kind, string? id)
    {
        if (kind is null || id is null) return "isolation_basis_revoked";
        if (kind == ConfigKinds.IsolationAcceptance)
            return file.Acceptances.FirstOrDefault(a => a.AcceptanceId == id) is not { } a || a.RevokedAt is not null ? "isolation_basis_revoked"
                : a.LapsedAtRecoveryId is not null ? "config_lapsed" : null;
        return file.SelftestConfirmations.FirstOrDefault(c => c.ConfirmationId == id) is not { } c || c.RevokedAt is not null || c.SupersededAt is not null ? "isolation_basis_revoked"
            : c.LapsedAtRecoveryId is not null ? "config_lapsed" : null;
    }

    /// <summary>
    /// §4.3: is a review's pinned basis still usable NOW — its isolation record not revoked or lapsed, and the repository's
    /// record in force, not lapsed, with the capture rules and Codex installation it was pinned under? null: usable; else
    /// the reason (<c>isolation_basis_revoked</c>, <c>config_lapsed</c>, <c>config_changed_since_review</c>). A review
    /// recorded without a pin (before P3.4C-4) has no basis the custodian can vouch for. Callers hold <see cref="Gate"/>.
    /// </summary>
    private static string? ReviewBasisProblem(ConfigRecordsFile file, string repoKey, OperationPin? pin)
    {
        if (pin is null) return "isolation_basis_revoked";
        string? iso = IsolationBasisProblem(file, pin.IsolationKind, pin.IsolationRecordId);
        if (iso is not null) return iso;
        RepositoryConfig? cur = file.CurrentOf(repoKey);
        if (cur is null || cur.IsRevoked) return "config_changed_since_review";
        if (cur.IsLapsed) return "config_lapsed";
        if (cur.CaptureRulesDigest != pin.CaptureRulesDigest || cur.CodexInstallation?.Sha256 != pin.CodexSha256) return "config_changed_since_review";
        return null;
    }
}
