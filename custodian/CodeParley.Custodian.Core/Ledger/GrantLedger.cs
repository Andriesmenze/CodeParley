using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

internal sealed record RecordedBy(string Role, string Channel, string Assurance, string ProofDigest, string RequestId);
internal sealed record LoopUse(string LoopId, string ConsumedAt);
/// <summary>A loop grant. <see cref="SuspendedAt"/> (P3.4C-3 §2.4 U2): recovery after a new boot suspends every unexpired
/// grant — a rolled-back consumption could otherwise be consumed again — and automation then needs a new operator grant.
/// <see cref="LastRecoveryId"/> stamps the recovery that changed it.</summary>
internal sealed record Grant(
    string GrantId, string RepoKey, string? RepositoryRoot, int LoopsTotal, int LoopsUsed,
    string CreatedAt, string ExpiresAt, string? RevokedAt, RecordedBy RecordedBy, string RequestId, List<LoopUse> Uses,
    string? SuspendedAt = null, string? LastRecoveryId = null);
/// <summary>The ledger file. <see cref="Loops"/> (P3.4C-2) holds the custodian-owned loop records
/// (Ledger/LoopRecords.cs) beside the grants they consumed.</summary>
internal sealed record LedgerFile(int Version, List<Grant> Grants, List<LoopRecord>? Loops = null);

// ---- P3.4C-1: the protected user-record log (decisions & amendments) ----

/// <summary>One committed user decision or task amendment. <see cref="Payload"/> holds the full record the
/// engine proposed (its structural fields AND the raw private text — a decision note or amendment text),
/// stored here and never re-exposed to the implementer surface. <see cref="RecordedBy"/> is set by the
/// custodian from the classified operator token, never from the request. For an amendment the custodian
/// derives <see cref="ContentKeyHash"/> (a KEYED HMAC of the normalized content-equivalence input under the
/// custodian's secret — equality-comparable but not reversible or offline-guessable; P3.4C-1 confidentiality
/// correction) and <see cref="TextBytes"/> from the authoritative text, so the implementer's derivation can
/// run the new-information gate and byte budget without the raw text; <see cref="ContentKeyScheme"/> tags the
/// keying scheme (a record lacking it is a pre-correction unkeyed record, never mixed with keyed ones);
/// <see cref="DisclosureDigest"/> is the engine-supplied, operator-confirmed digest of the redacted
/// reviewer-visible artifact, bound here.</summary>
internal sealed record UserRecordEntry(
    string RecordId, int Seq, string RecordKind, System.Text.Json.Nodes.JsonObject Payload,
    string? ContentKeyHash, int? TextBytes, string? DisclosureDigest,
    RecordedBy RecordedBy, string RequestId, string RecordedAt, string? ContentKeyScheme = null, string? DisclosureText = null);

/// <summary>The per-(repository identity, run) protected log. <see cref="Revision"/> is monotonic and bumps
/// on every committed record; prepare binds the revision it was prepared against and commit refuses a
/// changed revision (STALE_FINDING_STATE), the custodian-side analogue of the engine's decision-token
/// recheck. <see cref="RecoveredAtRevision"/> (P3.4C-3 §2.4 U4): the log's revision when a recovery after a new boot
/// ran — a waive or defer recorded at or before it may have lost its revocation, so on a run whose loop is not
/// terminal it no longer applies until the operator re-confirms it. <see cref="LastRecoveryId"/> stamps that recovery.</summary>
internal sealed record UserRecordLog(string RepoKey, string RunId, int Revision, List<UserRecordEntry> Records,
    int? RecoveredAtRevision = null, string? LastRecoveryId = null);

/// <summary>The store file. <see cref="ContentKeyId"/> is the non-secret id of the content-key secret the
/// keyed amendment records depend on; it is bound when the first keyed amendment is written and, if the
/// current secret's id differs (a lost or rotated secret), commit fails closed rather than silently
/// re-keying.</summary>
internal sealed record UserRecordsFile(int Version, List<UserRecordLog> Logs, string? ContentKeyId = null);

internal sealed record PreparedAuthorization(string RequestId, string Action, string Rendering, string Digest, string Challenge, string ExpiresAt, JsonObject? Facts = null);

/// <summary>The named points inside a hold of the ledger's lock at which the self-test-only hold hook is called
/// (P3.4C-3 N17/N18). Each is reached only after the hold's checks passed, before its write.</summary>
internal static class HoldPoints
{
    /// <summary><c>consume_loop</c>: the run record and the grant were checked; the loop is about to be minted.</summary>
    internal const string ConsumeChecked = "consume:checked";
    /// <summary><c>op_begin</c>: the bound caller was verified; the operation is about to be recorded.</summary>
    internal const string OpBeginBoundChecked = "op_begin:bound_checked";
    /// <summary><c>end</c>: the terminal run record is written; the loop's end is about to be derived.</summary>
    internal const string EndRunWritten = "end:run_written";
    /// <summary>A continuation spend or wake arm/consume was authorized; it is about to be written (suffix: the kind).</summary>
    internal const string LoopAuthorized = "loop:authorized:";
    /// <summary><c>commit</c> of a user record: its freshness was checked; it is about to be written.</summary>
    internal const string CommitFresh = "commit:fresh";
    /// <summary>A <c>run_transition</c> was computed; it is about to be written (suffix: the kind).</summary>
    internal const string RunApplied = "run:applied:";
}

/// <summary>
/// The custodian's one protected record type for P3.4B: a grant/consumption ledger with a two-phase,
/// proof-carrying operator path and a reduce-only implementer path.
///
/// Operator: <c>PrepareGrant</c>/<c>PrepareRevoke</c> record a time-boxed INTENT bound to a digest over
/// the action, canonical args, state shown, custodian id, request id and nonce; <c>Commit</c> re-derives
/// and re-validates all of it against the live ledger before applying it. Implementer: <c>ConsumeLoop</c>
/// spends one loop of an active grant, and <c>ListGrants</c> reads — neither can create or enlarge a grant
/// (invariant I-1). All mutations take one in-process lock and are persisted by atomic replace. The P3.4C-2
/// loop lifecycle (<c>loop_transition</c>) is in GrantLedger.Loops.cs.
/// </summary>
internal sealed partial class GrantLedger
{
    /// <summary>The ledger's single lock (P3.4C-3 §2.5): every decision and write across all store files — grants,
    /// intents, user records, loops and runs — and every read of them is made in one hold of it.</summary>
    private static readonly object Gate = new();

    /// <summary>SELF-TEST ONLY: called at named points inside a hold of <see cref="Gate"/> (<see cref="HoldPoints"/>), so
    /// the interleaving self-tests (N17, N18) can pause a holder and issue a competing request. Never set by the
    /// service.</summary>
    internal static Action<string>? HoldHook;

    private static void Hold(string point) => HoldHook?.Invoke(point);

    /// <summary>The single lock, entered only through here (§2.5 S7): the only other lock, the content-key
    /// <c>ValidateGate</c>, is taken inside this one or alone and never the other way round — entering this lock while
    /// holding it would invert the order, and is refused (fail closed) instead of risking a deadlock.</summary>
    private static object EnterGate() => AmendmentContentKey.HoldingValidateGate
        ? throw new InvalidOperationException("lock order violated: the ledger lock was requested while the content-key validation lock is held")
        : Gate;
    private readonly string _custodianId;
    private readonly IProcessTable _processes;
    private readonly Func<DateTime> _clock;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };

    /// <summary>P3.4C-3: a run record as it travels (both projections of the run section): every field present, a null
    /// one as null, so a client reads one shape from the real and the simulated custodian.</summary>
    private static readonly JsonSerializerOptions WireJson = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary><paramref name="processes"/> is the process table the loop-binding check reads and
    /// <paramref name="clock"/> the UTC time the loop lifecycle (mint, deadlines, nonce expiry) runs on — the OS
    /// and the system clock by default; only the self-tests inject either.</summary>
    internal GrantLedger(string custodianId, IProcessTable? processes = null, Func<DateTime>? clock = null)
    {
        _custodianId = custodianId;
        _processes = processes ?? Platform.Processes;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    private static string NowIso() => DateTime.UtcNow.ToString("o");

    // ---- operator: prepare / commit ----

    /// <summary>Prepare a grant for the directory <paramref name="repositoryRoot"/> names. The repository's
    /// identity is the custodian's own (<see cref="RepoIdentities"/>: handle-backed, refused rather than
    /// guessed); the client's spelling is only a locator, and the intent records the custodian's canonical
    /// path and key.</summary>
    internal PreparedAuthorization PrepareGrant(string repositoryRoot, int loops, int minutes, string requestId)
    {
        if (loops is < 1 || loops > CustodianConstants.MaxGrantLoops) throw new ArgumentException($"loops must be 1..{CustodianConstants.MaxGrantLoops}");
        if (minutes is < 1 || minutes > CustodianConstants.MaxGrantMinutes) throw new ArgumentException($"minutes must be 1..{CustodianConstants.MaxGrantMinutes}");
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        var args = new JsonObject { ["repositoryRoot"] = id.CanonicalPath, ["repoKey"] = id.Key, ["loops"] = loops, ["minutes"] = minutes };
        string rendering = $"Grant {loops} automated loop(s) for {minutes} min in repository:\n  {id.CanonicalPath}\n  identity {id.Key} ({id.FileSystem}): the grant follows this directory, not its path";
        return PrepareIntent("grant", args, StateDigestForRepo(id.Key), requestId, rendering);
    }

    internal PreparedAuthorization PrepareRevoke(string repositoryRoot, string requestId)
    {
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        var args = new JsonObject { ["repositoryRoot"] = id.CanonicalPath, ["repoKey"] = id.Key };
        return PrepareIntent("revoke", args, StateDigestForRepo(id.Key), requestId, $"Revoke all active grants for:\n  {id.CanonicalPath}\n  identity {id.Key}");
    }

    /// <summary>The intent file path for a request id, rejecting any id that is not a safe token so a
    /// control-plane field can never become a path-traversal (TD amendment 4: path substitution).</summary>
    private static string IntentPath(string requestId)
    {
        if (requestId.Length is < 1 or > 128 || requestId is "." or ".." ||
            !requestId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new ArgumentException("request id must be 1..128 chars of [A-Za-z0-9-_]");
        return Path.Combine(StorePaths.IntentsDir, requestId + ".json");
    }

    private PreparedAuthorization PrepareIntent(string action, JsonObject args, string stateDigest, string requestId, string rendering)
    {
        lock (EnterGate())
        {
            string existing = IntentPath(requestId);
            if (File.Exists(existing)) throw new InvalidOperationException("an authorization with this request id is already pending (REQUEST_ID_CONFLICT)");
            if (GrantByRequestId(Read(), requestId) is not null) throw new InvalidOperationException("this request id was already committed (REQUEST_ID_CONFLICT)");
            if (action == ConfigRecordAction && ConfigRequestCommitted(requestId)) throw new InvalidOperationException("this request id was already committed (REQUEST_ID_CONFLICT)");
            string nonce = Digest.Nonce();
            string expiresAt = DateTime.UtcNow.AddSeconds(CustodianConstants.AuthorizationTtlSeconds).ToString("o");
            string digest = Digest.AuthorizationDigest(action, args, stateDigest, _custodianId, requestId, nonce, expiresAt);
            var intent = new JsonObject
            {
                ["action"] = action, ["args"] = args.DeepClone(), ["stateDigest"] = stateDigest, ["nonce"] = nonce,
                ["digest"] = digest, ["expiresAt"] = expiresAt, ["createdAt"] = NowIso(), ["requestId"] = requestId,
            };
            Directory.CreateDirectory(StorePaths.IntentsDir);
            AtomicWrite(existing, intent.ToJsonString(Json));
            return new PreparedAuthorization(requestId, action, rendering, digest, nonce[..16], expiresAt);
        }
    }

    internal JsonObject Commit(string requestId, string? proofDigestFromClient)
    {
        // Phase 4 Increment 3 (§3.5): a fix decision is rendered again BEFORE the gate (no export is read under the lock);
        // its commit compares that rendering with the one the operator was shown.
        string? rerendered = RerenderForCommit(requestId, out _);
        JsonObject committed = CommitLocked(requestId, proofDigestFromClient, rerendered);
        DrainRetiredProposals(); // a rejected proposal's content, outside the gate
        return committed;
    }

    private JsonObject CommitLocked(string requestId, string? proofDigestFromClient, string? rerendered)
    {
        lock (EnterGate())
        {
            string path = IntentPath(requestId);
            if (!File.Exists(path)) throw new InvalidOperationException("no pending authorization for this request id (AUTHORIZATION_INVALID)");
            JsonObject intent = (JsonObject)(JsonNode.Parse(File.ReadAllText(path)) ?? throw new InvalidOperationException("corrupt intent"));
            string action = (string)intent["action"]!;
            var args = (JsonObject)intent["args"]!;
            string nonce = (string)intent["nonce"]!;
            string expiresAt = (string)intent["expiresAt"]!;
            string recordedDigest = (string)intent["digest"]!;
            string recordedState = (string)intent["stateDigest"]!;

            if (DateTime.Parse(expiresAt).ToUniversalTime() < DateTime.UtcNow) { TryDelete(path); throw new TimeoutException("authorization expired (AUTHORIZATION_EXPIRED)"); }
            // Re-derive the digest and the state shown; any drift refuses the commit. The "state shown" is
            // the grants for the repo (grant/revoke) or the per-run user-record log revision+digest
            // (user_record) — the custodian re-checks ITS OWN protected state, action-aware.
            string repoKey = (string?)args["repoKey"] ?? "";
            // P3.4C-3 (§3.4(2)): a decision on a run that has ended since its prepare is refused as such.
            if (action == "user_record" && (string?)args["recordKind"] == "decision" && ReadRun(repoKey, (string)args["runId"]!) is { IsTerminal: true } ended)
            { TryDelete(path); throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({ended.Status}) since this was prepared; nothing was committed"); }
            if (action == FixDecisionAction)
            {
                try { RequireFreshFixDecision(args, recordedState, rerendered, _clock()); }
                catch (CustodianRefusal) { TryDelete(path); throw; }
            }
            else if (CurrentStateDigest(action, args, repoKey) != recordedState)
            {
                TryDelete(path);
                if (action == ConfigRecordAction) throw StaleConfig("a configuration record this change affects changed since it was prepared");
                throw new InvalidOperationException("the ledger changed since this was prepared; nothing was committed (STALE_FINDING_STATE)");
            }
            string reDigest = Digest.AuthorizationDigest(action, args, recordedState, _custodianId, requestId, nonce, expiresAt);
            if (reDigest != recordedDigest) throw new InvalidOperationException("authorization digest mismatch (AUTHORIZATION_INVALID)");
            // A grant or a user_record is committed only for the directory the operator was shown:
            // re-establish the identity at its canonical path; a directory replaced since the prepare is a
            // different object. (A revoke only reduces authority and applies to the recorded key.)
            if ((action is "grant" or "user_record" or FixDecisionAction || (action == ConfigRecordAction && (string?)args["recordKind"] == ConfigKinds.Repository && (string?)args["action"] != ConfigKinds.Revoke))
                && !StillTheSameDirectory((string)args["repositoryRoot"]!, repoKey))
            {
                TryDelete(path);
                throw new InvalidOperationException("the repository directory changed since this was prepared (deleted, replaced or no longer reachable); nothing was committed (STALE_FINDING_STATE)");
            }
            Hold(HoldPoints.CommitFresh); // the freshness checks and the write below are one hold (§2.5 S5)

            JsonObject result = action switch
            {
                "grant" => ApplyGrant(args, requestId, recordedDigest, proofDigestFromClient),
                "revoke" => ApplyRevoke(repoKey),
                "user_record" => ApplyUserRecord(args, requestId, recordedDigest, proofDigestFromClient),
                ConfigRecordAction => ApplyConfigRecord(args, requestId, recordedDigest, proofDigestFromClient),
                FixDecisionAction => ApplyFixDecision(args, requestId, recordedDigest, proofDigestFromClient),
                _ => throw new InvalidOperationException($"unknown action '{action}'"),
            };
            TryDelete(path);
            return result;
        }
    }

    private JsonObject ApplyGrant(JsonObject args, string requestId, string digest, string? proof)
    {
        LedgerFile file = Read();
        var now = DateTime.UtcNow;
        var grant = new Grant(
            GrantId: Guid.NewGuid().ToString(),
            RepoKey: (string)args["repoKey"]!,
            RepositoryRoot: (string?)args["repositoryRoot"],
            LoopsTotal: (int)args["loops"]!,
            LoopsUsed: 0,
            CreatedAt: now.ToString("o"),
            ExpiresAt: now.AddMinutes((int)args["minutes"]!).ToString("o"),
            RevokedAt: null,
            RecordedBy: new RecordedBy("user", "custodian_operator", Platform.OperatorAssurance, proof ?? digest, requestId),
            RequestId: requestId,
            Uses: []);
        file.Grants.Add(grant);
        Prune(file, now);
        Write(file);
        Audit($"grant committed grantId={grant.GrantId} repoKey={grant.RepoKey} loops={grant.LoopsTotal} requestId={requestId} assurance={Platform.OperatorAssurance}");
        return new JsonObject { ["grantId"] = grant.GrantId, ["loopsTotal"] = grant.LoopsTotal, ["expiresAt"] = grant.ExpiresAt, ["assurance"] = Platform.OperatorAssurance };
    }

    private JsonObject ApplyRevoke(string repoKey)
    {
        LedgerFile file = Read();
        var now = DateTime.UtcNow;
        int n = 0;
        for (int i = 0; i < file.Grants.Count; i++)
        {
            Grant g = file.Grants[i];
            if (g.RepoKey == repoKey && g.RevokedAt is null && DateTime.Parse(g.ExpiresAt).ToUniversalTime() > now)
            { file.Grants[i] = g with { RevokedAt = now.ToString("o") }; n++; }
        }
        Write(file);
        Audit($"revoke committed repoKey={repoKey} revoked={n}");
        return new JsonObject { ["revoked"] = n };
    }

    // ---- implementer: consume / list (reduce-only; never creates authority) ----

    /// <summary>P3.4C-2: atomically consume one loop of an active grant AND mint the authoritative,
    /// custodian-owned loop record for <paramref name="runId"/>, co-located in the ledger (Option A), so the
    /// consume and the mint commit or roll back as one write (never a spent grant without a loop, nor a loop
    /// without consumed authority). Idempotent on <paramref name="requestId"/>; one non-terminal loop per run;
    /// a terminal run's loop is not resurrected. The loop is minted UNBOUND with no operation handle (the
    /// first handle is issued at bind); its one-time bind-nonce preimage is returned here exactly once (only
    /// its hash is stored).</summary>
    internal JsonObject ConsumeLoop(string repositoryRoot, string runId, string requestId)
    {
        ValidateRunId(runId);
        ValidateRequestId(requestId);
        // The custodian's own identity of the directory the client names; a legacy (textual) ledger key has
        // another scheme and is never equal to it, so a pre-P3.4C-0 grant is never consumed or reinterpreted.
        string repoKey = RepoIdentities.Resolve(repositoryRoot).Key;
        lock (EnterGate())
        {
            LedgerFile file = Read();
            DateTime now = _clock();

            // One loop per run, persisted (survives restart): a same-request replay returns the SAME result
            // and consumes nothing again; a different request for a run that already has a live loop is
            // refused (RUN_ALREADY_HAS_LOOP); a run whose loop has ended is never resurrected (LOOP_TERMINAL).
            // Refusals carry their code structurally (the run id they quote cannot select another code).
            LoopRecord? existing = file.Loops!.FirstOrDefault(l => l.RepoKey == repoKey && l.RunId == runId);
            if (existing is not null)
            {
                if (existing.RequestId == requestId) return ConsumeResultOf(existing);
                if (LoopStatuses.IsTerminal(existing.Status))
                    throw new CustodianRefusal(ErrorCodes.LoopTerminal, $"run {runId} already had an automation loop that ended ({existing.Status}); it is not resurrected");
                throw new CustodianRefusal(ErrorCodes.RunAlreadyHasLoop, $"run {runId} already has an automation loop; a second is not minted");
            }

            // P3.4C-3 (§3.4(1), §5.5 I1): a loop is minted only for a run the custodian holds open, read in this same
            // hold — so no `end` slips between the check and the mint, and no loop exists without its run record.
            RunRecord? run = ReadRun(repoKey, runId);
            if (run is null) throw new CustodianRefusal(ErrorCodes.RunNotOpen, $"run {runId} was not opened with the custodian; nothing was consumed");
            if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"run {runId} has ended ({run.Status}); nothing was consumed");

            // Reduce-only: spend one loop of an active grant; never create or enlarge authority (I-1). A grant suspended
            // by recovery (§2.4 U2) is never consumed.
            Grant? g = file.Grants.FirstOrDefault(x => x.RepoKey == repoKey && x.RevokedAt is null
                && DateTime.Parse(x.ExpiresAt).ToUniversalTime() > now && x.LoopsUsed < x.LoopsTotal && !IsSuspended(x));
            if (g is null) throw new CustodianRefusal(ErrorCodes.LoopNotAuthorized, "no automated loop is authorized for this repository");
            Hold(HoldPoints.ConsumeChecked);

            string loopId = Guid.NewGuid().ToString();
            string nonce = Digest.Nonce();
            var limits = new LoopLimits(CustodianConstants.LoopContinuations, CustodianConstants.LoopWakesPerOperation, CustodianConstants.LoopWakesPerRun, CustodianConstants.LoopRunSeconds);
            var loop = new LoopRecord(
                LoopId: loopId, RepoKey: repoKey, RunId: runId, Status: "unbound", Epoch: 1, LoopRevision: 1,
                StartedAt: now.ToString("o"), DeadlineAt: now.AddSeconds(limits.RunSeconds).ToString("o"),
                GrantId: g.GrantId,
                GrantUse: new LoopGrantUse("custodian", loopId, requestId, g.LoopsUsed + 1, g.LoopsTotal),
                Limits: limits, Used: new LoopUsed(0, 0),
                BindNonce: new BindNonce(Digest.Sha256Hex(nonce), now.ToString("o"), now.AddSeconds(CustodianConstants.BindNonceTtlSeconds).ToString("o"), null),
                RequestId: requestId);

            // Atomic consume + mint: the grant spend and the new loop record are ONE ledger write.
            file.Grants[file.Grants.IndexOf(g)] = g with { LoopsUsed = g.LoopsUsed + 1, Uses = [.. g.Uses, new LoopUse(loopId, now.ToString("o"))] };
            file.Loops!.Add(loop);
            Write(file);
            Audit($"loop consumed+minted grantId={g.GrantId} loopId={loopId} runId={runId} used={loop.GrantUse.LoopsUsed}/{loop.GrantUse.LoopsTotal} status=unbound epoch=1 rev=1");
            JsonObject res = ConsumeResultOf(loop);
            res["bindNonce"] = nonce; // one-time preimage the host presents to bind; only its hash is stored
            return res;
        }
    }

    /// <summary>The <c>consume_loop</c> result (contract §1): grant/loop identity, the grant usage, the run,
    /// and the loop's own epoch and revision. The bind-nonce preimage is added only on the minting call (never
    /// on an idempotent replay — the custodian does not keep it), and no operation handle is issued (bind does).</summary>
    private static JsonObject ConsumeResultOf(LoopRecord l) => new()
    {
        ["grantId"] = l.GrantId, ["loopId"] = l.LoopId,
        ["loopsUsed"] = l.GrantUse.LoopsUsed, ["loopsTotal"] = l.GrantUse.LoopsTotal,
        ["runId"] = l.RunId, ["loopEpoch"] = l.Epoch, ["loopRevision"] = l.LoopRevision,
    };

    /// <summary>Every grant, with the custodian's canonical path for the operator, the identity scheme of its
    /// key (a <c>legacy_text</c> grant from before P3.4C-0 is never active: it can be neither matched nor
    /// consumed), and the ceilings the custodian enforces — the authoritative limits a client reports.</summary>
    internal JsonObject ListGrants()
    {
        LedgerFile file;
        lock (EnterGate()) file = Read(); // P3.4C-3 §2.5 S6: no read races a replacement
        var now = DateTime.UtcNow;
        var arr = new JsonArray();
        foreach (Grant g in file.Grants)
        {
            bool current = RepoIdentities.IsCurrent(g.RepoKey);
            arr.Add(new JsonObject
            {
                ["grantId"] = g.GrantId, ["repoKey"] = g.RepoKey, ["repositoryRoot"] = g.RepositoryRoot,
                ["identity"] = current ? RepoIdentities.Scheme : "legacy_text",
                ["loopsUsed"] = g.LoopsUsed, ["loopsTotal"] = g.LoopsTotal,
                ["expiresAt"] = g.ExpiresAt, ["revoked"] = g.RevokedAt is not null,
                // P3.4C-3 (§2.4 U2): a grant suspended by recovery after a new boot is shown as such and is never active.
                ["suspended"] = IsSuspended(g),
                ["active"] = current && g.RevokedAt is null && !IsSuspended(g) && DateTime.Parse(g.ExpiresAt).ToUniversalTime() > now && g.LoopsUsed < g.LoopsTotal,
                ["assurance"] = g.RecordedBy.Assurance,
            });
        }
        return new JsonObject
        {
            ["grants"] = arr,
            ["ceilings"] = new JsonObject { ["loops"] = CustodianConstants.MaxGrantLoops, ["minutes"] = CustodianConstants.MaxGrantMinutes },
        };
    }

    // ---- P3.4C-1 operator: prepare / list user decisions & amendments ----

    /// <summary>Prepare a user decision or task amendment for (repository, run). The custodian establishes
    /// the repository's identity itself; the engine supplies the structural payload, the raw text and (for
    /// an amendment with text) the operator-confirmed redacted-artifact digest. The intent binds the payload
    /// and the current per-run log revision; nothing is recorded until <see cref="Commit"/>. Provenance,
    /// ordering, the content-equivalence hash and the byte length are the custodian's, never the client's.</summary>
    internal PreparedAuthorization PrepareUserRecord(string repositoryRoot, string runId, string recordKind, JsonObject payload, int baseRevision, string requestId)
    {
        ValidateRunId(runId);
        if (recordKind is not ("decision" or "amendment")) throw new ArgumentException("recordKind must be 'decision' or 'amendment'");
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        // Reject any client-supplied authority/provenance: the custodian alone sets it (I-2). Unknown
        // top-level payload keys are allowed (lenient forward-compat), but never these.
        foreach (string banned in new[] { "recorded_by", "role", "channel", "assurance", "proof_digest", "seq", "record_id", "read_disclosure_digest" })
            if (payload.ContainsKey(banned)) throw new ArgumentException($"payload may not carry '{banned}': provenance, ordering and identifiers are set by the custodian");

        string kind = (string?)payload["kind"] ?? throw new ArgumentException("payload.kind is required");
        string? disclosureText = null, redactionBasis = null;
        if (recordKind == "amendment")
        {
            string text = (string?)payload["text"] ?? "";
            if (text.Length > CustodianConstants.MaxAmendmentTextChars) throw new ArgumentException($"amendment text is longer than {CustodianConstants.MaxAmendmentTextChars} characters");
            // Phase 5 F-i2-5: the operator cannot read the working tree or write the implementer's run store, so the
            // CUSTODIAN produces the reviewer-visible redaction (its helper runs the engine's own redaction over a fresh
            // read under the held capture rules, outside the lock) and holds the representation the operator confirms.
            if (payload["custodian_redaction"] is not null)
            {
                if (payload["custodian_redaction"] is not JsonValue cr || !cr.TryGetValue(out bool on) || !on) throw new ArgumentException("payload.custodian_redaction is true when present");
                if (payload.ContainsKey("disclosure_digest") || payload.ContainsKey("source"))
                    throw new ArgumentException("an amendment the custodian redacts may not carry 'disclosure_digest' or 'source': the custodian derives both from its own read");
                payload = (JsonObject)payload.DeepClone();
                if (text.Trim().Length > 0)
                {
                    (disclosureText, string sourceId, redactionBasis, string readDisclosure) = RedactForReview(id, runId, text);
                    payload["disclosure_digest"] = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(disclosureText)));
                    payload["source"] = new JsonObject { ["source_id"] = sourceId };
                    // Phase 5 OI-1: the read's disclosure record is held before anything can be confirmed, and the record
                    // binds it; a later amendment's redaction covers what this read withheld.
                    payload["read_disclosure_digest"] = HoldReadDisclosure(id.Key, runId, readDisclosure);
                    // The basis the redaction rested on: the commit re-derives it, so a capture or a disclosure recorded
                    // in between (whose names the confirmed text was not redacted against) refuses the record.
                    payload["redaction_basis_digest"] = redactionBasis;
                }
                else payload["source"] = null;
            }
            // P3.4C-1 confidentiality correction: the content-equivalence key and the byte length are DERIVED
            // BY THE CUSTODIAN from the authoritative text at commit, under a custodian-only secret — never
            // supplied by the engine. A client that sends either is rejected (the custodian is their sole
            // source), so an implementer-visible value can never be an offline-guessable unkeyed hash.
            if (payload.ContainsKey("content_key_hash") || payload.ContainsKey("text_bytes"))
                throw new ArgumentException("payload may not carry 'content_key_hash' or 'text_bytes': the custodian derives the content-equivalence key and byte length from the authoritative text");
            // When an amendment carries text, the reviewer-visible representation is an engine-side artifact
            // the operator confirmed; its digest is bound here and returned to the implementer so a review
            // can validate the artifact before presenting it (raw text never leaves the operator surface).
            if (text.Trim().Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch((string?)payload["disclosure_digest"] ?? "", "^[0-9a-f]{64}$"))
                throw new ArgumentException("payload.disclosure_digest (sha256 of the operator-confirmed redacted artifact) is required for an amendment with text");
        }
        else
        {
            string note = (string?)payload["note"] ?? "";
            if (note.Length > CustodianConstants.MaxDecisionNoteChars) throw new ArgumentException($"decision note is longer than {CustodianConstants.MaxDecisionNoteChars} characters");
        }

        var args = new JsonObject
        {
            ["repositoryRoot"] = id.CanonicalPath, ["repoKey"] = id.Key, ["runId"] = runId,
            ["recordKind"] = recordKind, ["payload"] = payload.DeepClone(), ["baseRevision"] = baseRevision,
        };
        if (disclosureText is not null) args["disclosureText"] = disclosureText;
        if (redactionBasis is not null) args["redactionBasis"] = redactionBasis;
        // P3.4C-3 (§3.4(2), §2.5 S5): one hold — the log revision, a protected decision's run state and the state digest
        // the commit re-derives are read together, so nothing can change between them.
        lock (EnterGate())
        {
            int current = ReadUserLog(id.Key, runId)?.Revision ?? 0;
            if (baseRevision != current) throw new InvalidOperationException($"the run's user-record log changed since this was prepared (revision {current}, prepared against {baseRevision}); nothing was committed (STALE_FINDING_STATE)");
            if (recordKind == "decision") ValidateProtectedDecision(id.Key, runId, payload);
            if (redactionBasis is not null && CurrentBasisDigest(id.Key, runId) != redactionBasis)
                throw Stale("a capture or a disclosure was recorded for this run while the text was being redacted, so the redaction does not cover it");
            string scope = recordKind == "amendment" ? $"task amendment ({kind})" : $"decision ({kind})";
            string rendering = $"Record a {scope} for run {runId} in repository:\n  {id.CanonicalPath}\n  identity {id.Key} ({id.FileSystem})\n  (operator-authoritative; revision {current} → {current + 1})";
            if (disclosureText is not null)
                rendering += $"\n  Codex will see exactly this redaction of your text (the custodian's, from its own read; the raw text stays in the custodian):\n  {System.Text.Json.JsonSerializer.Serialize(disclosureText)}";
            return PrepareIntent("user_record", args, UserRecordStateDigest(args, id.Key), requestId, rendering);
        }
    }

    /// <summary>
    /// P3.4C-3 (§3.4(2)): a decision on a PROTECTED run (the custodian holds its loop or run record) is checked against the
    /// custodian's own run record at prepare — the run is open and not terminal, every covered item exists and is open,
    /// the decision names the run's latest accepted review, and no reply or response on a covered item is newer than the
    /// ones it names — else STALE_FINDING_STATE; the commit then re-checks the covered items' revisions in the same
    /// hold as its write. This closes the P3.4C-1 advisory token on protected runs. A run that is not protected is
    /// unchanged.
    /// </summary>
    private void ValidateProtectedDecision(string repoKey, string runId, JsonObject payload)
    {
        bool hasLoop = Read().Loops!.Any(l => l.RepoKey == repoKey && l.RunId == runId);
        RunRecord? run = ReadRun(repoKey, runId);
        if (!hasLoop && run is null) return;
        if (run is null) throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no run record for this protected run, so the state a decision covers cannot be verified; nothing was prepared");
        if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({run.Status}); nothing was prepared");
        HashSet<string> covered = CoveredItems(payload);
        if (covered.Count == 0) throw new ArgumentException("payload.covered_items must name the open items the decision covers");
        foreach (string itemId in covered)
            if (run.Items.FirstOrDefault(i => i.ItemId == itemId) is not { Status: "open" })
                throw Stale($"item {itemId} is not an open item of this run");
        if (payload["decided_against"] is not JsonObject da) throw new ArgumentException("payload.decided_against is required");
        RunReview? latest = run.Reviews.LastOrDefault(r => r.Accepted == true);
        if ((string?)da["run_review_id"] != latest?.ReviewId || RunFields.Integer(da["run_round"]) != latest?.Round)
            throw Stale("the run's current review is not the one the decision names");
        CheckLatestOnCovered(run.Replies, "replyId", (string?)da["latest_reply_id"], covered, "reply");
        CheckLatestOnCovered(run.Responses, "responseId", (string?)da["latest_response_id"], covered, "response");
    }

    /// <summary>The decision names <paramref name="claimed"/> as the latest reply (or response) it saw; none on a covered
    /// item may come after it in the custodian's order.</summary>
    private static void CheckLatestOnCovered(List<JsonObject> records, string idKey, string? claimed, HashSet<string> covered, string what)
    {
        int lastOnCovered = records.FindLastIndex(r => covered.Contains((string?)r["itemId"] ?? ""));
        if (claimed is null)
        {
            if (lastOnCovered >= 0) throw Stale($"a {what} on a covered item is newer than the state the decision names");
            return;
        }
        int claimedAt = records.FindIndex(r => (string?)r[idKey] == claimed);
        if (claimedAt < 0) throw Stale($"the {what} {claimed} the decision names is not one the custodian holds");
        if (lastOnCovered > claimedAt) throw Stale($"a {what} on a covered item is newer than {claimed}");
    }

    private static HashSet<string> CoveredItems(JsonNode? payload)
        => payload?["covered_items"] is JsonArray a ? a.Select(x => x is JsonValue v && v.TryGetValue(out string? s) ? s! : "").Where(s => s.Length > 0).ToHashSet(StringComparer.Ordinal) : [];

    private static CustodianRefusal Stale(string why) => new(ErrorCodes.StaleState, $"{why}; nothing was recorded — read the current state and decide anew");

    /// <summary>
    /// The "state shown" of a user record, which its commit re-derives in the same hold as its write: the run's
    /// user-record log; for a DECISION on a run the custodian holds a run record for, also the covered items'
    /// revisions and statuses and whether the run has ended (P3.4C-3 §3.4(2)) — so an assessment, response or reply
    /// touching a covered item, or the run's end, between prepare and commit makes the commit refuse.
    /// </summary>
    private string UserRecordStateDigest(JsonObject args, string repoKey)
    {
        string runId = (string)args["runId"]!;
        string log = UserLogDigest(repoKey, runId);
        // Phase 5 F-i2-5: an amendment the custodian redacted is bound to the redaction basis it was redacted against.
        if (args["redactionBasis"] is not null)
            return Digest.Sha256Hex(Digest.Canonical(new JsonObject { ["log"] = log, ["redactionBasis"] = CurrentBasisDigest(repoKey, runId) ?? "none" }));
        if ((string?)args["recordKind"] != "decision" || ReadRun(repoKey, runId) is not { } run) return log;
        var covered = new JsonArray(CoveredItems(args["payload"]).Order(StringComparer.Ordinal).Select(id =>
        {
            RunItem? it = run.Items.FirstOrDefault(i => i.ItemId == id);
            return (JsonNode)new JsonObject { ["id"] = id, ["revision"] = it?.ItemRevision ?? -1, ["status"] = it?.Status };
        }).ToArray());
        return Digest.Sha256Hex(Digest.Canonical(new JsonObject { ["log"] = log, ["covered"] = covered, ["terminal"] = run.IsTerminal }));
    }

    private JsonObject ApplyUserRecord(JsonObject args, string requestId, string digest, string? proof)
    {
        string repoKey = (string)args["repoKey"]!;
        string runId = (string)args["runId"]!;
        string recordKind = (string)args["recordKind"]!;
        var payload = (JsonObject)args["payload"]!;
        int baseRevision = (int)args["baseRevision"]!;

        UserRecordsFile file = ReadUserRecords();
        UserRecordLog? log = file.Logs.FirstOrDefault(l => l.RepoKey == repoKey && l.RunId == runId);
        if (log is null) { log = new UserRecordLog(repoKey, runId, 0, []); file.Logs.Add(log); }
        if (log.Revision != baseRevision) throw new InvalidOperationException($"the run's user-record log changed since this was prepared (STALE_FINDING_STATE)");
        if (log.Records.Count + 1 > CustodianConstants.MaxUserRecordsPerRun) throw new InvalidOperationException($"a run keeps at most {CustodianConstants.MaxUserRecordsPerRun} user records");

        string? contentKeyHash = null; int? textBytes = null; string? disclosureDigest = null; string? contentKeyScheme = null;
        if (recordKind == "amendment")
        {
            // P3.4C-1 confidentiality correction: the custodian DERIVES the content-equivalence key and the
            // byte length from its authoritative text (it never trusts an engine-supplied hash/length), under
            // a secret only it holds, so the implementer-visible value is equality-comparable but not
            // offline-guessable. The disclosure digest stays engine-supplied (it binds the operator-confirmed
            // redacted artifact). Pre-correction (unkeyed) records are never mixed with keyed ones.
            if (log.Records.Any(r => r.RecordKind == "amendment" && r.ContentKeyScheme != AmendmentContentKey.Scheme))
                throw new InvalidOperationException("this run's protected log holds pre-correction (unkeyed) amendment records; recording a keyed amendment into it is refused (fail closed) — do not mix keyed and unkeyed content keys");
            // Fail closed unless the runtime's Unicode globalization reproduces the engine's normalization.
            AmendmentContentKey.SelfValidate();
            ContentKey key = ContentKeySecret.GetOrCreate();
            if (file.ContentKeyId is not null && file.ContentKeyId != key.KeyId)
                throw new InvalidOperationException("the custodian content-key secret these protected records depend on is missing or was regenerated; recording is refused (fail closed) — the secret is not silently rotated");
            file = file with { ContentKeyId = key.KeyId };
            log = file.Logs.First(l => l.RepoKey == repoKey && l.RunId == runId);
            string kind = (string?)payload["kind"] ?? "";
            string text = (string?)payload["text"] ?? "";
            contentKeyHash = AmendmentContentKey.KeyedHash(key.Secret, kind, text);
            textBytes = AmendmentContentKey.Utf8ByteLength(text);
            disclosureDigest = (string?)payload["disclosure_digest"];
            contentKeyScheme = AmendmentContentKey.Scheme;
        }
        int seq = log.Records.Count + 1;
        // Phase 5 F-i2-5: the reviewer-visible representation the custodian produced and the operator confirmed, held with
        // the record; its digest is the one the payload binds (a mismatch is a fault: nothing is recorded).
        string? disclosureText = recordKind == "amendment" ? (string?)args["disclosureText"] : null;
        if (disclosureText is not null && Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(disclosureText))) != disclosureDigest)
            throw new InvalidOperationException("the held redaction does not hash to the disclosure digest the record binds; nothing was recorded");
        // Phase 5 OI-1: an amendment the custodian redacted is recorded only with its read disclosure held and intact.
        if (recordKind == "amendment" && (string?)payload["read_disclosure_digest"] is { } readDisclosureSha)
            RequireHeldReadDisclosure(repoKey, runId, readDisclosureSha);
        var entry = new UserRecordEntry(
            RecordId: Guid.NewGuid().ToString(), Seq: seq, RecordKind: recordKind, Payload: (JsonObject)payload.DeepClone(),
            ContentKeyHash: contentKeyHash, TextBytes: textBytes, DisclosureDigest: disclosureDigest,
            RecordedBy: new RecordedBy("user", "custodian_operator", Platform.OperatorAssurance, proof ?? digest, requestId),
            RequestId: requestId, RecordedAt: NowIso(), ContentKeyScheme: contentKeyScheme, DisclosureText: disclosureText);
        var updated = log with { Revision = log.Revision + 1, Records = [.. log.Records, entry] };
        file.Logs[file.Logs.IndexOf(log)] = updated;
        WriteUserRecords(file);
        Audit($"user_record committed kind={recordKind} recordId={entry.RecordId} seq={seq} repoKey={repoKey} runId={runId} revision={updated.Revision} requestId={requestId} assurance={Platform.OperatorAssurance}");
        return new JsonObject { ["recordId"] = entry.RecordId, ["seq"] = seq, ["revision"] = updated.Revision, ["recordKind"] = recordKind };
    }

    /// <summary>The per-run user-record log for (repository, run), projected for the caller's surface.
    /// The OPERATOR surface receives the complete records (full note / amendment text). The IMPLEMENTER
    /// surface receives an allowlisted STRUCTURAL projection only: never a raw note or amendment text — for
    /// an amendment, the content-equivalence hash, the original byte length and the redacted-artifact
    /// digest the derivation and review presentation need. <paramref name="operatorView"/> selects.</summary>
    /// <summary>The sections <c>list_user_records</c> returns when the request names none (today's response).</summary>
    internal static readonly IReadOnlySet<string> DefaultSections = new HashSet<string>(StringComparer.Ordinal) { "user", "loop" };
    internal static readonly IReadOnlySet<string> AllSections = new HashSet<string>(StringComparer.Ordinal) { "user", "loop", "run", "config", "derivation" };
    /// <summary>Phase 5 F-i2-5: sections served on the operator surface only (a request may name them besides <see cref="AllSections"/>).</summary>
    internal static readonly IReadOnlySet<string> OperatorSections = new HashSet<string>(StringComparer.Ordinal) { "snapshot" };

    /// <summary>P3.4C-3: every section is read in ONE hold of the ledger's lock (§2.5 S6) — one consistent snapshot of
    /// the user-record log, the loop record and the run record, each with its own revision. <c>protected</c> is the
    /// custodian's selection answer (§5.4): the run is protected when the custodian holds its loop record OR its run
    /// record.</summary>
    internal JsonObject ListUserRecords(string repositoryRoot, string runId, bool operatorView, IReadOnlySet<string>? sections = null, string? runJsonBase64 = null)
    {
        ValidateRunId(runId);
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        IReadOnlySet<string> want = sections ?? DefaultSections;
        // Phase 5 F-i2-5: the snapshot section is the operator's view of the run's held structure (decide on a host where
        // the operator cannot read the implementer's run store); the implementer surface has its own derivation.
        if (want.Contains("snapshot") && !operatorView)
            throw new CustodianRefusal(ErrorCodes.CallerNotAuthorized, "the snapshot section is served on the operator surface only");
        JsonObject listed = ListSections(id, runId, operatorView, want);
        // P3.4C-5 Increment 3 (§5.1): the derivation is measured and computed OUTSIDE the lock (§2.4), after the sections
        // above; it carries its own revision vector.
        if (want.Contains("derivation")) listed["derivation"] = DerivationSection(repositoryRoot, runId, runJsonBase64);
        return listed;
    }

    private JsonObject ListSections(RepoIdentity id, string runId, bool operatorView, IReadOnlySet<string> want)
    {
        string repoKey = id.Key;
        lock (EnterGate())
        {
            var result = new JsonObject();
            if (want.Contains("user"))
            {
                UserRecordLog? log = ReadUserLog(repoKey, runId);
                var arr = new JsonArray();
                if (log is not null)
                    foreach (UserRecordEntry e in log.Records)
                        arr.Add(operatorView ? OperatorProjection(e) : ImplementerProjection(e));
                result["governed"] = log is not null;
                result["revision"] = log?.Revision ?? 0;
                result["logDigest"] = UserLogDigest(repoKey, runId);
                result["records"] = arr;
                // P3.4C-3 (§2.4 U4): the revision recovery ran at; earlier waivers and deferrals lapse on a run whose
                // loop is not terminal until the operator re-confirms them (null: no recovery touched this log).
                result["recoveredAtRevision"] = log?.RecoveredAtRevision;
            }
            bool hasLoop = Read().Loops!.Any(l => l.RepoKey == repoKey && l.RunId == runId);
            result["protected"] = hasLoop || ReadRun(repoKey, runId) is not null;
            // P3.4C-2 (contract §6): the run's loop record from the LEDGER, with its OWN revision — the sections come
            // from different stores and no revision covers another.
            if (want.Contains("loop")) result["loop"] = LoopSection(repoKey, runId, operatorView);
            if (want.Contains("run")) result["run"] = RunSection(repoKey, runId, operatorView);
            // P3.4C-4 (§3.3): the repository's configuration record and the global records, read in this same hold.
            if (want.Contains("config")) result["config"] = ConfigSection(repoKey, operatorView);
            // Phase 5 F-i2-5: the run's held records scrubbed as the protected derivation reads them (§A.5: user records in
            // their implementer projection, no text), from this same hold, so its revision vector matches the sections
            // above. Null: the custodian holds no run record.
            if (want.Contains("snapshot")) result["snapshot"] = ReadRun(repoKey, runId) is { } run ? DerivationSnapshot(id, run, null) : null;
            return result;
        }
    }

    /// <summary>Operator projection: the complete record (full text), plus the custodian's trusted
    /// provenance, ordering and derived metadata.</summary>
    private static JsonObject OperatorProjection(UserRecordEntry e)
    {
        var o = (JsonObject)e.Payload.DeepClone();
        o["recordId"] = e.RecordId;
        o["seq"] = e.Seq;
        o["recordKind"] = e.RecordKind;
        o["recorded_by"] = RecordedByJson(e.RecordedBy);
        o["recorded_at"] = e.RecordedAt;
        if (e.ContentKeyHash is not null) o["contentKeyHash"] = e.ContentKeyHash;
        if (e.TextBytes is not null) o["textBytes"] = e.TextBytes;
        if (e.DisclosureDigest is not null) o["disclosureDigest"] = e.DisclosureDigest;
        if (e.DisclosureText is not null) o["disclosureText"] = e.DisclosureText;
        return o;
    }

    /// <summary>Implementer projection: an INDEPENDENT allowlist — only the fields the protected derivation
    /// and review presentation need, built field by field (never "serialize the record and drop two keys").
    /// The raw decision note and amendment text are never included.</summary>
    private static JsonObject ImplementerProjection(UserRecordEntry e)
    {
        JsonObject p = e.Payload;
        var o = new JsonObject
        {
            ["recordId"] = e.RecordId,
            ["seq"] = e.Seq,
            ["recordKind"] = e.RecordKind,
            ["kind"] = (string?)p["kind"] ?? "",
            ["recorded_by"] = RecordedByJson(e.RecordedBy),
            ["recorded_at"] = e.RecordedAt,
            ["request_digest"] = (string?)p["request_digest"],
            ["source_id"] = SourceIdOf(p),
        };
        if (e.RecordKind == "decision")
        {
            o["thread_id"] = (string?)p["thread_id"];
            o["current_item_id"] = (string?)p["current_item_id"];
            o["covered_items"] = CloneArray(p["covered_items"]);
            o["supersedes"] = CloneArray(p["supersedes"]);
            o["decided_against"] = p["decided_against"]?.DeepClone();
            o["context"] = p["context"]?.DeepClone();
        }
        else
        {
            o["relates_to"] = CloneArray(p["relates_to"]);
            o["replaces"] = (string?)p["replaces"];
            o["contentKeyHash"] = e.ContentKeyHash;
            o["textBytes"] = e.TextBytes;
            o["disclosureDigest"] = e.DisclosureDigest;
            // Phase 5 F-i2-5: the reviewer-visible representation the custodian holds (never the raw text): a review
            // presents it when the run store has no artifact of that digest.
            if (e.DisclosureText is not null) o["disclosureText"] = e.DisclosureText;
        }
        return o;
    }

    private static JsonObject RecordedByJson(RecordedBy r) => new()
    {
        ["role"] = r.Role, ["channel"] = r.Channel, ["assurance"] = r.Assurance, ["proof_digest"] = r.ProofDigest, ["request_id"] = r.RequestId,
    };
    private static string? SourceIdOf(JsonObject p) => p["source"] is JsonObject s ? (string?)s["source_id"] : null;
    private static JsonArray CloneArray(JsonNode? n) => n is JsonArray a ? (JsonArray)a.DeepClone() : [];

    private static void ValidateRunId(string runId)
    {
        if (runId.Length is < 1 or > 128 || !runId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new ArgumentException("runId must be 1..128 chars of [A-Za-z0-9-_]");
    }

    /// <summary>A request id the ledger persists as an idempotency key (and writes to the audit log) must be a
    /// safe token, like an intent's: no separator, control character or newline can enter the store or forge
    /// an audit line.</summary>
    private static void ValidateRequestId(string requestId)
    {
        if (requestId.Length is < 1 or > 128 || !requestId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new ArgumentException("request id must be 1..128 chars of [A-Za-z0-9-_]");
    }

    private UserRecordLog? ReadUserLog(string repoKey, string runId) => ReadUserRecords().Logs.FirstOrDefault(l => l.RepoKey == repoKey && l.RunId == runId);

    /// <summary>The digest of the per-run log the operator was shown: its revision and the ordered record
    /// ids. Any append (revision bump) changes it, so a concurrent commit refuses the stale one.</summary>
    private string UserLogDigest(string repoKey, string runId)
    {
        UserRecordLog? log = ReadUserLog(repoKey, runId);
        var ids = new JsonArray((log?.Records ?? []).Select(r => (JsonNode)r.RecordId).ToArray());
        return Digest.Sha256Hex(Digest.Canonical(new JsonObject { ["repoKey"] = repoKey, ["runId"] = runId, ["revision"] = log?.Revision ?? 0, ["records"] = ids }));
    }

    private static UserRecordsFile ReadUserRecords()
    {
        if (!File.Exists(StorePaths.UserRecordsPath)) return new UserRecordsFile(StoreFormat.FileVersion, []);
        UserRecordsFile f = JsonSerializer.Deserialize<UserRecordsFile>(File.ReadAllText(StorePaths.UserRecordsPath), Json) ?? new UserRecordsFile(StoreFormat.FileVersion, []);
        StoreFormat.RequireFileVersion("user-records.json", f.Version); // Phase 6 L-1
        return f;
    }

    private static void WriteUserRecords(UserRecordsFile file) => AtomicWrite(StorePaths.UserRecordsPath, JsonSerializer.Serialize(file, Json));

    /// <summary>The "state shown" a prepared action's commit re-derives, action-aware: grants for a
    /// grant/revoke, the per-run user-record log (and a protected decision's covered items) for a user_record.</summary>
    private string CurrentStateDigest(string action, JsonObject args, string repoKey)
        => action == "user_record" ? UserRecordStateDigest(args, repoKey)
         : action == ConfigRecordAction ? ConfigStateDigest(ReadConfigRecords(), args)
         : StateDigestForRepo(repoKey);

    /// <summary>Does <paramref name="canonicalPath"/> still resolve to <paramref name="repoKey"/>?</summary>
    private static bool StillTheSameDirectory(string canonicalPath, string repoKey)
    {
        try { return RepoIdentities.Resolve(canonicalPath).Key == repoKey; }
        catch (ArgumentException) { return false; }
    }

    // ---- recovery: drop expired, uncommitted intents at startup ----

    internal int SweepExpiredIntents()
    {
        lock (EnterGate())
        {
            if (!Directory.Exists(StorePaths.IntentsDir)) return 0;
            int n = 0;
            foreach (string f in Directory.EnumerateFiles(StorePaths.IntentsDir, "*.json"))
            {
                try
                {
                    var o = JsonNode.Parse(File.ReadAllText(f)) as JsonObject;
                    string? exp = (string?)o?["expiresAt"];
                    if (exp is null || DateTime.Parse(exp).ToUniversalTime() < DateTime.UtcNow) { File.Delete(f); n++; }
                }
                catch { try { File.Delete(f); n++; } catch { /* leave it */ } }
            }
            return n;
        }
    }

    // ---- state / persistence ----

    private static Grant? GrantByRequestId(LedgerFile file, string requestId) => file.Grants.FirstOrDefault(g => g.RequestId == requestId);

    private string StateDigestForRepo(string repoKey)
    {
        LedgerFile file = Read();
        var now = DateTime.UtcNow;
        var relevant = file.Grants.Where(g => g.RepoKey == repoKey)
            .Select(g => new JsonObject { ["id"] = g.GrantId, ["used"] = g.LoopsUsed, ["total"] = g.LoopsTotal, ["revoked"] = g.RevokedAt is not null })
            .ToArray();
        var arr = new JsonArray(relevant.Cast<JsonNode>().ToArray());
        return Digest.Sha256Hex(Digest.Canonical(new JsonObject { ["repoKey"] = repoKey, ["grants"] = arr }));
    }

    private static void Prune(LedgerFile file, DateTime now)
        => file.Grants.RemoveAll(g => DateTime.Parse(g.RevokedAt ?? g.ExpiresAt).ToUniversalTime() < now.AddDays(-1));

    internal LedgerFile Read()
    {
        if (!File.Exists(StorePaths.LedgerPath)) return new LedgerFile(StoreFormat.FileVersion, [], []);
        LedgerFile f = JsonSerializer.Deserialize<LedgerFile>(File.ReadAllText(StorePaths.LedgerPath), Json) ?? new LedgerFile(StoreFormat.FileVersion, [], []);
        StoreFormat.RequireFileVersion("ledger.json", f.Version); // Phase 6 L-1
        // A ledger written before P3.4C-2 has no loops section; present it as an empty one.
        return f.Loops is null ? f with { Loops = [] } : f;
    }

    private static void Write(LedgerFile file) => AtomicWrite(StorePaths.LedgerPath, JsonSerializer.Serialize(file, Json));

    /// <summary>Every store write goes through the write-through replacement (P3.4C-3, contract §2.4).</summary>
    private static void AtomicWrite(string path, string content) => DurableStore.Replace(path, content);

    private static void TryDelete(string path) { try { File.Delete(path); } catch { /* best effort */ } }

    private static void Audit(string line)
    {
        try { File.AppendAllText(StorePaths.AuditPath, $"{NowIso()} {line}\n"); } catch { /* best effort */ }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> RefusalAudited = new(StringComparer.Ordinal);

    /// <summary>P3.4C-3 (§3.4(4)): one bounded audit line for a refused transition — validated tokens and the code only,
    /// never the payload — at most once per (run, code) per minute. Returns whether a line was written.</summary>
    internal static bool AuditRefusal(string op, string? kind, string caller, int? clientPid, string? runId, string? loopId, string code)
    {
        string key = $"{runId ?? "-"}|{code}";
        DateTime now = DateTime.UtcNow;
        // Lock-free compare-and-set: exactly one caller per (run, code) per minute writes the line.
        while (true)
        {
            if (RefusalAudited.TryGetValue(key, out DateTime last))
            {
                if (now - last < TimeSpan.FromMinutes(1)) return false;
                if (RefusalAudited.TryUpdate(key, now, last)) break;
            }
            else if (RefusalAudited.TryAdd(key, now)) break;
        }
        if (RefusalAudited.Count > 10_000)
            foreach (KeyValuePair<string, DateTime> old in RefusalAudited.Where(kv => now - kv.Value >= TimeSpan.FromMinutes(1)).ToList())
                RefusalAudited.TryRemove(old);
        string safeCode = new string(code.Where(c => char.IsAsciiLetterOrDigit(c) || c == '_').Take(64).ToArray());
        Audit($"refused op={op} kind={kind ?? "-"} code={safeCode} caller={caller} clientPid={clientPid?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-"} runId={runId ?? "-"} loopId={loopId ?? "-"}");
        return true;
    }

    /// <summary>P3.4C-5 (§A.2, N5-19): one bounded audit line for a refused helper-channel event (an authority-shaped or
    /// unknown frame, an uncorrelated frame, a caller that is not the helper) — sanitized tokens only, never a payload,
    /// coalesced like <see cref="AuditRefusal"/> to one line per (event, frame type) per minute.</summary>
    internal static bool AuditHelperChannel(string evt, string? frameType, int? clientPid)
    {
        static string Token(string? s) => s is null ? "-" : new string(s.Where(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-').Take(48).ToArray());
        string safeEvt = Token(evt), safeType = Token(frameType);
        string key = $"helper|{safeEvt}|{safeType}";
        DateTime now = DateTime.UtcNow;
        if (RefusalAudited.TryGetValue(key, out DateTime last) && now - last < TimeSpan.FromMinutes(1)) return false;
        RefusalAudited[key] = now;
        Audit($"refused channel=helper event={safeEvt} frame={safeType} clientPid={clientPid?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-"}");
        return true;
    }
}
