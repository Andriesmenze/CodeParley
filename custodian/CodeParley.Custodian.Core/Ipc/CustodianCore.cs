using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ipc;

/// <summary>
/// Dispatches a classified request to the ledger. The caller class (from the OS, not the request)
/// decides what is allowed: operator actions create/commit/revoke authority; implementer actions only
/// consume a granted loop or read. An operator action attempted on the implementer surface is refused
/// (invariant I-1). The core never trusts an actor/role/authority field in the request body — there is
/// none to trust.
/// </summary>
internal sealed class CustodianCore
{
    private readonly GrantLedger _ledger;
    private readonly HelperBroker? _broker;
    private readonly Principal? _helper;

    /// <summary><paramref name="broker"/> and <paramref name="helper"/> (P3.4C-5): the helper channel and the helper's SID,
    /// when a helper is installed; without them every helper measurement refuses (HELPER_UNAVAILABLE). With them and the
    /// bound session's user (<paramref name="reader"/>, the implementer account), protected reviews are captured by the
    /// custodian through the helper and published to that user read-only (§3.1, §3.2).</summary>
    internal CustodianCore(string custodianId, HelperBroker? broker = null, Principal? helper = null, Principal? reader = null, (Principal Readers, string? Name)? repositoryReaders = null)
    {
        _ledger = new GrantLedger(custodianId);
        _ledger.SweepExpiredIntents(); // recovery: uncommitted, expired intents are not authority
        _broker = broker;
        _helper = helper;
        if (broker is not null && helper is not null && reader is not null)
        {
            _ledger.AttachCapture(new HelperCaptureRunner(broker), helper, reader);
            // P3.4C-5 Increment 3: the custodian's measurements (checks, the derivation, a spend's re-measurement).
            _ledger.AttachMeasurement(new HelperMeasurementRunner(broker));
            // P3.4C-5 Increment 4 (N5-8): the helper reads repositories through its group (the host resolves it); a repository
            // without that grant is refused with the operator's remedy.
            if (repositoryReaders is { } r) _ledger.AttachRepositoryReaders(r.Readers, r.Name);
        }
    }

    /// <summary>P3.4C-3 (§2.4): the startup recovery, run before the pipe server starts. Throws when recovery cannot
    /// complete — the service then serves nothing (fail closed). P3.4C-5 (N5-18): then, at EVERY start, every persisted
    /// measuring operation is interrupted and the export root swept. Phase 6 (L-5): an installer restore marker the host
    /// read and validated starts the restored epoch.</summary>
    internal RecoveryOutcome StartupRecovery(IBootIdentity boot, RestoreMarker? restore = null)
    {
        RecoveryOutcome outcome = _ledger.StartupRecovery(boot, restore);
        _ledger.ReconcileCapturesAtStart();
        return outcome;
    }

    /// <summary>Record a graceful stop in the session marker (a diagnostic only).</summary>
    internal void MarkCleanStop() => _ledger.MarkCleanStop();

    /// <summary>The exact argument keys each operation accepts. Any other key in <c>args</c> — including an
    /// authority-shaped field such as role/assurance/actor — is REJECTED, never ignored (TD amendment 2a):
    /// there is no field a caller could set that the custodian would read as authority, and sending one is
    /// treated as a malformed request rather than silently dropped.</summary>
    private static readonly IReadOnlyDictionary<string, string[]> AllowedArgs = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["ping"] = [],
        ["list_grants"] = [],
        ["service_identity"] = [],
        ["consume_loop"] = ["repositoryRoot", "runId"],
        ["prepare_grant"] = ["repositoryRoot", "loops", "minutes"],
        ["prepare_revoke"] = ["repositoryRoot"],
        ["commit"] = ["authorizationRequestId"],
        // P3.4C-1: protected user decisions & amendments. `payload` is a nested object (its own keys are
        // validated by the ledger, which rejects any provenance/ordering/identifier field).
        ["prepare_user_record"] = ["repositoryRoot", "runId", "recordKind", "payload", "baseRevision"],
        // P3.4C-3: an optional `sections` (["user","loop","run"]; default ["user","loop"], today's response). P3.4C-5
        // Increment 3: the `derivation` section needs `runJson` (the run's run.json bytes, base64; verified by digest).
        ["list_user_records"] = ["repositoryRoot", "runId", "sections", "runJson"],
        // Phase 5 F-i2-5: the bytes of a baseline capture or response disclosure record the run already binds by digest.
        ["hold_evidence"] = ["repositoryRoot", "runId", "sha256", "part", "parts", "data"],
        // P3.4C-4: the operator's configuration changes (set / revoke / reconfirm), committed by the existing `commit`.
        ["prepare_config_record"] = ["repositoryRoot", "recordKind", "action", "recordId", "payload", "baseRevision"],
        // P3.4C-2: the custodian-computed loop lifecycle. `fields` is a nested object whose keys the ledger
        // allowlists per kind (Ledger/LoopRequest.cs); the request's envelope id is the idempotency key.
        ["loop_transition"] = ["repositoryRoot", "runId", "loopId", "epoch", "baseLoopRevision", "kind", "fields"],
        // P3.4C-3: the custodian-computed run lifecycle and evidence (seven closed kinds). `fields` is allowlisted per
        // kind (Ledger/RunRequest.cs); the request's envelope id is the idempotency key.
        ["run_transition"] = ["repositoryRoot", "runId", "kind", "fields"],
        // P3.4C-5 Increment 1 (Amendment A §A.7): an operator-only DIAGNOSTIC — a real capture and a real derivation through
        // the helper on a configured repository; it commits nothing and creates no authority.
        ["helper_check"] = ["repositoryRoot", "runId", "target", "keep"],
        // Phase 4 Increment 3 (§3.5): the owner's decision on a held proposal (operator only; committed by `commit`), and the
        // custodian's rendering of it (read only, both surfaces: `fix show` and the originating session's inspection).
        ["prepare_fix_decision"] = ["repositoryRoot", "runId", "operationId", "decision"],
        ["render_fix_proposal"] = ["repositoryRoot", "runId", "operationId"],
    };

    /// <summary>Serve one classified request. <paramref name="clientProcessId"/> is the process connected to
    /// the pipe as the system reports it — correlation evidence for the loop-binding check only (D7).</summary>
    private static JsonObject Pong(CallerClass caller)
    {
        JsonObject id = CodeParley.Custodian.Cli.BuildIdentity.Of(OperatingSystem.IsWindows() ? "windows" : "linux");
        return new JsonObject { ["pong"] = true, ["caller"] = caller.ToString().ToLowerInvariant(), ["version"] = id["version"]?.DeepClone(), ["build"] = id["build"]?.DeepClone(), ["protocol"] = id["protocol"]?.DeepClone(), ["host"] = id["host"]?.DeepClone() };
    }

    internal Response Handle(CallerClass caller, Request req, string? clientProofDigest, int? clientProcessId = null)
    {
        try
        {
            // P3.4C-5 (§A.2, N5-19): the helper class is served measurement requests on the helper channel only — never an
            // operation here, authority-creating or not. Defence in depth: the helper pipe never routes to this
            // dispatcher, and the implementer/operator pipes' DACLs and classifier keep the helper SID out.
            if (caller == CallerClass.Helper)
            {
                GrantLedger.AuditRefusal(OpToken(req.Op), null, "helper", clientProcessId, null, null, ErrorCodes.CallerNotAuthorized);
                return Response.Fail(ErrorCodes.CallerNotAuthorized, "the helper service is served measurement requests on the helper channel only");
            }
            if (!AllowedArgs.TryGetValue(req.Op, out string[]? allowed))
                return Response.Fail(ErrorCodes.UnknownOperation, $"unknown operation '{req.Op}'");
            foreach (string key in req.Args.Select(kv => kv.Key))
                if (!allowed.Contains(key))
                    return Response.Fail(ErrorCodes.MalformedRequest, $"unexpected argument '{key}' for '{req.Op}' (no field conveys authority; unknown fields are refused, not ignored)");

            return req.Op switch
            {
                // Phase 6 Increment 3: the running service's release, build and protocol, for status and doctor (the executable's own
                // metadata; no authority, no store read).
                "ping" => Response.Success(Pong(caller)),
                // Operator-only: it runs the service's own token facts AND write probes (store + fixed
                // ambient targets). Operator-gating keeps the implementer from triggering service-side
                // writes, and the write probes are the TD P3.4B-live verification instrument (not authority).
                "service_identity" => Operator(caller, Platform.ServiceIdentity),
                "list_grants" => Response.Success(_ledger.ListGrants()),
                "consume_loop" => Implementer(caller, () => _ledger.ConsumeLoop(Str(req, "repositoryRoot"), Str(req, "runId"), req.RequestId)),
                "prepare_grant" => Operator(caller, () => Prepared(_ledger.PrepareGrant(Str(req, "repositoryRoot"), Int(req, "loops"), Int(req, "minutes"), req.RequestId))),
                "prepare_revoke" => Operator(caller, () => Prepared(_ledger.PrepareRevoke(Str(req, "repositoryRoot"), req.RequestId))),
                "commit" => Operator(caller, () => _ledger.Commit(Str(req, "authorizationRequestId"), clientProofDigest)),
                // P3.4C-1: recording a user decision/amendment is operator-only; reading the per-run log is
                // served to the operator (full records) and the implementer (structural projection), the
                // projection chosen by the OS caller class — never by the request (D-C').
                "prepare_user_record" => Operator(caller, () => Prepared(_ledger.PrepareUserRecord(Str(req, "repositoryRoot"), Str(req, "runId"), Str(req, "recordKind"), Obj(req, "payload"), Int(req, "baseRevision"), req.RequestId))),
                "prepare_config_record" => Operator(caller, () => Prepared(_ledger.PrepareConfigRecord(OptStr(req, "repositoryRoot"), StrictStr(req, "recordKind"), StrictStr(req, "action"),
                    OptStr(req, "recordId"), OptObj(req, "payload"), StrictInt(req, "baseRevision"), req.RequestId))),
                "list_user_records" => caller is CallerClass.Operator or CallerClass.Implementer
                    ? Response.Success(_ledger.ListUserRecords(Str(req, "repositoryRoot"), Str(req, "runId"), operatorView: caller == CallerClass.Operator, Sections(req), OptStr(req, "runJson")))
                    : Response.Fail(ErrorCodes.CallerNotAuthorized, "not an authorized caller"),
                "hold_evidence" => Implementer(caller, () => _ledger.HoldEvidence(StrictStr(req, "repositoryRoot"), StrictStr(req, "runId"), StrictStr(req, "sha256"), StrictInt(req, "part"), StrictInt(req, "parts"), StrictStr(req, "data"))),
                "loop_transition" => Audited(caller, req, clientProcessId, () => LoopTransition(caller, req, clientProofDigest, clientProcessId)),
                "run_transition" => Audited(caller, req, clientProcessId, () => RunTransition(caller, req, clientProofDigest, clientProcessId)),
                "prepare_fix_decision" => Operator(caller, () => Prepared(_ledger.PrepareFixDecision(StrictStr(req, "repositoryRoot"), StrictStr(req, "runId"), StrictStr(req, "operationId"), StrictStr(req, "decision"), req.RequestId))),
                "render_fix_proposal" => caller is CallerClass.Operator or CallerClass.Implementer
                    ? Response.Success(_ledger.RenderFixProposal(StrictStr(req, "repositoryRoot"), StrictStr(req, "runId"), StrictStr(req, "operationId")))
                    : Response.Fail(ErrorCodes.CallerNotAuthorized, "not an authorized caller"),
                "helper_check" => Operator(caller, () => _broker is null || _helper is null
                    ? throw new CustodianRefusal(ErrorCodes.HelperUnavailable, $"no helper is installed; the operator installs it with {OperatorWording.InstallHelper} and restarts the custodian")
                    : _ledger.HelperCheck(_broker, _helper, Str(req, "repositoryRoot"), OptStr(req, "runId"), OptObj(req, "target"), req.Args["keep"] is JsonValue k && k.TryGetValue(out bool keep) && keep)),
                _ => Response.Fail(ErrorCodes.UnknownOperation, $"unknown operation '{req.Op}'"),
            };
        }
        catch (Exception e) { return Classify(e); }
    }

    /// <summary>P3.4C-3 (§3.4(4), observability carried from P3.4C-2): every refused <c>loop_transition</c> or
    /// <c>run_transition</c> — including a <c>wake_consume</c> answered without authorization — appends one bounded audit
    /// line (code, kind, caller class, client pid, run and loop id; never the payload), coalesced to at most one line per
    /// (run, code) per minute.</summary>
    private static Response Audited(CallerClass caller, Request req, int? clientProcessId, Func<Response> act)
    {
        Response resp;
        try { resp = act(); }
        catch (Exception e) { resp = Classify(e); }
        string? code = !resp.Ok ? resp.Code : resp.Data?["refusal"] is JsonValue v && v.TryGetValue(out string? c) ? c : null;
        if (code is not null)
        {
            string? kind = req.Args["kind"] is JsonValue k && k.TryGetValue(out string? ks) && (LoopKinds.All.Contains(ks!) || RunKinds.All.Contains(ks!)) ? ks : null;
            string? runId = req.Args["runId"] is JsonValue r && r.TryGetValue(out string? rs) && IsToken(rs!) ? rs : null;
            string? loopId = req.Args["loopId"] is JsonValue l && l.TryGetValue(out string? ls) && Guid.TryParseExact(ls, "D", out _) ? ls : null;
            GrantLedger.AuditRefusal(req.Op, kind, caller == CallerClass.Operator ? "operator" : "implementer", clientProcessId, runId, loopId, code);
        }
        return resp;
    }

    private static bool IsToken(string s) => s.Length is >= 1 and <= 128 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>An operation name as audited: known operations by name, anything else as <c>other</c>.</summary>
    private static string OpToken(string op) => AllowedArgs.ContainsKey(op) ? op : "other";

    // P3.4C-2: the originating session drives its own loop from either surface. The per-kind rules (first
    // bind wins, operator-only resume, epochs, budgets, one-shot wakes) are the ledger's, and the caller class
    // it is given is the OS's classification of this connection — never a field of the request.
    private Response LoopTransition(CallerClass caller, Request req, string? proof, int? clientProcessId)
    {
        if (caller is not (CallerClass.Implementer or CallerClass.Operator)) return Response.Fail(ErrorCodes.CallerNotAuthorized, "not an authorized caller");
        LoopRequest parsed = LoopRequest.Parse(StrictStr(req, "runId"), StrictStr(req, "loopId"), StrictInt(req, "epoch"),
            StrictInt(req, "baseLoopRevision"), StrictStr(req, "kind"), Obj(req, "fields"), req.RequestId);
        var who = new LoopCaller(caller == CallerClass.Operator, proof, clientProcessId);
        return Response.Success(_ledger.LoopTransition(who, StrictStr(req, "repositoryRoot"), parsed));
    }

    // P3.4C-3: the engine records its run state and evidence; the per-kind caller rules (implementer-only evidence,
    // reduce-only recover/end on either surface, the bound caller, the writer) are the ledger's, and the caller class
    // is the OS's classification of this connection — never a field of the request.
    private Response RunTransition(CallerClass caller, Request req, string? proof, int? clientProcessId)
    {
        if (caller is not (CallerClass.Implementer or CallerClass.Operator)) return Response.Fail(ErrorCodes.CallerNotAuthorized, "not an authorized caller");
        RunRequest parsed = RunRequest.Parse(StrictStr(req, "runId"), StrictStr(req, "kind"), Obj(req, "fields"), req.RequestId);
        var who = new LoopCaller(caller == CallerClass.Operator, proof, clientProcessId);
        return Response.Success(_ledger.RunTransition(who, StrictStr(req, "repositoryRoot"), parsed));
    }

    /// <summary>The optional <c>sections</c> of <c>list_user_records</c>: distinct names from user/loop/run.</summary>
    private static IReadOnlySet<string>? Sections(Request r)
    {
        if (!r.Args.ContainsKey("sections")) return null;
        if (r.Args["sections"] is not JsonArray a || a.Count == 0) throw new ArgumentException("'sections' must be a non-empty array of section names");
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonNode? n in a)
        {
            string s = n is JsonValue v && v.TryGetValue(out string? x) && x is not null ? x : throw new ArgumentException("'sections' entries must be strings");
            if (!(GrantLedger.AllSections.Contains(s) || GrantLedger.OperatorSections.Contains(s)) || !set.Add(s)) throw new ArgumentException("'sections' entries must be distinct names from: user, loop, run, config, derivation, snapshot");
        }
        return set;
    }

    // consume/list are reduce-only and allowed from the implementer (and operator) surface.
    private static Response Implementer(CallerClass caller, Func<JsonObject> act)
        => caller is CallerClass.Implementer or CallerClass.Operator ? Response.Success(act())
           : Response.Fail(ErrorCodes.CallerNotAuthorized, "not an authorized caller");

    // prepare/commit/revoke are operator-only: an implementer-class caller can never create authority.
    private static Response Operator(CallerClass caller, Func<JsonObject> act)
        => caller == CallerClass.Operator ? Response.Success(act())
           : Response.Fail(ErrorCodes.CallerNotAuthorized, $"this action requires the operator surface ({Platform.OperatorSurfaceRequirement})");

    private static JsonObject Prepared(PreparedAuthorization p) => new()
    {
        ["authorizationRequestId"] = p.RequestId,
        ["action"] = p.Action,
        ["rendering"] = p.Rendering,
        ["digest"] = p.Digest,
        ["challenge"] = p.Challenge,
        ["expiresAt"] = p.ExpiresAt,
    };

    private static Response Classify(Exception e) => Response.Fail(CodeOf(e), e.Message);

    /// <summary>The error code an exception answers with (also the shared corpus runner's classification).</summary>
    internal static string CodeOf(Exception e)
    {
        string m = e.Message;
        return m switch
        {
            // First, by type: a custodian refusal carries its code structurally; a refused repository identity and
            // every other argument error can quote client-chosen text (a path, an id, a check name), so they are
            // classified by their type — never by a code their message happens to contain.
            _ when e is CustodianRefusal refusal => refusal.Code,
            _ when e is ArgumentException or FormatException => ErrorCodes.InvalidArgument,
            _ when m.Contains("REQUEST_ID_CONFLICT") => ErrorCodes.RequestIdConflict,
            _ when m.Contains("AUTHORIZATION_EXPIRED") => ErrorCodes.AuthorizationExpired,
            _ when m.Contains("AUTHORIZATION_INVALID") => ErrorCodes.AuthorizationInvalid,
            _ when m.Contains("STALE_FINDING_STATE") => ErrorCodes.StaleState,
            _ when m.Contains("LOOP_NOT_AUTHORIZED") => ErrorCodes.LoopNotAuthorized,
            _ when m.Contains("RUN_ALREADY_HAS_LOOP") => ErrorCodes.RunAlreadyHasLoop,
            _ when m.Contains("LOOP_TERMINAL") => ErrorCodes.LoopTerminal,
            _ when m.Contains("STALE_LOOP_EPOCH") => ErrorCodes.StaleLoopEpoch,
            _ when m.Contains("STALE_LOOP_STATE") => ErrorCodes.StaleLoopState,
            _ when m.Contains("UNKNOWN_OPERATION_HANDLE") => ErrorCodes.UnknownOperationHandle,
            _ => ErrorCodes.Internal,
        };
    }

    private static string Str(Request r, string key) => (string?)r.Args[key] ?? throw new ArgumentException($"missing '{key}'");
    private static int Int(Request r, string key) => (int?)r.Args[key] ?? throw new ArgumentException($"missing integer '{key}'");
    private static JsonObject Obj(Request r, string key) => r.Args[key] as JsonObject ?? throw new ArgumentException($"missing object '{key}'");

    /// <summary>An optional string argument: absent or null is null; another type is INVALID_ARGUMENT.</summary>
    private static string? OptStr(Request r, string key)
        => r.Args[key] switch { null => null, JsonValue v when v.TryGetValue(out string? s) => s, _ => throw new ArgumentException($"'{key}' must be a string") };

    /// <summary>An optional object argument: absent or null is null; another type is INVALID_ARGUMENT.</summary>
    private static JsonObject? OptObj(Request r, string key)
        => r.Args[key] switch { null => null, JsonObject o => o, _ => throw new ArgumentException($"'{key}' must be an object") };

    // Strict readers (P3.4C-2): a value of the wrong JSON type is INVALID_ARGUMENT, never coerced or an
    // internal error.
    private static string StrictStr(Request r, string key)
        => r.Args[key] is JsonValue v && v.TryGetValue(out string? s) && s is not null ? s : throw new ArgumentException($"'{key}' must be a string");
    private static int StrictInt(Request r, string key)
        => r.Args[key] is JsonValue v && v.TryGetValue(out int i) ? i : throw new ArgumentException($"'{key}' must be an integer");
}
