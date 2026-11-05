using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 4 Increment 3 (contract §3.5, N4-6): who can confirm. Only the operator surface prepares or commits an owner's
/// decision on a held proposal; on the implementer surface a confirmation-shaped request or field is refused — the decision
/// ops are operator-only (CALLER_NOT_AUTHORIZED, nothing prepared) and an application's begin carries no confirmation field
/// (MALFORMED_REQUEST: an unknown key is refused, never ignored). The ledger behaviour itself is in the shared run corpus.
/// </summary>
internal static partial class RunSelfTest
{
    private static int FixDecisionSurfaceCases(string repos)
    {
        int failed = 0;
        var core = new CustodianCore("cust-selftest");
        string repo = Directory.CreateDirectory(Path.Combine(repos, "FixSurface")).FullName.Replace('\\', '/');
        Request Req(string op, JsonObject args) => new(1, Rid("fixsurface"), op, args);

        Response prepare = core.Handle(CallerClass.Implementer, Req("prepare_fix_decision", new JsonObject { ["repositoryRoot"] = repo, ["runId"] = "r1", ["operationId"] = "fop-1-aaaaaaaaaaaa", ["decision"] = "confirm" }), null, 4242);
        failed += Check("N4-6: prepare_fix_decision on the implementer surface → CALLER_NOT_AUTHORIZED (only the operator surface confirms)",
            !prepare.Ok && prepare.Code == ErrorCodes.CallerNotAuthorized);
        Response commit = core.Handle(CallerClass.Implementer, Req("commit", new JsonObject { ["authorizationRequestId"] = "any" }), null, 4242);
        failed += Check("N4-6: commit on the implementer surface → CALLER_NOT_AUTHORIZED", !commit.Ok && commit.Code == ErrorCodes.CallerNotAuthorized);
        Response forged = core.Handle(CallerClass.Operator, Req("prepare_fix_decision", new JsonObject { ["repositoryRoot"] = repo, ["runId"] = "r1", ["operationId"] = "fop-1-aaaaaaaaaaaa", ["decision"] = "confirm", ["confirmed"] = true }), null);
        failed += Check("a decision request carrying an authority-shaped field → MALFORMED_REQUEST (refused, never ignored)", !forged.Ok && forged.Code == ErrorCodes.MalformedRequest);
        Response applyWithConfirmation = core.Handle(CallerClass.Implementer, Req("run_transition", new JsonObject
        {
            ["repositoryRoot"] = repo, ["runId"] = "r1", ["kind"] = "op_begin",
            ["fields"] = new JsonObject { ["operationKind"] = "apply", ["fixOperationId"] = "fop-1-aaaaaaaaaaaa", ["proposalDigest"] = Hex, ["confirmationId"] = "c-1" },
        }), null, 4242);
        failed += Check("N4-6: an application's begin carrying a confirmation field → MALFORMED_REQUEST (the custodian holds the confirmation)",
            !applyWithConfirmation.Ok && applyWithConfirmation.Code == ErrorCodes.MalformedRequest);
        Response render = core.Handle(CallerClass.Helper, Req("render_fix_proposal", new JsonObject { ["repositoryRoot"] = repo, ["runId"] = "r1", ["operationId"] = "fop-1-aaaaaaaaaaaa" }), null);
        failed += Check("the helper class is served no rendering (CALLER_NOT_AUTHORIZED)", !render.Ok && render.Code == ErrorCodes.CallerNotAuthorized);

        // Step 7.1 (S1, S6): the listing is the operator's only; a guided selection names all three expected values or none.
        foreach ((CallerClass who, string name) in new[] { (CallerClass.Implementer, "implementer"), (CallerClass.Helper, "helper") })
        {
            Response listed = core.Handle(who, Req("list_fix_proposals", new JsonObject()), null, 4242);
            failed += Check($"7.1 S1: list_fix_proposals on the {name} surface → CALLER_NOT_AUTHORIZED, nothing listed",
                !listed.Ok && listed.Code == ErrorCodes.CallerNotAuthorized && listed.Data is null);
        }
        Response operatorList = core.Handle(CallerClass.Operator, Req("list_fix_proposals", new JsonObject()), null);
        failed += Check("7.1 S1: list_fix_proposals on the operator surface is served", operatorList.Ok && (string?)operatorList.Data?["schema"] == GrantLedger.FixListingSchema);
        Response listForged = core.Handle(CallerClass.Operator, Req("list_fix_proposals", new JsonObject { ["includeNarrative"] = true }), null);
        failed += Check("7.1: a listing request with an unknown field → MALFORMED_REQUEST", !listForged.Ok && listForged.Code == ErrorCodes.MalformedRequest);
        JsonObject Prep(JsonObject extra)
        {
            var a = new JsonObject { ["repositoryRoot"] = repo, ["runId"] = "r1", ["operationId"] = "fop-1-aaaaaaaaaaaa", ["decision"] = "confirm" };
            foreach ((string k, JsonNode? v) in extra) a[k] = v?.DeepClone();
            return a;
        }
        string key = RepoIdentities.Resolve(repo).Key;
        foreach ((string label, JsonObject extra) in new (string, JsonObject)[]
        {
            ("one of three", new JsonObject { ["expectedRepoKey"] = key }),
            ("two of three", new JsonObject { ["expectedRepoKey"] = key, ["expectedProposalDigest"] = Hex }),
            ("a number", new JsonObject { ["expectedRepoKey"] = key, ["expectedProposalDigest"] = 7, ["expectedRenderingDigest"] = Hex }),
            ("a null", new JsonObject { ["expectedRepoKey"] = null, ["expectedProposalDigest"] = Hex, ["expectedRenderingDigest"] = Hex }),
            ("upper-case hex", new JsonObject { ["expectedRepoKey"] = key, ["expectedProposalDigest"] = Hex.ToUpperInvariant(), ["expectedRenderingDigest"] = Hex }),
            ("a key of another scheme", new JsonObject { ["expectedRepoKey"] = "legacy-" + key, ["expectedProposalDigest"] = Hex, ["expectedRenderingDigest"] = Hex }),
        })
        {
            Response r = core.Handle(CallerClass.Operator, Req("prepare_fix_decision", Prep(extra)), null);
            failed += Check($"7.1 S6: prepare_fix_decision with {label} of the expected values → MALFORMED_REQUEST", !r.Ok && r.Code == ErrorCodes.MalformedRequest);
        }
        Response implementerSelection = core.Handle(CallerClass.Implementer, Req("prepare_fix_decision", Prep(new JsonObject { ["expectedRepoKey"] = key })), null, 4242);
        failed += Check("7.1: a malformed selection from the implementer surface is refused as the caller first (CALLER_NOT_AUTHORIZED)",
            !implementerSelection.Ok && implementerSelection.Code == ErrorCodes.CallerNotAuthorized);
        return failed;
    }
}
