using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>The custodian's read of a held proposal, taken OUTSIDE the gate: the record it was read against (the fix
/// operation's status, proposal digest, boundary digest and baseline), the content it holds (re-verified against that
/// record) and its rendering; or why it cannot be read (<see cref="Problem"/>).</summary>
internal sealed record HeldProposalRead(
    string OperationId, string? Problem, string? Status, string? ProposalDigest, string? BoundaryDigest, string? BaselineDigest,
    FixRenderingResult? Rendering, JsonArray? Content);

/// <summary>A measurement taken before the gate for an application's begin, finish or reconciliation: the measured source
/// (null with the reason when it could not be measured).</summary>
internal sealed record ApplyMeasure(string? SourceId, bool Stable, string? Code, string? Detail);

/// <summary>Everything an application transition reads before the gate.</summary>
internal sealed record ApplyPre(HeldProposalRead? Held, ApplyMeasure? Measured);

/// <summary>
/// Phase 4 Increment 3 (contract §3.5–§3.6): the owner's confirmation of the custodian's rendering and the application.
///
/// <para><b>Rendering and confirmation (operator surface only).</b> <c>prepare_fix_decision</c> renders the held proposal
/// itself (<see cref="FixRendering"/>) from the baseline bytes of its published capture and the content it holds, and
/// prepares an intent bound to that rendering's digest, the proposal digest, the boundary, the baseline and the run. Its
/// <c>commit</c> renders again and refuses <c>CONFIRMATION_CONTENT_MISMATCH</c> when anything the operator was shown
/// changed. A confirmation is single use, bound to the exact rendered bytes, the proposal digest, the repository identity,
/// the run and the baseline source, and expires; a rejection closes the proposal (its content is removed).</para>
///
/// <para><b>Application (implementer surface, the bound session).</b> An <c>apply</c> operation's <c>op_begin</c> consumes
/// the confirmation — only when it exists, is unconsumed, unexpired and not rejected, no other application is in progress
/// for the repository (<c>APPLY_IN_PROGRESS</c>), the held content still renders the confirmed bytes, and the custodian's
/// own re-measurement of the primary source through its helper equals the baseline source (<c>FIX_STALE</c>; nothing is
/// consumed) — and returns the confirmed canonical content. Its <c>op_finish</c> records <c>applied</c> or
/// <c>apply_failed</c> with the custodian's post-apply measurement; a writer gone is <c>apply_interrupted</c> (an incident;
/// <c>recover</c>), never <c>applied</c>; <c>apply_reconcile</c> records what the implementer's reconciliation did.</para>
/// </summary>
internal sealed partial class GrantLedger
{
    internal const string FixDecisionAction = "fix_decision";

    /// <summary>The fix operation's statuses after its proposal: confirmed by the owner (awaiting the application), its
    /// confirmation consumed by an application, or rejected by the owner.</summary>
    internal const string FixConfirmed = "confirmed", FixConsumed = "consumed", FixDeclined = "declined";

    /// <summary>An application operation's statuses (its kind is <c>apply</c>).</summary>
    internal const string Applied = "applied", ApplyFailed = "apply_failed", ApplyInterrupted = "apply_interrupted",
        ApplyInterruptedRestored = "apply_interrupted_restored", ApplyInterruptedLeft = "apply_interrupted_left";

    // ---- the baseline tree of a review's published capture (outside the gate) ----

    /// <summary>The published export of a review re-hashed and its manifest's <c>tree</c> read — outside the gate.</summary>
    private static FixBaselineRead ReadExportTree(string reviewId, string reviewOperationId, JsonObject? reviewBegin)
    {
        if (Monitor.IsEntered(Gate)) throw new InvalidOperationException("the ledger lock is held across a baseline read"); // §2.4
        if (reviewBegin?["custodianCapture"] is not JsonObject cc || cc["retiredAt"] is not null) return new FixBaselineRead(reviewId, false, "no published capture is held for it", null);
        ExportRehash rh = RehashExport(reviewOperationId, reviewBegin);
        if (!rh.Unchanged) return new FixBaselineRead(reviewId, false, rh.Detail, null);
        try
        {
            JsonNode? manifest = JsonNode.Parse(File.ReadAllText(Path.Combine((string)cc["exportPath"]!, "review", "manifest.json")));
            if (manifest?["files"] is not JsonArray files) return new FixBaselineRead(reviewId, false, "the capture's manifest is malformed", null);
            var tree = new Dictionary<string, BaselineFile>(StringComparer.Ordinal);
            foreach (JsonNode? f in files)
            {
                if (f is not JsonObject e || e["path"] is not JsonValue pv || !pv.TryGetValue(out string? path) || e["area"] is not JsonValue av || !av.TryGetValue(out string? area)
                    || RunFields.Integer(e["size"]) is not long size || size < 0 || e["sha256"] is not JsonValue hv || !hv.TryGetValue(out string? sha)
                    || sha.Length != 64 || !sha.All(char.IsAsciiHexDigitLower))
                    return new FixBaselineRead(reviewId, false, "the capture's manifest is malformed", null);
                if (area == "tree") tree[path] = new BaselineFile(size, sha);
            }
            return new FixBaselineRead(reviewId, true, rh.Detail, tree);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return new FixBaselineRead(reviewId, false, $"the capture's manifest could not be read ({e.GetType().Name}: {Bounded(e.Message)})", null);
        }
    }

    /// <summary>The digest of the baseline a fix bound (what a confirmation and its state digest name).</summary>
    private static string BaselineDigestOf(JsonObject baseline) => EngineJson.Digest(new JsonObject
    {
        ["schema"] = "codeparley.custodian-fix-baseline.v1",
        ["reviewId"] = baseline["reviewId"]?.DeepClone(), ["sourceId"] = baseline["sourceId"]?.DeepClone(), ["exportDigest"] = baseline["exportDigest"]?.DeepClone(),
        ["manifestDigest"] = baseline["manifestDigest"]?.DeepClone(), ["treeDigest"] = baseline["treeDigest"]?.DeepClone(),
    });

    // ---- the held proposal: read, re-verified and rendered (outside the gate) ----

    /// <summary>
    /// Read a fix's held proposal OUTSIDE the gate: under a short hold the record (the operation, its proposal, its
    /// baseline review); then outside it the baseline export (re-hashed, its manifest read), the content file (its digest
    /// and every postimage re-verified against the record, every preimage the manifest's), the baseline bytes of every
    /// modified or deleted file (checked against the preimage), and the rendering.
    /// </summary>
    private HeldProposalRead ReadHeldProposal(RepoIdentity id, string runId, string operationId)
    {
        RunOperation? op;
        JsonObject? reviewBegin = null;
        string reviewOperationId = "";
        lock (EnterGate())
        {
            RunRecord? run = ReadRun(id.Key, runId);
            op = run?.Operations.FirstOrDefault(o => o.OperationId == operationId && o.Kind == "fix");
            if (op is not null)
            {
                string? reviewId = (string?)op.Begin["custodianBaseline"]?["reviewId"];
                RunReview? review = run!.Reviews.FirstOrDefault(r => r.ReviewId == reviewId);
                if (review is not null)
                {
                    reviewBegin = (JsonObject)review.Begin.DeepClone();
                    reviewOperationId = review.OperationId;
                }
            }
        }
        if (op is null) return new HeldProposalRead(operationId, "the run has no such delegated fix", null, null, null, null, null, null);
        JsonObject begin = op.Begin;
        JsonObject baseline = begin["custodianBaseline"]!.AsObject();
        JsonObject? proposal = op.Outcome?["proposal"] as JsonObject;
        string? recordDigest = (string?)proposal?["proposalDigest"];
        HeldProposalRead Fail(string why) => new(operationId, why, op.Status, recordDigest, (string?)begin["boundaryDigest"], BaselineDigestOf(baseline), null, null);
        if (proposal is null || recordDigest is null) return Fail("the fix holds no proposal");
        if (proposal["retiredAt"] is not null) return Fail($"the proposal was retired ({(string?)proposal["retiredReason"]}); its content is no longer held");

        FixBaselineRead tree = ReadExportTree((string)baseline["reviewId"]!, reviewOperationId, reviewBegin);
        if (!tree.Unchanged || tree.Tree is null) return Fail($"the baseline capture cannot be vouched for ({tree.Detail})");
        if (FixRules.TreeDigest(tree.Tree) != (string?)baseline["treeDigest"]) return Fail("the baseline capture is not the tree the fix bound");
        string exportPath = (string)reviewBegin!["custodianCapture"]!["exportPath"]!;
        JsonObject held;
        try { held = JsonNode.Parse(File.ReadAllText(ProposalPath(id.Key, runId, operationId)))!.AsObject(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException) { return Fail($"the held content could not be read ({e.GetType().Name})"); }
        // Phase 6 L-1: the held content is read only in the schema this build writes.
        if ((string?)held["schema"] != FixProposalContentSchema) return Fail($"the held content is in schema {(string?)held["schema"] ?? "(none)"}, which this build does not read");
        if ((string?)held["proposalDigest"] != recordDigest || held["changes"] is not JsonArray heldChanges) return Fail("the held content is not the proposal the record names");

        var canonical = new List<FixCanonicalChange>();
        var render = new List<RenderChange>();
        var content = new JsonArray();
        foreach (JsonObject c in heldChanges.OfType<JsonObject>())
        {
            string path = (string)c["path"]!, kind = (string)c["kind"]!;
            bool executable = (bool)c["executable"]!;
            string? b64 = (string?)c["content"];
            byte[]? post = b64 is null ? null : FixRules.DecodeStrictBase64(b64);
            if ((b64 is null) != (kind == "delete") || (b64 is not null && post is null)) return Fail($"the held content of {path} is malformed");
            BaselineFile? pre = kind == "add" ? null : tree.Tree.GetValueOrDefault(path);
            if (kind != "add" && pre is null) return Fail($"{path} is not in the baseline capture");
            if (kind == "add" && tree.Tree.ContainsKey(path)) return Fail($"{path} is in the baseline capture");
            string? postSha = post is null ? null : Convert.ToHexStringLower(SHA256.HashData(post));
            var cc = new FixCanonicalChange(path, kind, executable, pre, post?.LongLength, postSha, post is not null && Array.IndexOf(post, (byte)0) >= 0, b64);
            if (!JsonNode.DeepEquals(FixRules.ChangeSummary(cc), SummaryOf(c))) return Fail($"the held content of {path} does not hash to its record");
            byte[]? preBytes = null;
            if (pre is not null)
            {
                try { preBytes = File.ReadAllBytes(Path.Combine(exportPath, "tree", Path.Combine(path.Split('/')))); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return Fail($"the baseline bytes of {path} could not be read ({e.GetType().Name})"); }
                if (preBytes.LongLength != pre.Size || Convert.ToHexStringLower(SHA256.HashData(preBytes)) != pre.Sha256) return Fail($"the baseline bytes of {path} differ from its preimage");
            }
            canonical.Add(cc);
            render.Add(new RenderChange(path, kind, executable, pre, cc.PostSize, postSha, cc.PostBinary, preBytes, post));
            JsonObject entry = FixRules.ChangeSummary(cc);
            entry["content"] = b64;
            content.Add(entry);
        }
        var bound = new JsonObject
        {
            ["reviewId"] = baseline["reviewId"]?.DeepClone(), ["sourceId"] = baseline["sourceId"]?.DeepClone(),
            ["exportDigest"] = baseline["exportDigest"]?.DeepClone(), ["manifestDigest"] = baseline["manifestDigest"]?.DeepClone(),
        };
        if (FixRules.ProposalDigest(runId, operationId, (string)begin["fixId"]!, (string)begin["taskDigest"]!, (string)begin["boundaryDigest"]!, bound, canonical) != recordDigest)
            return Fail("the held content does not recompute to the proposal digest");
        var header = new RenderHeader(runId, id.CanonicalPath, id.Key, (string)begin["fixId"]!, operationId, (string)baseline["reviewId"]!, (string?)baseline["sourceId"] ?? "",
            (string)begin["taskDigest"]!, recordDigest, (string)proposal["expiresAt"]!, (string)begin["boundaryDigest"]!, RunFields.Integer(proposal["totalBytes"]) ?? 0);
        FixRenderingResult rendering = FixRendering.Render(header, begin["boundary"]!.AsObject(), render);
        return new HeldProposalRead(operationId, null, op.Status, recordDigest, (string?)begin["boundaryDigest"], BaselineDigestOf(baseline), rendering, content);
    }

    private static JsonObject SummaryOf(JsonObject c) => new()
    {
        ["path"] = c["path"]?.DeepClone(), ["kind"] = c["kind"]?.DeepClone(), ["executable"] = c["executable"]?.DeepClone(),
        ["preimage"] = c["preimage"]?.DeepClone(), ["postimage"] = c["postimage"]?.DeepClone(),
    };

    private static RunOperation FixOperationOf(RunRecord run, string operationId)
        => run.Operations.FirstOrDefault(o => o.OperationId == operationId && o.Kind == "fix")
           ?? throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"the run has no delegated fix {operationId}");

    /// <summary>A proposal awaiting the owner: proposed, not retired, inside its lifetime, on an open run.</summary>
    private static void RequirePending(RunRecord run, RunOperation op, DateTime now)
    {
        if (run.IsTerminal) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({run.Status}); nothing was prepared");
        JsonObject? p = ProposalOf(op);
        if (op.Status != RunOperationStatuses.Proposed || p is null)
            throw new CustodianRefusal(ErrorCodes.ProposalNotPending, $"delegated fix {op.OperationId} has no proposal awaiting the owner (it is {op.Status})");
        if (p["retiredAt"] is not null || ParseTime((string)p["expiresAt"]!) <= now)
            throw new CustodianRefusal(ErrorCodes.ProposalNotPending, $"the proposal of delegated fix {op.OperationId} has expired; nothing was prepared");
    }

    /// <summary>The "state shown" a fix decision's commit re-derives: the fix's status and proposal (digest, retirement), its
    /// boundary and baseline, the run's end — and the rendering the custodian produces now.</summary>
    private static string FixDecisionStateDigest(RunRecord? run, string operationId, string? renderingDigest)
    {
        RunOperation? op = run?.Operations.FirstOrDefault(o => o.OperationId == operationId && o.Kind == "fix");
        JsonObject? p = op is null ? null : ProposalOf(op);
        return Digest.Sha256Hex(Digest.Canonical(new JsonObject
        {
            ["schema"] = "codeparley.custodian-fix-decision-state.v1",
            ["runTerminal"] = run?.IsTerminal, ["status"] = op?.Status, ["proposalDigest"] = (string?)p?["proposalDigest"], ["retiredAt"] = (string?)p?["retiredAt"],
            ["boundaryDigest"] = (string?)op?.Begin["boundaryDigest"],
            ["baseline"] = op?.Begin["custodianBaseline"] is JsonObject b ? BaselineDigestOf(b) : null,
            ["renderingDigest"] = renderingDigest,
        }));
    }

    // ---- read: the custodian's rendering (operator and implementer; no authority) ----

    /// <summary><c>render_fix_proposal</c>: the custodian's rendering of a proposal it holds — what <c>fix show</c> prints and
    /// the originating session inspects before asking the owner (contract §3.7). Read only; it creates nothing.</summary>
    internal JsonObject RenderFixProposal(string repositoryRoot, string runId, string operationId)
    {
        ValidateRunId(runId);
        RunFields.RequireToken("operationId", operationId, 64);
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        HeldProposalRead read = ReadHeldProposal(id, runId, operationId);
        if (read.Problem is not null || read.Rendering is null) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"the custodian cannot render delegated fix {operationId}: {read.Problem}");
        JsonObject? confirmation;
        string? expiresAt;
        lock (EnterGate())
        {
            RunOperation op = FixOperationOf(ReadRun(id.Key, runId) ?? throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run"), operationId);
            confirmation = op.Outcome?["confirmation"]?.DeepClone() as JsonObject;
            expiresAt = (string?)ProposalOf(op)?["expiresAt"];
        }
        return new JsonObject
        {
            ["operationId"] = operationId, ["status"] = read.Status, ["proposalDigest"] = read.ProposalDigest, ["expiresAt"] = expiresAt,
            ["rendering"] = read.Rendering.Text, ["renderingDigest"] = read.Rendering.Digest, ["changesDigest"] = read.Rendering.ChangesDigest,
            ["confirmation"] = confirmation is null ? null : new JsonObject
            {
                ["confirmationId"] = confirmation["confirmationId"]?.DeepClone(), ["decision"] = confirmation["decision"]?.DeepClone(),
                ["expiresAt"] = confirmation["expiresAt"]?.DeepClone(), ["consumedAt"] = confirmation["consumedAt"]?.DeepClone(),
            },
        };
    }

    // ---- operator: prepare the owner's decision ----

    /// <summary><c>prepare_fix_decision</c> (operator surface): render the held proposal and prepare a decision bound to
    /// exactly that rendering. Nothing is recorded until <see cref="Commit"/>.</summary>
    internal PreparedAuthorization PrepareFixDecision(string repositoryRoot, string runId, string operationId, string decision, string requestId, FixSelection? expected = null)
    {
        ValidateRunId(runId);
        RunFields.RequireToken("operationId", operationId, 64);
        if (decision is not ("confirm" or "reject")) throw new ArgumentException("decision must be 'confirm' or 'reject'");
        RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
        // Step 7.1: the path the operator's selection reached must still be the repository identity that was listed.
        if (expected is not null && id.Key != expected.RepoKey)
            throw new CustodianRefusal(ErrorCodes.SelectionStale, $"the repository path now resolves to identity {id.Key}, not the identity that was selected ({expected.RepoKey}); nothing was prepared — list and review again");
        HeldProposalRead read = ReadHeldProposal(id, runId, operationId);
        lock (EnterGate())
        {
            RunRecord run = ReadRun(id.Key, runId) ?? throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run");
            RunOperation op = FixOperationOf(run, operationId);
            RequirePending(run, op, _clock());
            if (read.Problem is not null || read.Rendering is null)
                throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"the custodian cannot render delegated fix {operationId}, so nothing can be confirmed: {read.Problem}");
            JsonObject p = ProposalOf(op)!;
            JsonObject baseline = op.Begin["custodianBaseline"]!.AsObject();
            if ((string?)p["proposalDigest"] != read.ProposalDigest || (string?)op.Begin["boundaryDigest"] != read.BoundaryDigest || BaselineDigestOf(baseline) != read.BaselineDigest)
                throw new CustodianRefusal(ErrorCodes.ConfirmationContentMismatch, "the proposal changed while the custodian rendered it; nothing was prepared — prepare it again");
            // Step 7.1: a guided selection is prepared only for the proposal and the exact rendering the operator reviewed.
            if (expected is not null && read.ProposalDigest != expected.ProposalDigest)
                throw new CustodianRefusal(ErrorCodes.SelectionStale, $"delegated fix {operationId} now holds another proposal than the one that was selected; nothing was prepared — list and review again");
            if (expected is not null && read.Rendering.Digest != expected.RenderingDigest)
                throw new CustodianRefusal(ErrorCodes.SelectionStale, $"the custodian's rendering of delegated fix {operationId} is not the one that was reviewed; nothing was prepared — review it again");
            var args = new JsonObject
            {
                ["repositoryRoot"] = id.CanonicalPath, ["repoKey"] = id.Key, ["runId"] = runId, ["operationId"] = operationId, ["decision"] = decision,
                ["proposalDigest"] = read.ProposalDigest, ["renderingDigest"] = read.Rendering.Digest, ["boundaryDigest"] = read.BoundaryDigest,
                ["baselineDigest"] = read.BaselineDigest, ["baselineSourceId"] = (string?)baseline["sourceId"],
            };
            (string header, string footer, string[] consequences) = FixDecisionAuthority(decision, runId, operationId);
            string rendering = header + read.Rendering.Text + footer;
            var facts = new JsonObject
            {
                ["schema"] = FixDecisionFactsSchema, ["decision"] = decision, ["repoKey"] = id.Key, ["repositoryRoot"] = id.CanonicalPath,
                ["runId"] = runId, ["operationId"] = operationId, ["proposalDigest"] = read.ProposalDigest, ["renderingDigest"] = read.Rendering.Digest,
                ["baselineSourceId"] = (string?)baseline["sourceId"], ["authorityHeader"] = header, ["authorityFooter"] = footer,
                ["consequences"] = new JsonArray([.. consequences.Select(c => (JsonNode)c)]),
            };
            return PrepareIntent(FixDecisionAction, args, FixDecisionStateDigest(run, operationId, read.Rendering.Digest), requestId, rendering) with { Facts = facts };
        }
    }

    /// <summary>Step 7.1: the structured facts of a prepared fix decision (<c>fixDecision</c> in the response).</summary>
    internal const string FixDecisionFactsSchema = "codeparley.custodian-fix-decision-prepared.v1";

    /// <summary>A fix decision's authority text around the custodian's rendering (the prepared rendering is exactly
    /// header + rendering + footer) and its consequences as codes.</summary>
    private static (string Header, string Footer, string[] Consequences) FixDecisionAuthority(string decision, string runId, string operationId)
        => decision == "confirm"
            ? ($"Confirm delegated fix {operationId} of run {runId}: CodeParley may apply EXACTLY the content below, once.\n\n",
               "\nThe confirmation is single use and bound to this rendering (sha256 above), the proposal digest, this repository and run, and the baseline source.\n"
               + "The application re-checks that the working tree still matches the baseline (FIX_STALE otherwise) and writes only this content.\n"
               + "It authorizes no commit, push, merge, tag or release.",
               ["applies_exactly_this_content_once", "bound_to_this_rendering", "rechecks_the_baseline", "authorizes_no_commit_push_merge_tag_or_release"])
            : ($"Reject delegated fix {operationId} of run {runId}: the proposal below is closed and its content removed; nothing is applied.\n\n",
               "",
               ["closes_the_proposal", "removes_its_content", "applies_nothing"]);

    // ---- operator: the delegated fixes across repositories (Step 7.1, `fix review`) ----

    /// <summary>A guided selection's expected values (all three: the dispatcher refuses fewer).</summary>
    internal sealed record FixSelection(string RepoKey, string ProposalDigest, string RenderingDigest);

    internal const string FixListingSchema = "codeparley.custodian-fix-listing.v1";
    internal const int MaxListedFixes = 50, MaxListedPaths = 10;

    private static readonly string[] ListedStates = ["pending", "unavailable", "waiting", "expired", "ineligible"];

    /// <summary>
    /// <c>list_fix_proposals</c> (operator surface only): every delegated fix the custodian holds that awaits the owner
    /// (pending), awaits its application (waiting), or no longer can be decided (expired, ineligible), across repositories,
    /// or of the one identity <paramref name="repositoryRoot"/> resolves to. Facts the custodian holds only — never any text
    /// the implementer wrote. A fix's repository path comes from the custodian's own repository configuration history (the
    /// latest version's path, the one the run was opened under, then older ones), never from a run or grant; it is offered
    /// only when it resolves to the run's exact repository identity now (else the fix is <c>unavailable</c>, with the last
    /// recorded path). A run record that cannot be read fails the listing (nothing is silently left out).
    /// </summary>
    internal JsonObject ListFixProposals(string? repositoryRoot)
    {
        RepoIdentity? only = repositoryRoot is null ? null : RepoIdentities.Resolve(repositoryRoot);
        DateTime now = _clock();
        var found = new List<(RunRecord Run, RunOperation Op)>();
        ConfigRecordsFile config;
        lock (EnterGate())
        {
            config = ReadConfigRecords();
            if (Directory.Exists(StorePaths.RunsDir))
            {
                foreach (string file in Directory.EnumerateFiles(StorePaths.RunsDir, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                {
                    RunRecord run;
                    try { run = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new JsonException("empty"); }
                    catch (Exception e) when (e is JsonException or NotSupportedException or IOException or UnauthorizedAccessException)
                    {
                        throw new InvalidDataException($"a run record is unreadable ({Path.GetFileName(file)}); no delegated fix is listed until it is restored (fail closed)");
                    }
                    if (only is not null && run.RepoKey != only.Key) continue;
                    foreach (RunOperation op in run.Operations)
                        if (op.Kind == "fix" && ProposalOf(op) is not null && (op.Status == RunOperationStatuses.Proposed || op.Status == FixConfirmed)) found.Add((run, op));
                }
            }
        }

        // Outside the gate: repository identities and held proposals are read from the file system.
        var located = new Dictionary<string, (RepoIdentity? Id, string? Last)>(StringComparer.Ordinal);
        (RepoIdentity? Id, string? Last) Locate(RunRecord run)
        {
            string memo = run.RepoKey + "|" + (run.OpenedConfig?.ConfigRevision.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-");
            if (located.TryGetValue(memo, out var known)) return known;
            List<string> candidates = only is not null ? [only.CanonicalPath] : CandidatePaths(config, run);
            (RepoIdentity? Id, string? Last) result = (null, candidates.FirstOrDefault());
            foreach (string path in candidates)
            {
                RepoIdentity? id = null;
                try { id = RepoIdentities.Resolve(path); }
                catch (Exception e) when (e is not OutOfMemoryException) { /* the path no longer reaches a directory */ }
                if (id is not null && id.Key == run.RepoKey) { result = (id, path); break; }
            }
            return located[memo] = result;
        }

        var rows = new List<(int Rank, string ExpiresAt, JsonObject Entry, RunRecord Run, RunOperation Op, RepoIdentity? Id)>();
        foreach ((RunRecord run, RunOperation op) in found)
        {
            JsonObject p = ProposalOf(op)!;
            JsonObject? confirmation = op.Outcome?["confirmation"] as JsonObject;
            string expiresAt = (string?)p["expiresAt"] ?? "";
            string state;
            string? reason = null;
            if (op.Status == FixConfirmed)
            {
                bool lapsed = confirmation?["expiresAt"] is JsonValue cv && cv.TryGetValue(out string? ce) && ParseTime(ce) <= now;
                (state, reason) = run.IsTerminal ? ("ineligible", "run_ended") : lapsed ? ("ineligible", "confirmation_expired") : ("waiting", null);
            }
            else if (run.IsTerminal) (state, reason) = ("ineligible", "run_ended");
            else if (p["retiredAt"] is not null || ParseTime(expiresAt) <= now) (state, reason) = ("expired", "proposal_expired");
            else state = "pending";
            (RepoIdentity? id, string? last) = Locate(run);
            if (state == "pending" && id is null) (state, reason) = ("unavailable", "repository_unavailable");
            var changed = (p["changes"] as JsonArray ?? []).OfType<JsonObject>().Select(c => (string?)c["path"] ?? "").ToList();
            var entry = new JsonObject
            {
                ["state"] = state, ["selectable"] = false, ["reasonCode"] = reason, ["repoKey"] = run.RepoKey,
                ["repositoryRoot"] = id?.CanonicalPath, ["repositoryDisplay"] = id is null ? null : FixRendering.Escape(id.CanonicalPath),
                ["lastKnownPath"] = id is null && last is not null ? FixRendering.Escape(last) : null,
                ["runId"] = run.RunId, ["operationId"] = op.OperationId, ["proposalDigest"] = (string?)p["proposalDigest"], ["renderingDigest"] = null,
                ["changeCount"] = RunFields.Integer(p["changeCount"]) ?? changed.Count, ["totalBytes"] = RunFields.Integer(p["totalBytes"]) ?? 0,
                ["paths"] = new JsonArray([.. changed.Take(MaxListedPaths).Select(c => (JsonNode)FixRendering.Escape(c))]), ["pathCount"] = changed.Count,
                ["proposedAt"] = (string?)p["createdAt"], ["expiresAt"] = expiresAt,
                ["confirmationExpiresAt"] = state == "waiting" ? (string?)confirmation?["expiresAt"] : null,
            };
            rows.Add((Array.IndexOf(ListedStates, state), expiresAt, entry, run, op, id));
        }
        static List<(int Rank, string ExpiresAt, JsonObject Entry, RunRecord Run, RunOperation Op, RepoIdentity? Id)> Ordered(
            IEnumerable<(int Rank, string ExpiresAt, JsonObject Entry, RunRecord Run, RunOperation Op, RepoIdentity? Id)> of) => [.. of
            .OrderBy(r => r.Rank).ThenBy(r => r.ExpiresAt, StringComparer.Ordinal).ThenBy(r => r.Run.RepoKey, StringComparer.Ordinal)
            .ThenBy(r => r.Run.RunId, StringComparer.Ordinal).ThenBy(r => r.Op.OperationId, StringComparer.Ordinal)];
        // The response is bounded: the first MaxListedFixes rows in the listing's order (pending first, the soonest to expire
        // first). What is cut is counted, and the pending fixes among it are counted separately (never left out silently).
        List<(int Rank, string ExpiresAt, JsonObject Entry, RunRecord Run, RunOperation Op, RepoIdentity? Id)> ordered = Ordered(rows);
        var listed = ordered.Take(MaxListedFixes).ToList();
        int omittedPending = ordered.Skip(MaxListedFixes).Count(r => (string?)r.Entry["state"] == "pending");
        // A pending fix is selectable once the custodian has read, re-verified and rendered its held proposal now.
        for (int i = 0; i < listed.Count; i++)
        {
            (_, _, JsonObject entry, RunRecord run, RunOperation op, RepoIdentity? id) = listed[i];
            if ((string?)entry["state"] != "pending") continue;
            HeldProposalRead read = ReadHeldProposal(id!, run.RunId, op.OperationId);
            if (read.Problem is not null || read.Rendering is null || read.ProposalDigest != (string?)entry["proposalDigest"])
            {
                entry["state"] = "ineligible";
                entry["reasonCode"] = "content_unreadable";
                listed[i] = listed[i] with { Rank = Array.IndexOf(ListedStates, "ineligible") };
                continue;
            }
            entry["renderingDigest"] = read.Rendering.Digest;
            entry["selectable"] = true;
        }
        // A fix found unreadable now takes its place among the ineligible ones (the sections stay in order).
        var entries = new JsonArray([.. Ordered(listed).Select(r => (JsonNode)r.Entry)]);
        return new JsonObject
        {
            ["schema"] = FixListingSchema, ["snapshotAt"] = Iso(now), ["total"] = rows.Count, ["truncated"] = rows.Count > MaxListedFixes,
            ["omittedPending"] = omittedPending,
            ["listingDigest"] = Digest.Sha256Hex(Digest.Canonical(new JsonObject { ["entries"] = entries.DeepClone() })),
            ["entries"] = entries,
        };
    }

    /// <summary>The paths the custodian's configuration history records for a run's repository identity, in the order the
    /// listing tries them: the latest version's, the version the run was opened under, then the others, newest first.</summary>
    private static List<string> CandidatePaths(ConfigRecordsFile config, RunRecord run)
    {
        List<RepositoryConfig> versions = [.. config.Repositories.Where(r => r.RepoKey == run.RepoKey).OrderByDescending(r => r.ConfigRevision)];
        var ordered = new List<string>();
        void Add(string? path)
        {
            if (!string.IsNullOrEmpty(path) && !ordered.Contains(path, StringComparer.Ordinal)) ordered.Add(path);
        }
        if (versions.Count > 0) Add(versions[0].RepositoryRoot);
        if (run.OpenedConfig is { } pin) Add(versions.FirstOrDefault(v => v.ConfigRevision == pin.ConfigRevision)?.RepositoryRoot);
        foreach (RepositoryConfig v in versions) Add(v.RepositoryRoot);
        return ordered;
    }

    /// <summary>For a pending fix decision's commit, its rendering again — before the gate. Null when the intent is not a fix
    /// decision (or not readable: the commit then refuses it as usual).</summary>
    private string? RerenderForCommit(string requestId, out bool isFixDecision)
    {
        isFixDecision = false;
        JsonObject? intent;
        try
        {
            string path = IntentPath(requestId);
            lock (EnterGate()) intent = File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject : null;
        }
        catch (Exception e) when (e is IOException or JsonException or ArgumentException) { return null; }
        if ((string?)intent?["action"] != FixDecisionAction) return null;
        isFixDecision = true;
        JsonObject args = intent!["args"]!.AsObject();
        RepoIdentity id;
        try { id = RepoIdentities.Resolve((string)args["repositoryRoot"]!); }
        catch (ArgumentException) { return null; }
        if (id.Key != (string?)args["repoKey"]) return null;
        HeldProposalRead read = ReadHeldProposal(id, (string)args["runId"]!, (string)args["operationId"]!);
        return read.Problem is null ? read.Rendering?.Digest : null;
    }

    /// <summary>The commit of a fix decision, in the commit's hold (its freshness re-derived, the rendering compared).</summary>
    private void RequireFreshFixDecision(JsonObject args, string recordedState, string? rerendered, DateTime now)
    {
        RunRecord? run = ReadRun((string)args["repoKey"]!, (string)args["runId"]!);
        if (run is { IsTerminal: true } ended) throw new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({ended.Status}) since this was prepared; nothing was committed");
        if (rerendered is null || FixDecisionStateDigest(run, (string)args["operationId"]!, rerendered) != recordedState)
            throw new CustodianRefusal(ErrorCodes.ConfirmationContentMismatch, "the proposal, its boundary, its baseline or the custodian's rendering changed since it was prepared; nothing was committed — show and decide again");
        RequirePending(run!, FixOperationOf(run!, (string)args["operationId"]!), now);
    }

    /// <summary>Record the owner's decision on the fix operation (single hold, after the freshness checks).</summary>
    private JsonObject ApplyFixDecision(JsonObject args, string requestId, string digest, string? proof)
    {
        string repoKey = (string)args["repoKey"]!, runId = (string)args["runId"]!, operationId = (string)args["operationId"]!, decision = (string)args["decision"]!;
        DateTime now = _clock();
        RunRecord run = ReadRun(repoKey, runId)!;
        RunOperation op = FixOperationOf(run, operationId);
        var outcome = (JsonObject)op.Outcome!.DeepClone();
        var p = (JsonObject)outcome["proposal"]!;
        var recordedBy = new JsonObject
        {
            ["role"] = "user", ["channel"] = "custodian_operator", ["assurance"] = Platform.OperatorAssurance, ["proof_digest"] = proof ?? digest, ["request_id"] = requestId,
        };
        string confirmationId = Guid.NewGuid().ToString();
        DateTime proposalExpires = ParseTime((string)p["expiresAt"]!);
        DateTime cap = now.AddSeconds(CustodianConstants.FixConfirmationTtlSeconds);
        string expiresAt = Iso(proposalExpires < cap ? proposalExpires : cap);
        outcome["confirmation"] = new JsonObject
        {
            ["confirmationId"] = confirmationId, ["decision"] = decision, ["renderingDigest"] = args["renderingDigest"]?.DeepClone(),
            ["proposalDigest"] = args["proposalDigest"]?.DeepClone(), ["repoKey"] = repoKey, ["runId"] = runId,
            ["baselineSourceId"] = args["baselineSourceId"]?.DeepClone(), ["baselineDigest"] = args["baselineDigest"]?.DeepClone(),
            ["boundaryDigest"] = args["boundaryDigest"]?.DeepClone(), ["recordedAt"] = Iso(now), ["expiresAt"] = decision == "confirm" ? expiresAt : null,
            ["recordedBy"] = recordedBy, ["consumedAt"] = null, ["consumedBy"] = null,
        };
        string status = decision == "confirm" ? FixConfirmed : FixDeclined;
        if (decision == "reject")
        {
            p["retiredAt"] = Iso(now);
            p["retiredReason"] = FixDeclined;
            _retiredProposals.Enqueue(ProposalPath(repoKey, runId, operationId));
        }
        RunRecord next = run with { Operations = ReplaceOperation(run, op with { Status = status, Outcome = outcome }) };
        var result = new JsonObject
        {
            ["operationId"] = operationId, ["decision"] = decision, ["operationStatus"] = status, ["confirmationId"] = confirmationId,
            ["renderingDigest"] = args["renderingDigest"]?.DeepClone(), ["proposalDigest"] = args["proposalDigest"]?.DeepClone(),
            ["expiresAt"] = decision == "confirm" ? expiresAt : null, ["assurance"] = Platform.OperatorAssurance,
        };
        int revision = run.RunRevision + 1;
        var stored = new JsonObject { ["runId"] = runId, ["kind"] = FixDecisionAction, ["runRevision"] = revision, ["status"] = next.Status };
        foreach (KeyValuePair<string, JsonNode?> kv in result) stored[kv.Key] = kv.Value?.DeepClone();
        var evidence = new RunEvent(run.Events.Count + 1, FixDecisionAction, requestId, "operator", null, Digest.Sha256Hex(Digest.Canonical(stored)), run.Status, next.Status, Iso(now), (JsonObject)stored.DeepClone());
        WriteRun(next with { RunRevision = revision, Events = [.. run.Events, evidence] });
        Audit($"fix_decision committed decision={decision} runId={runId} operationId={operationId} confirmationId={confirmationId} rendering={((string?)args["renderingDigest"])?[..16]} requestId={requestId} assurance={Platform.OperatorAssurance}");
        return stored;
    }

    // ---- the application: what is read and measured before the gate ----

    /// <summary>For an application's begin, finish or reconciliation: the held proposal (begin only) and the custodian's own
    /// measurement of the primary source through its helper — both outside the gate. Null for any other transition.</summary>
    private ApplyPre? ReadForApply(RepoIdentity id, RunRequest req)
    {
        string? fixOperationId = null;
        bool begin = req.Kind == RunKinds.OpBegin && (string?)req.Fields["operationKind"] == "apply";
        if (begin) fixOperationId = (string?)req.Fields["fixOperationId"];
        else if (req.Kind == RunKinds.OpFinish || req.Kind == RunKinds.ApplyReconcile)
        {
            lock (EnterGate())
            {
                RunOperation? op = ReadRun(id.Key, req.RunId)?.Operations.FirstOrDefault(o => o.OperationId == (string?)req.Fields["operationId"]);
                if (op?.Kind != "apply") return null;
            }
        }
        else return null;
        HeldProposalRead? held = begin ? ReadHeldProposal(id, req.RunId, fixOperationId!) : null;
        return new ApplyPre(held, MeasureSource(id, req.RunId));
    }

    /// <summary>The custodian's measurement of the primary source (no checks), outside the gate.</summary>
    private ApplyMeasure MeasureSource(RepoIdentity id, string runId)
    {
        EngineRuntimeRecord runtime;
        JsonObject workload;
        try
        {
            lock (EnterGate())
            {
                runtime = RequireMeasureReady();
                RequireRepositoryReadable(id);
                RepositoryConfig cfg = RequireUsableConfig(id.Key, "an application's measurement");
                workload = new JsonObject { ["rules"] = RulesJson(cfg.CaptureRules), ["checks"] = new JsonArray(), ["snapshot"] = null };
            }
        }
        catch (CustodianRefusal r) { return new ApplyMeasure(null, false, r.Code, r.Message); }
        MeasureOutcome o = Measure(runtime, id, workload, CancellationToken.None);
        if (!o.Ok) return new ApplyMeasure(null, false, o.Code ?? ErrorCodes.MeasurementFailed, Bounded(o.Detail));
        return new ApplyMeasure((string?)o.Measured!["sourceId"], (bool?)o.Measured["stable"] ?? false, null, null);
    }

    /// <summary>The application operations of the repository that are in progress — running, or interrupted and not yet
    /// reconciled — across all its runs. Callers hold <see cref="Gate"/>.</summary>
    private static List<(string RunId, string OperationId, string Status)> ApplicationsInProgress(string repoKey)
    {
        var found = new List<(string, string, string)>();
        string dir = Path.GetDirectoryName(StorePaths.RunPath(repoKey, "x"))!;
        if (!Directory.Exists(dir)) return found;
        foreach (string file in Directory.EnumerateFiles(dir, "*.json").Order(StringComparer.Ordinal))
        {
            RunRecord run = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new InvalidDataException("a run record is unreadable (fail closed)");
            foreach (RunOperation o in run.Operations.Where(o => o.Kind == "apply" && (o.Status == RunOperationStatuses.Running || o.Status == ApplyInterrupted)))
                found.Add((run.RunId, o.OperationId, o.Status));
        }
        return found;
    }

    // ---- op_begin of an application ----

    /// <summary>Begin the application of a confirmed fix: consume its confirmation and return the confirmed content.</summary>
    private RunStep ApplyBeginStep(RunRecord run, RunRequest req, DateTime now, OperationWriter writer, int seq, ApplyPre? pre)
    {
        JsonObject f = req.Fields;
        string fixOperationId = (string)f["fixOperationId"]!;
        RunOperation fix = FixOperationOf(run, fixOperationId);
        JsonObject? confirmation = fix.Outcome?["confirmation"] as JsonObject;
        switch (fix.Status)
        {
            case FixConfirmed: break;
            case FixConsumed: throw new CustodianRefusal(ErrorCodes.ConfirmationConsumed, $"the confirmation of delegated fix {fixOperationId} was already used by application {(string?)confirmation?["consumedBy"]}; a confirmation is single use");
            case FixDeclined: throw new CustodianRefusal(ErrorCodes.FixDeclined, $"the owner rejected delegated fix {fixOperationId}; nothing is applied");
            default: throw new CustodianRefusal(ErrorCodes.FixNotConfirmed, $"delegated fix {fixOperationId} has no owner confirmation ({fix.Status}); the owner confirms the custodian's rendering with `{OperatorWording.Cli} fix confirm <run> <proposal> --repo <path>`");
        }
        JsonObject p = ProposalOf(fix)!;
        if (confirmation is null || (string?)confirmation["decision"] != "confirm" || (string?)confirmation["repoKey"] != run.RepoKey || (string?)confirmation["runId"] != run.RunId)
            throw new CustodianRefusal(ErrorCodes.FixNotConfirmed, $"delegated fix {fixOperationId} has no confirmation for this repository and run");
        if (ParseTime((string)confirmation["expiresAt"]!) <= now || p["retiredAt"] is not null)
            throw new CustodianRefusal(ErrorCodes.ConfirmationExpired, $"the confirmation of delegated fix {fixOperationId} has expired; the owner confirms it again (`{OperatorWording.Cli} fix confirm <run> <proposal> --repo <path>`) while the proposal lives");
        string digest = (string)p["proposalDigest"]!;
        if ((string)f["proposalDigest"]! != digest || (string?)confirmation["proposalDigest"] != digest)
            throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"proposal {(string)f["proposalDigest"]!} is not the confirmed proposal of delegated fix {fixOperationId}");
        List<(string RunId, string OperationId, string Status)> busy = ApplicationsInProgress(run.RepoKey);
        if (busy.Count > 0)
            throw new CustodianRefusal(ErrorCodes.ApplyInProgress, $"another application is in progress for this repository (run {busy[0].RunId}, {busy[0].OperationId}: {busy[0].Status}); one application at a time, and an interrupted one is reconciled first (`code-parley fix reconcile`)");
        HeldProposalRead? held = pre?.Held;
        if (held is null || held.OperationId != fixOperationId || held.Problem is not null || held.Rendering is null || held.Content is null)
            throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"the custodian cannot vouch for the confirmed content of delegated fix {fixOperationId} ({held?.Problem ?? "it was not read"}); nothing was applied");
        if (held.ProposalDigest != digest || held.Rendering.Digest != (string?)confirmation["renderingDigest"])
            throw new CustodianRefusal(ErrorCodes.ConfirmationContentMismatch, "the held content no longer renders the bytes the owner confirmed; nothing was applied");
        ApplyMeasure m = pre!.Measured ?? new ApplyMeasure(null, false, ErrorCodes.MeasurementFailed, "not measured");
        if (m.SourceId is null) throw new CustodianRefusal(m.Code ?? ErrorCodes.MeasurementFailed, $"the custodian could not measure the working tree before the application ({m.Detail}); nothing was applied");
        string baselineSource = (string)fix.Begin["custodianBaseline"]!["sourceId"]!;
        if (!m.Stable || m.SourceId != baselineSource)
            throw new CustodianRefusal(ErrorCodes.FixStale, m.Stable
                ? "the working tree is no longer the baseline the fix was made against (the custodian's re-measurement differs); nothing was applied and the confirmation is unused"
                : "the working tree was changing while the custodian measured it; nothing was applied and the confirmation is unused");
        string applyId = NewId("aop", seq);
        var begin = new JsonObject
        {
            ["operationKind"] = "apply", ["fixOperationId"] = fixOperationId, ["proposalDigest"] = digest,
            ["confirmationId"] = confirmation["confirmationId"]?.DeepClone(), ["renderingDigest"] = held.Rendering.Digest, ["sourceIdAtBegin"] = m.SourceId,
        };
        var apply = new RunOperation(applyId, seq, "apply", RunOperationStatuses.Running, Iso(now), null, writer, begin, null, fix.Pin);
        var conf = (JsonObject)confirmation.DeepClone();
        conf["consumedAt"] = Iso(now);
        conf["consumedBy"] = applyId;
        var fixOutcome = (JsonObject)fix.Outcome!.DeepClone();
        fixOutcome["confirmation"] = conf;
        RunOperation consumed = fix with { Status = FixConsumed, Outcome = fixOutcome };
        RunRecord next = run with { Operations = [.. ReplaceOperation(run, consumed), apply], Status = RunStatuses.Applying };
        JsonObject b = fix.Begin["custodianBaseline"]!.AsObject();
        return new RunStep(next, new JsonObject
        {
            ["operationId"] = applyId, ["operationStatus"] = RunOperationStatuses.Running, ["fixOperationId"] = fixOperationId, ["proposalDigest"] = digest,
            ["renderingDigest"] = held.Rendering.Digest, ["sourceIdAtBegin"] = m.SourceId,
            ["bindings"] = new JsonObject
            {
                ["runId"] = run.RunId, ["operationId"] = fixOperationId, ["fixId"] = fix.Begin["fixId"]?.DeepClone(), ["taskDigest"] = fix.Begin["taskDigest"]?.DeepClone(),
                ["boundaryDigest"] = fix.Begin["boundaryDigest"]?.DeepClone(),
                ["baseline"] = new JsonObject { ["reviewId"] = b["reviewId"]?.DeepClone(), ["sourceId"] = b["sourceId"]?.DeepClone(), ["exportDigest"] = b["exportDigest"]?.DeepClone(), ["manifestDigest"] = b["manifestDigest"]?.DeepClone() },
            },
        });
    }

    /// <summary>The confirmed content an application's begin returns (attached to the result, never stored in the run's
    /// transition log): the custodian's canonical changes with their bytes.</summary>
    private static JsonArray ContentForResult(ApplyPre? pre) => (JsonArray)(pre?.Held?.Content?.DeepClone() ?? new JsonArray());

    // ---- op_finish of an application ----

    /// <summary>Finish an application: <c>applied</c> or <c>apply_failed</c> as the engine reports it (a claim), with the
    /// custodian's own measurement of the post-apply source; the proposal's content is retired.</summary>
    private RunStep ApplyFinishStep(RunRecord run, RunOperation op, JsonObject outcome, string runStatus, DateTime now, ApplyPre? pre)
    {
        string status = (string)outcome["status"]!;
        ApplyMeasure? m = pre?.Measured;
        var stored = new JsonObject
        {
            ["status"] = status, ["files"] = outcome["files"]!.DeepClone(), ["detail"] = outcome["detail"]?.DeepClone(),
            ["sourceIdAfter"] = m?.SourceId, ["sourceStableAfter"] = m?.SourceId is null ? null : m.Stable, ["measurementProblem"] = m?.SourceId is null ? $"{m?.Code}: {m?.Detail}" : null,
        };
        RunRecord next = RetireProposalOf(run with { Operations = ReplaceOperation(run, op with { Status = status, EndedAt = Iso(now), Outcome = stored }), Status = runStatus },
            (string)op.Begin["fixOperationId"]!, status, now);
        return new RunStep(next, new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = status, ["sourceIdAfter"] = m?.SourceId });
    }

    /// <summary>Retire the fix's proposal (its content queued for removal outside the gate). Callers hold <see cref="Gate"/>.</summary>
    private RunRecord RetireProposalOf(RunRecord run, string fixOperationId, string reason, DateTime now)
    {
        RunOperation? fix = run.Operations.FirstOrDefault(o => o.OperationId == fixOperationId && o.Kind == "fix");
        if (fix is null || ProposalOf(fix) is not { } p || p["retiredAt"] is not null) return run;
        var outcome = (JsonObject)fix.Outcome!.DeepClone();
        outcome["proposal"]!["retiredAt"] = Iso(now);
        outcome["proposal"]!["retiredReason"] = reason;
        _retiredProposals.Enqueue(ProposalPath(run.RepoKey, run.RunId, fixOperationId));
        return run with { Operations = ReplaceOperation(run, fix with { Outcome = outcome }) };
    }

    // ---- recover: an application whose writer is gone ----

    /// <summary>An application whose writer is gone is <c>apply_interrupted</c> — an incident the custodian records itself,
    /// never <c>applied</c>; the confirmation stays consumed and the content is retired.</summary>
    private RunStep ApplyInterruptedStep(RunRecord run, RunOperation op, DateTime now)
    {
        RequireIncidentRoom(run, 1);
        var inc = new RunIncident(NewId("inc", run.Incidents.Count + 1), ApplyInterrupted, op.OperationId, null,
            "the application's writer is gone before it finished; the working tree may hold some of the confirmed content — reconcile it (`code-parley fix reconcile`)", Iso(now), "custodian");
        RunOperation interrupted = op with { Status = ApplyInterrupted, EndedAt = Iso(now), Outcome = new JsonObject { ["status"] = ApplyInterrupted, ["incidentId"] = inc.IncidentId } };
        RunRecord next = RetireProposalOf(run with
        {
            Operations = ReplaceOperation(run, interrupted), Incidents = [.. run.Incidents, inc], Status = run.IsTerminal ? run.Status : RunStatuses.Idle,
        }, (string)op.Begin["fixOperationId"]!, ApplyInterrupted, now);
        return new RunStep(next, new JsonObject { ["operationId"] = op.OperationId, ["operationStatus"] = ApplyInterrupted, ["incidentId"] = inc.IncidentId });
    }

    // ---- apply_reconcile ----

    /// <summary>Record the implementer's reconciliation of an interrupted application (restore or leave), with what it
    /// observed and the custodian's own measurement of the source afterwards. Reduce-only: it records, it authorizes nothing.</summary>
    private RunStep ApplyReconcileStep(RunRecord run, RunRequest req, DateTime now, ApplyPre? pre)
    {
        JsonObject f = req.Fields;
        string operationId = (string)f["operationId"]!;
        RunOperation op = run.Operations.FirstOrDefault(o => o.OperationId == operationId && o.Kind == "apply")
            ?? throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"the run has no application {operationId}");
        if (op.Status != ApplyInterrupted)
            throw new CustodianRefusal(ErrorCodes.OperationNotRunning, op.Status == RunOperationStatuses.Running
                ? $"application {operationId} is still running; it is reconciled only once its writer is gone and it is recorded interrupted (recover)"
                : $"application {operationId} is {op.Status}; only an interrupted application is reconciled");
        string status = (string)f["choice"]! == "restore" ? ApplyInterruptedRestored : ApplyInterruptedLeft;
        ApplyMeasure? m = pre?.Measured;
        var outcome = (JsonObject)op.Outcome!.DeepClone();
        outcome["status"] = status;
        outcome["reconciliation"] = new JsonObject
        {
            ["choice"] = f["choice"]!.DeepClone(), ["observed"] = f["observed"]!.DeepClone(), ["files"] = f["files"]!.DeepClone(), ["detail"] = f["detail"]?.DeepClone(),
            ["at"] = Iso(now), ["sourceIdAfter"] = m?.SourceId, ["measurementProblem"] = m?.SourceId is null ? $"{m?.Code}: {m?.Detail}" : null,
        };
        RunRecord next = run with { Operations = ReplaceOperation(run, op with { Status = status, Outcome = outcome }) };
        return new RunStep(next, new JsonObject { ["operationId"] = operationId, ["operationStatus"] = status, ["sourceIdAfter"] = m?.SourceId });
    }
}
