using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>The custodian's read of a delegated fix's baseline capture, taken before the gate (op_begin and op_finish of a
/// fix): its published export re-hashed against what the custodian recorded at publication, and the manifest's
/// <c>tree</c> files (null when the export or its manifest cannot be vouched for).</summary>
/// <summary>Phase 5 (§4.12): the host's Codex sandbox basis measured before the gate for a review or fix begin — the
/// measurement, or the refusal the measurement raised (applied in the transition, in order with its other checks).</summary>
internal sealed record IsolationBasisRead(System.Text.Json.Nodes.JsonObject? Basis, CustodianRefusal? Refusal);

internal sealed record FixBaselineRead(string ReviewId, bool Unchanged, string Detail, IReadOnlyDictionary<string, BaselineFile>? Tree);

/// <summary>
/// Phase 4 Increment 2 (contract §3.2, §3.4): the delegated fix. A <c>fix</c> operation binds — at <c>op_begin</c> — the run,
/// the task digest, the boundary (by digest) and the BASELINE: the published capture of a finished review the custodian
/// holds, re-hashed and read from its own manifest. Its budget is the run's declared <c>maxFixes</c> under
/// <see cref="CustodianConstants.MaxFixesPerRun"/>. It rests on an operator-confirmed FIX self-test (mode FIX, bound to the
/// approved Codex binary), never on the S1 reviewer confirmation. At <c>op_finish</c> the engine submits the proposal
/// CONTENT; the custodian validates it itself against the boundary and its own baseline (<see cref="FixRules"/>), trusting
/// no engine digest or preimage, and holds valid content in its private store (<c>fix-proposals</c>) under the digest it
/// computes — the operation is then <c>proposed</c>, which is not progress and authorizes no continuation or wake. A
/// proposal is retired (its content removed) when its run ends or its lifetime is over; while it is pending, its baseline
/// export is kept. Rendering, confirmation and application are Increment 3.
/// </summary>
internal sealed partial class GrantLedger
{
    /// <summary>Proposal files retired under the gate, removed once it is released (<see cref="DrainRetiredExports"/>).</summary>
    private readonly ConcurrentQueue<string> _retiredProposals = new();

    /// <summary>The schema of the fix-proposal content the custodian holds (Phase 6 L-1: read only in this schema).</summary>
    internal const string FixProposalContentSchema = "codeparley.custodian-fix-proposal-content.v1";
    internal const string ProposalRetiredRunEnded = "run_ended", ProposalRetiredExpired = "expired";

    // ---- the baseline, read before the gate ----

    /// <summary>For the begin or finish of a fix: the baseline capture it names (op_begin) or was bound to (op_finish), read
    /// outside the gate. Null when the request is neither (the transition decides everything else under the gate).</summary>
    private FixBaselineRead? ReadFixBaseline(string repoKey, RunRequest req)
    {
        string? reviewId;
        JsonObject? begin = null;
        string operationId = "";
        lock (EnterGate())
        {
            RunRecord? run = ReadRun(repoKey, req.RunId);
            if (run is null) return null;
            if (req.Kind == RunKinds.OpBegin)
            {
                if ((string?)req.Fields["operationKind"] != "fix") return null;
                reviewId = (string?)req.Fields["baselineReviewId"];
            }
            else if (req.Kind == RunKinds.OpFinish)
            {
                RunOperation? op = run.Operations.FirstOrDefault(o => o.OperationId == (string?)req.Fields["operationId"]);
                if (op is null || op.Kind != "fix") return null;
                reviewId = (string?)op.Begin["custodianBaseline"]?["reviewId"];
            }
            else return null;
            RunReview? review = run.Reviews.FirstOrDefault(r => r.ReviewId == reviewId);
            if (review is not null)
            {
                begin = (JsonObject)review.Begin.DeepClone();
                operationId = review.OperationId;
            }
        }
        return ReadExportTree(reviewId ?? "", operationId, begin);
    }

    // ---- op_begin ----

    /// <summary>The run's fix budget: its declared maxFixes (none declared: 0) under the custodian's cap.</summary>
    private static int FixLimit(RunRecord run) => Math.Min(run.Declaration.Budgets.MaxFixes ?? 0, CustodianConstants.MaxFixesPerRun);
    private static int FixesBegun(RunRecord run) => run.Operations.Count(o => o.Kind == "fix");

    /// <summary>
    /// Begin a delegated fix: P4-A — the repository's protected configuration in force with an approved Codex installation;
    /// FIX vs S1 — an operator-confirmed FIX self-test for this Codex version, binary, backend and fixer profile; the
    /// engine's Codex image the approved one; the run's fix budget; then the baseline — a finished review of this run whose
    /// published capture the custodian still holds and found unchanged. The custodian binds the boundary (by digest), the
    /// task digest and its own record of the baseline capture.
    /// </summary>
    private RunStep FixBeginStep(RunRecord run, RunRequest req, DateTime now, OperationWriter writer, int seq, FixBaselineRead? read, IsolationBasisRead? basisNow)
    {
        JsonObject f = req.Fields;
        RepositoryConfig cfg = RequireUsableConfig(run.RepoKey, "a delegated fix");
        if (cfg.CodexInstallation is not { } install)
            throw new CustodianRefusal(ErrorCodes.ConfigNotHeld, $"the repository's protected configuration has no approved Codex installation; a delegated fix is refused — the operator sets one with `{OperatorWording.Cli} setup --repo <path>`");
        (string isoKind, string isoId, int isoRevision) = RequireFixBasis(f["isolation"]!.AsObject(), install.Sha256, basisNow);
        if ((string)f["codexSha256"]! != install.Sha256)
            throw new CustodianRefusal(ErrorCodes.ConfigMismatch, "the Codex image the engine reports is not the approved installation; nothing was begun");
        int used = FixesBegun(run);
        int limit = FixLimit(run);
        if (used >= limit) throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"fixes: {used} of {limit} used");
        string fixId = (string)f["fixId"]!;
        if (run.Operations.Any(o => o.Kind == "fix" && (string?)o.Begin["fixId"] == fixId)) throw new ArgumentException($"fix id {fixId} was already used in this run");
        string reviewId = (string)f["baselineReviewId"]!;
        RunReview? review = run.Reviews.FirstOrDefault(r => r.ReviewId == reviewId);
        RunOperation? reviewOp = review is null ? null : run.Operations.FirstOrDefault(o => o.OperationId == review.OperationId);
        if (review?.Begin["custodianCapture"] is not JsonObject cap || cap["retiredAt"] is not null || reviewOp is null || RunOperationStatuses.IsActive(reviewOp.Status))
            throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"review {reviewId} is not a finished review of this run whose published capture the custodian still holds; nothing was begun");
        if (read is null || read.ReviewId != reviewId || !read.Unchanged || read.Tree is null)
            throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, $"the published capture of review {reviewId} cannot be vouched for as the fix's baseline ({read?.Detail ?? "it was not read"}); nothing was begun");
        JsonObject boundary = f["boundary"]!.AsObject();
        string boundaryDigest = FixRules.BoundaryDigest(boundary);
        var baseline = new JsonObject
        {
            ["reviewId"] = reviewId, ["reviewOperationId"] = review.OperationId, ["sourceId"] = review.Begin["sourceId"]?.DeepClone(), ["captureId"] = review.Begin["captureId"]?.DeepClone(),
            ["exportDigest"] = review.Begin["exportDigest"]?.DeepClone(), ["manifestDigest"] = review.Begin["manifestDigest"]?.DeepClone(), ["captureDigest"] = review.Begin["captureDigest"]?.DeepClone(),
            ["treeFiles"] = read.Tree.Count, ["treeDigest"] = FixRules.TreeDigest(read.Tree),
        };
        var begin = (JsonObject)f.DeepClone();
        begin["boundaryDigest"] = boundaryDigest;
        begin["custodianBaseline"] = baseline.DeepClone();
        var op = new RunOperation(NewId("fop", seq), seq, "fix", RunOperationStatuses.Running, Iso(now), null, writer, begin, null,
            new OperationPin(cfg.ConfigRevision, cfg.ConfigDigest, isoKind, isoId, isoRevision, null, install.Sha256));
        return new RunStep(run with { Operations = [.. run.Operations, op], Status = RunStatuses.Fixing }, new JsonObject
        {
            ["operationId"] = op.OperationId, ["fixId"] = fixId, ["configRevision"] = cfg.ConfigRevision, ["operationStatus"] = RunOperationStatuses.Running,
            ["boundaryDigest"] = boundaryDigest,
            ["baseline"] = new JsonObject { ["reviewId"] = reviewId, ["sourceId"] = baseline["sourceId"]?.DeepClone(), ["treeFiles"] = read.Tree.Count },
            ["fixesUsed"] = used + 1, ["maxFixes"] = limit,
        });
    }

    // ---- op_finish ----

    /// <summary>
    /// Finish a delegated fix: what the engine reports is recorded as its claim; only a <c>completed</c> fix submits content,
    /// which the custodian validates itself against the boundary it bound and its own baseline capture (read again before
    /// the gate, and still the tree it bound). Valid content is held in the custodian's private store under the
    /// custodian-computed digest (<c>proposed</c>); anything else is <c>rejected</c> with the custodian's violations.
    /// </summary>
    private RunStep FixFinishStep(RunRecord run, RunOperation op, JsonObject outcome, string runStatus, DateTime now, FixBaselineRead? read)
    {
        string reported = (string)outcome["status"]!;
        JsonArray changes = outcome["changes"]!.AsArray();
        if ((reported == "completed") != (changes.Count > 0)) throw new ArgumentException("fields.outcome.changes are submitted with a completed fix, and only with one");
        JsonObject begin = op.Begin;
        JsonObject boundary = begin["boundary"]!.AsObject();
        JsonObject baseline = begin["custodianBaseline"]!.AsObject();
        var stored = new JsonObject
        {
            ["status"] = reported, ["reportedStatus"] = reported, ["scan"] = outcome["scan"]?.DeepClone(), ["detail"] = outcome["detail"]?.DeepClone(),
            ["proposal"] = null, ["violations"] = new JsonArray(), ["violationCount"] = 0,
        };
        string opStatus = reported;
        // The basis the fix was begun under, re-checked at its finish (as a review's at its completion): the FIX
        // confirmation still in force, the repository's configuration still usable with the same Codex installation.
        string? basisProblem = reported == "completed" ? FixBasisProblem(ReadConfigRecords(), run.RepoKey, op.Pin) : null;
        if (basisProblem is not null)
        {
            opStatus = RunOperationStatuses.Rejected;
            stored["status"] = opStatus;
            stored["violations"] = new JsonArray(new JsonObject { ["kind"] = "basis_changed", ["path"] = null });
            stored["violationCount"] = 1;
            stored["basisProblem"] = basisProblem;
        }
        else if (reported == "completed")
        {
            bool intact = read is not null && read.ReviewId == (string?)baseline["reviewId"] && read.Unchanged && read.Tree is not null && FixRules.TreeDigest(read.Tree) == (string?)baseline["treeDigest"];
            (List<FixViolation> violations, List<FixCanonicalChange>? canonical, long total) = intact
                ? FixRules.Validate(boundary, read!.Tree!, changes)
                : ([new FixViolation("baseline_unavailable", null)], null, 0);
            if (canonical is null)
            {
                opStatus = RunOperationStatuses.Rejected;
                stored["status"] = opStatus;
                stored["violations"] = new JsonArray([.. violations.Take(CustodianConstants.MaxFixViolationsReported).Select(v => (JsonNode)new JsonObject { ["kind"] = v.Kind, ["path"] = v.Path })]);
                stored["violationCount"] = violations.Count;
            }
            else
            {
                opStatus = RunOperationStatuses.Proposed;
                var bound = new JsonObject
                {
                    ["reviewId"] = baseline["reviewId"]?.DeepClone(), ["sourceId"] = baseline["sourceId"]?.DeepClone(),
                    ["exportDigest"] = baseline["exportDigest"]?.DeepClone(), ["manifestDigest"] = baseline["manifestDigest"]?.DeepClone(),
                };
                string digest = FixRules.ProposalDigest(run.RunId, op.OperationId, (string)begin["fixId"]!, (string)begin["taskDigest"]!, (string)begin["boundaryDigest"]!, bound, canonical);
                stored["status"] = opStatus;
                stored["proposal"] = new JsonObject
                {
                    ["proposalDigest"] = digest, ["createdAt"] = Iso(now), ["expiresAt"] = Iso(now.AddSeconds((long)RunFields.Integer(boundary["proposalLifetimeSeconds"])!)),
                    ["changeCount"] = canonical.Count, ["totalBytes"] = total,
                    ["changes"] = new JsonArray([.. canonical.Select(c => (JsonNode)FixRules.ChangeSummary(c))]),
                    ["retiredAt"] = null, ["retiredReason"] = null,
                };
                // The canonical content goes to the custodian's private store in this hold, before the record that names it.
                WriteProposal(run.RepoKey, run.RunId, op.OperationId, digest, canonical);
            }
        }
        JsonObject? p = stored["proposal"] as JsonObject;
        return new RunStep(run with { Operations = ReplaceOperation(run, op with { Status = opStatus, EndedAt = Iso(now), Outcome = stored }), Status = runStatus }, new JsonObject
        {
            ["operationId"] = op.OperationId, ["operationStatus"] = opStatus,
            ["proposal"] = p is null ? null : new JsonObject { ["proposalDigest"] = p["proposalDigest"]?.DeepClone(), ["changeCount"] = p["changeCount"]?.DeepClone(), ["totalBytes"] = p["totalBytes"]?.DeepClone(), ["expiresAt"] = p["expiresAt"]?.DeepClone() },
            ["violations"] = stored["violations"]!.DeepClone(), ["violationCount"] = stored["violationCount"]!.DeepClone(),
        });
    }

    /// <summary>Is the basis a fix was begun under still in force? null: yes; else why not.</summary>
    private static string? FixBasisProblem(ConfigRecordsFile file, string repoKey, OperationPin? pin)
    {
        if (pin is null) return "isolation_basis_revoked";
        if (IsolationBasisProblem(file, pin.IsolationKind, pin.IsolationRecordId) is { } iso) return iso;
        RepositoryConfig? cur = file.CurrentOf(repoKey);
        if (cur is null || cur.IsRevoked) return "config_changed_since_fix";
        if (cur.IsLapsed) return "config_lapsed";
        if (cur.CodexInstallation?.Sha256 != pin.CodexSha256) return "config_changed_since_fix";
        return null;
    }

    // ---- the private store of proposal content ----

    private static string ProposalPath(string repoKey, string runId, string operationId) => StorePaths.FixProposalPath(repoKey, runId, operationId);

    /// <summary>The canonical content of a proposal, in the custodian's own store (inherits its protected DACL). Callers hold
    /// <see cref="Gate"/>.</summary>
    private static void WriteProposal(string repoKey, string runId, string operationId, string digest, List<FixCanonicalChange> changes)
    {
        var o = new JsonObject
        {
            ["schema"] = FixProposalContentSchema, ["repoKey"] = repoKey, ["runId"] = runId, ["operationId"] = operationId, ["proposalDigest"] = digest,
            ["changes"] = new JsonArray([.. changes.Select(c => { JsonObject s = FixRules.ChangeSummary(c); s["content"] = c.Content; return (JsonNode)s; })]),
        };
        AtomicWrite(ProposalPath(repoKey, runId, operationId), o.ToJsonString());
    }

    /// <summary>TEST only (the shared corpus): what the custodian holds in its private store for a fix — whether content is
    /// held, its paths and the preimages it recorded from its own baseline.</summary>
    internal static JsonObject HeldProposalForTest(string repoKey, string runId, string operationId)
    {
        string path = ProposalPath(repoKey, runId, operationId);
        if (!File.Exists(path)) return new JsonObject { ["held"] = false };
        JsonObject p = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        JsonArray changes = p["changes"] as JsonArray ?? [];
        return new JsonObject
        {
            ["held"] = true, ["proposalDigest"] = p["proposalDigest"]?.DeepClone(),
            ["paths"] = new JsonArray([.. changes.Select(c => (JsonNode?)c!["path"]?.DeepClone())]),
            ["preimages"] = new JsonArray([.. changes.Select(c => c!["preimage"]?.DeepClone())]),
        };
    }

    // ---- retention ----

    private static JsonObject? ProposalOf(RunOperation o) => o.Outcome?["proposal"] as JsonObject;

    /// <summary>Phase 4 Increment 3: a fix whose proposal still waits for the owner or for its application (proposed or
    /// confirmed) — its content and its baseline are kept, and it expires with its lifetime.</summary>
    private static bool AwaitsOwnerOrApplication(RunOperation o) => o.Kind == "fix" && o.Status is RunOperationStatuses.Proposed or FixConfirmed;

    /// <summary>The reviews whose published capture a fix still needs: one in flight, or one whose proposal is not retired
    /// and still waits for the owner or its application (Increment 3 renders and applies from it).</summary>
    private static IEnumerable<string> FixBaselinesHeld(RunRecord run)
        => run.Operations.Where(o => o.Kind == "fix" && (RunOperationStatuses.IsActive(o.Status) || (AwaitsOwnerOrApplication(o) && ProposalOf(o) is { } p && p["retiredAt"] is null)))
            .Select(o => (string?)o.Begin["custodianBaseline"]?["reviewId"] ?? "");

    private static int RetiredProposals(RunRecord run) => run.Operations.Count(o => ProposalOf(o)?["retiredAt"] is not null);

    /// <summary>Retire every proposal whose run ended or whose lifetime is over (the record says when and why; the held content
    /// is queued for removal outside the gate). The same instance when nothing changes. Callers hold <see cref="Gate"/>.</summary>
    private RunRecord RetireFixProposals(RunRecord run, DateTime now)
    {
        bool terminal = run.IsTerminal;
        // Phase 4 Increment 3: a confirmed proposal expires as a proposed one; an ended run also retires one whose application
        // consumed it (the content was handed to that application).
        var due = run.Operations.Where(o => o.Kind == "fix" && (AwaitsOwnerOrApplication(o) || (terminal && o.Status == FixConsumed)) && ProposalOf(o) is { } p && p["retiredAt"] is null
            && (terminal || ParseTime((string)p["expiresAt"]!) <= now)).Select(o => o.OperationId).ToHashSet(StringComparer.Ordinal);
        if (due.Count == 0) return run;
        foreach (string id in due) _retiredProposals.Enqueue(ProposalPath(run.RepoKey, run.RunId, id));
        return run with
        {
            Operations = [.. run.Operations.Select(o =>
            {
                if (!due.Contains(o.OperationId)) return o;
                var outcome = (JsonObject)o.Outcome!.DeepClone();
                var p = (JsonObject)outcome["proposal"]!;
                p["retiredAt"] = Iso(now);
                p["retiredReason"] = terminal ? ProposalRetiredRunEnded : ProposalRetiredExpired;
                return o with { Outcome = outcome };
            })],
        };
    }

    /// <summary>The proposal files a held run still references: a fix whose proposal is not retired — proposed, confirmed,
    /// or consumed by an application that has not ended.</summary>
    private static IEnumerable<string> ReferencedProposals(RunRecord run)
        => run.Operations.Where(o => o.Kind == "fix" && o.Status is RunOperationStatuses.Proposed or FixConfirmed or FixConsumed && ProposalOf(o) is { } p && p["retiredAt"] is null)
            .Select(o => Path.GetFullPath(ProposalPath(run.RepoKey, run.RunId, o.OperationId)));

    /// <summary>
    /// Remove every file under <see cref="StorePaths.FixProposalsDir"/> that no held run references — a proposal written by a
    /// finish whose run record was never written (the custodian stopped between the two), or a leftover temporary file.
    /// UNDER the gate (callers hold it): a finish writes its file and its record in one hold, so nothing referenced is ever
    /// removed. Returns the number removed.
    /// </summary>
    private int SweepOrphanProposals(HashSet<string> referenced)
    {
        if (!Monitor.IsEntered(Gate)) throw new InvalidOperationException("orphan proposals are swept under the ledger lock");
        if (!Directory.Exists(StorePaths.FixProposalsDir)) return 0;
        int removed = 0;
        foreach (string file in Directory.EnumerateFiles(StorePaths.FixProposalsDir, "*", SearchOption.AllDirectories))
        {
            if (referenced.Contains(Path.GetFullPath(file))) continue;
            try { File.Delete(file); removed++; Audit($"fix_proposal_orphan_removed file={Path.GetFileName(file)}"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Audit($"fix_proposal_orphan_remove_failed file={Path.GetFileName(file)}: {e.GetType().Name}"); }
        }
        return removed;
    }

    /// <summary>TEST only (the shared corpus): a proposal file no run references, as a custodian stopped between writing the
    /// content and the run record would leave it.</summary>
    internal static void WriteOrphanProposalForTest(string repoKey, string runId, string operationId)
        => AtomicWrite(ProposalPath(repoKey, runId, operationId), "{\"schema\":\"" + FixProposalContentSchema + "\",\"orphan\":true}");

    /// <summary>Remove the proposal files retired under the gate. Called only OUTSIDE the gate.</summary>
    private void DrainRetiredProposals()
    {
        while (_retiredProposals.TryDequeue(out string? file))
        {
            try { File.Delete(file); Audit($"fix_proposal_removed op={Path.GetFileNameWithoutExtension(file)} (retired)"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Audit($"fix_proposal_remove_failed op={Path.GetFileNameWithoutExtension(file)}: {e.GetType().Name}"); }
        }
    }

    /// <summary>The custodian's re-hash of a published export and its capture record against what it recorded (shared by
    /// the finish of a captured review and a fix's baseline read). Outside the gate.</summary>
    private static ExportRehash RehashExport(string operationId, JsonObject begin)
    {
        string exportDir = (string)begin["custodianCapture"]!["exportPath"]!;
        string capturePath = (string)begin["custodianCapture"]!["capturePath"]!;
        try
        {
            var files = new List<(string, long, string)>();
            foreach (string f in Directory.EnumerateFiles(exportDir, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = false }))
            {
                byte[] bytes = File.ReadAllBytes(f);
                files.Add((Path.GetRelativePath(exportDir, f).Replace('\\', '/'), bytes.LongLength, Convert.ToHexStringLower(SHA256.HashData(bytes))));
            }
            bool exportSame = ExportPaths.ExportDigest(files) == (string)begin["exportDigest"]!;
            bool recordSame = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(capturePath))) == (string)begin["captureDigest"]!;
            return new ExportRehash(operationId, exportSame && recordSame,
                exportSame && recordSame ? $"{files.Count} files unchanged" : $"{(exportSame ? "" : "the export's files differ")}{(!exportSame && !recordSame ? "; " : "")}{(recordSame ? "" : "the capture record differs")}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new ExportRehash(operationId, false, $"the export could not be read again ({e.GetType().Name}: {Bounded(e.Message)})");
        }
    }
}
