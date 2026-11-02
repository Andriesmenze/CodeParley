using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;

namespace CodeParley.Custodian.Ledger;

/// <summary>What an accepted review changes: the run's items after it (new items appended, prior items assessed),
/// its replies, the ids of its new items, and every item it touched.</summary>
internal sealed record AppliedReview(List<RunItem> Items, List<JsonObject> Replies, List<string> NewItemIds, List<RunItem> Changed);

/// <summary>
/// P3.4C-3: the custodian-derived review acceptance (contract §4.4) and the item lifecycle table (§4.5), mirrored from
/// the engine's rules (review-operation.ts; policy/carry-forward.ts; policy/triage.ts) and held to them by the shared
/// corpus. PURE: it decides from the custodian's own records and the validated outcome; a client never sets
/// <c>accepted</c>, an item's status or an assessment's effect, and a payload that contradicts the table is refused
/// (INVALID_ITEM_TRANSITION) with nothing applied.
/// </summary>
internal static class RunLifecycle
{
    /// <summary>Triage ranks (policy/triage.ts): a superseding finding must rank at least as high as the item it
    /// supersedes.</summary>
    internal static readonly IReadOnlyDictionary<string, int> Rank = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["established_defect"] = 3, ["serious_concern"] = 2, ["blocking_question"] = 2, ["minor_concern"] = 1, ["question"] = 0, ["note"] = 0,
    };

    private static readonly IReadOnlySet<string> FindingTriages = new HashSet<string>(StringComparer.Ordinal) { "established_defect", "serious_concern", "minor_concern", "note" };
    private static readonly IReadOnlySet<string> QuestionTriages = new HashSet<string>(StringComparer.Ordinal) { "blocking_question", "question" };

    /// <summary>§4.4: why a finished review is NOT accepted (empty: accepted). Accepted iff the outcome is
    /// <c>completed</c> with valid output, current at completion, the run was not stopped before the finish, and no
    /// invalidating incident is recorded for the operation.</summary>
    internal static List<string> NotAcceptedReasons(JsonObject outcome, bool runTerminal, IEnumerable<string> incidentKinds)
    {
        var reasons = new List<string>();
        string status = (string)outcome["status"]!;
        bool completed = status == "completed";
        if (!completed) reasons.Add($"status:{status}");
        else if (!(bool)outcome["outputValid"]!) reasons.Add("output_invalid");
        else if (!(bool)outcome["currentAtCompletion"]!) reasons.Add("not_current_at_completion");
        if (runTerminal) reasons.Add("run_stopped");
        foreach (string kind in incidentKinds.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
            if (RunEnums.InvalidatingIncidents.Contains(kind)) reasons.Add($"incident:{kind}");
        return reasons;
    }

    /// <summary>The last source an item was raised on or assessed <c>still_present</c> on (carry-forward.ts
    /// <c>lastPresentSource</c>).</summary>
    internal static string LastPresentSource(RunItem it)
    {
        string s = it.SourceId;
        foreach (RunItemAssessment a in it.Assessments) if (a.Assessment == "still_present") s = a.SourceId;
        return s;
    }

    /// <summary>§4.5: apply an ACCEPTED review — create its new items, record exactly one assessment for every item
    /// that was open before it (computing the effect and the resulting status itself), and record its replies. Every
    /// assessment, reply and response touching an item raises its revision by one.</summary>
    internal static AppliedReview ApplyAccepted(RunRecord run, RunReview review, string sourceId, JsonObject outcome, string now)
    {
        var byId = run.Items.ToDictionary(i => i.ItemId, StringComparer.Ordinal);
        List<RunItem> priorOpen = run.Items.Where(i => i.Status == "open").ToList();
        var priorOpenIds = priorOpen.Select(i => i.ItemId).ToHashSet(StringComparer.Ordinal);

        // 1. New items (accepted review only): status open iff an open-class triage, else informational.
        JsonArray newArr = outcome["newItems"]!.AsArray();
        if (run.Items.Count + newArr.Count > CustodianConstants.MaxItemsPerRun)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"a run keeps at most {CustodianConstants.MaxItemsPerRun} items");
        var created = new List<RunItem>();
        var declaredRestates = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (JsonObject n in newArr.Cast<JsonObject>())
        {
            string id = (string)n["itemId"]!;
            if (byId.ContainsKey(id)) throw Invalid($"item {id} already exists");
            string kind = (string)n["itemKind"]!;
            string triage = (string)n["triage"]!;
            bool question = kind == "question";
            if (!(question ? QuestionTriages : FindingTriages).Contains(triage)) throw Invalid($"a {kind} cannot be triaged {triage}");
            string status = RunEnums.OpenTriages.Contains(triage) ? "open" : "informational";
            if ((string)n["status"]! != status) throw Invalid($"item {id} is created {status} (triage {triage}), not {(string)n["status"]!}");
            string? relatedPrior = (string?)n["relatedPriorId"];
            string? relatedFinding = (string?)n["relatedFindingId"];
            if (question && (n["severity"] is not null || n["claimType"] is not null || n["category"] is not null || n["confidence"] is not null || n["impacts"]!.AsArray().Count > 0 || relatedPrior is not null))
                throw Invalid($"question {id} carries finding fields");
            if (!question && relatedFinding is not null) throw Invalid($"finding {id} names a related finding");
            if (relatedPrior is not null && !priorOpenIds.Contains(relatedPrior)) throw Invalid($"item {id} relates to {relatedPrior}, which was not open before this review");
            List<string> restates = n["restates"]!.AsArray().Select(x => (string)x!).ToList();
            foreach (string r in restates) if (!byId.ContainsKey(r)) throw Invalid($"item {id} restates {r}, which the custodian does not hold");
            declaredRestates[id] = restates;
            created.Add(new RunItem(
                ItemId: id, ItemKind: kind, ReviewId: review.ReviewId, Round: review.Round, SourceId: sourceId, Triage: triage,
                Severity: (string?)n["severity"], ClaimType: (string?)n["claimType"], Category: (string?)n["category"],
                Impacts: n["impacts"]!.AsArray().Select(x => (string)x!).ToList(), Confidence: (string?)n["confidence"],
                Status: status, SupersededBy: null, Supersedes: [], Restates: [], RelatedPriorId: relatedPrior, RelatedFindingId: relatedFinding,
                Assessments: [], ItemRevision: 1, CreatedAt: now));
        }
        var newById = created.ToDictionary(i => i.ItemId, StringComparer.Ordinal);
        foreach (RunItem q in created.Where(i => i.ItemKind == "question" && i.RelatedFindingId is not null))
            if (!newById.TryGetValue(q.RelatedFindingId!, out RunItem? f) || f.ItemKind != "finding")
                throw Invalid($"question {q.ItemId} relates to {q.RelatedFindingId}, which is not a finding of this review");

        // 2. Exactly one assessment entry for every item open before this review (and none for another item).
        var entries = new Dictionary<string, (string Assessment, string? By)>(StringComparer.Ordinal);
        foreach (JsonObject a in outcome["assessments"]!.AsArray().Cast<JsonObject>())
            entries[(string)a["itemId"]!] = ((string)a["assessment"]!, (string?)a["supersededByItemId"]);
        if (!entries.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(priorOpenIds))
            throw Invalid("the assessments must cover exactly the items open before this review, one entry each");

        var supersedes = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var restatedBy = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var assessed = new Dictionary<string, RunItem>(StringComparer.Ordinal);
        foreach (RunItem it in priorOpen)
        {
            (string a, string? by) = entries[it.ItemId];
            string status = it.Status;
            string? supersededBy = it.SupersededBy;
            string effect;
            switch (a)
            {
                case "still_present": effect = "kept_open"; break;
                case "no_longer_assessable": effect = "kept_open:not_assessable"; break;
                case "not_assessed": effect = "kept_open:not_assessed"; break;
                case "not_presented": effect = "kept_open:not_presented"; break;
                case "apparently_resolved":
                    if (LastPresentSource(it) == sourceId) effect = "ignored:same_source";
                    else { status = "reported_resolved"; effect = "status:reported_resolved"; }
                    break;
                case "superseded":
                    RunItem? sup = by is not null && newById.TryGetValue(by, out RunItem? s) && s.ItemKind == "finding" ? s : null;
                    if (sup is null) effect = "ignored:no_superseding_finding";
                    else if (!RunEnums.OpenTriages.Contains(sup.Triage) || Rank[sup.Triage] < Rank[it.Triage])
                    {
                        effect = "ignored:weaker_superseding_finding";
                        Add(restatedBy, sup.ItemId, it.ItemId);
                    }
                    else
                    {
                        status = "superseded";
                        supersededBy = sup.ItemId;
                        effect = $"status:superseded_by:{sup.ItemId}";
                        Add(supersedes, sup.ItemId, it.ItemId);
                    }
                    break;
                default: throw Invalid($"unknown assessment {a}");
            }
            string recorded = a == "not_presented" ? "not_assessed" : a;
            assessed[it.ItemId] = it with
            {
                Status = status, SupersededBy = supersededBy,
                Assessments = [.. it.Assessments, new RunItemAssessment(review.ReviewId, review.Round, sourceId, recorded, effect)],
                ItemRevision = it.ItemRevision + 1,
            };
        }

        // 3. The new items' lineage: what they supersede, and what they restate (declared, then from a supersession
        // ignored as weaker), never both.
        for (int k = 0; k < created.Count; k++)
        {
            RunItem n = created[k];
            List<string> sup = supersedes.GetValueOrDefault(n.ItemId) ?? [];
            List<string> links = [.. declaredRestates.GetValueOrDefault(n.ItemId) ?? [], .. restatedBy.GetValueOrDefault(n.ItemId) ?? []];
            created[k] = n with { Supersedes = sup, Restates = links.Distinct(StringComparer.Ordinal).Where(x => !sup.Contains(x)).ToList() };
        }

        // 4. Replies (accepted review only), each to an item the custodian already holds.
        JsonArray replyArr = outcome["replies"]!.AsArray();
        if (run.Replies.Count + replyArr.Count > CustodianConstants.MaxRepliesPerRun)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"a run keeps at most {CustodianConstants.MaxRepliesPerRun} reviewer replies");
        var existingReplies = run.Replies.Select(r => (string)r["replyId"]!).ToHashSet(StringComparer.Ordinal);
        var replies = new List<JsonObject>();
        var bumps = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (JsonObject r in replyArr.Cast<JsonObject>())
        {
            string replyId = (string)r["replyId"]!;
            string itemId = (string)r["itemId"]!;
            if (existingReplies.Contains(replyId)) throw Invalid($"reply {replyId} already exists");
            if (!byId.ContainsKey(itemId)) throw Invalid($"reply {replyId} answers on item {itemId}, which the custodian did not hold before this review");
            string? answers = (string?)r["answersResponseId"];
            if (answers is not null && !run.Responses.Any(x => (string?)x["responseId"] == answers && (string?)x["itemId"] == itemId))
                throw Invalid($"reply {replyId} answers response {answers}, which the custodian does not hold on item {itemId}");
            var stored = (JsonObject)r.DeepClone();
            stored["reviewId"] = review.ReviewId;
            stored["round"] = review.Round;
            stored["sourceId"] = sourceId;
            stored["recordedAt"] = now;
            replies.Add(stored);
            bumps[itemId] = bumps.GetValueOrDefault(itemId) + 1;
        }

        var items = new List<RunItem>(run.Items.Count + created.Count);
        var changed = new List<RunItem>();
        foreach (RunItem it in run.Items)
        {
            RunItem cur = assessed.GetValueOrDefault(it.ItemId) ?? it;
            if (bumps.TryGetValue(it.ItemId, out int b)) cur = cur with { ItemRevision = cur.ItemRevision + b };
            items.Add(cur);
            if (!ReferenceEquals(cur, it)) changed.Add(cur);
        }
        items.AddRange(created);
        changed.AddRange(created);
        return new AppliedReview(items, [.. run.Replies, .. replies], created.Select(c => c.ItemId).ToList(), changed);
    }

    private static void Add(Dictionary<string, List<string>> map, string key, string value)
    {
        if (!map.TryGetValue(key, out List<string>? list)) map[key] = list = [];
        list.Add(value);
    }

    private static CustodianRefusal Invalid(string message) => new(ErrorCodes.InvalidItemTransition, message);
}
