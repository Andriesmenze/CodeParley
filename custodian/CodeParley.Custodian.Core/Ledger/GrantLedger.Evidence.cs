using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// Phase 5 F-i2-5 (the TD's interim correction): the custodian's REDACTION EVIDENCE — the bytes of every record a
/// protected run's withheld names come from, held in its private store so that an amendment the custodian redacts covers
/// the run's whole history, not only the files that exist now. These are exactly the records the accepted Windows
/// workflow redacts against (engine/host-view.ts disclosureFor): the capture record of every review, the baseline capture
/// record and every response set's disclosure record — each already bound by digest in the run record (a review's
/// <c>captureDigest</c>, <c>declaration.baseline.digest</c>, a response set's <c>disclosureDigest</c>).
/// <list type="bullet">
/// <item>A review's capture record is the custodian's own: retained when it publishes the capture.</item>
/// <item>The baseline and the disclosure records are written by the engine; the engine hands their bytes over
/// (<c>hold_evidence</c>, in parts under the request limit) and the custodian keeps only content whose SHA-256 is a
/// digest its run record already binds — a claim the custodian cannot extend, exactly as trusted as the Windows path.</item>
/// </list>
/// Content-addressed (<c>evidence/&lt;repoKey&gt;/&lt;runId&gt;/&lt;SHA-256 prefix&gt;</c>), immutable, never served to
/// any caller: it names confidential files. A redaction whose basis is not complete refuses (REDACTION_REFUSED).
/// </summary>
internal sealed partial class GrantLedger
{
    /// <summary>The bytes one part of <c>hold_evidence</c> carries at most (base64-decoded), within the request limit.</summary>
    internal const int EvidencePartBytes = 512 * 1024;
    /// <summary>The size of one held record at most.</summary>
    internal const long MaxEvidenceBytes = 64L << 20;
    /// <summary>All of a run's evidence one redaction reads, at most.</summary>
    internal const long MaxRedactionEvidenceBytes = 48L << 20;

    /// <summary>One record a redaction rests on: its kind (<c>capture</c> or <c>disclosure</c>), its SHA-256 and what it
    /// is (for the refusal that names a missing one).</summary>
    internal sealed record EvidenceRef(string Kind, string Sha256, string Label);

    /// <summary>Every record the run's withheld names come from, as the run record and the run's user-record log bind
    /// them, in a stable order: the baseline and each review's capture, each response set's disclosure, and (Phase 5
    /// OI-1) the read disclosure of each amendment the custodian redacted — what that amendment's read withheld, as the
    /// accepted Windows workflow keeps a disclosure record of every user record's read. Callers hold <see cref="Gate"/>.</summary>
    private static List<EvidenceRef> EvidenceOf(RunRecord run, UserRecordLog? log)
    {
        var refs = new List<EvidenceRef>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(string kind, string? sha, string label)
        {
            if (sha is { Length: 64 } && seen.Add(kind + ":" + sha)) refs.Add(new EvidenceRef(kind, sha, label));
        }
        Add("capture", run.Declaration.Baseline?.Digest, "the baseline capture record");
        foreach (RunReview r in run.Reviews) Add("capture", (string?)r.Begin["captureDigest"], $"the capture record of review {r.ReviewId}");
        foreach (JsonObject x in run.Responses) Add("disclosure", (string?)x["disclosureDigest"], $"the disclosure record of response set {(string?)x["responseSetId"]}");
        foreach (UserRecordEntry e in log?.Records ?? [])
            if (e.RecordKind == "amendment") Add("disclosure", (string?)e.Payload["read_disclosure_digest"], $"the read disclosure record of amendment A-{e.Seq}");
        return refs;
    }

    /// <summary>An amendment of the run with reviewer-visible text whose read disclosure the custodian does not hold (one
    /// the engine redacted, or one recorded before the custodian kept read disclosures): its read's withheld names
    /// cannot be established, so a redaction against the run's history refuses. Null when there is none.</summary>
    private static UserRecordEntry? UnestablishedAmendment(UserRecordLog? log)
        => log?.Records.FirstOrDefault(e => e.RecordKind == "amendment" && e.DisclosureDigest is not null && e.Payload["read_disclosure_digest"] is null);

    /// <summary>The digest of a redaction basis (what the operator's confirmation and its commit bind).</summary>
    private static string BasisDigest(string repoKey, string runId, List<EvidenceRef> refs) => Digest.Sha256Hex(Digest.Canonical(new JsonObject
    {
        ["schema"] = "codeparley.redaction-basis.v1", ["repoKey"] = repoKey, ["runId"] = runId,
        ["evidence"] = new JsonArray([.. refs.Select(r => (JsonNode)new JsonArray(r.Kind, r.Sha256))]),
    }));

    /// <summary>The run's current redaction basis digest, re-derived at a commit; null without a run record.
    /// Callers hold <see cref="Gate"/>.</summary>
    private string? CurrentBasisDigest(string repoKey, string runId)
        => ReadRun(repoKey, runId) is { } run ? BasisDigest(repoKey, runId, EvidenceOf(run, ReadUserLog(repoKey, runId))) : null;

    /// <summary>Phase 5 OI-1: hold an amendment's read disclosure record (the custodian's own, from its helper's read) as
    /// protected evidence of the run before the record that binds it can be prepared. Write-once and content-addressed in
    /// the private store; the implementer surface can never hold or replace it (<see cref="HoldEvidence"/> accepts only
    /// the baseline and response disclosures the run record binds). Returns its digest.</summary>
    private string HoldReadDisclosure(string repoKey, string runId, string record)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(record);
        if (bytes.LongLength > MaxEvidenceBytes) throw new CustodianRefusal(ErrorCodes.RedactionRefused, "the read's disclosure record is larger than the custodian holds; nothing was prepared");
        string sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        lock (EnterGate()) RetainEvidence(repoKey, runId, sha, bytes);
        Audit($"evidence held repoKey={repoKey} runId={runId} sha256={sha[..16]} bytes={bytes.Length} (amendment read disclosure)");
        return sha;
    }

    /// <summary>Phase 5 OI-1: at a commit, the read disclosure record an amendment binds must be held and intact — an
    /// accepted amendment never lacks the evidence a later redaction needs. Callers hold <see cref="Gate"/>.</summary>
    private static void RequireHeldReadDisclosure(string repoKey, string runId, string sha)
    {
        string path = StorePaths.RedactionEvidencePath(repoKey, runId, sha);
        if (!File.Exists(path) || Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))) != sha)
            throw new CustodianRefusal(ErrorCodes.RedactionRefused, $"the custodian does not hold this amendment's read disclosure record ({sha[..12]}) intact; nothing was recorded");
    }

    private static bool IsHex64(string? s) => s is { Length: 64 } && s.All(char.IsAsciiHexDigitLower);

    /// <summary>Hold one record (content-addressed, write-once). An existing file must already be that content.</summary>
    private static void RetainEvidence(string repoKey, string runId, string sha256, byte[] bytes)
    {
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != sha256) throw new InvalidOperationException("evidence content does not hash to its digest");
        string path = StorePaths.RedactionEvidencePath(repoKey, runId, sha256);
        if (File.Exists(path) && Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))) == sha256) return;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        AtomicWrite(path, Encoding.UTF8.GetString(bytes));
        if (Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))) != sha256)
        {
            TryDelete(path);
            throw new InvalidOperationException("the held evidence differs from what was written (not valid UTF-8 text)");
        }
    }

    /// <summary>
    /// <c>hold_evidence</c> (implementer surface): part <paramref name="part"/> of <paramref name="parts"/> of the record whose
    /// SHA-256 is <paramref name="sha256"/>. Parts arrive in order (part 0 restarts); the last part is checked against the
    /// digest and the record is held only when the run record binds that digest as the baseline capture or a response
    /// set's disclosure record (EVIDENCE_NOT_HELD otherwise: nothing is kept). A record already held answers at once.
    /// </summary>
    internal JsonObject HoldEvidence(string repositoryRoot, string runId, string sha256, int part, int parts, string dataBase64)
    {
        ValidateRunId(runId);
        if (!IsHex64(sha256)) throw new ArgumentException("sha256 must be 64 lowercase hex characters");
        long maxParts = MaxEvidenceBytes / EvidencePartBytes;
        if (parts < 1 || parts > maxParts || part < 0 || part >= parts) throw new ArgumentException($"part must be 0..parts-1 and parts 1..{maxParts}");
        byte[] data;
        try { data = Convert.FromBase64String(dataBase64); }
        catch (FormatException) { throw new ArgumentException("data must be base64"); }
        if (data.Length > EvidencePartBytes) throw new ArgumentException($"one part carries at most {EvidencePartBytes} bytes");
        string repoKey = RepoIdentities.Resolve(repositoryRoot).Key;
        lock (EnterGate())
        {
            RunRecord run = ReadRun(repoKey, runId) ?? throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run; no evidence is held for it");
            bool bound = run.Declaration.Baseline?.Digest == sha256 || run.Responses.Any(x => (string?)x["disclosureDigest"] == sha256);
            if (!bound) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, "no baseline capture or response disclosure of this run has that digest; nothing was held");
            string path = StorePaths.RedactionEvidencePath(repoKey, runId, sha256);
            if (File.Exists(path)) return new JsonObject { ["held"] = true, ["sha256"] = sha256 };
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string partial = path + ".part";
            if (part > 0 && !File.Exists(partial)) throw new CustodianRefusal(ErrorCodes.InvalidArgument, $"part {part} does not follow the parts held so far; send the record again from part 0");
            using (var fs = new FileStream(partial, part == 0 ? FileMode.Create : FileMode.Open, FileAccess.Write, FileShare.None))
            {
                if (part > 0 && fs.Length != (long)part * EvidencePartBytes) throw new CustodianRefusal(ErrorCodes.InvalidArgument, $"part {part} does not follow the parts held so far; send the record again from part 0");
                fs.Seek(0, SeekOrigin.End);
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }
            if (part < parts - 1)
            {
                if (data.Length != EvidencePartBytes) { TryDelete(partial); throw new CustodianRefusal(ErrorCodes.InvalidArgument, "only the last part may be shorter than a full part"); }
                return new JsonObject { ["held"] = false, ["sha256"] = sha256, ["received"] = part + 1 };
            }
            byte[] all = File.ReadAllBytes(partial);
            TryDelete(partial);
            if (Convert.ToHexStringLower(SHA256.HashData(all)) != sha256) throw new CustodianRefusal(ErrorCodes.EvidenceNotHeld, "the record's parts do not hash to its digest; nothing was held");
            RetainEvidence(repoKey, runId, sha256, all);
            Audit($"evidence held repoKey={repoKey} runId={runId} sha256={sha256[..16]} bytes={all.Length}");
            return new JsonObject { ["held"] = true, ["sha256"] = sha256 };
        }
    }

    /// <summary>
    /// The redaction basis of a protected run: every record its withheld names come from, read from the private store and
    /// checked against its digest — the run's whole capture and disclosure history. Refuses (REDACTION_REFUSED) without a
    /// run record, when a record is not held or not intact, or when the history exceeds what one redaction reads: the
    /// redaction never falls back to the current repository alone. Returns the records and the basis digest.
    /// </summary>
    private (JsonArray Evidence, string BasisDigest) RedactionBasisOf(RepoIdentity id, string runId)
    {
        List<EvidenceRef> refs;
        lock (EnterGate())
        {
            RunRecord run = ReadRun(id.Key, runId) ?? throw new CustodianRefusal(ErrorCodes.RedactionRefused, "the custodian holds no record of this run, so its withheld names cannot be established; nothing was prepared");
            UserRecordLog? log = ReadUserLog(id.Key, runId);
            if (UnestablishedAmendment(log) is { } a)
                throw new CustodianRefusal(ErrorCodes.RedactionRefused, $"amendment A-{a.Seq} of this run has reviewer-visible text but the custodian holds no record of what its read withheld, so the run's withheld names cannot be established; nothing was prepared");
            refs = EvidenceOf(run, log);
        }
        var evidence = new JsonArray();
        long total = 0;
        foreach (EvidenceRef r in refs)
        {
            string path = StorePaths.RedactionEvidencePath(id.Key, runId, r.Sha256);
            byte[]? bytes = File.Exists(path) ? File.ReadAllBytes(path) : null;
            if (bytes is null || Convert.ToHexStringLower(SHA256.HashData(bytes)) != r.Sha256)
                throw new CustodianRefusal(ErrorCodes.RedactionRefused, $"the custodian does not hold {r.Label} ({r.Sha256[..12]}){(bytes is null ? "" : " intact")}, so the run's withheld names cannot be established; nothing was prepared (the redaction never falls back to the current repository alone)");
            total += bytes.LongLength;
            if (total > MaxRedactionEvidenceBytes) throw new CustodianRefusal(ErrorCodes.RedactionRefused, $"the run's capture and disclosure history is larger than one redaction reads ({MaxRedactionEvidenceBytes} bytes); nothing was prepared");
            evidence.Add(new JsonObject { ["kind"] = r.Kind, ["sha256"] = r.Sha256, ["text"] = Encoding.UTF8.GetString(bytes) });
        }
        return (evidence, BasisDigest(id.Key, runId, refs));
    }
}
