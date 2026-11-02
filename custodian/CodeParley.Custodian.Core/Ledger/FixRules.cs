using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CodeParley.Custodian.Ledger;

/// <summary>A baseline file as the custodian's own published capture manifest records it (area <c>tree</c>).</summary>
internal sealed record BaselineFile(long Size, string Sha256);

/// <summary>One violation of a submitted proposal (its kind and path; null for an aggregate limit).</summary>
internal sealed record FixViolation(string Kind, string? Path);

/// <summary>A change the custodian accepted, in its canonical form: the preimage is the custodian's own baseline record,
/// the postimage what it hashed of the bytes it received.</summary>
internal sealed record FixCanonicalChange(string Path, string Kind, bool Executable, BaselineFile? Preimage, long? PostSize, string? PostSha256, bool PostBinary, string? Content);

/// <summary>
/// Phase 4 Increment 2 (contract §3.2, §3.4): the custodian's OWN rules for a delegated fix — the boundary it binds at
/// <c>op_begin</c> and the proposal content it receives at <c>op_finish</c>. The custodian validates the content itself and
/// trusts no engine claim: every path portable and contained, inside the boundary, sensitive paths only when named exactly,
/// the counts, sizes and kinds per the boundary's switches, a modify or delete only of a path its baseline capture holds
/// (whose recorded hash becomes the preimage), an add only of a path it does not. The simulated custodian
/// (src/custodian/simulated-fix.ts) re-implements these rules; the shared run corpus holds both to one behaviour.
/// </summary>
internal static class FixRules
{
    private static readonly Regex ReservedDevice = new(@"^(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$|CLOCK\$)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    // ASCII digits only, as the engine's JavaScript \d.
    private static readonly Regex ShortName = new(@"^[^.~]{1,6}~[0-9]{1,6}(\.[^.]{0,3})?$", RegexOptions.CultureInvariant);

    private static string? SegmentProblem(string seg)
    {
        if (seg.Length == 0) return "empty segment";
        if (seg is "." or "..") return "dot segment";
        if (seg.Length > 255) return "segment too long";
        // Increment 2 restriction: delegated-fix paths are ASCII, so case folding is the same rule in every implementation
        // (no locale- or Unicode-version-dependent mapping decides whether two paths collide).
        if (seg.Any(c => c > 0x7f)) return "non-ASCII character (delegated-fix paths are limited to ASCII)";
        if (seg.Any(c => c < 0x20 || c == 0x7f || c is '<' or '>' or ':' or '"' or '|' or '?' or '*' or '\\' or '/')) return "control, reserved or separator character";
        if (seg[^1] is ' ' or '.') return "ends with a space or a dot";
        if (string.Equals(seg, ".git", StringComparison.OrdinalIgnoreCase)) return "names git metadata";
        string first = seg.Split('.')[0];
        string trimmed = first.TrimEnd(' ', '.');
        if (ReservedDevice.IsMatch(trimmed)) return "reserved Windows device name";
        if (ShortName.IsMatch(seg)) return "shaped like an 8.3 short name";
        return null;
    }

    /// <summary>Why <paramref name="rel"/> is not a portable, contained repository-relative path, or null.</summary>
    internal static string? PathProblem(string rel)
    {
        if (rel.Length == 0) return "empty path";
        if (rel.Length > CustodianConstants.MaxFixPathChars) return "path too long";
        if (rel.StartsWith('/')) return "absolute path";
        foreach (string seg in rel.Split('/'))
            if (SegmentProblem(seg) is { } p) return p;
        return null;
    }

    /// <summary>Paths that steer another trust domain change only when the boundary names the exact file.</summary>
    private static readonly string[] Sensitive =
    [
        ".gitmodules", ".gitattributes", ".lfsconfig", ".husky/", ".githooks/", ".pre-commit-config.yaml", ".github/", ".gitlab-ci.yml",
        ".circleci/", "azure-pipelines.yml", ".claude/", ".mcp.json", ".codex/", ".agents/", "claude.md", "agents.md", ".vscode/",
        ".code-parley/", ".ai-loop/", ".npmrc", ".yarnrc", ".yarnrc.yml",
    ];

    /// <summary>Case folding of a path: ASCII letters only (the same rule as the simulated custodian's; a non-ASCII path is
    /// never a valid fix path, and a non-ASCII baseline path folds to itself).</summary>
    internal static string AsciiFold(string s)
    {
        var b = s.ToCharArray();
        for (int i = 0; i < b.Length; i++) if (b[i] is >= 'A' and <= 'Z') b[i] = (char)(b[i] + 32);
        return new string(b);
    }

    /// <summary>Does a change to <paramref name="rel"/> need an exact listing (case-folded comparison)?</summary>
    internal static bool IsSensitive(string rel)
    {
        string p = AsciiFold(rel);
        string name = p[(p.LastIndexOf('/') + 1)..];
        return Sensitive.Any(s => s.EndsWith('/') ? p.StartsWith(s, StringComparison.Ordinal) || p.Contains("/" + s, StringComparison.Ordinal) : p == s || name == s);
    }

    private static IEnumerable<string> Strings(JsonNode? a) => (a as JsonArray ?? []).Select(x => (string)x!);

    /// <summary>Exact files; sensitive paths only when listed; directory grants cover their descendants.</summary>
    internal static bool IsPermitted(string rel, JsonObject boundary)
    {
        if (Strings(boundary["permittedFiles"]).Contains(rel, StringComparer.Ordinal)) return true;
        if (IsSensitive(rel)) return false;
        return Strings(boundary["permittedDirs"]).Any(d => rel.StartsWith(d + "/", StringComparison.Ordinal));
    }

    /// <summary>The first reason a (syntactically valid) boundary is unusable, or null.</summary>
    internal static string? BoundaryProblem(JsonObject b)
    {
        List<string> files = [.. Strings(b["permittedFiles"])];
        List<string> dirs = [.. Strings(b["permittedDirs"])];
        if (files.Count == 0 && dirs.Count == 0) return "the boundary permits nothing";
        foreach (string f in files)
            if (PathProblem(f) is { } p) return $"permitted file {f}: {p}";
        foreach (string d in dirs)
        {
            if (PathProblem(d) is { } p) return $"permitted directory {d}: {p}";
            if (IsSensitive(d + "/x")) return $"permitted directory {d} is sensitive; list its files exactly";
        }
        return null;
    }

    internal static string BoundaryDigest(JsonObject b)
    {
        var o = (JsonObject)b.DeepClone();
        o["schema"] = "codeparley.custodian-fix-boundary.v1";
        return EngineJson.Digest(o);
    }

    /// <summary>The baseline tree's digest (sorted path, size, sha256): what the fix's op_begin bound.</summary>
    internal static string TreeDigest(IReadOnlyDictionary<string, BaselineFile> tree) => EngineJson.Digest(new JsonObject
    {
        ["schema"] = "codeparley.custodian-fix-tree.v1",
        ["files"] = new JsonArray([.. tree.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => (JsonNode)new JsonArray(kv.Key, kv.Value.Size, kv.Value.Sha256))]),
    });

    /// <summary>The base64 alphabet with at most two trailing '=' (a decoding is checked to be canonical separately).</summary>
    internal static bool IsBase64Alphabet(string s)
    {
        int pad = s.EndsWith("==", StringComparison.Ordinal) ? 2 : s.EndsWith('=') ? 1 : 0;
        for (int i = 0; i < s.Length - pad; i++)
            if (!(char.IsAsciiLetterOrDigit(s[i]) || s[i] is '+' or '/')) return false;
        return true;
    }

    /// <summary>Strict base64 (canonical: what it decodes to re-encodes to exactly it), or null.</summary>
    internal static byte[]? DecodeStrictBase64(string s)
    {
        if (s.Length % 4 != 0 || !IsBase64Alphabet(s)) return null;
        try
        {
            byte[] b = Convert.FromBase64String(s);
            return Convert.ToBase64String(b) == s ? b : null;
        }
        catch (FormatException) { return null; }
    }

    /// <summary>
    /// Validate a submission against the boundary and the custodian's baseline tree, in the custodian's order: per change (in
    /// the order submitted) its path, canonical order, case collision, the boundary, the content's presence, the kind
    /// switches, the baseline, the bytes; then the aggregate limits. Every violation is reported; the canonical changes are
    /// returned only when there is none.
    /// </summary>
    internal static (List<FixViolation> Violations, List<FixCanonicalChange>? Canonical, long TotalBytes) Validate(JsonObject boundary, IReadOnlyDictionary<string, BaselineFile> tree, JsonArray changes)
    {
        var violations = new List<FixViolation>();
        var canonical = new List<FixCanonicalChange>();
        void V(string kind, string? path) => violations.Add(new FixViolation(kind, path));
        var foldedTree = tree.Keys.Select(AsciiFold).ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? prev = null;
        long total = 0;
        bool allowCreate = (bool)boundary["allowCreate"]!, allowDelete = (bool)boundary["allowDelete"]!, allowBinary = (bool)boundary["allowBinary"]!;
        long maxFileBytes = RunFields.Integer(boundary["maxFileBytes"])!.Value;
        foreach (JsonObject c in changes.Cast<JsonObject>())
        {
            string path = (string)c["path"]!;
            string kind = (string)c["kind"]!;
            bool executable = (bool)c["executable"]!;
            string? content = (string?)c["content"];
            if (PathProblem(path) is not null)
            {
                V("invalid_path", path);
                continue;
            }
            if (prev is not null && string.CompareOrdinal(prev, path) >= 0) V("not_canonical_order", path);
            prev = path;
            string fold = AsciiFold(path);
            if (!seen.Add(fold)) V("case_collision", path);
            if (!IsPermitted(path, boundary)) V(IsSensitive(path) ? "sensitive_path" : "outside_boundary", path);
            bool wantsContent = kind != "delete";
            if (wantsContent != (content is not null) || (kind == "delete" && executable))
            {
                V("content_mismatch", path);
                continue;
            }
            if (kind == "add" && !allowCreate) V("create_not_allowed", path);
            if (kind == "delete" && !allowDelete) V("delete_not_allowed", path);
            BaselineFile? baseFile = tree.GetValueOrDefault(path);
            if (kind != "add" && baseFile is null) V("not_in_baseline", path);
            if (kind == "add" && foldedTree.Contains(fold)) V("present_in_baseline", path);
            long? postSize = null;
            string? postSha = null;
            bool binary = false;
            if (content is not null)
            {
                byte[]? bytes = DecodeStrictBase64(content);
                if (bytes is null)
                {
                    V("content_mismatch", path);
                    continue;
                }
                binary = Array.IndexOf(bytes, (byte)0) >= 0;
                postSha = Convert.ToHexStringLower(SHA256.HashData(bytes));
                postSize = bytes.LongLength;
                if (binary && !allowBinary) V("binary_not_allowed", path);
                if (bytes.LongLength > maxFileBytes) V("file_too_large", path);
                if (kind == "modify" && baseFile is not null && baseFile.Sha256 == postSha && baseFile.Size == bytes.LongLength && !executable) V("unchanged", path);
                total += bytes.LongLength;
            }
            canonical.Add(new FixCanonicalChange(path, kind, executable, kind == "add" || baseFile is null ? null : baseFile, postSize, postSha, binary, content));
        }
        if (changes.Count > RunFields.Integer(boundary["maxChangedFiles"])) V("too_many_changes", null);
        if (total > RunFields.Integer(boundary["maxTotalBytes"])) V("total_too_large", null);
        return (violations, violations.Count == 0 ? canonical : null, total);
    }

    /// <summary>A canonical change as the proposal (and its digest) record it: the kind, the custodian's preimage and the
    /// postimage it hashed — never the content.</summary>
    internal static JsonObject ChangeSummary(FixCanonicalChange c) => new()
    {
        ["path"] = c.Path, ["kind"] = c.Kind, ["executable"] = c.Executable,
        ["preimage"] = c.Preimage is null ? null : new JsonObject { ["size"] = c.Preimage.Size, ["sha256"] = c.Preimage.Sha256 },
        ["postimage"] = c.PostSha256 is null ? null : new JsonObject { ["size"] = c.PostSize, ["sha256"] = c.PostSha256, ["binary"] = c.PostBinary },
    };

    /// <summary>The custodian-computed proposal digest: over its own bindings and the canonical changes.</summary>
    internal static string ProposalDigest(string runId, string operationId, string fixId, string taskDigest, string boundaryDigest, JsonObject baseline, IEnumerable<FixCanonicalChange> changes)
        => EngineJson.Digest(new JsonObject
        {
            ["schema"] = "codeparley.custodian-fix-proposal.v1",
            ["runId"] = runId,
            ["operationId"] = operationId,
            ["fixId"] = fixId,
            ["taskDigest"] = taskDigest,
            ["boundaryDigest"] = boundaryDigest,
            ["baseline"] = baseline.DeepClone(),
            ["changes"] = new JsonArray([.. changes.Select(c => (JsonNode)ChangeSummary(c))]),
        });
}
