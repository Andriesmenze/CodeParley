using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ledger;

/// <summary>One change as the custodian renders it: its canonical summary and the bytes on each side (null where the side is
/// absent: the preimage of an add, the postimage of a delete).</summary>
internal sealed record RenderChange(string Path, string Kind, bool Executable, BaselineFile? Preimage, long? PostSize, string? PostSha256, bool PostBinary, byte[]? Pre, byte[]? Post);

/// <summary>The fields of a rendering's header, all from the custodian's own records.</summary>
internal sealed record RenderHeader(
    string RunId, string RepositoryPath, string RepoKey, string FixId, string OperationId, string ReviewId, string SourceId,
    string TaskDigest, string ProposalDigest, string ExpiresAt, string BoundaryDigest, long TotalBytes);

/// <summary>A rendering: its exact text (the body and its last line), the body's SHA-256 (what a confirmation binds), and
/// the SHA-256 of its repository-independent part (from the boundary on; the shared corpus compares it across custodians).</summary>
internal sealed record FixRenderingResult(string Text, string Digest, string ChangesDigest);

/// <summary>
/// Phase 4 Increment 3 (contract §3.5): the custodian's OWN rendering of a held proposal — the run, the repository and the
/// baseline source, the boundary and its limits, the path list with the change kinds and the preimage and postimage
/// SHA-256s, a unified line diff per text file, and the rendering's own SHA-256 — built from the baseline bytes in its
/// published capture and the postimage bytes it holds. Deterministic: the same records give the same bytes, and the
/// simulated custodian (src/custodian/simulated-render.ts) renders the same text (the shared corpus holds them together).
///
/// What the operator's terminal shows must be what the bytes are: every control character but a tab, the C1 controls and
/// the invisible and bidirectional formatting characters are shown escaped (<c>&lt;U+XXXX&gt;</c>), a line without a final
/// newline is marked, binary content (a NUL byte) and bytes that are not UTF-8 are shown as sizes and hashes only, flagged.
/// </summary>
internal static class FixRendering
{
    /// <summary>A diff compares at most this many line pairs (the remaining middle of two files, after their common prefix and
    /// suffix); a larger middle is rendered as a full replacement.</summary>
    internal const long MaxCompareCells = 4_000_000;
    internal const int Context = 3;
    private static readonly UTF8Encoding Strict = new(false, true);

    internal static FixRenderingResult Render(RenderHeader h, JsonObject boundary, IReadOnlyList<RenderChange> changes)
    {
        var head = new StringBuilder();
        head.Append("CodeParley delegated fix: the custodian's rendering of the proposal (what a confirmation binds)\n");
        head.Append("run: ").Append(h.RunId).Append('\n');
        head.Append("repository: ").Append(Escape(h.RepositoryPath)).Append('\n');
        head.Append("repository identity: ").Append(h.RepoKey).Append('\n');
        head.Append("fix: ").Append(h.FixId).Append(" (operation ").Append(h.OperationId).Append(")\n");
        head.Append("baseline: review ").Append(h.ReviewId).Append(", source ").Append(h.SourceId).Append('\n');
        head.Append("task digest: ").Append(h.TaskDigest).Append('\n');
        head.Append("proposal digest: ").Append(h.ProposalDigest).Append('\n');
        head.Append("proposal expires: ").Append(h.ExpiresAt).Append('\n');

        var tail = new StringBuilder();
        tail.Append("boundary (digest ").Append(h.BoundaryDigest).Append("):\n");
        tail.Append("  permitted files: ").Append(List(boundary["permittedFiles"])).Append('\n');
        tail.Append("  permitted directories: ").Append(List(boundary["permittedDirs"])).Append('\n');
        tail.Append("  create: ").Append(Allowed(boundary["allowCreate"])).Append("; delete: ").Append(Allowed(boundary["allowDelete"]))
            .Append("; binary: ").Append(Allowed(boundary["allowBinary"])).Append('\n');
        tail.Append("  limits: ").Append(Num(boundary["maxChangedFiles"])).Append(" changed files, ").Append(Num(boundary["maxFileBytes"]))
            .Append(" bytes per file, ").Append(Num(boundary["maxTotalBytes"])).Append(" bytes in total\n");
        tail.Append("  time limit: ").Append(Num(boundary["timeLimitSeconds"])).Append(" s; proposal lifetime: ").Append(Num(boundary["proposalLifetimeSeconds"])).Append(" s\n");
        tail.Append("changes (").Append(changes.Count.ToString(CultureInfo.InvariantCulture)).Append(" files, ").Append(h.TotalBytes.ToString(CultureInfo.InvariantCulture)).Append(" bytes):\n");
        foreach (RenderChange c in changes)
        {
            tail.Append("  ").Append(c.Kind).Append(' ').Append(c.Path).Append(c.Executable ? " (executable)" : "").Append('\n');
            tail.Append("    preimage: ").Append(c.Preimage is null ? "none" : $"sha256 {c.Preimage.Sha256} ({c.Preimage.Size.ToString(CultureInfo.InvariantCulture)} bytes)").Append('\n');
            tail.Append("    postimage: ").Append(c.PostSha256 is null ? "none" : $"sha256 {c.PostSha256} ({c.PostSize!.Value.ToString(CultureInfo.InvariantCulture)} bytes){(c.PostBinary ? ", binary" : "")}").Append('\n');
        }
        foreach (RenderChange c in changes) AppendFile(tail, c);
        string body = head.ToString() + tail.ToString();
        string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        string changesDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(tail.ToString())));
        return new FixRenderingResult(body + "rendering sha256: " + digest + "\n", digest, changesDigest);
    }

    private static string List(JsonNode? a)
    {
        var items = (a as JsonArray ?? []).Select(x => Escape((string)x!)).ToList();
        return items.Count == 0 ? "(none)" : string.Join(", ", items);
    }

    private static string Allowed(JsonNode? v) => v is JsonValue j && j.TryGetValue(out bool b) && b ? "allowed" : "not allowed";
    private static string Num(JsonNode? v) => (RunFields.Integer(v) ?? 0).ToString(CultureInfo.InvariantCulture);

    /// <summary>One file's section: its unified line diff, or why it is shown as sizes and hashes only.</summary>
    private static void AppendFile(StringBuilder sb, RenderChange c)
    {
        sb.Append("=== ").Append(c.Kind).Append(' ').Append(c.Path).Append(" ===\n");
        bool binary = (c.Pre is not null && Array.IndexOf(c.Pre, (byte)0) >= 0) || (c.Post is not null && Array.IndexOf(c.Post, (byte)0) >= 0);
        if (binary)
        {
            sb.Append("(binary content: shown as sizes and hashes only) [FLAGGED: binary]\n");
            return;
        }
        string? pre = c.Pre is null ? "" : Decode(c.Pre);
        string? post = c.Post is null ? "" : Decode(c.Post);
        if (pre is null || post is null)
        {
            sb.Append("(not UTF-8 text: shown as sizes and hashes only) [FLAGGED: not text]\n");
            return;
        }
        sb.Append(c.Pre is null ? "--- /dev/null\n" : $"--- a/{c.Path}\n");
        sb.Append(c.Post is null ? "+++ /dev/null\n" : $"+++ b/{c.Path}\n");
        List<Line> a = Lines(pre), b = Lines(post);
        (List<Op> ops, bool full) = Diff(a, b);
        if (full) sb.Append("(too many lines to compare: shown as a full replacement)\n");
        AppendHunks(sb, ops, a, b);
    }

    private static string? Decode(byte[] bytes)
    {
        try { return Strict.GetString(bytes); }
        catch (DecoderFallbackException) { return null; }
    }

    /// <summary>A line: its text without the newline, and whether a newline ended it.</summary>
    private readonly record struct Line(string Text, bool Eol);

    private static List<Line> Lines(string text)
    {
        var lines = new List<Line>();
        if (text.Length == 0) return lines;
        string[] parts = text.Split('\n');
        bool lastEol = parts[^1].Length == 0;
        int count = lastEol ? parts.Length - 1 : parts.Length;
        for (int i = 0; i < count; i++) lines.Add(new Line(parts[i], i < count - 1 || lastEol));
        return lines;
    }

    /// <summary>One edit: <c>=</c> (a line of both), <c>-</c> (of the preimage), <c>+</c> (of the postimage), with its indexes.</summary>
    private readonly record struct Op(char Kind, int A, int B);

    /// <summary>The edit script: the common prefix and suffix kept, the middle compared by a longest common subsequence
    /// (preferring a deletion before an insertion), or — over <see cref="MaxCompareCells"/> — replaced whole.</summary>
    private static (List<Op> Ops, bool Full) Diff(List<Line> a, List<Line> b)
    {
        int n = a.Count, m = b.Count, p = 0, s = 0;
        while (p < n && p < m && a[p] == b[p]) p++;
        while (s < n - p && s < m - p && a[n - 1 - s] == b[m - 1 - s]) s++;
        var ops = new List<Op>();
        for (int i = 0; i < p; i++) ops.Add(new Op('=', i, i));
        int an = n - p - s, bm = m - p - s;
        bool full = (long)(an + 1) * (bm + 1) > MaxCompareCells;
        if (full)
        {
            for (int i = 0; i < an; i++) ops.Add(new Op('-', p + i, -1));
            for (int j = 0; j < bm; j++) ops.Add(new Op('+', -1, p + j));
        }
        else
        {
            int w = bm + 1;
            var l = new int[(an + 1) * w];
            for (int i = an - 1; i >= 0; i--)
                for (int j = bm - 1; j >= 0; j--)
                    l[i * w + j] = a[p + i] == b[p + j] ? l[(i + 1) * w + j + 1] + 1 : Math.Max(l[(i + 1) * w + j], l[i * w + j + 1]);
            int x = 0, y = 0;
            while (x < an && y < bm)
            {
                if (a[p + x] == b[p + y]) { ops.Add(new Op('=', p + x, p + y)); x++; y++; }
                else if (l[(x + 1) * w + y] >= l[x * w + y + 1]) { ops.Add(new Op('-', p + x, -1)); x++; }
                else { ops.Add(new Op('+', -1, p + y)); y++; }
            }
            for (; x < an; x++) ops.Add(new Op('-', p + x, -1));
            for (; y < bm; y++) ops.Add(new Op('+', -1, p + y));
        }
        for (int i = 0; i < s; i++) ops.Add(new Op('=', n - s + i, m - s + i));
        return (ops, full);
    }

    /// <summary>The hunks: each change with <see cref="Context"/> lines around it, changes at most 2×Context apart in one
    /// hunk; the header always gives a start and a length (a start one before the first line when the length is 0).</summary>
    private static void AppendHunks(StringBuilder sb, List<Op> ops, List<Line> a, List<Line> b)
    {
        var changed = new List<int>();
        for (int i = 0; i < ops.Count; i++) if (ops[i].Kind != '=') changed.Add(i);
        if (changed.Count == 0)
        {
            sb.Append("(no line changes)\n");
            return;
        }
        int k = 0;
        while (k < changed.Count)
        {
            int first = changed[k], last = first;
            while (k + 1 < changed.Count && changed[k + 1] - last - 1 <= 2 * Context) last = changed[++k];
            k++;
            int start = Math.Max(0, first - Context), end = Math.Min(ops.Count - 1, last + Context);
            int aBefore = 0, bBefore = 0, aCount = 0, bCount = 0;
            for (int i = 0; i < start; i++) { if (ops[i].Kind != '+') aBefore++; if (ops[i].Kind != '-') bBefore++; }
            for (int i = start; i <= end; i++) { if (ops[i].Kind != '+') aCount++; if (ops[i].Kind != '-') bCount++; }
            sb.Append("@@ -").Append((aCount == 0 ? aBefore : aBefore + 1).ToString(CultureInfo.InvariantCulture)).Append(',').Append(aCount.ToString(CultureInfo.InvariantCulture))
              .Append(" +").Append((bCount == 0 ? bBefore : bBefore + 1).ToString(CultureInfo.InvariantCulture)).Append(',').Append(bCount.ToString(CultureInfo.InvariantCulture)).Append(" @@\n");
            for (int i = start; i <= end; i++)
            {
                Op o = ops[i];
                Line line = o.Kind == '+' ? b[o.B] : a[o.A];
                sb.Append(o.Kind == '=' ? ' ' : o.Kind).Append(Escape(line.Text)).Append('\n');
                if (!line.Eol) sb.Append("\\ No newline at end of file\n");
            }
        }
    }

    /// <summary>Is this code point shown escaped? Every control character but a tab, DEL, the C1 controls, and the zero-width,
    /// line-separator, bidirectional and other invisible formatting characters.</summary>
    internal static bool MustEscape(int cp)
        => (cp < 0x20 && cp != 0x09) || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F) || (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E)
           || (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069) || cp == 0xFEFF || (cp >= 0xFFF9 && cp <= 0xFFFB);

    internal static string Escape(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (Rune r in s.EnumerateRunes())
        {
            if (MustEscape(r.Value)) sb.Append("<U+").Append(r.Value.ToString("X4", CultureInfo.InvariantCulture)).Append('>');
            else sb.Append(r.ToString());
        }
        return sb.ToString();
    }
}
