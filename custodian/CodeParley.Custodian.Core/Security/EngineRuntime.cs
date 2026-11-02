using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Security;

/// <summary>One file of the runtime tree as measured: its tree-relative path ('/'-separated), size and SHA-256.</summary>
internal sealed record RuntimeFile(string Path, long Size, string Sha256);

/// <summary>The engine runtime as the custodian measured it (contract §2.1): the approved tree's root and identity, the
/// two native images it launches (node.exe and the approved git), the helper entry, and a digest over every file.
/// Phase 6 (§7 b): the git is either inside the tree (<see cref="GitRelative"/>, hashed with it) or an administrator-installed
/// git outside it (<see cref="GitPath"/>, measured as Codex is: its image and its administrator control), so the tree hashed
/// before every launch holds only Node and the engine.</summary>
internal sealed record MeasuredRuntime(
    string Root, string RootFileId, string? GitRelative, MeasuredImage Node, MeasuredImage Git, string EntrySha256,
    string TreeDigest, int FileCount, long TotalBytes, string? GitPath = null);

/// <summary>
/// P3.4C-5 (contract §2.1, N5-6): the administrator-installed engine runtime the helper runs. Phase 5 (§4.1): the
/// measurement is the host's (<see cref="Platform.Images"/>); the tree digest, the comparison and the rendering are portable.
/// </summary>
internal static class EngineRuntime
{
    internal static string NodeName => Platform.Images.NodeName;
    internal const string EntryRelative = "dist/helper/main.js";
    internal const string TreeSchema = "arl.engine-runtime-tree.v1";

    /// <summary>The validated relative path of the approved git inside the runtime (the host's rule).</summary>
    internal static string GitRelative(string rel) => Platform.Images.GitRelative(rel);

    /// <summary>Measure the runtime with its git inside the tree (<paramref name="gitRelative"/>) or outside it
    /// (<paramref name="gitPath"/>); exactly one is given.</summary>
    internal static MeasuredRuntime Measure(string root, string? gitRelative, string? gitPath = null)
    {
        if ((gitRelative is null) == (gitPath is null)) throw new CustodianRefusal(ErrorCodes.RuntimeNotApproved, "the engine runtime names its git either inside the runtime or as an installed git outside it, exactly one");
        return Platform.Images.MeasureRuntime(root, gitRelative, gitPath);
    }

    /// <summary>The git executable the helper runs.</summary>
    internal static string GitExecutable(MeasuredRuntime m)
        => m.GitPath ?? Path.Combine(m.Root, m.GitRelative!.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>SHA-256 over the canonical JSON of every file row (path, size, SHA-256), sorted by path.</summary>
    internal static string TreeDigest(IReadOnlyList<RuntimeFile> files)
    {
        var rows = new JsonArray();
        foreach (RuntimeFile f in files.OrderBy(f => f.Path, StringComparer.Ordinal))
            rows.Add(new JsonArray(f.Path, f.Size, f.Sha256));
        return Ledger.Digest.Sha256Hex(EngineJson.Canonical(new JsonObject { ["schema"] = TreeSchema, ["files"] = rows }));
    }

    /// <summary>The differences between a held runtime and a measurement now (empty: the same tree).</summary>
    internal static List<string> Differences(JsonObject held, MeasuredRuntime now)
    {
        var d = new List<string>();
        if (!string.Equals((string?)held["root"], now.Root, StringComparison.OrdinalIgnoreCase)) d.Add("root");
        if ((string?)held["rootFileId"] != now.RootFileId) d.Add("root identity");
        if (!SameGitLocation(held, now)) d.Add("git location");
        if ((string?)held["nodeSha256"] != now.Node.Sha256) d.Add("node.exe");
        if ((string?)held["gitSha256"] != now.Git.Sha256) d.Add("git");
        if ((string?)held["entrySha256"] != now.EntrySha256) d.Add("helper entry");
        if ((string?)held["treeDigest"] != now.TreeDigest) d.Add("tree digest");
        return d;
    }

    private static bool SameGitLocation(JsonObject held, MeasuredRuntime now)
        => (string?)held["gitRelative"] == now.GitRelative && string.Equals((string?)held["gitPath"], now.GitPath, StringComparison.OrdinalIgnoreCase);

    /// <summary>The measured content a record holds (and an approval renders).</summary>
    internal static JsonObject Content(MeasuredRuntime m)
    {
        var o = new JsonObject { ["root"] = m.Root, ["rootFileId"] = m.RootFileId };
        if (m.GitPath is null) o["gitRelative"] = m.GitRelative;
        else o["gitPath"] = m.GitPath;
        o["entryRelative"] = EntryRelative;
        o["nodeSha256"] = m.Node.Sha256; o["nodeFileId"] = m.Node.FileId; o["nodeSize"] = m.Node.Size;
        o["gitSha256"] = m.Git.Sha256; o["gitFileId"] = m.Git.FileId; o["entrySha256"] = m.EntrySha256;
        o["treeDigest"] = m.TreeDigest; o["fileCount"] = m.FileCount; o["totalBytes"] = m.TotalBytes;
        return o;
    }

    internal static string Render(MeasuredRuntime m) => string.Join('\n',
        $"Approve the CodeParley engine runtime the helper service runs:",
        $"  root        {m.Root}  (directory id {m.RootFileId})",
        $"  {Platform.Images.NodeName,-11} {CodexImage.KindOf(m.Node.Form)}, {m.Node.Size} bytes, SHA-256 {m.Node.Sha256}",
        m.GitPath is null
            ? $"  git         {m.GitRelative}: {CodexImage.KindOf(m.Git.Form)}, {m.Git.Size} bytes, SHA-256 {m.Git.Sha256}"
            : $"  git         {m.GitPath} (installed outside the runtime, administrator-controlled): {CodexImage.KindOf(m.Git.Form)}, {m.Git.Size} bytes, SHA-256 {m.Git.Sha256}",
        $"  entry       {EntryRelative}  SHA-256 {m.EntrySha256}",
        $"  tree        {m.FileCount} files, {m.TotalBytes} bytes, digest {m.TreeDigest}",
        "  The tree is administrator-controlled (no one else can write in it or replace it). The helper runs exactly this",
        "  tree; any change refuses every measurement until it is approved again.");

}
