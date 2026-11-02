using System.Security.Cryptography;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Linux.Native;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 (contract §4.9): the approved executables measured with the custodian's own token on Linux — reached by the
/// no-follow walk (<see cref="LinuxRepoIdentities.WalkNoFollow"/>), every component refused rather than followed. An
/// image is one regular ELF file (<c>\x7fELF</c>) with one link, no setuid/setgid bit, hashed through the descriptor the
/// walk opened; the Codex image and its bundled bwrap are also owned by root with no group or other write on the file or
/// any ancestor (§4.9: an administrator-controlled installation). A runtime tree is administrator-controlled: every directory and file in it, and every ancestor up to
/// <c>/</c>, is owned by root and grants no group or other write; symbolic links and special files are refused.
/// Effective confinement is never inferred from these files (TD finding 5): S1/FIX confirmations rest on self-tests
/// (Increment 2/3). The shared libraries an image loads are not measured (the Windows DLL residual).
/// </summary>
internal static class LinuxImages
{
    internal const string NativeElf = "native_elf";
    internal const string NodeName = "node";
    private const long MaxImageBytes = 4L * 1024 * 1024 * 1024;
    private const int MaxFiles = 100_000;
    private const long MaxTotalBytes = 4L * 1024 * 1024 * 1024;

    private static bool _skipOwnershipForSelfTest;
    private static bool _acceptCorpusPeForSelfTest;

    /// <summary>Self-test only (the shared run corpus, whose Codex installation is the PE image it defines and pins by
    /// SHA-256 on every platform): also accept a PE image as the Codex image. Never set by the service.</summary>
    internal static void AcceptCorpusPeForSelfTest() => _acceptCorpusPeForSelfTest = true;
    internal static void SkipOwnershipChecksForSelfTest() => _skipOwnershipForSelfTest = true;

    private static CustodianRefusal Unsupported(string why) => new(ErrorCodes.CodexInstallationUnsupported, $"the Codex installation is not a supported native image: {why}");
    private static CustodianRefusal RuntimeRefused(string why) => new(ErrorCodes.RuntimeNotApproved, $"the engine runtime cannot be approved: {why}");

    internal static string GitRelative(string rel)
    {
        string[] parts = rel.Split('/');
        if (rel.Length is < 3 or > 260 || rel.StartsWith('/') || parts.Any(s => s.Length == 0 || s is "." or ".." || s.Any(char.IsControl)) || parts[^1] != "git")
            throw new ArgumentException("the runtime's git must be a relative path inside it ending in git");
        return rel;
    }

    internal static MeasuredImage MeasureCodex(string path) => MeasureApproved(path, Unsupported);

    /// <summary>An administrator-installed image (Codex, its bundled bwrap): the image rules, and owned by root with no group
    /// or other write on the file and every ancestor (a user-writable installation is refused).</summary>
    internal static MeasuredImage MeasureApproved(string path, Func<string, CustodianRefusal> refuse)
    {
        string[] components;
        try { components = LinuxRepoIdentities.Parse(path); }
        catch (ArgumentException e) { throw refuse(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal).Replace("repository path", "path", StringComparison.Ordinal)); }
        if (!_skipOwnershipForSelfTest) CheckAncestors(components[..^1], refuse);
        try { return MeasureImage("/" + string.Join('/', components), components, refuse, requireRootOwned: !_skipOwnershipForSelfTest); }
        catch (RepoIdentityRefused e) { throw refuse(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
    }

    private static MeasuredImage MeasureImage(string canonical, string[] components, Func<string, CustodianRefusal> refuse, bool requireRootOwned = false)
    {
        int pathFd = LinuxRepoIdentities.WalkNoFollow(components, canonical, finalIsDirectory: false);
        try
        {
            if (Libc.StatxFullFd(pathFd, out Libc.StatxFull st) != 0) throw refuse("the file cannot be examined");
            if (st.Type != Libc.S_IFREG) throw refuse($"{canonical} is not a regular file");
            if (st.Nlink != 1) throw refuse($"{canonical} has {st.Nlink} hard links");
            if ((st.Perm & 0xC00) != 0) throw refuse($"{canonical} is setuid or setgid");
            if (requireRootOwned && st.Uid != 0) throw refuse($"{canonical} is owned by uid {st.Uid}, not root (a user-writable installation is refused)");
            if (requireRootOwned && (st.Perm & 0x12 /* 0o022 */) != 0) throw refuse($"{canonical} is group- or other-writable");
            if ((long)st.Size > MaxImageBytes) throw refuse($"{canonical} is larger than 4 GiB");
            int fd = ReopenRegular(pathFd);
            if (fd < 0) throw refuse($"{canonical} cannot be read by the custodian ({Libc.ErrText(Libc.Errno)})");
            using var stream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(fd, ownsHandle: true), FileAccess.Read);
            Span<byte> magic = stackalloc byte[4];
            bool elf = stream.Read(magic) == 4 && magic[0] == 0x7f && magic[1] == (byte)'E' && magic[2] == (byte)'L' && magic[3] == (byte)'F';
            bool corpusPe = !elf && _acceptCorpusPeForSelfTest && magic[0] == (byte)'M' && magic[1] == (byte)'Z';
            if (!elf && !corpusPe) throw refuse($"{canonical} is not an ELF image");
            stream.Position = 0;
            string sha = Convert.ToHexStringLower(SHA256.HashData(stream));
            string fileId = Libc.HandleOf(pathFd) is { } h ? $"{h.Type}-{Convert.ToHexStringLower(h.Bytes)}-{st.BtimeSec}.{st.BtimeNsec:D9}" : throw refuse("the filesystem gives no file handle");
            return new MeasuredImage(canonical, elf ? NativeElf : CodexImage.NativePe, fileId, (long)st.Size, sha);
        }
        finally { Libc.close(pathFd); }
    }

    /// <summary>Open a regular file reached as an O_PATH descriptor for reading, through /proc/self/fd (the documented way
    /// to upgrade an O_PATH descriptor; it names the same open file, so no path is re-resolved).</summary>
    private static int ReopenRegular(int pathFd) => Libc.Openat(Libc.AT_FDCWD, $"/proc/self/fd/{pathFd}", Libc.O_RDONLY | Libc.O_CLOEXEC, 0);

    internal static MeasuredRuntime MeasureRuntime(string root, string? gitRelative, string? gitPath = null)
    {
        if (gitPath is not null) return MeasureWithInstalledGit(root, gitPath);
        string git = GitRelative(gitRelative!);
        string[] components;
        try { components = LinuxRepoIdentities.Parse(root); }
        catch (ArgumentException e) { throw RuntimeRefused(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
        string canonical = "/" + string.Join('/', components);
        if (!_skipOwnershipForSelfTest) CheckAncestors(components, RuntimeRefused);
        string rootId;
        int rootFd;
        try { rootFd = LinuxRepoIdentities.WalkNoFollow(components, canonical); }
        catch (RepoIdentityRefused e) { throw RuntimeRefused(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
        try
        {
            if (Libc.StatxFullFd(rootFd, out Libc.StatxFull rs) != 0) throw RuntimeRefused("the runtime directory cannot be examined");
            rootId = Libc.HandleOf(rootFd) is { } h ? $"{h.Type}-{Convert.ToHexStringLower(h.Bytes)}-{rs.BtimeSec}.{rs.BtimeNsec:D9}" : throw RuntimeRefused("the filesystem gives no handle for the runtime directory");
            if (!_skipOwnershipForSelfTest) CheckOwned(rs, ".");
        }
        finally { Libc.close(rootFd); }
        var files = new List<RuntimeFile>();
        long total = 0;
        string? entrySha = null;
        Walk(canonical, "", files, ref total, ref entrySha);
        if (files.Count == 0) throw RuntimeRefused("the runtime directory is empty");
        files.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        if (!files.Any(f => f.Path == NodeName)) throw RuntimeRefused($"it has no {NodeName} at its root");
        if (entrySha is null) throw RuntimeRefused($"it has no helper entry {EngineRuntime.EntryRelative} (build the engine first)");
        if (!files.Any(f => f.Path == git)) throw RuntimeRefused($"it has no {git}");
        MeasuredImage node = MeasureImage(canonical + "/" + NodeName, [.. components, NodeName], RuntimeRefused);
        MeasuredImage gitImage = MeasureImage(canonical + "/" + git, [.. components, .. git.Split('/')], RuntimeRefused);
        if (files.First(f => f.Path == NodeName).Sha256 != node.Sha256 || files.First(f => f.Path == git).Sha256 != gitImage.Sha256)
            throw RuntimeRefused("the runtime changed while it was measured");
        return new MeasuredRuntime(canonical, rootId, git, node, gitImage, entrySha, EngineRuntime.TreeDigest(files), files.Count, total);
    }

    /// <summary>Phase 6 (§7 b): the runtime tree (Node and the engine) and an installed git outside it, measured as Codex is:
    /// its image, root-owned with no group or other write on the file and every ancestor.</summary>
    private static MeasuredRuntime MeasureWithInstalledGit(string root, string gitPath)
    {
        if (Path.GetFileName(gitPath) != "git") throw RuntimeRefused("the installed git must be a path ending in git");
        string[] components;
        try { components = LinuxRepoIdentities.Parse(root); }
        catch (ArgumentException e) { throw RuntimeRefused(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
        string canonical = "/" + string.Join('/', components);
        if (!_skipOwnershipForSelfTest) CheckAncestors(components, RuntimeRefused);
        string rootId = RootIdentity(components, canonical);
        var files = new List<RuntimeFile>();
        long total = 0;
        string? entrySha = null;
        Walk(canonical, "", files, ref total, ref entrySha);
        files.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        if (!files.Any(f => f.Path == NodeName)) throw RuntimeRefused($"it has no {NodeName} at its root");
        if (entrySha is null) throw RuntimeRefused($"it has no helper entry {EngineRuntime.EntryRelative} (build the engine first)");
        MeasuredImage node = MeasureImage(canonical + "/" + NodeName, [.. components, NodeName], RuntimeRefused);
        MeasuredImage gitImage = MeasureApproved(gitPath, RuntimeRefused);
        if (files.First(f => f.Path == NodeName).Sha256 != node.Sha256) throw RuntimeRefused("the runtime changed while it was measured");
        string git = "/" + string.Join('/', LinuxRepoIdentities.Parse(gitPath));
        return new MeasuredRuntime(canonical, rootId, null, node, gitImage, entrySha, EngineRuntime.TreeDigest(files), files.Count, total, git);
    }

    private static string RootIdentity(string[] components, string canonical)
    {
        int rootFd;
        try { rootFd = LinuxRepoIdentities.WalkNoFollow(components, canonical); }
        catch (RepoIdentityRefused e) { throw RuntimeRefused(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
        try
        {
            if (Libc.StatxFullFd(rootFd, out Libc.StatxFull rs) != 0) throw RuntimeRefused("the runtime directory cannot be examined");
            string id = Libc.HandleOf(rootFd) is { } h ? $"{h.Type}-{Convert.ToHexStringLower(h.Bytes)}-{rs.BtimeSec}.{rs.BtimeNsec:D9}" : throw RuntimeRefused("the filesystem gives no handle for the runtime directory");
            if (!_skipOwnershipForSelfTest) CheckOwned(rs, ".");
            return id;
        }
        finally { Libc.close(rootFd); }
    }

    private static void Walk(string dir, string rel, List<RuntimeFile> files, ref long total, ref string? entrySha)
    {
        foreach (string entry in Directory.EnumerateFileSystemEntries(dir).Order(StringComparer.Ordinal))
        {
            string name = Path.GetFileName(entry);
            string childRel = rel.Length == 0 ? name : rel + "/" + name;
            if (Libc.StatxFullAt(Libc.AT_FDCWD, entry, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0) throw RuntimeRefused($"'{childRel}' cannot be examined");
            if (!_skipOwnershipForSelfTest) CheckOwned(st, childRel);
            if (st.Type == Libc.S_IFDIR) { Walk(entry, childRel, files, ref total, ref entrySha); continue; }
            if (st.Type != Libc.S_IFREG) throw RuntimeRefused($"'{childRel}' is a link or special file");
            if (files.Count >= MaxFiles) throw RuntimeRefused($"it has more than {MaxFiles} files");
            using FileStream fs = new(entry, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan);
            string sha = Convert.ToHexStringLower(SHA256.HashData(fs));
            total += (long)st.Size;
            if (total > MaxTotalBytes) throw RuntimeRefused("it is larger than 4 GiB");
            files.Add(new RuntimeFile(childRel, (long)st.Size, sha));
            if (childRel == EngineRuntime.EntryRelative) entrySha = sha;
        }
    }

    private static void CheckOwned(Libc.StatxFull st, string rel)
    {
        if (st.Uid != 0) throw RuntimeRefused($"'{rel}' is owned by uid {st.Uid}, not root (a user-writable runtime is refused)");
        if ((st.Perm & 0x12 /* 0o022 */) != 0) throw RuntimeRefused($"'{rel}' is group- or other-writable");
    }

    /// <summary>Every directory from <c>/</c> down to <paramref name="components"/> (inclusive) is owned by root and grants no
    /// group or other write.</summary>
    private static void CheckAncestors(string[] components, Func<string, CustodianRefusal> refuse)
    {
        for (int i = 0; i <= components.Length; i++)
        {
            string p = "/" + string.Join('/', components[..i]);
            if (Libc.StatxFullAt(Libc.AT_FDCWD, p, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0) throw refuse($"its ancestor {p} cannot be examined");
            if (st.Uid != 0 || (st.Perm & 0x12 /* 0o022 */) != 0) throw refuse($"its ancestor {p} is not root-owned or is group-/other-writable (someone else could replace what it contains)");
        }
    }

    /// <summary>A minimal 64-bit little-endian ELF header the measurement accepts, varied by <paramref name="variant"/>
    /// (the shared corpora's synthetic Codex and runtime images).</summary>
    internal static byte[] FixtureImage(byte variant)
    {
        var b = new byte[128];
        b[0] = 0x7f; b[1] = (byte)'E'; b[2] = (byte)'L'; b[3] = (byte)'F';
        b[4] = 2; b[5] = 1; b[6] = 1; // ELFCLASS64, ELFDATA2LSB, EV_CURRENT
        b[16] = 2; b[18] = 0x3e; b[20] = 1; // ET_EXEC, EM_X86_64, version
        b[64] = variant;
        "CodeParley synthetic ELF fixture"u8.CopyTo(b.AsSpan(72));
        return b;
    }
}

/// <summary>Phase 5 (§4.1): the Linux executable measurement behind the core's seam.</summary>
internal sealed class LinuxImageMeasure : IImageMeasure
{
    public string NodeName => LinuxImages.NodeName;
    public string GitRelative(string rel) => LinuxImages.GitRelative(rel);
    public MeasuredImage MeasureCodex(string path) => LinuxImages.MeasureCodex(path);
    public MeasuredRuntime MeasureRuntime(string root, string? gitRelative, string? gitPath) => LinuxImages.MeasureRuntime(root, gitRelative, gitPath);
    public string FixtureCodexName => "codex";
    public string FixtureRuntimeGit => "git/bin/git";
    public byte[] FixtureImage(byte variant) => LinuxImages.FixtureImage(variant);
    public void SkipOwnershipChecksForSelfTest() => LinuxImages.SkipOwnershipChecksForSelfTest();
}
