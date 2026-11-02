using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using Microsoft.Win32.SafeHandles;

namespace CodeParley.Custodian.Security;

/// <summary>
/// P3.4C-5 (contract §2.1, N5-6): the administrator-installed engine runtime the helper runs — node.exe, the built engine
/// (<c>dist/</c>, production <c>node_modules</c>, <c>prompts/</c>) and the approved git distribution in one directory. The
/// custodian measures it itself, with its own token:
/// <list type="bullet">
/// <item>the root is reached by the no-follow walk from the volume root (P3.4C-0): a link, junction or mount point in any
/// component is refused;</item>
/// <item>every directory and file below it is enumerated; a reparse point anywhere is refused; each file is opened without
/// following a reparse point and hashed through that handle;</item>
/// <item>node.exe and git are native PE images (the D-17 measurement);</item>
/// <item>the tree is <b>administrator-controlled</b>: every directory and file is owned by SYSTEM, Administrators or
/// TrustedInstaller and grants no write-like right to anyone else, and no ancestor of the root lets anyone else delete,
/// replace or re-permission what is below it. A user-writable runtime is refused;</item>
/// <item>the tree digest covers every file's relative path, size and SHA-256, sorted ordinally
/// (<c>arl.engine-runtime-tree.v1</c>).</item>
/// </list>
/// It is measured when the operator approves it (prepare and commit) and again before every helper launch, outside the
/// ledger lock; any difference refuses (CONFIG_MISMATCH), never falling back to another computation.
/// </summary>
internal static class WindowsEngineRuntime
{
    internal const string NodeName = "node.exe";
    internal const string EntryRelative = EngineRuntime.EntryRelative;
    private const int MaxFiles = 100_000;
    private const long MaxTotalBytes = 4L * 1024 * 1024 * 1024;

    private static readonly HashSet<string> TrustedOwners = new(StringComparer.Ordinal)
    {
        "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    };

    // Self-test only (never set by the service): measure a scratch tree, which a non-elevated test cannot make
    // administrator-owned. Every other property is still checked.
    private static bool _skipAclForSelfTest;
    internal static void SkipAclCheckForSelfTest() => _skipAclForSelfTest = true;

    private static CustodianRefusal Refused(string why) => new(ErrorCodes.RuntimeNotApproved, $"the engine runtime cannot be approved: {why}");

    /// <summary>The validated relative path of the approved git inside the runtime (e.g. <c>git/mingw64/bin/git.exe</c>).</summary>
    internal static string GitRelative(string rel)
    {
        string r = rel.Replace('\\', '/');
        string[] parts = r.Split('/');
        if (r.Length is < 7 or > 260 || r.StartsWith('/') || parts.Any(s => s.Length == 0 || s is "." or ".." || s.Contains(':') || s.EndsWith('.') || s.EndsWith(' ')) || !parts[^1].Equals("git.exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("the runtime's git must be a relative path inside it ending in git.exe");
        return r;
    }

    internal static MeasuredRuntime Measure(string root, string? gitRelative, string? gitPath = null)
    {
        if (gitPath is not null) return MeasureWithInstalledGit(root, gitPath);
        string git = GitRelative(gitRelative!);
        string canonical = WalkRoot(root, out string rootFileId);
        var files = new List<RuntimeFile>();
        long total = 0;
        string? entrySha = null;
        if (!_skipAclForSelfTest) CheckAncestors(canonical);
        Walk(canonical, "", files, ref total, ref entrySha);
        if (files.Count == 0) throw Refused("the runtime directory is empty");
        files.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        if (!files.Any(f => f.Path == NodeName)) throw Refused($"it has no {NodeName} at its root");
        if (entrySha is null) throw Refused($"it has no helper entry {EntryRelative} (build the engine first)");
        if (!files.Any(f => string.Equals(f.Path, git, StringComparison.OrdinalIgnoreCase))) throw Refused($"it has no {git}");
        MeasuredImage node = MeasureImage(Path.Combine(canonical, NodeName));
        MeasuredImage gitImage = MeasureImage(Path.Combine(canonical, git.Replace('/', '\\')));
        // The images were also hashed as tree files; both readings must agree (a change in between refuses).
        if (files.First(f => f.Path == NodeName).Sha256 != node.Sha256 || files.First(f => string.Equals(f.Path, git, StringComparison.OrdinalIgnoreCase)).Sha256 != gitImage.Sha256)
            throw Refused("the runtime changed while it was measured");
        return new MeasuredRuntime(canonical, rootFileId, git, node, gitImage, entrySha, EngineRuntime.TreeDigest(files), files.Count, total);
    }

    /// <summary>Phase 6 (§7 b): the runtime tree (Node and the engine, hashed file by file) and an administrator-installed
    /// git outside it, measured as Codex is — its image, and its administrator control: the file, every file beside it (the
    /// libraries it loads) and every ancestor writable or replaceable by no one but SYSTEM, Administrators or TrustedInstaller.</summary>
    private static MeasuredRuntime MeasureWithInstalledGit(string root, string gitPath)
    {
        string name = Path.GetFileName(gitPath);
        if (!name.Equals("git.exe", StringComparison.OrdinalIgnoreCase)) throw Refused("the installed git must be a path ending in git.exe");
        string canonical = WalkRoot(root, out string rootFileId);
        var files = new List<RuntimeFile>();
        long total = 0;
        string? entrySha = null;
        if (!_skipAclForSelfTest) CheckAncestors(canonical);
        Walk(canonical, "", files, ref total, ref entrySha);
        files.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        if (!files.Any(f => f.Path == NodeName)) throw Refused($"it has no {NodeName} at its root");
        if (entrySha is null) throw Refused($"it has no helper entry {EntryRelative} (build the engine first)");
        string gitDir = WalkRoot(Path.GetDirectoryName(gitPath) ?? throw Refused("the installed git path has no directory"), out _);
        string git = Path.Combine(gitDir, name);
        if (!_skipAclForSelfTest)
        {
            CheckAncestors(git);
            var dir = new DirectoryInfo(gitDir);
            CheckObject(dir.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner), gitDir, isDirectory: true);
            foreach (FileInfo f in dir.EnumerateFiles())
            {
                if ((f.Attributes & FileAttributes.ReparsePoint) != 0) throw Refused($"'{f.FullName}' beside the installed git is a reparse point");
                CheckObject(f.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner), f.FullName, isDirectory: false);
            }
        }
        MeasuredImage node = MeasureImage(Path.Combine(canonical, NodeName));
        MeasuredImage gitImage = MeasureImage(git);
        if (files.First(f => f.Path == NodeName).Sha256 != node.Sha256) throw Refused("the runtime changed while it was measured");
        return new MeasuredRuntime(canonical, rootFileId, null, node, gitImage, entrySha, EngineRuntime.TreeDigest(files), files.Count, total, git);
    }

    // ---- the walk ----

    /// <summary>Reach the root by the no-follow walk and return its canonical path and directory identity.</summary>
    private static string WalkRoot(string root, out string fileId)
    {
        string drive;
        string[] components;
        try { (drive, components) = WindowsRepoIdentities.Parse(root); }
        catch (ArgumentException e) { throw Refused(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal).Replace("repository path", "path", StringComparison.Ordinal)); }
        if (components.Length == 0) throw Refused("the path names a volume root");
        var open = new List<IntPtr>();
        try
        {
            IntPtr cur;
            try
            {
                cur = WindowsRepoIdentities.OpenVolumeRoot(drive, Native.FILE_READ_ATTRIBUTES, out _);
                open.Add(cur);
                foreach (string c in components) { cur = WindowsRepoIdentities.OpenChildDirectory(cur, c, Native.FILE_READ_ATTRIBUTES_NT); open.Add(cur); }
            }
            catch (ArgumentException e) { throw Refused(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
            fileId = FileIdOf(cur) ?? throw Refused("the volume reports no stable id for the runtime directory");
            string final = WindowsRepoIdentities.FinalPath(cur);
            return final.StartsWith(@"\\?\", StringComparison.Ordinal) ? final[4..] : final;
        }
        finally { for (int i = open.Count - 1; i >= 0; i--) Native.CloseHandle(open[i]); }
    }

    private static void Walk(string dir, string rel, List<RuntimeFile> files, ref long total, ref string? entrySha)
    {
        var info = new DirectoryInfo(dir);
        if (!_skipAclForSelfTest) CheckObject(info.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner), rel.Length == 0 ? "." : rel, isDirectory: true);
        foreach (FileSystemInfo e in info.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0, RecurseSubdirectories = false, IgnoreInaccessible = false, ReturnSpecialDirectories = false }))
        {
            string childRel = rel.Length == 0 ? e.Name : rel + "/" + e.Name;
            if ((e.Attributes & FileAttributes.ReparsePoint) != 0) throw Refused($"'{childRel}' is a link or reparse point");
            if ((e.Attributes & FileAttributes.Directory) != 0) { Walk(e.FullName, childRel, files, ref total, ref entrySha); continue; }
            if (files.Count >= MaxFiles) throw Refused($"it has more than {MaxFiles} files");
            RuntimeFile f = HashFile(e.FullName, childRel);
            total += f.Size;
            if (total > MaxTotalBytes) throw Refused("it is larger than 4 GiB");
            files.Add(f);
            if (childRel == EntryRelative) entrySha = f.Sha256;
        }
    }

    private static RuntimeFile HashFile(string path, string rel)
    {
        IntPtr h = Native.CreateFileW(path, 0x80000000 /* GENERIC_READ */ | Native.READ_CONTROL, Native.FILE_SHARE_READ, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_OPEN_REPARSE_POINT | 0x08000000 /* FILE_FLAG_SEQUENTIAL_SCAN */, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) throw Refused($"'{rel}' cannot be read by the custodian (error {Marshal.GetLastWin32Error()})");
        using var handle = new SafeFileHandle(h, ownsHandle: true);
        if (!Native.GetFileInformationByHandle(h, out Native.BY_HANDLE_FILE_INFORMATION fi)) throw Refused($"'{rel}': its attributes cannot be read");
        if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) throw Refused($"'{rel}' is a reparse point");
        using var fs = new FileStream(handle, FileAccess.Read, 1 << 16);
        if (!_skipAclForSelfTest) CheckObject(fs.GetAccessControl(), rel, isDirectory: false);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] chunk = new byte[1 << 20];
        long size = 0;
        for (int n; (n = fs.Read(chunk, 0, chunk.Length)) > 0;) { sha.AppendData(chunk, 0, n); size += n; }
        return new RuntimeFile(rel, size, Convert.ToHexStringLower(sha.GetHashAndReset()));
    }

    private static MeasuredImage MeasureImage(string path)
    {
        try { return WindowsCodexImage.Measure(path); }
        catch (CustodianRefusal r) { throw Refused(r.Message.Replace("the Codex installation is not a supported native image", Path.GetFileName(path) + " is not a supported native image", StringComparison.Ordinal)); }
    }

    // ---- administrator control ----

    private const FileSystemRights WriteLike = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
    private const FileSystemRights SwapLike = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
    private const int GenericWriteOrAll = unchecked((int)0x40000000) | 0x10000000;

    /// <summary>A runtime directory or file: a trusted owner, and no write-like right for anyone else (an inherit-only ACE
    /// applies to the children, which are checked themselves).</summary>
    private static void CheckObject(FileSystemSecurity sec, string rel, bool isDirectory)
    {
        string? owner = ((SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier)))?.Value;
        if (owner is null || !TrustedOwners.Contains(owner)) throw Refused($"'{rel}' is owned by {owner ?? "an unknown principal"}, not SYSTEM, Administrators or TrustedInstaller (a user-writable runtime is refused)");
        foreach (FileSystemAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (r.AccessControlType != AccessControlType.Allow || (r.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
            string sid = ((SecurityIdentifier)r.IdentityReference).Value;
            if (TrustedOwners.Contains(sid)) continue;
            if ((r.FileSystemRights & WriteLike) != 0 || ((int)r.FileSystemRights & GenericWriteOrAll) != 0)
                throw Refused($"'{rel}' grants {sid} write access ({r.FileSystemRights}) (a user-writable runtime is refused)");
        }
    }

    /// <summary>No ancestor of the root lets anyone but SYSTEM, Administrators or TrustedInstaller delete, rename into place,
    /// re-permission or take ownership of what is below it (creating a NEW sibling, as Users may in C:\, is harmless).</summary>
    private static void CheckAncestors(string root)
    {
        for (DirectoryInfo? d = new DirectoryInfo(root).Parent; d is not null; d = d.Parent)
        {
            DirectorySecurity sec = d.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            string? owner = ((SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier)))?.Value;
            if (owner is null || !TrustedOwners.Contains(owner)) throw Refused($"its ancestor {d.FullName} is owned by {owner ?? "an unknown principal"}, who could replace the runtime");
            foreach (FileSystemAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (r.AccessControlType != AccessControlType.Allow || (r.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                string sid = ((SecurityIdentifier)r.IdentityReference).Value;
                if (TrustedOwners.Contains(sid)) continue;
                if ((r.FileSystemRights & SwapLike) != 0 || ((int)r.FileSystemRights & unchecked((int)0x10000000)) != 0)
                    throw Refused($"its ancestor {d.FullName} lets {sid} delete or re-permission what it contains ({r.FileSystemRights})");
            }
        }
    }

    private static string? FileIdOf(IntPtr handle)
    {
        IntPtr buf = Marshal.AllocHGlobal(24);
        try
        {
            if (!Native.GetFileInformationByHandleEx(handle, Native.FileIdInfo, buf, 24)) return null;
            ulong volumeSerial = (ulong)Marshal.ReadInt64(buf);
            byte[] id = new byte[16];
            Marshal.Copy(buf + 8, id, 0, 16);
            if (volumeSerial == 0 || id.All(b => b == 0)) return null;
            return $"{volumeSerial:x16}-{Convert.ToHexString(id).ToLowerInvariant()}";
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}

/// <summary>Phase 5 (§4.1): the Windows executable measurement behind the core's <see cref="Platform.Images"/> seam.</summary>
internal sealed class WindowsImageMeasure : IImageMeasure
{
    public string NodeName => WindowsEngineRuntime.NodeName;
    public string GitRelative(string rel) => WindowsEngineRuntime.GitRelative(rel);
    public MeasuredImage MeasureCodex(string path) => WindowsCodexImage.Measure(path);
    public MeasuredRuntime MeasureRuntime(string root, string? gitRelative, string? gitPath) => WindowsEngineRuntime.Measure(root, gitRelative, gitPath);
    public string FixtureCodexName => "codex.exe";
    public string FixtureRuntimeGit => "git/cmd/git.exe";
    public byte[] FixtureImage(byte variant) => CodeParley.Custodian.Cli.ConfigFixture.PeBytes(variant);
    public void SkipOwnershipChecksForSelfTest() => WindowsEngineRuntime.SkipAclCheckForSelfTest();
}
