using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Linux.Native;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 (contract §4.6, D-L1, D5-I): a repository's identity as the custodian establishes it on Linux, from a
/// descriptor it opened itself by a no-follow walk from <c>/</c> — one component at a time with
/// <c>openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)</c>, so a symbolic or magic
/// link or a mount crossing in ANY component is refused rather than followed. From the final <c>O_PATH</c> descriptor:
/// <list type="bullet">
/// <item><c>fstatfs</c>: an ext4 filesystem (<c>EXT4_SUPER_MAGIC</c>) and its <c>f_fsid</c> (on ext4 the fold of the
/// superblock UUID, stable across remount and reboot; VERIFIED E1), which must be one the operator provisioned after a
/// privileged check of <c>metadata_csum</c> and 256-byte inodes;</item>
/// <item><c>name_to_handle_at(AT_EMPTY_PATH)</c>: the ext4 file handle (<c>FILEID_INO32_GEN</c>: the 32-bit inode number
/// and its random 32-bit generation; a generation of 0 is refused, it is a decode wildcard);</item>
/// <item><c>statx(STATX_BTIME)</c>: the birth time, set only at inode creation and unchangeable by its owner (E7).</item>
/// </list>
/// The key <c>fid2-&lt;fsid&gt;-&lt;handle type&gt;-&lt;handle&gt;-&lt;btime&gt;</c> is collision-RESISTANT, not collision-proof: a
/// replaced directory is distinguished immediately by its generation and in a brute force by its birth time (§10). The
/// path is only a locator; it is refused, never normalized.
/// </summary>
internal static class LinuxRepoIdentities
{
    internal const string Scheme = "fid2";
    private const int MaxPathChars = 1024;
    private const ulong ResolveFlags = Libc.RESOLVE_BENEATH | Libc.RESOLVE_NO_SYMLINKS | Libc.RESOLVE_NO_MAGICLINKS | Libc.RESOLVE_NO_XDEV;

    /// <summary>Self-test only (the shared corpora in a scratch directory): accept a filesystem the operator has not
    /// provisioned. Never set by the service.</summary>
    private static bool _anyExt4ForSelfTest;
    internal static void AcceptUnprovisionedFilesystemsForSelfTest() => _anyExt4ForSelfTest = true;

    /// <summary>Paths a repository may not be inside (the store, the runtime, the runtime directories, system trees).</summary>
    internal static readonly string[] ForbiddenRoots = ["/var/lib/codeparley", "/opt/codeparley", "/run", "/proc", "/sys", "/dev", "/etc", "/boot", "/usr"];

    private static RepoIdentityRefused Refused(string why) => new(RepoIdentities.RefusedPrefix + why);

    internal static RepoIdentity Resolve(string repositoryRoot)
    {
        string[] components = Parse(repositoryRoot);
        string canonical = "/" + string.Join('/', components);
        foreach (string f in ForbiddenRoots)
            if (canonical == f || canonical.StartsWith(f + "/", StringComparison.Ordinal)) throw Refused($"a repository may not be inside {f}");
        int fd = WalkNoFollow(components, canonical);
        try { return Identify(fd, canonical); }
        finally { Libc.close(fd); }
    }

    /// <summary>The strict locator syntax: absolute, no NUL or control character, no empty, <c>.</c> or <c>..</c>
    /// component (a single trailing <c>/</c> is accepted), at most 1024 characters.</summary>
    internal static string[] Parse(string input)
    {
        if (string.IsNullOrEmpty(input)) throw Refused("the repository path is empty");
        if (input.Length > MaxPathChars) throw Refused($"the repository path is longer than {MaxPathChars} characters");
        if (input[0] != '/') throw Refused("the repository path is not absolute");
        if (input.Any(char.IsControl)) throw Refused("the repository path contains a control character");
        string p = input.Length > 1 && input.EndsWith('/') ? input[..^1] : input;
        if (p == "/") throw Refused("the repository path names the filesystem root");
        string[] parts = p[1..].Split('/');
        foreach (string c in parts)
            if (c.Length == 0 || c is "." or "..") throw Refused("the repository path has an empty, '.' or '..' component (refused, not normalized)");
        return parts;
    }

    /// <summary>The no-follow walk from <c>/</c>; returns an O_PATH descriptor of the final directory.</summary>
    internal static int WalkNoFollow(string[] components, string canonical, bool finalIsDirectory = true)
    {
        int cur = Libc.Openat(Libc.AT_FDCWD, "/", Libc.O_PATH | Libc.O_DIRECTORY | Libc.O_CLOEXEC, 0);
        if (cur < 0) throw Refused("the filesystem root cannot be opened");
        try
        {
            for (int i = 0; i < components.Length; i++)
            {
                bool last = i == components.Length - 1;
                int flags = Libc.O_PATH | Libc.O_CLOEXEC | (last && !finalIsDirectory ? 0 : Libc.O_DIRECTORY);
                int next = -1;
                for (int attempt = 0; attempt < 8; attempt++)
                {
                    next = Libc.Openat2(cur, components[i], flags, 0, ResolveFlags);
                    if (next >= 0 || Libc.Errno != Libc.EAGAIN) break;
                }
                if (next < 0)
                {
                    int e = Libc.Errno;
                    string at = "/" + string.Join('/', components[..(i + 1)]);
                    throw e switch
                    {
                        Libc.ELOOP => Refused($"{at} is a symbolic or magic link (refused, not followed)"),
                        Libc.EXDEV => Refused($"{at} crosses a mount point (refused; a repository must be on the root filesystem)"),
                        Libc.ENOENT => Refused($"{at} does not exist"),
                        Libc.ENOTDIR => Refused($"{at} is not a directory"),
                        Libc.EACCES => new CustodianRefusal(ErrorCodes.RepositoryNotReadable,
                            $"the custodian cannot traverse {at} (permission denied); nothing was begun — the operator grants traverse-only access on each ancestor and read on the repository: `sudo setfacl -m u:codeparley:--x <each ancestor>` and `sudo setfacl -m u:codeparley:r-x {canonical}` (the test VM's cpt-acl does exactly this)"),
                        _ => Refused($"{at} cannot be opened ({Libc.ErrText(e)})"),
                    };
                }
                Libc.close(cur);
                cur = next;
            }
            return cur;
        }
        catch { Libc.close(cur); throw; }
    }

    private static RepoIdentity Identify(int fd, string canonical)
    {
        if (Libc.StatxFullFd(fd, out Libc.StatxFull st) != 0) throw Refused("the repository cannot be examined");
        if (st.Type != Libc.S_IFDIR) throw Refused("the repository is not a directory");
        (long type, ulong fsid) = Libc.FsOf(fd) ?? throw Refused("the repository's filesystem cannot be examined");
        bool provisioned = _anyExt4ForSelfTest || LinuxConfig.FilesystemProvisioned(fsid);
        (int htype, byte[] handle)? h = type == Libc.EXT4_SUPER_MAGIC && provisioned ? Libc.HandleOf(fd) : null;
        return new RepoIdentity(KeyOf(new IdentityFacts(st.HasBtime, st.BtimeSec, st.BtimeNsec, type, fsid, provisioned, h?.htype, h?.handle)), canonical, "ext4");
    }

    /// <summary>What the descriptor gave: the facts the key is derived from (injected by the identity self-test).</summary>
    internal readonly record struct IdentityFacts(bool HasBtime, long BtimeSec, uint BtimeNsec, long FsType, ulong Fsid, bool Provisioned, int? HandleType, byte[]? Handle);

    /// <summary>The identity key from the descriptor's facts, or a refusal (contract §4.6, D-L1). Pure.</summary>
    internal static string KeyOf(IdentityFacts f)
    {
        if (f.FsType != Libc.EXT4_SUPER_MAGIC) throw Refused($"the repository is not on an ext4 filesystem (type 0x{f.FsType:x}; only ext4 is supported)");
        if (!f.Provisioned)
            throw Refused($"the repository's filesystem (fsid {f.Fsid:x16}) was not provisioned by the operator (its metadata_csum and inode size are checked at provisioning)");
        if (!f.HasBtime) throw Refused("the filesystem reports no birth time for the repository (ext4 with 256-byte inodes is required)");
        if (f.HandleType is not { } htype || f.Handle is not { } handle) throw Refused("the filesystem gives no file handle for the repository");
        if (htype is not (1 or 2) || handle.Length < 8) throw Refused($"unsupported file handle type {htype} (ext4 FILEID_INO32_GEN expected)");
        uint generation = BitConverter.ToUInt32(handle, 4);
        if (generation == 0) throw Refused("the repository's inode generation is 0 (a wildcard; refused)");
        return $"{Scheme}-{f.Fsid:x16}-{htype}-{Convert.ToHexStringLower(handle)}-{f.BtimeSec}_{f.BtimeNsec:D9}";
    }
}

/// <summary>Phase 5 (§4.1): the Linux repository identity behind the core's seam.</summary>
internal sealed class LinuxRepoIdentityResolver : IRepoIdentityResolver
{
    public string Scheme => LinuxRepoIdentities.Scheme;
    public RepoIdentity Resolve(string repositoryRoot) => LinuxRepoIdentities.Resolve(repositoryRoot);
}
