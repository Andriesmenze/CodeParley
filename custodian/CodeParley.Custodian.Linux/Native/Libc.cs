// Copied from the reviewed P3.1B broker (broker/CodeParley.Broker.Linux/Native/Libc.cs) for the Phase 5 Linux custodian host
// (contract §4.1, §6); extended in LibcCustodian.cs. The broker itself is unchanged and stays undeployed.
using System.Runtime.InteropServices;
using System.Text;

namespace CodeParley.Custodian.Linux.Native;

/// <summary>
/// Thin glibc bindings for the few descriptor-relative and identity calls .NET does not expose.
/// Supported architectures are x86_64 and aarch64 (Linux), whose open(2) flag values differ;
/// <see cref="EnsureSupportedArchitecture"/> refuses anything else instead of guessing.
/// </summary>
internal static unsafe partial class Libc
{
    private const string L = "libc";

    internal static readonly bool IsArm64 = RuntimeInformation.ProcessArchitecture == Architecture.Arm64;

    // open(2) flags. Most are identical on x86_64 and aarch64; O_DIRECTORY/O_NOFOLLOW are not.
    internal const int O_RDONLY = 0x0;
    internal const int O_WRONLY = 0x1;
    internal const int O_CREAT = 0x40;
    internal const int O_EXCL = 0x80;
    internal const int O_NOCTTY = 0x100;
    internal const int O_TRUNC = 0x200;
    internal const int O_NONBLOCK = 0x800;
    internal const int O_CLOEXEC = 0x80000;
    internal static readonly int O_DIRECTORY = IsArm64 ? 0x4000 : 0x10000;
    internal static readonly int O_NOFOLLOW = IsArm64 ? 0x8000 : 0x20000;

    internal const int AT_FDCWD = -100;
    internal const int AT_SYMLINK_NOFOLLOW = 0x100;
    internal const int AT_REMOVEDIR = 0x200;
    internal const int AT_EMPTY_PATH = 0x1000;

    // openat2(2) resolve flags (Linux 5.6+).
    internal const ulong RESOLVE_NO_XDEV = 0x01;
    internal const ulong RESOLVE_NO_MAGICLINKS = 0x02;
    internal const ulong RESOLVE_NO_SYMLINKS = 0x04;
    internal const ulong RESOLVE_BENEATH = 0x08;

    private const long SYS_openat2 = 437;   // unified syscall number (x86_64 and aarch64)

    internal const int F_DUPFD_CLOEXEC = 1030;
    internal const int LOCK_EX = 2, LOCK_NB = 4;

    internal const uint S_IFMT = 0xF000, S_IFDIR = 0x4000, S_IFREG = 0x8000, S_IFLNK = 0xA000;
    internal const uint STATX_BASIC_STATS = 0x7FF;

    internal const int SOL_SOCKET = 1, SO_PEERCRED = 17;   // generic values (x86_64/aarch64)

    internal const int ENOENT = 2, EINTR = 4, EAGAIN = 11, EACCES = 13, EEXIST = 17, EXDEV = 18;
    internal const int ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ENOSYS = 38, ENOTEMPTY = 39, ELOOP = 40;
    internal const int EPERM = 1, ENAMETOOLONG = 36, E2BIG = 7;

    internal const byte DT_UNKNOWN = 0, DT_DIR = 4, DT_LNK = 10;

    [StructLayout(LayoutKind.Sequential)]
    internal struct OpenHow { public ulong Flags; public ulong Mode; public ulong Resolve; }

    /// <summary>struct statx — architecture-independent layout (256 bytes).</summary>
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    internal struct Statx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(16)] public uint Nlink;
        [FieldOffset(20)] public uint Uid;
        [FieldOffset(24)] public uint Gid;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(32)] public ulong Ino;
        [FieldOffset(40)] public ulong Size;
        [FieldOffset(112)] public long MtimeSec;
        [FieldOffset(120)] public uint MtimeNsec;
        [FieldOffset(136)] public uint DevMajor;
        [FieldOffset(140)] public uint DevMinor;

        internal readonly uint Type => Mode & S_IFMT;
        internal readonly bool IsDir => Type == S_IFDIR;
        internal readonly bool IsRegular => Type == S_IFREG;
        internal readonly bool IsSymlink => Type == S_IFLNK;
        internal readonly uint Perm => Mode & 0xFFFu;   // permission + setuid/setgid/sticky bits
        internal readonly ulong Dev => ((ulong)DevMajor << 32) | DevMinor;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UCred { public int Pid; public uint Uid; public uint Gid; }

    [DllImport(L, SetLastError = true)] private static extern long syscall(long number, int dirfd, byte* path, OpenHow* how, nuint size);
    [DllImport(L, SetLastError = true)] private static extern int openat(int dirfd, byte* path, int flags, uint mode);
    [DllImport(L, SetLastError = true)] internal static extern int close(int fd);
    [DllImport(L, SetLastError = true)] private static extern int mkdirat(int dirfd, byte* path, uint mode);
    [DllImport(L, SetLastError = true)] internal static extern int fchown(int fd, uint uid, uint gid);
    [DllImport(L, SetLastError = true)] private static extern int fchownat(int dirfd, byte* path, uint uid, uint gid, int flags);
    [DllImport(L, SetLastError = true)] internal static extern int fchmod(int fd, uint mode);
    [DllImport(L, SetLastError = true)] private static extern int unlinkat(int dirfd, byte* path, int flags);
    [DllImport(L, SetLastError = true)] private static extern int renameat(int olddirfd, byte* oldpath, int newdirfd, byte* newpath);
    [DllImport(L, SetLastError = true)] private static extern int statx(int dirfd, byte* path, int flags, uint mask, Statx* buf);
    [DllImport(L, SetLastError = true)] private static extern IntPtr fdopendir(int fd);
    [DllImport(L, SetLastError = true)] private static extern IntPtr readdir(IntPtr dirp);
    [DllImport(L, SetLastError = true)] private static extern int closedir(IntPtr dirp);
    [DllImport(L, SetLastError = true)] internal static extern int fcntl(int fd, int cmd, int arg);
    [DllImport(L, SetLastError = true)] internal static extern nint read(int fd, byte* buf, nuint count);
    [DllImport(L, SetLastError = true)] internal static extern nint write(int fd, byte* buf, nuint count);
    [DllImport(L, SetLastError = true)] internal static extern int fsync(int fd);
    [DllImport(L, SetLastError = true)] internal static extern int flock(int fd, int operation);
    [DllImport(L)] internal static extern uint geteuid();
    [DllImport(L)] internal static extern uint umask(uint mask);
    [DllImport(L, SetLastError = true)] internal static extern int getsockopt(int sockfd, int level, int optname, void* optval, uint* optlen);
    [DllImport(L, SetLastError = true)] private static extern int mkfifo(byte* path, uint mode);
    [DllImport(L, SetLastError = true)] private static extern int getpwnam_r(byte* name, byte* pwd, byte* buf, nuint buflen, IntPtr* result);
    [DllImport(L, SetLastError = true)] private static extern int getpwuid_r(uint uid, byte* pwd, byte* buf, nuint buflen, IntPtr* result);
    [DllImport(L, SetLastError = true)] private static extern int getgrnam_r(byte* name, byte* grp, byte* buf, nuint buflen, IntPtr* result);
    [DllImport(L, SetLastError = true)] private static extern int getgrgid_r(uint gid, byte* grp, byte* buf, nuint buflen, IntPtr* result);
    [DllImport(L, SetLastError = true)] private static extern int getgrouplist(byte* user, uint group, uint* groups, int* ngroups);

    internal static int Errno => Marshal.GetLastPInvokeError();

    internal static string ErrText(int errno) => $"{Marshal.GetPInvokeErrorMessage(errno)} (errno {errno})";

    internal static void EnsureSupportedArchitecture()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("the CodeParley Linux custodian runs only on Linux");
        Architecture a = RuntimeInformation.ProcessArchitecture;
        if (a is not (Architecture.X64 or Architecture.Arm64))
            throw new PlatformNotSupportedException($"unsupported architecture {a} (supported: x64, arm64)");
    }

    /// <summary>NUL-terminated UTF-8 bytes; rejects embedded NULs.</summary>
    internal static byte[] Z(string s)
    {
        if (s.Contains('\0')) throw new ArgumentException("path contains NUL");
        byte[] b = new byte[Encoding.UTF8.GetByteCount(s) + 1];
        Encoding.UTF8.GetBytes(s, 0, s.Length, b, 0);
        return b;
    }

    internal static int Openat2(int dirfd, string path, int flags, uint mode, ulong resolve)
    {
        byte[] p = Z(path);
        var how = new OpenHow { Flags = (ulong)(uint)flags, Mode = mode, Resolve = resolve };
        fixed (byte* pp = p)
        {
            long r = syscall(SYS_openat2, dirfd, pp, &how, (nuint)sizeof(OpenHow));
            return (int)r;
        }
    }

    internal static int Openat(int dirfd, string path, int flags, uint mode)
    {
        byte[] p = Z(path);
        fixed (byte* pp = p) return openat(dirfd, pp, flags, mode);
    }

    internal static int Mkfifo(string path, uint mode)
    {
        byte[] p = Z(path);
        fixed (byte* pp = p) return mkfifo(pp, mode);
    }

    internal static int Mkdirat(int dirfd, string name, uint mode)
    {
        byte[] p = Z(name);
        fixed (byte* pp = p) return mkdirat(dirfd, pp, mode);
    }

    internal static int Fchownat(int dirfd, string name, uint uid, uint gid, int flags)
    {
        byte[] p = Z(name);
        fixed (byte* pp = p) return fchownat(dirfd, pp, uid, gid, flags);
    }

    internal static int Unlinkat(int dirfd, string name, int flags)
    {
        byte[] p = Z(name);
        fixed (byte* pp = p) return unlinkat(dirfd, pp, flags);
    }

    internal static int Renameat(int olddirfd, string oldName, int newdirfd, string newName)
    {
        byte[] o = Z(oldName), n = Z(newName);
        fixed (byte* op = o) fixed (byte* np = n) return renameat(olddirfd, op, newdirfd, np);
    }

    internal static int StatxAt(int dirfd, string path, int flags, out Statx st)
    {
        byte[] p = Z(path);
        Statx s;
        int r;
        fixed (byte* pp = p) r = statx(dirfd, pp, flags, STATX_BASIC_STATS, &s);
        st = s;
        return r;
    }

    internal static int StatxFd(int fd, out Statx st) => StatxAt(fd, "", AT_EMPTY_PATH, out st);

    /// <summary>Entry names of a directory (excluding . and ..), read through an independent open
    /// file description so the caller's descriptor offset is untouched.</summary>
    internal static List<(string Name, byte Type)> ReadDirectory(int dirfd)
    {
        int fd = Openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if (fd < 0) throw new IOException("openat(.) failed: " + ErrText(Errno));
        IntPtr dirp = fdopendir(fd);
        if (dirp == IntPtr.Zero) { int e = Errno; close(fd); throw new IOException("fdopendir failed: " + ErrText(e)); }
        var names = new List<(string, byte)>();
        try
        {
            while (true)
            {
                Marshal.SetLastPInvokeError(0);
                IntPtr ent = readdir(dirp);
                if (ent == IntPtr.Zero)
                {
                    int e = Errno;
                    if (e != 0) throw new IOException("readdir failed: " + ErrText(e));
                    break;
                }
                // glibc struct dirent (64-bit): d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name[...]
                byte type = *((byte*)ent + 18);
                string? name = Marshal.PtrToStringUTF8(ent + 19);
                if (name is null or "." or "..") continue;
                names.Add((name, type));
            }
        }
        finally { closedir(dirp); }
        return names;
    }

    internal static UCred PeerCredentials(int sockfd)
    {
        UCred c;
        uint len = (uint)sizeof(UCred);
        if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &c, &len) != 0)
            throw new IOException("getsockopt(SO_PEERCRED) failed: " + ErrText(Errno));
        if (len != (uint)sizeof(UCred)) throw new IOException("SO_PEERCRED returned an unexpected size");
        return c;
    }

    // ---- NSS lookups (reentrant variants) ----

    internal sealed record PasswdEntry(string Name, uint Uid, uint Gid, string Home, string Shell);
    internal sealed record GroupEntry(string Name, uint Gid, string[] Members);

    internal static PasswdEntry? GetPasswdByName(string name) => PasswdLookup(Z(name), 0);

    internal static PasswdEntry? GetPasswdByUid(uint uid) => PasswdLookup(null, uid);

    internal static GroupEntry? GetGroupByName(string name) => GroupLookup(Z(name), 0);

    internal static GroupEntry? GetGroupByGid(uint gid) => GroupLookup(null, gid);

    /// <summary>All groups (primary + supplementary) NSS assigns to <paramref name="user"/>; this is
    /// what systemd applies for User= (initgroups semantics).</summary>
    internal static uint[] GetGroupList(string user, uint primaryGid)
    {
        byte[] u = Z(user);
        int n = 64;
        while (true)
        {
            uint[] groups = new uint[n];
            int count = n;
            int r;
            fixed (byte* up = u) fixed (uint* gp = groups) r = getgrouplist(up, primaryGid, gp, &count);
            if (r >= 0) return groups.AsSpan(0, count).ToArray();
            if (count <= n) count = n * 2;
            n = count;
            if (n > 65536) throw new IOException("getgrouplist: too many groups");
        }
    }

    private const int ERANGE = 34;

    /// <summary>getpwnam_r/getpwuid_r. The returned strings point into <c>buf</c>, so they are copied
    /// while it is still pinned.</summary>
    private static PasswdEntry? PasswdLookup(byte[]? name, uint uid)
    {
        byte* pwd = stackalloc byte[64];   // struct passwd is 48 bytes on 64-bit
        for (int size = 16384; size <= 1 << 22; size *= 4)
        {
            byte[] buf = new byte[size];
            IntPtr result;
            fixed (byte* bp = buf)
            fixed (byte* np = name)
            {
                int r = name is not null
                    ? getpwnam_r(np, pwd, bp, (nuint)size, &result)
                    : getpwuid_r(uid, pwd, bp, (nuint)size, &result);
                if (r == ERANGE) continue;
                if (r != 0) throw new IOException("passwd lookup failed: " + ErrText(r));
                if (result == IntPtr.Zero) return null;
                // struct passwd: pw_name(0) pw_passwd(8) pw_uid(16) pw_gid(20) pw_gecos(24) pw_dir(32) pw_shell(40)
                return new PasswdEntry(
                    Marshal.PtrToStringUTF8(*(IntPtr*)(pwd + 0)) ?? "",
                    *(uint*)(pwd + 16),
                    *(uint*)(pwd + 20),
                    Marshal.PtrToStringUTF8(*(IntPtr*)(pwd + 32)) ?? "",
                    Marshal.PtrToStringUTF8(*(IntPtr*)(pwd + 40)) ?? "");
            }
        }
        throw new IOException("passwd lookup: buffer too small");
    }

    /// <summary>getgrnam_r/getgrgid_r; strings and the member list are copied while pinned.</summary>
    private static GroupEntry? GroupLookup(byte[]? name, uint gid)
    {
        byte* grp = stackalloc byte[64];   // struct group is 32 bytes on 64-bit
        for (int size = 16384; size <= 1 << 22; size *= 4)
        {
            byte[] buf = new byte[size];
            IntPtr result;
            fixed (byte* bp = buf)
            fixed (byte* np = name)
            {
                int r = name is not null
                    ? getgrnam_r(np, grp, bp, (nuint)size, &result)
                    : getgrgid_r(gid, grp, bp, (nuint)size, &result);
                if (r == ERANGE) continue;
                if (r != 0) throw new IOException("group lookup failed: " + ErrText(r));
                if (result == IntPtr.Zero) return null;
                // struct group: gr_name(0) gr_passwd(8) gr_gid(16) gr_mem(24)
                var members = new List<string>();
                IntPtr* mem = *(IntPtr**)(grp + 24);
                for (int i = 0; mem != null && mem[i] != IntPtr.Zero; i++)
                    members.Add(Marshal.PtrToStringUTF8(mem[i]) ?? "");
                return new GroupEntry(Marshal.PtrToStringUTF8(*(IntPtr*)(grp + 0)) ?? "", *(uint*)(grp + 16), members.ToArray());
            }
        }
        throw new IOException("group lookup: buffer too small");
    }
}
