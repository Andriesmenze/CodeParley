using System.Runtime.InteropServices;

namespace CodeParley.Custodian.Linux.Native;

/// <summary>
/// Phase 5 (contract §4.4, §4.6, §4.8, §4.11): the calls the custodian needs beyond the broker's — the directory
/// identity (<c>name_to_handle_at</c>, <c>fstatfs</c>, <c>statx</c> birth time, the ext4 generation), the endpoint checks
/// (<c>getsockname</c>, socket options), the durable replace (<c>renameat</c> + <c>fsync</c> of the directory) and the
/// POSIX ACL publication (the <c>system.posix_acl_access</c> xattr). x86_64 only (D5-E).
/// </summary>
internal static unsafe partial class Libc
{
    [DllImport("libc", SetLastError = true)] private static extern int name_to_handle_at(int dirfd, byte* path, FileHandle* handle, int* mountId, int flags);
    [DllImport("libc", SetLastError = true)] private static extern int fstatfs(int fd, StatFs* buf);
    [DllImport("libc", SetLastError = true)] private static extern int getsockname(int sockfd, byte* addr, uint* addrlen);
    [DllImport("libc", SetLastError = true)] private static extern int ioctl(int fd, ulong request, long* arg);
    [DllImport("libc", SetLastError = true)] private static extern nint fgetxattr(int fd, byte* name, byte* value, nuint size);
    [DllImport("libc", SetLastError = true)] private static extern int fsetxattr(int fd, byte* name, byte* value, nuint size, int flags);
    [DllImport("libc", SetLastError = true, EntryPoint = "statx")] private static extern int statx_full(int dirfd, byte* path, int flags, uint mask, StatxFull* buf);
    [DllImport("libc", SetLastError = true)] internal static extern uint getuid();
    [DllImport("libc", SetLastError = true)] internal static extern uint getegid();
    [DllImport("libc", SetLastError = true, EntryPoint = "sysconf")] internal static extern long Sysconf(int name);
    internal const int SC_CLK_TCK = 2;

    internal const int O_PATH = 0x200000;
    internal const int SO_TYPE = 3, SO_ACCEPTCONN = 30, SO_DOMAIN = 39;
    internal const int AF_UNIX = 1, SOCK_STREAM = 1;
    internal const long EXT4_SUPER_MAGIC = 0xEF53;
    internal const ulong EXT4_IOC_GETVERSION = 0x80086603; // _IOR('f', 3, long)
    internal const uint STATX_BTIME = 0x800;
    private const int MaxHandleBytes = 128;

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileHandle
    {
        public uint HandleBytes;
        public int HandleType;
        public fixed byte Handle[MaxHandleBytes];
    }

    /// <summary>struct statfs (x86_64, 120 bytes): f_type at 0, f_fsid (two int) at 56.</summary>
    [StructLayout(LayoutKind.Explicit, Size = 120)]
    internal struct StatFs
    {
        [FieldOffset(0)] public long Type;
        [FieldOffset(56)] public int Fsid0;
        [FieldOffset(60)] public int Fsid1;
    }

    /// <summary>struct statx with the fields the identity and the store validation read (birth time at 80).</summary>
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    internal struct StatxFull
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(16)] public uint Nlink;
        [FieldOffset(20)] public uint Uid;
        [FieldOffset(24)] public uint Gid;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(32)] public ulong Ino;
        [FieldOffset(40)] public ulong Size;
        [FieldOffset(80)] public long BtimeSec;
        [FieldOffset(88)] public uint BtimeNsec;
        [FieldOffset(136)] public uint DevMajor;
        [FieldOffset(140)] public uint DevMinor;

        internal readonly uint Type => Mode & S_IFMT;
        internal readonly uint Perm => Mode & 0xFFFu;
        internal readonly bool HasBtime => (Mask & STATX_BTIME) != 0;
    }

    internal static int StatxFullFd(int fd, out StatxFull st) => StatxFullAt(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, out st);

    internal static int StatxFullAt(int dirfd, string path, int flags, out StatxFull st)
    {
        byte[] p = Z(path);
        StatxFull s;
        int r;
        fixed (byte* pp = p) r = statx_full(dirfd, pp, flags, STATX_BASIC_STATS | STATX_BTIME, &s);
        st = s;
        return r;
    }

    /// <summary>The opaque handle of the object <paramref name="fd"/> refers to (AT_EMPTY_PATH); null on failure.</summary>
    internal static (int Type, byte[] Bytes)? HandleOf(int fd)
    {
        FileHandle h;
        h.HandleBytes = MaxHandleBytes;
        h.HandleType = 0;
        int mount;
        byte[] empty = [0];
        fixed (byte* p = empty)
        {
            if (name_to_handle_at(fd, p, &h, &mount, AT_EMPTY_PATH) != 0) return null;
        }
        if (h.HandleBytes > MaxHandleBytes) return null;
        var bytes = new byte[h.HandleBytes];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = h.Handle[i];
        return (h.HandleType, bytes);
    }

    /// <summary>The filesystem type and fsid of the filesystem holding <paramref name="fd"/>; null on failure.</summary>
    internal static (long Type, ulong Fsid)? FsOf(int fd)
    {
        StatFs s;
        if (fstatfs(fd, &s) != 0) return null;
        return (s.Type & 0xFFFFFFFF, ((ulong)(uint)s.Fsid1 << 32) | (uint)s.Fsid0);
    }

    /// <summary>The ext4 inode generation of an object opened for reading (EXT4_IOC_GETVERSION); null on failure.</summary>
    internal static uint? GenerationOf(int fd)
    {
        long v = 0;
        return ioctl(fd, EXT4_IOC_GETVERSION, &v) == 0 ? (uint)v : null;
    }

    internal static int SocketInt(int fd, int option)
    {
        int v = 0;
        uint len = sizeof(int);
        return getsockopt(fd, SOL_SOCKET, option, &v, &len) == 0 ? v : -1;
    }

    /// <summary>The pathname a Unix socket is bound to; "" for an unnamed socket, "@…" for an abstract one, null on failure.</summary>
    internal static string? SocketPath(int fd)
    {
        byte* addr = stackalloc byte[110];
        uint len = 110;
        if (getsockname(fd, addr, &len) != 0) return null;
        if (len < 2 || *(ushort*)addr != AF_UNIX) return null;
        if (len == 2) return "";
        if (addr[2] == 0) return "@" + Marshal.PtrToStringUTF8((IntPtr)(addr + 3), (int)len - 3);
        return Marshal.PtrToStringUTF8((IntPtr)(addr + 2));
    }

    internal static byte[]? GetXattr(int fd, string name)
    {
        byte[] n = Z(name);
        fixed (byte* np = n)
        {
            nint size = fgetxattr(fd, np, null, 0);
            if (size < 0) return null;
            var buf = new byte[size];
            fixed (byte* bp = buf)
            {
                nint got = fgetxattr(fd, np, bp, (nuint)size);
                return got < 0 ? null : buf[..(int)got];
            }
        }
    }

    internal static int SetXattr(int fd, string name, byte[] value)
    {
        byte[] n = Z(name);
        fixed (byte* np = n) fixed (byte* vp = value) return fsetxattr(fd, np, vp, (nuint)value.Length, 0);
    }

    [DllImport("libc", SetLastError = true)] private static extern int fremovexattr(int fd, byte* name);

    /// <summary>Remove an extended attribute (0, or -1 with errno; ENODATA when it was not set).</summary>
    internal static int RemoveXattr(int fd, string name)
    {
        byte[] n = Z(name);
        fixed (byte* np = n) return fremovexattr(fd, np);
    }
}
