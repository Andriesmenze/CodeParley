using System.Runtime.InteropServices;

namespace CodeParley.Custodian.Linux.Native;

/// <summary>
/// Phase 5 Increment 2 (contract §4.4, §4.10): the custodian's side of the helper channel needs what .NET does not expose —
/// a Unix stream connection with <c>SO_PASSCRED</c> set before connecting, and the kernel's <c>SCM_CREDENTIALS</c> of the
/// first message the helper sends. With systemd socket activation (<c>Accept=yes</c>) the LISTENING socket belongs to PID 1,
/// so <c>SO_PEERCRED</c> on the custodian's connected socket names systemd, not the helper (VERIFIED, Increment 2 probe);
/// the credentials the kernel attaches to the helper's own message name the process that sent it, which an unprivileged
/// process cannot forge (unix(7): without CAP_SYS_ADMIN/CAP_SETUID a sender can only send its own pid, uid and gid).
/// </summary>
internal static unsafe partial class Libc
{
    internal const int SOCK_CLOEXEC = 0x80000, SO_PASSCRED = 16, SO_RCVTIMEO = 20, SCM_CREDENTIALS = 2, MSG_PEEK = 2;

    [DllImport("libc", SetLastError = true)] private static extern int socket(int domain, int type, int protocol);
    [DllImport("libc", SetLastError = true)] private static extern int setsockopt(int fd, int level, int optname, void* optval, uint optlen);
    [DllImport("libc", SetLastError = true)] private static extern int connect(int fd, byte* addr, uint addrlen);
    [DllImport("libc", SetLastError = true)] private static extern nint recvmsg(int fd, MsgHdr* msg, int flags);

    [StructLayout(LayoutKind.Sequential)] private struct IoVec { public void* Base; public nuint Len; }
    [StructLayout(LayoutKind.Sequential)]
    private struct MsgHdr
    {
        public void* Name; public uint NameLen; public IoVec* Iov; public nuint IovLen; public void* Control; public nuint ControlLen; public int Flags;
    }
    [StructLayout(LayoutKind.Sequential)] private struct TimeVal { public long Sec; public long Usec; }

    /// <summary>A blocking Unix stream socket, <c>SO_PASSCRED</c> on, connected to <paramref name="path"/>; the caller owns the
    /// descriptor. Throws <see cref="IOException"/> with the errno on failure.</summary>
    internal static int ConnectWithPassCred(string path, int receiveTimeoutMs)
    {
        byte[] p = System.Text.Encoding.UTF8.GetBytes(path);
        if (p.Length >= 108) throw new IOException("the socket path is too long");
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) throw new IOException("socket(AF_UNIX) failed: " + ErrText(Errno));
        try
        {
            int one = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(int)) != 0) throw new IOException("setsockopt(SO_PASSCRED) failed: " + ErrText(Errno));
            var tv = new TimeVal { Sec = receiveTimeoutMs / 1000, Usec = receiveTimeoutMs % 1000 * 1000 };
            if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, (uint)sizeof(TimeVal)) != 0) throw new IOException("setsockopt(SO_RCVTIMEO) failed: " + ErrText(Errno));
            byte* addr = stackalloc byte[110];
            new Span<byte>(addr, 110).Clear();
            *(ushort*)addr = AF_UNIX;
            p.CopyTo(new Span<byte>(addr + 2, 108));
            if (connect(fd, addr, (uint)(2 + p.Length + 1)) != 0) throw new IOException($"connect({path}) failed: " + ErrText(Errno));
            return fd;
        }
        catch { close(fd); throw; }
    }

    /// <summary>The kernel-attached credentials of the first bytes waiting on <paramref name="fd"/> (peeked: nothing is
    /// consumed). Null when the peer closed without sending, or no credentials were attached.</summary>
    internal static UCred? PeekSenderCredentials(int fd)
    {
        byte data;
        byte* control = stackalloc byte[64];
        var iov = new IoVec { Base = &data, Len = 1 };
        var msg = new MsgHdr { Iov = &iov, IovLen = 1, Control = control, ControlLen = 64 };
        nint n;
        do { n = recvmsg(fd, &msg, MSG_PEEK); } while (n < 0 && Errno == 4 /* EINTR */);
        if (n < 0) throw new IOException("recvmsg failed: " + ErrText(Errno));
        if (n == 0) return null;
        // struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; } followed by data aligned to sizeof(size_t).
        byte* c = control;
        byte* end = control + (long)msg.ControlLen;
        while (c + 16 <= end)
        {
            nuint len = *(nuint*)c;
            int level = *(int*)(c + 8), type = *(int*)(c + 12);
            if (len < 16) break;
            if (level == SOL_SOCKET && type == SCM_CREDENTIALS && len >= 16 + 12) return *(UCred*)(c + 16);
            c += ((long)len + 7) & ~7L;
        }
        return null;
    }
}
