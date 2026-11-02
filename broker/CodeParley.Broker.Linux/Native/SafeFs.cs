using System.Text;

namespace CodeParley.Broker.Linux.Native;

/// <summary>An owned file descriptor (closed on dispose).</summary>
internal sealed class Fd : IDisposable
{
    internal int Value { get; private set; }
    internal Fd(int value) { Value = value; }
    public void Dispose()
    {
        if (Value >= 0) { Libc.close(Value); Value = -1; }
    }
}

internal sealed class SafeFsException(string message, int errno) : IOException($"{message}: {Libc.ErrText(errno)}")
{
    internal int Errno { get; } = errno;
}

internal sealed record RemoveReport(bool Complete, int Removed, IReadOnlyList<string> Failures);

/// <summary>
/// Descriptor-relative filesystem primitives for a root process operating on trees that an
/// unprivileged worker can write. Every path below a trusted directory descriptor is resolved with
/// openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV): no
/// "..", no symlink in any component (including the last), no /proc magic links, no mount
/// crossing. On kernels without openat2 (before 5.6) the same rules are enforced by walking one
/// component at a time with openat(O_NOFOLLOW) and comparing device numbers. No string prefix check
/// is ever the safety mechanism.
/// </summary>
internal static class SafeFs
{
    private const ulong BeneathResolve =
        Libc.RESOLVE_BENEATH | Libc.RESOLVE_NO_SYMLINKS | Libc.RESOLVE_NO_MAGICLINKS | Libc.RESOLVE_NO_XDEV;

    private static readonly Lazy<bool> Openat2Available = new(ProbeOpenat2);

    /// <summary>Self-test only: exercise the pre-5.6 component-walk resolver on a modern kernel.</summary>
    internal static bool ForceWalkForSelfTest { get; set; }

    internal static bool UsesOpenat2 => !ForceWalkForSelfTest && Openat2Available.Value;

    internal static string ResolverDescription => UsesOpenat2
        ? "openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)"
        : "openat component walk (O_NOFOLLOW per component, same-device check)";

    private static bool ProbeOpenat2()
    {
        int fd = Libc.Openat2(Libc.AT_FDCWD, "/", Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_CLOEXEC, 0, Libc.RESOLVE_NO_SYMLINKS);
        if (fd >= 0) { Libc.close(fd); return true; }
        int e = Libc.Errno;
        // ENOSYS: kernel < 5.6. EPERM: a seccomp filter (e.g. some container runtimes) blocks it.
        if (e is Libc.ENOSYS or Libc.EPERM) return false;
        throw new SafeFsException("openat2 probe", e);
    }

    /// <summary>Open an absolute, trusted directory path; refuses a symlink in any component.</summary>
    internal static Fd OpenAbsoluteDir(string absPath)
    {
        if (!absPath.StartsWith('/')) throw new ArgumentException($"not an absolute path: {absPath}");
        if (UsesOpenat2)
        {
            int fd = Libc.Openat2(Libc.AT_FDCWD, absPath, Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_CLOEXEC, 0,
                Libc.RESOLVE_NO_SYMLINKS | Libc.RESOLVE_NO_MAGICLINKS);
            if (fd < 0) throw new SafeFsException($"open {absPath}", Libc.Errno);
            return new Fd(fd);
        }

        int cur = Libc.Openat(Libc.AT_FDCWD, "/", Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_CLOEXEC, 0);
        if (cur < 0) throw new SafeFsException("open /", Libc.Errno);
        foreach (string comp in SplitRelative(absPath.TrimStart('/'), allowEmpty: true))
        {
            int next = Libc.Openat(cur, comp, Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, 0);
            int e = Libc.Errno;
            Libc.close(cur);
            if (next < 0) throw new SafeFsException($"open {absPath}", e);
            cur = next;
        }
        return new Fd(cur);
    }

    /// <summary>Open <paramref name="rel"/> strictly beneath <paramref name="dir"/>. Returns the fd and
    /// errno (fd &lt; 0 on failure) without throwing.</summary>
    internal static (int Fd, int Errno) OpenBeneathRaw(Fd dir, string rel, int flags, uint mode = 0)
    {
        string[] comps = SplitRelative(rel, allowEmpty: false);
        if (UsesOpenat2)
        {
            int fd = Libc.Openat2(dir.Value, string.Join('/', comps), flags | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, mode, BeneathResolve);
            return fd >= 0 ? (fd, 0) : (-1, Libc.Errno);
        }

        if (Libc.StatxFd(dir.Value, out Libc.Statx rootSt) != 0) return (-1, Libc.Errno);
        int cur = Libc.fcntl(dir.Value, Libc.F_DUPFD_CLOEXEC, 0);
        if (cur < 0) return (-1, Libc.Errno);
        for (int i = 0; i < comps.Length - 1; i++)
        {
            int next = Libc.Openat(cur, comps[i], Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, 0);
            int e = Libc.Errno;
            Libc.close(cur);
            if (next < 0) return (-1, e);
            if (Libc.StatxFd(next, out Libc.Statx st) != 0 || st.Dev != rootSt.Dev) { Libc.close(next); return (-1, Libc.EXDEV); }
            cur = next;
        }
        int last = Libc.Openat(cur, comps[^1], flags | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, mode);
        int le = Libc.Errno;
        Libc.close(cur);
        if (last < 0) return (-1, le);
        if (Libc.StatxFd(last, out Libc.Statx lst) != 0 || lst.Dev != rootSt.Dev) { Libc.close(last); return (-1, Libc.EXDEV); }
        return (last, 0);
    }

    /// <summary>Open beneath <paramref name="dir"/>; null when the path does not exist.</summary>
    internal static Fd? OpenBeneath(Fd dir, string rel, int flags, uint mode = 0)
    {
        (int fd, int e) = OpenBeneathRaw(dir, rel, flags, mode);
        if (fd >= 0) return new Fd(fd);
        if (e == Libc.ENOENT) return null;
        throw new SafeFsException($"open beneath: {rel}", e);
    }

    internal static Fd OpenDirBeneath(Fd dir, string rel) =>
        OpenBeneath(dir, rel, Libc.O_RDONLY | Libc.O_DIRECTORY) ?? throw new SafeFsException($"open {rel}", Libc.ENOENT);

    internal static Fd Dup(Fd fd)
    {
        int d = Libc.fcntl(fd.Value, Libc.F_DUPFD_CLOEXEC, 0);
        if (d < 0) throw new SafeFsException("dup", Libc.Errno);
        return new Fd(d);
    }

    internal static Libc.Statx Stat(Fd fd)
    {
        if (Libc.StatxFd(fd.Value, out Libc.Statx st) != 0) throw new SafeFsException("fstat", Libc.Errno);
        return st;
    }

    /// <summary>lstat of a single entry of <paramref name="dir"/> (never follows a symlink).</summary>
    internal static bool TryStatEntry(Fd dir, string name, out Libc.Statx st)
    {
        ValidateName(name);
        if (Libc.StatxAt(dir.Value, name, Libc.AT_SYMLINK_NOFOLLOW, out st) == 0) return true;
        int e = Libc.Errno;
        if (e == Libc.ENOENT) return false;
        throw new SafeFsException($"stat {name}", e);
    }

    internal static void MakeDir(Fd dir, string name, uint mode)
    {
        ValidateName(name);
        if (Libc.Mkdirat(dir.Value, name, mode) != 0) throw new SafeFsException($"mkdir {name}", Libc.Errno);
    }

    internal static void Chown(Fd fd, uint uid, uint gid)
    {
        if (Libc.fchown(fd.Value, uid, gid) != 0) throw new SafeFsException("fchown", Libc.Errno);
    }

    internal static void Chmod(Fd fd, uint mode)
    {
        if (Libc.fchmod(fd.Value, mode) != 0) throw new SafeFsException("fchmod", Libc.Errno);
    }

    internal static void UnlinkEntry(Fd dir, string name, bool directory = false)
    {
        ValidateName(name);
        if (Libc.Unlinkat(dir.Value, name, directory ? Libc.AT_REMOVEDIR : 0) != 0)
        {
            int e = Libc.Errno;
            if (e != Libc.ENOENT) throw new SafeFsException($"unlink {name}", e);
        }
    }

    /// <summary>Change ownership of a whole tree without following symlinks. Only used on a freshly
    /// created tree that no other principal can reach yet.</summary>
    internal static void ChownTree(Fd root, uint uid, uint gid)
    {
        Chown(root, uid, gid);
        var stack = new Stack<string>();
        stack.Push("");
        while (stack.Count > 0)
        {
            string rel = stack.Pop();
            using Fd d = rel.Length == 0 ? Dup(root) : OpenDirBeneath(root, rel);
            foreach ((string name, byte type) in Libc.ReadDirectory(d.Value))
            {
                if (Libc.Fchownat(d.Value, name, uid, gid, Libc.AT_SYMLINK_NOFOLLOW) != 0)
                    throw new SafeFsException($"chown {Join(rel, name)}", Libc.Errno);
                bool isDir = type == Libc.DT_DIR
                    || (type == Libc.DT_UNKNOWN && TryStatEntry(d, name, out Libc.Statx st) && st.IsDir);
                if (isDir) stack.Push(Join(rel, name));
            }
        }
    }

    /// <summary>
    /// Remove <paramref name="name"/> (a file, symlink or whole directory tree) beneath
    /// <paramref name="parent"/>. Never follows a symlink and never crosses a mount; a concurrent
    /// writer can at most make the removal incomplete (reported), never redirect it outside the tree.
    /// </summary>
    internal static RemoveReport RemoveTree(Fd parent, string name, TimeSpan budget)
    {
        ValidateName(name);
        var failures = new List<string>();
        var failed = new HashSet<string>(StringComparer.Ordinal);
        int removed = 0;
        DateTime deadline = DateTime.UtcNow + budget;
        var stack = new Stack<string>();
        stack.Push(name);
        while (stack.Count > 0)
        {
            if (DateTime.UtcNow > deadline) { failures.Add("removal time budget exceeded"); break; }
            string rel = stack.Peek();
            (int dfd, int e) = OpenBeneathRaw(parent, rel, Libc.O_RDONLY | Libc.O_DIRECTORY);
            if (dfd < 0)
            {
                stack.Pop();
                if (e == Libc.ENOENT) continue;
                if (e is Libc.ENOTDIR or Libc.ELOOP)       // a file, FIFO, socket or symlink: unlink the entry itself
                {
                    if (UnlinkRelative(parent, rel, 0, failures)) removed++; else failed.Add(rel);
                    continue;
                }
                failures.Add($"open {rel}: {Libc.ErrText(e)}");   // e.g. EXDEV for a mount point: never descend
                failed.Add(rel);
                continue;
            }

            // Unlink every non-directory entry; collect subdirectories, which are processed first
            // (post-order) before this directory is revisited and removed.
            var childDirs = new List<string>();
            bool listFailed = false;
            try
            {
                foreach ((string child, _) in Libc.ReadDirectory(dfd))
                {
                    string childRel = rel + "/" + child;
                    if (failed.Contains(childRel)) continue;
                    if (Libc.Unlinkat(dfd, child, 0) == 0) { removed++; continue; }
                    int ue = Libc.Errno;
                    if (ue == Libc.EISDIR) childDirs.Add(childRel);
                    else if (ue != Libc.ENOENT) { failures.Add($"unlink {childRel}: {Libc.ErrText(ue)}"); failed.Add(childRel); }
                }
            }
            catch (IOException ex) { failures.Add($"list {rel}: {ex.Message}"); listFailed = true; }
            finally { Libc.close(dfd); }

            if (listFailed) { stack.Pop(); failed.Add(rel); continue; }
            if (childDirs.Count > 0)
            {
                foreach (string c in childDirs) stack.Push(c);
                continue;
            }
            stack.Pop();
            if (UnlinkRelative(parent, rel, Libc.AT_REMOVEDIR, failures)) removed++; else failed.Add(rel);
        }
        return new RemoveReport(failures.Count == 0, removed, failures);
    }

    private static bool UnlinkRelative(Fd parent, string rel, int flags, List<string> failures)
    {
        int slash = rel.LastIndexOf('/');
        string dirRel = slash < 0 ? "" : rel[..slash];
        string baseName = slash < 0 ? rel : rel[(slash + 1)..];
        Fd? dir = null;
        try
        {
            dir = dirRel.Length == 0 ? Dup(parent) : OpenBeneath(parent, dirRel, Libc.O_RDONLY | Libc.O_DIRECTORY);
            if (dir is null) return true;   // parent vanished: nothing left to unlink
            if (Libc.Unlinkat(dir.Value, baseName, flags) == 0) return true;
            int e = Libc.Errno;
            if (e == Libc.ENOENT) return true;
            failures.Add($"unlink {rel}: {Libc.ErrText(e)}");
            return false;
        }
        catch (IOException ex) { failures.Add($"unlink {rel}: {ex.Message}"); return false; }
        finally { dir?.Dispose(); }
    }

    /// <summary>Read a regular file beneath <paramref name="dir"/> without following symlinks and
    /// without blocking on a FIFO; at most <paramref name="maxBytes"/> are returned.</summary>
    internal static byte[]? ReadFileBeneath(Fd dir, string rel, int maxBytes, out bool truncated)
    {
        truncated = false;
        (int fd, int e) = OpenBeneathRaw(dir, rel, Libc.O_RDONLY | Libc.O_NONBLOCK | Libc.O_NOCTTY);
        if (fd < 0)
        {
            if (e == Libc.ENOENT) return null;
            throw new SafeFsException($"open {rel}", e);
        }
        using var f = new Fd(fd);
        Libc.Statx st = Stat(f);
        if (!st.IsRegular) throw new IOException($"{rel} is not a regular file; refusing to read it");
        var ms = new MemoryStream();
        byte[] buf = new byte[65536];
        unsafe
        {
            fixed (byte* p = buf)
            {
                while (ms.Length <= maxBytes)
                {
                    nint n = Libc.read(fd, p, (nuint)buf.Length);
                    if (n < 0)
                    {
                        int re = Libc.Errno;
                        if (re == Libc.EINTR) continue;
                        throw new SafeFsException($"read {rel}", re);
                    }
                    if (n == 0) break;
                    ms.Write(buf, 0, (int)n);
                }
            }
        }
        if (ms.Length > maxBytes) { truncated = true; ms.SetLength(maxBytes); }
        return ms.ToArray();
    }

    /// <summary>Write a file atomically (temp file + rename) into a trusted, root-only directory.</summary>
    internal static void WriteFileAtomic(Fd dir, string name, byte[] content, uint mode)
    {
        ValidateName(name);
        string tmp = $".{name}.tmp-{Environment.ProcessId}";
        Libc.Unlinkat(dir.Value, tmp, 0);
        int fd = Libc.Openat(dir.Value, tmp, Libc.O_WRONLY | Libc.O_CREAT | Libc.O_EXCL | Libc.O_NOFOLLOW | Libc.O_CLOEXEC, mode);
        if (fd < 0) throw new SafeFsException($"create {tmp}", Libc.Errno);
        try
        {
            unsafe
            {
                fixed (byte* p = content)
                {
                    int off = 0;
                    while (off < content.Length)
                    {
                        nint n = Libc.write(fd, p + off, (nuint)(content.Length - off));
                        if (n < 0) { int we = Libc.Errno; if (we == Libc.EINTR) continue; throw new SafeFsException($"write {tmp}", we); }
                        off += (int)n;
                    }
                }
            }
            if (Libc.fsync(fd) != 0) throw new SafeFsException($"fsync {tmp}", Libc.Errno);
        }
        finally { Libc.close(fd); }
        if (Libc.Renameat(dir.Value, tmp, dir.Value, name) != 0)
        {
            int re = Libc.Errno;
            Libc.Unlinkat(dir.Value, tmp, 0);
            throw new SafeFsException($"rename {tmp} -> {name}", re);
        }
        Libc.fsync(dir.Value);
    }

    internal static string Join(string rel, string name) => rel.Length == 0 ? name : rel + "/" + name;

    /// <summary>A single directory-entry name: not empty, no '/', not "." or "..", no NUL.</summary>
    internal static void ValidateName(string name)
    {
        if (name.Length == 0 || name.Contains('/') || name.Contains('\0') || name is "." or "..")
            throw new ArgumentException($"invalid entry name '{name}'");
    }

    private static string[] SplitRelative(string rel, bool allowEmpty)
    {
        if (rel.StartsWith('/')) throw new ArgumentException($"expected a relative path: {rel}");
        string[] comps = rel.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (comps.Length == 0 && !allowEmpty) throw new ArgumentException("empty relative path");
        foreach (string c in comps)
            if (c is "." or ".." || c.Contains('\0')) throw new ArgumentException($"invalid path component in '{rel}'");
        return comps;
    }

    internal static string Describe(Libc.Statx st) =>
        new StringBuilder().Append(Convert.ToString(st.Perm, 8).PadLeft(4, '0')).Append(' ').Append(st.Uid).Append(':').Append(st.Gid).ToString();
}
