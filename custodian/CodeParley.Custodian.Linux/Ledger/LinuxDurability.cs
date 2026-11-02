using System.Text.RegularExpressions;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Linux.Native;

namespace CodeParley.Custodian.Linux.Ledger;

/// <summary>
/// Phase 5 (contract §4.8): the Linux half of <see cref="DurableStore.Replace"/>. The temporary file was written and
/// <c>fsync</c>ed by the core; here it replaces the target with <c>rename(2)</c> (atomic: the target is never missing in
/// between, rename(2)), then the containing directory is <c>fsync</c>ed so the new directory entry itself is durable
/// (fsync(2) NOTES: an fsync of the file does not persist its directory entry). <c>auto_da_alloc</c> is not relied on.
/// A failure throws <see cref="IOException"/>; nothing is acknowledged then.
/// </summary>
internal sealed class LinuxDurableFiles(string? storeRoot = null) : IDurableFiles
{
    /// <summary>The store root the private-entry rule is judged against (the installed store unless a self-test names
    /// another).</summary>
    private string StoreRoot => storeRoot ?? Platform.Store.Root;

    /// <summary>The private, never-overwritten file (the content-key secret): 0600 from creation (no window in which the
    /// store group could open it), flushed, then the directory flushed.</summary>
    public void CreateNew(string path, byte[] content)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite };
        using (var fs = new FileStream(path, options))
        {
            fs.Write(content);
            fs.Flush(flushToDisk: true);
        }
        FlushDirectory(Path.GetDirectoryName(path)!);
    }

    private static void FlushDirectory(string dir)
    {
        int fd = Libc.Openat(Libc.AT_FDCWD, dir, Libc.O_RDONLY | Libc.O_DIRECTORY | Libc.O_CLOEXEC, 0);
        if (fd < 0) throw new IOException($"the store directory could not be opened to flush it ({Libc.ErrText(Libc.Errno)})");
        try
        {
            if (Libc.fsync(fd) != 0) throw new IOException($"the store directory could not be flushed ({Libc.ErrText(Libc.Errno)})");
        }
        finally { Libc.close(fd); }
    }

    public void ReplaceWith(string tmp, string path, Action afterReplace)
    {
        // F-8 (VM, Increment 1): the core creates the temporary file with the service's umask (0640). A private entry
        // (an intent, the content key) must grant the store group nothing (contract §4.3) — the start-time check refuses
        // it otherwise — so its temporary file is narrowed to 0600 BEFORE it takes the target's name. (Its directory,
        // intents/ 2700, already denies the group; this keeps the file's own mode right as well.)
        string rel = Path.GetRelativePath(StoreRoot, path).Replace(Path.DirectorySeparatorChar, '/');
        if (!rel.StartsWith("..", StringComparison.Ordinal) && Security.LinuxHostCheck.IsPrivateStoreEntry(rel))
        {
            try { File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                DurableStore.TryDelete(tmp);
                throw new IOException($"a private store file could not be made private before it was written ({e.Message})");
            }
        }
        if (Libc.Renameat(Libc.AT_FDCWD, tmp, Libc.AT_FDCWD, path) != 0)
        {
            int e = Libc.Errno;
            DurableStore.TryDelete(tmp);
            throw new IOException($"the store file could not be replaced (rename: {Libc.ErrText(e)})");
        }
        afterReplace();
        FlushDirectory(Path.GetDirectoryName(path)!);
    }
}

/// <summary>
/// Phase 5 (contract §4.8): the boot this custodian runs in, as the kernel's random per-boot UUID
/// (<c>/proc/sys/kernel/random/boot_id</c>; generated once per boot, DOCUMENTED; changes across a reboot, VERIFIED E1/E7),
/// compared exactly. An unreadable or malformed value reads as null, which the recovery treats as a new boot.
/// </summary>
internal sealed partial class LinuxBootIdentity : IBootIdentity
{
    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    private static partial Regex Uuid();

    public DateTime? BootTimeUtc() => null;

    public string? BootKey()
    {
        try
        {
            string v = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
            return Uuid().IsMatch(v) ? "boot_id:" + v : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    public bool SameBoot(string? recorded, string? current) => recorded is not null && current is not null && string.Equals(recorded, current, StringComparison.Ordinal);
}
