using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// Phase 6 Increment 2 (L-2): one process at a time owns the store — the serving custodian for its lifetime, or the
/// installer's migration while it runs. An exclusive open of <c>store.lock</c> at the store root (a share-none handle on
/// Windows, an advisory exclusive lock on Linux); a second owner is refused, naming the first's purpose when it can be
/// read. It holds no state: an orphaned file is harmless, and the lock ends with its process.
/// </summary>
internal sealed class StoreLock : IDisposable
{
    private readonly FileStream _handle;

    private StoreLock(FileStream handle) => _handle = handle;

    internal static string LockPath => Path.Combine(StorePaths.Root, "store.lock");

    internal static StoreLock Acquire(string purpose)
    {
        Directory.CreateDirectory(StorePaths.Root);
        FileStream h;
        try { h = new FileStream(LockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException)
        {
            throw new InvalidDataException("the store is in use by another custodian process (the running service, or a store upgrade); stop the service before an upgrade, and do not start it while one runs");
        }
        h.SetLength(0);
        using (var w = new StreamWriter(h, leaveOpen: true)) w.Write($"{purpose} pid {Environment.ProcessId} since {DateTime.UtcNow:o}\n");
        h.Flush(true);
        return new StoreLock(h);
    }

    public void Dispose() => _handle.Dispose();
}
