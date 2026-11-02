using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Ledger;

/// <summary>Phase 5 (§4.1): the Windows half of <see cref="DurableStore.Replace"/> — <c>MoveFileExW(MOVEFILE_REPLACE_EXISTING |
/// MOVEFILE_WRITE_THROUGH)</c> with a bounded retry, then <c>FlushFileBuffers</c> on the replaced file (unchanged from P3.4C-3).</summary>
internal sealed class WindowsDurableFiles : IDurableFiles
{
    private const int ErrorAccessDenied = 5, ErrorSharingViolation = 32, MaxAttempts = 10;

    public void CreateNew(string path, byte[] content)
    {
        using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        fs.Write(content);
        fs.Flush(flushToDisk: true);
    }

    public void ReplaceWith(string tmp, string path, Action afterReplace)
    {
        for (int attempt = 1; ; attempt++)
        {
            if (Native.MoveFileExW(tmp, path, Native.MOVEFILE_REPLACE_EXISTING | Native.MOVEFILE_WRITE_THROUGH)) break;
            int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            // Another process (an anti-malware scan of a file just written) can hold the target for a moment: retry,
            // bounded. Anything else, or a target held longer, fails the request — nothing is acknowledged.
            if (error is ErrorAccessDenied or ErrorSharingViolation && attempt < MaxAttempts) { Thread.Sleep(10 * attempt); continue; }
            DurableStore.TryDelete(tmp);
            throw new IOException($"the store file could not be replaced (MoveFileExW error {error})");
        }
        afterReplace();
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read))
                    fs.Flush(flushToDisk: true); // FlushFileBuffers on the replaced file
                break;
            }
            catch (IOException) when (attempt < MaxAttempts) { Thread.Sleep(10 * attempt); }
        }
    }
}
