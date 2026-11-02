using System.Text;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// P3.4C-3 (contract §2.4): the one write path for every custodian store file — the ledger, the user-record log, the
/// intents, the run files and the session and recovery markers. The new version is written to a temporary file in
/// the same directory and flushed (<c>FlushFileBuffers</c>), replaces the old version with
/// <c>MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)</c>, and the replaced file is flushed again;
/// only then does the caller acknowledge its request.
///
/// What this guarantees: after a crash of the custodian process or a service restart, each file is one complete
/// version (the replacement is atomic on one volume, and the OS still holds what was written). What it does NOT
/// guarantee by itself: that an acknowledged version survives an OS crash or a power loss — that holds only on
/// storage that honours flushes, is claimed only where the VM hard-power-off test shows it, and the custodian's
/// recovery after a new boot applies regardless (§2.4).
/// </summary>
internal static class DurableStore
{
    /// <summary>The steps of one replacement, at which the self-tests inject a crash (N16): after the temporary
    /// file was written and flushed, after the replacement, and after the final flush.</summary>
    internal const string StepTempWritten = "temp_written", StepReplaced = "replaced", StepFlushed = "flushed";

    /// <summary>SELF-TEST ONLY: called after each step with the step and the target path; a self-test throws from it
    /// to model a writer killed at that point. Never set by the service.</summary>
    internal static Action<string, string>? FaultHook;

    private const string TempMarker = ".tmp-";

    /// <summary>Replace <paramref name="path"/> with <paramref name="content"/> (UTF-8, no BOM) durably, as above.</summary>
    internal static void Replace(string path, string content)
    {
        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        string tmp = path + TempMarker + Guid.NewGuid().ToString("N")[..8];
        using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            fs.Write(new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content));
            fs.Flush(flushToDisk: true); // FlushFileBuffers
        }
        FaultHook?.Invoke(StepTempWritten, path);
        // Phase 5 (§4.1): the replacement and its own durability are the host's (Windows: MoveFileExW WRITE_THROUGH and a
        // flush of the replaced file; Linux: rename(2) and an fsync of the directory).
        Platform.Durable.ReplaceWith(tmp, path, () => FaultHook?.Invoke(StepReplaced, path));
        FaultHook?.Invoke(StepFlushed, path);
    }

    /// <summary>Create <paramref name="path"/> with <paramref name="content"/> only if it does not exist, flushed
    /// before returning (the content-key secret: never overwritten). Throws <see cref="IOException"/> if it exists.</summary>
    internal static void CreateNew(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Phase 5 (§4.3): the host creates it (Windows: inheriting the store's DACL; Linux: 0600 from creation, then the
        // directory is flushed).
        Platform.Durable.CreateNew(path, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content));
    }

    /// <summary>Delete the temporary files an interrupted replacement left under <paramref name="root"/> (never a
    /// live version: a temporary file is only ever the source of a replacement). Returns how many were removed.</summary>
    internal static int SweepTemporaries(string root)
    {
        if (!Directory.Exists(root)) return 0;
        int n = 0;
        foreach (string f in Directory.EnumerateFiles(root, "*" + TempMarker + "*", SearchOption.AllDirectories))
        {
            if (TryDelete(f)) n++;
        }
        return n;
    }

    internal static bool TryDelete(string path)
    {
        try { File.Delete(path); return true; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
}
