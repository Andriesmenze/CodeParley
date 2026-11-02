namespace CodeParley.Custodian.Security;

/// <summary>One process as the OS process table lists it: its id, its parent's id, its creation time (a FILETIME:
/// 100-ns intervals since 1601-01-01 UTC; 0 when unknown) and its image name (null when the table gives none).</summary>
internal sealed record ProcEntry(int Pid, int ParentPid, long CreateTime, string? ImageName = null);

/// <summary>A snapshot of the process table (null when it cannot be read). The default reads the OS; the
/// self-tests inject a fixed table so every branch of the check is exercised deterministically.</summary>
internal interface IProcessTable
{
    IReadOnlyDictionary<int, ProcEntry>? Snapshot();
}

internal sealed record ProcessCheckResult(int? Pid, long? StartedAtMs, int? ClientPid, bool Verified, string Detail);

/// <summary>
/// P3.4C-2 (D7): the custodian performs the OS process check ITSELF when a loop is bound or re-bound — a
/// client's own "verified" is never accepted. The named process (the CLAUDE_PID the host gave the hook)
/// must be running, its start time must be readable, and it must be an ANCESTOR of the process connected to
/// the custodian's pipe (the hook's helper) — the custodian's analogue of the engine's "CLAUDE_PID is an
/// ancestor of the hook process" check, judged from the OS's view of the connection instead of a pid the
/// client states. Each parent in the chain must have been created no later than its child (a later-created
/// "parent" is a reused process id). This correlates a binding with the originating session's process tree;
/// it does not authenticate a session (a same-user process can run under that tree): no L2/L3 claim.
/// </summary>
internal static class ProcessIdentityCheck
{
    internal const int MaxAncestryDepth = 16;
    private const long OneSecond = 10_000_000; // in FILETIME units
    private const long UnixEpochFileTime = 116_444_736_000_000_000;

    internal static ProcessCheckResult Verify(int? claimedPid, int? clientPid, IProcessTable processes)
    {
        if (claimedPid is null) return new(null, null, clientPid, false, "CLAUDE_PID was not supplied for the hook");
        IReadOnlyDictionary<int, ProcEntry>? table;
        try { table = processes.Snapshot(); }
        catch (Exception e) when (e is not OutOfMemoryException) { table = null; }
        int pid = claimedPid.Value;
        if (table is null) return new(pid, null, clientPid, false, "the process table could not be read");
        if (!table.TryGetValue(pid, out ProcEntry? named)) return new(pid, null, clientPid, false, $"process {pid} is not running");
        if (named.CreateTime <= 0) return new(pid, null, clientPid, false, $"the start time of process {pid} could not be read");
        long startedAtMs = (named.CreateTime - UnixEpochFileTime) / 10_000;
        if (clientPid is null || !table.TryGetValue(clientPid.Value, out ProcEntry? client))
            return new(pid, startedAtMs, clientPid, false, "the process connected to the custodian could not be identified");
        if (!IsAncestor(table, pid, client))
            return new(pid, startedAtMs, clientPid, false, $"process {pid} is not an ancestor of the process connected to the custodian ({clientPid})");
        string started = DateTimeOffset.FromUnixTimeMilliseconds(startedAtMs).UtcDateTime.ToString("o");
        return new(pid, startedAtMs, clientPid, true, $"process {pid}, an ancestor of the connected process {clientPid}, started {started}");
    }

    /// <summary>
    /// P3.4C-2 (TD decision on the Inc 9 escalation): the check of an AUTOMATION request — a continuation spend, a
    /// wake arm, a wake consume. It must come from the process tree of the Claude Code process the loop is bound
    /// to: that process must still run as the SAME instance (its OS creation time equals the one the custodian
    /// recorded when it verified the binding — a reused process id is another process) and be an ancestor of the
    /// process connected to the pipe. Correlation (D7), not authentication: any process inside that tree passes
    /// (the session's own tool commands descend from it too), and a same-user process can start a child under it.
    /// </summary>
    internal static ProcessCheckResult VerifyBound(int? boundPid, long? boundStartedAtMs, int? clientPid, IProcessTable processes)
    {
        if (boundPid is null || boundStartedAtMs is null) return new(boundPid, null, clientPid, false, "the binding records no verified process");
        ProcessCheckResult r = Verify(boundPid, clientPid, processes);
        if (r.StartedAtMs is { } now && now != boundStartedAtMs.Value)
            return r with { Verified = false, Detail = $"process {boundPid} started {Iso(now)}, not {Iso(boundStartedAtMs.Value)} like the process the loop was bound to: the process id was reused" };
        return r;
    }

    /// <summary>
    /// P3.4C-3 (contract §4.3): the process that sent a request — the PARENT of the process connected to the pipe (the
    /// engine sends each request through a short-lived helper whose parent is the engine process), from one snapshot of
    /// the process table, with its start time (Unix ms) and image name. Null when the table cannot be read, the client
    /// or its parent is not listed, or the "parent" was created after the client (a reused process id). An OS fact
    /// the custodian reads itself — never a field of the request.
    /// </summary>
    internal static (ProcEntry? Writer, long StartedAtMs, string Detail) WriterOf(int? clientPid, IProcessTable processes)
    {
        IReadOnlyDictionary<int, ProcEntry>? table;
        try { table = processes.Snapshot(); }
        catch (Exception e) when (e is not OutOfMemoryException) { table = null; }
        if (table is null) return (null, 0, "the process table could not be read");
        if (clientPid is null || !table.TryGetValue(clientPid.Value, out ProcEntry? client)) return (null, 0, "the process connected to the custodian could not be identified");
        // Phase 5 (F5-2): where the engine connects itself (Linux), the connected process IS the writer.
        if (Platform.WriterIsConnectedProcess)
            return client.CreateTime > 0 ? (client, (client.CreateTime - UnixEpochFileTime) / 10_000, $"process {client.Pid}, the process connected to the custodian") : (null, 0, $"the connected process {clientPid} has no start time");
        if (client.ParentPid == client.Pid || !table.TryGetValue(client.ParentPid, out ProcEntry? parent)) return (null, 0, $"the parent of the connected process {clientPid} is not running");
        if (parent.CreateTime <= 0 || parent.CreateTime > client.CreateTime + OneSecond) return (null, 0, $"the parent of the connected process {clientPid} cannot be established (its process id was reused)");
        return (parent, (parent.CreateTime - UnixEpochFileTime) / 10_000, $"process {parent.Pid}, the parent of the connected process {clientPid}");
    }

    /// <summary>P3.4C-3 (§5.2): is the process instance <paramref name="pid"/> started at <paramref name="startedAtMs"/>
    /// gone (not running, or its id now names a later process)? Null when the process table cannot be read: then
    /// nothing is assumed gone.</summary>
    internal static bool? IsGone(int pid, long startedAtMs, IProcessTable processes)
    {
        IReadOnlyDictionary<int, ProcEntry>? table;
        try { table = processes.Snapshot(); }
        catch (Exception e) when (e is not OutOfMemoryException) { table = null; }
        if (table is null) return null;
        if (!table.TryGetValue(pid, out ProcEntry? p)) return true;
        return (p.CreateTime - UnixEpochFileTime) / 10_000 != startedAtMs;
    }

    private static string Iso(long unixMs) => DateTimeOffset.FromUnixTimeMilliseconds(unixMs).UtcDateTime.ToString("o");

    /// <summary>Is <paramref name="ancestor"/> a proper ancestor of <paramref name="from"/>? Walks parent
    /// links (bounded), refusing a parent created after its child (a reused id) or a missing parent.</summary>
    private static bool IsAncestor(IReadOnlyDictionary<int, ProcEntry> table, int ancestor, ProcEntry from)
    {
        ProcEntry current = from;
        for (int depth = 0; depth < MaxAncestryDepth; depth++)
        {
            if (current.ParentPid == current.Pid || !table.TryGetValue(current.ParentPid, out ProcEntry? parent)) return false;
            if (parent.CreateTime > current.CreateTime + OneSecond) return false;
            if (parent.Pid == ancestor) return true;
            current = parent;
        }
        return false;
    }
}
