using System.Globalization;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 (contract §4.7): the OS process table from <c>/proc</c> — for every process its id, its parent id (field 4 of
/// <c>/proc/&lt;pid&gt;/stat</c>) and its start time (field 22, clock ticks after boot), both readable for every user's
/// processes without ptrace access (proc_pid_stat(5), VERIFIED E2), parsed after the LAST <c>)</c> (the command name may
/// contain spaces and parentheses). The start time is turned into the FILETIME the portable check compares, against the
/// boot time this process read once at start (<c>btime</c> in <c>/proc/stat</c>), so one process's values are consistent
/// with each other. Any failure yields null: the check then reports the identity unverified (fail closed).
/// </summary>
internal sealed class LinuxProcessTable : IProcessTable
{
    private const long UnixEpochFileTime = 116444736000000000;
    private static readonly long BootFileTime = ReadBootFileTime();
    private static readonly long TicksPerClockTick = 10_000_000 / ClockTicksPerSecond();

    public IReadOnlyDictionary<int, ProcEntry>? Snapshot()
    {
        if (BootFileTime <= 0) return null;
        var table = new Dictionary<int, ProcEntry>();
        try
        {
            foreach (string dir in Directory.EnumerateDirectories("/proc"))
            {
                string name = Path.GetFileName(dir);
                if (!int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out int pid) || pid <= 0) continue;
                ProcEntry? e = Read(pid);
                if (e is not null) table[pid] = e;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        return table.Count > 0 ? table : null;
    }

    /// <summary>One process, or null when it is gone or unreadable.</summary>
    internal static ProcEntry? Read(int pid)
    {
        string stat;
        try { stat = File.ReadAllText($"/proc/{pid}/stat"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        int close = stat.LastIndexOf(')');
        int open = stat.IndexOf('(');
        if (close < 0 || open < 0 || close + 2 >= stat.Length) return null;
        string[] rest = stat[(close + 2)..].Split(' ');
        // rest[0] = field 3 (state), rest[1] = field 4 (ppid), rest[19] = field 22 (starttime)
        if (rest.Length < 20 || !int.TryParse(rest[1], NumberStyles.None, CultureInfo.InvariantCulture, out int ppid)
            || !long.TryParse(rest[19], NumberStyles.None, CultureInfo.InvariantCulture, out long start)) return null;
        string comm = stat[(open + 1)..close];
        return new ProcEntry(pid, ppid, BootFileTime + start * TicksPerClockTick, comm);
    }

    private static long ReadBootFileTime()
    {
        try
        {
            foreach (string line in File.ReadLines("/proc/stat"))
                if (line.StartsWith("btime ", StringComparison.Ordinal) && long.TryParse(line[6..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long secs))
                    return UnixEpochFileTime + secs * 10_000_000;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return 0;
    }

    private static long ClockTicksPerSecond()
    {
        long v = Native.Libc.Sysconf(Native.Libc.SC_CLK_TCK);
        return v is > 0 and <= 10_000_000 ? v : 100;
    }
}
