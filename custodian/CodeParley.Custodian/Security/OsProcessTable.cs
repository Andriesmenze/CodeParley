using System.Runtime.InteropServices;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// The OS process table, read with <c>NtQuerySystemInformation(SystemProcessInformation)</c>: every
/// process's id, parent id and creation time, without opening any process (the custodian's service account
/// may not open another user's process). Only the 64-bit layout is parsed (the custodian is published
/// win-x64); anything else, or any failure, yields null — the check then reports the identity unverified.
/// </summary>
internal sealed class OsProcessTable : IProcessTable
{
    private const int MaxAttempts = 6;

    public IReadOnlyDictionary<int, ProcEntry>? Snapshot()
    {
        if (IntPtr.Size != 8) return null;
        int size = 1 << 20;
        for (int attempt = 0; attempt < MaxAttempts; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int status = Native.NtQuerySystemInformation(Native.SystemProcessInformation, buffer, size, out int needed);
                if (status == Native.STATUS_INFO_LENGTH_MISMATCH)
                {
                    size = Math.Max(size * 2, needed + (256 << 10));
                    continue;
                }
                return status < 0 ? null : Parse(buffer, size);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return null;
    }

    private static Dictionary<int, ProcEntry> Parse(IntPtr buffer, int size)
    {
        var table = new Dictionary<int, ProcEntry>();
        long offset = 0;
        while (offset >= 0 && offset + Native.SpiMinEntrySize <= size)
        {
            IntPtr entry = IntPtr.Add(buffer, (int)offset);
            uint next = (uint)Marshal.ReadInt32(entry, Native.SpiNextEntryOffset);
            long created = Marshal.ReadInt64(entry, Native.SpiCreateTime);
            long pid = Marshal.ReadIntPtr(entry, Native.SpiUniqueProcessId).ToInt64();
            long parent = Marshal.ReadIntPtr(entry, Native.SpiInheritedFromProcessId).ToInt64();
            if (pid is > 0 and <= int.MaxValue)
                table[(int)pid] = new ProcEntry((int)pid, parent is >= 0 and <= int.MaxValue ? (int)parent : -1, created, ImageName(buffer, size, entry));
            if (next == 0) break;
            offset += next;
        }
        return table;
    }

    /// <summary>The entry's image name (its UNICODE_STRING points into the same buffer), or null when it has none or
    /// the string does not lie wholly inside the buffer.</summary>
    private static string? ImageName(IntPtr buffer, int size, IntPtr entry)
    {
        int bytes = (ushort)Marshal.ReadInt16(entry, Native.SpiImageNameLength);
        IntPtr text = Marshal.ReadIntPtr(entry, Native.SpiImageNameBuffer);
        if (bytes is <= 0 or > 1024 || bytes % 2 != 0 || text == IntPtr.Zero) return null;
        long start = text.ToInt64() - buffer.ToInt64();
        if (start < 0 || start + bytes > size) return null;
        return Marshal.PtrToStringUni(text, bytes / 2);
    }
}

/// <summary>What the custodian observed of the process the client named as the originating Claude Code
/// process (CLAUDE_PID): its start time read from the OS, the connecting process, and whether the check
/// passed. A correlation fact (D7), never a credential.</summary>
