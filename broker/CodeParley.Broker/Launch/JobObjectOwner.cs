using System.Runtime.InteropServices;
using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Launch;

/// <summary>
/// Owns the worker process tree via a Windows Job Object (ported from the proven
/// spike/.../win-job.cs): kill-on-close, no breakaway, whole-tree/descendant containment. The worker
/// is created suspended and assigned here BEFORE it is resumed, so no code runs outside the job.
/// Disposing (closing the last handle) terminates the entire tree.
/// </summary>
internal sealed class JobObjectOwner : IDisposable
{
    private IntPtr _job;
    internal string Name { get; }

    internal JobObjectOwner(string name)
    {
        Name = name;
        _job = Native.CreateJobObjectW(IntPtr.Zero, name);
        if (_job == IntPtr.Zero) Native.ThrowLastError("CreateJobObject");

        var info = default(Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        // Kill-on-close only. No *_BREAKAWAY_OK flag is set, so descendants cannot leave the job.
        info.BasicLimitInformation.LimitFlags = Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!Native.SetInformationJobObject(_job, Native.JobObjectExtendedLimitInformation, ref info,
                Marshal.SizeOf<Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
            Native.ThrowLastError("SetInformationJobObject");
    }

    internal void Assign(IntPtr process)
    {
        if (!Native.AssignProcessToJobObject(_job, process)) Native.ThrowLastError("AssignProcessToJobObject");
    }

    internal void Terminate(uint exitCode = 1)
    {
        if (_job != IntPtr.Zero) Native.TerminateJobObject(_job, exitCode);
    }

    /// <summary>PIDs currently in the job (membership is the ownership record, not the PID chain).</summary>
    internal int[] ProcessIds()
    {
        const int cap = 1024;
        int size = 8 + IntPtr.Size * cap;   // NumberOfAssignedProcesses, NumberOfProcessIdsInList, then ULONG_PTR[]
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (!Native.QueryInformationJobObject(_job, Native.JobObjectBasicProcessIdList, buf, size, out _))
                return [];
            int inList = Marshal.ReadInt32(buf, 4);
            var ids = new int[inList];
            for (int i = 0; i < inList; i++) ids[i] = (int)Marshal.ReadIntPtr(buf, 8 + i * IntPtr.Size);
            return ids;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public void Dispose()
    {
        if (_job != IntPtr.Zero)
        {
            Native.CloseHandle(_job);   // kill-on-close terminates the whole worker tree
            _job = IntPtr.Zero;
        }
    }
}
