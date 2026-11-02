using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using CodeParley.Custodian.Interop;
using Microsoft.Win32.SafeHandles;

namespace CodeParley.Custodian.Security;

/// <summary>
/// P3.4C-5 (§A.3): one workload child of the helper service — Node running the approved engine runtime. The production
/// shape the Option-B gate proved (<c>Cli/HelperPrincipalFeasibility.cs</c> <c>LaunchInherit</c>): a plain
/// <c>CreateProcess</c> that inherits the helper service's OWN token (no token derivation, no AppContainer, no forced
/// integrity), suspended until it is inside a job object (kill on close, an active-process limit, a per-process memory
/// cap, UI restrictions), with exactly three inherited handles (PROC_THREAD_ATTRIBUTE_HANDLE_LIST) and an explicit,
/// allowlisted environment. Unlike the gate's launcher the standard streams stay open while it runs: the request goes in
/// on stdin, frames come back on stdout, and the stderr tail is kept, bounded. Disposing kills the job and everything in
/// it. The helper writes nothing to disk; neither does this class.
/// </summary>
internal sealed class HelperChild : IDisposable
{
    private IntPtr _job, _process, _thread;
    private readonly FileStream _stdin, _stdout;
    private readonly Task<string> _stderrTail;

    private HelperChild(IntPtr job, IntPtr process, IntPtr thread, FileStream stdin, FileStream stdout, Task<string> stderrTail)
    {
        _job = job; _process = process; _thread = thread; _stdin = stdin; _stdout = stdout; _stderrTail = stderrTail;
    }

    internal Stream Stdin => _stdin;
    internal Stream Stdout => _stdout;

    /// <summary>The last <paramref name="maxStderrBytes"/> bytes the child wrote to stderr (UTF-8), once it has exited.</summary>
    internal Task<string> StderrTail => _stderrTail;

    internal static HelperChild Start(string exe, IReadOnlyList<string> args, string cwd, IReadOnlyDictionary<string, string> env, HelperLimits limits, int maxStderrBytes = 4096)
    {
        IntPtr job = IntPtr.Zero, attrList = IntPtr.Zero, handleArray = IntPtr.Zero, envBlock = IntPtr.Zero;
        IntPtr inRead = IntPtr.Zero, inWrite = IntPtr.Zero, outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        var pi = default(HelperNative.PROCESS_INFORMATION);
        bool ok = false;
        try
        {
            job = HelperProcess.CreateJob(limits);
            HelperProcess.CreateInheritablePipe(out inRead, out inWrite, childEnd: 0);
            HelperProcess.CreateInheritablePipe(out outRead, out outWrite, childEnd: 1);
            HelperProcess.CreateInheritablePipe(out errRead, out errWrite, childEnd: 1);

            IntPtr size = IntPtr.Zero;
            HelperNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!HelperNative.InitializeProcThreadAttributeList(attrList, 1, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList");
            handleArray = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleArray, 0, inRead);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size, outWrite);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size * 2, errWrite);
            if (!HelperNative.UpdateProcThreadAttribute(attrList, 0, HelperNative.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray, IntPtr.Size * 3, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute(handle list)");

            var si = new HelperNative.STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<HelperNative.STARTUPINFOEX>();
            si.StartupInfo.dwFlags = HelperNative.STARTF_USESTDHANDLES | HelperNative.STARTF_USESHOWWINDOW;
            si.StartupInfo.hStdInput = inRead;
            si.StartupInfo.hStdOutput = outWrite;
            si.StartupInfo.hStdError = errWrite;
            si.lpAttributeList = attrList;

            envBlock = HelperProcess.EnvironmentBlock(env);
            var cmd = new StringBuilder(HelperProcess.CommandLine(exe, args));
            uint flags = HelperNative.CREATE_SUSPENDED | HelperNative.CREATE_NO_WINDOW | HelperNative.CREATE_UNICODE_ENVIRONMENT | HelperNative.EXTENDED_STARTUPINFO_PRESENT;
            if (!HelperNative.CreateProcessW(exe, cmd, IntPtr.Zero, IntPtr.Zero, true, flags, envBlock, cwd, ref si, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess (inherit token)");
            if (!HelperNative.AssignProcessToJobObject(job, pi.hProcess))
            {
                HelperNative.TerminateProcess(pi.hProcess, 1);
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject");
            }
            HelperNative.ResumeThread(pi.hThread);
            // The parent's copies of the child's ends are closed, so EOF arrives when the child (and its children) exit.
            Native.CloseHandle(inRead); inRead = IntPtr.Zero;
            Native.CloseHandle(outWrite); outWrite = IntPtr.Zero;
            Native.CloseHandle(errWrite); errWrite = IntPtr.Zero;

            var stdin = new FileStream(new SafeFileHandle(inWrite, true), FileAccess.Write, 1); inWrite = IntPtr.Zero;
            var stdout = new FileStream(new SafeFileHandle(outRead, true), FileAccess.Read, 1); outRead = IntPtr.Zero;
            var stderr = new FileStream(new SafeFileHandle(errRead, true), FileAccess.Read, 1); errRead = IntPtr.Zero;
            Task<string> tail = Task.Run(() => Tail(stderr, maxStderrBytes));
            ok = true;
            return new HelperChild(job, pi.hProcess, pi.hThread, stdin, stdout, tail);
        }
        finally
        {
            foreach (IntPtr h in new[] { inRead, inWrite, outRead, outWrite, errRead, errWrite })
                if (h != IntPtr.Zero) Native.CloseHandle(h);
            if (!ok)
            {
                if (pi.hThread != IntPtr.Zero) Native.CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) Native.CloseHandle(pi.hProcess);
                if (job != IntPtr.Zero) Native.CloseHandle(job); // kill on close
            }
            if (attrList != IntPtr.Zero) { HelperNative.DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
        }
    }

    /// <summary>Wait for the child's exit (polling, so cancellation and a deadline both end the wait) and return its code.</summary>
    internal async Task<int> WaitAsync(CancellationToken ct)
    {
        while (HelperNative.WaitForSingleObject(_process, 0) != HelperNative.WAIT_OBJECT_0)
            await Task.Delay(100, ct).ConfigureAwait(false);
        HelperNative.GetExitCodeProcess(_process, out uint exit);
        return unchecked((int)exit);
    }

    internal bool HasExited => HelperNative.WaitForSingleObject(_process, 0) == HelperNative.WAIT_OBJECT_0;

    /// <summary>Kill the child and everything it started (the whole job).</summary>
    internal void Kill()
    {
        if (_job != IntPtr.Zero) HelperNative.TerminateJobObject(_job, 0xC0DE);
    }

    public void Dispose()
    {
        Kill();
        try { _stdin.Dispose(); } catch { }
        try { _stdout.Dispose(); } catch { }
        if (_thread != IntPtr.Zero) { Native.CloseHandle(_thread); _thread = IntPtr.Zero; }
        if (_process != IntPtr.Zero) { Native.CloseHandle(_process); _process = IntPtr.Zero; }
        if (_job != IntPtr.Zero) { Native.CloseHandle(_job); _job = IntPtr.Zero; }
    }

    private static string Tail(Stream s, int max)
    {
        var ring = new Queue<byte>();
        byte[] buf = new byte[4096];
        try
        {
            for (int n; (n = s.Read(buf, 0, buf.Length)) > 0;)
                for (int i = 0; i < n; i++) { ring.Enqueue(buf[i]); if (ring.Count > max) ring.Dequeue(); }
        }
        catch (IOException) { }
        finally { s.Dispose(); }
        return Encoding.UTF8.GetString(ring.ToArray());
    }
}
