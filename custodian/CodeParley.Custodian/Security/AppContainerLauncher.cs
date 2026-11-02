using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// P3.4C-5 option A — FEASIBILITY SPIKE ONLY (TD decision on F5-1–F5-6). Starts a process inside an AppContainer from
/// the custodian's own (unchanged, SERVICE_SID_TYPE_RESTRICTED) service token, with documented APIs: a test-only
/// AppContainer profile (`CreateAppContainerProfile`), `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` with NO
/// capabilities, the same job object and three-handle inheritance list as <see cref="HelperProcess"/>, and an explicit
/// environment. Not wired into any product path or CLI verb.
///
/// UNVERIFIED (2026-10-15): it builds, but it has never been run, on the development host or under the real service.
/// The probe, the feasibility verb and the VM driver that would exercise it were not written
/// (`docs/validation/results/P3.4C-5-evidence-production.md` §4).
/// </summary>
internal static class AppContainerLauncher
{
    /// <summary>The test-only AppContainer profile name.</summary>
    internal const string ProfileName = "CodeParley.P34C5.HelperFeasibility";

    /// <summary>Create (or reuse) the test profile; returns its SID string and the HRESULT of the create.</summary>
    internal static string EnsureProfile(out int createHr)
    {
        createHr = HelperNative.CreateAppContainerProfile(ProfileName, "CodeParley helper feasibility (P3.4C-5)", "Test-only; deleted after the spike", IntPtr.Zero, 0, out IntPtr sid);
        if (createHr == HelperNative.HRESULT_ALREADY_EXISTS)
        {
            int hr = HelperNative.DeriveAppContainerSidFromAppContainerName(ProfileName, out sid);
            if (hr != 0) throw new Win32Exception(hr, "DeriveAppContainerSidFromAppContainerName");
        }
        else if (createHr != 0) throw new Win32Exception(createHr, $"CreateAppContainerProfile (HRESULT 0x{createHr:X8})");
        try { return new SecurityIdentifier(sid).Value; }
        finally { Native.FreeSid(sid); }
    }

    internal static int DeleteProfile() => HelperNative.DeleteAppContainerProfile(ProfileName);

    /// <summary>Derive the test profile's AppContainer SID from its name WITHOUT creating the profile. Used by the
    /// operator-side driver to grant the AppContainer SID read/execute on the scoped test resources before launch.</summary>
    internal static string DeriveSid()
    {
        int hr = HelperNative.DeriveAppContainerSidFromAppContainerName(ProfileName, out IntPtr sid);
        if (hr != 0) throw new Win32Exception(hr, $"DeriveAppContainerSidFromAppContainerName (HRESULT 0x{hr:X8})");
        try { return new SecurityIdentifier(sid).Value; }
        finally { Native.FreeSid(sid); }
    }

    internal static string? FolderPath(string sid)
    {
        int hr = HelperNative.GetAppContainerFolderPath(sid, out IntPtr p);
        if (hr != 0) return $"(GetAppContainerFolderPath HRESULT 0x{hr:X8})";
        try { return Marshal.PtrToStringUni(p); }
        finally { HelperNative.CoTaskMemFree(p); }
    }

    /// <summary>Run <paramref name="exe"/> in the AppContainer <paramref name="appContainerSid"/>. <paramref name="desktopMode"/>:
    /// "inherit" (the service's window station and desktop) or "private" (a desktop created for this run on the service's
    /// own window station, whose DACL grants only SYSTEM, the service and this AppContainer SID; the window station
    /// itself is not changed). <paramref name="tokenFacts"/> are read from the child's actual token.</summary>
    internal static HelperResult Run(string appContainerSid, string exe, IReadOnlyList<string> args, string cwd, IReadOnlyDictionary<string, string> env,
        byte[] stdin, HelperLimits limits, string desktopMode, out JsonObject tokenFacts)
    {
        tokenFacts = new JsonObject();
        IntPtr job = IntPtr.Zero, desktop = IntPtr.Zero, attrList = IntPtr.Zero, handleArray = IntPtr.Zero, envBlock = IntPtr.Zero, caps = IntPtr.Zero, acSid = IntPtr.Zero;
        IntPtr inRead = IntPtr.Zero, inWrite = IntPtr.Zero, outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        var pi = default(HelperNative.PROCESS_INFORMATION);
        var started = DateTime.UtcNow;
        try
        {
            if (!Native.ConvertStringSidToSidW(appContainerSid, out acSid)) throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertStringSidToSid(AppContainer)");
            job = HelperProcess.CreateJob(limits);
            HelperProcess.CreateInheritablePipe(out inRead, out inWrite, childEnd: 0);
            HelperProcess.CreateInheritablePipe(out outRead, out outWrite, childEnd: 1);
            HelperProcess.CreateInheritablePipe(out errRead, out errWrite, childEnd: 1);

            string? desktopName = null;
            if (desktopMode == "private")
            {
                string service = WindowsIdentity.GetCurrent().User!.Value;
                IntPtr sd = HelperProcess.SecurityAttributes($"D:P(A;;GA;;;SY)(A;;GA;;;{service})(A;;GA;;;{appContainerSid})", out IntPtr saBuf);
                try
                {
                    string name = "CPHelperAC" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4));
                    desktop = HelperNative.CreateDesktopW(name, IntPtr.Zero, IntPtr.Zero, 0, HelperNative.GENERIC_ALL, saBuf);
                    if (desktop == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateDesktop (private, on the service window station)");
                    desktopName = HelperProcess.ObjectName(HelperNative.GetProcessWindowStation()) + "\\" + name;
                }
                finally { Marshal.FreeHGlobal(saBuf); Native.LocalFree(sd); }
            }

            // Two attributes: the inherited-handle list and the AppContainer security capabilities (no capabilities).
            IntPtr size = IntPtr.Zero;
            HelperNative.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!HelperNative.InitializeProcThreadAttributeList(attrList, 2, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList");
            handleArray = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleArray, 0, inRead);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size, outWrite);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size * 2, errWrite);
            if (!HelperNative.UpdateProcThreadAttribute(attrList, 0, HelperNative.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray, IntPtr.Size * 3, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute(handle list)");
            var sc = new HelperNative.SECURITY_CAPABILITIES { AppContainerSid = acSid, Capabilities = IntPtr.Zero, CapabilityCount = 0 };
            caps = Marshal.AllocHGlobal(Marshal.SizeOf<HelperNative.SECURITY_CAPABILITIES>());
            Marshal.StructureToPtr(sc, caps, false);
            if (!HelperNative.UpdateProcThreadAttribute(attrList, 0, HelperNative.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, caps, Marshal.SizeOf<HelperNative.SECURITY_CAPABILITIES>(), IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute(security capabilities)");

            var si = new HelperNative.STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<HelperNative.STARTUPINFOEX>();
            si.StartupInfo.dwFlags = HelperNative.STARTF_USESTDHANDLES | HelperNative.STARTF_USESHOWWINDOW;
            si.StartupInfo.hStdInput = inRead;
            si.StartupInfo.hStdOutput = outWrite;
            si.StartupInfo.hStdError = errWrite;
            si.StartupInfo.lpDesktop = desktopName;
            si.lpAttributeList = attrList;

            envBlock = HelperProcess.EnvironmentBlock(env);
            var cmd = new StringBuilder(HelperProcess.CommandLine(exe, args));
            uint flags = HelperNative.CREATE_SUSPENDED | HelperNative.CREATE_NO_WINDOW | HelperNative.CREATE_UNICODE_ENVIRONMENT | HelperNative.EXTENDED_STARTUPINFO_PRESENT;
            if (!HelperNative.CreateProcessW(exe, cmd, IntPtr.Zero, IntPtr.Zero, true, flags, envBlock, cwd, ref si, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess (AppContainer)");
            tokenFacts = ChildToken(pi.hProcess);
            if (!HelperNative.AssignProcessToJobObject(job, pi.hProcess))
            {
                HelperNative.TerminateProcess(pi.hProcess, 1);
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject");
            }
            HelperNative.ResumeThread(pi.hThread);
            Native.CloseHandle(inRead); inRead = IntPtr.Zero;
            Native.CloseHandle(outWrite); outWrite = IntPtr.Zero;
            Native.CloseHandle(errWrite); errWrite = IntPtr.Zero;

            using var stdinStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(inWrite, true), FileAccess.Write); inWrite = IntPtr.Zero;
            using var stdoutStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(outRead, true), FileAccess.Read); outRead = IntPtr.Zero;
            using var stderrStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(errRead, true), FileAccess.Read); errRead = IntPtr.Zero;
            bool overLimit = false;
            var outTask = Task.Run(() => HelperProcess.ReadBounded(stdoutStream, limits.MaxStdoutBytes, () => overLimit = true));
            var errTask = Task.Run(() => HelperProcess.ReadBounded(stderrStream, limits.MaxStderrBytes, () => { }));
            try { stdinStream.Write(stdin); stdinStream.Flush(); } catch (IOException) { }
            stdinStream.Dispose();
            var deadline = started + limits.WallTime;
            bool timedOut = false;
            while (true)
            {
                if (HelperNative.WaitForSingleObject(pi.hProcess, 200) == HelperNative.WAIT_OBJECT_0) break;
                if (DateTime.UtcNow > deadline || overLimit)
                {
                    timedOut = !overLimit;
                    HelperNative.TerminateJobObject(job, 0xC0DE);
                    HelperNative.WaitForSingleObject(pi.hProcess, 5000);
                    break;
                }
            }
            HelperNative.TerminateJobObject(job, 0);
            byte[] stdout = outTask.Wait(TimeSpan.FromSeconds(10)) ? outTask.Result : [];
            byte[] stderr = errTask.Wait(TimeSpan.FromSeconds(10)) ? errTask.Result : [];
            HelperNative.GetExitCodeProcess(pi.hProcess, out uint exit);
            return new HelperResult(unchecked((int)exit), stdout, Encoding.UTF8.GetString(stderr), timedOut, overLimit, DateTime.UtcNow - started);
        }
        finally
        {
            foreach (IntPtr h in new[] { inRead, inWrite, outRead, outWrite, errRead, errWrite, pi.hThread, pi.hProcess })
                if (h != IntPtr.Zero) Native.CloseHandle(h);
            if (job != IntPtr.Zero) Native.CloseHandle(job);
            if (attrList != IntPtr.Zero) { HelperNative.DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            if (caps != IntPtr.Zero) Marshal.FreeHGlobal(caps);
            if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
            if (desktop != IntPtr.Zero) HelperNative.CloseDesktop(desktop);
            if (acSid != IntPtr.Zero) Native.LocalFree(acSid);
        }
    }

    /// <summary>The child's actual token: whether it is an AppContainer token, its AppContainer SID, user, integrity,
    /// capability count and groups.</summary>
    private static JsonObject ChildToken(IntPtr process)
    {
        var o = new JsonObject();
        if (!HelperNative.OpenProcessToken(process, Native.TOKEN_QUERY, out IntPtr t)) { o["error"] = $"OpenProcessToken {Marshal.GetLastWin32Error()}"; return o; }
        try
        {
            o["isAppContainer"] = ReadInt(t, HelperNative.TokenIsAppContainer) != 0;
            o["appContainerSid"] = ReadSidAt(t, HelperNative.TokenAppContainerSid);
            o["integrity"] = ReadSidAt(t, Native.TokenIntegrityLevel);
            o["user"] = ReadSidAt(t, HelperNative.TokenUser);
            o["capabilityCount"] = ReadCount(t, HelperNative.TokenCapabilities);
            o["groups"] = new JsonArray(HelperProcess.TokenGroups(t).Select(g => (JsonNode)$"{g.Sid} attr=0x{g.Attributes:x}").ToArray());
        }
        finally { Native.CloseHandle(t); }
        return o;
    }

    private static int ReadInt(IntPtr t, int cls)
    {
        IntPtr b = Marshal.AllocHGlobal(4);
        try { return Native.GetTokenInformation(t, cls, b, 4, out _) ? Marshal.ReadInt32(b) : -1; }
        finally { Marshal.FreeHGlobal(b); }
    }

    /// <summary>For token classes whose buffer starts with a SID pointer (TOKEN_USER, TOKEN_MANDATORY_LABEL,
    /// TOKEN_APPCONTAINER_INFORMATION).</summary>
    private static string? ReadSidAt(IntPtr t, int cls)
    {
        Native.GetTokenInformation(t, cls, IntPtr.Zero, 0, out int len);
        if (len <= 0) return null;
        IntPtr b = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(t, cls, b, len, out _)) return $"(error {Marshal.GetLastWin32Error()})";
            IntPtr sid = Marshal.ReadIntPtr(b);
            return sid == IntPtr.Zero ? null : new SecurityIdentifier(sid).Value;
        }
        finally { Marshal.FreeHGlobal(b); }
    }

    private static int ReadCount(IntPtr t, int cls)
    {
        Native.GetTokenInformation(t, cls, IntPtr.Zero, 0, out int len);
        if (len <= 0) return 0;
        IntPtr b = Marshal.AllocHGlobal(len);
        try { return Native.GetTokenInformation(t, cls, b, len, out _) ? Marshal.ReadInt32(b) : -1; }
        finally { Marshal.FreeHGlobal(b); }
    }
}
