using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>The limits a helper process runs under (contract §2.2).</summary>
internal sealed record HelperLimits(TimeSpan WallTime, int ActiveProcesses, long ProcessMemoryBytes, int MaxStdoutBytes, int MaxStderrBytes)
{
    internal static readonly HelperLimits Default = new(TimeSpan.FromMinutes(5), 16, 2L * 1024 * 1024 * 1024, 768 * 1024 * 1024, 256 * 1024);
}

/// <summary>What a helper run produced. <see cref="TimedOut"/> and <see cref="OverLimit"/> are failures, never partial results.</summary>
internal sealed record HelperResult(int ExitCode, byte[] Stdout, string Stderr, bool TimedOut, bool OverLimit, TimeSpan Elapsed);

/// <summary>The helper's token, as built (for the feasibility evidence and the audit; no secret in it).</summary>
internal sealed record HelperTokenFacts(string IntegritySid, IReadOnlyList<string> DisabledSids, string RestrictingSid, bool WriteRestricted, bool PrivilegesStripped);

/// <summary>FEASIBILITY DIAGNOSTICS ONLY (`self-test-helper --variants`): which of the token's properties to leave out, to
/// isolate a failure. The product always builds <see cref="Full"/>; nothing else ever constructs a variant.</summary>
internal sealed record HelperTokenVariant(bool DenyOnly, bool WriteRestrict, bool LowIntegrity, string Name, bool AllowRestrictedCode = false,
    string RestrictingSet = "random", bool KeepLogonSid = false, bool DuplicateOnly = false)
{
    internal static readonly HelperTokenVariant Full = new(true, true, true, "full");
}

/// <summary>
/// P3.4C-5 (contract §2.2): the custodian helper process. The service starts it with a token derived from its own:
/// <list type="bullet">
/// <item>the user SID, the logon SID and every service, SERVICE and administrative group are deny-only, so allow ACEs for
/// the custodian (its private store) never grant the helper anything;</item>
/// <item>WRITE_RESTRICTED with one random restricting SID that no ACL grants, so every write access check fails;</item>
/// <item>low integrity, so there is no write-up and no write or injection handle to the service process;</item>
/// <item>DISABLE_MAX_PRIVILEGE (only SeChangeNotifyPrivilege remains).</item>
/// </list>
/// It runs inside a job object (kill on close, an active-process limit, a memory cap, UI restrictions, a wall-time
/// limit), inherits exactly its three standard handles, gets an explicit environment and, optionally, a private window
/// station and desktop. Nothing is written by the helper: every result arrives on its stdout, bounded.
/// The custodian NEVER holds GrantLedger.Gate while a helper runs (§2.4); this class takes no lock.
/// </summary>
internal static class HelperProcess
{
    private const string LowIntegrity = "S-1-16-4096";
    private static readonly string[] DisabledWellKnown = ["S-1-5-6" /* SERVICE */, "S-1-5-80-0" /* ALL SERVICES */, "S-1-5-32-544" /* Administrators */, "S-1-5-18" /* SYSTEM */, "S-1-5-19", "S-1-5-20"];

    /// <summary>Run <paramref name="exe"/> under the helper token. <paramref name="privateDesktop"/> starts it on a
    /// window station and desktop created for this run (DACL: Everyone, low-integrity label), instead of inheriting the
    /// service's.</summary>
    internal static HelperResult Run(string exe, IReadOnlyList<string> args, string cwd, IReadOnlyDictionary<string, string> env, byte[] stdin,
        HelperLimits limits, bool privateDesktop, string helperGroupSid, out HelperTokenFacts facts, CancellationToken cancel = default, HelperTokenVariant? variant = null)
    {
        IntPtr token = BuildToken(out facts, variant ?? HelperTokenVariant.Full, helperGroupSid);
        IntPtr job = IntPtr.Zero, winsta = IntPtr.Zero, desktop = IntPtr.Zero, previousWinsta = IntPtr.Zero;
        IntPtr inRead = IntPtr.Zero, inWrite = IntPtr.Zero, outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        IntPtr attrList = IntPtr.Zero, handleArray = IntPtr.Zero, envBlock = IntPtr.Zero;
        var pi = default(HelperNative.PROCESS_INFORMATION);
        var started = DateTime.UtcNow;
        try
        {
            job = CreateJob(limits);
            CreateInheritablePipe(out inRead, out inWrite, childEnd: 0);
            CreateInheritablePipe(out outRead, out outWrite, childEnd: 1);
            CreateInheritablePipe(out errRead, out errWrite, childEnd: 1);

            string? desktopName = null;
            if (privateDesktop) desktopName = CreatePrivateDesktop(facts.RestrictingSid, out winsta, out desktop, out previousWinsta);

            // Exactly three handles are inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), whatever else is inheritable.
            IntPtr size = IntPtr.Zero;
            HelperNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!HelperNative.InitializeProcThreadAttributeList(attrList, 1, 0, ref size)) throw Win32("InitializeProcThreadAttributeList");
            handleArray = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleArray, 0, inRead);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size, outWrite);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size * 2, errWrite);
            if (!HelperNative.UpdateProcThreadAttribute(attrList, 0, HelperNative.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray, IntPtr.Size * 3, IntPtr.Zero, IntPtr.Zero))
                throw Win32("UpdateProcThreadAttribute");

            var si = new HelperNative.STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<HelperNative.STARTUPINFOEX>();
            si.StartupInfo.dwFlags = HelperNative.STARTF_USESTDHANDLES | HelperNative.STARTF_USESHOWWINDOW;
            si.StartupInfo.hStdInput = inRead;
            si.StartupInfo.hStdOutput = outWrite;
            si.StartupInfo.hStdError = errWrite;
            si.StartupInfo.lpDesktop = desktopName;
            si.lpAttributeList = attrList;

            envBlock = EnvironmentBlock(env);
            var cmd = new StringBuilder(CommandLine(exe, args));
            uint flags = HelperNative.CREATE_SUSPENDED | HelperNative.CREATE_NO_WINDOW | HelperNative.CREATE_UNICODE_ENVIRONMENT | HelperNative.EXTENDED_STARTUPINFO_PRESENT;
            if (!HelperNative.CreateProcessAsUserW(token, exe, cmd, IntPtr.Zero, IntPtr.Zero, true, flags, envBlock, cwd, ref si, out pi))
                throw Win32("CreateProcessAsUser");
            if (!HelperNative.AssignProcessToJobObject(job, pi.hProcess))
            {
                HelperNative.TerminateProcess(pi.hProcess, 1);
                throw Win32("AssignProcessToJobObject");
            }
            HelperNative.ResumeThread(pi.hThread);

            // The parent's copies of the child's ends are closed so EOF arrives when the child exits.
            Native.CloseHandle(inRead); inRead = IntPtr.Zero;
            Native.CloseHandle(outWrite); outWrite = IntPtr.Zero;
            Native.CloseHandle(errWrite); errWrite = IntPtr.Zero;

            using var stdinStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(inWrite, ownsHandle: true), FileAccess.Write);
            inWrite = IntPtr.Zero;
            using var stdoutStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(outRead, ownsHandle: true), FileAccess.Read);
            outRead = IntPtr.Zero;
            using var stderrStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(errRead, ownsHandle: true), FileAccess.Read);
            errRead = IntPtr.Zero;

            bool overLimit = false;
            var outTask = Task.Run(() => ReadBounded(stdoutStream, limits.MaxStdoutBytes, () => overLimit = true));
            var errTask = Task.Run(() => ReadBounded(stderrStream, limits.MaxStderrBytes, () => { }));
            try
            {
                stdinStream.Write(stdin);
                stdinStream.Flush();
            }
            catch (IOException) { /* the helper exited before reading its input; its exit code says why */ }
            stdinStream.Dispose();

            var deadline = started + limits.WallTime;
            bool timedOut = false;
            while (true)
            {
                uint w = HelperNative.WaitForSingleObject(pi.hProcess, 200);
                if (w == HelperNative.WAIT_OBJECT_0) break;
                if (cancel.IsCancellationRequested || DateTime.UtcNow > deadline || overLimit)
                {
                    timedOut = !cancel.IsCancellationRequested && !overLimit;
                    HelperNative.TerminateJobObject(job, 0xC0DE);
                    HelperNative.WaitForSingleObject(pi.hProcess, 5000);
                    break;
                }
            }
            // Every process the helper started dies with the job, so the pipes reach EOF.
            HelperNative.TerminateJobObject(job, 0);
            byte[] stdout = outTask.Wait(TimeSpan.FromSeconds(10)) ? outTask.Result : [];
            byte[] stderr = errTask.Wait(TimeSpan.FromSeconds(10)) ? errTask.Result : [];
            HelperNative.GetExitCodeProcess(pi.hProcess, out uint exit);
            cancel.ThrowIfCancellationRequested();
            return new HelperResult(unchecked((int)exit), stdout, Encoding.UTF8.GetString(stderr), timedOut, overLimit, DateTime.UtcNow - started);
        }
        finally
        {
            foreach (IntPtr h in new[] { inRead, inWrite, outRead, outWrite, errRead, errWrite, pi.hThread, pi.hProcess, token })
                if (h != IntPtr.Zero) Native.CloseHandle(h);
            if (job != IntPtr.Zero) Native.CloseHandle(job); // kill on close
            if (attrList != IntPtr.Zero) { HelperNative.DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
            if (desktop != IntPtr.Zero) HelperNative.CloseDesktop(desktop);
            if (previousWinsta != IntPtr.Zero) HelperNative.SetProcessWindowStation(previousWinsta);
            if (winsta != IntPtr.Zero) HelperNative.CloseWindowStation(winsta);
        }
    }

    /// <summary>The helper's primary token (see the class summary). The caller closes it.</summary>
    /// <param name="helperGroupSid">A group the custodian's token has ENABLED and no other account holds
    /// (`CodeParley Repository Readers`, contract §2.3). The helper's default DACL grants it, with SYSTEM and the
    /// restricting SID: the objects a process creates for itself at start-up (its own section, event and thread objects)
    /// must be accessible to the process, and its user SID is deny-only. The implementer is not in the group, so it can
    /// open none of the helper's objects.</param>
    internal static IntPtr BuildToken(out HelperTokenFacts facts, HelperTokenVariant variant, string helperGroupSid)
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY | Native.TOKEN_ASSIGN_PRIMARY | Native.TOKEN_ADJUST_DEFAULT, out IntPtr own))
            throw Win32("OpenProcessToken");
        var toFree = new List<IntPtr>();
        try
        {
            var disabled = new List<string>();
            string? logonSid = null;
            bool sourceWriteRestricted = false;
            string userSid = WindowsIdentity.GetCurrent().User!.Value;
            disabled.Add(userSid);
            foreach ((string sid, uint attributes) in TokenGroups(own))
            {
                bool logon = (attributes & HelperNative.SE_GROUP_LOGON_ID) == HelperNative.SE_GROUP_LOGON_ID;
                if (logon) logonSid = sid;
                if ((logon && !variant.KeepLogonSid) || sid.StartsWith("S-1-5-80-", StringComparison.Ordinal) || DisabledWellKnown.Contains(sid, StringComparer.Ordinal))
                    if (!disabled.Contains(sid, StringComparer.Ordinal)) disabled.Add(sid);
                if (sid == "S-1-5-33") sourceWriteRestricted = true;
            }
            if (!variant.DenyOnly) disabled.Clear();
            var disable = disabled.Select(s => new Native.SID_AND_ATTRIBUTES { Sid = Sid(s, toFree), Attributes = 0 }).ToArray();

            // One restricting SID that no ACL anywhere grants: a fresh random domain-form SID per run.
            Span<byte> r = stackalloc byte[12];
            RandomNumberGenerator.Fill(r);
            string restricting = $"S-1-5-21-{BitConverter.ToUInt32(r[..4])}-{BitConverter.ToUInt32(r[4..8])}-{BitConverter.ToUInt32(r[8..12])}-4242";
            // FEASIBILITY DIAGNOSTICS: a token derived from a write-restricted service token (SERVICE_SID_TYPE_RESTRICTED)
            // can only narrow its restricting set, so the candidates are drawn from it.
            if (variant.RestrictingSet == "write-restricted-sid") restricting = "S-1-5-33";
            else if (variant.RestrictingSet == "logon") restricting = logonSid ?? throw new InvalidOperationException("the token has no logon SID");
            else if (variant.RestrictingSet == "write-restricted-sid+logon") restricting = "S-1-5-33," + (logonSid ?? throw new InvalidOperationException("the token has no logon SID"));
            var restrict = restricting.Split(',').Select(x => new Native.SID_AND_ATTRIBUTES { Sid = Sid(x, toFree), Attributes = 0 }).ToArray();
            if (variant.AllowRestrictedCode) restrict = [.. restrict, new Native.SID_AND_ATTRIBUTES { Sid = Sid("S-1-5-12", toFree), Attributes = 0 }];

            if (!variant.WriteRestrict) restrict = [];
            uint flags = Native.DISABLE_MAX_PRIVILEGE | (variant.WriteRestrict ? Native.WRITE_RESTRICTED : 0);
            IntPtr restricted;
            if (variant.DuplicateOnly)
            {
                // FEASIBILITY DIAGNOSTICS: the caller's own token, duplicated (no CreateRestrictedToken); it keeps every
                // restriction the source already has (a SERVICE_SID_TYPE_RESTRICTED service is write-restricted).
                if (!Native.DuplicateTokenEx(own, Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE | Native.TOKEN_ASSIGN_PRIMARY | Native.TOKEN_ADJUST_DEFAULT, IntPtr.Zero, Native.SecurityImpersonation, Native.TokenPrimary, out restricted))
                    throw Win32("DuplicateTokenEx(own)");
                disabled.Clear();
                restricting = "(inherited from the source token)";
            }
            else if (!Native.CreateRestrictedToken(own, flags, (uint)disable.Length, disable.Length == 0 ? null : disable, 0, IntPtr.Zero, (uint)restrict.Length, restrict.Length == 0 ? null : restrict, out restricted))
                throw Win32("CreateRestrictedToken");
            try
            {
                if (!Native.DuplicateTokenEx(restricted, Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE | Native.TOKEN_ASSIGN_PRIMARY | Native.TOKEN_ADJUST_DEFAULT, IntPtr.Zero, Native.SecurityImpersonation, Native.TokenPrimary, out IntPtr primary))
                    throw Win32("DuplicateTokenEx");
                if (variant.LowIntegrity) SetLowIntegrity(primary, toFree);
                SetDefaultDacl(primary, $"D:(A;;GA;;;SY)(A;;GA;;;{helperGroupSid})" + (variant.WriteRestrict && !variant.DuplicateOnly ? string.Concat(restricting.Split(',').Select(x => $"(A;;GA;;;{x})")) : ""));
                facts = new HelperTokenFacts(variant.LowIntegrity ? LowIntegrity : "(inherited)", disabled, (variant.WriteRestrict ? restricting : "(none)") + (sourceWriteRestricted ? " [source token write-restricted]" : ""), variant.WriteRestrict, PrivilegesStripped: true);
                return primary;
            }
            finally { Native.CloseHandle(restricted); }
        }
        finally
        {
            foreach (IntPtr p in toFree) Native.LocalFree(p);
            Native.CloseHandle(own);
        }
    }

    private static void SetDefaultDacl(IntPtr token, string sddl)
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out IntPtr sd, out _)) throw Win32("ConvertStringSecurityDescriptor(default DACL)");
        IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            if (!Native.GetSecurityDescriptorDacl(sd, out _, out IntPtr dacl, out _)) throw Win32("GetSecurityDescriptorDacl");
            Marshal.WriteIntPtr(buf, dacl);
            if (!HelperNative.SetTokenInformation(token, HelperNative.TokenDefaultDacl, buf, IntPtr.Size)) throw Win32("SetTokenInformation(TokenDefaultDacl)");
        }
        finally { Marshal.FreeHGlobal(buf); Native.LocalFree(sd); }
    }

    private static void SetLowIntegrity(IntPtr token, List<IntPtr> toFree)
    {
        IntPtr sid = Sid(LowIntegrity, toFree);
        var label = new HelperNative.TOKEN_MANDATORY_LABEL { Label = new Native.SID_AND_ATTRIBUTES { Sid = sid, Attributes = HelperNative.SE_GROUP_INTEGRITY } };
        int size = Marshal.SizeOf<HelperNative.TOKEN_MANDATORY_LABEL>() + HelperNative.GetLengthSid(sid);
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(label, buf, false);
            if (!HelperNative.SetTokenInformation(token, Native.TokenIntegrityLevel, buf, size)) throw Win32("SetTokenInformation(TokenIntegrityLevel)");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static IntPtr Sid(string sddl, List<IntPtr> toFree)
    {
        if (!Native.ConvertStringSidToSidW(sddl, out IntPtr p)) throw Win32($"ConvertStringSidToSid({sddl})");
        toFree.Add(p);
        return p;
    }

    /// <summary>The token's groups as (SID, attributes).</summary>
    internal static List<(string Sid, uint Attributes)> TokenGroups(IntPtr token)
    {
        Native.GetTokenInformation(token, Native.TokenGroups, IntPtr.Zero, 0, out int len);
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, Native.TokenGroups, buf, len, out _)) throw Win32("GetTokenInformation(TokenGroups)");
            int count = Marshal.ReadInt32(buf);
            var list = new List<(string, uint)>(count);
            int stride = Marshal.SizeOf<Native.SID_AND_ATTRIBUTES>();
            for (int i = 0; i < count; i++)
            {
                var g = Marshal.PtrToStructure<Native.SID_AND_ATTRIBUTES>(buf + IntPtr.Size + i * stride);
                if (!Native.ConvertSidToStringSidW(g.Sid, out IntPtr str)) continue;
                list.Add((Marshal.PtrToStringUni(str)!, g.Attributes));
                Native.LocalFree(str);
            }
            return list;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    internal static IntPtr CreateJob(HelperLimits limits)
    {
        IntPtr job = HelperNative.CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Win32("CreateJobObject");
        var ext = new HelperNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        ext.BasicLimitInformation.LimitFlags = HelperNative.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | HelperNative.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | HelperNative.JOB_OBJECT_LIMIT_PROCESS_MEMORY | HelperNative.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        ext.BasicLimitInformation.ActiveProcessLimit = (uint)limits.ActiveProcesses;
        ext.ProcessMemoryLimit = (UIntPtr)(ulong)limits.ProcessMemoryBytes;
        SetJobInfo(job, HelperNative.JobObjectExtendedLimitInformation, ext);
        SetJobInfo(job, HelperNative.JobObjectBasicUIRestrictions, new HelperNative.JOBOBJECT_BASIC_UI_RESTRICTIONS { UIRestrictionsClass = HelperNative.JOB_OBJECT_UILIMIT_ALL });
        return job;
    }

    private static void SetJobInfo<T>(IntPtr job, int infoClass, T value) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(value, buf, false);
            if (!HelperNative.SetInformationJobObject(job, infoClass, buf, size)) throw Win32($"SetInformationJobObject({infoClass})");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>An anonymous pipe; the child's end (0 = read, 1 = write) inheritable, the parent's not.</summary>
    internal static void CreateInheritablePipe(out IntPtr read, out IntPtr write, int childEnd)
    {
        var sa = new HelperNative.SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<HelperNative.SECURITY_ATTRIBUTES>(), bInheritHandle = true };
        if (!HelperNative.CreatePipe(out read, out write, ref sa, 0)) throw Win32("CreatePipe");
        IntPtr parentEnd = childEnd == 0 ? write : read;
        HelperNative.SetHandleInformation(parentEnd, HelperNative.HANDLE_FLAG_INHERIT, 0);
    }

    /// <summary>A window station and desktop for this run only. Both grant Everyone (the helper's enabled group) and
    /// carry a low-integrity label; nothing else runs on them. Returns "winsta\desktop".</summary>
    private static string CreatePrivateDesktop(string restrictingSid, out IntPtr winsta, out IntPtr desktop, out IntPtr previous)
    {
        // As the Chromium sandbox does: an unnamed window station opened with only the rights needed to create a
        // desktop on it; one desktop on it. Both are private to this run, and their DACL grants the helper: Everyone
        // (its enabled group) and its restricting SID (a WRITE_RESTRICTED token's writes — including the system's own
        // desktop initialization — need it), with a low-integrity label so the low-integrity helper may write to them.
        // Nothing else runs on them; this grants nothing on the filesystem or on the service's own window station.
        string restrictAce = string.Concat(restrictingSid.Split(' ')[0].Split(',').Where(x => x.StartsWith("S-", StringComparison.Ordinal)).Select(x => $"(A;;GA;;;{x})"));
        string sddl = $"D:P(A;;GA;;;WD)(A;;GA;;;SY){restrictAce}S:(ML;;NW;;;LW)";
        winsta = HelperNative.CreateWindowStationW(null, 0, HelperNative.GENERIC_READ | HelperNative.WINSTA_CREATEDESKTOP | Native.READ_CONTROL | Native.WRITE_DAC | Native.WRITE_OWNER, IntPtr.Zero);
        if (winsta == IntPtr.Zero) throw Win32("CreateWindowStation");
        SetDacl(winsta, sddl);
        string name = ObjectName(winsta);
        previous = HelperNative.GetProcessWindowStation();
        if (!HelperNative.SetProcessWindowStation(winsta)) throw Win32("SetProcessWindowStation");
        IntPtr sd = SecurityAttributes(sddl, out IntPtr saBuf);
        try
        {
            desktop = HelperNative.CreateDesktopW("Default", IntPtr.Zero, IntPtr.Zero, 0, HelperNative.GENERIC_ALL, saBuf);
            if (desktop == IntPtr.Zero) throw Win32("CreateDesktop");
        }
        finally
        {
            HelperNative.SetProcessWindowStation(previous);
            previous = IntPtr.Zero;
            Marshal.FreeHGlobal(saBuf);
            Native.LocalFree(sd);
        }
        return name + @"\Default";
    }

    internal static void SetDacl(IntPtr handle, string sddl)
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out IntPtr sd, out _)) throw Win32("ConvertStringSecurityDescriptor");
        try
        {
            if (!Native.GetSecurityDescriptorDacl(sd, out _, out IntPtr dacl, out _)) throw Win32("GetSecurityDescriptorDacl");
            if (!Native.GetSecurityDescriptorSacl(sd, out _, out IntPtr sacl, out _)) throw Win32("GetSecurityDescriptorSacl");
            uint rc = Native.SetSecurityInfo(handle, HelperNative.SE_WINDOW_OBJECT, Native.DACL_SECURITY_INFORMATION | Native.PROTECTED_DACL_SECURITY_INFORMATION | Native.LABEL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, dacl, sacl);
            if (rc != 0) throw new Win32Exception((int)rc, "SetSecurityInfo(window station)");
        }
        finally { Native.LocalFree(sd); }
    }

    internal static string ObjectName(IntPtr handle)
    {
        HelperNative.GetUserObjectInformationW(handle, HelperNative.UOI_NAME, IntPtr.Zero, 0, out int needed);
        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            if (!HelperNative.GetUserObjectInformationW(handle, HelperNative.UOI_NAME, buf, needed, out _)) throw Win32("GetUserObjectInformation");
            return Marshal.PtrToStringUni(buf)!;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    internal static IntPtr SecurityAttributes(string sddl, out IntPtr saBuf)
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out IntPtr sd, out _)) throw Win32("ConvertStringSecurityDescriptor");
        var sa = new HelperNative.SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<HelperNative.SECURITY_ATTRIBUTES>(), lpSecurityDescriptor = sd, bInheritHandle = false };
        saBuf = Marshal.AllocHGlobal(sa.nLength);
        Marshal.StructureToPtr(sa, saBuf, false);
        return sd;
    }

    internal static IntPtr EnvironmentBlock(IReadOnlyDictionary<string, string> env)
    {
        var sb = new StringBuilder();
        foreach ((string k, string v) in env.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (k.Contains('=') || k.Contains('\0') || v.Contains('\0')) throw new ArgumentException($"invalid environment entry {k}");
            sb.Append(k).Append('=').Append(v).Append('\0');
        }
        sb.Append('\0');
        return Marshal.StringToHGlobalUni(sb.ToString());
    }

    /// <summary>A Windows command line that CommandLineToArgvW and the MSVC runtime parse back into exactly these arguments.</summary>
    internal static string CommandLine(string exe, IReadOnlyList<string> args)
    {
        var sb = new StringBuilder(Quote(exe));
        foreach (string a in args) sb.Append(' ').Append(Quote(a));
        return sb.ToString();
    }

    private static string Quote(string a)
    {
        if (a.Length > 0 && a.IndexOfAny([' ', '\t', '"']) < 0) return a;
        var sb = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in a)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { sb.Append('\\', slashes * 2 + 1).Append('"'); slashes = 0; continue; }
            sb.Append('\\', slashes).Append(c);
            slashes = 0;
        }
        sb.Append('\\', slashes * 2).Append('"');
        return sb.ToString();
    }

    internal static byte[] ReadBounded(Stream s, int max, Action overLimit)
    {
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        int n;
        while ((n = s.Read(buf, 0, buf.Length)) > 0)
        {
            if (ms.Length + n > max) { overLimit(); break; }
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    private static Win32Exception Win32(string what) => new(Marshal.GetLastWin32Error(), what);

    internal static JsonObject Describe(HelperTokenFacts f) => new()
    {
        ["integrity"] = f.IntegritySid,
        ["disabledSids"] = new JsonArray(f.DisabledSids.Select(s => (JsonNode)s).ToArray()),
        ["restrictingSid"] = f.RestrictingSid,
        ["writeRestricted"] = f.WriteRestricted,
        ["privilegesStripped"] = f.PrivilegesStripped,
    };
}
