using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Launch;

/// <summary>A logged-on worker's tokens. <see cref="Logon"/> (unrestricted) is used to load the
/// profile and derive the environment; <see cref="Restricted"/> (WRITE_RESTRICTED) is used to launch
/// the worker process. Both share the same logon session / logon SID.</summary>
internal sealed class WorkerToken : IDisposable
{
    internal IntPtr Logon { get; init; }
    internal IntPtr Restricted { get; init; }
    internal required string LogonSid { get; init; }

    public void Dispose()
    {
        if (Restricted != IntPtr.Zero) Native.CloseHandle(Restricted);
        if (Logon != IntPtr.Zero) Native.CloseHandle(Logon);
    }
}

internal static class TokenBuilder
{
    /// <summary>
    /// Log the worker on and derive its WRITE_RESTRICTED token. Per Microsoft's write-restricted
    /// token model, writes succeed ONLY via the restricting SIDs, so the set must let real runtimes
    /// function while still denying the protected writes:
    ///   - worker account SID  -> the worker's own persistent profile;
    ///   - per-launch logon SID -> this run's workspace;
    ///   - Everyone (S-1-1-0) + WRITE RESTRICTED (S-1-5-33) -> the Everyone-writable system locations
    ///     and named-object namespaces runtimes (node, git, the CLR) need to start.
    /// Sibling repos (Authenticated Users) and trusted state (SYSTEM/Administrators) grant none of
    /// these SIDs, so those writes remain denied (the workload's negative checks re-confirm it).
    /// </summary>
    internal static WorkerToken LogonAndRestrict(string account, IntPtr passwordLpwstr, string accountSid)
    {
        if (!Native.LogonUserW(account, ".", passwordLpwstr, Native.LOGON32_LOGON_INTERACTIVE, Native.LOGON32_PROVIDER_DEFAULT, out IntPtr logon))
            Native.ThrowLastError("LogonUser");

        IntPtr restricted = IntPtr.Zero;
        var sidPtrs = new List<IntPtr>();
        try
        {
            string logonSid = SidUtil.GetLogonSid(logon);
            string[] restrictSids = [accountSid, logonSid, "S-1-1-0", "S-1-5-33"];
            var restrict = new Native.SID_AND_ATTRIBUTES[restrictSids.Length];
            for (int i = 0; i < restrictSids.Length; i++)
            {
                IntPtr s = SidUtil.StringToSid(restrictSids[i]);
                sidPtrs.Add(s);
                restrict[i].Sid = s;
                restrict[i].Attributes = 0;
            }

            if (!Native.CreateRestrictedToken(logon, Native.WRITE_RESTRICTED, 0, IntPtr.Zero, 0, IntPtr.Zero,
                    (uint)restrict.Length, restrict, out restricted))
                Native.ThrowLastError("CreateRestrictedToken");

            var worker = new WorkerToken { Logon = logon, Restricted = restricted, LogonSid = logonSid };
            logon = restricted = IntPtr.Zero; // ownership transferred to WorkerToken
            return worker;
        }
        finally
        {
            foreach (IntPtr s in sidPtrs) if (s != IntPtr.Zero) Native.LocalFree(s);
            if (restricted != IntPtr.Zero) Native.CloseHandle(restricted);
            if (logon != IntPtr.Zero) Native.CloseHandle(logon);
        }
    }
}
