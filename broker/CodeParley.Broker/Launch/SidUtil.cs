using System.Runtime.InteropServices;
using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Launch;

/// <summary>SID string conversions and logon-SID extraction (matches the proven token experiment).</summary>
internal static class SidUtil
{
    internal static string SidToString(IntPtr pSid)
    {
        if (!Native.ConvertSidToStringSidW(pSid, out IntPtr str)) Native.ThrowLastError("ConvertSidToStringSid");
        try { return Marshal.PtrToStringUni(str)!; }
        finally { Native.LocalFree(str); }
    }

    /// <summary>Caller frees the returned PSID with <see cref="Native.LocalFree"/>.</summary>
    internal static IntPtr StringToSid(string sid)
    {
        if (!Native.ConvertStringSidToSidW(sid, out IntPtr p)) Native.ThrowLastError("ConvertStringSidToSid");
        return p;
    }

    /// <summary>The logon-session SID (S-1-5-5-X-Y) carried by a token, used as a restricting SID.</summary>
    internal static string GetLogonSid(IntPtr token)
    {
        int len = 0;
        _ = Native.GetTokenInformation(token, Native.TokenGroups, IntPtr.Zero, 0, out len);
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, Native.TokenGroups, buf, len, out len)) Native.ThrowLastError("GetTokenInformation");
            int count = Marshal.ReadInt32(buf);
            IntPtr arr = IntPtr.Add(buf, IntPtr.Size);              // GroupCount (DWORD) + padding == IntPtr.Size on x64
            int stride = Marshal.SizeOf<Native.SID_AND_ATTRIBUTES>();
            for (int i = 0; i < count; i++)
            {
                IntPtr entry = IntPtr.Add(arr, i * stride);
                uint attr = (uint)Marshal.ReadInt32(IntPtr.Add(entry, IntPtr.Size));
                if ((attr & Native.SE_GROUP_LOGON_ID) == Native.SE_GROUP_LOGON_ID)
                    return SidToString(Marshal.ReadIntPtr(entry));
            }
            throw new InvalidOperationException("token carries no logon SID");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
