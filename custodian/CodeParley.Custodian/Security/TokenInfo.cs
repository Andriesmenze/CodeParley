using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// Read-only introspection of a Windows access token: integrity level, restricting SIDs, privileges and
/// groups. Used by the host report so the live operator run records the custodian service's ACTUAL token
/// facts (TD amendment 2c), not just the constructed service configuration, and so administrator-equivalent
/// group membership (H-3) is measured, not assumed.
/// </summary>
internal static class TokenInfo
{
    internal static int IntegrityRid(IntPtr token)
    {
        Native.GetTokenInformation(token, Native.TokenIntegrityLevel, IntPtr.Zero, 0, out int len);
        if (len <= 0) return 0;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, Native.TokenIntegrityLevel, buf, len, out _)) return 0;
            return RidOf(Marshal.ReadIntPtr(buf)); // TOKEN_MANDATORY_LABEL.Label.Sid is the first field
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    internal static string IntegrityName(int rid) => rid switch
    {
        >= 0x4000 => "System",
        >= 0x3000 => "High",
        >= 0x2000 => "Medium",
        >= 0x1000 => "Low",
        _ => $"0x{rid:x}",
    };

    /// <summary>The restricting SIDs of a write-restricted token (empty = not restricted).</summary>
    internal static List<string> RestrictedSids(IntPtr token) => GroupLikeSids(token, Native.TokenRestrictedSids);

    /// <summary>Every group SID in the token (includes deny-only and the integrity SID).</summary>
    internal static List<string> GroupSids(IntPtr token) => GroupLikeSids(token, Native.TokenGroups);

    // TOKEN_GROUPS and the restricted-SID list share the shape { DWORD Count; SID_AND_ATTRIBUTES[Count] }.
    private static List<string> GroupLikeSids(IntPtr token, int infoClass)
    {
        var sids = new List<string>();
        Native.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out int len);
        if (len <= 0) return sids;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, infoClass, buf, len, out _)) return sids;
            int count = Marshal.ReadInt32(buf);
            IntPtr array = buf + IntPtr.Size; // the array is pointer-aligned after the DWORD count
            int stride = Marshal.SizeOf<Native.SID_AND_ATTRIBUTES>();
            for (int i = 0; i < count; i++)
            {
                var sa = Marshal.PtrToStructure<Native.SID_AND_ATTRIBUTES>(array + i * stride);
                string? s = SidString(sa.Sid);
                if (s is not null) sids.Add(s);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return sids;
    }

    internal static List<string> Privileges(IntPtr token)
    {
        var names = new List<string>();
        Native.GetTokenInformation(token, Native.TokenPrivileges, IntPtr.Zero, 0, out int len);
        if (len <= 0) return names;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, Native.TokenPrivileges, buf, len, out _)) return names;
            int count = Marshal.ReadInt32(buf);
            IntPtr array = buf + sizeof(int);
            int stride = Marshal.SizeOf<Native.LUID_AND_ATTRIBUTES>();
            for (int i = 0; i < count; i++)
            {
                var la = Marshal.PtrToStructure<Native.LUID_AND_ATTRIBUTES>(array + i * stride);
                var sb = new StringBuilder(256);
                int cch = sb.Capacity;
                Native.LUID luid = la.Luid;
                if (Native.LookupPrivilegeNameW(null, ref luid, sb, ref cch)) names.Add(sb.ToString());
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return names;
    }

    private static int RidOf(IntPtr sidPtr)
    {
        string? s = SidString(sidPtr);
        if (s is null) return 0;
        string[] parts = s.Split('-');
        return int.TryParse(parts[^1], out int rid) ? rid : 0;
    }

    private static string? SidString(IntPtr sid)
    {
        if (sid == IntPtr.Zero) return null;
        if (!Native.ConvertSidToStringSidW(sid, out IntPtr str)) return null;
        try { return Marshal.PtrToStringUni(str); }
        finally { Native.LocalFree(str); }
    }

    /// <summary>The current process token handle (query access).</summary>
    internal static IntPtr CurrentProcessToken() => WindowsIdentity.GetCurrent().Token;
}
