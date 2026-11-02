using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Security;

/// <summary>
/// Manages the dedicated worker account's Windows credential entirely within the broker: provisioning
/// rotates it to a random password stored only in a LocalSystem-readable LSA private secret, and the
/// launcher retrieves it at launch. The controller/operator never hold the worker password.
/// </summary>
internal static class WorkerCredential
{
    private const int ERROR_MEMBER_IN_ALIAS = 1378;

    /// <summary>Ensure the worker account exists, is a plain member of Users, has a fresh random
    /// password, and that password is stored in the LSA secret. Idempotent.</summary>
    internal static void Provision()
    {
        string password = NewPassword();
        try
        {
            if (!AccountExists())
            {
                var ui = new Native.USER_INFO_1
                {
                    usri1_name = BrokerConstants.WorkerAccount,
                    usri1_password = password,
                    usri1_priv = (uint)Native.USER_PRIV_USER,
                    usri1_flags = Native.UF_NORMAL_ACCOUNT | Native.UF_DONT_EXPIRE_PASSWD,
                    usri1_comment = "CodeParley dedicated worker identity (managed by the broker; do not use interactively).",
                };
                int r = Native.NetUserAdd(null, 1, ref ui, out _);
                if (r != Native.NERR_Success) throw new Win32Exception(r, "NetUserAdd");
            }
            else
            {
                var up = new Native.USER_INFO_1003 { usri1003_password = password };
                int r = Native.NetUserSetInfo(null, BrokerConstants.WorkerAccount, 1003, ref up, out _);
                if (r != Native.NERR_Success) throw new Win32Exception(r, "NetUserSetInfo");
            }

            AddToUsersGroup();
            StoreSecret(password);
        }
        finally
        {
            password = string.Empty; // best effort; the LSA secret is the durable store
        }
    }

    /// <summary>Remove the LSA secret and delete the worker account. Idempotent.</summary>
    internal static void Deprovision()
    {
        try { DeleteSecret(); } catch { /* best effort */ }
        int r = Native.NetUserDel(null, BrokerConstants.WorkerAccount);
        if (r != Native.NERR_Success && r != Native.NERR_UserNotFound) throw new Win32Exception(r, "NetUserDel");
    }

    internal static bool AccountExists()
    {
        int r = Native.NetUserGetInfo(null, BrokerConstants.WorkerAccount, 0, out IntPtr buf);
        if (r == Native.NERR_Success) { Native.NetApiBufferFree(buf); return true; }
        if (r == Native.NERR_UserNotFound) return false;
        throw new Win32Exception(r, "NetUserGetInfo");
    }

    /// <summary>Retrieve the worker password as an unmanaged LPWSTR for LogonUser; caller zeroes+frees.</summary>
    internal static IntPtr RetrievePasswordLpwstr()
    {
        IntPtr policy = OpenPolicy(Native.POLICY_GET_PRIVATE_INFORMATION);
        IntPtr keyBuf = IntPtr.Zero, data = IntPtr.Zero;
        try
        {
            var key = BuildLsaString(BrokerConstants.LsaSecretKey, out keyBuf);
            int st = Native.LsaRetrievePrivateData(policy, ref key, out data);
            if (st != 0) throw new Win32Exception(Native.LsaNtStatusToWinError(st), "LsaRetrievePrivateData");
            if (data == IntPtr.Zero) throw new InvalidOperationException("worker credential not provisioned (no LSA secret)");
            var lus = Marshal.PtrToStructure<Native.LSA_UNICODE_STRING>(data);
            int chars = lus.Length / 2;
            IntPtr outBuf = Marshal.AllocHGlobal((chars + 1) * 2);
            for (int i = 0; i < chars; i++) Marshal.WriteInt16(outBuf, i * 2, Marshal.ReadInt16(lus.Buffer, i * 2));
            Marshal.WriteInt16(outBuf, chars * 2, 0);
            return outBuf;
        }
        finally
        {
            if (data != IntPtr.Zero) Native.LsaFreeMemory(data);
            if (keyBuf != IntPtr.Zero) Marshal.FreeHGlobal(keyBuf);
            Native.LsaClose(policy);
        }
    }

    internal static void ZeroFreeLpwstr(IntPtr lpwstr)
    {
        if (lpwstr == IntPtr.Zero) return;
        int i = 0;
        while (Marshal.ReadInt16(lpwstr, i * 2) != 0) { Marshal.WriteInt16(lpwstr, i * 2, 0); i++; }
        Marshal.FreeHGlobal(lpwstr);
    }

    private static void AddToUsersGroup()
    {
        var m = new Native.LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname = $"{Environment.MachineName}\\{BrokerConstants.WorkerAccount}" };
        int r = Native.NetLocalGroupAddMembers(null, "Users", 3, ref m, 1);
        if (r != Native.NERR_Success && r != ERROR_MEMBER_IN_ALIAS) throw new Win32Exception(r, "NetLocalGroupAddMembers");
    }

    // ---- LSA secret helpers ----
    private static IntPtr OpenPolicy(uint access)
    {
        var attrs = default(Native.LSA_OBJECT_ATTRIBUTES);
        attrs.Length = Marshal.SizeOf<Native.LSA_OBJECT_ATTRIBUTES>();
        int st = Native.LsaOpenPolicy(IntPtr.Zero, ref attrs, access, out IntPtr h);
        if (st != 0) throw new Win32Exception(Native.LsaNtStatusToWinError(st), "LsaOpenPolicy");
        return h;
    }

    private static Native.LSA_UNICODE_STRING BuildLsaString(string s, out IntPtr buffer)
    {
        buffer = Marshal.StringToHGlobalUni(s);
        return new Native.LSA_UNICODE_STRING
        {
            Buffer = buffer,
            Length = (ushort)(s.Length * 2),
            MaximumLength = (ushort)((s.Length + 1) * 2),
        };
    }

    private static void StoreSecret(string value)
    {
        IntPtr policy = OpenPolicy(Native.POLICY_CREATE_SECRET);
        IntPtr keyBuf = IntPtr.Zero, valBuf = IntPtr.Zero, valPtr = IntPtr.Zero;
        try
        {
            var key = BuildLsaString(BrokerConstants.LsaSecretKey, out keyBuf);
            var val = BuildLsaString(value, out valBuf);
            valPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.LSA_UNICODE_STRING>());
            Marshal.StructureToPtr(val, valPtr, false);
            int st = Native.LsaStorePrivateData(policy, ref key, valPtr);
            if (st != 0) throw new Win32Exception(Native.LsaNtStatusToWinError(st), "LsaStorePrivateData");
        }
        finally
        {
            if (valPtr != IntPtr.Zero) Marshal.FreeHGlobal(valPtr);
            if (valBuf != IntPtr.Zero) { for (int i = 0; i < value.Length; i++) Marshal.WriteInt16(valBuf, i * 2, 0); Marshal.FreeHGlobal(valBuf); }
            if (keyBuf != IntPtr.Zero) Marshal.FreeHGlobal(keyBuf);
            Native.LsaClose(policy);
        }
    }

    private static void DeleteSecret()
    {
        IntPtr policy = OpenPolicy(Native.POLICY_CREATE_SECRET);
        IntPtr keyBuf = IntPtr.Zero;
        try
        {
            var key = BuildLsaString(BrokerConstants.LsaSecretKey, out keyBuf);
            Native.LsaStorePrivateData(policy, ref key, IntPtr.Zero); // null data deletes
        }
        finally
        {
            if (keyBuf != IntPtr.Zero) Marshal.FreeHGlobal(keyBuf);
            Native.LsaClose(policy);
        }
    }

    private static string NewPassword()
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", lower = "abcdefghijkmnpqrstuvwxyz", digit = "23456789", sym = "!@#$%^&*()-_=+";
        string all = upper + lower + digit + sym;
        var chars = new List<char> { Pick(upper), Pick(lower), Pick(digit), Pick(sym) };
        for (int i = 0; i < 20; i++) chars.Add(Pick(all));
        for (int i = chars.Count - 1; i > 0; i--) { int j = RandomNumberGenerator.GetInt32(i + 1); (chars[i], chars[j]) = (chars[j], chars[i]); }
        return new string(chars.ToArray());
        static char Pick(string s) => s[RandomNumberGenerator.GetInt32(s.Length)];
    }
}
