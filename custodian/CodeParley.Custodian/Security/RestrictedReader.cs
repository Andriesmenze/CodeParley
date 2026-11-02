using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// The capture-helper probe (TD amendment 5). Before the design depends on a restricted reader, this
/// demonstrates, run by the operator, what a WRITE_RESTRICTED token of the caller actually gets:
///   (1) it can READ a representative operator-owned repository file (including one with a
///       user-SID-specific ACL), so the helper can do its capture job; and
///   (2) it is DENIED custodian state — a WRITE to the operator-readable store, and both read and write
///       of a custodian-ONLY private record (the stand-in for an operator-private record / credential).
///
/// It records exactly what held and what did not. The known limitation it surfaces: WRITE_RESTRICTED
/// contains writes but does not restrict READS, so read-denial of custodian-only data comes from the
/// DACL (custodian-only, not operator-readable), not the token — and a fully read-only, integrity-lowered
/// helper under a distinct principal is the alternative returned for TD review.
/// </summary>
internal static class RestrictedReader
{
    internal static JsonObject Probe(string repoFile)
    {
        var o = new JsonObject { ["repoFile"] = repoFile, ["privateRecord"] = StorePaths.PrivateProbe, ["storeRoot"] = StorePaths.Root };
        o["unrestrictedCaller"] = Attempts(repoFile, restricted: false);
        o["writeRestrictedToken"] = Attempts(repoFile, restricted: true);
        o["finding"] = "WRITE_RESTRICTED contains writes; read-denial of custodian-only data is enforced by the DACL (custodian-only), not the token. A fully read-only helper under a distinct low-integrity principal is recommended for TD review.";
        return o;
    }

    private static JsonObject Attempts(string repoFile, bool restricted)
    {
        IntPtr restrictedToken = IntPtr.Zero;
        try
        {
            if (restricted) restrictedToken = BuildWriteRestricted();
            Func<JsonObject> body = () => new JsonObject
            {
                ["readRepoFile"] = Try(() => { _ = File.ReadAllBytes(repoFile); }),
                ["readPrivateRecord"] = Try(() => { _ = File.ReadAllBytes(StorePaths.PrivateProbe); }),
                ["writeStoreRoot"] = Try(() => WriteProbe(StorePaths.Root)),
            };
            if (!restricted) return body();
            using var identity = new WindowsIdentity(restrictedToken);
            return WindowsIdentity.RunImpersonated(identity.AccessToken, body);
        }
        catch (Exception e) { return new JsonObject { ["error"] = e.Message }; }
        finally { if (restrictedToken != IntPtr.Zero) Native.CloseHandle(restrictedToken); }
    }

    /// <summary>A WRITE_RESTRICTED primary→impersonation token of the current process, restricting SID =
    /// the caller's own user SID (the 3.1A shape): writes are granted only where that SID is explicitly
    /// allowed, reads are unaffected.</summary>
    private static IntPtr BuildWriteRestricted()
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY | Native.TOKEN_ASSIGN_PRIMARY | Native.TOKEN_IMPERSONATE | Native.TOKEN_ADJUST_DEFAULT | Native.TOKEN_ADJUST_GROUPS, out IntPtr proc))
            Native.ThrowLastError("OpenProcessToken");
        try
        {
            string userSid = WindowsIdentity.GetCurrent().User!.Value;
            if (!Native.ConvertStringSidToSidW(userSid, out IntPtr pSid)) Native.ThrowLastError("ConvertStringSidToSid");
            try
            {
                var restrict = new[] { new Native.SID_AND_ATTRIBUTES { Sid = pSid, Attributes = 0 } };
                if (!Native.CreateRestrictedToken(proc, Native.WRITE_RESTRICTED, 0, null, 0, IntPtr.Zero, (uint)restrict.Length, restrict, out IntPtr restricted))
                    Native.ThrowLastError("CreateRestrictedToken");
                try
                {
                    if (!Native.DuplicateTokenEx(restricted, Native.TOKEN_QUERY | Native.TOKEN_IMPERSONATE, IntPtr.Zero, Native.SecurityImpersonation, 2 /*TokenImpersonation*/, out IntPtr imp))
                        Native.ThrowLastError("DuplicateTokenEx");
                    return imp;
                }
                finally { Native.CloseHandle(restricted); }
            }
            finally { Native.FreeSid(pSid); }
        }
        finally { Native.CloseHandle(proc); }
    }

    private static void WriteProbe(string dir)
    {
        string p = Path.Combine(dir, "cp_write_probe_" + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        File.WriteAllText(p, "x");
        try { File.Delete(p); } catch { }
    }

    private static JsonObject Try(Action a)
    {
        try { a(); return new JsonObject { ["allowed"] = true }; }
        catch (Exception e) { return new JsonObject { ["allowed"] = false, ["denied"] = e.GetType().Name, ["detail"] = Compact(e.Message) }; }
    }

    private static string Compact(string s) => s.Replace('\n', ' ').Replace('\r', ' ').Trim();
}
