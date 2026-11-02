using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace CodeParley.Custodian.Security;

/// <summary>
/// The custodian host report: the mechanics facts (identity, store, config) that gate serving, and —
/// reported SEPARATELY — the production host preconditions (H-1..H-4) measured on this machine. A
/// precondition that is not met never blocks the mechanics, but it is stated so no run on this host can
/// be read as proof against an attacker able to obtain administrator rights (TD amendments 2 and 7).
/// </summary>
internal static class HostCheck
{
    internal sealed record Report(JsonObject Facts, List<string> MechanicsProblems, List<string> UnmetPreconditions)
    {
        internal bool MechanicsHealthy => MechanicsProblems.Count == 0;
    }

    internal static Report Verify()
    {
        var mech = new List<string>();
        var pre = new List<string>();
        var f = new JsonObject
        {
            ["component"] = "custodian",
            ["milestone"] = "P3.4B",
            ["platform"] = "windows",
            ["architecture"] = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            ["osVersion"] = Environment.OSVersion.VersionString,
        };

        f["identity"] = IdentityFacts(mech);
        f["expectedServiceSid"] = ServiceSid.Custodian().Value;
        f["runningProcessToken"] = ServiceTokenFacts();
        f["store"] = StoreFacts(mech);
        f["config"] = ConfigFacts(mech);
        f["preconditions"] = Preconditions(pre);

        f["mechanicsHealthy"] = mech.Count == 0;
        f["mechanicsProblems"] = new JsonArray(mech.Select(p => (JsonNode?)p).ToArray());
        f["unmetPreconditions"] = new JsonArray(pre.Select(p => (JsonNode?)p).ToArray());
        f["securityBoundaryClaim"] = pre.Count == 0
            ? "host preconditions met; adversarial results may be read as a security-boundary proof"
            : "host preconditions NOT met; results demonstrate MECHANICS only, not a boundary against an attacker who can elevate";
        return new Report(f, mech, pre);
    }

    private static JsonObject IdentityFacts(List<string> mech)
    {
        var o = new JsonObject();
        try
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            o["account"] = me.Name;
            o["sid"] = me.User?.Value;
            bool isCustodianSvc = me.User?.Value == ServiceSid.Custodian().Value;
            o["isCustodianServiceAccount"] = isCustodianSvc;
            o["isLocalSystem"] = me.User?.Value == "S-1-5-18";
            // Fully verified only when running as the virtual service account; the CLI (operator) prints
            // the report too, so this is a note, not a mechanics failure.
            o["note"] = isCustodianSvc ? "running as the virtual service account" : "not the service account (CLI/console view)";
        }
        catch (Exception e) { mech.Add("identity: " + e.Message); }
        return o;
    }

    /// <summary>The ACTUAL token facts of this process (TD amendment 2c): integrity, restricting SIDs,
    /// privileges, and whether it can write the protected store (TD amendment 2d: the High-labelled store
    /// must be writable by the service without weakening its label). Authoritative when the SERVICE
    /// answers it over the `service_identity` IPC op.</summary>
    internal static JsonObject ServiceTokenFacts()
    {
        var o = new JsonObject();
        try
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            IntPtr token = me.Token;
            int rid = TokenInfo.IntegrityRid(token);
            o["account"] = me.Name;
            o["sid"] = me.User?.Value;
            o["integrity"] = TokenInfo.IntegrityName(rid);
            o["integrityRid"] = $"0x{rid:x}";
            List<string> restricting = TokenInfo.RestrictedSids(token);
            o["isWriteRestricted"] = restricting.Count > 0;
            o["restrictingSids"] = new JsonArray(restricting.Select(s => (JsonNode?)s).ToArray());
            o["privileges"] = new JsonArray(TokenInfo.Privileges(token).Select(s => (JsonNode?)s).ToArray());
            (bool ok, string detail) = WriteProbe(StorePaths.Root, store: true);
            o["storeWritable"] = ok;
            o["storeWriteDetail"] = detail;
            // TD P3.4B-live verification #2: attempt writes OUTSIDE the approved store, under this token,
            // to a FIXED set of representative locations (never caller-supplied), and record the EFFECTIVE
            // result — not the constructed token config. A write-restricted service SID still carries the
            // World restricting SID, so world-writable dirs may be reachable; that is recorded as a finding,
            // never silently "fixed". Each target is create+delete only.
            var ambient = new JsonArray();
            bool anyOutsideWritable = false;
            foreach ((string name, string dir) in AmbientTargets())
            {
                (bool w, string d) = WriteProbe(dir, store: false);
                if (w) anyOutsideWritable = true;
                ambient.Add(new JsonObject { ["target"] = name, ["path"] = dir, ["writable"] = w, ["detail"] = d });
            }
            o["ambientWrites"] = ambient;
            o["anyWriteOutsideStore"] = anyOutsideWritable;
        }
        catch (Exception e) { o["error"] = e.Message; }
        return o;
    }

    private static IEnumerable<(string name, string dir)> AmbientTargets()
    {
        string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        yield return ("sharedParent", StorePaths.SharedParent);
        yield return ("programData", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        yield return ("windowsTemp", Path.Combine(windir, "Temp"));
        yield return ("systemDriveRoot", Path.GetPathRoot(windir) ?? "C:\\");
        yield return ("publicProfile", Environment.GetEnvironmentVariable("PUBLIC") ?? "C:\\Users\\Public");
    }

    private static (bool ok, string detail) WriteProbe(string dir, bool store)
    {
        if (!Directory.Exists(dir)) return (false, store ? "store does not exist (not provisioned)" : "directory absent");
        string p = Path.Combine(dir, "cp_write_probe_" + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try { File.WriteAllText(p, "x"); File.Delete(p); return (true, store ? "wrote and deleted in the High-labelled store" : "WRITABLE (create+delete succeeded)"); }
        catch (Exception e) { return (false, e.GetType().Name); }
    }

    private static JsonObject StoreFacts(List<string> mech)
    {
        var o = new JsonObject { ["root"] = StorePaths.Root };
        SecureStore.ParentState p = SecureStore.InspectParent();
        o["sharedParent"] = new JsonObject
        {
            ["path"] = StorePaths.SharedParent, ["exists"] = p.Exists, ["owner"] = p.Owner,
            ["isReparsePoint"] = p.IsReparse, ["usersWritable"] = p.UsersWritable,
            ["note"] = p.UsersWritable ? "parent is Users-writable (shared with broker); the custodian subtree is protected and a pre-created subtree is refused" : "parent not Users-writable",
        };
        List<string> sp = SecureStore.ValidateStore();
        o["protected"] = sp.Count == 0;
        if (sp.Count > 0) { o["problems"] = new JsonArray(sp.Select(x => (JsonNode?)x).ToArray()); mech.AddRange(sp); }
        return o;
    }

    private static JsonObject ConfigFacts(List<string> mech)
    {
        var o = new JsonObject();
        try
        {
            CustodianConfig cfg = CustodianConfig.Load();
            o["operatorSid"] = cfg.OperatorSid;
            o["operatorAccount"] = cfg.OperatorAccount;
            o["implementerSid"] = cfg.ImplementerSid;
            o["implementerAccount"] = cfg.ImplementerAccount;
            o["distinctPrincipals"] = cfg.OperatorSid != cfg.ImplementerSid;
            o["operatorAssurance"] = "local_admin_elevation (L1): the operator surface requires an elevated token of the operator SID; NOT a production boundary";
        }
        catch (Exception e) { mech.Add("config: " + e.Message); }
        return o;
    }

    private static JsonObject Preconditions(List<string> unmet)
    {
        var o = new JsonObject();
        bool accountIsAdmin = false, tokenElevated = false;
        try
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            tokenElevated = new WindowsPrincipal(me).IsInRole(WindowsBuiltInRole.Administrator);
            // The account's membership, NOT the current filtered token: a medium-integrity admin process
            // carries a LINKED (elevation) token whose groups include Administrators. Its presence, or
            // Administrators in the current token, means the account can elevate.
            accountIsAdmin = tokenElevated || LinkedTokenIsAdmin(me.Token);
            o["accountIsAdministrator"] = accountIsAdmin;
            o["currentTokenElevated"] = tokenElevated;
        }
        catch { /* reported via preconditions below */ }

        int consent = (int)(ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin") ?? -1);
        int adminApproval = (int)(ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "TypeOfAdminApprovalMode") ?? 1);
        int devmode = (int)(ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock", "AllowDevelopmentWithoutDevLicense") ?? 0);
        o["uacConsentPromptBehaviorAdmin"] = consent;
        o["typeOfAdminApprovalMode"] = adminApproval;
        o["administratorProtection"] = adminApproval == 2;
        o["developerMode"] = devmode == 1;

        // H-1: the implementer account must not be able to elevate silently.
        bool adminProtection = adminApproval == 2;
        if (accountIsAdmin && !adminProtection)
            unmet.Add("H-1: the calling account is a member of Administrators under legacy Admin Approval Mode (not a standard user, and Administrator protection is off); it can obtain administrator rights without an operator act");
        if (consent is not (1 or 2) && !adminProtection)
            unmet.Add($"H-2: UAC is not 'always notify' (ConsentPromptBehaviorAdmin={consent}); Windows binaries auto-elevate, the basis of silent bypasses");
        if (devmode == 1)
            o["developerModeNote"] = "symbolic-link creation is available to unprivileged processes; the no-follow resolver is designed to tolerate this (it refuses any reparse component)";

        // H-3: administrator-equivalent group membership (measured, not assumed).
        List<string> adminGroups = AdminEquivalentGroups();
        o["adminEquivalentGroups"] = new JsonArray(adminGroups.Select(g => (JsonNode?)g).ToArray());
        if (adminGroups.Count > 0)
            unmet.Add("H-3: the calling account is a member of administrator-equivalent group(s) that control privileged services (" + string.Join(", ", adminGroups) + "); it can reach SYSTEM without an operator act");
        return o;
    }

    // Admin-equivalent BUILTIN groups beyond plain Administrators (which is H-1): their members can
    // control privileged services and so reach SYSTEM. docker-users is a machine-local group checked by name.
    private static readonly (string Sid, string Name)[] AdminEquivalentBuiltin =
    [
        ("S-1-5-32-551", "Backup Operators"), ("S-1-5-32-549", "Server Operators"),
        ("S-1-5-32-550", "Print Operators"), ("S-1-5-32-578", "Hyper-V Administrators"),
    ];

    private static List<string> AdminEquivalentGroups()
    {
        var matched = new List<string>();
        try
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            var sids = new HashSet<string>(TokenInfo.GroupSids(me.Token), StringComparer.OrdinalIgnoreCase);
            // Include the linked (elevation) token's groups, which carry memberships a filtered token hides.
            IntPtr linked = LinkedToken(me.Token);
            if (linked != IntPtr.Zero) { try { foreach (string s in TokenInfo.GroupSids(linked)) sids.Add(s); } finally { Interop.Native.CloseHandle(linked); } }
            foreach ((string sid, string name) in AdminEquivalentBuiltin)
                if (sids.Contains(sid)) matched.Add($"{name} ({sid})");
            foreach (string local in new[] { "docker-users" })
                try { var s = ((SecurityIdentifier)new NTAccount(Environment.MachineName, local).Translate(typeof(SecurityIdentifier))).Value; if (sids.Contains(s)) matched.Add($"{local} ({s})"); }
                catch { /* group not present on this host */ }
        }
        catch { /* best effort */ }
        return matched;
    }

    private static IntPtr LinkedToken(IntPtr token)
    {
        if (!Interop.Native.GetTokenInformation(token, Interop.Native.TokenLinkedToken, IntPtr.Zero, 0, out int len) && len <= 0) return IntPtr.Zero;
        IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(Math.Max(len, IntPtr.Size));
        try { return Interop.Native.GetTokenInformation(token, Interop.Native.TokenLinkedToken, buf, Math.Max(len, IntPtr.Size), out _) ? System.Runtime.InteropServices.Marshal.ReadIntPtr(buf) : IntPtr.Zero; }
        finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
    }

    /// <summary>Does the token's linked (elevation-paired) token contain Administrators? True for a
    /// filtered-admin process; false/absent for a genuine standard user.</summary>
    private static bool LinkedTokenIsAdmin(IntPtr token)
    {
        if (!Interop.Native.GetTokenInformation(token, Interop.Native.TokenLinkedToken, IntPtr.Zero, 0, out int len) && len <= 0) return false;
        IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(Math.Max(len, IntPtr.Size));
        IntPtr linked = IntPtr.Zero;
        try
        {
            if (!Interop.Native.GetTokenInformation(token, Interop.Native.TokenLinkedToken, buf, Math.Max(len, IntPtr.Size), out _)) return false;
            linked = System.Runtime.InteropServices.Marshal.ReadIntPtr(buf);
            if (linked == IntPtr.Zero) return false;
            using var id = new WindowsIdentity(linked);
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
        finally { if (linked != IntPtr.Zero) Interop.Native.CloseHandle(linked); System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
    }

    private static object? ReadHklm(string subkey, string name)
    {
        try { using RegistryKey? k = Registry.LocalMachine.OpenSubKey(subkey); return k?.GetValue(name); }
        catch { return null; }
    }
}
