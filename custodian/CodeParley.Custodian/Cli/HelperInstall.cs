using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 (§A.1) operator installation of the dedicated helper principal (ELEVATED, run by the operator's install script,
/// never by the model). <c>install-helper</c>:
/// <list type="number">
/// <item>creates the <c>CodeParleyHelper</c> service (demand start) running this executable's <c>helper-service</c> verb under
/// the VIRTUAL account <c>NT SERVICE\CodeParleyHelper</c> (never LocalSystem), with a restricted service SID and
/// <c>SeChangeNotifyPrivilege</c> only;</item>
/// <item>lets the custodian's service SID query and start it (its security descriptor gains exactly that ACE);</item>
/// <item>adds the helper account to <c>CodeParley Repository Readers</c> (the narrow repository read grant, §2.3);</item>
/// <item>creates the export root inside the custodian's own store tree with a protected DACL — SYSTEM, Administrators and
/// the custodian; no write for anyone else, the helper included;</item>
/// <item>records the helper SID in the trusted configuration (the custodian hosts the helper pipe from its next start).</item>
/// </list>
/// No other ACL anywhere is changed: no write grant is given to the helper, and no broad grant to anyone.
/// <c>uninstall-helper</c> removes the service, the group membership and the configured SID (the export root is left for
/// the operator, with whatever it holds).
/// </summary>
internal static class HelperInstall
{
    internal static int Install(string[] args)
    {
        try
        {
            string exe = Environment.ProcessPath ?? throw new InvalidOperationException("cannot resolve the custodian executable path");
            CustodianConfig cfg = CustodianConfig.Load(); // provisioned first (fails closed otherwise)
            SecurityIdentifier helper = ServiceSid.Of(CustodianConstants.HelperServiceName);
            SecurityIdentifier custodian = ServiceSid.Custodian();
            string svc = CustodianConstants.HelperServiceName;

            if (Run("sc.exe", $"query {svc}", out _) == 0)
            {
                if (!args.Contains("--reinstall", StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException($"the service {svc} already exists (pass --reinstall to replace it)");
                Run("sc.exe", $"stop {svc}", out _);
                Thread.Sleep(1500);
                Require(Run("sc.exe", $"delete {svc}", out string del) == 0, "sc delete", del);
                Thread.Sleep(1500);
            }
            Require(Run("sc.exe", $"create {svc} binPath= \"\\\"{exe}\\\" helper-service\" obj= \"{CustodianConstants.HelperVirtualAccount}\" start= demand DisplayName= \"{CustodianConstants.HelperServiceDisplayName}\"", out string create) == 0, "sc create", create);
            Require(Run("sc.exe", $"sidtype {svc} restricted", out string st) == 0, "sc sidtype", st);
            Require(Run("sc.exe", $"privs {svc} SeChangeNotifyPrivilege", out string pv) == 0, "sc privs", pv);

            // The custodian (a restricted service) may query and start the helper; nothing else is added.
            Require(Run("sc.exe", $"sdshow {svc}", out string sddl) == 0, "sc sdshow", sddl);
            string updated = WithStartAce(sddl.Trim(), custodian.Value);
            Require(Run("sc.exe", $"sdset {svc} \"{updated}\"", out string sdset) == 0, "sc sdset", sdset);

            string group = CustodianConstants.RepositoryReadersGroup;
            if (Run("net.exe", $"localgroup \"{group}\"", out _) != 0)
                Require(Run("net.exe", $"localgroup \"{group}\" /add", out string ga) == 0, "create the repository-readers group", ga);
            int add = Run("net.exe", $"localgroup \"{group}\" \"{CustodianConstants.HelperVirtualAccount}\" /add", out string ma);
            Require(add == 0 || ma.Contains("1378", StringComparison.Ordinal) || ma.Contains("already a member", StringComparison.OrdinalIgnoreCase), "add the helper to the repository-readers group", ma);

            EnsureExportRoot(custodian);

            new CustodianConfig
            {
                OperatorSid = cfg.OperatorSid, OperatorAccount = cfg.OperatorAccount,
                ImplementerSid = cfg.ImplementerSid, ImplementerAccount = cfg.ImplementerAccount,
                HelperSid = helper.Value,
            }.Save();

            Console.WriteLine($"installed service '{svc}' as {CustodianConstants.HelperVirtualAccount} (restricted SID {helper.Value}, SeChangeNotifyPrivilege only, demand start) -> {exe} helper-service");
            Console.WriteLine($"custodian {custodian.Value} may query/start it; member of '{group}'; export root {StorePaths.ExportsRoot}");
            Console.WriteLine("restart the custodian service so it hosts the helper pipe");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("install-helper failed: " + e.Message); return 1; }
    }

    internal static int Uninstall(string[] args)
    {
        try
        {
            string svc = CustodianConstants.HelperServiceName;
            Run("sc.exe", $"stop {svc}", out _);
            Thread.Sleep(1000);
            int del = Run("sc.exe", $"delete {svc}", out string delOut);
            Run("net.exe", $"localgroup \"{CustodianConstants.RepositoryReadersGroup}\" \"{CustodianConstants.HelperVirtualAccount}\" /delete", out _);
            if (File.Exists(StorePaths.ConfigPath))
            {
                CustodianConfig cfg = CustodianConfig.Load();
                new CustodianConfig { OperatorSid = cfg.OperatorSid, OperatorAccount = cfg.OperatorAccount, ImplementerSid = cfg.ImplementerSid, ImplementerAccount = cfg.ImplementerAccount }.Save();
            }
            Console.WriteLine(del == 0 ? $"removed service '{svc}', its group membership and the configured helper identity" : $"sc delete {svc}: {delOut.Trim()}");
            Console.WriteLine($"the export root {StorePaths.ExportsRoot} is left in place; restart the custodian service");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("uninstall-helper failed: " + e.Message); return 1; }
    }

    /// <summary>The service SDDL with one more ACE granting <paramref name="sid"/> query-status and start (LCRP), inserted at
    /// the end of the DACL (before any SACL). Idempotent.</summary>
    internal static string WithStartAce(string sddl, string sid)
    {
        string ace = $"(A;;LCRP;;;{sid})";
        if (sddl.Contains(ace, StringComparison.OrdinalIgnoreCase)) return sddl;
        int d = sddl.IndexOf("D:", StringComparison.Ordinal);
        if (d < 0) throw new InvalidOperationException("the helper service's security descriptor has no DACL");
        int s = sddl.IndexOf("S:", d, StringComparison.Ordinal);
        return s < 0 ? sddl + ace : sddl[..s] + ace + sddl[s..];
    }

    /// <summary>The export root (§3.2) under the custodian's own tree: protected, SYSTEM / Administrators / the custodian
    /// full control, nothing for anyone else. The custodian creates each ticket's directory below it with its own DACL.</summary>
    internal static void EnsureExportRoot(SecurityIdentifier custodian)
    {
        var dir = new DirectoryInfo(StorePaths.ExportsRoot);
        if (!dir.Exists) dir.Create();
        if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException($"{dir.FullName} is a reparse point");
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags Both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(custodian, FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(sec);
    }

    private static void Require(bool ok, string what, string output)
    {
        if (!ok) throw new InvalidOperationException($"{what} failed: {output.Trim()}");
    }

    private static int Run(string exe, string arguments, out string output)
    {
        var psi = new ProcessStartInfo(exe, arguments) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        using Process p = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {exe}");
        output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return p.ExitCode;
    }
}
