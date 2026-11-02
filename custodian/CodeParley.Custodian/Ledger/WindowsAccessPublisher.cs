using System.Security.AccessControl;
using System.Security.Principal;

namespace CodeParley.Custodian.Ledger;

/// <summary>Phase 5 (§4.1): the Windows ACL model of the export directories and the repository-readers check, moved
/// verbatim from the ledger (P3.4C-5 §3.2, Increment 4) behind the core's <see cref="Platform.Access"/> seam.</summary>
internal sealed class WindowsAccessPublisher : IAccessPublisher
{
    /// <summary>Create the ticket directory with a protected DACL: SYSTEM, Administrators and the custodian full control,
    /// the helper read-and-execute only.</summary>
    public string CreateExportDirectory(string name, Principal helper)
    {
        var dir = new DirectoryInfo(name);
        dir.Create(Sec(new SecurityIdentifier(helper.Id)));
        return dir.FullName;
    }

    /// <summary>Drop the helper's access (publication): the same DACL without the helper ACE, propagated to the children.
    /// Returns whether every published file (the first 64 checked) then grants exactly SYSTEM, Administrators and the
    /// custodian — the helper nothing.</summary>
    public bool Seal(string path, Principal helperPrincipal)
    {
        _ = new SecurityIdentifier(helperPrincipal.Id);
        new DirectoryInfo(path).SetAccessControl(Sec(null));
        var allowed = new HashSet<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null), new(WellKnownSidType.BuiltinAdministratorsSid, null), WindowsIdentity.GetCurrent().User!,
        };
        foreach (string f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Take(64))
            foreach (FileSystemAccessRule r in new FileInfo(f).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (r.AccessControlType == AccessControlType.Allow && !allowed.Contains((SecurityIdentifier)r.IdentityReference)) return false;
        return true;
    }

    /// <summary>
    /// P3.4C-5 (§3.2): publish a ticket directory to the bound session's user: a protected DACL granting SYSTEM and the
    /// custodian full control and <paramref name="reader"/> read-and-execute — nobody else, and the helper nothing — on the
    /// directory and, because the sealed export carries its own protected DACL, on its <c>export</c> too; the files inherit
    /// it. The implementer can then read the export and the capture record, and cannot create, change, rename or delete
    /// anything in it. Verified on the published files (the first 256): only those three grant anything, and the reader
    /// holds no write-like right.
    /// </summary>
    public void Publish(string path, Principal readerPrincipal)
    {
        var reader = new SecurityIdentifier(readerPrincipal.Id);
        DirectorySecurity sec = PublicationSec(reader);
        new DirectoryInfo(path).SetAccessControl(sec);
        string export = Path.Combine(path, "export");
        if (Directory.Exists(export)) new DirectoryInfo(export).SetAccessControl(PublicationSec(reader));
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier self = WindowsIdentity.GetCurrent().User!;
        const FileSystemRights WriteLike = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes
            | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (string f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Take(256))
            foreach (FileSystemAccessRule r in new FileInfo(f).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (r.AccessControlType != AccessControlType.Allow) continue;
                var who = (SecurityIdentifier)r.IdentityReference;
                if (who == system || who == self) continue;
                if (who != reader || (r.FileSystemRights & WriteLike) != 0)
                    throw new InvalidOperationException($"a published file grants {who.Value} more than the publication allows ({r.FileSystemRights})");
            }
    }

    private static DirectorySecurity PublicationSec(SecurityIdentifier reader)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags Both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        if (reader != WindowsIdentity.GetCurrent().User) sec.AddAccessRule(new FileSystemAccessRule(reader, FileSystemRights.ReadAndExecute, Both, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }

    public string? RepositoryReadersProblem(string root, Principal readersPrincipal)
    {
        var readers = new System.Security.Principal.SecurityIdentifier(readersPrincipal.Id);
        System.Security.AccessControl.AuthorizationRuleCollection rules;
        try { rules = new DirectoryInfo(root).GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)); }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException) { return $"its access control list cannot be read: {e.GetType().Name}"; }
        const System.Security.AccessControl.FileSystemRights Need = System.Security.AccessControl.FileSystemRights.ReadAndExecute;
        const System.Security.AccessControl.InheritanceFlags Both = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
        bool denied = false, granted = false;
        foreach (System.Security.AccessControl.FileSystemAccessRule r in rules)
        {
            if (!r.IdentityReference.Equals(readers) || (r.FileSystemRights & Need) == 0) continue;
            if (r.AccessControlType == System.Security.AccessControl.AccessControlType.Deny) denied = true;
            else if ((r.FileSystemRights & Need) == Need && (r.InheritanceFlags & Both) == Both && (r.PropagationFlags & System.Security.AccessControl.PropagationFlags.InheritOnly) == 0) granted = true;
        }
        return denied ? "an ACE denies it read access" : granted ? null : "no ACE grants it read and execute, inherited by files and folders";
    }

    public string RepositoryReadersRemedy(string root, Principal readers)
        => $"the operator grants it on the repository only: `icacls \"{root}\" /grant \"*{readers.Id}:(OI)(CI)(RX)\"` (no ACE is added on any parent folder or the user profile)";

    private static DirectorySecurity Sec(SecurityIdentifier? helper)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags Both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        if (helper is not null) sec.AddAccessRule(new FileSystemAccessRule(helper, FileSystemRights.ReadAndExecute, Both, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }
}
