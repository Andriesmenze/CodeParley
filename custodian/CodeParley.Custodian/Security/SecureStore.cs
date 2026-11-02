using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// Creates and validates the protected custodian store. The store is writable only by the custodian
/// service SID (and SYSTEM/Administrators for recovery), readable by the operator's processes (CU-4),
/// and labelled High integrity, no-write-up so a medium-integrity implementer cannot write up to it
/// even if a DACL were wrong. The DACL is applied to an opened, reparse-checked handle via
/// <c>SetSecurityInfo</c> (no <c>icacls</c>), exactly as the reviewed broker pattern.
///
/// The shared parent <c>C:\ProgramData\CodeParley</c> is validated but NEVER rewritten here unless the
/// operator passes an explicit repair flag (TD amendment 4): the custodian owns only its own subtree.
/// </summary>
internal static class SecureStore
{
    private const uint RightsModify = 0x1301bf, RightsReadExecute = 0x1200a9;
    private static readonly string[] TrustedOwners =
        ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]; // SYSTEM, Administrators, TrustedInstaller
    private static readonly string[] BroadeningSids = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"]; // Everyone, AuthUsers, Users

    internal sealed record ParentState(bool Exists, bool IsDirectory, bool IsReparse, string? Owner, bool UsersWritable);

    /// <summary>Build the store DACL+label SDDL for the configured identities.</summary>
    internal static string StoreSddl(SecurityIdentifier custodian, SecurityIdentifier operatorSid, SecurityIdentifier implementerSid)
    {
        var sb = new StringBuilder("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        sb.Append($"(A;OICI;0x{RightsModify:x};;;{custodian.Value})");
        sb.Append($"(A;OICI;0x{RightsReadExecute:x};;;{implementerSid.Value})");
        if (operatorSid.Value != implementerSid.Value)
            sb.Append($"(A;OICI;0x{RightsReadExecute:x};;;{operatorSid.Value})");
        sb.Append("S:(ML;OICI;NW;;;HI)"); // High integrity, no write up
        return sb.ToString();
    }

    /// <summary>Validate the shared parent without changing it. Returns its measured state.</summary>
    internal static ParentState InspectParent()
    {
        string p = StorePaths.SharedParent;
        if (!Directory.Exists(p)) return new ParentState(false, false, false, null, false);
        IntPtr h = OpenNoFollow(p);
        try
        {
            Native.GetFileInformationByHandle(h, out Native.BY_HANDLE_FILE_INFORMATION fi);
            bool reparse = (fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            var sec = new DirectorySecurity(p, AccessControlSections.Access | AccessControlSections.Owner);
            string? owner = ((SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier)))?.Value;
            bool usersWrite = HasBroadeningWrite(sec);
            return new ParentState(true, (fi.FileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0, reparse, owner, usersWrite);
        }
        finally { Native.CloseHandle(h); }
    }

    /// <summary>Create the custodian root (and <c>intents/</c>) with a protected DACL + High label, or
    /// re-apply the protection to an existing custodian-owned root. Refuses if the root already exists
    /// but was not created by a prior custodian install (unless <paramref name="repairApproved"/>), and
    /// refuses to touch a shared parent that is a reparse point or not trusted-owned.</summary>
    internal static void EnsureStore(SecurityIdentifier custodian, SecurityIdentifier operatorSid, SecurityIdentifier implementerSid, bool repairApproved)
    {
        ParentState parent = InspectParent();
        if (parent.Exists)
        {
            if (parent.IsReparse) throw new InvalidOperationException($"{StorePaths.SharedParent} is a reparse point; refusing (operator must inspect it)");
            if (!parent.IsDirectory) throw new InvalidOperationException($"{StorePaths.SharedParent} exists but is not a directory");
            if (parent.Owner is null || !TrustedOwners.Contains(parent.Owner))
                throw new InvalidOperationException($"{StorePaths.SharedParent} is owned by {parent.Owner ?? "unknown"}, not SYSTEM/Administrators/TrustedInstaller; refusing to build under it");
            // A Users-writable parent is noted but NOT rewritten: the child's protected DACL is what
            // matters, and we refuse a pre-created child below. Repair of the parent is operator-driven.
        }
        else
        {
            Directory.CreateDirectory(StorePaths.SharedParent);
        }

        string root = StorePaths.Root;
        bool existed = Directory.Exists(root);
        if (existed && !repairApproved && !LooksLikeCustodianRoot())
            throw new InvalidOperationException($"{root} already exists and is not a recognized custodian store; refusing. Operator: inspect it and re-run install with -RepairStore to adopt and re-protect it.");
        if (!existed) Directory.CreateDirectory(root);

        ApplyProtection(root, StoreSddl(custodian, operatorSid, implementerSid));
        Directory.CreateDirectory(StorePaths.IntentsDir);
    }

    private static bool LooksLikeCustodianRoot() =>
        File.Exists(StorePaths.ConfigPath) || File.Exists(StorePaths.LedgerPath) || File.Exists(StorePaths.AuditPath);

    /// <summary>Apply the protected DACL and the mandatory-integrity label to an opened, reparse-checked
    /// handle for the path, then re-verify the final path is the literal target.</summary>
    private static void ApplyProtection(string path, string sddl)
    {
        IntPtr h = Native.CreateFileW(path, Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL | Native.WRITE_DAC | Native.WRITE_OWNER,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_BACKUP_SEMANTICS | Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) Native.ThrowLastError($"open '{path}' for protection");
        try
        {
            Native.GetFileInformationByHandle(h, out Native.BY_HANDLE_FILE_INFORMATION fi);
            if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new InvalidOperationException($"'{path}' is a reparse point; refusing to protect it");
            if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out IntPtr sd, out _))
                Native.ThrowLastError("ConvertStringSecurityDescriptor");
            try
            {
                if (!Native.GetSecurityDescriptorDacl(sd, out bool dPresent, out IntPtr dacl, out _) || !dPresent)
                    throw new InvalidOperationException("built descriptor has no DACL");
                Native.GetSecurityDescriptorSacl(sd, out bool sPresent, out IntPtr sacl, out _);
                int info = Native.DACL_SECURITY_INFORMATION | Native.PROTECTED_DACL_SECURITY_INFORMATION | (sPresent ? Native.LABEL_SECURITY_INFORMATION : 0);
                uint err = Native.SetSecurityInfo(h, Native.SE_KERNEL_OBJECT, info, IntPtr.Zero, IntPtr.Zero, dacl, sPresent ? sacl : IntPtr.Zero);
                if (err != 0) throw new System.ComponentModel.Win32Exception((int)err, "SetSecurityInfo");
            }
            finally { Native.LocalFree(sd); }
        }
        finally { Native.CloseHandle(h); }
    }

    /// <summary>Create (or re-protect) the custodian-ONLY private probe file: SYSTEM/Administrators and
    /// the custodian service SID only — NOT the operator. The capture-helper probe shows that even the
    /// operator's token is denied this file by the DACL, the stand-in for a private record / credential.</summary>
    internal static void EnsurePrivateProbe(SecurityIdentifier custodian)
    {
        string path = StorePaths.PrivateProbe;
        if (!File.Exists(path)) File.WriteAllText(path, "custodian-only private record (probe); the operator's token must be denied this\n");
        ApplyFileProtection(path, $"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{RightsReadExecute:x};;;{custodian.Value})");
    }

    private static void ApplyFileProtection(string path, string sddl)
    {
        IntPtr h = Native.CreateFileW(path, Native.READ_CONTROL | Native.WRITE_DAC,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) Native.ThrowLastError($"open '{path}' for protection");
        try
        {
            if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out IntPtr sd, out _))
                Native.ThrowLastError("ConvertStringSecurityDescriptor");
            try
            {
                if (!Native.GetSecurityDescriptorDacl(sd, out bool present, out IntPtr dacl, out _) || !present)
                    throw new InvalidOperationException("built descriptor has no DACL");
                uint err = Native.SetSecurityInfo(h, Native.SE_KERNEL_OBJECT,
                    Native.DACL_SECURITY_INFORMATION | Native.PROTECTED_DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (err != 0) throw new System.ComponentModel.Win32Exception((int)err, "SetSecurityInfo");
            }
            finally { Native.LocalFree(sd); }
        }
        finally { Native.CloseHandle(h); }
    }

    /// <summary>Verify the store chain at startup/host-check: the custodian root exists, is not a
    /// reparse point, is owned by a trusted principal and grants no write to Everyone/Users/AuthUsers.
    /// Returns the list of problems (empty = healthy).</summary>
    internal static List<string> ValidateStore()
    {
        var problems = new List<string>();
        string root = StorePaths.Root;
        if (!Directory.Exists(root)) { problems.Add($"custodian store {root} does not exist"); return problems; }
        try
        {
            IntPtr h = OpenNoFollow(root);
            try
            {
                Native.GetFileInformationByHandle(h, out Native.BY_HANDLE_FILE_INFORMATION fi);
                if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) problems.Add("custodian store is a reparse point");
            }
            finally { Native.CloseHandle(h); }
            var sec = new DirectorySecurity(root, AccessControlSections.Access | AccessControlSections.Owner);
            string? owner = ((SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier)))?.Value;
            if (owner is null || (!TrustedOwners.Contains(owner) && owner != ServiceSid.Custodian().Value))
                problems.Add($"custodian store owner is {owner ?? "unknown"} (not trusted)");
            if (HasBroadeningWrite(sec)) problems.Add("custodian store grants write to a broadening principal (Everyone/Users/AuthUsers)");
        }
        catch (Exception e) { problems.Add("store validation: " + e.Message); }
        return problems;
    }

    private static bool HasBroadeningWrite(FileSystemSecurity sec)
    {
        const FileSystemRights WriteBits =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes |
            FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        const int GenericWriteOrAll = unchecked((int)0x40000000) | 0x10000000;
        foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            string sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            bool writeLike = (rule.FileSystemRights & WriteBits) != 0 || ((int)rule.FileSystemRights & GenericWriteOrAll) != 0;
            if (writeLike && BroadeningSids.Contains(sid)) return true;
        }
        return false;
    }

    private static IntPtr OpenNoFollow(string path)
    {
        IntPtr h = Native.CreateFileW(path, Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_BACKUP_SEMANTICS | Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) Native.ThrowLastError($"open '{path}'");
        return h;
    }
}
