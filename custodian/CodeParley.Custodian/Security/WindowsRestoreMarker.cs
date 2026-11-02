using System.Security.AccessControl;
using System.Security.Principal;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Security;

/// <summary>
/// Phase 6 Increment 2 (L-5): the installer's restore marker on Windows, <c>C:\ProgramData\CodeParley\restore-marker.json</c>
/// — beside the store, never in it. Only an administrator's file is believed: it must be a regular file (not a reparse
/// point) owned by SYSTEM, Administrators or TrustedInstaller that grants no write-like right to anyone else. A marker that
/// fails any of this fails the start: a forged one could only start a needless restored epoch, but one the custodian cannot
/// trust names no restore it can establish (fail closed).
/// </summary>
internal static class WindowsRestoreMarker
{
    private static readonly HashSet<string> TrustedOwners = new(StringComparer.Ordinal)
        { "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" }; // SYSTEM, Administrators, TrustedInstaller

    private const FileSystemRights WriteLike = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
    private const int GenericWriteOrAll = unchecked((int)0x40000000) | 0x10000000;

    internal static string MarkerPath => Path.Combine(StorePaths.SharedParent, RestoreMarkers.FileName);

    /// <summary>The marker, or null when there is none.</summary>
    internal static RestoreMarker? Read() => Read(MarkerPath);

    internal static RestoreMarker? Read(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists && !Directory.Exists(path)) return null;
        string Refuse(string why) => throw new InvalidDataException($"{path} {why}; a restore marker is believed only from an administrator — nothing is served until an administrator repeats `rollback` or removes it (fail closed)");
        if (Directory.Exists(path) || (info.Attributes & FileAttributes.ReparsePoint) != 0) Refuse("is not a regular file");
        FileSecurity sec = info.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        string? owner = ((SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier)))?.Value;
        if (owner is null || !TrustedOwners.Contains(owner)) Refuse($"is owned by {owner ?? "an unknown principal"}, not SYSTEM, Administrators or TrustedInstaller");
        foreach (FileSystemAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (r.AccessControlType != AccessControlType.Allow) continue;
            string sid = ((SecurityIdentifier)r.IdentityReference).Value;
            if (TrustedOwners.Contains(sid)) continue;
            if ((r.FileSystemRights & WriteLike) != 0 || ((int)r.FileSystemRights & GenericWriteOrAll) != 0) Refuse($"grants {sid} write access ({r.FileSystemRights})");
        }
        return RestoreMarkers.Parse(File.ReadAllText(path), path);
    }
}
