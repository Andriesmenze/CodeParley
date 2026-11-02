using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// A repository's identity as the custodian itself establishes it (P3.4C-0, TD decision 3): the
/// <c>FILE_ID_INFO</c> (64-bit volume serial number + 128-bit file id) of the repository's root
/// directory, read from a handle the custodian opens with its OWN token by a no-follow walk from the
/// volume root. The client's path is only a locator: no client-computed key is ever trusted, and the
/// identity is the same for every supported spelling of the same directory (letter case, separators,
/// a trailing separator, an 8.3 short name), while a spelling that could name a different object
/// depending on how it is resolved — a link, junction or mount point in ANY component, a substituted,
/// mapped or network drive, <c>.</c>/<c>..</c>, a trailing dot or space, UNC/device/<c>\\?\</c> forms,
/// a non-NTFS/ReFS volume — is REFUSED rather than guessed.
///
/// The identity binds the directory OBJECT, not its content (a same-user implementer can always change
/// the files of its own repository; binding reviews to content is the Phase 2 source evidence). A grant
/// therefore follows the directory through a rename on the same volume, and does not survive its
/// replacement (a deleted and recreated directory gets a new file id; NTFS also stamps a reused MFT
/// record with a new sequence number).
/// </summary>

internal static class WindowsRepoIdentities
{
    /// <summary>The scheme of every key this custodian derives. A ledger key without this prefix is a
    /// legacy (pre-P3.4C-0) textual key: it is never matched against a resolved identity and never
    /// reinterpreted as one.</summary>
    internal const string Scheme = "fid1";

    internal const string RefusedPrefix = RepoIdentities.RefusedPrefix;

    private const int MaxPathChars = 1024;
    private const uint ShareAll = Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE;

    internal static bool IsCurrent(string? repoKey) => repoKey is not null && repoKey.StartsWith(Scheme + "-", StringComparison.Ordinal);

    /// <summary>The access the walk requests (root, each intermediate component, the final component).
    /// Production uses <see cref="Production"/>; only the identity self-test probes other masks.</summary>
    internal readonly record struct WalkAccess(string Name, uint Root, uint Intermediate, uint Final);

    /// <summary>Only <c>FILE_READ_ATTRIBUTES</c> on every component (asynchronous handles, no
    /// <c>SYNCHRONIZE</c>): the walk needs each directory only as the root of the next relative open
    /// (traversal is the bypass-traverse privilege every token, the custodian's included, holds) and the
    /// identity queries need only this right. NTFS also grants it implicitly to a caller that may list the
    /// parent directory, so the custodian needs no right to READ the repository to establish its identity.
    /// Measured on Windows (self-test-identity part C): a zero-access open is refused even to the owner.</summary>
    internal static readonly WalkAccess Production = new("read-attributes", Native.FILE_READ_ATTRIBUTES, Native.FILE_READ_ATTRIBUTES_NT, Native.FILE_READ_ATTRIBUTES_NT);

    /// <summary>Resolve the identity of the directory <paramref name="repositoryRoot"/> names.
    /// Throws <see cref="ArgumentException"/> (INVALID_ARGUMENT, message prefixed
    /// <see cref="RefusedPrefix"/>) for every refused form and every failure.</summary>
    internal static RepoIdentity Resolve(string repositoryRoot) => Resolve(repositoryRoot, Production);

    internal static RepoIdentity Resolve(string repositoryRoot, WalkAccess access)
    {
        (string drive, string[] components) = Parse(repositoryRoot);
        IntPtr root = OpenVolumeRoot(drive, access.Root, out string fileSystem);
        var open = new List<IntPtr> { root };
        try
        {
            IntPtr cur = root;
            for (int i = 0; i < components.Length; i++)
            {
                bool last = i == components.Length - 1;
                cur = OpenChildDirectory(cur, components[i], last ? access.Final : access.Intermediate);
                open.Add(cur);
            }
            return Identify(cur, drive, fileSystem);
        }
        finally
        {
            for (int i = open.Count - 1; i >= 0; i--) Native.CloseHandle(open[i]);
        }
    }

    // ---- the path is a locator: strict syntax, refused rather than normalized ----

    private static readonly char[] ForbiddenChars = ['<', '>', ':', '"', '|', '?', '*'];

    private static readonly HashSet<string> DosDevices = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM\u00B9", "COM\u00B2", "COM\u00B3",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT\u00B9", "LPT\u00B2", "LPT\u00B3",
    };

    internal static (string Drive, string[] Components) Parse(string input)
    {
        if (string.IsNullOrEmpty(input)) throw Refused("the repository path is empty");
        if (input.Length > MaxPathChars) throw Refused($"the repository path is longer than {MaxPathChars} characters");
        string p = input.Replace('/', '\\');
        if (p.StartsWith(@"\\", StringComparison.Ordinal))
            throw Refused(@"UNC, device and \\?\ paths are not supported; use the repository's local drive-letter path (X:\...)");
        if (p.Length < 3 || !char.IsAsciiLetter(p[0]) || p[1] != ':' || p[2] != '\\')
            throw Refused(@"the repository path must be an absolute local drive-letter path (X:\...)");
        string drive = char.ToUpperInvariant(p[0]) + @":\";
        string rest = p[3..];
        if (rest.EndsWith('\\')) rest = rest[..^1]; // one trailing separator is the same directory
        if (rest.Length == 0) return (drive, []);
        string[] parts = rest.Split('\\');
        foreach (string c in parts) ValidateComponent(c);
        return (drive, parts);
    }

    private static void ValidateComponent(string c)
    {
        if (c.Length == 0) throw Refused("the path has an empty component");
        if (c is "." or "..") throw Refused($"the path has a '{c}' component (traversal is refused, not resolved)");
        if (c.Length > 255) throw Refused("a path component is longer than 255 characters");
        if (c.EndsWith('.') || c.EndsWith(' ')) throw Refused($"the component '{c}' ends with a dot or a space (Windows would rewrite it to another name)");
        foreach (char ch in c)
            if (ch < 0x20 || Array.IndexOf(ForbiddenChars, ch) >= 0) throw Refused($"the component '{c}' contains a character that is not allowed (a stream, wildcard or control character)");
        if (DosDevices.Contains(c.Split('.')[0].TrimEnd(' '))) throw Refused($"the component '{c}' is a reserved device name");
    }

    // ---- the walk: the custodian's own handles, no reparse point in any component ----

    internal static IntPtr OpenVolumeRoot(string drive, uint access, out string fileSystem)
    {
        uint type = Native.GetDriveTypeW(drive);
        if (type != Native.DRIVE_FIXED) throw Refused($"{drive} is not a fixed local drive (drive type {type}); removable, network, optical and RAM drives are not supported");
        IntPtr h = Native.CreateFileW(drive, access, ShareAll, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_BACKUP_SEMANTICS | Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) throw Refused($"the volume root {drive} cannot be opened ({Win32Text(Marshal.GetLastWin32Error())})");
        try
        {
            // A drive letter that is a DOS-device alias (subst, or a drive mapped to a folder) resolves to
            // a different final path than its own root; only a real volume root is accepted.
            string final = FinalPath(h);
            if (!string.Equals(final.EndsWith('\\') ? final : final + "\\", drive, StringComparison.OrdinalIgnoreCase))
                throw Refused($"{drive} resolves to '{final}': a substituted or redirected drive letter is not supported; use the real path");
            fileSystem = FileSystemOf(h);
            if (fileSystem is not ("NTFS" or "ReFS")) throw Refused($"{drive} is a {fileSystem} volume; only NTFS and ReFS give a directory a stable identity");
            return h;
        }
        catch { Native.CloseHandle(h); throw; }
    }

    /// <summary>Open one directory name relative to its parent's handle. <c>OBJ_DONT_REPARSE</c> fails the
    /// open on ANY reparse point (symbolic link, junction, mount point, cloud placeholder…); a relative
    /// open resolves no path string, so a concurrent rename of an already-opened component cannot redirect
    /// the next step.</summary>
    internal static IntPtr OpenChildDirectory(IntPtr parent, string name, uint access)
    {
        IntPtr namePtr = Marshal.StringToHGlobalUni(name);
        IntPtr usPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.UNICODE_STRING>());
        try
        {
            var us = new Native.UNICODE_STRING { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = namePtr };
            Marshal.StructureToPtr(us, usPtr, false);
            var oa = new Native.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<Native.OBJECT_ATTRIBUTES>(),
                RootDirectory = parent,
                ObjectName = usPtr,
                Attributes = Native.OBJ_CASE_INSENSITIVE | Native.OBJ_DONT_REPARSE,
            };
            // Synchronous I/O needs SYNCHRONIZE; with no access right requested the handle is used only as
            // the next open's root and for queries, so it is opened without the synchronous option.
            uint options = Native.FILE_DIRECTORY_FILE | ((access & Native.SYNCHRONIZE) != 0 ? Native.FILE_SYNCHRONOUS_IO_NONALERT : 0);
            int status = Native.NtCreateFile(out IntPtr handle, access, ref oa, out _, IntPtr.Zero, 0, ShareAll, Native.FILE_OPEN, options, IntPtr.Zero, 0);
            if (status != 0) throw Refused($"'{name}': {StatusText(status)}");
            return handle;
        }
        finally
        {
            Marshal.FreeHGlobal(usPtr);
            Marshal.FreeHGlobal(namePtr);
        }
    }

    private static RepoIdentity Identify(IntPtr dir, string drive, string fileSystem)
    {
        // The final component must be a plain directory (OBJ_DONT_REPARSE already refused a reparse point
        // in the open; this re-checks it from the handle).
        IntPtr buf = Marshal.AllocHGlobal(24);
        try
        {
            if (!Native.GetFileInformationByHandleEx(dir, Native.FileAttributeTagInfo, buf, 8))
                throw Refused($"the directory's attributes cannot be read ({Win32Text(Marshal.GetLastWin32Error())})");
            uint attrs = (uint)Marshal.ReadInt32(buf);
            if ((attrs & Native.FILE_ATTRIBUTE_DIRECTORY) == 0) throw Refused("the repository root is not a directory");
            if ((attrs & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) throw Refused("the repository root is a reparse point");

            if (!Native.GetFileInformationByHandleEx(dir, Native.FileIdInfo, buf, 24))
                throw Refused($"the directory's file id cannot be read ({Win32Text(Marshal.GetLastWin32Error())})");
            ulong volumeSerial = (ulong)Marshal.ReadInt64(buf);
            byte[] fileId = new byte[16];
            Marshal.Copy(buf + 8, fileId, 0, 16);
            if (volumeSerial == 0 || fileId.All(b => b == 0)) throw Refused("the volume reports no stable file id for this directory");

            string canonical = FinalPath(dir);
            if (!canonical.StartsWith(drive, StringComparison.OrdinalIgnoreCase))
                throw Refused($"the directory resolves to '{canonical}', outside {drive}");
            string key = $"{Scheme}-{volumeSerial:x16}-{Convert.ToHexString(fileId).ToLowerInvariant()}";
            return new RepoIdentity(key, canonical, fileSystem);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    internal static string FinalPath(IntPtr handle)
    {
        var sb = new StringBuilder(512);
        uint n = Native.GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, Native.FILE_NAME_NORMALIZED | Native.VOLUME_NAME_DOS);
        if (n > sb.Capacity)
        {
            sb = new StringBuilder((int)n + 1);
            n = Native.GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, Native.FILE_NAME_NORMALIZED | Native.VOLUME_NAME_DOS);
        }
        if (n == 0) throw Refused($"the final path cannot be read ({Win32Text(Marshal.GetLastWin32Error())})");
        string p = sb.ToString();
        return p.StartsWith(@"\\?\", StringComparison.Ordinal) && !p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? p[4..] : p;
    }

    private static string FileSystemOf(IntPtr root)
    {
        var fs = new StringBuilder(64);
        if (!Native.GetVolumeInformationByHandleW(root, null, 0, out _, out _, out _, fs, (uint)fs.Capacity))
            throw Refused($"the volume's file system cannot be read ({Win32Text(Marshal.GetLastWin32Error())})");
        return fs.ToString();
    }

    internal static string StatusText(int status) => status switch
    {
        Native.STATUS_REPARSE_POINT_ENCOUNTERED or Native.STATUS_STOPPED_ON_SYMLINK =>
            "it is a symbolic link, junction or mount point (no component may be a link)",
        Native.STATUS_OBJECT_NAME_NOT_FOUND or Native.STATUS_OBJECT_PATH_NOT_FOUND => "it does not exist",
        Native.STATUS_NOT_A_DIRECTORY => "it is not a directory",
        Native.STATUS_ACCESS_DENIED => "the custodian is denied access to it",
        Native.STATUS_OBJECT_NAME_INVALID => "it is not a valid name",
        _ => $"{Win32Text(Native.RtlNtStatusToDosError(status))} (NTSTATUS 0x{status:X8})",
    };

    private static string Win32Text(int error) => $"{new Win32Exception(error).Message} ({error})";

    private static RepoIdentityRefused Refused(string why) => new(RefusedPrefix + why);
}

/// <summary>Phase 5 (§4.1): the Windows repository identity behind the core's <see cref="RepoIdentities"/> seam.</summary>
internal sealed class WindowsRepoIdentityResolver : IRepoIdentityResolver
{
    public string Scheme => WindowsRepoIdentities.Scheme;
    public RepoIdentity Resolve(string repositoryRoot) => WindowsRepoIdentities.Resolve(repositoryRoot);
}
