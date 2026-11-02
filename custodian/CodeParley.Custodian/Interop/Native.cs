using System.Runtime.InteropServices;
using System.Text;

namespace CodeParley.Custodian.Interop;

/// <summary>
/// Win32 interop for the custodian. P/Invoke signatures, constants and structs only — no lifetime or
/// policy. A focused subset of the patterns reviewed in the preserved broker's interop: handle-based
/// no-follow opens, SDDL→SetSecurityInfo DACL/label application, token classification and
/// CreateRestrictedToken for the capture-helper probe.
/// </summary>
internal static class Native
{
    // ---- CreateFile (handle-based no-follow) ----
    internal const uint FILE_READ_ATTRIBUTES = 0x80, READ_CONTROL = 0x20000, WRITE_DAC = 0x40000, WRITE_OWNER = 0x80000, FILE_GENERIC_READ = 0x120089;
    internal const uint OPEN_EXISTING = 3;
    internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    internal const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400, FILE_ATTRIBUTE_DIRECTORY = 0x10;
    internal const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
    internal static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    // ---- SetSecurityInfo ----
    internal const int SE_KERNEL_OBJECT = 6, SE_FILE_OBJECT = 1;
    internal const int DACL_SECURITY_INFORMATION = 0x00000004;
    internal const int LABEL_SECURITY_INFORMATION = 0x00000010;
    internal const int PROTECTED_DACL_SECURITY_INFORMATION = unchecked((int)0x80000000);
    internal const uint SDDL_REVISION_1 = 1;

    // ---- token ----
    internal const uint TOKEN_QUERY = 0x0008, TOKEN_DUPLICATE = 0x0002, TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_IMPERSONATE = 0x0004, TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_GROUPS = 0x0040;
    internal const uint WRITE_RESTRICTED = 0x8, DISABLE_MAX_PRIVILEGE = 0x1;
    internal const int TokenElevationType = 18, TokenIntegrityLevel = 25, TokenLinkedToken = 19;
    internal const int TokenGroups = 2, TokenPrivileges = 3, TokenRestrictedSids = 11;

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    internal const int SecurityImpersonation = 2, TokenPrimary = 1;
    // TOKEN_ELEVATION_TYPE: 1 = default (UAC off / not split), 2 = full (elevated), 3 = limited.
    internal const int TokenElevationTypeFull = 2;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    // ---- ntdll NtCreateFile (component-relative no-follow walk) ----
    // OBJ_DONT_REPARSE makes the object manager FAIL the open if ANY component is a reparse point,
    // and a relative open (RootDirectory = the parent handle) resolves no path string at all, so a
    // concurrent rename/substitution of an already-opened component cannot redirect the next step.
    internal const uint OBJ_INHERIT = 0x2, OBJ_CASE_INSENSITIVE = 0x40, OBJ_DONT_REPARSE = 0x1000;
    internal const uint FILE_OPEN = 1;
    internal const uint FILE_DIRECTORY_FILE = 0x1, FILE_SYNCHRONOUS_IO_NONALERT = 0x20,
        FILE_NON_DIRECTORY_FILE = 0x40, FILE_OPEN_REPARSE_POINT_NT = 0x200000, FILE_OPEN_FOR_BACKUP_INTENT = 0x4000;
    internal const uint SYNCHRONIZE = 0x100000, FILE_LIST_DIRECTORY = 0x1, FILE_READ_DATA = 0x1,
        FILE_READ_ATTRIBUTES_NT = 0x80, FILE_TRAVERSE = 0x20;

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES
    {
        public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK { public IntPtr StatusPointer; public IntPtr Information; }

    // Pack = 4: the native struct packs a DWORD then three FILETIMEs (each two DWORDs) with no
    // padding; the default x64 alignment would insert 4 bytes after the first DWORD and misalign
    // every field after it (NumberOfLinks included).
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes; public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    private const CharSet U = CharSet.Unicode;

    // ---------- advapi32 ----------
    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetSecurityDescriptorDacl(IntPtr sd, [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetSecurityDescriptorSacl(IntPtr sd, [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr sacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint SetSecurityInfo(IntPtr handle, int objectType, int secInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount, [In] SID_AND_ATTRIBUTES[]? sidsToDisable,
        uint deleteCount, IntPtr privsToDelete, uint restrictCount, [In] SID_AND_ATTRIBUTES[]? sidsToRestrict, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DuplicateTokenEx(IntPtr existing, uint desiredAccess, IntPtr attrs, int impLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSidToSidW(string sid, out IntPtr pSid);

    [DllImport("advapi32.dll")] internal static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupPrivilegeNameW(string? systemName, ref LUID luid, System.Text.StringBuilder name, ref int cchName);

    // ---------- kernel32 ----------
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    internal static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flagsAndAttributes, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    internal static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint count, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr p);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    // ---------- repository identity (P3.4C-0): handle-backed directory identity ----------
    internal const int FileAttributeTagInfo = 9, FileIdInfo = 0x12;
    internal const uint DRIVE_FIXED = 3;
    internal const uint FILE_NAME_NORMALIZED = 0x0, VOLUME_NAME_DOS = 0x0;
    internal const uint DDD_RAW_TARGET_PATH = 0x1, DDD_REMOVE_DEFINITION = 0x2, DDD_EXACT_MATCH_ON_REMOVE = 0x4;
    internal const int STATUS_ACCESS_DENIED = unchecked((int)0xC0000022), STATUS_OBJECT_NAME_INVALID = unchecked((int)0xC0000033),
        STATUS_OBJECT_NAME_NOT_FOUND = unchecked((int)0xC0000034), STATUS_OBJECT_PATH_NOT_FOUND = unchecked((int)0xC000003A),
        STATUS_NOT_A_DIRECTORY = unchecked((int)0xC0000103), STATUS_REPARSE_POINT_ENCOUNTERED = unchecked((int)0xC000050B),
        STATUS_STOPPED_ON_SYMLINK = unchecked((int)0x8000002D);

    /// <summary>Self-test only (P3.4C-4 M13): a second hard link to a file.</summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateHardLinkW(string newFileName, string existingFileName, IntPtr securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandleEx(IntPtr handle, int infoClass, IntPtr buffer, uint size);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetVolumeInformationByHandleW(IntPtr handle, StringBuilder? volumeName, uint volumeNameSize,
        out uint serial, out uint maxComponentLength, out uint fileSystemFlags, StringBuilder fileSystemName, uint fileSystemNameSize);
    [DllImport("kernel32.dll", CharSet = U)] internal static extern uint GetDriveTypeW(string rootPathName);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DefineDosDeviceW(uint flags, string deviceName, string? targetPath);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    internal static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, uint size);

    // ---------- P3.4C-2: process facts for the loop-binding check (correlation only, D7) ----------
    internal const int SystemProcessInformation = 5;
    internal const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    // SYSTEM_PROCESS_INFORMATION field offsets on 64-bit Windows (the custodian is published win-x64).
    internal const int SpiNextEntryOffset = 0x00, SpiCreateTime = 0x20, SpiUniqueProcessId = 0x50, SpiInheritedFromProcessId = 0x58;
    // ImageName is a UNICODE_STRING at 0x38: Length (bytes) at 0x38, Buffer (a pointer into the same buffer) at 0x40.
    internal const int SpiImageNameLength = 0x38, SpiImageNameBuffer = 0x40;
    internal const int SpiMinEntrySize = 0x60;

    /// <summary>Snapshot every process (pid, parent pid, creation time) without opening any of them: the
    /// custodian's service account may not open another user's process, and this query needs no access to
    /// the processes it lists.</summary>
    [DllImport("ntdll.dll")]
    internal static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    /// <summary>The process id of a connected named-pipe client, as the system reports it for the connection.
    /// CORRELATION evidence only, never authentication (D7): the custodian does not rely on it being
    /// unforgeable by a same-user client.</summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientProcessId(SafeHandle pipe, out uint clientProcessId);

    // ---------- P3.4C-3: the OS boot identity for recovery (contract §2.4) ----------
    /// <summary>SystemTimeOfDayInformation: the first field of the returned structure is the kernel's boot time (a
    /// FILETIME, UTC) — the value Win32_OperatingSystem.LastBootUpTime reports (equal on the development machine).</summary>
    internal const int SystemTimeOfDayInformation = 3;
    internal const int SystemTimeOfDayInformationSize = 48;

    // ---------- P3.4C-3: the write-through store replacement (contract §2.4) ----------
    internal const uint MOVEFILE_REPLACE_EXISTING = 0x1, MOVEFILE_WRITE_THROUGH = 0x8;

    /// <summary>Replace <paramref name="newName"/> with <paramref name="existing"/> on the same volume. With
    /// <see cref="MOVEFILE_WRITE_THROUGH"/> the call does not return until the move is on the disk.</summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileExW(string existing, string newName, uint flags);

    // ---------- ntdll ----------
    [DllImport("ntdll.dll")]
    internal static extern int NtCreateFile(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES attrs,
        out IO_STATUS_BLOCK iosb, IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);
    [DllImport("ntdll.dll")] internal static extern int RtlNtStatusToDosError(int status);

    internal static void ThrowLastError(string api)
        => throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), api + " failed");
}
