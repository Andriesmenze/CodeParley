using System.Runtime.InteropServices;
using System.Text;

namespace CodeParley.Broker.Interop;

/// <summary>
/// Win32 interop for the privileged broker. P/Invoke signatures, constants and structs only; all
/// lifetime/logic lives in the Launch/* and Security/* modules. Handles are raw IntPtr closed by the
/// callers in finally blocks (consistent with the proven spike/.../win-job.cs style). Classic
/// DllImport is used throughout because several Win32 structs carry string fields.
/// </summary>
internal static class Native
{
    // ---- access / logon / token ----
    internal const int LOGON32_LOGON_INTERACTIVE = 2, LOGON32_LOGON_BATCH = 4, LOGON32_PROVIDER_DEFAULT = 0;
    internal const uint TOKEN_ALL_ACCESS = 0xF01FF, TOKEN_QUERY = 0x0008, TOKEN_DUPLICATE = 0x0002;
    internal const uint WRITE_RESTRICTED = 0x8;             // CreateRestrictedToken flag
    internal const uint SE_GROUP_LOGON_ID = 0xC0000000;     // TokenGroups attribute marking the logon SID
    internal const int TokenGroups = 2;
    internal const int SecurityImpersonation = 2, TokenPrimary = 1;

    // ---- CreateProcess flags + stdio redirection ----
    internal const uint CREATE_SUSPENDED = 0x00000004, CREATE_UNICODE_ENVIRONMENT = 0x00000400, CREATE_NO_WINDOW = 0x08000000;
    internal const uint STARTF_USESTDHANDLES = 0x00000100;
    internal const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, CREATE_ALWAYS = 2, FILE_ATTRIBUTE_NORMAL = 0x80;

    // ---- SetSecurityInfo ----
    internal const int SE_KERNEL_OBJECT = 6;
    internal const int DACL_SECURITY_INFORMATION = 0x00000004;
    internal const int PROTECTED_DACL_SECURITY_INFORMATION = unchecked((int)0x80000000);
    internal const uint SDDL_REVISION_1 = 1;

    // ---- CreateFile (handle-based workspace validation) ----
    internal const uint FILE_READ_ATTRIBUTES = 0x80, READ_CONTROL = 0x20000, WRITE_DAC = 0x40000;
    internal const uint OPEN_EXISTING = 3;
    internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    internal const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    internal const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
    internal static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    // ---- Job Object ----
    internal const uint JOB_OBJECT_ASSIGN_PROCESS = 0x0001, JOB_OBJECT_QUERY = 0x0004, JOB_OBJECT_TERMINATE = 0x0008;
    internal const int JobObjectExtendedLimitInformation = 9, JobObjectBasicProcessIdList = 3;
    internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    // ---- window station / desktop ----
    internal const uint WINSTA_ALL_ACCESS = 0x37F, DESKTOP_ALL = 0x1FF;

    // ---- LSA ----
    internal const uint POLICY_CREATE_SECRET = 0x00000020, POLICY_GET_PRIVATE_INFORMATION = 0x00000004;

    // ---- netapi32 ----
    internal const uint UF_SCRIPT = 0x0001, UF_NORMAL_ACCOUNT = 0x0200, UF_DONT_EXPIRE_PASSWD = 0x10000;
    internal const int USER_PRIV_USER = 1, NERR_Success = 0, NERR_UserNotFound = 2221;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFO
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes; public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)] internal struct IO_COUNTERS { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length; public IntPtr RootDirectory, ObjectName, SecurityDescriptor, SecurityQualityOfService;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct PROFILEINFO
    {
        public int dwSize, dwFlags; public string lpUserName;
        public string? lpProfilePath, lpDefaultPath, lpServerName, lpPolicyPath; public IntPtr hProfile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct USER_INFO_1
    {
        public string usri1_name, usri1_password; public uint usri1_password_age, usri1_priv;
        public string? usri1_home_dir, usri1_comment; public uint usri1_flags; public string? usri1_script_path;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct USER_INFO_1003 { public string usri1003_password; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct LOCALGROUP_MEMBERS_INFO_3 { public string lgrmi3_domainandname; }

    private const CharSet U = CharSet.Unicode;

    // ---------- advapi32 ----------
    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LogonUserW(string user, string? domain, IntPtr password, int logonType, int logonProvider, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DuplicateTokenEx(IntPtr existing, uint desiredAccess, IntPtr attrs, int impLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount, IntPtr sidsToDisable,
        uint deleteCount, IntPtr privsToDelete, uint restrictCount, [In] SID_AND_ATTRIBUTES[] sidsToRestrict, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSidToSidW(string sid, out IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetSecurityDescriptorDacl(IntPtr sd, [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint SetSecurityInfo(IntPtr handle, int objectType, int secInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessAsUserW(IntPtr token, string? applicationName, string commandLine, IntPtr processAttrs,
        IntPtr threadAttrs, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment,
        string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInfo);

    [DllImport("advapi32.dll")] internal static extern int LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")] internal static extern int LsaStorePrivateData(IntPtr policy, ref LSA_UNICODE_STRING key, IntPtr data);
    [DllImport("advapi32.dll")] internal static extern int LsaRetrievePrivateData(IntPtr policy, ref LSA_UNICODE_STRING key, out IntPtr data);
    [DllImport("advapi32.dll")] internal static extern int LsaClose(IntPtr policy);
    [DllImport("advapi32.dll")] internal static extern int LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")] internal static extern int LsaNtStatusToWinError(int status);

    // ---------- kernel32 ----------
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    internal static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr buffer, int length, out int returnLength);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    internal static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flagsAndAttributes, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    internal static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint count, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr p);

    // ---------- userenv ----------
    [DllImport("userenv.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LoadUserProfileW(IntPtr token, ref PROFILEINFO profileInfo);
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnloadUserProfile(IntPtr token, IntPtr profile);
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool inherit);
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DestroyEnvironmentBlock(IntPtr env);

    // ---------- netapi32 ----------
    [DllImport("netapi32.dll", CharSet = U)] internal static extern int NetUserAdd(string? server, int level, ref USER_INFO_1 buf, out int paramError);
    [DllImport("netapi32.dll", CharSet = U)] internal static extern int NetUserSetInfo(string? server, string user, int level, ref USER_INFO_1003 buf, out int paramError);
    [DllImport("netapi32.dll", CharSet = U)] internal static extern int NetUserDel(string? server, string user);
    [DllImport("netapi32.dll", CharSet = U)] internal static extern int NetUserGetInfo(string? server, string user, int level, out IntPtr buf);
    [DllImport("netapi32.dll", CharSet = U)] internal static extern int NetLocalGroupAddMembers(string? server, string group, int level, ref LOCALGROUP_MEMBERS_INFO_3 buf, int totalEntries);
    [DllImport("netapi32.dll")] internal static extern int NetApiBufferFree(IntPtr buffer);

    // ---------- user32 ----------
    [DllImport("user32.dll", SetLastError = true, CharSet = U)]
    internal static extern IntPtr CreateWindowStationW(string? name, uint flags, uint access, ref SECURITY_ATTRIBUTES sa);
    [DllImport("user32.dll", SetLastError = true, CharSet = U)]
    internal static extern IntPtr CreateDesktopW(string desktop, string? device, IntPtr devmode, uint flags, uint access, ref SECURITY_ATTRIBUTES sa);
    [DllImport("user32.dll", SetLastError = true)] internal static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetProcessWindowStation(IntPtr winsta);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseWindowStation(IntPtr winsta);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseDesktop(IntPtr desktop);

    internal static void ThrowLastError(string api)
        => throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), api + " failed");
}
