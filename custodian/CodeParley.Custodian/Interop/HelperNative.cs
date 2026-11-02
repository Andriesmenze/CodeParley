using System.Runtime.InteropServices;

namespace CodeParley.Custodian.Interop;

/// <summary>
/// P3.4C-5 (contract §2.2): Win32 interop for the custodian helper — a primary token's integrity, process creation
/// with that token and an explicit inherited-handle list, the job object that contains the helper, and the private
/// window station and desktop it may run on. Signatures, constants and structs only.
/// </summary>
internal static class HelperNative
{
    private const CharSet U = CharSet.Unicode;

    // ---- token ----
    internal const uint SE_GROUP_INTEGRITY = 0x20, SE_GROUP_LOGON_ID = 0xC0000000, SE_GROUP_ENABLED = 0x4, SE_GROUP_USE_FOR_DENY_ONLY = 0x10;
    internal const int TokenUser = 1, TokenDefaultDacl = 6;

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL { public Native.SID_AND_ATTRIBUTES Label; }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length);

    [DllImport("advapi32.dll")] internal static extern int GetLengthSid(IntPtr sid);

    // ---- process creation ----
    internal const uint CREATE_SUSPENDED = 0x4, CREATE_NO_WINDOW = 0x08000000, CREATE_UNICODE_ENVIRONMENT = 0x400,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000, CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
    internal const int STARTF_USESTDHANDLES = 0x100, STARTF_USESHOWWINDOW = 0x1;
    internal static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x20002;

    [StructLayout(LayoutKind.Sequential, CharSet = U)]
    internal struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessAsUserW(IntPtr token, string? application, System.Text.StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory,
        ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);

    [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(IntPtr process, uint exitCode);
    internal const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 0x102, INFINITE = 0xFFFFFFFF;

    // ---- pipes and handles ----
    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SECURITY_ATTRIBUTES attributes, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    internal const uint HANDLE_FLAG_INHERIT = 0x1;

    // ---- job object ----
    internal const int JobObjectBasicUIRestrictions = 4, JobObjectExtendedLimitInformation = 9;
    internal const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8, JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100, JOB_OBJECT_LIMIT_JOB_TIME = 0x4,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400;
    internal const uint JOB_OBJECT_UILIMIT_ALL = 0xFF;

    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_BASIC_UI_RESTRICTIONS { public uint UIRestrictionsClass; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)] internal static extern IntPtr CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    // ---- private window station and desktop ----
    internal const uint WINSTA_ALL_ACCESS = 0x37F, WINSTA_CREATEDESKTOP = 0x8, DESKTOP_ALL_ACCESS = 0x1FF, GENERIC_ALL = 0x10000000, GENERIC_READ = 0x80000000;
    internal const int SE_WINDOW_OBJECT = 7, UOI_NAME = 2;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetUserObjectInformationW(IntPtr obj, int index, IntPtr info, int length, out int needed);

    [DllImport("user32.dll", SetLastError = true, CharSet = U)] internal static extern IntPtr CreateWindowStationW(string? name, uint flags, uint access, IntPtr attributes);
    [DllImport("user32.dll", SetLastError = true)] internal static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetProcessWindowStation(IntPtr winsta);
    [DllImport("user32.dll", SetLastError = true, CharSet = U)] internal static extern IntPtr CreateDesktopW(string name, IntPtr device, IntPtr devmode, uint flags, uint access, IntPtr attributes);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseWindowStation(IntPtr winsta);

    // ---- process access probe ----
    internal const uint PROCESS_VM_WRITE = 0x20, PROCESS_VM_OPERATION = 0x8, PROCESS_TERMINATE = 0x1, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    // ---- AppContainer (P3.4C-5 option A feasibility spike; documented userenv / process-attribute APIs) ----
    internal static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20009;
    internal const int TokenIsAppContainer = 29, TokenCapabilities = 30, TokenAppContainerSid = 31;
    internal const int HRESULT_ALREADY_EXISTS = unchecked((int)0x800700B7);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }

    [DllImport("userenv.dll", CharSet = U)]
    internal static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = U)]
    internal static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = U)]
    internal static extern int DeleteAppContainerProfile(string name);
    [DllImport("userenv.dll", CharSet = U)]
    internal static extern int GetAppContainerFolderPath(string sid, out IntPtr path);
    [DllImport("ole32.dll")] internal static extern void CoTaskMemFree(IntPtr p);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = U)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessW(string? application, System.Text.StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
}
