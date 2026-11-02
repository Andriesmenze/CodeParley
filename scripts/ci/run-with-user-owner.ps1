<#
  CI only, in no release artifact. Runs one custodian self-test with this process's token default owner set to the token's own
  user, then checks that it took. A named pipe created with no explicit owner takes the creator's default owner. On an elevated
  token that is Administrators, not the user, so an in-process pipe (the helper channel's, self-test-serve's) cannot pass the check
  it exists to exercise: owned by the identity that hosts it, as the installed service's pipes are owned by its service SID.

  The self-test inherits the owner through its primary token. Its user, groups, integrity and privileges stay as they are, and
  nothing in the custodian or its pipe validation changes.

    powershell -File run-with-user-owner.ps1 -Exe <custodian executable> -Verb self-test-helper-channel
    powershell -File run-with-user-owner.ps1 -Exe <custodian executable> -Verb self-test-serve --seconds 120
#>
param(
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$Verb,
  [Parameter(ValueFromRemainingArguments)][string[]]$Arguments
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class TokenDefaultOwner
{
    private const int TokenOwner = 4;
    private const uint TokenQuery = 0x0008, TokenAdjustDefault = 0x0080;

    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    private static IntPtr Open(uint access)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), access, out token)) throw new Win32Exception();
        return token;
    }

    public static string Get()
    {
        IntPtr token = Open(TokenQuery), info = IntPtr.Zero;
        try
        {
            int needed;
            GetTokenInformation(token, TokenOwner, IntPtr.Zero, 0, out needed);
            info = Marshal.AllocHGlobal(needed);
            if (!GetTokenInformation(token, TokenOwner, info, needed, out needed)) throw new Win32Exception();
            return new SecurityIdentifier(Marshal.ReadIntPtr(info)).Value;
        }
        finally
        {
            if (info != IntPtr.Zero) Marshal.FreeHGlobal(info);
            CloseHandle(token);
        }
    }

    public static void Set(SecurityIdentifier owner)
    {
        var bytes = new byte[owner.BinaryLength];
        owner.GetBinaryForm(bytes, 0);
        IntPtr token = Open(TokenAdjustDefault), sid = Marshal.AllocHGlobal(bytes.Length), info = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.Copy(bytes, 0, sid, bytes.Length);
            Marshal.WriteIntPtr(info, sid);
            if (!SetTokenInformation(token, TokenOwner, info, IntPtr.Size)) throw new Win32Exception();
        }
        finally
        {
            Marshal.FreeHGlobal(info);
            Marshal.FreeHGlobal(sid);
            CloseHandle(token);
        }
    }
}
'@
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$before = [TokenDefaultOwner]::Get()
[TokenDefaultOwner]::Set($user)
$after = [TokenDefaultOwner]::Get()
if ($after -ne $user.Value) { throw "the token's default owner is $after, not its user $($user.Value)" }
"token user $($user.Value); default owner $before -> $after"
& $Exe $Verb @Arguments
exit $LASTEXITCODE
