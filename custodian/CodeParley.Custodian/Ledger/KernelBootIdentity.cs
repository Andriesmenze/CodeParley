using System.Runtime.InteropServices;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// The kernel's recorded boot time, read with <c>NtQuerySystemInformation(SystemTimeOfDayInformation)</c> — the value
/// <c>Win32_OperatingSystem.LastBootUpTime</c> reports (VERIFIED equal on the development machine, Windows 11, 2026-10-13;
/// the VM acceptance V11 records both across restarts). It is fixed for a
/// boot (a resume from hibernation or Fast Startup restores it with the kernel's memory) and differs after every cold
/// boot; only an administrator can change the system clock that would move it. Any failure reads as null, which the
/// recovery rule treats as a new boot (fail closed).
/// </summary>
internal sealed class KernelBootIdentity : IBootIdentity
{
    public DateTime? BootTimeUtc()
    {
        IntPtr buffer = Marshal.AllocHGlobal(Native.SystemTimeOfDayInformationSize);
        try
        {
            int status = Native.NtQuerySystemInformation(Native.SystemTimeOfDayInformation, buffer, Native.SystemTimeOfDayInformationSize, out _);
            if (status < 0) return null;
            long fileTime = Marshal.ReadInt64(buffer, 0);
            return fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime) : null;
        }
        catch (Exception e) when (e is not OutOfMemoryException) { return null; }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}

