using System.ComponentModel;
using System.Runtime.InteropServices;
using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Launch;

/// <summary>
/// A private, non-interactive window station + desktop for one run (hardening #4). The DACL grants
/// only SYSTEM and the per-launch logon SID — never the operator's WinSta0\Default. The worker's
/// restricted token can use it because the logon SID is both granted here and a restricting SID in
/// the token (so write-class station/desktop access passes). Disposing destroys them with the run.
/// </summary>
internal sealed class WindowStationScope : IDisposable
{
    private IntPtr _winsta, _desk;

    /// <summary>Value for STARTUPINFO.lpDesktop: "station\desktop".</summary>
    internal string Desktop { get; }

    private WindowStationScope(IntPtr winsta, IntPtr desk, string desktop) { _winsta = winsta; _desk = desk; Desktop = desktop; }

    internal static WindowStationScope CreatePrivate(string runId, string logonSid)
    {
        string staName = "cp-" + runId;          // runId charset excludes '\' so this is a valid station name
        const string deskName = "cpdesk";
        // GENERIC_ALL for SYSTEM + the per-launch logon SID, plus a Low integrity label (SACL): a
        // SYSTEM-created station/desktop is otherwise System-IL, which the Medium-IL worker token
        // cannot attach to during process init (STATUS_DLL_INIT_FAILED / 0xC0000142).
        string staSddl = $"D:P(A;;GA;;;SY)(A;;GA;;;{logonSid})S:(ML;;NW;;;LW)";
        string deskSddl = $"D:P(A;;GA;;;SY)(A;;GA;;;{logonSid})S:(ML;;NW;;;LW)";

        IntPtr sdSta = IntPtr.Zero, sdDesk = IntPtr.Zero, winsta = IntPtr.Zero, desk = IntPtr.Zero;
        IntPtr orig = Native.GetProcessWindowStation();
        bool switched = false;
        try
        {
            var saSta = BuildSa(staSddl, out sdSta);
            winsta = Native.CreateWindowStationW(staName, 0, Native.WINSTA_ALL_ACCESS, ref saSta);
            if (winsta == IntPtr.Zero) Native.ThrowLastError("CreateWindowStation");

            if (!Native.SetProcessWindowStation(winsta)) Native.ThrowLastError("SetProcessWindowStation(private)");
            switched = true;

            var saDesk = BuildSa(deskSddl, out sdDesk);
            desk = Native.CreateDesktopW(deskName, null, IntPtr.Zero, 0, Native.DESKTOP_ALL, ref saDesk);
            int deskErr = Marshal.GetLastWin32Error();

            Native.SetProcessWindowStation(orig);   // restore the broker's own station
            switched = false;
            if (desk == IntPtr.Zero) throw new Win32Exception(deskErr, "CreateDesktop failed");

            var scope = new WindowStationScope(winsta, desk, staName + "\\" + deskName);
            winsta = desk = IntPtr.Zero;             // ownership transferred
            return scope;
        }
        catch
        {
            if (switched) Native.SetProcessWindowStation(orig);
            if (desk != IntPtr.Zero) Native.CloseDesktop(desk);
            if (winsta != IntPtr.Zero) Native.CloseWindowStation(winsta);
            throw;
        }
        finally
        {
            if (sdSta != IntPtr.Zero) Native.LocalFree(sdSta);
            if (sdDesk != IntPtr.Zero) Native.LocalFree(sdDesk);
        }
    }

    private static Native.SECURITY_ATTRIBUTES BuildSa(string sddl, out IntPtr sd)
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out sd, out _))
            Native.ThrowLastError("ConvertStringSecurityDescriptor");
        return new Native.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<Native.SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = sd,
            bInheritHandle = 0,
        };
    }

    public void Dispose()
    {
        if (_desk != IntPtr.Zero) { Native.CloseDesktop(_desk); _desk = IntPtr.Zero; }
        if (_winsta != IntPtr.Zero) { Native.CloseWindowStation(_winsta); _winsta = IntPtr.Zero; }
    }
}
