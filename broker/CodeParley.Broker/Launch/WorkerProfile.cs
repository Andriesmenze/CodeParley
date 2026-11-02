using System.Runtime.InteropServices;
using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Launch;

/// <summary>
/// Loads the worker account's real Windows profile (HKCU hive — where persistent Claude auth/cache
/// live) for the launch, and derives the base environment from the worker token via
/// CreateEnvironmentBlock. Unloads the profile when disposed. (Hardening #3.)
/// </summary>
internal sealed class WorkerProfile : IDisposable
{
    private const int PI_NOUI = 1;
    private readonly IntPtr _token;
    private Native.PROFILEINFO _pi;
    private bool _loaded;

    private WorkerProfile(IntPtr token, Native.PROFILEINFO pi) { _token = token; _pi = pi; _loaded = true; }

    internal static WorkerProfile Load(IntPtr logonToken, string account)
    {
        var pi = default(Native.PROFILEINFO);
        pi.dwSize = Marshal.SizeOf<Native.PROFILEINFO>();
        pi.lpUserName = account;
        pi.dwFlags = PI_NOUI;
        if (!Native.LoadUserProfileW(logonToken, ref pi)) Native.ThrowLastError("LoadUserProfile");
        return new WorkerProfile(logonToken, pi);
    }

    /// <summary>Environment derived from the loaded worker profile (USERPROFILE/APPDATA/… resolve to
    /// the worker), never the controller environment.</summary>
    internal Dictionary<string, string> DeriveBaseEnvironment()
    {
        if (!Native.CreateEnvironmentBlock(out IntPtr block, _token, false)) Native.ThrowLastError("CreateEnvironmentBlock");
        try { return EnvBlock.Parse(block); }
        finally { Native.DestroyEnvironmentBlock(block); }
    }

    public void Dispose()
    {
        if (_loaded)
        {
            Native.UnloadUserProfile(_token, _pi.hProfile);
            _loaded = false;
        }
    }
}
