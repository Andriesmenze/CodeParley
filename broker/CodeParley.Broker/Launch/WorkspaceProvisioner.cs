using System.Runtime.InteropServices;
using System.Text;
using CodeParley.Broker.Interop;

namespace CodeParley.Broker.Launch;

/// <summary>
/// Derives the per-run workspace from a caller runId under the broker's fixed trusted root and
/// provisions it safely (hardening #1): the directory is validated by HANDLE — rejecting reparse
/// points/junctions and confirming (via GetFinalPathNameByHandle) that the final path is contained
/// under the handle-verified trusted root — and the logon-SID ACL is applied to that opened handle,
/// closing the junction/TOCTOU window. No caller-supplied path ever reaches the filesystem.
/// </summary>
internal sealed class WorkspaceProvisioner
{
    internal string Path { get; }
    private WorkspaceProvisioner(string path) { Path = path; }

    /// <summary>Ensure the broker's trusted roots exist with a protected SYSTEM+Administrators-only
    /// DACL, so they are never writable by the worker (defense in depth alongside the token).</summary>
    internal static void EnsureTrustedRoots()
    {
        foreach (string dir in new[] { BrokerConstants.TrustedWorkspaceRoot, BrokerConstants.TrustedStateRoot })
        {
            Directory.CreateDirectory(dir);
            IntPtr h = OpenDirHandle(dir, Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL | Native.WRITE_DAC);
            try { ApplyDacl(h, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); }
            finally { Native.CloseHandle(h); }
        }

        // The durable runs registry inherits the SYSTEM/Administrators-only lock from the state root.
        Directory.CreateDirectory(BrokerConstants.RunsRoot);

        // Worker-READABLE (not worker-writable) directory for per-run git configs: it inherits
        // ProgramData's Users:(RX), so the worker can read its run's config via GIT_CONFIG_GLOBAL but
        // cannot rewrite it. The config itself is written per run (WritePerRunGitConfig) and names only
        // that run's exact clone as safe — never the Phase-3.1A proof-time `safe.directory = *`.
        Directory.CreateDirectory(BrokerConstants.GitConfigDir);
    }

    /// <summary>Write a per-run git config marking ONLY this run's exact clone directory as safe (the
    /// git ownership check, CVE-2022-24765), replacing the proof-time wildcard. The path is written with
    /// forward slashes — git's canonical form for `safe.directory` on Windows, and what it compares the
    /// discovered gitdir against; a native-backslash value is BOTH redundant and malformed (git reads a
    /// backslash as an escape, e.g. `C:\P` → "bad config line"). Trust is never broadened to a sibling
    /// or a parent — only this exact per-run clone.</summary>
    internal static string WritePerRunGitConfig(string runId, string repoPath)
    {
        Directory.CreateDirectory(BrokerConstants.GitConfigDir);
        string path = BrokerConstants.WorkerGitConfig(runId);
        string fwd = repoPath.Replace('\\', '/');
        File.WriteAllText(path, "[safe]\n\tdirectory = " + fwd + "\n");
        return path;
    }

    internal static WorkspaceProvisioner Create(string runId, string logonSid)
    {
        string root = BrokerConstants.TrustedWorkspaceRoot;
        Directory.CreateDirectory(root);

        string rootFinal;
        IntPtr rh = OpenDirHandle(root, Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL);
        try { AssertNotReparse(rh, "trusted root"); rootFinal = FinalPath(rh); }
        finally { Native.CloseHandle(rh); }

        string ws = System.IO.Path.Combine(root, runId);
        if (Directory.Exists(ws) || File.Exists(ws))
            throw new InvalidOperationException($"run workspace already exists for runId '{runId}'");
        Directory.CreateDirectory(ws);

        IntPtr h = OpenDirHandle(ws, Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL | Native.WRITE_DAC);
        try
        {
            AssertNotReparse(h, "workspace");
            string wsFinal = FinalPath(h);
            string expected = System.IO.Path.Combine(rootFinal, runId);
            if (!wsFinal.Equals(expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"workspace final path '{wsFinal}' is not the expected '{expected}' under the trusted root");

            // DACL applied to the verified handle: SYSTEM + Administrators Full; the per-launch logon
            // SID Modify; protected (no inheritance from parent), inheritable to children.
            ApplyDacl(h, $"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{logonSid})");
        }
        finally { Native.CloseHandle(h); }

        return new WorkspaceProvisioner(ws);
    }

    /// <summary>Clone a broker-staged source repo into &lt;workspace&gt;\repo as a standalone repo
    /// (self-contained .git, --no-hardlinks), with origin removed so the worker has no push path.</summary>
    internal string CloneStandalone(string gitExe, string sourceRepo)
    {
        string repo = System.IO.Path.Combine(Path, "repo");
        ProcessRunner.RunChecked(gitExe, ["clone", "--no-hardlinks", sourceRepo, repo]);
        ProcessRunner.RunChecked(gitExe, ["remote", "remove", "origin"], repo);
        return repo;
    }

    internal void Cleanup()
    {
        try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
        catch { /* best effort; the broker runs as SYSTEM */ }
    }

    private static IntPtr OpenDirHandle(string path, uint access)
    {
        IntPtr h = Native.CreateFileW(path, access,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
            IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_BACKUP_SEMANTICS | Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) Native.ThrowLastError($"CreateFile('{path}')");
        return h;
    }

    private static void AssertNotReparse(IntPtr handle, string what)
    {
        if (!Native.GetFileInformationByHandle(handle, out Native.BY_HANDLE_FILE_INFORMATION fi))
            Native.ThrowLastError("GetFileInformationByHandle");
        if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new InvalidOperationException($"{what} is a reparse point/junction; refusing");
    }

    private static string FinalPath(IntPtr handle)
    {
        var sb = new StringBuilder(512);
        uint n = Native.GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
        if (n == 0) Native.ThrowLastError("GetFinalPathNameByHandle");
        if (n > sb.Capacity)
        {
            sb = new StringBuilder((int)n + 1);
            n = Native.GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
            if (n == 0) Native.ThrowLastError("GetFinalPathNameByHandle");
        }
        string p = sb.ToString();
        return p.StartsWith(@"\\?\", StringComparison.Ordinal) ? p[4..] : p;
    }

    private static void ApplyDacl(IntPtr handle, string sddl)
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, Native.SDDL_REVISION_1, out IntPtr sd, out _))
            Native.ThrowLastError("ConvertStringSecurityDescriptor");
        try
        {
            if (!Native.GetSecurityDescriptorDacl(sd, out bool present, out IntPtr dacl, out _))
                Native.ThrowLastError("GetSecurityDescriptorDacl");
            if (!present) throw new InvalidOperationException("built security descriptor has no DACL");
            uint err = Native.SetSecurityInfo(handle, Native.SE_KERNEL_OBJECT,
                Native.DACL_SECURITY_INFORMATION | Native.PROTECTED_DACL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (err != 0) throw new System.ComponentModel.Win32Exception((int)err, "SetSecurityInfo");
        }
        finally { Native.LocalFree(sd); }
    }

}
