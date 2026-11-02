using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Security;
using Microsoft.Win32.SafeHandles;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 option B — the dedicated-helper-principal feasibility gate (TD authorization 2026-10-15). A FEASIBILITY TEST,
/// not the production helper: no dedicated IPC protocol, no installer, no product path.
///
/// Run AS THE DEDICATED HELPER SERVICE ACCOUNT (the VM driver creates a throwaway `CodeParleyHelper` service under the
/// virtual account `NT SERVICE\CodeParleyHelper`, SERVICE_SID_TYPE_RESTRICTED, SeChangeNotifyPrivilege only; points its
/// binary path here for one start; then deletes it), so the launch happens under the real helper identity in Session 0.
///
///   self-test-helper-principal --detach --node &lt;node.exe&gt; --git &lt;git.exe&gt; --repo &lt;dir&gt; --scratch &lt;dir&gt; --out &lt;file.json&gt;
///                              [--net-host url] [--net-private ip] [--net-port N]
///
/// Unlike the AppContainer / restricted-token helpers, children run under the helper's OWN token with a **plain
/// CreateProcess** (no CreateRestrictedToken, no AppContainer, no forced integrity change) inside a job object — the
/// way a production helper service would spawn Node/Git. It launches: `whoami /all` (the effective token under the real
/// identity, gate 1); Node running Git in the repository (gates 1.2/1.3); the existing `helper-probe` (the N5-7 denials,
/// gate 2); and standard `curl.exe` reachability with a non-helper control (gate 3). It records; it never acts on the
/// result, and it adds no filesystem write grant.
/// </summary>
internal static class HelperPrincipalFeasibility
{
    internal static int Run(string[] args)
    {
        // Started by the SCM (binPath pointed here for one start); relaunch detached, same token/account, then return.
        if (args.Contains("--detach"))
        {
            var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            foreach (string a in args) if (a != "--detach") psi.ArgumentList.Add(a);
            System.Diagnostics.Process.Start(psi);
            return 0;
        }
        string? node = Arg(args, "--node"), git = Arg(args, "--git"), repo = Arg(args, "--repo"), scratch = Arg(args, "--scratch"), outPath = Arg(args, "--out"), pipe = Arg(args, "--pipe"), custodianPid = Arg(args, "--custodian-pid");
        if (node is null || git is null || repo is null || scratch is null || (outPath is null && pipe is null))
        {
            Console.Error.WriteLine("self-test-helper-principal requires --node --git --repo --scratch and one of --pipe/--out");
            return 2;
        }
        // The helper writes NOTHING to disk (TD corrective 2026-10-15): it neither creates the scratch/cwd (the test
        // controller prepares it read-only) nor writes a report file; results go out over the controller's test pipe.
        string self = Environment.ProcessPath!;
        string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        string system32 = Path.Combine(sysRoot, "System32");
        string curl = Path.Combine(system32, "curl.exe");
        string userProfile = Environment.GetEnvironmentVariable("USERPROFILE") ?? Path.Combine(sysRoot, "ServiceProfiles", "CodeParleyHelper");
        string localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? Path.Combine(userProfile, "AppData", "Local");
        string netHost = Arg(args, "--net-host") ?? "http://www.msftconnecttest.com/connecttest.txt";
        string netPrivate = Arg(args, "--net-private") ?? "";
        string netPort = Arg(args, "--net-port") ?? "80";

        // A minimal, explicitly allowlisted environment — named variables only, no blind inherit. No gitconfig file is
        // written (git needs none: GIT_CONFIG_NOSYSTEM plus a GIT_CONFIG_GLOBAL that may be absent), so the helper makes
        // no filesystem write to run.
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = sysRoot,
            ["SystemDrive"] = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:",
            ["windir"] = sysRoot,
            ["PATH"] = string.Join(';', Path.GetDirectoryName(git)!, system32),
            ["PATHEXT"] = Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD",
            ["USERPROFILE"] = userProfile,
            ["LOCALAPPDATA"] = localAppData,
            ["TEMP"] = scratch, ["TMP"] = scratch, ["HOME"] = scratch,
            ["GIT_CONFIG_NOSYSTEM"] = "1", ["GIT_CONFIG_GLOBAL"] = Path.Combine(scratch, "gitconfig"), ["GIT_OPTIONAL_LOCKS"] = "0", ["GIT_TERMINAL_PROMPT"] = "0",
        };
        // Per-invocation protected git config (TD corrective 2026-10-15): trust ONLY this exact administrator-selected
        // test repository across the owner difference (the fixture is owned by cpimpl, the helper is a new principal).
        // Not safe.directory=*, not a global-config change — supplied via the environment so it also applies when git is
        // spawned by Node. Both path spellings are given because git compares against its canonical (forward-slash) form.
        env["GIT_CONFIG_COUNT"] = "2";
        env["GIT_CONFIG_KEY_0"] = "safe.directory"; env["GIT_CONFIG_VALUE_0"] = repo;
        env["GIT_CONFIG_KEY_1"] = "safe.directory"; env["GIT_CONFIG_VALUE_1"] = repo.Replace('\\', '/');
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var report = new JsonObject
        {
            ["verb"] = "self-test-helper-principal",
            ["caller"] = identity.Name,
            ["callerSid"] = identity.User?.Value,
            ["sessionId"] = System.Diagnostics.Process.GetCurrentProcess().SessionId,
            ["isSystem"] = identity.IsSystem,
            ["at"] = DateTime.UtcNow.ToString("o"),
        };

        var writeTargets = new List<string> { StorePaths.Root, repo, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), scratch, @"C:\Users\Public", Path.Combine(sysRoot, "Temp") };
        // P3.4C-5 Increment 1 (§A.8 N5-7): further targets the gate names (the export root, the approved runtime, the
        // helper's own profile, ...), required denials and characterization alike; the report records each outcome.
        if (Arg(args, "--extra-write-targets") is { } extra) writeTargets.AddRange(extra.Split(';', StringSplitOptions.RemoveEmptyEntries));
        var results = new JsonObject();
        try
        {
            // Gate 1: the effective token under the real helper identity, and basic execution.
            Launch(Path.Combine(system32, "whoami.exe"), ["/user", "/groups", "/priv", "/fo", "list"], scratch, env, results, "whoami", TimeSpan.FromSeconds(30));
            var nodeRun = Launch(node, ["-e", AppContainerFeasibility.NodeGitCheck(git, repo)], scratch, env, results, "node", TimeSpan.FromSeconds(60));
            bool basicOk = nodeRun.ExitCode == 0 && ParsedOk(nodeRun.Stdout, "ok");
            report["basicVerdict"] = basicOk ? "PASS" : "FAIL";

            // Independent of the Node/Git result (TD harness correction 2026-10-15): once the identity and the reporting
            // channel are operational, always run the isolation and network tests and report each outcome.
            // Gate 2: the existing N5-7 denials under the helper's own token; the process-modification test targets the
            // real custodian service process (not the helper itself).
            var probeArgs = new List<string> { "helper-probe", "--write-targets", string.Join(';', writeTargets), "--repo", repo, "--store-root", StorePaths.Root };
            if (Arg(args, "--extra-read-targets") is { } reads) { probeArgs.Add("--extra-read-targets"); probeArgs.Add(reads); }
            if (custodianPid is not null) { probeArgs.Add("--service-pid"); probeArgs.Add(custodianPid); }
            Launch(self, probeArgs.ToArray(), scratch, env, results, "probe", TimeSpan.FromMinutes(2));
            // Gate 3: network reachability (characterize only; outbound is an accepted residual, not a FAIL; no firewall rule).
            Launch(curl, CurlArgs(netHost), scratch, env, results, "netInternet", TimeSpan.FromSeconds(20));
            if (netPrivate.Length > 0) Launch(curl, CurlArgs($"http://{netPrivate}:{netPort}"), scratch, env, results, "netPrivate", TimeSpan.FromSeconds(20));
            Launch(curl, CurlArgs($"http://127.0.0.1:{netPort}"), scratch, env, results, "netLoopback", TimeSpan.FromSeconds(20));
        }
        catch (Exception e) { report["error"] = Describe(e); report["basicVerdict"] = "FAIL"; }

        // The non-AppContainer, non-job network control: this process, as the helper account, outside the job.
        report["netControl"] = RunControl(curl, CurlArgs(netHost), env);
        report["results"] = results;
        report["writeTargets"] = new JsonArray(writeTargets.Select(t => (JsonNode)t).ToArray());
        report["verdict"] = (string?)report["basicVerdict"] == "PASS" ? "BASIC-EXECUTION-OK (assess isolation from evidence)" : "BASIC-EXECUTION-FAILED";
        string json = report.ToJsonString(Indented);
        if (pipe is not null)
        {
            // The test-only result channel: connect to the controller's bounded, ACL'd pipe and send the report. The
            // controller owns any files; the helper makes no filesystem write. One-way; carries no authority operation.
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", pipe, System.IO.Pipes.PipeDirection.Out);
            client.Connect(15000);
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            client.Write(bytes, 0, bytes.Length);
            client.Flush();
        }
        else
        {
            File.WriteAllText(outPath!, json);
        }
        Console.WriteLine($"helper-principal feasibility: {report["verdict"]}");
        return (string?)report["basicVerdict"] == "PASS" ? 0 : 1;
    }

    /// <summary>Launch a child under the CALLER's own token (plain CreateProcess, no token derivation, no AppContainer),
    /// inside a job object with bounded stdout/stderr — the way a production helper service would spawn Node/Git.</summary>
    private static HelperResult LaunchInherit(string exe, IReadOnlyList<string> args, string cwd, IReadOnlyDictionary<string, string> env, HelperLimits limits)
    {
        IntPtr job = IntPtr.Zero, attrList = IntPtr.Zero, handleArray = IntPtr.Zero, envBlock = IntPtr.Zero;
        IntPtr inRead = IntPtr.Zero, inWrite = IntPtr.Zero, outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        var pi = default(HelperNative.PROCESS_INFORMATION);
        var started = DateTime.UtcNow;
        try
        {
            job = HelperProcess.CreateJob(limits);
            HelperProcess.CreateInheritablePipe(out inRead, out inWrite, childEnd: 0);
            HelperProcess.CreateInheritablePipe(out outRead, out outWrite, childEnd: 1);
            HelperProcess.CreateInheritablePipe(out errRead, out errWrite, childEnd: 1);

            IntPtr size = IntPtr.Zero;
            HelperNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!HelperNative.InitializeProcThreadAttributeList(attrList, 1, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList");
            handleArray = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleArray, 0, inRead);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size, outWrite);
            Marshal.WriteIntPtr(handleArray, IntPtr.Size * 2, errWrite);
            if (!HelperNative.UpdateProcThreadAttribute(attrList, 0, HelperNative.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray, IntPtr.Size * 3, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute(handle list)");

            var si = new HelperNative.STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<HelperNative.STARTUPINFOEX>();
            si.StartupInfo.dwFlags = HelperNative.STARTF_USESTDHANDLES | HelperNative.STARTF_USESHOWWINDOW;
            si.StartupInfo.hStdInput = inRead;
            si.StartupInfo.hStdOutput = outWrite;
            si.StartupInfo.hStdError = errWrite;
            si.lpAttributeList = attrList;

            envBlock = HelperProcess.EnvironmentBlock(env);
            var cmd = new StringBuilder(HelperProcess.CommandLine(exe, args));
            uint flags = HelperNative.CREATE_SUSPENDED | HelperNative.CREATE_NO_WINDOW | HelperNative.CREATE_UNICODE_ENVIRONMENT | HelperNative.EXTENDED_STARTUPINFO_PRESENT;
            if (!HelperNative.CreateProcessW(exe, cmd, IntPtr.Zero, IntPtr.Zero, true, flags, envBlock, cwd, ref si, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess (inherit token)");
            if (!HelperNative.AssignProcessToJobObject(job, pi.hProcess))
            {
                HelperNative.TerminateProcess(pi.hProcess, 1);
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject");
            }
            HelperNative.ResumeThread(pi.hThread);
            Native.CloseHandle(inRead); inRead = IntPtr.Zero;
            Native.CloseHandle(outWrite); outWrite = IntPtr.Zero;
            Native.CloseHandle(errWrite); errWrite = IntPtr.Zero;
            Native.CloseHandle(inWrite); inWrite = IntPtr.Zero; // the children read no stdin

            using var stdoutStream = new FileStream(new SafeFileHandle(outRead, true), FileAccess.Read); outRead = IntPtr.Zero;
            using var stderrStream = new FileStream(new SafeFileHandle(errRead, true), FileAccess.Read); errRead = IntPtr.Zero;
            bool overLimit = false;
            var outTask = Task.Run(() => HelperProcess.ReadBounded(stdoutStream, limits.MaxStdoutBytes, () => overLimit = true));
            var errTask = Task.Run(() => HelperProcess.ReadBounded(stderrStream, limits.MaxStderrBytes, () => { }));
            var deadline = started + limits.WallTime;
            bool timedOut = false;
            while (true)
            {
                if (HelperNative.WaitForSingleObject(pi.hProcess, 200) == HelperNative.WAIT_OBJECT_0) break;
                if (DateTime.UtcNow > deadline || overLimit)
                {
                    timedOut = !overLimit;
                    HelperNative.TerminateJobObject(job, 0xC0DE);
                    HelperNative.WaitForSingleObject(pi.hProcess, 5000);
                    break;
                }
            }
            HelperNative.TerminateJobObject(job, 0);
            byte[] stdout = outTask.Wait(TimeSpan.FromSeconds(10)) ? outTask.Result : [];
            byte[] stderr = errTask.Wait(TimeSpan.FromSeconds(10)) ? errTask.Result : [];
            HelperNative.GetExitCodeProcess(pi.hProcess, out uint exit);
            return new HelperResult(unchecked((int)exit), stdout, Encoding.UTF8.GetString(stderr), timedOut, overLimit, DateTime.UtcNow - started);
        }
        finally
        {
            foreach (IntPtr h in new[] { inRead, inWrite, outRead, outWrite, errRead, errWrite, pi.hThread, pi.hProcess })
                if (h != IntPtr.Zero) Native.CloseHandle(h);
            if (job != IntPtr.Zero) Native.CloseHandle(job);
            if (attrList != IntPtr.Zero) { HelperNative.DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
        }
    }

    private static HelperResult Launch(string exe, string[] args, string scratch, Dictionary<string, string> env, JsonObject into, string label, TimeSpan wall)
    {
        HelperResult r;
        var o = new JsonObject();
        try
        {
            r = LaunchInherit(exe, args, scratch, env, HelperLimits.Default with { WallTime = wall });
            o["exitHex"] = $"0x{unchecked((uint)r.ExitCode):X8}";
            o["timedOut"] = r.TimedOut;
            o["overLimit"] = r.OverLimit;
            o["ms"] = (long)r.Elapsed.TotalMilliseconds;
            string text = Encoding.UTF8.GetString(r.Stdout);
            try { o["stdout"] = JsonNode.Parse(text); }
            catch (JsonException) { o["stdout"] = text.Length > 2000 ? text[..2000] : text; }
            if (r.Stderr.Length > 0) o["stderr"] = r.Stderr.Length > 800 ? r.Stderr[..800] : r.Stderr;
        }
        catch (Exception e) { o["error"] = Describe(e); r = new HelperResult(-1, [], "", false, false, TimeSpan.Zero); }
        into[label] = o;
        return r;
    }

    private static JsonObject RunControl(string exe, string[] args, Dictionary<string, string> env)
    {
        var o = new JsonObject();
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            foreach (string a in args) psi.ArgumentList.Add(a);
            foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;
            using var p = System.Diagnostics.Process.Start(psi)!;
            string outp = p.StandardOutput.ReadToEnd();
            p.WaitForExit(20000);
            o["exit"] = p.HasExited ? p.ExitCode : -1;
            o["stdout"] = outp.Length > 400 ? outp[..400] : outp;
        }
        catch (Exception e) { o["error"] = Describe(e); }
        return o;
    }

    private static string[] CurlArgs(string url) => ["-sS", "-m", "8", "-o", "NUL", "-w", "%{http_code}", url];

    private static bool ParsedOk(byte[] stdout, string field)
    {
        try { return (bool?)JsonNode.Parse(Encoding.UTF8.GetString(stdout))?[field] == true; }
        catch (JsonException) { return false; }
    }

    private static string Describe(Exception e) =>
        e is Win32Exception w
            ? $"Win32Exception: {e.Message} (error {w.NativeErrorCode}: {new Win32Exception(w.NativeErrorCode).Message})"
            : $"{e.GetType().Name}: {e.Message}";

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static string? Arg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
