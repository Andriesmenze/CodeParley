using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 option A — the AppContainer helper feasibility spike (TD decision 2026-10-15 on F5-1–F5-6; D-18). A
/// FEASIBILITY TEST, not a product path: it establishes a verdict and nothing is wired to it.
///
/// Run AS THE CUSTODIAN SERVICE ACCOUNT (the VM driver points the service binary path at this verb for one start, then
/// restores it), so the launch happens under the real, unchanged SERVICE_SID_TYPE_RESTRICTED service token.
///
///   self-test-appcontainer --detach --node &lt;node.exe&gt; --git &lt;git.exe&gt; --repo &lt;dir&gt; --scratch &lt;dir&gt; --out &lt;file.json&gt;
///                          [--net-host host] [--net-private ip] [--net-port N] [--service-pid N]
///
/// It does no boundary probing of its own. For each desktop mode it launches, through the existing
/// <see cref="AppContainerLauncher"/>, only: Node running git in the repository (the basic-execution gate, TD step 5);
/// the custodian's existing <c>helper-probe</c> verb, which attempts and reports the N5-7 denials (reads of private
/// records, writes, the pipes, the service process); <c>whoami</c>; standard <c>curl.exe</c> reachability checks
/// (internet, a private address, loopback) with a non-AppContainer control; and standard <c>cmd</c> write attempts to
/// enumerate any AppContainer-local writable location. The verdict is reported, never acted on. If Node and git cannot
/// run under the AppContainer identity, it STOPS before the isolation children (basic-execution gate).
/// </summary>
internal static class AppContainerFeasibility
{
    internal static int Run(string[] args)
    {
        // Started by the SCM (binPath pointed here for one start); relaunch detached, same token/account, so the SCM's
        // ~30 s service-registration kill does not race the work. The relaunched copy writes --out.
        if (args.Contains("--detach"))
        {
            var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            foreach (string a in args) if (a != "--detach") psi.ArgumentList.Add(a);
            System.Diagnostics.Process.Start(psi);
            return 0;
        }
        string? node = Arg(args, "--node"), git = Arg(args, "--git"), repo = Arg(args, "--repo"), scratch = Arg(args, "--scratch"), outPath = Arg(args, "--out");
        if (node is null || git is null || repo is null || scratch is null || outPath is null)
        {
            Console.Error.WriteLine("self-test-appcontainer requires --node --git --repo --scratch --out");
            return 2;
        }
        Directory.CreateDirectory(scratch);
        string self = Environment.ProcessPath!;
        string servicePid = Arg(args, "--service-pid") ?? Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        string system32 = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32");
        string curl = Path.Combine(system32, "curl.exe");
        string cmd = Path.Combine(system32, "cmd.exe");
        string netHost = Arg(args, "--net-host") ?? "http://www.msftconnecttest.com/connecttest.txt";
        string netPrivate = Arg(args, "--net-private") ?? "";
        string netPort = Arg(args, "--net-port") ?? "80";
        // A minimal, explicitly allowlisted environment (contract §2.2; TD corrective 2026-10-15): named variables only,
        // never a blind inherit of the service environment. USERPROFILE/LOCALAPPDATA keep the REAL service profile so the
        // AppContainer runtime can locate its package folder (the cycle-1 error-203 cause); git config is pinned by the
        // GIT_* variables, not by HOME. TEMP/TMP/HOME point at the read-only prep dir — no writable AppContainer scratch.
        string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        string userProfile = Environment.GetEnvironmentVariable("USERPROFILE") ?? Path.Combine(sysRoot, "ServiceProfiles", "CodeParleyCustodian");
        string localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? Path.Combine(userProfile, "AppData", "Local");
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
        if (!File.Exists(Path.Combine(scratch, "gitconfig"))) File.WriteAllText(Path.Combine(scratch, "gitconfig"), "");

        var report = new JsonObject
        {
            ["verb"] = "self-test-appcontainer",
            ["caller"] = System.Security.Principal.WindowsIdentity.GetCurrent().Name,
            ["callerSid"] = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value,
            ["at"] = DateTime.UtcNow.ToString("o"),
            ["profileName"] = AppContainerLauncher.ProfileName,
        };

        // The test-only AppContainer profile and its SID (documented API; deleted in the finally block).
        string sid;
        try
        {
            sid = AppContainerLauncher.EnsureProfile(out int createHr);
            report["profileSid"] = sid;
            report["createHr"] = $"0x{createHr:X8}";
            report["folderPath"] = AppContainerLauncher.FolderPath(sid);
        }
        catch (Exception e)
        {
            report["profileError"] = Describe(e);
            report["verdict"] = "FAIL (profile)";
            File.WriteAllText(outPath, report.ToJsonString(Indented));
            Console.WriteLine($"appcontainer feasibility: {report["verdict"]} (report {outPath})");
            return 1;
        }

        var writeTargets = DefaultWriteTargets(repo, scratch, AppContainerLauncher.FolderPath(sid));
        bool anyBasicOk = false;
        var modes = new JsonArray();
        try
        {
            foreach (string desktop in new[] { "inherit", "private" })
            {
                var m = new JsonObject { ["desktop"] = desktop };
                try
                {
                    // Basic-execution gate (TD step 5): Node, git --version, and a real read-only git operation.
                    var nodeRun = Launch(sid, node, ["-e", NodeGitCheck(git, repo)], scratch, env, desktop, m, "node", TimeSpan.FromSeconds(60));
                    bool basicOk = nodeRun.ExitCode == 0 && ParsedOk(nodeRun.Stdout, "ok");
                    m["basicVerdict"] = basicOk ? "PASS" : "FAIL";
                    anyBasicOk |= basicOk;
                    if (!basicOk)
                    {
                        m["note"] = "basic execution failed; isolation children skipped for this mode";
                        modes.Add(m);
                        continue;
                    }

                    // Isolation denials (areas C, D-core, F): the existing helper-probe, unchanged.
                    Launch(sid, self, ["helper-probe", "--write-targets", string.Join(';', writeTargets), "--service-pid", servicePid, "--repo", repo, "--store-root", StorePaths.Root],
                        scratch, env, desktop, m, "probe", TimeSpan.FromMinutes(2));

                    // Token the children actually received (area A).
                    Launch(sid, Path.Combine(system32, "whoami.exe"), ["/user", "/groups", "/fo", "list"], scratch, env, desktop, m, "whoami", TimeSpan.FromSeconds(30));

                    // Network (area E): standard curl reachability, denial distinguished from unreachability by a control.
                    Launch(sid, curl, CurlArgs(netHost), scratch, env, desktop, m, "netInternet", TimeSpan.FromSeconds(20));
                    if (netPrivate.Length > 0) Launch(sid, curl, CurlArgs($"http://{netPrivate}:{netPort}"), scratch, env, desktop, m, "netPrivate", TimeSpan.FromSeconds(20));
                    Launch(sid, curl, CurlArgs($"http://127.0.0.1:{netPort}"), scratch, env, desktop, m, "netLoopback", TimeSpan.FromSeconds(20));

                    // Write-location enumeration (area D): standard cmd write attempts.
                    foreach (string dir in writeTargets)
                        Launch(sid, cmd, ["/c", $"echo x> \"{Path.Combine(dir, "cp_ac_probe.tmp")}\""], scratch, env, desktop, m, "write:" + dir, TimeSpan.FromSeconds(15));
                }
                catch (Exception e) { m["error"] = Describe(e); m["basicVerdict"] = "FAIL"; }
                modes.Add(m);
            }
        }
        finally
        {
            report["deleteProfileHr"] = $"0x{AppContainerLauncher.DeleteProfile():X8}";
        }

        // The non-AppContainer control for the network test: run as the service account, outside any AppContainer.
        report["netControl"] = RunControl(curl, CurlArgs(netHost), env);
        report["modes"] = modes;
        report["writeTargets"] = new JsonArray(writeTargets.Select(t => (JsonNode)t).ToArray());
        // The verb records a basic-execution verdict only; the isolation verdict (A–H) is assessed from this evidence,
        // not decided here.
        report["verdict"] = anyBasicOk ? "BASIC-EXECUTION-OK (assess isolation from evidence)" : "BASIC-EXECUTION-FAILED";
        File.WriteAllText(outPath, report.ToJsonString(Indented));
        Console.WriteLine($"appcontainer feasibility: {report["verdict"]} (report {outPath})");
        return anyBasicOk ? 0 : 1;
    }

    /// <summary>Print the test AppContainer SID (derived from the profile name, no profile created) so the operator-side
    /// driver can grant it read/execute on the scoped test resources before launch.</summary>
    internal static int PrintSid(string[] args)
    {
        Console.WriteLine(AppContainerLauncher.DeriveSid());
        return 0;
    }

    private static HelperResult Launch(string sid, string exe, string[] args, string scratch, Dictionary<string, string> env, string desktop, JsonObject into, string label, TimeSpan wall)
    {
        var r = AppContainerLauncher.Run(sid, exe, args, scratch, env, [], HelperLimits.Default with { WallTime = wall }, desktop, out var tokenFacts);
        var o = new JsonObject
        {
            ["exitHex"] = $"0x{unchecked((uint)r.ExitCode):X8}",
            ["timedOut"] = r.TimedOut,
            ["overLimit"] = r.OverLimit,
            ["ms"] = (long)r.Elapsed.TotalMilliseconds,
        };
        if (tokenFacts.Count > 0 && !into.ContainsKey("token")) into["token"] = tokenFacts.DeepClone();
        string text = Encoding.UTF8.GetString(r.Stdout);
        try { o["stdout"] = JsonNode.Parse(text); }
        catch (JsonException) { o["stdout"] = text.Length > 1500 ? text[..1500] : text; }
        if (r.Stderr.Length > 0) o["stderr"] = r.Stderr.Length > 800 ? r.Stderr[..800] : r.Stderr;
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

    internal static string NodeGitCheck(string git, string repo) =>
        "const {spawnSync}=require('child_process');" +
        $"const git={JsonSerializer.Serialize(git)};const repo={JsonSerializer.Serialize(repo)};" +
        "const v=spawnSync(git,['--version'],{encoding:'utf8'});" +
        "const head=spawnSync(git,['-C',repo,'rev-parse','HEAD'],{encoding:'utf8'});" +
        "const ls=spawnSync(git,['-C',repo,'ls-files','-z'],{encoding:'utf8',maxBuffer:64*1024*1024});" +
        "const ok=v.status===0&&head.status===0&&ls.status===0;" +
        "process.stdout.write(JSON.stringify({ok,node:process.version,gitVersion:(v.stdout||'').trim(),gitVersionStatus:v.status," +
        "headStatus:head.status,head:(head.stdout||'').trim(),lsStatus:ls.status,lsCount:(ls.stdout||'').split('\\0').filter(Boolean).length," +
        "err:((v.stderr||'')+(head.stderr||'')+(ls.stderr||'')+String(v.error||'')).slice(0,400)}));";

    private static List<string> DefaultWriteTargets(string repo, string scratch, string? acFolder)
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var targets = new List<string> { StorePaths.Root, repo, programData, scratch, @"C:\Users\Public" };
        if (acFolder is not null && acFolder.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase)) targets.Add(acFolder);
        return targets;
    }

    private static bool ParsedOk(byte[] stdout, string field)
    {
        try { return (bool?)JsonNode.Parse(Encoding.UTF8.GetString(stdout))?[field] == true; }
        catch (JsonException) { return false; }
    }

    private static string Describe(Exception e) =>
        e is System.ComponentModel.Win32Exception w
            ? $"Win32Exception: {e.Message} (error {w.NativeErrorCode}: {new System.ComponentModel.Win32Exception(w.NativeErrorCode).Message})"
            : $"{e.GetType().Name}: {e.Message}";

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static string? Arg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
