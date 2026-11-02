using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 increment 2 (contract §2.2, §10): the early Windows feasibility test of the helper boundary. It is a STOP
/// point. Run AS THE CUSTODIAN SERVICE ACCOUNT, because the helper token is derived from the caller's own token: on the
/// VM, the driver points the service's binary path at this verb for one start, then restores it.
///
///   self-test-helper --node &lt;node.exe&gt; --git &lt;git.exe&gt; --repo &lt;dir granted to CodeParley Repository Readers&gt;
///                    --scratch &lt;dir&gt; --out &lt;file.json&gt; [--write-targets a;b;…] [--service-pid N]
///
/// For each desktop mode (inherited, private), it starts three children under the helper token: Node running git in
/// the repository; the custodian's own `helper-probe` verb, which attempts every denial N5-7 lists; and `whoami`, which
/// records the token the children received. The verdict is PASS only if Node and git run AND every denial holds.
/// </summary>
internal static class HelperFeasibility
{
    internal static int Run(string[] args)
    {
        // Started by the service control manager (binPath pointed at this verb for one start): the SCM kills a process
        // that never registers as a service after ~30 s, so relaunch this verb detached (same token, same account) and
        // return at once. The relaunched copy does the work and writes --out.
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
            Console.Error.WriteLine("self-test-helper requires --node --git --repo --scratch --out");
            return 2;
        }
        Directory.CreateDirectory(scratch);
        string self = Environment.ProcessPath!;
        string writeTargets = Arg(args, "--write-targets") ?? string.Join(';', DefaultWriteTargets(repo, scratch));
        string servicePid = Arg(args, "--service-pid") ?? Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        // The group the helper's default DACL grants (contract §2.3): `CodeParley Repository Readers` on an installed
        // custodian; a dry run on a development host may name a stand-in group it holds enabled.
        string helperGroup = Arg(args, "--helper-group") ?? new System.Security.Principal.NTAccount("CodeParley Repository Readers").Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value;
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
            ["PATH"] = string.Join(';', Path.GetDirectoryName(git)!, Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32")),
            ["TEMP"] = scratch, ["TMP"] = scratch, ["HOME"] = scratch, ["USERPROFILE"] = scratch,
            ["GIT_CONFIG_NOSYSTEM"] = "1", ["GIT_CONFIG_GLOBAL"] = Path.Combine(scratch, "gitconfig"), ["GIT_OPTIONAL_LOCKS"] = "0", ["GIT_TERMINAL_PROMPT"] = "0",
        };
        if (!File.Exists(Path.Combine(scratch, "gitconfig"))) File.WriteAllText(Path.Combine(scratch, "gitconfig"), "");

        var report = new JsonObject
        {
            ["verb"] = "self-test-helper",
            ["caller"] = System.Security.Principal.WindowsIdentity.GetCurrent().Name,
            ["callerSid"] = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value,
            ["at"] = DateTime.UtcNow.ToString("o"),
        };
        var modes = new JsonArray();
        // Diagnostics: --restricted-code adds the well-known RESTRICTED SID (S-1-5-12) to the restricting set.
        HelperTokenVariant tokenVariant = args.Contains("--restricted-code") ? HelperTokenVariant.Full with { Name = "full+RESTRICTED", AllowRestrictedCode = true } : HelperTokenVariant.Full;
        report["tokenVariant"] = tokenVariant.Name;
        bool anyPass = false;
        foreach (bool privateDesktop in new[] { false, true })
        {
            var m = new JsonObject { ["privateDesktop"] = privateDesktop };
            try
            {
                string nodeScript = NodeProbeScript(git, repo);
                var nodeRun = HelperProcess.Run(node, ["-e", nodeScript], scratch, env, [], HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(45) }, privateDesktop, helperGroup, out var facts, default, tokenVariant);
                m["token"] = HelperProcess.Describe(facts);
                m["node"] = Outcome(nodeRun);
                var probeRun = HelperProcess.Run(self, ["helper-probe", "--write-targets", writeTargets, "--service-pid", servicePid, "--repo", repo, "--store-root", StorePaths.Root], scratch, env, [],
                    HelperLimits.Default with { WallTime = TimeSpan.FromMinutes(2) }, privateDesktop, helperGroup, out _, default, tokenVariant);
                m["probe"] = Outcome(probeRun);
                var whoami = HelperProcess.Run(Path.Combine(env["SystemRoot"], "System32", "whoami.exe"), ["/user", "/groups", "/priv", "/fo", "list"], scratch, env, [],
                    HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(30) }, privateDesktop, helperGroup, out _);
                m["whoami"] = Encoding.UTF8.GetString(whoami.Stdout).Trim();
                bool nodeOk = nodeRun.ExitCode == 0 && ParsedOk(nodeRun.Stdout, "ok");
                bool denialsOk = probeRun.ExitCode == 0 && ParsedOk(probeRun.Stdout, "allDenied");
                m["verdict"] = nodeOk && denialsOk ? "PASS" : "FAIL";
                anyPass |= nodeOk && denialsOk;
            }
            catch (Exception e)
            {
                m["error"] = e is System.ComponentModel.Win32Exception w ? $"Win32Exception: {e.Message} (error {w.NativeErrorCode}: {new System.ComponentModel.Win32Exception(w.NativeErrorCode).Message})" : $"{e.GetType().Name}: {e.Message}";
                m["verdict"] = "FAIL";
            }
            modes.Add(m);
        }
        report["helperGroup"] = helperGroup;
        try
        {
            Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY, out IntPtr t);
            report["sourceTokenGroups"] = new JsonArray(HelperProcess.TokenGroups(t).Select(g => (JsonNode)$"{g.Sid} attr=0x{g.Attributes:x}").ToArray());
            Native.CloseHandle(t);
        }
        catch (Exception e) { report["sourceTokenGroups"] = e.Message; }
        report["modes"] = modes;
        if (args.Contains("--variants"))
        {
            // Diagnostics: which token property makes a process fail to start (node --version only).
            var variants = new JsonArray();
            foreach (var v in new[]
            {
                HelperTokenVariant.Full,
                new HelperTokenVariant(false, true, true, "no-deny-only"),
                new HelperTokenVariant(true, false, true, "no-write-restrict"),
                new HelperTokenVariant(true, true, false, "no-low-integrity"),
                new HelperTokenVariant(false, false, false, "privileges-stripped-only"),
                new HelperTokenVariant(true, false, false, "deny-only-alone"),
                new HelperTokenVariant(false, true, false, "write-restrict-alone"),
                new HelperTokenVariant(false, false, true, "low-integrity-alone"),
                new HelperTokenVariant(false, true, false, "write-restrict+RESTRICTED-alone", AllowRestrictedCode: true),
                new HelperTokenVariant(true, true, true, "full+RESTRICTED", AllowRestrictedCode: true),
                new HelperTokenVariant(true, true, true, "wr33+deny-only+low", RestrictingSet: "write-restricted-sid"),
                new HelperTokenVariant(false, true, true, "wr33+low", RestrictingSet: "write-restricted-sid"),
                new HelperTokenVariant(true, true, true, "logon+deny-only(keep logon)+low", RestrictingSet: "logon", KeepLogonSid: true),
                new HelperTokenVariant(false, true, true, "logon+low", RestrictingSet: "logon"),
                new HelperTokenVariant(true, true, true, "wr33,logon+deny-only(keep logon)+low", RestrictingSet: "write-restricted-sid+logon", KeepLogonSid: true),
                new HelperTokenVariant(false, false, true, "duplicate+low (inherits the service's restrictions)", DuplicateOnly: true),
            })
            foreach (bool pd in new[] { false, true })
            {
                var o = new JsonObject { ["variant"] = v.Name, ["privateDesktop"] = pd };
                try
                {
                    var r = HelperProcess.Run(node, ["--version"], scratch, env, [], HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(30) }, pd, helperGroup, out var vf, default, v);
                    o["token"] = HelperProcess.Describe(vf);
                    o["exitHex"] = $"0x{unchecked((uint)r.ExitCode):X8}";
                    o["stdout"] = Encoding.UTF8.GetString(r.Stdout).Trim();
                    if (pd)
                    {
                        var g = HelperProcess.Run(git, ["--version"], scratch, env, [], HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(20) }, pd, helperGroup, out _, default, v);
                        o["gitVersion"] = $"0x{unchecked((uint)g.ExitCode):X8} {Encoding.UTF8.GetString(g.Stdout).Trim()} {g.Stderr.Trim()}";
                        string spawn = $"const r=require('child_process').spawnSync({JsonSerializer.Serialize(git)},['--version'],{{encoding:'utf8'}});process.stdout.write(String(r.status)+' '+(r.stdout||'').trim()+' '+String(r.error||'')+' '+(r.stderr||'').trim())";
                        var ns = HelperProcess.Run(node, ["-e", spawn], scratch, env, [], HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(20) }, pd, helperGroup, out _, default, v);
                        o["nodeSpawnsGit"] = $"0x{unchecked((uint)ns.ExitCode):X8} {Encoding.UTF8.GetString(ns.Stdout).Trim()}";
                    }
                }
                catch (Exception e) { o["error"] = e.Message; }
                variants.Add(o);
            }
            report["variants"] = variants;
            // Diagnostics: the N5-7 denial probe under the candidate boundaries (private desktop).
            var probes = new JsonArray();
            foreach (var v in new[]
            {
                HelperTokenVariant.Full,
                new HelperTokenVariant(true, false, true, "deny-only+low-integrity"),
                new HelperTokenVariant(false, false, true, "low-integrity-alone"),
                new HelperTokenVariant(true, true, true, "wr33+deny-only+low", RestrictingSet: "write-restricted-sid"),
                new HelperTokenVariant(false, true, true, "wr33+low", RestrictingSet: "write-restricted-sid"),
                new HelperTokenVariant(true, true, true, "logon+deny-only(keep logon)+low", RestrictingSet: "logon", KeepLogonSid: true),
                new HelperTokenVariant(false, true, true, "logon+low", RestrictingSet: "logon"),
                new HelperTokenVariant(true, true, true, "wr33,logon+deny-only(keep logon)+low", RestrictingSet: "write-restricted-sid+logon", KeepLogonSid: true),
                new HelperTokenVariant(false, false, true, "duplicate+low (inherits the service's restrictions)", DuplicateOnly: true),
            })
            {
                var o = new JsonObject { ["variant"] = v.Name };
                try
                {
                    var pr = HelperProcess.Run(self, ["helper-probe", "--write-targets", writeTargets, "--service-pid", servicePid, "--repo", repo, "--store-root", StorePaths.Root], scratch, env, [],
                        HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(45) }, true, helperGroup, out _, default, v);
                    o["exitHex"] = $"0x{unchecked((uint)pr.ExitCode):X8}";
                    var parsed = JsonNode.Parse(Encoding.UTF8.GetString(pr.Stdout));
                    o["allDenied"] = parsed?["allDenied"]?.DeepClone();
                    o["repoReadable"] = parsed?["repoReadable"]?.DeepClone();
                    var notDenied = new JsonArray();
                    foreach (var kv in parsed?["denials"]?.AsObject() ?? new JsonObject())
                        if (!((string?)kv.Value ?? "").StartsWith("denied", StringComparison.Ordinal)) notDenied.Add($"{kv.Key}: {(string?)kv.Value}");
                    o["notDenied"] = notDenied;
                }
                catch (Exception e) { o["error"] = e.Message; }
                probes.Add(o);
            }
            report["probeVariants"] = probes;
            // Diagnostics: git directly under the full token (both the cmd wrapper and the real binary).
            var gits = new JsonArray();
            HelperTokenVariant? rcVariant = args.Contains("--restricted-code") ? HelperTokenVariant.Full with { Name = "full+RESTRICTED", AllowRestrictedCode = true } : null;
            report["gitDirectVariant"] = rcVariant?.Name ?? "full";
            string mingw = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(git)!)!, "mingw64", "bin", "git.exe");
            foreach (string g in new[] { git, mingw })
            foreach (string[] a in new[] { new[] { "--version" }, new[] { "-C", repo, "rev-parse", "HEAD" }, new[] { "-C", repo, "ls-files" } })
            {
                var o = new JsonObject { ["git"] = g, ["args"] = string.Join(' ', a) };
                try
                {
                    var r = HelperProcess.Run(g, a, scratch, env, [], HelperLimits.Default with { WallTime = TimeSpan.FromSeconds(20) }, true, helperGroup, out _, default, rcVariant);
                    o["exitHex"] = $"0x{unchecked((uint)r.ExitCode):X8}";
                    o["timedOut"] = r.TimedOut;
                    string text = Encoding.UTF8.GetString(r.Stdout);
                    o["stdout"] = text.Length > 200 ? text[..200] : text;
                    o["stderr"] = r.Stderr.Length > 400 ? r.Stderr[..400] : r.Stderr;
                }
                catch (Exception e) { o["error"] = e.Message; }
                gits.Add(o);
            }
            report["gitDirect"] = gits;
        }
        report["verdict"] = anyPass ? "PASS" : "FAIL";
        File.WriteAllText(outPath, report.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"helper feasibility: {report["verdict"]} (report {outPath})");
        return anyPass ? 0 : 1;
    }

    /// <summary>Inside the helper token: attempt every denial of N5-7 and report each outcome. Exit 0 always; the JSON
    /// field allDenied is the verdict.</summary>
    internal static int Probe(string[] args)
    {
        string targets = Arg(args, "--write-targets") ?? "";
        int servicePid = int.TryParse(Arg(args, "--service-pid"), out int p) ? p : 0;
        string? repo = Arg(args, "--repo");
        var o = new JsonObject();
        var denials = new JsonObject();
        var absent = new JsonArray();
        bool all = true;

        // P3.4C-5 Increment 5 (§A.8 N5-7): a target that does not exist is not a denial — it is reported as absent and kept out
        // of allDenied (a "denied" counts only when the target exists and the failure is a genuine access denial).
        void Expect(string name, Action attempt)
        {
            string result;
            bool denied;
            try { attempt(); result = "ALLOWED"; denied = false; }
            catch (UnauthorizedAccessException e) { result = $"denied: {e.Message}"; denied = true; }
            catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
            {
                denials[name] = $"ABSENT (not a denial): {e.Message}";
                absent.Add(name);
                return;
            }
            catch (IOException e) { result = $"denied/io: {e.Message}"; denied = true; }
            catch (Exception e) { result = $"denied/{e.GetType().Name}: {e.Message}"; denied = true; }
            denials[name] = result;
            all &= denied;
        }

        // 1. Reading the custodian's private records (and, from the gate, named run, loop, user-record and intent files that
        // exist then: --extra-read-targets).
        string storeRoot = Arg(args, "--store-root") ?? StorePaths.Root;
        foreach (string f in PrivateFiles(storeRoot)) Expect($"read {f}", () => _ = File.ReadAllBytes(f));
        foreach (string f in (Arg(args, "--extra-read-targets") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries)) Expect($"read {f}", () => _ = File.ReadAllBytes(f));
        Expect($"list {storeRoot}", () => _ = Directory.GetFileSystemEntries(storeRoot));
        // 2. Writing anywhere.
        foreach (string dir in targets.Split(';', StringSplitOptions.RemoveEmptyEntries))
            Expect($"write {dir}", () =>
            {
                string f = Path.Combine(dir, "cp_helper_probe_" + Guid.NewGuid().ToString("N")[..8] + ".tmp");
                File.WriteAllText(f, "x");
                try { File.Delete(f); } catch { /* the write already succeeded: that is what is reported */ }
            });
        // 3. The custodian pipes.
        foreach (string pipe in new[] { CustodianConstants.ImplementerPipe, CustodianConstants.OperatorPipe })
            Expect($"pipe {pipe}", () =>
            {
                using var c = new System.IO.Pipes.NamedPipeClientStream(".", pipe, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.None,
                    System.Security.Principal.TokenImpersonationLevel.Identification);
                c.Connect(3000);
                byte[] req = Encoding.UTF8.GetBytes("{\"v\":1,\"requestId\":\"helper-probe\",\"op\":\"ping\",\"args\":{}}\n");
                c.Write(req);
                c.Flush();
                string line = new StreamReader(c, Encoding.UTF8).ReadLine() ?? "";
                // A response that is not ok is the refusal (the classifier); an ok response is a pass-through.
                var r = JsonNode.Parse(line)!;
                if ((bool?)r["ok"] == true) return;
                throw new UnauthorizedAccessException($"refused by the custodian: {(string?)r["code"]} {(string?)r["error"]}");
            });
        // 4. The service process.
        if (servicePid > 0)
        {
            Expect($"OpenProcess(VM_WRITE|VM_OPERATION) pid {servicePid}", () => OpenOrThrow(servicePid, HelperNative.PROCESS_VM_WRITE | HelperNative.PROCESS_VM_OPERATION));
            Expect($"OpenProcess(TERMINATE) pid {servicePid}", () => OpenOrThrow(servicePid, HelperNative.PROCESS_TERMINATE));
        }
        // Control: the repository IS readable (not a denial).
        if (repo is not null)
        {
            try { o["repoReadable"] = Directory.GetFileSystemEntries(repo).Length > 0; }
            catch (Exception e) { o["repoReadable"] = false; o["repoReadError"] = e.Message; }
        }
        o["denials"] = denials;
        o["absent"] = absent;
        o["allDenied"] = all;
        Console.Out.Write(o.ToJsonString());
        return 0;
    }

    private static void OpenOrThrow(int pid, uint access)
    {
        IntPtr h = HelperNative.OpenProcess(access, false, pid);
        if (h == IntPtr.Zero) throw new UnauthorizedAccessException($"OpenProcess failed ({System.Runtime.InteropServices.Marshal.GetLastWin32Error()})");
        Native.CloseHandle(h);
    }

    private static IEnumerable<string> PrivateFiles(string root)
    {
        foreach (string f in new[] { "custodian-config.json", "ledger.json", "user-records.json", "content-key.secret", "config-records.json", "session.json", "recovery.json", "audit.log" })
            yield return Path.Combine(root, f);
    }

    private static IEnumerable<string> DefaultWriteTargets(string repo, string scratch)
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        yield return StorePaths.Root;
        yield return StorePaths.RunsDir;
        yield return Path.Combine(programData, "CodeParley");
        yield return repo;
        yield return programData;
        yield return Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp");
        yield return scratch;
        yield return @"C:\Users\Public";
    }

    private static string NodeProbeScript(string git, string repo) =>
        "const {spawnSync}=require('child_process');const fs=require('fs');" +
        $"const git={JsonSerializer.Serialize(git)};const repo={JsonSerializer.Serialize(repo)};" +
        "const v=spawnSync(git,['--version'],{encoding:'utf8'});" +
        "const ls=spawnSync(git,['-C',repo,'ls-files','-z'],{encoding:'utf8',maxBuffer:64*1024*1024});" +
        "const head=spawnSync(git,['-C',repo,'rev-parse','HEAD'],{encoding:'utf8'});" +
        "let read=null;try{const f=(ls.stdout||'').split('\\0').filter(Boolean)[0];if(f)read=fs.readFileSync(require('path').join(repo,f)).length;}catch(e){read='ERR '+e.message;}" +
        "let tmpWrite;try{fs.writeFileSync(require('path').join(require('os').tmpdir(),'cp-node-probe.tmp'),'x');tmpWrite='ALLOWED';}catch(e){tmpWrite='denied: '+e.code;}" +
        "const ok=v.status===0&&ls.status===0&&head.status===0&&typeof read==='number'&&tmpWrite!=='ALLOWED';" +
        "process.stdout.write(JSON.stringify({ok,node:process.version,gitVersion:(v.stdout||'').trim(),gitVersionStatus:v.status,gitVersionErr:(v.stderr||String(v.error||'')).slice(0,400)," +
        "lsStatus:ls.status,lsCount:(ls.stdout||'').split('\\0').filter(Boolean).length,lsErr:(ls.stderr||String(ls.error||'')).slice(0,400),headStatus:head.status,head:(head.stdout||'').trim(),readBytes:read,tmpWrite}));";

    private static bool ParsedOk(byte[] stdout, string field)
    {
        try { return (bool?)JsonNode.Parse(Encoding.UTF8.GetString(stdout))?[field] == true; }
        catch (JsonException) { return false; }
    }

    private static JsonObject Outcome(HelperResult r)
    {
        var o = new JsonObject { ["exitCode"] = r.ExitCode, ["exitHex"] = $"0x{unchecked((uint)r.ExitCode):X8}", ["timedOut"] = r.TimedOut, ["overLimit"] = r.OverLimit, ["ms"] = (long)r.Elapsed.TotalMilliseconds };
        string text = Encoding.UTF8.GetString(r.Stdout);
        try { o["stdout"] = JsonNode.Parse(text); }
        catch (JsonException) { o["stdoutText"] = text.Length > 2000 ? text[..2000] : text; }
        if (r.Stderr.Length > 0) o["stderr"] = r.Stderr.Length > 2000 ? r.Stderr[..2000] : r.Stderr;
        return o;
    }

    private static string? Arg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
