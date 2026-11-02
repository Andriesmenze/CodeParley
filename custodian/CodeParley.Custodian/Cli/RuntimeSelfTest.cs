using System.Diagnostics;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED self-test of the approved engine runtime (P3.4C-5 contract §2.1, N5-6): the measurement and the
/// <c>engine_runtime</c> configuration record's lifecycle, on a scratch tree. A scratch tree is owned by the current user,
/// so the first case shows that refused; the others measure it with the administrator-control check switched off for the
/// rest of this process (self-test only) — that check runs on the VM against an administrator-installed tree.
/// </summary>
internal static class RuntimeSelfTest
{
    private sealed class Boot(DateTime value) : IBootIdentity
    {
        internal DateTime Value { get; set; } = value;
        public DateTime? BootTimeUtc() => Value;
    }

    internal static int Run(string work)
    {
        int failed = 0;
        string pe = Environment.ProcessPath!; // a native PE image to stand in for node.exe and git.exe
        string root = Path.Combine(work, "engine", "rt1");
        Build(root, pe);

        failed += Check("a user-owned (user-writable) runtime tree is refused (RUNTIME_NOT_APPROVED)",
            Refuses(() => EngineRuntime.Measure(root, "git/mingw64/bin/git.exe"), "RUNTIME_NOT_APPROVED"));

        // Phase 6 (§7 b): an installed git outside the runtime, measured as Codex is.
        string noGit = Path.Combine(work, "engine", "rt-nogit");
        Build(noGit, pe);
        Directory.Delete(Path.Combine(noGit, "git"), true);
        string gitDir = Path.Combine(work, "git-installed", "mingw64", "bin");
        Directory.CreateDirectory(gitDir);
        string gitExe = Path.Combine(gitDir, "git.exe");
        File.Copy(pe, gitExe, true);
        failed += Check("Phase 6 §7 b: an installed git a user can write (not administrator-controlled) is refused",
            Refuses(() => EngineRuntime.Measure(noGit, null, gitExe), "RUNTIME_NOT_APPROVED"));

        WindowsEngineRuntime.SkipAclCheckForSelfTest();
        failed += InstalledGitCases(root, noGit, gitExe);
        MeasuredRuntime m = EngineRuntime.Measure(root, "git/mingw64/bin/git.exe");
        failed += Check("the measurement covers every file (node, git, entry, prompts) with a tree digest", m.FileCount == 4 && m.TreeDigest.Length == 64 && m.Node.Form == CodexImage.NativePe);
        failed += Check("a second measurement of the unchanged tree is identical", EngineRuntime.Differences(EngineRuntime.Content(m), EngineRuntime.Measure(root, "git/mingw64/bin/git.exe")).Count == 0);
        File.AppendAllText(Path.Combine(root, "dist", "helper", "main.js"), "// changed\n");
        List<string> diff = EngineRuntime.Differences(EngineRuntime.Content(m), EngineRuntime.Measure(root, "git/mingw64/bin/git.exe"));
        failed += Check("a changed entry file changes the entry hash and the tree digest", diff.Contains("helper entry") && diff.Contains("tree digest"));
        File.WriteAllText(Path.Combine(root, "dist", "extra.js"), "x");
        failed += Check("an added file changes the tree digest", EngineRuntime.Differences(EngineRuntime.Content(m), EngineRuntime.Measure(root, "git/mingw64/bin/git.exe")).Contains("tree digest"));
        File.Delete(Path.Combine(root, "dist", "extra.js"));

        string linkRoot = Path.Combine(work, "engine", "link-to-rt1");
        if (Cmd($"/c mklink /J \"{linkRoot}\" \"{root}\"") && Directory.Exists(linkRoot))
            failed += Check("a runtime reached through a junction is refused (no-follow walk)", Refuses(() => EngineRuntime.Measure(linkRoot, "git/mingw64/bin/git.exe"), "runtime"));
        string inner = Path.Combine(root, "dist", "linked");
        if (Cmd($"/c mklink /J \"{inner}\" \"{work}\"") && Directory.Exists(inner))
        {
            failed += Check("a junction inside the runtime is refused", Refuses(() => EngineRuntime.Measure(root, "git/mingw64/bin/git.exe"), "reparse point"));
            Directory.Delete(inner);
        }
        failed += Check("a git path that leaves the runtime is refused", Refuses(() => EngineRuntime.Measure(root, "../git.exe"), "git"));
        failed += Check("a git path that is not git.exe is refused", Refuses(() => EngineRuntime.Measure(root, "git/mingw64/bin/sh.exe"), "git"));
        string noEntry = Path.Combine(work, "engine", "rt-noentry");
        Build(noEntry, pe);
        File.Delete(Path.Combine(noEntry, "dist", "helper", "main.js"));
        failed += Check("a runtime without the helper entry is refused", Refuses(() => EngineRuntime.Measure(noEntry, "git/mingw64/bin/git.exe"), "helper entry"));
        string script = Path.Combine(work, "engine", "rt-script");
        Build(script, pe);
        File.WriteAllText(Path.Combine(script, "node.exe"), "@echo not a PE");
        failed += Check("a node.exe that is not a native PE image is refused", Refuses(() => EngineRuntime.Measure(script, "git/mingw64/bin/git.exe"), "not a supported native image"));

        failed += LedgerCases(root);
        return failed;
    }

    /// <summary>Phase 6 (§7 b): the runtime without bundled Git — the tree hashed per launch is Node and the engine, and the
    /// installed git is measured (its image) and named outside it; the in-tree form is unchanged.</summary>
    private static int InstalledGitCases(string inTree, string noGit, string gitExe)
    {
        int failed = 0;
        MeasuredRuntime legacy = EngineRuntime.Measure(inTree, "git/mingw64/bin/git.exe");
        MeasuredRuntime m = EngineRuntime.Measure(noGit, null, gitExe);
        JsonObject content = EngineRuntime.Content(m);
        failed += Check("Phase 6 §7 b: with an installed git the tree hashed per launch holds only Node and the engine (3 files, not the 4 with git)",
            m.FileCount == legacy.FileCount - 1 && m.GitRelative is null && string.Equals(m.GitPath, gitExe, StringComparison.OrdinalIgnoreCase) && m.Git.Sha256 == legacy.Git.Sha256);
        failed += Check("... the record names the installed git (gitPath) and no in-tree git; the helper runs that git",
            content["gitPath"] is not null && !content.ContainsKey("gitRelative") && string.Equals(EngineRuntime.GitExecutable(m), gitExe, StringComparison.OrdinalIgnoreCase));
        failed += Check("... an unchanged installation measures the same", EngineRuntime.Differences(content, EngineRuntime.Measure(noGit, null, gitExe)).Count == 0);
        failed += Check("... an in-tree record and an installed-git record differ in the git location", EngineRuntime.Differences(EngineRuntime.Content(legacy), m).Contains("git location"));
        byte[] original = File.ReadAllBytes(gitExe);
        File.AppendAllText(gitExe, "changed");
        failed += Check("... a changed installed git image is a difference (refused until approved again)", EngineRuntime.Differences(content, EngineRuntime.Measure(noGit, null, gitExe)).Contains("git"));
        File.WriteAllBytes(gitExe, original);
        failed += Check("... exactly one git: none or both is refused",
            Refuses(() => EngineRuntime.Measure(noGit, null, null), "exactly one") && Refuses(() => EngineRuntime.Measure(inTree, "git/mingw64/bin/git.exe", gitExe), "exactly one"));
        failed += Check("... an installed git path that is not git.exe is refused", Refuses(() => EngineRuntime.Measure(noGit, null, Path.ChangeExtension(gitExe, ".cmd")), "git.exe"));
        failed += Check("... the approval payload takes git or gitPath, exactly one",
            ConfigValidation.EngineRuntimePayload(new JsonObject { ["path"] = noGit, ["gitPath"] = gitExe })["gitPath"] is not null
            && Throws(() => ConfigValidation.EngineRuntimePayload(new JsonObject { ["path"] = noGit }))
            && Throws(() => ConfigValidation.EngineRuntimePayload(new JsonObject { ["path"] = noGit, ["git"] = "git/mingw64/bin/git.exe", ["gitPath"] = gitExe })));
        return failed;
    }

    private static bool Throws(Action a)
    {
        try { a(); return false; }
        catch (ArgumentException) { return true; }
    }

    /// <summary>The <c>engine_runtime</c> record through the operator's prepare/commit: measured content, a change between
    /// prepare and commit refused, supersede, revoke, the U4b lapse after a new boot and a re-confirmation only of the
    /// unchanged tree.</summary>
    private static int LedgerCases(string root)
    {
        int failed = 0;
        Directory.CreateDirectory(StorePaths.IntentsDir);
        var boot = new Boot(new DateTime(2026, 10, 16, 8, 0, 0, DateTimeKind.Utc));
        var led = new GrantLedger("cust-selftest");
        led.StartupRecovery(boot);
        var payload = new JsonObject { ["path"] = root, ["git"] = "git/mingw64/bin/git.exe" };
        int G() => GrantLedger.ReadConfigRecordsLocked().GlobalRevision;
        JsonObject? Section() => (JsonObject?)led.ListUserRecords(root, "run-rt-1", operatorView: true, new HashSet<string> { "config" })["config"]?["engineRuntime"];

        PreparedAuthorization p1 = led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Set, null, payload, G(), "rt-set-1");
        failed += Check("prepare renders the measured runtime for the operator", p1.Rendering.Contains("Approve the CodeParley engine runtime", StringComparison.Ordinal) && p1.Rendering.Contains("tree ", StringComparison.Ordinal));
        failed += Check("a forged measured field in the payload is refused (the payload is path + git only)",
            Refuses(() => led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Set, null, new JsonObject { ["path"] = root, ["git"] = "git/mingw64/bin/git.exe", ["treeDigest"] = new string('0', 64) }, G(), "rt-forge"), "unexpected key"));
        led.Commit("rt-set-1", "proof-rt");
        JsonObject? s1 = Section();
        string id1 = (string)s1!["runtimeId"]!;
        failed += Check("committed: the config section reports the approved runtime in force (usable)", (bool?)s1["usable"] == true && (string?)s1["treeDigest"] is { Length: 64 });

        led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Set, null, payload, G(), "rt-set-2");
        File.WriteAllText(Path.Combine(root, "prompts", "p.md"), "changed between prepare and commit");
        failed += Check("a runtime that changed between prepare and commit is refused (STALE_CONFIG), nothing recorded", Refuses(() => led.Commit("rt-set-2", null), "STALE_CONFIG") && (string?)Section()!["runtimeId"] == id1);

        led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Set, null, payload, G(), "rt-set-3");
        led.Commit("rt-set-3", null);
        string id2 = (string)Section()!["runtimeId"]!;
        failed += Check("a new approval supersedes the previous one", id2 != id1 && GrantLedger.ReadConfigRecordsLocked().Runtimes.Single(r => r.RuntimeId == id1).SupersededAt is not null);

        // A new boot: recovery U4b lapses the approval; the re-confirmation measures the tree again.
        boot.Value = boot.Value.AddHours(2);
        new GrantLedger("cust-selftest").StartupRecovery(boot);
        failed += Check("after a new boot the approval is lapsed (U4b) and not usable", Section() is { } lapsed && (bool?)lapsed["lapsed"] == true && (bool?)lapsed["usable"] == false);
        File.AppendAllText(Path.Combine(root, "prompts", "p.md"), "+");
        failed += Check("re-confirming a runtime that changed since its approval is refused (CONFIG_MISMATCH)",
            Refuses(() => led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Reconfirm, id2, null, G(), "rt-rc-1"), "CONFIG_MISMATCH"));
        File.WriteAllText(Path.Combine(root, "prompts", "p.md"), "changed between prepare and commit"); // back to the approved bytes
        led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Reconfirm, id2, null, G(), "rt-rc-2");
        led.Commit("rt-rc-2", null);
        failed += Check("re-confirming the unchanged runtime restores it (usable)", (bool?)Section()!["usable"] == true);

        led.PrepareConfigRecord(null, ConfigKinds.EngineRuntime, ConfigKinds.Revoke, id2, null, G(), "rt-rv-1");
        led.Commit("rt-rv-1", null);
        failed += Check("a revoked runtime is not usable", Section() is { } rv && (bool?)rv["revoked"] == true && (bool?)rv["usable"] == false);
        failed += Check("the implementer projection of the runtime omits the recorder",
            led.ListUserRecords(root, "run-rt-1", operatorView: false, new HashSet<string> { "config" })["config"]?["engineRuntime"] is JsonObject impl && impl["recordedBy"] is null);
        return failed;
    }

    private static void Build(string root, string pe)
    {
        Directory.CreateDirectory(Path.Combine(root, "dist", "helper"));
        Directory.CreateDirectory(Path.Combine(root, "git", "mingw64", "bin"));
        Directory.CreateDirectory(Path.Combine(root, "prompts"));
        File.Copy(pe, Path.Combine(root, "node.exe"), overwrite: true);
        File.Copy(pe, Path.Combine(root, "git", "mingw64", "bin", "git.exe"), overwrite: true);
        File.WriteAllText(Path.Combine(root, "dist", "helper", "main.js"), "// helper entry\n");
        File.WriteAllText(Path.Combine(root, "prompts", "p.md"), "prompt\n");
    }

    private static bool Refuses(Action a, string expect)
    {
        try { a(); return false; }
        catch (Exception e) { return e.Message.Contains(expect, StringComparison.Ordinal); }
    }

    private static bool Cmd(string arguments)
    {
        var psi = new ProcessStartInfo("cmd.exe", arguments) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        using Process p = Process.Start(psi)!;
        p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit();
        return p.ExitCode == 0;
    }

    private static int Check(string name, bool ok) => HelperChannelSelfTest.Check(name, ok);
}
