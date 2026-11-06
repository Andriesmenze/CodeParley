using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 6 Increment 2 (contract §7 b): the engine runtime without bundled Git, on either host. A scratch runtime (the
/// host's node image and the helper entry) and an installed git outside it (the host's git image) are measured with the
/// host's measurement — ownership checks skipped, as a non-privileged self-test cannot make its files root- or
/// administrator-owned (the Windows ledger self-test and the native VM check the refusal of a user-writable git).
/// </summary>
internal static class RuntimeGitSelfTest
{
    internal static int Run()
    {
        string scratch = Path.Combine(Path.GetTempPath(), "cp-rtgit-" + Guid.NewGuid().ToString("N")[..8]);
        int failed = 0;
        try
        {
            Platform.Images.SkipOwnershipChecksForSelfTest();
            string gitName = Platform.Images.FixtureRuntimeGit.Split('/')[^1];
            string runtime = Path.Combine(scratch, "engine");
            Directory.CreateDirectory(Path.Combine(runtime, "dist", "helper"));
            File.WriteAllBytes(Path.Combine(runtime, Platform.Images.NodeName), Platform.Images.FixtureImage(1));
            File.WriteAllText(Path.Combine(runtime, "dist", "helper", "main.js"), "// helper\n");
            string gitDir = Path.Combine(scratch, "git", "bin");
            Directory.CreateDirectory(gitDir);
            string git = Path.Combine(gitDir, gitName);
            File.WriteAllBytes(git, Platform.Images.FixtureImage(2));
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(git, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

            MeasuredRuntime m = EngineRuntime.Measure(runtime, null, git);
            failed += Check("the tree hashed per launch holds only Node and the engine; the installed git is outside it", m.FileCount == 2 && m.GitRelative is null && m.GitPath is not null && m.Git.Sha256.Length == 64);
            failed += Check("the helper runs the installed git", EngineRuntime.GitExecutable(m) == m.GitPath);
            failed += Check("the record names gitPath, not gitRelative", EngineRuntime.Content(m) is var c && c["gitPath"] is not null && !c.ContainsKey("gitRelative"));
            failed += Check("an unchanged installation measures the same", EngineRuntime.Differences(EngineRuntime.Content(m), EngineRuntime.Measure(runtime, null, git)).Count == 0);
            File.WriteAllBytes(git, Platform.Images.FixtureImage(3));
            failed += Check("a changed installed git is a difference", EngineRuntime.Differences(EngineRuntime.Content(m), EngineRuntime.Measure(runtime, null, git)).Contains("git"));
            failed += Check("an installed git under another name is refused", Refused(() => EngineRuntime.Measure(runtime, null, Path.Combine(gitDir, "sh"))));
            failed += Check("exactly one git: neither is refused", Refused(() => EngineRuntime.Measure(runtime, null, null)));
            // A Node.js upgrade (D-98): the measured runtime's node replaced by another image of the host's form.
            MeasuredRuntime before = EngineRuntime.Measure(runtime, null, git);
            File.WriteAllBytes(Path.Combine(runtime, Platform.Images.NodeName), Platform.Images.FixtureImage(4));
            List<string> nodeDiff = EngineRuntime.Differences(EngineRuntime.Content(before), EngineRuntime.Measure(runtime, null, git));
            failed += Check("a replaced node image (a Node.js upgrade) is a difference in the node entry and the tree digest", nodeDiff.Contains("node.exe") && nodeDiff.Contains("tree digest"));
        }
        catch (Exception e)
        {
            Console.WriteLine($"[FAIL] unexpected: {e.GetType().Name}: {e.Message}");
            failed++;
        }
        finally
        {
            try { Directory.Delete(scratch, true); } catch { /* best effort */ }
        }
        Console.WriteLine($"\nruntime-git self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    private static bool Refused(Action a)
    {
        try { a(); return false; }
        catch (Ipc.CustodianRefusal) { return true; }
    }

    private static int Check(string name, bool ok)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        return ok ? 0 : 1;
    }
}
