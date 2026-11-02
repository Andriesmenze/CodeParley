using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux;

/// <summary>
/// Adversarial self-test of the descriptor-relative filesystem layer, in a private temp directory:
/// symlinked components, absolute and /proc magic links, "..", a FIFO trap, oversized files, a live
/// rename/symlink swap race during removal, and (as root) a no-follow ownership hand-over. Runs once
/// with openat2 and once with the pre-5.6 component walk. Any user may run it; nothing outside the
/// temp directory is touched (the "outside" tree it must protect is inside the temp directory too).
/// </summary>
internal static class SelfTest
{
    private static int _pass, _fail;

    internal static int RunFs(string[] args)
    {
        bool onlyWalk = args.Contains("--force-walk");
        Console.WriteLine($"openat2 available: {Probe()}");
        if (!onlyWalk && Probe()) RunAll(forceWalk: false);
        RunAll(forceWalk: true);
        Console.WriteLine($"selftest-fs: {_pass} passed, {_fail} failed");
        return _fail == 0 ? 0 : 1;
    }

    private static bool Probe()
    {
        bool saved = SafeFs.ForceWalkForSelfTest;
        SafeFs.ForceWalkForSelfTest = false;
        try { return SafeFs.UsesOpenat2; } finally { SafeFs.ForceWalkForSelfTest = saved; }
    }

    private static void RunAll(bool forceWalk)
    {
        SafeFs.ForceWalkForSelfTest = forceWalk;
        string mode = forceWalk ? "walk" : "openat2";
        string tmp = Directory.CreateTempSubdirectory("cp-selftest-").FullName;
        try
        {
            string tree = Path.Combine(tmp, "tree"), outside = Path.Combine(tmp, "outside");
            Directory.CreateDirectory(Path.Combine(tree, "a", "b", "c"));
            Directory.CreateDirectory(outside);
            File.WriteAllText(Path.Combine(tree, "a", "b", "c", "file.txt"), "inside");
            File.WriteAllText(Path.Combine(outside, "secret.txt"), "outside");
            File.CreateSymbolicLink(Path.Combine(tree, "dirlink"), outside);
            File.CreateSymbolicLink(Path.Combine(tree, "a", "filelink"), Path.Combine(outside, "secret.txt"));
            File.CreateSymbolicLink(Path.Combine(tree, "etclink"), "/etc");
            File.CreateSymbolicLink(Path.Combine(tree, "proclink"), "/proc/self/root");
            File.CreateSymbolicLink(Path.Combine(tree, "a", "up"), "../..");
            Libc.Mkfifo(Path.Combine(tree, "fifo"), 0b110_000_000);
            File.WriteAllBytes(Path.Combine(tree, "big.bin"), new byte[300_000]);

            using Fd root = SafeFs.OpenAbsoluteDir(tree);
            Check(mode, "open nested regular file", () => Opens(root, "a/b/c/file.txt"));
            Check(mode, "refuse symlinked directory component", () => !Opens(root, "dirlink/secret.txt"));
            Check(mode, "refuse symlink as last component", () => !Opens(root, "a/filelink"));
            Check(mode, "refuse absolute symlink (/etc)", () => !Opens(root, "etclink/passwd"));
            Check(mode, "refuse /proc magic link", () => !Opens(root, "proclink/etc/passwd"));
            Check(mode, "refuse relative escape link (../..)", () => !Opens(root, "a/up/outside/secret.txt"));
            Check(mode, "reject '..' component", () => Throws<ArgumentException>(() => SafeFs.OpenBeneath(root, "../outside/secret.txt", Libc.O_RDONLY)));
            Check(mode, "reject absolute path", () => Throws<ArgumentException>(() => SafeFs.OpenBeneath(root, "/etc/passwd", Libc.O_RDONLY)));
            Check(mode, "FIFO is refused without blocking", () =>
            {
                Task<bool> t = Task.Run(() => Throws<IOException>(() => SafeFs.ReadFileBeneath(root, "fifo", 1024, out _)));
                return t.Wait(TimeSpan.FromSeconds(5)) && t.Result;
            });
            Check(mode, "bounded read truncates", () =>
                SafeFs.ReadFileBeneath(root, "big.bin", 1000, out bool truncated) is { Length: 1000 } && truncated);

            // Removal never follows links: the "outside" tree survives a removal of everything inside.
            Check(mode, "remove a link as the top entry removes only the link", () =>
                SafeFs.RemoveTree(root, "dirlink", TimeSpan.FromSeconds(30)).Complete
                && File.ReadAllText(Path.Combine(outside, "secret.txt")) == "outside"
                && !Path.Exists(Path.Combine(tree, "dirlink")));

            using (Fd tmpFd = SafeFs.OpenAbsoluteDir(tmp))
            {
                RemoveReport rep = SafeFs.RemoveTree(tmpFd, "tree", TimeSpan.FromSeconds(30));
                Check(mode, "remove whole tree (links, FIFO, nested) completely", () => rep.Complete && !Path.Exists(tree));
                Check(mode, "outside content untouched by removal", () =>
                    File.ReadAllText(Path.Combine(outside, "secret.txt")) == "outside" && Directory.Exists("/etc"));
            }

            Check(mode, "rename/symlink swap race during removal cannot reach outside", () => SwapRace(tmp, outside));

            if (Libc.geteuid() == 0) Check(mode, "ownership hand-over never follows links (root)", () => ChownNoFollow(tmp, outside));
        }
        catch (Exception e) { Fail(mode, "self-test setup", e.ToString()); }
        finally
        {
            SafeFs.ForceWalkForSelfTest = false;
            try { Directory.Delete(tmp, recursive: true); } catch { /* best effort */ }
        }
    }

    private static bool SwapRace(string tmp, string outside)
    {
        string victim = Path.Combine(tmp, "race");
        for (int i = 0; i < 200; i++)
        {
            string d = Path.Combine(victim, "d" + i, "sub");
            Directory.CreateDirectory(d);
            File.WriteAllText(Path.Combine(d, "f.txt"), "x");
        }
        File.WriteAllText(Path.Combine(outside, "keep.txt"), "keep");
        using var stop = new CancellationTokenSource();
        Task attacker = Task.Run(() =>
        {
            int n = 0;
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    string target = Path.Combine(victim, "d" + (n % 200));
                    string moved = target + "-moved";
                    if (Directory.Exists(target) && !Path.Exists(moved)) Directory.Move(target, moved);
                    if (!Path.Exists(target)) Directory.CreateSymbolicLink(target, outside);
                }
                catch { /* the remover is racing us; keep going */ }
                n++;
            }
        });
        using (Fd tmpFd = SafeFs.OpenAbsoluteDir(tmp))
        {
            for (int pass = 0; pass < 20 && Path.Exists(victim); pass++)
                SafeFs.RemoveTree(tmpFd, "race", TimeSpan.FromSeconds(30));
        }
        stop.Cancel();
        attacker.Wait(TimeSpan.FromSeconds(10));
        using (Fd tmpFd = SafeFs.OpenAbsoluteDir(tmp)) SafeFs.RemoveTree(tmpFd, "race", TimeSpan.FromSeconds(30));
        return File.Exists(Path.Combine(outside, "keep.txt")) && File.Exists(Path.Combine(outside, "secret.txt"));
    }

    private static bool ChownNoFollow(string tmp, string outside)
    {
        string t = Path.Combine(tmp, "chown");
        Directory.CreateDirectory(Path.Combine(t, "x"));
        File.WriteAllText(Path.Combine(t, "x", "f"), "f");
        File.CreateSymbolicLink(Path.Combine(t, "x", "link"), Path.Combine(outside, "secret.txt"));
        File.CreateSymbolicLink(Path.Combine(t, "dlink"), outside);
        using (Fd fd = SafeFs.OpenAbsoluteDir(t)) SafeFs.ChownTree(fd, 65534, 65534);
        bool insideChanged = Stat(Path.Combine(t, "x", "f")).Uid == 65534 && Stat(Path.Combine(t, "x", "link")).Uid == 65534;
        bool outsideKept = Stat(Path.Combine(outside, "secret.txt")).Uid == 0 && Stat(outside).Uid == 0;
        return insideChanged && outsideKept;
    }

    private static Libc.Statx Stat(string path)
    {
        if (Libc.StatxAt(Libc.AT_FDCWD, path, Libc.AT_SYMLINK_NOFOLLOW, out Libc.Statx st) != 0) throw new IOException("stat " + path);
        return st;
    }

    private static bool Opens(Fd root, string rel)
    {
        (int fd, _) = SafeFs.OpenBeneathRaw(root, rel, Libc.O_RDONLY | Libc.O_NONBLOCK);
        if (fd < 0) return false;
        Libc.close(fd);
        return true;
    }

    private static bool Throws<T>(Action a) where T : Exception
    {
        try { a(); return false; }
        catch (T) { return true; }
    }

    private static void Check(string mode, string name, Func<bool> test)
    {
        try
        {
            if (test()) { _pass++; Console.WriteLine($"PASS [{mode}] {name}"); }
            else Fail(mode, name, "assertion failed");
        }
        catch (Exception e) { Fail(mode, name, e.Message); }
    }

    private static void Fail(string mode, string name, string detail)
    {
        _fail++;
        Console.WriteLine($"FAIL [{mode}] {name}: {detail}");
    }
}
