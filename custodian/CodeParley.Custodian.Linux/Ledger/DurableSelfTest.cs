using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Linux.Ledger;

/// <summary>
/// Phase 5 F-8: the store's durable write through the Linux host, into a scratch store root. An intent (and the content-key
/// path) must land 0600 — granting the store group nothing, as the start-time check requires — while a shared store file
/// keeps its group read; no temporary file is left. Exit 0 only when every case holds.
/// </summary>
internal static class DurableSelfTest
{
    internal static int Run()
    {
        int failed = 0, passed = 0;
        void Check(string name, bool ok, string detail)
        {
            if (ok) passed++; else failed++;
            Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}: {detail}");
        }
        string root = Directory.CreateTempSubdirectory("cp-durable-").FullName;
        IDurableFiles saved = Platform.Durable;
        try
        {
            Platform.Durable = new LinuxDurableFiles(root);
            Directory.CreateDirectory(Path.Combine(root, "intents"), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string intent = Path.Combine(root, "intents", "01a15b80-0000-7000-8000-000000000001.json");
            string ledger = Path.Combine(root, "ledger.json");
            string key = Path.Combine(root, "content-key.secret");
            DurableStore.Replace(intent, "{\"intent\":1}");
            DurableStore.Replace(intent, "{\"intent\":2}"); // a rewrite stays private too
            DurableStore.Replace(ledger, "{\"ledger\":1}");
            DurableStore.Replace(key, "{\"key\":1}");
            UnixFileMode Mode(string p) => File.GetUnixFileMode(p);
            Check("an intent is written 0600", Mode(intent) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), Mode(intent).ToString());
            Check("the intent's content is the last write", File.ReadAllText(intent) == "{\"intent\":2}", File.ReadAllText(intent));
            Check("the content-key path is written 0600", Mode(key) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), Mode(key).ToString());
            Check("a shared store file keeps its group read (not narrowed)", (Mode(ledger) & UnixFileMode.GroupRead) != 0, Mode(ledger).ToString());
            string[] left = Directory.EnumerateFiles(root, "*.tmp-*", SearchOption.AllDirectories).ToArray();
            Check("no temporary file is left", left.Length == 0, string.Join(", ", left));
        }
        catch (Exception e) { Check("the durable writes completed", false, e.Message); }
        finally
        {
            Platform.Durable = saved;
            try { Directory.Delete(root, recursive: true); } catch (IOException) { }
        }
        Console.WriteLine($"durable self-test: {passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }
}
