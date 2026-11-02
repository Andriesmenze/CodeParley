using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED self-test of the repository identity (P3.4C-0, TD decision 3), runnable by the
/// implementer session. Three parts, each recorded as evidence:
///   A. the pre-P3.4C-0 TEXTUAL key's actual behaviour on real aliases (the weakness being replaced);
///   B. the handle-backed identity as the calling user: the same key for every supported spelling,
///      a refusal for every redirecting or ambiguous form, a new key after replacement;
///   C. the identity under an EMULATED service-class token — a restricted token whose access checks
///      pass only where Everyone/Users/Authenticated Users/SERVICE/LOCAL/This Organization or the
///      custodian SID are granted, keeping the bypass-traverse privilege, as the custodian's virtual
///      account would. This is an emulation on the dev host (INFERRED), not the real service account;
///      the real service is verified on the disposable VM (increment 3).
/// Creates and removes its scratch tree; a temporary drive alias (DefineDosDevice, this logon session
/// only) is removed in a finally block. Nothing outside the scratch tree is modified.
/// </summary>
internal static class IdentitySelfTest
{
    private static int _failed;
    private static readonly JsonObject Evidence = new();

    internal static int Run(string[] args)
    {
        string baseDir = GetArg(args, "--scratch-base") ?? Path.GetTempPath();
        string scratch = Path.Combine(baseDir, "cp-identity-" + Guid.NewGuid().ToString("N")[..8]);
        string? substLetter = null;
        try
        {
            Directory.CreateDirectory(scratch);
            scratch = RepoIdentities.Resolve(scratch).CanonicalPath; // the long, real spelling
            Evidence["host"] = $"{Environment.OSVersion.VersionString}; user {WindowsIdentity.GetCurrent().Name}";
            Evidence["scratch"] = scratch;
            string repo = Path.Combine(scratch, "Repository With A Long Name");
            string other = Path.Combine(scratch, "Other");
            Directory.CreateDirectory(repo);
            Directory.CreateDirectory(other);
            Directory.CreateDirectory(Path.Combine(repo, "sub"));

            PartB(scratch, repo, other, ref substLetter);
            PartA(scratch, repo);
            PartC(scratch, repo, args);

            Console.WriteLine();
            Console.WriteLine(Evidence.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"\nidentity self-test: {(_failed == 0 ? "all checks passed" : _failed + " FAILED")}");
            return _failed == 0 ? 0 : 1;
        }
        finally
        {
            if (substLetter is not null) Native.DefineDosDeviceW(Native.DDD_REMOVE_DEFINITION, substLetter, null);
            RemoveTree(scratch);
        }
    }

    // ---- B: the handle-backed identity as the calling user ----

    private static void PartB(string scratch, string repo, string other, ref string? substLetter)
    {
        Console.WriteLine("== B. handle-backed identity (calling user)");
        var b = new JsonObject();
        RepoIdentity id = RepoIdentities.Resolve(repo);
        b["key"] = id.Key;
        b["canonical"] = id.CanonicalPath;
        b["fileSystem"] = id.FileSystem;
        Check("resolves a real directory to a fid1 key", RepoIdentities.IsCurrent(id.Key));
        Check("canonical path is the real path", string.Equals(id.CanonicalPath, repo, StringComparison.Ordinal));

        // Supported spellings of the SAME directory: one identity.
        Same(b, "forward slashes", repo.Replace('\\', '/'), id.Key);
        Same(b, "trailing separator", repo + "\\", id.Key);
        Same(b, "upper case", repo.ToUpperInvariant(), id.Key);
        Same(b, "lower case", repo.ToLowerInvariant(), id.Key);
        string? shortName = ShortPath(repo);
        if (shortName is not null && !string.Equals(shortName, repo, StringComparison.OrdinalIgnoreCase))
        {
            b["shortPath"] = shortName;
            Same(b, "8.3 short name", shortName, id.Key);
        }
        else Info(b, "8.3 short name", "no short name exists on this volume (8.3 generation off): not tested here");

        // A different directory: a different identity.
        Check("a different directory has a different key", RepoIdentities.Resolve(other).Key != id.Key);

        // Redirecting or ambiguous forms: refused, never guessed.
        string junction = Path.Combine(scratch, "junction-to-repo");
        bool hasJunction = TryCmd($"/c mklink /J \"{junction}\" \"{repo}\"");
        if (hasJunction) Refused(b, "junction to the repository", junction);
        string junctionParent = Path.Combine(scratch, "junction-to-scratch");
        if (TryCmd($"/c mklink /J \"{junctionParent}\" \"{scratch}\""))
            Refused(b, "path through a junction (intermediate component)", Path.Combine(junctionParent, Path.GetFileName(repo)));
        string symlink = Path.Combine(scratch, "symlink-to-repo");
        try { Directory.CreateSymbolicLink(symlink, repo); Refused(b, "directory symbolic link", symlink); }
        catch (Exception e) { Info(b, "directory symbolic link", "not creatable here: " + e.Message.Split('\n')[0]); }
        Refused(b, "'..' component", Path.Combine(repo, "sub", "..").Replace('/', '\\'));
        Refused(b, "'.' component", repo + "\\.\\sub");
        Refused(b, "trailing dot", repo + ".");
        Refused(b, "trailing space", repo + " ");
        Refused(b, @"\\?\ prefix", @"\\?\" + repo);
        Refused(b, "UNC administrative share", $@"\\localhost\{repo[0]}$\{repo[3..]}");
        Refused(b, "relative path", "Repository");
        Refused(b, "drive-relative path", repo[..2] + "Repository");
        Refused(b, "alternate data stream", repo + ":stream");
        Refused(b, "non-existent directory", Path.Combine(scratch, "missing"));
        string file = Path.Combine(scratch, "a-file.txt");
        File.WriteAllText(file, "x");
        Refused(b, "a file, not a directory", file);
        Refused(b, "reserved device name", Path.Combine(scratch, "NUL"));

        // A drive letter aliased to a folder (subst; this logon session only).
        substLetter = FreeDriveLetter();
        if (substLetter is not null && Native.DefineDosDeviceW(0, substLetter, scratch))
            Refused(b, $"substituted drive {substLetter}", substLetter + "\\" + Path.GetFileName(repo));
        else { Info(b, "substituted drive", "no free drive letter / DefineDosDevice failed: not tested"); substLetter = null; }

        // Replacement: delete + recreate at the same path is a NEW identity; a rename keeps it.
        string repl = Path.Combine(scratch, "replaced");
        Directory.CreateDirectory(repl);
        string k1 = RepoIdentities.Resolve(repl).Key;
        Directory.Delete(repl);
        Directory.CreateDirectory(repl);
        string k2 = RepoIdentities.Resolve(repl).Key;
        b["replacement"] = new JsonObject { ["before"] = k1, ["after"] = k2 };
        Check("a replaced directory (delete + recreate, same path) gets a new key", k1 != k2);
        string moved = Path.Combine(scratch, "moved");
        Directory.Move(repl, moved);
        Check("a renamed directory keeps its key (identity follows the object)", RepoIdentities.Resolve(moved).Key == k2);

        // Two directories whose names differ only in case (a case-sensitive directory).
        // fsutil exits 0 even when it fails (measured: "Access is denied" without elevation or WSL on this
        // host), so the flag is confirmed by a query and the pair by a listing, never by the exit code.
        string cs = Path.Combine(scratch, "case-sensitive");
        Directory.CreateDirectory(cs);
        TryProcess("fsutil.exe", $"file setCaseSensitiveInfo \"{cs}\" enable", out string fsOut);
        TryProcess("fsutil.exe", $"file queryCaseSensitiveInfo \"{cs}\"", out string fsQuery);
        bool caseSensitive = fsQuery.Contains("is enabled", StringComparison.OrdinalIgnoreCase);
        if (caseSensitive)
        {
            Directory.CreateDirectory(Path.Combine(cs, "Repo"));
            Directory.CreateDirectory(Path.Combine(cs, "repo"));
        }
        if (caseSensitive && Directory.GetDirectories(cs).Length == 2)
        {
            string upper = RepoIdentities.Resolve(Path.Combine(cs, "Repo")).Key, lower = RepoIdentities.Resolve(Path.Combine(cs, "repo")).Key;
            b["caseSensitivePair"] = new JsonObject { ["Repo"] = upper, ["repo"] = lower };
            Check("'Repo' and 'repo' in a case-sensitive directory are different identities", upper != lower);
        }
        else Info(b, "case-sensitive directory", "per-directory case sensitivity could not be enabled here (" + (fsOut + " " + fsQuery).Replace('\r', ' ').Replace('\n', ' ').Trim() + "): not tested live");

        // File-id reuse: create and delete directories; NTFS reuses MFT records but with a new sequence
        // number, so the 128-bit id must never repeat.
        string reuseDir = Path.Combine(scratch, "reuse");
        Directory.CreateDirectory(reuseDir);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var records = new Dictionary<string, int>(StringComparer.Ordinal);
        const int rounds = 300;
        for (int i = 0; i < rounds; i++)
        {
            string d = Path.Combine(reuseDir, "d");
            Directory.CreateDirectory(d);
            string key = RepoIdentities.Resolve(d).Key;
            Directory.Delete(d);
            ids.Add(key);
            string record = key.Split('-')[2][..12]; // NTFS: the low 48 bits (little-endian) are the MFT record
            records[record] = records.GetValueOrDefault(record) + 1;
        }
        int reusedRecords = records.Count(kv => kv.Value > 1);
        b["reuseProbe"] = new JsonObject { ["rounds"] = rounds, ["distinctIds"] = ids.Count, ["mftRecordsReused"] = reusedRecords };
        Check($"file-id reuse: {rounds} create/delete rounds gave {ids.Count} distinct ids ({reusedRecords} MFT record(s) reused with a new sequence number)", ids.Count == rounds);
        Evidence["B_handleIdentity"] = b;
    }

    // ---- A: the pre-P3.4C-0 textual key on the same aliases ----

    private static void PartA(string scratch, string repo)
    {
        Console.WriteLine("== A. legacy textual key (pre-P3.4C-0) on real aliases");
        var a = new JsonObject();
        string legacy = LegacyTextKey(repo);
        a["key"] = legacy;
        string? shortName = ShortPath(repo);
        if (shortName is not null && !string.Equals(shortName, repo, StringComparison.OrdinalIgnoreCase))
            Observe(a, "8.3 alias of the same directory gets a DIFFERENT textual key (a revoke via one spelling misses a grant via the other)", LegacyTextKey(shortName) != legacy);
        Observe(a, @"\\?\ spelling of the same directory gets a DIFFERENT textual key", LegacyTextKey(@"\\?\" + repo) != legacy);
        Observe(a, "'..' spelling of the same directory gets a DIFFERENT textual key", LegacyTextKey(Path.Combine(repo, "sub") + "\\..") != legacy);
        string cs = Path.Combine(scratch, "case-sensitive");
        if (Directory.Exists(cs) && Directory.GetDirectories(cs).Length == 2)
            Observe(a, "two DIFFERENT directories ('Repo'/'repo', case-sensitive dir) COLLIDE on one textual key (a grant for one is consumable by the other)", LegacyTextKey(Path.Combine(cs, "Repo")) == LegacyTextKey(Path.Combine(cs, "repo")));
        else
            a["byConstruction:caseCollision"] = "lower-casing maps two directories whose names differ only in case (possible in a case-sensitive directory) to one textual key; not demonstrated live because case sensitivity could not be enabled without elevation here";
        // By construction (a pure function of the spelling), not an observation: a directory replaced at the
        // same path keeps its textual key, so a grant follows the spelling to whatever object is there now.
        a["byConstruction"] = "a textual key is a function of the spelling only: it cannot tell a replaced directory (or a junction's new target) from the original";
        string junction = Path.Combine(scratch, "junction-to-repo");
        if (Directory.Exists(junction))
            Observe(a, "a junction path is hashed as text (no link check: the grant applies to whatever the junction points to)", LegacyTextKey(junction) != legacy);
        Evidence["A_legacyTextualKey"] = a;
    }

    /// <summary>The removed pre-P3.4C-0 derivation, reproduced only to record its behaviour.</summary>
    private static string LegacyTextKey(string repositoryRoot)
    {
        string norm = repositoryRoot.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(norm))).ToLowerInvariant()[..16];
    }

    // ---- C: an emulated service-class token ----

    private static readonly string[] ServiceClassSids = ["S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-6", "S-1-2-0", "S-1-5-15"];

    private static readonly WindowsRepoIdentities.WalkAccess[] Variants =
    [
        WindowsRepoIdentities.Production,
        new("zero-access", 0, 0, 0),
        new("synchronize+read-attributes", Native.FILE_READ_ATTRIBUTES | Native.SYNCHRONIZE, Native.SYNCHRONIZE | Native.FILE_READ_ATTRIBUTES_NT, Native.SYNCHRONIZE | Native.FILE_READ_ATTRIBUTES_NT),
        new("traverse+read-attributes", Native.FILE_READ_ATTRIBUTES | Native.SYNCHRONIZE, Native.SYNCHRONIZE | Native.FILE_TRAVERSE | Native.FILE_READ_ATTRIBUTES_NT, Native.SYNCHRONIZE | Native.FILE_READ_ATTRIBUTES_NT),
    ];

    private static void PartC(string scratch, string repo, string[] args)
    {
        Console.WriteLine("== C. emulated service-class token (restricted to Everyone/Users/AuthUsers/SERVICE/LOCAL/ThisOrg/custodian SID)");
        var c = new JsonObject { ["restrictingSids"] = new JsonArray([.. ServiceClassSids.Append(ServiceSid.Custodian().Value).Select(s => (JsonNode)s)]) };
        var targets = new List<string> { repo, Path.GetTempPath().TrimEnd('\\'), Environment.SystemDirectory };
        string? extra = GetArg(args, "--also");
        if (extra is not null) targets.AddRange(extra.Split(';', StringSplitOptions.RemoveEmptyEntries));
        // Warm every code path unimpersonated first: a first-time JIT/assembly load under a restricted
        // token could fail on the application's own files and be misread as an identity result.
        foreach (string t in targets) { try { RepoIdentities.Resolve(t); } catch { } }

        IntPtr token = BuildServiceClassToken();
        try
        {
            using var identity = new WindowsIdentity(token);
            var results = new JsonArray();
            foreach (string t in targets)
            {
                var row = new JsonObject { ["target"] = t };
                string? asSelf = null;
                try { asSelf = RepoIdentities.Resolve(t).Key; } catch (Exception e) { row["asSelf"] = e.Message; }
                if (asSelf is not null) row["asSelf"] = asSelf;
                foreach (WindowsRepoIdentities.WalkAccess v in Variants)
                {
                    string outcome = WindowsIdentity.RunImpersonated(identity.AccessToken, () =>
                    {
                        try { return WindowsRepoIdentities.Resolve(t, v).Key; }
                        catch (Exception e) { return "REFUSED " + e.Message; }
                    });
                    row[v.Name] = outcome;
                    if (v == WindowsRepoIdentities.Production && asSelf is not null && !outcome.StartsWith("REFUSED", StringComparison.Ordinal))
                        Check($"emulated service token derives the SAME key as the user for {t}", outcome == asSelf);
                    Console.WriteLine($"  [{v.Name,-24}] {t} -> {outcome}");
                }
                results.Add(row);
            }
            c["results"] = results;
        }
        finally { Native.CloseHandle(token); }
        Evidence["C_emulatedServiceToken"] = c;
    }

    /// <summary>A restricted impersonation token of this process: every access check must pass for BOTH
    /// the normal SIDs and the restricting service-class SIDs, so access is effectively what those SIDs
    /// are granted; privileges (bypass traverse checking) are kept, as the service's are.</summary>
    private static IntPtr BuildServiceClassToken()
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY | Native.TOKEN_ASSIGN_PRIMARY | Native.TOKEN_IMPERSONATE | Native.TOKEN_ADJUST_DEFAULT | Native.TOKEN_ADJUST_GROUPS, out IntPtr proc))
            Native.ThrowLastError("OpenProcessToken");
        var sids = new List<IntPtr>();
        try
        {
            foreach (string s in ServiceClassSids.Append(ServiceSid.Custodian().Value))
            {
                if (!Native.ConvertStringSidToSidW(s, out IntPtr p)) Native.ThrowLastError("ConvertStringSidToSid");
                sids.Add(p);
            }
            Native.SID_AND_ATTRIBUTES[] restrict = sids.Select(p => new Native.SID_AND_ATTRIBUTES { Sid = p, Attributes = 0 }).ToArray();
            if (!Native.CreateRestrictedToken(proc, 0, 0, null, 0, IntPtr.Zero, (uint)restrict.Length, restrict, out IntPtr restricted))
                Native.ThrowLastError("CreateRestrictedToken");
            try
            {
                if (!Native.DuplicateTokenEx(restricted, Native.TOKEN_QUERY | Native.TOKEN_IMPERSONATE, IntPtr.Zero, Native.SecurityImpersonation, 2 /*TokenImpersonation*/, out IntPtr imp))
                    Native.ThrowLastError("DuplicateTokenEx");
                return imp;
            }
            finally { Native.CloseHandle(restricted); }
        }
        finally
        {
            foreach (IntPtr p in sids) Native.FreeSid(p);
            Native.CloseHandle(proc);
        }
    }

    // ---- helpers ----

    private static void Same(JsonObject o, string name, string path, string expected)
    {
        try
        {
            string k = RepoIdentities.Resolve(path).Key;
            o["alias:" + name] = k;
            Check($"alias '{name}' resolves to the same key", k == expected);
        }
        catch (Exception e) { o["alias:" + name] = e.Message; Check($"alias '{name}' resolves to the same key ({e.Message})", false); }
    }

    private static void Refused(JsonObject o, string name, string path)
    {
        try
        {
            string k = RepoIdentities.Resolve(path).Key;
            o["refuse:" + name] = "RESOLVED " + k;
            Check($"refuses {name}", false);
        }
        catch (ArgumentException e) when (e.Message.StartsWith(RepoIdentities.RefusedPrefix, StringComparison.Ordinal))
        {
            o["refuse:" + name] = e.Message[RepoIdentities.RefusedPrefix.Length..];
            Check($"refuses {name}: {e.Message[RepoIdentities.RefusedPrefix.Length..]}", true);
        }
    }

    private static void Observe(JsonObject o, string what, bool holds)
    {
        o[what] = holds;
        Console.WriteLine($"[{(holds ? "OBSERVED" : "not seen")}] {what}");
    }

    private static void Info(JsonObject o, string name, string detail)
    {
        o["info:" + name] = detail;
        Console.WriteLine($"[info] {name}: {detail}");
    }

    private static void Check(string name, bool ok)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (!ok) _failed++;
    }

    private static string? ShortPath(string path)
    {
        var sb = new StringBuilder(1024);
        uint n = Native.GetShortPathNameW(path, sb, (uint)sb.Capacity);
        return n == 0 || n > sb.Capacity ? null : sb.ToString();
    }

    private static string? FreeDriveLetter()
    {
        var used = new HashSet<char>(DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])));
        for (char ch = 'Q'; ch <= 'Y'; ch++) if (!used.Contains(ch)) return ch + ":";
        return null;
    }

    private static bool TryCmd(string arguments) => TryProcess("cmd.exe", arguments, out _);

    private static bool TryProcess(string file, string arguments, out string output)
    {
        try
        {
            var psi = new ProcessStartInfo(file, arguments) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return p.ExitCode == 0;
        }
        catch (Exception e) { output = e.Message; return false; }
    }

    /// <summary>Remove the scratch tree without following any link inside it (junctions and symlinks are
    /// removed as links, never recursed into).</summary>
    private static void RemoveTree(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            foreach (string entry in Directory.EnumerateFileSystemEntries(dir))
            {
                var info = new FileInfo(entry);
                if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    if (info.Attributes.HasFlag(FileAttributes.Directory)) Directory.Delete(entry); else File.Delete(entry);
                }
                else if (info.Attributes.HasFlag(FileAttributes.Directory)) RemoveTree(entry);
                else File.Delete(entry);
            }
            Directory.Delete(dir);
        }
        catch (Exception e) { Console.WriteLine($"[warn] scratch cleanup incomplete for {dir}: {e.Message}"); }
    }

    private static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
