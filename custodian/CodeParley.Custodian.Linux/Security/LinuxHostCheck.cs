using System.Text.Json.Nodes;
using CodeParley.Custodian.Linux.Ledger;
using CodeParley.Custodian.Linux.Native;

namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 (contract §4.3, §4.14, D-L3): what the Linux custodian checks before it serves anything. Every item that fails
/// keeps the service from becoming ready and is named in the journal (fail closed); nothing is repaired automatically.
/// </summary>
internal static class LinuxHostCheck
{
    internal const string StoreRoot = "/var/lib/codeparley";
    internal const string StoreGroup = "codeparley-read";
    /// <summary>D5-D: the group the helper reads repositories through (operator-provisioned POSIX ACLs).</summary>
    internal const string ReadersGroup = "codeparley-readers";

    /// <summary>Groups whose members can become root or read raw devices (and so rewrite a birth time or generation): the
    /// implementer must be in none of them (F5-8; NL-8).</summary>
    internal static readonly string[] ForbiddenImplementerGroups = ["sudo", "admin", "wheel", "adm", "lxd", "docker", "libvirt", "disk", "kvm", "shadow", "systemd-journal"];

    /// <summary>The host preconditions; empty when all hold.</summary>
    internal static List<string> Preconditions(LinuxConfig cfg)
    {
        var p = new List<string>();
        string? osRelease = Read("/etc/os-release");
        if (osRelease is null || !osRelease.Contains("\nID=ubuntu", StringComparison.Ordinal) && !osRelease.StartsWith("ID=ubuntu", StringComparison.Ordinal)
            || !osRelease.Contains("VERSION_ID=\"24.04\"", StringComparison.Ordinal))
            p.Add("the distribution is not Ubuntu 24.04 (D5-E)");
        string kernel = Read("/proc/sys/kernel/osrelease")?.Trim() ?? "";
        if (!kernel.StartsWith("6.8.", StringComparison.Ordinal)) p.Add($"the kernel {kernel} is not 6.8 (D5-E)");
        if (System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64) p.Add("the architecture is not x86_64 (D5-E)");
        if (kernel.Contains("microsoft", StringComparison.OrdinalIgnoreCase) || kernel.Contains("WSL", StringComparison.Ordinal) || File.Exists("/proc/sys/fs/binfmt_misc/WSLInterop"))
            p.Add("this is WSL (its interop bridges any Linux uid into the Windows user)");
        Sysctl(p, "kernel/yama/ptrace_scope", v => v >= 1, "≥ 1");
        Sysctl(p, "fs/protected_symlinks", v => v == 1, "1");
        Sysctl(p, "fs/protected_hardlinks", v => v == 1, "1");
        Sysctl(p, "fs/protected_regular", v => v >= 1, "≥ 1");
        Sysctl(p, "fs/protected_fifos", v => v >= 1, "≥ 1");
        Sysctl(p, "kernel/apparmor_restrict_unprivileged_userns", v => v == 1, "1");
        if (Libc.GetPasswdByName(LinuxConfig.CustodianAccount) is not { } me || me.Uid != Libc.geteuid() || me.Uid == 0)
            p.Add($"the custodian does not run as its own account '{LinuxConfig.CustodianAccount}' (and never as root)");
        Libc.PasswdEntry? impl = Libc.GetPasswdByUid(cfg.ImplementerUid);
        if (impl is null) p.Add("the implementer account cannot be read");
        else
        {
            foreach (uint gid in Libc.GetGroupList(impl.Name, impl.Gid))
                if (Libc.GetGroupByGid(gid)?.Name is { } g && ForbiddenImplementerGroups.Contains(g))
                    p.Add($"the implementer '{impl.Name}' is in the administrative group '{g}' (it must be non-administrative, F5-8)");
        }
        if (cfg.OperatorUid == cfg.ImplementerUid) p.Add("the operator is not a separate account (D5-B)");
        if (Read("/proc/1/stat") is null) p.Add("/proc hides other users' processes from the custodian (hidepid without a gid= exemption): process correlation cannot be verified");
        p.AddRange(ValidateStore(cfg.HelperUid, cfg.ImplementerUid));
        return p;
    }

    /// <summary>
    /// The whole store tree, checked by the custodian itself (systemd repairs only the top of a state directory, F5-15):
    /// the root is <c>codeparley:codeparley-read</c> 2750 and not a link; every entry below is a directory or regular file
    /// (no symbolic link, device or socket), owned by the custodian, of group <c>codeparley-read</c>, with no group write and
    /// no access for others, files with one link; directories carry the setgid bit; <c>content-key.secret</c> and
    /// <c>intents</c> grant the group nothing. A foreign entry (planted by root as a test) is refused.
    /// </summary>
    internal static List<string> ValidateStore(uint? helperUid = null, uint? implementerUid = null)
    {
        var p = new List<string>();
        uint self = Libc.geteuid();
        uint? gid = Libc.GetGroupByName(StoreGroup)?.Gid;
        if (gid is null) { p.Add($"the store group '{StoreGroup}' does not exist"); return p; }
        if (Libc.StatxFullAt(Libc.AT_FDCWD, StoreRoot, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull root) != 0) { p.Add($"{StoreRoot} is missing"); return p; }
        if (root.Type != Libc.S_IFDIR) { p.Add($"{StoreRoot} is not a directory"); return p; }
        if (root.Uid != self || root.Gid != gid || root.Perm != 0x5E8) p.Add($"{StoreRoot} must be {LinuxConfig.CustodianAccount}:{StoreGroup} 2750 (it is uid {root.Uid}, gid {root.Gid}, mode {Convert.ToString(root.Perm, 8)})");
        if (StoreFilesystemProblem() is { } fs) p.Add(fs);
        // Increment 2 (§4.11): the store root and exports/ may carry exactly one named entry, the helper's traverse-only
        // grant (tmpfiles.d), so it reaches its per-request directories; nothing else in the store outside exports/ may carry
        // a named ACL entry or a default ACL (a planted grant would open the store to someone).
        if (AclProblem(StoreRoot, helperUid, traverseOnlyHelper: true) is { } ra) p.Add($"{StoreRoot}: {ra}");
        int n = 0;
        foreach (string e in Directory.EnumerateFileSystemEntries(StoreRoot, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = false, ReturnSpecialDirectories = false }))
        {
            if (++n > 200_000) { p.Add("the store has more than 200000 entries"); break; }
            string rel = e[(StoreRoot.Length + 1)..];
            if (Libc.StatxFullAt(Libc.AT_FDCWD, e, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0) { p.Add($"store entry '{rel}' cannot be examined"); continue; }
            bool dir = st.Type == Libc.S_IFDIR;
            if (!dir && st.Type != Libc.S_IFREG) { p.Add($"store entry '{rel}' is a link or special file"); continue; }
            if (st.Uid != self) p.Add($"store entry '{rel}' is owned by uid {st.Uid}, not the custodian");
            if (rel.StartsWith("exports/", StringComparison.Ordinal))
            {
                if (!dir && st.Nlink != 1) p.Add($"store file '{rel}' has {st.Nlink} hard links");
                if (!dir && (st.Perm & 0xC49) != 0) p.Add($"store file '{rel}' is executable, setuid or setgid");
                if (ExportEntryProblem(e, dir, st.Perm, helperUid, implementerUid) is { } xp) p.Add($"export entry '{rel}' {xp}");
                continue;
            }
            if (st.Gid != gid) p.Add($"store entry '{rel}' has group {st.Gid}, not {StoreGroup}");
            if ((st.Perm & 0x17 /* 0o027 */) != 0) p.Add($"store entry '{rel}' grants group write or other access (mode {Convert.ToString(st.Perm, 8)})");
            if (dir && (st.Perm & 0x400) == 0) p.Add($"store directory '{rel}' lacks the setgid bit");
            if (!dir && st.Nlink != 1) p.Add($"store file '{rel}' has {st.Nlink} hard links");
            if (!dir && (st.Perm & 0xC49) != 0) p.Add($"store file '{rel}' is executable, setuid or setgid");
            bool privateEntry = IsPrivateStoreEntry(rel);
            if (rel == "exports")
            {
                if (!dir || st.Perm != 0x5C8 /* 2710 */) p.Add($"store directory 'exports' must be 2710 (it is {Convert.ToString(st.Perm, 8)})");
                if (AclProblem(e, helperUid, traverseOnlyHelper: true) is { } ea) p.Add($"store directory 'exports': {ea}");
            }
            else if (AclProblem(e, helperUid, traverseOnlyHelper: false) is { } acl) p.Add($"store entry '{rel}': {acl}");
            if (privateEntry && (st.Perm & 0x38 /* 0o070 */) != 0) p.Add($"store entry '{rel}' must grant the store group nothing");
        }
        return p;
    }

    /// <summary>The store's filesystem must be one the repository identity accepts (contract §4.3, §4.6): ext4, provisioned by
    /// the operator after the privileged metadata_csum / inode-size check. Null when it is.</summary>
    internal static string? StoreFilesystemProblem()
    {
        int fd = Libc.Openat(Libc.AT_FDCWD, StoreRoot, Libc.O_PATH | Libc.O_DIRECTORY | Libc.O_CLOEXEC | Libc.O_NOFOLLOW, 0);
        if (fd < 0) return $"{StoreRoot} cannot be opened to examine its filesystem ({Libc.ErrText(Libc.Errno)})";
        try
        {
            if (Libc.FsOf(fd) is not { } fs) return $"the filesystem of {StoreRoot} cannot be examined";
            if (fs.Type != Libc.EXT4_SUPER_MAGIC) return $"the store is not on ext4 (filesystem magic 0x{fs.Type:x}); only provisioned ext4 is supported (D5-E)";
            if (!LinuxConfig.FilesystemProvisioned(fs.Fsid)) return $"the store's filesystem (fsid {fs.Fsid:x16}) was not provisioned by the operator";
            return null;
        }
        finally { Libc.close(fd); }
    }

    /// <summary>
    /// Increment 2 (§4.11): an entry under <c>exports/</c> — a ticket's or a published export's — is the custodian's own,
    /// grants nothing to other users and write to no one but the custodian; any access is carried by ACL entries for the
    /// helper (while it works) or the bound implementer (once published), both without write, and a default ACL only on a
    /// directory, with the same entries. Its owning group grants nothing, so its group is not the store group's: setting a
    /// directory's ACL clears its setgid bit (the custodian is not in that group). Null when the entry is allowed.
    /// </summary>
    internal static string? ExportEntryProblem(string path, bool dir, uint perm, uint? helperUid, uint? implementerUid)
    {
        if ((perm & 0x07) != 0) return $"grants other users access (mode {Convert.ToString(perm, 8)})";
        if ((perm & 0x10) != 0) return $"grants group-class write (mode {Convert.ToString(perm, 8)})";
        List<(ushort Tag, ushort Perm, uint Id)>? access = LinuxAccessPublisher.ReadAcl(path, "system.posix_acl_access");
        if (access is null && (perm & 0x38) != 0) return $"grants its owning group access (mode {Convert.ToString(perm, 8)})";
        List<(ushort Tag, ushort Perm, uint Id)>? dflt = LinuxAccessPublisher.ReadAcl(path, "system.posix_acl_default");
        if (dflt is not null && !dir) return "is a file with a default ACL";
        foreach ((ushort tag, ushort p, uint id) in (access ?? []).Concat(dflt ?? []))
        {
            if (tag == 0x04 && p != 0) return "grants its owning group access by ACL";
            if (tag == 0x08) return $"grants the group {id} access by ACL";
            if (tag == 0x02 && ((id != helperUid && id != implementerUid) || (p & 2) != 0)) return $"grants uid {id} access by ACL (perm {p})";
        }
        return null;
    }

    /// <summary>Why an entry's ACLs are not allowed (null: they are): no default ACL; no named group entry; a named user entry
    /// only when <paramref name="traverseOnlyHelper"/> and it is the helper's search-only grant.</summary>
    internal static string? AclProblem(string path, uint? helperUid, bool traverseOnlyHelper)
    {
        if (LinuxAccessPublisher.ReadAcl(path, "system.posix_acl_default") is not null) return "it carries a default ACL";
        foreach ((ushort tag, ushort perm, uint id) in LinuxAccessPublisher.ReadAcl(path, "system.posix_acl_access") ?? [])
        {
            if (tag == 0x08) return $"it grants the group {id} access by ACL";
            if (tag == 0x02 && !(traverseOnlyHelper && helperUid is { } h && id == h && perm == 1)) return $"it grants uid {id} access by ACL (perm {perm})";
        }
        return null;
    }

    /// <summary>The store entries that grant the store group nothing (contract §4.3): the content-key secret and the
    /// intents. <paramref name="rel"/> is relative to the store root, '/'-separated.</summary>
    internal static bool IsPrivateStoreEntry(string rel)
        => rel is "content-key.secret" or "intents" || rel.StartsWith("intents/", StringComparison.Ordinal);

    /// <summary>Create the private intents directory (2700) when it is missing, before the ledger can create it 2750.</summary>
    internal static void EnsurePrivateDirectories()
    {
        string intents = Path.Combine(StoreRoot, "intents");
        if (!Directory.Exists(intents)) Directory.CreateDirectory(intents, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    /// <summary>The operator-only <c>service_identity</c> diagnostic: the service's own credentials, capabilities, the no-new-
    /// privileges and seccomp state, and write probes (the store must be writable, nothing else probed may be).</summary>
    internal static JsonObject ServiceFacts()
    {
        string status = Read("/proc/self/status") ?? "";
        string Field(string name) => status.Split('\n').FirstOrDefault(l => l.StartsWith(name + ":", StringComparison.Ordinal))?[(name.Length + 1)..].Trim() ?? "";
        var probes = new JsonObject();
        foreach (string target in new[] { StoreRoot, "/etc", "/home", "/opt", "/run/codeparley", "/usr/local/bin" })
        {
            string probe = Path.Combine(target, ".cp-write-probe-" + Guid.NewGuid().ToString("N")[..8]);
            try { File.WriteAllText(probe, "probe"); File.Delete(probe); probes[target] = "writable"; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { probes[target] = "denied"; }
        }
        return new JsonObject
        {
            ["uid"] = Libc.geteuid(), ["gid"] = Libc.getegid(), ["groups"] = Field("Groups"),
            ["capEff"] = Field("CapEff"), ["capBnd"] = Field("CapBnd"), ["noNewPrivs"] = Field("NoNewPrivs"), ["seccomp"] = Field("Seccomp"),
            ["writeProbes"] = probes,
        };
    }

    private static void Sysctl(List<string> p, string name, Func<int, bool> ok, string expected)
    {
        string? v = Read("/proc/sys/" + name)?.Trim();
        if (v is null || !int.TryParse(v, out int n) || !ok(n)) p.Add($"{name.Replace('/', '.')} is {v ?? "unreadable"}, not {expected}");
    }

    private static string? Read(string path)
    {
        try { return File.ReadAllText(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }
}
