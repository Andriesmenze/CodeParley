using System.Buffers.Binary;
using CodeParley.Custodian.Linux.Native;

namespace CodeParley.Custodian.Linux.Ledger;

/// <summary>
/// Phase 5 (contract §4.11): export directories on Linux. The custodian writes every export file itself (owner
/// <c>codeparley</c>, files 0600 / directories 0700 in effect); POSIX ACLs (the <c>system.posix_acl_*</c> xattrs, which the
/// owner may set without privilege, VERIFIED E5) carry the two grants:
/// <list type="bullet">
/// <item><b>the helper, while it works</b> (Increment 2): a ticket directory is created with ONE named-user entry for the
/// helper account (read and search) in its access ACL and its default ACL, so the per-request configuration and the
/// staging files the custodian writes are readable by the helper and by no one else. <see cref="Seal"/> removes both.</item>
/// <item><b>the bound implementer, after publication</b>: ONE named-user entry (read, and search on directories) for its
/// uid, verified afterwards: no other named entry, no group or other access, no write for the reader.</item>
/// </list>
/// The repository-readers check reads the repository's access and default ACLs for the readers group.
/// </summary>
internal sealed class LinuxAccessPublisher : IAccessPublisher
{
    private const ushort UserObj = 0x01, User = 0x02, GroupObj = 0x04, Group = 0x08, Mask = 0x10, Other = 0x20;
    private const string AccessAcl = "system.posix_acl_access", DefaultAcl = "system.posix_acl_default";
    private const uint NoId = uint.MaxValue;

    private static uint IdOf(Principal p) => uint.Parse(p.Id, System.Globalization.CultureInfo.InvariantCulture);

    public string CreateExportDirectory(string name, Principal helper)
    {
        var dir = Directory.CreateDirectory(name, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        uint uid = IdOf(helper);
        var entries = new List<(ushort, ushort, uint)> { (UserObj, 7, NoId), (User, 5, uid), (GroupObj, 0, NoId), (Mask, 5, NoId), (Other, 0, NoId) };
        WriteAcl(dir.FullName, AccessAcl, entries);
        WriteAcl(dir.FullName, DefaultAcl, entries);
        return dir.FullName;
    }

    /// <summary>Remove the helper's access (publication): every named entry and every default ACL under the ticket goes;
    /// then the directory grants the group and others nothing, and no file is another user's or carries a named entry.
    /// True when the helper's access was removed and the check passed.</summary>
    public bool Seal(string path, Principal helper)
    {
        uint self = Libc.geteuid();
        foreach (string f in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories).Prepend(path))
        {
            if (Libc.StatxFullAt(Libc.AT_FDCWD, f, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0) return false;
            bool dir = st.Type == Libc.S_IFDIR;
            WriteAcl(f, AccessAcl, [(UserObj, (ushort)(dir ? 7 : 6), NoId), (GroupObj, 0, NoId), (Other, 0, NoId)]);
            if (dir) RemoveAcl(f, DefaultAcl);
        }
        if (Libc.StatxFullAt(Libc.AT_FDCWD, path, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull d) != 0 || d.Type != Libc.S_IFDIR || d.Uid != self || (d.Perm & 0x3F /* 0o077 */) != 0) return false;
        foreach (string f in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories).Prepend(path))
        {
            if (Libc.StatxFullAt(Libc.AT_FDCWD, f, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0) return false;
            if (st.Uid != self || (st.Perm & 0x3F /* 0o077 */) != 0) return false;
            if (ReadAcl(f, AccessAcl) is { } acl && acl.Any(e => e.Tag is User or Group)) return false;
            if (st.Type == Libc.S_IFDIR && ReadAcl(f, DefaultAcl) is not null) return false;
        }
        return true;
    }

    public void Publish(string path, Principal reader)
    {
        uint uid = IdOf(reader);
        uint self = Libc.geteuid();
        foreach (string f in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories).Prepend(path))
        {
            bool dir = Directory.Exists(f) && !File.Exists(f);
            ushort r = (ushort)(dir ? 5 : 4); // r-x / r--
            var entries = new List<(ushort, ushort, uint)> { (UserObj, (ushort)(dir ? 7 : 6), NoId) };
            if (uid != self) entries.Add((User, r, uid));
            entries.Add((GroupObj, 0, NoId));
            if (uid != self) entries.Add((Mask, r, NoId));
            entries.Add((Other, 0, NoId));
            WriteAcl(f, AccessAcl, entries);
            if (dir) RemoveAcl(f, DefaultAcl);
        }
        foreach (string f in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories).Take(256).Prepend(path))
        {
            if (Libc.StatxFullAt(Libc.AT_FDCWD, f, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0 || st.Uid != self || (st.Perm & 0x07 /* 0o007 */) != 0)
                throw new InvalidOperationException($"a published file grants more than the publication allows ({f})");
            foreach ((ushort tag, ushort perm, uint id) in ReadAcl(f, AccessAcl) ?? [])
                if ((tag == User && (id != uid || (perm & 2) != 0)) || tag == Group || (tag is GroupObj or Other && perm != 0))
                    throw new InvalidOperationException($"a published file's ACL grants more than the publication allows ({f})");
        }
    }

    public string? RepositoryReadersProblem(string root, Principal readers)
    {
        uint gid = IdOf(readers);
        List<(ushort Tag, ushort Perm, uint Id)>? access = ReadAcl(root, AccessAcl), dflt = ReadAcl(root, DefaultAcl);
        bool granted = access?.Any(e => e.Tag == Group && e.Id == gid && (e.Perm & 5) == 5) == true;
        bool inherited = dflt?.Any(e => e.Tag == Group && e.Id == gid && (e.Perm & 5) == 5) == true;
        return granted && inherited ? null : !granted ? "no ACL entry grants it read and search on the repository" : "no default ACL entry passes read and search to new files and directories";
    }

    public string RepositoryReadersRemedy(string root, Principal readers)
        => $"the operator grants it on the repository (read, and search on directories, inherited by new files) and traverse-only on its ancestors: `setfacl -R -m g:{readers.Display}:rX,d:g:{readers.Display}:rX \"{root}\"` and `setfacl -m g:{readers.Display}:--x <each ancestor>` (as root; on the test VM: cpt-acl readers)";

    // ---- the POSIX ACL xattr (include/uapi/linux/posix_acl_xattr.h: version 2, entries of tag u16, perm u16, id u32) ----

    internal static List<(ushort Tag, ushort Perm, uint Id)>? ReadAcl(string path, string name)
    {
        int fd = Libc.Openat(Libc.AT_FDCWD, path, Libc.O_PATH | Libc.O_CLOEXEC | Libc.O_NOFOLLOW, 0);
        if (fd < 0) return null;
        try
        {
            int rfd = Libc.Openat(Libc.AT_FDCWD, $"/proc/self/fd/{fd}", Libc.O_RDONLY | Libc.O_CLOEXEC, 0);
            if (rfd < 0) return null;
            try
            {
                byte[]? raw = Libc.GetXattr(rfd, name);
                if (raw is null || raw.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(raw) != 2) return null;
                var list = new List<(ushort, ushort, uint)>();
                for (int o = 4; o + 8 <= raw.Length; o += 8)
                    list.Add((BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(o)), BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(o + 2)), BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(o + 4))));
                return list;
            }
            finally { Libc.close(rfd); }
        }
        finally { Libc.close(fd); }
    }

    private static void WriteAcl(string path, string name, List<(ushort Tag, ushort Perm, uint Id)> entries)
    {
        var raw = new byte[4 + 8 * entries.Count];
        BinaryPrimitives.WriteUInt32LittleEndian(raw, 2);
        for (int i = 0; i < entries.Count; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(4 + 8 * i), entries[i].Tag);
            BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(6 + 8 * i), entries[i].Perm);
            BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8 + 8 * i), entries[i].Id);
        }
        int fd = Libc.Openat(Libc.AT_FDCWD, path, Libc.O_RDONLY | Libc.O_CLOEXEC | Libc.O_NOFOLLOW, 0);
        if (fd < 0) throw new IOException($"{path} cannot be opened to set its ACL ({Libc.ErrText(Libc.Errno)})");
        try
        {
            if (Libc.SetXattr(fd, name, raw) != 0) throw new IOException($"{path}: the ACL could not be set ({Libc.ErrText(Libc.Errno)})");
        }
        finally { Libc.close(fd); }
    }

    private static void RemoveAcl(string path, string name)
    {
        int fd = Libc.Openat(Libc.AT_FDCWD, path, Libc.O_RDONLY | Libc.O_CLOEXEC | Libc.O_NOFOLLOW, 0);
        if (fd < 0) throw new IOException($"{path} cannot be opened to remove its ACL ({Libc.ErrText(Libc.Errno)})");
        try
        {
            if (Libc.RemoveXattr(fd, name) != 0 && Libc.Errno != 61 /* ENODATA: there was none */)
                throw new IOException($"{path}: the default ACL could not be removed ({Libc.ErrText(Libc.Errno)})");
        }
        finally { Libc.close(fd); }
    }
}
