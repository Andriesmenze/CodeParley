using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using CodeParley.Custodian.Interop;

namespace CodeParley.Custodian.Security;

/// <summary>
/// Handle-based, no-follow path resolution (C-12). Every read the custodian makes of a path a
/// non-custodian principal can influence goes through here, never <c>File.ReadAllText(path)</c> (the
/// vulnerable broker pattern this component must not copy).
///
/// A trusted root is opened by handle and its real path confirmed. Each component below it is then
/// opened RELATIVE to its parent's handle with <c>NtCreateFile</c> and <c>OBJ_DONT_REPARSE</c>: a
/// symbolic link, junction, mount point or any other reparse point in ANY component fails the open,
/// and because each step resolves a single name against a kernel handle (not a re-parsed path string)
/// a concurrent rename/substitution between steps cannot redirect it. The final handle is rejected if
/// it is a reparse point or has more than one hard link.
/// </summary>
internal static class NoFollow
{
    internal sealed record Attempt(bool Opened, string Detail);

    /// <summary>Read a file at <paramref name="relative"/> beneath <paramref name="absRoot"/>, refusing
    /// any link/junction/reparse/<c>..</c> component and any hard-linked target. Throws on refusal.</summary>
    internal static byte[] ReadBeneath(string absRoot, string relative, long maxBytes)
    {
        using SafeFileHandle file = OpenBeneath(absRoot, relative, wantDirectory: false);
        VerifyFinalFile(file);
        using var fs = new FileStream(file, FileAccess.Read);
        if (fs.Length > maxBytes) throw new InvalidOperationException($"file exceeds {maxBytes} bytes");
        var buf = new byte[fs.Length];
        int off = 0;
        while (off < buf.Length)
        {
            int n = fs.Read(buf, off, buf.Length - off);
            if (n == 0) break;
            off += n;
        }
        return off == buf.Length ? buf : buf[..off];
    }

    /// <summary>Corpus helper: attempt a no-follow read and report whether it opened, never throwing.</summary>
    internal static Attempt TryReadBeneath(string absRoot, string relative, long maxBytes)
    {
        try { _ = ReadBeneath(absRoot, relative, maxBytes); return new Attempt(true, "opened"); }
        catch (Exception e) { return new Attempt(false, Compact(e.Message)); }
    }

    private static string Compact(string s) => s.Replace('\n', ' ').Replace('\r', ' ').Trim();

    /// <summary>Open a path beneath a trusted root with every component resolved no-follow.</summary>
    internal static SafeFileHandle OpenBeneath(string absRoot, string relative, bool wantDirectory)
    {
        if (relative.Length == 0) throw new ArgumentException("empty relative path");
        IntPtr root = OpenTrustedRoot(absRoot);
        var parents = new List<IntPtr> { root };
        try
        {
            string[] parts = relative.Split('/', '\\');
            IntPtr cur = root;
            for (int i = 0; i < parts.Length; i++)
            {
                string comp = parts[i];
                if (comp.Length == 0 || comp == "." || comp == "..")
                    throw new InvalidOperationException($"illegal path component '{comp}'");
                bool last = i == parts.Length - 1;
                SafeFileHandle h = OpenChild(cur, comp, directory: !last || wantDirectory);
                cur = h.DangerousGetHandle();
                parents.Add(cur);
                if (last)
                {
                    // Detach: hand ownership of the final handle to the caller, keep the rest to close.
                    parents.RemoveAt(parents.Count - 1);
                    return h;
                }
                h.SetHandleAsInvalid(); // the raw handle stays open in `parents` and is closed below
            }
            throw new InvalidOperationException("no final component");
        }
        finally
        {
            // Close every intermediate handle we opened (the final one was detached to the caller).
            for (int i = parents.Count - 1; i >= 0; i--) Native.CloseHandle(parents[i]);
        }
    }

    /// <summary>Open the trusted root directory by handle (no-follow) and confirm its real path is the
    /// literal root, so an intermediate junction in the root's own path cannot redirect the walk.</summary>
    private static IntPtr OpenTrustedRoot(string absRoot)
    {
        IntPtr h = Native.CreateFileW(absRoot, Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL | Native.FILE_LIST_DIRECTORY,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_BACKUP_SEMANTICS | Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) Native.ThrowLastError($"open trusted root '{absRoot}'");
        try
        {
            if (!Native.GetFileInformationByHandle(h, out Native.BY_HANDLE_FILE_INFORMATION fi)) Native.ThrowLastError("GetFileInformationByHandle(root)");
            if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) throw new InvalidOperationException("trusted root is a reparse point");
            string real = FinalPath(h);
            string expected = absRoot.TrimEnd('\\');
            if (!string.Equals(real.TrimEnd('\\'), expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"trusted root resolves to '{real}', not '{expected}'");
            return h;
        }
        catch { Native.CloseHandle(h); throw; }
    }

    /// <summary>Open one child name relative to a parent directory handle, failing on any reparse point.</summary>
    private static SafeFileHandle OpenChild(IntPtr parent, string name, bool directory)
    {
        IntPtr namePtr = Marshal.StringToHGlobalUni(name);
        try
        {
            var us = new Native.UNICODE_STRING
            {
                Length = (ushort)(name.Length * 2),
                MaximumLength = (ushort)(name.Length * 2),
                Buffer = namePtr,
            };
            IntPtr usPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.UNICODE_STRING>());
            try
            {
                Marshal.StructureToPtr(us, usPtr, false);
                var oa = new Native.OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf<Native.OBJECT_ATTRIBUTES>(),
                    RootDirectory = parent,
                    ObjectName = usPtr,
                    Attributes = Native.OBJ_CASE_INSENSITIVE | Native.OBJ_DONT_REPARSE,
                };
                uint access = Native.FILE_READ_DATA | Native.FILE_READ_ATTRIBUTES_NT | Native.SYNCHRONIZE | (directory ? Native.FILE_TRAVERSE : 0);
                uint options = Native.FILE_SYNCHRONOUS_IO_NONALERT | (directory ? Native.FILE_DIRECTORY_FILE : Native.FILE_NON_DIRECTORY_FILE) | Native.FILE_OPEN_FOR_BACKUP_INTENT;
                int status = Native.NtCreateFile(out IntPtr handle, access, ref oa, out _, IntPtr.Zero, 0,
                    Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, Native.FILE_OPEN, options, IntPtr.Zero, 0);
                if (status != 0)
                    throw new System.ComponentModel.Win32Exception(Native.RtlNtStatusToDosError(status), $"open component '{name}' (NTSTATUS 0x{status:X8})");
                return new SafeFileHandle(handle, ownsHandle: true);
            }
            finally { Marshal.FreeHGlobal(usPtr); }
        }
        finally { Marshal.FreeHGlobal(namePtr); }
    }

    private static void VerifyFinalFile(SafeFileHandle file)
    {
        if (!Native.GetFileInformationByHandle(file.DangerousGetHandle(), out Native.BY_HANDLE_FILE_INFORMATION fi))
            Native.ThrowLastError("GetFileInformationByHandle(final)");
        if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new InvalidOperationException("final component is a reparse point");
        if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0)
            throw new InvalidOperationException("final component is a directory");
        if (fi.NumberOfLinks != 1)
            throw new InvalidOperationException($"final component has {fi.NumberOfLinks} hard links (expected 1)");
    }

    private static string FinalPath(IntPtr handle)
    {
        var sb = new StringBuilder(512);
        uint n = Native.GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
        if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = Native.GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0); }
        if (n == 0) Native.ThrowLastError("GetFinalPathNameByHandle");
        string p = sb.ToString();
        return p.StartsWith(@"\\?\", StringComparison.Ordinal) ? p[4..] : p;
    }
}
