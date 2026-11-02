using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Ipc;

namespace CodeParley.Custodian.Security;

/// <summary>
/// P3.4C-4 (§4.4, TD clarification II): the approved Codex installation is the native executable image CodeParley
/// launches. The custodian measures it itself when the operator sets or re-confirms it: the path the operator named is
/// walked from the volume root with the custodian's own token, one component at a time relative to its parent's handle
/// with <c>OBJ_DONT_REPARSE</c> (the repository-identity walk, P3.4C-0), so a link, junction or mount point in any
/// component is refused rather than followed; the final component must be one regular file (no reparse point, one hard
/// link) named <c>*.exe</c> whose bytes are a Windows PE image (<c>MZ</c> header, <c>PE\0\0</c> signature). Its file identity
/// (volume serial + 128-bit file id), size and SHA-256 are read from that same handle. Where npm distributed the image
/// does not matter (a native <c>codex.exe</c> inside a package qualifies when it is selected directly); a launcher or
/// script (<c>.cmd</c>, <c>.bat</c>, <c>.ps1</c>, <c>.js</c>, <c>.sh</c>, a shim), a non-PE file, a linked path and a file
/// the service cannot read are refused CODEX_INSTALLATION_UNSUPPORTED. The measurement covers the main image only — not
/// the libraries or helpers it loads, its configuration or model-side state (residual, §8.2).
/// </summary>
internal static class WindowsCodexImage
{
    internal const string NativePe = CodexImage.NativePe;
    private const long MaxImageBytes = 4L * 1024 * 1024 * 1024;
    private const uint ShareAll = Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE;
    private static readonly string[] ScriptExtensions = [".cmd", ".bat", ".ps1", ".js", ".mjs", ".cjs", ".sh", ".vbs", ".py"];

    private static CustodianRefusal Unsupported(string why) => new(ErrorCodes.CodexInstallationUnsupported, $"the Codex installation is not a supported native image: {why}");

    internal static MeasuredImage Measure(string path)
    {
        string drive;
        string[] components;
        try { (drive, components) = WindowsRepoIdentities.Parse(path); }
        catch (ArgumentException e) { throw Unsupported(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal).Replace("repository path", "path", StringComparison.Ordinal)); }
        if (components.Length == 0) throw Unsupported("the path names a volume root, not a file");
        string name = components[^1];
        string ext = System.IO.Path.GetExtension(name);
        if (ScriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) throw Unsupported($"'{name}' is a launcher or script, not the native executable it starts");
        if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) throw Unsupported($"'{name}' is not an .exe");

        var open = new List<IntPtr>();
        try
        {
            IntPtr cur;
            try { cur = WindowsRepoIdentities.OpenVolumeRoot(drive, Native.FILE_READ_ATTRIBUTES, out _); }
            catch (ArgumentException e) { throw Unsupported(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
            open.Add(cur);
            for (int i = 0; i < components.Length - 1; i++)
            {
                try { cur = WindowsRepoIdentities.OpenChildDirectory(cur, components[i], Native.FILE_READ_ATTRIBUTES_NT); }
                catch (ArgumentException e) { throw Unsupported(e.Message.Replace(RepoIdentities.RefusedPrefix, "", StringComparison.Ordinal)); }
                open.Add(cur);
            }
            using SafeFileHandle file = OpenFile(cur, name);
            return Identify(file, path);
        }
        finally
        {
            for (int i = open.Count - 1; i >= 0; i--) Native.CloseHandle(open[i]);
        }
    }

    /// <summary>Open the final file relative to its directory's handle for reading, failing on any reparse point.</summary>
    private static SafeFileHandle OpenFile(IntPtr parent, string name)
    {
        IntPtr namePtr = Marshal.StringToHGlobalUni(name);
        IntPtr usPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.UNICODE_STRING>());
        try
        {
            var us = new Native.UNICODE_STRING { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = namePtr };
            Marshal.StructureToPtr(us, usPtr, false);
            var oa = new Native.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<Native.OBJECT_ATTRIBUTES>(),
                RootDirectory = parent,
                ObjectName = usPtr,
                Attributes = Native.OBJ_CASE_INSENSITIVE | Native.OBJ_DONT_REPARSE,
            };
            uint access = Native.FILE_READ_DATA | Native.FILE_READ_ATTRIBUTES_NT | Native.SYNCHRONIZE;
            uint options = Native.FILE_SYNCHRONOUS_IO_NONALERT | Native.FILE_NON_DIRECTORY_FILE;
            int status = Native.NtCreateFile(out IntPtr handle, access, ref oa, out _, IntPtr.Zero, 0, ShareAll, Native.FILE_OPEN, options, IntPtr.Zero, 0);
            if (status != 0) throw Unsupported($"'{name}': {WindowsRepoIdentities.StatusText(status)}");
            return new SafeFileHandle(handle, ownsHandle: true);
        }
        finally
        {
            Marshal.FreeHGlobal(usPtr);
            Marshal.FreeHGlobal(namePtr);
        }
    }

    private static MeasuredImage Identify(SafeFileHandle file, string path)
    {
        if (!Native.GetFileInformationByHandle(file.DangerousGetHandle(), out Native.BY_HANDLE_FILE_INFORMATION fi))
            throw Unsupported("its attributes cannot be read");
        if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) throw Unsupported("the file is a reparse point");
        if ((fi.FileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0) throw Unsupported("the path names a directory");
        if (fi.NumberOfLinks != 1) throw Unsupported($"the file has {fi.NumberOfLinks} hard links (one is required)");
        long size = ((long)fi.FileSizeHigh << 32) | fi.FileSizeLow;
        if (size > MaxImageBytes) throw Unsupported("the file is larger than 4 GiB");

        string fileId;
        IntPtr buf = Marshal.AllocHGlobal(24);
        try
        {
            if (!Native.GetFileInformationByHandleEx(file.DangerousGetHandle(), Native.FileIdInfo, buf, 24)) throw Unsupported("its file id cannot be read");
            ulong volumeSerial = (ulong)Marshal.ReadInt64(buf);
            byte[] id = new byte[16];
            Marshal.Copy(buf + 8, id, 0, 16);
            if (volumeSerial == 0 || id.All(b => b == 0)) throw Unsupported("the volume reports no stable file id for it");
            fileId = $"{volumeSerial:x16}-{Convert.ToHexString(id).ToLowerInvariant()}";
        }
        finally { Marshal.FreeHGlobal(buf); }

        using var fs = new FileStream(file, FileAccess.Read, 1 << 16);
        byte[] head = new byte[4096];
        int headLen = ReadAtMost(fs, head);
        if (!IsPortableExecutable(head.AsSpan(0, headLen), size, fs)) throw Unsupported("the file is not a Windows PE image");
        fs.Position = 0;
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] chunk = new byte[1 << 20];
        long total = 0;
        for (int n; (n = fs.Read(chunk, 0, chunk.Length)) > 0;)
        {
            sha.AppendData(chunk, 0, n);
            total += n;
        }
        if (total != size) throw Unsupported("the file changed while it was measured");
        return new MeasuredImage(path, NativePe, fileId, size, Convert.ToHexStringLower(sha.GetHashAndReset()));
    }

    private static int ReadAtMost(FileStream fs, byte[] buffer)
    {
        int off = 0;
        for (int n; off < buffer.Length && (n = fs.Read(buffer, off, buffer.Length - off)) > 0;) off += n;
        return off;
    }

    /// <summary>An <c>MZ</c> header whose <c>e_lfanew</c> points inside the file at a <c>PE\0\0</c> signature.</summary>
    private static bool IsPortableExecutable(ReadOnlySpan<byte> head, long size, FileStream fs)
    {
        if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z') return false;
        long lfanew = BitConverter.ToUInt32(head.Slice(0x3C, 4));
        if (lfanew < 0x40 || lfanew > size - 4) return false;
        Span<byte> sig = stackalloc byte[4];
        if (lfanew + 4 <= head.Length) head.Slice((int)lfanew, 4).CopyTo(sig);
        else
        {
            fs.Position = lfanew;
            if (fs.Read(sig) != 4) return false;
        }
        return sig[0] == (byte)'P' && sig[1] == (byte)'E' && sig[2] == 0 && sig[3] == 0;
    }

}
