using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Linux.Native;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 (contract §4.9, §4.12): the Codex sandbox basis on Linux, measured with the custodian's own token — what an S1
/// or FIX self-test confirmation binds and what every review and fix begin measures again:
/// <list type="bullet">
/// <item>the approved Codex binary (<c>…/bin/codex</c>) and its bundled <c>…/codex-resources/bwrap</c>: ELF, one link, no
/// setuid/setgid, owned by root with no group or other write on the file or any ancestor;</item>
/// <item>the AppArmor profile file (<c>/etc/codeparley/custodian.json</c> <c>codexProfile</c>, by default
/// <c>/etc/apparmor.d/codex-bwrap</c>): root-owned 0644, one link, attaching exactly one profile, to exactly that
/// <c>bwrap</c>, and including nothing the custodian does not measure;</item>
/// <item><c>kernel.apparmor_restrict_unprivileged_userns</c>, which must be 1 (the exception is then scoped to the
/// profiled binary);</item>
/// <item>the boot id (a confirmation is valid on the boot its self-test ran on only).</item>
/// </list>
/// None of this establishes confinement (TD finding 5): only the operator-confirmed self-test of the current boot does.
/// </summary>
internal sealed class LinuxIsolationBasis(Func<string> profilePath) : IIsolationBasis
{
    internal const string RestrictionPath = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
    internal const string BootIdPath = "/proc/sys/kernel/random/boot_id";
    private const long MaxProfileBytes = 64 * 1024;

    public bool Binds => true;

    private static CustodianRefusal Unavailable(string why) => new(ErrorCodes.CodexIsolationUnavailable, $"the Codex sandbox basis cannot be approved: {why}");

    public JsonObject Measure(string codexPath)
    {
        MeasuredImage codex = LinuxImages.MeasureCodex(codexPath);
        string bin = codex.Path[..codex.Path.LastIndexOf('/')];
        if (!bin.EndsWith("/bin", StringComparison.Ordinal) || bin.Length <= "/bin".Length)
            throw Unavailable($"{codex.Path} is not in a Codex installation's bin directory (its bundled bwrap is found beside it, in codex-resources)");
        string bwrapPath = bin[..^"/bin".Length] + "/codex-resources/bwrap";
        MeasuredImage bwrap = LinuxImages.MeasureApproved(bwrapPath, Unavailable);
        string profile = profilePath();
        string profileSha = ProfileSha256(profile, bwrapPath);
        string restriction = ReadProc(RestrictionPath) ?? throw Unavailable($"{RestrictionPath} cannot be read (AppArmor's user-namespace restriction is not available on this kernel)");
        if (restriction != "1") throw Unavailable($"kernel.apparmor_restrict_unprivileged_userns is {restriction}, not 1 (without the restriction the exception is not scoped to the profiled bwrap)");
        string boot = ReadProc(BootIdPath) ?? throw Unavailable("the boot id cannot be read");
        return new JsonObject
        {
            ["codexPath"] = codex.Path, ["codexSha256"] = codex.Sha256, ["codexFileId"] = codex.FileId,
            ["bwrapPath"] = bwrap.Path, ["bwrapSha256"] = bwrap.Sha256, ["bwrapFileId"] = bwrap.FileId,
            ["profilePath"] = profile, ["profileSha256"] = profileSha,
            ["usernsRestriction"] = restriction, ["bootId"] = boot,
        };
    }

    private static string? ReadProc(string path)
    {
        try { return File.ReadAllText(path).Trim(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The profile file's SHA-256, after its rules: root-owned 0644 with one link and root-owned ancestors that
    /// grant no group or other write; exactly one <c>profile</c>, attached to exactly <paramref name="bwrapPath"/>; no
    /// include but the system's <c>tunables/global</c> (a <c>local/</c> or conditional include would extend the profile
    /// with a file this measurement does not cover).</summary>
    internal static string ProfileSha256(string path, string bwrapPath)
    {
        if (!path.StartsWith("/etc/apparmor.d/", StringComparison.Ordinal) || path.Contains("/../", StringComparison.Ordinal) || path.EndsWith("/..", StringComparison.Ordinal))
            throw Unavailable($"the profile path {path} is not a file in /etc/apparmor.d");
        for (string p = path; ;)
        {
            int slash = p.LastIndexOf('/');
            p = slash <= 0 ? "/" : p[..slash];
            if (Libc.StatxFullAt(Libc.AT_FDCWD, p, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull a) != 0 || a.Type != Libc.S_IFDIR || a.Uid != 0 || (a.Perm & 0x12 /* 0o022 */) != 0)
                throw Unavailable($"the profile's ancestor {p} is not a root-owned directory without group or other write");
            if (p == "/") break;
        }
        int fd = Libc.Openat(Libc.AT_FDCWD, path, Libc.O_RDONLY | Libc.O_CLOEXEC | Libc.O_NOFOLLOW, 0);
        if (fd < 0) throw Unavailable($"the AppArmor profile {path} is missing or unreadable ({Libc.ErrText(Libc.Errno)}); profile presence never establishes confinement, but without it there is no approved exception");
        byte[] content;
        using (var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(fd, ownsHandle: true), FileAccess.Read))
        {
            if (Libc.StatxFullFd(fd, out Libc.StatxFull st) != 0) throw Unavailable($"{path} cannot be examined");
            if (st.Type != Libc.S_IFREG || st.Uid != 0 || st.Perm != 0x1A4 /* 0644 */ || st.Nlink != 1)
                throw Unavailable($"the AppArmor profile {path} must be a root-owned 0644 regular file with one link (it is uid {st.Uid}, mode {Convert.ToString(st.Perm, 8)}, {st.Nlink} links)");
            if ((long)st.Size > MaxProfileBytes) throw Unavailable($"the AppArmor profile {path} is larger than {MaxProfileBytes} bytes");
            using var ms = new MemoryStream();
            fs.CopyTo(ms);
            content = ms.ToArray();
        }
        string text;
        try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(content); }
        catch (DecoderFallbackException) { throw Unavailable($"the AppArmor profile {path} is not UTF-8 text"); }
        if (ProfileProblem(text, bwrapPath) is { } why) throw Unavailable($"the AppArmor profile {path} {why}");
        return Convert.ToHexStringLower(SHA256.HashData(content));
    }

    private static readonly Regex Include = new(@"^\s*#?\s*include\b(?<rest>.*)$", RegexOptions.CultureInvariant);
    private static readonly Regex Attachment = new(@"^\s*profile\s+\S+\s+(?:""(?<q>[^""]+)""|(?<u>/\S+))", RegexOptions.CultureInvariant);
    private static readonly Regex ProfileWord = new(@"(^|\s)(profile|hat)\s", RegexOptions.CultureInvariant);

    /// <summary>Why the profile text is not the approved form (null: it is). Pure, so it is self-tested.</summary>
    internal static string? ProfileProblem(string text, string bwrapPath)
    {
        string? attached = null;
        int profiles = 0;
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (Include.Match(line) is { Success: true } inc)
            {
                if (inc.Groups["rest"].Value.Trim() != "<tunables/global>") return $"includes another file ({line.Trim()}), which the custodian does not measure";
                continue;
            }
            string code = line.TrimStart().StartsWith('#') ? "" : line;
            if (code.TrimStart().StartsWith('^')) return "defines a hat";
            if (!ProfileWord.IsMatch(" " + code)) continue;
            profiles++;
            Match m = Attachment.Match(code);
            if (!m.Success) return $"has a profile without an absolute attachment path ({code.Trim()})";
            attached = m.Groups["q"].Success ? m.Groups["q"].Value : m.Groups["u"].Value;
        }
        if (profiles != 1) return $"must define exactly one profile (it defines {profiles})";
        return attached == bwrapPath ? null : $"attaches to {attached}, not to the approved bwrap {bwrapPath}";
    }
}
