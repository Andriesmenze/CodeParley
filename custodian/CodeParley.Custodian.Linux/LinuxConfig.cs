using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Linux.Native;

namespace CodeParley.Custodian.Linux;

/// <summary>
/// Phase 5 (contract §4.2, §4.6): the Linux custodian's trusted configuration — the principals and the provisioned
/// filesystems. Written only by root (the provisioning), read by the custodian, never by a model-reachable path:
/// <list type="bullet">
/// <item><c>/etc/codeparley/custodian.json</c>: <c>{"implementer": "&lt;login&gt;", "operator": "&lt;login&gt;", "helper": "codeparley-helper",
/// "codexProfile": "/etc/apparmor.d/&lt;file&gt;"}</c> (the AppArmor profile file of the approved Codex's bwrap, §4.9;
/// default <c>/etc/apparmor.d/codex-bwrap</c>);</item>
/// <item><c>/etc/codeparley/filesystems.json</c>: <c>{"filesystems": [{"uuid": "…", "fsid": "&lt;16 hex&gt;", "metadataCsum": true, "inodeSize": 256}]}</c>.</item>
/// </list>
/// Both files and <c>/etc/codeparley</c> must be root-owned and not group- or other-writable; anything else — a missing,
/// unreadable or malformed file, an unknown account, an implementer equal to the operator or to root — refuses to start
/// (fail closed).
/// </summary>
internal sealed record LinuxConfig(string ImplementerName, uint ImplementerUid, string OperatorName, uint OperatorUid, string HelperName, uint? HelperUid,
    string CodexProfile = LinuxConfig.DefaultCodexProfile)
{
    internal const string DefaultCodexProfile = "/etc/apparmor.d/codex-bwrap";
    internal const string Dir = "/etc/codeparley";
    internal const string ConfigPath = Dir + "/custodian.json";
    internal const string FilesystemsPath = Dir + "/filesystems.json";
    internal const string CustodianAccount = "codeparley";

    private static HashSet<ulong>? _filesystems;

    internal static LinuxConfig Load()
    {
        RequireRootOwned(Dir, directory: true);
        RequireRootOwned(ConfigPath, directory: false);
        JsonObject o = JsonNode.Parse(File.ReadAllText(ConfigPath)) as JsonObject ?? throw new InvalidDataException($"{ConfigPath} is not a JSON object");
        foreach ((string k, _) in o)
            if (k is not ("implementer" or "operator" or "helper" or "codexProfile")) throw new InvalidDataException($"{ConfigPath}: unexpected field '{k}'");
        string impl = (string?)o["implementer"] ?? throw new InvalidDataException($"{ConfigPath}: implementer is required");
        string op = (string?)o["operator"] ?? throw new InvalidDataException($"{ConfigPath}: operator is required");
        string helper = (string?)o["helper"] ?? "codeparley-helper";
        Libc.PasswdEntry implPw = Libc.GetPasswdByName(impl) ?? throw new InvalidDataException($"the implementer account '{impl}' does not exist");
        Libc.PasswdEntry opPw = Libc.GetPasswdByName(op) ?? throw new InvalidDataException($"the operator account '{op}' does not exist");
        if (implPw.Uid == 0 || opPw.Uid == 0) throw new InvalidDataException("neither the implementer nor the operator may be root");
        if (implPw.Uid == opPw.Uid) throw new InvalidDataException("the operator must be a separate account from the implementer (D5-B)");
        uint self = Libc.geteuid();
        if (implPw.Uid == self || opPw.Uid == self) throw new InvalidDataException("the custodian's own account cannot be the implementer or the operator");
        uint? helperUid = Libc.GetPasswdByName(helper)?.Uid;
        string profile = (string?)o["codexProfile"] ?? DefaultCodexProfile;
        string name = profile.StartsWith("/etc/apparmor.d/", StringComparison.Ordinal) ? profile["/etc/apparmor.d/".Length..] : "";
        if (name.Length is 0 or > 128 || name.Contains('/') || name is "." or ".." || name.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)))
            throw new InvalidDataException($"{ConfigPath}: codexProfile must name a file directly in /etc/apparmor.d");
        return new LinuxConfig(impl, implPw.Uid, op, opPw.Uid, helper, helperUid, profile);
    }

    /// <summary>Was the filesystem with this <c>f_fsid</c> provisioned (its metadata_csum and inode size checked by root)?</summary>
    internal static bool FilesystemProvisioned(ulong fsid)
    {
        if (_filesystems is null)
        {
            var set = new HashSet<ulong>();
            try
            {
                RequireRootOwned(FilesystemsPath, directory: false);
                if (JsonNode.Parse(File.ReadAllText(FilesystemsPath))?["filesystems"] is JsonArray a)
                    foreach (JsonObject f in a.OfType<JsonObject>())
                        if ((bool?)f["metadataCsum"] == true && (int?)f["inodeSize"] >= 256 && (string?)f["fsid"] is { Length: 16 } hex)
                            set.Add(Convert.ToUInt64(hex, 16));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException or FormatException) { }
            _filesystems = set;
        }
        return _filesystems.Contains(fsid);
    }

    internal const string RestoreMarkerPath = Dir + "/" + RestoreMarkers.FileName;

    /// <summary>Phase 6 (L-5): the installer's restore marker, or null when there is none. Like the configuration it must be
    /// root-owned and not group/other-writable; a present marker that is not fails the start (fail closed).</summary>
    internal static RestoreMarker? ReadRestoreMarker()
    {
        if (Libc.StatxFullAt(Libc.AT_FDCWD, RestoreMarkerPath, Libc.AT_SYMLINK_NOFOLLOW, out _) != 0) return null;
        RequireRootOwned(RestoreMarkerPath, directory: false);
        return RestoreMarkers.Parse(File.ReadAllText(RestoreMarkerPath), RestoreMarkerPath);
    }

    internal const string TestHoldRecoveryPath = Dir + "/test-hold-recovery-seconds";

    /// <summary>TEST HOOK (NL-7 c): seconds to hold the start BEFORE new-boot recovery, so a client connecting meanwhile is
    /// shown to wait unanswered (nothing is served before recovery and READY=1). Only root can create the file (it must be
    /// root-owned and not group/other-writable, like the configuration); absent → 0. A present but invalid file fails the
    /// start (fail closed). It only delays; it changes no decision.</summary>
    internal static int TestHoldRecoverySeconds()
    {
        if (Libc.StatxFullAt(Libc.AT_FDCWD, TestHoldRecoveryPath, Libc.AT_SYMLINK_NOFOLLOW, out _) != 0) return 0;
        RequireRootOwned(TestHoldRecoveryPath, directory: false);
        string v = File.ReadAllText(TestHoldRecoveryPath).Trim();
        if (!int.TryParse(v, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int s) || s < 1 || s > 60)
            throw new InvalidDataException($"{TestHoldRecoveryPath} must hold a whole number of seconds from 1 to 60");
        return s;
    }

    /// <summary>The path exists, is not a symbolic link, is owned by root and is not group- or other-writable.</summary>
    internal static void RequireRootOwned(string path, bool directory)
    {
        if (Libc.StatxFullAt(Libc.AT_FDCWD, path, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0)
            throw new InvalidDataException($"{path} is missing or unreadable ({Libc.ErrText(Libc.Errno)})");
        if (st.Type != (directory ? Libc.S_IFDIR : Libc.S_IFREG)) throw new InvalidDataException($"{path} is not a {(directory ? "directory" : "regular file")}");
        if (st.Uid != 0) throw new InvalidDataException($"{path} is not owned by root");
        if ((st.Perm & 0x12 /* 0o022 */) != 0) throw new InvalidDataException($"{path} is group- or other-writable");
    }
}
