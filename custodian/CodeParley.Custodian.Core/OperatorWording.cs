namespace CodeParley.Custodian;

/// <summary>
/// Phase 6 Increment 3: the commands a refusal's remedy names, in this host's terms. The operator runs CodeParley's CLI in
/// an elevated terminal on Windows and through the root-owned wrapper as the operator account on Linux; the helper is
/// installed by the custodian's verb on Windows and by the product installer on Linux. Wording only: no authority.
/// </summary>
internal static class OperatorWording
{
    /// <summary>The operator's CLI, as the operator types it.</summary>
    internal static string Cli => OperatingSystem.IsWindows() ? "code-parley" : "/usr/local/sbin/code-parley-operator";

    /// <summary>How the operator installs (or repairs) the helper.</summary>
    internal static string InstallHelper => OperatingSystem.IsWindows()
        ? "`CodeParley.Custodian.exe install-helper`"
        : "the product installer (`sudo bash codeparley-installer.sh install --release <dir>`)";

    /// <summary>How the operator approves the engine runtime, with this host's arguments. On Linux the approved root is the
    /// versioned directory the installer's <c>current</c> link names (the measurement never follows a link); setup resolves it.</summary>
    internal static string ApproveRuntime => OperatingSystem.IsWindows()
        ? "`code-parley setup --repo <path> --runtime <engine dir> --runtime-git-path <installed git.exe>` (elevated)"
        : "`/usr/local/sbin/code-parley-operator setup --repo <path>` (it approves the versioned directory /opt/codeparley/engine/current names)";
}
