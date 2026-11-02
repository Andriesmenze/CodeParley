namespace CodeParley.Broker.Launch;

/// <summary>
/// Absolute trusted host tool paths the broker resolves itself (never caller-supplied). Hardcoded,
/// existence-checked defaults for this milestone; a later version reads these from trusted config.
/// </summary>
internal static class HostTools
{
    private static readonly string System32 =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");

    internal static string PowerShell => Path.Combine(System32, "WindowsPowerShell", "v1.0", "powershell.exe");

    internal static string GitExe =>
        FirstExisting(@"C:\Program Files\Git\cmd\git.exe", @"C:\Program Files\Git\bin\git.exe") ?? "git.exe";

    internal static string GitCmdDir => @"C:\Program Files\Git\cmd";
    internal static string NodeDir => @"C:\Program Files\nodejs";
    internal static string NodeExe => Path.Combine(NodeDir, "node.exe");
    internal static string ComSpec => Path.Combine(System32, "cmd.exe");

    /// <summary>Absolute tool dirs prepended to the worker PATH for deterministic resolution.</summary>
    internal static IReadOnlyList<string> WorkerPathDirs => [NodeDir, GitCmdDir];

    private static string? FirstExisting(params string[] paths) => paths.FirstOrDefault(File.Exists);
}
