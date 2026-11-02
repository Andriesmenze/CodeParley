using System.Diagnostics;

namespace CodeParley.Broker.Linux.Host;

/// <summary>
/// Runs the broker's own helper processes (systemctl, systemd-run, git) by absolute path with an
/// explicit environment and cwd "/": both streams are drained (no pipe-buffer deadlock), stdin is
/// closed, and a timeout kills the child so a hung tool becomes a precise error, never a hung
/// request. The handler's own transient unit is a further bound: anything left is killed with it.
/// </summary>
internal static class ProcessRunner
{
    internal readonly record struct Result(int ExitCode, string StdOut, string StdErr)
    {
        internal string Combined => (StdErr + StdOut).Trim();
    }

    internal static readonly IReadOnlyDictionary<string, string> BaseEnvironment = new Dictionary<string, string>
    {
        ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin",
        ["LANG"] = "C.UTF-8",
        ["SYSTEMD_COLORS"] = "0",
        ["SYSTEMD_PAGER"] = "",
        ["SYSTEMD_LOG_COLOR"] = "0",
    };

    internal static Result Run(string exe, IReadOnlyList<string> args, IReadOnlyDictionary<string, string>? env = null, int timeoutMs = 60_000)
    {
        if (!exe.StartsWith('/')) throw new ArgumentException($"helper must be an absolute path: {exe}");
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            WorkingDirectory = "/",
        };
        psi.Environment.Clear();
        foreach (KeyValuePair<string, string> kv in env ?? BaseEnvironment) psi.Environment[kv.Key] = kv.Value;
        foreach (string a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {exe}");
        p.StandardInput.Close();
        Task<string> outTask = p.StandardOutput.ReadToEndAsync();
        Task<string> errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException($"{Path.GetFileName(exe)} timed out after {timeoutMs} ms: {string.Join(' ', args)}");
        }
        p.WaitForExit();
        return new Result(p.ExitCode, outTask.GetAwaiter().GetResult(), errTask.GetAwaiter().GetResult());
    }

    internal static Result RunChecked(string exe, IReadOnlyList<string> args, IReadOnlyDictionary<string, string>? env = null, int timeoutMs = 60_000)
    {
        Result r = Run(exe, args, env, timeoutMs);
        if (r.ExitCode != 0)
            throw new InvalidOperationException($"{Path.GetFileName(exe)} {string.Join(' ', args)} failed ({r.ExitCode}): {r.Combined}");
        return r;
    }
}
