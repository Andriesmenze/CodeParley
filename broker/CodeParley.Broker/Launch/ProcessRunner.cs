using System.Diagnostics;

namespace CodeParley.Broker.Launch;

/// <summary>
/// Runs the broker's own helper processes (git, icacls) safely: both stdout and stderr are drained
/// (no pipe-buffer deadlock), a timeout kills a stuck child (so a hung tool becomes a precise error,
/// never a frozen broker), and git is forced non-interactive (no gpg/credential prompts as SYSTEM).
/// </summary>
internal static class ProcessRunner
{
    internal readonly record struct Result(int ExitCode, string StdOut, string StdErr);

    internal static Result Run(string exe, IReadOnlyList<string> args, string? cwd = null, int timeoutMs = 60_000)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (cwd is not null) psi.WorkingDirectory = cwd;
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GIT_CONFIG_NOSYSTEM"] = "1";
        psi.Environment["GIT_CONFIG_GLOBAL"] = "NUL";   // no global config (no gpg-sign / pinentry hang as SYSTEM)
        psi.Environment["GCM_INTERACTIVE"] = "never";
        foreach (string a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {exe}");
        p.StandardInput.Close();                                   // never block on input
        Task<string> outTask = p.StandardOutput.ReadToEndAsync();
        Task<string> errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException($"{Path.GetFileName(exe)} timed out after {timeoutMs} ms: {string.Join(' ', args)}");
        }
        p.WaitForExit();                                           // let the async readers complete
        return new Result(p.ExitCode, outTask.GetAwaiter().GetResult(), errTask.GetAwaiter().GetResult());
    }

    /// <summary>Run and throw on a non-zero exit code.</summary>
    internal static void RunChecked(string exe, IReadOnlyList<string> args, string? cwd = null, int timeoutMs = 60_000)
    {
        Result r = Run(exe, args, cwd, timeoutMs);
        if (r.ExitCode != 0)
            throw new InvalidOperationException($"{Path.GetFileName(exe)} {string.Join(' ', args)} failed ({r.ExitCode}): {(r.StdErr + r.StdOut).Trim()}");
    }
}
