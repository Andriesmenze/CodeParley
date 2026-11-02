using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Linux.Native;

namespace CodeParley.Custodian.Linux.Ipc;

/// <summary>
/// Phase 5 Increment 2 (contract §4.10, D5-C): the Linux helper, one per job. systemd starts the custodian executable with
/// the verb <c>helper</c> as <c>codeparley-helper@N.service</c> (user <c>codeparley-helper</c>, cgroup limits on memory,
/// tasks and runtime, <c>KillMode=control-group</c>) with the custodian's accepted connection as standard input. It holds
/// no authority and no state:
/// <list type="number">
/// <item>it runs only as the helper account, and serves only a peer the kernel identifies (<c>SO_PEERCRED</c> on the
/// accepted socket) as the custodian account — anyone else is refused before a byte is read;</item>
/// <item>it sends a hello, reads ONE request, validates its launch section (plain absolute paths; exactly one
/// <c>safe.directory</c>, the request's repository) and re-hashes the runtime's node and entry against the custodian's
/// measurements;</item>
/// <item>it runs the workload (Node, the approved runtime's helper entry) with an allowlisted environment whose every home
/// and temp variable is the custodian's read-only per-request directory, relays only the workload's frame types (without
/// any correlation or operation field of their own), forwards the custodian's staging notice, kills the whole process tree
/// on a deadline, a broken channel or a frame it does not relay, and reports the exit.</item>
/// </list>
/// It writes nothing. The Windows helper (<c>Cli/HelperHost.cs</c>) is the same protocol over the custodian's helper pipe.
/// </summary>
internal static class LinuxHelperAgent
{
    private static readonly HashSet<string> WorkloadFrames = new(StringComparer.Ordinal) { "file", "stage_complete", "result", "failed" };

    internal static int Run()
    {
        static void Log(string m) => Console.Error.WriteLine(m);
        LinuxConfig cfg;
        try { cfg = LinuxConfig.Load(); }
        catch (Exception e) { Log($"the helper could not read its configuration: {e.Message}"); return 3; }
        uint self = Libc.geteuid();
        if (cfg.HelperUid is not { } helperUid || self != helperUid)
        {
            Log($"the helper must run as '{cfg.HelperName}', not uid {self}; serving nothing");
            return 3;
        }
        uint? custodianUid = Libc.GetPasswdByName(LinuxConfig.CustodianAccount)?.Uid;
        Libc.UCred peer;
        try { peer = Libc.PeerCredentials(0); }
        catch (IOException e) { Log($"standard input is not the custodian's connection ({e.Message}); serving nothing"); return 3; }
        if (custodianUid is null || peer.Uid != custodianUid)
        {
            Log($"refused a peer: uid {peer.Uid} (pid {peer.Pid}) is not the custodian account '{LinuxConfig.CustodianAccount}'; nothing was read");
            return 3;
        }
        using var socket = new Socket(new SafeSocketHandle(0, ownsHandle: false));
        using var stream = new NetworkStream(socket, ownsSocket: false);
        try
        {
            ServeAsync(stream, Log).GetAwaiter().GetResult();
            return 0;
        }
        catch (Exception e)
        {
            Log($"the request ended on a channel failure: {e.Message}");
            return 1;
        }
    }

    /// <summary>The launch fields of a request, validated.</summary>
    internal sealed record Launch(string Node, string NodeSha256, string Entry, string EntrySha256, string Git, string Home, string GitConfig, string Repository, string SafeDirectory, long MaxFrameBody);

    internal static Launch ParseLaunch(JsonObject request)
    {
        if (request["launch"] is not JsonObject l) throw new HelperFrameError("the request has no launch section");
        string Abs(string key)
        {
            string v = l[key] is JsonValue jv && jv.TryGetValue(out string? s) && s is not null ? s : throw new HelperFrameError($"launch.{key} is missing");
            if (v.Length is < 2 or > 1024 || !v.StartsWith('/') || v.Contains('\0') || v.Split('/').Skip(1).Any(seg => seg is "" or "." or ".."))
                throw new HelperFrameError($"launch.{key} must be a plain absolute path");
            return v;
        }
        string Hex(string key) => l[key] is JsonValue jv && jv.TryGetValue(out string? s) && s is { Length: 64 } && s.All(Uri.IsHexDigit) ? s.ToLowerInvariant() : throw new HelperFrameError($"launch.{key} must be a SHA-256");
        string repo = Abs("repository");
        string safe = l["safeDirectory"] is JsonValue sv && sv.TryGetValue(out string? sd) && sd is not null ? sd : throw new HelperFrameError("launch.safeDirectory is missing");
        // §A.4: exactly one safe.directory, the validated repository itself — never '*', a parent or another path.
        if (!string.Equals(safe, repo, StringComparison.Ordinal)) throw new HelperFrameError("launch.safeDirectory must be exactly the request's repository");
        long maxBody = l["maxFrameBody"] is JsonValue mv && mv.TryGetValue(out long m) && m is > 0 ? Math.Min(m, CustodianConstants.MaxHelperBodyBytes) : throw new HelperFrameError("launch.maxFrameBody is missing");
        return new Launch(Abs("node"), Hex("nodeSha256"), Abs("entry"), Hex("entrySha256"), Abs("git"), Abs("home"), Abs("gitconfig"), repo, safe, maxBody);
    }

    /// <summary>The workload's environment: named variables only. Every home, temp and XDG variable is the custodian's
    /// read-only per-request directory; git reads no system or global configuration and trusts exactly the repository.</summary>
    internal static Dictionary<string, string> WorkloadEnvironment(Launch l) => new(StringComparer.Ordinal)
    {
        ["PATH"] = string.Join(':', Path.GetDirectoryName(l.Git)!, "/usr/bin", "/bin"),
        ["HOME"] = l.Home, ["TMPDIR"] = l.Home,
        ["XDG_CONFIG_HOME"] = l.Home, ["XDG_DATA_HOME"] = l.Home, ["XDG_CACHE_HOME"] = l.Home, ["XDG_STATE_HOME"] = l.Home,
        ["LANG"] = "C.UTF-8", ["LC_ALL"] = "C.UTF-8",
        ["GIT_CONFIG_NOSYSTEM"] = "1", ["GIT_CONFIG_GLOBAL"] = l.GitConfig,
        ["GIT_CONFIG_COUNT"] = "1", ["GIT_CONFIG_KEY_0"] = "safe.directory", ["GIT_CONFIG_VALUE_0"] = l.SafeDirectory,
        ["GIT_TERMINAL_PROMPT"] = "0", ["GIT_OPTIONAL_LOCKS"] = "0", ["GIT_NO_LAZY_FETCH"] = "1",
        ["CODEPARLEY_HELPER"] = "1",
    };

    private static async Task ServeAsync(Stream channel, Action<string> log)
    {
        await HelperFrames.WriteAsync(channel, new JsonObject { ["t"] = "hello", ["v"] = 1 }, ReadOnlyMemory<byte>.Empty, CancellationToken.None).ConfigureAwait(false);
        HelperFrame? request;
        using (var wait = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            request = await HelperFrames.ReadAsync(channel, CustodianConstants.MaxHelperBodyBytes, wait.Token).ConfigureAwait(false);
        if (request is null || request.Type == "bye") return;
        if (request.Type != "request") { log($"the custodian answered the hello with '{request.Type}'"); return; }

        string? ticket = request.Str("ticket"), instance = request.Str("instance"), kind = request.Str("kind");
        long timeoutMs = Math.Clamp(request.Long("timeoutMs") ?? 0, 1000, CustodianConstants.HelperRequestSeconds * 1000L);
        async Task Send(JsonObject header, ReadOnlyMemory<byte> body)
        {
            header["ticket"] = ticket;
            header["instance"] = instance;
            await HelperFrames.WriteAsync(channel, header, body, CancellationToken.None).ConfigureAwait(false);
        }
        if (!IsToken(ticket) || !IsToken(instance) || kind is not ("capture" or "derive"))
        {
            log($"refused a malformed request (kind '{kind}')");
            await Send(new JsonObject { ["t"] = "exit", ["exitCode"] = -1, ["stderr"] = "malformed request" }, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            return;
        }
        Launch launch;
        try
        {
            JsonObject body = JsonNode.Parse(request.Body) as JsonObject ?? throw new HelperFrameError("the request body is not a JSON object");
            launch = ParseLaunch(body);
            if (Sha256Of(launch.Node) != launch.NodeSha256) throw new HelperFrameError("node does not match the custodian's measurement");
            if (Sha256Of(launch.Entry) != launch.EntrySha256) throw new HelperFrameError("the engine entry does not match the custodian's measurement");
            if (!File.Exists(launch.Git)) throw new HelperFrameError("the approved git is missing");
        }
        catch (Exception e) when (e is HelperFrameError or JsonException or IOException or UnauthorizedAccessException)
        {
            log($"refused a request: {e.Message}");
            await Send(new JsonObject { ["t"] = "failed", ["code"] = "REQUEST_REFUSED", ["detail"] = e.Message }, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            await Send(new JsonObject { ["t"] = "exit", ["exitCode"] = -1 }, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            return;
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeoutMs));
        bool timedOut = false;
        string? relayProblem = null;
        int exitCode = -1;
        string stderr = "";
        var psi = new ProcessStartInfo(launch.Node)
        {
            WorkingDirectory = launch.Home, UseShellExecute = false,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        psi.ArgumentList.Add(launch.Entry);
        psi.ArgumentList.Add(kind);
        psi.Environment.Clear();
        foreach ((string k, string v) in WorkloadEnvironment(launch)) psi.Environment[k] = v;
        Process? child = null;
        try
        {
            child = Process.Start(psi) ?? throw new IOException("the workload could not be started");
            Process started = child;
            using CancellationTokenRegistration killOnDeadline = deadline.Token.Register(() => Kill(started));
            Task<string> errTail = Tail(child.StandardError.BaseStream, 4096);
            Stream childIn = child.StandardInput.BaseStream, childOut = child.StandardOutput.BaseStream;
            await childIn.WriteAsync(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(request.Body).ReplaceLineEndings(" ") + "\n"), deadline.Token).ConfigureAwait(false);
            await childIn.FlushAsync(deadline.Token).ConfigureAwait(false);

            // Custodian → workload: the staging notice (correlated), nothing else.
            Task inbound = Task.Run(async () =>
            {
                while (!deadline.IsCancellationRequested)
                {
                    HelperFrame? f = await HelperFrames.ReadAsync(channel, 64 * 1024, deadline.Token).ConfigureAwait(false);
                    if (f is null) throw new IOException("the custodian closed the channel");
                    if (f.Type != "staged" || f.Str("ticket") != ticket || f.Str("instance") != instance || f.Str("dir") is not { Length: > 0 } dir)
                        throw new HelperFrameError($"an unexpected '{f.Type}' frame from the custodian");
                    string line = new JsonObject { ["t"] = "staged", ["dir"] = dir }.ToJsonString() + "\n";
                    await childIn.WriteAsync(Encoding.UTF8.GetBytes(line), deadline.Token).ConfigureAwait(false);
                    await childIn.FlushAsync(deadline.Token).ConfigureAwait(false);
                }
            }, deadline.Token);

            // Workload → custodian: only the workload's frame types, without any correlation or operation field of its own.
            while (true)
            {
                HelperFrame? f = await HelperFrames.ReadAsync(childOut, launch.MaxFrameBody, deadline.Token).ConfigureAwait(false);
                if (f is null) break;
                if (!WorkloadFrames.Contains(f.Type) || f.Header.ContainsKey("ticket") || f.Header.ContainsKey("instance") || f.Header.ContainsKey("op"))
                {
                    relayProblem = $"the workload sent a '{f.Type}' frame the helper does not relay";
                    break;
                }
                await Send(f.Header, f.Body).ConfigureAwait(false);
                if (inbound.IsFaulted) { relayProblem = inbound.Exception?.InnerException?.Message; break; }
            }
            if (deadline.IsCancellationRequested) timedOut = true;
            if (relayProblem is not null) Kill(child);
            using (var grace = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                try { await child.WaitForExitAsync(grace.Token).ConfigureAwait(false); exitCode = child.ExitCode; }
                catch (OperationCanceledException) { Kill(child); }
            }
            if (await Task.WhenAny(errTail, Task.Delay(5000)).ConfigureAwait(false) == errTail) stderr = errTail.Result;
        }
        catch (OperationCanceledException) { timedOut = true; if (child is not null) Kill(child); }
        catch (Exception e) when (e is HelperFrameError or IOException or System.ComponentModel.Win32Exception)
        {
            relayProblem = e.Message;
            if (child is not null) Kill(child);
        }
        finally
        {
            if (child is not null) { Kill(child); child.Dispose(); }
        }
        if (relayProblem is not null) log($"the workload was stopped: {relayProblem}");
        var exit = new JsonObject
        {
            ["t"] = "exit", ["exitCode"] = timedOut || relayProblem is not null ? -1 : exitCode, ["timedOut"] = timedOut,
            ["stderr"] = relayProblem ?? (stderr.Length > 2000 ? stderr[^2000..] : stderr),
        };
        try { await Send(exit, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false); }
        catch (Exception e) when (e is IOException or OperationCanceledException) { }
    }

    /// <summary>Kill the workload and everything it started (the unit's cgroup is the backstop: KillMode=control-group).</summary>
    private static void Kill(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static async Task<string> Tail(Stream s, int max)
    {
        var ring = new Queue<byte>();
        byte[] buf = new byte[4096];
        try
        {
            for (int n; (n = await s.ReadAsync(buf).ConfigureAwait(false)) > 0;)
                for (int i = 0; i < n; i++) { ring.Enqueue(buf[i]); if (ring.Count > max) ring.Dequeue(); }
        }
        catch (IOException) { }
        return Encoding.UTF8.GetString(ring.ToArray());
    }

    private static bool IsToken(string? s) => s is { Length: 32 } && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string Sha256Of(string path)
    {
        using FileStream fs = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(fs));
    }
}
