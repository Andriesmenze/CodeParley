using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// P3.4C-5 (§A.1, §A.3): the <c>CodeParleyHelper</c> service. The SCM starts the custodian executable with the verb
/// <c>helper-service</c> under the virtual account <c>NT SERVICE\CodeParleyHelper</c>; this hosts <see cref="HelperHostService"/>.
/// It holds no authority and no state: it attaches to the custodian's helper pipe, runs the one request it is sent, and
/// stops once idle.
/// </summary>
internal static class HelperHost
{
    internal static int Run(string[] args)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = CustodianConstants.HelperServiceName);
        builder.Services.AddHostedService<HelperHostService>();
        builder.Build().Run();
        return 0;
    }
}

internal sealed class HelperHostService(ILogger<HelperHostService> log, IHostApplicationLifetime lifetime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        SecurityIdentifier? self = WindowsIdentity.GetCurrent().User;
        SecurityIdentifier expected = ServiceSid.Of(CustodianConstants.HelperServiceName);
        if (self != expected)
        {
            // Fail closed: the helper verb serves only as its own dedicated identity, never as another account.
            log.LogError("the helper must run as {Expected}, not {Self}; not attaching", CustodianConstants.HelperVirtualAccount, self?.Value);
            lifetime.StopApplication();
            return;
        }
        log.LogInformation("CodeParley Helper starting as {Self}", self.Value);
        try { await new HelperAgent(ServiceSid.Custodian(), TimeSpan.FromMinutes(5), log).RunAsync(stoppingToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        catch (Exception e) { log.LogError(e, "the helper faulted"); }
        log.LogInformation("CodeParley Helper stopping (idle or stopped)");
        lifetime.StopApplication();
    }
}

/// <summary>
/// The helper's work loop (testable in-process). For each attachment it:
/// <list type="number">
/// <item>authenticates the SERVER before sending anything: the connected pipe must be owned by the custodian service's
/// SID and grant no other principal (SYSTEM aside) the right to create instances or change its security — the check the
/// TypeScript client makes of the custodian's implementer pipe (src/custodian/pipe-transport.ts);</item>
/// <item>sends a hello, then serves the one request it is sent (or goes idle on a goodbye);</item>
/// <item>validates the request, re-hashes the runtime's <c>node.exe</c> and entry script against the custodian's
/// measurements, and runs the workload in a job (<see cref="HelperChild"/>) with an allowlisted environment that points
/// every home and temp variable at the custodian's read-only per-request directory and gives git exactly one
/// <c>safe.directory</c> — the validated repository;</item>
/// <item>relays the workload's frames to the custodian with the request's ticket and instance, forwards the custodian's
/// staging notice, kills the job on a deadline, a broken channel or a frame it does not relay, and reports the exit.</item>
/// </list>
/// It writes nothing to disk.
/// </summary>
internal sealed class HelperAgent(SecurityIdentifier expectedServer, TimeSpan idleLimit, ILogger log)
{
    /// <summary>The rights no principal but the custodian and SYSTEM may hold on its pipe (create an instance, change its
    /// DACL or owner, generic write/all) — FOREIGN_FORBIDDEN_RIGHTS in src/custodian/pipe-transport.ts.</summary>
    internal const int ForeignForbiddenRights = 0x4 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    private static readonly HashSet<string> WorkloadFrames = new(StringComparer.Ordinal) { "file", "stage_complete", "result", "failed" };

    /// <summary>Requests served so far (diagnostics and the self-test).</summary>
    internal int Served { get; private set; }

    internal async Task RunAsync(CancellationToken ct)
    {
        DateTime lastWork = DateTime.UtcNow;
        while (!ct.IsCancellationRequested && DateTime.UtcNow - lastWork < idleLimit)
        {
            NamedPipeClientStream? pipe = await TryConnectAsync(ct).ConfigureAwait(false);
            if (pipe is null) { await Task.Delay(2000, ct).ConfigureAwait(false); continue; }
            using (pipe)
            {
                string? problem = ServerProblem(pipe, expectedServer);
                if (problem is not null)
                {
                    log.LogError("the helper pipe is not the custodian's ({Problem}); nothing was sent", problem);
                    await Task.Delay(2000, ct).ConfigureAwait(false);
                    continue;
                }
                HelperFrame? first;
                try
                {
                    await HelperFrames.WriteAsync(pipe, new JsonObject { ["t"] = "hello", ["v"] = 1 }, ct).ConfigureAwait(false);
                    using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    wait.CancelAfter(TimeSpan.FromSeconds(30));
                    first = await HelperFrames.ReadAsync(pipe, CustodianConstants.MaxHelperBodyBytes, wait.Token).ConfigureAwait(false);
                }
                catch (Exception e) when (e is IOException or HelperFrameError or OperationCanceledException && !ct.IsCancellationRequested)
                {
                    log.LogWarning("the helper channel failed before a request: {Error}", e.Message);
                    continue;
                }
                switch (first?.Type)
                {
                    case "bye":
                        await Task.Delay(1000, ct).ConfigureAwait(false);
                        continue;
                    case "request":
                        // A request ends when the custodian has its outcome; the custodian may close the channel first (a
                        // refusal, a deadline), so a failure here ends this request only, never the helper.
                        try { await ServeRequestAsync(pipe, first, ct).ConfigureAwait(false); }
                        catch (Exception e) when (e is IOException or HelperFrameError or ObjectDisposedException || e is OperationCanceledException && !ct.IsCancellationRequested)
                        {
                            log.LogWarning("the request ended on a channel failure: {Error}", e.Message);
                        }
                        Served++;
                        lastWork = DateTime.UtcNow;
                        continue;
                    default:
                        log.LogWarning("the custodian answered the hello with '{Type}' ({Detail})", first?.Type ?? "nothing", first?.Str("detail"));
                        await Task.Delay(2000, ct).ConfigureAwait(false);
                        continue;
                }
            }
        }
    }

    private static async Task<NamedPipeClientStream?> TryConnectAsync(CancellationToken ct)
    {
        var c = new NamedPipeClientStream(".", CustodianConstants.HelperPipe, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try { await c.ConnectAsync(5000, ct).ConfigureAwait(false); return c; }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException) { c.Dispose(); return null; }
    }

    /// <summary>Why the connected pipe is not the custodian's, or null when it is (owner and access list).</summary>
    internal static string? ServerProblem(NamedPipeClientStream pipe, SecurityIdentifier expected)
    {
        PipeSecurity sd;
        try { sd = pipe.GetAccessControl(); }
        catch (Exception e) { return "its security cannot be read: " + e.Message; }
        var owner = (SecurityIdentifier?)sd.GetOwner(typeof(SecurityIdentifier));
        if (owner is null) return "its owner cannot be read";
        if (owner != expected) return $"it is owned by {owner.Value}, not by the custodian identity {expected.Value}";
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        foreach (PipeAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (rule.AccessControlType == AccessControlType.Allow && sid != expected && sid != system && ((int)rule.PipeAccessRights & ForeignForbiddenRights) != 0)
                return $"its access list lets {sid.Value} create instances or change its security";
        }
        return null;
    }

    /// <summary>The launch fields of a request, validated.</summary>
    internal sealed record Launch(string Node, string NodeSha256, string Entry, string EntrySha256, string Git, string Home, string GitConfig, string Repository, string SafeDirectory, long MaxFrameBody);

    internal static Launch ParseLaunch(JsonObject request)
    {
        if (request["launch"] is not JsonObject l) throw new HelperFrameError("the request has no launch section");
        string Abs(string key)
        {
            string v = l[key] is JsonValue jv && jv.TryGetValue(out string? s) && s is not null ? s : throw new HelperFrameError($"launch.{key} is missing");
            if (v.Length is < 4 or > 1024 || !Path.IsPathFullyQualified(v) || v.StartsWith(@"\\", StringComparison.Ordinal) || v.Contains("..", StringComparison.Ordinal) || v.Contains('*') || v.Contains('?'))
                throw new HelperFrameError($"launch.{key} must be a plain absolute local path");
            return v;
        }
        string Hex(string key) => l[key] is JsonValue jv && jv.TryGetValue(out string? s) && s is { Length: 64 } && s.All(Uri.IsHexDigit) ? s.ToLowerInvariant() : throw new HelperFrameError($"launch.{key} must be a SHA-256");
        string repo = Abs("repository");
        string safe = l["safeDirectory"] is JsonValue sv && sv.TryGetValue(out string? sd) && sd is not null ? sd : throw new HelperFrameError("launch.safeDirectory is missing");
        // §A.4: exactly one safe.directory, the validated repository itself — never '*', a parent or another path.
        if (safe.Contains('*') || !string.Equals(safe.Replace('\\', '/').TrimEnd('/'), repo.Replace('\\', '/').TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
            throw new HelperFrameError("launch.safeDirectory must be exactly the request's repository");
        long maxBody = l["maxFrameBody"] is JsonValue mv && mv.TryGetValue(out long m) && m is > 0 ? Math.Min(m, CustodianConstants.MaxHelperBodyBytes) : throw new HelperFrameError("launch.maxFrameBody is missing");
        return new Launch(Abs("node"), Hex("nodeSha256"), Abs("entry"), Hex("entrySha256"), Abs("git"), Abs("home"), Abs("gitconfig"), repo, safe, maxBody);
    }

    /// <summary>The workload's environment: named variables only. Every home and temp variable is the custodian's read-only
    /// per-request directory (the helper is given no writable scratch); git reads no system or global configuration and
    /// trusts exactly the validated repository (§A.4).</summary>
    internal static Dictionary<string, string> WorkloadEnvironment(Launch l)
    {
        string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = sysRoot,
            ["SystemDrive"] = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:",
            ["windir"] = sysRoot,
            ["PATH"] = string.Join(';', Path.GetDirectoryName(l.Git)!, Path.Combine(sysRoot, "System32")),
            ["PATHEXT"] = ".COM;.EXE;.BAT;.CMD",
            ["USERPROFILE"] = l.Home, ["HOME"] = l.Home, ["APPDATA"] = l.Home, ["LOCALAPPDATA"] = l.Home,
            ["TEMP"] = l.Home, ["TMP"] = l.Home,
            ["GIT_CONFIG_NOSYSTEM"] = "1", ["GIT_CONFIG_GLOBAL"] = l.GitConfig,
            ["GIT_CONFIG_COUNT"] = "1", ["GIT_CONFIG_KEY_0"] = "safe.directory", ["GIT_CONFIG_VALUE_0"] = l.SafeDirectory,
            ["GIT_TERMINAL_PROMPT"] = "0", ["GIT_OPTIONAL_LOCKS"] = "0", ["GIT_NO_LAZY_FETCH"] = "1",
            ["CODEPARLEY_HELPER"] = "1",
        };
    }

    private async Task ServeRequestAsync(NamedPipeClientStream pipe, HelperFrame request, CancellationToken ct)
    {
        string? ticket = request.Str("ticket"), instance = request.Str("instance"), kind = request.Str("kind");
        long timeoutMs = Math.Clamp(request.Long("timeoutMs") ?? 0, 1000, CustodianConstants.HelperRequestSeconds * 1000L);
        async Task Send(JsonObject header, ReadOnlyMemory<byte> body)
        {
            header["ticket"] = ticket;
            header["instance"] = instance;
            await HelperFrames.WriteAsync(pipe, header, body, ct).ConfigureAwait(false);
        }
        if (!IsToken(ticket) || !IsToken(instance) || kind is not ("capture" or "derive"))
        {
            log.LogWarning("refused a malformed request (kind '{Kind}')", kind);
            await Send(new JsonObject { ["t"] = "exit", ["exitCode"] = -1, ["stderr"] = "malformed request" }, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            return;
        }
        Launch launch;
        try
        {
            JsonObject body = JsonNode.Parse(request.Body) as JsonObject ?? throw new HelperFrameError("the request body is not a JSON object");
            launch = ParseLaunch(body);
            if (Sha256Of(launch.Node) != launch.NodeSha256) throw new HelperFrameError("node.exe does not match the custodian's measurement");
            if (Sha256Of(launch.Entry) != launch.EntrySha256) throw new HelperFrameError("the engine entry does not match the custodian's measurement");
            if (!File.Exists(launch.Git)) throw new HelperFrameError("the approved git is missing");
        }
        catch (Exception e) when (e is HelperFrameError or JsonException or IOException or UnauthorizedAccessException)
        {
            log.LogWarning("refused a request: {Error}", e.Message);
            await Send(new JsonObject { ["t"] = "failed", ["code"] = "REQUEST_REFUSED", ["detail"] = e.Message }, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            await Send(new JsonObject { ["t"] = "exit", ["exitCode"] = -1 }, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            return;
        }

        var limits = HelperLimits.Default with { WallTime = TimeSpan.FromMilliseconds(timeoutMs) };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(limits.WallTime);
        bool timedOut = false, refused = false;
        string? relayProblem = null;
        int exitCode = -1;
        string stderr = "";
        HelperChild? child = null;
        try
        {
            child = HelperChild.Start(launch.Node, [launch.Entry, kind], launch.Home, WorkloadEnvironment(launch), limits);
            // The child's streams are synchronous handles: a blocked read or write ignores cancellation, so the deadline (and
            // the service stopping) kills the whole job, which ends both.
            HelperChild started = child;
            using CancellationTokenRegistration killOnDeadline = deadline.Token.Register(() => started.Kill());
            await child.Stdin.WriteAsync(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(request.Body).ReplaceLineEndings(" ") + "\n"), deadline.Token).ConfigureAwait(false);
            await child.Stdin.FlushAsync(deadline.Token).ConfigureAwait(false);

            // Custodian → workload: the staging notice (correlated), nothing else.
            Task inbound = Task.Run(async () =>
            {
                while (!deadline.IsCancellationRequested)
                {
                    HelperFrame? f = await HelperFrames.ReadAsync(pipe, 64 * 1024, deadline.Token).ConfigureAwait(false);
                    if (f is null) throw new IOException("the custodian closed the channel");
                    if (f.Type != "staged" || f.Str("ticket") != ticket || f.Str("instance") != instance || f.Str("dir") is not { Length: > 0 } dir)
                        throw new HelperFrameError($"an unexpected '{f.Type}' frame from the custodian");
                    string line = new JsonObject { ["t"] = "staged", ["dir"] = dir }.ToJsonString() + "\n";
                    await child.Stdin.WriteAsync(Encoding.UTF8.GetBytes(line), deadline.Token).ConfigureAwait(false);
                    await child.Stdin.FlushAsync(deadline.Token).ConfigureAwait(false);
                }
            }, deadline.Token);

            // Workload → custodian: only the workload's frame types, without any correlation or operation field of its own.
            while (true)
            {
                HelperFrame? f = await HelperFrames.ReadAsync(child.Stdout, launch.MaxFrameBody, deadline.Token).ConfigureAwait(false);
                if (f is null) break; // the workload closed stdout (exited)
                if (!WorkloadFrames.Contains(f.Type) || f.Header.ContainsKey("ticket") || f.Header.ContainsKey("instance") || f.Header.ContainsKey("op"))
                {
                    relayProblem = $"the workload sent a '{f.Type}' frame the helper does not relay";
                    refused = true;
                    break;
                }
                await Send(f.Header, f.Body).ConfigureAwait(false);
                if (inbound.IsFaulted) { relayProblem = inbound.Exception?.InnerException?.Message; break; }
            }
            if (deadline.IsCancellationRequested && !ct.IsCancellationRequested) timedOut = true;
            if (refused || relayProblem is not null) child.Kill();
            using (var grace = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token))
            {
                grace.CancelAfter(TimeSpan.FromSeconds(10));
                try { exitCode = await child.WaitAsync(grace.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { child.Kill(); }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { timedOut = true; child?.Kill(); }
        catch (Exception e) when (e is HelperFrameError or IOException or System.ComponentModel.Win32Exception)
        {
            relayProblem = e.Message;
            child?.Kill();
        }
        finally
        {
            if (child is not null)
            {
                child.Kill();
                if (child.StderrTail.Wait(TimeSpan.FromSeconds(5))) stderr = child.StderrTail.Result;
                child.Dispose();
            }
        }
        if (relayProblem is not null) log.LogWarning("the workload was stopped: {Problem}", relayProblem);
        var exit = new JsonObject
        {
            ["t"] = "exit", ["exitCode"] = timedOut || relayProblem is not null ? -1 : exitCode, ["timedOut"] = timedOut,
            ["stderr"] = relayProblem ?? (stderr.Length > 2000 ? stderr[^2000..] : stderr),
        };
        try { await Send(exit, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false); }
        catch (Exception e) when (e is IOException or OperationCanceledException) { }
    }

    private static bool IsToken(string? s) => s is { Length: 32 } && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string Sha256Of(string path)
    {
        using FileStream fs = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(fs));
    }
}
