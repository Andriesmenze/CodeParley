using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;
using Microsoft.Extensions.Logging;

namespace CodeParley.Custodian.Ipc;

/// <summary>
/// The authenticated named-pipe surfaces. Each pipe's DACL admits only SYSTEM and the one configured identity for that
/// surface (never a group); the connected client is additionally impersonated and classified from its token
/// (CallerClassifier). The first pipe instance is created with <see cref="PipeOptions.FirstPipeInstance"/>, so a squatted
/// pipe of the same name makes our own create fail and that surface stop (fail closed, not serve through an attacker's
/// pipe).
/// <list type="bullet">
/// <item>Implementer and operator: one line-delimited JSON request per connection, one response; served sequentially.</item>
/// <item>Helper (P3.4C-5 §A.2, hosted only when a helper identity is configured): its DACL also admits the custodian's own
/// SID; the client sends one hello frame, is classified by SID alone, and is then handed to the
/// <see cref="HelperBroker"/>, which sends it at most one measurement request. Any other first frame — an authority
/// operation shape included — is refused and audited.</item>
/// </list>
/// </summary>
internal sealed class PipeServer
{
    private readonly CustodianCore _core;
    private readonly ILogger _log;
    private readonly CustodianConfig _cfg;
    private readonly HelperBroker? _broker;

    internal PipeServer(CustodianCore core, ILogger log, CustodianConfig cfg, HelperBroker? broker = null)
    {
        _core = core; _log = log; _cfg = cfg; _broker = broker;
    }

    internal async Task RunAsync(CancellationToken ct)
    {
        bool helper = _broker is not null && _cfg.HelperSid is not null;
        _log.LogInformation("custodian IPC: implementer=\\\\.\\pipe\\{Imp} operator=\\\\.\\pipe\\{Op} helper={Helper}",
            CustodianConstants.ImplementerPipe, CustodianConstants.OperatorPipe, helper ? @"\\.\pipe\" + CustodianConstants.HelperPipe : "(not installed)");
        var surfaces = new List<Task>
        {
            Listen(CustodianConstants.ImplementerPipe, PipeSurface.Implementer, ct),
            Listen(CustodianConstants.OperatorPipe, PipeSurface.Operator, ct),
        };
        if (helper) surfaces.Add(Listen(CustodianConstants.HelperPipe, PipeSurface.Helper, ct));
        await Task.WhenAll(surfaces).ConfigureAwait(false);
    }

    /// <summary>Set once the helper surface could not be created (a squatted name): measurements then fail closed.</summary>
    internal bool HelperSurfaceFailed { get; private set; }

    private async Task Listen(string pipeName, PipeSurface surface, CancellationToken ct)
    {
        bool first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try { server = Create(pipeName, surface, first); }
            catch (Exception e)
            {
                // FirstPipeInstance failing means someone holds the name: refuse to serve (fail closed).
                _log.LogError(e, "cannot create pipe {Pipe} (squatted?); this surface will not serve", pipeName);
                if (surface == PipeSurface.Helper) HelperSurfaceFailed = true;
                return;
            }
            first = false;
            using (server)
            {
                try { await server.WaitForConnectionAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                catch (Exception e) { _log.LogWarning(e, "pipe {Pipe} wait failed", pipeName); continue; }
                try
                {
                    if (surface == PipeSurface.Helper) await ServeHelper(server, ct).ConfigureAwait(false);
                    else await ServeOne(server, surface, ct).ConfigureAwait(false);
                }
                catch (Exception e) { _log.LogWarning(e, "pipe {Pipe} client failed", pipeName); }
                finally { try { if (server.IsConnected) server.Disconnect(); } catch { } }
            }
        }
    }

    private NamedPipeServerStream Create(string pipeName, PipeSurface surface, bool first)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        SecurityIdentifier who = surface switch
        {
            PipeSurface.Operator => _cfg.OperatorSecurityIdentifier(),
            PipeSurface.Implementer => _cfg.ImplementerSecurityIdentifier(),
            _ => _cfg.HelperSecurityIdentifier() ?? throw new InvalidOperationException("no helper identity is configured"),
        };
        security.AddAccessRule(new PipeAccessRule(who, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        if (surface == PipeSurface.Helper)
        {
            // §A.2: the helper pipe grants exactly the custodian service SID, the helper service SID and SYSTEM.
            SecurityIdentifier self = WindowsIdentity.GetCurrent().User!;
            if (self != who) security.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }
        PipeOptions opts = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, opts, 0, 0, security);
    }

    private async Task ServeOne(NamedPipeServerStream server, PipeSurface surface, CancellationToken ct)
    {
        using var reader = new StreamReader(server, Encoding.UTF8, false, 4096, leaveOpen: true);
        // Read the request first: client data must have flowed before impersonation for reliable
        // named-pipe client authentication (the reviewed broker ordering).
        Task<string?> readTask = reader.ReadLineAsync(ct).AsTask();
        string? line = await readTask.ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return;
        if (line.Length > CustodianConstants.MaxRequestBytes) { await Write(server, Response.Fail(ErrorCodes.MalformedRequest, "request too large"), ct); return; }

        // Read only the token facts under impersonation (an identification-level token cannot open
        // files); decide + hash the proof digest after reverting to self.
        CallerClassifier.TokenFacts facts = default;
        server.RunAsClient(() => facts = CallerClassifier.ReadFacts());
        CallerClassifier.Result cls = CallerClassifier.Decide(surface, _cfg, facts);
        if (cls.Class == CallerClass.Unknown)
        {
            _log.LogWarning("rejected caller on {Surface}: {Detail}", surface == PipeSurface.Operator ? "operator" : "implementer", cls.Detail);
            await Write(server, Response.Fail(ErrorCodes.CallerNotAuthorized, cls.Detail), ct);
            return;
        }

        // P3.4C-2: the connected process as the system reports it (correlation evidence for the loop-binding
        // check, D7 — never an identity or an authority; the caller class above is the authority).
        int? clientPid = ClientPid(server);

        Response resp;
        try
        {
            Request req = Request.Parse(line);
            resp = _core.Handle(cls.Class, req, cls.ProofDigest, clientPid);
        }
        catch (Exception e) { resp = Response.Fail(ErrorCodes.MalformedRequest, "bad request: " + e.Message); }
        await Write(server, resp, ct).ConfigureAwait(false);
    }

    /// <summary>The helper surface (§A.2): a hello frame first (client data before impersonation), then classification by
    /// SID; only an authenticated helper reaches the broker.</summary>
    private async Task ServeHelper(NamedPipeServerStream server, CancellationToken ct)
    {
        HelperFrame? hello = null;
        string? frameProblem = null;
        using (var helloTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            helloTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            try { hello = await HelperFrames.ReadAsync(server, 4096, helloTimeout.Token).ConfigureAwait(false); }
            catch (HelperFrameError e) { frameProblem = e.Message; }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { frameProblem = "no hello within 10 s"; }
        }
        if (hello is null && frameProblem is null) return; // connected and closed without data

        int? clientPid = ClientPid(server);
        CallerClassifier.TokenFacts facts = default;
        try { server.RunAsClient(() => facts = CallerClassifier.ReadFacts()); }
        catch (Exception e) { frameProblem ??= "the client could not be identified: " + e.Message; }
        CallerClassifier.Result cls = CallerClassifier.Decide(PipeSurface.Helper, _cfg, facts);

        string? refusal = null, evt = null;
        if (cls.Class != CallerClass.Helper) { refusal = cls.Detail; evt = "caller_refused"; }
        else if (frameProblem is not null) { refusal = "malformed hello: " + frameProblem; evt = "malformed_frame"; }
        else if (hello!.Header.ContainsKey("op")) { refusal = $"an operation frame ('{hello.Str("op")}') is not served on the helper channel"; evt = "authority_frame_refused"; }
        else if (hello.Type != "hello" || hello.Long("v") != 1) { refusal = $"the first frame must be a version-1 hello, not '{hello.Type}'"; evt = "frame_type_refused"; }
        if (refusal is not null)
        {
            GrantLedger.AuditHelperChannel(evt!, hello?.Type, clientPid);
            _log.LogWarning("refused helper-channel client: {Detail}", refusal);
            try { await HelperFrames.WriteAsync(server, new JsonObject { ["t"] = "refused", ["v"] = 1, ["code"] = ErrorCodes.HelperChannelRefused, ["detail"] = refusal }, ct).ConfigureAwait(false); }
            catch (Exception) { /* the client may already be gone */ }
            return;
        }
        await _broker!.ServeAsync(server, clientPid, ct).ConfigureAwait(false);
    }

    private static int? ClientPid(NamedPipeServerStream server)
        => Native.GetNamedPipeClientProcessId(server.SafePipeHandle, out uint pid) && pid is > 0 and <= int.MaxValue ? (int)pid : null;

    private static async Task Write(NamedPipeServerStream server, Response resp, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(resp.ToJson() + "\n");
        await server.WriteAsync(bytes, ct).ConfigureAwait(false);
        await server.FlushAsync(ct).ConfigureAwait(false);
    }
}
