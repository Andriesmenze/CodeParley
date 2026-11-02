using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CodeParley.Broker.Ipc;

/// <summary>
/// Authenticated local named-pipe IPC. Caller authorization (hardening 4A): the pipe ACL admits only
/// SYSTEM and the single trusted controller SID from the broker config, and the server additionally
/// impersonates the connected client and requires its SID to be EXACTLY that controller SID — never
/// "any administrator". One line-delimited JSON request per connection, one JSON response; requests are
/// serviced sequentially.
/// </summary>
internal sealed class PipeServer(BrokerCore core, ILogger logger, SecurityIdentifier controllerSid)
{
    internal async Task RunAsync(CancellationToken ct)
    {
        logger.LogInformation("pipe server listening on \\\\.\\pipe\\{Pipe} (controller SID {Sid})", BrokerConstants.PipeName, controllerSid.Value);
        while (!ct.IsCancellationRequested)
        {
            using NamedPipeServerStream server = CreateSecuredPipe();
            try { await server.WaitForConnectionAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            try { await ServeOneAsync(server, ct).ConfigureAwait(false); }
            catch (Exception e) { logger.LogWarning(e, "pipe client handling failed"); }
            finally { try { if (server.IsConnected) server.Disconnect(); } catch { } }
        }
    }

    /// <summary>A pipe whose DACL grants FullControl to SYSTEM and ReadWrite to only the trusted
    /// controller SID; no Everyone/Users ACE. Defense in depth alongside the impersonated-SID check.</summary>
    private NamedPipeServerStream CreateSecuredPipe()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(controllerSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            BrokerConstants.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    private async Task ServeOneAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        using var reader = new StreamReader(server, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        // Read the request first: client data must have flowed before impersonation for reliable
        // named-pipe client authentication. Then authorize.
        string? line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return;

        if (!TryAuthorize(server, out string callerSid))
        {
            logger.LogWarning("rejected unauthorized caller {Sid}", callerSid);
            await WriteAsync(server, BrokerResponse.Fail(ErrorCodes.Unauthorized, "caller is not the configured controller"), ct).ConfigureAwait(false);
            return;
        }

        BrokerResponse resp;
        try
        {
            BrokerRequest? req = ProtocolJson.Deserialize<BrokerRequest>(line);
            resp = req is null ? BrokerResponse.Fail(ErrorCodes.MalformedRequest, "malformed request") : core.Handle(req);
        }
        catch (Exception e) { resp = BrokerResponse.Fail(ErrorCodes.MalformedRequest, "bad request: " + e.Message); }

        await WriteAsync(server, resp, ct).ConfigureAwait(false);
    }

    /// <summary>Authorize by impersonating the client and requiring its SID to equal exactly the trusted
    /// controller SID (not membership in any group).</summary>
    private bool TryAuthorize(NamedPipeServerStream server, out string callerSid)
    {
        string sid = "unknown";
        bool ok = false;
        server.RunAsClient(() =>
        {
            using WindowsIdentity id = WindowsIdentity.GetCurrent();
            sid = id.User?.Value ?? "unknown";
            ok = id.User is not null && id.User.Equals(controllerSid);
        });
        callerSid = sid;
        return ok;
    }

    private static async Task WriteAsync(NamedPipeServerStream server, BrokerResponse resp, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(ProtocolJson.Serialize(resp) + "\n");
        await server.WriteAsync(bytes, ct).ConfigureAwait(false);
        await server.FlushAsync(ct).ConfigureAwait(false);
    }
}
