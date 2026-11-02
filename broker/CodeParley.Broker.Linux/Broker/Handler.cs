using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Broker;

/// <summary>
/// One request on one connection, started by systemd socket activation (Accept=yes): stdin is the
/// accepted Unix-socket connection. The caller is authenticated by the kernel (SO_PEERCRED) BEFORE
/// any request byte is read; only root and the configured controller uid are served. The request
/// is a single JSON line (64 KiB max, 10 s), the response a single JSON line.
/// </summary>
internal static class Handler
{
    private const int MaxRequestBytes = 64 * 1024;
    private const int IoTimeoutMs = 10_000;

    internal static int Serve()
    {
        Libc.umask(0b000_111_111);
        Directory.SetCurrentDirectory("/");

        Libc.UCred peer;
        try { peer = Libc.PeerCredentials(0); }
        catch (Exception e) { Log.Error("handle: stdin is not a connected Unix socket: " + e.Message); return 2; }

        using var sock = new Socket(new SafeSocketHandle(0, ownsHandle: false));
        sock.ReceiveTimeout = IoTimeoutMs;
        sock.SendTimeout = IoTimeoutMs;

        BrokerSettings settings;
        try { settings = BrokerSettings.Load(); }
        catch (Exception e)
        {
            Log.Error("broker settings unusable: " + e.Message);
            Send(sock, BrokerResponse.Fail(ErrorCodes.HostUnverified, "broker settings unusable: " + e.Message));
            return 1;
        }

        if (peer.Uid != 0 && peer.Uid != settings.ControllerUid)
        {
            Log.Warn($"rejected caller uid={peer.Uid} gid={peer.Gid} pid={peer.Pid}");
            Send(sock, BrokerResponse.Fail(ErrorCodes.Unauthorized, "caller is not the configured controller"));
            return 0;
        }

        BrokerResponse resp;
        string op = "?", runId = "-";
        try { resp = HandleRequest(sock, settings, peer.Uid, ref op, ref runId); }
        catch (Exception e)
        {
            Log.Error($"op={op} runId={runId}: {e}");
            resp = BrokerResponse.Fail(ErrorCodes.Internal, e.Message);
        }
        Log.Info($"op={op} runId={runId} caller uid={peer.Uid} pid={peer.Pid} -> ok={resp.Ok} state={resp.State ?? "-"} error={resp.ErrorCode ?? "-"}");
        Send(sock, resp);
        return 0;
    }

    private static BrokerResponse HandleRequest(Socket sock, BrokerSettings s, uint callerUid, ref string op, ref string runId)
    {
        string? line = ReadLine(sock, out string? readError);
        if (line is null) return BrokerResponse.Fail(ErrorCodes.MalformedRequest, readError ?? "no request");
        BrokerRequest? req;
        try { req = ProtocolJson.Deserialize<BrokerRequest>(line); }
        catch (JsonException e) { return BrokerResponse.Fail(ErrorCodes.MalformedRequest, "invalid request: " + e.Message); }
        if (req is null) return BrokerResponse.Fail(ErrorCodes.MalformedRequest, "empty request");
        op = req.Op?.ToString() ?? "?";
        runId = req.RunId ?? "-";
        return Dispatch(req, s, callerUid);
    }

    private static BrokerResponse Dispatch(BrokerRequest req, BrokerSettings s, uint callerUid)
    {
        if (req.Version != Layout.ProtocolVersion)
            return BrokerResponse.Fail(ErrorCodes.UnsupportedVersion, $"unsupported protocol version {req.Version} (expected {Layout.ProtocolVersion})");
        if (req.Op is null) return BrokerResponse.Fail(ErrorCodes.MalformedRequest, "op is required");

        bool hasRun = req.RunId is not null, hasWorkload = req.WorkloadKey is not null, hasTimeout = req.TimeoutSeconds is not null;
        switch (req.Op.Value)
        {
            case BrokerOp.Ping:
            case BrokerOp.Capabilities:
                if (hasRun || hasWorkload || hasTimeout) return BrokerResponse.Fail(ErrorCodes.MalformedRequest, $"{req.Op} takes no arguments");
                if (req.Op == BrokerOp.Ping) return new BrokerResponse { Ok = true, State = "ready" };
                HostCheck.Report report = HostCheck.Verify(s);
                return new BrokerResponse { Ok = true, Capabilities = report.Facts };
            case BrokerOp.LaunchWorkload:
                return RunOps.Launch(req, s, callerUid);
            case BrokerOp.GetStatus:
            case BrokerOp.Terminate:
            case BrokerOp.Cleanup:
                if (hasWorkload || hasTimeout) return BrokerResponse.Fail(ErrorCodes.MalformedRequest, $"{req.Op} takes only runId");
                if (!RunOps.IsValidRunId(req.RunId)) return BrokerResponse.Fail(ErrorCodes.InvalidRunId, "runId must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$");
                return req.Op switch
                {
                    BrokerOp.GetStatus => RunOps.Status(req.RunId!),
                    BrokerOp.Terminate => RunOps.Terminate(req.RunId!),
                    _ => RunOps.Cleanup(req.RunId!),
                };
            default:
                return BrokerResponse.Fail(ErrorCodes.MalformedRequest, "unknown operation");
        }
    }

    private static string? ReadLine(Socket sock, out string? error)
    {
        error = null;
        var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(IoTimeoutMs);
        while (true)
        {
            int n;
            try { n = sock.Receive(buf); }
            catch (SocketException e) { error = "request not received: " + e.SocketErrorCode; return null; }
            if (n == 0) break;   // EOF ends the request as well
            int nl = Array.IndexOf(buf, (byte)'\n', 0, n);
            ms.Write(buf, 0, nl >= 0 ? nl : n);
            if (ms.Length > MaxRequestBytes) { error = $"request exceeds {MaxRequestBytes} bytes"; return null; }
            if (nl >= 0) break;
            if (DateTime.UtcNow > deadline) { error = "request timed out"; return null; }
        }
        if (ms.Length == 0) { error = "empty request"; return null; }
        try { return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(ms.ToArray()); }
        catch (DecoderFallbackException) { error = "request is not valid UTF-8"; return null; }
    }

    private static void Send(Socket sock, BrokerResponse resp)
    {
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(ProtocolJson.Serialize(resp) + "\n");
            int off = 0;
            while (off < bytes.Length) off += sock.Send(bytes, off, bytes.Length - off, SocketFlags.None);
            sock.Shutdown(SocketShutdown.Send);
        }
        catch (Exception e) { Log.Warn("response not delivered: " + e.Message); }
    }
}

/// <summary>Journal-friendly stderr logging (systemd parses the &lt;N&gt; priority prefix).</summary>
internal static class Log
{
    internal static void Info(string m) => Write(6, m);
    internal static void Warn(string m) => Write(4, m);
    internal static void Error(string m) => Write(3, m);

    private static void Write(int prio, string m)
    {
        try { Console.Error.WriteLine($"<{prio}>{m.Replace('\n', ' ')}"); } catch { /* never fail on logging */ }
    }
}
