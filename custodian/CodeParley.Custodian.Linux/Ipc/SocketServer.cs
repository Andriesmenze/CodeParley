using System.Net.Sockets;
using System.Text;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Linux.Native;
using CodeParley.Custodian.Linux.Security;

namespace CodeParley.Custodian.Linux.Ipc;

/// <summary>
/// Phase 5 (contract §4.4, §4.5): the Linux caller surfaces — two pathname Unix sockets PID 1 created from
/// <c>codeparley-implementer.socket</c> and <c>codeparley-operator.socket</c> and handed to this ONE service
/// (<c>Accept=no</c>). The custodian identifies the inherited descriptors BY NAME (<c>LISTEN_FDNAMES</c>; the order across
/// socket units is undefined, sd_listen_fds(3)) and verifies each one — an AF_UNIX listening stream socket bound to the
/// expected path in the root-owned <c>/run/codeparley</c>, the socket file owned by the custodian, of the surface's group,
/// mode 0660 — refusing to start on anything missing, extra, duplicated or unexpected. A connection is classified from
/// <c>SO_PEERCRED</c> (the uid the kernel recorded at connect) BEFORE any request byte is read: the implementer surface
/// admits exactly the configured implementer uid, the operator surface exactly the configured operator uid (group
/// membership is never sufficient alone). Then the unchanged protocol: one line-delimited JSON request (at most 1 MiB),
/// one response, served sequentially per surface (D5-H).
/// </summary>
internal sealed class SocketServer
{
    internal const string RuntimeDir = "/run/codeparley";
    internal static readonly (string Name, string Path, string Group, CallerClass Class)[] Surfaces =
    [
        ("implementer", RuntimeDir + "/implementer.sock", "codeparley-impl", CallerClass.Implementer),
        ("operator", RuntimeDir + "/operator.sock", "codeparley-op", CallerClass.Operator),
    ];

    private readonly CustodianCore _core;
    private readonly LinuxConfig _cfg;
    private readonly Dictionary<string, Socket> _listeners;
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(60);

    private SocketServer(CustodianCore core, LinuxConfig cfg, Dictionary<string, Socket> listeners)
    {
        _core = core; _cfg = cfg; _listeners = listeners;
    }

    /// <summary>The inherited listeners, identified by name and verified; throws (the service then serves nothing) with the
    /// first problem. Clears <c>LISTEN_PID</c>, <c>LISTEN_FDS</c> and <c>LISTEN_FDNAMES</c> so no child inherits them.</summary>
    internal static Dictionary<string, int> InheritedDescriptors()
    {
        string? pid = Environment.GetEnvironmentVariable("LISTEN_PID"), count = Environment.GetEnvironmentVariable("LISTEN_FDS"), names = Environment.GetEnvironmentVariable("LISTEN_FDNAMES");
        Environment.SetEnvironmentVariable("LISTEN_PID", null);
        Environment.SetEnvironmentVariable("LISTEN_FDS", null);
        Environment.SetEnvironmentVariable("LISTEN_FDNAMES", null);
        if (pid is null || count is null || names is null) throw new InvalidOperationException("no socket descriptors were passed (start the custodian through its socket units)");
        if (!int.TryParse(pid, out int p) || p != Environment.ProcessId) throw new InvalidOperationException($"LISTEN_PID {pid} is not this process");
        if (!int.TryParse(count, out int n) || n != Surfaces.Length) throw new InvalidOperationException($"{count} socket descriptors were passed, expected exactly {Surfaces.Length}");
        string[] fdNames = names.Split(':');
        if (fdNames.Length != n) throw new InvalidOperationException("LISTEN_FDNAMES does not name every descriptor");
        var byName = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < n; i++)
        {
            if (!Surfaces.Any(s => s.Name == fdNames[i])) throw new InvalidOperationException($"an unexpected socket descriptor '{fdNames[i]}' was passed");
            if (!byName.TryAdd(fdNames[i], 3 + i)) throw new InvalidOperationException($"the socket descriptor '{fdNames[i]}' was passed twice");
        }
        foreach (var s in Surfaces)
        {
            if (!byName.TryGetValue(s.Name, out int fd)) throw new InvalidOperationException($"the '{s.Name}' socket descriptor is missing");
            VerifyDescriptor(fd, s.Path, s.Group);
        }
        return byName;
    }

    /// <summary>One inherited descriptor: an AF_UNIX listening stream socket bound to <paramref name="path"/>, whose socket
    /// file is the custodian's, of <paramref name="group"/>, mode 0660, in a root-owned 0755 runtime directory.</summary>
    internal static void VerifyDescriptor(int fd, string path, string group)
    {
        if (Libc.SocketInt(fd, Libc.SO_DOMAIN) != Libc.AF_UNIX) throw new InvalidOperationException($"descriptor {fd} is not an AF_UNIX socket");
        if (Libc.SocketInt(fd, Libc.SO_TYPE) != Libc.SOCK_STREAM) throw new InvalidOperationException($"descriptor {fd} is not a stream socket");
        if (Libc.SocketInt(fd, Libc.SO_ACCEPTCONN) != 1) throw new InvalidOperationException($"descriptor {fd} is not listening");
        string? bound = Libc.SocketPath(fd);
        if (bound != path) throw new InvalidOperationException($"descriptor {fd} is bound to '{bound ?? "?"}', not {path} (abstract and unnamed sockets are refused)");
        uint? gid = Libc.GetGroupByName(group)?.Gid;
        if (gid is null) throw new InvalidOperationException($"the surface group '{group}' does not exist");
        if (Libc.StatxFullAt(Libc.AT_FDCWD, path, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull st) != 0) throw new InvalidOperationException($"{path} cannot be examined");
        if (st.Type != 0xC000) throw new InvalidOperationException($"{path} is not a socket");
        if (st.Uid != Libc.geteuid() || st.Gid != gid || st.Perm != 0x1B0) throw new InvalidOperationException($"{path} must be {LinuxConfig.CustodianAccount}:{group} 0660 (it is uid {st.Uid}, gid {st.Gid}, mode {Convert.ToString(st.Perm, 8)})");
        if (Libc.StatxFullAt(Libc.AT_FDCWD, RuntimeDir, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull d) != 0 || d.Type != Libc.S_IFDIR || d.Uid != 0 || (d.Perm & 0x12 /* 0o022 */) != 0)
            throw new InvalidOperationException($"{RuntimeDir} must be a root-owned directory nobody else can write");
    }

    internal static SocketServer Create(CustodianCore core, LinuxConfig cfg, Dictionary<string, int> descriptors)
    {
        var listeners = new Dictionary<string, Socket>(StringComparer.Ordinal);
        foreach ((string name, int fd) in descriptors) listeners[name] = new Socket(new SafeSocketHandle((IntPtr)fd, ownsHandle: true));
        return new SocketServer(core, cfg, listeners);
    }

    internal Task RunAsync(Action<string> log, CancellationToken ct)
        => Task.WhenAll(Surfaces.Select(s => Listen(s.Name, s.Class, log, ct)));

    private async Task Listen(string name, CallerClass surface, Action<string> log, CancellationToken ct)
    {
        Socket listener = _listeners[name];
        while (!ct.IsCancellationRequested)
        {
            Socket conn;
            try { conn = await listener.AcceptAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { log($"{name}: accept failed: {e.Message}"); await Task.Delay(100, ct).ConfigureAwait(false); continue; }
            using (conn)
            {
                try { await ServeOne(conn, name, surface, log, ct).ConfigureAwait(false); }
                catch (Exception e) when (e is not OperationCanceledException) { log($"{name}: client failed: {e.Message}"); }
            }
        }
    }

    private async Task ServeOne(Socket conn, string name, CallerClass surface, Action<string> log, CancellationToken ct)
    {
        // The kernel's record of the peer at connect, read BEFORE any request byte (contract §4.4).
        Libc.UCred peer = Libc.PeerCredentials((int)conn.Handle);
        long start = LinuxProcessTable.Read(peer.Pid)?.CreateTime ?? 0;
        string proof = Digest.Sha256Hex($"uid={peer.Uid};gid={peer.Gid};pid={peer.Pid};start={start};surface={name}");
        uint expected = surface == CallerClass.Operator ? _cfg.OperatorUid : _cfg.ImplementerUid;
        using var stream = new NetworkStream(conn, ownsSocket: false);
        if (peer.Uid != expected)
        {
            log($"rejected caller on {name}: uid {peer.Uid} (pid {peer.Pid}) is not the configured {name}");
            GrantLedger.AuditRefusal("connect", null, name, peer.Pid, null, null, ErrorCodes.CallerNotAuthorized);
            await Write(stream, Response.Fail(ErrorCodes.CallerNotAuthorized, $"uid {peer.Uid} is not the configured {name} of this custodian"), ct).ConfigureAwait(false);
            return;
        }
        string? line = await ReadLine(stream, ct).ConfigureAwait(false);
        if (line is null) return;
        if (line.Length == 0) return;
        Response resp;
        if (Encoding.UTF8.GetByteCount(line) > CustodianConstants.MaxRequestBytes) resp = Response.Fail(ErrorCodes.MalformedRequest, "request too large");
        else
        {
            try
            {
                Request req = Request.Parse(line);
                resp = _core.Handle(surface, req, proof, peer.Pid > 0 ? peer.Pid : null);
            }
            catch (Exception e) { resp = Response.Fail(ErrorCodes.MalformedRequest, "bad request: " + e.Message); }
        }
        await Write(stream, resp, ct).ConfigureAwait(false);
    }

    /// <summary>One request line, at most <see cref="CustodianConstants.MaxRequestBytes"/> + 1 bytes (a longer line is
    /// reported too large), within <see cref="ReadTimeout"/>; null when the client sent nothing.</summary>
    private static async Task<string?> ReadLine(NetworkStream stream, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ReadTimeout);
        var buf = new MemoryStream();
        var one = new byte[8192];
        while (buf.Length <= CustodianConstants.MaxRequestBytes)
        {
            int got;
            try { got = await stream.ReadAsync(one, timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
            if (got == 0) break;
            int nl = Array.IndexOf(one, (byte)'\n', 0, got);
            buf.Write(one, 0, nl >= 0 ? nl : got);
            if (nl >= 0) return Encoding.UTF8.GetString(buf.GetBuffer(), 0, (int)buf.Length).TrimEnd('\r');
        }
        return buf.Length == 0 ? null : Encoding.UTF8.GetString(buf.GetBuffer(), 0, (int)buf.Length);
    }

    private static async Task Write(NetworkStream stream, Response resp, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(resp.ToJson() + "\n");
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }
}
