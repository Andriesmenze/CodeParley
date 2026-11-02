using System.Net.Sockets;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Linux.Native;

namespace CodeParley.Custodian.Linux.Ipc;

/// <summary>
/// Phase 5 Increment 2 (contract §4.2, §4.4, §4.10, D5-C): the custodian's side of the Linux helper. The direction is the
/// reverse of Windows: the custodian CONNECTS to <c>/run/codeparley-helper/job.sock</c>, and systemd starts one
/// <c>codeparley-helper@.service</c> instance (user <c>codeparley-helper</c>, per-job cgroup limits) for that connection.
/// Before anything is sent the custodian authenticates the server:
/// <list type="number">
/// <item>the endpoint: <c>/run/codeparley-helper</c> a root-owned directory nobody else can write; the socket owned by the
/// helper account, group <c>codeparley</c>, mode 0660 (only root, through the root-owned units, can put one there);</item>
/// <item>the process: the kernel's <c>SCM_CREDENTIALS</c> of the helper's first message must name the helper account,
/// and that process must run in a <c>codeparley-helper@</c> unit's cgroup. (<c>SO_PEERCRED</c> of the connecting side names
/// PID 1, the listener's creator, so it cannot authenticate the helper here.)</item>
/// </list>
/// The first frame must be a version-1 hello; then the channel is served by the core's <see cref="HelperBroker"/> (one job).
/// The helper authenticates the custodian with <c>SO_PEERCRED</c> on its accepted socket.
/// </summary>
internal sealed class LinuxHelperStarter(LinuxConfig cfg, Action<string> log) : IHelperStarter
{
    internal const string RuntimeDir = "/run/codeparley-helper";
    internal const string SocketPath = RuntimeDir + "/job.sock";

    internal HelperBroker? Broker { get; set; }

    public void EnsureRunning()
    {
        HelperBroker broker = Broker ?? throw new InvalidOperationException("the helper starter has no broker");
        if (cfg.HelperUid is not { } helperUid)
            throw new CustodianRefusal(ErrorCodes.HelperUnavailable, $"the helper account '{cfg.HelperName}' does not exist; the operator provisions it (contract §4.2)");
        if (EndpointProblem(helperUid) is { } problem)
            throw new CustodianRefusal(ErrorCodes.HelperUnavailable, $"the helper endpoint {SocketPath} is not available or not trusted: {problem}");
        int fd;
        try { fd = Libc.ConnectWithPassCred(SocketPath, receiveTimeoutMs: 15_000); }
        catch (IOException e) { throw new CustodianRefusal(ErrorCodes.HelperUnavailable, "the helper could not be reached: " + e.Message); }
        Socket? socket = null;
        try
        {
            Libc.UCred? sender = Libc.PeekSenderCredentials(fd);
            if (sender is not { } who) throw Refused("no_credentials", null, "the helper closed the channel without a hello");
            if (who.Uid != helperUid) throw Refused("caller_refused", who.Pid, $"the process that answered is uid {who.Uid}, not the helper account '{cfg.HelperName}'");
            if (!InHelperUnit(who.Pid)) throw Refused("caller_refused", who.Pid, $"the process that answered ({who.Pid}) does not run in a codeparley-helper@ unit");
            socket = new Socket(new SafeSocketHandle((IntPtr)fd, ownsHandle: true));
            fd = -1;
            var stream = new NetworkStream(socket, ownsSocket: true);
            int pid = who.Pid;
            _ = Task.Run(async () =>
            {
                using (stream)
                {
                    try
                    {
                        HelperFrame? hello;
                        using (var helloTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                            hello = await HelperFrames.ReadAsync(stream, 4096, helloTimeout.Token).ConfigureAwait(false);
                        string? refusal = hello is null ? "the helper closed the channel"
                            : hello.Header.ContainsKey("op") ? $"an operation frame ('{hello.Str("op")}') is not served on the helper channel"
                            : hello.Type != "hello" || hello.Long("v") != 1 ? $"the first frame must be a version-1 hello, not '{hello.Type}'" : null;
                        if (refusal is not null)
                        {
                            GrantLedger.AuditHelperChannel(hello is null ? "malformed_frame" : "frame_type_refused", hello?.Type, pid);
                            log($"refused the helper channel: {refusal}");
                            return;
                        }
                        await broker.ServeAsync(stream, pid, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception e) { log($"the helper channel failed: {e.Message}"); }
                }
            });
        }
        catch (CustodianRefusal) { throw; }
        catch (Exception e) { throw new CustodianRefusal(ErrorCodes.HelperUnavailable, "the helper channel failed: " + e.Message); }
        finally
        {
            if (fd >= 0) Libc.close(fd);
        }
    }

    private CustodianRefusal Refused(string evt, int? pid, string detail)
    {
        GrantLedger.AuditHelperChannel(evt, "hello", pid);
        log("refused the helper channel: " + detail);
        return new CustodianRefusal(ErrorCodes.HelperChannelRefused, detail);
    }

    /// <summary>Why the helper endpoint may not be trusted (null: it may).</summary>
    internal static string? EndpointProblem(uint helperUid)
    {
        if (Libc.StatxFullAt(Libc.AT_FDCWD, RuntimeDir, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull d) != 0) return $"{RuntimeDir} does not exist";
        if (d.Type != Libc.S_IFDIR || d.Uid != 0 || (d.Perm & 0x12 /* 0o022 */) != 0) return $"{RuntimeDir} is not a root-owned directory nobody else can write";
        if (Libc.StatxFullAt(Libc.AT_FDCWD, SocketPath, Libc.AT_SYMLINK_NOFOLLOW, out Libc.StatxFull s) != 0) return "the helper socket does not exist (is codeparley-helper.socket installed and started?)";
        uint? group = Libc.GetGroupByName(LinuxConfig.CustodianAccount)?.Gid;
        if (s.Type != 0xC000 || s.Uid != helperUid || s.Gid != group || s.Perm != 0x1B0 /* 0660 */)
            return $"the helper socket must be a socket of the helper account, group {LinuxConfig.CustodianAccount}, mode 0660 (it is uid {s.Uid}, gid {s.Gid}, mode {Convert.ToString(s.Perm, 8)})";
        return null;
    }

    /// <summary>Does <paramref name="pid"/> run in a <c>codeparley-helper@…service</c> unit (its cgroup v2 path)?</summary>
    internal static bool InHelperUnit(int pid)
    {
        try
        {
            foreach (string line in File.ReadAllLines($"/proc/{pid}/cgroup"))
                if (line.StartsWith("0::", StringComparison.Ordinal) && line.Contains("/codeparley-helper@", StringComparison.Ordinal) && line.EndsWith(".service", StringComparison.Ordinal))
                    return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return false;
    }
}
