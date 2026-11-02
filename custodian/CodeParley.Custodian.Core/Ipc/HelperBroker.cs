using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Ipc;

/// <summary>Asks for a helper to attach (production: start the helper service). Throws a <see cref="CustodianRefusal"/>
/// (<c>HELPER_UNAVAILABLE</c>) with an actionable message when it cannot.</summary>
internal interface IHelperStarter
{
    void EnsureRunning();
}

/// <summary>Production: start <c>CodeParleyHelper</c> through the service control manager when it is not running. The
/// helper service's security descriptor grants the custodian's service SID start and query rights (install-helper).</summary>
/// <summary>What one helper job's frames are handed to (capture publication, a derivation result). Each callback may throw
/// to end the job fail-closed; nothing it was given becomes authority unless the caller commits it afterwards.</summary>
internal interface IHelperJobHandler
{
    /// <summary>The largest single frame body this job accepts.</summary>
    long MaxFrameBody { get; }
    void OnFile(HelperFrame file);
    /// <summary>The helper sent every staged file: publish the staging read-only to the helper and return its directory.</summary>
    string OnStageComplete();
    void OnResult(byte[] json);
}

/// <summary>How a helper job ended. <see cref="Ok"/> only when a single correlated result arrived and the child exited 0.</summary>
internal sealed record HelperJobOutcome(bool Ok, string? Code, string? Detail, string Ticket, JsonObject? Exit);

/// <summary>
/// P3.4C-5 (§A.2, §A.3): the custodian side of the helper channel. The custodian is the only authority: the helper is
/// sent one bounded request at a time and returns frames, nothing else.
/// <list type="bullet">
/// <item><b>Correlation (N5-18 on the channel):</b> every request carries a fresh ticket bound to this service instance's
/// random id; every frame back must echo both, else the job ends fail-closed and the event is audited. A restarted
/// service has a new instance id, so a late frame of an orphaned helper is refused.</item>
/// <item><b>Bounds:</b> one outstanding job; an attach deadline; a request deadline; frame caps (HelperFrames); a second
/// result or a second stage-complete is refused.</item>
/// <item><b>No authority on the channel (N5-19):</b> a frame of any other type — an authority operation shape included —
/// is refused and audited, and ends the job.</item>
/// </list>
/// The broker takes no ledger lock: a job runs outside <c>GrantLedger.Gate</c> (contract §2.4).
/// </summary>
internal sealed class HelperBroker
{
    private readonly IHelperStarter _starter;
    private readonly SemaphoreSlim _exclusive = new(1, 1);
    private readonly object _slot = new();
    private Pending? _pending;

    internal HelperBroker(IHelperStarter starter, string? instanceId = null)
    {
        _starter = starter;
        InstanceId = instanceId ?? NewToken();
    }

    /// <summary>This service instance's id (random per start): tickets are bound to it.</summary>
    internal string InstanceId { get; }

    internal TimeSpan AttachTimeout { get; init; } = TimeSpan.FromSeconds(CustodianConstants.HelperAttachSeconds);

    private sealed class Pending(string kind, string ticket, JsonObject parameters, IHelperJobHandler handler, TimeSpan timeout, CancellationToken cancel)
    {
        /// <summary>The caller's cancellation (P3.4C-5: a review's capture the engine abandoned, or its run ended): the
        /// running job's channel is ended, so the helper kills its workload.</summary>
        internal CancellationToken Cancel { get; } = cancel;
        internal string Kind { get; } = kind;
        internal string Ticket { get; } = ticket;
        internal JsonObject Parameters { get; } = parameters;
        internal GuardedHandler Handler { get; } = new(handler);
        internal TimeSpan Timeout { get; } = timeout;
        internal TaskCompletionSource Attached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<HelperJobOutcome> Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Taken;
    }

    /// <summary>Forwards to the job's handler until the job's caller has its outcome; afterwards every callback throws, so a
    /// stalled channel that wakes up late can never publish into a job that already ended.</summary>
    internal sealed class GuardedHandler(IHelperJobHandler inner) : IHelperJobHandler
    {
        private volatile bool _closed;
        internal void Close() => _closed = true;
        private void Open() { if (_closed) throw new HelperFrameError("the job has already ended"); }
        public long MaxFrameBody => inner.MaxFrameBody;
        public void OnFile(HelperFrame file) { Open(); inner.OnFile(file); }
        public string OnStageComplete() { Open(); return inner.OnStageComplete(); }
        public void OnResult(byte[] json) { Open(); inner.OnResult(json); }
    }

    internal static string NewToken() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    /// <summary>Run one job: ask for the helper, hand it the request when it attaches, and wait for the outcome.</summary>
    internal async Task<HelperJobOutcome> RunAsync(string kind, JsonObject parameters, IHelperJobHandler handler, TimeSpan timeout, CancellationToken ct)
    {
        await _exclusive.WaitAsync(ct).ConfigureAwait(false);
        var job = new Pending(kind, NewToken(), parameters, handler, timeout, ct);
        try
        {
            lock (_slot) _pending = job;
            try { _starter.EnsureRunning(); }
            catch (CustodianRefusal r) { return new HelperJobOutcome(false, r.Code, r.Message, job.Ticket, null); }

            Task attached = job.Attached.Task;
            if (await Task.WhenAny(attached, Task.Delay(AttachTimeout, ct)).ConfigureAwait(false) != attached)
            {
                bool withdrawn;
                lock (_slot)
                {
                    withdrawn = Interlocked.Exchange(ref job.Taken, 1) == 0;
                    if (withdrawn) _pending = null;
                }
                // A connection took the job at the deadline: it runs to its own end, and this call reports that end, so
                // no handler callback can happen after this call returned.
                if (!withdrawn) return await Bounded(job).ConfigureAwait(false);
                return new HelperJobOutcome(false, ErrorCodes.HelperUnavailable, $"the helper did not attach within {AttachTimeout.TotalSeconds:0} s", job.Ticket, null);
            }
            return await Bounded(job).ConfigureAwait(false);
        }
        finally
        {
            job.Handler.Close();
            lock (_slot) if (ReferenceEquals(_pending, job)) _pending = null;
            _exclusive.Release();
        }
    }

    /// <summary>The job's outcome, or a timeout once its deadline (plus a grace period for the helper to report the
    /// kill) has passed — a hard bound even if the channel stalls in a way no cancellation reaches.</summary>
    private static async Task<HelperJobOutcome> Bounded(Pending job)
    {
        Task<HelperJobOutcome> done = job.Done.Task;
        if (await Task.WhenAny(done, Task.Delay(job.Timeout + TimeSpan.FromSeconds(30))).ConfigureAwait(false) == done) return await done.ConfigureAwait(false);
        return new HelperJobOutcome(false, ErrorCodes.MeasurementTimeout, $"the helper did not finish within {job.Timeout.TotalSeconds:0} s (hard bound)", job.Ticket, null);
    }

    /// <summary>Serve one AUTHENTICATED helper connection (the caller classified it as the helper and read its hello).
    /// With no job waiting it says goodbye; otherwise it runs that job over the connection.</summary>
    internal async Task ServeAsync(Stream pipe, int? clientPid, CancellationToken ct)
    {
        Pending? job = null;
        DateTime until = DateTime.UtcNow.AddSeconds(5);
        while (job is null && DateTime.UtcNow < until && !ct.IsCancellationRequested)
        {
            lock (_slot)
            {
                if (_pending is { } p && Interlocked.Exchange(ref p.Taken, 1) == 0) { job = p; _pending = null; }
            }
            if (job is null) await Task.Delay(100, ct).ConfigureAwait(false);
        }
        if (job is null)
        {
            await HelperFrames.WriteAsync(pipe, new JsonObject { ["t"] = "bye", ["v"] = 1 }, ct).ConfigureAwait(false);
            return;
        }
        job.Attached.TrySetResult();
        HelperJobOutcome? outcome = null;
        try { outcome = await RunJobAsync(pipe, job, clientPid, ct).ConfigureAwait(false); }
        catch (Exception e) { outcome = new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, "the helper job ended: " + e.Message, job.Ticket, null); }
        finally { job.Done.TrySetResult(outcome ?? new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, "the helper job ended without an outcome", job.Ticket, null)); }
    }

    private async Task<HelperJobOutcome> RunJobAsync(Stream pipe, Pending job, int? clientPid, CancellationToken outer)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outer, job.Cancel);
        cts.CancelAfter(job.Timeout);
        bool staged = false;
        byte[]? result = null;
        JsonObject? exit = null;
        try
        {
            var request = new JsonObject
            {
                ["t"] = "request", ["v"] = 1, ["ticket"] = job.Ticket, ["instance"] = InstanceId, ["kind"] = job.Kind,
                ["timeoutMs"] = (long)job.Timeout.TotalMilliseconds,
            };
            await HelperFrames.WriteAsync(pipe, request, System.Text.Encoding.UTF8.GetBytes(job.Parameters.ToJsonString()), cts.Token).ConfigureAwait(false);
            while (true)
            {
                HelperFrame? f = await HelperFrames.ReadAsync(pipe, Math.Max(job.Handler.MaxFrameBody, 64 * 1024), cts.Token).ConfigureAwait(false);
                if (f is null) throw new HelperFrameError("the helper closed the channel before reporting its exit");
                Correlate(f, job, clientPid);
                switch (f.Type)
                {
                    case "file":
                        if (staged && !LateFileAllowed(f)) throw new HelperFrameError("an export file arrived after the staging was published");
                        job.Handler.OnFile(f);
                        break;
                    case "stage_complete":
                        if (staged) throw new HelperFrameError("a second stage-complete");
                        staged = true;
                        string dir = job.Handler.OnStageComplete();
                        await HelperFrames.WriteAsync(pipe, new JsonObject { ["t"] = "staged", ["v"] = 1, ["ticket"] = job.Ticket, ["instance"] = InstanceId, ["dir"] = dir }, cts.Token).ConfigureAwait(false);
                        break;
                    case "result":
                        if (result is not null) throw new HelperFrameError("a second result for one ticket");
                        result = f.Body;
                        job.Handler.OnResult(f.Body);
                        break;
                    case "failed":
                        return new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, $"the helper reported a failure: {Bounded(f.Str("code"))}: {Bounded(f.Str("detail"))}", job.Ticket, null);
                    case "exit":
                        exit = f.Header;
                        long code = f.Long("exitCode") ?? -1;
                        if (result is null) return new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, $"the helper's workload exited {code} without a result: {Bounded(f.Str("stderr"))}", job.Ticket, exit);
                        if (code != 0) return new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, $"the helper's workload exited {code}", job.Ticket, exit);
                        return new HelperJobOutcome(true, null, null, job.Ticket, exit);
                    default:
                        throw Refuse("frame_type_refused", f, clientPid, $"a '{Bounded(f.Type)}' frame is not served on the helper channel");
                }
            }
        }
        catch (OperationCanceledException) when (job.Cancel.IsCancellationRequested && !outer.IsCancellationRequested)
        {
            return new HelperJobOutcome(false, ErrorCodes.MeasurementCancelled, "the measurement was cancelled; the helper's channel was ended", job.Ticket, exit);
        }
        catch (OperationCanceledException) when (!outer.IsCancellationRequested)
        {
            return new HelperJobOutcome(false, ErrorCodes.MeasurementTimeout, $"the helper did not finish within {job.Timeout.TotalSeconds:0} s", job.Ticket, exit);
        }
        catch (HelperFrameError e)
        {
            return new HelperJobOutcome(false, ErrorCodes.HelperChannelRefused, e.Message, job.Ticket, exit);
        }
        catch (CustodianRefusal r)
        {
            return new HelperJobOutcome(false, r.Code, r.Message, job.Ticket, exit);
        }
        catch (IOException e)
        {
            return new HelperJobOutcome(false, ErrorCodes.HelperChannelRefused, "the helper channel failed: " + e.Message, job.Ticket, exit);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return new HelperJobOutcome(false, ErrorCodes.MeasurementFailed, $"the measurement failed: {e.GetType().Name}: {Bounded(e.Message)}", job.Ticket, exit);
        }
    }

    // After the staging is published only the files the second phase produces may arrive (the prepared diff and the
    // manifest, both under review/).
    private static bool LateFileAllowed(HelperFrame f) => f.Str("area") == "review" && f.Str("path") is "diff.patch" or "manifest.json";

    /// <summary>Every frame after the request must echo this job's ticket and this instance's id (and carry no operation
    /// field: no authority-shaped frame is ever served here).</summary>
    private void Correlate(HelperFrame f, Pending job, int? clientPid)
    {
        if (f.Header.ContainsKey("op")) throw Refuse("authority_frame_refused", f, clientPid, $"an operation frame ('{Bounded(f.Str("op"))}') is not served on the helper channel");
        if (f.Str("instance") != InstanceId) throw Refuse("instance_mismatch", f, clientPid, "a frame for another (earlier) service instance");
        if (f.Str("ticket") != job.Ticket) throw Refuse("ticket_mismatch", f, clientPid, "a frame for a ticket that is not outstanding");
    }

    private static HelperFrameError Refuse(string evt, HelperFrame f, int? clientPid, string message)
    {
        GrantLedger.AuditHelperChannel(evt, f.Type, clientPid);
        return new HelperFrameError(message);
    }

    private static string Bounded(string? s) => s is null ? "" : s.Length > 400 ? s[..400] : s;
}
