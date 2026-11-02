using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// NON-PRIVILEGED self-test of the P3.4C-2 loop lifecycle (increment 6), run by <c>self-test-ledger</c> against
/// its scratch store, plus the pipe cases run by <c>self-test-ipc</c>. It proves the contract's §4 negative
/// invariants on the custodian itself: no implementer sequence clears an operator-only pause (rebind keeps it
/// paused; an implementer resume is CALLER_NOT_AUTHORIZED; a second pause cannot replace the reason), first
/// bind wins, a terminal loop refuses everything, stale epochs/revisions are refused, a wake claim authorizes
/// at most one dispatch (TD correction B) - and the custodian's own process check (D7). The process table is a
/// fixed one, so every branch is deterministic; one case reads the real OS table.
/// </summary>
internal static class LoopSelfTest
{
    // A fixed process table: 100 the originating Claude process; 200 its hook; 300 the hook's pipe helper (the
    // connected client); 400 an unrelated process; 500 a "child" of 100 created BEFORE it (100 is a reused id).
    private const long Second = 10_000_000;
    private static readonly long T0 = DateTime.UtcNow.AddMinutes(-10).ToFileTimeUtc();
    internal const int Claude = 100, Helper = 300, Unrelated = 400, ReusedChild = 500;

    private sealed class FixedTable(Dictionary<int, ProcEntry>? entries) : IProcessTable
    {
        public IReadOnlyDictionary<int, ProcEntry>? Snapshot() => entries;
    }

    /// <summary>The fixed process table (also the loop corpus's): <see cref="Claude"/> is an ancestor of
    /// <see cref="Helper"/>, the connected client; <see cref="Unrelated"/> is not.</summary>
    internal static readonly IProcessTable Table = new FixedTable(new Dictionary<int, ProcEntry>
    {
        [Claude] = new(Claude, 1, T0),
        [200] = new(200, Claude, T0 + 10 * Second),
        [Helper] = new(Helper, 200, T0 + 11 * Second),
        [Unrelated] = new(Unrelated, 1, T0 + 5 * Second),
        [ReusedChild] = new(ReusedChild, Claude, T0 - 60 * Second),
    });

    /// <summary><see cref="Table"/> after the Claude process ended: the helper's chain no longer reaches it.</summary>
    internal static readonly IProcessTable WithoutClaude = new FixedTable(new Dictionary<int, ProcEntry>
    {
        [200] = new(200, Claude, T0 + 10 * Second),
        [Helper] = new(Helper, 200, T0 + 11 * Second),
        [Unrelated] = new(Unrelated, 1, T0 + 5 * Second),
    });

    /// <summary><see cref="Table"/> with pid <see cref="Claude"/> reused by a process created 2 s later: by its parent
    /// links still an ancestor of the helper, but not the process instance the loop was bound to.</summary>
    internal static readonly IProcessTable ClaudeReused = new FixedTable(new Dictionary<int, ProcEntry>
    {
        [Claude] = new(Claude, 1, T0 + 2 * Second),
        [200] = new(200, Claude, T0 + 10 * Second),
        [Helper] = new(Helper, 200, T0 + 11 * Second),
        [Unrelated] = new(Unrelated, 1, T0 + 5 * Second),
    });

    internal static readonly LoopCaller Impl = new(false, "proof-implementer", Helper);
    /// <summary>The implementer surface reached by a process OUTSIDE the bound Claude process's tree.</summary>
    internal static readonly LoopCaller Outsider = new(false, "proof-implementer", Unrelated);
    internal static readonly LoopCaller Oper = new(true, "proof-operator", null);

    private static readonly JsonSerializerOptions LedgerJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, WriteIndented = true,
    };

    private sealed record Fx(GrantLedger Led, string Repo, string Run, string LoopId, string Nonce, string MintRequestId);

    private static int _seq;

    internal static int Run(string repos)
    {
        int failed = 0;
        failed += ProcessCheckCases();
        failed += BindRefusalCases(repos);
        failed += BindCases(repos);
        failed += SpendCases(repos);
        Fx wake = Bound(repos, "Wake");
        failed += WakeCases(wake);
        failed += WakeAcrossOperationsCases(wake);
        failed += WakeEpochAndOperationCases(repos);
        foreach (string reason in PauseReasons.OperatorOnly.Order(StringComparer.Ordinal))
        {
            Fx paused = Bound(repos, "Protected" + reason.Replace("_", ""));
            failed += ProtectedPauseCases(paused, reason);
            failed += ProtectedPauseChainCases(paused, reason);
        }
        failed += BoundCallerCases(repos);
        failed += BudgetEndNeedsBoundCallerCases(repos);
        failed += RebindAndResumeCases(repos);
        failed += TerminalCases(repos);
        failed += ValidationCases(repos);
        failed += ProjectionCases(repos);
        failed += ConcurrencyAndRestartCases(repos);
        return failed;
    }

    // ---- D7: the custodian's own process check ----

    private static int ProcessCheckCases()
    {
        int f = 0;
        ProcessCheckResult ok = ProcessIdentityCheck.Verify(Claude, Helper, Table);
        long expectedMs = new DateTimeOffset(DateTime.FromFileTimeUtc(T0)).ToUnixTimeMilliseconds();
        f += Check("process check: CLAUDE_PID that is an ancestor of the connected process is verified, OS start time recorded", ok.Verified && ok.StartedAtMs == expectedMs && ok.ClientPid == Helper);
        f += Check("process check: an unrelated process is not verified", !ProcessIdentityCheck.Verify(Unrelated, Helper, Table).Verified);
        f += Check("process check: a missing CLAUDE_PID is not verified", !ProcessIdentityCheck.Verify(null, Helper, Table).Verified);
        f += Check("process check: a pid that is not running is not verified", !ProcessIdentityCheck.Verify(999, Helper, Table).Verified);
        f += Check("process check: an unidentified connected process is not verified", !ProcessIdentityCheck.Verify(Claude, null, Table).Verified);
        f += Check("process check: a parent created after its child (a reused id) is not an ancestor", !ProcessIdentityCheck.Verify(Claude, ReusedChild, Table).Verified);
        f += Check("process check: a process is not its own ancestor", !ProcessIdentityCheck.Verify(Helper, Helper, Table).Verified);
        f += Check("process check: an unreadable process table fails closed", !ProcessIdentityCheck.Verify(Claude, Helper, new FixedTable(null)).Verified);

        IReadOnlyDictionary<int, ProcEntry>? os = new OsProcessTable().Snapshot();
        f += Check("process check: the OS process table is readable and lists this process", os is not null && os.ContainsKey(Environment.ProcessId));
        if (os is not null && os.TryGetValue(Environment.ProcessId, out ProcEntry? self) && os.ContainsKey(self.ParentPid))
            f += Check("process check (OS): this process's parent is a verified ancestor of this process", ProcessIdentityCheck.Verify(self.ParentPid, Environment.ProcessId, new OsProcessTable()).Verified);
        else Console.WriteLine("[skip] process check (OS): this process's parent is no longer running");
        return f;
    }

    // ---- bind: first bind wins, one-time nonce, custodian-verified identity, handle #1 ----

    private static int BindRefusalCases(string repos)
    {
        int f = 0;
        Fx fx = NewLoop(repos, "BindRefused");
        f += Check("bind: a wrong nonce is refused (BIND_NONCE_INVALID); the loop stays unbound, the nonce unused",
            Refused(() => Do(fx, Impl, LoopKinds.Bind, BindFields(fx with { Nonce = new string('0', 64) })), ErrorCodes.BindNonceInvalid)
            && Loop(fx).Status == LoopStatuses.Unbound && Loop(fx).BindNonce.UsedAt is null);
        f += Check("bind: a client-asserted 'verified' is refused, not ignored (MALFORMED_REQUEST)",
            Refused(() => Do(fx, Impl, LoopKinds.Bind, new JsonObject { ["bindNonce"] = fx.Nonce, ["session_id"] = "session-1", ["process"] = new JsonObject { ["pid"] = Claude, ["verified"] = true } }), ErrorCodes.MalformedRequest));

        Fx expired = NewLoop(repos, "BindExpired");
        EditLoop(expired, x => x with { BindNonce = x.BindNonce with { ExpiresAt = DateTime.UtcNow.AddSeconds(-1).ToString("o") } });
        f += Check("bind: an expired nonce is refused (BIND_NONCE_INVALID)",
            Refused(() => Do(expired, Impl, LoopKinds.Bind, BindFields(expired)), ErrorCodes.BindNonceInvalid) && Loop(expired).Status == LoopStatuses.Unbound);

        Fx unverified = NewLoop(repos, "BindUnverified");
        JsonObject ub = Do(unverified, Impl, LoopKinds.Bind, BindFields(unverified, pid: Unrelated));
        f += Check("bind: an identity the custodian cannot verify binds (first bind wins) with verified=false",
            (string?)ub["status"] == LoopStatuses.Active && !(bool)ub["binding"]!["verified"]!);
        f += Check("bind: an unverified binding automates nothing (spend and wake_arm: PROCESS_IDENTITY_UNVERIFIED)",
            Refused(() => Do(unverified, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.ProcessIdentityUnverified)
            && Refused(() => Do(unverified, Impl, LoopKinds.WakeArm, CurrentHandle(unverified)), ErrorCodes.ProcessIdentityUnverified));
        return f;
    }

    private static int BindCases(string repos)
    {
        int f = 0;
        Fx fx = NewLoop(repos, "Bind");
        string rid = Rid("bind");
        JsonObject b = Do(fx, Impl, LoopKinds.Bind, BindFields(fx), rid);
        LoopRecord l = Loop(fx);
        f += Check("bind: unbound -> active, epoch 1, revision 2, operation handle #1 issued at bind (correction A)",
            (string?)b["status"] == LoopStatuses.Active && (int)b["epoch"]! == 1 && (int)b["loopRevision"]! == 2
            && l.Operations!.Count == 1 && (string?)b["operationHandle"] == l.Operations[0].Handle);
        f += Check("bind: the CUSTODIAN verified the process against the connected client and marked the nonce used",
            (bool)b["binding"]!["verified"]! && l.Binding!.Process.Verified && l.Binding.Process.ClientPid == Helper && l.BindNonce.UsedAt is not null);
        JsonObject replay = Do(fx, Impl, LoopKinds.Bind, BindFields(fx), rid, 1, 1);
        f += Check("bind: an idempotent replay returns the same result and changes nothing",
            (string?)replay["operationHandle"] == (string?)b["operationHandle"] && Loop(fx).LoopRevision == 2);
        f += Check("bind: the same request id with different fields is a conflict (REQUEST_ID_CONFLICT)",
            Refused(() => Do(fx, Impl, LoopKinds.Bind, BindFields(fx, "session-other"), rid, 1, 1), ErrorCodes.RequestIdConflict));
        f += Check("bind: a second bind - even with the nonce - is refused; the first binding stands",
            Refused(() => Do(fx, Impl, LoopKinds.Bind, BindFields(fx, "session-2")), ErrorCodes.InvalidLoopTransition) && Loop(fx).Binding!.SessionId == "session-1");
        Do(fx, Impl, LoopKinds.Pause, Reason(PauseReasons.UserInterrupt));
        f += Check("bind: refused on a paused loop (first bind wins)",
            Refused(() => Do(fx, Impl, LoopKinds.Bind, BindFields(fx)), ErrorCodes.InvalidLoopTransition) && Loop(fx).Status == LoopStatuses.Paused);
        return f;
    }

    // ---- spend_continuation: reduce-only, new handle each, custodian-derived budget end; stale refusals ----

    private static int SpendCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "Spend");
        LoopRecord l0 = Loop(fx);
        f += Check("stale base revision refused (STALE_LOOP_STATE); nothing spent",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend(), rev: l0.LoopRevision - 1), ErrorCodes.StaleLoopState) && Loop(fx).Used.Continuations == 0);
        f += Check("stale epoch refused (STALE_LOOP_EPOCH); nothing spent",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend(), epoch: l0.Epoch + 1), ErrorCodes.StaleLoopEpoch) && Loop(fx).Used.Continuations == 0);
        string rid = Rid("spend");
        JsonObject s1 = Do(fx, Impl, LoopKinds.SpendContinuation, Spend(), rid);
        f += Check("spend 1: reduce-only (1 of 2) and a NEW operation handle",
            (int)s1["continuationsUsed"]! == 1 && (string?)s1["operationHandle"] != l0.CurrentOperation!.Handle && Loop(fx).Operations!.Count == 2);
        JsonObject s1b = Do(fx, Impl, LoopKinds.SpendContinuation, Spend(), rid, l0.Epoch, l0.LoopRevision);
        f += Check("spend 1 replay: the same handle; nothing spent again",
            (string?)s1b["operationHandle"] == (string?)s1["operationHandle"] && Loop(fx).Used.Continuations == 1);
        Do(fx, Impl, LoopKinds.SpendContinuation, Spend());
        f += Check("spend 2 (2 of 2)", Loop(fx).Used.Continuations == 2);
        int before = Loop(fx).LoopRevision;
        f += Check("spend 3: past the budget -> LOOP_BUDGET_EXHAUSTED and the loop ENDS (budget_exhausted, custodian-derived)",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.LoopBudgetExhausted)
            && Loop(fx).Status == LoopStatuses.BudgetExhausted && Loop(fx).Ended!.By == "custodian" && Loop(fx).LoopRevision == before + 1);
        f += Check("an exhausted loop refuses every transition (LOOP_TERMINAL)", AllTerminal(fx));
        return f;
    }

    // ---- wake_arm / wake_consume: current handle only, both budgets, one-shot authorization ----

    private static int WakeCases(Fx fx)
    {
        int f = 0;
        f += Check("wake_arm: an invented handle is refused (UNKNOWN_OPERATION_HANDLE)",
            Refused(() => Do(fx, Impl, LoopKinds.WakeArm, Handle("op-1-000000000000")), ErrorCodes.UnknownOperationHandle));
        JsonObject arm = Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx));
        string claim = (string)arm["claimId"]!;
        LoopRecord la = Loop(fx);
        f += Check("wake_arm: a claim on the current operation; per-operation AND per-run budgets spent and persisted",
            (int)arm["wakesUsedOperation"]! == 1 && (int)arm["wakesUsedRun"]! == 1 && la.Used.Wakes == 1 && la.CurrentOperation!.WakesUsed == 1 && la.WakeClaims!.Single().State == "armed");
        f += Check("wake_arm: a second arm on the same operation is refused (per-operation budget)",
            Refused(() => Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx)), ErrorCodes.LoopBudgetExhausted));

        string rid = Rid("consume");
        JsonObject c1 = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim), rid);
        f += Check("wake_consume: the consuming call authorizes one dispatch; consumption persisted",
            Authorized(c1) && Loop(fx).WakeClaims!.Single().State == "consumed");
        JsonObject c2 = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim), rid, la.Epoch, la.LoopRevision);
        f += Check("wake_consume: a same-request replay NEVER authorizes again (correction B)", !Authorized(c2) && (bool)c2["replayed"]!);
        JsonObject c3 = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim));
        f += Check("wake_consume: a different request on the consumed claim never authorizes (WAKE_ALREADY_CONSUMED)",
            !Authorized(c3) && (string?)c3["refusal"] == ErrorCodes.WakeAlreadyConsumed && (bool)c3["consumed"]!);
        JsonObject c4 = Do(fx, Impl, LoopKinds.WakeConsume, Claim("wc-9-000000000000"));
        f += Check("wake_consume: an invented claim never authorizes (ok response, dispatchAuthorized:false)",
            !Authorized(c4) && (string?)c4["refusal"] == ErrorCodes.UnknownWakeClaim);
        JsonObject c5 = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim), epoch: la.Epoch + 5);
        f += Check("wake_consume: a stale epoch never authorizes", !Authorized(c5) && (string?)c5["refusal"] == ErrorCodes.StaleLoopEpoch);
        return f;
    }

    /// <summary>Continues <see cref="WakeCases"/>' loop (its first operation's wake is spent): operation 2
    /// arms the run's second wake; operation 3 has none left.</summary>
    private static int WakeAcrossOperationsCases(Fx fx)
    {
        int f = 0;
        string op1 = Loop(fx).CurrentOperation!.Handle;
        Do(fx, Impl, LoopKinds.SpendContinuation, Spend());
        f += Check("wake_arm: an earlier operation's handle is refused after a continuation (UNKNOWN_OPERATION_HANDLE)",
            Refused(() => Do(fx, Impl, LoopKinds.WakeArm, Handle(op1)), ErrorCodes.UnknownOperationHandle));
        string claim2 = (string)Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx))["claimId"]!;
        Do(fx, Impl, LoopKinds.SpendContinuation, Spend());
        JsonObject stale = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim2));
        f += Check("wake_consume: a claim of an earlier operation never authorizes", !Authorized(stale) && (string?)stale["refusal"] == ErrorCodes.UnknownOperationHandle);
        f += Check("wake_arm: the per-run wake budget (2) is enforced across operations",
            Refused(() => Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx)), ErrorCodes.LoopBudgetExhausted) && Loop(fx).Used.Wakes == 2);
        return f;
    }

    private static int WakeEpochAndOperationCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "WakeEpoch");
        string claim = (string)Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx))["claimId"]!;
        Do(fx, Impl, LoopKinds.Rebind, RebindFields());
        JsonObject c = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim));
        f += Check("wake: a claim armed before a rebind is stale (epoch-bound) and never authorizes",
            !Authorized(c) && (string?)c["refusal"] == ErrorCodes.StaleLoopEpoch && Loop(fx).Epoch == 2);
        f += Check("wake: a rebind does not reset the operation's wake counter",
            Refused(() => Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx)), ErrorCodes.LoopBudgetExhausted));

        Fx paused = Bound(repos, "WakePaused");
        string pc = (string)Do(paused, Impl, LoopKinds.WakeArm, CurrentHandle(paused))["claimId"]!;
        Do(paused, Impl, LoopKinds.Pause, Reason(PauseReasons.UserInterrupt));
        JsonObject pr = Do(paused, Impl, LoopKinds.WakeConsume, Claim(pc));
        f += Check("wake: a claim on a paused loop never authorizes", !Authorized(pr) && (string?)pr["refusal"] == ErrorCodes.InvalidLoopTransition);
        return f;
    }

    // ---- TD decision on the Inc 9 escalation: automation requests come from the bound session and its process ----

    private static int BoundCallerCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "BoundCaller");
        f += Check("spend: a request naming another session is refused (SESSION_NOT_BOUND); nothing spent",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend("session-other")), ErrorCodes.SessionNotBound) && Loop(fx).Used.Continuations == 0);
        f += Check("spend: the bound session id from outside the bound Claude process's tree is refused (PROCESS_IDENTITY_UNVERIFIED)",
            Refused(() => Do(fx, Outsider, LoopKinds.SpendContinuation, Spend()), ErrorCodes.ProcessIdentityUnverified) && Loop(fx).Used.Continuations == 0);
        f += Check("wake_arm: another session, or the bound session id from outside the tree, reserves nothing",
            Refused(() => Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx, "session-other")), ErrorCodes.SessionNotBound)
            && Refused(() => Do(fx, Outsider, LoopKinds.WakeArm, CurrentHandle(fx)), ErrorCodes.ProcessIdentityUnverified)
            && Loop(fx).Used.Wakes == 0 && Loop(fx).WakeClaims!.Count == 0);
        string claim = (string)Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx))["claimId"]!;
        JsonObject other = Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim, "session-other"));
        JsonObject spoofed = Do(fx, Outsider, LoopKinds.WakeConsume, Claim(claim));
        f += Check("wake_consume: another session, or the bound session id from outside the tree, authorizes nothing; the claim stays armed",
            !Authorized(other) && (string?)other["refusal"] == ErrorCodes.SessionNotBound
            && !Authorized(spoofed) && (string?)spoofed["refusal"] == ErrorCodes.ProcessIdentityUnverified
            && Loop(fx).WakeClaims!.Single().State == "armed");
        f += Check("wake_consume: the bound session's own process then consumes it", Authorized(Do(fx, Impl, LoopKinds.WakeConsume, Claim(claim))));
        f += Check("a spend, wake_arm or wake_consume without a session id is refused (INVALID_ARGUMENT)",
            Invalid(() => Do(fx, Impl, LoopKinds.SpendContinuation, []))
            && Invalid(() => Do(fx, Impl, LoopKinds.WakeArm, new JsonObject { ["operationHandle"] = Loop(fx).CurrentOperation!.Handle }))
            && Invalid(() => Do(fx, Impl, LoopKinds.WakeConsume, new JsonObject { ["claimId"] = claim })));
        f += Check("spend: the bound Claude process ended -> PROCESS_IDENTITY_UNVERIFIED",
            Refused(() => Do(fx with { Led = new GrantLedger("cust-selftest", WithoutClaude) }, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.ProcessIdentityUnverified));
        f += Check("spend: the bound pid now names a later-created process (a reused id) -> PROCESS_IDENTITY_UNVERIFIED",
            Refused(() => Do(fx with { Led = new GrantLedger("cust-selftest", ClaudeReused) }, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.ProcessIdentityUnverified)
            && Loop(fx).Used.Continuations == 0);
        f += Check("spend: the bound session's own process spends", (int)Do(fx, Impl, LoopKinds.SpendContinuation, Spend())["continuationsUsed"]! == 1);
        return f;
    }

    /// <summary>A spend past the budget ends the loop, but only once it passed the binding checks: another
    /// session or a process outside the tree cannot end a loop that way.</summary>
    private static int BudgetEndNeedsBoundCallerCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "BudgetEndBound");
        Do(fx, Impl, LoopKinds.SpendContinuation, Spend());
        Do(fx, Impl, LoopKinds.SpendContinuation, Spend());
        int rev = Loop(fx).LoopRevision;
        f += Check("past the budget: another session's or an outside process's spend is refused WITHOUT ending the loop",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend("session-other")), ErrorCodes.SessionNotBound)
            && Refused(() => Do(fx, Outsider, LoopKinds.SpendContinuation, Spend()), ErrorCodes.ProcessIdentityUnverified)
            && Loop(fx).Status == LoopStatuses.Active && Loop(fx).LoopRevision == rev);
        f += Check("past the budget: the bound session's spend ends it (budget_exhausted)",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.LoopBudgetExhausted) && Loop(fx).Status == LoopStatuses.BudgetExhausted);
        return f;
    }

    // ---- TD correction 2: no implementer sequence clears an operator-only pause ----

    private static int ProtectedPauseCases(Fx fx, string reason)
    {
        int f = 0;
        Do(fx, Impl, LoopKinds.Pause, Reason(reason));
        f += Check($"[{reason}] an implementer resume -> CALLER_NOT_AUTHORIZED; still paused",
            Refused(() => Do(fx, Impl, LoopKinds.Resume, []), ErrorCodes.CallerNotAuthorized) && Paused(fx, reason));
        int e0 = Loop(fx).Epoch;
        JsonObject rb = Do(fx, Impl, LoopKinds.Rebind, RebindFields());
        f += Check($"[{reason}] rebind keeps the loop PAUSED (only the binding and the epoch change)",
            (string?)rb["status"] == LoopStatuses.Paused && (string?)rb["pauseReason"] == reason && Loop(fx).Epoch == e0 + 1 && Paused(fx, reason));
        f += Check($"[{reason}] a second pause cannot replace (downgrade) the reason",
            Refused(() => Do(fx, Impl, LoopKinds.Pause, Reason(PauseReasons.UserInterrupt)), ErrorCodes.InvalidLoopTransition) && Paused(fx, reason));
        f += Check($"[{reason}] bind is refused", Refused(() => Do(fx, Impl, LoopKinds.Bind, BindFields(fx)), ErrorCodes.InvalidLoopTransition) && Paused(fx, reason));
        return f;
    }

    /// <summary>Continues <see cref="ProtectedPauseCases"/>' paused loop: no further implementer step clears
    /// the pause; the operator's resume does.</summary>
    private static int ProtectedPauseChainCases(Fx fx, string reason)
    {
        int f = 0;
        f += Check($"[{reason}] continuations and wakes are refused while paused",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.InvalidLoopTransition)
            && Refused(() => Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx)), ErrorCodes.InvalidLoopTransition) && Paused(fx, reason));
        int e1 = Loop(fx).Epoch;
        Do(fx, Impl, LoopKinds.Rebind, RebindFields());
        f += Check($"[{reason}] pause -> rebind -> rebind -> implementer resume never reaches active",
            Refused(() => Do(fx, Impl, LoopKinds.Resume, []), ErrorCodes.CallerNotAuthorized) && Paused(fx, reason) && Loop(fx).Epoch == e1 + 1);
        JsonObject resumed = Do(fx, Oper, LoopKinds.Resume, []);
        f += Check($"[{reason}] only the OPERATOR caller class resumes it",
            (string?)resumed["status"] == LoopStatuses.Active && Loop(fx).Pause is null && Loop(fx).ResumedAt is not null);
        return f;
    }

    private static int RebindAndResumeCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "Rebind");
        Do(fx, Impl, LoopKinds.Pause, Reason(PauseReasons.UserInterrupt));
        f += Check("[user_interrupt] the implementer may resume (not an operator-only pause)", (string?)Do(fx, Impl, LoopKinds.Resume, [])["status"] == LoopStatuses.Active);
        f += Check("resume on an active loop is refused", Refused(() => Do(fx, Impl, LoopKinds.Resume, []), ErrorCodes.InvalidLoopTransition));
        f += Check("rebind with another session id is refused (first bind wins)",
            Refused(() => Do(fx, Impl, LoopKinds.Rebind, RebindFields("session-intruder")), ErrorCodes.InvalidLoopTransition) && Loop(fx).Binding!.SessionId == "session-1");
        int e0 = Loop(fx).Epoch;
        f += Check("rebind whose identity the custodian cannot re-verify is refused; the epoch stays",
            Refused(() => Do(fx, Impl, LoopKinds.Rebind, RebindFields(pid: Unrelated)), ErrorCodes.ProcessIdentityUnverified) && Loop(fx).Epoch == e0);
        JsonObject ra = Do(fx, Impl, LoopKinds.Rebind, RebindFields());
        f += Check("rebind on an active loop stays active (epoch + 1)", (string?)ra["status"] == LoopStatuses.Active && (int)ra["epoch"]! == e0 + 1);

        Fx unbound = NewLoop(repos, "RebindUnbound");
        f += Check("rebind on an unbound loop is refused (bind first)", Refused(() => Do(unbound, Impl, LoopKinds.Rebind, RebindFields()), ErrorCodes.InvalidLoopTransition));
        f += Check("pause on an unbound loop is refused", Refused(() => Do(unbound, Impl, LoopKinds.Pause, Reason(PauseReasons.UserInterrupt)), ErrorCodes.InvalidLoopTransition));
        JsonObject cancelled = Do(unbound, Impl, LoopKinds.End, new JsonObject { ["status"] = LoopStatuses.Cancelled });
        f += Check("end on an unbound loop cancels it", (string?)cancelled["status"] == LoopStatuses.Cancelled);
        return f;
    }

    // ---- terminal states: end, deadline, no resurrection ----

    private static int TerminalCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "End");
        f += Check("end: a client cannot end with a custodian-derived or completion status (expired, budget_exhausted, ready)",
            Invalid(() => Do(fx, Impl, LoopKinds.End, new JsonObject { ["status"] = "expired" }))
            && Invalid(() => Do(fx, Impl, LoopKinds.End, new JsonObject { ["status"] = "budget_exhausted" }))
            && Invalid(() => Do(fx, Impl, LoopKinds.End, new JsonObject { ["status"] = "ready" })));
        JsonObject e = Do(fx, Impl, LoopKinds.End, new JsonObject { ["status"] = LoopStatuses.Cancelled, ["reason"] = "operator stop" });
        f += Check("end: non-terminal -> cancelled (irreversible)", (string?)e["status"] == LoopStatuses.Cancelled && Loop(fx).Ended!.Status == LoopStatuses.Cancelled);
        f += Check("a cancelled loop refuses every transition, the operator's resume included (LOOP_TERMINAL)", AllTerminal(fx));
        f += Check("consume_loop for the run is LOOP_TERMINAL (no resurrection)",
            Refused(() => fx.Led.ConsumeLoop(fx.Repo, fx.Run, Rid("remint")), ErrorCodes.LoopTerminal));

        Fx dl = Bound(repos, "Deadline");
        EditLoop(dl, x => x with { DeadlineAt = DateTime.UtcNow.AddSeconds(-1).ToString("o") });
        int r0 = Loop(dl).LoopRevision;
        f += Check("deadline: the next transition finds the window ended -> LOOP_TERMINAL; expired (custodian-derived, persisted)",
            Refused(() => Do(dl, Impl, LoopKinds.SpendContinuation, Spend()), ErrorCodes.LoopTerminal)
            && Loop(dl).Status == LoopStatuses.Expired && Loop(dl).Ended!.By == "custodian" && Loop(dl).LoopRevision == r0 + 1);
        f += Check("deadline: wake_consume on the expired loop never authorizes", !Authorized(Do(dl, Impl, LoopKinds.WakeConsume, Claim("wc-1-000000000000"))));
        return f;
    }

    // ---- request validation ----

    private static int ValidationCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "Validate");
        f += Check("an unknown kind is refused (INVALID_ARGUMENT)", Invalid(() => Do(fx, Impl, "promote", [])));
        f += Check("an unknown field is refused, not ignored (MALFORMED_REQUEST)",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, new JsonObject { ["used"] = 0 }), ErrorCodes.MalformedRequest));
        f += Check("a client-supplied epoch inside fields is refused (MALFORMED_REQUEST)",
            Refused(() => Do(fx, Impl, LoopKinds.Rebind, new JsonObject { ["session_id"] = "session-1", ["process"] = new JsonObject { ["pid"] = Claude }, ["epoch"] = 99 }), ErrorCodes.MalformedRequest));
        f += Check("a pause reason outside the enum is refused (INVALID_ARGUMENT)", Invalid(() => Do(fx, Impl, LoopKinds.Pause, Reason("vacation"))));
        f += Check("a loop id that is not this run's is refused (UNKNOWN_LOOP)",
            Refused(() => fx.Led.LoopTransition(Impl, fx.Repo, LoopRequest.Parse(fx.Run, Guid.NewGuid().ToString(), 1, 2, LoopKinds.SpendContinuation, Spend(), Rid("x"))), ErrorCodes.UnknownLoop));
        f += Check("a run without a loop is refused (UNKNOWN_LOOP)",
            Refused(() => fx.Led.LoopTransition(Impl, fx.Repo, LoopRequest.Parse("run-none", fx.LoopId, 1, 2, LoopKinds.SpendContinuation, Spend(), Rid("x"))), ErrorCodes.UnknownLoop));
        f += Check("an unsafe request id is refused (INVALID_ARGUMENT)", Invalid(() => LoopRequest.Parse(fx.Run, fx.LoopId, 1, 2, LoopKinds.Resume, [], "bad id\n")));
        f += Check("the minting request id cannot be reused for a transition (REQUEST_ID_CONFLICT)",
            Refused(() => Do(fx, Impl, LoopKinds.SpendContinuation, Spend(), fx.MintRequestId), ErrorCodes.RequestIdConflict));
        Do(fx, Impl, LoopKinds.Pause, new JsonObject { ["reason"] = PauseReasons.ConfigChange, ["detail"] = "line one\nforged line" });
        f += Check("pause detail: control characters are neutralized (no forged evidence or audit line)", Loop(fx).Pause!.Detail == "line one forged line");
        return f;
    }

    // ---- contract §6/§7: projections and protected-vs-attended selection ----

    private static int ProjectionCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "Projection");
        Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx));
        JsonObject listing = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false);
        JsonObject section = listing["loop"]!.AsObject();
        f += Check("[contract 6] the loop section has its OWN revision, separate from the user-record log's",
            (bool)section["protected"]! && (int)section["loopRevision"]! == Loop(fx).LoopRevision && (int)listing["revision"]! == 0);
        string implJson = section.ToJsonString();
        f += Check("[contract 6] the implementer projection omits the session id, process facts, nonce and history",
            !implJson.Contains("session-1") && !implJson.Contains("sessionId") && !implJson.Contains("process") && !implJson.Contains("Nonce")
            && !implJson.Contains("events") && !implJson.Contains(Loop(fx).BindNonce.Sha256));
        JsonNode record = section["record"]!;
        f += Check("[contract 6] the implementer projection shows the state, budgets, current handle and claims",
            (string?)record["status"] == LoopStatuses.Active && (int)record["remaining"]!["wakes"]! == 1
            && record["operations"]!.AsArray().Count == 1 && record["wakeClaims"]!.AsArray().Count == 1);
        JsonObject op = fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: true)["loop"]!.AsObject();
        f += Check("[contract 6] the operator projection is the full record (session, process facts, history)",
            op.ToJsonString().Contains("session-1") && op["record"]!["events"]!.AsArray().Count >= 2);
        f += Check("[contract 7] a run without a custodian loop is not protected",
            !(bool)fx.Led.ListUserRecords(fx.Repo, "run-unprotected", operatorView: false)["loop"]!["protected"]!);
        Do(fx, Impl, LoopKinds.End, new JsonObject { ["status"] = LoopStatuses.RunEnded });
        f += Check("[contract 7] a terminal protected run stays protected", (bool)fx.Led.ListUserRecords(fx.Repo, fx.Run, operatorView: false)["loop"]!["protected"]!);
        return f;
    }

    // ---- concurrency and restart durability ----

    private static int ConcurrencyAndRestartCases(string repos)
    {
        int f = 0;
        Fx fx = Bound(repos, "Race");
        string claim = (string)Do(fx, Impl, LoopKinds.WakeArm, CurrentHandle(fx))["claimId"]!;
        LoopRecord at = Loop(fx);
        int authorized = 0;
        JsonObject raceClaim = WithDerivation(fx, Claim(claim)); // one derivation; only the first consume can use it
        Parallel.For(0, 12, i =>
        {
            JsonObject r = fx.Led.LoopTransition(Impl, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, at.Epoch, at.LoopRevision, LoopKinds.WakeConsume, raceClaim, $"race-consume-{i}"));
            if (Authorized(r)) Interlocked.Increment(ref authorized);
        });
        f += Check($"concurrent wake_consume of one claim: exactly 1 of 12 authorized (got {authorized})", authorized == 1);

        var restarted = new GrantLedger("cust-selftest", Table);
        LoopRecord after = restarted.Read().Loops!.Single(l => l.LoopId == fx.LoopId);
        WakeClaim won = after.WakeClaims!.Single();
        f += Check("restart: the budgets, the epoch and the consumed claim persist", after.Used.Wakes == 1 && won.State == "consumed" && after.Epoch == at.Epoch);
        JsonObject replay = restarted.LoopTransition(Impl, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, at.Epoch, at.LoopRevision, LoopKinds.WakeConsume, raceClaim, won.ConsumeRequestId!));
        f += Check("restart: replaying the winning consume does not authorize again", !Authorized(replay));

        LoopRecord s0 = Loop(fx);
        int applied = 0;
        JsonObject raceSpend = WithDerivation(fx, Spend());
        Parallel.For(0, 8, i =>
        {
            try
            {
                fx.Led.LoopTransition(Impl, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, s0.Epoch, s0.LoopRevision, LoopKinds.SpendContinuation, raceSpend, $"race-spend-{i}"));
                Interlocked.Increment(ref applied);
            }
            catch (CustodianRefusal) { /* STALE_LOOP_STATE for every loser */ }
        });
        f += Check($"concurrent spend at one revision: exactly 1 applied (got {applied})", applied == 1 && Loop(fx).Used.Continuations == 1);
        return f;
    }

    // ---- pipe cases (run by self-test-ipc, through the real pipe server, classifier and dispatch) ----

    /// <summary>One loop addressed over the real pipes: an envelope per request, the loop's arguments filled in.</summary>
    private sealed class IpcLoop(Func<string, string, string> send, string repo, string run)
    {
        internal string LoopId { get; set; } = "";

        internal JsonObject Send(string pipe, string rid, string op, JsonObject args)
            => JsonNode.Parse(send(pipe, new JsonObject { ["v"] = 1, ["requestId"] = rid, ["op"] = op, ["args"] = args }.ToJsonString()))!.AsObject();

        internal JsonObject Args(int epoch, int rev, string kind, JsonObject fields) => new()
        {
            ["repositoryRoot"] = repo, ["runId"] = run, ["loopId"] = LoopId, ["epoch"] = epoch, ["baseLoopRevision"] = rev, ["kind"] = kind, ["fields"] = fields,
        };

        internal JsonObject T(string pipe, string rid, string kind, JsonObject fields, int epoch, int rev) => Send(pipe, rid, "loop_transition", Args(epoch, rev, kind, fields));

        internal JsonObject List(string rid) => Send(CustodianConstants.ImplementerPipe, rid, "list_user_records", new JsonObject { ["repositoryRoot"] = repo, ["runId"] = run });
    }

    /// <summary>The loop lifecycle over the real pipes. A grant is seeded directly in the scratch store
    /// (prepare_grant is operator-only; this token may not be elevated). The pipe client is THIS process, so
    /// its parent stands for the originating Claude process: the bind exercises the OS-reported client pid and
    /// the real process table.</summary>
    internal static int IpcCases(string scratch, Func<string, string, string> send, bool elevated)
    {
        const string Run = "run-ipc-loop";
        string repo = Directory.CreateDirectory(Path.Combine(scratch, "loop-ipc-repo")).FullName;
        var seed = new GrantLedger("cust-ipc-seed");
        seed.PrepareGrant(repo, 2, 60, "ipc-grant");
        seed.Commit("ipc-grant", null);
        RunSelfTest.EnsureConfig(seed, repo); // P3.4C-4: a run is opened only under the repository's protected configuration
        var loop = new IpcLoop(send, repo, Run);

        // P3.4C-3: the run is registered (run_transition open) before its loop is consumed, over the same pipe.
        JsonObject opened = loop.Send(CustodianConstants.ImplementerPipe, "ipc-open", "run_transition",
            new JsonObject { ["repositoryRoot"] = repo, ["runId"] = Run, ["kind"] = "open", ["fields"] = RunSelfTest.DefaultOpenFields() });
        int o = Check("ipc: run_transition open registers the run over the implementer pipe", (bool?)opened["ok"] == true);
        if (o != 0) return o;
        JsonObject mint = loop.Send(CustodianConstants.ImplementerPipe, "ipc-mint", "consume_loop", new JsonObject { ["repositoryRoot"] = repo, ["runId"] = Run });
        int f = Check("ipc: consume_loop mints the loop over the implementer pipe", (bool?)mint["ok"] == true);
        if (f != 0) return f;
        loop.LoopId = (string)mint["data"]!["loopId"]!;
        int parent = new OsProcessTable().Snapshot()?.GetValueOrDefault(Environment.ProcessId)?.ParentPid ?? -1;
        f += IpcBindCases(loop, (string)mint["data"]!["bindNonce"]!, parent, elevated);
        f += IpcRefusalCases(loop, parent);
        return f;
    }

    private static int IpcBindCases(IpcLoop loop, string nonce, int parent, bool elevated)
    {
        const string Imp = CustodianConstants.ImplementerPipe;
        int f = 0;
        JsonObject bound = loop.T(Imp, "ipc-bind", LoopKinds.Bind, new JsonObject
        {
            ["bindNonce"] = nonce, ["session_id"] = "session-ipc", ["process"] = new JsonObject { ["pid"] = parent },
        }, 1, 1);
        f += Check("ipc: bind over the pipe - the custodian verified CLAUDE_PID against the OS-reported connected process",
            (bool?)bound["ok"] == true && (bool?)bound["data"]?["binding"]?["verified"] == true);
        f += Check("ipc: a spend naming another session is refused over the pipe (SESSION_NOT_BOUND)",
            (string?)loop.T(Imp, "ipc-spend-other", LoopKinds.SpendContinuation, Spend("session-other"), 1, 2)["code"] == ErrorCodes.SessionNotBound);
        // P3.4C-5 Increment 3: this custodian has no helper, so it serves no derivation — the bound session's spend passes its
        // OS check of the connected process and is then refused on the derivation rule (fail closed).
        f += Check("ipc: the bound session's spend passes the custodian's OS check of the connected process, then needs the custodian's derivation (DERIVATION_STALE without one)",
            (string?)loop.T(Imp, "ipc-spend", LoopKinds.SpendContinuation, Spend("session-ipc"), 1, 2)["code"] == ErrorCodes.DerivationStale);
        loop.T(Imp, "ipc-pause", LoopKinds.Pause, new JsonObject { ["reason"] = PauseReasons.OperatorActionRequired }, 1, 2);
        f += Check("ipc: an implementer resume of an operator-only pause -> CALLER_NOT_AUTHORIZED",
            (string?)loop.T(Imp, "ipc-resume", LoopKinds.Resume, [], 1, 3)["code"] == ErrorCodes.CallerNotAuthorized);
        string? opResume = (string?)loop.T(CustodianConstants.OperatorPipe, "ipc-resume-op", LoopKinds.Resume, [], 1, 3)["code"];
        f += elevated
            ? Check("ipc: the operator pipe serves the elevated configured operator's resume (not CALLER_NOT_AUTHORIZED)", opResume != ErrorCodes.CallerNotAuthorized)
            : Check("ipc: the operator pipe refuses this non-elevated token (no operator authority to resume)", opResume == ErrorCodes.CallerNotAuthorized);
        return f;
    }

    private static int IpcRefusalCases(IpcLoop loop, int parent)
    {
        const string Imp = CustodianConstants.ImplementerPipe;
        int f = 0;
        JsonObject forged = loop.T(Imp, "ipc-forge", LoopKinds.Rebind, new JsonObject
        {
            ["session_id"] = "session-ipc", ["process"] = new JsonObject { ["pid"] = parent, ["verified"] = true },
        }, 1, 4);
        f += Check("ipc: a client 'verified' is refused, not ignored (MALFORMED_REQUEST)", (string?)forged["code"] == ErrorCodes.MalformedRequest);
        JsonObject wc = loop.T(Imp, "ipc-wake", LoopKinds.WakeConsume, Claim("wc-1-000000000000", "session-ipc"), 1, 4);
        f += Check("ipc: wake_consume of an invented claim answers ok with dispatchAuthorized:false",
            (bool?)wc["ok"] == true && (bool?)wc["data"]?["dispatchAuthorized"] == false);
        JsonObject args = loop.Args(1, 4, LoopKinds.Resume, []);
        args["role"] = "operator";
        f += Check("ipc: an authority-shaped extra argument is refused (MALFORMED_REQUEST)",
            (string?)loop.Send(Imp, "ipc-extra", "loop_transition", args)["code"] == ErrorCodes.MalformedRequest);
        JsonObject listed = loop.List("ipc-list-loop");
        f += Check("ipc: list_user_records carries the protected loop section without the session id",
            (bool?)listed["data"]?["loop"]?["protected"] == true && !listed.ToJsonString().Contains("session-ipc"));
        return f;
    }

    // ---- helpers ----

    private static string Rid(string tag) => $"{tag}-{Interlocked.Increment(ref _seq)}";

    private static Fx NewLoop(string repos, string name)
    {
        var led = new GrantLedger("cust-selftest", Table);
        string repo = Directory.CreateDirectory(Path.Combine(repos, "Loop" + name)).FullName;
        string grant = Rid("grant");
        led.PrepareGrant(repo, 8, 60, grant);
        led.Commit(grant, null);
        string mintRid = Rid("mint");
        RunSelfTest.Open(led, repo, "run-" + name); // P3.4C-3: a loop is minted only for an open run
        JsonObject minted = led.ConsumeLoop(repo, "run-" + name, mintRid);
        return new Fx(led, repo, "run-" + name, (string)minted["loopId"]!, (string)minted["bindNonce"]!, mintRid);
    }

    private static Fx Bound(string repos, string name)
    {
        Fx fx = NewLoop(repos, name);
        Do(fx, Impl, LoopKinds.Bind, BindFields(fx));
        return fx;
    }

    private static LoopRecord Loop(Fx fx) => fx.Led.Read().Loops!.Single(l => l.LoopId == fx.LoopId);

    /// <summary>One transition against the loop's CURRENT epoch and revision (unless given). P3.4C-5 Increment 3: a
    /// continuation or wake that names no derivation is asked on a fresh custodian derivation with moved progress (these
    /// P3.4C-2 cases test the loop's own rules; the derivation rules have their own cases), and a replayed request id
    /// sends the same fields again.</summary>
    private static JsonObject Do(Fx fx, LoopCaller caller, string kind, JsonObject fields, string? requestId = null, int? epoch = null, int? rev = null)
    {
        LoopRecord l = Loop(fx);
        string rid = requestId ?? Rid(kind);
        if (kind is LoopKinds.SpendContinuation or LoopKinds.WakeConsume && !fields.ContainsKey("derivation_id"))
            fields = Sent.GetOrAdd(rid, _ => WithDerivation(fx, fields));
        return fx.Led.LoopTransition(caller, fx.Repo, LoopRequest.Parse(fx.Run, fx.LoopId, epoch ?? l.Epoch, rev ?? l.LoopRevision, kind, fields, rid));
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, JsonObject> Sent = new(StringComparer.Ordinal);

    /// <summary><paramref name="fields"/> naming a fresh custodian derivation of the fixture's run, on moved progress (a new
    /// progress fingerprint). Unchanged when the custodian serves none (the request then names none).</summary>
    private static JsonObject WithDerivation(Fx fx, JsonObject fields) => WithDerivation(fx.Led, fx.Repo, fx.Run, fields);

    internal static JsonObject WithDerivation(GrantLedger led, string repo, string run, JsonObject fields)
    {
        CaptureFixture.Measurements.Spec = CaptureFixture.Measurements.Spec with { Fingerprint = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) };
        JsonObject d = led.DerivationSection(repo, run, RunSelfTest.RunJsonBase64);
        if ((bool?)d["available"] != true) return fields;
        var withId = (JsonObject)fields.DeepClone();
        withId["derivation_id"] = (string)d["derivationId"]!;
        return withId;
    }

    /// <summary>Set up a time-based condition the way only the custodian store could: an edit of the scratch
    /// ledger (the real store is custodian-only).</summary>
    private static void EditLoop(Fx fx, Func<LoopRecord, LoopRecord> edit)
    {
        LedgerFile file = fx.Led.Read();
        int i = file.Loops!.FindIndex(l => l.LoopId == fx.LoopId);
        file.Loops[i] = edit(file.Loops[i]);
        File.WriteAllText(StorePaths.LedgerPath, JsonSerializer.Serialize(file, LedgerJson));
    }

    /// <summary>Every kind on a terminal loop is LOOP_TERMINAL (the operator's resume included); a
    /// wake_consume answers dispatchAuthorized:false with that refusal.</summary>
    private static bool AllTerminal(Fx fx)
    {
        bool ok = true;
        foreach ((LoopCaller caller, string kind, JsonObject fields) in new (LoopCaller, string, JsonObject)[]
        {
            (Impl, LoopKinds.Bind, BindFields(fx)), (Impl, LoopKinds.Rebind, RebindFields()), (Impl, LoopKinds.SpendContinuation, Spend()),
            (Impl, LoopKinds.WakeArm, Handle("op-1-000000000000")), (Impl, LoopKinds.Pause, Reason(PauseReasons.UserInterrupt)),
            (Impl, LoopKinds.Resume, []), (Oper, LoopKinds.Resume, []), (Impl, LoopKinds.End, new JsonObject { ["status"] = LoopStatuses.Cancelled }),
        })
            ok &= Refused(() => Do(fx, caller, kind, fields), ErrorCodes.LoopTerminal);
        JsonObject wc = Do(fx, Impl, LoopKinds.WakeConsume, Claim("wc-1-000000000000"));
        return ok && !Authorized(wc) && (string?)wc["refusal"] == ErrorCodes.LoopTerminal;
    }

    private static JsonObject BindFields(Fx fx, string session = "session-1", int? pid = Claude)
        => new() { ["bindNonce"] = fx.Nonce, ["session_id"] = session, ["process"] = new JsonObject { ["pid"] = pid } };
    private static JsonObject RebindFields(string session = "session-1", int? pid = Claude)
        => new() { ["session_id"] = session, ["process"] = new JsonObject { ["pid"] = pid } };
    private static JsonObject Reason(string reason) => new() { ["reason"] = reason };
    private static JsonObject Spend(string session = "session-1") => new() { ["session_id"] = session };
    private static JsonObject Claim(string claimId, string session = "session-1") => new() { ["claimId"] = claimId, ["session_id"] = session };
    private static JsonObject Handle(string handle, string session = "session-1") => new() { ["operationHandle"] = handle, ["session_id"] = session };
    private static JsonObject CurrentHandle(Fx fx, string session = "session-1") => Handle(Loop(fx).CurrentOperation!.Handle, session);
    private static bool Authorized(JsonObject r) => r["dispatchAuthorized"] is JsonValue v && v.GetValue<bool>();
    private static bool Paused(Fx fx, string reason) => Loop(fx) is { Status: LoopStatuses.Paused } l && l.Pause?.Reason == reason;

    private static bool Refused(Func<JsonObject> act, string code)
    {
        try { act(); Console.WriteLine($"    (expected {code}, got a result)"); return false; }
        catch (CustodianRefusal r)
        {
            if (r.Code != code) Console.WriteLine($"    (expected {code}, got {r.Code}: {r.Message})");
            return r.Code == code;
        }
        catch (Exception e) { Console.WriteLine($"    (expected {code}, got {e.GetType().Name}: {e.Message})"); return false; }
    }

    private static bool Invalid(Func<object> act)
    {
        try { act(); return false; }
        catch (ArgumentException) { return true; }
        catch (Exception e) { Console.WriteLine($"    (expected INVALID_ARGUMENT, got {e.GetType().Name}: {e.Message})"); return false; }
    }

    private static int Check(string name, bool ok) { Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}"); return ok ? 0 : 1; }
}
