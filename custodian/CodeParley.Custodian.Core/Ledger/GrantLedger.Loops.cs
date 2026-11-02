using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>Who is asking, as the OS classified the connection — never request content.
/// <see cref="ClientProcessId"/> is the process connected to the pipe, as the system reports it (correlation
/// evidence for the binding check, D7).</summary>
internal sealed record LoopCaller(bool IsOperator, string? ProofDigest, int? ClientProcessId)
{
    internal string Name => IsOperator ? "operator" : "implementer";
}

/// <summary>
/// P3.4C-2 increment 6: the custodian-owned loop lifecycle (<c>loop_transition</c>, contract §2–§5). Every
/// transition is computed HERE from the stored record and the request's typed fields — a client never
/// replaces a record or sets a status, epoch, budget, binding verdict, handle or claim. Each applied
/// transition bumps the loop's own revision and appends evidence; requests are idempotent on their request id
/// (a replay returns the stored result, except that a replayed <c>wake_consume</c> never authorizes again).
/// All transitions run under the ledger's single lock and persist by one atomic ledger write.
/// </summary>
internal sealed partial class GrantLedger
{
    private const string CustodianActor = "custodian";
    private const string LiveBinding = "live";
    private const string ClaimArmed = "armed", ClaimConsumed = "consumed";

    /// <summary>One kind's outcome: the next record and its kind-specific result — or a custodian-derived
    /// terminal record to persist before the refusal is returned (the budget ran out).</summary>
    private sealed record LoopStep(LoopRecord? Next, JsonObject? Result, LoopRecord? Derived = null, CustodianRefusal? Refusal = null)
    {
        internal static LoopStep Applied(LoopRecord next, JsonObject result) => new(next, result);
        internal static LoopStep DerivedRefusal(LoopRecord derived, CustodianRefusal refusal) => new(null, null, derived, refusal);
    }

    /// <summary>Apply one <c>loop_transition</c> for the run of the directory <paramref name="repositoryRoot"/>
    /// names (the custodian's own identity of it). Refusals are <see cref="CustodianRefusal"/>s — except for
    /// <c>wake_consume</c>, which answers every call that does not consume its claim with
    /// <c>dispatchAuthorized:false</c> (TD correction B), so no refusal shape can pass for an authorization.</summary>
    internal JsonObject LoopTransition(LoopCaller caller, string repositoryRoot, LoopRequest req)
    {
        string repoKey = RepoIdentities.Resolve(repositoryRoot).Key;
        if (req.Kind is LoopKinds.SpendContinuation or LoopKinds.WakeConsume) return AutomationTransition(caller, repoKey, req);
        lock (EnterGate())
        {
            return ApplyLoopTransition(caller, repoKey, req, _clock(), Automation.None)!;
        }
    }

    /// <summary>P3.4C-5 Increment 3 (§5.2, §2.4, N5-17): the authority-creating transitions — a continuation or a wake — are
    /// decided on the custodian's own derivation in three steps: under the gate every rule is checked (the derivation named
    /// usable: cached, fresh, of the current revisions, an implementer step, moved progress); outside it the source and the
    /// checks' inputs the derivation measured are measured again; under the gate everything is checked again and the
    /// re-measurement must equal the derivation's before anything is spent. A wake refused anywhere is answered
    /// <c>dispatchAuthorized:false</c>.</summary>
    private JsonObject AutomationTransition(LoopCaller caller, string repoKey, LoopRequest req)
    {
        try
        {
            DerivationEntry d;
            EngineRuntimeRecord runtime;
            lock (EnterGate())
            {
                var pre = new Automation(Phase.Precheck, null, null);
                if (ApplyLoopTransition(caller, repoKey, req, _clock(), pre) is { } replayed) return replayed;
                d = pre.Checked ?? throw new InvalidOperationException("a precheck passed without a derivation");
                runtime = RequireMeasureReady();
            }
            JsonObject? measured = Remeasure(d, runtime);
            lock (EnterGate())
            {
                return ApplyLoopTransition(caller, repoKey, req, _clock(), new Automation(Phase.Commit, d, measured))!;
            }
        }
        catch (CustodianRefusal r) when (req.Kind == LoopKinds.WakeConsume)
        {
            return WakeNotAuthorized(req, r, IsClaimConsumed(repoKey, req));
        }
    }

    private enum Phase { None, Precheck, Commit }

    /// <summary>Which step of an automation transition this is (§5.2): none (any other kind), the precheck (the loop's rules
    /// and a current derivation; no write; it reports the derivation it checked), or the commit (every rule again, the
    /// re-measurement, then the derivation's route and progress).</summary>
    private sealed class Automation(Phase phase, DerivationEntry? derivation, JsonObject? measured)
    {
        internal static readonly Automation None = new(Phase.None, null, null);
        internal Phase Phase { get; } = phase;
        internal DerivationEntry? Derivation { get; } = derivation;
        internal JsonObject? Measured { get; } = measured;
        internal DerivationEntry? Checked { get; set; }
    }

    /// <summary>The derivation rules of a continuation or wake (§5.2) in their order — stale (current, then the re-measurement
    /// of N5-17), then the route, then progress; the precheck stops before the re-measurement. Callers hold
    /// <see cref="Gate"/>.</summary>
    private DerivationEntry RequireAutomationDerivation(string repoKey, LoopRecord loop, LoopRequest req, DateTime now, Automation a)
    {
        DerivationEntry d = RequireCurrentDerivation(repoKey, req, now);
        if (a.Phase == Phase.Commit)
        {
            if (a.Derivation is null || a.Derivation.DerivationId != d.DerivationId) throw new CustodianRefusal(ErrorCodes.DerivationStale, "the derivation changed during the re-measurement; derive again");
            RequireSameMeasurement(d, a.Measured);
            RequireRouteAndProgress(d, loop);
        }
        a.Checked = d;
        return d;
    }

    private JsonObject? ApplyLoopTransition(LoopCaller caller, string repoKey, LoopRequest req, DateTime now, Automation automation)
    {
        LedgerFile file = Read();
        int index = file.Loops!.FindIndex(l => l.RepoKey == repoKey && l.RunId == req.RunId);
        if (index < 0 || file.Loops[index].LoopId != req.LoopId)
            throw new CustodianRefusal(ErrorCodes.UnknownLoop, "this run has no automation loop with that id");
        LoopRecord loop = Normalized(file.Loops[index]);
        if (ReplayOf(loop, caller, req) is { } replayed) return replayed;

        // Custodian-derived: a live loop past its deadline ends (expired) before anything else is judged.
        if (!LoopStatuses.IsTerminal(loop.Status) && now >= ParseTime(loop.DeadlineAt))
        {
            PersistDerived(file, index, DeriveEnd(loop, LoopStatuses.Expired, "run_seconds", now));
            throw new CustodianRefusal(ErrorCodes.LoopTerminal, "the loop's automation window ended; the loop is now expired");
        }
        // P3.4C-3 (§3.4(3), §2.5 S3): the run record, read in this same hold. A terminal or MISSING run record — the run
        // ended (and its end's own derivation did not reach the ledger), a rollback removed it, or the loop was minted
        // before P3.4C-3 — ends the loop by derivation first, and nothing is authorized (fail closed).
        if (!LoopStatuses.IsTerminal(loop.Status) && ReadRun(repoKey, req.RunId) is var run && (run is null || run.IsTerminal))
        {
            PersistDerived(file, index, DeriveEnd(loop, LoopStatuses.RunEnded, run is null ? "run_record_missing" : $"run_{run.Status}", now));
            throw new CustodianRefusal(ErrorCodes.LoopTerminal, run is null
                ? "the custodian holds no run record for this loop's run; the loop ended and authorizes nothing"
                : $"the run has ended ({run.Status}); the loop ended with it and authorizes nothing");
        }
        if (LoopStatuses.IsTerminal(loop.Status))
            throw new CustodianRefusal(ErrorCodes.LoopTerminal, $"the loop has ended ({loop.Status}); no transition leaves a terminal state");
        AuthorizeKind(caller, loop, req);
        if (req.Epoch != loop.Epoch)
            throw new CustodianRefusal(ErrorCodes.StaleLoopEpoch, $"the loop is in epoch {loop.Epoch}, not {req.Epoch}");
        if (req.BaseLoopRevision != loop.LoopRevision)
            throw new CustodianRefusal(ErrorCodes.StaleLoopState, $"the loop is at revision {loop.LoopRevision}, not {req.BaseLoopRevision}");
        if (loop.Events!.Count >= CustodianConstants.MaxLoopEvents && req.Kind != LoopKinds.End)
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, $"the loop's transition log is full ({CustodianConstants.MaxLoopEvents}); only end is accepted");

        LoopStep step = Step(caller, repoKey, loop, req, now, automation);
        if (step.Derived is not null)
        {
            PersistDerived(file, index, step.Derived);
            throw step.Refusal!;
        }
        if (automation.Phase == Phase.Precheck) return null; // every rule passed; nothing is written before the re-measurement
        LoopRecord next = Recorded(step.Next!, loop, caller, req, step.Result!, now, out JsonObject result);
        file.Loops[index] = next;
        if (req.Kind is LoopKinds.SpendContinuation or LoopKinds.WakeArm or LoopKinds.WakeConsume) Hold(HoldPoints.LoopAuthorized + req.Kind);
        Write(file); // persisted BEFORE the result (a wake_consume's authorization included) is returned
        Audit($"loop_transition kind={req.Kind} loopId={next.LoopId} runId={next.RunId} {loop.Status}->{next.Status} epoch={next.Epoch} rev={next.LoopRevision} caller={caller.Name} requestId={req.RequestId}");
        return result;
    }

    private LoopStep Step(LoopCaller caller, string repoKey, LoopRecord loop, LoopRequest req, DateTime now, Automation automation) => req.Kind switch
    {
        LoopKinds.Bind => BindStep(caller, loop, req, now),
        LoopKinds.Rebind => RebindStep(caller, loop, req, now),
        LoopKinds.SpendContinuation => SpendStep(caller, repoKey, loop, req, now, automation),
        LoopKinds.WakeArm => WakeArmStep(caller, loop, req, now),
        LoopKinds.WakeConsume => WakeConsumeStep(caller, repoKey, loop, req, now, automation),
        LoopKinds.Pause => PauseStep(caller, loop, req, now),
        LoopKinds.Resume => ResumeStep(loop, now),
        LoopKinds.End => EndStep(caller, loop, req, now),
        _ => throw new ArgumentException("unknown loop transition kind"),
    };

    // ---- the kinds ----

    /// <summary>unbound → active: first bind wins, against the custodian's one-time nonce; the custodian runs
    /// the process check itself and records its verdict; issues operation handle #1 (TD correction A).</summary>
    private LoopStep BindStep(LoopCaller caller, LoopRecord loop, LoopRequest req, DateTime now)
    {
        if (loop.Status != LoopStatuses.Unbound || loop.Binding is not null)
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, loop.Binding is null ? $"the loop is {loop.Status}" : "the loop is already bound (the first binding wins)");
        CheckBindNonce(loop.BindNonce, req.BindNonce!, now);
        LoopProcessFacts process = CheckProcess(req.ClaimedPid, caller, now);
        LoopOperation op = NewOperation(1, loop.Epoch, LoopKinds.Bind, now);
        LoopRecord next = loop with
        {
            Status = LoopStatuses.Active,
            Binding = new LoopBinding(req.SessionId!, LiveBinding, Iso(now), null, process),
            BindNonce = loop.BindNonce with { UsedAt = Iso(now) },
            Operations = [op],
        };
        return LoopStep.Applied(next, new JsonObject { ["operationHandle"] = op.Handle, ["binding"] = BindingResult(next.Binding!) });
    }

    /// <summary>active → active, paused → paused: the SAME session re-binds with a re-verified identity; the
    /// epoch advances (wakes armed before are stale). It updates the binding and the epoch ONLY — never the
    /// status or the pause (TD correction 2): a rebind cannot resume anything.</summary>
    private LoopStep RebindStep(LoopCaller caller, LoopRecord loop, LoopRequest req, DateTime now)
    {
        if (loop.Binding is null || loop.Status == LoopStatuses.Unbound)
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, "the loop is not bound; a rebind needs an earlier binding");
        if (!string.Equals(loop.Binding.SessionId, req.SessionId, StringComparison.Ordinal))
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, "the loop is bound to another session; a rebind does not move it (the first binding wins)");
        LoopProcessFacts process = CheckProcess(req.ClaimedPid, caller, now);
        if (!process.Verified)
            throw new CustodianRefusal(ErrorCodes.ProcessIdentityUnverified, $"the session's process identity could not be re-verified: {process.Detail}");
        LoopRecord next = loop with
        {
            Epoch = loop.Epoch + 1,
            Binding = loop.Binding with { State = LiveBinding, ReboundAt = Iso(now), Process = process },
        };
        var result = new JsonObject { ["binding"] = BindingResult(next.Binding!) };
        if (next.Pause is { } pause) result["pauseReason"] = pause.Reason;
        return LoopStep.Applied(next, result);
    }

    /// <summary>active → active: reduce-only, for the bound session's process tree only. Asking past the
    /// continuation budget ends the loop (budget_exhausted, custodian-derived) — but only once the request passed
    /// the binding checks, so another session cannot end it this way. P3.4C-5 Increment 3 (§5.2): granted only on the
    /// custodian's own derivation — an implementer-step route with moved progress, re-measured unchanged — whose
    /// progress fingerprint the loop then records. Issues the next operation handle.</summary>
    private LoopStep SpendStep(LoopCaller caller, string repoKey, LoopRecord loop, LoopRequest req, DateTime now, Automation automation)
    {
        RequireActiveVerified(loop);
        RequireBoundCaller(caller, loop, req);
        if (loop.Used.Continuations >= loop.Limits.Continuations)
            return LoopStep.DerivedRefusal(DeriveEnd(loop, LoopStatuses.BudgetExhausted, "continuations", now),
                new CustodianRefusal(ErrorCodes.LoopBudgetExhausted, $"the continuation budget ({loop.Limits.Continuations}) is used up; the loop ended (budget_exhausted)"));
        DerivationEntry d = RequireAutomationDerivation(repoKey, loop, req, now, automation);
        LoopOperation op = NewOperation(loop.Operations!.Count + 1, loop.Epoch, LoopKinds.SpendContinuation, now);
        LoopRecord next = loop with
        {
            Used = loop.Used with { Continuations = loop.Used.Continuations + 1 }, Operations = [.. loop.Operations, op],
            Progress = new LoopProgress(d.Fingerprint, d.DerivationId, Iso(now), LoopKinds.SpendContinuation),
        };
        return LoopStep.Applied(next, new JsonObject
        {
            ["operationHandle"] = op.Handle, ["continuationsUsed"] = next.Used.Continuations, ["continuationsLimit"] = next.Limits.Continuations,
            ["derivationId"] = d.DerivationId, ["route"] = d.RouteCode,
        });
    }

    /// <summary>active: reserves one wake against the CURRENT custodian-issued operation — it can neither mint
    /// a handle nor reset a counter — spending the per-operation AND the per-run budget (both persisted), and
    /// returns a one-shot, epoch-bound claim. For the bound session's process tree only.</summary>
    private LoopStep WakeArmStep(LoopCaller caller, LoopRecord loop, LoopRequest req, DateTime now)
    {
        RequireActiveVerified(loop);
        RequireBoundCaller(caller, loop, req);
        LoopOperation op = CurrentOperation(loop, req.OperationHandle!);
        if (op.WakesUsed >= loop.Limits.WakesPerOperation)
            throw new CustodianRefusal(ErrorCodes.LoopBudgetExhausted, $"this operation has used its idle-wake budget ({loop.Limits.WakesPerOperation})");
        if (loop.Used.Wakes >= loop.Limits.WakesPerRun)
            throw new CustodianRefusal(ErrorCodes.LoopBudgetExhausted, $"the run's idle-wake budget ({loop.Limits.WakesPerRun}) is used up");
        var claim = new WakeClaim(NewId("wc", loop.WakeClaims!.Count + 1), op.Handle, loop.Epoch, ClaimArmed, Iso(now), req.RequestId);
        LoopOperation spent = op with { WakesUsed = op.WakesUsed + 1 };
        LoopRecord next = loop with
        {
            Used = loop.Used with { Wakes = loop.Used.Wakes + 1 },
            Operations = [.. loop.Operations!.Take(loop.Operations!.Count - 1), spent],
            WakeClaims = [.. loop.WakeClaims, claim],
        };
        return LoopStep.Applied(next, new JsonObject
        {
            ["claimId"] = claim.ClaimId, ["operationHandle"] = op.Handle, ["wakesUsedOperation"] = spent.WakesUsed, ["wakesUsedRun"] = next.Used.Wakes,
        });
    }

    /// <summary>active: consumes an armed claim of the current epoch and operation, persisting the consumption
    /// before returning; that call alone returns <c>dispatchAuthorized:true</c>. At most one trusted wake
    /// authorization per claim — not proof that untrusted code dispatches once (contract §5 boundary). Only the
    /// bound session's process tree consumes; any other caller leaves the claim armed.</summary>
    private LoopStep WakeConsumeStep(LoopCaller caller, string repoKey, LoopRecord loop, LoopRequest req, DateTime now, Automation automation)
    {
        WakeClaim claim = loop.WakeClaims!.FirstOrDefault(c => c.ClaimId == req.ClaimId)
            ?? throw new CustodianRefusal(ErrorCodes.UnknownWakeClaim, "no such wake claim");
        if (claim.State != ClaimArmed)
            throw new CustodianRefusal(ErrorCodes.WakeAlreadyConsumed, "the wake claim was already consumed (one dispatch authorization per claim)");
        if (claim.Epoch != loop.Epoch)
            throw new CustodianRefusal(ErrorCodes.StaleLoopEpoch, $"the wake claim was armed in epoch {claim.Epoch}; the loop is in epoch {loop.Epoch}");
        if (loop.CurrentOperation?.Handle != claim.OperationHandle)
            throw new CustodianRefusal(ErrorCodes.UnknownOperationHandle, "the wake claim belongs to an earlier operation");
        RequireActiveVerified(loop);
        RequireBoundCaller(caller, loop, req);
        // P3.4C-5 Increment 3 (§5.2): a wake is dispatched only on the custodian's own derivation, as a continuation is.
        DerivationEntry d = RequireAutomationDerivation(repoKey, loop, req, now, automation);
        WakeClaim consumed = claim with { State = ClaimConsumed, ConsumedAt = Iso(now), ConsumeRequestId = req.RequestId };
        LoopRecord next = loop with
        {
            WakeClaims = [.. loop.WakeClaims!.Select(c => c.ClaimId == claim.ClaimId ? consumed : c)],
            Progress = new LoopProgress(d.Fingerprint, d.DerivationId, Iso(now), LoopKinds.WakeConsume),
        };
        return LoopStep.Applied(next, new JsonObject
        {
            ["dispatchAuthorized"] = true, ["claimId"] = claim.ClaimId, ["consumed"] = true, ["operationHandle"] = claim.OperationHandle,
            ["derivationId"] = d.DerivationId, ["route"] = d.RouteCode,
        });
    }

    /// <summary>active → paused. Only an active loop pauses: a paused loop keeps its reason, so no later pause
    /// can replace (and thereby downgrade) an operator-only reason.</summary>
    private static LoopStep PauseStep(LoopCaller caller, LoopRecord loop, LoopRequest req, DateTime now)
    {
        if (loop.Status != LoopStatuses.Active)
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, $"only an active loop pauses; this loop is {Describe(loop)}");
        LoopRecord next = loop with { Status = LoopStatuses.Paused, Pause = new LoopPause(req.Reason!, req.Detail ?? "", Iso(now), caller.Name) };
        return LoopStep.Applied(next, new JsonObject { ["pauseReason"] = req.Reason });
    }

    /// <summary>paused → active. An operator-only pause was already refused for a non-operator caller
    /// (<see cref="AuthorizeKind"/>).</summary>
    private static LoopStep ResumeStep(LoopRecord loop, DateTime now)
    {
        if (loop.Status != LoopStatuses.Paused || loop.Pause is null)
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, $"only a paused loop resumes; this loop is {Describe(loop)}");
        LoopRecord next = loop with { Status = LoopStatuses.Active, Pause = null, ResumedAt = Iso(now) };
        return LoopStep.Applied(next, new JsonObject { ["resumedFrom"] = loop.Pause.Reason, ["resumedAt"] = next.ResumedAt });
    }

    /// <summary>non-terminal → cancelled / run_ended: terminal and irreversible.</summary>
    private static LoopStep EndStep(LoopCaller caller, LoopRecord loop, LoopRequest req, DateTime now)
    {
        LoopRecord next = loop with { Status = req.EndStatus!, Ended = new LoopEnded(req.EndStatus!, req.Reason ?? "", Iso(now), caller.Name) };
        return LoopStep.Applied(next, new JsonObject { ["endReason"] = next.Ended!.Reason });
    }

    // ---- guards ----

    /// <summary>A resume from an operator-only pause needs the OPERATOR caller class (the elevated operator
    /// token on the operator surface, as the OS classified it); anything else is refused, fail-closed.</summary>
    private static void AuthorizeKind(LoopCaller caller, LoopRecord loop, LoopRequest req)
    {
        if (req.Kind == LoopKinds.Resume && loop.Pause is { } pause && PauseReasons.OperatorOnly.Contains(pause.Reason) && !caller.IsOperator)
            throw new CustodianRefusal(ErrorCodes.CallerNotAuthorized, $"a loop paused for {pause.Reason} resumes only on the operator surface with verified operator authority");
    }

    /// <summary>Automation (a continuation or a wake) needs an active loop whose live binding has a
    /// custodian-verified process identity.</summary>
    private static void RequireActiveVerified(LoopRecord loop)
    {
        if (loop.Status != LoopStatuses.Active)
            throw new CustodianRefusal(ErrorCodes.InvalidLoopTransition, $"the loop is {Describe(loop)}; it automates nothing");
        if (loop.Binding is not { State: LiveBinding, Process.Verified: true })
            throw new CustodianRefusal(ErrorCodes.ProcessIdentityUnverified, "the loop's binding has no custodian-verified process identity; it automates nothing");
    }

    /// <summary>
    /// TD decision on the Inc 9 escalation: an automation request must name the BOUND session and come from the
    /// bound Claude process's tree — that process still running as the instance the custodian verified (same
    /// creation time) and an ancestor of the process connected to the pipe. Checked before the request changes
    /// anything; a refusal changes nothing. Correlation (D7), not authentication: the session id is the client's
    /// claim, and a process inside that tree — or one a same-user process starts under it — passes.
    /// </summary>
    private void RequireBoundCaller(LoopCaller caller, LoopRecord loop, LoopRequest req)
    {
        LoopBinding binding = loop.Binding!;
        if (!string.Equals(binding.SessionId, req.SessionId, StringComparison.Ordinal))
            throw new CustodianRefusal(ErrorCodes.SessionNotBound, "the request names a session the loop is not bound to");
        ProcessCheckResult r = ProcessIdentityCheck.VerifyBound(binding.Process.Pid, binding.Process.StartedAtMs, caller.ClientProcessId, _processes);
        if (!r.Verified)
            throw new CustodianRefusal(ErrorCodes.ProcessIdentityUnverified, $"the request does not come from the bound session's process: {r.Detail}");
    }

    private static LoopOperation CurrentOperation(LoopRecord loop, string handle)
    {
        LoopOperation? current = loop.CurrentOperation;
        if (current is null || !string.Equals(current.Handle, handle, StringComparison.Ordinal))
            throw new CustodianRefusal(ErrorCodes.UnknownOperationHandle, "the operation handle is not the loop's current custodian-issued operation");
        return current;
    }

    private static void CheckBindNonce(BindNonce nonce, string preimage, DateTime now)
    {
        if (nonce.UsedAt is not null) throw new CustodianRefusal(ErrorCodes.BindNonceInvalid, "the binding nonce was already used");
        if (now > ParseTime(nonce.ExpiresAt)) throw new CustodianRefusal(ErrorCodes.BindNonceInvalid, "the binding nonce expired");
        byte[] presented = Encoding.ASCII.GetBytes(Digest.Sha256Hex(preimage));
        if (!CryptographicOperations.FixedTimeEquals(presented, Encoding.ASCII.GetBytes(nonce.Sha256)))
            throw new CustodianRefusal(ErrorCodes.BindNonceInvalid, "the binding nonce does not match");
    }

    private LoopProcessFacts CheckProcess(int? claimedPid, LoopCaller caller, DateTime now)
    {
        ProcessCheckResult r = ProcessIdentityCheck.Verify(claimedPid, caller.ClientProcessId, _processes);
        return new LoopProcessFacts(r.Pid, r.StartedAtMs, r.ClientPid, r.Verified, r.Detail, Iso(now));
    }

    // ---- idempotency, evidence, persistence ----

    /// <summary>A request id already applied to this loop returns its stored result, provided it is the same
    /// request (kind, fields, epoch, base revision) from the same caller class; otherwise it is a conflict. A
    /// replayed <c>wake_consume</c> reports <c>dispatchAuthorized:false</c>: it never authorizes a second
    /// dispatch (TD correction B).</summary>
    private static JsonObject? ReplayOf(LoopRecord loop, LoopCaller caller, LoopRequest req)
    {
        if (req.RequestId == loop.RequestId)
            throw new CustodianRefusal(ErrorCodes.RequestIdConflict, "this request id minted the loop");
        LoopEvent? prior = loop.Events!.FirstOrDefault(e => e.Caller != CustodianActor && e.RequestId == req.RequestId);
        if (prior is null) return null;
        if (prior.Kind != req.Kind || prior.RequestDigest != req.Digest || prior.Caller != caller.Name)
            throw new CustodianRefusal(ErrorCodes.RequestIdConflict, "this request id was already used for a different loop transition");
        var result = (JsonObject)(prior.Result?.DeepClone() ?? new JsonObject());
        if (req.Kind == LoopKinds.WakeConsume)
        {
            result["dispatchAuthorized"] = false;
            result["replayed"] = true;
        }
        return result;
    }

    /// <summary>The applied record: revision + 1 and one evidence entry carrying the full result (for replays).</summary>
    private static LoopRecord Recorded(LoopRecord next, LoopRecord before, LoopCaller caller, LoopRequest req, JsonObject stepResult, DateTime now, out JsonObject result)
    {
        int revision = before.LoopRevision + 1;
        result = new JsonObject { ["loopId"] = next.LoopId, ["kind"] = req.Kind, ["status"] = next.Status, ["epoch"] = next.Epoch, ["loopRevision"] = revision };
        foreach (KeyValuePair<string, JsonNode?> kv in stepResult) result[kv.Key] = kv.Value?.DeepClone();
        var evidence = new LoopEvent(before.Events!.Count + 1, req.Kind, req.RequestId, caller.Name, caller.ProofDigest, Iso(now),
            req.Digest, before.Status, next.Status, next.Epoch, (JsonObject)result.DeepClone());
        return next with { LoopRevision = revision, Events = [.. before.Events, evidence] };
    }

    /// <summary>A custodian-derived end (deadline or continuation budget): terminal, with its own evidence.</summary>
    private static LoopRecord DeriveEnd(LoopRecord loop, string status, string reason, DateTime now)
    {
        var evidence = new LoopEvent(loop.Events!.Count + 1, "derive", "", CustodianActor, null, Iso(now), "", loop.Status, status, loop.Epoch,
            new JsonObject { ["status"] = status, ["reason"] = reason });
        return loop with
        {
            Status = status, Ended = new LoopEnded(status, reason, Iso(now), CustodianActor),
            LoopRevision = loop.LoopRevision + 1, Events = [.. loop.Events, evidence],
        };
    }

    private static void PersistDerived(LedgerFile file, int index, LoopRecord derived)
    {
        file.Loops![index] = derived;
        Write(file);
        Audit($"loop derived {derived.Status} ({derived.Ended?.Reason}) loopId={derived.LoopId} runId={derived.RunId} rev={derived.LoopRevision}");
    }

    private static JsonObject WakeNotAuthorized(LoopRequest req, CustodianRefusal refusal, bool consumed) => new()
    {
        ["loopId"] = req.LoopId, ["kind"] = LoopKinds.WakeConsume, ["dispatchAuthorized"] = false, ["claimId"] = req.ClaimId,
        ["consumed"] = consumed, ["refusal"] = refusal.Code, ["reason"] = refusal.Message,
    };

    private bool IsClaimConsumed(string repoKey, LoopRequest req)
    {
        try
        {
            LoopRecord? loop = Read().Loops!.FirstOrDefault(l => l.RepoKey == repoKey && l.RunId == req.RunId && l.LoopId == req.LoopId);
            return loop?.WakeClaims?.Any(c => c.ClaimId == req.ClaimId && c.State == ClaimConsumed) == true;
        }
        catch (Exception e) when (e is IOException or JsonException) { return false; }
    }

    // ---- the loop section of list_user_records (contract §6) and protected-vs-attended selection (§7) ----

    /// <summary>The run's loop as the caller's surface may see it, with the loop record's OWN revision and a
    /// digest of that snapshot (never combined with the user-record log's revision). <c>protected</c> is the
    /// custodian's selection answer: a run is protected once its loop was minted, and stays protected after
    /// the loop ends.</summary>
    private JsonObject LoopSection(string repoKey, string runId, bool operatorView)
    {
        // Under the ledger lock: the two surfaces are served concurrently, and a read must not race the
        // atomic replace of a transition being written on the other surface.
        LoopRecord? found;
        lock (EnterGate()) found = Read().Loops!.FirstOrDefault(l => l.RepoKey == repoKey && l.RunId == runId);
        if (found is null)
            return new JsonObject { ["protected"] = false, ["loopRevision"] = 0, ["loopDigest"] = LoopDigest(repoKey, runId, null), ["record"] = null };
        LoopRecord loop = Normalized(found);
        return new JsonObject
        {
            ["protected"] = true,
            ["loopRevision"] = loop.LoopRevision,
            ["loopDigest"] = LoopDigest(repoKey, runId, loop),
            ["record"] = operatorView ? OperatorLoopProjection(loop) : ImplementerLoopProjection(loop),
        };
    }

    /// <summary>Identifies a loop snapshot: its identity, revision, epoch and status (not its content, so it
    /// reveals nothing the implementer projection omits).</summary>
    private static string LoopDigest(string repoKey, string runId, LoopRecord? loop) => Digest.Sha256Hex(Digest.Canonical(new JsonObject
    {
        ["repoKey"] = repoKey, ["runId"] = runId, ["loopId"] = loop?.LoopId, ["loopRevision"] = loop?.LoopRevision ?? 0,
        ["epoch"] = loop?.Epoch ?? 0, ["status"] = loop?.Status,
    }));

    /// <summary>Operator projection: the complete record — binding, session id, process facts, nonce timing
    /// and the transition history.</summary>
    private static JsonNode OperatorLoopProjection(LoopRecord loop) => JsonSerializer.SerializeToNode(loop, Json)!;

    /// <summary>Implementer projection: an INDEPENDENT allowlist, built field by field — the state, budgets,
    /// deadline, binding state and verdict, pause and end, operation handles with their wake counters and the
    /// wake claims. Never the session id, the process facts, the nonce or the history.</summary>
    private static JsonObject ImplementerLoopProjection(LoopRecord loop) => new()
    {
        ["loopId"] = loop.LoopId,
        ["status"] = loop.Status,
        ["epoch"] = loop.Epoch,
        ["loopRevision"] = loop.LoopRevision,
        ["startedAt"] = loop.StartedAt,
        ["deadlineAt"] = loop.DeadlineAt,
        ["grantId"] = loop.GrantId,
        ["grantUse"] = new JsonObject { ["loopsUsed"] = loop.GrantUse.LoopsUsed, ["loopsTotal"] = loop.GrantUse.LoopsTotal },
        ["limits"] = new JsonObject
        {
            ["continuations"] = loop.Limits.Continuations, ["wakesPerOperation"] = loop.Limits.WakesPerOperation,
            ["wakesPerRun"] = loop.Limits.WakesPerRun, ["runSeconds"] = loop.Limits.RunSeconds,
        },
        ["used"] = new JsonObject { ["continuations"] = loop.Used.Continuations, ["wakes"] = loop.Used.Wakes },
        ["remaining"] = new JsonObject
        {
            ["continuations"] = Math.Max(0, loop.Limits.Continuations - loop.Used.Continuations),
            ["wakes"] = Math.Max(0, loop.Limits.WakesPerRun - loop.Used.Wakes),
        },
        ["binding"] = loop.Binding is null ? null : BindingResult(loop.Binding),
        ["pause"] = loop.Pause is null ? null : new JsonObject { ["reason"] = loop.Pause.Reason, ["at"] = loop.Pause.At },
        ["resumedAt"] = loop.ResumedAt,
        // P3.4C-5 Increment 3 (§5.2): what the latest continuation or wake was spent on.
        ["progress"] = loop.Progress is null ? null : new JsonObject { ["fingerprint"] = loop.Progress.Fingerprint, ["derivationId"] = loop.Progress.DerivationId, ["at"] = loop.Progress.At, ["kind"] = loop.Progress.Kind },
        ["ended"] = loop.Ended is null ? null : new JsonObject { ["status"] = loop.Ended.Status, ["reason"] = loop.Ended.Reason, ["at"] = loop.Ended.At },
        ["operations"] = new JsonArray(loop.Operations!.Select(o => (JsonNode)new JsonObject
        {
            ["handle"] = o.Handle, ["seq"] = o.Seq, ["epoch"] = o.Epoch, ["wakesUsed"] = o.WakesUsed,
            ["current"] = o.Handle == loop.CurrentOperation?.Handle,
        }).ToArray()),
        ["wakeClaims"] = new JsonArray(loop.WakeClaims!.Select(c => (JsonNode)new JsonObject
        {
            ["claimId"] = c.ClaimId, ["state"] = c.State, ["epoch"] = c.Epoch, ["operationHandle"] = c.OperationHandle,
        }).ToArray()),
    };

    // ---- helpers ----

    private static LoopRecord Normalized(LoopRecord loop)
        => loop with { Operations = loop.Operations ?? [], WakeClaims = loop.WakeClaims ?? [], Events = loop.Events ?? [] };

    private static JsonObject BindingResult(LoopBinding b) => new() { ["state"] = b.State, ["verified"] = b.Process.Verified };

    private static LoopOperation NewOperation(int seq, int epoch, string issuedBy, DateTime now) => new(NewId("op", seq), seq, epoch, Iso(now), issuedBy, 0);

    /// <summary>A custodian identifier: a readable sequence plus a random suffix, so a handle or claim from
    /// one loop (or an invented one) never names another's.</summary>
    private static string NewId(string prefix, int seq) => $"{prefix}-{seq}-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6))}";

    private static string Describe(LoopRecord loop) => loop.Pause is { } p ? $"{loop.Status} ({p.Reason})" : loop.Status;

    private static string Iso(DateTime t) => t.ToString("o", CultureInfo.InvariantCulture);

    private static DateTime ParseTime(string iso) => DateTime.Parse(iso, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();
}
