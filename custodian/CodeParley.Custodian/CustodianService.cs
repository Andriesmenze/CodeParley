using System.Security.Principal;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeParley.Custodian;

/// <summary>
/// The hosted custodian service. It fails closed: without a provisioned config it opens no pipe, and a
/// store that does not validate (missing, reparse point, broadening write) leaves the service unhealthy
/// and serving nothing. Otherwise it classifies and serves the two pipe surfaces.
/// </summary>
internal sealed class CustodianService : BackgroundService
{
    private readonly ILogger<CustodianService> _log;
    private StoreLock? _storeLock;

    public override void Dispose()
    {
        _storeLock?.Dispose();
        base.Dispose();
    }
    public CustodianService(ILogger<CustodianService> log) => _log = log;

    private static Principal? Pr(SecurityIdentifier? sid) => sid is null ? null : new Principal(sid.Value, sid.Value);

    /// <summary>P3.4C-5 Increment 4 (N5-8): the group the helper reads repositories through (created by install-helper); a
    /// missing group is attached as the null SID with the reinstall remedy, so every protected measurement is refused with
    /// an actionable message (unchanged; Phase 5 moved it from the core's constructor to this Windows host).</summary>
    private static (Principal, string?) RepositoryReaders()
    {
        try
        {
            var sid = (SecurityIdentifier)new NTAccount(CustodianConstants.RepositoryReadersGroup).Translate(typeof(SecurityIdentifier));
            return (new Principal(sid.Value, sid.Value), null);
        }
        catch (IdentityNotMappedException)
        {
            var nul = new SecurityIdentifier(WellKnownSidType.NullSid, null);
            return (new Principal(nul.Value, nul.Value), CustodianConstants.RepositoryReadersGroup + " (missing: reinstall the helper with `CodeParley.Custodian.exe install-helper --reinstall`)");
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("CodeParley Custodian starting");

        // P3.4C-1: startup self-validation of the Unicode globalization backend. Protected amendment
        // content keys depend on reproducing the engine's normalization exactly; detect an incompatible
        // backend (invariant mode / NLS fallback) early. Protected amendment operations also re-check and
        // fail closed at commit, so a failure here is logged but does not stop grants/decisions.
        try
        {
            AmendmentContentKey.SelfValidate();
            _log.LogInformation("Unicode globalization self-validation passed (content-key normalization; data version {Version})", AmendmentContentKey.GlobalizationVersion);
        }
        catch (Exception e)
        {
            _log.LogError(e, "Unicode globalization self-validation FAILED; protected amendment operations will fail closed");
        }

        CustodianConfig cfg;
        try { cfg = CustodianConfig.Load(); }
        catch (Exception e) { _log.LogError(e, "not provisioned; no pipe will be opened (fail closed)"); return; }

        List<string> storeProblems = SecureStore.ValidateStore();
        if (storeProblems.Count > 0)
        {
            _log.LogError("custodian store did not validate ({Problems}); serving nothing (fail closed)", string.Join("; ", storeProblems));
            return;
        }

        string custodianId;
        try { custodianId = WindowsIdentity.GetCurrent().User?.Value ?? ServiceSid.Custodian().Value; }
        catch { custodianId = ServiceSid.Custodian().Value; }

        // P3.4C-5 (§A.2): with a helper installed, the helper surface and its broker (a fresh instance id per start).
        HelperBroker? broker = cfg.HelperSid is null ? null : new HelperBroker(new ServiceHelperStarter());
        CustodianCore core;
        try
        {
            // P3.4C-3 (§2.4): temporaries an interrupted write left are never live versions; then the recovery a new boot
            // (or a pending recovery) requires completes BEFORE any pipe is opened. If it cannot complete, nothing is
            // served (fail closed): the operator repairs or reinstalls.
            // Phase 6 L-2: the store is this process's until it exits (a store upgrade cannot run meanwhile).
            _storeLock = StoreLock.Acquire("custodian service");
            int swept = DurableStore.SweepTemporaries(StorePaths.Root);
            if (swept > 0) _log.LogInformation("swept {Count} temporary store file(s) of interrupted writes", swept);
            // Phase 6 L-1: the store's format before any state is accepted (an older store waits for `upgrade`).
            StoreFormat.RequireServable();
            core = new CustodianCore(custodianId, broker, Pr(cfg.HelperSecurityIdentifier()), Pr(cfg.ImplementerSecurityIdentifier()), broker is null ? null : RepositoryReaders());
            // Phase 6 L-5: the installer's restore marker (administrator-written, beside the store), validated or fail closed.
            RestoreMarker? restore = WindowsRestoreMarker.Read();
            RecoveryOutcome recovery = core.StartupRecovery(new KernelBootIdentity(), restore);
            if (recovery.Reason.Contains(GrantLedger.RestoredPrefix, StringComparison.Ordinal))
                _log.LogWarning("restored epoch {Id} completed before serving ({Reason}): every open protected run ended \"restored\", every unconsumed fix confirmation void, grants suspended, configuration lapsed, intents void", recovery.RecoveryId, recovery.Reason);
            else if (recovery.Recovered)
                _log.LogWarning("recovery {Id} completed before serving ({Reason}): live loops paused for the operator, grants suspended (a new operator grant is needed), a new evidence epoch for open runs, earlier waivers and deferrals lapse until re-confirmed, pending intents void", recovery.RecoveryId, recovery.Reason);
            else
                _log.LogInformation("no recovery needed ({Reason})", recovery.Reason);
        }
        catch (Exception e)
        {
            _log.LogError(e, "the custodian could not complete its startup recovery; serving nothing (fail closed)");
            return;
        }

        try
        {
            if (broker is not null) _log.LogInformation("helper channel enabled for {Helper}; service instance {Instance}", CustodianConstants.HelperVirtualAccount, broker.InstanceId);
            var pipe = new PipeServer(core, _log, cfg, broker);
            await pipe.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch (Exception e) { _log.LogError(e, "custodian service faulted"); }
        try { core.MarkCleanStop(); } catch (Exception e) { _log.LogWarning(e, "the clean-stop diagnostic could not be recorded"); }

        _log.LogInformation("CodeParley Custodian stopping");
    }
}
