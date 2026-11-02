using System.Security.Principal;
using CodeParley.Broker.Ipc;
using CodeParley.Broker.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeParley.Broker;

/// <summary>The hosted broker: owns the named-pipe IPC listener and the run registry/launcher. It
/// loads the trusted controller SID (fail closed if unprovisioned) and disposes the core on shutdown
/// so any still-active run is recorded `interrupted` and its tree is torn down.</summary>
internal sealed class BrokerService : BackgroundService
{
    private readonly ILogger<BrokerService> _log;

    public BrokerService(ILogger<BrokerService> log) => _log = log;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("CodeParley Broker starting (pipe \\\\.\\pipe\\{Pipe})", BrokerConstants.PipeName);

        SecurityIdentifier controllerSid;
        try
        {
            controllerSid = BrokerConfig.Load().ControllerSecurityIdentifier();
        }
        catch (Exception e)
        {
            // Fail closed: without a trusted controller SID we cannot authorize anyone, so we do not
            // open the pipe at all. `provision --controller <account>` must run first.
            _log.LogError(e, "broker is not provisioned with a trusted controller SID; the IPC will not be opened");
            return;
        }

        BrokerCore? core = null;
        try
        {
            core = new BrokerCore();
            var pipe = new PipeServer(core, _log, controllerSid);
            await pipe.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch (Exception e) { _log.LogError(e, "broker service faulted"); }
        finally { core?.Dispose(); }

        _log.LogInformation("CodeParley Broker stopping");
    }
}
