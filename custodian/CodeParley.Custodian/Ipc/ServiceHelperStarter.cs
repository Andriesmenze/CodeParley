using System.ServiceProcess;

namespace CodeParley.Custodian.Ipc;

internal sealed class ServiceHelperStarter : IHelperStarter
{
    public void EnsureRunning()
    {
        try
        {
            using var sc = new ServiceController(CustodianConstants.HelperServiceName);
            ServiceControllerStatus status = sc.Status;
            if (status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending) return;
            if (status == ServiceControllerStatus.StopPending) sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            sc.Start();
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or System.ServiceProcess.TimeoutException)
        {
            string why = e.InnerException?.Message ?? e.Message;
            throw new CustodianRefusal(ErrorCodes.HelperUnavailable,
                $"the helper service {CustodianConstants.HelperServiceName} could not be started ({why}); the operator installs it, elevated, with `CodeParley.Custodian.exe install-helper`");
        }
    }
}

