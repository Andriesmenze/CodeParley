using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// TEST-ONLY (P3.4C-5 Increment 1 VM gate, §A.8 N5-19): run AS THE REAL HELPER SERVICE ACCOUNT (the VM driver points the
/// CodeParleyHelper service at this verb for one start and restores it), against the installed custodian:
/// <list type="bullet">
/// <item>the helper authenticates the real custodian's helper pipe (owner + access list);</item>
/// <item>with the helper's own SID, an authority-operation frame, an implementer-protocol request line and a first frame
/// that is not a hello are each refused (the custodian audits them);</item>
/// <item>the helper's token opens neither the implementer nor the operator pipe.</item>
/// </list>
/// It writes nothing to disk: the report goes over the controller's test result pipe (as in the Option-B gate).
///
///   self-test-helper-negatives --detach --pipe &lt;controller result pipe&gt;
/// </summary>
internal static class HelperNegativesSelfTest
{
    internal static int Run(string[] args)
    {
        if (args.Contains("--detach"))
        {
            var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            foreach (string a in args) if (a != "--detach") psi.ArgumentList.Add(a);
            System.Diagnostics.Process.Start(psi);
            return 0;
        }
        string? resultPipe = null;
        for (int i = 0; i < args.Length - 1; i++) if (args[i] == "--pipe") resultPipe = args[i + 1];
        if (resultPipe is null) { Console.Error.WriteLine("self-test-helper-negatives requires --pipe <controller result pipe>"); return 2; }

        var id = WindowsIdentity.GetCurrent();
        var report = new JsonObject { ["verb"] = "self-test-helper-negatives", ["caller"] = id.Name, ["callerSid"] = id.User?.Value, ["at"] = DateTime.UtcNow.ToString("o") };
        var results = new JsonObject();
        try
        {
            using (NamedPipeClientStream c = HelperChannelSelfTest.HelperClient.Connect())
                results["serverAuthentication"] = HelperAgent.ServerProblem(c, ServiceSid.Custodian()) ?? "authenticated: owned by the custodian service SID, no foreign create/re-permission rights";
            results["authorityFrame"] = Describe(HelperChannelSelfTest.HelperClient.Exchange(new JsonObject { ["t"] = "hello", ["v"] = 1, ["op"] = "spend_continuation" }));
            string line = new JsonObject { ["v"] = 1, ["requestId"] = "neg-1", ["op"] = "decide", ["args"] = new JsonObject() }.ToJsonString() + "\n";
            results["implementerProtocolLine"] = Describe(HelperChannelSelfTest.HelperClient.Raw(Encoding.UTF8.GetBytes(line)));
            results["nonHelloFirstFrame"] = Describe(HelperChannelSelfTest.HelperClient.Exchange(new JsonObject { ["t"] = "result", ["v"] = 1 }));
            results["implementerPipe"] = OpenPipe(CustodianConstants.ImplementerPipe);
            results["operatorPipe"] = OpenPipe(CustodianConstants.OperatorPipe);
        }
        catch (Exception e) { report["error"] = $"{e.GetType().Name}: {e.Message}"; }
        report["results"] = results;
        byte[] bytes = Encoding.UTF8.GetBytes(report.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        using var client = new NamedPipeClientStream(".", resultPipe, PipeDirection.Out);
        client.Connect(15000);
        client.Write(bytes, 0, bytes.Length);
        return 0;
    }

    private static string Describe(JsonObject? reply)
        => reply is null ? "no reply (the custodian closed the channel)" : $"{(string?)reply["t"]}: {(string?)reply["code"]} {(string?)reply["detail"]}";

    private static string OpenPipe(string name)
    {
        try
        {
            using var c = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Identification);
            c.Connect(3000);
            return "OPENED (unexpected)";
        }
        catch (UnauthorizedAccessException e) { return "denied: " + e.Message; }
        catch (Exception e) { return $"not opened: {e.GetType().Name}: {e.Message}"; }
    }
}
