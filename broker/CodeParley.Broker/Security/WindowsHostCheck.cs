using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using CodeParley.Broker.Launch;

namespace CodeParley.Broker.Security;

/// <summary>
/// Live verification of the host properties the worker boundary depends on (the Windows parallel of
/// the Linux broker's HostCheck). Every fact is measured on the request; any problem makes the host
/// unverified and a launch is refused (fail closed, invariant #8). The same object is the
/// Capabilities report. Measured facts are distinguished from assertions.
/// </summary>
internal static class WindowsHostCheck
{
    private static readonly string[] BroadeningSids = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"]; // Everyone, AuthUsers, Users

    internal sealed record Report(JsonObject Facts, List<string> Problems)
    {
        internal bool Verified => Problems.Count == 0;
    }

    internal static Report Verify()
    {
        var problems = new List<string>();
        var f = new JsonObject
        {
            ["platform"] = "windows",
            ["architecture"] = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            ["osVersion"] = Environment.OSVersion.VersionString,
        };

        // The broker must run as LocalSystem (the privileged host identity).
        var ident = new JsonObject();
        try
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            ident["account"] = me.Name;
            ident["sid"] = me.User?.Value;
            bool isSystem = me.User?.Value == "S-1-5-18";
            ident["isLocalSystem"] = isSystem;
            if (!isSystem) problems.Add($"broker is not running as LocalSystem (is {me.Name}); the service host must be LocalSystem");
        }
        catch (Exception e) { problems.Add("identity: " + e.Message); }
        f["brokerIdentity"] = ident;

        // Trusted controller configuration (hardening 4A): a specific controller SID, not a group.
        var ipc = new JsonObject { ["transport"] = "named pipe \\\\.\\pipe\\" + BrokerConstants.PipeName, ["peerAuthentication"] = "exact controller SID (pipe ACL + impersonated client SID), never 'any administrator'" };
        try
        {
            BrokerConfig cfg = BrokerConfig.Load();
            ipc["controllerSid"] = cfg.ControllerSid;
            ipc["controllerAccount"] = cfg.ControllerAccount;
        }
        catch (Exception e) { problems.Add("controller config: " + e.Message); }
        f["ipc"] = ipc;

        // Worker identity provisioned (account + LSA secret).
        var wi = new JsonObject { ["account"] = BrokerConstants.WorkerAccount };
        try
        {
            bool exists = WorkerCredential.AccountExists();
            wi["provisioned"] = exists;
            if (!exists) problems.Add($"worker account '{BrokerConstants.WorkerAccount}' is not provisioned");
            if (exists)
            {
                string sid = ((SecurityIdentifier)new NTAccount(BrokerConstants.WorkerAccount).Translate(typeof(SecurityIdentifier))).Value;
                wi["sid"] = sid;
            }
        }
        catch (Exception e) { problems.Add("worker identity: " + e.Message); }
        f["workerIdentity"] = wi;

        // Trusted tools: exist, admin/SYSTEM-owned, not writable by Everyone/Users/AuthUsers.
        var tools = new JsonObject();
        foreach ((string name, string path) in new[] { ("node", HostTools.NodeExe), ("git", HostTools.GitExe) })
        {
            try { VerifyTrustedPath(path, isDir: false); tools[name] = path; }
            catch (Exception e) { problems.Add($"untrusted or missing {name} ({path}): {e.Message}"); }
        }
        f["toolchain"] = tools;

        // Trusted roots: exist and are locked to SYSTEM/Administrators (no broadening write).
        var fs = new JsonObject();
        foreach ((string name, string path) in new[]
                 {
                     ("workspaceRoot", BrokerConstants.TrustedWorkspaceRoot),
                     ("stateRoot", BrokerConstants.TrustedStateRoot),
                     ("runsRoot", BrokerConstants.RunsRoot),
                 })
        {
            try { VerifyTrustedPath(path, isDir: true); fs[name] = path + " (locked)"; }
            catch (Exception e) { problems.Add($"trusted root {name} ({path}): {e.Message}"); }
        }
        f["filesystem"] = fs;

        f["workerToken"] = new JsonObject
        {
            ["model"] = "WRITE_RESTRICTED (unchanged from Phase 3.1A)",
            ["restrictingSids"] = "worker account SID + per-launch logon SID + Everyone + WRITE RESTRICTED",
            ["ambientWriteRemoval"] = "AuthUsers/Users/world are not restricting SIDs, so ambient group writes are denied",
        };
        f["lifetimeBoundary"] = new JsonObject
        {
            ["owner"] = "Job Object (kill-on-close, no breakaway)",
            ["timeout"] = "broker-enforced wall-clock timer (RuntimeMaxSec equivalent)",
            ["terminalStates"] = new JsonArray("exited", "timed_out", "terminated", "interrupted", "unclean", "failed", "lost"),
        };
        f["concurrency"] = new JsonObject
        {
            ["model"] = "single active worker (Phase 3): a launch is rejected while any run is active",
            ["enforcedIn"] = "trusted broker state (live Job Object membership / process-exit), under the admission lock — not controller scheduling",
            ["crossRunIsolation"] = "all runs share one worker identity; single-active replaces per-run identities",
            ["staleStateRecovery"] = "on broker restart the kill-on-close Job Objects are gone; durable records reconcile to `lost` and stale workspaces are removed before the next launch",
        };
        f["limits"] = new JsonObject { ["maxConcurrentRuns"] = BrokerConstants.MaxConcurrentRuns, ["maxTimeoutSeconds"] = BrokerConstants.MaxTimeoutSeconds };

        f["verified"] = problems.Count == 0;
        f["problems"] = new JsonArray(problems.Select(p => (JsonNode?)p).ToArray());
        return new Report(f, problems);
    }

    /// <summary>A trusted path exists, is owned by SYSTEM/Administrators/TrustedInstaller, and grants no
    /// write/modify/full control to Everyone, Authenticated Users or Users.</summary>
    private static void VerifyTrustedPath(string path, bool isDir)
    {
        if (isDir ? !Directory.Exists(path) : !File.Exists(path))
            throw new InvalidOperationException("does not exist");

        FileSystemSecurity sec = isDir
            ? new DirectorySecurity(path, AccessControlSections.Access | AccessControlSections.Owner)
            : new FileSecurity(path, AccessControlSections.Access | AccessControlSections.Owner);

        var owner = (SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier));
        string[] trustedOwners = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]; // SYSTEM, Administrators, TrustedInstaller
        if (owner is null || !trustedOwners.Contains(owner.Value))
            throw new InvalidOperationException($"owner is {owner?.Value ?? "unknown"} (not SYSTEM/Administrators/TrustedInstaller)");

        // Only genuine write/modify bits count: composite rights like Modify/FullControl share
        // read/execute bits with ReadAndExecute, so masking against them would flag a read-only ACE.
        const FileSystemRights WriteBits =
            FileSystemRights.WriteData | FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        const int GenericWriteOrAll = unchecked((int)0x40000000) | 0x10000000; // GENERIC_WRITE | GENERIC_ALL
        foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            string sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            bool writeLike = (rule.FileSystemRights & WriteBits) != 0 || ((int)rule.FileSystemRights & GenericWriteOrAll) != 0;
            if (writeLike && BroadeningSids.Contains(sid))
                throw new InvalidOperationException($"grants write to a broadening principal ({sid})");
        }
    }
}
