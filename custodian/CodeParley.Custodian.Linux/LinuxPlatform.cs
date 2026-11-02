using CodeParley.Custodian.Linux.Ledger;
using CodeParley.Custodian.Linux.Native;
using CodeParley.Custodian.Linux.Security;

namespace CodeParley.Custodian.Linux;

/// <summary>
/// Phase 5 (contract §4.1): the Linux host's implementations of the core's seams, set once at process start. The store
/// is <c>/var/lib/codeparley</c> (created by <c>tmpfiles.d</c>, validated in full by the custodian); the engine connects
/// to the custodian itself, so the connected process is the writer (F5-2); environment variable names are case-sensitive.
/// </summary>
internal static class LinuxPlatform
{
    internal static void Configure()
    {
        Libc.EnsureSupportedArchitecture();
        Platform.Repo = new LinuxRepoIdentityResolver();
        Platform.Store = new LinuxStoreLocation();
        Platform.Durable = new LinuxDurableFiles();
        Platform.Images = new LinuxImageMeasure();
        Platform.Access = new LinuxAccessPublisher();
        // §4.12: the Codex sandbox basis (the profile path is the administrator's configuration, read at each measurement).
        Platform.Isolation = new LinuxIsolationBasis(() => LinuxConfig.Load().CodexProfile);
        Platform.Processes = new LinuxProcessTable();
        Platform.WriterIsConnectedProcess = true;
        // Contract §4.5 (D5-B): the operator is a separate account the kernel identifies (SO_PEERCRED), not an elevation.
        Platform.OperatorAssurance = "local_operator_account";
        Platform.OperatorSurfaceRequirement = "the configured operator account";
        Platform.ServiceIdentity = LinuxHostCheck.ServiceFacts;
        // The shared config corpus fixes the custodian's rule on every platform: environment names that differ only in case
        // are refused as duplicates (stricter than the engine needs on Linux; fail closed).
        Platform.CaseInsensitiveEnvironment = true;
        Platform.CurrentUser = () =>
        {
            uint uid = Libc.geteuid();
            return new Principal(uid.ToString(System.Globalization.CultureInfo.InvariantCulture), Libc.GetPasswdByUid(uid)?.Name ?? uid.ToString(System.Globalization.CultureInfo.InvariantCulture));
        };
    }

    private sealed class LinuxStoreLocation : IStoreLocation
    {
        public string Root => LinuxHostCheck.StoreRoot;
        public string SharedParent => "/var/lib";
    }
}
