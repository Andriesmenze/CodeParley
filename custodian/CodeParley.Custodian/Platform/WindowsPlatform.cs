using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Platforms;

/// <summary>
/// Phase 5 (contract §4.1): the Windows host's implementations of the core's seams — exactly the code that ran inside
/// the single Windows custodian before the core/host split (moved, not rewritten). Configured once, first thing in
/// <c>Program</c>, for every verb and the service.
/// </summary>
internal static class WindowsPlatform
{
    internal static void Configure()
    {
        CodeParley.Custodian.Platform.Repo = new WindowsRepoIdentityResolver();
        CodeParley.Custodian.Platform.Store = new WindowsStoreLocation();
        CodeParley.Custodian.Platform.Durable = new WindowsDurableFiles();
        CodeParley.Custodian.Platform.Images = new WindowsImageMeasure();
        CodeParley.Custodian.Platform.Access = new WindowsAccessPublisher();
        CodeParley.Custodian.Platform.Isolation = new NoIsolationBasis();
        CodeParley.Custodian.Platform.Processes = new OsProcessTable();
        CodeParley.Custodian.Platform.WriterIsConnectedProcess = false; // the engine connects through a short-lived helper
        CodeParley.Custodian.Platform.ServiceIdentity = HostCheck.ServiceTokenFacts;
        CodeParley.Custodian.Platform.CaseInsensitiveEnvironment = true;
        CodeParley.Custodian.Platform.CurrentUser = () => new Principal(System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value, System.Security.Principal.WindowsIdentity.GetCurrent().Name);
    }

    /// <summary>The store under ProgramData (P3.4B): <c>C:\ProgramData\CodeParley\Custodian</c>, its parent shared with the
    /// preserved broker and never modified here.</summary>
    private sealed class WindowsStoreLocation : IStoreLocation
    {
        public string SharedParent => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CodeParley");
        public string Root => Path.Combine(SharedParent, "Custodian");
    }
}
