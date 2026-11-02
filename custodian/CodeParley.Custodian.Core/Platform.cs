using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian;

/// <summary>
/// Phase 5 (contract §4.1): the host seams of the portable custodian core. The core — the protocol, the dispatcher, the
/// ledgers, the records, the digests, the recovery algorithm and the corpora — is the same code on every platform; each
/// host (<c>CodeParley.Custodian</c> on Windows, <c>CodeParley.Custodian.Linux</c>) sets these once at process start,
/// before any ledger is constructed. An unset seam throws: nothing falls back to another platform's behaviour or to a
/// weaker check (fail closed).
/// </summary>
internal static class Platform
{
    private static IRepoIdentityResolver? _repo;
    private static IStoreLocation? _store;
    private static IDurableFiles? _durable;
    private static IImageMeasure? _images;
    private static IAccessPublisher? _access;
    private static IProcessTable? _processes;
    private static Func<JsonObject>? _serviceIdentity;
    private static IIsolationBasis? _isolation;

    private static InvalidOperationException Unset(string what) => new($"the custodian host did not configure its {what} (no fallback)");

    /// <summary>How a repository directory is identified (Windows: the no-follow walk + FILE_ID_INFO; Linux: openat2 +
    /// fstatfs + name_to_handle_at + statx birth time).</summary>
    internal static IRepoIdentityResolver Repo { get => _repo ?? throw Unset("repository identity"); set => _repo = value; }

    /// <summary>Where the production store lives (Windows: ProgramData\CodeParley\Custodian; Linux: /var/lib/codeparley).</summary>
    internal static IStoreLocation Store { get => _store ?? throw Unset("store location"); set => _store = value; }

    /// <summary>The platform half of a durable replacement (Windows: MoveFileExW WRITE_THROUGH; Linux: rename + fsync of
    /// the directory).</summary>
    internal static IDurableFiles Durable { get => _durable ?? throw Unset("durable file operations"); set => _durable = value; }

    /// <summary>Measurement of the approved executables (Codex, the engine runtime).</summary>
    internal static IImageMeasure Images { get => _images ?? throw Unset("executable measurement"); set => _images = value; }

    /// <summary>Phase 5 (contract §4.9, §4.12): the host sandbox basis an S1 or FIX self-test confirmation binds besides the
    /// engine's record (Linux: Codex's bundled bwrap, the AppArmor profile, the user-namespace restriction, the boot);
    /// Windows binds none.</summary>
    internal static IIsolationBasis Isolation { get => _isolation ?? throw Unset("isolation basis"); set => _isolation = value; }

    /// <summary>Access control of export directories and repository-readers checks (helper channel).</summary>
    internal static IAccessPublisher Access { get => _access ?? throw Unset("access publisher"); set => _access = value; }

    /// <summary>The OS process table a ledger reads when none is injected (self-tests inject fixed tables).</summary>
    internal static IProcessTable Processes { get => _processes ?? throw Unset("process table"); set => _processes = value; }

    /// <summary>Who sent a request, relative to the process connected to the endpoint (F5-2): on Windows the engine sends
    /// each request through a short-lived helper, so the writer is the connected process's PARENT; on Linux the engine
    /// connects itself, so the writer is the connected process. Default: the Windows topology.</summary>
    internal static bool WriterIsConnectedProcess { get; set; }

    /// <summary>The operator-only <c>service_identity</c> diagnostic (the service's own token facts and write probes).</summary>
    internal static Func<JsonObject> ServiceIdentity { get => _serviceIdentity ?? throw Unset("service identity diagnostic"); set => _serviceIdentity = value; }

    /// <summary>Environment variable names compare case-insensitively (Windows) or exactly (Linux) — the engine's rule.</summary>
    internal static bool CaseInsensitiveEnvironment { get; set; } = true;

    /// <summary>The assurance an operator-committed record carries (its provenance label): what this host's operator
    /// classification establishes. Windows: <c>local_admin_elevation</c> (an elevated token of the operator SID). Linux
    /// (contract §4.5, D5-B): <c>local_operator_account</c> (the separate operator uid, by SO_PEERCRED).</summary>
    internal static string OperatorAssurance { get; set; } = "local_admin_elevation";

    /// <summary>How a refusal names what the operator surface requires, in this host's terms.</summary>
    internal static string OperatorSurfaceRequirement { get; set; } = "an elevated operator token";

    private static Func<Principal>? _currentUser;

    /// <summary>The principal this process runs as (Windows: its user SID; Linux: its uid) — the self-test fixtures' helper
    /// and reader.</summary>
    internal static Func<Principal> CurrentUser { get => _currentUser ?? throw Unset("current user"); set => _currentUser = value; }
}

/// <summary>Repository identity (the scheme prefix of every key this host derives, and the resolution).</summary>
internal interface IRepoIdentityResolver
{
    string Scheme { get; }
    RepoIdentity Resolve(string repositoryRoot);
}

/// <summary>The production store root and its shared parent (the self-test override is <see cref="StorePaths"/>'s).</summary>
internal interface IStoreLocation
{
    string Root { get; }
    string SharedParent { get; }
}

/// <summary>The platform steps of <see cref="DurableStore.Replace"/>: replace <c>path</c> with the flushed temporary file
/// <c>tmp</c> atomically, then make the replacement itself durable. Throws <see cref="IOException"/> when it cannot (the
/// temporary file is removed then). <paramref name="afterReplace"/> is the self-test fault hook between the steps.</summary>
internal interface IDurableFiles
{
    void ReplaceWith(string tmp, string path, Action afterReplace);

    /// <summary>Create <paramref name="path"/> with <paramref name="content"/> only if it does not exist (a private,
    /// never-overwritten file: the content-key secret), flushed before returning; <see cref="IOException"/> if it exists.</summary>
    void CreateNew(string path, byte[] content);
}

/// <summary>Measurement of the approved executables with the custodian's own token.</summary>
internal interface IImageMeasure
{
    string NodeName { get; }
    string GitRelative(string rel);
    MeasuredImage MeasureCodex(string path);
    /// <summary>The runtime tree with its git inside it (<paramref name="gitRelative"/>) or an installed git outside it
    /// (<paramref name="gitPath"/>, Phase 6 §7 b); exactly one is non-null.</summary>
    MeasuredRuntime MeasureRuntime(string root, string? gitRelative, string? gitPath);

    // ---- self-test support (the shared corpora's synthetic installations; never used by the service) ----

    /// <summary>The file name of a synthetic Codex image (Windows: codex.exe).</summary>
    string FixtureCodexName { get; }

    /// <summary>The runtime-relative path of a synthetic runtime's git (Windows: git/cmd/git.exe).</summary>
    string FixtureRuntimeGit { get; }

    /// <summary>A minimal native image the host's measurement accepts (Windows: a PE image), varied by <paramref name="variant"/>.</summary>
    byte[] FixtureImage(byte variant);

    /// <summary>Self-test only: measure scratch trees a non-privileged test cannot make administrator-owned.</summary>
    void SkipOwnershipChecksForSelfTest();
}

/// <summary>
/// Phase 5 (contract §4.12): the sandbox basis of an approved Codex installation, measured by the custodian with its own
/// token. Profile presence never establishes confinement — only the operator-confirmed self-test of the current boot
/// does; this measurement is what that confirmation binds and what each review and fix re-checks.
/// </summary>
internal interface IIsolationBasis
{
    /// <summary>Does this host bind a sandbox basis (a self-test confirmation must then name its Codex and boot)?</summary>
    bool Binds { get; }

    /// <summary>The basis of the Codex installation whose binary is <paramref name="codexPath"/>: every field the custodian
    /// measured (image hashes and file ids, the profile's hash, the restriction, the boot id). Throws
    /// <see cref="CustodianRefusal"/> when a precondition fails (an image or the profile not approvable, the restriction off).</summary>
    JsonObject Measure(string codexPath);
}

/// <summary>The Windows host: no host sandbox basis (the S1 record and the approved Codex image are what binds).</summary>
internal sealed class NoIsolationBasis : IIsolationBasis
{
    public bool Binds => false;
    public JsonObject Measure(string codexPath) => throw new InvalidOperationException("this host binds no sandbox basis");
}

/// <summary>An OS principal the access publisher grants or checks (Windows: a SID string; Linux: a numeric uid/gid).</summary>
internal sealed record Principal(string Id, string Display);

/// <summary>Export directory access (P3.4C-5 §3.2): create a ticket directory the helper may write, seal it (the helper's
/// access removed, the content verified to grant no one else), publish it read-only to the bound user, and check that a
/// repository grants the readers group what the helper needs.</summary>
internal interface IAccessPublisher
{
    string CreateExportDirectory(string name, Principal helper);
    bool Seal(string path, Principal helper);
    void Publish(string path, Principal reader);
    string? RepositoryReadersProblem(string root, Principal readers);
    string RepositoryReadersRemedy(string root, Principal readers);
}
