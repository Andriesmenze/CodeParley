namespace CodeParley.Broker;

/// <summary>A fixed, allowlisted deterministic workload the broker may launch (never an arbitrary
/// executable). The broker chooses the interpreter, script and arguments; the caller names only the key.</summary>
internal sealed record WorkloadDef(string Key, int DefaultTimeoutSeconds, int MaxTimeoutSeconds, bool IsProof);

/// <summary>
/// Fixed, trusted broker configuration. These are deliberately not caller-supplied: the IPC surface
/// is semantic (runId + workloadKey [+ timeout]), and every path/identity the broker acts on is derived here.
/// </summary>
internal static class BrokerConstants
{
    internal const string ServiceName = "CodeParleyBroker";
    internal const string ServiceDisplayName = "CodeParley Broker";
    internal const string PipeName = "CodeParley.Broker";
    internal const int ProtocolVersion = 1;

    /// <summary>The dedicated low-privilege worker account (SAM name); created/managed by `provision`.</summary>
    internal const string WorkerAccount = "cp-worker";

    /// <summary>LSA private-secret key holding the worker's broker-managed password (LocalSystem-only).</summary>
    internal const string LsaSecretKey = "L$CodeParley_BrokerWorker";

    /// <summary>Phase 3 single-active-worker invariant: at most one worker run may be active at a time.
    /// Cross-run isolation comes from this invariant (all runs share one worker identity), not from
    /// per-run identities. Enforced in trusted broker state under the admission lock.</summary>
    internal const int MaxConcurrentRuns = 1;

    /// <summary>Upper bound for any run's wall-clock limit (the broker kills the tree at the deadline).</summary>
    internal const int MaxTimeoutSeconds = 3600;

    /// <summary>Lower bound for a run's wall-clock limit.</summary>
    internal const int MinTimeoutSeconds = 3;

    /// <summary>After the main process exits on its own, the broker waits up to this long for the Job
    /// Object to empty (descendants finishing) before deciding `exited` vs `unclean` (force-kill).</summary>
    internal const int StopGraceSeconds = 5;

    /// <summary>Allowlisted deterministic workloads the broker may launch (never an arbitrary executable).</summary>
    internal static readonly IReadOnlyDictionary<string, WorkloadDef> Workloads =
        new Dictionary<string, WorkloadDef>(StringComparer.Ordinal)
        {
            ["proof-battery"] = new("proof-battery", DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 900, IsProof: true),
            // Deterministic lifecycle workloads (build a tree / a detached straggler) so the operator
            // proof can exercise whole-tree kill, timeout and the `unclean` straggler path.
            ["lifecycle-tree"] = new("lifecycle-tree", DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 3600, IsProof: false),
            ["lifecycle-detached"] = new("lifecycle-detached", DefaultTimeoutSeconds: 120, MaxTimeoutSeconds: 600, IsProof: false),
        };

    private static string DataHome =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CodeParley", "broker");

    /// <summary>Trusted root under which per-run workspaces are created (ProgramData; admin/SYSTEM-owned).</summary>
    internal static string TrustedWorkspaceRoot => Path.Combine(DataHome, "work");

    /// <summary>Broker-owned trusted staging area (e.g. the deterministic source repo to clone).</summary>
    internal static string TrustedStateRoot => Path.Combine(DataHome, "state");

    /// <summary>Trusted per-run records (durable registry) for status and restart recovery (`lost`).
    /// Locked SYSTEM/Administrators-only, under the trusted state root.</summary>
    internal static string RunsRoot => Path.Combine(TrustedStateRoot, "runs");

    /// <summary>Trusted broker configuration (controller SID etc.), SYSTEM/Administrators-only.</summary>
    internal static string ConfigPath => Path.Combine(TrustedStateRoot, "broker-config.json");

    /// <summary>Directory for per-run, worker-READABLE (not worker-writable) git configs that mark the
    /// exact per-run clone safe (git CVE-2022-24765 ownership check). Lives in the Users-readable broker
    /// dir, so the worker can read its run's config but cannot tamper with it.</summary>
    internal static string GitConfigDir => Path.Combine(DataHome, "git");

    /// <summary>The per-run git config path (names only the exact per-run repo as safe, never `*`).</summary>
    internal static string WorkerGitConfig(string runId) => Path.Combine(GitConfigDir, runId + ".gitconfig");
}
