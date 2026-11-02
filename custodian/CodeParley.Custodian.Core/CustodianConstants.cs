namespace CodeParley.Custodian;

/// <summary>
/// Fixed, trusted custodian configuration (Phase 3.4B mechanics proof). Nothing here is
/// caller-supplied: the IPC surface is semantic, and every path and identity the custodian acts on
/// is derived here. This is a NEW component (CU-5): it copies reviewed patterns from the preserved
/// <c>broker/</c>, never shares its service name, identity, pipe or store with it.
/// </summary>
internal static class CustodianConstants
{
    /// <summary>The custodian Windows service. It runs under the VIRTUAL service account
    /// <c>NT SERVICE\CodeParleyCustodian</c> (never LocalSystem): the deterministic service SID is
    /// granted the store ACL, and the service holds no logon, impersonate or token-creation privilege.</summary>
    internal const string ServiceName = "CodeParleyCustodian";
    internal const string ServiceDisplayName = "CodeParley Custodian";

    /// <summary>The virtual service account the SCM runs the service as (no password, no profile key
    /// of its own beyond the service SID).</summary>
    internal const string VirtualAccount = @"NT SERVICE\CodeParleyCustodian";

    internal const int ProtocolVersion = 1;

    /// <summary>Two pipes, classified by the OS from the connected client's token (never request
    /// content): the implementer surface (model-reachable requests and hints) and the operator surface
    /// (protected authority actions, prepare/commit). The producer pipe of the full architecture is a
    /// later milestone and is not created here.</summary>
    internal const string ImplementerPipe = "CodeParley.Custodian.v1.implementer";
    internal const string OperatorPipe = "CodeParley.Custodian.v1.operator";

    /// <summary>P3.4C-5 Amendment A (§A.1, §A.2): the dedicated helper service and its channel. The helper runs as a second
    /// Windows service under its own VIRTUAL account (never LocalSystem, never a token derived from the custodian), with a
    /// restricted service SID and SeChangeNotifyPrivilege only. It is a CLIENT of the third pipe, which only it may open
    /// (its DACL grants the helper SID, the custodian SID and SYSTEM). The helper class is decided by the connecting
    /// token's SID alone and is served only measurement requests: it is neither the implementer nor the operator.</summary>
    internal const string HelperPipe = "CodeParley.Custodian.v1.helper";
    internal const string HelperServiceName = "CodeParleyHelper";
    internal const string HelperServiceDisplayName = "CodeParley Helper";
    internal const string HelperVirtualAccount = @"NT SERVICE\CodeParleyHelper";

    /// <summary>The local group that may read the protected repositories (contract §2.3); the helper account is its member.</summary>
    internal const string RepositoryReadersGroup = "CodeParley Repository Readers";

    /// <summary>Helper channel bounds (§A.2): a frame header, a single file body, how long the custodian waits for the
    /// helper to attach after asking for it, and the longest a request may run before it ends fail-closed.</summary>
    internal const int MaxHelperHeaderBytes = 64 * 1024;
    internal const long MaxHelperBodyBytes = 256L * 1024 * 1024;
    internal const int HelperAttachSeconds = 60;
    internal const int HelperRequestSeconds = 600;

    /// <summary>P3.4C-5 Increment 4 (§3.2 retention): a live run keeps the published exports of its latest captures only
    /// (the current review and the one before it); older ones are retired.</summary>
    internal const int MaxPublishedExportsPerRun = 2;

    /// <summary>P3.4C-5 Increment 4: a published export older than this is retired even on a live run.</summary>
    internal static readonly TimeSpan ExportRetention = TimeSpan.FromDays(7);

    /// <summary>A protected operator action's prepared authorization is valid for at most this long
    /// (the challenge/digest/nonce it carries must be committed within the window).</summary>
    internal const int AuthorizationTtlSeconds = 120;

    /// <summary>Hard cap on a single grant's loop count and lifetime (the mechanics ledger mirrors the
    /// engine's loop-grant bounds; the engine is NOT migrated here).</summary>
    internal const int MaxGrantLoops = 8;
    internal const int MaxGrantMinutes = 180;

    /// <summary>P3.4C-2: the default budgets a newly minted loop record carries. The custodian OWNS these
    /// now — a loop is minted at the default ceilings (mirrors the engine's HARD_LOOP_LIMITS in
    /// src/policy/continuation.ts; only an operator grant could ever lower them, never a client request):
    /// automated continuations per loop, idle wakes per review operation, idle wakes per run, and the
    /// wall-clock run budget in seconds (deadline = started_at + LoopRunSeconds).</summary>
    internal const int LoopContinuations = 2;
    internal const int LoopWakesPerOperation = 1;
    internal const int LoopWakesPerRun = 2;
    internal const int LoopRunSeconds = 900;

    /// <summary>A loop's one-time binding nonce is valid this long after it was minted, and is usable once
    /// (mirrors BIND_NONCE_TTL_MS in src/policy/continuation.ts).</summary>
    internal const int BindNonceTtlSeconds = 60;

    /// <summary>P3.4C-2: a loop keeps at most this many transition-evidence entries. A legitimate loop (one
    /// bind, two continuations, a few wakes, pauses and re-binds within its 15-minute window) stays far below
    /// it; beyond it only <c>end</c> is accepted, so a client cycling transitions cannot grow the store.</summary>
    internal const int MaxLoopEvents = 128;

    /// <summary>P3.4C-1 protected user-record log bounds (mirrors the engine's USER_LIMITS so the custodian
    /// enforces the same ceilings authoritatively). A record's payload is bounded by the request framing;
    /// these cap the per-run log and the two text fields the payload may carry.</summary>
    internal const int MaxUserRecordsPerRun = 600;      // decisions (500) + amendments (50) + headroom
    internal const int MaxDecisionNoteChars = 2000;     // USER_LIMITS.noteChars
    internal const int MaxAmendmentTextChars = 4000;    // USER_LIMITS.amendmentChars

    /// <summary>P3.4C-3 run-record caps (contract §2.3), enforced by the custodian (BUDGET_EXHAUSTED, the limit
    /// named). The review and check-execution maxima are the engine's hard caps (HARD_MAX_REVIEWS_PER_RUN,
    /// HARD_MAX_EXECUTIONS_PER_RUN); a run's declared budget can only lower them. The response limits mirror
    /// RESPONSE_LIMITS; the others bound the store.</summary>
    internal const int MaxReviewsPerRun = 20;
    internal const int MaxCheckExecutionsPerRun = 100;   // non-skipped executions
    internal const int MaxAllExecutionsPerRun = 200;     // including skipped ones
    internal const int MaxResponsesPerCall = 50;
    internal const int MaxResponsesPerItem = 20;
    internal const int MaxResponsesPerRun = 1000;
    internal const int MaxNewItemsPerReview = 100;
    internal const int MaxItemsPerRun = 500;
    internal const int MaxRepliesPerRun = 1000;
    internal const int MaxIncidentsPerRun = 200;
    internal const int MaxRunEvents = 1024;              // when full, only `end` is accepted
    internal const int MaxImplementerProjectionBytes = 3 * 1024 * 1024;

    /// <summary>Phase 4 Increment 2 (contract §3.2, §3.4): the delegated-fix caps. A run's declared <c>maxFixes</c> can only
    /// lower <see cref="MaxFixesPerRun"/>; a boundary is validated within the others. The content caps keep a submitted
    /// proposal (base64) inside <see cref="MaxRequestBytes"/>.</summary>
    internal const int MaxFixesPerRun = 10;
    internal const int MaxFixPermittedFiles = 50;
    internal const int MaxFixPermittedDirs = 20;
    internal const int MaxFixChangedFiles = 50;
    internal const int MaxFixFileBytes = 256 * 1024;
    internal const int MaxFixTotalBytes = 512 * 1024;
    internal const int MinFixTimeLimitSeconds = 30, MaxFixTimeLimitSeconds = 3600;
    internal const int MinFixLifetimeSeconds = 60, MaxFixLifetimeSeconds = 7 * 24 * 3600;
    internal const int MaxFixViolationsReported = 20;
    internal const int MaxFixPathChars = 1024;
    /// <summary>Phase 4 Increment 3 (§3.5): how long an owner's confirmation can be used (never past its proposal's lifetime).</summary>
    internal const int FixConfirmationTtlSeconds = 30 * 60;

    /// <summary>Request/response framing bounds (strict, like the MCP input schemas).</summary>
    internal const int MaxRequestBytes = 1 * 1024 * 1024;
    internal const int MaxResponseBytes = 4 * 1024 * 1024;
}
