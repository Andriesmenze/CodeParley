namespace CodeParley.Custodian.Security;

/// <summary>
/// The custodian store layout under ProgramData. The custodian service is the only writer; the
/// operator's processes may read (CU-4). The parent <c>C:\ProgramData\CodeParley</c> is shared with
/// the preserved broker and is NEVER silently modified here (TD amendment 4): the custodian owns only
/// its own <c>Custodian</c> subtree, created with a protected DACL and refused if it already exists.
/// </summary>
internal static class StorePaths
{
    // A test-only in-process override of the store root, set ONLY by the non-privileged self-test verbs
    // (never from an environment variable and never by the running service), so the ledger logic can be
    // exercised without the privileged ProgramData store. A relocatable store would otherwise be an
    // attack surface (TD amendment 4: untrusted environment variables), so no runtime path consults it.
    private static string? _selfTestRoot;

    /// <summary>Self-test only: redirect the store to a scratch directory for this process.</summary>
    internal static void OverrideRootForSelfTest(string root) => _selfTestRoot = root;

    /// <summary>The shared parent (also used by the broker). Validated, never rewritten without an
    /// explicit operator repair flag.</summary>
    internal static string SharedParent => _selfTestRoot is not null
        ? Path.GetDirectoryName(_selfTestRoot.TrimEnd('\\', '/'))!
        : Platform.Store.SharedParent;

    /// <summary>The custodian's own protected root. Everything the custodian writes lives below it.</summary>
    internal static string Root => _selfTestRoot ?? Platform.Store.Root;

    /// <summary>Trusted custodian configuration (operator SID, implementer SID). Custodian/Admin only.</summary>
    internal static string ConfigPath => Path.Combine(Root, "custodian-config.json");

    /// <summary>The durable grant/consumption ledger (the one protected record type of P3.4B).</summary>
    internal static string LedgerPath => Path.Combine(Root, "ledger.json");

    /// <summary>P3.4C-1: the durable protected log of user decisions and task amendments, keyed per
    /// (repository identity, run). The custodian is the sole writer; it inherits the protected DACL +
    /// High label of <see cref="Root"/>, so no new ACL or privilege is needed.</summary>
    internal static string UserRecordsPath => Path.Combine(Root, "user-records.json");

    /// <summary>P3.4C-1 confidentiality correction: the custodian's HMAC secret for protected amendment
    /// content-equivalence keys. Generated once with a CSPRNG, custodian-store-only (inherits Root's
    /// protected DACL), never served/logged, and never regenerated while records depend on it.</summary>
    internal static string ContentKeySecretPath => Path.Combine(Root, "content-key.secret");

    /// <summary>P3.4C-4: the custodian-held trusted configuration (repository configuration records, isolation
    /// acceptances, self-test confirmations). Written only through the operator's prepare→commit path; it inherits the
    /// protected DACL and High label of <see cref="Root"/>.</summary>
    internal static string ConfigRecordsPath => Path.Combine(Root, "config-records.json");

    /// <summary>In-flight two-phase authorization intents (prepare → commit), for crash recovery.</summary>
    internal static string IntentsDir => Path.Combine(Root, "intents");

    /// <summary>P3.4C-3: the protected run records, one file per run: <c>runs\&lt;repoKey&gt;\&lt;runId&gt;.json</c>.
    /// Created by the service below <see cref="Root"/>, so they inherit its custodian-only DACL and High label.</summary>
    internal static string RunsDir => Path.Combine(Root, "runs");

    /// <summary>The file of one run. Both components are validated tokens (the custodian's own repository key and
    /// the run id), so neither can name a path outside <see cref="RunsDir"/>.</summary>
    internal static string RunPath(string repoKey, string runId)
    {
        if (!IsToken(repoKey, 200) || !IsToken(runId, 128)) throw new ArgumentException("the run's repository key and run id must be safe tokens");
        return Path.Combine(RunsDir, repoKey, runId + ".json");
    }

    /// <summary>Phase 4 Increment 2: the content of delegated-fix proposals the custodian validated and holds, one file per fix
    /// operation: <c>fix-proposals\&lt;repoKey&gt;\&lt;runId&gt;\&lt;operationId&gt;.json</c>. Below <see cref="Root"/> (custodian-only DACL),
    /// beside — not inside — <see cref="RunsDir"/>, whose every file is a run record.</summary>
    internal static string FixProposalsDir => Path.Combine(Root, "fix-proposals");

    internal static string FixProposalPath(string repoKey, string runId, string operationId)
    {
        if (!IsToken(repoKey, 200) || !IsToken(runId, 128) || !IsToken(operationId, 64)) throw new ArgumentException("a proposal's repository key, run id and operation id must be safe tokens");
        return Path.Combine(FixProposalsDir, repoKey, runId, operationId + ".json");
    }

    /// <summary>Phase 5 F-i2-5: the redaction evidence of protected runs: the capture and disclosure records their withheld
    /// names come from, content-addressed under evidence/repoKey/runId/(first 32 hex of the SHA-256) (GrantLedger.Evidence.cs).
    /// The content is checked against the full digest at every read; the short name keeps the path within Windows' MAX_PATH
    /// below a deep store root.</summary>
    internal static string RedactionEvidenceDir => Path.Combine(Root, "evidence");

    internal static string RedactionEvidencePath(string repoKey, string runId, string sha256)
    {
        if (!IsToken(repoKey, 200) || !IsToken(runId, 128) || sha256.Length != 64 || !sha256.All(char.IsAsciiHexDigitLower)) throw new ArgumentException("evidence's repository key, run id and digest must be safe tokens");
        return Path.Combine(RedactionEvidenceDir, repoKey, runId, sha256[..32]);
    }

    /// <summary>P3.4C-3 (§2.4): the protected session marker — the OS boot the custodian last completed recovery in
    /// (or first started in), and a diagnostic clean-stop flag.</summary>
    internal static string SessionPath => Path.Combine(Root, "session.json");

    /// <summary>P3.4C-3 (§2.4): the recovery marker — a pending recovery (its id and boot) until it completes.</summary>
    internal static string RecoveryPath => Path.Combine(Root, "recovery.json");

    private static bool IsToken(string s, int max)
        => s.Length >= 1 && s.Length <= max && s is not ("." or "..") && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>P3.4C-5 (§3.2, Amendment A): the root under which the custodian stages and publishes measurement output — one
    /// directory per ticket, each with its own DACL. Inside the custodian's own tree (the shared parent is never modified);
    /// created by <c>install-helper</c> with a protected DACL (SYSTEM, Administrators, the custodian).</summary>
    internal static string ExportsRoot => Path.Combine(Root, "exports");

    /// <summary>Append-only audit of every operator action (caller class, assurance, proof digest).</summary>
    internal static string AuditPath => Path.Combine(Root, "audit.log");

    /// <summary>A private operator record used by the capture-helper probe to show it is denied
    /// custodian-only data (it must NOT be readable by the restricted reader).</summary>
    internal static string PrivateProbe => Path.Combine(Root, "operator-private.probe");
}
