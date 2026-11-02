using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 5 (§4.1): the fixtures the shared corpora (<see cref="LoopCorpusSelfTest"/>, <see cref="RunCorpusSelfTest"/>) and
/// the Windows ledger self-tests use — a fixed process table, the callers, and a run opened with the default declaration
/// — moved verbatim into the portable core so the same corpora run on every host. Values are unchanged.
/// </summary>
internal static class CorpusFixtures
{
    // A fixed process table: 100 the originating Claude process; 200 its hook; 300 the hook's pipe helper (the
    // connected client); 400 an unrelated process; 500 a "child" of 100 created BEFORE it (100 is a reused id).
    private const long Second = 10_000_000;
    private static readonly long T0 = DateTime.UtcNow.AddMinutes(-10).ToFileTimeUtc();
    internal const int Claude = 100, Helper = 300, Unrelated = 400, ReusedChild = 500;

    internal sealed class FixedTable(Dictionary<int, ProcEntry>? entries) : IProcessTable
    {
        public IReadOnlyDictionary<int, ProcEntry>? Snapshot() => entries;
    }

    /// <summary>The fixed process table (also the loop corpus's): <see cref="Claude"/> is an ancestor of
    /// <see cref="Helper"/>, the connected client; <see cref="Unrelated"/> is not.</summary>
    internal static readonly IProcessTable Table = new FixedTable(new Dictionary<int, ProcEntry>
    {
        [Claude] = new(Claude, 1, T0),
        [200] = new(200, Claude, T0 + 10 * Second),
        [Helper] = new(Helper, 200, T0 + 11 * Second),
        [Unrelated] = new(Unrelated, 1, T0 + 5 * Second),
        [ReusedChild] = new(ReusedChild, Claude, T0 - 60 * Second),
    });

    /// <summary><see cref="Table"/> after the Claude process ended: the helper's chain no longer reaches it.</summary>
    internal static readonly IProcessTable WithoutClaude = new FixedTable(new Dictionary<int, ProcEntry>
    {
        [200] = new(200, Claude, T0 + 10 * Second),
        [Helper] = new(Helper, 200, T0 + 11 * Second),
        [Unrelated] = new(Unrelated, 1, T0 + 5 * Second),
    });

    /// <summary><see cref="Table"/> with pid <see cref="Claude"/> reused by a process created 2 s later: by its parent
    /// links still an ancestor of the helper, but not the process instance the loop was bound to.</summary>
    internal static readonly IProcessTable ClaudeReused = new FixedTable(new Dictionary<int, ProcEntry>
    {
        [Claude] = new(Claude, 1, T0 + 2 * Second),
        [200] = new(200, Claude, T0 + 10 * Second),
        [Helper] = new(Helper, 200, T0 + 11 * Second),
        [Unrelated] = new(Unrelated, 1, T0 + 5 * Second),
    });

    internal static readonly LoopCaller Impl = new(false, "proof-implementer", Helper);
    /// <summary>The implementer surface reached by a process OUTSIDE the bound Claude process's tree.</summary>
    internal static readonly LoopCaller Outsider = new(false, "proof-implementer", Unrelated);
    internal static readonly LoopCaller Oper = new(true, "proof-operator", null);

    // ---- a run opened with the default declaration ----

    private const string SrcA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string SrcB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static int _seq;

    /// <summary>P3.4C-5 Increment 3: the run.json bytes the self-tests' runs are opened with (their digest is the declaration's
    /// runJsonDigest), sent with a derivation request.</summary>
    internal const string RunJsonText = "{\"schema\":\"selftest\"}";
    internal static readonly string RunJsonDigest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(RunJsonText)));
    internal static string RunJsonBase64 => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(RunJsonText));

    /// <summary>Register a run with the custodian as the engine does before it consumes a loop (P3.4C-3 §1.3): a
    /// <c>run_transition open</c> on the implementer surface with a default declaration. Shared with the P3.4C-2 loop
    /// self-tests and corpus, whose loops are now minted only for an open run.</summary>
    internal static JsonObject Open(GrantLedger led, string repo, string run)
    {
        EnsureConfig(led, repo);
        return led.RunTransition(new LoopCaller(false, "proof-implementer", null), repo, RunRequest.Parse(run, "open", OpenFields(), $"rsf-open-{Interlocked.Increment(ref _seq)}"));
    }

    /// <summary>P3.4C-4: a run is opened only under the repository's protected configuration; the fixture holds the default
    /// one (<see cref="ConfigFixture"/>) unless the repository already has a record — revoked or lapsed included, which a
    /// test set up on purpose.</summary>
    internal static void EnsureConfig(GrantLedger led, string repo)
    {
        if (GrantLedger.ReadConfigRecordsLocked().CurrentOf(RepoIdentities.Resolve(repo).Key) is not null) return;
        ConfigFixture.Hold(led, repo, Path.Combine(Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(repo)))!, "codex-fixture"));
    }

    /// <summary>The <c>open</c> fields of the default declaration.</summary>
    internal static JsonObject OpenFields() => new()
    {
        ["runJsonDigest"] = RunJsonDigest,
        ["budgets"] = new JsonObject { ["maxReviews"] = 5, ["maxCheckExecutions"] = 50 },
        ["baseline"] = new JsonObject { ["sourceId"] = SrcA, ["digest"] = SrcB },
    };
}
