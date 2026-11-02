namespace CodeParley.Broker.Launch;

/// <summary>
/// The host-execution outcome the broker reports, parity with the Linux broker's vocabulary
/// (`exited`/`timed_out`/`terminated`/`interrupted`/`unclean`/`failed`/`lost`, plus the non-terminal
/// states). No host-execution state — not even <see cref="Exited"/> with code 0 — is a task-level
/// PASS, `ready`, or user authorization; see HOST-CONTRACT.md.
/// </summary>
internal static class RunState
{
    internal const string None = "none";
    internal const string Starting = "starting";
    internal const string Running = "running";
    internal const string Stopping = "stopping";
    internal const string Exited = "exited";
    internal const string TimedOut = "timed_out";
    internal const string Terminated = "terminated";
    internal const string Interrupted = "interrupted";
    internal const string Unclean = "unclean";
    internal const string Failed = "failed";
    internal const string Lost = "lost";

    internal static bool IsTerminal(string s) =>
        s is Exited or TimedOut or Terminated or Interrupted or Unclean or Failed or Lost;
}

/// <summary>
/// The trusted facts the broker gathers from its own records and from the OS (process-exit state and
/// Job Object membership) — never from anything the worker wrote. A pure classifier turns them into a
/// terminal state with a deterministic precedence, so the mapping can be verified without elevation.
/// </summary>
internal readonly record struct TerminalFacts(
    bool LaunchFailed,
    bool Lost,
    bool TerminateRequested,
    bool TimedOut,
    bool StoppedExternally,
    bool DescendantsRemained,
    int? ExitCode);

internal readonly record struct TerminalVerdict(string State, int? ExitCode, string Note);

internal static class TerminalClassifier
{
    /// <summary>
    /// Precedence (highest first), using only Windows-reliable evidence:
    ///   failed (launch/unexpected) → lost (host restart, no recorded outcome) →
    ///   terminated (broker asked, whole job killed) → timed_out (broker wall-clock limit, whole job killed) →
    ///   interrupted (broker/host shutdown stopped an active run) →
    ///   unclean (main exited on its own but descendants had to be force-killed — cleanup not established) →
    ///   exited (main exited on its own and the job emptied cleanly; carries the exit code).
    /// A non-zero <see cref="TerminalFacts.ExitCode"/> on a clean exit is a cleanly-run-but-failed
    /// workload (`exited`), never a success claim by itself. Success (`exited`) is returned only when
    /// descendant cleanup IS established (the job emptied); a bare exit code never promotes to success.
    /// </summary>
    internal static TerminalVerdict Classify(TerminalFacts f)
    {
        if (f.LaunchFailed)
            return new(RunState.Failed, null, "the launch failed or the run died unexpectedly");
        if (f.Lost)
            return new(RunState.Lost, null, "the broker/host restarted mid-run; no recorded outcome could be recovered");
        if (f.TerminateRequested)
            return new(RunState.Terminated, null, "the broker was asked to stop the run; the whole process tree was killed");
        if (f.TimedOut)
            return new(RunState.TimedOut, null, "execution reached the run's wall-clock limit; the whole process tree was killed");
        if (f.StoppedExternally)
            return new(RunState.Interrupted, null, "the run was stopped from outside the broker before its limit (broker/host shutdown)");
        if (f.DescendantsRemained)
            return new(RunState.Unclean, f.ExitCode,
                "the main process finished but descendant(s) remained in the Job Object and had to be force-killed; host containment was not clean");
        return new(RunState.Exited, f.ExitCode,
            f.ExitCode is 0 or null
                ? "the main process exited on its own and the process tree was contained cleanly"
                : "the main process exited on its own (non-zero code: a cleanly-run but failed workload) and the tree was contained cleanly");
    }
}
