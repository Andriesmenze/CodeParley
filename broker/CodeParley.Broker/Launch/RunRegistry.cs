using System.Collections.Concurrent;

namespace CodeParley.Broker.Launch;

/// <summary>Tracks the runs the broker currently owns (for status queries and restart recovery).</summary>
internal sealed class RunRegistry
{
    private readonly ConcurrentDictionary<string, WorkerRun> _runs = new(StringComparer.OrdinalIgnoreCase);

    internal bool TryAdd(WorkerRun run) => _runs.TryAdd(run.RunId, run);
    internal WorkerRun? Get(string runId) => _runs.TryGetValue(runId, out WorkerRun? r) ? r : null;
    internal bool Remove(string runId) => _runs.TryRemove(runId, out _);
    internal IReadOnlyCollection<WorkerRun> All => _runs.Values.ToArray();
}
