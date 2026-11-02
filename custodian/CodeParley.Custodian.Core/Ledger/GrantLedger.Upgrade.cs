using System.Text.Json;
using System.Text.Json.Nodes;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

internal sealed partial class GrantLedger
{
    /// <summary>
    /// Phase 6 (L-2): the migration's read of the whole store — every versioned file through the loader that serves it,
    /// every run record and every held fix-proposal content — without writing anything. A file this build would refuse
    /// fails the upgrade before the store is marked (the installer then offers <c>rollback</c>). Returns the files read.
    /// </summary>
    internal int ReadEveryRecordForUpgrade()
    {
        lock (EnterGate())
        {
            Read();
            ReadUserRecords();
            ReadConfigRecords();
            int files = 3;
            foreach (string file in Files(StorePaths.RunsDir))
            {
                _ = JsonSerializer.Deserialize<RunRecord>(File.ReadAllText(file), Json) ?? throw new InvalidDataException($"the run record {Path.GetFileName(file)} is empty");
                files++;
            }
            foreach (string file in Files(StorePaths.FixProposalsDir))
            {
                string? schema = (string?)(JsonNode.Parse(File.ReadAllText(file)) as JsonObject)?["schema"];
                if (schema != FixProposalContentSchema) throw new InvalidDataException($"the held fix-proposal content {Path.GetFileName(file)} is in schema {schema ?? "(none)"}, which this build does not read");
                files++;
            }
            return files;
        }
    }

    private static IEnumerable<string> Files(string dir)
        => Directory.Exists(dir) ? Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal) : [];
}
