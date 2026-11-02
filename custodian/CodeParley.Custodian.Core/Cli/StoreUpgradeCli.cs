using System.Text.Json.Nodes;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Cli;

/// <summary>
/// Phase 6 Increment 2: the verbs the installers call (both hosts; on Linux as the custodian account, so every file the
/// migration writes is the custodian's). Each prints one JSON object; a refusal prints <c>{"refused": "..."}</c> with the
/// remedy and exits 1.
/// <list type="bullet">
/// <item><c>store-status</c>: the store's format and upgrade journal (L-1: the installer checks it before it upgrades,
/// rolls back or uninstalls).</item>
/// <item><c>store-upgrade --backup-sha256 &lt;hex&gt;</c>: migrate after the installer's backup (L-2, L-4);
/// <c>store-upgrade --resume</c> completes an interrupted one (L-3).</item>
/// </list>
/// </summary>
internal static class StoreUpgradeCli
{
    internal static int Status()
    {
        Console.WriteLine(StoreUpgrade.Status().ToJsonString());
        return 0;
    }

    internal static int Upgrade(string[] args)
    {
        string? sha = null;
        bool resume = false;
        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--backup-sha256" when i + 1 < args.Length: sha = args[++i]; break;
                case "--resume": resume = true; break;
                default: return Refuse($"unexpected argument '{args[i]}' (store-upgrade --backup-sha256 <hex> | --resume [--backup-sha256 <hex>])");
            }
        }
        try
        {
            Console.WriteLine(StoreUpgrade.Run(sha, resume).ToJsonString());
            return 0;
        }
        catch (InvalidDataException e) { return Refuse(e.Message); }
    }

    private static int Refuse(string why)
    {
        Console.WriteLine(new JsonObject { ["refused"] = why }.ToJsonString());
        return 1;
    }
}
