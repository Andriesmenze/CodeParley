using System.Text.Json;
using CodeParley.Custodian.Ledger;

namespace CodeParley.Custodian.Cli;

/// <summary>P3.4C-1: the content-key normalization against the shared golden corpus (both hosts; moved verbatim from
/// the Windows CLI in Phase 5).</summary>
internal static class ContentKeySelfTest
{
    internal static int Run(string[] args)
    {
        string? corpus = GetArg(args, "--corpus");
        if (corpus is null || !File.Exists(corpus))
        {
            Console.Error.WriteLine("self-test-content-key requires --corpus <path to test/fixtures/amendment-content-key-corpus.json>");
            return 2;
        }
        static string Hex(string s) => string.Join(" ", s.EnumerateRunes().Select(r => r.Value.ToString("x")));
        Console.WriteLine($"globalization: invariant-mode={System.Globalization.CultureInfo.InvariantCulture.CompareInfo.Version.FullVersion == 0}, data version {AmendmentContentKey.GlobalizationVersion}, .NET {Environment.Version}");
        int failed = 0;
        // The self-validation sentinels (NFC, İ, Final_Sigma, NEL exclusion, ß, NBSP) must pass, else the
        // globalization backend is incompatible (invariant/NLS) — protected amendment ops fail closed.
        try { AmendmentContentKey.SelfValidate(); failed += Check("globalization self-validation (sentinels) passes", true); }
        catch (Exception e) { failed += Check($"globalization self-validation (sentinels) passes — {e.Message}", false); }

        string json = File.ReadAllText(corpus);
        // The content-equivalence normalization is culture-INDEPENDENT: assert the whole corpus under the
        // invariant culture AND under a contrasting culture (Turkish — the classic İ/ı casing trap).
        foreach (string cultureName in new[] { "", "tr-TR" })
        {
            var prior = System.Threading.Thread.CurrentThread.CurrentCulture;
            try
            {
                System.Threading.Thread.CurrentThread.CurrentCulture = cultureName.Length == 0 ? System.Globalization.CultureInfo.InvariantCulture : new System.Globalization.CultureInfo(cultureName);
                int n = 0, bad = 0;
                using var doc = JsonDocument.Parse(json);
                foreach (JsonElement e in doc.RootElement.EnumerateArray())
                {
                    n++;
                    string kind = e.GetProperty("kind").GetString()!;
                    string text = e.GetProperty("text").GetString()!;
                    string expectedKey = e.GetProperty("content_key").GetString()!;
                    int expectedBytes = e.GetProperty("bytes").GetInt32();
                    string gotKey = AmendmentContentKey.ContentKeyInput(kind, text);
                    int gotBytes = AmendmentContentKey.Utf8ByteLength(text);
                    if (gotKey != expectedKey || gotBytes != expectedBytes)
                    {
                        bad++;
                        Console.WriteLine($"[FAIL] entry {n} kind={kind} culture={(cultureName.Length == 0 ? "invariant" : cultureName)}\n  exp key cps=[{Hex(expectedKey)}] bytes={expectedBytes}\n  got key cps=[{Hex(gotKey)}] bytes={gotBytes}");
                    }
                }
                failed += Check($"all {n} corpus entries match the TypeScript normalization under culture {(cultureName.Length == 0 ? "invariant" : cultureName)}", bad == 0);
            }
            finally { System.Threading.Thread.CurrentThread.CurrentCulture = prior; }
        }
        Console.WriteLine($"content-key self-test: {(failed == 0 ? "all passed" : failed + " FAILED")}");
        return failed == 0 ? 0 : 1;
    }

    private static int Check(string name, bool ok) { Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}"); return ok ? 0 : 1; }

    private static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }
}
