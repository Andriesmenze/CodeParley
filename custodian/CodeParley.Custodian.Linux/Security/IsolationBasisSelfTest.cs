namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 (§4.9): the AppArmor profile rules of <see cref="LinuxIsolationBasis.ProfileProblem"/> against fixed texts —
/// the approved form passes; another attachment, a second profile, a hat, a local or conditional include and a profile
/// without an attachment path are refused. Pure (no file, no root); the measurement itself runs on the VM (NL-15).
/// </summary>
internal static class IsolationBasisSelfTest
{
    private const string Bwrap = "/opt/codeparley-codex/0.160.0/codex-resources/bwrap";

    private static string Profile(string attachment, string extra = "")
        => $"abi <abi/4.0>,\ninclude <tunables/global>\n\n# comment\nprofile codeparley-codex-bwrap {attachment} flags=(unconfined) {{\n  userns,\n{extra}}}\n";

    internal static int Run()
    {
        (string Name, string Text, bool Ok)[] cases =
        [
            ("approved, unquoted", Profile(Bwrap), true),
            ("approved, quoted", Profile($"\"{Bwrap}\""), true),
            ("approved, CRLF", Profile(Bwrap).Replace("\n", "\r\n"), true),
            ("another attachment", Profile("/home/cp/.local/opt/codex/codex-resources/bwrap"), false),
            ("a glob attachment", Profile("/opt/codeparley-codex/*/codex-resources/bwrap"), false),
            ("no attachment path", "profile codeparley-codex-bwrap flags=(unconfined) {\n  userns,\n}\n", false),
            ("a second profile", Profile(Bwrap) + "profile other /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n", false),
            ("a hat", Profile(Bwrap, "  ^child {\n  }\n"), false),
            ("a local include", Profile(Bwrap, "  include if exists <local/codex-bwrap>\n"), false),
            ("an old-style include", "#include <abstractions/base>\n" + Profile(Bwrap), false),
            ("no profile", "abi <abi/4.0>,\ninclude <tunables/global>\n", false),
        ];
        int failed = 0;
        foreach ((string name, string text, bool ok) in cases)
        {
            string? problem = LinuxIsolationBasis.ProfileProblem(text, Bwrap);
            bool pass = (problem is null) == ok;
            if (!pass) failed++;
            Console.WriteLine($"{(pass ? "PASS" : "FAIL")} {name}: {problem ?? "accepted"}");
        }
        Console.WriteLine(failed == 0 ? $"isolation-basis self-test: all {cases.Length} cases passed" : $"isolation-basis self-test: {failed} of {cases.Length} cases FAILED");
        return failed == 0 ? 0 : 1;
    }
}
