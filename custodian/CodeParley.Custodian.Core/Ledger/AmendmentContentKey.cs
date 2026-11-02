using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// P3.4C-1 confidentiality correction: the custodian's derivation of a protected amendment's
/// content-equivalence KEY and original UTF-8 byte length, from the authoritative raw text and kind.
///
/// The key is a KEYED hash (HMAC-SHA256 under a secret held only by the custodian), so the
/// implementer-visible value supports equality (duplicate / new-information detection) but cannot be
/// reversed or reproduced by offline guessing of low-entropy private text — unlike the earlier unkeyed
/// SHA-256, which violated D-C'. The custodian is the SOLE computer of protected keys, so there is no
/// cross-runtime HMAC byte-equality to maintain.
///
/// What MUST match the TypeScript engine is the semantic EQUIVALENCE RELATION of
/// <c>amendmentContentKey(kind,text)</c> (src/policy/amendments.ts): two inputs are equivalent iff their
/// normalized forms are equal. <see cref="NormalizeText"/> reproduces that normalization exactly —
/// Unicode NFC, JavaScript's whitespace set for trim + single-space collapse, and JavaScript
/// <c>String.prototype.toLowerCase</c> (the locale-independent Unicode mapping, including its only two
/// special cases: U+0130 İ → "i̇" and the context-sensitive Greek Final_Sigma). Parity is pinned by a
/// shared golden corpus (self-test <c>content-key</c>; the TypeScript side asserts the same corpus).
/// </summary>
internal static class AmendmentContentKey
{
    /// <summary>The explicit domain separator bound into the HMAC message (matches the TypeScript domain
    /// tag used by the legacy local key, so the key's provenance is unambiguous).</summary>
    internal const string Domain = "arl.amendment-content-key.v1";

    /// <summary>The key scheme tag stored on a keyed amendment record; a record lacking it is a
    /// pre-correction (unkeyed) record and is never mixed with keyed records.</summary>
    internal const string Scheme = "hmac-sha256-v1";

    /// <summary>JavaScript's <c>\s</c> / <c>String.prototype.trim</c> whitespace set: the ASCII control
    /// whitespace, U+FEFF, and the Unicode space/line/paragraph separators. Deliberately NOT .NET's
    /// <c>char.IsWhiteSpace</c>, which also includes U+0085 (NEL) that JavaScript's <c>\s</c> excludes.</summary>
    private static bool IsJsWhitespace(char c) =>
        c is '\t' or '\n' or '\v' or '\f' or '\r' or '﻿'
        || CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.SpaceSeparator or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator;

    private static bool IsCased(int cp) =>
        CharUnicodeInfo.GetUnicodeCategory(cp) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter;

    private static bool IsCaseIgnorable(int cp) =>
        CharUnicodeInfo.GetUnicodeCategory(cp) is UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark or UnicodeCategory.Format
            or UnicodeCategory.ModifierLetter or UnicodeCategory.ModifierSymbol
        || cp is 0x27 or 0x2E or 0x3A or 0xB7 or 0x2018 or 0x2019 or 0x2024 or 0x2027 or 0xFE52 or 0xFF07 or 0xFF0E;

    /// <summary>The Unicode Final_Sigma condition: a Σ lowercases to ς (U+03C2) iff it is preceded by a
    /// cased character (skipping case-ignorable ones) and NOT followed by one; else σ (U+03C3).</summary>
    private static bool FinalSigma(int[] cps, int i)
    {
        bool before = false;
        for (int j = i - 1; j >= 0; j--) { if (IsCaseIgnorable(cps[j])) continue; before = IsCased(cps[j]); break; }
        if (!before) return false;
        for (int j = i + 1; j < cps.Length; j++) { if (IsCaseIgnorable(cps[j])) continue; if (IsCased(cps[j])) return false; break; }
        return true;
    }

    /// <summary>Lowercase exactly as JavaScript <c>String.prototype.toLowerCase</c>: per-code-point
    /// invariant lowercasing, plus the two locale-independent special cases .NET's simple mapping omits —
    /// U+0130 → "i̇" (U+0069 U+0307) and Greek Final_Sigma.</summary>
    private static string JsLower(string s)
    {
        int[] cps = s.EnumerateRunes().Select(r => r.Value).ToArray();
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < cps.Length; i++)
        {
            int cp = cps[i];
            if (cp == 0x03A3) sb.Append(FinalSigma(cps, i) ? 'ς' : 'σ');
            else if (cp == 0x0130) sb.Append("i̇");
            else sb.Append(new Rune(cp).ToString().ToLowerInvariant());
        }
        return sb.ToString();
    }

    /// <summary>The normalized comparison form of an amendment's text, byte-identical to TypeScript's
    /// <c>text.normalize("NFC").trim().replace(/\s+/g," ").toLowerCase()</c>.</summary>
    internal static string NormalizeText(string text)
    {
        string t = text.Normalize(NormalizationForm.FormC);
        var trimmed = new StringBuilder(t.Length);
        bool inRun = false;
        foreach (char c in t)
        {
            if (IsJsWhitespace(c)) { inRun = true; continue; }
            if (inRun && trimmed.Length > 0) trimmed.Append(' ');
            inRun = false;
            trimmed.Append(c);
        }
        return JsLower(trimmed.ToString());
    }

    /// <summary>The normalized content-equivalence input, matching TypeScript <c>amendmentContentKey</c>:
    /// <c>kind + U+0000 + normalizedText</c>. Kinds are a fixed enum (no NUL), so this is unambiguous.</summary>
    internal static string ContentKeyInput(string kind, string text) => $"{kind}\u0000{NormalizeText(text)}";

    /// <summary>The original text's length in UTF-8 bytes (the effective-amendment byte budget uses this).</summary>
    internal static int Utf8ByteLength(string text) => Encoding.UTF8.GetByteCount(text);

    /// <summary>The keyed content-equivalence hash: HMAC-SHA256(secret, domain U+0000 ContentKeyInput),
    /// lowercase hex. Equal normalized content under the same secret yields an equal value; without the
    /// secret the value cannot be reproduced or reversed.</summary>
    internal static string KeyedHash(byte[] secret, string kind, string text)
    {
        byte[] msg = Encoding.UTF8.GetBytes($"{Domain}\u0000{ContentKeyInput(kind, text)}");
        return Convert.ToHexStringLower(HMACSHA256.HashData(secret, msg));
    }

    /// <summary>A proxy for the runtime's Unicode data version (the invariant collation version), recorded as
    /// evidence. A change here flags that an OS/ICU upgrade could in principle alter normalization for some
    /// code points; <see cref="SelfValidate"/> is the guard that fails closed if the behavior actually
    /// diverges on the sentinels, and existing keys are never silently recomputed.</summary>
    internal static int GlobalizationVersion => CultureInfo.InvariantCulture.CompareInfo.Version.FullVersion;

    private static string Hex(string s) => string.Join(" ", s.EnumerateRunes().Select(r => r.Value.ToString("x")));

    private static volatile bool _validated;
    private static readonly object ValidateGate = new();

    /// <summary>P3.4C-3 (§2.5 S7): does the calling thread hold the validation lock? The ledger refuses to take its own
    /// lock while it does (the order is ledger lock → validation lock, never the reverse).</summary>
    internal static bool HoldingValidateGate => Monitor.IsEntered(ValidateGate);

    /// <summary>Startup / pre-protected-operation self-validation: confirm the runtime's Unicode
    /// globalization reproduces the engine's content-equivalence normalization for a set of sentinels that
    /// an invariant-mode or NLS backend would get wrong (NFC composition, Turkish İ, Greek Final_Sigma, the
    /// NEL whitespace EXCLUSION, German ß, NBSP collapse). Throws (so protected amendment operations FAIL
    /// CLOSED) if the required ICU-backed behavior is unavailable. Cached after the first success.</summary>
    internal static void SelfValidate()
    {
        if (_validated) return;
        lock (ValidateGate)
        {
            if (_validated) return;
            (string input, string expected)[] sentinels =
            {
                ("", ""),
                ("Hello  World", "hello world"),
                ("Café", "café"),          // NFC composes e + combining acute
                ("İstanbul", "i̇stanbul"),   // Turkish İ → i + combining dot
                ("ΟΔΟΣ", "οδος"), // ΟΔΟΣ → οδος (Final_Sigma)
                ("nel\u0085stays", "nel\u0085stays"),  // U+0085 NEL is NOT JS whitespace
                ("STRAßE", "straße"),        // ß round-trips under lowercasing
                ("A B", "a b"),                   // NBSP is whitespace → collapsed
            };
            foreach ((string input, string expected) in sentinels)
            {
                string got = NormalizeText(input);
                if (got != expected)
                    throw new InvalidOperationException(
                        $"the custodian's Unicode globalization does not reproduce the required content-equivalence normalization " +
                        $"(sentinel expected [{Hex(expected)}], got [{Hex(got)}]); the ICU-backed globalization backend is missing or " +
                        $"incompatible, so protected amendment operations FAIL CLOSED. Globalization data version {GlobalizationVersion}.");
            }
            _validated = true;
        }
    }
}
