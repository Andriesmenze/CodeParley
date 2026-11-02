// P3.4C-1 confidentiality correction — the SHARED golden corpus that pins the amendment content-equivalence
// NORMALIZATION so the C# custodian reproduces TypeScript's `amendmentContentKey(kind,text)` relation
// exactly. This test derives the corpus from the real TS function (the Phase-2 oracle) and writes it to
// test/fixtures/; the custodian's `self-test-content-key` reads the same committed file and asserts C#
// produces byte-identical normalized keys and UTF-8 byte lengths. The two runtimes never share the HMAC
// computation (the custodian keys that under its own secret) — only this normalization relation.

import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { amendmentContentKey, contentKeyHash } from "../src/policy/amendments.js";

const CORPUS_PATH = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "amendment-content-key-corpus.json");

/** The inputs the corpus covers (the TD's cross-runtime list): ASCII + realistic guidance, mixed case and
 * collapsing/trimming whitespace, the full JS `\s` set (and U+0085 NEL which it excludes), NFC-equivalent
 * sequences, non-ASCII lowercasing incl. Greek Final_Sigma and Turkish İ, German ß/ẞ, ligatures, titlecase,
 * Cyrillic, empty and boundary inputs, and amendment kinds for domain separation. */
const INPUTS: { kind: string; text: string }[] = [
  { kind: "clarification", text: "" },
  { kind: "clarification", text: "   " },
  { kind: "clarification", text: "Prefer an explicit loop over recursion" },
  { kind: "clarification", text: "Prefer  an   explicit\tloop\nover recursion" },
  { kind: "clarification", text: "  Prefer an explicit loop over recursion  " },
  { kind: "scope", text: "Prefer an explicit loop over recursion" },
  { kind: "constraint", text: "Focus the review on error handling" },
  { kind: "priority", text: "FOCUS THE REVIEW ON ERROR HANDLING" },
  { kind: "acceptance-criteria", text: "tabs\t\tand\r\nnewlines here" },
  { kind: "clarification", text: "non break space　cjk﻿bom" },
  { kind: "clarification", text: "nel\u0085stays" },
  { kind: "clarification", text: "Café vs Café (NFC)" },
  { kind: "clarification", text: "CAFÉ" },
  { kind: "clarification", text: "straße and STRASSE and ẞ" },
  { kind: "clarification", text: "İstanbul and ISTANBUL and i̇" },
  { kind: "clarification", text: "Diyarbakır" },
  { kind: "clarification", text: "ΟΔΟΣ" },
  { kind: "clarification", text: "ΣΟΦΟΣ and ΑΣ and Σ" },
  { kind: "clarification", text: "ΑΣΒ" },
  { kind: "clarification", text: "ПРИВЕТ world" },
  { kind: "clarification", text: "ligature ﬀ and titlecase ǅ and roman Ⅷ" },
  { kind: "withdrawal", text: "it's a co·op decision." },
  // Expanded edge cases: supplementary (astral) characters, combining-mark canonical reordering under NFC,
  // stacked marks, vertical-tab/form-feed whitespace, Greek accents + non-final sigma, Cyrillic, boundary
  // length, and a final-sigma after a space-separated capitalized word.
  { kind: "clarification", text: "emoji \u{1F600} astral \u{20000} cjk" },
  { kind: "clarification", text: "math bold \u{1D400}\u{1D41A} letters" },
  { kind: "clarification", text: "reorder ọ́ vs ọ́" },
  { kind: "clarification", text: "stacked á̂̃ marks" },
  { kind: "scope", text: "   leading\u000bvtab\u000cff trailing   " },
  { kind: "priority", text: "Αάσσος" },
  { kind: "constraint", text: "CYRILLIC ДА text" },
  { kind: "clarification", text: "x".repeat(2000) },
  { kind: "clarification", text: "a word then Σ" },
];

describe("amendment content-equivalence key: the shared normalization corpus (P3.4C-1)", () => {
  it("regenerates the committed corpus from the real amendmentContentKey (the C# custodian asserts the same file)", () => {
    const corpus = INPUTS.map(({ kind, text }) => ({ kind, text, content_key: amendmentContentKey(kind, text), bytes: Buffer.byteLength(text, "utf8") }));
    writeFileSync(CORPUS_PATH, JSON.stringify(corpus, null, 1) + "\n");
    const committed = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
    expect(committed).toEqual(corpus);
    // Every entry round-trips through the real function.
    for (const e of corpus) {
      expect(amendmentContentKey(e.kind, e.text)).toBe(e.content_key);
      expect(Buffer.byteLength(e.text, "utf8")).toBe(e.bytes);
    }
  });

  it("the equivalence relation groups case/whitespace/NFC-equivalent content and separates by kind", () => {
    const k = (kind: string, text: string) => contentKeyHash(kind, text);
    // Case + whitespace collapse + NFC are equivalence-preserving.
    expect(k("clarification", "Prefer  an EXPLICIT\tloop")).toBe(k("clarification", "prefer an explicit loop"));
    expect(k("clarification", "Café")).toBe(k("clarification", "Café"));
    // The kind is part of the key (domain separation); different text differs.
    expect(k("scope", "x")).not.toBe(k("clarification", "x"));
    expect(k("clarification", "a")).not.toBe(k("clarification", "b"));
  });
});
