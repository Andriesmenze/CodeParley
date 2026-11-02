// P3.4C-4 M9: the configuration validation and digests the engine and the simulated custodian compute, held to the
// shared corpus (test/fixtures/config-digest-corpus.json) that the real custodian checks too (self-test-config-corpus).
// The corpus pins tricky strings (non-ASCII, escapes, control characters) and integer-like object keys, whose order is
// where a canonical JSON writer most easily drifts from JavaScript's.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { repositoryContent, validateRepositoryPayload } from "../src/custodian/simulated-config.js";
import { sha256OfCanonicalJson } from "../src/common/hash.js";

interface Corpus {
  canonical: { name: string; value: unknown; digest: string }[];
  accepted: { name: string; payload: Record<string, unknown>; digests: Record<string, string>; captureRulesDigest: string; configDigest: string }[];
  refused: { name: string; payload: Record<string, unknown> }[];
}
const corpus = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "config-digest-corpus.json"), "utf8")) as Corpus;

describe("the configuration digest corpus (M9)", () => {
  it.each(corpus.canonical.map((c) => [c.name, c] as const))("canonical JSON: %s", (_n, c) => {
    expect(sha256OfCanonicalJson(c.value)).toBe(c.digest);
  });

  it.each(corpus.accepted.map((a) => [a.name, a] as const))("accepted: %s", (_n, a) => {
    const content = repositoryContent(validateRepositoryPayload(structuredClone(a.payload)), null);
    const checks = content["checks"] as Record<string, { definitionDigest: string }>;
    expect(Object.fromEntries(Object.entries(checks).map(([n, c]) => [n, c.definitionDigest]))).toEqual(a.digests);
    expect(content["captureRulesDigest"]).toBe(a.captureRulesDigest);
    expect(content["configDigest"]).toBe(a.configDigest);
  });

  it.each(corpus.refused.map((r) => [r.name, r] as const))("refused: %s", (_n, r) => {
    expect(() => validateRepositoryPayload(structuredClone(r.payload))).toThrow();
  });
});
