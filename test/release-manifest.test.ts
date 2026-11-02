// Phase 6 Increment 2 (contract §8, A-1 to A-3, A-5): the BUILD-ID every release artifact carries and the unsigned
// release manifest (scripts/package/lib/release-manifest.mjs), whose rule the installers apply to what they install.

import { describe, it, expect } from "vitest";

interface BuildIdInput { artifact: string; version: string; commit: string; signature: string; dirty: boolean; toolchain: Record<string, string>; builtAt: string; testBuild?: boolean }
interface Entry { name: string; file: string; size: number; sha256: string; buildId: Record<string, unknown> }
interface Lib {
  ARTIFACTS: readonly { name: string; platform: string }[];
  MANIFEST_SCHEMA: string;
  buildId(i: BuildIdInput): Record<string, unknown>;
  buildManifest(i: { version: string; commit: string; signature: string; dirty: boolean; entries: Entry[] }): { releaseCandidate: boolean; signed: boolean; artifacts: Entry[]; schema: string };
  artifactProblem(m: unknown, name: string, file: string, f: { size: number; sha256: string }): string | null;
}
const load = async (): Promise<Lib> => (await import(new URL("../scripts/package/lib/release-manifest.mjs", import.meta.url).href)) as Lib;

const COMMIT = "a".repeat(40);
const TOOLS = { dotnetSdk: "10.0.201", node: "v22.0.0", npm: "10.0.0" };
const base = (artifact: string, o: Partial<BuildIdInput> = {}): BuildIdInput => ({ artifact, version: "0.4.0", commit: COMMIT, signature: "verified", dirty: false, toolchain: TOOLS, builtAt: "2026-10-28T00:00:00.000Z", ...o });

async function entries(o: Partial<BuildIdInput> = {}): Promise<Entry[]> {
  const lib = await load();
  return lib.ARTIFACTS.map((a, i) => ({ name: a.name, file: `${a.name}.tar.gz`, size: 100 + i, sha256: String(i).repeat(64).slice(0, 64), buildId: lib.buildId(base(a.name, o)) }));
}

describe("Phase 6 §8: release artifact identity and the manifest", () => {
  it("A-2: a BUILD-ID names the commit, its signature, the version and the toolchain; only a clean, verified build is a release candidate", async () => {
    const { buildId } = await load();
    expect(buildId(base("plugin-windows"))).toMatchObject({ schema: "codeparley.build-id.v1", artifact: "plugin-windows", commit: COMMIT, signature: "verified", releaseCandidate: true, toolchain: TOOLS });
    expect(buildId(base("plugin-windows", { dirty: true })).releaseCandidate).toBe(false);
    expect(buildId(base("plugin-windows", { signature: "unverified" })).releaseCandidate).toBe(false);
    expect(buildId(base("plugin-windows", { testBuild: true }))).toMatchObject({ testBuild: true, releaseCandidate: false }); // a VM gate's --test-version build
    expect(() => buildId(base("plugin-windows", { commit: "abc" }))).toThrow(/40-character/);
    expect(() => buildId(base("something-else"))).toThrow(/unknown artifact/);
    expect(() => buildId(base("plugin-windows", { toolchain: { node: "v22", npm: "10" } }))).toThrow(/dotnetSdk/);
  });

  it("A-3: the manifest lists every artifact once, in order, with size, SHA-256 and BUILD-ID; it is unsigned", async () => {
    const { buildManifest, ARTIFACTS, MANIFEST_SCHEMA } = await load();
    const e = await entries();
    const m = buildManifest({ version: "0.4.0", commit: COMMIT, signature: "verified", dirty: false, entries: [...e].reverse() });
    expect(m.schema).toBe(MANIFEST_SCHEMA);
    expect(m.artifacts.map((a) => a.name)).toEqual(ARTIFACTS.map((a) => a.name));
    expect(m).toMatchObject({ releaseCandidate: true, signed: false });
    expect(() => buildManifest({ version: "0.4.0", commit: COMMIT, signature: "verified", dirty: false, entries: e.slice(1) })).toThrow(/lacks the artifact/);
    expect(() => buildManifest({ version: "0.4.0", commit: COMMIT, signature: "verified", dirty: false, entries: [...e, e[0]!] })).toThrow(/twice/);
    expect(() => buildManifest({ version: "0.4.1", commit: COMMIT, signature: "verified", dirty: false, entries: e })).toThrow(/another commit or version/);
    const bad = e.map((x, i) => (i === 2 ? { ...x, sha256: "XYZ" } : x));
    expect(() => buildManifest({ version: "0.4.0", commit: COMMIT, signature: "verified", dirty: false, entries: bad })).toThrow(/sha256/);
    expect(buildManifest({ version: "0.4.0", commit: COMMIT, signature: "unverified", dirty: false, entries: await entries({ signature: "unverified" }) }).releaseCandidate).toBe(false);
  });

  it("A-5: an installer accepts a file only with the manifest's name, size and SHA-256", async () => {
    const { buildManifest, artifactProblem } = await load();
    const e = await entries();
    const m = buildManifest({ version: "0.4.0", commit: COMMIT, signature: "verified", dirty: false, entries: e });
    const c = m.artifacts.find((a) => a.name === "custodian-windows-x64")!;
    expect(artifactProblem(m, c.name, c.file, { size: c.size, sha256: c.sha256 })).toBeNull();
    expect(artifactProblem(m, c.name, c.file, { size: c.size, sha256: "0".repeat(64) })).toMatch(/SHA-256/);
    expect(artifactProblem(m, c.name, c.file, { size: c.size + 1, sha256: c.sha256 })).toMatch(/bytes/);
    expect(artifactProblem(m, c.name, "other.tar.gz", { size: c.size, sha256: c.sha256 })).toMatch(/names/);
    expect(artifactProblem(m, "missing", c.file, { size: c.size, sha256: c.sha256 })).toMatch(/no artifact/);
    expect(artifactProblem({ schema: "x" }, c.name, c.file, { size: c.size, sha256: c.sha256 })).toMatch(/not a CodeParley release manifest/);
  });
});
