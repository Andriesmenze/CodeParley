// Phase 5: the real package manifest (package.json `files`) decides what CodeParley's distributable
// contains. A stage holds the compiled modules of the run-wide build of src/ (test/global-setup.ts)
// beside planted development files; npm packs it with the real package.json, and the tarball, read
// with scripts/package/lib/tar-lite.mjs, must satisfy the content policy and agree with npm's own
// list. The full clean build, install and run is scripts/package/smoke.mjs (not part of `npm test`:
// it installs from the registry).

import { describe, it, expect, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { supported } from "./helpers/git-fixture.js";
import { removeScratch, scratchDir } from "./helpers/package-fixture.js";

interface Policy {
  checkPackageContent(paths: string[], o: { pkg: unknown; inventory: { modules: string[]; prompts: string[] } }): { ok: boolean; unexpected: unknown[]; missing: unknown[]; orphans: unknown[] };
  sourceInventory(repoDir: string): { modules: string[]; prompts: string[] };
}
interface Tar {
  packageFiles(gz: Buffer): Map<string, { path: string; size: number }>;
}
interface Tools {
  npmCli(nodePath: string): string;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const load = async <T>(rel: string): Promise<T> => (await import(new URL(`../scripts/package/${rel}`, import.meta.url).href)) as T;
const policy = await load<Policy>("lib/policy.mjs");
const tar = await load<Tar>("lib/tar-lite.mjs");
const tools = await load<Tools>("lib/tools.mjs");

function findNpm(): string | null {
  try {
    return tools.npmCli(process.execPath);
  } catch {
    return null;
  }
}
const npm = findNpm();
afterAll(removeScratch);

/** Development content that must never ship, planted in the stage (paths relative to the package root). */
const PLANTED = ["src/cli/main.ts", "test/a.test.ts", "docs/TD_HANDOFF.md", "docs/validation/results/x-evidence/run.json", "CLAUDE.md", "IMPLEMENTATION_PLAN.md", "custodian/Program.cs", "broker/HOST-CONTRACT.md", "plugin/build-plugin.mjs", "scripts/package/pack.mjs", "dist/cli/main.js.map", "dist/cli/main.d.ts", "dist/test-server.mjs", ".tmp-test-dist/x.js", "package-lock.json", "tsconfig.json", ".github/workflows/ci.yml"];

describe.skipIf(!supported || npm === null)("the package manifest on a clean build (npm pack)", () => {
  it("ships the runtime allowlist and nothing else, and the tarball agrees with npm's list", async () => {
    let compiled = sharedCompiledSrc();
    if (!compiled) {
      compiled = join(repoRoot, ".tmp-test-dist", `pkg-${randomBytes(4).toString("hex")}`);
      buildSrc(repoRoot, compiled);
    }
    const inventory = policy.sourceInventory(repoRoot);
    const stage = await scratchDir("cp-pkgstage-");
    for (const f of ["package.json", "README.md"]) cpSync(join(repoRoot, f), join(stage, f));
    cpSync(join(repoRoot, "prompts"), join(stage, "prompts"), { recursive: true });
    // Exactly the compiled source modules (other suites add helper scripts beside the shared build).
    for (const m of inventory.modules) cpSync(join(compiled, ...m.slice("dist/".length).split("/")), join(stage, ...m.split("/")));
    for (const p of PLANTED) {
      mkdirSync(dirname(join(stage, ...p.split("/"))), { recursive: true });
      writeFileSync(join(stage, ...p.split("/")), "development only\n");
    }

    const out = await scratchDir("cp-pkgout-");
    const r = spawnSync(process.execPath, [npm!, "pack", "--json", "--ignore-scripts", "--pack-destination", out], { cwd: stage, encoding: "utf8", windowsHide: true, env: { ...process.env, npm_config_update_notifier: "false" } });
    expect(r.status, r.stderr).toBe(0);
    const report = JSON.parse(r.stdout.slice(r.stdout.indexOf("["))) as { filename: string; files: { path: string }[] }[];
    const paths = [...tar.packageFiles(readFileSync(join(out, report[0]!.filename))).keys()].sort();

    expect(paths).toEqual(report[0]!.files.map((f) => f.path).sort());
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as unknown;
    expect(policy.checkPackageContent(paths, { pkg, inventory })).toEqual({ ok: true, unexpected: [], missing: [], orphans: [] });
    expect(paths.filter((p) => PLANTED.includes(p))).toEqual([]);
    expect(paths).toEqual(["README.md", ...inventory.modules, "package.json", ...inventory.prompts].sort());
  }, 180_000);
});
