// The reviewer prompt is read only from CodeParley's own installation (Phase 5 security fix).
// src/prompts/render.ts resolves exactly `<root>/prompts/<name>`, the root fixed by where the
// module is (the folder above src/ or dist/; a flat test build is its own root), with no upward
// search and no fallback. The clean-install smoke test had shown the old upward search reading a
// decoy template from above an npm installation whose own prompts/ was missing
// (docs/validation/results/P5-packaging-local.md). Every layout below is surrounded by decoys at
// each place that search looked.

import { describe, it, expect, afterAll } from "vitest";
import { copyFileSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { installationRoot, resolveTemplatePath, templatePath } from "../src/prompts/render.js";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { tempDir } from "./helpers/git-fixture.js";

interface RenderModule {
  templatePath(name: string): string;
  loadTemplate(name?: string): Promise<{ id: string; version: string }>;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const NAME = "codex-reviewer.md";
const TEMPLATE = readFileSync(join(repoRoot, "prompts", NAME), "utf8");
const VERSION = /version:\s*([0-9A-Za-z.-]+)/.exec(TEMPLATE)?.[1];
/** A decoy that even names the right template: only its location can give it away. */
const DECOY = "<!-- template: codex-reviewer version: 999 -->\nDECOY: not the template CodeParley ships\n";

/** Every temporary folder this file made, removed afterwards. */
const bases: string[] = [];
afterAll(() => {
  for (const b of bases) rmSync(b, { recursive: true, force: true });
});

async function newBase(prefix: string): Promise<string> {
  const base = await tempDir(prefix);
  bases.push(base);
  return base;
}

function put(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

/** Every file the old search read `name` from: `<dir>/prompts/<name>` for the renderer's folder and five above. */
function oldSearch(moduleFile: string): string[] {
  const out: string[] = [];
  let dir = dirname(moduleFile);
  for (let i = 0; i < 6; i++) {
    out.push(join(dir, "prompts", NAME));
    dir = dirname(dir);
  }
  return out;
}

/** The layouts sit this deep inside the temporary base, so every folder the old search reached is inside it. */
const NEST = join("n1", "n2", "n3");

/** Plant the decoy everywhere the old search looked except the installation's own place; never outside `base`. */
function plantDecoys(base: string, moduleFile: string, own: string): number {
  let planted = 0;
  for (const p of oldSearch(moduleFile)) {
    if (p === own) continue;
    if (!p.startsWith(base + sep)) throw new Error(`a decoy would land outside the test's own folder: ${p}`);
    put(p, DECOY);
    planted++;
  }
  return planted;
}

/** [layout, the renderer's path, its installation root], relative to a temporary base. */
const LAYOUTS: [string, string, string][] = [
  ["a source checkout (the tests run src/)", "repo/src/prompts/render.ts", "repo"],
  ["a built checkout", "repo/dist/prompts/render.js", "repo"],
  ["a global npm installation (Linux)", "prefix/lib/node_modules/code-parley/dist/prompts/render.js", "prefix/lib/node_modules/code-parley"],
  ["a global npm installation (Windows)", "prefix/node_modules/code-parley/dist/prompts/render.js", "prefix/node_modules/code-parley"],
  ["an npm project installation", "project/node_modules/code-parley/dist/prompts/render.js", "project/node_modules/code-parley"],
  ["the Claude Code plugin's cached copy", "claude/plugins/cache/code-parley-local/code-parley/0.3.0-p3.3b.b1/app/dist/prompts/render.js", "claude/plugins/cache/code-parley-local/code-parley/0.3.0-p3.3b.b1/app"],
  ["a flat test build", "repo/.tmp-test-dist/run-1/prompts/render.js", "repo/.tmp-test-dist/run-1"],
];

describe("prompt templates come only from the installation (the location rule)", () => {
  it.each(LAYOUTS)("%s: the root is fixed by the renderer's location", (_layout, mod, root) => {
    expect(installationRoot(join("/base", mod))).toBe(join("/base", root));
  });

  it.each(LAYOUTS)("%s: its own template is read, never a decoy around it", async (_layout, mod, root) => {
    const base = await newBase("cp-tpl-");
    const moduleFile = join(base, NEST, mod);
    const own = join(base, NEST, root, "prompts", NAME);
    expect(plantDecoys(base, moduleFile, own)).toBe(5);
    put(own, TEMPLATE);
    const found = resolveTemplatePath(moduleFile, NAME);
    expect(found).toBe(realpathSync(own));
    expect(readFileSync(found, "utf8")).toBe(TEMPLATE);
  });

  it.each(LAYOUTS)("%s: with its own template missing it fails, naming what to restore, and reads no decoy", async (_layout, mod, root) => {
    const base = await newBase("cp-tpl-");
    const moduleFile = join(base, NEST, mod);
    const own = join(base, NEST, root, "prompts", NAME);
    expect(plantDecoys(base, moduleFile, own)).toBe(5);
    let error: Error | null = null;
    try {
      resolveTemplatePath(moduleFile, NAME);
    } catch (e) {
      error = e as Error;
    }
    expect(error?.message).toContain(`is missing from its installation (ENOENT): expected ${own}`);
    expect(error?.message).toContain("never from anywhere else: reinstall CodeParley");
  });

  it("accepts template names only, never a path", () => {
    for (const bad of ["../codex-reviewer.md", "sub/codex-reviewer.md", "..\\codex-reviewer.md", "Codex-Reviewer.md", "codex-reviewer.txt", ".md", ""]) {
      expect(() => resolveTemplatePath(join(repoRoot, "src", "prompts", "render.ts"), bad), bad).toThrow(/invalid prompt template name/);
    }
  });

  it("this checkout resolves its own prompts/", () => {
    expect(templatePath(NAME)).toBe(realpathSync(join(repoRoot, "prompts", NAME)));
  });
});

/** The compiled renderer (the run-wide build of src/, or this file's own). */
function compiledDir(): string {
  const shared = sharedCompiledSrc();
  if (shared) return shared;
  const dir = join(repoRoot, ".tmp-test-dist", `tpl-${randomBytes(4).toString("hex")}`);
  buildSrc(repoRoot, dir);
  return dir;
}

/** The compiled renderer installed as npm installs a package globally on Linux, as a fresh module instance. */
async function installRenderer(): Promise<{ base: string; pkg: string; load: () => Promise<RenderModule> }> {
  const compiled = compiledDir();
  const base = await newBase("cp-tplpkg-");
  const pkg = join(base, "lib", "node_modules", "code-parley");
  for (const rel of ["prompts/render.js", "common/hash.js"]) {
    mkdirSync(dirname(join(pkg, "dist", rel)), { recursive: true });
    copyFileSync(join(compiled, ...rel.split("/")), join(pkg, "dist", ...rel.split("/")));
  }
  put(join(pkg, "package.json"), JSON.stringify({ name: "code-parley", type: "module" }));
  const load = async (): Promise<RenderModule> => (await import(pathToFileURL(join(pkg, "dist", "prompts", "render.js")).href)) as RenderModule;
  return { base, pkg, load };
}

describe("the compiled renderer in an npm installation (the clean-install exploit)", () => {
  it("the run-wide flat build carries its own templates (test/helpers/build-src.ts)", async () => {
    const dir = compiledDir();
    const m = (await import(pathToFileURL(join(dir, "prompts", "render.js")).href)) as RenderModule;
    expect(m.templatePath(NAME)).toBe(realpathSync(join(dir, "prompts", NAME)));
  });

  it("prompts/ missing, decoys above the package: refused with what to restore; restored: the package's own", async () => {
    const { base, pkg, load } = await installRenderer();
    // The smoke test's decoy (<prefix>/lib/prompts) and every other folder the old search reached.
    for (const p of [join(base, "lib", "prompts", NAME), join(base, "lib", "node_modules", "prompts", NAME), join(base, "prompts", NAME), join(pkg, "dist", "prompts", NAME)]) put(p, DECOY);
    const m = await load();
    expect(() => m.templatePath(NAME)).toThrow(/missing from its installation/);
    await expect(m.loadTemplate()).rejects.toThrow(/reinstall CodeParley/);
    put(join(pkg, "prompts", NAME), TEMPLATE);
    expect(m.templatePath(NAME)).toBe(realpathSync(join(pkg, "prompts", NAME)));
    expect((await m.loadTemplate()).version).toBe(VERSION);
  });

  it("a template altered in place, or not a file, is refused", async () => {
    const { pkg, load } = await installRenderer();
    const m = await load();
    const own = join(pkg, "prompts", NAME);
    put(own, "<!-- template: decoy version: 1 -->\nanother template\n");
    await expect(m.loadTemplate()).rejects.toThrow(/names template \x22decoy\x22, not \x22codex-reviewer\x22: it was altered or replaced/);
    put(own, "no header at all\n");
    await expect(m.loadTemplate()).rejects.toThrow(/is not a valid template \(prompt template lacks its/);
    rmSync(own);
    mkdirSync(own);
    expect(() => m.templatePath(NAME)).toThrow(/is not a regular file/);
  });

  it("a link out of the installation is refused: the whole prompts/ folder, or the template", async () => {
    // A folder link needs no privilege (a junction on Windows); a file link may (Developer Mode).
    const folder = await installRenderer();
    put(join(folder.base, "outside", NAME), TEMPLATE);
    symlinkSync(join(folder.base, "outside"), join(folder.pkg, "prompts"), "junction");
    await expect(folder.load().then((m) => m.templatePath(NAME))).rejects.toThrow(/leads outside its installation/);

    const file = await installRenderer();
    put(join(file.base, "outside", NAME), TEMPLATE);
    mkdirSync(join(file.pkg, "prompts"));
    try {
      symlinkSync(join(file.base, "outside", NAME), join(file.pkg, "prompts", NAME), "file");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EPERM") return; // no file links for this Windows account
      throw e;
    }
    await expect(file.load().then((m) => m.templatePath(NAME))).rejects.toThrow(/leads outside its installation/);
  });
});
