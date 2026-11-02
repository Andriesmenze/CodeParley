// A synthetic npm installation for the Phase 5 installation diagnostics (test/package-tools.test.ts):
// <base>/lib/node_modules/fakepkg, as a global npm install lays a package out, with one nested
// dependency, a module reached only by a dynamic import, one named only by a module URL, a
// re-export, a prompt template and a template lookup that walks up like CodeParley's own
// (src/prompts/render.ts).

import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tempDir, win } from "./git-fixture.js";

/** The temporary folders made through this module (fakeInstall, scratchDir), removed by removeScratch(). */
const made: string[] = [];

/** A temporary folder that removeScratch() removes. */
export async function scratchDir(prefix: string): Promise<string> {
  const dir = await tempDir(prefix);
  made.push(dir);
  return dir;
}

/** Remove every temporary folder made through this module (call it in afterAll). */
export function removeScratch(): void {
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
}

const RENDER_JS = [
  'import { existsSync } from "node:fs";',
  'import { dirname, join } from "node:path";',
  'import { fileURLToPath } from "node:url";',
  "export function templatePath(name) {",
  "  let dir = dirname(fileURLToPath(import.meta.url));",
  "  for (let i = 0; i < 6; i++) {",
  '    const p = join(dir, "prompts", name);',
  "    if (existsSync(p) && dir !== dirname(fileURLToPath(import.meta.url))) return p;",
  "    dir = dirname(dir);",
  "  }",
  '  throw new Error("prompt template " + name + " not found");',
  "}",
].join("\n");

const FILES: Record<string, string> = {
  "package.json": JSON.stringify({ name: "fakepkg", version: "1.0.0", type: "module", bin: { fake: "dist/cli/main.js" }, engines: { node: ">=18" }, dependencies: { "dep-a": "^1.2.0" } }),
  "dist/cli/main.js": '#!/usr/bin/env node\nimport { x } from "../lib/x.js";\nimport "dep-a";\nexport * from "../lib/y.js";\n',
  "dist/lib/x.js": 'export const x = 1;\nexport async function later() {\n  return import("./lazy.js");\n}\nexport const worker = new URL("./worker.js", import.meta.url);\n',
  "dist/lib/y.js": "export const y = 2;\n",
  "dist/lib/lazy.js": "export const lazy = 3;\n",
  "dist/lib/worker.js": "export {};\n",
  "dist/prompts/render.js": RENDER_JS,
  "prompts/t.md": "<!-- template: t version: 1 -->\nhello\n",
  "node_modules/dep-a/package.json": JSON.stringify({ name: "dep-a", version: "1.3.0", exports: { ".": "./index.js" } }),
  "node_modules/dep-a/index.js": "export default 1;\n",
};

/** Write the installation, then let `mutate(pkg, base)` damage it. */
export async function fakeInstall(mutate?: (pkg: string, base: string) => void): Promise<{ base: string; pkg: string }> {
  const base = await scratchDir("cp-inst-");
  const pkg = join(base, "lib", "node_modules", "fakepkg");
  for (const [rel, text] of Object.entries(FILES)) {
    const p = join(pkg, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  if (!win) chmodSync(join(pkg, "dist", "cli", "main.js"), 0o755);
  if (mutate) mutate(pkg, base);
  return { base, pkg };
}
