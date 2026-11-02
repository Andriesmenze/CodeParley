// Build src/ for integration suites that run it in child processes (test servers,
// cross-process children). The output goes under .tmp-test-dist/ inside the repository, so the
// children resolve the repository's node_modules. No vitest imports: the global setup uses it.

import { spawnSync } from "node:child_process";
import { copyFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * Compile src/ into `outDir` (tsc, no declarations or source maps). Such a flat build is its own
 * installation root (src/prompts/render.ts reads templates only from the installation), so the
 * prompt templates go into its prompts/, beside the compiled renderer.
 */
export function buildSrc(repoRootDir: string, outDir: string): void {
  const tsc = join(repoRootDir, "node_modules", "typescript", "bin", "tsc");
  const r = spawnSync(process.execPath, [tsc, "-p", join(repoRootDir, "tsconfig.json"), "--outDir", outDir, "--sourceMap", "false", "--declaration", "false"], { cwd: repoRootDir, encoding: "utf8", windowsHide: true });
  if (r.status !== 0) throw new Error(`tsc failed: ${r.stdout}\n${r.stderr}`);
  for (const f of readdirSync(join(repoRootDir, "prompts"))) {
    if (f.endsWith(".md")) copyFileSync(join(repoRootDir, "prompts", f), join(outDir, "prompts", f));
  }
}
