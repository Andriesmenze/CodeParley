// Run-wide test setup (vitest globalSetup; M1.6-17). On every supported platform (Windows and
// Linux, where the suites that run src/ in child processes live), src/ is compiled ONCE per run — instead of once per suite — and the
// MCP test-server entry is written beside it before any worker starts (no suite rewrites it
// while another starts a server from it). Suites find it through test/helpers/compiled-src.ts;
// the teardown removes it.

import { mkdir, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { TestProject } from "vitest/node";
import { buildSrc } from "./helpers/build-src.js";
import { TEST_SERVER_SOURCE } from "./helpers/test-server-source.js";
import { TEST_HOOKS_SOURCE } from "./helpers/test-hooks-source.js";

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  if (process.platform !== "win32" && process.platform !== "linux") return async () => undefined;
  // Linux: fixtures create data homes and repositories with plain mkdir, so their modes follow
  // the umask, and CodeParley refuses a data home other users can write to. Ubuntu's default for
  // regular users is 002 (user private groups), which made every fixture home group-writable
  // and refused (native-Linux check, plan L-20). Pin 022 for the whole run — set here, before any
  // worker starts, so every worker inherits it. The product's own behaviour under 002 is tested
  // explicitly (linux-store.integration.test.ts).
  if (process.platform === "linux") process.umask(0o022);
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const outDir = join(root, ".tmp-test-dist", `run-${randomBytes(4).toString("hex")}`);
  await mkdir(outDir, { recursive: true });
  buildSrc(root, outDir);
  await writeFile(join(outDir, "test-server.mjs"), TEST_SERVER_SOURCE);
  await writeFile(join(outDir, "test-hooks.mjs"), TEST_HOOKS_SOURCE);
  project.provide("compiledSrcDir", outDir);
  return async () => {
    await rm(outDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => undefined);
  };
}
