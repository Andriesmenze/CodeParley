import { relative } from "node:path";
import { fileURLToPath } from "node:url";
import { configDefaults, defineConfig } from "vitest/config";
import { BaseSequencer, type TestSpecification } from "vitest/node";
import { excludedFiles, readDurations, startOrder, testFiles } from "./test/schedule.js";

const root = fileURLToPath(new URL(".", import.meta.url));

/** CI's sequencer: the files start in test/schedule.ts's order (no results cache on a CI runner). Locally vitest's own
 * order applies: previously failed files first, then the longest measured on this machine. */
function scheduledSequencer(order: (files: string[]) => string[]) {
  const rel = (spec: TestSpecification) => relative(root, spec.moduleId).replaceAll("\\", "/");
  return class ScheduledSequencer extends BaseSequencer {
    override async sort(specs: TestSpecification[]): Promise<TestSpecification[]> {
      const rank = new Map(order(specs.map(rel)).map((f, i) => [f, i]));
      return [...specs].sort((a, b) => (rank.get(rel(a)) ?? -1) - (rank.get(rel(b)) ?? -1));
    }
  };
}

export default defineConfig(({ mode }) => {
  // Step 6 (test/schedule.ts): CP_TEST_SHARD=<index>/<count> runs one CI shard, `--mode quick` (npm run test:quick)
  // the quick tier. Both only exclude files from the include pattern below; unset, the whole suite runs as before.
  const files = testFiles(root);
  const durations = readDurations(root);
  const excluded = excludedFiles(files, durations, process.platform, { shard: process.env["CP_TEST_SHARD"], quick: mode === "quick" });
  if (excluded.length > 0) {
    const what = mode === "quick" ? "quick tier" : `shard ${process.env["CP_TEST_SHARD"]}`;
    console.log(`test schedule: ${what}: ${files.length - excluded.length} of ${files.length} test files (${excluded.length} excluded)`);
  }
  return {
    test: {
      environment: "node",
      include: ["test/**/*.test.ts"],
      exclude: [...configDefaults.exclude, ...excluded],
      ...(process.env["CI"] ? { sequence: { sequencer: scheduledSequencer((f) => startOrder(f, durations, process.platform)) } } : {}),
      // Compiles src/ once per run for the suites that run it in child processes (M1.6-17).
      globalSetup: ["./test/global-setup.ts"],
      // The integration suites spawn many processes (git, node, PowerShell, test servers) per
      // test. Locally, leave half the cores to those children: oversubscription made per-test
      // time limits flaky on loaded development machines (M1.6). On CI (a dedicated runner) use
      // every core: GitHub's runners for private repositories have 2, where "50%" meant a single
      // worker and a fully serial run (M1.6-17). The limits below bound how long a hung test may
      // take; they are not assertions about the product (tests that assert durations do so
      // explicitly).
      // Phase 6 (TD, D-38): the local T1 runner keeps CI=true but caps the workers (CP_TEST_MAX_WORKERS=50%), because a
      // development machine is shared; GitHub's runs never set it and keep "100%".
      maxWorkers: process.env["CP_TEST_MAX_WORKERS"] ?? (process.env["CI"] ? "100%" : "50%"),
      testTimeout: 60_000,
      hookTimeout: 60_000,
    },
  };
});
