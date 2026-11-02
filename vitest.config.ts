import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
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
});
