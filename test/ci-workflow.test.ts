// Phase 6 Increment 1 (contract §4.2, §4.3): the CI workflow's security restrictions, pinned. CI runs with the default
// read-only token and nothing else (no secret, no signing key, no write permission), never on pull_request_target,
// with every action pinned to a full commit id, no container or Docker service, and every test job behind the identity
// job that verifies the commit and its signature. T1 runs the same steps locally (scripts/ci/run-workflow-local.mjs),
// so the parser it uses must read this workflow.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error -- a plain .mjs script without type declarations
import { parseJobs } from "../scripts/ci/run-workflow-local.mjs";

interface Step { name?: string; if?: string; shell?: string; run?: string; uses?: string; env: Record<string, string> }
interface Job { env: Record<string, string>; steps: Step[] }

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const text = readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8");
const code = text.split(/\r?\n/).filter((l) => !l.trimStart().startsWith("#")).join("\n");
const jobs = parseJobs(text) as Record<string, Job>;

describe("CI workflow restrictions (Phase 6 Increment 1)", () => {
  it("has read-only permissions, uses no secret and never runs on pull_request_target", () => {
    expect(code).toMatch(/^permissions:\n {2}contents: read\n/m);
    expect(code.match(/^\s*permissions:/gm)).toHaveLength(1);
    expect(code).not.toMatch(/\bsecrets\./);
    expect(code).not.toMatch(/pull_request_target/);
    expect(code).not.toMatch(/: write\b/);
    // D-38: the 50% worker cap is the local runner's; remote CI keeps its execution settings.
    expect(code).not.toMatch(/CP_TEST_MAX_WORKERS/);
  });

  it("pins every action to a full commit id and starts no container or Docker service", () => {
    const uses = [...code.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]!);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
    expect(code).not.toMatch(/^\s*(container|services):/m);
    expect(code).not.toMatch(/docker|--privileged/i);
  });

  it("puts every test job behind the identity job, on the commit it verified", () => {
    expect(Object.keys(jobs).sort()).toEqual(["identity", "test"]);
    expect(code).toMatch(/^ {2}test:\n(?: {4}.*\n)*? {4}needs: identity$/m);
    const verify = jobs["identity"]!.steps.find((s) => s.run?.includes("verify-commit-identity.mjs"));
    expect(verify?.run).toContain('--expect "$EXPECTED_SHA"');
    expect(jobs["test"]!.steps.filter((s) => s.uses?.startsWith("actions/checkout@"))).toHaveLength(1);
    expect(code).toMatch(/ref: \$\{\{ needs\.identity\.outputs\.sha \}\}/);
  });

  it("never restores or saves the npm cache on a manual run, and never caches automatically", () => {
    // setup-node caches when `cache` is non-empty, or, with package-manager-cache true, when package.json names npm.
    const setups = [...code.matchAll(/uses: actions\/setup-node@\S+.*\n {8}with:\n((?: {10}.*\n)+)/g)].map((m) => m[1]!);
    expect(setups).toHaveLength(2);
    for (const w of setups) expect(w).toMatch(/^ {10}package-manager-cache: false$/m);
    const caches = setups.flatMap((w) => [...w.matchAll(/^ {10}cache: (.*)$/gm)].map((m) => m[1]!));
    expect(caches).toEqual(["${{ github.event_name != 'workflow_dispatch' && 'npm' || '' }}"]);
    expect(code).not.toMatch(/actions\/cache@|^\s*cache-dependency-path:/m);
  });

  it("builds and self-tests both custodians with the pinned SDK, and runs the suite, the install smoke and the plugin check", () => {
    const steps = jobs["test"]!.steps;
    const run = (name: string) => steps.find((s) => s.name === name);
    expect(steps.find((s) => s.uses?.startsWith("actions/setup-dotnet@"))).toBeDefined();
    expect(code).toMatch(/global-json-file: custodian\/global\.json/);
    expect(run("Build the Windows custodian")).toMatchObject({ if: "runner.os == 'Windows'" });
    expect(run("Build the Linux custodian")).toMatchObject({ if: "runner.os == 'Linux'" });
    expect(run("Custodian self-tests (Windows)")?.run).toContain("--host windows");
    expect(run("Custodian self-tests (Linux)")?.run).toContain("--host linux");
    const order = steps.map((s) => s.name);
    expect(order.indexOf("Build the Windows custodian")).toBeLessThan(order.indexOf("Test"));
    expect(run("Test")?.run).toBe("npm test");
    expect(run("Install smoke test")?.run).toContain("scripts/package/smoke.mjs");
    expect(run("Plugin build and verification")?.run).toContain("verify-plugin.mjs");
  });
});
