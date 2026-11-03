// Phase 6 Increment 1 (contract §4.2, §4.3): the CI workflow's security restrictions, pinned. CI runs with the default
// read-only token and nothing else (no secret, no signing key, no write permission), never on pull_request_target,
// with every action pinned to a full commit id, no container or Docker service, and every test job behind the identity
// job that verifies the commit and its signature. T1 runs the same steps locally (scripts/ci/run-workflow-local.mjs),
// so the parser it uses must read this workflow.

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error -- a plain .mjs script without type declarations
import { parseJobs } from "../scripts/ci/run-workflow-local.mjs";
import { commitAll, initRepo, linux, setupEnv, tempDir, win } from "./helpers/git-fixture.js";

interface Step { name?: string; if?: string; shell?: string; run?: string; uses?: string; env: Record<string, string> }
interface Job { env: Record<string, string>; steps: Step[] }

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const text = readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8");
const code = text.split(/\r?\n/).filter((l) => !l.trimStart().startsWith("#")).join("\n");
const jobs = parseJobs(text) as Record<string, Job>;
const identityScript = join(root, "scripts", "ci", "verify-commit-identity.mjs");
// The bash GitHub's runners use for `shell: bash` (on Windows, Git for Windows' bash, as in the local runner).
const bash = win ? "C:/Program Files/Git/bin/bash.exe" : "bash";

/** How every job selects the commit under test: from the event alone. */
const SELECTED = "${{ github.event.pull_request.head.sha || github.sha }}";

/** The value of SELECTED for a `github` context: `a || b` takes the first non-empty operand, as GitHub does. */
function selectedBy(github: Record<string, unknown>): string {
  const operands = /^\$\{\{ (.+) \}\}$/.exec(SELECTED)![1]!.split(" || ");
  const value = (path: string) => path.split(".").slice(1).reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], github);
  return operands.map((p) => value(p)).find((v) => typeof v === "string" && v !== "") as string;
}

function runBash(script: string, cwd: string, env: Record<string, string>): { status: number | null; out: string } {
  const file = join(cwd, "step.sh");
  writeFileSync(file, `${script}\n`);
  const r = spawnSync(bash, ["--noprofile", "--norc", "-eo", "pipefail", file], { cwd, env: setupEnv(env), encoding: "utf8", windowsHide: true });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function identity(cwd: string, args: string[]): { status: number | null; out: string } {
  const r = spawnSync(process.execPath, [identityScript, ...args], { cwd, env: setupEnv(), encoding: "utf8", windowsHide: true, timeout: 120_000 });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

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

  it("puts every test job behind the identity job, which always verifies the commit and its signature", () => {
    expect(Object.keys(jobs).sort()).toEqual(["identity", "test"]);
    expect(code).toMatch(/^ {2}test:\n(?: {4}.*\n)*? {4}needs: identity$/m);
    const verify = jobs["identity"]!.steps.find((s) => s.run?.includes("verify-commit-identity.mjs"));
    expect(verify).toMatchObject({ env: { EXPECTED_SHA: SELECTED, REQUESTED_SHA: "${{ inputs.expected_sha }}" } });
    expect(verify?.if).toBeUndefined();
    expect(verify?.run).toContain('--expect "$EXPECTED_SHA" --requested "$REQUESTED_SHA" $MERGE');
    expect(code).not.toMatch(/continue-on-error/);
    // No command text carries an expression: inputs and outputs reach a command only through the environment.
    for (const job of Object.values(jobs)) for (const s of job.steps) expect(s.run ?? "").not.toContain("${{");
  });

  it("selects the commit from the event in both jobs, never from an input or a job output", () => {
    const refs = [...code.matchAll(/uses: actions\/checkout@\S+.*\n {8}with:\n((?: {10}.*\n)+)/g)].map((m) => /^ {10}ref: (.*)$/m.exec(m[1]!)?.[1]);
    expect(refs).toEqual([SELECTED, SELECTED]);
    // The only use of the manual run's input: the identity job's assertion.
    expect(code.match(/inputs\.expected_sha/g)).toHaveLength(1);
    expect(code.match(/needs\.identity\.outputs\.sha/g)).toHaveLength(1);
    // What the expression selects, per event (github.sha of a manual run is the head of the ref it was started on).
    const pr = { event: { pull_request: { head: { sha: "a".repeat(40) } } }, sha: "b".repeat(40) };
    expect(selectedBy(pr)).toBe("a".repeat(40));
    expect(selectedBy({ event: { ref: "refs/heads/main" }, sha: "c".repeat(40) })).toBe("c".repeat(40));
    expect(selectedBy({ event: { inputs: { expected_sha: "e".repeat(40) } }, sha: "d".repeat(40) })).toBe("d".repeat(40));
  });

  it("has every test job confirm, before running anything, that it checked out the commit the identity job verified", async () => {
    const steps = jobs["test"]!.steps;
    const at = steps.findIndex((s) => s.uses?.startsWith("actions/checkout@"));
    expect(steps.filter((s) => s.uses?.startsWith("actions/checkout@"))).toHaveLength(1);
    const confirm = steps[at + 1]!;
    expect(confirm).toMatchObject({ name: "Confirm the verified commit", shell: "bash", env: { VERIFIED_SHA: "${{ needs.identity.outputs.sha }}" } });
    expect(confirm.if).toBeUndefined();
    const repo = await initRepo(await tempDir("cp-ci-wf-"));
    try {
      const head = commitAll(repo);
      const run = (sha: string) => runBash(confirm.run!, repo, { VERIFIED_SHA: sha });
      expect(run(head).status).toBe(0);
      for (const other of ["f".repeat(40), ""]) {
        const r = run(other);
        expect(r.status).toBe(1);
        expect(r.out).toContain(`HEAD ${head} is not the commit the identity job verified`);
      }
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
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

// The identity check (scripts/ci/verify-commit-identity.mjs) on an unsigned fixture commit. A gpg that does not exist
// stands in for the key step: getting that far means the commit checks passed, and the script still stops there.
describe("CI commit identity check (Phase 6 Increment 1)", () => {
  const noGpg = ["--gpg", join(root, "no-such-gpg")];
  const realGpg = linux && spawnSync("gpg", ["--version"], { windowsHide: true }).status === 0;

  const withRepo = async (body: (repo: string, head: string) => void) => {
    const repo = await initRepo(await tempDir("cp-ci-id-"));
    try {
      body(repo, commitAll(repo));
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  };

  it("passes the commit checks when the requested commit is the selected one, or none is requested", async () => {
    await withRepo((repo, head) => {
      for (const requested of [head, head.toUpperCase(), ""]) {
        const r = identity(repo, ["--expect", head, "--requested", requested, ...noGpg]);
        expect(r.status).toBe(1);
        expect(r.out).toContain("commit identity: FAIL: no key in");
        expect(r.out).not.toMatch(/is not the (expected|requested) commit/);
      }
    });
  });

  it("fails closed, before the signature, when the requested commit is not the selected one", async () => {
    await withRepo((repo, head) => {
      // An input that looks like an option is a value like any other: it names no commit, so it fails.
      for (const requested of ["f".repeat(40), head.slice(0, 12), `${head} `, "--allow-github-merge"]) {
        const r = identity(repo, ["--expect", head, "--requested", requested, ...noGpg]);
        expect(r.status).toBe(1);
        expect(r.out).toContain(`commit identity: FAIL: HEAD ${head} is not the requested commit`);
        expect(r.out).not.toContain("no key in");
      }
      const r = identity(repo, ["--expect", "f".repeat(40), "--requested", head, ...noGpg]);
      expect(r.out).toContain(`commit identity: FAIL: HEAD ${head} is not the expected commit`);
    });
  });

  it.skipIf(!realGpg)("still requires the owner's signature when the commit checks pass (Linux, with gpg)", async () => {
    await withRepo((repo, head) => {
      const r = identity(repo, ["--expect", head, "--requested", head]);
      expect(r.status).toBe(1);
      expect(r.out).toContain(`commit identity: FAIL: ${head} is not signed by the owner's key`);
    });
  });
});
