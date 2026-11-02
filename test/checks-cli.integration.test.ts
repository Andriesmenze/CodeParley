// `code-parley checks approve|list|revoke` and `lock show|release` (plan §14.2, §16.4,
// MR-C). Approval is CLI-only, shows exactly what will run, and is bound to the digest of
// what was shown.

import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { runCli, APPROVAL_STATEMENT } from "../src/cli/cli.js";
import { loadTrustProjects } from "../src/config/trusted-projects.js";
import { evaluateProject } from "../src/checks/project-config.js";
import { readRootCommit } from "../src/capture/root-commit.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { readWorktreeLock, type WorktreeLockInfo } from "../src/store/locks.js";
import { selfOwner } from "../src/store/owner.js";
import { approve, captureIo, makeFixture, type Fixture } from "./helpers/checks-fixture.js";
import { win, linux, supported, commitAll, gitExe, initRepo, tempDir, writeFiles } from "./helpers/git-fixture.js";

const cli = (f: Fixture, ...args: string[]) => {
  const io = captureIo();
  return runCli([...args, "--repo", f.repo, "--home", f.dataHome, "--git", f.git], io).then((code) => ({ code, out: io.lines.join("\n"), err: io.errors.join("\n"), io }));
};

const PROPOSALS = {
  proposed_checks: {
    unit: { argv: ["npm", "test", "--", "--grep", "a b&c"], env: { CI: "1" }, env_passthrough: ["NODE_OPTIONS"], freshness_inputs: ["node_modules/.package-lock.json"], timeout_seconds: 600 },
    lint: { argv: ["node", "scripts/pass.js", "lint"] },
  },
  proposed_profiles: { default: ["unit", "lint"] },
  // A repository cannot set the verification floor: this key is not read.
  required_profiles: [],
  no_required_checks: true,
};

async function withProposals(f: Fixture, body: unknown = PROPOSALS, dir = ".code-parley"): Promise<void> {
  await mkdir(join(f.repo, dir), { recursive: true });
  await writeFile(join(f.repo, dir, "config.json"), JSON.stringify(body));
}

describe.skipIf(!supported)("checks approve / list / revoke (CLI only)", () => {
  it("shows every definition and the approval statement, refuses without a user-chosen floor, and binds approval to the shown digest", async () => {
    const f = await makeFixture();
    await withProposals(f);

    // The repository's own "no_required_checks" is ignored: the user must choose the floor.
    const noFloor = await cli(f, "checks", "approve", "--from-proposals");
    expect(noFloor.code).toBe(1);
    expect(noFloor.err).toMatch(/verification floor is required/);

    const show = await cli(f, "checks", "approve", "--from-proposals", "--required-profile", "default");
    expect(show.code).toBe(2);
    expect(show.out).toContain(APPROVAL_STATEMENT);
    expect(show.out).toContain('argv:        ["npm","test","--","--grep","a b&c"]');
    // Windows: the npm.cmd shim through cmd.exe; Linux: the npm launcher script, run by its "#!" interpreter.
    expect(show.out).toMatch(
      win ? /resolves to: .*npm\.cmd \(batch file, run through cmd\.exe\)|resolves to: NOT RESOLVABLE NOW/ : /resolves to: \/.*\/npm \(script, run by its interpreter \(#!.*node\)\)|resolves to: NOT RESOLVABLE NOW/,
    );
    expect(show.out).toContain('env:         CI="1"');
    expect(show.out).toContain("passthrough: NODE_OPTIONS");
    expect(show.out).toContain("freshness:   node_modules/.package-lock.json");
    expect(show.out).toContain("verification floor: required profiles default");
    const digest = /approval digest: ([0-9a-f]{64})/.exec(show.out)![1]!;
    expect(show.out).toContain(`--confirm ${digest.slice(0, 16)}`);
    expect(await loadTrustProjects(f.trustProjectsPath)).toEqual({}); // nothing written yet

    const wrong = await cli(f, "checks", "approve", "--from-proposals", "--required-profile", "default", "--confirm", "0123456789abcdef");
    expect(wrong.code).toBe(2);
    expect(wrong.err).toMatch(/does not match/);

    // The repository changes its proposal between display and confirmation: refused.
    await withProposals(f, { ...PROPOSALS, proposed_checks: { ...PROPOSALS.proposed_checks, lint: { argv: ["cmd", "/c", "del", "/q", "*"] } } });
    const toctou = await cli(f, "checks", "approve", "--from-proposals", "--required-profile", "default", "--confirm", digest.slice(0, 16));
    expect(toctou.code).toBe(2);
    expect(await loadTrustProjects(f.trustProjectsPath)).toEqual({});

    await withProposals(f);
    const ok = await cli(f, "checks", "approve", "--from-proposals", "--required-profile", "default", "--confirm", digest.slice(0, 16));
    expect(ok.code).toBe(0);
    const projects = await loadTrustProjects(f.trustProjectsPath);
    const ev = evaluateProject(projects, f.repo, await readRootCommit({ gitExe: f.git, repoRoot: f.repo }));
    expect(ev.status).toBe("approved");
    expect(ev.approval?.digest).toBe(digest);
    expect(ev.approval?.via).toBe("cli");
    expect(ev.requiredProfiles).toEqual(["default"]);
    expect(ev.rootCommit).toMatch(/^[0-9a-f]{40}$/);
  }, 60_000);

  it("interactive approval requires typing 'approve'", async () => {
    const f = await makeFixture();
    await withProposals(f);
    const io = captureIo();
    io.prompt = async () => "yes";
    expect(await runCli(["checks", "approve", "--from-proposals", "--no-required-checks", "--repo", f.repo, "--home", f.dataHome, "--git", f.git], io)).toBe(2);
    io.prompt = async () => "approve";
    expect(await runCli(["checks", "approve", "--from-proposals", "--no-required-checks", "--repo", f.repo, "--home", f.dataHome, "--git", f.git], io)).toBe(0);
  }, 60_000);

  it("refuses invalid proposals (shell strings, unknown keys, secret passthrough)", async () => {
    const f = await makeFixture();
    await withProposals(f, { proposed_checks: { a: { argv: "npm test" }, b: { argv: ["x"], sandbox: false }, c: { argv: ["x"], env_passthrough: ["ANTHROPIC_API_KEY"] } }, proposed_profiles: { p: ["a"] } });
    const r = await cli(f, "checks", "approve", "--from-proposals", "--required-profile", "p");
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/a: argv/);
    expect(r.err).toMatch(/b: .*sandbox/);
    expect(r.err).toMatch(/ANTHROPIC_API_KEY/);
  }, 60_000);

  it("list reports status, problems, pending proposals and the lock; revoke removes the entry", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { lint: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["lint"] }, required_profiles: ["default"] });
    await withProposals(f);
    const l = await cli(f, "checks", "list");
    expect(l.code).toBe(0);
    expect(l.out).toMatch(/trusted configuration: approved/);
    expect(l.out).toMatch(/pending approval \(new\): unit/);
    expect(l.out).toMatch(/pending approval \(changed\): lint/);

    // A root-commit change (the path now holds a different repository) is reported.
    const trust = JSON.parse(await readFile(f.trustProjectsPath, "utf8"));
    const key = Object.keys(trust)[0]!;
    trust[key].root_commit = "f".repeat(40);
    await writeFile(f.trustProjectsPath, JSON.stringify(trust));
    expect((await cli(f, "checks", "list")).out).toMatch(/root_commit_mismatch/);

    const rv = await cli(f, "checks", "revoke");
    expect(rv.code).toBe(2);
    const token = /--confirm ([0-9a-f]{16})/.exec(rv.out)![1]!;
    expect((await cli(f, "checks", "revoke", "--confirm", token)).code).toBe(0);
    expect(await loadTrustProjects(f.trustProjectsPath)).toEqual({});
  }, 60_000);

  it("reads proposals from .code-parley/config.json, falls back to the legacy .ai-loop/config.json with a warning, and prefers the new file", async () => {
    const f = await makeFixture();
    await withProposals(f, PROPOSALS, ".ai-loop");
    const legacy = await cli(f, "checks", "list");
    expect(legacy.code).toBe(0);
    expect(legacy.out).toMatch(/pending approval \(new\): unit/);
    expect(legacy.out).toMatch(/proposal warning: repository preferences were read from the legacy location \.ai-loop\/config\.json; move them to \.code-parley\/config\.json/);

    await withProposals(f, { proposed_checks: { only: { argv: ["node", "scripts/pass.js"] } }, proposed_profiles: { p: ["only"] } });
    const both = await cli(f, "checks", "list");
    expect(both.out).toMatch(/pending approval \(new\): only/);
    expect(both.out).not.toMatch(/pending approval \(new\): unit/);
    expect(both.out).toMatch(/proposal warning: \.ai-loop\/config\.json is ignored because \.code-parley\/config\.json exists/);
  }, 60_000);

  it("a preferences file the user's exclusions classify as confidential is not read or printed by the CLI (PR #2 review)", async () => {
    const f = await makeFixture();
    await withProposals(f, { proposed_checks: { secret: { argv: ["node", "scripts/pass.js", "CONFIDENTIAL-ARGV-7d1"] } }, proposed_profiles: { p: ["secret"] } });
    await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ schema_version: 1, allowed_roots: [f.repo], capture: { exclude_globs: ["**/.env", "**/.code-parley/**"] } }));
    const list = await cli(f, "checks", "list");
    expect(list.code).toBe(0);
    expect(`${list.out}\n${list.err}`).not.toContain("CONFIDENTIAL-ARGV-7d1");
    expect(list.out).not.toMatch(/pending approval/);
    const approve = await cli(f, "checks", "approve", "--from-proposals", "--required-profile", "p");
    expect(approve.code).toBe(1);
    expect(`${approve.out}\n${approve.err}`).not.toContain("CONFIDENTIAL-ARGV-7d1");
  }, 60_000);

  it("approval is keyed by the worktree: a commit does not invalidate it, a new root commit does", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { lint: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["lint"] }, required_profiles: ["default"] });
    await writeFile(join(f.repo, "src", "app.js"), "module.exports = 3;\n");
    commitAll(f.repo, "more");
    expect((await cli(f, "checks", "list")).out).toMatch(/trusted configuration: approved/);
  }, 60_000);

  it("the root commit is null only for an unborn HEAD; a branch pointing at a missing commit fails loudly (PR #2 review)", async () => {
    const git = await gitExe();
    const unborn = await tempDir("cp-root-unborn-");
    await initRepo(unborn);
    expect(await readRootCommit({ gitExe: git, repoRoot: unborn })).toBeNull();

    const broken = await tempDir("cp-root-broken-");
    await initRepo(broken);
    await writeFiles(broken, { "a.txt": "a\n" });
    commitAll(broken, "first");
    const ref = (await readFile(join(broken, ".git", "HEAD"), "utf8")).trim().replace(/^ref: /, "");
    await writeFile(join(broken, ".git", ...ref.split("/")), `${"0".repeat(39)}1\n`); // no such commit
    await expect(readRootCommit({ gitExe: git, repoRoot: broken })).rejects.toThrow();
  }, 60_000);

  it("an approval bound to a root commit does not apply to an empty repository at the same path (PR #2 review)", async () => {
    const f = await makeFixture();
    await approve(f, { checks: { lint: { argv: ["node", "scripts/pass.js"] } }, profiles: { default: ["lint"] }, required_profiles: ["default"] });
    const projects = await loadTrustProjects(f.trustProjectsPath);
    expect(evaluateProject(projects, f.repo, null).status).toBe("root_commit_mismatch");
  }, 60_000);
});

describe.skipIf(!supported)("lock show / release (MR-C)", () => {
  async function plantLock(f: Fixture, info: Partial<WorktreeLockInfo>): Promise<string> {
    const p = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    await mkdir(join(f.dataHome, "locks"), { recursive: true });
    const now = new Date().toISOString();
    const full: WorktreeLockInfo = {
      owner: { serverInstanceId: "dead-server", pid: 999_999, startedAtMs: 1 },
      operation_id: "0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000",
      kind: "checks",
      acquired_at: now,
      heartbeat_at: now,
      command_lines: ["unit: [\"npm\",\"test\"]"],
      ownership_unresolved: true,
      ...info,
    };
    await writeFile(p, JSON.stringify(full));
    return p;
  }

  it("shows the recorded commands and releases only with the operation id after inspection", async () => {
    const f = await makeFixture();
    const p = await plantLock(f, { children: [{ pid: 999_998, startedAtMs: 1, command_line: "npm.cmd test", check: "unit" }] });
    const show = await cli(f, "lock", "show");
    expect(show.out).toMatch(/ownership unresolved: YES/);
    expect(show.out).toContain('recorded command: unit: ["npm","test"]');
    expect(show.out).toContain("recorded child: pid 999998");
    const noConfirm = await cli(f, "lock", "release");
    expect(noConfirm.code).toBe(2);
    expect(await readWorktreeLock(p)).not.toBeNull();
    const rel = await cli(f, "lock", "release", "--confirm", "0199aaaa-bbbb-7ccc");
    expect(rel.code).toBe(0);
    expect(await readWorktreeLock(p)).toBeNull();
  }, 60_000);

  it("refuses to release a lock held by a live owner", async () => {
    const f = await makeFixture();
    const p = await plantLock(f, { owner: selfOwner(), ownership_unresolved: false });
    const r = await cli(f, "lock", "release", "--confirm", "0199aaaa-bbbb-7ccc");
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/live/);
    expect(await readWorktreeLock(p)).not.toBeNull();
  }, 60_000);

  it("refuses while a recorded child (or its descendant) is still running, unless --force", async () => {
    const f = await makeFixture();
    const child = spawn(process.execPath, ["-e", "setTimeout(()=>{}, 60000)"], { stdio: "ignore", windowsHide: true });
    try {
      const startedAtMs = Date.now() - 500;
      await new Promise((r) => setTimeout(r, 300));
      const p = await plantLock(f, { children: [{ pid: child.pid!, startedAtMs, command_line: "node sleeper", check: "unit" }] });
      const r = await cli(f, "lock", "release", "--confirm", "0199aaaa-bbbb-7ccc");
      expect(r.code).toBe(1);
      expect(r.out).toMatch(new RegExp(`STILL RUNNING \\(recorded child\\): pid ${child.pid}`));
      expect(await readWorktreeLock(p)).not.toBeNull();
      expect((await cli(f, "lock", "release", "--confirm", "0199aaaa-bbbb-7ccc", "--force")).code).toBe(0);
    } finally {
      child.kill();
    }
  }, 60_000);

  it("refuses while a descendant of an exited recorded child runs (Windows: its parent link; Linux: the child's session)", async () => {
    const f = await makeFixture();
    const gcFile = join(f.scratch, "gc.pid");
    // Like every CodeParley child on Linux, the recorded child leads its own session; it starts
    // a grandchild in that session and exits. (Windows: the grandchild is detached, so it is not
    // in the child's kill-on-close job and outlives it, keeping the exited child's PID as parent.)
    const script = `const {spawn}=require('child_process');const g=spawn(process.execPath,['-e','setTimeout(()=>{},60000)'],{stdio:'ignore',windowsHide:true,detached:${win}});require('fs').writeFileSync(${JSON.stringify(gcFile)},String(g.pid));g.unref();`;
    const startedAtMs = Date.now() - 500;
    const child = spawn(process.execPath, ["-e", script], { stdio: "ignore", windowsHide: true, detached: linux });
    const exited = new Promise((r) => child.once("exit", r));
    await exited;
    const gc = Number(await readFile(gcFile, "utf8"));
    try {
      const p = await plantLock(f, { children: [{ pid: child.pid!, startedAtMs, command_line: "node spawner", check: "unit" }] });
      const r = await cli(f, "lock", "release", "--confirm", "0199aaaa-bbbb-7ccc");
      expect(r.code).toBe(1);
      expect(r.out).toContain(`STILL RUNNING (descendant of ${child.pid}): pid ${gc}`);
      expect(await readWorktreeLock(p)).not.toBeNull();
    } finally {
      process.kill(gc);
    }
  }, 60_000);
});
