// `code-parley runs list | show | stop | purge` and retention at server start (plan §5.1,
// §5.4, §15.5, §15.6, MR-E, MR-F, MR-J; M1.6). Windows: the store, junctions, process
// evidence and the server are exercised for real.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli } from "../src/cli/cli.js";
import { uuidv7 } from "../src/common/ids.js";
import { createRun, commitState, readState } from "../src/store/state-store.js";
import { canonicalPathKey, runPaths, worktreeLockPath, type RunPaths } from "../src/store/paths.js";
import { selfOwner } from "../src/store/owner.js";
import { newStateRecord, type RunState } from "../src/schemas/run-state.js";
import { isDomainError } from "../src/common/errors.js";
import { captureIo } from "./helpers/checks-fixture.js";
import { compileServer, removeCompiledServer, errorCode, sc, waitUntil, writeServerConfig } from "./helpers/mcp-harness.js";
import { mcpFixture, newRunOver, open, type McpFixture } from "./helpers/mcp-fixture.js";
import { gitExe, mklinkJunction, tempDir, win, supported } from "./helpers/git-fixture.js";

const DAY = 86_400_000;

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

async function cli(home: string, ...args: string[]): Promise<{ code: number; out: string; err: string }> {
  const io = captureIo();
  const code = await runCli([...args, "--home", home, "--git", await gitExe()], io);
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

async function stateOf(home: string, runId: string): Promise<{ state: string; operations: { operation_id: string; status: string }[]; events: { type: string; actor: string }[] }> {
  for (const k of await readdir(join(home, "runs"))) {
    const p = join(home, "runs", k, runId, "state.json");
    if (existsSync(p)) return JSON.parse(await readFile(p, "utf8"));
  }
  throw new Error("state.json not found");
}

// ---------------------------------------------------------------------------
// Synthetic runs for purge and retention
// ---------------------------------------------------------------------------

interface MadeRun {
  runId: string;
  paths: RunPaths;
}

async function makeRun(home: string, repo: string, o: { state?: RunState; ageDays?: number; ops?: { status: string; kind?: string; owner?: { serverInstanceId: string; pid: number; startedAtMs: number } }[] } = {}): Promise<MadeRun> {
  const runId = uuidv7();
  const paths = runPaths(home, canonicalPathKey(repo), runId);
  const at = new Date(Date.now() - (o.ageDays ?? 0) * DAY).toISOString();
  const st = newStateRecord(runId, o.state ?? "IDLE", at);
  st.operations = (o.ops ?? []).map((op) => ({ operation_id: uuidv7(), kind: op.kind ?? "checks", status: op.status, started_at: at, ...(op.owner ? { owner: op.owner } : {}) }));
  await createRun(paths, { schema_version: 1, run_id: runId, created_at: at, repository_root: repo, versions: {}, scope: { allowed_snapshot: [repo], client_roots_snapshot: [] }, envelope: { goal: "synthetic" } }, st);
  await mkdir(join(paths.opsDir, "op1"), { recursive: true });
  await writeFile(join(paths.opsDir, "op1", "result.json"), JSON.stringify({ filler: "x".repeat(2048) }));
  await mkdir(join(paths.exportsDir, "op1", "tree", "src"), { recursive: true });
  await writeFile(join(paths.exportsDir, "op1", "tree", "src", "a.js"), "module.exports = 1;\n");
  return { runId, paths };
}

const DEAD_OWNER = { serverInstanceId: "dead-server", pid: 999_999, startedAtMs: 1 };

describe.skipIf(!supported)("runs purge: preview, confirm, keep active/unresolved runs, never follow links", () => {
  it("deletes exactly what was previewed, keeps every active or unresolved run, and leaves link targets alone", async () => {
    const base = await tempDir("cp-purge-");
    const home = join(base, "home");
    const repo = join(base, "repo-x");
    const outside = join(base, "outside");
    await mkdir(outside, { recursive: true });
    await writeFile(join(outside, "canary.txt"), "must survive");

    const idle = await makeRun(home, repo, { ageDays: 40, ops: [{ status: "completed" }] });
    const closed = await makeRun(home, repo, { state: "CLOSED", ageDays: 45 });
    expect(mklinkJunction(join(closed.paths.runDir, "ops", "junction-out"), outside)).toBe(true);
    const interrupted = await makeRun(home, repo, { state: "INTERRUPTED", ageDays: 40, ops: [{ status: "interrupted" }] });
    const active = await makeRun(home, repo, { state: "CHECKING", ageDays: 40, ops: [{ status: "running", owner: DEAD_OWNER }] });
    const locked = await makeRun(home, repo, { ageDays: 40, ops: [{ status: "completed" }] });
    const lockedOp = (await readState(locked.paths)).operations[0]!.operation_id;
    await mkdir(join(home, "locks"), { recursive: true });
    await writeFile(worktreeLockPath(home, "0123456789abcdef"), JSON.stringify({ owner: DEAD_OWNER, operation_id: lockedOp, kind: "checks", acquired_at: new Date().toISOString(), heartbeat_at: new Date().toISOString(), ownership_unresolved: true }));
    const unreadable = await makeRun(home, repo, { ageDays: 40 });
    await writeFile(unreadable.paths.stateJson, "{ not json");
    const young = await makeRun(home, repo, { ageDays: 2 });
    // A run folder that is itself a junction to a directory outside the store.
    const realElsewhere = join(base, "elsewhere-run");
    const linkedId = uuidv7();
    await mkdir(realElsewhere, { recursive: true });
    await writeFile(join(realElsewhere, "keep.txt"), "outside the store");
    expect(mklinkJunction(join(home, "runs", canonicalPathKey(repo), linkedId), realElsewhere)).toBe(true);

    const preview = await cli(home, "runs", "purge", "--older-than", "30");
    expect(preview.code).toBe(2);
    expect(preview.out).toMatch(/would delete 2 run\(s\)/);
    expect(preview.out).toContain(idle.runId);
    expect(preview.out).toContain(closed.runId);
    for (const [r, code] of [[interrupted, "interrupted"], [active, "active_operation"], [locked, "worktree_lock"], [unreadable, "unreadable"]] as const) {
      expect(preview.out).toMatch(new RegExp(`${r.runId}[^\\n]*\\n\\s+${code}:`));
    }
    expect(preview.out).toMatch(new RegExp(`${linkedId}[^\\n]*\\n\\s+(link_in_store|unreadable):`));
    expect(preview.out).not.toContain(young.runId);
    const token = /--confirm ([0-9a-f]{16})/.exec(preview.out)![1]!;
    expect(existsSync(idle.paths.runDir) && existsSync(closed.paths.runDir)).toBe(true);

    expect((await cli(home, "runs", "purge", "--older-than", "30", "--dry-run")).code).toBe(0);
    const wrong = await cli(home, "runs", "purge", "--older-than", "30", "--confirm", "0000000000000000");
    expect(wrong.code).toBe(2);
    expect(existsSync(idle.paths.runDir)).toBe(true);

    expect(token).toMatch(/^[0-9a-f]{16}$/);

    // Windows: a file of the closed run is held open (an editor, antivirus): that run is left
    // untouched. (Linux renames and deletes open files; nothing is held.)
    if (win) {
      const held = join(closed.paths.opsDir, "op1", "result.json");
      const ps = spawn(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-Command", `$f=[System.IO.File]::Open('${held}','Open','Read','Read'); [Console]::Out.WriteLine('OPEN'); Start-Sleep -Seconds 10; $f.Close()`], { windowsHide: true });
      await new Promise<void>((res) => ps.stdout.on("data", (d: Buffer) => d.toString().includes("OPEN") && res()));
      const token2 = /--confirm ([0-9a-f]{16})/.exec((await cli(home, "runs", "purge", "--older-than", "30")).out)![1]!;
      const partial = await cli(home, "runs", "purge", "--older-than", "30", "--confirm", token2);
      expect(partial.code).toBe(1);
      expect(partial.out).toContain(`deleted ${idle.runId}`);
      expect(partial.out).toMatch(new RegExp(`NOT deleted ${closed.runId}: a file in the run is in use`));
      expect(existsSync(idle.paths.runDir)).toBe(false);
      expect(existsSync(join(closed.paths.runDir, "state.json"))).toBe(true);
      ps.kill();
      await new Promise((r) => ps.on("exit", r));
    }

    const token3 = /--confirm ([0-9a-f]{16})/.exec((await cli(home, "runs", "purge", "--older-than", "30")).out)![1]!;
    const done = await cli(home, "runs", "purge", "--older-than", "30", "--confirm", token3);
    expect(done.code).toBe(0);
    expect(existsSync(idle.paths.runDir)).toBe(false);
    expect(existsSync(closed.paths.runDir)).toBe(false);
    // The junction inside the run was removed as a link: its target is untouched.
    expect(await readFile(join(outside, "canary.txt"), "utf8")).toBe("must survive");
    // Kept runs, the young run and the linked folder's real target are all still there.
    for (const r of [interrupted, active, locked, unreadable, young]) expect(existsSync(r.paths.runDir)).toBe(true);
    expect(await readFile(join(realElsewhere, "keep.txt"), "utf8")).toBe("outside the store");
    // No tombstones are left behind.
    expect((await readdir(join(home, "runs", ".trash")).catch(() => [])).length).toBe(0);

    // A run that changes between the preview and the confirmation is not deleted (explicit id:
    // the token binds the revision shown).
    const extra = await makeRun(home, repo, { state: "CLOSED", ageDays: 50 });
    const t4 = /--confirm ([0-9a-f]{16})/.exec((await cli(home, "runs", "purge", extra.runId)).out)![1]!;
    await commitState(extra.paths, selfOwner(), (st) => st);
    const stale = await cli(home, "runs", "purge", extra.runId, "--confirm", t4);
    expect(stale.code).toBe(2);
    expect(stale.err).toMatch(/does not match/);
    expect(existsSync(extra.paths.runDir)).toBe(true);
    const t5 = /--confirm ([0-9a-f]{16})/.exec((await cli(home, "runs", "purge", extra.runId)).out)![1]!;
    expect((await cli(home, "runs", "purge", extra.runId, "--confirm", t5)).code).toBe(0);
    expect(existsSync(extra.paths.runDir)).toBe(false);
  }, 120_000);

  it("explicit ids are still subject to the safety rules; leftover tombstones are retried", async () => {
    const base = await tempDir("cp-purge2-");
    const home = join(base, "home");
    const repo = join(base, "repo-y");
    const active = await makeRun(home, repo, { state: "REVIEWING", ops: [{ status: "running", kind: "review", owner: selfOwner() }] });
    const tomb = join(home, "runs", ".trash", `${uuidv7()}.0a1b2c3d`);
    await mkdir(join(tomb, "deep"), { recursive: true });
    await writeFile(join(tomb, "deep", "left.txt"), "left over");
    const p = await cli(home, "runs", "purge", active.runId.slice(0, 8));
    expect(p.out).toMatch(/would delete 0 run\(s\)/);
    expect(p.out).toMatch(/active_operation/);
    expect(p.out).toMatch(/1 leftover item\(s\)/);
    const token = /--confirm ([0-9a-f]{16})/.exec(p.out)![1]!;
    const r = await cli(home, "runs", "purge", active.runId.slice(0, 8), "--confirm", token);
    expect(r.out).toMatch(/cleaned 1 leftover item/);
    expect(existsSync(tomb)).toBe(false);
    expect(existsSync(active.paths.runDir)).toBe(true);
    // Selection is required; an unknown id is RUN_NOT_FOUND.
    expect((await cli(home, "runs", "purge")).code).toBe(1);
    expect((await cli(home, "runs", "purge", "01a10737-0000-7000-8000-000000000000")).err).toMatch(/RUN_NOT_FOUND/);
  }, 60_000);

  it("a trash directory that is a link is neither cleaned nor used (M1.6-13)", async () => {
    const base = await tempDir("cp-purge4-");
    const home = join(base, "home");
    const old = await makeRun(home, join(base, "repo-t"), { state: "CLOSED", ageDays: 40 });
    // runs\.trash redirected to a folder outside the store holding a tombstone-named folder.
    const outside = join(base, "outside-trash");
    const victim = join(outside, `${uuidv7()}.0a1b2c3d`);
    await mkdir(victim, { recursive: true });
    await writeFile(join(victim, "keep.txt"), "outside the store");
    expect(mklinkJunction(join(home, "runs", ".trash"), outside)).toBe(true);
    const token = /--confirm ([0-9a-f]{16})/.exec((await cli(home, "runs", "purge", old.runId)).out)![1]!;
    const r = await cli(home, "runs", "purge", old.runId, "--confirm", token);
    expect(r.out).toMatch(/the trash directory is a link/);
    expect(await readFile(join(victim, "keep.txt"), "utf8")).toBe("outside the store");
    expect(existsSync(join(old.paths.runDir, "state.json"))).toBe(true);
  }, 60_000);

  it("a run whose capture record is missing: list withholds its goal, show fails closed unless --reveal-withheld (M1.6-15)", async () => {
    const base = await tempDir("cp-missing-rec-");
    const home = join(base, "home");
    const r = await makeRun(home, join(base, "repo-m"), { ops: [{ status: "completed", kind: "prepare" }] });
    // The state refers to a capture record that does not exist (damage, an editor, antivirus).
    await commitState(r.paths, selfOwner(), (st) => {
      st.operations[0]!.outcome = { capture_ref: "ops/op1/capture.json" };
      return st;
    });
    const list = await cli(home, "runs", "list");
    expect(list.code).toBe(0);
    expect(list.out).toContain(r.runId);
    expect(list.out).toMatch(/goal: \[withheld: a capture record of this run is missing/);
    expect(list.out).not.toContain("synthetic");
    const show = await cli(home, "runs", "show", r.runId);
    expect(show.code).toBe(1);
    expect(show.err).toMatch(/capture record of this run is missing or unreadable/);
    const reveal = await cli(home, "runs", "show", r.runId, "--reveal-withheld");
    expect(reveal.code).toBe(0);
    expect(reveal.out).toMatch(/its withheld paths cannot be listed/);
  }, 60_000);

  it("a purged run is never recreated by a late writer (the run lock does not create missing parents)", async () => {
    const base = await tempDir("cp-purge3-");
    const home = join(base, "home");
    const r = await makeRun(home, join(base, "repo-z"), { ageDays: 40 });
    const token = /--confirm ([0-9a-f]{16})/.exec((await cli(home, "runs", "purge", r.runId)).out)![1]!;
    expect((await cli(home, "runs", "purge", r.runId, "--confirm", token)).code).toBe(0);
    const late = await commitState(r.paths, selfOwner(), (st) => st).then(
      () => "committed",
      (e: unknown) => (isDomainError(e) ? e.code : String(e)),
    );
    expect(late).toBe("RUN_NOT_FOUND");
    expect(existsSync(r.paths.runDir)).toBe(false);
  }, 60_000);

  it.runIf(process.platform === "linux")("--repo follows the Linux name rules: paths that differ only in case are two repositories", async () => {
    const base = await realpath(await tempDir("cp-case-"));
    const home = join(base, "home");
    const upper = join(base, "Repo");
    const lower = join(base, "repo");
    await mkdir(upper, { recursive: true });
    await mkdir(lower, { recursive: true });
    const a = await makeRun(home, upper, { ageDays: 40, ops: [{ status: "completed" }] });
    const b = await makeRun(home, lower, { ageDays: 40, ops: [{ status: "completed" }] });
    const list = JSON.parse((await cli(home, "runs", "list", "--repo", upper, "--json")).out) as { runs: { run_id: string }[] };
    expect(list.runs.map((r) => r.run_id)).toEqual([a.runId]);
    const preview = await cli(home, "runs", "purge", "--older-than", "30", "--repo", lower);
    expect(preview.out).toContain(b.runId);
    expect(preview.out).not.toContain(a.runId);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// list / show / stop over a real server
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("runs list / show (CLI view; MR-F)", () => {
  it("lists and shows a run from its records, redacting withheld names and never printing check output", async () => {
    const f: McpFixture = await mcpFixture();
    const c = await open(f, "v2-legacy");
    let runId: string;
    try {
      runId = await newRunOver(c, f, { task_envelope: { goal: "Review the add() change; leave .env alone" } });
      sc(await c.call("run_checks", { run_id: runId, wait_seconds: 40 }));
      const rv = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 40 }));
      if (rv["status"] === "running") await waitUntil(async () => (await stateOf(f.dataHome, runId)).state === "IDLE", 60_000);
    } finally {
      await c.close();
    }
    const list = await cli(f.dataHome, "runs", "list");
    expect(list.code).toBe(0);
    expect(list.out).toContain(runId.slice(0, 8));
    expect(list.out).toMatch(/goal: Review the add\(\) change; leave \[withheld path\] alone/);
    expect(list.out).not.toContain(".env");
    const listJson = JSON.parse((await cli(f.dataHome, "runs", "list", "--json")).out) as { runs: { run_id: string; state: string }[] };
    expect(listJson.runs.map((r) => r.run_id)).toContain(runId);

    const show = await cli(f.dataHome, "runs", "show", runId.slice(0, 8));
    expect(show.code).toBe(0);
    expect(show.out).toContain(`run ${runId}`);
    expect(show.out).toMatch(/check executions:\n\s+unit: passed/);
    expect(show.out).toMatch(/stdout: \d+ byte\(s\)/);
    expect(show.out).toMatch(/round 1 [0-9a-f]{8}: completed/);
    expect(show.out).toMatch(/\[open\] /);
    expect(show.out).toMatch(/path\(s\) are withheld as confidential/);
    expect(show.out).not.toContain("CHECK_STDOUT_TOKEN_9f2");
    expect(show.out).not.toContain(".env");
    expect(show.out).not.toContain("SECRET_ENV_VALUE");

    const reveal = await cli(f.dataHome, "runs", "show", runId, "--reveal-withheld");
    expect(reveal.out).toMatch(/withheld \(confidential\) paths — local view/);
    expect(reveal.out).toContain(".env");
    expect(reveal.out).not.toContain("CHECK_STDOUT_TOKEN_9f2");

    const j = JSON.parse((await cli(f.dataHome, "runs", "show", runId, "--json")).out) as { withheld: { count: number; paths: unknown }; operations: unknown[] };
    expect(j.withheld.count).toBeGreaterThanOrEqual(1);
    expect(j.withheld.paths).toBeNull();
    expect(j.operations.length).toBeGreaterThanOrEqual(3);
  }, 180_000);
});

describe.skipIf(!supported)("runs stop: stop_review_loop semantics from the CLI (MR-E, MR-J)", () => {
  it("cancels exactly the named operation of another process, reports already_finished on a retry, never touches a newer operation, and the CLI exits", async () => {
    const f = await mcpFixture();
    const owner = await open(f, "v2-legacy");
    try {
      const runId = await newRunOver(owner, f);
      const a = sc(await owner.call("run_checks", { run_id: runId, checks: ["slow"], wait_seconds: 1 }));
      expect(a["status"]).toBe("running");
      const opA = a["operation_id"] as string;

      expect((await cli(f.dataHome, "runs", "stop", runId)).err).toMatch(/--operation <operation-id> is required/);

      // An ambiguous operation prefix is refused (UUIDv7 prefixes are timestamps and collide).
      const sameMinute = (await stateOf(f.dataHome, runId)).operations.filter((o) => o.operation_id.startsWith(opA.slice(0, 8))).length > 1;
      if (sameMinute) expect((await cli(f.dataHome, "runs", "stop", runId, "--operation", opA.slice(0, 8))).err).toMatch(/matches 2 operations/);

      const stopA = await cli(f.dataHome, "runs", "stop", runId.slice(0, 8), "--operation", opA, "--reason", "cli test");
      expect([0, 3]).toContain(stopA.code);
      expect(stopA.out).toMatch(/operation status cancelled/);
      expect(stopA.out).toMatch(/: (terminated|cancellation_requested) /);
      const st = await stateOf(f.dataHome, runId);
      expect(st.events.find((e) => e.type === "operation.cancel_requested")?.actor).toBe("user_cli");

      const b = sc(await owner.call("run_checks", { run_id: runId, checks: ["slow2"], wait_seconds: 1 }));
      expect(b["status"]).toBe("running");
      const retry = await cli(f.dataHome, "runs", "stop", runId, "--operation", opA);
      expect(retry.code).toBe(0);
      expect(retry.out).toMatch(/already_finished/);
      expect((await stateOf(f.dataHome, runId)).operations.find((o) => o.operation_id === b["operation_id"])!.status).toBe("running");
      const mismatch = await cli(f.dataHome, "runs", "stop", runId, "--operation", "01a10737-0000-7000-8000-000000000000");
      expect(mismatch.code).toBe(1);
      expect(mismatch.err).toMatch(/OPERATION_MISMATCH/);
      expect((await cli(f.dataHome, "runs", "stop", runId, "--close")).err).toMatch(/RUN_BUSY/);

      // The real CLI process: abort cancels B, ends the run, and the process exits promptly
      // (its cross-process wait stops with the bounded wait).
      const dist = await compileServer();
      const t0 = Date.now();
      const r = spawnSync(process.execPath, [join(dist, "cli", "main.js"), "runs", "stop", runId, "--abort", "--wait", "20", "--home", f.dataHome, "--git", await gitExe()], { encoding: "utf8", timeout: 90_000, windowsHide: true });
      expect(r.error).toBeUndefined();
      expect([0, 3]).toContain(r.status);
      expect(r.stdout).toMatch(/run state: STOPPED/);
      expect(Date.now() - t0).toBeLessThan(60_000);
      expect(errorCode(await owner.call("run_checks", { run_id: runId }))).toBe("RUN_TERMINAL");
    } finally {
      await owner.close();
    }
  }, 180_000);
});

// ---------------------------------------------------------------------------
// Retention at server start
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("retention at server start (trusted configuration)", () => {
  it("deletes old idle/closed runs, keeps interrupted/active/young ones, records the pass, and never blocks serving", async () => {
    const f = await mcpFixture();
    const repo = f.repo;
    const old = await makeRun(f.dataHome, repo, { state: "CLOSED", ageDays: 40 });
    const interrupted = await makeRun(f.dataHome, repo, { state: "INTERRUPTED", ageDays: 40, ops: [{ status: "interrupted" }] });
    const young = await makeRun(f.dataHome, repo, { state: "CLOSED", ageDays: 3 });
    await mkdir(join(f.dataHome, "logs"), { recursive: true });
    await writeFile(join(f.dataHome, "logs", "server-2020-01-01.log"), "old log\n");
    const cfg = await writeServerConfig(f.scratch, { argv: f.argv, fake: { script: f.fakeScript }, retentionDelayMs: 200 });
    const { connect } = await import("./helpers/mcp-harness.js");
    const c = await connect("v2-legacy", cfg);
    try {
      // Serving is not delayed by retention.
      expect(sc(await c.call("get_review_status", {}))["summary"]).toMatch(/run\(s\)/);
      expect(await waitUntil(() => existsSync(join(f.dataHome, "logs", "retention-last.json")), 30_000)).toBe(true);
    } finally {
      await c.close();
    }
    expect(existsSync(old.paths.runDir)).toBe(false);
    expect(existsSync(interrupted.paths.runDir)).toBe(true);
    expect(existsSync(young.paths.runDir)).toBe(true);
    expect(existsSync(join(f.dataHome, "logs", "server-2020-01-01.log"))).toBe(false);
    const summary = JSON.parse(await readFile(join(f.dataHome, "logs", "retention-last.json"), "utf8")) as { deleted: { run_id: string }[]; kept: { run_id: string; code: string }[]; error: string | null };
    expect(summary.deleted.map((d) => d.run_id)).toEqual([old.runId]);
    expect(summary.kept).toContainEqual(expect.objectContaining({ run_id: interrupted.runId, code: "interrupted" }));
    expect(summary.error).toBeNull();
    const logs = (await readdir(join(f.dataHome, "logs"))).filter((n) => n.startsWith("server-"));
    const text = (await Promise.all(logs.map((n) => readFile(join(f.dataHome, "logs", n), "utf8")))).join("");
    expect(text).toMatch(/retention \(30 days\): deleted 1 run\(s\)/);
  }, 120_000);

  it("purge_on_startup false keeps everything; a live retention lock holder makes other servers skip", async () => {
    const f = await mcpFixture({ config: { retention: { max_age_days: 30, purge_on_startup: false } } });
    const old = await makeRun(f.dataHome, f.repo, { state: "CLOSED", ageDays: 40 });
    const cfg = await writeServerConfig(f.scratch, { argv: f.argv, fake: { script: f.fakeScript }, retentionDelayMs: 100 });
    const { connect } = await import("./helpers/mcp-harness.js");
    const serverLog = async (): Promise<string> =>
      (await Promise.all((await readdir(join(f.dataHome, "logs")).catch(() => [] as string[])).filter((n) => n.startsWith("server-")).map((n) => readFile(join(f.dataHome, "logs", n), "utf8")))).join("");
    const c = await connect("v2-legacy", cfg);
    expect(await waitUntil(async () => /retention: disabled/.test(await serverLog()), 30_000)).toBe(true);
    await c.close();
    expect(existsSync(old.paths.runDir)).toBe(true);

    // Re-enable, but hold the store-wide retention lock as a live owner (this process).
    await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ schema_version: 1, retention: { max_age_days: 30 } }));
    await mkdir(join(f.dataHome, "locks"), { recursive: true });
    await writeFile(join(f.dataHome, "locks", "retention.lock"), JSON.stringify({ owner: selfOwner(), operation_id: "retention-test", kind: "retention", acquired_at: new Date().toISOString(), heartbeat_at: new Date().toISOString() }));
    const c2 = await connect("v2-legacy", cfg);
    expect(await waitUntil(async () => /retention: skipped \(another server is applying retention\)/.test(await serverLog()), 30_000)).toBe(true);
    await c2.close();
    expect(existsSync(old.paths.runDir)).toBe(true);
  }, 120_000);
});
