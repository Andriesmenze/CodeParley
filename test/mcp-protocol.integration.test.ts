// MCP protocol behaviour over real stdio (plan §11, §18.1, MR-F, MR-H, T1/T2/T13; M1.5):
// both protocol eras and client runtimes, stdout purity, stdin-close exit, working-directory
// and environment independence, malformed input and domain errors, spoofed engine-owned
// evidence, attempts to widen roots or lower verification, strict client roots, and the
// confidentiality boundary of every host result.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { compileServer, removeCompiledServer, errorCode, FLAVORS, sc, type Flavor } from "./helpers/mcp-harness.js";
import { mcpFixture, newRunOver, open, type McpFixture } from "./helpers/mcp-fixture.js";
import { defect, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { commitAll, initRepo, tempDir, win, supported, writeFiles } from "./helpers/git-fixture.js";

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

async function runCount(f: McpFixture): Promise<number> {
  const runs = join(f.dataHome, "runs");
  if (!existsSync(runs)) return 0;
  let n = 0;
  for (const k of await readdir(runs)) n += (await readdir(join(runs, k))).length;
  return n;
}

describe.skipIf(!supported)("protocol eras and transport (P1, P5, P7, K1)", () => {
  it("every client runtime sees the same tool list; the era is pinned per connection", async () => {
    const f = await mcpFixture();
    const lists: string[] = [];
    for (const flavor of FLAVORS) {
      const c = await open(f, flavor);
      try {
        const tools = await c.listTools();
        lists.push(JSON.stringify(tools.map((t) => ({ name: t.name, annotations: t.annotations, inputSchema: t.inputSchema }))));
        const diag = sc(await c.call("diag_echo", {}));
        expect((diag["protocol"] as { version: string; era: string }).era).toBe(flavor === "v2-modern" ? "modern" : "legacy");
        expect((diag["client"] as { info: { name: string } }).info.name).toBe(flavor === "v1" ? "arl-test-v1" : "arl-test-v2");
      } finally {
        await c.close();
      }
    }
    expect(new Set(lists).size).toBe(1);
    expect(JSON.parse(lists[0]!).map((t: { name: string }) => t.name)).toEqual(["create_review_run", "run_checks", "review_with_codex", "get_review_status", "get_review_history", "respond_to_review", "start_review_loop", "stop_review_loop", "delegate_fix", "apply_fix", "diag_echo"]);
  }, 120_000);

  it("stdout carries only JSON-RPC messages; the server runs from any cwd with a host-like limited environment and exits when stdin closes", async () => {
    const f = await mcpFixture();
    const dir = await compileServer();
    const elsewhere = await tempDir("arl-cwd-");
    // The SDK's default inherited set (C3): what a host like Desktop passes.
    const env: Record<string, string> = { CODEPARLEY_TEST_SERVER_CONFIG: f.cfgPath };
    const inherited = win
      ? ["APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERNAME", "USERPROFILE", "PROGRAMFILES"]
      : ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"];
    for (const k of inherited) if (process.env[k]) env[k] = process.env[k]!;
    const child = spawn(process.execPath, [join(dir, "test-server.mjs")], { cwd: elsewhere, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    const exited = new Promise<number | null>((res) => child.on("exit", (code) => res(code)));
    const send = (m: unknown) => child.stdin.write(JSON.stringify(m) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "raw", version: "1" } } });
    await new Promise((r) => setTimeout(r, 500));
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "create_review_run", arguments: { task_envelope: { goal: "g" }, repository_root: f.repo, wait_seconds: 30 } } });
    send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "run_checks", arguments: { run_id: "../../etc" } } });
    send({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "no_such_tool", arguments: {} } });
    const deadline = Date.now() + 60_000;
    // Requests still in flight when stdin closes are aborted unanswered (stdio binding), so
    // wait for every response before closing.
    while (Date.now() < deadline && ![1, 2, 3, 4, 5].every((id) => stdout.includes(`"id":${id}`))) await new Promise((r) => setTimeout(r, 100));
    child.stdin.end();
    const code = await Promise.race([exited, new Promise<"timeout">((r) => setTimeout(() => r("timeout"), 20_000))]);
    expect(code).toBe(0);
    const lines = stdout.split("\n").filter((l) => l.trim());
    expect(lines.length).toBeGreaterThanOrEqual(5);
    for (const l of lines) {
      const m = JSON.parse(l) as { jsonrpc: string };
      expect(m.jsonrpc).toBe("2.0");
    }
    const byId = new Map(lines.map((l) => JSON.parse(l) as { id?: number; result?: { structuredContent?: Record<string, unknown>; isError?: boolean } }).filter((m) => m.id !== undefined).map((m) => [m.id!, m]));
    expect((byId.get(3)!.result!.structuredContent!["prepare"] as { status: string }).status).toBe("completed");
    expect(byId.get(4)!.result!.isError).toBe(true);
    expect((byId.get(4)!.result!.structuredContent!["error"] as { code: string }).code).toBe("INVALID_ARGUMENT");
    expect(byId.get(5)!.result!.isError).toBe(true);
    // Nothing was written into the working directory the server was started from.
    expect(await readdir(elsewhere)).toEqual([]);
  }, 120_000);
});

describe.skipIf(!supported)("malformed input and domain errors (P5: isError with structuredContent)", () => {
  for (const flavor of ["v2-legacy", "v2-modern"] as Flavor[]) {
    it(`${flavor}: invalid arguments and domain errors are structured, with stable codes`, async () => {
      const f = await mcpFixture();
      const c = await open(f, flavor);
      try {
        const cases: [string, Record<string, unknown>, string][] = [
          ["create_review_run", {}, "INVALID_ARGUMENT"],
          ["create_review_run", { task_envelope: { goal: "" } }, "INVALID_ARGUMENT"],
          ["create_review_run", { task_envelope: { goal: "g" }, wait_seconds: "soon" }, "INVALID_ARGUMENT"],
          ["run_checks", { run_id: "..\\..\\Windows" }, "INVALID_ARGUMENT"],
          ["run_checks", { run_id: "01a10737-5c4b-7bd1-9ca4-57bf27dd42dc" }, "RUN_NOT_FOUND"],
          ["review_with_codex", { run_id: "x", depth: "extreme" }, "INVALID_ARGUMENT"],
          ["stop_review_loop", { run_id: "01a10737-5c4b-7bd1-9ca4-57bf27dd42dc", mode: "finalize" }, "INVALID_ARGUMENT"],
          ["get_review_history", { run_id: "01a10737-5c4b-7bd1-9ca4-57bf27dd42dc", limit: 1000 }, "INVALID_ARGUMENT"],
          ["no_such_tool", {}, "INVALID_ARGUMENT"],
        ];
        for (const [tool, args, code] of cases) {
          const r = await c.call(tool, args);
          expect(errorCode(r), `${tool} ${JSON.stringify(args)}`).toBe(code);
          const s = sc(r);
          expect(s["summary"]).toEqual(expect.stringContaining(code));
          expect((s["error"] as { retryable: boolean }).retryable).toEqual(expect.any(Boolean));
        }
        const runId = await newRunOver(c, f);
        expect(errorCode(await c.call("stop_review_loop", { run_id: runId, mode: "cancel_active" }))).toBe("INVALID_ARGUMENT"); // MR-E: expected id required
        expect(errorCode(await c.call("run_checks", { run_id: runId, checks: ["nope"] }))).toBe("CHECK_NOT_APPROVED");
        expect(errorCode(await c.call("run_checks", { run_id: runId, profiles: ["nope"] }))).toBe("UNKNOWN_PROFILE");
      } finally {
        await c.close();
      }
    }, 120_000);
  }

  it("spoofed engine-owned evidence is refused before anything happens", async () => {
    const f = await mcpFixture();
    const c = await open(f, "v2-modern");
    try {
      const spoof = { diff: "--- a\n+++ b", files: [{ path: "src/math.js", content: "x" }], manifest: {}, check_results: [{ check: "unit", status: "passed" }], findings: [], history: [], isolation: { mode: "S1" }, allowed_roots: ["C:\\"], security_roots: ["C:\\"] };
      for (const [k, v] of Object.entries(spoof)) {
        expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, [k]: v })), k).toBe("INVALID_ARGUMENT");
      }
      expect(await runCount(f)).toBe(0);
      const runId = await newRunOver(c, f);
      for (const [k, v] of Object.entries(spoof)) {
        expect(errorCode(await c.call("run_checks", { run_id: runId, [k]: v })), k).toBe("INVALID_ARGUMENT");
        expect(errorCode(await c.call("review_with_codex", { run_id: runId, [k]: v })), k).toBe("INVALID_ARGUMENT");
      }
      const st = sc(await c.call("get_review_status", { run_id: runId }));
      expect((st["budgets"] as { name: string; used: number }[]).every((b) => b.used === 0)).toBe(true);
    } finally {
      await c.close();
    }
  }, 120_000);
});

describe.skipIf(!supported)("scope: configured roots are the only authority (D-03, T2)", () => {
  it("repository_root outside the allowed roots, the data home, relative paths and client roots cannot widen scope", async () => {
    const f = await mcpFixture();
    const other = await tempDir("arl-other-");
    await initRepo(join(other, "repo"));
    await writeFiles(join(other, "repo"), { "a.txt": "a\n" });
    commitAll(join(other, "repo"), "init");
    // The client advertises only the OUTSIDE repository as its root.
    const c = await open(f, "v2-legacy", { roots: [join(other, "repo")] });
    try {
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: join(other, "repo") }))).toBe("SCOPE_REPO_ROOT_OUTSIDE_ALLOWED");
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: "repo" }))).toBe("INVALID_PATH");
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.dataHome }))).toMatch(/NOT_A_GIT_WORKTREE|SCOPE_REPO_ROOT_OUTSIDE_ALLOWED/);
      // No repository_root: the only client root is outside the allowed roots → not selected.
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" } }))).toBe("REPOSITORY_NOT_SPECIFIED");
      expect(await runCount(f)).toBe(0);
      // Advisory mode: a run inside the allowed roots works, with a warning about the session roots.
      const r = sc(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, wait_seconds: 30 }));
      expect((r["warnings"] as { code: string }[]).map((w) => w.code)).toContain("REPO_OUTSIDE_SESSION_ROOTS");
    } finally {
      await c.close();
    }
  }, 120_000);

  it("a removed allowed root revokes the run at its next operation (MR-H step 1/3); stop stays allowed", async () => {
    const f = await mcpFixture({ allowedRoot: undefined });
    // Configure the root in config.json only, so it can be removed while the server runs.
    await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ schema_version: 1, allowed_roots: [f.repo] }));
    const cfgPath = join(f.scratch, "noroot.json");
    await writeFile(cfgPath, JSON.stringify({ argv: ["--home", f.dataHome, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } }));
    const c = await open({ ...f, cfgPath }, "v2-modern");
    try {
      const runId = await newRunOver(c, f);
      await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ schema_version: 1, allowed_roots: [] }));
      expect(errorCode(await c.call("run_checks", { run_id: runId }))).toBe("SCOPE_NOT_CONFIGURED");
      await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ schema_version: 1, allowed_roots: [f.scratch] }));
      expect(errorCode(await c.call("run_checks", { run_id: runId }))).toBe("SCOPE_REVOKED");
      expect(errorCode(await c.call("get_review_status", { run_id: runId }))).toBe("SCOPE_REVOKED");
      const stopped = sc(await c.call("stop_review_loop", { run_id: runId, mode: "close" }));
      expect(stopped["state"]).toBe("CLOSED");
    } finally {
      await c.close();
    }
  }, 120_000);

  for (const flavor of ["v2-legacy", "v2-modern", "v1"] as Flavor[]) {
    it(`${flavor}: strict client roots — association re-checked before every operation (MR-H)`, async () => {
      const f = await mcpFixture({ config: { client_roots: { enforce: true } } });
      const elsewhere = await tempDir("arl-roots-");
      const c = await open(f, flavor, { roots: [f.repo] });
      try {
        // Without repository_root, the single in-scope client root selects the repository
        // (2026 era: requested through a multi-round-trip input_required result).
        const created = sc(await c.call("create_review_run", { task_envelope: { goal: "g" }, wait_seconds: 30 }));
        const runId = created["run_id"] as string;
        expect(created["repository"]).toMatchObject({ root: expect.stringContaining("repo") });
        expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 30 }))["status"]).toBe("passed");
        await c.setRoots([elsewhere]);
        await new Promise((r) => setTimeout(r, 400));
        expect(errorCode(await c.call("run_checks", { run_id: runId }))).toBe("REPO_OUTSIDE_SESSION_ROOTS");
        expect(errorCode(await c.call("review_with_codex", { run_id: runId }))).toBe("REPO_OUTSIDE_SESSION_ROOTS");
        await c.setRoots([f.repo]);
        await new Promise((r) => setTimeout(r, 400));
        expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 30 }))["status"]).toBe("passed");
        // Clearing every root is no way around strict mode: no root, no association
        // (dogfood review, M1.6-15; 2026 era: an empty multi-round-trip roots response).
        await c.setRoots([]);
        await new Promise((r) => setTimeout(r, 400));
        expect(errorCode(await c.call("run_checks", { run_id: runId }))).toBe("REPO_OUTSIDE_SESSION_ROOTS");
        expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo }))).toBe("REPO_OUTSIDE_SESSION_ROOTS");
      } finally {
        await c.close();
      }
    }, 120_000);
  }
});

describe.skipIf(!supported)("strict client roots fail closed (MR-H)", () => {
  it("2025 era: a client that declares roots but cannot list them is refused in strict mode, not treated as rootless", async () => {
    const f = await mcpFixture({ config: { client_roots: { enforce: true } } });
    const c = await open(f, "v2-legacy", { roots: [f.repo], rootsFail: true });
    try {
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo }))).toBe("REPO_OUTSIDE_SESSION_ROOTS");
      expect(await runCount(f)).toBe(0);
    } finally {
      await c.close();
    }
  }, 60_000);
});

describe.skipIf(!supported)("verification cannot be lowered and budgets cannot be raised (D-29, R-16)", () => {
  it("budget overrides only lower; a subset run leaves the floor unsatisfied; additions raise it", async () => {
    const f = await mcpFixture();
    const c = await open(f, "v2-legacy");
    try {
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, budget_overrides: { max_reviews: 50 } }))).toBe("INVALID_ARGUMENT");
      expect(errorCode(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, additional_required_checks: ["not-approved"] }))).toMatch(/^(UNKNOWN_PROFILE|CHECK_NOT_APPROVED)$/);
      const runId = await newRunOver(c, f, { budget_overrides: { max_check_executions: 2 } });
      // Run only an optional check: the floor (unit) is still missing.
      const sub = sc(await c.call("run_checks", { run_id: runId, checks: ["flag"], wait_seconds: 30 }));
      expect(sub["status"]).toBe("passed");
      expect((sub["floor"] as { satisfied_for_current_source: boolean; missing: string[] }).satisfied_for_current_source).toBe(false);
      expect((sub["floor"] as { missing: string[] }).missing).toContain("unit");
      expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 30 }))["status"]).toBe("passed");
      expect(errorCode(await c.call("run_checks", { run_id: runId, wait_seconds: 30 }))).toBe("BUDGET_EXHAUSTED");
      // A run created with an additional requirement reports it in its floor.
      const raised = sc(await c.call("create_review_run", { task_envelope: { goal: "g" }, repository_root: f.repo, additional_required_checks: ["flag"], wait_seconds: 30 }));
      expect((raised["verification_floor"] as { required: string[]; source: string[] }).required.sort()).toEqual(["flag", "unit"]);
      expect((raised["verification_floor"] as { source: string[] }).source.sort()).toEqual(["run_argument", "trusted_config"]);
    } finally {
      await c.close();
    }
  }, 120_000);
});

describe.skipIf(!supported)("confidentiality boundary of host results (MR-F, §16.2)", () => {
  it("withheld names and hashes, check output and local paths never reach the host — in results, errors and history", async () => {
    const f = await mcpFixture({ extraFiles: { "config/Ä.env": "UNICODE_SECRET=1\n" } });
    const envSha = createHash("sha256").update(await readFile(join(f.repo, ".env"))).digest("hex");
    // A hostile reviewer output naming the withheld files (any spelling) and their hash.
    await setScenario(
      f,
      okScenario(
        output({
          summary: "see .env",
          assessment: `The .env file and CONFIG\\ä.env leak; hash ${envSha}; store at ${f.dataHome}\\runs`,
          findings: [defect({ title: "secret in .env", consequence: "config/ä.env is readable", evidence: [{ kind: "reasoning", detail: `.env holds ${envSha}`, path: ".env", start_line: 1, end_line: 1 }] })],
          coverage: { files_reviewed: ["src/math.js", ".env"], files_not_reviewed: ["config/Ä.env"], limitations: "could not read .env" },
        }),
      ),
    );
    const c = await open(f, "v2-modern");
    try {
      const all: unknown[] = [];
      const runId = await newRunOver(c, f, { task_envelope: { goal: "Do not leak .env or config/Ä.env", references: [{ path: ".env", note: "secret" }] } });
      all.push(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 30 })));
      const review = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 40, focus: ".env handling" }));
      all.push(review);
      all.push(sc(await c.call("get_review_status", { run_id: runId })));
      // The run list (no run_id) shows each run's goal redacted with that run's own withheld
      // names, like the run's own status (dogfood review finding, M1.6-15) — not withheld whole.
      const list = sc(await c.call("get_review_status", {}));
      all.push(list);
      const row = (list["runs"] as { run_id: string; goal_excerpt: string | null; goal_withheld: boolean }[]).find((x) => x.run_id === runId)!;
      expect(row.goal_withheld).toBe(false);
      expect(row.goal_excerpt).toContain("[withheld path]");
      const hist = sc(await c.call("get_review_history", { run_id: runId }));
      all.push(hist);
      for (const part of ["result", "review_output", "review_items"]) all.push(sc(await c.call("get_review_history", { run_id: runId, artifact: { operation_id: review["operation_id"] as string, part } })));
      all.push(sc(await c.call("stop_review_loop", { run_id: runId, mode: "close" })));
      const text = JSON.stringify(all);
      expect(text).not.toContain(envSha);
      expect(text).not.toContain("SECRET_ENV_VALUE");
      expect(text).not.toContain("UNICODE_SECRET");
      expect(text).not.toContain("CHECK_STDOUT_TOKEN");
      expect(text.toLowerCase()).not.toContain(f.dataHome.toLowerCase().replace(/\\/g, "\\\\"));
      expect(text).not.toMatch(/(^|[^a-z.])\.env\b/i);
      expect(text.toLowerCase()).not.toContain("ä.env");
      expect(text).toContain("[withheld path]");
      expect(text).toContain("[withheld hash]");
      // The review itself still happened and is usable.
      expect(review["status"]).toBe("completed");
      expect((review["findings"] as unknown[]).length).toBe(1);
      // The local run store still has the exact data for the user (CLI/`runs show`).
      const stateText = await readFile(join(f.dataHome, "runs", (await readdir(join(f.dataHome, "runs")))[0]!, runId, "state.json"), "utf8");
      expect(stateText).toContain(".env");
    } finally {
      await c.close();
    }
  }, 180_000);

  it("a run whose capture record is missing fails closed: its goal is withheld in the list, its own results are withheld (M1.6-15)", async () => {
    const f = await mcpFixture();
    let c = await open(f, "v2-modern");
    let runId = "";
    try {
      runId = await newRunOver(c, f, { task_envelope: { goal: "Do not leak .env" } });
    } finally {
      await c.close();
    }
    // The baseline capture record the run refers to disappears (damage, an editor, antivirus).
    const runDir = join(f.dataHome, "runs", (await readdir(join(f.dataHome, "runs")))[0]!, runId);
    const st = JSON.parse(await readFile(join(runDir, "state.json"), "utf8")) as { operations: { outcome?: { capture_ref?: unknown } }[] };
    const ref = st.operations.map((o) => o.outcome?.capture_ref).find((x): x is string => typeof x === "string")!;
    await rm(join(runDir, ...ref.split("/")));
    c = await open(f, "v2-modern"); // a fresh server process: nothing cached
    try {
      const list = sc(await c.call("get_review_status", {}));
      const row = (list["runs"] as { run_id: string; goal_excerpt: string | null; goal_withheld: boolean }[]).find((x) => x.run_id === runId)!;
      expect(row).toMatchObject({ goal_excerpt: null, goal_withheld: true });
      expect(JSON.stringify(list)).not.toMatch(/\.env/);
      expect(errorCode(await c.call("get_review_status", { run_id: runId }))).toBe("INTERNAL");
    } finally {
      await c.close();
    }
  }, 120_000);
});

describe.skipIf(!supported)("result size bound (K6) with paging", () => {
  it("a large review result is shortened under 40 000 characters and pages back in full", async () => {
    const f = await mcpFixture();
    // 90 findings (the reviewer schema allows at most 100), each well over 1 KB.
    const findings = Array.from({ length: 90 }, (_, i) => defect({ title: `finding ${i}`, consequence: `consequence ${i} `.repeat(30), recommended_change: "change ".repeat(80) }));
    await setScenario(f, okScenario(output({ findings })));
    const c = await open(f, "v2-legacy");
    try {
      const runId = await newRunOver(c, f);
      const r = await c.call("review_with_codex", { run_id: runId, wait_seconds: 40 });
      const s = sc(r);
      expect(JSON.stringify(s).length).toBeLessThanOrEqual(40_000);
      const tr = s["truncation"] as { truncated: boolean; cut_lists: { field: string }[] };
      expect(tr.truncated).toBe(true);
      expect(tr.cut_lists.map((x) => x.field)).toContain("findings");
      let doc = "";
      for (let offset = 0; ; ) {
        const page = sc(await c.call("get_review_history", { run_id: runId, artifact: { operation_id: s["operation_id"] as string, part: "result", offset } }));
        const a = page["artifact"] as { content: string; length: number; total_length: number };
        expect(JSON.stringify(page).length).toBeLessThanOrEqual(40_000 + 2_000);
        doc += a.content;
        offset += a.length;
        if (offset >= a.total_length || a.length === 0) break;
      }
      const full = JSON.parse(doc) as { findings: unknown[] };
      expect(full.findings.length).toBe(90);
    } finally {
      await c.close();
    }
  }, 180_000);
});

// Silence "unused" for helpers kept for readability in failure output.
void mkdir;
