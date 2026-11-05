// Phase 3.3a: the Claude Code plugin package (plugin/build-plugin.mjs). The built plugin is
// self-contained (its own compiled CodeParley and production dependencies); its hooks are thin
// launchers of the hook adapter; its MCP server is CodeParley's. A test build wires the scripted fake
// Codex. Here the plugin's OWN server and hook launcher run as a host would run them (the host expands
// ${CLAUDE_PLUGIN_ROOT}), proving the packaged adapter binds and continues a session.

import { describe, it, expect, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { runCli } from "../src/cli/cli.js";
import { CONTROLLER_LABEL } from "../src/policy/continuation.js";
import { supported } from "./helpers/git-fixture.js";
import { compileServer, removeCompiledServer, repoRootDir } from "./helpers/mcp-harness.js";
import { TOOL_VERSION } from "../src/common/version.js";
import { custodianHooks, mcpFixture } from "./helpers/mcp-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { operatorIo, protectServerConfig } from "./helpers/continuation-fixture.js";

afterAll(removeCompiledServer);

const PREFIX = "mcp__plugin_code-parley_code-parley__";

// Both tests compile and package the server (CPU-heavy): ~15-20 s alone, 36-37 s under a partial parallel load, over 60 s
// in a full run (P3.4C-5 Increment 4 triage of the OPEN plugin timeouts). The bound only stops a hung test.
const PLUGIN_BOUND = 180_000;

interface HookDef {
  type: string;
  command: string;
  args: string[];
  timeout?: number;
  asyncRewake?: boolean;
}

/** What a host does with ${CLAUDE_PLUGIN_ROOT} (forward slashes on Windows, per the plugin docs). */
const expand = (s: string, root: string) => s.split("${CLAUDE_PLUGIN_ROOT}").join(root.replace(/\\/g, "/"));

async function runHook(root: string, def: HookDef, input: Record<string, unknown>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(expand(def.command, root), def.args.map((a) => expand(a, root)), { env: { ...process.env, CLAUDE_PID: String(process.pid) }, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
  child.stdin.end(JSON.stringify(input));
  const code = await new Promise<number | null>((r) => child.on("exit", (c) => r(c)));
  return { code, stdout, stderr };
}

describe.skipIf(!supported)("the CodeParley Claude Code plugin package (Phase 3.3a)", () => {
  it("builds a self-contained plugin whose own server and hook launcher bind and continue a session", async () => {
    const compiled = await compileServer();
    const f = await mcpFixture();
    const root = join(f.scratch, "plugin", "code-parley");
    const scenarioDir = join(f.scratch, "plugin-scenario");
    const b = spawnSync(process.execPath, [join(repoRootDir, "plugin", "build-plugin.mjs"), "--out", root, "--dist", compiled, "--home", f.dataHome, "--allowed-root", f.repo, "--git", f.git, "--test-fake-codex", "--test-scenario-dir", scenarioDir], { encoding: "utf8", windowsHide: true });
    expect(b.status, b.stderr).toBe(0);

    // Layout: manifest, hooks, MCP config, launch arguments, the application and its production dependencies only.
    const manifest = JSON.parse(readFileSync(join(root, ".claude-plugin", "plugin.json"), "utf8"));
    expect(manifest.name).toBe("code-parley");
    expect(manifest.description).toMatch(/^TEST BUILD \(scripted fake Codex/);
    for (const p of ["app/dist/hooks/adapter.js", "app/dist/engine/continuation.js", "app/dist/server/server.js", "app/prompts/codex-reviewer.md", "app/node_modules/zod", "app/node_modules/@modelcontextprotocol/server", "app/node_modules/@modelcontextprotocol/core", "bin/hook.mjs", "bin/server.mjs", "test/server-fake-codex.mjs", "test/hook-fake-custodian.mjs"]) expect(existsSync(join(root, p)), p).toBe(true);
    expect(existsSync(join(scenarioDir, "fake-codex.mjs"))).toBe(true);
    for (const dev of ["typescript", "vitest", "@modelcontextprotocol/client", "@modelcontextprotocol/sdk"]) expect(existsSync(join(root, "app", "node_modules", dev)), dev).toBe(false);
    const launch = JSON.parse(readFileSync(join(root, "launch.json"), "utf8")).argv as string[];
    expect(launch.slice(0, 2)).toEqual(["--home", f.dataHome]);
    const mcp = JSON.parse(readFileSync(join(root, ".mcp.json"), "utf8"));
    expect(mcp.mcpServers["code-parley"].args).toEqual(["${CLAUDE_PLUGIN_ROOT}/test/server-fake-codex.mjs"]);
    const hooks = JSON.parse(readFileSync(join(root, "hooks", "hooks.json"), "utf8")).hooks as Record<string, { matcher?: string; hooks: HookDef[] }[]>;
    expect(Object.keys(hooks).sort()).toEqual(["ConfigChange", "PostToolUse", "PreToolUse", "SessionEnd", "SessionStart", "Stop", "UserPromptSubmit"]);
    const all = Object.values(hooks).flat();
    // A TEST build runs the test-only hook launcher (it injects the simulated custodian through the
    // adapter's DI seam, then runs the same packaged adapter); a production build runs bin/hook.mjs.
    for (const g of all) for (const h of g.hooks) expect(h.args[0]).toBe("${CLAUDE_PLUGIN_ROOT}/test/hook-fake-custodian.mjs");
    expect(hooks["PreToolUse"]![0]!.matcher).toBe(`${PREFIX}.*`);
    const bindDef = hooks["PostToolUse"]!.find((g) => g.matcher === `${PREFIX}start_review_loop$`)!.hooks[0]!;
    const wakeDef = hooks["PostToolUse"]!.find((g) => g.matcher === `${PREFIX}review_with_codex$`)!.hooks[0]!;
    expect(wakeDef).toMatchObject({ asyncRewake: true });
    expect(wakeDef.timeout).toBeGreaterThan(Number(wakeDef.args[wakeDef.args.indexOf("--max-seconds") + 1]));
    const stopDef = hooks["Stop"]![0]!.hooks[0]!;

    // The plugin's own MCP server (its bundled app and dependencies), as the host starts it.
    // The fake reviewer's scenario lives outside the plugin (hosts may run a cached copy of it).
    expect(JSON.parse(readFileSync(join(root, "launch.json"), "utf8")).test_scenario_dir).toBe(scenarioDir);
    writeFileSync(join(scenarioDir, "scenario.json"), JSON.stringify(okScenario(output({ findings: [defect()] }))));
    const transport = new StdioClientTransport({ command: expand(mcp.mcpServers["code-parley"].command, root), args: mcp.mcpServers["code-parley"].args.map((a: string) => expand(a, root)), env: process.env as Record<string, string>, stderr: "pipe" });
    const client = new Client({ name: "plugin-test-host", version: "1.0.0" }, { capabilities: {}, versionNegotiation: { mode: "legacy" } });
    await client.connect(transport);
    try {
      const names = (await client.listTools()).tools.map((t) => t.name);
      expect(names).toContain("start_review_loop");
      const sc = (r: unknown) => (r as { structuredContent: Record<string, unknown> }).structuredContent;
      const created = sc(await client.callTool({ name: "create_review_run", arguments: { task_envelope: { goal: "plugin test" }, repository_root: f.repo, wait_seconds: 40 } }, { timeout: 90_000 }));
      const runId = created["run_id"] as string;
      await protectServerConfig(f, custodianHooks(join(scenarioDir, "custodian-state.json")).custodian);
      const io = operatorIo("allow", true, custodianHooks(join(scenarioDir, "custodian-state.json")));
      expect(await runCli(["loop", "allow", "--repo", f.repo, "--home", f.dataHome, "--git", f.git], io), io.errors.join("\n")).toBe(0);
      const started = await client.callTool({ name: "start_review_loop", arguments: { run_id: runId } }, { timeout: 90_000 });
      expect(typeof sc(started)["bind_nonce"]).toBe("string");
      // The host runs the plugin's PostToolUse hook: bound to this session.
      const base = { session_id: "plugin-S1", transcript_path: null, cwd: f.repo, permission_mode: "default" };
      const bound = await runHook(root, bindDef, { ...base, hook_event_name: "PostToolUse", tool_name: `${PREFIX}start_review_loop`, tool_input: { run_id: runId }, tool_response: started });
      expect(bound.code).toBe(0);
      const status = sc(await client.callTool({ name: "get_review_status", arguments: { run_id: runId } }, { timeout: 90_000 }));
      expect(status["continuation"]).toMatchObject({ status: "active", binding: { state: "live", epoch: 1, process_verified: true } });
      // The host runs the plugin's Stop hook: the engine says run the checks, so the turn continues.
      const stop = await runHook(root, stopDef, { ...base, hook_event_name: "Stop", stop_hook_active: false });
      const block = JSON.parse(stop.stdout) as { decision: string; reason: string };
      expect(block.decision).toBe("block");
      expect(block.reason.startsWith(CONTROLLER_LABEL)).toBe(true);
      expect(block.reason).toContain("run_checks");
      // A real review through the packaged server (its bundled prompt templates and the fake Codex).
      expect(sc(await client.callTool({ name: "run_checks", arguments: { run_id: runId, wait_seconds: 45 } }, { timeout: 90_000 }))["status"]).not.toBe("running");
      const review = sc(await client.callTool({ name: "review_with_codex", arguments: { run_id: runId, wait_seconds: 45 } }, { timeout: 120_000 }));
      expect(review["status"], JSON.stringify(review["failure"])).toBe("completed");
      expect((review["findings"] as unknown[]).length).toBe(1);
    } finally {
      await client.close();
    }
  }, PLUGIN_BOUND);

  it("P3.3b provenance: the version carries the content digest; the same build anywhere has one identity; a changed copy fails verification", async () => {
    const f = await mcpFixture();
    // Both builds package one private snapshot of the compiled sources: other test files add their child scripts to
    // the shared build while this one runs, which would otherwise change the content between the two builds.
    const compiled = join(f.scratch, "prov-dist");
    cpSync(await compileServer(), compiled, { recursive: true });
    const scenarioDir = join(f.scratch, "prov-scenario");
    const build = (dir: string, ...extra: string[]) => {
      const b = spawnSync(process.execPath, [join(repoRootDir, "plugin", "build-plugin.mjs"), "--out", dir, "--dist", compiled, "--home", f.dataHome, "--allowed-root", f.repo, "--git", f.git, "--test-fake-codex", "--test-scenario-dir", scenarioDir, ...extra], { encoding: "utf8", windowsHide: true });
      expect(b.status, `${b.stderr}\n${(b.stdout ?? "").slice(-2000)}`).toBe(0);
      return JSON.parse(readFileSync(join(dir, "build-info.json"), "utf8")) as { version: string; test_build: boolean; content: { digest: string; files: [string, number, string][] }; source: { commit: string | null } };
    };
    const verify = (dir: string, ...extra: string[]) => {
      const v = spawnSync(process.execPath, [join(repoRootDir, "plugin", "verify-plugin.mjs"), dir, "--json", ...extra], { encoding: "utf8", windowsHide: true });
      return { code: v.status, r: JSON.parse(v.stdout) as { ok: boolean; version: string; digest: string; checks: { name: string; ok: boolean; detail: string }[] } };
    };
    const a = join(f.scratch, "prov-a", "code-parley");
    const b = join(f.scratch, "prov-b", "code-parley");
    const ia = build(a);
    const ib = build(b);
    // The version a host keys its plugin cache by ends with the content digest; the build is location-independent.
    expect(ia.version.split("-b")[0]).toBe(TOOL_VERSION);
    expect(ia.version).toMatch(/-b[0-9a-f]{12}$/); // the release version (test/release-version.test.ts), then the digest
    expect(ia.version.endsWith(ia.content.digest.slice(0, 12))).toBe(true);
    expect(JSON.parse(readFileSync(join(a, ".claude-plugin", "plugin.json"), "utf8")).version).toBe(ia.version);
    expect(ia.test_build).toBe(true);
    expect(ib.content.digest).toBe(ia.content.digest);
    expect(ia.content.files.some(([p]) => p === "build-info.json" || p === ".claude-plugin/plugin.json")).toBe(false);
    expect(verify(a, "--against", b)).toMatchObject({ code: 0, r: { ok: true, version: ia.version, digest: ia.content.digest } });
    // Another launch argument is another build: another digest, another version.
    const ic = build(join(f.scratch, "prov-c", "code-parley"), "--config", join(f.scratch, "other-config.json"));
    expect(ic.content.digest).not.toBe(ia.content.digest);
    // A changed copy (a cached copy edited after install, a stale build) fails verification and names the file.
    writeFileSync(join(b, "app", "dist", "engine", "continuation.js"), readFileSync(join(b, "app", "dist", "engine", "continuation.js"), "utf8") + "\n// changed\n");
    const bad = verify(b, "--against", a);
    expect(bad.code).toBe(1);
    expect(bad.r.ok).toBe(false);
    expect(bad.r.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(expect.arrayContaining(["intact: the files are exactly those the build recorded", "same content as the intended build (--against)"]));
    expect(bad.r.checks.find((c) => c.name.startsWith("intact"))!.detail).toContain("app/dist/engine/continuation.js");
    // A host's own bookkeeping in a cached copy is not content.
    const markers = join(a, ".in_use");
    mkdirSync(markers, { recursive: true });
    writeFileSync(join(markers, "12345"), JSON.stringify({ pid: 12345 }));
    writeFileSync(join(a, ".orphaned_at"), "1");
    expect(verify(a, "--expect", ia.content.digest)).toMatchObject({ code: 0, r: { ok: true } });
  }, PLUGIN_BOUND);
});
