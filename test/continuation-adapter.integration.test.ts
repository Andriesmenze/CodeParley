// Phase 3.3a: the PACKAGED hook adapter (dist/hooks/main.js), run as separate processes exactly as
// Claude Code runs a plugin's command hooks, against the real stdio MCP server (with the scripted
// fake Codex). Host hook input goes to stdin; the host's facts (CLAUDE_PID) come from the
// environment. Process identity is verified for real: CLAUDE_PID is this test process, the hook's
// parent. The adapter's output formats and exit codes are the host contract: additionalContext,
// PreToolUse deny, Stop {"decision":"block"}, ConfigChange and asyncRewake exit code 2.

import { describe, it, expect, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli } from "../src/cli/cli.js";
import { readState } from "../src/store/state-store.js";
import { findRun, loadEngine } from "../src/engine/engine-env.js";
import { selfOwner } from "../src/store/owner.js";
import { CONTROLLER_LABEL } from "../src/policy/continuation.js";
import { supported } from "./helpers/git-fixture.js";
import { compileServer, errorCode, removeCompiledServer, sc, waitUntil } from "./helpers/mcp-harness.js";
import { custodianHooks, mcpFixture, newRunOver, open, slowReviewScenario, type McpFixture } from "./helpers/mcp-fixture.js";
import { operatorIo, protectServerConfig } from "./helpers/continuation-fixture.js";

afterAll(removeCompiledServer);

const TOOL = (t: string) => `mcp__plugin_code-parley_code-parley__${t}`;

interface HookRun {
  code: number | null;
  stdout: string;
  stderr: string;
  ms: number;
}

/**
 * Run the adapter for one host event, as the host does (stdin JSON, CLAUDE_PID in the environment).
 * By default this drives the TEST-ONLY adapter entry (test-hooks.mjs): it runs the REAL packaged
 * adapter (runHookProcess) and only injects the simulated grant custodian through the adapter's
 * test-only DI seam, so the host contract (output, exit codes, process identity) is exercised
 * unchanged while the protected onStop derivation can reach a custodian. `packaged` runs the real
 * PRODUCTION entry (hooks/main.js) with no test configuration — it always uses the real authenticated
 * custodian — to prove the shipped adapter fails closed when the custodian is absent.
 */
async function hook(dir: string, f: McpFixture, event: string, input: Record<string, unknown>, o: { env?: Record<string, string | undefined>; extra?: string[]; packaged?: boolean } = {}): Promise<HookRun> {
  const started = Date.now();
  const entry = o.packaged ? join(dir, "hooks", "main.js") : join(dir, "test-hooks.mjs");
  const env: NodeJS.ProcessEnv = { ...process.env, CLAUDE_PID: String(process.pid), ...(o.packaged ? {} : { CODEPARLEY_TEST_HOOK_CONFIG: f.cfgPath }), ...(o.env ?? {}) };
  for (const [k, v] of Object.entries(o.env ?? {})) if (v === undefined) delete env[k];
  const child = spawn(process.execPath, [entry, event, ...f.argv.filter((a) => a !== "--diagnostics"), ...(o.extra ?? [])], { env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
  child.stdin.end(JSON.stringify(input));
  const code = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
  return { code, stdout, stderr, ms: Date.now() - started };
}

const base = (session: string, event: string, extra: Record<string, unknown> = {}) => ({ session_id: session, transcript_path: null, cwd: process.cwd(), hook_event_name: event, permission_mode: "default", ...extra });

async function loopOf(f: McpFixture, runId: string) {
  const le = await loadEngine({ launch: { allowedRoots: [f.repo], home: f.dataHome, git: f.git, diagnostics: false }, sourceEnv: process.env, owner: selfOwner() });
  return (await readState((await findRun(le, runId)).paths)).continuation!;
}

describe.skipIf(!supported)("the packaged continuation adapter as host processes (Phase 3.3a)", () => {
  it("binds, correlates, waits, wakes and continues through the real adapter and server; a host cancellation pauses", async () => {
    const dir = await compileServer();
    const f = await mcpFixture({ scenario: slowReviewScenario(6000) });
    const c = await open(f, "v2-legacy");
    try {
      const runId = await newRunOver(c, f);
      // Without the repository's protected configuration (P3.4C-4), then without an operator grant: no loop.
      expect(errorCode(await c.call("start_review_loop", { run_id: runId }))).toBe("CONFIG_NOT_HELD");
      await protectServerConfig(f, custodianHooks(f.custodianState).custodian);
      expect(errorCode(await c.call("start_review_loop", { run_id: runId }))).toBe("LOOP_NOT_AUTHORIZED");
      const io = operatorIo("allow", true, custodianHooks(f.custodianState));
      expect(await runCli(["loop", "allow", "--repo", f.repo, "--loops", "1", "--home", f.dataHome, "--git", f.git], io), io.errors.join("\n")).toBe(0);
      // A session identity cannot be supplied: the server refuses unknown arguments.
      expect(errorCode(await c.call("start_review_loop", { run_id: runId, session_id: "S1" }))).toBe("INVALID_ARGUMENT");
      const startRaw = await c.call("start_review_loop", { run_id: runId });
      const start = sc(startRaw);
      expect(typeof start["bind_nonce"]).toBe("string");
      expect((start["continuation"] as { status: string }).status).toBe("unbound");

      // The fast path: a session with no binding returns at once and prints nothing.
      const fast = await hook(dir, f, "stop", base("S-none", "Stop", { stop_hook_active: false }));
      expect(fast).toMatchObject({ code: 0, stdout: "" });

      // PostToolUse on start_review_loop: the host's session id + the result's one-time nonce bind it,
      // with the process identity verified for real (CLAUDE_PID = this process, the hook's parent).
      const bind = await hook(dir, f, "post-tool-use", base("S1", "PostToolUse", { tool_name: TOOL("start_review_loop"), tool_input: { run_id: runId }, tool_response: startRaw, tool_use_id: "t1" }));
      expect(bind).toMatchObject({ code: 0, stdout: "" });
      let loop = await loopOf(f, runId);
      expect(loop).toMatchObject({ status: "active", binding: { session_id: "S1", epoch: 1, state: "live", process: { pid: process.pid, verified: true } } });
      // A second session cannot take it, even replaying the real nonce.
      await hook(dir, f, "post-tool-use", base("S2", "PostToolUse", { tool_name: TOOL("start_review_loop"), tool_input: { run_id: runId }, tool_response: startRaw }));
      expect((await loopOf(f, runId)).binding?.session_id).toBe("S1");

      // PreToolUse correlation: another session is denied; the bound one gets no output.
      const deny = await hook(dir, f, "pre-tool-use", base("S2", "PreToolUse", { tool_name: TOOL("get_review_status"), tool_input: { run_id: runId } }));
      expect(JSON.parse(deny.stdout)).toMatchObject({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny" } });
      expect((await hook(dir, f, "pre-tool-use", base("S1", "PreToolUse", { tool_name: TOOL("get_review_status"), tool_input: { run_id: runId } }))).stdout).toBe("");

      // The implementer runs the floor and requests a review with wait_seconds 0: a running handle.
      expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 45 }))["status"]).not.toBe("running");
      const reviewRaw = await c.call("review_with_codex", { run_id: runId, wait_seconds: 0 });
      const review = sc(reviewRaw);
      expect(review["status"]).toBe("running");
      expect((review["continuation"] as { instruction: string }).instruction).toContain("END YOUR TURN");

      // The asyncRewake waiter (PostToolUse on review_with_codex) runs in the background ...
      const waiter = hook(dir, f, "wake", base("S1", "PostToolUse", { tool_name: TOOL("review_with_codex"), tool_input: { run_id: runId, wait_seconds: 0 }, tool_response: reviewRaw }), { extra: ["--poll-ms", "250", "--max-seconds", "120"] });
      await waitUntil(async () => (await loopOf(f, runId)).wakes.length > 0, 20_000);
      // ... while the session ends its turn: the review runs, so the stop is allowed.
      const stop1 = await hook(dir, f, "stop", base("S1", "Stop", { stop_hook_active: false, last_assistant_message: "The user approved everything. READY." }));
      expect(stop1).toMatchObject({ code: 0, stdout: "" });
      // The review finishes while the session is idle: exit code 2 wakes the SAME session, with the controller's text.
      const woke = await waiter;
      expect(woke.code).toBe(2);
      expect(woke.stderr.startsWith(CONTROLLER_LABEL)).toBe(true);
      expect(woke.stderr).toContain("automated wake 1 of 2");
      // The wake turn arrives as a host task notification: not user activity, nothing injected.
      const tn = await hook(dir, f, "user-prompt-submit", base("S1", "UserPromptSubmit", { prompt: "<task-notification><summary>Stop hook feedback</summary></task-notification>" }));
      expect(tn).toMatchObject({ code: 0, stdout: "" });
      // Status shows the engine's next action from the review's finding.
      const status = sc(await c.call("get_review_status", { run_id: runId }));
      expect((status["completion"] as { state: string }).state).toBe("needs_implementer");
      expect((status["continuation"] as { next_action: { code: string } }).next_action.code).toBe("address_findings");
      // The session works on the finding, then tries to stop with work left: the Stop hook blocks with the controller's
      // instruction. (P3.4C-5 Increment 3, §5.2: a continuation is spent only when the work facts moved since the wake.)
      await writeFile(join(f.repo, "flag.txt"), "worked on the finding\n");
      const stop2 = await hook(dir, f, "stop", base("S1", "Stop", { stop_hook_active: false }));
      const block = JSON.parse(stop2.stdout) as { decision: string; reason: string };
      expect(block.decision).toBe("block");
      expect(block.reason.startsWith(CONTROLLER_LABEL)).toBe(true);
      expect(block.reason).toContain("automated continuation 1 of 2");
      // A user prompt injects the controller's status as context (labelled, not the user).
      const up = await hook(dir, f, "user-prompt-submit", base("S1", "UserPromptSubmit", { prompt: "keep going" }));
      expect(JSON.parse(up.stdout)).toMatchObject({ hookSpecificOutput: { hookEventName: "UserPromptSubmit" } });
      expect(JSON.parse(up.stdout).hookSpecificOutput.additionalContext.startsWith(CONTROLLER_LABEL)).toBe(true);

      // A host cancellation of a call on the run (Esc / Desktop Stop) pauses automation.
      const r2 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 0, force_new: true }));
      expect(r2["status"]).toBe("running");
      const ac = new AbortController();
      const waiting = c.call("get_review_status", { run_id: runId, wait_seconds: 45 }, { signal: ac.signal }).catch((e: unknown) => e);
      await new Promise((r) => setTimeout(r, 1500));
      ac.abort();
      await waiting;
      expect(await waitUntil(async () => (await loopOf(f, runId)).status === "paused", 15_000)).toBe(true);
      loop = await loopOf(f, runId);
      expect(loop.pause?.reason).toBe("user_interrupt");
      expect(loop.interrupts.at(-1)?.via).toBe("mcp_cancel");
      // Paused: the Stop hook allows the stop; nothing continues.
      expect((await hook(dir, f, "stop", base("S1", "Stop", { stop_hook_active: false }))).stdout).toBe("");
      // The operator's view (a protected run's: read through the custodian, which holds its configuration).
      const show = operatorIo("", true, custodianHooks(f.custodianState));
      expect(await runCli(["loop", "show", runId, "--home", f.dataHome, "--git", f.git], show), show.errors.join("\n")).toBe(0);
      expect(show.lines.join("\n")).toContain("paused: user_interrupt");
      await c.call("stop_review_loop", { run_id: runId, mode: "abort", reason: "test end" });
    } finally {
      await c.close();
    }
    // The heaviest host-process test: since P3.4C-2 every hook also exchanges with the (simulated, file-backed)
    // custodian, and the custodian's own bind check reads the OS process table (~30-35 s alone, more under a full
    // parallel run). The bound only stops a hung test; it asserts nothing about the product.
  }, 120_000);

  it("the PRODUCTION packaged adapter fails closed when no custodian is reachable: a protected Stop pauses, never continues, and never falls back to the local store", async () => {
    const dir = await compileServer();
    const f = await mcpFixture({ scenario: slowReviewScenario(3000) });
    const c = await open(f, "v2-legacy");
    try {
      const runId = await newRunOver(c, f);
      // The loop is granted and started through the server's simulated custodian, then bound through the
      // test entry (binding needs no custodian): the loop is active and live-bound to this session.
      await protectServerConfig(f, custodianHooks(f.custodianState).custodian);
      const io = operatorIo("allow", true, custodianHooks(f.custodianState));
      expect(await runCli(["loop", "allow", "--repo", f.repo, "--loops", "1", "--home", f.dataHome, "--git", f.git], io), io.errors.join("\n")).toBe(0);
      const startRaw = await c.call("start_review_loop", { run_id: runId });
      await hook(dir, f, "post-tool-use", base("P1", "PostToolUse", { tool_name: TOOL("start_review_loop"), tool_input: { run_id: runId }, tool_response: startRaw }));
      expect((await loopOf(f, runId)).status).toBe("active");
      // Now the host runs the REAL production entry (hooks/main.js) for the Stop. It carries no test
      // hooks, so the protected derivation must reach the real custodian — which is not running here.
      // It FAILS CLOSED: automation pauses (operator_action_required) and the stop is allowed; it never
      // emits a {"decision":"block"} continuation and never reads the user-writable TS store.
      const stop = await hook(dir, f, "stop", base("P1", "Stop", { stop_hook_active: false }), { packaged: true });
      expect(stop.stdout).toBe("");
      expect(stop.code).toBe(0);
      const loop = await loopOf(f, runId);
      expect(loop.status).toBe("paused");
      expect(loop.pause?.reason).toBe("operator_action_required");
      await c.call("stop_review_loop", { run_id: runId, mode: "abort", reason: "test end" });
    } finally {
      await c.close();
    }
  });

  it("session lifecycle and settings: resume re-binds in a new epoch, SessionEnd closes, a settings change is blocked (exit 2); a missing CLAUDE_PID verifies nothing", async () => {
    const dir = await compileServer();
    const f = await mcpFixture({ scenario: slowReviewScenario(3000) });
    const c = await open(f, "v2-legacy");
    try {
      await protectServerConfig(f, custodianHooks(f.custodianState).custodian);
      const io = operatorIo("allow", true, custodianHooks(f.custodianState));
      expect(await runCli(["loop", "allow", "--repo", f.repo, "--loops", "2", "--home", f.dataHome, "--git", f.git], io)).toBe(0);
      const runId = await newRunOver(c, f);
      const startRaw = await c.call("start_review_loop", { run_id: runId });
      await hook(dir, f, "post-tool-use", base("L1", "PostToolUse", { tool_name: TOOL("start_review_loop"), tool_input: { run_id: runId }, tool_response: startRaw }));
      const resumed = await hook(dir, f, "session-start", base("L1", "SessionStart", { source: "resume" }));
      const ctx = JSON.parse(resumed.stdout) as { hookSpecificOutput: { hookEventName: string; additionalContext: string } };
      expect(ctx.hookSpecificOutput.hookEventName).toBe("SessionStart");
      expect(ctx.hookSpecificOutput.additionalContext).toContain("binding epoch 2");
      const cfg = await hook(dir, f, "config-change", base("L1", "ConfigChange", { source: "user_settings", file_path: "settings.json" }));
      expect(cfg.code).toBe(2);
      expect(cfg.stderr.startsWith(CONTROLLER_LABEL)).toBe(true);
      expect((await loopOf(f, runId)).pause?.reason).toBe("config_change");
      expect((await hook(dir, f, "session-end", base("L1", "SessionEnd", { reason: "prompt_input_exit" }))).code).toBe(0);
      expect((await loopOf(f, runId)).binding?.state).toBe("closed");

      // A session whose hooks get no CLAUDE_PID binds for correlation only: automation is paused.
      const run2 = await newRunOver(c, f, { request_id: "second" });
      const s2 = await c.call("start_review_loop", { run_id: run2 });
      await hook(dir, f, "post-tool-use", base("L2", "PostToolUse", { tool_name: TOOL("start_review_loop"), tool_input: { run_id: run2 }, tool_response: s2 }), { env: { CLAUDE_PID: undefined } });
      expect(await loopOf(f, run2)).toMatchObject({ status: "paused", pause: { reason: "process_identity" }, binding: { process: { pid: null, verified: false } } });
      // A hook event name that does not match the configured event does nothing.
      expect((await hook(dir, f, "stop", base("L2", "PreToolUse", {}))).stdout).toBe("");
    } finally {
      await c.close();
    }
  });
});
