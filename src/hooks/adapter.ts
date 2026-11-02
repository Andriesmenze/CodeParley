// The Claude Code hook adapter (Phase 3.3a): a THIN translation between the host's hook protocol
// and CodeParley's continuation controller (engine/continuation.ts).
//
//   node dist/hooks/main.js <event> [launch arguments as for the server: --home, --config, --git, …]
//   events: session-start · session-end · user-prompt-submit · pre-tool-use · post-tool-use (bind) ·
//           stop · config-change · wake (the asyncRewake waiter on review_with_codex)
//
// It reads the host's hook input, collects host facts (session id, transcript path, CLAUDE_PID, its
// own pid), asks the engine, and prints the engine's verdict in the host's output format. It decides
// nothing itself: no routing, binding or wake rule lives here (test/layering.test.ts).
//
// Hooks run in EVERY session of the user (user-scope plugin), so a session with no CodeParley
// binding exits at once, before the engine is even loaded. Any error allows the host to proceed
// (no continuation, no wake) — except a correlation check that could not be made for a call that
// names a run, which is refused (fail safe both ways). Every verdict is logged to the data home's
// logs; model text is never logged or used.

import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { parseLaunchArgs, type LaunchArgs } from "../config/launch-args.js";
import { resolveDataHome } from "../store/paths.js";
import { sessionIndexPath, sessionKey } from "../store/continuation-paths.js";

export const HOOK_EVENTS: Readonly<Record<string, string>> = {
  "session-start": "SessionStart",
  "session-end": "SessionEnd",
  "user-prompt-submit": "UserPromptSubmit",
  "pre-tool-use": "PreToolUse",
  "post-tool-use": "PostToolUse",
  stop: "Stop",
  "config-change": "ConfigChange",
  wake: "PostToolUse",
};

/** Phase 6 (contract §7): each event's deadline in the plugin's hook configuration (plugin/build-plugin.mjs; SessionEnd
 * has none and gets the host's default of 60 s). The custodian client's busy waits end before it, by the margin. */
export const HOOK_DEADLINE_S: Readonly<Record<string, number>> = {
  "session-start": 30, "session-end": 60, "user-prompt-submit": 30, "pre-tool-use": 30, "post-tool-use": 60, stop: 120, "config-change": 30, wake: 960,
};
/** What a hook keeps for itself after its custodian calls: its own start, the engine's work and its output. */
export const HOOK_DEADLINE_MARGIN_MS = 5000;

/** Events that matter only to a session that already has a binding (the fast path). */
const NEEDS_BINDING = new Set(["session-start", "session-end", "user-prompt-submit", "stop", "config-change", "wake"]);

export interface HookIo {
  stdin: string;
  env: NodeJS.ProcessEnv;
  out(text: string): void;
  err(text: string): void;
  /** TEST ONLY: engine test hooks (e.g. a simulated custodian) injected by a test-only adapter entry. The
   * production entry (src/hooks/main.ts) never sets this, so production always uses the real, authenticated
   * custodian transport and fails closed when it is unavailable — there is no production path to a simulated
   * or user-configurable authority. */
  testHooks?: import("../engine/engine-env.js").EngineTestHooks;
}

/** Adapter-only options (everything else is a launch argument, as for the server). */
interface AdapterOptions {
  maxSeconds: number;
  pollMs: number;
}

function splitOptions(argv: readonly string[]): { launch: string[]; opts: AdapterOptions } {
  const launch: string[] = [];
  const opts: AdapterOptions = { maxSeconds: 900, pollMs: 1500 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--max-seconds" || a === "--poll-ms") {
      const v = Number(argv[++i]);
      if (!Number.isFinite(v) || v <= 0) throw new Error(`${a} requires a positive number`);
      if (a === "--max-seconds") opts.maxSeconds = Math.min(v, 3600);
      else opts.pollMs = Math.max(50, Math.min(v, 60_000));
    } else launch.push(a);
  }
  return { launch, opts };
}

function logLine(dataHome: string, line: string): void {
  try {
    const dir = join(dataHome, "logs");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    appendFileSync(join(dir, `hooks-${new Date().toISOString().slice(0, 10)}.log`), `${new Date().toISOString()} [${process.pid}] ${line.replace(/[\u0000-\u001f]/g, " ").slice(0, 600)}\n`, { mode: 0o600 });
  } catch {
    /* logging is best effort */
  }
}

/** Run one hook invocation; returns the process exit code (0, or 2 to block a change / wake the session). */
export async function runHook(argv: readonly string[], io: HookIo): Promise<number> {
  const event = argv[0] ?? "";
  if (!(event in HOOK_EVENTS)) {
    io.err(`code-parley hook: unknown event ${JSON.stringify(event.slice(0, 40))}`);
    return 0;
  }
  const { setCustodianClientDeadline } = await import("../custodian/transport.js");
  setCustodianClientDeadline(Date.now() + HOOK_DEADLINE_S[event]! * 1000 - HOOK_DEADLINE_MARGIN_MS);
  let launch: LaunchArgs;
  let opts: AdapterOptions;
  try {
    const s = splitOptions(argv.slice(1));
    launch = parseLaunchArgs(s.launch);
    opts = s.opts;
  } catch (e) {
    io.err(`code-parley hook: ${(e as Error).message}`);
    return 0;
  }
  let input: Record<string, unknown>;
  try {
    const v: unknown = JSON.parse(io.stdin);
    if (!v || typeof v !== "object" || Array.isArray(v)) return 0;
    input = v as Record<string, unknown>;
  } catch {
    return 0;
  }
  // The host names its event; a mismatch means a misconfigured hook: do nothing.
  if (typeof input["hook_event_name"] === "string" && input["hook_event_name"] !== HOOK_EVENTS[event]) return 0;
  const sessionId = typeof input["session_id"] === "string" && input["session_id"].length > 0 && input["session_id"].length <= 256 ? input["session_id"] : null;
  if (!sessionId) return 0;
  const dataHome = resolveDataHome({ home: launch.home ?? null, env: io.env }).dataHome;

  // Fast path: a session with no binding is none of CodeParley's business (no engine, no config).
  if (NEEDS_BINDING.has(event) && !existsSync(sessionIndexPath(dataHome, sessionId))) return 0;

  const cont = await import("../engine/continuation.js");
  const { selfOwner } = await import("../store/owner.js");
  const session = sessionKey(sessionId).slice(0, 8);
  const log = (line: string) => logLine(dataHome, `${event} session=${session} ${line}`);
  const facts = {
    session_id: sessionId,
    transcript_path: typeof input["transcript_path"] === "string" ? input["transcript_path"] : null,
    claudePid: cont.claudePidOf(io.env),
    hookPid: process.pid,
  };
  const toolInput = input["tool_input"];
  try {
    const { loadEngine } = await import("../engine/engine-env.js");
    const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), ...(io.testHooks ? { testHooks: io.testHooks } : {}) });
    const str = (k: string): string | null => (typeof input[k] === "string" ? (input[k] as string) : null);
    let o: Awaited<ReturnType<typeof cont.onStop>>;
    switch (event) {
      case "session-start":
        o = await cont.onSessionStart(le, facts, str("source"));
        break;
      case "session-end":
        o = await cont.onSessionEnd(le, facts, str("reason"));
        break;
      case "user-prompt-submit":
        o = await cont.onUserPrompt(le, facts, str("prompt") ?? "");
        break;
      case "pre-tool-use":
        o = await cont.onPreToolUse(le, facts, toolInput);
        break;
      case "post-tool-use":
        o = await cont.onLoopStarted(le, facts, input["tool_response"]);
        break;
      case "stop":
        o = await cont.onStop(le, facts, input["stop_hook_active"] === true);
        break;
      case "config-change":
        o = await cont.onConfigChange(le, facts, str("source"));
        break;
      case "wake":
        return await waiter(cont, le, facts, input["tool_response"], opts, io, log);
      default:
        return 0;
    }
    log(`${o.verdict}: ${o.log}`);
    return emit(event, o, io);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log(`error: ${msg}`);
    if (event === "pre-tool-use" && toolInput && typeof toolInput === "object" && typeof (toolInput as Record<string, unknown>)["run_id"] === "string") {
      io.out(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `[CodeParley correlation] the session binding could not be checked (${msg.slice(0, 160)}); the call is refused` } }));
    }
    return 0;
  }
}

function emit(event: string, o: { text: string | null; verdict: string }, io: HookIo): number {
  if (!o.text) return 0;
  switch (o.verdict) {
    case "context":
      io.out(JSON.stringify({ hookSpecificOutput: { hookEventName: HOOK_EVENTS[event], additionalContext: o.text } }));
      return 0;
    case "deny":
      io.out(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: o.text } }));
      return 0;
    case "block":
      if (event === "stop") {
        io.out(JSON.stringify({ decision: "block", reason: o.text }));
        return 0;
      }
      io.err(o.text); // ConfigChange: exit 2 keeps the running session's settings
      return 2;
    default:
      return 0;
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * The asyncRewake waiter: arm a wake for the review this review_with_codex result left running,
 * poll the engine until it decides, and exit 2 with the controller's text to wake the SAME idle
 * session — or exit 0. Bounded by the loop's deadline and --max-seconds (below the hook timeout).
 */
async function waiter(cont: typeof import("../engine/continuation.js"), le: Parameters<typeof cont.onStop>[0], facts: Parameters<typeof cont.onStop>[1], toolResponse: unknown, opts: AdapterOptions, io: HookIo, log: (l: string) => void): Promise<number> {
  const instance = `${process.pid}-${randomBytes(3).toString("hex")}`;
  const arm = await cont.armWake(le, facts, toolResponse, instance);
  if ("skip" in arm) {
    log(`not armed: ${arm.skip}`);
    return 0;
  }
  const a = arm.armed;
  log(`armed ${a.operation_id} epoch ${a.epoch} (${instance})`);
  const deadline = Math.min(arm.deadlineMs, Date.now() + opts.maxSeconds * 1000);
  for (;;) {
    const c = await cont.checkWake(le, a, facts.claudePid, facts.transcript_path).catch((e: unknown): { state: "wait"; reason: string } => ({ state: "wait", reason: `check failed: ${e instanceof Error ? e.message : String(e)}` }));
    if (c.state === "stop") {
      await cont.abandonWake(le, a, c.reason);
      log(`no wake: ${c.reason}`);
      return 0;
    }
    if (c.state === "ready") {
      const r = await cont.consumeWake(le, a, facts);
      if (!r.wake || !r.text) {
        log(`no wake: ${r.reason}`);
        return 0;
      }
      log(`wake: ${r.reason}`);
      io.err(r.text);
      return 2;
    }
    if (Date.now() >= deadline) {
      await cont.abandonWake(le, a, "the waiter reached its time limit");
      log("no wake: time limit");
      return 0;
    }
    await sleep(opts.pollMs);
  }
}

/** Read stdin, run the hook, and set the exit code (the process entry). */
export async function runHookProcess(argv: readonly string[], opts: { testHooks?: import("../engine/engine-env.js").EngineTestHooks } = {}): Promise<void> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of process.stdin) {
    const b = Buffer.isBuffer(c) ? c : Buffer.from(String(c));
    size += b.length;
    if (size > 16 * 1024 * 1024) break;
    chunks.push(b);
  }
  process.exitCode = await runHook(argv, {
    stdin: Buffer.concat(chunks).toString("utf8"),
    env: process.env,
    out: (t) => process.stdout.write(t),
    err: (t) => process.stderr.write(t),
    ...(opts.testHooks ? { testHooks: opts.testHooks } : {}),
  });
}
