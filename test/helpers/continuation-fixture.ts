// Phase 3.3a test fixtures: a real git repository with approved checks (verification floor), the
// scripted fake Codex, and an in-process engine (`Loaded`) whose test hooks inject the session's
// process identity, its liveness and the controller clock. A simulated host calls the controller's
// hook functions exactly as the hook adapter does; the operator acts through the real CLI.

import { AsyncLocalStorage } from "node:async_hooks";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { clearProbeCache, probeCodex } from "../../src/agents/codex/probe.js";
import { ensureSelfTest } from "../../src/agents/codex/selftest.js";
import { buildChildEnv } from "../../src/process/env.js";
import { storeLayout } from "../../src/store/paths.js";
import { runCli, type CliIo } from "../../src/cli/cli.js";
import { createReviewRun } from "../../src/engine/runs.js";
import { loadEngine, reviewContext, type EngineTestHooks, type Loaded, type RunHandle } from "../../src/engine/engine-env.js";
import { startChecksOperation, startReviewOperation } from "../../src/engine/operations.js";
import {
  abandonWake,
  armWake,
  checkWake,
  consumeWake,
  onConfigChange,
  onLoopStarted,
  onPreToolUse,
  onSessionEnd,
  onSessionStart,
  onStop,
  onUserPrompt,
  startLoop,
  type HookFacts,
} from "../../src/engine/continuation.js";
import type { ReviewEngineContext } from "../../src/engine/review-operation.js";
import { SimulatedCustodianTransport } from "../../src/custodian/transport.js";
import type { SimBoundProcess, SimProcessCheck } from "../../src/custodian/simulated-loops.js";
import type { SimWriter } from "../../src/custodian/simulated-runs.js";
import { selfOwner } from "../../src/store/owner.js";
import { readState } from "../../src/store/state-store.js";
import type { ProcessIdentity } from "../../src/schemas/continuation.js";
import type { ArmedWake } from "../../src/policy/continuation.js";
import { approve } from "./checks-fixture.js";
import { fakeSelfTestDeps, makeReviewFixture, setScenario, type FakeScenario, type ReviewFixture } from "./review-fixture.js";

export const NODE = process.execPath;

// P3.4C-2 (TD decision on the Inc 9 escalation): the custodian checks an automation request's CONNECTED process
// against the loop's bound Claude process — an OS fact, modelled here independently of any session id a request
// names. While a HostSession runs one of its hooks, the connected process is in that session's Claude process tree
// (its CLAUDE_PID); anywhere else (a test sending straight to the pipe) it is a same-user process outside every
// Claude Code session, unless the test says otherwise with inProcessTreeOf.
const connectedTree = new AsyncLocalStorage<{ claudePid: number | null }>();

/** Run `fn` as a process inside the tree of the Claude process `claudePid` (null: outside every session). */
export function inProcessTreeOf<T>(claudePid: number | null, fn: () => Promise<T>): Promise<T> {
  return connectedTree.run({ claudePid }, fn);
}

/** The fixture custodian's check of an automation request's connected process (GrantLedger.Loops.cs
 * RequireBoundCaller): the bound process still runs as the instance verified at bind (start time 1_000; a pid in
 * `reused` now names a later process, one in `gone` ended) and the connected process is inside its tree.
 * `engineCall` (P3.4C-3, a run's op_begin or respond): a call a test makes without naming a process tree is the
 * model's own tool call through the session's MCP server — inside the bound session's tree; a test models any other
 * caller with inProcessTreeOf. */
export function treeCheck(bound: SimBoundProcess, f: { gone: ReadonlySet<number>; reused: ReadonlySet<number> }, engineCall = false): SimProcessCheck {
  const store = connectedTree.getStore();
  const client = store ? store.claudePid : engineCall ? bound.pid : null;
  const why = treeRefusal(bound, client, f);
  return { pid: bound.pid, startedAtMs: bound.startedAtMs, clientPid: client, verified: why === null, detail: why ?? `test process ${bound.pid}, an ancestor of the connected hook` };
}

/** Why the connected process does not pass the check (null: it does). */
function treeRefusal(bound: SimBoundProcess, client: number | null, f: { gone: ReadonlySet<number>; reused: ReadonlySet<number> }): string | null {
  const pid = bound.pid;
  if (pid === null || bound.startedAtMs === null) return "the binding records no verified process";
  if (f.gone.has(pid)) return `process ${pid} is not running`;
  if (f.reused.has(pid)) return `process ${pid} is not the process the loop was bound to: the process id was reused`;
  if (client === pid) return null;
  const connected = client === null ? "a process outside every Claude Code session" : "a process of Claude process " + client;
  return `process ${pid} is not an ancestor of the process connected to the custodian (${connected})`;
}

export interface ContFixture extends ReviewFixture {
  le: Loaded;
  /** P3.4C-0: the simulated grant custodian (a Windows installation with the custodian) the engine and
   * the operator CLI share; its clock is the controller clock. With `accounts`, the engine's transport: it
   * reaches only the implementer pipe. */
  custodian: SimulatedCustodianTransport;
  /** With `accounts` only: the operator account's transport (it reaches only the operator pipe), over the same
   * custodian state, and the test hooks the operator's CLI runs with. */
  operatorCustodian?: SimulatedCustodianTransport;
  operatorHooks?: EngineTestHooks;
  /** Controller clock override (null: real time). */
  clock: { now: number | null };
  /** Claude process ids whose process has "ended". */
  gone: Set<number>;
  /** Claude process ids whose identity cannot be verified (e.g. no start time). */
  unverifiable: Set<number>;
  /** Claude process ids that now name a LATER process (the bound one ended and its id was reused). */
  reused: Set<number>;
  /** The platform the protected-loop gate decides for (win32: a Windows installation with the custodian). */
  custodianPlatform: NodeJS.Platform;
}

export interface ContFixtureOptions {
  /** Model the OS pipe separation (P3.4C-1's VM lesson): the engine and the session's hooks reach only the
   * implementer pipe, the operator's CLI only the operator pipe — two account-bound simulated transports over one
   * shared custodian state, each classified by the pipe it can reach. Without it, one transport serves both. */
  accounts?: boolean;
  /** The platform the protected-loop gate decides for (default win32: a Windows installation with the custodian).
   * Another platform models a host without a validated custodian, where nothing is exchanged with one (D-14). */
  custodianPlatform?: NodeJS.Platform;
  /** The custodian's view of whether an operation's writer is gone (default: this process lives; P3.4C-3 `recover`). */
  writerGone?: (w: SimWriter) => boolean | null;
  /** The process the simulated custodian identifies as the sender of the engine's requests (default: this process). */
  writer?: () => SimWriter | null;
  /** P3.4C-5: the custodian's capture helper — auto (default: it captures a reserved review at once), manual (a test
   * captures it: `runReservedCapture`), or none (a custodian without the helper: protected reviews are refused). */
  helper?: "auto" | "manual" | "none";
  /** P3.4C-5 (F-5-1): the custodian's check measurements — auto (default: measured at once) or manual (a test runs each
   * reserved one: `runReservedCheckMeasurement`, or restarts the custodian while it waits). */
  measure?: "auto" | "manual";
  /** P3.4C-5 Increment 3: every custodian derivation reports moved progress (tests of the loop's own rules). */
  freshProgress?: boolean;
  /** P3.4C-5 Increment 4 (N5-8): the helper's repository group and whether a repository grants it read access. */
  repositoryReaders?: { sid: string; name: string; problem: (canonicalRoot: string) => string | null };
}

export async function contFixture(scenario: FakeScenario, opts: ContFixtureOptions = {}): Promise<ContFixture> {
  clearProbeCache();
  const f = await makeReviewFixture();
  await approve(f, { checks: { unit: { argv: [NODE, "scripts/pass.js", "CHECK_TOKEN_3a"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
  await setScenario(f, scenario);
  const clock = { now: null as number | null };
  const gone = new Set<number>();
  const unverifiable = new Set<number>();
  const reused = new Set<number>();
  // P3.4C-2: the custodian checks a bind's or re-bind's CLAUDE_PID itself; here it reaches the same verdict as the
  // identity hook below (no pid, or an unverifiable one: not verified).
  const simOptions = {
    now: () => clock.now ?? Date.now(),
    processCheck: (pid: number | null): SimProcessCheck =>
      pid === null || unverifiable.has(pid)
        ? { pid, startedAtMs: null, clientPid: process.pid, verified: false, detail: pid === null ? "CLAUDE_PID was not supplied for the hook" : "the start time could not be read (test)" }
        : { pid, startedAtMs: 1_000, clientPid: process.pid, verified: true, detail: `test process ${pid}` },
    clientCheck: (bound: SimBoundProcess) => treeCheck(bound, { gone, reused }),
    runClientCheck: (bound: SimBoundProcess) => treeCheck(bound, { gone, reused }, true),
    ...(opts.writerGone ? { writerGone: opts.writerGone } : {}),
    ...(opts.writer ? { writer: opts.writer } : {}),
    ...(opts.repositoryReaders ? { repositoryReaders: opts.repositoryReaders } : {}),
    // P3.4C-5: the custodian captures protected reviews itself (the in-process helper capture, published per ticket).
    // P3.4C-5 Increment 3: the custodian's check measurements and derivation run in process (the helper's own workload).
    ...(opts.helper === "none" ? {} : { helper: { exportsRoot: join(f.scratch, "custodian-exports"), mode: opts.helper === "manual" ? ("manual" as const) : ("auto" as const), measure: opts.measure ?? ("auto" as const), gitExe: f.git, ...(opts.freshProgress ? { freshProgress: true } : {}) } }),
  };
  const statePath = opts.accounts ? join(f.scratch, "custodian-sim.json") : undefined;
  const custodian = opts.accounts
    ? new SimulatedCustodianTransport({ ...simOptions, account: "implementer", statePath })
    : new SimulatedCustodianTransport({ ...simOptions, caller: "by_surface" });
  const operatorCustodian = opts.accounts ? new SimulatedCustodianTransport({ ...simOptions, account: "operator", statePath }) : undefined;
  const platform = opts.custodianPlatform ?? "win32";
  const hooks: EngineTestHooks = {
    custodian: { platform, transport: custodian },
    review: { codexLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] }, selfTestDeps: fakeSelfTestDeps(f), sweep: null },
    checks: { sweep: null, exitGraceMs: 1500 },
    continuation: {
      identity: async (hp): Promise<ProcessIdentity> =>
        hp.claudePid === null
          ? { pid: null, started_at_ms: null, verified: false, detail: "CLAUDE_PID was not set for the hook" }
          : unverifiable.has(hp.claudePid)
            ? { pid: hp.claudePid, started_at_ms: null, verified: false, detail: "the start time could not be read (test)" }
            : { pid: hp.claudePid, started_at_ms: 1_000, verified: true, detail: `test process ${hp.claudePid}` },
      processAlive: async (p) => p.pid !== null && !gone.has(p.pid),
      now: () => clock.now ?? Date.now(),
    },
  };
  const le = await loadEngine({ launch: { allowedRoots: [f.repo], home: f.dataHome, codex: f.codexExe, git: f.git, diagnostics: false }, sourceEnv: process.env, owner: selfOwner(), testHooks: hooks });
  const operatorHooks: EngineTestHooks | undefined = operatorCustodian ? { ...hooks, custodian: { platform, transport: operatorCustodian } } : undefined;
  return { ...f, le, custodian, clock, gone, unverifiable, reused, custodianPlatform: platform, ...(operatorCustodian ? { operatorCustodian, operatorHooks } : {}) };
}

/** Create a run over the fixture repository and wait for its baseline. */
export async function newRun(f: ContFixture, goal = "Fix add() under CodeParley automation"): Promise<RunHandle> {
  const c = await createReviewRun(f.le, { task_envelope: { goal }, repository_root: f.repo }, { roots: null });
  const p = await c.completion;
  if (p.status !== "completed") throw new Error(`baseline ${p.status}: ${JSON.stringify(p.failure)}`);
  return c.run;
}

/** The operator at an interactive terminal, answering every prompt with `answer`; `hooks` give the CLI
 * the test's (simulated) custodian. */
export function operatorIo(answer: string, interactive = true, hooks?: EngineTestHooks): CliIo & { lines: string[]; errors: string[] } {
  const lines: string[] = [];
  const errors: string[] = [];
  return { lines, errors, out: (l) => lines.push(l), err: (l) => errors.push(l), prompt: interactive ? async () => answer : null, interactive, env: process.env, cwd: process.cwd(), ...(hooks ? { engineTestHooks: hooks } : {}) };
}

/** `code-parley <args> --home <home> --git <git>` as the operator (with the fixture's custodian: with `accounts`, the
 * operator account's transport, which reaches only the operator pipe). */
export async function cli(f: ContFixture, args: string[], io: CliIo & { lines: string[]; errors: string[] } = operatorIo("")): Promise<{ code: number; out: string; err: string }> {
  const code = await runCli([...args, "--home", f.dataHome, "--git", f.git], { ...io, engineTestHooks: io.engineTestHooks ?? f.operatorHooks ?? f.le.env.testHooks! });
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

/** The backend the fixture's reviews use (the configured Windows backend, else the compatibility row's preference). */
export async function fixtureBackend(f: ContFixture): Promise<string> {
  return backendOf(f, f.le.cfg.config.codex.windows_sandbox);
}

async function backendOf(f: ReviewFixture, windowsSandbox: string | null | undefined): Promise<string> {
  const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
  return process.platform === "win32" && windowsSandbox ? windowsSandbox : probe.compat.preferredBackends[0]!;
}

/** The S1 self-test of the fixture's Codex, run (with the fake probes) and stored as `code-parley codex selftest` would. */
export async function storeFixtureSelfTest(f: ContFixture): Promise<void> {
  await storeSelfTestOf(f, await fixtureBackend(f));
}

async function storeSelfTestOf(f: ReviewFixture, backend: string): Promise<void> {
  const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
  await ensureSelfTest({
    probe,
    backend: backend as Parameters<typeof ensureSelfTest>[0]["backend"],
    mode: "S1",
    dataHome: f.dataHome,
    selftestDir: storeLayout(f.dataHome).selftestDir,
    env: buildChildEnv({ source: process.env, includeCodexAuth: true }).env,
    deps: fakeSelfTestDeps(f),
  });
}

const configured = new WeakSet<ContFixture>();

/**
 * P3.4C-4: the operator imports the repository's configuration into the custodian (`code-parley config set`, with the
 * fixture's Codex installation) and confirms the stored S1 self-test (`config confirm-selftest`) — through the real CLI,
 * at an interactive terminal, on the operator surface. A protected run needs it (CONFIG_NOT_HELD otherwise). Once per
 * fixture.
 */
export async function protectConfig(f: ContFixture, hooks?: EngineTestHooks): Promise<void> {
  if (configured.has(f)) return;
  await storeFixtureSelfTest(f);
  const set = await cli(f, ["config", "set", "--repo", f.repo, "--codex", f.codexExe], operatorIo("confirm", true, hooks));
  if (set.code !== 0) throw new Error(`config set exit ${set.code}: ${set.err}`);
  const st = await cli(f, ["config", "confirm-selftest", "--repo", f.repo, "--backend", await fixtureBackend(f), "--codex", f.codexExe], operatorIo("confirm", true, hooks));
  if (st.code !== 0) throw new Error(`config confirm-selftest exit ${st.code}: ${st.err}`);
  // P3.4C-5: the engine runtime the custodian's helper runs (a synthetic, measured tree).
  const rt = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", await syntheticRuntime(f.scratch), "--runtime-git", SYNTHETIC_RUNTIME_GIT], operatorIo("confirm", true, hooks));
  if (rt.code !== 0) throw new Error(`config approve-runtime exit ${rt.code}: ${rt.err}`);
  configured.add(f);
}

/**
 * P3.4C-4: `protectConfig` for a packaged-server fixture — the operator's CLI (in process, with `custodian`: the
 * server's file-backed simulated custodian) imports the repository's configuration and confirms the stored S1
 * self-test, so the server's protected runs hold it. The data home configures no Windows backend (the default one).
 */
export async function protectServerConfig(f: ReviewFixture, custodian: EngineTestHooks["custodian"]): Promise<void> {
  const backend = await backendOf(f, null);
  await storeSelfTestOf(f, backend);
  const hooks: EngineTestHooks = { ...(custodian ? { custodian } : {}), review: { codexLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] }, selfTestDeps: fakeSelfTestDeps(f), sweep: null } };
  const runtime = await syntheticRuntime(f.scratch);
  for (const args of [["config", "set", "--repo", f.repo, "--codex", f.codexExe], ["config", "confirm-selftest", "--repo", f.repo, "--backend", backend, "--codex", f.codexExe], ["config", "approve-runtime", "--repo", f.repo, "--runtime", runtime, "--runtime-git", SYNTHETIC_RUNTIME_GIT]]) {
    const io = operatorIo("confirm", true, hooks);
    const code = await runCli([...args, "--home", f.dataHome, "--git", f.git], io);
    if (code !== 0) throw new Error(`${args.slice(0, 2).join(" ")} exit ${code}: ${io.errors.join("\n")}`);
  }
}

/** P3.4C-4: the operator sets the repository's protected configuration again from the current local approval (a
 * definition the operator changed reaches protected runs only this way). */
export async function setConfig(f: ContFixture, hooks?: EngineTestHooks): Promise<void> {
  const set = await cli(f, ["config", "set", "--repo", f.repo, "--codex", f.codexExe], operatorIo("confirm", true, hooks));
  if (set.code !== 0) throw new Error(`config set exit ${set.code}: ${set.err}`);
}

/** P3.4C-5: the relative path of git inside the synthetic engine runtime. */
export const SYNTHETIC_RUNTIME_GIT = "git/cmd/git.exe";

/** A minimal PE image (the custodian measures node.exe and git as native images; never executed here). */
function syntheticPe(variant: number): Buffer {
  const b = Buffer.alloc(512);
  b.write("MZ", 0, "latin1");
  b[0x3c] = 0x80;
  b.write("PE", 0x80, "latin1");
  b[0x84] = 0x64;
  b[0x85] = 0x86;
  b[0x100] = variant;
  return b;
}

/** P3.4C-5: a synthetic engine runtime tree (node.exe, git, the helper entry) for `config approve-runtime`. The simulated
 * custodian's helper runs the engine's capture in process; the real one runs this tree, so a test approves only a shape. */
export async function syntheticRuntime(scratch: string): Promise<string> {
  const root = join(scratch, "engine-runtime");
  await mkdir(join(root, "git", "cmd"), { recursive: true });
  await mkdir(join(root, "dist", "helper"), { recursive: true });
  await writeFile(join(root, "node.exe"), syntheticPe(0));
  await writeFile(join(root, "git", "cmd", "git.exe"), syntheticPe(1));
  await writeFile(join(root, "dist", "helper", "main.js"), "// synthetic helper entry\n");
  return root;
}

/** The operator allows `loops` automated loops in the fixture repository (interactive terminal, typed "allow"); the
 * repository's protected configuration is imported first (P3.4C-4) unless `config: false`. */
export async function grant(f: ContFixture, loops = 1, opts: { config?: boolean } = {}): Promise<void> {
  // Phase 5: a Linux custodian holds the configuration the same way (the platforms the protected-loop gate admits).
  if (opts.config !== false && (f.custodianPlatform === "win32" || f.custodianPlatform === "linux")) await protectConfig(f);
  const r = await cli(f, ["loop", "allow", "--repo", f.repo, "--loops", String(loops), "--minutes", "60"], operatorIo("allow"));
  if (r.code !== 0) throw new Error(`loop allow exit ${r.code}: ${r.err}`);
}

/** A simulated Claude Code session: the controller's hook functions with this session's host facts. */
export class HostSession {
  readonly facts: HookFacts;
  constructor(
    readonly f: ContFixture,
    readonly sessionId: string,
    claudePid: number | null,
    transcriptPath: string | null = null,
  ) {
    this.facts = { session_id: sessionId, transcript_path: transcriptPath, claudePid, hookPid: process.pid };
  }
  /** Run one of this session's hooks: its process is inside this session's Claude process tree. */
  private hook<T>(fn: () => Promise<T>): Promise<T> {
    return inProcessTreeOf(this.facts.claudePid, fn);
  }
  /** start_review_loop as the model calls it, then the host's PostToolUse binding hook. */
  startLoop(run: RunHandle): Promise<{ nonce: string | null; bound: string }> {
    return this.hook(async () => {
      const s = await startLoop(this.f.le, run);
      const r = await onLoopStarted(this.f.le, this.facts, { content: [{ type: "text", text: JSON.stringify({ run_id: run.runId, bind_nonce: s.nonce }) }], structuredContent: { run_id: run.runId, bind_nonce: s.nonce } });
      return { nonce: s.nonce, bound: r.log };
    });
  }
  bind(runId: string, nonce: string | null) {
    return this.hook(() => onLoopStarted(this.f.le, this.facts, { structuredContent: { run_id: runId, bind_nonce: nonce } }));
  }
  stop(active = false) {
    return this.hook(() => onStop(this.f.le, this.facts, active));
  }
  prompt(text: string) {
    return this.hook(() => onUserPrompt(this.f.le, this.facts, text));
  }
  preToolUse(input: Record<string, unknown>) {
    return this.hook(() => onPreToolUse(this.f.le, this.facts, input));
  }
  sessionStart(source: string) {
    return this.hook(() => onSessionStart(this.f.le, this.facts, source));
  }
  sessionEnd(reason: string) {
    return this.hook(() => onSessionEnd(this.f.le, this.facts, reason));
  }
  configChange(source: string) {
    return this.hook(() => onConfigChange(this.f.le, this.facts, source));
  }
  arm(runId: string, operationId: string, instance: string) {
    return this.hook(() => armWake(this.f.le, this.facts, { structuredContent: { run_id: runId, operation_id: operationId, kind: "review", status: "running" } }, instance));
  }
  check(a: ArmedWake) {
    return this.hook(() => checkWake(this.f.le, a, this.facts.claudePid, this.facts.transcript_path));
  }
  consume(a: ArmedWake) {
    return this.hook(() => consumeWake(this.f.le, a, this.facts));
  }
  abandon(a: ArmedWake, reason: string) {
    return this.hook(() => abandonWake(this.f.le, a, reason));
  }
}

/** Poll the waiter's check until it leaves "wait" (or the time is up). */
export async function waitForWake(s: HostSession, a: ArmedWake, ms = 45_000): Promise<{ state: string; reason: string }> {
  const end = Date.now() + ms;
  for (;;) {
    const c = await s.check(a);
    if (c.state !== "wait" || Date.now() > end) return c;
    await new Promise((r) => setTimeout(r, 150));
  }
}

export async function runChecks(f: ContFixture, run: RunHandle): Promise<void> {
  const s = await startChecksOperation(f.le, run, {});
  const r = await s.completion;
  if (r.kind !== "checks") throw new Error("not a checks result");
}

/** Start a review (it runs in this process); returns its operation id and completion. */
export async function startReview(f: ContFixture, run: RunHandle): Promise<{ operationId: string; done: Promise<unknown> }> {
  const s = await startReviewOperation(f.le, run, {});
  return { operationId: s.operation.operation_id, done: s.completion };
}

export async function reviewCtx(f: ContFixture, run: RunHandle): Promise<ReviewEngineContext> {
  return reviewContext(f.le, run);
}

export async function loopOf(run: RunHandle) {
  const st = await readState(run.paths);
  return st.continuation!;
}

export async function eventsOf(run: RunHandle, prefix = "loop."): Promise<string[]> {
  return (await readState(run.paths)).events.filter((e) => e.type.startsWith(prefix)).map((e) => e.type);
}

export async function writeRepoFile(f: ContFixture, rel: string, text: string): Promise<void> {
  await writeFile(join(f.repo, rel), text);
}
