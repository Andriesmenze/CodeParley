// MCP protocol test harness (plan §18.1 "MCP protocol"; M1.5). The server is compiled once per
// test file into .tmp-test-dist/ (git-ignored) and launched over REAL stdio through a
// TEST-ONLY entry script that wires the scripted fake Codex (test/fixtures/fake-codex) into
// the engine's test hooks; the production entry (src/server/main.ts) has no test hooks.
// Clients: TypeScript SDK v2 pinned to the 2025 era (`legacy`), v2 negotiating 2026-07-28
// (`auto`), and SDK v1 (2025 era) — the three client runtimes the hosts use (K1).

import { spawnSync, type ChildProcess } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Client as V1Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport as V1Transport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ListRootsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { buildSrc } from "./build-src.js";
import { sharedCompiledSrc } from "./compiled-src.js";
import { TEST_SERVER_SOURCE } from "./test-server-source.js";
import { TEST_HOOKS_SOURCE } from "./test-hooks-source.js";

export const repoRootDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..");


let compiled: string | null = null;
let ownBuild = false;

/**
 * The compiled server with its TEST-ONLY entry: the run-wide shared build when there is one
 * (test/global-setup.ts writes the entry into it), else a build of this test file's own.
 */
export async function compileServer(): Promise<string> {
  if (compiled) return compiled;
  const shared = sharedCompiledSrc();
  if (shared) {
    compiled = shared;
    return shared;
  }
  const outDir = join(repoRootDir, ".tmp-test-dist", `mcp-${randomBytes(4).toString("hex")}`);
  buildSrc(repoRootDir, outDir);
  await writeFile(join(outDir, "test-server.mjs"), TEST_SERVER_SOURCE);
  await writeFile(join(outDir, "test-hooks.mjs"), TEST_HOOKS_SOURCE);
  compiled = outDir;
  ownBuild = true;
  return outDir;
}

/** Remove this test file's own build (afterAll); the shared build is removed by the global teardown. */
export async function removeCompiledServer(): Promise<void> {
  if (!compiled) return;
  const dir = compiled;
  const own = ownBuild;
  compiled = null;
  ownBuild = false;
  if (own) await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}

export type Flavor = "v2-legacy" | "v2-modern" | "v1";
export const FLAVORS: Flavor[] = ["v2-legacy", "v2-modern", "v1"];

export interface ServerConfig {
  argv: string[];
  fake?: { script: string };
  shutdownWaitMs?: number;
  /** Delay of the startup retention pass (production default 3 s). */
  retentionDelayMs?: number;
  /** Bound on an operation's wait for a bounded read holding the worktree lock (production 30 s). */
  worktreeWaitMs?: number;
  /** P3.4C-0: the server's (simulated, file-backed) grant custodian, shared with the test's in-process CLI. */
  custodianState?: string;
}

export interface CallResult {
  structuredContent?: Record<string, unknown>;
  content?: { type: string; text?: string }[];
  isError?: boolean;
}

export interface Conn {
  flavor: Flavor;
  call(name: string, args: Record<string, unknown>, opts?: { signal?: AbortSignal; timeoutMs?: number }): Promise<CallResult>;
  listTools(): Promise<{ name: string; title?: string; description?: string; inputSchema: unknown; outputSchema?: unknown; annotations?: Record<string, unknown> }[]>;
  protocolVersion(): string | undefined;
  setRoots(paths: string[]): Promise<void>;
  pid: number | null;
  stderr: string[];
  close(): Promise<void>;
  /**
   * End the session as a host that waits for the server does: close its stdin and wait for the
   * server to exit by itself. Resolves with its exit code (null after a signal), or "timeout" if
   * it was still running after `ms`; either way the client is closed before this resolves, and
   * after a timeout that close kills the server (up to 4 s more). close() alone is no
   * substitute: the SDKs kill the server 2 s after closing stdin.
   */
  endSession(ms: number): Promise<number | null | "timeout">;
}

export interface ConnectOptions {
  /** Working directory of the server process (cwd independence). */
  cwd?: string;
  /** Environment of the server process; default: this process's environment. */
  env?: Record<string, string>;
  /** Client roots (local paths); the client declares the roots capability when set. */
  roots?: string[];
  /** The client declares roots but its roots/list handler fails. */
  rootsFail?: boolean;
  /** Extra time for slow calls (ms). */
  timeoutMs?: number;
}

function fileUri(p: string): string {
  return pathToFileURL(p).href;
}

export async function connect(flavor: Flavor, cfgPath: string, o: ConnectOptions = {}): Promise<Conn> {
  const dir = await compileServer();
  const env: Record<string, string> = { ...(o.env ?? (process.env as Record<string, string>)), CODEPARLEY_TEST_SERVER_CONFIG: cfgPath };
  const params = { command: process.execPath, args: [join(dir, "test-server.mjs")], env, cwd: o.cwd ?? dir, stderr: "pipe" as const };
  let roots = (o.roots ?? []).map((p) => ({ uri: fileUri(p), name: p }));
  const stderr: string[] = [];
  const timeout = o.timeoutMs ?? 90_000;
  if (flavor === "v1") {
    const client = new V1Client({ name: "arl-test-v1", version: "1.0.0" }, { capabilities: o.roots ? { roots: { listChanged: true } } : {} });
    if (o.roots) client.setRequestHandler(ListRootsRequestSchema, () => ({ roots }));
    const transport = new V1Transport(params);
    transport.stderr?.on("data", (d: Buffer) => stderr.push(d.toString("utf8")));
    await client.connect(transport);
    return {
      flavor,
      call: (name, args, co) => client.callTool({ name, arguments: args }, undefined, { timeout: co?.timeoutMs ?? timeout, ...(co?.signal ? { signal: co.signal } : {}) }) as Promise<CallResult>,
      listTools: async () => (await client.listTools()).tools as never,
      protocolVersion: () => (client as unknown as { _serverVersion?: unknown; transport?: { protocolVersion?: string } }).transport?.protocolVersion,
      setRoots: async (paths) => {
        roots = paths.map((p) => ({ uri: fileUri(p), name: p }));
        await client.sendRootsListChanged();
      },
      pid: transport.pid,
      stderr,
      close: () => client.close(),
      endSession: (ms) => endSession(transport, () => client.close(), ms),
    };
  }
  const client = new Client({ name: "arl-test-v2", version: "2.0.0" }, { capabilities: o.roots ? { roots: { listChanged: true } } : {}, versionNegotiation: { mode: flavor === "v2-modern" ? "auto" : "legacy" } });
  if (o.roots) client.setRequestHandler("roots/list", () => {
    if (o.rootsFail) throw new Error("roots unavailable");
    return { roots };
  });
  const transport = new StdioClientTransport(params);
  transport.stderr?.on("data", (d: Buffer) => stderr.push(d.toString("utf8")));
  await client.connect(transport);
  return {
    flavor,
    call: (name, args, co) => client.callTool({ name, arguments: args }, { timeout: co?.timeoutMs ?? timeout, ...(co?.signal ? { signal: co.signal } : {}) }) as Promise<CallResult>,
    listTools: async () => (await client.listTools()).tools as never,
    protocolVersion: () => client.getNegotiatedProtocolVersion?.() ?? undefined,
    setRoots: async (paths) => {
      roots = paths.map((p) => ({ uri: fileUri(p), name: p }));
      // 2026-07-28 has no roots/list_changed notification: the server asks per call.
      if (flavor !== "v2-modern") await client.sendRootsListChanged();
    },
    pid: transport.pid,
    stderr,
    close: () => client.close(),
    endSession: (ms) => endSession(transport, () => client.close(), ms),
  };
}

/**
 * Close the server's stdin and wait for the server to exit by itself. The SDKs' close() also
 * ends stdin, but kills the server 2 s later (SIGTERM, which is TerminateProcess on Windows,
 * then SIGKILL after 2 s more), cutting short the bounded shutdown in which the server records
 * its operations' outcomes. Both pinned SDKs keep the child process in the transport's private
 * `_process` (the transport spawns it; it cannot be handed one); if a new version does not, this
 * throws rather than falling back to close(), which would bring the 2 s kill back unnoticed.
 * The client is closed before this resolves: after a timeout that close kills the server.
 */
async function endSession(transport: object, close: () => Promise<void>, ms: number): Promise<number | null | "timeout"> {
  const child = (transport as { _process?: ChildProcess })._process;
  if (!child?.stdin) {
    const name = (transport as { constructor?: { name?: string } }).constructor?.name ?? "the transport";
    throw new Error(`endSession: ${name} does not expose the server process (the pinned SDKs keep it in _process); update endSession for this SDK version rather than falling back to close(), which kills the server 2 s after closing stdin`);
  }
  const exited = new Promise<number | null>((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) resolve(child.exitCode);
    else child.once("exit", (code) => resolve(code));
  });
  child.stdin.end();
  let timer: NodeJS.Timeout | undefined;
  const timedOut = new Promise<"timeout">((r) => {
    timer = setTimeout(() => r("timeout"), ms);
  });
  const result = await Promise.race([exited, timedOut]);
  clearTimeout(timer);
  await close(); // releases the client; only after a timeout is there still a server to kill
  return result;
}

export async function writeServerConfig(dir: string, cfg: ServerConfig): Promise<string> {
  await mkdir(dir, { recursive: true });
  const p = join(dir, `server-${randomBytes(4).toString("hex")}.json`);
  await writeFile(p, JSON.stringify(cfg));
  return p;
}

/** The structured result, asserting the MCP result contract (object + identical text copy). */
export function sc(r: CallResult): Record<string, unknown> {
  if (!r.structuredContent || typeof r.structuredContent !== "object") throw new Error(`no structuredContent: ${JSON.stringify(r).slice(0, 500)}`);
  const text = r.content?.find((c) => c.type === "text")?.text;
  if (text === undefined || JSON.stringify(JSON.parse(text)) !== JSON.stringify(r.structuredContent)) throw new Error("the text block is not the JSON of structuredContent");
  return r.structuredContent;
}

export function errorCode(r: CallResult): string | null {
  const e = (r.structuredContent as { error?: { code?: string } } | undefined)?.error;
  return r.isError ? (e?.code ?? "NO_CODE") : null;
}

export async function waitUntil(fn: () => Promise<boolean> | boolean, ms: number, stepMs = 200): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return fn();
}

/** Kill the server process alone, abruptly (Windows: TerminateProcess via taskkill /F; Linux: SIGKILL). */
export function taskkillHard(pid: number): void {
  if (process.platform !== "win32") {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* already gone */
    }
    return;
  }
  spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(pid), "/F"], { windowsHide: true });
}
