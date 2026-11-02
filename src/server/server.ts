// The stdio MCP server process (plan §5.1, §11; M1.5). One process per host session.
//
//  - stdout carries only MCP messages (the SDK transport); diagnostics go to stderr and to
//    <data home>\logs\server-<date>.log — never source content or environment values;
//  - nothing depends on the working directory: configuration and data come from launch
//    arguments, the configuration file and the data home;
//  - when stdin closes (the host ended the session) — or, on Linux, on SIGTERM/SIGINT/SIGHUP —
//    every operation this process owns is cancelled and given a bounded time to commit its
//    outcome and termination evidence; an abrupt kill instead leaves them for recovery (§15.5)
//    by the next server.

import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { TOOL_VERSION } from "../common/version.js";
import { parseLaunchArgs, type LaunchArgs } from "../config/launch-args.js";
import { loadConfig } from "../config/load-config.js";
import { ensurePrivateDataHome, loadEngine, type EngineEnv, type EngineTestHooks } from "../engine/engine-env.js";
import { cancelOwnedOperations } from "../engine/operations.js";
import { applyRetention } from "../engine/retention.js";
import { selfOwner } from "../store/owner.js";
import { serveStdio } from "./sdk.js";
import { SERVER_INSTRUCTIONS, SERVER_NAME, callTool, toolDefinitions, type Session } from "./tools.js";

export interface ServerOptions {
  argv: readonly string[];
  env: NodeJS.ProcessEnv;
  /** TEST ONLY: fake Codex, scripted process tables, faster polling. */
  testHooks?: EngineTestHooks;
  /** Bound on the shutdown wait for owned operations (default 15 s). */
  shutdownWaitMs?: number;
  /** Delay before the startup retention pass (default 3 s; it never delays serving). */
  retentionDelayMs?: number;
}

/** The server log: stderr, and a daily file under the data home (best effort). Exported for tests. */
export function makeLogger(launch: LaunchArgs, env: NodeJS.ProcessEnv): Promise<(line: string) => void> {
  return loadConfig(launch, env)
    .then(async (cfg) => {
      // Linux: the data home is made private (0700) before anything is written into it; a log
      // folder created first would give it the process umask's mode, which the engine then
      // refuses, and expose the logs meanwhile.
      if (process.platform === "linux") await ensurePrivateDataHome(cfg.dataHome);
      const dir = join(cfg.dataHome, "logs");
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      return join(dir, `server-${new Date().toISOString().slice(0, 10)}.log`);
    })
    .catch(() => null)
    .then((file) => (line: string) => {
      const text = `${new Date().toISOString()} [${process.pid}] ${line}\n`;
      process.stderr.write(text);
      if (file) {
        try {
          appendFileSync(file, text, { mode: 0o600 });
        } catch {
          /* logging is best effort */
        }
      }
    });
}

export async function runServer(o: ServerOptions): Promise<void> {
  let launch: LaunchArgs;
  try {
    launch = parseLaunchArgs(o.argv);
  } catch (e) {
    process.stderr.write(`code-parley: ${(e as Error).message}\n`);
    process.exitCode = 2;
    return;
  }
  const log = await makeLogger(launch, o.env);
  const env: EngineEnv = { launch, sourceEnv: o.env, owner: selfOwner(), ...(o.testHooks ? { testHooks: o.testHooks } : {}) };
  log(`server ${TOOL_VERSION} starting (node ${process.version}; diagnostics ${launch.diagnostics ? "on" : "off"}; ${launch.allowedRoots.length} launch root(s))`);
  process.on("unhandledRejection", (e) => log(`unhandled rejection: ${e instanceof Error ? e.message : String(e)}`));

  let shuttingDown = false;
  const shutdown = async (why: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`${why}: cancelling owned operations`);
    const n = await cancelOwnedOperations(o.shutdownWaitMs ?? 15_000).catch(() => -1);
    log(`shutdown complete (${n} owned operation(s) cancelled)`);
    process.exit(0);
  };

  serveStdio({
    name: SERVER_NAME,
    version: TOOL_VERSION,
    instructions: SERVER_INSTRUCTIONS,
    onError: (e) => log(`protocol error: ${e.message}`),
    session: () => {
      const session: Session = { env, diagnostics: launch.diagnostics, legacyRoots: null, log };
      return {
        tools: () => toolDefinitions(launch.diagnostics),
        call: (name, args, ctx) => callTool(session, name, args, ctx),
        rootsChanged: (roots) => {
          session.legacyRoots = roots;
          log(`client roots: ${roots === null ? "unavailable" : `${roots.length} root(s)`}`);
        },
        closed: () => void shutdown("transport closed"),
      };
    },
  });
  process.stdin.on("end", () => void shutdown("stdin closed"));
  // Linux (plan §1.13): a host ending the session, a closed terminal or Ctrl-C arrives as a
  // signal; it gets the same bounded shutdown as a closed stdin (owned operations cancelled and
  // their termination evidence committed). A SIGKILL cannot be handled: the session reaper ends
  // the children and recovery records the rest. Windows has no such signals (TerminateProcess).
  if (process.platform !== "win32") {
    for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.on(sig, () => void shutdown(`${sig} received`));
  }

  // Retention (plan §15.6, §1.12): once the transport is up, apply the trusted retention
  // policy. It runs in the background, is bounded, and its failures are logged and recorded
  // (logs\retention-last.json) — they never stop the server from serving.
  const retention = setTimeout(() => {
    if (shuttingDown) return;
    void loadEngine(env)
      .then((le) => applyRetention(le, log))
      .catch((e: unknown) => log(`retention: not applied (${e instanceof Error ? e.message : String(e)})`));
  }, o.retentionDelayMs ?? 3000);
  retention.unref();
}
