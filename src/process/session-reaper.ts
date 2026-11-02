// The session reaper (Linux; plan §1.13) — the Linux counterpart of the kill-on-close job object
// that ends a Windows server's direct children when the server exits (G7).
//
// On Linux a child does not die with its parent. Every child CodeParley starts leads its own
// session (spawn.ts), and this module hands each one, by PID and exact start ticks, to ONE small
// helper process per server: `session-reaper-main.js`, started detached (its own session, so a
// signal to the server's terminal or process group does not reach it), whose stdin is a pipe
// only the server holds (pipes are close-on-exec: no other child inherits the write end). When
// that pipe reaches end-of-file — the server exited, however it exited, SIGKILL included — or the
// reaper's parent changes, the reaper ends every session still registered (process/kill-tree.ts,
// identity-checked, SIGTERM then SIGKILL) and exits. The server releases a session as soon as
// its direct child has exited (the caller's descendant sweep handles what remains). The reaper
// signals nothing it was not given. If it cannot be started (no compiled entry, as in in-process
// unit tests), children are not reaped on a server crash and recovery handles them (§15.5).

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

let reaper: ChildProcess | null = null;
let unavailable = false;

function mainPath(): string | null {
  try {
    const p = fileURLToPath(new URL("./session-reaper-main.js", import.meta.url));
    return existsSync(p) ? p : null;
  } catch {
    return null;
  }
}

function ensureReaper(): ChildProcess | null {
  if (process.platform !== "linux" || unavailable) return null;
  if (reaper && reaper.exitCode === null && reaper.signalCode === null && reaper.stdin && !reaper.stdin.destroyed) return reaper;
  const main = mainPath();
  if (!main) {
    unavailable = true;
    return null;
  }
  try {
    const c = spawn(process.execPath, [main, String(process.pid)], { detached: true, stdio: ["pipe", "ignore", "ignore"], env: {} });
    c.on("error", () => {
      if (reaper === c) reaper = null;
    });
    c.on("exit", () => {
      if (reaper === c) reaper = null;
    });
    c.stdin?.on("error", () => {
      if (reaper === c) reaper = null;
    });
    // The reaper must never keep this server alive.
    c.unref();
    (c.stdin as unknown as { unref?: () => void } | null)?.unref?.();
    reaper = c;
    return c;
  } catch {
    unavailable = true;
    return null;
  }
}

function send(msg: Record<string, unknown>): boolean {
  const r = ensureReaper();
  if (!r?.stdin) return false;
  try {
    return r.stdin.write(`${JSON.stringify(msg)}\n`) || true;
  } catch {
    return false;
  }
}

/** Register a session this server started (its leader's PID and start ticks). Linux only. */
export function ownSession(pid: number, startTicks: number): boolean {
  return send({ op: "own", pid, ticks: startTicks });
}

/** The session's leader has exited and been waited for: stop reaping it. */
export function releaseSession(pid: number): void {
  if (reaper) send({ op: "release", pid });
}

/** Is a session reaper running for this server (Linux)? */
export function sessionReaperRunning(): boolean {
  return reaper !== null && reaper.exitCode === null && reaper.signalCode === null;
}
