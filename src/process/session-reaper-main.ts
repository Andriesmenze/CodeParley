// Entry point of the session reaper process (Linux; see session-reaper.ts). It reads ownership
// lines from stdin — {"op":"own","pid":N,"ticks":T} and {"op":"release","pid":N} — and, when stdin
// ends or its parent changes (the server is gone), ends every session still registered and exits.
// It is not an MCP server and writes nothing.

import { createInterface } from "node:readline";
import { killTreePosix } from "./kill-tree.js";

const serverPid = Number(process.argv[2]);
const owned = new Map<number, number>();
let ending = false;

createInterface({ input: process.stdin }).on("line", (line) => {
  try {
    const m = JSON.parse(line) as { op?: string; pid?: unknown; ticks?: unknown };
    if (typeof m.pid !== "number" || !Number.isSafeInteger(m.pid) || m.pid <= 1) return;
    if (m.op === "own" && typeof m.ticks === "number") owned.set(m.pid, m.ticks);
    else if (m.op === "release") owned.delete(m.pid);
  } catch {
    /* a malformed line registers nothing */
  }
});

async function end(): Promise<void> {
  if (ending) return;
  ending = true;
  // Each session is matched by its leader's exact identity (the registered start ticks).
  await Promise.all([...owned].map(([pid, ticks]) => killTreePosix(pid, { timeoutMs: 10_000, startTicks: ticks }).catch(() => false)));
  process.exit(0);
}

process.stdin.on("end", () => void end());
process.stdin.on("close", () => void end());
// Backstop: the server died but something still holds the pipe open.
setInterval(() => {
  if (process.ppid !== serverPid) void end();
}, 1000);
