// A minimal MCP client over stdio for the install smoke test (Phase 5): newline-delimited JSON-RPC,
// the 2025-11-25 `initialize` handshake, `tools/list` and one `tools/call`. It exists so an
// installed CodeParley server is exercised with no dependency on the MCP SDK (the clean
// environment has none) and so stdout purity can be checked line by line.

import { spawn, spawnSync } from "node:child_process";

export const PROTOCOL_VERSION = "2025-11-25";

const delay = (ms) => new Promise((r) => setTimeout(r, ms).unref?.());

/** Start `command args` and talk JSON-RPC to it: { request, notify, close, lines, stderr }. */
export function startSession({ command, args, env, cwd, verbatim = false, timeoutMs = 60_000 }) {
  const child = spawn(command, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"], windowsHide: true, windowsVerbatimArguments: verbatim });
  const lines = [];
  const waiters = new Map();
  let buf = "";
  let stderr = "";
  let spawnError = null;
  child.on("error", (e) => {
    spawnError = e;
    for (const w of waiters.values()) w.fail(e);
    waiters.clear();
  });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (d) => {
    buf += d;
    for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
      const line = buf.slice(0, i).replace(/\r$/, "");
      buf = buf.slice(i + 1);
      if (line.trim()) onLine(line);
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (d) => {
    stderr += d;
  });
  const exited = new Promise((res) => child.on("close", (code, signal) => res({ code, signal })));

  function onLine(line) {
    lines.push(line);
    let msg = null;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const w = msg && msg.id !== undefined ? waiters.get(msg.id) : undefined;
    if (w) {
      waiters.delete(msg.id);
      w.done(msg);
    }
  }

  function request(id, method, params = {}) {
    if (spawnError) return Promise.reject(spawnError);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        waiters.delete(id);
        reject(new Error(`no response to ${method} within ${timeoutMs} ms`));
      }, timeoutMs);
      waiters.set(id, {
        done: (m) => {
          clearTimeout(t);
          resolve(m);
        },
        fail: (e) => {
          clearTimeout(t);
          reject(e);
        },
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  function notify(method, params) {
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, ...(params ? { params } : {}) })}\n`);
  }

  /** Close stdin (the host ending the session) and wait for the exit: { code, signal, timedOut }. */
  async function close(waitMs = 30_000) {
    child.stdin.end();
    const r = await Promise.race([exited, delay(waitMs).then(() => null)]);
    if (r !== null) return { ...r, timedOut: false };
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true });
    else child.kill("SIGKILL");
    return { code: null, signal: null, timedOut: true };
  }

  return { request, notify, close, lines, stderr: () => stderr, pid: child.pid };
}

/** Lines on stdout that are not JSON-RPC 2.0 messages (stdout must carry nothing else). */
export function impureLines(lines) {
  return lines.filter((l) => {
    try {
      return JSON.parse(l)?.jsonrpc !== "2.0";
    } catch {
      return true;
    }
  });
}

/**
 * The handshake an MCP host performs, then the tool list and (with `callTool`) one tool call; with `session`, an
 * async function given `call(name, args)`, further tool calls whose answers it returns as `session`.
 * Returns { serverInfo, protocolVersion, tools, call, session, exit, impure, stderr } or throws.
 */
export async function handshake(opts, { callTool = null, session = null } = {}) {
  const s = startSession(opts);
  try {
    const init = await s.request(1, "initialize", { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "codeparley-install-smoke", version: "1" } });
    if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
    s.notify("notifications/initialized");
    const list = await s.request(2, "tools/list", {});
    if (list.error) throw new Error(`tools/list failed: ${JSON.stringify(list.error)}`);
    const call = callTool ? await s.request(3, "tools/call", { name: callTool, arguments: {} }) : null;
    let id = 10;
    const more = session ? await session((name, args) => s.request(id++, "tools/call", { name, arguments: args })) : null;
    const exit = await s.close();
    return { serverInfo: init.result?.serverInfo ?? null, protocolVersion: init.result?.protocolVersion ?? null, tools: (list.result?.tools ?? []).map((t) => t.name), call, session: more, exit, impure: impureLines(s.lines), stderr: s.stderr() };
  } catch (e) {
    await s.close(5_000);
    e.stderr = s.stderr();
    throw e;
  }
}
