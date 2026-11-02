// The real Linux custodian transport (Phase 5, contract §4.4): one request per connection over the custodian's
// pathname Unix sockets (custodian/CodeParley.Custodian.Linux/Ipc/SocketServer.cs), the endpoint verified before anything
// is sent.
//
// Node cannot read SO_PEERCRED of a socket it connected (net exposes no getsockopt), so the client cannot ask the kernel
// who listens. It relies instead on where the socket is: the runtime directory /run/codeparley is created by root
// (tmpfiles.d) and nobody else can write in it, so no other account can create, replace or rename a socket there
// (unix(7): creating a socket file needs write and search permission on its directory). Before each connection the
// client checks with lstat that
//   1. /run/codeparley is a directory owned by root and neither group- nor other-writable, and
//   2. the surface's socket is a socket owned by the custodian's account (codeparley, resolved from /etc/passwd).
// Anything else is refused before a byte is written (CustodianNotTrusted). Then one request line, one response line,
// each with a deadline; any failure is fail-closed and says whether the request can have reached the custodian.
// Phase 6 (contract §7 a): an absent socket (ENOENT, ECONNREFUSED) fails at once; a full backlog (EAGAIN: present but
// busy) is retried until the busy wait ends (CustodianBusy). A connection the backlog accepted is queued behind the
// request being served, so the answer is waited for up to the hook's budget (or the usual deadline plus the default
// busy wait); one that does not come is "unknown" — the queued request may still be served after the client gave up.
// The custodian classifies the caller itself (SO_PEERCRED, before reading the request); nothing the client sends
// authenticates anything.

import { lstat, readFile } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import {
  CUSTODIAN_LINUX_ACCOUNT, CUSTODIAN_MEASURING_OPS, CUSTODIAN_PROTOCOL_VERSION, CUSTODIAN_RUNTIME_DIR, CUSTODIAN_SOCKETS,
  type CustodianOp, type CustodianResponse, type CustodianSurface,
} from "./protocol.js";
import { MEASURING_RESPONSE_MS, parseCustodianResponse } from "./pipe-transport.js";
import { CustodianBusy, CustodianNotTrusted, CustodianUnavailable, DEFAULT_BUSY_WAIT_MS, custodianClientDeadline, type CustodianTransport } from "./transport.js";

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024; // CustodianConstants.MaxResponseBytes

export interface SocketTransportOptions {
  /** TEST ONLY: other socket paths and runtime directory (default: the installed ones). */
  sockets?: Partial<Record<CustodianSurface, string>>;
  runtimeDir?: string;
  /** TEST ONLY: the uid the socket owner must be (default: the custodian account's uid from /etc/passwd). */
  expectedUid?: number;
  /** TEST ONLY: the uid the runtime directory owner must be (default: 0, root). */
  runtimeDirUid?: number;
  connectMs?: number;
  responseMs?: number;
}

/** The uid of a local account from /etc/passwd (system accounts are local; null when absent or unreadable). */
export async function localAccountUid(name: string, passwd = "/etc/passwd"): Promise<number | null> {
  let text: string;
  try {
    text = await readFile(passwd, "utf8");
  } catch {
    return null;
  }
  for (const line of text.split("\n")) {
    const f = line.split(":");
    if (f[0] === name && f.length >= 3 && /^\d+$/.test(f[2]!)) return Number(f[2]);
  }
  return null;
}

/** Why the endpoint may not be trusted (null: it may). Pure, so the rule is unit-tested without a custodian. */
export function socketEndpointProblem(
  dir: { isDirectory: boolean; uid: number; mode: number } | null,
  sock: { isSocket: boolean; uid: number; mode: number } | null,
  expect: { dirUid: number; sockUid: number },
): { problem: string; present: boolean } | null {
  if (!dir) return { problem: "the custodian's runtime directory does not exist", present: false };
  if (!dir.isDirectory) return { problem: "the custodian's runtime directory is not a directory", present: true };
  if (dir.uid !== expect.dirUid) return { problem: `the custodian's runtime directory is owned by uid ${dir.uid}, not root`, present: true };
  if ((dir.mode & 0o022) !== 0) return { problem: "the custodian's runtime directory is group- or other-writable", present: true };
  if (!sock) return { problem: "the custodian's socket does not exist", present: false };
  if (!sock.isSocket) return { problem: "the custodian's endpoint is not a socket", present: true };
  if (sock.uid !== expect.sockUid) return { problem: `the socket is owned by uid ${sock.uid}, not the custodian's account`, present: true };
  if ((sock.mode & 0o002) !== 0) return { problem: "the socket is other-writable", present: true };
  return null;
}

export class UnixSocketCustodianTransport implements CustodianTransport {
  private readonly sockets: Record<CustodianSurface, string>;
  private readonly runtimeDir: string;
  private readonly connectMs: number;
  private readonly responseMs: number;
  private readonly expectedUid: number | undefined;
  private readonly runtimeDirUid: number;

  constructor(opts: SocketTransportOptions = {}) {
    this.sockets = { ...CUSTODIAN_SOCKETS, ...(opts.sockets ?? {}) };
    this.runtimeDir = opts.runtimeDir ?? CUSTODIAN_RUNTIME_DIR;
    this.connectMs = opts.connectMs ?? 3000;
    this.responseMs = opts.responseMs ?? 20_000;
    this.expectedUid = opts.expectedUid;
    this.runtimeDirUid = opts.runtimeDirUid ?? 0;
  }

  async send(surface: CustodianSurface, op: CustodianOp, args: Record<string, unknown>, requestId: string): Promise<CustodianResponse> {
    const path = this.sockets[surface];
    const custodianUid = this.expectedUid ?? (await localAccountUid(CUSTODIAN_LINUX_ACCOUNT));
    if (custodianUid === null) throw new CustodianUnavailable(`the custodian's account '${CUSTODIAN_LINUX_ACCOUNT}' does not exist on this host`, "not_delivered");
    const stat = async (p: string) => {
      try {
        const s = await lstat(p);
        return { isDirectory: s.isDirectory(), isSocket: s.isSocket(), uid: s.uid, mode: s.mode };
      } catch {
        return null;
      }
    };
    const verdict = socketEndpointProblem(await stat(this.runtimeDir), await stat(path), { dirUid: this.runtimeDirUid, sockUid: custodianUid });
    if (verdict) {
      if (verdict.present) throw new CustodianNotTrusted(`the endpoint ${path} is not the CodeParley custodian (${verdict.problem}); nothing was sent`, "not_delivered", { socket: path });
      throw new CustodianUnavailable(`the custodian could not be reached on ${path} (${verdict.problem})`, "not_delivered");
    }
    const line = JSON.stringify({ v: CUSTODIAN_PROTOCOL_VERSION, requestId, op, args }) + "\n";
    const responseMs = CUSTODIAN_MEASURING_OPS.has(op) ? Math.max(this.responseMs, MEASURING_RESPONSE_MS) : this.responseMs;
    const text = await exchangeWhileBusy(path, line, this.connectMs, responseMs);
    const parsed = parseCustodianResponse(text);
    if (!parsed) throw new CustodianUnavailable("the custodian's response is not a valid protocol response; whether the request was applied is unknown", "unknown");
    return parsed;
  }
}

/** The socket's backlog is full (EAGAIN): the custodian is present but busy; nothing was sent. */
class Backlogged extends Error {}

/** One exchange within the waits (§7 a): under a hook deadline everything ends by it; without one, a busy custodian adds
 * the default busy wait. A full backlog is retried until the busy wait ends (CustodianBusy). */
async function exchangeWhileBusy(path: string, line: string, connectMs: number, responseMs: number): Promise<string> {
  const deadline = custodianClientDeadline();
  const started = Date.now();
  const room = deadline === null ? null : Math.max(500, deadline - started);
  const busyMs = room ?? DEFAULT_BUSY_WAIT_MS;
  const answerMs = room ?? responseMs + DEFAULT_BUSY_WAIT_MS;
  for (let attempt = 0; ; attempt++) {
    try {
      return await exchange(path, line, Math.min(connectMs, busyMs), answerMs - (Date.now() - started));
    } catch (e) {
      if (!(e instanceof Backlogged)) throw e;
      const waited = Date.now() - started;
      if (waited + 100 >= busyMs) throw new CustodianBusy(`the custodian on ${path} is busy: its connection backlog stayed full for ${waited} ms; nothing was sent`, "not_delivered", waited);
      await new Promise((r) => setTimeout(r, Math.min(100 * 2 ** Math.min(attempt, 4), 1000)));
    }
  }
}

/** Connect, send one line, read one line; deadlines on both. Before the request is written, a failure is
 * "not_delivered"; after it, "unknown". */
function exchange(path: string, line: string, connectMs: number, responseMs: number): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let sent = false;
    let done = false;
    const chunks: Buffer[] = [];
    let size = 0;
    const sock: Socket = createConnection({ path });
    const fail = (e: Error): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      reject(e);
    };
    let timer = setTimeout(() => fail(new CustodianUnavailable(`the custodian did not accept the connection on ${path} within ${connectMs} ms`, "not_delivered")), connectMs);
    sock.once("connect", () => {
      clearTimeout(timer);
      const answerMs = Math.max(1, responseMs);
      timer = setTimeout(() => fail(new CustodianUnavailable(`the custodian did not answer within ${answerMs} ms (busy with earlier requests, or not serving); whether the request was applied is unknown`, "unknown")), answerMs);
      sent = true;
      sock.write(line);
    });
    sock.on("data", (b: Buffer) => {
      size += b.length;
      if (size > MAX_RESPONSE_BYTES + 1) return fail(new CustodianUnavailable("the custodian's response is too large; whether the request was applied is unknown", "unknown"));
      chunks.push(b);
      const all = Buffer.concat(chunks);
      const nl = all.indexOf(0x0a);
      if (nl >= 0) {
        done = true;
        clearTimeout(timer);
        sock.end();
        resolve(all.subarray(0, nl).toString("utf8").replace(/\r$/, ""));
      }
    });
    sock.on("error", (e: NodeJS.ErrnoException) => {
      if (!sent && e.code === "EAGAIN") return fail(new Backlogged(e.message));
      const why = e.code === "EACCES" ? "permission denied (this account is not allowed on this surface)" : e.code ?? e.message;
      fail(new CustodianUnavailable(`the custodian could not be reached on ${path} (${why})${sent ? "; whether the request was applied is unknown" : ""}`, sent ? "unknown" : "not_delivered"));
    });
    sock.on("close", () => fail(new CustodianUnavailable(`the custodian closed the connection on ${path} without a response${sent ? "; whether the request was applied is unknown" : ""}`, sent ? "unknown" : "not_delivered")));
  });
}
