// P3.4C-0 increment 2: the real Windows custodian transport (src/custodian/pipe-transport.ts).
//
// Pure units (any OS): the helper's output parsing, the pipe-security policy, the response envelope and
// the delivery outcome of every failure, with the helper run injected.
//
// Windows only: the helper against REAL named pipes on this host — a squatting server owned by this user
// is refused before a byte is sent; a verified endpoint gets exactly one request line and its response is
// accepted; malformed, closed and silent servers are fail-closed with outcome "unknown"; a pipe whose
// access list lets another principal create instances is refused; and the OS fact the anti-squat check
// rests on — a DACL granting ReadWrite (not CreateNewInstance) stops a same-user process from adding an
// instance of a held pipe — is measured. These use this process's DEFAULT OWNER as the expected owner where a
// positive path is needed (a test server cannot be owned by the custodian's service SID); the real service
// identity is verified on the disposable VM (increment 3). Phase 6 S-1: the default owner of the objects a
// process creates is its user SID with a standard token, but BUILTIN\Administrators (S-1-5-32-544) with an
// elevated one (an elevated CI runner); the transport refuses such a pipe for the custodian (the owner must be
// exactly the service SID), and the tests take the owner from the token instead of assuming the user SID.

import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { createServer, type Server, type Socket } from "node:net";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDomainError } from "../src/common/errors.js";
import { uuidv7 } from "../src/common/ids.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import {
  CLIENT_START_MS, MEASURING_RESPONSE_MS, RESPONSE_FLOOR_MS,
  FOREIGN_FORBIDDEN_RIGHTS, PipeCustodianTransport, clientWaits, parseCustodianResponse, parsePipeOutput, pipeSecurityProblem,
  type HelperRun,
} from "../src/custodian/pipe-transport.js";
import { CUSTODIAN_PROTOCOL_VERSION, custodianServiceSid } from "../src/custodian/protocol.js";
import { CustodianBusy, CustodianNotTrusted, CustodianUnavailable, DEFAULT_BUSY_WAIT_MS, setCustodianClientDeadline } from "../src/custodian/transport.js";
import { CustodianGrants } from "../src/custodian/grants.js";

const SERVICE = custodianServiceSid();
const ME = "S-1-5-21-1-2-3-1001";
const enc = (s: string) => Buffer.from(s, "utf8").toString("base64");
const result = (stage: string, ok: boolean, owner: string, aces: string, error: string, response: string) =>
  `@@result ${stage} ${ok ? 1 : 0} ${enc(owner)} ${enc(aces)} ${enc(error)} ${enc(response)}`;
const run = (r: Partial<HelperRun>) => async (): Promise<HelperRun> => ({ status: 0, stdout: "", spawnError: null, timedOut: false, ...r });

async function failure(p: Promise<unknown>): Promise<{ type: string; outcome: string | undefined; message: string }> {
  try {
    await p;
    return { type: "NO_ERROR", outcome: undefined, message: "" };
  } catch (e) {
    if (e instanceof CustodianNotTrusted) return { type: "NOT_TRUSTED", outcome: e.outcome, message: e.message };
    if (e instanceof CustodianBusy) return { type: "BUSY", outcome: e.outcome, message: e.message };
    if (e instanceof CustodianUnavailable) return { type: "UNAVAILABLE", outcome: e.outcome, message: e.message };
    return { type: `OTHER:${String(e)}`, outcome: undefined, message: String(e) };
  }
}

// Phase 6 S-1: an elevated process's objects are owned by BUILTIN\Administrators; that is not the custodian.
describe("pipe-transport units: an elevated owner (any OS)", () => {
  it("refuses a pipe owned by BUILTIN\\Administrators, the default owner of an elevated process's objects", () => {
    expect(pipeSecurityProblem("S-1-5-32-544", [{ sid: "S-1-5-18", allow: true, rights: 0x1f019f }], SERVICE)).toMatch(/owned by S-1-5-32-544, not by the custodian/);
  });
});

describe("pipe-transport units (any OS)", () => {
  it("accepts only the expected owner, and no foreign principal that could add instances or change security", () => {
    expect(pipeSecurityProblem(SERVICE, [{ sid: "S-1-5-18", allow: true, rights: 0x1f019f }, { sid: ME, allow: true, rights: 0x2019b }], SERVICE)).toBeNull();
    expect(pipeSecurityProblem(ME, [], SERVICE)).toMatch(/owned by S-1-5-21-1-2-3-1001, not by the custodian/);
    expect(pipeSecurityProblem("", [], SERVICE)).toMatch(/owner could not be read/);
    // CreateNewInstance (FILE_APPEND_DATA) for the implementer: an extra instance could be served by anyone.
    expect(pipeSecurityProblem(SERVICE, [{ sid: ME, allow: true, rights: 0x2019b | 0x4 }], SERVICE)).toMatch(/create pipe instances/);
    for (const right of [0x40000, 0x80000, 0x10000000, 0x40000000]) expect(pipeSecurityProblem(SERVICE, [{ sid: "S-1-1-0", allow: true, rights: right }], SERVICE)).not.toBeNull();
    // A deny entry only reduces access.
    expect(pipeSecurityProblem(SERVICE, [{ sid: "S-1-1-0", allow: false, rights: FOREIGN_FORBIDDEN_RIGHTS }], SERVICE)).toBeNull();
  });

  it("validates the response envelope strictly", () => {
    expect(parseCustodianResponse('{"ok":true,"data":{"pong":true}}')).toEqual({ ok: true, data: { pong: true } });
    expect(parseCustodianResponse('{"ok":false,"code":"LOOP_NOT_AUTHORIZED","error":"no"}')).toEqual({ ok: false, code: "LOOP_NOT_AUTHORIZED", error: "no" });
    for (const bad of ["", "not json", "[]", '{"ok":"yes"}', '{"ok":true,"data":[]}', '{"ok":false,"code":"x y","error":"e"}', '{"ok":false,"code":"A"}', '{"ok":true,"extra":1}']) {
      expect(parseCustodianResponse(bad), bad).toBeNull();
    }
  });

  it("parses the helper's report", () => {
    const x = parsePipeOutput(`noise\r\n@@verified\r\n${result("done", true, SERVICE, `S-1-5-18:1:2032031;${ME}:1:131483`, "", '{"ok":true}')}\r\n`);
    expect(x.verified).toBe(true);
    expect(x.result).toEqual({ stage: "done", ok: true, owner: SERVICE, aces: [{ sid: "S-1-5-18", allow: true, rights: 2032031 }, { sid: ME, allow: true, rights: 131483 }], error: "", response: '{"ok":true}' });
    expect(parsePipeOutput("@@result bogus 1 a b c d").result).toBeNull();
  });

  it("maps every failure to fail-closed with the right delivery outcome", async () => {
    const t = (r: Partial<HelperRun>) => new PipeCustodianTransport({ run: run(r) }).send("implementer", "ping", {}, "r1");
    // Never started, or ended before verification: provably not delivered.
    expect(await failure(t({ spawnError: "ENOENT" }))).toMatchObject({ type: "UNAVAILABLE", outcome: "not_delivered" });
    expect(await failure(t({ status: 1, stdout: "" }))).toMatchObject({ type: "UNAVAILABLE", outcome: "not_delivered" });
    expect(await failure(t({ status: 2, stdout: result("connect", false, "", "", "TimeoutException", "") }))).toMatchObject({ type: "UNAVAILABLE", outcome: "not_delivered" });
    expect(await failure(t({ status: 3, stdout: result("security", false, ME, "", "owned by someone else", "") }))).toMatchObject({ type: "NOT_TRUSTED", outcome: "not_delivered" });
    // After verification: the request may have been applied.
    expect(await failure(t({ timedOut: true, status: null, stdout: "@@verified\n" }))).toMatchObject({ type: "UNAVAILABLE", outcome: "unknown" });
    expect(await failure(t({ status: 4, stdout: "@@verified\n" + result("receive", false, SERVICE, "", "timed out waiting for the response", "") }))).toMatchObject({ type: "UNAVAILABLE", outcome: "unknown" });
    expect(await failure(t({ status: 0, stdout: "@@verified\n" + result("done", true, SERVICE, "", "", "garbage") }))).toMatchObject({ type: "UNAVAILABLE", outcome: "unknown" });
    // Evidence that does not hold is never accepted, even with a valid-looking response.
    expect(await failure(t({ status: 0, stdout: "@@verified\n" + result("done", true, ME, "", "", '{"ok":true}') }))).toMatchObject({ type: "NOT_TRUSTED", outcome: "unknown" });
    // A verified, valid exchange.
    const ok = await new PipeCustodianTransport({ run: run({ status: 0, stdout: "@@verified\n" + result("done", true, SERVICE, `S-1-5-18:1:2032031`, "", '{"ok":true,"data":{"pong":true}}') }) }).send("implementer", "ping", {}, "r2");
    expect(ok).toEqual({ ok: true, data: { pong: true } });
  });

  it("sends the pipe, the expected owner and exactly one protocol line to the helper", async () => {
    let seen = "";
    const t = new PipeCustodianTransport({ connectMs: 1234, responseMs: 5678, run: async (stdin) => ((seen = stdin), { status: 1, stdout: "", spawnError: null, timedOut: false }) });
    await failure(t.send("operator", "consume_loop", { repositoryRoot: "C:\\r" }, "req-9"));
    const [pipe, owner, line, c, r] = seen.split("\n");
    expect(pipe).toBe("CodeParley.Custodian.v1.operator");
    expect(owner).toBe(SERVICE);
    expect(Buffer.from(line!, "base64").toString("utf8")).toBe('{"v":1,"requestId":"req-9","op":"consume_loop","args":{"repositoryRoot":"C:\\\\r"}}\n');
    expect([c, r]).toEqual(["1234", "5678"]);
  });

  it("P3.4C-5: a configuration prepare or commit (the custodian measures the engine runtime inside it) gets the longer response deadline", async () => {
    const seen: string[] = [];
    const t = new PipeCustodianTransport({ connectMs: 1234, responseMs: 5678, run: async (stdin, wallMs) => (seen.push(`${stdin.split("\n")[4]}|${wallMs}`), { status: 1, stdout: "", spawnError: null, timedOut: false }) });
    await failure(t.send("operator", "prepare_config_record", { recordKind: "engine_runtime" }, "req-10"));
    await failure(t.send("operator", "commit", { authorizationRequestId: "req-10" }, "req-11"));
    await failure(t.send("operator", "list_grants", {}, "req-12"));
    const busy = DEFAULT_BUSY_WAIT_MS; // no hook deadline: a busy custodian is waited for the default
    expect(seen).toEqual([`${MEASURING_RESPONSE_MS}|${busy + 2 * MEASURING_RESPONSE_MS + 30_000}`, `${MEASURING_RESPONSE_MS}|${busy + 2 * MEASURING_RESPONSE_MS + 30_000}`, `5678|${busy + 2 * 5678 + 30_000}`]);
  });

  it("Phase 6 §7 a: the waits — an absent pipe for the connect time, a busy one for the default or until the hook's deadline leaves room for an answer", () => {
    expect(clientWaits(3000, null, 1_000)).toEqual({ absentMs: 3000, busyMs: DEFAULT_BUSY_WAIT_MS, budgetMs: 0 });
    // SessionStart: 30 s minus the hook's 5 s margin, from a hook that started now.
    const now = 1_000_000;
    const w = clientWaits(3000, now + 25_000, now);
    expect(w).toEqual({ absentMs: 3000, busyMs: 25_000 - CLIENT_START_MS - RESPONSE_FLOOR_MS, budgetMs: 25_000 - CLIENT_START_MS });
    expect(w.budgetMs).toBeLessThan(25_000); // the whole exchange ends before the deadline
    // Nearly out of time: never more than what is left (at least a short attempt), and never longer than the budget.
    const late = clientWaits(3000, now + 1000, now);
    expect(late.budgetMs).toBe(500);
    expect(late.absentMs).toBeLessThanOrEqual(late.budgetMs);
    expect(late.busyMs).toBeLessThanOrEqual(late.budgetMs);
  });

  it("Phase 6 §7 a: the helper is given the busy wait and the budget; an absent pipe (exit 6) is unavailable, a busy one (exit 7) is CUSTODIAN_BUSY, both not delivered", async () => {
    let seen = "";
    const at = Date.now();
    setCustodianClientDeadline(at + 25_000);
    try {
      await failure(new PipeCustodianTransport({ connectMs: 3000, run: async (stdin) => ((seen = stdin), { status: 1, stdout: "", spawnError: null, timedOut: false }) }).send("implementer", "ping", {}, "r"));
    } finally {
      setCustodianClientDeadline(null);
    }
    const lines = seen.split("\n");
    expect(Number(lines[3])).toBe(3000);
    expect(Number(lines[6])).toBeLessThanOrEqual(25_000 - CLIENT_START_MS - RESPONSE_FLOOR_MS);
    expect(Number(lines[7])).toBeLessThanOrEqual(25_000 - CLIENT_START_MS);
    expect(Number(lines[6])).toBeGreaterThan(15_000);
    const t = (r: Partial<HelperRun>) => new PipeCustodianTransport({ run: run(r) }).send("implementer", "ping", {}, "r1");
    expect(await failure(t({ status: 6, stdout: result("connect", false, "", "", "absent: no pipe x exists", "") }))).toMatchObject({ type: "UNAVAILABLE", outcome: "not_delivered" });
    expect(await failure(t({ status: 7, stdout: result("connect", false, "", "", "busy: the pipe exists but no instance became free within 30000 ms", "") }))).toMatchObject({ type: "BUSY", outcome: "not_delivered" });
    const busy = new CustodianGrants({ send: async () => { throw new CustodianBusy("busy", "not_delivered", 1234); } });
    const e = await busy.consume("C:\\r", "run-1").catch((x: unknown) => x);
    expect(isDomainError(e) && [e.code, e.retryable, e.details?.["outcome"], e.details?.["reason"], e.details?.["waited_ms"]]).toEqual(["CUSTODIAN_BUSY", true, "not_delivered", "busy", 1234]);
  });

  it("is fail-closed off Windows without a helper", async () => {
    if (process.platform === "win32") return;
    expect(await failure(new PipeCustodianTransport().send("implementer", "ping", {}, "r"))).toMatchObject({ type: "UNAVAILABLE", outcome: "not_delivered" });
  });

  it("the grant store maps transport failures to engine errors with the outcome (retryable only when nothing was delivered)", async () => {
    const lost = new CustodianGrants({ send: async () => { throw new CustodianUnavailable("broke", "unknown"); } });
    const e1 = await lost.consume("C:\\r", "run-1").catch((e: unknown) => e);
    expect(isDomainError(e1) && e1.code).toBe("CUSTODIAN_UNAVAILABLE");
    expect(isDomainError(e1) && e1.retryable).toBe(false);
    expect(isDomainError(e1) && e1.details?.["outcome"]).toBe("unknown");
    const off = new CustodianGrants({ send: async () => { throw new CustodianUnavailable("no pipe", "not_delivered"); } });
    const e2 = await off.consume("C:\\r", "run-1").catch((e: unknown) => e);
    expect(isDomainError(e2) && e2.retryable).toBe(true);
    const fake = new CustodianGrants({ send: async () => { throw new CustodianNotTrusted("impostor", "not_delivered", { owner: ME }); } });
    const e3 = await fake.consume("C:\\r", "run-1").catch((e: unknown) => e);
    expect(isDomainError(e3) && e3.code).toBe("SERVER_NOT_TRUSTED");
    expect(isDomainError(e3) && e3.retryable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Windows: real named pipes on this host
// ---------------------------------------------------------------------------

const win = process.platform === "win32";
const servers: Server[] = [];
const children: ChildProcess[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
  for (const c of children.splice(0)) c.kill();
});

function pipeName(): string {
  return `cp-test-${randomBytes(6).toString("hex")}`;
}

/** A Node pipe server (owned by this user) that records what it received and answers with `answer`. */
async function nodeServer(name: string, answer: ((s: Socket) => void) | null): Promise<{ received: Buffer[] }> {
  const received: Buffer[] = [];
  const srv = createServer((s) => {
    s.on("data", (d) => {
      received.push(d);
      if (answer && d.includes(10)) answer(s);
    });
    s.on("error", () => undefined);
  });
  servers.push(srv);
  await new Promise<void>((res) => srv.listen(`\\\\.\\pipe\\${name}`, () => res()));
  return { received };
}

const SYSTEM_FULL = "$sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.IO.Pipes.PipeAccessRights]::FullControl, 'Allow'))";
const ME_READWRITE = "$sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($me, [System.IO.Pipes.PipeAccessRights]::ReadWrite, 'Allow'))";
/** The custodian's pipe security shape (Ipc/PipeServer.cs): SYSTEM full control, one identity ReadWrite. */
const CUSTODIAN_SHAPE = [SYSTEM_FULL, ME_READWRITE].join("\n");

type Act = { respond: string } | "close" | "silent";

/**
 * A Windows PowerShell pipe server with an explicit access list (so its security can match the
 * custodian's), serving `acts.length` sequential connections: each records the request line it read
 * (GOT <base64>) and then answers, closes or stays silent. Resolves once it is listening.
 */
async function psServer(name: string, rules: string, acts: Act[] = []): Promise<{ child: ChildProcess; got: () => string[] }> {
  const actScript = (a: Act): string =>
    a === "close" ? "" : a === "silent" ? "Start-Sleep -Seconds 6" :
      `$b = [Convert]::FromBase64String('${Buffer.from(a.respond + "\n", "utf8").toString("base64")}'); $s.Write($b, 0, $b.Length); $s.Flush(); $s.WaitForPipeDrain()`;
  const serve = acts.map((a, i) => [
    `$s = [System.IO.Pipes.NamedPipeServerStream]::new('${name}', [System.IO.Pipes.PipeDirection]::InOut, -1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 0, 0, $sec)`,
    i === 0 ? "[Console]::Out.WriteLine('LISTENING'); [Console]::Out.Flush()" : "",
    "$t = $s.WaitForConnectionAsync(); [void]$t.Wait(20000)",
    "$r = [System.IO.StreamReader]::new($s, [System.Text.UTF8Encoding]::new($false))",
    "$lt = $r.ReadLineAsync(); [void]$lt.Wait(10000)",
    "[Console]::Out.WriteLine('GOT ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$lt.Result))); [Console]::Out.Flush()",
    actScript(a),
    "$s.Dispose()",
  ].join("\n"));
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User",
    "$sec = [System.IO.Pipes.PipeSecurity]::new()",
    rules,
    ...(acts.length ? serve : [
      `$s = [System.IO.Pipes.NamedPipeServerStream]::new('${name}', [System.IO.Pipes.PipeDirection]::InOut, -1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 0, 0, $sec)`,
      "[Console]::Out.WriteLine('LISTENING'); [Console]::Out.Flush()",
      "$t = $s.WaitForConnectionAsync(); [void]$t.Wait(20000); Start-Sleep -Milliseconds 300; $s.Dispose()",
    ]),
  ].join("\n");
  const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  let out = "";
  await new Promise<void>((res, rej) => {
    child.stdout!.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.includes("LISTENING")) res();
    });
    child.on("exit", (c) => rej(new Error(`pipe server exited ${c}`)));
  });
  return { child, got: () => [...out.matchAll(/^GOT (\S*)\r?$/gm)].map((m) => Buffer.from(m[1]!, "base64").toString("utf8")) };
}

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));

const ADMINISTRATORS = "S-1-5-32-544";

describe.skipIf(!win)("pipe-transport against real named pipes (Windows)", () => {
  let mySid = "";
  /** The owner of the objects this process creates: its user SID, or Administrators when the token is elevated. */
  let myOwner = "";
  beforeAll(() => {
    const ids = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$i = [System.Security.Principal.WindowsIdentity]::GetCurrent(); $i.User.Value; $i.Owner.Value"], { encoding: "utf8", windowsHide: true }).trim().split(/\s+/);
    mySid = ids[0]!.trim();
    myOwner = ids[1]!.trim();
    expect(mySid).toMatch(/^S-1-5-21-/);
    expect([mySid, ADMINISTRATORS]).toContain(myOwner);
  });

  it("no custodian running: fail-closed, nothing delivered", async () => {
    const t = new PipeCustodianTransport({ pipeNames: { implementer: pipeName() }, connectMs: 500 });
    const t0 = Date.now();
    expect(await failure(t.send("implementer", "ping", {}, "r"))).toMatchObject({ type: "UNAVAILABLE", outcome: "not_delivered" });
    // Phase 6 §7 a: an absent pipe is not waited for as a busy one would be (the default busy wait is 30 s).
    expect(Date.now() - t0).toBeLessThan(15_000);
  });

  it("Phase 6 §7 a: a present but busy custodian is waited for — the queued call is answered once the first is served", async () => {
    const name = pipeName();
    // One instance at a time, like the custodian: the first connection is held 4 s, then the next instance answers.
    const srv = await psServer(name, CUSTODIAN_SHAPE, ["silent", { respond: '{"ok":true,"data":{"queued":true}}' }]);
    const first = new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner, responseMs: 1000 }).send("implementer", "ping", {}, "first").catch(() => null);
    await settle(800);
    setCustodianClientDeadline(Date.now() + 25_000);
    try {
      const queued = await new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner, connectMs: 1000 }).send("implementer", "ping", {}, "queued");
      expect(queued).toEqual({ ok: true, data: { queued: true } });
    } finally {
      setCustodianClientDeadline(null);
    }
    await first;
    expect(srv.got().length).toBe(2);
  }, 60_000);

  it("Phase 6 §7 a: a custodian that stays busy past the call's budget is CUSTODIAN_BUSY with nothing delivered, never CUSTODIAN_UNAVAILABLE", async () => {
    const name = pipeName();
    const srv = await psServer(name, CUSTODIAN_SHAPE, ["silent"]);
    const first = new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner, responseMs: 1000 }).send("implementer", "ping", {}, "first").catch(() => null);
    await settle(800);
    setCustodianClientDeadline(Date.now() + CLIENT_START_MS + RESPONSE_FLOOR_MS + 2500);
    try {
      const f = await failure(new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner, connectMs: 1000 }).send("implementer", "ping", {}, "queued"));
      expect(f).toMatchObject({ type: "BUSY", outcome: "not_delivered" });
    } finally {
      setCustodianClientDeadline(null);
    }
    await first;
    expect(srv.got()).toEqual([expect.stringContaining('"requestId":"first"')]);
  }, 60_000);

  it("a server squatting the name (owned by this user, not the custodian) is refused BEFORE a byte is sent", async () => {
    const name = pipeName();
    const srv = await nodeServer(name, (s) => s.end('{"ok":true,"data":{}}\n'));
    const t = new PipeCustodianTransport({ pipeNames: { implementer: name } }); // expects the custodian's service SID
    const f = await failure(t.send("implementer", "consume_loop", { repositoryRoot: "C:\\x" }, "r"));
    expect(f).toMatchObject({ type: "NOT_TRUSTED", outcome: "not_delivered" });
    expect(f.message).toContain(`owned by ${myOwner}`);
    await new Promise((r) => setTimeout(r, 200));
    expect(Buffer.concat(srv.received).length).toBe(0);
  });

  it("the default named-pipe security (Administrators full control) is refused even with the right owner: Administrators could add instances", async (ctx) => {
    // With an elevated token the test's own owner IS Administrators, so "the right owner" and "a foreign Administrators
    // entry" cannot both hold; the elevated case is the next test (the production expectation refuses such a pipe).
    if (myOwner === ADMINISTRATORS) ctx.skip();
    const name = pipeName();
    const srv = await nodeServer(name, (s) => s.end('{"ok":true,"data":{}}\n'));
    const f = await failure(new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner }).send("implementer", "ping", {}, "r"));
    expect(f).toMatchObject({ type: "NOT_TRUSTED", outcome: "not_delivered" });
    expect(f.message).toContain("S-1-5-32-544");
    await settle(200);
    expect(Buffer.concat(srv.received).length).toBe(0);
  });

  it("an elevated process's pipe (owned by BUILTIN\\Administrators) is refused by the production expectation before a byte is sent", async (ctx) => {
    if (myOwner !== ADMINISTRATORS) ctx.skip(); // a standard token cannot create an Administrators-owned object
    const name = pipeName();
    const srv = await nodeServer(name, (s) => s.end('{"ok":true,"data":{}}\n'));
    const f = await failure(new PipeCustodianTransport({ pipeNames: { implementer: name } }).send("implementer", "consume_loop", { repositoryRoot: "C:\\x" }, "r"));
    expect(f).toMatchObject({ type: "NOT_TRUSTED", outcome: "not_delivered" });
    expect(f.message).toContain(`owned by ${ADMINISTRATORS}`);
    await settle(200);
    expect(Buffer.concat(srv.received).length).toBe(0);
  });

  it("a verified endpoint (the custodian's security shape) receives exactly one protocol line and its response is accepted", async () => {
    const name = pipeName();
    const srv = await psServer(name, CUSTODIAN_SHAPE, [{ respond: '{"ok":true,"data":{"pong":true,"caller":"implementer"}}' }]);
    const res = await new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner }).send("implementer", "ping", {}, "req-1");
    expect(res).toEqual({ ok: true, data: { pong: true, caller: "implementer" } });
    await settle(300);
    expect(srv.got()).toEqual(['{"v":1,"requestId":"req-1","op":"ping","args":{}}']);
  });

  it("every exchange is a new connection that repeats the verification", async () => {
    const name = pipeName();
    const srv = await psServer(name, CUSTODIAN_SHAPE, [{ respond: '{"ok":true,"data":{"n":1}}' }, { respond: '{"ok":true,"data":{"n":2}}' }]);
    const good = new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner });
    expect(await good.send("implementer", "ping", {}, "a")).toEqual({ ok: true, data: { n: 1 } });
    expect(await good.send("implementer", "ping", {}, "b")).toEqual({ ok: true, data: { n: 2 } });
    await settle(300);
    expect(srv.got().map((l) => JSON.parse(l).requestId)).toEqual(["a", "b"]);
  });

  it("a malformed answer, a close without an answer and silence are fail-closed with outcome unknown (the request was sent)", async () => {
    const malformed = pipeName();
    await psServer(malformed, CUSTODIAN_SHAPE, [{ respond: "this is not json" }]);
    const closed = pipeName();
    await psServer(closed, CUSTODIAN_SHAPE, ["close"]);
    const silent = pipeName();
    await psServer(silent, CUSTODIAN_SHAPE, ["silent"]);
    const t = (name: string) => new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner, responseMs: 1500 });
    expect(await failure(t(malformed).send("implementer", "ping", {}, "r"))).toMatchObject({ type: "UNAVAILABLE", outcome: "unknown" });
    expect(await failure(t(closed).send("implementer", "ping", {}, "r"))).toMatchObject({ type: "UNAVAILABLE", outcome: "unknown" });
    expect(await failure(t(silent).send("implementer", "ping", {}, "r"))).toMatchObject({ type: "UNAVAILABLE", outcome: "unknown" });
  });

  it("a pipe whose access list lets another principal create instances is refused, even with the right owner", async () => {
    const name = pipeName();
    await psServer(name, [CUSTODIAN_SHAPE, "$sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), [System.IO.Pipes.PipeAccessRights]::CreateNewInstance -bor [System.IO.Pipes.PipeAccessRights]::ReadWrite, 'Allow'))"].join("\n"));
    const f = await failure(new PipeCustodianTransport({ pipeNames: { implementer: name }, expectedOwnerSid: myOwner }).send("implementer", "ping", {}, "r"));
    expect(f).toMatchObject({ type: "NOT_TRUSTED", outcome: "not_delivered" });
    expect(f.message).toContain("S-1-1-0");
  });

  it("OS evidence: while a pipe is held, a DACL granting this user ReadWrite (the custodian's shape) refuses this user a new instance; FullControl would allow it", async () => {
    const attempt = (name: string): string =>
      execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `try { $s = [System.IO.Pipes.NamedPipeServerStream]::new('${name}', [System.IO.Pipes.PipeDirection]::InOut, -1); $s.Dispose(); 'CREATED' } catch { 'REFUSED: ' + $_.Exception.InnerException.GetType().Name + ' ' + $_.Exception.InnerException.Message }`], { encoding: "utf8", windowsHide: true }).trim();
    const held = pipeName();
    await psServer(held, [SYSTEM_FULL, ME_READWRITE].join("\n"));
    expect(attempt(held)).toMatch(/^REFUSED: UnauthorizedAccessException/);
    const control = pipeName();
    await psServer(control, [SYSTEM_FULL, "$sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($me, [System.IO.Pipes.PipeAccessRights]::FullControl, 'Allow'))"].join("\n"));
    expect(attempt(control)).toBe("CREATED");
  });
});

// ---------------------------------------------------------------------------
// Windows + a built custodian: the transport against the custodian's REAL pipe server
// ---------------------------------------------------------------------------

const custodianExe = ["Debug", "Release"]
  .map((c) => join(fileURLToPath(new URL(".", import.meta.url)), "..", "custodian", "CodeParley.Custodian", "bin", c, "net10.0-windows", "CodeParley.Custodian.exe"))
  .find((p) => existsSync(p)) ?? null;
const ownerWrapper = fileURLToPath(new URL("../scripts/ci/run-with-user-owner.ps1", import.meta.url));
const elevatedToken = () =>
  execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value"], { encoding: "utf8", windowsHide: true }).trim() === ADMINISTRATORS;

describe.skipIf(!win || custodianExe === null)("the transport against the custodian's real pipe server (self-test-serve, in-process as this user)", () => {
  let server: ChildProcess | null = null;
  let owner = "";
  let scratch = "";

  beforeAll(async () => {
    if (existsSync(String.raw`\\.\pipe\CodeParley.Custodian.v1.implementer`)) throw new Error("a custodian is serving on this host: this test needs its pipe names free");
    scratch = mkdtempSync(join(tmpdir(), "cp-e2e-"));
    const serve = ["self-test-serve", "--seconds", "120"];
    // self-test-serve reports its user as the owner of its pipes. On an elevated token (a CI runner) they would be owned by
    // Administrators, which the transport rightly refuses (tested above), so it runs with the default owner set to its user.
    server = elevatedToken()
      ? spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ownerWrapper, "-Exe", custodianExe!, "-Verb", ...serve], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] })
      : spawn(custodianExe!, serve, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    owner = await new Promise<string>((res, rej) => {
      let out = "";
      server!.stdout!.on("data", (d: Buffer) => {
        out += d.toString();
        const m = /SERVING owner=(\S+)/.exec(out);
        if (m) res(m[1]!);
      });
      server!.on("exit", (c) => rej(new Error(`self-test-serve exited ${c}: ${out}`)));
    });
  });
  afterAll(() => {
    // The whole tree: under the wrapper the server is a child of the process spawned here, and it would keep the pipe names.
    if (server?.pid) { try { execFileSync("taskkill.exe", ["/pid", String(server.pid), "/t", "/f"], { stdio: "ignore", windowsHide: true }); } catch { /* it has exited */ } }
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  });

  it("authenticates the server's pipes (owner + access list) and exchanges with the real core", async () => {
    const t = new PipeCustodianTransport({ expectedOwnerSid: owner });
    expect(await t.send("implementer", "ping", {}, uuidv7())).toMatchObject({ ok: true, data: { pong: true, caller: "implementer", protocol: CUSTODIAN_PROTOCOL_VERSION } });
    const listing = await new CustodianGrants(t).list();
    expect(listing.ceilings).toEqual({ loops: 8, minutes: 180 });
    expect(listing.grants).toEqual([]);
  });

  it("consume: the custodian establishes the repository identity itself (a link is refused, an unknown directory's run is not open)", async () => {
    const t = new PipeCustodianTransport({ expectedOwnerSid: owner });
    const repo = join(scratch, "Repo");
    execFileSync("cmd.exe", ["/c", "mkdir", repo], { windowsHide: true });
    // P3.4C-3: a loop is minted only for a run the custodian holds open (run_transition open, which itself needs a grant).
    const e1 = await new CustodianGrants(t).consume(repo, "run-e2e").catch((e: unknown) => e);
    expect(isDomainError(e1) && e1.code).toBe("RUN_NOT_OPEN");
    const link = join(scratch, "link");
    execFileSync("cmd.exe", ["/c", "mklink", "/J", link, repo], { windowsHide: true });
    const e2 = await new CustodianGrants(t).consume(link, "run-e2e").catch((e: unknown) => e);
    expect(isDomainError(e2) && e2.code).toBe("INVALID_ARGUMENT");
    expect(isDomainError(e2) && e2.message).toMatch(/repository identity refused: 'link': it is a symbolic link, junction or mount point/);
  });

  it("operator actions from this non-elevated process are refused by the custodian's OS caller classification; forged authority fields are rejected", async (ctx) => {
    // Needs a standard token: an elevated one is the operator's (the custodian's self-test-ipc covers that classification).
    if (elevatedToken()) ctx.skip();
    const t = new PipeCustodianTransport({ expectedOwnerSid: owner });
    const e = await new CustodianOperator(t).mint(scratch, 1, 10, uuidv7()).catch((x: unknown) => x);
    expect(isDomainError(e) && e.code).toBe("CALLER_NOT_AUTHORIZED");
    const forged = await t.send("implementer", "consume_loop", { repositoryRoot: scratch, role: "operator", assurance: "local_operator" }, uuidv7());
    expect(forged).toMatchObject({ ok: false, code: "MALFORMED_REQUEST" });
  });

  it("the same server is not the custodian SERVICE: the production transport refuses it before sending", async () => {
    const f = await failure(new PipeCustodianTransport().send("implementer", "ping", {}, uuidv7()));
    expect(f).toMatchObject({ type: "NOT_TRUSTED", outcome: "not_delivered" });
    expect(f.message).toContain(`owned by ${owner}`);
  });
});
