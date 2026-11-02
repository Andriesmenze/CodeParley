// The real Windows custodian transport (P3.4C-0): one request per connection over the custodian's named
// pipes (custodian/…/Ipc/PipeServer.cs), with the connected endpoint AUTHENTICATED before anything is sent.
//
// Node cannot read the security descriptor of a pipe it connected (net.connect exposes no handle, and
// there is no supported FFI), so each exchange runs a short-lived Windows PowerShell 5.1 helper — the
// engine's existing way of asking Windows for facts (process/win-powershell.ts: no cmdlets, .NET only,
// never resolved through PATH). On the SAME handle it then uses for the exchange, the helper:
//   1. connects at the IDENTIFICATION impersonation level (the custodian can identify the caller, never
//      act as it);
//   2. reads the connected pipe's security descriptor from the kernel object (GetSecurityInfo through
//      PipeStream.GetAccessControl) and refuses — before writing a byte — unless the OWNER is the expected
//      custodian identity (the NT SERVICE\CodeParleyCustodian SID, computed in TypeScript: protocol.ts)
//      and no ACE lets any principal other than the custodian or SYSTEM create a pipe instance or change
//      the pipe's security. A standard user cannot create an object owned by another SID, and all
//      instances of one pipe name share one security descriptor, so the owner check alone would accept an
//      extra instance someone else was allowed to create: the ACE check closes that;
//   3. writes the request line and reads one response line, each with a deadline.
// The pipe name, a PID, a claimed identity or the custodian's own answer authenticate nothing. Every
// exchange is a new process and a new connection, so a reconnection repeats the verification. Any
// failure is fail-closed and says whether the request can have reached the custodian (DeliveryOutcome).
// The evidence the helper read is re-checked here (pipeSecurityProblem) before a response is accepted.

import { runProcess } from "../process/spawn.js";
import { powerShellEnv, powerShellExe } from "../process/win-powershell.js";
import { CUSTODIAN_MEASURING_OPS, CUSTODIAN_PIPES, CUSTODIAN_PROTOCOL_VERSION, custodianServiceSid, type CustodianOp, type CustodianResponse, type CustodianSurface } from "./protocol.js";
import { CustodianBusy, CustodianNotTrusted, CustodianUnavailable, DEFAULT_BUSY_WAIT_MS, custodianClientDeadline, type CustodianTransport } from "./transport.js";

const SYSTEM_SID = "S-1-5-18";
/** FILE_CREATE_PIPE_INSTANCE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE. */
export const FOREIGN_FORBIDDEN_RIGHTS = 0x4 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024; // Ipc/CustodianConstants.cs MaxResponseBytes

/** The helper: connect, verify the connected pipe's security, exchange one line. Windows PowerShell 5.1,
 * no cmdlets (`::new`, not New-Object), only single quotes (the script is a command-line argument).
 * Input (stdin, one value per line): pipe name, expected owner SID, base64 request line, connect ms (how long an
 * ABSENT pipe is waited for), response ms, max response bytes, busy ms (how long a pipe that exists but has no free
 * instance is waited for), budget ms (the whole exchange from the helper's start; 0: none). Output: `@@verified` once
 * the endpoint passed verification (nothing is written before it), then
 * `@@result <stage> <ok> <b64 owner> <b64 aces> <b64 error> <b64 response>`.
 * Exit 0 done; 2 failure at <stage>; 3 the endpoint is not the custodian; 4 timeout/incomplete; 5 too large;
 * 6 no such pipe (absent); 7 the pipe stayed busy (Phase 6, contract §7 a). */
export const PIPE_CLIENT_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$enc = [System.Text.UTF8Encoding]::new($false)",
  "function B64([string]$s) { return [Convert]::ToBase64String($enc.GetBytes([string]$s)) }",
  "function Emit([string]$stage, [string]$ok, [string]$owner, [string]$aces, [string]$err, [string]$resp) { [Console]::Out.WriteLine('@@result ' + $stage + ' ' + $ok + ' ' + (B64 $owner) + ' ' + (B64 $aces) + ' ' + (B64 $err) + ' ' + (B64 $resp)); [Console]::Out.Flush() }",
  "$pipe = [Console]::In.ReadLine()",
  "$expected = [Console]::In.ReadLine()",
  "$request = [Convert]::FromBase64String([Console]::In.ReadLine())",
  "$connectMs = [int][Console]::In.ReadLine()",
  "$responseMs = [int][Console]::In.ReadLine()",
  "$maxBytes = [int][Console]::In.ReadLine()",
  "$busyMs = [int][Console]::In.ReadLine()",
  "$budgetMs = [int][Console]::In.ReadLine()",
  "$start = [DateTime]::UtcNow",
  "$stage = 'connect'; $owner = ''; $aces = ''; $client = $null",
  // An absent pipe (no instance at all) and a busy one (instances, none free) are told apart: the name is listed while
  // any instance exists. A busy pipe is waited for up to busy ms, an absent one up to connect ms.
  "function PipeExists { return [System.IO.Directory]::GetFiles('\\\\.\\pipe\\') -contains ('\\\\.\\pipe\\' + $pipe) }",
  "try {",
  "  while ($null -eq $client) {",
  "    $now = [DateTime]::UtcNow",
  "    if (-not (PipeExists)) {",
  "      if (($now - $start).TotalMilliseconds -ge $connectMs) { Emit 'connect' '0' '' '' ('absent: no pipe ' + $pipe + ' exists') ''; exit 6 }",
  "      [System.Threading.Thread]::Sleep(100); continue",
  "    }",
  "    $left = $busyMs - [int]($now - $start).TotalMilliseconds",
  "    if ($left -le 0) { Emit 'connect' '0' '' '' ('busy: the pipe exists but no instance became free within ' + $busyMs + ' ms') ''; exit 7 }",
  "    $c = [System.IO.Pipes.NamedPipeClientStream]::new('.', $pipe, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous, [System.Security.Principal.TokenImpersonationLevel]::Identification)",
  "    try { $c.Connect([Math]::Min($left, 1000)); $client = $c }",
  // Busy: .NET Framework reports a wait that ran out on a busy pipe as an IOException with ERROR_SEM_TIMEOUT (0x79), or
  // ERROR_PIPE_BUSY (0xE7), not as a TimeoutException; anything else (access denied, ...) is no busy pipe.
  "    catch { $c.Dispose(); $x = $_.Exception; if ($x.InnerException) { $x = $x.InnerException }; if (-not ($x -is [System.TimeoutException] -or ($x -is [System.IO.IOException] -and (($x.HResult -band 0xFFFF) -eq 0x79 -or ($x.HResult -band 0xFFFF) -eq 0xE7)))) { throw } }",
  "  }",
  "  $stage = 'security'",
  "  $sd = $client.GetAccessControl()",
  "  $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
  "  $list = [System.Collections.Generic.List[string]]::new()",
  "  $foreign = ''",
  "  foreach ($r in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {",
  "    $sid = $r.IdentityReference.Value",
  "    $allow = $r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow",
  "    $mask = [int64]$r.PipeAccessRights.value__",
  "    if ($mask -lt 0) { $mask += 4294967296 }",
  "    $list.Add($sid + ':' + [int]$allow + ':' + $mask)",
  `    if ($allow -and $sid -ne $expected -and $sid -ne '${SYSTEM_SID}' -and (($mask -band ${FOREIGN_FORBIDDEN_RIGHTS}) -ne 0) -and $foreign -eq '') { $foreign = $sid }`,
  "  }",
  "  $aces = [string]::Join(';', $list)",
  "  if ($owner -ne $expected) { Emit 'security' '0' $owner $aces ('the pipe is owned by ' + $owner + ', not by the custodian identity ' + $expected) ''; exit 3 }",
  "  if ($foreign -ne '') { Emit 'security' '0' $owner $aces ('the pipe security lets ' + $foreign + ' (not the custodian or SYSTEM) create pipe instances or change its security') ''; exit 3 }",
  "  [Console]::Out.WriteLine('@@verified'); [Console]::Out.Flush()",
  "  $stage = 'send'",
  "  $w = $client.WriteAsync($request, 0, $request.Length)",
  "  if (-not $w.Wait($responseMs)) { Emit 'send' '0' $owner $aces 'timed out sending the request' ''; exit 4 }",
  "  $stage = 'receive'",
  "  $buffer = [byte[]]::new(65536)",
  "  $received = [System.IO.MemoryStream]::new()",
  "  $deadline = [DateTime]::UtcNow.AddMilliseconds($responseMs)",
  "  if ($budgetMs -gt 0 -and $start.AddMilliseconds($budgetMs) -lt $deadline) { $deadline = $start.AddMilliseconds($budgetMs) }",
  "  $complete = $false",
  "  while (-not $complete) {",
  "    $left = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds",
  "    if ($left -le 0) { Emit 'receive' '0' $owner $aces 'timed out waiting for the response' ''; exit 4 }",
  "    $t = $client.ReadAsync($buffer, 0, $buffer.Length)",
  "    if (-not $t.Wait($left)) { Emit 'receive' '0' $owner $aces 'timed out waiting for the response' ''; exit 4 }",
  "    $n = $t.Result",
  "    if ($n -le 0) { break }",
  "    $received.Write($buffer, 0, $n)",
  "    if ([Array]::IndexOf($buffer, [byte]10, 0, $n) -ge 0) { $complete = $true }",
  "    if ($received.Length -gt $maxBytes) { Emit 'receive' '0' $owner $aces 'the response is too large' ''; exit 5 }",
  "  }",
  "  $text = $enc.GetString($received.ToArray())",
  "  $nl = $text.IndexOf([char]10)",
  "  if ($nl -lt 0) { Emit 'receive' '0' $owner $aces 'the connection closed before a complete response' $text; exit 4 }",
  "  Emit 'done' '1' $owner $aces '' $text.Substring(0, $nl)",
  "  exit 0",
  "} catch {",
  "  Emit $stage '0' $owner $aces ($_.Exception.GetType().FullName + ': ' + $_.Exception.Message) ''",
  "  exit 2",
  "} finally {",
  "  if ($null -ne $client) { $client.Dispose() }",
  "}",
].join("\n");

export type PipeStage = "connect" | "security" | "send" | "receive" | "done";

export interface PipeAce {
  sid: string;
  allow: boolean;
  rights: number;
}

export interface PipeExchange {
  /** The endpoint passed verification (the helper may have started sending after this). */
  verified: boolean;
  result: { stage: PipeStage; ok: boolean; owner: string; aces: PipeAce[]; error: string; response: string } | null;
}

const b64 = (s: string): string => Buffer.from(s, "base64").toString("utf8");

/** Parse the helper's output (pure). */
export function parsePipeOutput(stdout: string): PipeExchange {
  let verified = false;
  let result: PipeExchange["result"] = null;
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "@@verified") verified = true;
    if (!line.startsWith("@@result ")) continue;
    const [, stage, ok, owner, aces, error, response] = line.split(" ");
    if (!stage || !["connect", "security", "send", "receive", "done"].includes(stage) || (ok !== "0" && ok !== "1")) continue;
    result = { stage: stage as PipeStage, ok: ok === "1", owner: b64(owner ?? ""), aces: parseAces(b64(aces ?? "")), error: b64(error ?? ""), response: b64(response ?? "") };
  }
  return { verified, result };
}

function parseAces(s: string): PipeAce[] {
  if (!s) return [];
  return s.split(";").map((a) => {
    const [sid, allow, rights] = a.split(":");
    return { sid: sid ?? "", allow: allow === "1", rights: Number(rights) };
  });
}

/** Why a pipe with this owner and DACL is NOT the custodian, or null when it is acceptable (pure). */
export function pipeSecurityProblem(owner: string, aces: readonly PipeAce[], expectedOwner: string): string | null {
  if (!owner) return "the pipe's owner could not be read";
  if (owner.toUpperCase() !== expectedOwner.toUpperCase()) return `the pipe is owned by ${owner}, not by the custodian identity ${expectedOwner}`;
  for (const a of aces) {
    if (!Number.isFinite(a.rights)) return "the pipe's access list could not be read";
    const privileged = a.sid.toUpperCase() === expectedOwner.toUpperCase() || a.sid === SYSTEM_SID;
    if (a.allow && !privileged && (a.rights & FOREIGN_FORBIDDEN_RIGHTS) !== 0) {
      return `the pipe's access list lets ${a.sid} create pipe instances or change the pipe's security (rights 0x${(a.rights >>> 0).toString(16)})`;
    }
  }
  return null;
}

/** Validate one response line as the custodian's envelope (Ipc/Protocol.cs Response); null when it is not. */
export function parseCustodianResponse(line: string): CustodianResponse | null {
  let v: unknown;
  try {
    v = JSON.parse(line);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).some((k) => !["ok", "data", "code", "error"].includes(k))) return null;
  if (typeof o.ok !== "boolean") return null;
  if (o.ok) {
    if (o.data !== undefined && (o.data === null || typeof o.data !== "object" || Array.isArray(o.data))) return null;
    return { ok: true, data: (o.data as Record<string, unknown> | undefined) ?? {} };
  }
  if (typeof o.code !== "string" || !/^[A-Z_]{1,64}$/.test(o.code) || typeof o.error !== "string") return null;
  return { ok: false, code: o.code, error: o.error };
}

/** One run of the helper (the process primitive's result, narrowed). */
export interface HelperRun {
  status: number | null;
  stdout: string;
  spawnError: string | null;
  timedOut: boolean;
}

export interface PipeTransportOptions {
  /** TEST ONLY: the identity the pipe owner must be (default: the custodian service SID). */
  expectedOwnerSid?: string;
  /** TEST ONLY: other pipe names (default: Ipc/CustodianConstants.cs). */
  pipeNames?: Partial<Record<CustodianSurface, string>>;
  connectMs?: number;
  responseMs?: number;
  /** TEST ONLY: run the helper differently (default: Windows PowerShell 5.1 with the helper script). */
  run?: (stdin: string, wallMs: number) => Promise<HelperRun>;
}

/** P3.4C-5: the response deadline of a measuring operation (CUSTODIAN_MEASURING_OPS). */
export const MEASURING_RESPONSE_MS = 180_000;

/** Phase 6 (§7 a): the time a client process takes to start (Windows PowerShell), and the least an answer is left once
 * connected, both taken from a hook's budget. */
export const CLIENT_START_MS = 1500;
export const RESPONSE_FLOOR_MS = 5000;

/** How long an absent and a busy custodian are waited for, and the whole exchange's budget (0: none), from now. Under a
 * hook deadline the waits end in time for an answer before it; without one, a busy custodian is waited for
 * {@link DEFAULT_BUSY_WAIT_MS}. Pure (exported for the unit tests). */
export function clientWaits(connectMs: number, deadline: number | null, now: number, startMs = CLIENT_START_MS): { absentMs: number; busyMs: number; budgetMs: number } {
  if (deadline === null) return { absentMs: connectMs, busyMs: Math.max(connectMs, DEFAULT_BUSY_WAIT_MS), budgetMs: 0 };
  const room = Math.max(500, deadline - now - startMs);
  const absentMs = Math.min(connectMs, room);
  return { absentMs, busyMs: Math.max(absentMs, room - RESPONSE_FLOOR_MS), budgetMs: room };
}

const runHelper = (stdin: string, wallMs: number): Promise<HelperRun> =>
  runProcess(powerShellExe(), ["-NoProfile", "-NonInteractive", "-Command", PIPE_CLIENT_SCRIPT], { env: powerShellEnv(), stdin, wallMs, maxStdoutBytes: 4 * MAX_RESPONSE_BYTES });

export class PipeCustodianTransport implements CustodianTransport {
  private readonly expected: string;
  private readonly pipes: Record<CustodianSurface, string>;
  private readonly connectMs: number;
  private readonly responseMs: number;
  private readonly run: (stdin: string, wallMs: number) => Promise<HelperRun>;

  constructor(opts: PipeTransportOptions = {}) {
    this.expected = opts.expectedOwnerSid ?? custodianServiceSid();
    this.pipes = { ...CUSTODIAN_PIPES, ...(opts.pipeNames ?? {}) };
    this.connectMs = opts.connectMs ?? 3000;
    this.responseMs = opts.responseMs ?? 20_000;
    this.run = opts.run ?? runHelper;
  }

  async send(surface: CustodianSurface, op: CustodianOp, args: Record<string, unknown>, requestId: string): Promise<CustodianResponse> {
    const pipe = this.pipes[surface];
    if (!this.runInjected && process.platform !== "win32") throw new CustodianUnavailable("the custodian's named pipes exist only on Windows", "not_delivered");
    const line = JSON.stringify({ v: CUSTODIAN_PROTOCOL_VERSION, requestId, op, args }) + "\n";
    const responseMs = CUSTODIAN_MEASURING_OPS.has(op) ? Math.max(this.responseMs, MEASURING_RESPONSE_MS) : this.responseMs;
    const w = clientWaits(this.connectMs, custodianClientDeadline(), Date.now());
    const stdin = [pipe, this.expected, Buffer.from(line, "utf8").toString("base64"), String(w.absentMs), String(responseMs), String(MAX_RESPONSE_BYTES), String(w.busyMs), String(w.budgetMs)].join("\n") + "\n";
    // PowerShell's own start-up is not part of the protocol deadlines: allow it generously (the budget bounds the helper).
    const r = await this.run(stdin, (w.budgetMs > 0 ? w.budgetMs : w.busyMs + 2 * responseMs) + 30_000);
    if (r.spawnError) throw new CustodianUnavailable(`Windows PowerShell could not be started for the custodian client (${r.spawnError})`, "not_delivered");
    const x = parsePipeOutput(r.stdout);
    if (!x.result) {
      // The helper ended without a report (killed, crashed or blocked by policy). Before verification
      // nothing was written; after it, the request may have been.
      const why = r.timedOut ? "it timed out" : `exit ${r.status}`;
      throw new CustodianUnavailable(`the custodian client ended without a result (${why})`, x.verified ? "unknown" : "not_delivered");
    }
    const res = x.result;
    if (res.stage === "connect" || res.stage === "security") throw this.notConnected(r.status, res, pipe, w.busyMs);
    // Defense in depth: the helper verified before it sent; re-check its evidence before accepting anything.
    const problem = pipeSecurityProblem(res.owner, res.aces, this.expected);
    if (problem) throw new CustodianNotTrusted(`the custodian client's verification evidence does not hold (${problem}); whether the request was applied is unknown`, "unknown", { pipe, owner: res.owner, aces: res.aces });
    if (res.stage !== "done" || !res.ok) {
      throw new CustodianUnavailable(`the exchange with the custodian broke after the request was sent (${res.error}); whether it was applied is unknown`, "unknown");
    }
    const parsed = parseCustodianResponse(res.response);
    if (!parsed) throw new CustodianUnavailable("the custodian's response is not a valid protocol response; whether the request was applied is unknown", "unknown");
    return parsed;
  }

  /** Why nothing was sent: the pipe stayed busy (exit 7), the endpoint is not the custodian (exit 3), or it could not be
   * reached (absent, exit 6, or any other connect failure). */
  private notConnected(status: number | null, res: { error: string; owner: string; aces: PipeAce[] }, pipe: string, busyMs: number): Error {
    if (status === 7) return new CustodianBusy(`the custodian on \\\\.\\pipe\\${pipe} is busy serving another request (${res.error}); nothing was sent`, "not_delivered", busyMs);
    if (status === 3) {
      return new CustodianNotTrusted(`the endpoint on \\\\.\\pipe\\${pipe} is not the CodeParley custodian (${res.error}); nothing was sent`, "not_delivered", { pipe, owner: res.owner, expected_owner: this.expected, aces: res.aces });
    }
    return new CustodianUnavailable(`the custodian could not be reached on \\\\.\\pipe\\${pipe} (${res.error})`, "not_delivered");
  }

  private get runInjected(): boolean {
    return this.run !== runHelper;
  }
}
