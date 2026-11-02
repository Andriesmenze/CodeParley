// The single process-spawn primitive. Every child process in the system is launched here
// (plan §5.3 rule 4, §28 "no generic shell"). Never uses a shell; argv is passed verbatim.
// Provides bounded wall-clock and idle timeouts, output caps, a line callback, cancellation
// via AbortSignal, and tree-kill on timeout/cancel (plan §12.3, §14.3, G7).
//
// Ownership (plan §1.13): on Windows a child is not detached, so it sits in libuv's
// kill-on-close job and dies with the server. On Linux every child leads a NEW session and
// process group (`detached`, i.e. setsid): the session id tags the child's whole tree for
// termination (kill-tree.ts) and for termination evidence (tree.ts), and the child is
// registered with the session reaper (session-reaper.ts), which ends the session if the server
// dies before it has waited for the child.

import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { buildChildEnv } from "./env.js";
import { killTree, type RootIdentity } from "./kill-tree.js";
import { fdTargetSync, isPipeEndpoint, readStatSync } from "./linux-proc.js";
import { ownSession, releaseSession } from "./session-reaper.js";

const OWN_SESSIONS = process.platform === "linux";

export interface RunOptions {
  cwd?: string;
  /** Explicit environment. If omitted, the minimal platform base env is used (no secrets). */
  env?: Record<string, string>;
  /** Written to the child's stdin, which is then closed (an open stdin blocks `codex exec`, X1). */
  stdin?: string | Buffer | null;
  /**
   * "utf8" (default): stdout is decoded once at the end, so multi-byte characters split
   * across chunks stay intact. "buffer": stdout is returned raw in `stdoutBuffer` and
   * `stdout` is empty — for binary protocols such as `git cat-file --batch` (M1.2).
   */
  stdoutMode?: "utf8" | "buffer";
  /** Wall-clock budget. On expiry the tree is killed. Default 120s. */
  wallMs?: number;
  /** Idle budget: no stdout/stderr for this long kills the tree. 0 disables. Default 0. */
  idleMs?: number;
  maxStdoutBytes?: number;
  maxStderrBytes?: number;
  /** Called for each complete stdout line (newline-delimited, CR stripped). */
  onStdoutLine?: (line: string) => void;
  /**
   * Longest line (in characters) delivered to `onStdoutLine`. A longer line is discarded up
   * to its newline and reported once through `onStdoutLineOverflow`, so a child cannot grow
   * the line buffer without bound. Default: unlimited (callers that parse untrusted output
   * set it).
   */
  maxLineChars?: number;
  onStdoutLineOverflow?: (discardedChars: number) => void;
  /** Cancels the run; the tree is killed and `cancelled` is set. */
  signal?: AbortSignal;
  /**
   * Pass `args` to CreateProcess without libuv's quoting. Only for the `cmd.exe /d /s /c`
   * invocation built by `win-command.ts`, which escapes every argument itself (N2). Ignored
   * outside Windows.
   */
  windowsVerbatimArguments?: boolean;
  /** Called once with the child's PID right after a successful spawn (recovery records it). */
  onSpawn?: (pid: number) => void;
  /**
   * Linux: keep the child's session registered with the session reaper after the run, until the
   * caller calls `RunResult.releaseSession` — for callers that sweep the tree's descendants
   * afterwards, so that a server dying before the sweep still has the session ended. Default:
   * released when the run (and any tree kill) has finished.
   */
  holdSession?: boolean;
  /**
   * Called before ANY tree kill this run performs (cancellation, wall timeout, idle
   * timeout), after the reason is recorded and before the kill starts. Its result is kept in
   * `treeKill.evidence` (e.g. a process-table snapshot of the tree before it was killed).
   */
  beforeTreeKill?: () => Promise<unknown>;
  /** Keep a rolling tail of the last N bytes of each stream (independent of the caps). */
  tailBytes?: number;
  /** "buffer": stderr is also returned raw in `stderrBuffer` (check logs, M1.3). */
  stderrMode?: "utf8" | "buffer";
  /**
   * After the direct child exits, wait at most this long for its stdout/stderr to close.
   * A descendant that inherited the pipes keeps them open after the child is gone; without
   * this bound the run would hang until the wall clock (and then kill nothing, because the
   * child is already dead). On expiry the streams are destroyed and `stdioHeldAfterExit`
   * is set. Default 5000ms.
   */
  exitGraceMs?: number;
}

export interface RunResult {
  file: string;
  argv: string[];
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  /** Raw stdout (capped at maxStdoutBytes) when stdoutMode is "buffer"; otherwise undefined. */
  stdoutBuffer?: Buffer;
  stderr: string;
  /** Raw stderr (capped at maxStderrBytes) when stderrMode is "buffer". */
  stderrBuffer?: Buffer;
  /** Last `tailBytes` of each stream, when requested. */
  stdoutTail?: Buffer;
  stderrTail?: Buffer;
  stdoutBytes: number;
  stderrBytes: number;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  timedOut: boolean;
  idleTimedOut: boolean;
  cancelled: boolean;
  spawnError: string | null;
  pid: number | null;
  durationMs: number;
  /** The child exited but its stdio stayed open past `exitGraceMs` (a descendant holds it). */
  stdioHeldAfterExit: boolean;
  /**
   * Linux: the child's stdout/stderr endpoints as named in /proc ("socket:[N]"), read right
   * after the spawn. A process found holding one later inherited it from the child's tree
   * (`sweepDescendants`). Empty when unknown and on Windows.
   */
  stdioEndpoints: string[];
  /**
   * Set whenever this run decided to kill the child's tree, whatever the reason; null when
   * it never did. Callers decide termination from this record, never from their own
   * listeners (F3).
   */
  treeKill: TreeKillRecord | null;
  /** Resolves once the tree kill (if any) has recorded its evidence and outcome. */
  treeKillSettled: Promise<void>;
  /** Linux with `holdSession`: hand the child's session back (the reaper no longer ends it). A no-op otherwise. */
  releaseSession: () => void;
}

export type TreeKillReason = "cancelled" | "wall_timeout" | "idle_timeout";

export interface TreeKillRecord {
  reason: TreeKillReason;
  requestedAtMs: number;
  /** Result of `beforeTreeKill` (null when absent or failed). */
  evidence: unknown;
  /** The tree kill was issued (false: the child had already exited). */
  killIssued: boolean;
  /** The kill reported the tree gone (Windows: taskkill succeeded); null while unknown. */
  killOk: boolean | null;
}

const DEFAULTS = {
  wallMs: 120_000,
  idleMs: 0,
  maxStdoutBytes: 50 * 1024 * 1024,
  maxStderrBytes: 5 * 1024 * 1024,
  exitGraceMs: 5000,
};

/** Spawn `file args`, wait with bounds, and return a typed result. Never throws for a
 * non-zero exit; only rejects on programmer error. */
export function runProcess(file: string, args: readonly string[], opts: RunOptions = {}): Promise<RunResult> {
  const wallMs = opts.wallMs ?? DEFAULTS.wallMs;
  const idleMs = opts.idleMs ?? DEFAULTS.idleMs;
  const maxStdoutBytes = finiteOr(opts.maxStdoutBytes, DEFAULTS.maxStdoutBytes);
  const maxStderrBytes = finiteOr(opts.maxStderrBytes, DEFAULTS.maxStderrBytes);
  const env = opts.env ?? buildChildEnv().env;
  const argv = [...args];
  const tailBytes = finiteOr(opts.tailBytes, 0);
  const exitGraceMs = finiteOr(opts.exitGraceMs, DEFAULTS.exitGraceMs);

  return new Promise<RunResult>((resolve) => {
    const started = Date.now();

    if (opts.signal?.aborted) {
      resolve(baseResult(file, argv, started, { cancelled: true }));
      return;
    }

    let child;
    try {
      child = spawn(file, argv, {
        cwd: opts.cwd,
        env,
        shell: false,
        windowsHide: true,
        windowsVerbatimArguments: opts.windowsVerbatimArguments === true,
        // Linux: a new session and process group (see the module comment). Windows: stay in
        // the kill-on-close job.
        detached: OWN_SESSIONS,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      resolve(baseResult(file, argv, started, { spawnError: errMsg(err) }));
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    const lineDecoder = new StringDecoder("utf8");
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let idleTimedOut = false;
    let cancelled = false;
    let settled = false;
    let lineBuf = "";
    const maxLineChars = finiteOr(opts.maxLineChars, Number.MAX_SAFE_INTEGER);
    /** > 0 while discarding the rest of an over-long line (characters dropped so far). */
    let discarding = 0;
    const reportOverflow = (n: number) => {
      try {
        opts.onStdoutLineOverflow?.(n);
      } catch {
        /* ignore */
      }
    };
    let stdioHeldAfterExit = false;
    let exitInfo: { code: number | null; sig: NodeJS.Signals | null } | null = null;
    let exitGrace: NodeJS.Timeout | null = null;
    const stdoutTail = new TailBuffer(tailBytes);
    const stderrTail = new TailBuffer(tailBytes);

    // After the direct child has exited its PID may be reused, so nothing may be killed by
    // that PID any more: every kill path checks `exited`.
    let exited = false;
    let treeKill: TreeKillRecord | null = null;
    let treeKillSettled: Promise<void> = Promise.resolve();
    // Every kill path goes through here and is recorded with its reason (F3).
    const killChildTree = (reason: TreeKillReason) => {
      if (exited || child.pid == null || treeKill) return;
      const rec: TreeKillRecord = { reason, requestedAtMs: Date.now(), evidence: null, killIssued: false, killOk: null };
      treeKill = rec;
      const pid = child.pid;
      treeKillSettled = (async () => {
        if (opts.beforeTreeKill) rec.evidence = await opts.beforeTreeKill().catch(() => null);
        if (exited) return;
        rec.killIssued = true;
        rec.killOk = await killTree(pid, 10_000, identity);
      })();
    };
    const wall = setTimeout(() => {
      timedOut = true;
      killChildTree("wall_timeout");
    }, wallMs);

    let idle: NodeJS.Timeout | null = null;
    const bumpIdle = () => {
      if (idleMs <= 0) return;
      if (idle) clearTimeout(idle);
      idle = setTimeout(() => {
        idleTimedOut = true;
        killChildTree("idle_timeout");
      }, idleMs);
    };
    bumpIdle();

    const onAbort = () => {
      cancelled = true;
      killChildTree("cancelled");
    };
    if (opts.signal) opts.signal.addEventListener("abort", onAbort, { once: true });

    let reaped = false;
    let stdioEndpoints: string[] = [];
    // The child's identity for every kill of its tree: exact start ticks on Linux (read right
    // after the spawn, before the child can have been waited for), else the spawn time.
    let identity: RootIdentity = { startedAtMs: started };
    if (OWN_SESSIONS && child.pid != null) {
      const st = readStatSync(child.pid);
      if (st) identity = { startTicks: st.startTicks };
      if (st) reaped = ownSession(child.pid, st.startTicks);
      const pid = child.pid;
      stdioEndpoints = [1, 2].map((fd) => fdTargetSync(pid, fd)).filter((t): t is string => t !== null && isPipeEndpoint(t));
    }

    if (child.pid != null && opts.onSpawn) {
      try {
        opts.onSpawn(child.pid);
      } catch {
        /* a callback error must not break the run */
      }
    }

    child.stdout.on("data", (b: Buffer) => {
      bumpIdle();
      stdoutTail.push(b);
      const room = maxStdoutBytes - stdoutBytes;
      if (room > 0) stdoutChunks.push(room >= b.length ? b : b.subarray(0, room));
      stdoutBytes += b.length;
      if (opts.onStdoutLine) {
        lineBuf += lineDecoder.write(b);
        if (discarding > 0) {
          const nl = lineBuf.indexOf("\n");
          if (nl < 0) {
            discarding += lineBuf.length;
            lineBuf = "";
          } else {
            discarding += nl;
            reportOverflow(discarding);
            discarding = 0;
            lineBuf = lineBuf.slice(nl + 1);
          }
        }
        let nl: number;
        while (discarding === 0 && (nl = lineBuf.indexOf("\n")) >= 0) {
          const line = lineBuf.slice(0, nl).replace(/\r$/, "");
          lineBuf = lineBuf.slice(nl + 1);
          if (line.length > maxLineChars) {
            reportOverflow(line.length);
            continue;
          }
          if (line.length) {
            try {
              opts.onStdoutLine(line);
            } catch {
              /* a callback error must not break capture */
            }
          }
        }
        if (discarding === 0 && lineBuf.length > maxLineChars) {
          // An over-long line without its newline yet: drop it up to the newline.
          discarding = lineBuf.length;
          lineBuf = "";
        }
      }
    });
    child.stderr.on("data", (b: Buffer) => {
      bumpIdle();
      stderrTail.push(b);
      const room = maxStderrBytes - stderrBytes;
      if (room > 0) stderrChunks.push(room >= b.length ? b : b.subarray(0, room));
      stderrBytes += b.length;
    });

    const finish = (status: number | null, sig: NodeJS.Signals | null, spawnError: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(wall);
      if (idle) clearTimeout(idle);
      if (exitGrace) clearTimeout(exitGrace);
      if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
      let releaseHeld: () => void = () => undefined;
      if (reaped && child.pid != null) {
        const pid = child.pid;
        // After any tree kill this run started has finished with the session (or, when the
        // caller holds it, after the caller's own sweep).
        const release = () => void treeKillSettled.finally(() => releaseSession(pid));
        if (opts.holdSession) {
          let done = false;
          releaseHeld = () => {
            if (!done) release();
            done = true;
          };
        } else release();
      }
      if (opts.onStdoutLine) lineBuf += lineDecoder.end();
      if (opts.onStdoutLine && discarding > 0) {
        reportOverflow(discarding + lineBuf.length);
        lineBuf = "";
      } else if (opts.onStdoutLine && lineBuf.length > maxLineChars) {
        reportOverflow(lineBuf.length);
        lineBuf = "";
      }
      if (opts.onStdoutLine && lineBuf.trim().length) {
        try {
          opts.onStdoutLine(lineBuf.replace(/\r$/, ""));
        } catch {
          /* ignore */
        }
      }
      const stdoutAll = Buffer.concat(stdoutChunks);
      const stderrAll = Buffer.concat(stderrChunks);
      const binary = opts.stdoutMode === "buffer";
      resolve({
        file,
        argv,
        status,
        signal: sig,
        stdout: binary ? "" : stdoutAll.toString("utf8"),
        ...(binary ? { stdoutBuffer: stdoutAll } : {}),
        stderr: stderrAll.toString("utf8"),
        ...(opts.stderrMode === "buffer" ? { stderrBuffer: stderrAll } : {}),
        ...(tailBytes > 0 ? { stdoutTail: stdoutTail.bytes(), stderrTail: stderrTail.bytes() } : {}),
        stdoutBytes,
        stderrBytes,
        stdoutTruncated: stdoutBytes > maxStdoutBytes,
        stderrTruncated: stderrBytes > maxStderrBytes,
        timedOut,
        idleTimedOut,
        cancelled,
        spawnError,
        pid: child.pid ?? null,
        durationMs: Date.now() - started,
        stdioHeldAfterExit,
        stdioEndpoints,
        treeKill,
        treeKillSettled,
        releaseSession: releaseHeld,
      });
    };

    child.on("error", (e) => finish(null, null, errMsg(e)));
    child.on("exit", (code, sig) => {
      exited = true;
      exitInfo = { code, sig };
      clearTimeout(wall);
      if (idle) clearTimeout(idle);
      // The child is gone; its stdio normally closes right away. If a descendant inherited
      // the pipes they stay open: stop waiting after the grace period (bounded execution).
      exitGrace = setTimeout(() => {
        stdioHeldAfterExit = true;
        child.stdout.destroy();
        child.stderr.destroy();
        finish(exitInfo?.code ?? null, exitInfo?.sig ?? null, null);
      }, exitGraceMs);
    });
    child.on("close", (code, sig) => finish(code ?? exitInfo?.code ?? null, sig ?? exitInfo?.sig ?? null, null));

    if (opts.stdin != null) {
      child.stdin.on("error", () => {
        /* ignore EPIPE */
      });
      child.stdin.write(opts.stdin);
    }
    child.stdin.end();
  });
}

function baseResult(
  file: string,
  argv: string[],
  started: number,
  over: Partial<RunResult>,
): RunResult {
  return {
    file,
    argv,
    status: null,
    signal: null,
    stdout: "",
    stderr: "",
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    idleTimedOut: false,
    cancelled: false,
    spawnError: null,
    pid: null,
    durationMs: Date.now() - started,
    stdioHeldAfterExit: false,
    stdioEndpoints: [],
    treeKill: null,
    treeKillSettled: Promise.resolve(),
    releaseSession: () => undefined,
    ...over,
  };
}

/** A fixed-size rolling window over the last `cap` bytes written. */
class TailBuffer {
  private chunks: Buffer[] = [];
  private size = 0;
  constructor(private readonly cap: number) {}
  push(b: Buffer): void {
    if (this.cap <= 0) return;
    const piece = b.length > this.cap ? b.subarray(b.length - this.cap) : b;
    this.chunks.push(Buffer.from(piece));
    this.size += piece.length;
    while (this.size - (this.chunks[0]?.length ?? 0) >= this.cap && this.chunks.length > 1) {
      this.size -= this.chunks.shift()!.length;
    }
  }
  bytes(): Buffer {
    const all = Buffer.concat(this.chunks);
    return all.length > this.cap ? all.subarray(all.length - this.cap) : all;
  }
}

function finiteOr(v: number | undefined, fallback: number): number {
  return v !== undefined && Number.isFinite(v) && v >= 0 ? v : fallback;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
