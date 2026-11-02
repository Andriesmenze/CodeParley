// The Codex review adapter (plan §12.1, §12.3, §12.7; G7; M1.3-11).
//
// Launch: the native codex.exe (probe.ts), argv from argv.ts, cwd = the immutable export,
// an explicit environment, the prompt on stdin (then closed, X1). Not detached, so the
// child sits in libuv's kill-on-close job: if this server dies, codex.exe dies with it.
//
// Bounded: wall-clock and idle timeouts (Codex never times out by itself, X4), a per-line
// cap on the JSONL stream, a capped stored event stream and stderr, a capped final message.
//
// Termination. Every timeout and cancellation kills the WHOLE tree (`taskkill /T /F`): MXC
// ends sandboxed descendants on a tree kill of codex.exe but NOT when codex.exe alone is
// terminated (M1.3-11). After codex.exe exits for any reason, its surviving descendants are
// looked up through the process table (parent-PID chain with creation-time checks), killed
// and re-checked. A cancellation is reported `terminated` only when that re-check confirms
// nothing of the tree is alive; otherwise it stays `cancellation_requested` with the
// survivors named (MR-J semantics). Nothing is ever killed by a PID that may have exited.

import { readFile, stat } from "node:fs/promises";
import { runProcess, type TreeKillReason } from "../../process/spawn.js";
import { startFactsOf } from "../../process/start-facts.js";
import { ticksOfIdentity } from "../../process/linux-proc.js";
import { confirmTreeTermination, NO_KILL, snapshotProcessTable, sweepDescendants, type DescendantSweep, type ProcEntry, type SweepDeps, type TerminationCheck } from "../../process/proc-table.js";
import type { CancellationRecord, CodexAudit } from "../../schemas/review.js";
import { CodexEventStream, MAX_EVENT_LINE_CHARS, classifyOutcome, type EventLimits, type ProcessOutcome } from "./events.js";
import type { CodexLauncher } from "./probe.js";

export interface ReviewRunLimits {
  wallMs: number;
  idleMs: number;
  maxStderrBytes: number;
  maxLastMessageBytes: number;
  maxLineChars: number;
  events?: Partial<EventLimits>;
  /** Bounded wait for stdio after codex.exe exits (a descendant may hold the pipes). */
  exitGraceMs?: number;
}

export const DEFAULT_RUN_LIMITS: Omit<ReviewRunLimits, "wallMs" | "idleMs"> = {
  maxStderrBytes: 5 * 1024 * 1024,
  maxLastMessageBytes: 2 * 1024 * 1024,
  maxLineChars: MAX_EVENT_LINE_CHARS,
};

export interface ReviewRunRequest {
  launcher: CodexLauncher;
  argv: readonly string[];
  exportRoot: string;
  prompt: string;
  env: Record<string, string>;
  lastMessagePath: string;
  limits: ReviewRunLimits;
  /** Explicit operation cancellation (never a call cancellation, D-27). */
  signal?: AbortSignal;
  /** Called once Codex is spawned (the engine records PID, start and — Linux — exact start identity for recovery). */
  onSpawn?: (child: { pid: number; startedAtMs: number; startIdentity?: string }) => void;
  onProgress?: (msg: string) => void;
  /** Descendant sweep after exit; null disables it (unit tests without a process table). */
  sweep?: SweepDeps | null;
}

export interface ReviewRunResult {
  outcome: ProcessOutcome;
  audit: CodexAudit;
  eventsJsonl: string;
  stderr: Buffer;
  stderrBytes: number;
  lastMessage: string | null;
  lastMessageBytes: number | null;
  lastMessageTooLarge: boolean;
  /**
   * P3.4C-3 C5: the `-o` file disagrees with the final message in Codex's own event stream — not byte-identical, or a
   * file with no final message in the stream. Any same-user process can write that file after Codex exits; the stream
   * comes from the child's stdout pipe. The review's output is then invalid (never accepted).
   */
  lastMessageMismatch: boolean;
  pid: number | null;
  startedAtMs: number;
  durationMs: number;
  exitStatus: number | null;
  stdioHeldAfterExit: boolean;
  descendants: DescendantSweep | null;
  /** The process layer's record of a tree kill (any reason), or null when none happened. */
  treeKill: { reason: TreeKillReason; killIssued: boolean; killOk: boolean | null } | null;
  /** Termination evidence for the Codex tree after it ended (null: no process table). */
  termination: TerminationCheck | null;
  cancellation: CancellationRecord | null;
}

export async function runCodexReview(req: ReviewRunRequest): Promise<ReviewRunResult> {
  const stream = new CodexEventStream(req.limits.events ?? {});
  const internal = new AbortController();
  const snapshot = req.sweep === null ? null : (req.sweep?.snapshot ?? snapshotProcessTable);
  let requestedAt: string | null = null;
  const onAbort = () => {
    requestedAt = new Date().toISOString();
    req.onProgress?.("cancellation requested: killing the Codex process tree");
    internal.abort();
  };
  if (req.signal?.aborted) onAbort();
  else req.signal?.addEventListener("abort", onAbort, { once: true });

  const startedAtMs = Date.now();
  // Linux: Codex's exact start ticks, so a newer process holding its PID is never taken for it.
  let codexTicks: number | null = null;
  const rootOf = (pid: number) => ({ pid, startedAtMs, ...(codexTicks !== null ? { startTicks: codexTicks } : {}) });
  let lastProgress = 0;
  const run = await runProcess(req.launcher.file, [...req.launcher.prefixArgs, ...req.argv], {
    cwd: req.exportRoot,
    env: req.env,
    stdin: req.prompt,
    wallMs: req.limits.wallMs,
    idleMs: req.limits.idleMs,
    maxStdoutBytes: 0, // the sanitized stream is kept by CodexEventStream
    maxStderrBytes: req.limits.maxStderrBytes,
    stderrMode: "buffer",
    tailBytes: 4096,
    maxLineChars: req.limits.maxLineChars,
    onStdoutLine: (line) => {
      stream.push(line);
      if (req.onProgress && Date.now() - lastProgress > 5000) {
        lastProgress = Date.now();
        const a = stream.audit();
        req.onProgress(`codex: ${a.events_total} events, ${a.commands_run} commands`);
      }
    },
    onStdoutLineOverflow: (n) => stream.overflow(n),
    signal: internal.signal,
    // Whatever the reason for a tree kill (cancellation, wall or idle timeout), the process
    // layer records the tree BEFORE killing it, so "everything seen is gone" can be checked.
    ...(snapshot ? { beforeTreeKill: () => snapshot() } : {}),
    onSpawn: (pid) => {
      const facts = startFactsOf(pid, startedAtMs);
      codexTicks = ticksOfIdentity(facts.startIdentity);
      req.onSpawn?.({ pid, startedAtMs: facts.startedAtMs, ...(facts.startIdentity ? { startIdentity: facts.startIdentity } : {}) });
    },
    ...(req.limits.exitGraceMs !== undefined ? { exitGraceMs: req.limits.exitGraceMs } : {}),
    // Linux: the reaper keeps Codex's session until the descendant sweep below is done.
    holdSession: true,
  });
  req.signal?.removeEventListener("abort", onAbort);

  // Survivors of the tree after codex.exe exited (any reason). Never by a bare PID: the
  // sweep walks parent links from the recorded child with creation-time checks.
  let descendants: DescendantSweep | null = null;
  if (run.pid != null && req.sweep !== null) {
    descendants = await sweepDescendants(rootOf(run.pid), req.sweep ?? {}, run.stdioHeldAfterExit ? run.stdioEndpoints : []).catch(() => ({ scanned: false, survivors: [], terminated: null }));
  }

  // P3.4C-3 C5: the final message is the completed turn's last agent message in Codex's own event stream (read from
  // the child's stdout pipe), under the size limit. The -o file is only a cross-check: when it exists it must be
  // byte-identical; a file without a final message in the stream is a mismatch too.
  let lastMessage: string | null = null;
  let lastMessageBytes: number | null = null;
  let lastMessageTooLarge = false;
  let lastMessageMismatch = false;
  const streamed = stream.lastAgentMessage;
  if (streamed !== null) {
    lastMessageBytes = Buffer.byteLength(streamed, "utf8");
    if (lastMessageBytes > req.limits.maxLastMessageBytes) lastMessageTooLarge = true;
    else lastMessage = streamed;
  }
  const st = await stat(req.lastMessagePath).catch(() => null);
  if (st && st.isFile()) {
    // An oversized file is output over the cap whatever the stream holds (its event line may have been dropped).
    if (st.size > req.limits.maxLastMessageBytes) lastMessageTooLarge = true;
    else if (streamed === null || st.size !== lastMessageBytes) lastMessageMismatch = true;
    else {
      const bytes = await readFile(req.lastMessagePath).catch(() => null);
      lastMessageMismatch = bytes === null || !bytes.equals(Buffer.from(streamed, "utf8"));
    }
  }

  const audit = stream.audit();
  const cancelled = requestedAt !== null || run.cancelled;
  const outcome = classifyOutcome({
    exitStatus: run.status,
    spawnError: run.spawnError,
    timedOut: run.timedOut,
    idleTimedOut: run.idleTimedOut,
    cancelled,
    stderrTail: run.stderrTail?.toString("utf8") ?? "",
    audit,
    lastMessage: lastMessageTooLarge ? "x" : lastMessage,
  });

  // Termination evidence on EVERY exit, decided from the process layer's own record of
  // whether (and why) it killed the tree — never from which listener fired — so a
  // cancellation during execution, a timeout, and a cancellation that arrives after this
  // function returned are all judged on the same evidence (F3).
  await run.treeKillSettled;
  let termination: TerminationCheck | null = null;
  if (run.pid == null) {
    termination = { established: true, survivors: [], unattributable: [], reason: "no Codex process was created" };
  } else if (snapshot) {
    const pre = run.treeKill ? ((run.treeKill.evidence as ProcEntry[] | null) ?? null) : NO_KILL;
    const post = await snapshot().catch(() => null);
    termination = confirmTreeTermination(rootOf(run.pid), pre, post, descendants);
  }
  // The sweep and the termination assessment are done: hand the session back (see checks/runner.ts).
  run.releaseSession();
  const cancellation = cancelled ? cancellationRecord(requestedAt ?? new Date().toISOString(), termination) : null;

  return {
    outcome,
    audit,
    eventsJsonl: stream.storedJsonl(),
    stderr: run.stderrBuffer ?? Buffer.alloc(0),
    stderrBytes: run.stderrBytes,
    lastMessage,
    lastMessageBytes,
    lastMessageTooLarge,
    lastMessageMismatch,
    pid: run.pid,
    startedAtMs,
    durationMs: run.durationMs,
    exitStatus: run.status,
    stdioHeldAfterExit: run.stdioHeldAfterExit,
    descendants,
    treeKill: run.treeKill ? { reason: run.treeKill.reason, killIssued: run.treeKill.killIssued, killOk: run.treeKill.killOk } : null,
    termination,
    cancellation,
  };
}

/**
 * The only constructor of a cancellation record (F3): "terminated" iff the termination
 * evidence establishes it; missing evidence (null) is "cancellation_requested".
 */
export function cancellationRecord(requestedAt: string, termination: TerminationCheck | null): CancellationRecord {
  return {
    requested_at: requestedAt,
    outcome: termination?.established === true ? "terminated" : "cancellation_requested",
    survivors: termination?.survivors ?? [],
    unattributable: termination?.unattributable ?? [],
    detail: termination?.reason ?? "no termination evidence is available (the process table was not read)",
  };
}
