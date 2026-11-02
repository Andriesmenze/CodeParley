// Run ONE approved check (plan §14.3). The engine (engine/checks-operation.ts) owns the
// operation, the worktree lock, source identities and persistence; this module only
// prepares the invocation and executes it through the process layer:
//  - argv only, no shell; argv[0] resolved deterministically (process/command.ts): on
//    Windows .cmd/.bat shims run through an explicit, escaped cmd.exe invocation; on Linux
//    the file runs itself (ELF, or a "#!" script) and anything else is refused;
//  - cwd inside the repository, reached without any link/junction component;
//  - explicit environment (no Claude/Codex credentials), stdin closed at once;
//  - wall-clock timeout (default 900 s, hard cap 3600 s) and cancellation kill the tree;
//  - each stream is capped (10 MiB stored) with a rolling 4 KB tail; output beyond the cap
//    is drained and counted, so a flooding check cannot block or exhaust memory;
//  - after the direct child exits, descendants still alive are found and killed
//    (process/proc-table.ts), so nothing a check started outlives the worktree lock.

import { stat } from "node:fs/promises";
import { join } from "node:path";
import { runProcess, type RunResult } from "../process/spawn.js";
import { buildInvocation, displayCommandLine, resolveCommand, type Invocation, type ResolvedCommand } from "../process/command.js";
import { lookupEnv } from "../process/env.js";
import { startFactsOf } from "../process/start-facts.js";
import { ticksOfIdentity } from "../process/linux-proc.js";
import {
  confirmTreeTermination,
  NO_KILL,
  snapshotProcessTable,
  sweepDescendants,
  type DescendantSweep,
  type ProcEntry,
  type SweepDeps,
  type TerminationCheck,
} from "../process/proc-table.js";
import { canonicalizePath, isContainedIn } from "../workspace/paths.js";
import { firstLinkComponent } from "../workspace/links.js";
import type { CheckDefinition, CheckExecutionStatus, FreshnessInputDigest } from "../schemas/checks.js";
import {
  buildCheckEnv,
  computeCheckSpecId,
  computeEnvDigest,
  computeExecutionInputId,
  computeFreshnessDigest,
  hashFreshnessInputs,
} from "./identity.js";

export const STREAM_CAP_BYTES = 10 * 1024 * 1024;
export const TAIL_BYTES = 4096;

export interface PreparedCheck {
  name: string;
  def: CheckDefinition;
  definitionDigest: string;
  resolved: ResolvedCommand;
  invocation: Invocation;
  commandLine: string;
  cwdAbs: string;
  env: Record<string, string>;
  envDigest: string;
  envNames: string[];
  passthroughMissing: string[];
  freshness: FreshnessInputDigest[];
  freshnessDigest: string;
  checkSpecId: string;
  executionInputId: string;
}

export type PrepareResult =
  | { ok: true; check: PreparedCheck }
  | {
      ok: false;
      error: string;
      /** Identity parts that could still be computed (for the record). */
      partial: { envDigest: string | null; envNames: string[]; freshness: FreshnessInputDigest[]; freshnessDigest: string | null; resolved: ResolvedCommand | null };
    };

export interface PrepareContext {
  /** Canonical repository root. */
  repoRoot: string;
  /** The server's environment (passthrough values are read from it). */
  sourceEnv: NodeJS.ProcessEnv;
}

/** Resolve everything about a check that does not require running it. Never throws. */
export async function prepareCheck(name: string, def: CheckDefinition, definitionDigest: string, ctx: PrepareContext): Promise<PrepareResult> {
  const ce = buildCheckEnv(def, ctx.sourceEnv);
  const envDigest = computeEnvDigest(ce.env);
  const envNames = Object.keys(ce.env).sort();
  const freshness = await hashFreshnessInputs(ctx.repoRoot, def.freshness_inputs);
  const freshnessDigest = computeFreshnessDigest(freshness);
  const partial = { envDigest, envNames, freshness, freshnessDigest, resolved: null as ResolvedCommand | null };
  if (ce.refused.length > 0) return { ok: false, error: `passthrough refused: ${ce.refused.join(", ")}`, partial };

  const cwd = await resolveCheckCwd(ctx.repoRoot, def.cwd);
  if (!cwd.ok) return { ok: false, error: cwd.reason, partial };

  const r = resolveCommand(def.argv[0]!, { relativeBase: ctx.repoRoot, pathValue: lookupEnv(ce.env, "PATH"), pathext: lookupEnv(ce.env, "PATHEXT") });
  if (!r.ok) return { ok: false, error: r.reason, partial };
  const resolved = r.command;
  if (resolved.how === "relative" && !isContainedIn(resolved.path, ctx.repoRoot)) {
    return { ok: false, error: `relative argv[0] resolves outside the repository: ${resolved.path}`, partial: { ...partial, resolved } };
  }
  let invocation: Invocation;
  try {
    invocation = buildInvocation(resolved, def.argv.slice(1), lookupEnv(ce.env, "SystemRoot") ?? process.env["SystemRoot"]);
  } catch (e) {
    return { ok: false, error: (e as Error).message, partial: { ...partial, resolved } };
  }
  const checkSpecId = computeCheckSpecId({ name, def, definitionDigest, resolved });
  return {
    ok: true,
    check: {
      name,
      def,
      definitionDigest,
      resolved,
      invocation,
      commandLine: displayCommandLine([resolved.path, ...def.argv.slice(1)]),
      cwdAbs: cwd.path,
      env: ce.env,
      envDigest,
      envNames,
      passthroughMissing: ce.missing,
      freshness,
      freshnessDigest,
      checkSpecId,
      executionInputId: computeExecutionInputId({ checkSpecId, envDigest, freshnessDigest }),
    },
  };
}

/** The check's working directory: inside the repository, existing, no link component. */
export async function resolveCheckCwd(repoRoot: string, cwd: string): Promise<{ ok: true; path: string } | { ok: false; reason: string }> {
  const abs = cwd === "." ? repoRoot : join(repoRoot, ...cwd.split("/"));
  const link = await firstLinkComponent(abs, repoRoot, new Map());
  if (link) return { ok: false, reason: `check cwd passes through a link or junction: ${link}` };
  let canon: string;
  try {
    canon = await canonicalizePath(abs);
  } catch (e) {
    return { ok: false, reason: `check cwd is invalid: ${(e as Error).message}` };
  }
  if (!isContainedIn(canon, repoRoot)) return { ok: false, reason: `check cwd is outside the repository: ${canon}` };
  const st = await stat(canon).catch(() => null);
  if (!st || !st.isDirectory()) return { ok: false, reason: `check cwd does not exist: ${cwd}` };
  return { ok: true, path: canon };
}

export interface ExecuteOptions {
  signal?: AbortSignal;
  /** Called with the direct child's PID, start time and (Linux) exact start identity right after spawn. */
  onSpawn?: (child: { pid: number; startedAtMs: number; startIdentity?: string }) => void;
  streamCapBytes?: number;
  tailBytes?: number;
  /** Process-table access for the descendant sweep (tests inject fakes; null disables). */
  sweep?: SweepDeps | null;
  /** TEST ONLY: override the definition's timeout (milliseconds). */
  wallMsOverride?: number;
  exitGraceMs?: number;
}

export interface CheckRunOutcome {
  status: Exclude<CheckExecutionStatus, "skipped">;
  error: string | null;
  exitCode: number | null;
  pid: number | null;
  startedAtMs: number;
  durationMs: number;
  timedOut: boolean;
  cancelled: boolean;
  stdout: Buffer;
  stderr: Buffer;
  stdoutBytes: number;
  stderrBytes: number;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  stdoutTail: Buffer;
  stderrTail: Buffer;
  stdioHeldAfterExit: boolean;
  descendants: DescendantSweep | null;
  /** Why the process layer killed the tree (cancellation, wall or idle timeout); null if it never did. */
  treeKillReason: string | null;
  /**
   * Termination evidence after the child exited, by the same rule as reviews (F3,
   * `confirmTreeTermination`): established only when the process table was read before the
   * kill and after the exit and nothing linked or untraceable survives. Null when the
   * process table is not consulted (sweep disabled): no evidence, never "terminated".
   */
  termination: TerminationCheck | null;
}

export async function executeCheck(c: PreparedCheck, opts: ExecuteOptions = {}): Promise<CheckRunOutcome> {
  const cap = opts.streamCapBytes ?? STREAM_CAP_BYTES;
  const startedAtMs = Date.now();
  let childStart = startedAtMs;
  let childTicks: number | null = null;
  const snapshot = opts.sweep === null ? null : (opts.sweep?.snapshot ?? snapshotProcessTable);
  const r: RunResult = await runProcess(c.invocation.file, c.invocation.args, {
    cwd: c.cwdAbs,
    env: c.env,
    windowsVerbatimArguments: c.invocation.windowsVerbatimArguments,
    wallMs: opts.wallMsOverride ?? c.def.timeout_seconds * 1000,
    idleMs: 0,
    maxStdoutBytes: cap,
    maxStderrBytes: cap,
    stdoutMode: "buffer",
    stderrMode: "buffer",
    tailBytes: opts.tailBytes ?? TAIL_BYTES,
    // Linux: the reaper keeps the check's session until the descendant sweep below is done.
    holdSession: true,
    ...(opts.exitGraceMs !== undefined ? { exitGraceMs: opts.exitGraceMs } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
    // Whatever the reason for a tree kill, record the tree BEFORE killing it, so "everything
    // seen is gone" can be checked afterwards (the review adapter's rule, M1.4-18).
    ...(snapshot ? { beforeTreeKill: () => snapshot() } : {}),
    onSpawn: (pid) => {
      const facts = startFactsOf(pid, Date.now());
      childStart = facts.startedAtMs;
      childTicks = ticksOfIdentity(facts.startIdentity);
      opts.onSpawn?.({ pid, startedAtMs: childStart, ...(facts.startIdentity ? { startIdentity: facts.startIdentity } : {}) });
    },
  });

  let descendants: DescendantSweep | null = null;
  // Started slightly before our timestamp: allow for it in the parent/child time check.
  // Linux: the exact start ticks too, so a newer process holding the PID is never taken for it.
  const root = r.pid != null ? { pid: r.pid, startedAtMs: childStart - 1000, ...(childTicks !== null ? { startTicks: childTicks } : {}) } : null;
  let termination: TerminationCheck | null = null;
  try {
    if (root && opts.sweep !== null) {
      // Linux: whoever still holds the check's output pipes inherited them from its tree.
      descendants = await sweepDescendants(root, opts.sweep ?? {}, r.stdioHeldAfterExit ? r.stdioEndpoints : []).catch(() => ({ scanned: false, survivors: [], terminated: null }));
    }

    // Termination evidence on every exit, from the process layer's own kill record (F3).
    await r.treeKillSettled;
    if (!root) {
      termination = { established: true, survivors: [], unattributable: [], reason: "no check process was created" };
    } else if (snapshot) {
      const pre = r.treeKill ? ((r.treeKill.evidence as ProcEntry[] | null) ?? null) : NO_KILL;
      const post = await snapshot().catch(() => null);
      termination = confirmTreeTermination(root, pre, post, descendants);
    }
  } finally {
    // The sweep and the termination assessment are done: hand the session back. (Possible
    // survivors are reported; the reaper does not keep a session for long, because once no
    // member is left its id may be reused by an unrelated session.)
    r.releaseSession();
  }

  const status: CheckRunOutcome["status"] = r.spawnError
    ? "error"
    : r.cancelled
      ? "cancelled"
      : r.timedOut
        ? "timed_out"
        : r.status === 0
          ? "passed"
          : "failed";
  return {
    status,
    error: r.spawnError,
    exitCode: r.status,
    pid: r.pid,
    startedAtMs,
    durationMs: r.durationMs,
    timedOut: r.timedOut,
    cancelled: r.cancelled,
    stdout: r.stdoutBuffer ?? Buffer.alloc(0),
    stderr: r.stderrBuffer ?? Buffer.alloc(0),
    stdoutBytes: r.stdoutBytes,
    stderrBytes: r.stderrBytes,
    stdoutTruncated: r.stdoutTruncated,
    stderrTruncated: r.stderrTruncated,
    stdoutTail: r.stdoutTail ?? Buffer.alloc(0),
    stderrTail: r.stderrTail ?? Buffer.alloc(0),
    stdioHeldAfterExit: r.stdioHeldAfterExit,
    descendants,
    treeKillReason: r.treeKill?.reason ?? null,
    termination,
  };
}

