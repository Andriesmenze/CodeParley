// Phase 4 Increment 1 — the safe, bounded delegated-fixer launch primitive (contract §5; D-20).
//
// Composes the three Increment-1 pieces and nothing more:
//   1. the fail-closed gate (fix-isolation.ts): load the stored cp_fix self-test and refuse the launch
//      unless it is complete and matches the exact Codex binary (SHA-256), version, backend and fixer
//      profile structure about to be launched — CODEX_ISOLATION_UNAVAILABLE otherwise, before any process;
//   2. the safe argv (fix-profile.ts `fixExecArgv`): `codex exec` under the writable `cp_fix` profile, no
//      forbidden flag or sandbox mode;
//   3. the existing bounded launcher (adapter.ts `runCodexReview`): wall/idle timeouts and reliable
//      process-tree termination (the same controls the reviewer uses), reused unchanged.
//
// This is a primitive, deliberately NOT wired to any production entry point (no MCP surface, no apply, no
// delegation record): the engine wiring that would call it is a later, separately-authorized increment.
// It performs no patch application and makes no custodian call.

import { readFile } from "node:fs/promises";
import { sha256OfBytes } from "../../common/hash.js";
import { buildChildEnv } from "../../process/env.js";
import { runCodexReview, DEFAULT_RUN_LIMITS, type ReviewRunLimits, type ReviewRunResult } from "./adapter.js";
import { fixExecArgv, type FixProfileInput } from "./fix-profile.js";
import { decideFixIsolation, fixIsolationUnavailableError } from "./fix-isolation.js";
import { loadFixSelfTest } from "./fix-selftest.js";
import type { CodexProbe } from "./probe.js";
import type { SandboxBackend } from "./argv.js";

export interface FixLaunchRequest {
  probe: CodexProbe;
  backend: SandboxBackend;
  /** The disposable workspace's writable `tree` (the fixer's working directory). */
  workspaceTree: string;
  /** The disposable workspace's writable `scratch`. */
  workspaceScratch: string;
  /** Where the fixer's final message is written (cross-checked against the event stream). */
  lastMessagePath: string;
  /** The fixer instructions (read from stdin). */
  prompt: string;
  /** Directory holding the stored cp_fix self-test records. */
  selftestDir: string;
  /** Paths the write grant must not overlap (the primary worktree, the Codex home, …). */
  protectedPaths: readonly string[];
  model?: string | null;
  reasoningEffort?: string | null;
  limits?: Partial<ReviewRunLimits>;
  env?: Record<string, string>;
  signal?: AbortSignal;
  /** Test seam: launch the gated, built argv through this instead of the real process. */
  run?: typeof runCodexReview;
}

/**
 * Launch a delegated fixer under `cp_fix`, gated fail-closed on the stored self-test. Throws
 * CODEX_ISOLATION_UNAVAILABLE (nothing launched) when the self-test is absent, incomplete, mismatched or
 * did not establish confinement. On success returns the bounded run's result (no patch is applied here).
 */
export async function launchFixer(req: FixLaunchRequest): Promise<ReviewRunResult> {
  const profile: FixProfileInput = {
    backend: req.backend,
    installDir: req.probe.installDir,
    writableDirs: [req.workspaceTree, req.workspaceScratch],
    protectedPaths: req.protectedPaths,
  };
  const bytes = await readFile(req.probe.launcher.exe).catch(() => null);
  const codexSha256 = bytes ? sha256OfBytes(bytes) : null;
  if (!codexSha256) throw fixIsolationUnavailableError([`the Codex executable ${req.probe.launcher.exe} cannot be read to bind the self-test`]);

  const record = await loadFixSelfTest(req.selftestDir, req.probe.version, codexSha256, profile);
  const decision = decideFixIsolation({ codexVersion: req.probe.version, codexSha256, backend: req.backend, profile, record });
  if (!decision.ok) throw fixIsolationUnavailableError(decision.reasons);

  // Only now, with confinement established for exactly this binary and profile, build the argv and launch.
  const argv = fixExecArgv({ ...profile, cwd: req.workspaceTree, lastMessagePath: req.lastMessagePath, model: req.model ?? null, reasoningEffort: req.reasoningEffort ?? null });
  const env = req.env ?? buildChildEnv({ includeCodexAuth: true }).env;
  const limits: ReviewRunLimits = { wallMs: 10 * 60_000, idleMs: 2 * 60_000, ...DEFAULT_RUN_LIMITS, ...req.limits };
  const run = req.run ?? runCodexReview;
  return run({
    launcher: req.probe.launcher,
    argv,
    exportRoot: req.workspaceTree,
    prompt: req.prompt,
    env,
    lastMessagePath: req.lastMessagePath,
    limits,
    ...(req.signal ? { signal: req.signal } : {}),
  });
}
