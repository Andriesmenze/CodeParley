// The repository's root commit(s), used as the consistency check of trusted project
// configuration (plan §14.1, R-35): approvals are keyed by canonical worktree path, and an
// entry recorded for a different repository at that path must not apply. Runs one
// hardened, allowlisted query (`rev-list --max-parents=0 HEAD`), which reads commit objects
// only. Several roots (merged histories) are sorted and joined with ","; an unborn HEAD
// gives null. In a shallow clone the shallow boundary is reported, so deepening the clone
// changes the value and requires re-approval (fails closed).

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { GitQuery, type ProtectedGitConfig } from "./git-query.js";

export interface RootCommitOptions {
  gitExe: string;
  /** Canonical worktree root. */
  repoRoot: string;
  /** Scratch parent for the empty hooks directory (defaults to the OS temp dir). */
  scratchParent?: string;
  envOverrides?: Record<string, string>;
  /** P3.4C-5 (the custodian's helper): an existing empty hooks directory to use instead of creating one (the helper
   * writes nothing), and its protected git configuration (§A.4). */
  hooksDir?: string;
  protectedConfig?: ProtectedGitConfig;
}

export async function readRootCommit(opts: RootCommitOptions): Promise<string | null> {
  const scratch = opts.hooksDir ?? (await mkdtemp(join(opts.scratchParent ?? tmpdir(), "arl-root-")));
  try {
    const q = new GitQuery({
      gitExe: opts.gitExe,
      cwd: opts.repoRoot,
      emptyHooksDir: scratch,
      ...(opts.envOverrides ? { envOverrides: opts.envOverrides } : {}),
      ...(opts.protectedConfig ? { protectedConfig: opts.protectedConfig } : {}),
    });
    // Only an unborn HEAD (a branch without a commit yet) has no consistency value: HEAD names
    // no object at all. Without peeling, `rev-parse --verify -q HEAD` still resolves a HEAD whose
    // commit is missing or corrupt, so such a repository reaches rev-list and fails loudly
    // instead of passing for "no commits" — which would store an unbound approval or skip the
    // R-35 check (PR #2 review). Every other failure propagates.
    const head = await q.text("rev-parse", ["--verify", "-q", "HEAD"], { okCodes: [0, 1] });
    if (!head.trim()) return null;
    const out = await q.text("rev-list", ["--max-parents=0", "HEAD"]);
    const roots = out
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => /^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(s))
      .sort();
    return roots.length > 0 ? roots.join(",") : null;
  } finally {
    if (!opts.hooksDir) await rm(scratch, { recursive: true, force: true }).catch(() => undefined);
  }
}
