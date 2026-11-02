// Resolve a directory's git top level for scope resolution (plan §8.2 step 3).
//
// This is the ONLY git invocation in M1.1 and is deliberately minimal: it is NOT the
// hardened capture query suite (that is M1.2, which disables filters/hooks/fsmonitor/lazy
// fetch). It is used only to map a launch/subdirectory to its repository root so the
// configured-root authority can be enforced. It spawns git through the process layer.

import { DomainError } from "../common/errors.js";
import { runProcess } from "../process/spawn.js";
import { buildChildEnv } from "../process/env.js";
import { canonicalizePath } from "./paths.js";

export interface GitTopLevelOptions {
  gitExe: string;
  env?: Record<string, string>;
}

/** Return the canonical git top level of `dir`, or throw NOT_A_GIT_WORKTREE / GIT_NOT_FOUND. */
export async function resolveGitTopLevel(dir: string, opts: GitTopLevelOptions): Promise<string> {
  const env = opts.env ?? buildChildEnv().env;
  const r = await runProcess(
    opts.gitExe,
    ["-C", dir, "rev-parse", "--show-toplevel"],
    { env, wallMs: 15_000 },
  );
  if (r.spawnError) {
    throw new DomainError("GIT_NOT_FOUND", `could not run git: ${r.spawnError}`, { details: { gitExe: opts.gitExe } });
  }
  if (r.status !== 0) {
    const tail = r.stderr.trim().split(/\r?\n/).slice(-1)[0] ?? "";
    throw new DomainError("NOT_A_GIT_WORKTREE", `not a git work tree: ${dir}${tail ? ` (${tail})` : ""}`, {
      details: { dir },
    });
  }
  const top = r.stdout.trim();
  if (!top) throw new DomainError("NOT_A_GIT_WORKTREE", `git returned no top level for ${dir}`, { details: { dir } });
  return canonicalizePath(top);
}
