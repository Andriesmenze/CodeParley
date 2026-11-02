// Phase 4 foundation — disposable writable workspaces for a delegated Codex fix (plan §22.3; P3.0
// trust-boundary spike §7 topology, adapted). A workspace is where a delegated fixer is allowed to
// write; the primary worktree never is. This module owns the workspace's LIFECYCLE on disk — creating
// it, telling the launcher which directory to grant write to, and tearing it down without ever
// following a link. The OS confinement of the fixing process is a separate mechanism (the Codex `mxc`
// sandbox, validated in docs/validation/results/P4.0-workspace-isolation.md); scope is still enforced
// on the result (capture/fix-scan.ts), because a workspace-write sandbox cannot enforce per-file scope.
//
// Layout, under the data home so no untracked files land in any repository (store/paths.ts):
//
//   <dataHome>/work/<run-id>/<workspace-id>/
//     tree/      the fixer's writable copy of the files it may change (the ONLY writable grant)
//     scratch/   the fixer's writable scratch + TEMP (writable, never read back as a result)
//     control/   CodeParley-only: the baseline manifest and workspace metadata (fixer never writes it)
//
// The launcher grants write to `tree` and `scratch` only. `control` is a sibling, not under either, so
// the sandbox's write grant never covers it and the post-run scan reads a baseline the fixer could not
// have altered. Nothing here launches a process, reads the fixer's output, or applies anything.

import { mkdir, lstat, readdir, readlink } from "node:fs/promises";
import { join } from "node:path";
import { DomainError } from "../common/errors.js";
import { canonicalPathKey } from "../store/paths.js";
import { removeTreeNoFollow, isPlainDirectory, type RemoveTreeResult } from "../store/remove-tree.js";
import { canonicalizePath, isContainedIn, PATH_RULES, samePath } from "./paths.js";

/** The disposable workspace's directories. `root` is the per-run, per-workspace parent. */
export interface DisposableWorkspace {
  workspaceId: string;
  root: string;
  /** The fixer's writable tree (grant write here). */
  tree: string;
  /** The fixer's writable scratch and TEMP (grant write here). */
  scratch: string;
  /** CodeParley-only: baseline + metadata (never granted to the fixer). */
  control: string;
  /** The directories the launcher may grant the fixer write to (tree, scratch). */
  writableGrants: string[];
}

/** Where a run's workspaces live: `<dataHome>/work/<run-id>`. */
export function workRoot(dataHome: string, runId: string): string {
  return join(dataHome, "work", runId);
}

export function workspaceLayout(dataHome: string, runId: string, workspaceId: string): DisposableWorkspace {
  const root = join(workRoot(dataHome, runId), workspaceId);
  const tree = join(root, "tree");
  const scratch = join(root, "scratch");
  const control = join(root, "control");
  return { workspaceId, root, tree, scratch, control, writableGrants: [tree, scratch] };
}

/**
 * Create a disposable workspace. Fails closed if:
 *  - the primary worktree is inside the workspace root, or the workspace root is inside the primary
 *    worktree (either way a write to the workspace could reach the worktree) — WORKSPACE_OVERLAPS_PRIMARY;
 *  - any directory being created already exists as a link/reparse point — WORKSPACE_LINK_PRESENT
 *    (a pre-placed link could redirect writes out of the workspace).
 *
 * `primaryWorktreeRoot` must be canonical (workspace/paths.ts canonicalizePath). The caller ACL-prepares
 * the workspace for the launcher separately; this module only lays out directories.
 */
export async function createDisposableWorkspace(opts: {
  dataHome: string;
  runId: string;
  workspaceId: string;
  primaryWorktreeRoot: string;
}): Promise<DisposableWorkspace> {
  const ws = workspaceLayout(opts.dataHome, opts.runId, opts.workspaceId);
  // Canonicalize against the nearest existing ancestor (the root may not exist yet) and re-append the
  // remaining segments, so containment is checked against real targets and the real spelling.
  const rootReal = await canonicalizePath(ws.root);
  if (
    isContainedIn(opts.primaryWorktreeRoot, rootReal) ||
    isContainedIn(rootReal, opts.primaryWorktreeRoot) ||
    samePath(rootReal, opts.primaryWorktreeRoot)
  ) {
    throw new DomainError("WORKSPACE_OVERLAPS_PRIMARY", "the disposable workspace overlaps the primary worktree", {
      details: { workspaceRoot: ws.root, resolved: rootReal, primaryWorktreeRoot: opts.primaryWorktreeRoot },
    });
  }
  // Create each directory, refusing to adopt one that already exists as a link.
  for (const dir of [workRoot(opts.dataHome, opts.runId), ws.root, ws.tree, ws.scratch, ws.control]) {
    await assertNotLink(dir);
    await mkdir(dir, { recursive: true });
    await assertNotLink(dir);
  }
  return ws;
}

/**
 * Remove a disposable workspace and everything below it, never following a link (store/remove-tree.ts:
 * a symlink/junction/mount point is removed as a link, its target untouched). Returns the per-entry
 * tally; a non-empty `failures` means some entry could not be removed (an editor or scanner holding it).
 */
export async function destroyDisposableWorkspace(ws: DisposableWorkspace): Promise<RemoveTreeResult> {
  return removeTreeNoFollow(ws.root);
}

/** Remove a whole run's `work/<run-id>` tree (all its workspaces), link-safely. */
export async function destroyRunWorkspaces(dataHome: string, runId: string): Promise<RemoveTreeResult> {
  return removeTreeNoFollow(workRoot(dataHome, runId));
}

/**
 * Remove every workspace of a run except `keep`, link-safely: the workspaces of fixers that ended without their own
 * teardown (a killed process runs no `finally`). Only for a caller the custodian has just made the run's one active
 * operation, so no other fixer can be using any of them. Returns the workspace ids removed.
 */
export async function destroyStaleRunWorkspaces(dataHome: string, runId: string, keep: string): Promise<string[]> {
  const root = workRoot(dataHome, runId);
  const names = await readdir(root).catch(() => [] as string[]);
  const removed: string[] = [];
  for (const name of names) {
    if (name === keep) continue;
    await removeTreeNoFollow(join(root, name));
    removed.push(name);
  }
  return removed;
}

/** A workspace id bound to the primary worktree + task, so two tasks never share a workspace path. */
export function workspaceIdFor(primaryWorktreeRoot: string, taskId: string): string {
  return `${canonicalPathKey(primaryWorktreeRoot)}-${canonicalPathKey(`${PATH_RULES}:${taskId}`)}`;
}

/** Throw WORKSPACE_LINK_PRESENT if `dir` exists and is a symlink/junction/reparse point. */
async function assertNotLink(dir: string): Promise<void> {
  let st;
  try {
    st = await lstat(dir);
  } catch {
    return; // does not exist yet
  }
  if (st.isSymbolicLink()) throw linkPresent(dir, "symlink");
  if (PATH_RULES === "win32") {
    // A junction is a directory to lstat but readlink succeeds on it (store/remove-tree.ts isLinkLike).
    try {
      await readlink(dir);
      throw linkPresent(dir, "junction");
    } catch (e) {
      if (e instanceof DomainError) throw e;
      // EINVAL: a plain directory, or a reparse point readlink cannot express — the final path decides.
    }
  }
  if (st.isDirectory() && !(await isPlainDirectory(dir))) throw linkPresent(dir, "reparse_point");
}

function linkPresent(dir: string, kind: string): DomainError {
  return new DomainError("WORKSPACE_LINK_PRESENT", `a disposable-workspace directory already exists as a ${kind}: ${dir}`, { details: { dir, kind } });
}
