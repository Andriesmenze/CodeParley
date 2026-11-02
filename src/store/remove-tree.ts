// Link-safe deletion inside the run store (plan §15.6, §1.12; M1.6 purge and retention).
//
// Deletion never follows a link. A symbolic link, junction or other reparse point is removed
// as a link (unlink, or rmdir for a directory reparse point: both remove the reparse point,
// never its target) and its target is never visited. A directory is entered only when it is
// provably a plain directory: lstat says directory, readlink fails, AND its final path
// (realpath) is its parent's final path plus its own name. The last check is what catches a
// junction whose target is a volume GUID path (`\??\Volume{…}\…`, creatable without
// elevation): libuv cannot express that target, so readlink fails on it with the same EINVAL
// as on a plain directory and lstat silently stats the target instead (M1.6-13, reproduced).
// The directory's identity (dev + ino, exact as bigint) and final path are re-checked after
// listing, so a directory swapped for a link between the check and the listing is refused
// rather than walked. Residual risk (stated): a process that can write to the data home can
// still race the per-entry operations; such a process already runs with the user's own rights.
//
// Linux (plan §1.13): links are symbolic links (lstat); in addition a mount point — a directory
// on another device than its parent, or any directory or file the mount table lists (a bind
// mount from the same file system keeps the device id; workspace/mounts.ts) — is never entered
// or removed: removing below it would delete another tree's content. It is reported as a
// failure (MOUNT_POINT) and left in place.
//
// Failures (a file held open by an editor or antivirus, permissions) are retried briefly,
// then recorded and skipped; the caller decides what a partial removal means.

import { chmod, lstat, readdir, readlink, realpath, rmdir, unlink } from "node:fs/promises";
import type { BigIntStats } from "node:fs";
import { basename, dirname, join } from "node:path";
import { PATH_RULES, samePath } from "../workspace/paths.js";
import { isMountPoint } from "../workspace/mounts.js";

const WIN = PATH_RULES === "win32";

/** The parts of a (bigint or number) lstat result this module uses. */
type EntryStats = { isSymbolicLink(): boolean; isDirectory(): boolean };

/** Device id of `path` itself (no link following), or null. */
async function devOf(path: string): Promise<bigint | null> {
  return (await lstat(path, { bigint: true }).catch(() => null))?.dev ?? null;
}

export interface RemoveTreeResult {
  removedFiles: number;
  removedDirs: number;
  /** Links and reparse points removed as links (their targets untouched). */
  removedLinks: number;
  bytes: number;
  failures: { path: string; code: string }[];
}

const RETRY_CODES = new Set(["EBUSY", "EPERM", "EACCES", "ENOTEMPTY"]);
const ATTEMPTS = 8;

function codeOf(e: unknown): string {
  return (e as { code?: string }).code ?? "UNKNOWN";
}

async function withRetry(op: () => Promise<void>, onPerm?: () => Promise<void>): Promise<string | null> {
  for (let i = 0; i < ATTEMPTS; i++) {
    try {
      await op();
      return null;
    } catch (e) {
      const code = codeOf(e);
      if (code === "ENOENT") return null; // already gone
      if (!RETRY_CODES.has(code) || i === ATTEMPTS - 1) return code;
      if (code === "EPERM" && onPerm && i === 0) await onPerm().catch(() => undefined);
      await new Promise((r) => setTimeout(r, 25 * (i + 1)));
    }
  }
  return "UNKNOWN";
}


/**
 * Does the directory at `path` redirect somewhere else? It does not when its final path is its
 * parent's final path (`parentReal`, computed when not supplied) plus its own name. An entry
 * whose final path cannot be read counts as redirecting: refusing is the safe direction.
 */
async function redirects(path: string, parentReal: string | null): Promise<boolean> {
  const real = await realpath(path).catch(() => null);
  const pr = parentReal ?? (await realpath(dirname(path)).catch(() => null));
  return real === null || pr === null || !samePath(real, join(pr, basename(path)));
}

/**
 * Is this entry a link of any kind (symlink, junction, mount point, other redirecting reparse
 * point)? `parentReal` is the parent directory's final path when the caller already knows it.
 */
export async function isLinkLike(path: string, st: EntryStats, parentReal: string | null = null): Promise<boolean> {
  if (st.isSymbolicLink()) return true;
  if (!st.isDirectory()) return false;
  try {
    // A junction to a drive path is a directory to lstat, but readlink succeeds on it.
    await readlink(path);
    return true;
  } catch {
    // A plain directory, or a reparse point readlink cannot express: the final path decides.
    return redirects(path, parentReal);
  }
}

/** True when `path` exists and is a plain directory (not a link or reparse point). */
export async function isPlainDirectory(path: string): Promise<boolean> {
  const st = await lstat(path, { bigint: true }).catch(() => null);
  if (!st?.isDirectory() || (await isLinkLike(path, st))) return false;
  // Linux: a mount point is not a plain directory of its parent.
  if (WIN) return true;
  const real = await realpath(path).catch(() => null);
  return real !== null && st.dev === (await devOf(dirname(path))) && !isMountPoint(real);
}

/** Remove the entry at `path`; `parentReal` is its parent's final path (null: compute it). */
async function removeEntry(path: string, r: RemoveTreeResult, parentReal: string | null, parentDev: bigint | null): Promise<void> {
  let st: BigIntStats;
  try {
    st = await lstat(path, { bigint: true });
  } catch (e) {
    if (codeOf(e) !== "ENOENT") r.failures.push({ path, code: codeOf(e) });
    return;
  }
  if (await isLinkLike(path, st, parentReal)) return removeLink(path, r);
  const ownReal = parentReal !== null ? join(parentReal, basename(path)) : await realpath(path).catch(() => null);
  // Linux: a mounted directory or file is left in place (deleting through it would reach another tree).
  if (isMountedEntry(st, ownReal, parentDev)) {
    r.failures.push({ path, code: "MOUNT_POINT" });
    return;
  }
  if (st.isDirectory()) return removeDirectory(path, st, r, parentReal, ownReal);
  return removeFile(path, st, r);
}

/** Linux: a directory on another device than its parent, or any entry the mount table lists. */
function isMountedEntry(st: BigIntStats, ownReal: string | null, parentDev: bigint | null): boolean {
  if (WIN) return false;
  if (st.isDirectory() && parentDev !== null && st.dev !== parentDev) return true;
  return ownReal !== null && isMountPoint(ownReal);
}

/**
 * Remove a link itself, never its target. libuv's unlink refuses a directory reparse point it
 * cannot read as a link (EPERM); rmdir removes the reparse point, not the target.
 */
async function removeLink(path: string, r: RemoveTreeResult): Promise<void> {
  const code = await withRetry(async () => {
    try {
      await unlink(path);
    } catch (e) {
      if (codeOf(e) === "EISDIR" || codeOf(e) === "EPERM") await rmdir(path);
      else throw e;
    }
  });
  if (code) r.failures.push({ path, code });
  else r.removedLinks++;
}

/** Remove a plain directory and everything below it (its entries are removed by `removeEntry`). */
async function removeDirectory(path: string, st: BigIntStats, r: RemoveTreeResult, parentReal: string | null, ownReal: string | null): Promise<void> {
  if (ownReal === null) {
    r.failures.push({ path, code: "CHANGED_DURING_PURGE" });
    return;
  }
  let names: string[];
  try {
    names = await readdir(path);
  } catch (e) {
    r.failures.push({ path, code: codeOf(e) });
    return;
  }
  // Refuse to descend if the directory was swapped (e.g. for a link) since the checks above:
  // same identity (exact, bigint) and still not redirecting.
  const again = await lstat(path, { bigint: true }).catch(() => null);
  if (!again?.isDirectory() || again.ino !== st.ino || again.dev !== st.dev || (await isLinkLike(path, again, parentReal))) {
    r.failures.push({ path, code: "CHANGED_DURING_PURGE" });
    return;
  }
  for (let i = 0; i < names.length; i += 16) {
    await Promise.all(names.slice(i, i + 16).map((n) => removeEntry(join(path, n), r, ownReal, st.dev)));
  }
  const code = await withRetry(() => rmdir(path));
  if (code) r.failures.push({ path, code });
  else r.removedDirs++;
}

async function removeFile(path: string, st: BigIntStats, r: RemoveTreeResult): Promise<void> {
  const size = Number(st.size);
  const code = await withRetry(
    () => unlink(path),
    () => chmod(path, 0o666), // a read-only attribute makes unlink fail with EPERM on Windows
  );
  if (code) r.failures.push({ path, code });
  else {
    r.removedFiles++;
    r.bytes += size;
  }
}

/**
 * Remove `root` and everything below it without following links. If `root` itself is a link,
 * only the link is removed. Never throws for per-entry failures: they are returned.
 */
export async function removeTreeNoFollow(root: string): Promise<RemoveTreeResult> {
  const r: RemoveTreeResult = { removedFiles: 0, removedDirs: 0, removedLinks: 0, bytes: 0, failures: [] };
  await removeEntry(root, r, null, WIN ? null : await devOf(dirname(root)));
  return r;
}

/** Total size of regular files below `root`, not following links (bounded by `maxEntries`). */
export async function treeSize(root: string, maxEntries = 200_000): Promise<{ bytes: number; files: number; complete: boolean }> {
  let bytes = 0;
  let files = 0;
  let seen = 0;
  const rootSt = await lstat(root).catch(() => null);
  if (!rootSt || !rootSt.isDirectory() || (await isLinkLike(root, rootSt))) return { bytes, files, complete: true };
  const rootReal = await realpath(root).catch(() => null);
  if (rootReal === null) return { bytes, files, complete: false };
  const rootDev = WIN ? null : await devOf(root);
  const stack = [{ dir: root, real: rootReal }];
  while (stack.length > 0) {
    const { dir, real } = stack.pop()!;
    const names = await readdir(dir).catch(() => [] as string[]);
    for (const n of names) {
      if (++seen > maxEntries) return { bytes, files, complete: false };
      const p = join(dir, n);
      const st = await lstat(p).catch(() => null);
      if (!st) continue;
      if (await isLinkLike(p, st, real)) continue;
      // A mount point (Linux): another device, or listed in the mount table (a bind mount).
      if (rootDev !== null && ((st.isDirectory() && (await devOf(p)) !== rootDev) || isMountPoint(join(real, n)))) continue;
      if (st.isDirectory()) stack.push({ dir: p, real: join(real, n) });
      else if (st.isFile()) {
        bytes += st.size;
        files++;
      }
    }
  }
  return { bytes, files, complete: true };
}
