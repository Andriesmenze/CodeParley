// Link and reparse-point handling (plan §8.4). Capture must never follow a link. Any path
// whose final component — or any directory component below a root — is a link is refused and
// recorded as a coverage limitation by the caller.
//
// Windows: Node's lstat reports symlinks via isSymbolicLink(); junctions are detected by a
// successful readlink (which throws EINVAL on a non-reparse entry). This dual check avoids
// depending on a single Node behaviour (the exact behaviour is pinned by LV-WIN-PATHS).
//
// Linux (plan §1.13): a symbolic link is an ordinary filesystem object, reported by lstat. A
// MOUNT POINT inside the root is treated as a link too: a mounted directory or file (a bind or
// FUSE mount, another file system) can expose any tree, exactly the escape a junction is on
// Windows. Mount points are recognised by a device id different from the root's, and — for a
// bind mount from the same file system, whose device id is the same — by the mount table
// (workspace/mounts.ts).

import { lstat, readlink } from "node:fs/promises";
import { DomainError } from "../common/errors.js";
import { PATH_RULES, PATH_SEP, caseKey, isContainedIn, withoutTrailingSeparator } from "./paths.js";
import { isMountPoint } from "./mounts.js";

const WIN = PATH_RULES === "win32";

/** Does `path` itself exist and is it a symlink/junction/other reparse point? */
export async function isReparsePoint(path: string): Promise<boolean> {
  let st;
  try {
    st = await lstat(path);
  } catch {
    return false; // does not exist / not accessible: not our link concern here
  }
  if (st.isSymbolicLink()) return true;
  if (!WIN) return false;
  // Junctions on Windows are directories to lstat but readlink succeeds on them.
  try {
    await readlink(path);
    return true;
  } catch (e) {
    // EINVAL: not a reparse point (ordinary files and directories on NTFS and on SMB shares; also
    // a reparse point libuv cannot express, which safe-read's final-path check refuses). Any other
    // error leaves the entry unclassified: treat it as a link so callers refuse it (fail closed).
    return (e as { code?: string }).code !== "EINVAL";
  }
}

/** Linux: is `path` a symlink, or a mount point (another device than the root's, or listed in the mount table)? */
async function isLinkOrMount(path: string, rootDev: bigint | null): Promise<boolean> {
  let st;
  try {
    st = await lstat(path, { bigint: true });
  } catch {
    return false;
  }
  if (st.isSymbolicLink()) return true;
  if (rootDev !== null && st.dev !== rootDev) return true;
  return isMountPoint(path);
}

/**
 * Walk every path component strictly below `root` down to and including `path`, and return
 * the first that is a link (Windows: any reparse point; Linux: a symlink or a mount point), or
 * null if none is. `cache` memoizes component results across a capture. `path` and `root` must
 * be canonical/validated.
 */
export async function firstLinkComponent(
  path: string,
  root: string,
  cache?: Map<string, boolean>,
): Promise<string | null> {
  if (!isContainedIn(path, root)) {
    // Defensive: only check components inside the root.
    return null;
  }
  const base = withoutTrailingSeparator(root);
  const rel = path.slice(base.length).replace(WIN ? /^\\/ : /^\/+/, "");
  const segs = rel.length ? rel.split(PATH_SEP) : [];
  let rootDev: bigint | null = null;
  if (!WIN && segs.length > 0) rootDev = (await lstat(base, { bigint: true }).catch(() => null))?.dev ?? null;
  let current = base;
  for (const seg of segs) {
    current = current === "/" ? `/${seg}` : `${current}${PATH_SEP}${seg}`;
    const key = caseKey(current);
    let link = cache?.get(key);
    if (link === undefined) {
      link = WIN ? await isReparsePoint(current) : await isLinkOrMount(current, rootDev);
      cache?.set(key, link);
    }
    if (link) return current;
  }
  return null;
}

/** Throw DomainError("LINK_NOT_ALLOWED") if any component of `path` below `root` is a link. */
export async function assertNoLinkInPath(path: string, root: string, cache?: Map<string, boolean>): Promise<void> {
  const offending = await firstLinkComponent(path, root, cache);
  if (offending) {
    throw new DomainError("LINK_NOT_ALLOWED", `path crosses a link or reparse point: ${offending}`, {
      details: { path, offending, root },
    });
  }
}
