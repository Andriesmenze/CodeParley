// Mount points on Linux (plan §1.13). A bind mount of a directory or a file from the SAME file
// system keeps its device id, so comparing device ids cannot see it, and `realpath` keeps the
// mount point's spelling; yet it can expose any tree, exactly like a link. /proc/self/mountinfo
// lists every mount point of this process's mount namespace, bind mounts included: capture,
// sizing and deletion treat every listed mount point below their root as a link (in addition
// to the device test). Nothing here is consulted on Windows.

import { constants, readFileSync } from "node:fs";
import { open, readFile } from "node:fs/promises";

/** The mount points (field 5) of a /proc/<pid>/mountinfo text, with the kernel's octal escapes decoded. */
export function parseMountInfo(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split("\n")) {
    const fields = line.split(" ");
    const point = fields[4];
    if (fields.length < 5 || !point) continue;
    // The kernel escapes space, tab, newline and backslash as \ooo; other bytes appear as they are.
    out.add(point.replace(/\\([0-7]{3})/g, (_, o: string) => String.fromCharCode(parseInt(o, 8))));
  }
  return out;
}

const TTL_MS = 1000;
let cached: { at: number; points: Set<string> | null } | null = null;

/**
 * The mount points of this process's mount namespace, read at most once a second; null when
 * /proc/self/mountinfo cannot be read (then nothing can be shown NOT to be a mount point).
 */
export function mountPoints(now: number = Date.now()): Set<string> | null {
  if (cached && now - cached.at < TTL_MS) return cached.points;
  let points: Set<string> | null;
  try {
    points = parseMountInfo(readFileSync("/proc/self/mountinfo", "utf8"));
  } catch {
    points = null;
  }
  cached = { at: now, points };
  return points;
}

/**
 * Is the canonical absolute `path` a mount point? Fails closed: when the mount table cannot be
 * read, every path counts as one (callers refuse to read or delete through it).
 */
export function isMountPoint(path: string): boolean {
  const points = mountPoints();
  return points === null || points.has(path);
}

/**
 * The mount id (`mnt_id`, /proc/self/fdinfo) of the open descriptor `fd`: the mount the open
 * file lies on, fixed for the descriptor's lifetime whatever is mounted later. Null when it
 * cannot be read.
 */
export async function mountIdOfFd(fd: number): Promise<number | null> {
  const text = await readFile(`/proc/self/fdinfo/${fd}`, "utf8").catch(() => null);
  const line = text?.split("\n").find((l) => l.startsWith("mnt_id:"));
  const raw = line?.slice("mnt_id:".length).trim() ?? "";
  const id = Number(raw);
  return raw.length > 0 && Number.isSafeInteger(id) ? id : null;
}

/** The mount id of the directory `dir` (a final link is not followed); null when it cannot be read. */
export async function mountIdOfDir(dir: string): Promise<number | null> {
  const fh = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW).catch(() => null);
  if (!fh) return null;
  try {
    return await mountIdOfFd(fh.fd);
  } finally {
    await fh.close();
  }
}
