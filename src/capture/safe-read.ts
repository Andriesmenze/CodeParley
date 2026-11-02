// Read working-tree files without following links, and hash exactly the bytes read
// (plan §8.4, §10.1, MR-B).
//
// For each path:
//  1. every component below the repository root is checked for a reparse point
//     (symlink, junction, mount point) — cached per capture for directories;
//  2. lstat must report a regular file with a single hard link (a hard link inside the
//     repository can name any file on the volume, which is the same escape as a link);
//  3. realpath must equal the expected path apart from letter case, which rejects 8.3
//     aliases (e.g. `GIT~1\config` naming `.git\config`) and any other alias;
//  4. the file is opened and fstat must report the same file id as step 2, so a swap
//     between the checks and the open is detected;
//  5. after reading, the open file's size, write time and change time must be unchanged (a
//     same-size write in place changes the times), and realpath and lstat are repeated and
//     must still agree.
// The bytes hashed are the bytes returned; size/mtime/file id are used only to detect
// races, never as evidence that content is unchanged.
//
// Residual risk (stated in the M1.2 procedure): a component swapped for a junction and
// swapped back strictly between steps 3 and 5 is not detectable from user mode.
//
// Linux (plan §1.13): step 1 also refuses mount points below the root (links.ts); step 3
// compares exactly (case-sensitive names); step 4 opens with O_NOFOLLOW (a final component
// swapped for a symlink fails the open instead of being followed) and O_NONBLOCK (a file
// swapped for a FIFO cannot block the capture: the open returns and fstat refuses it).

import { constants } from "node:fs";
import { lstat, open, readlink, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { firstLinkComponent } from "../workspace/links.js";
import { mountIdOfDir, mountIdOfFd } from "../workspace/mounts.js";
import { PATH_RULES, samePath } from "../workspace/paths.js";
import { EolStatsAccumulator, type EolStats } from "./eol.js";
import { gitObjectHasher, type ObjectFormat } from "./git-object.js";

export type ReadKind =
  | "file" // regular file read completely
  | "link" // the path or a directory component is a link/reparse point/hard link
  | "missing"
  | "not_regular" // directory, device, ...
  | "alias" // realpath differs from the expected path (8.3 alias etc.)
  | "unstable"; // changed or swapped while being read

export interface ReadResult {
  kind: ReadKind;
  reason?: string;
  size?: number;
  sha256?: string;
  /** Git blob id of the raw bytes, in the repository's object format. */
  gitOid?: string;
  stats?: EolStats;
  /** The content, when `retain` was requested and size <= maxRetainBytes. */
  bytes?: Buffer;
  /** For kind "link": SHA-256 of the link target text (never dereferenced). */
  linkTargetSha256?: string;
  /** For kind "link" on the path itself: the link target text. */
  linkTarget?: string;
}

export interface SafeReadOptions {
  root: string;
  objectFormat: ObjectFormat;
  /** Keep the content in memory when it is at most this many bytes. */
  maxRetainBytes: number;
  retain: boolean;
  /** Directory reparse-point cache shared across a capture. */
  linkCache: Map<string, boolean>;
  /** TEST ONLY: runs once a first chunk has been read (to change the file mid-read). */
  afterFirstChunk?: (absPath: string) => Promise<void>;
}

const CHUNK = 1 << 20;

/** Open flags for the read: no link following and no blocking on Linux; plain read on Windows. */
const OPEN_FLAGS: string | number = PATH_RULES === "win32" ? "r" : constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/** Read `absPath` (inside `opts.root`) under the rules above. Never throws for file-level problems. */
export async function readWorkingFile(absPath: string, opts: SafeReadOptions): Promise<ReadResult> {
  const first = await readOnce(absPath, opts);
  // One retry for a file that was being written while we read it.
  if (first.kind === "unstable") return readOnce(absPath, opts);
  return first;
}

/** Linux: the root's mount id per link cache (one per capture), taken at its first read. */
const rootMountIds = new WeakMap<Map<string, boolean>, number>();

/**
 * Linux: does the open descriptor `fd` lie on the root's own mount? A bind mount from the same
 * file system keeps device ids and `realpath` spellings, so one placed over a directory after
 * the capture cached that directory's link check would otherwise go unseen (PR #4 review).
 * The descriptor's mount cannot change once it is open: no window is left. Unknown is "no".
 */
async function onRootMount(fd: number, opts: SafeReadOptions): Promise<boolean> {
  let root = rootMountIds.get(opts.linkCache) ?? null;
  if (root === null) {
    root = await mountIdOfDir(opts.root);
    if (root !== null) rootMountIds.set(opts.linkCache, root);
  }
  return root !== null && (await mountIdOfFd(fd)) === root;
}

async function readOnce(absPath: string, opts: SafeReadOptions): Promise<ReadResult> {
  const link = await firstLinkComponent(absPath, opts.root, opts.linkCache);
  if (link) {
    // Directory components are cached; the final component is re-checked each time.
    return { kind: "link", reason: samePath(link, absPath) ? "reparse_point" : "reparse_point_ancestor", linkTargetSha256: await linkTargetHash(link) };
  }

  let st;
  try {
    st = await lstat(absPath, { bigint: true });
  } catch (e) {
    return isEnoent(e) ? { kind: "missing" } : { kind: "unstable", reason: errCode(e) };
  }
  if (st.isSymbolicLink()) {
    const target = await readlink(absPath).catch(() => "");
    return { kind: "link", reason: "symlink", linkTarget: target, linkTargetSha256: createHash("sha256").update(target, "utf8").digest("hex") };
  }
  if (!st.isFile()) return { kind: "not_regular", reason: st.isDirectory() ? "directory" : "special_file" };
  // A hard link is hashed for the source identity but never retained or exported.
  const hardLink = st.nlink > 1n;

  if (!(await realpathMatches(absPath))) return { kind: "alias", reason: "realpath_mismatch" };

  let fh;
  try {
    fh = await open(absPath, OPEN_FLAGS);
  } catch (e) {
    return isEnoent(e) ? { kind: "missing" } : { kind: "unstable", reason: errCode(e) };
  }
  try {
    const fst = await fh.stat({ bigint: true });
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev || (fst.nlink > 1n) !== hardLink) {
      return { kind: "unstable", reason: "swapped_before_open" };
    }
    if (process.platform === "linux" && !(await onRootMount(fh.fd, opts))) return { kind: "link", reason: "mount_point" };
    const expected = Number(fst.size);
    const sha = createHash("sha256");
    const oid = gitObjectHasher(opts.objectFormat, "blob", expected);
    const eol = new EolStatsAccumulator();
    const keep = opts.retain && !hardLink && expected <= opts.maxRetainBytes;
    const chunks: Buffer[] = [];
    let total = 0;
    const buf = Buffer.allocUnsafe(CHUNK);
    for (let first = true; ; first = false) {
      const { bytesRead } = await fh.read(buf, 0, CHUNK, null);
      if (bytesRead === 0) break;
      const piece = buf.subarray(0, bytesRead);
      sha.update(piece);
      oid.update(piece);
      eol.update(piece);
      total += bytesRead;
      if (keep && total <= opts.maxRetainBytes) chunks.push(Buffer.from(piece));
      if (total > expected) break; // grew while reading
      if (first) await opts.afterFirstChunk?.(absPath);
    }
    if (total !== expected) return { kind: "unstable", reason: "size_changed_while_reading" };
    // A same-size write in place leaves size and file id unchanged; its write time and change
    // time do not (reads never change them). Compared through the open handle (PR #2 review).
    const fst2 = await fh.stat({ bigint: true });
    if (fst2.size !== fst.size || fst2.mtimeNs !== fst.mtimeNs || fst2.ctimeNs !== fst.ctimeNs) {
      return { kind: "unstable", reason: "changed_while_reading" };
    }

    const after = await lstat(absPath, { bigint: true }).catch(() => null);
    if (!after || after.ino !== st.ino || after.dev !== st.dev || after.size !== fst.size || !(await realpathMatches(absPath))) {
      return { kind: "unstable", reason: "changed_while_reading" };
    }
    if (hardLink) return { kind: "link", reason: "hard_link", size: total, sha256: sha.digest("hex"), gitOid: oid.digest("hex"), stats: eol.finish() };
    return {
      kind: "file",
      size: total,
      sha256: sha.digest("hex"),
      gitOid: oid.digest("hex"),
      stats: eol.finish(),
      ...(keep ? { bytes: Buffer.concat(chunks, total) } : {}),
    };
  } finally {
    await fh.close().catch(() => undefined);
  }
}

async function realpathMatches(absPath: string): Promise<boolean> {
  try {
    const real = await realpath(absPath);
    return samePath(real, absPath);
  } catch {
    return false;
  }
}

async function linkTargetHash(path: string): Promise<string> {
  try {
    const target = await readlink(path);
    return createHash("sha256").update(target, "utf8").digest("hex");
  } catch {
    return sha256Empty();
  }
}

function sha256Empty(): string {
  return createHash("sha256").update("", "utf8").digest("hex");
}

function isEnoent(e: unknown): boolean {
  const c = errCode(e);
  return c === "ENOENT" || c === "ENOTDIR";
}

function errCode(e: unknown): string {
  return (e as { code?: string })?.code ?? "UNKNOWN";
}
