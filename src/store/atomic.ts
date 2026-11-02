// Atomic file replacement (plan §15.3). Write a uniquely-named temp file, fsync it, then
// rename over the target. On Windows a locked target (editor, antivirus) surfaces as
// EPERM/EACCES/EBUSY; those are retried for up to ~2s, then the write fails loudly. This is
// the single commit mechanism for the authoritative run-state record. In-house per §6.2.
//
// Linux (plan §1.13): a rename, and a newly created file, become durable only when their
// DIRECTORY is fsynced as well; without that a crash right after the commit can lose the new
// directory entry even though the file's own bytes were synced. Both are done here. Windows
// cannot open a directory for fsync, and NTFS journals the metadata change itself.

import { open, rename, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

const RETRY_CODES = new Set(["EPERM", "EACCES", "EBUSY"]);
const SYNC_DIRECTORIES = process.platform !== "win32";

export interface AtomicWriteOptions {
  /** Total time to keep retrying a locked rename. Default 2000ms (plan §15.3). */
  retryMs?: number;
}

/** fsync a directory so a rename or a new entry in it is durable (Linux; no-op on Windows). */
export async function syncDirectory(dir: string): Promise<void> {
  if (!SYNC_DIRECTORIES) return;
  const fh = await open(dir, "r");
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

/** Atomically write `data` to `targetPath` (fsync + rename-over with retry). */
export async function atomicWriteFile(targetPath: string, data: string | Buffer, opts: AtomicWriteOptions = {}): Promise<void> {
  const retryMs = opts.retryMs ?? 2000;
  const dir = dirname(targetPath);
  await mkdir(dir, { recursive: true });
  const tmp = join(dir, `.tmp-${randomBytes(8).toString("hex")}`);

  // Write + fsync the temp file so the bytes are durable before we commit by rename.
  const fh = await open(tmp, "w");
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }

  const started = Date.now();
  for (;;) {
    try {
      await rename(tmp, targetPath);
    } catch (e) {
      const code = (e as { code?: string }).code ?? "";
      if (RETRY_CODES.has(code) && Date.now() - started < retryMs) {
        await delay(50);
        continue;
      }
      // give up: remove the temp and rethrow loudly
      await rm(tmp, { force: true }).catch(() => undefined);
      throw e;
    }
    // The commit is visible from here on; making it durable cannot undo it, so a failure to
    // sync the directory does not turn a completed commit into a reported failure.
    await syncDirectory(dir).catch(() => undefined);
    return;
  }
}

/** Write `data` to `path` with fsync, without the rename (for immutable artifacts that are
 * written once at a fresh unique path). The directory entry is made durable too (Linux). */
export async function writeFileSynced(path: string, data: string | Buffer): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFileSyncedIn(path, data);
}

/** As writeFileSynced, into a directory that must already exist: nothing is created around it. */
export async function writeFileSyncedIn(path: string, data: string | Buffer): Promise<void> {
  const fh = await open(path, "w");
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await syncDirectory(dirname(path));
}

export async function readTextIfExists(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch (e) {
    if ((e as { code?: string }).code === "ENOENT") return null;
    throw e;
  }
}

/** Write-if-absent using the exclusive flag; returns false if the file already exists. */
export async function writeFileExclusive(path: string, data: string | Buffer): Promise<boolean> {
  // The parent may be removed concurrently (a lock holder's release removes its lock
  // directory between our mkdir and our create): recreate it and try again.
  for (let attempt = 0; ; attempt++) {
    await mkdir(dirname(path), { recursive: true });
    try {
      await writeFile(path, data, { flag: "wx" });
      return true;
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === "EEXIST") return false;
      if (code === "ENOENT" && attempt < 20) continue;
      throw e;
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
