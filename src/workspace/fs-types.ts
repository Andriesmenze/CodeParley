// File-system types on Linux (plan §1.13). Capture's link, alias and identity guarantees and the
// store's atomic commit point rest on POSIX semantics: case-sensitive names, real symbolic and
// hard links, atomic rename, exclusive create. File systems known NOT to provide them — WSL's
// drvfs mounts of Windows drives (9p), FAT/exFAT, NTFS, SMB/CIFS — and FUSE mounts, whose
// semantics depend on whatever implements them, are refused for capture and for the data home.
// Other file systems are allowed; only ext4 (and tmpfs, for scratch) was validated, and
// `doctor` says so. Nothing here is consulted on Windows.

import { statfs } from "node:fs/promises";
import { dirname } from "node:path";

export type FsStatus = "validated" | "unvalidated" | "refused";

export interface FsType {
  /** statfs f_type (magic number). */
  type: number;
  name: string;
  status: FsStatus;
}

const TYPES: ReadonlyMap<number, [string, FsStatus]> = new Map([
  [0xef53, ["ext2/ext3/ext4", "validated"]],
  [0x01021994, ["tmpfs", "validated"]],
  [0x58465342, ["xfs", "unvalidated"]],
  [0x9123683e, ["btrfs", "unvalidated"]],
  [0x794c7630, ["overlayfs", "unvalidated"]],
  [0x2fc12fc1, ["zfs", "unvalidated"]],
  [0xf2f52010, ["f2fs", "unvalidated"]],
  [0xca451a4e, ["bcachefs", "unvalidated"]],
  [0x52654973, ["reiserfs", "unvalidated"]],
  [0x3153464a, ["jfs", "unvalidated"]],
  [0x0000f15f, ["ecryptfs", "unvalidated"]],
  [0x00006969, ["nfs", "unvalidated"]],
  [0x01021997, ["9p (WSL drvfs or virtio-9p)", "refused"]],
  [0x00004d44, ["vfat/msdos", "refused"]],
  [0x2011bab0, ["exfat", "refused"]],
  [0x7366746e, ["ntfs3", "refused"]],
  [0x5346544e, ["ntfs", "refused"]],
  [0x65735546, ["fuse", "refused"]],
  [0x0000517b, ["smb", "refused"]],
  [0xff534d42, ["cifs", "refused"]],
  [0xfe534d42, ["smb2", "refused"]],
  [0x00004244, ["hfs", "refused"]],
  [0x0000482b, ["hfsplus", "refused"]],
]);

/** Classify a statfs magic number. */
export function classifyFsType(type: number): FsType {
  const t = type >>> 0;
  const known = TYPES.get(t);
  return known ? { type: t, name: known[0], status: known[1] } : { type: t, name: `unknown (0x${t.toString(16)})`, status: "unvalidated" };
}

/** The file system holding `path` (or, if it does not exist yet, its nearest existing ancestor). */
export async function fsTypeOf(path: string): Promise<FsType | null> {
  let p = path;
  for (let i = 0; i < 4096; i++) {
    try {
      return classifyFsType((await statfs(p)).type);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") return null;
      const up = dirname(p);
      if (up === p) return null;
      p = up;
    }
  }
  return null;
}
