// Git object identities computed in-process (no git invocation, nothing written).
//
// Comparing the git blob id of the raw working-file bytes with the base tree's blob id
// is a content comparison (the same one git's own object store relies on), not a
// metadata shortcut (MR-B). No object id is hard-coded: the empty tree id is derived for
// the repository's object format (plan §9.7, SHA-256 support).

import { createHash, type Hash } from "node:crypto";

export type ObjectFormat = "sha1" | "sha256";

/** Hash for a git object of `type` and `size`, ready for content updates. */
export function gitObjectHasher(format: ObjectFormat, type: "blob" | "tree", size: number): Hash {
  const h = createHash(format === "sha1" ? "sha1" : "sha256");
  h.update(`${type} ${size}\0`, "latin1");
  return h;
}

/** Git blob id of `bytes`. */
export function gitBlobOid(format: ObjectFormat, bytes: Buffer): string {
  return gitObjectHasher(format, "blob", bytes.length).update(bytes).digest("hex");
}

/** The empty tree's id in this object format ("tree 0\0"). */
export function emptyTreeOid(format: ObjectFormat): string {
  return gitObjectHasher(format, "tree", 0).digest("hex");
}

export function oidLength(format: ObjectFormat): number {
  return format === "sha1" ? 40 : 64;
}

export interface LfsPointer {
  sha256: string;
  size: number;
}

/**
 * Parse a Git LFS pointer file (spec v1). Returns null for anything that is not a
 * well-formed pointer. Used to decide whether an LFS-managed working file still matches
 * its base without running git-lfs (the pointer records the content's SHA-256 and size).
 */
export function parseLfsPointer(bytes: Buffer): LfsPointer | null {
  if (bytes.length > 1024) return null;
  const text = bytes.toString("utf8");
  if (!text.startsWith("version https://git-lfs.github.com/spec/v1\n")) return null;
  const oid = /^oid sha256:([0-9a-f]{64})$/m.exec(text);
  const size = /^size (\d+)$/m.exec(text);
  if (!oid || !size) return null;
  const n = Number(size[1]);
  if (!Number.isSafeInteger(n)) return null;
  return { sha256: oid[1]!, size: n };
}
