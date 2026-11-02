// SHA-256 helpers. In-house per plan §6.2. All identities are full 64-hex SHA-256; only
// the display is shortened (plan §10).

import { createHash } from "node:crypto";

export type Sha256 = string; // 64 lowercase hex

export function sha256OfBytes(bytes: Buffer | Uint8Array): Sha256 {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256OfString(s: string): Sha256 {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Canonical JSON hash: stable key ordering so the same logical object always hashes the
 * same. Used for manifest/identity digests (plan §10).
 */
export function sha256OfCanonicalJson(value: unknown): Sha256 {
  return sha256OfString(canonicalize(value));
}

/** Deterministic JSON serialization with sorted object keys. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/** Short display form of a hash (first 12 chars) (plan §11.2). */
export function shortHash(h: string): string {
  return h.slice(0, 12);
}
