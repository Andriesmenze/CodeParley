// Globally unique IDs and short display forms. In-house per plan §6.2.
//
// UUIDv7 (time-ordered) is used for run, operation and finding IDs so records sort by
// creation and stay globally unique across processes (plan §5.4, §13.5). Node has no
// built-in v7 generator, so we build one from a 48-bit millisecond timestamp plus random.

import { randomBytes } from "node:crypto";

/** A globally unique, time-ordered identifier (UUIDv7). */
export type Id = string;

/** Generate a UUIDv7 string. */
export function uuidv7(now: number = Date.now()): Id {
  const bytes = randomBytes(16);

  // 48-bit big-endian millisecond timestamp in bytes 0..5.
  const ts = BigInt(now);
  bytes[0] = Number((ts >> 40n) & 0xffn);
  bytes[1] = Number((ts >> 32n) & 0xffn);
  bytes[2] = Number((ts >> 24n) & 0xffn);
  bytes[3] = Number((ts >> 16n) & 0xffn);
  bytes[4] = Number((ts >> 8n) & 0xffn);
  bytes[5] = Number(ts & 0xffn);

  // Version 7 in the high nibble of byte 6; variant (10xx) in the high bits of byte 8.
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;

  const hex = bytes.toString("hex");
  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20, 32)
  );
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isUuid(s: string): boolean {
  return UUID_RE.test(s);
}

/** Short display form of an ID (first 8 chars), for logs and summaries (plan §11.2). */
export function shortId(id: string): string {
  return id.slice(0, 8);
}
