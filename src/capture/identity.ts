// Source identity (plan §10.1, MR-B). Pure.
//
// `source_id` is the SHA-256 over a canonical, path-sorted manifest of the captured
// WORKING TREE: for every present path its area, source class, size and the SHA-256 of
// the raw bytes actually read (link target text for links, the checked-out commit for
// submodules). Confidential and size-skipped files are hashed but never exported.
//
// It deliberately does NOT depend on the review target, the base, repository-context
// exclusions or the export cap: those decide what a review is SHOWN and belong to the
// review input identity (export manifest digest, `engine/identities.ts`). So a check run
// and a review of the same working tree agree on `source_id`.

import { sha256OfCanonicalJson } from "../common/hash.js";
import type { SourceEntry } from "../schemas/capture.js";

export const SOURCE_ID_SCHEMA = "arl.source-id.v1";

export function computeSourceId(entries: readonly Pick<SourceEntry, "path" | "area" | "class" | "size" | "sha256">[]): string {
  const rows = [...entries]
    // Byte order for the tie-breaker too: a locale-dependent comparison has no place in a digest.
    .sort((a, b) => compareUtf8(a.path, b.path) || compareUtf8(a.area, b.area))
    .map((e) => [e.path, e.area, e.class, e.size, e.sha256]);
  return sha256OfCanonicalJson({ schema: SOURCE_ID_SCHEMA, entries: rows });
}

/** Byte-order comparison of the UTF-8 encodings (stable across platforms and locales). */
export function compareUtf8(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}
