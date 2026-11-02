// The content identity of a built CodeParley plugin (P3.3b provenance). Shared by build-plugin.mjs,
// which records it, and verify-plugin.mjs, which recomputes it for any copy a host loads: the
// marketplace folder (read in place by the CLI) or a host's cached copy (Claude Desktop loads the copy
// made at install: ~/.claude/plugins/cache/<marketplace>/code-parley/<version>/).
//
// The digest covers every file of the plugin except the two that carry it (.claude-plugin/plugin.json,
// whose version ends with the digest, and build-info.json) and the host's own bookkeeping in a cached
// copy (.in_use/, .orphaned_at).

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export const CONTENT_SCHEMA = "codeparley.plugin-content.v1";
export const BUILD_INFO = "build-info.json";
export const MANIFEST = ".claude-plugin/plugin.json";
/** Paths excluded from the content digest: the files that record it, and a host cache's bookkeeping. */
export const EXCLUDED = [MANIFEST, BUILD_INFO];
export const HOST_MARKERS = [".in_use/", ".orphaned_at"];

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

function walk(root, rel = "") {
  const out = [];
  for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...walk(root, p));
    else if (e.isFile()) out.push(p);
    else throw new Error(`unexpected entry in the plugin (not a file or directory): ${p}`);
  }
  return out;
}

const isHostMarker = (p) => HOST_MARKERS.some((m) => (m.endsWith("/") ? p.startsWith(m) : p === m));

/** Every file of the plugin directory as [path, size, sha256], sorted; the host markers it skipped. */
export function contentFiles(root) {
  const files = [];
  const markers = [];
  for (const p of walk(root).sort()) {
    if (isHostMarker(p)) {
      markers.push(p);
      continue;
    }
    if (EXCLUDED.includes(p)) continue;
    const bytes = readFileSync(join(root, ...p.split("/")));
    files.push([p, statSync(join(root, ...p.split("/"))).size, sha256(bytes)]);
  }
  return { files, markers };
}

export function contentDigest(files) {
  return sha256(JSON.stringify({ schema: CONTENT_SCHEMA, files }));
}

/** The plugin version a build carries: the template's base version (the release version, package.json) plus the
 * content digest as a pre-release identifier — `-b<digest>`, or `.b<digest>` when the base already has one. */
export function versionOf(base, digest) {
  return `${base}${base.includes("-") ? "." : "-"}b${digest.slice(0, 12)}`;
}
