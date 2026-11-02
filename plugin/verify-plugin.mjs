#!/usr/bin/env node
// Verify a CodeParley plugin copy (P3.3b provenance): the marketplace folder a CLI session reads in
// place, or the copy a host cached at install (Claude Desktop: ~/.claude/plugins/cache/<marketplace>/
// code-parley/<version>/). Read-only.
//
//   node plugin/verify-plugin.mjs <plugin dir> [--against <intended build dir>] [--expect <digest|version>] [--json]
//
// It recomputes the content digest (plugin-content.mjs) and checks that
//  - the copy is intact: its files are exactly those its build-info.json records;
//  - plugin.json's version is build-info's, and that version ends with the content digest;
//  - with --against: the copy is the intended build (same digest; the differing files are listed);
//  - with --expect: the digest or the version is the expected one.
// A host's bookkeeping in a cached copy (.in_use/, .orphaned_at) is reported, never counted.
// Exit 0 when every check holds, 1 otherwise.

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { BUILD_INFO, contentDigest, contentFiles, versionOf } from "./plugin-content.mjs";

function parse(argv) {
  const o = { dir: null, against: null, expect: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--against") o.against = resolve(argv[++i] ?? "");
    else if (a === "--expect") o.expect = argv[++i] ?? "";
    else if (a === "--json") o.json = true;
    else if (!a.startsWith("--") && !o.dir) o.dir = resolve(a);
    else throw new Error(`unknown option ${a}`);
  }
  if (!o.dir) throw new Error("usage: verify-plugin.mjs <plugin dir> [--against <dir>] [--expect <digest|version>] [--json]");
  return o;
}

function readJson(p) {
  return JSON.parse(readFileSync(p, "utf8"));
}

/** What one plugin directory is: its recorded identity and its recomputed content. */
export function inspect(dir) {
  const infoPath = join(dir, BUILD_INFO);
  const info = existsSync(infoPath) ? readJson(infoPath) : null;
  const manifest = readJson(join(dir, ".claude-plugin", "plugin.json"));
  const { files, markers } = contentFiles(dir);
  const digest = contentDigest(files);
  return { dir, info, manifest, files, markers, digest };
}

/** Files that differ between two content lists: [path, how]. */
export function diffFiles(a, b) {
  const ma = new Map(a.map(([p, , h]) => [p, h]));
  const mb = new Map(b.map(([p, , h]) => [p, h]));
  const out = [];
  for (const [p, h] of ma) if (!mb.has(p)) out.push([p, "only in the first"]);
  else if (mb.get(p) !== h) out.push([p, "content differs"]);
  for (const p of mb.keys()) if (!ma.has(p)) out.push([p, "only in the second"]);
  return out.sort((x, y) => (x[0] < y[0] ? -1 : 1));
}

export function verify(o) {
  const c = inspect(o.dir);
  const checks = [];
  const check = (name, ok, detail = "") => checks.push({ name, ok, detail });
  check("build-info.json present", c.info !== null, c.info ? "" : "not a P3.3b-or-later build (no build-info.json)");
  if (c.info) {
    const recorded = c.info.content?.digest ?? null;
    const drift = diffFiles(c.info.content?.files ?? [], c.files);
    check("intact: the files are exactly those the build recorded", recorded === c.digest && drift.length === 0, drift.slice(0, 20).map(([p, how]) => `${p}: ${how}`).join("; "));
    check("plugin.json version is the build's", c.manifest.version === c.info.version, `${c.manifest.version} vs ${c.info.version}`);
    const base = String(c.info.version).replace(/[.-]b[0-9a-f]{12}$/, "");
    check("the version carries the content digest", c.info.version === versionOf(base, c.digest), `${c.info.version} vs digest ${c.digest.slice(0, 12)}`);
  }
  let against = null;
  if (o.against) {
    const t = inspect(o.against);
    const drift = diffFiles(t.files, c.files);
    against = { dir: t.dir, version: t.manifest.version, digest: t.digest };
    check("same content as the intended build (--against)", t.digest === c.digest && drift.length === 0, drift.slice(0, 20).map(([p, how]) => `${p}: ${how === "only in the first" ? "missing here" : how === "only in the second" ? "extra here" : how}`).join("; "));
    check("same version as the intended build (--against)", t.manifest.version === c.manifest.version, `${c.manifest.version} vs ${t.manifest.version}`);
  }
  if (o.expect) check(`matches --expect ${o.expect}`, o.expect === c.digest || o.expect === c.manifest.version || (o.expect.length >= 12 && c.digest.startsWith(o.expect)));
  return {
    dir: c.dir,
    name: c.manifest.name,
    version: c.manifest.version,
    digest: c.digest,
    test_build: c.info?.test_build ?? null,
    description_test_build: /^TEST BUILD/.test(String(c.manifest.description ?? "")),
    source: c.info?.source ?? null,
    built_at: c.info?.built_at ?? null,
    launch_argv: c.info?.launch_argv ?? null,
    files: c.files.length,
    host_markers: c.markers,
    against,
    checks,
    ok: checks.every((x) => x.ok),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const o = parse(process.argv.slice(2));
    const r = verify(o);
    if (o.json) process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    else {
      process.stdout.write(`${r.dir}\n  ${r.name} ${r.version}${r.test_build ? " (TEST BUILD)" : ""}; content digest ${r.digest}; ${r.files} files; source ${r.source?.commit ?? "unknown"}${r.source?.dirty ? " (uncommitted changes)" : ""}; built ${r.built_at ?? "?"}\n`);
      if (r.host_markers.length) process.stdout.write(`  host bookkeeping (not content): ${r.host_markers.join(", ")}\n`);
      for (const x of r.checks) process.stdout.write(`  ${x.ok ? "ok  " : "FAIL"} ${x.name}${x.detail && !x.ok ? `: ${x.detail}` : ""}\n`);
      process.stdout.write(r.ok ? "VERIFIED\n" : "NOT VERIFIED\n");
    }
    process.exitCode = r.ok ? 0 : 1;
  } catch (e) {
    process.stderr.write(`verify-plugin: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  }
}
