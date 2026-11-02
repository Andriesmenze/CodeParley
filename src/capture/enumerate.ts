// Candidate enumeration and pre-read classification (plan §9.3 steps 1–3). Every list
// comes from the allowed git queries; no query reads working-tree content.

import { join } from "node:path";
import { CASE_INSENSITIVE_NAMES, PATH_RULES, SEGMENT_PROBLEM_LABEL, segmentProblem, validateGitRelativePath } from "../workspace/paths.js";
import { compileGlobs, matchesAny, type CompiledGlob } from "./globs.js";
import type { GitQuery } from "./git-query.js";
import { parseCheckAttr, parseLsFilesStage, parseLsTree, parsePathList, type IndexEntry, type TreeEntry } from "./git-parse.js";
import { compareUtf8 } from "./identity.js";

export interface Listing {
  /** Stage-0 index entries by path. */
  index: Map<string, IndexEntry>;
  /** Paths with unmerged (stage 1–3) entries. */
  unmerged: string[];
  /** Untracked, non-ignored files. */
  untracked: string[];
  /** Untracked nested repositories ("dir/" entries). */
  nestedRepos: string[];
  /** Ignored files matching the trusted context_include globs. */
  context: string[];
  /** Digest-able fingerprint of index + untracked listing, for stability re-checks. */
  fingerprint: string;
}

export async function listRepository(q: GitQuery, contextInclude: readonly CompiledGlob[]): Promise<Listing> {
  const stage = parseLsFilesStage(await q.text("ls-files", ["-z", "-v", "--stage", "--cached"]));
  const index = new Map<string, IndexEntry>();
  const unmerged: string[] = [];
  for (const e of stage) {
    if (e.stage !== 0) unmerged.push(e.path);
    else index.set(e.path, e);
  }
  const others = parsePathList(await q.text("ls-files", ["-z", "--others", "--exclude-standard"]));
  const untracked = others.filter((p) => !p.endsWith("/"));
  const nestedRepos = others.filter((p) => p.endsWith("/")).map((p) => p.slice(0, -1));
  let context: string[] = [];
  if (contextInclude.length > 0) {
    const ignored = parsePathList(await q.text("ls-files", ["-z", "--others", "--ignored", "--exclude-standard"]));
    context = ignored.filter((p) => !p.endsWith("/") && matchesAny(contextInclude, p));
  }
  const fingerprint = JSON.stringify([
    stage.map((e) => [e.path, e.mode, e.oid, e.stage, e.assumeUnchanged, e.skipWorktree]),
    others,
  ]);
  return { index, unmerged: [...new Set(unmerged)], untracked, nestedRepos, context, fingerprint };
}

/** Full recursive tree listing of a commit: path -> entry (blobs and gitlinks). */
export async function listTree(q: GitQuery, commit: string): Promise<Map<string, TreeEntry>> {
  const out = new Map<string, TreeEntry>();
  for (const e of parseLsTree(await q.text("ls-tree", ["-r", "-z", "-l", "--full-tree", commit]))) {
    if (e.type !== "tree") out.set(e.path, e);
  }
  return out;
}

export interface PathAttributes {
  filter: string | null;
  workingTreeEncoding: string | null;
  text: string;
  eol: string;
  crlf: string;
}

const ATTRS = ["filter", "working-tree-encoding", "text", "eol", "crlf"] as const;

/** `check-attr` for all paths (attributes are data; check-attr runs no driver). */
export async function readAttributes(q: GitQuery, paths: readonly string[]): Promise<Map<string, PathAttributes>> {
  const result = new Map<string, PathAttributes>();
  if (paths.length === 0) return result;
  const stdin = paths.map((p) => `${p}\0`).join("");
  const parsed = parseCheckAttr(await q.text("check-attr", ["-z", "--stdin", ...ATTRS], { stdin }));
  for (const p of paths) {
    const a = parsed.get(p) ?? {};
    const val = (k: string) => a[k] ?? "unspecified";
    const filter = val("filter");
    const wte = val("working-tree-encoding");
    result.set(p, {
      filter: filter === "unspecified" || filter === "unset" ? null : filter,
      workingTreeEncoding: wte === "unspecified" || wte === "unset" ? null : wte,
      text: val("text"),
      eol: val("eol"),
      crlf: val("crlf"),
    });
  }
  return result;
}

/** Why a git-reported path cannot be captured on this platform, or null. */
export function pathProblem(rel: string): string | null {
  try {
    validateGitRelativePath(rel);
  } catch {
    return "invalid_git_path";
  }
  for (const seg of rel.split("/")) {
    const p = segmentProblem(seg);
    if (p) return `${SEGMENT_PROBLEM_LABEL}: ${p}`;
    if (looksLikeShortName(seg)) return "windows_name: possible 8.3 short-name alias";
  }
  return null;
}

/**
 * A segment shaped like an 8.3 short name (`GIT~1`, `PROGRA~1.TXT`) may resolve to a
 * DIFFERENT existing directory entry on NTFS — `GIT~1` can name `.git`. Such paths are never
 * read or written by capture on Windows (reads are also guarded by the realpath check in
 * safe-read.ts). Linux file systems supported for capture have no short names
 * (workspace/fs-types.ts refuses NTFS, FAT and drvfs mounts), so the rule is Windows-only.
 */
export function looksLikeShortName(seg: string): boolean {
  return PATH_RULES === "win32" && /^[^.~]{1,6}~\d{1,6}(\.[^.]{0,3})?$/.test(seg);
}

export function absolutePath(root: string, rel: string): string {
  return join(root, ...rel.split("/"));
}

/**
 * Paths sharing a case-insensitive spelling with an earlier path (NTFS maps them to one file).
 * None on Linux: the supported file systems are case-sensitive, so `README` and `readme` are
 * two files and both are captured.
 */
export function caseCollisions(paths: readonly string[]): Set<string> {
  if (!CASE_INSENSITIVE_NAMES) return new Set();
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const p of [...paths].sort(compareUtf8)) {
    const k = p.toLowerCase();
    if (seen.has(k)) dup.add(p);
    else seen.add(k);
  }
  return dup;
}

export { compileGlobs, matchesAny };
