// Prepared review diff (plan §9.6, D-30, G9).
//
// `git diff --no-index --no-ext-diff --no-textconv --no-color -M --ignore-cr-at-eol`
// between the export's own `review/base` and `review/head` copies — never inside the
// source repository. Configuration is fully isolated: no system config, an empty global
// config file, an empty HOME/XDG_CONFIG_HOME, no system attributes, discovery stopped by
// GIT_CEILING_DIRECTORIES, an empty hooks directory. With no configuration there is no
// driver to run, and the flags disable drivers anyway.
//
// Paths are rewritten to repository-relative `a/<path>` / `b/<path>` using random
// per-diff prefixes (`--src-prefix`/`--dst-prefix`) that are checked not to occur in
// any path, so the rewrite cannot touch file content or path text. Per-file and total
// caps apply; binary files are listed only. Exit code 1 means "differences found".
// EOL-only changes produce no output here (by design); their facts come from full raw
// bytes (eol.ts, MR-I), never from this patch.

import { randomBytes } from "node:crypto";
import { dirname } from "node:path";
import { runProcess } from "../process/spawn.js";
import { buildChildEnv } from "../process/env.js";
import { PROTECTED_HARDENING } from "./git-query.js";

export interface PreparedDiffOptions {
  gitExe: string;
  /** The export's review directory containing `base/` and `head/`. */
  reviewDir: string;
  emptyHomeDir: string;
  emptyGlobalConfig: string;
  emptyHooksDir: string;
  maxDiffBytes: number;
  /** All repository-relative paths present under base/ and head/ (for prefix collision checks). */
  allPaths: readonly string[];
  signal?: AbortSignal;
  /** P3.4C-5 (§A.4): the helper's per-invocation hardening (git-query.ts PROTECTED_HARDENING). */
  hardened?: boolean;
}

export interface DiffNameStatus {
  status: string; // A, D, M, R<score>, T, ...
  path: string; // repository-relative (new path for renames)
  oldPath?: string;
}

export interface DiffSection {
  path: string;
  oldPath?: string;
  state: "included" | "truncated" | "omitted" | "binary";
}

export interface PreparedDiffResult {
  ok: boolean;
  error?: string;
  /** Rewritten, capped patch body (without the header notes added by the caller). */
  patch: string;
  nameStatus: DiffNameStatus[];
  sections: DiffSection[];
  /** False if sections could not be matched one-to-one with name-status entries. */
  sectionsMapped: boolean;
  totalBytesBeforeCaps: number;
}

export function isolatedDiffEnv(o: Pick<PreparedDiffOptions, "reviewDir" | "emptyHomeDir" | "emptyGlobalConfig">): Record<string, string> {
  const base = buildChildEnv().env;
  // Drop every variable git could use to locate the real user's configuration.
  for (const k of ["USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA"]) delete base[k];
  return {
    ...base,
    HOME: o.emptyHomeDir,
    XDG_CONFIG_HOME: o.emptyHomeDir,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: o.emptyGlobalConfig,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CEILING_DIRECTORIES: dirname(o.reviewDir),
    GIT_OPTIONAL_LOCKS: "0",
    GIT_NO_LAZY_FETCH: "1",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
  };
}

export function isolatedDiffArgv(emptyHooksDir: string, extra: readonly string[], hardened = false): string[] {
  return [
    "--no-pager",
    ...(hardened ? PROTECTED_HARDENING.flatMap((kv) => ["-c", kv]) : []),
    "-c",
    "core.quotepath=false",
    "-c",
    "core.fsmonitor=false",
    "-c",
    `core.hooksPath=${emptyHooksDir}`,
    "-c",
    "color.ui=false",
    "-c",
    "core.longpaths=true",
    "diff",
    "--no-index",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "-M",
    "--ignore-cr-at-eol",
    ...extra,
    "--",
    "base",
    "head",
  ];
}

export async function runPreparedDiff(o: PreparedDiffOptions): Promise<PreparedDiffResult> {
  const env = isolatedDiffEnv(o);
  const empty: PreparedDiffResult = { ok: true, patch: "", nameStatus: [], sections: [], sectionsMapped: true, totalBytesBeforeCaps: 0 };

  // Name-status first (also tells us about renames for the change set).
  const ns = await runProcess(o.gitExe, isolatedDiffArgv(o.emptyHooksDir, ["--name-status", "-z"], o.hardened), {
    cwd: o.reviewDir,
    env,
    wallMs: 120_000,
    ...(o.signal ? { signal: o.signal } : {}),
  });
  if (ns.spawnError || (ns.status !== 0 && ns.status !== 1)) {
    return { ...empty, ok: false, error: ns.spawnError ?? `git diff --name-status exited ${String(ns.status)}: ${ns.stderr.trim()}` };
  }
  const nameStatus = parseNameStatusZ(ns.stdout);
  if (nameStatus.length === 0) return empty;

  let nonce = "";
  for (let i = 0; i < 5 && !nonce; i++) {
    const n = `arl${randomBytes(8).toString("hex")}`;
    if (!o.allPaths.some((p) => p.includes(n))) nonce = n;
  }
  if (!nonce) return { ...empty, ok: false, error: "could not choose a unique diff prefix" };
  const A = `${nonce}A/`;
  const B = `${nonce}B/`;

  const pr = await runProcess(o.gitExe, isolatedDiffArgv(o.emptyHooksDir, [`--src-prefix=${A}`, `--dst-prefix=${B}`], o.hardened), {
    cwd: o.reviewDir,
    env,
    wallMs: 120_000,
    maxStdoutBytes: 256 * 1024 * 1024,
    ...(o.signal ? { signal: o.signal } : {}),
  });
  if (pr.spawnError || (pr.status !== 0 && pr.status !== 1) || pr.stdoutTruncated) {
    return { ...empty, nameStatus, ok: false, error: pr.spawnError ?? `git diff exited ${String(pr.status)}: ${pr.stderr.trim()}` };
  }

  const rewritten = rewritePatch(pr.stdout, A, B);
  const rawSections = splitSections(rewritten);
  // Sections and name-status entries are in the same order, but git prints NO section for a
  // file whose only change is hidden by --ignore-cr-at-eol (observed with git 2.43 on Linux), so
  // the two lists are aligned by each section's exact header rather than by index.
  const alignment = alignSections(rawSections, nameStatus);
  const sectionsMapped = alignment !== null;

  const perFileCap = Math.max(4096, Math.floor(o.maxDiffBytes / 4));
  let total = 0;
  const outParts: string[] = [];
  const sections: DiffSection[] = [];
  const omitted: string[] = [];
  rawSections.forEach((text, i) => {
    const ns_ = alignment ? nameStatus[alignment[i]!]! : { status: "?", path: `section-${i + 1}` };
    const meta = { path: ns_.path, ...(ns_.oldPath ? { oldPath: ns_.oldPath } : {}) };
    const isBinary = /^Binary files .* differ$/m.test(text);
    let body = text;
    let state: DiffSection["state"] = isBinary ? "binary" : "included";
    if (Buffer.byteLength(body, "utf8") > perFileCap) {
      body = truncateAtLine(body, perFileCap) + `[code-parley: diff for this file truncated at ${perFileCap} bytes; full copies are in review/base and review/head]\n`;
      state = "truncated";
    }
    const len = Buffer.byteLength(body, "utf8");
    if (total + len > o.maxDiffBytes) {
      sections.push({ ...meta, state: "omitted" });
      omitted.push(meta.path);
      return;
    }
    total += len;
    outParts.push(body);
    sections.push({ ...meta, state });
  });
  if (omitted.length > 0) {
    outParts.push(`[code-parley: ${omitted.length} file diff(s) omitted (total diff cap ${o.maxDiffBytes} bytes): ${omitted.join(", ")}]\n`);
  }
  return {
    ok: true,
    patch: outParts.join(""),
    nameStatus,
    sections,
    sectionsMapped,
    totalBytesBeforeCaps: Buffer.byteLength(rewritten, "utf8"),
  };
}

/** Parse `--name-status -z` from `base`/`head` and strip the side prefix. */
export function parseNameStatusZ(out: string): DiffNameStatus[] {
  const parts = out.split("\0");
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  const res: DiffNameStatus[] = [];
  for (let i = 0; i < parts.length; ) {
    const status = parts[i++]!;
    if (/^[RC]/.test(status)) {
      const from = stripSide(parts[i++]!);
      const to = stripSide(parts[i++]!);
      res.push({ status, path: to, oldPath: from });
    } else {
      res.push({ status, path: stripSide(parts[i++]!) });
    }
  }
  return res;
}

function stripSide(p: string): string {
  return p.replace(/^(base|head)\//, "");
}

/** Rewrite prefixes to repository-relative a/ b/ and strip base/ head/ from rename lines. */
export function rewritePatch(patch: string, A: string, B: string): string {
  const lines = patch.split("\n");
  for (let i = 0; i < lines.length; i++) {
    let l = lines[i]!;
    if (l.includes(A) || l.includes(B)) {
      l = l.split(`${A}base/`).join("a/").split(`${A}head/`).join("a/").split(`${B}head/`).join("b/").split(`${B}base/`).join("b/");
    }
    const m = /^(rename from |rename to |copy from |copy to )("?)(base|head)\/(.*)$/.exec(l);
    if (m) l = `${m[1]}${m[2]}${m[4]}`;
    lines[i] = l;
  }
  return lines.join("\n");
}

function splitSections(patch: string): string[] {
  if (!patch) return [];
  const out: string[] = [];
  const lines = patch.split(/(?<=\n)/);
  let cur = "";
  for (const l of lines) {
    if (l.startsWith("diff --git ") && cur) {
      out.push(cur);
      cur = "";
    }
    cur += l;
  }
  if (cur) out.push(cur);
  return out;
}

/**
 * The name-status entry each section belongs to (index per section, in order), or null when
 * the sections cannot be matched one-to-one. Entries without a section (a change hidden by
 * --ignore-cr-at-eol) are skipped; a section must match its entry's header exactly.
 */
export function alignSections(sections: readonly string[], nameStatus: readonly DiffNameStatus[]): number[] | null {
  const out: number[] = [];
  let j = 0;
  for (const s of sections) {
    while (j < nameStatus.length && !sectionIs(s, nameStatus[j]!)) j++;
    if (j === nameStatus.length) return null;
    out.push(j++);
  }
  return out;
}

/** Is `section`'s `diff --git` header exactly the one git writes for `ns` (plain or C-quoted paths)? */
function sectionIs(section: string, ns: DiffNameStatus): boolean {
  const header = section.slice(0, section.indexOf("\n") >= 0 ? section.indexOf("\n") : section.length).replace(/\r$/, "");
  const from = ns.oldPath ?? ns.path;
  const side = (prefix: "a" | "b", p: string) => [`${prefix}/${p}`, `"${prefix}/${quoteC(p)}"`];
  for (const a of side("a", from)) for (const b of side("b", ns.path)) if (header === `diff --git ${a} ${b}`) return true;
  return false;
}

function quoteC(p: string): string {
  return JSON.stringify(p).slice(1, -1);
}

function truncateAtLine(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) return text;
  let cut = buf.lastIndexOf(0x0a, maxBytes - 1);
  if (cut < 0) cut = maxBytes;
  // Never cut inside a UTF-8 sequence.
  let s = buf.subarray(0, cut + 1).toString("utf8");
  if (s.endsWith("�")) s = s.slice(0, -1);
  return s.endsWith("\n") ? s : s + "\n";
}
