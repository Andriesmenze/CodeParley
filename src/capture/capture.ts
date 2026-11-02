// Source capture and sanitized review export (plan §9, §10.1; MR-A, MR-B, MR-F, MR-I).
//
// Pipeline (all under the per-worktree lock, kind "capture", plan §14.4):
//  1. Inspect the repository and refuse unsupported states (repo-support.ts).
//  2. Enumerate candidates from the index, the untracked listing and selected ignored
//     context (no query reads file content; MR-A).
//  3. Read attributes (data only) and neutralize every filter name seen.
//  4. Pass 1: classify each path BEFORE reading content (confidential exclusions first),
//     then read it safely and hash the raw bytes (sha256 + git blob id).
//  5. Change set: compare raw-byte blob ids with the target's base tree (no status/diff).
//  6. Dispositions: confidential, repository-context, export cap.
//  7. Pass 2 (review): re-read every exported file, hashing exactly the bytes written
//     into the export (MR-B); a difference from pass 1 marks the capture unstable.
//     Base versions of changed files come from raw `cat-file --batch` (never for
//     confidential paths). EOL facts come from full raw bytes (MR-I).
//  8. Prepared diff in isolation; model-facing manifest with counts only for
//     confidential and repository-context exclusions (MR-F); publish in one rename.
//  9. Re-list the repository: any change since step 2 marks the capture unstable.
// The source repository is never written: no index, refs, objects, config or LFS store.

import { existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { DomainError } from "../common/errors.js";
import { sha256OfBytes, sha256OfCanonicalJson, sha256OfString } from "../common/hash.js";
import { acquireWorktreeLock, acquireWorktreeLockWaiting, type LockDeps, type WorktreeLockHandle } from "../store/locks.js";
import type { OwnerRecord } from "../store/owner.js";
import { canonicalPathKey, worktreeLockPath, type RunPaths } from "../store/paths.js";
import { publishArtifact } from "../store/artifacts.js";
import { canonicalizePath, PATH_RULES, samePath } from "../workspace/paths.js";
import { firstLinkComponent } from "../workspace/links.js";
import {
  CaptureRecordSchema,
  BaselineRecordSchema,
  ReviewManifestSchema,
  type BaselineEntry,
  type BaselineRecord,
  type CaptureRecord,
  type CaptureRules,
  type ChangeEntry,
  type ReviewManifest,
  type ReviewTarget,
  type SourceEntry,
  type TargetBase,
} from "../schemas/capture.js";
import { chooseRepoPreferences, parseRepoPreferences } from "../schemas/repo-preferences.js";
import { compareEol, gitNormalizes, isBinaryStats, normalizeCrlf, type EolStats } from "./eol.js";
import { emptyTreeOid, gitBlobOid, parseLfsPointer } from "./git-object.js";
import { GitQuery, GitQueryFailed, type ProtectedGitConfig } from "./git-query.js";
import { isHexOid, type GitSubcommand } from "./git-args.js";
import { parseCatFileBatch, parseCatFileBatchCheck, type IndexEntry } from "./git-parse.js";
import { inspectRepository, type RepoState } from "./repo-support.js";
import {
  absolutePath,
  caseCollisions,
  compileGlobs,
  listRepository,
  listTree,
  matchesAny,
  pathProblem,
  readAttributes,
  type Listing,
  type PathAttributes,
} from "./enumerate.js";
import type { CompiledGlob } from "./globs.js";
import { readWorkingFile, type ReadResult } from "./safe-read.js";
import { computeSourceId, compareUtf8 } from "./identity.js";
import { StagedExport, exportPathProblem, type ExportSink } from "./export-writer.js";
import { runPreparedDiff, type PreparedDiffResult } from "./prepared-diff.js";
import { assertNoWithheldLeak, buildLimitations, finalizeManifest, withheldPaths } from "./manifest.js";

export interface CaptureRulesInput {
  exclude_globs: readonly string[];
  context_include: readonly string[];
  max_file_bytes: number;
  max_export_bytes: number;
  max_diff_bytes: number;
}

export interface CaptureLockOptions {
  dataHome: string;
  owner: OwnerRecord;
  deps?: LockDeps;
}

export interface CaptureTestHooks {
  /** After attributes were read (MR-A acceptance: change .gitattributes/config here). */
  afterAttributeScan?: () => Promise<void> | void;
  /** After pass 1, before pass 2 (staleness tests: edit a file here). */
  afterFirstPass?: () => Promise<void> | void;
  onGitQuery?: (sub: GitSubcommand, args: readonly string[]) => void;
}

export interface LoadedBaseline {
  record: BaselineRecord;
  /** The published baseline directory (contains files/ and baseline.json). */
  dir: string;
}

export interface CaptureOptions {
  kind: "review" | "baseline";
  /** Canonical repository root (from scope resolution, plan §8.2). */
  repoRoot: string;
  gitExe: string;
  target: ReviewTarget;
  rules: CaptureRulesInput;
  runPaths: RunPaths;
  /** The capture's operation id; also the export/baseline directory name. */
  operationId: string;
  lock: CaptureLockOptions;
  /** Required for target since_baseline. */
  baseline?: LoadedBaseline;
  signal?: AbortSignal;
  /** fsync every exported file before publication (default true, plan §15.3). */
  fsync?: boolean;
  testHooks?: CaptureTestHooks;
  /** TEST ONLY: environment overrides for source queries (hostile global/system config). */
  gitEnvOverrides?: Record<string, string>;
}

export interface CaptureResult {
  record: CaptureRecord;
  /** Run-relative reference of the local capture record artifact. */
  recordRef: string;
  exportDir: string | null;
  manifest: ReviewManifest | null;
  baselineDir: string | null;
  baseline: BaselineRecord | null;
}

export interface SourceIdentityOptions {
  repoRoot: string;
  gitExe: string;
  rules: CaptureRulesInput;
  lock: CaptureLockOptions;
  operationId: string;
  /**
   * The caller already holds this repository's worktree lock (a check operation holds it,
   * kind "checks", for its whole duration, plan §14.4). The read runs under it instead of
   * acquiring a capture lock; the handle must still be valid.
   */
  heldLock?: WorktreeLockHandle;
  /**
   * The read is a step of an operation (a review's completion check), not an observer: like a
   * capture it waits for a bounded read holding the lock, up to 30 s, reads stand aside for it,
   * and `signal` ends the wait. Without it the read is a bounded observer (status, freshness):
   * it never waits and stands aside while an operation waits (D-31).
   */
  operationStep?: boolean;
  signal?: AbortSignal;
  testHooks?: CaptureTestHooks;
  gitEnvOverrides?: Record<string, string>;
}

export interface SourceIdentityResult {
  source_id: string;
  entries: SourceEntry[];
  stable: boolean;
  instability: { path: string; reason: string }[];
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/** Capture the working tree under the worktree lock; produce a review export or a baseline. */
export async function runCapture(opts: CaptureOptions): Promise<CaptureResult> {
  if (opts.kind === "baseline" && opts.target.kind !== "uncommitted") {
    throw new DomainError("INVALID_ARGUMENT", "a baseline capture uses the uncommitted target");
  }
  if (opts.target.kind === "since_baseline" && !opts.baseline) {
    throw new DomainError("BASE_UNAVAILABLE", "target since_baseline needs the run's baseline capture");
  }
  // A capture runs inside an operation (a review, a baseline capture): it waits for a bounded
  // read or capture holding the lock, up to 30 s, and stops waiting when the operation is
  // cancelled (D-31).
  return withCaptureLock(opts.repoRoot, opts.lock, opts.operationId, undefined, opts.signal ? { signal: opts.signal } : {}, () =>
    withScratch(join(opts.lock.dataHome, "tmp"), (scratch) => captureLocked(opts, scratch, diskIo(opts))),
  );
}

/** The custodian helper's read-only per-request directories (P3.4C-5): the custodian creates them, the helper reads them. */
export interface HelperScratch {
  hooks: string;
  home: string;
  gitconfig: string;
}

export interface HelperCaptureOptions {
  /** The repository the custodian validated (its canonical path). */
  repoRoot: string;
  /** The approved runtime's git. */
  gitExe: string;
  target: ReviewTarget;
  rules: CaptureRulesInput;
  operationId: string;
  /** Streams the export to the custodian; nothing is written locally. */
  sink: ExportSink;
  scratch: HelperScratch;
  protectedGit: ProtectedGitConfig;
  signal?: AbortSignal;
}

export interface HelperCaptureResult {
  record: CaptureRecord;
  manifest: ReviewManifest;
  /** The helper's own digest over what it streamed (the custodian computes and decides with its own). */
  exportDigest: string;
}

/**
 * P3.4C-5 (Amendment A §A.7): the SAME sanitizing review capture as {@link runCapture} — inspection, enumeration,
 * attributes, both passes, change detection, base blobs, head copies, EOL facts, the prepared diff, the manifest and the
 * stability re-check — run by the custodian's helper, which may write nothing: no worktree lock (the custodian
 * serializes a run's operations), no scratch it creates (the custodian provides read-only directories), the export
 * streamed to the custodian through `sink` (whose staging the prepared diff then reads), and the capture record
 * returned instead of published. Git runs with the protected configuration of §A.4. Review captures of the uncommitted
 * or base-ref targets only (a baseline capture and since_baseline are later increments).
 */
export async function runHelperCapture(o: HelperCaptureOptions): Promise<HelperCaptureResult> {
  if (o.target.kind === "since_baseline") throw new DomainError("INVALID_ARGUMENT", "the helper capture does not take since_baseline yet");
  let digest = "";
  const io: CaptureIo = {
    reviewSink: async () => o.sink,
    baselineSink: async () => {
      throw new DomainError("INVALID_ARGUMENT", "the helper capture takes review captures only");
    },
    exportRef: () => "custodian-published",
    publishRecord: async () => "custodian-held",
    protectedGit: o.protectedGit,
    hardenedDiff: true,
    onExportDigest: (d) => (digest = d),
  };
  const core: CaptureCore = { kind: "review", repoRoot: o.repoRoot, gitExe: o.gitExe, target: o.target, rules: o.rules, operationId: o.operationId, ...(o.signal ? { signal: o.signal } : {}) };
  const r = await captureLocked(core, { root: "", ...o.scratch }, io);
  if (!r.manifest) throw new DomainError("INTERNAL", "the helper capture produced no manifest");
  return { record: r.record, manifest: r.manifest, exportDigest: digest };
}

/** P3.4C-5: the derivation's source-identity read by the custodian's helper — {@link computeSourceIdentity}'s read with no
 * lock and no scratch of its own (read-only custodian directories) and the protected git configuration. */
export async function computeHelperSourceIdentity(o: { repoRoot: string; gitExe: string; rules: CaptureRulesInput; scratch: HelperScratch; protectedGit: ProtectedGitConfig; signal?: AbortSignal }): Promise<SourceIdentityResult> {
  const s = await openSession({ repoRoot: o.repoRoot, gitExe: o.gitExe, rules: o.rules, protectedGit: o.protectedGit, ...(o.signal ? { signal: o.signal } : {}) }, { root: "", ...o.scratch });
  await firstPass(s, o.rules);
  markRepoContext(s);
  const before = s.listing.fingerprint;
  const after = (await listRepository(s.q, s.contextGlobs)).fingerprint;
  if (after !== before) s.instability.push({ path: "<repository>", reason: "index_or_untracked_listing_changed" });
  const entries = sortedEntries(s);
  return { source_id: computeSourceId(entries), entries, stable: s.instability.length === 0, instability: s.instability };
}

/** Where a capture's output goes: the run's directories (attended and protected engine captures) or the custodian. */
interface CaptureIo {
  reviewSink(): Promise<ExportSink>;
  baselineSink(): Promise<ExportSink>;
  exportRef(sink: ExportSink): string;
  publishRecord(record: CaptureRecord): Promise<string>;
  protectedGit?: ProtectedGitConfig;
  hardenedDiff: boolean;
  onExportDigest?: (digest: string) => void;
}

type CaptureCore = Omit<CaptureOptions, "runPaths" | "lock" | "fsync">;

function diskIo(opts: CaptureOptions): CaptureIo {
  return {
    reviewSink: async () => {
      const staged = new StagedExport(join(opts.runPaths.exportsDir, opts.operationId), opts.fsync ?? true);
      await mkdir(opts.runPaths.exportsDir, { recursive: true });
      return staged;
    },
    baselineSink: async () => {
      await mkdir(opts.runPaths.baselineDir, { recursive: true });
      return new StagedExport(join(opts.runPaths.baselineDir, opts.operationId), opts.fsync ?? true);
    },
    exportRef: (sink) => relRef(opts.runPaths.runDir, sink.finalDir),
    publishRecord: async (record) => (await publishArtifact(opts.runPaths.runDir, opts.runPaths.opsDir, opts.operationId, "capture.json", JSON.stringify(record, null, 2))).ref,
    hardenedDiff: false,
  };
}

/**
 * Recompute `source_id` with a full read of the working tree (plan §10.1: check start/end
 * identities, status recomputation). Same classification as a capture; nothing exported.
 */
export async function computeSourceIdentity(opts: SourceIdentityOptions): Promise<SourceIdentityResult> {
  const wait = opts.operationStep ? (opts.signal ? { signal: opts.signal } : {}) : null;
  return withCaptureLock(opts.repoRoot, opts.lock, opts.operationId, opts.heldLock, wait, () => {
    // Cancelled while the lock was obtained or verified: do not start reading the tree. The
    // read itself stops on `signal` too.
    checkAbort(opts.signal);
    return withScratch(join(opts.lock.dataHome, "tmp"), async (scratch) => {
      const s = await openSession(opts, scratch);
      await firstPass(s, opts.rules);
      markRepoContext(s);
      const before = s.listing.fingerprint;
      const after = (await listRepository(s.q, s.contextGlobs)).fingerprint;
      if (after !== before) s.instability.push({ path: "<repository>", reason: "index_or_untracked_listing_changed" });
      const entries = sortedEntries(s);
      return { source_id: computeSourceId(entries), entries, stable: s.instability.length === 0, instability: s.instability };
    });
  });
}

/** Load a published baseline (baseline/<id>/baseline.json), validated. */
export async function loadBaseline(dir: string): Promise<LoadedBaseline> {
  const record = BaselineRecordSchema.parse(JSON.parse(await readFile(join(dir, "baseline.json"), "utf8")));
  return { record, dir };
}

/** Validate a model-supplied base_ref before it reaches git (no options, ranges or paths). */
export function isValidRefSyntax(ref: string): boolean {
  return (
    ref.length > 0 &&
    ref.length <= 256 &&
    /^[A-Za-z0-9._/@{}~^-]+$/.test(ref) &&
    !ref.startsWith("-") &&
    !ref.includes("..") &&
    !ref.endsWith(".lock") &&
    !/(^|\/)\./.test(ref)
  );
}

// ---------------------------------------------------------------------------
// Session: repository inspection, listing, attributes, pass 1
// ---------------------------------------------------------------------------

interface Scratch {
  root: string;
  hooks: string;
  home: string;
  gitconfig: string;
}

interface Work {
  entry: SourceEntry;
  index: IndexEntry | undefined;
  attrs: PathAttributes;
  stats: EolStats | null;
  /** Blob id of the CRLF->LF normalized content (null when not computed). */
  normOid: string | null;
  submoduleCommit: string | null;
}

interface Session {
  q: GitQuery;
  protectedGit: ProtectedGitConfig | undefined;
  state: RepoState;
  root: string;
  gitExe: string;
  scratch: Scratch;
  listing: Listing;
  attrs: Map<string, PathAttributes>;
  excludeGlobs: CompiledGlob[];
  contextGlobs: CompiledGlob[];
  repoExcludeGlobs: CompiledGlob[];
  repoExcludePaths: string[];
  repoPreferenceWarnings: string[];
  works: Map<string, Work>;
  instability: { path: string; reason: string }[];
  linkCache: Map<string, boolean>;
  signal: AbortSignal | undefined;
  envOverrides: Record<string, string> | undefined;
  hooks: CaptureTestHooks | undefined;
  extraAttrPaths: string[];
}

async function openSession(
  opts: { repoRoot: string; gitExe: string; rules: CaptureRulesInput; signal?: AbortSignal; testHooks?: CaptureTestHooks; gitEnvOverrides?: Record<string, string>; protectedGit?: ProtectedGitConfig },
  scratch: Scratch,
  extraAttrPaths: readonly string[] = [],
): Promise<Session> {
  const root = opts.repoRoot.replace(/\\$/, "");
  const q = new GitQuery({
    gitExe: opts.gitExe,
    cwd: root,
    emptyHooksDir: scratch.hooks,
    ...(opts.protectedGit ? { protectedConfig: opts.protectedGit } : {}),
    ...(opts.gitEnvOverrides ? { envOverrides: opts.gitEnvOverrides } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.testHooks?.onGitQuery ? { onQuery: opts.testHooks.onGitQuery } : {}),
  });
  const state = await inspectRepository(q, root);
  q.setAttrSourceTree(emptyTreeOid(state.objectFormat));
  q.neutralizeFilters(state.configFilterNames);

  const contextGlobs = compileGlobs(opts.rules.context_include);
  const listing = await listRepository(q, contextGlobs);
  if (listing.unmerged.length > 0) {
    throw new DomainError("UNSUPPORTED_REPO_STATE", `the index has unmerged entries (merge or rebase conflict): ${listing.unmerged.slice(0, 5).join(", ")}`, {
      details: { reasons: ["unmerged_entries"], count: listing.unmerged.length },
    });
  }
  const s: Session = {
    q,
    protectedGit: opts.protectedGit,
    state,
    root,
    gitExe: opts.gitExe,
    scratch,
    listing,
    attrs: new Map(),
    excludeGlobs: compileGlobs(opts.rules.exclude_globs),
    contextGlobs,
    repoExcludeGlobs: [],
    repoExcludePaths: [],
    repoPreferenceWarnings: [],
    works: new Map(),
    instability: [],
    linkCache: new Map(),
    signal: opts.signal,
    envOverrides: opts.gitEnvOverrides,
    hooks: opts.testHooks,
    extraAttrPaths: [...extraAttrPaths],
  };
  return s;
}

function treeCandidates(s: Session): string[] {
  return [...new Set([...s.listing.index.keys(), ...s.listing.untracked])].sort(compareUtf8);
}

async function scanAttributes(s: Session): Promise<void> {
  const paths = [...new Set([...treeCandidates(s), ...s.listing.context, ...s.extraAttrPaths])].filter((p) => !/[\0\n]/.test(p));
  s.attrs = await readAttributes(s.q, paths);
  s.q.neutralizeFilters([...s.attrs.values()].map((a) => a.filter).filter((f): f is string => !!f));
  await s.hooks?.afterAttributeScan?.();
}

async function loadRepoPreferences(s: Session): Promise<void> {
  // `.code-parley/config.json`, else the legacy `.ai-loop/config.json` (plan §1.12); a file
  // under a confidentiality exclusion is neither read nor named.
  const choice = chooseRepoPreferences(
    (p) => s.listing.index.has(p) || s.listing.untracked.includes(p),
    (p) => matchesAny(s.excludeGlobs, p),
  );
  s.repoPreferenceWarnings.push(...choice.warnings);
  const rel = choice.path;
  if (!rel) return;
  const r = await readWorkingFile(absolutePath(s.root, rel), {
    root: s.root,
    objectFormat: s.state.objectFormat,
    maxRetainBytes: 256 * 1024,
    retain: true,
    linkCache: s.linkCache,
  });
  if (r.kind !== "file" || !r.bytes) {
    s.repoPreferenceWarnings.push("repository preferences could not be read safely; ignored");
    return;
  }
  let json: unknown;
  try {
    json = JSON.parse(r.bytes.toString("utf8"));
  } catch {
    s.repoPreferenceWarnings.push("repository preferences are not valid JSON; ignored");
    return;
  }
  const parsed = parseRepoPreferences(json);
  s.repoPreferenceWarnings.push(...parsed.warnings);
  s.repoExcludePaths = parsed.prefs.review?.exclude_paths ?? [];
  s.repoExcludeGlobs = compileGlobs(s.repoExcludePaths);
}

const DEFAULT_ATTRS: PathAttributes = { filter: null, workingTreeEncoding: null, text: "unspecified", eol: "unspecified", crlf: "unspecified" };

async function firstPass(s: Session, rules: CaptureRulesInput): Promise<void> {
  await scanAttributes(s);
  await loadRepoPreferences(s);

  const tree = treeCandidates(s);
  const treeSet = new Set(tree);
  const context = s.listing.context.filter((p) => !treeSet.has(p)).sort(compareUtf8);
  const collisions = caseCollisions([...tree, ...context]);

  for (const nested of s.listing.nestedRepos) {
    s.works.set(nested, newWork(s, nested, "tree", undefined, matchesAny(s.excludeGlobs, nested) ? "excluded" : "path_unsupported", "nested_repository"));
  }

  const items = [...tree.map((p) => ({ path: p, area: "tree" as const })), ...context.map((p) => ({ path: p, area: "context" as const }))];
  await mapPool(items, 8, async ({ path, area }) => {
    checkAbort(s.signal);
    const w = await examine(s, rules, path, area, collisions.has(path));
    if (w) s.works.set(path, w);
  });
}

function newWork(s: Session, path: string, area: "tree" | "context", index: IndexEntry | undefined, cls: SourceEntry["class"], reason?: string): Work {
  const attrs = s.attrs.get(path) ?? DEFAULT_ATTRS;
  return {
    entry: {
      path,
      area,
      class: cls,
      disposition: "not_exported",
      ...(reason ? { reason } : {}),
      size: null,
      sha256: null,
      git_oid: null,
      tracked: !!index,
      ...(index ? { index_flags: { assume_unchanged: index.assumeUnchanged, skip_worktree: index.skipWorktree } } : {}),
      filter: attrs.filter,
      working_tree_encoding: attrs.workingTreeEncoding,
      git_eol_normalized: false,
    },
    index,
    attrs,
    stats: null,
    normOid: null,
    submoduleCommit: null,
  };
}

/** Classify (before reading) and read one candidate. Returns null if it is absent. */
async function examine(s: Session, rules: CaptureRulesInput, path: string, area: "tree" | "context", collision: boolean): Promise<Work | null> {
  const index = s.listing.index.get(path);
  const confidential = matchesAny(s.excludeGlobs, path);
  const problem = pathProblem(path) ?? (collision ? "case_collision" : null);
  if (problem) return newWork(s, path, area, index, confidential ? "excluded" : "path_unsupported", problem);

  if (index?.mode === "160000") {
    const w = newWork(s, path, area, index, confidential ? "excluded" : "submodule");
    const commit = await submoduleHead(s, path);
    w.submoduleCommit = commit ?? index.oid;
    if (!commit) w.entry.reason = "submodule_head_unknown";
    w.entry.sha256 = sha256OfString(w.submoduleCommit);
    w.entry.git_oid = w.submoduleCommit;
    return w;
  }

  const r = await readWorkingFile(absolutePath(s.root, path), {
    root: s.root,
    objectFormat: s.state.objectFormat,
    maxRetainBytes: rules.max_file_bytes,
    retain: true,
    linkCache: s.linkCache,
  });
  return workFromRead(s, rules, path, area, index, confidential, r);
}

function workFromRead(
  s: Session,
  rules: CaptureRulesInput,
  path: string,
  area: "tree" | "context",
  index: IndexEntry | undefined,
  confidential: boolean,
  r: ReadResult,
): Work | null {
  switch (r.kind) {
    case "missing":
      if (!index) s.instability.push({ path, reason: "vanished_during_capture" });
      return null;
    case "link": {
      const w = newWork(s, path, area, index, confidential ? "excluded" : "link_skipped", r.reason);
      w.entry.size = r.size ?? null;
      w.entry.sha256 = r.sha256 ?? r.linkTargetSha256 ?? null;
      // git records link targets with "/"; only Windows spells them with backslashes.
      const target = r.linkTarget === undefined ? undefined : PATH_RULES === "win32" ? r.linkTarget.replace(/\\/g, "/") : r.linkTarget;
      w.entry.git_oid = r.gitOid ?? (target !== undefined ? gitBlobOid(s.state.objectFormat, Buffer.from(target, "utf8")) : null);
      return w;
    }
    case "not_regular":
    case "alias":
      return newWork(s, path, area, index, confidential ? "excluded" : "path_unsupported", r.reason ?? r.kind);
    case "unstable":
      s.instability.push({ path, reason: `unstable_read:${r.reason ?? ""}` });
      return newWork(s, path, area, index, confidential ? "excluded" : "path_unsupported", "unstable_read");
    case "file": {
      let cls: SourceEntry["class"];
      let reason: string | undefined;
      if (index?.mode === "120000") {
        cls = confidential ? "excluded" : "link_skipped";
        reason = "git_symlink";
      } else if (confidential) cls = "excluded";
      else if ((r.size ?? 0) > rules.max_file_bytes) cls = "size_skipped";
      else cls = area === "context" ? "context" : "permitted";
      const w = newWork(s, path, area, index, cls, reason);
      applyRead(s, w, r);
      return w;
    }
  }
}

function applyRead(s: Session, w: Work, r: ReadResult): void {
  w.entry.size = r.size ?? null;
  w.entry.sha256 = r.sha256 ?? null;
  w.entry.git_oid = r.gitOid ?? null;
  w.stats = r.stats ?? null;
  if (r.bytes && r.stats) w.normOid = r.stats.crlf > 0 ? gitBlobOid(s.state.objectFormat, normalizeCrlf(r.bytes)) : (r.gitOid ?? null);
  else w.normOid = null;
  w.entry.git_eol_normalized = r.stats ? !isBinaryStats(r.stats) && gitNormalizes(w.attrs, s.state.autocrlf, r.stats) : false;
}

async function submoduleHead(s: Session, rel: string): Promise<string | null> {
  const abs = absolutePath(s.root, rel);
  if (await firstLinkComponent(abs, s.root, s.linkCache)) return null;
  if (!existsSync(join(abs, ".git"))) return null;
  const sq = new GitQuery({
    gitExe: s.gitExe,
    cwd: abs,
    emptyHooksDir: s.scratch.hooks,
    ...(s.protectedGit ? { protectedConfig: s.protectedGit } : {}),
    ...(s.envOverrides ? { envOverrides: s.envOverrides } : {}),
    ...(s.signal ? { signal: s.signal } : {}),
    ...(s.hooks?.onGitQuery ? { onQuery: s.hooks.onGitQuery } : {}),
  });
  sq.setAttrSourceTree(emptyTreeOid(s.state.objectFormat));
  sq.neutralizeFilters(s.q.neutralizedFilters());
  try {
    const lines = (await sq.text("rev-parse", ["--show-toplevel", "HEAD"])).split(/\r?\n/);
    const top = await canonicalizePath(lines[0] ?? "");
    if (!samePath(top, abs) || !isHexOid(lines[1] ?? "")) return null;
    return lines[1]!;
  } catch {
    return null;
  }
}

function sortedEntries(s: Session): SourceEntry[] {
  return [...s.works.values()].map((w) => w.entry).sort((a, b) => compareUtf8(a.path, b.path));
}

// ---------------------------------------------------------------------------
// Target base and change detection
// ---------------------------------------------------------------------------

interface BaseItem {
  path: string;
  mode: string | null;
  oid: string | null;
  size: number | null;
  source: "commit" | "baseline_copy" | "baseline_commit";
  /** since_baseline only. */
  sha256?: string | null;
  baselineEntry?: BaselineEntry;
}

interface ResolvedBase {
  base: TargetBase;
  items: Map<string, BaseItem>;
  /** base_ref only: HEAD tree, for committed/uncommitted flags. */
  headTree: Map<string, { oid: string }> | null;
}

async function resolveBase(s: Session, target: ReviewTarget, baseline: LoadedBaseline | undefined): Promise<ResolvedBase> {
  const fromTree = async (commit: string | null) => {
    const items = new Map<string, BaseItem>();
    if (!commit) return items;
    for (const e of (await listTree(s.q, commit)).values()) {
      items.set(e.path, { path: e.path, mode: e.mode, oid: e.oid, size: e.size, source: "commit" });
    }
    return items;
  };
  if (target.kind === "uncommitted") {
    const head = s.state.headCommit;
    return { base: { kind: head ? "commit" : "empty", commit: head, baseline_capture_id: null }, items: await fromTree(head), headTree: null };
  }
  if (target.kind === "base_ref") {
    if (!isValidRefSyntax(target.ref)) throw new DomainError("INVALID_ARGUMENT", `invalid base_ref: ${JSON.stringify(target.ref)}`);
    const head = s.state.headCommit;
    if (!head) throw new DomainError("BASE_UNAVAILABLE", "base_ref needs a HEAD commit (HEAD is unborn)");
    const resolved = (await s.q.text("rev-parse", ["--verify", "-q", "--end-of-options", `${target.ref}^{commit}`], { okCodes: [0, 1] })).trim();
    if (!isHexOid(resolved)) {
      throw new DomainError("BASE_UNAVAILABLE", `base_ref does not resolve to a commit: ${target.ref}${s.state.shallow ? " (shallow clone)" : ""}`, {
        details: { ref: target.ref, shallow: s.state.shallow },
      });
    }
    let mb: string;
    try {
      mb = (await s.q.text("merge-base", [resolved, head], { okCodes: [0, 1] })).trim();
    } catch (e) {
      if (e instanceof GitQueryFailed) mb = "";
      else throw e;
    }
    if (!isHexOid(mb)) {
      throw new DomainError("BASE_UNAVAILABLE", `no merge base between ${target.ref} and HEAD${s.state.shallow ? " (shallow clone)" : ""}`, {
        details: { ref: target.ref, shallow: s.state.shallow },
      });
    }
    const headTree = new Map<string, { oid: string }>();
    for (const e of (await listTree(s.q, head)).values()) headTree.set(e.path, { oid: e.oid });
    return { base: { kind: "commit", commit: mb, baseline_capture_id: null }, items: await fromTree(mb), headTree };
  }
  // since_baseline
  const rec = baseline!.record;
  if (rec.object_format !== s.state.objectFormat) throw new DomainError("BASE_UNAVAILABLE", "baseline object format does not match the repository");
  const items = new Map<string, BaseItem>();
  for (const e of rec.entries) {
    items.set(e.path, {
      path: e.path,
      mode: null,
      oid: e.git_oid,
      size: e.size,
      source: e.base === "copy" ? "baseline_copy" : "baseline_commit",
      sha256: e.sha256,
      baselineEntry: e,
    });
  }
  return { base: { kind: "baseline", commit: rec.head_commit, baseline_capture_id: rec.capture_id }, items, headTree: null };
}

type CompareOutcome = { kind: "none" } | { kind: "unchanged" } | { kind: "eol_equivalent" } | { kind: "skip_worktree_absent" } | { kind: "changed"; change: ChangeEntry };

interface CompareContext {
  s: Session;
  targetKind: ReviewTarget["kind"];
  headTree: Map<string, { oid: string }> | null;
  lfsPointers: Map<string, { sha256: string; size: number } | null>;
}

const LINKISH = new Set(["git_symlink", "symlink"]);

function compare(ctx: CompareContext, path: string, base: BaseItem | undefined, w: Work | undefined): CompareOutcome {
  const { s } = ctx;
  if (!base && !w) return { kind: "none" };
  const confidential = matchesAny(s.excludeGlobs, path);
  const mk = (status: ChangeEntry["status"], extra: Partial<ChangeEntry> = {}): CompareOutcome => {
    const headOid = ctx.headTree ? (ctx.headTree.get(path)?.oid ?? null) : null;
    const change: ChangeEntry = {
      path,
      status,
      confidential,
      class: w ? w.entry.class : "absent",
      base: base
        ? {
            oid: base.oid,
            mode: base.mode,
            size: base.size,
            source: base.source,
            available: false,
          }
        : null,
      current: w ? { sha256: w.entry.sha256, size: w.entry.size } : null,
      binary: null,
      eol: null,
      transformation_unsupported: false,
      change_uncertain: false,
      index_flag_hidden: !!(w?.index && (w.index.skipWorktree || w.index.assumeUnchanged)),
      committed: ctx.targetKind === "base_ref" ? (base?.oid ?? null) !== headOid : null,
      uncommitted: ctx.targetKind === "base_ref" ? headOid !== (w?.entry.git_oid ?? null) : ctx.targetKind === "uncommitted" ? true : null,
      in_export: { base: false, head: false },
      diff: "none",
      ...extra,
    };
    return { kind: "changed", change };
  };

  if (!w) {
    const idx = s.listing.index.get(path);
    if (idx?.skipWorktree) return { kind: "skip_worktree_absent" };
    return mk("deleted");
  }
  if (!base) return mk("added");

  if (ctx.targetKind === "since_baseline") {
    const be = base.baselineEntry!;
    if (w.entry.sha256 !== null && be.sha256 !== null && w.entry.sha256 === be.sha256) return { kind: "unchanged" };
    const wasLink = be.class === "link_skipped";
    const isLink = w.entry.class === "link_skipped";
    return mk(wasLink !== isLink ? "type_changed" : "modified", w.entry.sha256 === null || be.sha256 === null ? { change_uncertain: true } : {});
  }

  const baseIsGitlink = base.mode === "160000";
  const baseIsLink = base.mode === "120000";
  if (baseIsGitlink || w.entry.class === "submodule") {
    if (baseIsGitlink && w.entry.class === "submodule") return w.submoduleCommit === base.oid ? { kind: "unchanged" } : mk("modified");
    return mk("type_changed");
  }
  if (w.entry.class === "path_unsupported") return mk("modified", { change_uncertain: true });

  const curIsLinkish = w.entry.class === "link_skipped" ? LINKISH.has(w.entry.reason ?? "") : false;
  if (w.entry.class === "link_skipped" && !curIsLinkish && w.entry.reason !== "hard_link") {
    // A junction/reparse point (or a link in a parent directory) stands where git has a path.
    return mk("type_changed");
  }
  if (baseIsLink !== curIsLinkish) return mk("type_changed");
  if (w.entry.git_oid !== null && w.entry.git_oid === base.oid) return { kind: "unchanged" };
  if (baseIsLink) return mk("modified");

  const attrs = w.attrs;
  if (attrs.filter || attrs.workingTreeEncoding) {
    if (attrs.filter === "lfs" && !confidential && base.oid) {
      const ptr = ctx.lfsPointers.get(base.oid);
      if (ptr && ptr.sha256 === w.entry.sha256 && ptr.size === w.entry.size) return { kind: "unchanged" };
      return mk("modified", { transformation_unsupported: true, change_uncertain: !ptr });
    }
    return mk("modified", { transformation_unsupported: true, change_uncertain: true });
  }
  if (w.normOid !== null && w.normOid === base.oid && w.entry.git_eol_normalized) return { kind: "eol_equivalent" };
  return mk("modified");
}

interface ChangeSet {
  changes: Map<string, ChangeEntry>;
  eolEquivalent: Set<string>;
  skipWorktreeAbsent: string[];
}

function detectChanges(ctx: CompareContext, items: Map<string, BaseItem>): ChangeSet {
  const changes = new Map<string, ChangeEntry>();
  const eolEquivalent = new Set<string>();
  const skipWorktreeAbsent: string[] = [];
  const treeWorks = new Map([...ctx.s.works].filter(([, w]) => w.entry.area === "tree"));
  const paths = [...new Set([...items.keys(), ...treeWorks.keys()])].sort(compareUtf8);
  for (const p of paths) {
    const o = compare(ctx, p, items.get(p), treeWorks.get(p));
    if (o.kind === "changed") changes.set(p, o.change);
    else if (o.kind === "eol_equivalent") eolEquivalent.add(p);
    else if (o.kind === "skip_worktree_absent") skipWorktreeAbsent.push(p);
  }
  return { changes, eolEquivalent, skipWorktreeAbsent };
}

/** Blob ids of LFS pointers we may read (non-confidential, small, filter=lfs, raw differs). */
function lfsPointerOids(s: Session, items: Map<string, BaseItem>): string[] {
  const out = new Set<string>();
  for (const [p, w] of s.works) {
    const b = items.get(p);
    if (!b || b.source !== "commit" || !b.oid || b.mode === "160000" || b.mode === "120000") continue;
    if (w.attrs.filter !== "lfs" || w.entry.class === "excluded" || matchesAny(s.excludeGlobs, p)) continue;
    if (w.entry.git_oid === b.oid || (b.size ?? 0) > 1024) continue;
    out.add(b.oid);
  }
  return [...out];
}

/** Raw blobs via `cat-file --batch` (no --filters/--textconv), batched by size. Missing -> null. */
async function catFileBlobs(q: GitQuery, wanted: readonly { oid: string; size: number | null }[]): Promise<Map<string, Buffer | null>> {
  const result = new Map<string, Buffer | null>();
  let unique = [...new Map(wanted.map((w) => [w.oid, w])).values()];
  // Sizes unknown (e.g. partial clone, ls-tree printed "BAD"): ask batch-check first.
  const unknown = unique.filter((w) => w.size === null || !Number.isFinite(w.size)).map((w) => w.oid);
  if (unknown.length > 0) {
    const sizes = parseCatFileBatchCheck(await q.text("cat-file", ["--batch-check"], { stdin: unknown.join("\n") + "\n" }), unknown);
    for (const [oid, size] of sizes) if (size === null) result.set(oid, null);
    unique = unique
      .filter((w) => result.get(w.oid) !== null || !unknown.includes(w.oid))
      .map((w) => (unknown.includes(w.oid) ? { ...w, size: sizes.get(w.oid) ?? null } : w));
  }
  const LIMIT = 64 * 1024 * 1024;
  let batch: { oid: string; size: number | null }[] = [];
  let bytes = 0;
  const flush = async () => {
    if (batch.length === 0) return;
    const oids = batch.map((b) => b.oid);
    const r = await q.run("cat-file", ["--batch"], {
      stdin: oids.join("\n") + "\n",
      binary: true,
      maxStdoutBytes: bytes + oids.length * 160 + 1024 * 1024,
    });
    for (const o of parseCatFileBatch(r.stdoutBuffer ?? Buffer.alloc(0), oids)) result.set(o.oid, o.type === "blob" ? o.content : null);
    batch = [];
    bytes = 0;
  };
  for (const w of unique) {
    const sz = w.size ?? 0;
    if (batch.length > 0 && bytes + sz > LIMIT) await flush();
    batch.push(w);
    bytes += sz;
  }
  await flush();
  return result;
}

// ---------------------------------------------------------------------------
// The locked capture
// ---------------------------------------------------------------------------

async function captureLocked(opts: CaptureCore, scratch: Scratch, io: CaptureIo): Promise<CaptureResult> {
  const startedAt = new Date().toISOString();
  const timings: Record<string, number> = {};
  const t0 = Date.now();
  const mark = (k: string, since: number) => (timings[k] = Date.now() - since);
  const rules = opts.rules;

  const baselinePaths = opts.baseline ? opts.baseline.record.entries.map((e) => e.path) : [];
  const s = await openSession({ ...opts, ...(io.protectedGit ? { protectedGit: io.protectedGit } : {}) }, scratch, baselinePaths);
  mark("inspect_and_list", t0);

  let t = Date.now();
  const resolved = await resolveBase(s, opts.target, opts.baseline);
  // Attributes for base-only paths too (a deleted LFS file is still filter-managed).
  s.extraAttrPaths.push(...resolved.items.keys());
  mark("resolve_base", t);

  t = Date.now();
  await firstPass(s, rules);
  mark("first_pass", t);

  t = Date.now();
  const lfsOids = lfsPointerOids(s, resolved.items);
  const lfsBlobs = lfsOids.length ? await catFileBlobs(s.q, lfsOids.map((oid) => ({ oid, size: 1024 }))) : new Map<string, Buffer | null>();
  const lfsPointers = new Map<string, { sha256: string; size: number } | null>();
  for (const [oid, b] of lfsBlobs) lfsPointers.set(oid, b ? parseLfsPointer(b) : null);
  const ctx: CompareContext = { s, targetKind: opts.target.kind, headTree: resolved.headTree, lfsPointers };
  const cs = detectChanges(ctx, resolved.items);
  mark("change_detection", t);

  await opts.testHooks?.afterFirstPass?.();

  const out =
    opts.kind === "review"
      ? await reviewExport(opts, s, resolved, ctx, cs, timings, io)
      : await baselineExport(opts, s, cs, timings, io);

  // Stability re-check: the listing, HEAD and attributes must be as they were at the start.
  t = Date.now();
  try {
    const relist = await listRepository(s.q, s.contextGlobs);
    if (relist.fingerprint !== s.listing.fingerprint) s.instability.push({ path: "<repository>", reason: "index_or_untracked_listing_changed" });
    const headNow = (await s.q.text("rev-parse", ["--verify", "-q", "HEAD^{commit}"], { okCodes: [0, 1] })).trim() || null;
    if (headNow !== s.state.headCommit) s.instability.push({ path: "<repository>", reason: "head_moved" });
    // Attributes decide transformation flags; if they changed (e.g. .gitattributes edited
    // mid-capture) those flags may describe the old attributes. check-attr runs no driver.
    const attrsNow = await readAttributes(s.q, [...s.attrs.keys()]);
    const attrChanged = [...s.attrs].filter(([p, a]) => JSON.stringify(attrsNow.get(p)) !== JSON.stringify(a)).length;
    if (attrChanged > 0) s.instability.push({ path: "<attributes>", reason: `attributes_changed_for_${attrChanged}_paths` });
  } catch (e) {
    await out.staged.abort();
    throw e;
  }
  mark("stability_check", t);

  const entries = sortedEntries(s);
  const sourceId = computeSourceId(entries);
  const changes = [...cs.changes.values()].sort((a, b) => compareUtf8(a.path, b.path));
  const limitations = buildLimitations({
    entries,
    changes,
    instability: s.instability,
    skipWorktreeAbsent: cs.skipWorktreeAbsent,
    baseUnavailable: out.baseUnavailable,
    exportOverCap: out.exportOverCap,
    inProgress: s.state.inProgress,
    externalGitDir: s.state.externalGitDir,
    repoPreferenceWarnings: s.repoPreferenceWarnings,
    diffProblem: out.diffProblem,
  });

  const rulesRecord: CaptureRules = {
    exclude_globs: [...rules.exclude_globs],
    context_include: [...rules.context_include],
    repo_exclude_paths: s.repoExcludePaths,
    max_file_bytes: rules.max_file_bytes,
    max_export_bytes: rules.max_export_bytes,
    max_diff_bytes: rules.max_diff_bytes,
  };
  const rulesDigest = sha256OfCanonicalJson({ schema: "arl.capture-rules.v1", ...rulesRecord });

  // Publish the export / baseline (artifacts first, plan §15.3).
  let manifest: ReviewManifest | null = null;
  let exportInfo: CaptureRecord["export"] = null;
  let baselineInfo: CaptureRecord["baseline"] = null;
  let baselineRecord: BaselineRecord | null = null;
  try {
    if (out.kind === "review") {
      manifest = buildManifest({
        opts,
        s,
        resolved,
        sourceId,
        rulesDigest,
        entries,
        changes,
        eolEquivalent: [...cs.eolEquivalent].sort(compareUtf8),
        limitations: limitations.model,
        staged: out.staged,
        diffPatch: out.diffPatch,
      });
      await out.staged.write("review", "manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));
      const digest = out.staged.digest();
      io.onExportDigest?.(digest);
      await out.staged.publish();
      exportInfo = {
        ref: io.exportRef(out.staged),
        manifest_digest: manifest.manifest_digest,
        export_digest: digest,
        file_count: out.staged.files().length,
        total_bytes: out.staged.files().reduce((a, f) => a + f.size, 0),
      };
    } else {
      baselineRecord = BaselineRecordSchema.parse({
        schema: "arl.baseline.v1",
        capture_id: opts.operationId,
        object_format: s.state.objectFormat,
        head_commit: s.state.headCommit,
        source_id: sourceId,
        entries: out.baselineEntries,
      });
      await out.staged.writeRaw("baseline.json", Buffer.from(JSON.stringify(baselineRecord, null, 2), "utf8"));
      await out.staged.publish();
      baselineInfo = { ref: io.exportRef(out.staged), copied: out.copied };
    }
  } catch (e) {
    await out.staged.abort();
    throw e;
  }

  const record = CaptureRecordSchema.parse({
    schema: "arl.capture-record.v1",
    capture_id: opts.operationId,
    kind: opts.kind,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    repository: {
      root: s.root,
      git_dir: s.state.gitDir,
      common_dir: s.state.commonDir,
      head_commit: s.state.headCommit,
      branch: s.state.branch,
    },
    git: { exe: opts.gitExe, version: s.state.gitVersion.raw },
    target: opts.target,
    base: resolved.base,
    rules: rulesRecord,
    rules_digest: rulesDigest,
    support: {
      git_version: s.state.gitVersion.raw,
      object_format: s.state.objectFormat,
      unborn_head: s.state.headCommit === null,
      shallow: s.state.shallow,
      partial_clone: s.state.partialClone,
      linked_worktree: s.state.linkedWorktree,
      external_git_dir: s.state.externalGitDir,
      submodules: entries.filter((e) => e.class === "submodule").length,
      index_flags: {
        assume_unchanged: [...s.listing.index.values()].filter((e) => e.assumeUnchanged).length,
        skip_worktree: [...s.listing.index.values()].filter((e) => e.skipWorktree).length,
      },
      filters_in_use: [...new Set([...s.attrs.values()].map((a) => a.filter).filter((f): f is string => !!f))].sort(),
      transformation_unsupported: entries.filter((e) => e.filter || e.working_tree_encoding).length,
      in_progress: s.state.inProgress,
    },
    source_id: sourceId,
    entries,
    changes,
    eol_conversion_equivalent: [...cs.eolEquivalent].sort(compareUtf8),
    limitations: limitations.local,
    model_limitations: limitations.model,
    stable: s.instability.length === 0,
    instability: s.instability,
    neutralized_filters: s.q.neutralizedFilters(),
    export: exportInfo,
    baseline: baselineInfo,
    timings_ms: { ...timings, total: Date.now() - t0 },
  });
  const recordRef = await io.publishRecord(record);
  return {
    record,
    recordRef,
    exportDir: out.kind === "review" ? out.staged.finalDir : null,
    manifest,
    baselineDir: out.kind === "baseline" ? out.staged.finalDir : null,
    baseline: baselineRecord,
  };
}

// ---------------------------------------------------------------------------
// Review export (pass 2, base/head copies, prepared diff)
// ---------------------------------------------------------------------------

interface ReviewOut {
  kind: "review";
  staged: ExportSink;
  diffPatch: Buffer;
  baseUnavailable: { path: string; reason: string }[];
  exportOverCap: boolean;
  diffProblem: string | null;
}

interface BaselineOut {
  kind: "baseline";
  staged: ExportSink;
  baselineEntries: BaselineEntry[];
  copied: number;
  baseUnavailable: { path: string; reason: string }[];
  exportOverCap: false;
  diffProblem: null;
}

/**
 * A source read (no export): mark what a review export withholds as repository context — a
 * permitted or context file matching the repository's review.exclude_paths — so that the read's
 * host views withhold it too (Codex review of PR #10). An export exempts files under review
 * (assignDispositions); a read knows no change set, so it marks every match, and the views
 * exempt names a capture of the run exported as reviewed changes (engine/host-view.ts).
 * Dispositions are not part of the source identity.
 */
function markRepoContext(s: Session): void {
  for (const w of s.works.values()) {
    const e = w.entry;
    if ((e.class === "permitted" || e.class === "context") && matchesAny(s.repoExcludeGlobs, e.path)) e.disposition = "excluded_repo_context";
  }
}

function assignDispositions(s: Session, cs: ChangeSet, rules: CaptureRulesInput, applyCap: boolean): boolean {
  const changed = new Set<string>();
  for (const c of cs.changes.values()) {
    changed.add(c.path);
    if (c.old_path) changed.add(c.old_path);
  }
  const exported: Work[] = [];
  for (const w of s.works.values()) {
    const e = w.entry;
    if (e.class === "excluded") e.disposition = "excluded_confidential";
    else if (e.class === "permitted" || e.class === "context") {
      // Repository exclusions never apply to a changed file (plan §7.2).
      if (!changed.has(e.path) && matchesAny(s.repoExcludeGlobs, e.path)) e.disposition = "excluded_repo_context";
      else {
        e.disposition = "exported";
        exported.push(w);
      }
    } else e.disposition = "not_exported";
  }
  if (!applyCap) return false;
  const total = exported.reduce((a, w) => a + (w.entry.size ?? 0), 0);
  if (total <= rules.max_export_bytes) return false;
  // Keep changed files, files in the same directories, and context files (plan §9.3 step 4).
  const dirs = new Set([...changed].map((p) => dirOf(p)));
  let kept = 0;
  for (const w of exported) {
    const p = w.entry.path;
    if (changed.has(p) || w.entry.area === "context" || dirs.has(dirOf(p))) kept += w.entry.size ?? 0;
    else w.entry.disposition = "context_reduced";
  }
  return kept > rules.max_export_bytes;
}

function dirOf(p: string): string {
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}

async function reviewExport(
  opts: CaptureCore,
  s: Session,
  resolved: ResolvedBase,
  ctx: CompareContext,
  cs: ChangeSet,
  timings: Record<string, number>,
  io: CaptureIo,
): Promise<ReviewOut> {
  const rules = opts.rules;
  const exportOverCap = assignDispositions(s, cs, rules, true);
  const staged = await io.reviewSink();
  await staged.init(["tree", "context", "review/base", "review/head"]);
  const baseUnavailable: { path: string; reason: string }[] = [];
  try {
    // --- base copies for changed, non-confidential paths
    let t = Date.now();
    const baseWritten = new Set<string>();
    const exportBases = async (changes: ChangeEntry[]) => {
      const wantBlob: { oid: string; size: number | null; path: string }[] = [];
      for (const c of changes) {
        const b = c.base;
        if (!b || c.confidential || c.transformation_unsupported || baseWritten.has(c.path)) continue;
        if (b.mode === "160000" || b.mode === "120000") continue;
        if (exportPathProblem(c.path)) {
          baseUnavailable.push({ path: c.path, reason: "path_unsupported" });
          continue;
        }
        const item = resolved.items.get(c.path);
        if (item?.baselineEntry && item.baselineEntry.base === "unavailable") {
          baseUnavailable.push({ path: c.path, reason: `baseline_${item.baselineEntry.reason ?? item.baselineEntry.class}` });
          continue;
        }
        if ((b.size ?? 0) > rules.max_file_bytes) {
          baseUnavailable.push({ path: c.path, reason: "base_larger_than_max_file_bytes" });
          continue;
        }
        if (b.source === "baseline_copy") {
          const copy = join(opts.baseline!.dir, "files", ...c.path.split("/"));
          const bytes = await readFile(copy).catch(() => null);
          if (!bytes || sha256OfBytes(bytes) !== item?.sha256) {
            baseUnavailable.push({ path: c.path, reason: "baseline_copy_missing_or_corrupt" });
            continue;
          }
          if (await staged.write("review/base", c.path, bytes)) {
            baseWritten.add(c.path);
            b.available = true;
            c.in_export.base = true;
          } else baseUnavailable.push({ path: c.path, reason: "case_collision" });
          continue;
        }
        if (b.oid) wantBlob.push({ oid: b.oid, size: b.size, path: c.path });
      }
      if (wantBlob.length === 0) return;
      const blobs = await catFileBlobs(s.q, wantBlob);
      const missing = wantBlob.filter((w) => !blobs.get(w.oid));
      if (missing.length > 0) {
        throw new DomainError("BASE_UNAVAILABLE", `base blob(s) are missing from the object store${s.state.partialClone ? " (partial clone; lazy fetch is disabled)" : ""}`, {
          details: { count: missing.length, partial_clone: s.state.partialClone },
        });
      }
      for (const w of wantBlob) {
        const c = cs.changes.get(w.path)!;
        const blob = blobs.get(w.oid)!;
        if (blob.length > rules.max_file_bytes) {
          baseUnavailable.push({ path: w.path, reason: "base_larger_than_max_file_bytes" });
          continue;
        }
        if (await staged.write("review/base", w.path, blob)) {
          baseWritten.add(w.path);
          c.base!.available = true;
          c.in_export.base = true;
        } else baseUnavailable.push({ path: w.path, reason: "case_collision" });
      }
    };
    await exportBases([...cs.changes.values()]);
    timings["export_base"] = Date.now() - t;

    // --- pass 2: re-read and write exported files (hash = exported bytes, MR-B)
    t = Date.now();
    const exported = [...s.works.values()].filter((w) => w.entry.disposition === "exported").sort((a, b) => compareUtf8(a.entry.path, b.entry.path));
    const recheck: string[] = [];
    await mapPool(exported, 4, async (w) => {
      checkAbort(s.signal);
      const e = w.entry;
      const r = await readWorkingFile(absolutePath(s.root, e.path), {
        root: s.root,
        objectFormat: s.state.objectFormat,
        maxRetainBytes: rules.max_file_bytes,
        retain: true,
        linkCache: new Map(),
      });
      if (r.kind !== "file" || !r.bytes) {
        s.instability.push({ path: e.path, reason: `changed_between_passes:${r.kind}${r.reason ? `:${r.reason}` : ""}` });
        const repl = workFromRead(s, rules, e.path, e.area, w.index, false, r);
        if (repl) {
          repl.entry.disposition = "not_exported";
          s.works.set(e.path, repl);
        } else s.works.delete(e.path);
        recheck.push(e.path);
        return;
      }
      if (r.sha256 !== e.sha256) {
        s.instability.push({ path: e.path, reason: "content_changed_between_passes" });
        applyRead(s, w, r);
        recheck.push(e.path);
      }
      await staged.write(e.area === "context" ? "context" : "tree", e.path, r.bytes);
    });
    // Re-evaluate the change status of anything that changed under us.
    for (const p of recheck) {
      cs.changes.delete(p);
      cs.eolEquivalent.delete(p);
      const w = s.works.get(p);
      if (w && w.entry.area !== "tree") continue;
      const o = compare(ctx, p, resolved.items.get(p), w);
      if (o.kind === "changed") cs.changes.set(p, o.change);
      else if (o.kind === "eol_equivalent") cs.eolEquivalent.add(p);
    }
    await exportBases(recheck.map((p) => cs.changes.get(p)).filter((c): c is ChangeEntry => !!c));
    timings["second_pass"] = Date.now() - t;

    // --- head copies and EOL facts for changed permitted files
    t = Date.now();
    for (const c of cs.changes.values()) {
      const w = s.works.get(c.path);
      c.class = w ? w.entry.class : "absent";
      c.current = w ? { sha256: w.entry.sha256, size: w.entry.size } : null;
      if (c.confidential || c.transformation_unsupported) continue;
      let head: Buffer | null = null;
      if (w && w.entry.class === "permitted" && w.entry.disposition === "exported") {
        head = await staged.read(`tree/${c.path}`);
        if (sha256OfBytes(head) !== w.entry.sha256) throw new DomainError("INTERNAL", `export copy mismatch for ${c.path}`);
        if (await staged.write("review/head", c.path, head)) c.in_export.head = true;
      }
      const base = c.in_export.base ? await staged.read(`review/base/${c.path}`) : null;
      if (head && base) {
        const cmp = compareEol(base, head);
        c.binary = cmp === null;
        c.eol = cmp ? { ...cmp, git_eol_normalized: w!.entry.git_eol_normalized } : null;
      } else if (head || base) {
        c.binary = (head ?? base)!.includes(0);
      }
    }
    timings["head_copies"] = Date.now() - t;

    // --- prepared diff
    t = Date.now();
    // The prepared diff reads base/ and head/ from disk: the run's staging, or (helper) the custodian's read-only staging.
    const reviewDir = await staged.reviewDirForDiff();
    const allPaths = staged.files().map((f) => f.rel.replace(/^review\/(base|head)\//, ""));
    const diff = await runPreparedDiff({
      gitExe: opts.gitExe,
      reviewDir,
      emptyHomeDir: s.scratch.home,
      emptyGlobalConfig: s.scratch.gitconfig,
      emptyHooksDir: s.scratch.hooks,
      maxDiffBytes: rules.max_diff_bytes,
      allPaths,
      hardened: io.hardenedDiff,
      ...(s.signal ? { signal: s.signal } : {}),
    });
    applyDiff(cs, diff);
    const diffPatch = Buffer.from(diffHeader(cs, baseUnavailable, diff) + diff.patch, "utf8");
    await staged.write("review", "diff.patch", diffPatch);
    timings["prepared_diff"] = Date.now() - t;

    return { kind: "review", staged, diffPatch, baseUnavailable, exportOverCap, diffProblem: diff.ok ? null : (diff.error ?? "prepared diff failed") };
  } catch (e) {
    await staged.abort();
    throw e;
  }
}

/** Merge renames from the isolated diff and record per-file diff states. */
function applyDiff(cs: ChangeSet, diff: PreparedDiffResult): void {
  for (const ns of diff.nameStatus) {
    if (!ns.oldPath || !/^R/.test(ns.status)) continue;
    const added = cs.changes.get(ns.path);
    const deleted = cs.changes.get(ns.oldPath);
    if (!added || !deleted || added.status !== "added" || deleted.status !== "deleted") continue;
    added.status = "renamed";
    added.old_path = ns.oldPath;
    added.base = deleted.base;
    added.in_export.base = deleted.in_export.base;
    added.committed = deleted.committed === null && added.committed === null ? null : !!(deleted.committed || added.committed);
    cs.changes.delete(ns.oldPath);
  }
  const state = new Map<string, string>();
  if (diff.sectionsMapped) for (const sec of diff.sections) state.set(sec.path, sec.state);
  for (const c of cs.changes.values()) {
    if (c.confidential) c.diff = "none";
    else if (c.transformation_unsupported || c.class === "size_skipped" || c.class === "link_skipped" || c.class === "submodule" || c.class === "path_unsupported")
      c.diff = "note";
    else if (state.has(c.path)) c.diff = state.get(c.path) as ChangeEntry["diff"];
    else if (!diff.sectionsMapped && (c.in_export.base || c.in_export.head) && !c.eol?.eol_only_change) c.diff = "included";
    else c.diff = "none";
  }
}

function diffHeader(cs: ChangeSet, baseUnavailable: { path: string; reason: string }[], diff: PreparedDiffResult): string {
  const lines = [
    "# code-parley prepared diff: repository-relative paths; base = review/base, current = review/head.",
    "# CR-at-end-of-line differences are hidden here; line-ending facts are in review/manifest.json (\"eol\").",
  ];
  const notes: string[] = [];
  let confidential = 0;
  for (const c of cs.changes.values()) {
    if (c.confidential) confidential++;
    else if (c.transformation_unsupported) notes.push(`# ${c.path}: filter-managed or working-tree-encoding file; raw current bytes are in tree/, no diff.`);
    else if (c.class === "size_skipped") notes.push(`# ${c.path}: larger than max_file_bytes; not exported.`);
    else if (c.class === "link_skipped") notes.push(`# ${c.path}: link or reparse point; not followed.`);
    else if (c.class === "submodule") notes.push(`# ${c.path}: submodule pointer ${c.status}; content not exported.`);
    else if (c.eol?.eol_only_change) notes.push(`# ${c.path}: line endings changed only (${c.eol.base_style} -> ${c.eol.current_style}).`);
  }
  for (const b of baseUnavailable) if (!cs.changes.get(b.path)?.confidential) notes.push(`# ${b.path}: base version not exported (${b.reason}).`);
  if (confidential > 0) notes.push(`# ${confidential} changed file(s) excluded by confidentiality rules; names and contents withheld, NOT reviewed.`);
  if (!diff.ok) notes.push(`# prepared diff unavailable: ${diff.error ?? "unknown error"}`);
  return [...lines, ...notes, ""].join("\n");
}

// ---------------------------------------------------------------------------
// Baseline (plan §9.4 "Baseline capture")
// ---------------------------------------------------------------------------

async function baselineExport(opts: CaptureCore, s: Session, cs: ChangeSet, timings: Record<string, number>, io: CaptureIo): Promise<BaselineOut> {
  assignDispositions(s, cs, opts.rules, false);
  const t = Date.now();
  const staged = await io.baselineSink();
  await staged.init(["files"]);
  const headTree = s.state.headCommit ? await listTree(s.q, s.state.headCommit) : new Map();
  const entries: BaselineEntry[] = [];
  let copied = 0;
  try {
    const works = [...s.works.values()].filter((w) => w.entry.area === "tree").sort((a, b) => compareUtf8(a.entry.path, b.entry.path));
    for (const w of works) {
      checkAbort(s.signal);
      const e = w.entry;
      const head = headTree.get(e.path);
      const row = (base: BaselineEntry["base"], reason?: string): BaselineEntry => ({
        path: e.path,
        class: e.class,
        size: e.size,
        sha256: e.sha256,
        git_oid: e.git_oid,
        base,
        ...(reason ? { reason } : {}),
      });
      if (e.class !== "permitted") {
        entries.push(row("unavailable", e.class === "excluded" ? "confidential" : e.class));
        continue;
      }
      // Raw bytes equal to the HEAD blob: since_baseline reads that blob.
      if (head && head.mode !== "160000" && head.mode !== "120000" && head.oid === e.git_oid) {
        entries.push(row("commit_blob"));
        continue;
      }
      const r = await readWorkingFile(absolutePath(s.root, e.path), {
        root: s.root,
        objectFormat: s.state.objectFormat,
        maxRetainBytes: opts.rules.max_file_bytes,
        retain: true,
        linkCache: new Map(),
      });
      if (r.kind !== "file" || !r.bytes) {
        s.instability.push({ path: e.path, reason: `changed_between_passes:${r.kind}` });
        entries.push(row("unavailable", "unstable_read"));
        continue;
      }
      if (r.sha256 !== e.sha256) {
        s.instability.push({ path: e.path, reason: "content_changed_between_passes" });
        applyRead(s, w, r);
      }
      if (await staged.write("files", e.path, r.bytes)) {
        copied++;
        entries.push(row("copy"));
      } else entries.push(row("unavailable", "case_collision"));
    }
  } catch (err) {
    await staged.abort();
    throw err;
  }
  timings["baseline_copies"] = Date.now() - t;
  return { kind: "baseline", staged, baselineEntries: entries, copied, baseUnavailable: [], exportOverCap: false, diffProblem: null };
}

// ---------------------------------------------------------------------------
// Model-facing manifest (MR-F)
// ---------------------------------------------------------------------------

function buildManifest(a: {
  opts: CaptureCore;
  s: Session;
  resolved: ResolvedBase;
  sourceId: string;
  rulesDigest: string;
  entries: SourceEntry[];
  changes: ChangeEntry[];
  eolEquivalent: string[];
  limitations: CaptureRecord["limitations"];
  staged: ExportSink;
  diffPatch: Buffer;
}): ReviewManifest {
  const withheld = withheldPaths(a.entries, a.changes);
  const visible = (p: string) => !withheld.has(p);
  const files = a.staged.files();
  const listArea = (prefix: string) =>
    files
      .filter((f) => f.rel.startsWith(prefix))
      .map((f) => ({ path: f.rel.slice(prefix.length), size: f.size, sha256: f.sha256 }))
      .sort((x, y) => compareUtf8(x.path, y.path));
  const changedPaths = new Set(a.changes.map((c) => c.path));
  const m = finalizeManifest({
    schema: "arl.review-manifest.v1",
    capture_id: a.opts.operationId,
    target: { kind: a.opts.target.kind, ref: a.opts.target.kind === "base_ref" ? a.opts.target.ref : null },
    base: a.resolved.base,
    head: { commit: a.s.state.headCommit, branch: a.s.state.branch },
    object_format: a.s.state.objectFormat,
    source_id: a.sourceId,
    rules_digest: a.rulesDigest,
    limits: { max_file_bytes: a.opts.rules.max_file_bytes, max_export_bytes: a.opts.rules.max_export_bytes, max_diff_bytes: a.opts.rules.max_diff_bytes },
    files: [
      ...listArea("tree/").map((f) => ({ ...f, area: "tree" as const })),
      ...listArea("context/").map((f) => ({ ...f, area: "context" as const })),
    ],
    changes: a.changes
      .filter((c) => !c.confidential)
      .map((c) => ({
        path: c.path,
        status: c.status,
        ...(c.old_path ? { old_path: c.old_path } : {}),
        class: c.class,
        binary: c.binary,
        eol: c.eol,
        transformation_unsupported: c.transformation_unsupported,
        change_uncertain: c.change_uncertain,
        index_flag_hidden: c.index_flag_hidden,
        committed: c.committed,
        uncommitted: c.uncommitted,
        base_in_export: c.in_export.base,
        head_in_export: c.in_export.head,
        diff: c.diff,
      })),
    review_files: {
      diff_patch: { size: a.diffPatch.length, sha256: sha256OfBytes(a.diffPatch) },
      base: listArea("review/base/"),
      head: listArea("review/head/"),
    },
    exclusions: {
      confidential: {
        count: a.entries.filter((e) => e.class === "excluded").length,
        changed_count: a.changes.filter((c) => c.confidential).length,
      },
      repository_context: { count: a.entries.filter((e) => e.disposition === "excluded_repo_context").length },
      size_skipped: a.entries.filter((e) => e.class === "size_skipped" && visible(e.path)).map((e) => ({ path: e.path, size: e.size, changed: changedPaths.has(e.path) })),
      context_reduced: a.entries.filter((e) => e.disposition === "context_reduced").map((e) => ({ path: e.path, size: e.size })),
      link_skipped: a.entries.filter((e) => e.class === "link_skipped" && visible(e.path)).map((e) => ({ path: e.path, reason: e.reason ?? "link" })),
      path_unsupported: a.entries.filter((e) => e.class === "path_unsupported" && visible(e.path)).map((e) => ({ path: e.path, reason: e.reason ?? "unsupported" })),
      submodules: a.entries.filter((e) => e.class === "submodule" && visible(e.path)).map((e) => ({ path: e.path, changed: changedPaths.has(e.path) })),
    },
    eol_conversion_equivalent: { count: a.eolEquivalent.length, paths: a.eolEquivalent.filter(visible) },
    limitations: a.limitations,
    stable: a.s.instability.length === 0,
  });
  const withheldHashes = new Set<string>();
  for (const e of a.entries) if (withheld.has(e.path) && e.sha256) withheldHashes.add(e.sha256);
  for (const c of a.changes) if (c.confidential && c.base?.oid) withheldHashes.add(c.base.oid);
  assertNoWithheldLeak(m, withheld, withheldHashes);
  return ReviewManifestSchema.parse(m);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * `wait`: an operation's capture, which waits for a bounded holder and stops when `signal`
 * aborts; null: a bounded read, which never waits and stands aside for waiting operations.
 */
async function withCaptureLock<T>(repoRoot: string, lock: CaptureLockOptions, operationId: string, held: WorktreeLockHandle | undefined, wait: { signal?: AbortSignal } | null, fn: () => Promise<T>): Promise<T> {
  const lockPath = worktreeLockPath(lock.dataHome, canonicalPathKey(repoRoot));
  if (held) {
    if (!samePath(held.lockPath, lockPath) || !(await held.verify())) {
      throw new DomainError("WORKTREE_BUSY", "the worktree lock passed to the source-identity read is not held for this repository");
    }
    return fn();
  }
  const req = { owner: lock.owner, operationId, kind: "capture" };
  const handle = wait ? await acquireWorktreeLockWaiting(lockPath, req, lock.deps ?? {}, wait.signal) : await acquireWorktreeLock(lockPath, req, lock.deps ?? {}, { yieldToWaiters: true });
  const timer = setInterval(() => void handle.heartbeat().catch(() => undefined), 10_000);
  timer.unref?.();
  try {
    return await fn();
  } finally {
    clearInterval(timer);
    await handle.release();
  }
}

async function withScratch<T>(parent: string, fn: (s: Scratch) => Promise<T>): Promise<T> {
  const root = join(parent, `capture-${randomBytes(6).toString("hex")}`);
  const scratch: Scratch = { root, hooks: join(root, "hooks"), home: join(root, "home"), gitconfig: join(root, "gitconfig") };
  await mkdir(scratch.hooks, { recursive: true });
  await mkdir(scratch.home, { recursive: true });
  await writeFile(scratch.gitconfig, "");
  try {
    return await fn(scratch);
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => undefined);
  }
}

async function mapPool<T>(items: readonly T[], concurrency: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]!);
    }
  });
  await Promise.all(workers);
}

function checkAbort(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new DomainError("INTERNAL", "capture cancelled");
}

function relRef(runDir: string, abs: string): string {
  const base = runDir.replace(/\\$/, "");
  return (abs.startsWith(base) ? abs.slice(base.length) : abs).replace(/^[\\/]/, "").replace(/\\/g, "/");
}

