// Phase 4 Increment 3 — the application of an owner-confirmed delegated fix, and its reconciliation (contract §3.6).
//
// `applyFix` writes ONLY the content the custodian hands back when it consumes the owner's single-use confirmation, and
// only after re-checking every target at use. The sequence (each step fails closed):
//
//   1. P4-A, as for the delegation: Windows, the validated custodian, a protected run with its configuration in force.
//   2. Lock: the per-worktree lock of kind `fix_apply` (a live holder: WORKTREE_BUSY; a dead one: never released
//      automatically — WORKTREE_OWNERSHIP_UNRESOLVED until `code-parley fix reconcile`).
//   3. Consume (custodian): `op_begin` of an `apply` operation. The custodian checks the confirmation (present, unconsumed,
//      unexpired, not rejected, this repository and run), that no other application is in progress for the repository
//      (APPLY_IN_PROGRESS), that the held content still renders the confirmed bytes, re-measures the primary source
//      through its helper (FIX_STALE: nothing is consumed), and returns the confirmed canonical content.
//   4. The engine uses that content only — never a proposal file in the data home — and checks it: every postimage is the
//      hash of the bytes returned, and the proposal digest recomputes to the confirmed one.
//   5. Pre-validation, before any write: each target resolved segment by segment from the repository root without
//      following links (no symlink, junction or other reparse point in any existing component; no 8.3 alias); a modify or
//      delete target is a regular, single-link file whose bytes hash to the custodian's preimage (kept for rollback); an
//      add target is absent — including a path the sanitized export never held but the worktree does.
//   6. A journal (data home) records the application before the first write: the ticket (the custodian's operation),
//      each file's preimage and postimage hashes, the preimage bytes beside it, and the directories it creates.
//   7. Each write goes to a temporary file created exclusively in the verified parent; immediately before the replace the
//      parent's identity and the target's preimage (or absence) are verified again; the replace is one rename; after it
//      the final path's identity and hash must be the postimage's. A delete removes only a file verified at its preimage.
//   8. op_finish: `applied` (the custodian measures the post-apply source), or — on any ordinary failure — every file
//      this application replaced and still at its postimage is restored from the preimage bytes, an added file still at
//      its postimage is removed, and `apply_failed` is recorded with the restored state. No atomic multi-file
//      application is claimed.
//
// An interruption (the process killed, power lost) leaves the custodian's operation running with its writer gone: the
// custodian records it `apply_interrupted` (recover) — never `applied`, even when every file is at its postimage — and
// `reconcileApplications` (`code-parley fix reconcile`) reports each journaled file's state and, on the user's choice,
// restores the files still at their postimage (restore) or leaves them (leave), records that with the custodian and
// clears the lock it verified. Same-user processes are not stopped by any of this: the use-time checks DETECT a
// replacement, redirection or content change and fail or roll back; they do not prevent a racing same-user writer.

import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, open, readFile, readdir, realpath, rename, rm, rmdir, unlink } from "node:fs/promises";
import { basename, dirname, join, relative, sep } from "node:path";
import { z } from "zod";
import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { readWorkingFile } from "../capture/safe-read.js";
import type { ApplyFileState, RunApplyOutcome, RunSection } from "../custodian/protocol.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import { portablePathProblem } from "../policy/delegated-fix.js";
import { atomicWriteFile } from "../store/atomic.js";
import { acquireWorktreeLock, acquireWorktreeLockWaiting, clearWorktreeOwnership, isBusyWithBoundedRead, readWorktreeLock, type LockDeps, type WorktreeLockHandle } from "../store/locks.js";
import { selfOwner } from "../store/owner.js";
import { canonicalPathKey, worktreeLockPath } from "../store/paths.js";
import { readState } from "../store/state-store.js";
import { firstLinkComponent } from "../workspace/links.js";
import { canonicalizePath, isContainedIn, samePath } from "../workspace/paths.js";
import { custodianEvidenceFor, reconcileCustodianRun, type CustodianEvidence } from "./custodian-evidence.js";
import { evidenceSelection, type Loaded, type RunHandle } from "./engine-env.js";
import { heldConfigFor } from "./protected-config.js";
import { SimulatedKill } from "./simulated-kill.js";

/** The worktree-lock kind of an application: like checks, a dead holder is never released automatically. */
export const FIX_APPLY_LOCK_KIND = "fix_apply";
const JOURNAL_SCHEMA = "codeparley.fix-apply-journal.v1";
/** A file of a confirmed proposal is at most this large (CustodianConstants.MaxFixFileBytes). */
const MAX_FILE_BYTES = 256 * 1024;

/** apply_fix's input: the delegated fix whose confirmed proposal is applied — never contents, a diff or a confirmation. */
export const ApplyFixInputSchema = z.object({ proposal_id: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/) }).strict();
export type ApplyFixInput = z.input<typeof ApplyFixInputSchema>;

export interface ApplyFixResult {
  fix_operation_id: string;
  apply_operation_id: string;
  status: "applied" | "apply_failed";
  files: { path: string; state: ApplyFileState }[];
  detail: string | null;
  /** The custodian's measurement of the source after the application (null: it could not measure). */
  source_id_after: string | null;
  next: string;
}

/** Test seams: a hook before each file's replace (to race it), and a simulated process death right after the
 * `killAfterWrites`-th write (no further write, no rollback, no finish, the lock left held — what a killed process leaves).
 * A `beforeReplace` that throws `SimulatedKill` dies with that file's temporary file in place, as a real kill would. */
export interface ApplyFixHooks {
  beforeReplace?: (path: string, abs: string) => Promise<void>;
  killAfterWrites?: number;
  lockDeps?: LockDeps;
}

/** What a simulated kill throws (tests only): nothing below it runs. */
export { SimulatedKill };

interface ConfirmedChange {
  path: string;
  kind: "add" | "modify" | "delete";
  executable: boolean;
  preimage: { size: number; sha256: string } | null;
  postimage: { size: number; sha256: string; binary: boolean } | null;
  content: string | null;
}

/** The journal of one application (data home; written before the first write). */
interface Journal {
  schema: typeof JOURNAL_SCHEMA;
  runId: string;
  repositoryRoot: string;
  fixOperationId: string;
  applyOperationId: string;
  proposalDigest: string;
  lockPath: string;
  lockOperationId: string;
  startedAt: string;
  files: { path: string; kind: ConfirmedChange["kind"]; preimage: ConfirmedChange["preimage"]; postimage: ConfirmedChange["postimage"]; preimageFile: string | null }[];
  createdDirs: string[];
  /** Each temporary file, journaled before it is created: a kill can leave the one in flight (holding confirmed bytes). */
  temporaries?: string[];
}

const unavailable = (why: string): DomainError => new DomainError("FIX_DELEGATION_UNAVAILABLE", `the application is refused: ${why} (P4-A: Windows or Linux, through the validated custodian, with a protected configuration only); nothing was applied`, { retryable: false });
const refused = (why: string): DomainError => new DomainError("APPLY_TARGET_REFUSED", why, { retryable: false });
const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/** The custodian's proposal digest (FixRules.ProposalDigest), recomputed by the engine over what the custodian returned. */
export function proposalDigestOf(bindings: Record<string, unknown>, changes: readonly ConfirmedChange[]): string {
  const baseline = bindings["baseline"] as Record<string, unknown>;
  return sha256OfCanonicalJson({
    schema: "codeparley.custodian-fix-proposal.v1",
    runId: bindings["runId"], operationId: bindings["operationId"], fixId: bindings["fixId"], taskDigest: bindings["taskDigest"], boundaryDigest: bindings["boundaryDigest"],
    baseline: { reviewId: baseline["reviewId"], sourceId: baseline["sourceId"], exportDigest: baseline["exportDigest"], manifestDigest: baseline["manifestDigest"] },
    changes: changes.map((c) => ({ path: c.path, kind: c.kind, executable: c.executable, preimage: c.preimage, postimage: c.postimage })),
  });
}

/** The data-home directory of one application's journal. */
export function journalDirOf(dataHome: string, runId: string, applyOperationId: string): string {
  return join(dataHome, "fix-apply", runId, applyOperationId);
}

// ---------------------------------------------------------------------------
// P4-A and the custodian's records
// ---------------------------------------------------------------------------

interface Protected {
  ev: CustodianEvidence;
  run: RunSection | null;
}

async function protectedRun(le: Loaded, run: RunHandle, requireConfig: boolean): Promise<Protected> {
  const platform = le.env.testHooks?.custodian?.platform ?? process.platform;
  if (platform !== "win32" && platform !== "linux") throw unavailable(`delegated fixes need the CodeParley custodian on Windows or Linux (this is ${platform})`);
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw unavailable("no validated CodeParley custodian is available on this host");
  const sel = evidenceSelection(le, run);
  const st = await readState(run.paths);
  let ev: CustodianEvidence | null;
  let held;
  try {
    ev = await custodianEvidenceFor(sel, st);
    held = ev ? await heldConfigFor(sel, st) : null;
  } catch (e) {
    throw isDomainError(e) && e.code !== "INTERNAL" ? e : unavailable(`the custodian could not answer for this run (${e instanceof Error ? e.message : String(e)})`);
  }
  if (!ev || !held) throw unavailable("this run is not protected by the custodian (an attended run)");
  if (requireConfig && (!held.section.repository || !held.section.repository.usable)) throw unavailable("the repository has no protected configuration in force");
  return { ev, run: held.run };
}

type HeldOperation = Record<string, unknown> & { operationId: string; kind: string; status: string; begin: Record<string, unknown>; outcome: Record<string, unknown> | null; writerAlive?: boolean | null };

const operationsOf = (run: RunSection | null): HeldOperation[] => ((run?.record as { operations?: HeldOperation[] } | null)?.operations ?? []);

// ---------------------------------------------------------------------------
// Use-time checks
// ---------------------------------------------------------------------------

interface Target {
  change: ConfirmedChange;
  abs: string;
  parent: string;
  /** The directories this change needs created (top-down; absent at pre-validation). */
  missing: string[];
  /** The parent's identity at pre-validation (null: it is created by this application). */
  parentId: { dev: bigint; ino: bigint } | null;
  preBytes: Buffer | null;
  post: Buffer | null;
}

const readOpts = (root: string, cache: Map<string, boolean>) => ({ root, objectFormat: "sha1" as const, maxRetainBytes: MAX_FILE_BYTES, retain: true, linkCache: cache });

/** The absolute path of a repository-relative path, checked portable and contained. */
function absoluteOf(root: string, rel: string): string {
  const problem = portablePathProblem(rel);
  if (problem) throw refused(`${rel}: not a portable repository path (${problem}); nothing was written`);
  const abs = join(root, ...rel.split("/"));
  if (!isContainedIn(abs, root) || samePath(abs, root)) throw refused(`${rel}: not contained in the repository; nothing was written`);
  return abs;
}

/** The parent chain of `abs`: every existing component a real directory (no link or reparse point), none an alias; the
 * components that do not exist yet. */
async function verifyParent(root: string, abs: string, cache: Map<string, boolean>): Promise<{ parent: string; missing: string[]; parentId: { dev: bigint; ino: bigint } | null }> {
  const parent = dirname(abs);
  const chain: string[] = [];
  for (let p = parent; !samePath(p, root); p = dirname(p)) {
    if (!isContainedIn(p, root)) throw refused(`${abs}: its parent leaves the repository`);
    chain.unshift(p);
  }
  const missing: string[] = [];
  for (const dir of chain) {
    if (missing.length > 0) {
      missing.push(dir);
      continue;
    }
    const st = await lstat(dir, { bigint: true }).catch((e: unknown) => ((e as { code?: string }).code === "ENOENT" ? null : Promise.reject(e)));
    if (st === null) {
      missing.push(dir);
      continue;
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw refused(`${dir} is not a real directory (a link, a junction or a file); nothing was written`);
  }
  const existing = missing.length > 0 ? dirname(missing[0]!) : parent;
  if (!samePath(existing, root) && (await firstLinkComponent(existing, root, cache)) !== null) throw refused(`a component of ${existing} is a link, a junction or another reparse point; nothing was written`);
  if (!samePath(await realpath(existing).catch(() => ""), existing)) throw refused(`${existing} is not reached by its own name (an alias or a redirected directory); nothing was written`);
  const st = missing.length > 0 ? null : await lstat(parent, { bigint: true });
  return { parent, missing, parentId: st ? { dev: st.dev, ino: st.ino } : null };
}

/** A modify or delete target at its preimage: a regular, single-link file, no link anywhere on its way, these bytes. */
async function requireAtPreimage(root: string, abs: string, pre: { size: number; sha256: string }, cache: Map<string, boolean>): Promise<Buffer> {
  const r = await readWorkingFile(abs, readOpts(root, cache));
  if (r.kind === "missing") throw refused(`${abs} is absent; the confirmed change needs it at its preimage; nothing more was written`);
  if (r.kind === "link") throw refused(`${abs} is a link, a junction or a hard-linked file (${r.reason ?? "link"}); nothing more was written`);
  if (r.kind !== "file") throw refused(`${abs} is not a regular file the application can verify (${r.kind}${r.reason ? `: ${r.reason}` : ""}); nothing more was written`);
  if (r.size !== pre.size || r.sha256 !== pre.sha256 || !r.bytes) throw refused(`${abs} is not at the confirmed preimage (its bytes changed since the baseline); nothing more was written`);
  return r.bytes;
}

async function requireAbsent(abs: string): Promise<void> {
  const st = await lstat(abs).catch((e: unknown) => ((e as { code?: string }).code === "ENOENT" || (e as { code?: string }).code === "ENOTDIR" ? null : Promise.reject(e)));
  if (st !== null) throw refused(`${abs} exists, but the confirmed change adds it (the sanitized baseline did not hold it); nothing more was written`);
}

/** The parent is still the directory pre-validation saw (same identity, no link, reached by its own name). */
async function requireSameParent(t: Target, root: string): Promise<void> {
  const st = await lstat(t.parent, { bigint: true }).catch(() => null);
  if (!st || st.isSymbolicLink() || !st.isDirectory()) throw refused(`${t.parent} is no longer a real directory; nothing more was written`);
  if (t.parentId && (st.dev !== t.parentId.dev || st.ino !== t.parentId.ino)) throw refused(`${t.parent} was replaced since it was verified (a redirected parent); nothing more was written`);
  if ((await firstLinkComponent(t.parent, root, new Map())) !== null) throw refused(`a component of ${t.parent} became a link or a junction; nothing more was written`);
  if (!samePath(await realpath(t.parent).catch(() => ""), t.parent)) throw refused(`${t.parent} is no longer reached by its own name; nothing more was written`);
}

/** Write `bytes` to the target through an exclusively created temporary file in its verified parent and one rename —
 * the parent and the target (at `expected`, or absent) verified again just before, the result just after. */
async function replaceVerified(t: Target, root: string, bytes: Buffer, expected: { size: number; sha256: string } | null, hooks: ApplyFixHooks, journalTemporary?: (tmp: string) => Promise<void>): Promise<void> {
  const tmp = join(t.parent, `.cp-fix-${randomBytes(8).toString("hex")}.tmp`);
  await journalTemporary?.(tmp);
  const fh = await open(tmp, "wx");
  let tmpId: { dev: bigint; ino: bigint } | null = null;
  let renamed = false;
  try {
    await fh.writeFile(bytes);
    await fh.sync();
    const st = await fh.stat({ bigint: true });
    tmpId = { dev: st.dev, ino: st.ino };
  } finally {
    await fh.close();
  }
  try {
    await hooks.beforeReplace?.(t.change.path, t.abs);
    await requireSameParent(t, root);
    if (expected) await requireAtPreimage(root, t.abs, expected, new Map());
    else await requireAbsent(t.abs);
    await rename(tmp, t.abs);
    renamed = true;
    const after = await lstat(t.abs, { bigint: true });
    if (after.isSymbolicLink() || !after.isFile() || !tmpId || after.dev !== tmpId.dev || after.ino !== tmpId.ino) throw refused(`${t.abs} is not the file just written (replaced during the rename)`);
    const r = await readWorkingFile(t.abs, readOpts(root, new Map()));
    if (r.kind !== "file" || r.sha256 !== sha256(bytes)) throw refused(`${t.abs} does not hold the bytes just written`);
  } catch (e) {
    if (e instanceof SimulatedKill) throw e; // a killed process cleans nothing up
    throw renamed ? e : await discardTemporary(t, root, tmp, tmpId, e);
  }
}

/** Remove a temporary file that was never renamed: only through its parent while that is still the verified directory,
 * and only while the name still holds the file created. When the parent was moved away or redirected, nothing is removed
 * through the new path (that would act on whatever it now reaches); the temporary file, holding the confirmed bytes, may
 * remain where the moved directory now is, and the failure names it. */
async function discardTemporary(t: Target, root: string, tmp: string, id: { dev: bigint; ino: bigint } | null, cause: unknown): Promise<unknown> {
  const parentHolds = await requireSameParent(t, root).then(() => true, () => false);
  if (parentHolds) {
    const st = await lstat(tmp, { bigint: true }).catch(() => null);
    if (st && id && st.isFile() && st.dev === id.dev && st.ino === id.ino) await unlink(tmp).catch(() => undefined);
    return cause;
  }
  const why = cause instanceof Error ? cause.message : String(cause);
  return refused(`the temporary file ${basename(tmp)} (the confirmed bytes of ${t.change.path}) was not removed: its directory was moved or redirected, so it may remain where that directory now is; ${why}`);
}

/** Delete a target verified at its preimage. */
async function deleteVerified(t: Target, root: string, hooks: ApplyFixHooks): Promise<void> {
  await hooks.beforeReplace?.(t.change.path, t.abs);
  await requireSameParent(t, root);
  await requireAtPreimage(root, t.abs, t.change.preimage!, new Map());
  await unlink(t.abs);
  await requireAbsent(t.abs);
}

/** A file's state now, against its journaled preimage and postimage (never following a link). */
async function stateOf(root: string, abs: string, f: Pick<Journal["files"][number], "kind" | "preimage" | "postimage">): Promise<ApplyFileState> {
  const r = await readWorkingFile(abs, readOpts(root, new Map()));
  if (r.kind === "missing") return "absent";
  if (r.kind !== "file") return "unknown";
  if (f.postimage && r.sha256 === f.postimage.sha256 && r.size === f.postimage.size) return "postimage";
  if (f.preimage && r.sha256 === f.preimage.sha256 && r.size === f.preimage.size) return "preimage";
  return "other";
}

/** Is the file where the application left it (a delete's postimage is its absence)? */
const atPostimage = (kind: ConfirmedChange["kind"], s: ApplyFileState): boolean => (kind === "delete" ? s === "absent" : s === "postimage");

// ---------------------------------------------------------------------------
// apply_fix
// ---------------------------------------------------------------------------

/**
 * Apply the owner-confirmed proposal of delegated fix `proposal_id` to the primary worktree. Refusals before the
 * custodian consumed the confirmation apply nothing (and consume nothing); once it is consumed the operation is always
 * finished — applied, or apply_failed with what was restored — unless the process dies (then: reconcile).
 */
export async function applyFix(le: Loaded, run: RunHandle, input: ApplyFixInput, hooks: ApplyFixHooks = {}): Promise<ApplyFixResult> {
  const req = ApplyFixInputSchema.parse(input);
  await reconcileCustodianRun(evidenceSelection(le, run), run.paths, le.env.owner); // a pending end arrives before any consume
  const { ev, run: held } = await protectedRun(le, run, true);
  const fix = operationsOf(held).find((o) => o.operationId === req.proposal_id && o.kind === "fix");
  if (!fix) throw new DomainError("EVIDENCE_NOT_HELD", `the custodian holds no delegated fix ${req.proposal_id} of this run; nothing was applied`, { retryable: false });
  const proposal = (fix.outcome?.["proposal"] ?? null) as { proposalDigest?: string; changes?: ConfirmedChange[] } | null;
  if (!proposal?.proposalDigest) throw new DomainError("FIX_NOT_CONFIRMED", `delegated fix ${req.proposal_id} holds no proposal (${fix.status}); nothing was applied`, { retryable: false });
  if ((proposal.changes ?? []).some((c) => c.executable)) {
    throw new DomainError("FIX_NOT_APPLICABLE", `delegated fix ${req.proposal_id} sets an executable bit, which this platform's working tree cannot carry faithfully; nothing was applied (the confirmation is unused)`, { retryable: false });
  }

  const root = await canonicalizePath(run.meta.repository_root);
  const lockPath = worktreeLockPath(le.dataHome, canonicalPathKey(run.meta.repository_root));
  const lockOperationId = uuidv7();
  const lockRequest = { owner: selfOwner(), operationId: lockOperationId, kind: FIX_APPLY_LOCK_KIND };
  const lock: WorktreeLockHandle = await acquireWorktreeLock(lockPath, lockRequest, hooks.lockDeps ?? {}).catch((e: unknown) => {
    if (isBusyWithBoundedRead(e)) return acquireWorktreeLockWaiting(lockPath, lockRequest, hooks.lockDeps ?? {});
    throw e;
  });
  let killed = false;
  try {
    // ---- 3. the custodian consumes the confirmation and returns the confirmed content ----
    const begun = await ev.transition("op_begin", { operationKind: "apply", fixOperationId: req.proposal_id, proposalDigest: proposal.proposalDigest }, `${lockOperationId}-begin`);
    const applyId = String(begun["operationId"]);
    const finish = async (outcome: RunApplyOutcome): Promise<ApplyFixResult> => {
      const done = await ev.transition("op_finish", { operationId: applyId, outcome }, `${lockOperationId}-finish`);
      return {
        fix_operation_id: req.proposal_id, apply_operation_id: applyId, status: outcome.status, files: outcome.files, detail: outcome.detail,
        source_id_after: (done["sourceIdAfter"] as string | null | undefined) ?? null,
        next: outcome.status === "applied"
          ? "the source changed: run fresh checks and request a distinct review (review_with_codex) before the run can be ready"
          : "nothing confirmed remains applied (see files); the confirmation was used — a new delegation and confirmation are needed",
      };
    };
    const changes = (begun["changes"] ?? []) as ConfirmedChange[];
    const untouched = (): RunApplyOutcome["files"] => changes.map((c) => ({ path: c.path, state: c.kind === "add" ? "absent" : "preimage" }));

    // ---- 4. the custodian's content, checked against the confirmed digest ----
    let targets: Target[];
    try {
      if (begun["proposalDigest"] !== proposal.proposalDigest) throw refused("the custodian returned another proposal than the one confirmed");
      for (const c of changes) {
        const post = c.content === null ? null : Buffer.from(c.content, "base64");
        if ((post === null) !== (c.kind === "delete") || (post && (post.length !== c.postimage?.size || sha256(post) !== c.postimage?.sha256))) throw refused(`the content returned for ${c.path} does not hash to its postimage`);
      }
      if (proposalDigestOf(begun["bindings"] as Record<string, unknown>, changes) !== proposal.proposalDigest) throw refused("the content returned does not recompute to the confirmed proposal digest");
      // ---- 5. pre-validation of every target, before any write ----
      const cache = new Map<string, boolean>();
      targets = [];
      for (const c of changes) {
        const abs = absoluteOf(root, c.path);
        const p = await verifyParent(root, abs, cache);
        const preBytes = c.kind === "add" ? (await requireAbsent(abs), null) : await requireAtPreimage(root, abs, c.preimage!, cache);
        targets.push({ change: c, abs, parent: p.parent, missing: p.missing, parentId: p.parentId, preBytes, post: c.content === null ? null : Buffer.from(c.content, "base64") });
      }
    } catch (e) {
      return finish({ status: "apply_failed", files: untouched(), detail: `refused before any write: ${e instanceof Error ? e.message : String(e)}`.slice(0, 500) });
    }

    // ---- 6. the journal, before the first write ----
    const jdir = journalDirOf(le.dataHome, run.runId, applyId);
    const journal: Journal = {
      schema: JOURNAL_SCHEMA, runId: run.runId, repositoryRoot: root, fixOperationId: req.proposal_id, applyOperationId: applyId, proposalDigest: proposal.proposalDigest,
      lockPath, lockOperationId, startedAt: new Date().toISOString(),
      files: targets.map((t, i) => ({ path: t.change.path, kind: t.change.kind, preimage: t.change.preimage, postimage: t.change.postimage, preimageFile: t.preBytes ? `${i}.pre` : null })),
      createdDirs: [],
      temporaries: [],
    };
    try {
      await mkdir(jdir, { recursive: true });
      for (const [i, t] of targets.entries()) if (t.preBytes) await atomicWriteFile(join(jdir, `${i}.pre`), t.preBytes);
      await atomicWriteFile(join(jdir, "journal.json"), JSON.stringify(journal, null, 2));
    } catch (e) {
      await rm(jdir, { recursive: true, force: true }).catch(() => undefined);
      return finish({ status: "apply_failed", files: untouched(), detail: `the journal could not be written; nothing was written to the worktree: ${e instanceof Error ? e.message : String(e)}`.slice(0, 500) });
    }

    // ---- 7. the writes ----
    const journalTemporary = async (tmp: string): Promise<void> => {
      journal.temporaries!.push(tmp);
      await atomicWriteFile(join(jdir, "journal.json"), JSON.stringify(journal, null, 2));
    };
    const written: Target[] = [];
    try {
      for (const t of targets) {
        for (const dir of t.missing) {
          await mkdir(dir);
          journal.createdDirs.push(dir);
          await atomicWriteFile(join(jdir, "journal.json"), JSON.stringify(journal, null, 2));
          const st = await lstat(dir, { bigint: true });
          if (st.isSymbolicLink() || !st.isDirectory()) throw refused(`${dir} is not the directory just created`);
          if (dir === t.parent) t.parentId = { dev: st.dev, ino: st.ino };
        }
        if (t.change.kind === "delete") await deleteVerified(t, root, hooks);
        else await replaceVerified(t, root, t.post!, t.change.kind === "modify" ? t.change.preimage : null, hooks, journalTemporary);
        written.push(t);
        if (hooks.killAfterWrites !== undefined && written.length >= hooks.killAfterWrites) {
          killed = true;
          throw new SimulatedKill();
        }
      }
    } catch (e) {
      if (e instanceof SimulatedKill) {
        killed = true;
        throw e;
      }
      const files = await rollback(root, targets, written, journal, journalTemporary);
      await rm(jdir, { recursive: true, force: true }).catch(() => undefined);
      return finish({ status: "apply_failed", files, detail: `${e instanceof Error ? e.message : String(e)}; the files written were restored where still at their postimage`.slice(0, 500) });
    }
    const result = await finish({ status: "applied", files: targets.map((t) => ({ path: t.change.path, state: t.change.kind === "delete" ? "absent" : "postimage" })), detail: null });
    await rm(jdir, { recursive: true, force: true }).catch(() => undefined);
    return result;
  } finally {
    if (!killed) await lock.release().catch(() => undefined);
  }
}

/** §3.6.3: restore every file this application replaced that is still at its postimage (an added one is removed, a deleted
 * one recreated), then the directories it created when empty; returns each file's state afterwards. */
async function rollback(root: string, targets: Target[], written: Target[], journal: Journal, journalTemporary: (tmp: string) => Promise<void>): Promise<RunApplyOutcome["files"]> {
  const noHooks: ApplyFixHooks = {};
  for (const t of [...written].reverse()) {
    try {
      const s = await stateOf(root, t.abs, t.change);
      if (!atPostimage(t.change.kind, s)) continue;
      if (t.change.kind === "add") await unlink(t.abs);
      else if (t.change.kind === "modify") await replaceVerified(t, root, t.preBytes!, t.change.postimage, noHooks, journalTemporary);
      else await replaceVerified(t, root, t.preBytes!, null, noHooks, journalTemporary);
    } catch {
      /* reported below as its state */
    }
  }
  for (const dir of [...journal.createdDirs].reverse()) await rmdir(dir).catch(() => undefined);
  const out: RunApplyOutcome["files"] = [];
  for (const t of targets) out.push({ path: t.change.path, state: await stateOf(root, t.abs, t.change).catch((): ApplyFileState => "unknown") });
  return out;
}

// ---------------------------------------------------------------------------
// fix reconcile
// ---------------------------------------------------------------------------

export interface ReconcileReport {
  applications: {
    apply_operation_id: string;
    fix_operation_id: string | null;
    /** The custodian's status before (running with its writer gone, interrupted) and after this reconciliation. */
    status_before: string;
    status_after: string;
    observed: "none" | "partial" | "all_at_postimage" | null;
    journal: "present" | "missing";
    files: { path: string; kind: string; state_before: ApplyFileState; state_after: ApplyFileState }[];
    choice: "restore" | "leave" | null;
    lock_cleared: boolean;
    /** The application's temporary files still present (a kill leaves the one in flight); removed on either choice. */
    temporary_files: { path: string; removed: boolean }[];
    detail: string | null;
  }[];
}

/**
 * `code-parley fix reconcile <run>` (implementer, §3.6.4): every application of the run that is interrupted — or still
 * running in the custodian's records with its writer gone (recovered here first: apply_interrupted) — is reported file by
 * file against its journal (none / partial / all at the postimage). With a choice it is reconciled: `restore` returns the
 * files still at their journaled postimage to their verified preimage (an added file is removed); `leave` changes
 * nothing. The outcome is recorded with the custodian (apply_interrupted_restored / _left) and the worktree lock the
 * application held is cleared once the state is verified. Never recorded `applied`.
 */
export async function reconcileApplications(le: Loaded, run: RunHandle, choice: "restore" | "leave" | null): Promise<ReconcileReport> {
  const { ev, run: held } = await protectedRun(le, run, false);
  const report: ReconcileReport = { applications: [] };
  for (const op of operationsOf(held).filter((o) => o.kind === "apply" && (o.status === "running" || o.status === "apply_interrupted"))) {
    let status = op.status;
    if (status === "running") {
      if (op.writerAlive !== false) {
        report.applications.push({ apply_operation_id: op.operationId, fix_operation_id: String(op.begin["fixOperationId"] ?? ""), status_before: status, status_after: status, observed: null, journal: "missing", files: [], choice: null, lock_cleared: false, temporary_files: [], detail: op.writerAlive === true ? "the application is still running (its writer is alive): nothing to reconcile yet" : "the custodian cannot establish whether its writer is gone: nothing to reconcile yet" });
        continue;
      }
      const rec = await ev.transition("recover", { operationId: op.operationId, incidents: [] }, `reconcile-recover-${op.operationId}`);
      status = String(rec["operationStatus"]);
    }
    const jdir = journalDirOf(le.dataHome, run.runId, op.operationId);
    const journal = await readFile(join(jdir, "journal.json"), "utf8").then((t) => JSON.parse(t) as Journal).catch(() => null);
    const root = journal?.repositoryRoot ?? (await canonicalizePath(run.meta.repository_root));
    const files: ReconcileReport["applications"][number]["files"] = [];
    for (const f of journal?.files ?? []) {
      const s = await stateOf(root, absoluteOf(root, f.path), f).catch((): ApplyFileState => "unknown");
      files.push({ path: f.path, kind: f.kind, state_before: s, state_after: s });
    }
    const atPost = files.filter((f) => atPostimage(f.kind as ConfirmedChange["kind"], f.state_before)).length;
    // No journal: the process died before its journal was written, which is before the first write.
    const observed = files.length === 0 || atPost === 0 ? "none" : atPost === files.length ? "all_at_postimage" : "partial";
    const temporaries = await temporariesPresent(journal?.temporaries ?? []);
    const entry: ReconcileReport["applications"][number] = {
      apply_operation_id: op.operationId, fix_operation_id: String(op.begin["fixOperationId"] ?? ""), status_before: status, status_after: status, observed, journal: journal ? "present" : "missing", files, choice: null, lock_cleared: false,
      temporary_files: temporaries.map((a) => ({ path: relative(root, a).split(sep).join("/"), removed: false })), detail: null,
    };
    report.applications.push(entry);
    if (choice === null) continue;
    if (choice === "restore" && journal) {
      for (const [i, f] of journal.files.entries()) {
        const file = files[i]!;
        if (!atPostimage(f.kind, file.state_before)) continue;
        const abs = absoluteOf(root, f.path);
        try {
          if (f.kind === "add") await unlink(abs);
          else {
            const pre = await readFile(join(jdir, f.preimageFile!));
            if (sha256(pre) !== f.preimage!.sha256) throw refused(`the journaled preimage of ${f.path} does not hash to its preimage`);
            const p = await verifyParent(root, abs, new Map());
            const t: Target = { change: { path: f.path, kind: f.kind, executable: false, preimage: f.preimage, postimage: f.postimage, content: null }, abs, parent: p.parent, missing: [], parentId: p.parentId, preBytes: pre, post: null };
            await replaceVerified(t, root, pre, f.kind === "modify" ? f.postimage : null, {}, async (tmp) => {
              journal.temporaries = [...(journal.temporaries ?? []), tmp];
              await atomicWriteFile(join(jdir, "journal.json"), JSON.stringify(journal, null, 2));
            });
          }
        } catch (e) {
          entry.detail = `${f.path}: ${e instanceof Error ? e.message : String(e)}`.slice(0, 500);
        }
        file.state_after = await stateOf(root, abs, f).catch((): ApplyFileState => "unknown");
      }
      for (const dir of [...journal.createdDirs].reverse()) await rmdir(dir).catch(() => undefined);
    }
    // The application's own temporary files are not part of the confirmed change: removed on either choice, before the
    // custodian measures the reconciled source.
    for (const [i, a] of temporaries.entries()) entry.temporary_files[i]!.removed = await removeTemporary(root, a).catch(() => false);
    const rec = await ev.transition("apply_reconcile", {
      operationId: op.operationId, choice, observed, files: files.map((f) => ({ path: f.path, state: f.state_after })), detail: entry.detail,
    }, `reconcile-${op.operationId}`);
    entry.status_after = String(rec["operationStatus"]);
    entry.choice = choice;
    // The lock this application held (a dead holder: ownership_unresolved) is cleared once the state is recorded.
    const lp = journal?.lockPath ?? worktreeLockPath(le.dataHome, canonicalPathKey(run.meta.repository_root));
    const info = await readWorktreeLock(lp);
    if (info && info.kind === FIX_APPLY_LOCK_KIND && (journal ? info.operation_id === journal.lockOperationId : true)) {
      await clearWorktreeOwnership(lp);
      entry.lock_cleared = true;
    }
    await rm(jdir, { recursive: true, force: true }).catch(() => undefined);
  }
  return report;
}

/** The journaled temporary files that still exist (without following a link). */
async function temporariesPresent(list: readonly string[]): Promise<string[]> {
  const out: string[] = [];
  for (const a of list) if ((await lstat(a).catch(() => null)) !== null) out.push(a);
  return out;
}

/** Remove one journaled temporary file: only a regular, single-link file at that exact name, inside the repository, whose
 * parent is a real directory reached by its own name — never through a link, a junction or a redirected directory. */
async function removeTemporary(root: string, abs: string): Promise<boolean> {
  const parent = dirname(abs);
  if (!isContainedIn(abs, root) || samePath(abs, root) || !basename(abs).startsWith(".cp-fix-")) return false;
  if (!samePath(parent, root) && (await firstLinkComponent(parent, root, new Map())) !== null) return false;
  if (!samePath(await realpath(parent).catch(() => ""), parent)) return false;
  const st = await lstat(abs, { bigint: true }).catch(() => null);
  if (!st || st.isSymbolicLink() || !st.isFile() || st.nlink !== 1n) return false;
  await unlink(abs);
  return true;
}

/** The journals of applications this data home still holds for `runId` (reconciliation leftovers). */
export async function pendingJournals(dataHome: string, runId: string): Promise<string[]> {
  return readdir(join(dataHome, "fix-apply", runId)).catch(() => []);
}

/** The separator of the platform's paths (tests build absolute paths with it). */
export const PATH_SEPARATOR = sep;
