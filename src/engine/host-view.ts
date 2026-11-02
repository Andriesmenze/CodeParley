// Host-facing view of engine results (MR-F, plan §11.1, §16.2; M1.5). The withheld names and
// hashes come from the engine's OWN capture records for the run (every capture it made:
// baseline and review exports), from the disclosure records of implementer responses (Phase
// 2.1: what each response's source read withheld), plus any source identity computed during
// the call. The transformation and the invariant are the M1.4 policy functions; this module
// only collects their inputs and fails closed when the invariant does not hold.

import { DomainError } from "../common/errors.js";
import { resolveArtifact } from "../store/artifacts.js";
import { readTextIfExists } from "../store/atomic.js";
import { readState } from "../store/state-store.js";
import { withheldPaths } from "../capture/manifest.js";
import { CaptureRecordSchema, type SourceEntry } from "../schemas/capture.js";
import { ResponseDisclosureSchema } from "../schemas/responses.js";
import { RATIONALE_EXCERPT_CHARS } from "../policy/responses.js";
import type { StateRecord } from "../schemas/run-state.js";
import { assertHostConfidential, hostValue, localValue, type HostDisclosure } from "../policy/host-disclosure.js";
import { evidenceSelection, pathDisclosure, type Loaded, type RunHandle } from "./engine-env.js";
import { readFile } from "node:fs/promises";
import { sha256OfBytes } from "../common/hash.js";
import { custodianEvidenceFor } from "./custodian-evidence.js";
import { operatorRunSection } from "./protected-user-records.js";
import { captureDigestsOf, hydratedSectionOf, rawStateOf } from "./run-evidence.js";

/** What one record (a capture, a response's source read, this call's read) withholds. */
interface Withheld {
  /** Withheld whatever else is known: confidential names, and a capture's own exclusions. */
  paths: Set<string>;
  hashes: Set<string>;
  /**
   * Files a source read found under the repository's review.exclude_paths, with their hashes. A
   * review export withholds such a file unless it is a change under review (plan §7.2); a read
   * knows no change set, so it reports every match and viewWithheld decides.
   */
  repoContext: Map<string, Set<string>>;
  /** A capture's changes (path and old path): names its export carried as reviewed changes. */
  reviewedChanges: Set<string>;
}

function emptyWithheld(): Withheld {
  return { paths: new Set(), hashes: new Set(), repoContext: new Map(), reviewedChanges: new Set() };
}

/** Capture records are immutable artifacts: cache their withheld sets by absolute path. */
const recordCache = new Map<string, Withheld>();

async function withheldOfRecord(runDir: string, ref: string, bound?: string): Promise<Withheld> {
  const abs = resolveArtifact(runDir, ref);
  if (bound !== undefined) {
    // P3.4C-3 C6: a protected run's capture record must have the digest the custodian holds, read now (never from the
    // cache): a record shrunk after recording would under-redact, so a mismatch refuses the view.
    const bytes = await readFile(abs).catch(() => null);
    if (!bytes || sha256OfBytes(bytes) !== bound) throw new Error(`capture record ${ref} does not have the digest the custodian holds for it`);
    const key = `${abs}#${bound}`;
    const hit = recordCache.get(key);
    if (hit) return hit;
    const out = withheldOfCapture(bytes.toString("utf8"));
    recordCache.set(key, out);
    return out;
  }
  const hit = recordCache.get(abs);
  if (hit) return hit;
  const raw = await readTextIfExists(abs);
  // A record the run's state refers to that is missing or empty is NOT "nothing withheld": its
  // withheld names are unknown, so the caller must fail closed (dogfood verification, M1.6-15).
  // Only a successfully parsed record is cached.
  if (!raw) throw new Error(`capture record ${ref} is missing or empty`);
  const out = withheldOfCapture(raw);
  if (recordCache.size > 2000) recordCache.clear();
  recordCache.set(abs, out);
  return out;
}

function withheldOfCapture(raw: string): Withheld {
  const out = emptyWithheld();
  const rec = CaptureRecordSchema.parse(JSON.parse(raw));
  for (const p of withheldPaths(rec.entries, rec.changes)) out.paths.add(p);
  addEntryHashes(out.hashes, rec.entries, out.paths);
  for (const c of rec.changes) {
    if (c.confidential && c.base?.oid) out.hashes.add(c.base.oid);
    out.reviewedChanges.add(c.path);
    if (c.old_path) out.reviewedChanges.add(c.old_path);
  }
  return out;
}

/**
 * C6: the custodian's capture digests of a protected run (by artifact ref; empty for an attended run). Taken from a
 * state hydrated from its run record, else asked of the custodian; a run marked protected whose custodian cannot
 * answer refuses the view (fail closed: the withheld set cannot be established).
 */
async function boundCaptureDigests(le: Loaded, run: RunHandle, st: StateRecord): Promise<Map<string, string>> {
  const hydrated = hydratedSectionOf(st);
  if (hydrated) return captureDigestsOf(hydrated, rawStateOf(st));
  try {
    const ev = await custodianEvidenceFor(evidenceSelection(le, run), st);
    return ev ? captureDigestsOf(await ev.runSection(), st) : new Map();
  } catch (e) {
    // The operator's CLI reaches only the operator pipe: read the run section there (the OS caller identity decides
    // which surface answers; both are reads).
    const section = await operatorRunSection(le, run).catch(() => {
      throw e;
    });
    return captureDigestsOf(section, st);
  }
}

/**
 * A response's disclosure record (Phase 2.1): the names and hashes its source read withheld.
 * Missing or unreadable is NOT "nothing withheld": the caller fails closed. Cached once parsed.
 */
async function withheldOfResponseDisclosure(runDir: string, ref: string, bound?: string): Promise<Withheld> {
  const abs = resolveArtifact(runDir, ref);
  let raw: string | null;
  let key = abs;
  if (bound !== undefined) {
    // P3.4C-3 N8: on a protected run the record must have the digest the custodian holds for its response set, read
    // now; a shrunken record would under-redact, so a mismatch refuses the view.
    const bytes = await readFile(abs).catch(() => null);
    if (!bytes || sha256OfBytes(bytes) !== bound) throw new Error(`response disclosure record ${ref} does not have the digest the custodian holds for it`);
    raw = bytes.toString("utf8");
    key = `${abs}#${bound}`;
  } else {
    const hit = recordCache.get(abs);
    if (hit) return hit;
    raw = await readTextIfExists(abs);
  }
  if (!raw) throw new Error(`response disclosure record ${ref} is missing or empty`);
  const hit = recordCache.get(key);
  if (hit) return hit;
  const rec = ResponseDisclosureSchema.parse(JSON.parse(raw));
  const out = withheldOfRead({ paths: rec.withheld_paths, hashes: rec.withheld_hashes, repoContext: rec.repo_context });
  if (recordCache.size > 2000) recordCache.clear();
  recordCache.set(key, out);
  return out;
}

/**
 * Phase 5 F-i2-5 (the TD's interim correction): the withheld names and hashes of a redaction the CUSTODIAN's helper makes
 * for a protected amendment — the same parts and the same rules as disclosureFor(le, run, { entries }) on the accepted
 * Windows workflow: every capture record of the run (each review's and the baseline's), every response set's disclosure
 * record, and the current read, combined by viewWithheld. The records are the custodian's held copies, each already
 * checked against the digest its run record binds (the caller verifies them; a record that does not parse throws: fail
 * closed, nothing is shrunk).
 */
export function withheldOfHeldRecords(records: readonly { kind: "capture" | "disclosure"; text: string }[], entries: readonly SourceEntry[]): { paths: Set<string>; hashes: Set<string> } {
  const parts: Withheld[] = records.map((r) => {
    if (r.kind === "capture") return withheldOfCapture(r.text);
    const rec = ResponseDisclosureSchema.parse(JSON.parse(r.text));
    return withheldOfRead({ paths: rec.withheld_paths, hashes: rec.withheld_hashes, repoContext: rec.repo_context });
  });
  parts.push(withheldOfRead(withheldOfEntries(entries)));
  return viewWithheld(parts);
}

/**
 * References of every disclosure record the run's state points to: what the source read of each
 * implementer response (Phase 2.1) and of each user record with text (Phase 2.3: decision notes,
 * task amendments) had to withhold. Their text can name a file no capture record knows.
 */
export function responseDisclosureRefsOf(st: StateRecord): string[] {
  const refs = new Set<string>();
  for (const r of st.implementer_responses) if (r.disclosure_ref) refs.add(r.disclosure_ref);
  for (const d of st.user_decisions ?? []) if (d.disclosure_ref) refs.add(d.disclosure_ref);
  for (const a of st.task_amendments ?? []) if (a.disclosure_ref) refs.add(a.disclosure_ref);
  return [...refs];
}

/**
 * The hashes that identify withheld files' content: the content SHA-256 and the git object id
 * (a host-authored text can name either; Codex review of PR #10).
 */
function addEntryHashes(hashes: Set<string>, entries: readonly SourceEntry[], withheld: ReadonlySet<string>): void {
  for (const e of entries) {
    if (!withheld.has(e.path)) continue;
    if (e.sha256) hashes.add(e.sha256);
    if (e.git_oid) hashes.add(e.git_oid);
  }
}

/** A source read's withheld set, as a response's disclosure record keeps it. */
export interface ReadWithheld {
  paths: string[];
  hashes: string[];
  repoContext: { path: string; hashes: string[] }[];
}

/**
 * The withheld names and hashes among a source read's entries: the confidential ones, and
 * apart from them the files the read marked as repository context (computeSourceIdentity).
 */
export function withheldOfEntries(entries: readonly SourceEntry[]): ReadWithheld {
  const confidential = new Set(entries.filter((e) => e.class === "excluded").map((e) => e.path));
  const hashes = new Set<string>();
  addEntryHashes(hashes, entries, confidential);
  const repoContext = entries
    .filter((e) => e.disposition === "excluded_repo_context" && !confidential.has(e.path))
    .map((e) => ({ path: e.path, hashes: [e.sha256, e.git_oid].filter((h): h is string => !!h) }));
  return { paths: [...confidential], hashes: [...hashes], repoContext };
}

/**
 * Phase 5 OI-1: a read's disclosure record (`arl.response-disclosure.v1`, the format the accepted Windows workflow keeps for
 * every user record's read), always written — empty arrays when the read withheld nothing — so the custodian can hold
 * what a custodian-redacted amendment's read withheld and redact the run's later amendments against it.
 */
export function readDisclosureRecord(w: ReadWithheld): string {
  const repoContext = [...w.repoContext].map((r) => ({ path: r.path, hashes: [...r.hashes].sort() })).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return JSON.stringify({ schema: "arl.response-disclosure.v1", withheld_paths: [...w.paths].sort(), withheld_hashes: [...w.hashes].sort(), repo_context: repoContext }, null, 2);
}

function withheldOfRead(r: { paths: readonly string[]; hashes: readonly string[]; repoContext?: readonly { path: string; hashes: readonly string[] }[] }): Withheld {
  const out = emptyWithheld();
  for (const p of r.paths) out.paths.add(p);
  for (const h of r.hashes) out.hashes.add(h);
  for (const c of r.repoContext ?? []) out.repoContext.set(c.path, new Set([...(out.repoContext.get(c.path) ?? []), ...c.hashes]));
  return out;
}

/**
 * The withheld set of one view (exported for tests). Everything the parts withhold outright —
 * the run's capture records, as M1 always did, and every confidential name and hash a source
 * read saw — plus each repository-context file a read saw, unless a capture of the run exported
 * that name as a reviewed change: the export never withholds a changed file (plan §7.2), and a
 * name it showed is not hidden again. Any other match is withheld, with its hashes (Codex review
 * of PR #10); a read knows no change set, so this can withhold a file before its first review.
 */
export function viewWithheld(parts: readonly Withheld[]): { paths: Set<string>; hashes: Set<string> } {
  const out = { paths: new Set<string>(), hashes: new Set<string>() };
  const reviewed = new Set<string>();
  for (const w of parts) {
    for (const p of w.paths) out.paths.add(p);
    for (const h of w.hashes) out.hashes.add(h);
    for (const c of w.reviewedChanges) reviewed.add(c);
  }
  for (const w of parts) {
    for (const [p, hashes] of w.repoContext) {
      if (reviewed.has(p)) continue;
      out.paths.add(p);
      for (const h of hashes) out.hashes.add(h);
    }
  }
  return out;
}

/** For tests: the record shapes viewWithheld combines. */
export const withheldParts = { emptyWithheld, withheldOfRead };

/** References of every capture record the run's state points to. */
export function captureRefsOf(st: StateRecord): string[] {
  const refs = new Set<string>();
  for (const r of st.reviews) if (r.artifacts["capture"]) refs.add(r.artifacts["capture"]);
  for (const op of st.operations) {
    const ref = (op.outcome as { capture_ref?: unknown } | undefined)?.capture_ref;
    if (typeof ref === "string") refs.add(ref);
  }
  return [...refs];
}

/** The disclosure limits for one host result about `run` (null: no run in scope). */
export async function disclosureFor(le: Loaded, run: RunHandle | null, extra: { entries?: readonly SourceEntry[]; state?: StateRecord } = {}): Promise<HostDisclosure> {
  const parts: Withheld[] = [];
  const reason = (e: unknown) => (e instanceof Error ? e.message : String(e)).slice(0, 120);
  if (run) {
    const given = extra.state ?? (await readState(run.paths));
    const st = rawStateOf(given);
    const bound = await boundCaptureDigests(le, run, given).catch((e: unknown) => {
      throw new DomainError("INTERNAL", `the custodian's record of this protected run could not be read, so its withheld names cannot be established; the result is withheld (${reason(e)})`);
    });
    for (const ref of captureRefsOf(st)) {
      // A capture record that cannot be read must not silently shrink the withheld set.
      parts.push(
        await withheldOfRecord(run.paths.runDir, ref, bound.get(ref)).catch((e: unknown) => {
          throw new DomainError("INTERNAL", `a capture record of this run could not be read; the result is withheld (${reason(e)})`);
        }),
      );
    }
    // What the source reads of implementer responses withheld (Phase 2.1): their text may name a
    // file no capture record knows (made confidential or excluded after the last capture).
    for (const ref of responseDisclosureRefsOf(st)) {
      parts.push(
        await withheldOfResponseDisclosure(run.paths.runDir, ref, bound.get(ref)).catch((e: unknown) => {
          throw new DomainError("INTERNAL", `a response disclosure record of this run could not be read; the result is withheld (${reason(e)})`);
        }),
      );
    }
  }
  if (extra.entries) parts.push(withheldOfRead(withheldOfEntries(extra.entries)));
  const all = viewWithheld(parts);
  return { withheldPaths: all.paths, withheldHashes: all.hashes, ...pathDisclosure(le, run?.meta.repository_root ?? null) };
}

/**
 * The value as the host may see it: withheld names/hashes redacted, local paths scrubbed,
 * then the MR-F invariant. Throws (fail closed, nothing of the value returned) if the
 * invariant still fails.
 */
export function toHost<T>(value: T, d: HostDisclosure): { value: T; redactions: number } {
  const counter = { n: 0 };
  const v = cutExcerpts(hostValue(value, d, counter));
  try {
    assertHostConfidential(v, d);
  } catch {
    throw new DomainError("INTERNAL", "the result was withheld because it would disclose a confidential path or hash (MR-F, fail closed)");
  }
  return { value: v, redactions: counter.n };
}

/**
 * The CLI's default view of run information (M1.6): withheld names and hashes redacted,
 * local paths kept, and the same MR-F invariant (fail closed).
 */
export function toLocal<T>(value: T, d: HostDisclosure): { value: T; redactions: number } {
  const counter = { n: 0 };
  const v = cutExcerpts(localValue(value, d, counter));
  try {
    assertHostConfidential(v, d);
  } catch {
    throw new DomainError("INTERNAL", "the output was withheld because it would disclose a confidential path or hash (MR-F, fail closed); --reveal-withheld shows local details");
  }
  return { value: v, redactions: counter.n };
}

/** Fields that reports carry whole and every view shortens to an excerpt of this many characters. */
const EXCERPT_FIELDS = new Map<string, number>([
  ["rationale_excerpt", RATIONALE_EXCERPT_CHARS],
  // Phase 2.2: reviewer replies and item titles in thread summaries.
  ["reply_excerpt", RATIONALE_EXCERPT_CHARS],
  ["title_excerpt", 120],
  // Phase 2.3: user decision notes and task amendment texts in summaries.
  ["note_excerpt", RATIONALE_EXCERPT_CHARS],
  ["text_excerpt", RATIONALE_EXCERPT_CHARS],
]);

/**
 * Shorten excerpt fields (Phase 2.1). Views call this AFTER redaction: a cut made before it could
 * end inside a withheld name, and the matcher does not recognize the fragment that remains.
 */
export function cutExcerpts<T>(value: T): T {
  const visit = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(visit);
    if (!v || typeof v !== "object") return v;
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      const max = EXCERPT_FIELDS.get(k);
      o[k] = max !== undefined && typeof x === "string" && x.length > max ? `${x.slice(0, max - 1)}…` : visit(x);
    }
    return o;
  };
  return visit(value) as T;
}

/**
 * Phase 2.2 (plan §1.15, P2.2-9): what discussion text sent to CODEX must not carry. Implementer
 * turns are host-authored text: their names are checked against the current capture's withheld
 * set and every earlier record of the run (capture records, response disclosure records), so a
 * file withheld at any point stays withheld — minus the names the current export itself shows
 * (`exported`, compared with `key`): exported repository context is not redacted. A record that
 * cannot be read fails closed (throws), and the review fails before anything is sent.
 */
export async function modelWithheld(
  runDir: string,
  st: StateRecord,
  current: { paths: ReadonlySet<string>; hashes: ReadonlySet<string> },
  exported: ReadonlySet<string>,
  key: (p: string) => string,
): Promise<{ paths: Set<string>; hashes: Set<string> }> {
  const parts: Withheld[] = [];
  // Every record of the run (hydration does not shrink the withheld set); a protected run's bound captures verified.
  const raw = rawStateOf(st);
  const bound = captureDigestsOf(hydratedSectionOf(st), raw);
  for (const ref of captureRefsOf(raw)) parts.push(await withheldOfRecord(runDir, ref, bound.get(ref)));
  for (const ref of responseDisclosureRefsOf(raw)) parts.push(await withheldOfResponseDisclosure(runDir, ref, bound.get(ref)));
  const all = viewWithheld(parts);
  const paths = new Set<string>(current.paths);
  for (const p of all.paths) if (!exported.has(key(p))) paths.add(p);
  return { paths, hashes: new Set([...current.hashes, ...all.hashes]) };
}

/** The exact withheld (confidential) paths of every capture of a run — local CLI use only. */
export async function withheldPathsOfRun(run: RunHandle, state?: StateRecord): Promise<string[]> {
  const st = rawStateOf(state ?? (await readState(run.paths)));
  const parts: Withheld[] = [];
  for (const ref of captureRefsOf(st)) parts.push(await withheldOfRecord(run.paths.runDir, ref));
  for (const ref of responseDisclosureRefsOf(st)) parts.push(await withheldOfResponseDisclosure(run.paths.runDir, ref));
  return [...viewWithheld(parts).paths].sort();
}
