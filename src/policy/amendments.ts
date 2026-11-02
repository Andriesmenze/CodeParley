// Task amendments (Phase 2.3, plan §1.16 P2.3-8 to -10). PURE: no I/O, no clock.
//
// The task envelope in run.json is immutable. The user changes requirements, scope, constraints,
// acceptance criteria, priority or context by appending amendments through the local operator
// interface (P2.3-1). This module derives, on every read:
//  - which records count at all: only those with a recognized provenance (role user, channel
//    local_cli, assurance local_operator today; USER_ASSURANCES);
//  - the EFFECTIVE set: every amendment neither replaced by a later one nor a withdrawal;
//  - who has seen what: an amendment is seen by the reviewer only through the delivery record of
//    an ACCEPTED review (P2.2-6's rule), never because a review happened after it;
//  - the new-information gate's amendment basis (P2.3-10): an amendment that names a thread is new
//    information for that thread until Codex has replied having seen it — or seen the same content
//    in another amendment — so one amendment unlocks at most one exchange per thread, re-recording
//    the same content unlocks nothing, and no budget is ever reset;
//  - the checks on a new amendment (kind, text, relates_to, replaces, duplicates, bounds).

import { sha256OfCanonicalJson } from "../common/hash.js";
import { AMENDMENT_KINDS, CUSTODIAN_ASSURANCES, CUSTODIAN_SERVED, USER_ASSURANCES, USER_LIMITS, USER_ROLE, type TaskAmendment } from "../schemas/user-authority.js";
import { hasUnsafeChars } from "./text-safety.js";

export const AMENDMENT_POLICY_VERSION = "amendments.v1";

const KNOWN_KINDS: ReadonlySet<string> = new Set(AMENDMENT_KINDS);

/**
 * Was the record written by a recognized user channel (P2.3-2)? The role must be the user's and the
 * (channel, assurance) pair one that USER_ASSURANCES defines; anything else is never user authority
 * (fail closed). The custodian's pair counts only on a record the custodian returned to this process
 * (P3.4C-3 C3: `CUSTODIAN_SERVED`); the same label in the user-writable store is unrecognized.
 */
export function isUserChannelRecord(r: { recorded_by: { role: string; channel: string; assurance?: string | undefined } }): boolean {
  const a = r.recorded_by.assurance;
  if (r.recorded_by.role !== USER_ROLE || a === undefined || !Object.hasOwn(USER_ASSURANCES, a) || USER_ASSURANCES[a]!.channel !== r.recorded_by.channel) return false;
  return !CUSTODIAN_ASSURANCES.includes(a) || (r as { [CUSTODIAN_SERVED]?: unknown })[CUSTODIAN_SERVED] === true;
}

/**
 * The comparison form of an amendment's content: its kind and its text, Unicode-normalized, with
 * whitespace runs collapsed and letter case folded — so that re-recording the same words is never
 * new content (P2.3-10).
 */
export function amendmentContentKey(kind: string, text: string): string {
  return `${kind}\u0000${text.normalize("NFC").trim().replace(/\s+/g, " ").toLowerCase()}`;
}

/**
 * The content-equivalence key of a recorded amendment, preserving the exact `amendmentContentKey`
 * equivalence whether the amendment is legacy (raw `text` present — computed here, locally) or PROTECTED
 * (custodian-backed: the custodian supplied `content_key_hash`, a KEYED HMAC of the same normalized key
 * under its secret, and the engine has no raw text). Equivalence is compared only within one run's
 * amendment set, which is either all-legacy or all-custodian (never mixed — no import), so the two never
 * collide and the keyed vs unkeyed forms are never compared against each other. */
export function amendmentContentKeyOf(a: TaskAmendment): string {
  return typeof a.content_key_hash === "string" ? a.content_key_hash : contentKeyHash(a.kind, a.text);
}

/** The LEGACY local content-equivalence key: an UNKEYED hash of the normalized `amendmentContentKey`. Used
 * ONLY for legacy / custodian-less amendments, whose raw `text` is in `state.json` and therefore already
 * visible to the implementer — so this adds no exposure there. It is NOT used for a protected amendment:
 * on the protected path the custodian derives a KEYED HMAC (P3.4C-1 confidentiality correction), which the
 * implementer cannot reverse or reproduce offline, and the engine no longer supplies any content key. */
export function contentKeyHash(kind: string, text: string): string {
  return sha256OfCanonicalJson(["arl.amendment-content-key.v1", amendmentContentKey(kind, text)]);
}

/** The amendment's original text size in UTF-8 bytes, from the custodian metadata (protected) or the raw
 * text (legacy) — for the effective-bytes budget without needing the raw text. */
export function amendmentTextBytes(a: TaskAmendment): number {
  return typeof a.text_bytes === "number" ? a.text_bytes : Buffer.byteLength(a.text, "utf8");
}

/** The review fields this module reads. */
export interface AmendmentReviewLike {
  review_id: string;
  round: number;
  accepted: boolean | null;
  amendments?: { presented: readonly { amendment_id: string }[] } | undefined;
}

export interface AmendmentSeen {
  review_id: string;
  round: number;
  reviewIdx: number;
}

export interface AmendmentFacts {
  /** Records with a recognized provenance, in recording order. */
  all: TaskAmendment[];
  /** Records in the list without a recognized provenance (never user authority; reported). */
  unrecognized: number;
  byId: Map<string, TaskAmendment>;
  /** amendment id → the amendment that replaced (or withdrew) it. */
  replacedBy: Map<string, string>;
  /** Neither replaced nor a withdrawal, in seq order. */
  effective: TaskAmendment[];
  /** Accepted reviews that presented each amendment, oldest first. */
  seen: Map<string, AmendmentSeen[]>;
  /** Content key → the first accepted review index that presented an amendment with that content. */
  contentSeenAt: Map<string, number>;
  /** The run's amendment revision: how many recognized amendments were recorded. */
  seq: number;
}

export function buildAmendmentFacts(records: readonly TaskAmendment[], reviews: readonly AmendmentReviewLike[]): AmendmentFacts {
  const all = records.filter(isUserChannelRecord);
  const byId = new Map<string, TaskAmendment>();
  for (const a of all) if (!byId.has(a.amendment_id)) byId.set(a.amendment_id, a);
  const replacedBy = new Map<string, string>();
  for (const a of all) if (a.replaces && byId.has(a.replaces) && !replacedBy.has(a.replaces)) replacedBy.set(a.replaces, a.amendment_id);
  const effective = all.filter((a) => byId.get(a.amendment_id) === a && a.kind !== "withdrawal" && !replacedBy.has(a.amendment_id)).sort((a, b) => a.seq - b.seq);
  const seen = new Map<string, AmendmentSeen[]>();
  const contentSeenAt = new Map<string, number>();
  reviews.forEach((r, k) => {
    if (r.accepted !== true) return;
    for (const p of r.amendments?.presented ?? []) {
      const list = seen.get(p.amendment_id) ?? [];
      list.push({ review_id: r.review_id, round: r.round, reviewIdx: k });
      seen.set(p.amendment_id, list);
      const a = byId.get(p.amendment_id);
      if (a) {
        const key = amendmentContentKeyOf(a);
        if (!contentSeenAt.has(key)) contentSeenAt.set(key, k);
      }
    }
  });
  return { all, unrecognized: records.length - all.length, byId, replacedBy, effective, seen, contentSeenAt, seq: all.reduce((m, a) => Math.max(m, a.seq), 0) };
}

export type AmendmentStatus = "effective" | "replaced" | "withdrawn" | "withdrawal";

export function amendmentStatus(f: AmendmentFacts, a: TaskAmendment): AmendmentStatus {
  if (a.kind === "withdrawal") return "withdrawal";
  const by = f.replacedBy.get(a.amendment_id);
  if (!by) return "effective";
  return f.byId.get(by)?.kind === "withdrawal" ? "withdrawn" : "replaced";
}

/** The first accepted review that presented the amendment (null: the reviewer has not seen it). */
export function amendmentSeenBy(f: AmendmentFacts, amendmentId: string): { review_id: string; round: number } | null {
  const s = f.seen.get(amendmentId)?.[0];
  return s ? { review_id: s.review_id, round: s.round } : null;
}

/**
 * The effective amendments that are NEW information for a thread (P2.3-10): they name the thread
 * (a `relates_to` id is one of its items), and neither they nor an amendment with the same content
 * were presented to an accepted review up to `lastReplyIdx` — the review of the thread's latest
 * reviewer reply. Once Codex has replied having seen them, they no longer count.
 */
export function newAmendmentsFor(f: AmendmentFacts, threadItemIds: ReadonlySet<string>, lastReplyIdx: number): TaskAmendment[] {
  return f.effective.filter((a) => {
    if (!a.relates_to.some((id) => threadItemIds.has(id))) return false;
    if ((f.seen.get(a.amendment_id) ?? []).some((s) => s.reviewIdx <= lastReplyIdx)) return false;
    const at = f.contentSeenAt.get(amendmentContentKeyOf(a));
    return at === undefined || at > lastReplyIdx;
  });
}

/** The effective amendments a review presented compared with now (completion, P2.3-11). */
export function amendmentDelta(f: AmendmentFacts, presentedIds: readonly string[]): { not_presented: string[]; no_longer_effective: string[] } {
  const presented = new Set(presentedIds);
  const effective = new Set(f.effective.map((a) => a.amendment_id));
  return {
    not_presented: f.effective.filter((a) => !presented.has(a.amendment_id)).map((a) => a.amendment_id),
    no_longer_effective: [...presented].filter((id) => !effective.has(id)),
  };
}

/**
 * The guidance for effective amendments a review withheld because the confidentiality scan could not
 * clear their text within its bound: a later review withholds them again, so the user replaces them.
 */
export function amendmentWithheldDetail(labels: readonly string[], review: string): string {
  const why = `the user's amendment(s) ${labels.join(", ")} were withheld from ${review}: the confidentiality scan could not clear their text within its bound, and a later review withholds them again.`;
  return [why, "The user replaces each one with new text: code-parley amend <run> <kind> (--text … | --text-file …) --replaces", labels.length === 1 ? labels[0] : "A-n"].join(" ");
}

// ---------------------------------------------------------------------------
// A new amendment
// ---------------------------------------------------------------------------

export interface AmendmentInput {
  kind: string;
  text: string;
  /** Thread ids (already resolved from item references by the caller). */
  relates_to: readonly string[];
  /** An amendment id (already resolved from a reference by the caller), or null. */
  replaces: string | null;
}

/** Problems with a new amendment against the run's current amendments (each an INVALID_ARGUMENT). */
export function amendmentProblems(input: AmendmentInput, f: AmendmentFacts, threadOf: (id: string) => string = (id) => id): string[] {
  if (!KNOWN_KINDS.has(input.kind)) return [`kind must be one of ${AMENDMENT_KINDS.join(", ")}`];
  if (input.text.length > USER_LIMITS.amendmentChars) return [`the text is at most ${USER_LIMITS.amendmentChars} characters`];
  const problems = [...shapeProblems(input), ...replacesProblems(input, f)];
  if (f.all.length + 1 > USER_LIMITS.amendmentsPerRun) problems.push(`a run keeps at most ${USER_LIMITS.amendmentsPerRun} amendments`);
  if (input.kind !== "withdrawal") problems.push(...contentProblems(input, f, threadOf));
  return problems;
}

/** The amendment's own text, threads and, for a withdrawal, what it withdraws. */
function shapeProblems(input: AmendmentInput): string[] {
  const problems: string[] = [];
  if (hasUnsafeChars(input.text)) problems.push("the text may not contain control or bidirectional-override characters");
  if (input.kind !== "withdrawal" && input.text.trim() === "") problems.push(`a ${input.kind} amendment needs a text`);
  if (input.relates_to.length > USER_LIMITS.relatesToPerAmendment) problems.push(`at most ${USER_LIMITS.relatesToPerAmendment} threads`);
  if (input.kind === "withdrawal" && input.replaces === null) problems.push("a withdrawal names the amendment it withdraws (--replaces)");
  return problems;
}

/** Only an effective amendment of this run can be replaced or withdrawn. */
function replacesProblems(input: AmendmentInput, f: AmendmentFacts): string[] {
  if (input.replaces === null) return [];
  const r = f.byId.get(input.replaces);
  if (!r) return ["--replaces names no amendment of this run"];
  const status = amendmentStatus(f, r);
  return status === "effective" ? [] : [`amendment ${r.amendment_id} is no longer effective (${status}); only an effective amendment can be replaced`];
}

/**
 * Content already in effect (nothing new), or effective text over its bound. Thread scopes compare
 * as the lineage stands now (`threadOf`: an item to its current thread), so a consolidation cannot
 * make a repetition look new.
 */
function contentProblems(input: AmendmentInput, f: AmendmentFacts, threadOf: (id: string) => string): string[] {
  const problems: string[] = [];
  const key = contentKeyHash(input.kind, input.text);
  const scope = (ids: readonly string[]) => [...new Set(ids.map(threadOf))].sort().join("\u0000");
  const rel = scope(input.relates_to);
  // Equal to any amendment in effect, the one it replaces included: it would change nothing (P2.3-8).
  const dup = f.effective.find((a) => amendmentContentKeyOf(a) === key && scope(a.relates_to) === rel);
  if (dup) problems.push(`an identical amendment is already in effect (A-${dup.seq}); nothing new would be recorded`);
  const others = f.effective.filter((a) => a.amendment_id !== input.replaces);
  const bytes = others.reduce((n, a) => n + amendmentTextBytes(a), 0) + Buffer.byteLength(input.text, "utf8");
  if (bytes > USER_LIMITS.effectiveAmendmentBytes) problems.push(`the effective amendments would hold ${bytes} bytes of text, over ${USER_LIMITS.effectiveAmendmentBytes}; replace or withdraw an earlier one`);
  return problems;
}

/** The digest a request_id is bound to (`arl.amend-request.v1`). */
export function amendRequestDigest(runId: string, input: AmendmentInput): string {
  return sha256OfCanonicalJson({ schema: "arl.amend-request.v1", run: runId, kind: input.kind, text: input.text, relates_to: [...input.relates_to].sort(), replaces: input.replaces });
}
