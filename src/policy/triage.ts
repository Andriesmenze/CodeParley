// Triage of reviewer output (plan §13.3, §12.7; D-12, MR-K). PURE: no I/O, no clock.
//
// Classes:
//   established_defect  claim_type defect, ≥1 VALID in-scope evidence of kind code_reference,
//                       counterexample or check_output, impacts not empty, consequence not
//                       empty, category ≠ style, confidence ≠ low
//   serious_concern     not established, and severity critical/high, or category security,
//                       or impacts include security — whatever the confidence (never dropped)
//   minor_concern       any other defect or risk
//   note                suggestion, or style
// "Established" is established PER THE REVIEWER'S EVIDENCE, never engine-verified (MR-K).
// Evidence references are validated where practical: the path exists in the reviewed
// export, the line range lies within that file, the kind is known. A reference that fails
// is kept (marked) but does not count, so the finding is triaged without it and a policy
// note says so. Triage affects reporting only: M1 has no PASS.

import type { EvidenceOut, FindingOut, ReviewOutput, StoredEvidence, Triage } from "../schemas/review.js";

export const TRIAGE_POLICY_VERSION = "triage.v1";
export const ESTABLISHED_LABEL = "established per reviewer evidence (not engine-verified)";

/** Lines per file in the reviewed export, keyed by lower-cased repository-relative path. */
export interface ExportIndex {
  current: ReadonlyMap<string, { path: string; lines: number }>;
  base: ReadonlyMap<string, { path: string; lines: number }>;
  /** Confidential / repository-context paths (never valid references, MR-F). */
  withheld: ReadonlySet<string>;
  /**
   * The key `current` and `base` are indexed by, and that reported paths are looked up with:
   * the platform's name rules (Windows: lower case; Linux: exact, so `Case.ts` and `case.ts`
   * stay two files). Default: lower case.
   */
  key?: (path: string) => string;
}

const lowerKey = (p: string): string => p.toLowerCase();

/** Count lines of a text buffer (a final line without a newline counts). */
export function countLines(bytes: Buffer): number {
  if (bytes.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < bytes.length; i++) if (bytes[i] === 0x0a) n++;
  return bytes[bytes.length - 1] === 0x0a ? n : n + 1;
}

/** Normalize a model-reported path to repository-relative form (display data only, §8.3 rule 7). */
export function normalizeReportedPath(p: string): string {
  return parseReportedPath(p).path;
}

/**
 * Split a model-reported path into the version it names and its repository-relative path
 * (F7): `review/base/…` is the BASE version; `tree/…`, `context/…`, `review/head/…` and a
 * bare path are the CURRENT version (review/head holds current copies of changed files).
 */
export function parseReportedPath(p: string): { path: string; version: "current" | "base" | null } {
  let s = p.trim().replace(/\\/g, "/");
  while (s.startsWith("./")) s = s.slice(2);
  const lower = s.toLowerCase();
  if (lower.startsWith("review/base/")) return { path: s.slice("review/base/".length), version: "base" };
  for (const prefix of ["tree/", "context/", "review/head/"]) {
    if (lower.startsWith(prefix)) return { path: s.slice(prefix.length), version: "current" };
  }
  return { path: s, version: null };
}

const LOCATION_KINDS = new Set(["code_reference", "counterexample", "check_output"]);

/**
 * Validate one evidence reference against EXACTLY the version it targets (F7). An explicit
 * `review/base/` reference is checked against the base copy only; any other reference is
 * checked against the current version only, so an older, longer base can never make an
 * out-of-range current reference look valid. A bare path naming a file that exists only as
 * a base (a deleted file) is a base reference and is recorded as such.
 */
export function validateEvidence(e: EvidenceOut, index: ExportIndex): StoredEvidence {
  const base = { kind: e.kind, detail: e.detail, path: e.path, start_line: e.start_line, end_line: e.end_line };
  if (e.path === null || e.path.trim() === "") {
    return { ...base, version: null, in_scope: false, validation: LOCATION_KINDS.has(e.kind) ? "no_location" : "not_applicable" };
  }
  const parsed = parseReportedPath(e.path);
  const rel = parsed.path;
  const keyOf = index.key ?? lowerKey;
  const key = keyOf(rel);
  if (/^[a-z]:\//i.test(rel) || rel.startsWith("/") || rel.split("/").includes("..")) return { ...base, path: rel, version: parsed.version, in_scope: false, validation: "path_not_in_export" };
  if ([...index.withheld].some((w) => keyOf(w) === key)) return { ...base, path: rel, version: parsed.version, in_scope: false, validation: "path_withheld" };
  const cur = index.current.get(key);
  const old = index.base.get(key);
  const version: "current" | "base" = parsed.version ?? (cur ? "current" : old ? "base" : "current");
  const target = version === "base" ? old : cur;
  if (!target) return { ...base, path: rel, version, in_scope: false, validation: "path_not_in_export" };
  if (e.start_line === null && e.end_line === null) return { ...base, path: target.path, version, in_scope: true, validation: "valid" };
  const s = e.start_line;
  const en = e.end_line ?? e.start_line;
  if (s === null || en === null || !Number.isInteger(s) || !Number.isInteger(en) || s < 1 || en < s) return { ...base, path: target.path, version, in_scope: false, validation: "invalid_line" };
  if (en > Math.max(target.lines, 1)) return { ...base, path: target.path, version, in_scope: false, validation: "line_out_of_range" };
  return { ...base, path: target.path, version, in_scope: true, validation: "valid" };
}

export interface TriageResult {
  triage: Triage;
  notes: string[];
  evidence: StoredEvidence[];
}

const isSecurity = (f: FindingOut) => f.category === "security" || f.impacts.includes("security");

export function triageFinding(f: FindingOut, index: ExportIndex): TriageResult {
  const evidence = f.evidence.map((e) => validateEvidence(e, index));
  const notes: string[] = [];
  const failed = evidence.filter((e) => e.validation !== "valid" && e.validation !== "not_applicable");
  if (failed.length > 0) {
    notes.push(`${failed.length} evidence reference(s) failed validation (${[...new Set(failed.map((e) => e.validation))].join(", ")}); triaged without them`);
  }
  const strong = evidence.some((e) => LOCATION_KINDS.has(e.kind) && e.in_scope && e.validation === "valid");
  const strongIgnoringValidation = f.evidence.some((e) => LOCATION_KINDS.has(e.kind) && e.path !== null && e.path.trim() !== "");
  const establishedShape =
    f.claim_type === "defect" && f.impacts.length > 0 && f.consequence.trim().length > 0 && f.category !== "style" && f.confidence !== "low";

  let triage: Triage;
  if (establishedShape && strong) {
    triage = "established_defect";
    notes.push(ESTABLISHED_LABEL);
  } else if ((f.claim_type !== "suggestion" || isSecurity(f)) && (f.severity === "critical" || f.severity === "high" || isSecurity(f))) {
    triage = "serious_concern";
    if (establishedShape && strongIgnoringValidation && !strong) notes.push("downgraded from established_defect: no evidence reference validated against the reviewed export (MR-K)");
  } else if (f.claim_type === "suggestion" || f.category === "style") {
    triage = "note";
  } else {
    triage = "minor_concern";
    if (establishedShape && strongIgnoringValidation && !strong) notes.push("downgraded from established_defect: no evidence reference validated against the reviewed export (MR-K)");
  }
  return { triage, notes, evidence };
}

export const OPEN_TRIAGE: ReadonlySet<Triage> = new Set(["established_defect", "serious_concern", "blocking_question"]);
const RANK: Record<Triage, number> = { established_defect: 3, serious_concern: 2, blocking_question: 2, minor_concern: 1, question: 0, note: 0 };
export function triageRank(t: Triage): number {
  return RANK[t];
}

/** Display clamps (§12.7 "text clamped"); validation caps are in the schema. */
export const CLAMP = { summary: 1000, assessment: 6000, title: 300, text: 4000, evidenceDetail: 2000, note: 1000 } as const;

export function clamp(s: string, max: number, counter: { n: number }): string {
  if (s.length <= max) return s;
  counter.n++;
  return `${s.slice(0, max - 1)}…`;
}

/**
 * Advisory-verdict conflicts with the triage are recorded, never acted on (§13.3).
 * `openCount` counts the reviewer items open after carry-forward (this review's and earlier
 * rounds'); `findingCount` counts this review's new findings, whatever their triage. A
 * re-review may keep requiring changes for a prior item it found still present, so
 * CHANGES_REQUIRED conflicts only when the review raised no finding and nothing is open.
 */
export function verdictConflicts(out: ReviewOutput, openCount: number, findingCount: number): string[] {
  const c: string[] = [];
  if (out.verdict === "APPROVE" && openCount > 0) c.push(`verdict_conflict: APPROVE alongside ${openCount} open reviewer item(s)`);
  if (out.verdict === "CHANGES_REQUIRED" && findingCount === 0 && openCount === 0) c.push("verdict_conflict: CHANGES_REQUIRED without any finding");
  return c;
}
