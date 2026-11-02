// Carry-forward of REVIEWER items across review rounds (plan §13.2, §13.4; MR-D). PURE.
//
// Only reviewer-owned items (findings and blocking questions a reviewer raised) can be
// assessed by a later reviewer, and only through the aliases the bundle listed. Engine-owned
// conditions — failed, stale, missing or removed checks, capture exclusions and other
// coverage limitations, isolation incidents — have no alias, are never items, and are
// derived from engine records at report time, so no reviewer statement can touch them.
//
// Effects of a later reviewer's assessment of an OPEN item:
//   still_present          stays open
//   apparently_resolved    → reported_resolved (reported by the reviewer, NOT verified) only
//                          when this review's source differs from the last source on which
//                          the item was raised or seen present; otherwise ignored
//   no_longer_assessable   stays open (limitation prior_item_not_assessable)
//   superseded             → superseded only by a new item of this review whose triage is at
//                          least as strong (open class); otherwise stays open
//   (omitted)              stays open (limitation prior_item_not_assessed)
//
// Phase 2.2 (plan §1.15, P2.2-3): a supersession ignored because the new finding is weaker keeps
// its lifecycle effect (none: the old item stays open) but is returned as a RESTATEMENT link — the
// reviewer said the new finding continues the old one, so they share a discussion thread and its
// exchange budget. Restatement changes no item's status.

import type { ItemAssessment, PriorAssessmentOut, ReviewerItem } from "../schemas/review.js";
import { OPEN_TRIAGE, triageRank } from "./triage.js";

export interface PriorEntry {
  alias: string;
  item: ReviewerItem;
}

export interface NewItemRef {
  index: number;
  id: string;
  triage: ReviewerItem["triage"];
}

export interface CarryForwardInput {
  reviewId: string;
  round: number;
  sourceId: string;
  /** Open items presented in this review's bundle, with their aliases. */
  prior: readonly PriorEntry[];
  /** Open items NOT presented (bundle cap) — recorded as not assessed. */
  notPresented: readonly ReviewerItem[];
  assessments: readonly PriorAssessmentOut[];
  /** This review's new findings, by output index. */
  newFindings: readonly NewItemRef[];
}

export interface CarryForwardResult {
  /** Updated copies of every prior item touched (presented or not). */
  updated: ReviewerItem[];
  /** id → ids of prior items each new finding supersedes. */
  supersedes: Map<string, string[]>;
  /** id → ids of prior items each new finding restates (a supersession ignored as weaker; Phase 2.2). */
  restates: Map<string, string[]>;
  notes: string[];
  notAssessed: string[];
  notAssessable: string[];
  reportedResolved: string[];
}

export function carryForward(i: CarryForwardInput): CarryForwardResult {
  const byAlias = new Map<string, PriorEntry>();
  for (const p of i.prior) {
    byAlias.set(p.alias.toLowerCase(), p);
    byAlias.set(p.item.id.toLowerCase(), p);
  }
  const updated = new Map<string, ReviewerItem>();
  const touch = (it: ReviewerItem): ReviewerItem => {
    const cur = updated.get(it.id) ?? structuredClone(it);
    updated.set(it.id, cur);
    return cur;
  };
  const supersedes = new Map<string, string[]>();
  const restates = new Map<string, string[]>();
  const notes: string[] = [];
  const assessed = new Set<string>();
  const notAssessable: string[] = [];
  const reportedResolved: string[] = [];
  const record = (it: ReviewerItem, a: ItemAssessment["assessment"], note: string, effect: string) =>
    it.assessments.push({ review_id: i.reviewId, round: i.round, source_id: i.sourceId, assessment: a, note: note.slice(0, 1000), effect });

  for (const a of i.assessments) {
    const entry = byAlias.get(a.id.trim().toLowerCase());
    if (!entry) {
      notes.push(`ignored assessment of unknown id ${JSON.stringify(a.id.slice(0, 64))}: only reviewer items listed in the bundle can be assessed; engine-owned conditions (checks, coverage, isolation) cannot`);
      continue;
    }
    if (assessed.has(entry.item.id)) {
      notes.push(`ignored duplicate assessment of ${entry.alias}`);
      continue;
    }
    assessed.add(entry.item.id);
    const it = touch(entry.item);
    switch (a.assessment) {
      case "still_present":
        record(it, a.assessment, a.note, "kept_open");
        break;
      case "no_longer_assessable":
        record(it, a.assessment, a.note, "kept_open:not_assessable");
        notAssessable.push(it.id);
        break;
      case "apparently_resolved": {
        const lastSeen = lastPresentSource(entry.item);
        if (lastSeen === i.sourceId) {
          record(it, a.assessment, a.note, "ignored:same_source");
          notes.push(`${entry.alias}: "apparently_resolved" on the same source it was raised or last seen present on; kept open`);
        } else {
          it.status = "reported_resolved";
          record(it, a.assessment, a.note, "status:reported_resolved");
          reportedResolved.push(it.id);
        }
        break;
      }
      case "superseded": {
        const by = a.superseded_by_index === null ? undefined : i.newFindings.find((n) => n.index === a.superseded_by_index);
        if (!by) {
          record(it, a.assessment, a.note, "ignored:no_superseding_finding");
          notes.push(`${entry.alias}: "superseded" without a valid superseded_by_index; kept open`);
        } else if (!OPEN_TRIAGE.has(by.triage) || triageRank(by.triage) < triageRank(it.triage)) {
          record(it, a.assessment, a.note, "ignored:weaker_superseding_finding");
          restates.set(by.id, [...(restates.get(by.id) ?? []), it.id]);
          notes.push(`${entry.alias}: superseding finding is triaged ${by.triage}, weaker than ${it.triage}; kept open (the two share a discussion thread)`);
        } else {
          it.status = "superseded";
          it.superseded_by = by.id;
          supersedes.set(by.id, [...(supersedes.get(by.id) ?? []), it.id]);
          record(it, a.assessment, a.note, `status:superseded_by:${by.id}`);
        }
        break;
      }
    }
  }

  const notAssessed: string[] = [];
  for (const p of i.prior) {
    if (assessed.has(p.item.id)) continue;
    const it = touch(p.item);
    record(it, "not_assessed", "", "kept_open:not_assessed");
    notAssessed.push(it.id);
  }
  for (const it0 of i.notPresented) {
    const it = touch(it0);
    record(it, "not_assessed", "", "kept_open:not_presented");
    notAssessed.push(it.id);
  }
  return { updated: [...updated.values()], supersedes, restates, notes, notAssessed, notAssessable, reportedResolved };
}

/** The last source the item was raised on or assessed `still_present` on. */
export function lastPresentSource(it: ReviewerItem): string {
  let s = it.source_id;
  for (const a of it.assessments) if (a.assessment === "still_present") s = a.source_id;
  return s;
}
