// Discussion threads over reviewer-item lineage (Phase 2.2, plan §1.15 P2.2-1). PURE.
//
// A thread is a connected component of the run's reviewer items under the explicit lineage
// links a reviewer declared: accepted supersession (`supersedes` / `superseded_by`) and
// restatement (`restates`). "Related" (`related_prior_id`) is never a link: related is not the
// same. Threads are DERIVED on every read from those persisted links — there is no thread table
// that could drift — so runs written before Phase 2.2 get threads from their supersession.
//
// Identity: a thread's id is the id of its earliest ROOT (an item that supersedes or restates
// nothing): earliest by round, then the order its review listed it, then id. The other roots of
// a consolidated thread (one item superseding several) are its `merged` ids. Thread ids are
// item ids, so anything that names an item can name its thread.
//
// Robustness: the links come from the run's own state file, which may be damaged. The
// derivation never loops and never throws: a union-find (iterative, path halving) over the
// items, links read per item and link operations in total capped, dangling links (ids that are
// not items of the run) and self-links skipped, and directed cycles found by a topological
// pass. Each anomaly is reported on its thread so that reports can flag it for the user.

import type { ReviewerItem } from "../schemas/review.js";
import { DISCUSSION_LIMITS } from "../schemas/discussion.js";

export type LineageAnomaly = "dangling_link" | "self_link" | "cycle" | "links_truncated";

export interface Thread {
  /** The earliest root's id (or, in a damaged lineage without a root, the earliest member's). */
  id: string;
  /** Members, oldest first (round, then the order their review listed them, then id). */
  members: ReviewerItem[];
  /** The other roots: threads that were consolidated into this one. */
  merged: string[];
  anomalies: LineageAnomaly[];
}

export interface ThreadIndex {
  threads: Map<string, Thread>;
  /** item id → thread id. */
  threadOf: Map<string, string>;
  /** Anomalies over the whole run. */
  anomalyCount: number;
}

export interface LineageBounds {
  linksPerItem: number;
  linkOperations: number;
}

const DEFAULT_BOUNDS: LineageBounds = { linksPerItem: DISCUSSION_LIMITS.linksPerItem, linkOperations: DISCUSSION_LIMITS.linkOperations };

/** The restatement links an item carries (defensive: a damaged value reads as none). */
export function restatesOf(it: ReviewerItem): string[] {
  const r = (it as { restates?: unknown }).restates;
  return Array.isArray(r) ? r.filter((x): x is string => typeof x === "string") : [];
}

/** The predecessor ids an item names itself (supersession and restatement), capped. */
function ownPredecessors(it: ReviewerItem, cap: number): { ids: string[]; truncated: boolean } {
  const raw = [...(Array.isArray(it.supersedes) ? it.supersedes : []), ...restatesOf(it)];
  return { ids: raw.slice(0, cap), truncated: raw.length > cap };
}

/**
 * Order key of items: round, then the position the raising review listed the item at, then id.
 * `positions` maps item id → index in its review's item list (UUIDv7 ids are not ordered within
 * one millisecond).
 */
export function itemOrder(positions: ReadonlyMap<string, number>): (a: ReviewerItem, b: ReviewerItem) => number {
  return (a, b) => a.round - b.round || (positions.get(a.id) ?? 0) - (positions.get(b.id) ?? 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** Item positions within their raising review (for the order key). */
export function itemPositions(reviews: readonly { item_ids: readonly string[] }[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const r of reviews)
    r.item_ids.forEach((id, k) => {
      out.set(id, k);
    });
  return out;
}

export function buildThreads(items: readonly ReviewerItem[], positions: ReadonlyMap<string, number>, bounds: LineageBounds = DEFAULT_BOUNDS): ThreadIndex {
  const index = new Map<string, number>();
  items.forEach((it, k) => {
    if (!index.has(it.id)) index.set(it.id, k);
  });
  const parent = items.map((_, k) => k);
  const find = (k: number): number => {
    let x = k;
    while (parent[x] !== x) {
      parent[x] = parent[parent[x]!]!;
      x = parent[x]!;
    }
    return x;
  };
  const union = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb);
  };
  // Directed predecessor edges (newer item → the item it continues), for roots and cycles.
  const preds = items.map(() => new Set<number>());
  const anomalies = items.map(() => new Set<LineageAnomaly>());
  let operations = 0;
  let exhausted = false;
  const link = (from: number, toId: string): void => {
    if (exhausted) return;
    if (++operations > bounds.linkOperations) {
      exhausted = true;
      anomalies[from]!.add("links_truncated");
      return;
    }
    const to = index.get(toId);
    if (to === undefined) {
      anomalies[from]!.add("dangling_link");
      return;
    }
    if (to === from) {
      anomalies[from]!.add("self_link");
      return;
    }
    preds[from]!.add(to);
    union(from, to);
  };
  items.forEach((it, k) => {
    if (index.get(it.id) !== k) return; // a duplicate id: the first record is the item
    const own = ownPredecessors(it, bounds.linksPerItem);
    if (own.truncated) anomalies[k]!.add("links_truncated");
    for (const id of own.ids) link(k, id);
    // The reverse spelling of supersession: the successor continues this item.
    if (typeof it.superseded_by === "string") {
      const succ = index.get(it.superseded_by);
      if (succ === undefined) anomalies[k]!.add("dangling_link");
      else if (succ === k) anomalies[k]!.add("self_link");
      else if (!exhausted) {
        if (++operations > bounds.linkOperations) {
          exhausted = true;
          anomalies[k]!.add("links_truncated");
        } else {
          preds[succ]!.add(k);
          union(succ, k);
        }
      }
    }
  });
  // Directed cycles (Kahn): what is left after peeling every node without a predecessor.
  const indegree = items.map(() => 0);
  const succs = items.map(() => [] as number[]);
  preds.forEach((ps, k) => {
    for (const p of ps) {
      succs[p]!.push(k);
      indegree[k]!++;
    }
  });
  const remaining = [...indegree];
  const queue: number[] = [];
  remaining.forEach((d, k) => {
    if (d === 0) queue.push(k);
  });
  for (let q = 0; q < queue.length; q++) {
    for (const s of succs[queue[q]!]!) if (--remaining[s]! === 0) queue.push(s);
  }
  remaining.forEach((d, k) => {
    if (d > 0) anomalies[k]!.add("cycle");
  });

  const order = itemOrder(positions);
  const groups = new Map<number, number[]>();
  items.forEach((it, k) => {
    if (index.get(it.id) !== k) return;
    const r = find(k);
    const g = groups.get(r);
    if (g) g.push(k);
    else groups.set(r, [k]);
  });
  const threads = new Map<string, Thread>();
  const threadOf = new Map<string, string>();
  let anomalyCount = 0;
  for (const ks of groups.values()) {
    const members = ks.map((k) => items[k]!).sort(order);
    const roots = ks.filter((k) => preds[k]!.size === 0 && !anomalies[k]!.has("cycle")).map((k) => items[k]!).sort(order);
    const id = (roots[0] ?? members[0]!).id;
    const set = new Set<LineageAnomaly>();
    for (const k of ks) for (const a of anomalies[k]!) set.add(a);
    if (exhausted) set.add("links_truncated");
    anomalyCount += set.size;
    threads.set(id, { id, members, merged: roots.slice(1).map((r) => r.id), anomalies: [...set].sort() });
    for (const m of members) threadOf.set(m.id, id);
  }
  return { threads, threadOf, anomalyCount };
}

/** The thread of an item id (or of a merged thread id), if any. */
export function threadFor(ix: ThreadIndex, id: string): Thread | null {
  const t = ix.threadOf.get(id);
  return t ? (ix.threads.get(t) ?? null) : null;
}
