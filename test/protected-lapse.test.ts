// P3.4C-3 (contract §2.4 U4): after a custodian recovery, waive and defer decisions recorded at or before the recovered
// revision stop applying on a run whose loop is not terminal (their revocation may have been lost); restricting
// decisions (require_resolution), later decisions and amendments stay. Unit tests of the rule on custodian listings.

import { describe, it, expect } from "vitest";
import { fromListing } from "../src/engine/protected-user-records.js";
import type { UserRecordListing } from "../src/custodian/protocol.js";

const decision = (seq: number, kind: string) => ({ recordId: `d-${seq}`, seq, recordKind: "decision", kind, thread_id: `T-${seq}`, current_item_id: `i-${seq}`, covered_items: [`i-${seq}`], supersedes: [], decided_against: null, context: null, recorded_by: {}, recorded_at: "2026-10-13T00:00:00Z", request_digest: null, source_id: null });
const amendment = (seq: number) => ({ recordId: `a-${seq}`, seq, recordKind: "amendment", kind: "clarify", relates_to: [], replaces: null, recorded_by: {}, recorded_at: "2026-10-13T00:00:00Z", request_digest: null, source_id: null });

function listing(records: Record<string, unknown>[], recoveredAtRevision: number | null, loopStatus: string | null): UserRecordListing {
  return {
    governed: true, revision: records.length, logDigest: "x", records, protected: true, recoveredAtRevision,
    loop: loopStatus === null ? null : { protected: true, loopRevision: 1, loopDigest: "y", record: { status: loopStatus } },
    run: null,
  } as unknown as UserRecordListing;
}

describe("§2.4 U4 — the lapse rule", () => {
  const records = [decision(1, "waive"), decision(2, "defer"), decision(3, "require_resolution"), amendment(4), decision(5, "waive")];

  it("a recovery at revision 4 lapses the earlier waive and defer, keeps require_resolution, the amendment and the later waive", () => {
    const a = fromListing(listing(records, 4, "paused"));
    expect(a.lapsed.map((d) => d.decision_id)).toEqual(["d-1", "d-2"]);
    expect(a.decisions.map((d) => d.decision_id)).toEqual(["d-3", "d-5"]);
    expect(a.amendments.map((x) => x.amendment_id)).toEqual(["a-4"]);
  });

  it("no recovery: nothing lapses", () => {
    expect(fromListing(listing(records, null, "active")).lapsed).toEqual([]);
  });

  it("a run whose loop is terminal keeps its decisions", () => {
    expect(fromListing(listing(records, 4, "run_ended")).lapsed).toEqual([]);
  });

  it("a run with no loop record lapses them (fail closed: the operator re-confirms)", () => {
    expect(fromListing(listing(records, 4, null)).lapsed.map((d) => d.decision_id)).toEqual(["d-1", "d-2"]);
  });
});
