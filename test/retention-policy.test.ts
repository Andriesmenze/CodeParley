// Purge eligibility (policy/retention.ts; plan §15.5, §15.6; M1.6). Pure: runs everywhere.

import { describe, it, expect } from "vitest";
import { lastActivityMs, oldEnough, purgeVerdict, type RunFacts } from "../src/policy/retention.js";

const DAY = 86_400_000;
const base = (over: Partial<RunFacts> = {}, state: Partial<NonNullable<RunFacts["state"]>> = {}): RunFacts => ({
  runId: "r1",
  plainDirectory: true,
  readError: null,
  metaRunId: "r1",
  createdAt: "2026-01-01T00:00:00.000Z",
  state: { state: "IDLE", updated_at: "2026-01-02T00:00:00.000Z", operations: [{ operation_id: "op-1", kind: "checks", status: "completed" }], ...state },
  ...over,
});
const none = new Set<string>();

describe("purgeVerdict", () => {
  it("an idle, closed, stopped or configuration-error run with nothing running is eligible", () => {
    for (const s of ["IDLE", "CLOSED", "STOPPED", "CONFIGURATION_ERROR"]) expect(purgeVerdict(base({}, { state: s }), none)).toEqual({ eligible: true });
  });

  it("a running operation keeps the run — live server or a dead one whose recovery is not recorded", () => {
    const v = purgeVerdict(base({}, { state: "CHECKING", operations: [{ operation_id: "op-2", kind: "checks", status: "running" }] }), none);
    expect(v).toMatchObject({ eligible: false, code: "active_operation" });
    // Even when the stored run state claims idle (a writer's view may lag), a running op wins.
    expect(purgeVerdict(base({}, { state: "IDLE", operations: [{ operation_id: "op-2", kind: "review", status: "running" }] }), none)).toMatchObject({ code: "active_operation" });
  });

  it("an INTERRUPTED run is recovery evidence: kept until the user closes it", () => {
    expect(purgeVerdict(base({}, { state: "INTERRUPTED", operations: [{ operation_id: "op-3", kind: "checks", status: "interrupted" }] }), none)).toMatchObject({ eligible: false, code: "interrupted" });
  });

  it("a worktree lock that references one of its operations keeps it (MR-C evidence)", () => {
    expect(purgeVerdict(base(), new Set(["op-1"]))).toMatchObject({ eligible: false, code: "worktree_lock" });
    expect(purgeVerdict(base(), new Set(["other"]))).toEqual({ eligible: true });
  });

  it("unreadable, newer-schema, inconsistent and linked runs are kept", () => {
    expect(purgeVerdict(base({ readError: { code: "INTERNAL", detail: "bad json" }, state: null }), none)).toMatchObject({ code: "unreadable" });
    expect(purgeVerdict(base({ readError: { code: "STORE_VERSION_UNSUPPORTED", detail: "v9" }, state: null }), none)).toMatchObject({ code: "newer_schema" });
    expect(purgeVerdict(base({ metaRunId: "someone-else" }), none)).toMatchObject({ code: "inconsistent" });
    expect(purgeVerdict(base({}, { state: "REVIEWING" }), none)).toMatchObject({ code: "inconsistent" });
    expect(purgeVerdict(base({ plainDirectory: false }), none)).toMatchObject({ code: "link_in_store" });
  });
});

describe("age", () => {
  it("last activity is the later of the last commit and creation; unknown age is never old enough", () => {
    const f = base();
    expect(lastActivityMs(f)).toBe(Date.parse("2026-01-02T00:00:00.000Z"));
    expect(lastActivityMs({ state: null, createdAt: null })).toBeNull();
    const now = Date.parse("2026-02-01T00:00:00.000Z");
    expect(oldEnough(lastActivityMs(f), now, 30 * DAY)).toBe(true);
    expect(oldEnough(lastActivityMs(f), now, 31 * DAY)).toBe(false);
    expect(oldEnough(null, now, 0)).toBe(false);
    // A clock skew into the future is simply "recent".
    expect(oldEnough(now + DAY, now, 0)).toBe(false);
  });
});
