// Phase 4 Increment 2 — the custodian's own rules for a delegated fix (the simulated custodian's re-implementation of
// custodian/…/Ledger/FixRules.cs), the FIX self-test confirmation's shape, and the routing of a fix (N4-11). The custodian
// shares no code with the engine's policy (test/delegated-fix-layering.test.ts); here the two path rule sets are held to
// the same verdicts, so the engine's scan and the custodian's validation agree on what a boundary admits.

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  decodeStrictBase64, fixBoundaryDigest, fixBoundaryProblem, fixPathProblem, fixPermitted, fixProposalDigest, fixSensitive, fixTreeDigest, validateFixSubmission,
  type SimBaselineFile, type SimFixBoundary, type SimFixSubmittedChange,
} from "../src/custodian/simulated-fix.js";
import { isPermitted, portablePathProblem, sensitivePathReason, type FixBoundary } from "../src/policy/delegated-fix.js";
import { routeFromEngine, instructionFor, type RoutingFacts } from "../src/policy/continuation.js";
import { snapshotOperationStatus } from "../src/custodian/simulated-derivation.js";
import { SimulatedCustodianTransport } from "../src/custodian/transport.js";
import type { SimRunOperation } from "../src/custodian/simulated-runs.js";

const sha = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");
const b64 = (s: string | Buffer): string => Buffer.from(s).toString("base64");

const BOUNDARY: SimFixBoundary = {
  permittedFiles: [".github/workflows/ci.yml"], permittedDirs: ["src"], allowCreate: true, allowDelete: true, allowBinary: false,
  maxChangedFiles: 5, maxFileBytes: 64, maxTotalBytes: 100, timeLimitSeconds: 600, proposalLifetimeSeconds: 3600,
};
const TREE = new Map<string, SimBaselineFile>([
  ["src/a.ts", { size: 2, sha256: sha("a\n") }],
  [".github/workflows/ci.yml", { size: 9, sha256: sha("on: push\n") }],
  ["docs/x.md", { size: 2, sha256: sha("x\n") }],
]);
const ch = (path: string, kind: SimFixSubmittedChange["kind"], content: string | null, executable = false): SimFixSubmittedChange => ({ path, kind, executable, content });

describe("the custodian's path rules agree with the engine's (independent implementations, one verdict)", () => {
  const paths = [
    "src/a.ts", "src/../a.ts", "./src/a.ts", "/abs.ts", "src//a.ts", "src/a.ts.", "src/a.ts ", "src/CON.txt", "src/con", "src/aux.js", "src/COM1",
    "src/LPT¹.txt", "src/PROGRA~1.TXT", "src/GIT~1", "src/.git/config", "src/.GIT", "src/a:b.ts", "src/a|b.ts", "src/a\\b.ts", "src/a\u0001.ts",
    "src/é.ts", ".github/workflows/ci.yml", ".GitHub/x.yml", "src/.claude/settings.json", "CLAUDE.md", "docs/AGENTS.md", ".npmrc", "src/.vscode/tasks.json",
    "src/x.mcp.json", ".mcp.json", "a".repeat(256), `src/${"b".repeat(1100)}`, "src/ok-name_1.2.ts",
  ];
  const engineBoundary: FixBoundary = {
    task_id: "t", permitted_files: [".github/workflows/ci.yml"], permitted_dirs: ["src"], allow_create: true, allow_delete: true, allow_binary: false,
    max_changed_files: 5, max_file_bytes: 64, max_total_bytes: 100, proposal_lifetime_ms: 1000,
  };
  it.each(paths)("%s", (p) => {
    // Increment 2 restriction (TD review): the custodian accepts ASCII paths only, so its case folding is one rule on
    // every implementation; on ASCII paths it agrees with the engine's rules exactly.
    if (/[^\u0000-\u007f]/.test(p)) {
      expect(fixPathProblem(p)).not.toBeNull();
      return;
    }
    expect(fixPathProblem(p) === null).toBe(portablePathProblem(p) === null);
    expect(fixSensitive(p)).toBe(sensitivePathReason(p) !== null);
    if (fixPathProblem(p) === null) expect(fixPermitted(p, BOUNDARY)).toBe(isPermitted(p, engineBoundary));
  });
});

describe("the custodian's validation of submitted content (trusting no engine claim)", () => {
  it("accepts valid content and records the preimage from ITS baseline, never one the engine claims", () => {
    const r = validateFixSubmission(BOUNDARY, TREE, [ch(".github/workflows/ci.yml", "modify", b64("on: pull_request\n")), ch("src/a.ts", "modify", b64("b\n")), ch("src/new.ts", "add", b64("n\n"))]);
    expect(r.violations).toEqual([]);
    expect(r.canonical!.map((c) => [c.path, c.kind, c.preimage])).toEqual([
      [".github/workflows/ci.yml", "modify", { size: 9, sha256: sha("on: push\n") }],
      ["src/a.ts", "modify", { size: 2, sha256: sha("a\n") }],
      ["src/new.ts", "add", null],
    ]);
    expect(r.totalBytes).toBe(17 + 2 + 2);
  });

  it("a delete of a baseline file within the boundary is valid; a delete carries no content", () => {
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "delete", null)]).violations).toEqual([]);
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "delete", b64("a\n"))]).violations).toEqual([{ kind: "content_mismatch", path: "src/a.ts" }]);
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "delete", null, true)]).violations).toEqual([{ kind: "content_mismatch", path: "src/a.ts" }]);
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", null)]).violations).toEqual([{ kind: "content_mismatch", path: "src/a.ts" }]);
  });

  it("non-ASCII paths are refused outright; folding is ASCII-only, so a non-ASCII baseline path never collides with an ASCII add", () => {
    for (const p of ["src/\u00e9.ts", "src/\u00c9.ts", "src/\u0130.ts", "src/\u212a.ts", "src/\u00df.ts"]) {
      expect(validateFixSubmission(BOUNDARY, TREE, [ch(p, "add", b64("x"))]).violations).toEqual([{ kind: "invalid_path", path: p }]);
    }
    const tree = new Map(TREE).set("src/\u212a.ts", { size: 1, sha256: sha("k") }); // KELVIN SIGN: JS and .NET folding may differ
    expect(validateFixSubmission(BOUNDARY, tree, [ch("src/k.ts", "add", b64("k"))]).violations).toEqual([]);
    expect(fixBoundaryProblem({ ...BOUNDARY, permittedDirs: ["src/\u00e9"] })).toContain("non-ASCII");
  });

  it("an add whose path folds onto a baseline file is refused (a case-only alias of an existing file)", () => {
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/A.ts", "add", b64("z\n"))]).violations).toEqual([{ kind: "present_in_baseline", path: "src/A.ts" }]);
  });

  it("only canonical base64 is content: a non-canonical encoding of the same bytes is refused", () => {
    expect(decodeStrictBase64("YQ==")?.toString()).toBe("a");
    expect(decodeStrictBase64("YR==")).toBeNull(); // decodes to "a" too, but is not the canonical encoding
    expect(decodeStrictBase64("YQ")).toBeNull();
    expect(decodeStrictBase64("Y Q==")).toBeNull();
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", "YR==")]).violations).toEqual([{ kind: "content_mismatch", path: "src/a.ts" }]);
  });

  it("binary content needs allowBinary; a NUL byte anywhere makes content binary", () => {
    const bin = Buffer.from([0x62, 0x00, 0x0a]);
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", b64(bin))]).violations).toEqual([{ kind: "binary_not_allowed", path: "src/a.ts" }]);
    expect(validateFixSubmission({ ...BOUNDARY, allowBinary: true }, TREE, [ch("src/a.ts", "modify", b64(bin))]).violations).toEqual([]);
  });

  it("an unchanged modify is no change; the switches and limits each refuse", () => {
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", b64("a\n"))]).violations).toEqual([{ kind: "unchanged", path: "src/a.ts" }]);
    expect(validateFixSubmission({ ...BOUNDARY, allowCreate: false }, TREE, [ch("src/n.ts", "add", b64("n"))]).violations).toEqual([{ kind: "create_not_allowed", path: "src/n.ts" }]);
    expect(validateFixSubmission({ ...BOUNDARY, allowDelete: false }, TREE, [ch("src/a.ts", "delete", null)]).violations).toEqual([{ kind: "delete_not_allowed", path: "src/a.ts" }]);
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", b64("x".repeat(65)))]).violations).toEqual([{ kind: "file_too_large", path: "src/a.ts" }]);
    const many = ["src/1.ts", "src/2.ts", "src/3.ts", "src/4.ts", "src/5.ts", "src/6.ts"].map((p) => ch(p, "add", b64("x".repeat(20))));
    expect(validateFixSubmission(BOUNDARY, TREE, many).violations).toEqual([{ kind: "too_many_changes", path: null }, { kind: "total_too_large", path: null }]);
  });

  it("the boundary binds exact files for sensitive paths; a sensitive directory grants nothing", () => {
    expect(fixBoundaryProblem({ ...BOUNDARY, permittedDirs: [".claude"] })).toContain("sensitive");
    expect(fixBoundaryProblem({ ...BOUNDARY, permittedFiles: [], permittedDirs: [] })).toBe("the boundary permits nothing");
    expect(fixBoundaryProblem({ ...BOUNDARY, permittedDirs: ["src/../.."] })).not.toBeNull();
    expect(validateFixSubmission(BOUNDARY, TREE, [ch("src/.claude/x.json", "add", b64("{}"))]).violations).toEqual([{ kind: "sensitive_path", path: "src/.claude/x.json" }]);
  });

  it("the custodian's digests are deterministic and bind every field", () => {
    expect(fixBoundaryDigest(BOUNDARY)).toBe(fixBoundaryDigest({ ...BOUNDARY }));
    expect(fixBoundaryDigest({ ...BOUNDARY, maxFileBytes: 65 })).not.toBe(fixBoundaryDigest(BOUNDARY));
    expect(fixTreeDigest(TREE)).toBe(fixTreeDigest(new Map([...TREE.entries()].reverse())));
    const canonical = validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", b64("b\n"))]).canonical!;
    const base = { runId: "r1", operationId: "fop-1", fixId: "fx1", taskDigest: "d".repeat(64), boundaryDigest: fixBoundaryDigest(BOUNDARY), baseline: { reviewId: "rv1", sourceId: "a".repeat(64), exportDigest: "e".repeat(64), manifestDigest: "m".repeat(64) }, changes: canonical };
    const d = fixProposalDigest(base);
    expect(fixProposalDigest({ ...base })).toBe(d);
    expect(fixProposalDigest({ ...base, operationId: "fop-2" })).not.toBe(d);
    expect(fixProposalDigest({ ...base, changes: validateFixSubmission(BOUNDARY, TREE, [ch("src/a.ts", "modify", b64("c\n"))]).canonical! })).not.toBe(d);
  });
});

describe("routing a delegated fix (§3.2): in flight waits, a pending proposal awaits the owner (N4-11)", () => {
  const counts = { incomplete: 0, checks_not_satisfied: 0, review_not_current: 0, needs_user_decision: 0, needs_reviewer: 0, needs_implementer: 1 };
  const facts = (over: Partial<RoutingFacts> = {}): RoutingFacts => ({
    run_state: "IDLE", active_operation: null, operations: [], acknowledged_before: "2026-10-19T00:00:00.000Z",
    completion: { state: "needs_implementer", counts, blockers: [{ category: "needs_implementer", code: "open_finding" }] },
    budgets: { reviews: { used: 1, limit: 5 }, check_executions: { used: 1, limit: 20 } }, ...over,
  });

  it("without a fix the open finding is an implementer step", () => {
    expect(routeFromEngine(facts())).toMatchObject({ code: "address_findings", kind: "implementer_step" });
  });

  it("a fix in flight routes wait_for_operation", () => {
    expect(routeFromEngine(facts({ active_operation: { kind: "fix", operation_id: "fop-1" } }))).toMatchObject({ code: "wait_for_operation", kind: "implementer_step", reason: "fix_running" });
  });

  it("a pending proposal is an await: no continuation (not an implementer step) and nothing to wake on", () => {
    const r = routeFromEngine(facts({ pending_fix_proposals: 1 }));
    expect(r).toEqual({ code: "await_fix_confirmation", kind: "await", reason: "fix_proposal_pending" });
    expect(instructionFor("run-1", r)).toContain("awaiting the owner's confirmation");
    expect(instructionFor("run-1", r)).toContain("END YOUR TURN NOW");
  });

  it("a fix the custodian rejected (or that failed) pauses automation; it is never retried automatically", () => {
    const r = routeFromEngine(facts({ operations: [{ kind: "fix", operation_id: "fop-1", status: "rejected", started_at: "2026-10-19T01:00:00.000Z", ended_at: "2026-10-19T01:01:00.000Z" }] }));
    expect(r).toMatchObject({ code: "pause", pause: "operation_unsuccessful", reason: "fix_rejected" });
  });

  it("the snapshot reports a retired or past-lifetime proposal as expired (no longer pending)", () => {
    const op = (proposal: Record<string, unknown> | null): SimRunOperation => ({ operationId: "fop-1", seq: 2, kind: "fix", status: "proposed", beganAt: "", endedAt: "", writer: { pid: 1, startedAtMs: 1, imageName: "node.exe" }, begin: {}, outcome: { proposal } });
    const now = Date.parse("2026-10-19T12:00:00.000Z");
    expect(snapshotOperationStatus(op({ expiresAt: "2026-10-19T13:00:00.000Z", retiredAt: null }), now)).toBe("proposed");
    expect(snapshotOperationStatus(op({ expiresAt: "2026-10-19T11:59:59.000Z", retiredAt: null }), now)).toBe("expired");
    expect(snapshotOperationStatus(op({ expiresAt: "2026-10-19T13:00:00.000Z", retiredAt: "2026-10-19T11:00:00.000Z" }), now)).toBe("expired");
    expect(snapshotOperationStatus({ ...op(null), kind: "review", status: "completed" }, now)).toBe("completed");
  });
});

describe("the FIX self-test confirmation (FIX vs S1 separation)", () => {
  const S1 = { selftestId: "st1", codexVersion: "0.160.0", backend: "mxc", mode: "S1", profileDigest: "a".repeat(64), s1Available: true, rowsSummary: { total: 6, passed: 6, failed: [] }, recordDigest: "5".repeat(64) };
  const FIX = { ...S1, selftestId: "fx1", mode: "FIX", profileDigest: "9".repeat(64), recordDigest: "8".repeat(64), codexSha256: "c".repeat(64) };
  const prepare = async (payload: Record<string, unknown>) => {
    const t = new SimulatedCustodianTransport({ caller: "by_surface" });
    return t.send("operator", "prepare_config_record", { recordKind: "selftest_confirmation", action: "set", payload, baseRevision: 0 }, `p-${Math.random().toString(36).slice(2)}`);
  };

  it("a FIX confirmation names the Codex binary; an S1 one may not", async () => {
    const fix = await prepare(FIX);
    expect(fix.ok, fix.error).toBe(true);
    expect(String(fix.data?.["rendering"])).toContain("Confirm the FIX self-test record for delegated fixes (separate from the S1 review confirmation)");
    expect(String(fix.data?.["rendering"])).toContain(`Codex binary SHA-256 ${"c".repeat(64)}`);
    const { codexSha256: _drop, ...noBinary } = FIX;
    expect((await prepare(noBinary)).code).toBe("INVALID_ARGUMENT");
    expect((await prepare({ ...S1, codexSha256: "c".repeat(64) })).code).toBe("MALFORMED_REQUEST");
    expect((await prepare({ ...noBinary, mode: "S2" })).code).toBe("INVALID_ARGUMENT");
    expect((await prepare({ ...FIX, s1Available: false })).code).toBe("INVALID_ARGUMENT");
    expect((await prepare(S1)).ok).toBe(true);
  });
});
