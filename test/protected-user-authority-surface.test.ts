// P3.4C-1 regression (VM-discovered): the protected operator-WRITE path must validate against the records on
// the OPERATOR surface, not the implementer pipe — which, under the custodian's OS pipe DACLs, the operator
// account cannot reach. The earlier code read `listUserRecords("implementer", …)` during operator-side
// validation; against the real OS-separated custodian that is refused (CUSTODIAN_UNAVAILABLE) and nothing is
// recorded. The local `--simulate`/in-process tests masked it because one permissive transport served every
// surface.
//
// These tests enforce the two surfaces SEPARATELY — two account-bound SimulatedCustodianTransports over ONE
// shared state, each reaching only its own pipe (modelling the OS DACL) — so a cross-account request is
// refused exactly as the Windows custodian refuses it. They FAIL against the previous wrong-surface
// implementation and pass after the operator-surface correction. The controller/Stop-hook derivation keeps
// the implementer surface (D-C'); the OS caller classification stays authoritative (a request never names its
// own class); and no raw decision note or amendment text crosses to the implementer projection.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { SimulatedCustodianTransport } from "../src/custodian/transport.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { recordUserDecisionProtected, recordAmendmentProtected, type ProtectedCustodian, type UserChannelContext } from "../src/engine/user-authority.js";
import { authoritativeUserRecordsOf, withListedUserRecords } from "../src/engine/protected-user-records.js";
import { readState, commitState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import type { UserDecision } from "../src/schemas/user-authority.js";
import { contFixture, newRun, type ContFixture } from "./helpers/continuation-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";

const DD = "a".repeat(64); // a well-formed (test) redacted-artifact digest
const SRC = "b".repeat(64); // a well-formed (test) disclosure source id (a Sha256)

describe("P3.4C-1 protected write validates against the operator surface (VM-discovered cross-account fix)", () => {
  let f: ContFixture;
  let sp = "";
  let opT: SimulatedCustodianTransport; // the operator account's process: reaches ONLY the operator pipe
  let implT: SimulatedCustodianTransport; // the implementer account's process: reaches ONLY the implementer pipe
  let opCust: ProtectedCustodian;

  beforeEach(async () => {
    f = await contFixture(okScenario(output({ findings: [] })));
    sp = join(mkdtempSync(join(tmpdir(), "cp-surface-")), "sim.json");
    opT = new SimulatedCustodianTransport({ account: "operator", statePath: sp });
    implT = new SimulatedCustodianTransport({ account: "implementer", statePath: sp });
    opCust = { operator: new CustodianOperator(opT), grants: new CustodianGrants(opT) };
  });
  afterEach(() => rmSync(dirname(sp), { recursive: true, force: true }));

  const ctxFor = (run: RunHandle): UserChannelContext => ({ runId: run.runId, runPaths: run.paths, owner: f.le.env.owner, currentSource: async () => ({ source_id: null, note: null }) });

  it("1. operator decision recording reads the OPERATOR surface (the old implementer-surface read is refused as unreachable)", async () => {
    const run = await newRun(f);
    // A decision on a non-existent finding: the write FIRST reads the authoritative records, THEN validates.
    // Reaching FINDING_NOT_FOUND proves the read used the operator surface (reachable); the previous code read
    // the implementer pipe, which the operator account cannot reach -> it would reject CUSTODIAN_UNAVAILABLE.
    await expect(
      recordUserDecisionProtected(ctxFor(run), opCust, f.repo, { item_id: "01999999-9999-7999-8999-999999999999", kind: "waive", note: "", token: "t" }, async () => true),
    ).rejects.toMatchObject({ code: "FINDING_NOT_FOUND" });
    expect(opT.received.some((r) => r.op === "list_user_records" && r.surface === "operator")).toBe(true);
    expect(opT.received.some((r) => r.surface === "implementer")).toBe(false);
  });

  it("2. operator amendment recording goes through the operator surface and is served structurally on the implementer surface", async () => {
    const run = await newRun(f);
    const res = await recordAmendmentProtected(ctxFor(run), opCust, f.repo, { kind: "clarification", text: "operator-only guidance text", relates_to: [], replaces: null }, { digest: DD, source_id: SRC }, async () => true);
    expect("recorded" in res).toBe(true);
    expect(opT.received.some((r) => r.op === "list_user_records" && r.surface === "operator")).toBe(true);
    expect(opT.received.some((r) => r.surface === "implementer")).toBe(false);

    // The IMPLEMENTER surface serves the record structurally: a keyed hash, no raw text, no secret.
    const impl = await new CustodianGrants(implT).listUserRecords("implementer", f.repo, run.runId);
    const implAmd = impl.records.at(-1) as Record<string, unknown>;
    expect(implAmd.text).toBeUndefined();
    expect(typeof implAmd.contentKeyHash).toBe("string");
    const implJson = JSON.stringify(impl);
    expect(implJson).not.toContain("operator-only guidance text");
    expect(implJson).not.toContain("secret");

    // The OPERATOR surface carries the raw text (operator-only); the source binding round-trips through the
    // write's own reconstruction (`withListedUserRecords` reads the operator projection), and the raw text is
    // dropped from the reconstructed state (no confidential text in validation).
    const op = await new CustodianGrants(opT).listUserRecords("operator", f.repo, run.runId);
    expect((op.records.at(-1) as Record<string, unknown>).text).toBe("operator-only guidance text");
    const rebuilt = withListedUserRecords(await readState(run.paths), op);
    expect(rebuilt.task_amendments.at(-1)?.source).toEqual({ source_id: SRC, note: null });
    expect(rebuilt.task_amendments.at(-1)?.text).toBe("");
  });

  it("3. the OS classification is authoritative: operator refused on the implementer pipe, implementer on the operator pipe", async () => {
    const run = await newRun(f);
    await recordAmendmentProtected(ctxFor(run), opCust, f.repo, { kind: "clarification", text: "x", relates_to: [], replaces: null }, { digest: DD, source_id: null }, async () => true);
    // operator account -> implementer pipe: refused (operator-only records are never served on the wrong pipe).
    await expect(new CustodianGrants(opT).listUserRecords("implementer", f.repo, run.runId)).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    // implementer account -> operator pipe: refused (an implementer can never obtain operator-only full records).
    await expect(new CustodianGrants(implT).listUserRecords("operator", f.repo, run.runId)).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
    // implementer account -> prepare_user_record (an operator-only WRITE): unreachable on the implementer pipe.
    await expect(new CustodianOperator(implT).prepareUserRecord(f.repo, run.runId, "decision", { kind: "waive", note: "n", thread_id: "t", request_digest: "d" }, 1, "rid-x")).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
  });

  it("4. the protected controller derivation keeps using the implementer surface (refused on the operator pipe)", async () => {
    const run = await newRun(f);
    await recordAmendmentProtected(ctxFor(run), opCust, f.repo, { kind: "clarification", text: "guidance", relates_to: [], replaces: null }, { digest: DD, source_id: null }, async () => true);
    const st = await readState(run.paths);
    // The derivation reads the IMPLEMENTER surface: it works through the implementer-bound transport…
    const derived = await authoritativeUserRecordsOf({ custodian: { platform: "win32", transport: implT }, repositoryRoot: f.repo, runId: run.runId }, st, { protected: true });
    expect(derived.amendments.length).toBe(1);
    expect(derived.amendments[0]!.text).toBe(""); // raw text never reaches the derivation
    expect(typeof derived.amendments[0]!.content_key_hash).toBe("string");
    // …and an OPERATOR-bound transport cannot serve it, proving the derivation uses the implementer pipe.
    await expect(authoritativeUserRecordsOf({ custodian: { platform: "win32", transport: opT }, repositoryRoot: f.repo, runId: run.runId }, st, { protected: true })).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
  });

  it("5. stale base revision is refused, and a forged legacy record is not authority under protected derivation", async () => {
    const run = await newRun(f);
    await recordAmendmentProtected(ctxFor(run), opCust, f.repo, { kind: "clarification", text: "first", relates_to: [], replaces: null }, { digest: DD, source_id: null }, async () => true);
    // Stale base revision: the log is at revision 1; preparing against 0 is refused (optimistic concurrency).
    await expect(new CustodianOperator(opT).prepareUserRecord(f.repo, run.runId, "amendment", { kind: "scope", text: "y", disclosure_digest: DD }, 0, "rid-stale")).rejects.toMatchObject({ code: "STALE_FINDING_STATE" });
    // A forged legacy decision written to the user-writable store is NOT authority under protected derivation
    // (which trusts only the custodian; this run's custodian log holds no decision).
    await commitState(run.paths, f.le.env.owner, (cur) => { cur.user_decisions.push(forgedDecision()); return cur; });
    const st = await readState(run.paths);
    const derived = await authoritativeUserRecordsOf({ custodian: { platform: "win32", transport: implT }, repositoryRoot: f.repo, runId: run.runId }, st, { protected: true });
    expect(derived.decisions.length).toBe(0);
    expect(derived.amendments.length).toBe(1);
  });

  it("6. the operator CLI's attended VIEW read uses the operator surface on a governed run; model-reachable attended reads stay on the implementer surface", async () => {
    const run = await newRun(f);
    // Record a protected amendment as the operator: this marks the run custodian-governed, so subsequent
    // attended reads consult the custodian (the condition that exposed the second operator-side read).
    await recordAmendmentProtected(ctxFor(run), opCust, f.repo, { kind: "clarification", text: "guidance", relates_to: [], replaces: null }, { digest: DD, source_id: null }, async () => true);
    const st = await readState(run.paths);
    expect(st.user_records_custodian).toBe(true);

    // The operator CLI's attended read (asOperator) uses the OPERATOR surface — the pipe this account can
    // reach. The previous code read the implementer surface here too, which the operator-bound transport
    // refuses; so this records-through only after the fix.
    const opView = await authoritativeUserRecordsOf({ custodian: { platform: "win32", transport: opT }, repositoryRoot: f.repo, runId: run.runId }, st, { protected: false, asOperator: true });
    expect(opView.amendments.length).toBe(1);
    expect(opView.amendments[0]!.text).toBe(""); // raw text is dropped even from the operator projection

    // A model-reachable attended read (NO asOperator) reads the IMPLEMENTER surface: it works through the
    // implementer-bound transport, and an operator-bound transport cannot serve it — so a model-reachable
    // caller never silently reaches the operator surface (D-C' confidentiality boundary preserved).
    const implView = await authoritativeUserRecordsOf({ custodian: { platform: "win32", transport: implT }, repositoryRoot: f.repo, runId: run.runId }, st, { protected: false });
    expect(implView.amendments.length).toBe(1);
    await expect(authoritativeUserRecordsOf({ custodian: { platform: "win32", transport: opT }, repositoryRoot: f.repo, runId: run.runId }, st, { protected: false })).rejects.toMatchObject({ code: "CUSTODIAN_UNAVAILABLE" });
  });
});

/** A schema-valid legacy user decision written directly to the user-writable store (never custodian-backed). */
function forgedDecision(): UserDecision {
  return {
    decision_id: "01999999-0000-7000-8000-000000000001",
    thread_id: "t-forged",
    current_item_id: "t-forged",
    covered_items: ["t-forged"],
    kind: "waive",
    note: "FORGED",
    decided_against: { token: "x", run_review_id: null, run_round: null, latest_reply_id: null, latest_response_id: null, amendments_seq: 0 },
    context: { awaiting: "", escalation_reasons: [], reviewer_stance: null, implementer_position: null },
    supersedes: [],
    source: null,
    disclosure_ref: null,
    recorded_by: { role: "user", channel: "local_cli", assurance: "local_operator", tool_version: "forged" },
    request_id: null,
    request_digest: "f".repeat(64),
    recorded_at: new Date().toISOString(),
  };
}
