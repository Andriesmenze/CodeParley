// Phase 5 F-i2-5 (option A, [[D-28]]; the owner's choice: the custodian holds the artifact): `amend <run> --repo` through
// the CUSTODIAN alone. The operator account cannot read the working tree or write the implementer's run store, so the
// custodian's helper redacts the text over its own fresh read (the engine's own host view) and the custodian holds the
// representation the operator confirms; a review presents it from the custodian, under the digest the record binds.

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { runCli } from "../src/cli/cli.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import { loadAmendmentTexts } from "../src/engine/disclosure-artifact.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { readState } from "../src/store/state-store.js";
import { sha256OfString } from "../src/common/hash.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { contFixture, grant, HostSession, inProcessTreeOf, newRun, operatorIo, reviewCtx, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const ADD = "add() subtracts";
const scenario = () => okScenario(output({ findings: [defect()] }));

async function protectedRun(f: ContFixture, sessionId: string, pid: number): Promise<{ run: RunHandle; itemId: string }> {
  const run = await newRun(f);
  const A = new HostSession(f, sessionId, pid);
  await grant(f, 1);
  await A.startLoop(run);
  const itemId = await inProcessTreeOf(pid, async () => {
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "deferred", rationale: "out of scope for this change" }] });
    return item.id;
  });
  await A.stop(false);
  return { run, itemId };
}

async function opCli(f: ContFixture, home: string, args: string[], io = operatorIo("")): Promise<{ code: number; out: string; err: string }> {
  const code = await runCli([...args, "--home", home, "--git", f.git], { ...io, engineTestHooks: io.engineTestHooks ?? f.operatorHooks! });
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

async function emptyHome(f: ContFixture, name: string): Promise<string> {
  const home = join(f.scratch, name);
  await mkdir(home, { recursive: true });
  return home;
}

describe.skipIf(!supported)("F-i2-5 — `amend --repo`: the custodian redacts and holds the reviewer-visible representation", () => {
  it("the operator confirms the custodian's redaction; the custodian holds it; a review presents it under the bound digest", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, itemId } = await protectedRun(f, "sess-amend-ok", 9301);
    const home = await emptyHome(f, "op-home-amend");
    const outside = join(f.scratch, "elsewhere", "notes.txt"); // a local path outside the repository (not a kept root)
    const raw = `Keep .env untouched; my notes are in ${outside}; the fix belongs in src/math.js.`;
    const io = operatorIo("amend");
    const r = await opCli(f, home, ["amend", run.runId, "constraint", "--repo", f.repo, "--text", raw, "--thread", itemId], io);
    expect(r.code, r.err).toBe(0);
    expect(r.out).toContain("Codex will see exactly this redaction of your text");
    expect(r.out).toContain("Recorded by the custodian: amendment");
    // The rendering showed the redaction: not the confidential name, not a local path outside the repository (the
    // accepted rules keep paths under the repository root, engine-env.ts pathDisclosure).
    const rendering = r.out.slice(r.out.indexOf("Codex will see exactly"));
    expect(rendering).not.toContain(".env");
    expect(rendering).not.toContain(outside);
    expect(rendering).toContain("src/math.js");

    // The implementer's projection: the representation and its digest, never the raw text.
    const impl = await new CustodianGrants(f.custodian).listUserRecords("implementer", f.repo, run.runId);
    const rec = impl.records[0]!;
    const shown = String(rec["disclosureText"]);
    expect(shown).not.toContain(".env");
    expect(rec["disclosureDigest"]).toBe(sha256OfString(shown));
    expect(JSON.stringify(impl)).not.toContain("Keep .env untouched");
    // The operator's projection keeps the raw text.
    const op = await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId);
    expect(op.records[0]!["text"]).toBe(raw);

    // A review presents the custodian-held representation (the run store holds no artifact of it).
    const hydrated = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
    const texts = await loadAmendmentTexts(run.paths, hydrated.task_amendments);
    expect(texts.withheld).toEqual([]);
    expect(texts.amendments.map((a) => a.text)).toEqual([shown]);

    // The listing through the custodian shows it as Codex sees it.
    const listed = await opCli(f, home, ["amend", run.runId, "--repo", f.repo]);
    expect(listed.code, listed.err).toBe(0);
    expect(listed.out).toContain("A-1 constraint");
    expect(listed.out).toContain("as Codex sees it");
  });

  it("a representation that does not hash to the bound digest is withheld (fail closed)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-amend-digest", 9302);
    const home = await emptyHome(f, "op-home-amend-digest");
    expect((await opCli(f, home, ["amend", run.runId, "clarification", "--repo", f.repo, "--text", "prefer small commits"], operatorIo("amend"))).code).toBe(0);
    const hydrated = await withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
    const altered = hydrated.task_amendments.map((a) => ({ ...a, disclosure_text: `${a.disclosure_text ?? ""} (altered)` }));
    const texts = await loadAmendmentTexts(run.paths, altered);
    expect(texts.amendments).toEqual([]);
    expect(texts.withheld).toEqual([{ amendment_id: altered[0]!.amendment_id, reason: "disclosure_artifact_missing_or_altered" }]);
  });

  it("a client-supplied digest or source is refused, and the implementer cannot prepare an amendment", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-amend-forge", 9303);
    const operator = new CustodianOperator(f.operatorCustodian!);
    const base = { kind: "clarification", text: "x", relates_to: [], replaces: null, request_digest: "0".repeat(64), custodian_redaction: true };
    await expect(operator.prepareUserRecord(f.repo, run.runId, "amendment", { ...base, disclosure_digest: "a".repeat(64) }, 0, "req-forge-1")).rejects.toThrow(/may not carry 'disclosure_digest' or 'source'/);
    await expect(operator.prepareUserRecord(f.repo, run.runId, "amendment", { ...base, source: { source_id: "b".repeat(64) } }, 0, "req-forge-2")).rejects.toThrow(/may not carry 'disclosure_digest' or 'source'/);
    await expect(new CustodianOperator(f.custodian).prepareUserRecord(f.repo, run.runId, "amendment", base, 0, "req-forge-3")).rejects.toThrow(/cannot reach the operator pipe|CALLER_NOT_AUTHORIZED/);
    const home = await emptyHome(f, "op-home-amend-impl");
    const r = await opCli(f, home, ["amend", run.runId, "clarification", "--repo", f.repo, "--text", "x"], operatorIo("amend", true, f.le.env.testHooks));
    expect(r.code).toBe(1);
    expect((await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId)).records).toHaveLength(0);
  });

  it("a wrong repository or run is RUN_NOT_FOUND; recording needs an interactive terminal", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-amend-wrong", 9304);
    const home = await emptyHome(f, "op-home-amend-wrong");
    const unknown = await opCli(f, home, ["amend", "01900000-0000-7000-8000-000000000000", "clarification", "--repo", f.repo, "--text", "x"], operatorIo("amend"));
    expect(unknown.code).toBe(1);
    expect(unknown.err).toContain("RUN_NOT_FOUND");
    const tty = await opCli(f, home, ["amend", run.runId, "clarification", "--repo", f.repo, "--text", "x"], operatorIo("amend", false));
    expect(tty.code).toBe(1);
    expect(tty.err).toContain("INTERACTIVE_TERMINAL_REQUIRED");
    expect((await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId)).records).toHaveLength(0);
  });
});
