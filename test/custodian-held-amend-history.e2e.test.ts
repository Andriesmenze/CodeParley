// Phase 5 F-i2-5, the TD's interim correction (historical confidentiality redaction): an amendment the CUSTODIAN redacts
// is redacted against the run's whole evidence history — the baseline capture record, every review's capture record and
// every response set's disclosure record, as the custodian holds them, the sources the accepted Windows workflow redacts
// against (engine/host-view.ts disclosureFor) — and never against the current repository alone. Deleting a confidential
// file cannot make a name the run's evidence withheld disclosable; a basis that cannot be established refuses.

import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { runCli } from "../src/cli/cli.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import { CustodianRuns } from "../src/custodian/runs.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { contFixture, grant, HostSession, inProcessTreeOf, newRun, operatorIo, reviewCtx, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const ADD = "add() subtracts";
const SECRET = join("deploy", "prod-signing.pem"); // a confidential name by the default capture rules (**/*.pem)
const SECRET_POSIX = "deploy/prod-signing.pem";
const scenario = () => okScenario(output({ findings: [defect()] }));

/** A protected run reviewed once (with a response), the confidential file present only while `present` says so. */
async function protectedRun(f: ContFixture, sessionId: string, pid: number, present: "baseline" | "review"): Promise<{ run: RunHandle; A: HostSession }> {
  await mkdir(join(f.repo, "deploy"), { recursive: true });
  await writeFile(join(f.repo, SECRET), "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n");
  const run = await newRun(f);
  if (present === "baseline") await rm(join(f.repo, SECRET)); // only the baseline capture ever saw it
  const A = new HostSession(f, sessionId, pid);
  await grant(f, 1);
  await A.startLoop(run);
  await inProcessTreeOf(pid, async () => {
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    const ctx = await reviewCtx(f, run);
    const item = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: item.id, response_token: item.token!, disposition: "deferred", rationale: "out of scope for this change" }] });
  });
  await A.stop(false);
  await rm(join(f.repo, SECRET), { force: true }); // deleted before the amendment: the current read no longer knows it
  return { run, A };
}

async function opCli(f: ContFixture, home: string, args: string[], io = operatorIo("")): Promise<{ code: number; out: string; err: string }> {
  await mkdir(home, { recursive: true });
  const code = await runCli([...args, "--home", home, "--git", f.git], { ...io, engineTestHooks: io.engineTestHooks ?? f.operatorHooks! });
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

const TEXT = `Rotate the key in ${SECRET_POSIX} before the release.`;

async function amend(f: ContFixture, run: RunHandle, name: string): Promise<{ code: number; out: string; err: string }> {
  return opCli(f, join(f.scratch, name), ["amend", run.runId, "constraint", "--repo", f.repo, "--text", TEXT], operatorIo("amend"));
}

const records = async (f: ContFixture, run: RunHandle) => (await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId)).records;

describe.skipIf(!supported)("F-i2-5 — the custodian redacts an amendment against the run's whole evidence history", () => {
  it("a confidential file a review captured, deleted before the amendment, stays withheld", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-hist-review", 9401, "review");
    const r = await amend(f, run, "op-hist-review");
    expect(r.code, r.err).toBe(0);
    const shown = r.out.slice(r.out.indexOf("Codex will see exactly"));
    expect(shown).not.toContain("prod-signing.pem");
    const held = (await new CustodianGrants(f.custodian).listUserRecords("implementer", f.repo, run.runId)).records[0]!;
    expect(String(held["disclosureText"])).not.toContain("prod-signing.pem");
    expect(String(held["disclosureText"])).toContain("before the release");
  });

  it("a confidential file only the baseline captured (deleted before the first review) stays withheld", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-hist-baseline", 9402, "baseline");
    const r = await amend(f, run, "op-hist-baseline");
    expect(r.code, r.err).toBe(0);
    expect(r.out.slice(r.out.indexOf("Codex will see exactly"))).not.toContain("prod-signing.pem");
  });

  it("missing capture evidence refuses the amendment (REDACTION_REFUSED), never a fallback to the current repository", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-hist-missing", 9403, "review");
    const ev = f.operatorCustodian!.evidenceForTest(f.repo, run.runId);
    const held = ev.list();
    expect(held.length).toBeGreaterThanOrEqual(3); // the baseline, the review's capture, the response set's disclosure record
    for (const sha of held) {
      const text = f.operatorCustodian!.evidenceForTest(f.repo, run.runId);
      text.remove(sha);
      const r = await amend(f, run, `op-hist-missing-${sha.slice(0, 6)}`);
      expect(r.code).toBe(1);
      expect(r.err).toContain("REDACTION_REFUSED");
      expect(r.err).toMatch(/does not hold the (baseline capture record|capture record of review|disclosure record of response set)/);
      expect(await records(f, run)).toHaveLength(0);
      // Handed back (by the engine, through hold_evidence) only where the run binds it; a review's capture is the custodian's own.
      break;
    }
  });

  it("altered evidence refuses the amendment", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-hist-altered", 9404, "review");
    const ev = f.operatorCustodian!.evidenceForTest(f.repo, run.runId);
    for (const sha of ev.list()) ev.alter(sha, "{}");
    const r = await amend(f, run, "op-hist-altered");
    expect(r.code).toBe(1);
    expect(r.err).toContain("REDACTION_REFUSED");
    expect(r.err).toContain("intact");
    expect(await records(f, run)).toHaveLength(0);
  });

  it("evidence is held only for a digest the run itself binds (another run's or an unbound record is refused)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-hist-bound", 9405, "review");
    const runs = new CustodianRuns(f.custodian);
    // Not a record this run binds: refused, nothing held.
    await expect(runs.holdEvidence("implementer", { repositoryRoot: f.repo, runId: run.runId }, Buffer.from('{"schema":"forged"}', "utf8"))).rejects.toThrow(/EVIDENCE_NOT_HELD|no baseline capture or response disclosure/);
    // A run the custodian does not hold: refused.
    await expect(runs.holdEvidence("implementer", { repositoryRoot: f.repo, runId: "01900000-0000-7000-8000-000000000000" }, Buffer.from("{}", "utf8"))).rejects.toThrow(/RUN_NOT_OPEN|no record of this run/);
    // Run B's history is its own: run A's evidence never stands in for it.
    const B = await newRun(f);
    const ev = f.operatorCustodian!.evidenceForTest(f.repo, B.runId);
    expect(ev.list()).toEqual([]);
  });

  it("a capture recorded between the prepare and the commit refuses the commit (the confirmed text was not redacted against it)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, A } = await protectedRun(f, "sess-hist-stale", 9406, "review");
    const operator = new CustodianOperator(f.operatorCustodian!);
    const base = (await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId)).revision;
    const prepared = await operator.prepareUserRecord(f.repo, run.runId, "amendment", { kind: "clarification", text: TEXT, relates_to: [], replaces: null, request_digest: "0".repeat(64), custodian_redaction: true }, base, "req-hist-stale");
    expect(prepared.rendering).toContain("Codex will see exactly");
    // A new review of a changed source: a new capture record joins the run's history.
    await writeFile(join(f.repo, "src", "extra.js"), "export const extra = 1;\n");
    await inProcessTreeOf(9406, async () => {
      await (await startReview(f, run)).done;
    });
    void A;
    await expect(operator.commitUserRecord(prepared.authorizationRequestId)).rejects.toThrow(/STALE|changed since/);
    expect(await records(f, run)).toHaveLength(0);
  });
});

// Phase 5 OI-1 (the TD's D-29 decision): every committed custodian-held amendment keeps what its read withheld as the
// run's protected evidence, and a later amendment is redacted against it — as the accepted Windows workflow keeps a
// disclosure record of every user record's read (engine/host-view.ts responseDisclosureRefsOf).
const LATE = join("deploy", "late-signing.pem"); // introduced after the last review: no capture, baseline or response saw it
const LATE_POSIX = "deploy/late-signing.pem";

async function amendText(f: ContFixture, run: RunHandle, name: string, text: string): Promise<{ code: number; out: string; err: string }> {
  return opCli(f, join(f.scratch, name), ["amend", run.runId, "constraint", "--repo", f.repo, "--text", text], operatorIo("amend"));
}
const shownOf = (r: { out: string }) => r.out.slice(r.out.indexOf("Codex will see exactly"));

/** A protected run reviewed once; then LATE appears and A1 names it (its read withholds it); then LATE is deleted. */
async function afterA1(f: ContFixture, sessionId: string, pid: number): Promise<{ run: RunHandle; a1Sha: string }> {
  const { run } = await protectedRun(f, sessionId, pid, "review");
  await writeFile(join(f.repo, LATE), "-----BEGIN PRIVATE KEY-----\nnot a real key either\n-----END PRIVATE KEY-----\n");
  const a1 = await amendText(f, run, `${sessionId}-a1`, `Do not ship ${LATE_POSIX}.`);
  expect(a1.code, a1.err).toBe(0);
  expect(shownOf(a1)).not.toContain("late-signing.pem");
  await rm(join(f.repo, LATE));
  const a1Sha = String((await records(f, run))[0]!["read_disclosure_digest"]);
  expect(a1Sha).toMatch(/^[0-9a-f]{64}$/);
  return { run, a1Sha };
}

const A2_TEXT = `${LATE_POSIX} was removed; keep it out of the release.`;

describe.skipIf(!supported)("OI-1 — a later amendment is redacted against every earlier custodian-held amendment's read", () => {
  it("a confidential file introduced after the last review, withheld by A1 and deleted before A2, stays withheld in A2", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, a1Sha } = await afterA1(f, "sess-oi1", 9411);
    const ev = f.operatorCustodian!.evidenceForTest(f.repo, run.runId);
    expect(ev.list()).toContain(a1Sha);
    expect(ev.get(a1Sha)).toContain(LATE_POSIX); // what A1's read withheld, held by the custodian
    const a2 = await amendText(f, run, "op-oi1-a2", A2_TEXT);
    expect(a2.code, a2.err).toBe(0);
    expect(shownOf(a2)).not.toContain("late-signing.pem");
    expect(shownOf(a2)).toContain("keep it out of the release");
    const held = (await new CustodianGrants(f.custodian).listUserRecords("implementer", f.repo, run.runId)).records;
    expect(held).toHaveLength(2);
    expect(JSON.stringify(held)).not.toContain("late-signing.pem");
    expect(JSON.stringify(held)).not.toContain("read_disclosure_digest"); // the implementer projection carries no read record
  });

  it("control: without A1, the same deleted file is not withheld (the current read alone no longer knows it)", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await protectedRun(f, "sess-oi1-control", 9412, "review");
    await writeFile(join(f.repo, LATE), "x\n");
    await rm(join(f.repo, LATE));
    const r = await amendText(f, run, "op-oi1-control", A2_TEXT);
    expect(r.code, r.err).toBe(0);
    expect(shownOf(r)).toContain("late-signing.pem");
  });

  it("A1's read disclosure missing: A2 is refused (REDACTION_REFUSED), nothing recorded", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, a1Sha } = await afterA1(f, "sess-oi1-missing", 9413);
    f.operatorCustodian!.evidenceForTest(f.repo, run.runId).remove(a1Sha);
    const r = await amendText(f, run, "op-oi1-missing", A2_TEXT);
    expect(r.code).toBe(1);
    expect(r.err).toContain("REDACTION_REFUSED");
    expect(r.err).toContain("the read disclosure record of amendment A-1");
    expect(await records(f, run)).toHaveLength(1);
  });

  it("A1's read disclosure altered: A2 is refused", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, a1Sha } = await afterA1(f, "sess-oi1-altered", 9414);
    f.operatorCustodian!.evidenceForTest(f.repo, run.runId).alter(a1Sha, '{"schema":"arl.response-disclosure.v1","withheld_paths":[],"withheld_hashes":[],"repo_context":[]}');
    const r = await amendText(f, run, "op-oi1-altered", A2_TEXT);
    expect(r.code).toBe(1);
    expect(r.err).toContain("REDACTION_REFUSED");
    expect(r.err).toContain("intact");
    expect(await records(f, run)).toHaveLength(1);
  });

  it("wrong run and the implementer: another run's basis has no A1 record, and the implementer cannot hold or replace it", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run, a1Sha } = await afterA1(f, "sess-oi1-bound", 9415);
    const bytes = Buffer.from(f.operatorCustodian!.evidenceForTest(f.repo, run.runId).get(a1Sha)!, "utf8");
    const runs = new CustodianRuns(f.custodian);
    await expect(runs.holdEvidence("implementer", { repositoryRoot: f.repo, runId: run.runId }, bytes)).rejects.toThrow(/EVIDENCE_NOT_HELD|no baseline capture or response disclosure/);
    await expect(runs.holdEvidence("implementer", { repositoryRoot: f.repo, runId: run.runId }, Buffer.from("{}", "utf8"))).rejects.toThrow(/EVIDENCE_NOT_HELD|no baseline capture or response disclosure/);
    expect(f.operatorCustodian!.evidenceForTest(f.repo, run.runId).get(a1Sha)).toBe(bytes.toString("utf8"));
    const B = await newRun(f);
    expect(f.operatorCustodian!.evidenceForTest(f.repo, B.runId).list()).not.toContain(a1Sha);
    // A client cannot name a read disclosure record itself.
    const operator = new CustodianOperator(f.operatorCustodian!);
    const base = (await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId)).revision;
    await expect(operator.prepareUserRecord(f.repo, run.runId, "amendment", { kind: "clarification", text: A2_TEXT, relates_to: [], replaces: null, request_digest: "0".repeat(64), custodian_redaction: true, read_disclosure_digest: a1Sha }, base, "req-oi1-forged")).rejects.toThrow(/read_disclosure_digest/);
  });

  it("prepare/commit: an amendment committed in between, or A2's own read disclosure lost before its commit, refuses the commit", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const { run } = await afterA1(f, "sess-oi1-race", 9416);
    const operator = new CustodianOperator(f.operatorCustodian!);
    const base = (await new CustodianGrants(f.operatorCustodian!).listUserRecords("operator", f.repo, run.runId)).revision;
    const payload = (text: string) => ({ kind: "clarification", text, relates_to: [], replaces: null, request_digest: "0".repeat(64), custodian_redaction: true });
    const pending = await operator.prepareUserRecord(f.repo, run.runId, "amendment", payload(A2_TEXT), base, "req-oi1-pending");
    const other = await operator.prepareUserRecord(f.repo, run.runId, "amendment", payload("another constraint"), base, "req-oi1-other");
    await operator.commitUserRecord(other.authorizationRequestId);
    await expect(operator.commitUserRecord(pending.authorizationRequestId)).rejects.toThrow(/STALE|changed since/);
    expect(await records(f, run)).toHaveLength(2);
    // A2's own read disclosure, held at its prepare, removed before its commit: nothing is recorded.
    const ev = f.operatorCustodian!.evidenceForTest(f.repo, run.runId);
    const before = new Set(ev.list());
    const a3 = await operator.prepareUserRecord(f.repo, run.runId, "amendment", payload("a third constraint naming nothing secret"), base + 1, "req-oi1-a3");
    const fresh = ev.list().filter((s) => !before.has(s));
    const own = fresh.length > 0 ? fresh : ev.list(); // content-addressed: an identical read is the record already held
    for (const sha of own) if (ev.get(sha)?.includes("arl.response-disclosure.v1")) ev.remove(sha);
    await expect(operator.commitUserRecord(a3.authorizationRequestId)).rejects.toThrow(/REDACTION_REFUSED|read disclosure record/);
    expect(await records(f, run)).toHaveLength(2);
  });
});
