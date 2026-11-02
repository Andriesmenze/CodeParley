// P3.4C-3 corrective (TD authorization 2026-10-14): on a protected run, the fields that decide check freshness, the
// floor and review currency come from the custodian's record — never from the user-writable state.json. Before the
// corrective, hydrateRunEvidence kept from the local cache: the four execution identities freshness compares
// (check_spec_id, env_digest, freshness_digest, execution_input_id) and definition_digest; the order of the
// executions (the floor's decisive execution is the last fresh conclusive one); and the review's recorded source and
// check-evidence digest (review currency). Each case edits only the local cache; the derivation must not move.
// Simulation: the simulated custodian over two account-bound transports; the engine in this process.

import { describe, it, expect } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { routeRun } from "../src/engine/continuation.js";
import { checksContext } from "../src/engine/engine-env.js";
import { evaluateChecksStatus } from "../src/engine/checks-operation.js";
import { evidenceOf } from "../src/engine/review-operation.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { commitState, readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { approve } from "./helpers/checks-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, NODE, newRun, runChecks, startReview, type ContFixture, setConfig } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [] }));

async function protectedRun(f: ContFixture, session: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, session, pid).startLoop(run);
  return run;
}

async function view(f: ContFixture, run: RunHandle) {
  return withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
}

async function floorOf(f: ContFixture, run: RunHandle) {
  const r = (await routeRun(f.le, run, await view(f, run))).report;
  return { satisfied: r.floor.satisfied_for_current_source, stale: r.floor.stale, failed: r.floor.failed, review: r.latest_review?.freshness ?? null };
}

const IDENTITY = ["definition_digest", "check_spec_id", "env_digest", "freshness_digest", "execution_input_id"] as const;

describe.skipIf(!supported)("P3.4C-3 corrective — execution and review identities come from the custodian's record", () => {
  it("(A) a fresh execution: a local edit of an identity field does not make it stale", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ident-a", 9801);
    await runChecks(f, run);
    expect((await floorOf(f, run)).satisfied).toBe(true);
    await commitState(run.paths, f.le.env.owner, (cur) => {
      for (const e of cur.check_executions) e.env_digest = "e".repeat(64);
      return cur;
    });
    expect((await floorOf(f, run)).satisfied).toBe(true);
  });

  it("(B) a legitimately stale execution: copying the current identities into the local copy does not make it fresh", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ident-b", 9802);
    await runChecks(f, run);
    // The approved definition changes — approved locally and set for protected runs by the operator (P3.4C-4) — so the
    // execution is legitimately stale (its spec no longer matches).
    await approve(f, { checks: { unit: { argv: [NODE, "scripts/pass.js", "CHECK_TOKEN_3b"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    await setConfig(f);
    const stale = await floorOf(f, run);
    expect(stale.satisfied).toBe(false);
    expect(stale.stale).toContain("unit");
    // The current identities, as an attended run of the new definition records them.
    const other = await newRun(f, "an attended run of the new definition");
    await runChecks(f, other);
    const current = (await readState(other.paths)).check_executions.at(-1)!;
    await commitState(run.paths, f.le.env.owner, (cur) => {
      for (const e of cur.check_executions) for (const k of IDENTITY) (e as Record<string, unknown>)[k] = current[k];
      return cur;
    });
    const after = await floorOf(f, run);
    expect(after.satisfied).toBe(false);
    expect(after.stale).toContain("unit");
  });

  it("(C) the custodian's order decides: reordering the local executions does not let an earlier pass hide a later failure", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const flag = join(f.scratch, "fail-now.flag");
    await approve(f, { checks: { unit: { argv: [NODE, "-e", `process.exit(require("fs").existsSync(${JSON.stringify(flag)}) ? 1 : 0)`] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    const run = await protectedRun(f, "sess-ident-c", 9803);
    await runChecks(f, run); // passes
    await writeFile(flag, "x");
    await runChecks(f, run); // fails on the same inputs: the later failure decides
    const before = await floorOf(f, run);
    expect(before.satisfied).toBe(false);
    expect(before.failed).toContain("unit");
    await commitState(run.paths, f.le.env.owner, (cur) => {
      cur.check_executions.reverse();
      return cur;
    });
    const after = await floorOf(f, run);
    expect(after.satisfied).toBe(false);
    expect(after.failed).toContain("unit");
  });

  it("(D) a review whose check evidence changed: a local edit of its recorded evidence digest does not make it current", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    // The check fails once the flag exists, so its second execution's evidence differs deterministically (a re-run
    // that passes again can tie on every evidence field, duration_ms included).
    const flag = join(f.scratch, "fail-now.flag");
    await approve(f, { checks: { unit: { argv: [NODE, "-e", `process.exit(require("fs").existsSync(${JSON.stringify(flag)}) ? 1 : 0)`] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    const run = await protectedRun(f, "sess-ident-d", 9804);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    expect((await floorOf(f, run)).review?.current).toBe(true);
    await writeFile(flag, "x");
    await runChecks(f, run); // new check evidence: the review is legitimately no longer current
    const stale = await floorOf(f, run);
    expect(stale.review?.current).toBe(false);
    const v = await view(f, run);
    const sourceId = v.reviews.at(-1)!.source_id;
    const digest = evidenceOf(await evaluateChecksStatus(await checksContext(f.le, run), sourceId, v), v).digest;
    await commitState(run.paths, f.le.env.owner, (cur) => {
      cur.reviews.at(-1)!.check_evidence_digest = digest;
      return cur;
    });
    expect((await floorOf(f, run)).review?.current).toBe(false);
  });

  // Fail closed (item 4). The custodian's store is not same-user writable; these cases corrupt the SIMULATED custodian's
  // state file to stand for authoritative data that is missing or malformed, and check that nothing falls back to the
  // local cache.
  async function corruptHeld(f: ContFixture, run: RunHandle, mutate: (held: Record<string, unknown>) => void): Promise<void> {
    const path = join(f.scratch, "custodian-sim.json");
    const st = JSON.parse(await readFile(path, "utf8")) as { runs: Record<string, Record<string, unknown>> };
    const held = Object.values(st.runs).find((r) => r["runId"] === run.runId)!;
    mutate(held);
    await writeFile(path, JSON.stringify(st));
  }

  it("(E) a held execution whose identity is malformed or missing does not count — never filled from the local copy", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ident-e", 9805);
    await runChecks(f, run);
    expect((await floorOf(f, run)).satisfied).toBe(true);
    await corruptHeld(f, run, (held) => {
      const e = (held["checkExecutions"] as Record<string, unknown>[])[0]!;
      e["envDigest"] = "not-a-digest";
    });
    const malformed = await floorOf(f, run);
    expect(malformed.satisfied).toBe(false);
    await corruptHeld(f, run, (held) => {
      const e = (held["checkExecutions"] as Record<string, unknown>[])[0]!;
      delete e["envDigest"];
    });
    expect((await floorOf(f, run)).satisfied).toBe(false);
  });

  it("(F) a held review whose bindings are missing is never accepted — never filled from the local copy", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedRun(f, "sess-ident-f", 9806);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    expect((await view(f, run)).reviews.at(-1)!.accepted).toBe(true);
    await corruptHeld(f, run, (held) => {
      const r = (held["reviews"] as Record<string, unknown>[])[0]!;
      delete (r["begin"] as Record<string, unknown>)["checkEvidenceDigest"];
    });
    const v = await view(f, run);
    expect(v.reviews.at(-1)!.accepted).toBe(false);
    expect(v.reviews.at(-1)!.not_accepted_reasons).toContain("custodian_bindings_unreadable");
  });
});
