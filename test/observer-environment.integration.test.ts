// P3.3b (preliminary A): completion is derived for the DERIVING process's environment. A check result
// binds the effective child environment built from the environment of the process that evaluates it
// (plan §10.3), so an observer whose PATH differs — an operator terminal, a harness — derives the
// session's check results stale, and with them the review's check evidence, where the session's own
// server and hooks derive them current. These tests pin that:
//  1. the environment is the ONLY difference: the same run, store, configuration, source snapshot and
//     review record; the observer's view is labelled, and deriving records nothing;
//  2. stale review evidence never derives ready (a changed source, even with fresh passing checks; a
//     changed export; an unknown source), while the reviewed evidence derives ready again;
//  3. the operator's resume guard cannot be passed from a terminal whose environment hides a thread
//     that needs a user decision, and it needs a fresh read of the working tree.

import { describe, it, expect } from "vitest";
import { appendFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { findRun, loadEngine, type Loaded } from "../src/engine/engine-env.js";
import { routeRun } from "../src/engine/continuation.js";
import { OBSERVER_ENVIRONMENT_DIFFERS } from "../src/engine/status.js";
import { acquireWorktreeLock } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { readState } from "../src/store/state-store.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { itemNow, respond } from "./helpers/respond-fixture.js";
import { cli, contFixture, grant, HostSession, loopOf, newRun, operatorIo, reviewCtx, runChecks, startReview, writeRepoFile, type ContFixture } from "./helpers/continuation-fixture.js";

const ADD = "add() subtracts";
const approve = () => okScenario(output({ verdict: "APPROVE", summary: "Fine.", assessment: "Nothing to change.", findings: [] }));

/** This environment with one more PATH entry: what a terminal with another PATH is to CodeParley. */
function otherPathEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  const key = Object.keys(env).find((k) => k.toUpperCase() === "PATH") ?? "PATH";
  env[key] = `${env[key] ?? ""}${process.platform === "win32" ? ";" : ":"}${join(process.cwd(), "observer-only-path-entry")}`;
  return env;
}

/** The fixture's engine, deriving for another environment (an observer such as an operator terminal). */
function observer(f: ContFixture, env: NodeJS.ProcessEnv): Promise<Loaded> {
  return loadEngine({ ...f.le.env, sourceEnv: env });
}

async function readyRun(f: ContFixture) {
  const run = await newRun(f);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  const st = await readState(run.paths);
  const routed = await routeRun(f.le, run, st);
  expect(routed.report.completion.state).toBe("ready");
  return { run, st, routed };
}

async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await filesUnder(p)));
    else out.push(p);
  }
  return out;
}

/** A protected run whose disputed thread escalated in the session's environment: the loop is paused for a user decision. */
async function escalatedRun(sessionId: string, pid: number) {
  const f = await contFixture(okScenario(output({ findings: [defect()] })));
  const run = await newRun(f);
  const A = new HostSession(f, sessionId, pid);
  await grant(f, 1);
  await A.startLoop(run);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  const ctx = await reviewCtx(f, run);
  // The implementer disputes; the reviewer maintains; the implementer repeats itself without new information.
  const a1 = await itemNow(ctx, ADD);
  await respond(ctx, { responses: [{ finding_id: a1.id, response_token: a1.token!, disposition: "disputed", rationale: "Subtraction is intended here.", references: [{ path: "src/math.js", start_line: 1 }] }] });
  await setScenario(f, okScenario(output({ prior_findings: [{ id: "PF-1", assessment: "still_present", superseded_by_index: null, note: "" }], discussion_replies: [{ id: "PF-1", stance: "maintain", reply: "add() must add.", new_information: "not_applicable" }] })));
  await (await startReview(f, run)).done;
  const a2 = await itemNow(ctx, ADD);
  await respond(ctx, { responses: [{ finding_id: a2.id, response_token: a2.token!, disposition: "disputed", rationale: "As I said, subtraction is intended.", references: [{ path: "src/math.js", start_line: 1 }] }] });

  // The session (the environment the checks ran in): no new information, so the thread escalates — a hard pause.
  const session = await routeRun(f.le, run, await readState(run.paths));
  expect(session.report.completion.counts.needs_user_decision).toBe(1);
  expect(session.route).toMatchObject({ kind: "pause", pause: "user_decision_required" });
  expect((await A.stop(false)).verdict).toBe("none");
  expect(await loopOf(run)).toMatchObject({ status: "paused", pause: { reason: "user_decision_required" } });
  return { f, run, A };
}

describe.skipIf(!supported)("completion is derived for the deriving process's environment (P3.3b)", () => {
  it("one run: ready for the environment its checks ran in, stale for another PATH — every other input identical, the view labelled, nothing recorded", async () => {
    const f = await contFixture(approve());
    const { run, st, routed: session } = await readyRun(f);
    expect(session.report.limitations.map((l) => l.code)).not.toContain(OBSERVER_ENVIRONMENT_DIFFERS);

    const le2 = await observer(f, otherPathEnv());
    const run2 = await findRun(le2, run.runId);
    const terminal = await routeRun(le2, run2, st);
    // The same repository identity, store, configuration, source snapshot and trusted review record...
    expect(run2.repoKey).toBe(run.repoKey);
    expect(run2.meta.repository_root).toBe(run.meta.repository_root);
    expect(le2.dataHome).toBe(f.le.dataHome);
    expect(le2.cfg.config).toEqual(f.le.cfg.config);
    expect(terminal.src?.recomputed && terminal.src.stable).toBe(true);
    expect(terminal.src?.source_id).toBe(session.src?.source_id);
    expect(terminal.report.latest_review).toMatchObject({ review_id: session.report.latest_review!.review_id, source_id: session.report.latest_review!.source_id, accepted: true });
    // ...but check freshness is judged for the observer's own environment: stale there, never ready.
    expect(terminal.report.floor.stale).toEqual(["unit"]);
    expect(terminal.report.completion.state).toBe("checks_not_satisfied");
    expect(terminal.report.completion.blockers.map((b) => b.code)).toEqual(expect.arrayContaining(["required_check_stale", "review_stale"]));
    expect(terminal.report.latest_review?.freshness).toMatchObject({ source: true, inputs: false, current: false, stale_reasons: ["check_evidence_changed_since_review"] });
    expect(terminal.route.code).toBe("run_checks");
    // The observer's report says why (and lists it with completion's limitations).
    const note = terminal.report.limitations.find((l) => l.code === OBSERVER_ENVIRONMENT_DIFFERS);
    expect(note?.detail).toContain("unit");
    expect(terminal.report.completion.limitations.map((l) => l.code)).toContain(OBSERVER_ENVIRONMENT_DIFFERS);
    // Deriving is observing: nothing was recorded, and the checks' own environment still derives ready.
    expect((await readState(run.paths)).revision).toBe(st.revision);
    expect((await routeRun(f.le, run, await readState(run.paths))).report.completion.state).toBe("ready");

    // The operator's loop view in that environment carries the same note.
    const A = new HostSession(f, "sess-OBS", 8181);
    await grant(f, 1);
    await A.startLoop(run);
    const shown = await cli(f, ["loop", "show", run.runId], { ...operatorIo(""), env: otherPathEnv() });
    expect(shown.code, shown.err).toBe(0);
    // P3.4C-5 Increment 3 (§5.4): a protected run's next action is the custodian's derivation — it holds no check of this
    // run (they ran before it was protected), so it routes the checks; the terminal's environment note stays local.
    expect(shown.out).toMatch(/next action \(the custodian's derivation der-[0-9a-f]+, [^)]*\): run_checks/);
    expect(shown.out).toContain("only because this process's environment");
    const same = await cli(f, ["loop", "show", run.runId]);
    expect(same.out).not.toContain("only because this process's environment");
  });

  it("stale review evidence never derives ready: a changed source (even with fresh passing checks), an unknown source, a changed export", async () => {
    const f = await contFixture(approve());
    const { run } = await readyRun(f);

    // The working tree changes after the review.
    await writeRepoFile(f, "src/extra.js", "export const x = 1;\n");
    let r = await routeRun(f.le, run, await readState(run.paths));
    expect(r.report.completion.ready).toBe(false);
    expect(r.report.latest_review?.freshness?.stale_reasons).toContain("source_changed_since_review");
    // Fresh, passing checks on the new source do not make the old review current.
    await runChecks(f, run);
    r = await routeRun(f.le, run, await readState(run.paths));
    expect(r.report.floor.satisfied_for_current_source).toBe(true);
    expect(r.report.completion.state).toBe("review_not_current");
    expect(r.report.completion.blockers.map((b) => b.code)).toContain("review_stale");
    expect(r.route.code).toBe("request_review");
    // Back to the reviewed source: the evidence the review saw is current again (derived, not remembered).
    await rm(join(f.repo, "src", "extra.js"));
    r = await routeRun(f.le, run, await readState(run.paths));
    expect(r.report.completion.state).toBe("ready");

    // A report that could not read the tree within its time: the source is unknown, never ready.
    r = await routeRun(f.le, run, await readState(run.paths), 0);
    expect(r.src?.recomputed).toBe(false);
    expect(r.report.completion.state).toBe("incomplete");
    expect(r.report.completion.blockers.map((b) => b.code)).toContain("current_source_unknown");
    expect(r.route.code).toBe("refresh_status");

    // The review's export no longer matches what the engine published: stale, never ready.
    const st = await readState(run.paths);
    const review = st.reviews.find((x) => x.accepted === true)!;
    const exported = (await filesUnder(join(run.paths.runDir, ...review.export_ref.split("/")))).find((p) => !p.endsWith("manifest.json"))!;
    await appendFile(exported, "\n// changed after the review\n");
    r = await routeRun(f.le, run, await readState(run.paths));
    expect(r.report.completion.ready).toBe(false);
    expect(r.report.latest_review?.freshness?.stale_reasons).toContain("export_changed_since_review");
  });

  it("a terminal whose environment hides a needed user decision cannot resume the loop; neither can one that cannot read the tree", async () => {
    const { f, run } = await escalatedRun("sess-ENV", 7171);

    // A terminal with another PATH sees the check stale, which reads as new check evidence: there the
    // same thread waits for the reviewer, and its own derivation finds no needed user decision.
    const env2 = otherPathEnv();
    const le2 = await observer(f, env2);
    const terminal = await routeRun(le2, await findRun(le2, run.runId), await readState(run.paths));
    expect(terminal.report.completion.counts.needs_user_decision).toBe(0);
    expect(terminal.route.kind).not.toBe("pause");
    // The resume is refused there all the same: a needed decision in any view refuses it.
    const refused = await cli(f, ["loop", "resume", run.runId], { ...operatorIo("resume"), env: env2 });
    expect(refused.code).toBe(1);
    expect(refused.err).toContain("still needs a user decision");
    expect((await loopOf(run)).status).toBe("paused");

    // Without a fresh read of the working tree nothing is resumed either.
    const lock = await acquireWorktreeLock(worktreeLockPath(f.dataHome, canonicalPathKey(run.meta.repository_root)), { owner: f.le.env.owner, operationId: "test-holds-the-worktree", kind: "capture" });
    try {
      const busy = await cli(f, ["loop", "resume", run.runId], operatorIo("resume"));
      expect(busy.code).toBe(1);
      expect(busy.err).toContain("could not be read fresh and stable");
    } finally {
      await lock.release();
    }
    expect((await loopOf(run)).status).toBe("paused");

    // A decision in the user-writable store (`decide` without --protected) does not satisfy the guard on a protected run:
    // it derives from the custodian's records (P3.4C-3 C1); the protected decision does (the case below).
    const thread = (await readState(run.paths)).findings.find((x) => x.title === ADD)!.id;
    const decided = await cli(f, ["decide", run.runId, thread, "defer", "--note", "next sprint"], operatorIo("defer"));
    expect(decided.code, decided.err).toBe(0);
    const still = await cli(f, ["loop", "resume", run.runId], { ...operatorIo("resume"), env: env2 });
    expect(still.code).toBe(1);
    expect(still.err).toContain("still needs a user decision");
    expect((await loopOf(run)).status).toBe("paused");
    expect((await readState(run.paths)).user_decisions).toHaveLength(1);
  });

  it("after the user's protected decision the same terminal can resume", async () => {
    const { f, run } = await escalatedRun("sess-ENV2", 7172);
    const thread = (await readState(run.paths)).findings.find((x) => x.title === ADD)!.id;
    const decided = await cli(f, ["decide", run.runId, thread, "defer", "--note", "next sprint", "--protected"], operatorIo("defer"));
    expect(decided.code, decided.err).toBe(0);
    const resumed = await cli(f, ["loop", "resume", run.runId], { ...operatorIo("resume"), env: otherPathEnv() });
    expect(resumed.code, resumed.err).toBe(0);
    expect((await loopOf(run)).status).toBe("active");
  }, 180_000); // two protected CLI round trips after an escalation: 60 s was exceeded under machine load (Phase 6 Increment 1, run A)
});
