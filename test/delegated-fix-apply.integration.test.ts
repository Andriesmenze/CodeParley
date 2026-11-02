// Phase 4 Increment 3 — the owner's confirmation of the custodian's rendering and the safe application (contract §3.5,
// §3.6), end to end against real git repositories, the simulated custodian (its in-process helper capture, measurement
// and derivation) and the engine's own application path. Every assertion reads the worktree, the engine's journal and
// lock, and the custodian's own records.
//
//   N4-6  only the operator surface confirms; a changed proposal, baseline or rendering refuses the commit
//         (CONFIRMATION_CONTENT_MISMATCH: the shared corpus; here the CLI's typed decision and the implementer refusal);
//   N4-7  the application is refused without a confirmation, after a rejection, after expiry, on a replay (single use);
//   N4-8  a concurrent application (WORKTREE_BUSY), a source changed since the baseline (FIX_STALE, nothing written, the
//         confirmation unused), and data-home "proposal" files planted after the confirmation make no difference;
//   N4-9  use-time safety: a preimage changed at use, a redirected parent (junction), a hard-linked target, an add whose
//         target exists in the worktree but not in the sanitized export — refused or rolled back, nothing outside written;
//   N4-10 interruption: a killed application is apply_interrupted, never applied; the loop pauses; `fix reconcile`
//         reports and restores; the lock is ownership_unresolved until reconciled;
//   N4-11 after the application the run is not ready until fresh checks and a fresh accepted review are current.

import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { link, mkdir, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli } from "../src/cli/cli.js";
import { delegateFix } from "../src/engine/fix-operation.js";
import { applyFix, journalDirOf, SimulatedKill } from "../src/engine/fix-apply.js";
import { custodianDerivationOf } from "../src/custodian/grants.js";
import { acquireWorktreeLock, readWorktreeLock } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { selfOwner } from "../src/store/owner.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1, MATH_V2 } from "./helpers/review-fixture.js";
import { cli, operatorIo, runChecks, type ContFixture } from "./helpers/continuation-fixture.js";
import { TASK, codeOf, confirmFix, editing, editingMany, opsOf, protectedRun, sha, storeFixSelfTest_ } from "./helpers/delegated-fix.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import type { SimWriter } from "../src/custodian/simulated-runs.js";

const BOUND = { timeout: 300_000 };
const EXTRA = "export const extra = 1;\n";
const TWO = { task: "fix add() and add src/extra.js", boundary: { permitted_files: ["src/math.js", "src/extra.js"], allow_create: true, max_changed_files: 2, max_file_bytes: 4096, max_total_bytes: 8192, time_limit_seconds: 120, proposal_lifetime_seconds: 3600 } };

/** A protected run with one delegated fix proposed (the custodian holds its content). */
async function proposed(maxFixes = 2, task = TASK, edits = editing("src/math.js", MATH_V1), opts = {}): Promise<{ f: ContFixture; run: RunHandle; op: string; A: Awaited<ReturnType<typeof protectedRun>>["A"] }> {
  const { f, run, A } = await protectedRun(maxFixes, opts);
  await storeFixSelfTest_(f);
  await confirmFix(f);
  const r = await delegateFix(f.le, run, task, { launch: edits });
  expect(r.status, r.detail ?? "").toBe("proposed");
  return { f, run, op: r.operation_id, A };
}

/** The owner's decision at the operator terminal, typed (`fix confirm|reject <run> <proposal>`). */
const decide = (f: ContFixture, run: RunHandle, op: string, decision: "confirm" | "reject", typed: string = decision, interactive = true) =>
  cli(f, ["fix", decision, run.runId, op, "--repo", f.repo], operatorIo(typed, interactive));

const math = (f: ContFixture): Promise<string> => readFile(join(f.repo, "src", "math.js"), "utf8");

describe.skipIf(!supported)("Phase 4 Increment 3: confirmation of the rendered bytes and the safe application (engine)", BOUND, () => {
  it("the owner confirms exactly the custodian's rendering; apply_fix writes only that content, once; the run then needs fresh checks and a distinct review before ready (N4-11)", async () => {
    const { f, run, op } = await proposed();
    // fix show prints the custodian's own rendering (the implementer inspects the same bytes).
    const shown = await cli(f, ["fix", "show", run.runId, op], operatorIo(""));
    expect(shown.code, shown.err).toBe(0);
    expect(shown.out).toContain("--- a/src/math.js");
    expect(shown.out).toContain("-  return a - b;");
    expect(shown.out).toContain("+  return a + b;");
    expect(shown.out).toMatch(/rendering sha256: [0-9a-f]{64}/);
    const renderingDigest = /rendering sha256: ([0-9a-f]{64})/.exec(shown.out)![1]!;
    // Phase 5 F-i2-5: the operator, with no run store of its own, sees the same bytes through the custodian (--repo).
    const opHome = join(f.scratch, "op-home-fix-show");
    await mkdir(opHome, { recursive: true });
    const io = operatorIo("");
    const code = await runCli(["fix", "show", run.runId, op, "--repo", f.repo, "--home", opHome, "--git", f.git], { ...io, engineTestHooks: f.le.env.testHooks! });
    expect(code, io.errors.join(" | ")).toBe(0);
    expect(io.lines).toEqual(shown.out.split(/\r?\n/));
    expect(await readdir(join(opHome, "runs")).catch(() => [])).toEqual([]);

    // The typed confirmation, at an interactive terminal, binds that rendering.
    const confirmed = await decide(f, run, op, "confirm");
    expect(confirmed.code, confirmed.err).toBe(0);
    expect(confirmed.out).toContain(`rendering sha256: ${renderingDigest}`);
    expect(confirmed.out).toContain(`bound to rendering ${renderingDigest}`);
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["confirmed"]);
    expect(await math(f)).toBe(MATH_V2);

    // Before the application, the derivation routes the confirmed fix to an await (no continuation, no wake).
    const runJson = await readFile(run.paths.runJson);
    const awaiting = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, runJson);
    expect(awaiting.available && awaiting.route).toMatchObject({ code: "await_fix_application", kind: "await" });

    const r = await applyFix(f.le, run, { proposal_id: op });
    expect(r).toMatchObject({ status: "applied", files: [{ path: "src/math.js", state: "postimage" }] });
    expect(r.source_id_after).toMatch(/^[0-9a-f]{64}$/);
    expect(await math(f)).toBe(MATH_V1);
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["consumed"]);
    expect(opsOf(f, run, "apply").map((o) => o.status)).toEqual(["applied"]);
    // The custodian's content is retired; the journal and the lock are gone.
    expect(f.custodian.heldProposalForTest(f.repo, run.runId, op)).toEqual({ held: false });
    expect(existsSync(journalDirOf(f.dataHome, run.runId, r.apply_operation_id))).toBe(false);
    expect(await readWorktreeLock(worktreeLockPath(f.dataHome, canonicalPathKey(f.repo)))).toBeNull();

    // Single use: a second application is refused, nothing written again.
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("CONFIRMATION_CONSUMED");

    // N4-11: the applied source is not ready: its checks are not fresh and no accepted review covers it — the route is an
    // implementer step (address the finding: run checks, request a distinct review), never ready.
    const after = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, runJson);
    expect(after.available && after.completion.state).not.toBe("ready");
    expect(after.available && after.route).toMatchObject({ kind: "implementer_step" });
    expect(after.available && after.completion.blockers.map((b) => b.category)).toEqual(expect.arrayContaining(["checks_not_satisfied"]));
  });

  it("N4-6/N4-7: no confirmation, no application; the implementer surface cannot confirm; the CLI needs a typed decision at an interactive terminal; a confirmation is decided once", async () => {
    const { f, run, op } = await proposed();
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("FIX_NOT_CONFIRMED");
    // A confirmation request on the implementer surface: refused by caller class (nothing prepared).
    const forged = await f.custodian.send("implementer", "prepare_fix_decision", { repositoryRoot: f.repo, runId: run.runId, operationId: op, decision: "confirm" }, "forged-1");
    expect(forged).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    // apply_fix's input carries no confirmation (strict schema), and the custodian refuses a confirmation-shaped field.
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op, confirmation_id: "c-1" } as never))).not.toBe("ok");
    // Not at an interactive terminal; or a mistyped answer: nothing is recorded.
    expect((await decide(f, run, op, "confirm", "confirm", false)).err).toContain("INTERACTIVE_TERMINAL_REQUIRED");
    expect((await decide(f, run, op, "confirm", "yes")).code).toBe(2);
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["proposed"]);
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    // Decided once: neither a second confirmation nor a rejection of a confirmed proposal is prepared.
    expect((await decide(f, run, op, "confirm")).err).toContain("PROPOSAL_NOT_PENDING");
    expect((await decide(f, run, op, "reject")).err).toContain("PROPOSAL_NOT_PENDING");
    expect(await math(f)).toBe(MATH_V2);
  });

  it("N4-7: a rejected proposal is never applied; an expired confirmation is refused", async () => {
    const { f, run, op } = await proposed(2);
    expect((await decide(f, run, op, "reject")).code).toBe(0);
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["declined"]);
    expect(f.custodian.heldProposalForTest(f.repo, run.runId, op)).toEqual({ held: false });
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("FIX_DECLINED");

    const second = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
    expect((await decide(f, run, second.operation_id, "confirm")).code).toBe(0);
    f.clock.now = Date.now() + 45 * 60_000; // past the confirmation's 30 minutes
    expect(await codeOf(applyFix(f.le, run, { proposal_id: second.operation_id }))).toBe("CONFIRMATION_EXPIRED");
    expect(await math(f)).toBe(MATH_V2);
  });

  it("N4-8: a source changed since the baseline is FIX_STALE — nothing written, the confirmation unused; data-home 'proposal' files planted after the confirmation make no difference", async () => {
    const { f, run, op } = await proposed();
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    // Someone edits the worktree after the review the fix was made against.
    await writeFile(join(f.repo, "src", "math.js"), MATH_V2 + "// edited\n");
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("FIX_STALE");
    expect(await math(f)).toBe(MATH_V2 + "// edited\n");
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["confirmed"]); // unused
    expect(opsOf(f, run, "apply")).toEqual([]);
    // Back at the baseline, with forged proposal files planted in the data home: the custodian's content is applied.
    await writeFile(join(f.repo, "src", "math.js"), MATH_V2);
    await mkdir(join(f.dataHome, "work", run.runId, "forged", "tree", "src"), { recursive: true });
    await writeFile(join(f.dataHome, "work", run.runId, "forged", "tree", "src", "math.js"), "FORGED\n");
    await mkdir(join(f.dataHome, "fix-proposals"), { recursive: true });
    await writeFile(join(f.dataHome, "fix-proposals", `${op}.json`), JSON.stringify({ changes: [{ path: "src/math.js", content: Buffer.from("FORGED\n").toString("base64") }] }));
    const r = await applyFix(f.le, run, { proposal_id: op });
    expect(r.status).toBe("applied");
    expect(await math(f)).toBe(MATH_V1);
  });

  it("N4-8: a second, concurrent application is refused (WORKTREE_BUSY) while the first holds the worktree", async () => {
    const { f, run, op } = await proposed(3);
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let reached!: () => void;
    const inside = new Promise<void>((r) => (reached = r));
    const first = applyFix(f.le, run, { proposal_id: op }, { beforeReplace: async () => { reached(); await gate; } });
    await inside;
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("WORKTREE_BUSY");
    // An application in flight (the run `applying`) routes a wait — the custodian's derivation over its own records.
    const during = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, await readFile(run.paths.runJson));
    expect(during.available && during.route).toMatchObject({ code: "wait_for_operation", reason: "apply_running" });
    release();
    expect((await first).status).toBe("applied");
  });

  it("N4-9: a preimage changed at use fails the application and every file already replaced is restored (apply_failed)", async () => {
    const { f, run, op } = await proposed(2, TWO, editingMany({ "src/extra.js": EXTRA, "src/math.js": MATH_V1 }));
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    // The changes are applied in canonical order (src/extra.js, then src/math.js); math.js changes just before its replace.
    const r = await applyFix(f.le, run, { proposal_id: op }, { beforeReplace: async (rel, abs) => { if (rel === "src/math.js") await writeFile(abs, "RACED\n"); } });
    expect(r.status).toBe("apply_failed");
    expect(r.detail).toContain("not at the confirmed preimage");
    // The add was rolled back; the raced file kept the racer's bytes (never overwritten).
    expect(existsSync(join(f.repo, "src", "extra.js"))).toBe(false);
    expect(await math(f)).toBe("RACED\n");
    // The parent held: the temporary file of the refused replace was removed (none is left in the worktree).
    expect((await readdir(join(f.repo, "src"))).filter((n) => n.startsWith(".cp-fix-"))).toEqual([]);
    expect(r.files).toEqual([{ path: "src/extra.js", state: "absent" }, { path: "src/math.js", state: "other" }]);
    expect(opsOf(f, run, "apply").map((o) => o.status)).toEqual(["apply_failed"]);
    // The derivation pauses on the failed application (never retried automatically).
    const d = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, await readFile(run.paths.runJson));
    expect(d.available && d.route).toMatchObject({ kind: "pause", reason: "apply_apply_failed" });
  });

  it("N4-9: a redirected parent (src replaced by a junction to a directory outside the repository) is refused; nothing outside the repository is written", async () => {
    const { f, run, op } = await proposed();
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    const outside = join(f.scratch, "outside");
    await mkdir(outside, { recursive: true });
    await writeFile(join(outside, "math.js"), MATH_V2);
    const r = await applyFix(f.le, run, { proposal_id: op }, {
      beforeReplace: async () => {
        await rename(join(f.repo, "src"), join(f.repo, "src-moved"));
        await symlink(outside, join(f.repo, "src"), "junction");
      },
    });
    expect(r.status).toBe("apply_failed");
    expect(await readFile(join(outside, "math.js"), "utf8")).toBe(MATH_V2);
    expect((await readdir(outside)).filter((n) => n.startsWith(".cp-fix-"))).toEqual([]);
    // Nothing is removed through the redirected path: the temporary file moved away with the real directory, and the
    // failure names it (it holds only the confirmed bytes).
    const strays = (await readdir(join(f.repo, "src-moved"))).filter((n) => n.startsWith(".cp-fix-"));
    expect(strays).toHaveLength(1);
    expect(r.detail).toContain(`the temporary file ${strays[0]} (the confirmed bytes of src/math.js) was not removed`);
  });

  it("N4-9: a hard-linked target is refused — by the custodian's re-measurement before the application (FIX_STALE), and by the engine's own check at use", async () => {
    const { f, run, op } = await proposed();
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    const outsideLink = join(f.scratch, "math-hardlink.js");
    await link(join(f.repo, "src", "math.js"), outsideLink);
    expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("FIX_STALE");
    expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["confirmed"]); // unused
    await rm(outsideLink);
    // The link made after the custodian measured (between pre-validation and the replace): the engine refuses at use.
    const r = await applyFix(f.le, run, { proposal_id: op }, { beforeReplace: async (_rel, abs) => link(abs, outsideLink) });
    expect(r.status).toBe("apply_failed");
    expect(r.detail).toContain("hard-linked");
    expect(await readFile(outsideLink, "utf8")).toBe(MATH_V2);
    expect(await math(f)).toBe(MATH_V2);
  });

  it("N4-9 (Increment 2 residual): an add of a path the sanitized export never held but the worktree does (.env) is refused at use", async () => {
    const task = { task: "create .env", boundary: { permitted_files: [".env"], allow_create: true, max_changed_files: 1, max_file_bytes: 4096, max_total_bytes: 4096, time_limit_seconds: 120, proposal_lifetime_seconds: 3600 } };
    const { f, run, op } = await proposed(2, task, editing(".env", "OVERWRITTEN=1\n"));
    const held = f.custodian.heldProposalForTest(f.repo, run.runId, op) as { paths: string[]; preimages: unknown[] };
    expect(held.paths).toEqual([".env"]);
    expect(held.preimages).toEqual([null]); // an add: absent from the custodian's baseline (confidential, never exported)
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    const before = await readFile(join(f.repo, ".env"), "utf8");
    const r = await applyFix(f.le, run, { proposal_id: op });
    expect(r.status).toBe("apply_failed");
    expect(r.detail).toContain("exists, but the confirmed change adds it");
    expect(await readFile(join(f.repo, ".env"), "utf8")).toBe(before);
  });

  it("N4-10: a killed application is apply_interrupted (never applied), pauses the loop, holds the lock unresolved, and `fix reconcile --restore` returns the files to their preimage and clears it", async () => {
    const gone = new Set<number>();
    const writerGone = (w: SimWriter): boolean | null => gone.has(w.pid);
    const { f, run, op } = await proposed(2, TWO, editingMany({ "src/extra.js": EXTRA, "src/math.js": MATH_V1 }), { writerGone });
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    // The process dies after its first write (src/extra.js): no rollback, no finish, the lock left behind.
    await expect(applyFix(f.le, run, { proposal_id: op }, { killAfterWrites: 1 })).rejects.toBeInstanceOf(SimulatedKill);
    expect(await readFile(join(f.repo, "src", "extra.js"), "utf8")).toBe(EXTRA);
    expect(await math(f)).toBe(MATH_V2);
    const applyOp = opsOf(f, run, "apply")[0]!;
    expect(applyOp.status).toBe("running");
    expect(existsSync(join(journalDirOf(f.dataHome, run.runId, applyOp.operationId), "journal.json"))).toBe(true);
    // Its writer is gone (this test process plays the dead one): the lock is never released automatically.
    gone.add(process.pid);
    const lockPath = worktreeLockPath(f.dataHome, canonicalPathKey(f.repo));
    expect(await codeOf(acquireWorktreeLock(lockPath, { owner: selfOwner(), operationId: "next", kind: "checks" }, { classify: async () => "dead", staleMs: 0 }))).toBe("WORKTREE_OWNERSHIP_UNRESOLVED");
    expect((await readWorktreeLock(lockPath))?.ownership_unresolved).toBe(true);

    // The report alone records nothing (exit 3: a choice is needed); the custodian recovered the operation first.
    const report = await cli(f, ["fix", "reconcile", run.runId], operatorIo(""));
    expect(report.code, report.err).toBe(3);
    expect(report.out).toContain("some files at their postimage");
    expect(report.out).toContain("add src/extra.js: postimage");
    expect(report.out).toContain("modify src/math.js: preimage");
    expect(opsOf(f, run, "apply").map((o) => o.status)).toEqual(["apply_interrupted"]);
    expect(f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!.incidents.map((i) => `${i.kind}:${i.source}`)).toContain("apply_interrupted:custodian");
    // The loop pauses until it is reconciled, whatever was acknowledged.
    const runJson = await readFile(run.paths.runJson);
    const paused = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, runJson);
    expect(paused.available && paused.route).toMatchObject({ kind: "pause", reason: "apply_interrupted_unreconciled" });
    // Another application of the repository is refused until then.
    const other = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
    expect((await decide(f, run, other.operation_id, "confirm")).code).toBe(0);
    gone.delete(process.pid);
    await writeFile(join(f.repo, "src", "extra.js"), EXTRA); // (still there)
    expect(["APPLY_IN_PROGRESS", "WORKTREE_OWNERSHIP_UNRESOLVED", "FIX_STALE"]).toContain(await codeOf(applyFix(f.le, run, { proposal_id: other.operation_id })));

    const restored = await cli(f, ["fix", "reconcile", run.runId, "--restore"], operatorIo(""));
    expect(restored.code, restored.err).toBe(0);
    expect(restored.out).toContain("add src/extra.js: postimage -> absent");
    expect(restored.out).toContain("the application's worktree lock was cleared");
    expect(existsSync(join(f.repo, "src", "extra.js"))).toBe(false);
    expect(await math(f)).toBe(MATH_V2);
    expect(opsOf(f, run, "apply").map((o) => o.status)).toEqual(["apply_interrupted_restored"]);
    expect(await readWorktreeLock(lockPath)).toBeNull();
    expect(existsSync(journalDirOf(f.dataHome, run.runId, applyOp.operationId))).toBe(false);
    // Never recorded applied; the run's checks run again (the lock is free).
    expect(opsOf(f, run, "apply").some((o) => o.status === "applied")).toBe(false);
    await runChecks(f, run);
  });

  it("N4-10: an interruption with every file already at its postimage is still never recorded applied; `--leave` keeps the files and records that", async () => {
    const gone = new Set<number>();
    const { f, run, op } = await proposed(2, TASK, editing("src/math.js", MATH_V1), { writerGone: (w: SimWriter) => gone.has(w.pid) });
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    // Killed right after its only write, before its finish.
    await expect(applyFix(f.le, run, { proposal_id: op }, { killAfterWrites: 1 })).rejects.toBeInstanceOf(SimulatedKill);
    expect(await math(f)).toBe(MATH_V1);
    gone.add(process.pid);
    const report = await cli(f, ["fix", "reconcile", run.runId], operatorIo(""));
    expect(report.code, report.err).toBe(3);
    expect(report.out).toContain("every file at its postimage (never recorded applied)");
    const left = await cli(f, ["fix", "reconcile", run.runId, "--leave"], operatorIo(""));
    expect(left.code, left.err).toBe(0);
    expect(opsOf(f, run, "apply").map((o) => o.status)).toEqual(["apply_interrupted_left"]);
    expect(await math(f)).toBe(MATH_V1);
    // Left as it is, the changed source goes through checks and review like any other change: never `applied`.
    const d = await custodianDerivationOf(f.custodian, "implementer", f.repo, run.runId, await readFile(run.paths.runJson));
    expect(d.available && d.route.kind).toBe("implementer_step");
    expect(d.available && d.completion.state).not.toBe("ready");
  });

  it("N4-10: killed with a temporary file in flight (the next file's confirmed bytes): the journal names it and `fix reconcile` removes it, so the worktree is the baseline again", async () => {
    const gone = new Set<number>();
    const { f, run, op } = await proposed(2, TWO, editingMany({ "src/extra.js": EXTRA, "src/math.js": MATH_V1 }), { writerGone: (w: SimWriter) => gone.has(w.pid) });
    expect((await decide(f, run, op, "confirm")).code).toBe(0);
    // The process dies inside the second replace, after its temporary file (src/math.js's postimage) was written.
    const dies = async (rel: string): Promise<void> => {
      if (rel === "src/math.js") throw new SimulatedKill();
    };
    await expect(applyFix(f.le, run, { proposal_id: op }, { beforeReplace: dies })).rejects.toBeInstanceOf(SimulatedKill);
    const temps = async (): Promise<string[]> => (await readdir(join(f.repo, "src"))).filter((n) => n.startsWith(".cp-fix-"));
    const [tmp] = await temps();
    expect(tmp).toBeDefined();
    gone.add(process.pid);
    const report = await cli(f, ["fix", "reconcile", run.runId], operatorIo(""));
    expect(report.code, report.err).toBe(3);
    expect(report.out).toContain(`temporary file src/${tmp}: present`);
    const restored = await cli(f, ["fix", "reconcile", run.runId, "--restore"], operatorIo(""));
    expect(restored.code, restored.err).toBe(0);
    expect(restored.out).toContain(`temporary file src/${tmp}: removed`);
    expect(await temps()).toEqual([]);
    expect(existsSync(join(f.repo, "src", "extra.js"))).toBe(false);
    expect(await math(f)).toBe(MATH_V2);
    gone.delete(process.pid);
    // The worktree is the baseline again: another confirmed fix applies (not FIX_STALE).
    const other = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
    expect((await decide(f, run, other.operation_id, "confirm")).code).toBe(0);
    expect((await applyFix(f.le, run, { proposal_id: other.operation_id })).status).toBe("applied");
  });
});
