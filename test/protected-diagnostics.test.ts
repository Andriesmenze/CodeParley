// P3.4C-5 Increment 4 (contract §6, N5-8, N5-9): actionable diagnostics for contexts that cannot run the protected path.
// Every failure names its cause and the operator's remedy, and still fails closed — there is no fallback to the engine's
// own computation.
//
// N5-8 — a repository the helper's group cannot read is refused when the operator protects it, at a protected reservation
//        and at a derivation (REPOSITORY_NOT_READABLE with the exact icacls grant on the repository only).
// N5-9 — the isolation profile cannot start without an interactive desktop (0xC0000142): the self-test, the isolation
//        decision and a review say `no_desktop_session` with the remedy (run from a signed-in desktop session, D-17).
// (HELPER_UNAVAILABLE and RUNTIME_NOT_APPROVED, with their commands, are test/protected-capture.test.ts's.)

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { runSelfTest } from "../src/agents/codex/selftest.js";
import { classifyOutcome } from "../src/agents/codex/events.js";
import { decideIsolation, isolationUnavailableError } from "../src/agents/codex/isolation.js";
import type { CodexProbe } from "../src/agents/codex/probe.js";
import type { CodexAudit, SelfTestRecord } from "../src/schemas/review.js";
import { isDomainError } from "../src/common/errors.js";
import { custodianDerivationOf } from "../src/custodian/grants.js";
import { startChecksOperation } from "../src/engine/operations.js";
import { supported, win } from "./helpers/git-fixture.js";
import { fakeSelfTestDeps, makeReviewFixture, okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, grant, HostSession, newRun, operatorIo } from "./helpers/continuation-fixture.js";

const NO_DESKTOP = 0xc0000142;

describe.skipIf(!supported || !win)("N5-9 — no interactive desktop session (0xC0000142)", () => {
  it("the self-test records no_desktop_session with the remedy; the isolation decision and its error carry reason no_desktop_session", async () => {
    const f = await makeReviewFixture();
    const probe = { version: "0.160.0", installDir: f.fakeDir, compat: { webSearchDisabledValue: "disabled" } } as unknown as CodexProbe;
    const deps = fakeSelfTestDeps(f);
    // The sandbox cannot start any process in this context: the profile's liveness probe exits 0xC0000142.
    const noDesktop = { ...deps, runCodex: async () => ({ status: NO_DESKTOP, stdout: "", stderr: "" }) };
    const rec = await runSelfTest({ probe, backend: "mxc", mode: "S1", dataHome: f.dataHome, deps: noDesktop });
    expect(rec.profile_runs).toBe(false);
    expect(rec.s1_available).toBe(false);
    expect(rec.rejection_reason).toMatch(/^no_desktop_session: .*0xC0000142.*signed-in desktop session \(D-17\)/);

    const d = decideIsolation({ compat: { webSearchDisabledValue: "disabled" } as never, codexVersion: "0.160.0", installDir: f.fakeDir, backends: ["mxc"], selfTests: new Map([["mxc", rec as SelfTestRecord]]), acceptances: [], userHooksPresent: false });
    expect(d.ok).toBe(false);
    const reasons = (d as { reasons: string[] }).reasons;
    expect(reasons.join(" ")).toContain("no_desktop_session");
    const e = isolationUnavailableError(reasons);
    expect(e.code).toBe("CODEX_ISOLATION_UNAVAILABLE");
    expect(e.details).toMatchObject({ reason: "no_desktop_session", remedy: expect.stringContaining("PowerShell Direct") });
    expect(e.message).toContain("no interactive desktop session");
  }, 120_000);
});

describe("N5-9 — a review whose isolated processes cannot start fails closed, naming the cause", () => {
  const audit = (exitCodes: (number | null)[]): CodexAudit => ({ commands: exitCodes.map((c) => ({ command: "type x", exit_code: c, status: "failed" })), turn_completed: true, turn_failed: null, error_events: [] }) as unknown as CodexAudit;
  const base = { spawnError: null, timedOut: false, idleTimedOut: false, cancelled: false, stderrTail: "", lastMessage: "{}" };
  it("Codex exiting 0xC0000142, or a command it ran exiting so, is no_desktop_session with the remedy; other failures are unchanged", () => {
    expect(classifyOutcome({ ...base, exitStatus: NO_DESKTOP, audit: audit([]) })).toMatchObject({ status: "failed", failureClass: "no_desktop_session", detail: expect.stringContaining("CODEX_ISOLATION_UNAVAILABLE (no_desktop_session)") });
    expect(classifyOutcome({ ...base, exitStatus: 0, audit: audit([0, -1073741502]) })).toMatchObject({ status: "failed", failureClass: "no_desktop_session", detail: expect.stringContaining("signed-in desktop session") });
    expect(classifyOutcome({ ...base, exitStatus: 0, audit: audit([0, 1]) }).failureClass).not.toBe("no_desktop_session");
    expect(classifyOutcome({ ...base, exitStatus: 3, audit: audit([]) }).failureClass).toBe("non_zero_exit");
  });
});

describe.skipIf(!supported)("N5-8 — the helper's repository group cannot read the repository", () => {
  it("config set, a protected reservation and the derivation refuse REPOSITORY_NOT_READABLE with the icacls remedy; once granted, the run proceeds", async () => {
    let readable = true;
    const sid = "S-1-5-21-1-2-3-1009";
    const f = await contFixture(okScenario(output({ findings: [] })), { repositoryReaders: { sid, name: "CodeParley Repository Readers", problem: () => (readable ? null : "no ACE grants it read and execute, inherited by files and folders") } });
    await grant(f, 1); // the operator protects the repository while it is readable
    const run = await newRun(f);
    await new HostSession(f, "sess-n58", 7501).startLoop(run);
    readable = false;
    const remedy = `icacls "${run.meta.repository_root}" /grant "*${sid}:(OI)(CI)(RX)"`;
    let refused: unknown = null;
    try {
      await (await startChecksOperation(f.le, run, {})).completion;
    } catch (e) {
      refused = e;
    }
    expect(isDomainError(refused) && refused.code).toBe("REPOSITORY_NOT_READABLE");
    expect((refused as Error).message).toContain(remedy);
    const d = await custodianDerivationOf(f.custodian, "implementer", run.meta.repository_root, run.runId, await readFile(run.paths.runJson));
    expect(d).toMatchObject({ available: false, code: "REPOSITORY_NOT_READABLE" });
    const set = await cli(f, ["config", "set", "--repo", f.repo, "--codex", f.codexExe], operatorIo("confirm", true));
    expect(set.code).not.toBe(0);
    expect(set.err + set.out).toContain("REPOSITORY_NOT_READABLE");
    expect(set.err + set.out).toContain("/grant");
    readable = true;
    const r = await (await startChecksOperation(f.le, run, {})).completion;
    expect(r.kind).toBe("checks");
  }, 180_000);
});
