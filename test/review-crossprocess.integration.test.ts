// Server crash during a review (plan §15.5; M1.3-11). A separate Node process acts as the
// server session and runs the compiled engine; its (fake) Codex starts a DETACHED
// descendant, standing in for an MXC sandboxed command that survives when codex.exe alone
// is terminated. The server is killed without /T (what Task Manager or a host crash does;
// Linux: SIGKILL, so none of its handlers run). A restarted session must mark the review
// interrupted, report the possible surviving sandboxed commands as an isolation incident, and
// sweep nothing. On Linux the server's session reaper has already ended Codex's linked tree.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { startReview } from "../src/engine/review-operation.js";
import { readState } from "../src/store/state-store.js";
import { clearProbeCache } from "../src/agents/codex/probe.js";
import { win, supported } from "./helpers/git-fixture.js";
import { pidAlive } from "../src/store/owner.js";
import { STALE_HEARTBEAT_MS } from "../src/store/locks.js";
import { isDomainError } from "../src/common/errors.js";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { defect, grandchildPid, makeReviewFixture, newReviewRun, okScenario, output, setScenario } from "./helpers/review-fixture.js";

// Flake P-e (Phase 6 Increment 1): a server killed inside a run-state commit leaves the run mutation lock fresh. It
// is broken only once its heartbeat is older than STALE_HEARTBEAT_MS and its holder is dead (fail-safe), and writes
// meanwhile answer the retryable STORE_LOCKED; under load a kill lands inside a commit more often. A client retries a
// retryable error, so the first write after the crash does too, for at most the stale threshold and a margin.
async function afterCrash<T>(call: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + STALE_HEARTBEAT_MS + 10_000;
  for (;;) {
    try {
      return await call();
    } catch (e) {
      if (!isDomainError(e) || e.code !== "STORE_LOCKED" || Date.now() > deadline) throw e;
      await new Promise((res) => setTimeout(res, 500));
    }
  }
}

const repoRootDir = join(dirname(fileURLToPath(import.meta.url)), "..");
let outDir = "";

const CHILD_REVIEW = `
import { readFileSync } from "node:fs";
import { startReview } from "./engine/review-operation.js";
import { selfOwner } from "./store/owner.js";
const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const hooks = { codexLauncher: cfg.launcher, sweep: null };
// F11 fault injection: die abruptly exactly where the completion used to be split.
if (cfg.crashBeforeCompletion) hooks.beforeCompletionCommit = () => process.kill(process.pid, "SIGKILL");
const ctx = { ...cfg, owner: selfOwner(), sourceEnv: process.env, testHooks: hooks };
try {
  const s = await startReview(ctx, cfg.request ?? {});
  process.stdout.write(JSON.stringify({ operation_id: s.operation_id, pid: process.pid }) + "\\n");
  const r = await s.completion;
  process.stdout.write(JSON.stringify({ done: r.status }) + "\\n");
} catch (e) {
  process.stdout.write(JSON.stringify({ error: e.code ?? String(e) }) + "\\n");
}
`;


async function waitFor(fn: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return fn();
}

/** Kill a process abruptly (Windows: taskkill /F, the tree only with /T; Linux: SIGKILL to that process). */
function hardKill(pid: number, tree = false): void {
  if (!win) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* already gone */
    }
    return;
  }
  spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(pid), ...(tree ? ["/T"] : []), "/F"], { stdio: "ignore", windowsHide: true });
}

let ownBuild = false;
beforeAll(async () => {
  if (!supported) return;
  // The run-wide build of src/, or this file's own where there is none; the child script goes beside it.
  const shared = sharedCompiledSrc();
  if (shared) outDir = shared;
  else {
    outDir = join(repoRootDir, ".tmp-test-dist", randomBytes(4).toString("hex"));
    await mkdir(outDir, { recursive: true });
    buildSrc(repoRootDir, outDir);
    ownBuild = true;
  }
  await writeFile(join(outDir, "child-review.mjs"), CHILD_REVIEW);
}, 120_000);

afterAll(async () => {
  if (outDir && ownBuild) await rm(outDir, { recursive: true, force: true }).catch(() => undefined);
});

describe.skipIf(!supported)("server crash during a review (M1.3-11, §15.5)", () => {
  it("a restarted session reports possible surviving sandboxed commands, marks the review interrupted and sweeps nothing", async () => {
    clearProbeCache();
    const f = await makeReviewFixture();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 5 });
    // A first review stores the S1 self-test record the crashing session reuses.
    await setScenario(f, okScenario(output()));
    expect((await (await startReview(ctx, {})).completion).status).toBe("completed");

    await setScenario(f, { exec: { spawn_grandchild: true, hang: "silent" } });
    const cfgFile = join(f.scratch, "child-ctx.json");
    const { dataHome, runPaths, meta, gitExe, rules, trustProjectsPath, trustIsolationPath, selftestDir, codex, budgets } = ctx;
    await writeFile(cfgFile, JSON.stringify({ dataHome, runPaths, meta, gitExe, rules, trustProjectsPath, trustIsolationPath, selftestDir, codex: { ...codex }, budgets, launcher: ctx.testHooks!.codexLauncher, request: { force_new: true } }));
    const server = spawn(process.execPath, [join(outDir, "child-review.mjs"), cfgFile], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let out = "";
    server.stdout!.on("data", (b: Buffer) => (out += b.toString("utf8")));
    expect(await waitFor(() => out.includes("operation_id"), 60_000)).toBe(true);
    const started = JSON.parse(out.split("\n")[0]!) as { operation_id: string; pid: number };
    let errOut = "";
    server.stderr!.on("data", (b: Buffer) => (errOut += b.toString("utf8")));
    expect(await waitFor(() => grandchildPid(f) !== null, 30_000), `server output: ${out} ${errOut}`).toBe(true);
    const gc = grandchildPid(f)!;
    let codexPid = 0;
    expect(
      await waitFor(async () => {
        const op = (await readState(ctx.runPaths)).operations.find((o) => o.operation_id === started.operation_id);
        codexPid = (op?.["child"] as { pid?: number } | undefined)?.pid ?? 0;
        return codexPid > 0;
      }, 30_000),
    ).toBe(true);

    try {
      hardKill(started.pid); // the server dies; no /T
      expect(await waitFor(() => !pidAlive(started.pid), 15_000)).toBe(true);
      expect(await waitFor(() => !pidAlive(codexPid), 15_000)).toBe(true);
      if (win) {
        // codex.exe (here: the fake) was in the server's kill-on-close job; the detached
        // descendant, like an MXC sandboxed command after codex.exe alone died, survives.
        expect(pidAlive(gc)).toBe(true);
      } else {
        // Plan §1.13: the session reaper ended Codex's session and everything linked to it when
        // it looked, the detached descendant included (its parent was still alive).
        expect(await waitFor(() => !pidAlive(gc), 15_000)).toBe(true);
      }

      // A restarted session: recovery runs before anything else.
      await setScenario(f, okScenario(output()));
      const r = await (await afterCrash(() => startReview(ctx, { focus: "after the crash" }))).completion;
      expect(r.status).toBe("completed");
      const st = await readState(ctx.runPaths);
      const crashed = st.operations.find((o) => o.operation_id === started.operation_id)!;
      expect(crashed.status).toBe("interrupted");
      const crashedReview = st.reviews.find((x) => x.operation_id === started.operation_id)!;
      expect(crashedReview).toMatchObject({ status: "interrupted", failure: { class: "owner_died" } });
      const inc = st.isolation_incidents.find((i) => i.kind === "possible_surviving_sandboxed_commands")!;
      expect(inc).toBeTruthy();
      expect(inc.operation_id).toBe(started.operation_id);
      expect(inc.review_id).toBe(crashedReview.review_id);
      expect(inc.detail).toContain(`recorded codex child pid ${codexPid}`);
      if (win) {
        expect(inc.detail).toContain(`(${gc})`); // linked live descendant named
        expect((inc["possible_orphans"] as { pid: number }[]).map((p) => p.pid)).toContain(gc);
      }
      expect(inc.detail).toMatch(/Nothing was swept/);
      expect(st.events.some((e) => e.type === "recovery.interrupted" && /possible surviving sandboxed commands/.test(e.summary))).toBe(true);
      expect(r.incidents.map((i) => i.kind)).toContain("possible_surviving_sandboxed_commands");
      // No sweep: the survivor is still running after recovery and a new review.
      if (win) expect(pidAlive(gc)).toBe(true);
    } finally {
      if (pidAlive(gc)) hardKill(gc, true);
      if (pidAlive(started.pid)) hardKill(started.pid, true);
    }
  }, 180_000);
});

describe.skipIf(!supported)("server crash before the completion commit (M1.3-11, §15.5)", () => {
  it("F11: a server killed right before the completion commit leaves no half-published result", async () => {
    clearProbeCache();
    const f = await makeReviewFixture();
    const { review: ctx } = await newReviewRun(f, { maxReviews: 5 });
    await setScenario(f, okScenario(output({ findings: [defect()] })));
    const r1 = await (await startReview(ctx, {})).completion;
    expect(r1.accepted).toBe(true);
    await writeFile(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a + b;\n}\n");
    await setScenario(f, okScenario(output({ verdict: "APPROVE", findings: [defect({ title: "from the crashed review" })], prior_findings: [{ id: "PF-1", assessment: "apparently_resolved", superseded_by_index: null, note: "" }] })));
    const cfgFile = join(f.scratch, "child-ctx-f11.json");
    const { dataHome, runPaths, meta, gitExe, rules, trustProjectsPath, trustIsolationPath, selftestDir, codex, budgets } = ctx;
    await writeFile(cfgFile, JSON.stringify({ dataHome, runPaths, meta, gitExe, rules, trustProjectsPath, trustIsolationPath, selftestDir, codex: { ...codex }, budgets, launcher: ctx.testHooks!.codexLauncher, request: {}, crashBeforeCompletion: true }));
    const server = spawn(process.execPath, [join(outDir, "child-review.mjs"), cfgFile], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let out = "";
    server.stdout!.on("data", (b: Buffer) => (out += b.toString("utf8")));
    const exited = new Promise<number | null>((r) => server.on("exit", (c) => r(c)));
    expect(await waitFor(() => out.includes("operation_id"), 60_000)).toBe(true);
    const started = JSON.parse(out.split("\n")[0]!) as { operation_id: string; pid: number };
    await exited; // it died inside beforeCompletionCommit
    expect(out).not.toContain('"done"');

    // Before any recovery: nothing of the crashed review's result is in the authoritative state.
    const raw = await readState(ctx.runPaths);
    expect(raw.operations.find((o) => o.operation_id === started.operation_id)!.status).toBe("running");
    expect(raw.reviews.find((r) => r.operation_id === started.operation_id)!.status).toBe("running");
    expect(raw.findings.map((x) => [x.title, x.status])).toEqual([["add() subtracts", "open"]]);
    // A restarted session recovers it as interrupted, still without any of its claims.
    await setScenario(f, okScenario(output()));
    await (await startReview(ctx, { focus: "after the crash" })).completion;
    const st = await readState(ctx.runPaths);
    expect(st.operations.find((o) => o.operation_id === started.operation_id)!.status).toBe("interrupted");
    expect(st.reviews.find((r) => r.operation_id === started.operation_id)!.status).toBe("interrupted");
    expect(st.findings.map((x) => x.title)).not.toContain("from the crashed review");
    expect(st.findings.find((x) => x.title === "add() subtracts")!.assessments.some((a) => a.assessment === "apparently_resolved")).toBe(false);
  }, 180_000);
});
