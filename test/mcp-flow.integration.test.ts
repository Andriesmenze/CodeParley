// End-to-end M1 flow over real stdio in both protocol eras (plan §11, §18.1; M1.5):
// create_review_run → run_checks → review_with_codex → get_review_status → get_review_history
// → stop_review_loop(close), with the scripted fake Codex. Every result must be a complete
// structuredContent object with an identical text copy, and no result may carry withheld
// names or hashes, raw check output, the data home or the user profile.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { approve } from "./helpers/checks-fixture.js";
import { defect, makeReviewFixture, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";
import { compileServer, removeCompiledServer, connect, errorCode, FLAVORS, sc, writeServerConfig, type Conn, type Flavor } from "./helpers/mcp-harness.js";
import { supported } from "./helpers/git-fixture.js";

const node = process.execPath;

async function setup(flavor: Flavor, extraFiles: Record<string, string> = {}): Promise<{ f: ReviewFixture; c: Conn; cfg: string }> {
  const f = await makeReviewFixture(extraFiles);
  await approve(f, {
    checks: {
      unit: { argv: [node, "scripts/pass.js", "PRINTS_A_SECRET_TOKEN_abc123"] },
      flag: { argv: [node, "scripts/flag.js"] },
    },
    profiles: { default: ["unit"] },
    required_profiles: ["default"],
  });
  await setScenario(f, okScenario(output({ findings: [defect()] })));
  const cfg = await writeServerConfig(f.scratch, { argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git, "--diagnostics"], fake: { script: f.fakeScript } });
  const c = await connect(flavor, cfg);
  return { f, c, cfg };
}

/** Everything a host result must never contain. */
function assertNoLeak(f: ReviewFixture, value: unknown): void {
  const text = JSON.stringify(value);
  const envBytes = readFileSync(join(f.repo, ".env"));
  const envSha = createHash("sha256").update(envBytes).digest("hex");
  expect(text).not.toContain("SECRET_ENV_VALUE");
  expect(text).not.toContain("hunter");
  expect(text).not.toContain("PRINTS_A_SECRET_TOKEN"); // check stdout never returned
  expect(text).not.toContain(envSha);
  expect(text.toLowerCase()).not.toContain(f.dataHome.toLowerCase().replace(/\\/g, "\\\\"));
  expect(text.toLowerCase()).not.toContain(f.dataHome.toLowerCase());
  expect(text).not.toMatch(/"\.env"|[\\/]\.env\b|\b\.env"/);
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

describe.skipIf(!supported)("M1 flow over stdio (both protocol eras)", () => {
  for (const flavor of FLAVORS) {
    it(`${flavor}: create → checks → review → status → history → close`, async () => {
      const { f, c } = await setup(flavor);
      try {
        const diag = sc(await c.call("diag_echo", { text: "hi" }));
        expect((diag["protocol"] as { version: string }).version).toBe(flavor === "v2-modern" ? "2026-07-28" : "2025-11-25");
        expect(diag["echo"]).toBe("hi");

        const created = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()", background: "The add function was edited." }, repository_root: f.repo, wait_seconds: 30 }));
        assertNoLeak(f, created);
        expect(created["run_id"]).toMatch(/^[0-9a-f-]{36}$/);
        expect(created["summary"]).toEqual(expect.any(String));
        const runId = created["run_id"] as string;
        expect((created["prepare"] as { status: string }).status).toBe("completed");
        expect((created["verification_floor"] as { required: string[] }).required).toEqual(["unit"]);
        expect(created["state"]).toBe("IDLE");

        const checks = sc(await c.call("run_checks", { run_id: runId, wait_seconds: 40 }));
        assertNoLeak(f, checks);
        expect(checks["status"]).toBe("passed");
        const results = checks["results"] as Record<string, unknown>[];
        expect(results[0]!["check"]).toBe("unit");
        expect(results[0]).not.toHaveProperty("stdout_tail");
        expect(results[0]).not.toHaveProperty("stderr_tail");
        expect((results[0]!["stdout_bytes"] as number) > 0).toBe(true);
        expect((checks["floor"] as { satisfied_for_current_source: boolean }).satisfied_for_current_source).toBe(true);

        const review = sc(await c.call("review_with_codex", { run_id: runId, focus: "check add()", wait_seconds: 40 }));
        assertNoLeak(f, review);
        expect(review["status"]).toBe("completed");
        expect(review["accepted"]).toBe(true);
        expect(review["verdict"]).toBe("CHANGES_REQUIRED");
        const findings = review["findings"] as { triage: string; title: string }[];
        expect(findings[0]!.triage).toBe("established_defect");
        expect((review["effective_isolation"] as { mode: string }).mode).toBe("S1");
        expect((review["coverage"] as { excluded_changed: { confidential_count: number } }).excluded_changed.confidential_count).toBe(1);

        const status = sc(await c.call("get_review_status", { run_id: runId }));
        assertNoLeak(f, status);
        expect(status["state"]).toBe("IDLE");
        expect(status["active_operation"]).toBeNull();
        expect((status["open_findings"] as unknown[]).length).toBe(1);
        expect((status["latest_review"] as { accepted: boolean }).accepted).toBe(true);
        // No PASS: completion is derived (Phase 2.3), and an open finding keeps it from ready.
        expect(status["summary"]).toContain("completion: needs_implementer");
        expect(status["summary"]).not.toMatch(/\bPASS\b/);
        expect(status["completion"]).toMatchObject({ state: "needs_implementer", ready: false });

        const listed = sc(await c.call("get_review_status", {}));
        expect((listed["runs"] as { run_id: string }[]).some((x) => x.run_id === runId)).toBe(true);

        const hist = sc(await c.call("get_review_history", { run_id: runId }));
        assertNoLeak(f, hist);
        const types = (hist["events"] as { type: string }[]).map((e) => e.type);
        expect(types).toContain("run.created");
        expect(types).toContain("review.finished");
        const art = sc(await c.call("get_review_history", { run_id: runId, artifact: { operation_id: review["operation_id"] as string, part: "result", length: 500 } }));
        expect((art["artifact"] as { length: number; total_length: number }).length).toBe(500);
        expect((art["artifact"] as { total_length: number }).total_length).toBeGreaterThan(500);
        const forbidden = await c.call("get_review_history", { run_id: runId, artifact: { operation_id: review["operation_id"] as string, part: "prompt" } });
        expect(errorCode(forbidden)).toBe("INVALID_ARGUMENT");

        const closed = sc(await c.call("stop_review_loop", { run_id: runId, mode: "close" }));
        assertNoLeak(f, closed);
        expect(closed["state"]).toBe("CLOSED");
        expect(closed["cancellation"]).toBeNull();
        expect(closed["note"]).toBe("Repository files were not modified by this tool.");
        expect((closed["open_findings"] as unknown[]).length).toBe(1);
        // A closed run is read-only.
        expect(errorCode(await c.call("run_checks", { run_id: runId }))).toBe("RUN_TERMINAL");
      } finally {
        await c.close();
      }
    }, 180_000);
  }
});
