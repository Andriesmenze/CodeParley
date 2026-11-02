// Phase 2.1: a process killed while it records responses (shared contract; Windows
// TerminateProcess, Linux SIGKILL). A child records batches of three responses in a loop and is
// killed at random moments, repeatedly — inside the run lock, during the atomic write, between
// commits. After every kill the run state must parse, every recorded batch must be complete
// (all three or none), every item's response chain intact, and the next writer must get the run
// lock back (a dead holder's lock is reclaimed) and record.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomBytes, randomInt } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { uuidv7 } from "../src/common/ids.js";
import { createRun, readState } from "../src/store/state-store.js";
import { canonicalPathKey, runPaths } from "../src/store/paths.js";
import { selfOwner } from "../src/store/owner.js";
import { newStateRecord, type StateRecord } from "../src/schemas/run-state.js";
import type { ReviewerItem } from "../src/schemas/review.js";
import { respondToReview } from "../src/engine/respond.js";
import { itemDiscussion, reportDiscussion } from "../src/policy/responses.js";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { repoRootDir } from "./helpers/mcp-harness.js";

const ITEMS = 60;
const H = (c: string) => c.repeat(64);

function item(id: string, k: number): ReviewerItem {
  return {
    id,
    item_kind: "finding",
    review_id: "review-1",
    round: 1,
    source_id: H("a"),
    review_input_id: H("b"),
    title: `finding ${k}`,
    claim_type: "defect",
    severity: "high",
    category: "correctness",
    impacts: ["correctness"],
    consequence: "c",
    confidence: "high",
    evidence: [],
    investigation: "",
    recommended_change: "",
    triage: "established_defect",
    basis: "reviewer_evidence",
    policy_notes: [],
    status: "open",
    related_prior_id: null,
    supersedes: [],
    superseded_by: null,
    assessments: [],
    created_at: new Date().toISOString(),
  };
}

// The child: three responses per batch (items chosen round-robin), forever, until killed.
const CHILD = `
import { respondToReview } from "./engine/respond.js";
import { readState } from "./store/state-store.js";
import { itemDiscussion, reportDiscussion } from "./policy/responses.js";
import { runPaths } from "./store/paths.js";
import { selfOwner } from "./store/owner.js";
const [home, key, runId, startAt] = process.argv.slice(2);
const paths = runPaths(home, key, runId);
const owner = selfOwner();
for (let i = Number(startAt); ; i++) {
  const st = await readState(paths);
  const picked = [0, 1, 2].map((k) => st.findings[(3 * i + k) % st.findings.length]);
  const responses = picked.map((it) => ({ finding_id: it.id, response_token: itemDiscussion(it, reportDiscussion(st, null).view, null).response_token, disposition: i % 2 ? "accepted" : "disputed", rationale: "batch " + i }));
  try {
    await respondToReview({ runId, runPaths: paths, owner, currentSource: async () => ({ source_id: "f".repeat(64), note: null }), lockDeps: { staleMs: 300 } }, { responses });
    process.stdout.write("ok " + i + "\\n");
  } catch (e) {
    process.stdout.write("err " + (e.code ?? e.message) + "\\n");
  }
}
`;

let dist = "";
let ownBuild = false;
beforeAll(async () => {
  const shared = sharedCompiledSrc();
  if (shared) dist = shared;
  else {
    dist = join(repoRootDir, ".tmp-test-dist", `crash-${randomBytes(4).toString("hex")}`);
    buildSrc(repoRootDir, dist);
    ownBuild = true;
  }
  await writeFile(join(dist, "respond-crash-child.mjs"), CHILD);
}, 120_000);
afterAll(async () => {
  if (ownBuild) await rm(dist, { recursive: true, force: true }).catch(() => undefined);
});

/** Every batch complete (3 records), every item's chain linked oldest to newest, events and revisions consistent. */
function assertConsistent(st: StateRecord, initialEvents: number): void {
  const bySet = new Map<string, number>();
  for (const r of st.implementer_responses) bySet.set(r.response_set_id, (bySet.get(r.response_set_id) ?? 0) + 1);
  for (const [set, n] of bySet) expect(n, `batch ${set}`).toBe(3);
  const byItem = new Map<string, string[]>();
  for (const r of st.implementer_responses) {
    const chain = byItem.get(r.item_id) ?? [];
    expect(r.supersedes, `chain of ${r.item_id}`).toBe(chain.at(-1) ?? null);
    chain.push(r.response_id);
    byItem.set(r.item_id, chain);
  }
  expect(st.events.length - initialEvents).toBe(bySet.size);
  expect(st.revision).toBe(bySet.size);
  expect(st.findings.every((f) => f.status === "open" && f.assessments.length === 0)).toBe(true);
}

describe("a process killed while recording responses (Phase 2.1)", () => {
  it("leaves complete batches or nothing, a readable state, and a run lock the next writer gets back", async () => {
    const home = await mkdtemp(join(tmpdir(), "arl-respond-crash-"));
    try {
      const runId = uuidv7();
      const repoKey = canonicalPathKey(home);
      const paths = runPaths(home, repoKey, runId);
      const st0 = newStateRecord(runId, "IDLE");
      st0.findings = Array.from({ length: ITEMS }, (_, k) => item(uuidv7(), k));
      await createRun(paths, { schema_version: 1, run_id: runId, created_at: new Date().toISOString(), repository_root: home, versions: {}, scope: { allowed_snapshot: [home], client_roots_snapshot: [] } }, st0);
      let lines = 0;
      for (let round = 0; round < 6; round++) {
        const child: ChildProcess = spawn(process.execPath, [join(dist, "respond-crash-child.mjs"), home, repoKey, runId, String(round * 1000)], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
        let out = "";
        child.stdout!.on("data", (d: Buffer) => (out += d.toString("utf8")));
        // Let it commit a few batches, then kill it at a random moment (most likely mid-commit).
        for (let i = 0; i < 200 && (out.match(/^ok /gm) ?? []).length < 2; i++) await new Promise((r) => setTimeout(r, 50));
        await new Promise((r) => setTimeout(r, 20 + randomInt(120)));
        const exited = new Promise((r) => child.once("exit", r));
        child.kill("SIGKILL");
        await exited;
        // Every round makes progress: a lock the previous child left behind (complete or torn)
        // is reclaimed, so the next writer is never locked out (before the fix, a torn owner
        // record kept the run locked forever).
        expect((out.match(/^ok /gm) ?? []).length, `round ${round} committed batches before it was killed`).toBeGreaterThanOrEqual(2);
        lines += (out.match(/^ok /gm) ?? []).length;
        expect(out, "the child only ever reports successes before it is killed").not.toMatch(/^err (?!STORE_LOCKED)/m);
        assertConsistent(await readState(paths), 0);
      }
      expect(lines).toBeGreaterThan(6);
      // The next writer (this process) gets the lock back and records.
      const st = await readState(paths);
      const it = st.findings[0]!;
      const out = await respondToReview(
        { runId, runPaths: paths, owner: selfOwner(), currentSource: async () => ({ source_id: H("f"), note: null }), lockDeps: { staleMs: 300 } },
        { responses: [{ finding_id: it.id, response_token: itemDiscussion(it, reportDiscussion(st, null).view, null).response_token!, disposition: "deferred", rationale: "after the crashes" }, ...[1, 2].map((k) => ({ finding_id: st.findings[k]!.id, response_token: itemDiscussion(st.findings[k]!, reportDiscussion(st, null).view, null).response_token!, disposition: "accepted" as const, rationale: "" }))] },
      );
      expect(out.recorded).toHaveLength(3);
      assertConsistent(await readState(paths), 0);
    } finally {
      await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  }, 240_000);
});
