// Phase 2.3: a process killed while it records user decisions and task amendments (shared
// contract; Windows TerminateProcess, Linux SIGKILL; plan P2.3-15). A child records decisions
// (each with a note, so its disclosure artifact is written before the commit) and amendments in a
// loop and is killed at random moments, repeatedly. After every kill the run state must parse;
// every recorded decision must be whole, its supersession chain intact; amendment numbers
// contiguous; no record may refer to a missing artifact (a crash before the commit leaves at most
// an unreferenced one); events and revisions match the records; and the next writer must get the
// run lock back and record.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomBytes, randomInt } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { uuidv7 } from "../src/common/ids.js";
import { createRun, readState } from "../src/store/state-store.js";
import { canonicalPathKey, runPaths } from "../src/store/paths.js";
import { selfOwner } from "../src/store/owner.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { newStateRecord, type StateRecord } from "../src/schemas/run-state.js";
import type { ReviewerItem } from "../src/schemas/review.js";
import { recordUserDecision, threadDecisionView } from "../src/engine/user-authority.js";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { repoRootDir } from "./helpers/mcp-harness.js";

const ITEMS = 40;
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

// The child: a decision with a note (round-robin over the items), then an amendment, forever, until killed.
const CHILD = `
import { recordAmendment, recordUserDecision, threadDecisionView } from "./engine/user-authority.js";
import { readState } from "./store/state-store.js";
import { runPaths } from "./store/paths.js";
import { selfOwner } from "./store/owner.js";
const [home, key, runId, startAt] = process.argv.slice(2);
const paths = runPaths(home, key, runId);
const ctx = {
  runId, runPaths: paths, owner: selfOwner(), lockDeps: { staleMs: 300 },
  currentSource: async () => ({ source_id: "f".repeat(64), note: null, withheld: { paths: ["secret.env"], hashes: [], repoContext: [] } }),
};
for (let i = Number(startAt); ; i++) {
  try {
    const st = await readState(paths);
    if (i % 2 === 0 || st.task_amendments.length >= 40) {
      const it = st.findings[Math.floor(i / 2) % st.findings.length];
      const v = threadDecisionView(st, it.id);
      await recordUserDecision(ctx, { item_id: it.id, kind: i % 4 === 0 ? "waive" : "defer", note: "decision " + i, token: v.token });
    } else {
      await recordAmendment(ctx, { kind: "clarification", text: "amendment " + i, relates_to: [], replaces: null });
    }
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
    dist = join(repoRootDir, ".tmp-test-dist", `crash-user-${randomBytes(4).toString("hex")}`);
    buildSrc(repoRootDir, dist);
    ownBuild = true;
  }
  await writeFile(join(dist, "user-crash-child.mjs"), CHILD);
}, 120_000);
afterAll(async () => {
  if (ownBuild) await rm(dist, { recursive: true, force: true }).catch(() => undefined);
});

/** Every record whole and chained; amendment numbers contiguous; every referenced artifact present; events and revisions consistent. */
function assertConsistent(st: StateRecord, runDir: string): void {
  const lastOnItem = new Map<string, string>();
  for (const d of st.user_decisions) {
    expect(d.covered_items).toHaveLength(1);
    const prev = lastOnItem.get(d.covered_items[0]!);
    expect(d.supersedes, `chain of ${d.covered_items[0]}`).toEqual(prev ? [prev] : []);
    lastOnItem.set(d.covered_items[0]!, d.decision_id);
    expect(d.recorded_by).toMatchObject({ role: "user", channel: "local_cli", assurance: "local_operator" });
  }
  expect(st.task_amendments.map((a) => a.seq)).toEqual(st.task_amendments.map((_, k) => k + 1));
  for (const r of [...st.user_decisions, ...st.task_amendments]) {
    expect(r.disclosure_ref, "every record here has text, so a disclosure record").not.toBeNull();
    expect(existsSync(resolveArtifact(runDir, r.disclosure_ref!)), `artifact of ${r.disclosure_ref}`).toBe(true);
  }
  const n = st.user_decisions.length + st.task_amendments.length;
  expect(st.events.length).toBe(n);
  expect(st.revision).toBe(n);
  expect(st.findings.every((f) => f.status === "open" && f.assessments.length === 0)).toBe(true);
}

describe("a process killed while recording user decisions and amendments (Phase 2.3)", () => {
  it("leaves whole records or nothing, never a record without its artifact, a readable state, and a run lock the next writer gets back", async () => {
    const home = await mkdtemp(join(tmpdir(), "arl-user-crash-"));
    try {
      const runId = uuidv7();
      const repoKey = canonicalPathKey(home);
      const paths = runPaths(home, repoKey, runId);
      const st0 = newStateRecord(runId, "IDLE");
      st0.findings = Array.from({ length: ITEMS }, (_, k) => item(uuidv7(), k));
      await createRun(paths, { schema_version: 1, run_id: runId, created_at: new Date().toISOString(), repository_root: home, versions: {}, scope: { allowed_snapshot: [home], client_roots_snapshot: [] } }, st0);
      let lines = 0;
      for (let round = 0; round < 6; round++) {
        const child: ChildProcess = spawn(process.execPath, [join(dist, "user-crash-child.mjs"), home, repoKey, runId, String(round * 1000)], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
        let out = "";
        child.stdout!.on("data", (d: Buffer) => (out += d.toString("utf8")));
        for (let i = 0; i < 200 && (out.match(/^ok /gm) ?? []).length < 2; i++) await new Promise((r) => setTimeout(r, 50));
        await new Promise((r) => setTimeout(r, 20 + randomInt(120)));
        const exited = new Promise((r) => child.once("exit", r));
        child.kill("SIGKILL");
        await exited;
        expect((out.match(/^ok /gm) ?? []).length, `round ${round} committed records before it was killed`).toBeGreaterThanOrEqual(2);
        lines += (out.match(/^ok /gm) ?? []).length;
        expect(out, "the child only ever reports successes before it is killed").not.toMatch(/^err (?!STORE_LOCKED)/m);
        assertConsistent(await readState(paths), paths.runDir);
      }
      expect(lines).toBeGreaterThan(6);
      // The next writer (this process) gets the lock back and records.
      const st = await readState(paths);
      const it = st.findings[0]!;
      const out = await recordUserDecision(
        { runId, runPaths: paths, owner: selfOwner(), currentSource: async () => ({ source_id: H("f"), note: null, withheld: { paths: ["secret.env"], hashes: [] } }), lockDeps: { staleMs: 300 } },
        { item_id: it.id, kind: "require_resolution", note: "after the crashes", token: threadDecisionView(st, it.id).token },
      );
      expect(out.decision.kind).toBe("require_resolution");
      assertConsistent(await readState(paths), paths.runDir);
    } finally {
      await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  }, 240_000);
});
