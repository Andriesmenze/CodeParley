// Phase 2.1 over real stdio in both protocol eras (three client runtimes): respond_to_review in
// the host flow (status tokens → responses → status, history → server restart → history again →
// close), confidentiality of response text (withheld names, hashes and local paths never come
// back), cross-process races on one item (two servers), and the strict input (no authority
// claim, no engine-owned data).

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { acquireWorktreeLock } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { selfOwner } from "../src/store/owner.js";
import { canonicalizePath } from "../src/workspace/paths.js";
import { join } from "node:path";
import { approve } from "./helpers/checks-fixture.js";
import { defect, makeReviewFixture, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";
import { compileServer, removeCompiledServer, connect, errorCode, FLAVORS, sc, writeServerConfig, type Conn, type Flavor } from "./helpers/mcp-harness.js";
import { supported } from "./helpers/git-fixture.js";

const node = process.execPath;

interface OpenItem {
  id: string;
  title: string;
  response_token: string | null;
  discussion_state: string;
  implementer_response: { disposition: string; rationale_excerpt: string; stale_reasons: string[] } | null;
}

async function setup(flavor: Flavor): Promise<{ f: ReviewFixture; c: Conn; cfg: string }> {
  const f = await makeReviewFixture({ "config/db.env": "DB_PASSWORD=swordfish\n" });
  await approve(f, { checks: { unit: { argv: [node, "scripts/pass.js"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
  await setScenario(
    f,
    okScenario(output({ findings: [defect(), defect({ title: "overflow risk", severity: "high", claim_type: "risk", evidence: [] })], questions: [{ question: "Should add() accept strings?", related_finding_index: 0, blocking: true }] })),
  );
  const cfg = await writeServerConfig(f.scratch, { argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } });
  return { f, c: await connect(flavor, cfg), cfg };
}

/** A run with an accepted review; its open items as get_review_status shows them. */
async function reviewedRun(c: Conn, f: ReviewFixture): Promise<{ runId: string; open: OpenItem[] }> {
  const created = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }));
  const runId = created["run_id"] as string;
  const review = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
  expect(review["accepted"]).toBe(true);
  const status = sc(await c.call("get_review_status", { run_id: runId }));
  return { runId, open: status["open_findings"] as OpenItem[] };
}

/** Everything a host result must never contain (MR-F): withheld names and hashes, the data home. */
function assertNoLeak(f: ReviewFixture, value: unknown): void {
  const text = JSON.stringify(value);
  for (const p of [".env", "config/db.env"]) {
    const sha = createHash("sha256").update(readFileSync(join(f.repo, ...p.split("/")))).digest("hex");
    expect(text, `hash of ${p}`).not.toContain(sha);
  }
  expect(text).not.toMatch(/\x22\.env\x22|[\\/]\.env\b|\b\.env\x22|db\.env/);
  expect(text.toLowerCase()).not.toContain(f.dataHome.toLowerCase());
  expect(text.toLowerCase()).not.toContain(f.dataHome.toLowerCase().replace(/\\/g, "\\\\"));
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

describe.skipIf(!supported)("respond_to_review over stdio (Phase 2.1)", () => {
  for (const flavor of FLAVORS) {
    it(`${flavor}: tokens in status → responses → status and history → server restart → history again → close`, async () => {
      const { f, c: c0, cfg } = await setup(flavor);
      let c = c0;
      try {
        const { runId, open } = await reviewedRun(c, f);
        expect(open.map((x) => x.title).sort()).toEqual(["Should add() accept strings?", "add() subtracts", "overflow risk"]);
        for (const x of open) expect(x).toMatchObject({ response_token: expect.stringMatching(/^[0-9a-f]{32}$/), discussion_state: "open", implementer_response: null });
        const by = (t: string) => open.find((x) => x.title === t)!;

        const request = {
          run_id: runId,
          request_id: "first-responses",
          responses: [
            { finding_id: by("add() subtracts").id, response_token: by("add() subtracts").response_token, disposition: "accepted" },
            { finding_id: by("overflow risk").id, response_token: by("overflow risk").response_token, disposition: "disputed", rationale: "Inputs are bounded by the caller.", references: [{ path: "src/math.js", start_line: 2 }] },
            { finding_id: by("Should add() accept strings?").id, response_token: by("Should add() accept strings?").response_token, disposition: "deferred", rationale: "Decided in the next change." },
          ],
        };
        const out = sc(await c.call("respond_to_review", request));
        expect(out["deduplicated"]).toBe(false);
        expect((out["recorded"] as { discussion_state: string }[]).map((r) => r.discussion_state)).toEqual(["accepted_unresolved", "disputed", "deferral_requested"]);
        expect(out["summary"]).toMatch(/claim, not a resolution/);
        expect((out["source"] as { source_id: string | null }).source_id).toMatch(/^[0-9a-f]{64}$/);
        // The same request again (a lost response): the recorded result, nothing new.
        const again = sc(await c.call("respond_to_review", request));
        expect(again).toMatchObject({ deduplicated: true, response_set_id: out["response_set_id"] });
        // The same request_id with other arguments: a conflict, nothing recorded.
        expect(errorCode(await c.call("respond_to_review", { ...request, responses: [request.responses[0]] }))).toBe("REQUEST_ID_CONFLICT");

        const status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(status["summary"]).toMatch(/1 accepted \(unresolved\), 1 disputed, 1 deferral requested \(not a user decision\)/);
        expect(status["discussion"]).toMatchObject({ accepted_unresolved: 1, disputed: 1, deferral_requested: 1, open: 0, responses_recorded: 3 });
        // Responses never touch the reviewer's lifecycle: all three items are still open.
        expect((status["open_findings"] as OpenItem[]).map((x) => x.title).sort()).toEqual(open.map((x) => x.title).sort());
        const items = status["open_findings"] as OpenItem[];
        expect(items.find((x) => x.title === "overflow risk")!.implementer_response).toMatchObject({ disposition: "disputed", rationale_excerpt: "Inputs are bounded by the caller.", stale_reasons: [] });
        expect((status["limitations"] as { code: string }[]).map((l) => l.code)).toContain("responses_are_claims");

        // A stale token (the item changed: it has a response now) is refused over MCP too.
        const stale = await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: by("overflow risk").id, response_token: by("overflow risk").response_token, disposition: "accepted" }] });
        expect(errorCode(stale)).toBe("STALE_FINDING_STATE");

        // Restart: a new server process over the same data home.
        await c.close();
        c = await connect(flavor, cfg);
        const after = sc(await c.call("get_review_status", { run_id: runId }));
        expect(after["discussion"]).toMatchObject({ disputed: 1, deferral_requested: 1, accepted_unresolved: 1 });
        const hist = sc(await c.call("get_review_history", { run_id: runId, responses: {} }));
        const doc = JSON.parse((hist["responses"] as { content: string }).content) as { items: { title: string; responses: { disposition: string; rationale: string; recorded_by: { role: string } }[] }[] };
        expect(doc.items.map((x) => [x.title, x.responses.map((r) => r.disposition)])).toEqual(
          expect.arrayContaining([
            ["add() subtracts", ["accepted"]],
            ["overflow risk", ["disputed"]],
            ["Should add() accept strings?", ["deferred"]],
          ]),
        );
        expect(doc.items.flatMap((x) => x.responses).every((r) => r.recorded_by.role === "implementer")).toBe(true);
        const one = sc(await c.call("get_review_history", { run_id: runId, responses: { finding_id: by("overflow risk").id, length: 200 } }));
        expect((one["responses"] as { length: number; total_length: number }).length).toBe(200);
        const events = sc(await c.call("get_review_history", { run_id: runId }));
        expect((events["events"] as { type: string; actor: string }[]).filter((e) => e.type === "review.responses_recorded")).toEqual([expect.objectContaining({ actor: "host" })]);

        const closed = sc(await c.call("stop_review_loop", { run_id: runId, mode: "close" }));
        expect(closed["discussion"]).toMatchObject({ disputed: 1 });
        const now = (sc(await c.call("get_review_status", { run_id: runId }))["open_findings"] as OpenItem[]).find((x) => x.title === "add() subtracts")!;
        expect(errorCode(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: now.id, response_token: now.response_token, disposition: "disputed", rationale: "too late" }] }))).toBe("RUN_TERMINAL");
      } finally {
        await c.close();
      }
    }, 240_000);
  }

  it("response text never brings withheld names, hashes or local paths back to the host; it is stored as written", async () => {
    const { f, c } = await setup("v2-modern");
    try {
      const { runId, open } = await reviewedRun(c, f);
      const envSha = createHash("sha256").update(readFileSync(join(f.repo, ".env"))).digest("hex");
      const hostile = `See .env and CONFIG\\DB.ENV (hash ${envSha}); notes in ${join(f.dataHome, "runs", "x")} and config/db.env`;
      const x = open.find((i) => i.title === "add() subtracts")!;
      const out = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: x.id, response_token: x.response_token, disposition: "disputed", rationale: hostile, references: [{ path: "config/db.env", start_line: 1 }] }] }));
      assertNoLeak(f, out);
      const status = sc(await c.call("get_review_status", { run_id: runId }));
      assertNoLeak(f, status);
      const excerpt = (status["open_findings"] as OpenItem[]).find((i) => i.id === x.id)!.implementer_response!.rationale_excerpt;
      expect(excerpt).toContain("[withheld path]");
      expect(excerpt).toContain("[withheld hash]");
      expect(excerpt).toContain("[data home]");
      const hist = sc(await c.call("get_review_history", { run_id: runId, responses: { finding_id: x.id } }));
      assertNoLeak(f, hist);
      expect((hist["responses"] as { content: string }).content).toContain("[withheld path]");
      // Stored as written (local record); redaction happens on every way out.
      const stateFile = readFileSync(join(f.dataHome, "runs", readdirSync(join(f.dataHome, "runs")).find((k) => k !== ".trash")!, runId, "state.json"), "utf8");
      expect(stateFile).toContain("config/db.env");
    } finally {
      await c.close();
    }
  }, 180_000);

  it("a confidential file created after the last capture: what the response's source read knew stays withheld in every later view — history, runs show, status that cannot read the tree, after a restart — and a missing disclosure record fails closed (dogfood finding)", async () => {
    const { f, c: c0, cfg } = await setup("v2-legacy");
    let c = c0;
    try {
      const { runId, open } = await reviewedRun(c, f);
      // Created after the review: no capture record of the run knows this file.
      await writeFile(join(f.repo, "config", "new.env"), "NEW_SECRET=after-the-review\n");
      const content = readFileSync(join(f.repo, "config", "new.env"));
      const sha = createHash("sha256").update(content).digest("hex");
      // Its git object id identifies it as well (Codex review of PR #10); the fixture uses SHA-1.
      const oid = createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${content.length}\0`), content])).digest("hex");
      const leaks = (v: unknown) => {
        const s = JSON.stringify(v);
        return s.includes("new.env") || s.includes(sha) || s.includes(oid);
      };
      const x = open[0]!;
      const out = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: x.id, response_token: x.response_token, disposition: "disputed", rationale: `see config/new.env (sha256 ${sha}, blob ${oid})`, references: [{ path: "config/new.env", start_line: 1 }] }] }));
      expect(leaks(out)).toBe(false);
      // History has no source read of its own.
      const hist = sc(await c.call("get_review_history", { run_id: runId, responses: {} }));
      expect(leaks(hist)).toBe(false);
      expect((hist["responses"] as { content: string }).content).toContain("[withheld path]");
      expect((hist["responses"] as { content: string }).content).toContain("[withheld hash]");
      // The CLI's default view (its output can reach a model too).
      const dir = await compileServer();
      const cli = spawnSync(process.execPath, [join(dir, "cli", "main.js"), "runs", "show", runId, "--home", f.dataHome, "--json"], { encoding: "utf8", windowsHide: true });
      expect(cli.status, cli.stderr).toBe(0);
      expect(cli.stdout).toContain("[withheld path]");
      expect(leaks(cli.stdout)).toBe(false);
      // Status while the worktree is busy: its own source read fails, so only the run's records can withhold.
      const lock = await acquireWorktreeLock(worktreeLockPath(f.dataHome, canonicalPathKey(await canonicalizePath(f.repo))), { owner: selfOwner(), operationId: "test-holds-the-worktree", kind: "capture" });
      try {
        const status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(status["current_source_recomputed"]).toBe(false);
        expect(leaks(status)).toBe(false);
      } finally {
        await lock.release();
      }
      // After a restart.
      await c.close();
      c = await connect("v2-modern", cfg);
      expect(leaks(sc(await c.call("get_review_history", { run_id: runId, responses: {} })))).toBe(false);
      // A disclosure record the state refers to that is missing: nothing is shown unfiltered.
      const key = readdirSync(join(f.dataHome, "runs")).find((k) => !k.startsWith("."))!;
      const runDir = join(f.dataHome, "runs", key, runId);
      const ref = (JSON.parse(readFileSync(join(runDir, "state.json"), "utf8")) as { implementer_responses: { disclosure_ref: string | null }[] }).implementer_responses[0]!.disclosure_ref;
      expect(ref).toMatch(/disclosure\.json$/);
      await rm(join(runDir, ...ref!.split("/")));
      await c.close();
      c = await connect("v2-modern", cfg);
      const failed = await c.call("get_review_history", { run_id: runId, responses: {} });
      expect(errorCode(failed)).toBe("INTERNAL");
      expect(leaks(failed)).toBe(false);
    } finally {
      await c.close();
    }
  }, 240_000);

  it("a file the repository excludes from review after the last capture stays withheld with its hashes in every view; a reviewed change under the same exclusion keeps its name (PR #10 review)", async () => {
    const { f, c: c0, cfg } = await setup("v2-modern");
    let c = c0;
    try {
      const { runId, open } = await reviewedRun(c, f);
      // After the review the repository keeps notes/** (a new file there) and src/** (where the
      // reviewed change is) out of reviews. No capture record of the run knows the new file.
      await mkdir(join(f.repo, ".code-parley"), { recursive: true });
      await writeFile(join(f.repo, ".code-parley", "config.json"), JSON.stringify({ review: { exclude_paths: ["notes/**", "src/**"] } }));
      await mkdir(join(f.repo, "notes"), { recursive: true });
      await writeFile(join(f.repo, "notes", "plan.md"), "Rotate the signing keys on Friday.\n");
      const content = readFileSync(join(f.repo, "notes", "plan.md"));
      const sha = createHash("sha256").update(content).digest("hex");
      const oid = createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${content.length}\0`), content])).digest("hex");
      const leaks = (v: unknown) => {
        const s = typeof v === "string" ? v : JSON.stringify(v);
        return s.includes("plan.md") || s.includes(sha) || s.includes(oid);
      };
      const x = open[0]!;
      const out = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: x.id, response_token: x.response_token, disposition: "disputed", rationale: `see notes/plan.md (sha256 ${sha}, blob ${oid})`, references: [{ path: "notes/plan.md", start_line: 1 }] }] }));
      expect(out["recorded"]).toHaveLength(1);
      expect(leaks(out)).toBe(false);
      const hist = sc(await c.call("get_review_history", { run_id: runId, responses: {} }));
      expect(leaks(hist)).toBe(false);
      expect((hist["responses"] as { content: string }).content).toContain("[withheld path]");
      expect((hist["responses"] as { content: string }).content).toContain("[withheld hash]");
      const dir = await compileServer();
      const cli = spawnSync(process.execPath, [join(dir, "cli", "main.js"), "runs", "show", runId, "--home", f.dataHome, "--json"], { encoding: "utf8", windowsHide: true });
      expect(cli.status, cli.stderr).toBe(0);
      expect(leaks(cli.stdout)).toBe(false);
      // Status without a read of its own: only the run's records can withhold the file.
      const lock = await acquireWorktreeLock(worktreeLockPath(f.dataHome, canonicalPathKey(await canonicalizePath(f.repo))), { owner: selfOwner(), operationId: "test-holds-the-worktree", kind: "capture" });
      try {
        const status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(status["current_source_recomputed"]).toBe(false);
        expect(leaks(status)).toBe(false);
        // Not withheld beyond the export: the reviewed change keeps its name.
        expect(JSON.stringify(status)).toContain("src/math.js");
      } finally {
        await lock.release();
      }
      // After a restart, and with a read of its own.
      await c.close();
      c = await connect("v2-modern", cfg);
      expect(leaks(sc(await c.call("get_review_history", { run_id: runId, responses: {} })))).toBe(false);
      const status2 = sc(await c.call("get_review_status", { run_id: runId }));
      expect(status2["current_source_recomputed"]).toBe(true);
      expect(leaks(status2)).toBe(false);
      expect(JSON.stringify(status2)).toContain("src/math.js");
    } finally {
      await c.close();
    }
  }, 240_000);

  it("a response recorded while the working tree cannot be read keeps its disposition and no view shows its text: a confidential file created after the review stays withheld (PR #10 review)", async () => {
    const { f, c } = await setup("v2-legacy");
    try {
      const { runId, open } = await reviewedRun(c, f);
      // Created after the review: no capture record knows it, and the response's own read cannot run.
      await writeFile(join(f.repo, "config", "late.env"), "LATE_SECRET=only-after-the-review\n");
      const content = readFileSync(join(f.repo, "config", "late.env"));
      const sha = createHash("sha256").update(content).digest("hex");
      const oid = createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${content.length}\0`), content])).digest("hex");
      const leaks = (v: unknown) => {
        const s = typeof v === "string" ? v : JSON.stringify(v);
        return s.includes("late.env") || s.includes(sha) || s.includes(oid);
      };
      const x = open[0]!;
      const lock = await acquireWorktreeLock(worktreeLockPath(f.dataHome, canonicalPathKey(await canonicalizePath(f.repo))), { owner: selfOwner(), operationId: "test-holds-the-worktree", kind: "capture" });
      try {
        const out = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: x.id, response_token: x.response_token, disposition: "disputed", rationale: `see config/late.env (sha256 ${sha}, blob ${oid})`, references: [{ path: "config/late.env", start_line: 1 }] }] }));
        expect(out["recorded"]).toHaveLength(1);
        expect(String(out["summary"])).toMatch(/could not be checked for confidential names/);
        expect(leaks(out)).toBe(false);
        const hist = sc(await c.call("get_review_history", { run_id: runId, responses: {} }));
        expect(leaks(hist)).toBe(false);
        expect((hist["responses"] as { content: string }).content).toContain("[withheld: recorded while the working tree could not be read");
        const status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(leaks(status)).toBe(false);
        expect((status["open_findings"] as OpenItem[]).find((i) => i.id === x.id)!.implementer_response).toMatchObject({ disposition: "disputed" });
      } finally {
        await lock.release();
      }
      // Readable again: the text was never checked, so it stays withheld; the CLI too.
      expect(leaks(sc(await c.call("get_review_history", { run_id: runId, responses: {} })))).toBe(false);
      expect(leaks(sc(await c.call("get_review_status", { run_id: runId })))).toBe(false);
      const dir = await compileServer();
      const cli = spawnSync(process.execPath, [join(dir, "cli", "main.js"), "runs", "show", runId, "--home", f.dataHome, "--json"], { encoding: "utf8", windowsHide: true });
      expect(cli.status, cli.stderr).toBe(0);
      expect(leaks(cli.stdout)).toBe(false);
    } finally {
      await c.close();
    }
  }, 240_000);

  it("two servers race to respond to one item with the same token: exactly one response is recorded", async () => {
    const { f, c, cfg } = await setup("v2-legacy");
    const c2 = await connect("v2-modern", cfg);
    try {
      const { runId, open } = await reviewedRun(c, f);
      const x = open.find((i) => i.title === "overflow risk")!;
      const call = (conn: Conn, disposition: string) => conn.call("respond_to_review", { run_id: runId, responses: [{ finding_id: x.id, response_token: x.response_token, disposition, rationale: `from ${conn.flavor}` }] });
      const [a, b] = await Promise.all([call(c, "disputed"), call(c2, "accepted")]);
      const codes = [errorCode(a), errorCode(b)].sort();
      expect(codes).toEqual([null, "STALE_FINDING_STATE"].sort());
      const hist = sc(await c.call("get_review_history", { run_id: runId, responses: { finding_id: x.id } }));
      const doc = JSON.parse((hist["responses"] as { content: string }).content) as { items: { finding_id: string; responses: unknown[] }[] };
      expect(doc.items.find((i) => i.finding_id === x.id)!.responses).toHaveLength(1);
    } finally {
      await c2.close();
      await c.close();
    }
  }, 180_000);

  it("while a review of the run is running, respond_to_review is refused with RUN_BUSY; afterwards the old token is stale and the new one is accepted", async () => {
    const { f, c } = await setup("v2-modern");
    try {
      const { runId, open } = await reviewedRun(c, f);
      const x = open.find((i) => i.title === "add() subtracts")!;
      const respondTo = (token: string | null) => c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: x.id, response_token: token, disposition: "disputed", rationale: "intended" }] });
      await setScenario(f, okScenario(output({ prior_findings: [] }), { sleep_ms: 6000 }));
      const handle = sc(await c.call("review_with_codex", { run_id: runId, force_new: true, wait_seconds: 0 }));
      expect(handle["status"]).toBe("running");
      const busy = await respondTo(x.response_token);
      expect(errorCode(busy)).toBe("RUN_BUSY");
      expect((sc(busy)["error"] as { retryable: boolean; details: { operation_id: string } }).details.operation_id).toBe(handle["operation_id"]);
      const done = sc(await c.call("get_review_status", { run_id: runId, wait_seconds: 45 }));
      expect((done["completed_operation"] as { accepted: boolean }).accepted).toBe(true);
      expect((done["discussion"] as { responses_recorded: number }).responses_recorded).toBe(0);
      expect(errorCode(await respondTo(x.response_token))).toBe("STALE_FINDING_STATE");
      const fresh = (done["open_findings"] as OpenItem[]).find((i) => i.id === x.id)!;
      expect(errorCode(await respondTo(fresh.response_token))).toBeNull();
    } finally {
      await c.close();
    }
  }, 180_000);

  it("the input cannot claim user authority or carry engine-owned data (strict schema, INVALID_ARGUMENT)", async () => {
    const { f, c } = await setup("v1");
    try {
      const { runId, open } = await reviewedRun(c, f);
      const x = open[0]!;
      const one = { finding_id: x.id, response_token: x.response_token, disposition: "accepted" };
      for (const extra of [{ actor: "user" }, { authority: "user" }, { recorded_by: { role: "user", channel: "cli" } }, { status: "reported_resolved" }, { source_id: "a".repeat(64) }, { title: "rewritten" }, { evidence: [] }]) {
        expect(errorCode(await c.call("respond_to_review", { run_id: runId, responses: [{ ...one, ...extra }] })), JSON.stringify(extra)).toBe("INVALID_ARGUMENT");
      }
      expect(errorCode(await c.call("respond_to_review", { run_id: runId, responses: [one], user_decision: true }))).toBe("INVALID_ARGUMENT");
      expect(errorCode(await c.call("respond_to_review", { run_id: runId, responses: [{ ...one, disposition: "resolved" }] }))).toBe("INVALID_ARGUMENT");
      expect(errorCode(await c.call("get_review_history", { run_id: runId, responses: {}, artifact: { operation_id: runId, part: "result" } }))).toBe("INVALID_ARGUMENT");
      // Nothing was recorded by any refused call.
      expect((sc(await c.call("get_review_status", { run_id: runId }))["discussion"] as { responses_recorded: number }).responses_recorded).toBe(0);
    } finally {
      await c.close();
    }
  }, 180_000);
});
