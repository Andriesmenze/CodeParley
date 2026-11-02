// Phase 2.2 over real stdio in the three client runtimes (plan §1.15): the host flow one explicit
// step at a time — review → responses → status threads (informational items included, with
// tokens) → a later review that presents the responses → Codex's structured reply → status and
// history → server restart → a repeated argument held back and escalated → close. Also: reviewer
// replies pass the host view like all text, the inputs stay strict (no stance, thread or user
// field anywhere), and a status with many threads stays inside the host's result bound.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { approve } from "./helpers/checks-fixture.js";
import { defect, makeReviewFixture, MATH_V1, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";
import { compileServer, removeCompiledServer, connect, errorCode, FLAVORS, sc, writeServerConfig, type Conn, type Flavor } from "./helpers/mcp-harness.js";
import { supported } from "./helpers/git-fixture.js";
import { MAX_RESULT_CHARS } from "../src/server/result.js";

const node = process.execPath;

const ADD = "add() subtracts";
const OVERFLOW = "overflow risk";
const NIT = "naming nit";
const QUESTION = "Should add() accept strings?";
const NONBLOCKING = "Is the README updated?";

interface Thread {
  thread_id: string;
  items: { id: string; status: string; title_excerpt: string; response_token: string | null }[];
  awaiting: string;
  last_speaker: string | null;
  new_information_required: boolean;
  escalation: { needed: boolean; reasons: string[] };
  exchanges: { used: number; limit: number };
  latest_reviewer: { stance: string; reply_excerpt: string } | null;
  latest_implementer: { position: string; delivery: string; delivery_reason: string | null; seen_by_reviewer: unknown } | null;
}

function threads(status: Record<string, unknown>): Thread[] {
  return (status["discussion"] as { threads: Thread[] }).threads;
}

function threadWith(status: Record<string, unknown>, title: string): Thread {
  const t = threads(status).find((x) => x.items.some((i) => i.title_excerpt === title));
  if (!t) throw new Error(`no thread for ${title}`);
  return t;
}

function tokenOf(status: Record<string, unknown>, title: string): { id: string; token: string } {
  const it = threadWith(status, title).items.find((i) => i.title_excerpt === title)!;
  return { id: it.id, token: it.response_token! };
}

function round1() {
  return okScenario(
    output({
      findings: [defect(), defect({ title: OVERFLOW, severity: "high", claim_type: "risk", evidence: [] }), defect({ title: NIT, claim_type: "suggestion", category: "style", severity: "low", evidence: [] })],
      questions: [
        { question: QUESTION, related_finding_index: 0, blocking: true },
        { question: NONBLOCKING, related_finding_index: null, blocking: false },
      ],
    }),
  );
}

function round2(replyText: string) {
  return okScenario(
    output({
      prior_findings: [1, 2, 3].map((k) => ({ id: `PF-${k}`, assessment: "still_present" as const, superseded_by_index: null, note: "" })),
      discussion_replies: [{ id: "PF-2", stance: "maintain", reply: replyText, new_information: "not_applicable" }],
    }),
  );
}

/** A whole history document (`responses` or an operation's `artifact` part), paged through. */
async function historyDoc(c: Conn, runId: string, what: { responses: Record<string, unknown> } | { artifact: Record<string, unknown> }): Promise<Record<string, unknown>> {
  const key = "responses" in what ? "responses" : "artifact";
  let text = "";
  for (let offset = 0; ; ) {
    const page = sc(await c.call("get_review_history", { run_id: runId, [key]: { ...("responses" in what ? what.responses : what.artifact), offset } }))[key] as { content: string; length: number; total_length: number };
    text += page.content;
    offset += page.length;
    if (offset >= page.total_length || page.length === 0) break;
  }
  return JSON.parse(text) as Record<string, unknown>;
}

/** A check that takes 150 ms longer on each run (a counter outside the repository) and fails from its third run. */
const VARY = "const fs=require('fs'); const f=process.argv[2]; const n=(fs.existsSync(f)?Number(fs.readFileSync(f,'utf8')):0)+1; fs.writeFileSync(f,String(n)); setTimeout(()=>process.exit(n>=3?1:0), 150*n);\n";

async function setup(flavor: Flavor): Promise<{ f: ReviewFixture; c: Conn; cfg: string }> {
  const f = await makeReviewFixture({ "config/db.env": "DB_PASSWORD=swordfish\n" });
  await approve(f, { checks: { unit: { argv: [node, "scripts/pass.js"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
  await setScenario(f, round1());
  const cfg = await writeServerConfig(f.scratch, { argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } });
  return { f, c: await connect(flavor, cfg), cfg };
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  await compileServer();
}, 120_000);

describe.skipIf(!supported)("the discussion over stdio (Phase 2.2)", () => {
  for (const flavor of FLAVORS) {
    it(`${flavor}: review → responses → status threads → a later review presents them → Codex's reply → history → restart → a repetition escalates → close`, async () => {
      const { f, c: c0, cfg } = await setup(flavor);
      let c = c0;
      try {
        const created = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }));
        const runId = created["run_id"] as string;
        const r1 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
        expect(r1["accepted"]).toBe(true);
        let status = sc(await c.call("get_review_status", { run_id: runId }));
        // Informational items are discoverable from status, with their tokens (P2.2-10).
        for (const title of [NIT, NONBLOCKING]) expect(threadWith(status, title).items[0]).toMatchObject({ status: "informational", response_token: expect.stringMatching(/^[0-9a-f]{32}$/) });
        expect((status["open_findings"] as { thread_id: string }[]).every((x) => typeof x.thread_id === "string")).toBe(true);

        const ov = tokenOf(status, OVERFLOW);
        const out = sc(
          await c.call("respond_to_review", {
            run_id: runId,
            request_id: "p22-first",
            responses: [
              { finding_id: ov.id, response_token: ov.token, disposition: "disputed", rationale: "Inputs are bounded by the caller.", references: [{ path: "src/math.js", start_line: 1 }] },
              { finding_id: tokenOf(status, NONBLOCKING).id, response_token: tokenOf(status, NONBLOCKING).token, disposition: "accepted", rationale: "Yes, in this change." },
              { finding_id: tokenOf(status, ADD).id, response_token: tokenOf(status, ADD).token, disposition: "accepted" },
            ],
          }),
        );
        expect(out["delivery_preview"]).toMatchObject({ reply_sought: 1, context: 2, not_presented: [] });
        // A replay returns the recorded result, preview included.
        expect(sc(await c.call("respond_to_review", { run_id: runId, request_id: "p22-first", responses: [{ finding_id: ov.id, response_token: ov.token, disposition: "disputed", rationale: "Inputs are bounded by the caller.", references: [{ path: "src/math.js", start_line: 1 }] }, { finding_id: tokenOf(status, NONBLOCKING).id, response_token: tokenOf(status, NONBLOCKING).token, disposition: "accepted", rationale: "Yes, in this change." }, { finding_id: tokenOf(status, ADD).id, response_token: tokenOf(status, ADD).token, disposition: "accepted" }] }))).toMatchObject({ deduplicated: true, response_set_id: out["response_set_id"] });
        status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(threadWith(status, OVERFLOW)).toMatchObject({ awaiting: "reviewer", last_speaker: "implementer" });
        expect(status["summary"]).toMatch(/with a turn the next review presents to Codex/);

        await setScenario(f, round2("Callers outside this module are not bounded."));
        const r2 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
        expect(r2["accepted"]).toBe(true);
        expect(r2["review_input_id"]).not.toBe(r1["review_input_id"]);
        expect(r2["discussion"]).toMatchObject({ presented: 3, reply_sought: 1, context: 2, replies_recorded: true, replies: [{ item_id: ov.id, stance: "maintain" }] });
        status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(threadWith(status, OVERFLOW)).toMatchObject({ awaiting: "implementer", last_speaker: "reviewer", new_information_required: true, exchanges: { used: 1, limit: 3 }, latest_reviewer: { stance: "maintain", reply_excerpt: "Callers outside this module are not bounded." } });
        expect((status["discussion"] as { reviewer_replies_recorded: number }).reviewer_replies_recorded).toBe(1);

        // Restart: the discussion is durable.
        await c.close();
        c = await connect(flavor, cfg);
        status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(threadWith(status, OVERFLOW)).toMatchObject({ last_speaker: "reviewer", latest_reviewer: { stance: "maintain" } });
        const hist = sc(await c.call("get_review_history", { run_id: runId, responses: { finding_id: threadWith(status, OVERFLOW).thread_id } }));
        const doc = JSON.parse((hist["responses"] as { content: string }).content) as { threads: { timeline: { event: string }[] }[]; items: { reviewer_replies: { stance: string; reply: string }[]; responses: { seen_by_reviewer: unknown }[] }[] };
        expect(doc.threads[0]!.timeline.map((e) => e.event)).toEqual(["implementer_turn", "presented_to_reviewer", "reviewer_reply"]);
        expect(doc.items[0]!.reviewer_replies[0]).toMatchObject({ stance: "maintain", reply: "Callers outside this module are not bounded." });
        expect(doc.items[0]!.responses[0]!.seen_by_reviewer).toMatchObject({ round: 2 });

        // The same argument again, reworded: recorded, not presented, escalated to the user.
        const ov2 = tokenOf(status, OVERFLOW);
        const again = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: ov2.id, response_token: ov2.token, disposition: "disputed", rationale: "As I said, the caller bounds it.", references: [{ path: "src/math.js", start_line: 1 }] }] }));
        expect(again["delivery_preview"]).toMatchObject({ reply_sought: 0, not_presented: [{ finding_id: ov.id, reason: "no_new_information" }] });
        status = sc(await c.call("get_review_status", { run_id: runId }));
        expect(threadWith(status, OVERFLOW)).toMatchObject({ awaiting: "user", escalation: { needed: true, reasons: ["disagreement_without_new_information"] } });
        expect(status["summary"]).toMatch(/needing a user decision/);
        expect((status["limitations"] as { code: string }[]).map((l) => l.code)).toContain("discussion_escalated");

        const closed = sc(await c.call("stop_review_loop", { run_id: runId, mode: "close" }));
        expect(closed["state"]).toBe("CLOSED");
        expect((closed["discussion"] as { escalated: number }).escalated).toBe(1);
      } finally {
        await c.close();
      }
    }, 300_000);
  }

  it("Codex's replies pass the host view like all text: withheld names, hashes and local paths never come back", async () => {
    const { f, c } = await setup("v2-modern");
    try {
      const runId = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }))["run_id"] as string;
      sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
      const status = sc(await c.call("get_review_status", { run_id: runId }));
      const ov = tokenOf(status, OVERFLOW);
      sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: ov.id, response_token: ov.token, disposition: "disputed", rationale: "bounded" }] }));
      const dbSha = createHash("sha256").update(readFileSync(join(f.repo, "config", "db.env"))).digest("hex");
      await setScenario(f, round2(`See config/db.env and .env (sha ${dbSha}) in ${join(f.dataHome, "runs")}`));
      const r2 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
      const s2 = sc(await c.call("get_review_status", { run_id: runId }));
      const hist = sc(await c.call("get_review_history", { run_id: runId, responses: {} }));
      for (const v of [r2, s2, hist]) {
        const text = JSON.stringify(v);
        expect(text).not.toContain("db.env");
        expect(text).not.toContain(dbSha);
        expect(text).not.toMatch(/\x22\.env\x22|[\\/]\.env\b|\s\.env\b/);
        expect(text.toLowerCase()).not.toContain(f.dataHome.toLowerCase());
      }
      expect(threadWith(s2, OVERFLOW).latest_reviewer!.reply_excerpt).toContain("[withheld path]");
      // The CLI's views (their output can reach a model too): threads and replies, redacted.
      const dir = await compileServer();
      for (const args of [["runs", "show", runId], ["runs", "show", runId, "--json"], ["runs", "list"]]) {
        const cli = spawnSync(process.execPath, [join(dir, "cli", "main.js"), ...args, "--home", f.dataHome], { encoding: "utf8", windowsHide: true });
        expect(cli.status, cli.stderr).toBe(0);
        expect(cli.stdout).not.toContain("db.env");
        expect(cli.stdout).not.toContain(dbSha);
        if (args.length === 3 && args[0] === "runs" && args[1] === "show") {
          expect(cli.stdout).toMatch(/reviewer replies: 1 recorded/);
          expect(cli.stdout).toMatch(/discussion threads: /);
          expect(cli.stdout).toMatch(/reviewer: maintain in round 2/);
        }
      }
    } finally {
      await c.close();
    }
  }, 180_000);

  it("the inputs stay strict: no stance, thread, reviewer or user field can be supplied anywhere", async () => {
    const { f, c } = await setup("v1");
    try {
      const runId = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }))["run_id"] as string;
      sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
      const status = sc(await c.call("get_review_status", { run_id: runId }));
      const ov = tokenOf(status, OVERFLOW);
      const one = { finding_id: ov.id, response_token: ov.token, disposition: "disputed", rationale: "x" };
      for (const extra of [{ stance: "withdraw" }, { thread_id: ov.id }, { reviewer_reply: "ok" }, { new_information: "yes" }, { user_decision: "defer" }, { escalation: false }, { delivered: true }]) {
        expect(errorCode(await c.call("respond_to_review", { run_id: runId, responses: [{ ...one, ...extra }] })), JSON.stringify(extra)).toBe("INVALID_ARGUMENT");
      }
      expect(errorCode(await c.call("respond_to_review", { run_id: runId, responses: [{ ...one, disposition: "withdrawn" }] }))).toBe("INVALID_ARGUMENT");
      expect(errorCode(await c.call("review_with_codex", { run_id: runId, discussion: [] }))).toBe("INVALID_ARGUMENT");
      expect(errorCode(await c.call("get_review_history", { run_id: runId, responses: { thread_id: ov.id } }))).toBe("INVALID_ARGUMENT");
      // A thread id is an item id: the history selects the whole thread by it.
      expect(errorCode(await c.call("get_review_history", { run_id: runId, responses: { finding_id: threadWith(status, OVERFLOW).thread_id } }))).toBeNull();
      expect((sc(await c.call("get_review_status", { run_id: runId }))["discussion"] as { responses_recorded: number }).responses_recorded).toBe(0);
    } finally {
      await c.close();
    }
  }, 180_000);

  it("a status with many threads stays inside the host bound: threads are capped, the rest counted and paged by the history", async () => {
    const { f, c } = await setup("v2-legacy");
    try {
      const many = Array.from({ length: 30 }, (_, k) => defect({ title: `risk ${k}`, claim_type: "risk", severity: "high", evidence: [] }));
      const notes = Array.from({ length: 30 }, (_, k) => defect({ title: `note ${k}`, claim_type: "suggestion", category: "style", severity: "low", evidence: [] }));
      await setScenario(f, okScenario(output({ findings: [...many, ...notes] })));
      const runId = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }))["run_id"] as string;
      sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
      const status = sc(await c.call("get_review_status", { run_id: runId }));
      expect(JSON.stringify(status).length).toBeLessThanOrEqual(MAX_RESULT_CHARS);
      expect(status["truncation"]).toBeUndefined();
      expect(status["discussion"]).toMatchObject({ threads_total: 60, threads_shown: 40 });
      const shown = threads(status);
      expect(shown).toHaveLength(40);
      // Ordered by who must act: the 30 open risks (the implementer has not responded) come first.
      expect(shown.slice(0, 30).every((t) => t.awaiting === "implementer")).toBe(true);
      // An idle thread carries no empty fields.
      expect(Object.keys(shown[0]!)).not.toEqual(expect.arrayContaining(["latest_implementer", "latest_reviewer", "escalation"]));
      expect((status["limitations"] as { code: string }[]).map((l) => l.code)).toContain("discussion_threads_truncated");
      // The history pages every thread with its tokens, also the 20 status did not list (PR #11 review).
      const doc = await historyDoc(c, runId, { responses: {} });
      expect(doc["threads"]).toHaveLength(60);
      const listed = doc["items"] as { finding_id: string; title: string; response_token: string | null }[];
      expect(listed).toHaveLength(60);
      expect(listed.every((i) => /^[0-9a-f]{32}$/.test(i.response_token ?? ""))).toBe(true);
      const shownTokens = new Map(shown.flatMap((t) => t.items.map((i) => [i.id, i.response_token] as const)));
      expect(listed.filter((i) => shownTokens.has(i.finding_id)).every((i) => shownTokens.get(i.finding_id) === i.response_token)).toBe(true);
      const hidden = listed.filter((i) => !shownTokens.has(i.finding_id));
      expect(hidden).toHaveLength(20);
      // A token found only there is the current one.
      const out = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: hidden[0]!.finding_id, response_token: hidden[0]!.response_token, disposition: "accepted" }] }));
      expect(out["recorded"]).toHaveLength(1);
    } finally {
      await c.close();
    }
  }, 180_000);

  it("check results, not their timing, decide the evidence basis; a review result rebuilt later previews the next review as status does (PR #11 review)", async () => {
    const f = await makeReviewFixture({ "config/db.env": "DB_PASSWORD=swordfish\n", "scripts/vary.js": VARY });
    await approve(f, { checks: { unit: { argv: [node, "scripts/vary.js", join(f.scratch, "vary-count.txt")] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    await setScenario(f, round1());
    const cfg = await writeServerConfig(f.scratch, { argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } });
    const c = await connect("v2-modern", cfg);
    try {
      const runId = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }))["run_id"] as string;
      expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 45 }))["operation_status"]).toBe("completed");
      expect(sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }))["accepted"]).toBe(true);
      const ov = tokenOf(sc(await c.call("get_review_status", { run_id: runId })), OVERFLOW);
      const ref = [{ path: "src/math.js", start_line: 1 }];
      sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: ov.id, response_token: ov.token, disposition: "disputed", rationale: "Inputs are bounded by the caller.", references: ref }] }));
      await setScenario(f, round2("Callers outside this module are not bounded."));
      const r2 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
      expect(r2["accepted"]).toBe(true);

      // The checks run again, slower, with the same result: no new information.
      expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 45 }))["operation_status"]).toBe("completed");
      const ov2 = tokenOf(sc(await c.call("get_review_status", { run_id: runId })), OVERFLOW);
      const again = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: ov.id, response_token: ov2.token, disposition: "disputed", rationale: "As I said, the caller bounds the inputs.", references: ref }] }));
      expect(again["delivery_preview"]).toMatchObject({ reply_sought: 0, not_presented: [{ finding_id: ov.id, reason: "no_new_information" }] });
      let status = sc(await c.call("get_review_status", { run_id: runId }));
      expect(threadWith(status, OVERFLOW)).toMatchObject({ awaiting: "user", latest_implementer: { delivery: "not_delivered", delivery_reason: "no_new_information" } });

      // The third run fails: the check results changed, so the same argument earns its exchange.
      expect(sc(await c.call("run_checks", { run_id: runId, wait_seconds: 45 }))["operation_status"]).toBe("completed");
      status = sc(await c.call("get_review_status", { run_id: runId }));
      expect(threadWith(status, OVERFLOW)).toMatchObject({ awaiting: "reviewer", latest_implementer: { delivery: "pending", delivery_basis: ["check_evidence_changed"] } });
      // The second review's result, rebuilt now, says the same about the next review.
      const result = await historyDoc(c, runId, { artifact: { operation_id: r2["operation_id"], part: "result" } });
      const open = (result["open_findings"] as { title: string; implementer_response: unknown }[]).find((x) => x.title === OVERFLOW)!;
      expect(open.implementer_response).toMatchObject({ delivery: "pending", delivery_basis: ["check_evidence_changed"] });
    } finally {
      await c.close();
    }
  }, 240_000);

  it("a review result rebuilt without a fresh current source previews the next review by the response's own source, as status and the review do (PR #11 review)", async () => {
    const { f, c } = await setup("v2-modern");
    try {
      const runId = sc(await c.call("create_review_run", { task_envelope: { goal: "Fix add()" }, repository_root: f.repo, wait_seconds: 30 }))["run_id"] as string;
      expect(sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }))["accepted"]).toBe(true);
      const ov = tokenOf(sc(await c.call("get_review_status", { run_id: runId })), OVERFLOW);
      const ref = [{ path: "src/math.js", start_line: 1 }];
      sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: ov.id, response_token: ov.token, disposition: "disputed", rationale: "Inputs are bounded by the caller.", references: ref }] }));
      await setScenario(f, round2("Callers outside this module are not bounded."));
      const r2 = sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }));
      expect(r2["accepted"]).toBe(true);

      // The code changes after Codex replied, and the implementer repeats its position on the new source.
      await writeFile(join(f.repo, "src", "math.js"), MATH_V1);
      const ov2 = tokenOf(sc(await c.call("get_review_status", { run_id: runId })), OVERFLOW);
      const again = sc(await c.call("respond_to_review", { run_id: runId, responses: [{ finding_id: ov.id, response_token: ov2.token, disposition: "disputed", rationale: "As I said, the caller bounds the inputs.", references: ref }] }));
      expect(again["delivery_preview"]).toMatchObject({ reply_sought: 1, not_presented: [] });
      const status = sc(await c.call("get_review_status", { run_id: runId }));
      expect(threadWith(status, OVERFLOW)).toMatchObject({ awaiting: "reviewer", latest_implementer: { delivery: "pending", delivery_basis: ["source_changed"] } });
      // The second review's result, rebuilt now: the tree is no longer the source it reviewed, so it
      // does not know the current source. It judges the turn by the turn's own source, as status
      // does without a read, and claims no staleness against the source it reviewed.
      const result = await historyDoc(c, runId, { artifact: { operation_id: r2["operation_id"], part: "result" } });
      const open = (result["open_findings"] as { title: string; implementer_response: unknown }[]).find((x) => x.title === OVERFLOW)!;
      expect(open.implementer_response).toMatchObject({ delivery: "pending", delivery_reason: null, delivery_basis: ["source_changed"], source_checked: false, stale_reasons: [] });

      // The review presents the turn for that reason.
      await setScenario(f, round2("Still not bounded."));
      expect(sc(await c.call("review_with_codex", { run_id: runId, wait_seconds: 45 }))["discussion"]).toMatchObject({ reply_sought: 1, replies: [{ item_id: ov.id, stance: "maintain" }] });
      const doc = await historyDoc(c, runId, { responses: { finding_id: ov.id } });
      const timeline = (doc["threads"] as { timeline: { event: string; round?: number; reply_sought?: boolean; basis?: string[] }[] }[])[0]!.timeline;
      expect(timeline.filter((e) => e.event === "presented_to_reviewer").at(-1)).toMatchObject({ round: 3, reply_sought: true, basis: ["source_changed"] });
    } finally {
      await c.close();
    }
  }, 240_000);
});
