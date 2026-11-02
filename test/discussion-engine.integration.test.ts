// Phase 2.2 against real git repositories and the scripted fake Codex (shared contract: the same
// behaviour on Windows and Linux; plan §1.15). The whole loop, one explicit step at a time:
// review → respond → a later review presents the response (bound into review_input_id) → the
// reviewer's structured reply → status and history. Also: "seen" only through an accepted
// review's delivery, withheld text never reaching Codex, every stance, tokens moved by replies,
// threads across supersession, restatement and consolidation, the new-information gate, budgets
// that are never reset, escalation instead of fake resolution, informational items, a damaged
// lineage, and a crash before the completion commit.

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { startReview, type ReviewEngineContext, type ReviewOperationResult, type ReviewRequest } from "../src/engine/review-operation.js";
import { responsesDocument } from "../src/engine/history.js";
import { clearProbeCache } from "../src/agents/codex/probe.js";
import { acquireWorktreeLock } from "../src/store/locks.js";
import { canonicalPathKey, worktreeLockPath } from "../src/store/paths.js";
import { commitState, readState } from "../src/store/state-store.js";
import { reportDiscussion, respondable, responseToken } from "../src/policy/responses.js";
import { seenBy, threadOfItem } from "../src/policy/discussion.js";
import { threadReports, type ThreadReport } from "../src/policy/discussion-reports.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, fakeCalls, lastExec, makeReviewFixture, newReviewRun, okScenario, output, setScenario, type ReviewFixture } from "./helpers/review-fixture.js";
import { itemNow, items, respond } from "./helpers/respond-fixture.js";
import type { ReviewOutput } from "../src/schemas/review.js";

async function review(ctx: ReviewEngineContext, req: ReviewRequest = {}): Promise<ReviewOperationResult> {
  return (await startReview(ctx, req)).completion;
}

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  let err: unknown = null;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect((err as { code?: string } | null)?.code, `expected ${code}, got ${String((err as Error | null)?.message ?? "success")}`).toBe(code);
}

async function lastPrompt(f: ReviewFixture): Promise<string> {
  const call = await lastExec(f);
  return call.prompt!;
}

/** The JSON of one prompt section (between its data markers). */
function section(prompt: string, name: string): unknown {
  const start = prompt.indexOf(` ${name}\n`);
  const body = prompt.slice(start + name.length + 2, prompt.indexOf("\nDATA ", start));
  return body.trim() === "none" ? null : JSON.parse(body);
}

interface PriorEntry {
  id: string;
  title: string;
  discussion?: { thread: string; exchanges_used: number; history: { from: string; position?: string; stance?: string }[]; implementer_turn: { position: string; rationale: string; presented_because: string[] } | null; awaiting_reply: boolean };
}

function priorOf(prompt: string, title: string): PriorEntry {
  const list = section(prompt, "prior") as PriorEntry[];
  const hit = list.find((p) => p.title === title);
  if (!hit) throw new Error(`no prior item ${title}`);
  return hit;
}

/** The discussion thread of an item, as status reports it now (no source read: preview by the recorded source). */
async function threadOf(ctx: ReviewEngineContext, title: string): Promise<ThreadReport> {
  const st = await readState(ctx.runPaths);
  const it = st.findings.find((f) => f.title === title)!;
  const { view } = reportDiscussion(st, null);
  const reports = threadReports(view.ix, view.plan, (x) => (respondable(x) ? responseToken(x, view.ix) : null));
  return reports.find((r) => r.thread_id === threadOfItem(view.ix, it).id)!;
}

const ADD = "add() subtracts";
const OVERFLOW = "overflow risk";
const NIT = "naming nit";
const QUESTION = "Should add() accept strings?";
const NONBLOCKING = "Is the README updated?";

function round1(): ReturnType<typeof okScenario> {
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

/** Every open item still present (aliases in the order the bundle lists them), plus extra output. */
function stillPresent(n: number, over: Partial<ReviewOutput> = {}): ReturnType<typeof okScenario> {
  return okScenario(output({ prior_findings: Array.from({ length: n }, (_, k) => ({ id: `PF-${k + 1}`, assessment: "still_present" as const, superseded_by_index: null, note: "" })), ...over }));
}

async function setup(files: Record<string, string> = {}) {
  clearProbeCache();
  const f = await makeReviewFixture(files);
  const { review: ctx } = await newReviewRun(f, { maxReviews: 12 });
  await setScenario(f, round1());
  const r1 = await review(ctx);
  expect(r1.accepted).toBe(true);
  return { f, ctx, r1 };
}

describe.skipIf(!supported)("the bounded discussion (Phase 2.2, shared contract)", () => {
  it("a response enters the next review: presented with its thread and a reply sought, bound into review_input_id; Codex's maintain is recorded and the finding stays open", async () => {
    const { f, ctx, r1 } = await setup();
    const ov = await itemNow(ctx, OVERFLOW);
    const out = await respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "disputed", rationale: "Inputs are bounded by the caller in src/math.js.", references: [{ path: "src/math.js", start_line: 1, end_line: 2 }] }] });
    // Recording starts nothing; the preview says the next review asks Codex for a reply.
    expect((await fakeCalls(f, "exec")).length).toBe(1);
    expect(out.delivery_preview).toMatchObject({ reply_sought: 1, context: 0, not_presented: [] });
    expect(await threadOf(ctx, OVERFLOW)).toMatchObject({ awaiting: "reviewer", last_speaker: "implementer", reviewer_seen_latest_implementer_turn: false, exchanges: { used: 0, limit: 3 } });

    // Open items PF-1 add(), PF-2 overflow, PF-3 the blocking question.
    await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-2", stance: "maintain", reply: "Callers outside this module are not bounded.", new_information: "not_applicable" }] }));
    const r2 = await review(ctx);
    expect(r2.accepted).toBe(true);
    expect(r2.deduplicated).toBe(false);
    expect(r2.review_input_id).not.toBe(r1.review_input_id);
    const entry = priorOf(await lastPrompt(f), OVERFLOW);
    expect(entry.id).toBe("PF-2");
    expect(entry.discussion).toMatchObject({ awaiting_reply: true, exchanges_used: 0, implementer_turn: { position: "disputed", rationale: "Inputs are bounded by the caller in src/math.js.", presented_because: ["first_exchange"] } });
    // Items without discussion carry none.
    expect(priorOf(await lastPrompt(f), ADD).discussion).toBeUndefined();

    const st = await readState(ctx.runPaths);
    expect(st.reviewer_replies).toEqual([expect.objectContaining({ item_id: ov.id, review_id: r2.review_id, round: 2, stance: "maintain", answers: { response_id: out.recorded[0]!.response_id }, assessment: "still_present", recorded_by: { role: "reviewer", channel: "codex" } })]);
    expect(st.findings.find((x) => x.id === ov.id)!.status).toBe("open");
    expect(r2.discussion).toMatchObject({ presented: 1, reply_sought: 1, context: 0, replies_recorded: true, replies: [{ item_id: ov.id, stance: "maintain" }] });
    expect(r2.prior_items.find((p) => p.title === OVERFLOW)).toMatchObject({ presented_in_this_review: true, response_seen_by_reviewer: true, reviewer_reply: { stance: "maintain" } });
    expect(seenBy(reportDiscussion(st, null).view.ix, out.recorded[0]!.response_id)).toEqual({ review_id: r2.review_id, round: 2 });
    expect(await threadOf(ctx, OVERFLOW)).toMatchObject({ awaiting: "implementer", last_speaker: "reviewer", new_information_required: true, exchanges: { used: 1 }, latest_reviewer: { stance: "maintain" }, escalation: { needed: false } });
    // The token read before the reply is stale now.
    await expectCode(respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "accepted", rationale: "" }] }), "STALE_FINDING_STATE");
    // The history pages the whole timeline.
    const doc = responsesDocument(st, ov.id) as { threads: { timeline: { event: string }[] }[]; items: { reviewer_replies: { stance: string }[] }[] };
    expect(doc.threads[0]!.timeline.map((e) => e.event)).toEqual(["implementer_turn", "presented_to_reviewer", "reviewer_reply"]);
    expect(doc.items[0]!.reviewer_replies.map((x) => x.stance)).toEqual(["maintain"]);
  }, 180_000);

  it("identical source and evidence: the discussion decides the input — a new turn is a new input, and the same discussion again is the earlier review", async () => {
    const { f, ctx } = await setup();
    const ov = await itemNow(ctx, OVERFLOW);
    await respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "disputed", rationale: "bounded" }] });
    await setScenario(f, stillPresent(3));
    const r2 = await review(ctx);
    // r2 presented the dispute and got no reply: r3 presents it again (awaiting a reply) — another input.
    const r3 = await review(ctx);
    expect(r3.deduplicated).toBe(false);
    expect(r3.review_input_id).not.toBe(r2.review_input_id);
    expect(priorOf(await lastPrompt(f), OVERFLOW).discussion).toMatchObject({ awaiting_reply: true, exchanges_used: 1, implementer_turn: { presented_because: ["unanswered"] } });
    expect(r2.limitations.map((l) => l.code)).toContain("discussion_reply_missing");
    // Settle the thread: the implementer accepts; r4 presents that as context, r5 has nothing new
    // to present, r6 has the same discussion as r5 — the identical-input guard returns r5.
    const ov2 = await itemNow(ctx, OVERFLOW);
    await respond(ctx, { responses: [{ finding_id: ov2.id, response_token: ov2.token!, disposition: "accepted", rationale: "fair" }] });
    const r4 = await review(ctx);
    expect(r4.discussion).toMatchObject({ presented: 1, reply_sought: 0, context: 1 });
    const r5 = await review(ctx);
    const execs = (await fakeCalls(f, "exec")).length;
    const r6 = await review(ctx);
    expect(r6).toMatchObject({ deduplicated: true, review_id: r5.review_id, review_input_id: r5.review_input_id });
    expect((await fakeCalls(f, "exec")).length).toBe(execs);
  }, 240_000);

  it("seen only through an accepted review: a review that was not accepted presented the turn, but it stays unseen, its replies are recorded nowhere, and the next accepted review presents it", async () => {
    const { f, ctx } = await setup();
    const a = await itemNow(ctx, ADD);
    const out = await respond(ctx, { responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed", rationale: "MARKER-PRESENTED intended" }] });
    const id = out.recorded[0]!.response_id;
    // The scripted Codex edits the tree during the review: the result is stale, not accepted.
    const replying = stillPresent(3, { discussion_replies: [{ id: "PF-1", stance: "withdraw", reply: "ok", new_information: "not_applicable" }] });
    await setScenario(f, { exec: { ...replying.exec!, touch_on_start: join(f.repo, "src", "math.js") } });
    const notAccepted = await review(ctx);
    expect(notAccepted.accepted).toBe(false);
    expect(await lastPrompt(f)).toContain("MARKER-PRESENTED");
    let st = await readState(ctx.runPaths);
    expect(seenBy(reportDiscussion(st, null).view.ix, id)).toBeNull();
    expect(st.reviewer_replies).toEqual([]);
    expect(notAccepted.discussion).toMatchObject({ presented: 1, replies_recorded: false, replies: [{ stance: "withdraw" }] });
    expect((await threadOf(ctx, ADD)).latest_implementer).toMatchObject({ seen_by_reviewer: null, delivery: "pending" });
    // The next accepted review presents it.
    await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-1", stance: "maintain", reply: "still subtracts", new_information: "not_applicable" }] }));
    const ok = await review(ctx);
    expect(ok.accepted).toBe(true);
    expect(await lastPrompt(f)).toContain("MARKER-PRESENTED");
    st = await readState(ctx.runPaths);
    expect(seenBy(reportDiscussion(st, null).view.ix, id)).toEqual({ review_id: ok.review_id, round: ok.round });
    expect(st.reviewer_replies).toEqual([expect.objectContaining({ review_id: ok.review_id, stance: "maintain" })]);
  }, 240_000);

  it("withheld text never reaches Codex; names withheld by any record of the run are redacted; exported context stays", async () => {
    const { f, ctx } = await setup({ "config/old.env": "OLD_SECRET=1\n" });
    const a = await itemNow(ctx, ADD);
    // The worktree cannot be read: the response is recorded with its text withheld from every view.
    const lock = await acquireWorktreeLock(worktreeLockPath(ctx.dataHome, canonicalPathKey(ctx.meta.repository_root)), { owner: ctx.owner, operationId: "test-holds-the-worktree", kind: "capture" });
    try {
      await respond(ctx, { responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed", rationale: "SECRET-RATIONALE-MARKER see config/old.env" }] });
    } finally {
      await lock.release();
    }
    expect((await readState(ctx.runPaths)).implementer_responses[0]!.text_withheld).toBe(true);
    // A file withheld by the first capture, deleted since: no later capture knows it.
    await rm(join(f.repo, "config", "old.env"));
    const envSha = createHash("sha256").update(readFileSync(join(f.repo, ".env"))).digest("hex");
    const ov = await itemNow(ctx, OVERFLOW);
    await respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "disputed", rationale: `.env (sha ${envSha}) and config/old.env stay; src/math.js line 2 is the fix; ${join(f.dataHome, "x")}`, references: [{ path: "config/old.env", start_line: 1 }, { path: "src/math.js", start_line: 2 }] }] });
    await setScenario(f, stillPresent(3));
    const r2 = await review(ctx);
    expect(r2.accepted).toBe(true);
    const prompt = await lastPrompt(f);
    expect(prompt).not.toContain("SECRET-RATIONALE-MARKER");
    expect(prompt).not.toContain("old.env");
    expect(prompt).not.toContain(envSha);
    expect(prompt).not.toMatch(/"\.env"|\s\.env\s/);
    expect(prompt.toLowerCase()).not.toContain(f.dataHome.toLowerCase());
    const entry = priorOf(prompt, OVERFLOW);
    expect(entry.discussion!.implementer_turn!.rationale).toContain("src/math.js line 2 is the fix");
    expect(entry.discussion!.implementer_turn!.rationale).toContain("[withheld path]");
    expect(entry.discussion!.implementer_turn!.rationale).toContain("[withheld hash]");
    expect(JSON.stringify(entry)).toContain('"path":"src/math.js"');
    // The withheld response was not presented, and the result says why.
    expect(r2.discussion!.not_delivered).toEqual([expect.objectContaining({ item_id: a.id, reason: "text_withheld" })]);
    expect(priorOf(prompt, ADD).discussion).toBeUndefined();
  }, 180_000);

  it("a repetition without new information is recorded, not presented, and escalates; genuinely new evidence is presented", async () => {
    const { f, ctx } = await setup();
    const ov = await itemNow(ctx, OVERFLOW);
    await respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "disputed", rationale: "Bounded by the caller.", references: [{ path: "src/math.js", start_line: 1 }] }] });
    await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-2", stance: "maintain", reply: "Not shown.", new_information: "not_applicable" }] }));
    await review(ctx);
    // The same position, reworded, citing the same location.
    const ov2 = await itemNow(ctx, OVERFLOW);
    const rep = await respond(ctx, { responses: [{ finding_id: ov2.id, response_token: ov2.token!, disposition: "disputed", rationale: "REWORDED-MARKER As I said, the caller bounds it.", references: [{ path: "src/math.js", start_line: 1 }] }] });
    expect(rep.delivery_preview.not_presented).toEqual([{ finding_id: ov.id, reason: "no_new_information" }]);
    expect(await threadOf(ctx, OVERFLOW)).toMatchObject({ awaiting: "user", new_information_required: true, escalation: { needed: true, reasons: ["disagreement_without_new_information"] } });
    await setScenario(f, stillPresent(3));
    const r3 = await review(ctx);
    expect(await lastPrompt(f)).not.toContain("REWORDED-MARKER");
    expect(r3.discussion!.not_delivered).toEqual([expect.objectContaining({ item_id: ov.id, reason: "no_new_information" })]);
    // New evidence (a location never cited before): presented, a reply sought.
    const ov3 = await itemNow(ctx, OVERFLOW);
    const fresh = await respond(ctx, { responses: [{ finding_id: ov3.id, response_token: ov3.token!, disposition: "disputed", rationale: "NEW-EVIDENCE-MARKER the guard is in validate()", references: [{ path: "src/math.js", start_line: 3 }] }] });
    expect(fresh.delivery_preview).toMatchObject({ reply_sought: 1, not_presented: [] });
    await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-2", stance: "withdraw", reply: "The guard covers it.", new_information: "yes" }] }));
    await review(ctx);
    expect(priorOf(await lastPrompt(f), OVERFLOW).discussion).toMatchObject({ awaiting_reply: true, implementer_turn: { presented_because: ["new_references"] } });
    // Withdrawn on an unchanged source: the item stays open (lifecycle rule), and only a user or a later review closes it.
    const st = await readState(ctx.runPaths);
    expect(st.findings.find((x) => x.id === ov.id)!.status).toBe("open");
    expect(await threadOf(ctx, OVERFLOW)).toMatchObject({ awaiting: "user", escalation: { reasons: ["withdrawn_but_open"] }, latest_reviewer: { stance: "withdraw", new_information: "yes" } });
  }, 240_000);

  it("the budget follows the lineage: a superseding finding continues the thread and its exchanges; exhausted disagreement escalates, the finding stays open", async () => {
    const { f, ctx } = await setup();
    const a = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed", rationale: "intended", references: [{ path: "src/math.js", start_line: 1 }] }] });
    // r2 supersedes add() by a more precise finding (index 0) and maintains.
    const precise = defect({ title: "add() returns a - b for every input", evidence: [{ kind: "code_reference", detail: "a - b", path: "src/math.js", start_line: 2, end_line: 2 }] });
    await setScenario(
      f,
      okScenario(
        output({
          findings: [precise],
          prior_findings: [
            { id: "PF-1", assessment: "superseded", superseded_by_index: 0, note: "more precise" },
            { id: "PF-2", assessment: "still_present", superseded_by_index: null, note: "" },
            { id: "PF-3", assessment: "still_present", superseded_by_index: null, note: "" },
          ],
          discussion_replies: [{ id: "PF-1", stance: "revise", reply: "Restated more precisely.", new_information: "not_applicable" }],
        }),
      ),
    );
    await review(ctx);
    let st = await readState(ctx.runPaths);
    const succ = st.findings.find((x) => x.title === precise.title)!;
    const ix = reportDiscussion(st, null).view.ix;
    expect(threadOfItem(ix, succ).id).toBe(a.id);
    // Two more exchanges on the successor (each with new evidence): 3 of 3 used.
    for (const [k, line] of [[0, 4], [1, 5]] as const) {
      const s = await itemNow(ctx, precise.title);
      await respond(ctx, { responses: [{ finding_id: s.id, response_token: s.token!, disposition: "disputed", rationale: `still intended ${k}`, references: [{ path: "src/math.js", start_line: line }] }] });
      // Open now: overflow (PF-1), the question (PF-2), the successor (PF-3).
      await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-3", stance: "maintain", reply: `no (${k})`, new_information: "yes" }] }));
      const r = await review(ctx);
      expect(r.discussion!.reply_sought).toBe(1);
    }
    expect((await threadOf(ctx, precise.title)).exchanges).toEqual({ used: 3, limit: 3, exhausted: true });
    // A fourth argument, even with new evidence: not presented, escalated, nothing resolved.
    const s = await itemNow(ctx, precise.title);
    const out = await respond(ctx, { responses: [{ finding_id: s.id, response_token: s.token!, disposition: "disputed", rationale: "one more", references: [{ path: "src/math.js", start_line: 9 }] }] });
    expect(out.delivery_preview.not_presented).toEqual([{ finding_id: s.id, reason: "exchange_budget_exhausted" }]);
    expect(await threadOf(ctx, precise.title)).toMatchObject({ awaiting: "user", escalation: { needed: true, reasons: ["exchange_budget_exhausted"] } });
    st = await readState(ctx.runPaths);
    expect(st.findings.find((x) => x.id === s.id)!.status).toBe("open");
    // The next review still assesses the item (verification is never stopped by the budget).
    await setScenario(f, stillPresent(3));
    await review(ctx);
    expect(priorOf(await lastPrompt(f), precise.title).discussion).toMatchObject({ awaiting_reply: false, implementer_turn: null, exchange_budget_exhausted: true });
  }, 300_000);

  it("restatement joins the item's thread; 'related' alone does not; a consolidation keeps every predecessor's discussion and budget use", async () => {
    const { f, ctx } = await setup();
    const it = await items(ctx);
    await respond(ctx, {
      responses: [
        { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "disputed", rationale: "first dispute" },
        { finding_id: it.get(OVERFLOW)!.id, response_token: it.get(OVERFLOW)!.token!, disposition: "disputed", rationale: "second dispute" },
      ],
    });
    // r2: one finding consolidates add() and overflow (both superseded by index 0); another
    // restates the question; a third is only related to it.
    const merged = defect({ title: "arithmetic is wrong for all inputs", severity: "critical", evidence: [{ kind: "code_reference", detail: "a - b", path: "src/math.js", start_line: 2, end_line: 2 }] });
    await setScenario(
      f,
      okScenario(
        output({
          findings: [merged, defect({ title: "the strings question, restated", claim_type: "risk", severity: "high", evidence: [], restates_prior_id: "PF-3" }), defect({ title: "a related risk", claim_type: "risk", severity: "high", evidence: [], related_prior_id: "PF-3" })],
          prior_findings: [
            { id: "PF-1", assessment: "superseded", superseded_by_index: 0, note: "" },
            { id: "PF-2", assessment: "superseded", superseded_by_index: 0, note: "" },
            { id: "PF-3", assessment: "still_present", superseded_by_index: null, note: "" },
          ],
          discussion_replies: [
            { id: "PF-1", stance: "revise", reply: "merged", new_information: "not_applicable" },
            { id: "PF-2", stance: "revise", reply: "merged", new_information: "not_applicable" },
          ],
        }),
      ),
    );
    const r2 = await review(ctx);
    expect(r2.accepted).toBe(true);
    const st = await readState(ctx.runPaths);
    const ix = reportDiscussion(st, null).view.ix;
    const byTitle = (t: string) => st.findings.find((x) => x.title === t)!;
    const t = threadOfItem(ix, byTitle(merged.title));
    expect(t.id).toBe(it.get(ADD)!.id);
    expect(t.merged).toEqual([it.get(OVERFLOW)!.id]);
    expect(threadOfItem(ix, byTitle("the strings question, restated")).id).toBe(it.get(QUESTION)!.id);
    expect(byTitle("the strings question, restated").restates).toEqual([it.get(QUESTION)!.id]);
    expect(threadOfItem(ix, byTitle("a related risk")).id).toBe(byTitle("a related risk").id);
    // Both disputes were exchanges: the consolidated thread has used 2.
    expect((await threadOf(ctx, merged.title)).exchanges.used).toBe(2);
    const doc = responsesDocument(st, byTitle(merged.title).id) as { items: { finding_id: string; responses: unknown[] }[] };
    expect(doc.items.filter((x) => x.responses.length === 1).map((x) => x.finding_id).sort()).toEqual([it.get(ADD)!.id, it.get(OVERFLOW)!.id].sort());
    // A response on the merged finding answers the revision: presented (reviewer_revised).
    const m = await itemNow(ctx, merged.title);
    const out = await respond(ctx, { responses: [{ finding_id: m.id, response_token: m.token!, disposition: "disputed", rationale: "still intended" }] });
    expect(out.delivery_preview.reply_sought).toBe(1);
  }, 240_000);

  it("need_information earns the implementer's answer an exchange; informational items are discoverable with tokens and an answer to a question reaches Codex as context", async () => {
    const { f, ctx } = await setup();
    // Status lists informational items' threads with tokens (P2.1 left them out of status).
    for (const title of [NIT, NONBLOCKING]) {
      const t = await threadOf(ctx, title);
      expect(t.items[0]).toMatchObject({ status: "informational", response_token: expect.stringMatching(/^[0-9a-f]{32}$/) });
    }
    const it = await items(ctx);
    await respond(ctx, {
      responses: [
        { finding_id: it.get(NIT)!.id, response_token: (await threadOf(ctx, NIT)).items[0]!.response_token!, disposition: "disputed", rationale: "The name follows the module convention." },
        { finding_id: it.get(NONBLOCKING)!.id, response_token: (await threadOf(ctx, NONBLOCKING)).items[0]!.response_token!, disposition: "accepted", rationale: "ANSWER-MARKER yes, in this change" },
        { finding_id: it.get(ADD)!.id, response_token: it.get(ADD)!.token!, disposition: "disputed", rationale: "intended" },
      ],
    });
    // The informational item's token once its response is recorded, before the review.
    const nitToken = (await threadOf(ctx, NIT)).items[0]!.response_token!;
    await setScenario(
      f,
      stillPresent(3, {
        discussion_replies: [
          { id: "IN-1", stance: "withdraw", reply: "Fine.", new_information: "not_applicable" },
          { id: "PF-1", stance: "need_information", reply: "Which callers rely on subtraction?", new_information: "not_applicable" },
        ],
      }),
    );
    const r2 = await review(ctx);
    const informational = section(await lastPrompt(f), "informational") as { id: string; title: string; discussion: { awaiting_reply: boolean } }[];
    expect(informational.map((x) => [x.id, x.title, x.discussion.awaiting_reply])).toEqual([
      ["IN-1", NIT, true],
      ["IN-2", NONBLOCKING, false],
    ]);
    expect(await lastPrompt(f)).toContain("ANSWER-MARKER");
    expect(r2.discussion).toMatchObject({ reply_sought: 2, context: 1 });
    const st = await readState(ctx.runPaths);
    expect(st.findings.find((x) => x.title === NIT)!.status).toBe("informational");
    expect(st.reviewer_replies.find((x) => x.item_id === it.get(NIT)!.id)).toMatchObject({ stance: "withdraw", assessment: null });
    // The reply moved the informational item's token although no assessment changed.
    await expectCode(respond(ctx, { responses: [{ finding_id: it.get(NIT)!.id, response_token: nitToken, disposition: "accepted", rationale: "" }] }), "STALE_FINDING_STATE");
    // Codex asked: the implementer's answer earns an exchange even without new references.
    expect(await threadOf(ctx, ADD)).toMatchObject({ awaiting: "implementer", latest_reviewer: { stance: "need_information" } });
    const a = await itemNow(ctx, ADD);
    const out = await respond(ctx, { responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed", rationale: "Only the legacy ledger import." }] });
    expect(out.delivery_preview.reply_sought).toBe(1);
    await setScenario(f, stillPresent(3));
    await review(ctx);
    expect(priorOf(await lastPrompt(f), ADD).discussion).toMatchObject({ awaiting_reply: true, implementer_turn: { presented_because: ["answers_reviewer_question"] } });
  }, 240_000);

  it("a crash before the completion commit records no reply and counts nothing as seen; a damaged lineage never breaks a report or a review", async () => {
    const { f, ctx } = await setup();
    const a = await itemNow(ctx, ADD);
    const out = await respond(ctx, { responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed", rationale: "intended" }] });
    await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-1", stance: "maintain", reply: "no", new_information: "not_applicable" }] }));
    ctx.testHooks!.beforeCompletionCommit = () => {
      throw new Error("injected crash before the completion commit");
    };
    const crashed = await review(ctx);
    ctx.testHooks!.beforeCompletionCommit = undefined;
    expect(crashed.accepted).toBe(false);
    let st = await readState(ctx.runPaths);
    expect(st.reviewer_replies).toEqual([]);
    expect(seenBy(reportDiscussion(st, null).view.ix, out.recorded[0]!.response_id)).toBeNull();
    // Damage the lineage: a cycle between two open items and a dangling link.
    await commitState(ctx.runPaths, ctx.owner, (s) => {
      const ov = s.findings.find((x) => x.title === OVERFLOW)!;
      const q = s.findings.find((x) => x.title === QUESTION)!;
      ov.supersedes = [q.id];
      q.supersedes = [ov.id];
      ov.restates = ["0199ffff-0000-7000-8000-00000000dead"];
      return s;
    });
    const t = await threadOf(ctx, OVERFLOW);
    expect(t.lineage_anomalies).toEqual(expect.arrayContaining(["cycle", "dangling_link"]));
    expect(t.escalation.reasons).toContain("lineage_anomaly");
    await setScenario(f, stillPresent(3));
    const r = await review(ctx);
    expect(r.accepted).toBe(true);
    st = await readState(ctx.runPaths);
    expect(seenBy(reportDiscussion(st, null).view.ix, out.recorded[0]!.response_id)).toEqual({ review_id: r.review_id, round: r.round });
  }, 240_000);

  it("concurrency: a review presents exactly what was recorded before it started; a response attempted while it runs is refused and reaches the next review; a replay after delivery records nothing", async () => {
    const { f, ctx } = await setup();
    const a = await itemNow(ctx, ADD);
    const first = { request_id: "before", responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed" as const, rationale: "BEFORE-MARKER intended" }] };
    const r0 = await respond(ctx, first);
    const ov = await itemNow(ctx, OVERFLOW);
    const scenario = stillPresent(3, { discussion_replies: [{ id: "PF-1", stance: "maintain", reply: "no", new_information: "not_applicable" }] });
    await setScenario(f, { exec: { ...scenario.exec!, sleep_ms: 2500 } });
    const started = await startReview(ctx, {});
    for (let i = 0; i < 100 && (await readState(ctx.runPaths)).reviews.length < 2; i++) await new Promise((r) => setTimeout(r, 100));
    await expectCode(respond(ctx, { responses: [{ finding_id: ov.id, response_token: ov.token!, disposition: "disputed", rationale: "DURING-MARKER" }] }), "RUN_BUSY");
    const r2 = await started.completion;
    expect(r2.accepted).toBe(true);
    const st = await readState(ctx.runPaths);
    const rec = st.reviews.find((r) => r.review_id === r2.review_id)!;
    expect(rec.discussion!.delivered.map((d) => d.response_id)).toEqual([r0.recorded[0]!.response_id]);
    expect(await lastPrompt(f)).not.toContain("DURING-MARKER");
    // The replay of the delivered request: nothing recorded, nothing pending.
    const replay = await respond(ctx, first);
    expect(replay).toMatchObject({ deduplicated: true, delivery_preview: { reply_sought: 0, context: 0, not_presented: [] } });
    // Recorded after the review, it reaches the next one.
    const ov2 = await itemNow(ctx, OVERFLOW);
    await respond(ctx, { responses: [{ finding_id: ov2.id, response_token: ov2.token!, disposition: "disputed", rationale: "AFTER-MARKER" }] });
    await setScenario(f, stillPresent(3));
    await review(ctx);
    expect(await lastPrompt(f)).toContain("AFTER-MARKER");
  }, 180_000);

  it("previously recorded responses (a P2.1-era run) are presented to the next review, and the answer ordering needs no clock", async () => {
    const { f, ctx } = await setup();
    const a = await itemNow(ctx, ADD);
    await respond(ctx, { responses: [{ finding_id: a.id, response_token: a.token!, disposition: "disputed", rationale: "P21-MARKER recorded by an earlier version" }] });
    // As a P2.1 server wrote it: no run_review_id, run_round, reviewer_reply_id or thread_id.
    await commitState(ctx.runPaths, ctx.owner, (s) => {
      for (const r of s.implementer_responses) {
        delete (r.answers as Record<string, unknown>)["run_review_id"];
        delete (r.answers as Record<string, unknown>)["run_round"];
        delete (r.answers as Record<string, unknown>)["reviewer_reply_id"];
        delete (r as Record<string, unknown>)["thread_id"];
      }
      return s;
    });
    await setScenario(f, stillPresent(3, { discussion_replies: [{ id: "PF-1", stance: "maintain", reply: "no", new_information: "not_applicable" }] }));
    const r2 = await review(ctx);
    expect(await lastPrompt(f)).toContain("P21-MARKER");
    expect(r2.discussion).toMatchObject({ reply_sought: 1, replies: [{ stance: "maintain" }] });
    expect(await threadOf(ctx, ADD)).toMatchObject({ last_speaker: "reviewer" });
  }, 180_000);
});
