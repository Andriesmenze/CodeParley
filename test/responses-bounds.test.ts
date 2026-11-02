// Phase 2.1, from the review of PR #10 (platform-independent: the run store only, no git or
// Codex). A respond_to_review result is bounded by design: even a full batch of the largest
// entries needs no shortening, whose recovery hint would name an operation this tool does not
// have. A disclosure record that no commit came to reference is removed again: limits are
// checked before it is written, and a commit refused afterwards removes it, so retries cannot
// grow the store. A run purged while a response is recorded is never recreated.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { uuidv7 } from "../src/common/ids.js";
import { createRun, readState } from "../src/store/state-store.js";
import { canonicalPathKey, runPaths, type RunPaths } from "../src/store/paths.js";
import { selfOwner } from "../src/store/owner.js";
import { newStateRecord } from "../src/schemas/run-state.js";
import type { ReviewerItem } from "../src/schemas/review.js";
import { RESPONSE_LIMITS } from "../src/schemas/responses.js";
import { respondToReview, type RespondContext, type RespondTestHooks, type SourceForResponse } from "../src/engine/respond.js";
import { itemDiscussion, reportDiscussion, WITHHELD_RESPONSE_TEXT } from "../src/policy/responses.js";
import { responsesDocument } from "../src/engine/history.js";
import { fitToLimit, MAX_RESULT_CHARS } from "../src/server/result.js";

const H = (c: string) => c.repeat(64);
const WITHHELD = { paths: ["config/secret.env"], hashes: [H("e"), "f".repeat(40)] };

/** A reviewer question whose text is as long as a question may be (it is the item's title). */
function question(k: number): ReviewerItem {
  return {
    id: uuidv7(),
    item_kind: "question",
    review_id: "review-1",
    round: 1,
    source_id: H("a"),
    review_input_id: H("b"),
    title: `${k} ${"q".repeat(3990)}`,
    claim_type: null,
    severity: null,
    category: null,
    impacts: [],
    consequence: "",
    confidence: null,
    evidence: [],
    investigation: "",
    recommended_change: "",
    triage: "blocking_question",
    basis: "reviewer_evidence",
    policy_notes: [],
    status: "open",
    related_prior_id: null,
    related_finding_id: null,
    supersedes: [],
    superseded_by: null,
    assessments: [],
    created_at: new Date().toISOString(),
  };
}

let home = "";
let paths: RunPaths;
let runId = "";

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "arl-respond-bounds-"));
  runId = uuidv7();
  paths = runPaths(home, canonicalPathKey(home), runId);
  const st0 = newStateRecord(runId, "IDLE");
  st0.findings = Array.from({ length: RESPONSE_LIMITS.perCall }, (_, k) => question(k));
  await createRun(paths, { schema_version: 1, run_id: runId, created_at: new Date().toISOString(), repository_root: home, versions: {}, scope: { allowed_snapshot: [home], client_roots_snapshot: [] } }, st0);
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

function context(source: () => SourceForResponse, testHooks?: RespondTestHooks): RespondContext {
  return { runId, runPaths: paths, owner: selfOwner(), currentSource: async () => source(), ...(testHooks ? { testHooks } : {}) };
}

async function tokens(): Promise<{ id: string; token: string }[]> {
  const st = await readState(paths);
  return st.findings.map((it) => ({ id: it.id, token: itemDiscussion(it, reportDiscussion(st, null).view, null).response_token! }));
}

async function opsDirs(): Promise<string[]> {
  return existsSync(paths.opsDir) ? (await readdir(paths.opsDir)).sort() : [];
}

describe("respond_to_review results and records stay bounded (Phase 2.1, PR #10 review)", () => {
  it("a full batch of the largest entries needs no shortening: no reviewer text, no repeated source note", async () => {
    const first = await tokens();
    await respondToReview(context(() => ({ source_id: H("c"), note: null })), { responses: first.map((x) => ({ finding_id: x.id, response_token: x.token, disposition: "accepted" as const, rationale: "" })) });
    // Each entry at its largest: it supersedes an earlier response, has the longest state and the
    // longest note (a fix claimed on the very source the reviewer saw), and a maximal rationale.
    const second = await tokens();
    const out = await respondToReview(context(() => ({ source_id: H("a"), note: null, withheld: WITHHELD })), {
      responses: second.map((x) => ({ finding_id: x.id, response_token: x.token, disposition: "fix_claimed" as const, rationale: "r".repeat(RESPONSE_LIMITS.rationaleChars) })),
    });
    expect(out.recorded).toHaveLength(RESPONSE_LIMITS.perCall);
    expect(out.recorded.every((r) => r.supersedes !== null && r.discussion_state === "fix_claimed_awaiting_verification" && r.notes.length === 1)).toBe(true);
    expect(JSON.stringify(out)).not.toContain("qqqq");
    expect(JSON.stringify(out).length).toBeLessThan(MAX_RESULT_CHARS * 0.75);
    expect(fitToLimit({ ...out })).not.toHaveProperty("truncation");

    // Without a source the reason is reported once, not in every entry.
    const third = await tokens();
    const note = `the worktree is busy (a check or capture holds it); this is the last known value ${"n".repeat(300)}`;
    const busy = await respondToReview(context(() => ({ source_id: null, note })), { responses: third.map((x) => ({ finding_id: x.id, response_token: x.token, disposition: "disputed" as const, rationale: "d".repeat(RESPONSE_LIMITS.rationaleChars) })) });
    expect(busy.source.note).toBe(note);
    expect(JSON.stringify(busy.recorded)).not.toContain("nnnn");
    expect(fitToLimit({ ...busy })).not.toHaveProperty("truncation");
  });

  it("a refused call leaves no disclosure record: limits are checked before one is written, and a commit refused afterwards removes it", async () => {
    let target = (await tokens())[0]!;
    for (let i = 0; i < RESPONSE_LIMITS.perItem; i++) {
      const res = await respondToReview(context(() => ({ source_id: H("c"), note: null })), { responses: [{ finding_id: target.id, response_token: target.token, disposition: "accepted", rationale: "" }] });
      target = { id: target.id, token: res.recorded[0]!.response_token! };
    }
    const before = await opsDirs();
    // At the per-item limit with a still-current token: refused before the source is read, so
    // retrying cannot write anything.
    let reads = 0;
    const counting = context(() => {
      reads++;
      return { source_id: H("c"), note: null, withheld: WITHHELD };
    });
    for (let k = 0; k < 3; k++) {
      await expect(respondToReview(counting, { responses: [{ finding_id: target.id, response_token: target.token, disposition: "disputed", rationale: "again" }] })).rejects.toMatchObject({ code: "BUDGET_EXHAUSTED" });
    }
    expect(reads).toBe(0);
    expect(await opsDirs()).toEqual(before);

    // Refused inside the commit, after the record was written: it is removed again.
    const other = (await tokens())[1]!;
    const refusing = context(() => ({ source_id: H("c"), note: null, withheld: WITHHELD }), {
      beforeWrite: () => {
        throw new Error("injected refusal");
      },
    });
    await expect(respondToReview(refusing, { responses: [{ finding_id: other.id, response_token: other.token, disposition: "disputed", rationale: "x" }] })).rejects.toThrow("injected refusal");
    expect(await opsDirs()).toEqual(before);

    // Recorded: the record stays, and the response refers to it.
    const kept = await respondToReview(context(() => ({ source_id: H("c"), note: null, withheld: WITHHELD })), { responses: [{ finding_id: other.id, response_token: other.token, disposition: "disputed", rationale: "x" }] });
    expect(await opsDirs()).toEqual([...before, kept.response_set_id].sort());
    expect((await readState(paths)).implementer_responses.at(-1)!.disclosure_ref).toBe(`ops/${kept.response_set_id}/responses/disclosure.json`);
  });

  // Purge and retention move an idle run into the trash under its run lock; a response holds no
  // lock while it reads the source and writes its disclosure record (Codex review of PR #10).
  it("a run purged while its source was read is not recreated by the disclosure record", async () => {
    const target = (await tokens())[0]!;
    const trash = join(home, "trash-during-read");
    const ctx: RespondContext = {
      ...context(() => ({ source_id: H("c"), note: null })),
      currentSource: async () => {
        await rename(paths.runDir, trash);
        return { source_id: H("c"), note: null, withheld: WITHHELD };
      },
    };
    await expect(respondToReview(ctx, { responses: [{ finding_id: target.id, response_token: target.token, disposition: "disputed", rationale: "x" }] })).rejects.toMatchObject({ code: "RUN_NOT_FOUND" });
    expect(existsSync(paths.runDir)).toBe(false);
    expect(await readdir(join(trash, "ops"))).toEqual([]);
  });

  it("a run purged after the disclosure record was written takes the record with it and is not recreated", async () => {
    const target = (await tokens())[0]!;
    const trash = join(home, "trash-after-write");
    const ctx = context(() => ({ source_id: H("c"), note: null, withheld: WITHHELD }), {
      afterPublish: async () => {
        await rename(paths.runDir, trash);
      },
    });
    await expect(respondToReview(ctx, { responses: [{ finding_id: target.id, response_token: target.token, disposition: "disputed", rationale: "x" }] })).rejects.toMatchObject({ code: "RUN_NOT_FOUND" });
    expect(existsSync(paths.runDir)).toBe(false);
    expect(await readdir(join(trash, "ops"))).toHaveLength(1);
  });

  // Codex review of PR #10 (third round): without a read of the working tree, nothing knows what
  // is confidential now, so the text of such a response is withheld from every view.
  it("responses recorded without a read of the working tree keep their dispositions, and every view withholds their text", async () => {
    const [a, b] = (await tokens()).slice(0, 2) as [{ id: string; token: string }, { id: string; token: string }];
    const named = "notes/late-name.md";
    const unread = await respondToReview(context(() => ({ source_id: null, note: "the worktree is busy (a check or capture holds it)" })), {
      responses: [
        { finding_id: a.id, response_token: a.token, disposition: "disputed", rationale: `see ${named}`, references: [{ path: named, start_line: 1 }] },
        { finding_id: b.id, response_token: b.token, disposition: "deferred", rationale: "later" },
      ],
    });
    expect(unread.summary).toMatch(/could not be checked for confidential names/);
    expect(unread.recorded.every((r) => r.notes.some((n) => n.includes("text withheld from every view")))).toBe(true);
    const st = await readState(paths);
    expect(st.implementer_responses.map((r) => [r.disposition, r.text_withheld])).toEqual([
      ["disputed", true],
      ["deferred", true],
    ]);
    // Status and results: the excerpt; history: the rationale and the references.
    const item = st.findings.find((f) => f.id === a.id)!;
    const shown = itemDiscussion(item, reportDiscussion(st, null).view, null);
    expect(shown.discussion_state).toBe("disputed");
    expect(shown.implementer_response!.rationale_excerpt).toBe(WITHHELD_RESPONSE_TEXT);
    const doc = JSON.stringify(responsesDocument(st, a.id));
    expect(doc).not.toContain("late-name");
    expect(doc).toContain(WITHHELD_RESPONSE_TEXT);
    // A read that saw the tree change may have missed a file created meanwhile: also withheld.
    const [, c] = (await tokens()).slice(1, 3) as [unknown, { id: string; token: string }];
    await respondToReview(context(() => ({ source_id: null, note: "the working tree changed while it was being read", withheld: { paths: [], hashes: [] } })), { responses: [{ finding_id: c.id, response_token: c.token, disposition: "disputed", rationale: "seen while it changed" }] });
    expect((await readState(paths)).implementer_responses.at(-1)!.text_withheld).toBe(true);
    // Recorded again with a read: the new response's text is shown.
    const again = (await tokens()).find((x) => x.id === a.id)!;
    await respondToReview(context(() => ({ source_id: H("c"), note: null, withheld: { paths: [], hashes: [] } })), { responses: [{ finding_id: a.id, response_token: again.token, disposition: "disputed", rationale: "checked now" }] });
    const st2 = await readState(paths);
    expect(itemDiscussion(st2.findings.find((f) => f.id === a.id)!, reportDiscussion(st2, null).view, null).implementer_response!.rationale_excerpt).toBe("checked now");
  });
});
