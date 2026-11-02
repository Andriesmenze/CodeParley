// Phase 2.2 compatibility (plan §1.15, P2.2-12): run stores written by released and earlier
// versions — v0.1.0 (Windows, M1), v0.2.0 (Linux) and the Phase 2.1 code (commit b21ef09, with the
// implementer's responses it recorded and never sent to Codex) — are read with today's schemas,
// served with derived threads, and reviewed by today's engine: a P2.1 response on a live item is
// presented to the next review, nothing earlier versions recorded is rewritten, and their reviews
// count as having presented nothing (true: they never sent a response).

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { StateRecordSchema } from "../src/schemas/run-state.js";
import { canonicalPathKey } from "../src/store/paths.js";
import { canonicalizePath } from "../src/workspace/paths.js";
import { lastExec, makeReviewFixture, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { compileServer, connect, removeCompiledServer, sc, writeServerConfig } from "./helpers/mcp-harness.js";
import { supported } from "./helpers/git-fixture.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "compat");
// The stores written before Phase 2.2 (a P2.2 store has replies and deliveries: user-authority-compat covers it).
const NAMES = readdirSync(FIXTURES).filter((n) => /^(v\d|p2\.1-)/.test(n));

interface FixtureMeta {
  tag: string;
  platform: string;
  run_id: string;
  files: string[];
}

function meta(name: string): FixtureMeta {
  return JSON.parse(readFileSync(join(FIXTURES, name, "fixture.json"), "utf8")) as FixtureMeta;
}

function substituted(name: string, rel: string, values: { repo: string; scratch: string }): string {
  const esc = (p: string) => JSON.stringify(p).slice(1, -1);
  return readFileSync(join(FIXTURES, name, "run", ...rel.split("/")), "utf8").split("<REPO>").join(esc(values.repo)).split("<SCRATCH>").join(esc(values.scratch)).split("<NODE>").join(esc(process.execPath));
}

interface Thread {
  thread_id: string;
  items: { id: string; title_excerpt: string; status: string; response_token: string | null }[];
  awaiting: string;
  escalation?: { needed: boolean; reasons: string[] };
  latest_implementer?: { position: string; delivery: string };
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  if (supported) await compileServer();
}, 120_000);

describe("compatibility of earlier stores with the discussion (Phase 2.2)", () => {
  it("fixtures exist for v0.1.0 (Windows), v0.2.0 (Linux) and the Phase 2.1 code (Linux)", () => {
    expect(NAMES.map((n) => `${meta(n).tag}-${meta(n).platform}`).sort()).toEqual(["p2.1-linux", "v0.1.0-win32", "v0.2.0-linux"]);
  });

  for (const name of NAMES) {
    it(`${name}: today's schemas read every record; every original field is kept; no reply and no delivery exist yet`, () => {
      const raw = JSON.parse(substituted(name, "state.json", { repo: "/r", scratch: "/s" })) as Record<string, unknown>;
      expect(raw["reviewer_replies"]).toBeUndefined();
      const parsed = StateRecordSchema.parse(raw);
      expect(parsed.reviewer_replies).toEqual([]);
      expect(parsed.reviews.every((r) => r.discussion === undefined)).toBe(true);
      expect(parsed.findings.every((f) => f.restates === undefined)).toBe(true);
      // Phase 2.3's lists are additive too (P2.3-16): absent in the old record, empty when read.
      expect(raw["user_decisions"]).toBeUndefined();
      expect(raw["task_amendments"]).toBeUndefined();
      expect(parsed.user_decisions).toEqual([]);
      expect(parsed.task_amendments).toEqual([]);
      const { reviewer_replies: _r, implementer_responses: _i, user_decisions: _d, task_amendments: _a, user_records_custodian: _u, run_records_custodian: _rr, ...rest } = parsed as unknown as Record<string, unknown>;
      const { implementer_responses: _ri, ...rawRest } = raw;
      expect(JSON.parse(JSON.stringify(rest))).toEqual(rawRest);
    });

    it.skipIf(!supported)(`${name}: served with threads from its supersession; the next review presents what it recorded; its records stay as they were`, async () => {
      const m = meta(name);
      const f = await makeReviewFixture({ "config/db.env": "DB_PASSWORD=swordfish\n" });
      const repo = await canonicalizePath(f.repo);
      const runDir = join(f.dataHome, "runs", canonicalPathKey(repo), m.run_id);
      for (const rel of m.files) {
        await mkdir(dirname(join(runDir, ...rel.split("/"))), { recursive: true });
        await writeFile(join(runDir, ...rel.split("/")), substituted(name, rel, { repo, scratch: f.scratch }));
      }
      await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ retention: { purge_on_startup: false } }));
      const before = StateRecordSchema.parse(JSON.parse(await readFile(join(runDir, "state.json"), "utf8")));
      const cfg = await writeServerConfig(f.scratch, { argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } });
      const c = await connect("v2-modern", cfg);
      try {
        const status = sc(await c.call("get_review_status", { run_id: m.run_id }));
        const threads = (status["discussion"] as { threads: Thread[] }).threads;
        const of = (title: string) => threads.find((t) => t.items.some((i) => i.title_excerpt === title))!;
        // The superseding finding continues the superseded one's thread.
        const overflow = before.findings.find((x) => x.title === "overflow risk")!;
        expect(of("overflow for large ints").thread_id).toBe(overflow.id);
        // Informational items are listed with their tokens.
        expect(of("naming nit").items[0]).toMatchObject({ status: "informational", response_token: expect.stringMatching(/^[0-9a-f]{32}$/) });
        const p21 = before.implementer_responses.length > 0;
        if (p21) {
          // What P2.1 recorded and never sent: pending for the next review; the deferral needs a user.
          expect(of("overflow for large ints")).toMatchObject({ awaiting: "reviewer", latest_implementer: { position: "disputed", delivery: "pending" } });
          expect(of("Should add() accept strings?").escalation).toEqual({ needed: true, reasons: ["deferral_requested"] });
        }

        // Open now: the question (round 1) is PF-1, the superseding finding (round 2) PF-2.
        await setScenario(
          f,
          okScenario(
            output({
              prior_findings: [
                { id: "PF-1", assessment: "still_present", superseded_by_index: null, note: "" },
                { id: "PF-2", assessment: "still_present", superseded_by_index: null, note: "" },
              ],
              discussion_replies: p21 ? [{ id: "PF-2", stance: "maintain", reply: "Inputs are not bounded at the API.", new_information: "not_applicable" }] : [],
            }),
          ),
        );
        const r3 = sc(await c.call("review_with_codex", { run_id: m.run_id, wait_seconds: 45 }));
        expect(r3["accepted"]).toBe(true);
        const prompt = (await lastExec(f)).prompt!;
        if (p21) {
          expect(prompt).toContain("P21-SUCCESSOR-DISPUTE");
          expect(prompt).toContain("P21-DEFERRAL");
          // The dispute of the superseded item was never sent and is not copied onto its successor.
          expect(prompt).not.toContain("P21-DISPUTE inputs");
          expect(r3["discussion"]).toMatchObject({ reply_sought: 1, context: 1, replies: [{ stance: "maintain" }] });
        } else {
          expect(r3["discussion"]).toMatchObject({ presented: 0, replies: [] });
          expect(section(prompt)).toBeNull();
        }
      } finally {
        await c.close();
      }
      // Nothing earlier versions recorded was rewritten: responses, reviews and run.json are as they were.
      const after = StateRecordSchema.parse(JSON.parse(await readFile(join(runDir, "state.json"), "utf8")));
      expect(after.implementer_responses).toEqual(before.implementer_responses);
      expect(after.reviews.slice(0, before.reviews.length)).toEqual(before.reviews);
      expect(after.findings.map((x) => [x.id, x.title, x.triage, x.supersedes, x.superseded_by])).toEqual(
        expect.arrayContaining(before.findings.map((x) => [x.id, x.title, x.triage, x.supersedes, x.superseded_by])),
      );
      expect(await readFile(join(runDir, "run.json"), "utf8")).toBe(substituted(name, "run.json", { repo, scratch: f.scratch }));
    }, 180_000);
  }
});

/** The informational-discussion section of a prompt (null when "none"). */
function section(prompt: string): unknown {
  const start = prompt.indexOf(" informational\n");
  const body = prompt.slice(start + " informational\n".length, prompt.indexOf("\nDATA ", start));
  return body.trim() === "none" ? null : JSON.parse(body);
}
