// Phase 2.1 compatibility (plan §1.14): run stores written by the RELEASED versions — v0.1.0 on
// Windows (M1) and v0.2.0 on Linux (the Linux milestone) — stay readable and usable. The
// fixtures under test/fixtures/compat/ were produced by those releases' own code
// (compat-fixtures.generate.test.ts), with local paths replaced by placeholders. Each is
//  - parsed with today's schemas: every original field kept, the new list empty;
//  - installed into a fresh data home (paths substituted) and served by today's server over
//    stdio: status with response tokens, responses recorded, history, the old review results —
//    and afterwards every original record is byte-for-byte what it was, apart from the commit's
//    own revision, timestamp, the appended event and the new responses.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { StateRecordSchema } from "../src/schemas/run-state.js";
import { canonicalPathKey } from "../src/store/paths.js";
import { canonicalizePath } from "../src/workspace/paths.js";
import { makeReviewFixture } from "./helpers/review-fixture.js";
import { compileServer, connect, errorCode, removeCompiledServer, sc, writeServerConfig } from "./helpers/mcp-harness.js";
import { supported } from "./helpers/git-fixture.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "compat");
const NAMES = readdirSync(FIXTURES).filter((n) => /^v\d/.test(n));

interface FixtureMeta {
  tag: string;
  platform: string;
  run_id: string;
  files: string[];
}

function meta(name: string): FixtureMeta {
  return JSON.parse(readFileSync(join(FIXTURES, name, "fixture.json"), "utf8")) as FixtureMeta;
}

/** A fixture file with its placeholders replaced (JSON-escaped: every record is JSON). */
function substituted(name: string, rel: string, values: { repo: string; scratch: string }): string {
  const esc = (p: string) => JSON.stringify(p).slice(1, -1);
  return readFileSync(join(FIXTURES, name, "run", ...rel.split("/")), "utf8")
    .split("<REPO>")
    .join(esc(values.repo))
    .split("<SCRATCH>")
    .join(esc(values.scratch))
    .split("<NODE>")
    .join(esc(process.execPath));
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  if (supported) await compileServer();
}, 120_000);

describe("compatibility with stores of released versions (Phase 2.1)", () => {
  it("fixtures exist for v0.1.0 (Windows) and v0.2.0 (Linux)", () => {
    expect(NAMES.map((n) => `${meta(n).tag}-${meta(n).platform}`).sort()).toEqual(["v0.1.0-win32", "v0.2.0-linux"]);
  });

  for (const name of NAMES) {
    it(`${name}: today's schemas read every record; every original field is kept and the response and reply lists start empty`, () => {
      const raw = JSON.parse(substituted(name, "state.json", { repo: "/r", scratch: "/s" })) as Record<string, unknown>;
      expect(raw["implementer_responses"]).toBeUndefined();
      expect(raw["reviewer_replies"]).toBeUndefined();
      expect(raw["user_decisions"]).toBeUndefined();
      expect(raw["task_amendments"]).toBeUndefined();
      expect(raw["schema_version"]).toBe(1);
      const parsed = StateRecordSchema.parse(raw) as Record<string, unknown>;
      expect(parsed["implementer_responses"]).toEqual([]);
      // Phase 2.2: the reviewer-reply list is additive as well (P2.2-12).
      expect(parsed["reviewer_replies"]).toEqual([]);
      // Phase 2.3: so are the user's decisions and task amendments (P2.3-16).
      expect(parsed["user_decisions"]).toEqual([]);
      expect(parsed["task_amendments"]).toEqual([]);
      const { implementer_responses: _added, reviewer_replies: _replies, user_decisions: _ud, task_amendments: _ta, user_records_custodian: _urc, run_records_custodian: _rrc, ...rest } = parsed;
      expect(JSON.parse(JSON.stringify(rest))).toEqual(raw);
      // The run holds tracked reviewer items from two accepted rounds: resolved, superseded, open.
      const findings = (parsed as { findings: { status: string }[] }).findings;
      expect(new Set(findings.map((x) => x.status))).toEqual(new Set(["reported_resolved", "superseded", "open", "informational"]));
    });

    it.skipIf(!supported)(`${name}: today's server serves the old run — tokens, responses, history, old results — and leaves its records as they were`, async () => {
      const m = meta(name);
      const f = await makeReviewFixture({ "config/db.env": "DB_PASSWORD=swordfish\n" });
      const repo = await canonicalizePath(f.repo);
      const runDir = join(f.dataHome, "runs", canonicalPathKey(repo), m.run_id);
      for (const rel of m.files) {
        await mkdir(dirname(join(runDir, ...rel.split("/"))), { recursive: true });
        await writeFile(join(runDir, ...rel.split("/")), substituted(name, rel, { repo, scratch: f.scratch }));
      }
      // The fixture's run is as old as the fixture: keep retention away from it.
      await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ retention: { purge_on_startup: false } }));
      const before = JSON.parse(await readFile(join(runDir, "state.json"), "utf8")) as Record<string, unknown>;
      const cfg = await writeServerConfig(f.scratch, { argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } });
      const c = await connect("v2-modern", cfg);
      try {
        const status = sc(await c.call("get_review_status", { run_id: m.run_id }));
        expect(status["state"]).toBe("IDLE");
        const open = status["open_findings"] as { id: string; title: string; response_token: string; discussion_state: string; implementer_response: unknown }[];
        expect(open.map((x) => x.title).sort()).toEqual(["Should add() accept strings?", "overflow for large ints"]);
        for (const x of open) expect(x).toMatchObject({ response_token: expect.stringMatching(/^[0-9a-f]{32}$/), discussion_state: "open", implementer_response: null });
        expect(status["discussion"]).toMatchObject({ open: 2, reviewer_resolved: 1, superseded: 1, responses_recorded: 0 });

        const by = (t: string) => open.find((x) => x.title === t)!;
        const out = sc(
          await c.call("respond_to_review", {
            run_id: m.run_id,
            responses: [
              { finding_id: by("overflow for large ints").id, response_token: by("overflow for large ints").response_token, disposition: "disputed", rationale: "Numbers here are bounded." },
              { finding_id: by("Should add() accept strings?").id, response_token: by("Should add() accept strings?").response_token, disposition: "accepted", rationale: "Numbers only." },
            ],
          }),
        );
        expect((out["recorded"] as { discussion_state: string; answers_round: number }[]).map((r) => [r.discussion_state, r.answers_round])).toEqual([
          ["disputed", 2],
          ["accepted_unresolved", 2],
        ]);
        // Superseded and resolved items of the old run are closed for responses.
        const st0 = StateRecordSchema.parse(before);
        const superseded = st0.findings.find((x) => x.status === "superseded")!;
        expect(errorCode(await c.call("respond_to_review", { run_id: m.run_id, responses: [{ finding_id: superseded.id, response_token: "x", disposition: "disputed", rationale: "x" }] }))).toBe("FINDING_NOT_RESPONDABLE");

        const hist = sc(await c.call("get_review_history", { run_id: m.run_id, responses: {} }));
        const doc = JSON.parse((hist["responses"] as { content: string }).content) as { items: { title: string; responses: unknown[]; response_token: string | null }[] };
        // Every item with a response, and (Phase 2.2) every item that can still be responded to, with its token.
        expect(doc.items.map((x) => x.title).sort()).toEqual(["Should add() accept strings?", "naming nit", "overflow for large ints"]);
        expect(doc.items.filter((x) => x.responses.length > 0).map((x) => x.title).sort()).toEqual(["Should add() accept strings?", "overflow for large ints"]);
        expect(doc.items.every((x) => typeof x.response_token === "string")).toBe(true);
        // The old round-2 result still builds, now with the response context.
        const round2 = st0.reviews.at(-1)!;
        const art = sc(await c.call("get_review_history", { run_id: m.run_id, artifact: { operation_id: round2.operation_id, part: "result" } }));
        const result = JSON.parse((art["artifact"] as { content: string }).content) as { prior_items: { title: string; discussion_state: string; response_before_review: unknown }[] };
        expect(result.prior_items.map((p) => [p.title, p.discussion_state, p.response_before_review]).sort()).toEqual([
          ["Should add() accept strings?", "accepted_unresolved", null],
          ["add() subtracts", "reviewer_resolved", null],
          ["overflow risk", "superseded", null],
        ]);
      } finally {
        await c.close();
      }
      // Every original record is unchanged; only the commit's own bookkeeping and the new list differ.
      const after = JSON.parse(await readFile(join(runDir, "state.json"), "utf8")) as Record<string, unknown>;
      const strip = (s: Record<string, unknown>) => {
        const { revision: _r, updated_at: _u, events: _e, implementer_responses: _i, reviewer_replies: _p, user_decisions: _d, task_amendments: _a, user_records_custodian: _urc, run_records_custodian: _rrc, ...rest } = s;
        return rest;
      };
      expect(strip(after)).toEqual(strip(before));
      expect(after["revision"]).toBe((before["revision"] as number) + 1);
      expect((after["events"] as unknown[]).slice(0, (before["events"] as unknown[]).length)).toEqual(before["events"]);
      expect(after["implementer_responses"]).toHaveLength(2);
      expect(after["reviewer_replies"]).toEqual([]);
      expect(await readFile(join(runDir, "run.json"), "utf8")).toBe(substituted(name, "run.json", { repo, scratch: f.scratch }));
    }, 180_000);
  }
});
