// Phase 2.3 compatibility (plan §1.16, P2.3-16): run stores written by earlier versions — v0.1.0
// (Windows, M1), v0.2.0 (Linux), the Phase 2.1 code (b21ef09, Linux) and the Phase 2.2 code
// (07941a0, Windows: reviewer replies and delivery records) — are read with today's schemas (no
// user records: empty lists), served with a derived completion, and accept the local operator's
// decisions and amendments. Nothing an earlier version recorded is rewritten, and the next review
// presents the amendment.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { StateRecordSchema } from "../src/schemas/run-state.js";
import { canonicalPathKey } from "../src/store/paths.js";
import { canonicalizePath } from "../src/workspace/paths.js";
import { runCli, type CliIo } from "../src/cli/cli.js";
import { lastExec, makeReviewFixture, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { compileServer, connect, removeCompiledServer, sc, writeServerConfig } from "./helpers/mcp-harness.js";
import { supported } from "./helpers/git-fixture.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "compat");
const NAMES = readdirSync(FIXTURES).filter((n) => /^(v\d|p\d)/.test(n));

interface FixtureMeta {
  tag: string;
  platform: string;
  run_id: string;
  files: string[];
}

const meta = (name: string): FixtureMeta => JSON.parse(readFileSync(join(FIXTURES, name, "fixture.json"), "utf8")) as FixtureMeta;

function substituted(name: string, rel: string, values: { repo: string; scratch: string }): string {
  const esc = (p: string) => JSON.stringify(p).slice(1, -1);
  return readFileSync(join(FIXTURES, name, "run", ...rel.split("/")), "utf8").split("<REPO>").join(esc(values.repo)).split("<SCRATCH>").join(esc(values.scratch)).split("<NODE>").join(esc(process.execPath));
}

function operator(answer: string): CliIo & { errors: string[] } {
  const errors: string[] = [];
  return { errors, out: () => undefined, err: (l) => errors.push(l), prompt: async () => answer, interactive: true, env: process.env, cwd: process.cwd() };
}

interface Thread {
  thread_id: string;
  items: { id: string; title_excerpt: string; status: string }[];
  user_decision?: { kind: string; status: string; assurance: string };
  completion_category?: string;
}

afterAll(removeCompiledServer);
beforeAll(async () => {
  if (supported) await compileServer();
}, 120_000);

describe("compatibility of earlier stores with the user layer (Phase 2.3)", () => {
  it("fixtures exist for v0.1.0, v0.2.0, the Phase 2.1 code and the Phase 2.2 code", () => {
    expect(NAMES.map((n) => `${meta(n).tag}-${meta(n).platform}`).sort()).toEqual(["p2.1-linux", "p2.2-win32", "v0.1.0-win32", "v0.2.0-linux"]);
  });

  for (const name of NAMES) {
    it(`${name}: today's schemas read every record; the user lists start empty; every original field is kept`, () => {
      const raw = JSON.parse(substituted(name, "state.json", { repo: "/r", scratch: "/s" })) as Record<string, unknown>;
      expect(raw["user_decisions"]).toBeUndefined();
      expect(raw["task_amendments"]).toBeUndefined();
      const parsed = StateRecordSchema.parse(raw);
      expect(parsed.user_decisions).toEqual([]);
      expect(parsed.task_amendments).toEqual([]);
      const { user_decisions: _d, task_amendments: _a, ...rest } = parsed as unknown as Record<string, unknown>;
      const added = new Set(Object.keys(rest).filter((k) => !(k in raw)));
      for (const k of added) expect(["implementer_responses", "reviewer_replies", "user_records_custodian", "run_records_custodian"]).toContain(k);
      for (const k of added) delete (rest as Record<string, unknown>)[k];
      expect(JSON.parse(JSON.stringify(rest))).toEqual(raw);
      // No earlier version's review presented an amendment (true: none existed).
      expect(parsed.reviews.every((r) => r.amendments === undefined)).toBe(true);
    });

    it.skipIf(!supported)(`${name}: served with a derived completion; the operator decides and amends; nothing earlier is rewritten; the next review presents the amendment`, async () => {
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
      const c = await connect("v2-legacy", cfg);
      try {
        let status = sc(await c.call("get_review_status", { run_id: m.run_id }));
        expect((status["completion"] as { ready: boolean }).ready).toBe(false); // open items remain
        expect(status["user"]).toMatchObject({ decisions: { recorded: 0 }, amendments: { recorded: 0 } });
        const threads = () => (status["discussion"] as { threads: Thread[] }).threads;
        const of = (title: string) => threads().find((t) => t.items.some((i) => i.title_excerpt === title))!;
        expect(threads().every((t) => t.user_decision === undefined)).toBe(true);
        const target = of("overflow for large ints").items.find((i) => i.title_excerpt === "overflow for large ints")!;

        // The local operator decides and amends on the old run.
        expect(await runCli(["decide", m.run_id, target.id, "waive", "--home", f.dataHome, "--git", f.git], operator("waive"))).toBe(0);
        expect(await runCli(["amend", m.run_id, "clarification", "--text", `COMPAT-AMENDMENT for ${name}`, "--thread", target.id, "--home", f.dataHome, "--git", f.git], operator("amend"))).toBe(0);
        status = sc(await c.call("get_review_status", { run_id: m.run_id }));
        expect(of("overflow for large ints")).toMatchObject({ completion_category: "settled_by_waiver", user_decision: { kind: "waive", status: "applies", assurance: "local_operator" } });
        expect(status["user"]).toMatchObject({ amendments: { recorded: 1, not_seen_by_reviewer: 1 } });

        // The next review the host requests presents the amendment.
        await setScenario(f, okScenario(output({ prior_findings: [{ id: "PF-1", assessment: "still_present", superseded_by_index: null, note: "" }, { id: "PF-2", assessment: "still_present", superseded_by_index: null, note: "" }] })));
        const r = sc(await c.call("review_with_codex", { run_id: m.run_id, wait_seconds: 45 }));
        expect(r["accepted"]).toBe(true);
        expect(r["amendments"]).toMatchObject({ presented: [{ id: "A-1" }] });
        expect((await lastExec(f)).prompt).toContain(`COMPAT-AMENDMENT for ${name}`);
      } finally {
        await c.close();
      }
      // Nothing earlier versions recorded was rewritten.
      const after = StateRecordSchema.parse(JSON.parse(await readFile(join(runDir, "state.json"), "utf8")));
      expect(after.implementer_responses).toEqual(before.implementer_responses);
      expect(after.reviewer_replies).toEqual(before.reviewer_replies);
      expect(after.reviews.slice(0, before.reviews.length)).toEqual(before.reviews);
      expect(after.isolation_incidents).toEqual(before.isolation_incidents);
      expect(after.check_executions).toEqual(before.check_executions);
      for (const it of before.findings) {
        const now = after.findings.find((x) => x.id === it.id)!;
        expect({ ...now, assessments: now.assessments.slice(0, it.assessments.length) }).toEqual(it);
      }
      expect(after.user_decisions).toHaveLength(1);
      expect(after.task_amendments).toHaveLength(1);
      expect(await readFile(join(runDir, "run.json"), "utf8")).toBe(substituted(name, "run.json", { repo, scratch: f.scratch }));
    }, 180_000);
  }
});
