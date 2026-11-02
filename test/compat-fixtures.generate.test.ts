// OPT-IN GENERATOR (Phase 2.1, plan §1.14): run-store records written by a RELEASED version, for
// the compatibility tests (responses-compat.integration.test.ts). Skipped unless
// CODEPARLEY_GEN_COMPAT names a release tag (v0.1.0, v0.2.0) and CODEPARLEY_GEN_COMPAT_OUT a
// directory. It compiles that tag's src/ with this checkout's toolchain (the dependencies are
// identical), starts that release's own TEST-ONLY server over stdio with the scripted fake
// Codex, and drives a realistic run through MCP: checks, a review with an established defect, a
// serious risk, a style note and a blocking question; a fix; a second review that reports one
// item resolved, supersedes one and keeps one open. The run's records (run.json, state.json, the
// capture records and review artifacts they reference, the export manifests) are written to the
// output directory with every local path replaced by a placeholder (<REPO>, <SCRATCH>, <NODE>).
//
// Phase 2.2: the ref may be any commit (CODEPARLEY_GEN_COMPAT_NAME names the fixture, default the
// ref), the scripted reviewer output keeps that version's schema (output schema v2: no
// discussion fields), and a version that has respond_to_review (Phase 2.1) also records the
// implementer's responses: after round 1 on every open item, after round 2 a dispute of the
// superseding finding (never sent to Codex by that version). Their disclosure records are copied.
//
// Phase 2.3: a version with the discussion (Phase 2.2: its review_with_codex output schema has
// `discussion`) gets reviewer output in its own schema (v3) and a structured reply in round 2 to the
// dispute recorded after round 1 — so the store holds reviewer replies, delivery records and the
// review's discussion artifact (copied).
//
//   CODEPARLEY_GEN_COMPAT=v0.1.0 CODEPARLEY_GEN_COMPAT_OUT=<dir> npx vitest run test/compat-fixtures.generate.test.ts
//   CODEPARLEY_GEN_COMPAT=b21ef09 CODEPARLEY_GEN_COMPAT_NAME=p2.1 CODEPARLEY_GEN_COMPAT_OUT=<dir> npx vitest run test/compat-fixtures.generate.test.ts
//   CODEPARLEY_GEN_COMPAT=07941a0 CODEPARLEY_GEN_COMPAT_NAME=p2.2 CODEPARLEY_GEN_COMPAT_OUT=<dir> npx vitest run test/compat-fixtures.generate.test.ts

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { approve } from "./helpers/checks-fixture.js";
import { defect, makeReviewFixture, okScenario, output, setScenario } from "./helpers/review-fixture.js";
import { repoRootDir } from "./helpers/mcp-harness.js";

const TAG = process.env["CODEPARLEY_GEN_COMPAT"] ?? "";
const OUT = process.env["CODEPARLEY_GEN_COMPAT_OUT"] ?? "";
const NAME = process.env["CODEPARLEY_GEN_COMPAT_NAME"] ?? TAG;

/** Reviewer output in the generating version's schema (v2: without Phase 2.2's discussion fields). */
function legacy<T>(out: T): T {
  const o = JSON.parse(JSON.stringify(out)) as { exec?: { final?: { discussion_replies?: unknown; findings?: { restates_prior_id?: unknown }[] } } };
  const fin = o.exec?.final;
  if (fin) {
    delete fin.discussion_replies;
    for (const x of fin.findings ?? []) delete x.restates_prior_id;
  }
  return o as T;
}

function git(args: string[]): string {
  const r = spawnSync("git", ["-C", repoRootDir, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}

/** The tag's src/ and tsconfig, compiled into .tmp-test-dist (resolves this checkout's node_modules). */
async function buildTag(tag: string): Promise<string> {
  const dir = join(repoRootDir, ".tmp-test-dist", `compat-${tag}`);
  await rm(dir, { recursive: true, force: true });
  for (const file of git(["ls-tree", "-r", "--name-only", tag, "src"]).split("\n").filter(Boolean)) {
    await mkdir(dirname(join(dir, file)), { recursive: true });
    await writeFile(join(dir, file), git(["show", `${tag}:${file}`]));
  }
  await writeFile(join(dir, "tsconfig.json"), git(["show", `${tag}:tsconfig.json`]));
  // That version's own reviewer prompt: the template is looked up in the directories above the
  // build, which would otherwise find this checkout's newer one.
  await mkdir(join(dir, "prompts"), { recursive: true });
  await writeFile(join(dir, "prompts", "codex-reviewer.md"), git(["show", `${tag}:prompts/codex-reviewer.md`]));
  const tsc = join(repoRootDir, "node_modules", "typescript", "bin", "tsc");
  const r = spawnSync(process.execPath, [tsc, "-p", join(dir, "tsconfig.json"), "--outDir", join(dir, "dist"), "--sourceMap", "false", "--declaration", "false"], { encoding: "utf8", windowsHide: true });
  if (r.status !== 0) throw new Error(`tsc failed for ${tag}: ${r.stdout}\n${r.stderr}`);
  // That release's own TEST-ONLY server entry (the template literal of its test-server-source.ts).
  const src = git(["show", `${tag}:test/helpers/test-server-source.ts`]);
  const entry = src.slice(src.indexOf("`") + 1, src.lastIndexOf("`"));
  await writeFile(join(dir, "dist", "test-server.mjs"), entry);
  return join(dir, "dist");
}

async function call(client: Client, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const r = (await client.callTool({ name, arguments: args }, { timeout: 120_000 })) as { structuredContent?: Record<string, unknown>; isError?: boolean };
  if (r.isError || !r.structuredContent) throw new Error(`${name} failed: ${JSON.stringify(r).slice(0, 800)}`);
  return r.structuredContent;
}

/** Replace every spelling of a local path (raw, JSON-escaped, forward slashes) by a placeholder. */
function scrub(text: string, paths: [string, string][]): string {
  let out = text;
  for (const [p, label] of paths) {
    // Longest first: a path inside a JSON string that is itself JSON-encoded is escaped twice.
    for (const v of new Set([p.replace(/\\/g, "\\\\\\\\"), p.replace(/\\/g, "\\\\"), p, p.replace(/\\/g, "/")])) out = out.split(v).join(label);
  }
  return out;
}

describe.skipIf(!TAG || !OUT)(`compatibility fixture generator (${TAG || "off"})`, () => {
  it(`writes a run store produced by ${TAG}`, async () => {
    const dist = await buildTag(TAG);
    const f = await makeReviewFixture({ "config/db.env": "DB_PASSWORD=swordfish\n" });
    await approve(f, { checks: { unit: { argv: [process.execPath, "scripts/pass.js"] } }, profiles: { default: ["unit"] }, required_profiles: ["default"] });
    const cfgPath = join(f.scratch, "server.json");
    await writeFile(cfgPath, JSON.stringify({ argv: ["--home", f.dataHome, "--allowed-root", f.repo, "--codex", f.codexExe, "--git", f.git], fake: { script: f.fakeScript } }));
    const client = new Client({ name: "compat-generator", version: "1.0.0" }, { capabilities: {}, versionNegotiation: { mode: "legacy" } });
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [join(dist, "test-server.mjs")], env: { ...(process.env as Record<string, string>), CODEPARLEY_TEST_SERVER_CONFIG: cfgPath }, cwd: dist, stderr: "pipe" }));
    try {
      const tools = (await client.listTools()).tools;
      const hasResponses = tools.some((t) => t.name === "respond_to_review");
      // Phase 2.2 and later: reviewer output schema v3 (discussion replies, restatements).
      const hasDiscussion = JSON.stringify(tools.find((t) => t.name === "review_with_codex")?.outputSchema ?? {}).includes('"discussion"');
      const own = <T>(x: T): T => (hasDiscussion ? x : legacy(x));
      await setScenario(
        f,
        own(
          okScenario(
            output({
              findings: [defect(), defect({ title: "overflow risk", severity: "high", claim_type: "risk", evidence: [] }), defect({ title: "naming nit", claim_type: "suggestion", category: "style", severity: "low", evidence: [] })],
              questions: [{ question: "Should add() accept strings?", related_finding_index: 0, blocking: true }],
            }),
          ),
        ),
      );
      const created = await call(client, "create_review_run", { task_envelope: { goal: "Fix add() (compatibility fixture)" }, repository_root: f.repo, wait_seconds: 40 });
      const runId = created["run_id"] as string;
      expect((await call(client, "run_checks", { run_id: runId, wait_seconds: 45 }))["status"]).toBe("passed");
      const round1 = await call(client, "review_with_codex", { run_id: runId, wait_seconds: 45 });
      expect(round1["accepted"], JSON.stringify({ status: round1["status"], failure: round1["failure"], summary: round1["summary"] })).toBe(true);
      // Phase 2.1 and later: the implementer's responses to round 1 (that version never sends them to Codex).
      const openNow = async () => (await call(client, "get_review_status", { run_id: runId }))["open_findings"] as { id: string; title: string; response_token: string }[];
      if (hasResponses) {
        const open = await openNow();
        const by = (t: string) => open.find((x) => x.title === t)!;
        await call(client, "respond_to_review", {
          run_id: runId,
          responses: [
            { finding_id: by("add() subtracts").id, response_token: by("add() subtracts").response_token, disposition: "accepted" },
            { finding_id: by("overflow risk").id, response_token: by("overflow risk").response_token, disposition: "disputed", rationale: "P21-DISPUTE inputs are bounded by the caller" },
            { finding_id: by("Should add() accept strings?").id, response_token: by("Should add() accept strings?").response_token, disposition: "deferred", rationale: "P21-DEFERRAL decided in the next change" },
          ],
        });
      }
      // The fix, then round 2: add() resolved, the risk superseded, the question still open.
      await writeFile(join(f.repo, "src", "math.js"), "export function add(a, b) {\n  return a + b;\n}\n");
      await setScenario(
        f,
        own(
          okScenario(
            output({
              findings: [defect({ title: "overflow for large ints", severity: "critical", evidence: [{ kind: "code_reference", detail: "a + b", path: "src/math.js", start_line: 2, end_line: 2 }] })],
              prior_findings: [
                { id: "PF-1", assessment: "apparently_resolved", superseded_by_index: null, note: "now adds" },
                { id: "PF-2", assessment: "superseded", superseded_by_index: 0, note: "more precise" },
                { id: "PF-3", assessment: "still_present", superseded_by_index: null, note: "" },
              ],
              // Phase 2.2: the reviewer's structured reply to the dispute presented with awaiting_reply.
              ...(hasDiscussion ? { discussion_replies: [{ id: "PF-2", stance: "maintain" as const, reply: "P22-REPLY callers outside this module are not bounded", new_information: "not_applicable" as const }] } : {}),
            }),
          ),
        ),
      );
      expect((await call(client, "review_with_codex", { run_id: runId, wait_seconds: 45 }))["accepted"]).toBe(true);
      if (hasResponses) {
        const succ = (await openNow()).find((x) => x.title === "overflow for large ints")!;
        await call(client, "respond_to_review", { run_id: runId, responses: [{ finding_id: succ.id, response_token: succ.response_token, disposition: "disputed", rationale: "P21-SUCCESSOR-DISPUTE numbers stay below 2^53 here", references: [{ path: "src/math.js", start_line: 2 }] }] });
      }

      // Copy the run's records: run.json, state.json, and the artifacts its state references.
      const key = (await readdir(join(f.dataHome, "runs"))).find((k) => k !== ".trash")!;
      const runDir = join(f.dataHome, "runs", key, runId);
      const state = JSON.parse(await readFile(join(runDir, "state.json"), "utf8")) as { reviews: { artifacts: Record<string, string>; export_ref: string }[]; operations: { outcome?: { capture_ref?: string } }[]; implementer_responses?: { disclosure_ref?: string | null }[] };
      const files = new Set(["run.json", "state.json"]);
      for (const r of state.reviews) {
        for (const k of ["capture", "items", "output", "discussion"]) if (r.artifacts[k]) files.add(r.artifacts[k]!);
        files.add(`${r.export_ref}/review/manifest.json`);
      }
      for (const op of state.operations) if (op.outcome?.capture_ref) files.add(op.outcome.capture_ref);
      for (const r of state.implementer_responses ?? []) if (r.disclosure_ref) files.add(r.disclosure_ref);
      const out = join(OUT, `${NAME}-${process.platform}`);
      await rm(out, { recursive: true, force: true });
      const paths: [string, string][] = [
        [f.repo, "<REPO>"],
        [f.scratch, "<SCRATCH>"],
        [process.execPath, "<NODE>"],
      ];
      for (const rel of files) {
        const src = join(runDir, ...rel.split("/"));
        if (!existsSync(src)) throw new Error(`referenced record missing: ${rel}`);
        await mkdir(dirname(join(out, "run", ...rel.split("/"))), { recursive: true });
        await writeFile(join(out, "run", ...rel.split("/")), scrub(await readFile(src, "utf8"), paths));
      }
      await writeFile(join(out, "fixture.json"), `${JSON.stringify({ tag: NAME, ref: TAG, platform: process.platform, node: process.version, generated_at: new Date().toISOString(), run_id: runId, files: [...files].sort() }, null, 2)}\n`);
    } finally {
      await client.close();
    }
  }, 300_000);
});
