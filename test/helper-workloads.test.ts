// P3.4C-5 Increment 1 (Amendment A §A.7): the custodian helper's workloads, run as the real built entry
// (dist/helper/main.js) in a child process, with this test playing the custodian's side of the frames: it validates each
// streamed file, writes the staging itself, publishes it read-only to the workload, and checks the result. The capture
// is the SAME sanitizing capture as the attended one — the same manifest and export digests for the same repository
// state — and the workload writes nothing (its home and temp stay empty, the repository is unchanged). The `derive`
// workload measures what the engine measures — the source identity, the root commit, each check's freshness inputs and
// the stat of the executable the session claimed, with the check-spec id they give (P3.4C-5 Increment 3); the protected
// derivation it runs over a snapshot is tested in protected-derivation.test.ts.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exportDigestOf } from "../src/capture/export-writer.js";
import { computeCheckSpecId, computeFreshnessDigest, hashFreshnessInputs } from "../src/checks/identity.js";
import { checkDefinitionDigest, normalizeCheckDefinition } from "../src/checks/project-config.js";
import { resolveCommand } from "../src/process/command.js";
import { buildSrc } from "./helpers/build-src.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { capture, cleanup, commitAll, gitExe, harness, initRepo, snapshotTree, sourceIdentity, supported, tempDir, writeFiles, type Harness } from "./helpers/git-fixture.js";

const repoRootDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const RULES = { exclude_globs: [".env", "secrets/**"], context_include: [], max_file_bytes: 1_000_000, max_export_bytes: 20_000_000, max_diff_bytes: 2_000_000 };
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

interface Frame {
  h: Record<string, unknown>;
  body: Buffer;
}

/** Run the helper entry for one request, answering as the custodian: write streamed files into `staging`, publish it. */
async function runHelper(entry: string, kind: string, request: unknown, staging: string | null, env: NodeJS.ProcessEnv, cwd: string) {
  const child = spawn(process.execPath, [entry, kind], { cwd, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const frames: Frame[] = [];
  const written: { rel: string; size: number; sha256: string }[] = [];
  let stderr = "";
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
  let buf = Buffer.alloc(0);
  child.stdout.on("data", (d: Buffer) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 4) return;
      const hl = buf.readUInt32LE(0);
      if (buf.length < 8 + hl) return;
      const bl = buf.readUInt32LE(4 + hl);
      if (buf.length < 8 + hl + bl) return;
      const h = JSON.parse(buf.subarray(4, 4 + hl).toString("utf8")) as Record<string, unknown>;
      const body = Buffer.from(buf.subarray(8 + hl, 8 + hl + bl));
      buf = buf.subarray(8 + hl + bl);
      frames.push({ h, body });
      if (h["t"] === "file") {
        // The custodian's checks: the claimed size and SHA-256 are the bytes'; the custodian writes the file.
        expect(h["size"]).toBe(body.length);
        expect(h["sha256"]).toBe(sha(body));
        const rel = `${String(h["area"])}/${String(h["path"])}`;
        const abs = join(staging!, ...rel.split("/"));
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, body, { flag: "wx" });
        written.push({ rel, size: body.length, sha256: sha(body) });
      } else if (h["t"] === "stage_complete") {
        child.stdin.write(JSON.stringify({ t: "staged", dir: staging }) + "\n");
      }
    }
  });
  child.stdin.write(JSON.stringify(request) + "\n");
  const code = await new Promise<number | null>((resolve) => child.on("close", resolve));
  const result = frames.find((f) => f.h["t"] === "result");
  const failed = frames.find((f) => f.h["t"] === "failed");
  return { code, frames, written, stderr, result: result ? (JSON.parse(result.body.toString("utf8")) as Record<string, unknown>) : null, failed: failed?.h ?? null };
}

describe.skipIf(!supported)("the custodian helper's workloads (P3.4C-5 Increment 1, A.7)", () => {
  let dist = "";
  let ownBuild: string | null = null;
  let h: Harness;
  let repo = "";
  let cfg = "";
  const scratchDirs: string[] = [];

  beforeAll(async () => {
    dist = sharedCompiledSrc() ?? "";
    if (!dist) {
      ownBuild = join(repoRootDir, ".tmp-test-dist", `helper-${randomBytes(4).toString("hex")}`);
      buildSrc(repoRootDir, ownBuild);
      dist = ownBuild;
    }
    h = await harness();
    repo = await tempDir("cp-helper-repo-");
    await initRepo(repo);
    await writeFiles(repo, { "src/a.ts": "export const a = 1;\n", "README.md": "# fixture\n", "package.json": '{"name":"fixture"}\n', ".env": "TOKEN=top-secret\n" });
    commitAll(repo, "base");
    await writeFiles(repo, { "src/a.ts": "export const a = 2;\n", "src/b.ts": "export const b = 1;\n", ".env": "TOKEN=changed-secret\n" });
    cfg = await tempDir("cp-helper-cfg-");
    await mkdir(join(cfg, "home"));
    await mkdir(join(cfg, "hooks"));
    writeFileSync(join(cfg, "gitconfig"), "");
    scratchDirs.push(h.dataHome, repo, cfg);
  }, 240_000);

  afterAll(async () => {
    await cleanup(...scratchDirs);
    if (ownBuild) await cleanup(ownBuild);
  });

  async function launch() {
    return {
      node: process.execPath,
      nodeSha256: "0".repeat(64),
      entry: join(dist, "helper", "main.js"),
      entrySha256: "0".repeat(64),
      git: await gitExe(),
      home: join(cfg, "home"),
      hooks: join(cfg, "hooks"),
      gitconfig: join(cfg, "gitconfig"),
      repository: repo,
      safeDirectory: repo.replace(/\\/g, "/"),
      maxFrameBody: 64 * 1024 * 1024,
    };
  }

  // The helper service's environment: home and temp are the custodian's per-request directory.
  const helperEnv = (): NodeJS.ProcessEnv => {
    const keep = ["SystemRoot", "SystemDrive", "windir", "PATH", "PATHEXT"];
    const env: NodeJS.ProcessEnv = {};
    for (const k of Object.keys(process.env)) if (keep.some((x) => x.toLowerCase() === k.toLowerCase())) env[k] = process.env[k];
    for (const k of ["USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"]) env[k] = join(cfg, "home");
    return env;
  };

  it("captures the SAME export as the attended capture, streamed: identical manifest and export digests, writing nothing", async () => {
    const operationId = `cap-${randomBytes(6).toString("hex")}`;
    const attended = await capture(h, repo, { operationId, rules: RULES });
    const before = snapshotTree(repo);
    const staging = await tempDir("cp-helper-staging-");
    scratchDirs.push(staging);

    const r = await runHelper(join(dist, "helper", "main.js"), "capture", { launch: await launch(), workload: { operationId, target: { kind: "uncommitted" }, rules: RULES } }, staging, helperEnv(), join(cfg, "home"));
    expect(r.failed, r.stderr).toBeNull();
    expect(r.code).toBe(0);
    const res = r.result!;
    // Parity with the attended capture of the same state.
    expect(res["sourceId"]).toBe(attended.record.source_id);
    expect(res["manifestDigest"]).toBe(attended.manifest!.manifest_digest);
    expect(res["exportDigest"]).toBe(attended.record.export!.export_digest);
    // What the custodian wrote is exactly what the helper's digest covers.
    expect(exportDigestOf(r.written)).toBe(res["exportDigest"]);
    expect(r.written.map((w) => w.rel)).toContain("review/manifest.json");
    expect(r.written.map((w) => w.rel)).toContain("review/diff.patch");
    // The confidential file never left the helper: no frame names it, no byte of it is in any frame.
    expect(r.written.some((w) => w.rel.endsWith(".env"))).toBe(false);
    expect(r.frames.some((f) => f.body.includes(Buffer.from("changed-secret")))).toBe(false);
    // The prepared diff was computed over the custodian's staging (published after the files, before the diff).
    const order = r.frames.map((f) => (f.h["t"] === "file" ? `${String(f.h["area"])}/${String(f.h["path"])}` : String(f.h["t"])));
    expect(order.indexOf("stage_complete")).toBeLessThan(order.indexOf("review/diff.patch"));
    expect(order.at(-1)).toBe("result");
    // The workload wrote nothing: its home/temp stays empty and the repository is unchanged.
    expect(readdirSync(join(cfg, "home"))).toEqual([]);
    expect(readdirSync(join(cfg, "hooks"))).toEqual([]);
    expect(snapshotTree(repo)).toEqual(before);
  });

  it("measures the source, each check's freshness inputs and the claimed executable's stat the engine's way (a measurement only: no snapshot)", async () => {
    const src = await sourceIdentity(h, repo, RULES);
    const fresh = computeFreshnessDigest(await hashFreshnessInputs(repo, ["package.json"]));
    const n = normalizeCheckDefinition({ argv: ["node", "--version"], cwd: ".", env: {}, env_passthrough: [], timeout_seconds: 60, freshness_inputs: ["package.json"] });
    if (!n.ok) throw new Error(n.problems.join("; "));
    const digest = checkDefinitionDigest("test", n.def);
    const resolved = resolveCommand(process.execPath, { relativeBase: repo, pathValue: "" });
    if (!resolved.ok) throw new Error(resolved.reason);
    const checks = [
      { name: "test", definition: n.def, definitionDigest: digest, executable: process.execPath },
      { name: "unresolved", definition: n.def, definitionDigest: digest, executable: null },
    ];
    const r = await runHelper(join(dist, "helper", "main.js"), "derive", { launch: await launch(), workload: { rules: RULES, checks, snapshot: null } }, null, helperEnv(), join(cfg, "home"));
    expect(r.failed, r.stderr).toBeNull();
    const res = r.result! as { measured: { sourceId: string; stable: boolean; rootCommit: string | null; checks: { name: string; freshnessDigest: string; checkSpecId: string | null; executable: unknown; problem: string | null }[] }; derivation: unknown; scope: { authoritative: boolean } };
    expect(res.measured.sourceId).toBe(src.source_id);
    expect(res.measured.stable).toBe(true);
    expect(res.measured.rootCommit).toMatch(/^[0-9a-f]{40}/);
    expect(res.measured.checks[0]).toMatchObject({ name: "test", freshnessDigest: fresh, problem: null, checkSpecId: computeCheckSpecId({ name: "test", def: n.def, definitionDigest: digest, resolved: resolved.command }) });
    expect(res.measured.checks[1]).toMatchObject({ name: "unresolved", freshnessDigest: fresh, checkSpecId: null, executable: null, problem: "no_executable_claim" });
    expect(res.derivation).toBeNull();
    expect(res.scope.authoritative).toBe(false);
    expect(readdirSync(join(cfg, "home"))).toEqual([]);
  });

  it("refuses a request with an unknown field, and a wildcard safe.directory, with a failed frame and a non-zero exit", async () => {
    const extra = await runHelper(join(dist, "helper", "main.js"), "derive", { launch: await launch(), workload: {}, role: "operator" }, null, helperEnv(), join(cfg, "home"));
    expect(extra.code).not.toBe(0);
    expect(extra.failed?.["t"]).toBe("failed");
    const star = await runHelper(join(dist, "helper", "main.js"), "capture", { launch: { ...(await launch()), safeDirectory: "*" }, workload: { operationId: "cap-x", target: { kind: "uncommitted" }, rules: RULES } }, await tempDir("cp-helper-st-"), helperEnv(), join(cfg, "home"));
    expect(star.code).not.toBe(0);
    expect(star.failed?.["t"]).toBe("failed");
    // A wildcard inside a longer value passes the request schema; git's protected configuration refuses it.
    const inner = await runHelper(join(dist, "helper", "main.js"), "capture", { launch: { ...(await launch()), safeDirectory: `${repo.replace(/\\/g, "/")}/*` }, workload: { operationId: "cap-y", target: { kind: "uncommitted" }, rules: RULES } }, await tempDir("cp-helper-st-"), helperEnv(), join(cfg, "home"));
    expect(inner.code).not.toBe(0);
    expect(String(inner.failed?.["detail"])).toMatch(/exactly one validated repository/);
  });
});
