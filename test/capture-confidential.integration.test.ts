// Confidentiality exclusions (plan §9.3, CG4, T4, MR-F): excluded content never reaches
// any model-facing form (exported tree, base/head copies, diff, manifest), and excluded
// NAMES and per-file HASHES never appear model-side either; local records keep them.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync, unlinkSync, renameSync } from "node:fs";
import { join } from "node:path";
import {
  supported,
  gitExe,
  tempDir,
  initRepo,
  writeFiles,
  commitAll,
  git,
  harness,
  capture,
  exportCorpus,
  exportFileList,
  sourceIdentity,
  cleanup,
  type Harness,
} from "./helpers/git-fixture.js";
import { resolveArtifact } from "../src/store/artifacts.js";

describe.skipIf(!supported)("confidential and repository-context exclusions", () => {
  let repo: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    repo = await initRepo(join(await tempDir("arl-conf-"), "repo"));
    h = await harness();
    await writeFiles(repo, {
      ".env": "API_TOKEN=SECRET-ENV-UNCHANGED-1\n",
      "config/app.key": "SECRET-KEY-TRACKED-2\n",
      "deploy/gone.pem": "SECRET-GONE-3\n",
      "creds.key": "SECRET-RENAMED-4\n",
      "old.pem": "SECRET-HISTORICAL-5\n",
      "src/main.ts": "export const main = 1;\n",
      "docs/unchanged.md": "# untouched doc\n",
      "docs/changed.md": "# doc v1\n",
      ".gitignore": "build/\n",
    });
    commitAll(repo, "init with secrets");
    unlinkSync(join(repo, "old.pem"));
    commitAll(repo, "remove historical secret"); // only in history now
    await writeFiles(repo, {
      "config/app.key": "SECRET-KEY-TRACKED-2-CHANGED\n",
      "secrets/id_rsa": "SECRET-UNTRACKED-6\n",
      "certs/server.pem": "SECRET-STAGED-7\n",
      "src/main.ts": "export const main = 2;\n",
      "docs/changed.md": "# doc v2\n",
      ".code-parley/config.json": JSON.stringify({ review: { exclude_paths: ["docs/**"] }, bogus_key: true }),
      "build/gen.ts": "export const generated = true;\n",
      "build/other.ts": "export const other = true;\n",
      "build/.env": "SECRET-CONTEXT-8\n",
    });
    git(repo, ["add", "certs/server.pem"]); // staged secret
    await writeFiles(repo, { "certs/server.pem": "SECRET-STAGED-7-MODIFIED\n" });
    unlinkSync(join(repo, "deploy/gone.pem"));
    renameSync(join(repo, "creds.key"), join(repo, "creds.txt")); // confidential -> permitted name
  });
  afterAll(async () => cleanup(repo, h.dataHome));

  it("withholds confidential content, names and hashes from every model-facing form", async () => {
    const r = await capture(h, repo, { rules: { context_include: ["build/gen.ts", "build/.env"] } });
    const corpus = await exportCorpus(r.exportDir!);
    const manifestText = readFileSync(join(r.exportDir!, "review", "manifest.json"), "utf8");

    // Content: no secret token anywhere in the export (tree, base, head, diff, manifest).
    for (const token of ["SECRET-ENV-UNCHANGED-1", "SECRET-KEY-TRACKED-2", "SECRET-GONE-3", "SECRET-HISTORICAL-5", "SECRET-UNTRACKED-6", "SECRET-STAGED-7", "SECRET-CONTEXT-8"]) {
      expect(corpus, token).not.toContain(token);
    }
    // Names: no confidential path is listed or mentioned.
    const confidentialPaths = ["config/app.key", "deploy/gone.pem", "creds.key", "secrets/id_rsa", "certs/server.pem", "build/.env"];
    for (const p of confidentialPaths) expect(corpus, p).not.toContain(p);
    expect(JSON.parse(manifestText).files.map((f: { path: string }) => f.path)).not.toContain(".env");
    expect(manifestText).not.toMatch(/"\.env"/);
    // Hashes: no confidential per-file hash appears model-side.
    const confidentialHashes = r.record.entries.filter((e) => e.class === "excluded" && e.sha256).map((e) => e.sha256!);
    expect(confidentialHashes.length).toBeGreaterThanOrEqual(5);
    for (const hash of confidentialHashes) expect(corpus).not.toContain(hash);
    // The exclusion patterns themselves are not disclosed either.
    expect(manifestText).not.toContain("**/*.pem");

    // Counts and coverage limitation are visible without names.
    const m = JSON.parse(manifestText);
    expect(m.exclusions.confidential.count).toBe(r.record.entries.filter((e) => e.class === "excluded").length);
    // app.key (modified), id_rsa (added), server.pem (added), gone.pem (deleted), creds.key (deleted)
    expect(m.exclusions.confidential.changed_count).toBe(5);
    const lim = m.limitations.find((l: { code: string }) => l.code === "excluded_changed_file");
    expect(lim).toMatchObject({ count: 5 });
    expect(lim.paths).toBeUndefined();
    expect(readFileSync(join(r.exportDir!, "review", "diff.patch"), "utf8")).toContain("5 changed file(s) excluded by confidentiality rules");

    // The renamed-to-permitted file is reviewed under its new name only.
    expect(exportFileList(r.exportDir!)).toContain("tree/creds.txt");
    expect(m.changes.find((c: { path: string }) => c.path === "creds.txt")?.status).toBe("added");

    // The LOCAL record keeps exact paths and hashes (runs show / CLI reports).
    const local = readFileSync(resolveArtifact(h.runPaths.runDir, r.recordRef), "utf8");
    for (const p of [...confidentialPaths, ".env"]) expect(local).toContain(p);
    for (const hash of confidentialHashes) expect(local).toContain(hash);
    expect(r.record.limitations.find((l) => l.code === "excluded_changed_file")?.paths).toEqual(
      expect.arrayContaining(["config/app.key", "secrets/id_rsa", "certs/server.pem", "deploy/gone.pem", "creds.key"]),
    );
  });

  it("repository exclude_paths drop only UNCHANGED files, as counts; context_include exports ignored files", async () => {
    const r = await capture(h, repo, { rules: { context_include: ["build/gen.ts", "build/.env"] } });
    const files = exportFileList(r.exportDir!);
    const manifestText = readFileSync(join(r.exportDir!, "review", "manifest.json"), "utf8");
    const m = JSON.parse(manifestText);
    expect(files).not.toContain("tree/docs/unchanged.md");
    expect(manifestText).not.toContain("docs/unchanged.md");
    expect(m.exclusions.repository_context.count).toBe(1);
    expect(files).toContain("tree/docs/changed.md"); // never excludes a changed file
    expect(files).toContain("context/build/gen.ts");
    expect(files).not.toContain("context/build/other.ts");
    expect(files.some((f) => f.endsWith("build/.env"))).toBe(false);
    expect(m.limitations.some((l: { code: string; detail: string }) => l.code === "repo_preferences_warning" && l.detail.includes("bogus_key"))).toBe(true);
    // Local record names the repository-context exclusion.
    expect(r.record.entries.find((e) => e.path === "docs/unchanged.md")?.disposition).toBe("excluded_repo_context");
  });

  it("a source-identity read marks what an export withholds as repository context — every match, since it knows no change set — and its identity is unchanged (PR #10 review)", async () => {
    const read = await sourceIdentity(h, repo);
    const at = (p: string) => read.entries.find((e) => e.path === p);
    expect(at("docs/unchanged.md")?.disposition).toBe("excluded_repo_context");
    // An export keeps a changed file; a read cannot tell, so the host views exempt names a capture exported as reviewed changes.
    expect(at("docs/changed.md")?.disposition).toBe("excluded_repo_context");
    expect(at("src/main.ts")?.disposition).toBe("not_exported");
    // Confidential files stay confidential, never "repository context".
    expect(at(".env")?.class).toBe("excluded");
    expect(at(".env")?.disposition).not.toBe("excluded_repo_context");
    // Dispositions are not part of the source identity: the export of the same tree has the same one.
    const exported = await capture(h, repo);
    expect(read.source_id).toBe(exported.record.source_id);
  });

  it("unchanged tracked confidential files are hashed into source_id but never exported", async () => {
    const r1 = await capture(h, repo);
    await writeFiles(repo, { ".env": "API_TOKEN=SECRET-ENV-UNCHANGED-1-ROTATED\n" });
    const r2 = await capture(h, repo);
    expect(r2.record.source_id).not.toBe(r1.record.source_id); // the content change is bound
    expect(r2.manifest!.manifest_digest).not.toBe(""); // still no names
    expect(await exportCorpus(r2.exportDir!)).not.toContain("SECRET-ENV-UNCHANGED-1");
    await writeFiles(repo, { ".env": "API_TOKEN=SECRET-ENV-UNCHANGED-1\n" });
  });
});
