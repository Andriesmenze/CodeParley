import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync, existsSync, writeFileSync, unlinkSync, renameSync, utimesSync, statSync } from "node:fs";
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
  sourceIdentity,
  snapshotTree,
  diffSnapshots,
  exportFileList,
  cleanup,
  type Harness,
} from "./helpers/git-fixture.js";
import { verifyReviewExport } from "../src/capture/export-writer.js";
import { ReviewManifestSchema } from "../src/schemas/capture.js";

describe.skipIf(!supported)("capture: change set, export layout, identities", () => {
  let repo: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    repo = await initRepo(join(await tempDir("arl-basic-"), "repo"));
    const body = Array.from({ length: 30 }, (_, i) => `line ${i} of the original file`).join("\n") + "\n";
    await writeFiles(repo, {
      "src/a.ts": "export const a = 1;\n",
      "src/b.ts": "export const b = 2;\n",
      "src/old-name.ts": body,
      "README.md": "# fixture\n",
      "bin/blob.dat": Buffer.from([0, 1, 2, 3, 0, 255]),
      "ünïcode/文件.txt": "unicode\n",
    });
    commitAll(repo, "init");
    // modify, delete, add, rename (with a small edit), binary modify
    await writeFiles(repo, {
      "src/a.ts": "export const a = 42;\n",
      "src/new.ts": "export const n = 3;\n",
      "bin/blob.dat": Buffer.from([0, 9, 9, 9, 0, 255]),
      "ünïcode/文件.txt": "unicode changed\n",
    });
    unlinkSync(join(repo, "src", "b.ts"));
    renameSync(join(repo, "src", "old-name.ts"), join(repo, "src", "new-name.ts"));
    writeFileSync(join(repo, "src", "new-name.ts"), body.replace("line 3 ", "line THREE "));
    h = await harness();
  });
  afterAll(async () => cleanup(repo, h.dataHome));

  it("captures the uncommitted change set without writing to the repository", async () => {
    const before = snapshotTree(repo);
    const r = await capture(h, repo);
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);

    const byPath = new Map(r.record.changes.map((c) => [c.path, c]));
    expect(byPath.get("src/a.ts")?.status).toBe("modified");
    expect(byPath.get("src/b.ts")?.status).toBe("deleted");
    expect(byPath.get("src/new.ts")?.status).toBe("added");
    expect(byPath.get("src/new-name.ts")?.status).toBe("renamed");
    expect(byPath.get("src/new-name.ts")?.old_path).toBe("src/old-name.ts");
    expect(byPath.has("src/old-name.ts")).toBe(false);
    expect(byPath.get("bin/blob.dat")?.binary).toBe(true);
    expect(byPath.get("ünïcode/文件.txt")?.status).toBe("modified");
    expect(byPath.has("README.md")).toBe(false);
    expect(r.record.stable).toBe(true);

    // Export layout: tree, review/base, review/head, diff, manifest; no .git anywhere.
    const files = exportFileList(r.exportDir!);
    expect(files).toContain("tree/src/a.ts");
    expect(files).toContain("tree/README.md");
    expect(files).toContain("review/base/src/a.ts");
    expect(files).toContain("review/head/src/a.ts");
    expect(files).toContain("review/base/src/b.ts");
    expect(files).not.toContain("review/head/src/b.ts");
    expect(files).toContain("review/head/src/new.ts");
    expect(files).toContain("review/diff.patch");
    expect(files).toContain("review/manifest.json");
    expect(files.some((f) => f.split("/").some((seg) => seg.toLowerCase() === ".git"))).toBe(false);
    expect(readFileSync(join(r.exportDir!, "review", "base", "src", "a.ts"), "utf8")).toBe("export const a = 1;\n");

    const patch = readFileSync(join(r.exportDir!, "review", "diff.patch"), "utf8");
    expect(patch).toContain("diff --git a/src/a.ts b/src/a.ts");
    expect(patch).toContain("-export const a = 1;");
    expect(patch).toContain("+export const a = 42;");
    expect(patch).toContain("rename from src/old-name.ts");
    expect(patch).toContain("rename to src/new-name.ts");
    expect(patch).toMatch(/Binary files a\/bin\/blob\.dat and b\/bin\/blob\.dat differ/);
    expect(patch).not.toMatch(/arl[0-9a-f]{16}[AB]\//);

    // The manifest validates, verifies, and its source_id equals a fresh recomputation.
    const manifest = ReviewManifestSchema.parse(JSON.parse(readFileSync(join(r.exportDir!, "review", "manifest.json"), "utf8")));
    expect(manifest.source_id).toBe(r.record.source_id);
    expect(await verifyReviewExport(r.exportDir!)).toEqual({ ok: true, problems: [] });
    const recomputed = await sourceIdentity(h, repo);
    expect(recomputed.source_id).toBe(r.record.source_id);
    expect(recomputed.stable).toBe(true);
  });

  it("detects tampering with a published export", async () => {
    const r = await capture(h, repo);
    writeFileSync(join(r.exportDir!, "tree", "src", "a.ts"), "tampered\n");
    const v = await verifyReviewExport(r.exportDir!);
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toContain("tree/src/a.ts");
  });

  it("MR-B: a same-length in-place edit with the mtime restored changes source_id", async () => {
    const f = join(repo, "README.md");
    const T = new Date("2026-01-02T03:04:05Z");
    utimesSync(f, T, T); // whole-second mtime so it can be restored exactly
    const st = statSync(f);
    const before = await sourceIdentity(h, repo);
    writeFileSync(f, "# fixturE\n"); // same length
    utimesSync(f, T, T);
    expect(statSync(f).mtimeMs).toBe(st.mtimeMs);
    expect(statSync(f).size).toBe(st.size);
    const after = await sourceIdentity(h, repo);
    expect(after.source_id).not.toBe(before.source_id);
    writeFileSync(f, "# fixture\n");
    utimesSync(f, T, T);
    expect((await sourceIdentity(h, repo)).source_id).toBe(before.source_id);
  });

  it("base_ref target compares against the merge base and flags committed vs uncommitted", async () => {
    const r2 = await initRepo(join(await tempDir("arl-baseref-"), "repo"));
    await writeFiles(r2, { "x.txt": "x1\n", "y.txt": "y1\n" });
    commitAll(r2, "base");
    git(r2, ["branch", "basebranch"]);
    await writeFiles(r2, { "x.txt": "x2\n" });
    commitAll(r2, "second");
    await writeFiles(r2, { "y.txt": "y2\n" });
    const r = await capture(h, r2, { target: { kind: "base_ref", ref: "basebranch" } });
    const byPath = new Map(r.record.changes.map((c) => [c.path, c]));
    expect(byPath.get("x.txt")).toMatchObject({ status: "modified", committed: true, uncommitted: false });
    expect(byPath.get("y.txt")).toMatchObject({ status: "modified", committed: false, uncommitted: true });
    expect(r.record.base.kind).toBe("commit");

    await expect(capture(h, r2, { target: { kind: "base_ref", ref: "--upload-pack=evil" } })).rejects.toSatisfy(
      (e) => (e as { code: string }).code === "INVALID_ARGUMENT",
    );
    await expect(capture(h, r2, { target: { kind: "base_ref", ref: "no-such-branch" } })).rejects.toSatisfy(
      (e) => (e as { code: string }).code === "BASE_UNAVAILABLE",
    );
    await cleanup(r2);
  });

  it("since_baseline compares with the baseline capture (copies for dirty files, blobs for clean)", async () => {
    const r3 = await initRepo(join(await tempDir("arl-since-"), "repo"));
    await writeFiles(r3, { "clean.txt": "c1\n", "dirty.txt": "d0\n", "stay.txt": "s0\n" });
    commitAll(r3, "init");
    await writeFiles(r3, { "dirty.txt": "d1 dirty at baseline\n", "stay.txt": "s1 dirty at baseline\n", "untracked.txt": "u1\n" });
    const b = await capture(h, r3, { kind: "baseline" });
    expect(b.baseline).not.toBeNull();
    const kinds = new Map(b.baseline!.entries.map((e) => [e.path, e.base]));
    expect(kinds.get("clean.txt")).toBe("commit_blob");
    expect(kinds.get("dirty.txt")).toBe("copy");
    expect(kinds.get("untracked.txt")).toBe("copy");
    expect(existsSync(join(b.baselineDir!, "files", "dirty.txt"))).toBe(true);

    await writeFiles(r3, { "clean.txt": "c2\n", "dirty.txt": "d2 after baseline\n" });
    const { loadBaseline } = await import("../src/capture/capture.js");
    const r = await capture(h, r3, { target: { kind: "since_baseline" }, baseline: await loadBaseline(b.baselineDir!) });
    const byPath = new Map(r.record.changes.map((c) => [c.path, c]));
    expect([...byPath.keys()].sort()).toEqual(["clean.txt", "dirty.txt"]);
    expect(readFileSync(join(r.exportDir!, "review", "base", "dirty.txt"), "utf8")).toBe("d1 dirty at baseline\n");
    expect(readFileSync(join(r.exportDir!, "review", "base", "clean.txt"), "utf8")).toBe("c1\n");
    expect(r.record.base).toMatchObject({ kind: "baseline", baseline_capture_id: b.record.capture_id });
    await cleanup(r3);
  });

  it("SHA-256 repositories capture with 64-hex object ids", async () => {
    const r4 = await initRepo(join(await tempDir("arl-sha256-"), "repo"), { objectFormat: "sha256" });
    await writeFiles(r4, { "a.txt": "one\n", "b.txt": "two\n" });
    commitAll(r4, "init");
    await writeFiles(r4, { "a.txt": "uno\n" });
    unlinkSync(join(r4, "b.txt"));
    const r = await capture(h, r4);
    expect(r.record.support.object_format).toBe("sha256");
    expect(r.record.repository.head_commit).toMatch(/^[0-9a-f]{64}$/);
    const byPath = new Map(r.record.changes.map((c) => [c.path, c]));
    expect(byPath.get("a.txt")?.status).toBe("modified");
    expect(byPath.get("b.txt")?.status).toBe("deleted");
    expect(readFileSync(join(r.exportDir!, "review", "base", "b.txt"), "utf8")).toBe("two\n");
    expect(r.record.changes.every((c) => !c.base?.oid || /^[0-9a-f]{64}$/.test(c.base.oid))).toBe(true);
    await cleanup(r4);
  });
});
