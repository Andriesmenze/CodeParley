// Repository support matrix (plan §9.7, LV-WIN-GIT): unsupported states are refused with
// explicit errors; supported unusual states are captured and reported.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { existsSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalizePath } from "../src/workspace/paths.js";
import {
  supported,
  win,
  gitExe,
  tempDir,
  initRepo,
  writeFiles,
  commitAll,
  git,
  harness,
  capture,
  exportFileList,
  snapshotTree,
  diffSnapshots,
  cleanup,
  shPath,
  type Harness,
} from "./helpers/git-fixture.js";

const code = (c: string) => (e: unknown) => (e as { code?: string }).code === c;

describe.skipIf(!supported)("repository support matrix", () => {
  let base: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-states-");
    h = await harness();
  });
  afterAll(async () => cleanup(base, h.dataHome));

  async function simpleRepo(name: string): Promise<string> {
    const r = await initRepo(join(base, name));
    await writeFiles(r, { "a.txt": "a\n", "b.txt": "b\n", "dir/c.txt": "c\n" });
    commitAll(r, "init");
    return r;
  }

  it("refuses sparse checkout, unmerged entries and core.worktree", async () => {
    const sparse = await simpleRepo("sparse");
    git(sparse, ["sparse-checkout", "set", "--no-cone", "a.txt"]);
    await expect(capture(h, sparse)).rejects.toSatisfy(code("UNSUPPORTED_REPO_STATE"));

    const conflict = await simpleRepo("conflict");
    git(conflict, ["checkout", "-q", "-b", "other"]);
    await writeFiles(conflict, { "a.txt": "other\n" });
    commitAll(conflict, "other");
    git(conflict, ["checkout", "-q", "main"]);
    await writeFiles(conflict, { "a.txt": "main\n" });
    commitAll(conflict, "main");
    git(conflict, ["merge", "other"], { allowFail: true });
    await expect(capture(h, conflict)).rejects.toSatisfy(code("UNSUPPORTED_REPO_STATE"));

    const wt = await simpleRepo("coreworktree");
    git(wt, ["config", "core.worktree", shPath(wt)]);
    await expect(capture(h, wt)).rejects.toSatisfy(code("UNSUPPORTED_REPO_STATE"));
  });

  it("refuses a bare repository", async () => {
    const bare = join(base, "bare.git");
    git(base, ["init", "-q", "--bare", bare]);
    await expect(capture(h, await canonicalizePath(bare))).rejects.toSatisfy(code("NOT_A_GIT_WORKTREE"));
  });

  it("captures an unborn HEAD (empty base)", async () => {
    const r = await initRepo(join(base, "unborn"));
    await writeFiles(r, { "new.txt": "new\n" });
    const res = await capture(h, r);
    expect(res.record.base.kind).toBe("empty");
    expect(res.record.support.unborn_head).toBe(true);
    expect(res.record.changes).toEqual([expect.objectContaining({ path: "new.txt", status: "added" })]);
  });

  it("skip-worktree and assume-unchanged entries are compared directly and flagged", async () => {
    const r = await simpleRepo("flags");
    git(r, ["update-index", "--skip-worktree", "a.txt"]);
    git(r, ["update-index", "--assume-unchanged", "b.txt"]);
    git(r, ["update-index", "--skip-worktree", "dir/c.txt"]);
    await writeFiles(r, { "a.txt": "a hidden edit\n", "b.txt": "b hidden edit\n" });
    unlinkSync(join(r, "dir", "c.txt")); // absent skip-worktree file: not a deletion
    const res = await capture(h, r);
    const c = new Map(res.record.changes.map((x) => [x.path, x]));
    expect(c.get("a.txt")).toMatchObject({ status: "modified", index_flag_hidden: true });
    expect(c.get("b.txt")).toMatchObject({ status: "modified", index_flag_hidden: true });
    expect(c.has("dir/c.txt")).toBe(false);
    expect(res.record.limitations.find((l) => l.code === "index_flag_absent")?.paths).toEqual(["dir/c.txt"]);
    expect(res.record.support.index_flags).toEqual({ assume_unchanged: 1, skip_worktree: 2 });
  });

  it("submodule pointer changes are listed; content is not exported", async () => {
    const sub = await simpleRepo("sub-src");
    const sup = await simpleRepo("super");
    git(sup, ["-c", "protocol.file.allow=always", "submodule", "add", "-q", shPath(sub), "mod"]);
    commitAll(sup, "add submodule");
    await writeFiles(join(sup, "mod"), { "a.txt": "advanced\n" });
    commitAll(join(sup, "mod"), "advance submodule");
    const before = snapshotTree(sup);
    const res = await capture(h, sup);
    expect(diffSnapshots(before, snapshotTree(sup))).toEqual([]);
    expect(res.record.changes.find((c) => c.path === "mod")).toMatchObject({ status: "modified", class: "submodule", diff: "note" });
    expect(exportFileList(res.exportDir!).some((f) => f.startsWith("tree/mod/"))).toBe(false);
    expect(res.manifest!.exclusions.submodules).toEqual([{ path: "mod", changed: true }]);
  });

  it("working-tree-encoding paths are transformation_unsupported (raw bytes, no diff)", async () => {
    const r = await initRepo(join(base, "wte"));
    await writeFiles(r, {
      ".gitattributes": "*.u16 text working-tree-encoding=UTF-16LE-BOM\n",
      "doc.u16": Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("hello\r\n", "utf16le")]),
    });
    commitAll(r, "init");
    const res = await capture(h, r);
    const c = res.record.changes.find((x) => x.path === "doc.u16");
    expect(c).toMatchObject({ transformation_unsupported: true, change_uncertain: true, diff: "note" });
    expect(exportFileList(res.exportDir!)).toContain("tree/doc.u16");
    expect(res.record.entries.find((e) => e.path === "doc.u16")?.working_tree_encoding).toBe("UTF-16LE-BOM");
  });

  it("shallow clone: uncommitted works; base_ref without history is BASE_UNAVAILABLE", async () => {
    const src = await simpleRepo("shallow-src");
    for (const n of [1, 2, 3]) {
      await writeFiles(src, { "a.txt": `v${n}\n` });
      commitAll(src, `c${n}`);
    }
    const clone = join(base, "shallow");
    git(base, ["clone", "-q", "--depth", "1", `file:///${shPath(src)}`, clone]);
    await writeFiles(clone, { "b.txt": "changed\n" });
    const cl = await canonicalizePath(clone);
    const res = await capture(h, cl);
    expect(res.record.support.shallow).toBe(true);
    expect(res.record.changes.map((c) => c.path)).toEqual(["b.txt"]);
    await expect(capture(h, cl, { target: { kind: "base_ref", ref: "HEAD~2" } })).rejects.toSatisfy(code("BASE_UNAVAILABLE"));
  });

  it("partial clone: lazy fetch is disabled; a missing base blob is BASE_UNAVAILABLE and nothing is fetched", async () => {
    const src = await simpleRepo("partial-src");
    git(src, ["config", "uploadpack.allowFilter", "true"]);
    git(src, ["config", "uploadpack.allowAnySHA1InWant", "true"]);
    const clone = join(base, "partial");
    git(base, ["clone", "-q", "--filter=blob:none", "--no-checkout", win ? `file:///${shPath(src)}` : `file://${src}`, clone]);
    git(clone, ["read-tree", "HEAD"]); // index from trees only; no blobs downloaded
    const blobOid = git(clone, ["rev-parse", "HEAD:a.txt"]).stdout.trim();
    const missing = () => git(clone, ["cat-file", "-e", blobOid], { env: { GIT_NO_LAZY_FETCH: "1" }, allowFail: true }).status !== 0;
    expect(missing()).toBe(true);
    renameSync(src, `${src}-moved`); // any fetch attempt would now fail loudly as well
    const cl = await canonicalizePath(clone);
    // git 2.45+ can disable lazy fetch (GIT_NO_LAZY_FETCH): the missing blob is BASE_UNAVAILABLE.
    // Older git cannot, so the support matrix refuses partial clones outright (plan §9.7).
    const [maj, min] = (/(\d+)\.(\d+)/.exec(git(base, ["version"]).stdout) ?? []).slice(1).map(Number) as [number, number];
    const lazyFetchControllable = maj > 2 || (maj === 2 && min >= 45);
    await expect(capture(h, cl)).rejects.toSatisfy(code(lazyFetchControllable ? "BASE_UNAVAILABLE" : "UNSUPPORTED_REPO_STATE"));
    expect(missing()).toBe(true); // capture fetched nothing
    // Restore the source (cleanup). Windows may still hold a handle on the moved folder for a
    // moment (indexing, antivirus): retry briefly.
    for (let i = 0; ; i++) {
      try {
        renameSync(`${src}-moved`, src);
        break;
      } catch (e) {
        if (i >= 50 || !["EPERM", "EBUSY", "EACCES"].includes((e as { code?: string }).code ?? "")) throw e;
        await new Promise((r) => setTimeout(r, 100));
      }
    }
  });

  it("separate git dir and linked worktrees are supported and reported", async () => {
    const gitDir = join(base, "separate.gitdir");
    const wtRepo = join(base, "separate");
    git(base, ["init", "-q", `--separate-git-dir=${gitDir}`, wtRepo]);
    git(wtRepo, ["config", "core.autocrlf", "false"]);
    await writeFiles(wtRepo, { "s.txt": "s\n" });
    commitAll(wtRepo, "init");
    await writeFiles(wtRepo, { "s.txt": "s2\n" });
    const res = await capture(h, await canonicalizePath(wtRepo));
    expect(res.record.support.external_git_dir).toBe(true);
    expect(res.record.limitations.some((l) => l.code === "external_git_dir")).toBe(true);
    expect(exportFileList(res.exportDir!).some((f) => f.toLowerCase().includes(".git"))).toBe(false);

    const main = await simpleRepo("main-wt");
    const linked = join(base, "linked-wt");
    git(main, ["worktree", "add", "-q", linked]);
    await writeFiles(linked, { "a.txt": "edited in linked worktree\n" });
    const res2 = await capture(h, await canonicalizePath(linked));
    expect(res2.record.support.linked_worktree).toBe(true);
    expect(res2.record.changes.map((c) => c.path)).toEqual(["a.txt"]);
  });

  it("an untracked nested repository is reported, not exported", async () => {
    const r = await simpleRepo("outer-nested");
    const nested = await initRepo(join(r, "nested"));
    await writeFiles(nested, { "x.txt": "NESTED-CONTENT\n" });
    commitAll(nested, "n");
    const res = await capture(h, r);
    expect(res.record.entries.find((e) => e.path === "nested")).toMatchObject({ class: "path_unsupported", reason: "nested_repository" });
    expect(exportFileList(res.exportDir!).some((f) => f.includes("nested"))).toBe(false);
  });

  it("merge in progress without conflicts is captured and reported", async () => {
    const r = await simpleRepo("inprogress");
    git(r, ["checkout", "-q", "-b", "side"]);
    await writeFiles(r, { "side.txt": "side\n" });
    commitAll(r, "side");
    git(r, ["checkout", "-q", "main"]);
    git(r, ["merge", "--no-commit", "--no-ff", "side"]);
    expect(existsSync(join(r, ".git", "MERGE_HEAD"))).toBe(true);
    const res = await capture(h, r);
    expect(res.record.support.in_progress).toContain("MERGE_HEAD");
    expect(res.record.limitations.some((l) => l.code === "operation_in_progress")).toBe(true);
  });

  it("a file edited between the two read passes marks the capture unstable; the export stays self-consistent", async () => {
    const r = await simpleRepo("stale");
    await writeFiles(r, { "a.txt": "edit 1\n" });
    const res = await capture(h, r, {
      testHooks: { afterFirstPass: () => writeFileSync(join(r, "a.txt"), "edit 2 during capture\n") },
    });
    expect(res.record.stable).toBe(false);
    expect(res.record.instability).toEqual(expect.arrayContaining([expect.objectContaining({ path: "a.txt", reason: "content_changed_between_passes" })]));
    expect(res.manifest!.stable).toBe(false);
    expect(res.manifest!.limitations.find((l) => l.code === "source_changed_during_capture")?.paths).toEqual(["a.txt"]);
    // MR-B: the identity describes exactly the exported bytes.
    const { verifyReviewExport } = await import("../src/capture/export-writer.js");
    expect((await verifyReviewExport(res.exportDir!)).ok).toBe(true);
    const tree = res.manifest!.files.find((f) => f.path === "a.txt")!;
    expect(res.record.entries.find((e) => e.path === "a.txt")!.sha256).toBe(tree.sha256);
    const { readFileSync } = await import("node:fs");
    expect(readFileSync(join(res.exportDir!, "tree", "a.txt"), "utf8")).toBe("edit 2 during capture\n");
  });
});
