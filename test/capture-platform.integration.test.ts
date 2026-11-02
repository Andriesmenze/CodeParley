// Gate C items deferred from M1.1 and exercised through capture (LV-WIN-GIT, LV-WIN-PATHS):
// the machine's REAL git configuration and paths over 260 characters (a shared contract, run
// on Windows and Linux), subst drives (Windows), and repositories reached through a symbolic
// link (Linux, plan §1.13).

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { canonicalizePath } from "../src/workspace/paths.js";
import { win, linux, supported, gitExe, tempDir, initRepo, writeFiles, commitAll, git, harness, capture, snapshotTree, diffSnapshots, exportFileList, cleanup, type Harness } from "./helpers/git-fixture.js";

function subst(args: string[]): number | null {
  return spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "subst.exe"), args, { windowsHide: true }).status;
}

describe.skipIf(!supported)("platform behaviour through capture", () => {
  let base: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-plat-");
    h = await harness();
  });
  afterAll(async () => cleanup(base, h.dataHome));

  it("captures under this machine's real system/global git configuration without writing or executing", async () => {
    const repo = await initRepo(join(base, "realcfg"));
    await writeFiles(repo, { "a.txt": "a\n", "b.txt": "b\n" });
    commitAll(repo, "init");
    await writeFiles(repo, { "a.txt": "a changed\n" });
    const before = snapshotTree(repo);
    const r = await capture(h, repo); // no environment overrides: real system + global config
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);
    expect(r.record.changes.map((c) => c.path)).toEqual(["a.txt"]);
    // Filter drivers defined in the real configuration (e.g. git-lfs) are neutralized.
    const realFilters = spawnSync(await gitExe(), ["config", "--get-regexp", "^filter\\..*\\.(clean|smudge|process)$"], { encoding: "utf8", cwd: repo }).stdout;
    for (const m of realFilters.matchAll(/^filter\.(.+)\.(?:clean|smudge|process) /gm)) expect(r.record.neutralized_filters).toContain(m[1]);
    expect(r.record.git.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("handles paths longer than 260 characters (source read, export write, prepared diff)", async () => {
    const repo = await initRepo(join(base, "longpaths"));
    git(repo, ["config", "core.longpaths", "true"]);
    const seg = "d".repeat(40);
    const rel = `${Array.from({ length: 7 }, (_, i) => `${seg}${i}`).join("/")}/deep-file.txt`;
    expect(join(repo, rel).length).toBeGreaterThan(260);
    await writeFiles(repo, { [rel]: "deep v1\n", "short.txt": "s\n" });
    git(repo, ["-c", "core.longpaths=true", "add", "-A"]);
    git(repo, ["-c", "core.longpaths=true", "commit", "-q", "-m", "deep"]);
    await writeFiles(repo, { [rel]: "deep v2\n" });
    const r = await capture(h, repo);
    expect(r.record.changes.map((c) => c.path)).toEqual([rel]);
    expect(r.record.changes[0]!.in_export).toEqual({ base: true, head: true });
    expect(exportFileList(r.exportDir!)).toContain(`tree/${rel}`);
    const patch = readFileSync(join(r.exportDir!, "review", "diff.patch"), "utf8");
    expect(patch).toContain(`+++ b/${rel}`);
    expect(r.record.limitations.some((l) => l.code === "prepared_diff_unavailable")).toBe(false);
  });
});

describe.skipIf(!win)("subst drives (Windows)", () => {
  let base: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-plat-subst-");
    h = await harness();
  });
  afterAll(async () => cleanup(base, h.dataHome));

  it("canonicalizes a subst drive to the real path and captures through it", async () => {
    const letter = ["Q", "R", "S", "T", "U", "V", "W", "Y"].find((l) => !existsSync(`${l}:\\`));
    if (!letter) return; // no free drive letter on this machine
    const repo = await initRepo(join(base, "substrepo"));
    await writeFiles(repo, { "a.txt": "a\n" });
    commitAll(repo, "init");
    await writeFiles(repo, { "a.txt": "a2\n" });
    expect(subst([`${letter}:`, base])).toBe(0);
    try {
      const viaSubst = `${letter}:\\substrepo`;
      const canon = await canonicalizePath(viaSubst);
      expect(canon.toLowerCase()).toBe(repo.toLowerCase());
      const r = await capture(h, canon);
      expect(r.record.repository.root.toLowerCase()).toBe(repo.toLowerCase());
      expect(r.record.changes.map((c) => c.path)).toEqual(["a.txt"]);
      // A non-canonical (subst) root is refused rather than captured under two identities.
      await expect(capture(h, viaSubst)).rejects.toSatisfy((e) => (e as { code?: string }).code === "NOT_A_GIT_WORKTREE");
    } finally {
      subst([`${letter}:`, "/d"]);
    }
  });
});

describe.skipIf(!linux)("repositories reached through a symbolic link (Linux)", () => {
  let base: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-plat-link-");
    h = await harness();
  });
  afterAll(async () => cleanup(base, h.dataHome));

  it("canonicalizes a symlinked path to the real path and captures through it; the non-canonical root is refused", async () => {
    const repo = await initRepo(join(base, "real-repo"));
    await writeFiles(repo, { "a.txt": "a\n" });
    commitAll(repo, "init");
    await writeFiles(repo, { "a.txt": "a2\n" });
    const viaLink = join(base, "linked-repo");
    symlinkSync(repo, viaLink);
    const canon = await canonicalizePath(viaLink);
    expect(canon).toBe(repo);
    const r = await capture(h, canon);
    expect(r.record.repository.root).toBe(repo);
    expect(r.record.changes.map((c) => c.path)).toEqual(["a.txt"]);
    // One repository, one identity: the link spelling is refused rather than captured as another root.
    await expect(capture(h, viaLink)).rejects.toSatisfy((e) => (e as { code?: string }).code === "NOT_A_GIT_WORKTREE");
  });
});
