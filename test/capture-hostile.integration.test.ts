// Hostile-configuration capture fixtures (plan §9.1 CG1–CG3, §18.1 "Capture integration",
// MR-A, LV-WIN-GIT). Each fixture is first captured, asserting that nothing executed and
// nothing under the repository (including .git) changed; then a POSITIVE CONTROL runs
// plain git against the same fixture and asserts the hostile configuration really fires.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
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
  snapshotTree,
  diffSnapshots,
  markerCmd,
  readMarker,
  shPath,
  cleanup,
  type Harness,
} from "./helpers/git-fixture.js";

function hasGitLfs(): boolean {
  return spawnSync("git-lfs", ["version"], { windowsHide: true }).status === 0;
}

function hookScript(marker: string, name: string): string {
  return `#!/bin/sh\necho hook-${name} >> '${shPath(marker)}'\n`;
}

describe.skipIf(!supported)("capture under hostile repository configuration", () => {
  let base: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-hostile-");
    h = await harness();
  });
  afterAll(async () => cleanup(base, h.dataHome));

  it("runs no fsmonitor, hook, external diff, textconv, clean/smudge or process filter (repo-local config)", async () => {
    const repo = await initRepo(join(base, "local"));
    const marker = join(base, "local-marker.txt");
    await writeFiles(repo, {
      ".gitattributes": "*.flt filter=evil\n*.prc filter=evilproc\n*.dif diff=evil\n*.tc diff=evtc\n",
      "a.flt": "filtered\n",
      "b.prc": "processed\n",
      "c.dif": "external diff\n",
      "d.tc": "textconv\n",
      "plain.txt": "plain\n",
      ".husky/post-index-change": hookScript(marker, "post-index-change"),
      ".husky/pre-commit": hookScript(marker, "pre-commit"),
      ".husky/reference-transaction": hookScript(marker, "reference-transaction"),
      ".husky/post-checkout": hookScript(marker, "post-checkout"),
    });
    // Linux runs a hook only when it is executable (Windows ignores the bit): make the positive
    // control meaningful there too.
    if (!win) for (const hook of ["post-index-change", "pre-commit", "reference-transaction", "post-checkout"]) chmodSync(join(repo, ".husky", hook), 0o755);
    commitAll(repo, "init");
    // Hostile configuration, installed after the fixture commit.
    git(repo, ["config", "core.fsmonitor", markerCmd(marker, "fsmonitor")]);
    git(repo, ["config", "core.hooksPath", ".husky"]);
    git(repo, ["config", "filter.evil.clean", markerCmd(marker, "clean", "cat")]);
    git(repo, ["config", "filter.evil.smudge", markerCmd(marker, "smudge", "cat")]);
    git(repo, ["config", "filter.evil.required", "true"]);
    git(repo, ["config", "filter.evilproc.process", markerCmd(marker, "process")]);
    git(repo, ["config", "diff.evil.command", markerCmd(marker, "extdiff")]);
    git(repo, ["config", "diff.evtc.textconv", markerCmd(marker, "textconv", "cat")]);
    await writeFiles(repo, { "a.flt": "filtered changed\n", "b.prc": "processed changed\n", "c.dif": "ext changed\n", "d.tc": "tc changed\n" });

    const before = snapshotTree(repo);
    const r = await capture(h, repo);
    expect(readMarker(marker)).toBe("");
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);
    const byPath = new Map(r.record.changes.map((c) => [c.path, c]));
    expect(byPath.get("a.flt")?.transformation_unsupported).toBe(true);
    expect(byPath.get("b.prc")?.transformation_unsupported).toBe(true);
    expect(byPath.get("c.dif")?.status).toBe("modified");
    expect(r.record.neutralized_filters).toEqual(expect.arrayContaining(["evil", "evilproc"]));

    // Positive controls: the same configuration fires under plain git.
    git(repo, ["status", "--porcelain"], { allowFail: true });
    expect(readMarker(marker)).toContain("fsmonitor");
    // One file per control: the deliberately broken process filter aborts a whole-tree diff.
    git(repo, ["diff", "--", "a.flt"], { allowFail: true });
    expect(readMarker(marker)).toContain("clean");
    git(repo, ["diff", "--", "b.prc"], { allowFail: true });
    expect(readMarker(marker)).toContain("process");
    git(repo, ["diff", "--", "c.dif", "d.tc"], { allowFail: true });
    expect(readMarker(marker)).toContain("extdiff");
    expect(readMarker(marker)).toContain("textconv");
    git(repo, ["add", "plain.txt"], { allowFail: true });
    expect(readMarker(marker)).toContain("hook-post-index-change");
  });

  it("runs nothing from hostile GLOBAL and SYSTEM configuration either", async () => {
    const repo = await initRepo(join(base, "global"));
    const marker = join(base, "global-marker.txt");
    await writeFiles(repo, { ".gitattributes": "*.g filter=gfilt\n*.d diff=gdiff\n", "x.g": "one\n", "z.d": "zz\n", "y.txt": "y\n" });
    commitAll(repo, "init");
    const hooksDir = join(base, "global-hooks");
    await writeFiles(hooksDir, { "post-index-change": hookScript(marker, "global-post-index-change") });
    const globalCfg = join(base, "hostile-global.gitconfig");
    writeFileSync(
      globalCfg,
      [
        "[core]",
        `\tfsmonitor = ${markerCmd(marker, "global-fsmonitor")}`,
        `\thooksPath = ${shPath(hooksDir)}`,
        `\tpager = ${markerCmd(marker, "pager", "cat")}`,
        "[filter \"gfilt\"]",
        `\tclean = ${markerCmd(marker, "global-clean", "cat")}`,
        `\tprocess = ${markerCmd(marker, "global-process")}`,
        "[diff]",
        `\texternal = ${markerCmd(marker, "global-external")}`,
        "[diff \"gdiff\"]",
        `\ttextconv = ${markerCmd(marker, "global-textconv", "cat")}`,
        "",
      ].join("\n"),
    );
    const systemCfg = join(base, "hostile-system.gitconfig");
    writeFileSync(systemCfg, `[core]\n\tfsmonitor = ${markerCmd(marker, "system-fsmonitor")}\n[filter "gfilt"]\n\tsmudge = ${markerCmd(marker, "system-smudge", "cat")}\n`);
    await writeFiles(repo, { "x.g": "two\n", "z.d": "zz changed\n" });
    const overrides = { GIT_CONFIG_GLOBAL: globalCfg, GIT_CONFIG_SYSTEM: systemCfg };

    const before = snapshotTree(repo);
    const r = await capture(h, repo, { gitEnvOverrides: overrides });
    expect(readMarker(marker)).toBe("");
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);
    expect(r.record.neutralized_filters).toContain("gfilt");

    // Positive control with the same global/system files.
    git(repo, ["status", "--porcelain"], { env: { GIT_CONFIG_GLOBAL: globalCfg, GIT_CONFIG_SYSTEM: systemCfg, GIT_CONFIG_NOSYSTEM: "" }, allowFail: true });
    expect(readMarker(marker)).toMatch(/global-fsmonitor|system-fsmonitor/);
    const hostileEnv = { GIT_CONFIG_GLOBAL: globalCfg, GIT_CONFIG_SYSTEM: systemCfg, GIT_CONFIG_NOSYSTEM: "" };
    git(repo, ["diff", "--", "x.g"], { env: hostileEnv, allowFail: true });
    expect(readMarker(marker)).toMatch(/global-process|global-clean/);
    // fsmonitor off here: the stub above left a token in the index that would hide z.d.
    git(repo, ["-c", "core.fsmonitor=false", "diff", "--", "z.d"], { env: hostileEnv, allowFail: true });
    expect(readMarker(marker)).toMatch(/global-external|global-textconv/);
  });

  it("MR-A: attributes switched to another configured driver and a new local driver mid-capture execute nothing", async () => {
    const repo = await initRepo(join(base, "mra"));
    const marker = join(base, "mra-marker.txt");
    await writeFiles(repo, { ".gitattributes": "*.dat filter=one\n", "a.dat": "a\n", "b.txt": "b\n", "c.bin": "c\n" });
    commitAll(repo, "init");
    git(repo, ["config", "filter.one.clean", markerCmd(marker, "one-clean", "cat")]);
    git(repo, ["config", "filter.two.clean", markerCmd(marker, "two-clean", "cat")]); // configured, initially unused
    git(repo, ["config", "filter.two.smudge", markerCmd(marker, "two-smudge", "cat")]);
    await writeFiles(repo, { "a.dat": "a changed\n", "b.txt": "b changed\n", "c.bin": "c changed\n" });

    let afterSwitch: Map<string, string> | null = null;
    const r = await capture(h, repo, {
      testHooks: {
        afterAttributeScan: () => {
          // Host edits .gitattributes to select the second configured driver, and adds a
          // brand-new local driver definition selected by another pattern.
          writeFileSync(join(repo, ".gitattributes"), "* filter=two\n*.bin filter=three\n");
          appendFileSync(join(repo, ".git", "config"), `[filter "three"]\n\tclean = ${markerCmd(marker, "three-clean", "cat")}\n\tprocess = ${markerCmd(marker, "three-process")}\n`);
          afterSwitch = snapshotTree(repo);
        },
      },
    });
    expect(readMarker(marker)).toBe("");
    expect(afterSwitch).not.toBeNull();
    expect(diffSnapshots(afterSwitch!, snapshotTree(repo))).toEqual([]);
    // The attribute change is detected and the capture is marked unstable (stale).
    expect(r.record.stable).toBe(false);
    expect(r.record.instability.map((i) => i.path)).toContain("<attributes>");

    // Positive control: plain git now runs the switched drivers.
    git(repo, ["diff", "--", "b.txt"], { allowFail: true });
    expect(readMarker(marker)).toContain("two-clean");
    git(repo, ["diff", "--", "c.bin"], { allowFail: true });
    expect(readMarker(marker)).toMatch(/three-clean|three-process/);
  });

  // Git for Windows bundles git-lfs; on Linux it is a separate package (installed on CI runners).
  it.skipIf(!hasGitLfs())("Git LFS: capture writes nothing to .git/lfs/objects; plain status does (G8)", async () => {
    const repo = await initRepo(join(base, "lfs"));
    git(repo, ["config", "filter.lfs.clean", "git-lfs clean -- %f"]);
    git(repo, ["config", "filter.lfs.smudge", "git-lfs smudge -- %f"]);
    git(repo, ["config", "filter.lfs.process", "git-lfs filter-process"]);
    git(repo, ["config", "filter.lfs.required", "true"]);
    await writeFiles(repo, {
      ".gitattributes": "*.bin filter=lfs diff=lfs merge=lfs -text\n",
      "big.bin": Buffer.from("LFS CONTENT v1 ".repeat(100)),
      "same.bin": Buffer.from("UNCHANGED LFS CONTENT ".repeat(50)),
      "note.txt": "n\n",
    });
    commitAll(repo, "init");
    const lfsObjects = join(repo, ".git", "lfs", "objects");
    expect(existsSync(lfsObjects)).toBe(true); // the fixture really went through git-lfs
    await writeFiles(repo, { "big.bin": Buffer.from("LFS CONTENT v2 ".repeat(100)) });

    const before = snapshotTree(repo);
    const r = await capture(h, repo);
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);
    const byPath = new Map(r.record.changes.map((c) => [c.path, c]));
    expect(byPath.get("big.bin")).toMatchObject({ status: "modified", transformation_unsupported: true, change_uncertain: false });
    expect(byPath.has("same.bin")).toBe(false); // unchanged per the LFS pointer's sha256
    expect(r.record.support.filters_in_use).toContain("lfs");

    // Positive control (G8): plain status runs the clean filter, which stores a new object.
    const countObjects = () => snapshotTree(lfsObjects).size;
    const n = countObjects();
    git(repo, ["status", "--porcelain"], { env: { GIT_OPTIONAL_LOCKS: "0" }, allowFail: true });
    expect(countObjects()).toBeGreaterThan(n);
  });

  it("the isolated prepared diff ignores a hostile enclosing repository and inherited git variables", async () => {
    const outer = await initRepo(join(base, "outer"));
    const marker = join(base, "outer-marker.txt");
    git(outer, ["config", "core.fsmonitor", markerCmd(marker, "outer-fsmonitor")]);
    git(outer, ["config", "diff.external", markerCmd(marker, "outer-external")]);
    git(outer, ["config", "core.pager", markerCmd(marker, "outer-pager", "cat")]);
    const inner = await initRepo(join(base, "inner"));
    await writeFiles(inner, { ".gitattributes": "* diff=x\n", "f.txt": "1\n" });
    commitAll(inner, "init");
    await writeFiles(inner, { "f.txt": "2\n" });
    // The run store lives INSIDE the hostile outer repository.
    const h2 = await (async () => {
      const { runPaths } = await import("../src/store/paths.js");
      const { uuidv7 } = await import("../src/common/ids.js");
      const dataHome = join(outer, "store");
      return { dataHome, runPaths: runPaths(dataHome, "k", uuidv7()) };
    })();
    const saved = { ...process.env };
    process.env["GIT_CONFIG_GLOBAL"] = join(base, "hostile-global.gitconfig");
    process.env["GIT_DIR"] = join(outer, ".git");
    process.env["GIT_EXTERNAL_DIFF"] = "sh -c 'echo inherited >> x'";
    try {
      const r = await capture(h2, inner);
      expect(readMarker(marker)).toBe("");
      expect(r.record.changes.map((c) => c.path)).toEqual(["f.txt"]);
    } finally {
      for (const k of ["GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_EXTERNAL_DIFF"]) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    }
  });

  it("issues only allowlisted read-only git subcommands", async () => {
    const repo = await initRepo(join(base, "calls"));
    await writeFiles(repo, { "a.txt": "1\n", "b.txt": "2\n" });
    commitAll(repo, "init");
    await writeFiles(repo, { "a.txt": "changed\n", "c.txt": "new\n" });
    const subs = new Set<string>();
    await capture(h, repo, { testHooks: { onGitQuery: (sub) => subs.add(sub) } });
    const forbidden = ["status", "diff", "add", "checkout", "hash-object", "update-index", "write-tree", "stash", "fetch"];
    for (const f of forbidden) expect(subs.has(f)).toBe(false);
    expect([...subs].sort()).toEqual(expect.arrayContaining(["cat-file", "check-attr", "ls-files", "ls-tree", "rev-parse", "version"]));
  });

  it("is refused while another live owner holds the worktree lock", async () => {
    const repo = await initRepo(join(base, "locked"));
    await writeFiles(repo, { "a.txt": "1\n" });
    commitAll(repo, "init");
    const { acquireWorktreeLock } = await import("../src/store/locks.js");
    const { worktreeLockPath, canonicalPathKey } = await import("../src/store/paths.js");
    const { selfOwner } = await import("../src/store/owner.js");
    const handle = await acquireWorktreeLock(worktreeLockPath(h.dataHome, canonicalPathKey(repo)), { owner: selfOwner(), operationId: "other-op", kind: "checks" });
    try {
      await expect(capture(h, repo)).rejects.toSatisfy((e) => (e as { code: string }).code === "WORKTREE_BUSY");
    } finally {
      await handle.release();
    }
    expect(readdirSync(h.runPaths.runDir)).toBeDefined();
  });
});
