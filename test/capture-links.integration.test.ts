// Links, junctions, reparse points, hard links and Windows path aliases (plan §8.3, §8.4,
// T5). Capture never follows a link and never exports content reached through one. The
// Windows suite exercises junctions, 8.3 aliases and alternate data streams; the Linux suite
// (plan §1.13) the same escapes with symbolic links, plus FIFOs, case-distinct names and
// file systems with Windows semantics.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  linux,
  win,
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
  mklinkJunction,
  mklinkFile,
  mklinkHard,
  snapshotTree,
  diffSnapshots,
  cleanup,
  type Harness,
} from "./helpers/git-fixture.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";

/** Can this user mount inside a new user and mount namespace (`unshare -rm`)? */
function canUnshareMount(): boolean {
  if (!linux) return false;
  const r = spawnSync("unshare", ["-rm", "sh", "-c", "mount -t tmpfs none /mnt 2>/dev/null || mount -t tmpfs none /tmp"], { stdio: "ignore", timeout: 10_000 });
  return r.status === 0;
}

describe.skipIf(!win)("links and reparse-point escapes (Windows)", () => {
  let base: string;
  let repo: string;
  let outside: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-links-");
    outside = join(base, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "secret.txt"), "OUTSIDE-SECRET-JUNCTION\n");
    writeFileSync(join(outside, "f.txt"), "OUTSIDE-SECRET-PARENT-SWAP\n");
    writeFileSync(join(outside, "hard-target.txt"), "OUTSIDE-SECRET-HARDLINK\n");
    writeFileSync(join(outside, "file-target.txt"), "OUTSIDE-SECRET-FILE-SYMLINK\n");
    repo = await initRepo(join(base, "repo"));
    h = await harness();
    await writeFiles(repo, { "keep.txt": "keep\n", "swap/f.txt": "inside\n" });
    // A git-tracked symlink (mode 120000) checked out as a plain text file (core.symlinks=false).
    const oid = git(repo, ["hash-object", "-w", "--stdin"], { input: "../outside/secret.txt" }).stdout.trim();
    git(repo, ["update-index", "--add", "--cacheinfo", `120000,${oid},tracked-link`]);
    writeFileSync(join(repo, "tracked-link"), "../outside/secret.txt");
    commitAll(repo, "init");
    // Escapes created after the commit (as a hostile host could):
    expect(mklinkJunction(join(repo, "jdir"), outside)).toBe(true); // untracked junction
    rmSync(join(repo, "swap"), { recursive: true });
    expect(mklinkJunction(join(repo, "swap"), outside)).toBe(true); // tracked dir replaced by a junction
    expect(mklinkHard(join(repo, "hard.txt"), join(outside, "hard-target.txt"))).toBe(true); // hard link
  });
  afterAll(async () => cleanup(base, h.dataHome));

  it("never exports content reached through a junction, a swapped parent directory or a hard link", async () => {
    const fileLink = mklinkFile(join(repo, "flink.txt"), join(outside, "file-target.txt")); // needs Developer Mode
    const before = snapshotTree(repo);
    const r = await capture(h, repo);
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);
    const corpus = await exportCorpus(r.exportDir!);
    for (const s of ["OUTSIDE-SECRET-JUNCTION", "OUTSIDE-SECRET-PARENT-SWAP", "OUTSIDE-SECRET-HARDLINK", "OUTSIDE-SECRET-FILE-SYMLINK"]) {
      expect(corpus, s).not.toContain(s);
    }
    const files = exportFileList(r.exportDir!);
    expect(files.some((f) => f.includes("jdir"))).toBe(false);
    expect(files).not.toContain("tree/hard.txt");
    expect(files).not.toContain("tree/tracked-link");
    expect(files).toContain("tree/keep.txt");

    const cls = new Map(r.record.entries.map((e) => [e.path, e]));
    expect(cls.get("hard.txt")).toMatchObject({ class: "link_skipped", reason: "hard_link" });
    expect(cls.get("tracked-link")).toMatchObject({ class: "link_skipped", reason: "git_symlink" });
    expect(cls.get("swap/f.txt")?.class).toBe("link_skipped");
    if (fileLink) expect(cls.get("flink.txt")?.class).toBe("link_skipped");
    // The tracked file under the swapped directory is a type change, not a content read.
    expect(r.record.changes.find((c) => c.path === "swap/f.txt")?.status).toBe("type_changed");
    // The unchanged git symlink is not reported as a change.
    expect(r.record.changes.some((c) => c.path === "tracked-link")).toBe(false);
    expect(r.manifest!.limitations.find((l) => l.code === "link_skipped")?.paths).toEqual(expect.arrayContaining(["hard.txt", "tracked-link"]));
  });

  it("rejects paths from git that cannot name a plain file on Windows (ADS, 8.3 alias of .git, case collisions)", async () => {
    const r2 = await initRepo(join(base, "names"));
    await writeFiles(r2, { "ok.txt": "ok\n", "Case.txt": "upper\n" });
    commitAll(r2, "init");
    const blob = git(r2, ["hash-object", "-w", "--stdin"], { input: "PLANTED\n" }).stdout.trim();
    const add = (path: string) => git(r2, ["-c", "core.protectNTFS=false", "update-index", "--add", "--cacheinfo", `100644,${blob},${path}`]);
    add("ads:stream.txt"); // would address an alternate data stream
    add("GIT~1/config"); // may alias .git\config through an 8.3 short name
    add("case.txt"); // collides with Case.txt on NTFS
    git(r2, ["-c", "core.protectNTFS=false", "commit", "-q", "-m", "hostile names"]);
    const r = await capture(h, r2);
    const corpus = await exportCorpus(r.exportDir!);
    expect(corpus).not.toContain("[core]"); // .git/config content never exported
    const files = exportFileList(r.exportDir!);
    expect(files.some((f) => f.includes(":"))).toBe(false);
    expect(files.some((f) => /git~1/i.test(f))).toBe(false);
    const cls = new Map(r.record.entries.map((e) => [e.path, e]));
    expect(cls.get("GIT~1/config")?.class).toBe("path_unsupported");
    expect(r.record.entries.filter((e) => e.reason === "case_collision").length).toBe(1);
    // The ADS path exists only in git; it is reported, and its base is never written.
    const ads = r.record.changes.find((c) => c.path === "ads:stream.txt");
    expect(ads?.in_export.base).toBe(false);
    await cleanup(r2);
  });
});

describe.skipIf(!linux)("links, special files and file systems on Linux", () => {
  let base: string;
  let repo: string;
  let outside: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    base = await tempDir("arl-links-linux-");
    outside = join(base, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "secret.txt"), "OUTSIDE-SECRET-DIRLINK\n");
    writeFileSync(join(outside, "f.txt"), "OUTSIDE-SECRET-PARENT-SWAP\n");
    writeFileSync(join(outside, "hard-target.txt"), "OUTSIDE-SECRET-HARDLINK\n");
    writeFileSync(join(outside, "file-target.txt"), "OUTSIDE-SECRET-FILE-SYMLINK\n");
    repo = await initRepo(join(base, "repo"));
    h = await harness();
    await writeFiles(repo, { "keep.txt": "keep\n", "swap/f.txt": "inside\n" });
    commitAll(repo, "init");
    // Escapes created after the commit (as a hostile host could):
    expect(mklinkJunction(join(repo, "jdir"), outside)).toBe(true); // untracked directory symlink
    rmSync(join(repo, "swap"), { recursive: true });
    expect(mklinkJunction(join(repo, "swap"), outside)).toBe(true); // tracked dir replaced by a symlink
    expect(mklinkHard(join(repo, "hard.txt"), join(outside, "hard-target.txt"))).toBe(true); // hard link
    expect(mklinkFile(join(repo, "flink.txt"), join(outside, "file-target.txt"))).toBe(true); // file symlink
  });
  afterAll(async () => cleanup(base, h.dataHome));

  it("never exports content reached through a directory symlink, a swapped parent directory, a file symlink or a hard link", async () => {
    const before = snapshotTree(repo);
    const r = await capture(h, repo);
    expect(diffSnapshots(before, snapshotTree(repo))).toEqual([]);
    const corpus = await exportCorpus(r.exportDir!);
    for (const s of ["OUTSIDE-SECRET-DIRLINK", "OUTSIDE-SECRET-PARENT-SWAP", "OUTSIDE-SECRET-HARDLINK", "OUTSIDE-SECRET-FILE-SYMLINK"]) expect(corpus, s).not.toContain(s);
    const files = exportFileList(r.exportDir!);
    expect(files.some((f) => f.includes("jdir"))).toBe(false);
    expect(files).not.toContain("tree/hard.txt");
    expect(files).not.toContain("tree/flink.txt");
    expect(files).toContain("tree/keep.txt");
    const cls = new Map(r.record.entries.map((e) => [e.path, e]));
    expect(cls.get("hard.txt")).toMatchObject({ class: "link_skipped", reason: "hard_link" });
    expect(cls.get("flink.txt")?.class).toBe("link_skipped");
    expect(cls.get("swap/f.txt")?.class).toBe("link_skipped");
    expect(r.record.changes.find((c) => c.path === "swap/f.txt")?.status).toBe("type_changed");
  });

  it("a FIFO never blocks or reaches the export (git does not even list it), and a tracked git symlink is never followed", async () => {
    const r2 = await initRepo(join(base, "special"));
    await writeFiles(r2, { "ok.txt": "ok\n" });
    commitAll(r2, "init");
    expect(mklinkFile(join(r2, "tlink"), join(outside, "secret.txt"))).toBe(true);
    git(r2, ["add", "tlink"]);
    git(r2, ["commit", "-q", "-m", "tracked symlink"]);
    expect(spawnSync("mkfifo", [join(r2, "pipe")]).status).toBe(0);
    const started = Date.now();
    const r = await capture(h, r2);
    expect(Date.now() - started).toBeLessThan(30_000);
    const cls = new Map(r.record.entries.map((e) => [e.path, e]));
    expect(cls.get("tlink")?.class).toBe("link_skipped");
    expect(cls.has("pipe")).toBe(false);
    expect(exportFileList(r.exportDir!).some((f) => f.endsWith("pipe"))).toBe(false);
    expect(await exportCorpus(r.exportDir!)).not.toContain("OUTSIDE-SECRET-DIRLINK");
    await cleanup(r2);
  });

  it("names that differ only in case are two files and both are captured; names Windows cannot hold are ordinary", async () => {
    const r3 = await initRepo(join(base, "names"));
    await writeFiles(r3, { "Case.txt": "upper\n", "case.txt": "lower\n", "con.txt": "device name on Windows\n", "dir/a:b.txt": "colon\n" });
    commitAll(r3, "init");
    await writeFiles(r3, { "Case.txt": "upper v2\n", "case.txt": "lower v2\n" });
    const r = await capture(h, r3);
    const files = exportFileList(r.exportDir!);
    expect(files).toEqual(expect.arrayContaining(["tree/Case.txt", "tree/case.txt", "tree/con.txt", "tree/dir/a:b.txt"]));
    expect(r.record.entries.some((e) => e.reason === "case_collision")).toBe(false);
    expect(r.record.changes.map((c) => c.path).sort()).toEqual(["Case.txt", "case.txt"]);
    await cleanup(r3);
  });

  // A mount point is another file system's tree, exactly the escape a directory link is. The
  // capture runs in a private user and mount namespace where the user may mount a tmpfs.
  it.runIf(canUnshareMount())("a mount point inside the work tree — tmpfs or a bind mount from the same file system, over a tracked directory or file or untracked — is never read or exported", async () => {
    const dist = sharedCompiledSrc(); // the shared build of src/ (test/global-setup.ts)
    expect(dist).not.toBeNull();
    if (!dist) return;
    const r5 = await initRepo(join(base, "mounts"));
    await writeFiles(r5, { "keep.txt": "keep\n", "sub/f.txt": "inside\n", "tracked.txt": "tracked\n" });
    commitAll(r5, "init");
    mkdirSync(join(r5, "mnt"));
    mkdirSync(join(r5, "bound"));
    // Outside the work tree but on the SAME file system: a bind mount keeps the device id.
    const bindSrc = join(base, "bind-src");
    mkdirSync(bindSrc);
    writeFileSync(join(bindSrc, "dir-secret.txt"), "BIND-SECRET-DIR\n");
    writeFileSync(join(base, "bind-file-secret.txt"), "BIND-SECRET-FILE\n");
    const mod = (p: string) => JSON.stringify(pathToFileURL(join(dist, p)).href);
    const script = join(base, "mount-capture.mjs");
    await writeFile(
      script,
      [
        `import { mkdirSync } from "node:fs";`,
        `import { runCapture } from ${mod("capture/capture.js")};`,
        `import { runPaths } from ${mod("store/paths.js")};`,
        `import { selfOwner } from ${mod("store/owner.js")};`,
        `import { uuidv7 } from ${mod("common/ids.js")};`,
        `import { parseUserConfig } from ${mod("schemas/config.js")};`,
        `const [repo, dataHome, gitExe] = process.argv.slice(2);`,
        `const rp = runPaths(dataHome, "repokey", uuidv7());`,
        `mkdirSync(rp.opsDir, { recursive: true });`,
        `const r = await runCapture({ kind: "review", repoRoot: repo, gitExe, target: { kind: "uncommitted" }, rules: parseUserConfig({}).capture, runPaths: rp, operationId: uuidv7(), lock: { dataHome, owner: selfOwner() }, fsync: false });`,
        `process.stdout.write(JSON.stringify({ exportDir: r.exportDir, entries: r.record.entries, changes: r.record.changes }));`,
      ].join("\n"),
    );
    // tmpfs over the tracked directory "sub" and over the untracked "mnt", each with a secret; a
    // bind mount of an outside directory onto the untracked "bound"; a file bind mount over the
    // tracked "tracked.txt".
    const sh =
      'for d in "$1/sub" "$1/mnt"; do mount -t tmpfs none "$d" || exit 9; done; echo MOUNT-SECRET-OVER-TRACKED > "$1/sub/f.txt"; echo MOUNT-SECRET-UNTRACKED > "$1/mnt/x.txt"; ' +
      'mount --bind "$6" "$1/bound" || exit 10; mount --bind "$7" "$1/tracked.txt" || exit 11; exec "$2" "$3" "$1" "$4" "$5"';
    const run = spawnSync("unshare", ["-rm", "sh", "-c", sh, "sh", r5, process.execPath, script, h.dataHome, await gitExe(), bindSrc, join(base, "bind-file-secret.txt")], { encoding: "utf8", timeout: 60_000 });
    expect(run.status, run.stderr).toBe(0);
    const out = JSON.parse(run.stdout) as { exportDir: string; entries: { path: string; class: string }[]; changes: { path: string; status: string }[] };
    const corpus = await exportCorpus(out.exportDir);
    for (const secret of ["MOUNT-SECRET-OVER-TRACKED", "MOUNT-SECRET-UNTRACKED", "BIND-SECRET-DIR", "BIND-SECRET-FILE"]) expect(corpus, secret).not.toContain(secret);
    const files = exportFileList(out.exportDir);
    expect(files).toContain("tree/keep.txt");
    expect(files.some((p) => p.startsWith("tree/sub/") || p.startsWith("tree/mnt/") || p.startsWith("tree/bound/"))).toBe(false);
    expect(files).not.toContain("tree/tracked.txt");
    const cls = new Map(out.entries.map((e) => [e.path, e.class]));
    expect(cls.get("sub/f.txt")).toBe("link_skipped");
    expect(cls.get("tracked.txt")).toBe("link_skipped");
    for (const p of ["mnt/x.txt", "bound/dir-secret.txt"]) if (cls.has(p)) expect(cls.get(p), p).toBe("link_skipped");
    await cleanup(r5);
  });

  // A capture caches the link checks of directory components. A bind mount placed over an
  // already-checked directory keeps its device id and realpath spelling, so the read itself
  // verifies that the opened file lies on the root's own mount (PR #4 review).
  it.runIf(canUnshareMount())("a bind mount placed over a directory after its link check was cached is caught at the read", async () => {
    const dist = sharedCompiledSrc();
    expect(dist).not.toBeNull();
    if (!dist) return;
    const root = realpathSync(await mkdtemp(join(base, "race-")));
    mkdirSync(join(root, "dir"));
    writeFileSync(join(root, "dir", "f.txt"), "inside\n");
    const outside = join(base, "race-outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "f.txt"), "BIND-RACE-SECRET\n");
    const mod = (p: string) => JSON.stringify(pathToFileURL(join(dist, p)).href);
    const script = join(base, "mount-race.mjs");
    await writeFile(
      script,
      [
        `import { spawnSync } from "node:child_process";`,
        `import { readWorkingFile } from ${mod("capture/safe-read.js")};`,
        `const [root, outside] = process.argv.slice(2);`,
        `const file = root + "/dir/f.txt";`,
        `const opts = { root, objectFormat: "sha1", maxRetainBytes: 1 << 20, retain: true, linkCache: new Map() };`,
        `const view = (r) => ({ kind: r.kind, reason: r.reason ?? null, text: r.bytes ? r.bytes.toString("utf8") : null });`,
        `const before = view(await readWorkingFile(file, opts));`,
        `if (spawnSync("mount", ["--bind", outside, root + "/dir"]).status !== 0) process.exit(12);`,
        `const raced = view(await readWorkingFile(file, opts));`,
        `const fresh = view(await readWorkingFile(file, { ...opts, linkCache: new Map() }));`,
        `process.stdout.write(JSON.stringify({ before, raced, fresh }));`,
      ].join("\n"),
    );
    const run = spawnSync("unshare", ["-rm", process.execPath, script, root, outside], { encoding: "utf8", timeout: 60_000 });
    expect(run.status, run.stderr).toBe(0);
    const out = JSON.parse(run.stdout) as Record<"before" | "raced" | "fresh", { kind: string; reason: string | null; text: string | null }>;
    expect(out.before).toEqual({ kind: "file", reason: null, text: "inside\n" });
    expect(out.raced).toEqual({ kind: "link", reason: "mount_point", text: null });
    expect(out.fresh.kind).toBe("link");
    expect(run.stdout).not.toContain("BIND-RACE-SECRET");
  });

  it.skipIf(!existsSync("/mnt/c/Windows"))("a work tree on a Windows drive mounted by WSL (drvfs, 9p) is refused: its semantics are Windows', not POSIX", async () => {
    const tmp = await mkdtemp("/mnt/c/Windows/Temp/arl-drvfs-").catch(() => null);
    if (!tmp) return; // not writable from this distribution
    try {
      const r4 = await initRepo(join(tmp, "repo"));
      await writeFiles(r4, { "a.txt": "a\n" });
      commitAll(r4, "init");
      await expect(capture(h, r4)).rejects.toMatchObject({ code: "UNSUPPORTED_REPO_STATE", details: { reasons: [expect.stringMatching(/^filesystem_unsupported:9p/)] } });
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
