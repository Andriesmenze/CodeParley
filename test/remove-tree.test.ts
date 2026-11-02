// Link-safe deletion (store/remove-tree.ts; plan §15.6; M1.6). Runs on every platform: a
// directory link is created with Node's "junction" type (a junction on Windows, needing no
// privilege; a symbolic link elsewhere). File symlinks are exercised where they can be made.
// Linux (plan §1.13): a mount point inside the tree is never entered, tested in a private user
// and mount namespace where the user may mount a tmpfs.

import { describe, it, expect } from "vitest";
import { lstat, mkdir, mkdtemp, open, readdir, readFile, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { isPlainDirectory, removeTreeNoFollow, treeSize } from "../src/store/remove-tree.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";
import { mountIdOfDir, mountIdOfFd, parseMountInfo } from "../src/workspace/mounts.js";

async function layout() {
  const base = await mkdtemp(join(tmpdir(), "cp-rmtree-"));
  const outside = join(base, "outside");
  await mkdir(join(outside, "nested"), { recursive: true });
  await writeFile(join(outside, "keep.txt"), "outside");
  await writeFile(join(outside, "nested", "deep.txt"), "outside too");
  const root = join(base, "run");
  await mkdir(join(root, "ops", "a"), { recursive: true });
  await writeFile(join(root, "state.json"), "{}");
  await writeFile(join(root, "ops", "a", "result.json"), "x".repeat(1000));
  await symlink(outside, join(root, "ops", "dir-link"), "junction");
  let fileLink = false;
  try {
    await symlink(join(outside, "keep.txt"), join(root, "file-link"), "file");
    fileLink = true;
  } catch {
    /* file symlinks need a privilege on Windows (Developer Mode); the directory case still runs */
  }
  return { base, outside, root, fileLink };
}

describe("removeTreeNoFollow", () => {
  it("removes the tree and every link as a link, never what a link points to", async () => {
    const { outside, root, fileLink } = await layout();
    expect(await isPlainDirectory(root)).toBe(true);
    expect(await isPlainDirectory(join(root, "ops", "dir-link"))).toBe(false);
    const size = await treeSize(root);
    expect(size.complete).toBe(true);
    expect(size.bytes).toBe(1002); // "{}" + 1000 bytes; the link target's files are not counted

    const r = await removeTreeNoFollow(root);
    expect(r.failures).toEqual([]);
    expect(r.removedLinks).toBe(fileLink ? 2 : 1);
    expect(r.removedFiles).toBe(2);
    expect(existsSync(root)).toBe(false);
    expect(await readFile(join(outside, "keep.txt"), "utf8")).toBe("outside");
    expect(await readFile(join(outside, "nested", "deep.txt"), "utf8")).toBe("outside too");
  });

  it("a root that is itself a link is removed as a link only", async () => {
    const { base, outside } = await layout();
    const linkRoot = join(base, "linked-root");
    await symlink(outside, linkRoot, "junction");
    const r = await removeTreeNoFollow(linkRoot);
    expect(r.failures).toEqual([]);
    expect(r.removedLinks).toBe(1);
    expect(existsSync(linkRoot)).toBe(false);
    expect(await readFile(join(outside, "nested", "deep.txt"), "utf8")).toBe("outside too");
  });

  it("a missing root is not an error", async () => {
    const r = await removeTreeNoFollow(join(tmpdir(), "cp-rmtree-does-not-exist-1f2e3d"));
    expect(r).toEqual({ removedFiles: 0, removedDirs: 0, removedLinks: 0, bytes: 0, failures: [] });
  });
});

/**
 * A junction whose target is written as a volume GUID path (`\\?\Volume{…}\…`), as
 * `mklink /J` makes it without elevation. libuv cannot express that target: lstat reports a
 * plain directory (it stats the target), readlink fails with EINVAL as on a plain directory,
 * and readdir lists the target. Before M1.6-13 purge deleted the target's files through it.
 */
function volumeGuidJunction(link: string, target: string): void {
  const sys = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
  const mv = spawnSync(join(sys, "mountvol.exe"), [target.slice(0, 3), "/L"], { encoding: "utf8", windowsHide: true });
  const volume = (mv.stdout ?? "").trim();
  if (mv.status !== 0 || !/^\\\\\?\\Volume\{[0-9a-fA-F-]+\}\\$/.test(volume)) throw new Error(`mountvol: ${mv.status} ${mv.stdout} ${mv.stderr}`);
  const mk = spawnSync(join(sys, "cmd.exe"), ["/d", "/c", "mklink", "/J", link, volume + target.slice(3)], { encoding: "utf8", windowsHide: true });
  if (mk.status !== 0) throw new Error(`mklink: ${mk.stdout} ${mk.stderr}`);
}

describe.runIf(process.platform === "win32")("volume GUID junctions (Windows)", () => {
  it("are recognised as links: not walked, not sized, removed as links, the target survives", async () => {
    const { outside, root } = await layout();
    const vj = join(root, "ops", "vguid-link");
    volumeGuidJunction(vj, outside);
    // The precondition that made this dangerous: Node sees a plain directory listing the target.
    expect((await lstat(vj)).isDirectory()).toBe(true);
    expect(await readdir(vj)).toContain("keep.txt");

    expect(await isPlainDirectory(vj)).toBe(false);
    expect((await treeSize(root)).bytes).toBe(1002); // the target's files are not counted
    const r = await removeTreeNoFollow(root);
    expect(r.failures).toEqual([]);
    expect(r.removedFiles).toBe(2); // state.json and ops/a/result.json only
    expect(existsSync(root)).toBe(false);
    expect(await readFile(join(outside, "keep.txt"), "utf8")).toBe("outside");
    expect(await readFile(join(outside, "nested", "deep.txt"), "utf8")).toBe("outside too");
  });

  it("a root that is such a junction is removed as a link only", async () => {
    const { base, outside } = await layout();
    const linkRoot = join(base, "vguid-root");
    volumeGuidJunction(linkRoot, outside);
    expect(await isPlainDirectory(linkRoot)).toBe(false);
    expect(await treeSize(linkRoot)).toEqual({ bytes: 0, files: 0, complete: true });
    const r = await removeTreeNoFollow(linkRoot);
    expect(r.failures).toEqual([]);
    expect(r.removedLinks).toBe(1);
    expect(r.removedFiles).toBe(0);
    expect(existsSync(linkRoot)).toBe(false);
    expect(await readFile(join(outside, "nested", "deep.txt"), "utf8")).toBe("outside too");
  });
});

/** Can this user mount inside a new user and mount namespace (`unshare -rm`)? */
function canUnshareMount(): boolean {
  if (process.platform !== "linux") return false;
  const r = spawnSync("unshare", ["-rm", "sh", "-c", "mount -t tmpfs none /mnt 2>/dev/null || mount -t tmpfs none /tmp"], { stdio: "ignore", timeout: 10_000 });
  return r.status === 0;
}

describe.runIf(canUnshareMount())("mount points (Linux)", () => {
  it("a mount point inside the tree — tmpfs, or a bind mount of a directory or a file from the same file system — is never entered, sized or removed: it is reported (MOUNT_POINT) and its content survives", async () => {
    const dist = sharedCompiledSrc(); // the shared build of src/ (test/global-setup.ts)
    expect(dist).not.toBeNull();
    if (!dist) return;
    const base = await mkdtemp(join(tmpdir(), "cp-rmtree-mnt-"));
    const root = join(base, "run");
    const mnt = join(root, "ops", "mnt");
    await mkdir(mnt, { recursive: true });
    await writeFile(join(root, "state.json"), "{}");
    // Outside the tree but on the same file system (a bind mount keeps the device id).
    const outside = join(base, "outside");
    await mkdir(outside);
    await writeFile(join(outside, "keep.txt"), "outside");
    await writeFile(join(base, "outside-file.txt"), "outside file");
    const bound = join(root, "ops", "bound");
    await mkdir(bound);
    const boundFile = join(root, "ops", "bound-file.txt");
    await writeFile(boundFile, "placeholder");
    const script = join(base, "probe.mjs");
    await writeFile(
      script,
      `import { existsSync } from "node:fs";\n` +
        `import { isPlainDirectory, removeTreeNoFollow, treeSize } from ${JSON.stringify(pathToFileURL(join(dist, "store", "remove-tree.js")).href)};\n` +
        `const [root, mnt] = process.argv.slice(2);\n` +
        `const plain = await isPlainDirectory(mnt); const size = await treeSize(root); const rm = await removeTreeNoFollow(root);\n` +
        `process.stdout.write(JSON.stringify({ plain, size, rm, survived: existsSync(mnt + "/other-fs.txt") }));\n`,
    );
    // In a private mount namespace: a tmpfs on ops/mnt holding a file, bind mounts of the outside
    // directory and file, then the removal.
    const sh = 'mount -t tmpfs none "$1" && echo other > "$1/other-fs.txt" && mount --bind "$5" "$6" && mount --bind "$7" "$8" && exec "$2" "$3" "$4" "$1"';
    const r = spawnSync("unshare", ["-rm", "sh", "-c", sh, "sh", mnt, process.execPath, script, root, outside, bound, join(base, "outside-file.txt"), boundFile], {
      encoding: "utf8",
      timeout: 30_000,
    });
    expect(r.status, r.stderr).toBe(0);
    const out = JSON.parse(r.stdout) as { plain: boolean; size: { bytes: number }; rm: { removedFiles: number; failures: { path: string; code: string }[] }; survived: boolean };
    expect(out.plain).toBe(false);
    expect(out.size.bytes).toBe(2); // "{}" only: nothing below or at a mount point is counted
    expect(out.rm.removedFiles).toBe(1);
    expect(out.rm.failures).toEqual(expect.arrayContaining([
      { path: mnt, code: "MOUNT_POINT" },
      { path: bound, code: "MOUNT_POINT" },
      { path: boundFile, code: "MOUNT_POINT" },
    ]));
    expect(out.survived).toBe(true);
    // The bind mounts' sources were never touched (the namespace, and with it the mounts, is gone now).
    expect(await readFile(join(outside, "keep.txt"), "utf8")).toBe("outside");
    expect(await readFile(join(base, "outside-file.txt"), "utf8")).toBe("outside file");
  });
});

describe("the Linux mount table (workspace/mounts.ts)", () => {
  it("lists every mount point of /proc/self/mountinfo, with the kernel's escapes decoded", () => {
    const text = [
      "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw",
      "41 22 8:2 /home/u/outside /home/u/repo/bound rw,relatime shared:1 - ext4 /dev/sda2 rw",
      "42 22 0:45 / /home/u/repo/with\\040space rw - tmpfs none rw",
      "43 22 8:2 /etc/hosts /home/u/repo/file\\134name rw - ext4 /dev/sda2 rw",
      "",
    ].join("\n");
    expect([...parseMountInfo(text)]).toEqual(["/", "/home/u/repo/bound", "/home/u/repo/with space", "/home/u/repo/file\\name"]);
  });

  it.runIf(process.platform === "linux")("reads the mount id of an open file and of a directory: the same mount gives the same id", async () => {
    const dir = await mkdtemp(join(tmpdir(), "arl-mntid-"));
    await writeFile(join(dir, "f.txt"), "x");
    const fh = await open(join(dir, "f.txt"), "r");
    try {
      const fileId = await mountIdOfFd(fh.fd);
      expect(Number.isSafeInteger(fileId)).toBe(true);
      expect(await mountIdOfDir(dir)).toBe(fileId);
    } finally {
      await fh.close();
    }
    expect(await mountIdOfDir(join(dir, "missing"))).toBeNull();
    expect(await mountIdOfFd(1_000_000)).toBeNull();
  });
});
