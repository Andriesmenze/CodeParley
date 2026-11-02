import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, realpath } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizePath, isContainedIn } from "../src/workspace/win-paths.js";
import { isReparsePoint, firstLinkComponent, assertNoLinkInPath } from "../src/workspace/links.js";

const win = process.platform === "win32";

function mklinkJunction(link: string, target: string): boolean {
  const r = spawnSync(process.env["ComSpec"] ?? "cmd.exe", ["/c", "mklink", "/J", link, target], { windowsHide: true });
  return r.status === 0;
}
function mklinkSymlinkDir(link: string, target: string): boolean {
  const r = spawnSync(process.env["ComSpec"] ?? "cmd.exe", ["/c", "mklink", "/D", link, target], { windowsHide: true });
  return r.status === 0;
}

describe.skipIf(!win)("canonicalizePath (Windows)", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await realpath(await mkdtemp(join(tmpdir(), "arl-canon-")));
    await mkdir(join(dir, "real"), { recursive: true });
    await writeFile(join(dir, "real", "f.txt"), "x");
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("resolves an existing path and matches case-insensitively", async () => {
    const canon = await canonicalizePath(join(dir, "REAL", "f.txt").toUpperCase());
    expect(isContainedIn(canon, dir)).toBe(true);
    expect(canon.toLowerCase()).toBe(join(dir, "real", "f.txt").toLowerCase());
  });

  it("resolves the nearest existing ancestor for a non-existent path (rule 5)", async () => {
    const canon = await canonicalizePath(join(dir, "real", "does", "not", "exist.txt"));
    expect(canon.toLowerCase().startsWith((await realpath(join(dir, "real"))).toLowerCase())).toBe(true);
    expect(canon.toLowerCase().endsWith("does\\not\\exist.txt")).toBe(true);
  });
});

describe.skipIf(!win)("links and reparse points (Windows)", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await realpath(await mkdtemp(join(tmpdir(), "arl-links-")));
    await mkdir(join(dir, "target"), { recursive: true });
    await writeFile(join(dir, "target", "secret.txt"), "s");
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("detects a junction as a reparse point and refuses paths through it", async () => {
    const link = join(dir, "jlink");
    const ok = mklinkJunction(link, join(dir, "target"));
    expect(ok, "mklink /J should succeed without admin").toBe(true);

    expect(await isReparsePoint(link)).toBe(true);
    expect(await isReparsePoint(join(dir, "target"))).toBe(false);

    const offending = await firstLinkComponent(join(link, "secret.txt"), dir);
    expect(offending?.toLowerCase()).toBe(link.toLowerCase());

    await expect(assertNoLinkInPath(join(link, "secret.txt"), dir)).rejects.toSatisfy(
      (e) => (e as { code: string }).code === "LINK_NOT_ALLOWED",
    );

    // A path with no link component passes.
    await expect(assertNoLinkInPath(join(dir, "target", "secret.txt"), dir)).resolves.toBeUndefined();
  });

  it("detects a directory symlink when creatable (else skips)", async () => {
    const link = join(dir, "slink");
    if (!mklinkSymlinkDir(link, join(dir, "target"))) return; // needs admin / Developer Mode
    expect(await isReparsePoint(link)).toBe(true);
  });
});
