// Step 6: the tests' temporary directories and files are removed after each test file (helpers/temp-dirs.ts, called by
// the setup file), never through a link: fixtures hold junctions and symbolic links on purpose, and what they point to
// outside the fixture must survive its removal.

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tempDir } from "./helpers/git-fixture.js";
import { removeTrackedTemp, trackTemp } from "./helpers/temp-dirs.js";

/** Run `fn` with CP_TEST_KEEP_TMP set to `value` (undefined: unset), whatever the caller's environment says. */
async function withKeep<T>(value: string | undefined, fn: () => Promise<T>): Promise<T> {
  const before = process.env["CP_TEST_KEEP_TMP"];
  if (value === undefined) delete process.env["CP_TEST_KEEP_TMP"];
  else process.env["CP_TEST_KEEP_TMP"] = value;
  try {
    return await fn();
  } finally {
    if (before === undefined) delete process.env["CP_TEST_KEEP_TMP"];
    else process.env["CP_TEST_KEEP_TMP"] = before;
  }
}

describe("the tests' temporary directories (Step 6)", () => {
  it("removes what a test file tracked, directories and files, and never follows a link out of them", async () => {
    // An untracked directory outside every fixture, which the fixture links to.
    const outside = await mkdtemp(join(tmpdir(), "cp-tmpdirs-outside-"));
    try {
      await writeFile(join(outside, "keep.txt"), "outside");
      const fixture = await tempDir("cp-tmpdirs-");
      await mkdir(join(fixture, "repo", ".git"), { recursive: true });
      await writeFile(join(fixture, "repo", "a.txt"), "a");
      // A junction on Windows (no privilege needed), a symbolic link elsewhere.
      await symlink(outside, join(fixture, "repo", "dir-link"), "junction");
      // A tracked path that is itself a link: only the link goes.
      const link = trackTemp(join(tmpdir(), `cp-tmpdirs-link-${process.pid}-${Date.now()}`));
      await symlink(outside, link, "junction");
      const file = trackTemp(join(tmpdir(), `cp-tmpdirs-file-${process.pid}-${Date.now()}`));
      await writeFile(file, "");

      const r = await withKeep(undefined, removeTrackedTemp);
      expect(r).toMatchObject({ kept: false, removed: 3, failures: [] });
      for (const p of [fixture, link, file]) expect(existsSync(p), p).toBe(false);
      expect(readFileSync(join(outside, "keep.txt"), "utf8")).toBe("outside");
      // Nothing is left to remove: each path is removed once.
      expect(await withKeep(undefined, removeTrackedTemp)).toMatchObject({ removed: 0, failures: [] });
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("keeps everything with CP_TEST_KEEP_TMP=1, to inspect a run", async () => {
    const fixture = await tempDir("cp-tmpdirs-keep-");
    try {
      expect(await withKeep("1", removeTrackedTemp)).toMatchObject({ kept: true, removed: 0, failures: [] });
      expect(existsSync(fixture)).toBe(true);
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });
});
