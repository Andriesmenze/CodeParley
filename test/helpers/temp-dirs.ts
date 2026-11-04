// Step 6: the temporary directories and files the tests make, removed after each test file. Fixtures are made under
// the system temporary directory (tempDir in git-fixture.ts, or trackTemp around a direct mkdtemp) and were left there:
// a full run left hundreds of megabytes, and nothing removed them before the disk was nearly full (Windows' Storage
// Sense, where it is on, acts when free space is low). The vitest setup file test/setup-temp-dirs.ts removes what a
// test file tracked once all its tests and hooks have run; each test file makes its own, so nothing else uses them.
//
// Removal never follows a link (src/store/remove-tree.ts): fixtures hold junctions and symbolic links on purpose, some
// pointing outside the directory removed, and on Linux a mount point is left in place. What cannot be removed (a file
// a process still holds open) is reported and left. CP_TEST_KEEP_TMP=1 keeps everything, to inspect a run.

const tracked: string[] = [];

/** Remove `path` (a directory or file the test file made under the temporary directory) after the file's tests. */
export function trackTemp(path: string): string {
  tracked.push(path);
  return path;
}

export interface TempRemoval {
  removed: number;
  kept: boolean;
  failures: { path: string; code: string }[];
}

/** Remove every path tracked so far, the latest first, never following a link; the setup file calls it once per file. */
export async function removeTrackedTemp(): Promise<TempRemoval> {
  const paths = tracked.splice(0).reverse();
  const out: TempRemoval = { removed: 0, kept: process.env["CP_TEST_KEEP_TMP"] === "1", failures: [] };
  if (paths.length === 0 || out.kept) return out;
  const { removeTreeNoFollow } = await import("../../src/store/remove-tree.js");
  for (const p of paths) {
    const r = await removeTreeNoFollow(p);
    out.failures.push(...r.failures);
    if (r.failures.length === 0) out.removed++;
  }
  return out;
}
