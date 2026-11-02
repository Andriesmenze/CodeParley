// Scope end to end on this repository (shared contract, Windows and Linux): a subdirectory
// launch resolves to the git top level through the real git, and configured-root authority is
// enforced with the platform's path rules (workspace/paths.ts).

import { describe, it, expect } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveNativeExecutable } from "../src/process/native-resolve.js";
import { resolveGitTopLevel } from "../src/workspace/git-toplevel.js";
import { canonicalizePath, samePath } from "../src/workspace/paths.js";
import { computeAllowedRoots, resolveScope, defaultHardExclusions } from "../src/workspace/scope.js";
import { supported, win } from "./helpers/git-fixture.js";

// test/ -> repo root
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const nowhere = win ? "C:\\definitely\\not\\here" : "/definitely/not/here";
const someDataHome = win ? "C:\\nope\\CodeParley" : "/nope/code-parley";

describe.skipIf(!supported)("scope end-to-end on this repository", () => {
  it("resolves a subdirectory launch to the git top level and enforces configured-root authority", async () => {
    const git = await resolveNativeExecutable("git");
    expect(git.ok).toBe(true);

    const canonRepo = await canonicalizePath(repoRoot);
    const subdir = join(canonRepo, "src");

    // The one real git call in M1.1: subdir -> top level.
    const top = await resolveGitTopLevel(subdir, { gitExe: git.path! });
    expect(samePath(top, canonRepo)).toBe(true);

    // Allowed roots = the repo's parent; hard exclusions applied.
    const parent = await canonicalizePath(join(canonRepo, ".."));
    const allowed = await computeAllowedRoots([parent], [], defaultHardExclusions(process.env, someDataHome), canonicalizePath);
    expect(allowed.some((r) => samePath(r, parent))).toBe(true);

    const res = await resolveScope(
      { allowedRoots: allowed, repositoryRootArg: subdir },
      { canonicalize: canonicalizePath, resolveGitTopLevel: (p) => resolveGitTopLevel(p, { gitExe: git.path! }) },
    );
    expect(samePath(res.repositoryRoot, canonRepo)).toBe(true);
  });

  it("rejects a repository outside the allowed roots", async () => {
    const git = await resolveNativeExecutable("git");
    const canonRepo = await canonicalizePath(repoRoot);
    await expect(
      resolveScope(
        { allowedRoots: [nowhere], repositoryRootArg: canonRepo },
        { canonicalize: canonicalizePath, resolveGitTopLevel: (p) => resolveGitTopLevel(p, { gitExe: git.path! }) },
      ),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "SCOPE_REPO_ROOT_OUTSIDE_ALLOWED");
  });
});
