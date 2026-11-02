// Scope resolution (plan §8.2, D-03, MR-H) as a SHARED CONTRACT: the same assertions run on
// every platform against that platform's path rules (workspace/paths.ts), with paths written
// once in a logical form and spelled per platform — `C:\src\repo` on Windows, `/src/repo` on
// Linux.

import { describe, it, expect } from "vitest";
import {
  computeAllowedRoots,
  resolveScope,
  reevaluateScope,
  isHardExcluded,
  type ScopeDeps,
} from "../src/workspace/scope.js";
import { isDomainError } from "../src/common/errors.js";
import { pathKey } from "../src/workspace/paths.js";

const win = process.platform === "win32";
/** A logical absolute path ("/src/repo") in this platform's spelling ("C:\src\repo" or "/src/repo"). */
const P = (logical: string): string => (win ? `C:${logical.split("/").join("\\")}` : logical);
const ROOT = win ? "C:\\" : "/";

// Fakes: identity canonicalize (inputs are already canonical in these tests) and a map-based
// git top-level resolver.
const idCanon = async (p: string): Promise<string> => {
  if (win) {
    const q = p.split("/").join("\\");
    return q.endsWith("\\") ? q.slice(0, -1) : q;
  }
  let q = p;
  while (q.length > 1 && q.endsWith("/")) q = q.slice(0, -1);
  return q;
};
function depsWithGit(map: Record<string, string>): ScopeDeps {
  return {
    canonicalize: idCanon,
    resolveGitTopLevel: async (p) => {
      const hit = Object.entries(map).find(([k]) => pathKey(k) === pathKey(p));
      if (!hit) throw Object.assign(new Error("not a worktree"), { code: "NOT_A_GIT_WORKTREE" });
      return hit[1];
    },
  };
}

describe("computeAllowedRoots + hard exclusions", () => {
  it("drops filesystem roots, system dirs, the user profile/home dir itself, and the data home — but keeps its subdirs", async () => {
    const exclusions = {
      containedDirs: [P("/Windows"), P("/Users/me/AppData/Local/CodeParley")],
      exactDirs: [P("/Users/me")],
    };
    const roots = await computeAllowedRoots(
      [ROOT, P("/Windows"), P("/Windows/System32"), P("/Users/me"), P("/Users/me/src"), P("/Users/me/AppData/Local/CodeParley/runs")],
      [],
      exclusions,
      idCanon,
    );
    expect(roots).toEqual([P("/Users/me/src")]);
  });

  it("isHardExcluded flags filesystem roots, contained system paths, and the exact profile/home dir", () => {
    const none = { containedDirs: [], exactDirs: [] };
    expect(isHardExcluded(ROOT, none)).toBe(true);
    if (win) expect(isHardExcluded("D:\\", none)).toBe(true);
    expect(isHardExcluded(P("/Windows/System32"), { containedDirs: [P("/Windows")], exactDirs: [] })).toBe(true);
    expect(isHardExcluded(P("/Users/me/src"), { containedDirs: [P("/Windows")], exactDirs: [P("/Users/me")] })).toBe(false);
    expect(isHardExcluded(P("/Users/me"), { containedDirs: [], exactDirs: [P("/Users/me")] })).toBe(true);
  });

  it("de-duplicates roots by the platform's name semantics (case-insensitive on Windows, exact on Linux)", async () => {
    const roots = await computeAllowedRoots([P("/src/Repo"), P("/src/repo")], [], { containedDirs: [], exactDirs: [] }, idCanon);
    expect(roots).toEqual(win ? [P("/src/Repo")] : [P("/src/Repo"), P("/src/repo")]);
  });
});

describe("resolveScope", () => {
  const allowed = [P("/src")];

  it("resolves a repository_root argument to its git top level inside the allowed roots", async () => {
    const deps = depsWithGit({ [P("/src/repo/sub")]: P("/src/repo"), [P("/src/repo")]: P("/src/repo") });
    const res = await resolveScope({ allowedRoots: allowed, repositoryRootArg: P("/src/repo/sub") }, deps);
    expect(res.repositoryRoot).toBe(P("/src/repo"));
    expect(res.warnings).toHaveLength(0);
  });

  it("errors when the resolved repo is outside the allowed roots", async () => {
    const deps = depsWithGit({ [P("/other/repo")]: P("/other/repo") });
    await expect(resolveScope({ allowedRoots: allowed, repositoryRootArg: P("/other/repo") }, deps)).rejects.toSatisfy(
      (e) => isDomainError(e) && (e as { code: string }).code === "SCOPE_REPO_ROOT_OUTSIDE_ALLOWED",
    );
    // A sub-directory inside an allowed root whose repository lies above it is outside as well.
    const above = depsWithGit({ [P("/src/repo/sub")]: P("/src") });
    await expect(resolveScope({ allowedRoots: [P("/src/repo")], repositoryRootArg: P("/src/repo/sub") }, above)).rejects.toSatisfy(
      (e) => (e as { code: string }).code === "SCOPE_REPO_ROOT_OUTSIDE_ALLOWED",
    );
  });

  it("never runs git for a path outside every allowed root (no repository oracle for the host)", async () => {
    let gitCalls = 0;
    const deps: ScopeDeps = {
      canonicalize: idCanon,
      resolveGitTopLevel: async () => {
        gitCalls++;
        throw Object.assign(new Error("not a worktree"), { code: "NOT_A_GIT_WORKTREE" });
      },
    };
    for (const p of [P("/etc"), P("/Users/me"), P("/other/not-a-repo")]) {
      await expect(resolveScope({ allowedRoots: allowed, repositoryRootArg: p }, deps)).rejects.toSatisfy((e) => (e as { code: string }).code === "SCOPE_REPO_ROOT_OUTSIDE_ALLOWED");
    }
    expect(gitCalls).toBe(0);
  });

  it("a case variant of an allowed root is inside it on Windows only (Linux names are case-sensitive)", async () => {
    const deps = depsWithGit({ [P("/SRC/repo")]: P("/SRC/repo") });
    const r = resolveScope({ allowedRoots: allowed, repositoryRootArg: P("/SRC/repo") }, deps);
    if (win) expect((await r).repositoryRoot).toBe(P("/SRC/repo"));
    else await expect(r).rejects.toSatisfy((e) => (e as { code: string }).code === "SCOPE_REPO_ROOT_OUTSIDE_ALLOWED");
  });

  it("picks the single in-scope client root when no argument is given", async () => {
    const deps = depsWithGit({ [P("/src/repo")]: P("/src/repo") });
    const res = await resolveScope({ allowedRoots: allowed, clientRoots: [P("/src/repo")] }, deps);
    expect(res.repositoryRoot).toBe(P("/src/repo"));
  });

  it("requires a repository when client roots are ambiguous", async () => {
    const deps = depsWithGit({});
    await expect(
      resolveScope({ allowedRoots: allowed, clientRoots: [P("/src/a"), P("/src/b")] }, deps),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "REPOSITORY_NOT_SPECIFIED");
  });

  it("errors when no roots are configured", async () => {
    await expect(resolveScope({ allowedRoots: [] }, depsWithGit({}))).rejects.toSatisfy(
      (e) => (e as { code: string }).code === "SCOPE_NOT_CONFIGURED",
    );
  });

  it("advisory client roots: warns when repo is not associated, strict mode errors", async () => {
    const deps = depsWithGit({ [P("/src/repo")]: P("/src/repo") });
    const warn = await resolveScope(
      { allowedRoots: allowed, repositoryRootArg: P("/src/repo"), clientRoots: [P("/src/elsewhere")] },
      deps,
    );
    expect(warn.warnings[0]?.code).toBe("REPO_OUTSIDE_SESSION_ROOTS");

    await expect(
      resolveScope(
        { allowedRoots: allowed, repositoryRootArg: P("/src/repo"), clientRoots: [P("/src/elsewhere")], enforceClientRoots: true },
        deps,
      ),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "REPO_OUTSIDE_SESSION_ROOTS");
  });

  it("associates a repo that is ABOVE a client root (subdirectory launch)", async () => {
    const deps = depsWithGit({ [P("/src/repo/pkg")]: P("/src/repo") });
    const res = await resolveScope(
      { allowedRoots: allowed, repositoryRootArg: P("/src/repo/pkg"), clientRoots: [P("/src/repo/pkg")], enforceClientRoots: true },
      deps,
    );
    expect(res.repositoryRoot).toBe(P("/src/repo"));
    expect(res.warnings).toHaveLength(0);
  });
});

describe("reevaluateScope (MR-H)", () => {
  it("revokes when the repo is no longer inside the allowed roots", () => {
    expect(() => reevaluateScope(P("/src/repo"), { allowedRoots: [P("/other")] })).toThrowError();
    try {
      reevaluateScope(P("/src/repo"), { allowedRoots: [P("/other")] });
    } catch (e) {
      expect((e as { code: string }).code).toBe("SCOPE_REVOKED");
    }
  });

  it("strict mode re-checks client-root association after roots change", () => {
    try {
      reevaluateScope(P("/src/repo"), { allowedRoots: [P("/src")], clientRoots: [P("/src/elsewhere")], enforceClientRoots: true });
      throw new Error("expected throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe("REPO_OUTSIDE_SESSION_ROOTS");
    }
  });

  it("stays valid (with a warning) in advisory mode", () => {
    const warnings = reevaluateScope(P("/src/repo"), { allowedRoots: [P("/src")], clientRoots: [P("/src/elsewhere")] });
    expect(warnings[0]?.code).toBe("REPO_OUTSIDE_SESSION_ROOTS");
  });
});

describe("an empty client-root list versus no roots capability (dogfood review, M1.6-15)", () => {
  const allowed = [P("/src")];
  const code = (f: () => unknown): string | null => {
    try {
      f();
      return null;
    } catch (e) {
      return (e as { code: string }).code;
    }
  };

  it("strict mode refuses a client that supplied an empty list (it cannot clear its roots to bypass association)", async () => {
    expect(code(() => reevaluateScope(P("/src/repo"), { allowedRoots: [P("/src")], clientRoots: [], enforceClientRoots: true }))).toBe("REPO_OUTSIDE_SESSION_ROOTS");
    const deps = depsWithGit({ [P("/src/repo")]: P("/src/repo") });
    await expect(
      resolveScope({ allowedRoots: allowed, repositoryRootArg: P("/src/repo"), clientRoots: [], enforceClientRoots: true }, deps),
    ).rejects.toSatisfy((e) => (e as { code: string }).code === "REPO_OUTSIDE_SESSION_ROOTS");
  });

  it("a client without roots (null) cannot be checked: allowed in strict mode, as specified (§8.2 step 4)", async () => {
    expect(reevaluateScope(P("/src/repo"), { allowedRoots: [P("/src")], clientRoots: null, enforceClientRoots: true })).toEqual([]);
    const deps = depsWithGit({ [P("/src/repo")]: P("/src/repo") });
    const res = await resolveScope({ allowedRoots: allowed, repositoryRootArg: P("/src/repo"), clientRoots: null, enforceClientRoots: true }, deps);
    expect(res.warnings).toEqual([]);
  });

  it("advisory mode is unchanged for an empty list: allowed, no warning", async () => {
    expect(reevaluateScope(P("/src/repo"), { allowedRoots: [P("/src")], clientRoots: [] })).toEqual([]);
    const deps = depsWithGit({ [P("/src/repo")]: P("/src/repo") });
    expect((await resolveScope({ allowedRoots: allowed, repositoryRootArg: P("/src/repo"), clientRoots: [] }, deps)).warnings).toEqual([]);
  });
});
