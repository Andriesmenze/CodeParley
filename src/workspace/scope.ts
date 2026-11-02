// Workspace scope resolution (plan §8.2, D-03). Configured allowed roots are the ONLY
// authority; client roots (from the host) are advisory and, in strict mode, require the
// repository to be associated with a client root (MR-H). Pure logic: the filesystem and
// git are injected so this is unit-testable without either.

import { DomainError } from "../common/errors.js";
import { isContainedIn, isFilesystemRoot, PATH_RULES, pathKey, samePath } from "./paths.js";

export interface ScopeWarning {
  code: string;
  detail: string;
}

export interface ScopeInputs {
  /** Canonicalized allowed roots (already passed through computeAllowedRoots). */
  allowedRoots: string[];
  /**
   * Canonicalized client roots from the host session (advisory). `null`/absent: the client
   * supplies no roots (no roots capability), so association cannot be checked. `[]`: the client
   * supplied roots, none of them usable — in strict mode nothing is associated (M1.6-15).
   */
  clientRoots?: string[] | null;
  /** Model-supplied repository selection (a raw path; will be canonicalized + git-resolved). */
  repositoryRootArg?: string | undefined;
  /** Strict mode: enforce repository association with a client root (plan §8.2 step 4). */
  enforceClientRoots?: boolean;
}

export interface ScopeResolution {
  repositoryRoot: string;
  allowedSnapshot: string[];
  clientRootsSnapshot: string[];
  warnings: ScopeWarning[];
}

export interface ScopeDeps {
  /** Canonicalize an absolute path (validate + realpath). */
  canonicalize(path: string): Promise<string>;
  /** Resolve the git top level of a directory, canonical. Rejects if not a worktree. */
  resolveGitTopLevel(path: string): Promise<string>;
}

/** Hard exclusions (plan §8.2 step 1). `containedDirs` exclude themselves and anything inside
 * them (system/data dirs); `exactDirs` exclude only an exact match (the user-profile dir
 * itself — projects commonly live under it, so its subdirectories stay allowed). */
export interface HardExclusions {
  containedDirs: string[];
  exactDirs: string[];
}

/**
 * Compute the authoritative allowed-roots set: canonicalize configured + launch roots,
 * drop hard exclusions (plan §8.2 step 1). Returns a de-duplicated canonical list.
 */
export async function computeAllowedRoots(
  configuredRoots: readonly string[],
  launchRoots: readonly string[],
  hardExclusions: HardExclusions,
  canonicalize: (p: string) => Promise<string>,
): Promise<string[]> {
  const raw = [...configuredRoots, ...launchRoots];
  const out: string[] = [];
  const seen = new Set<string>();
  const exclusions: HardExclusions = {
    containedDirs: await canonicalizeAll(hardExclusions.containedDirs, canonicalize),
    exactDirs: await canonicalizeAll(hardExclusions.exactDirs, canonicalize),
  };
  for (const r of raw) {
    let canon: string;
    try {
      canon = await canonicalize(r);
    } catch {
      continue; // a non-existent/invalid configured root is simply not authoritative
    }
    if (isHardExcluded(canon, exclusions)) continue;
    const key = pathKey(canon);
    if (!seen.has(key)) {
      seen.add(key);
      out.push(canon);
    }
  }
  return out;
}

/** Hard-exclusion test: a filesystem root, inside a contained dir, or an exact user-profile/home match. */
export function isHardExcluded(canonRoot: string, exclusions: HardExclusions): boolean {
  if (isFilesystemRoot(canonRoot)) return true; // a bare drive root, or `/`
  for (const ex of exclusions.exactDirs) {
    if (samePath(canonRoot, ex)) return true;
  }
  for (const ex of exclusions.containedDirs) {
    if (isContainedIn(canonRoot, ex)) return true;
  }
  return false;
}

/** Linux system directories that can never be, or contain, an allowed root (plan §1.13). */
export const LINUX_SYSTEM_DIRS: readonly string[] = ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/run", "/sbin", "/snap", "/sys", "/usr"];

/**
 * Build the default hard exclusions (plan §8.2 step 1). `otherDataHomes` are the default data
 * locations that are not in use (Windows: the CodeParley folder and the legacy AIReviewLoop
 * folder, §1.12; Linux: the configuration directory as well): none may ever become, or
 * contain, an allowed root. The user's profile (Windows) or home directory (Linux) itself is
 * excluded exactly; projects below it stay allowed.
 */
export function defaultHardExclusions(env: NodeJS.ProcessEnv, dataHome: string, otherDataHomes: readonly string[] = []): HardExclusions {
  const containedDirs: string[] = [];
  const exactDirs: string[] = [];
  if (PATH_RULES === "win32") {
    for (const name of ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"]) {
      const v = env[name];
      if (v) containedDirs.push(v);
    }
    if (env["USERPROFILE"]) exactDirs.push(env["USERPROFILE"]!);
  } else {
    containedDirs.push(...LINUX_SYSTEM_DIRS);
    if (env["HOME"]) exactDirs.push(env["HOME"]!);
  }
  containedDirs.push(dataHome, ...otherDataHomes.filter((d) => !samePath(d, dataHome)));
  return { containedDirs, exactDirs };
}

/** Resolve scope (plan §8.2 steps 2–5). */
export async function resolveScope(inputs: ScopeInputs, deps: ScopeDeps): Promise<ScopeResolution> {
  const allowed = inputs.allowedRoots;
  if (allowed.length === 0) {
    throw new DomainError("SCOPE_NOT_CONFIGURED", "no allowed roots are configured");
  }
  const clientRoots = inputs.clientRoots ?? [];
  const warnings: ScopeWarning[] = [];

  // Step 2: pick the candidate directory.
  let candidate: string;
  if (inputs.repositoryRootArg) {
    candidate = inputs.repositoryRootArg;
  } else {
    const inScopeClientRoots = clientRoots.filter((c) => isInsideAny(c, allowed));
    if (inScopeClientRoots.length === 1) {
      candidate = inScopeClientRoots[0]!;
    } else {
      throw new DomainError(
        "REPOSITORY_NOT_SPECIFIED",
        "no repository_root given and the client roots do not identify exactly one repository inside the allowed roots",
      );
    }
  }

  // Step 3: resolve the git top level and require it inside the allowed roots. The top level
  // is the candidate or an ancestor of it, so a candidate outside every allowed root is refused
  // before git runs there at all (git would read that directory, and its answer would tell the
  // host whether an arbitrary folder is a repository).
  if (!isInsideAny(candidate, allowed)) {
    throw new DomainError("SCOPE_REPO_ROOT_OUTSIDE_ALLOWED", `repository is outside the allowed roots: ${candidate}`, {
      details: { candidate, allowed },
    });
  }
  const repositoryRoot = await deps.resolveGitTopLevel(candidate);
  if (!isInsideAny(repositoryRoot, allowed)) {
    throw new DomainError("SCOPE_REPO_ROOT_OUTSIDE_ALLOWED", `repository root is outside the allowed roots: ${repositoryRoot}`, {
      details: { repositoryRoot, allowed },
    });
  }

  // Step 4: client-root association (advisory, or enforced in strict mode).
  warnings.push(...associationCheck(repositoryRoot, inputs.clientRoots, inputs.enforceClientRoots === true, "repository is not associated with any client root"));

  return {
    repositoryRoot,
    allowedSnapshot: [...allowed],
    clientRootsSnapshot: [...clientRoots],
    warnings,
  };
}

/**
 * Re-evaluate a prior resolution after roots/config change (MR-H). Re-runs step 1 (via the
 * freshly computed allowedRoots passed in) and step 3/4 containment against the known
 * repository root. Throws SCOPE_REVOKED or (strict) REPO_OUTSIDE_SESSION_ROOTS if the repo
 * is no longer permitted.
 */
export function reevaluateScope(
  repositoryRoot: string,
  current: { allowedRoots: string[]; clientRoots?: string[] | null; enforceClientRoots?: boolean },
): ScopeWarning[] {
  if (current.allowedRoots.length === 0) {
    throw new DomainError("SCOPE_NOT_CONFIGURED", "no allowed roots are configured");
  }
  if (!isInsideAny(repositoryRoot, current.allowedRoots)) {
    throw new DomainError("SCOPE_REVOKED", `repository root is no longer inside the allowed roots: ${repositoryRoot}`, {
      details: { repositoryRoot, allowed: current.allowedRoots },
    });
  }
  return associationCheck(repositoryRoot, current.clientRoots, current.enforceClientRoots === true, "repository is not associated with any client root after roots changed");
}

/**
 * Plan §8.2 step 4. A client that supplied roots must have one the repository lies inside or
 * above: otherwise strict mode refuses (REPO_OUTSIDE_SESSION_ROOTS) and advisory mode warns.
 * An EMPTY supplied list is refused in strict mode too — no root means no association, and
 * treating it like "no roots capability" let a client clear its roots to bypass strict mode
 * (dogfood review, M1.6-15); advisory mode stays silent for it, as before. A client without
 * roots (`null`/absent) cannot be checked: strict mode is enforceable only where roots exist.
 */
function associationCheck(repositoryRoot: string, clientRoots: readonly string[] | null | undefined, enforce: boolean, message: string): ScopeWarning[] {
  if (clientRoots === null || clientRoots === undefined) return [];
  if (isAssociatedWithAny(repositoryRoot, clientRoots)) return [];
  if (enforce) {
    throw new DomainError("REPO_OUTSIDE_SESSION_ROOTS", clientRoots.length === 0 ? `${message} (the client supplied no usable root): ${repositoryRoot}` : `${message}: ${repositoryRoot}`, {
      details: { repositoryRoot, clientRoots: [...clientRoots] },
    });
  }
  return clientRoots.length > 0 ? [{ code: "REPO_OUTSIDE_SESSION_ROOTS", detail: `repository ${repositoryRoot} is not inside or above any client session root` }] : [];
}

function isInsideAny(path: string, roots: readonly string[]): boolean {
  return roots.some((r) => isContainedIn(path, r));
}

/** Associated = the repo is inside a client root, or above it (contains it), or equal. */
function isAssociatedWithAny(repo: string, clientRoots: readonly string[]): boolean {
  return clientRoots.some((c) => isContainedIn(repo, c) || isContainedIn(c, repo));
}

async function canonicalizeAll(paths: readonly string[], canonicalize: (p: string) => Promise<string>): Promise<string[]> {
  const out: string[] = [];
  for (const p of paths) {
    try {
      out.push(await canonicalize(p));
    } catch {
      /* skip unresolved exclusions */
    }
  }
  return out;
}
