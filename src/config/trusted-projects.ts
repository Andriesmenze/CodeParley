// Trusted project configuration (plan §7.1 layer 3, §14.1, R-35): keyed by canonical
// worktree path with the root commit as a consistency check. Read by the engine; written
// ONLY by the `code-parley checks approve|revoke` CLI (M1.3), atomically and under a
// lock so two CLI sessions cannot lose each other's update. There is no MCP write path.

import { join, dirname } from "node:path";
import { DomainError, isDomainError } from "../common/errors.js";
import { atomicWriteFile, readTextIfExists } from "../store/atomic.js";
import { acquireRunLock } from "../store/locks.js";
import type { OwnerRecord } from "../store/owner.js";
import { pathKey, withoutTrailingSeparator } from "../workspace/paths.js";
import { parseTrustProjects, type ProjectEntry, type TrustProjects } from "../schemas/trust.js";

export async function loadTrustProjects(trustProjectsPath: string): Promise<TrustProjects> {
  const raw = await readTextIfExists(trustProjectsPath);
  if (raw == null) return {};
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    throw new DomainError("CONFIG_INVALID", `trust/projects.json is not valid JSON: ${String((e as Error).message)}`);
  }
  try {
    return parseTrustProjects(json);
  } catch (e) {
    throw new DomainError("CONFIG_INVALID", `trust/projects.json failed validation: ${String((e as Error).message)}`);
  }
}

export interface TrustedProjectLookup {
  entry: ProjectEntry | null;
  /** Null if no entry; true/false if an entry exists and its root_commit matches. */
  rootCommitMatches: boolean | null;
}

/**
 * Find the trusted entry for a canonical worktree path (case-insensitive key match on Windows, exact on Linux) and
 * check root-commit consistency (R-35). A mismatch means the trusted config was recorded for
 * a different repository at that path; callers treat the entry as not applicable.
 */
export function lookupTrustedProject(
  projects: TrustProjects,
  canonicalWorktreePath: string,
  currentRootCommit: string | null,
): TrustedProjectLookup {
  const target = pathKey(canonicalWorktreePath);
  for (const [key, entry] of Object.entries(projects)) {
    if (pathKey(key) === target) {
      // A recorded root must be found again: no current root (HEAD unborn) is a mismatch.
      let rootCommitMatches: boolean | null = null;
      if (entry.root_commit != null) rootCommitMatches = entry.root_commit === currentRootCommit;
      return { entry, rootCommitMatches };
    }
  }
  return { entry: null, rootCommitMatches: null };
}

/**
 * Read-modify-write trust/projects.json under its lock. `mutate` receives the parsed file
 * and returns the next content; the write is atomic (fsync + rename).
 */
export async function updateTrustProjects(
  trustProjectsPath: string,
  owner: OwnerRecord,
  mutate: (current: TrustProjects) => TrustProjects,
): Promise<TrustProjects> {
  const lockDir = join(dirname(trustProjectsPath), ".projects.lock");
  const started = Date.now();
  for (;;) {
    let lock;
    try {
      lock = await acquireRunLock(lockDir, owner);
    } catch (e) {
      if (isDomainError(e) && e.code === "STORE_LOCKED" && Date.now() - started < 5000) {
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
    try {
      const next = parseTrustProjects(mutate(await loadTrustProjects(trustProjectsPath)));
      await atomicWriteFile(trustProjectsPath, JSON.stringify(next, null, 2) + "\n");
      return next;
    } finally {
      await lock.release();
    }
  }
}

/** The key under which an entry for this worktree is stored (an existing case variant wins). */
export function trustKeyFor(projects: TrustProjects, canonicalWorktreePath: string): string {
  const target = pathKey(canonicalWorktreePath);
  return Object.keys(projects).find((k) => pathKey(k) === target) ?? withoutTrailingSeparator(canonicalWorktreePath);
}
