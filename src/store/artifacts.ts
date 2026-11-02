// Immutable artifact publication (plan §15.3). Artifacts (results, logs, events, prompts,
// raw output) are written and fsynced into fresh, uniquely-named paths BEFORE the state
// commit that references them. An artifact that nothing references is garbage and can never
// be mistaken for a result (recovery deletes such orphans). Artifacts are never rewritten.

import { mkdir } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { DomainError } from "../common/errors.js";
import { writeFileSynced, writeFileSyncedIn } from "./atomic.js";

export interface ArtifactRef {
  /** Path relative to the run directory, as stored in state (stable, portable). */
  ref: string;
  /** Absolute path on disk. */
  absolute: string;
}

/**
 * Publish an immutable artifact for an operation. Writes ops/<operationId>/<name> with
 * fsync and returns its reference. The caller references `ref` from the next state commit.
 */
export async function publishArtifact(
  runDir: string,
  opsDir: string,
  operationId: string,
  name: string,
  data: string | Buffer,
): Promise<ArtifactRef> {
  const absolute = join(opsDir, operationId, name);
  await writeFileSynced(absolute, data);
  const ref = toRunRelative(runDir, absolute);
  return { ref, absolute };
}

/**
 * As publishArtifact, for a writer that is not an operation of the run (an implementer
 * response): the run may be purged meanwhile — purge and retention move an idle run into the
 * trash — and its directory must never be recreated. So nothing is created recursively: each
 * directory below the run's own is created one level at a time, and a run that is gone fails
 * with RUN_NOT_FOUND (Codex review of PR #10). What was written before a purge moves with the
 * run into the trash.
 */
export async function publishArtifactInRun(runDir: string, opsDir: string, operationId: string, name: string, data: string | Buffer): Promise<ArtifactRef> {
  const absolute = join(opsDir, operationId, name);
  let dir = runDir;
  for (const segment of relative(runDir, dirname(absolute)).split(/[\\/]/)) {
    dir = join(dir, segment);
    try {
      await mkdir(dir);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === "ENOENT") throw runGone();
      if (code !== "EEXIST") throw e;
    }
  }
  try {
    await writeFileSyncedIn(absolute, data);
  } catch (e) {
    if ((e as { code?: string }).code === "ENOENT") throw runGone();
    throw e;
  }
  return { ref: toRunRelative(runDir, absolute), absolute };
}

function runGone(): DomainError {
  return new DomainError("RUN_NOT_FOUND", "the run no longer exists (it was purged while this was being recorded)");
}

/** Resolve an artifact ref (run-relative, "/"-separated) back to an absolute path. */
export function resolveArtifact(runDir: string, ref: string): string {
  return join(runDir, ...ref.split("/"));
}

function toRunRelative(runDir: string, absolute: string): string {
  const base = runDir.replace(/\\$/, "");
  let rel = absolute.startsWith(base) ? absolute.slice(base.length) : absolute;
  rel = rel.replace(/^[\\/]/, "").replace(/\\/g, "/");
  return rel;
}
