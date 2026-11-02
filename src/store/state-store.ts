// The authoritative run-state record and its single commit point (plan §15.3, F9, D-16).
//
// state.json is the one source of truth. A change becomes real only when state.json is
// atomically replaced with revision + 1. Mutation happens under the per-run lock with an
// optimistic re-read: we read the current revision inside the lock and write exactly
// revision + 1, so a torn or concurrent write cannot be mistaken for a committed state.

import { mkdir } from "node:fs/promises";
import { DomainError } from "../common/errors.js";
import { atomicWriteFile, readTextIfExists, writeFileExclusive } from "./atomic.js";
import { acquireRunLock, type RunLockHandle } from "./locks.js";
import { isDomainError } from "../common/errors.js";
import type { OwnerRecord } from "./owner.js";
import type { RunPaths } from "./paths.js";
import {
  STATE_SCHEMA_VERSION,
  StateRecordSchema,
  RunMetaSchema,
  type StateRecord,
  type RunMeta,
} from "../schemas/run-state.js";
import type { LockDeps } from "./locks.js";

/** Create a new run: write immutable run.json and the initial state.json (revision 0). */
export async function createRun(paths: RunPaths, meta: RunMeta, initialState: StateRecord): Promise<void> {
  await mkdir(paths.runDir, { recursive: true });
  await mkdir(paths.opsDir, { recursive: true });
  const metaOk = await writeFileExclusive(paths.runJson, JSON.stringify(RunMetaSchema.parse(meta), null, 2));
  if (!metaOk) throw new DomainError("INVALID_ARGUMENT", `run already exists: ${paths.runJson}`);
  const state = StateRecordSchema.parse({ ...initialState, revision: 0 });
  await atomicWriteFile(paths.stateJson, JSON.stringify(state, null, 2));
}

/** Read immutable run meta (plan §15.2). */
export async function readMeta(paths: RunPaths): Promise<RunMeta> {
  const raw = await readTextIfExists(paths.runJson);
  if (raw == null) throw new DomainError("RUN_NOT_FOUND", `run.json not found: ${paths.runJson}`);
  return RunMetaSchema.parse(JSON.parse(raw));
}

/** Read the authoritative state. Throws STORE_VERSION_UNSUPPORTED for a newer schema. */
export async function readState(paths: RunPaths): Promise<StateRecord> {
  const raw = await readTextIfExists(paths.stateJson);
  if (raw == null) throw new DomainError("RUN_NOT_FOUND", `state.json not found: ${paths.stateJson}`);
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch (e) {
    throw new DomainError("INTERNAL", `state.json is not valid JSON: ${String((e as Error).message)}`);
  }
  const versionOnly = parsedJson as { schema_version?: unknown };
  if (typeof versionOnly.schema_version === "number" && versionOnly.schema_version > STATE_SCHEMA_VERSION) {
    throw new DomainError("STORE_VERSION_UNSUPPORTED", `state.json schema_version ${versionOnly.schema_version} is newer than supported (${STATE_SCHEMA_VERSION}); opened read-only`, {
      details: { found: versionOnly.schema_version, supported: STATE_SCHEMA_VERSION },
    });
  }
  return StateRecordSchema.parse(parsedJson);
}

export interface CommitOptions {
  lockDeps?: LockDeps;
  now?: () => string;
  /** How long to keep retrying acquisition of the short run-mutation lock. Default 5000ms. */
  lockAcquireMs?: number;
}

/** Acquire the per-run mutation lock, retrying while it is held by a live writer (it is a
 * short critical section, so concurrent commits serialize rather than fail). Exported for
 * the purge, which deletes a run only while holding its lock (M1.6). */
export async function acquireRunLockWithRetry(lockDir: string, owner: OwnerRecord, opts: CommitOptions): Promise<RunLockHandle> {
  const budget = opts.lockAcquireMs ?? 5000;
  const started = Date.now();
  for (;;) {
    try {
      // A run's lock lives inside its directory: never recreate a run that was purged.
      return await acquireRunLock(lockDir, owner, opts.lockDeps ?? {}, { parentMustExist: true });
    } catch (e) {
      if (isDomainError(e) && e.code === "STORE_LOCKED" && Date.now() - started < budget) {
        await new Promise((r) => setTimeout(r, 15 + Math.floor(Math.random() * 30)));
        continue;
      }
      throw e;
    }
  }
}

/**
 * The single commit point. Under the per-run lock: read the current state, apply `mutate`
 * to produce the next logical content, then persist it as revision + 1. `mutate` must not
 * change `revision`/`updated_at` (they are managed here). Returns the committed record.
 */
export async function commitState(
  paths: RunPaths,
  owner: OwnerRecord,
  mutate: (current: StateRecord) => StateRecord,
  opts: CommitOptions = {},
): Promise<StateRecord> {
  const now = opts.now ?? (() => new Date().toISOString());
  const lock = await acquireRunLockWithRetry(paths.lockDir, owner, opts);
  try {
    const current = await readState(paths);
    const next = mutate(structuredCloneSafe(current));
    const committed: StateRecord = StateRecordSchema.parse({
      ...next,
      run_id: current.run_id,
      created_at: current.created_at,
      revision: current.revision + 1,
      updated_at: now(),
    });
    await atomicWriteFile(paths.stateJson, JSON.stringify(committed, null, 2));
    return committed;
  } finally {
    await lock.release();
  }
}

function structuredCloneSafe<T>(v: T): T {
  // Node 22/24 has global structuredClone; fall back to JSON round-trip for plain records.
  try {
    return structuredClone(v);
  } catch {
    return JSON.parse(JSON.stringify(v)) as T;
  }
}
