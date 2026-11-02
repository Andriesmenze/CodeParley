// Check identities (plan §10.3; MR-G).
//
// check_spec_id binds WHAT runs: the canonical definition (argv, cwd, trusted env values,
// passthrough NAMES, timeout, freshness-input list), the executable it resolves to (path,
// size, mtime) and the approved definition digest.
//
// execution_input_id binds what the run DEPENDED ON besides the source tree:
//   check_spec_id + digest of the effective child environment (every name and value the
//   child received, including passed-through values, which are never stored) + the SHA-256
//   of every configured freshness input read at execution start.
// A result is fresh only while this identity equals the one computed now, so changing a
// passthrough variable, PATH, or a freshness input (for example node_modules/.package-
// lock.json) makes an earlier result stale. Everything else the check touches (installed
// tools beyond the resolved executable, services, network content) is NOT bound: every
// result reports environment_bound "partial".

import { join } from "node:path";
import { sha256OfCanonicalJson, sha256OfString } from "../common/hash.js";
import { buildChildEnv, ENV_NAMES_CASE_INSENSITIVE, envNameKey } from "../process/env.js";
import { readWorkingFile } from "../capture/safe-read.js";
import type { ResolvedCommand } from "../process/command.js";
import { caseKey } from "../workspace/paths.js";
import type { CheckDefinition, FreshnessInputDigest } from "../schemas/checks.js";
import { normalizeRepoRelative } from "./project-config.js";

export const CHECK_SPEC_ID_SCHEMA = "arl.check-spec-id.v1";
export const EXECUTION_INPUT_ID_SCHEMA = "arl.execution-input-id.v1";
export const ENV_DIGEST_SCHEMA = "arl.check-env.v1";
export const FRESHNESS_DIGEST_SCHEMA = "arl.freshness-inputs.v1";

export interface SpecIdInput {
  name: string;
  def: CheckDefinition;
  definitionDigest: string;
  resolved: Pick<ResolvedCommand, "path" | "kind" | "size" | "mtimeMs"> | null;
}

export function computeCheckSpecId(i: SpecIdInput): string {
  return sha256OfCanonicalJson({
    schema: CHECK_SPEC_ID_SCHEMA,
    name: i.name,
    argv: i.def.argv,
    cwd: i.def.cwd,
    env: i.def.env,
    env_passthrough: i.def.env_passthrough,
    timeout_seconds: i.def.timeout_seconds,
    freshness_inputs: i.def.freshness_inputs,
    // Case-folded on Windows (NTFS), exact on Linux.
    executable: i.resolved ? { path: caseKey(i.resolved.path), kind: i.resolved.kind, size: i.resolved.size, mtime_ms: i.resolved.mtimeMs } : null,
    approval_digest: i.definitionDigest,
  });
}

export interface CheckEnv {
  env: Record<string, string>;
  /** Passthrough names refused by the secret denylist (approval already refuses them). */
  refused: string[];
  /** Configured passthrough names absent from the server environment. */
  missing: string[];
}

/** The explicit child environment for a check: platform basics, configured passthrough
 * names (screened), then the trusted constant `env` values. Never Claude/Codex credentials. */
export function buildCheckEnv(def: CheckDefinition, source: NodeJS.ProcessEnv): CheckEnv {
  const { env, refusedPassthrough } = buildChildEnv({ source, passthrough: def.env_passthrough, extra: def.env });
  const present = new Set(Object.keys(env).map(envNameKey));
  const missing = def.env_passthrough.filter((n) => !refusedPassthrough.includes(n) && !present.has(envNameKey(n)));
  return { env, refused: refusedPassthrough, missing };
}

/** Digest of every name and value the child receives. Names are case-folded on Windows, exact on Linux. */
export function computeEnvDigest(env: Readonly<Record<string, string>>): string {
  const rows = Object.entries(env)
    .map(([k, v]) => [ENV_NAMES_CASE_INSENSITIVE ? k.toUpperCase() : k, sha256OfString(v)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return sha256OfCanonicalJson({ schema: ENV_DIGEST_SCHEMA, vars: rows });
}

/** Read and hash every configured freshness input (no link following, plan §8.4). */
export async function hashFreshnessInputs(repoRoot: string, paths: readonly string[]): Promise<FreshnessInputDigest[]> {
  const out: FreshnessInputDigest[] = [];
  const linkCache = new Map<string, boolean>();
  for (const p of paths) {
    const n = normalizeRepoRelative(p, { allowRoot: false });
    if (!n.ok) {
      out.push({ path: p, state: "invalid_path", sha256: null, size: null });
      continue;
    }
    const r = await readWorkingFile(join(repoRoot, ...n.path.split("/")), { root: repoRoot, objectFormat: "sha1", maxRetainBytes: 0, retain: false, linkCache });
    if (r.kind === "file") out.push({ path: n.path, state: "file", sha256: r.sha256 ?? null, size: r.size ?? null });
    else if (r.kind === "link") out.push({ path: n.path, state: "link", sha256: r.sha256 ?? r.linkTargetSha256 ?? null, size: r.size ?? null });
    else out.push({ path: n.path, state: r.kind, sha256: null, size: null });
  }
  return out;
}

export function computeFreshnessDigest(entries: readonly FreshnessInputDigest[]): string {
  return sha256OfCanonicalJson({ schema: FRESHNESS_DIGEST_SCHEMA, inputs: entries.map((e) => [e.path, e.state, e.sha256, e.size]) });
}

export function computeExecutionInputId(i: { checkSpecId: string; envDigest: string; freshnessDigest: string }): string {
  return sha256OfCanonicalJson({ schema: EXECUTION_INPUT_ID_SCHEMA, check_spec_id: i.checkSpecId, env_digest: i.envDigest, freshness_digest: i.freshnessDigest });
}
