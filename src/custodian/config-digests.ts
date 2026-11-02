// P3.4C-4: the digest schemes of the custodian-held configuration (contract §2.2), shared by the engine and the simulated
// custodian, and pinned byte for byte against the real custodian (Ledger/ConfigRecords.cs ConfigValidation, EngineJson)
// by the shared corpus test/fixtures/config-digest-corpus.json. PURE: no I/O.

import { sha256OfCanonicalJson } from "../common/hash.js";

export const CHECK_DEFINITION_DIGEST_SCHEMA = "arl.check-definition.v1";
export const CAPTURE_RULES_CONFIG_SCHEMA = "arl.capture-rules-config.v1";
export const REPOSITORY_CONFIG_SCHEMA = "arl.repository-config.v1";

/** A check definition in the engine's canonical form (src/checks/project-config.ts normalizeCheckDefinition). */
export interface HeldDefinition {
  argv: string[];
  cwd: string;
  timeout_seconds: number;
  env: Record<string, string>;
  env_passthrough: string[];
  freshness_inputs: string[];
  description?: string;
}

/** The capture rules a protected run uses (the custodian's record; config.json `capture` without its defaults). */
export interface HeldCaptureRules {
  excludeGlobs: string[];
  contextInclude: string[];
  maxFileBytes: number;
  maxExportBytes: number;
  maxDiffBytes: number;
}

/** `arl.check-definition.v1`: the engine's checkDefinitionDigest, computed by the custodian from the held definition. */
export function definitionDigest(name: string, def: HeldDefinition): string {
  return sha256OfCanonicalJson({ schema: CHECK_DEFINITION_DIGEST_SCHEMA, name, def });
}

/** `arl.capture-rules-config.v1`: the digest of the configured capture rules (not the per-capture record, which adds the
 * repository's own exclusions). */
export function captureRulesConfigDigest(r: HeldCaptureRules): string {
  return sha256OfCanonicalJson({
    schema: CAPTURE_RULES_CONFIG_SCHEMA,
    exclude_globs: r.excludeGlobs,
    context_include: r.contextInclude,
    max_file_bytes: r.maxFileBytes,
    max_export_bytes: r.maxExportBytes,
    max_diff_bytes: r.maxDiffBytes,
  });
}

/** `arl.repository-config.v1`: every P, C and M field of a repository record, without its own digest. */
export function repositoryConfigDigest(content: Record<string, unknown>): string {
  const { configDigest: _drop, ...rest } = content;
  return sha256OfCanonicalJson({ ...rest, schema: REPOSITORY_CONFIG_SCHEMA });
}
