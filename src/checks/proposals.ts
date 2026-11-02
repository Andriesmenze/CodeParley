// Repository check proposals (`.code-parley/config.json`, legacy `.ai-loop/config.json`;
// plan §7.4, §14.2, §1.12). Untrusted and inert: they are only ever shown as
// `pending_approval` (CLI `checks list`, MCP `create_review_run`) and approved through the
// CLI. Read with the capture's safe reader (no links, bounded). A preferences file matching
// a trusted confidentiality exclusion is never read (its content would otherwise reach the
// host through `pending_approval`).

import { join } from "node:path";
import { readWorkingFile, type ReadResult } from "../capture/safe-read.js";
import { compileGlobs, matchesAny } from "../capture/globs.js";
import { LEGACY_REPO_PREFERENCES_PATH, REPO_PREFERENCES_PATH, chooseRepoPreferences } from "../schemas/repo-preferences.js";
import { parseProposals, type ParsedProposals } from "./project-config.js";

export interface ProposalReadOptions {
  /** Trusted confidentiality exclusions (`capture.exclude_globs`). */
  excludeGlobs?: readonly string[];
}

async function readPreferenceFile(repoRoot: string, rel: string): Promise<ReadResult> {
  return readWorkingFile(join(repoRoot, ...rel.split("/")), { root: repoRoot, objectFormat: "sha1", maxRetainBytes: 256 * 1024, retain: true, linkCache: new Map() });
}

/** Read and parse the repository's proposals; null when no preferences file exists. */
export async function readRepoProposals(repoRoot: string, opts: ProposalReadOptions = {}): Promise<ParsedProposals | null> {
  const excluded = compileGlobs(opts.excludeGlobs ?? []);
  const reads = new Map<string, ReadResult>();
  for (const rel of [REPO_PREFERENCES_PATH, LEGACY_REPO_PREFERENCES_PATH]) reads.set(rel, await readPreferenceFile(repoRoot, rel));
  const choice = chooseRepoPreferences(
    (p) => (reads.get(p)?.kind ?? "missing") !== "missing",
    (p) => matchesAny(excluded, p),
  );
  if (!choice.path) return null;
  const r = reads.get(choice.path)!;
  const warn = (w: string): ParsedProposals => ({ checks: {}, profiles: {}, warnings: [...choice.warnings, w] });
  if (r.kind !== "file" || !r.bytes) return warn(`${choice.path} could not be read safely (${r.kind}); ignored`);
  let json: unknown;
  try {
    json = JSON.parse(r.bytes.toString("utf8"));
  } catch {
    return warn(`${choice.path} is not valid JSON; ignored`);
  }
  const parsed = parseProposals(json);
  return { ...parsed, warnings: [...choice.warnings, ...parsed.warnings] };
}
