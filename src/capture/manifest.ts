// Limitations and the model-facing manifest (plan §9.3 step 5, §9.5, §11.2, MR-F). Pure.
//
// Local limitations carry exact paths. Model-facing limitations never name — and the
// model-facing manifest never lists or hashes — a confidential (`excluded`) or
// repository-context-excluded path: those appear only as counts. `assertNoWithheldLeak`
// re-checks the finished manifest as a runtime invariant before it is written.

import { sha256OfCanonicalJson } from "../common/hash.js";
import type { ChangeEntry, Limitation, ReviewManifest, SourceEntry } from "../schemas/capture.js";

export interface LimitationInputs {
  entries: readonly SourceEntry[];
  changes: readonly ChangeEntry[];
  instability: readonly { path: string; reason: string }[];
  skipWorktreeAbsent: readonly string[];
  baseUnavailable: readonly { path: string; reason: string }[];
  exportOverCap: boolean;
  inProgress: readonly string[];
  externalGitDir: boolean;
  repoPreferenceWarnings: readonly string[];
  diffProblem: string | null;
}

export interface Limitations {
  local: Limitation[];
  model: Limitation[];
}

/** The set of paths whose names/hashes must never reach a model (MR-F). */
export function withheldPaths(entries: readonly SourceEntry[], changes: readonly ChangeEntry[]): Set<string> {
  const s = new Set<string>();
  for (const e of entries) if (e.class === "excluded" || e.disposition === "excluded_repo_context") s.add(e.path);
  for (const c of changes) if (c.confidential) {
    s.add(c.path);
    if (c.old_path) s.add(c.old_path);
  }
  return s;
}

export function buildLimitations(i: LimitationInputs): Limitations {
  const withheld = withheldPaths(i.entries, i.changes);
  const local: Limitation[] = [];
  const model: Limitation[] = [];

  /** Add a per-path limitation: local keeps all paths; model keeps non-withheld paths + a withheld count. */
  const add = (code: string, detail: string, paths: readonly string[]) => {
    if (paths.length === 0) return;
    local.push({ code, detail, paths: [...paths], count: paths.length });
    const visible = paths.filter((p) => !withheld.has(p));
    const hidden = paths.length - visible.length;
    if (visible.length === 0 && hidden === 0) return;
    model.push({
      code,
      detail: hidden > 0 ? `${detail} (${hidden} confidential path(s) not named)` : detail,
      ...(visible.length > 0 ? { paths: visible } : {}),
      count: paths.length,
    });
  };
  /** Add a count-only limitation that names nothing in the model-facing form. */
  const addCount = (code: string, detail: string, paths: readonly string[]) => {
    if (paths.length === 0) return;
    local.push({ code, detail, paths: [...paths], count: paths.length });
    model.push({ code, detail, count: paths.length });
  };
  const addPlain = (code: string, detail: string) => {
    local.push({ code, detail });
    model.push({ code, detail });
  };

  const byClass = (cls: SourceEntry["class"]) => i.entries.filter((e) => e.class === cls).map((e) => e.path);

  addCount("excluded_confidential", "files excluded by trusted confidentiality rules; names and contents withheld from the review", byClass("excluded"));
  addCount(
    "excluded_changed_file",
    "changed files excluded by trusted confidentiality rules; names and contents withheld — this change is NOT reviewed",
    i.changes.filter((c) => c.confidential).map((c) => c.path),
  );
  addCount(
    "excluded_repo_context",
    "unchanged files excluded from the context export by repository preferences",
    i.entries.filter((e) => e.disposition === "excluded_repo_context").map((e) => e.path),
  );
  add("size_skipped", "files larger than max_file_bytes; not exported", byClass("size_skipped"));
  add("context_reduced", "unchanged files dropped because the export exceeded max_export_bytes", i.entries.filter((e) => e.disposition === "context_reduced").map((e) => e.path));
  add("link_skipped", "links, junctions, reparse points or hard links; never followed or exported", byClass("link_skipped"));
  add("path_unsupported", "paths that cannot be captured on Windows or could not be read stably", byClass("path_unsupported"));
  add("submodule_not_reviewed", "submodule content is not exported; only pointer changes are listed", byClass("submodule"));

  const changed = (pred: (c: ChangeEntry) => boolean) => i.changes.filter(pred).map((c) => c.path);
  add("transformation_unsupported", "filter-managed or working-tree-encoding files: raw bytes exported, no diff", changed((c) => c.transformation_unsupported));
  add("eol_change", "line-ending style differs between base and current (from full raw bytes)", changed((c) => c.eol?.eol_change === true));
  add("eol_only_change", "only line endings changed (hidden in the prepared diff, which ignores CR at EOL)", changed((c) => c.eol?.eol_only_change === true));
  add("index_flag_hidden", "changed files marked skip-worktree or assume-unchanged in the index", changed((c) => c.index_flag_hidden));
  add("index_flag_absent", "skip-worktree files absent from the working tree (not treated as deletions)", i.skipWorktreeAbsent);
  add("base_unavailable", "base content not exported for these changed files", i.baseUnavailable.map((b) => b.path));
  add("diff_truncated", "prepared diff truncated for these files", changed((c) => c.diff === "truncated"));
  add("diff_omitted", "prepared diff omitted for these files (total diff cap)", changed((c) => c.diff === "omitted"));
  add("source_changed_during_capture", "source changed while it was being captured; this evidence is stale", i.instability.map((x) => x.path));

  if (i.exportOverCap) addPlain("export_over_cap", "changed and context files alone exceed max_export_bytes; all of them were kept");
  if (i.inProgress.length > 0) addPlain("operation_in_progress", `repository operation in progress: ${i.inProgress.join(", ")}`);
  if (i.externalGitDir) addPlain("external_git_dir", "the git directory lies outside the work tree (linked worktree or separate git dir)");
  for (const w of i.repoPreferenceWarnings) addPlain("repo_preferences_warning", w);
  if (i.diffProblem) addPlain("prepared_diff_unavailable", i.diffProblem);
  return { local, model };
}

/** Compute the manifest digest over everything except the digest field itself. */
export function finalizeManifest(m: Omit<ReviewManifest, "manifest_digest">): ReviewManifest {
  return { ...m, manifest_digest: sha256OfCanonicalJson(m) };
}

/**
 * Runtime invariant (MR-F): no string value anywhere in the model-facing object equals a
 * withheld path or a withheld file's hash. Throws if violated.
 */
export function assertNoWithheldLeak(obj: unknown, withheld: ReadonlySet<string>, withheldHashes: ReadonlySet<string>): void {
  const visit = (v: unknown): void => {
    if (typeof v === "string") {
      if (withheld.has(v) || withheldHashes.has(v)) throw new Error("model-facing data would disclose a confidential exclusion");
      return;
    }
    if (Array.isArray(v)) v.forEach(visit);
    else if (v && typeof v === "object") Object.values(v).forEach(visit);
  };
  visit(obj);
}
