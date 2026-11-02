// Phase 4 foundation — scan a delegated fixer's workspace tree into the typed facts the policy
// evaluates (policy/delegated-fix.ts), and assemble the bound, inert proposal. Reuses the capture
// machinery so a delegated fix is held to the same filesystem-escape rules as a review capture:
//  - readWorkingFile (capture/safe-read.ts) hashes exactly the bytes read and refuses a link, a hard
//    link (nlink>1), an 8.3/other alias (realpath mismatch), a special file, or a file that changed
//    mid-read — each becomes a scan anomaly, so a proposal built on it is rejected (fail toward refusal);
//  - a directory that is itself a link/reparse point/mount point is never descended (isPlainDirectory);
//  - names unsafe on Windows OR POSIX, and case-folding collisions, are anomalies (portable rules).
// A bounded walk: at most maxEntries and maxDepth, else `complete:false` (an incomplete scan never
// yields an eligible proposal). Nothing here writes to the workspace or applies anything.

import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { readWorkingFile } from "./safe-read.js";
import { isBinaryStats } from "./eol.js";
import { isPlainDirectory } from "../store/remove-tree.js";
import { PATH_RULES } from "../workspace/paths.js";
import {
  boundaryDigest,
  evaluateFix,
  foldPath,
  manifestDigest,
  portableSegmentProblem,
  proposalDigest,
  type FixBoundary,
  type FixEvaluation,
  type FixFileEntry,
  type FixPostFile,
  type FixPostScan,
  type FixProposal,
  type ScanAnomaly,
  FIX_SCHEMA_VERSION,
} from "../policy/delegated-fix.js";

export interface FixScanLimits {
  maxEntries: number;
  maxDepth: number;
  maxFileBytes: number;
}

export const DEFAULT_SCAN_LIMITS: FixScanLimits = { maxEntries: 50_000, maxDepth: 64, maxFileBytes: 64 * 1024 * 1024 };

/** POSIX execute bit; always false on Windows (no mode bits that matter here). */
function executableFromMode(mode: number): boolean {
  return PATH_RULES !== "win32" && (mode & 0o111) !== 0;
}

/**
 * Scan `treeDir` (a disposable workspace's `tree`) into typed facts. Paths are repository-relative with
 * "/" separators. Reads only; never follows a link; bounded by `limits`.
 */
export async function scanFixTree(treeDir: string, limits: FixScanLimits = DEFAULT_SCAN_LIMITS): Promise<FixPostScan> {
  const files: FixPostFile[] = [];
  const anomalies: ScanAnomaly[] = [];
  const linkCache = new Map<string, boolean>();
  const relByFold = new Map<string, string>();
  let entries = 0;
  let complete = true;

  const addAnomaly = (a: ScanAnomaly): void => {
    anomalies.push(a);
  };

  async function walk(absDir: string, relDir: string, depth: number): Promise<void> {
    if (!complete) return;
    if (depth > limits.maxDepth) {
      addAnomaly({ path: relDir, kind: "limit", detail: `directory nesting exceeds ${limits.maxDepth}` });
      complete = false;
      return;
    }
    let names: string[];
    try {
      names = await readdir(absDir);
    } catch (e) {
      addAnomaly({ path: relDir, kind: "unreadable", detail: `cannot list directory: ${code(e)}` });
      return;
    }
    for (const name of names.sort()) {
      if (++entries > limits.maxEntries) {
        addAnomaly({ path: relDir, kind: "limit", detail: `workspace has more than ${limits.maxEntries} entries` });
        complete = false;
        return;
      }
      const rel = relDir ? `${relDir}/${name}` : name;
      const abs = join(absDir, name);

      const nameProblem = portableSegmentProblem(name);
      if (nameProblem) {
        addAnomaly({ path: rel, kind: "unsafe_name", detail: nameProblem });
        continue; // never read or descend into an unsafe-named entry
      }
      const fold = foldPath(rel);
      const prior = relByFold.get(fold);
      if (prior !== undefined && prior !== rel) {
        addAnomaly({ path: rel, kind: "case_collision", detail: `collides under case folding with "${prior}"` });
        continue;
      }
      relByFold.set(fold, rel);

      let st;
      try {
        st = await lstat(abs);
      } catch (e) {
        addAnomaly({ path: rel, kind: "unreadable", detail: code(e) });
        continue;
      }
      if (st.isDirectory()) {
        if (!(await isPlainDirectory(abs))) {
          addAnomaly({ path: rel, kind: "link", detail: "directory is a link, junction or mount point (not descended)" });
          continue;
        }
        await walk(abs, rel, depth + 1);
        if (!complete) return;
        continue;
      }
      // A file (or something shaped like one): read it under the capture rules.
      const r = await readWorkingFile(abs, { root: treeDir, objectFormat: "sha256", maxRetainBytes: 0, retain: false, linkCache });
      switch (r.kind) {
        case "file": {
          if ((r.size ?? 0) > limits.maxFileBytes) {
            addAnomaly({ path: rel, kind: "limit", detail: `file is larger than ${limits.maxFileBytes} bytes` });
            break;
          }
          files.push({ path: rel, size: r.size ?? 0, sha256: r.sha256 ?? "", executable: executableFromMode(st.mode), binary: r.stats ? isBinaryStats(r.stats) : false });
          break;
        }
        case "link":
          addAnomaly({ path: rel, kind: r.reason === "hard_link" ? "hard_link" : "link", detail: r.reason ?? "link" });
          break;
        case "alias":
          addAnomaly({ path: rel, kind: "alias", detail: r.reason ?? "realpath mismatch" });
          break;
        case "not_regular":
          addAnomaly({ path: rel, kind: "special_file", detail: r.reason ?? "not a regular file" });
          break;
        case "unstable":
          addAnomaly({ path: rel, kind: "unstable", detail: r.reason ?? "changed while reading" });
          break;
        case "missing":
          break; // vanished during the walk (a race); nothing to record
      }
    }
  }

  await walk(treeDir, "", 0);
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { files, anomalies, complete };
}

function code(e: unknown): string {
  return (e as { code?: string })?.code ?? "UNKNOWN";
}

/** Baseline manifest of the files CodeParley seeded into `tree` BEFORE the fixer ran (same scan). */
export async function baselineManifest(treeDir: string, limits: FixScanLimits = DEFAULT_SCAN_LIMITS): Promise<{ files: FixFileEntry[]; scan: FixPostScan }> {
  const scan = await scanFixTree(treeDir, limits);
  const files: FixFileEntry[] = scan.files.map((f) => ({ path: f.path, size: f.size, sha256: f.sha256, executable: f.executable }));
  return { files, scan };
}

/**
 * Build the inert proposal for a completed delegated fix: scan the post-run tree, evaluate it against
 * the boundary and the baseline, and bind everything by digest. Never applies anything; a `rejected`
 * or `empty` proposal is still returned (with its violations) so the caller can report it.
 */
export async function captureFixProposal(input: {
  proposalId: string;
  workspaceId: string;
  treeDir: string;
  boundary: FixBoundary;
  baseline: readonly FixFileEntry[];
  nowMs: number;
  limits?: FixScanLimits;
}): Promise<{ proposal: FixProposal; evaluation: FixEvaluation; scan: FixPostScan }> {
  const scan = await scanFixTree(input.treeDir, input.limits ?? DEFAULT_SCAN_LIMITS);
  const evaluation = evaluateFix({ boundary: input.boundary, baseline: input.baseline, post: scan });
  const core: Omit<FixProposal, "digest"> = {
    schema_version: FIX_SCHEMA_VERSION,
    proposal_id: input.proposalId,
    workspace_id: input.workspaceId,
    boundary: input.boundary,
    boundary_digest: boundaryDigest(input.boundary),
    baseline_digest: manifestDigest(input.baseline),
    status: evaluation.status,
    changes: evaluation.changes,
    violations: evaluation.violations,
    created_at_ms: input.nowMs,
    expires_at_ms: input.nowMs + input.boundary.proposal_lifetime_ms,
  };
  return { proposal: { ...core, digest: proposalDigest(core) }, evaluation, scan };
}
