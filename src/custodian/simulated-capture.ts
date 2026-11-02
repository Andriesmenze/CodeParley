// The simulated custodian's review capture (P3.4C-5 Increment 2; GrantLedger.Capture.cs, Cli/CaptureFixture.cs): a test
// stand-in, constructed only by test code. Two kinds of capture:
//  - the IN-PROCESS helper capture (engine tests): the engine's own helper capture (capture.ts runHelperCapture, the code
//    the real helper service runs) into a ticket staging the simulator then publishes — the export directory, the capture
//    record beside it, renamed to its published name. No access control is modelled (the real custodian publishes the
//    ticket directory read-only to the implementer);
//  - the SYNTHETIC capture of the shared run corpus (CaptureFixture): a manifest listing context/README.md, that file and
//    a record, or a modelled failure — the same capture the real custodian's self-test runner streams, so both sides
//    compute the same review input identity.

import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256OfBytes, sha256OfCanonicalJson } from "../common/hash.js";
import { runHelperCapture, type CaptureRulesInput } from "../capture/capture.js";
import { StagedExport, exportDigestOf, listFiles } from "../capture/export-writer.js";
import type { ReviewTarget } from "../schemas/capture.js";
import type { SimCaptureEnd, SimPublishedCapture } from "./simulated-runs.js";
import type { Launch } from "../helper/request.js";
import type { SimMeasureOutcome } from "./simulated-derivation.js";
import type { SimBaselineFile, SimFixBaselineRead } from "./simulated-fix.js";

/** The simulated helper: where published exports go, and how captures run (auto: the in-process helper capture right
 * after a reservation; manual: only when the test asks — the shared corpus). */
export interface SimHelperOptions {
  exportsRoot: string;
  mode?: "auto" | "manual";
  /** The git the in-process helper capture runs (auto mode). */
  gitExe?: string;
  /** P3.4C-5 Increment 3: how the custodian's measurements run — auto: the helper's own workload in process, right after a
   * check reservation (needs `gitExe`); manual: the corpus's synthetic measurement, a check measurement only when the test
   * asks. Default: as `mode`. */
  measure?: "auto" | "manual";
  /** TEST ONLY (P3.4C-5 Increment 3): every derivation gets a fresh progress fingerprint — work that "moved" — for tests of
   * the loop's own rules that are not about progress. */
  freshProgress?: boolean;
}

/** What a synthetic capture produces (SyntheticCapture). */
export interface SimSyntheticCapture {
  sourceId?: string | null;
  stable?: boolean;
  fail?: string | null;
  /** Phase 4 Increment 2: the export also carries the corpus's `tree` files (a delegated fix's baseline). */
  tree?: boolean;
}

/** Phase 4 Increment 2: the synthetic capture's `tree` files (CaptureFixture.TreeFiles), exported with `tree: true`. */
export const SYNTHETIC_TREE_FILES: readonly (readonly [string, string])[] = [
  [".github/workflows/ci.yml", "on: push\n"],
  ["docs/guide.md", "# Guide\n"],
  ["src/app.ts", "export const answer = 41;\n"],
  ["src/util.ts", "export const twice = (n: number): number => n * 2;\n"],
];

const failed = (reason: string, detail: string): SimCaptureEnd => ({ captured: false, reason, detail, capture: null });

/** The engine's manifest content digest (review-operation.ts manifestContentDigest; ManifestContentDigest). */
export function manifestContentDigestOf(manifest: Record<string, unknown>): string {
  const { capture_id: _c, manifest_digest: _d, ...content } = manifest;
  return sha256OfCanonicalJson({ digest_schema: "arl.manifest-content.v1", content });
}

async function published(exportsRoot: string, ticket: string, record: Record<string, unknown>, manifest: Record<string, unknown>): Promise<SimPublishedCapture> {
  const staging = join(exportsRoot, `${ticket}.staging`);
  const final = join(exportsRoot, ticket);
  const recordBytes = Buffer.from(JSON.stringify(record, null, 2), "utf8");
  await writeFile(join(staging, "capture.json"), recordBytes, { flag: "wx" });
  await renameWithRetry(staging, final);
  const exportPath = join(final, "export");
  const rows: { rel: string; size: number; sha256: string }[] = [];
  for (const rel of await listFiles(exportPath)) {
    const bytes = await readFile(join(exportPath, ...rel.split("/")));
    rows.push({ rel, size: bytes.length, sha256: sha256OfBytes(bytes) });
  }
  return {
    recordText: recordBytes.toString("utf8"),
    dir: final, exportPath, capturePath: join(final, "capture.json"), sourceId: String(record["source_id"]), stable: record["stable"] === true,
    captureId: String(record["capture_id"] ?? manifest["capture_id"]), captureDigest: sha256OfBytes(recordBytes), manifestDigest: String(manifest["manifest_digest"]),
    manifestContentDigest: manifestContentDigestOf(manifest), exportDigest: exportDigestOf(rows), fileCount: rows.length, totalBytes: rows.reduce((n, r) => n + r.size, 0),
  };
}

/** A directory rename on Windows fails while anything (an indexer, a scanner) still holds a file in it: retried, bounded. */
async function renameWithRetry(from: string, to: string): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await rename(from, to);
      return;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (attempt >= 20 || (code !== "EPERM" && code !== "EBUSY" && code !== "EACCES")) throw e;
      await new Promise((r) => setTimeout(r, 50 * attempt));
    }
  }
}

/** The in-process helper capture of `repoRoot` (auto mode): the engine's helper capture with protected git into the
 * ticket's staging, then published. */
export async function simulatedHelperCapture(o: { repoRoot: string; gitExe: string; target: ReviewTarget; rules: CaptureRulesInput; exportsRoot: string; ticket: string; operationId: string; signal?: AbortSignal }): Promise<SimCaptureEnd> {
  const staging = join(o.exportsRoot, `${o.ticket}.staging`);
  const cfg = join(o.exportsRoot, `${o.ticket}.cfg`);
  try {
    await mkdir(join(cfg, "home"), { recursive: true });
    await mkdir(join(cfg, "hooks"), { recursive: true });
    await writeFile(join(cfg, "gitconfig"), "");
    await mkdir(staging, { recursive: true });
    const sink = new StagedExport(join(staging, "export"), false);
    const r = await runHelperCapture({
      repoRoot: o.repoRoot, gitExe: o.gitExe, target: o.target, rules: o.rules, operationId: o.operationId, sink,
      scratch: { home: join(cfg, "home"), hooks: join(cfg, "hooks"), gitconfig: join(cfg, "gitconfig") },
      protectedGit: { safeDirectory: o.repoRoot.replace(/\\/g, "/"), globalConfig: join(cfg, "gitconfig") },
      ...(o.signal ? { signal: o.signal } : {}),
    });
    if (o.signal?.aborted) return failed("cancelled", "the capture was cancelled");
    return { captured: true, reason: null, detail: null, capture: await published(o.exportsRoot, o.ticket, r.record as unknown as Record<string, unknown>, r.manifest as unknown as Record<string, unknown>) };
  } catch (e) {
    if (o.signal?.aborted) return failed("cancelled", "the capture was cancelled");
    return failed("measurement_failed", `${e instanceof Error ? e.name : "Error"}: ${(e instanceof Error ? e.message : String(e)).slice(0, 400)}`);
  } finally {
    await rm(cfg, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** The synthetic capture's one exported file (CaptureFixture.ContextFile). */
const CONTEXT_FILE = Buffer.from("# corpus\n", "utf8");

/** The synthetic manifest (CaptureFixture.Manifest). */
export function syntheticManifest(captureId: string, sourceId: string, tree = false): Record<string, unknown> {
  const treeFiles = tree ? SYNTHETIC_TREE_FILES.map(([path, text]) => ({ area: "tree", path, size: Buffer.byteLength(text, "utf8"), sha256: sha256OfBytes(Buffer.from(text, "utf8")) })) : [];
  const m: Record<string, unknown> = {
    schema: "arl.corpus-capture.v1",
    capture_id: captureId,
    source_id: sourceId,
    files: [{ area: "context", path: "README.md", size: CONTEXT_FILE.length, sha256: sha256OfBytes(CONTEXT_FILE) }, ...treeFiles],
    review_files: { base: [], head: [] },
  };
  m["manifest_digest"] = sha256OfCanonicalJson(m);
  return m;
}

/** The synthetic capture (manual mode): the custodian's validation of the frames is modelled by the failures it would
 * refuse (a file outside the manifest, a claimed hash that is not the bytes', a withheld path), which publish nothing. */
export async function syntheticCapture(o: { exportsRoot: string; ticket: string; operationId: string; selection: string | null; spec: SimSyntheticCapture }): Promise<SimCaptureEnd> {
  switch (o.spec.fail ?? null) {
    case "timeout":
      return failed("measurement_timeout", "MEASUREMENT_TIMEOUT: synthetic: the helper did not finish");
    case "helper":
      return failed("measurement_failed", "MEASUREMENT_FAILED: synthetic: the workload failed");
    case "runtime":
      return failed("runtime_changed", "CONFIG_MISMATCH: synthetic: the engine runtime differs from the one approved");
    case "cancelled":
      return failed("cancelled", "MEASUREMENT_CANCELLED: synthetic: cancelled");
    case "frame_hash":
      return failed("measurement_failed", "HelperFrameError: a file's claimed SHA-256 differs from the custodian's hash of its bytes");
    case "frame_outside_manifest":
      return failed("measurement_failed", "publication refused: an export file is not in the manifest as written: context/OTHER.md");
    case "withheld":
      return failed("measurement_failed", "publication refused: a withheld (confidential) path is in the export");
    case "export_digest": // N5-12: the custodian's own digest of the written bytes decides; the helper's claim changes nothing
      return failed("measurement_failed", "publication refused: the helper's export digest differs from the custodian's");
    default:
      break;
  }
  const source = o.spec.sourceId ?? o.selection ?? "0".repeat(64);
  const manifest = syntheticManifest(o.operationId, source, o.spec.tree === true);
  const exportDir = join(o.exportsRoot, `${o.ticket}.staging`, "export");
  await mkdir(join(exportDir, "context"), { recursive: true });
  await mkdir(join(exportDir, "review"), { recursive: true });
  await writeFile(join(exportDir, "context", "README.md"), CONTEXT_FILE);
  if (o.spec.tree === true) {
    for (const [path, text] of SYNTHETIC_TREE_FILES) {
      const target = join(exportDir, "tree", ...path.split("/"));
      await mkdir(join(target, ".."), { recursive: true });
      await writeFile(target, text, "utf8");
    }
  }
  await writeFile(join(exportDir, "review", "manifest.json"), JSON.stringify(manifest));
  const record = { capture_id: o.operationId, source_id: source, stable: o.spec.stable ?? true, entries: [], changes: [] };
  return { captured: true, reason: null, detail: null, capture: await published(o.exportsRoot, o.ticket, record, manifest) };
}

/** The custodian's re-hash of a captured review's export and capture record (RehashForFinish), from disk. */
export async function rehashCapture(operationId: string, begin: Record<string, unknown>): Promise<{ operationId: string; unchanged: boolean; detail: string }> {
  const cc = begin["custodianCapture"] as Record<string, unknown> | undefined;
  try {
    const exportPath = String(cc?.["exportPath"]);
    const rows: { rel: string; size: number; sha256: string }[] = [];
    for (const rel of await listFiles(exportPath)) {
      const bytes = await readFile(join(exportPath, ...rel.split("/")));
      rows.push({ rel, size: bytes.length, sha256: sha256OfBytes(bytes) });
    }
    const exportSame = exportDigestOf(rows) === begin["exportDigest"];
    const recordSame = createHash("sha256").update(await readFile(String(cc?.["capturePath"]))).digest("hex") === begin["captureDigest"];
    const detail = exportSame && recordSame ? `${rows.length} files unchanged` : [exportSame ? "" : "the export's files differ", recordSame ? "" : "the capture record differs"].filter(Boolean).join("; ");
    return { operationId, unchanged: exportSame && recordSame, detail };
  } catch (e) {
    return { operationId, unchanged: false, detail: `the export could not be read again (${e instanceof Error ? e.message.slice(0, 200) : String(e)})` };
  }
}

/**
 * Phase 4 Increment 2 (GrantLedger.Fix.cs ReadFixBaseline): a delegated fix's baseline — the review's published export
 * re-hashed against the export and capture digests the custodian recorded, and the `tree` files of its own manifest (every
 * entry checked: a malformed manifest vouches for nothing).
 */
export async function readFixBaseline(reviewId: string, operationId: string, begin: Record<string, unknown> | null): Promise<SimFixBaselineRead> {
  const cc = begin?.["custodianCapture"] as Record<string, unknown> | undefined;
  if (!begin || !cc || cc["retiredAt"] != null) return { reviewId, unchanged: false, detail: "no published capture is held for it", tree: null };
  const rh = await rehashCapture(operationId, begin);
  if (!rh.unchanged) return { reviewId, unchanged: false, detail: rh.detail, tree: null };
  let manifest: unknown;
  try {
    manifest = JSON.parse(await readFile(join(String(cc["exportPath"]), "review", "manifest.json"), "utf8"));
  } catch (e) {
    return { reviewId, unchanged: false, detail: `the capture's manifest could not be read (${e instanceof Error ? e.message.slice(0, 200) : String(e)})`, tree: null };
  }
  const files = (manifest as { files?: unknown } | null)?.files;
  if (!Array.isArray(files)) return { reviewId, unchanged: false, detail: "the capture's manifest is malformed", tree: null };
  const tree = new Map<string, SimBaselineFile>();
  for (const f of files as Record<string, unknown>[]) {
    if (!f || typeof f !== "object" || typeof f["path"] !== "string" || typeof f["area"] !== "string" || !Number.isSafeInteger(f["size"]) || (f["size"] as number) < 0 || typeof f["sha256"] !== "string" || !/^[0-9a-f]{64}$/.test(f["sha256"])) {
      return { reviewId, unchanged: false, detail: "the capture's manifest is malformed", tree: null };
    }
    if (f["area"] === "tree") tree.set(f["path"], { size: f["size"] as number, sha256: f["sha256"] });
  }
  return { reviewId, unchanged: true, detail: rh.detail, tree };
}

/** Change one published file of a captured review (a bypass of the export's access control). */
export function tamperCapture(begin: Record<string, unknown>): void {
  const exportPath = String((begin["custodianCapture"] as Record<string, unknown>)["exportPath"]);
  const target = join(exportPath, "review", "manifest.json");
  writeFileSync(target, "tampered\n", { flag: "a" });
}

/** Remove a ticket's directories (a measurement that ended without a capture). */
export function removeTicketDirs(exportsRoot: string, ticket: string): void {
  for (const d of [`${ticket}.staging`, `${ticket}.cfg`, ticket]) rmSync(join(exportsRoot, d), { recursive: true, force: true });
}

/** The start sweep (N5-18): every export directory no captured review references is removed. */
export function sweepExports(exportsRoot: string, referencedExportPaths: ReadonlySet<string>, liveTickets: ReadonlySet<string> = new Set()): number {
  mkdirSync(exportsRoot, { recursive: true });
  const keep = new Set([...referencedExportPaths].map((p) => join(p, "..").toLowerCase()));
  let removed = 0;
  for (const e of readdirSync(exportsRoot, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const full = join(exportsRoot, e.name);
    // A measurement in progress owns `<ticket>`, `<ticket>.staging` and `<ticket>.cfg` (TicketDirs.Live).
    if (liveTickets.has(e.name.replace(/\.(staging|cfg)$/, ""))) continue;
    if (!keep.has(full.toLowerCase())) {
      rmSync(full, { recursive: true, force: true });
      removed++;
    }
  }
  return removed;
}

/** P3.4C-5 Increment 3 (auto mode): the in-process helper measurement of `repoRoot` — the helper's own `derive` workload
 * (the measurement, and with a snapshot the protected derivation), with protected git and the custodian's per-request
 * read-only directories, as the helper service runs it. */
export async function simulatedHelperMeasure(o: { repoRoot: string; gitExe: string; workload: Record<string, unknown>; exportsRoot: string; ticket: string }): Promise<SimMeasureOutcome> {
  const cfg = join(o.exportsRoot, `${o.ticket}.cfg`);
  try {
    await mkdir(join(cfg, "home"), { recursive: true });
    await mkdir(join(cfg, "hooks"), { recursive: true });
    await writeFile(join(cfg, "gitconfig"), "");
    const launch = {
      node: process.execPath, nodeSha256: "0".repeat(64), entry: process.execPath, entrySha256: "0".repeat(64), git: o.gitExe,
      home: join(cfg, "home"), gitconfig: join(cfg, "gitconfig"), hooks: join(cfg, "hooks"),
      repository: o.repoRoot, safeDirectory: o.repoRoot.replace(/\\/g, "/"), maxFrameBody: 16 << 20,
    } as Launch;
    // Loaded on use: the helper's workload pulls in the engine's derivation, which the transport must not import statically
    // (the engine imports the transport).
    const { deriveWorkload } = await import("../helper/workloads.js");
    const { DeriveWorkloadSchema } = await import("../helper/request.js");
    const r = await deriveWorkload(launch, DeriveWorkloadSchema.parse(o.workload));
    return { ok: true, code: null, detail: null, measured: r["measured"] as Record<string, unknown>, derivation: (r["derivation"] ?? null) as Record<string, unknown> | null, redaction: (r["redaction"] ?? null) as Record<string, unknown> | null };
  } catch (e) {
    return { ok: false, code: "MEASUREMENT_FAILED", detail: `${e instanceof Error ? e.name : "Error"}: ${(e instanceof Error ? e.message : String(e)).slice(0, 400)}`, measured: null, derivation: null };
  } finally {
    await rm(cfg, { recursive: true, force: true }).catch(() => undefined);
  }
}
