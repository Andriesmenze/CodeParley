// Phase 4 Increment 2 — delegation of ONE scoped fix to Codex, ending in a custodian-validated proposal (contract §3.2–§3.4).
//
// `delegateFix` is the bounded, validated command a delegated fix starts from: the model-reachable `delegate_fix` MCP tool
// (Phase 4 Increment 3 exposes it; the owner's confirmation and the application are engine/fix-decision.ts and
// engine/fix-apply.ts). Its input names a task and a boundary — never file contents or diffs.
//
// The sequence:
//   1. P4-A: Windows, the validated custodian, a PROTECTED run with the repository's protected configuration in force;
//      anywhere else it is refused (FIX_DELEGATION_UNAVAILABLE) before anything is begun.
//   2. FIX vs S1: the local cp_fix self-test must exist and pass for the approved Codex binary — but it confers nothing by
//      itself: the custodian must hold an operator-confirmed FIX self-test for it (mode FIX, separate from S1). The
//      custodian checks that claim again at op_begin.
//   3. op_begin (operationKind fix): the custodian binds the run, the task digest, the boundary and the baseline — the
//      published capture of a finished review it holds and re-hashes — and spends one of the run's maxFixes.
//   4. The disposable workspace (under the data home, never overlapping the primary worktree) is seeded from that
//      capture's `tree` (each file checked against the capture's manifest); the fixer runs through Increment 1's
//      `launchFixer` (the cp_fix gate, the safe argv, the bounded launcher); the tree is scanned and evaluated against
//      the boundary (`captureFixProposal`); the workspace is destroyed, whatever happened. A killed engine runs no
//      teardown: its operation is recovered (interrupted) and its workspace removed by the run's next delegation, or
//      with the run's other workspaces when the run ends.
//   5. op_finish: the engine's report and, for an eligible proposal, its CONTENT (per path, in canonical order). The
//      custodian validates the content itself against its own baseline and the boundary it bound, and holds it under the
//      digest it computes (`proposed`), or rejects it. Nothing here writes the primary worktree, renders or confirms.
//
// A proposal awaiting confirmation is not progress: the derivation routes it to an await (no continuation, no wake).

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";
import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfBytes, sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import type { ConfigSection, RunFixBegin, RunFixOutcome, RunSection } from "../custodian/protocol.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import { probeCodex, type CodexProbe } from "../agents/codex/probe.js";
import { launchFixer, type FixLaunchRequest } from "../agents/codex/fix-launcher.js";
import type { ReviewRunResult } from "../agents/codex/adapter.js";
import type { SandboxBackend } from "../agents/codex/argv.js";
import { baselineManifest, captureFixProposal } from "../capture/fix-scan.js";
import type { FixBoundary, FixFileEntry } from "../policy/delegated-fix.js";
import { createDisposableWorkspace, destroyDisposableWorkspace, destroyStaleRunWorkspaces, type DisposableWorkspace } from "../workspace/disposable-workspace.js";
import { canonicalizePath, caseKey } from "../workspace/paths.js";
import { readState } from "../store/state-store.js";
import { custodianEvidenceFor, reconcileCustodianRun, type CustodianEvidence } from "./custodian-evidence.js";
import { SimulatedKill } from "./simulated-kill.js";
import { evidenceSelection, type Loaded, type RunHandle } from "./engine-env.js";
import { approvedCodexImage, heldConfigFor } from "./protected-config.js";
import { fixBackendFor, storedFixSelfTest } from "./fix-confirmation.js";

/** The custodian's hard caps (CustodianConstants.cs), mirrored to refuse an out-of-range request before it is sent. */
const CAPS = { files: 50, dirs: 20, changed: 50, fileBytes: 256 * 1024, totalBytes: 512 * 1024 } as const;
const RelPath = z.string().min(1).max(1024);

/** The delegate_fix input: a task and a boundary — never file contents, diffs or a confirmation. */
export const DelegateFixInputSchema = z
  .object({
    task: z.string().min(1).max(8000),
    boundary: z
      .object({
        permitted_files: z.array(RelPath).max(CAPS.files).default([]),
        permitted_dirs: z.array(RelPath).max(CAPS.dirs).default([]),
        allow_create: z.boolean().default(false),
        allow_delete: z.boolean().default(false),
        allow_binary: z.boolean().default(false),
        max_changed_files: z.number().int().min(1).max(CAPS.changed).default(10),
        max_file_bytes: z.number().int().min(1).max(CAPS.fileBytes).default(64 * 1024),
        max_total_bytes: z.number().int().min(1).max(CAPS.totalBytes).default(256 * 1024),
        time_limit_seconds: z.number().int().min(30).max(3600).default(600),
        proposal_lifetime_seconds: z.number().int().min(60).max(7 * 24 * 3600).default(3600),
      })
      .strict(),
    /** The finished review whose published capture seeds the workspace (default: the latest one the custodian holds). */
    baseline_review_id: z.string().min(1).max(128).optional(),
  })
  .strict();
export type DelegateFixInput = z.input<typeof DelegateFixInputSchema>;

export interface DelegateFixResult {
  fix_id: string;
  operation_id: string;
  /** The custodian's verdict: proposed (content held, awaiting the owner), rejected, or what the fixer run reported. */
  status: string;
  proposal: { proposal_digest: string; change_count: number; total_bytes: number; expires_at: string } | null;
  violations: { kind: string; path: string | null }[];
  violation_count: number;
  baseline_review_id: string;
  detail: string | null;
}

/** Test seams: the Codex probe, and the fixer run (the real one is Increment 1's `launchFixer`). */
export interface DelegateFixHooks {
  probe?: () => Promise<CodexProbe>;
  launch?: (req: FixLaunchRequest) => Promise<Pick<ReviewRunResult, "outcome">>;
  signal?: AbortSignal;
  /** Called once the custodian began the fix operation (the MCP tool returns a handle while the fixer runs). */
  onBegun?: (operationId: string, fixId: string) => void;
}

const unavailable = (why: string): DomainError => new DomainError("FIX_DELEGATION_UNAVAILABLE", `a delegated fix is refused: ${why} (P4-A: Windows or Linux, through the validated custodian, with a protected configuration only); nothing was begun`, { retryable: false });

/** A held review whose published capture can seed a fix: finished, its export not retired. */
function baselineReviewOf(run: RunSection | null, wanted: string | undefined): { reviewId: string; exportPath: string } {
  const rec = (run?.record ?? null) as { reviews?: Record<string, unknown>[]; operations?: Record<string, unknown>[] } | null;
  const active = new Set((rec?.operations ?? []).filter((o) => ["running", "measuring", "captured"].includes(String(o["status"]))).map((o) => String(o["operationId"])));
  const candidates = (rec?.reviews ?? []).filter((r) => {
    const c = (r["begin"] as Record<string, unknown> | undefined)?.["custodianCapture"] as Record<string, unknown> | undefined;
    return c && c["retiredAt"] == null && typeof c["exportPath"] === "string" && !active.has(String(r["operationId"]));
  });
  const pick = wanted ? candidates.find((r) => r["reviewId"] === wanted) : candidates.at(-1);
  if (!pick) {
    throw new DomainError("EVIDENCE_NOT_HELD", wanted
      ? `review ${wanted} is not a finished review of this run whose published capture the custodian still holds; nothing was begun`
      : "the custodian holds no finished review of this run with a published capture to seed a fix from; run a review first (nothing was begun)", { retryable: false });
  }
  const c = (pick["begin"] as Record<string, unknown>)["custodianCapture"] as Record<string, unknown>;
  return { reviewId: String(pick["reviewId"]), exportPath: String(c["exportPath"]) };
}

/** The manifest's `tree` files of a published export (the engine's own read; the custodian reads its own at finish). */
async function exportTree(exportPath: string): Promise<{ path: string; size: number; sha256: string }[]> {
  const manifest = JSON.parse(await readFile(join(exportPath, "review", "manifest.json"), "utf8")) as { files?: { area?: string; path?: string; size?: number; sha256?: string }[] };
  return (manifest.files ?? []).filter((f) => f.area === "tree").map((f) => ({ path: String(f.path), size: Number(f.size), sha256: String(f.sha256) }));
}

/** Seed `ws.tree` from the export's `tree` area, every file checked against the manifest; returns the baseline the scan
 * judges against (the seeded files as scanned). */
async function seedWorkspace(ws: DisposableWorkspace, exportPath: string): Promise<FixFileEntry[]> {
  const files = await exportTree(exportPath);
  for (const f of files) {
    const bytes = await readFile(join(exportPath, "tree", ...f.path.split("/")));
    if (bytes.length !== f.size || sha256OfBytes(bytes) !== f.sha256) throw new DomainError("EVIDENCE_NOT_HELD", `the baseline export's file ${f.path} differs from its manifest; nothing was delegated`, { retryable: false });
    const target = join(ws.tree, ...f.path.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: "wx" });
  }
  const { files: seeded, scan } = await baselineManifest(ws.tree);
  if (!scan.complete || scan.anomalies.length > 0 || seeded.length !== files.length) {
    throw new DomainError("INTERNAL", "the seeded workspace does not match the baseline export (an anomaly or an incomplete scan); nothing was delegated", { retryable: false });
  }
  return seeded;
}

/** The fixer's instructions (stdin): the task and the boundary, as plain text. */
function fixPrompt(task: string, b: FixBoundary): string {
  const scope = [...b.permitted_files.map((f) => `- file ${f}`), ...b.permitted_dirs.map((d) => `- files under ${d}/`)].join("\n");
  return [
    "You are fixing one scoped task in a disposable copy of a repository (your working directory).",
    "Edit files in place in this working directory; nothing else is writable and the network is unavailable to commands.",
    "Change only these paths:",
    scope,
    b.allow_create ? "You may create new files within those paths." : "Do not create new files.",
    b.allow_delete ? "You may delete files within those paths." : "Do not delete files.",
    `Change at most ${b.max_changed_files} files. Do not create links. Do not change any other file.`,
    "",
    "Task:",
    task,
  ].join("\n");
}

/**
 * Delegate one scoped fix of a protected run to Codex. Refusals before op_begin begin nothing; once the custodian began
 * the `fix` operation it is always finished (with what happened), and the disposable workspace is always destroyed.
 */
/** The Codex a protected fix launches: the operator-approved installation, as for a protected review, whatever PATH or
 * config.json say (an installer's Codex is on no account's PATH); `approvedCodexImage` then refuses anything else. */
export function fixCodexExecutable(section: ConfigSection, configured: string | null): string | null {
  return section.repository?.codexInstallation?.path ?? configured;
}

export async function delegateFix(le: Loaded, run: RunHandle, input: DelegateFixInput, hooks: DelegateFixHooks = {}): Promise<DelegateFixResult> {
  const req = DelegateFixInputSchema.parse(input);
  // ---- 1. P4-A ----
  // Phase 5 Increment 3: Windows and Linux, each only through a validated custodian (D-14); elsewhere refused.
  const platform = le.env.testHooks?.custodian?.platform ?? process.platform;
  if (platform !== "win32" && platform !== "linux") throw unavailable(`delegated fixes need the CodeParley custodian on Windows or Linux (this is ${platform})`);
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw unavailable("no validated CodeParley custodian is available on this host");
  const sel = evidenceSelection(le, run);
  const st = await readState(run.paths);
  let ev: CustodianEvidence | null;
  let held;
  try {
    ev = await custodianEvidenceFor(sel, st);
    held = ev ? await heldConfigFor(sel, st) : null;
  } catch (e) {
    throw isDomainError(e) && e.code !== "INTERNAL" ? e : unavailable(`the custodian could not answer for this run (${e instanceof Error ? e.message : String(e)})`);
  }
  if (!ev || !held) throw unavailable("this run is not protected by the custodian (an attended run)");
  if (!held.section.repository || !held.section.repository.usable) throw unavailable("the repository has no protected configuration in force");

  // ---- 2. the Codex the fixer runs and its FIX basis (local record + custodian confirmation) ----
  const probe = hooks.probe ? await hooks.probe() : await probeCodex({ configured: fixCodexExecutable(held.section, le.env.launch.codex ?? le.cfg.config.codex.executable), sourceEnv: le.env.sourceEnv, testLauncher: le.env.testHooks?.review?.codexLauncher ?? null });
  const backend: SandboxBackend = fixBackendFor(platform, le.cfg.config.codex.windows_sandbox ?? null, probe);
  const { sha256: codexSha256 } = await approvedCodexImage(held.section, probe.launcher.exe, (a, b) => caseKey(a) === caseKey(b));
  const local = await storedFixSelfTest(le.layout.selftestDir, le.dataHome, backend, probe);
  if (local.codexSha256 !== codexSha256) throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", "the stored cp_fix self-test is not for the approved Codex binary; nothing was begun", { retryable: false });
  const confirmation = held.section.selftestConfirmations.find((c) => c.mode === "FIX" && c.usable && c.selftestId === local.record.selftest_id && c.codexSha256 === codexSha256 && c.profileDigest === local.profileDigest);
  if (!confirmation) {
    throw new DomainError("CODEX_ISOLATION_UNAVAILABLE", `the custodian holds no operator-confirmed FIX self-test for Codex ${probe.version} (${codexSha256.slice(0, 12)}) on ${backend}: a local cp_fix self-test confers no authority by itself — the operator confirms it with \`code-parley config confirm-selftest --fix\` (an S1 confirmation does not count); nothing was begun`, { retryable: false });
  }

  // ---- 3. op_begin ----
  const baseline = baselineReviewOf(held.run, req.baseline_review_id);
  const fixId = uuidv7();
  const b = req.boundary;
  const policyBoundary: FixBoundary = {
    task_id: fixId, permitted_files: b.permitted_files, permitted_dirs: b.permitted_dirs, allow_create: b.allow_create, allow_delete: b.allow_delete,
    allow_binary: b.allow_binary, max_changed_files: b.max_changed_files, max_file_bytes: b.max_file_bytes, max_total_bytes: b.max_total_bytes,
    proposal_lifetime_ms: b.proposal_lifetime_seconds * 1000,
  };
  const begin: RunFixBegin = {
    operationKind: "fix",
    fixId,
    taskDigest: sha256OfCanonicalJson({ schema: "codeparley.fix-task.v1", task: req.task }),
    baselineReviewId: baseline.reviewId,
    boundary: {
      permittedFiles: b.permitted_files, permittedDirs: b.permitted_dirs, allowCreate: b.allow_create, allowDelete: b.allow_delete, allowBinary: b.allow_binary,
      maxChangedFiles: b.max_changed_files, maxFileBytes: b.max_file_bytes, maxTotalBytes: b.max_total_bytes, timeLimitSeconds: b.time_limit_seconds,
      proposalLifetimeSeconds: b.proposal_lifetime_seconds,
    },
    isolation: { mode: "FIX", profileDigest: local.profileDigest, selftestId: local.record.selftest_id, backend, codexVersion: probe.version },
    codexSha256,
  };
  // A fix whose engine was killed is still running in the custodian's records until it is recovered (its writer gone:
  // interrupted); without this the run stays RUN_BUSY for the next delegation.
  await reconcileCustodianRun(sel, run.paths, le.env.owner);
  const begun = await ev.transition("op_begin", begin, `${fixId}-begin`);
  const operationId = String(begun["operationId"]);
  hooks.onBegun?.(operationId, fixId);

  // ---- 4. the workspace, the fixer, the scan ----
  let outcome: RunFixOutcome;
  let ws: DisposableWorkspace | null = null;
  let killed = false;
  try {
    const primary = await canonicalizePath(run.meta.repository_root);
    // This fix is now the run's one active operation: any other workspace of the run belongs to a fixer that ended without
    // its own teardown (a killed engine runs no `finally`). Removed before this one is created.
    await destroyStaleRunWorkspaces(le.dataHome, run.runId, fixId).catch(() => []);
    ws = await createDisposableWorkspace({ dataHome: le.dataHome, runId: run.runId, workspaceId: fixId, primaryWorktreeRoot: primary });
    const seeded = await seedWorkspace(ws, baseline.exportPath);
    const protectedPaths = [primary, await canonicalizePath(probe.codexHome).catch(() => probe.codexHome)];
    const launch = hooks.launch ?? (le.env.testHooks?.fix?.launch as DelegateFixHooks["launch"] | undefined) ?? launchFixer;
    const ran = await launch({
      probe, backend, workspaceTree: ws.tree, workspaceScratch: ws.scratch, lastMessagePath: join(ws.control, "last-message.txt"),
      prompt: fixPrompt(req.task, policyBoundary), selftestDir: le.layout.selftestDir, protectedPaths,
      limits: { wallMs: b.time_limit_seconds * 1000 }, ...(hooks.signal ? { signal: hooks.signal } : {}),
    });
    const ran_ = ran.outcome.status;
    if (ran_ === "timed_out" || ran_ === "cancelled") outcome = { status: ran_, scan: null, detail: ran.outcome.detail.slice(0, 500), changes: [] };
    else if (ran_ !== "completed") outcome = { status: "failed", scan: null, detail: `${ran.outcome.failureClass ?? ran_}: ${ran.outcome.detail}`.slice(0, 500), changes: [] };
    else outcome = await proposalOutcome(ws, policyBoundary, seeded, fixId);
  } catch (e) {
    if (e instanceof SimulatedKill) {
      killed = true; // a killed process tears nothing down and finishes nothing
      throw e;
    }
    outcome = { status: "failed", scan: null, detail: `${isDomainError(e) ? e.code : e instanceof Error ? e.name : "Error"}: ${e instanceof Error ? e.message : String(e)}`.slice(0, 500), changes: [] };
  } finally {
    if (ws && !killed) await destroyDisposableWorkspace(ws).catch(() => undefined);
  }

  // ---- 5. op_finish: the custodian validates the content itself ----
  const done = await ev.transition("op_finish", { operationId, outcome }, `${fixId}-finish`);
  const p = done["proposal"] as { proposalDigest: string; changeCount: number; totalBytes: number; expiresAt: string } | null | undefined;
  return {
    fix_id: fixId,
    operation_id: operationId,
    status: String(done["operationStatus"]),
    proposal: p ? { proposal_digest: p.proposalDigest, change_count: p.changeCount, total_bytes: p.totalBytes, expires_at: p.expiresAt } : null,
    violations: (done["violations"] as { kind: string; path: string | null }[] | undefined) ?? [],
    violation_count: Number(done["violationCount"] ?? 0),
    baseline_review_id: baseline.reviewId,
    detail: outcome.detail,
  };
}

/** The engine's scan of the fixer's tree and, for an eligible proposal, its content (canonical order, base64). */
async function proposalOutcome(ws: DisposableWorkspace, boundary: FixBoundary, baseline: FixFileEntry[], fixId: string): Promise<RunFixOutcome> {
  const { evaluation, scan } = await captureFixProposal({ proposalId: fixId, workspaceId: fixId, treeDir: ws.tree, boundary, baseline, nowMs: Date.now() });
  const summary = { complete: scan.complete, files: scan.files.length, anomalies: scan.anomalies.length, violations: evaluation.violations.length };
  if (evaluation.status === "empty") return { status: "empty", scan: summary, detail: "the fixer changed nothing", changes: [] };
  if (evaluation.status === "rejected") {
    return { status: "rejected", scan: summary, detail: `the engine's scan rejected the workspace: ${evaluation.violations.slice(0, 5).map((v) => `${v.kind}${v.path ? ` ${v.path}` : ""}`).join("; ")}`.slice(0, 500), changes: [] };
  }
  const changes: RunFixOutcome["changes"] = [];
  for (const c of evaluation.changes) {
    if (!c.result) {
      changes.push({ path: c.path, kind: "delete", executable: false, content: null });
      continue;
    }
    const bytes = await readFile(join(ws.tree, ...c.path.split("/")));
    if (sha256OfBytes(bytes) !== c.result.sha256) throw new DomainError("INTERNAL", `${c.path} changed after the workspace was scanned; nothing was submitted`, { retryable: false });
    changes.push({ path: c.path, kind: c.kind, executable: c.result.executable, content: bytes.toString("base64") });
  }
  return { status: "completed", scan: summary, detail: null, changes };
}
