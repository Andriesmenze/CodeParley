// Run administration for the CLI (plan §5.1 `runs list/show`, §15.5, §15.6, MR-F; M1.6).
// Built from the store's own records and the engine's existing views; nothing here changes a
// run. Running operations whose server died are SHOWN as interrupted (recovery planned as a
// view, as get_review_status does); recovery is recorded by the next operation or a stop.
//
// Confidentiality: by default every string goes through the CLI view (host-view.ts
// `toLocal`): withheld names and hashes are redacted and the MR-F invariant applies, because
// CLI output can reach a model (a host agent with shell access may run the CLI). Raw check
// output, prompts and Codex event streams are never printed; their local files are named so
// the user can open them. `--reveal-withheld` lists the exact withheld paths, locally.

import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { DomainError, isDomainError } from "../common/errors.js";
import { isUuid } from "../common/ids.js";
import { readMeta, readState } from "../store/state-store.js";
import { readWorktreeLock } from "../store/locks.js";
import { REPO_KEY_RE, runPaths, type RunPaths } from "../store/paths.js";
import { resolveArtifact } from "../store/artifacts.js";
import { isPlainDirectory, treeSize } from "../store/remove-tree.js";
import { classifyOwnerLiveness, OWNER_LIVENESS_DEPS, type Liveness, type OwnerRecord } from "../store/owner.js";
import { lastActivityMs, purgeVerdict, type PurgeVerdict } from "../policy/retention.js";
import { samePath } from "../workspace/paths.js";
import type { RunMeta, StateRecord } from "../schemas/run-state.js";
import { eventsPage, type EventView } from "./history.js";
import { cutExcerpts, disclosureFor, toLocal, withheldPathsOfRun } from "./host-view.js";
import { compactFinding, compactIncident, currentSource, discussionInputOf, discussionReport, knownSourceOf, observedState, runReport, SOURCE_BUDGET_MS, type CompactFinding, type CompactIncident, type DiscussionReport, type UserReport } from "./status.js";
import type { CompletionReport } from "../policy/completion.js";
import { effectiveBudgets, type Loaded, type RunHandle } from "./engine-env.js";
import { withAuthoritativeUserRecords } from "./protected-user-records.js";

const DAY_MS = 86_400_000;

// ---------------------------------------------------------------------------
// Scanning the store
// ---------------------------------------------------------------------------

export interface ScannedRun {
  repoKey: string;
  runId: string;
  paths: RunPaths;
  meta: RunMeta | null;
  state: StateRecord | null;
  readError: { code: string; detail: string } | null;
  /** The run directory and the store directories above it are plain directories. */
  plainDirectory: boolean;
}

function errorOf(e: unknown): { code: string; detail: string } {
  return { code: isDomainError(e) ? e.code : ((e as { code?: string }).code ?? "INTERNAL"), detail: (e instanceof Error ? e.message : String(e)).slice(0, 300) };
}

/** Every run folder in the store (runs/<16-hex repo key>/<uuid>), readable or not. */
export async function scanRuns(le: Loaded): Promise<ScannedRun[]> {
  const runsDir = le.layout.runsDir;
  const runsPlain = await isPlainDirectory(runsDir);
  const out: ScannedRun[] = [];
  for (const repoKey of (await readdir(runsDir).catch(() => [] as string[])).sort()) {
    if (!REPO_KEY_RE.test(repoKey)) continue;
    const keyPlain = runsPlain && (await isPlainDirectory(join(runsDir, repoKey)));
    for (const runId of (await readdir(join(runsDir, repoKey)).catch(() => [] as string[])).sort()) {
      if (!isUuid(runId)) continue;
      const paths = runPaths(le.dataHome, repoKey, runId);
      let meta: RunMeta | null = null;
      let state: StateRecord | null = null;
      let readError: ScannedRun["readError"] = null;
      try {
        meta = await readMeta(paths);
        state = await readState(paths);
      } catch (e) {
        readError = errorOf(e);
      }
      out.push({ repoKey, runId, paths, meta, state, readError, plainDirectory: keyPlain && (await isPlainDirectory(paths.runDir)) });
    }
  }
  return out;
}

/** Operation ids referenced by the store's worktree locks (held or ownership_unresolved). */
export async function lockedOperationIds(le: Loaded): Promise<Set<string>> {
  const out = new Set<string>();
  for (const f of await readdir(le.layout.locksDir).catch(() => [] as string[])) {
    if (!f.endsWith(".lock")) continue;
    const l = await readWorktreeLock(join(le.layout.locksDir, f)).catch(() => null);
    if (l?.operation_id) out.add(l.operation_id);
  }
  return out;
}

export function verdictOf(s: ScannedRun, locked: ReadonlySet<string>): PurgeVerdict {
  return purgeVerdict(
    {
      runId: s.runId,
      plainDirectory: s.plainDirectory,
      readError: s.readError,
      metaRunId: s.meta?.run_id ?? null,
      createdAt: s.meta?.created_at ?? null,
      state: s.state,
    },
    locked,
  );
}

export function lastActivityOf(s: ScannedRun): number | null {
  return lastActivityMs({ state: s.state, createdAt: s.meta?.created_at ?? null });
}

// ---------------------------------------------------------------------------
// Resolving run and operation references (full ids or unique prefixes of >= 8 characters)
// ---------------------------------------------------------------------------

const PREFIX_RE = /^[0-9a-f][0-9a-f-]{7,35}$/;

export async function resolveRunRef(le: Loaded, ref: string): Promise<RunHandle> {
  const r = ref.trim().toLowerCase();
  if (!PREFIX_RE.test(r)) throw new DomainError("INVALID_ARGUMENT", "a run id (or a unique prefix of at least 8 characters, as runs list shows it) is required");
  const matches = (await scanRuns(le)).filter((s) => s.runId.startsWith(r));
  if (matches.length === 0) throw new DomainError("RUN_NOT_FOUND", `no run ${ref} in ${le.dataHome}`);
  if (matches.length > 1) throw new DomainError("INVALID_ARGUMENT", `${ref} matches ${matches.length} runs (${matches.map((m) => m.runId).join(", ")}); give more characters`);
  const m = matches[0]!;
  if (!m.meta) throw new DomainError(m.readError?.code === "STORE_VERSION_UNSUPPORTED" ? "STORE_VERSION_UNSUPPORTED" : "RUN_NOT_FOUND", `run ${m.runId} cannot be read: ${m.readError?.detail ?? "run.json missing"}`);
  return { runId: m.runId, repoKey: m.repoKey, paths: m.paths, meta: m.meta };
}

/** The full id of an operation of `st` given its id or a unique prefix (>= 8 characters). */
export function resolveOperationRef(st: StateRecord, ref: string): string {
  const r = ref.trim().toLowerCase();
  if (!PREFIX_RE.test(r)) throw new DomainError("INVALID_ARGUMENT", "an operation id (or a unique prefix of at least 8 characters) is required");
  const matches = st.operations.filter((o) => o.operation_id.startsWith(r));
  // An id that is not one of this run's operations is passed through unchanged, so the
  // stop logic reports OPERATION_MISMATCH exactly as stop_review_loop does (MR-E).
  if (matches.length === 0) return r;
  if (matches.length > 1) throw new DomainError("INVALID_ARGUMENT", `${ref} matches ${matches.length} operations of this run; give more characters`);
  return matches[0]!.operation_id;
}

// ---------------------------------------------------------------------------
// Owner liveness (display only)
// ---------------------------------------------------------------------------

function classifier(le: Loaded): (o: OwnerRecord) => Promise<Liveness> {
  return le.env.testHooks?.classify ?? ((o: OwnerRecord) => classifyOwnerLiveness(o, OWNER_LIVENESS_DEPS));
}

// ---------------------------------------------------------------------------
// runs list
// ---------------------------------------------------------------------------

export interface RunRetention {
  max_age_days: number;
  purge_on_startup: boolean;
  last_activity: string | null;
  /** When an age-based purge (retention) could first delete it; null when unknown. */
  eligible_after: string | null;
  verdict: "eligible" | "kept";
  keep_code: string | null;
  keep_reason: string | null;
}

export interface RunRow {
  run_id: string;
  state: string;
  /** The stored state, when a dead server's operation is shown as interrupted. */
  stored_state: string | null;
  created_at: string | null;
  repository_root: string | null;
  goal: string | null;
  /** True when the goal was withheld because the run's confidentiality records are unreadable. */
  goal_withheld?: boolean;
  active_operation: { operation_id: string; kind: string; owner: Liveness | "unknown" } | null;
  reviews: number;
  check_executions: number;
  open_items: number;
  /** Implementer responses recorded on the run's reviewer items (Phase 2.1). */
  responses: number;
  /** Reviewer replies recorded (Phase 2.2). */
  reviewer_replies: number;
  incidents: number;
  read_error: { code: string; detail: string } | null;
  retention: RunRetention;
}

export function retentionOf(le: Loaded, s: ScannedRun, locked: ReadonlySet<string>): RunRetention {
  const days = le.cfg.config.retention.max_age_days;
  const last = lastActivityOf(s);
  const v = verdictOf(s, locked);
  return {
    max_age_days: days,
    purge_on_startup: le.cfg.config.retention.purge_on_startup,
    last_activity: last === null ? null : new Date(last).toISOString(),
    eligible_after: last === null ? null : new Date(last + days * DAY_MS).toISOString(),
    verdict: v.eligible ? "eligible" : "kept",
    keep_code: v.eligible ? null : v.code,
    keep_reason: v.eligible ? null : v.reason,
  };
}

function handleOf(s: ScannedRun): RunHandle | null {
  return s.meta ? { runId: s.runId, repoKey: s.repoKey, paths: s.paths, meta: s.meta } : null;
}

async function rowOf(le: Loaded, s: ScannedRun, locked: ReadonlySet<string>): Promise<RunRow> {
  const observed = s.state ? await observedState(le, s.state) : null;
  const st = observed?.state ?? null;
  const active = s.state?.operations.find((o) => o.status === "running") ?? null;
  let liveness: Liveness | "unknown" = "unknown";
  if (active?.owner) liveness = await classifier(le)(active.owner).catch(() => "unknown" as const);
  const goal = ((s.meta?.envelope ?? {}) as { goal?: unknown }).goal;
  const row: RunRow = {
    run_id: s.runId,
    state: st?.state ?? "UNREADABLE",
    stored_state: st && s.state && st.state !== s.state.state ? s.state.state : null,
    created_at: s.meta?.created_at ?? null,
    repository_root: s.meta?.repository_root ?? null,
    goal: typeof goal === "string" ? goal.slice(0, 160) : null,
    active_operation: active ? { operation_id: active.operation_id, kind: active.kind, owner: liveness } : null,
    reviews: s.state?.reviews.length ?? 0,
    check_executions: s.state?.check_executions.length ?? 0,
    open_items: s.state?.findings.filter((f) => f.status === "open").length ?? 0,
    responses: s.state?.implementer_responses.length ?? 0,
    reviewer_replies: s.state?.reviewer_replies.length ?? 0,
    incidents: s.state?.isolation_incidents.length ?? 0,
    read_error: s.readError,
    retention: retentionOf(le, s, locked),
  };
  // Confidentiality: the goal is host-provided text and may name a withheld file (MR-F). When
  // the run's confidentiality records cannot be read, the goal is withheld (the row's other
  // fields are engine-generated), so one damaged run does not hide the whole list.
  const h = handleOf(s);
  if (!h) return row;
  try {
    return toLocal(row, await disclosureFor(le, h, s.state ? { state: s.state } : {})).value;
  } catch {
    return { ...row, goal: null, goal_withheld: true };
  }
}

export interface ListOptions {
  /** Only runs of this canonical repository root. */
  repo?: string;
}

/** Every run in the store, newest first (the CLI is not limited to the allowed roots). */
export async function listRunRows(le: Loaded, o: ListOptions = {}): Promise<RunRow[]> {
  const locked = await lockedOperationIds(le);
  const scanned = (await scanRuns(le)).filter((s) => !o.repo || (s.meta !== null && samePath(s.meta.repository_root, o.repo)));
  const rows: RunRow[] = [];
  for (const s of scanned) rows.push(await rowOf(le, s, locked));
  return rows.sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
}

// ---------------------------------------------------------------------------
// runs show
// ---------------------------------------------------------------------------

export interface OperationDetail {
  operation_id: string;
  kind: string;
  status: string;
  /** "interrupted" when the stored status is running but its server is gone. */
  observed_status: string;
  started_at: string | null;
  ended_at: string | null;
  owner: { pid: number; server_instance: string; liveness: Liveness | "unknown" } | null;
  cancel_requested: { at: string; mode: string; by: string } | null;
  cancellation: { outcome: string; detail: string; survivors: { pid: number; name: string }[]; unattributable: { pid: number; name: string }[] } | null;
  summary: string;
}

export interface RunDetails {
  run_id: string;
  run_dir: string;
  size: { bytes: number; files: number; complete: boolean };
  state: string;
  stored_state: string;
  revision: number;
  created_at: string;
  updated_at: string;
  repository_root: string;
  root_commit: string | null;
  target: unknown;
  goal: string | null;
  allowed_root_snapshot: string[];
  client_roots_warning: string | null;
  verification_floor: { required: string[]; no_required_checks: boolean };
  budgets: { reviews: { used: number; limit: number }; check_executions: { used: number; limit: number } };
  operations: OperationDetail[];
  recovery_pending: string[];
  checks: {
    execution_id: string;
    operation_id: string;
    check: string;
    status: string;
    exit_code: number | null;
    duration_ms: number | null;
    timed_out: boolean;
    cancelled: boolean;
    source_stable: boolean;
    stdout: { bytes: number; truncated: boolean; file: string | null } | null;
    stderr: { bytes: number; truncated: boolean; file: string | null } | null;
  }[];
  reviews: {
    review_id: string;
    operation_id: string;
    round: number;
    status: string;
    verdict: string | null;
    accepted: boolean | null;
    not_accepted_reasons: string[];
    isolation: string;
    codex_version: string;
    duration_ms: number | null;
    items: number;
    current_at_completion: boolean | null;
    stale_reasons: string[];
    failure: string | null;
  }[];
  /** Open items with their discussion state and the implementer's latest response (Phase 2.1). */
  open_items: CompactFinding[];
  item_counts: Record<string, number>;
  /** Discussion states and responses (Phase 2.1); threads, replies and escalation (Phase 2.2). */
  discussion: DiscussionReport;
  /**
   * Phase 2.3: the derived completion, as status reports it (one bounded read of the working tree;
   * null when the report could not be made, with the reason in notes).
   */
  completion: CompletionReport | null;
  /** Phase 2.3: the user's decisions and task amendments. */
  user: UserReport | null;
  incidents: CompactIncident[];
  events: { total: number; shown: EventView[] };
  withheld: { count: number; paths: string[] | null };
  retention: RunRetention;
  notes: string[];
}

export interface ShowOptions {
  /** List the exact withheld (confidential) paths. */
  reveal?: boolean;
  /** How many of the newest events to show (default 15). */
  events?: number;
}

function artifactFile(run: RunHandle, ref: string | null | undefined): string | null {
  return ref ? resolveArtifact(run.paths.runDir, ref) : null;
}

function opSummary(op: StateRecord["operations"][number], st: StateRecord): string {
  const oc = (op.outcome ?? {}) as Record<string, unknown>;
  if (op.kind === "prepare") {
    if (typeof oc["baseline_source_id"] === "string") return `baseline ${String(oc["baseline_source_id"]).slice(0, 12)}`;
    const f = oc["failure"] as { code?: string } | undefined;
    return f?.code ? `failed: ${f.code}` : "";
  }
  if (op.kind === "checks") {
    const ex = st.check_executions.filter((e) => e.operation_id === op.operation_id);
    return ex.map((e) => `${e.check}: ${e.status}${e.exit_code !== null ? ` (exit ${e.exit_code})` : ""}`).join(", ");
  }
  if (op.kind === "review") {
    const reviewId = (oc["deduplicated_of"] ?? oc["review_id"] ?? op["review_id"]) as string | undefined;
    const r = reviewId ? st.reviews.find((x) => x.review_id === reviewId) : undefined;
    if (!r) return "";
    return `review ${r.review_id.slice(0, 8)} round ${r.round}: ${r.status}${r.verdict ? `, ${r.verdict}` : ""}${r.accepted ? ", accepted" : r.accepted === false ? ", not accepted" : ""}${oc["deduplicated_of"] ? " (identical earlier input)" : ""}`;
  }
  return "";
}

interface ReportSections {
  completion: CompletionReport | null;
  user: UserReport | null;
  discussion: DiscussionReport;
  open_items: CompactFinding[];
  note: string | null;
}

/**
 * Completion, the user layer and the discussion of `runs show` from ONE report (Phase 2.3), built
 * from a bounded read of the working tree as status builds it (a status read: it never waits for
 * the worktree lock), so the discussion and completion agree on who must act. Without that read
 * the discussion judges each turn by the source recorded with it, and the note says why
 * completion is missing.
 */
async function reportSections(le: Loaded, run: RunHandle, raw: StateRecord, observed: StateRecord): Promise<ReportSections> {
  try {
    const src = await currentSource(le, run, raw, SOURCE_BUDGET_MS);
    const report = await runReport(le, run, raw, src.source_id, knownSourceOf(src), observed);
    return { completion: report.completion, user: report.user, discussion: report.discussion, open_items: report.open_findings, note: src.note ? `completion: ${src.note}` : null };
  } catch (e) {
    const d = discussionInputOf(raw, null);
    return {
      completion: null,
      user: null,
      discussion: discussionReport(raw, d),
      open_items: raw.findings.filter((f) => f.status === "open").map((f) => compactFinding(f, d)),
      note: `completion could not be derived now (${(e instanceof Error ? e.message : String(e)).slice(0, 160)})`,
    };
  }
}

export async function runDetails(le: Loaded, run: RunHandle, o: ShowOptions = {}): Promise<RunDetails> {
  // Attended `runs show`: a custodian-governed run derives from the authoritative custodian projection
  // (P3.4C-1); a never-governed run uses the TS store with no custodian exchange.
  const raw = await withAuthoritativeUserRecords(le, run, await readState(run.paths), { protected: false });
  const { state: st, recoveryPending } = await observedState(le, raw);
  const locked = await lockedOperationIds(le);
  const scanned: ScannedRun = { repoKey: run.repoKey, runId: run.runId, paths: run.paths, meta: run.meta, state: raw, readError: null, plainDirectory: await isPlainDirectory(run.paths.runDir) };
  const classify = classifier(le);
  const operations: OperationDetail[] = [];
  for (const op of raw.operations) {
    const obs = st.operations.find((x) => x.operation_id === op.operation_id);
    const cr = op["cancel_requested"] as { at?: string; mode?: string; by?: string } | undefined;
    const oc = (op.outcome ?? {}) as { cancellation?: OperationDetail["cancellation"]; review_id?: string };
    const reviewId = oc.review_id ?? (op["review_id"] as string | undefined);
    const canc = oc.cancellation ?? (reviewId ? (raw.reviews.find((r) => r.review_id === reviewId)?.cancellation ?? null) : null);
    operations.push({
      operation_id: op.operation_id,
      kind: op.kind,
      status: op.status,
      observed_status: obs?.status ?? op.status,
      started_at: op.started_at ?? null,
      ended_at: op.ended_at ?? null,
      owner: op.owner ? { pid: op.owner.pid, server_instance: op.owner.serverInstanceId, liveness: op.status === "running" ? await classify(op.owner).catch(() => "unknown" as const) : "unknown" } : null,
      cancel_requested: cr?.at ? { at: cr.at, mode: cr.mode ?? "", by: cr.by ?? "" } : null,
      cancellation: canc ? { outcome: canc.outcome, detail: canc.detail ?? "", survivors: canc.survivors ?? [], unattributable: canc.unattributable ?? [] } : null,
      summary: opSummary(op, raw),
    });
  }
  const b = effectiveBudgets(le, run.meta);
  const floor = (run.meta as { verification_floor?: { required?: { check: string }[]; no_required_checks?: boolean } }).verification_floor;
  const counts: Record<string, number> = {};
  for (const f of raw.findings) counts[f.status] = (counts[f.status] ?? 0) + 1;
  // A missing or unreadable capture record: which names are withheld is unknown. Only the
  // explicit local --reveal-withheld view may continue (it redacts nothing anyway).
  let withheld: string[] = [];
  let withheldUnknown = false;
  try {
    withheld = await withheldPathsOfRun(run, raw);
  } catch {
    if (!o.reveal) throw new DomainError("INTERNAL", "a capture record of this run is missing or unreadable, so its confidential names are unknown: the details are withheld (MR-F); `runs show --reveal-withheld` shows them unredacted, locally");
    withheldUnknown = true;
  }
  const page = eventsPage(raw, Math.max(0, (raw.events.at(-1)?.seq ?? 0) - Math.max(1, Math.min(o.events ?? 15, 500))), 500);
  const sections = await reportSections(le, run, raw, st);
  const completionNote = sections.note;
  const scopeMeta = run.meta.scope as { allowed_snapshot: string[]; client_roots_warning?: string | null };
  const notes: string[] = [];
  if (recoveryPending.length) notes.push(`${recoveryPending.length} running operation(s) belong to a server that is no longer running; they are shown as interrupted and recovery is recorded by the next operation or \`runs stop\``);
  if (withheld.length && !o.reveal) notes.push(`${withheld.length} path(s) are withheld as confidential; their names are not shown (use --reveal-withheld to list them here, locally)`);
  if (withheldUnknown) notes.push("a capture record of this run is missing or unreadable: its withheld paths cannot be listed");
  notes.push("raw check output, prompts and Codex event streams are not printed; check log files are listed so you can open them yourself");
  if (completionNote) notes.push(completionNote);

  const details: RunDetails = {
    run_id: run.runId,
    run_dir: run.paths.runDir,
    size: await treeSize(run.paths.runDir),
    state: st.state,
    stored_state: raw.state,
    revision: raw.revision,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
    repository_root: run.meta.repository_root,
    root_commit: run.meta.root_commit ?? null,
    target: run.meta.target ?? { kind: "uncommitted" },
    goal: (((run.meta.envelope ?? {}) as { goal?: unknown }).goal as string | undefined) ?? null,
    allowed_root_snapshot: scopeMeta.allowed_snapshot,
    client_roots_warning: scopeMeta.client_roots_warning ?? null,
    verification_floor: { required: [...new Set((floor?.required ?? []).map((r) => r.check))], no_required_checks: floor?.no_required_checks === true },
    budgets: { reviews: { used: raw.counters["reviews"] ?? 0, limit: b.max_reviews_per_run }, check_executions: { used: raw.counters["check_executions"] ?? 0, limit: b.max_check_executions_per_run } },
    operations,
    recovery_pending: recoveryPending,
    checks: raw.check_executions.map((e) => ({
      execution_id: e.execution_id,
      operation_id: e.operation_id,
      check: e.check,
      status: e.status,
      exit_code: e.exit_code,
      duration_ms: e.duration_ms,
      timed_out: e.timed_out,
      cancelled: e.cancelled,
      source_stable: e.source_stable,
      stdout: e.stdout ? { bytes: e.stdout.bytes, truncated: e.stdout.truncated, file: artifactFile(run, e.stdout.artifact) } : null,
      stderr: e.stderr ? { bytes: e.stderr.bytes, truncated: e.stderr.truncated, file: artifactFile(run, e.stderr.artifact) } : null,
    })),
    reviews: raw.reviews.map((r) => ({
      review_id: r.review_id,
      operation_id: r.operation_id,
      round: r.round,
      status: r.status,
      verdict: r.verdict,
      accepted: r.accepted,
      not_accepted_reasons: r.not_accepted_reasons,
      isolation: `${r.effective_isolation.mode}/${r.effective_isolation.backend}/reads ${r.effective_isolation.reads}/network ${r.effective_isolation.network}`,
      codex_version: r.codex.version,
      duration_ms: r.duration_ms,
      items: r.item_ids.length,
      current_at_completion: r.freshness?.current ?? null,
      stale_reasons: r.freshness?.stale_reasons ?? [],
      failure: r.failure ? `${r.failure.class}: ${r.failure.detail}` : null,
    })),
    open_items: sections.open_items,
    item_counts: counts,
    discussion: sections.discussion,
    completion: sections.completion,
    user: sections.user,
    incidents: raw.isolation_incidents.map(compactIncident),
    events: { total: page.total, shown: page.events },
    withheld: { count: withheld.length, paths: o.reveal ? withheld : null },
    retention: retentionOf(le, scanned, locked),
    notes,
  };
  if (o.reveal) return cutExcerpts(details); // the user asked for local details: nothing is redacted
  return toLocal(details, await disclosureFor(le, run, { state: raw })).value;
}
