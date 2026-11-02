// `code-parley runs …` (plan §5.1, §5.4, §15.5, §15.6, §16.4; M1.6). The user's own channel
// for operating the run store; every command is a thin adapter over engine operations:
//
//   runs list   [--repo <path>] [--json]
//   runs show   <run> [--events <n>] [--reveal-withheld] [--json]
//   runs stop   <run> --operation <op> [--reason <text>] [--wait <s>]     cancel exactly that operation
//   runs stop   <run> --abort [--operation <op>] [--reason <text>]        cancel, then STOPPED
//   runs stop   <run> --close [--reason <text>]                           an idle run → CLOSED
//   runs stop   <run-id> (--close | --abort) --repo <path> [--reason <text>]   the operator: at the custodian alone
//   runs purge  (<run>... | --older-than <days> | --retention) [--repo <path>] [--dry-run] [--confirm <token>] [--json]
//
// `stop` is stop_review_loop's own engine function (MR-E, MR-J): targeted by operation id, a
// finished operation reports its outcome, a different active operation is never touched, and
// `terminated` is printed only from the engine's termination evidence. Nothing is swept.
// `purge` previews, then deletes exactly what was previewed (--confirm <token>); active and
// unresolved runs are always kept (policy/retention.ts). Output redacts withheld names by
// default (MR-F); raw check output is never printed. `--abort` and `--close` end the run at the custodian, operator
// surface first; the run counts as ended only on the custodian's acknowledgment, never on the local record. With --repo the
// operator names the run and its repository, and no engine, data home or run store is read: on Linux the operator has none,
// and on any host the implementer's cannot block or steer it (Phase 5 G-OP; TD, candidate 3). Both ids are locators.

import { DomainError } from "../common/errors.js";
import { shortHash } from "../common/hash.js";
import { isUuid } from "../common/ids.js";
import { loadEngine, type Loaded } from "../engine/engine-env.js";
import { askCustodianToEnd, endEstablished, type CustodianEndResult } from "../engine/custodian-evidence.js";
import { stopRun, type StopMode } from "../engine/operations.js";
import { listRunRows, resolveOperationRef, resolveRunRef, runDetails, type RunDetails, type RunRow } from "../engine/run-admin.js";
import { DAY_MS, daysToMs, executePurge, planPurge, type PurgeCandidate, type PurgePlan, type PurgeSelector } from "../engine/retention.js";
import { readState } from "../store/state-store.js";
import type { CustodianDerivation } from "../custodian/protocol.js";
import { custodianPresence } from "../custodian/protected-loops.js";
import { derivationForDisplay } from "../engine/custodian-loop.js";
import { locallyProtected } from "../engine/protected-user-records.js";
import { selfOwner } from "../store/owner.js";
import { canonicalizePath } from "../workspace/paths.js";
import { resolveGitTopLevel } from "../workspace/git-toplevel.js";
import { resolveNativeExecutable } from "../process/native-resolve.js";
import { buildChildEnv } from "../process/env.js";
import { printable } from "../process/command.js";
import { linuxOperatorRepo } from "./operator-trust.js";
import type { CliIo } from "./cli.js";

export interface RunsArgs {
  cmd: string | undefined;
  refs: string[];
  one(flag: string): string | undefined;
  has(flag: string): boolean;
}

/** Exit codes: 0 done, 1 error, 2 confirmation required, 3 cancellation requested but not confirmed, 4 the stop did not establish that no confirmed fix can run. */
export async function runRunsCli(a: RunsArgs, io: CliIo): Promise<number> {
  if (a.cmd === "stop" && a.one("--repo") !== undefined) return stopAtCustodian(a, a.one("--repo")!, io);
  const launch = {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  switch (a.cmd) {
    case "list":
      return list(le, a, io);
    case "show":
      return show(le, a, io);
    case "stop":
      return stop(le, a, io);
    case "purge":
      return purge(le, a, io);
    default:
      throw new DomainError("INVALID_ARGUMENT", "usage: code-parley runs (list | show | stop | purge) … (see code-parley --help)");
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function repoFilter(le: Loaded, raw: string | undefined): Promise<string | undefined> {
  if (raw === undefined) return undefined;
  const canon = await canonicalizePath(raw);
  const g = await resolveNativeExecutable("git", { configured: le.env.launch.git ?? null, env: buildChildEnv({ source: le.env.sourceEnv }).env }).catch(() => null);
  if (!g?.ok || !g.path) return canon;
  return resolveGitTopLevel(canon, { gitExe: g.path }).catch(() => canon); // a deleted repository still filters by path
}

function when(iso: string | null): string {
  return iso ? `${iso.slice(0, 16).replace("T", " ")}Z` : "unknown";
}

function ageDays(iso: string | null, nowMs = Date.now()): string {
  if (!iso) return "?";
  return `${Math.max(0, Math.floor((nowMs - Date.parse(iso)) / DAY_MS))}d`;
}

function mb(bytes: number): string {
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

function dataHomeLine(le: Loaded): string {
  return `data home: ${le.dataHome}${le.cfg.legacyDataHome ? " (legacy folder name AIReviewLoop; see doctor)" : ""}`;
}

// ---------------------------------------------------------------------------
// runs list
// ---------------------------------------------------------------------------

function retentionText(r: RunRow["retention"]): string {
  if (r.verdict === "kept") return `kept by purge: ${r.keep_code}`;
  return r.eligible_after ? `purge-eligible after ${r.eligible_after.slice(0, 10)}` : "purge-eligible";
}

async function list(le: Loaded, a: RunsArgs, io: CliIo): Promise<number> {
  const rows = await listRunRows(le, { ...(a.one("--repo") ? { repo: (await repoFilter(le, a.one("--repo")))! } : {}) });
  if (a.has("--json")) {
    io.out(JSON.stringify({ data_home: le.dataHome, legacy_data_home: le.cfg.legacyDataHome, retention: le.cfg.config.retention, runs: rows }, null, 2));
    return 0;
  }
  io.out(dataHomeLine(le));
  const ret = le.cfg.config.retention;
  io.out(`retention: runs inactive for ${ret.max_age_days} day(s) are purged when a server starts (${ret.purge_on_startup ? "on" : "OFF"}); active and unresolved runs are always kept`);
  for (const r of rows) {
    io.out("");
    // Full ids: the first characters of a UUIDv7 are its timestamp, so short prefixes collide.
    io.out(`${r.run_id}  ${r.state.padEnd(11)}  created ${when(r.created_at)}  last activity ${when(r.retention.last_activity)} (${ageDays(r.retention.last_activity)})`);
    io.out(`    repository: ${r.repository_root ?? "(unknown)"}`);
    if (r.goal) io.out(`    goal: ${r.goal}`);
    else if (r.goal_withheld) io.out("    goal: [withheld: a capture record of this run is missing or unreadable; see runs show --reveal-withheld]");
    if (r.stored_state) io.out(`    stored state ${r.stored_state}: its running operation's server is gone (shown as interrupted; recorded by the next operation or runs stop)`);
    if (r.active_operation) io.out(`    active: ${r.active_operation.kind} operation ${r.active_operation.operation_id} (server ${r.active_operation.owner})`);
    if (r.read_error) io.out(`    UNREADABLE: ${r.read_error.code}: ${r.read_error.detail}`);
    io.out(`    ${r.reviews} review(s), ${r.check_executions} check execution(s), ${r.open_items} open reviewer item(s), ${r.responses} implementer response(s), ${r.reviewer_replies} reviewer repl${r.reviewer_replies === 1 ? "y" : "ies"}, ${r.incidents} isolation incident(s); ${retentionText(r.retention)}`);
  }
  io.out("");
  io.out(`${rows.length} run(s). Details: runs show <run-id> (a unique prefix of at least 8 characters is accepted).`);
  return 0;
}

// ---------------------------------------------------------------------------
// runs show
// ---------------------------------------------------------------------------

/** Phase 2.3: the user's records and the derived completion (P2.3-12). */
function printUserLayer(d: RunDetails, io: CliIo): void {
  if (d.user) {
    const u = d.user;
    const statuses = Object.entries(u.decisions).filter(([k, v]) => k !== "recorded" && typeof v === "number" && v > 0).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`);
    io.out(`user decisions: ${u.decisions.recorded}${statuses.length ? ` (${statuses.join(", ")})` : ""}; task amendments: ${u.amendments.recorded} (${u.amendments.effective} in effect, ${u.amendments.not_seen_by_reviewer} not yet seen by the reviewer)`);
    for (const a of u.amendments.in_effect) io.out(`  ${a.id} ${a.kind}${a.seen_by_reviewer ? ` (seen in round ${a.seen_by_reviewer.round})` : " (not yet seen by the reviewer)"}: ${printable(a.text_excerpt)}`);
  }
  for (const t of d.discussion.threads) {
    const u = t.user_decision;
    if (u) io.out(`  thread ${t.thread_id}: user ${u.kind} — ${u.status}${u.lapse_reasons.length ? ` (${u.lapse_reasons.join(", ")})` : ""}; ${t.blocks_completion ? `still blocks completion (${t.completion_category ?? ""})` : "settled for completion"}`);
  }
  const c = d.completion;
  // P3.4C-5 Increment 3 (§5.4): a protected run's completion is the custodian's derivation; this terminal's is detail.
  const cd = (d as RunDetails & { custodian_derivation?: CustodianDerivation | null }).custodian_derivation ?? null;
  if (cd?.available) io.out(`completion (the custodian's derivation ${cd.derivationId}, ${cd.at}; authoritative for automation): ${cd.completion.state.toUpperCase()}; route ${cd.route.code} (${cd.route.kind})${cd.completion.blockers.length ? `; blockers ${cd.completion.blockers.map((b) => b.code).join(", ")}` : ""}`);
  else if (cd) io.out(`completion: the custodian's derivation is unavailable (${cd.code}: ${printable(cd.detail)}); what follows is this terminal's own, NOT authoritative`);
  if (!c) return;
  io.out(`completion (${cd ? "this terminal's own derivation, detail only" : "derived"}; nothing can set it, and it starts nothing): ${c.state.toUpperCase()}${c.blockers_total ? ` — ${c.blockers_total} blocker(s)` : ""}`);
  for (const b of c.blockers) io.out(`  [${b.category}] ${b.code}${b.threads ? ` (${b.threads} thread(s): ${b.thread_ids?.join(", ") ?? ""}${b.threads > (b.thread_ids?.length ?? 0) ? ", …" : ""})` : ""}: ${printable(b.detail)}`);
  if (c.settled_by_user.waived_total || c.settled_by_user.deferred_total) io.out(`  settled by the user: ${c.settled_by_user.waived_total} waived, ${c.settled_by_user.deferred_total} deferred (their reviewer findings stay open)`);
  for (const l of c.limitations) io.out(`  limitation ${l.code}: ${printable(l.detail)}`);
}

function printDetails(d: RunDetails, io: CliIo): void {
  io.out(`run ${d.run_id}`);
  io.out(`  state: ${d.state}${d.state !== d.stored_state ? ` (stored: ${d.stored_state})` : ""}, revision ${d.revision}; created ${d.created_at}; last change ${d.updated_at}`);
  io.out(`  repository: ${d.repository_root}${d.root_commit ? ` (root commit ${d.root_commit.slice(0, 12)})` : ""}`);
  io.out(`  target: ${JSON.stringify(d.target)}`);
  if (d.goal) io.out(`  goal: ${d.goal}`);
  if (d.client_roots_warning) io.out(`  scope warning: ${d.client_roots_warning}`);
  io.out(`  verification floor: ${d.verification_floor.no_required_checks ? "no required checks (explicit)" : d.verification_floor.required.length ? d.verification_floor.required.join(", ") : "none configured"}`);
  io.out(`  budgets: reviews ${d.budgets.reviews.used}/${d.budgets.reviews.limit}, check executions ${d.budgets.check_executions.used}/${d.budgets.check_executions.limit}`);
  io.out(`  run store: ${d.run_dir} (${mb(d.size.bytes)}${d.size.complete ? "" : "+"}, ${d.size.files} file(s); contains copies of repository files)`);
  io.out(`  retention: last activity ${d.retention.last_activity ?? "unknown"}; ${d.retention.verdict === "kept" ? `kept by purge: ${d.retention.keep_reason}` : `purge-eligible after ${d.retention.eligible_after ?? "?"} (max age ${d.retention.max_age_days} days)`}`);
  io.out("operations:");
  for (const o of d.operations) {
    io.out(`  ${o.operation_id}  ${o.kind.padEnd(7)} ${o.observed_status}${o.observed_status !== o.status ? ` (stored: ${o.status})` : ""}  ${when(o.started_at)} → ${when(o.ended_at)}${o.summary ? `  ${o.summary}` : ""}`);
    if (o.status === "running" && o.owner) io.out(`      owner: server pid ${o.owner.pid} (${o.owner.liveness})`);
    if (o.cancel_requested) io.out(`      cancellation requested ${o.cancel_requested.at} (${o.cancel_requested.mode})`);
    if (o.cancellation) {
      io.out(`      cancellation: ${o.cancellation.outcome} — ${o.cancellation.detail}`);
      for (const p of o.cancellation.survivors) io.out(`        possible survivor: pid ${p.pid} ${p.name}`);
      for (const p of o.cancellation.unattributable) io.out(`        unattributable (not killed): pid ${p.pid} ${p.name}`);
    }
  }
  if (d.checks.length) {
    io.out("check executions:");
    for (const c of d.checks) {
      io.out(`  ${c.check}: ${c.status}${c.exit_code !== null ? ` (exit ${c.exit_code})` : ""}${c.duration_ms !== null ? `, ${(c.duration_ms / 1000).toFixed(1)} s` : ""}${c.timed_out ? ", timed out" : ""}${c.cancelled ? ", cancelled" : ""}${c.source_stable ? "" : ", source changed during the check"}  [execution ${c.execution_id.slice(0, 8)}, operation ${c.operation_id.slice(0, 8)}]`);
      for (const [name, s] of [["stdout", c.stdout], ["stderr", c.stderr]] as const) if (s) io.out(`      ${name}: ${s.bytes} byte(s)${s.truncated ? " (stored copy capped)" : ""}${s.file ? ` — ${s.file}` : ""}`);
    }
  }
  if (d.reviews.length) {
    io.out("reviews:");
    for (const r of d.reviews) {
      io.out(`  round ${r.round} ${r.review_id.slice(0, 8)}: ${r.status}${r.verdict ? `, ${r.verdict}` : ""}${r.accepted ? ", accepted" : r.accepted === false ? `, not accepted (${r.not_accepted_reasons.join(", ")})` : ""}; ${r.isolation}; Codex ${r.codex_version}${r.duration_ms !== null ? `, ${Math.round(r.duration_ms / 1000)} s` : ""}; ${r.items} item(s)${r.current_at_completion === false ? `; not current at completion (${r.stale_reasons.join(", ")})` : ""}${r.failure ? `; ${r.failure}` : ""}`);
    }
  }
  io.out(`reviewer items: ${Object.entries(d.item_counts).map(([k, v]) => `${v} ${k}`).join(", ") || "none"} (triaged per the reviewer's evidence; not engine-verified)`);
  for (const f of d.open_items) {
    const loc = f.locations[0];
    io.out(`  [open] ${f.triage} ${f.severity ?? ""} ${f.category ?? ""}: ${f.title}${loc?.path ? ` (${loc.path}${loc.start_line ? `:${loc.start_line}${loc.end_line && loc.end_line !== loc.start_line ? `-${loc.end_line}` : ""}` : ""})` : ""} — round ${f.round}  [item ${f.id}]`);
    const r = f.implementer_response;
    io.out(`      discussion: ${f.discussion_state.replace(/_/g, " ")}${r ? ` — implementer ${r.disposition} ${when(r.recorded_at)} (answering round ${r.answers_round}${r.responses_on_item > 1 ? `, ${r.responses_on_item} responses` : ""}${r.stale_reasons.length ? `; ${r.stale_reasons.join(", ")}` : ""}; ${r.seen_by_reviewer ? `seen by the reviewer in round ${r.seen_by_reviewer.round}` : r.delivery === "pending" ? "the next review presents it" : `not presented to the reviewer${r.delivery_reason ? ` (${r.delivery_reason.replace(/_/g, " ")})` : ""}`}): ${printable(r.rationale_excerpt)}` : ""}  [thread ${f.thread_id}]`);
  }
  if (d.discussion.responses_recorded) io.out(`implementer responses: ${d.discussion.responses_recorded} recorded (claims by the implementer, not user decisions; nothing is resolved by a response)`);
  if (d.discussion.reviewer_replies_recorded) io.out(`reviewer replies: ${d.discussion.reviewer_replies_recorded} recorded (the reviewer's stance; it changes no item's lifecycle)`);
  if (d.discussion.threads.length) {
    io.out(`discussion threads: ${d.discussion.threads_total} (${d.discussion.awaiting_implementer} awaiting the implementer, ${d.discussion.awaiting_reviewer} with a turn the next review presents, ${d.discussion.awaiting_user} needing a user decision); exchanges used ${d.discussion.exchanges_used} of ${d.discussion.exchanges_limit_per_run} per run`);
    for (const t of d.discussion.threads) {
      const li = t.latest_implementer;
      const lr = t.latest_reviewer;
      io.out(`  thread ${t.thread_id}: ${t.item_count} item(s); awaiting ${t.awaiting}; exchanges ${t.exchanges?.used ?? 0}/${t.exchanges?.limit ?? "?"}${t.escalation?.needed ? `; ESCALATION: ${t.escalation.reasons.join(", ")}` : ""}${t.new_information_required ? "; new information required to continue" : ""}`);
      if (li) io.out(`      implementer: ${li.position} (${li.seen_by_reviewer ? `seen in round ${li.seen_by_reviewer.round}` : li.delivery === "pending" ? "the next review presents it" : `not presented${li.delivery_reason ? `: ${li.delivery_reason.replace(/_/g, " ")}` : ""}`})`);
      if (lr) io.out(`      reviewer: ${lr.stance} in round ${lr.round}${lr.new_information === "no" ? " (no new information)" : ""}: ${printable(lr.reply_excerpt)}`);
    }
  }
  printUserLayer(d, io);
  io.out(`isolation incidents: ${d.incidents.length}`);
  for (const i of d.incidents) io.out(`  ${i.kind} (${i.at}): ${i.detail}`);
  if (d.withheld.paths) {
    io.out(`withheld (confidential) paths — local view, do not paste into a model conversation:`);
    for (const p of d.withheld.paths) io.out(`  ${p}`);
  }
  io.out(`events (last ${d.events.shown.length} of ${d.events.total}):`);
  for (const e of d.events.shown) io.out(`  #${e.seq} ${e.ts} ${e.actor} ${e.type}: ${e.summary}`);
  for (const n of d.notes) io.out(`note: ${n}`);
}

async function show(le: Loaded, a: RunsArgs, io: CliIo): Promise<number> {
  if (a.refs.length !== 1) throw new DomainError("INVALID_ARGUMENT", "runs show takes exactly one run id");
  const run = await resolveRunRef(le, a.refs[0]!);
  const events = a.one("--events") !== undefined ? Number(a.one("--events")) : undefined;
  if (events !== undefined && (!Number.isInteger(events) || events < 1)) throw new DomainError("INVALID_ARGUMENT", "--events must be a positive integer");
  const details = await runDetails(le, run, { reveal: a.has("--reveal-withheld"), ...(events !== undefined ? { events } : {}) });
  // P3.4C-5 Increment 3 (§5.4): a protected run shows the custodian's derivation.
  const custodian = await derivationForDisplay(le, run, locallyProtected(await readState(run.paths))).catch(() => null);
  const d = custodian ? { ...details, custodian_derivation: custodian } : details;
  if (a.has("--json")) io.out(JSON.stringify(d, null, 2));
  else printDetails(d, io);
  return 0;
}

// ---------------------------------------------------------------------------
// runs stop (the engine's stop_review_loop semantics, MR-E/MR-J)
// ---------------------------------------------------------------------------

async function stop(le: Loaded, a: RunsArgs, io: CliIo): Promise<number> {
  if (a.refs.length !== 1) throw new DomainError("INVALID_ARGUMENT", "runs stop takes exactly one run id");
  const modes = [a.has("--abort") && "abort", a.has("--close") && "close"].filter(Boolean) as StopMode[];
  if (modes.length > 1) throw new DomainError("INVALID_ARGUMENT", "choose one of --abort or --close");
  const mode: StopMode = modes[0] ?? "cancel_active";
  const opRef = a.one("--operation");
  if (mode === "cancel_active" && !opRef) throw new DomainError("INVALID_ARGUMENT", "--operation <operation-id> is required: cancellation always targets one operation (see runs show). Use --abort to cancel whatever is active and end the run, or --close to end an idle run.");
  if (mode === "close" && opRef) throw new DomainError("INVALID_ARGUMENT", "--close takes no --operation (it requires an idle run)");
  const waitS = a.one("--wait") !== undefined ? Number(a.one("--wait")) : 45;
  if (!Number.isFinite(waitS) || waitS < 0 || waitS > 600) throw new DomainError("INVALID_ARGUMENT", "--wait must be 0..600 seconds");
  const run = await resolveRunRef(le, a.refs[0]!);
  const expected = opRef ? resolveOperationRef(await readState(run.paths), opRef) : undefined;
  const out = await stopRun(le, run, mode, expected, a.one("--reason"), Math.round(waitS * 1000), undefined, { actor: "user_cli", custodianSurfaces: ["operator", "implementer"] });
  io.out(`run ${run.runId}: ${mode}${expected ? ` (operation ${expected})` : ""}`);
  io.out(`  ${out.custodian_end && out.custodian_end.outcome !== "no_custodian" ? "local record" : "run state"}: ${out.state.state}`);
  const ended = out.custodian_end ? printCustodianEnd(out.custodian_end, run.runId, io) : true;
  const notEnded = ended ? 0 : 4;
  const c = out.cancellation;
  if (!c) {
    if (mode !== "close") io.out("  no operation was active");
    else if (ended) {
      io.out("  the run is closed (read-only from now on); open items, conditions and incidents stay in its history");
      io.out(`  completion at closing (derived; closing did not need it to be ready): code-parley runs show ${run.runId}`);
    }
    return notEnded;
  }
  io.out(`  ${c.kind} operation ${c.operation_id}: ${c.outcome} (operation status ${c.operation_status})`);
  io.out(`  ${c.detail}`);
  for (const p of c.record?.survivors ?? []) io.out(`    possible survivor: pid ${p.pid} ${p.name}`);
  for (const p of c.record?.unattributable ?? []) io.out(`    unattributable (not killed): pid ${p.pid} ${p.name}`);
  if (c.outcome === "cancellation_requested") {
    io.out("  Termination is NOT confirmed. code-parley never sweeps processes: inspect the processes named above yourself. Check again with `code-parley runs show`.");
    return notEnded || 3;
  }
  return notEnded;
}

/** The operator's stop: the custodian's `end`, from the two locators alone. Nothing local is read, changed or cancelled. */
async function stopAtCustodian(a: RunsArgs, repo: string, io: CliIo): Promise<number> {
  const usage = "code-parley runs stop <full-run-id> (--close | --abort) --repo <path>";
  if (a.refs.length !== 1) throw new DomainError("INVALID_ARGUMENT", `runs stop takes exactly one run id: ${usage}`);
  const runId = a.refs[0]!.trim().toLowerCase();
  if (!isUuid(runId)) throw new DomainError("INVALID_ARGUMENT", `give the full run id with --repo (no prefix: there is no run store to resolve it in): ${usage}`);
  if (a.has("--abort") === a.has("--close")) throw new DomainError("INVALID_ARGUMENT", `choose one of --abort or --close: ${usage}`);
  if (a.one("--operation") !== undefined || a.one("--wait") !== undefined) throw new DomainError("INVALID_ARGUMENT", `--operation and --wait need the run's local record; with --repo nothing local is cancelled: ${usage}`);
  const repositoryRoot = process.platform === "linux" ? linuxOperatorRepo(repo) : repo;
  const status = a.has("--close") ? "closed" : "stopped";
  const hooks = io.engineTestHooks?.custodian;
  const sel = { custodian: hooks, presence: () => custodianPresence(io.engineTestHooks !== undefined, hooks), repositoryRoot, runId };
  const r = await askCustodianToEnd(sel, { status, reason: a.one("--reason")?.trim() || `${status} by the operator` }, ["operator", "implementer"], false);
  io.out(`run ${runId}: ${a.has("--close") ? "close" : "abort"} at the custodian (repository ${repositoryRoot})`);
  io.out("  local record: not read and not changed; nothing local was cancelled");
  const ended = printCustodianEnd(r, runId, io, repositoryRoot);
  if (r.outcome === "ended" || r.outcome === "already_ended") io.out("  An operation already running finishes on its own. The implementer's record catches up on its next call.");
  return ended ? 0 : 4;
}

/** The custodian's answer about the run's end. True only when the stop established that no confirmed fix can run. */
function printCustodianEnd(r: CustodianEndResult, runId: string, io: CliIo, repo?: string): boolean {
  const named = repo === undefined ? "" : ` --repo ${repo}`;
  switch (r.outcome) {
    case "no_custodian":
      io.out("  custodian: none is installed on this host; this is an attended run");
      break;
    case "ended":
    case "already_ended":
      io.out(`  custodian: ${r.outcome === "ended" ? `ended the run (${r.surface} surface)` : "the run had already ended"}; no confirmed fix can begin now`);
      if (r.applications === null) io.out(`  WARNING: the custodian's record could not be read, so whether an application had already begun is UNKNOWN. Check: code-parley fix show ${runId}${named}`);
      for (const p of r.applications ?? []) io.out(`  WARNING: application ${p.operation_id} had already begun (${p.status}) and is not recalled. The implementer checks the working tree: code-parley fix reconcile ${runId}`);
      break;
    case "refused":
      io.out(`  custodian: the run is NOT ended: refused ${r.code}: ${printable(r.detail)}`);
      io.out(r.code === "RUN_BUSY" ? `  A confirmed fix can still be applied. Stop what is running: code-parley runs stop ${runId} --abort${named}` : r.code === "RUN_NOT_OPEN" ? `  ${repo === undefined ? "The repository comes from the local run record, which proves nothing." : "The custodian holds no run under this id and repository: check both."} A protected run may still be open under another repository.` : "  A confirmed fix can still be applied.");
      break;
    case "not_delivered":
      io.out(`  custodian: the run is NOT ended: the request did not reach it (${r.code}: ${printable(r.detail)})`);
      io.out("  A confirmed fix can still be applied. Repeat this command once the custodian answers.");
      break;
    case "unknown":
      io.out(`  custodian: UNKNOWN whether the run ended: the answer was lost (${r.code}: ${printable(r.detail)})`);
      io.out("  Treat the run as NOT ended. Repeat this command: it is safe to repeat.");
      break;
  }
  return endEstablished(r);
}

// ---------------------------------------------------------------------------
// runs purge (preview → confirm → delete exactly what was previewed)
// ---------------------------------------------------------------------------

function candidateLine(c: PurgeCandidate): string {
  return `${c.run_id}  ${c.state.padEnd(11)}  last activity ${when(c.last_activity)} (${ageDays(c.last_activity)})  ${mb(c.bytes)}  ${c.repository_root ?? "(unknown repository)"}`;
}

function printPlan(le: Loaded, plan: PurgePlan, io: CliIo): void {
  io.out(dataHomeLine(le));
  const total = plan.delete.reduce((s, c) => s + c.bytes, 0);
  io.out(`would delete ${plan.delete.length} run(s), ${mb(total)}:`);
  for (const c of plan.delete) io.out(`  ${candidateLine(c)}`);
  if (plan.keep.length) {
    io.out(`kept (never purged while active or unresolved) — ${plan.keep.length} run(s):`);
    for (const c of plan.keep) io.out(`  ${candidateLine(c)}\n      ${c.keep_code}: ${c.keep_reason}`);
  }
  if (plan.pending_trash.length) io.out(`${plan.pending_trash.length} leftover item(s) of an earlier purge in runs\\.trash will be retried`);
}

async function purge(le: Loaded, a: RunsArgs, io: CliIo): Promise<number> {
  const sel: PurgeSelector = {};
  const older = a.one("--older-than");
  if (a.refs.length) sel.runIds = await Promise.all(a.refs.map(async (r) => (await resolveRunRef(le, r)).runId));
  if (older !== undefined) sel.minAgeMs = daysToMs(Number(older));
  if (a.has("--retention")) sel.minAgeMs = le.cfg.config.retention.max_age_days * DAY_MS;
  if (!sel.runIds && sel.minAgeMs === undefined) throw new DomainError("INVALID_ARGUMENT", "say what to purge: run ids, --older-than <days>, or --retention (the configured max_age_days)");
  if (a.one("--repo")) sel.repo = (await repoFilter(le, a.one("--repo")))!;

  const plan = await planPurge(le, sel);
  if (a.has("--json") && (a.has("--dry-run") || !a.one("--confirm"))) {
    io.out(JSON.stringify({ data_home: le.dataHome, ...plan }, null, 2));
    return a.has("--dry-run") || (plan.delete.length === 0 && plan.pending_trash.length === 0) ? 0 : 2;
  }
  printPlan(le, plan, io);
  if (plan.delete.length === 0 && plan.pending_trash.length === 0) {
    io.out("nothing to delete");
    return 0;
  }
  if (a.has("--dry-run")) return 0;

  const confirm = a.one("--confirm");
  let ok = confirm !== undefined && confirm.toLowerCase() === plan.token;
  if (confirm !== undefined && !ok) {
    io.err(`--confirm ${confirm} does not match the runs listed above (token ${plan.token}): the selection or a run changed since the preview. Nothing was deleted.`);
    return 2;
  }
  if (!ok && io.prompt) ok = (await io.prompt(`Type "purge" to delete the ${plan.delete.length} run(s) listed above: `)).trim() === "purge";
  if (!ok) {
    io.out(`Not deleted. To delete exactly the runs listed above, re-run the same command with --confirm ${plan.token}`);
    return 2;
  }
  const out = await executePurge(le, plan);
  if (a.has("--json")) io.out(JSON.stringify(out, null, 2));
  for (const d of out.deleted) io.out(`deleted ${d.run_id} (${mb(d.bytes)}, ${d.files} file(s))`);
  for (const s of out.skipped) io.out(`NOT deleted ${s.run_id}: ${s.reason}`);
  for (const i of out.incomplete) io.out(`INCOMPLETE ${i.run_id}: moved out of the store, ${i.remaining} item(s) could not be deleted yet (retried by the next purge; ${i.tombstone})`);
  if (out.trash_cleaned) io.out(`cleaned ${out.trash_cleaned} leftover item(s) of an earlier purge`);
  io.out(`purge: ${out.deleted.length} deleted, ${out.skipped.length} not deleted, ${out.incomplete.length} incomplete (token ${shortHash(plan.token)})`);
  return out.skipped.length || out.incomplete.length ? 1 : 0;
}
