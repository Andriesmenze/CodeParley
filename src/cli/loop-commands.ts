// `code-parley loop …` (Phase 3.3a; P3.4C-0): the operator's channel for same-session continuation.
//
//   loop grants                                      the custodian's grants and its ceilings (read-only)
//   loop allow  --repo <path> [--loops <n>] [--minutes <m>] [--request-id <id>]
//                                                    allow n automated loops in that repository until
//                                                    they expire (elevated, interactive terminal only)
//   loop revoke --repo <path>                        revoke that repository's active grants (elevated)
//   loop show   <run> [--json]                       a run's loop: status, budgets, binding, wakes
//   loop stop   <run> [--reason <text>]              operator cancellation: automation ends (also
//                                                    acknowledges an unreconciled loop start)
//   loop resume <run>                                resume a paused loop (interactive terminal only)
//   … <run> --repo <path>                           Phase 5 F-i2-5: the run as the CUSTODIAN holds it, for an operator
//                                                    who cannot read the implementer's run store (Linux, D5-B)
//
// A grant is the only way an automated loop can start (start_review_loop consumes one); no tool, hook or
// model text creates or enlarges one. Since P3.4C-0 grants are held by the Windows custodian: `allow` and
// `revoke` are operator actions the custodian accepts only from an ELEVATED operator token (its OS caller
// classification, assurance L1), `allow` is two-phase (the custodian renders what it will grant, the
// operator confirms it by typing, then it is committed), and the custodian enforces its own ceilings.
// Like `decide` and `amend`, `allow` and `resume` also require an interactive terminal and have no
// --confirm flag — layering, not the security boundary. Stopping needs no confirmation: it only reduces
// automation. Without a validated custodian (every platform but Windows today) grants are refused.

import { DomainError, isDomainError } from "../common/errors.js";
import { loadEngine, gitExeOf, type Loaded } from "../engine/engine-env.js";
import { commitGrant, custodianRunOf, grantProblems, listGrants, loopDetails, operatorResumeLoop, operatorStopLoop, prepareGrant, refuseWhileHeldDecisionNeeded, resumeOverview, revokeGrants, type GrantRequest } from "../engine/loop-authority.js";
import { custodianLoopForDisplay, operatorEndLoop, operatorResumeLoopAt, type CustodianRunRef } from "../engine/custodian-loop.js";
import { resolveRunRef } from "../engine/run-admin.js";
import { lapsedRecords, operatorConfigSection } from "../engine/config-authority.js";
import { custodianEquipped } from "../engine/protected-user-records.js";
import { reconfirmRepository } from "./config-commands.js";
import { HARD_LOOP_LIMITS } from "../policy/continuation.js";
import { readState } from "../store/state-store.js";
import { pidAlive, selfOwner } from "../store/owner.js";
import { canonicalizePath } from "../workspace/paths.js";
import { resolveGitTopLevel } from "../workspace/git-toplevel.js";
import { linuxOperatorRepo } from "./operator-trust.js";
import type { CliIo } from "./cli.js";

export interface LoopArgs {
  cmd: string | undefined;
  refs: string[];
  one(flag: string): string | undefined;
  has(flag: string): boolean;
}

export const LOOP_NOT_INTERACTIVE =
  "Loop grants and resumes are recorded only at an interactive terminal, with the confirmation typed by you: run this command yourself in a terminal (stdin and stdout must be a terminal; there is no flag that skips this). Nothing was recorded.";

const NOT_ELEVATED =
  "The CodeParley custodian accepts grants and revocations only from the operator surface with an elevated operator token: run this command in an elevated terminal (Run as administrator) as the operator account. Nothing was recorded.";

export async function runLoopCli(a: LoopArgs, io: CliIo): Promise<number> {
  const launch = {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
  // P3.4C-4: the loop commands are the operator's channel: a protected run's configuration is read on the OPERATOR surface (the
  // pipe the operator account reaches), as its user records are (P3.4C-3 asOperator).
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), custodianReadSurface: "operator", ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  if (a.has("--confirm")) throw new DomainError("INVALID_ARGUMENT", "loop has no --confirm: you confirm by typing at an interactive terminal (nothing skips that)");
  try {
    switch (a.cmd) {
      case "grants":
        return await grants(le, a, io);
      case "allow":
        return await allow(le, a, io);
      case "revoke":
        return await revoke(le, a, io);
      case "show":
        return await show(le, a, io);
      case "stop":
        return await stop(le, a, io);
      case "resume":
        return await resume(le, a, io);
      default:
        throw new DomainError("INVALID_ARGUMENT", "usage: code-parley loop (grants | allow | revoke | show | stop | resume) … (see code-parley --help)");
    }
  } catch (e) {
    // The custodian's OS caller classification refused a non-elevated (or non-operator) caller.
    if (isDomainError(e) && e.code === "CALLER_NOT_AUTHORIZED") throw new DomainError("CALLER_NOT_AUTHORIZED", `${NOT_ELEVATED} (${e.message})`);
    throw e;
  }
}

/** The repository an operator command names with `--repo` (on Linux resolved by the custodian: G-OP). */
export async function repoRoot(le: Loaded, raw: string | undefined): Promise<string> {
  if (!raw) throw new DomainError("INVALID_ARGUMENT", "--repo <path> is required");
  // Phase 5 G-OP: the separate Linux operator account cannot read the repository; the custodian resolves it.
  if (process.platform === "linux") return linuxOperatorRepo(raw);
  return resolveGitTopLevel(await canonicalizePath(raw), { gitExe: await gitExeOf(le) });
}

function intFlag(a: LoopArgs, flag: string, dflt: number): number {
  const v = a.one(flag);
  if (v === undefined) return dflt;
  if (!/^\d{1,6}$/.test(v.trim())) throw new DomainError("INVALID_ARGUMENT", `${flag} must be a whole number`);
  return Number(v.trim());
}

const perLoop = (): string => {
  const L = HARD_LOOP_LIMITS;
  return `${L.continuations} automated continuation(s), ${L.wakes_per_run} idle wake(s) (${L.wakes_per_operation} per review) and ${Math.round(L.run_seconds / 60)} minutes`;
};

async function grants(le: Loaded, a: LoopArgs, io: CliIo): Promise<number> {
  const listing = await listGrants(le);
  if (a.has("--json")) {
    io.out(JSON.stringify({ custodian: { ceilings: listing.ceilings }, per_loop_limits: HARD_LOOP_LIMITS, grants: listing.grants }, null, 2));
    return 0;
  }
  const c = listing.ceilings;
  io.out(c ? `custodian ceilings (enforced by the custodian): at most ${c.loops} loop(s) and ${c.minutes} minutes per grant` : "custodian ceilings: not reported by this custodian");
  io.out(`per loop (CodeParley's limits): ${perLoop()}`);
  const now = Date.now();
  for (const g of listing.grants) {
    const state = g.identity === "legacy_text" ? "inert (recorded before P3.4C-0 under a textual identity: never consumed)" : g.revoked ? "revoked" : g.suspended ? "suspended after a restart of the OS (never consumed again; a new grant is needed)" : Date.parse(g.expiresAt) <= now ? `expired ${g.expiresAt}` : g.loopsUsed >= g.loopsTotal ? "used up" : `valid until ${g.expiresAt}`;
    io.out(`${g.grantId}  ${g.repositoryRoot ?? "(path not recorded)"}`);
    io.out(`    loops ${g.loopsUsed}/${g.loopsTotal}; ${state}; identity ${g.repoKey}; assurance ${g.assurance}`);
  }
  io.out(`${listing.grants.length} grant(s) held by the custodian.`);
  return 0;
}

async function allow(le: Loaded, a: LoopArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  const req: GrantRequest = { repository_root: root, loops: intFlag(a, "--loops", 1), minutes: intFlag(a, "--minutes", 60), request_id: a.one("--request-id") };
  const problems = grantProblems(req);
  if (problems.length) throw new DomainError("INVALID_ARGUMENT", problems.join("; "));
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", LOOP_NOT_INTERACTIVE);
  let prepared;
  try {
    prepared = await prepareGrant(le, req);
  } catch (e) {
    if (isDomainError(e) && e.code === "REQUEST_ID_CONFLICT" && /already committed/i.test(e.message)) {
      io.out(`This request id was already recorded by the custodian. Nothing new was recorded.`);
      return 0;
    }
    if (isDomainError(e) && e.code === "REQUEST_ID_CONFLICT") throw new DomainError("REQUEST_ID_CONFLICT", `an authorization with this request id is already pending at the custodian; use another --request-id (or none). Nothing was recorded (${e.message})`);
    throw e;
  }
  io.out("The CodeParley custodian prepared this grant (nothing is granted until you confirm):");
  for (const line of prepared.rendering.split("\n")) io.out(`  ${line}`);
  io.out(`You allow CodeParley to keep the Claude Code session that starts a loop in this repository working on its own: up to ${req.loops} loop(s), each one with at most ${perLoop()}, until ${new Date(Date.now() + req.minutes * 60_000).toISOString()}. This confirmation expires at ${prepared.expiresAt}.`);
  io.out("Automation adds liveness only: it records no user decision, never clears a needs_user_decision pause, and READY authorizes no commit, push, merge, tag or release. You can stop it at any time: code-parley loop stop <run>, or revoke the grant: code-parley loop revoke --repo <path>.");
  const answer = (await io.prompt('Type "allow" to grant this (anything else cancels): ')).trim().toLowerCase();
  if (answer !== "allow") {
    io.out("Not recorded (the prepared authorization expires unused).");
    return 2;
  }
  const out = await commitGrant(le, prepared.authorizationRequestId);
  io.out(`Recorded by the custodian: grant ${out.grantId}, ${out.loopsTotal} loop(s) until ${out.expiresAt} (assurance ${out.assurance}).`);
  return 0;
}

async function revoke(le: Loaded, a: LoopArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  const n = await revokeGrants(le, root);
  io.out(`revoked ${n} grant(s) for ${root}; loops already started keep running until they end (code-parley loop stop <run> ends one)`);
  return 0;
}

// ---- Phase 5 F-i2-5 (option A): the run as the custodian holds it (`--repo <path>`) ----
//
// On Linux the operator account cannot read the implementer's run store (D5-B), so a run-scoped command names the run
// by its repository and id and acts on the CUSTODIAN's records only: the loop's status, budgets and binding as the
// custodian holds them, and its operator transitions. The implementer's local record is a cache the engine reconciles
// from the custodian; this account never writes it.

/** The run the operator named with `--repo`, confirmed with the custodian (null: no `--repo`, the local run store). */
async function custodianRun(le: Loaded, a: LoopArgs): Promise<CustodianRunRef | null> {
  const repo = a.one("--repo");
  if (repo === undefined) return null;
  const ref = a.refs[0];
  if (!ref) throw new DomainError("INVALID_ARGUMENT", "name the run: code-parley loop show|stop|resume <run> --repo <path>");
  return custodianRunOf(le, await repoRoot(le, repo), ref);
}

async function showCustodianRun(le: Loaded, run: CustodianRunRef, a: LoopArgs, io: CliIo): Promise<number> {
  const c = await custodianLoopForDisplay(le, run);
  if (a.has("--json")) {
    io.out(JSON.stringify({ run_id: run.runId, repository_root: run.meta.repository_root, loop: c, source: "custodian" }, null, 2));
    return 0;
  }
  if (!c) {
    io.out(`run ${run.runId} (${run.meta.repository_root}): the custodian holds no automation loop for it`);
    return 0;
  }
  const left = Math.max(0, Math.round((Date.parse(c.deadlineAt) - Date.now()) / 1000));
  io.out(`run ${run.runId} (${run.meta.repository_root}) — as the custodian holds it`);
  io.out(`loop ${c.loopId}: ${c.status}${c.pause ? ` — paused: ${c.pause.reason} at ${c.pause.at}` : ""}${c.ended ? ` — ended: ${c.ended.status} (${c.ended.reason}) at ${c.ended.at}` : ""}`);
  io.out(`  started ${c.startedAt}; deadline ${c.deadlineAt} (${left} s left); grant ${c.grantId} (loop ${c.grantUse.loopsUsed} of ${c.grantUse.loopsTotal})`);
  io.out(`  continuations ${c.used.continuations}/${c.limits.continuations}; wakes ${c.used.wakes}/${c.limits.wakesPerRun} (${c.limits.wakesPerOperation} per review) — the custodian's counters`);
  io.out(c.binding ? `  binding: ${c.binding.state}, process ${c.binding.verified ? "verified by the custodian" : "NOT verified"}` : "  binding: none (not bound to a session)");
  const current = c.operations.find((o) => o.current);
  io.out(`  operations: ${c.operations.length}${current ? `; current ${current.handle} (wakes used ${current.wakesUsed})` : ""}; wake claims: ${c.wakeClaims.length}`);
  return 0;
}

async function stopCustodianRun(le: Loaded, run: CustodianRunRef, a: LoopArgs, io: CliIo): Promise<number> {
  const r = await operatorEndLoop(le, run, a.one("--reason") ?? "no reason given");
  if (r.applied) io.out(`automation of run ${run.runId} cancelled by the custodian (${r.surface} surface); nothing continues or wakes automatically`);
  else if (r.code === "INVALID_LOOP_TRANSITION" || r.reason.includes("holds no automation loop")) io.out(`the loop of run ${run.runId} had already ended or does not exist (${r.reason}); nothing changed`);
  else throw new DomainError(r.code === "CUSTODIAN_UNAVAILABLE" ? "CUSTODIAN_UNAVAILABLE" : r.code === "CALLER_NOT_AUTHORIZED" ? "CALLER_NOT_AUTHORIZED" : "INVALID_ARGUMENT", `the custodian did NOT record the cancellation (${r.reason})`);
  return 0;
}

async function resumeCustodianRun(le: Loaded, run: CustodianRunRef, io: CliIo): Promise<number> {
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", LOOP_NOT_INTERACTIVE);
  const root = run.meta.repository_root;
  // P3.4C-4 (D4-E): a lapsed configuration is re-confirmed first, as its own authorization.
  const section = await operatorConfigSection(le, root);
  const lapsed = lapsedRecords(section);
  if (lapsed.repository || (section.repository && lapsed.globals > 0)) {
    io.out(`The repository's protected configuration lapsed when the custodian recovered after a restart of the OS. Re-confirm it first; this is separate from the resume.`);
    const code = await reconfirmRepository(le, io, root, section);
    if (code !== 0) {
      io.out("The configuration was not re-confirmed, so the resume is refused (CONFIG_LAPSED). Nothing was resumed.");
      return 2;
    }
  }
  const o = await resumeOverview(le, run);
  if (o.unavailable !== null || !o.loop) {
    io.out(`The custodian's record of this loop could not be read (${o.unavailable ?? "no loop record"}); nothing was resumed.`);
    return 1;
  }
  io.out(`run ${run.runId}: the custodian's loop is ${o.loop.status}${o.loop.pause ? ` (${o.loop.pause})` : ""}`);
  io.out(`Resuming lets CodeParley continue this run's session automatically again, within what is left of its budgets as the custodian records them (continuations ${o.loop.used.continuations}/${o.loop.limits.continuations}, wakes ${o.loop.used.wakes}/${o.loop.limits.wakesPerRun}) and until ${o.loop.deadlineAt}. It records no decision.`);
  if (o.recovered) io.out("The custodian recovered after a restart of the OS: these budgets and records are what survived it, and resuming accepts them.");
  io.out(`In force: ${o.decisions.length} user decision(s); ${o.amendments} amendment(s).`);
  if (o.lapsed.length) io.out(`Lapsed by the recovery (no longer applied; record them again with \`code-parley decide\` to keep them): ${o.lapsed.slice(0, 10).map((d) => `${d.kind} on ${d.thread}`).join(", ")}.`);
  // Whether a thread still needs a decision is the custodian's derivation: a resumed loop spends a continuation only on
  // its implementer-step route, so automation stays at a pause while a decision is still needed (ROUTE_NOT_IMPLEMENTER_STEP).
  await refuseWhileHeldDecisionNeeded(le, run);
  io.out("No thread needs your decision in the custodian's records; the custodian's derivation judges it again at the session's next step, and if one does (for example after a change in the working tree), automation pauses again there.");
  const answer = (await io.prompt('Type "resume" to resume automation (anything else cancels): ')).trim().toLowerCase();
  if (answer !== "resume") {
    io.out("Not resumed.");
    return 2;
  }
  const c = await operatorResumeLoopAt(le, run);
  if (!c.applied) {
    const hint = c.code === "CALLER_NOT_AUTHORIZED" ? " Resuming this pause needs the operator surface: run the command as the operator account." : "";
    throw new DomainError(c.code === "CALLER_NOT_AUTHORIZED" ? "CALLER_NOT_AUTHORIZED" : c.code === "CUSTODIAN_UNAVAILABLE" ? "CUSTODIAN_UNAVAILABLE" : "INVALID_ARGUMENT", `the custodian did not resume the loop (${c.reason}); nothing was resumed.${hint}`);
  }
  io.out(`automation of run ${run.runId} resumed by the custodian (${c.surface} surface; status ${c.status})`);
  return 0;
}

async function show(le: Loaded, a: LoopArgs, io: CliIo): Promise<number> {
  const viaCustodian = await custodianRun(le, a);
  if (viaCustodian) return showCustodianRun(le, viaCustodian, a, io);
  const ref = a.refs[0];
  if (!ref) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley loop show <run> [--json]");
  const run = await resolveRunRef(le, ref);
  const d = await loopDetails(le, run, pidAlive);
  if (!d) {
    const start = (await readState(run.paths)).loop_start;
    if (a.has("--json")) {
      io.out(JSON.stringify({ run_id: run.runId, loop: null, loop_start: start ?? null }, null, 2));
      return 0;
    }
    io.out(`run ${run.runId} has no automation loop`);
    if (start) io.out(`  loop start ${start.request_id} (${start.started_at}): ${start.status}${start.detail ? ` — ${start.detail}` : ""}${start.status === "unreconciled" ? `; acknowledge it with code-parley loop stop ${run.runId}` : ""}`);
    return 0;
  }
  if (a.has("--json")) {
    io.out(JSON.stringify(d, null, 2));
    return 0;
  }
  const v = d.view;
  io.out(`run ${d.run_id} (${d.repository_root})`);
  io.out(`loop ${v.loop_id}: ${v.status}${v.pause ? ` — paused: ${v.pause.reason} (${v.pause.detail}) at ${v.pause.at}` : ""}${v.ended ? ` — ended: ${v.ended.reason} at ${v.ended.at}` : ""}`);
  io.out(`  started ${v.started_at}; deadline ${v.deadline_at} (${v.seconds_left} s left); grant ${d.grant_id}${d.grant_use ? ` (custodian: loop ${d.grant_use.loops_used} of ${d.grant_use.loops_total})` : ""}`);
  io.out(`  continuations ${v.budgets.continuations.used}/${v.budgets.continuations.limit}; wakes ${v.budgets.wakes.used}/${v.budgets.wakes.limit} (${v.budgets.wakes.per_operation} per review)${d.budgets_source === "custodian" ? " — the custodian's counters" : d.budgets_source === "local_cache_unverified" ? " — the local cache (the custodian could not be asked; not authoritative)" : ""}`);
  const b = d.binding;
  io.out(b ? `  binding: session ${b.session_id}, epoch ${b.epoch}, ${b.state}${b.close_reason ? ` (${b.close_reason})` : ""}; process ${b.process ? `${b.process.pid ?? "none"} ${b.process.verified ? "verified" : `NOT verified (${b.process.detail})`}${b.process.alive === null ? "" : b.process.alive ? ", running" : ", gone"}` : "unknown"}` : "  binding: none (not bound to a session)");
  io.out(`  turn: ${d.turn.active ? "in a turn" : "idle"} since ${d.turn.at}; last user prompt ${d.last_user_prompt_at ?? "none"}`);
  for (const w of d.wakes) io.out(`  wake for review ${w.operation_id}: armed ${w.armed}x; ${w.consumed ? `consumed ${w.consumed}` : w.superseded_at ? `superseded ${w.superseded_at}` : "not consumed"}${w.rejected.length ? `; refused: ${w.rejected.slice(-3).join(" | ")}` : ""}`);
  for (const i of d.interrupts.slice(-5)) io.out(`  interrupt ${i.at} via ${i.via}: ${i.detail}`);
  if (v.next_action) {
    io.out(d.derivation?.available
      ? `  next action (the custodian's derivation ${d.derivation.derivationId}, ${d.derivation.at}; completion ${d.derivation.completion.state}): ${v.next_action.code} (${v.next_action.kind}; ${v.next_action.reason})`
      : `  next action (derived now in this terminal's environment — NOT authoritative${d.derivation ? `: the custodian's derivation is unavailable (${d.derivation.code})` : ""}): ${v.next_action.code} (${v.next_action.kind}; ${v.next_action.reason})`);
  }
  if (d.observer_environment) io.out(`  note: ${d.observer_environment}`);
  return 0;
}

async function stop(le: Loaded, a: LoopArgs, io: CliIo): Promise<number> {
  const viaCustodian = await custodianRun(le, a);
  if (viaCustodian) return stopCustodianRun(le, viaCustodian, a, io);
  const ref = a.refs[0];
  if (!ref) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley loop stop <run> [--reason <text>]");
  const run = await resolveRunRef(le, ref);
  const r = await operatorStopLoop(le, run, a.one("--reason"));
  if (r.status.startsWith("start_")) {
    io.out(r.stopped ? `the unfinished automation start of run ${run.runId} is acknowledged: nothing continues` : `the automation start of run ${run.runId} was already acknowledged; nothing changed`);
  } else {
    io.out(r.stopped ? `automation of run ${run.runId} cancelled; nothing continues or wakes automatically` : `the loop of run ${run.runId} had already ended (${r.status}); nothing changed`);
  }
  if (r.custodian) io.out(r.custodian);
  return 0;
}

async function resume(le: Loaded, a: LoopArgs, io: CliIo): Promise<number> {
  const viaCustodian = await custodianRun(le, a);
  if (viaCustodian) return resumeCustodianRun(le, viaCustodian, io);
  const ref = a.refs[0];
  if (!ref) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley loop resume <run>");
  const run = await resolveRunRef(le, ref);
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", LOOP_NOT_INTERACTIVE);
  const st = await readState(run.paths);
  const loop = st.continuation;
  if (!loop) throw new DomainError("INVALID_ARGUMENT", `run ${run.runId} has no automation loop`);
  io.out(`run ${run.runId}: loop ${loop.status}${loop.pause ? ` (${loop.pause.reason}: ${loop.pause.detail})` : ""}`);
  // P3.4C-4 (D4-E, the TD's usability direction): after a restart of the OS the repository's protected configuration (and
  // the global records its reviews rest on) lapsed. The re-confirmation is offered FIRST, as its own authorization —
  // the custodian's rendering of the configuration as it survived, its own typed confirmation and commit — never
  // combined with the resume's. Declined, the resume is refused (CONFIG_LAPSED).
  if (custodianEquipped(le)) {
    const section = await operatorConfigSection(le, run.meta.repository_root);
    const lapsed = lapsedRecords(section);
    if (lapsed.repository || (section.repository && lapsed.globals > 0)) {
      io.out(`The repository's protected configuration${lapsed.repository ? "" : "'s global records"} lapsed when the custodian recovered after a restart of the OS (${lapsed.repository ? "the repository record" : ""}${lapsed.repository && lapsed.globals ? " and " : ""}${lapsed.globals ? `${lapsed.globals} global record(s)` : ""}). Re-confirm it first; this is separate from the resume.`);
      const code = await reconfirmRepository(le, io, run.meta.repository_root, section);
      if (code !== 0) {
        io.out("The configuration was not re-confirmed, so the resume is refused (CONFIG_LAPSED). Nothing was resumed.");
        return 2;
      }
    }
  }
  // P3.4C-3 (§2.4 U1): what the resume accepts is the custodian's record — after a restart of the OS possibly restored
  // budgets — together with the decisions in force, the lapsed ones and the amendments.
  const o = await resumeOverview(le, run);
  if (o.unavailable !== null || !o.loop) {
    io.out(`The custodian's record of this loop could not be read (${o.unavailable ?? "no loop record"}); the resume will be refused.`);
  } else {
    io.out(`Resuming lets CodeParley continue this run's session automatically again, within what is left of its budgets as the custodian records them (continuations ${o.loop.used.continuations}/${o.loop.limits.continuations}, wakes ${o.loop.used.wakes}/${o.loop.limits.wakesPerRun}) and until ${o.loop.deadlineAt}. It records no decision.`);
    if (o.recovered) io.out("The custodian recovered after a restart of the OS: these budgets and records are what survived it, and resuming accepts them.");
    io.out(`In force: ${o.decisions.length} user decision(s)${o.decisions.length ? ` (${o.decisions.slice(0, 10).map((d) => `${d.kind} on ${d.thread}`).join(", ")})` : ""}; ${o.amendments} amendment(s).`);
    if (o.lapsed.length) io.out(`Lapsed by the recovery (no longer applied; record them again with \`code-parley decide\` to keep them): ${o.lapsed.slice(0, 10).map((d) => `${d.kind} on ${d.thread}`).join(", ")}${o.lapsed.length > 10 ? ", …" : ""}.`);
  }
  const answer = (await io.prompt('Type "resume" to resume automation (anything else cancels): ')).trim().toLowerCase();
  if (answer !== "resume") {
    io.out("Not resumed.");
    return 2;
  }
  const r = await operatorResumeLoop(le, run);
  io.out(`automation of run ${run.runId} is ${r.status} (${r.detail})`);
  return 0;
}
