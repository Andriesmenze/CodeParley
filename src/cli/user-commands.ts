// `code-parley decide` and `code-parley amend` (Phase 2.3, plan §1.16): the local operator
// interface — the only supported way to create operator-authoritative user records.
//
//   decide <run>                                   the run's threads with an open item: the three layers
//   decide <run> <thread>                          one thread in full (read-only)
//   decide <run> <thread> <kind> [--note <text>] [--request-id <id>]
//                                                  record a decision: require-resolution | waive | defer | revoke
//   amend  <run>                                   the run's task amendments (read-only)
//   amend  <run> <kind> (--text <text> | --text-file <file>) [--thread <ref>]... [--replaces <ref>] [--request-id <id>]
//                                                  record an amendment: scope | constraint | acceptance-criteria |
//                                                  priority | clarification | withdrawal
//   … <run> … --repo <path>                        Phase 5 F-i2-5: a protected run as the CUSTODIAN holds it, for an
//                                                  operator who cannot read the implementer's run store (Linux, D5-B);
//                                                  the record is protected, the view is its structure only
//
// The listings are read-only and work anywhere. RECORDING needs an interactive terminal: stdin and
// stdout must be terminals and the operator types the confirmation word there (P2.3-1). There is no
// flag, environment variable or file that skips it — unlike `checks approve --confirm` — so that the
// agent's ordinary, non-interactive shell cannot produce a user record through supported behaviour.
// That is a guard, not verified human presence: CodeParley trusts the local OS user, its own
// installation and its store (assurance `local_operator`, P2.3-2); a same-user process that drives
// a pseudo-terminal, calls the engine or edits the store can create such a record (adversarial
// evidence A4–A7), as it can already forge other CodeParley evidence. Output passes the local view
// (MR-F: withheld names redacted, local paths kept).

import { readFile } from "node:fs/promises";
import { DomainError, isDomainError } from "../common/errors.js";
import { loadEngine, type Loaded, type RunHandle } from "../engine/engine-env.js";
import { disclosureFor, toHost, toLocal, withheldOfEntries } from "../engine/host-view.js";
import { resolveRunRef } from "../engine/run-admin.js";
import { repoRoot } from "./loop-commands.js";
import { withAuthoritativeUserRecords } from "../engine/protected-user-records.js";
import { loadAmendmentTexts, publishDisclosureArtifact } from "../engine/disclosure-artifact.js";
import { currentSource, SOURCE_BUDGET_MS } from "../engine/status.js";
import { decidableThreads, heldRunOf, protectedCustodianFor, recordAmendment, recordAmendmentHeld, recordAmendmentProtected, recordUserDecision, recordUserDecisionHeld, recordUserDecisionProtected, replayedAmendment, replayedDecision, resolveAmendmentRef, resolveItemRef, threadDecisionView, threadIdOfItem, type HeldRun, type ProtectedCustodian, type ThreadDecisionView, type UserChannelContext } from "../engine/user-authority.js";
import type { PreparedUserRecord } from "../custodian/protocol.js";
import type { SourceForResponse } from "../engine/respond.js";
import { amendmentSeenBy, amendmentStatus, type AmendmentFacts } from "../policy/amendments.js";
import { discussionIndexOf } from "../policy/discussion.js";
import type { ThreadReport } from "../policy/discussion-reports.js";
import { DECISION_MEANINGS } from "../policy/user-decisions.js";
import { AMENDMENT_KINDS, DECISION_KINDS, USER_LIMITS, type AmendmentKind, type DecisionKind } from "../schemas/user-authority.js";
import { readState } from "../store/state-store.js";
import { selfOwner } from "../store/owner.js";
import { printable } from "../process/command.js";
import type { CliIo } from "./cli.js";

export interface UserArgs {
  group: "decide" | "amend";
  refs: string[];
  one(flag: string): string | undefined;
  many(flag: string): string[];
  has(flag: string): boolean;
}

export const NOT_INTERACTIVE =
  "User decisions and task amendments are recorded only at an interactive terminal, with the confirmation typed by you: run this command yourself in a terminal (stdin and stdout must be a terminal; there is no flag that skips this). Nothing was recorded.";

export async function runUserCli(a: UserArgs, io: CliIo): Promise<number> {
  const launch = {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
  // P3.4C-4: decide and amend are the operator's channel: a protected run's configuration is read on the OPERATOR surface (the
  // pipe the operator account reaches), as its user records are (P3.4C-3 asOperator).
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), custodianReadSurface: "operator", ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  if (a.refs.length === 0) throw new DomainError("INVALID_ARGUMENT", a.group === "decide" ? "usage: code-parley decide <run> … (see code-parley --help)" : "usage: code-parley amend <run> … (see code-parley --help)");
  if (a.has("--confirm")) throw new DomainError("INVALID_ARGUMENT", `${a.group} has no --confirm: you confirm by typing at an interactive terminal (nothing skips that)`);
  try {
    if (a.one("--repo") !== undefined) return a.group === "decide" ? await decideHeld(le, a, io) : await amendHeld(le, a, io);
    const run = await resolveRunRef(le, a.refs[0]!);
    return a.group === "decide" ? await decide(le, run, a, io) : await amend(le, run, a, io);
  } catch (e) {
    // The custodian's OS caller classification refused a non-elevated (or non-operator) caller (--protected).
    if (isDomainError(e) && e.code === "CALLER_NOT_AUTHORIZED") throw new DomainError("CALLER_NOT_AUTHORIZED", `${NOT_ELEVATED} (${e.message})`);
    throw e;
  }
}

const NOT_ELEVATED =
  "A protected user record (--protected) is accepted by the CodeParley custodian only from the operator surface with an elevated operator token: run this command in an elevated terminal (Run as administrator) as the operator account. Nothing was recorded.";

/** What the user typed for a kind, in its stored form (`require-resolution` → `require_resolution`). */
function kindOf<T extends string>(raw: string, kinds: readonly T[], what: string): T {
  const k = raw.trim().toLowerCase().replace(/-/g, "_");
  if (!(kinds as readonly string[]).includes(k)) throw new DomainError("INVALID_ARGUMENT", `${what} must be one of ${kinds.map((x) => x.replace(/_/g, "-")).join(", ")}`);
  return k as T;
}

/** The operator interface's engine context: the source read is the status read, bounded (P2.3-14). */
function channel(le: Loaded, run: RunHandle): UserChannelContext {
  return {
    runId: run.runId,
    runPaths: run.paths,
    owner: le.env.owner,
    currentSource: async (): Promise<SourceForResponse> => {
      const src = await currentSource(le, run, await readState(run.paths), SOURCE_BUDGET_MS);
      const withheld = src.entries ? withheldOfEntries(src.entries) : undefined;
      if (src.recomputed && src.stable === true && src.source_id) return { source_id: src.source_id, note: null, withheld };
      return { source_id: null, note: src.recomputed ? "the working tree changed while it was being read" : (src.note ?? "the source identity was not recomputed"), withheld };
    },
    ...(le.env.testHooks?.lockDeps ? { lockDeps: le.env.testHooks.lockDeps } : {}),
    ...(le.env.testHooks?.classify ? { classify: le.env.testHooks.classify } : {}),
  };
}

/** The local view of a value (withheld names redacted, local paths kept; fails closed). */
async function local<T>(le: Loaded, run: RunHandle, value: T): Promise<T> {
  return toLocal(value, await disclosureFor(le, run, { state: await readState(run.paths) })).value;
}

const one = (s: string | null | undefined, max = 160): string => printable((s ?? "").replace(/\s+/g, " ").trim()).slice(0, max);

const PREVIEW_UNCHECKED = "[not shown: the working tree could not be read completely now, so the text could not be checked for confidential names; recording it needs that read as well]";

/**
 * The user's own text as the confirmation shows it (P2.3-14): the local view, with what a fresh
 * read of the working tree withholds besides the run's records, cut after redaction. Without a
 * complete, stable read nothing of it is shown (fail closed).
 */
async function preview(le: Loaded, run: RunHandle, text: string, max: number): Promise<string> {
  const st = await readState(run.paths);
  const src = await currentSource(le, run, st, SOURCE_BUDGET_MS).catch(() => null);
  if (!src?.recomputed || src.stable !== true || !src.source_id || !src.entries) return PREVIEW_UNCHECKED;
  try {
    const shown = toLocal(text, await disclosureFor(le, run, { state: st, entries: src.entries })).value;
    return JSON.stringify(shown.length > max ? `${shown.slice(0, max - 1)}…` : shown);
  } catch {
    return "[not shown: it would disclose a confidential name]";
  }
}

// ---------------------------------------------------------------------------
// decide
// ---------------------------------------------------------------------------

async function decide(le: Loaded, run: RunHandle, a: UserArgs, io: CliIo): Promise<number> {
  const [, threadRef, kindRaw] = a.refs;
  if (a.refs.length > 3) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley decide <run> [<thread> [<kind>]] [--note <text>] [--request-id <id>] [--protected]");
  // A custodian-governed run shows and decides against the authoritative custodian records (so the view,
  // the decision token and a protected write agree); a never-governed run reads the TS store (Phase 2).
  // asOperator: this is the operator CLI, so it reads the OPERATOR surface (the pipe this account can reach;
  // the implementer pipe is not the operator's). The reconstruction still drops the raw note/text.
  const st = await withAuthoritativeUserRecords(le, run, await readState(run.paths), { protected: false, asOperator: true });
  if (threadRef === undefined) {
    const threads = await local(le, run, decidableThreads(st));
    if (a.has("--json")) io.out(JSON.stringify({ run_id: run.runId, threads }, null, 2));
    else printThreads(io, run, threads);
    return 0;
  }
  const itemId = resolveItemRef(st, threadRef);
  // The token comes from the state itself; the user sees the local (redacted) copy of the view.
  const raw = threadDecisionView(st, itemId);
  const view = await local(le, run, raw);
  if (kindRaw === undefined) {
    if (a.has("--json")) io.out(JSON.stringify(view, null, 2));
    else printThread(io, view);
    return 0;
  }
  const kind = kindOf<DecisionKind>(kindRaw, DECISION_KINDS, "the decision");
  const note = a.one("--note") ?? "";
  const requestId = a.one("--request-id");
  const protectedRecord = a.has("--protected");
  // A replay of a LEGACY decision records nothing (a protected record's idempotency is the custodian's).
  if (!protectedRecord) {
    const replay = replayedDecision(st, run.runId, { item_id: itemId, kind, note, request_id: requestId });
    if (replay) {
      io.out(`This request id was already recorded: decision ${replay.decision_id} (${replay.kind}). Nothing new was recorded.`);
      return 0;
    }
  }
  // Nothing of the user's text is printed before the terminal is established (independent review).
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", NOT_INTERACTIVE);
  printThread(io, view);
  if (!raw.decidable.ok) throw new DomainError("FINDING_NOT_RESPONDABLE", `this thread cannot be decided: ${raw.decidable.reason}. Nothing was recorded`);
  io.out("");
  io.out(`Your decision: ${kind} — ${DECISION_MEANINGS[kind]}.`);
  io.out(`It covers the open item(s) above (${raw.covered_items.length}); it lapses if the reviewer revises the finding, a new open item joins the thread, or the lineage breaks. Nothing starts: no review, check, fix or close.`);
  if (note) io.out(`Your note (recorded as typed and never sent to Codex; withheld names are shown redacted): ${await preview(le, run, note, USER_LIMITS.noteChars)}`);
  const prompt = io.prompt;
  if (protectedRecord) {
    io.out("This decision will be recorded as PROTECTED authority by the Windows custodian (not the local store); protected automation reads only the custodian for this run.");
    const result = await recordUserDecisionProtected(channel(le, run), custodian(le), run.meta.repository_root, { item_id: itemId, kind, note, token: raw.token, request_id: requestId }, (prepared) => confirmProtected(io, prompt, prepared, kind));
    if ("cancelled" in result) {
      io.out("Not recorded (the prepared authorization expires unused).");
      return 2;
    }
    io.out(`Recorded by the custodian: decision ${result.recorded.recordId} (${kind}), sequence ${result.recorded.seq}, log revision ${result.recorded.revision}. Nothing was started; the next review or status shows its effect.`);
    return 0;
  }
  const answer = (await prompt(`Type "${kind}" to record this decision as yours (anything else cancels): `)).trim().toLowerCase().replace(/-/g, "_");
  if (answer !== kind) {
    io.out("Not recorded.");
    return 2;
  }
  const out = await recordUserDecision(channel(le, run), { item_id: itemId, kind, note, token: raw.token, request_id: requestId });
  io.out(
    out.deduplicated
      ? `This request id was already recorded: decision ${out.decision.decision_id} (${out.decision.kind}). Nothing new was recorded.`
      : `Recorded your decision ${out.decision.decision_id}: ${out.decision.kind} on thread ${out.decision.thread_id} (${out.decision.covered_items.length} open item(s)). Nothing was started; the next review or status shows its effect.`,
  );
  return 0;
}

// ---- Phase 5 F-i2-5 (option A): decide on the run as the custodian holds it (`--repo <path>`) ----

const HELD_STRUCTURE_ONLY = "(the run as the custodian holds it: its structure only — finding titles and reviewer replies are not held there; read them in the session)";

/** The protected run the operator named by repository and id, as the custodian holds it (no run store is read; the
 * custodian must hold its run record for that repository: RUN_NOT_FOUND otherwise). */
async function heldRun(le: Loaded, a: UserArgs): Promise<{ cust: ProtectedCustodian; held: HeldRun }> {
  const root = await repoRoot(le, a.one("--repo"));
  const ref = a.refs[0]!;
  const cust = custodian(le);
  return { cust, held: await heldRunOf(cust, root, ref) };
}

async function decideHeld(le: Loaded, a: UserArgs, io: CliIo): Promise<number> {
  const [, threadRef, kindRaw] = a.refs;
  if (a.refs.length > 3) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley decide <run> [<thread> [<kind>]] --repo <path> [--note <text>] [--request-id <id>]");
  const { cust, held } = await heldRun(le, a);
  const st = held.state;
  if (threadRef === undefined) {
    const threads = decidableThreads(st);
    if (a.has("--json")) io.out(JSON.stringify({ run_id: held.runId, repository_root: held.repositoryRoot, source: "custodian", threads }, null, 2));
    else {
      printThreads(io, held, threads, ` --repo ${held.repositoryRoot}`);
      io.out(HELD_STRUCTURE_ONLY);
    }
    return 0;
  }
  const itemId = resolveItemRef(st, threadRef);
  const view = threadDecisionView(st, itemId);
  if (kindRaw === undefined) {
    if (a.has("--json")) io.out(JSON.stringify({ ...view, source: "custodian" }, null, 2));
    else {
      printThread(io, view);
      io.out(HELD_STRUCTURE_ONLY);
    }
    return 0;
  }
  const kind = kindOf<DecisionKind>(kindRaw, DECISION_KINDS, "the decision");
  const note = a.one("--note") ?? "";
  const requestId = a.one("--request-id");
  // Nothing of the user's text is printed before the terminal is established (independent review).
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", NOT_INTERACTIVE);
  const prompt = io.prompt;
  printThread(io, view);
  io.out(HELD_STRUCTURE_ONLY);
  if (!view.decidable.ok) throw new DomainError("FINDING_NOT_RESPONDABLE", `this thread cannot be decided: ${view.decidable.reason}. Nothing was recorded`);
  io.out("");
  io.out(`Your decision: ${kind} — ${DECISION_MEANINGS[kind]}.`);
  io.out(`It covers the open item(s) above (${view.covered_items.length}); it lapses if the reviewer revises the finding, a new open item joins the thread, or the lineage breaks. Nothing starts: no review, check, fix or close.`);
  if (note) io.out(`Your note (recorded as typed, in the custodian only, never sent to Codex): ${JSON.stringify(note.length > USER_LIMITS.noteChars ? `${note.slice(0, USER_LIMITS.noteChars - 1)}…` : note)}`);
  io.out("This decision will be recorded as PROTECTED authority by the custodian, against the run as the custodian holds it; protected automation reads only the custodian for this run.");
  const result = await recordUserDecisionHeld(cust, held, { item_id: itemId, kind, note, token: view.token, request_id: requestId }, (prepared) => confirmProtected(io, prompt, prepared, kind));
  if ("cancelled" in result) {
    io.out("Not recorded (the prepared authorization expires unused).");
    return 2;
  }
  io.out(`Recorded by the custodian: decision ${result.recorded.recordId} (${kind}), sequence ${result.recorded.seq}, log revision ${result.recorded.revision}. Nothing was started; the custodian's derivation shows its effect at the session's next step.`);
  return 0;
}

async function amendHeld(le: Loaded, a: UserArgs, io: CliIo): Promise<number> {
  const [, kindRaw] = a.refs;
  if (a.refs.length > 2) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley amend <run> [<kind>] --repo <path> (--text <text> | --text-file <file>) [--thread <ref>]... [--replaces <ref>] [--request-id <id>]");
  const { cust, held } = await heldRun(le, a);
  const st = held.state;
  const facts = discussionIndexOf(st).amendments;
  if (kindRaw === undefined) {
    // The custodian's records: the reviewer-visible representation where it holds one (the raw text stays there).
    const rows = amendmentRows(facts).map((r) => ({ ...r, text: st.task_amendments.find((x) => x.amendment_id === r.amendment_id)?.disclosure_text ?? "" }));
    if (a.has("--json")) io.out(JSON.stringify({ run_id: held.runId, repository_root: held.repositoryRoot, source: "custodian", amendments: rows }, null, 2));
    else {
      io.out(`run ${held.runId}: ${rows.length} task amendment(s), ${facts.effective.length} in effect (as the custodian holds them)`);
      for (const r of rows) io.out(`  A-${r.seq} ${r.kind} [${r.status}]${r.replaces ? ` replaces ${r.replaces}` : ""}${r.seen_by_reviewer ? `; seen by the reviewer in round ${r.seen_by_reviewer.round}` : "; not seen by the reviewer"}${r.text ? ` — as Codex sees it: ${one(r.text, 200)}` : ""}`);
    }
    return 0;
  }
  const kind = kindOf<AmendmentKind>(kindRaw, AMENDMENT_KINDS, "the amendment kind");
  const text = await textOf(a);
  const relates = a.many("--thread").map((ref) => threadIdOfItem(st, resolveItemRef(st, ref)));
  const replacesRef = a.one("--replaces");
  const replaces = replacesRef ? resolveAmendmentRef(st, replacesRef) : null;
  const requestId = a.one("--request-id");
  // Nothing of the user's text is printed before the terminal is established (independent review).
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", NOT_INTERACTIVE);
  const prompt = io.prompt;
  io.out(`run ${held.runId}: task amendment ${kind}${replaces ? ` replacing A-${facts.byId.get(replaces)?.seq ?? "?"}` : ""}${relates.length ? ` for thread(s) ${relates.join(", ")}` : " (task-wide)"}`);
  io.out("The original task envelope stays as it was; the next review presents this amendment to Codex as your own task context. Nothing starts now.");
  io.out("This amendment will be recorded as PROTECTED authority by the custodian, against the run as the custodian holds it. The custodian reads the working tree itself and redacts your text for Codex; its rendering below shows exactly what Codex will see (the raw text stays in the custodian).");
  const result = await recordAmendmentHeld(cust, held, { kind, text, relates_to: relates, replaces, request_id: requestId }, (prepared) => confirmProtected(io, prompt, prepared, "amend"));
  if ("cancelled" in result) {
    io.out("Not recorded (the prepared authorization expires unused).");
    return 2;
  }
  io.out(`Recorded by the custodian: amendment ${result.recorded.recordId}, sequence ${result.recorded.seq}, log revision ${result.recorded.revision}. Nothing was started; the next review presents it.`);
  return 0;
}

/** The protected-record custodian for this run's operator action (no validated custodian → refused). */
function custodian(le: Loaded): ProtectedCustodian {
  return protectedCustodianFor(le.env.testHooks?.custodian);
}

/**
 * Confirm a prepared protected record: show the custodian's own rendering of exactly what it will
 * record, then require the operator to type the confirmation word (the same word as the legacy path).
 */
async function confirmProtected(io: CliIo, prompt: NonNullable<CliIo["prompt"]>, prepared: PreparedUserRecord, word: string): Promise<boolean> {
  io.out("The CodeParley custodian prepared this record (nothing is recorded until you confirm):");
  for (const line of prepared.rendering.split("\n")) io.out(`  ${line}`);
  io.out(`This confirmation expires at ${prepared.expiresAt}.`);
  const answer = (await prompt(`Type "${word}" to record this as yours (anything else cancels): `)).trim().toLowerCase().replace(/-/g, "_");
  return answer === word;
}

function layer(t: ThreadReport): string[] {
  const out: string[] = [];
  const r = t.latest_reviewer;
  const i = t.latest_implementer;
  out.push(`    reviewer: ${r ? `${r.stance} (round ${r.round}, new information: ${r.new_information}) — ${one(r.reply_excerpt)}` : "no reply yet"}`);
  out.push(`    implementer: ${i ? `${i.position} (after round ${i.answers_round}; ${i.seen_by_reviewer ? `seen by the reviewer in round ${i.seen_by_reviewer.round}` : `not seen by the reviewer: ${i.delivery}${i.delivery_reason ? ` (${i.delivery_reason})` : ""}`})` : "no response"}`);
  const u = t.user_decision;
  out.push(`    user: ${u ? `${u.kind} — ${u.status}${u.lapse_reasons.length ? ` (${u.lapse_reasons.join(", ")})` : ""}, ${u.recorded_at}${u.earlier_decisions ? `; ${u.earlier_decisions} earlier` : ""}` : "no decision"}`);
  out.push(`    awaiting ${t.awaiting}; exchanges ${t.exchanges.used}/${t.exchanges.limit}${t.escalation.needed ? `; ESCALATED: ${t.escalation.reasons.join(", ")}` : ""}; completion: ${t.completion_category ?? "nothing open"}${t.user_information_pending.length ? `; your amendments not yet seen by the reviewer: ${t.user_information_pending.join(", ")}` : ""}`);
  return out;
}

function printThreads(io: CliIo, run: Pick<RunHandle, "runId">, threads: ThreadReport[], suffix = ""): void {
  io.out(`run ${run.runId}: ${threads.length} thread(s) with an open item`);
  for (const t of threads) {
    const head = t.items[0];
    io.out(`  thread ${t.thread_id} — ${head ? one(head.title_excerpt, 100) : ""}`);
    for (const l of layer(t)) io.out(l);
  }
  if (threads.length) io.out(["Decide one: code-parley decide", run.runId, `<thread> (require-resolution | waive | defer | revoke) [--note <text>]${suffix}`].join(" "));
}

function printThread(io: CliIo, v: ThreadDecisionView): void {
  io.out(`run ${v.run_id}, thread ${v.thread_id}`);
  for (const it of v.items) io.out(`  ${it.status === "open" ? "OPEN" : it.status} ${it.kind} ${it.id} (round ${it.round}, ${it.triage}${it.severity ? `, ${it.severity}` : ""}${it.category ? `/${it.category}` : ""}${it.last_assessment ? `, last assessed ${it.last_assessment}` : ""}): ${one(it.title, 200)}`);
  for (const l of layer(v.report)) io.out(l);
  for (const d of v.decisions) io.out(`  your decision ${d.decision_id}: ${d.kind}, ${d.status}${d.reasons.length ? ` (${d.reasons.join(", ")})` : ""}, ${d.recorded_at}${d.note ? ` — ${one(d.note)}` : ""}`);
  io.out(`  task amendments so far: ${v.amendments_seq}`);
  if (!v.decidable.ok) io.out(`  not decidable: ${v.decidable.reason}`);
}

// ---------------------------------------------------------------------------
// amend
// ---------------------------------------------------------------------------

async function amend(le: Loaded, run: RunHandle, a: UserArgs, io: CliIo): Promise<number> {
  const [, kindRaw] = a.refs;
  if (a.refs.length > 2) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley amend <run> [<kind>] (--text <text> | --text-file <file>) [--thread <ref>]... [--replaces <ref>] [--protected]");
  // A governed run shows and amends against the authoritative custodian records, with the reviewer-visible
  // disclosure artifacts loaded for display; a never-governed run reads the TS store (Phase 2).
  // asOperator: the operator CLI reads the OPERATOR surface (the pipe this account can reach); the raw
  // note/text is still dropped by the reconstruction.
  const authed = await withAuthoritativeUserRecords(le, run, await readState(run.paths), { protected: false, asOperator: true });
  const st = { ...authed, task_amendments: (await loadAmendmentTexts(run.paths, authed.task_amendments)).amendments };
  const facts = discussionIndexOf(st).amendments;
  if (kindRaw === undefined) {
    const rows = await local(le, run, amendmentRows(facts));
    if (a.has("--json")) io.out(JSON.stringify({ run_id: run.runId, amendments: rows }, null, 2));
    else {
      io.out(`run ${run.runId}: ${rows.length} task amendment(s), ${facts.effective.length} in effect`);
      for (const r of rows) io.out(`  A-${r.seq} ${r.kind} [${r.status}]${r.replaces ? ` replaces ${r.replaces}` : ""}${r.seen_by_reviewer ? `; seen by the reviewer in round ${r.seen_by_reviewer.round}` : "; not seen by the reviewer"} — ${one(r.text, 200)}`);
    }
    return 0;
  }
  const kind = kindOf<AmendmentKind>(kindRaw, AMENDMENT_KINDS, "the amendment kind");
  const text = await textOf(a);
  const relates = a.many("--thread").map((ref) => threadIdOfItem(st, resolveItemRef(st, ref)));
  const replacesRef = a.one("--replaces");
  const replaces = replacesRef ? resolveAmendmentRef(st, replacesRef) : null;
  const requestId = a.one("--request-id");
  const protectedRecord = a.has("--protected");
  // A replay of a LEGACY amendment records nothing (a protected record's idempotency is the custodian's).
  if (!protectedRecord) {
    const replay = replayedAmendment(st, run.runId, { kind, text, relates_to: relates, replaces, request_id: requestId });
    if (replay) {
      io.out(`This request id was already recorded: amendment A-${replay.seq} (${replay.amendment_id}). Nothing new was recorded.`);
      return 0;
    }
  }
  // Nothing of the user's text is printed before the terminal is established (independent review).
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", NOT_INTERACTIVE);
  const prompt = io.prompt;
  io.out(`run ${run.runId}: task amendment ${kind}${replaces ? ` replacing A-${facts.byId.get(replaces)?.seq ?? "?"}` : ""}${relates.length ? ` for thread(s) ${relates.join(", ")}` : " (task-wide)"}`);
  if (text) io.out(`text (recorded as you confirm it here; presented to later reviews after the redaction of withheld names and local paths; withheld names are shown redacted here): ${await preview(le, run, text, USER_LIMITS.amendmentChars)}`);
  io.out("The original task envelope stays as it was; the next review you request presents this amendment to Codex as your own task context. Nothing starts now.");
  if (protectedRecord) {
    io.out("This amendment will be recorded as PROTECTED authority by the Windows custodian (the raw text stays in the custodian; later reviews see only an operator-confirmed, redacted representation).");
    // Produce and confirm the exact reviewer-visible redacted representation; publish it engine-side BEFORE
    // the custodian binds its digest. The raw text is never written to the engine-side artifact.
    const disc = text.trim() !== "" ? await reviewerDisclosure(le, run, text) : { redacted: "", source_id: null };
    if ("error" in disc) throw new DomainError("SOURCE_UNAVAILABLE", `${disc.error}. Nothing was recorded`, { retryable: true });
    if (text.trim() !== "") io.out(`Codex will see exactly this reviewer-visible representation (the raw text stays only in the custodian): ${JSON.stringify(disc.redacted.length > USER_LIMITS.amendmentChars ? `${disc.redacted.slice(0, USER_LIMITS.amendmentChars - 1)}…` : disc.redacted)}`);
    const published = text.trim() !== "" ? await publishDisclosureArtifact(run.paths, disc.redacted) : { digest: "", ref: "" };
    const result = await recordAmendmentProtected(channel(le, run), custodian(le), run.meta.repository_root, { kind, text, relates_to: relates, replaces, request_id: requestId }, { digest: published.digest, source_id: disc.source_id }, (prepared) => confirmProtected(io, prompt, prepared, "amend"));
    if ("cancelled" in result) {
      io.out("Not recorded (the prepared authorization expires unused).");
      return 2;
    }
    io.out(`Recorded by the custodian: amendment ${result.recorded.recordId}, sequence ${result.recorded.seq}, log revision ${result.recorded.revision}. Nothing was started; the next review you request presents it.`);
    return 0;
  }
  const answer = (await prompt('Type "amend" to record this amendment as yours (anything else cancels): ')).trim().toLowerCase();
  if (answer !== "amend") {
    io.out("Not recorded.");
    return 2;
  }
  const out = await recordAmendment(channel(le, run), { kind, text, relates_to: relates, replaces, request_id: requestId });
  io.out(
    out.deduplicated
      ? `This request id was already recorded: amendment A-${out.amendment.seq} (${out.amendment.amendment_id}). Nothing new was recorded.`
      : `Recorded your amendment A-${out.amendment.seq} (${out.amendment.amendment_id}). Nothing was started; the next review you request presents it.`,
  );
  return 0;
}

/**
 * The exact reviewer-visible redaction of an amendment text (what Codex will see), through the existing
 * host-disclosure mechanism (withheld names redacted, local paths scrubbed, MR-F enforced), plus the
 * source id of the stable read it was produced against. An error (fail closed) when the worktree could
 * not be read completely or the text would still disclose a confidential name.
 */
async function reviewerDisclosure(le: Loaded, run: RunHandle, text: string): Promise<{ redacted: string; source_id: string | null } | { error: string }> {
  const st = await readState(run.paths);
  const src = await currentSource(le, run, st, SOURCE_BUDGET_MS).catch(() => null);
  if (!src?.recomputed || src.stable !== true || !src.source_id || !src.entries) {
    return { error: "the working tree could not be read completely now, so the reviewer-visible representation could not be produced; try again when the worktree is free" };
  }
  try {
    const redacted = toHost(text, await disclosureFor(le, run, { state: st, entries: src.entries })).value;
    return { redacted, source_id: src.source_id };
  } catch {
    return { error: "the amendment text would disclose a confidential name even after redaction, so it cannot be recorded as reviewer-visible" };
  }
}

async function textOf(a: UserArgs): Promise<string> {
  const inline = a.one("--text");
  const file = a.one("--text-file");
  if (inline !== undefined && file !== undefined) throw new DomainError("INVALID_ARGUMENT", "give either --text or --text-file");
  if (file === undefined) return inline ?? "";
  const t = await readFile(file, "utf8").catch((e: unknown) => {
    throw new DomainError("INVALID_ARGUMENT", `cannot read ${file}: ${(e as Error).message}`);
  });
  if (t.length > USER_LIMITS.amendmentChars) throw new DomainError("INVALID_ARGUMENT", `the text is at most ${USER_LIMITS.amendmentChars} characters`);
  return t.replace(/\r\n/g, "\n").trimEnd();
}

function amendmentRows(f: AmendmentFacts): { amendment_id: string; seq: number; kind: string; status: string; replaces: string | null; relates_to: string[]; text: string; seen_by_reviewer: { review_id: string; round: number } | null; recorded_at: string }[] {
  return f.all.map((x) => ({
    amendment_id: x.amendment_id,
    seq: x.seq,
    kind: x.kind,
    status: amendmentStatus(f, x),
    replaces: x.replaces ? `A-${f.byId.get(x.replaces)?.seq ?? "?"}` : null,
    relates_to: x.relates_to,
    text: x.text,
    seen_by_reviewer: amendmentSeenBy(f, x.amendment_id),
    recorded_at: x.recorded_at,
  }));
}
