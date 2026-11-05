// `code-parley fix …` (Phase 4 Increment 3, contract §3.1): the owner's decision on a delegated fix, and its reconciliation.
//
//   fix review [--repo <path>] [--no-pager]
//                                      (operator, interactive; Step 7.1) the fixes waiting for a decision, chosen by number,
//                                      the custodian's whole rendering, then confirm, reject or leave (fix-review.ts)
//   fix show <run> [<proposal>]        the run's delegated fixes; with a proposal, the custodian's exact rendering of it
//                                      (read only — the originating session's inspection uses it too, §3.7)
//   fix show <run-id> [<proposal>] --repo <path>
//                                      the same, for an operator who cannot read the implementer's run store (Linux,
//                                      D5-B): the run as the custodian holds it under that repository
//   fix confirm <run-id> <proposal> --repo <path>
//                                      (operator, interactive) confirm EXACTLY the rendered content, single use
//   fix reject <run-id> <proposal> --repo <path>
//                                      (operator, interactive) close the proposal; nothing is applied
//   fix reconcile <run> [--restore | --leave]
//                                      (implementer) an interrupted application: each journaled file's state; with a
//                                      choice, restore the files still at their postimage or leave them, record it with
//                                      the custodian and clear the application's lock
//
// The custodian renders the proposal itself and binds the confirmation to the digest of exactly what it rendered; this
// command prints that rendering verbatim and commits only what the operator typed at an interactive terminal (no flag
// skips it — layering, not the boundary: the custodian accepts the decision only from the elevated operator token,
// assurance L1). Nothing here writes the repository: the application is `apply_fix` (the implementer's engine).
//
// Phase 5 G-OP (contract §4.5, F5-17): confirm and reject read nothing from an engine data home (the implementer can write
// that). The operator names the full run id and the repository; everything the decision rests on comes from the custodian.

import { DomainError, isDomainError } from "../common/errors.js";
import { hostOperatorAssurance } from "../schemas/user-authority.js";
import { isUuid } from "../common/ids.js";
import { protectedLoopGate } from "../custodian/protected-loops.js";
import { loadEngine, type Loaded, type RunHandle } from "../engine/engine-env.js";
import { resolveRunRef } from "../engine/run-admin.js";
import { reconcileApplications } from "../engine/fix-apply.js";
import { commitFixDecision, prepareFixDecision } from "../engine/fix-decision.js";
import { fixRenderingOf, fixRunSectionOf, type FixRunRef } from "../engine/fix-view.js";
import { repoRoot } from "./loop-commands.js";
import { runFixReview } from "./fix-review.js";
import { selfOwner } from "../store/owner.js";
import type { CliIo } from "./cli.js";

export interface FixArgs {
  cmd: string | undefined;
  refs: string[];
  one(flag: string): string | undefined;
  has(flag: string): boolean;
}

export const FIX_NOT_INTERACTIVE =
  "A delegated fix is confirmed or rejected only at an interactive terminal, with the decision typed by you: run this command yourself in a terminal (stdin and stdout must be a terminal; there is no flag that skips this). Nothing was recorded.";

const NOT_ELEVATED = process.platform === "linux"
  ? "The CodeParley custodian accepts a delegated fix's confirmation only on its operator socket, from the operator account: run this command as the operator account through /usr/local/sbin/code-parley-operator. Nothing was recorded."
  : "The CodeParley custodian accepts a delegated fix's confirmation only from the operator surface with an elevated operator token: run this command in an elevated terminal (Run as administrator) as the operator account. Nothing was recorded.";

const USAGE = "usage: code-parley fix (review [--repo <path>] [--no-pager] | show <run> [<proposal>] [--repo <path>] | confirm <run-id> <proposal> --repo <path> | reject <run-id> <proposal> --repo <path> | reconcile <run> [--restore | --leave])";

export async function runFixCli(a: FixArgs, io: CliIo): Promise<number> {
  const launch = {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
  if (a.has("--confirm")) throw new DomainError("INVALID_ARGUMENT", "fix has no --confirm: you confirm by typing at an interactive terminal (nothing skips that)");
  // Step 7.1: the guided review is the operator's channel too (no engine, no data home), and takes no positional argument.
  if (a.cmd === "review") {
    if (a.refs.length > 0) throw new DomainError("INVALID_ARGUMENT", `fix review takes no run, fix or number (you choose at the terminal): ${USAGE}`);
    const gate = protectedLoopGate(io.engineTestHooks?.custodian);
    if (!gate.available) throw gate.error;
    try {
      return await runFixReview(gate.transport, io, { repo: a.one("--repo") ?? null, noPager: a.has("--no-pager") });
    } catch (e) {
      if (isDomainError(e) && e.code === "CALLER_NOT_AUTHORIZED") throw new DomainError("CALLER_NOT_AUTHORIZED", `${NOT_ELEVATED} (${e.message})`);
      throw e;
    }
  }
  if (!a.refs[0] || !["show", "confirm", "reject", "reconcile"].includes(a.cmd ?? "")) throw new DomainError("INVALID_ARGUMENT", USAGE);
  // confirm/reject are the operator's channel (the operator surface): no engine and no data home (G-OP).
  if (a.cmd === "confirm" || a.cmd === "reject") {
    try {
      return await decide(a, a.cmd, io);
    } catch (e) {
      if (isDomainError(e) && e.code === "CALLER_NOT_AUTHORIZED") throw new DomainError("CALLER_NOT_AUTHORIZED", `${NOT_ELEVATED} (${e.message})`);
      throw e;
    }
  }
  // reconcile is the implementer's; show reads either surface.
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  // Phase 5 F-i2-5: with --repo, show reads the run as the custodian holds it (the operator's data home has no run store).
  if (a.cmd === "show" && a.one("--repo") !== undefined) {
    const runId = (a.refs[0] ?? "").trim().toLowerCase();
    if (!isUuid(runId)) throw new DomainError("INVALID_ARGUMENT", "give the full run id with --repo: code-parley fix show <run-id> [<proposal>] --repo <path>");
    return await show(le, { runId, meta: { repository_root: await repoRoot(le, a.one("--repo")) } }, a.refs[1] ?? null, io);
  }
  const run = await resolveRunRef(le, a.refs[0]);
  return a.cmd === "show" ? await show(le, run, a.refs[1] ?? null, io) : await reconcile(le, run, a, io);
}

async function show(le: Loaded, run: FixRunRef, proposal: string | null, io: CliIo): Promise<number> {
  if (proposal) {
    const r = await fixRenderingOf(le, run, proposal);
    io.out(`delegated fix ${r.operationId}: ${r.status}${r.confirmation ? ` (owner ${r.confirmation.decision === "confirm" ? "confirmed" : "rejected"}${r.confirmation.consumedAt ? `, applied from at ${r.confirmation.consumedAt}` : r.confirmation.expiresAt ? `, confirmation expires ${r.confirmation.expiresAt}` : ""})` : ""}`);
    io.out("The custodian's rendering (verbatim):");
    for (const line of r.rendering.replace(/\n$/, "").split("\n")) io.out(line);
    return 0;
  }
  const listing = await fixRunSectionOf(le, run);
  const ops = ((listing.run?.record as { operations?: Record<string, unknown>[] } | null)?.operations ?? []).filter((o) => o["kind"] === "fix" || o["kind"] === "apply");
  if (ops.length === 0) {
    io.out(`run ${run.runId} has no delegated fix the custodian holds`);
    return 0;
  }
  for (const o of ops) {
    const p = ((o["outcome"] as Record<string, unknown> | null)?.["proposal"] ?? null) as Record<string, unknown> | null;
    io.out(o["kind"] === "fix"
      ? `fix ${String(o["operationId"])}: ${String(o["status"])}${p ? `; proposal ${String(p["proposalDigest"]).slice(0, 16)}…, ${String(p["changeCount"])} file(s), ${String(p["totalBytes"])} bytes, expires ${String(p["expiresAt"])}${p["retiredAt"] ? `, retired (${String(p["retiredReason"])})` : ""}` : ""}`
      : `  application ${String(o["operationId"])} of ${String((o["begin"] as Record<string, unknown>)["fixOperationId"])}: ${String(o["status"])}`);
  }
  io.out(`show one: code-parley fix show ${run.runId} <proposal>; decide: code-parley fix confirm|reject ${run.runId} <proposal> --repo ${run.meta.repository_root} (operator)`);
  return 0;
}

async function decide(a: FixArgs, decision: "confirm" | "reject", io: CliIo): Promise<number> {
  const runId = (a.refs[0] ?? "").trim().toLowerCase();
  const proposal = a.refs[1];
  const repo = a.one("--repo");
  if (!isUuid(runId)) throw new DomainError("INVALID_ARGUMENT", `give the full run id (as fix show prints it): code-parley fix ${decision} <run-id> <proposal> --repo <path>`);
  if (!proposal) throw new DomainError("INVALID_ARGUMENT", `name the proposal: code-parley fix ${decision} ${runId} <proposal> --repo <path>`);
  if (!repo) throw new DomainError("INVALID_ARGUMENT", `name the run's repository: code-parley fix ${decision} ${runId} ${proposal} --repo <path> (the custodian holds the run under that repository's identity)`);
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", FIX_NOT_INTERACTIVE);
  const gate = protectedLoopGate(io.engineTestHooks?.custodian);
  if (!gate.available) throw gate.error;
  const transport = gate.transport;
  const prepared = await prepareFixDecision(transport, repo, runId, proposal, decision);
  io.out("The CodeParley custodian prepared this decision (nothing is recorded until you type it):");
  io.out("");
  for (const line of prepared.rendering.replace(/\n$/, "").split("\n")) io.out(line);
  io.out("");
  io.out(`This prepared decision expires at ${prepared.expiresAt}.`);
  const answer = (await io.prompt(`Type "${decision}" to record this (anything else cancels): `)).trim().toLowerCase();
  if (answer !== decision) {
    io.out("Not recorded (the prepared decision expires unused).");
    return 2;
  }
  const out = await commitFixDecision(transport, prepared.authorizationRequestId);
  io.out(decision === "confirm"
    ? `Confirmed by the custodian: delegated fix ${proposal} (${out.operationStatus}), confirmation ${out.confirmationId}, bound to rendering ${out.renderingDigest}; single use, expires ${out.expiresAt ?? "-"} (assurance ${hostOperatorAssurance()}). The originating session applies it with apply_fix.`
    : `Rejected by the custodian: delegated fix ${proposal} (${out.operationStatus}); its content was removed and nothing is applied (assurance ${hostOperatorAssurance()}).`);
  return 0;
}

async function reconcile(le: Loaded, run: RunHandle, a: FixArgs, io: CliIo): Promise<number> {
  if (a.has("--restore") && a.has("--leave")) throw new DomainError("INVALID_ARGUMENT", "choose one: --restore or --leave");
  const choice = a.has("--restore") ? "restore" : a.has("--leave") ? "leave" : null;
  const report = await reconcileApplications(le, run, choice);
  if (report.applications.length === 0) {
    io.out(`run ${run.runId} has no interrupted application to reconcile`);
    return 0;
  }
  for (const x of report.applications) {
    io.out(`application ${x.apply_operation_id} of delegated fix ${x.fix_operation_id}: ${x.status_before}${x.status_after !== x.status_before ? ` -> ${x.status_after}` : ""}`);
    if (x.observed === null) {
      io.out(`  ${x.detail ?? ""}`);
      continue;
    }
    io.out(`  observed: ${x.observed === "all_at_postimage" ? "every file at its postimage (never recorded applied)" : x.observed === "partial" ? "some files at their postimage" : "no file at its postimage"}${x.journal === "missing" ? " (no journal: the application ended before its first write)" : ""}`);
    for (const f of x.files) io.out(`  ${f.kind} ${f.path}: ${f.state_before}${f.state_after !== f.state_before ? ` -> ${f.state_after}` : ""}`);
    for (const t of x.temporary_files) io.out(`  temporary file ${t.path}: ${x.choice ? (t.removed ? "removed" : "NOT removed (not a regular file reached through a verified directory); remove it yourself") : "present (removed on either choice)"}`);
    if (x.choice) io.out(`  recorded with the custodian (${x.choice}); ${x.lock_cleared ? "the application's worktree lock was cleared" : "no lock of this application was held"}${x.detail ? `; ${x.detail}` : ""}`);
    else io.out(`  choose: code-parley fix reconcile ${run.runId} --restore (return the files at their postimage to their preimage) | --leave (keep them; they go through checks and review)`);
  }
  return report.applications.some((x) => x.observed !== null && x.choice === null) ? 3 : 0;
}
