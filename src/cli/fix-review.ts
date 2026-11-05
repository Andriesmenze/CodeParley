// `code-parley fix review` (Step 7.1, contract STEP-7.1 revision 2 §5): the operator's guided decision on a delegated fix.
//
//   1 list_fix_proposals (operator surface)   the fixes the custodian holds, numbered: no run id, fix id or path to type
//   2 a number                                an index into this one listing; it authorizes nothing
//   3 render_fix_proposal                     the custodian's whole rendering, checked (listed digests, its own SHA-256,
//                                             no unescaped terminal control), shown completely before any decision
//   4 confirm, reject or leave
//   5 prepare_fix_decision + expected values  prepared only for the listed proposal and the rendering reviewed
//   6 the prepared decision checked           its facts equal the selection and the review, and its text is exactly the
//                                             custodian's authority header + the reviewed bytes + its footer
//   7 the decision's authority                what it does, shown before the word is asked for
//   8 the typed word, then commit             the existing two-phase commit (the custodian re-renders and re-checks)
//   9 the result                              as the custodian recorded it
//
// Presentation, not authority: the custodian decides who may list, prepare and commit (the operator surface: an elevated
// operator token on Windows, the operator account on Linux) and binds a confirmation to the rendering digest. Showing
// every line is a precondition for offering the decision, not proof that the operator read them.

import { createHash } from "node:crypto";
import { DomainError, isDomainError } from "../common/errors.js";
import { deliveryOutcomeOf, type FixRendering } from "../custodian/grants.js";
import { escapeText, unescapedIn } from "../custodian/render-escape.js";
import type { CustodianTransport } from "../custodian/transport.js";
import { commitFixDecision, listFixProposals, prepareGuidedFixDecision, renderListedFix, type FixDecisionFacts, type FixListing, type FixListingEntry, type PreparedFixDecision } from "../engine/fix-decision.js";
import { hostOperatorAssurance } from "../schemas/user-authority.js";
import type { CliIo } from "./cli.js";

/** The largest rendering `fix review` shows (it refuses a larger one rather than cut it; the custodian's own bounds keep a
 * proposal far below this). */
export const MAX_REVIEW_RENDERING_BYTES = 8 * 1024 * 1024;

export const FIX_REVIEW_NOT_INTERACTIVE =
  "fix review decides only at an interactive terminal, with your choices and the decision typed by you: run it yourself in a terminal (stdin and stdout must be a terminal; nothing skips this). Nothing was listed or recorded.";

export const FIX_REVIEW_OLD_CUSTODIAN =
  "This custodian predates `fix review`. Use `code-parley fix show <run-id> <proposal> --repo <path>` and `code-parley fix confirm|reject <run-id> <proposal> --repo <path>`, or upgrade the custodian. Nothing was recorded.";

export interface FixReviewOptions {
  repo: string | null;
  noPager: boolean;
}

type ReviewOutcome = "decided" | "left" | "refused" | "unknown" | "quit";

const short = (d: string) => `${d.slice(0, 4)}…${d.slice(-4)}`;
const sha256 = (s: string) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const custodianText = (s: string) => escapeText(s);

/** The guided workflow. Exit 0 when the operator quits or nothing waits; 2 for an older custodian. */
export async function runFixReview(transport: CustodianTransport, io: CliIo, opts: FixReviewOptions): Promise<number> {
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", FIX_REVIEW_NOT_INTERACTIVE);
  const prompt = io.prompt;
  for (let round = 0; round < 500; round++) {
    let listing: FixListing;
    try {
      listing = await listFixProposals(transport, opts.repo);
    } catch (e) {
      if (olderCustodian(e)) {
        io.err(FIX_REVIEW_OLD_CUSTODIAN);
        return 2;
      }
      throw e;
    }
    const selectable = showListing(io, listing);
    if (selectable.length === 0) return 0;
    const answer = (await prompt(`Choose a number to review (1–${selectable.length}; q to quit): `)).trim();
    if (answer.toLowerCase() === "q" || answer === "") return 0;
    const n = /^\d{1,4}$/.test(answer) ? Number(answer) : NaN;
    const entry = Number.isInteger(n) && n >= 1 && n <= selectable.length ? selectable[n - 1]! : null;
    if (!entry) {
      io.out(`${custodianText(answer)} is not a listed number.`);
      continue;
    }
    const outcome = await reviewOne(transport, io, prompt, entry, opts);
    if (outcome === "quit") return 0;
    io.out("");
  }
  return 0;
}

/** Print the listing; returns the selectable entries in their numbered order. */
function showListing(io: CliIo, listing: FixListing): FixListingEntry[] {
  const selectable = listing.entries.filter((e) => e.selectable && e.state === "pending" && e.renderingDigest !== null && e.repositoryRoot !== null);
  io.out(`Delegated fixes held by the CodeParley custodian (as of ${custodianText(listing.snapshotAt)}):`);
  if (listing.entries.length === 0) {
    io.out("  none");
    io.out("No delegated fix is waiting for your decision.");
    return [];
  }
  let k = 0;
  for (const e of listing.entries) {
    const label = e.selectable && selectable.includes(e) ? String(++k).padStart(3) : "  -";
    const where = e.repositoryDisplay ?? (e.lastKnownPath ? `(last at ${e.lastKnownPath}; moved or unavailable — run fix review --repo <its path>)` : `(identity ${custodianText(e.repoKey)})`);
    const files = `${e.changeCount} file${e.changeCount === 1 ? "" : "s"}, ${e.totalBytes} bytes`;
    io.out(`${label}  ${where}  run ${custodianText(e.runId)}  fix ${custodianText(e.operationId)}  ${files}  ${stateText(e)}`);
    if (e.paths.length > 0) io.out(`       ${e.paths.join(", ")}${e.pathCount > e.paths.length ? `, … (${e.pathCount} paths)` : ""}`);
  }
  if (listing.truncated) {
    // The custodian lists at most a bounded number, the soonest to expire first; what it left out is reported, never dropped.
    const more = listing.total - listing.entries.length;
    io.out(`${listing.entries.length} of ${listing.total} delegated fixes are shown; ${more} more ${more === 1 ? "is" : "are"} not.`);
    io.out(listing.omittedPending > 0
      ? `${listing.omittedPending} of those ${listing.omittedPending === 1 ? "waits" : "wait"} for your decision. The fixes that expire soonest are listed first: confirm or reject some of them and list again, or list one repository with: code-parley fix review --repo <path>`
      : "None of those waits for your decision.");
  }
  if (selectable.length === 0) io.out("No delegated fix is waiting for your decision.");
  return selectable;
}

function stateText(e: FixListingEntry): string {
  switch (e.state) {
    case "pending":
      return e.selectable ? `waiting for your decision, expires ${custodianText(e.expiresAt)}` : "cannot be shown now";
    case "unavailable":
      return "not selectable: its repository is not at any path the custodian has recorded";
    case "waiting":
      return `confirmed, waiting for the session to apply it${e.confirmationExpiresAt ? ` (until ${custodianText(e.confirmationExpiresAt)})` : ""}`;
    case "expired":
      return "expired: it can no longer be decided";
    case "ineligible":
      return `cannot be decided (${custodianText(e.reasonCode ?? "ineligible")})`;
  }
}

async function reviewOne(transport: CustodianTransport, io: CliIo, prompt: (q: string) => Promise<string>, entry: FixListingEntry, opts: FixReviewOptions): Promise<ReviewOutcome> {
  // 3. The custodian's rendering, checked before a byte of it is shown.
  let r: FixRendering;
  try {
    r = await renderListedFix(transport, entry);
  } catch (e) {
    return refusal(io, e, "The custodian could not show this fix");
  }
  const fault = renderingFault(r, entry);
  if (fault) {
    io.err(`The custodian's rendering did not pass CodeParley's checks (${fault}); it is not shown and nothing can be decided on it. Nothing was recorded.`);
    return "refused";
  }
  const shown = await present(io, prompt, r.rendering, opts.noPager);
  if (shown !== "complete") {
    io.out("Left pending: nothing was sent.");
    return shown === "quit" ? "quit" : "left";
  }
  // 4. The choice, offered only after the whole rendering was shown.
  let decision: "confirm" | "reject" | null = null;
  for (let i = 0; i < 5 && decision === null; i++) {
    const c = (await prompt(`[c]onfirm  [r]eject  [l]eave pending   (rendering sha256 ${short(r.renderingDigest)}): `)).trim().toLowerCase();
    if (c === "c" || c === "confirm") decision = "confirm";
    else if (c === "r" || c === "reject") decision = "reject";
    else if (c === "l" || c === "leave" || c === "") {
      io.out("Left pending: nothing was sent.");
      return "left";
    }
  }
  if (decision === null) return "left";
  // 5. Prepared only for this proposal and the rendering reviewed.
  let prepared: PreparedFixDecision;
  try {
    prepared = await prepareGuidedFixDecision(transport, entry, r.renderingDigest, decision);
  } catch (e) {
    return refusal(io, e, "The custodian did not prepare this decision");
  }
  // 6. The prepared decision is the one reviewed, byte for byte.
  const mismatch = preparedMismatch(prepared, entry, r, decision);
  if (mismatch) {
    io.err(`The prepared decision does not match what you reviewed (${mismatch}). Nothing was recorded; the prepared decision expires unused. Review it again.`);
    return "refused";
  }
  const facts = prepared.facts!;
  // 7. What the decision does, before the word is asked for.
  io.out("");
  io.out(`The custodian prepared this decision for exactly the rendering you reviewed (sha256 ${r.renderingDigest}):`);
  for (const line of facts.authorityHeader.replace(/\n+$/, "").split("\n")) io.out(`  ${line}`);
  for (const line of facts.authorityFooter.replace(/^\n+/, "").split("\n").filter((l) => l !== "")) io.out(`  ${line}`);
  io.out(`  repository: ${entry.repositoryDisplay}`);
  io.out(`  (this prepared decision expires ${custodianText(prepared.expiresAt)})`);
  // 8. The typed word and the existing commit.
  const word = (await prompt(`Type "${decision}" to record this (anything else cancels): `)).trim().toLowerCase();
  if (word !== decision) {
    io.out("Not recorded (the prepared decision expires unused).");
    return "left";
  }
  let out: { decision: string; operationStatus: string; confirmationId: string; renderingDigest: string; expiresAt: string | null };
  try {
    out = await commitFixDecision(transport, prepared.authorizationRequestId);
  } catch (e) {
    if (deliveryOutcomeOf(e) === "unknown") {
      io.err("The custodian's answer was lost after the decision was sent: CodeParley does not know whether it was recorded and does not send it again. The listing below shows what the custodian holds.");
      return "unknown";
    }
    return refusal(io, e, "The custodian did not record the decision");
  }
  // 9. The result, as recorded.
  if (out.decision !== decision || out.renderingDigest !== r.renderingDigest) {
    io.err(`The custodian's answer does not name the decision you typed (${custodianText(out.decision)}, rendering ${custodianText(out.renderingDigest)}): treat it as not recorded and check the listing.`);
    return "unknown";
  }
  io.out(decision === "confirm"
    ? `Confirmed by the custodian: delegated fix ${entry.operationId} (${out.operationStatus}), confirmation ${out.confirmationId}, bound to rendering ${out.renderingDigest}; single use, expires ${out.expiresAt ?? "-"} (assurance ${hostOperatorAssurance()}). The originating session applies it with apply_fix.`
    : `Rejected by the custodian: delegated fix ${entry.operationId} (${out.operationStatus}); its content was removed and nothing is applied (assurance ${hostOperatorAssurance()}).`);
  io.out("The custodian recorded the decision in the run's record and its audit log.");
  return "decided";
}

/** Why the custodian's rendering cannot be shown (null: it can). */
export function renderingFault(r: FixRendering, entry: FixListingEntry): string | null {
  if (r.proposalDigest !== entry.proposalDigest) return "the proposal changed since the listing";
  if (r.renderingDigest !== entry.renderingDigest) return "the rendering changed since the listing";
  if (Buffer.byteLength(r.rendering, "utf8") > MAX_REVIEW_RENDERING_BYTES) return `it is larger than ${MAX_REVIEW_RENDERING_BYTES} bytes`;
  const trailer = `rendering sha256: ${r.renderingDigest}\n`;
  if (!r.rendering.endsWith(trailer)) return "it does not end with its own SHA-256";
  if (sha256(r.rendering.slice(0, -trailer.length)) !== r.renderingDigest) return "its SHA-256 does not match its bytes";
  const lines = r.rendering.slice(0, -1).split("\n");
  for (const [i, line] of lines.entries()) {
    const cp = unescapedIn(line);
    if (cp !== null) return `line ${i + 1} holds an unescaped U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
  }
  return null;
}

/** Why the prepared decision is not the one reviewed (null: it is). */
export function preparedMismatch(p: PreparedFixDecision, entry: FixListingEntry, r: FixRendering, decision: "confirm" | "reject"): string | null {
  const f: FixDecisionFacts | null = p.facts;
  if (!f) return "the custodian sent no structured decision";
  if (f.decision !== decision) return "another decision";
  if (f.repoKey !== entry.repoKey) return "another repository identity";
  if (f.runId !== entry.runId || f.operationId !== entry.operationId) return "another run or fix";
  if (f.proposalDigest !== entry.proposalDigest) return "another proposal";
  if (f.renderingDigest !== r.renderingDigest) return "another rendering";
  if (p.rendering !== f.authorityHeader + r.rendering + f.authorityFooter) return "its text is not the reviewed rendering with the decision's authority around it";
  for (const part of [f.authorityHeader, f.authorityFooter]) for (const line of part.split("\n")) if (unescapedIn(line) !== null) return "its authority text holds an unescaped character";
  return null;
}

function olderCustodian(e: unknown): boolean {
  // custodianError() keeps a code the engine does not know as INTERNAL with the custodian's own code in its details.
  return isDomainError(e) && (e.details as { custodian_code?: string } | undefined)?.custodian_code === "UNKNOWN_OPERATION";
}

function refusal(io: CliIo, e: unknown, what: string): ReviewOutcome {
  if (!isDomainError(e)) throw e;
  if (deliveryOutcomeOf(e) === "unknown") {
    io.err(`${what}: the custodian's answer was lost (${custodianText(e.message)}). Nothing is sent again; the listing below shows what the custodian holds.`);
    return "unknown";
  }
  io.err(`${what}: ${e.code}: ${custodianText(e.message)}`);
  if (e.code === "SELECTION_STALE" || e.code === "PROPOSAL_NOT_PENDING" || e.code === "CONFIRMATION_CONTENT_MISMATCH") io.err("Nothing was recorded. The listing is read again: review the fix again if it is still waiting.");
  else io.err("Nothing was recorded.");
  return "refused";
}

// ---- the pager ----

/**
 * Show the rendering. Paged (default): CodeParley's own pager, which prints the custodian's lines unchanged behind a
 * line-number gutter, wraps a long line with a visible continuation marker (never cuts it) and returns "complete" only
 * once every page has been shown. --no-pager: every line written once, unchanged. "left": the operator left first.
 */
export async function present(io: CliIo, prompt: (q: string) => Promise<string>, rendering: string, noPager: boolean): Promise<"complete" | "left" | "quit"> {
  const lines = rendering.replace(/\n$/, "").split("\n");
  if (noPager) {
    for (const line of lines) io.out(line);
    io.out(`[end of the custodian's rendering: all ${lines.length} lines shown]`);
    return "complete";
  }
  const size = io.terminalSize?.() ?? { columns: 100, rows: 30 };
  const width = Math.max(20, Math.min(400, size.columns) - 9);
  const pageRows = Math.max(5, Math.min(200, size.rows) - 3);
  const rows: { line: number; text: string; first: boolean }[] = [];
  for (const [i, line] of lines.entries()) {
    const cps = Array.from(line);
    if (cps.length === 0) rows.push({ line: i, text: "", first: true });
    for (let at = 0; at < cps.length; at += width) rows.push({ line: i, text: cps.slice(at, at + width).join(""), first: at === 0 });
  }
  const pages: { from: number; to: number }[] = [];
  for (let at = 0; at < rows.length; at += pageRows) pages.push({ from: at, to: Math.min(rows.length, at + pageRows) });
  const shown = new Set<number>();
  let page = 0;
  for (let guard = 0; guard < 100_000; guard++) {
    const p = pages[page]!;
    for (const row of rows.slice(p.from, p.to)) io.out(row.first ? `${String(row.line + 1).padStart(6)} | ${row.text}` : `${" ".repeat(6)} : ${row.text}`);
    shown.add(page);
    const first = rows[p.from]!.line + 1;
    const last = rows[p.to - 1]!.line + 1;
    if (shown.size === pages.length) {
      io.out(`[end of the custodian's rendering: all ${lines.length} lines shown]`);
      return "complete";
    }
    const missing = pages.length - shown.size;
    const cmd = (await prompt(`[lines ${first}–${last} of ${lines.length}; ${missing} page${missing === 1 ? "" : "s"} not shown yet]  Enter: next  b: back  g: first  G: last  /text: find  q: leave  `)).trim();
    if (cmd === "q") return "left";
    if (cmd === "" || cmd === " ") page = Math.min(pages.length - 1, page + 1 === pages.length ? firstUnshown(shown, pages.length) : page + 1);
    else if (cmd === "b") page = Math.max(0, page - 1);
    else if (cmd === "g") page = 0;
    else if (cmd === "G") page = pages.length - 1;
    else if (cmd.startsWith("/") && cmd.length > 1) {
      const needle = cmd.slice(1).toLowerCase();
      const hit = rows.findIndex((row, idx) => idx >= p.to && row.text.toLowerCase().includes(needle));
      if (hit < 0) io.out(`"${escapeText(cmd.slice(1))}" is not in the rest of the rendering.`);
      else page = Math.floor(hit / pageRows);
    }
  }
  return "left";
}

function firstUnshown(shown: Set<number>, count: number): number {
  for (let i = 0; i < count; i++) if (!shown.has(i)) return i;
  return count - 1;
}
