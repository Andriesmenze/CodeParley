// P3.4C-1: resolving the AUTHORITATIVE user decisions & amendments for a run, and hydrating them into the
// state the discussion/completion derivation reads (src/policy/discussion.ts `discussionSourceOf`).
//
// Two sources, chosen by host and context — never by a user-writable run-mode flag:
//  - Custodian-less host (no validated custodian; the P3.4C-0 gate is closed): the legacy TypeScript store
//    (state.json `user_decisions`/`task_amendments`) is authoritative. This preserves attended/manual
//    Phase 2 on Linux and on Windows without the custodian (D-14).
//  - Custodian-equipped host (Windows + validated custodian): the custodian is authoritative.
//      * PROTECTED derivation (the controller's continuation while an automated loop is live): custodian
//        ONLY — the legacy store is never read; a custodian with no log for the run yields an empty
//        authoritative set (not a fall-through); the custodian being unavailable FAILS CLOSED.
//      * ATTENDED derivation (status, history, operator views): a governed run (the custodian holds a log)
//        uses the custodian; a never-governed run uses the legacy store (attended Phase 2). The custodian
//        being unavailable on a custodian host FAILS CLOSED for every run — a governed attended view can
//        never be tricked into treating legacy records as authoritative by downing the custodian.
//
// The engine reads on the IMPLEMENTER surface, so it only ever receives the structural projection (never a
// raw decision note or amendment text; D-C'). A forged `user_decisions`/`task_amendments` entry in the
// user-writable TS store therefore has NO effect on the protected path or on a governed run.

import { DomainError, isDomainError } from "../common/errors.js";
import { CustodianGrants } from "../custodian/grants.js";
import { protectedLoopGate, type CustodianTestHooks } from "../custodian/protected-loops.js";
import { CUSTODIAN_UNAVAILABLE, SERVER_NOT_TRUSTED, type RunSection, type UserRecordListing } from "../custodian/protocol.js";
import type { CustodianPresence } from "../custodian/service-presence.js";
import type { StateRecord } from "../schemas/run-state.js";
import type { TaskAmendment, UserDecision } from "../schemas/user-authority.js";
import { CUSTODIAN_CHANNEL, CUSTODIAN_SERVED, hostOperatorAssurance } from "../schemas/user-authority.js";
import type { Loaded, RunHandle } from "./engine-env.js";
import { hydrateRunEvidence } from "./run-evidence.js";
import { verifyRunJson } from "./protected-config.js";

/** The sections every protected read asks for: the user records, the loop and the run record (P3.4C-3). */
const ALL_SECTIONS = ["user", "loop", "run"] as const;

export interface AuthoritativeUserRecords {
  decisions: UserDecision[];
  amendments: TaskAmendment[];
  /** Where the records came from: the custodian's protected log, or the legacy TS store. */
  source: "custodian" | "legacy";
  /** The custodian holds a protected log for this run (always false for a legacy source). */
  governed: boolean;
  /** The custodian log revision the snapshot is current as of (0 for a legacy source). */
  revision: number;
  /** P3.4C-3 (§2.4 U4): waive/defer decisions recorded at or before the custodian's last recovery on a run whose loop
   * is not terminal — they no longer apply (their revocation may have been lost) until the operator re-confirms them.
   * Not in `decisions`. Always empty for a legacy source. */
  lapsed: UserDecision[];
  /** P3.4C-3: the custodian's run section of a PROTECTED run (null otherwise): the evidence a protected read derives
   * from (`hydrateRunEvidence`). */
  run: RunSection | null;
}

/** Is this host custodian-equipped (the P3.4C-0 protected-loop gate is open)? */
export function custodianEquipped(le: Loaded): boolean {
  return protectedLoopGate(le.env.testHooks?.custodian).available;
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

/** The disclosure source binding of a record, read from EITHER projection shape: the implementer projection
 * exposes a top-level `source_id`; the operator projection relays the record's `source` object. Both yield the
 * same binding, so the operator write's validation reconstructs it identically (the raw note/text is never
 * relayed to the engine state by `decisionOf`/`amendmentsOf`, only this non-confidential source id). */
const sourceOf = (r: Record<string, unknown>): { source_id: string; note: null } | null => {
  const sid = strOrNull(r["source_id"]) ?? strOrNull((r["source"] as { source_id?: unknown } | null | undefined)?.["source_id"]);
  return sid !== null ? { source_id: sid, note: null } : null;
};

/** P3.4C-3 (C3): mark a record built from the custodian's answer, in memory only (see CUSTODIAN_SERVED). */
function served<T extends object>(r: T): T {
  (r as { [CUSTODIAN_SERVED]?: true })[CUSTODIAN_SERVED] = true;
  return r;
}

/** The provenance every custodian-served record carries (the custodian sets it; a projection only relays
 * it). The engine trusts a record as user authority only through `isUserChannelRecord`, which this matches. */
function custodianProvenance(r: Record<string, unknown>): UserDecision["recorded_by"] {
  const rb = (r["recorded_by"] ?? {}) as Record<string, unknown>;
  return {
    role: str(rb["role"]) || "user",
    channel: str(rb["channel"]) || CUSTODIAN_CHANNEL,
    assurance: str(rb["assurance"]) || hostOperatorAssurance(),
    ...(typeof rb["proof_digest"] === "string" ? { proof_digest: rb["proof_digest"] } : {}),
  };
}

/** Map one custodian decision projection (either surface) to a UserDecision. The raw note is dropped
 * (recorded empty) regardless of surface — the operator projection carries it but the engine state never
 * needs it, and the implementer projection never has it; the finding-lifecycle derivation does not read it. */
function decisionOf(r: Record<string, unknown>): UserDecision {
  const rb = (r["recorded_by"] ?? {}) as Record<string, unknown>;
  const da = (r["decided_against"] ?? {}) as Record<string, unknown>;
  return served<UserDecision>({
    decision_id: str(r["recordId"]),
    thread_id: str(r["thread_id"]),
    current_item_id: str(r["current_item_id"]),
    covered_items: arr(r["covered_items"]),
    kind: str(r["kind"]),
    note: "",
    decided_against: {
      token: str(da["token"]),
      run_review_id: strOrNull(da["run_review_id"]),
      run_round: typeof da["run_round"] === "number" ? (da["run_round"] as number) : null,
      latest_reply_id: strOrNull(da["latest_reply_id"]),
      latest_response_id: strOrNull(da["latest_response_id"]),
      amendments_seq: typeof da["amendments_seq"] === "number" ? (da["amendments_seq"] as number) : 0,
    },
    context: (r["context"] ?? { awaiting: "", escalation_reasons: [], reviewer_stance: null, implementer_position: null }) as UserDecision["context"],
    supersedes: arr(r["supersedes"]),
    source: sourceOf(r),
    disclosure_ref: null,
    recorded_by: custodianProvenance(r),
    request_id: strOrNull(rb["request_id"]),
    request_digest: str(r["request_digest"]),
    recorded_at: str(r["recorded_at"]),
  });
}

/** Map custodian amendment projections (either surface) to TaskAmendments, in recording order. `seq` is the
 * amendment's 1-based position among amendments (the A-<seq> label); the custodian's global per-log
 * sequence is not the amendment label. The raw text is dropped (empty) regardless of surface; the derivation
 * uses `content_key_hash`/`text_bytes`, and a review presents the digest-bound redacted artifact. */
function amendmentsOf(records: Record<string, unknown>[]): TaskAmendment[] {
  const out: TaskAmendment[] = [];
  let seq = 0;
  for (const r of records) {
    if (str(r["recordKind"]) !== "amendment") continue;
    seq += 1;
    const rb = (r["recorded_by"] ?? {}) as Record<string, unknown>;
    out.push(served<TaskAmendment>({
      amendment_id: str(r["recordId"]),
      seq,
      kind: str(r["kind"]),
      text: "",
      relates_to: arr(r["relates_to"]),
      replaces: strOrNull(r["replaces"]),
      source: sourceOf(r),
      disclosure_ref: null,
      recorded_by: custodianProvenance(r),
      request_id: strOrNull(rb["request_id"]),
      request_digest: str(r["request_digest"]),
      recorded_at: str(r["recorded_at"]),
      ...(typeof r["contentKeyHash"] === "string" ? { content_key_hash: r["contentKeyHash"] } : {}),
      ...(typeof r["textBytes"] === "number" ? { text_bytes: r["textBytes"] as number } : {}),
      ...(typeof r["disclosureDigest"] === "string" ? { disclosure_digest: r["disclosureDigest"] } : {}),
      ...(typeof r["disclosureText"] === "string" ? { disclosure_text: r["disclosureText"] } : {}),
    }));
  }
  return out;
}

/** The decision kinds that relax what is required (a lost revocation would otherwise keep relaxing it, §2.4 U4). */
const LAPSING_KINDS: ReadonlySet<string> = new Set(["waive", "defer"]);
/** Loop statuses that are not terminal (the custodian's live set). */
const LIVE_LOOP: ReadonlySet<string> = new Set(["unbound", "active", "paused"]);

/**
 * §2.4 U4: does a recovery lapse this listing's earlier waivers and deferrals? Only when the custodian recorded a
 * recovery for the log and the run's loop is not terminal — a run without a loop record counts as not terminal (fail
 * closed: the operator re-confirms).
 */
function lapsesAt(listing: UserRecordListing): number | null {
  if (listing.recoveredAtRevision === null) return null;
  const loop = listing.loop?.record ?? null;
  if (loop && !LIVE_LOOP.has(str(loop["status"]))) return null;
  return listing.recoveredAtRevision;
}

/** The authoritative records of an already-fetched custodian listing (the lapse rule applied). */
export function fromListing(listing: UserRecordListing): AuthoritativeUserRecords {
  const at = lapsesAt(listing);
  const decisions: UserDecision[] = [];
  const lapsed: UserDecision[] = [];
  for (const r of listing.records) {
    if (str(r["recordKind"]) !== "decision") continue;
    const d = decisionOf(r);
    const seq = typeof r["seq"] === "number" ? (r["seq"] as number) : Number.POSITIVE_INFINITY;
    if (at !== null && LAPSING_KINDS.has(d.kind) && seq <= at) lapsed.push(d);
    else decisions.push(d);
  }
  const amendments = amendmentsOf(listing.records);
  return { decisions, amendments, source: "custodian", governed: listing.governed, revision: listing.revision, lapsed, run: listing.protected === true ? listing.run : null };
}

function legacy(st: StateRecord): AuthoritativeUserRecords {
  return { decisions: st.user_decisions ?? [], amendments: st.task_amendments ?? [], source: "legacy", governed: false, revision: 0, lapsed: [], run: null };
}

/**
 * Resolve the authoritative decisions/amendments for a run. `mode.protected` selects the controller's
 * protected-automation path (custodian only, fail closed) versus an attended read (governed-aware). On a
 * custodian-equipped host the engine reads the IMPLEMENTER projection; a transport failure propagates
 * (fail closed, no legacy fallback). On a custodian-less host the legacy store is authoritative.
 */
/** A run named by its custodian-validated repository identity and run id, for a resolver call that has no
 * `Loaded`/`RunHandle` (the review operation works from a `ReviewEngineContext`). */
export interface RunRecordId {
  custodian?: CustodianTestHooks;
  repositoryRoot: string;
  runId: string;
}

/**
 * How to read the authoritative records. `protected` selects the controller's unattended derivation
 * (custodian only, fail closed) versus an attended read (governed-aware). `asOperator` is set ONLY by an
 * operator-authorized CLI command (`decide`/`amend`): it reads the OPERATOR surface — the pipe the operator
 * account can reach — instead of the implementer surface. Every model-reachable / engine caller (MCP status,
 * `runs show`, the review presentation, the protected derivation) leaves it unset and reads the implementer
 * surface, so operator-only full records never cross to a model-reachable path (D-C'). The OS caller
 * classification stays authoritative — this only names the pipe the caller's own account is entitled to.
 */
export interface UserRecordsMode {
  protected: boolean;
  asOperator?: boolean;
}

/**
 * P3.4C-3 (contract §5.4): the local copy marks the run protected — the hint set once the custodian acknowledged its
 * `open`, or a loop cached from the custodian. Never a selection: it only adds refusals (a display that must consult
 * the custodian, a refusal instead of an attended fallback, RUN_RECORD_MISSING).
 */
export function locallyProtected(st: StateRecord): boolean {
  return st.run_records_custodian === true || st.continuation != null;
}

function runRecordMissing(runId: string): DomainError {
  return new DomainError("RUN_RECORD_MISSING", `run ${runId} is recorded locally as protected, but the custodian holds neither its loop nor its run record (it may have been reinstalled, or its store rolled back); nothing proceeds on this run — automate a new run`, { retryable: false });
}

/** As `authoritativeUserRecords`, from the raw identity instead of `le`/`run`. */
export async function authoritativeUserRecordsOf(id: RunRecordId, st: StateRecord, mode: UserRecordsMode): Promise<AuthoritativeUserRecords> {
  // ATTENDED (a display or an operator view): consult the custodian only for a run the local copy marks governed or
  // protected — the hint decides only whether a display consults the custodian (§5.4, §6.6; a display decides
  // nothing). A never-marked run uses the TS store exactly as Phase 2 did, with NO custodian exchange. The PROTECTED
  // path never consults the marks: it always reads the custodian.
  if (!mode.protected && !st.user_records_custodian && !locallyProtected(st)) return legacy(st);
  const gate = protectedLoopGate(id.custodian);
  if (!gate.available) throw gate.error; // protected, or marked attended, without a custodian here: fail closed
  // An operator command reads the operator surface (the only pipe that account can reach) — for the protected resume
  // guard too (C1); every engine caller reads the implementer surface. The reconstruction drops the raw note/text
  // from either projection, so the surface only decides REACHABILITY, never what confidential text is exposed.
  const surface = mode.asOperator ? "operator" : "implementer";
  const listing = await new CustodianGrants(gate.transport).listUserRecords(surface, id.repositoryRoot, id.runId, ALL_SECTIONS);
  if (locallyProtected(st) && listing.protected === false) throw runRecordMissing(id.runId);
  return fromListing(listing);
}

/** What a review presents as the user's own records (C2). */
export interface ReviewUserRecords {
  records: AuthoritativeUserRecords;
}

/**
 * P3.4C-3 C2 (contract §6.5, mandatory): the user records a review presents are selected by the CUSTODIAN's answer,
 * never by a local hint or any other user-writable field.
 *  - No custodian service on this host → the legacy records (Phase 2, no exchange; rule 5).
 *  - The custodian answers protected (it holds the run's loop or run record) → its records ONLY; an empty log is an
 *    empty set, never a legacy fallback (rule 2).
 *  - It answers not protected → its records if it holds a user-record log for the run (`governed`, P3.4C-1), else
 *    the legacy records (rule 3) — but a run the local copy marks protected is refused (RUN_RECORD_MISSING).
 *  - Registered (or unknown) but unreachable, or an unusable answer → refused, whatever the local copy says (Phase 6
 *    S-3, D-34, superseding rule 4's "no user records, with a limitation": the local marks are user-writable hints, so
 *    a protected run whose mark was removed would otherwise be reviewed as an attended one). Never legacy records.
 */
export async function reviewUserRecords(id: RunRecordId, st: StateRecord, presence: () => Promise<CustodianPresence>): Promise<ReviewUserRecords> {
  if ((await presence()) === "absent") return { records: legacy(st) };
  let listing: UserRecordListing;
  try {
    const gate = protectedLoopGate(id.custodian);
    if (!gate.available) throw gate.error;
    listing = await new CustodianGrants(gate.transport).listUserRecords("implementer", id.repositoryRoot, id.runId, ALL_SECTIONS);
    if (listing.protected === null) throw new DomainError(CUSTODIAN_UNAVAILABLE, "the custodian did not answer whether this run is protected", { retryable: false });
  } catch (e) {
    if (isDomainError(e) && (e.code === CUSTODIAN_UNAVAILABLE || e.code === SERVER_NOT_TRUSTED)) throw e;
    const why = e instanceof Error ? e.message : String(e);
    throw new DomainError(CUSTODIAN_UNAVAILABLE, `the custodian could not say whether this run is protected or which user records it has (${why}); the review is refused — start the CodeParley custodian service, then retry`, { retryable: false });
  }
  if (listing.protected) return { records: fromListing(listing) };
  if (locallyProtected(st)) throw runRecordMissing(id.runId);
  return { records: listing.governed ? fromListing(listing) : legacy(st) };
}

export async function authoritativeUserRecords(le: Loaded, run: RunHandle, st: StateRecord, mode: UserRecordsMode): Promise<AuthoritativeUserRecords> {
  return authoritativeUserRecordsOf({ custodian: le.env.testHooks?.custodian, repositoryRoot: run.meta.repository_root, runId: run.runId }, st, mode);
}

/** The run section as the OPERATOR surface reports it (the operator's CLI reaches only that pipe); a read. */
export async function operatorRunSection(le: Loaded, run: RunHandle): Promise<RunSection | null> {
  const gate = protectedLoopGate(le.env.testHooks?.custodian);
  if (!gate.available) throw gate.error;
  return (await new CustodianGrants(gate.transport).listUserRecords("operator", run.meta.repository_root, run.runId, ["run"])).run;
}

/** `st` with its decisions/amendments replaced by the authoritative set, for the derivation to read
 * transparently through `discussionSourceOf` — and, for a protected run, its evidence by the custodian's run record
 * (P3.4C-3, `hydrateRunEvidence`). */
export async function withAuthoritativeUserRecords(le: Loaded, run: RunHandle, st: StateRecord, mode: UserRecordsMode): Promise<StateRecord> {
  const a = await authoritativeUserRecords(le, run, st, mode);
  // P3.4C-4 (§1.1): a protected run's run.json is re-verified before a protected read derives anything from it.
  if (a.run) await verifyRunJson(run.paths.runJson, run.meta, a.run);
  return hydrateRunEvidence({ ...st, user_decisions: a.decisions, task_amendments: a.amendments }, a.run, run.paths.runDir);
}

/** `st` with its decisions/amendments replaced by the records of an ALREADY-FETCHED custodian listing (the
 * OPERATOR projection — the protected WRITER reads its OWN surface). The writer uses this to validate a new
 * record against the custodian's current records (decidability, token, supersedes) from the same snapshot it
 * bound its base revision to. `decisionOf`/`amendmentsOf` drop the raw note/text the operator projection
 * carries, so the reconstructed state holds no confidential text. */
export function withListedUserRecords(st: StateRecord, listing: UserRecordListing): StateRecord {
  const a = fromListing(listing);
  return { ...st, user_decisions: a.decisions, task_amendments: a.amendments };
}
