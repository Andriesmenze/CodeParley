// The custodian transport: one request in, one response out, over a chosen surface. Two implementations
// share this interface — the real Windows named-pipe client (pipe-transport.ts, which verifies the
// CONNECTED pipe's owner and security before it sends anything) and the in-process
// SimulatedCustodianTransport below, a faithful re-implementation of the custodian's observable behaviour
// for deterministic, portable contract and integration tests. The grant store (grants.ts / operator.ts)
// is written against this interface and does not know which transport it has. The simulator is never
// selected by configuration, an environment variable or a platform: only test code constructs it.

import { closeSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { basename, isAbsolute, join, sep } from "node:path";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { uuidv7 } from "../common/ids.js";
import { TOOL_VERSION } from "../common/version.js";
import { amendmentContentKey } from "../policy/amendments.js";
import { inodeGenerationSync } from "../process/inode-generation.js";
import { snapshotProcessTable } from "../process/proc-table.js";
import {
  CUSTODIAN_GRANT_CEILINGS, CUSTODIAN_PROTOCOL_VERSION, CUSTODIAN_UNAVAILABLE, EVIDENCE_PART_BYTES, SERVER_NOT_TRUSTED,
  type CustodianOp, type CustodianResponse, type CustodianSurface,
} from "./protocol.js";
import {
  LIVE_STATUSES, SimLoopInvalid, SimLoopRefusal, applyLoopTransition, consumeResultOf, loopSection, mintLoop, parseLoopRequest, recoveredLoop,
  type SimBoundProcess, type SimClientCheck, type SimLoop, type SimProcessCheck, type SimRunView,
} from "./simulated-loops.js";
import {
  FIX_LISTING_SCHEMA, MAX_LISTED_FIXES, compareListingRows, expectedSelectionOf, fixCandidatePaths, listableFixes, listingEntry,
  applyFixDecision, applyRunTransition, commitCapture, proposalKey, commitCheckEnd, commitCheckStart, heldProposalRead, heldReadTarget, isRunTerminal, parseRunRequest, prepareFixDecision,
  reconcileCapturesAtStart, requireFreshFixDecision, retentionSweep, runKey, runLimits, runSection, evidenceKey, evidenceRefsOf, redactionBasisDigest, unestablishedAmendment,
  type SimApplyMeasure, type SimApplyPre, type SimCaptureEnd, type SimCaptureTicket, type SimExportRehash, type SimHeldProposal, type SimHeldRead, type SimRun, type SimRunStore, type SimWriter,
} from "./simulated-runs.js";
import type { SimFixBaselineRead } from "./simulated-fix.js";
import { applyConfig, configRequestCommitted, configSection, configStateDigest, currentOf, currentRuntime, emptyConfig, lapseAll, prepareConfig, requireUsableConfig, type SimConfigFile } from "./simulated-config.js";
import {
  readFixBaseline, rehashCapture, removeTicketDirs, simulatedHelperCapture, simulatedHelperMeasure, sweepExports, syntheticCapture, tamperCapture,
  type SimHelperOptions, type SimSyntheticCapture,
} from "./simulated-capture.js";
import {
  SIM_DERIVATION_TTL_MS, derivationChecks, derivationSnapshot, measuredDigest, measuredProblem, requireCurrentDerivation, requireRouteAndProgress, requireSameMeasurement, revisionVector, rulesJson,
  syntheticMeasure, type SimCheckTicket, type SimDerivationEntry, type SimDerivationState, type SimMeasureOutcome, type SimSyntheticMeasurement,
} from "./simulated-derivation.js";
import type { ReviewTarget } from "../schemas/capture.js";
import { escapeText } from "./render-escape.js";

export interface CustodianTransport {
  /** Send one classified request. Resolves with the custodian's response envelope, or rejects with a
   * transport failure — CustodianUnavailable (no trusted custodian could be reached, or the exchange
   * broke) or CustodianNotTrusted (the endpoint is not the custodian). The store maps both to fail-closed
   * engine errors; neither is ever a "no authority" answer from the custodian. */
  send(surface: CustodianSurface, op: CustodianOp, args: Record<string, unknown>, requestId: string): Promise<CustodianResponse>;
}

/**
 * Whether a failed exchange can have reached the custodian. `not_delivered`: the request was provably
 * never sent (no connection, or the endpoint failed verification before the first byte) — nothing can
 * have been applied, so a later retry is safe. `unknown`: the request was (or may have been) sent and no
 * valid response came back — the custodian may have applied it, so nothing may be retried automatically.
 */
export type DeliveryOutcome = "not_delivered" | "unknown";

/** Thrown by a transport when it cannot reach a trusted custodian or the exchange broke. */
export class CustodianUnavailable extends Error {
  readonly code = CUSTODIAN_UNAVAILABLE;
  constructor(message: string, readonly outcome: DeliveryOutcome = "not_delivered") {
    super(message);
    this.name = "CustodianUnavailable";
  }
}

/** Phase 6 (contract §7 a): thrown when the custodian is present but serving another request for longer than this call may
 * wait (its pipe exists but no instance became free; or, on Linux, its socket's backlog stayed full). Fail closed like
 * {@link CustodianUnavailable}, with its own code: a busy custodian is not an absent one. */
export class CustodianBusy extends CustodianUnavailable {
  constructor(message: string, outcome: DeliveryOutcome, readonly waitedMs: number) {
    super(message, outcome);
    this.name = "CustodianBusy";
  }
}

/** How long a call with no hook deadline waits for a busy custodian (the shortest hook deadline). */
export const DEFAULT_BUSY_WAIT_MS = 30_000;

let clientDeadlineAtMs: number | null = null;

/** Phase 6 (§7 a): the absolute time (epoch ms) by which this process needs its custodian answers — a hook's deadline
 * minus a margin, set once by the hook runner; null (the default): no hook deadline, {@link DEFAULT_BUSY_WAIT_MS}
 * applies to a busy custodian and the usual response deadlines to an answer. */
export function setCustodianClientDeadline(atMs: number | null): void {
  clientDeadlineAtMs = atMs;
}

export function custodianClientDeadline(): number | null {
  return clientDeadlineAtMs;
}

/** Thrown when the endpoint is not the custodian (wrong pipe owner, or a pipe security that would let
 * another principal serve it). The security evidence the client read is attached. */
export class CustodianNotTrusted extends Error {
  readonly code = SERVER_NOT_TRUSTED;
  constructor(message: string, readonly outcome: DeliveryOutcome = "not_delivered", readonly evidence: Record<string, unknown> = {}) {
    super(message);
    this.name = "CustodianNotTrusted";
  }
}

// ---------------------------------------------------------------------------
// In-process simulated custodian (contract + integration tests)
// ---------------------------------------------------------------------------

/** The caller class the simulated custodian attributes to requests (the real custodian reads it from the
 * OS token). "by_surface": the operator surface is an elevated operator and the implementer surface the
 * implementer, as on a single-account host where elevation is the operator's L1 vehicle. */
export type SimulatedCaller = "operator" | "implementer";

const AUTH_TTL_MS = 120_000;

/** Operations only the operator class may perform (they create or reduce authority, or probe the service). */
const OPERATOR_ONLY_OPS: ReadonlySet<CustodianOp> = new Set<CustodianOp>(["prepare_grant", "prepare_revoke", "commit", "prepare_user_record", "prepare_config_record", "service_identity", "prepare_fix_decision", "list_fix_proposals"]);
/** The loop transitions that automate (contract §5): the custodian checks their session and connected process. */
const AUTOMATION_KINDS: ReadonlySet<string> = new Set(["spend_continuation", "wake_arm", "wake_consume"]);
/** P3.4C-3 (contract §3.5): the run transitions accepted only from the bound session's process tree. */
const BOUND_RUN_KINDS: ReadonlySet<string> = new Set(["op_begin", "respond"]);
/** P3.4C-3 (contract §4.3): the run transitions that record or check the process that sent them (the writer). */
const WRITER_RUN_KINDS: ReadonlySet<string> = new Set(["op_begin", "record_execution", "op_finish"]);

const ALLOWED_ARGS: Record<CustodianOp, readonly string[]> = {
  ping: [],
  list_grants: [],
  service_identity: [],
  consume_loop: ["repositoryRoot", "runId"],
  prepare_grant: ["repositoryRoot", "loops", "minutes"],
  prepare_revoke: ["repositoryRoot"],
  commit: ["authorizationRequestId"],
  prepare_user_record: ["repositoryRoot", "runId", "recordKind", "payload", "baseRevision"],
  list_user_records: ["repositoryRoot", "runId", "sections", "runJson"],
  prepare_config_record: ["repositoryRoot", "recordKind", "action", "recordId", "payload", "baseRevision"],
  loop_transition: ["repositoryRoot", "runId", "loopId", "epoch", "baseLoopRevision", "kind", "fields"],
  run_transition: ["repositoryRoot", "runId", "kind", "fields"],
  prepare_fix_decision: ["repositoryRoot", "runId", "operationId", "decision", "expectedRepoKey", "expectedProposalDigest", "expectedRenderingDigest"],
  render_fix_proposal: ["repositoryRoot", "runId", "operationId"],
  list_fix_proposals: ["repositoryRoot"],
  hold_evidence: ["repositoryRoot", "runId", "sha256", "part", "parts", "data"],
};

/** The sections list_user_records returns when the request names none (CustodianCore/GrantLedger DefaultSections). */
const DEFAULT_SECTIONS: readonly string[] = ["user", "loop"];
const ALL_SECTIONS: ReadonlySet<string> = new Set(["user", "loop", "run", "config", "derivation"]);
/** Phase 5 F-i2-5 (GrantLedger.OperatorSections): sections served on the operator surface only. */
const OPERATOR_SECTIONS: ReadonlySet<string> = new Set(["snapshot"]);

/** This process as the simulated custodian identifies a request's sender by default: its pid, a start time fixed when
 * the module loads, and its image name. */
const SELF_WRITER: SimWriter = Object.freeze({ pid: process.pid, startedAtMs: Math.round(Date.now() - process.uptime() * 1000), imageName: basename(process.execPath) });
const isSelfWriter = (w: SimWriter): boolean => w.pid === SELF_WRITER.pid && w.startedAtMs === SELF_WRITER.startedAtMs;
/** How far a default writer's recorded start time (computed in its own process) may be from the OS table's. */
const WRITER_START_TOLERANCE_MS = 2_000;

/** Mirror of the custodian's protected user-record log (P3.4C-1). */
interface SimUserRecord {
  recordId: string;
  seq: number;
  recordKind: "decision" | "amendment";
  payload: Record<string, unknown>;
  contentKeyHash: string | null;
  textBytes: number | null;
  disclosureDigest: string | null;
  contentKeyScheme: string | null;
  recordedBy: { role: string; channel: string; assurance: string; proof_digest: string; request_id: string };
  recordedAt: string;
  /** Phase 5 F-i2-5: the reviewer-visible representation the custodian produced and the operator confirmed. */
  disclosureText?: string | null;
}
interface SimUserLog {
  repoKey: string;
  runId: string;
  revision: number;
  records: SimUserRecord[];
  /** P3.4C-3 (§2.4 U4): the log's revision when a recovery after a new boot ran. */
  recoveredAtRevision?: number | null;
  lastRecoveryId?: string | null;
}

interface SimGrant {
  grantId: string;
  repoKey: string;
  repositoryRoot: string;
  loopsTotal: number;
  loopsUsed: number;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  assurance: string;
  requestId: string;
  uses: { loopId: string; at: string }[];
  /** P3.4C-3 (§2.4 U2): set by a recovery after a new boot; a suspended grant authorizes nothing. */
  suspendedAt?: string | null;
  lastRecoveryId?: string | null;
}

interface SimIntent {
  action: "grant" | "revoke" | "user_record" | "config_record" | "fix_decision";
  args: Record<string, unknown>;
  repoKey: string;
  stateDigest: string;
  expiresAtMs: number;
  requestId: string;
}

interface SimState {
  grants: SimGrant[];
  intents: Record<string, SimIntent>;
  /** P3.4C-1 per-(repoKey\u0000runId) protected user-record logs. */
  userLogs?: Record<string, SimUserLog>;
  /** P3.4C-1 confidentiality correction: the simulated custodian's HMAC secret for amendment content keys
   * (mirrors the real custodian's `content-key.secret`), generated once and persisted with the state so
   * equality survives a "restart" (a fresh transport over the same statePath), and its non-secret id. */
  contentKeySecret?: string;
  contentKeyId?: string;
  /** P3.4C-2: the custodian-owned loop records, beside the grants (co-located, as in ledger.json). */
  loops?: SimLoop[];
  /** P3.4C-3: the custodian-owned run records, by (repoKey\u0000runId) (runs\<repoKey>\<runId>.json). */
  runs?: Record<string, SimRun>;
  /** P3.4C-4: the custodian-held trusted configuration (config-records.json). */
  config?: SimConfigFile;
  /** P3.4C-5 Increment 3 (§5.1): the custodian's derivation cache — in memory in the service (lost on restart); kept with
   * the simulated state so every transport over it is the one custodian. */
  derivations?: Record<string, SimDerivationEntry>;
  /** Phase 4 Increment 2: the proposal content the custodian holds in its private store (fix-proposals\…). */
  fixProposals?: Record<string, SimHeldProposal>;
  /** Phase 5 F-i2-5: the redaction evidence the custodian holds (redaction-evidence\…), by evidenceKey. */
  evidence?: Record<string, string>;
}

/** The domain separator the amendment content-equivalence HMAC binds (matches the C# custodian). */
const CONTENT_KEY_DOMAIN = "arl.amendment-content-key.v1";
/** The keyed content-key scheme tag (matches the C# custodian's AmendmentContentKey.Scheme). */
const CONTENT_KEY_SCHEME = "hmac-sha256-v1";

/** A repository identity as the simulated custodian establishes it. */
export interface SimIdentity {
  key: string;
  canonicalPath: string;
}

/** A failure injected into the next request for one operation (once). */
export type SimulatedFault =
  /** The request never reaches the custodian (no pipe / connect failure / refused before sending). */
  | "not_delivered"
  /** The custodian applies the request, then the connection breaks before the response arrives. */
  | "lost_response"
  /** The endpoint is an impostor: refused before anything is sent. */
  | "untrusted";

/** Options for the simulated custodian. */
export interface SimulatedOptions {
  caller?: SimulatedCaller | "by_surface";
  /** Injectable clock (ms). Default Date.now. */
  now?: () => number;
  /** Persist the simulated ledger in this file, so an in-process CLI and a separate server process in a
   * test share one custodian (each request reads and writes it under a lock file). */
  statePath?: string;
  /** Bind this transport to ONE account's pipe, modelling the OS pipe DACLs: a request on any other surface
   * is refused as unreachable (as the OS denies a non-owner's connect), and the caller is classified by the
   * reachable surface. Two account-bound transports over one `statePath` reproduce the real cross-account
   * separation, instead of one permissive transport that serves every surface. */
  account?: CustodianSurface;
  /** How the simulated custodian establishes a repository's identity. Default: from the filesystem, as
   * the real custodian does — no link in any component; the directory's device and inode. */
  identity?: (repositoryRoot: string) => SimIdentity;
  /** P3.4C-2: how the simulated custodian checks the process a bind/rebind names (CLAUDE_PID). The real
   * custodian checks it is running and an ancestor of the process connected to its pipe; the default here
   * checks the same against THIS process (the simulator's "connected client"), from the OS process table. */
  processCheck?: (claimedPid: number | null) => SimProcessCheck | Promise<SimProcessCheck>;
  /** P3.4C-2 (TD decision on the Inc 9 escalation): how the simulated custodian checks the process connected to
   * its pipe against the BOUND process, for a spend_continuation, wake_arm or wake_consume. The real custodian
   * requires the bound process to still run with the start time it verified and to be an ancestor of the
   * connected process; the default checks the same against THIS process (the simulator's "connected client").
   * Tests model the OS caller here, independently of any session id the request names. */
  clientCheck?: (bound: SimBoundProcess) => SimProcessCheck | Promise<SimProcessCheck>;
  /** P3.4C-3 (contract §3.5): the same check for a run's op_begin and respond — evidence is accepted only from the bound
   * session's process tree. Default: `clientCheck`. */
  runClientCheck?: (bound: SimBoundProcess) => SimProcessCheck | Promise<SimProcessCheck>;
  /** P3.4C-3 (contract §4.3): the process the simulated custodian identifies as the sender of this transport's
   * requests — the real custodian takes the parent of the process connected to its pipe from its own process table.
   * Default: this process. null models a sender that cannot be identified. Tests give each simulated engine instance
   * its own writer (a "crashed" engine and its successor are different processes). */
  writer?: () => SimWriter | null;
  /** P3.4C-3 (contract §5.2): whether an operation's writer is gone, as the custodian's process table shows it (null:
   * the table cannot be read, so nothing is assumed gone). Default: this process is alive; another writer is looked up
   * in one OS process-table snapshot (gone if absent or its id now names another process). */
  writerGone?: (w: SimWriter) => boolean | null;
  /** P3.4C-5 (§3.1): the custodian's capture helper. Without it every protected review is refused (HELPER_UNAVAILABLE),
   * as by a custodian without the helper service. With it, a review reservation is captured by the simulated custodian:
   * in process right after the reservation (auto), or only when a test asks (manual: the shared corpus). */
  helper?: SimHelperOptions;
  /** P3.4C-5 Increment 4 (N5-8; GrantLedger.AttachRepositoryReaders): the helper's repository group, and whether a
   * repository grants it read access (its problem, or null). Without it nothing is checked (as without a helper). */
  repositoryReaders?: { sid: string; name: string; problem: (canonicalRoot: string) => string | null };
}

/** One reserved capture, with what the in-process helper needs (the validated repository, the rules it was reserved under). */
interface PendingCapture {
  t: SimCaptureTicket;
  repositoryRoot: string;
  canonicalRoot: string;
  rules: { exclude_globs: string[]; context_include: string[]; max_file_bytes: number; max_export_bytes: number; max_diff_bytes: number };
}

/** P3.4C-5 Increment 3: one reserved check measurement, with what the in-process helper needs. */
interface PendingCheck {
  t: SimCheckTicket;
  repositoryRoot: string;
  canonicalRoot: string;
}

/** P3.4C-5 Increment 3 (§5.2): the step of an automation transition — the precheck (every rule, no write; it reports the
 * derivation it checked), or the commit (every rule again, with the re-measurement). */
interface AutomationContext {
  phase: "precheck" | "commit";
  entry: SimDerivationEntry | null;
  measured: Record<string, unknown> | null;
  checked: SimDerivationEntry | null;
}

/** The default simulated process check: the claimed pid must be running and an ancestor of this process
 * (each parent created no later than its child), judged from the OS process table. */
export async function osProcessCheck(claimedPid: number | null): Promise<SimProcessCheck> {
  const client = process.pid;
  if (claimedPid === null) return { pid: null, startedAtMs: null, clientPid: client, verified: false, detail: "CLAUDE_PID was not supplied for the hook" };
  const table = await snapshotProcessTable().catch(() => null);
  if (!table) return { pid: claimedPid, startedAtMs: null, clientPid: client, verified: false, detail: "the process table could not be read" };
  const byPid = new Map(table.map((e) => [e.pid, e]));
  const named = byPid.get(claimedPid);
  if (!named) return { pid: claimedPid, startedAtMs: null, clientPid: client, verified: false, detail: `process ${claimedPid} is not running` };
  const startedAtMs = named.createdMs > 0 ? named.createdMs : null;
  if (startedAtMs === null) return { pid: claimedPid, startedAtMs: null, clientPid: client, verified: false, detail: `the start time of process ${claimedPid} could not be read` };
  let cur = byPid.get(client);
  for (let depth = 0; depth < 16 && cur; depth++) {
    const parent = byPid.get(cur.ppid);
    if (!parent || parent.pid === cur.pid || parent.createdMs > cur.createdMs + 1000) break;
    if (parent.pid === claimedPid) return { pid: claimedPid, startedAtMs, clientPid: client, verified: true, detail: `process ${claimedPid}, an ancestor of the connected process ${client}` };
    cur = parent;
  }
  return { pid: claimedPid, startedAtMs, clientPid: client, verified: false, detail: `process ${claimedPid} is not an ancestor of the process connected to the custodian (${client})` };
}

/**
 * Linux derives a process's wall-clock start from its age on every read (/proc/uptime, 10 ms resolution, and
 * Date.now(): process/linux-proc.ts), so two reads of one process differ by a few milliseconds; Windows reports the
 * creation time exactly. A process that reuses the pid was created after the bound one was verified alive, far outside
 * this window (the rule of store/owner.ts classifyOwnerLiveness).
 */
const START_JITTER_MS = process.platform === "linux" ? 1000 : 0;

/** The default simulated check of an automation request's connected process: the bound process must still run
 * with the start time recorded when it was verified (a reused pid is another process) and be an ancestor of this
 * process, judged from the OS process table. */
export async function osBoundProcessCheck(bound: SimBoundProcess): Promise<SimProcessCheck> {
  const r = await osProcessCheck(bound.pid);
  if (bound.startedAtMs === null) return { ...r, verified: false, detail: "the binding records no verified process" };
  if (r.startedAtMs !== null && Math.abs(r.startedAtMs - bound.startedAtMs) > START_JITTER_MS) return { ...r, verified: false, detail: `process ${bound.pid} is not the process the loop was bound to: the process id was reused` };
  return r;
}

/** The simulated custodian's process checks: the injected ones, else the OS-based defaults. */
function processChecksOf(opts: SimulatedOptions): Required<Pick<SimulatedOptions, "processCheck" | "clientCheck">> {
  return { processCheck: opts.processCheck ?? osProcessCheck, clientCheck: opts.clientCheck ?? osBoundProcessCheck };
}

/**
 * The simulated custodian's default identity: refuse rather than guess (a relative path, '.', '..', an
 * empty component, a symbolic link or junction in ANY component, a non-directory), and identify the
 * directory by device + inode, so every spelling of one directory is one identity and a replaced
 * directory is another. (The real custodian uses the handle-backed FILE_ID_INFO on Windows; see
 * custodian/…/Security/RepoIdentity.cs.)
 *
 * POSIX (Phase 5, F5-13): ext4 reuses a freed inode number at once, so (dev, ino) alone gives a replaced directory the
 * old identity. The key adds the inode generation (random per creation on ext4: separates an immediate replacement)
 * and the birth time in nanoseconds (separates a later one), as the Linux custodian's descriptor-backed identity does
 * (custodian/CodeParley.Custodian.Linux/Security/LinuxRepoIdentity.cs). `generationOf` is injectable for unit tests.
 */
export function filesystemIdentity(repositoryRoot: string, generationOf: (dir: string) => bigint | null = inodeGenerationSync): SimIdentity {
  const refuse = (why: string): never => {
    throw simError("INVALID_ARGUMENT", `repository identity refused: ${why}`);
  };
  if (!repositoryRoot || !isAbsolute(repositoryRoot)) refuse("the repository path must be absolute");
  if (process.platform === "win32" && !/^[A-Za-z]:[\\/]/.test(repositoryRoot)) refuse("only local drive-letter paths are supported");
  const native = process.platform === "win32" ? repositoryRoot.replace(/\//g, "\\") : repositoryRoot;
  const root = process.platform === "win32" ? native.slice(0, 3) : "/";
  const rest = native.slice(root.length).replace(/[\\/]+$/, "");
  const parts = rest.length ? rest.split(/[\\/]/) : [];
  let cur = root;
  for (const c of parts) {
    if (c === "" || c === "." || c === "..") refuse(`the path has a '${c || "empty"}' component`);
    cur = cur.endsWith(sep) ? cur + c : cur + sep + c;
    let st;
    try {
      st = lstatSync(cur);
    } catch {
      return refuse(`'${c}': it does not exist`);
    }
    if (st.isSymbolicLink()) refuse(`'${c}': it is a symbolic link, junction or mount point (no component may be a link)`);
    if (!st.isDirectory()) refuse(`'${c}': it is not a directory`);
  }
  const big = statSync(cur, { bigint: true });
  const canonicalPath = realpathSync.native(cur);
  if (process.platform === "win32") return { key: `sim1-${big.dev.toString(16)}-${big.ino.toString(16)}`, canonicalPath };
  const gen = generationOf(cur);
  return { key: `sim2-${big.dev.toString(16)}-${big.ino.toString(16)}-${gen === null ? "x" : gen.toString(16)}-${big.birthtimeNs.toString(16)}`, canonicalPath };
}

export class SimulatedCustodianTransport implements CustodianTransport {
  private memory: SimState = { grants: [], intents: {} };
  private caller: SimulatedCaller | "by_surface";
  private readonly now: () => number;
  private readonly statePath: string | null;
  private readonly identity: (repositoryRoot: string) => SimIdentity;
  private readonly processCheck: (claimedPid: number | null) => SimProcessCheck | Promise<SimProcessCheck>;
  private readonly clientCheck: (bound: SimBoundProcess) => SimProcessCheck | Promise<SimProcessCheck>;
  private readonly runClientCheck: (bound: SimBoundProcess) => SimProcessCheck | Promise<SimProcessCheck>;
  private readonly writerOf: () => SimWriter | null;
  private readonly writerGoneOpt: ((w: SimWriter) => boolean | null) | null;
  private readonly reachableSurface: CustodianSurface | null;
  private readonly helper: SimHelperOptions | null;
  private readonly repositoryReaders: SimulatedOptions["repositoryReaders"] | null;
  private readonly captureCancels = new Map<string, AbortController>();
  private manualCaptures = new Map<string, PendingCapture>();
  /** P3.4C-5 Increment 3: reserved check measurements waiting for the test (manual helper). */
  private manualChecks = new Map<string, PendingCheck>();
  /** P3.4C-5 Increment 4: tickets whose measurement is in progress (their configuration directories are live). */
  private measuringTickets = new Set<string>();
  /** P3.4C-5 Increment 4: ticket directories retired in a hold, removed after it. */
  private retiredDirs: string[] = [];
  /** P3.4C-5 Increment 3: the corpus's synthetic measurement (manual helper). */
  private synthetic: SimSyntheticMeasurement = {};
  private previousCaptures = new Map<string, PendingCapture>();
  private readonly runningCaptures = new Set<Promise<void>>();
  /** Requests being handled, a caller's or one it stopped waiting for (TEST control: `settle`). */
  private readonly runningRequests = new Set<Promise<void>>();
  private unavailable: string | null = null;
  private readonly faults = new Map<CustodianOp, SimulatedFault>();
  /** Every request that reached the simulated custodian (tests assert what was — and was not — sent). */
  readonly received: { surface: CustodianSurface; op: CustodianOp; args: Record<string, unknown>; requestId: string }[] = [];

  constructor(opts: SimulatedOptions = {}) {
    // When bound to an account, classify by the reachable surface (operator pipe -> operator class), as the OS
    // does; otherwise keep the historical default. The account only RESTRICTS which surface this transport can
    // reach — it never lets the request name its own class.
    this.caller = opts.caller ?? (opts.account ? "by_surface" : "implementer");
    this.now = opts.now ?? (() => Date.now());
    this.statePath = opts.statePath ?? null;
    this.identity = opts.identity ?? filesystemIdentity;
    const checks = processChecksOf(opts);
    this.processCheck = checks.processCheck;
    this.clientCheck = checks.clientCheck;
    this.runClientCheck = opts.runClientCheck ?? checks.clientCheck;
    this.writerOf = opts.writer ?? (() => SELF_WRITER);
    this.writerGoneOpt = opts.writerGone ?? null;
    this.reachableSurface = opts.account ?? null;
    this.helper = opts.helper ?? null;
    this.repositoryReaders = opts.repositoryReaders ?? null;
    if (this.helper) mkdirSync(this.helper.exportsRoot, { recursive: true });
  }

  /** TEST control: change the attributed caller class. */
  setCaller(caller: SimulatedCaller | "by_surface"): void {
    this.caller = caller;
  }

  /** TEST control: make the transport fail closed (a stopped custodian: nothing is delivered). */
  setUnavailable(reason: string | null): void {
    this.unavailable = reason;
  }

  /** TEST control: inject a failure into the next request for `op` (once). */
  failNext(op: CustodianOp, fault: SimulatedFault): void {
    this.faults.set(op, fault);
  }

  /** TEST view: the ledger as it is now (grants, P3.4C-2 loop records, P3.4C-3 run records, P3.4C-4 configuration). */
  snapshot(): { grants: SimGrant[]; loops: SimLoop[]; runs: SimRun[]; config: SimConfigFile } {
    return this.read((st) => ({ grants: structuredClone(st.grants), loops: structuredClone(st.loops ?? []), runs: structuredClone(Object.values(st.runs ?? {})), config: structuredClone(st.config ?? emptyConfig()) }));
  }

  /**
   * TEST control (P3.4C-4): give `repositoryRoot` a protected configuration record without the operator's two-phase
   * exchange — for protocol tests about something else (grants, loops, runs) that need a run opened. The record is
   * validated, digested and committed exactly as an operator's `set` is (prepareConfig/applyConfig); the default
   * payload holds one check, `unit`, a floor on it, the default capture rules and no Codex installation (protected reviews
   * stay refused). Returns the committed record's revision.
   */
  seedConfig(repositoryRoot: string, payload?: Record<string, unknown>): number {
    return this.withState((st) => {
      const file = (st.config ??= emptyConfig());
      const id = this.identity(repositoryRoot);
      const p = payload ?? {
        rootCommit: null,
        checks: { unit: { argv: ["node", "scripts/pass.js"], cwd: ".", timeout_seconds: 900, env: {}, env_passthrough: [], freshness_inputs: [] } },
        profiles: { default: ["unit"] }, requiredProfiles: ["default"], noRequiredChecks: false, testGlobs: [],
        captureRules: { excludeGlobs: ["**/.env"], contextInclude: [], maxFileBytes: 2_097_152, maxExportBytes: 536_870_912, maxDiffBytes: 400_000 },
        codexPath: null,
      };
      const base = file.repositories.filter((r) => r.repoKey === id.key && r.supersededAt === null).at(-1)?.configRevision ?? 0;
      const prepared = prepareConfig(file, { repositoryRoot, recordKind: "repository", action: "set", recordId: null, payload: p, baseRevision: base }, (r) => this.identity(r));
      const recordedBy = { role: "user", channel: "custodian_operator", assurance: "local_admin_elevation", proofDigest: "simulated-seed", requestId: `seed-${randomBytes(6).toString("hex")}` };
      const out = applyConfig(file, prepared.args, recordedBy.requestId, recordedBy, this.now());
      return Number(out["configRevision"]);
    });
  }

  /**
   * TEST control (P3.4C-5): approve a synthetic engine runtime (node.exe and git as PE images, the helper entry) written
   * into `dir`, through the operator's prepare/commit path. Returns the runtime id.
   */
  seedEngineRuntime(dir: string): string {
    const root = join(dir, `engine-runtime-${randomBytes(4).toString("hex")}`);
    mkdirSync(join(root, "git", "cmd"), { recursive: true });
    mkdirSync(join(root, "dist", "helper"), { recursive: true });
    writeFileSync(join(root, "node.exe"), simulatedPe(0));
    writeFileSync(join(root, "git", "cmd", "git.exe"), simulatedPe(1));
    writeFileSync(join(root, "dist", "helper", "main.js"), "// synthetic helper entry\n");
    return this.withState((st) => {
      const file = (st.config ??= emptyConfig());
      const prepared = prepareConfig(file, { repositoryRoot: null, recordKind: "engine_runtime", action: "set", recordId: null, payload: { path: root, git: "git/cmd/git.exe" }, baseRevision: file.globalRevision }, (r) => this.identity(r));
      const recordedBy = { role: "user", channel: "custodian_operator", assurance: "local_admin_elevation", proofDigest: "simulated-seed", requestId: `seed-${randomBytes(6).toString("hex")}` };
      return String(applyConfig(file, prepared.args, recordedBy.requestId, recordedBy, this.now())["recordId"]);
    });
  }

  /** TEST control (P3.4C-5, manual helper): capture the review reserved as `operationId` now with the corpus's synthetic
   * capture; returns the commit's result, or {recorded: false} when it was not recorded. */
  async runReservedCapture(operationId: string, spec: SimSyntheticCapture = {}, late = false): Promise<Record<string, unknown>> {
    const pending = (late ? this.previousCaptures : this.manualCaptures);
    const entry = [...pending.values()].find((x) => x.t.operationId === operationId);
    if (!entry) throw new Error(`no capture of ${operationId} is reserved`);
    pending.delete(entry.t.ticket);
    const selection = this.read((st) => (st.runs?.[runKey(entry.t.repoKey, entry.t.runId)]?.operations.find((o) => o.operationId === operationId)?.begin["selectionSourceId"] as string | undefined) ?? null);
    const end = await syntheticCapture({ exportsRoot: this.helper!.exportsRoot, ticket: entry.t.ticket, operationId, selection, spec });
    const out = await this.commitMeasurement(entry, end);
    return out ?? { recorded: false };
  }

  /** TEST control (P3.4C-5): change one published file of the captured review `operationId`. */
  tamperCapture(repositoryRoot: string, runId: string, operationId: string): void {
    const repoKey = this.identity(repositoryRoot).key;
    const begin = this.read((st) => st.runs?.[runKey(repoKey, runId)]?.operations.find((o) => o.operationId === operationId)?.begin ?? null);
    if (!begin) throw new Error(`no operation ${operationId}`);
    tamperCapture(begin);
  }

  /** TEST control (P3.4C-5, N5-18): the custodian restarts in the same boot — every persisted measuring operation is
   * interrupted, the export root swept; the previous instance's reserved captures can only report late. Returns the
   * number of interrupted operations. */
  restartCustodian(): number {
    for (const ac of this.captureCancels.values()) ac.abort();
    this.captureCancels.clear();
    this.previousCaptures = this.manualCaptures;
    this.manualCaptures = new Map();
    this.manualChecks = new Map();
    const out = this.withState((st) => {
      delete st.derivations; // the derivation cache is lost on restart (§5.1)
      return reconcileCapturesAtStart(this.runStoreOf(st), this.now());
    });
    this.sweepExportsNow(); // P3.4C-5 Increment 4: the full retention sweep
    return out.interrupted;
  }

  /** TEST control (P3.4C-5): wait until every in-process capture this transport started has committed. */
  async settleCaptures(): Promise<void> {
    while (this.runningCaptures.size) await Promise.all([...this.runningCaptures]);
  }

  /** TEST control: wait until every request this transport received has been answered and every in-process capture it
   * started has committed, including a request whose caller stopped waiting (SessionStart's bounded derivation): this
   * custodian runs in the test's process, so its work must end before the test's directories are removed. */
  async settle(): Promise<void> {
    while (this.runningRequests.size || this.runningCaptures.size) await Promise.all([...this.runningRequests, ...this.runningCaptures]);
  }

  /** TEST control: model a storage rollback or loss of config-records.json alone (contract §2.4): replace the
   * configuration store with `file` (an earlier version; `null`: lost). */
  replaceConfigStore(file: SimConfigFile | null): void {
    this.withState((st) => {
      if (file === null) delete st.config;
      else st.config = structuredClone(file);
    });
  }

  /** TEST control: model a storage rollback of the protected run records (contract §2.4: a store file can revert
   * independently of the others). Removes the run record of (repository, run); the other records are untouched. */
  /** TEST control (Phase 4 Increment 2): what the custodian holds in its private store for the fix `operationId` — whether
   * content is held, its paths, the preimages the custodian recorded from its own baseline, and its digest. */
  heldProposalForTest(repositoryRoot: string, runId: string, operationId: string): Record<string, unknown> {
    const repoKey = this.identity(repositoryRoot).key;
    const p = this.read((st) => st.fixProposals?.[proposalKey(repoKey, runId, operationId)] ?? null);
    if (!p) return { held: false };
    return { held: true, proposalDigest: p.proposalDigest, paths: p.changes.map((c) => c.path), preimages: p.changes.map((c) => c.preimage) };
  }

  /** TEST control (Step 7.1): a run as a run opened before P3.4C-4 has it — no configuration pinned at its open. */
  unpinRunForTest(repositoryRoot: string, runId: string): void {
    const repoKey = this.identity(repositoryRoot).key;
    this.withState((st) => {
      const run = (st.runs ??= {})[runKey(repoKey, runId)];
      if (!run) throw new Error(`no run ${runId}`);
      run.openedConfig = null;
    });
  }

  dropRunRecord(repositoryRoot: string, runId: string): void {
    const repoKey = this.identity(repositoryRoot).key;
    this.withState((st) => {
      delete (st.runs ??= {})[runKey(repoKey, runId)];
    });
  }

  /**
   * TEST control: the custodian's recovery after a new boot (contract §2.4 U1–U5, GrantLedger.Recovery.cs RunRecovery),
   * as the service runs it before it serves any request. U1: a live loop pauses for the operator (an unbound loop, which
   * can no longer bind, ends); U2: every unexpired, unrevoked grant is suspended; U3: every open run gets a new evidence
   * epoch; U4: every user-record log records the revision recovery ran at; U5: every pending intent is void. Each record
   * is stamped with the recovery id, so a repeated call with the same id changes nothing twice. Returns the id.
   */
  simulateRecoveryAfterNewBoot(recoveryId = `rec-${randomBytes(8).toString("hex")}`): string {
    this.withState((st) => {
      const now = this.now();
      st.loops = (st.loops ?? []).map((l) => (l.lastRecoveryId === recoveryId || !LIVE_STATUSES.has(l.status) ? l : recoveredLoop(l, recoveryId, now)));
      for (const g of st.grants) {
        if (g.lastRecoveryId === recoveryId || g.revokedAt !== null || Date.parse(g.expiresAt) <= now) continue;
        g.suspendedAt ??= new Date(now).toISOString();
        g.lastRecoveryId = recoveryId;
      }
      for (const [key, run] of Object.entries(st.runs ?? {})) {
        if (run.lastRecoveryId === recoveryId || isRunTerminal(run)) continue;
        st.runs![key] = { ...run, evidenceEpoch: run.evidenceEpoch + 1, lastRecoveryId: recoveryId };
      }
      for (const [key, log] of Object.entries(st.userLogs ?? {})) {
        if (log.lastRecoveryId === recoveryId) continue;
        st.userLogs![key] = { ...log, recoveredAtRevision: log.revision, lastRecoveryId: recoveryId };
      }
      // U4b (P3.4C-4): every configuration record in force lapses until the operator re-confirms it.
      if (st.config) lapseAll(st.config, recoveryId);
      st.intents = {};
    });
    return recoveryId;
  }

  send(surface: CustodianSurface, op: CustodianOp, args: Record<string, unknown>, requestId: string): Promise<CustodianResponse> {
    const res = this.handleRequest(surface, op, args, requestId);
    const tracked: Promise<void> = res.then(
      () => undefined,
      () => undefined,
    ).finally(() => this.runningRequests.delete(tracked));
    this.runningRequests.add(tracked);
    return res;
  }

  private async handleRequest(surface: CustodianSurface, op: CustodianOp, args: Record<string, unknown>, requestId: string): Promise<CustodianResponse> {
    if (this.unavailable !== null) throw new CustodianUnavailable(this.unavailable, "not_delivered");
    if (this.reachableSurface !== null && surface !== this.reachableSurface) {
      // Modelled OS pipe DACL: this account's process cannot even connect to the other surface's pipe, so the
      // custodian never sees the request (it is not pushed to `received`). This is the real cross-account refusal.
      throw new CustodianUnavailable(`simulated OS separation: the ${this.reachableSurface} account cannot reach the ${surface} pipe (Access to the path is denied)`, "not_delivered");
    }
    const fault = this.faults.get(op);
    if (fault) this.faults.delete(op);
    if (fault === "not_delivered") throw new CustodianUnavailable(`simulated: ${op} was not delivered`, "not_delivered");
    if (fault === "untrusted") throw new CustodianNotTrusted(`simulated: the endpoint for ${op} is not the custodian`, "not_delivered", { owner: "S-1-5-21-impostor" });
    this.received.push({ surface, op, args: structuredClone(args), requestId });
    // The custodian observes the processes itself before it decides — OS facts, never fields of the request.
    const observed = await this.observe(op, args, surface);
    // P3.4C-5 Increment 3 (§5.2, N5-17): a continuation or a wake is decided in three steps around a re-measurement.
    if (op === "loop_transition" && (args.kind === "spend_continuation" || args.kind === "wake_consume") && Object.keys(args).every((k) => ALLOWED_ARGS[op].includes(k))) {
      const res = await this.automationTransition(surface, args, requestId, observed);
      if (fault === "lost_response") throw new CustodianUnavailable(`simulated: the connection broke after ${op} was applied`, "unknown");
      return res;
    }
    // Phase 5 F-i2-5 (GrantLedger.PrepareUserRecord): an amendment the custodian redacts is measured before the hold.
    if (op === "prepare_user_record" && args.recordKind === "amendment" && typeof args.payload === "object" && args.payload !== null && !Array.isArray(args.payload) && "custodian_redaction" in args.payload) {
      try {
        args = { ...args, payload: await this.redactedAmendment(String(args.repositoryRoot), String(args.runId), args.payload as Record<string, unknown>, requestId) };
      } catch (e) {
        return failFromError(e);
      }
    }
    const res = this.withState((st) => this.handle(st, surface, op, args, requestId, observed));
    // P3.4C-5 Increment 4 (§3.2 retention), after the hold: retired exports removed; opening a run sweeps the export root.
    this.drainRetired();
    if (op === "run_transition" && args.kind === "open" && res.ok) this.sweepExportsNow();
    // P3.4C-5 Increment 3 (§5.1): the derivation is measured and computed outside the hold, after the other sections.
    if (op === "list_user_records" && res.ok && Array.isArray(args.sections) && (args.sections as unknown[]).includes("derivation")) {
      (res.data as Record<string, unknown>)["derivation"] = await this.derivationSection(args);
    }
    if (fault === "lost_response") throw new CustodianUnavailable(`simulated: the connection broke after ${op} was applied`, "unknown");
    return res;
  }

  private async observe(op: CustodianOp, args: Record<string, unknown>, surface: CustodianSurface = "implementer"): Promise<SimObserved> {
    const kind = String(args.kind);
    const loopOp = op === "loop_transition";
    const runOp = op === "run_transition";
    return {
      process: loopOp && (kind === "bind" || kind === "rebind") ? await this.observeProcess(args) : null,
      client: (loopOp && AUTOMATION_KINDS.has(kind)) || (runOp && BOUND_RUN_KINDS.has(kind)) ? await this.observeClient(args, loopOp) : null,
      writer: runOp && WRITER_RUN_KINDS.has(kind) ? this.writerOf() : null,
      writerGone: (runOp && kind === "recover") || (op === "list_user_records" && wantsRunSection(args)) ? await this.writerGoneCheck(args) : null,
      rehash: runOp && kind === "op_finish" ? await this.rehashForFinish(args) : null,
      fixBaseline: runOp && (kind === "op_begin" || kind === "op_finish") ? await this.fixBaselineFor(args, kind) : null,
      applyPre: runOp ? await this.applyPreFor(args, kind) : null,
      heldRead: op === "prepare_fix_decision" || op === "render_fix_proposal" ? await this.heldReadFor(args.repositoryRoot, args.runId, args.operationId)
        : op === "commit" ? await this.heldReadForCommit(args.authorizationRequestId) : null,
      // Step 7.1: the listing is built before the hold (as the real custodian builds it outside its lock), for the operator only.
      fixListing: op === "list_fix_proposals" && (this.caller === "by_surface" ? surface === "operator" : this.caller === "operator") ? await this.fixListingFor(args) : null,
    };
  }

  /** Step 7.1 (GrantLedger.ListFixProposals): the operator's listing — the runs and the configuration history read, then the
   * candidate paths resolved to identities and the pending fixes' held proposals read and rendered, all before the hold. A
   * refusal (a repository the filter names that cannot be resolved) is returned as the error the request answers with. */
  private async fixListingFor(args: Record<string, unknown>): Promise<Record<string, unknown> | Error> {
    let only: { key: string; canonicalPath: string } | null = null;
    if (args.repositoryRoot !== undefined && args.repositoryRoot !== null) {
      if (typeof args.repositoryRoot !== "string") return simError("INVALID_ARGUMENT", "'repositoryRoot' must be a string");
      try {
        only = this.identity(args.repositoryRoot);
      } catch (e) {
        return e instanceof Error ? e : new Error(String(e));
      }
    }
    const nowMs = this.now();
    const snap = this.read((st) => ({ runs: structuredClone(Object.values(st.runs ?? {})), config: structuredClone(st.config ?? emptyConfig()) }));
    const located = new Map<string, { id: { key: string; canonicalPath: string } | null; last: string | null }>();
    const locate = (run: SimRun) => {
      const memo = `${run.repoKey}|${run.openedConfig?.configRevision ?? "-"}`;
      const known = located.get(memo);
      if (known) return known;
      const candidates = only ? [only.canonicalPath] : fixCandidatePaths(snap.config, run);
      let result: { id: { key: string; canonicalPath: string } | null; last: string | null } = { id: null, last: candidates[0] ?? null };
      for (const path of candidates) {
        let id: { key: string; canonicalPath: string } | null = null;
        try {
          id = this.identity(path);
        } catch {
          // the path no longer reaches a directory
        }
        if (id && id.key === run.repoKey) {
          result = { id, last: path };
          break;
        }
      }
      located.set(memo, result);
      return result;
    };
    const rows = listableFixes(snap.runs, only?.key ?? null).map((f) => ({ ...listingEntry(f, locate(f.run), nowMs, escapeText), f }));
    const listed = [...rows].sort(compareListingRows).slice(0, MAX_LISTED_FIXES);
    for (const r of listed) {
      if (r.entry["state"] !== "pending") continue;
      const read = await this.heldReadFor(String(r.entry["repositoryRoot"]), r.f.run.runId, r.f.op.operationId);
      if (!read || read.problem !== null || !read.rendering || read.proposalDigest !== r.entry["proposalDigest"]) {
        r.entry["state"] = "ineligible";
        r.entry["reasonCode"] = "content_unreadable";
        continue;
      }
      r.entry["renderingDigest"] = read.rendering.digest;
      r.entry["selectable"] = true;
    }
    const entries = listed.map((r) => r.entry);
    return { schema: FIX_LISTING_SCHEMA, snapshotAt: new Date(nowMs).toISOString(), total: rows.length, truncated: rows.length > MAX_LISTED_FIXES, listingDigest: sha256OfCanonicalJson({ entries }), entries };
  }

  /** Phase 4 Increment 3 (GrantLedger.FixApply.cs ReadHeldProposal): before the hold, a fix's held content re-verified against
   * its record and its baseline capture, and rendered. Null when the request names no run and fix. */
  private async heldReadFor(repositoryRoot: unknown, runId: unknown, operationId: unknown): Promise<SimHeldRead | null> {
    if (typeof repositoryRoot !== "string" || typeof runId !== "string" || typeof operationId !== "string") return null;
    let identity: { key: string; canonicalPath: string };
    try {
      identity = this.identity(repositoryRoot);
    } catch {
      return null;
    }
    const snap = this.read((st) => {
      const run = st.runs?.[runKey(identity.key, runId)] ?? null;
      return { run: run ? structuredClone(run) : null, held: structuredClone(st.fixProposals?.[proposalKey(identity.key, runId, operationId)] ?? null) };
    });
    const target = heldReadTarget(snap.run, operationId);
    const pre = new Map<string, Buffer | null>();
    if (!target) return heldProposalRead(identity, runId, operationId, { run: snap.run, held: snap.held, tree: null, pre });
    const tree = await readFixBaseline(target.reviewId, target.reviewOperationId, target.reviewBegin);
    const exportPath = (target.reviewBegin?.["custodianCapture"] as Record<string, unknown> | undefined)?.["exportPath"];
    for (const c of snap.held?.changes ?? []) {
      if (c.kind !== "add" && typeof exportPath === "string") pre.set(c.path, await readFile(join(exportPath, "tree", ...c.path.split("/"))).catch(() => null));
    }
    return heldProposalRead(identity, runId, operationId, { run: snap.run, held: snap.held, tree, pre });
  }

  /** For a pending fix decision's commit: its rendering again, before the hold (RerenderForCommit). */
  private async heldReadForCommit(authorizationRequestId: unknown): Promise<SimHeldRead | null> {
    const intent = typeof authorizationRequestId === "string" ? this.read((st) => (st.intents[authorizationRequestId] ? structuredClone(st.intents[authorizationRequestId]!) : null)) : null;
    if (!intent || intent.action !== "fix_decision") return null;
    return this.heldReadFor(intent.args["repositoryRoot"], intent.args["runId"], intent.args["operationId"]);
  }

  /** Phase 4 Increment 3 (ReadForApply): an application's begin reads its confirmed content; its begin, finish and
   * reconciliation measure the primary source — both before the hold. Null for any other transition. */
  private async applyPreFor(args: Record<string, unknown>, kind: string): Promise<SimApplyPre | null> {
    const fields = (args.fields ?? {}) as Record<string, unknown>;
    const begin = kind === "op_begin" && fields["operationKind"] === "apply";
    if (!begin) {
      if (kind !== "op_finish" && kind !== "apply_reconcile") return null;
      let repoKey: string;
      try {
        repoKey = this.identity(String(args.repositoryRoot)).key;
      } catch {
        return null;
      }
      const isApply = this.read((st) => st.runs?.[runKey(repoKey, String(args.runId))]?.operations.find((o) => o.operationId === fields["operationId"])?.kind === "apply");
      if (!isApply) return null;
    }
    const held = begin ? await this.heldReadFor(args.repositoryRoot, args.runId, fields["fixOperationId"]) : null;
    return { held, measured: await this.measureSource(String(args.repositoryRoot), String(args.runId)) };
  }

  /** MeasureSource: the custodian's measurement of the primary source (no checks), outside the hold. */
  private async measureSource(repositoryRoot: string, runId: string): Promise<SimApplyMeasure> {
    let prepared: { canonicalRoot: string; workload: Record<string, unknown> };
    try {
      const identity = this.identity(repositoryRoot);
      prepared = this.read((st) => {
        this.requireMeasureReady(st);
        this.requireRepositoryReadable(identity.canonicalPath);
        const cfg = requireUsableConfig(st.config ?? emptyConfig(), identity.key, "an application's measurement");
        return { canonicalRoot: identity.canonicalPath, workload: { rules: rulesJson(cfg), checks: [], snapshot: null } };
      });
    } catch (e) {
      const code = (e as { code?: unknown }).code;
      return { sourceId: null, stable: false, code: typeof code === "string" ? code : "MEASUREMENT_FAILED", detail: e instanceof Error ? e.message : String(e) };
    }
    void runId;
    const o = await this.measure(prepared.canonicalRoot, prepared.workload, `msr-${randomBytes(10).toString("hex")}`);
    if (!o.ok) return { sourceId: null, stable: false, code: o.code ?? "MEASUREMENT_FAILED", detail: (o.detail ?? "").slice(0, 400) };
    return { sourceId: String(o.measured!["sourceId"]), stable: o.measured!["stable"] === true, code: null, detail: null };
  }

  /** Phase 4 Increment 2 (GrantLedger.Fix.cs ReadFixBaseline): before the hold, the baseline capture a fix names (op_begin)
   * or was bound to (op_finish) is read from the custodian's own published export: re-hashed against what it recorded, and
   * its manifest's `tree` files taken as the baseline. Null when the request is not a fix's begin or finish. */
  private async fixBaselineFor(args: Record<string, unknown>, kind: string): Promise<SimFixBaselineRead | null> {
    let repoKey: string;
    try {
      repoKey = this.identity(String(args.repositoryRoot)).key;
    } catch {
      return null;
    }
    const fields = (args.fields ?? {}) as Record<string, unknown>;
    const target = this.read((st) => {
      const run = st.runs?.[runKey(repoKey, String(args.runId))];
      if (!run) return null;
      let reviewId: unknown;
      if (kind === "op_begin") {
        if (fields["operationKind"] !== "fix") return null;
        reviewId = fields["baselineReviewId"];
      } else {
        const op = run.operations.find((o) => o.operationId === fields["operationId"]);
        if (!op || op.kind !== "fix") return null;
        reviewId = (op.begin["custodianBaseline"] as Record<string, unknown> | undefined)?.["reviewId"];
      }
      const review = run.reviews.find((r) => r.reviewId === reviewId);
      return review ? { reviewId: review.reviewId, operationId: review.operationId, begin: structuredClone(review.begin) } : { reviewId: String(reviewId), operationId: "", begin: null };
    });
    if (!target) return null;
    return readFixBaseline(target.reviewId, target.operationId, target.begin);
  }

  /** P3.4C-5 (§3.1 step 7): before the hold, a captured review's published export is hashed again (RehashForFinish). */
  private async rehashForFinish(args: Record<string, unknown>): Promise<SimExportRehash | null> {
    let repoKey: string;
    try {
      repoKey = this.identity(String(args.repositoryRoot)).key;
    } catch {
      return null;
    }
    const operationId = String((args.fields as Record<string, unknown> | undefined)?.["operationId"] ?? "");
    const begin = this.read((st) => {
      const op = st.runs?.[runKey(repoKey, String(args.runId))]?.operations.find((o) => o.operationId === operationId);
      return op && op.status === "captured" ? structuredClone(op.begin) : null;
    });
    return begin ? rehashCapture(operationId, begin) : null;
  }

  private async observeProcess(args: Record<string, unknown>): Promise<SimProcessCheck> {
    const p = (args.fields as { process?: { pid?: unknown } } | undefined)?.process?.pid;
    return this.processCheck(typeof p === "number" && Number.isInteger(p) && p > 0 ? p : null);
  }

  /** For an automation request (and a run's op_begin or respond, P3.4C-3), the custodian checks the connected process
   * against the bound one — an OS fact, never a field of the request — for the binding it reads first (the transition
   * re-checks it is unchanged). */
  private async observeClient(args: Record<string, unknown>, byLoopId: boolean): Promise<SimClientCheck | null> {
    let repoKey: string;
    try {
      repoKey = this.identity(String(args.repositoryRoot)).key;
    } catch {
      return null;
    }
    const bound = this.read((st): SimBoundProcess | null => {
      const loop = (st.loops ?? []).find((l) => l.repoKey === repoKey && l.runId === args.runId && (!byLoopId || l.loopId === args.loopId));
      return loop?.binding ? { pid: loop.binding.process.pid, startedAtMs: loop.binding.process.startedAtMs } : null;
    });
    if (!bound) return null;
    return { bound, verdict: await (byLoopId ? this.clientCheck : this.runClientCheck)(bound) };
  }

  /** P3.4C-3: the custodian's view of whether an operation's writer is gone — the injected check, else this process is
   * alive and any other writer of a running operation is looked up in one OS process-table snapshot, taken before the
   * state hold as the custodian takes its own. */
  private async writerGoneCheck(args: Record<string, unknown>): Promise<(w: SimWriter) => boolean | null> {
    if (this.writerGoneOpt) return this.writerGoneOpt;
    let repoKey: string;
    try {
      repoKey = this.identity(String(args.repositoryRoot)).key;
    } catch {
      return selfOnlyGone;
    }
    const runId = args.runId;
    const others = typeof runId === "string" && this.read((st) => (st.runs?.[runKey(repoKey, runId)]?.operations ?? []).some((o) => o.status === "running" && !isSelfWriter(o.writer)));
    if (!others) return selfOnlyGone;
    const table = await snapshotProcessTable().catch(() => null);
    return (w) => {
      if (isSelfWriter(w)) return false;
      if (!table) return null;
      const p = table.find((e) => e.pid === w.pid);
      if (!p) return true;
      return p.createdMs > 0 ? Math.abs(p.createdMs - w.startedAtMs) > WRITER_START_TOLERANCE_MS : null;
    };
  }

  private handle(st: SimState, surface: CustodianSurface, op: CustodianOp, args: Record<string, unknown>, requestId: string, observed: SimObserved = NOTHING_OBSERVED): CustodianResponse {
    const bad = Object.keys(args).find((k) => !ALLOWED_ARGS[op].includes(k));
    if (bad) return { ok: false, code: "MALFORMED_REQUEST", error: `unexpected argument '${bad}' for '${op}'` };
    // The surface only selects the pipe; the custodian classifies by identity. The simulation enforces
    // the same rule: operator ops need the operator class; consume/list are reduce-only / read.
    const caller = this.caller === "by_surface" ? (surface === "operator" ? "operator" : "implementer") : this.caller;
    if (OPERATOR_ONLY_OPS.has(op) && caller !== "operator") return notAuthorized(op);
    try {
      return ok(this.dispatch(st, op, args, requestId, caller, observed));
    } catch (e) {
      return failFromError(e);
    }
  }

  private dispatch(st: SimState, op: CustodianOp, args: Record<string, unknown>, requestId: string, caller: SimulatedCaller, observed: SimObserved): Record<string, unknown> {
    const s = (key: string): string => String(args[key] ?? "");
    switch (op) {
      case "ping":
        // Phase 6 Increment 3: the real custodian also reports its release, build and protocol (Ipc/CustodianCore.cs Pong).
        return { pong: true, caller, version: TOOL_VERSION, build: null, protocol: CUSTODIAN_PROTOCOL_VERSION, host: "simulated" };
      case "list_grants":
        return this.list(st);
      case "consume_loop":
        return this.consume(st, s("repositoryRoot"), args.runId, requestId);
      case "loop_transition":
        // Either surface: the originating session drives its own loop; the per-kind rules (operator-only
        // resume included) take the caller class the OS would assign, never a request field.
        return this.loopTransition(st, args, requestId, caller === "operator", observed);
      case "run_transition":
        // P3.4C-3: either surface; recover and end are the operator's too, every other kind the implementer's only.
        return this.runTransition(st, args, requestId, caller === "operator", observed);
      case "prepare_grant":
        return this.prepareGrant(st, s("repositoryRoot"), Number(args.loops), Number(args.minutes), requestId);
      case "prepare_revoke":
        return this.prepareRevoke(st, s("repositoryRoot"), requestId);
      case "commit":
        return this.commit(st, s("authorizationRequestId"), observed.heldRead ?? null);
      case "prepare_user_record":
        return this.prepareUserRecord(st, s("repositoryRoot"), s("runId"), s("recordKind"), (args.payload ?? {}) as Record<string, unknown>, Number(args.baseRevision), requestId);
      case "prepare_config_record":
        return this.prepareConfigRecord(st, args, requestId);
      case "prepare_fix_decision":
        return this.prepareFixDecisionOp(st, args, requestId, observed.heldRead ?? null);
      case "render_fix_proposal":
        return this.renderFixProposalOp(st, args, observed.heldRead ?? null);
      case "list_fix_proposals":
        if (!observed.fixListing) throw simError("INTERNAL", "the listing was not built");
        if (observed.fixListing instanceof Error) throw observed.fixListing;
        return observed.fixListing;
      case "hold_evidence":
        return { ok: true, data: this.holdEvidence(st, args) };
      case "list_user_records":
        // Served to the operator (full records) and the implementer (structural projection); the surface
        // selects the projection, never the request (D-C').
        return this.listUserRecords(st, s("repositoryRoot"), s("runId"), caller === "operator", sectionsOf(args), observed.writerGone);
      case "service_identity":
        return { note: "simulated" };
      default:
        throw simError("UNKNOWN_OPERATION", `unknown operation '${String(op)}'`);
    }
  }

  // ---- state: in memory, or a file shared between processes (under a lock file) ----

  private load(): SimState {
    const st = this.statePath === null ? this.memory : this.loadFromFile();
    st.userLogs ??= {};
    return st;
  }

  private loadFromFile(): SimState {
    try {
      return JSON.parse(readFileSync(this.statePath!, "utf8")) as SimState;
    } catch {
      return { grants: [], intents: {}, userLogs: {} };
    }
  }

  /** Run `fn` on the state under the lock file (a write replaces the state file before the lock is released). Reads
   * take the lock too, so no reader holds the file while another process replaces it (Windows refuses that rename). */
  private withState<T>(fn: (st: SimState) => T, write = true): T {
    if (this.statePath === null) return fn(this.memory);
    const lock = this.statePath + ".lock";
    const waitStart = Date.now();
    const deadline = waitStart + 10_000;
    let fd: number | null = null;
    while (fd === null) {
      try {
        fd = openSync(lock, "wx");
      } catch {
        if (Date.now() > deadline) throw new CustodianUnavailable("simulated custodian state is locked", "not_delivered");
        pause(20);
      }
    }
    // Phase 6 Increment 1 (load flakes, test double only): a long wait for the shared state is reported, so a test that
    // fails under load says whether the simulated custodian's lock was the cause.
    if (Date.now() - waitStart > 2_000) process.stderr.write(`[simulated custodian] waited ${Date.now() - waitStart} ms for the shared state lock (${this.reachableSurface ?? "any surface"})
`);
    try {
      const st = this.load();
      const out = fn(st);
      if (write) {
        const tmp = `${this.statePath}.${process.pid}.tmp`;
        writeFileSync(tmp, JSON.stringify(st));
        replaceWithRetry(tmp, this.statePath);
      }
      return out;
    } finally {
      closeSync(fd);
      unlinkSync(lock);
    }
  }

  /** A read of the state under the lock (nothing is written). */
  private read<T>(fn: (st: SimState) => T): T {
    return this.withState(fn, false);
  }

  // ---- the ledger (Ledger/GrantLedger.cs semantics) ----

  private stateDigest(st: SimState, repoKey: string): string {
    const relevant = st.grants
      .filter((g) => g.repoKey === repoKey)
      .map((g) => ({ id: g.grantId, used: g.loopsUsed, total: g.loopsTotal, revoked: g.revokedAt !== null }));
    return sha256OfCanonicalJson({ repoKey, grants: relevant });
  }

  private prepareGrant(st: SimState, repositoryRoot: string, loops: number, minutes: number, requestId: string): Record<string, unknown> {
    if (!Number.isInteger(loops) || loops < 1 || loops > CUSTODIAN_GRANT_CEILINGS.loops) throw simError("INVALID_ARGUMENT", `loops must be 1..${CUSTODIAN_GRANT_CEILINGS.loops}`);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > CUSTODIAN_GRANT_CEILINGS.minutes) throw simError("INVALID_ARGUMENT", `minutes must be 1..${CUSTODIAN_GRANT_CEILINGS.minutes}`);
    const id = this.identity(repositoryRoot);
    this.assertRequestIdFree(st, requestId);
    st.intents[requestId] = { action: "grant", args: { repositoryRoot: id.canonicalPath, repoKey: id.key, loops, minutes }, repoKey: id.key, stateDigest: this.stateDigest(st, id.key), expiresAtMs: this.now() + AUTH_TTL_MS, requestId };
    return { authorizationRequestId: requestId, action: "grant", rendering: `Grant ${loops} automated loop(s) for ${minutes} min in repository:\n  ${id.canonicalPath}\n  identity ${id.key} (simulated)`, digest: "simulated", challenge: "simulated", expiresAt: new Date(this.now() + AUTH_TTL_MS).toISOString() };
  }

  private prepareRevoke(st: SimState, repositoryRoot: string, requestId: string): Record<string, unknown> {
    const id = this.identity(repositoryRoot);
    this.assertRequestIdFree(st, requestId);
    st.intents[requestId] = { action: "revoke", args: { repositoryRoot: id.canonicalPath, repoKey: id.key }, repoKey: id.key, stateDigest: this.stateDigest(st, id.key), expiresAtMs: this.now() + AUTH_TTL_MS, requestId };
    return { authorizationRequestId: requestId, action: "revoke", rendering: `Revoke all active grants for:\n  ${id.canonicalPath}\n  identity ${id.key}`, digest: "simulated", challenge: "simulated", expiresAt: new Date(this.now() + AUTH_TTL_MS).toISOString() };
  }

  private assertRequestIdFree(st: SimState, requestId: string): void {
    if (requestId.length < 1 || requestId.length > 128 || requestId === "." || requestId === ".." || !/^[A-Za-z0-9_-]+$/.test(requestId)) {
      throw simError("INVALID_ARGUMENT", "request id must be 1..128 chars of [A-Za-z0-9-_]");
    }
    if (st.intents[requestId]) throw simError("REQUEST_ID_CONFLICT", "an authorization with this request id is already pending (REQUEST_ID_CONFLICT)");
    if (st.grants.some((g) => g.requestId === requestId)) throw simError("REQUEST_ID_CONFLICT", "this request id was already committed (REQUEST_ID_CONFLICT)");
    if (st.config && configRequestCommitted(st.config, requestId)) throw simError("REQUEST_ID_CONFLICT", "this request id was already committed (REQUEST_ID_CONFLICT)");
  }

  /** P3.4C-4 (GrantLedger.Config.cs PrepareConfigRecord): validate, measure, render and bind the change to the state of
   * every record it affects; nothing is recorded until commit. */
  private prepareConfigRecord(st: SimState, args: Record<string, unknown>, requestId: string): Record<string, unknown> {
    const root = args.repositoryRoot;
    if (root !== undefined && root !== null && typeof root !== "string") throw simError("INVALID_ARGUMENT", "'repositoryRoot' must be a string");
    const recordId = args.recordId ?? null;
    if (recordId !== null && typeof recordId !== "string") throw simError("INVALID_ARGUMENT", "'recordId' must be a string");
    const payload = args.payload ?? null;
    if (payload !== null && (typeof payload !== "object" || Array.isArray(payload))) throw simError("INVALID_ARGUMENT", "'payload' must be an object");
    if (args.recordKind === "repository" && args.action === "set" && typeof root === "string") this.requireRepositoryReadable(this.identity(root).canonicalPath); // N5-8
    const prepared = prepareConfig(st.config ?? emptyConfig(), { repositoryRoot: typeof root === "string" ? root : null, recordKind: args.recordKind, action: args.action, recordId, payload, baseRevision: args.baseRevision }, (r) => this.identity(r));
    this.assertRequestIdFree(st, requestId);
    st.intents[requestId] = { action: "config_record", args: prepared.args, repoKey: String(prepared.args["repoKey"] ?? ""), stateDigest: prepared.stateDigest, expiresAtMs: this.now() + AUTH_TTL_MS, requestId };
    return { authorizationRequestId: requestId, action: "config_record", rendering: prepared.rendering, digest: "simulated", challenge: "simulated", expiresAt: new Date(this.now() + AUTH_TTL_MS).toISOString() };
  }

  /** Phase 4 Increment 3 (GrantLedger.FixApply.cs PrepareFixDecision): render the held proposal and prepare a decision bound
   * to exactly that rendering; nothing is recorded until commit. */
  private prepareFixDecisionOp(st: SimState, args: Record<string, unknown>, requestId: string, read: SimHeldRead | null): Record<string, unknown> {
    const runId = strictToken(args.runId, "runId", 128);
    const operationId = strictToken(args.operationId, "operationId", 64);
    if (typeof args.decision !== "string") throw simError("INVALID_ARGUMENT", "'decision' must be a string");
    if (args.decision !== "confirm" && args.decision !== "reject") throw simError("INVALID_ARGUMENT", "decision must be 'confirm' or 'reject'");
    if (typeof args.repositoryRoot !== "string") throw simError("INVALID_ARGUMENT", "'repositoryRoot' must be a string");
    const expected = expectedSelectionOf(args);
    const identity = this.identity(args.repositoryRoot);
    const prepared = prepareFixDecision(this.runStoreOf(st), identity, runId, operationId, args.decision, read, this.now(), expected);
    this.assertRequestIdFree(st, requestId);
    st.intents[requestId] = { action: "fix_decision", args: prepared.args, repoKey: identity.key, stateDigest: prepared.stateDigest, expiresAtMs: this.now() + AUTH_TTL_MS, requestId };
    return {
      authorizationRequestId: requestId, action: "fix_decision", rendering: prepared.rendering, digest: "simulated", challenge: "simulated", expiresAt: new Date(this.now() + AUTH_TTL_MS).toISOString(),
      fixDecision: prepared.facts,
    };
  }

  /** Phase 4 Increment 3 (RenderFixProposal): the custodian's rendering of a proposal it holds (read only, both surfaces). */
  private renderFixProposalOp(st: SimState, args: Record<string, unknown>, read: SimHeldRead | null): Record<string, unknown> {
    const runId = strictToken(args.runId, "runId", 128);
    const operationId = strictToken(args.operationId, "operationId", 64);
    if (typeof args.repositoryRoot !== "string") throw simError("INVALID_ARGUMENT", "'repositoryRoot' must be a string");
    const identity = this.identity(args.repositoryRoot);
    if (!read || read.problem !== null || !read.rendering) throw simError("EVIDENCE_NOT_HELD", `the custodian cannot render delegated fix ${operationId}: ${read?.problem ?? "it was not read"}`);
    const run = st.runs?.[runKey(identity.key, runId)];
    if (!run) throw simError("RUN_NOT_OPEN", "the custodian holds no record of this run");
    const op = run.operations.find((o) => o.operationId === operationId && o.kind === "fix");
    if (!op) throw simError("EVIDENCE_NOT_HELD", `the run has no delegated fix ${operationId}`);
    const c = (op.outcome?.["confirmation"] ?? null) as Record<string, unknown> | null;
    return {
      operationId, status: read.status, proposalDigest: read.proposalDigest, expiresAt: (op.outcome?.["proposal"] as Record<string, unknown> | undefined)?.["expiresAt"] ?? null,
      rendering: read.rendering.text, renderingDigest: read.rendering.digest, changesDigest: read.rendering.changesDigest,
      confirmation: c ? { confirmationId: c["confirmationId"] ?? null, decision: c["decision"] ?? null, expiresAt: c["expiresAt"] ?? null, consumedAt: c["consumedAt"] ?? null } : null,
    };
  }

  private commit(st: SimState, authorizationRequestId: string, held: SimHeldRead | null = null): Record<string, unknown> {
    const intent = st.intents[authorizationRequestId];
    if (!intent) throw simError("AUTHORIZATION_INVALID", "no pending authorization for this request id (AUTHORIZATION_INVALID)");
    if (intent.expiresAtMs < this.now()) {
      delete st.intents[authorizationRequestId];
      throw simError("AUTHORIZATION_EXPIRED", "authorization expired (AUTHORIZATION_EXPIRED)");
    }
    // P3.4C-3 (§3.4(2)): a decision on a run that has ended since its prepare is refused as such.
    const ended = intent.action === "user_record" && intent.args.recordKind === "decision" ? st.runs?.[runKey(intent.repoKey, String(intent.args.runId))] : undefined;
    if (ended && isRunTerminal(ended)) {
      delete st.intents[authorizationRequestId];
      throw simError("RUN_TERMINAL", `the run has ended (${ended.status}) since this was prepared; nothing was committed`);
    }
    if (intent.action === "fix_decision") {
      // Phase 4 Increment 3 (RequireFreshFixDecision): the rendering produced again before the hold must be the one shown.
      try {
        requireFreshFixDecision(this.runStoreOf(st), intent.args, intent.stateDigest, held && held.problem === null ? held.rendering?.digest ?? null : null, this.now());
      } catch (e) {
        delete st.intents[authorizationRequestId];
        throw e;
      }
    }
    const current = intent.action === "fix_decision" ? intent.stateDigest
      : intent.action === "user_record"
      ? this.userRecordStateDigest(st, intent.repoKey, String(intent.args.runId), String(intent.args.recordKind), intent.args.payload, intent.args.redactionBasis !== undefined)
      : intent.action === "config_record"
        ? configStateDigest(st.config ?? emptyConfig(), intent.args)
        : this.stateDigest(st, intent.repoKey);
    if (current !== intent.stateDigest) {
      delete st.intents[authorizationRequestId];
      if (intent.action === "config_record") throw simError("STALE_CONFIG", "a configuration record this change affects changed since it was prepared; nothing was recorded — prepare it again against the current configuration");
      throw simError("STALE_FINDING_STATE", "the ledger changed since this was prepared (STALE_FINDING_STATE)");
    }
    if (intent.action === "grant" || intent.action === "user_record" || intent.action === "fix_decision" || (intent.action === "config_record" && intent.args.recordKind === "repository" && intent.args.action !== "revoke")) {
      let same = false;
      try {
        same = this.identity(String(intent.args.repositoryRoot)).key === intent.repoKey;
      } catch {
        same = false;
      }
      if (!same) {
        delete st.intents[authorizationRequestId];
        throw simError("STALE_FINDING_STATE", "the repository directory changed since this was prepared; nothing was committed (STALE_FINDING_STATE)");
      }
    }
    delete st.intents[authorizationRequestId];
    if (intent.action === "config_record") {
      const recordedBy = { role: "user", channel: "custodian_operator", assurance: "local_admin_elevation", proofDigest: "simulated", requestId: intent.requestId };
      return applyConfig((st.config ??= emptyConfig()), intent.args, intent.requestId, recordedBy, this.now());
    }
    if (intent.action === "fix_decision") {
      const recordedBy = { role: "user", channel: "custodian_operator", assurance: "local_admin_elevation", proof_digest: "simulated", request_id: intent.requestId };
      return applyFixDecision(this.runStoreOf(st), intent.args, intent.requestId, recordedBy, this.now());
    }
    return intent.action === "grant" ? this.applyGrant(st, intent) : intent.action === "revoke" ? this.applyRevoke(st, intent.repoKey) : this.applyUserRecord(st, intent);
  }

  private applyGrant(st: SimState, intent: SimIntent): Record<string, unknown> {
    const now = this.now();
    const grant: SimGrant = {
      grantId: uuidv7(),
      repoKey: intent.repoKey,
      repositoryRoot: String(intent.args.repositoryRoot),
      loopsTotal: Number(intent.args.loops),
      loopsUsed: 0,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + Number(intent.args.minutes) * 60_000).toISOString(),
      revokedAt: null,
      assurance: "local_admin_elevation",
      requestId: intent.requestId,
      uses: [],
    };
    st.grants.push(grant);
    return { grantId: grant.grantId, loopsTotal: grant.loopsTotal, expiresAt: grant.expiresAt, assurance: "local_admin_elevation" };
  }

  private applyRevoke(st: SimState, repoKey: string): Record<string, unknown> {
    const now = this.now();
    let n = 0;
    for (const g of st.grants) {
      if (g.repoKey === repoKey && g.revokedAt === null && Date.parse(g.expiresAt) > now) {
        g.revokedAt = new Date(now).toISOString();
        n++;
      }
    }
    return { revoked: n };
  }

  /** P3.4C-2 (GrantLedger.cs ConsumeLoop): consume one grant loop AND mint the run's unbound loop record in one
   * state write; idempotent on the request id; one loop per run; a terminal run is never resurrected. */
  private consume(st: SimState, repositoryRoot: string, runId: unknown, requestId: string): Record<string, unknown> {
    if (typeof runId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(runId)) throw simError("INVALID_ARGUMENT", "runId must be 1..128 chars of [A-Za-z0-9-_]");
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(requestId)) throw simError("INVALID_ARGUMENT", "request id must be 1..128 chars of [A-Za-z0-9-_]");
    const now = this.now();
    const repoKey = this.identity(repositoryRoot).key;
    const loops = (st.loops ??= []);
    const existing = loops.find((l) => l.repoKey === repoKey && l.runId === runId);
    if (existing) {
      if (existing.requestId === requestId) return consumeResultOf(existing);
      if (!LIVE_STATUSES.has(existing.status)) throw simError("LOOP_TERMINAL", `run ${runId} already had an automation loop that ended (${existing.status}); it is not resurrected (LOOP_TERMINAL)`);
      throw simError("RUN_ALREADY_HAS_LOOP", `run ${runId} already has an automation loop; a second is not minted (RUN_ALREADY_HAS_LOOP)`);
    }
    // P3.4C-3 (§3.4(1), §5.5 I1): a loop is minted only for a run the custodian holds open, read in this same hold.
    const run = (st.runs ??= {})[runKey(repoKey, runId)];
    if (!run) throw simError("RUN_NOT_OPEN", `run ${runId} was not opened with the custodian; nothing was consumed`);
    if (isRunTerminal(run)) throw simError("RUN_TERMINAL", `run ${runId} has ended (${run.status}); nothing was consumed`);
    // A grant suspended by recovery (§2.4 U2) is never consumed.
    const g = st.grants.find((x) => x.repoKey === repoKey && x.revokedAt === null && Date.parse(x.expiresAt) > now && x.loopsUsed < x.loopsTotal && !x.suspendedAt);
    if (!g) throw simError("LOOP_NOT_AUTHORIZED", "no automated loop is authorized for this repository (LOOP_NOT_AUTHORIZED)");
    const loopId = uuidv7();
    g.loopsUsed += 1;
    g.uses.push({ loopId, at: new Date(now).toISOString() });
    const { loop, nonce } = mintLoop({ repoKey, runId, requestId, grantId: g.grantId, loopsUsed: g.loopsUsed, loopsTotal: g.loopsTotal, loopId, nowMs: now });
    loops.push(loop);
    return { ...consumeResultOf(loop), bindNonce: nonce };
  }

  /** P3.4C-2 (GrantLedger.Loops.cs): one custodian-computed loop transition; P3.4C-3: it reads the run record in the
   * same hold. */
  private loopTransition(st: SimState, args: Record<string, unknown>, requestId: string, operator: boolean, o: SimObserved, automation: AutomationContext | null = null): Record<string, unknown> {
    const req = parseLoopRequest(args, requestId);
    const repoKey = this.identity(String(args.repositoryRoot)).key;
    const runs = (st.runs ??= {});
    const runOf = (runId: string): SimRunView | null => {
      const r = runs[runKey(repoKey, runId)];
      return r ? { status: r.status, terminal: isRunTerminal(r) } : null;
    };
    const now = this.now();
    const check = automation
      ? {
          phase: automation.phase,
          check: (loop: SimLoop, r: typeof req) => {
            const run = runs[runKey(repoKey, r.runId)] ?? null;
            // In order (RequireAutomationDerivation): stale — current, then the re-measurement — then route, then progress.
            const d = requireCurrentDerivation(new Map(Object.entries(st.derivations ?? {})), repoKey, r.runId, r.derivationId, revisionVector(this.derivationStateOf(st), repoKey, run, r.runId), now);
            if (automation.phase === "commit") {
              if (automation.entry?.derivationId !== d.derivationId) throw new SimLoopRefusal("DERIVATION_STALE", "the derivation changed during the re-measurement; derive again");
              requireSameMeasurement(d, automation.measured);
              requireRouteAndProgress(d, loop);
            }
            automation.checked = d;
            return { derivationId: d.derivationId, fingerprint: d.fingerprint, routeCode: d.routeCode };
          },
        }
      : undefined;
    return applyLoopTransition((st.loops ??= []), repoKey, req, { operator, client: o.client, ...(check ? { automation: check } : {}) }, now, o.process, runOf);
  }

  /** §5.2, N5-17 (GrantLedger.Loops.cs AutomationTransition): every rule under the hold (no write), the derivation's
   * measurement taken again outside it, then every rule again and the re-measurement compared under the hold. */
  private async automationTransition(surface: CustodianSurface, args: Record<string, unknown>, requestId: string, observed: SimObserved): Promise<CustodianResponse> {
    const pre: AutomationContext = { phase: "precheck", entry: null, measured: null, checked: null };
    const first = this.withState((st) => this.handleLoop(st, surface, args, requestId, observed, pre));
    if (!first.ok || (first.data as Record<string, unknown>)["precheck"] !== true) return first;
    const entry = pre.checked!;
    const measured = await this.remeasure(entry);
    return this.withState((st) => this.handleLoop(st, surface, args, requestId, observed, { phase: "commit", entry, measured, checked: null }));
  }

  private handleLoop(st: SimState, surface: CustodianSurface, args: Record<string, unknown>, requestId: string, observed: SimObserved, automation: AutomationContext): CustodianResponse {
    const caller = this.caller === "by_surface" ? (surface === "operator" ? "operator" : "implementer") : this.caller;
    try {
      return ok(this.loopTransition(st, args, requestId, caller === "operator", observed, automation));
    } catch (e) {
      return failFromError(e);
    }
  }

  /** N5-17: the derivation's measurement, taken again (null when it did not succeed). */
  private async remeasure(d: SimDerivationEntry): Promise<Record<string, unknown> | null> {
    const o = await this.measure(d.canonicalRoot, structuredClone(d.workload), `msr-${randomBytes(10).toString("hex")}`);
    return o.ok ? o.measured : null;
  }

  /** P3.4C-3 (GrantLedger.Runs.cs): one custodian-computed run transition. */
  private runTransition(st: SimState, args: Record<string, unknown>, requestId: string, operator: boolean, o: SimObserved): Record<string, unknown> {
    const req = parseRunRequest(args, requestId);
    const identity = this.identity(String(args.repositoryRoot));
    const repoKey = identity.key;
    const store = this.runStoreOf(st);
    store.rehash = o.rehash ?? null;
    store.fixBaseline = o.fixBaseline ?? null;
    store.applyPre = o.applyPre ?? null;
    store.startCheckMeasurement = (t) => this.startCheckMeasurement({ t, repositoryRoot: String(args.repositoryRoot), canonicalRoot: identity.canonicalPath });
    store.requireRepositoryReadable = () => this.requireRepositoryReadable(identity.canonicalPath);
    store.startCapture = (t) => {
      const r = currentOf(st.config ?? emptyConfig(), repoKey)!.captureRules;
      this.startCapture({
        t, repositoryRoot: String(args.repositoryRoot), canonicalRoot: identity.canonicalPath,
        rules: { exclude_globs: [...r.excludeGlobs], context_include: [...r.contextInclude], max_file_bytes: r.maxFileBytes, max_export_bytes: r.maxExportBytes, max_diff_bytes: r.maxDiffBytes },
      });
    };
    return applyRunTransition(store, repoKey, req, { operator, clientPid: process.pid, client: o.client, writer: o.writer, writerGone: o.writerGone ?? selfOnlyGone }, this.now());
  }

  /** The ledger state a run transition (or a capture's commit) reads and writes, in one hold. */
  private runStoreOf(st: SimState): SimRunStore {
    return {
      runs: (st.runs ??= {}),
      loops: (st.loops ??= []),
      grants: st.grants,
      amendmentsOf: (rk, runId) =>
        ((st.userLogs ??= {})[this.userLogKey(rk, runId)]?.records ?? []).filter((r) => r.recordKind === "amendment").map((r) => ({ recordId: r.recordId, disclosureDigest: r.disclosureDigest })),
      config: (st.config ??= emptyConfig()),
      captureEnabled: this.helper !== null,
      measureEnabled: this.helper !== null,
      cancelCapture: (ticket) => {
        if (ticket) this.captureCancels.get(ticket)?.abort();
      },
      retired: this.retiredDirs,
      fixProposals: (st.fixProposals ??= {}),
      evidence: (st.evidence ??= {}),
    };
  }

  /** P3.4C-5 Increment 4 (GrantLedger.DrainRetiredExports): remove the ticket directories retired in the last hold. */
  private drainRetired(): void {
    for (const dir of this.retiredDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  }

  /** The tickets whose directories a measurement in progress owns (TicketDirs.Live). */
  private liveTickets(): Set<string> {
    return new Set([...this.captureCancels.keys(), ...this.manualCaptures.keys(), ...this.manualChecks.keys(), ...this.measuringTickets]);
  }

  /** TEST control and service behaviour (GrantLedger.SweepExports): the full retention sweep — exports the rules no longer
   * keep are retired, then everything under the export root no held, unretired capture references and no measurement in
   * progress owns is removed. Returns the number retired and removed. */
  sweepExportsNow(): { retired: number; removed: number; proposalsRemoved: number } {
    if (!this.helper) return { retired: 0, removed: 0, proposalsRemoved: 0 };
    const out = this.withState((st) => retentionSweep(this.runStoreOf(st), this.now()));
    this.drainRetired();
    const removed = sweepExports(this.helper.exportsRoot, out.referenced, this.liveTickets());
    return { retired: out.retired, removed, proposalsRemoved: out.proposalsRemoved };
  }

  /** TEST control (Phase 4 Increment 2): held proposal content no run references, as a custodian stopped between writing the
   * content and the run record would leave it. */
  orphanProposalForTest(repositoryRoot: string, runId: string, operationId: string): void {
    const repoKey = this.identity(repositoryRoot).key;
    this.withState((st) => {
      (st.fixProposals ??= {})[proposalKey(repoKey, runId, operationId)] = { repoKey, runId, operationId, proposalDigest: "0".repeat(64), changes: [] };
    });
  }

  /** Start a reserved capture after the reservation is written (manual: only when a test asks). */
  private startCapture(pc: PendingCapture): void {
    const ac = new AbortController();
    this.captureCancels.set(pc.t.ticket, ac);
    if (this.helper?.mode === "manual") {
      this.manualCaptures.set(pc.t.ticket, pc);
      return;
    }
    const run = (async () => {
      const gitExe = this.helper?.gitExe;
      const end: SimCaptureEnd = gitExe
        ? await simulatedHelperCapture({ repoRoot: pc.canonicalRoot, gitExe, target: pc.t.target as ReviewTarget, rules: pc.rules, exportsRoot: this.helper!.exportsRoot, ticket: pc.t.ticket, operationId: pc.t.operationId, signal: ac.signal })
        : { captured: false, reason: "measurement_failed", detail: "the simulated helper has no git", capture: null };
      await this.commitMeasurement(pc, ac.signal.aborted && end.captured ? { captured: false, reason: "cancelled", detail: "the capture was cancelled", capture: null } : end);
    })().catch(() => undefined);
    const tracked = run.finally(() => this.runningCaptures.delete(tracked));
    this.runningCaptures.add(tracked);
  }

  // ---- P3.4C-5 Increment 3: the custodian's measurements (§4, §5.1) ----

  /** One measurement: the corpus's synthetic one (manual helper), or the helper's own workload in process (auto). */
  private async measure(canonicalRoot: string, workload: Record<string, unknown>, ticket: string): Promise<SimMeasureOutcome> {
    if (!this.helper) return { ok: false, code: "HELPER_UNAVAILABLE", detail: "no helper", measured: null, derivation: null };
    this.measuringTickets.add(ticket);
    let o: SimMeasureOutcome;
    try {
      o = this.measureMode() === "manual" ? syntheticMeasure(workload, this.synthetic)
        : this.helper.gitExe ? await simulatedHelperMeasure({ repoRoot: canonicalRoot, gitExe: this.helper.gitExe, workload, exportsRoot: this.helper.exportsRoot, ticket })
        : { ok: false, code: "MEASUREMENT_FAILED", detail: "the simulated helper has no git", measured: null, derivation: null };
    } finally {
      this.measuringTickets.delete(ticket);
    }
    if (!o.ok) return o;
    const problem = measuredProblem(o.measured, (workload["checks"] as Record<string, unknown>[] | undefined) ?? []);
    if (problem !== null) return { ok: false, code: "MEASUREMENT_FAILED", detail: problem, measured: null, derivation: null };
    if (this.helper.freshProgress && o.derivation) o.derivation["progressFingerprint"] = randomBytes(32).toString("hex");
    return o;
  }

  private measureMode(): "auto" | "manual" {
    return this.helper?.measure ?? this.helper?.mode ?? "auto";
  }

  /** TEST control (P3.4C-5 Increment 3, manual helper): what the synthetic measurement measures and derives. */
  setSyntheticMeasurement(spec: SimSyntheticMeasurement): void {
    this.synthetic = { ...spec };
  }

  /** Start a reserved check measurement after the reservation is written (manual: only when a test asks). */
  private startCheckMeasurement(pc: PendingCheck): void {
    const ac = new AbortController();
    this.captureCancels.set(pc.t.ticket, ac);
    if (this.measureMode() === "manual") {
      this.manualChecks.set(pc.t.ticket, pc);
      return;
    }
    const run = (async () => {
      const o = await this.measure(pc.canonicalRoot, pc.t.workload, pc.t.ticket);
      await this.commitCheck(pc, ac.signal.aborted ? { ok: false, code: "MEASUREMENT_CANCELLED", detail: "the measurement was cancelled", measured: null, derivation: null } : o);
    })().catch(() => undefined);
    const tracked = run.finally(() => this.runningCaptures.delete(tracked));
    this.runningCaptures.add(tracked);
  }

  private async commitCheck(pc: PendingCheck, o: SimMeasureOutcome): Promise<Record<string, unknown> | null> {
    const gone = await this.writerGoneCheck({ repositoryRoot: pc.repositoryRoot, runId: pc.t.runId });
    const out = this.withState((st) => (pc.t.kind === "start" ? commitCheckStart(this.runStoreOf(st), pc.t, o, gone, this.now()) : commitCheckEnd(this.runStoreOf(st), pc.t, o, this.now())));
    this.captureCancels.delete(pc.t.ticket);
    return out;
  }

  /** TEST control (P3.4C-5 Increment 3, manual helper): run the check measurement reserved for `operationId` now with
   * the synthetic measurement `spec`; returns its commit's result, or null when none is waiting. */
  async runReservedCheckMeasurement(operationId: string, spec: SimSyntheticMeasurement = {}): Promise<Record<string, unknown> | null> {
    const entry = [...this.manualChecks.values()].find((x) => x.t.operationId === operationId);
    if (!entry) return null;
    this.manualChecks.delete(entry.t.ticket);
    const saved = this.synthetic;
    this.synthetic = { ...spec };
    try {
      return await this.commitCheck(entry, await this.measure(entry.canonicalRoot, entry.t.workload, entry.t.ticket));
    } finally {
      this.synthetic = saved;
    }
  }

  private derivationStateOf(st: SimState): SimDerivationState {
    return {
      runs: (st.runs ??= {}),
      loops: (st.loops ??= []),
      config: (st.config ??= emptyConfig()),
      userLog: (rk, runId) => {
        const log = (st.userLogs ??= {})[this.userLogKey(rk, runId)];
        return log ? { revision: log.revision, recoveredAtRevision: log.recoveredAtRevision ?? null, records: log.records.map((r) => this.implementerProjection(r)) } : null;
      },
      configSection: (rk) => configSection(st.config ?? emptyConfig(), rk, false),
      nowMs: this.now(),
    };
  }

  /** §5.1 (GrantLedger.Derivation.cs DerivationSection): the snapshot in one hold, the measurement and derivation outside
   * it, the result cached under a fresh derivationId — or available:false with the reason (fail closed). */
  /** TEST: the snapshot the last derivation section built (null when it built none) — the run corpus's N5-5 parity oracle
   * compares it with the real custodian's (GrantLedger.LastDerivationSnapshotForTest). */
  lastDerivationSnapshotForTest: Record<string, unknown> | null = null;

  private async derivationSection(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.lastDerivationSnapshotForTest = null;
    const unavailable = (code: string, detail: string): Record<string, unknown> => ({ available: false, authority: "custodian", code, detail: detail.slice(0, 400) });
    let prepared: { canonicalRoot: string; repoKey: string; runId: string; workload: Record<string, unknown>; atMs: number };
    try {
      if (typeof args.runJson !== "string") throw new SimLoopRefusal("INVALID_ARGUMENT", "the derivation needs the run's run.json (runJson, base64): the custodian verifies it against the declaration it holds and reads the run's own floor from it");
      const bytes = Buffer.from(args.runJson, "base64");
      if (bytes.length > 256 * 1024) throw new SimLoopRefusal("INVALID_ARGUMENT", "runJson is larger than 256 KiB");
      const identity = this.identity(String(args.repositoryRoot));
      const runId = String(args.runId);
      prepared = this.read((st) => {
        const run = st.runs?.[runKey(identity.key, runId)];
        if (!run) throw new SimLoopRefusal("RUN_NOT_OPEN", "the custodian holds no record of this run; there is no protected derivation");
        if (createHash("sha256").update(bytes).digest("hex") !== run.declaration.runJsonDigest) throw new SimLoopRefusal("RUN_JSON_MISMATCH", "run.json differs from the one the run was opened with (the custodian's declaration digest); nothing is derived");
        let floor: unknown = null;
        try {
          const parsed = JSON.parse(bytes.toString("utf8")) as unknown;
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
          floor = (parsed as Record<string, unknown>)["verification_floor"] ?? null;
        } catch {
          throw new SimLoopRefusal("RUN_JSON_MISMATCH", "run.json is not a JSON object");
        }
        this.requireMeasureReady(st);
        this.requireRepositoryReadable(identity.canonicalPath);
        const cfg = requireUsableConfig(st.config ?? emptyConfig(), identity.key, "a protected derivation");
        const snapshot = derivationSnapshot(this.derivationStateOf(st), identity.canonicalPath, run, floor && typeof floor === "object" && !Array.isArray(floor) ? floor : null, runLimits(run) as { maxReviews: number; maxCheckExecutions: number });
        this.lastDerivationSnapshotForTest = structuredClone(snapshot);
        return {
          canonicalRoot: identity.canonicalPath, repoKey: identity.key, runId,
          workload: { rules: rulesJson(cfg), checks: derivationChecks(run, cfg, snapshot["executables"] as Record<string, unknown>), snapshot },
          atMs: this.now(),
        };
      });
    } catch (e) {
      const code = (e as { code?: unknown }).code;
      return unavailable(typeof code === "string" ? code : "INVALID_ARGUMENT", e instanceof Error ? e.message : String(e));
    }
    const o = await this.measure(prepared.canonicalRoot, prepared.workload, `der-${randomBytes(10).toString("hex")}`);
    if (!o.ok) return unavailable(o.code ?? "MEASUREMENT_FAILED", o.detail ?? "");
    const d = o.derivation ?? {};
    const route = (d["route"] ?? {}) as Record<string, unknown>;
    const fingerprint = d["progressFingerprint"], inputDigest = d["inputDigest"];
    if (typeof route["kind"] !== "string" || typeof route["code"] !== "string" || typeof fingerprint !== "string" || fingerprint.length !== 64 || typeof inputDigest !== "string" || inputDigest.length !== 64 || typeof (d["completion"] as Record<string, unknown> | undefined)?.["state"] !== "string") {
      return unavailable("MEASUREMENT_FAILED", "the helper returned no well-formed derivation");
    }
    const snapshotRevision = (prepared.workload["snapshot"] as Record<string, unknown>)["revision"] as Record<string, unknown>;
    const derivationId = `der-${randomBytes(12).toString("hex")}`;
    const section: Record<string, unknown> = {
      available: true, authority: "custodian", derivationId, at: new Date(prepared.atMs).toISOString(), ttlSeconds: SIM_DERIVATION_TTL_MS / 1000,
      revision: structuredClone(snapshotRevision), completion: structuredClone(d["completion"]), route: structuredClone(route), floor: structuredClone(d["floor"] ?? null),
      currentSourceId: d["currentSourceId"] ?? null, inputDigest, progressFingerprint: fingerprint, measured: structuredClone(o.measured),
    };
    const entry: SimDerivationEntry = {
      derivationId, repoKey: prepared.repoKey, runId: prepared.runId, atMs: prepared.atMs, revision: structuredClone(snapshotRevision), routeKind: route["kind"] as string, routeCode: route["code"] as string,
      fingerprint, inputDigest, measuredDigest: measuredDigest(o.measured!), workload: { rules: prepared.workload["rules"], checks: prepared.workload["checks"], snapshot: null }, section: structuredClone(section),
      canonicalRoot: prepared.canonicalRoot,
    };
    this.withState((st) => {
      const cache = (st.derivations ??= {});
      for (const [k, v] of Object.entries(cache)) if (prepared.atMs - v.atMs > 2 * SIM_DERIVATION_TTL_MS) delete cache[k];
      cache[derivationId] = entry;
    });
    return section;
  }

  /** N5-8 (GrantLedger.RequireRepositoryReadable): the helper's group must be able to read the repository; the refusal
   * names the operator's icacls grant on the repository only. */
  private requireRepositoryReadable(canonicalRoot: string): void {
    const r = this.repositoryReaders;
    if (!r) return;
    const problem = r.problem(canonicalRoot);
    if (problem !== null) {
      throw new SimLoopRefusal("REPOSITORY_NOT_READABLE", `the repository ${canonicalRoot} is not readable by '${r.name}' (${problem}); nothing was begun — the operator grants it on the repository only: \`icacls "${canonicalRoot}" /grant "*${r.sid}:(OI)(CI)(RX)"\` (no ACE is added on any parent folder or the user profile)`);
    }
  }

  /** The runtime a measurement runs under (RequireMeasureReady). */
  private requireMeasureReady(st: SimState): void {
    if (!this.helper) throw new SimLoopRefusal("HELPER_UNAVAILABLE", "the custodian measures a protected run's source and checks through its helper, which is not installed or not enabled; nothing was begun — the operator installs it (`CodeParley.Custodian.exe install-helper`) and restarts the custodian");
    const rt = currentRuntime(st.config ?? emptyConfig());
    if (!rt) throw new SimLoopRefusal("RUNTIME_NOT_APPROVED", "no engine runtime is approved for the custodian's helper; nothing was begun — the operator approves one with `code-parley config approve-runtime --runtime <dir> --runtime-git <relative git.exe>`");
    if (rt.revokedAt !== null) throw new SimLoopRefusal("RUNTIME_NOT_APPROVED", `the approved engine runtime ${rt.runtimeId} was revoked; nothing was begun — the operator approves one again (\`code-parley config approve-runtime\`)`);
    if (rt.lapsedAtRecoveryId !== null) throw new SimLoopRefusal("CONFIG_LAPSED", `the engine runtime approval lapsed after a restart of the OS (recovery ${rt.lapsedAtRecoveryId}); nothing was begun — the operator re-confirms it (\`code-parley config reconfirm-runtime ${rt.runtimeId}\`)`);
  }

  /** The commit of a measurement (CommitCapture) in one hold; a capture not kept is removed. */
  private async commitMeasurement(pc: PendingCapture, end: SimCaptureEnd): Promise<Record<string, unknown> | null> {
    const gone = await this.writerGoneCheck({ repositoryRoot: pc.repositoryRoot, runId: pc.t.runId });
    const out = this.withState((st) => commitCapture(this.runStoreOf(st), pc.t, end, gone, this.now()));
    if (!out.keep && this.helper) removeTicketDirs(this.helper.exportsRoot, pc.t.ticket);
    this.drainRetired();
    this.captureCancels.delete(pc.t.ticket);
    return out.result;
  }

  private list(st: SimState): Record<string, unknown> {
    const now = this.now();
    return {
      grants: st.grants.map((g) => ({
        grantId: g.grantId, repoKey: g.repoKey, repositoryRoot: g.repositoryRoot, identity: g.repoKey.split("-")[0],
        loopsUsed: g.loopsUsed, loopsTotal: g.loopsTotal, expiresAt: g.expiresAt, revoked: g.revokedAt !== null,
        // P3.4C-3 (§2.4 U2): a grant suspended by recovery after a new boot is shown as such and is never active.
        suspended: !!g.suspendedAt,
        active: g.revokedAt === null && !g.suspendedAt && Date.parse(g.expiresAt) > now && g.loopsUsed < g.loopsTotal,
        assurance: g.assurance,
      })),
      ceilings: { loops: CUSTODIAN_GRANT_CEILINGS.loops, minutes: CUSTODIAN_GRANT_CEILINGS.minutes },
    };
  }

  // ---- P3.4C-1 user-record log (Ledger/GrantLedger.cs user-record semantics) ----

  private userLogKey(repoKey: string, runId: string): string {
    return `${repoKey}\u0000${runId}`;
  }

  private userLogDigest(st: SimState, repoKey: string, runId: string): string {
    const log = (st.userLogs ??= {})[this.userLogKey(repoKey, runId)];
    return sha256OfCanonicalJson({ repoKey, runId, revision: log?.revision ?? 0, records: (log?.records ?? []).map((r) => r.recordId) });
  }

  /** The custodian redactions measured for a prepare, by request id (consumed by the prepare in the same request): the
   * representation and the basis digest it rests on. */
  private readonly redactions = new Map<string, { text: string; basis: string; readDisclosure: string }>();
  /** hold_evidence parts received so far, by evidenceKey (GrantLedger.HoldEvidence's `.part` file). */
  private readonly evidenceParts = new Map<string, Buffer>();

  /** TEST control (F-i2-5): the redaction evidence the custodian holds for a run, by SHA-256 — a test removes or alters one. */
  evidenceForTest(repositoryRoot: string, runId: string): { list: () => string[]; get: (sha256: string) => string | undefined; remove: (sha256: string) => void; alter: (sha256: string, text: string) => void } {
    const key = this.identity(repositoryRoot).key;
    const prefix = evidenceKey(key, runId, "");
    return {
      list: () => this.read((st) => Object.keys(st.evidence ?? {}).filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length))),
      get: (sha) => this.read((st) => st.evidence?.[evidenceKey(key, runId, sha)]),
      remove: (sha) => this.withState((st) => void delete st.evidence?.[evidenceKey(key, runId, sha)]),
      alter: (sha, text) => this.withState((st) => void ((st.evidence ??= {})[evidenceKey(key, runId, sha)] = text)),
    };
  }

  /** hold_evidence (GrantLedger.HoldEvidence): a part of a record whose digest the run binds as its baseline capture or a
   * response set's disclosure record; the last part is checked and the record held. */
  private holdEvidence(st: SimState, args: Record<string, unknown>): Record<string, unknown> {
    const runId = String(args.runId);
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(runId)) throw simError("INVALID_ARGUMENT", "runId must be 1..128 chars of [A-Za-z0-9-_]");
    const sha = String(args.sha256);
    if (!/^[0-9a-f]{64}$/.test(sha)) throw simError("INVALID_ARGUMENT", "sha256 must be 64 lowercase hex characters");
    const part = Number(args.part), parts = Number(args.parts);
    const maxParts = (64 << 20) / EVIDENCE_PART_BYTES;
    if (!Number.isInteger(part) || !Number.isInteger(parts) || parts < 1 || parts > maxParts || part < 0 || part >= parts) throw simError("INVALID_ARGUMENT", `part must be 0..parts-1 and parts 1..${maxParts}`);
    const data = Buffer.from(String(args.data), "base64");
    if (data.length > EVIDENCE_PART_BYTES) throw simError("INVALID_ARGUMENT", `one part carries at most ${EVIDENCE_PART_BYTES} bytes`);
    const repoKey = this.identity(String(args.repositoryRoot)).key;
    const run = st.runs?.[runKey(repoKey, runId)];
    if (!run) throw simError("RUN_NOT_OPEN", "the custodian holds no record of this run; no evidence is held for it");
    const bound = run.declaration.baseline?.digest === sha || run.responses.some((x) => x["disclosureDigest"] === sha);
    if (!bound) throw simError("EVIDENCE_NOT_HELD", "no baseline capture or response disclosure of this run has that digest; nothing was held");
    const key = evidenceKey(repoKey, runId, sha);
    if ((st.evidence ??= {})[key] !== undefined) return { held: true, sha256: sha };
    const sofar = part === 0 ? Buffer.alloc(0) : this.evidenceParts.get(key);
    if (!sofar || sofar.length !== part * EVIDENCE_PART_BYTES) throw simError("INVALID_ARGUMENT", `part ${part} does not follow the parts held so far; send the record again from part 0`);
    const all = Buffer.concat([sofar, data]);
    if (part < parts - 1) {
      if (data.length !== EVIDENCE_PART_BYTES) {
        this.evidenceParts.delete(key);
        throw simError("INVALID_ARGUMENT", "only the last part may be shorter than a full part");
      }
      this.evidenceParts.set(key, all);
      return { held: false, sha256: sha, received: part + 1 };
    }
    this.evidenceParts.delete(key);
    if (createHash("sha256").update(all).digest("hex") !== sha) throw simError("EVIDENCE_NOT_HELD", "the record's parts do not hash to its digest; nothing was held");
    st.evidence[key] = all.toString("utf8");
    return { held: true, sha256: sha };
  }

  /** The run's redaction basis (GrantLedger.RedactionBasisOf): every bound record, held and intact, or a refusal. */
  private redactionBasisOf(st: SimState, repoKey: string, runId: string): { evidence: { kind: string; sha256: string; text: string }[]; basis: string } {
    const run = st.runs?.[runKey(repoKey, runId)];
    if (!run) throw simError("REDACTION_REFUSED", "the custodian holds no record of this run, so its withheld names cannot be established; nothing was prepared");
    const records = (st.userLogs ?? {})[this.userLogKey(repoKey, runId)]?.records ?? [];
    const a = unestablishedAmendment(records);
    if (a) throw simError("REDACTION_REFUSED", `amendment A-${a.seq} of this run has reviewer-visible text but the custodian holds no record of what its read withheld, so the run's withheld names cannot be established; nothing was prepared`);
    const refs = evidenceRefsOf(run, records);
    const evidence = refs.map((r) => {
      const text = st.evidence?.[evidenceKey(repoKey, runId, r.sha256)];
      if (text === undefined || createHash("sha256").update(text, "utf8").digest("hex") !== r.sha256) {
        throw simError("REDACTION_REFUSED", `the custodian does not hold ${r.label} (${r.sha256.slice(0, 12)})${text === undefined ? "" : " intact"}, so the run's withheld names cannot be established; nothing was prepared (the redaction never falls back to the current repository alone)`);
      }
      return { kind: r.kind, sha256: r.sha256, text };
    });
    return { evidence, basis: redactionBasisDigest(repoKey, runId, refs) };
  }

  /** The run's current redaction basis digest (GrantLedger.CurrentBasisDigest), or null without a run record. */
  private currentBasisDigest(st: SimState, repoKey: string, runId: string): string | null {
    const run = st.runs?.[runKey(repoKey, runId)];
    return run ? redactionBasisDigest(repoKey, runId, evidenceRefsOf(run, (st.userLogs ?? {})[this.userLogKey(repoKey, runId)]?.records ?? [])) : null;
  }

  /**
   * Phase 5 F-i2-5 (GrantLedger.RedactForReview): the custodian's helper redacts the amendment text over a fresh, stable
   * read under the held capture rules; the payload gets the digest and the read's source, and the representation waits
   * for the prepare. A client-supplied digest or source, an unstable read or a failed helper refuses.
   */
  private async redactedAmendment(repositoryRoot: string, runId: string, payload: Record<string, unknown>, requestId: string): Promise<Record<string, unknown>> {
    if (payload.custodian_redaction !== true) throw simError("INVALID_ARGUMENT", "payload.custodian_redaction is true when present");
    if ("disclosure_digest" in payload || "source" in payload) throw simError("INVALID_ARGUMENT", "an amendment the custodian redacts may not carry 'disclosure_digest' or 'source': the custodian derives both from its own read");
    if ("read_disclosure_digest" in payload) throw simError("INVALID_ARGUMENT", "payload may not carry 'read_disclosure_digest': the custodian sets it from its own read");
    const text = String(payload.text ?? "");
    if (text.trim().length === 0) return { ...payload, source: null };
    const identity = this.identity(repositoryRoot);
    const { rules, evidence, basis } = this.read((st) => {
      this.requireMeasureReady(st);
      this.requireRepositoryReadable(identity.canonicalPath);
      const rules = rulesJson(requireUsableConfig(st.config ?? emptyConfig(), identity.key, "a protected amendment's redaction"));
      return { rules, ...this.redactionBasisOf(st, identity.key, runId) };
    });
    const o = await this.measure(identity.canonicalPath, { rules, checks: [], snapshot: null, redact: { text, keepRoots: [identity.canonicalPath], evidence } }, `red-${randomBytes(10).toString("hex")}`);
    if (!o.ok) throw simError(o.code ?? "MEASUREMENT_FAILED", `the custodian could not read the repository to redact the amendment text (${(o.detail ?? "").slice(0, 200)}); nothing was prepared`);
    const r = o.redaction ?? null;
    if (!r) throw simError("REDACTION_REFUSED", "the helper produced no redaction; nothing was prepared");
    if (r["ok"] !== true) throw simError("REDACTION_REFUSED", `the amendment text cannot be made reviewer-visible (${String(r["error"] ?? "no reason given").slice(0, 200)}); nothing was prepared`);
    if (o.measured?.["stable"] !== true || r["sourceId"] !== o.measured["sourceId"]) throw simError("REDACTION_REFUSED", "the working tree changed while it was being read, so the redaction is not established; nothing was prepared — try again when the worktree is free");
    const redacted = String(r["redacted"]);
    // Phase 5 OI-1: what this read withheld (the helper's disclosure record), held at the prepare and bound by the record.
    const readDisclosure = r["disclosure"];
    if (typeof readDisclosure !== "string" || readDisclosure.length === 0) throw simError("REDACTION_REFUSED", "the helper did not report what its read withheld, so later redactions could not cover it; nothing was prepared");
    this.redactions.set(requestId, { text: redacted, basis, readDisclosure });
    return { ...payload, disclosure_digest: createHash("sha256").update(redacted, "utf8").digest("hex"), source: { source_id: String(r["sourceId"]) }, redaction_basis_digest: basis, read_disclosure_digest: createHash("sha256").update(readDisclosure, "utf8").digest("hex") };
  }

  private prepareUserRecord(st: SimState, repositoryRoot: string, runId: string, recordKind: string, payload: Record<string, unknown>, baseRevision: number, requestId: string): Record<string, unknown> {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(runId)) throw simError("INVALID_ARGUMENT", "runId must be 1..128 chars of [A-Za-z0-9-_]");
    if (recordKind !== "decision" && recordKind !== "amendment") throw simError("INVALID_ARGUMENT", "recordKind must be 'decision' or 'amendment'");
    for (const banned of ["recorded_by", "role", "channel", "assurance", "proof_digest", "seq", "record_id"]) {
      if (banned in payload) throw simError("INVALID_ARGUMENT", `payload may not carry '${banned}': the custodian sets provenance, ordering and identifiers`);
    }
    const kind = String(payload.kind ?? "");
    if (!kind) throw simError("INVALID_ARGUMENT", "payload.kind is required");
    if (recordKind === "amendment") {
      const text = String(payload.text ?? "");
      // P3.4C-1 confidentiality correction: the content-equivalence key and byte length are DERIVED by the
      // custodian from the authoritative text (keyed HMAC under its secret), never supplied by the client.
      if ("content_key_hash" in payload || "text_bytes" in payload) throw simError("INVALID_ARGUMENT", "payload may not carry 'content_key_hash' or 'text_bytes': the custodian derives the content-equivalence key and byte length from the authoritative text");
      if (text.trim().length > 0) {
        const dd = payload.disclosure_digest;
        if (typeof dd !== "string" || !/^[0-9a-f]{64}$/.test(dd)) throw simError("INVALID_ARGUMENT", "payload.disclosure_digest (sha256 of the operator-confirmed redacted artifact) is required for an amendment with text");
      }
    }
    const id = this.identity(repositoryRoot);
    this.assertRequestIdFree(st, requestId);
    const current = (st.userLogs ??= {})[this.userLogKey(id.key, runId)]?.revision ?? 0;
    if (baseRevision !== current) throw simError("STALE_FINDING_STATE", `the run's user-record log changed since this was prepared (revision ${current}, prepared against ${baseRevision})`);
    if (recordKind === "decision") this.validateProtectedDecision(st, id.key, runId, payload);
    const redaction = recordKind === "amendment" ? (this.redactions.get(requestId) ?? null) : null;
    this.redactions.delete(requestId);
    // Phase 5 OI-1: only the custodian sets read_disclosure_digest (from its own read); a client cannot name one.
    const readSha = redaction ? createHash("sha256").update(redaction.readDisclosure, "utf8").digest("hex") : null;
    if ("read_disclosure_digest" in payload && payload.read_disclosure_digest !== readSha) {
      throw simError("INVALID_ARGUMENT", "payload may not carry 'read_disclosure_digest': the custodian sets it from its own read");
    }
    if (redaction && readSha !== null) (st.evidence ??= {})[evidenceKey(id.key, runId, readSha)] = redaction.readDisclosure;
    const disclosureText = redaction?.text ?? null;
    const redactionBasis = redaction?.basis ?? null;
    if (redactionBasis !== null && this.currentBasisDigest(st, id.key, runId) !== redactionBasis) {
      throw simError("STALE_FINDING_STATE", "a capture or a disclosure was recorded for this run while the text was being redacted, so the redaction does not cover it; nothing was recorded — read the current state and decide anew");
    }
    st.intents[requestId] = {
      action: "user_record",
      args: { repositoryRoot: id.canonicalPath, repoKey: id.key, runId, recordKind, payload, baseRevision, ...(disclosureText !== null ? { disclosureText } : {}), ...(redactionBasis !== null ? { redactionBasis } : {}) },
      repoKey: id.key,
      stateDigest: this.userRecordStateDigest(st, id.key, runId, recordKind, payload, redactionBasis !== null),
      expiresAtMs: this.now() + AUTH_TTL_MS,
      requestId,
    };
    const shown = disclosureText !== null ? `\n  Codex will see exactly this redaction of your text (the custodian's, from its own read; the raw text stays in the custodian):\n  ${JSON.stringify(disclosureText)}` : "";
    return { authorizationRequestId: requestId, action: "user_record", rendering: `Record a ${recordKind} (${kind}) for run ${runId}\n  ${id.canonicalPath}\n  identity ${id.key} (simulated; revision ${current} → ${current + 1})${shown}`, digest: "simulated", challenge: "simulated", expiresAt: new Date(this.now() + AUTH_TTL_MS).toISOString() };
  }

  /**
   * P3.4C-3 (§3.4(2), GrantLedger.cs ValidateProtectedDecision): a decision on a PROTECTED run (the custodian holds its
   * loop or run record) is checked against the custodian's own run record at prepare — the run is open and not
   * terminal, every covered item exists and is open, the decision names the run's latest accepted review, and no reply
   * or response on a covered item is newer than the ones it names. A run that is not protected is unchanged.
   */
  private validateProtectedDecision(st: SimState, repoKey: string, runId: string, payload: Record<string, unknown>): void {
    const hasLoop = (st.loops ?? []).some((l) => l.repoKey === repoKey && l.runId === runId);
    const run = st.runs?.[runKey(repoKey, runId)];
    if (!hasLoop && !run) return;
    if (!run) throw simError("RUN_NOT_OPEN", "the custodian holds no run record for this protected run, so the state a decision covers cannot be verified; nothing was prepared");
    if (isRunTerminal(run)) throw simError("RUN_TERMINAL", `the run has ended (${run.status}); nothing was prepared`);
    const covered = coveredItems(payload);
    if (covered.size === 0) throw simError("INVALID_ARGUMENT", "payload.covered_items must name the open items the decision covers");
    for (const itemId of covered) if (run.items.find((i) => i.itemId === itemId)?.status !== "open") throw stale(`item ${itemId} is not an open item of this run`);
    const da = payload.decided_against;
    if (!da || typeof da !== "object" || Array.isArray(da)) throw simError("INVALID_ARGUMENT", "payload.decided_against is required");
    const d = da as Record<string, unknown>;
    const latest = [...run.reviews].reverse().find((r) => r.accepted === true) ?? null;
    if (stringOrNull(d.run_review_id) !== (latest?.reviewId ?? null) || integerOrNull(d.run_round) !== (latest?.round ?? null)) throw stale("the run's current review is not the one the decision names");
    checkLatestOnCovered(run.replies, "replyId", stringOrNull(d.latest_reply_id), covered, "reply");
    checkLatestOnCovered(run.responses, "responseId", stringOrNull(d.latest_response_id), covered, "response");
  }

  /** The "state shown" of a user record, which its commit re-derives in the same hold as its write: the run's
   * user-record log; for a DECISION on a run the custodian holds a run record for, also the covered items' revisions
   * and statuses and whether the run has ended (GrantLedger.cs UserRecordStateDigest). */
  private userRecordStateDigest(st: SimState, repoKey: string, runId: string, recordKind: string, payload: unknown, redacted = false): string {
    const log = this.userLogDigest(st, repoKey, runId);
    // Phase 5 F-i2-5: an amendment the custodian redacted is bound to the redaction basis it was redacted against.
    if (redacted) return sha256OfCanonicalJson({ log, redactionBasis: this.currentBasisDigest(st, repoKey, runId) ?? "none" });
    const run = st.runs?.[runKey(repoKey, runId)];
    if (recordKind !== "decision" || !run) return log;
    const covered = [...coveredItems(payload)].sort().map((id) => {
      const it = run.items.find((i) => i.itemId === id);
      return { id, revision: it?.itemRevision ?? -1, status: it?.status ?? null };
    });
    return sha256OfCanonicalJson({ log, covered, terminal: isRunTerminal(run) });
  }

  /** The simulated custodian's content-key HMAC secret: generated once (CSPRNG) and persisted with the
   * state (so equality survives a "restart"), with a non-secret id. Never served on any surface. */
  private contentKeySecret(st: SimState): Buffer {
    if (!st.contentKeySecret) {
      st.contentKeySecret = randomBytes(32).toString("hex");
      st.contentKeyId = randomBytes(8).toString("hex");
    }
    return Buffer.from(st.contentKeySecret, "hex");
  }

  private applyUserRecord(st: SimState, intent: SimIntent): Record<string, unknown> {
    const repoKey = String(intent.args.repoKey);
    const runId = String(intent.args.runId);
    const recordKind = String(intent.args.recordKind) as "decision" | "amendment";
    const payload = (intent.args.payload ?? {}) as Record<string, unknown>;
    const logs = (st.userLogs ??= {});
    const key = this.userLogKey(repoKey, runId);
    const log: SimUserLog = logs[key] ?? { repoKey, runId, revision: 0, records: [] };
    let contentKeyHash: string | null = null;
    let textBytes: number | null = null;
    let disclosureDigest: string | null = null;
    let contentKeyScheme: string | null = null;
    if (recordKind === "amendment") {
      // The custodian DERIVES the keyed content key and byte length from the authoritative text (never the
      // client). Pre-correction (unkeyed) records are never mixed with keyed ones; the secret binds by id.
      if (log.records.some((r) => r.recordKind === "amendment" && r.contentKeyScheme !== CONTENT_KEY_SCHEME)) {
        throw simError("STALE_FINDING_STATE", "this run holds pre-correction (unkeyed) amendment records; a keyed amendment is refused (fail closed)");
      }
      const secret = this.contentKeySecret(st);
      const kind = String(payload.kind ?? "");
      const text = String(payload.text ?? "");
      contentKeyHash = createHmac("sha256", secret).update(`${CONTENT_KEY_DOMAIN}\u0000${amendmentContentKey(kind, text)}`, "utf8").digest("hex");
      textBytes = Buffer.byteLength(text, "utf8");
      disclosureDigest = typeof payload.disclosure_digest === "string" ? (payload.disclosure_digest as string) : null;
      contentKeyScheme = CONTENT_KEY_SCHEME;
    }
    const disclosureText = recordKind === "amendment" && typeof intent.args.disclosureText === "string" ? intent.args.disclosureText : null;
    if (disclosureText !== null && createHash("sha256").update(disclosureText, "utf8").digest("hex") !== disclosureDigest) throw simError("INTERNAL", "the held redaction does not hash to the disclosure digest the record binds; nothing was recorded");
    // Phase 5 OI-1 (GrantLedger.RequireHeldReadDisclosure): recorded only with its read disclosure held and intact.
    const readSha = recordKind === "amendment" && typeof payload.read_disclosure_digest === "string" ? payload.read_disclosure_digest : null;
    if (readSha !== null) {
      const held = st.evidence?.[evidenceKey(repoKey, runId, readSha)];
      if (held === undefined || createHash("sha256").update(held, "utf8").digest("hex") !== readSha) throw simError("REDACTION_REFUSED", `the custodian does not hold this amendment's read disclosure record (${readSha.slice(0, 12)}) intact; nothing was recorded`);
    }
    const seq = log.records.length + 1;
    const rec: SimUserRecord = {
      recordId: uuidv7(),
      seq,
      recordKind,
      payload: structuredClone(payload),
      contentKeyHash,
      textBytes,
      disclosureDigest,
      contentKeyScheme,
      recordedBy: { role: "user", channel: "custodian_operator", assurance: "local_admin_elevation", proof_digest: "simulated", request_id: intent.requestId },
      recordedAt: new Date(this.now()).toISOString(),
      ...(disclosureText !== null ? { disclosureText } : {}),
    };
    logs[key] = { ...log, revision: log.revision + 1, records: [...log.records, rec] };
    return { recordId: rec.recordId, seq, revision: logs[key]!.revision, recordKind };
  }

  /** P3.4C-3: every requested section from one state read (one hold) — the user-record log, the loop record and the
   * run record, each with its own revision. `protected` is the custodian's selection answer (§5.4): the custodian
   * holds the run's loop record OR its run record. */
  private listUserRecords(st: SimState, repositoryRoot: string, runId: string, operatorView: boolean, sections: readonly string[], writerGone: ((w: SimWriter) => boolean | null) | null): Record<string, unknown> {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(runId) || runId === "." || runId === "..") throw simError("INVALID_ARGUMENT", "runId must be 1..128 chars of [A-Za-z0-9-_]");
    const identity = this.identity(repositoryRoot);
    const repoKey = identity.key;
    // Phase 5 F-i2-5 (GrantLedger.ListUserRecords): the snapshot section is served on the operator surface only.
    if (sections.includes("snapshot") && !operatorView) throw simError("CALLER_NOT_AUTHORIZED", "the snapshot section is served on the operator surface only");
    const result: Record<string, unknown> = {};
    if (sections.includes("user")) {
      const log = (st.userLogs ??= {})[this.userLogKey(repoKey, runId)];
      result.governed = log !== undefined;
      result.revision = log?.revision ?? 0;
      result.logDigest = this.userLogDigest(st, repoKey, runId);
      result.records = (log?.records ?? []).map((r) => (operatorView ? this.operatorProjection(r) : this.implementerProjection(r)));
      // §2.4 U4: the revision recovery ran at (null: no recovery touched this log).
      result.recoveredAtRevision = log?.recoveredAtRevision ?? null;
    }
    const run = (st.runs ??= {})[runKey(repoKey, runId)] ?? null;
    result.protected = (st.loops ?? []).some((l) => l.repoKey === repoKey && l.runId === runId) || run !== null;
    // P3.4C-2 (contract §6): the loop section, from the loop records with their OWN revision.
    if (sections.includes("loop")) result.loop = loopSection(st.loops ?? [], repoKey, runId, operatorView);
    if (sections.includes("run")) result.run = runSection(run, repoKey, runId, operatorView, operatorView ? null : (writerGone ?? selfOnlyGone), st.config ?? emptyConfig());
    // P3.4C-4 (§3.3): the repository's configuration record and the global records, from this same read.
    if (sections.includes("config")) result.config = configSection(st.config ?? emptyConfig(), repoKey, operatorView);
    // Phase 5 F-i2-5: the run's held records scrubbed as the protected derivation reads them, from this same read.
    if (sections.includes("snapshot")) result.snapshot = run ? derivationSnapshot(this.derivationStateOf(st), identity.canonicalPath, run, null, runLimits(run) as { maxReviews: number; maxCheckExecutions: number }) : null;
    return result;
  }

  private operatorProjection(r: SimUserRecord): Record<string, unknown> {
    const o: Record<string, unknown> = { ...structuredClone(r.payload), recordId: r.recordId, seq: r.seq, recordKind: r.recordKind, recorded_by: r.recordedBy, recorded_at: r.recordedAt };
    if (r.contentKeyHash !== null) o.contentKeyHash = r.contentKeyHash;
    if (r.textBytes !== null) o.textBytes = r.textBytes;
    if (r.disclosureDigest !== null) o.disclosureDigest = r.disclosureDigest;
    if (typeof r.disclosureText === "string") o.disclosureText = r.disclosureText;
    return o;
  }

  /** An INDEPENDENT allowlist — only the fields the derivation and review presentation need; never the raw
   * decision note or amendment text. */
  private implementerProjection(r: SimUserRecord): Record<string, unknown> {
    const p = r.payload;
    const base: Record<string, unknown> = {
      recordId: r.recordId, seq: r.seq, recordKind: r.recordKind, kind: p.kind ?? "",
      recorded_by: r.recordedBy, recorded_at: r.recordedAt, request_digest: p.request_digest ?? null,
      source_id: (p.source as { source_id?: unknown } | undefined)?.source_id ?? null,
    };
    if (r.recordKind === "decision") {
      base.thread_id = p.thread_id ?? null;
      base.current_item_id = p.current_item_id ?? null;
      base.covered_items = Array.isArray(p.covered_items) ? structuredClone(p.covered_items) : [];
      base.supersedes = Array.isArray(p.supersedes) ? structuredClone(p.supersedes) : [];
      base.decided_against = p.decided_against ? structuredClone(p.decided_against) : null;
      base.context = p.context ? structuredClone(p.context) : null;
    } else {
      base.relates_to = Array.isArray(p.relates_to) ? structuredClone(p.relates_to) : [];
      base.replaces = p.replaces ?? null;
      base.contentKeyHash = r.contentKeyHash;
      base.textBytes = r.textBytes;
      base.disclosureDigest = r.disclosureDigest;
      if (typeof r.disclosureText === "string") base.disclosureText = r.disclosureText;
    }
    return base;
  }
}

function pause(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Replace `to` with `from`, retrying briefly while another process (an anti-malware scan of the file just written)
 * holds the target for a moment — as the custodian's write path does (DurableStore). */
function replaceWithRetry(from: string, to: string): void {
  for (let attempt = 1; ; attempt++) {
    try {
      renameSync(from, to);
      return;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (attempt >= 10 || (code !== "EPERM" && code !== "EBUSY" && code !== "EACCES")) throw e;
      pause(25 * attempt);
    }
  }
}

/** The OS facts the simulated custodian reads itself before it decides — never fields of the request. */
interface SimObserved {
  /** bind/rebind: the custodian's check of the process the request names. */
  process: SimProcessCheck | null;
  /** An automation loop kind, or a run's op_begin/respond: the connected process checked against the bound one. */
  client: SimClientCheck | null;
  /** A run's op_begin, record_execution or op_finish: the process that sent the request. */
  writer: SimWriter | null;
  /** A run's recover, or a run section: whether an operation's writer is gone. */
  writerGone: ((w: SimWriter) => boolean | null) | null;
  /** P3.4C-5: a run's op_finish of a captured review: the custodian's re-hash of its export, taken before the hold. */
  rehash?: SimExportRehash | null;
  /** Phase 4 Increment 2: a fix's op_begin or op_finish: the custodian's read of the baseline capture, before the hold. */
  fixBaseline?: SimFixBaselineRead | null;
  /** Phase 4 Increment 3: an application's begin, finish or reconciliation: its content and measurement, before the hold. */
  applyPre?: SimApplyPre | null;
  /** Step 7.1: the operator's listing (built before the hold), or the refusal it answers with. */
  fixListing?: Record<string, unknown> | Error | null;
  /** Phase 4 Increment 3: a fix decision's prepare or commit, or a rendering: the held proposal read and rendered. */
  heldRead?: SimHeldRead | null;
}

/** A request token as the custodian validates it (RunFields.RequireToken): 1..max chars of [A-Za-z0-9-_]. */
function strictToken(v: unknown, name: string, max: number): string {
  if (typeof v !== "string") throw simError("INVALID_ARGUMENT", `'${name}' must be a string`);
  if (v.length < 1 || v.length > max || v === "." || v === ".." || !/^[A-Za-z0-9_-]+$/.test(v)) throw simError("INVALID_ARGUMENT", `${name} must be 1..${max} chars of [A-Za-z0-9-_]`);
  return v;
}
const NOTHING_OBSERVED: SimObserved = { process: null, client: null, writer: null, writerGone: null };

/** A minimal PE image (CaptureFixture/ConfigFixture.PeBytes): an MZ header whose e_lfanew points at a PE signature. */
function simulatedPe(variant: number): Buffer {
  const b = Buffer.alloc(512);
  b[0] = 0x4d;
  b[1] = 0x5a;
  b[0x3c] = 0x80;
  b[0x80] = 0x50;
  b[0x81] = 0x45;
  b[0x84] = 0x64;
  b[0x85] = 0x86;
  b[0x100] = variant;
  return b;
}

/** Without a process-table snapshot only this process is known: it is alive; nothing else is assumed gone. */
const selfOnlyGone = (w: SimWriter): boolean | null => (isSelfWriter(w) ? false : null);

function wantsRunSection(args: Record<string, unknown>): boolean {
  return Array.isArray(args.sections) && args.sections.includes("run");
}

/** list_user_records' optional `sections` (CustodianCore.cs Sections): distinct names from user, loop, run. */
function sectionsOf(args: Record<string, unknown>): readonly string[] {
  if (!("sections" in args)) return DEFAULT_SECTIONS;
  const v = args.sections;
  if (!Array.isArray(v) || v.length === 0) throw simError("INVALID_ARGUMENT", "'sections' must be a non-empty array of section names");
  const seen = new Set<string>();
  for (const x of v) {
    if (typeof x !== "string") throw simError("INVALID_ARGUMENT", "'sections' entries must be strings");
    if (!(ALL_SECTIONS.has(x) || OPERATOR_SECTIONS.has(x)) || seen.has(x)) throw simError("INVALID_ARGUMENT", "'sections' entries must be distinct names from: user, loop, run, config, derivation, snapshot");
    seen.add(x);
  }
  return [...seen];
}

/** The item ids a decision covers (GrantLedger.cs CoveredItems): the non-empty strings of payload.covered_items. */
function coveredItems(payload: unknown): Set<string> {
  const a = (payload as { covered_items?: unknown } | null)?.covered_items;
  return new Set(Array.isArray(a) ? a.filter((x): x is string => typeof x === "string" && x.length > 0) : []);
}

/** The decision names `claimed` as the latest reply (or response) it saw; none on a covered item may come after it in
 * the custodian's order (GrantLedger.cs CheckLatestOnCovered). */
function checkLatestOnCovered(records: readonly Record<string, unknown>[], idKey: string, claimed: string | null, covered: ReadonlySet<string>, what: string): void {
  let lastOnCovered = -1;
  records.forEach((r, i) => {
    if (covered.has(typeof r["itemId"] === "string" ? r["itemId"] : "")) lastOnCovered = i;
  });
  if (claimed === null) {
    if (lastOnCovered >= 0) throw stale(`a ${what} on a covered item is newer than the state the decision names`);
    return;
  }
  const claimedAt = records.findIndex((r) => r[idKey] === claimed);
  if (claimedAt < 0) throw stale(`the ${what} ${claimed} the decision names is not one the custodian holds`);
  if (lastOnCovered > claimedAt) throw stale(`a ${what} on a covered item is newer than ${claimed}`);
}

const stale = (why: string): SimError => simError("STALE_FINDING_STATE", `${why}; nothing was recorded — read the current state and decide anew`);
const stringOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const integerOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isInteger(v) ? v : null);

interface SimError extends Error {
  simCode: string;
}
function simError(code: string, message: string): SimError {
  const e = new Error(message) as SimError;
  e.simCode = code;
  return e;
}
function failFromError(e: unknown): CustodianResponse {
  const code = e instanceof SimLoopRefusal ? e.code : e instanceof SimLoopInvalid ? "INVALID_ARGUMENT" : ((e as SimError)?.simCode ?? "INTERNAL");
  return { ok: false, code, error: e instanceof Error ? e.message : String(e) };
}
function ok(data: Record<string, unknown>): CustodianResponse {
  return { ok: true, data };
}
function notAuthorized(op: string): CustodianResponse {
  return { ok: false, code: "CALLER_NOT_AUTHORIZED", error: `${op} requires the operator surface (an elevated operator token)` };
}

/** The protocol version the simulated transport speaks (for parity assertions). */
export const SIMULATED_PROTOCOL_VERSION = CUSTODIAN_PROTOCOL_VERSION;
