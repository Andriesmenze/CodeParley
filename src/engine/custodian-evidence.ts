// P3.4C-3 (contract §3.2, §4.2, §4.3, §5.2–§5.4): on a PROTECTED run the engine records its evidence with the
// CUSTODIAN first — run_transition op_begin / record_execution / op_finish (checks, reviews), respond, recover and end —
// and only then updates its local state.json, which is a cache. Whether a run's evidence goes through the custodian
// is the custodian's answer (it holds the run's loop or run record), asked wherever the custodian service is
// registered (or its registration is unknown); the local marks can only add a refusal.
//
// The custodian validates and orders what the engine reports; it does not authenticate who produced it (digest binding
// proves integrity since recording, not producer authenticity; D7 correlation is not implementer authentication).

import { readFile } from "node:fs/promises";
import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfBytes, shortHash } from "../common/hash.js";
import { CustodianGrants, deliveryOutcomeOf } from "../custodian/grants.js";
import { protectedLoopGate, type CustodianTestHooks } from "../custodian/protected-loops.js";
import { CUSTODIAN_UNAVAILABLE, custodianError, SERVER_NOT_TRUSTED, type CustodianSurface, type RunSection, type RunTransitionFields, type RunTransitionKind, type RunTransitionResult } from "../custodian/protocol.js";
import { CustodianRuns } from "../custodian/runs.js";
import type { CustodianPresence } from "../custodian/service-presence.js";
import type { CustodianTransport } from "../custodian/transport.js";
import { resolveArtifact } from "../store/artifacts.js";
import type { OwnerRecord } from "../store/owner.js";
import type { RunPaths } from "../store/paths.js";
import { commitState, readState } from "../store/state-store.js";
import type { StateRecord } from "../schemas/run-state.js";
import { locallyProtected } from "./protected-user-records.js";
import { verifyRunJson } from "./protected-config.js";
import type { RunMeta } from "../schemas/run-state.js";

/** What the engine needs to ask whether a run's evidence goes through the custodian. */
export interface EvidenceSelection {
  custodian?: CustodianTestHooks | undefined;
  presence: () => Promise<CustodianPresence>;
  repositoryRoot: string;
  runId: string;
  /** P3.4C-4 (§1.1): the run's run.json and the metadata the engine parsed from it, re-verified against the digest the
   * custodian bound at `open` before a protected run's evidence is recorded (RUN_JSON_MISMATCH). */
  runJson?: { path: string; meta: RunMeta };
}

/** The custodian channel of a protected run's evidence. Every refusal is thrown as the engine error of its code. */
export interface CustodianEvidence {
  transition<K extends RunTransitionKind>(kind: K, fields: RunTransitionFields[K], requestId: string): Promise<RunTransitionResult>;
  /** The run section as the custodian holds it now (the implementer projection; null: no record). */
  runSection(): Promise<RunSection | null>;
  /** Phase 5 F-i2-5: hand over the bytes of a record the run binds by digest, as redaction evidence (CustodianRuns.holdEvidence). */
  holdEvidence(bytes: Buffer): Promise<void>;
}

/** How often a request whose answer was lost, or that was not delivered, is sent again under the same request id
 * (replay-safe: the custodian returns the stored result of an applied request). */
const ATTEMPTS = 3;

function unavailable(why: string): DomainError {
  return new DomainError(CUSTODIAN_UNAVAILABLE, why, { retryable: false, details: { outcome: "not_delivered" } });
}

function runRecordMissing(runId: string): DomainError {
  return new DomainError("RUN_RECORD_MISSING", `run ${runId} is recorded locally as protected, but the custodian holds neither its loop nor its run record; nothing is recorded on this run — automate a new run`, { retryable: false });
}

/**
 * The custodian channel for this run's evidence, or null for an attended run (its evidence stays in the TS store and
 * never becomes authoritative). Fail closed: where the custodian service is registered (or its registration unknown),
 * a custodian that cannot answer refuses every run (CUSTODIAN_UNAVAILABLE; Phase 6 S-3: the local marks are
 * user-writable hints); a run the local copy marks protected of which it holds no record is refused (RUN_RECORD_MISSING).
 */
export async function custodianEvidenceFor(sel: EvidenceSelection, st: StateRecord): Promise<CustodianEvidence | null> {
  const marked = locallyProtected(st);
  if ((await sel.presence()) === "absent") {
    if (marked) throw unavailable("this run is recorded as protected, but no CodeParley custodian service is installed on this host; nothing was recorded");
    return null;
  }
  const gate = protectedLoopGate(sel.custodian);
  let protectedRun: boolean;
  let transport: CustodianTransport;
  let section: RunSection | null = null;
  try {
    if (!gate.available) throw gate.error;
    transport = gate.transport;
    const listing = await new CustodianGrants(transport).listUserRecords("implementer", sel.repositoryRoot, sel.runId, ["run"]);
    if (listing.protected === null) throw unavailable("the custodian did not answer whether this run is protected");
    protectedRun = listing.protected;
    section = listing.run;
  } catch (e) {
    // Phase 6 S-3 (D-34): a registered (or unknown) custodian that cannot answer refuses every run, marked or not: the
    // local marks are user-writable hints, so a run whose mark was removed is not thereby attended (fail closed).
    throw isDomainError(e) ? e : unavailable(`the custodian could not say whether this run is protected (${e instanceof Error ? e.message : String(e)}); start the CodeParley custodian service, then retry`);
  }
  if (!protectedRun) {
    if (marked) throw runRecordMissing(sel.runId);
    return null;
  }
  if (sel.runJson) await verifyRunJson(sel.runJson.path, sel.runJson.meta, section);
  const runs = new CustodianRuns(transport);
  const target = { repositoryRoot: sel.repositoryRoot, runId: sel.runId };
  return {
    async runSection() {
      return (await new CustodianGrants(transport).listUserRecords("implementer", sel.repositoryRoot, sel.runId, ["run"])).run;
    },
    async holdEvidence(bytes) {
      for (let attempt = 1; ; attempt++) {
        try {
          return await runs.holdEvidence("implementer", target, bytes);
        } catch (e) {
          if (attempt >= ATTEMPTS || deliveryOutcomeOf(e) === null) throw e;
          await new Promise((r) => setTimeout(r, 150 * attempt));
        }
      }
    },
    async transition(kind, fields, requestId) {
      for (let attempt = 1; ; attempt++) {
        try {
          const out = await runs.transition("implementer", target, kind, fields, requestId);
          if (out.ok) return out.data;
          throw custodianError(out.code, out.message);
        } catch (e) {
          if (attempt >= ATTEMPTS || deliveryOutcomeOf(e) === null) throw e;
          await new Promise((r) => setTimeout(r, 150 * attempt));
        }
      }
    },
  };
}

/** A run end the custodian has not acknowledged yet (state.json `custodian_end_pending`). */
export interface PendingEnd {
  status: "stopped" | "closed";
  reason: string;
}

/** The incident kinds `recover` carries (contract §3.2). */
const RECOVER_INCIDENTS: ReadonlySet<string> = new Set(["possible_surviving_sandboxed_commands", "termination_unconfirmed"]);

/**
 * End a protected run with the custodian (contract §5.4: the local stop has already applied — a reduction — and the
 * custodian's `end` follows; in the same hold it derives the loop's end). Retried under the same request id until
 * the custodian acknowledges it (an `end` it already applied, or a run it holds as ended, both count); until then the
 * run's `custodian_end_pending` mark keeps it pending for the next engine call that reconciles the run. Never throws.
 */
export async function endCustodianRun(sel: EvidenceSelection, paths: RunPaths, owner: OwnerRecord, end: PendingEnd): Promise<boolean> {
  const st = await readState(paths);
  let ev: CustodianEvidence | null;
  try {
    ev = await custodianEvidenceFor(sel, st);
  } catch {
    return false;
  }
  if (ev) {
    const pending = st.custodian_end_pending ?? end;
    try {
      await ev.transition("end", { status: pending.status, reason: bounded(pending.reason) || pending.status }, `${sel.runId}-end`);
    } catch (e) {
      if (!isDomainError(e) || e.code !== "RUN_TERMINAL") return false;
    }
  }
  if (st.custodian_end_pending) {
    await commitState(paths, owner, (cur) => {
      delete cur.custodian_end_pending;
      return cur;
    }).catch(() => undefined);
  }
  return true;
}

/** An application the custodian held as begun when a run ended: it is not recalled (`op_finish` still runs on an ended run). */
export interface ApplicationAtEnd {
  operation_id: string;
  status: string;
}

/**
 * What the custodian said about ending a run. Only `ended` and `already_ended` are its acknowledgment; `no_custodian`
 * means the service manager says none is installed and no local mark says otherwise. A local record proves none of them.
 * `applications` is what had already begun, read after the end (nothing can begin later); null: it could not be read.
 */
export type CustodianEndResult =
  | { outcome: "ended" | "already_ended"; surface: CustodianSurface; applications: ApplicationAtEnd[] | null }
  | { outcome: "no_custodian" }
  | { outcome: "refused" | "not_delivered" | "unknown"; code: string; detail: string };

/** Did this stop establish that no confirmed fix can begin, and that none already had? */
export function endEstablished(r: CustodianEndResult): boolean {
  if (r.outcome === "no_custodian") return true;
  return (r.outcome === "ended" || r.outcome === "already_ended") && r.applications !== null && r.applications.length === 0;
}

const RUNNING_APPLICATIONS: ReadonlySet<string> = new Set(["running", "apply_interrupted"]);

/** The applications of the run that had begun and not finished, as the custodian holds them; null when unreadable. */
async function applicationsAtEnd(transport: CustodianTransport, surface: CustodianSurface, repositoryRoot: string, runId: string): Promise<ApplicationAtEnd[] | null> {
  try {
    const ops = (await new CustodianGrants(transport).listUserRecords(surface, repositoryRoot, runId, ["run"])).run?.record?.["operations"];
    if (!Array.isArray(ops)) return null;
    return (ops as { kind?: unknown; status?: unknown; operationId?: unknown }[])
      .filter((o) => o.kind === "apply" && typeof o.status === "string" && RUNNING_APPLICATIONS.has(o.status))
      .map((o) => ({ operation_id: String(o.operationId), status: String(o.status) }));
  } catch {
    return null;
  }
}

type EndAttempt = { outcome: "ended" | "already_ended" } | Extract<CustodianEndResult, { code: string }>;

/** One surface's answer to `end`, sent again under the same request id while its delivery is in doubt. */
async function endOnSurface(runs: CustodianRuns, surface: CustodianSurface, target: { repositoryRoot: string; runId: string }, end: PendingEnd): Promise<EndAttempt> {
  const reason = bounded(end.reason) || end.status;
  // The surface and the end travel in the id: a replay is only ever one caller's same request (REQUEST_ID_CONFLICT otherwise).
  const requestId = `${target.runId}-end-${surface}-${end.status}-${shortHash(sha256OfBytes(Buffer.from(reason)))}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const out = await runs.transition(surface, target, "end", { status: end.status, reason }, requestId);
      if (out.ok) return { outcome: "ended" };
      if (out.code === "RUN_TERMINAL") return { outcome: "already_ended" };
      return { outcome: "refused", code: out.code, detail: out.message };
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e);
      const code = isDomainError(e) ? e.code : "INTERNAL";
      const delivery = deliveryOutcomeOf(e);
      if (code === SERVER_NOT_TRUSTED) return { outcome: "not_delivered", code, detail };
      if (delivery !== null && attempt < ATTEMPTS) {
        await new Promise((r) => setTimeout(r, 150 * attempt));
        continue;
      }
      if (delivery === "not_delivered") return { outcome: "not_delivered", code, detail };
      if (delivery === "unknown" || !isDomainError(e)) return { outcome: "unknown", code, detail };
      return { outcome: "refused", code, detail };
    }
  }
}

/** Is another surface worth trying? Refused here, or unreachable or in doubt here; never an endpoint that is not the custodian. */
function tryNextSurface(a: Extract<CustodianEndResult, { code: string }>): boolean {
  if (a.code === SERVER_NOT_TRUSTED) return false;
  return a.code === "CALLER_NOT_AUTHORIZED" || (a.code === CUSTODIAN_UNAVAILABLE && a.outcome !== "refused");
}

/**
 * Ask the custodian to end a run, from nothing but its two locators (contract §5.4; TD, candidate 3). They locate; the
 * custodian resolves the repository's identity itself and refuses a run it does not hold under it. It decides from the
 * OS caller it observes, so `surfaces` is only the order to try the pipes: `end` is open to both, and a pipe this
 * process may not reach refuses it. Only the service manager's "not installed" (Phase 6 S-3) spares the question, and
 * only for a run the caller may treat as attended (`attendedIfAbsent`).
 */
export async function askCustodianToEnd(sel: Pick<EvidenceSelection, "custodian" | "presence" | "repositoryRoot" | "runId">, end: PendingEnd, surfaces: readonly CustodianSurface[], attendedIfAbsent: boolean): Promise<CustodianEndResult> {
  const presence = await sel.presence().catch(() => "unknown" as const);
  if (presence === "absent") {
    if (attendedIfAbsent) return { outcome: "no_custodian" };
    return { outcome: "not_delivered", code: CUSTODIAN_UNAVAILABLE, detail: "this run can only end at the custodian, and no CodeParley custodian service is installed on this host" };
  }
  const gate = protectedLoopGate(sel.custodian);
  if (!gate.available) return { outcome: "not_delivered", code: gate.error.code, detail: gate.error.message };
  const runs = new CustodianRuns(gate.transport);
  const target = { repositoryRoot: sel.repositoryRoot, runId: sel.runId };
  let failure: Extract<CustodianEndResult, { code: string }> | null = null;
  for (const surface of surfaces) {
    const a = await endOnSurface(runs, surface, target, end);
    if (!("code" in a)) return { outcome: a.outcome, surface, applications: await applicationsAtEnd(gate.transport, surface, target.repositoryRoot, target.runId) };
    if (failure?.outcome !== "unknown") failure = a; // what may have been delivered outranks what was not
    if (!tryNextSurface(a)) return a.code === SERVER_NOT_TRUSTED ? a : failure;
  }
  return failure ?? { outcome: "not_delivered", code: CUSTODIAN_UNAVAILABLE, detail: "no custodian surface was tried" };
}

/**
 * `askCustodianToEnd` for a run with a local record, which decides nothing: a run the custodian might hold is always
 * asked, and a pending mark goes only with an acknowledgment.
 */
export async function establishCustodianEnd(sel: EvidenceSelection, paths: RunPaths, owner: OwnerRecord, end: PendingEnd, surfaces: readonly CustodianSurface[]): Promise<CustodianEndResult> {
  const r = await askCustodianToEnd(sel, end, surfaces, !locallyProtected(await readState(paths)));
  if (r.outcome === "ended" || r.outcome === "already_ended") {
    await commitState(paths, owner, (cur) => {
      delete cur.custodian_end_pending;
      return cur;
    }).catch(() => undefined);
  }
  return r;
}

/**
 * Bring a protected run's custodian record up to date before new work (contract §5.2): a pending `end` is sent
 * again, and every operation the custodian holds as running whose writer IT sees gone is recovered (`recover`, with
 * the engine's recovery incidents of that operation; the custodian decides from its own process table and refuses
 * while the writer lives). Best effort: whatever the custodian refuses stays as it is — a later `op_begin` is then
 * refused `RUN_BUSY`, never run attended.
 */
export async function reconcileCustodianRun(sel: EvidenceSelection, paths: RunPaths, owner: OwnerRecord): Promise<void> {
  const st = await readState(paths);
  if (st.custodian_end_pending) await endCustodianRun(sel, paths, owner, st.custodian_end_pending);
  let ev: CustodianEvidence | null;
  let section: RunSection | null;
  try {
    ev = await custodianEvidenceFor(sel, st);
    if (!ev) return;
    section = await ev.runSection();
  } catch {
    return;
  }
  const ops = (section?.record?.["operations"] ?? []) as { operationId?: unknown; status?: unknown; writerAlive?: unknown }[];
  for (const o of ops) {
    // P3.4C-5: a review the custodian is capturing or has captured is active too.
    if ((o.status !== "running" && o.status !== "measuring" && o.status !== "captured") || o.writerAlive !== false || typeof o.operationId !== "string") continue;
    const local = st.operations.find((x) => x["custodian_operation_id"] === o.operationId);
    const incidents = local
      ? st.isolation_incidents.filter((i) => i.operation_id === local.operation_id && RECOVER_INCIDENTS.has(i.kind)).slice(0, 10).map((i) => ({ kind: i.kind as "possible_surviving_sandboxed_commands" | "termination_unconfirmed", detail: bounded(i.detail) }))
      : [];
    await ev.transition("recover", { operationId: o.operationId, incidents }, `${o.operationId}-recover`).catch(() => undefined);
  }
}

/** The SHA-256 of a run artifact as it is on disk now (null when the artifact is absent). */
export async function artifactDigest(runDir: string, ref: string | null | undefined): Promise<string | null> {
  if (!ref) return null;
  const bytes = await readFile(resolveArtifact(runDir, ref)).catch(() => null);
  return bytes ? sha256OfBytes(bytes) : null;
}

/** A bounded engine text for a custodian field (control characters are replaced by the custodian). */
export function bounded(text: string | null | undefined, max = 500): string {
  const t = text ?? "";
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
