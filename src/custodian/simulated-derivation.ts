// P3.4C-5 Increment 3 (contract §4, §5): the simulated custodian's measured check inputs and protected derivation — a
// mirror of custodian/…/Ledger/GrantLedger.Checks.cs and GrantLedger.Derivation.cs, held to the same shared corpus. The
// snapshot is built field for field as the custodian builds it; the measurement is the engine's own (in process, the
// helper's code) or the corpus's synthetic one; the derivation is the engine's pure protected derivation.

import { createHash } from "node:crypto";
import { sha256OfCanonicalJson } from "../common/hash.js";
import type { SimLoop } from "./simulated-loops.js";
import { SimLoopRefusal } from "./simulated-loops.js";
import { currentOf, reviewBasisProblem, type SimConfigFile, type SimRepositoryConfig } from "./simulated-config.js";
import type { SimRun, SimRunOperation } from "./simulated-runs.js";

type Rec = Record<string, unknown>;

/** §5.2: how long a derivation may authorize a continuation or a wake (it must also still match every revision). */
export const SIM_DERIVATION_TTL_MS = 120_000;
const REPLY_SEEKING: ReadonlySet<string> = new Set(["disputed", "fix_claimed"]);

/** The identities an execution claim carries that the custodian measures or computes itself (N5-2). */
export const MEASURED_EXECUTION_KEYS = ["sourceIdAtStart", "sourceIdAtEnd", "sourceStable", "freshnessDigest", "checkSpecId", "executionInputId"] as const;

/** One reserved check measurement (CheckTicket): a checks operation's start, or one execution's end. */
export interface SimCheckTicket {
  ticket: string;
  kind: "start" | "end";
  repoKey: string;
  runId: string;
  operationId: string;
  workload: Rec;
}

/** How a measurement ended (MeasureOutcome). */
export interface SimMeasureOutcome {
  ok: boolean;
  code: string | null;
  detail: string | null;
  measured: Rec | null;
  derivation: Rec | null;
  /** Phase 5 F-i2-5: a redaction the workload asked for (MeasureOutcome.Redaction). */
  redaction?: Rec | null;
}

/** One cached derivation (DerivationEntry). */
export interface SimDerivationEntry {
  derivationId: string;
  repoKey: string;
  runId: string;
  atMs: number;
  revision: Rec;
  routeKind: string;
  routeCode: string;
  fingerprint: string;
  inputDigest: string;
  measuredDigest: string;
  workload: Rec;
  section: Rec;
  /** The repository the custodian validated (where a re-measurement runs). */
  canonicalRoot: string;
}

const clone = <T>(v: T): T => (v === undefined ? (null as T) : structuredClone(v));
const iso = (ms: number): string => new Date(ms).toISOString();
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : null) as string) : []);

// ---- the revision vector and the snapshot (§5.1, §A.5) ----

export interface SimDerivationState {
  runs: Record<string, SimRun>;
  loops: SimLoop[];
  config: SimConfigFile;
  userLog: (repoKey: string, runId: string) => { revision: number; recoveredAtRevision: number | null; records: Rec[] } | null;
  configSection: (repoKey: string) => Rec;
  /** Phase 4 Increment 2: the custodian's clock when it builds the snapshot (a proposal past its lifetime is reported
   * `expired`). */
  nowMs?: number;
}

/** Phase 4 Increment 2 (GrantLedger.Derivation.cs SnapshotOperationStatus): an operation's status as the snapshot reports it
 * — a proposal that is retired or past its lifetime is `expired` (no longer pending confirmation). */
export function snapshotOperationStatus(o: SimRun["operations"][number], nowMs: number): string {
  if (o.kind !== "fix" || o.status !== "proposed") return o.status;
  const p = (o.outcome?.["proposal"] ?? null) as Rec | null;
  return !p || p["retiredAt"] != null || Date.parse(String(p["expiresAt"])) <= nowMs ? "expired" : o.status;
}

/** The revisions a derivation depends on (RevisionVector). */
export function revisionVector(s: SimDerivationState, repoKey: string, run: SimRun | null, runId: string): Rec {
  const loop = s.loops.find((l) => l.repoKey === repoKey && l.runId === runId) ?? null;
  const cur = currentRepository(s.config, repoKey);
  return {
    runRevision: run?.runRevision ?? null,
    loopRevision: loop?.loopRevision ?? null,
    evidenceEpoch: run?.evidenceEpoch ?? null,
    configRevision: cur?.configRevision ?? null,
    globalRevision: s.config.globalRevision,
    userRevision: s.userLog(repoKey, runId)?.revision ?? 0,
  };
}

const currentRepository = currentOf;

const nonSkipped = (run: SimRun): number => run.checkExecutions.filter((e) => e["status"] !== "skipped").length;

/** The custodian's held records of the run, SCRUBBED to what the protected derivation consumes (DerivationSnapshot). */
export function derivationSnapshot(s: SimDerivationState, canonicalRoot: string, run: SimRun, runFloor: unknown, limits: { maxReviews: number; maxCheckExecutions: number }): Rec {
  const loop = s.loops.find((l) => l.repoKey === run.repoKey && l.runId === run.runId) ?? null;
  const users = s.userLog(run.repoKey, run.runId);
  const dispositions = new Map(run.responses.map((r) => [String(r["responseId"]), (r["disposition"] ?? null) as string | null]));
  const executables: Record<string, string> = {};
  for (const o of run.operations.filter((x) => x.kind === "checks")) {
    for (const p of (o.begin["planned"] as Rec[] | undefined) ?? []) if (typeof p["executable"] === "string") executables[String(p["check"])] = p["executable"] as string;
  }
  const sortedExecutables = Object.fromEntries(Object.keys(executables).sort().map((k) => [k, executables[k]!]));

  const presented = (r: SimRun["reviews"][number]): Rec | null => {
    const p = (r.outcome?.["presented"] ?? null) as Rec | null;
    if (!p) return null;
    const discussion = (p["discussion"] ?? {}) as Rec;
    const deliveries: Rec[] = [];
    if (Array.isArray(discussion["deliveries"])) {
      for (const d of discussion["deliveries"] as Rec[]) deliveries.push({ responseId: clone(d["responseId"]), itemId: clone(d["itemId"]), replySought: clone(d["replySought"]), basis: strs(d["basis"]) });
    } else {
      for (const d of (discussion["delivered"] as Rec[] | undefined) ?? []) {
        for (const rid of (d["responseIds"] as string[] | undefined) ?? []) deliveries.push({ responseId: rid, itemId: clone(d["itemId"]), replySought: REPLY_SEEKING.has(dispositions.get(rid) ?? ""), basis: [] });
      }
    }
    const amendments = (p["amendments"] ?? {}) as Rec;
    return { deliveries, amendments: ((amendments["presented"] as Rec[] | undefined) ?? []).map((a) => (a["amendmentId"] ?? null) as string | null), withheld: strs(amendments["withheld"]) };
  };
  const bindings = (r: SimRun["reviews"][number]): Rec | null => {
    const b = r.begin;
    const hex = ["sourceId", "reviewInputId", "checkEvidenceDigest", "manifestDigest", "exportDigest", "captureDigest"];
    if (hex.some((k) => typeof b[k] !== "string" || (b[k] as string).length !== 64) || typeof b["captureStable"] !== "boolean" || !Array.isArray(b["checkExecutionIds"])) return null;
    return {
      sourceId: b["sourceId"], reviewInputId: b["reviewInputId"], checkEvidenceDigest: b["checkEvidenceDigest"], checkResultsDigest: clone(b["checkResultsDigest"]) ?? null,
      checkExecutionIds: strs(b["checkExecutionIds"]), captureStable: b["captureStable"], manifestDigest: b["manifestDigest"], exportDigest: b["exportDigest"], captureDigest: b["captureDigest"],
    };
  };
  const repository = currentRepository(s.config, run.repoKey) ? ((clone(s.configSection(run.repoKey)["repository"]) ?? null) as Rec | null) : null;
  const n = (v: unknown): unknown => (v === undefined ? null : clone(v));
  return {
    schema: "arl.derivation-snapshot.v2",
    repositoryRoot: canonicalRoot,
    revision: revisionVector(s, run.repoKey, run, run.runId),
    run: {
      status: run.status,
      evidenceEpoch: run.evidenceEpoch,
      used: { reviews: run.reviews.length, checkExecutions: nonSkipped(run) },
      limits: { maxReviews: limits.maxReviews, maxCheckExecutions: limits.maxCheckExecutions },
      operations: run.operations.map((o) => ({
        operationId: o.operationId, kind: o.kind, status: snapshotOperationStatus(o, s.nowMs ?? Date.now()), beganAt: o.beganAt, endedAt: o.endedAt,
        planned: o.kind === "checks" ? ((o.begin["planned"] as Rec[] | undefined) ?? []).map((p) => (p["check"] ?? null) as string | null) : [],
      })),
      checkExecutions: run.checkExecutions.map((e) => ({
        executionId: n(e["executionId"]), operationId: n(e["operationId"]), check: n(e["check"]), status: n(e["status"]),
        exitCode: n(e["exitCode"]), timedOut: n(e["timedOut"]), cancelled: n(e["cancelled"]), durationMs: n(e["durationMs"]),
        definitionDigest: n(e["definitionDigest"]), checkSpecId: n(e["checkSpecId"]), envDigest: n(e["envDigest"]),
        freshnessDigest: n(e["freshnessDigest"]), executionInputId: n(e["executionInputId"]),
        sourceIdAtStart: n(e["sourceIdAtStart"]), sourceIdAtEnd: n(e["sourceIdAtEnd"]), sourceStable: n(e["sourceStable"]),
        evidenceEpoch: e["evidenceEpoch"] ?? run.evidenceEpoch,
      })),
      reviews: run.reviews.map((r) => ({
        reviewId: r.reviewId, operationId: r.operationId, round: r.round, accepted: r.accepted,
        notAcceptedReasons: [...r.notAcceptedReasons], evidenceEpoch: r.evidenceEpoch,
        status: n(r.outcome?.["status"]), verdict: n(r.outcome?.["verdict"]),
        basisUsable: reviewBasisProblem(s.config, run.repoKey, run.operations.find((o) => o.operationId === r.operationId)?.pin) === null,
        isolationMode: n((r.begin["isolation"] as Rec | undefined)?.["mode"]),
        bindings: bindings(r),
        exportIntact: typeof r.begin["custodianCapture"] === "object" && r.begin["custodianCapture"] !== null && ((r.outcome?.["exportRehash"] as Rec | undefined)?.["unchanged"] === true),
        itemIds: [...r.itemIds],
        presented: presented(r),
      })),
      items: run.items.map((i) => ({
        itemId: i.itemId, reviewId: i.reviewId, round: i.round, sourceId: i.sourceId, itemKind: i.itemKind, status: i.status,
        triage: i.triage, severity: i.severity, claimType: i.claimType, category: i.category, confidence: i.confidence,
        impacts: [...i.impacts], relatedPriorId: i.relatedPriorId, relatedFindingId: i.relatedFindingId,
        supersedes: [...i.supersedes], supersededBy: i.supersededBy, restates: [...i.restates],
        assessments: i.assessments.map((a) => ({ reviewId: a.reviewId, round: a.round, sourceId: a.sourceId, assessment: a.assessment, effect: a.effect })),
      })),
      responses: run.responses.map((r) => {
        const a = (r["answers"] ?? {}) as Rec;
        return {
          responseId: n(r["responseId"]), responseSetId: n(r["responseSetId"]), itemId: n(r["itemId"]), disposition: n(r["disposition"]),
          textWithheld: n(r["textWithheld"]),
          answers: { reviewId: n(a["reviewId"]), round: n(a["round"]), runReviewId: n(a["runReviewId"]), runRound: n(a["runRound"]), reviewerReplyId: n(a["reviewerReplyId"]) },
          sourceId: n(r["sourceId"]), supersedes: n(r["supersedes"]), threadId: n(r["threadId"]),
          referenceKeys: strs(r["referenceKeys"]),
          rationalePresent: typeof r["rationalePresent"] === "boolean" ? r["rationalePresent"] : true,
        };
      }),
      replies: run.replies.map((r) => ({
        replyId: n(r["replyId"]), reviewId: n(r["reviewId"]), round: n(r["round"]), itemId: n(r["itemId"]), stance: n(r["stance"]),
        newInformation: n(r["newInformation"]), answersResponseId: n(r["answersResponseId"]), assessment: n(r["assessment"]),
      })),
      incidents: run.incidents.map((i) => ({ incidentId: i.incidentId, kind: i.kind, reviewId: i.reviewId, operationId: i.operationId })),
    },
    loop: loop ? { status: loop.status, startedAt: loop.startedAt, resumedAt: loop.resumedAt } : null,
    user: { governed: users !== null, revision: users?.revision ?? 0, recoveredAtRevision: users?.recoveredAtRevision ?? null, records: users?.records ?? [] },
    config: { globalRevision: s.config.globalRevision, repository, acceptances: [], selftestConfirmations: [] },
    runFloor: runFloor === undefined ? null : clone(runFloor),
    executables: sortedExecutables,
  };
}

/** The checks a derivation measures (DerivationChecks): every held check and every executed one with a held definition. */
export function derivationChecks(run: SimRun, cfg: SimRepositoryConfig | null, executables: Rec): Rec[] {
  const names = new Set<string>();
  if (cfg) for (const n of Object.keys(cfg.checks)) names.add(n);
  for (const e of run.checkExecutions) if (typeof e["check"] === "string") names.add(e["check"] as string);
  return [...names]
    .sort(ordinal)
    .filter((n) => cfg !== null && cfg.checks[n] !== undefined)
    .map((n) => ({ name: n, definition: clone(cfg!.checks[n]!.definition), definitionDigest: cfg!.checks[n]!.definitionDigest, executable: (executables[n] ?? null) as string | null }));
}

const ordinal = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export function rulesJson(cfg: SimRepositoryConfig): Rec {
  const r = cfg.captureRules;
  return { exclude_globs: [...r.excludeGlobs], context_include: [...r.contextInclude], max_file_bytes: r.maxFileBytes, max_export_bytes: r.maxExportBytes, max_diff_bytes: r.maxDiffBytes };
}

/** A checks operation's measurement workload (CheckWorkload). */
export function checkWorkload(cfg: SimRepositoryConfig, begin: Rec): Rec {
  const checks: Rec[] = [];
  for (const p of [...((begin["planned"] as Rec[] | undefined) ?? [])].sort((a, b) => ordinal(String(a["check"]), String(b["check"])))) {
    if (p["definitionDigest"] === null || p["definitionDigest"] === undefined) continue;
    const name = String(p["check"]);
    const c = cfg.checks[name];
    if (!c) continue;
    checks.push({ name, definition: clone(c.definition), definitionDigest: c.definitionDigest, executable: (p["executable"] ?? null) as string | null });
  }
  return { rules: rulesJson(cfg), checks, snapshot: null };
}

/** A measurement as the custodian accepts it (MeasuredProblem); null when acceptable. */
export function measuredProblem(m: Rec | null, requested: readonly Rec[]): string | null {
  const hex = (v: unknown): boolean => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  if (!m || !hex(m["sourceId"]) || typeof m["stable"] !== "boolean" || !Array.isArray(m["checks"])) return "a malformed measurement";
  if (m["rootCommit"] !== null && m["rootCommit"] !== undefined && typeof m["rootCommit"] !== "string") return "a malformed root commit";
  const want = requested.map((c) => String(c["name"]));
  const got = (m["checks"] as Rec[]).map((c) => c["name"]);
  if (got.length !== want.length || got.some((g, i) => g !== want[i])) return "the measurement does not cover exactly the requested checks";
  for (const c of m["checks"] as Rec[]) {
    if (!(c["freshnessDigest"] === null || hex(c["freshnessDigest"])) || !(c["checkSpecId"] === null || hex(c["checkSpecId"]))) return `a malformed measurement of check ${String(c["name"])}`;
  }
  return null;
}

export const measuredDigest = (m: Rec): string => sha256OfCanonicalJson(m);

// ---- the measured execution (§4) ----

export function measurementRecord(measured: Rec, ticket: string, nowMs: number): Rec {
  return { ...clone(measured), ticket, at: iso(nowMs) };
}

/** An execution as the custodian records it (MeasuredExecution). */
export function measuredExecution(run: SimRun, op: SimRunOperation, claim: Rec, start: Rec | null, end: Rec | null, failure: string | null, endTicket: string | null, nowMs: number): { stored: Rec; mismatched: string[] } {
  const s: Rec = clone(claim);
  const check = String(s["check"]);
  const mc = ((start?.["checks"] as Rec[] | undefined) ?? []).find((c) => c["name"] === check) ?? null;
  const startSource = (start?.["sourceId"] ?? null) as string | null;
  const endSource = (end?.["sourceId"] ?? null) as string | null;
  s["sourceIdAtStart"] = startSource;
  s["sourceIdAtEnd"] = endSource;
  s["sourceStable"] = start !== null && end !== null && start["stable"] === true && end["stable"] === true && startSource === endSource;
  const freshness = (mc?.["freshnessDigest"] ?? null) as string | null;
  const spec = (mc?.["checkSpecId"] ?? null) as string | null;
  const env = (claim["envDigest"] ?? null) as string | null;
  s["freshnessDigest"] = freshness;
  s["checkSpecId"] = spec;
  s["executionInputId"] = spec !== null && env !== null && freshness !== null ? sha256OfCanonicalJson({ schema: "arl.execution-input-id.v1", check_spec_id: spec, env_digest: env, freshness_digest: freshness }) : null;
  s["operationId"] = op.operationId;
  s["evidenceEpoch"] = run.evidenceEpoch;
  s["configRevision"] = op.pin?.configRevision ?? null;
  s["custodianMeasurement"] = { startTicket: (start?.["ticket"] ?? null) as string | null, endTicket, measuredAt: iso(nowMs), endMeasured: end !== null, failure };
  if (failure !== null && Array.isArray(s["limitations"])) {
    const lim = s["limitations"] as Rec[];
    if (lim.length >= 20) lim.pop();
    lim.push({ code: "custodian_end_measurement_failed", detail: `the custodian could not measure the source after this execution (${failure}); it does not count as fresh` });
  }
  // Phase 6 Increment 3: the helper's own reason it measured no check-spec identity (GrantLedger.Checks.cs HelperProblemDetail).
  const helperProblem = (mc?.["problem"] ?? null) as string | null;
  if (helperProblem !== null && Array.isArray(s["limitations"])) {
    const lim = s["limitations"] as Rec[];
    if (lim.length >= 20) lim.pop();
    lim.push({ code: `helper_${helperProblem}`, detail: helperProblemDetail(helperProblem) });
  }
  const mismatched = MEASURED_EXECUTION_KEYS.filter((k) => sha256OfCanonicalJson(claim[k] ?? null) !== sha256OfCanonicalJson(s[k] ?? null));
  return { stored: s, mismatched };
}

/** What the helper's measurement problem means (GrantLedger.Checks.cs HelperProblemDetail, kept identical). */
export function helperProblemDetail(problem: string): string {
  switch (problem) {
    case "executable_unresolvable":
      return "the custodian's helper could not resolve this check's executable to an absolute file it can read (it runs under its own account, without your PATH): name the executable by an absolute path outside your user profile, approve the checks again and set the configuration again; this execution does not count as fresh";
    case "no_executable_claim":
      return "the check's executable was not resolved when it ran, so the helper had nothing to measure; this execution does not count as fresh";
    case "definition_invalid":
      return "the helper refused the check definition the custodian holds; approve the checks again and set the configuration again; this execution does not count as fresh";
    default:
      return `the helper measured no check-spec identity (${problem}); this execution does not count as fresh`;
  }
}

/** A skipped execution (SkippedExecution): nothing ran, nothing is measured. */
export function skippedExecution(run: SimRun, op: SimRunOperation, claim: Rec): Rec {
  const latest = (op.measured?.["sourceId"] ?? null) as string | null;
  return { ...clone(claim), sourceIdAtStart: latest, sourceIdAtEnd: latest, sourceStable: false, freshnessDigest: null, checkSpecId: null, executionInputId: null, operationId: op.operationId, evidenceEpoch: run.evidenceEpoch, configRevision: op.pin?.configRevision ?? null };
}

/** A pending execution recorded without its end (RecordUnmeasuredPending). */
export function recordUnmeasuredPending(run: SimRun, op: SimRunOperation, reason: string, nowMs: number): SimRun {
  if (!op.pending) return run;
  const { stored } = measuredExecution(run, op, op.pending["execution"] as Rec, op.measured ?? null, null, reason, (op.pending["ticket"] ?? null) as string | null, nowMs);
  return { ...run, checkExecutions: [...run.checkExecutions, stored], operations: run.operations.map((o) => (o.operationId === op.operationId ? { ...op, pending: null } : o)) };
}

export function measurementReason(code: string | null): string {
  switch (code) {
    case "MEASUREMENT_TIMEOUT":
      return "measurement_timeout";
    case "MEASUREMENT_CANCELLED":
      return "cancelled";
    case "CONFIG_MISMATCH":
      return "runtime_changed";
    case "HELPER_UNAVAILABLE":
      return "helper_unavailable";
    default:
      return "measurement_failed";
  }
}

// ---- enforcement (§5.2, N5-17) ----

/** The derivation rules a continuation or wake must meet (RequireUsableDerivation). */
export function requireCurrentDerivation(cache: ReadonlyMap<string, SimDerivationEntry>, repoKey: string, runId: string, derivationId: string | undefined, currentRevision: Rec, nowMs: number): SimDerivationEntry {
  if (!derivationId) throw new SimLoopRefusal("DERIVATION_STALE", "no custodian derivation is named: read the run's derivation section (list_user_records, sections [derivation]) and name its derivationId");
  const d = cache.get(derivationId);
  if (!d || d.repoKey !== repoKey || d.runId !== runId) throw new SimLoopRefusal("DERIVATION_STALE", "the custodian holds no such derivation of this run (it may have expired, or the custodian restarted); derive again");
  if (nowMs - d.atMs > SIM_DERIVATION_TTL_MS) throw new SimLoopRefusal("DERIVATION_STALE", `the derivation is older than ${SIM_DERIVATION_TTL_MS / 1000} s; derive again`);
  if (sha256OfCanonicalJson(d.revision) !== sha256OfCanonicalJson(currentRevision)) throw new SimLoopRefusal("DERIVATION_STALE", "a custodian record of the run changed since the derivation (run, loop, configuration or user records); derive again");
  return d;
}

/** §5.2, once the derivation is known current (RequireRouteAndProgress): an implementer-step route, and moved progress. */
export function requireRouteAndProgress(d: SimDerivationEntry, loop: SimLoop): void {
  if (d.routeKind !== "implementer_step") throw new SimLoopRefusal("ROUTE_NOT_IMPLEMENTER_STEP", `the custodian's derivation routes ${d.routeCode} (${d.routeKind}), not an implementer step: nothing is spent; the loop pauses or ends as the route says`);
  if (loop.progress?.fingerprint === d.fingerprint) {
    throw new SimLoopRefusal("NO_PROGRESS", `no work fact changed since the loop's previous ${loop.progress.kind.replace("_", " ")} (the same progress fingerprint): nothing is spent; the loop pauses (no_progress)`);
  }
}

/** The re-measurement must equal the derivation's (RequireSameMeasurement, N5-17). */
export function requireSameMeasurement(d: SimDerivationEntry, measured: Rec | null): void {
  if (measured === null) throw new SimLoopRefusal("DERIVATION_STALE", "the custodian could not measure the source and the checks' inputs again before granting it; derive again");
  if (measuredDigest(measured) !== d.measuredDigest) throw new SimLoopRefusal("DERIVATION_STALE", "the working tree or a check's inputs changed since the derivation (the custodian's re-measurement differs); derive again");
}

// ---- the corpus's synthetic measurement (mirrors CaptureFixture.SyntheticMeasurementRunner) ----

export interface SimSyntheticMeasurement {
  sourceId?: string;
  stable?: boolean;
  fail?: "timeout" | "helper" | "runtime" | "cancelled";
  routeKind?: string;
  routeCode?: string;
  fingerprint?: string;
  freshness?: Record<string, string>;
}

const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
export const syntheticFreshnessOf = (check: string): string => sha256(`synthetic-freshness:${check}`);
export const syntheticSpecOf = (check: string): string => sha256(`synthetic-spec:${check}`);
export const SYNTHETIC_SOURCE = "a".repeat(64);

/** The synthetic measurement (and, with a snapshot, derivation) of a workload. */
export function syntheticMeasure(workload: Rec, spec: SimSyntheticMeasurement = {}): SimMeasureOutcome {
  const fails: Record<string, [string, string]> = {
    timeout: ["MEASUREMENT_TIMEOUT", "synthetic: the helper did not finish"],
    helper: ["MEASUREMENT_FAILED", "synthetic: the workload failed"],
    runtime: ["CONFIG_MISMATCH", "synthetic: the engine runtime differs from the one approved"],
    cancelled: ["MEASUREMENT_CANCELLED", "synthetic: cancelled"],
  };
  if (spec.fail) {
    const [code, detail] = fails[spec.fail]!;
    return { ok: false, code, detail, measured: null, derivation: null };
  }
  const source = spec.sourceId ?? SYNTHETIC_SOURCE;
  const stable = spec.stable ?? true;
  const checks = ((workload["checks"] as Rec[] | undefined) ?? []).map((c) => {
    const name = String(c["name"]);
    const exe = (c["executable"] ?? null) as string | null;
    return { name, freshnessDigest: spec.freshness?.[name] ?? syntheticFreshnessOf(name), executable: exe === null ? null : { path: exe, kind: "native", size: 1, mtimeMs: 1 }, checkSpecId: syntheticSpecOf(name), problem: null };
  });
  const measured: Rec = { sourceId: source, stable, rootCommit: null, checks };
  let derivation: Rec | null = null;
  const snap = (workload["snapshot"] ?? null) as Rec | null;
  if (snap) {
    const run = (snap["run"] ?? null) as Rec | null;
    const arr = (v: unknown): Rec[] => (Array.isArray(v) ? (v as Rec[]) : []);
    const fingerprint = spec.fingerprint ?? sha256OfCanonicalJson({
      source: stable ? source : null,
      executions: arr(run?.["checkExecutions"]).map((e) => [e["check"] ?? null, e["executionInputId"] ?? null, e["status"] ?? null]),
      items: arr(run?.["items"]).map((i) => [i["itemId"] ?? null, i["status"] ?? null, i["triage"] ?? null]),
      responses: arr(run?.["responses"]).map((r) => [r["itemId"] ?? null, r["disposition"] ?? null]),
      reviews: arr(run?.["reviews"]).filter((r) => r["accepted"] === true).map((r) => [((r["bindings"] as Rec | null)?.["reviewInputId"] ?? null), r["verdict"] ?? null]),
      user: arr((snap["user"] as Rec | undefined)?.["records"]).map((u) => [u["recordId"] ?? null, u["kind"] ?? null]),
    });
    const kind = spec.routeKind ?? "implementer_step";
    derivation = {
      schema: "arl.protected-derivation.v1",
      completion: { state: kind === "end" ? "ready" : "needs_implementer", ready: kind === "end", blockers: [], counts: {} },
      route: { code: spec.routeCode ?? "address_findings", kind, reason: "synthetic" },
      floor: null,
      currentSourceId: stable ? source : null,
      progressFingerprint: fingerprint,
      inputDigest: sha256OfCanonicalJson({ snapshot: snap, measured }),
    };
  }
  // Phase 5 F-i2-5 (SyntheticMeasurementRunner): a synthetic redaction withholds the word "confidential".
  const rq = (workload["redact"] ?? null) as Rec | null;
  const redaction: Rec | null = rq
    ? stable
      ? { ok: true, redacted: String(rq["text"] ?? "").split("confidential").join("[withheld]"), sourceId: source, redactions: 0 }
      : { ok: false, error: "the working tree changed while it was being read" }
    : null;
  return { ok: true, code: null, detail: null, measured, derivation, ...(redaction ? { redaction } : {}) };
}
