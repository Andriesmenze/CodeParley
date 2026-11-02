// Verification floor, check selection, freshness and engine-owned check conditions
// (plan §7.2, §7.3, §10.4, §14.5; D-29, MR-D, MR-G). PURE: no I/O, no clock.
//
// Capabilities versus obligations (D-29): tool arguments may SELECT any approved checks to
// run, and may ADD requirements, but can never remove a requirement that trusted
// configuration set. The floor of a run is the union of what was required when the run was
// created and what trusted configuration requires now; a requirement whose definition later
// disappears is reported `removed` (unsatisfiable), never silently dropped.
//
// Freshness is reported per dimension, because "the check ran on this source" and "the
// check ran with this definition and environment" are different claims:
//   source       start == end == current source_id (and both reads stable)
//   spec         the check_spec_id computed now equals the recorded one
//   environment  the effective-environment digest and freshness-input hashes match
// A result is fresh only if all three are. Environment binding is partial by design.
//
// Supersession is engine-owned and has nothing to do with reviewer findings: for each check
// the LATEST conclusive execution that is fresh for the current inputs decides its status,
// so a successful re-run on current inputs supersedes an earlier failure (MR-D), and a
// failure on current inputs supersedes an earlier pass.

import type { CheckExecutionRecord, FloorRequirement, RunVerificationFloor } from "../schemas/checks.js";

// ---------------------------------------------------------------------------
// Inputs describing the trusted configuration now (built by the engine)
// ---------------------------------------------------------------------------

export interface TrustedView {
  /** approved | no_entry | unapproved | approval_invalid | root_commit_mismatch | entry_invalid */
  status: string;
  /** Every defined check name with its current definition digest (null if invalid). */
  defined: ReadonlyMap<string, string | null>;
  /** Names that may run now (entry approved and the check approved). */
  approved: ReadonlySet<string>;
  profiles: Readonly<Record<string, readonly string[]>>;
  requiredProfiles: readonly string[];
  noRequiredChecks: boolean;
  floorConfigured: boolean;
}

/** Current identity parts of one check, computed by the engine at evaluation time. */
export interface CurrentCheckInputs {
  check: string;
  state: "runnable" | "removed" | "unapproved";
  /** The current definition digest (null when removed or invalid). */
  definitionDigest: string | null;
  checkSpecId: string | null;
  envDigest: string | null;
  freshnessDigest: string | null;
  executionInputId: string | null;
}

// ---------------------------------------------------------------------------
// Floor resolution
// ---------------------------------------------------------------------------

export type FloorError = { code: "UNKNOWN_PROFILE" | "CHECK_NOT_APPROVED"; name: string; detail: string };

/** Requirements from trusted configuration alone. Empty unless the entry is approved. */
export function trustedRequirements(t: TrustedView): FloorRequirement[] {
  if (t.status !== "approved") return [];
  const out: FloorRequirement[] = [];
  for (const p of t.requiredProfiles) {
    for (const c of t.profiles[p] ?? []) out.push({ check: c, source: "trusted_config", via: p, definition_digest: t.defined.get(c) ?? null });
  }
  return dedupeRequirements(out);
}

/**
 * The floor fixed at run creation: trusted requirements plus `additional` names (checks or
 * profiles) from the tool call. Additional names must be approved; there is no argument
 * that removes anything.
 */
export function resolveRunFloor(t: TrustedView, additional: readonly string[]): { ok: true; floor: RunVerificationFloor } | { ok: false; errors: FloorError[] } {
  const errors: FloorError[] = [];
  const extra: FloorRequirement[] = [];
  for (const name of additional) {
    if (Object.prototype.hasOwnProperty.call(t.profiles, name)) {
      for (const c of t.profiles[name] ?? []) {
        if (!t.approved.has(c)) errors.push({ code: "CHECK_NOT_APPROVED", name: c, detail: `check ${c} (profile ${name}) is not approved` });
        extra.push({ check: c, source: "run_argument", via: name, definition_digest: t.defined.get(c) ?? null });
      }
    } else if (t.defined.has(name)) {
      if (!t.approved.has(name)) errors.push({ code: "CHECK_NOT_APPROVED", name, detail: `check ${name} is not approved` });
      extra.push({ check: name, source: "run_argument", via: "check", definition_digest: t.defined.get(name) ?? null });
    } else {
      errors.push({ code: "UNKNOWN_PROFILE", name, detail: `no approved check or profile named ${name}` });
    }
  }
  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    floor: {
      required: dedupeRequirements([...trustedRequirements(t), ...extra]),
      no_required_checks: t.status === "approved" && t.noRequiredChecks,
      approval_digest: null,
    },
  };
}

/** The floor in force now: the run's fixed floor ∪ what trusted configuration requires now. */
export function effectiveRequirements(runFloor: RunVerificationFloor | null, t: TrustedView): FloorRequirement[] {
  return dedupeRequirements([...(runFloor?.required ?? []), ...trustedRequirements(t)]);
}

function dedupeRequirements(reqs: readonly FloorRequirement[]): FloorRequirement[] {
  const seen = new Set<string>();
  const out: FloorRequirement[] = [];
  for (const r of reqs) {
    const k = `${r.check}\u0000${r.source}\u0000${r.via}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(r);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Selection for run_checks (a capability: any approved subset)
// ---------------------------------------------------------------------------

export interface SelectionItem {
  check: string;
  /** runnable: will execute; otherwise recorded as skipped with this reason. */
  disposition: "runnable" | "definition_removed" | "approval_invalid";
}

export type SelectionResult = { ok: true; items: SelectionItem[]; usedFloor: boolean } | { ok: false; errors: FloorError[] };

/**
 * Resolve which checks an operation runs. Explicit names must be approved (an error names
 * every problem). With no names, the run's effective floor is used; required checks that
 * were removed or are no longer approved are kept as SKIPPED items so the outcome records
 * them distinctly instead of dropping them.
 */
export function resolveSelection(t: TrustedView, requested: { checks?: readonly string[]; profiles?: readonly string[] }, requirements: readonly FloorRequirement[]): SelectionResult {
  const explicit = (requested.checks?.length ?? 0) + (requested.profiles?.length ?? 0) > 0;
  const order: string[] = [];
  const add = (c: string) => {
    if (!order.includes(c)) order.push(c);
  };
  if (!explicit) {
    for (const r of requirements) add(r.check);
    const items = order.map<SelectionItem>((c) => ({
      check: c,
      disposition: t.approved.has(c) ? "runnable" : t.defined.has(c) ? "approval_invalid" : "definition_removed",
    }));
    return { ok: true, items, usedFloor: true };
  }
  const errors: FloorError[] = [];
  for (const p of requested.profiles ?? []) {
    if (!Object.prototype.hasOwnProperty.call(t.profiles, p)) errors.push({ code: "UNKNOWN_PROFILE", name: p, detail: `no profile named ${p}` });
    else for (const c of t.profiles[p] ?? []) add(c);
  }
  for (const c of requested.checks ?? []) add(c);
  for (const c of order) {
    if (!t.approved.has(c)) errors.push({ code: "CHECK_NOT_APPROVED", name: c, detail: t.defined.has(c) ? `check ${c} is not approved (trusted configuration: ${t.status})` : `no approved check named ${c}` });
  }
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, items: order.map((c) => ({ check: c, disposition: "runnable" as const })), usedFloor: false };
}

// ---------------------------------------------------------------------------
// Freshness of one execution
// ---------------------------------------------------------------------------

export interface ExecutionFreshness {
  fresh: boolean;
  source: "fresh" | "changed" | "unstable" | "unknown";
  spec: "fresh" | "changed" | "removed" | "unapproved" | "unknown";
  environment: "fresh" | "changed" | "unknown";
  reasons: string[];
}

export function evaluateExecutionFreshness(e: CheckExecutionRecord, currentSourceId: string | null, cur: CurrentCheckInputs | undefined): ExecutionFreshness {
  const reasons: string[] = [];
  let source: ExecutionFreshness["source"];
  if (e.source_id_at_start === null || e.source_id_at_end === null) {
    source = "unknown";
    reasons.push("source_identity_missing");
  } else if (!e.source_stable || e.source_id_at_start !== e.source_id_at_end) {
    source = "unstable";
    reasons.push("source_changed_during_execution");
  } else if (currentSourceId === null) {
    source = "unknown";
    reasons.push("current_source_unknown");
  } else if (e.source_id_at_start === currentSourceId) {
    source = "fresh";
  } else {
    source = "changed";
    reasons.push("source_changed");
  }

  let spec: ExecutionFreshness["spec"];
  if (!cur || cur.state === "removed") {
    spec = "removed";
    reasons.push("definition_removed");
  } else if (cur.state === "unapproved") {
    spec = "unapproved";
    reasons.push("approval_invalid");
  } else if (cur.checkSpecId === null || e.check_spec_id === null) {
    spec = "unknown";
    reasons.push("spec_unresolvable");
  } else if (cur.checkSpecId === e.check_spec_id) {
    spec = "fresh";
  } else {
    spec = "changed";
    reasons.push("spec_changed");
  }

  let environment: ExecutionFreshness["environment"];
  if (!cur || cur.envDigest === null || cur.freshnessDigest === null || e.env_digest === null || e.freshness_digest === null) {
    environment = "unknown";
    reasons.push("environment_unknown");
  } else {
    environment = "fresh";
    if (cur.envDigest !== e.env_digest) {
      environment = "changed";
      reasons.push("environment_values_changed");
    }
    if (cur.freshnessDigest !== e.freshness_digest) {
      environment = "changed";
      reasons.push("freshness_inputs_changed");
    }
  }

  const fresh =
    source === "fresh" &&
    spec === "fresh" &&
    environment === "fresh" &&
    !!cur &&
    cur.executionInputId !== null &&
    cur.executionInputId === e.execution_input_id;
  return { fresh, source, spec, environment, reasons };
}

/**
 * Stale ONLY because the deriving process's environment differs from the one the check ran in: the
 * same source, specification and freshness inputs, but another effective-environment digest (PATH
 * and the other variables a check receives). Freshness is judged for the deriving process's own
 * environment, so a process with another environment — an operator terminal, a harness — sees such
 * a result stale where the process that ran the check sees it current (P3.3b).
 */
export function staleOnlyByEnvironment(v: { status: string; freshness: ExecutionFreshness | null }): boolean {
  const f = v.freshness;
  return v.status === "stale" && f !== null && f.source === "fresh" && f.spec === "fresh" && f.environment === "changed" && f.reasons.length > 0 && f.reasons.every((r) => r === "environment_values_changed");
}

// ---------------------------------------------------------------------------
// Floor evaluation and engine conditions
// ---------------------------------------------------------------------------

export type FloorCheckStatus = "satisfied" | "missing" | "stale" | "failed" | "timed_out" | "error" | "cancelled" | "removed" | "unapproved";

export interface CheckStatusView {
  check: string;
  required: boolean;
  required_by: { source: FloorRequirement["source"]; via: string }[];
  status: FloorCheckStatus;
  /** The execution that decided the status (latest fresh conclusive, else latest). */
  execution_id: string | null;
  last_status: CheckExecutionRecord["status"] | null;
  freshness: ExecutionFreshness | null;
  /** Fresh failures on the current inputs that a later fresh execution superseded. */
  superseded_failures: number;
  /** The requirement's definition digest differs from the one fixed at run creation. */
  definition_changed_since_floor: boolean;
}

export interface FloorEvaluation {
  configured: boolean;
  no_required_checks: boolean;
  satisfied_for_current_source: boolean;
  checks: CheckStatusView[];
  missing: string[];
  stale: string[];
  failed: string[];
  timed_out: string[];
  error: string[];
  cancelled: string[];
  removed: string[];
  unapproved: string[];
}

const CONCLUSIVE = new Set<CheckExecutionRecord["status"]>(["passed", "failed", "timed_out"]);

/** Status of one check from its executions (newest last) and its current inputs. */
export function checkStatus(
  check: string,
  executions: readonly CheckExecutionRecord[],
  currentSourceId: string | null,
  cur: CurrentCheckInputs | undefined,
): Omit<CheckStatusView, "required" | "required_by" | "definition_changed_since_floor"> {
  const mine = executions.filter((e) => e.check === check);
  if (!cur || cur.state === "removed") {
    const last = mine.at(-1) ?? null;
    return { check, status: "removed", execution_id: last?.execution_id ?? null, last_status: last?.status ?? null, freshness: null, superseded_failures: 0 };
  }
  if (cur.state === "unapproved") {
    const last = mine.at(-1) ?? null;
    return { check, status: "unapproved", execution_id: last?.execution_id ?? null, last_status: last?.status ?? null, freshness: null, superseded_failures: 0 };
  }
  const withFreshness = mine.map((e) => ({ e, f: evaluateExecutionFreshness(e, currentSourceId, cur) }));
  const freshAll = withFreshness.filter((x) => x.f.fresh);
  const freshConclusive = freshAll.filter((x) => CONCLUSIVE.has(x.e.status));
  const decisive = freshConclusive.at(-1);
  if (decisive) {
    const superseded = freshConclusive.slice(0, -1).filter((x) => x.e.status !== "passed").length;
    const status: FloorCheckStatus = decisive.e.status === "passed" ? "satisfied" : decisive.e.status === "timed_out" ? "timed_out" : "failed";
    return { check, status, execution_id: decisive.e.execution_id, last_status: decisive.e.status, freshness: decisive.f, superseded_failures: decisive.e.status === "passed" ? superseded : 0 };
  }
  // No fresh conclusive evidence. A fresh inconclusive attempt (spawn error, cancelled)
  // explains why; otherwise the latest attempt is stale, or there is none.
  const freshInconclusive = freshAll.filter((x) => x.e.status === "error" || x.e.status === "cancelled").at(-1);
  if (freshInconclusive) {
    return { check, status: freshInconclusive.e.status === "error" ? "error" : "cancelled", execution_id: freshInconclusive.e.execution_id, last_status: freshInconclusive.e.status, freshness: freshInconclusive.f, superseded_failures: 0 };
  }
  const latestRun = withFreshness.filter((x) => x.e.status !== "skipped").at(-1);
  if (latestRun) return { check, status: "stale", execution_id: latestRun.e.execution_id, last_status: latestRun.e.status, freshness: latestRun.f, superseded_failures: 0 };
  return { check, status: "missing", execution_id: null, last_status: mine.at(-1)?.status ?? null, freshness: null, superseded_failures: 0 };
}

export function evaluateFloor(
  floorConfigured: boolean,
  noRequiredChecks: boolean,
  requirements: readonly FloorRequirement[],
  executions: readonly CheckExecutionRecord[],
  currentSourceId: string | null,
  current: ReadonlyMap<string, CurrentCheckInputs>,
): FloorEvaluation {
  const byCheck = new Map<string, FloorRequirement[]>();
  for (const r of requirements) byCheck.set(r.check, [...(byCheck.get(r.check) ?? []), r]);
  const views: CheckStatusView[] = [];
  for (const [check, reqs] of byCheck) {
    const cur = current.get(check);
    const base = checkStatus(check, executions, currentSourceId, cur);
    const nowDigest = cur?.definitionDigest ?? null;
    views.push({
      ...base,
      required: true,
      required_by: reqs.map((r) => ({ source: r.source, via: r.via })),
      definition_changed_since_floor: nowDigest !== null && reqs.some((r) => r.definition_digest !== null && r.definition_digest !== nowDigest),
    });
  }
  const list = (s: FloorCheckStatus) => views.filter((v) => v.status === s).map((v) => v.check);
  const configured = floorConfigured || requirements.length > 0;
  const allSatisfied = views.every((v) => v.status === "satisfied");
  return {
    configured,
    no_required_checks: noRequiredChecks && requirements.length === 0,
    satisfied_for_current_source: configured && currentSourceId !== null && allSatisfied,
    checks: views,
    missing: list("missing"),
    stale: list("stale"),
    failed: list("failed"),
    timed_out: list("timed_out"),
    error: list("error"),
    cancelled: list("cancelled"),
    removed: list("removed"),
    unapproved: list("unapproved"),
  };
}

export interface CheckCondition {
  kind: "check_failed" | "check_stale" | "check_missing";
  check: string;
  required: boolean;
  reason: string;
  detail: string;
  source: "engine";
  execution_id: string | null;
}

/**
 * Engine-owned conditions derived at report time (MR-D): never stored as findings and
 * never resolvable by a reviewer. Required checks that are not satisfied produce one
 * condition each; a fresh failure of an optional (non-required) check is also reported.
 */
export function deriveCheckConditions(floor: FloorEvaluation, optional: readonly CheckStatusView[] = []): CheckCondition[] {
  const out: CheckCondition[] = [];
  for (const v of floor.checks) {
    if (v.status === "satisfied") continue;
    out.push(conditionFor(v, true));
  }
  for (const v of optional) {
    if (v.required) continue;
    if (v.status === "failed" || v.status === "timed_out") out.push(conditionFor(v, false));
  }
  return out;
}

function conditionFor(v: CheckStatusView, required: boolean): CheckCondition {
  const kind: CheckCondition["kind"] =
    v.status === "failed" || v.status === "timed_out" ? "check_failed" : v.status === "stale" ? "check_stale" : "check_missing";
  const why = v.freshness?.reasons.length ? ` (${v.freshness.reasons.join(", ")})` : "";
  const detail =
    v.status === "stale"
      ? `${v.check}: last result (${v.last_status ?? "none"}) is not fresh for the current inputs${why}`
      : v.status === "missing"
        ? `${v.check}: no execution yet`
        : v.status === "removed"
          ? `${v.check}: required check is no longer defined in trusted configuration`
          : v.status === "unapproved"
            ? `${v.check}: required check is not approved (trusted configuration changed or invalid)`
            : `${v.check}: ${v.status} on the current inputs`;
  return { kind, check: v.check, required, reason: v.status, detail, source: "engine", execution_id: v.execution_id };
}

// ---------------------------------------------------------------------------
// Removed tests (plan §14.5 item 2)
// ---------------------------------------------------------------------------

export interface ChangeLike {
  path: string;
  status: string;
  old_path?: string;
  confidential: boolean;
}

export interface TestsRemoved {
  /** Model-safe paths (confidential paths are never named, MR-F). */
  paths: string[];
  confidential_count: number;
}

/**
 * Test files (matching the approved `test_globs`) deleted or renamed away in a change set.
 * A passing check cannot speak for tests that no longer exist; skipped tests INSIDE files
 * are not detected in M1. `isTestPath` is the compiled test-glob matcher.
 */
export function testsRemoved(changes: readonly ChangeLike[], isTestPath: (path: string) => boolean): TestsRemoved {
  const paths: string[] = [];
  let confidential = 0;
  for (const c of changes) {
    const gone =
      (c.status === "deleted" && isTestPath(c.path)) ||
      (c.status === "renamed" && c.old_path !== undefined && isTestPath(c.old_path) && !isTestPath(c.path));
    if (!gone) continue;
    if (c.confidential) confidential++;
    else paths.push(c.status === "renamed" ? c.old_path! : c.path);
  }
  return { paths: paths.sort(), confidential_count: confidential };
}
