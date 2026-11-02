// Host-facing views of the engine's operation results (plan §11.3–§11.5; M1.5). Field
// selection only — the engine computed everything. What is deliberately absent:
//  - check stdout/stderr and their tails (M1.4-1: check output is a separate
//    confidentiality channel; repository code can print anything it can read). Byte counts
//    and truncation stay; the logs stay in the local run store;
//  - local paths, process command lines and raw Codex output (they stay in the run store).

import type { CancellationRecord } from "../schemas/review.js";
import type { ChecksOperationResult } from "./checks-operation.js";
import type { ReviewOperationResult } from "./review-operation.js";
import type { PrepareResult } from "./runs.js";
import { compactIncident } from "./status.js";

export const CHECK_OUTPUT_NOTE =
  "Check stdout/stderr are kept in the local run store and are not returned through MCP (they can contain anything the check's code could read). Re-run the command yourself to see its output.";

export function checksResultView(r: ChecksOperationResult) {
  return {
    summary: r.summary,
    operation_id: r.operation_id,
    operation_status: r.operation_status,
    status: r.status,
    execution_ids: r.execution_ids,
    results: r.results.map((x) => ({
      check: x.check,
      execution_id: x.execution_id,
      status: x.status,
      skip_reason: x.skip_reason,
      error: x.error,
      check_spec_id: x.check_spec_id,
      execution_input_id: x.execution_input_id,
      exit_code: x.exit_code,
      duration_ms: x.duration_ms,
      stdout_bytes: x.stdout_bytes,
      stderr_bytes: x.stderr_bytes,
      output_truncated: x.truncated,
      source_stable: x.source_stable,
    })),
    output_note: CHECK_OUTPUT_NOTE,
    source_id_at_start: r.source_id_at_start,
    source_id_at_end: r.source_id_at_end,
    stable: r.stable,
    floor: floorView(r.floor),
    conditions: r.conditions,
    limitations: r.limitations,
    budgets: r.budgets,
    cancellation: cancellationView(r.cancellation),
  };
}

export function floorView(f: ChecksOperationResult["floor"]) {
  return {
    configured: f.configured,
    satisfied_for_current_source: f.satisfied_for_current_source,
    missing: f.missing,
    stale: f.stale,
    failed: [...f.failed, ...f.timed_out],
    removed: f.removed,
    unapproved: f.unapproved,
    checks: f.checks.map((c) => ({ check: c.check, status: c.status, last_status: c.last_status, execution_id: c.execution_id, required_by: c.required_by })),
  };
}

export function cancellationView(c: CancellationRecord | null) {
  return c ? { outcome: c.outcome, requested_at: c.requested_at, detail: c.detail, survivors: c.survivors, unattributable: c.unattributable } : null;
}

export function reviewResultView(r: ReviewOperationResult) {
  return {
    summary: r.summary,
    operation_id: r.operation_id,
    operation_status: r.operation_status,
    review_id: r.review_id,
    round: r.round,
    status: r.status,
    failure: r.failure,
    deduplicated: r.deduplicated,
    source_id: r.source_id,
    review_input_id: r.review_input_id,
    freshness: r.freshness ? { source: r.freshness.source, inputs: r.freshness.check_evidence, current: r.freshness.current, stale_reasons: r.freshness.stale_reasons } : null,
    freshness_at_completion: r.freshness_at_completion ? { source: r.freshness_at_completion.source, inputs: r.freshness_at_completion.check_evidence, current: r.freshness_at_completion.current, stale_reasons: r.freshness_at_completion.stale_reasons } : null,
    accepted: r.accepted,
    not_accepted_reasons: r.not_accepted_reasons,
    current_review_id: r.current_review_id,
    effective_isolation: r.effective_isolation,
    verdict: r.verdict,
    assessment: r.assessment,
    findings: r.findings,
    prior_items: r.prior_items,
    open_findings: r.open_findings,
    conditions: r.conditions,
    incidents: r.incidents.map(compactIncident),
    questions: r.questions,
    suggestions: r.suggestions,
    positive_observations: r.positive_observations,
    context_requests: r.context_requests,
    coverage: r.coverage,
    limitations: r.limitations,
    policy_notes: r.policy_notes,
    reviewer: r.reviewer,
    cancellation: cancellationView(r.cancellation),
    budgets: r.budgets,
    discussion: r.discussion,
    amendments: r.amendments,
  };
}

export function prepareResultView(p: PrepareResult) {
  return {
    summary:
      p.status === "completed"
        ? `baseline captured (source ${p.baseline_source_id?.slice(0, 12)}); ${p.limitations.length} limitation(s)`
        : `baseline capture ${p.status}${p.failure ? `: ${p.failure.code}: ${p.failure.detail.slice(0, 200)}` : ""}; target since_baseline is unavailable for this run`,
    operation_id: p.operation_id,
    status: p.status,
    baseline_source_id: p.baseline_source_id,
    limitations: p.limitations,
    failure: p.failure,
    cancellation: cancellationView(p.cancellation),
  };
}
