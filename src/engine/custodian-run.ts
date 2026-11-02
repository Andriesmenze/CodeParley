// P3.4C-3: the engine's registration of a run with the CUSTODIAN (run_transition open; contract §3.2, §5.5).
//
// `start_review_loop` registers the run before it consumes a loop: `open` declares the run's frozen declaration —
// the digest of its run.json, the budgets the custodian enforces, and its baseline capture — and needs an operator
// grant with a loop left (nothing is consumed; without one nothing is registered). From then on the run is protected
// for selection (§5.4), yet nothing is authorized until its loop is minted and bound (I4). `open` is idempotent on
// the declaration whatever the request id (I5), so a start retried after a lost answer registers nothing twice; a
// changed declaration is RUN_DECLARATION_CONFLICT and that run can never become protected (a new run is needed).

import { readFile } from "node:fs/promises";
import { DomainError } from "../common/errors.js";
import { sha256OfBytes } from "../common/hash.js";
import { CustodianRuns } from "../custodian/runs.js";
import { custodianError, type RunTransitionFields } from "../custodian/protocol.js";
import type { CustodianTransport } from "../custodian/transport.js";
import { resolveArtifact } from "../store/artifacts.js";
import { commitState, readState } from "../store/state-store.js";
import { runBudgets, type Loaded, type RunHandle } from "./engine-env.js";
import { waitForPrepare } from "./runs.js";

/** How long a start waits for a baseline capture that is still running before it refuses (RUN_BUSY). */
const BASELINE_WAIT_MS = 60_000;

/**
 * The run's declaration (contract §3.2 `open`): the digest of its run.json as written, the effective budgets
 * (configuration lowered by the run's overrides), and its completed baseline capture bound by digest (null: the
 * capture failed or was cancelled — the run has no baseline). A capture still running is waited for, so the
 * declaration is the same on every attempt; one that does not finish in time refuses the start (RUN_BUSY).
 */
export async function runDeclaration(le: Loaded, run: RunHandle): Promise<RunTransitionFields["open"]> {
  const runJson = await readFile(run.paths.runJson);
  let st = await readState(run.paths);
  const running = [...st.operations].reverse().find((o) => o.kind === "prepare" && o.status === "running");
  if (running) {
    // A capture this process owns is awaited through its completion, which takes no signal: the race bounds both.
    const timeout = AbortSignal.timeout(BASELINE_WAIT_MS);
    await Promise.race([
      waitForPrepare(run, running.operation_id, 250, timeout).catch(() => undefined),
      new Promise<void>((resolve) => timeout.addEventListener("abort", () => resolve(), { once: true })),
    ]);
    st = await readState(run.paths);
    if (st.operations.some((o) => o.kind === "prepare" && o.status === "running")) {
      throw new DomainError("RUN_BUSY", "the run's baseline capture is still running; start the loop when it has finished (nothing was registered or consumed)", { retryable: true });
    }
  }
  // Contract §1.3: a run with a running operation is not registered (its evidence would straddle the protection).
  const active = st.operations.find((o) => o.status === "running");
  if (active) throw new DomainError("RUN_BUSY", `the run has a running ${active.kind} operation; start the loop when it has finished (nothing was registered or consumed)`, { retryable: true, details: { operation_id: active.operation_id } });
  const prep = [...st.operations].reverse().find((o) => o.kind === "prepare");
  const outcome = (prep?.status === "completed" ? prep.outcome : undefined) as { baseline_source_id?: unknown; capture_ref?: unknown } | undefined;
  let baseline: RunTransitionFields["open"]["baseline"] = null;
  if (typeof outcome?.baseline_source_id === "string" && typeof outcome.capture_ref === "string") {
    const bytes = await readFile(resolveArtifact(run.paths.runDir, outcome.capture_ref));
    baseline = { sourceId: outcome.baseline_source_id, digest: sha256OfBytes(bytes) };
  }
  const b = runBudgets(le, run.meta);
  // Phase 4 Increment 2: a fix budget is declared only when the configuration allows delegated fixes (an absent maxFixes is
  // none), so a run's declaration is unchanged for a host that does not use them.
  const maxFixes = le.cfg.config.budgets.max_fixes_per_run;
  return { runJsonDigest: sha256OfBytes(runJson), budgets: { maxReviews: b.max_reviews_per_run, maxCheckExecutions: b.max_check_executions_per_run, ...(maxFixes > 0 ? { maxFixes } : {}) }, baseline };
}

/**
 * Register the run with the custodian (implementer surface). Refusals keep their codes: LOOP_NOT_AUTHORIZED (no grant
 * has a loop left; nothing was registered), RUN_TERMINAL (the custodian's record of the run has ended),
 * RUN_DECLARATION_CONFLICT (the run was registered with another declaration). A transport failure is fail-closed and
 * carries its delivery outcome; a retry is safe (idempotent on the declaration).
 */
/** The run's baseline capture record (the prepare's capture), handed to the custodian when it is the one the declaration binds. */
async function holdBaseline(run: RunHandle, runs: CustodianRuns, target: { repositoryRoot: string; runId: string }, digest: string): Promise<void> {
  const st = await readState(run.paths);
  const prep = [...st.operations].reverse().find((o) => o.kind === "prepare" && o.status === "completed");
  const ref = (prep?.outcome as { capture_ref?: unknown } | undefined)?.capture_ref;
  if (typeof ref !== "string") return;
  const bytes = await readFile(resolveArtifact(run.paths.runDir, ref));
  if (sha256OfBytes(bytes) === digest) await runs.holdEvidence("implementer", target, bytes);
}

export async function openCustodianRun(le: Loaded, run: RunHandle, transport: CustodianTransport): Promise<void> {
  const declaration = await runDeclaration(le, run);
  const runs = new CustodianRuns(transport);
  const target = { repositoryRoot: run.meta.repository_root, runId: run.runId };
  const out = await runs.transition("implementer", target, "open", declaration);
  if (out.ok) {
    // Phase 5 F-i2-5: the baseline capture record's bytes, as redaction evidence (best effort: without them the custodian
    // refuses an amendment it would redact rather than redact against less).
    if (declaration.baseline) await holdBaseline(run, runs, target, declaration.baseline.digest).catch(() => undefined);
    // The local hint (§5.4): set once the custodian acknowledged the registration. It only ever adds refusals.
    await commitState(run.paths, le.env.owner, (cur) => {
      cur.run_records_custodian = true;
      return cur;
    });
    return;
  }
  throw custodianError(out.code, out.code === "RUN_DECLARATION_CONFLICT"
    ? `this run was registered with the custodian under another declaration (its run.json, budgets or baseline changed since), so it cannot become protected; automate a new run (${out.message})`
    : out.message);
}
