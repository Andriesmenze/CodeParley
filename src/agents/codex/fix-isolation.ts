// Phase 4 Increment 1 — the fail-closed launch gate for a delegated fixer (contract §5; D-20).
//
// A fixer `codex exec` under the writable `cp_fix` profile may launch ONLY when a stored, complete fix
// self-test (fix-selftest.ts) establishes OS confinement for EXACTLY the Codex binary (SHA-256), version,
// backend and fixer profile structure about to be launched. Anything else — no record, an incomplete run,
// a version / binary / backend / profile mismatch, or a self-test whose confinement rows did not all pass —
// is CODEX_ISOLATION_UNAVAILABLE, and nothing is launched. There is no policy-only fallback and no
// permission relaxation (the write grant never widens to make a backend accept the profile).
//
// This is the writable-fixer counterpart of decideIsolation (isolation.ts) for the read-only reviewer; the
// reviewer path is unchanged.

import { DomainError } from "../../common/errors.js";
import type { FixSelfTestRecord } from "../../schemas/review.js";
import { fixProfileDigest, type FixProfileInput } from "./fix-profile.js";
import type { SandboxBackend } from "./argv.js";

export interface FixIsolationDecisionInput {
  codexVersion: string;
  /** SHA-256 of the exact codex.exe about to be launched (engine's measurement). */
  codexSha256: string;
  backend: SandboxBackend;
  /** The profile about to be launched (its structure digest must match the stored record). */
  profile: FixProfileInput;
  /** The stored fix self-test for this version/binary/backend/profile, or null. */
  record: FixSelfTestRecord | null;
}

export type FixIsolationDecision =
  | { ok: true; record: FixSelfTestRecord }
  | { ok: false; reasons: string[] };

/** Decide whether a delegated fixer may launch. Pure; the caller loads the record. Fail closed. */
export function decideFixIsolation(i: FixIsolationDecisionInput): FixIsolationDecision {
  const reasons: string[] = [];
  const rec = i.record;
  const wantDigest = fixProfileDigest(i.profile);
  if (!rec) {
    reasons.push(`no cp_fix self-test for Codex ${i.codexVersion} (${i.codexSha256.slice(0, 12)}) on ${i.backend}`);
  } else {
    if (!rec.complete) reasons.push(`${i.backend}: the cp_fix self-test did not complete (a probe timed out or could not start); it is not a determination and re-runs`);
    if (rec.codex_version !== i.codexVersion) reasons.push(`${i.backend}: the cp_fix self-test is for Codex ${rec.codex_version}, not ${i.codexVersion}`);
    if (rec.codex_sha256 !== i.codexSha256) reasons.push(`${i.backend}: the cp_fix self-test is bound to a different Codex binary (SHA-256 ${rec.codex_sha256.slice(0, 12)} ≠ ${i.codexSha256.slice(0, 12)})`);
    if (rec.backend !== i.backend) reasons.push(`${i.backend}: the cp_fix self-test is for backend ${rec.backend}`);
    if (rec.profile_digest !== wantDigest) reasons.push(`${i.backend}: the cp_fix self-test is for a different fixer profile (digest ${rec.profile_digest.slice(0, 12)} ≠ ${wantDigest.slice(0, 12)})`);
    if (!rec.profile_runs) reasons.push(`${i.backend}: the cp_fix profile was rejected on this backend (${rec.rejection_reason ?? "unknown reason"})`);
    if (rec.complete && rec.profile_runs && !rec.confinement_available) {
      const failed = rec.rows.filter((r) => !r.pass || r.inconclusive).map((r) => `${r.name}${r.inconclusive ? " (inconclusive)" : ""}`);
      reasons.push(`${i.backend}: the cp_fix self-test did not establish confinement (failed/inconclusive: ${failed.join(", ") || "none passed"})`);
    }
  }
  if (reasons.length > 0) return { ok: false, reasons };
  return { ok: true, record: rec! };
}

/** The refusal a caller raises when the fixer launch gate is not satisfied. */
export function fixIsolationUnavailableError(reasons: readonly string[]): DomainError {
  return new DomainError(
    "CODEX_ISOLATION_UNAVAILABLE",
    `a delegated fixer cannot launch: ${reasons.join("; ")}. Run the cp_fix self-test on the approved Codex installation (code-parley codex fix-selftest) and do not relax the profile.`,
    { retryable: false },
  );
}
