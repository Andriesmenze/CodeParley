// Effective isolation decision (plan §12.2, D-25; Gate A §1.7). Fail closed.
//
//  - S1 (reads restricted to the export + Codex install + minimal system paths, no writes,
//    OS-enforced network blocking) is available on a backend only when the stored self-test
//    of EXACTLY the production profile on that backend, for the installed Codex version,
//    passed every row with successful positive controls. A `:root` grant is never added to
//    make a backend accept the profile (argv.ts refuses it), and nothing weaker is ever
//    labelled S1.
//  - S2 (`--sandbox read-only`: unrestricted reads) is used only with a CLI-written
//    acceptance record listing `unrestricted_reads` AND `advisory_network` (network
//    enforcement is not self-tested for S2 in M1.4, so it is reported as advisory), for
//    this backend and Codex version range, bound to the current acceptance statement.
//  - Otherwise: CODEX_ISOLATION_UNAVAILABLE, naming the failed rows and both remedies.
// The decision itself (`decideIsolation`) is pure; loaders read the trusted files.

import { DomainError } from "../../common/errors.js";
import { sha256OfString } from "../../common/hash.js";
import { readTextIfExists } from "../../store/atomic.js";
import {
  IsolationAcceptanceFileSchema,
  type EffectiveIsolation,
  type IsolationAcceptance,
  type IsolationAcceptanceFile,
  type SelfTestRecord,
} from "../../schemas/review.js";
import { profileDigest, type IsolationArgvInput, type SandboxBackend } from "./argv.js";
import type { CompatRow } from "./compat.js";

/** The statement `codex accept-reduced-isolation` shows; an acceptance binds its digest. */
export const REDUCED_ISOLATION_STATEMENT =
  "Reduced Codex isolation (S2): Codex may read any file you can read, and its contents may be sent to OpenAI. " +
  "Network blocking is advisory: programs that ignore proxy settings can reach the network. " +
  "This applies to every review run under this acceptance until you revoke it.";

export const REDUCED_ISOLATION_STATEMENT_SHA256 = sha256OfString(REDUCED_ISOLATION_STATEMENT);

export interface IsolationDecisionInput {
  compat: CompatRow;
  codexVersion: string;
  installDir: string;
  /** Backends to consider, in preference order (configured one, or the compat preference). */
  backends: readonly SandboxBackend[];
  /** Stored S1 self-test per backend (null: none for this exact profile and version). */
  selfTests: ReadonlyMap<SandboxBackend, SelfTestRecord | null>;
  acceptances: readonly IsolationAcceptance[];
  userHooksPresent: boolean;
}

export type IsolationDecision =
  | { ok: true; isolation: EffectiveIsolation; argv: IsolationArgvInput }
  | { ok: false; reasons: string[]; missingSelfTests: SandboxBackend[] };

export function decideIsolation(i: IsolationDecisionInput): IsolationDecision {
  const reasons: string[] = [];
  const missing: SandboxBackend[] = [];
  for (const backend of i.backends) {
    const argv: IsolationArgvInput = { mode: "S1", backend, installDir: i.installDir, webSearchDisabledValue: i.compat.webSearchDisabledValue };
    const rec = i.selfTests.get(backend) ?? null;
    if (!rec) {
      missing.push(backend);
      reasons.push(`${backend}: no self-test of the production S1 profile for Codex ${i.codexVersion}`);
      continue;
    }
    if (rec.mode !== "S1" || rec.codex_version !== i.codexVersion || rec.profile_digest !== profileDigest(argv)) {
      missing.push(backend);
      reasons.push(`${backend}: stored self-test does not match this profile or version`);
      continue;
    }
    if (!rec.complete) {
      reasons.push(`${backend}: the self-test did not complete (a probe timed out or could not start); it is not stored and re-runs on the next review`);
      continue;
    }
    if (!rec.profile_runs) {
      reasons.push(rec.rejection_reason?.startsWith(NO_DESKTOP_SESSION)
        ? `${backend}: ${NO_DESKTOP_SESSION} — the production S1 profile could not start without an interactive desktop (${rec.rejection_reason}); ${NO_DESKTOP_REMEDY}`
        : `${backend}: the production S1 profile was rejected (${rec.rejection_reason ?? "unknown reason"})`);
      continue;
    }
    if (!rec.s1_available) {
      const failed = rec.rows.filter((r) => !r.pass || r.inconclusive).map((r) => `${r.name}${r.inconclusive ? " (inconclusive)" : ""}`);
      reasons.push(`${backend}: S1 self-test rows not passed: ${failed.join(", ") || "none recorded"}`);
      continue;
    }
    return {
      ok: true,
      argv,
      isolation: {
        mode: "S1",
        backend,
        reads: "restricted",
        network: "os_enforced",
        selftest_id: rec.selftest_id,
        acceptance_id: null,
        user_hooks_present: i.userHooksPresent,
        profile_digest: profileDigest(argv),
        codex_version: i.codexVersion,
      },
    };
  }

  // Reduced isolation only with an explicit, current acceptance (never automatic, F1).
  for (const backend of i.backends) {
    const acc = i.acceptances.find(
      (a) =>
        a.revoked_at === null &&
        a.backend === backend &&
        i.codexVersion.startsWith(a.codex_version_range) &&
        a.statement_sha256 === REDUCED_ISOLATION_STATEMENT_SHA256 &&
        a.accepted.includes("unrestricted_reads") &&
        a.accepted.includes("advisory_network"),
    );
    if (!acc) continue;
    const argv: IsolationArgvInput = { mode: "S2", backend, installDir: i.installDir, webSearchDisabledValue: i.compat.webSearchDisabledValue, acceptanceId: acc.acceptance_id };
    return {
      ok: true,
      argv,
      isolation: {
        mode: "S2",
        backend,
        reads: "unrestricted",
        network: "env_advisory",
        selftest_id: null,
        acceptance_id: acc.acceptance_id,
        user_hooks_present: i.userHooksPresent,
        profile_digest: profileDigest(argv),
        codex_version: i.codexVersion,
      },
    };
  }
  if (i.acceptances.some((a) => a.revoked_at === null && a.statement_sha256 !== REDUCED_ISOLATION_STATEMENT_SHA256)) {
    reasons.push("an acceptance record exists for an older statement; it must be re-accepted");
  }
  return { ok: false, reasons, missingSelfTests: missing };
}

/**
 * P3.4C-5 Increment 4 (§6, N5-9): the signature of a sandboxed process started without an interactive window station or
 * desktop (session 0, a service, PowerShell Direct, a batch logon) — STATUS_DLL_INIT_FAILED, 0xC0000142, as an unsigned or
 * a signed exit status. Observed on the tested Windows VM for the `mxc` profile (P3.4C-4) only.
 */
export function isNoDesktopExit(code: number | null | undefined): boolean {
  return code === 0xc0000142 || code === -1073741502;
}
export const NO_DESKTOP_SESSION = "no_desktop_session";
export const NO_DESKTOP_REMEDY = "run it from a signed-in desktop session (D-17) — not from a service, PowerShell Direct or a scheduled batch logon";

/** The error a review gets when no configuration passes and nothing is accepted (§12.2). With a profile that could not
 * start for want of a desktop (§6), the error says so: `reason: "no_desktop_session"` and the remedy. Still fail-closed. */
export function isolationUnavailableError(reasons: readonly string[]): DomainError {
  const noDesktop = reasons.some((r) => r.includes(NO_DESKTOP_SESSION));
  return new DomainError(
    "CODEX_ISOLATION_UNAVAILABLE",
    `No Codex isolation configuration is available. ${reasons.join("; ")}. ` +
      (noDesktop ? `The isolation profile cannot start in this context (no interactive desktop session): ${NO_DESKTOP_REMEDY}. Otherwise: ` : "") +
      "Remedies: configure a backend whose S1 self-test passes " +
      (process.platform === "win32"
        ? "(`code-parley codex selftest`; codex.windows_sandbox, mxc preferred)"
        : "(`code-parley codex selftest`; Linux: Codex's bubblewrap sandbox, which needs unprivileged user namespaces)") +
      ", or record an acceptance of reduced isolation (`code-parley codex accept-reduced-isolation`).",
    { details: noDesktop ? { reasons, reason: NO_DESKTOP_SESSION, remedy: NO_DESKTOP_REMEDY } : { reasons } },
  );
}

/** Read trust/isolation.json (missing → no records). An invalid file grants nothing. */
export async function loadAcceptances(path: string): Promise<{ file: IsolationAcceptanceFile; problem: string | null }> {
  const raw = await readTextIfExists(path);
  if (raw == null) return { file: { schema_version: 1, records: [] }, problem: null };
  try {
    return { file: IsolationAcceptanceFileSchema.parse(JSON.parse(raw)), problem: null };
  } catch (e) {
    return { file: { schema_version: 1, records: [] }, problem: `trust/isolation.json is invalid and grants nothing: ${String((e as Error).message).slice(0, 200)}` };
  }
}
