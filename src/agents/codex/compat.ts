// Codex compatibility table (plan §12.4, §12.6, §19.6; Gate A §1.7; Linux Gate A §1.13). Pure data.
//
// Every fact here is per platform and Codex version and was observed on the target machine;
// nothing is assumed for versions not listed. A version outside the table is refused
// (CODEX_UNSUPPORTED_VERSION) until Gate A (LV-ISO-1..3) re-runs for it on that platform.

import type { SandboxBackend } from "./argv.js";

export interface BackendFacts {
  /**
   * What the exact production S1 profile did on this backend (Gate A). "unconfirmed": the
   * offline probes were contained, but no live review has confirmed it yet. The self-test still
   * decides at run time.
   */
  s1: "enforced" | "rejected" | "unconfirmed";
  note: string;
}

export interface CompatRow {
  /** The platform the row was validated on. */
  platform: "win32" | "linux";
  /** Version prefix, e.g. "0.160.". */
  versionPrefix: string;
  /** `exec --help` must list every one of these. */
  requiredExecFlags: readonly string[];
  /** The `web_search` value that disables search (M1.0-4: 0.160.0 enum disabled|cached|indexed|live). */
  webSearchDisabledValue: string;
  /** Preferred backends for S1, in order (M1.0-1). */
  preferredBackends: readonly SandboxBackend[];
  backends: Readonly<Partial<Record<SandboxBackend, BackendFacts>>>;
  /** M1.0-5: untrusted user hooks did not run (gated by persisted hook trust). Reported, not relied on. Null: not established on this platform. */
  untrustedUserHooksRun: boolean | null;
  /**
   * Do sandboxed commands survive when the Codex process alone is terminated? Windows/MXC: yes
   * (M1.3-11: MXC ends them on orderly exit and on a tree kill, not when codex.exe alone dies).
   * Linux/bwrap: no (bubblewrap runs with --die-with-parent in its own PID namespace; observed).
   */
  sandboxSurvivesAbruptCodexExit: boolean;
}

export const REQUIRED_EXEC_FLAGS: readonly string[] = [
  "--json",
  "--ephemeral",
  "--color",
  "--ignore-user-config",
  "--ignore-rules",
  "--skip-git-repo-check",
  "--cd",
  "--output-schema",
  "--output-last-message",
  "--sandbox",
];

export const COMPAT_TABLE: readonly CompatRow[] = [
  {
    platform: "win32",
    versionPrefix: "0.160.",
    requiredExecFlags: REQUIRED_EXEC_FLAGS,
    webSearchDisabledValue: "disabled",
    preferredBackends: ["mxc"],
    backends: {
      mxc: { s1: "enforced", note: "Gate A 2026-10-03: production S1 profile accepted and enforced (11/11 rows, live hostile run contained)" },
      elevated: { s1: "rejected", note: "requires effective ':root' read access (X19)" },
      unelevated: { s1: "rejected", note: "restricted read-only access requires the elevated backend" },
    },
    untrustedUserHooksRun: false,
    sandboxSurvivesAbruptCodexExit: true,
  },
  {
    platform: "linux",
    versionPrefix: "0.160.",
    requiredExecFlags: REQUIRED_EXEC_FLAGS,
    webSearchDisabledValue: "disabled",
    preferredBackends: ["bwrap"],
    backends: {
      bwrap: { s1: "enforced", note: "Linux Gate A 2026-10-05 (WSL2, Ubuntu 24.04, kernel 6.18; native Ubuntu 24.04.5, kernel 6.8, AppArmor's user-namespace restriction on and the bundled bubblewrap given userns by a profile — without one it is rejected, reviews fail closed): production S1 profile accepted and enforced by the bundled bubblewrap (20/20 offline rows; live hostile review contained, no leak; mount, user, PID and network namespaces; seccomp network filter)" },
    },
    untrustedUserHooksRun: null,
    sandboxSurvivesAbruptCodexExit: false,
  },
];

/** The row for an installed Codex version on a platform, or null when it is not validated there. */
export function compatRowFor(version: string | null, platform: NodeJS.Platform = process.platform): CompatRow | null {
  if (!version) return null;
  return COMPAT_TABLE.find((r) => r.platform === platform && version.startsWith(r.versionPrefix)) ?? null;
}
