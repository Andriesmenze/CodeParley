// P3.4C-4 (contract §1, §4.3, §4.4): on a PROTECTED run the engine takes its trusted configuration from the CUSTODIAN
// only — the approved checks with the verification floor and test globs, the capture rules, the isolation basis
// (confirmed self-tests, accepted reduced isolation) and the approved Codex installation — and never from
// trust/projects.json, trust/isolation.json, selftest/*.json or config.json. Whether a run is protected is the
// custodian's answer (P3.4C-3 §5.4); the local marks only add refusals. An attended run is unchanged (Phase 2).
//
// Fail closed: a protected run whose configuration the custodian cannot report is refused (CUSTODIAN_UNAVAILABLE); one
// without a usable repository record evaluates as having nothing approved, and its starts are refused CONFIG_NOT_HELD /
// CONFIG_LAPSED (the custodian refuses them too, inside its transitions). run.json is re-verified against the digest
// the custodian bound at `open` before every protected use (RUN_JSON_MISMATCH).

import { readFile } from "node:fs/promises";
import { DomainError, isDomainError } from "../common/errors.js";
import { sha256OfBytes, sha256OfCanonicalJson } from "../common/hash.js";
import { CustodianGrants } from "../custodian/grants.js";
import { protectedLoopGate, type CustodianTestHooks } from "../custodian/protected-loops.js";
import { CUSTODIAN_UNAVAILABLE, type ConfigSection, type HeldAcceptance, type HeldRepositoryConfig, type RunSection } from "../custodian/protocol.js";
import { captureRulesConfigDigest } from "../custodian/config-digests.js";
import type { CustodianPresence } from "../custodian/service-presence.js";
import type { CaptureRulesInput } from "../capture/capture.js";
import { evaluateEntry, projectApprovalDigest, type ProjectEvaluation } from "../checks/project-config.js";
import type { ProjectEntry } from "../schemas/trust.js";
import type { IsolationAcceptance, SelfTestRecord } from "../schemas/review.js";
import { SelfTestRecordSchema } from "../schemas/review.js";
import { RunMetaSchema, type RunMeta, type StateRecord } from "../schemas/run-state.js";
import { locallyProtected } from "./protected-user-records.js";

/** What the engine needs to ask the custodian for a run's configuration (as EvidenceSelection, plus run.json). */
export interface ConfigSelection {
  custodian?: CustodianTestHooks | undefined;
  presence: () => Promise<CustodianPresence>;
  repositoryRoot: string;
  runId: string;
  /** The run's run.json and the metadata the engine parsed from it (re-verified against the custodian's digest). */
  runJson?: { path: string; meta: RunMeta };
  /** The surface this process's account reads on (default: the implementer's). */
  surface?: "operator" | "implementer";
}

/** A protected run's configuration as the custodian reports it now. */
export interface HeldConfig {
  section: ConfigSection;
  /** The run section read in the same custodian snapshot. */
  run: RunSection | null;
}

function unavailable(why: string): DomainError {
  return new DomainError(CUSTODIAN_UNAVAILABLE, why, { retryable: false, details: { outcome: "not_delivered" } });
}

/**
 * The custodian's configuration for this run, or null for an attended run (its configuration stays the local files).
 * One read of the run and config sections; a custodian that cannot answer refuses every run (CUSTODIAN_UNAVAILABLE;
 * Phase 6 S-3: the local marks are user-writable hints); a run the local copy marks protected of which it holds no
 * record is refused (RUN_RECORD_MISSING); a protected run's run.json is re-verified here (RUN_JSON_MISMATCH).
 */
export async function heldConfigFor(sel: ConfigSelection, st: StateRecord): Promise<HeldConfig | null> {
  const marked = locallyProtected(st);
  if ((await sel.presence()) === "absent") {
    if (marked) throw unavailable("this run is recorded as protected, but no CodeParley custodian service is installed on this host; its configuration cannot be read");
    return null;
  }
  const gate = protectedLoopGate(sel.custodian);
  let listing;
  try {
    if (!gate.available) throw gate.error;
    listing = await new CustodianGrants(gate.transport).listUserRecords(sel.surface ?? "implementer", sel.repositoryRoot, sel.runId, ["run", "config"]);
    if (listing.protected === null) throw unavailable("the custodian did not answer whether this run is protected");
  } catch (e) {
    // Phase 6 S-3 (D-34): refused whatever the local marks say (they are user-writable hints): fail closed.
    throw isDomainError(e) ? e : unavailable(`the custodian could not say whether this run is protected (${e instanceof Error ? e.message : String(e)}); start the CodeParley custodian service, then retry`);
  }
  if (!listing.protected) {
    if (marked) throw new DomainError("RUN_RECORD_MISSING", `run ${sel.runId} is recorded locally as protected, but the custodian holds neither its loop nor its run record; nothing proceeds on this run — automate a new run`, { retryable: false });
    return null;
  }
  if (!listing.config) throw unavailable("the custodian did not report this protected run's configuration (fail closed)");
  if (sel.runJson) await verifyRunJson(sel.runJson.path, sel.runJson.meta, listing.run);
  return { section: listing.config, run: listing.run };
}

/**
 * §1.1: a protected run's run.json, re-verified before use against the digest the custodian bound at `open` — the
 * bytes on disk now, and the metadata the engine parsed from them, which must be the same document (a file changed
 * after the engine read it and restored before this check is caught by the second comparison). Fail closed.
 */
export async function verifyRunJson(path: string, meta: RunMeta, run: RunSection | null): Promise<void> {
  const declared = ((run?.record?.["declaration"] ?? null) as { runJsonDigest?: unknown } | null)?.runJsonDigest;
  if (!run?.registered) return; // protected by its loop only (no run record): there is no bound run.json yet
  if (typeof declared !== "string") throw new DomainError("RUN_JSON_MISMATCH", "the custodian's record of this protected run binds no run.json digest; nothing proceeds (fail closed)", { retryable: false });
  const bytes = await readFile(path).catch(() => null);
  const mismatch = (why: string) => new DomainError("RUN_JSON_MISMATCH", `this protected run's run.json ${why} since the custodian registered it; nothing proceeds on this run (fail closed) — automate a new run`, { retryable: false });
  if (!bytes || sha256OfBytes(bytes) !== declared) throw mismatch("was changed");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw mismatch("is unreadable");
  }
  let reparsed: RunMeta;
  try {
    reparsed = RunMetaSchema.parse(parsed);
  } catch {
    throw mismatch("is malformed");
  }
  if (sha256OfCanonicalJson(reparsed) !== sha256OfCanonicalJson(meta)) throw mismatch("the engine read differs from the one the custodian bound (it changed");
}

/** Why a protected run's repository record cannot be used, as the code a start is refused with (null: usable). */
export function heldRepositoryProblem(section: ConfigSection): { code: "CONFIG_NOT_HELD" | "CONFIG_LAPSED"; message: string } | null {
  const r = section.repository;
  if (!r || r.revoked) {
    return { code: "CONFIG_NOT_HELD", message: `the custodian holds no protected configuration for this repository${r ? " in force (it was revoked)" : ""}; protected checks and reviews are refused until the operator sets it: code-parley config set --repo <path>` };
  }
  if (r.lapsed) {
    return { code: "CONFIG_LAPSED", message: `the repository's protected configuration lapsed when the custodian recovered after a restart of the OS; protected checks and reviews are refused until the operator re-confirms it: code-parley config reconfirm --repo <path> (or code-parley loop resume <run>)` };
  }
  return null;
}

/** Refuse a protected start whose repository record is not usable. */
export function requireUsableHeld(section: ConfigSection): HeldRepositoryConfig {
  const p = heldRepositoryProblem(section);
  if (p) throw new DomainError(p.code, p.message, { retryable: false });
  return section.repository!;
}

/**
 * The trusted check configuration of a protected run, evaluated exactly as the local trust file would be (the engine's
 * own normalization and digests): the held definitions, profiles, floor and test globs, with an approval record the
 * engine derives from the held content. A held definition whose digest the engine computes differently does not run
 * (approval_invalid). A record that is missing, revoked or lapsed approves nothing.
 */
export function heldEvaluation(section: ConfigSection, canonicalRoot: string, rootCommit: string | null): ProjectEvaluation {
  const problem = heldRepositoryProblem(section);
  if (problem) {
    return {
      key: null, status: problem.code === "CONFIG_LAPSED" ? "config_lapsed" : "config_not_held", problems: [problem.message], checks: new Map(), removed: [],
      profiles: {}, requiredProfiles: [], noRequiredChecks: false, floorConfigured: false, testGlobs: [], approval: null, rootCommit: null,
    };
  }
  const r = section.repository!;
  const checkDigests = Object.fromEntries(Object.entries(r.checks).map(([n, c]) => [n, c.definitionDigest]));
  const entry: ProjectEntry = {
    ...(r.rootCommit !== null ? { root_commit: r.rootCommit } : {}),
    checks: Object.fromEntries(Object.entries(r.checks).map(([n, c]) => [n, c.definition])),
    profiles: r.profiles,
    ...(r.noRequiredChecks ? { no_required_checks: true } : { required_profiles: r.requiredProfiles }),
    test_globs: r.testGlobs,
    approval: {
      at: r.recordedAt,
      via: "cli",
      digest: projectApprovalDigest({ canonicalRoot, rootCommit: r.rootCommit, checkDigests, profiles: r.profiles, requiredProfiles: r.requiredProfiles, noRequiredChecks: r.noRequiredChecks, testGlobs: r.testGlobs }),
      checks: checkDigests,
    },
  };
  return evaluateEntry(`custodian:${r.configRevision}`, entry, canonicalRoot, rootCommit);
}

/** The held capture rules, as the capture pipeline takes them. */
export function heldCaptureRules(section: ConfigSection): CaptureRulesInput {
  const r = section.repository?.captureRules;
  // A record that is missing, revoked or lapsed: the default exclusions apply to any read (nothing protected starts).
  if (!r) return { exclude_globs: ["**/*"], context_include: [], max_file_bytes: 1, max_export_bytes: 1, max_diff_bytes: 1 };
  return { exclude_globs: [...r.excludeGlobs], context_include: [...r.contextInclude], max_file_bytes: r.maxFileBytes, max_export_bytes: r.maxExportBytes, max_diff_bytes: r.maxDiffBytes };
}

/** The digest the custodian holds for the rules a capture used (compared at op_begin). */
export function heldCaptureRulesDigest(section: ConfigSection): string {
  const r = section.repository!.captureRules;
  return captureRulesConfigDigest(r);
}

/** The engine's digest of a stored self-test record (the record as its engine produced and stored it). */
export function selfTestRecordDigest(rec: SelfTestRecord): string {
  return sha256OfCanonicalJson(SelfTestRecordSchema.parse(rec));
}

/** Is this stored self-test record confirmed by a usable custodian record (same record digest, self-test, Codex version,
 * backend and profile)? */
export function confirmedSelfTest(section: ConfigSection, rec: SelfTestRecord): boolean {
  const digest = selfTestRecordDigest(rec);
  return section.selftestConfirmations.some((c) => c.usable && c.recordDigest === digest && c.selftestId === rec.selftest_id && c.codexVersion === rec.codex_version && c.backend === rec.backend && c.profileDigest === rec.profile_digest && c.mode === "S1");
}

/** The held acceptances of reduced isolation in force, in the shape the isolation decision reads. */
export function heldAcceptances(section: ConfigSection): IsolationAcceptance[] {
  return section.acceptances.filter((a: HeldAcceptance) => a.usable).map((a) => ({
    acceptance_id: a.acceptanceId,
    accepted: a.accepted.filter((x): x is IsolationAcceptance["accepted"][number] => x === "unrestricted_reads" || x === "advisory_network"),
    backend: a.backend,
    codex_version_range: a.codexVersionRange,
    statement_sha256: a.statementSha256,
    accepted_at: a.recordedAt,
    via: "cli",
    revoked_at: null,
  }));
}

/**
 * §4.4: the approved Codex installation a protected review must launch. CodeParley launches exactly this file (it is the
 * probe's configured executable on a protected run); a review whose resolved image or its SHA-256 differs is refused
 * before anything is sent (CONFIG_MISMATCH). The SHA-256 is the engine's measurement of the image it is about to launch
 * — an engine claim the custodian compares (R1-class residual: a swap after it is not detected).
 */
export async function approvedCodexImage(section: ConfigSection, launchedExe: string, sameFile: (a: string, b: string) => boolean): Promise<{ sha256: string }> {
  const i = section.repository?.codexInstallation;
  if (!i) throw new DomainError("CONFIG_NOT_HELD", "the repository's protected configuration has no approved Codex installation; a protected review is refused — the operator sets one with code-parley config set --repo <path> --codex <codex.exe>", { retryable: false });
  if (!sameFile(launchedExe, i.path)) throw new DomainError("CONFIG_MISMATCH", `the Codex executable CodeParley would launch (${launchedExe}) is not the approved installation (${i.path}); nothing was sent`, { retryable: false });
  const bytes = await readFile(launchedExe).catch(() => null);
  if (!bytes) throw new DomainError("CONFIG_MISMATCH", `the approved Codex executable ${launchedExe} cannot be read; nothing was sent`, { retryable: false });
  const sha256 = sha256OfBytes(bytes);
  if (sha256 !== i.sha256) throw new DomainError("CONFIG_MISMATCH", "the Codex executable at the approved path is not the image the operator approved (its SHA-256 differs); nothing was sent — the operator approves it again with code-parley config set", { retryable: false });
  return { sha256 };
}
