// The custodian helper's two workloads (P3.4C-5, Amendment A §A.5, §A.7), run by the approved engine runtime under
// NT SERVICE\CodeParleyHelper. Both use the engine's own code — the same capture and the same pure policy functions the
// engine runs — and neither writes anything: git runs with the custodian's protected configuration, and every home and
// temp directory is the custodian's read-only per-request directory.
//
// capture — the real sanitizing review capture (capture.ts runHelperCapture), its export streamed to the custodian.
// derive  — the custodian's measurement (the current source identity, the repository's root commit, and per check its
//           freshness-input digest and executable stat with the check-spec id they give) and, when the custodian sends
//           its scrubbed snapshot, the PROTECTED derivation over it (engine/protected-derivation.ts, P3.4C-5 Increment
//           3): completion, the route, the progress fingerprint and the input digest. Without a snapshot it is a
//           measurement only — a check's start or end (§4), or a spend's re-measurement (N5-17). With `redact` (Phase 5
//           F-i2-5) it also redacts an amendment text for review over the same read: what the read withholds and local
//           paths outside the kept roots, the engine's own host view (engine/host-view.ts toHost).

import { userInfo } from "node:os";
import { computeHelperSourceIdentity, runHelperCapture, type HelperScratch } from "../capture/capture.js";
import { readDisclosureRecord, toHost, withheldOfEntries, withheldOfHeldRecords } from "../engine/host-view.js";
import { sha256OfString } from "../common/hash.js";
import type { SourceEntry } from "../schemas/capture.js";
import type { ProtectedGitConfig } from "../capture/git-query.js";
import { readRootCommit } from "../capture/root-commit.js";
import { computeCheckSpecId, computeFreshnessDigest, hashFreshnessInputs } from "../checks/identity.js";
import { normalizeCheckDefinition } from "../checks/project-config.js";
import { protectedDerive, type DerivationMeasurement, type DerivationSnapshot, type MeasuredCheck } from "../engine/protected-derivation.js";
import { resolveCommand } from "../process/command.js";
import type { CaptureWorkload, DeriveWorkload, Launch, MeasuredCheckRequest } from "./request.js";
import type { FrameWriter, LineReader } from "./frames.js";
import { FramedExport } from "./framed-export.js";

/** Who ran the workload, as its own process sees it (evidence for the record; the custodian authenticates the helper
 * service by its SID on the pipe, never by this). */
function identity(): { user: string; pid: number; node: string } {
  let user = "unknown";
  try {
    user = userInfo().username;
  } catch {
    /* a service account without a resolvable profile: reported as unknown */
  }
  return { user, pid: process.pid, node: process.version };
}

function scratchOf(l: Launch): HelperScratch {
  return { hooks: l.hooks, home: l.home, gitconfig: l.gitconfig };
}

function protectedGitOf(l: Launch): ProtectedGitConfig {
  return { safeDirectory: l.safeDirectory, globalConfig: l.gitconfig };
}

export async function captureWorkload(l: Launch, w: CaptureWorkload, frames: FrameWriter, lines: LineReader): Promise<Record<string, unknown>> {
  const sink = new FramedExport(frames, async () => {
    await frames.write({ t: "stage_complete" });
    const line = await lines.next();
    const msg = line ? (JSON.parse(line) as { t?: unknown; dir?: unknown }) : null;
    if (!msg || msg.t !== "staged" || typeof msg.dir !== "string" || msg.dir.length === 0) throw new Error("the custodian did not publish the staging");
    return msg.dir;
  });
  const r = await runHelperCapture({
    repoRoot: l.repository,
    gitExe: l.git,
    target: w.target,
    rules: w.rules,
    operationId: w.operationId,
    sink,
    scratch: scratchOf(l),
    protectedGit: protectedGitOf(l),
  });
  return { record: r.record, manifestDigest: r.manifest.manifest_digest, exportDigest: r.exportDigest, sourceId: r.record.source_id, stable: r.record.stable, identity: identity() };
}

/** The measurement of a check's inputs (§4, §5.1 step 2), the engine's own way: the freshness inputs hashed from the
 * repository, and the STAT of the executable the session resolved (the path is the engine's claim; resolving an
 * absolute path stats it, exactly as the engine's resolution would) with the check-spec id it gives. */
async function measureCheck(repository: string, c: MeasuredCheckRequest): Promise<MeasuredCheck> {
  const n = normalizeCheckDefinition(c.definition);
  if (!n.ok) return { name: c.name, freshnessDigest: null, executable: null, checkSpecId: null, problem: "definition_invalid" };
  const def = n.def;
  const freshnessDigest = computeFreshnessDigest(await hashFreshnessInputs(repository, def.freshness_inputs));
  if (c.executable === null) return { name: c.name, freshnessDigest, executable: null, checkSpecId: null, problem: "no_executable_claim" };
  const r = resolveCommand(c.executable, { relativeBase: repository, pathValue: "" });
  if (!r.ok || r.command.how !== "absolute") return { name: c.name, freshnessDigest, executable: null, checkSpecId: null, problem: "executable_unresolvable" };
  const resolved = r.command;
  return {
    name: c.name,
    freshnessDigest,
    executable: { path: resolved.path, kind: resolved.kind, size: resolved.size, mtimeMs: resolved.mtimeMs },
    checkSpecId: computeCheckSpecId({ name: c.name, def, definitionDigest: c.definitionDigest, resolved }),
    problem: null,
  };
}

/** The measurement the custodian asks for (a check's start and end, a derivation, a spend's re-measurement, N5-17), and
 * the read's entries it was measured from. */
async function measureRead(l: Launch, w: Pick<DeriveWorkload, "rules" | "checks">): Promise<{ measured: DerivationMeasurement; entries: readonly SourceEntry[] }> {
  const src = await computeHelperSourceIdentity({ repoRoot: l.repository, gitExe: l.git, rules: w.rules, scratch: scratchOf(l), protectedGit: protectedGitOf(l) });
  const rootCommit = await readRootCommit({ gitExe: l.git, repoRoot: l.repository, hooksDir: l.hooks, protectedConfig: protectedGitOf(l) });
  const checks: MeasuredCheck[] = [];
  for (const c of w.checks) checks.push(await measureCheck(l.repository, c));
  return { measured: { sourceId: src.source_id, stable: src.stable, rootCommit, checks }, entries: src.entries };
}

export async function measureInputs(l: Launch, w: Pick<DeriveWorkload, "rules" | "checks">): Promise<DerivationMeasurement> {
  return (await measureRead(l, w)).measured;
}

/**
 * Phase 5 F-i2-5: the reviewer-visible representation of a protected amendment's text, as the operator's own `amend`
 * produces it on the accepted Windows workflow (cli/user-commands.ts reviewerDisclosure → disclosureFor with the read's
 * entries): every name and hash the run's history withholds — the capture records of its reviews and baseline and its
 * response disclosure records, which the custodian holds and sends — and this read withholds, redacted, local paths
 * outside the kept roots scrubbed, then the MR-F invariant (engine/host-view.ts). Every held record must hash to its
 * digest and parse; only from a stable read; a text that would still disclose a withheld name is refused (fail closed),
 * never shortened.
 */
function redactionOf(r: NonNullable<DeriveWorkload["redact"]>, m: DerivationMeasurement, entries: readonly SourceEntry[]): Record<string, unknown> {
  if (!m.stable) return { ok: false, error: "the working tree changed while it was being read" };
  for (const e of r.evidence) if (sha256OfString(e.text) !== e.sha256) return { ok: false, error: `a held ${e.kind} record (${e.sha256.slice(0, 12)}) does not hash to its digest` };
  let withheld: { paths: Set<string>; hashes: Set<string> };
  try {
    withheld = withheldOfHeldRecords(r.evidence, entries);
  } catch (e) {
    return { ok: false, error: `a held record is not one the engine reads (${(e instanceof Error ? e.message : String(e)).slice(0, 160)})` };
  }
  const posix = process.platform !== "win32";
  try {
    const out = toHost(r.text, { withheldPaths: withheld.paths, withheldHashes: withheld.hashes, keepRoots: r.keepRoots, hiddenDirs: posix ? [{ dir: "/tmp", label: "[temp]" }] : [], posixPaths: posix });
    // Phase 5 OI-1: what this read withheld, for the custodian to hold — a later amendment is redacted against it.
    return { ok: true, redacted: out.value, sourceId: m.sourceId, redactions: out.redactions, disclosure: readDisclosureRecord(withheldOfEntries(entries)) };
  } catch {
    return { ok: false, error: "the text would disclose a confidential name even after redaction" };
  }
}

/** `derive`: the measurement, and — with a snapshot — the protected derivation over it (§5.1); with `redact`, the
 * redaction of an amendment text over the same read. */
export async function deriveWorkload(l: Launch, w: DeriveWorkload): Promise<Record<string, unknown>> {
  const { measured, entries } = await measureRead(l, w);
  const derivation = w.snapshot ? protectedDerive(w.snapshot as unknown as DerivationSnapshot, measured) : null;
  return { measured, derivation, ...(w.redact ? { redaction: redactionOf(w.redact, measured, entries) } : {}), identity: identity(), scope: { increment: 3, authoritative: derivation !== null } };
}
