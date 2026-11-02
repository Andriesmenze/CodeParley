// Phase 6 Increment 3 (contract §3.2, §3.4; [[D-41]]): what the protected side of this host looks like — the custodian
// service, the surfaces this account reaches, the running custodian's release and protocol, and for one repository the
// operator's records with the one command that restores each.
//
// READ-ONLY and a DISPLAY. It sends `ping`, `list_grants` and the config section of `list_user_records` (reads every
// account may already make) and asks the host's service manager; it prepares, confirms and commits nothing. Nothing reads
// its answer to decide anything: the custodian decides every protected request itself, and a "ready" here grants no
// authority. Every state comes from an observation, and what was not observed is reported as unknown. It quotes no
// protected content: record identities, states and digests prefixes only.

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDomainError } from "../common/errors.js";
import { uuidv7 } from "../common/ids.js";
import { TOOL_VERSION } from "../common/version.js";
import { CustodianGrants, grantListingOf } from "../custodian/grants.js";
import { custodianPresence, protectedLoopGate } from "../custodian/protected-loops.js";
import { CONFIG_VIEW_RUN, CUSTODIAN_PROTOCOL_VERSION, type ConfigSection, type CustodianSurface, type GrantSummary } from "../custodian/protocol.js";
import { CUSTODIAN_SERVICE_NAME, type CustodianPresence } from "../custodian/service-presence.js";
import { CustodianBusy, CustodianNotTrusted, custodianClientDeadline, setCustodianClientDeadline, type CustodianTransport } from "../custodian/transport.js";
import { runProcess } from "../process/spawn.js";
import type { Loaded } from "./engine-env.js";

/** The host's state, most decisive first. Every value is backed by an observation (see {@link hostStateOf}). */
export type HostState =
  | "unsupported_platform" // no custodian exists for this OS
  | "not_installed" // the service manager says the service does not exist
  | "stopped" // installed, and the service manager reports it stopped (Windows) or its sockets not listening (Linux)
  | "untrusted" // an endpoint answered that is not owned by the custodian (refused, as every client refuses it)
  | "incompatible" // the custodian answered with another protocol version than this engine speaks
  | "busy" // the custodian is serving another request longer than the probe waited
  | "unavailable" // installed and not stopped, but nothing answered
  | "ready"; // the custodian answered on at least one surface with this engine's protocol

/** One repository-level state on top of a ready host. */
export type RepositoryState = "ready" | "misconfigured" | "unknown";

export interface CustodianIdentity {
  version: string | null;
  build: string | null;
  protocol: number | null;
  host: string | null;
}

export interface SurfaceProbe {
  surface: CustodianSurface;
  result: "answers" | "refused" | "busy" | "unavailable" | "untrusted" | "incompatible";
  /** The transport's or the custodian's own words (no protected content). */
  detail: string | null;
  identity: CustodianIdentity | null;
}

export type RecordName = "engine_runtime" | "repository" | "isolation" | "fix_confirmation" | "loop_grant";
export type RecordStateValue = "in_force" | "lapsed" | "changed" | "missing" | "revoked" | "suspended" | "used_up" | "expired";

export interface RecordState {
  record: RecordName;
  state: RecordStateValue;
  /** Whether a protected review (or, for the FIX confirmation and the grant, a delegated fix / an automated loop) needs it. */
  required: boolean;
  detail: string;
  /** The one command that restores it (the operator's, in this platform's terms); null when in force. */
  restore: string | null;
  /** Whether `setup --resume` restores it (it was in force before and lapsed, changed or was suspended). */
  resumable: boolean;
}

export interface ProtectedStatus {
  platform: NodeJS.Platform;
  engine: { version: string; protocol: number };
  service: { presence: CustodianPresence; manager_state: string | null };
  surfaces: SurfaceProbe[];
  custodian: CustodianIdentity | null;
  state: HostState;
  /** Why the state is what it is, and what it means (the busy limitation included). */
  explanation: string[];
  repository: { root: string; state: RepositoryState; read_on: CustodianSurface | null; records: RecordState[] } | null;
  /** The commands to run next, in order. */
  next: string[];
}

/** Test seams: the service manager's answer and the Codex file hash. Production uses the host's own. */
export interface StatusProbeHooks {
  managerState?: () => Promise<string | null>;
  hashFile?: (path: string) => Promise<string | null>;
  exists?: (path: string) => Promise<boolean>;
  builtAt?: (root: string) => Promise<number | null>;
  installedRuntime?: () => Promise<string | null>;
}

/** How long a probe waits for a busy custodian before it reports `busy` (a bounded display, never a retry loop). */
export const STATUS_BUSY_WAIT_MS = 12_000;

export const BUSY_LIMITATION =
  "The custodian serves one request at a time. Right after a boot its first protected request measures the approved engine runtime " +
  "(on Windows about 13–55 s on the test VM; a queued call waited 37.7 s), and a hook queued behind it can be refused CUSTODIAN_BUSY. " +
  "That is a known first-release limitation: it fails closed (nothing is granted, consumed or weakened), and it clears when the measurement ends.";

/** The operator's CLI on this platform (the Linux wrapper; an elevated terminal on Windows). */
export function operatorCli(platform: NodeJS.Platform = process.platform): string {
  return platform === "linux" ? "/usr/local/sbin/code-parley-operator" : "code-parley";
}

function operatorWhere(platform: NodeJS.Platform): string {
  return platform === "linux" ? "as the operator account" : "in an elevated terminal as the operator account";
}

/** The service manager's word for the custodian's state, or null when it could not be read. */
async function hostManagerState(platform: NodeJS.Platform): Promise<string | null> {
  try {
    if (platform === "win32") {
      const sc = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "sc.exe");
      const r = await runProcess(sc, ["query", CUSTODIAN_SERVICE_NAME], { wallMs: 15_000 });
      const m = /STATE\s*:\s*\d+\s+([A-Z_]+)/.exec(r.stdout);
      return m ? m[1]! : null;
    }
    if (platform === "linux") {
      // The implementer socket decides reachability (the service is socket-activated and may be inactive while it listens).
      const r = await runProcess("/usr/bin/systemctl", ["is-active", "codeparley-implementer.socket", "codeparley-custodian.service"], { wallMs: 15_000 });
      const [sock, svc] = r.stdout.split(/\r?\n/).map((s) => s.trim());
      return sock ? `socket ${sock}, service ${svc ?? "unknown"}` : null;
    }
  } catch {
    /* unreadable: unknown */
  }
  return null;
}

function stoppedByManager(platform: NodeJS.Platform, s: string | null): boolean {
  if (s === null) return false;
  if (platform === "win32") return s === "STOPPED";
  return /^socket (inactive|failed)/.test(s);
}

/** When the engine runtime at `root` was built (its BUILD-ID's builtAt, epoch ms); null when it has none or it is unreadable. */
async function runtimeBuiltAt(root: string): Promise<number | null> {
  try {
    const o = JSON.parse(await readFile(join(root, "BUILD-ID"), "utf8")) as { builtAt?: unknown };
    const t = typeof o.builtAt === "string" ? Date.parse(o.builtAt) : NaN;
    return Number.isFinite(t) ? t : null;
  } catch {
    return null;
  }
}

/** The installer's link to the installed engine runtime on Linux. The custodian measures without following links, so the
 * approved root is the versioned directory the link names, never the link. */
export const LINUX_ENGINE_CURRENT = "/opt/codeparley/engine/current";

/** Where the product installer places engine runtimes, one versioned directory each. */
function installerEngineDir(platform: NodeJS.Platform): string | null {
  if (platform === "win32") return join(process.env["ProgramFiles"] ?? "C:\\Program Files", "CodeParley", "engine");
  if (platform === "linux") return "/opt/codeparley/engine";
  return null;
}

/** The installed engine runtime: the versioned directory this CLI runs from when the installer placed it (both
 * installers keep the previous version for a rollback, so the approved one may still exist after an upgrade), else on
 * Linux the one `current` names; null for a development checkout without an installation. */
export async function installedEngineRuntime(platform: NodeJS.Platform = process.platform): Promise<string | null> {
  const base = installerEngineDir(platform);
  if (!base) return null;
  const own = await realpath(fileURLToPath(new URL("../..", import.meta.url))).catch(() => null);
  const norm = (p: string) => (platform === "win32" ? p.toLowerCase() : p);
  if (own && norm(dirname(own)) === norm(base)) return own;
  return platform === "linux" ? realpath(LINUX_ENGINE_CURRENT).catch(() => null) : null;
}

/** Whether two runtime roots name the same directory (Windows paths compare without case). */
function sameRoot(platform: NodeJS.Platform, a: string, b: string): boolean {
  return platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

async function pathExists(path: string): Promise<boolean> {
  return stat(path).then(() => true, (e: NodeJS.ErrnoException) => e.code !== "ENOENT");
}

async function sha256OfFile(path: string): Promise<string | null> {
  return new Promise((resolve) => {
    const h = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (c) => h.update(c));
    s.on("error", () => resolve(null));
    s.on("end", () => resolve(h.digest("hex")));
  });
}

function identityOf(data: Record<string, unknown> | undefined): CustodianIdentity {
  const str = (k: string): string | null => (typeof data?.[k] === "string" ? (data[k] as string) : null);
  return { version: str("version"), build: str("build"), protocol: typeof data?.["protocol"] === "number" ? (data["protocol"] as number) : null, host: str("host") };
}

/** One ping on one surface, classified. */
async function probe(t: CustodianTransport, surface: CustodianSurface): Promise<SurfaceProbe> {
  try {
    const res = await t.send(surface, "ping", {}, uuidv7());
    if (res.ok) {
      const id = identityOf(res.data);
      if (id.protocol !== null && id.protocol !== CUSTODIAN_PROTOCOL_VERSION) return { surface, result: "incompatible", detail: `the custodian speaks protocol ${id.protocol}; this engine speaks ${CUSTODIAN_PROTOCOL_VERSION}`, identity: id };
      return { surface, result: "answers", detail: null, identity: id };
    }
    if (res.code === "CALLER_NOT_AUTHORIZED") return { surface, result: "refused", detail: "the custodian does not serve this account on this surface", identity: null };
    if (res.code === "MALFORMED_REQUEST" && /unsupported protocol version/i.test(res.error ?? "")) return { surface, result: "incompatible", detail: res.error ?? null, identity: null };
    return { surface, result: "unavailable", detail: `${res.code ?? "error"}: ${res.error ?? ""}`.trim(), identity: null };
  } catch (e) {
    if (e instanceof CustodianBusy) return { surface, result: "busy", detail: e.message, identity: null };
    if (e instanceof CustodianNotTrusted) return { surface, result: "untrusted", detail: e.message, identity: null };
    return { surface, result: "unavailable", detail: e instanceof Error ? e.message : String(e), identity: null };
  }
}

/** The host state from the observations, most decisive first. */
export function hostStateOf(platform: NodeJS.Platform, presence: CustodianPresence, managerState: string | null, surfaces: readonly SurfaceProbe[]): HostState {
  if (platform !== "win32" && platform !== "linux") return "unsupported_platform";
  if (presence === "absent") return "not_installed";
  const any = (r: SurfaceProbe["result"]): boolean => surfaces.some((s) => s.result === r);
  if (any("untrusted")) return "untrusted";
  if (any("incompatible")) return "incompatible";
  if (any("answers")) return "ready";
  if (any("busy")) return "busy";
  if (stoppedByManager(platform, managerState)) return "stopped";
  return "unavailable";
}

function explain(s: Pick<ProtectedStatus, "platform" | "state" | "surfaces" | "custodian" | "service">): string[] {
  const p = s.platform;
  const out: string[] = [];
  switch (s.state) {
    case "unsupported_platform":
      out.push(`No CodeParley custodian exists on ${p}: protected loops and delegated fixes need Windows or Linux. Attended reviews, checks and your own decisions work here.`);
      break;
    case "not_installed":
      out.push("The custodian is not installed. Protected loops and delegated fixes are refused (fail-closed); attended reviews are unaffected.");
      break;
    case "stopped":
      out.push(p === "win32"
        ? "The CodeParleyCustodian service is installed but stopped. It starts automatically at boot; an administrator starts it now with `sc.exe start CodeParleyCustodian`."
        : "The custodian's sockets are not listening. An administrator starts them with `sudo systemctl start codeparley-implementer.socket codeparley-operator.socket codeparley-helper.socket`.");
      break;
    case "untrusted":
      out.push(`An endpoint answered that is NOT owned by the custodian (${s.surfaces.find((x) => x.result === "untrusted")?.detail ?? "owner check failed"}). CodeParley refuses it, so no authority went to it. Do not proceed: an administrator checks the host and restarts the custodian.`);
      break;
    case "incompatible":
      out.push(`The custodian and this engine are from different releases (${s.surfaces.find((x) => x.result === "incompatible")?.detail ?? "protocol mismatch"}). Install both from the same CodeParley release.`);
      break;
    case "busy":
      out.push("The custodian is installed and running but busy serving another request; it did not answer within the probe's wait.");
      out.push(BUSY_LIMITATION);
      break;
    case "unavailable":
      out.push(`The custodian is installed (${s.service.manager_state ?? "service state unknown"}) but did not answer. It may still be starting, or it refused to serve its store (an interrupted upgrade or a store from a newer release: the product installer's status says which).`);
      break;
    case "ready":
      if (s.custodian && s.custodian.version !== null && s.custodian.version !== TOOL_VERSION)
        out.push(`The custodian reports release ${s.custodian.version}; this engine is ${TOOL_VERSION}. The protocol matches, so they work together; install both from one release when you can.`);
      if (s.custodian && s.custodian.version === null) out.push("The custodian answered without a release identity (an older build).");
      break;
  }
  const refused = s.surfaces.filter((x) => x.result === "refused" || (x.result === "unavailable" && s.state === "ready"));
  if (s.state === "ready" && refused.length)
    out.push(`This account reaches the ${s.surfaces.filter((x) => x.result === "answers").map((x) => x.surface).join(" and ")} surface only (the ${refused.map((x) => x.surface).join(" and ")} surface is another account's${p === "win32" ? ", or needs an elevated terminal" : ""}).`);
  return out;
}

// ---------------------------------------------------------------------------
// The repository's records
// ---------------------------------------------------------------------------

function same(platform: NodeJS.Platform, a: string, b: string): boolean {
  return platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/** The repository's records as the custodian reports them, each with its restore command. */
export async function repositoryRecords(o: {
  platform: NodeJS.Platform;
  root: string;
  section: ConfigSection;
  grants: GrantSummary[] | null;
  hashFile: (path: string) => Promise<string | null>;
  nowMs: number;
  /** Windows: the implementer's data home, which `setup` reads the approved checks and stored self-tests from (null: a
   * placeholder is shown — the operator's own account does not know it). */
  implementerHome?: string | null;
  exists?: (path: string) => Promise<boolean>;
  builtAt?: (root: string) => Promise<number | null>;
  /** The installed engine runtime's versioned directory (null: none, e.g. a development checkout). */
  installedRuntime?: () => Promise<string | null>;
}): Promise<RecordState[]> {
  const { platform, root, section } = o;
  const op = operatorCli(platform);
  const where = operatorWhere(platform);
  const setup = `${op} setup --repo ${root}`;
  // What `config set` / `confirm-selftest` read locally on Windows: the implementer's approvals and self-tests.
  const home = platform === "win32" ? ` --home "${o.implementerHome ?? "<the implementer's data home>"}"` : "";
  const setupLocal = `${setup}${home}`;
  const resume = `${op} setup --resume --repo ${root}`;
  const linux = platform === "linux";
  const out: RecordState[] = [];

  const rt = section.engineRuntime ?? null;
  if (!rt) out.push({ record: "engine_runtime", state: "missing", required: true, detail: "no engine runtime is approved for the custodian's helper", restore: setup, resumable: false });
  else if (rt.revoked) out.push({ record: "engine_runtime", state: "revoked", required: true, detail: `runtime ${rt.runtimeId} was revoked`, restore: setup, resumable: false });
  else {
    // Certain signs that the approved tree is not the one in use now (the custodian refuses it at its next use, and a
    // re-confirmation would be refused too): the directory is gone (an upgrade removed an older one), the installed
    // engine runtime is another versioned directory (an upgrade keeps the previous one: VERIFIED on both VMs), or the
    // engine there was BUILT after the approval was recorded (its BUILD-ID: reinstalled in place). Anything subtler is
    // the custodian's to find: it re-measures the tree.
    const builtAt = await (o.builtAt ?? runtimeBuiltAt)(rt.root);
    const installed = await (o.installedRuntime ?? (() => installedEngineRuntime(platform)))();
    // setup approves the installed runtime by default; on Windows the operator also names the installed git.
    const approve = linux ? resume : `${resume}${installed ? "" : " --runtime <the installed engine directory>"} --runtime-git-path <installed git.exe>`;
    if (!(await (o.exists ?? pathExists)(rt.root))) out.push({ record: "engine_runtime", state: "changed", required: true, detail: `the approved runtime directory of ${rt.runtimeId} no longer exists (removed by an upgrade?): approve the installed one`, restore: approve, resumable: true });
    else if (installed !== null && !sameRoot(platform, installed, rt.root)) out.push({ record: "engine_runtime", state: "changed", required: true, detail: `the installed engine runtime is ${installed}; the approved one (${rt.runtimeId}) is ${rt.root}: an upgrade installed a new one`, restore: approve, resumable: true });
    else if (builtAt !== null && builtAt > Date.parse(rt.recordedAt)) out.push({ record: "engine_runtime", state: "changed", required: true, detail: `the engine at the approved path was built ${new Date(builtAt).toISOString()}, after runtime ${rt.runtimeId} was approved (${rt.recordedAt}): an upgrade replaced it`, restore: approve, resumable: true });
    else if (rt.lapsed) out.push({ record: "engine_runtime", state: "lapsed", required: true, detail: `runtime ${rt.runtimeId} lapsed after a restart of the OS or a rollback`, restore: resume, resumable: true });
    else out.push({ record: "engine_runtime", state: "in_force", required: true, detail: `runtime ${rt.runtimeId} (${rt.fileCount} files)`, restore: null, resumable: false });
  }

  const r = section.repository;
  if (!r) out.push({ record: "repository", state: "missing", required: true, detail: "no protected configuration is held for this repository", restore: setupLocal, resumable: false });
  else if (r.revoked) out.push({ record: "repository", state: "revoked", required: true, detail: `configuration revision ${r.configRevision} was revoked`, restore: setupLocal, resumable: false });
  else {
    // A Codex update replaces the approved file: compared by its hash, the same way the custodian will refuse it.
    const now = r.codexInstallation ? await o.hashFile(r.codexInstallation.path) : null;
    const changed = r.codexInstallation !== null && now !== null && now !== r.codexInstallation.sha256;
    if (!r.codexInstallation) out.push({ record: "repository", state: "changed", required: true, detail: `configuration revision ${r.configRevision} has no approved Codex installation`, restore: setupLocal, resumable: true });
    else if (changed) out.push({ record: "repository", state: "changed", required: true, detail: `the approved Codex installation changed since revision ${r.configRevision} (SHA-256 ${r.codexInstallation.sha256.slice(0, 12)}… → ${now!.slice(0, 12)}…, an update)`, restore: linux ? `the implementer: code-parley config propose --repo ${root} --out <file>; then ${resume} --proposal-file <file>` : `${resume}${home} --codex <the updated codex.exe>`, resumable: true });
    else if (r.lapsed) out.push({ record: "repository", state: "lapsed", required: true, detail: `configuration revision ${r.configRevision} lapsed after a restart of the OS or a rollback`, restore: resume, resumable: true });
    else out.push({ record: "repository", state: "in_force", required: true, detail: `configuration revision ${r.configRevision}${now === null && r.codexInstallation ? " (the Codex file could not be read here to compare)" : ""}`, restore: null, resumable: false });
  }

  // The isolation basis: an S1 self-test confirmation, or an operator's acceptance of reduced isolation.
  const s1 = section.selftestConfirmations.filter((c) => c.mode !== "FIX" && !c.revoked);
  const acc = section.acceptances.filter((a) => !a.revoked);
  const proposal = (fix: boolean) => `the implementer: code-parley codex ${fix ? "fix-selftest" : "selftest"}, then code-parley config propose-selftest${fix ? " --fix" : ""} --repo ${root} --out <file>; then`;
  const isolationRestore = (fix: boolean, lapsed: boolean): string =>
    linux ? `${proposal(fix)} ${lapsed ? resume : `${op} setup${fix ? " --fix" : ""} --repo ${root}`} --proposal-file <file>` : `${lapsed ? resume : `${op} setup${fix ? " --fix" : ""} --repo ${root}`}${home}`;
  if (s1.some((c) => c.usable) || acc.some((a) => a.usable)) {
    const c = s1.find((x) => x.usable);
    out.push({ record: "isolation", state: "in_force", required: true, detail: c ? `S1 self-test confirmation ${c.confirmationId} (Codex ${c.codexVersion}, ${c.backend})` : `reduced-isolation acceptance ${acc.find((a) => a.usable)!.acceptanceId}`, restore: null, resumable: false });
  } else if (s1.some((c) => c.lapsed) || acc.some((a) => a.lapsed)) {
    // A Linux S1 confirmation is bound to its boot and is never re-confirmed: a new self-test and its proposal.
    out.push({ record: "isolation", state: "lapsed", required: true, detail: linux ? "the S1 self-test confirmation lapsed with the boot it was made on (it is not re-confirmed: a new self-test)" : "the S1 self-test confirmation lapsed after a restart of the OS or a rollback", restore: isolationRestore(false, true), resumable: true });
  } else out.push({ record: "isolation", state: "missing", required: true, detail: "no S1 self-test confirmation (or reduced-isolation acceptance) is in force", restore: isolationRestore(false, false), resumable: false });

  const fixes = section.selftestConfirmations.filter((c) => c.mode === "FIX" && !c.revoked);
  if (fixes.some((c) => c.usable)) out.push({ record: "fix_confirmation", state: "in_force", required: false, detail: `FIX self-test confirmation ${fixes.find((c) => c.usable)!.confirmationId}`, restore: null, resumable: false });
  else if (fixes.some((c) => c.lapsed)) out.push({ record: "fix_confirmation", state: "lapsed", required: false, detail: "the FIX self-test confirmation lapsed (delegated fixes only)", restore: isolationRestore(true, true).replace(resume, `${resume} --fix`), resumable: true });
  else out.push({ record: "fix_confirmation", state: "missing", required: false, detail: "no FIX self-test confirmation (needed for delegated fixes only)", restore: isolationRestore(true, false), resumable: false });

  if (o.grants === null) {
    out.push({ record: "loop_grant", state: "missing", required: false, detail: "the grants could not be listed from this account", restore: `${op} loop allow --repo ${root} ${where}`, resumable: false });
  } else {
    const mine = o.grants.filter((g) => g.repositoryRoot !== null && same(platform, g.repositoryRoot, root) && !g.revoked);
    const active = mine.find((g) => g.active && g.loopsUsed < g.loopsTotal && Date.parse(g.expiresAt) > o.nowMs);
    const allow = `${op} setup --repo ${root} --loops <1-8> --minutes <1-180>`;
    if (active) out.push({ record: "loop_grant", state: "in_force", required: false, detail: `grant ${active.grantId}: ${active.loopsTotal - active.loopsUsed} of ${active.loopsTotal} loop(s) left until ${active.expiresAt}`, restore: null, resumable: false });
    else if (mine.some((g) => g.suspended)) out.push({ record: "loop_grant", state: "suspended", required: false, detail: "the grant was suspended by a restart of the OS or a rollback (a grant never comes back: a new one is needed)", restore: allow, resumable: true });
    else if (mine.some((g) => g.loopsUsed >= g.loopsTotal)) out.push({ record: "loop_grant", state: "used_up", required: false, detail: "every granted loop was used", restore: allow, resumable: true });
    else if (mine.length) out.push({ record: "loop_grant", state: "expired", required: false, detail: "the grant expired", restore: allow, resumable: true });
    else out.push({ record: "loop_grant", state: "missing", required: false, detail: "no loop is granted for this repository (automated loops need one; attended runs do not)", restore: allow, resumable: false });
  }
  return out;
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

export async function protectedStatus(le: Loaded, o: { repositoryRoot?: string | null; hooks?: StatusProbeHooks; nowMs?: number } = {}): Promise<ProtectedStatus> {
  const testHooks = le.env.testHooks?.custodian;
  const platform = testHooks?.platform ?? process.platform;
  const engine = { version: TOOL_VERSION, protocol: CUSTODIAN_PROTOCOL_VERSION };
  const presence = await custodianPresence(le.env.testHooks !== undefined, testHooks);
  const gate = protectedLoopGate(testHooks);
  const managerState = presence === "absent" || !gate.available ? null : await (o.hooks?.managerState ?? (() => hostManagerState(platform)))();
  let surfaces: SurfaceProbe[] = [];
  if (gate.available && presence !== "absent") {
    // A bounded wait: a busy custodian is reported, not waited out (the hooks' own deadline mechanism).
    const before = custodianClientDeadline();
    setCustodianClientDeadline(Date.now() + STATUS_BUSY_WAIT_MS);
    try {
      surfaces = [await probe(gate.transport, "implementer"), await probe(gate.transport, "operator")];
    } finally {
      setCustodianClientDeadline(before);
    }
  }
  const custodian = surfaces.find((s) => s.identity)?.identity ?? null;
  const state = hostStateOf(platform, presence, managerState, surfaces);
  const base = { platform, engine, service: { presence, manager_state: managerState }, surfaces, custodian, state };
  const explanation = explain(base);
  const next: string[] = [];
  let repository: ProtectedStatus["repository"] = null;

  if (o.repositoryRoot) {
    const root = o.repositoryRoot;
    const on = (["operator", "implementer"] as CustodianSurface[]).find((s) => surfaces.some((x) => x.surface === s && x.result === "answers")) ?? null;
    if (state !== "ready" || on === null || !gate.available) repository = { root, state: "unknown", read_on: null, records: [] };
    else {
      let section: ConfigSection | null = null;
      try {
        section = (await new CustodianGrants(gate.transport).listUserRecords(on, root, CONFIG_VIEW_RUN, ["config"])).config ?? null;
      } catch (e) {
        const why = isDomainError(e) || e instanceof Error ? e.message : String(e);
        explanation.push(`The repository's records could not be read (${why}).${/denied access/.test(why) ? " An administrator runs the installer's grant-repository for this repository." : ""}`);
      }
      let grants: GrantSummary[] | null = null;
      try {
        const res = await gate.transport.send(on, "list_grants", {}, uuidv7());
        if (res.ok) grants = grantListingOf(res.data).grants;
      } catch {
        /* reported as "could not be listed" */
      }
      if (!section) repository = { root, state: "unknown", read_on: on, records: [] };
      else {
        const records = await repositoryRecords({ platform, root, section, grants, hashFile: o.hooks?.hashFile ?? sha256OfFile, ...(o.hooks?.exists ? { exists: o.hooks.exists } : {}), ...(o.hooks?.builtAt ? { builtAt: o.hooks.builtAt } : {}), ...(o.hooks?.installedRuntime ? { installedRuntime: o.hooks.installedRuntime } : {}), nowMs: o.nowMs ?? Date.now(), implementerHome: on === "implementer" ? (le.dataHome ?? null) : null });
        repository = { root, state: records.some((r) => r.required && r.state !== "in_force") ? "misconfigured" : "ready", read_on: on, records };
        for (const r of records) if (r.restore && (r.required || r.state !== "missing")) next.push(r.restore);
      }
    }
  }
  if (state === "not_installed") next.push(platform === "linux" ? "sudo bash codeparley-installer.sh install --release <dir> --implementer <login> --operator <login>" : "codeparley-installer.ps1 install -Release <dir> -Operator <DOMAIN\\admin> -Implementer <DOMAIN\\user> (elevated PowerShell)");
  return { ...base, explanation, repository, next: [...new Set(next)] };
}
