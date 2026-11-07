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
import type { SandboxBackend } from "../agents/codex/argv.js";
import type { IsolationDecision } from "../agents/codex/isolation.js";
import { probeCodex, type CodexProbe } from "../agents/codex/probe.js";
import type { SelfTestRecord } from "../schemas/review.js";
import { confirmedFixSelfTest, confirmedSelfTest, namesFixRecord, namesS1Record, protectedIsolationDecision, reviewBackends, storedS1SelfTest, type StoredFixIdentity } from "./protected-config.js";

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
export type RecordStateValue = "in_force" | "lapsed" | "changed" | "missing" | "revoked" | "suspended" | "used_up" | "expired" | "unconfirmed" | "unverified";

/**
 * Step 7.2 (F-S71-2): why a self-test row is what it is. `record_*`: the stored record protected execution would use was
 * read (missing, not passing, or not the one the custodian's confirmation covers) — `unconfirmed`. The others: it could
 * not be read or compared from this account — `unverified`, which is NOT established, never "misconfigured".
 */
export type RecordReason = "record_missing" | "record_failed" | "record_changed" | "store_inaccessible" | "not_compared" | "probe_failed" | "no_installation";

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
  /** Step 7.2: for the S1 and FIX rows, why they are unconfirmed or unverified. */
  reason?: RecordReason;
}

/** Step 7.2: what a protected review and a delegated fix would use on this host (null fields: not determined). */
export interface ProtectedPath {
  /** The approved Codex installation the custodian holds (what both launch). */
  codex_path: string;
  codex_version: string | null;
  /** The backends a protected review considers, in order (the review's own rule). */
  s1_backends: string[];
  /** The backend a delegated fix runs on (the delegation's own rule). */
  fix_backend: string | null;
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
  repository: { root: string; state: RepositoryState; read_on: CustodianSurface | null; records: RecordState[]; protected_path?: ProtectedPath | null } | null;
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
// Step 7.2 (F-S71-2): the stored self-tests protected execution would use
// ---------------------------------------------------------------------------

/** What a protected review would load and decide: its backends, the stored S1 record per backend, and its isolation
 * decision over the custodian's records — computed with the review's own functions (engine/protected-config.ts). */
export interface S1Evidence {
  codexVersion: string;
  backends: SandboxBackend[];
  stored: { backend: SandboxBackend; record: SelfTestRecord | null }[];
  decision: IsolationDecision;
}

/** What a delegated fix would use: the stored FIX self-test as the delegation reads it (null, with the delegation's own
 * refusal in `why`, when it has none it could use). */
export interface FixEvidence {
  codexVersion: string;
  backend: string;
  local: StoredFixIdentity | null;
  why: string | null;
}

/** Why the stored self-tests could not be observed from this account. */
export type NotObservedReason = Extract<RecordReason, "store_inaccessible" | "not_compared" | "probe_failed" | "no_installation">;

/** An observation of the implementer's stored self-tests, or why it could not be made from this account. `s2`: the
 * acceptance of reduced isolation a review would use without any S1 record (S2 needs no stored record). */
export type Observed<T> =
  | { ok: true; value: T }
  | { ok: false; reason: NotObservedReason; why: string; verify: string | null; s2?: { acceptanceId: string; backend: string } | null };

/** Reads the stored FIX self-test the delegation would use. Supplied by the CLI: this module imports no fixer module. */
export type FixEvidenceReader = (probe: CodexProbe) => Promise<FixEvidence>;

function s2Of(d: IsolationDecision): { acceptanceId: string; backend: string } | null {
  return d.ok && d.isolation.mode === "S2" && d.isolation.acceptance_id ? { acceptanceId: d.isolation.acceptance_id, backend: d.isolation.backend } : null;
}

function notObserved<T>(reason: NotObservedReason, why: string, verify: string | null, s2: { acceptanceId: string; backend: string } | null = null): Observed<T> {
  return { ok: false, reason, why, verify, s2 };
}

/** Observe, read-only, the stored self-tests a protected review (S1) and a delegated fix (FIX) of this repository would
 * use, with the functions they use themselves. Nothing is run, written or confirmed. */
export async function observeStoredSelfTests(le: Loaded, o: { platform: NodeJS.Platform; root: string; on: CustodianSurface; section: ConfigSection; fix?: FixEvidenceReader }): Promise<{ s1: Observed<S1Evidence>; fix: Observed<FixEvidence>; path: ProtectedPath | null }> {
  const { platform, root, on, section } = o;
  const repo = section.repository;
  const inst = repo && !repo.revoked ? repo.codexInstallation : null;
  if (!inst) {
    const why = "no approved Codex installation is held, so the stored self-test protected execution would use cannot be determined";
    return { s1: notObserved("no_installation", why, null), fix: notObserved("no_installation", why, null), path: null };
  }
  const unread: ProtectedPath = { codex_path: inst.path, codex_version: null, s1_backends: [], fix_backend: null };
  const implementerStatus = `the implementer: code-parley status --repo ${root}`;
  // Linux: the operator account cannot read the implementer's files, by design (Phase 5 G-OP); nothing is tried.
  if (platform === "linux" && on === "operator") {
    const why = "the implementer's self-test store is not readable from the operator account (by design); the implementer's own status compares it with the custodian's confirmations";
    return { s1: notObserved("store_inaccessible", why, implementerStatus), fix: notObserved("store_inaccessible", why, implementerStatus), path: unread };
  }
  let probe: CodexProbe;
  try {
    probe = await probeCodex({ configured: inst.path, sourceEnv: le.env.sourceEnv, testLauncher: le.env.testHooks?.review?.codexLauncher ?? null });
  } catch (e) {
    const why = `the approved Codex installation ${inst.path} could not be probed (${(e instanceof Error ? e.message : String(e)).slice(0, 200)})`;
    return { s1: notObserved("probe_failed", why, "code-parley doctor"), fix: notObserved("probe_failed", why, "code-parley doctor"), path: unread };
  }
  // The review's rules on this host (the review decides with process.platform).
  const backends = reviewBackends(process.platform, le.cfg.config.codex.windows_sandbox, probe);
  const path: ProtectedPath = { codex_path: inst.path, codex_version: probe.version, s1_backends: [...backends], fix_backend: null };
  const s2 = s2Of(protectedIsolationDecision(section, probe, backends, new Map()));
  // Windows: the elevated operator reads the implementer's store only through --home (as setup's commands do).
  if (platform === "win32" && on === "operator" && !le.env.launch.home) {
    const why = "this account's data home is not the implementer's, so the stored self-tests were not compared";
    const verify = `${operatorCli(platform)} status --repo ${root} --home "<the implementer's data home>" (or ${implementerStatus})`;
    return { s1: notObserved("not_compared", why, verify, s2), fix: notObserved("not_compared", why, verify), path };
  }
  const homeGone = await stat(le.dataHome).then(
    () => null,
    (e: NodeJS.ErrnoException) => (e.code === "ENOENT" ? `there is no CodeParley data home at ${le.dataHome}` : `the data home ${le.dataHome} cannot be read (${e.code ?? e.message})`),
  );
  if (homeGone) return { s1: notObserved("store_inaccessible", homeGone, implementerStatus, s2), fix: notObserved("store_inaccessible", homeGone, implementerStatus), path };
  let s1: Observed<S1Evidence>;
  try {
    const stored: S1Evidence["stored"] = [];
    for (const b of backends) stored.push({ backend: b, record: await storedS1SelfTest(le.layout.selftestDir, probe, b) });
    // Exactly the review's selection: a stored record counts only if a usable confirmation covers it.
    const selfTests = new Map(stored.map((x) => [x.backend, x.record && confirmedSelfTest(section, x.record) ? x.record : null] as const));
    s1 = { ok: true, value: { codexVersion: probe.version, backends, stored, decision: protectedIsolationDecision(section, probe, backends, selfTests) } };
  } catch (e) {
    s1 = notObserved("store_inaccessible", `the stored S1 self-tests cannot be read (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`, implementerStatus, s2);
  }
  let fix: Observed<FixEvidence>;
  if (!o.fix) fix = notObserved("not_compared", "the stored FIX self-test is compared by `code-parley status`", `code-parley status --repo ${root}`);
  else {
    try {
      const value = await o.fix(probe);
      path.fix_backend = value.backend;
      fix = { ok: true, value };
    } catch (e) {
      fix = notObserved("store_inaccessible", `the stored FIX self-test cannot be read (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`, implementerStatus);
    }
  }
  return { s1, fix, path };
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
  /** F-S71-1: the identity the custodian resolved `root` to (`list_user_records`' repoKey); null when it reported none.
   * A grant applies to this directory only if its repoKey is this one — as the custodian itself authorizes loops. */
  repoKey: string | null;
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
  /** Step 7.2: the stored S1 and FIX self-tests protected execution would use, as observed from this account (absent:
   * not compared). Every S1/FIX row is classified against them, never on the custodian's records alone. */
  s1?: Observed<S1Evidence>;
  fix?: Observed<FixEvidence>;
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
  // Step 7.2 (F-S71-2): a confirmation counts only for the stored record protected execution would use, observed with
  // the execution path's own functions; a custodian-only fact (lapsed, revoked, missing) only where no local fact decides.
  const notObservedRow = (record: "isolation" | "fix_confirmation", required: boolean, o: Exclude<Observed<unknown>, { ok: true }> | undefined): RecordState => {
    const reason = o?.reason ?? "not_compared";
    const why = o?.why ?? "the stored self-test was not compared";
    const verify = o ? o.verify : `code-parley status --repo ${root}`;
    return { record, state: "unverified", required, detail: `a usable confirmation is held, but it is not established that it covers the stored self-test: ${why}`, restore: verify, resumable: false, reason };
  };
  // The commands that confirm the current stored record (rerun: the implementer runs the self-test first).
  const step = (fix: boolean, resumeIt: boolean) => (resumeIt ? `${resume}${fix ? " --fix" : ""}` : `${op} setup${fix ? " --fix" : ""} --repo ${root}`);
  const confirmCmd = (fix: boolean, resumeIt: boolean, rerun: string | null): string =>
    linux
      ? `the implementer: ${rerun !== null ? `code-parley codex ${fix ? "fix-selftest" : "selftest"}, then ` : ""}code-parley config propose-selftest${fix ? " --fix" : ""} --repo ${root} --out <file>; then ${step(fix, resumeIt)} --proposal-file <file>`
      : `${rerun !== null ? `the implementer: code-parley codex ${fix ? "fix-selftest" : "selftest"}${rerun ? ` --backend ${rerun}` : ""} in an interactive desktop session; then ` : ""}${step(fix, resumeIt)}${home}`;
  const covers = (cs: typeof section.selftestConfirmations) => cs.map((c) => `confirmation ${c.confirmationId} covers self-test ${c.selftestId} (Codex ${c.codexVersion}, ${c.backend}${c.lapsed ? ", lapsed" : ""})`).join("; ");

  const allS1 = section.selftestConfirmations.filter((c) => c.mode !== "FIX");
  const revokedS1 = allS1.filter((c) => c.revoked);
  const lapsedRow = (): RecordState =>
    // A Linux S1 confirmation is bound to its boot and is never re-confirmed: a new self-test and its proposal.
    ({ record: "isolation", state: "lapsed", required: true, detail: linux ? "the S1 self-test confirmation lapsed with the boot it was made on (it is not re-confirmed: a new self-test)" : "the S1 self-test confirmation lapsed after a restart of the OS or a rollback", restore: isolationRestore(false, true), resumable: true });
  const ev = o.s1;
  if (ev?.ok) {
    const { decision: d, stored, codexVersion, backends } = ev.value;
    const recs = stored.filter((x): x is { backend: SandboxBackend; record: SelfTestRecord } => x.record !== null);
    if (d.ok && d.isolation.mode === "S1") {
      const rec = recs.find((x) => x.backend === d.isolation.backend)!.record;
      const c = s1.find((x) => x.usable && namesS1Record(x, rec));
      out.push({ record: "isolation", state: "in_force", required: true, detail: `S1 self-test confirmation ${c?.confirmationId ?? "?"} covers the stored self-test ${rec.selftest_id} (Codex ${codexVersion}, ${rec.backend})`, restore: null, resumable: false });
    } else {
      // What the stored record(s) are against the custodian's confirmations, for the detail and the restore.
      const usableOrLapsed = s1.filter((c) => c.usable || c.lapsed);
      const passing = recs.filter((x) => x.record.profile_runs && x.record.s1_available);
      const reason: RecordReason = !recs.length ? "record_missing" : !passing.length ? "record_failed" : "record_changed";
      const s1Why =
        reason === "record_missing"
          ? `no stored S1 self-test of Codex ${codexVersion} on ${backends.join(" or ")} (the installation the custodian approved)`
          : reason === "record_failed"
            ? `the stored S1 self-test ${recs[0]!.record.selftest_id} (Codex ${codexVersion}, ${recs[0]!.backend}) did not pass`
            : `the stored S1 self-test ${passing[0]!.record.selftest_id} (Codex ${codexVersion}, ${passing[0]!.backend}) is not the one confirmed${usableOrLapsed.length ? ` (${covers(usableOrLapsed)})` : ""}`;
      if (d.ok) {
        // Explicitly accepted reduced isolation (S2): the review would run with it; S1 is named beside it.
        out.push({ record: "isolation", state: "in_force", required: true, detail: `reduced isolation (S2): the operator's acceptance ${d.isolation.acceptance_id} for ${d.isolation.backend}; S1 is not established (${s1Why})`, restore: null, resumable: false });
      } else if (recs.some((x) => s1.some((c) => c.lapsed && namesS1Record(c, x.record))) || acc.some((a) => a.lapsed)) {
        out.push(lapsedRow());
      } else if (recs.some((x) => revokedS1.some((c) => namesS1Record(c, x.record)))) {
        // The operator revoked the confirmation of THIS record: never restored by --resume.
        out.push({ record: "isolation", state: "revoked", required: true, detail: `the confirmation of the stored S1 self-test ${recs.find((x) => revokedS1.some((c) => namesS1Record(c, x.record)))!.record.selftest_id} was revoked (setup --resume does not restore it)`, restore: confirmCmd(false, false, null), resumable: false });
      } else if (usableOrLapsed.length || acc.length) {
        // A historical confirmation exists, but not for the record a protected review would use (F-S71-2).
        out.push({ record: "isolation", state: "unconfirmed", required: true, detail: `${usableOrLapsed.some((c) => c.usable) ? "a usable S1 confirmation is held, but " : ""}${s1Why}: a protected review is refused (CODEX_ISOLATION_UNAVAILABLE) until the operator confirms the stored one`, restore: confirmCmd(false, true, reason === "record_changed" ? null : (backends[0] ?? "")), resumable: true, reason });
      } else if (revokedS1.length || section.acceptances.some((a) => a.revoked)) {
        out.push({ record: "isolation", state: "revoked", required: true, detail: "every S1 self-test confirmation (or acceptance) was revoked (setup --resume does not restore it)", restore: isolationRestore(false, false), resumable: false });
      } else out.push({ record: "isolation", state: "missing", required: true, detail: "no S1 self-test confirmation (or reduced-isolation acceptance) is in force", restore: isolationRestore(false, false), resumable: false });
    }
  } else if (ev && !ev.ok && ev.s2) {
    out.push({ record: "isolation", state: "in_force", required: true, detail: `reduced isolation (S2): the operator's acceptance ${ev.s2.acceptanceId} for ${ev.s2.backend}; whether a confirmed S1 self-test applies was not compared (${ev.why})`, restore: null, resumable: false });
  } else if (s1.some((c) => c.usable) || acc.some((a) => a.usable)) {
    out.push(notObservedRow("isolation", true, ev));
  } else if (s1.some((c) => c.lapsed) || acc.some((a) => a.lapsed)) {
    out.push(lapsedRow());
  } else if (revokedS1.length || section.acceptances.some((a) => a.revoked)) {
    out.push({ record: "isolation", state: "revoked", required: true, detail: "every S1 self-test confirmation (or acceptance) was revoked (setup --resume does not restore it)", restore: isolationRestore(false, false), resumable: false });
  } else out.push({ record: "isolation", state: "missing", required: true, detail: "no S1 self-test confirmation (or reduced-isolation acceptance) is in force", restore: isolationRestore(false, false), resumable: false });

  // The FIX confirmation (delegated fixes only; optional for readiness).
  const allFix = section.selftestConfirmations.filter((c) => c.mode === "FIX");
  const fixes = allFix.filter((c) => !c.revoked);
  const revokedFix = allFix.filter((c) => c.revoked);
  const fixLapsedRow = (): RecordState => ({ record: "fix_confirmation", state: "lapsed", required: false, detail: "the FIX self-test confirmation lapsed (delegated fixes only)", restore: isolationRestore(true, true).replace(resume, `${resume} --fix`), resumable: true });
  const fixMissingRow = (): RecordState => ({ record: "fix_confirmation", state: "missing", required: false, detail: "no FIX self-test confirmation (needed for delegated fixes only)", restore: isolationRestore(true, false), resumable: false });
  const fixRevokedRow = (what: string): RecordState => ({ record: "fix_confirmation", state: "revoked", required: false, detail: `${what} (setup --resume does not restore it; delegated fixes only)`, restore: confirmCmd(true, false, null), resumable: false });
  const fx = o.fix;
  if (fx?.ok) {
    const { local, why, backend, codexVersion } = fx.value;
    const c = local ? confirmedFixSelfTest(section, local) : undefined;
    if (local && c) out.push({ record: "fix_confirmation", state: "in_force", required: false, detail: `FIX self-test confirmation ${c.confirmationId} covers the stored FIX self-test ${local.selftestId} (Codex ${codexVersion}, ${backend})`, restore: null, resumable: false });
    else if (local && fixes.some((x) => x.lapsed && namesFixRecord(x, local))) out.push(fixLapsedRow());
    else if (local && revokedFix.some((x) => namesFixRecord(x, local))) out.push(fixRevokedRow(`the confirmation of the stored FIX self-test ${local.selftestId} was revoked`));
    else if (fixes.length) {
      const reason: RecordReason = local ? "record_changed" : "record_missing";
      const what = local
        ? `the stored FIX self-test ${local.selftestId} (Codex ${codexVersion}, binary ${local.codexSha256.slice(0, 12)}…, ${backend}) is not the one confirmed (${fixes.map((x) => `confirmation ${x.confirmationId} covers self-test ${x.selftestId}, binary ${(x.codexSha256 ?? "none").slice(0, 12)}…`).join("; ")})`
        : `no stored FIX self-test the delegation could use (${why ?? "none"})`;
      out.push({ record: "fix_confirmation", state: "unconfirmed", required: false, detail: `${fixes.some((x) => x.usable) ? "a usable FIX confirmation is held, but " : ""}${what}: a delegated fix is refused until the operator confirms the stored one`, restore: confirmCmd(true, true, local ? null : backend), resumable: true, reason });
    } else if (revokedFix.length) out.push(fixRevokedRow("every FIX self-test confirmation was revoked"));
    else out.push(fixMissingRow());
  } else if (fixes.some((c) => c.usable)) out.push(notObservedRow("fix_confirmation", false, fx));
  else if (fixes.some((c) => c.lapsed)) out.push(fixLapsedRow());
  else if (revokedFix.length) out.push(fixRevokedRow("every FIX self-test confirmation was revoked"));
  else out.push(fixMissingRow());

  if (o.grants === null) {
    out.push({ record: "loop_grant", state: "missing", required: false, detail: "the grants could not be listed from this account", restore: `${op} loop allow --repo ${root} ${where}`, resumable: false });
  } else {
    // F-S71-1: a grant is this directory's only by the identity the custodian resolved it to now (the custodian
    // authorizes loops by that key), never by its path: a directory replaced at the same path is another directory.
    // Without the identity, no grant is shown as in force.
    const mine = o.repoKey === null ? [] : o.grants.filter((g) => g.repoKey === o.repoKey && !g.revoked);
    const active = mine.find((g) => g.active && g.loopsUsed < g.loopsTotal && Date.parse(g.expiresAt) > o.nowMs);
    const allow = `${op} setup --repo ${root} --loops <1-8> --minutes <1-180>`;
    // Grants recorded at this path for another identity (a replaced directory, or before P3.4C-0): shown, never counted.
    const elsewhere = o.grants.filter((g) => !g.revoked && g.repositoryRoot !== null && same(platform, g.repositoryRoot, root) && (o.repoKey === null || g.repoKey !== o.repoKey));
    const staleActive = elsewhere.find((g) => g.active && g.loopsUsed < g.loopsTotal && Date.parse(g.expiresAt) > o.nowMs);
    // This directory's own grants decide first; another directory's is only explained when this one has none.
    if (active) out.push({ record: "loop_grant", state: "in_force", required: false, detail: `grant ${active.grantId}: ${active.loopsTotal - active.loopsUsed} of ${active.loopsTotal} loop(s) left until ${active.expiresAt}`, restore: null, resumable: false });
    else if (mine.some((g) => g.suspended)) out.push({ record: "loop_grant", state: "suspended", required: false, detail: "the grant was suspended by a restart of the OS or a rollback (a grant never comes back: a new one is needed)", restore: allow, resumable: true });
    else if (mine.some((g) => g.loopsUsed >= g.loopsTotal)) out.push({ record: "loop_grant", state: "used_up", required: false, detail: "every granted loop was used", restore: allow, resumable: true });
    else if (mine.length) out.push({ record: "loop_grant", state: "expired", required: false, detail: "the grant expired", restore: allow, resumable: true });
    else if (o.repoKey === null && staleActive) out.push({ record: "loop_grant", state: "missing", required: false, detail: `grant ${staleActive.grantId} names this path, but the custodian did not report this directory's identity (an older custodian), so no grant is shown as in force here; the custodian decides when a loop starts`, restore: allow, resumable: false });
    else if (staleActive) out.push({ record: "loop_grant", state: "missing", required: false, detail: `grant ${staleActive.grantId} was made for another directory at this path (identity ${staleActive.repoKey}; this directory is ${o.repoKey}): it does not authorize loops here, so a new grant is needed (automated loops need one; attended runs do not)`, restore: allow, resumable: true });
    else out.push({ record: "loop_grant", state: "missing", required: false, detail: "no loop is granted for this repository (automated loops need one; attended runs do not)", restore: allow, resumable: false });
  }
  return out;
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/** The repository's state from its records: `misconfigured` when a required record is known not to be in force; else
 * `unknown` when a required record could not be verified from this account (Step 7.2: not established); else `ready`. */
export function repositoryStateOf(records: readonly RecordState[]): RepositoryState {
  if (records.some((r) => r.required && r.state !== "in_force" && r.state !== "unverified")) return "misconfigured";
  if (records.some((r) => r.required && r.state === "unverified")) return "unknown";
  return "ready";
}

export async function protectedStatus(le: Loaded, o: { repositoryRoot?: string | null; hooks?: StatusProbeHooks; nowMs?: number; fix?: FixEvidenceReader } = {}): Promise<ProtectedStatus> {
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
      let repoKey: string | null = null;
      try {
        const listing = await new CustodianGrants(gate.transport).listUserRecords(on, root, CONFIG_VIEW_RUN, ["config"]);
        section = listing.config ?? null;
        repoKey = listing.repoKey;
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
        const observed = await observeStoredSelfTests(le, { platform, root, on, section, ...(o.fix ? { fix: o.fix } : {}) });
        const records = await repositoryRecords({ platform, root, repoKey, section, grants, hashFile: o.hooks?.hashFile ?? sha256OfFile, ...(o.hooks?.exists ? { exists: o.hooks.exists } : {}), ...(o.hooks?.builtAt ? { builtAt: o.hooks.builtAt } : {}), ...(o.hooks?.installedRuntime ? { installedRuntime: o.hooks.installedRuntime } : {}), nowMs: o.nowMs ?? Date.now(), implementerHome: on === "implementer" ? (le.dataHome ?? null) : null, s1: observed.s1, fix: observed.fix });
        repository = { root, state: repositoryStateOf(records), read_on: on, records, protected_path: observed.path };
        for (const r of records) if (r.restore && (r.required || r.state !== "missing")) next.push(r.restore);
      }
    }
  }
  if (state === "not_installed") next.push(platform === "linux" ? "sudo bash codeparley-installer.sh install --release <dir> --implementer <login> --operator <login>" : "codeparley-installer.ps1 install -Release <dir> -Operator <DOMAIN\\admin> -Implementer <DOMAIN\\user> (elevated PowerShell)");
  return { ...base, explanation, repository, next: [...new Set(next)] };
}
