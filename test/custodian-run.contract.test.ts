// P3.4C-3 contract test: the custodian-owned run records (run_transition, the run section of list_user_records,
// consume_loop's open-run precondition, the loop's run-record check and protected decision freshness) against the
// shared corpus test/fixtures/run-transition-corpus.json. The SAME corpus is run against the real custodian's ledger
// by `CodeParley.Custodian.exe self-test-run-corpus` (and here too, when a built custodian exists on Windows), so the
// simulated custodian the engine tests use and the real custodian obey one observable behaviour. Platform-independent:
// no pipe, no service; the process facts are a fixed table (the C# runner's), switched per step.

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../src/common/hash.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import { SimulatedCustodianTransport, filesystemIdentity } from "../src/custodian/transport.js";
import { escapeText } from "../src/custodian/render-escape.js";
import type { SimBoundProcess, SimProcessCheck } from "../src/custodian/simulated-loops.js";
import type { SimWriter } from "../src/custodian/simulated-runs.js";
import type { CustodianResponse, CustodianSurface } from "../src/custodian/protocol.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CORPUS_PATH = join(ROOT, "test", "fixtures", "run-transition-corpus.json");

type Json = Record<string, unknown>;
interface Step extends Json {
  op: "t" | "mint" | "bind" | "loop" | "replay" | "list" | "amend" | "decide" | "commit" | "dropRun" | "grant" | "config" | "revokeGlobal" | "recover" | "capture" | "tamper" | "restart" | "measure" | "derive" | "exports" | "orphan" | "sweep" | "advance" | "fixConfirm" | "held" | "orphanProposal" | "fixPrepare" | "fixRender" | "fixList" | "repo" | "moveRepo" | "unpin" | "grantIdentity";
}
interface Scenario {
  name: string;
  grant?: boolean | number;
  config?: boolean;
  steps: Step[];
}
interface CorpusConfig {
  payload: Json & { checks: Record<string, Json> };
  digests: Record<string, string>;
  captureRulesDigest: string;
  codexSha256: string;
  selftest: Json;
  acceptance: Json;
  /** Phase 4 Increment 2: the FIX self-test confirmation a delegated fix rests on (separate from S1). */
  fixSelftest: Json;
}
const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8")) as { templates: Record<string, Json>; scenarios: Scenario[]; config: CorpusConfig };
/** P3.4C-5 Increment 3: the run.json bytes a corpus derivation sends (RunSelfTest.RunJsonText; its digest is $runJson). */
const CORPUS_RUN_JSON = Buffer.from('{"schema":"selftest"}', "utf8");

/** P3.4C-4: the corpus's Codex installation — a 512-byte PE image (config.pe), `variant` at 0x100. */
function corpusPe(variant = 0): Buffer {
  const b = Buffer.alloc(512);
  b.write("MZ", 0, "latin1");
  b[0x3c] = 0x80;
  b.write("PE", 0x80, "latin1");
  b[0x84] = 0x64;
  b[0x85] = 0x86;
  b[0x100] = variant;
  return b;
}

// The fixed process facts (the C# runner's table): the Claude process the loop binds to; the engine, the writer of
// what it sends; a shell inside the session's tree; an unrelated process.
const CLAUDE = 100;
const CLAUDE_START = 1_000;
const ENGINE: SimWriter = { pid: 200, startedAtMs: 11_000, imageName: "node.exe" };
const SHELL: SimWriter = { pid: 250, startedAtMs: 13_000, imageName: "pwsh.exe" };
const UNRELATED: SimWriter = { pid: 400, startedAtMs: 6_000, imageName: "evil.exe" };

/** The OS facts of one step (independent of every request field). */
interface Mode {
  client: string | null;
  writer: string | null;
  writerState: string | null;
}

const fixedProcessCheck = (pid: number | null): SimProcessCheck =>
  pid === CLAUDE ? { pid, startedAtMs: CLAUDE_START, clientPid: 300, verified: true, detail: "an ancestor of the connected process" } : { pid, startedAtMs: null, clientPid: 300, verified: false, detail: "not an ancestor of the connected process" };

function clientVerdict(bound: SimBoundProcess, client: string | null): SimProcessCheck {
  const refused = (detail: string): SimProcessCheck => ({ pid: bound.pid, startedAtMs: bound.startedAtMs, clientPid: 300, verified: false, detail });
  if (bound.pid !== CLAUDE || bound.startedAtMs !== CLAUDE_START) return refused("the binding records another process");
  if (client === "ended") return refused(`process ${CLAUDE} is not running`);
  if (client === "reused") return refused(`process ${CLAUDE} is not the process the loop was bound to: the process id was reused`);
  if (client === "outsider") return refused(`process ${CLAUDE} is not an ancestor of the process connected to the custodian`);
  if (client !== null) throw new Error(`unknown corpus client ${client}`);
  return { pid: CLAUDE, startedAtMs: CLAUDE_START, clientPid: 300, verified: true, detail: "an ancestor of the connected process" };
}

const writerOf = (m: Mode): SimWriter => (m.client === "outsider" ? UNRELATED : m.writer === "other" ? SHELL : ENGINE);

function writerGone(m: Mode, w: SimWriter): boolean | null {
  if (m.writerState === "unreadable") return null;
  if (m.writerState === "gone" && w.pid === ENGINE.pid) return true;
  return ![ENGINE, SHELL, UNRELATED].some((x) => x.pid === w.pid && x.startedAtMs === w.startedAtMs);
}

interface Sent {
  surface: CustodianSurface;
  args: Json;
  requestId: string;
  mode: Mode;
}

class Runner {
  private readonly nonces = new Map<string, string>();
  private readonly ops = new Map<string, string>();
  private readonly derivations = new Map<string, string>();
  private readonly amendments = new Map<string, string>();
  private readonly intents = new Map<string, string>();
  private readonly sent = new Map<string, Sent>();
  /** Step 7.1: the scenario's named directories (main: the repository; other; moved) with their canonical paths when named,
   * and the listing entries captured as selections (RunCorpusSelfTest). */
  private readonly paths = new Map<string, { path: string; canonical: string }>();
  private readonly selections = new Map<string, Json>();
  private generated = 0;
  private stepNo = 0;
  private acceptanceId: string | null = null;
  private confirmationId: string | null = null;
  private fixConfirmationId: string | null = null;

  constructor(
    private readonly t: SimulatedCustodianTransport,
    private readonly repo: string,
    private readonly mode: Mode,
    private readonly scratch: string,
    /** P3.4C-5 Increment 3 (N5-5): each derive step's snapshot, by step number (from 1), for the parity oracle. */
    private readonly snapshots: Map<number, unknown> | null = null,
    /** P3.4C-5 Increment 4: the scenario's clock (the `advance` step moves it). */
    private readonly clock: { now: number } = { now: Date.now() },
  ) {}

  /** Step 7.1: the scenario's directory named `name` (main is the repository; any other a new directory beside it). */
  private namedPath(name: string): string {
    const known = this.paths.get(name);
    if (known) return known.path;
    const path = name === "main" ? this.repo : join(this.scratch, "repos", name);
    mkdirSync(path, { recursive: true });
    this.paths.set(name, { path, canonical: filesystemIdentity(path).canonicalPath });
    return path;
  }

  /** Step 7.1: a listing as the corpus compares it (RunCorpusSelfTest.ListingSummary). */
  private listingSummary(listing: Json): Json {
    const nameOf = (p: unknown): string => {
      if (typeof p !== "string") return "-";
      for (const [name, { canonical }] of this.paths) if (process.platform === "win32" ? canonical.toLowerCase() === p.toLowerCase() : canonical === p) return name;
      return "?";
    };
    const entries = ((listing["entries"] ?? []) as Json[]).map((e) => {
      const alias = [...this.ops].find(([, id]) => id === e["operationId"])?.[0] ?? "?";
      let where = typeof e["repositoryRoot"] === "string" ? nameOf(e["repositoryRoot"]) : typeof e["lastKnownPath"] === "string" ? `last:${nameOf(e["lastKnownPath"])}` : "-";
      if (typeof e["repositoryRoot"] === "string" && e["repositoryDisplay"] !== escapeText(e["repositoryRoot"])) where += "!display";
      if ((e["selectable"] === true) !== (typeof e["renderingDigest"] === "string")) where += "!digest";
      return `${String(e["state"])} ${e["selectable"] === true ? "selectable" : "-"} ${alias} ${typeof e["reasonCode"] === "string" ? e["reasonCode"] : "-"} ${where}`;
    });
    return { schema: listing["schema"] ?? null, total: listing["total"] ?? null, truncated: listing["truncated"] ?? null, omittedPending: listing["omittedPending"] ?? null, entries };
  }

  /** The corpus's Codex installation (variant 0 by default) written below the scenario's scratch directory. */
  private pe(variant = 0): string {
    const dir = join(this.scratch, "codex", `v${variant}`);
    mkdirSync(dir, { recursive: true });
    const path = join(dir, "codex.exe");
    writeFileSync(path, corpusPe(variant));
    return path;
  }

  private async configSection(): Promise<Json> {
    const res = await this.t.send("operator", "list_user_records", { repositoryRoot: this.repo, runId: "config-view", sections: ["config"] }, `list-${++this.generated}`);
    return res.data?.["config"] as Json;
  }

  private async prepareAndCommit(args: Json): Promise<CustodianResponse> {
    const rid = `cfg-${++this.generated}`;
    const prep = await this.t.send("operator", "prepare_config_record", args, rid);
    if (!prep.ok) return prep;
    return this.t.send("operator", "commit", { authorizationRequestId: rid }, `commit-${++this.generated}`);
  }

  private payloadOf(overlay: Json | undefined, codex: unknown): Json {
    const base = structuredClone(corpus.config.payload) as Json;
    for (const [k, v] of Object.entries(overlay ?? {})) {
      if (k === "checks") {
        const checks: Json = {};
        for (const [n, d] of Object.entries(v as Json)) checks[n] = typeof (d as Json)["$from"] === "string" ? structuredClone(corpus.config.payload.checks[(d as Json)["$from"] as string]) : d;
        base[k] = checks;
      } else base[k] = v;
    }
    base["codexPath"] = codex === "none" ? null : typeof codex === "string" && codex.startsWith("variant:") ? this.pe(Number(codex.slice(8))) : this.pe(0);
    return base;
  }

  /** P3.4C-4: the corpus's protected configuration (config.*), set as the operator would; returns a parity problem. */
  async holdConfig(): Promise<string | null> {
    const set = await this.prepareAndCommit({ repositoryRoot: this.repo, recordKind: "repository", action: "set", payload: this.payloadOf(undefined, undefined), baseRevision: 0 });
    if (!set.ok) return `config set: ${set.code} ${set.error}`;
    const conf = await this.prepareAndCommit({ recordKind: "selftest_confirmation", action: "set", payload: corpus.config.selftest, baseRevision: Number((await this.configSection())["globalRevision"]) });
    if (!conf.ok) return `confirm self-test: ${conf.code} ${conf.error}`;
    this.confirmationId = String(conf.data?.["recordId"]);
    const acc = await this.prepareAndCommit({ recordKind: "isolation_acceptance", action: "set", payload: corpus.config.acceptance, baseRevision: Number((await this.configSection())["globalRevision"]) });
    if (!acc.ok) return `accept isolation: ${acc.code} ${acc.error}`;
    this.acceptanceId = String(acc.data?.["recordId"]);
    // The digest parity oracle: what the (simulated) custodian computed is exactly the corpus's pinned digests.
    const r = (await this.configSection())["repository"] as Json;
    const got = Object.fromEntries(Object.entries(r["checks"] as Record<string, Json>).map(([n, c]) => [n, c["definitionDigest"]]));
    if (canonicalize(got) !== canonicalize(corpus.config.digests)) return `definition digests ${JSON.stringify(got)} are not the corpus's`;
    if (r["captureRulesDigest"] !== corpus.config.captureRulesDigest) return `capture-rules digest ${String(r["captureRulesDigest"])} is not the corpus's`;
    if ((r["codexInstallation"] as Json)["sha256"] !== corpus.config.codexSha256) return `Codex SHA-256 ${String((r["codexInstallation"] as Json)["sha256"])} is not the corpus's`;
    return null;
  }

  async step(s: Step): Promise<string | null> {
    this.stepNo++;
    if (s.op === "grant") {
      await new CustodianOperator(this.t).mint(this.repo, Number(s["loops"]), 60, `grant-${++this.generated}`);
      return null;
    }
    if (s.op === "dropRun") {
      this.t.dropRunRecord(this.repo, String(s["run"]));
      return null;
    }
    this.mode.client = typeof s["client"] === "string" ? (s["client"] as string) : null;
    this.mode.writer = typeof s["writer"] === "string" ? (s["writer"] as string) : null;
    this.mode.writerState = typeof s["writerState"] === "string" ? (s["writerState"] as string) : null;
    try {
      const res = await this.execute(s);
      const capture = s["capture"] as Json | undefined;
      if (res.ok && capture) {
        if (typeof capture["op"] === "string") this.ops.set(capture["op"], String(res.data?.["operationId"]));
        if (typeof capture["amendment"] === "string") this.amendments.set(capture["amendment"], String(res.data?.["recordId"]));
        if (typeof capture["intent"] === "string") this.intents.set(capture["intent"], String(res.data?.["authorizationRequestId"]));
      }
      return compare(this.resolve(s["expect"]) as Json, res, s.op === "list");
    } finally {
      this.mode.client = this.mode.writer = this.mode.writerState = null;
    }
  }

  private async execute(s: Step): Promise<CustodianResponse> {
    const run = String(s["run"] ?? "");
    const surface: CustodianSurface = s["caller"] === "operator" || s["view"] === "operator" ? "operator" : "implementer";
    switch (s.op) {
      case "t": {
        const requestId = typeof s["requestId"] === "string" ? (s["requestId"] as string) : `corpus-${++this.generated}`;
        const args: Json = { repositoryRoot: this.repo, runId: run, kind: s["kind"], fields: this.resolve(s["fields"]) };
        // A replay re-sends the FIRST request sent under the id (a later conflicting one does not replace it).
        if (!this.sent.has(requestId)) this.sent.set(requestId, { surface, args, requestId, mode: { ...this.mode } });
        // Phase 4 Increment 3: what the custodian's measurement of the source gives during this transition (RunCorpusSelfTest).
        if (s["source"] && typeof s["source"] === "object") this.t.setSyntheticMeasurement(this.measuredSpec(s["source"] as Json));
        let res: CustodianResponse;
        try {
          res = await this.t.send(surface, "run_transition", args, requestId);
        } finally {
          if (s["source"] && typeof s["source"] === "object") this.t.setSyntheticMeasurement({});
        }
        // P3.4C-5 Increment 3 (§4): the custodian's measurement of a checks operation's start and of each execution's end
        // runs at once (the corpus's synthetic measurement), unless the step leaves it pending (RunCorpusSelfTest).
        const fields = args["fields"] as Json;
        const measuring = res.ok && ((s["kind"] === "op_begin" && fields["operationKind"] === "checks" && res.data?.["operationStatus"] === "measuring") || (s["kind"] === "record_execution" && res.data?.["executionStatus"] === "measuring"));
        if (measuring && s["measure"] !== false) await this.t.runReservedCheckMeasurement(String(res.data?.["operationId"]), this.measuredSpec(s["measured"] as Json | undefined));
        return res;
      }
      case "measure": {
        const r = await this.t.runReservedCheckMeasurement(this.ops.get(String(s["of"]))!, this.measuredSpec(s["measured"] as Json | undefined));
        return r ? { ok: true, data: r } : { ok: false, code: "INTERNAL", error: "no check measurement is pending" };
      }
      case "derive": {
        const spec = (s["derivation"] ?? {}) as Json;
        this.t.setSyntheticMeasurement({
          ...(typeof spec["sourceId"] === "string" ? { sourceId: this.resolve(spec["sourceId"]) as string } : {}),
          routeKind: typeof spec["routeKind"] === "string" ? spec["routeKind"] : "implementer_step",
          routeCode: typeof spec["routeCode"] === "string" ? spec["routeCode"] : "address_findings",
          ...(typeof spec["fingerprint"] === "string" ? { fingerprint: this.resolve(spec["fingerprint"]) as string } : {}),
          ...(spec["freshness"] && typeof spec["freshness"] === "object" ? { freshness: this.resolve(spec["freshness"]) as Record<string, string> } : {}),
        });
        try {
          const runJson = typeof s["runJson"] === "string" ? Buffer.from(s["runJson"] as string, "utf8") : CORPUS_RUN_JSON;
          const res = await this.t.send("implementer", "list_user_records", { repositoryRoot: this.repo, runId: run, sections: ["derivation"], runJson: runJson.toString("base64") }, `derive-${++this.generated}`);
          this.snapshots?.set(this.stepNo, this.t.lastDerivationSnapshotForTest);
          const d = res.data?.["derivation"] as Json | undefined;
          if (res.ok && typeof s["as"] === "string" && typeof d?.["derivationId"] === "string") this.derivations.set(s["as"] as string, d["derivationId"] as string);
          return res.ok ? { ok: true, data: d } : res;
        } finally {
          this.t.setSyntheticMeasurement({});
        }
      }
      case "replay": {
        const prior = this.sent.get(String(s["of"]))!;
        Object.assign(this.mode, prior.mode);
        return this.t.send(prior.surface, "run_transition", prior.args, prior.requestId);
      }
      case "mint": {
        const res = await this.t.send("implementer", "consume_loop", { repositoryRoot: this.repo, runId: run }, `mint-${++this.generated}`);
        if (res.ok && typeof res.data?.["bindNonce"] === "string") this.nonces.set(run, res.data["bindNonce"] as string);
        return res;
      }
      case "bind":
      case "loop": {
        const loop = this.t.snapshot().loops.find((l) => l.runId === run);
        const fields = s.op === "bind" ? { bindNonce: this.nonces.get(run), session_id: "s-1", process: { pid: CLAUDE } } : this.resolve(s["fields"]);
        const args = { repositoryRoot: this.repo, runId: run, loopId: loop?.loopId ?? "00000000-0000-4000-8000-00000000ffff", epoch: loop?.epoch ?? 1, baseLoopRevision: loop?.loopRevision ?? 1, kind: s.op === "bind" ? "bind" : s["kind"], fields };
        return this.t.send("implementer", "loop_transition", args, `loop-${++this.generated}`);
      }
      case "list":
        return this.t.send(surface, "list_user_records", { repositoryRoot: this.repo, runId: run, sections: ["user", "loop", "run", "config"] }, `list-${++this.generated}`);
      case "grantIdentity": {
        // F-S71-1: the identity list_user_records reports for the repository path, against the latest grant's key.
        const l = await this.t.send(surface, "list_user_records", { repositoryRoot: this.repo, runId: run, sections: ["config"] }, `list-${++this.generated}`);
        if (!l.ok) return l;
        const g = await this.t.send("operator", "list_grants", {}, `grants-${++this.generated}`);
        if (!g.ok) return g;
        const key = typeof l.data?.["repoKey"] === "string" ? (l.data["repoKey"] as string) : null;
        const last = ((g.data?.["grants"] as Json[] | undefined) ?? []).at(-1) ?? null;
        return { ok: true, data: { reported: key !== null, matchesLatestGrant: last !== null && key !== null && last["repoKey"] === key, latestGrantActive: last?.["active"] === true } };
      }
      case "config": {
        const action = String(s["action"]);
        const revision = Number(((await this.configSection())["repository"] as Json | null)?.["configRevision"] ?? 0);
        return this.prepareAndCommit({ repositoryRoot: this.repo, recordKind: "repository", action, ...(action === "set" ? { payload: this.payloadOf(s["payload"] as Json | undefined, s["codex"]) } : {}), baseRevision: revision });
      }
      case "revokeGlobal": {
        const kind = String(s["kind"]);
        const recordId = kind === "isolation_acceptance" ? this.acceptanceId : kind === "fix_confirmation" ? this.fixConfirmationId : this.confirmationId;
        return this.prepareAndCommit({ recordKind: kind === "fix_confirmation" ? "selftest_confirmation" : kind, action: "revoke", recordId, baseRevision: Number((await this.configSection())["globalRevision"]) });
      }
      // ---- Phase 4 Increment 2: the delegated fix (RunCorpusSelfTest) ----
      case "fixConfirm": {
        const res = await this.prepareAndCommit({ recordKind: "selftest_confirmation", action: "set", payload: corpus.config.fixSelftest, baseRevision: Number((await this.configSection())["globalRevision"]) });
        if (res.ok) this.fixConfirmationId = String(res.data?.["recordId"]);
        return res;
      }
      case "orphanProposal": {
        const id = `fop-0-${String(s["name"])}`;
        this.t.orphanProposalForTest(this.repo, run, id);
        this.ops.set(String(s["name"]), id);
        return { ok: true, data: {} };
      }
      case "held":
        return { ok: true, data: this.t.heldProposalForTest(this.repo, run, this.ops.get(String(s["of"]))!) as Json };
      // ---- Phase 4 Increment 3: the owner's decision and the custodian's rendering (RunCorpusSelfTest) ----
      case "fixPrepare": {
        // Step 7.1: `repo` names the directory the request names; `expected` the selection fields exactly as sent.
        const repositoryRoot = typeof s["repo"] === "string" ? this.namedPath(s["repo"]) : this.repo;
        const expected = s["expected"] ? (this.resolve(s["expected"]) as Json) : {};
        const res = await this.t.send("operator", "prepare_fix_decision", { repositoryRoot, runId: run, operationId: this.ops.get(String(s["of"]))!, decision: s["decision"], ...expected }, `fixdecision-${++this.generated}`);
        return res.ok ? { ok: true, data: { authorizationRequestId: res.data?.["authorizationRequestId"], action: res.data?.["action"], rendering: res.data?.["rendering"], fixDecision: res.data?.["fixDecision"] ?? null } } : res;
      }
      // ---- Step 7.1: the operator's listing (`fix review`; RunCorpusSelfTest) ----
      case "fixList": {
        this.namedPath("main");
        const args = typeof s["repo"] === "string" ? { repositoryRoot: this.namedPath(s["repo"]) } : {};
        const res = await this.t.send((s["surface"] as CustodianSurface | undefined) ?? "operator", "list_fix_proposals", args, `fixlist-${++this.generated}`);
        if (!res.ok) return res;
        const sel = s["select"] as Json | undefined;
        if (sel) {
          const id = this.ops.get(String(sel["of"]));
          const entry = ((res.data?.["entries"] ?? []) as Json[]).find((e) => e["operationId"] === id);
          if (!entry) throw new Error(`the listing has no entry for ${String(id)}`);
          this.selections.set(String(sel["as"]), structuredClone(entry));
        }
        return { ok: true, data: this.listingSummary(res.data ?? {}) };
      }
      case "repo":
        this.namedPath(String(s["name"]));
        return { ok: true, data: {} };
      case "moveRepo": {
        this.namedPath("main");
        const to = `${this.repo}-${String(s["to"])}`;
        renameSync(this.repo, to);
        this.paths.set(String(s["to"]), { path: to, canonical: filesystemIdentity(to).canonicalPath });
        if (s["reuse"] === true) mkdirSync(this.repo, { recursive: true });
        return { ok: true, data: {} };
      }
      case "unpin":
        this.t.unpinRunForTest(this.namedPath("main"), run);
        return { ok: true, data: {} };
      case "fixRender":
        return this.t.send(surface, "render_fix_proposal", { repositoryRoot: this.repo, runId: run, operationId: this.ops.get(String(s["of"]))! }, `render-${++this.generated}`);
      case "recover":
        this.t.simulateRecoveryAfterNewBoot();
        return { ok: true, data: {} };
      case "capture": {
        // P3.4C-5: capture the reserved review `of` with the corpus's synthetic capture (late: a capture of the custodian
        // instance before the last restart — its result must not be recorded).
        const spec = { sourceId: (this.resolve(s["sourceId"]) as string | undefined) ?? null, stable: s["stable"] !== false, fail: (s["fail"] as string | undefined) ?? null, tree: s["tree"] === true };
        try {
          return { ok: true, data: await this.t.runReservedCapture(this.ops.get(String(s["of"]))!, spec, s["late"] === true) };
        } catch (e) {
          return { ok: false, code: "INTERNAL", error: e instanceof Error ? e.message : String(e) };
        }
      }
      case "tamper":
        this.t.tamperCapture(this.repo, run, this.ops.get(String(s["of"]))!);
        return { ok: true, data: { tampered: true } };
      case "restart":
        return { ok: true, data: { interrupted: this.t.restartCustodian() } };
      // ---- P3.4C-5 Increment 4: export retention (RunCorpusSelfTest) ----
      case "exports": {
        const root = join(this.scratch, "exports");
        const dirs = existsSync(root) ? readdirSync(root, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name) : [];
        const side = (d: string): boolean => d.endsWith(".staging") || d.endsWith(".cfg");
        return { ok: true, data: { published: dirs.filter((d) => !side(d)).length, staging: dirs.filter(side).length } };
      }
      case "orphan":
        for (const n of s["names"] as string[]) mkdirSync(join(this.scratch, "exports", n), { recursive: true });
        return { ok: true, data: {} };
      case "sweep":
        return { ok: true, data: this.t.sweepExportsNow() as unknown as Json };
      case "advance":
        this.clock.now += Number(s["hours"]) * 3600_000;
        return { ok: true, data: {} };
      case "amend": {
        const payload = { kind: "clarification", text: "a corpus amendment", disclosure_digest: this.resolve(s["disclosure"]) };
        return this.userRecord(run, "amendment", payload, true);
      }
      case "decide": {
        const payload = { kind: "waive", note: "", covered_items: s["covered"], decided_against: this.resolve(s["decidedAgainst"]) };
        return this.userRecord(run, "decision", payload, false);
      }
      case "commit": {
        const id = this.intents.get(String(s["intent"]))!;
        return this.t.send("operator", "commit", { authorizationRequestId: id }, `commit-${++this.generated}`);
      }
      default:
        throw new Error(`unknown corpus op ${String(s.op)}`);
    }
  }

  /** The step's synthetic measurement (RunCorpusSelfTest.SettleMeasurement): sourceId, stable, fail. */
  private measuredSpec(m: Json | undefined): { sourceId?: string; stable?: boolean; fail?: "timeout" | "helper" | "runtime" | "cancelled" } {
    return {
      ...(m && typeof m["sourceId"] === "string" ? { sourceId: this.resolve(m["sourceId"]) as string } : {}),
      ...(m && m["stable"] === false ? { stable: false } : {}),
      ...(m && typeof m["fail"] === "string" ? { fail: m["fail"] as "timeout" | "helper" | "runtime" | "cancelled" } : {}),
    };
  }

  /** Prepare a user record at the run's current log revision (and, for an amendment, commit it). */
  private async userRecord(run: string, recordKind: "decision" | "amendment", payload: Json, commit: boolean): Promise<CustodianResponse> {
    const listing = await this.t.send("operator", "list_user_records", { repositoryRoot: this.repo, runId: run }, `list-${++this.generated}`);
    const baseRevision = Number(listing.data?.["revision"] ?? 0);
    const requestId = `record-${++this.generated}`;
    const prepared = await this.t.send("operator", "prepare_user_record", { repositoryRoot: this.repo, runId: run, recordKind, payload, baseRevision }, requestId);
    if (!prepared.ok || !commit) return prepared;
    return this.t.send("operator", "commit", { authorizationRequestId: requestId }, `commit-${++this.generated}`);
  }

  /** Templates, $omit and placeholders, resolved recursively. */
  resolve(v: unknown): unknown {
    if (Array.isArray(v)) return v.map((x) => this.resolve(x));
    if (v && typeof v === "object") {
      const o = v as Json;
      const base = typeof o["$template"] === "string" ? (this.resolve(structuredClone(corpus.templates[o["$template"] as string]!)) as Json) : {};
      const out: Json = { ...base };
      for (const [k, x] of Object.entries(o)) {
        if (k === "$template") continue;
        if (x === "$omit") delete out[k];
        else out[k] = this.resolve(x);
      }
      return out;
    }
    if (typeof v !== "string" || !v.startsWith("$")) return v;
    if (v.startsWith("$hex:")) return v.slice(5).repeat(64);
    if (v.startsWith("$sha:")) return createHash("sha256").update(v.slice(5), "utf8").digest("hex");
    if (v.startsWith("$op:")) return this.ops.get(v.slice(4));
    // Step 7.1: a field of a captured listing entry ($sel:alias:field), and a named directory's identity.
    if (v.startsWith("$sel:")) {
      const [alias, field] = v.slice(5).split(":") as [string, string];
      return this.selections.get(alias)?.[field] ?? null;
    }
    if (v.startsWith("$key:")) return filesystemIdentity(this.namedPath(v.slice(5))).key;
    if (v.startsWith("$proposal:")) {
      const id = this.ops.get(v.slice(10));
      for (const r of Object.values(this.t.snapshot().runs ?? {})) {
        const op = r.operations.find((o) => o.operationId === id);
        if (op) return ((op.outcome?.["proposal"] ?? null) as Json | null)?.["proposalDigest"] ?? null;
      }
      return null;
    }
    if (v.startsWith("$der:")) return this.derivations.get(v.slice(5));
    if (v === "$runJson") return createHash("sha256").update(CORPUS_RUN_JSON).digest("hex");
    if (v.startsWith("$amendment:")) return this.amendments.get(v.slice(11));
    if (v === "$claude") return CLAUDE;
    if (v.startsWith("$def:")) return corpus.config.digests[v.slice(5)];
    if (v === "$captureRules") return corpus.config.captureRulesDigest;
    if (v === "$codexSha") return corpus.config.codexSha256;
    if (v === "$acceptance") return this.acceptanceId;
    throw new Error(`unknown corpus placeholder ${v}`);
  }
}

/** A list step's run record, summarized (the corpus's `summary`; mirrors RunCorpusSelfTest.Summary). */
function summary(record: Json | null, reviewBasis: Json | null): Json | null {
  if (!record) return null;
  const arr = (k: string): Json[] => (Array.isArray(record[k]) ? (record[k] as Json[]) : []);
  const strs = (v: unknown): string[] => (Array.isArray(v) ? (v as string[]) : []);
  const reviewState = (r: Json): string => {
    const round = String(r["round"]);
    if (r["accepted"] === true) return `${round}:accepted`;
    if (r["accepted"] === false) return `${round}:not:${strs(r["notAcceptedReasons"]).join("+")}`;
    return `${round}:running`;
  };
  return {
    status: record["status"],
    runRevision: record["runRevision"],
    evidenceEpoch: record["evidenceEpoch"],
    operations: arr("operations").map((o) => `${String(o["kind"])}:${String(o["status"])}`),
    writerAlive: arr("operations").filter((o) => "writerAlive" in o).map((o) => o["writerAlive"] ?? null),
    reviews: Object.fromEntries(arr("reviews").map((r) => [String(r["reviewId"]), reviewState(r)])),
    items: Object.fromEntries(arr("items").map((i) => [String(i["itemId"]), `${String(i["status"])}@${String(i["itemRevision"])}`])),
    effects: Object.fromEntries(arr("items").map((i) => [String(i["itemId"]), (i["assessments"] as Json[]).map((a) => `${String(a["assessment"])}=${String(a["effect"])}`)])),
    links: Object.fromEntries(arr("items").map((i) => [String(i["itemId"]), `by=${typeof i["supersededBy"] === "string" ? i["supersededBy"] : "-"};sup=${strs(i["supersedes"]).join(",")};re=${strs(i["restates"]).join(",")}`])),
    incidents: arr("incidents").map((i) => `${String(i["kind"])}:${String(i["source"])}`),
    executions: arr("checkExecutions").map((e) => `${String(e["executionId"])}:${String(e["status"])}`),
    responses: arr("responses").map((r) => `${String(r["responseId"])}:${String(r["itemId"])}`),
    replies: arr("replies").map((r) => `${String(r["replyId"])}:${String(r["itemId"])}`),
    // P3.4C-4: each review's basis now (usable, or why not) from the run section's reviewBasis.
    basis: Object.fromEntries(Object.entries(reviewBasis ?? {}).map(([id, b]) => [id, (b as Json)["basisUsable"] === true ? "usable" : String((b as Json)["basisReason"])])),
  };
}

/** The corpus's expectation check (mirrors RunCorpusSelfTest.Compare). */
function compare(expect: Json, res: CustodianResponse, list: boolean): string | null {
  if (!res.ok) return expect["ok"] === true ? `expected ok, got ${res.code}: ${res.error}` : expect["code"] === res.code ? null : `expected ${String(expect["code"])}, got ${res.code}: ${res.error}`;
  if (expect["ok"] !== true) return `expected ${String(expect["code"])}, got ok: ${JSON.stringify(res.data)}`;
  const data = res.data ?? {};
  const m = expect["data"] ? mismatch(expect["data"] as Json, data, "") : null;
  if (m) return m;
  const json = JSON.stringify(data);
  for (const p of (expect["present"] as string[] | undefined) ?? []) if (!(p in data)) return `'${p}' missing from ${json}`;
  // F-S71-1: a listing reports the identity it was resolved under (its top-level repoKey); the projections below it must
  // still carry no internal field, so they alone are scanned.
  const scanned = list && "repoKey" in data ? JSON.stringify({ ...data, repoKey: undefined }) : json;
  for (const a of (expect["absent"] as string[] | undefined) ?? []) if (scanned.includes(a)) return `'${a}' must not appear in ${json}`;
  // Phase 4 Increment 3: the rendering's text (the custodian's exact bytes) has — and lacks — these lines or fragments.
  const re = expect["rendering"] as { has?: string[]; lacks?: string[] } | undefined;
  if (re) {
    const text = typeof data["rendering"] === "string" ? (data["rendering"] as string) : "";
    for (const x of re.has ?? []) if (!text.includes(x)) return `the rendering lacks ${JSON.stringify(x)}:\n${text}`;
    for (const x of re.lacks ?? []) if (text.includes(x)) return `the rendering must not contain ${JSON.stringify(x)}:\n${text}`;
  }
  if (!list) return null;
  const record = ((data["run"] as Json | undefined)?.["record"] ?? null) as Json | null;
  const reviewBasis = ((data["run"] as Json | undefined)?.["reviewBasis"] ?? null) as Json | null;
  if (expect["recordKeys"]) {
    const want = [...(expect["recordKeys"] as string[])].sort().join(",");
    const got = Object.keys(record ?? {}).sort().join(",");
    if (want !== got) return `record keys [${got}] are not [${want}]`;
  }
  for (const k of (expect["recordHas"] as string[] | undefined) ?? []) if (!record || !(k in record)) return `run.record has no '${k}'`;
  if ("summary" in expect) {
    const got = summary(record, reviewBasis);
    const want = expect["summary"] as Json | null;
    if (want === null || got === null) return want === got ? null : `summary: expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`;
    const sm = mismatch(want, got, "summary.");
    if (sm) return sm;
  }
  return null;
}

/** A partial deep match: every key the expectation names must equal (objects recursively, anything else exactly). */
function mismatch(want: Json, got: Json, path: string): string | null {
  for (const [k, w] of Object.entries(want)) {
    const g = got[k];
    if (w && typeof w === "object" && !Array.isArray(w)) {
      if (!g || typeof g !== "object" || Array.isArray(g)) return `${path}${k}: expected an object, got ${JSON.stringify(g ?? null)}`;
      const m = mismatch(w as Json, g as Json, `${path}${k}.`);
      if (m) return m;
    } else if (canonicalize(w) !== canonicalize(g ?? null)) return `${path}${k}: expected ${JSON.stringify(w)}, got ${JSON.stringify(g ?? null)}`;
  }
  return null;
}

/** Run one corpus scenario against a fresh simulated custodian; returns its problems (and, given `snapshots`, records each
 * derive step's snapshot). */
async function runScenario(scenario: Scenario, snapshots: Map<number, unknown> | null = null): Promise<string[]> {
  const scratch = realpathSync.native(mkdtempSync(join(tmpdir(), "cp-runcorpus-")));
  try {
    const repo = join(scratch, "repos", "Corpus"); // the real custodian's corpus layout (RunCorpusSelfTest)
    mkdirSync(repo, { recursive: true });
    const clock = { now: Date.parse("2026-10-13T12:00:00Z") };
    const mode: Mode = { client: null, writer: null, writerState: null };
    const t = new SimulatedCustodianTransport({
      caller: "by_surface",
      now: () => clock.now,
      processCheck: fixedProcessCheck,
      clientCheck: (bound) => clientVerdict(bound, mode.client),
      writer: () => writerOf(mode),
      writerGone: (w) => writerGone(mode, w),
      // P3.4C-5: the custodian captures protected reviews itself; the corpus asks for each capture.
      helper: { exportsRoot: join(scratch, "exports"), mode: "manual" },
    });
    if (scenario.grant !== false) await new CustodianOperator(t).mint(repo, typeof scenario.grant === "number" ? scenario.grant : 8, 60, "corpus-grant");
    const runner = new Runner(t, repo, mode, scratch, snapshots, clock);
    const problems: string[] = [];
    if (scenario.config !== false) {
      const parity = await runner.holdConfig();
      if (parity) problems.push(`config: ${parity}`);
      t.seedEngineRuntime(scratch); // P3.4C-5: an approved (synthetic) engine runtime
    }
    for (const [i, step] of scenario.steps.entries()) {
      const p = await runner.step(step);
      if (p) problems.push(`step ${i + 1} (${step.op} ${String(step["kind"] ?? step["of"] ?? step["intent"] ?? "")}): ${p}`);
    }
    return problems;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

describe("P3.4C-3 run records — the shared corpus against the simulated custodian", () => {
  it.each(corpus.scenarios.map((s) => [s.name, s] as const))("%s", async (_name, scenario) => {
    expect(await runScenario(scenario)).toEqual([]);
  });

  it("the corpus covers every kind, every refusal code and both surfaces", () => {
    const steps = corpus.scenarios.flatMap((s) => s.steps);
    const kinds = new Set(steps.filter((x) => x.op === "t").map((x) => x["kind"]));
    for (const k of ["open", "op_begin", "record_execution", "op_finish", "recover", "respond", "end"]) expect(kinds).toContain(k);
    const codes = new Set(steps.map((x) => (x["expect"] as Json | undefined)?.["code"]).filter(Boolean));
    for (const c of ["RUN_NOT_OPEN", "RUN_TERMINAL", "RUN_DECLARATION_CONFLICT", "RUN_BUSY", "OPERATION_NOT_RUNNING", "WRITER_MISMATCH", "OPERATION_WRITER_ALIVE", "EVIDENCE_NOT_HELD", "BUDGET_EXHAUSTED", "FINDING_NOT_FOUND", "FINDING_NOT_RESPONDABLE", "INVALID_ITEM_TRANSITION", "PROCESS_IDENTITY_UNVERIFIED", "STALE_FINDING_STATE", "REQUEST_ID_CONFLICT", "CALLER_NOT_AUTHORIZED", "LOOP_NOT_AUTHORIZED", "LOOP_TERMINAL", "MALFORMED_REQUEST", "INVALID_ARGUMENT",
      "CONFIG_NOT_HELD", "CONFIG_LAPSED", "CHECK_NOT_APPROVED", "ISOLATION_NOT_ACCEPTED", "CONFIG_MISMATCH"]) {
      expect(codes, c).toContain(c);
    }
    expect(steps.some((x) => x["caller"] === "operator" && x.op === "t")).toBe(true);
    expect(steps.some((x) => x["view"] === "operator")).toBe(true);
  });
});

describe("the simulated custodian's recovery after a new boot (a test control mirroring GrantLedger.Recovery.cs U1–U5 with U4b)", () => {
  it("pauses live loops for the operator, suspends grants, starts a new evidence epoch, stamps recoveredAtRevision, lapses the configuration and voids intents — each once", async () => {
    const scratch = realpathSync.native(mkdtempSync(join(tmpdir(), "cp-runrecovery-")));
    try {
      const repo = join(scratch, "Corpus");
      mkdirSync(repo);
      const mode: Mode = { client: null, writer: null, writerState: null };
      const t = new SimulatedCustodianTransport({ caller: "by_surface", processCheck: fixedProcessCheck, clientCheck: (bound) => clientVerdict(bound, mode.client), writer: () => writerOf(mode), writerGone: (w) => writerGone(mode, w), helper: { exportsRoot: join(scratch, "exports"), mode: "manual" } });
      const op = new CustodianOperator(t);
      await op.mint(repo, 3, 60, "grant-1");
      const runner = new Runner(t, repo, mode, scratch);
      expect(await runner.holdConfig()).toBeNull();
      t.seedEngineRuntime(scratch);
      const steps: Step[] = [
        { op: "t", run: "r1", kind: "open", fields: { $template: "open" }, expect: { ok: true } },
        { op: "mint", run: "r1", expect: { ok: true } },
        { op: "bind", run: "r1", expect: { ok: true } },
        { op: "t", run: "r1", kind: "op_begin", fields: { $template: "reviewBegin" }, capture: { op: "r1" }, expect: { ok: true } },
        { op: "capture", run: "r1", of: "r1", expect: { ok: true, data: { operationStatus: "captured" } } },
        { op: "t", run: "r1", kind: "op_finish", fields: { operationId: "$op:r1", outcome: { $template: "reviewOutcome" }, promptDigest: "$hex:5", presented: { $template: "presented" } }, expect: { ok: true, data: { accepted: true } } },
        { op: "t", run: "r2", kind: "open", fields: { $template: "open" }, expect: { ok: true } },
        { op: "mint", run: "r2", expect: { ok: true } },
        { op: "amend", run: "r1", disclosure: "$hex:d", capture: { amendment: "a1" }, expect: { ok: true } },
      ];
      for (const s of steps) expect(await runner.step(s)).toBeNull();
      const pending = await op.prepareGrant(repo, 1, 60, "grant-2"); // an intent the recovery voids

      const id = t.simulateRecoveryAfterNewBoot("rec-test");
      const after = t.snapshot();
      expect(after.loops.map((l) => [l.runId, l.status, l.pause?.reason ?? l.ended?.reason])).toEqual([["r1", "paused", "operator_action_required"], ["r2", "cancelled", "unbindable after an OS restart"]]);
      expect(after.grants.every((g) => typeof g.suspendedAt === "string")).toBe(true);
      expect(after.runs.map((r) => [r.runId, r.evidenceEpoch])).toEqual([["r1", 2], ["r2", 2]]);
      expect((await op.list()).grants.map((g) => [g.suspended, g.active])).toEqual([[true, false]]);
      const listed = await t.send("implementer", "list_user_records", { repositoryRoot: repo, runId: "r1" }, "list-r");
      expect(listed.data?.["recoveredAtRevision"]).toBe(1);
      expect(await t.send("operator", "commit", { authorizationRequestId: pending.authorizationRequestId }, "commit-r")).toMatchObject({ ok: false, code: "AUTHORIZATION_INVALID" });
      // U4b (P3.4C-4): every configuration record in force lapsed, stamped with this recovery.
      expect(after.config.repositories.filter((r) => r.supersededAt === null).every((r) => r.lapsedAtRecoveryId === "rec-test" && r.lastRecoveryId === "rec-test")).toBe(true);
      expect(after.config.acceptances.every((a) => a.lapsedAtRecoveryId === "rec-test")).toBe(true);
      expect(after.config.selftestConfirmations.every((c) => c.lapsedAtRecoveryId === "rec-test")).toBe(true);
      expect((after.config.engineRuntimes ?? []).every((r) => r.lapsedAtRecoveryId === "rec-test")).toBe(true);

      // Idempotent under its id: a resumed recovery changes nothing twice.
      t.simulateRecoveryAfterNewBoot(id);
      expect(t.snapshot()).toEqual(after);

      // The lapsed configuration refuses first; once the operator re-confirmed it, a suspended grant authorizes nothing: no
      // run is registered and no loop consumed.
      const more: Step[] = [
        { op: "t", run: "r3", kind: "open", fields: { $template: "open" }, expect: { ok: false, code: "CONFIG_LAPSED" } },
        { op: "config", action: "reconfirm", expect: { ok: true, data: { globalsReconfirmed: 3 } } },
        { op: "t", run: "r3", kind: "open", fields: { $template: "open" }, expect: { ok: false, code: "LOOP_NOT_AUTHORIZED" } },
        // The session bound before the restart has ended with it: nothing more is recorded from it (D-15).
        { op: "t", run: "r1", kind: "op_begin", client: "ended", fields: { $template: "reviewBegin", reviewId: "rv2" }, expect: { ok: false, code: "PROCESS_IDENTITY_UNVERIFIED" } },
        // The accepted review of epoch 1 no longer deduplicates the same inputs: completion needs current-epoch evidence.
        { op: "t", run: "r1", kind: "op_begin", fields: { $template: "reviewBegin", reviewId: "rv2" }, expect: { ok: true, data: { round: 2 }, absent: ["deduplicatedOf"] } },
      ];
      for (const s of more) expect(await runner.step(s)).toBeNull();
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});

const custodianExe = ["Debug", "Release"]
  .map((c) => join(ROOT, "custodian", "CodeParley.Custodian", "bin", c, "net10.0-windows", "CodeParley.Custodian.exe"))
  .find((p) => existsSync(p)) ?? null;

describe.skipIf(process.platform !== "win32" || custodianExe === null)("the same corpus against the REAL custodian ledger (self-test-run-corpus, when built)", () => {
  it("passes every scenario", () => {
    const r = spawnSync(custodianExe!, ["self-test-run-corpus", "--corpus", CORPUS_PATH], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
    expect(r.stdout + r.stderr).toMatch(/run corpus self-test: all \d+ scenarios \(\d+ steps\) passed/);
    expect(r.status).toBe(0);
  });

  // P3.4C-5 Increment 3 (N5-5): the custodian derives over a snapshot of what it holds; the real and the simulated
  // custodian build the SAME snapshot at every derive step of the corpus (ids, times and the scratch paths normalized).
  it("builds the same derivation snapshot as the simulated custodian at every derive step", async () => {
    const dump = mkdtempSync(join(tmpdir(), "cp-snapdump-"));
    try {
      const r = spawnSync(custodianExe!, ["self-test-run-corpus", "--corpus", CORPUS_PATH, "--dump", dump], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
      expect(r.status, r.stdout + r.stderr).toBe(0);
      let compared = 0;
      for (const [index, scenario] of corpus.scenarios.entries()) {
        if (!scenario.steps.some((x) => x.op === "derive")) continue;
        const snapshots = new Map<number, unknown>();
        expect(await runScenario(scenario, snapshots)).toEqual([]);
        for (const [step, mine] of snapshots) {
          const theirs = JSON.parse(readFileSync(join(dump, `${String(index).padStart(2, "0")}-${String(step).padStart(3, "0")}.json`), "utf8")) as unknown;
          expect(normalizeSnapshot(mine), `${scenario.name}, step ${step}`).toEqual(normalizeSnapshot(theirs));
          if (mine !== null) compared++;
        }
      }
      expect(compared).toBeGreaterThan(0);
    } finally {
      rmSync(dump, { recursive: true, force: true });
    }
  });
});

/** A snapshot with what legitimately differs between two custodians replaced: times, generated ids (by order of first
 * appearance), the scenario's scratch paths, the repository's file identity with the configuration digest that covers
 * it (an OS fact of each scratch directory), and the digests of a capture that names its generated id. Everything else — every record, revision, digest and value — must match. */
function normalizeSnapshot(v: unknown): unknown {
  const ids = new Map<string, string>();
  // The synthetic capture's own record names its capture id (the generated operation id), so its digests differ too.
  const environmental = new Set(["fileId", "configDigest", "captureDigest", "manifestDigest", "exportDigest", "manifestContentDigest"]);
  const walk = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(walk);
    if (x && typeof x === "object") return Object.fromEntries(Object.keys(x).sort().map((k) => [k, environmental.has(k) ? `<${k}>` : walk((x as Record<string, unknown>)[k])]));
    if (typeof x !== "string") return x;
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(x)) return "<time>";
    if (/^(cop|rop|tkt|der|wc|op|inc)-[0-9a-z-]+$/i.test(x) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x)) {
      if (!ids.has(x)) ids.set(x, `<id:${ids.size}>`);
      return ids.get(x);
    }
    return /cp-runcorpus-/.test(x) ? x.replace(/^.*cp-runcorpus-[^\\/]+/, "<scratch>").replace(/\\/g, "/") : x;
  };
  return walk(v);
}
