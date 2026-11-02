// P3.4C-2 contract test: the custodian-owned loop lifecycle (consume_loop's mint, loop_transition and the
// list_user_records loop section) against the shared corpus test/fixtures/loop-transition-corpus.json. The
// SAME corpus is run against the real custodian's ledger by `CodeParley.Custodian.exe self-test-loop-corpus`
// (and here too, when a built custodian exists on Windows), so the simulated custodian the engine tests use
// and the real custodian obey one observable behaviour. Platform-independent: no pipe, no service.

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CustodianOperator } from "../src/custodian/operator.js";
import { SimulatedCustodianTransport } from "../src/custodian/transport.js";
import type { SimBoundProcess, SimProcessCheck } from "../src/custodian/simulated-loops.js";
import type { CustodianResponse, CustodianSurface } from "../src/custodian/protocol.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CORPUS_PATH = join(ROOT, "test", "fixtures", "loop-transition-corpus.json");

type Json = Record<string, unknown>;
interface Step extends Json {
  op: "mint" | "t" | "replay" | "list" | "advance" | "derive" | "measurement";
}
interface Scenario {
  name: string;
  steps: Step[];
}
const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8")) as { scenarios: Scenario[] };

// The corpus's fixed process facts (the C# self-test's table): the custodian verifies $claude as an ancestor
// of the connected process; $unrelated it does not.
const CLAUDE = 100;
const UNRELATED = 400;
const fixedProcessCheck = (pid: number | null): SimProcessCheck =>
  pid === CLAUDE ? { pid, startedAtMs: 1, clientPid: 300, verified: true, detail: "an ancestor of the connected process" } : { pid, startedAtMs: null, clientPid: 300, verified: false, detail: "not an ancestor of the connected process" };

/** The process connected to the pipe for one step (the C# runner's Connection), checked against the bound one:
 * absent = the bound session's hook helper (a descendant of $claude); outsider = outside $claude's tree; ended =
 * $claude exited; reused = $claude's pid names a later process. An OS fact, independent of every field. */
const fixedClientCheck = (bound: SimBoundProcess, client: string | null): SimProcessCheck => {
  const refused = (detail: string): SimProcessCheck => ({ pid: bound.pid, startedAtMs: bound.startedAtMs, clientPid: 300, verified: false, detail });
  if (bound.pid !== CLAUDE || bound.startedAtMs !== 1) return refused("the binding records another process");
  if (client === "ended") return refused(`process ${CLAUDE} is not running`);
  if (client === "reused") return refused(`process ${CLAUDE} is not the process the loop was bound to: the process id was reused`);
  if (client === "outsider") return refused(`process ${CLAUDE} is not an ancestor of the process connected to the custodian (${UNRELATED})`);
  if (client !== null) throw new Error(`unknown corpus client ${client}`);
  return { pid: CLAUDE, startedAtMs: 1, clientPid: 300, verified: true, detail: "an ancestor of the connected process" };
};

interface Sent {
  surface: CustodianSurface;
  args: Json;
  requestId: string;
}

/** The run.json every corpus run is opened with (RunSelfTest.RunJsonText): its digest is the declaration's, and its bytes go
 * with a derivation request (P3.4C-5 Increment 3). */
const RUN_JSON = Buffer.from('{"schema":"selftest"}', "utf8");
/** The run declaration every corpus run is opened with (RunSelfTest.OpenFields' default). */
const OPEN_FIELDS = { runJsonDigest: createHash("sha256").update(RUN_JSON).digest("hex"), budgets: { maxReviews: 5, maxCheckExecutions: 50 }, baseline: { sourceId: "a".repeat(64), digest: "b".repeat(64) } };
const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

class Runner {
  private readonly nonces = new Map<string, string>();
  private readonly claims = new Map<string, string>();
  private readonly sent = new Map<string, Sent>();
  private readonly derivations = new Map<string, string>();
  private measurement: { sourceId?: string } = {};
  private generated = 0;

  constructor(
    private readonly t: SimulatedCustodianTransport,
    private readonly repo: string,
    private readonly advance: (seconds: number) => void,
    private readonly connection: { client: string | null },
  ) {}

  async step(s: Step): Promise<string | null> {
    if (s.op === "advance") {
      this.advance(Number(s["seconds"]));
      return null;
    }
    if (s.op === "measurement") {
      // P3.4C-5 Increment 3 (N5-17): what the custodian's (synthetic) measurement measures from now on.
      this.measurement = typeof s["sourceId"] === "string" ? { sourceId: s["sourceId"] as string } : {};
      this.t.setSyntheticMeasurement(this.measurement);
      return null;
    }
    const res = await this.execute(s);
    if (res.ok && s["capture"] && typeof (s["capture"] as Json)["claim"] === "string") this.claims.set((s["capture"] as Json)["claim"] as string, String(res.data?.["claimId"]));
    return compare(s["expect"] as Json, res);
  }

  private async execute(s: Step): Promise<CustodianResponse> {
    const run = String(s["run"] ?? "");
    switch (s.op) {
      case "mint": {
        // P3.4C-3: the engine registers the run (run_transition open, idempotent on its declaration) before it consumes
        // a loop; a refused open is the step's refusal (as LoopCorpusSelfTest.Mint).
        this.t.seedConfig(this.repo); // P3.4C-4: a run is opened only under the repository's protected configuration
        const opened = await this.t.send("implementer", "run_transition", { repositoryRoot: this.repo, runId: run, kind: "open", fields: OPEN_FIELDS }, `open-${++this.generated}`);
        if (!opened.ok) return opened;
        const res = await this.t.send("implementer", "consume_loop", { repositoryRoot: this.repo, runId: run }, String(s["requestId"]));
        if (res.ok && typeof res.data?.["bindNonce"] === "string") this.nonces.set(run, res.data["bindNonce"] as string);
        return res;
      }
      case "list": {
        const res = await this.t.send(s["view"] === "operator" ? "operator" : "implementer", "list_user_records", { repositoryRoot: this.repo, runId: run }, `list-${++this.generated}`);
        return res.ok ? { ok: true, data: res.data?.["loop"] as Json } : res;
      }
      case "replay": {
        const prior = this.sent.get(String(s["of"]))!;
        return this.t.send(prior.surface, "loop_transition", prior.args, prior.requestId);
      }
      case "derive": {
        // P3.4C-5 Increment 3 (§5.1): the derivation section with the corpus's synthetic derivation (LoopCorpusSelfTest.Derive).
        const spec = (s["derivation"] ?? {}) as Json;
        this.t.setSyntheticMeasurement({
          ...this.measurement,
          routeKind: typeof spec["routeKind"] === "string" ? spec["routeKind"] : "implementer_step",
          routeCode: typeof spec["routeCode"] === "string" ? spec["routeCode"] : "address_findings",
          ...(typeof spec["fingerprint"] === "string" ? { fingerprint: sha256(`corpus-fingerprint:${spec["fingerprint"]}`) } : {}),
        });
        try {
          const d = await this.derivation(run);
          if (typeof s["as"] === "string" && typeof d["derivationId"] === "string") this.derivations.set(s["as"] as string, d["derivationId"] as string);
          return { ok: true, data: d };
        } finally {
          this.t.setSyntheticMeasurement(this.measurement);
        }
      }
      default:
        return this.transition(s, run);
    }
  }

  private async derivation(run: string): Promise<Json> {
    const res = await this.t.send("implementer", "list_user_records", { repositoryRoot: this.repo, runId: run, sections: ["derivation"], runJson: RUN_JSON.toString("base64") }, `derive-${++this.generated}`);
    return (res.ok ? res.data?.["derivation"] : { available: false, code: res.code }) as Json;
  }

  private async transition(s: Step, run: string): Promise<CustodianResponse> {
    const fields = this.resolve(run, this.t.snapshot().loops.find((l) => l.runId === run), structuredClone(s["fields"])) as Json;
    // P3.4C-5 Increment 3 (§5.2): a continuation or wake naming no derivation is asked on a fresh one with moved progress
    // (LoopCorpusSelfTest.Transition) — unless the step says "derivation": "none".
    if ((s["kind"] === "spend_continuation" || s["kind"] === "wake_consume") && !("derivation_id" in fields) && s["derivation"] !== "none") {
      this.t.setSyntheticMeasurement({ ...this.measurement, fingerprint: randomBytes(32).toString("hex") });
      try {
        const d = await this.derivation(run);
        if (typeof d["derivationId"] === "string") fields["derivation_id"] = d["derivationId"];
      } finally {
        this.t.setSyntheticMeasurement(this.measurement);
      }
    }
    const loop = this.t.snapshot().loops.find((l) => l.runId === run);
    const requestId = typeof s["requestId"] === "string" ? (s["requestId"] as string) : `corpus-${++this.generated}`;
    const args: Json = {
      repositoryRoot: this.repo,
      runId: run,
      loopId: typeof s["loopId"] === "string" ? s["loopId"] : (loop?.loopId ?? "00000000-0000-4000-8000-00000000ffff"),
      epoch: relative(s["epoch"], loop?.epoch ?? 1),
      baseLoopRevision: relative(s["rev"], loop?.loopRevision ?? 1),
      kind: s["kind"],
      fields,
    };
    const surface: CustodianSurface = s["caller"] === "operator" ? "operator" : "implementer";
    this.sent.set(requestId, { surface, args, requestId });
    this.connection.client = typeof s["client"] === "string" ? (s["client"] as string) : null;
    try {
      return await this.t.send(surface, "loop_transition", args, requestId);
    } finally {
      this.connection.client = null;
    }
  }

  private resolve(run: string, loop: { operations: { handle: string }[] } | undefined, v: unknown): unknown {
    if (Array.isArray(v)) return v.map((x) => this.resolve(run, loop, x));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Json).map(([k, x]) => [k, this.resolve(run, loop, x)]));
    if (typeof v !== "string" || !v.startsWith("$")) return v;
    const ops = loop?.operations ?? [];
    const fixed: Record<string, unknown> = {
      $nonce: this.nonces.get(run),
      $wrongNonce: "0".repeat(64),
      $claude: CLAUDE,
      $unrelated: UNRELATED,
      $handle: ops.at(-1)?.handle ?? "op-1-000000000000",
      $previousHandle: ops.length > 1 ? ops.at(-2)!.handle : "op-1-000000000000",
      $inventedHandle: "op-1-000000000000",
      $inventedClaim: "wc-1-000000000000",
    };
    if (v in fixed) return fixed[v];
    if (v.startsWith("$claim:")) return this.claims.get(v.slice("$claim:".length));
    if (v.startsWith("$der:")) return this.derivations.get(v.slice("$der:".length)) ?? "der-unknown000000000000000000";
    throw new Error(`unknown corpus placeholder ${v}`);
  }
}

function relative(spec: unknown, current: number): number {
  if (spec === undefined) return current;
  if (typeof spec === "number") return spec;
  return current + Number(spec);
}

/** The corpus's expectation check (mirrors LoopCorpusSelfTest.Compare). */
function compare(expect: Json, res: CustodianResponse): string | null {
  if (!res.ok) return expect["ok"] === true ? `expected ok, got ${res.code}: ${res.error}` : expect["code"] === res.code ? null : `expected ${String(expect["code"])}, got ${res.code}`;
  if (expect["ok"] !== true) return `expected ${String(expect["code"])}, got ok: ${JSON.stringify(res.data)}`;
  const data = res.data ?? {};
  const m = expect["data"] ? mismatch(expect["data"] as Json, data, "") : null;
  if (m) return m;
  const json = JSON.stringify(data);
  for (const p of (expect["present"] as string[] | undefined) ?? []) if (!(p in data)) return `'${p}' missing from ${json}`;
  for (const a of (expect["absent"] as string[] | undefined) ?? []) if (json.includes(a)) return `'${a}' must not appear in ${json}`;
  if (expect["recordKeys"]) {
    const want = [...(expect["recordKeys"] as string[])].sort().join(",");
    const got = Object.keys((data["record"] as Json | null) ?? {}).sort().join(",");
    if (want !== got) return `record keys [${got}] are not [${want}]`;
  }
  return null;
}

function mismatch(want: Json, got: Json, path: string): string | null {
  for (const [k, w] of Object.entries(want)) {
    const g = got[k];
    if (w && typeof w === "object" && !Array.isArray(w)) {
      if (!g || typeof g !== "object") return `${path}${k}: expected an object, got ${JSON.stringify(g)}`;
      const m = mismatch(w as Json, g as Json, `${path}${k}.`);
      if (m) return m;
    } else if (JSON.stringify(w) !== JSON.stringify(g ?? null)) return `${path}${k}: expected ${JSON.stringify(w)}, got ${JSON.stringify(g ?? null)}`;
  }
  return null;
}

describe("P3.4C-2 loop lifecycle — the shared corpus against the simulated custodian", () => {
  it.each(corpus.scenarios.map((s) => [s.name, s] as const))("%s", async (_name, scenario) => {
    const scratch = realpathSync.native(mkdtempSync(join(tmpdir(), "cp-loopcorpus-")));
    try {
      const repo = join(scratch, "Corpus");
      mkdirSync(repo);
      let now = Date.parse("2026-10-12T12:00:00Z");
      const connection = { client: null as string | null };
      // P3.4C-5 Increment 3: the custodian's helper (the corpus's synthetic measurement) and an approved engine runtime.
      const t = new SimulatedCustodianTransport({ caller: "by_surface", now: () => now, processCheck: fixedProcessCheck, clientCheck: (bound) => fixedClientCheck(bound, connection.client), helper: { exportsRoot: join(scratch, "exports"), mode: "manual" } });
      t.seedEngineRuntime(join(scratch, "runtime"));
      await new CustodianOperator(t).mint(repo, 8, 60, "corpus-grant");
      const runner = new Runner(t, repo, (seconds) => (now += seconds * 1000), connection);
      const problems: string[] = [];
      for (const [i, step] of scenario.steps.entries()) {
        const p = await runner.step(step);
        if (p) problems.push(`step ${i + 1} (${step.op} ${String(step["kind"] ?? step["of"] ?? "")}): ${p}`);
      }
      expect(problems).toEqual([]);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it("the corpus covers every kind, both operator-only pauses, the replay rules and the bound-caller checks", () => {
    const kinds = new Set(corpus.scenarios.flatMap((s) => s.steps.map((x) => x["kind"])).filter(Boolean));
    for (const k of ["bind", "rebind", "spend_continuation", "wake_arm", "wake_consume", "pause", "resume", "end"]) expect(kinds.has(k), k).toBe(true);
    const text = JSON.stringify(corpus);
    for (const needle of ["operator_action_required", "user_decision_required", '"replayed":true', "CALLER_NOT_AUTHORIZED", "LOOP_TERMINAL", "RUN_ALREADY_HAS_LOOP", "SESSION_NOT_BOUND", '"client":"outsider"', '"client":"ended"', '"client":"reused"']) expect(text, needle).toContain(needle);
  });
});

const custodianExe = ["Debug", "Release"]
  .map((c) => join(ROOT, "custodian", "CodeParley.Custodian", "bin", c, "net10.0-windows", "CodeParley.Custodian.exe"))
  .find((p) => existsSync(p)) ?? null;

describe.skipIf(process.platform !== "win32" || custodianExe === null)("the same corpus against the REAL custodian ledger (self-test-loop-corpus, when built)", () => {
  it("passes every scenario", () => {
    const r = spawnSync(custodianExe!, ["self-test-loop-corpus", "--corpus", CORPUS_PATH], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
    expect(r.status, `${r.stdout}\n${r.stderr}`).toBe(0);
    expect(r.stdout).toMatch(/loop corpus self-test: all \d+ scenarios \(\d+ steps\) passed/);
  });
});
