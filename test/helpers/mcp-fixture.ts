// A repository + data home + approved checks + fake Codex + server configuration for MCP
// protocol tests (M1.5). The repository has a changed confidential `.env` (MR-F) and a
// planted defect in src/math.js (the default review scenario reports it).

import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { SimulatedCustodianTransport } from "../../src/custodian/transport.js";
import type { EngineTestHooks } from "../../src/engine/engine-env.js";
import { approve } from "./checks-fixture.js";
import { defect, makeReviewFixture, okScenario, output, setScenario, type FakeScenario, type ReviewFixture } from "./review-fixture.js";
import { connect, sc, writeServerConfig, type Conn, type ConnectOptions, type Flavor } from "./mcp-harness.js";

export const NODE = process.execPath;

export interface McpFixture extends ReviewFixture {
  cfgPath: string;
  argv: string[];
  /** The file-backed simulated custodian the test server uses (a Windows installation with the custodian). */
  custodianState: string;
}

/** Engine test hooks with a simulated custodian over `statePath` (an in-process CLI shares a server's ledger). */
export function custodianHooks(statePath: string): EngineTestHooks {
  return { custodian: { platform: "win32", transport: new SimulatedCustodianTransport({ caller: "by_surface", statePath }) } };
}

export interface McpFixtureOptions {
  extraFiles?: Record<string, string>;
  /** config.json content for the data home (e.g. client_roots strict mode). */
  config?: Record<string, unknown>;
  scenario?: FakeScenario;
  /** Allowed root (default: the repository itself). */
  allowedRoot?: string;
  diagnostics?: boolean;
  shutdownWaitMs?: number;
  worktreeWaitMs?: number;
}

export async function mcpFixture(o: McpFixtureOptions = {}): Promise<McpFixture> {
  const f = await makeReviewFixture(o.extraFiles ?? {});
  await approve(f, {
    checks: {
      unit: { argv: [NODE, "scripts/pass.js", "CHECK_STDOUT_TOKEN_9f2"] },
      flag: { argv: [NODE, "scripts/flag.js"] },
      slow: { argv: [NODE, "scripts/sleep.js", "25000"] },
      slow2: { argv: [NODE, "scripts/sleep.js", "25000"] },
    },
    profiles: { default: ["unit"], slowset: ["slow"] },
    required_profiles: ["default"],
  });
  await setScenario(f, o.scenario ?? okScenario(output({ findings: [defect()] })));
  if (o.config) {
    await mkdir(f.dataHome, { recursive: true });
    await writeFile(join(f.dataHome, "config.json"), JSON.stringify({ schema_version: 1, ...o.config }));
  }
  const argv = ["--home", f.dataHome, "--allowed-root", o.allowedRoot ?? f.repo, "--codex", f.codexExe, "--git", f.git, ...(o.diagnostics === false ? [] : ["--diagnostics"])];
  const custodianState = join(f.scratch, "custodian-state.json");
  const cfgPath = await writeServerConfig(f.scratch, {
    argv,
    fake: { script: f.fakeScript },
    custodianState,
    ...(o.shutdownWaitMs !== undefined ? { shutdownWaitMs: o.shutdownWaitMs } : {}),
    ...(o.worktreeWaitMs !== undefined ? { worktreeWaitMs: o.worktreeWaitMs } : {}),
  });
  return { ...f, cfgPath, argv, custodianState };
}

export async function open(f: McpFixture, flavor: Flavor, o: ConnectOptions = {}): Promise<Conn> {
  return connect(flavor, f.cfgPath, o);
}

/** Create a run and wait for its baseline. */
export async function newRunOver(c: Conn, f: McpFixture, extra: Record<string, unknown> = {}): Promise<string> {
  const r = sc(await c.call("create_review_run", { task_envelope: { goal: "Review the add() change" }, repository_root: f.repo, wait_seconds: 40, ...extra }));
  if (typeof r["run_id"] !== "string") throw new Error(`create_review_run failed: ${JSON.stringify(r).slice(0, 400)}`);
  return r["run_id"];
}

export function slowReviewScenario(sleepMs: number, extra: Partial<NonNullable<FakeScenario["exec"]>> = {}): FakeScenario {
  return okScenario(output({ findings: [defect()] }), { sleep_ms: sleepMs, ...extra });
}
