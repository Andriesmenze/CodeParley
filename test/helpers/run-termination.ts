// TD, candidate 3: the fixture and helpers of the run-termination suite (run-termination.test.ts,
// run-termination-behaviour.test.ts and run-termination-repository.test.ts), moved there unchanged from the one file it
// was until Step 6.

import { expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli } from "../../src/cli/cli.js";
import { delegateFix } from "../../src/engine/fix-operation.js";
import { applyFix, SimulatedKill } from "../../src/engine/fix-apply.js";
import { establishCustodianEnd, type CustodianEndResult } from "../../src/engine/custodian-evidence.js";
import { evidenceSelection, type RunHandle } from "../../src/engine/engine-env.js";
import { SimulatedCustodianTransport } from "../../src/custodian/transport.js";
import { MATH_V1, MATH_V2 } from "./review-fixture.js";
import { cli, operatorIo, type ContFixture } from "./continuation-fixture.js";
import { TASK, codeOf, confirmFix, editing, opsOf, protectedRun, storeFixSelfTest_ } from "./delegated-fix.js";

export const BOUND = { timeout: 300_000 };

/** A protected run with a confirmed delegated fix, unapplied: what an operator wants to stop. */
export async function confirmed(): Promise<{ f: ContFixture; run: RunHandle; op: string }> {
  const { f, run } = await protectedRun(2, { accounts: true });
  await storeFixSelfTest_(f);
  await confirmFix(f);
  const r = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
  expect(r.status, r.detail ?? "").toBe("proposed");
  const c = await cli(f, ["fix", "confirm", run.runId, r.operation_id, "--repo", f.repo], operatorIo("confirm", true));
  expect(c.code, c.err).toBe(0);
  expect(opsOf(f, run, "fix").map((o) => o.status)).toEqual(["confirmed"]);
  return { f, run, op: r.operation_id };
}

export const custodianRun = (f: ContFixture, run: RunHandle) => f.custodian.snapshot().runs.find((r) => r.runId === run.runId)!;
export const math = (f: ContFixture): Promise<string> => readFile(join(f.repo, "src", "math.js"), "utf8");
export const operatorStop = (f: ContFixture, run: RunHandle, ...flags: string[]) => cli(f, ["runs", "stop", run.runId, ...flags], operatorIo(""));
export const implementerStop = (f: ContFixture, run: RunHandle, ...flags: string[]) => cli(f, ["runs", "stop", run.runId, ...flags], { ...operatorIo(""), engineTestHooks: f.le.env.testHooks! });
export const operator = (f: ContFixture) => f.operatorCustodian!;

/** The application the engine would make: refused, and nothing written. */
export async function refusedForGood(f: ContFixture, run: RunHandle, op: string): Promise<void> {
  expect(await codeOf(applyFix(f.le, run, { proposal_id: op }))).toBe("RUN_TERMINAL");
  expect(await math(f)).toBe(MATH_V2);
}

/** What candidate 2 printed when the custodian had not ended the run. */
export function claimsNothing(out: string): void {
  expect(out).not.toMatch(/the run is closed/);
  expect(out).toMatch(/NOT ended|UNKNOWN/);
}

export const atCustodian = (f: ContFixture, runId: string, repo: string, ...flags: string[]) => cli(f, ["runs", "stop", runId, "--repo", repo, ...flags], operatorIo(""));

export const ends = (t: SimulatedCustodianTransport) => t.received.filter((x) => x.op === "run_transition" && x.args.kind === "end");

/** The command from an operator account's own home, which holds no run store. */
export async function fromEmptyHome(f: ContFixture, args: string[]): Promise<{ code: number; out: string; err: string }> {
  const home = await mkdtemp(join(f.scratch, "operator-home-"));
  const io = operatorIo("", true, f.operatorHooks!);
  const code = await runCli([...args, "--home", home, "--git", f.git], io);
  return { code, out: io.lines.join("\n"), err: io.errors.join("\n") };
}

/** A transport that loses every reply to a run transition, after delivery. */
export function lossy(t: SimulatedCustodianTransport): SimulatedCustodianTransport {
  return new Proxy(t, {
    get(target, k, r) {
      if (k === "send") return async (s: never, op: never, a: never, id: never) => {
        target.failNext("run_transition", "lost_response");
        return target.send(s, op, a, id);
      };
      return Reflect.get(target, k, r) as unknown;
    },
  });
}

/** The end with every answer lost after delivery: the transport drops each reply, so no attempt is acknowledged. */
export async function stopWithEveryAnswerLost(f: ContFixture, run: RunHandle): Promise<CustodianEndResult> {
  return establishCustodianEnd({ ...evidenceSelection(f.le, run), custodian: { platform: process.platform, transport: lossy(operator(f)) } }, run.paths, f.le.env.owner, { status: "closed", reason: "lost" }, ["operator"]).then((r) => {
    if (r.outcome === "ended") throw new Error("the first attempt's reply was not lost");
    return r;
  });
}

/** An operation the custodian holds as running, as a writer that stays alive would leave it: checks, or an application
 * that stopped before its first write. */
export async function busyRun(f: ContFixture, run: RunHandle, kind: "checks" | "apply" = "checks"): Promise<void> {
  if (kind === "apply") {
    await expect(applyFix(f.le, run, { proposal_id: opsOf(f, run, "fix")[0]!.operationId }, { beforeReplace: () => { throw new SimulatedKill(); } })).rejects.toBeInstanceOf(SimulatedKill);
    return;
  }
  const begun = await f.custodian.send("implementer", "run_transition", { repositoryRoot: run.meta.repository_root, runId: run.runId, kind: "op_begin", fields: { operationKind: "checks", planned: [{ check: "unit", checkSpecId: null, definitionDigest: null, required: true }], inputIdentity: null } }, "busy-1");
  expect(begun.ok, begun.error).toBe(true);
}
