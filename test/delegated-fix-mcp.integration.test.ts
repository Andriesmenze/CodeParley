// Phase 4 Increment 3 — the MCP surface of a delegated fix (contract §3.1), called in process through the server's own
// dispatcher against the simulated custodian: delegate_fix starts the fix and returns its verdict or a handle;
// get_review_status reports the run's fixes as the custodian holds them; no tool confirms — the owner does, at the operator
// terminal; apply_fix applies exactly the confirmed content. The fixer is the engine's test seam (the real one is
// Increment 1's launchFixer, verified on the VM).

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { callTool, type Session } from "../src/server/tools.js";
import type { CallContext, ToolOutcome } from "../src/server/sdk.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1, MATH_V2 } from "./helpers/review-fixture.js";
import { cli, operatorIo, type ContFixture } from "./helpers/continuation-fixture.js";
import { confirmFix, editing, opsOf, protectedRun, storeFixSelfTest_ } from "./helpers/delegated-fix.js";
import type { RunHandle } from "../src/engine/engine-env.js";

const BOUND = { timeout: 300_000 };

function ctx(): CallContext {
  return {
    signal: new AbortController().signal, progress: () => undefined, protocolVersion: "2025-11-25", era: "legacy", clientInfo: { name: "test", version: "1" },
    clientSupportsRoots: false, rootsResponse: null, listRootsNow: async () => null,
  };
}

const session = (f: ContFixture): Session => ({ env: f.le.env, diagnostics: false, legacyRoots: [f.repo], log: () => undefined });

/** The structured result of a call (or its error). */
const call = async (f: ContFixture, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> => {
  const out: ToolOutcome = await callTool(session(f), name, args, ctx());
  if (out.kind !== "result") throw new Error(`${name}: ${out.kind}`);
  return out.structuredContent;
};

async function ready(): Promise<{ f: ContFixture; run: RunHandle }> {
  const { f, run } = await protectedRun(2);
  await storeFixSelfTest_(f);
  await confirmFix(f);
  (f.le.env.testHooks as { fix?: unknown }).fix = { launch: editing("src/math.js", MATH_V1) };
  return { f, run };
}

describe.skipIf(!supported)("Phase 4 Increment 3: delegate_fix and apply_fix over MCP (no tool confirms)", BOUND, () => {
  it("delegate_fix → (the owner confirms at the terminal) → apply_fix; get_review_status reports the fix as the custodian holds it", async () => {
    const { f, run } = await ready();
    const delegated = await call(f, "delegate_fix", { run_id: run.runId, task: "add() subtracts: make it return a + b.", boundary: { permitted_files: ["src/math.js"], max_changed_files: 1 }, wait_seconds: 45 });
    expect(delegated["status"], JSON.stringify(delegated)).toBe("proposed");
    expect(String(delegated["next"])).toContain("code-parley fix confirm");
    const proposal = String(delegated["proposal_id"]);
    expect(await readFile(join(f.repo, "src", "math.js"), "utf8")).toBe(MATH_V2);

    const status = await call(f, "get_review_status", { run_id: run.runId });
    const fixes = status["fixes"] as { proposal_id: string; status: string; proposal: { changes: { path: string }[] } }[];
    expect(fixes).toMatchObject([{ proposal_id: proposal, status: "proposed", proposal: { changes: [{ path: "src/math.js", kind: "modify" }] } }]);
    expect(JSON.stringify(status)).not.toContain("a + b"); // no content in the status
    // The continuation awaits the owner.
    expect(JSON.stringify(status["continuation"] ?? {})).not.toContain("implementer_step");

    // No tool confirms: apply_fix before the owner's decision is refused.
    const early = await call(f, "apply_fix", { run_id: run.runId, proposal_id: proposal });
    expect(JSON.stringify(early)).toContain("FIX_NOT_CONFIRMED");
    // A confirmation-shaped argument is refused by the strict schema.
    const forged = await call(f, "apply_fix", { run_id: run.runId, proposal_id: proposal, confirmation_id: "c-1" });
    expect(JSON.stringify(forged)).toContain("INVALID_ARGUMENT");
    const smuggled = await call(f, "delegate_fix", { run_id: run.runId, task: "x", boundary: { permitted_files: ["src/math.js"] }, content: "ZXhw" });
    expect(JSON.stringify(smuggled)).toContain("INVALID_ARGUMENT");

    expect((await cli(f, ["fix", "confirm", run.runId, proposal, "--repo", f.repo], operatorIo("confirm"))).code).toBe(0);
    const applied = await call(f, "apply_fix", { run_id: run.runId, proposal_id: proposal });
    expect(applied).toMatchObject({ status: "applied", proposal_id: proposal, files: [{ path: "src/math.js", state: "postimage" }] });
    expect(String(applied["next"])).toContain("fresh checks");
    expect(await readFile(join(f.repo, "src", "math.js"), "utf8")).toBe(MATH_V1);
    expect(opsOf(f, run, "apply").map((o) => o.status)).toEqual(["applied"]);
    const after = await call(f, "get_review_status", { run_id: run.runId });
    expect((after["fixes"] as { status: string; applications: { status: string }[] }[])[0]).toMatchObject({ status: "consumed", applications: [{ status: "applied" }] });
  });
});
