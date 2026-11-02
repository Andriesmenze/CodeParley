// The TEST-ONLY hook-adapter entry (P3.4C-1). It mirrors test-server-source.ts: it runs the REAL
// packaged adapter code (src/hooks/adapter.ts `runHookProcess`), only injecting a simulated grant
// custodian through the adapter's narrowly scoped, test-only DI seam (HookIo.testHooks). The
// production entry (src/hooks/main.ts) never reads this config and never sets testHooks, so it always
// uses the real, authenticated PipeCustodianTransport and FAILS CLOSED when the custodian is absent;
// nothing in production selects a simulated or user-configurable authority (test/layering.test.ts).
//
// Spawned exactly as the host spawns the packaged adapter — `node test-hooks.mjs <event> <launch args>`
// on stdio, with CLAUDE_PID in the environment — so the host contract (output formats, exit codes,
// process identity) is exercised unchanged. Only CODEPARLEY_TEST_HOOK_CONFIG (a file with the shared
// simulated custodian's ledger path) distinguishes it, and it is read by this test entry alone.
export const TEST_HOOKS_SOURCE = `
import { readFileSync } from "node:fs";
import { runHookProcess } from "./hooks/adapter.js";
const cfg = JSON.parse(readFileSync(process.env.CODEPARLEY_TEST_HOOK_CONFIG, "utf8"));
const hooks = {};
if (cfg.custodianState) {
  const { SimulatedCustodianTransport } = await import("./custodian/transport.js");
  // P3.4C-5 Increment 3: the custodian derives a protected run through its (in-process) helper, with the launch's git;
  // a derivation lives in the answering custodian's memory, and a hook derives and spends in the same process.
  const argv = process.argv.slice(2);
  const gi = argv.indexOf("--git");
  const helper = { exportsRoot: cfg.custodianState + ".exports", mode: "auto", ...(gi >= 0 ? { gitExe: argv[gi + 1] } : {}) };
  hooks.custodian = { platform: "win32", transport: new SimulatedCustodianTransport({ caller: "by_surface", statePath: cfg.custodianState, helper }) };
}
await runHookProcess(process.argv.slice(2), Object.keys(hooks).length ? { testHooks: hooks } : {});
`;
