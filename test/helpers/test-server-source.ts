// The TEST-ONLY MCP server entry (M1.5; moved here in M1.6 so the global setup can write it once
// beside the shared build). It wires the scripted fake Codex into the engine's test hooks; the
// production entry (src/server/main.ts) has no test hooks.
export const TEST_SERVER_SOURCE = `
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { runServer } from "./server/server.js";
const cfg = JSON.parse(readFileSync(process.env.CODEPARLEY_TEST_SERVER_CONFIG, "utf8"));
const hooks = { cancelPollMs: 150 };
if (cfg.worktreeWaitMs !== undefined) hooks.lockDeps = { worktreeWaitMs: cfg.worktreeWaitMs };
if (cfg.fake) {
  const runCodex = async (argv, cwd) => {
    const r = spawnSync(process.execPath, [cfg.fake.script, ...argv], { cwd, encoding: "utf8", timeout: 30000, windowsHide: true });
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  };
  const runPowerShell = async (script) => {
    if (script.includes("TcpClient") || script.includes("/dev/tcp/")) return { status: 0, stdout: "NET_OK", stderr: "" };
    if (script.includes("GetHostAddresses") || script.includes("getent hosts")) return { status: 0, stdout: "DNS_OK:1.2.3.4", stderr: "" };
    if (process.platform !== "win32") {
      const r = spawnSync("/bin/bash", ["--noprofile", "--norc", "-c", script], { encoding: "utf8", timeout: 30000 });
      return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
    }
    const m = /-LiteralPath '((?:[^']|'')*)'/.exec(script);
    const p = m ? m[1].replace(/''/g, "'") : "";
    try { return { status: 0, stdout: "READ_OK:" + readFileSync(p, "utf8").trim(), stderr: "" }; } catch (e) { return { status: 0, stdout: "READ_FAIL:" + String(e), stderr: "" }; }
  };
  // Phase 5 (§4.12): the fake Codex starts no bwrap; it stands for the installation's own, as a real sandbox shows it.
  let installation = "";
  const bwrapAt = (dir) => ({ path: dir + "/codex-resources/bwrap", sha256: "b".repeat(64) });
  const bwrap = { installed: async (dir) => ((installation = dir), bwrapAt(dir)), running: async () => [{ pid: 1, ...bwrapAt(installation) }] };
  hooks.review = { codexLauncher: { file: process.execPath, prefixArgs: [cfg.fake.script] }, selfTestDeps: { runCodex, runPowerShell, grantUsersRead: async () => true, bwrap }, sweep: null };
  hooks.checks = { sweep: null, exitGraceMs: 1500 };
}
if (cfg.custodianState) {
  // P3.4C-0: a simulated grant custodian (a Windows installation with the custodian), its ledger in a
  // file the test's in-process CLI shares. The production entry has no such hook.
  const { SimulatedCustodianTransport } = await import("./custodian/transport.js");
  // P3.4C-5: the custodian captures protected reviews itself (the in-process helper capture, the server's git).
  const gi = cfg.argv.indexOf("--git");
  const helper = { exportsRoot: cfg.custodianState + ".exports", mode: "auto", ...(gi >= 0 ? { gitExe: cfg.argv[gi + 1] } : {}) };
  hooks.custodian = { platform: "win32", transport: new SimulatedCustodianTransport({ caller: "by_surface", statePath: cfg.custodianState, helper }) };
}
await runServer({ argv: cfg.argv, env: process.env, testHooks: hooks, shutdownWaitMs: cfg.shutdownWaitMs ?? 15000, ...(cfg.retentionDelayMs !== undefined ? { retentionDelayMs: cfg.retentionDelayMs } : {}) });
`;
