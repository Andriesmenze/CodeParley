#!/usr/bin/env node
// TEST ONLY — present only in a plugin built with --test-fake-codex (Phase 3.3a validation). The MCP
// server launcher with CodeParley's scripted fake Codex (test/fixtures/fake-codex) wired into the
// engine's test hooks, as the repository's MCP test server does: no real Codex runs, nothing leaves
// the machine. The fake reviewer reads scenario.json from launch.json's test_scenario_dir (outside the
// plugin, which a host may copy into its cache). A production build never contains this file.

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const config = JSON.parse(readFileSync(join(root, "launch.json"), "utf8"));
const launch = config.argv ?? [];
// The fake reviewer lives in the scenario directory, outside the plugin (it reads scenario.json
// beside itself and records its calls there).
const fakeScript = join(config.test_scenario_dir, "fake-codex.mjs");

const runCodex = async (argv, cwd) => {
  const r = spawnSync(process.execPath, [fakeScript, ...argv], { cwd, encoding: "utf8", timeout: 30000, windowsHide: true });
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
  try {
    return { status: 0, stdout: "READ_OK:" + readFileSync(p, "utf8").trim(), stderr: "" };
  } catch (e) {
    return { status: 0, stdout: "READ_FAIL:" + String(e), stderr: "" };
  }
};

// P3.4C-0: a simulated grant custodian (a Windows installation with the custodian), its ledger in the
// scenario directory so the test's operator CLI shares it. Never present in a production build.
const { SimulatedCustodianTransport } = await import(pathToFileURL(join(root, "app", "dist", "custodian", "transport.js")).href);
const testHooks = {
  review: { codexLauncher: { file: process.execPath, prefixArgs: [fakeScript] }, selfTestDeps: { runCodex, runPowerShell, grantUsersRead: async () => true }, sweep: null },
  checks: { sweep: null, exitGraceMs: 1500 },
  // P3.4C-5: the simulated custodian captures protected reviews itself (its helper runs the engine's capture in process,
  // with the server's git).
  custodian: {
    platform: "win32",
    transport: new SimulatedCustodianTransport({
      caller: "by_surface",
      statePath: join(config.test_scenario_dir, "custodian-state.json"),
      helper: { exportsRoot: join(config.test_scenario_dir, "custodian-exports"), mode: "auto", ...(launch.includes("--git") ? { gitExe: launch[launch.indexOf("--git") + 1] } : {}) },
    }),
  },
};
const { runServer } = await import(pathToFileURL(join(root, "app", "dist", "server", "server.js")).href);
await runServer({ argv: [...launch, ...process.argv.slice(2)], env: process.env, testHooks });
