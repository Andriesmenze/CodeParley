#!/usr/bin/env node
// TEST ONLY — present only in a plugin built with --test-fake-codex (Phase 3.4C-1 validation). The hook
// launcher with a simulated grant custodian wired into the adapter's test-only DI seam, exactly as the
// repository's test-hooks entry and server-fake-codex.mjs do. It runs the REAL packaged adapter
// (app/dist/hooks/adapter.js `runHookProcess`); only the custodian transport is injected, so the host
// contract (output formats, exit codes, process identity) is exercised unchanged. A production build
// never contains this file, and bin/hook.mjs never reads any test configuration: the production adapter
// always uses the real, authenticated custodian and fails closed when it is absent.
//
//   hooks/hooks.json (test build): node "${CLAUDE_PLUGIN_ROOT}/test/hook-fake-custodian.mjs" <event> [options]

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const config = JSON.parse(readFileSync(join(root, "launch.json"), "utf8"));
const launch = config.argv ?? [];
const [event = "", ...extra] = process.argv.slice(2);

// The custodian's ledger lives in the scenario directory (outside the plugin), shared with the test's
// operator CLI and the plugin's own fake-Codex server, so all three see the same grants and user records.
const { SimulatedCustodianTransport } = await import(pathToFileURL(join(root, "app", "dist", "custodian", "transport.js")).href);
// P3.4C-5 Increment 3: the custodian derives a protected run through its helper (in process, with the launch's git); a
// derivation lives in the answering custodian's memory, and a hook derives and spends in the same process.
const testHooks = {
  custodian: {
    platform: "win32",
    transport: new SimulatedCustodianTransport({
      caller: "by_surface",
      statePath: join(config.test_scenario_dir, "custodian-state.json"),
      helper: { exportsRoot: join(config.test_scenario_dir, "custodian-exports"), mode: "auto", ...(launch.includes("--git") ? { gitExe: launch[launch.indexOf("--git") + 1] } : {}) },
    }),
  },
};
const { runHookProcess } = await import(pathToFileURL(join(root, "app", "dist", "hooks", "adapter.js")).href);
await runHookProcess([event, ...launch, ...extra], { testHooks });
