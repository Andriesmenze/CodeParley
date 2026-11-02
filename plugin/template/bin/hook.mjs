#!/usr/bin/env node
// CodeParley plugin: the hook launcher (Phase 3.3a). It adds the launch arguments recorded in
// ../launch.json (the data home and executables chosen when the plugin was built; none in a default
// build) and runs CodeParley's packaged hook adapter. It decides nothing: every decision is made by
// CodeParley's engine (app/dist/engine/continuation.js).
//
//   hooks/hooks.json: node "${CLAUDE_PLUGIN_ROOT}/bin/hook.mjs" <event> [adapter options]

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
let launch = [];
try {
  launch = JSON.parse(readFileSync(join(root, "launch.json"), "utf8")).argv ?? [];
} catch {
  /* a default build has no launch arguments */
}
const [event = "", ...extra] = process.argv.slice(2);
const { runHookProcess } = await import(pathToFileURL(join(root, "app", "dist", "hooks", "adapter.js")).href);
await runHookProcess([event, ...launch, ...extra]);
