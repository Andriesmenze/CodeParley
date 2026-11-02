#!/usr/bin/env node
// CodeParley plugin: the MCP server launcher (production entry, no test hooks). It adds the launch
// arguments recorded in ../launch.json and runs CodeParley's packaged stdio MCP server.

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
const { runServer } = await import(pathToFileURL(join(root, "app", "dist", "server", "server.js")).href);
await runServer({ argv: [...launch, ...process.argv.slice(2)], env: process.env });
