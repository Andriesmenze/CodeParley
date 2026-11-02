#!/usr/bin/env node
// Entry point of the Claude Code hook adapter (see adapter.ts): node dist/hooks/main.js <event> [launch arguments].

import { runHookProcess } from "./adapter.js";

await runHookProcess(process.argv.slice(2));
