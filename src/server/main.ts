#!/usr/bin/env node
// Entry point of the code-parley MCP server (stdio). Host configuration (plan B.1):
//   node.exe <install>\dist\server\main.js --allowed-root <dir> [--diagnostics] [--home <dir>]
// stdout is reserved for MCP messages.

import { runServer } from "./server.js";

await runServer({ argv: process.argv.slice(2), env: process.env });
