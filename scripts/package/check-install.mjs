#!/usr/bin/env node
// Diagnose a CodeParley installation (Phase 5): is it complete, and can this Node.js run it?
//
//   node scripts/package/check-install.mjs [<package dir>] [--node <node executable>] [--no-probe] [--json]
//
// <package dir> is an installed package (for example <npm prefix>/node_modules/code-parley, or
// <prefix>/lib/node_modules/code-parley on Linux) or a built git checkout; the default is this
// repository. --node names the Node.js that will run CodeParley (default: the one running this).
// Exit status: 0 when nothing failed, 1 when a check failed, 2 on a usage error. Git, Codex,
// configuration and the store are `code-parley doctor`'s checks, not this one's.

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkInstall } from "./lib/install-check.mjs";
import { formatChecks, verdict } from "./lib/format.mjs";

function parse(argv) {
  const o = { dir: resolve(fileURLToPath(import.meta.url), "..", "..", ".."), node: process.execPath, probe: true, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--node") o.node = resolve(argv[++i] ?? "");
    else if (a === "--no-probe") o.probe = false;
    else if (a === "--json") o.json = true;
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else o.dir = resolve(a);
  }
  return o;
}

let o;
try {
  o = parse(process.argv.slice(2));
} catch (e) {
  process.stderr.write(`check-install: ${e.message}\n`);
  process.exit(2);
}
const report = checkInstall(o.dir, { nodePath: o.node, probe: o.probe });
if (o.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
else {
  process.stdout.write(`CodeParley installation check: ${report.package.dir} (${report.package.kind}); Node.js ${report.node.version ?? "?"} at ${report.node.path}\n`);
  for (const l of formatChecks(report.checks)) process.stdout.write(`${l}\n`);
  process.stdout.write(`${verdict(report.checks)}\n`);
}
process.exitCode = report.ok ? 0 : 1;
