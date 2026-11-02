#!/usr/bin/env node
// Entry point for the `code-parley` CLI (see cli.ts). Prompts only on an interactive
// terminal; otherwise commands that need confirmation require --confirm.

import { createInterface } from "node:readline/promises";
import { runCli, type CliIo } from "./cli.js";

const interactive = process.stdin.isTTY === true;
const io: CliIo = {
  // User records (Phase 2.3) need stdin AND stdout to be terminals: the user sees what they confirm.
  interactive: interactive && process.stdout.isTTY === true,
  out: (l) => process.stdout.write(l + "\n"),
  err: (l) => process.stderr.write(l + "\n"),
  prompt: interactive
    ? async (q) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        try {
          return await rl.question(q);
        } finally {
          rl.close();
        }
      }
    : null,
  env: process.env,
  cwd: process.cwd(),
};

process.exitCode = await runCli(process.argv.slice(2), io);
