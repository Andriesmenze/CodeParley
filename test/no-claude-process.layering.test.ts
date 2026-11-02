// Phase 5 NL-22 ([[D-01]], [[D-02]]): no path anywhere starts, restores or replaces a Claude process — CodeParley keeps the
// ORIGINATING session iterating (Stop-hook continuations, asyncRewake) and never runs a Claude of its own. Pinned
// statically over the engine (TypeScript) and the custodian (the portable core and both hosts, Windows and Linux).
//  - The engine: no module names a Claude executable as a command, and none carries a flag that resumes, continues or
//    forks a Claude session. (Only src/process/* spawns at all: layering.test.ts.)
//  - The custodian: outside its CLI self-tests and verbs, only the helper launchers start processes — Windows
//    (`HelperProcess`, `HelperChild`, `AppContainerLauncher` over the `HelperNative` declarations) and Linux
//    (`LinuxHelperAgent`, which starts exactly the approved runtime's `node`); no product string literal names Claude.

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const rel = (base: string, f: string) => relative(base, f).split(sep).join("/");

function files(dir: string, ext: string, skip: (rel: string) => boolean = () => false): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, e.name);
      if (e.isDirectory()) {
        if (e.name === "bin" || e.name === "obj") continue;
        walk(full);
      } else if (e.name.endsWith(ext) && !skip(rel(root, full))) out.push(full);
    }
  };
  walk(dir);
  return out;
}

/** The text with comments removed (block, line and C# doc comments): what is code and string literals. */
const code = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

describe("NL-22 — no path starts, restores or replaces a Claude process (D-01)", () => {
  it("the engine names no Claude executable as a command and carries no flag that resumes, continues or forks a session", () => {
    const src = files(join(root, "src"), ".ts");
    const exe = /["'`](?:claude|claude\.exe|claude\.cmd|claude-code|@anthropic-ai\/claude-code)["'`]/;
    const flags = /["'`]--(?:resume|continue|fork-session|session-id)["'`]/;
    const named = src.filter((f) => exe.test(code(readFileSync(f, "utf8")))).map((f) => rel(join(root, "src"), f));
    // engine/continuation.ts: the literal "claude" is the label of the session's own process in the liveness check of the
    // ORIGINATING session (it observes that process; it starts nothing).
    expect(named).toEqual(["engine/continuation.ts"]);
    expect(code(readFileSync(join(root, "src/engine/continuation.ts"), "utf8")).match(new RegExp(exe.source, "g"))).toEqual(['"claude"']);
    // Phase 6 Increment 3: CodeParley's OWN option `setup --resume` (the operator's re-confirmation of lapsed records) is
    // parsed in cli/cli.ts and read in cli/setup-commands.ts; neither file starts a process, so the literal is never an
    // argument to one.
    const withFlags = src.filter((f) => flags.test(code(readFileSync(f, "utf8")))).map((f) => rel(join(root, "src"), f));
    expect(withFlags).toEqual(["cli/cli.ts", "cli/setup-commands.ts"]);
    for (const f of withFlags) {
      const t = code(readFileSync(join(root, "src", f), "utf8"));
      expect(t, f).not.toMatch(/node:child_process|process\/spawn\.js|runProcess\(|spawn\(/);
      expect([...new Set(t.match(new RegExp(flags.source, "g")))], f).toEqual(['"--resume"']);
    }
  });

  it("the custodian (core, Windows and Linux hosts) starts processes only in its helper launchers, and no literal is a Claude command", () => {
    const custodian = join(root, "custodian");
    const product = files(custodian, ".cs", (r) => r.includes("/Cli/") || r.startsWith("custodian/scripts/"));
    const launches = /\bProcess\.Start\(|new\s+ProcessStartInfo\b|\bCreateProcess(?:AsUser)?W?\(|\bposix_spawn|\bexecve\(/;
    const launching = product.filter((f) => launches.test(code(readFileSync(f, "utf8")))).map((f) => rel(custodian, f)).sort();
    expect(launching).toEqual([
      "CodeParley.Custodian.Linux/Ipc/LinuxHelperAgent.cs",
      "CodeParley.Custodian/Interop/HelperNative.cs",
      "CodeParley.Custodian/Security/AppContainerLauncher.cs",
      "CodeParley.Custodian/Security/HelperChild.cs",
      "CodeParley.Custodian/Security/HelperProcess.cs",
    ]);
    // The Linux helper agent starts exactly the approved runtime's node (the launch the custodian measured).
    const agent = code(readFileSync(join(custodian, "CodeParley.Custodian.Linux/Ipc/LinuxHelperAgent.cs"), "utf8"));
    expect(agent.match(/new\s+ProcessStartInfo\(([^)]*)\)/g)).toEqual(["new ProcessStartInfo(launch.Node)"]);
    // No product string literal is a Claude command (the custodian's other mentions refuse Claude credentials in a check's
    // environment, protect `.claude/` and `CLAUDE.md` from a delegated fix, or name the CLAUDE_PID claim: none starts one).
    const command = /"(?:[^"\n]*[\\/])?(?:claude|claude\.exe|claude\.cmd|claude-code)"/; // executables are lower-case; `CLAUDE*` is an environment prefix the custodian refuses
    const literals = product.filter((f) => command.test(code(readFileSync(f, "utf8")))).map((f) => rel(custodian, f));
    expect(literals).toEqual([]);
  });
});
