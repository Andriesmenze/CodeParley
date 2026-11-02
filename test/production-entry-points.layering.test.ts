// Phase 6 Increment 1, S-3 (pre-merge item from P3.4C-3 §9.3): the `presence: "host"` test seam is unreachable from
// production. The production entry points (the package's `bin` and the hook entry) build the engine WITHOUT test hooks,
// so whether a custodian is installed is asked of the host's own service manager; no production input (argument,
// environment, configuration) can set `presence`. Pinned statically over the entry points and the engine's context
// builders, and behaviourally over the engine's own presence query.

import { describe, it, expect, vi } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const hostQuery = vi.hoisted(() => vi.fn(async () => "registered" as const));
vi.mock("../src/custodian/service-presence.js", async (orig) => ({ ...(await orig<object>()), custodianServicePresence: hostQuery }));

const { evidenceSelection } = await import("../src/engine/engine-env.js");
type Le = Parameters<typeof evidenceSelection>[0];
type Run = Parameters<typeof evidenceSelection>[1];

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(root, rel), "utf8");
/** The text with comments removed: what is code and string literals. */
const code = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

function sources(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name.endsWith(".ts")) out.push(full);
    }
  };
  walk(dir);
  return out;
}

describe("S-3 — the presence test seam is unreachable from the production entry points", () => {
  it("the three production entry points pass no test hooks", () => {
    const server = code(read("src/server/main.ts"));
    expect(server.match(/runServer\(/g)).toHaveLength(1);
    expect(server).toMatch(/runServer\(\{\s*argv:\s*process\.argv\.slice\(2\),\s*env:\s*process\.env\s*\}\)/);
    const hooks = code(read("src/hooks/main.ts"));
    expect(hooks.match(/runHookProcess\(/g)).toHaveLength(1);
    expect(hooks).toMatch(/runHookProcess\(process\.argv\.slice\(2\)\)/);
    const cli = code(read("src/cli/main.ts"));
    expect(cli).not.toMatch(/engineTestHooks|testHooks/);
    expect(cli).toMatch(/runCli\(process\.argv\.slice\(2\), io\)/);
    // package.json's bin names exactly these entry points (built to dist/).
    const pkg = JSON.parse(read("package.json")) as { bin: Record<string, string> };
    expect(pkg.bin).toEqual({ "code-parley": "dist/cli/main.js", "code-parley-mcp": "dist/server/main.js" });
  });

  it("test hooks reach the engine only through those entry points' option objects, never from the environment or arguments", () => {
    const srcFiles = sources(join(root, "src"));
    // Every place that hands test hooks to the engine takes them from its caller's options.
    const handing = srcFiles.filter((f) => /\btestHooks:\s/.test(code(readFileSync(f, "utf8")))).map((f) => relative(join(root, "src"), f).split(sep).join("/")).sort();
    for (const f of handing) {
      const text = code(readFileSync(join(root, "src", f), "utf8"));
      expect(text, f).not.toMatch(/testHooks:\s*(?:JSON\.parse|process\.env|argv)/);
    }
    // `presence` is set only by test code: no source assigns the seam's value.
    const assigning = srcFiles.filter((f) => /presence:\s*["']host["']/.test(code(readFileSync(f, "utf8"))));
    expect(assigning).toEqual([]);
    // No environment variable or argument names the presence seam.
    const envNamed = srcFiles.filter((f) => /process\.env\[?["'.]?\w*PRESENCE/i.test(code(readFileSync(f, "utf8"))));
    expect(envNamed).toEqual([]);
  });

  it("the engine's context builders derive presence from whether test hooks exist (production: none)", () => {
    const env = code(read("src/engine/engine-env.ts"));
    expect(env.match(/custodianPresence\(t !== undefined, t\?\.custodian\)/g)).toHaveLength(3);
    const loops = code(read("src/custodian/protected-loops.ts"));
    expect(loops).toMatch(/if \(!underTest\) return custodianServicePresence\(\);/);
  });

  it("without test hooks the engine asks the host's service manager; with them it never does", async () => {
    const run = { runId: "r", repoKey: "k", paths: { runJson: "x" }, meta: { repository_root: "C:\\repo" } } as unknown as Run;
    const production = { env: { launch: {}, sourceEnv: {}, owner: {} } } as unknown as Le;
    hostQuery.mockClear();
    expect(await evidenceSelection(production, run).presence()).toBe("registered");
    expect(hostQuery).toHaveBeenCalledTimes(1);
    const underTest = { env: { launch: {}, sourceEnv: {}, owner: {}, testHooks: {} } } as unknown as Le;
    hostQuery.mockClear();
    expect(await evidenceSelection(underTest, run).presence()).toBe("absent");
    const seam = { env: { launch: {}, sourceEnv: {}, owner: {}, testHooks: { custodian: { platform: process.platform, presence: "host" } } } } as unknown as Le;
    expect(await evidenceSelection(seam, run).presence()).toBe("registered");
    expect(hostQuery).toHaveBeenCalledTimes(1); // only the seam asked the host
  });
});
