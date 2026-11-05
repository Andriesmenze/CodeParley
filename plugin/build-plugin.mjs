#!/usr/bin/env node
// Build a self-contained CodeParley Claude Code plugin (Phase 3.3a): thin hooks and the CodeParley
// MCP server. Nothing is installed and no settings are written.
//
//   node plugin/build-plugin.mjs (--out <dir> | --marketplace <dir>) [--node <node executable> | --node-path <path on the target>]
//        [launch arguments for the server and the hooks: --home <dir> --allowed-root <dir>...
//         --git <git> --codex <codex> --config <file>]
//        [--test-fake-codex --test-scenario-dir <dir>] [--dist <compiled sources, default dist/>]
//
// Requires `npm run build` first. It copies dist/ and the production dependencies into <plugin>/app,
// and writes .claude-plugin/plugin.json, hooks/hooks.json (every hook runs bin/hook.mjs, which
// forwards to CodeParley's engine), .mcp.json (the CodeParley server) and launch.json (the launch
// arguments above; none by default, so the default data home and configuration apply).
//
// --marketplace <dir> builds the plugin into <dir>/code-parley beside a local marketplace manifest
// (<dir>/.claude-plugin/marketplace.json), for a user-scope install:
//   claude plugin marketplace add <dir>
//   claude plugin install code-parley@code-parley-local --scope user
// and the reversal: claude plugin uninstall code-parley@code-parley-local --scope user;
//   claude plugin marketplace remove code-parley-local
// For one session only, without installing: claude --plugin-dir <plugin dir>
//
// --test-fake-codex (TEST ONLY, Phase 3.3a validation): the MCP server wires CodeParley's scripted
// fake Codex (test/fixtures/fake-codex) instead of Codex; --home is then required, so a test build
// never touches the real data home. The fake reviewer's scenario.json lives in --test-scenario-dir,
// OUTSIDE the plugin: a host may copy a plugin into its cache (Claude Desktop does), so nothing a
// test changes at run time may live inside the plugin. A test build says so in its manifest.
//
// Provenance (P3.3b): the plugin's version is the template's base version plus a digest of the
// plugin's content (plugin-content.mjs), and build-info.json records that digest, every file's hash,
// the source commit and whether the tree had changes. A host keys its plugin cache by version, so a
// changed build never reuses a stale cached copy; `node plugin/verify-plugin.mjs <dir>` checks any copy
// a host runs against its record and against the intended build.

import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, posix, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { productionPackages } from "../scripts/package/lib/production-packages.mjs";
import { BUILD_INFO, CONTENT_SCHEMA, EXCLUDED, contentDigest, contentFiles, versionOf } from "./plugin-content.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const PLUGIN = "code-parley";
const SERVER = "code-parley";
const MARKETPLACE = "code-parley-local";
const TOOL_PREFIX = `mcp__plugin_${PLUGIN}_${SERVER}__`;

function parse(argv) {
  const o = { out: null, marketplace: null, node: process.execPath, launch: [], testFakeCodex: false, scenarioDir: null, home: null, codex: null, dist: join(repo, "dist") };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => {
      const x = argv[++i];
      if (x === undefined) throw new Error(`${a} requires a value`);
      return x;
    };
    if (a === "--out") o.out = resolve(v());
    else if (a === "--marketplace") o.marketplace = resolve(v());
    else if (a === "--node") o.node = resolve(v());
    // Phase 6 Increment 3: a release plugin runs the installed engine runtime's Node, a path on the TARGET host (another
    // platform's form, e.g. /opt/codeparley/engine/current/node from Windows), kept verbatim.
    else if (a === "--node-path") {
      o.node = v();
      if (!(posix.isAbsolute(o.node) || win32.isAbsolute(o.node))) throw new Error("--node-path must be an absolute path on the target host");
    }
    else if (a === "--dist") o.dist = resolve(v());
    else if (a === "--test-fake-codex") o.testFakeCodex = true;
    else if (a === "--test-scenario-dir") o.scenarioDir = resolve(v());
    else if (a === "--home") o.launch.push(a, (o.home = resolve(v())));
    else if (a === "--codex") o.launch.push(a, (o.codex = resolve(v())));
    else if (a === "--allowed-root" || a === "--git" || a === "--config") o.launch.push(a, resolve(v()));
    else throw new Error(`unknown option ${a}`);
  }
  if (!o.out === !o.marketplace) throw new Error("give exactly one of --out <dir> or --marketplace <dir>");
  if (o.testFakeCodex && !o.home) throw new Error("--test-fake-codex requires --home (a test build never uses the real data home)");
  if (o.testFakeCodex && !o.scenarioDir) throw new Error("--test-fake-codex requires --test-scenario-dir (the fake reviewer's scenario, outside the plugin)");
  return o;
}

/** The plugin's hooks: every one runs the hook launcher (`entry`, bin/hook.mjs in a production build),
 * which forwards the host's event to CodeParley's engine. A test build points `entry` at the test-only
 * hook launcher (test/hook-fake-custodian.mjs), which runs the SAME packaged adapter with a simulated
 * custodian injected; bin/hook.mjs itself is never a test entry and reads no test configuration. */
export function hooksJson(node, entry = "${CLAUDE_PLUGIN_ROOT}/bin/hook.mjs") {
  const cmd = (event, extra = [], more = {}) => ({ type: "command", command: node, args: [entry, event, ...extra], ...more });
  return {
    description: "CodeParley same-session continuation adapter: thin hooks that forward host facts to CodeParley's engine, which makes every decision. Automation adds liveness only.",
    hooks: {
      SessionStart: [{ hooks: [cmd("session-start", [], { timeout: 30 })] }],
      SessionEnd: [{ hooks: [cmd("session-end")] }],
      UserPromptSubmit: [{ hooks: [cmd("user-prompt-submit", [], { timeout: 30 })] }],
      PreToolUse: [{ matcher: `${TOOL_PREFIX}.*`, hooks: [cmd("pre-tool-use", [], { timeout: 30 })] }],
      PostToolUse: [
        { matcher: `${TOOL_PREFIX}start_review_loop$`, hooks: [cmd("post-tool-use", [], { timeout: 60 })] },
        // The only cross-host idle wake (P3.2): asyncRewake exits 2 to wake the same idle session.
        { matcher: `${TOOL_PREFIX}review_with_codex$`, hooks: [cmd("wake", ["--max-seconds", "900"], { asyncRewake: true, timeout: 960 })] },
      ],
      Stop: [{ hooks: [cmd("stop", [], { timeout: 120 })] }],
      ConfigChange: [{ hooks: [cmd("config-change", [], { timeout: 30 })] }],
    },
  };
}

function writeJson(p, v) {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, `${JSON.stringify(v, null, 2)}\n`);
}

/** The checkout the build came from: its commit and whether the files a build packages had changes. */
function sourceOf() {
  const git = (...a) => execFileSync("git", ["-C", repo, ...a], { encoding: "utf8", windowsHide: true }).trim();
  try {
    const dirty = git("status", "--porcelain", "--", "src", "prompts", "plugin", "package.json", "package-lock.json");
    return { commit: git("rev-parse", "HEAD"), dirty: dirty.length > 0, tool_version: JSON.parse(readFileSync(join(repo, "package.json"), "utf8")).version };
  } catch {
    return { commit: null, dirty: null, tool_version: JSON.parse(readFileSync(join(repo, "package.json"), "utf8")).version };
  }
}

function build(o) {
  const dist = o.dist;
  if (!existsSync(join(dist, "hooks", "adapter.js")) || !existsSync(join(dist, "server", "server.js"))) throw new Error("dist/ is missing or stale: run `npm run build` first");
  const root = o.marketplace ? join(o.marketplace, PLUGIN) : o.out;
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  const tpl = join(here, "template");
  cpSync(join(tpl, ".claude-plugin"), join(root, ".claude-plugin"), { recursive: true });
  cpSync(join(tpl, "bin"), join(root, "bin"), { recursive: true });
  // The application: compiled sources (no maps or declarations) and the production dependencies.
  cpSync(dist, join(root, "app", "dist"), { recursive: true, filter: (s) => !/\.(d\.ts|js\.map|d\.ts\.map)$/.test(s) });
  // The production dependency closure, from the repository's own node_modules (offline; fail-closed:
  // scripts/package/lib/production-packages.mjs).
  for (const rel of productionPackages(repo)) cpSync(join(repo, "node_modules", rel), join(root, "app", "node_modules", rel), { recursive: true });
  // The reviewer's prompt templates (src/prompts/render.ts looks for prompts/ above dist/).
  cpSync(join(repo, "prompts"), join(root, "app", "prompts"), { recursive: true });
  writeJson(join(root, "app", "package.json"), { name: "code-parley-app", private: true, type: "module", version: JSON.parse(readFileSync(join(repo, "package.json"), "utf8")).version });

  const launch = [...o.launch];
  let serverEntry = "${CLAUDE_PLUGIN_ROOT}/bin/server.mjs";
  let hookEntry = "${CLAUDE_PLUGIN_ROOT}/bin/hook.mjs";
  const manifest = JSON.parse(readFileSync(join(tpl, ".claude-plugin", "plugin.json"), "utf8"));
  // Phase 6 Increment 1: the plugin's base version is the release version (package.json); a mismatch is a build error.
  const releaseVersion = JSON.parse(readFileSync(join(repo, "package.json"), "utf8")).version;
  if (manifest.version !== releaseVersion) throw new Error(`the plugin template's version ${manifest.version} is not the release version ${releaseVersion} (package.json)`);
  if (o.testFakeCodex) {
    cpSync(join(tpl, "test"), join(root, "test"), { recursive: true });
    // The fake reviewer runs from the scenario directory: it reads scenario.json beside itself.
    mkdirSync(o.scenarioDir, { recursive: true });
    cpSync(join(repo, "test", "fixtures", "fake-codex", "fake-codex.mjs"), join(o.scenarioDir, "fake-codex.mjs"));
    if (!existsSync(join(o.scenarioDir, "scenario.json"))) writeJson(join(o.scenarioDir, "scenario.json"), {});
    if (!o.codex) {
      // The Codex probe needs an executable's identity; it is never run (an empty placeholder on Windows).
      // It lives beside the scenario, outside the plugin, so launch.json never names the plugin's own
      // location: the build's content (and its version) does not depend on where it was built.
      const placeholder = join(o.scenarioDir, "codex-placeholder", process.platform === "win32" ? "codex.exe" : "codex");
      mkdirSync(dirname(placeholder), { recursive: true });
      if (process.platform === "win32") writeFileSync(placeholder, "");
      else {
        // A regular-file copy of what /bin/true resolves to: it may be a symbolic link (a multicall coreutils), which
        // cpSync would copy as a link, so a second build into the same scenario folder found source and destination the
        // same file. Remove first, so a repeated build never writes through an older placeholder.
        rmSync(placeholder, { force: true });
        copyFileSync("/bin/true", placeholder);
      }
      launch.push("--codex", placeholder);
    }
    serverEntry = "${CLAUDE_PLUGIN_ROOT}/test/server-fake-codex.mjs";
    hookEntry = "${CLAUDE_PLUGIN_ROOT}/test/hook-fake-custodian.mjs";
    manifest.description = `TEST BUILD (scripted fake Codex, data home ${o.home}). ${manifest.description}`;
  }
  writeJson(join(root, "launch.json"), { argv: launch, ...(o.testFakeCodex ? { test_scenario_dir: o.scenarioDir } : {}) });
  writeJson(join(root, "hooks", "hooks.json"), hooksJson(o.node, hookEntry));
  writeJson(join(root, ".mcp.json"), { mcpServers: { [SERVER]: { command: o.node, args: [serverEntry] } } });
  // The content identity, then the files that carry it (excluded from the digest).
  const { files } = contentFiles(root);
  const digest = contentDigest(files);
  manifest.version = versionOf(manifest.version, digest);
  writeJson(join(root, ".claude-plugin", "plugin.json"), manifest);
  writeJson(join(root, BUILD_INFO), {
    schema: "codeparley.plugin-build.v1",
    name: manifest.name,
    version: manifest.version,
    test_build: o.testFakeCodex,
    content: { schema: CONTENT_SCHEMA, digest, excluded: EXCLUDED, files },
    source: sourceOf(),
    launch_argv: launch,
    built_at: new Date().toISOString(),
  });
  if (o.marketplace) {
    writeJson(join(o.marketplace, ".claude-plugin", "marketplace.json"), {
      name: MARKETPLACE,
      owner: { name: "Andries van der Merk" },
      plugins: [{ name: PLUGIN, source: `./${PLUGIN}`, description: manifest.description }],
    });
  }
  return root;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const root = build(parse(process.argv.slice(2)));
    const info = JSON.parse(readFileSync(join(root, BUILD_INFO), "utf8"));
    process.stdout.write(`built the CodeParley plugin at ${root}\n  version ${info.version}${info.test_build ? " (TEST BUILD)" : ""}; content digest ${info.content.digest}; source ${info.source.commit ?? "unknown"}${info.source.dirty ? " with uncommitted changes" : ""}\n`);
  } catch (e) {
    process.stderr.write(`build-plugin: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  }
}
