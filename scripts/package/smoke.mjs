#!/usr/bin/env node
// Clean-install smoke test of CodeParley's distributable package (Phase 5).
//
//   node scripts/package/smoke.mjs [--tarball <code-parley-x.y.z.tgz>] [--node <node executable>]
//        [--npm-cli <npm-cli.js>] [--mode global|local|both] [--work <dir>] [--keep]
//        [--shared-cache] [--no-faults] [--report <file>] [--json]
//
// Without --tarball it packs this checkout first (pack.mjs). Then, in a new directory under --work
// (default: the system temporary directory) with a clean environment — a minimal PATH (the Node.js
// under test, git, the system directories), a temporary home, an empty npm user configuration and
// (default) an empty npm cache, so dependencies come from the registry as for a new user — it:
//
//  1. installs the tarball with npm, globally (--prefix) and/or into an empty project;
//  2. checks that the installed package is byte-for-byte the tarball's content;
//  3. runs the installation diagnostics (lib/install-check.mjs) with the Node.js under test;
//  4. runs the CLI by script path (`node <package>/dist/cli/main.js help`, the documented form) and
//     through npm's bin shim, and checks that each shim points into the installed package;
//  5. runs `doctor --json` against a temporary data home, proving the installed CLI works and
//     touches nothing of the user's;
//  6. speaks MCP to the installed server, as a host does: by script path with --diagnostics (and a
//     diag_echo call) and through its bin shim without (diag_echo must then be absent); the
//     released tool set must be served, stdout must carry only JSON-RPC, and closing stdin must end
//     the server with exit code 0;
//  7. compares the resolved dependency versions with the development lockfile (a drift is a
//     warning: an installation resolves the declared ranges afresh);
//  8. the gate without a custodian (Phase 6, contract §3.5 Layer A): on the installed package a manual
//     review run is created for a scratch repository, while a protected loop (`start_review_loop`) and
//     the custodian's grants (`loop grants`) are refused fail-closed, never served from user-writable
//     state; on a machine where a custodian answers, the refusal is reported as not applicable;
//  9. fault injection (default; --no-faults skips it): copies of the global installation are
//     damaged one way each, and the diagnostics must name each fault.
//
// --node runs the INSTALLED package with another Node.js (npm itself runs under this one). The work
// directory is removed after a passing run unless --keep; a failing run keeps it. Exit status: 0
// every check passed and every fault was detected, 1 otherwise, 2 a precondition is missing.

import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { release, tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { checkInstall, nodeVersionOf, scanImports } from "./lib/install-check.mjs";
import { handshake } from "./lib/mcp-stdio.mjs";
import { formatChecks, verdict } from "./lib/format.mjs";
import { packageFiles } from "./lib/tar-lite.mjs";
import { npmCli, run, which } from "./lib/tools.mjs";

export const SMOKE_SCHEMA = "codeparley.install-smoke.v1";
const HERE = dirname(fileURLToPath(import.meta.url));
const WIN = process.platform === "win32";
/** The public entry points (README: Installation, Host setup). */
const CLI_BIN = "code-parley";
const MCP_BIN = "code-parley-mcp";
/** The MCP tools of the released v0.3.0 surface; later additions are recorded, not required. */
const RELEASED_TOOLS = ["create_review_run", "run_checks", "review_with_codex", "get_review_status", "get_review_history", "stop_review_loop", "respond_to_review"];
const GIT_VERSION_PREFIX = /^git version /;
const CMD_SHIM_SCRIPT = /\x22%dp0%\\([^\x22]+)\x22/g;
const NPM_NOTICE = /^npm (warn|WARN|error|ERR)/;
const TEMPLATE_SUFFIX = /\.md$/;

const check = (id, status, summary, details = [], hint = null) => ({ id, status, summary, details, ...(hint ? { hint } : {}) });

function parse(argv) {
  const o = { tarball: null, node: process.execPath, npmCli: null, mode: "both", work: tmpdir(), keep: false, sharedCache: false, faults: true, report: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => {
      const x = argv[++i];
      if (x === undefined) throw new Error(`${a} requires a value`);
      return x;
    };
    if (a === "--tarball") o.tarball = resolve(v());
    else if (a === "--node") o.node = resolve(v());
    else if (a === "--npm-cli") o.npmCli = resolve(v());
    else if (a === "--mode") o.mode = v();
    else if (a === "--work") o.work = resolve(v());
    else if (a === "--report") o.report = resolve(v());
    else if (a === "--keep") o.keep = true;
    else if (a === "--shared-cache") o.sharedCache = true;
    else if (a === "--no-faults") o.faults = false;
    else if (a === "--json") o.json = true;
    else throw new Error(`unknown option ${a}`);
  }
  if (!["global", "local", "both"].includes(o.mode)) throw new Error("--mode is global, local or both");
  return o;
}

class Precondition extends Error {}

/** What the run needs, verified before anything is installed. */
async function preflight(o) {
  const nodeVersion = nodeVersionOf(o.node);
  if (!nodeVersion) throw new Precondition(`the Node.js under test does not run: ${o.node}`);
  let npm;
  try {
    npm = npmCli(process.execPath, o.npmCli);
  } catch (e) {
    throw new Precondition(e.message);
  }
  const git = which("git");
  if (!git) throw new Precondition("git is not on PATH: CodeParley requires git (README: Platform and requirements)");
  let tarball = o.tarball;
  let packReport = null;
  if (!tarball) {
    const { pack } = await import("./pack.mjs");
    const r = pack({ out: join(HERE, "..", "..", ".tmp-package"), requireClean: false, reproducible: false, keepStage: false, npmCli: o.npmCli });
    if (!r.ok) throw new Precondition(`the package does not satisfy the content policy; run scripts/package/pack.mjs for the details (${r.tarball.file})`);
    tarball = r.tarball.file;
  }
  if (!existsSync(tarball)) throw new Precondition(`no such tarball: ${tarball}`);
  const reportFile = tarball.replace(/\.tgz$/, ".pack.json");
  if (existsSync(reportFile)) packReport = JSON.parse(readFileSync(reportFile, "utf8"));
  const bytes = readFileSync(tarball);
  const files = packageFiles(bytes, { data: true });
  const pkg = JSON.parse(files.get("package.json")?.data.toString("utf8") ?? "{}");
  const npmVersion = run(process.execPath, [npm, "--version"]).stdout.trim();
  const gitVersion = run(git, ["--version"]).stdout.trim();
  return { nodePath: o.node, nodeVersion, npm, npmVersion, git, gitVersion, tarball, sha256: createHash("sha256").update(bytes).digest("hex"), files, pkg, packReport };
}

/** A clean environment: nothing of the user's npm configuration, home, data or Codex. */
function cleanEnv(work, pre, cache) {
  const home = join(work, "home");
  const tmp = join(work, "tmp");
  for (const d of [home, tmp]) mkdirSync(d, { recursive: true });
  const npmrc = join(work, "npmrc");
  writeFileSync(npmrc, "");
  const npmVars = { npm_config_userconfig: npmrc, npm_config_cache: cache.dir, npm_config_update_notifier: "false", npm_config_fund: "false", npm_config_audit: "false", ...(cache.shared ? { npm_config_prefer_offline: "true" } : {}) };
  const paths = [dirname(pre.nodePath), dirname(process.execPath), dirname(pre.git)];
  if (WIN) {
    const root = process.env.SystemRoot ?? "C:\\Windows";
    const appData = join(home, "AppData", "Roaming");
    const localAppData = join(home, "AppData", "Local");
    for (const d of [appData, localAppData]) mkdirSync(d, { recursive: true });
    const sys = [join(root, "System32"), root, join(root, "System32", "Wbem"), join(root, "System32", "WindowsPowerShell", "v1.0")];
    return { SystemRoot: root, windir: root, SystemDrive: process.env.SystemDrive ?? "C:", ComSpec: join(root, "System32", "cmd.exe"), PATHEXT: ".COM;.EXE;.BAT;.CMD", OS: "Windows_NT", PROCESSOR_ARCHITECTURE: process.env.PROCESSOR_ARCHITECTURE ?? "AMD64", NUMBER_OF_PROCESSORS: process.env.NUMBER_OF_PROCESSORS ?? "2", TEMP: tmp, TMP: tmp, USERPROFILE: home, APPDATA: appData, LOCALAPPDATA: localAppData, PATH: [...new Set([...paths, ...sys])].join(";"), ...npmVars };
  }
  return { HOME: home, TMPDIR: tmp, LANG: "C.UTF-8", XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), XDG_DATA_HOME: join(home, ".local", "share"), XDG_CACHE_HOME: join(home, ".cache"), PATH: [...new Set([...paths, "/usr/local/bin", "/usr/bin", "/bin"])].join(":"), ...npmVars };
}

function npmWarnings(text) {
  return text.split(/\r?\n/).filter((l) => NPM_NOTICE.test(l.trim())).slice(0, 30);
}

function install(mode, ctx) {
  const name = ctx.pre.pkg.name;
  const npmArgs = ["--ignore-scripts", "--no-audit", "--no-fund", "--loglevel", "warn"];
  const started = Date.now();
  let r;
  let root;
  let pkgDir;
  let binDir;
  if (mode === "global") {
    root = join(ctx.work, "global");
    r = run(process.execPath, [ctx.pre.npm, "install", "--global", "--prefix", root, ctx.pre.tarball, ...npmArgs], { env: ctx.env, cwd: ctx.work });
    pkgDir = WIN ? join(root, "node_modules", name) : join(root, "lib", "node_modules", name);
    binDir = WIN ? root : join(root, "bin");
  } else {
    root = join(ctx.work, "project");
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, "package.json"), `${JSON.stringify({ name: "codeparley-smoke-project", version: "0.0.0", private: true }, null, 2)}\n`);
    r = run(process.execPath, [ctx.pre.npm, "install", ctx.pre.tarball, ...npmArgs], { env: ctx.env, cwd: root });
    pkgDir = join(root, "node_modules", name);
    binDir = join(root, "node_modules", ".bin");
  }
  const warnings = npmWarnings(`${r.stdout}\n${r.stderr}`);
  const ok = r.status === 0 && existsSync(join(pkgDir, "package.json"));
  const summary = ok ? `npm installed the tarball (${mode}) in ${Date.now() - started} ms` : `npm install (${mode}) failed with exit ${r.status ?? r.error}`;
  const details = ok ? warnings : [...warnings, ...(r.stderr || r.stdout).trim().split("\n").slice(-15)];
  return { mode, root, pkgDir, binDir, ok, check: check("install", ok ? (warnings.length ? "warn" : "pass") : "fail", summary, details, ok ? null : "see the npm output above; a network failure with an empty cache can be retried with --shared-cache") };
}

function walk(root, rel, out) {
  for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) {
      if (p !== "node_modules") walk(root, p, out);
    } else out.push(p);
  }
  return out;
}

const sha = (b) => createHash("sha256").update(b).digest("hex");

function checkInstalledFiles(inst, files) {
  const installed = new Set(walk(inst.pkgDir, "", []));
  const extra = [...installed].filter((p) => !files.has(p)).sort();
  const missing = [...files.keys()].filter((p) => !installed.has(p)).sort();
  const changed = [...files.values()].filter((f) => installed.has(f.path) && sha(readFileSync(join(inst.pkgDir, ...f.path.split("/")))) !== sha(f.data)).map((f) => f.path);
  const details = [...missing.map((p) => `missing: ${p}`), ...extra.map((p) => `not in the tarball: ${p}`), ...changed.map((p) => `content differs from the tarball: ${p}`)];
  if (details.length === 0) return check("installed-files", "pass", `the installed package is exactly the tarball's ${files.size} files (sha256 each)`);
  return check("installed-files", "fail", "the installed package differs from the tarball", details.slice(0, 40));
}

/** How to run a bin shim: directly on Linux, through cmd.exe on Windows. */
function shimCommand(shim, args, env) {
  if (!WIN) return { cmd: shim, args, verbatim: false };
  const q = (s) => `"${s}"`;
  return { cmd: env.ComSpec, args: ["/d", "/s", "/c", `"${[q(shim), ...args.map(q)].join(" ")}"`], verbatim: true };
}

/** The script a bin shim runs, resolved: Windows parses npm's .cmd shim, Linux follows the link. */
function shimTarget(inst, name) {
  const shim = join(inst.binDir, WIN ? `${name}.cmd` : name);
  if (!existsSync(shim)) return { shim, target: null, why: "the shim does not exist" };
  if (!WIN) return { shim, target: realpathSync(shim) };
  const m = [...readFileSync(shim, "utf8").matchAll(CMD_SHIM_SCRIPT)].map((x) => x[1]).filter((p) => !p.endsWith("node.exe"));
  return m.length ? { shim, target: resolve(inst.binDir, m.at(-1)) } : { shim, target: null, why: "no script path found in the .cmd shim" };
}

function checkShims(inst, ctx) {
  const problems = [];
  for (const name of [CLI_BIN, MCP_BIN]) {
    const declared = ctx.pre.pkg.bin?.[name];
    if (!declared) {
      problems.push(`${name}: not declared in package.json bin`);
      continue;
    }
    const t = shimTarget(inst, name);
    const want = resolve(inst.pkgDir, declared);
    if (!t.target) problems.push(`${name}: ${t.why} (${t.shim})`);
    else if (realpathSync(t.target) !== realpathSync(want)) problems.push(`${name}: the shim runs ${t.target}, not the installed ${want}`);
    else if (!WIN && (statSync(t.target).mode & 0o111) === 0) problems.push(`${name}: ${t.target} is not executable`);
  }
  if (problems.length) return check("shim-targets", "fail", "a bin shim does not run the installed entry point", problems);
  return check("shim-targets", "pass", `${CLI_BIN} and ${MCP_BIN} shims run the installed package's entry points`);
}

function usageCheck(id, r, how) {
  const ok = r.status === 0 && r.stdout.includes("usage: code-parley");
  if (ok) return check(id, "pass", `${how}: help printed the usage, exit 0`);
  return check(id, "fail", `${how}: exit ${r.status ?? r.error}`, [(r.stderr || r.stdout).trim().split("\n").slice(0, 12).join("\n")]);
}

function checkCli(inst, ctx) {
  const cli = join(inst.pkgDir, "dist", "cli", "main.js");
  const byScript = usageCheck("cli-script", run(ctx.pre.nodePath, [cli, "help"], { env: ctx.env, cwd: ctx.work, timeoutMs: 120_000 }), "node <package>/dist/cli/main.js");
  const s = shimCommand(join(inst.binDir, WIN ? `${CLI_BIN}.cmd` : CLI_BIN), ["help"], ctx.env);
  const byShim = usageCheck("cli-shim", run(s.cmd, s.args, { env: ctx.env, cwd: ctx.work, verbatim: s.verbatim, timeoutMs: 120_000 }), `${CLI_BIN} (bin shim)`);
  return [byScript, byShim];
}

function doctorProblems(d, ctx) {
  const problems = [];
  if (d.tool_version !== ctx.pre.pkg.version) problems.push(`tool_version ${d.tool_version} ≠ package version ${ctx.pre.pkg.version}`);
  if (d.node?.version !== `v${ctx.pre.nodeVersion}`) problems.push(`doctor ran under ${d.node?.version}, not the Node.js under test v${ctx.pre.nodeVersion}`);
  if (resolve(d.data_home?.path ?? "") !== resolve(ctx.dataHome)) problems.push(`data home ${d.data_home?.path} is not the isolated ${ctx.dataHome}`);
  if (!d.git?.version) problems.push(`CodeParley found no git in the clean environment: ${d.git?.error ?? "unknown"}`);
  if (!(d.allowed_roots?.effective?.length > 0)) problems.push("the --allowed-root was not taken");
  return problems;
}

function checkDoctor(inst, ctx) {
  const cli = join(inst.pkgDir, "dist", "cli", "main.js");
  const r = run(ctx.pre.nodePath, [cli, "doctor", "--json", "--home", ctx.dataHome, "--allowed-root", ctx.allowed], { env: ctx.env, cwd: ctx.work, timeoutMs: 180_000 });
  let d;
  try {
    d = JSON.parse(r.stdout);
  } catch {
    return check("doctor", "fail", `doctor --json printed no report (exit ${r.status ?? r.error})`, [(r.stderr || r.stdout).trim().split("\n").slice(0, 12).join("\n")]);
  }
  const problems = doctorProblems(d, ctx);
  if (problems.length) return check("doctor", "fail", "doctor ran but its report is wrong", problems);
  const env = (d.problems ?? []).map((p) => `environment (expected in a clean environment): ${p}`);
  const git = d.git.version.replace(GIT_VERSION_PREFIX, "");
  return check("doctor", "pass", `doctor ran (exit ${r.status}): ${d.tool_version}, node ${d.node.version}, git ${git}, data home isolated, codex ${d.codex?.version ?? "not found"}`, env);
}

function mcpProblems(h, ctx, diagnostics) {
  const problems = [];
  if (h.serverInfo?.name !== "code-parley") problems.push(`serverInfo.name is ${JSON.stringify(h.serverInfo?.name)}`);
  if (h.serverInfo?.version !== ctx.pre.pkg.version) problems.push(`serverInfo.version ${h.serverInfo?.version} ≠ package version ${ctx.pre.pkg.version}`);
  const absent = RELEASED_TOOLS.filter((t) => !h.tools.includes(t));
  if (absent.length) problems.push(`released tools not served: ${absent.join(", ")}`);
  if (diagnostics !== h.tools.includes("diag_echo")) problems.push(`diag_echo is ${diagnostics ? "missing with" : "served without"} --diagnostics`);
  if (diagnostics && (h.call?.error || h.call?.result?.isError)) problems.push(`diag_echo failed: ${JSON.stringify(h.call.error ?? h.call.result).slice(0, 400)}`);
  if (h.impure.length) problems.push(`stdout carried non-JSON-RPC output: ${h.impure.slice(0, 3).join(" | ")}`);
  if (h.exit.timedOut) problems.push("the server did not exit after stdin closed");
  else if (h.exit.code !== 0) problems.push(`the server exited ${h.exit.code ?? h.exit.signal} after stdin closed`);
  return problems;
}

async function mcpCheck(id, how, spawnOpts, ctx, diagnostics) {
  try {
    const h = await handshake(spawnOpts, { callTool: diagnostics ? "diag_echo" : null });
    const problems = mcpProblems(h, ctx, diagnostics);
    if (problems.length) return check(id, "fail", `${how}: the MCP server misbehaved`, [...problems, ...h.stderr.trim().split("\n").slice(-5)]);
    const extra = h.tools.filter((t) => !RELEASED_TOOLS.includes(t) && t !== "diag_echo");
    return check(id, "pass", `${how}: initialize (${h.protocolVersion}) → ${h.serverInfo.name} ${h.serverInfo.version}; ${h.tools.length} tools${diagnostics ? ", diag_echo answered" : ", no diag_echo"}; stdout pure; exit 0 on stdin close`, extra.length ? [`tools beyond the released set: ${extra.join(", ")}`] : []);
  } catch (e) {
    return check(id, "fail", `${how}: ${e.message}`, String(e.stderr ?? "").trim().split("\n").slice(-12));
  }
}

async function checkMcp(inst, ctx) {
  const server = join(inst.pkgDir, "dist", "server", "main.js");
  const args = ["--home", ctx.dataHome, "--allowed-root", ctx.allowed];
  const byScript = await mcpCheck("mcp-script", "node <package>/dist/server/main.js --diagnostics", { command: ctx.pre.nodePath, args: [server, ...args, "--diagnostics"], env: ctx.env, cwd: ctx.work }, ctx, true);
  const s = shimCommand(join(inst.binDir, WIN ? `${MCP_BIN}.cmd` : MCP_BIN), args, ctx.env);
  const byShim = await mcpCheck("mcp-shim", `${MCP_BIN} (bin shim)`, { command: s.cmd, args: s.args, verbatim: s.verbatim, env: ctx.env, cwd: ctx.work }, ctx, false);
  return [byScript, byShim];
}

/** A refusal without a custodian: the fail-closed codes, and the CLI's statement that nothing falls back. */
const GATE_CODES = ["CUSTODIAN_UNAVAILABLE", "PROTECTED_MODE_UNAVAILABLE", "PLATFORM_UNSUPPORTED"];
const NO_FALLBACK = /no grants\.json fallback/i;

/** A scratch repository with one committed file and one uncommitted change, for a manual review run. */
function gateRepo(inst, ctx) {
  const repo = join(ctx.allowed, `gate-${inst.mode}`);
  mkdirSync(repo, { recursive: true });
  const git = (args) => run(ctx.pre.git, ["-c", "user.name=CodeParley smoke", "-c", "user.email=smoke@example.invalid", "-c", "commit.gpgsign=false", ...args], { env: ctx.env, cwd: repo, timeoutMs: 60_000 });
  writeFileSync(join(repo, "a.txt"), "one\n");
  for (const args of [["init", "-q"], ["add", "a.txt"], ["commit", "-q", "-m", "baseline"]]) {
    const r = git(args);
    if (r.status !== 0) return { repo, error: `git ${args[0]} exited ${r.status}: ${(r.stderr || r.stdout).trim().slice(0, 400)}` };
  }
  writeFileSync(join(repo, "a.txt"), "one\ntwo\n");
  return { repo, error: null };
}

/** The error of an MCP tool-call answer, or null when it succeeded. */
function toolError(answer) {
  if (answer?.error) return { code: "JSONRPC", message: JSON.stringify(answer.error).slice(0, 400) };
  if (answer?.result?.isError) return answer.result.structuredContent?.error ?? { code: "UNKNOWN", message: JSON.stringify(answer.result).slice(0, 400) };
  return null;
}

function grantsGate(inst, ctx) {
  const cli = join(inst.pkgDir, "dist", "cli", "main.js");
  const g = run(ctx.pre.nodePath, [cli, "loop", "grants", "--json", "--home", ctx.dataHome], { env: ctx.env, cwd: ctx.work, timeoutMs: 120_000 });
  const text = `${g.stdout}${g.stderr}`.trim();
  const code = GATE_CODES.find((c) => text.includes(c));
  if (g.status === 0) return check("gate-cli-grants", "skip", "a custodian answered `loop grants` on this machine: the no-custodian refusal is not applicable here", [text.split("\n")[0].slice(0, 300)]);
  if (code && NO_FALLBACK.test(text)) return check("gate-cli-grants", "pass", `\`loop grants\` without a custodian is refused fail-closed (${code}, exit ${g.status}, no grants.json fallback)`);
  return check("gate-cli-grants", "fail", `\`loop grants\` without a custodian did not refuse fail-closed (exit ${g.status ?? g.error})`, [text.slice(0, 800)]);
}

function loopGate(loop) {
  const e = toolError(loop);
  if (!e) return check("gate-protected-loop", "skip", "start_review_loop was served: a custodian answered on this machine, so the no-custodian refusal is not applicable here");
  if (GATE_CODES.includes(e.code)) return check("gate-protected-loop", "pass", `a protected loop without a custodian is refused fail-closed (${e.code})`, [String(e.message).slice(0, 300)]);
  return check("gate-protected-loop", "fail", `start_review_loop without a custodian failed with ${e.code}, not a custodian refusal`, [String(e.message).slice(0, 600)]);
}

async function checkGate(inst, ctx) {
  const { repo, error } = gateRepo(inst, ctx);
  if (error) return [check("gate-manual-review", "fail", "the scratch repository could not be prepared", [error])];
  const out = [grantsGate(inst, ctx)];
  const server = join(inst.pkgDir, "dist", "server", "main.js");
  const session = async (call) => {
    const created = await call("create_review_run", { task_envelope: { goal: "install smoke: a manual review run without a custodian" }, repository_root: repo });
    const runId = created?.result?.structuredContent?.run_id ?? null;
    return { created, runId, loop: runId ? await call("start_review_loop", { run_id: runId }) : null };
  };
  try {
    const h = await handshake({ command: ctx.pre.nodePath, args: [server, "--home", ctx.dataHome, "--allowed-root", ctx.allowed], env: ctx.env, cwd: ctx.work, timeoutMs: 180_000 }, { session });
    const { created, runId, loop } = h.session;
    const e = toolError(created);
    if (e || !runId) {
      out.push(check("gate-manual-review", "fail", "create_review_run failed on the installed package without a custodian", [`${e?.code ?? "no run_id"}: ${e?.message ?? JSON.stringify(created?.result).slice(0, 400)}`]));
      return out;
    }
    out.push(check("gate-manual-review", "pass", `manual review works without a custodian: create_review_run → ${runId} (state ${created.result.structuredContent.state ?? "?"})`));
    out.push(loopGate(loop));
  } catch (e) {
    out.push(check("gate-manual-review", "fail", `the MCP session failed: ${e.message}`, String(e.stderr ?? "").trim().split("\n").slice(-12)));
  }
  return out;
}

/** The versions the installation resolved, against what the development lockfile pins. */
function checkDrift(inst, ctx, report) {
  const deps = report.checks.find((c) => c.id === "dependencies");
  const pinned = ctx.pre.packReport?.lockfile_production ?? null;
  const installed = {};
  for (const name of Object.keys(pinned ?? {})) {
    const p = [join(inst.pkgDir, "node_modules", name, "package.json"), join(inst.root, "node_modules", name, "package.json"), join(inst.root, "lib", "node_modules", name, "package.json")].find((f) => existsSync(f));
    installed[name] = p ? JSON.parse(readFileSync(p, "utf8")).version : null;
  }
  if (!pinned) return check("dependency-drift", "skip", "no pack report beside the tarball: nothing to compare with", deps ? [deps.summary] : []);
  const drift = Object.entries(pinned).filter(([n, v]) => installed[n] !== v).map(([n, v]) => `${n}: lockfile ${v}, installed ${installed[n] ?? "none"}`);
  if (drift.length) return check("dependency-drift", "warn", "the installation resolved other versions than the development lockfile (npm tarballs carry no lockfile)", drift);
  const pairs = Object.entries(installed).map(([n, v]) => `${n}@${v}`);
  const versions = pairs.join(", ");
  return check("dependency-drift", "pass", `installed versions equal the lockfile: ${versions}`);
}

/** A module the engine loads only later (a dynamic import or a module URL), relative to the package. */
function lazyModule(pkgDir) {
  const files = walk(pkgDir, "", []).filter((p) => p.startsWith("dist/") && p.endsWith(".js")).sort();
  const refs = [];
  for (const rel of files) {
    for (const r of scanImports(readFileSync(join(pkgDir, ...rel.split("/")), "utf8"))) {
      if ((r.kind === "url" || r.kind === "dynamic") && r.spec.startsWith(".")) refs.push({ kind: r.kind, target: relative(pkgDir, resolve(join(pkgDir, ...rel.split("/")), "..", r.spec)).split(sep).join("/") });
    }
  }
  return (refs.find((r) => r.kind === "url") ?? refs[0])?.target ?? null;
}

/** The faults the diagnostics must name: [id, the check that must fail, damage(copy, info) | null]. */
function faults(info) {
  const rm = (p) => rmSync(p, { recursive: true, force: true });
  return [
    ["missing-dependency", "dependencies", info.dep ? (c) => rm(join(c, "node_modules", info.dep)) : null],
    ["incompatible-dependency", "dependencies", info.dep ? (c) => {
      const f = join(c, "node_modules", info.dep, "package.json");
      writeFileSync(f, JSON.stringify({ ...JSON.parse(readFileSync(f, "utf8")), version: "0.0.1" }));
    } : null],
    ["missing-lazy-module", "modules", info.lazy ? (c) => rm(join(c, ...info.lazy.split("/"))) : null],
    ["missing-entrypoint", "entrypoints", (c) => rm(join(c, ...info.mcpTarget.split("/")))],
    ["missing-prompts", "prompts", (c) => rm(join(c, "prompts"))],
    // The clean-install exploit: the package's prompts/ gone, decoys that even name the right template
    // where the old upward search looked (<prefix>/lib/node_modules/prompts, <prefix>/lib/prompts).
    ["prompt-escape", "prompt-lookup", info.template ? (c) => {
      rm(join(c, "prompts"));
      const templateId = info.template.replace(TEMPLATE_SUFFIX, "");
      const decoy = `<!-- template: ${templateId} version: 999 -->\nDECOY: not the template CodeParley ships\n`;
      for (const dir of [join(c, "..", "prompts"), join(c, "..", "..", "prompts")]) {
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, info.template), decoy);
      }
    } : null],
    ["unsupported-node (simulated version 20.10.0)", "node-runtime", null, "20.10.0"],
  ];
}

function runFaults(inst, ctx) {
  const templates = [...ctx.pre.files.keys()].filter((p) => p.startsWith("prompts/")).map((p) => p.slice("prompts/".length));
  const dep = Object.keys(ctx.pre.pkg.dependencies ?? {}).find((d) => existsSync(join(inst.pkgDir, "node_modules", d))) ?? null;
  const info = { dep, lazy: lazyModule(inst.pkgDir), mcpTarget: String(ctx.pre.pkg.bin?.[MCP_BIN] ?? "dist/server/main.js").replace(/^\.\//, ""), template: templates[0] ?? null };
  const results = [];
  for (const [id, expect, damage, nodeVersion] of faults(info)) {
    if (damage === null && !nodeVersion) {
      results.push({ id, expected_check: expect, detected: null, diagnostic: "not applicable to this installation" });
      continue;
    }
    const copy = join(ctx.work, "faults", id.split(" ")[0], "lib", "node_modules", ctx.pre.pkg.name);
    cpSync(inst.pkgDir, copy, { recursive: true });
    if (damage) damage(copy);
    const r = checkInstall(copy, { nodePath: ctx.pre.nodePath, ...(nodeVersion ? { nodeVersion } : {}), env: ctx.env, probeEnv: ctx.env, expectTemplates: templates });
    const hit = r.checks.find((c) => c.id === expect);
    // The product must refuse (fail-closed), not merely be diagnosed: an escape is a regression.
    const escaped = id === "prompt-escape" && hit?.summary.includes("fail-open") === true;
    results.push({ id, expected_check: expect, detected: hit?.status === "fail", regression: escaped ? "the engine read a decoy template from outside the installation (fail-open prompt lookup)" : null, failed_checks: r.checks.filter((c) => c.status === "fail").map((c) => c.id), diagnostic: hit ? [hit.summary, ...hit.details.slice(0, 3)].join(" | ") : "check not run" });
  }
  return results;
}

async function smokeOne(mode, ctx) {
  const inst = install(mode, ctx);
  const out = { mode, package_dir: inst.pkgDir, bin_dir: inst.binDir, checks: [inst.check] };
  if (!inst.ok) return { out, inst };
  out.checks.push(checkInstalledFiles(inst, ctx.pre.files));
  const templates = [...ctx.pre.files.keys()].filter((p) => p.startsWith("prompts/")).map((p) => p.slice("prompts/".length));
  const diag = checkInstall(inst.pkgDir, { nodePath: ctx.pre.nodePath, env: ctx.env, probeEnv: ctx.env, expectTemplates: templates });
  out.checks.push(...diag.checks.map((c) => ({ ...c, id: `check:${c.id}` })));
  out.checks.push(checkShims(inst, ctx), ...checkCli(inst, ctx), checkDoctor(inst, ctx), ...(await checkMcp(inst, ctx)), ...(await checkGate(inst, ctx)), checkDrift(inst, ctx, diag));
  return { out, inst };
}

export async function smoke(o) {
  const pre = await preflight(o);
  const work = join(o.work, `cps-${randomBytes(4).toString("hex")}`);
  mkdirSync(work, { recursive: true });
  const cache = o.sharedCache ? { dir: run(process.execPath, [pre.npm, "config", "get", "cache"]).stdout.trim(), shared: true } : { dir: join(work, "npm-cache"), shared: false };
  const ctx = { pre, work, env: cleanEnv(work, pre, cache), dataHome: join(work, "data"), allowed: join(work, "allowed") };
  mkdirSync(ctx.allowed, { recursive: true });
  const modes = o.mode === "both" ? ["global", "local"] : [o.mode];
  const installs = [];
  let faultResults = [];
  for (const mode of modes) {
    const { out, inst } = await smokeOne(mode, ctx);
    installs.push(out);
    if (o.faults && mode === "global" && inst.ok) faultResults = runFaults(inst, ctx);
  }
  const ok = installs.every((i) => i.checks.every((c) => c.status !== "fail")) && faultResults.every((f) => f.detected !== false && !f.regression);
  const report = {
    schema: SMOKE_SCHEMA,
    ok,
    tarball: { file: pre.tarball, sha256: pre.sha256, files: pre.files.size, package: `${pre.pkg.name}@${pre.pkg.version}`, pack_report: pre.packReport ? { commit: pre.packReport.source?.commit, dirty: pre.packReport.source?.dirty, built_on: pre.packReport.tools?.platform } : null },
    environment: { platform: `${process.platform}-${process.arch}`, os_release: release(), node_under_test: { path: pre.nodePath, version: pre.nodeVersion }, harness_node: process.version, npm: { cli: pre.npm, version: pre.npmVersion }, git: { path: pre.git, version: pre.gitVersion }, npm_cache: cache.shared ? "shared (user cache, prefer-offline)" : "fresh (empty)" },
    installs,
    faults: faultResults,
    work_dir: work,
    kept: o.keep || !ok,
    created_at: new Date().toISOString(),
  };
  writeFileSync(join(work, "smoke-report.json"), `${JSON.stringify(report, null, 2)}\n`);
  if (o.report) writeFileSync(o.report, `${JSON.stringify(report, null, 2)}\n`);
  if (!report.kept) rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  return report;
}

function summary(r) {
  const e = r.environment;
  const lines = [`CodeParley install smoke test: ${r.tarball.package} (${r.tarball.files} files, sha256 ${r.tarball.sha256.slice(0, 16)}…)`, `  ${e.platform} ${e.os_release}; Node.js under test ${e.node_under_test.version} (${e.node_under_test.path}); npm ${e.npm.version}; ${e.git.version}; npm cache ${e.npm_cache}`];
  for (const i of r.installs) {
    lines.push(`[${i.mode}] ${i.package_dir}`, ...formatChecks(i.checks, { indent: "  " }), `  ${verdict(i.checks)}`);
  }
  if (r.faults.length) {
    lines.push("[faults] damaged copies of the global installation; the diagnostics must name each fault");
    for (const f of r.faults) {
      const label = f.detected === null ? "SKIP" : f.detected && !f.regression ? "PASS" : "FAIL";
      const regression = f.regression ? `REGRESSION: ${f.regression} | ` : "";
      lines.push(`  ${label}  ${f.id} → ${f.expected_check}: ${regression}${f.diagnostic}`);
    }
  }
  lines.push(r.ok ? "smoke: OK" : `smoke: FAILED (work directory kept: ${r.work_dir})`);
  if (r.ok && r.kept) lines.push(`work directory kept: ${r.work_dir}`);
  return lines;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let o;
  try {
    o = parse(process.argv.slice(2));
    const r = await smoke(o);
    process.stdout.write(o.json ? `${JSON.stringify(r, null, 2)}\n` : `${summary(r).join("\n")}\n`);
    process.exitCode = r.ok ? 0 : 1;
  } catch (e) {
    process.stderr.write(`smoke: ${e instanceof Precondition ? "precondition: " : ""}${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  }
}
