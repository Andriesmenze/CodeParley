#!/usr/bin/env node
// Phase 6 Increment 1 (contract §4.1, T1 local validation): run one job of .github/workflows/ci.yml on this machine,
// step by step, with the commands the workflow itself contains: no second copy of the CI steps to drift from it. Each
// `run:` step runs in the shell GitHub uses (Windows: pwsh with $ErrorActionPreference stop and the last exit code;
// Linux, and `shell: bash`: bash -eo pipefail); an `if: runner.os == '…'` is honoured; a step that fails stops the job.
//
//   node scripts/ci/run-workflow-local.mjs --job identity|verify|test --log <dir> [--expect <sha>] [--node <node executable>]
//        [--npm-cli <npm-cli.js>] [--bash <bash>] [--set NAME=value]... [--substitute "<step name>=<reason>"]...
//
// What is not run, and is recorded as such in <dir>/summary.json: an action step (`uses:`; the local Node.js, .NET SDK
// and checkout stand in for setup-node, setup-dotnet and checkout), the step that writes the machine's global git
// configuration, and a step named by --substitute (its artifact prepared another way, with the reason). The checkout
// must be clean and, with --expect, at that commit; it is checked again after the job. --node runs the job under
// another Node.js: on Windows it gets a PATH directory of its own with node.exe and npm/npx shims (--npm-cli, default
// the system npm), on Linux its own directory (which carries npm). --set gives a step environment value the workflow
// computes with an expression (the identity job's EXPECTED_SHA and MERGE; the verify and test jobs' VERIFIED_SHA, and
// the test job's CP_TEST_SHARD, the matrix's shard: `--set CP_TEST_SHARD=` runs the whole suite, `=2/4` one shard;
// and its CP_TEST_GIT: `auto` on Windows (test/test-git.ts finds Git for Windows' own git.exe), empty on Linux).
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "..");
const WIN = process.platform === "win32";
const GLOBAL_CONFIG_STEP = "Keep the repository's line endings";
/** GitHub's wrapper for a pwsh step: stop on errors, and exit with the last native command's code. */
const PS_PROLOGUE = "$ErrorActionPreference = 'stop'";
const PS_EPILOGUE = "if ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }";
/** The start of a workflow expression, which only GitHub evaluates. */
const EXPRESSION = "$" + "{{";

function parseArgs(argv) {
  const o = { job: null, log: null, expect: null, node: null, npmCli: null, bash: WIN ? "C:/Program Files/Git/bin/bash.exe" : "bash", set: {}, substitute: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => argv[++i] ?? (() => { throw new Error(`${a} requires a value`); })();
    if (a === "--job") o.job = v();
    else if (a === "--log") o.log = resolve(v());
    else if (a === "--expect") o.expect = v().toLowerCase();
    else if (a === "--node") o.node = resolve(v());
    else if (a === "--npm-cli") o.npmCli = resolve(v());
    else if (a === "--bash") o.bash = v();
    else if (a === "--set" || a === "--substitute") {
      const s = v();
      const eq = s.indexOf("=");
      if (eq < 1) throw new Error(`${a} takes NAME=value`);
      o[a.slice(2)][s.slice(0, eq)] = s.slice(eq + 1);
    } else throw new Error(`unknown option ${a}`);
  }
  if (!o.job || !o.log) throw new Error("usage: run-workflow-local.mjs --job <job> --log <dir> [options]");
  return o;
}

const indentOf = (l) => l.length - l.trimStart().length;
const KEY = /^[\w-]+$/;
const unquote = (v) => (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0] ? v.slice(1, -1) : v);

/** `key: value` of one workflow line, or null when it is not one. */
function keyValue(body) {
  const colon = body.indexOf(":");
  const key = colon > 0 ? body.slice(0, colon) : "";
  return KEY.test(key) ? { key, value: body.slice(colon + 1).trim() } : null;
}

/** A step's key at indent 8 (or after its `- `): a block `run: |` takes the more-indented lines that follow. */
function stepKey(st, lines, i, body) {
  const kv = keyValue(body);
  if (!kv) throw new Error(`workflow line ${i + 1}: not a key`);
  st.sub = null;
  if (kv.key === "run" && kv.value === "|") {
    const block = [];
    while (i + 1 < lines.length && (lines[i + 1].trim() === "" || indentOf(lines[i + 1]) >= 10)) block.push(lines[++i].slice(10));
    st.step.run = block.join("\n").trimEnd();
  } else if ((kv.key === "env" || kv.key === "with") && kv.value === "") st.sub = kv.key;
  else st.step[kv.key] = unquote(kv.value);
  return i;
}

/** One line inside a job's `steps:`. Returns the index of the last line it consumed. */
function stepLine(st, lines, i, ind) {
  const body = lines[i].trim();
  if (ind === 6 && body.startsWith("- ")) {
    st.step = { env: {} };
    st.job.steps.push(st.step);
    return stepKey(st, lines, i, body.slice(2));
  }
  if (ind === 10 && st.sub) {
    const kv = keyValue(body);
    if (kv && st.sub === "env") st.step.env[kv.key] = unquote(kv.value);
    return i;
  }
  if (ind !== 8) throw new Error(`workflow line ${i + 1}: unexpected indentation`);
  return stepKey(st, lines, i, body);
}

function jobEnvLine(job, l) {
  const kv = keyValue(l.trim());
  if (kv) job.env[kv.key] = unquote(kv.value);
}

/** The jobs of this repository's workflow: their env and their steps (name, if, shell, run, env, uses). The parser
 *  knows this file's layout (two-space indents, block `run: |`), and fails on anything it cannot place. */
export function parseJobs(text) {
  const lines = text.replaceAll("\r\n", "\n").split("\n");
  const jobs = {};
  const st = { job: null, section: null, step: null, sub: null };
  const start = lines.indexOf("jobs:");
  if (start < 0) throw new Error("no jobs: in the workflow");
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() === "" || l.trimStart().startsWith("#")) continue;
    const ind = indentOf(l);
    if (ind === 0) break;
    if (ind === 2) {
      st.job = { env: {}, steps: [] };
      jobs[l.trim().split(":")[0]] = st.job;
      st.section = null;
    } else if (ind === 4) st.section = l.trim().split(":")[0];
    else if (st.section === "env" && ind === 6) jobEnvLine(st.job, l);
    else if (st.section === "steps") i = stepLine(st, lines, i, ind);
  }
  return jobs;
}

/** `if:` conditions this runner can decide: runner.os == 'Windows' | 'Linux'. Anything else is refused. */
function condition(expr, runnerOs) {
  if (expr === undefined) return true;
  const m = /^runner\.os == '(Windows|Linux)'$/.exec(expr.trim());
  if (!m) throw new Error(`cannot evaluate the condition '${expr}' locally`);
  return m[1] === runnerOs;
}

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, maxBuffer: 256 * 1024 * 1024, ...opts });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, error: r.error };
}

/** A PATH directory that makes --node the job's `node`, `npm` and `npx`. */
function nodeDir(o, work) {
  if (!o.node) return null;
  if (!WIN) return dirname(o.node);
  const dir = join(work, "node");
  mkdirSync(dir, { recursive: true });
  copyFileSync(o.node, join(dir, "node.exe"));
  const npmCli = o.npmCli ?? join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (!existsSync(npmCli)) throw new Error(`no npm-cli.js at ${npmCli} (use --npm-cli)`);
  // Laid out like a Node.js installation (npm beside node, as setup-node leaves it): tools that look for npm next to
  // the running node (scripts/package/smoke.mjs) find it. A copy, never a link: removing the work directory must not
  // reach the system's npm.
  const npm = join(dir, "node_modules", "npm");
  cpSync(dirname(dirname(npmCli)), npm, { recursive: true });
  writeFileSync(join(dir, "npm.cmd"), `@"%~dp0node.exe" "%~dp0node_modules\\npm\\bin\\npm-cli.js" %*\r\n`);
  writeFileSync(join(dir, "npx.cmd"), `@"%~dp0node.exe" "%~dp0node_modules\\npm\\bin\\npx-cli.js" %*\r\n`);
  return dir;
}

function runStep(step, o, env, work, n) {
  const shell = step.shell ?? (WIN ? "pwsh" : "bash");
  if (step.run.includes(EXPRESSION)) throw new Error(`step '${step.name}' has an expression in its command`);
  if (shell === "pwsh") {
    const file = join(work, `step-${n}.ps1`);
    writeFileSync(file, [PS_PROLOGUE, step.run, PS_EPILOGUE, ""].join("\n"));
    return sh("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", `. '${file}'`], { cwd: ROOT, env });
  }
  if (shell !== "bash") throw new Error(`step '${step.name}': unsupported shell ${shell}`);
  const file = join(work, `step-${n}.sh`);
  writeFileSync(file, `${step.run}\n`);
  return sh(o.bash, ["--noprofile", "--norc", "-eo", "pipefail", file], { cwd: ROOT, env });
}

function stepEnv(step, o, base) {
  const env = { ...base };
  for (const [k, v] of Object.entries(step.env)) {
    if (v.includes(EXPRESSION)) {
      if (!(k in o.set)) throw new Error(`step '${step.name}': ${k} is computed by the workflow; give it with --set ${k}=…`);
      env[k] = o.set[k];
    } else env[k] = v;
  }
  return env;
}

/** Why a step does not run here, or null when it runs. */
function notRun(step, name, o, runnerOs) {
  if (step.uses) return { status: "skip", note: `action ${step.uses}: the local toolchain stands in` };
  if (name === GLOBAL_CONFIG_STEP) return { status: "skip", note: `writes the machine's global git configuration; core.autocrlf here: ${sh("git", ["config", "core.autocrlf"], { cwd: ROOT }).out.trim() || "unset"}` };
  if (name in o.substitute) return { status: "substituted", note: o.substitute[name] };
  if (!condition(step.if, runnerOs)) return { status: "skip", note: `if: ${step.if}` };
  return null;
}

/** The job's environment: this process's, the job's `env:`, the runner's variables and --node's PATH directory. */
function jobEnv(o, job, work, runnerOs) {
  const runnerTemp = join(work, "runner-temp");
  mkdirSync(runnerTemp);
  // CI=true as on GitHub; the test workers capped at half the cores, as authorized for local runs only (D-38).
  const base = { ...process.env, ...job.env, CI: "true", CP_TEST_MAX_WORKERS: "50%", RUNNER_OS: runnerOs, RUNNER_TEMP: runnerTemp, GITHUB_OUTPUT: join(work, "github-output"), GITHUB_WORKSPACE: ROOT };
  const extra = nodeDir(o, work);
  if (extra) {
    const pathKey = WIN ? (Object.keys(process.env).find((k) => k.toUpperCase() === "PATH") ?? "Path") : "PATH";
    base[pathKey] = `${extra}${delimiter}${process.env[pathKey] ?? ""}`;
  }
  return base;
}

function runSteps(job, o, base, work, runnerOs, summary) {
  let n = 0;
  for (const step of job.steps) {
    n++;
    const rec = { name: step.name ?? `step ${n}`, status: null, exit: null, seconds: 0, log: null, note: null };
    summary.steps.push(rec);
    const skipped = notRun(step, rec.name, o, runnerOs);
    if (skipped) Object.assign(rec, skipped);
    else {
      const t0 = Date.now();
      const r = runStep(step, o, stepEnv(step, o, base), work, n);
      Object.assign(rec, { seconds: Math.round((Date.now() - t0) / 100) / 10, exit: r.status, status: r.status === 0 ? "pass" : "fail", log: `step-${String(n).padStart(2, "0")}.log` });
      writeFileSync(join(o.log, rec.log), r.out);
    }
    console.log(`${rec.status.toUpperCase().padEnd(11)} ${rec.name}${rec.seconds ? ` (${rec.seconds} s)` : ""}${rec.note ? `: ${rec.note}` : ""}`);
    if (rec.status === "fail") return 1;
  }
  return 0;
}

/** Why the checkout cannot be validated, or null: T1 runs on an exact, clean commit. */
function precondition(summary, o) {
  if (!summary.clean_before) return "the checkout has uncommitted changes: T1 runs on an exact, clean commit";
  if (o.expect && summary.head !== o.expect) return `HEAD ${summary.head} is not the expected commit ${o.expect}`;
  return null;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  const job = parseJobs(readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8"))[o.job];
  if (!job) throw new Error(`no job '${o.job}' in the workflow`);
  mkdirSync(o.log, { recursive: true });
  const work = mkdtempSync(join(tmpdir(), "cp-wf-"));
  const runnerOs = WIN ? "Windows" : "Linux";
  const dirty = () => sh("git", ["status", "--porcelain"], { cwd: ROOT }).out.trim();
  const summary = { job: o.job, runner_os: runnerOs, head: sh("git", ["rev-parse", "HEAD"], { cwd: ROOT }).out.trim(), expected: o.expect, clean_before: dirty() === "", clean_after: null, node: null, started_at: new Date().toISOString(), finished_at: null, steps: [], ok: false };
  let code = 1;
  const refused = precondition(summary, o);
  if (refused) console.error(refused);
  else {
    const base = jobEnv(o, job, work, runnerOs);
    summary.node = sh("node", ["--version"], { env: base }).out.trim();
    console.log(`${o.job} on ${runnerOs}, node ${summary.node}, at ${summary.head}`);
    code = runSteps(job, o, base, work, runnerOs, summary);
  }
  summary.finished_at = new Date().toISOString();
  summary.clean_after = dirty() === "";
  summary.ok = code === 0 && summary.clean_after;
  writeFileSync(join(o.log, "summary.json"), JSON.stringify(summary, null, 2));
  rmSync(work, { recursive: true, force: true });
  console.log(`${o.job} on ${runnerOs} at ${summary.head}: ${summary.ok ? "OK" : "FAILED"}${summary.clean_after ? "" : " (the checkout is no longer clean)"}`);
  process.exit(summary.ok ? 0 : 1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(`run-workflow-local: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }
}
