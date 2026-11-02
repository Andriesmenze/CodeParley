// Process and tool helpers for the packaging scripts (Phase 5): run a program without a shell, find
// npm's CLI next to a Node.js, read a checkout's identity. No dependencies.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

/** Run `cmd args` without a shell: { status, stdout, stderr, error }. */
export function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, maxBuffer: 64 * 1024 * 1024, timeout: opts.timeoutMs ?? 600_000, cwd: opts.cwd, env: opts.env, input: opts.input, windowsVerbatimArguments: opts.verbatim === true });
  return { status: r.status, signal: r.signal, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error ? r.error.message : null };
}

/** The first `name` on `PATH` (Windows: name.exe), or null. */
export function which(name, env = process.env) {
  const exts = process.platform === "win32" ? [".exe", ""] : [""];
  const pathVar = Object.keys(env).find((k) => k.toUpperCase() === "PATH");
  for (const dir of (pathVar ? env[pathVar] : "").split(process.platform === "win32" ? ";" : ":")) {
    if (!dir) continue;
    for (const ext of exts) {
      const p = join(dir, name + ext);
      if (existsSync(p) && statSync(p).isFile()) return p;
    }
  }
  return null;
}

/** The production dependency versions a lockfile pins: { name: version }. */
export function lockfileProduction(lockfile) {
  const out = {};
  for (const [key, entry] of Object.entries(lockfile.packages ?? {})) {
    // Top-level entries only: a nested copy (node_modules/a/node_modules/b) is another version of b.
    if (!key.startsWith("node_modules/") || key.indexOf("/node_modules/") !== -1 || entry.dev || entry.devOptional) continue;
    out[key.slice("node_modules/".length)] = entry.version;
  }
  return out;
}

/** Like run, but throws with the program's output when it fails. */
export function runOk(cmd, args, opts = {}) {
  const r = run(cmd, args, opts);
  if (r.status !== 0) throw new Error(`${opts.label ?? cmd} failed (exit ${r.status ?? r.signal ?? r.error}):\n${(r.stderr || r.stdout).trim().slice(-4000)}`);
  return r;
}

/**
 * npm's JavaScript entry (npm-cli.js) for `nodePath`: an explicit override, npm_execpath when it
 * names npm-cli.js, or the npm bundled beside that Node.js. Throws with a hint when none exists.
 */
export function npmCli(nodePath, override = null, env = process.env) {
  const candidates = [];
  if (override) candidates.push(override);
  if (env.npm_execpath && env.npm_execpath.endsWith("npm-cli.js")) candidates.push(env.npm_execpath);
  const bin = dirname(nodePath);
  candidates.push(join(bin, "node_modules", "npm", "bin", "npm-cli.js"), join(bin, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"));
  const found = candidates.find((c) => existsSync(c));
  if (!found) throw new Error(`npm's CLI (npm-cli.js) was not found for ${nodePath}: pass --npm-cli <path to npm-cli.js>`);
  return found;
}

export function sha256File(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/** The commit of `repo` and whether the inputs of a package build have uncommitted changes. */
export function sourceIdentity(repo, inputs) {
  const git = (...a) => runOk("git", ["-C", repo, ...a], { label: `git ${a[0]}` }).stdout.trim();
  const commit = git("rev-parse", "HEAD");
  const status = git("status", "--porcelain", "--untracked-files=all", "--", ...inputs);
  return { commit, dirty: status.length > 0, changes: status ? status.split("\n").map((l) => l.trim()).slice(0, 50) : [] };
}

/** The versions of the tools a run used, as reported by the tools themselves. */
export function toolVersions(nodePath, npmCliPath, env) {
  const v = (cmd, args) => {
    const r = run(cmd, args, { env, timeoutMs: 60_000 });
    return r.status === 0 ? r.stdout.trim().split("\n")[0] : null;
  };
  return { node: v(nodePath, ["--version"]), npm: npmCliPath ? v(nodePath, [npmCliPath, "--version"]) : null, git: v("git", ["--version"]) };
}
