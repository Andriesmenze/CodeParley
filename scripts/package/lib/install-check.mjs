// Installation diagnostics for CodeParley (Phase 5): is an installed copy complete, and can this
// Node.js run it? Dependency-free and static (it reads files, it does not load CodeParley's
// modules), so it works on exactly the installations that fail to start: a missing compiled
// module, a missing or incompatible dependency, missing prompt templates, an unsupported Node.js.
// The optional probe runs one internal lookup (the prompt template location) in a child process.
//
// It checks an npm-installed package (global or project) and a built git checkout alike. What the
// package should contain (and must not) is the packing policy's job (policy.mjs); git, Codex and
// configuration are `code-parley doctor`'s.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isBuiltin } from "node:module";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { satisfies } from "./semver-lite.mjs";

export const CHECK_SCHEMA = "codeparley.install-check.v1";

// tsc's ESM output puts each static import or re-export on one line: `import … from "x";`.
const STATIC_FROM = /^(?:import|export)\b.*\bfrom\s*([\x22\x27])([^\x22\x27\n]+)\1\s*;?\s*$/;
const SIDE_EFFECT = /^import\s*([\x22\x27])([^\x22\x27\n]+)\1\s*;?\s*$/;
const DYNAMIC = /\bimport\(\s*([\x22\x27])([^\x22\x27\n]+)\1\s*\)/g;
const URL_REF = /\bnew URL\(\s*([\x22\x27])(\.\.?\/[^\x22\x27\n]+)\1\s*,\s*import\.meta\.url\s*\)/g;
const TEMPLATE_HEADER = /^<!--\s*template:\s*[a-z0-9-]+\s+version:\s*[0-9A-Za-z.-]+\s*-->/;
const SHEBANG = "#!/usr/bin/env node";

const check = (id, status, summary, details = [], hint = null) => ({ id, status, summary, details, ...(hint ? { hint } : {}) });

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/** A dependency's manifest; a damaged one reads as an empty manifest (its version is then unknown). */
function readManifestOf(dir) {
  try {
    return readJson(join(dir, "package.json"));
  } catch {
    return {};
  }
}

function walkFiles(root, rel, out) {
  let entries;
  try {
    entries = readdirSync(join(root, rel), { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory() && e.name !== "node_modules") walkFiles(root, p, out);
    else if (e.isFile()) out.push(p);
  }
  return out;
}

/** The module references in one compiled file: [{ kind: static|dynamic|url, spec }]. */
export function scanImports(source) {
  const out = [];
  for (const raw of source.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) continue;
    if (line.startsWith("import") || line.startsWith("export")) {
      const m = STATIC_FROM.exec(line) ?? SIDE_EFFECT.exec(line);
      if (m) out.push({ kind: "static", spec: m[2] });
    }
    for (const m of line.matchAll(DYNAMIC)) out.push({ kind: "dynamic", spec: m[2] });
    for (const m of line.matchAll(URL_REF)) out.push({ kind: "url", spec: m[2] });
  }
  return out;
}

/** The package a bare specifier names, and the subpath it asks for ("." for the root). */
export function splitBare(spec) {
  const parts = spec.split("/");
  const name = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
  const rest = spec.slice(name.length);
  return { name, subpath: rest ? `.${rest}` : "." };
}

/** Node's lookup: <dir>/node_modules/<name> for each ancestor of `fromDir`. The package dir or null. */
export function findPackageDir(fromDir, name) {
  let dir = resolve(fromDir);
  for (;;) {
    if (basename(dir) !== "node_modules") {
      const candidate = join(dir, "node_modules", ...name.split("/"));
      if (existsSync(join(candidate, "package.json"))) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Where an installation's own dependencies may live: the node_modules holding the package, or its own. */
export function installBoundary(pkgDir) {
  let dir = resolve(pkgDir);
  for (;;) {
    const parent = dirname(dir);
    if (parent === dir) return join(resolve(pkgDir), "node_modules");
    if (basename(parent) === "node_modules") return parent;
    dir = parent;
  }
}

const inside = (child, parent) => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

function exportsHas(manifest, subpath) {
  const ex = manifest.exports;
  if (ex === undefined || ex === null) return true;
  if (typeof ex === "string" || Array.isArray(ex)) return subpath === ".";
  const keys = Object.keys(ex);
  if (!keys.some((k) => k.startsWith("."))) return subpath === ".";
  return keys.some((k) => k === subpath || (k.includes("*") && subpath.startsWith(k.slice(0, k.indexOf("*")))));
}

function checkManifest(ctx) {
  if (ctx.manifestError) return check("manifest", "fail", `package.json cannot be read: ${ctx.manifestError}`, [], "the installation is incomplete or damaged: reinstall the package");
  const pkg = ctx.pkg;
  const problems = [];
  if (!pkg.name || !pkg.version) problems.push("package.json has no name or version");
  if (pkg.type !== "module") problems.push(`package.json "type" is ${JSON.stringify(pkg.type)}, not "module": the compiled ES modules would not load`);
  if (!pkg.bin || Object.keys(pkg.bin).length === 0) problems.push("package.json declares no entry points (bin)");
  return problems.length ? check("manifest", "fail", "the package manifest is not usable", problems) : check("manifest", "pass", `${pkg.name} ${pkg.version}`);
}

function checkNode(ctx) {
  const range = ctx.pkg?.engines?.node;
  const version = ctx.nodeVersion;
  if (version === null) return check("node-runtime", "fail", `the Node.js executable does not run: ${ctx.nodePath}`, [], "pass the path of a working node executable");
  if (!range) return check("node-runtime", "warn", `Node.js ${version}; the package declares no engines.node range`);
  const ok = satisfies(version, range);
  if (ok === true) return check("node-runtime", "pass", `Node.js ${version} satisfies ${range}`);
  if (ok === null) return check("node-runtime", "warn", `cannot evaluate engines.node ${JSON.stringify(range)} for Node.js ${version}`);
  return check("node-runtime", "fail", `Node.js ${version} is not supported: CodeParley requires ${range}`, [`node executable: ${ctx.nodePath}`], `install a supported Node.js (${range}) and run CodeParley with it; hosts must launch that node executable`);
}

function entryProblems(ctx, name, target) {
  const file = join(ctx.pkgDir, target);
  if (!existsSync(file)) return [`${name}: ${target} is missing`];
  const st = statSync(file);
  if (!st.isFile()) return [`${name}: ${target} is not a file`];
  const out = [];
  const first = readFileSync(file, "utf8").split("\n", 1)[0].trim();
  if (first !== SHEBANG) out.push(`${name}: ${target} does not start with "${SHEBANG}"`);
  if (ctx.platform !== "win32" && ctx.npmInstalled && (st.mode & 0o111) === 0) out.push(`${name}: ${target} is not executable (mode ${(st.mode & 0o777).toString(8)})`);
  return out;
}

function checkEntrypoints(ctx) {
  if (!ctx.pkg?.bin) return check("entrypoints", "skip", "no entry points declared");
  const problems = [];
  for (const [name, target] of Object.entries(ctx.pkg.bin)) problems.push(...entryProblems(ctx, name, target));
  const names = Object.keys(ctx.pkg.bin).join(", ");
  if (problems.length === 0) return check("entrypoints", "pass", `entry points present: ${names}`);
  return check("entrypoints", "fail", "an entry point is missing or unusable", problems, ctx.isCheckout ? "a git checkout must be built: run `npm ci` and `npm run build`" : "the installation is incomplete: reinstall the package");
}

/** Every reference in every shipped .js file: the missing relative targets and the bare imports. */
function scanPackage(ctx) {
  const files = walkFiles(ctx.pkgDir, "dist", []).filter((p) => p.endsWith(".js"));
  const missing = [];
  const bare = new Map();
  for (const rel of files) {
    const abs = join(ctx.pkgDir, ...rel.split("/"));
    for (const ref of scanImports(readFileSync(abs, "utf8"))) {
      if (ref.spec.startsWith("node:") || isBuiltin(ref.spec)) continue;
      if (ref.spec.startsWith("./") || ref.spec.startsWith("../")) {
        const target = resolve(dirname(abs), ref.spec);
        if (!existsSync(target)) missing.push(`${rel} → ${ref.spec} (${ref.kind}): ${relative(ctx.pkgDir, target).split(sep).join("/")} is missing`);
        continue;
      }
      if (!bare.has(ref.spec)) bare.set(ref.spec, []);
      bare.get(ref.spec).push(rel);
    }
  }
  return { files, missing, bare };
}

function checkModules(ctx, scan) {
  if (scan.files.length === 0) return check("modules", "fail", "dist/ holds no compiled modules", [], ctx.isCheckout ? "run `npm run build`" : "the installation is incomplete: reinstall the package");
  if (scan.missing.length === 0) return check("modules", "pass", `${scan.files.length} compiled modules; every relative import, dynamic import and module URL resolves`);
  return check("modules", "fail", `${scan.missing.length} module reference(s) point at missing files`, scan.missing, ctx.isCheckout ? "rebuild: `npm run build`" : "the installation is incomplete: reinstall the package");
}

function declaredRange(pkg, name) {
  return pkg.dependencies?.[name] ?? pkg.optionalDependencies?.[name] ?? pkg.peerDependencies?.[name] ?? null;
}

/** The dependency closure from the package: one record per (requester, dependency). */
function dependencyClosure(ctx) {
  const records = [];
  const seen = new Set();
  const queue = [{ dir: ctx.pkgDir, pkg: ctx.pkg, label: ctx.pkg.name }];
  while (queue.length) {
    const { dir, pkg, label } = queue.shift();
    for (const [name, range] of Object.entries({ ...(pkg.dependencies ?? {}), ...(pkg.optionalDependencies ?? {}) })) {
      const found = findPackageDir(dir, name);
      const manifest = found ? readManifestOf(found) : null;
      records.push({ requester: label, name, range, dir: found, version: manifest?.version ?? null, optional: !!pkg.optionalDependencies?.[name] });
      if (found && !seen.has(found)) {
        seen.add(found);
        queue.push({ dir: found, pkg: manifest, label: `${name}@${manifest.version ?? "?"}` });
      }
    }
  }
  return records;
}

function closureProblems(ctx, closure) {
  const fails = [];
  const warns = [];
  for (const r of closure) {
    if (!r.dir) {
      (r.optional ? warns : fails).push(`${r.requester} needs ${r.name}@${r.range}: not installed`);
      continue;
    }
    const ok = r.version === null ? false : satisfies(r.version, r.range);
    if (ok === false) fails.push(`${r.requester} needs ${r.name}@${r.range}: ${r.version ?? "an unreadable package"} is installed (${r.dir})`);
    if (ok === null) warns.push(`${r.requester} needs ${r.name}@${r.range}: cannot evaluate the range for ${r.version}`);
    if (!inside(r.dir, ctx.boundary) && !inside(r.dir, ctx.pkgDir)) warns.push(`${r.name} resolves outside the installation, from ${r.dir}: an unrelated node_modules is masking a missing dependency`);
  }
  return { fails, warns };
}

function importProblems(ctx, scan) {
  const fails = [];
  for (const [spec, importers] of scan.bare) {
    const { name, subpath } = splitBare(spec);
    const others = importers.length - 1;
    const more = others > 0 ? ` (+${others} more)` : "";
    const where = `${importers[0]}${more}`;
    if (!declaredRange(ctx.pkg, name)) fails.push(`${where} imports "${spec}", which package.json does not declare as a dependency`);
    const dir = findPackageDir(join(ctx.pkgDir, "dist"), name);
    if (dir && !exportsHas(readManifestOf(dir), subpath)) fails.push(`${where} imports "${spec}": ${name} does not export ${subpath}`);
  }
  return fails;
}

function checkDependencies(ctx, scan, closure) {
  const { fails, warns } = closureProblems(ctx, closure);
  fails.push(...importProblems(ctx, scan));
  const versions = closure.filter((r) => r.requester === ctx.pkg.name).map((r) => `${r.name}@${r.version ?? "MISSING"} (wants ${r.range})`);
  const hint = ctx.isCheckout ? "install the dependencies: `npm ci`" : "the installation is incomplete or damaged: reinstall the package";
  if (fails.length) return check("dependencies", "fail", `${fails.length} dependency problem(s)`, [...fails, ...warns], hint);
  if (warns.length) return check("dependencies", "warn", `dependencies resolve, with ${warns.length} warning(s): ${versions.join(", ")}`, warns);
  return check("dependencies", "pass", `${closure.length} dependency link(s) resolve inside the installation: ${versions.join(", ")}`);
}

function checkPrompts(ctx) {
  const dir = join(ctx.pkgDir, "prompts");
  const present = existsSync(dir) ? readdirSync(dir).filter((n) => n.endsWith(".md")).sort() : [];
  const absent = (ctx.expectTemplates ?? []).filter((n) => !present.includes(n));
  // The probe looks up every template, including expected ones that are missing: where would the engine read them from?
  ctx.templates = [...new Set([...present, ...absent])].sort();
  const hint = "reviews cannot render the Codex prompt (versions before the prompt-path fix even read a template from outside the package instead): reinstall the package";
  if (present.length === 0) return check("prompts", "fail", "prompts/ holds no prompt templates", absent.map((n) => `prompts/${n} is missing`), hint);
  if (absent.length) return check("prompts", "fail", "a prompt template is missing", absent.map((n) => `prompts/${n} is missing`), hint);
  const bad = present.filter((n) => !TEMPLATE_HEADER.test(readFileSync(join(dir, n), "utf8")));
  if (bad.length) return check("prompts", "fail", "a prompt template lacks its header", bad.map((n) => `prompts/${n}`));
  return check("prompts", "pass", `prompt templates: ${present.join(", ")}`);
}

/**
 * The probe: the engine's own template lookup, in a child process, must stay inside the package. A
 * missing template must be refused (fail-closed); a path outside the package is the fail-open
 * lookup of the versions before the prompt-path fix.
 */
export function probeTemplates(ctx) {
  const render = join(ctx.pkgDir, "dist", "prompts", "render.js");
  if (!existsSync(render) || !ctx.templates?.length) return check("prompt-lookup", "skip", "no template lookup to probe");
  const r = spawnSync(ctx.nodePath, ["--input-type=module", "-e", probeScript(render, ctx.templates)], { encoding: "utf8", windowsHide: true, timeout: 30_000, env: ctx.probeEnv });
  if (r.status !== 0) return check("prompt-lookup", "fail", "the template lookup probe could not run", [(r.stderr || r.error?.message || "").trim().split("\n").slice(0, 6).join("\n")]);
  const c = classifyProbe(ctx, JSON.parse(r.stdout));
  if (c === null) return check("prompt-lookup", "warn", "dist/prompts/render.js exports no templatePath: the probe is out of date");
  if (c.escaped.length) return check("prompt-lookup", "fail", "the engine's template lookup leaves the package (fail-open): it would read a prompt from outside the installation", [...c.escaped, ...c.refused], "this CodeParley version predates the prompt-path fix: upgrade it, then reinstall the package");
  if (c.refused.length) return check("prompt-lookup", "fail", "the engine refuses a missing or invalid prompt template (fail-closed)", c.refused, "reinstall the package: reviews fail until its prompt templates are restored");
  return check("prompt-lookup", "pass", `the engine resolves and loads ${c.loaded.length} template(s) inside the package: ${c.loaded.join(", ")}`);
}

/** The probe's script: the engine's own lookup (templatePath) and load (loadTemplate) of each template. */
function probeScript(render, names) {
  return [
    `const m = await import(${JSON.stringify(pathToFileURL(render).href)});`,
    "const out = {};",
    `for (const n of ${JSON.stringify(names)}) {`,
    "const r = {};",
    'try { r.path = typeof m.templatePath === "function" ? m.templatePath(n) : null; } catch (e) { r.error = String(e && e.message); }',
    'if (typeof r.path === "string" && typeof m.loadTemplate === "function") {',
    "try { const t = await m.loadTemplate(n); r.load = { id: t.id, version: t.version }; } catch (e) { r.load = { error: String(e && e.message) }; }",
    "}",
    "out[n] = r;",
    "}",
    "process.stdout.write(JSON.stringify(out));",
  ].join(" ");
}

/** Sort the probe's answers: escaped (outside the package), refused (an error), loaded; null when the probe is out of date. */
function classifyProbe(ctx, found) {
  const out = { escaped: [], refused: [], loaded: [] };
  const own = join(realOrSelf(ctx.pkgDir), "prompts");
  for (const [name, r] of Object.entries(found)) {
    if (r.error !== undefined) out.refused.push(`${name}: ${r.error}`);
    else if (r.path === null) return null;
    else if (!inside(realOrSelf(r.path), own)) out.escaped.push(`${name} resolves OUTSIDE the package, to ${r.path}`);
    else if (r.load?.error !== undefined) out.refused.push(`${name}: ${r.load.error}`);
    else out.loaded.push(r.load ? `${name} (${r.load.id} v${r.load.version})` : name);
  }
  return out;
}

/** The real path of `p`, or `p` resolved when it does not exist. */
function realOrSelf(p) {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

function checkEnvironment(ctx) {
  const warns = [];
  for (const v of ["NODE_OPTIONS", "NODE_PATH"]) if (ctx.env[v]) warns.push(`${v} is set: it changes how Node.js loads modules for every process, including the hosts' servers`);
  return warns.length ? check("environment", "warn", "the Node.js environment is not neutral", warns) : check("environment", "pass", "NODE_OPTIONS and NODE_PATH are not set");
}

/**
 * Check the installation at `pkgDir`. Options: nodePath (the Node.js that will run it; default this
 * one), nodeVersion (default: that node's), env (for the environment check), probe (run the
 * template-lookup probe; default true), probeEnv, expectTemplates (template names the package
 * shipped, e.g. from its tarball), platform. Returns { schema, ok, package, node, checks }.
 */
/** What every check reads: the options with their defaults, the manifest, and where the package sits. */
function contextOf(pkgDir, opts) {
  const dir = resolve(pkgDir);
  const nodePath = opts.nodePath ?? process.execPath;
  const ctx = { pkgDir: dir, nodePath, platform: opts.platform ?? process.platform, env: opts.env ?? process.env, probeEnv: opts.probeEnv, expectTemplates: opts.expectTemplates ?? null };
  ctx.nodeVersion = opts.nodeVersion ?? nodeVersionOf(nodePath);
  try {
    ctx.pkg = readJson(join(dir, "package.json"));
  } catch (e) {
    ctx.manifestError = e.message;
  }
  ctx.boundary = installBoundary(dir);
  ctx.npmInstalled = dir.split(sep).includes("node_modules");
  ctx.isCheckout = !ctx.npmInstalled && existsSync(join(dir, "src")) && existsSync(join(dir, "tsconfig.json"));
  return ctx;
}

function kindOf(ctx) {
  if (ctx.npmInstalled) return "npm";
  return ctx.isCheckout ? "checkout" : "directory";
}

export function checkInstall(pkgDir, opts = {}) {
  const ctx = contextOf(pkgDir, opts);
  const checks = [checkManifest(ctx)];
  if (ctx.pkg) {
    const scan = scanPackage(ctx);
    checks.push(checkNode(ctx), checkEntrypoints(ctx), checkModules(ctx, scan), checkDependencies(ctx, scan, dependencyClosure(ctx)), checkPrompts(ctx));
    if (opts.probe !== false) checks.push(probeTemplates(ctx));
  }
  checks.push(checkEnvironment(ctx));
  const pkg = ctx.pkg ?? {};
  return { schema: CHECK_SCHEMA, ok: checks.every((c) => c.status !== "fail"), package: { dir: ctx.pkgDir, name: pkg.name ?? null, version: pkg.version ?? null, kind: kindOf(ctx) }, node: { path: ctx.nodePath, version: ctx.nodeVersion }, checks };
}

/** The version of a Node.js executable ("22.12.0"), or null when it does not run. */
export function nodeVersionOf(nodePath) {
  if (nodePath === process.execPath) return process.versions.node;
  const r = spawnSync(nodePath, ["-p", "process.versions.node"], { encoding: "utf8", windowsHide: true, timeout: 30_000 });
  return r.status === 0 ? r.stdout.trim() : null;
}
