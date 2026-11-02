// The content policy of CodeParley's npm package (Phase 5): what a distributable may contain, what it
// must contain, and why. It is an allowlist: a file that matches no rule is a violation even when it
// is not a known development file, so a new top-level folder never ships by accident. Adding a
// runtime asset is a deliberate change to both this policy and package.json `files`.
//
// Completeness (every source module compiled, every prompt template present, no compiled module
// without a source) needs the source tree, so it is checked when packing, not after installing.

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

const LICENSE_FILE = /^(LICEN[CS]E|NOTICE)(\.(md|txt))?$/i;
const PROMPT_FILE = /^prompts\/[^\/]+\.md$/;

/** What the package may contain. */
export const ALLOWED = [
  { rule: "package.json", why: "the package manifest", test: (p) => p === "package.json" },
  { rule: "README.md", why: "the user documentation", test: (p) => p === "README.md" },
  { rule: "LICENSE / NOTICE", why: "license notices", test: (p) => LICENSE_FILE.test(p) },
  { rule: "dist/**/*.js", why: "the compiled runtime modules", test: (p) => p.startsWith("dist/") && p.endsWith(".js") },
  { rule: "prompts/*.md", why: "the reviewer prompt templates, read at run time (src/prompts/render.ts)", test: (p) => PROMPT_FILE.test(p) },
];

/** Known development-only content, so a violation says what the file is. */
const DEV_PREFIXES = [
  ["src/", "TypeScript sources (the package ships the compiled dist/)"],
  ["test/", "the test suite"],
  ["docs/", "design and validation records (internal evidence)"],
  ["custodian/", "the Windows custodian service sources (built and installed separately)"],
  ["broker/", "the Phase 3.1 broker sources (preserved, not distributed)"],
  ["spike/", "the M1.0 spike"],
  ["plugin/", "the Claude Code plugin builder (a separate distribution)"],
  ["scripts/", "development and packaging tools"],
  [".github/", "CI configuration"],
  [".codacy", "static-analysis configuration"],
  [".tmp-", "local build and test scratch"],
  ["node_modules/", "dependencies (installed by npm, not bundled)"],
];
const DEV_SUFFIXES = [
  [".map", "a source map (it points at sources the package does not ship)"],
  [".d.ts", "a type declaration (CodeParley is not a library)"],
  [".ts", "a TypeScript source"],
];
const DEV_FILES = new Map([
  ["CLAUDE.md", "agent instructions for this repository"],
  ["DESIGN.MD", "design notes"],
  ["IMPLEMENTATION_PLAN.md", "the implementation plan"],
  ["BROAD_PLAN.md", "the roadmap"],
  ["package-lock.json", "the development lockfile"],
  ["tsconfig.json", "build configuration"],
  ["tsconfig.test.json", "build configuration"],
  ["vitest.config.ts", "test configuration"],
  [".gitignore", "repository configuration"],
]);

/** Why `path` must not ship: a known development file, or "matches no allowlist rule". */
export function devReason(path) {
  if (DEV_FILES.has(path)) return DEV_FILES.get(path);
  for (const [prefix, why] of DEV_PREFIXES) if (path.startsWith(prefix)) return why;
  for (const [suffix, why] of DEV_SUFFIXES) if (path.endsWith(suffix)) return why;
  return "matches no allowlist rule (a runtime asset must be added to the policy and to package.json files deliberately)";
}

/** The allowlist rule `path` falls under, or null. */
export function allowedBy(path) {
  return ALLOWED.find((a) => a.test(path)) ?? null;
}

function walk(root, rel, out) {
  for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) walk(root, p, out);
    else if (e.isFile()) out.push(p);
  }
  return out;
}

/** The runtime content a source tree must produce: a compiled module per source module, and the prompts. */
export function sourceInventory(repoDir) {
  const src = existsSync(join(repoDir, "src")) ? walk(join(repoDir, "src"), "", []) : [];
  const modules = src.filter((p) => p.endsWith(".ts") && !p.endsWith(".d.ts")).map((p) => `dist/${p.slice(0, -3)}.js`);
  const prompts = existsSync(join(repoDir, "prompts")) ? walk(join(repoDir, "prompts"), "", []).map((p) => `prompts/${p}`) : [];
  return { modules: modules.sort(), prompts: prompts.sort() };
}

const normalizeBin = (target) => String(target).replace(/^\.\//, "");

/** The files the package must contain, each with the reason. */
export function requiredFiles(pkg, inventory) {
  const req = new Map([
    ["package.json", "the package manifest"],
    ["README.md", "the user documentation"],
  ]);
  for (const [name, target] of Object.entries(pkg.bin ?? {})) req.set(normalizeBin(target), `the ${name} entry point (package.json bin)`);
  for (const m of inventory?.modules ?? []) if (!req.has(m)) req.set(m, "a compiled source module");
  for (const p of inventory?.prompts ?? []) req.set(p, "a prompt template the engine reads at run time");
  return req;
}

/**
 * Check a package's file list (paths relative to the package root) against the policy:
 * { ok, unexpected: [{path, why}], missing: [{path, why}], orphans: [path] }. `inventory` (from
 * sourceInventory) enables the completeness rules; without it only the allowlist and the entry
 * points are checked.
 */
export function checkPackageContent(paths, { pkg, inventory = null }) {
  const files = new Set(paths);
  const unexpected = [...files].filter((p) => !allowedBy(p)).sort().map((p) => ({ path: p, why: devReason(p) }));
  const missing = [...requiredFiles(pkg, inventory)].filter(([p]) => !files.has(p)).map(([path, why]) => ({ path, why }));
  const known = inventory ? new Set(inventory.modules) : null;
  const orphans = known ? [...files].filter((p) => p.startsWith("dist/") && p.endsWith(".js") && !known.has(p)).sort() : [];
  return { ok: unexpected.length === 0 && missing.length === 0 && orphans.length === 0, unexpected, missing, orphans };
}
