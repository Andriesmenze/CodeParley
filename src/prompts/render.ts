// Logic-free prompt rendering (plan §17). The renderer substitutes `{{NAME}}` placeholders
// and nothing else: no conditionals, no loops. A template placeholder without a value, or a
// value without a placeholder, is an error. Substitution is single-pass, so a value that
// itself contains `{{X}}` is never expanded. The template's id and version, and a SHA-256
// of the rendered prompt, are recorded with every review.
//
// Templates are read only from the CodeParley installation this module belongs to (Phase 5):
// the earlier upward search for any `prompts/` folder read the reviewer prompt from outside the
// installation when the installation's own was missing (docs/validation/results/
// P5-packaging-local.md, §5 item 3). There is no fallback location.

import { realpathSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256OfString } from "../common/hash.js";

export interface PromptTemplate {
  id: string;
  version: string;
  text: string;
  placeholders: string[];
}

const HEADER = /^<!--\s*template:\s*([a-z0-9-]+)\s+version:\s*([0-9A-Za-z.-]+)\s*-->\r?\n/;
const PLACEHOLDER = /\{\{([A-Z][A-Z0-9_]*)\}\}/g;
/** A template is a file directly in prompts/: no path, no traversal. */
const TEMPLATE_FILE = /^[a-z0-9][a-z0-9-]*\.md$/;
/** The folders a CodeParley package keeps its modules in: src/ (a checkout, as the tests run it) and dist/ (built). */
const MODULE_TREES = new Set(["src", "dist"]);
const REMEDY =
  "reinstall CodeParley (in a source checkout, restore the prompts/ folder from git; for the Claude Code plugin, rebuild it with plugin/build-plugin.mjs and reinstall it)";

export function parseTemplate(raw: string): PromptTemplate {
  const h = HEADER.exec(raw);
  if (!h) throw new Error("prompt template lacks its `<!-- template: <id> version: <v> -->` header");
  const text = raw.slice(h[0].length);
  const placeholders = [...new Set([...text.matchAll(PLACEHOLDER)].map((m) => m[1]!))];
  return { id: h[1]!, version: h[2]!, text, placeholders };
}

export function renderTemplate(t: PromptTemplate, values: Readonly<Record<string, string>>): string {
  const missing = t.placeholders.filter((p) => !(p in values));
  if (missing.length) throw new Error(`prompt template ${t.id}: no value for ${missing.join(", ")}`);
  const unused = Object.keys(values).filter((k) => !t.placeholders.includes(k));
  if (unused.length) throw new Error(`prompt template ${t.id}: unknown placeholder(s) ${unused.join(", ")}`);
  return t.text.replace(PLACEHOLDER, (_m, name: string) => values[name]!);
}

export function promptDigest(rendered: string): string {
  return sha256OfString(rendered);
}

/**
 * The installation root of the module at `moduleFile` (this file, or its compiled form), fixed by
 * where the module is and never by where a `prompts/` folder happens to exist: the folder above
 * `src/` or `dist/` — a source checkout, a built checkout, the npm package, and the Claude Code
 * plugin's `app/` (plugin/build-plugin.mjs puts `prompts/` beside `app/dist/`). Any other tree is
 * its own root: the test suites compile src/ straight into a folder of their own and put the
 * templates in its `prompts/` (test/helpers/build-src.ts).
 */
export function installationRoot(moduleFile: string): string {
  const tree = dirname(dirname(moduleFile));
  return MODULE_TREES.has(basename(tree).toLowerCase()) ? dirname(tree) : tree;
}

/** `child` lies strictly inside `parent` (both already resolved). */
function within(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/**
 * Template `name` of the installation the module at `moduleFile` belongs to: exactly
 * `<root>/prompts/<name>`, resolved to its real path, which must stay inside that installation's
 * `prompts/`. Missing, not a regular file, or a link leading out of the installation: an error
 * that says what to restore. There is no other place to look.
 */
export function resolveTemplatePath(moduleFile: string, name: string): string {
  if (!TEMPLATE_FILE.test(name)) throw new Error(`invalid prompt template name ${JSON.stringify(name)}: a file name in prompts/ (lower-case letters, digits and dashes, ending in .md)`);
  const root = installationRoot(moduleFile);
  const file = join(root, "prompts", name);
  let real: string;
  try {
    real = realpathSync(file);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "unreadable";
    throw new Error(`CodeParley's prompt template ${name} is missing from its installation (${code}): expected ${file}. Prompt templates are read only from the installation (${root}), never from anywhere else: ${REMEDY}`);
  }
  if (!within(real, join(realpathSync(root), "prompts"))) throw new Error(`CodeParley's prompt template ${file} leads outside its installation, to ${real}, and is not used: ${REMEDY}`);
  if (!statSync(real).isFile()) throw new Error(`CodeParley's prompt template ${file} is not a regular file: ${REMEDY}`);
  return real;
}

/** `prompts/<name>` of this module's own installation (resolveTemplatePath). */
export function templatePath(name: string): string {
  return resolveTemplatePath(fileURLToPath(import.meta.url), name);
}

const cache = new Map<string, PromptTemplate>();

/**
 * Load a template of this installation. One that is not a valid template, or whose header names
 * another template, was altered or replaced: an error, never a fallback.
 */
export async function loadTemplate(name = "codex-reviewer.md"): Promise<PromptTemplate> {
  const hit = cache.get(name);
  if (hit) return hit;
  const path = templatePath(name);
  let t: PromptTemplate;
  try {
    t = parseTemplate(await readFile(path, "utf8"));
  } catch (e) {
    throw new Error(`CodeParley's prompt template ${path} is not a valid template (${(e as Error).message}): ${REMEDY}`);
  }
  const expected = name.slice(0, -".md".length);
  if (t.id !== expected) throw new Error(`CodeParley's prompt template ${path} names template "${t.id}", not "${expected}": it was altered or replaced; ${REMEDY}`);
  cache.set(name, t);
  return t;
}
