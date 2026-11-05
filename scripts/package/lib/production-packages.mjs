// The production dependency closure of a checkout's installed node_modules: the packages a build copies next to the
// compiled engine (the Claude Code plugin, plugin/build-plugin.mjs; the engine runtimes, scripts/package/stage-release.mjs).
// Offline: it reads what is installed.
//
// npm decides the closure (`npm query .prod`: the packages `npm ls --omit=dev` lists) and reports each one's location
// relative to the checkout. The absolute paths `npm ls --parseable` prints cannot be matched against the checkout's
// path: npm 11 redacts UUID-like strings in its output, so under a directory such as a worktree's UUID every line
// reads `…\***\…` and a prefix match silently drops every dependency.
//
// Fail-closed: the closure must be exactly package-lock.json's non-development packages, at their locked versions (an
// optional one may be missing, and is then not on disk); each must be on disk with the locked name and version; every
// direct dependency in package.json must be among them; and each nested package must sit inside a top-level one (it
// is copied with it). Anything else throws, naming what is wrong.

import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const NM = "node_modules/";

/** npm's production packages of the checkout at `dir`: `{ location, name, version }`, `location` relative to `dir`. */
export function npmQueryProd(dir) {
  const out = execSync("npm query .prod", { cwd: dir, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const list = JSON.parse(out);
  if (!Array.isArray(list)) throw new Error("`npm query .prod` did not return a list");
  return list.map((p) => ({ location: typeof p.location === "string" ? p.location : "", name: p.name, version: p.version }));
}

/** The top-level production packages of the checkout at `dir`, as paths relative to its node_modules (`zod`,
 * `@scope/name`). `query` is npm's answer (tests give their own). */
export function productionPackages(dir, query = npmQueryProd) {
  const fail = (message) => {
    throw new Error(`production dependencies of ${dir}: ${message}`);
  };
  const readJson = (file, what) => {
    try {
      return JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      return fail(`cannot read ${what} (${e instanceof Error ? e.message : String(e)})`);
    }
  };
  const pkg = readJson(join(dir, "package.json"), "package.json");
  const lock = readJson(join(dir, "package-lock.json"), "package-lock.json");
  if (!lock.packages || typeof lock.packages !== "object") fail("package-lock.json has no `packages` map (lockfile version 2 or later is needed)");

  const locked = new Map(Object.entries(lock.packages).filter(([loc, e]) => loc.startsWith(NM) && !e.dev));
  for (const [loc, e] of locked) if (e.link) fail(`${loc} is a link; linked packages are not packaged`);

  let found;
  try {
    found = query(dir);
  } catch (e) {
    fail(`npm could not list them (${e instanceof Error ? e.message.split("\n")[0] : String(e)})`);
  }
  const installed = new Map(found.filter((p) => p.location !== "").map((p) => [p.location, p]));
  const onDisk = (loc) => join(dir, ...loc.split("/"));
  const nameOf = (loc) => loc.slice(loc.lastIndexOf(NM) + NM.length);

  const problems = [];
  for (const [loc, e] of locked) {
    const got = installed.get(loc);
    if (!got) {
      if ((e.optional || e.devOptional) && !existsSync(onDisk(loc))) continue;
      problems.push(`${loc}@${e.version} is locked but npm does not report it installed`);
    } else if (got.version !== e.version) problems.push(`${loc} is ${got.version}, locked ${e.version}`);
  }
  for (const loc of installed.keys()) {
    if (!loc.startsWith(NM)) problems.push(`${loc} is outside node_modules`);
    else if (!locked.has(loc)) problems.push(`${loc} is installed as a production dependency but package-lock.json does not list it as one`);
  }
  for (const [loc, got] of installed) {
    const file = join(onDisk(loc), "package.json");
    if (!existsSync(file)) {
      problems.push(`${loc} has no package.json`);
      continue;
    }
    const m = readJson(file, `${loc}/package.json`);
    const want = locked.get(loc);
    const name = want?.name ?? nameOf(loc);
    if (m.name !== name || m.version !== (want?.version ?? got.version)) problems.push(`${loc}/package.json is ${m.name}@${m.version}, expected ${name}@${want?.version ?? got.version}`);
  }
  for (const d of Object.keys(pkg.dependencies ?? {})) if (!installed.has(`${NM}${d}`)) problems.push(`the direct dependency ${d} is not installed at ${NM}${d}`);

  const top = [...installed.keys()].filter((loc) => loc.startsWith(NM) && !loc.slice(NM.length).includes(`/${NM}`));
  for (const loc of installed.keys()) {
    const inner = loc.indexOf(`/${NM}`, NM.length);
    if (loc.startsWith(NM) && inner >= 0 && !installed.has(loc.slice(0, inner))) problems.push(`${loc} is nested in ${loc.slice(0, inner)}, which is not a production dependency`);
  }
  if (Object.keys(pkg.dependencies ?? {}).length > 0 && top.length === 0) problems.push("none found, but package.json has dependencies");
  if (problems.length > 0) fail(`${problems.join("; ")}. Run \`npm ci\` and build again.`);
  return top.map((loc) => loc.slice(NM.length)).sort();
}
