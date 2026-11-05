// The production dependency closure the plugin and the engine runtimes package (scripts/package/lib/production-packages.mjs),
// from npm's own answer (`npm query .prod`, run for real here) on small installed projects under an ordinary path and
// under a UUID-like one (where npm 11's `npm ls --parseable` redacts the path).
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error -- a plain .mjs module without type declarations
import { npmQueryProd, productionPackages } from "../scripts/package/lib/production-packages.mjs";
import { tempDir } from "./helpers/git-fixture.js";

type Query = (dir: string) => { location: string; name?: string; version?: string }[];
const packages = productionPackages as (dir: string, query?: Query) => string[];
const query = npmQueryProd as Query;

const UUID = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

interface Pkg { version: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }
/** An installed project: its package.json, node_modules and a matching package-lock.json (lockfile version 3). */
function project(dir: string, opts: { lockDev?: string[]; omit?: string[]; installedVersion?: Record<string, string> } = {}): string {
  const nm: Record<string, Pkg & { dev?: boolean; optional?: boolean }> = {
    "node_modules/dep": { version: "1.0.0", dependencies: { sub: "^1.0.0", inner: "2.0.0" } },
    "node_modules/sub": { version: "1.2.0" },
    "node_modules/dep/node_modules/inner": { version: "2.0.0" },
    "node_modules/@scope/lib": { version: "3.0.0" },
    "node_modules/devdep": { version: "1.0.0", dependencies: { devsub: "1.0.0" }, dev: true },
    "node_modules/devsub": { version: "1.0.0", dev: true },
  };
  mkdirSync(dir, { recursive: true });
  const root = { name: "proj", version: "1.0.0", dependencies: { dep: "1.0.0", "@scope/lib": "3.0.0" }, devDependencies: { devdep: "1.0.0" } };
  writeFileSync(join(dir, "package.json"), JSON.stringify(root));
  const lockPackages: Record<string, unknown> = { "": { name: root.name, version: root.version, dependencies: root.dependencies, devDependencies: root.devDependencies } };
  for (const [loc, p] of Object.entries(nm)) {
    const name = loc.slice(loc.lastIndexOf("node_modules/") + "node_modules/".length);
    if (!opts.omit?.includes(loc)) {
      mkdirSync(join(dir, ...loc.split("/")), { recursive: true });
      writeFileSync(join(dir, ...loc.split("/"), "package.json"), JSON.stringify({ name, version: opts.installedVersion?.[loc] ?? p.version, ...(p.dependencies ? { dependencies: p.dependencies } : {}) }));
    }
    const dev = p.dev || opts.lockDev?.includes(loc);
    lockPackages[loc] = { version: p.version, ...(p.dependencies ? { dependencies: p.dependencies } : {}), ...(dev ? { dev: true } : {}) };
  }
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: root.name, version: root.version, lockfileVersion: 3, requires: true, packages: lockPackages }));
  return dir;
}

describe("the production dependency closure (npm query .prod)", () => {
  // npm 11 prints a UUID-like path segment as *** in `npm ls --parseable` (npm 10 does not), which is why the closure
  // comes from `npm query .prod`'s relative locations: the answer must not depend on the path or the npm version.
  it("is the same under an ordinary path and under a UUID-like one", async () => {
    const base = await tempDir("cp-prod-");
    for (const dir of [project(join(base, "plain", "proj")), project(join(base, UUID, "proj"))]) {
      expect(packages(dir), dir).toEqual(["@scope/lib", "dep", "sub"]);
    }
  });

  it("keeps development packages out, and a nested production package with the package it is nested in", async () => {
    const dir = project(join(await tempDir("cp-prod-"), "proj"));
    const all = query(dir).map((p) => p.location).sort();
    expect(all).toEqual(["", "node_modules/@scope/lib", "node_modules/dep", "node_modules/dep/node_modules/inner", "node_modules/sub"]);
    expect(packages(dir)).not.toContain("devdep");
    expect(packages(dir)).not.toContain("devsub");
  });

  it("fails when a locked production package is not installed, or installed at another version", async () => {
    const base = await tempDir("cp-prod-");
    expect(() => packages(project(join(base, "a"), { omit: ["node_modules/sub"] }))).toThrow(/node_modules\/sub@1\.2\.0 is locked but npm does not report it installed/);
    expect(() => packages(project(join(base, "b"), { omit: ["node_modules/dep/node_modules/inner"] }))).toThrow(/inner@2\.0\.0 is locked but npm does not report it installed/);
    expect(() => packages(project(join(base, "c"), { omit: ["node_modules/@scope/lib"] }))).toThrow(/the direct dependency @scope\/lib is not installed/);
    expect(() => packages(project(join(base, "d"), { installedVersion: { "node_modules/sub": "1.3.0" } }))).toThrow(/node_modules\/sub is 1\.3\.0, locked 1\.2\.0/);
  });

  it("fails when the lock and npm disagree on what is production", async () => {
    const dir = project(join(await tempDir("cp-prod-"), "proj"), { lockDev: ["node_modules/sub"] });
    expect(() => packages(dir)).toThrow(/node_modules\/sub is installed as a production dependency but package-lock\.json does not list it as one/);
  });

  it("fails without a lockfile, when npm cannot answer, or when it reports nothing for a project with dependencies", async () => {
    const dir = project(join(await tempDir("cp-prod-"), "proj"));
    expect(() => packages(dir, () => { throw new Error("npm ERR! code ELSPROBLEMS"); })).toThrow(/npm could not list them \(npm ERR! code ELSPROBLEMS\)/);
    expect(() => packages(dir, () => [{ location: "" }])).toThrow(/none found, but package\.json has dependencies/);
    expect(() => packages(dir, () => [{ location: "node_modules/dep/node_modules/inner", version: "2.0.0" }])).toThrow(/nested in node_modules\/dep, which is not a production dependency/);
    rmSync(join(dir, "package-lock.json"));
    expect(() => packages(dir)).toThrow(/cannot read package-lock\.json/);
  });

  it("finds this repository's own closure: the MCP server SDK, its core and zod, no development package", () => {
    const repo = join(__dirname, "..");
    const prod = packages(repo);
    expect(prod).toEqual(expect.arrayContaining(["@modelcontextprotocol/server", "@modelcontextprotocol/core", "zod"]));
    for (const dev of ["typescript", "vitest", "@modelcontextprotocol/client", "@modelcontextprotocol/sdk", "@types/node"]) expect(prod).not.toContain(dev);
  });
});
