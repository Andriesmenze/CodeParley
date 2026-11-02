// Phase 5 packaging tools (scripts/package/lib): the semver subset, the tarball reader, the package
// content policy and the installation diagnostics, on synthetic installations. The tools are plain
// dependency-free .mjs (they must run where CodeParley's dependencies are missing), so they are
// loaded by URL and typed here.

import { describe, it, expect, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { win } from "./helpers/git-fixture.js";
import { fakeInstall, removeScratch, scratchDir } from "./helpers/package-fixture.js";

interface Check {
  id: string;
  status: "pass" | "fail" | "warn" | "skip";
  summary: string;
  details: string[];
  hint?: string;
}
interface CheckReport {
  ok: boolean;
  checks: Check[];
  package: { kind: string };
}
interface Semver {
  satisfies(version: string, range: string): boolean | null;
}
interface TarEntry {
  path: string;
  type: string;
  size: number;
  data?: Buffer;
}
interface Tar {
  readTarGz(gz: Buffer, o?: { data?: boolean }): TarEntry[];
  packageFiles(gz: Buffer, o?: { data?: boolean }): Map<string, TarEntry>;
}
interface PolicyResult {
  ok: boolean;
  unexpected: { path: string; why: string }[];
  missing: { path: string; why: string }[];
  orphans: string[];
}
interface Policy {
  checkPackageContent(paths: string[], o: { pkg: unknown; inventory?: { modules: string[]; prompts: string[] } | null }): PolicyResult;
  sourceInventory(repoDir: string): { modules: string[]; prompts: string[] };
}
interface InstallCheck {
  checkInstall(dir: string, opts?: Record<string, unknown>): CheckReport;
  scanImports(source: string): { kind: string; spec: string }[];
  splitBare(spec: string): { name: string; subpath: string };
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const load = async <T>(rel: string): Promise<T> => (await import(new URL(`../scripts/package/${rel}`, import.meta.url).href)) as T;
const semver = await load<Semver>("lib/semver-lite.mjs");
const tar = await load<Tar>("lib/tar-lite.mjs");
const policy = await load<Policy>("lib/policy.mjs");
const ic = await load<InstallCheck>("lib/install-check.mjs");
afterAll(removeScratch);

const byId = (r: CheckReport, id: string): Check => {
  const c = r.checks.find((x) => x.id === id);
  if (!c) throw new Error(`no check ${id}: ${r.checks.map((x) => x.id).join(", ")}`);
  return c;
};

describe("semver subset (engines and dependency ranges)", () => {
  it.each([
    ["22.12.0", "^22.12.0 || ^24.0.0", true],
    ["22.11.9", "^22.12.0 || ^24.0.0", false],
    ["23.1.0", "^22.12.0 || ^24.0.0", false],
    ["24.0.0", "^22.12.0 || ^24.0.0", true],
    ["25.0.0", "^22.12.0 || ^24.0.0", false],
    ["20.10.0", "^22.12.0 || ^24.0.0", false],
    ["4.6.6", "^4.2.0", true],
    ["5.0.0", "^4.2.0", false],
    ["2.3.0", "2.3.0", true],
    ["2.3.1", "2.3.0", false],
    ["0.2.5", "^0.2.3", true],
    ["0.3.0", "^0.2.3", false],
    ["1.2.9", "~1.2.3", true],
    ["1.3.0", "~1.2.3", false],
    ["20.0.0", ">=20", true],
    ["19.9.9", ">=20", false],
    ["22.0.0", ">22", false],
    ["23.0.0", ">22", true],
    ["22.5.0", ">=22.1.0 <23", true],
    ["23.0.0", ">=22.1.0 <23", false],
    ["7.1.0", "*", true],
    ["7.1.0", "7.x", true],
    ["2.0.0-beta.1", "^2.0.0", false],
    ["2.0.0-beta.1", "2.0.0-beta.1", true],
  ])("%s satisfies %s: %s", (v, r, want) => {
    expect(semver.satisfies(v, r)).toBe(want);
  });

  it("reports syntax it does not evaluate as null, never as satisfied", () => {
    expect(semver.satisfies("1.5.0", "1.0.0 - 2.0.0")).toBeNull();
    expect(semver.satisfies("1.5.0", "latest")).toBeNull();
    expect(semver.satisfies("not-a-version", "^1.0.0")).toBeNull();
  });
});

describe("tar reader (npm tarballs)", () => {
  const tarExe = win ? join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "tar.exe") : "tar";
  const haveTar = spawnSync(tarExe, ["--version"], { windowsHide: true }).status === 0;

  it.skipIf(!haveTar)("reads ustar entries and long names (pax on bsdtar, GNU long names on GNU tar)", async () => {
    const dir = await scratchDir("cp-tar-");
    const dirName = "d".repeat(70);
    const fileName = "f".repeat(70);
    const long = `${dirName}/${fileName}.txt`;
    mkdirSync(join(dir, "package", "d".repeat(70)), { recursive: true });
    writeFileSync(join(dir, "package", "short.txt"), "hello\n");
    writeFileSync(join(dir, "package", ...long.split("/")), "x".repeat(1500));
    const r = spawnSync(tarExe, ["-czf", "out.tgz", "package"], { cwd: dir, windowsHide: true, encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    const files = tar.packageFiles(readFileSync(join(dir, "out.tgz")), { data: true });
    expect(files.get("short.txt")?.data?.toString("utf8")).toBe("hello\n");
    expect(files.get(long)?.size).toBe(1500);
    expect([...files.keys()].sort()).toEqual([long, "short.txt"].sort());
  });

  it("rejects a truncated archive", () => {
    const header = Buffer.alloc(512);
    header.write("package/a.txt", 0);
    header.write("0001000 ", 124);
    header.write("ustar", 257);
    expect(() => tar.readTarGz(gzipSync(header))).toThrow(/truncated/);
  });
});

describe("package content policy", () => {
  const pkg = { bin: { a: "dist/cli/main.js", b: "./dist/server/main.js" } };
  const inventory = { modules: ["dist/cli/main.js", "dist/server/main.js", "dist/x.js"], prompts: ["prompts/p.md"] };
  const complete = ["package.json", "README.md", "LICENSE", ...inventory.modules, ...inventory.prompts];

  it("accepts exactly the runtime allowlist with every required file", () => {
    expect(policy.checkPackageContent(complete, { pkg, inventory })).toEqual({ ok: true, unexpected: [], missing: [], orphans: [] });
  });

  it("names every development file, every missing runtime file and every orphaned module", () => {
    const files = [...complete.filter((p) => p !== "dist/server/main.js" && p !== "prompts/p.md"), "src/x.ts", "dist/x.js.map", "dist/x.d.ts", "docs/a.md", "CLAUDE.md", "custodian/Svc.cs", "newdir/f.txt", "dist/old.js"];
    const r = policy.checkPackageContent(files, { pkg, inventory });
    expect(r.ok).toBe(false);
    const why = Object.fromEntries(r.unexpected.map((u) => [u.path, u.why]));
    expect(Object.keys(why).sort()).toEqual(["CLAUDE.md", "custodian/Svc.cs", "dist/x.d.ts", "dist/x.js.map", "docs/a.md", "newdir/f.txt", "src/x.ts"]);
    expect(why["dist/x.js.map"]).toMatch(/source map/);
    expect(why["custodian/Svc.cs"]).toMatch(/custodian/);
    expect(why["newdir/f.txt"]).toMatch(/no allowlist rule/);
    expect(r.missing.map((m) => m.path).sort()).toEqual(["dist/server/main.js", "prompts/p.md"]);
    expect(r.orphans).toEqual(["dist/old.js"]);
  });

  it("derives the required modules and prompts from this repository's sources", () => {
    const inv = policy.sourceInventory(repoRoot);
    expect(inv.modules).toContain("dist/cli/main.js");
    expect(inv.modules).toContain("dist/process/session-reaper-main.js");
    expect(inv.modules.some((m) => m.endsWith(".d.js") || m.includes(".ts"))).toBe(false);
    expect(inv.prompts).toContain("prompts/codex-reviewer.md");
  });
});

describe("import scanning (tsc ESM output)", () => {
  it("finds static, side-effect, re-export, dynamic and module-URL references and ignores comments and strings", () => {
    const src = [
      'import { a } from "./a.js";',
      'import "dep-side";',
      'export * from "../b.js";',
      'export { c } from "@scope/pkg/sub";',
      '// import { d } from "./commented.js";',
      ' * import("./in-jsdoc.js")',
      `export const note = "import { e } from 'nowhere'";`,
      'export const importantThing = 1;',
      '    const { f } = await import("./lazy.js");',
      'const u = new URL("./worker.js", import.meta.url);',
      'const v = new URL(uri);',
    ].join("\n");
    expect(ic.scanImports(src)).toEqual([
      { kind: "static", spec: "./a.js" },
      { kind: "static", spec: "dep-side" },
      { kind: "static", spec: "../b.js" },
      { kind: "static", spec: "@scope/pkg/sub" },
      { kind: "dynamic", spec: "./lazy.js" },
      { kind: "url", spec: "./worker.js" },
    ]);
  });

  it("splits a bare specifier into the package and the exported subpath", () => {
    expect(ic.splitBare("zod")).toEqual({ name: "zod", subpath: "." });
    expect(ic.splitBare("@modelcontextprotocol/server/stdio")).toEqual({ name: "@modelcontextprotocol/server", subpath: "./stdio" });
  });
});

const failing = (r: CheckReport): string[] => r.checks.filter((c) => c.status === "fail").map((c) => c.id);

describe("installation diagnostics (lib/install-check.mjs)", () => {
  it("passes a complete installation, probing the template lookup in a child process", async () => {
    const { pkg } = await fakeInstall();
    const r = ic.checkInstall(pkg, { env: {} });
    expect(failing(r)).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.package.kind).toBe("npm");
    expect(byId(r, "prompt-lookup").status).toBe("pass");
    expect(byId(r, "modules").summary).toMatch(/dynamic import and module URL/);
  });

  it.each([
    ["a module only a dynamic import loads", "dist/lib/lazy.js", "modules", /lazy\.js \(dynamic\)/],
    ["a module only a module URL names", "dist/lib/worker.js", "modules", /worker\.js \(url\)/],
    ["a re-exported module", "dist/lib/y.js", "modules", /y\.js \(static\)/],
    ["the entry point", "dist/cli/main.js", "entrypoints", /fake: dist\/cli\/main\.js is missing/],
    ["the dependency", "node_modules/dep-a", "dependencies", /needs dep-a@\^1\.2\.0: not installed/],
  ])("names a missing %s", async (_what, rel, id, detail) => {
    const { pkg } = await fakeInstall((p) => rmSync(join(p, ...rel.split("/")), { recursive: true }));
    const r = ic.checkInstall(pkg, { env: {}, probe: false });
    expect(byId(r, id).status).toBe("fail");
    expect(byId(r, id).details.join("\n")).toMatch(detail);
    expect(byId(r, id).hint).toMatch(/reinstall/);
  });

  it("names an incompatible, undeclared or unexported dependency", async () => {
    const { pkg } = await fakeInstall((p) => {
      writeFileSync(join(p, "node_modules", "dep-a", "package.json"), JSON.stringify({ name: "dep-a", version: "0.9.0", exports: { ".": "./index.js" } }));
      mkdirSync(join(p, "node_modules", "dep-b"), { recursive: true });
      writeFileSync(join(p, "node_modules", "dep-b", "package.json"), JSON.stringify({ name: "dep-b", version: "1.0.0" }));
      writeFileSync(join(p, "dist", "lib", "y.js"), 'import "dep-b";\nimport { s } from "dep-a/sub";\nexport const y = 2;\n');
    });
    const d = byId(ic.checkInstall(pkg, { env: {}, probe: false }), "dependencies");
    expect(d.status).toBe("fail");
    const text = d.details.join("\n");
    expect(text).toMatch(/needs dep-a@\^1\.2\.0: 0\.9\.0 is installed/);
    expect(text).toMatch(/imports \x22dep-b\x22, which package\.json does not declare/);
    expect(text).toMatch(/imports \x22dep-a\/sub\x22: dep-a does not export \.\/sub/);
  });

  it("warns when a dependency resolves from a node_modules outside the installation", async () => {
    const { pkg } = await fakeInstall((p, base) => {
      rmSync(join(p, "node_modules", "dep-a"), { recursive: true });
      mkdirSync(join(base, "node_modules", "dep-a"), { recursive: true });
      writeFileSync(join(base, "node_modules", "dep-a", "package.json"), JSON.stringify({ name: "dep-a", version: "1.4.0" }));
    });
    const d = byId(ic.checkInstall(pkg, { env: {}, probe: false }), "dependencies");
    expect(d.status).toBe("warn");
    expect(d.details.join("\n")).toMatch(/resolves outside the installation/);
  });

  it("fails an unsupported Node.js with what to install", async () => {
    const { pkg } = await fakeInstall();
    const n = byId(ic.checkInstall(pkg, { env: {}, probe: false, nodeVersion: "16.20.0" }), "node-runtime");
    expect(n.status).toBe("fail");
    expect(n.summary).toBe("Node.js 16.20.0 is not supported: CodeParley requires >=18");
    expect(n.hint).toMatch(/install a supported Node\.js/);
  });

  it("shows where the engine would read a missing template from: outside the package", async () => {
    const { pkg, base } = await fakeInstall((p, b) => {
      rmSync(join(p, "prompts"), { recursive: true });
      mkdirSync(join(b, "lib", "prompts"), { recursive: true });
      writeFileSync(join(b, "lib", "prompts", "t.md"), "<!-- template: decoy version: 0 -->\ndecoy\n");
    });
    const r = ic.checkInstall(pkg, { env: {}, expectTemplates: ["t.md"] });
    expect(byId(r, "prompts").status).toBe("fail");
    const lookup = byId(r, "prompt-lookup");
    expect(lookup.status).toBe("fail");
    expect(lookup.details.join("\n")).toContain(`resolves OUTSIDE the package, to ${join(base, "lib", "prompts", "t.md")}`);
    expect(lookup.summary).toMatch(/fail-open/);
  });

  it("tells a fail-closed engine (it refuses the missing template) from a fail-open one", async () => {
    const { pkg } = await fakeInstall((p, b) => {
      rmSync(join(p, "prompts"), { recursive: true });
      mkdirSync(join(b, "lib", "prompts"), { recursive: true });
      writeFileSync(join(b, "lib", "prompts", "t.md"), "<!-- template: t version: 9 -->\ndecoy\n");
      writeFileSync(join(p, "dist", "prompts", "render.js"), 'export function templatePath(name) {\n  throw new Error("prompt template " + name + " is missing from its installation");\n}\n');
    });
    const lookup = byId(ic.checkInstall(pkg, { env: {}, expectTemplates: ["t.md"] }), "prompt-lookup");
    expect(lookup.status).toBe("fail");
    expect(lookup.summary).toMatch(/refuses a missing or invalid prompt template \(fail-closed\)/);
    expect(lookup.details).toEqual(["t.md: prompt template t.md is missing from its installation"]);
    expect(lookup.hint).toMatch(/reinstall the package/);
  });

  it("loads each template as a review would, and reports one the engine refuses to load", async () => {
    const { pkg } = await fakeInstall((p) => {
      const lines = [
        'import { join } from "node:path";',
        'import { fileURLToPath } from "node:url";',
        'export function templatePath(name) { return join(fileURLToPath(import.meta.url), "..", "..", "..", "prompts", name); }',
        'export async function loadTemplate(name) { throw new Error("prompt template " + name + " names template x: it was altered"); }',
      ];
      writeFileSync(join(p, "dist", "prompts", "render.js"), lines.join("\n"));
    });
    const lookup = byId(ic.checkInstall(pkg, { env: {} }), "prompt-lookup");
    expect(lookup.status).toBe("fail");
    expect(lookup.summary).toMatch(/fail-closed/);
    expect(lookup.details).toEqual(["t.md: prompt template t.md names template x: it was altered"]);
  });

  it("fails an entry point without its #! line, and (Linux) one that is not executable", async () => {
    const { pkg } = await fakeInstall((p) => {
      writeFileSync(join(p, "dist", "cli", "main.js"), 'import { x } from "../lib/x.js";\n');
      if (!win) chmodSync(join(p, "dist", "cli", "main.js"), 0o644);
    });
    const e = byId(ic.checkInstall(pkg, { env: {}, probe: false }), "entrypoints");
    expect(e.status).toBe("fail");
    expect(e.details.join("\n")).toMatch(/does not start with \x22#!\/usr\/bin\/env node\x22/);
    if (!win) expect(e.details.join("\n")).toMatch(/is not executable/);
  });

  it("tells an unbuilt git checkout to build, and warns about NODE_OPTIONS", async () => {
    const dir = await scratchDir("cp-checkout-");
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "a.ts"), "export {};\n");
    writeFileSync(join(dir, "tsconfig.json"), "{}\n");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "cp", version: "1.0.0", type: "module", bin: { cp: "dist/cli/main.js" } }));
    const r = ic.checkInstall(dir, { env: { NODE_OPTIONS: "--require x" }, probe: false });
    expect(r.package.kind).toBe("checkout");
    expect(byId(r, "entrypoints").hint).toMatch(/npm run build/);
    expect(byId(r, "modules").hint).toMatch(/npm run build/);
    expect(byId(r, "environment").status).toBe("warn");
  });
});
