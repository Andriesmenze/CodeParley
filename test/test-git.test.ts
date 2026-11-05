// Step 6: CP_TEST_GIT, the git binary the suite runs (test/test-git.ts).
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { delimiter, dirname, join, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { describeTestGit, selectTestGit, systemTestGitDeps, withFirstOnPath, type TestGitDeps } from "./test-git.js";

const repo = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const V253 = "git version 2.53.0.windows.2";
const V256 = "git version 2.56.0.windows.4";
const REPO = "D:\\a\\CodeParley\\CodeParley";

interface FakeFile { version?: string; exec?: string; native?: boolean; real?: string }
type Files = Record<string, FakeFile>;

/** A Git for Windows installation as its files: the stable entry, the bin launcher and the layout's own binary, all
 * reporting the same version and exec path. */
function gfw(root: string, layout: string, version: string): Files {
  const own: FakeFile = { version, exec: `${root.replaceAll("\\", "/")}/${layout}/libexec/git-core`, native: true };
  return { [`${root}\\cmd\\git.exe`]: { ...own }, [`${root}\\bin\\git.exe`]: { ...own }, [`${root}\\${layout}\\bin\\git.exe`]: { ...own } };
}

/** A controlled Windows machine: these files, and `onPath` as the first git on PATH. */
function machine(files: Files, onPath: string | null, opts: { repoRoot?: string; links?: Record<string, string> } = {}): TestGitDeps {
  const key = (p: string) => win32.normalize(p).toLowerCase();
  const byKey = new Map(Object.entries(files).map(([p, f]) => [key(p), { path: p, ...f }]));
  const links = new Map(Object.entries(opts.links ?? {}).map(([from, to]) => [key(from), to]));
  return {
    platform: "win32",
    repoRoot: opts.repoRoot ?? REPO,
    firstOnPath: () => onPath,
    exists: (p) => byKey.has(key(p)),
    realpath: (p) => {
      if (links.has(key(p))) return links.get(key(p))!;
      const f = byKey.get(key(p));
      if (f) return f.real ?? f.path;
      return [...byKey.keys()].some((k) => k.startsWith(`${key(p)}\\`)) ? win32.normalize(p) : null;
    },
    isNativeImage: (p) => byKey.get(key(p))?.native ?? false,
    version: (p) => byKey.get(key(p))?.version ?? "",
    execPath: (p) => byKey.get(key(p))?.exec ?? "",
  };
}

const PF = "C:\\Program Files\\Git";
const auto = (deps: TestGitDeps) => selectTestGit("auto", deps);

describe("CP_TEST_GIT=auto: Git for Windows' own binary, found at run time", () => {
  it("finds mingw64\\bin\\git.exe in a 2.53 installation (the layout up to 2.55)", () => {
    expect(auto(machine(gfw(PF, "mingw64", V253), `${PF}\\cmd\\git.exe`))).toEqual({
      mode: "native", exe: `${PF}\\mingw64\\bin\\git.exe`, dir: `${PF}\\mingw64\\bin`, version: V253, installation: PF, entry: `${PF}\\cmd\\git.exe`,
    });
  });

  it("finds ucrt64\\bin\\git.exe in a 2.56 installation, from the runner's bin launcher, ignoring a stale mingw64 copy", () => {
    const files = { ...gfw(PF, "ucrt64", V256), [`${PF}\\mingw64\\bin\\git.exe`]: { version: V253, exec: `${PF}/mingw64/libexec/git-core`, native: true } };
    const t = auto(machine(files, `${PF}\\bin\\git.exe`));
    expect(t).toMatchObject({ mode: "native", exe: `${PF}\\ucrt64\\bin\\git.exe`, version: V256, installation: PF });
  });

  it("keeps the native binary when it is already first on PATH (Git Bash)", () => {
    expect(auto(machine(gfw(PF, "mingw64", V253), `${PF}\\mingw64\\bin\\git.exe`))).toMatchObject({ mode: "native", exe: `${PF}\\mingw64\\bin\\git.exe` });
  });

  it("falls back to the git on PATH, saying why, when the installation has no native binary or no git is on PATH", () => {
    const files = gfw(PF, "ucrt64", V256);
    delete files[`${PF}\\ucrt64\\bin\\git.exe`];
    const t = auto(machine(files, `${PF}\\cmd\\git.exe`));
    expect(t).toMatchObject({ mode: "fallback", exe: `${PF}\\cmd\\git.exe`, version: V256 });
    expect(describeTestGit(t)).toMatch(/^test git: FALLBACK, the native binary is not used: no native C:\\Program Files\\Git\\ucrt64\\bin\\git\.exe\. The suite runs C:\\Program Files\\Git\\cmd\\git\.exe \(git version 2\.56/);
    expect(auto(machine(gfw(PF, "ucrt64", V256), null))).toMatchObject({ mode: "fallback", exe: null, reason: "no git on PATH" });
  });

  it("falls back for a layout it does not know and for a binary that is not a PE image", () => {
    const msys = { "C:\\msys64\\usr\\bin\\git.exe": { version: "git version 2.56.0", exec: "/usr/lib/git-core", native: true } };
    expect(auto(machine(msys, "C:\\msys64\\usr\\bin\\git.exe"))).toMatchObject({ mode: "fallback", reason: expect.stringMatching(/not inside a known Git for Windows layout/) });
    const files = gfw(PF, "ucrt64", V256);
    files[`${PF}\\ucrt64\\bin\\git.exe`]!.native = false;
    expect(auto(machine(files, `${PF}\\cmd\\git.exe`))).toMatchObject({ mode: "fallback", reason: `no native ${PF}\\ucrt64\\bin\\git.exe` });
  });

  it("needs the stable entry cmd\\git.exe: a tree without it is not a Git for Windows installation", () => {
    const files = gfw("C:\\tools\\git", "ucrt64", V256);
    delete files["C:\\tools\\git\\cmd\\git.exe"];
    expect(auto(machine(files, "C:\\tools\\git\\bin\\git.exe"))).toMatchObject({ mode: "fallback", reason: expect.stringMatching(/has no stable entry .*cmd\\git\.exe/) });
  });

  it("never selects a binary outside the installation: a linked candidate, an installation in the repository or node_modules", () => {
    const linked = gfw(PF, "ucrt64", V256);
    linked[`${PF}\\ucrt64\\bin\\git.exe`]!.real = `${REPO}\\node_modules\\evil\\git.exe`;
    expect(auto(machine(linked, `${PF}\\cmd\\git.exe`))).toMatchObject({ mode: "fallback", reason: expect.stringMatching(/resolves to .*node_modules.*not to itself/) });
    const junction = machine(gfw(PF, "ucrt64", V256), `${PF}\\cmd\\git.exe`, { links: { [PF]: "E:\\elsewhere\\Git" } });
    expect(auto(junction)).toMatchObject({ mode: "fallback", reason: expect.stringMatching(/not a canonical absolute path/) });
    for (const root of [`${REPO}\\vendor\\Git`, "C:\\work\\node_modules\\git-bin\\Git"]) {
      expect(auto(machine(gfw(root, "ucrt64", V256), `${root}\\cmd\\git.exe`)), root).toMatchObject({ mode: "fallback", reason: expect.stringMatching(/inside the repository or a node_modules directory/) });
    }
  });

  it("falls back when the binary's, the stable entry's or the PATH git's version or exec path differ", () => {
    for (const [file, field, value] of [
      [`${PF}\\ucrt64\\bin\\git.exe`, "version", V253],
      [`${PF}\\cmd\\git.exe`, "version", V253],
      [`${PF}\\bin\\git.exe`, "version", V253],
      [`${PF}\\cmd\\git.exe`, "version", "not git"],
      [`${PF}\\ucrt64\\bin\\git.exe`, "exec", "C:/Other/ucrt64/libexec/git-core"],
      [`${PF}\\cmd\\git.exe`, "exec", "C:/Other/ucrt64/libexec/git-core"],
    ] as const) {
      const files = gfw(PF, "ucrt64", V256);
      files[file]![field] = value;
      expect(auto(machine(files, `${PF}\\bin\\git.exe`)), `${file} ${field}`).toMatchObject({ mode: "fallback" });
    }
  });

  it("with several installations, uses only the one the first git on PATH belongs to", () => {
    const portable = "D:\\PortableGit";
    const both = { ...gfw(PF, "mingw64", V253), ...gfw(portable, "ucrt64", V256) };
    expect(auto(machine(both, `${portable}\\cmd\\git.exe`))).toMatchObject({ mode: "native", exe: `${portable}\\ucrt64\\bin\\git.exe`, installation: portable });
    expect(auto(machine(both, `${PF}\\cmd\\git.exe`))).toMatchObject({ mode: "native", exe: `${PF}\\mingw64\\bin\\git.exe`, installation: PF });
    // The first installation lacks its binary: the other one's is never taken instead.
    const firstBroken = { ...both };
    delete firstBroken[`${portable}\\ucrt64\\bin\\git.exe`];
    expect(auto(machine(firstBroken, `${portable}\\cmd\\git.exe`))).toMatchObject({ mode: "fallback", exe: `${portable}\\cmd\\git.exe` });
    // A git on PATH that reports another installation than the one it lives in.
    const crossed = { ...both, [`${PF}\\cmd\\git.exe`]: { version: V256, exec: `${portable}/ucrt64/libexec/git-core`, native: true } };
    expect(auto(machine(crossed, `${PF}\\cmd\\git.exe`))).toMatchObject({ mode: "fallback", reason: expect.stringMatching(/not part of the installation it reports/) });
  });

  it("changes nothing on Linux, or when CP_TEST_GIT is unset or empty", () => {
    expect(selectTestGit("auto", { ...machine({}, "/usr/bin/git"), platform: "linux" })).toEqual({ mode: "off" });
    expect(selectTestGit(undefined, machine({}, null))).toEqual({ mode: "off" });
    expect(selectTestGit("", machine({}, null))).toEqual({ mode: "off" });
  });
});

describe("CP_TEST_GIT=<path>: an explicitly configured git, fail-closed", () => {
  // Paths in the host's own form: an explicit value must be absolute on the machine that runs the suite.
  const host = process.platform === "win32" ? "C:\\Tools\\Git\\mingw64\\bin\\git.exe" : "/opt/git/bin/git";
  const onPath = process.platform === "win32" ? "C:\\Tools\\Git\\cmd\\git.exe" : "/usr/bin/git";
  const deps = (own: FakeFile, extra: Files = {}) => ({
    ...machine({ [host]: own, [onPath]: { version: V256 }, ...extra }, onPath, { repoRoot: repo }),
    platform: process.platform,
  });

  it("accepts an existing git outside the repository that reports the PATH git's version", () => {
    expect(selectTestGit(host, deps({ version: V256 }))).toEqual({ mode: "configured", exe: host, dir: dirname(host), version: V256 });
  });

  it("refuses a relative path, another program, a missing file, a git in the repository or node_modules, and another version", () => {
    expect(() => selectTestGit("git", deps({ version: V256 }))).toThrow(/"auto" or the absolute path of a git executable/);
    expect(() => selectTestGit(join(dirname(host), process.platform === "win32" ? "bash.exe" : "bash"), deps({ version: V256 }))).toThrow(/absolute path of a git executable/);
    expect(() => selectTestGit(join(dirname(host), "..", "other", process.platform === "win32" ? "git.exe" : "git"), deps({ version: V256 }))).toThrow(/names no file/);
    const inRepo = join(repo, "node_modules", ".bin", process.platform === "win32" ? "git.exe" : "git");
    expect(() => selectTestGit(inRepo, deps({ version: V256 }, { [inRepo]: { version: V256 } }))).toThrow(/inside the repository or a node_modules directory/);
    expect(() => selectTestGit(host, deps({ version: V253 }))).toThrow(/not the same installation's binary/);
    expect(() => selectTestGit(host, deps({ version: "" }))).toThrow(/not the same installation's binary/);
  });

  it("refuses a configured path that does not exist on this machine (the real file system)", () => {
    const missing = process.platform === "win32" ? "C:\\Program Files\\Git\\no-such-layout\\bin\\git.exe" : "/no-such-dir/bin/git";
    expect(() => selectTestGit(missing, systemTestGitDeps(repo))).toThrow(/names no file/);
  });
});

describe("CP_TEST_GIT on this machine", () => {
  const stable = "C:\\Program Files\\Git\\cmd\\git.exe";

  it.skipIf(process.platform !== "win32" || !existsSync(stable))("finds this machine's Git for Windows binary and checks it against cmd\\git.exe", () => {
    const t = selectTestGit("auto", systemTestGitDeps(repo));
    expect(t.mode, describeTestGit(t)).toBe("native");
    if (t.mode !== "native") return;
    expect(t.exe).toMatch(/\\(mingw64|ucrt64|clangarm64)\\bin\\git\.exe$/i);
    expect(existsSync(t.exe)).toBe(true);
    const v = (exe: string) => `${spawnSync(exe, ["--version"], { encoding: "utf8", windowsHide: true }).stdout}`.trim();
    expect(v(t.exe)).toBe(v(stable));
  });

  // The configuration sets PATH before any worker starts; this worker must see the binary it selected.
  it.skipIf(!process.env["CP_TEST_GIT_SELECTED"])("makes the selected binary the first git on this worker's PATH", () => {
    const selected = process.env["CP_TEST_GIT_SELECTED"]!;
    expect(existsSync(selected)).toBe(true);
    const first =
      process.platform === "win32"
        ? `${spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "where.exe"), ["git"], { encoding: "utf8" }).stdout}`.split(/\r?\n/)[0]!.trim()
        : `${spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout}`.trim();
    expect(first.toLowerCase()).toBe(selected.toLowerCase());
  });
});

describe("withFirstOnPath", () => {
  it("moves the directory to the front of PATH without repeating it", () => {
    const d = process.platform === "win32" ? "C:\\Program Files\\Git\\ucrt64\\bin" : "/opt/git/bin";
    expect(withFirstOnPath(["a", d, "b"].join(delimiter), d)).toBe([d, "a", "b"].join(delimiter));
    expect(withFirstOnPath(["a", `${d}${process.platform === "win32" ? "\\" : "/"}`, "b"].join(delimiter), d)).toBe([d, "a", "b"].join(delimiter));
    expect(withFirstOnPath(undefined, d)).toBe(d);
  });
});
