// Step 6: the git executable the test suite runs (tests only; the product's own git selection is unchanged).
//
// Git for Windows puts launchers on PATH (`cmd\git.exe`, `bin\git.exe`) that start the installation's own binary as a
// second process: about 16–17 ms more per call at rest and ≈ 27 ms under the suite's load, on tens of thousands of
// calls. Where that binary lives is internal to Git for Windows: `mingw64\bin\git.exe` up to 2.55, `ucrt64\bin\git.exe`
// from 2.56 (only `cmd\git.exe` is promised to stay). The selected binary's directory goes first on the suite's PATH
// before any worker starts, so the fixtures, the product's PATH lookup (`where.exe git`) and the servers the tests start
// all find it.
//
// CP_TEST_GIT:
// - unset or empty: PATH is left as it is.
// - `auto` (CI's Windows test jobs): find the native binary of the installation the first git on PATH belongs to. The
//   installation is the one that git reports (`--exec-path`, `<installation>\<layout>\libexec\git-core`, a known layout)
//   and must hold the stable entry `cmd\git.exe`; the binary is `<installation>\<layout>\bin\git.exe`, at its canonical
//   path (no link out of the installation), a PE image, reporting the same version and exec path as `cmd\git.exe`. If
//   any of that does not hold, the suite runs the git on PATH as before and says so loudly: the optimization is
//   unavailable, which is no reason to stop the suite. On Linux, `auto` changes nothing (git is a native binary).
// - an absolute path: that git, fail-closed: an existing `git` executable outside the repository and node_modules that
//   reports the same version as the git on PATH (the same installation's binary); anything else stops the run.
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, relative, win32 } from "node:path";

/** Git for Windows' layouts: the directory under the installation that holds its own `bin\git.exe`. */
export const GIT_FOR_WINDOWS_LAYOUTS = ["ucrt64", "mingw64", "clangarm64"] as const;

export interface TestGitDeps {
  platform: NodeJS.Platform;
  /** The repository root: nothing under it, or under a node_modules directory, is selected. */
  repoRoot: string;
  /** The first git on PATH as the product's lookup finds it (Windows: `where.exe git`'s first `.exe`), or null. */
  firstOnPath(): string | null;
  exists(path: string): boolean;
  /** The canonical path (links and junctions resolved), or null. */
  realpath(path: string): string | null;
  /** A regular file holding a native executable image (Windows: PE, `MZ`; Linux: ELF). */
  isNativeImage(path: string): boolean;
  /** `<exe> --version`, trimmed ("" when it does not run). */
  version(exe: string): string;
  /** `<exe> --exec-path`, trimmed ("" when it does not run). */
  execPath(exe: string): string;
}

export type TestGit =
  | { mode: "off" }
  | { mode: "configured"; exe: string; dir: string; version: string }
  | { mode: "native"; exe: string; dir: string; version: string; installation: string; entry: string }
  | { mode: "fallback"; exe: string | null; version: string; reason: string };

const GIT_VERSION = /^git version \S+/;

function underUntrusted(path: string, repoRoot: string, rel: (from: string, to: string) => string): boolean {
  const r = rel(repoRoot, path);
  const insideRepo = r === "" || (!r.startsWith("..") && !isAbsolute(r) && !win32.isAbsolute(r));
  return insideRepo || /(^|[\\/])node_modules([\\/]|$)/i.test(path);
}

/** What CP_TEST_GIT selects. Throws only for an explicitly configured path that fails its checks. */
export function selectTestGit(value: string | undefined, deps: TestGitDeps): TestGit {
  if (value === undefined || value === "") return { mode: "off" };
  if (value === "auto") return deps.platform === "win32" ? nativeGitForWindows(deps) : { mode: "off" };
  return configured(value, deps);
}

function configured(value: string, deps: TestGitDeps): TestGit {
  if (!isAbsolute(value) || !/^git(\.exe)?$/i.test(basename(value))) {
    throw new Error(`CP_TEST_GIT must be "auto" or the absolute path of a git executable, not ${JSON.stringify(value)}`);
  }
  if (!deps.exists(value)) throw new Error(`CP_TEST_GIT names no file: ${value}`);
  if (underUntrusted(value, deps.repoRoot, relative)) throw new Error(`CP_TEST_GIT names a git inside the repository or a node_modules directory: ${value}`);
  const own = deps.version(value);
  const entry = deps.firstOnPath();
  const onPath = entry === null ? "" : deps.version(entry);
  if (!GIT_VERSION.test(own) || own !== onPath) {
    throw new Error(`CP_TEST_GIT reports "${own}" but the git on PATH reports "${onPath}": not the same installation's binary`);
  }
  return { mode: "configured", exe: value, dir: dirname(value), version: own };
}

function nativeGitForWindows(deps: TestGitDeps): TestGit {
  const w = win32;
  const same = (a: string | null, b: string) => a !== null && w.normalize(a).toLowerCase() === w.normalize(b).toLowerCase();
  const inside = (child: string, parent: string) => {
    const r = w.relative(parent, child);
    return r !== "" && !r.startsWith("..") && !w.isAbsolute(r);
  };
  const entry = deps.firstOnPath();
  const entryVersion = entry === null ? "" : deps.version(entry);
  const fallback = (reason: string): TestGit => ({ mode: "fallback", exe: entry, version: entryVersion, reason });
  if (entry === null) return fallback("no git on PATH");

  const exec = deps.execPath(entry);
  const m = /^(.+?)[\\/]+([^\\/]+)[\\/]+libexec[\\/]+git-core[\\/]*$/i.exec(exec);
  const layout = m?.[2]?.toLowerCase();
  if (!m || !(GIT_FOR_WINDOWS_LAYOUTS as readonly string[]).includes(layout!)) {
    return fallback(`${entry} reports --exec-path ${JSON.stringify(exec)}, not inside a known Git for Windows layout (${GIT_FOR_WINDOWS_LAYOUTS.join(", ")})`);
  }
  const installation = w.normalize(m[1]!);
  if (!w.isAbsolute(installation) || !same(deps.realpath(installation), installation)) return fallback(`the installation ${installation} is not a canonical absolute path`);
  if (underUntrusted(installation, deps.repoRoot, w.relative)) return fallback(`the installation ${installation} is inside the repository or a node_modules directory`);
  const stable = w.join(installation, "cmd", "git.exe");
  if (!deps.exists(stable) || !deps.isNativeImage(stable)) return fallback(`${installation} has no stable entry ${stable}: not a Git for Windows installation`);
  const canonicalEntry = deps.realpath(entry);
  if (canonicalEntry === null || !inside(canonicalEntry, installation)) return fallback(`the git on PATH (${entry}) is not part of the installation it reports (${installation})`);

  const candidate = w.join(installation, layout!, "bin", "git.exe");
  if (!deps.exists(candidate) || !deps.isNativeImage(candidate)) return fallback(`no native ${candidate}`);
  if (!same(deps.realpath(candidate), candidate)) return fallback(`${candidate} resolves to ${deps.realpath(candidate) ?? "nothing"}, not to itself inside the installation`);
  const stableVersion = deps.version(stable);
  const version = deps.version(candidate);
  if (!GIT_VERSION.test(stableVersion) || version !== stableVersion || entryVersion !== stableVersion) {
    return fallback(`versions differ: ${candidate} "${version}", ${stable} "${stableVersion}", ${entry} "${entryVersion}"`);
  }
  const sameExec = (other: string) => w.normalize(other).toLowerCase() === w.normalize(exec).toLowerCase();
  if (!sameExec(deps.execPath(candidate)) || !sameExec(deps.execPath(stable))) return fallback(`${candidate} or ${stable} reports another --exec-path than ${exec}`);
  return { mode: "native", exe: candidate, dir: w.dirname(candidate), version, installation, entry: stable };
}

/** The one log line that says which git the suite runs. */
export function describeTestGit(t: TestGit): string {
  switch (t.mode) {
    case "off":
      return "test git: the git on PATH (CP_TEST_GIT unset)";
    case "configured":
      return `test git: configured ${t.exe} (${t.version})`;
    case "native":
      return `test git: native ${t.exe} (${t.version}), Git for Windows at ${t.installation}, checked against ${t.entry}`;
    case "fallback":
      return `test git: FALLBACK, the native binary is not used: ${t.reason}. The suite runs ${t.exe ?? "no git"} (${t.version || "no version"})`;
  }
}

/** PATH with `dir` first (and not repeated later). */
export function withFirstOnPath(path: string | undefined, dir: string): string {
  const norm = (p: string) => p.replace(/[\\/]+$/, "").toLowerCase();
  return [dir, ...(path ?? "").split(delimiter).filter((p) => p !== "" && norm(p) !== norm(dir))].join(delimiter);
}

/** This machine, as the selection sees it. */
export function systemTestGitDeps(repoRoot: string): TestGitDeps {
  const run = (exe: string, arg: string) => {
    const r = spawnSync(exe, [arg], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
    return r.status === 0 ? `${r.stdout ?? ""}`.trim() : "";
  };
  return {
    platform: process.platform,
    repoRoot,
    firstOnPath: () => {
      if (process.platform === "win32") {
        const where = spawnSync(win32.join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "where.exe"), ["git"], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
        return `${where.stdout ?? ""}`.split(/\r?\n/).map((s) => s.trim()).find((s) => /\.exe$/i.test(s)) ?? null;
      }
      const r = spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8", timeout: 15_000 });
      return `${r.stdout ?? ""}`.trim() || null;
    },
    exists: (p) => existsSync(p),
    realpath: (p) => {
      try {
        return realpathSync.native(p);
      } catch {
        return null;
      }
    },
    isNativeImage: (p) => {
      let fd: number | null = null;
      try {
        if (!statSync(p).isFile()) return false;
        fd = openSync(p, "r");
        const b = Buffer.alloc(4);
        const n = readSync(fd, b, 0, 4, 0);
        return process.platform === "win32" ? n >= 2 && b[0] === 0x4d && b[1] === 0x5a : n === 4 && b.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
      } catch {
        return false;
      } finally {
        if (fd !== null) closeSync(fd);
      }
    },
    version: (exe) => run(exe, "--version"),
    execPath: (exe) => run(exe, "--exec-path"),
  };
}
