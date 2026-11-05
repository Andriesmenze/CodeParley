// Step 6: CP_TEST_GIT, the git binary the suite runs (test/test-git.ts).
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { testGitDir, withFirstOnPath } from "./test-git.js";

const exe = process.platform === "win32" ? join("C:\\", "Program Files", "Git", "mingw64", "bin", "git.exe") : "/usr/bin/git";
const deps = (o: { exists?: boolean; version?: string; pathVersion?: string } = {}) => ({
  exists: () => o.exists ?? true,
  version: () => o.version ?? "git version 2.56.0.windows.4",
  pathVersion: () => o.pathVersion ?? "git version 2.56.0.windows.4",
});

describe("CP_TEST_GIT", () => {
  it("is optional: unset or empty leaves PATH alone", () => {
    expect(testGitDir(undefined, deps())).toBeNull();
    expect(testGitDir("", deps())).toBeNull();
  });

  it("puts the directory of the same installation's git binary first", () => {
    expect(testGitDir(exe, deps())).toBe(dirname(exe));
  });

  it("refuses anything but an absolute path to an existing git that reports the same version as the git on PATH", () => {
    expect(() => testGitDir("git", deps())).toThrow(/absolute path of a git executable/);
    expect(() => testGitDir(join(dirname(exe), "bash.exe"), deps())).toThrow(/absolute path of a git executable/);
    expect(() => testGitDir(exe, deps({ exists: false }))).toThrow(/names no file/);
    expect(() => testGitDir(exe, deps({ version: "git version 2.43.0" }))).toThrow(/not the same installation's binary/);
    expect(() => testGitDir(exe, deps({ version: "", pathVersion: "" }))).toThrow(/not the same installation's binary/);
  });

  it("moves the directory to the front of PATH without repeating it", () => {
    const d = dirname(exe);
    expect(withFirstOnPath(["a", d, "b"].join(delimiter), d)).toBe([d, "a", "b"].join(delimiter));
    expect(withFirstOnPath(["a", `${d}${process.platform === "win32" ? "\\" : "/"}`, "b"].join(delimiter), d)).toBe([d, "a", "b"].join(delimiter));
    expect(withFirstOnPath(undefined, d)).toBe(d);
  });

  // The configuration sets PATH before any worker starts; this worker must see it.
  it.skipIf(!process.env["CP_TEST_GIT"])("makes the configured binary the first git on this worker's PATH", () => {
    const configured = process.env["CP_TEST_GIT"]!;
    expect(existsSync(configured)).toBe(true);
    const first =
      process.platform === "win32"
        ? `${spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "where.exe"), ["git"], { encoding: "utf8" }).stdout}`.split(/\r?\n/)[0]!.trim()
        : `${spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout}`.trim();
    expect(first.toLowerCase()).toBe(configured.toLowerCase());
  });
});
