// Step 6: the git executable the test suite runs (tests only; the product's own git selection is unchanged).
//
// Git for Windows puts launchers on PATH (`cmd\git.exe`, `bin\git.exe`) that start the real binary
// (`mingw64\bin\git.exe`) as a second process: about 16–17 ms more per call at rest and ≈ 27 ms under the suite's load,
// on tens of thousands of calls. Git Bash already puts `mingw64\bin` first, so a local run uses the real binary; CI's
// Windows test jobs name it in CP_TEST_GIT. Its directory then goes first on the suite's PATH, so the fixtures, the
// product's PATH lookup (`where.exe git`) and the servers the tests start all find that binary.
//
// Fail-closed: a value that is set must be the absolute path of an existing `git` executable that reports the same
// version as the git already on PATH (the same installation's binary, not another git); anything else stops the run.
import { basename, delimiter, dirname, isAbsolute } from "node:path";

export interface TestGitDeps {
  exists(path: string): boolean;
  /** `<exe> --version`, trimmed. */
  version(exe: string): string;
  /** `git --version` of the git on the current PATH, trimmed. */
  pathVersion(): string;
}

/** The directory to put first on PATH for CP_TEST_GIT, or null when it is unset or empty. */
export function testGitDir(value: string | undefined, deps: TestGitDeps): string | null {
  if (value === undefined || value === "") return null;
  if (!isAbsolute(value) || !/^git(\.exe)?$/i.test(basename(value))) {
    throw new Error(`CP_TEST_GIT must be the absolute path of a git executable, not ${JSON.stringify(value)}`);
  }
  if (!deps.exists(value)) throw new Error(`CP_TEST_GIT names no file: ${value}`);
  const own = deps.version(value);
  const onPath = deps.pathVersion();
  if (!/^git version \S+/.test(own) || own !== onPath) {
    throw new Error(`CP_TEST_GIT reports "${own}" but the git on PATH reports "${onPath}": not the same installation's binary`);
  }
  return dirname(value);
}

/** PATH with `dir` first (and not repeated later). */
export function withFirstOnPath(path: string | undefined, dir: string): string {
  const norm = (p: string) => p.replace(/[\\/]+$/, "").toLowerCase();
  return [dir, ...(path ?? "").split(delimiter).filter((p) => p !== "" && norm(p) !== norm(dir))].join(delimiter);
}
