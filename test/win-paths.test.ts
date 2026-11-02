import { describe, it, expect } from "vitest";
import {
  validateWindowsPath,
  normalizeLexically,
  isContainedIn,
  validateGitRelativePath,
} from "../src/workspace/win-paths.js";
import { isDomainError } from "../src/common/errors.js";

describe("validateWindowsPath", () => {
  it("accepts absolute drive and UNC paths", () => {
    expect(validateWindowsPath("C:\\src\\repo")).toBe("C:\\src\\repo");
    expect(validateWindowsPath("C:/src/repo")).toBe("C:\\src\\repo"); // forward slashes normalized
    expect(validateWindowsPath("\\\\server\\share\\dir")).toBe("\\\\server\\share\\dir");
  });

  it.each([
    ["drive-relative", "C:foo"],
    ["root-relative", "\\foo"],
    ["device namespace \\\\?\\", "\\\\?\\C:\\x"],
    ["device namespace \\\\.\\", "\\\\.\\C:\\x"],
    ["alternate data stream", "C:\\x\\file.txt:stream"],
    ["reserved device CON", "C:\\x\\CON"],
    ["reserved device NUL.txt", "C:\\x\\NUL.txt"],
    ["trailing dot", "C:\\x\\name."],
    ["trailing space", "C:\\x\\name "],
    ["pipe char", "C:\\x\\a|b"],
    ["wildcard", "C:\\x\\a?b"],
    ["relative", "src\\repo"],
  ])("rejects %s", (_label, input) => {
    try {
      validateWindowsPath(input);
      throw new Error("expected rejection");
    } catch (e) {
      expect(isDomainError(e)).toBe(true);
      expect((e as { code: string }).code).toBe("INVALID_PATH");
    }
  });

  it("rejects NUL and control characters", () => {
    expect(() => validateWindowsPath("C:\\x\\a\u0000b")).toThrow();
    expect(() => validateWindowsPath("C:\\x\\a\u0001b")).toThrow();
  });
});

describe("normalizeLexically", () => {
  it("resolves . and .. without touching disk", () => {
    expect(normalizeLexically("C:\\a\\b\\..\\c")).toBe("C:\\a\\c");
    expect(normalizeLexically("C:\\a\\.\\b")).toBe("C:\\a\\b");
    expect(normalizeLexically("C:\\a\\b\\..\\..\\..\\..\\x")).toBe("C:\\x");
  });
  it("keeps the UNC root", () => {
    expect(normalizeLexically("\\\\srv\\share\\a\\..\\b")).toBe("\\\\srv\\share\\b");
  });
});

describe("isContainedIn (case-insensitive, separator-aware)", () => {
  it("treats equal paths as contained", () => {
    expect(isContainedIn("C:\\src\\repo", "C:\\src\\repo")).toBe(true);
  });
  it("is case-insensitive", () => {
    expect(isContainedIn("c:\\SRC\\Repo\\file.ts", "C:\\src\\repo")).toBe(true);
  });
  it("is separator-aware (no prefix false positives)", () => {
    expect(isContainedIn("C:\\src\\repo-two", "C:\\src\\repo")).toBe(false);
    expect(isContainedIn("C:\\src\\repo\\a", "C:\\src\\repo")).toBe(true);
  });
  it("rejects a parent as contained in a child", () => {
    expect(isContainedIn("C:\\src", "C:\\src\\repo")).toBe(false);
  });
});

describe("validateGitRelativePath", () => {
  it("accepts a normal relative path and normalizes slashes", () => {
    expect(validateGitRelativePath("src\\a\\b.ts")).toBe("src/a/b.ts");
  });
  it("rejects absolute, .. and .git paths", () => {
    expect(() => validateGitRelativePath("C:\\x")).toThrow();
    expect(() => validateGitRelativePath("../escape")).toThrow();
    expect(() => validateGitRelativePath(".git/config")).toThrow();
    expect(() => validateGitRelativePath("a/../b")).toThrow();
  });
});
