// Platform path rules (Linux milestone, plan §1.13). The ONE place that decides whether the
// Windows rules (win-paths.ts: drive/UNC paths, case-insensitive NTFS names) or the POSIX
// rules (posix-paths.ts: `/` only, case-sensitive names) apply. Every other module compares,
// keys and validates paths through these functions, so a path is never compared case-
// insensitively on Linux (where `/x/Repo` and `/x/repo` are different repositories) and
// Windows behaviour — including every persisted key and digest — is exactly what it was.

import * as win from "./win-paths.js";
import * as posix from "./posix-paths.js";

export type PathRules = "win32" | "posix";

/** The rule set for this process. macOS is not a supported platform (plan §22.5). */
export const PATH_RULES: PathRules = process.platform === "win32" ? "win32" : "posix";

const isWin = PATH_RULES === "win32";

/** True where file names compare case-insensitively (NTFS). */
export const CASE_INSENSITIVE_NAMES = isWin;

/** The platform's path separator. */
export const PATH_SEP = isWin ? "\\" : "/";

/** Canonicalize an absolute path with the OS (win-paths.ts / posix-paths.ts rules). */
export function canonicalizePath(input: string, opts: win.PathValidationOptions = {}): Promise<string> {
  return isWin ? win.canonicalizePath(input, opts) : posix.canonicalizePosixPath(input);
}

/** Is `child` inside or equal to `root`? Both canonical. */
export function isContainedIn(child: string, root: string): boolean {
  return isWin ? win.isContainedIn(child, root) : posix.isContainedInPosix(child, root);
}

/**
 * Comparison key for an absolute path: on Windows the path without a trailing backslash,
 * lower-cased (the form every M1 key and digest used); on POSIX the exact path without a
 * trailing slash.
 */
export function pathKey(p: string): string {
  return isWin ? p.replace(/\\$/, "").toLowerCase() : posix.stripTrailingSlash(p);
}

/**
 * Comparison form of a name or relative path: lower-cased on Windows (NTFS), exact on POSIX.
 * Used where M1 lower-cased a value without stripping anything (so Windows forms are
 * unchanged).
 */
export function caseKey(s: string): string {
  return isWin ? s.toLowerCase() : s;
}

/** `p` without a trailing separator, case preserved ("/" stays "/"). */
export function withoutTrailingSeparator(p: string): string {
  return isWin ? p.replace(/\\$/, "") : posix.stripTrailingSlash(p);
}

/** Do two absolute paths name the same location (after canonicalization)? */
export function samePath(a: string, b: string): boolean {
  return pathKey(a) === pathKey(b);
}

/** Is `p` a filesystem root (`X:\`, a bare drive, or `/`)? */
export function isFilesystemRoot(p: string): boolean {
  return isWin ? /^[A-Za-z]:\\?$/.test(p) : posix.stripTrailingSlash(p) === "/";
}

/**
 * Why a single repository-relative segment cannot be captured, exported or used as a check
 * path on this platform, or null.
 */
export function segmentProblem(seg: string): string | null {
  return isWin ? win.windowsSegmentProblem(seg) : posix.posixSegmentProblem(seg);
}

/** Label for a segment problem in capture reasons ("windows_name: …" is the M1 form). */
export const SEGMENT_PROBLEM_LABEL = isWin ? "windows_name" : "posix_name";

/** Validate a path that came from git (relative, no `..`, no `.git`): platform-neutral. */
export const validateGitRelativePath = win.validateGitRelativePath;
