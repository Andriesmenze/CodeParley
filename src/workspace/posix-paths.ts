// POSIX (Linux) path validation, canonicalization and containment — the Linux counterpart of
// win-paths.ts (plan §8.3; Linux milestone, plan §1.13).
//
// Linux file systems are case-sensitive and `/` is the only separator; a name may contain any
// byte except NUL and `/`. Scope paths (allowed roots, repository roots) must be absolute and
// free of control characters. Canonicalization calls fs.realpath on the path AS GIVEN, so the
// kernel resolves symbolic links and `..` by its own rules: there is no lexical `..` folding
// first, because on Linux `link/..` names the parent of the link's TARGET, not of the link.
// For a path that does not exist, the nearest existing ancestor is resolved and the missing
// tail re-appended; a missing tail containing `..` is refused (its meaning depends on links
// that do not exist yet). Containment is exact and separator-aware. Link following itself is
// handled in links.ts.

import { realpath } from "node:fs/promises";
import { DomainError } from "../common/errors.js";

/** Does `s` contain a control character (U+0000 to U+001F, or DEL)? */
function hasControlChar(s: string): boolean {
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Validate an absolute POSIX path and collapse repeated separators. Throws
 * DomainError("INVALID_PATH"). Does not touch the filesystem.
 */
export function validatePosixPath(input: string): string {
  if (typeof input !== "string" || input.length === 0) throw invalid("empty path", input);
  if (hasControlChar(input)) throw invalid("contains control characters", input);
  if (!input.startsWith("/")) throw invalid("must be an absolute path (/...)", input);
  return input.replace(/\/{2,}/g, "/");
}

/** Canonicalize an absolute POSIX path with the OS (see the module comment). */
export async function canonicalizePosixPath(input: string): Promise<string> {
  const p = validatePosixPath(input);
  try {
    return await realpath(p);
  } catch (e) {
    if (!isEnoent(e)) throw e;
  }
  const segs = p.split("/").filter((s) => s.length > 0);
  const tail: string[] = [];
  while (segs.length > 0) {
    const last = segs.pop()!;
    if (last === "..") throw invalid("the part of the path that does not exist contains '..'", input);
    if (last !== ".") tail.unshift(last);
    const ancestor = `/${segs.join("/")}`;
    try {
      const real = await realpath(ancestor);
      return `${real === "/" ? "" : real}/${tail.join("/")}`;
    } catch (e) {
      if (!isEnoent(e)) throw e;
    }
  }
  return `/${tail.join("/")}`;
}

/** `p` without trailing separators ("/" stays "/"). */
export function stripTrailingSlash(p: string): string {
  if (p.length <= 1) return p;
  const s = p.replace(/\/+$/, "");
  return s.length === 0 ? "/" : s;
}

/** Is `child` inside or equal to `root`? Exact (case-sensitive) and separator-aware. */
export function isContainedInPosix(child: string, root: string): boolean {
  const c = stripTrailingSlash(child);
  const r = stripTrailingSlash(root);
  if (r === "/") return c.startsWith("/");
  return c === r || c.startsWith(`${r}/`);
}

/**
 * Why a single relative path segment cannot be captured or exported on Linux, or null.
 * Control characters and backslashes are refused although Linux allows them: they would make
 * names ambiguous in reports and in the confidentiality matcher (which treats `\` as a
 * separator), so such paths are reported as unsupported rather than read (fail closed).
 */
export function posixSegmentProblem(seg: string): string | null {
  if (seg.length === 0) return "empty segment";
  if (seg === "." || seg === "..") return "dot segment";
  if (hasControlChar(seg)) return "control character";
  if (seg.includes("/")) return "slash";
  if (seg.includes("\\")) return "backslash";
  return null;
}

function invalid(reason: string, input: unknown): DomainError {
  return new DomainError("INVALID_PATH", `invalid path: ${reason}`, { details: { input: String(input) } });
}

function isEnoent(e: unknown): boolean {
  return !!e && typeof e === "object" && (e as { code?: string }).code === "ENOENT";
}
