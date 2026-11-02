// Windows path validation, canonicalization and containment (plan §8.3).
//
// Accept only absolute drive paths (X:\...) or UNC (\\server\share\...). Reject every
// device-namespace prefix, alternate data streams, reserved device names, control/invalid
// characters, and relative or drive-relative forms. Canonicalization uses fs.realpath,
// which on Windows calls GetFinalPathNameByHandleW and so resolves junctions, symlinks,
// mount points, subst/mapped drives, 8.3 names and case. Containment is case-insensitive
// and separator-aware. Link following itself is handled in links.ts.

import { realpath } from "node:fs/promises";
import { parse as parsePath } from "node:path";
import { DomainError } from "../common/errors.js";

const INVALID_CHARS = /[<>"|*?\u0000-\u001f]/;
const RESERVED_DEVICE = /^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]|CONIN\$|CONOUT\$)$/i;
const DEVICE_NS_PREFIX = /^(\\\\\?\\|\\\\\.\\|\\\?\?\\)/; // \\?\  \\.\  \??\

export interface PathValidationOptions {
  /** Allow UNC (\\server\share\...). Default true. */
  allowUnc?: boolean;
}

/**
 * Validate a Windows path against plan §8.3 rules 1–2 and return it with separators
 * normalized to backslash. Throws DomainError("INVALID_PATH") on any violation.
 * This does NOT touch the filesystem.
 */
export function validateWindowsPath(input: string, opts: PathValidationOptions = {}): string {
  const allowUnc = opts.allowUnc ?? true;
  if (typeof input !== "string" || input.length === 0) {
    throw invalid("empty path", input);
  }
  if (INVALID_CHARS.test(input)) throw invalid("contains control or invalid characters (<>\"|*? or NUL)", input);
  if (DEVICE_NS_PREFIX.test(input)) throw invalid("device-namespace prefix (\\\\?\\, \\\\.\\, \\??\\) not allowed", input);

  const path = input.replace(/\//g, "\\");

  const isDrive = /^[A-Za-z]:\\/.test(path);
  const isUnc = /^\\\\[^\\]/.test(path);

  if (!isDrive && !isUnc) {
    if (/^[A-Za-z]:(?![\\])/.test(path)) throw invalid("drive-relative path (C:foo) not allowed", input);
    if (/^\\(?!\\)/.test(path)) throw invalid("root-relative path (\\foo) not allowed", input);
    throw invalid("must be an absolute drive path (X:\\...) or UNC (\\\\server\\share\\...)", input);
  }
  if (isUnc && !allowUnc) throw invalid("UNC paths not allowed here", input);

  // Alternate data streams: a ':' anywhere except the drive designator at index 1.
  const colonIdx = path.indexOf(":", isDrive ? 2 : 0);
  if (colonIdx !== -1) throw invalid("alternate data stream (':' after the drive) not allowed", input);

  // Segment checks.
  const body = isUnc ? path.slice(2) : path.slice(3); // strip "\\" or "X:\"
  const segments = body.split("\\").filter((s) => s.length > 0);
  // For UNC the first two segments are server and share; still subject to char rules.
  for (const seg of segments) {
    if (seg === "." || seg === "..") continue; // handled by normalization; not inherently invalid
    if (/[ .]$/.test(seg)) throw invalid(`segment ends with space or dot: "${seg}"`, input);
    const base = seg.split(".")[0] ?? seg;
    if (RESERVED_DEVICE.test(base)) throw invalid(`reserved device name: "${seg}"`, input);
  }
  return path;
}

/** Lexically resolve `.` and `..` without touching the filesystem. Keeps the root. */
export function normalizeLexically(path: string): string {
  const p = path.replace(/\//g, "\\");
  const isUnc = /^\\\\/.test(p);
  const driveMatch = p.match(/^[A-Za-z]:\\/);
  let root: string;
  let rest: string;
  if (isUnc) {
    // \\server\share\rest
    const m = p.match(/^(\\\\[^\\]+\\[^\\]+\\?)(.*)$/);
    root = m ? m[1]!.replace(/\\?$/, "\\") : "\\\\";
    rest = m ? m[2]! : p.slice(2);
  } else if (driveMatch) {
    root = driveMatch[0]!;
    rest = p.slice(root.length);
  } else {
    root = "";
    rest = p;
  }
  const out: string[] = [];
  for (const seg of rest.split("\\")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0) out.pop();
      continue;
    }
    out.push(seg);
  }
  return root + out.join("\\");
}

/**
 * Canonicalize an absolute path with the OS (fs.realpath). For a path that does not exist,
 * resolve the nearest existing ancestor and re-append the remaining validated segments
 * (plan §8.3 rule 5). Validates first.
 */
export async function canonicalizePath(input: string, opts: PathValidationOptions = {}): Promise<string> {
  const validated = normalizeLexically(validateWindowsPath(input, opts));
  try {
    return await realpath(validated);
  } catch (e) {
    if (!isEnoent(e)) throw e;
  }
  // Walk up to the nearest existing ancestor.
  const parts = validated.split("\\");
  const tail: string[] = [];
  while (parts.length > 1) {
    tail.unshift(parts.pop()!);
    const ancestor = parts.join("\\");
    const candidate = /^[A-Za-z]:$/.test(ancestor) ? ancestor + "\\" : ancestor;
    try {
      const real = await realpath(candidate);
      return [real.replace(/\\$/, ""), ...tail].join("\\");
    } catch (e) {
      if (!isEnoent(e)) throw e;
    }
  }
  return validated; // nothing existed; return the normalized form
}

/**
 * Is `child` inside or equal to `root`? Case-insensitive, separator-aware (plan §8.3
 * rule 4). Both should already be canonical.
 */
export function isContainedIn(child: string, root: string): boolean {
  const c = child.replace(/\\$/, "").toLowerCase();
  const r = root.replace(/\\$/, "").toLowerCase();
  if (c === r) return true;
  return c.startsWith(r + "\\");
}

/**
 * Validate a path that came from git output (plan §8.3 rule 6): must be relative, contain
 * no ".." segment, and must not name `.git` or anything under it. Returns the path with
 * forward slashes normalized to the relative POSIX-ish form git uses.
 */
export function validateGitRelativePath(rel: string): string {
  if (typeof rel !== "string" || rel.length === 0) throw invalid("empty git path", rel);
  const p = rel.replace(/\\/g, "/");
  if (/^([A-Za-z]:|\/|\\)/.test(p) || /^[A-Za-z]:/.test(rel)) throw invalid("git path must be relative", rel);
  const segs = p.split("/");
  for (const s of segs) {
    if (s === "..") throw invalid('git path contains ".."', rel);
    if (s.toLowerCase() === ".git") throw invalid("git path names .git", rel);
  }
  return p;
}

/**
 * Why a single relative path segment cannot name a file on Windows, or null if it can
 * (plan §8.3 rule 2 applied per segment). Used for paths that come from git (which may
 * have been committed on another OS) before they are read from, or written into, a
 * Windows directory: `a:b` would address an alternate data stream, `x.` or `x ` is
 * silently trimmed to another name, and `con.txt` opens a device.
 */
export function windowsSegmentProblem(seg: string): string | null {
  if (seg.length === 0) return "empty segment";
  if (seg === "." || seg === "..") return "dot segment";
  if (INVALID_CHARS.test(seg)) return "control or invalid character";
  if (seg.includes(":")) return "':' (alternate data stream)";
  if (seg.includes("\\")) return "backslash";
  if (/[ .]$/.test(seg)) return "ends with space or dot";
  const base = seg.split(".")[0] ?? seg;
  if (RESERVED_DEVICE.test(base)) return "reserved device name";
  return null;
}

function invalid(reason: string, input: unknown): DomainError {
  return new DomainError("INVALID_PATH", `invalid Windows path: ${reason}`, { details: { input: String(input) } });
}

function isEnoent(e: unknown): boolean {
  return !!e && typeof e === "object" && (e as { code?: string }).code === "ENOENT";
}

/** Convenience: the drive/share root of a validated path. */
export function rootOf(path: string): string {
  const parsed = parsePath(path);
  return parsed.root;
}
