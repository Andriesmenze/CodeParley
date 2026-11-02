// Resolve a check's argv[0] to an executable on Linux and build its invocation (plan §14.3;
// Linux milestone, plan §1.13) — the counterpart of win-command.ts. No shell is ever involved
// in choosing or starting what runs:
//
//  - An absolute argv[0] names that file; one containing "/" is resolved against the repository
//    root; a bare name is searched ONLY in absolute PATH entries, in PATH order. An empty or
//    relative entry (which a shell would read as the working directory) is skipped, so a file
//    planted in the repository cannot shadow the approved command.
//  - The hit must be a regular file this user may execute. Directories and non-executable files
//    are skipped, as a shell's lookup does.
//  - The kernel starts the file itself: an ELF executable directly; a script through the
//    interpreter on its "#!" line (npm, npx and most tool launchers are scripts). Arguments reach
//    the program verbatim (execve). A file that is neither is REFUSED: execvp would hand it to
//    /bin/sh, an implicit shell.
//
// This module performs no spawning; `spawn.ts` runs what it builds.

import { accessSync, closeSync, constants, openSync, readSync, statSync, type Stats } from "node:fs";
import { isAbsolute, join, resolve as resolvePath } from "node:path";

export type PosixCommandKind = "native" | "script";

export interface PosixResolvedCommand {
  /** Absolute path of the file that will run (as found; links are followed only by the OS). */
  path: string;
  kind: PosixCommandKind;
  how: "absolute" | "relative" | "path";
  size: number;
  mtimeMs: number;
  /** For scripts: the "#!" line (without "#!"), for display. */
  interpreter?: string;
}

export interface PosixResolveOptions {
  /** Base for argv[0] values containing "/" (the repository root). */
  relativeBase: string;
  /** PATH value of the CHILD environment. */
  pathValue: string | undefined;
}

export type PosixResolveResult = { ok: true; command: PosixResolvedCommand } | { ok: false; reason: string };

/** Resolve argv[0] (see the module comment). Never throws for a miss. */
export function resolvePosixCommand(argv0: string, opts: PosixResolveOptions): PosixResolveResult {
  if (argv0.length === 0 || hasControlChar(argv0)) return { ok: false, reason: "argv[0] is empty or contains a control character" };
  if (argv0.startsWith("/")) return examine(argv0, "absolute", true);
  if (argv0.includes("/")) return examine(resolvePath(opts.relativeBase, argv0), "relative", true);
  for (const dir of (opts.pathValue ?? "").split(":")) {
    // An empty or relative PATH entry would resolve against the working directory: skip it.
    if (!dir || !isAbsolute(dir)) continue;
    const hit = examine(join(dir, argv0), "path", false);
    if (hit.ok) return hit;
    if ("fatal" in hit && hit.fatal) return hit;
  }
  return { ok: false, reason: `${argv0} was not found on PATH (absolute PATH entries only)` };
}

type Examined = PosixResolveResult | { ok: false; reason: string; fatal: true };

/** Does `s` contain a control character (C0, DEL or C1)? Such names could rewrite a terminal when shown. */
function hasControlChar(s: string): boolean {
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

function examine(p: string, how: PosixResolvedCommand["how"], explicit: boolean): Examined {
  let st: Stats;
  try {
    st = statSync(p);
  } catch {
    return { ok: false, reason: `no executable found at ${p}` };
  }
  if (!st.isFile()) return { ok: false, reason: `not a regular file: ${p}` };
  try {
    accessSync(p, constants.X_OK);
  } catch {
    return { ok: false, reason: `not executable for this user: ${p}` };
  }
  const head = readHead(p);
  if (head === null) return { ok: false, reason: `cannot read ${p}` };
  if (head.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    return { ok: true, command: { path: p, kind: "native", how, size: st.size, mtimeMs: Math.trunc(st.mtimeMs) } };
  }
  if (head[0] === 0x23 && head[1] === 0x21) {
    const line = head.subarray(2).toString("utf8").split(/\r?\n/)[0]!.trim();
    return { ok: true, command: { path: p, kind: "script", how, size: st.size, mtimeMs: Math.trunc(st.mtimeMs), interpreter: line } };
  }
  // An executable without an ELF header or "#!" line would be run by /bin/sh (execvp): refuse.
  const reason = `unsupported executable type: ${p} has no ELF header and no "#!" line, so it would be run by /bin/sh implicitly (shell use must be explicit in the approved argv)`;
  return explicit ? { ok: false, reason } : { ok: false, reason, fatal: true };
}

function readHead(p: string): Buffer | null {
  let fd: number | null = null;
  try {
    fd = openSync(p, "r");
    const buf = Buffer.alloc(256);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n);
  } catch {
    return null;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

export interface PosixInvocation {
  file: string;
  args: string[];
  windowsVerbatimArguments: false;
}

/** The invocation of a resolved command: the file itself, arguments verbatim. */
export function buildPosixInvocation(cmd: PosixResolvedCommand, args: readonly string[]): PosixInvocation {
  for (const a of args) if (a.includes("\0")) throw new Error("an argument contains a NUL character");
  return { file: cmd.path, args: [...args], windowsVerbatimArguments: false };
}
