// Resolve a check's argv[0] to an executable and build its Windows invocation (plan §14.3,
// N2, D-19 as revised by M1.3-3). No shell is ever involved in choosing what runs:
//
//  - Resolution is done here, in-process, so the result is deterministic and recorded in the
//    check-spec identity. A bare name is searched ONLY in absolute PATH entries, in PATH
//    order, trying PATHEXT extensions (cmd.exe's directory-major order). The working
//    directory is never searched: CreateProcess/libuv would look in the cwd first, which
//    would let a file planted in the repository (`npm.exe`) shadow the approved command.
//  - Native executables (.exe, .com) are spawned directly with libuv's MSVCRT quoting.
//  - Batch files (.cmd, .bat; npm shims) cannot be spawned without cmd.exe. They run as
//    `%SystemRoot%\System32\cmd.exe /d /v:off /s /c "<quoted path> <args>"` with
//    windowsVerbatimArguments. Every argument is MSVCRT-quoted and then caret-escaped
//    TWICE: once for cmd's parse of the /c line and once for the batch file's parse of the
//    line that forwards `%*`. Single escaping (cross-spawn's choice for anything that is
//    not under node_modules\.bin) lets an argument containing `"` flip cmd's quote state,
//    after which a later `&` splits the command (validated on this machine; see the M1.3
//    validation record). `/d` skips AutoRun, `/v:off` disables delayed `!var!` expansion.
//  - Anything else (.ps1, .js, extensionless scripts) is refused: shell use must be explicit
//    in the approved argv (for example ["pwsh", "-NoProfile", "-Command", "..."]).
//
// This module performs no spawning; `spawn.ts` runs what it builds.

import { statSync } from "node:fs";
import { extname, isAbsolute, join, resolve as resolvePath, win32 } from "node:path";

export type CommandKind = "native" | "batch";

export interface ResolvedCommand {
  /** Absolute path of the file that will run (the batch file itself for .cmd/.bat). */
  path: string;
  kind: CommandKind;
  /** How argv[0] was resolved. */
  how: "absolute" | "relative" | "path";
  size: number;
  mtimeMs: number;
}

export interface ResolveCommandOptions {
  /** Base for argv[0] values containing a path separator (the repository root). */
  relativeBase: string;
  /** PATH value of the CHILD environment. */
  pathValue: string | undefined;
  /** PATHEXT value of the child environment. */
  pathext: string | undefined;
}

export type ResolveCommandResult = { ok: true; command: ResolvedCommand } | { ok: false; reason: string };

const NATIVE_EXT = new Set([".exe", ".com"]);
const BATCH_EXT = new Set([".cmd", ".bat"]);
const DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD";

/** Resolve argv[0] (see the module comment for the rules). Never throws for a miss. */
export function resolveCommand(argv0: string, opts: ResolveCommandOptions): ResolveCommandResult {
  if (argv0.length === 0 || /[\0"\r\n]/.test(argv0)) return { ok: false, reason: "argv[0] is empty or contains a quote or control character" };
  const exts = (opts.pathext && opts.pathext.trim() ? opts.pathext : DEFAULT_PATHEXT)
    .split(";")
    .map((e) => e.trim().toLowerCase())
    .filter((e) => /^\.[a-z0-9]+$/.test(e));

  const candidatesFor = (base: string): string[] => {
    const own = extname(base).toLowerCase();
    // A name that already has an executable extension is tried as is first.
    return [...(own && exts.includes(own) ? [base] : []), ...exts.map((e) => base + e)];
  };

  const hasSep = /[\\/]/.test(argv0);
  if (/^[A-Za-z]:[\\/]/.test(argv0) || /^\\\\[^\\/]/.test(argv0)) return pick(candidatesFor(argv0), "absolute");
  if (/^[A-Za-z]:/.test(argv0) || /^[\\/]/.test(argv0)) return { ok: false, reason: "drive-relative or root-relative argv[0] is not allowed" };
  if (hasSep) return pick(candidatesFor(resolvePath(opts.relativeBase, argv0)), "relative");

  for (const rawDir of (opts.pathValue ?? "").split(";")) {
    const dir = rawDir.trim().replace(/^"(.*)"$/, "$1");
    // Relative PATH entries (including ".") would resolve against the cwd: skip them.
    if (!dir || !isAbsolute(dir)) continue;
    const hit = pick(candidatesFor(join(dir, argv0)), "path");
    if (hit.ok) return hit;
  }
  return { ok: false, reason: `${argv0} was not found on PATH` };
}

function pick(candidates: string[], how: ResolvedCommand["how"]): ResolveCommandResult {
  for (const c of candidates) {
    let st;
    try {
      st = statSync(c);
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    const ext = extname(c).toLowerCase();
    const kind: CommandKind | null = NATIVE_EXT.has(ext) ? "native" : BATCH_EXT.has(ext) ? "batch" : null;
    if (!kind) return { ok: false, reason: `unsupported executable type "${ext || "(none)"}": ${c} (only .exe, .com, .cmd and .bat run; shell use must be explicit)` };
    return { ok: true, command: { path: c, kind, how, size: st.size, mtimeMs: Math.trunc(st.mtimeMs) } };
  }
  return { ok: false, reason: `no executable found for ${candidates[0] ?? "(none)"}` };
}

export interface Invocation {
  file: string;
  args: string[];
  windowsVerbatimArguments: boolean;
}

/** cmd.exe rejects command lines longer than 8191 characters. */
const CMD_LINE_MAX = 8191;
const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/** Build the process invocation for a resolved command and its arguments. Throws on
 * arguments that cannot be passed faithfully. */
export function buildInvocation(cmd: ResolvedCommand, args: readonly string[], systemRoot = process.env["SystemRoot"] ?? "C:\\Windows"): Invocation {
  for (const a of args) if (a.includes("\0")) throw new Error("an argument contains a NUL character");
  if (cmd.kind === "native") return { file: cmd.path, args: [...args], windowsVerbatimArguments: false };

  if (/[\0"%\r\n]/.test(cmd.path)) throw new Error(`batch file path cannot be passed to cmd.exe safely: ${cmd.path}`);
  for (const a of args) {
    if (/[\r\n]/.test(a)) throw new Error("a batch file argument contains a line break, which cmd.exe cannot pass");
  }
  const line = [`"${cmd.path}"`, ...args.map(escapeBatchArgument)].join(" ");
  if (line.length + 2 > CMD_LINE_MAX) throw new Error(`batch command line exceeds ${CMD_LINE_MAX} characters`);
  return {
    // Always a Windows path (this invocation only exists on Windows), whatever the host.
    file: win32.join(systemRoot, "System32", "cmd.exe"),
    args: ["/d", "/v:off", "/s", "/c", `"${line}"`],
    windowsVerbatimArguments: true,
  };
}

/**
 * Quote one argument for a batch file that forwards it to a program using MSVCRT parsing:
 * MSVCRT-quote (double the backslashes before a quote and at the end, escape `"` as `\"`,
 * wrap in quotes), then caret-escape cmd metacharacters twice (see the module comment).
 */
export function escapeBatchArgument(arg: string): string {
  let a = arg.replace(/(\\*)"/g, '$1$1\\"');
  a = a.replace(/(\\*)$/, "$1$1");
  a = `"${a}"`;
  a = a.replace(CMD_META, "^$1");
  return a.replace(CMD_META, "^$1");
}

/** Human-readable command line for records and the CLI (never executed). */
export function displayCommandLine(argv: readonly string[]): string {
  return argv.map((a) => (/^[A-Za-z0-9_./:\\=+,@-]+$/.test(a) ? a : JSON.stringify(a))).join(" ");
}
