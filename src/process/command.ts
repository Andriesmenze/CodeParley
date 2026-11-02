// Check-command resolution for this platform (plan §14.3; Linux milestone, plan §1.13):
// win-command.ts (PATHEXT, `.cmd` shims through an escaped cmd.exe) on Windows,
// posix-command.ts (execute permission, ELF or "#!" scripts) on Linux. The check runner, the
// identities and the CLI use only this module, so both platforms share one check model.

import * as win from "./win-command.js";
import * as posix from "./posix-command.js";

export type CommandKind = win.CommandKind | posix.PosixCommandKind;

export interface ResolvedCommand {
  path: string;
  kind: CommandKind;
  how: "absolute" | "relative" | "path";
  size: number;
  mtimeMs: number;
  /** Linux scripts: the "#!" line, for display. */
  interpreter?: string;
}

export interface ResolveCommandOptions {
  relativeBase: string;
  /** PATH value of the CHILD environment. */
  pathValue: string | undefined;
  /** PATHEXT value of the child environment (Windows). */
  pathext?: string | undefined;
}

export type ResolveCommandResult = { ok: true; command: ResolvedCommand } | { ok: false; reason: string };

export interface Invocation {
  file: string;
  args: string[];
  windowsVerbatimArguments: boolean;
}

const WIN = process.platform === "win32";

/** Resolve argv[0] under this platform's rules. Never throws for a miss. */
export function resolveCommand(argv0: string, opts: ResolveCommandOptions): ResolveCommandResult {
  return WIN ? win.resolveCommand(argv0, { relativeBase: opts.relativeBase, pathValue: opts.pathValue, pathext: opts.pathext }) : posix.resolvePosixCommand(argv0, opts);
}

/** Build the invocation of a resolved command. Throws on arguments that cannot be passed faithfully. */
export function buildInvocation(cmd: ResolvedCommand, args: readonly string[], systemRoot?: string): Invocation {
  if (WIN) return win.buildInvocation(cmd as win.ResolvedCommand, args, systemRoot ?? process.env["SystemRoot"] ?? "C:\\Windows");
  return posix.buildPosixInvocation(cmd as posix.PosixResolvedCommand, args);
}

/** How the resolved command runs, in words (CLI approval display). */
export function describeKind(cmd: ResolvedCommand): string {
  switch (cmd.kind) {
    case "batch":
      return "batch file, run through cmd.exe";
    case "script":
      // The "#!" line comes from the file: shown with its control characters escaped.
      return `script, run by its interpreter (#!${printable(cmd.interpreter ?? "")})`;
    default:
      return "native executable";
  }
}

/**
 * `s` with every control character (C0, DEL, C1) shown as `\xNN`: for repository-supplied
 * text printed on the user's terminal (a name or "#!" line with escape sequences could rewrite
 * what the approval shows).
 */
export function printable(s: string): string {
  let out = "";
  for (const c of s) {
    const code = c.charCodeAt(0);
    out += code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? `\\x${code.toString(16).padStart(2, "0")}` : c;
  }
  return out;
}

export const displayCommandLine = win.displayCommandLine;
