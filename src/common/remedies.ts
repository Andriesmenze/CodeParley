// Phase 6 Increment 3 (contract §3.4): the remediation catalog — for each refusal an operator or the implementer is
// likely to meet, its cause and the command that fixes it, in this platform's terms. The CLI prints it under an error
// and the MCP server adds it to an error result (`error.remedy`).
//
// Wording only. A remedy names a command a person runs; it records, grants and confirms nothing, and nothing reads it to
// decide anything. It never quotes protected content or a path from the error: the error's own message carries the
// specifics.

import type { ErrorCode } from "./errors.js";

export interface Remedy {
  /** Why this refusal happens. */
  cause: string;
  /** What to do, with the exact command. */
  fix: string;
}

type Platform = "win32" | "linux" | "other";

function platformOf(p: NodeJS.Platform): Platform {
  return p === "win32" ? "win32" : p === "linux" ? "linux" : "other";
}

/** The operator's CLI and where it is typed. */
function operator(p: Platform): { cli: string; where: string } {
  if (p === "linux") return { cli: "/usr/local/sbin/code-parley-operator", where: "as the operator account" };
  return { cli: "code-parley", where: "in an elevated terminal (Run as administrator) as the operator account" };
}

/** The product installer, as an administrator runs it, with its options in that installer's syntax. */
function installer(p: Platform, verb: string, o: { release?: boolean; resume?: boolean; path?: boolean } = {}): string {
  if (p === "linux") return `\`sudo bash codeparley-installer.sh ${verb}${o.release ? " --release <dir>" : ""}${o.resume ? " --resume" : ""}${o.path ? " --path <repository>" : ""}\``;
  return `\`codeparley-installer.ps1 ${verb}${o.release ? " -Release <dir>" : ""}${o.resume ? " -Resume" : ""}${o.path ? " -Path <repository>" : ""}\` (elevated PowerShell)`;
}

/** The custodian's service in this platform's terms. */
function service(p: Platform): string {
  return p === "linux" ? "the codeparley-custodian service (started by its sockets)" : "the CodeParleyCustodian service";
}

type Entry = (p: Platform) => Remedy;

const CATALOG: Partial<Record<ErrorCode, Entry>> = {
  CUSTODIAN_UNAVAILABLE: (p) => ({
    cause: p === "other"
      ? "protected runs need the CodeParley custodian, which exists on Windows and Linux only"
      : `no trusted answer came from ${service(p)}: it is not installed, stopped, still starting, or it refused its store (for example after an interrupted upgrade)`,
    fix: p === "other"
      ? "use attended reviews here; protected loops and delegated fixes need Windows or Linux with the custodian installed"
      : `run \`code-parley status\` to see which; it names the state and the command for it (install: ${installer(p, "install", { release: true })}; an interrupted upgrade: ${installer(p, "upgrade", { resume: true })}). Nothing falls back to weaker authority meanwhile`,
  }),
  CUSTODIAN_BUSY: (p) => ({
    cause: p === "win32"
      ? "the custodian serves one request at a time and was busy longer than this request could wait. Right after a boot, its first protected request measures the approved engine runtime (about 13–55 s measured on the test VM; a queued call waited 37.7 s), and a hook queued behind that can run out of time"
      : "the custodian serves one request at a time and was busy longer than this request could wait",
    fix: "wait for the current request to finish and try again; `code-parley status` shows when it answers again. This is a known first-release limitation: it fails closed (nothing was granted, consumed or weakened) and clears by itself",
  }),
  SERVER_NOT_TRUSTED: (p) => ({
    cause: `the endpoint that answered is not owned by ${service(p)}: another process holds the custodian's ${p === "linux" ? "socket" : "pipe"} name`,
    fix: `do not proceed; an administrator checks the host (${installer(p, "status")}) and restarts the custodian. CodeParley refuses to talk to it, so no authority went to it`,
  }),
  CALLER_NOT_AUTHORIZED: (p) => ({
    cause: "the custodian accepts this request only from another surface (the operator's, or the implementer's)",
    fix: `run operator commands with \`${operator(p).cli}\` ${operator(p).where}; the implementer's commands from the implementer's own account`,
  }),
  INTERACTIVE_TERMINAL_REQUIRED: () => ({
    cause: "operator records are confirmed only by a person typing the confirmation at a terminal",
    fix: "run the command yourself in an interactive terminal (stdin and stdout a terminal); no flag skips the confirmation",
  }),
  OPERATOR_CODE_UNTRUSTED: () => ({
    cause: "on a Linux host with the custodian, operator commands run only from the approved engine runtime through the root-owned wrapper",
    fix: "run the command as `/usr/local/sbin/code-parley-operator <command>` (the absolute path, not through PATH or an alias)",
  }),
  LOOP_NOT_AUTHORIZED: (p) => ({
    cause: "the operator has not granted a loop for this repository, or the grant is used up, expired, or was suspended by a restart of the OS",
    fix: `the operator grants loops with \`${operator(p).cli} setup --repo <path>\` (or \`loop allow --repo <path>\`) ${operator(p).where}; \`code-parley status --repo <path>\` shows the grants`,
  }),
  LOOP_START_UNRECONCILED: () => ({
    cause: "a loop start's answer was lost, so it is not known whether a loop was started",
    fix: "stop that loop (`code-parley loop stop <run>`) and start a new run",
  }),
  CONFIG_NOT_HELD: (p) => ({
    cause: "the custodian holds no protected configuration for this repository (never set, or revoked)",
    fix: `the operator sets it with \`${operator(p).cli} setup --repo <path>\` ${operator(p).where}`,
  }),
  CONFIG_LAPSED: (p) => ({
    cause: "the operator's records lapse when the custodian recovers after a restart of the OS (and after a rollback): they must be confirmed again",
    fix: `the operator re-confirms them with \`${operator(p).cli} setup --resume --repo <path>\` ${operator(p).where}; \`code-parley status --repo <path>\` lists what lapsed`,
  }),
  ISOLATION_NOT_ACCEPTED: (p) => ({
    cause: "no Codex isolation basis is confirmed for this Codex version and backend (an S1 self-test confirmation, or for a delegated fix the FIX self-test confirmation)",
    fix: p === "linux"
      ? "the implementer runs `code-parley codex selftest` (or `codex fix-selftest`) and `code-parley config propose-selftest [--fix] --repo <path> --out <file>`; the operator confirms it with `/usr/local/sbin/code-parley-operator setup [--fix] --repo <path> --proposal-file <file>`"
      : `the implementer runs \`code-parley codex selftest\` (or \`codex fix-selftest\`); the operator confirms it with \`code-parley setup [--fix] --repo <path>\` ${operator(p).where}`,
  }),
  CONFIG_MISMATCH: (p) => ({
    cause: "what is installed no longer matches what the operator approved (the Codex installation or the engine runtime changed, for example after an update or an upgrade)",
    fix: `approve the new one: the operator runs \`${operator(p).cli} setup --repo <path>\` ${operator(p).where} (a re-confirmation refused this way is not retried: setup sets the configuration again, with its own confirmation${p === "linux" ? ", from the implementer's `config propose` file" : ""}); after a Codex update the implementer first runs \`code-parley codex selftest\`${p === "linux" ? " and `config propose` / `config propose-selftest`" : ""}`,
  }),
  STALE_CONFIG: () => ({
    cause: "the configuration changed between the rendering you saw and its confirmation, so the confirmation covered something that is no longer current",
    fix: "run the same command again: it renders the current configuration for a new confirmation",
  }),
  RUNTIME_NOT_APPROVED: (p) => ({
    cause: "no engine runtime is approved for the custodian's helper (none yet, or it was revoked), or the one named cannot be approved (the message says why)",
    fix: p === "linux"
      ? "the operator runs `/usr/local/sbin/code-parley-operator setup --repo <path>` (it approves the versioned directory /opt/codeparley/engine/current names, with /usr/bin/git)"
      : "the operator runs `code-parley setup --repo <path> --runtime-git-path <installed git.exe>` in an elevated terminal (the runtime is the installed engine directory)",
  }),
  HELPER_UNAVAILABLE: (p) => ({
    cause: "the custodian's helper, which measures and captures protected runs, is not installed, not enabled or could not start",
    fix: p === "linux" ? `reinstall or repair with ${installer(p, "upgrade", { release: true })}` : "an administrator runs `CodeParley.Custodian.exe install-helper` (or the product installer's upgrade) and restarts the CodeParleyCustodian service",
  }),
  REPOSITORY_NOT_READABLE: (p) => ({
    cause: "the custodian's helper cannot read this repository: it has no repository-readers grant",
    fix: `an administrator runs ${installer(p, "grant-repository", { path: true })}`,
  }),
  CODEX_ISOLATION_UNAVAILABLE: (p) => ({
    cause: "Codex's sandbox could not be confirmed for this review (the stored self-test failed or is missing, the operator's confirmation covers another stored self-test than the current one, or on Linux its basis changed or it lapsed with the boot)",
    fix: p === "linux"
      ? "`code-parley status --repo <path>` (as the implementer) names which; the implementer runs `code-parley codex selftest` if the record is missing, then `code-parley config propose-selftest --repo <path> --out <file>`; the operator confirms it with `/usr/local/sbin/code-parley-operator setup --resume --repo <path> --proposal-file <file>`"
      : "`code-parley status --repo <path>` names which; the implementer runs `code-parley codex selftest` in an interactive desktop session if the record is missing or failed, and the operator confirms the stored one with `code-parley setup --resume --repo <path> --home <the implementer's data home>` in an elevated terminal",
  }),
  CODEX_INSTALLATION_UNSUPPORTED: () => ({
    cause: "the Codex installation named for protected reviews is not a form the custodian can measure (a launcher, a script or a link instead of the native executable)",
    fix: "name the native Codex executable (`code-parley doctor` shows the one it resolves) and set the configuration again",
  }),
  CHECK_NOT_APPROVED: () => ({
    cause: "the repository's check definitions are not approved (or changed since they were approved)",
    fix: "the implementer reviews and approves them: `code-parley checks list --repo <path>`, then `code-parley checks approve --repo <path> --from-proposals`",
  }),
  NO_CHECKS_CONFIGURED: () => ({
    cause: "the repository has no approved checks",
    fix: "propose checks in the repository's .code-parley/config.json and approve them with `code-parley checks approve --repo <path> --from-proposals`",
  }),
  SCOPE_NOT_CONFIGURED: () => ({
    cause: "no allowed roots are configured, so CodeParley may act on no repository",
    fix: "run `code-parley init --repo <path>` (it adds the repository to config.json's allowed_roots), then restart the Claude Code session",
  }),
  SCOPE_REPO_ROOT_OUTSIDE_ALLOWED: () => ({
    cause: "the repository is not under any allowed root",
    fix: "run `code-parley init --repo <path>`, then restart the Claude Code session",
  }),
  FIX_DELEGATION_UNAVAILABLE: (p) => ({
    cause: "a delegated fix needs a protected run through the validated custodian, a protected configuration in force, a fix budget (budgets.max_fixes_per_run > 0) and the operator's FIX self-test confirmation",
    fix: `\`code-parley status --repo <path>\` shows which is missing; the budget is set with \`code-parley init --repo <path> --max-fixes <n>\` (a new run picks it up), the confirmation with \`${operator(p).cli} setup --fix --repo <path>\``,
  }),
  STORE_VERSION_UNSUPPORTED: (p) => ({
    cause: "a store was written by a newer CodeParley than this one",
    fix: `install the matching release (${installer(p, "upgrade", { release: true })}) instead of running an older build against it`,
  }),
  CODEX_NOT_FOUND: () => ({
    cause: "no Codex CLI was found",
    fix: "install Codex, or name it with config.json `codex.executable`; `code-parley doctor` shows what it resolves",
  }),
  CODEX_UNSUPPORTED_VERSION: () => ({
    cause: "the installed Codex version is not one CodeParley supports",
    fix: "install a supported Codex version; `code-parley doctor` shows the version found",
  }),
  AUTHORIZATION_EXPIRED: () => ({
    cause: "the rendered record was not confirmed in time",
    fix: "run the command again and confirm the new rendering",
  }),
  CONFIRMATION_EXPIRED: (p) => ({
    cause: "the operator's confirmation of a delegated fix expired before it was applied",
    fix: `the operator confirms it again: \`${operator(p).cli} fix confirm <run> <proposal> --repo <path>\` ${operator(p).where}`,
  }),
};

/** The codes the catalog covers (the tested table). */
export const REMEDY_CODES: readonly ErrorCode[] = Object.keys(CATALOG) as ErrorCode[];

/** An unavailable custodian whose message shows the OS refused this account the OPERATOR endpoint (the pipe's or socket's
 * access list): the service is there, this account may not use that surface (VERIFIED on the Windows VM: "Access to the
 * path is denied" on the operator pipe). Only the wording changes; the refusal stays fail-closed. */
function operatorEndpointDenied(code: string, message: string | undefined): boolean {
  return code === "CUSTODIAN_UNAVAILABLE" && message !== undefined && /operator/i.test(message) && /access (to the path )?is denied|EACCES|permission denied/i.test(message);
}

/** The cause and fix for a refusal code on this platform, or null when the catalog has none. The error's message may
 * select a more precise remedy of the same code; it is never quoted. */
export function remedyFor(code: string, platform: NodeJS.Platform = process.platform, message?: string): Remedy | null {
  if (operatorEndpointDenied(code, message)) {
    const r = CATALOG.CALLER_NOT_AUTHORIZED!(platformOf(platform));
    return { cause: "the custodian is running, but this account may not connect to its operator endpoint: operator commands are the operator's", fix: r.fix };
  }
  const e = (CATALOG as Record<string, Entry | undefined>)[code];
  return e ? e(platformOf(platform)) : null;
}

/** The two lines the CLI prints under an error. */
export function remedyLines(code: string, platform: NodeJS.Platform = process.platform, message?: string): string[] {
  const r = remedyFor(code, platform, message);
  return r ? [`  cause: ${r.cause}`, `  fix:   ${r.fix}`] : [];
}
