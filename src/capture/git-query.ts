// Hardened git queries toward the SOURCE repository (plan §9.2, CG1–CG3, MR-A).
//
// Every call:
//  - is validated against the read-only allowlist in git-args.ts (no status/diff/add,
//    no --filters/--textconv): structurally, no query converts working-tree content, so
//    no clean/smudge/process filter, textconv or external diff can run (MR-A);
//  - disables fsmonitor, hooks (empty core.hooksPath), untracked-cache writes, pager,
//    colour, auto gc/maintenance, and every transport (protocol.allow=never);
//  - reads in-tree attributes from the EMPTY tree (`--attr-source`) — except check-attr,
//    which must report the real attributes — so even a query that consulted attributes
//    could not select a driver, whatever `.gitattributes` says at that moment;
//  - neutralizes every filter driver name seen so far (attributes or any config scope)
//    via GIT_CONFIG_COUNT/KEY/VALUE (an env pair cannot be mis-split the way
//    `-c filter.<name>.clean=` could be for a hostile driver name);
//  - runs with an explicit environment: GIT_OPTIONAL_LOCKS=0, GIT_NO_LAZY_FETCH=1,
//    GIT_TERMINAL_PROMPT=0, LC_ALL=C, and no inherited GIT_* variable at all.
// A `safe.directory` refusal surfaces as GIT_UNSAFE_DIRECTORY; the server never sets it.

import { DomainError } from "../common/errors.js";
import { runProcess, type RunResult } from "../process/spawn.js";
import { buildChildEnv } from "../process/env.js";
import { validateGitArgs, type GitSubcommand } from "./git-args.js";

export interface GitQueryOptions {
  gitExe: string;
  /** Canonical worktree root; every query runs with `-C <cwd>`. */
  cwd: string;
  /** An existing empty directory used as core.hooksPath. */
  emptyHooksDir: string;
  /**
   * TEST ONLY: extra environment (e.g. GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM pointing at
   * hostile fixture files). Production capture passes nothing here.
   */
  envOverrides?: Record<string, string>;
  signal?: AbortSignal;
  /** Observer for every spawned query (tests enumerate call sites with it). */
  onQuery?: (sub: GitSubcommand, args: readonly string[]) => void;
  /**
   * P3.4C-5 (Amendment A §A.4): the custodian helper's protected git configuration. No system configuration, a global
   * configuration file the custodian provides (empty, read-only), EXACTLY ONE `safe.directory` — the repository the
   * custodian validated (git trusts it across the owner difference; never `*`, a parent or a second path) — and the
   * repository-configured external execution a read-only query could otherwise reach neutralized per invocation.
   * Attended captures pass nothing here and are unchanged.
   */
  protectedConfig?: ProtectedGitConfig;
}

export interface ProtectedGitConfig {
  safeDirectory: string;
  globalConfig: string;
}

/**
 * The per-invocation `-c` overrides of the helper's git (§A.4): command scope beats every repository setting, so a
 * hostile `.git/config` cannot make a read-only query start a program — no editor, askpass, ssh command or credential
 * helper (transports are already refused by `protocol.allow=never`, the fsmonitor and hooks by FIXED_CONFIG).
 */
export const PROTECTED_HARDENING: readonly string[] = ["core.editor=false", "core.askPass=", "core.sshCommand=", "credential.helper=", "core.pager=cat"];

export interface QueryOptions {
  stdin?: string | Buffer;
  binary?: boolean;
  /** Exit codes treated as success (default [0]). */
  okCodes?: readonly number[];
  maxStdoutBytes?: number;
  wallMs?: number;
}

const FIXED_CONFIG: readonly string[] = [
  "core.fsmonitor=false",
  "core.untrackedCache=false",
  "core.quotepath=false",
  "color.ui=false",
  "gc.auto=0",
  "maintenance.auto=false",
  "protocol.allow=never",
  // Git for Windows: allow paths over MAX_PATH when listing the work tree (read-only effect).
  "core.longpaths=true",
];

export class GitQuery {
  private readonly neutralized = new Set<string>();
  private attrSourceTree: string | null = null;

  constructor(private readonly opts: GitQueryOptions) {}

  /** Neutralize these filter driver names in every later query (defence in depth). */
  neutralizeFilters(names: Iterable<string>): void {
    for (const n of names) if (n.length > 0 && !/[\0\n]/.test(n)) this.neutralized.add(n);
  }

  neutralizedFilters(): string[] {
    return [...this.neutralized].sort();
  }

  /** Read in-tree attributes from this (empty) tree in every query except check-attr. */
  setAttrSourceTree(oid: string): void {
    this.attrSourceTree = oid;
  }

  /** Build the full argv for a query (exposed for argv-invariant tests). */
  buildArgv(sub: GitSubcommand, args: readonly string[]): string[] {
    validateGitArgs(sub, args);
    const argv = ["--no-pager"];
    for (const kv of FIXED_CONFIG) argv.push("-c", kv);
    if (this.opts.protectedConfig) for (const kv of PROTECTED_HARDENING) argv.push("-c", kv);
    argv.push("-c", `core.hooksPath=${this.opts.emptyHooksDir}`);
    if (this.attrSourceTree && sub !== "check-attr") argv.push(`--attr-source=${this.attrSourceTree}`);
    argv.push("-C", this.opts.cwd, sub, ...args);
    return argv;
  }

  /** Build the explicit child environment (exposed for env-invariant tests). */
  buildEnv(): Record<string, string> {
    const extra: Record<string, string> = {
      GIT_OPTIONAL_LOCKS: "0",
      GIT_NO_LAZY_FETCH: "1",
      GIT_TERMINAL_PROMPT: "0",
      GCM_INTERACTIVE: "never",
      LC_ALL: "C",
    };
    const keys: [string, string][] = [];
    if (this.opts.protectedConfig) {
      if (!this.opts.protectedConfig.safeDirectory || this.opts.protectedConfig.safeDirectory.includes("*")) throw new DomainError("INTERNAL", "a protected git configuration trusts exactly one validated repository");
      extra["GIT_CONFIG_NOSYSTEM"] = "1";
      extra["GIT_CONFIG_GLOBAL"] = this.opts.protectedConfig.globalConfig;
      keys.push(["safe.directory", this.opts.protectedConfig.safeDirectory]);
    }
    for (const name of this.neutralized) {
      keys.push([`filter.${name}.clean`, ""], [`filter.${name}.smudge`, ""], [`filter.${name}.process`, ""], [`filter.${name}.required`, "false"]);
    }
    if (keys.length > 0) {
      extra["GIT_CONFIG_COUNT"] = String(keys.length);
      keys.forEach(([k, v], i) => {
        extra[`GIT_CONFIG_KEY_${i}`] = k;
        extra[`GIT_CONFIG_VALUE_${i}`] = v;
      });
    }
    // buildChildEnv copies only a Windows allowlist: no GIT_DIR, GIT_WORK_TREE,
    // GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY, GIT_CONFIG_PARAMETERS, GIT_EXTERNAL_DIFF,
    // GIT_PAGER, GIT_TRACE*, ... can be inherited (plan §9.2 "Environment").
    return buildChildEnv({ extra: { ...extra, ...(this.opts.envOverrides ?? {}) } }).env;
  }

  async run(sub: GitSubcommand, args: readonly string[], q: QueryOptions = {}): Promise<RunResult> {
    const argv = this.buildArgv(sub, args);
    this.opts.onQuery?.(sub, args);
    const r = await runProcess(this.opts.gitExe, argv, {
      env: this.buildEnv(),
      wallMs: q.wallMs ?? 120_000,
      ...(q.stdin !== undefined ? { stdin: q.stdin } : {}),
      ...(q.binary ? { stdoutMode: "buffer" as const } : {}),
      ...(q.maxStdoutBytes !== undefined ? { maxStdoutBytes: q.maxStdoutBytes } : {}),
      ...(this.opts.signal ? { signal: this.opts.signal } : {}),
    });
    if (r.spawnError) throw new DomainError("GIT_NOT_FOUND", `could not run git: ${r.spawnError}`, { details: { gitExe: this.opts.gitExe } });
    if (r.cancelled) throw new DomainError("INTERNAL", "capture cancelled", { details: { sub } });
    if (r.timedOut) throw new DomainError("INTERNAL", `git ${sub} timed out`, { retryable: true, details: { sub } });
    if (r.stdoutTruncated) throw new DomainError("INTERNAL", `git ${sub} output exceeded the capture limit`, { details: { sub } });
    const ok = q.okCodes ?? [0];
    if (r.status === null || !ok.includes(r.status)) {
      if (/dubious ownership|safe\.directory/i.test(r.stderr)) {
        throw new DomainError("GIT_UNSAFE_DIRECTORY", `git refused the repository (safe.directory): ${lastLine(r.stderr)}`, {
          details: { cwd: this.opts.cwd },
        });
      }
      throw new GitQueryFailed(sub, r);
    }
    return r;
  }

  async text(sub: GitSubcommand, args: readonly string[], q: QueryOptions = {}): Promise<string> {
    return (await this.run(sub, args, q)).stdout;
  }
}

/** A git query exited unexpectedly. Callers map specific cases to domain errors. */
export class GitQueryFailed extends DomainError {
  readonly status: number | null;
  readonly stderr: string;
  constructor(sub: string, r: RunResult) {
    super("INTERNAL", `git ${sub} failed (exit ${String(r.status)}): ${lastLine(r.stderr)}`, { details: { sub, status: r.status } });
    this.status = r.status;
    this.stderr = r.stderr;
  }
}

function lastLine(s: string): string {
  return s.trim().split(/\r?\n/).slice(-1)[0] ?? "";
}
