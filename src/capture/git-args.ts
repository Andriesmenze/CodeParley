// Allowlist for git queries against the SOURCE repository (plan §9.2, CG1/CG2, MR-A).
//
// Capture never asks git to read working-tree file *content*. Clean/smudge/process
// filters, textconv and external diff drivers only run when git converts between the
// working tree and the object database (status, worktree diff, add, checkout,
// hash-object, cat-file --filters/--textconv). None of those are allowed here, so no
// query can run a filter — whichever driver `.gitattributes` or git config selects, and
// however they change during a capture. That is the MR-A guarantee; the per-call
// neutralization in git-query.ts is defence in depth on top of it.
//
// `status` (listed in plan §9.2) is deliberately NOT allowed: change detection compares
// raw bytes with base blobs instead (the §9.4 "MR-A route"). `ls-tree` is added: it
// reads tree objects only and replaces `diff-tree` for listing base trees. `rev-list` is
// allowed only as `rev-list --max-parents=0 HEAD` (M1.3: the root commit that keys trusted
// project configuration, R-35); it walks commit objects only. Anything not listed here
// throws before a process is spawned.

export type GitSubcommand =
  | "version"
  | "rev-parse"
  | "symbolic-ref"
  | "config"
  | "ls-files"
  | "ls-tree"
  | "check-attr"
  | "cat-file"
  | "merge-base"
  | "rev-list";

const HEX_OID = /^[0-9a-f]{40}$|^[0-9a-f]{64}$/;

/** A revision expression we accept from a trusted caller after ref validation. */
const SAFE_REV = /^[A-Za-z0-9._/@{}~^-]+$/;

const GIT_ATTRS = new Set(["filter", "working-tree-encoding", "text", "eol", "crlf", "diff", "binary"]);

interface Rule {
  /** Flags allowed exactly as given. */
  flags: ReadonlySet<string>;
  /** Validates a positional (non-flag) argument; return false to refuse. */
  positional?: (arg: string, prev: string | undefined) => boolean;
  /** Flags that take the next argument as a value, validated by the function. */
  valued?: Readonly<Record<string, (v: string) => boolean>>;
}

const CONFIG_KEY_PATTERN = /^[\^$()|.*\\a-z0-9_?+\[\]-]+$/i;

const RULES: Readonly<Record<GitSubcommand, Rule>> = {
  version: { flags: new Set() },
  "rev-parse": {
    flags: new Set([
      "--show-toplevel",
      "--absolute-git-dir",
      "--git-common-dir",
      "--path-format=absolute",
      "--is-inside-work-tree",
      "--is-bare-repository",
      "--is-shallow-repository",
      "--show-object-format",
      "--verify",
      "--quiet",
      "-q",
      "--end-of-options",
    ]),
    valued: { "--git-path": (v) => /^[A-Za-z_][A-Za-z0-9_./-]*$/.test(v) && !v.includes("..") },
    positional: (a, prev) => (prev === "--end-of-options" || a === "HEAD" || HEX_OID.test(a) || /\^\{commit\}$/.test(a)) && SAFE_REV.test(a) && !a.startsWith("-"),
  },
  "symbolic-ref": { flags: new Set(["-q", "--quiet"]), positional: (a) => a === "HEAD" },
  config: {
    // read flags only: no --add/--unset/--replace-all/--edit/--file/--blob/subcommands
    flags: new Set(["-z", "--null", "--show-scope"]),
    valued: {
      "--get": (v) => CONFIG_KEY_PATTERN.test(v),
      "--get-regexp": (v) => CONFIG_KEY_PATTERN.test(v),
    },
  },
  "ls-files": {
    // Index and directory listing only. Refused: -m/--modified, -d/--deleted, --eol,
    // -k/--killed, --recurse-submodules, --format (worktree eol info reads content).
    flags: new Set(["-z", "--cached", "--others", "--ignored", "--exclude-standard", "--stage", "-v", "--full-name", "--"]),
  },
  "ls-tree": {
    flags: new Set(["-r", "-z", "-l", "--long", "--full-tree"]),
    positional: (a) => HEX_OID.test(a),
  },
  "check-attr": {
    flags: new Set(["-z", "--stdin"]),
    positional: (a) => GIT_ATTRS.has(a),
  },
  "cat-file": {
    // Raw object bytes only. Refused: --filters, --textconv, --follow-symlinks, -p, ...
    flags: new Set(["--batch", "--batch-check"]),
  },
  "merge-base": { flags: new Set(), positional: (a) => HEX_OID.test(a) },
  "rev-list": { flags: new Set(["--max-parents=0"]), positional: (a) => a === "HEAD" },
};

export class GitArgumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitArgumentError";
  }
}

export function isAllowedSubcommand(sub: string): sub is GitSubcommand {
  return Object.prototype.hasOwnProperty.call(RULES, sub);
}

/** Throw GitArgumentError unless `sub args` is an allowed read-only query. */
export function validateGitArgs(sub: string, args: readonly string[]): asserts sub is GitSubcommand {
  if (!isAllowedSubcommand(sub)) throw new GitArgumentError(`git subcommand not allowed during capture: ${sub}`);
  const rule = RULES[sub];
  let prev: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (rule.valued && Object.prototype.hasOwnProperty.call(rule.valued, a)) {
      const v = args[++i];
      if (v === undefined || !rule.valued[a]!(v)) throw new GitArgumentError(`git ${sub}: bad value for ${a}: ${String(v)}`);
      prev = v;
      continue;
    }
    if (rule.flags.has(a)) {
      prev = a;
      continue;
    }
    if (rule.positional && !a.startsWith("-") && rule.positional(a, prev)) {
      prev = a;
      continue;
    }
    throw new GitArgumentError(`git ${sub}: argument not allowed during capture: ${a}`);
  }
}

/** Is `s` a full object id (SHA-1 or SHA-256, lowercase hex)? */
export function isHexOid(s: string): boolean {
  return HEX_OID.test(s);
}
