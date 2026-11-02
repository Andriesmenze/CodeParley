// Phase 5 G-OP (contract §4.5): on Linux the operator runs the CLI only through the root-owned wrapper
// /usr/local/sbin/code-parley-operator, which starts the approved engine runtime /opt/codeparley/engine/<build>/ with a
// cleared environment. Before any custodian contact an operator command checks, as defence in depth, that
//   - none of the variables the wrapper drops is present (NODE_OPTIONS, NODE_PATH, NODE_EXTRA_CA_CERTS, LD_*, GIT_*,
//     CODEPARLEY_*, npm_*): they could make the operator's own process run or load code the implementer chose;
//   - the CLI entry and the Node executable, both by realpath, lie under the approved runtime, and each of them and every
//     ancestor up to / is owned by root and neither group- nor other-writable.
// Anything else refuses OPERATOR_CODE_UNTRUSTED. This catches a mis-installed or copied tree (a copy run from an
// implementer-writable directory); it is not a security proof — the guarantee is the installation's DAC.

import { lstatSync, realpathSync } from "node:fs";
import { posix } from "node:path";
import { DomainError } from "../common/errors.js";

// Linux paths whatever the host (the rule is unit-tested on Windows too).
const { dirname, sep } = posix;

export const OPERATOR_RUNTIME_ROOT = "/opt/codeparley/engine";
export const OPERATOR_WRAPPER = "/usr/local/sbin/code-parley-operator";

/**
 * The operator commands: they use the custodian's operator surface. `repoNamed`: the command carries --repo, which is what
 * makes `runs stop` the operator's (it ends a run at the custodian alone); every other `runs` form stays the implementer's.
 */
export function isOperatorCommand(group: string | undefined, cmd: string | undefined, repoNamed = false): boolean {
  // Phase 5 F-3: `config propose` / `config propose-selftest` are the implementer's (it writes the payload it proposes).
  if (group === "config" && (cmd === "propose" || cmd === "propose-selftest")) return false;
  // Phase 6 Increment 3: `setup` runs the operator's config and loop commands.
  return group === "decide" || group === "amend" || group === "loop" || group === "config" || group === "setup" || (group === "fix" && (cmd === "confirm" || cmd === "reject")) || (group === "runs" && cmd === "stop" && repoNamed);
}

/** A variable the wrapper drops from the operator's environment. */
export function droppedVariable(name: string): boolean {
  return name === "NODE_OPTIONS" || name === "NODE_PATH" || name === "NODE_EXTRA_CA_CERTS" || /^(LD_|GIT_|CODEPARLEY_|npm_)/.test(name);
}

export interface PathFacts {
  /** null: does not exist / cannot be read. */
  lstat(p: string): { uid: number; mode: number; isSymbolicLink: boolean; isFile: boolean; isDirectory: boolean } | null;
  realpath(p: string): string | null;
}

const realFacts: PathFacts = {
  lstat(p) {
    try {
      const s = lstatSync(p);
      return { uid: s.uid, mode: s.mode, isSymbolicLink: s.isSymbolicLink(), isFile: s.isFile(), isDirectory: s.isDirectory() };
    } catch {
      return null;
    }
  },
  realpath(p) {
    try {
      return realpathSync.native(p);
    } catch {
      return null;
    }
  },
};

/** Why this operator process may not be trusted (null: it may). Pure given `facts`, so it is unit-tested. */
export function operatorCodeProblem(o: { env: NodeJS.ProcessEnv; entry: string | undefined; execPath: string; runtimeRoot?: string; facts?: PathFacts }): string | null {
  const facts = o.facts ?? realFacts;
  const root = o.runtimeRoot ?? OPERATOR_RUNTIME_ROOT;
  const dropped = Object.keys(o.env).filter((k) => o.env[k] !== undefined && droppedVariable(k)).sort();
  if (dropped.length) return `the environment contains ${dropped.join(", ")}, which the operator wrapper drops (run it through ${OPERATOR_WRAPPER})`;
  for (const [what, p] of [["the CLI", o.entry], ["Node", o.execPath]] as const) {
    if (!p) return `${what}'s path is unknown`;
    const real = facts.realpath(p);
    if (!real) return `${what} (${p}) cannot be resolved`;
    if (!real.startsWith(root + sep)) return `${what} (${real}) is not in the approved runtime ${root} (run it through ${OPERATOR_WRAPPER})`;
    const leaf = facts.lstat(real);
    if (!leaf || !leaf.isFile) return `${what} (${real}) is not a regular file`;
    for (let cur = real; ; cur = dirname(cur)) {
      const s = cur === real ? leaf : facts.lstat(cur);
      if (!s) return `${cur} cannot be read`;
      if (s.isSymbolicLink) return `${cur} is a symbolic link`;
      if (s.uid !== 0) return `${cur} is not owned by root (uid ${s.uid})`;
      if ((s.mode & 0o022) !== 0) return `${cur} is group- or other-writable`;
      if (cur === dirname(cur)) break;
    }
  }
  return null;
}

/** Refuse OPERATOR_CODE_UNTRUSTED unless this process is the approved operator runtime with a clean environment. */
export function assertOperatorCodeTrusted(env: NodeJS.ProcessEnv): void {
  const problem = operatorCodeProblem({ env, entry: process.argv[1], execPath: process.execPath });
  if (problem) throw new DomainError("OPERATOR_CODE_UNTRUSTED", `this operator command runs only from the approved CodeParley runtime: ${problem}. Nothing was sent to the custodian.`);
}

/**
 * Phase 5 G-OP (contract §4.5): on Linux an operator command names the repository by the absolute path of its root and
 * passes it to the custodian unchanged. The operator account is separate (D5-B) and cannot read the implementer's
 * home, so nothing is resolved locally (no realpath, no git): the custodian resolves the identity itself, refusing any
 * link, mount crossing or unprovisioned filesystem. Only a plain absolute path is accepted.
 */
export function linuxOperatorRepo(raw: string): string {
  const ok = raw.startsWith("/") && raw.length <= 4096 && !raw.includes("\0") && (raw === "/" || posix.normalize(raw) === raw) && !raw.endsWith("/");
  if (!ok) throw new DomainError("INVALID_ARGUMENT", `--repo must be the repository root's plain absolute path (no '.', '..', '//' or trailing '/'): the custodian resolves its identity itself (got ${JSON.stringify(raw.slice(0, 200))})`);
  return raw;
}
