// Phase 5 G-OP (contract §4.5, NL-10 d/e): an operator command on Linux runs only from the approved, root-owned runtime
// with the wrapper's cleared environment; it refuses OPERATOR_CODE_UNTRUSTED before any custodian contact otherwise. The
// rule is pure over injected path facts; the real installation is exercised on the VM (NL-10).

import { describe, it, expect } from "vitest";
import { droppedVariable, isOperatorCommand, operatorCodeProblem, type PathFacts } from "../src/cli/operator-trust.js";

const ROOT = "/opt/codeparley/engine";
const ENTRY = `${ROOT}/b1/dist/cli/main.js`;
const NODE = `${ROOT}/b1/node/bin/node`;

/** A file system where everything listed is root-owned 0755 (dirs) / 0644 (files) unless overridden. */
function fs(over: Record<string, Partial<{ uid: number; mode: number; isSymbolicLink: boolean }>> = {}, links: Record<string, string> = {}): PathFacts {
  const files = new Set([ENTRY, NODE, "/home/cpimpl-l/copy/dist/cli/main.js"]);
  return {
    realpath: (p) => links[p] ?? p,
    lstat: (p) => {
      const isFile = files.has(p);
      return { uid: 0, mode: isFile ? 0o100644 : 0o40755, isSymbolicLink: false, isFile, isDirectory: !isFile, ...(over[p] ?? {}) };
    },
  };
}

const ok = { env: { PATH: "/usr/bin:/bin", HOME: "/home/cpop-l", LANG: "C.UTF-8", TERM: "xterm" }, entry: ENTRY, execPath: NODE };

describe("Phase 5 G-OP: the operator code check", () => {
  it("the approved root-owned runtime with the wrapper's environment is trusted", () => {
    expect(operatorCodeProblem({ ...ok, facts: fs() })).toBeNull();
  });

  it("(d) any variable the wrapper drops is refused, whatever its value", () => {
    for (const k of ["NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "LD_PRELOAD", "LD_LIBRARY_PATH", "GIT_DIR", "GIT_CONFIG_GLOBAL", "CODEPARLEY_HOME", "npm_config_prefix"]) {
      expect(droppedVariable(k), k).toBe(true);
      expect(operatorCodeProblem({ ...ok, env: { ...ok.env, [k]: "" }, facts: fs() }), k).toContain(k);
    }
    for (const k of ["PATH", "HOME", "LANG", "TERM", "NODE_ENV_X", "XGIT"]) expect(droppedVariable(k), k).toBe(false);
  });

  it("(e) a copied tree outside the runtime, or reached through a link into it, is judged by its real path", () => {
    expect(operatorCodeProblem({ ...ok, entry: "/home/cpimpl-l/copy/dist/cli/main.js", facts: fs() })).toContain("not in the approved runtime");
    expect(operatorCodeProblem({ ...ok, entry: "/home/cpimpl-l/link.js", facts: fs({}, { "/home/cpimpl-l/link.js": ENTRY }) })).toBeNull();
    expect(operatorCodeProblem({ ...ok, entry: `${ROOT}/b1/x.js`, facts: fs({}, { [`${ROOT}/b1/x.js`]: "/tmp/evil.js" }) })).toContain("not in the approved runtime");
    expect(operatorCodeProblem({ ...ok, entry: undefined, facts: fs() })).toContain("unknown");
    expect(operatorCodeProblem({ ...ok, facts: { ...fs(), realpath: () => null } })).toContain("cannot be resolved");
  });

  it("(b) a non-root owner or a group/other-writable file or ancestor anywhere up to / is refused", () => {
    for (const p of [ENTRY, `${ROOT}/b1/dist`, `${ROOT}/b1`, ROOT, "/opt/codeparley", "/opt", "/", NODE, `${ROOT}/b1/node/bin`]) {
      expect(operatorCodeProblem({ ...ok, facts: fs({ [p]: { uid: 1001 } }) }), p).toContain("not owned by root");
      const mode = p === ENTRY || p === NODE ? 0o100664 : 0o40775;
      expect(operatorCodeProblem({ ...ok, facts: fs({ [p]: { mode } }) }), p).toContain("writable");
      expect(operatorCodeProblem({ ...ok, facts: fs({ [p]: { mode: mode | 0o002 } }) }), p).toContain("writable");
    }
    expect(operatorCodeProblem({ ...ok, facts: fs({ [ENTRY]: { isSymbolicLink: true } }) })).toContain("symbolic link");
  });

  it("the operator commands are exactly those on the custodian's operator surface", () => {
    for (const [g, c] of [["decide", undefined], ["amend", "x"], ["loop", "allow"], ["loop", "grants"], ["config", "set"], ["fix", "confirm"], ["fix", "reject"]] as const) expect(isOperatorCommand(g, c), `${g} ${c}`).toBe(true);
    for (const [g, c] of [["fix", "show"], ["fix", "reconcile"], ["runs", "list"], ["checks", "approve"], ["doctor", undefined], ["codex", "selftest"], ["config", "propose"], ["config", "propose-selftest"]] as const) expect(isOperatorCommand(g, c), `${g} ${c}`).toBe(false);
    // TD, candidate 3: only `runs stop` with --repo is the operator's; the implementer keeps every other `runs` form.
    expect(isOperatorCommand("runs", "stop", true)).toBe(true);
    expect(isOperatorCommand("runs", "stop", false)).toBe(false);
    for (const c of ["list", "show", "purge", undefined]) expect(isOperatorCommand("runs", c, true), `runs ${c} --repo`).toBe(false);
  });
});

describe("Phase 5 G-OP: the Linux operator names the repository root (the custodian resolves it)", () => {
  it("a plain absolute path passes unchanged; anything relative, dotted, doubled or trailing is refused", async () => {
    const { linuxOperatorRepo } = await import("../src/cli/operator-trust.js");
    expect(linuxOperatorRepo("/home/cpimpl-l/nl/repo1")).toBe("/home/cpimpl-l/nl/repo1");
    for (const bad of ["repo", "./repo", "/home/a/../b", "/home/./a", "/home//a", "/home/a/", "", "/a\0b"]) expect(() => linuxOperatorRepo(bad), bad).toThrow(/plain absolute path/);
  });
});
