// LV-WIN-PROC (check part) on the real machine, and its Linux counterpart: argv fidelity for
// native executables, both npm shim styles and the real npm.cmd (Windows), "#!" scripts, PATH
// rules and the real npm (Linux); bounded execution (timeouts, tree kill, descendant sweep,
// stdio held by a descendant, output caps); cancellation; non-zero exits. Platform-independent
// cases are a shared contract.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { prepareCheck, executeCheck, type PreparedCheck } from "../src/checks/runner.js";
import { normalizeCheckDefinition, checkDefinitionDigest } from "../src/checks/project-config.js";
import { describeKind, printable, resolveCommand, type ResolvedCommand } from "../src/process/command.js";
import { snapshotProcessTable, findDescendants } from "../src/process/proc-table.js";
import { killTree } from "../src/process/kill-tree.js";
import { pidAlive } from "../src/store/owner.js";
import { linux, supported, win } from "./helpers/git-fixture.js";

const npm = supported ? resolveCommand("npm", { relativeBase: process.cwd(), pathValue: process.env["PATH"], pathext: process.env["PATHEXT"] }) : null;
const haveNpmCmd = win && !!npm && npm.ok && npm.command.kind === "batch";
const haveNpmScript = linux && !!npm && npm.ok && npm.command.kind === "script";
const repoRootDir = join(dirname(fileURLToPath(import.meta.url)), "..");

// Hostile arguments: every cmd metacharacter, quotes, backslashes, %, !, ^, empty,
// leading/trailing spaces, tab, non-ASCII.
export const HOSTILE_ARGS = [
  "plain", "with space", 'quo"te', "amp&x", "pipe|y", "lt<gt>", "caret^z", "pct%PATH%pct", "%%", "bang!x!",
  "paren(1)", "semi;colon", "comma,c", "back\\slash\\", 'bs\\"q', "", "\u00fcn\u00efc\u00f8d\u00e9\u20ac\u4e2d", "tab\tx", "=eq",
  "a&&b||c", "^", "%~dp0", "!PATH!", '"', "\\\\server\\share\\", "*?", "%1", "%*", "  lead and trail  ", "-flag=--x",
];

let dir: string;
let echoJs: string;
let fx: string;
/** Linux: a directory with spaces, parentheses and "&" holding "#!" scripts. */
const scriptsDir = () => join(dir, "scripts (x86) & co");

async function waitFor(fn: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return fn();
}

/** The grandchild recorded by spawn-gc.js: "<pid> <spawned at, epoch ms>". */
async function readGc(pidFile: string): Promise<{ pid: number; at: number }> {
  const [pid, at] = (await readFile(pidFile, "utf8")).trim().split(" ").map(Number);
  return { pid: pid!, at: at! };
}

/**
 * Is that grandchild still running? Identity is PID plus creation time (the product's rule,
 * 2 s tolerance): under a busy parallel suite Windows can hand a freed PID to a new process
 * within milliseconds, so a PID-only probe can report a killed grandchild as alive (M1.6).
 * (`pidAlive` is the product's: on Linux a zombie is not alive.)
 */
async function gcAlive(gc: { pid: number; at: number }): Promise<boolean> {
  if (!pidAlive(gc.pid)) return false;
  const t = await snapshotProcessTable();
  if (!t) return true; // cannot tell: treat as alive
  return t.some((e) => e.pid === gc.pid && Math.abs(e.createdMs - gc.at) <= 2000);
}

async function prep(def: unknown, name = "c"): Promise<PreparedCheck> {
  const n = normalizeCheckDefinition(def);
  if (!n.ok) throw new Error(n.problems.join("; "));
  const p = await prepareCheck(name, n.def, checkDefinitionDigest(name, n.def), { repoRoot: dir, sourceEnv: process.env });
  if (!p.ok) throw new Error(p.error);
  return p.check;
}

beforeAll(async () => {
  if (!supported) return;
  dir = await realpath(await mkdtemp(join(tmpdir(), "arl-chkproc-")));
  fx = join(dir, "fixtures");
  await mkdir(fx, { recursive: true });
  echoJs = join(fx, "echo.js");
  await writeFile(echoJs, "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n");
  if (win) {
    await mkdir(join(dir, "shims (x86) & co", "node_modules", ".bin"), { recursive: true });
    // npm.cmd style shim: forwards %* on a plain line.
    await writeFile(join(dir, "shims (x86) & co", "npmstyle.cmd"), ["@ECHO OFF", "SETLOCAL", `SET "NODE_EXE=${process.execPath}"`, `"%NODE_EXE%" "${echoJs}" %*`, ""].join("\r\n"));
    // cmd-shim style (node_modules\.bin), generated from the real template installed in this repo.
    const tpl = readFileSync(join(repoRootDir, "node_modules", ".bin", "tsc.cmd"), "utf8");
    const shim = tpl.replace(/"%dp0%\\[^"]*\\tsc"/, `"${echoJs}"`);
    if (shim === tpl) throw new Error("unexpected cmd-shim template");
    await writeFile(join(dir, "shims (x86) & co", "node_modules", ".bin", "shimstyle.cmd"), shim);
  }
  if (linux) {
    await mkdir(scriptsDir(), { recursive: true });
    // A "#!" script run by node itself, and a /bin/sh script forwarding "$@".
    await writeFile(join(scriptsDir(), "echo-node"), `#!${process.execPath}\nprocess.stdout.write(JSON.stringify(process.argv.slice(2)));\n`, { mode: 0o755 });
    await writeFile(join(scriptsDir(), "fwd.sh"), `#!/bin/sh\nexec "${process.execPath}" "${echoJs}" "$@"\n`, { mode: 0o755 });
    // A planted file of the same name in the repository root, and two files that must be refused.
    await writeFile(join(dir, "fwd.sh"), "#!/bin/sh\necho PLANTED\n", { mode: 0o755 });
    await writeFile(join(dir, "noshebang"), "echo implicit shell\n", { mode: 0o755 });
    await writeFile(join(dir, "noexec.sh"), "#!/bin/sh\necho hi\n", { mode: 0o644 });
    await chmod(join(dir, "noexec.sh"), 0o644);
  }

  await writeFile(
    join(fx, "spawn-gc.js"),
    [
      "const { spawn } = require('node:child_process');",
      "const fs = require('node:fs');",
      "const [pidFile, mode] = process.argv.slice(2);",
      "const gc = spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 120000)'], { detached: true, stdio: mode === 'inherit' ? 'inherit' : 'ignore', windowsHide: true });",
      "fs.writeFileSync(pidFile, gc.pid + ' ' + Date.now());",
      "if (mode !== 'inherit') gc.unref();",
      "if (mode === 'sleep') setTimeout(()=>{}, 120000); else process.exit(0);",
    ].join("\n"),
  );
  if (win) await writeFile(join(dir, "gc.cmd"), ["@ECHO OFF", `"${process.execPath}" "${join(fx, "spawn-gc.js")}" %*`, ""].join("\r\n"));
  // Linux: sh stays the parent of node (no exec), as cmd.exe does for a .cmd shim.
  if (linux) await writeFile(join(dir, "gc.sh"), `#!/bin/sh\n"${process.execPath}" "${join(fx, "spawn-gc.js")}" "$@"\n`, { mode: 0o755 });
  await writeFile(join(fx, "flood.js"), "const b = Buffer.alloc(1024*1024, 120); for (let i=0;i<30;i++) process.stdout.write(b); process.stderr.write('E'.repeat(5000)); process.stdout.write('\\nTAIL-MARKER');\n");
  await writeFile(join(fx, "exit.js"), "process.stderr.write('boom'); process.exit(Number(process.argv[2]));\n");
});

afterAll(async () => {
  if (supported) await rm(dir, { recursive: true, force: true }).catch(() => undefined);
});

describe("the approval display (repository-supplied names and #! lines)", () => {
  it("shows control characters escaped, so an escape sequence cannot rewrite what the user approves", () => {
    expect(printable("a\x1b[31mb\u009b\x7fc\td")).toBe("a\\x1b[31mb\\x9b\\x7fc\\x09d");
    expect(printable("plain ü/文")).toBe("plain ü/文");
    expect(describeKind({ path: "/r/t.sh", kind: "script", how: "absolute", size: 1, mtimeMs: 1, interpreter: "/bin/sh\x1b]0;x\x07" } as ResolvedCommand)).toBe("script, run by its interpreter (#!/bin/sh\\x1b]0;x\\x07)");
  });
});

describe.skipIf(!supported)("argv fidelity: native executables", () => {
  it("native executable: every hostile argument arrives byte-exact", async () => {
    const c = await prep({ argv: [process.execPath, echoJs, ...HOSTILE_ARGS] });
    expect(c.resolved.kind).toBe("native");
    const o = await executeCheck(c, { sweep: null });
    expect(o.status).toBe("passed");
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(HOSTILE_ARGS);
  });
});

describe.skipIf(!linux)("argv fidelity and resolution on Linux (plan §1.13)", () => {
  it("argv[0] with any control character (an escape sequence, a tab, DEL, C1) is refused", () => {
    for (const bad of ["to\x1b[2Kol", "to\tol", "to\x7fol", "to\u009bol"]) {
      const r = resolveCommand(bad, { relativeBase: dir, pathValue: scriptsDir() });
      expect(r.ok, JSON.stringify(bad)).toBe(false);
      expect(!r.ok && r.reason).toMatch(/control character/);
    }
  });

  it('a "#!" script in a directory with spaces, parentheses and "&": the kernel runs its interpreter; byte-exact', async () => {
    const c = await prep({ argv: [join(scriptsDir(), "echo-node"), ...HOSTILE_ARGS] });
    expect(c.resolved.kind).toBe("script");
    expect(c.invocation.file).toBe(join(scriptsDir(), "echo-node"));
    expect(c.invocation.args).toEqual(HOSTILE_ARGS);
    const o = await executeCheck(c, { sweep: null });
    expect(o.stderr.toString("utf8")).toBe("");
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(HOSTILE_ARGS);
  });

  it('a /bin/sh script forwarding "$@": byte-exact', async () => {
    const o = await executeCheck(await prep({ argv: [join(scriptsDir(), "fwd.sh"), ...HOSTILE_ARGS] }), { sweep: null });
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(HOSTILE_ARGS);
  });

  it("a bare name resolves through absolute PATH entries only, never to a file planted in the repository", async () => {
    // ".", an empty entry and a relative entry would all name the planted repository-root file from the check's cwd.
    const c = await prep({ argv: ["fwd.sh", "x y"], env: { PATH: `.::fixtures/..:${scriptsDir()}` } });
    expect(c.resolved.path).toBe(join(scriptsDir(), "fwd.sh"));
    const o = await executeCheck(c, { sweep: null });
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(["x y"]);
    // A path with a "/" names that file relative to the repository root, explicitly.
    expect((await prep({ argv: ["./fwd.sh"] })).resolved.path).toBe(join(dir, "fwd.sh"));
  });

  it('PATH search skips directories and non-executable files, but a hit with neither ELF header nor "#!" line stops it: refused, never passed over for a later entry', async () => {
    const asDir = join(dir, "path-dir");
    const noExec = join(dir, "path-noexec");
    const plain = join(dir, "path-plain");
    await mkdir(join(asDir, "fwd.sh"), { recursive: true });
    await mkdir(noExec, { recursive: true });
    await writeFile(join(noExec, "fwd.sh"), "#!/bin/sh\necho no\n", { mode: 0o644 });
    await mkdir(plain, { recursive: true });
    await writeFile(join(plain, "fwd.sh"), "echo would run under /bin/sh\n", { mode: 0o755 });
    const ok = resolveCommand("fwd.sh", { relativeBase: dir, pathValue: `${asDir}:${noExec}:${scriptsDir()}` });
    expect(ok.ok && ok.command.path).toBe(join(scriptsDir(), "fwd.sh"));
    // A shell's lookup would stop at the plain file and run it with /bin/sh; CodeParley stops there too, and refuses.
    const refused = resolveCommand("fwd.sh", { relativeBase: dir, pathValue: `${plain}:${scriptsDir()}` });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.reason).toMatch(/\/bin\/sh/);
  });

  it('an executable with neither an ELF header nor a "#!" line is refused (it would run under an implicit /bin/sh), and so is a file without the execute bit', async () => {
    for (const [argv0, reason] of [
      ["./noshebang", /\/bin\/sh/],
      ["./noexec.sh", /not executable/],
    ] as const) {
      const n = normalizeCheckDefinition({ argv: [argv0] });
      if (!n.ok) throw new Error(n.problems.join("; "));
      const p = await prepareCheck("c", n.def, "d", { repoRoot: dir, sourceEnv: process.env });
      expect(p.ok).toBe(false);
      if (!p.ok) expect(p.error).toMatch(reason);
    }
  });

  it.skipIf(!haveNpmScript)("the real npm: `npm --version` and `npm run <script> -- <hostile args>` end to end", async () => {
    const proj = join(dir, "npmproj");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { echo: `node "${echoJs}"` } }));
    const v = await executeCheck(await prep({ argv: ["npm", "--version"] }), { sweep: null });
    expect(v.status).toBe("passed");
    expect(v.stdout.toString("utf8").trim()).toMatch(/^\d+\.\d+\.\d+/);
    // npm quotes the arguments for its script shell (sh -c); the end-to-end result must still be exact.
    const c = await prep({ argv: ["npm", "run", "--silent", "echo", "--", ...HOSTILE_ARGS], cwd: "npmproj" });
    const o = await executeCheck(c, { sweep: null });
    expect(o.status).toBe("passed");
    expect(JSON.parse(o.stdout.toString("utf8").trim().split(/\r?\n/).pop()!)).toEqual(HOSTILE_ARGS);
  }, 60_000);
});

describe.skipIf(!win)("argv fidelity: Windows shims (LV-WIN-PROC, N2)", () => {
  it("npm.cmd-style batch shim in a directory with spaces, parentheses and '&': byte-exact", async () => {
    const c = await prep({ argv: [join(dir, "shims (x86) & co", "npmstyle.cmd"), ...HOSTILE_ARGS] });
    expect(c.resolved.kind).toBe("batch");
    expect(c.invocation.file.toLowerCase()).toMatch(/system32\\cmd\.exe$/);
    const o = await executeCheck(c, { sweep: null });
    expect(o.stderr.toString("utf8")).toBe("");
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(HOSTILE_ARGS);
  });

  it("node_modules\\.bin cmd-shim (real template): byte-exact", async () => {
    const c = await prep({ argv: [join(dir, "shims (x86) & co", "node_modules", ".bin", "shimstyle.cmd"), ...HOSTILE_ARGS] });
    const o = await executeCheck(c, { sweep: null });
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(HOSTILE_ARGS);
  });

  it("a bare name resolves through PATH and PATHEXT to the shim, never to a planted cwd file", async () => {
    await writeFile(join(dir, "npmstyle.exe"), "not really an exe");
    const c = await prep({ argv: ["npmstyle", "x y"], env: { PATH: join(dir, "shims (x86) & co") } });
    expect(c.resolved.path).toBe(join(dir, "shims (x86) & co", "npmstyle.cmd"));
    const o = await executeCheck(c, { sweep: null });
    expect(JSON.parse(o.stdout.toString("utf8"))).toEqual(["x y"]);
  });

  it.skipIf(!haveNpmCmd)("the real npm.cmd: `npm --version` and `npm run <script> -- <hostile args>` end to end", async () => {
    const proj = join(dir, "npmproj");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { echo: `node "${echoJs.replace(/\\/g, "/")}"` } }));
    const v = await executeCheck(await prep({ argv: ["npm", "--version"] }), { sweep: null });
    expect(v.status).toBe("passed");
    expect(v.stdout.toString("utf8").trim()).toMatch(/^\d+\.\d+\.\d+/);
    // npm re-quotes for its own script shell; the end-to-end result must still be exact.
    const args = HOSTILE_ARGS.filter((a) => !/[\t]/.test(a));
    const c = await prep({ argv: ["npm", "run", "--silent", "echo", "--", ...args], cwd: "npmproj" });
    const o = await executeCheck(c, { sweep: null });
    expect(o.status).toBe("passed");
    expect(JSON.parse(o.stdout.toString("utf8").trim().split(/\r?\n/).pop()!)).toEqual(args);
  }, 60_000);
});

describe.skipIf(!supported)("bounded execution", () => {
  it("non-zero exit codes are failures with the exit code recorded", async () => {
    for (const code of [1, 3, 255]) {
      const o = await executeCheck(await prep({ argv: [process.execPath, join(fx, "exit.js"), String(code)] }), { sweep: null });
      expect(o.status).toBe("failed");
      expect(o.exitCode).toBe(code);
      expect(o.stderrTail.toString()).toBe("boom");
    }
  });

  it("a missing executable is an error (never a shell fallback)", async () => {
    const n = normalizeCheckDefinition({ argv: ["definitely-not-a-command-xyz"] });
    if (!n.ok) throw new Error();
    const p = await prepareCheck("c", n.def, "d", { repoRoot: dir, sourceEnv: process.env });
    expect(p.ok).toBe(false);
  });

  it("output beyond the cap is drained and counted; the tail is the true end", async () => {
    const o = await executeCheck(await prep({ argv: [process.execPath, join(fx, "flood.js")] }), { sweep: null, streamCapBytes: 1024 * 1024 });
    expect(o.status).toBe("passed");
    expect(o.stdoutBytes).toBeGreaterThan(30 * 1024 * 1024);
    expect(o.stdout.length).toBe(1024 * 1024);
    expect(o.stdoutTruncated).toBe(true);
    expect(o.stdoutTail.toString("utf8").endsWith("TAIL-MARKER")).toBe(true);
    expect(o.stdoutTail.length).toBe(4096);
    expect(o.stderrBytes).toBe(5000);
    expect(o.stderrTruncated).toBe(false);
  }, 60_000);

  it("timeout kills the whole tree, including a detached grandchild (Windows: taskkill /T; Linux: session, group and parent links)", async () => {
    const pidFile = join(dir, "gc-timeout.pid");
    const o = await executeCheck(await prep({ argv: [process.execPath, join(fx, "spawn-gc.js"), pidFile, "sleep"] }), { sweep: null, wallMsOverride: 2500 });
    expect(o.status).toBe("timed_out");
    const gc = await readGc(pidFile);
    expect(await waitFor(async () => !(await gcAlive(gc)), 5000)).toBe(true);
  }, 30_000);

  it("timeout through a shim (Windows: cmd.exe -> node -> grandchild; Linux: sh -> node -> grandchild in a new session) kills the tree", async () => {
    const pidFile = join(dir, "gc-cmd.pid");
    const o = await executeCheck(await prep({ argv: [join(dir, win ? "gc.cmd" : "gc.sh"), pidFile, "sleep"] }), { sweep: null, wallMsOverride: 2500 });
    expect(o.status).toBe("timed_out");
    const gc = await readGc(pidFile);
    expect(await waitFor(async () => !(await gcAlive(gc)), 5000)).toBe(true);
  }, 30_000);

  // Linux: the grandchild left the session and its parent exited, so only the pipes it holds link it.
  it("a descendant holding the output pipes cannot hang the run; it is found and terminated", async () => {
    const pidFile = join(dir, "gc-inherit.pid");
    const started = Date.now();
    const o = await executeCheck(await prep({ argv: [process.execPath, join(fx, "spawn-gc.js"), pidFile, "inherit"] }), { exitGraceMs: 1500 });
    expect(Date.now() - started).toBeLessThan(20_000);
    expect(o.status).toBe("passed");
    expect(o.stdioHeldAfterExit).toBe(true);
    const gc = await readGc(pidFile);
    expect(o.descendants?.scanned).toBe(true);
    // Phase 6 flake P-e: on a failure, show what the sweep saw (was the table read; which descendants were linked).
    expect(o.descendants?.survivors.map((s) => s.pid), JSON.stringify({ descendants: o.descendants, grandchild: gc })).toContain(gc.pid);
    expect(o.descendants?.terminated).toBe(true);
    expect(await gcAlive(gc)).toBe(false);
  }, 40_000);

  it.skipIf(!win)("a detached grandchild left behind after a normal exit is swept", async () => {
    const pidFile = join(dir, "gc-left.pid");
    const o = await executeCheck(await prep({ argv: [process.execPath, join(fx, "spawn-gc.js"), pidFile, "exit"] }), {});
    expect(o.status).toBe("passed");
    const gc = await readGc(pidFile);
    // Phase 6 flake P-e: on a failure, show what the sweep saw (was the table read; which descendants were linked).
    expect(o.descendants?.survivors.map((s) => s.pid), JSON.stringify({ descendants: o.descendants, grandchild: gc })).toContain(gc.pid);
    expect(o.descendants?.terminated).toBe(true);
    expect(await waitFor(async () => !(await gcAlive(gc)), 3000)).toBe(true);
  }, 40_000);

  it.skipIf(!linux)("Linux: a grandchild that left the session, closed its output and lost its parent is reported unattributable, never killed", async () => {
    const pidFile = join(dir, "gc-left-linux.pid");
    const o = await executeCheck(await prep({ argv: [process.execPath, join(fx, "spawn-gc.js"), pidFile, "exit"] }), {});
    const gc = await readGc(pidFile);
    try {
      expect(o.status).toBe("passed");
      expect(o.descendants?.scanned).toBe(true);
      expect(o.descendants?.survivors.map((s) => s.pid)).not.toContain(gc.pid);
      expect(o.termination?.established).toBe(false);
      expect(o.termination?.unattributable.map((u) => u.pid)).toContain(gc.pid);
      expect(await gcAlive(gc)).toBe(true);
    } finally {
      process.kill(gc.pid, "SIGKILL");
    }
  }, 40_000);

  it("cancellation kills the tree and reports cancelled", async () => {
    const pidFile = join(dir, "gc-cancel.pid");
    const ac = new AbortController();
    const p = executeCheck(await prep({ argv: [process.execPath, join(fx, "spawn-gc.js"), pidFile, "sleep"] }), { sweep: null, signal: ac.signal });
    await waitFor(() => existsSync(pidFile), 10_000);
    ac.abort();
    const o = await p;
    expect(o.status).toBe("cancelled");
    const gc = await readGc(pidFile);
    expect(await waitFor(async () => !(await gcAlive(gc)), 5000)).toBe(true);
  }, 30_000);

  it("stdin is closed immediately (a check waiting on stdin ends instead of hanging)", async () => {
    const o = await executeCheck(await prep({ argv: [process.execPath, "-e", "process.stdin.resume(); process.stdin.on('end', () => { process.stdout.write('eof'); })"] }), { sweep: null, wallMsOverride: 10_000 });
    expect(o.status).toBe("passed");
    expect(o.stdout.toString()).toBe("eof");
  });

  it("the process table sees our own process tree (sanity for the sweep)", async () => {
    const t = await snapshotProcessTable();
    expect(t).not.toBeNull();
    const self = t!.find((e) => e.pid === process.pid);
    expect(self).toBeDefined();
    // PID-reuse guard: a "child" created before its parent is not linked.
    expect(findDescendants([{ pid: 10, ppid: 1, createdMs: 1000, name: "old" }], { pid: 1, startedAtMs: 50_000 })).toEqual([]);
    expect(findDescendants([{ pid: 10, ppid: 1, createdMs: 60_000, name: "new" }, { pid: 11, ppid: 10, createdMs: 61_000, name: "gc" }], { pid: 1, startedAtMs: 50_000 }).map((e) => e.pid)).toEqual([10, 11]);
    void killTree;
  });
});
