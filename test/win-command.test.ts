import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, rm, writeFile, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveCommand, buildInvocation, escapeBatchArgument, displayCommandLine } from "../src/process/win-command.js";

let root: string;
let binA: string;
let binB: string;
let repo: string;

beforeAll(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), "arl-wincmd-")));
  binA = join(root, "binA");
  binB = join(root, "binB");
  repo = join(root, "repo");
  for (const d of [binA, binB, repo, join(repo, "scripts")]) await mkdir(d, { recursive: true });
  await writeFile(join(binA, "tool.cmd"), "@echo a\r\n");
  await writeFile(join(binB, "tool.exe"), "MZ");
  await writeFile(join(binB, "other.exe"), "MZ");
  await writeFile(join(binA, "script.ps1"), "");
  await writeFile(join(repo, "tool.exe"), "MZ"); // planted in the "cwd": must never be found by name
  await writeFile(join(repo, "scripts", "run.cmd"), "@echo r\r\n");
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

const opts = (pathValue: string, pathext = ".COM;.EXE;.BAT;.CMD") => ({ relativeBase: repo, pathValue, pathext });

const win = process.platform === "win32";

describe.skipIf(!win)("resolveCommand (plan §14.3, M1.3-3)", () => {
  it("searches PATH directory-major: the first directory with any PATHEXT match wins", () => {
    const r = resolveCommand("tool", opts(`${binA};${binB}`));
    expect(r.ok && r.command.path).toBe(join(binA, "tool.cmd"));
    expect(r.ok && r.command.kind).toBe("batch");
    const r2 = resolveCommand("tool", opts(`${binB};${binA}`));
    expect(r2.ok && r2.command.kind).toBe("native");
  });

  it("never searches the working directory or relative PATH entries", () => {
    // `tool.exe` exists in the repository (a check's cwd); a bare name must not find it.
    const r = resolveCommand("tool", opts(`.;repo;${binA}`));
    expect(r.ok && r.command.path).toBe(join(binA, "tool.cmd"));
    expect(resolveCommand("tool", opts("")).ok).toBe(false);
  });

  it("strips quotes around PATH entries", () => {
    const r = resolveCommand("other", opts(`"${binB}"`));
    expect(r.ok && r.command.path).toBe(join(binB, "other.exe"));
  });

  it("resolves repository-relative argv[0] against the repository root", () => {
    const r = resolveCommand("scripts/run", opts(""));
    expect(r.ok && r.command.path).toBe(join(repo, "scripts", "run.cmd"));
    expect(r.ok && r.command.how).toBe("relative");
  });

  it("accepts absolute paths and refuses drive-relative / root-relative ones", () => {
    expect(resolveCommand(join(binB, "other.exe"), opts("")).ok).toBe(true);
    expect(resolveCommand("C:tool.exe", opts("")).ok).toBe(false);
    expect(resolveCommand("\\tool.exe", opts("")).ok).toBe(false);
  });

  it("refuses unsupported executable types (shell use must be explicit)", () => {
    const r = resolveCommand(join(binA, "script.ps1"), opts("", ".PS1;.EXE"));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/unsupported executable type/);
  });

  it("refuses quotes and control characters in argv[0]", () => {
    expect(resolveCommand('to"ol', opts(binA)).ok).toBe(false);
    expect(resolveCommand("to\nol", opts(binA)).ok).toBe(false);
  });

  it("records size and mtime (part of check_spec_id)", () => {
    const r = resolveCommand("tool", opts(binA));
    expect(r.ok && r.command.size).toBeGreaterThan(0);
    expect(r.ok && typeof r.command.mtimeMs).toBe("number");
  });
});

describe("buildInvocation / escaping (N2)", () => {
  const native = { path: "C:\\x\\a.exe", kind: "native" as const, how: "absolute" as const, size: 1, mtimeMs: 1 };
  const batch = { path: "C:\\dir (x86) & co\\a.cmd", kind: "batch" as const, how: "absolute" as const, size: 1, mtimeMs: 1 };

  it("spawns native executables directly with the argv unchanged", () => {
    const inv = buildInvocation(native, ["a b", 'q"x', ""]);
    expect(inv).toEqual({ file: "C:\\x\\a.exe", args: ["a b", 'q"x', ""], windowsVerbatimArguments: false });
  });

  it("runs batch files through an explicit cmd.exe /d /v:off /s /c with verbatim arguments", () => {
    const inv = buildInvocation(batch, ["x"], "C:\\Windows");
    expect(inv.file).toBe("C:\\Windows\\System32\\cmd.exe");
    expect(inv.args.slice(0, 4)).toEqual(["/d", "/v:off", "/s", "/c"]);
    expect(inv.args[4]).toBe(`""C:\\dir (x86) & co\\a.cmd" ${escapeBatchArgument("x")}"`);
    expect(inv.windowsVerbatimArguments).toBe(true);
  });

  it("double caret-escapes every metacharacter after MSVCRT quoting", () => {
    expect(escapeBatchArgument("a&b")).toBe('^^^"a^^^&b^^^"');
    expect(escapeBatchArgument('q"x')).toBe('^^^"q\\^^^"x^^^"');
    expect(escapeBatchArgument("tail\\")).toBe('^^^"tail\\\\^^^"');
    expect(escapeBatchArgument("")).toBe('^^^"^^^"');
    expect(escapeBatchArgument("%PATH%")).toBe('^^^"^^^%PATH^^^%^^^"');
  });

  it("refuses arguments a batch file cannot receive faithfully", () => {
    expect(() => buildInvocation(batch, ["a\nb"])).toThrow(/line break/);
    expect(() => buildInvocation(batch, ["a\0b"])).toThrow(/NUL/);
    expect(() => buildInvocation(native, ["a\0b"])).toThrow(/NUL/);
    expect(() => buildInvocation({ ...batch, path: "C:\\100%\\a.cmd" }, [])).toThrow(/safely/);
    expect(() => buildInvocation(batch, ["x".repeat(9000)])).toThrow(/8191/);
  });

  it("allows line breaks for native executables (no cmd.exe parse)", () => {
    expect(buildInvocation(native, ["a\nb"]).args).toEqual(["a\nb"]);
  });

  it("displays argv unambiguously", () => {
    expect(displayCommandLine(["npm", "run", "a b", 'q"'])).toBe('npm run "a b" "q\\""');
  });
});
