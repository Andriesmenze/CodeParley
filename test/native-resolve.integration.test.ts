import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { codexLinuxCandidates, codexVendorCandidates, isElfExecutable, resolveNativeExecutable } from "../src/process/native-resolve.js";

const win = process.platform === "win32";
const linux = process.platform === "linux";

describe.skipIf(!win)("resolveNativeExecutable (Windows)", () => {
  it("resolves git to a native git.exe on PATH", async () => {
    const r = await resolveNativeExecutable("git");
    expect(r.ok).toBe(true);
    expect(r.path?.toLowerCase().endsWith("git.exe")).toBe(true);
    expect(r.how).toContain("path");
  });

  it("resolves node to a native node.exe on PATH", async () => {
    const r = await resolveNativeExecutable("node");
    expect(r.ok).toBe(true);
    expect(r.path?.toLowerCase().endsWith("node.exe")).toBe(true);
  });

  it("reports an error for a non-existent tool", async () => {
    const r = await resolveNativeExecutable("definitely-not-a-real-exe-xyz");
    expect(r.ok).toBe(false);
  });

  describe("shim handling", () => {
    let dir: string;
    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "arl-shim-"));
      await writeFile(join(dir, "foo.cmd"), "@echo off\n"); // a shim
      await mkdir(join(dir, "vendor", "bin"), { recursive: true });
      await writeFile(join(dir, "vendor", "bin", "foo.exe"), "MZ"); // a fake native exe
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });

    it("resolves a configured shim to its vendored native exe when candidates point to it", async () => {
      const r = await resolveNativeExecutable("foo", {
        configured: join(dir, "foo.cmd"),
        refuseShim: true,
        shimVendorCandidates: (shimDir) => [join(shimDir, "vendor", "bin", "foo.exe")],
      });
      expect(r.ok).toBe(true);
      expect(r.how).toBe("configured-shim-resolved");
      expect(r.path?.toLowerCase().endsWith("foo.exe")).toBe(true);
    });

    it("refuses a configured shim when no native exe can be found and refuseShim is set", async () => {
      const r = await resolveNativeExecutable("foo", {
        configured: join(dir, "foo.cmd"),
        refuseShim: true,
        shimVendorCandidates: () => [],
      });
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/shim/);
    });
  });
});

describe.skipIf(!linux)("resolveNativeExecutable (Linux)", () => {
  it("resolves git and node to native ELF executables on PATH", async () => {
    for (const name of ["git", "node"]) {
      const r = await resolveNativeExecutable(name);
      expect(r.ok).toBe(true);
      expect(r.how).toBe("path-native");
      expect(isElfExecutable(r.path!)).toBe(true);
    }
  });

  it("reports an error for a non-existent tool", async () => {
    const r = await resolveNativeExecutable("definitely-not-a-real-exe-xyz");
    expect(r.ok).toBe(false);
  });

  describe("launcher handling", () => {
    let dir: string;
    // npm layout: <prefix>/bin/foo -> ../lib/node_modules/foo/bin/foo.js (a Node launcher), with the
    // real ELF binary vendored inside the package.
    const launcher = () => join(dir, "lib", "node_modules", "foo", "bin", "foo.js");
    const elf = () => join(dir, "lib", "node_modules", "foo", "vendor", "foo");
    const bin = () => join(dir, "bin");
    const vendored = (launcherDir: string) => [join(launcherDir, "..", "vendor", "foo")];
    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "arl-launcher-"));
      await mkdir(dirname(launcher()), { recursive: true });
      await mkdir(dirname(elf()), { recursive: true });
      await mkdir(bin(), { recursive: true });
      await writeFile(launcher(), "#!/usr/bin/env node\n", { mode: 0o755 });
      await writeFile(elf(), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), { mode: 0o755 });
      await symlink(join("..", "lib", "node_modules", "foo", "bin", "foo.js"), join(bin(), "foo"));
      await writeFile(join(bin(), "noexec"), Buffer.from([0x7f, 0x45, 0x4c, 0x46]), { mode: 0o644 });
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });

    it("maps a configured launcher (through its npm bin symlink) to the vendored ELF binary", async () => {
      const r = await resolveNativeExecutable("foo", { configured: join(bin(), "foo"), refuseShim: true, shimVendorCandidates: vendored });
      expect(r).toMatchObject({ ok: true, how: "configured-shim-resolved", path: elf() });
    });

    it("refuses a configured launcher without a vendored ELF binary when a native executable is required", async () => {
      const r = await resolveNativeExecutable("foo", { configured: join(bin(), "foo"), refuseShim: true, shimVendorCandidates: () => [] });
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/shim/);
      // A vendored candidate that is not ELF is no better than none.
      const notElf = await resolveNativeExecutable("foo", { configured: join(bin(), "foo"), refuseShim: true, shimVendorCandidates: () => [launcher()] });
      expect(notElf.ok).toBe(false);
    });

    it("searches only absolute, executable PATH entries and maps a launcher found there", async () => {
      const env = { PATH: `.:relative/bin:${bin()}` };
      const r = await resolveNativeExecutable("foo", { env, refuseShim: true, shimVendorCandidates: vendored });
      expect(r).toMatchObject({ ok: true, how: "path-shim-resolved", path: elf() });
      // A file without the execute bit is not a PATH hit.
      expect((await resolveNativeExecutable("noexec", { env })).ok).toBe(false);
      // A relative PATH entry is never searched, even when it names the same directory from the current one.
      expect((await resolveNativeExecutable("foo", { env: { PATH: relative(process.cwd(), bin()) }, shimVendorCandidates: vendored })).ok).toBe(false);
    });

    it("knows the npm @openai/codex 0.160 layout (nested platform package)", async () => {
      const pkg = join(dir, "codex-prefix", "lib", "node_modules", "@openai", "codex");
      const nativeCodex = join(pkg, "node_modules", "@openai", "codex-linux-x64", "vendor", "x86_64-unknown-linux-musl", "bin", "codex");
      await mkdir(join(pkg, "bin"), { recursive: true });
      await mkdir(dirname(nativeCodex), { recursive: true });
      await writeFile(join(pkg, "bin", "codex.js"), "#!/usr/bin/env node\n", { mode: 0o755 });
      await writeFile(nativeCodex, Buffer.from([0x7f, 0x45, 0x4c, 0x46]), { mode: 0o755 });
      const prefixBin = join(dir, "codex-prefix", "bin");
      await mkdir(prefixBin, { recursive: true });
      await symlink(join("..", "lib", "node_modules", "@openai", "codex", "bin", "codex.js"), join(prefixBin, "codex"));
      expect(codexLinuxCandidates(join(pkg, "bin"))).toContain(nativeCodex);
      const r = await resolveNativeExecutable("codex", { env: { PATH: prefixBin }, refuseShim: true, shimVendorCandidates: codexVendorCandidates });
      expect(r).toMatchObject({ ok: true, how: "path-shim-resolved", path: nativeCodex });
    });
  });
});
