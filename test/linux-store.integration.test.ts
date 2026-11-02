// The Linux data home and file-system rules (plan §1.13), on a real Linux file system: the data
// home is created private (0700), a looser one is tightened, one other users can write to is
// refused, and the statfs classification refuses file systems without POSIX semantics.

import { describe, it, expect, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensurePrivateDataHome } from "../src/engine/engine-env.js";
import { parseLaunchArgs } from "../src/config/launch-args.js";
import { makeLogger } from "../src/server/server.js";
import { classifyFsType, fsTypeOf } from "../src/workspace/fs-types.js";
import { linux } from "./helpers/git-fixture.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";

const dirs: string[] = [];
afterAll(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => undefined);
});
async function scratch(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "arl-linux-store-"));
  dirs.push(d);
  return d;
}
const modeOf = async (p: string) => (await stat(p)).mode & 0o777;

describe("file-system classification (statfs magic numbers)", () => {
  it("validates ext4 and tmpfs, refuses file systems without POSIX semantics, and reports others as unvalidated", () => {
    expect(classifyFsType(0xef53)).toMatchObject({ name: "ext2/ext3/ext4", status: "validated" });
    expect(classifyFsType(0x01021994).status).toBe("validated");
    for (const t of [0x01021997, 0x4d44, 0x2011bab0, 0x7366746e, 0x5346544e, 0x65735546, 0x517b, 0xff534d42, 0xfe534d42]) expect(classifyFsType(t).status, t.toString(16)).toBe("refused");
    expect(classifyFsType(0x9123683e)).toMatchObject({ name: "btrfs", status: "unvalidated" });
    expect(classifyFsType(0x12345678)).toMatchObject({ name: "unknown (0x12345678)", status: "unvalidated" });
    // statfs reports f_type as a signed 32-bit value on some platforms.
    expect(classifyFsType(0xff534d42 | 0).status).toBe("refused");
  });
});

describe.skipIf(!linux)("the Linux data home", () => {
  it("is created private (0700) and a looser private one is tightened", async () => {
    const base = await scratch();
    const home = join(base, "state", "code-parley");
    await ensurePrivateDataHome(home);
    expect(await modeOf(home)).toBe(0o700);
    await chmod(home, 0o750);
    await ensurePrivateDataHome(home);
    expect(await modeOf(home)).toBe(0o700);
  });

  it("the server log is private: the data home is made private before the log folder is created in it", async () => {
    const base = await scratch();
    const home = join(base, "state", "code-parley");
    const log = await makeLogger(parseLaunchArgs(["--home", home, "--config", join(base, "none.json")]), process.env);
    log("private log test");
    expect(await modeOf(home)).toBe(0o700);
    expect(await modeOf(join(home, "logs"))).toBe(0o700);
    const files = await readdir(join(home, "logs"));
    expect(files).toHaveLength(1);
    expect(await modeOf(join(home, "logs", files[0]!))).toBe(0o600);
  });

  // Ubuntu's default umask for regular users is 002 (user private groups). The suite pins 022
  // for its fixtures (test/global-setup.ts); the product must not depend on it.
  it("under Ubuntu's default umask 002, the CLI and the server create their data homes private; a group-writable one is refused", async () => {
    const dist = sharedCompiledSrc();
    expect(dist).not.toBeNull();
    if (!dist) return;
    const base = await scratch();
    const under002 = (args: string[]) => spawnSync("sh", ["-c", 'umask 002; exec "$0" "$@"', process.execPath, ...args], { encoding: "utf8", input: "", timeout: 60_000 });
    under002([join(dist, "cli", "main.js"), "doctor", "--home", join(base, "cli", "code-parley")]);
    expect(await modeOf(join(base, "cli", "code-parley"))).toBe(0o700);
    under002([join(dist, "server", "main.js"), "--home", join(base, "srv")]); // stdin closed: it starts and exits
    expect(await modeOf(join(base, "srv"))).toBe(0o700);
    expect(await modeOf(join(base, "srv", "logs"))).toBe(0o700);
    const logs = await readdir(join(base, "srv", "logs"));
    expect(logs).toHaveLength(1);
    expect(await modeOf(join(base, "srv", "logs", logs[0]!))).toBe(0o600);
    // A directory the user made under that umask (mkdir: 0775) is refused, with the remedy.
    const made = join(base, "made");
    await mkdir(made);
    await chmod(made, 0o775);
    const r = under002([join(dist, "cli", "main.js"), "doctor", "--home", made]);
    expect(`${r.stdout}${r.stderr}`).toMatch(/writable by other users \(mode 775\); run `chmod 700/);
  });

  it("refuses a data home other users can write to, and one that is not a directory", async () => {
    const base = await scratch();
    const open = join(base, "open");
    await ensurePrivateDataHome(open);
    await chmod(open, 0o777);
    await expect(ensurePrivateDataHome(open)).rejects.toMatchObject({ code: "CONFIG_INVALID", message: expect.stringMatching(/writable by other users/) });
    expect(await modeOf(open)).toBe(0o777); // reported, not silently "fixed"
    const file = join(base, "file");
    await writeFile(file, "x");
    await expect(ensurePrivateDataHome(file)).rejects.toMatchObject({ code: "CONFIG_INVALID", message: expect.stringMatching(/not a directory/) });
  });

  it("knows the file system of a path that does not exist yet (its nearest existing ancestor)", async () => {
    const base = await scratch();
    const t = await fsTypeOf(join(base, "not", "yet", "here"));
    expect(t).not.toBeNull();
    expect(t!.status).not.toBe("refused");
  });

  it.skipIf(!existsSync("/mnt/c/Windows"))("refuses a data home on a Windows drive mounted by WSL (drvfs, 9p)", async () => {
    await expect(ensurePrivateDataHome("/mnt/c/Windows/Temp/arl-never-created/code-parley")).rejects.toMatchObject({ code: "CONFIG_INVALID", message: expect.stringMatching(/9p/) });
    expect(existsSync("/mnt/c/Windows/Temp/arl-never-created")).toBe(false);
  });
});
