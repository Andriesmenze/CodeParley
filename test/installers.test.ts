// Phase 6 Increment 2 (contract §6.1, §6.3, §6.4, §8 A-5): the product installers. They change machine state, so they
// run only on the native VMs (the acceptance gate); here they are parsed by their own interpreters and held to the same
// verbs, the same manifest check and the lifecycle rules' fixed points.

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const ps1 = join(root, "installer", "windows", "codeparley-installer.ps1");
const sh = join(root, "installer", "linux", "codeparley-installer.sh");
const win = readFileSync(ps1, "utf8");
const lin = readFileSync(sh, "utf8");
const VERBS = ["install", "upgrade", "rollback", "uninstall", "purge", "grant-repository", "revoke-repository", "status"];

describe("Phase 6 §6: the product installers", () => {
  it.runIf(process.platform === "win32")("the Windows installer parses under Windows PowerShell 5.1 (the target's own shell)", () => {
    const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('${ps1.replace(/'/g, "''")}',[ref]$t,[ref]$e);if($e){$e|%{$_.Extent.StartLineNumber.ToString()+': '+$_.Message};exit 1}`], { encoding: "utf8", windowsHide: true });
    expect(r.stdout + r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it.runIf(process.platform !== "win32")("the Linux installer parses under bash", () => {
    const r = spawnSync("bash", ["-n", sh], { encoding: "utf8" });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it("both offer the same verbs", () => {
    expect(/ValidateSet\(([^)]*)\)/.exec(win)![1]!.match(/'[^']+'/g)!.map((v) => v.slice(1, -1))).toEqual(VERBS);
    for (const v of VERBS) expect(lin).toMatch(new RegExp(`^  ${v}\\) do_`, "m"));
  });

  it("A-5: both check an artifact's size and SHA-256 against the manifest, and the BUILD-ID inside, before installing it", () => {
    expect(win).toMatch(/Get-FileHash -Algorithm SHA256/);
    expect(win).toMatch(/the manifest says \$\(\$e\.sha256\); nothing was installed/);
    expect(win).toMatch(/the BUILD-ID inside .* does not match the manifest/);
    expect(lin).toMatch(/sha256sum --strict -c --quiet/);
    expect(lin).toMatch(/does not have the SHA-256 the manifest says; nothing was installed/);
    expect(lin).toMatch(/the BUILD-ID inside \$1 does not match the manifest/);
  });

  it("L-2/L-4: an upgrade backs the store up before it migrates, with the backup's hash, and keeps the last two backups", () => {
    for (const s of [win, lin]) {
      expect(s.indexOf("store-upgrade', '--backup-sha256'") >= 0 || s.indexOf("store-upgrade --backup-sha256") >= 0).toBe(true);
      expect(s).toMatch(/last two/);
    }
    expect(win.indexOf("New-Backup $record")).toBeLessThan(win.indexOf("'store-upgrade', '--backup-sha256'"));
    expect(lin.indexOf('sha=$(new_backup "$cur")')).toBeLessThan(lin.indexOf("store-upgrade --backup-sha256"));
    expect(lin).toMatch(/as_custodian "\$\(custodian_of "\$version"\)" store-upgrade/); // as the custodian's account
  });

  it("L-5/L-6: a rollback restores only a backup whose hash matches, to the build that matches it, and writes the restore marker", () => {
    expect(win).toMatch(/it is never restored/);
    expect(lin).toMatch(/it is never restored/);
    expect(win).toMatch(/restore-marker\.json/);
    expect(lin).toMatch(/MARKER=\$ETC\/restore-marker\.json/);
    for (const s of [win, lin]) expect(s).toMatch(/session\.json/); // any build recovers the restored store
  });

  it("rollback refuses an incompatible target before touching the store: the backup's store format must be the one the previous build serves; a script-installed build only with -AllowLegacyRollback", () => {
    for (const s of [win, lin]) expect(s).toMatch(/not a compatible rollback target; nothing was changed/);
    expect(win).toMatch(/storeFormat = \$format/);
    expect(lin).toMatch(/\\"storeFormat\\":\$2/);
    expect(win).toMatch(/if \(-not \$AllowLegacyRollback\) \{ Fail /);
    // The checks come before the store's contents are removed.
    expect(win.indexOf("not a compatible rollback target")).toBeLessThan(win.indexOf("Get-ChildItem -LiteralPath $Store -Force"));
    expect(lin.indexOf("not a compatible rollback target")).toBeLessThan(lin.indexOf('find "$STORE" -mindepth 1 -delete'));
  });

  it("Linux: install admits the store's own filesystem (the custodian's host check) and checks every tool it needs first; a fresh store's backup records the format it will be served at", () => {
    expect(lin).toMatch(/admit_filesystem "\$STORE" "\$version"/);
    expect(lin.indexOf("for t in findmnt dumpe2fs setfacl")).toBeLessThan(lin.indexOf('unpack "$cust"'));
    expect(lin).toMatch(/o\["format"\] or o\["serves"\]/);
    expect(lin).toMatch(/as_custodian\(\) \{ runuser -u "\$CUST" -- \/bin\/sh -c 'umask 0027; exec "\$@"'/); // the service's umask
    expect(win).toMatch(/\$null -ne \$before\.format\) \{ \[int\]\$before\.format \} else \{ \[int\]\$before\.serves \}/);
  });

  it("Linux: an upgrade's cleanup never removes the `current` link; a start clears earlier failed (rate-limited) units", () => {
    expect(lin).toMatch(/\[ -L "\$\{v%\/\}" \] && continue/);
    expect(lin.indexOf("systemctl reset-failed")).toBeLessThan(lin.indexOf('systemctl start "${SOCKETS[@]}"'));
  });

  it("both installers put the code-parley command in an administrator-owned place, follow upgrades and rollbacks, and remove it", () => {
    expect(win).toMatch(/function Set-Cli/);
    expect(win.match(/Set-Cli \$record/g)!.length).toBeGreaterThanOrEqual(3); // install, upgrade, rollback
    expect(win).toMatch(/GetEnvironmentVariable\('Path', 'Machine'\)/);
    expect(win).toMatch(/Remove-Cli\n\s+# The directories this installer recorded/);
    expect(lin).toMatch(/operator\/code-parley" \/usr\/local\/bin\/code-parley/);
    expect(lin).toMatch(/rm -f [^\n]*\/usr\/local\/bin\/code-parley/);
  });

  it("Linux: both services run the installed build through the current link (the helper's unit too, found by the first real protected check)", () => {
    expect(lin).toMatch(/current\/codeparley-custodian#" \/etc\/systemd\/system\/codeparley-custodian\.service/);
    expect(lin).toMatch(/current\/codeparley-custodian helper#" \/etc\/systemd\/system\/codeparley-helper@\.service/);
  });

  it("Windows: the custodian gets read-attributes (nothing more) along the repository's path; revoke and purge remove them", () => {
    expect(win).toMatch(/function Get-WalkedPaths/);
    expect(win).toMatch(/\$d -eq \$full\) \{ '\(RA,RC\)' \} else \{ '\(RA\)' \}/);
    expect(win.match(/Remove-WalkGrant \$r/g)!.length).toBe(2);
    expect(win).toMatch(/\$parent -ieq \$users/); // the profile itself is never changed
  });

  it("Windows: backup, rollback and purge reach the locked review exports in backup mode; a failed backup brings the service back", () => {
    expect(win).toMatch(/robocopy\.exe @arguments \/B/);
    expect(win).toMatch(/Invoke-Robocopy @\(\$Store, \$staging/);
    expect(win.match(/Clear-Locked \(Join-Path \$Store 'exports'\)/g)!.length).toBe(2);
    expect(win).toMatch(/Start-Service \$CustodianService -ErrorAction SilentlyContinue\n\s+Fail "the store backup failed/);
  });

  it("Windows: an install after an uninstall keeps the kept store, backups and grants on the record", () => {
    expect(win).toMatch(/\$kept -and \$kept\.version/);
    expect(win).toMatch(/\$record\.repositories = @\(\$kept\.repositories\)/);
  });

  it("L-8/L-9: uninstall keeps the store, the backups and the grants and names how to remove them; purge needs the store named", () => {
    expect(win).toMatch(/Kept \(each removed by/);
    expect(lin).toMatch(/Kept \(each removed by/);
    expect(win).toMatch(/\$ConfirmStore -ne \$Store/);
    expect(lin).toMatch(/\[ "\$CONFIRM" = "\$STORE" \]/);
  });

  it("§3.3 (TD 2026-10-29): the Windows custodian starts automatically, not delayed, with bounded restarts; the helper is demand-started; the installer never approves a runtime", () => {
    expect(win).toMatch(/sc\.exe config \$CustodianService start= auto /);
    expect(win).not.toMatch(/delayed-auto/);
    expect(win).toMatch(/actions= restart\/10000\/restart\/60000\/\/0/);
    for (const s of [win, lin]) expect(s).not.toMatch(/\bconfig approve-runtime\b[^\n]*operatorIo|\bprepare_config_record\b/);
  });
});

/** The body of a shell function of the Linux installer: from `<name>() {` to its closing `}` line. */
function body(name: string): string {
  const at = lin.indexOf(`\n${name}() {`);
  expect(at, name).toBeGreaterThan(0);
  const end = lin.indexOf("\n}\n", at);
  return lin.slice(at, end + 2);
}

// Node.js migration (D-98, plan amendment A): an official Node.js 25 or later Linux build needs libatomic.so.1, which a
// minimal Ubuntu 24.04 lacks. The installer reads what the bundled node needs from the verified archive, before any state
// changes, and refuses when a library is missing; after unpacking, the node must start (as the helper, with an empty
// environment) and be the version its BUILD-ID names, before any service is stopped.
describe("Node.js runtime prerequisites (Linux installer)", () => {
  it("install and upgrade check the bundled node's libraries before any state changes, and its start before any service stops", () => {
    const install = body("do_install");
    expect(install.indexOf('check_runtime_libraries "$engine"')).toBeGreaterThan(install.indexOf('engine=$(artifact engine-runtime-linux-x64)'));
    expect(install.indexOf('check_runtime_libraries "$engine"')).toBeLessThan(install.indexOf("groupadd --system"));
    expect(install.indexOf('runtime_starts "$OPT/engine/$version" "$node"')).toBeGreaterThan(install.indexOf('unpack "$engine"'));
    expect(install.indexOf('runtime_starts "$OPT/engine/$version" "$node"')).toBeLessThan(install.indexOf("deploy_units"));
    expect(install.indexOf('runtime_starts "$OPT/engine/$version" "$node"')).toBeLessThan(install.indexOf('ln -sfn "$version" "$OPT/engine/current"'));
    const upgrade = body("do_upgrade").slice(body("do_upgrade").indexOf('cur=$(record_get version)'));
    expect(upgrade.indexOf('check_runtime_libraries "$engine"')).toBeGreaterThan(upgrade.indexOf('engine=$(artifact engine-runtime-linux-x64)'));
    expect(upgrade.indexOf('check_runtime_libraries "$engine"')).toBeLessThan(upgrade.indexOf('unpack "$cust"'));
    expect(upgrade.indexOf('runtime_starts "$OPT/engine/$version" "$node"')).toBeGreaterThan(upgrade.indexOf('unpack "$engine"'));
    expect(upgrade.indexOf('runtime_starts "$OPT/engine/$version" "$node"')).toBeLessThan(upgrade.indexOf("stop_all"));
    const rollback = body("do_rollback");
    expect(rollback.indexOf('runtime_starts "$OPT/engine/$prev" "$pnode"')).toBeGreaterThan(0);
    expect(rollback.indexOf('runtime_starts "$OPT/engine/$prev" "$pnode"')).toBeLessThan(rollback.indexOf("stop_all"));
    // The installer never installs a package (no package-manager command runs); it names the one to install.
    expect(lin).not.toMatch(/^\s*(?:apt|apt-get|dpkg)\s/m);
    expect(body("check_runtime_libraries")).toMatch(/apt install libatomic1\)/);
    // The start check: the helper account, an empty environment, the BUILD-ID's version.
    expect(body("runtime_starts")).toMatch(/runuser -u "\$HELPER" -- env -i "\$1\/node" --version/);
    expect(body("manifest_node")).toMatch(/\["buildId"\]\["node"\]/);
  });

  /** A minimal ELF64 image whose dynamic section names `needed`. */
  function elf(needed: string[]): Buffer {
    const strtab = Buffer.from(`\0${needed.join("\0")}\0`, "latin1");
    const strOff = 176;
    const dynOff = 512;
    const vaddr = 0x400000;
    const entries: [number, number][] = [];
    let at = 1;
    for (const n of needed) { entries.push([1, at]); at += n.length + 1; }
    entries.push([5, vaddr + strOff], [0, 0]);
    const size = dynOff + entries.length * 16;
    const b = Buffer.alloc(size);
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(b, 0);
    b.writeUInt16LE(3, 0x10); // ET_DYN
    b.writeUInt16LE(0x3e, 0x12); // x86-64
    b.writeBigUInt64LE(64n, 0x20); // e_phoff
    b.writeUInt16LE(56, 0x36); // e_phentsize
    b.writeUInt16LE(2, 0x38); // e_phnum
    const ph = (i: number, type: number, offset: number, va: number, filesz: number) => {
      const o = 64 + i * 56;
      b.writeUInt32LE(type, o);
      b.writeBigUInt64LE(BigInt(offset), o + 8);
      b.writeBigUInt64LE(BigInt(va), o + 16);
      b.writeBigUInt64LE(BigInt(va), o + 24);
      b.writeBigUInt64LE(BigInt(filesz), o + 32);
      b.writeBigUInt64LE(BigInt(filesz), o + 40);
    };
    ph(0, 1, 0, vaddr, size); // PT_LOAD
    ph(1, 2, dynOff, vaddr + dynOff, entries.length * 16); // PT_DYNAMIC
    strtab.copy(b, strOff);
    entries.forEach(([tag, val], i) => {
      b.writeBigInt64LE(BigInt(tag), dynOff + i * 16);
      b.writeBigUInt64LE(BigInt(val), dynOff + i * 16 + 8);
    });
    return b;
  }

  const LIBC = "\tlibc.so.6 (libc6,x86-64, OS ABI: Linux 3.2.0) => /lib/x86_64-linux-gnu/libc.so.6\n\tlibstdc++.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libstdc++.so.6\n";
  const ATOMIC = "\tlibatomic.so.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libatomic.so.1\n";
  const linuxOnly = it.runIf(process.platform === "linux" && spawnSync("python3", ["--version"]).status === 0);

  /** Run the installer's check_runtime_libraries on an archive holding `files`, with `cache` as `ldconfig -p`. */
  function check(files: Record<string, Buffer>, cache: string): { status: number | null; err: string } {
    const dir = mkdtempSync(join(tmpdir(), "cp-rtlib-"));
    try {
      mkdirSync(join(dir, "tree"));
      for (const [name, data] of Object.entries(files)) writeFileSync(join(dir, "tree", name), data);
      expect(spawnSync("tar", ["-czf", join(dir, "engine.tar.gz"), "-C", join(dir, "tree"), "."]).status).toBe(0);
      writeFileSync(join(dir, "cache.txt"), `${Object.keys(files).length} libs found in cache \`/etc/ld.so.cache'\n${cache}`);
      const harness = [
        'die() { echo "codeparley-installer: $*" >&2; exit 1; }',
        `ldconfig() { cat '${join(dir, "cache.txt")}'; }`,
        body("check_runtime_libraries"),
        `check_runtime_libraries '${join(dir, "engine.tar.gz")}'`,
      ].join("\n");
      writeFileSync(join(dir, "h.sh"), `set -euo pipefail\n${harness}\n`);
      const r = spawnSync("bash", [join(dir, "h.sh")], { encoding: "utf8" });
      return { status: r.status, err: r.stderr };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  linuxOnly("a node that needs libatomic.so.1 is refused without it, naming the package, and accepted with it", () => {
    const node26 = elf(["libatomic.so.1", "libstdc++.so.6", "libc.so.6"]);
    const without = check({ node: node26 }, LIBC);
    expect(without.status).toBe(1);
    expect(without.err).toContain("the bundled Node.js needs libatomic.so.1, which is not installed (apt install libatomic1)");
    expect(without.err).toContain("nothing was changed");
    expect(check({ node: node26 }, LIBC + ATOMIC)).toEqual({ status: 0, err: "" });
  });

  linuxOnly("a node that does not need libatomic (a Node.js 24 build) is accepted without it", () => {
    expect(check({ node: elf(["libstdc++.so.6", "libc.so.6"]) }, LIBC)).toEqual({ status: 0, err: "" });
  });

  linuxOnly("an archive without a readable node image is refused, failing closed", () => {
    const none = check({ "not-node": elf(["libc.so.6"]) }, LIBC);
    expect(none.status).toBe(1);
    expect(none.err).toContain("cannot read the bundled Node.js's library needs");
    const notElf = check({ node: Buffer.from("#!/bin/sh\n") }, LIBC);
    expect(notElf.status).toBe(1);
    expect(notElf.err).toContain("nothing was changed");
  });
});
