// Phase 6 Increment 2 (contract §6.1, §6.3, §6.4, §8 A-5): the product installers. They change machine state, so they
// run only on the native VMs (the acceptance gate); here they are parsed by their own interpreters and held to the same
// verbs, the same manifest check and the lifecycle rules' fixed points.

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
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
