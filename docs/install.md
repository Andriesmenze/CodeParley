# Installing CodeParley

CodeParley has two install routes:

| Route | What you install | What you get |
|---|---|---|
| [Protected](#windows-11-protected-install) | The installer, the custodian service, the engine runtime and the Claude Code plugin | Everything: manual review, the protected loop, optional delegated fixes |
| [Manual review](#manual-review-any-platform) | The npm tarball | Reviews, checks, discussion and your decisions, with no custodian |

Protected mode runs on two platforms only: Windows 11 x64, and Ubuntu 24.04 x86_64 with kernel 6.8.
Everywhere else, including WSL2, use manual review. Claude Code (CLI) is the only supported host for
protected mode; Claude Desktop is manual review only.

## The accounts

Protected mode separates who does the work from who approves it. These are real, separate OS
accounts.

| Role | Windows | Linux |
|---|---|---|
| **Implementer**: runs Claude Code, `init`, the checks and the self-tests | A standard user | An ordinary login, in no administrative group |
| **Operator**: confirms every protected record by typing | An administrator, in an elevated terminal | A separate login, through `/usr/local/sbin/code-parley-operator` |
| **Administrator**: runs the installer | Elevated PowerShell | `root` (`sudo`) |

On Windows the operator and the administrator may be the same person and account. The installer
never creates the human accounts: they must exist first.

## Get the release

Version 1.0.0 was released privately: no public binary release is available yet. The first public
binary release is planned as 1.0.1, on the
[releases page](https://github.com/vanderMerkProjects/CodeParley/releases). The 1.0.0 file names in
this guide match the version of these sources; they are examples, not downloads available now. When
1.0.1 is published, follow that release's signed manifest and use the artifact file names it lists.

A release's artifacts are:

| File | Used by |
|---|---|
| `release-manifest.json` and its detached signature | Everyone: verify these first |
| `codeparley-installer.ps1`, `custodian-windows-x64.tar.gz`, `engine-runtime-windows-x64.tar.gz`, `plugin-windows.tar.gz` | Windows protected install |
| `codeparley-installer.sh`, `custodian-linux-x64.tar.gz`, `engine-runtime-linux-x64.tar.gz`, `plugin-linux.tar.gz` | Linux protected install |
| `code-parley-1.0.0.tgz` | Manual review |

Put them in one directory; this document calls it `<dir>`. The installers bundle Node.js 24.22.2 in
the engine runtime and a self-contained .NET runtime in the custodian: the target needs no SDK or
Node.js.

## Verify a release

The owner signs `release-manifest.json` with a separate release key. The manifest lists each
artifact with its size and SHA-256. The installers check size, SHA-256 and BUILD-ID against the
manifest, but they do **not** check its signature. Verify the signature yourself, first, or those
checks prove nothing.

1. Check the signature against the release key's fingerprint, published in
   [verifying-releases.md](verifying-releases.md#the-release-key). Here the detached
   signature is `release-manifest.json.asc`; use the name the release gives it.

   ```bash
   gpg --import <release public key file>
   gpg --verify release-manifest.json.asc release-manifest.json
   ```

   Compare the `Primary key fingerprint` that `gpg` prints with the published fingerprint, character
   by character. `Good signature` alone only says that some key in your keyring signed the file.

2. Check each artifact against the manifest.

   Linux:

   ```bash
   python3 -I -c 'import json; [print(a["sha256"]+"  "+a["file"]) for a in json.load(open("release-manifest.json"))["artifacts"]]' \
     | sha256sum --strict -c -
   ```

   Windows (PowerShell, in `<dir>`):

   ```powershell
   $m = Get-Content release-manifest.json -Raw | ConvertFrom-Json
   foreach ($a in $m.artifacts) {
     $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $a.file).Hash.ToLowerInvariant()
     if ($h -ne $a.sha256) { throw "$($a.file) does not match the manifest" }
   }
   ```

   If you only downloaded one platform's files, the command stops at the first file you do not have;
   that is not a mismatch.

3. Check that `"releaseCandidate": true` is in the manifest. The installers warn when it is not.
   The flag means the manifest was built from a clean, signed commit; it does not mark a pre-release.
   The 1.0.0 manifest has it.

## Windows 11 protected install

### Windows prerequisites

- Windows 11 x64.
- An administrator account for the operator, and a separate standard user for the implementer.
- Git for Windows, installed machine-wide, 2.41 or later (2.45+ for partial clones). The engine
  runtime does not bundle it: the operator approves an installed `git.exe`.
- Codex CLI 0.160.x in an **administrator-controlled directory** outside the implementer's writable
  locations, for example under `C:\Program Files`, as the complete release layout. The implementer
  must be able to run it and only administrators to change it. The standalone Codex installer places
  it in a user profile, where the custodian cannot measure it: protected reviews refuse that. Use
  the native `codex.exe`, not a launcher or a link.
- Claude Code for the implementer, and Codex logged in for the implementer (`codex login`).
- The implementer works in a signed-in desktop session: Codex's `mxc` sandbox does not start from a
  service, PowerShell Direct or a scheduled batch logon.
- CodeParley's client talks to the custodian through Windows PowerShell 5.1 in FullLanguage mode. A
  Constrained Language, AppLocker or WDAC policy blocks it, and protected calls fail closed.

A repository may live under the implementer's profile, for example `C:\Users\you\src\app`.
`grant-repository` gives the helper read access to the repository, and gives the custodian service
read-attributes on the repository and on each folder between it and the profile, plus read-control on
the repository. Nothing on the profile folder itself changes, and `revoke-repository` removes these
entries.

### Install

In elevated PowerShell, as an administrator:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <dir>\codeparley-installer.ps1 install `
  -Release <dir> -Operator <MACHINE\admin> -Implementer <MACHINE\user>
```

This document writes that as `codeparley-installer.ps1 <verb>` from here on. The verbs are
`install`, `upgrade`, `rollback`, `uninstall`, `purge`, `grant-repository`, `revoke-repository` and
`status`.

The installer checks every artifact against the manifest, then installs:

| Item | Where |
|---|---|
| The custodian service | `CodeParleyCustodian`, automatic delayed start |
| The helper service | `CodeParleyHelper`, started by the custodian |
| Binaries and engine runtime | `C:\Program Files\CodeParley\custodian\<version>`, `...\engine\<version>` |
| The command | `C:\Program Files\CodeParley\bin\code-parley.cmd`, on the machine `PATH` |
| The protected store | `C:\ProgramData\CodeParley\Custodian` |
| The group | `CodeParley Repository Readers` |

Open a **new** terminal to see `code-parley` on the `PATH`.

### Set up a repository

Do this once per repository. `code-parley init` prints these steps with your paths filled in.

**1. The implementer** registers the repository, approves the checks and runs the self-test.
Pointing `codex.executable` in `config.json` at the administrator's Codex is simplest:
`%LOCALAPPDATA%\CodeParley\config.json`, `"codex": { "executable": "C:\\...\\codex.exe" }`.

```powershell
code-parley init --repo C:\src\app
code-parley checks list --repo C:\src\app
code-parley checks approve --repo C:\src\app --from-proposals --required-profile <profile>
code-parley codex selftest --codex <codex.exe>
```

`checks approve` needs checks to approve: either `proposed_checks` in the repository's
`.code-parley/config.json`, or a definitions file with `--file`
([README](../README.md#approving-checks)). It shows exactly what will run and asks you to type
`approve`. Restart open Claude Code sessions after `init`.

**2. An administrator** lets the helper read the repository:

```powershell
codeparley-installer.ps1 grant-repository -Path C:\src\app
```

**3. The operator**, in an elevated terminal, runs `setup`. Git refuses a repository another account
owns, so add it to the operator's own `safe.directory` first. `--home` names the implementer's data
home, where `setup` reads the approved checks and the stored self-test.

```powershell
git config --global --add safe.directory C:/src/app
code-parley setup --repo C:\src\app --home <implementer's %LOCALAPPDATA%\CodeParley> `
  --codex <codex.exe> `
  --runtime-git-path "C:\Program Files\Git\mingw64\bin\git.exe" `
  --loops 1 --minutes 60
```

`setup` walks through the records in order. For each one the custodian renders what will be recorded
and you type `confirm` (`allow` for the loop grant). Anything else stops there and records nothing
further; running `setup` again continues. Steps already in force are skipped. Without `--no-grant`
the last step grants automated loops: `--loops` 1 to 8 (default 1), `--minutes` 1 to 180 (default
60).

The first step, approving the engine runtime, takes a while: the custodian measures every file.

**4. The implementer** installs the plugin, once per account:

```powershell
New-Item -ItemType Directory <plugin dir>
tar -xzf <dir>\plugin-windows.tar.gz -C <plugin dir>
claude plugin marketplace add <plugin dir>
claude plugin install code-parley@code-parley-local --scope user
```

Keep `<plugin dir>`. Start a new Claude Code session.

**5. Check it:**

```powershell
code-parley status --repo C:\src\app
code-parley doctor --protected --repo C:\src\app
```

`status` exits 0 and says `READY` when the repository is set up. That is a display: it grants
nothing. Go on with [docs/protected-workflow.md](protected-workflow.md).

## Ubuntu 24.04 protected install

### Linux prerequisites

The custodian checks these at every start and refuses to serve if one fails:

- Ubuntu 24.04, kernel 6.8.x, x86_64. Not WSL.
- The default kernel hardening is in place: `kernel.yama.ptrace_scope` ≥ 1, `fs.protected_symlinks`
  and `fs.protected_hardlinks` = 1, `fs.protected_regular` and `fs.protected_fifos` ≥ 1,
  `kernel.apparmor_restrict_unprivileged_userns` = 1.
- The implementer is in none of the groups `sudo`, `admin`, `wheel`, `adm`, `lxd`, `docker`,
  `libvirt`, `disk`, `kvm`, `shadow`, `systemd-journal`.
- The operator is a different account from the implementer.
- `/proc` does not hide other users' processes from the custodian.

The installer and `grant-repository` also need:

- Root, and `python3`.
- The tools `findmnt`, `dumpe2fs`, `setfacl`, `getfacl`, `runuser`, `systemctl`, `systemd-tmpfiles`,
  `useradd`, `groupadd`, `usermod`. Most are there by default; for the rest: `sudo apt install acl
  e2fsprogs`.
- The store and each repository on the **root filesystem**, ext4 with `metadata_csum`, 256-byte
  inodes and birth time.
- An administrator-supplied Codex CLI 0.160.x: a directory with `bin/codex` and
  `codex-resources/bwrap`. The installer copies it root-owned to `/opt/codeparley-codex/<version>`.
- `/usr/bin/git`, 2.41 or later (2.45+ for partial clones). `setup` approves it by default.
- Claude Code for the implementer.

### Install

```bash
sudo bash codeparley-installer.sh install --release <dir> \
  --implementer <login> --operator <login> --codex <codex dir> --load-apparmor
```

`--load-apparmor` loads an AppArmor profile that lets Codex's copied `bwrap` use user namespaces. It
is a machine-wide change; read [what it grants](security.md#linux-sandbox-and-service-hardening)
first. Without it the profile is only staged at `/opt/codeparley/codeparley-codex-bwrap.profile`,
and the Codex self-test fails on this kernel configuration. The installer loads it only together
with `--codex`, at `install`.

The installer adds the implementer to `codeparley-impl` and `codeparley-read`, and the operator to
`codeparley-op` and `codeparley-read`. **Both must log in again** for the new groups to take effect.

| Item | Where |
|---|---|
| The custodian | `/opt/codeparley/custodian/<version>`, run by systemd as the account `codeparley` |
| The sockets | `codeparley-implementer.socket`, `codeparley-operator.socket`, `codeparley-helper.socket`, enabled at boot |
| The engine runtime | `/opt/codeparley/engine/<version>`, with a `current` link |
| The implementer's command | `/usr/local/bin/code-parley` |
| The operator's command | `/usr/local/sbin/code-parley-operator`. Always use this absolute path |
| The protected store | `/var/lib/codeparley` |
| Trusted configuration | `/etc/codeparley` |

### Set up a repository

Do this once per repository. `code-parley init` prints these steps with your paths filled in. The
examples use `CODEX=/opt/codeparley-codex/0.160.0/bin/codex` and a repository at
`/home/impl/src/app`.

**1. The implementer** logs Codex in, registers the repository, approves the checks and runs the
self-test. The installer keeps Codex off the `PATH`, so name it, or set `codex.executable` in
`~/.config/code-parley/config.json`.

```bash
$CODEX login
code-parley init --repo /home/impl/src/app
code-parley checks list --repo /home/impl/src/app
code-parley checks approve --repo /home/impl/src/app --from-proposals --required-profile <profile>
code-parley codex selftest --codex $CODEX
```

Restart open Claude Code sessions after `init`. The operator cannot read your data home or the
repository, so you write what it will confirm into proposal files. Use a new file name each time, in
a directory the operator can read:

```bash
install -d -m 0755 /tmp/cp-proposals
code-parley config propose --repo /home/impl/src/app --out /tmp/cp-proposals/repo.json --codex $CODEX
code-parley config propose-selftest --repo /home/impl/src/app --out /tmp/cp-proposals/s1.json --codex $CODEX
```

The files hold check definitions and digests, no secrets, and every local user can read them while
they exist. The custodian validates them and measures Codex itself, so a proposal is only a claim
until the operator confirms the rendering.

**2. An administrator** grants read access and restarts the custodian, which admits the repository's
filesystem:

```bash
sudo bash codeparley-installer.sh grant-repository --path /home/impl/src/app
sudo systemctl restart codeparley-custodian.service
```

`--path` must be a plain absolute path with no link in it. The grant gives `codeparley-readers` read
access on the tree, the custodian read access on the top directory, and a traverse entry on each
ancestor that others cannot already search (a home directory with mode `0750`, say). Each is
recorded.

**3. The operator**, logged in as the operator account:

```bash
/usr/local/sbin/code-parley-operator setup --repo /home/impl/src/app \
  --proposal-file /tmp/cp-proposals/repo.json \
  --proposal-file /tmp/cp-proposals/s1.json \
  --loops 1 --minutes 60
```

`setup` routes each proposal by what it proposes. It approves the engine runtime (the versioned
directory `current` names, with `/usr/bin/git`), sets the repository's configuration, confirms the
S1 self-test and grants the loops. For each one the custodian renders what will be recorded and you
type `confirm` (`allow` for the loop grant). Anything else stops there and records nothing further.
It needs an interactive terminal; no flag skips the confirmations.

**4. The implementer** installs the plugin, once per account:

```bash
mkdir -p <plugin dir>
tar -xzf <dir>/plugin-linux.tar.gz -C <plugin dir>
claude plugin marketplace add <plugin dir>
claude plugin install code-parley@code-parley-local --scope user
```

Keep `<plugin dir>`. Start a new Claude Code session.

**5. Check it:**

```bash
code-parley status --repo /home/impl/src/app
code-parley doctor --protected --repo /home/impl/src/app
```

`status` exits 0 and says `READY` when the repository is set up. That is a display: it grants
nothing. Go on with [docs/protected-workflow.md](protected-workflow.md).

## Turning on delegated fixes

Delegated fixes are off by default, and normal review and Claude-led remediation work with them off.
To opt in, for one repository:

Windows, as the implementer, then the operator in an elevated terminal:

```powershell
code-parley init --repo C:\src\app --max-fixes 3
code-parley codex fix-selftest --codex <codex.exe>
```

```powershell
code-parley setup --fix --repo C:\src\app --home <implementer's %LOCALAPPDATA%\CodeParley> --no-grant
```

Linux, as the implementer, then the operator:

```bash
code-parley init --repo /home/impl/src/app --max-fixes 3
code-parley codex fix-selftest --codex $CODEX
code-parley config propose-selftest --fix --repo /home/impl/src/app --out /tmp/cp-proposals/fix.json --codex $CODEX
```

```bash
/usr/local/sbin/code-parley-operator setup --fix --repo /home/impl/src/app \
  --proposal-file /tmp/cp-proposals/fix.json --no-grant
```

`--max-fixes` takes 1 to 10; 0 turns delegated fixes off again. It is written to
`budgets.max_fixes_per_run` in the implementer's `config.json`. Restart open sessions; a new run
picks it up. The operator's confirmation before any patch is applied is separate and always needed:
[docs/protected-workflow.md](protected-workflow.md#delegated-fixes).

## Upgrade

Verify the new release first. An upgrade stops the services, backs the store up, migrates it and
keeps the previous version for a one-step rollback. The two most recent backups are kept.

```powershell
codeparley-installer.ps1 upgrade -Release <new dir>
```

```bash
sudo bash codeparley-installer.sh upgrade --release <new dir>
```

Protected reviews are refused until the operator approves the new engine runtime. `status` reports
the engine runtime `changed`:

Windows, in an elevated terminal as the operator:

```powershell
code-parley status --repo C:\src\app
code-parley setup --resume --repo C:\src\app --runtime-git-path "C:\Program Files\Git\mingw64\bin\git.exe"
```

Linux, as the operator:

```bash
/usr/local/sbin/code-parley-operator setup --resume --repo /home/impl/src/app
```

**On Windows, also reinstall the plugin after each upgrade**, as the implementer: its hooks and
server name the versioned engine path. On Linux the plugin follows the `current` link and needs
nothing.

```powershell
claude plugin uninstall code-parley@code-parley-local --scope user
claude plugin marketplace remove code-parley-local
New-Item -ItemType Directory <new plugin dir>
tar -xzf <new dir>\plugin-windows.tar.gz -C <new plugin dir>
claude plugin marketplace add <new plugin dir>
claude plugin install code-parley@code-parley-local --scope user
```

If an upgrade is interrupted, the custodian refuses to serve until it is finished. Complete it, or
roll back:

```powershell
codeparley-installer.ps1 upgrade -Resume
```

```bash
sudo bash codeparley-installer.sh upgrade --resume
```

### A Codex update

Protected reviews run only the exact Codex file the operator approved, so an update of that file
makes `status` report the repository record `changed` and refuses protected reviews until it is
approved. S1 and FIX confirmations are bound to the Codex binary too, so run the self-tests again
first.

CodeParley supports Codex 0.160.x; other versions are refused.

- **Windows:** put the new version in an administrator-controlled directory. The implementer runs
  `code-parley codex selftest --codex <new codex.exe>`. The operator runs `code-parley setup
  --resume --repo <path> --home <implementer's data home> --codex <new codex.exe>`.
- **Linux:** the installer copies Codex at `install` only; `upgrade` does not take a new one. After
  a new copy is in place, the implementer runs `code-parley codex selftest --codex <new codex>`,
  then `code-parley config propose` and `code-parley config propose-selftest` with `--codex <new
  codex>`. The operator runs `/usr/local/sbin/code-parley-operator setup --resume --repo <path>
  --proposal-file <file>` with both files.

## Rollback

Rollback returns to the kept previous build, restoring the store from the backup taken for it.

```powershell
codeparley-installer.ps1 rollback
```

```bash
sudo bash codeparley-installer.sh rollback
```

It is one step: afterwards no previous build is kept, and a second rollback is refused. It is also
refused if the backup is missing, does not match its recorded SHA-256, or holds a store format the
previous build does not serve; nothing is changed then.

A restored store must not bring back authority. So at its next start the custodian:

- ends every open protected run, with the reason `restored`;
- voids every unconsumed delegated-fix confirmation and every prepared request;
- suspends every loop grant;
- lapses every approval: configuration, engine runtime, S1 and FIX confirmations.

Nothing done after the backup is re-authorized. The operator re-confirms what is still wanted, with
`setup --resume` as after an upgrade. Start new runs. On Windows, reinstall the plugin from the
**previous** release's `plugin-windows` archive.

## Uninstall and purge

| | `uninstall` | `purge` |
|---|---|---|
| Services or units, binaries, engine runtime, the commands | Removed | Removed |
| Windows event-log source | Removed | Removed |
| Linux Codex copy and AppArmor profile | Removed | Removed |
| The protected store | **Kept** | Removed |
| Backups | **Kept** | Removed |
| Windows group `CodeParley Repository Readers` | **Kept** | Removed |
| Linux service accounts and groups, `/etc/codeparley` | **Kept** | Removed |
| Linux membership of your two accounts in the groups | **Kept** | Removed |
| Per-repository grants the installer recorded | **Kept**, listed | Removed |
| The install record | Updated | Removed |

**Neither touches** the Claude Code plugin, the implementer's data home, or `config.json`. Remove
the plugin yourself ([plugin/README.md](../plugin/README.md)). The Windows Codex installation and
your Git are yours and stay.

```powershell
codeparley-installer.ps1 uninstall
codeparley-installer.ps1 purge -ConfirmStore "C:\ProgramData\CodeParley\Custodian"
```

```bash
sudo bash codeparley-installer.sh uninstall
sudo bash codeparley-installer.sh purge --confirm-store /var/lib/codeparley
```

`purge` is destructive and asks for the exact store path as confirmation. It reports anything it
could not remove. To remove one repository's grant without uninstalling:

```powershell
codeparley-installer.ps1 revoke-repository -Path C:\src\app
```

```bash
sudo bash codeparley-installer.sh revoke-repository --path /home/impl/src/app
```

`install` after `uninstall` works on both platforms and keeps the store. Give the accounts again,
and on Linux `--codex` and `--load-apparmor`: the Codex copy and the profile were removed, so
`status` then shows what must be approved again.

`codeparley-installer.ps1 status` and `sudo bash codeparley-installer.sh status` show the services,
the installed and previous version, the store, the backups and the repository grants.

## After a reboot

By design a restart of the OS lapses the operator's records and suspends loop grants: an approval
made before a boot does not silently carry over. The custodian comes back by itself: on Windows the
service has a delayed automatic start, about two minutes after boot on the test VM; on Linux the
sockets are enabled at boot.

First check what lapsed:

```bash
code-parley status --repo <path>
```

**Windows.** The operator, in an elevated terminal:

```powershell
code-parley setup --resume --repo C:\src\app --loops 1 --minutes 60
```

One re-confirmation covers the repository's configuration and the lapsed global records, including
the S1 confirmation. A suspended grant never comes back: a new grant is a separate step. Add `--fix`
if you use delegated fixes. If `status` names `--home` for a record, add it.

**Linux.** An S1 confirmation is bound to its boot and is never re-confirmed: it needs a new
self-test. A reboot also empties `/tmp`.

```bash
# the implementer
code-parley codex selftest --codex $CODEX
install -d -m 0755 /tmp/cp-proposals
code-parley config propose-selftest --repo /home/impl/src/app --out /tmp/cp-proposals/s1-boot2.json --codex $CODEX
```

```bash
# the operator
/usr/local/sbin/code-parley-operator setup --resume --repo /home/impl/src/app \
  --proposal-file /tmp/cp-proposals/s1-boot2.json --loops 1 --minutes 60
```

For delegated fixes, also run `codex fix-selftest` and `config propose-selftest --fix`, and pass
that file with `--fix`.

A loop that was running is paused. `code-parley loop resume <run>` offers the re-confirmation first,
then shows what it would accept. User decisions that the recovery lapsed are listed there, and must
be recorded again to keep them.

The first protected request after a boot makes the custodian measure the engine runtime, and a call
queued behind that can be refused `CUSTODIAN_BUSY`. See
[docs/troubleshooting.md](troubleshooting.md#custodian_busy).

## Manual review (any platform)

You need Node.js `^22.12 || ^24`, git 2.41 or later, and Codex CLI 0.160.x, logged in. The
[README](../README.md#requirements-for-manual-review) has the details per platform. Installing the
npm tarball gives you no custodian: protected loops and delegated fixes are refused.

```bash
npm install -g code-parley-1.0.0.tgz
code-parley init --repo <path>
code-parley doctor
```

`init` prints the steps of a protected install too; for manual review, you need only the checks and
the self-test from that list.

Register the server with your host. Use `node` plus the script path, not a `.cmd` shim; `npm root
-g` prints the folder that holds `code-parley`.

**Claude Code:**

```powershell
claude mcp add --scope user code-parley -- "C:\Program Files\nodejs\node.exe" "<npm root -g>\code-parley\dist\server\main.js"
```

```bash
claude mcp add --scope user code-parley -- "$(command -v node)" "$(npm root -g)/code-parley/dist/server/main.js"
```

Add `--diagnostics` at the end to register `diag_echo` (setup diagnostics). Allow the tools in your
Claude Code permissions (`mcp__code-parley__…`) or approve them when asked.

**Claude Desktop, Chat tab.** Edit `%APPDATA%\Claude\claude_desktop_config.json` (the Microsoft
Store/MSIX install reads the same file) and restart Desktop:

```json
{
  "mcpServers": {
    "code-parley": {
      "command": "C:\\Program Files\\nodejs\\node.exe",
      "args": ["<npm root -g>\\code-parley\\dist\\server\\main.js"]
    }
  }
}
```

Write the JSON with an editor (double backslashes); a shell that eats backslashes produces a server
that fails to start (`spawn … ENOENT`). Desktop's server log is
`%APPDATA%\Claude\logs\mcp-server-code-parley.log`.

**Claude Desktop, Code tab.** Code-tab sessions load the same entry; no extra setup. All Code-tab
sessions share one server process.

To remove a manual install: `npm uninstall -g code-parley`. It leaves the data home and
`config.json`.
