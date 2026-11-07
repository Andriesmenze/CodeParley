# Troubleshooting

Start here:

```bash
code-parley status --repo <path>
code-parley doctor --protected --repo <path>
```

`status` says what state the custodian and the repository are in, and prints the command that
restores each record. Every CLI refusal prints its `cause:` and `fix:` under the error. Claude
receives the same text as `error.remedy`.

In the fixes below, *operator* means:

| | Run it as |
|---|---|
| Windows | `code-parley <command>` in an elevated terminal (Run as administrator), as the operator account |
| Linux | `/usr/local/sbin/code-parley-operator <command>`, as the operator account, by that absolute path |

And *installer* means `codeparley-installer.ps1 <verb>` in elevated PowerShell on Windows, and `sudo
bash codeparley-installer.sh <verb>` on Linux.

## `status`

`code-parley status [--repo <path>] [--json]` works from any account. It is a display: it grants,
confirms and changes nothing, and the custodian decides each protected request itself. A busy
custodian is probed for at most 12 seconds.

### Exit codes

| Command | Exit codes |
|---|---|
| `status` | 0: the host is ready and, with `--repo`, so is the repository. 1: anything else |
| `doctor` | 0: no problems. 1: problems were listed |
| `setup` | 0: the repository is ready. 1: stopped on an error, or still not ready. 2: a step was not confirmed, or cannot run yet |
| Other commands | 0 ok. 1 error. 2 confirmation required or not typed. 3 cancellation requested, termination not confirmed |
| `fix reconcile` | 0: nothing to reconcile, or a choice was recorded. 3: an application waits for `--restore` or `--leave` |
| `runs stop --close`, `--abort` | As other commands, and 4: it did not establish that no confirmed fix can run. The custodian refused, did not answer or lost its answer, or an application had already begun. The local record and the custodian's answer are printed separately. On a host with a custodian this includes an attended run it never held (`RUN_NOT_OPEN`), although the run closed locally |

### Host states

| State | Meaning | What to do |
|---|---|---|
| `READY` | The custodian answered on at least one surface with this engine's protocol | Nothing. On Windows the operator surface answers only in an elevated terminal |
| `NOT INSTALLED` | The service manager says the service does not exist | Protected requests are refused; manual reviews are unaffected. Install it: [docs/install.md](install.md) |
| `STOPPED` | Windows: the service is installed and stopped. Linux: the sockets are not listening | Windows: `sc.exe start CodeParleyCustodian`. Linux: `sudo systemctl start codeparley-implementer.socket codeparley-operator.socket codeparley-helper.socket` |
| `UNTRUSTED` | An endpoint answered that the custodian does not own | Do not proceed. CodeParley refused it, so no authority went to it. An administrator checks the host and restarts the custodian |
| `INCOMPATIBLE` | The custodian and this engine speak different protocol versions | Install both from the same release |
| `BUSY` | The custodian is running, and serving another request for longer than the probe waited | [Below](#custodian_busy) |
| `UNAVAILABLE` | Installed and not stopped, but nothing answered | It may still be starting: on Windows the delayed start takes about two minutes after boot. Or it refused its store: the installer's `status` says which. An interrupted upgrade: `upgrade --resume` (Windows `-Resume`) |
| `UNSUPPORTED PLATFORM` | No custodian exists for this OS | Manual review works here |

On Linux, a custodian that refuses to start because a host precondition failed shows as
`UNAVAILABLE`. The reason is in the journal, which needs an administrator:

```bash
sudo journalctl -u codeparley-custodian.service -n 50
```

The preconditions are in [docs/install.md](install.md#linux-prerequisites). There is no store-repair
command: a store that fails validation stays down until an administrator repairs it.

### Repository state

With `--repo` on a ready host, `status` adds `READY`, `MISCONFIGURED` (a required record is not in
force), or `UNKNOWN` (the custodian must answer first, or the records could not be read). It lists
each record:

| Record | Required for | |
|---|---|---|
| `engine runtime` | Every protected run | The runtime the custodian's helper executes |
| `repository configuration` | Every protected run | The approved checks, the capture rules and the Codex installation |
| `Codex isolation (S1)` | Every protected run | The S1 self-test confirmation, or an accepted reduction |
| `FIX confirmation` | Delegated fixes only | Shown as `[optional]` |
| `loop grant` | Automated loops only | Shown as `[optional]` |

| Record state | Meaning | Restored by |
|---|---|---|
| `in force` | Valid now | Nothing needed |
| `LAPSED` | A restart of the OS, or a rollback | `setup --resume` |
| `CHANGED` | Engine runtime: an upgrade installed a new one, or removed or rebuilt the approved one. Repository: the approved Codex file changed | `setup --resume`, after the steps `status` prints |
| `MISSING` | Never set up | `setup` |
| `REVOKED` | The operator revoked it | `setup` |
| `SUSPENDED` | Loop grant: a restart of the OS suspended it. It never comes back | A new grant, with `setup` |
| `USED UP`, `EXPIRED` | Loop grant: every loop used, or past its end | A new grant, with `setup` |

Each line prints its exact command, in this platform's terms. On Windows a command may include
`--home <the implementer's data home>`: fill in the path if the operator ran `status`.

## `doctor --protected`

`code-parley doctor` is read-only and offline: it reports Node.js, the data home, `config.json`, the
allowed roots, git, Codex and its self-test results, the store and retention. With `--protected
[--repo <path>]` it adds the host state and the records from `status`, plus:

- whether the readers grant is present on the repository (Windows: `CodeParley Repository Readers`,
  read with `icacls`; Linux: `codeparley-readers`, read with `getfacl`);
- on Linux, how many filesystems are admitted (`/etc/codeparley/filesystems.json`) and whether the
  AppArmor profile file is installed.

On Linux, `doctor` as the implementer lists Codex as not found unless `config.json` names it. It
prints the administrator's Codex path: pass `--codex <path>`, or set `codex.executable`.

## `CUSTODIAN_BUSY`

The custodian serves one request at a time. Right after a boot, the first protected request makes it
measure the approved engine runtime. On Windows that took about 13 to 55 seconds on the test VM, and
a call queued behind it waited up to 37.7 seconds. A hook queued behind that can run out of time and
be refused `CUSTODIAN_BUSY`.

This is a known limitation of this release. It fails closed: nothing is granted, consumed or
weakened.

1. Wait for the current request to finish.
2. Run `code-parley status`. It waits at most 12 seconds and shows `BUSY` while the custodian is
   still occupied.
3. When it answers, retry what was refused. If `setup` stopped, run it again; steps already recorded
   are kept and skipped.

The custodian's measurement also runs before each later helper launch, in about a second when warm.
Delayed start is separate: on Windows the custodian is not there at all for about two minutes after
boot, and calls in that window fail `CUSTODIAN_UNAVAILABLE`. Wait and retry.

## Refusal codes

### Custodian and operator

| Code | Cause | Fix |
|---|---|---|
| `CUSTODIAN_UNAVAILABLE` | No trusted answer from the custodian: it is not installed, stopped, still starting, or it refused its store (for example after an interrupted upgrade). Or the service is running and this account may not use that endpoint | Run `code-parley status`; it names the state and the command. Install: installer `install`. Interrupted upgrade: installer `upgrade -Resume` (Linux `--resume`). If the message says access to the operator endpoint was denied, run the command as the operator. Nothing falls back to weaker authority meanwhile |
| `CUSTODIAN_BUSY` | The custodian serves one request at a time and was busy longer than this request could wait | [Above](#custodian_busy) |
| `SERVER_NOT_TRUSTED` | Another process holds the custodian's pipe (Linux: socket) name | Do not proceed. An administrator checks the host (installer `status`) and restarts the custodian. No authority went to it |
| `CALLER_NOT_AUTHORIZED` | The custodian accepts this request only from another surface | Run operator commands as the operator; the implementer's commands from the implementer's own account |
| `INTERACTIVE_TERMINAL_REQUIRED` | Operator records are confirmed only by a person typing at a terminal | Run the command yourself, with stdin and stdout a terminal. No flag skips the confirmation |
| `OPERATOR_CODE_UNTRUSTED` | Linux: on a host with the custodian, operator commands run only from the approved runtime through the root-owned wrapper | Run `/usr/local/sbin/code-parley-operator <command>`: the absolute path, not through `PATH` or an alias |
| `LOOP_NOT_AUTHORIZED` | No grant for this repository, or it is used up, expired, or was suspended by a restart of the OS | The operator runs `setup --repo <path>` or `loop allow --repo <path>`. `status --repo <path>` shows the grants |
| `LOOP_START_UNRECONCILED` | A loop start's answer was lost, so it is not known whether a loop was started | `code-parley loop stop <run>`, then start a new run |
| `AUTHORIZATION_EXPIRED` | The rendered record was not confirmed in time | Run the command again and confirm the new rendering |

### Configuration

| Code | Cause | Fix |
|---|---|---|
| `CONFIG_NOT_HELD` | No protected configuration for this repository: never set, or revoked | The operator runs `setup --repo <path>` |
| `CONFIG_LAPSED` | The operator's records lapse when the custodian recovers after a restart of the OS, and after a rollback | The operator runs `setup --resume --repo <path>`. `status --repo <path>` lists what lapsed |
| `CONFIG_MISMATCH` | What is installed no longer matches what was approved: Codex or the engine runtime changed | The operator runs `setup --repo <path>`. A re-confirmation refused this way is not retried: `setup` offers to set the configuration again, with its own confirmation (on Linux from the implementer's `config propose` file). After a Codex update the implementer first runs `code-parley codex selftest`; on Linux also `config propose` and `config propose-selftest` |
| `STALE_CONFIG` | The configuration changed between the rendering and the confirmation | Run the same command again |
| `ISOLATION_NOT_ACCEPTED` | No isolation basis is confirmed for this Codex version and backend: an S1 confirmation, or for a delegated fix the FIX confirmation | Windows: the implementer runs `code-parley codex selftest` (or `codex fix-selftest`); the operator runs `setup [--fix] --repo <path>`. Linux: the implementer also runs `config propose-selftest [--fix] --repo <path> --out <file>`; the operator runs `setup [--fix] --repo <path> --proposal-file <file>` |
| `RUNTIME_NOT_APPROVED` | No engine runtime is approved (none yet, or revoked), or the one named cannot be approved; the message says why | Windows: the operator runs `code-parley setup --repo <path> --runtime-git-path <installed git.exe>`. Linux: the operator runs `setup --repo <path>`; it approves the versioned directory `/opt/codeparley/engine/current` names, with `/usr/bin/git` |
| `HELPER_UNAVAILABLE` | The custodian's helper is not installed, not enabled, or could not start | Windows: an administrator runs `CodeParley.Custodian.exe install-helper` (or the installer's `upgrade`) and restarts `CodeParleyCustodian`. Linux: installer `upgrade --release <dir>` |
| `REPOSITORY_NOT_READABLE` | The helper has no readers grant on this repository | Installer `grant-repository -Path <repository>` (Linux `--path`). On Linux, then restart the custodian |
| `CODEX_INSTALLATION_UNSUPPORTED` | The Codex named is not a form the custodian can measure: a launcher, a script or a link | Name the native executable (`code-parley doctor` shows the one it resolves), and set the configuration again |
| `STORE_VERSION_UNSUPPORTED` | A store was written by a newer CodeParley | Install the matching release (installer `upgrade`) instead of running an older build against it |

### Reviews and checks

| Code | Cause | Fix |
|---|---|---|
| `CODEX_ISOLATION_UNAVAILABLE` | Codex's sandbox could not be confirmed: the stored self-test failed or is missing, the operator's confirmation covers another stored self-test than the current one (`status` shows `UNCONFIRMED`), or on Linux its basis changed or it lapsed with the boot | `status --repo <path>` names the case; for `UNCONFIRMED` the operator runs `setup --resume --repo <path>` (Windows: with `--home <the implementer's data home>`). Windows: the implementer runs `code-parley codex selftest` in an interactive desktop session; `doctor` shows the result. Linux: the implementer runs `codex selftest`, then `config propose-selftest --repo <path> --out <file>`; the operator runs `setup --resume --repo <path> --proposal-file <file>`. Manual review: read the failed rows. Reduced isolation is a deliberate, recorded choice ([README](../README.md#codex-isolation)) |
| `CODEX_NOT_FOUND` | No Codex CLI was found | Install Codex, or name it with `codex.executable` in `config.json`. `doctor` shows what it resolves |
| `CODEX_UNSUPPORTED_VERSION` | The installed Codex is not a supported version | Install Codex 0.160.x. `doctor` shows the version found |
| `CODEX_AUTH_MISSING`, or a review `failed` with an auth error | Codex is not logged in | `codex login` in a terminal |
| `CHECK_NOT_APPROVED`, or a floor shown `unapproved` | The check definitions are not approved, or changed since. A hand-edited trust file invalidates the whole approval by design | `code-parley checks list --repo <path>`, then `code-parley checks approve --repo <path> --from-proposals` |
| `NO_CHECKS_CONFIGURED` | The repository has no approved checks | Propose checks in `.code-parley/config.json` and approve them with `checks approve --from-proposals` |
| `SCOPE_NOT_CONFIGURED` | No allowed roots are configured | `code-parley init --repo <path>`, then restart the Claude Code session |
| `SCOPE_REPO_ROOT_OUTSIDE_ALLOWED` | The repository's git top level is outside the allowed roots | `code-parley init --repo <path>`, then restart the Claude Code session |
| `REPOSITORY_NOT_SPECIFIED` | Desktop Chat has no session folders | Tell Claude the repository path |
| `REPO_OUTSIDE_SESSION_ROOTS` | The repository is not one of the session's folders | A warning; in strict mode an error |
| `SCOPE_REVOKED` | The repository left your allowed roots after the run was created | `stop_review_loop` still works |
| `NOT_A_GIT_WORKTREE` | Not a git repository. For the Windows operator, usually git's "dubious ownership": the repository belongs to the implementer | As the operator: `git config --global --add safe.directory <repository with forward slashes>` |
| `WORKTREE_BUSY` | Checks in any session are running here, a capture or source read held it for more than 30 s, or a delegated fix is being applied | Wait, or cancel the other operation |
| `WORKTREE_OWNERSHIP_UNRESOLVED` | A server died during checks | [README: Recovery](../README.md#recovery-after-a-crash): `lock show`, then `lock release` |
| `RUN_BUSY` | One operation per run at a time. `respond_to_review` and `decide` wait until a running review has finished; `amend` does not | Poll, or cancel the active one |
| `STALE_FINDING_STATE` | The finding changed after it was read. For `decide`: the thread changed between the display and your confirmation | Read the status again. For `decide`, run the command again |
| `FINDING_NOT_FOUND`, `FINDING_NOT_RESPONDABLE` | Not an item id from a status or review result; an engine condition or incident cannot be responded to; a superseded finding is replaced by the item it names; a finding reported resolved is closed | Respond to what status shows now |
| `SOURCE_UNAVAILABLE` | A fix claim needs the current source identity, which could not be read: usually a running check holds the worktree | Retry when it is free |
| `BUDGET_EXHAUSTED` | The run's review, check or fix budget is used up, or its response limit (20 per finding, 1 000 per run), or its limit of user records (500 decisions, 50 per thread; 50 amendments) | Create a new run |

### Delegated fixes and the protected run

| Code | Cause | Fix |
|---|---|---|
| `FIX_DELEGATION_UNAVAILABLE` | A delegated fix needs a protected run through the validated custodian, a protected configuration in force, a fix budget and the operator's FIX self-test confirmation | `status --repo <path>` shows which is missing. Budget: `code-parley init --repo <path> --max-fixes <n>`; a new run picks it up. Confirmation: the operator runs `setup --fix --repo <path>` |
| `EVIDENCE_NOT_HELD` | No finished review with a published capture to seed a fix from, or the confirmed content cannot be vouched for | Run a review first. For a proposal: delegate again |
| `FIX_NOT_CONFIRMED`, `FIX_DECLINED` | No confirmation is held, or the operator rejected the proposal | Nothing is applied. Confirm it, or delegate again |
| `CONFIRMATION_EXPIRED` | The confirmation expired before it was applied | The operator runs `fix confirm <run> <proposal> --repo <path>` |
| `CONFIRMATION_CONSUMED` | The confirmation was already used | A new delegation and confirmation |
| `CONFIRMATION_CONTENT_MISMATCH` | The rendering cannot be re-derived from what the custodian holds, or differs from the one confirmed | Nothing is recorded. Delegate again |
| `FIX_STALE` | The working tree moved since the fix's baseline | Nothing was written and the confirmation stays unused. Delegate again from a new review |
| `FIX_NOT_APPLICABLE` | The proposal cannot be applied faithfully here, for example an executable bit this platform's working tree cannot carry | Nothing was applied |
| `APPLY_TARGET_REFUSED` | A target or its parent is not what was confirmed | Nothing more is written. See `fix reconcile <run>` |
| `APPLY_IN_PROGRESS` | Another application is under way in this repository | Wait. If it was interrupted: `code-parley fix reconcile <run>` |
| `PROCESS_IDENTITY_UNVERIFIED` | The calling process is not the session bound to the loop, for example a new process after the loop's 15-minute window | Work in the bound session. Otherwise end the run and start a new one |
| `RUN_ALREADY_HAS_LOOP` | One loop per run, ever | Start a new run |
| `RUN_DECLARATION_CONFLICT` | The run changed after it was registered with the custodian, so it cannot become protected | Start a new run |
| `RUN_RECORD_MISSING` | The run is marked protected locally, but the custodian holds no record of it, for example after a reinstall | Nothing proceeds on this run. Start a new run |
| `RUN_TERMINAL`, `RUN_NOT_OPEN` | The run has ended, for example `restored` after a rollback | Start a new run |

## Linux sandbox and file systems

| Symptom | What to do |
|---|---|
| The self-test's profile is rejected (`bwrap: … Operation not permitted`, namespace errors) | Unprivileged user namespaces are disabled (`/proc/sys/user/max_user_namespaces` is 0) or restricted by AppArmor (`/proc/sys/kernel/apparmor_restrict_unprivileged_userns` is 1, the Ubuntu 23.10+ default); `doctor` shows both. Allowing them is an administrator's decision: on a protected install `--load-apparmor`, on a manual install an AppArmor profile for Codex's bundled `bwrap` ([README](../README.md#codex-isolation)). CodeParley never changes system settings by itself and never runs Codex unsandboxed instead. Inside a container, user namespaces are often unavailable too. |
| `UNSUPPORTED_REPO_STATE` with `filesystem_unsupported:<type>` | The repository is on a file system without POSIX semantics (a Windows drive mounted by WSL such as `/mnt/c`, FAT/exFAT, NTFS, SMB, FUSE). Clone it into the Linux file system (for example `~/src`). With `mount_table_unreadable`: `/proc/self/mountinfo` cannot be read (a restricted container?), so mount points inside the repository could not be recognised; CodeParley needs `/proc`. |
| `CONFIG_INVALID` about the data home | It is writable by other users (`chmod 700 <dir>`), owned by another user, or on an unsupported file system; or choose another one with `--home` / `XDG_STATE_HOME`. |
| A check is refused as an "unsupported executable type" or "not found on PATH" | The file has neither an ELF header nor a `#!` line (it would run under an implicit `/bin/sh`): add a `#!` line or make the shell explicit (`["sh", "-c", "…"]`). Bare names are looked up only in absolute `PATH` entries: give a path, or fix `PATH`. |
| `install` or `upgrade` refuses: "the bundled Node.js needs libatomic.so.1, which is not installed" | Node.js 26's official Linux build links `libatomic`. Install it (`sudo apt install libatomic1`) and run the same command again; nothing was changed. The same library missing at run time shows as `libatomic.so.1: cannot open shared object file`. |
| `upgrade` or `rollback` refuses: the bundled (or previous) Node.js "does not start" | The engine's `node` did not run as `codeparley-helper` or reported another version than its BUILD-ID. The running version and the store are untouched. Check `ldd /opt/codeparley/engine/<version>/node` for a missing library. |
| `grant-repository` refuses the path | It must be a plain existing directory with no link in it, on ext4 with `metadata_csum` and 256-byte inodes. |

## Other symptoms

| Symptom | What to do |
|---|---|
| Review result says `stale` / not current | The source or check evidence changed during or after the review: re-run checks and request a new review. |
| `cancellation_requested` (CLI exit 3) | Termination was not confirmed; the named processes may still run. Inspect them yourself (`runs show`). On a busy machine an unrelated process can be listed as `unattributable`: it was created during the operation and its parent has already exited, so CodeParley cannot rule out that it descends from the check and reports it instead of guessing. On Linux the same applies to a process of yours that was adopted by `init` or a user service manager (`systemd --user`) during the operation. |
| `code-parley` is not found on Windows after installing | Open a new terminal: the installer changed the machine `PATH`. |
| A new group has no effect on Linux | Log in again after `install`: `usermod` changes take effect at the next login. |
| Repository on a mapped network drive | A mapped drive resolves to its UNC path (`\\server\share\…`). Give the allowed root and the repository the same way (both through the share); the same folder reached once through a local path and once through a share is treated as two different places and refused (`SCOPE_REPO_ROOT_OUTSIDE_ALLOWED`). Capture is slower over the network. |
| Slow reviews or checks on a very large working tree | A check run re-reads and hashes all non-ignored files before its first check and after each check; a review reads them and also copies them for Codex. Measured on Windows 11 with Defender on: about 10 000 files → identity 9 s, review capture 45 s; 100 000 files (40 000 untracked) → identity 90 s, review capture about 15 minutes. On Linux, 100 000 files took about 10.4 minutes to capture. Keep dependencies and build output git-ignored. While re-reading takes longer than 20 s, `get_review_status` shows the last known source. |
| Repository in a OneDrive folder | Capture reads every file it exports, so OneDrive downloads cloud-only ("files on demand") files of the repository during a capture. Keep reviewed repositories fully local ("Always keep on this device") or outside OneDrive. |
| A Desktop server fails to start | Check `%APPDATA%\Claude\logs\mcp-server-code-parley.log`; usually a wrong path in the config entry. |
| Anything else | `code-parley doctor`; server logs in `%LOCALAPPDATA%\CodeParley\logs\server-<date>.log` (Linux: `~/.local/state/code-parley/logs/`). |

## After a reboot

Operator records lapse and grants suspend by design. On Linux S1 needs a new self-test. `status
--repo <path>` names exactly what lapsed, and `setup --resume` restores it with typed confirmations:
[docs/install.md](install.md#after-a-reboot).

## After an upgrade

`status --repo <path>` reports the engine runtime `changed`. The operator runs `setup --resume`. On
Windows the implementer also reinstalls the plugin: [docs/install.md](install.md#upgrade). If the
upgrade was interrupted, the custodian refuses to serve until `upgrade --resume` (Windows `-Resume`)
or `rollback`.

## After an interrupted delegated fix

`code-parley fix reconcile <run>` reports each file's state; choose `--restore` or `--leave`:
[docs/protected-workflow.md](protected-workflow.md#an-interrupted-application).
