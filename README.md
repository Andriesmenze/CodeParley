# CodeParley

CodeParley gives Claude an **independent second opinion from Codex** on the code changes in a local
git repository, plus **checks you approved** (tests, linters, builds), with every result tied to
exactly the source it describes.

It runs as a local MCP server next to your Claude host. Claude asks for a review; CodeParley captures
a sanitized, read-only snapshot of the changes itself, runs Codex on that snapshot under verified read
isolation, and reports triaged findings, check results, coverage and limitations back to Claude. Claude
and Codex then discuss the findings within fixed limits, you settle what they cannot, and whether the
task is complete is derived from the evidence: nobody can set it.

A review never changes your repository. The two things that do are the check commands you approved,
which run your code with your privileges, and a delegated fix, which is written to your working tree
only after you confirmed its exact content. CodeParley itself never commits, pushes, merges, tags or releases.

## Contents

- [The two modes](#the-two-modes)
- [Supported platforms and hosts](#supported-platforms-and-hosts)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Requirements for manual review](#requirements-for-manual-review)
- [Configuration: allowed roots](#configuration-allowed-roots)
- [Approving checks](#approving-checks)
- [Codex isolation](#codex-isolation)
- [Using it: runs, checks, reviews](#using-it)
- [Responding to findings and discussing them with Codex](#responding-to-findings-and-discussing-them-with-codex)
- [Your decisions, task amendments and completion](#your-decisions-task-amendments-and-completion)
- [Status, history and cancellation](#status-history-and-cancellation)
- [What is sent to Codex, and what is not](#what-is-sent-to-codex-and-what-is-not)
- [The local run store](#the-local-run-store)
- [Recovery after a crash](#recovery-after-a-crash)
- [Troubleshooting](#troubleshooting)
- [Known host behaviour](#known-host-behaviour)
- [CLI reference](#cli-reference)
- [Development](#development)
- [License](#license)

## The two modes

| | Manual review | Protected loop |
|---|---|---|
| What you get | Reviews, approved checks, responses, the discussion with Codex, your decisions, derived completion | All of that, plus a bounded automated loop in the session that started it, and optional delegated fixes |
| Who holds the authority | Your OS account: the records are files in your own data home | The **custodian**, a separate service with its own store, which the implementer account cannot write |
| Who starts work | You or Claude, one request at a time | The same, plus up to 2 automated continuations and 2 wake-ups per granted loop, within 15 minutes |
| Installed with | The npm tarball | The Windows or Linux installer, the Claude Code plugin, and a separate operator account |
| Where it runs | Windows and Linux | Windows 11 x64 and Ubuntu 24.04 x86_64 only |

Manual review stays available everywhere. Without a validated custodian, protected loops and delegated
fixes are refused: nothing falls back to weaker authority.

Nothing runs on its own in manual review. In a protected loop, the operator first grants a limited
number of loops for one repository, typed at an operator terminal. Each loop can keep the originating
Claude Code session working on its own within those limits; it starts no other session, records no
decision, and ends at `ready`, at its limits, or when the operator stops it. Delegated fixes are off by
default.

The custodian's protection has stated limits, listed in [docs/security.md](docs/security.md). CodeParley
does not claim production-secure unattended operation.

## Supported platforms and hosts

| | Windows 11 x64 | Ubuntu 24.04 x86_64 | Other Linux, WSL2 |
|---|---|---|---|
| Manual review | Yes | Yes | Linux and WSL2: yes (repositories in the Linux file system) |
| Protected loop and delegated fixes | Yes | Yes: kernel 6.8, ext4 with `metadata_csum` and birth time, repositories on the root filesystem | No |

| Host | Support |
|---|---|
| Claude Code (CLI) | Manual review, protected loop, delegated fixes. The only supported host for the protected workflow. |
| Claude Desktop | Manual review only, in the Chat and Code tabs. No protected or delegated-fix claim. Not available on Linux. |

An npm install needs Node.js `^26.13`, the one supported Node.js major (Node.js 26 LTS). The installers bundle
Node.js 26 and need no SDK or Node.js on the target (on Linux, the bundled Node.js needs `libatomic1`; see
[docs/install.md](docs/install.md#linux-prerequisites)). Releases 1.0.0 and 1.0.1 support `^22.12 || ^24` and bundle
Node.js 24.22.2. macOS is not supported.

## Quick start

CodeParley is delivered as artifacts on this repository's
[releases page](https://github.com/vanderMerkProjects/CodeParley/releases). Verify the release first
([docs/verifying-releases.md](docs/verifying-releases.md)). Version 1.0.0 was released privately; the first public
binary release is 1.0.1 (until it appears there, no public binary is available). The examples below name the version
of these sources.

**Manual review:**

```bash
npm install -g code-parley-1.0.1.tgz
code-parley init --repo <path>
code-parley doctor
```

Then register the server with your host ([details](docs/install.md#manual-review-any-platform)) and ask
Claude for a review.

**Protected loop:** this involves two accounts, an implementer and an operator, and an administrator
step. In short:

1. An administrator runs the installer (`install`).
2. The implementer runs `code-parley init --repo <path>`, approves the checks and runs the Codex
   self-test.
3. An administrator runs the installer's `grant-repository`.
4. The operator runs `setup` and confirms each record by typing.
5. The implementer installs the plugin and checks `code-parley status --repo <path>`.

[docs/install.md](docs/install.md) has the exact commands for each platform.

## Documentation

| Document | Contents |
|---|---|
| [docs/install.md](docs/install.md) | Verifying a release, installing, setting up a repository, upgrade, rollback, uninstall, reboot recovery |
| [docs/protected-workflow.md](docs/protected-workflow.md) | The loop, grants, delegated fixes, what `ready` means, refusals you will meet |
| [docs/troubleshooting.md](docs/troubleshooting.md) | `status` and `doctor --protected`, every refusal code with its cause and fix |
| [docs/security.md](docs/security.md) | The security claim, the trust model and every known limit |
| [docs/verifying-releases.md](docs/verifying-releases.md) | Checking a release's signature and hashes, and how this repository's sources relate to the 1.0.0 build |
| [docs/development.md](docs/development.md) | Building, the test classes, CI and what is validated outside it |
| [plugin/README.md](plugin/README.md) | The Claude Code plugin |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing changes |

## What it does

| Capability | Details |
|---|---|
| Ten MCP tools | `create_review_run`, `run_checks`, `review_with_codex`, `get_review_status`, `get_review_history`, `respond_to_review`, `start_review_loop`, `stop_review_loop`, `delegate_fix`, `apply_fix` (and `diag_echo` with `--diagnostics`) |
| Scope you control | Only repositories inside your configured **allowed roots**. The host's own roots are advisory; tool arguments can never widen scope. |
| Read-only capture | Changes are read with hardened git queries: no index writes, no hooks, no filters (incl. LFS), no lazy fetch, nothing written to your repository. |
| Confidentiality | Files matching confidentiality globs (`.env`, keys, certificates, … by default) never reach Codex or the host model: not their content, names or hashes. |
| Independent review | Codex reviews an immutable export under the **S1** isolation profile (reads confined to the export, no writes, OS-enforced no network), verified by an offline self-test. Fails closed. |
| Approved checks | Only commands you approved through the CLI run; required checks form a verification floor that tool arguments can raise but never lower. |
| Evidence identities | Every check result and review is bound to the exact source, inputs and environment it saw; stale evidence is reported as stale, never reused silently. |
| Long work as operations | A tool call waits at most about 45 s and returns a handle; Claude polls. Cancelling a call (Esc, a timeout) never stops the work; stopping is explicit and targeted. |
| Responses to findings | Claude records its position on each finding (accepted, disputed, deferred, fix claimed) as the implementer's claim, beside the finding and never changing it; responses are checked against the exact state Claude read, and kept with their history. |
| Bounded discussion | The next review shows Claude's responses to Codex, which replies with a structured stance per finding; each issue's discussion follows the finding across rewordings and merges, allows 3 exchanges, passes on a repeated argument only with new information, and flags an unresolved disagreement for your decision. |
| Your decisions | You decide an unresolved thread (`require-resolution`, `waive`, `defer`, `revoke`) and amend the task (scope, constraints, acceptance criteria, priority, clarification) with the CLI, at an interactive terminal. Your records sit beside Claude's and Codex's, are never changed, and no MCP tool can write them. |
| Derived completion | Status reports whether the task is complete (`ready`) or what blocks it (checks, review freshness, a decision you owe, the reviewer or Claude), derived on every read. Nothing can set it, and `ready` authorizes nothing. |
| Protected loop | With a validated custodian and an operator's grant, the originating Claude Code session keeps working within fixed limits. See [docs/protected-workflow.md](docs/protected-workflow.md). |
| Delegated fixes | Off by default. Codex proposes one scoped fix in a disposable copy; the custodian validates and holds it; the operator confirms the exact rendering; only then is it applied. |
| Persistence and recovery | One authoritative record per run; crashes are recovered and reported, nothing is assumed. |
| Operations CLI | `code-parley init`, `status`, `setup`, `doctor`, `checks`, `lock`, `codex`, `runs`, `decide`, `amend`, `loop`, `config`, `fix`. Retention runs at server start. |

## Architecture

```text
Claude Code CLI / Claude Desktop (Chat tab, Code tab)
        │  MCP over stdio (protocol 2025-11-25 or 2026-07-28, negotiated per connection)
        ▼
code-parley server (node dist/server/main.js)
  ├── MCP layer   tool schemas, strict argument validation, bounded waits, result shaping,
  │               confidentiality filter on every host-facing text
  ├── Engine      runs, operations, identities, triage, carry-forward, budgets, retention
  ├── Policy      pure rules: triage, verification floor, review bundle, confidentiality, retention
  ├── Capture     hardened read-only git queries → sanitized export (plain folder, no .git)
  ├── Checks      trusted check definitions → argv execution (no shell) under a worktree lock
  ├── Codex       agent probe, offline sandbox self-test, `codex exec` with the isolation profile
  └── Store       config, trust, run records, artifacts, locks, logs
                  (Windows: %LOCALAPPDATA%\CodeParley; Linux: ~/.local/state/code-parley)
        │
        ├── git             read-only queries against your repository
        ├── check commands  the argv you approved, in your working tree
        ├── codex           sandboxed (S1: MXC on Windows, bubblewrap on Linux),
        │                   working directory = the sanitized export
        └── custodian       protected installs only: a separate service with its own store
                            (Windows: CodeParleyCustodian; Linux: codeparley-custodian)

code-parley CLI (you, in a terminal)
```

Each Claude Code session and Desktop's Chat start their own server process; Desktop's Code-tab
sessions share one. All processes coordinate through the store and its locks, so they must use
the **same data home** (the default) to see each other's runs and locks.

## Requirements for manual review

One engine serves Windows and Linux; the platform-specific parts sit behind small platform modules.
A protected install has further requirements, listed in [docs/install.md](docs/install.md).

### Windows

| Requirement | Supported |
|---|---|
| Windows | Windows 11, native (not WSL). Codex's **MXC** sandbox backend must pass the S1 self-test on your machine. |
| Node.js | `^26.13` |
| Git for Windows | 2.41 or later (2.45+ for partial clones) |
| Codex CLI | **0.160.x**, native install (`codex.exe`, not only an npm `.cmd` shim), logged in (`codex login`, or `CODEX_API_KEY`). Other versions are refused. |
| Repository locations | Local NTFS folders, paths over 260 characters, 8.3-shaped names, `subst` drives, a mapped network drive and a OneDrive folder (see [Troubleshooting](docs/troubleshooting.md) for the last two). Not validated: other network file systems, ReFS/Dev Drive volumes, removable media, `\\wsl$` paths. |

### Linux

| Requirement | Supported |
|---|---|
| Linux | x86-64, with **unprivileged user namespaces** available to Codex's bundled bubblewrap (on Ubuntu 23.10 and later that takes an AppArmor profile; see [Codex isolation](#codex-isolation)). |
| Node.js | `^26.13` (its official Linux build needs `libatomic1`: `sudo apt install libatomic1`) |
| git | 2.41 or later (2.45+ for partial clones) |
| Codex CLI | **0.160.x**, for example `npm install -g @openai/codex@0.160.0` (CodeParley maps the npm launcher to the native binary it bundles), logged in (`codex login`). Its bundled bubblewrap must pass the S1 self-test (`code-parley codex selftest --backend bwrap`). |
| Hosts | Claude Code (standalone CLI). Claude Desktop does not run on Linux. |
| File systems | Validated: ext4 (and tmpfs). Allowed but not validated (`doctor` says so): xfs, btrfs, zfs, overlayfs, NFS and others. **Refused** for repositories and the data home: Windows drives mounted by WSL (`/mnt/c`, drvfs/9p), FAT/exFAT, NTFS, SMB/CIFS and FUSE mounts: their semantics are not POSIX (or not knowable). Under WSL, keep repositories in the Linux file system (for example `~/src`). |

## Configuration: allowed roots

CodeParley only works on repositories inside directories you allow. `code-parley init --repo <path>`
adds a repository to the list. The file is `%LOCALAPPDATA%\CodeParley\config.json` (Linux:
`~/.config/code-parley/config.json`, or `$XDG_CONFIG_HOME/code-parley/config.json`; use
`"allowed_roots": ["/home/you/src"]`):

```jsonc
{
  "schema_version": 1,
  "allowed_roots": ["C:\\src"],            // required; repositories at or below these folders
  "client_roots": { "enforce": false },    // true: the repository must also belong to the host session's folders
  "retention": { "max_age_days": 30, "purge_on_startup": true }
}
```

Other settings (all optional) include `capture.exclude_globs` (confidentiality exclusions: an
explicit list **replaces** the defaults), `budgets`, `waits`, `codex.executable`,
`codex.windows_sandbox` (the Codex Windows sandbox backend; default `mxc`) and `codex.model`.
`--allowed-root <dir>` on the server command line adds roots for that server only.

A Claude Code session reads `config.json` when it starts: restart open sessions after a change.

- Drive roots, `%SystemRoot%`, Program Files, `%USERPROFILE%` itself and the data home can never
  be allowed roots. On Linux: `/`, system directories (`/usr`, `/etc`, `/proc`, `/sys`, `/dev`,
  `/run`, `/boot`, …), your home directory itself, and the data and configuration directories.
- A Claude Code session started in a subdirectory works: the repository is resolved to its git
  top level, which must lie inside an allowed root.
- The host's session folders ("client roots") only choose a default repository and produce a
  warning when the repository lies outside them; in strict mode (`client_roots.enforce`) that
  becomes an error, re-checked before every operation. In strict mode a session that reports
  no folders at all is refused too; a host without folder support (Desktop Chat) cannot be
  checked, so strict mode does not restrict it.

`code-parley doctor` shows the effective roots, Codex, git, the stored self-test and store health.

## Approving checks

Checks are commands that run **your repository's code with your privileges, outside any
sandbox**, so only you can approve them, and only through the CLI. Approval pins the exact
definitions (argv, working directory, environment, timeouts); any change needs re-approval.

Write a definitions file (argv arrays, no shell strings):

```json
{
  "checks": {
    "unit": { "argv": ["npm", "test"], "timeout_seconds": 900, "freshness_inputs": ["node_modules/.package-lock.json"] },
    "lint": { "argv": ["npm", "run", "lint"], "timeout_seconds": 300 }
  },
  "profiles": { "default": ["unit", "lint"] },
  "required_profiles": ["default"],
  "test_globs": ["test/**", "**/*.test.*"]
}
```

```powershell
code-parley checks approve --repo C:\src\app --file checks.json          # shows exactly what will run; exit 2
code-parley checks approve --repo C:\src\app --file checks.json --confirm <digest shown>
code-parley checks list --repo C:\src\app
code-parley checks revoke --repo C:\src\app
```

At an interactive terminal the command asks you to type `approve` instead of quoting the digest.

- `required_profiles` is the **verification floor**: the checks every run requires. A run can add
  required checks (`additional_required_checks`) but never remove them. If a project truly has
  none, say so with `"no_required_checks": true`.
- A repository can *propose* checks in `.code-parley/config.json` (`proposed_checks`,
  `proposed_profiles`); proposals stay inert until you run
  `checks approve --from-proposals --required-profile <name>`. (The legacy file name
  `.ai-loop/config.json` is still read when the new one is absent.)
- `freshness_inputs` (for example a lockfile) and `env_passthrough` (variable names) bind a
  result to its environment: change them and earlier results become stale.
- How `argv[0]` is found: a path names that file (relative paths are relative to the repository
  root); a bare name is looked up in the check's `PATH`. On Windows `PATHEXT` applies (`npm` →
  `npm.cmd`, run through an escaped `cmd.exe`). On Linux only absolute `PATH` entries are
  searched (an empty or relative entry is skipped, so a file planted in the repository cannot
  stand in), and the file must be an ELF executable or a script with a `#!` line (`npm` and
  `npx` are); anything else is refused rather than handed to an implicit `/bin/sh`. If a check
  needs a shell, say so in the argv: `["sh", "-c", "…"]`. Variable names are case-sensitive on
  Linux.

For a protected run the operator imports the approved checks into the custodian; a later local change
does not affect protected runs until the operator confirms it.

## Codex isolation

Codex reads source code and sends what it reads to OpenAI. CodeParley therefore runs Codex only
under an isolation level it has **verified on this machine**:

| Mode | What Codex can read | Network for commands | When used |
|---|---|---|---|
| **S1** (default, required) | only the sanitized export, the Codex installation and minimal system paths | blocked by the OS | when the offline S1 self-test passes for your Codex version and backend |
| **S2** (reduced) | any file you can read | advisory only | only after you explicitly accept it (below) and only when S1 is unavailable |

On Windows S1 is provided by Codex's **MXC** sandbox backend (`codex.windows_sandbox: "mxc"`).
Codex 0.160's `elevated` and `unelevated` backends reject the S1 profile; CodeParley never widens
the profile to make them run, and never labels anything weaker as S1. The profile needs a logon
session with an interactive desktop: run the self-test and Claude Code from a signed-in desktop
session, not from a service, PowerShell Direct or a scheduled batch logon.

On Linux S1 is provided by the **bubblewrap** sandbox Codex bundles (backend `bwrap`): Codex
runs each command in new mount, user, PID and network namespaces whose file system holds only
the export, the Codex installation and minimal system paths, with a seccomp filter on network
sockets. CodeParley pins it by refusing Codex's legacy Landlock path. It needs unprivileged
user namespaces; where they are disabled, the self-test reports the profile rejected and
reviews fail closed (see [Troubleshooting](docs/troubleshooting.md)).

**Ubuntu 23.10 and later** allow user namespaces only to programs AppArmor permits
(`kernel.apparmor_restrict_unprivileged_userns = 1`, the default). There the self-test reports
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` and reviews fail closed until an
administrator allows Codex's bundled bubblewrap: the file `codex-resources/bwrap` in the
installation directory that `code-parley codex probe` prints. A profile of the kind Ubuntu ships
for Chrome and VS Code does it. For a protected install the installer does this
(`--load-apparmor`). For manual review, this one was validated on Ubuntu 24.04.5 with the
restriction still on:

```text
# /etc/apparmor.d/codex-bwrap, then: sudo apparmor_parser -r /etc/apparmor.d/codex-bwrap
abi <abi/4.0>,
include <tunables/global>

profile codex-bwrap "<installation directory>/codex-resources/bwrap" flags=(unconfined) {
  userns,
  include if exists <local/codex-bwrap>
}
```

**Know what this grants.** AppArmor attaches the profile to the file's path, not to CodeParley
or Codex. Every local user and program that can execute that file gets user namespaces, with
capabilities inside them, through it, for itself and for everything it starts, including the
commands Codex runs in its sandbox. For that one file this reopens the kernel attack surface the
restriction exists to close. It is the same trade-off Ubuntu makes in the profiles of this kind it
ships for Chrome, VS Code and others. Use it only where that is acceptable, typically a single-user
development machine. A system-wide installation (root-owned) keeps the file from being replaced but
does not limit who can run it; to limit that, also restrict the file's execute permission to the
users who run reviews (for example a group and mode `0750`). Without the profile, reviews stay
refused. CodeParley never changes system settings by itself, and never runs Codex unsandboxed
instead.

```powershell
code-parley codex probe                    # version, flags, backend facts
code-parley codex selftest --backend mxc   # offline, no model call, about a minute; stored
code-parley codex selftest --backend bwrap # Linux
```

The first review runs the self-test automatically if none is stored. The self-test reads
canary files inside and outside the export (including one readable by every local user), tries
writes and network, and compares each with a positive control outside the sandbox; on Linux it
also checks the sandbox's namespaces, signals to and `/proc` of an outside process, inherited
descriptors and (under WSL) Windows interop. If S1 is not available, reviews fail closed with
`CODEX_ISOLATION_UNAVAILABLE`.

Only if you decide that is acceptable for your machine and code:

```powershell
code-parley codex accept-reduced-isolation --backend <backend>              # shows the statement and a digest
code-parley codex accept-reduced-isolation --backend <backend> --confirm <digest>
code-parley codex revoke-reduced-isolation
```

Every review reports its **effective isolation** (mode, backend, reads, network); a review under
S2 also records an `isolation_reduced` incident. Your user-level Codex hooks, if any, are reported
(`user_hooks_present`) because they run outside the sandbox.

## Using it

Ask Claude in natural language; it calls the tools. A typical flow:

1. **Create a run:** "Create a CodeParley review run for `C:\src\app`: the goal is …".
   `create_review_run` validates scope, records the task envelope (goal, constraints, acceptance
   criteria as context for the reviewer), fixes the verification floor and captures a baseline.
   Review target: `uncommitted` (default), `base_ref` (changes since a branch's merge base) or
   `since_baseline` (changes since the run was created).
2. **Run checks:** `run_checks` runs the floor (or named approved checks/profiles). Results show
   status, exit code, duration and whether the floor is satisfied **for the current source**.
   Raw output stays local.
3. **Request a review:** `review_with_codex` (optional `focus`, `depth`: focused/standard/deep).
   Reviews take minutes, so the call returns a handle and Claude polls `get_review_status`.
4. **Read the result:** an advisory verdict and assessment; findings triaged as
   `established_defect` / `serious_concern` (open items, carried across rounds) or
   `minor_concern` / `note`; **engine conditions** (failing, stale or missing checks; coverage
   gaps) that the reviewer cannot resolve; isolation incidents; coverage and limitations;
   freshness now and at completion.
5. **Respond:** `respond_to_review` records Claude's position on each finding (see
   [Responding to findings](#responding-to-findings-and-discussing-them-with-codex)).
6. **Fix, re-check, re-review:** after a change, re-run the checks and request a new review.
   Earlier check results become stale for the new source; the reviewer assesses each earlier
   open item (`apparently_resolved` on a newer source becomes `reported_resolved`); items it
   does not assess stay open. The new review's result lists those earlier items with their
   assessment and new status (`prior_items`), next to Claude's response recorded before that
   review. That review was shown Claude's new responses and replied to the disputes and fix
   claims (`discussion`); status shows each discussion thread and who must act next.
7. **Decide:** when status says a thread awaits you, decide it, or amend the task, in your own
   terminal ([Your decisions](#your-decisions-task-amendments-and-completion)). Status's
   `completion` says what still blocks the task.
8. **Close:** `stop_review_loop(mode: "close")` ends the run with its final open items, their
   discussion state, conditions, limitations and the completion state at closing. There is no
   PASS to set: completion is derived, and closing does not require it.

The automated loop follows the same flow, with Claude continuing on its own between steps:
[docs/protected-workflow.md](docs/protected-workflow.md).

## Responding to findings and discussing them with Codex

After a review, Claude records its response to each finding with `respond_to_review`:

| Disposition | Meaning | The finding afterwards |
|---|---|---|
| `accepted` | The finding is valid. | Still open work (`accepted_unresolved`) until a later review reports it resolved. |
| `disputed` | Claude disagrees, with a rationale. | An unresolved disagreement (`disputed`); the finding stays open. |
| `deferred` | Claude asks to leave it for later work: its position, not a decision. | Still open and outstanding (`deferral_requested`). Deferring a finding with authority is yours: `code-parley decide … defer`. |
| `fix_claimed` | Claude changed the code and claims the finding is addressed. | A claim awaiting verification (`fix_claimed_awaiting_verification`); a later review decides. If that review still finds it, the state is `fix_not_confirmed`. |

- **A response is a claim, recorded beside the finding.** It never changes the reviewer's text,
  the finding's triage or its status, and it resolves nothing; only a later review can report a
  finding resolved (per the reviewer, not engine-verified). Responses are recorded as Claude's
  (the implementer's), never as yours, whatever their text says.
- **Responses are tied to what Claude read.** Every tracked finding in a status or review result
  carries a `response_token`; a response must present it. If the finding changed since (a newer
  review assessed it, or another response was recorded), the call fails with
  `STALE_FINDING_STATE` and nothing is recorded, so a late or duplicate call never applies to a
  newer state. Up to 50 responses go in one call, recorded together or not at all; `request_id`
  makes a retry return the recorded result. Responses are recorded **between reviews**: while a
  review of the run is running the call is refused with `RUN_BUSY`; wait for it, read the
  findings again and respond to what it left.
- **Each response records the source it was made on.** A fix claim needs the current source
  identity (`SOURCE_UNAVAILABLE`, retry later, while checks hold the worktree or an operation
  waits for it); status flags a response whose source has changed since, or a fix claimed on
  the very source the reviewer saw. Other responses are recorded even when the working tree
  cannot be read completely (busy, or changing while it is read), but then their text could
  not be checked for confidential names, so every view withholds it; record them again when
  the worktree is free.
- **History is kept.** A newer response supersedes the earlier one, which stays in
  `get_review_history(run_id, responses: {finding_id?})`. When a reviewer supersedes a finding
  with a new one, the response stays with the old finding and is shown next to the new one; it
  is never carried over.
- **Recording a response sends nothing and starts nothing.** The next review that you or Claude
  request shows it to Codex (see below); `respond_to_review` previews what that review would do
  (`delivery_preview`).
- Engine conditions (checks, coverage) and isolation incidents cannot be responded to.
- Response text is stored as written and is redacted on every way out, like all host-visible
  text: withheld file names and hashes, including those of files made confidential after the
  last review (each response keeps what its own source read had to withhold), and local paths.

### The discussion with Codex

- **Responses reach Codex only inside a review.** That review shows each finding's discussion
  (Claude's new response and the earlier exchanges), labelled as the implementer's claims and
  arguments, not facts and not your decisions. Disputes and fix claims ask Codex for a reply; an
  acceptance or a deferral request on an open finding, and the answer to a question, are shown as
  context. Codex answers each with a **stance**: `maintain` (it stands by the finding), `withdraw`
  (it no longer believes the finding applies), `revise` (it changes the finding or its argument)
  or `need_information` (it says what it needs), and says whether Claude's turn brought new
  information.
- **A stance never closes a finding.** Findings leave the open set only as before: a later
  review on newer code reports them resolved, or replaces them with a more precise finding. A
  fix claim is confirmed only that way. A withdrawal on unchanged code leaves the finding open and
  flags it for your decision.
- **One discussion per issue.** When Codex replaces a finding by a more precise one, merges
  several into one, or declares a new finding the same issue (`restates_prior_id`), the discussion
  continues on the new finding as one thread, with its history and its budget. A finding that is
  merely related starts its own thread.
- **Bounded.** Each thread allows 3 exchanges (a run 50, a review 20 replies), however often the
  finding is reworded or merged. After Codex has answered, another argument is passed on only if
  it brings something new: Codex asked for information, revised its finding, the code or the
  check results changed, Claude changed its position, or Claude cites evidence it has not cited
  before. Rephrasing the same point is recorded but not shown to Codex. When the budget is spent
  or the disagreement stands without new information, the thread is **escalated**: status says a
  user decision is needed. You record it with `code-parley decide` (below); CodeParley never takes
  one on your behalf.
- **Seen means shown.** A response counts as seen by Codex only when an accepted review showed
  it; status reports, per thread, whether Codex has seen Claude's latest turn, who spoke last and
  who must act (`awaiting`: you, Claude, the next review, or nobody).
- **Informational findings** (minor concerns, notes, non-blocking questions) are listed in the
  status's `discussion.threads` with their tokens, so Claude can respond to them too.
- Before Claude's text is shown to Codex, withheld file names and hashes (from every capture and
  every response of the run) and local paths are removed; a response whose text could not be
  checked is never shown. The review's input identity includes the discussion, so a review is
  reused only if it saw exactly the same discussion.

## Your decisions, task amendments and completion

Claude's responses and Codex's replies are the agents' statements. Your decisions and your changes
to the task are a third layer, recorded only by you, with two CLI commands you run in a terminal:

```text
code-parley decide <run>                     threads with an open finding: Codex's stance, Claude's position, your decision, who must act
code-parley decide <run> <thread>            one thread in full
code-parley decide <run> <thread> <kind> [--note <text>]
code-parley amend <run>                      the task amendments
code-parley amend <run> <kind> (--text <text> | --text-file <file>) [--thread <thread>]... [--replaces <A-n>]
```

Run and thread references accept unique prefixes (8 or more characters); a thread is named by any
of its findings. The commands show what will be recorded and record it only after you type the
confirmation (the kind, or `amend`). They show your note or text with withheld names redacted, as
every CLI view does, and only at a terminal. `--request-id <id>` makes a retry safe: the same
command returns the recorded decision or amendment, even once the thread can no longer be decided,
and the same id with other arguments is refused (`REQUEST_ID_CONFLICT`).

On a protected run these commands are the operator's and the custodian holds the records:
[docs/protected-workflow.md](docs/protected-workflow.md#decisions-and-amendments-on-a-protected-run).

**Decisions** settle one thread each:

| Kind | You say | Effect while it applies |
|---|---|---|
| `require-resolution` | The reviewer's concern must be addressed: Claude's dispute or deferral request is overruled. | The thread keeps blocking completion until a review reports its findings resolved; Claude must act, not you. |
| `waive` | Proceed despite the open finding: overrule the disagreement, or accept the risk (your note says which). | The thread no longer blocks completion. The finding stays open and visible, and Codex keeps assessing it. |
| `defer` | Out of this task: follow-up work. | The thread no longer blocks completion and is reported as deferred. The finding stays open. |
| `revoke` | Your previous decision on this thread no longer stands. | The default rules apply again. |

- **A decision is bound to what you saw.** If the thread changed between the display and your
  confirmation (a review, a response, a reply, another decision or an amendment), nothing is
  recorded (`STALE_FINDING_STATE`): run the command again. Decisions are recorded between reviews
  (`RUN_BUSY` while a review of the run runs).
- **A decision covers exactly the open findings it showed you.** It lapses, and the thread waits
  for you again, if Codex later revises one of them, a new open finding joins the thread (a more
  precise successor, a restatement or a merge), or the thread's lineage is damaged. It becomes moot
  when a review reports everything in the thread resolved. Carrying the findings forward, further
  replies and Claude's new responses do not affect it, so a waiver never widens to findings you have
  not seen.
- **Records are never changed.** A later decision on the same thread replaces the earlier one;
  both stay in the history. A note (up to 2 000 characters) is stored as you typed it and is never
  sent to Codex.
- **What a decision cannot do:** make a check pass, clear an isolation incident, stand in for a
  review, or change a finding (only accepted reviews change findings). Engine conditions and
  incidents cannot be decided.

**Task amendments** change the task without rewriting it: the original task envelope stays as it
was created, and each amendment (`scope`, `constraint`, `acceptance-criteria`, `priority`,
`clarification`, or a `withdrawal` of an earlier one) is appended as `A-1`, `A-2`, …; `--replaces`
supersedes an earlier one.

- The **next review you or Claude request** presents every amendment in effect to Codex, in its own
  section labelled as your amendments, apart from the original task and from Claude's claims. The
  review's input identity includes them, so a review is never reused across different amendments,
  and its result lists what it presented.
- An amendment that names a thread (`--thread`) is new information for it: an argument held back
  for lack of new information is passed on once more. Recording the same words again counts for
  nothing, and no exchange budget is reset.
- Amendments can be recorded while a review runs; that review does not count as having seen them,
  and the next one presents them. Up to 50 per run, 4 000 characters each, 32 KB in effect.
- The text is checked against the working tree for confidential names when it is recorded
  (`SOURCE_UNAVAILABLE` if the tree cannot be read now: retry), and redacted before it reaches Codex.
- A `--text-file` is read as UTF-8 with its line endings normalized to LF and the whitespace at its
  end removed, so the same file gives the same text on Windows and Linux. The confirmation shows
  the text that will be recorded.

**Nothing starts.** A decision or an amendment starts no review, check, fix or close.

**Completion** is derived on every `get_review_status`, `stop_review_loop` and `runs show`, never
stored, and nothing can set it. It names the first state that holds and lists the blockers:

| State | Blocked by |
|---|---|
| `incomplete` | an operation running, an interrupted run, an unknown current source, an isolation containment incident, a damaged thread lineage |
| `checks_not_satisfied` | a required check failed, timed out, missing, stale, removed or unapproved, or no verification floor |
| `review_not_current` | no accepted review, a review that is no longer current, or amendments the latest review did not present (one it withheld, you replace: `amend … --replaces`) |
| `needs_user_decision` | a thread escalated for your decision, or one whose decision lapsed |
| `needs_reviewer` | a thread waiting for the next review (a reply is due, or the latest review did not assess an open finding) |
| `needs_implementer` | any other open finding without your waiver or deferral |
| `ready` | none of the above |

`ready` lists its limitations (coverage, isolation, triage per the reviewer's evidence, and the
findings you waived or deferred, which stay open) and authorizes nothing: it commits, merges and
closes nothing. `stop_review_loop(close)` does not require it and reports the state at closing.

**The trust model in manual review.** These records are *operator-authoritative*: only CodeParley's
local operator interface writes them, with the provenance `role: user, channel: local_cli, assurance:
local_operator`. The commands record only when stdin and stdout are terminals and you type the
confirmation; no flag, environment variable or file skips that. So Claude's MCP calls and its
ordinary, non-interactive shell cannot create a user record, and a response saying "the user
approved this" stays Claude's claim. It is **not** proof that a person was at the keyboard:
CodeParley trusts your local OS account, its own installation and its run store. A process running
as you with arbitrary code or file access (for example an agent that drives a pseudo-terminal,
calls CodeParley's code directly or edits the store) can create such a record, as it could already
forge reviews or check results. Run `decide` and `amend` yourself; if you allow an agent shell
access, you can deny these commands in your host's permission settings, which raises the bar but does
not stop a determined process running as you. A protected install moves these records to the
custodian, under a separate operator account: see [docs/security.md](docs/security.md).

## Status, history and cancellation

- `get_review_status(run_id, wait_seconds)` is read-only. With `wait_seconds` (≤ 50) it waits for
  the active operation and returns its full result as `completed_operation`. Without `run_id` it
  lists the runs in your allowed roots. Its `discussion.threads` lists every discussion thread
  with a finding Claude can respond to (informational ones included): the findings and their
  tokens, Claude's latest position and whether Codex has seen it, Codex's latest stance, your
  decision and its status, the exchange budget, whether new information is needed, any
  escalation, and who must act. Its `completion` and `user` (your decisions by status, and the
  amendments: recorded, in effect, not yet seen by Codex) are also in `stop_review_loop`'s result
  and `runs show`.
- `get_review_history(run_id)` pages the run's events; `artifact: {operation_id, part}` pages an
  operation's full result (`result`, `review_output`, `review_items`) when a result was
  shortened; `responses: {finding_id?}` pages the discussion history (every finding Claude can
  respond to, with its token, also when status listed only the first 40 threads; full rationales,
  Codex's replies, the reviewer's later assessments, your decisions with their status and what they
  were decided against, every task amendment with the reviews that presented it, and each thread's
  timeline of turns, presentations to Codex, replies and decisions; `finding_id` selects a whole
  thread). Raw check output, prompts and Codex event streams are never served.
- **Cancelling a call is not cancelling the work.** Pressing Esc in Claude Code, or a host
  timeout, ends only that call's wait; the operation keeps running and Claude can keep polling.
- To stop work, use `stop_review_loop`:
  - `cancel_active` with `expected_operation_id` cancels **exactly that** operation (its process
    tree is killed); a retry for an operation that already ended returns its outcome, and a
    different active operation is never touched (`OPERATION_MISMATCH`);
  - `abort` cancels whatever is active and ends the run (`STOPPED`); `close` ends an idle run.
  - The outcome is `terminated` only when CodeParley confirmed the process tree is gone;
    otherwise `cancellation_requested`, with any possible survivors named. Nothing is swept.
- From a terminal: `code-parley runs stop <run-id> --operation <operation-id>` (same semantics),
  `--abort`, or `--close`.

## What is sent to Codex, and what is not

Codex sends what it is given, and what it reads, to OpenAI.

**Sent (the review bundle and the export Codex reads):**

- the task envelope and focus text supplied through Claude (goal, background, constraints,
  acceptance criteria: reviewer context);
- the prepared diff of the change (capped) and the export manifest (names, sizes and hashes of
  exported files; only **counts** of withheld files);
- the exported files of the repository that are not withheld (current versions, and base versions
  of changed files), which Codex reads inside its sandbox;
- check **metadata**: name, required or optional, status, exit code, duration, timeout,
  freshness;
- earlier open reviewer findings, for re-assessment, with their discussion: Claude's responses
  that earn an exchange and earlier replies, with withheld names and hashes and local paths
  removed; a response whose text could not be checked is never sent;
- your task amendments in effect, as your own task context, with withheld names and hashes and
  local paths removed; one whose confidentiality check could not finish is not sent (and completion
  stays `review_not_current`, with `amendment_withheld`, until you replace it);
- repository instruction files (`AGENTS.md` …) **only** if you set
  `codex.load_project_instructions`, quoted as untrusted data;
- for a delegated fix, the task text and boundary, and the files of the disposable copy Codex edits.

**Never sent:**

- confidential files: content, names and per-file hashes of everything matching
  `capture.exclude_globs` (defaults: `.env`, `.env.*`, `*.env`, `.envrc`, `*.pem`, `*.key`,
  `*.pfx`, `*.p12`, `id_rsa*`/`id_dsa*`/`id_ecdsa*`/`id_ed25519*`, `*.kdbx`, `.netrc`, `_netrc`
  and variants);
- raw check output (stdout/stderr): it can print anything the check's code can read;
- git history, the object store and `.git`; files outside the export (under S1);
- the targets of symlinks, junctions or hard links, and anything below a mount point inside the
  repository (Linux, bind mounts included): never followed or exported;
- environment variables, Claude/Anthropic credentials, and local paths such as the run store
  (Codex's own working-directory context is turned off);
- your decisions and their notes: they act on completion, not on Codex.

The host model (Claude) sees the same withheld-name protection in every tool result and error,
and never receives raw check output.

## The local run store

Everything stays in the **data home**, `%LOCALAPPDATA%\CodeParley` on Windows and
`~/.local/state/code-parley` (`$XDG_STATE_HOME/code-parley`) on Linux, where it is created
private to you (`0700`) and refused if other users can write to it (override with `--home`,
which then holds `config.json` too):

| Path | Contents |
|---|---|
| `config.json` | your configuration (Linux: in `~/.config/code-parley/` unless `--home` is given) |
| `trust\projects.json`, `trust\isolation.json` | approved checks; reduced-isolation acceptances (CLI-written) |
| `selftest\` | stored Codex sandbox self-test results |
| `runs\<repo-key>\<run-id>\` | `run.json` + `state.json` (the authoritative record of a manual run), operation artifacts, **review exports (copies of your repository files)**, prompts, Codex event streams, check logs |
| `locks\`, `logs\` | worktree locks; server logs (no environment values, no source content) |

The custodian's protected store is separate: `C:\ProgramData\CodeParley\Custodian` on Windows,
`/var/lib/codeparley` on Linux.

**Retention.** When a server starts it deletes runs with no activity for
`retention.max_age_days` (default 30), but never a run that is active or unresolved: running
operations (even of a server that died), `INTERRUPTED` runs, runs referenced by a worktree lock,
unreadable or newer-format records, and anything reached through a link are kept and reported.
Deletion never follows links (including junctions to volume GUID paths, which Node does not
report as links) and never enters a mount point, and on Windows a run with a file held open is
left untouched. Old server logs are pruned too. Set `"purge_on_startup": false` to keep everything
until you purge yourself. `code-parley doctor` shows the last retention pass.

```powershell
code-parley runs list                       # every run, with its state and retention status
code-parley runs show <run-id>              # operations, checks (with local log paths), reviews, open items, incidents, events
code-parley runs purge --older-than 14      # preview; exit 2
code-parley runs purge --older-than 14 --confirm <token>   # deletes exactly what was previewed
code-parley runs purge <run-id> …           # specific runs (same safety rules)
```

`runs list/show` redact withheld file names by default (their output may end up in a model's
context); `runs show --reveal-withheld` lists them locally.

Earlier builds stored data in `%LOCALAPPDATA%\AIReviewLoop`. If that folder exists and no
`CodeParley` folder does, it is used as is (`doctor` says so). To move it, close every host that
uses CodeParley, then rename the folder to `CodeParley`.

## Recovery after a crash

If a server dies (host crash, Task Manager), the next operation or stop on that run records it:

- the interrupted operation is marked `interrupted` and the run `INTERRUPTED`;
- an interrupted **check** leaves the repository's worktree lock `ownership_unresolved`,
  because commands it started may still be running. New checks and captures are refused
  (`WORKTREE_OWNERSHIP_UNRESOLVED`) until you inspect and release it:
  `code-parley lock show --repo <path>`, then
  `code-parley lock release --repo <path> --confirm <operation-id>`;
- an interrupted **review** records a `possible_surviving_sandboxed_commands` incident (sandboxed
  commands have no repository access and no network);
- nothing is killed unless it is provably the recorded process, and nothing is swept.

What survives the server differs by platform. On Windows each process's direct children sit in
a kill-on-close job and die with it, while a detached descendant (or an MXC sandboxed command)
can survive. On Linux every child CodeParley starts leads its own session, and a small helper
process per server (the session reaper) ends those sessions, with every process still linked
to them, when the server dies, even by `SIGKILL`; a descendant that started its own session
*after its parent had exited* cannot be linked and is reported, never killed. The worktree lock
stays `ownership_unresolved` either way: an empty process list is never taken as proof.

Inspect with `code-parley runs show <run-id>`; continue with a new operation, or end the run with
`code-parley runs stop <run-id> --close`.

Recovery after a reboot, an upgrade or an interrupted delegated fix is in
[docs/troubleshooting.md](docs/troubleshooting.md).

## Troubleshooting

Start with `code-parley doctor` (add `--protected --repo <path>` on a protected install) and
`code-parley status --repo <path>`. Every refusal code, the Linux sandbox and file-system cases and
the recovery paths are in [docs/troubleshooting.md](docs/troubleshooting.md).

## Known host behaviour

Observed with Claude Code 2.1.286 and 2.1.289 and Claude Desktop 2.19675.0 (MSIX):

- **Desktop Chat asks for permission on every call** of a user-added local server, read-only
  tools included (the annotations are correct on the wire). Destructive tools (`run_checks`,
  `stop_review_loop`) always prompt; you may choose to always allow the read-only ones.
- **Desktop Code-tab sessions share one server process** (Chat has its own). Their session
  folders are combined into one set of client roots; cancellation between Code-tab sessions is
  in-process; the server lives as long as Desktop keeps it.
- **Desktop speaks protocol 2025-11-25** to local servers. Standalone Claude Code negotiated
  2026-07-28 with `MCP_PROTOCOL_NEGOTIATION=auto` (2.1.286) and by default (2.1.289). Both eras
  work.
- Desktop Chat applies a per-call limit (60 s for user-added local servers unless your
  administrator changed it); CodeParley's calls return within about 45 s (a status call that
  waits, within 55 s) and hand back a handle when the work is not finished.
- The Code tab may rewrite the advertised input schemas (dropping `additionalProperties: false`);
  the server validates arguments strictly regardless.
- Esc in Claude Code (and a host timeout) cancels only the call's wait: see
  [cancellation](#status-history-and-cancellation). In a live automated loop it also pauses the
  automation.
- **When a standalone session ends** while CodeParley still runs one of its operations, the server
  starts cancelling it at once, but Claude Code (2.1.289, `claude -p`) terminated the server
  before the outcome could be recorded. The check's process tree ended with the server (Windows
  job objects end each `node.exe`'s children; commands started through a `.cmd` shim can
  survive, see [Recovery](#recovery-after-a-crash)). The run then shows `INTERRUPTED`, and the
  next operation or `runs stop` records it. Stop or wait for operations before ending a session.
- Local paths outside your repository are replaced in results (`[data home]`, `[user profile]`,
  `[local path]`, …); for unknown paths containing spaces this is best effort.

## CLI reference

`code-parley help` prints the same list. On Linux the operator runs the operator commands (`setup`,
`decide`, `amend`, `loop`, `config`, `fix review`, `fix confirm`, `fix reject`, `runs stop --repo`) through
`/usr/local/sbin/code-parley-operator`, by that absolute path; on Windows the operator runs them as
`code-parley` in an elevated terminal. `config propose` and `config propose-selftest` are the
implementer's.

```text
usage: code-parley <command> [options]

Setup and status
  init           --repo <path> [--max-fixes <0-10>] [--dry-run]
  status         [--repo <path>] [--json]
  setup          --repo <path> [--resume] [--fix] [--codex <exe>] [--backend <b>] [--proposal-file <file>]...
                 [--runtime <dir> --runtime-git-path <git>] [--loops <n> --minutes <m> | --no-grant]
  doctor         [--protected [--repo <path>]] [--codex <codex executable>] [--config <file>]
                 [--allowed-root <dir>]... [--json]

Checks and locks
  checks list    --repo <path>
  checks approve --repo <path> (--from-proposals | --file <defs.json>) [--required-profile <name>]...
                 [--no-required-checks] [--test-glob <glob>]... [--confirm <digest>]
  checks revoke  --repo <path> [--confirm <digest>]
  lock show      --repo <path>
  lock release   --repo <path> [--confirm <operation-id>] [--force]

Codex
  codex probe    [--codex <codex executable>]
  codex selftest [--backend mxc|elevated|unelevated (Windows) | bwrap (Linux)] [--codex <codex executable>]
  codex fix-selftest [--backend mxc (Windows)] [--codex <codex executable>]
  codex accept-reduced-isolation --backend <b> [--confirm <digest>]
  codex revoke-reduced-isolation [--acceptance <id>]

Runs
  runs list      [--repo <path>] [--json]
  runs show      <run-id> [--events <n>] [--reveal-withheld] [--json]
  runs stop      <run-id> --operation <operation-id> [--reason <text>] [--wait <seconds>]
  runs stop      <run-id> --abort [--operation <operation-id>] [--reason <text>]
  runs stop      <run-id> --close [--reason <text>]
  runs stop      <full-run-id> (--close | --abort) --repo <path> [--reason <text>]
  runs purge     (<run-id>... | --older-than <days> | --retention) [--repo <path>] [--dry-run]
                 [--confirm <token>] [--json]

Decisions and amendments (record only at an interactive terminal; listings work anywhere)
  decide         <run-id> [<thread> [require-resolution | waive | defer | revoke]] [--note <text>]
                 [--protected] [--request-id <id>] [--json]
  decide         <run-id> … --repo <path>
  amend          <run-id> [scope | constraint | acceptance-criteria | priority | clarification | withdrawal]
                 (--text <text> | --text-file <file>) [--thread <thread>]... [--replaces <A-n>]
                 [--protected] [--request-id <id>] [--json]
  amend          <run-id> … --repo <path>

Loops
  loop grants    [--json]
  loop allow     --repo <path> [--loops <n, 1-8>] [--minutes <m, 1-180>] [--request-id <id>]
  loop revoke    --repo <path>
  loop show      <run-id> [--repo <path>] [--json]
  loop stop      <run-id> [--repo <path>] [--reason <text>]
  loop resume    <run-id> [--repo <path>]

Protected configuration
  config show    --repo <path> [--json]
  config set     --repo <path> [--codex <codex.exe> | --proposal-file <file>]
  config propose --repo <path> --out <file> [--codex <exe>]
  config propose-selftest [--fix] --repo <path> --out <file> [--backend <b>] [--codex <exe>]
  config reconfirm --repo <path>
  config revoke  --repo <path>
  config accept-isolation --repo <path> --backend <b> [--codex <exe>]
  config confirm-selftest [--fix] --repo <path> (--backend <b> [--codex <exe>] | --proposal-file <file>)
  config approve-runtime --repo <path> --runtime <dir> (--runtime-git <rel git.exe> | --runtime-git-path <installed git.exe>)
  config reconfirm-runtime --repo <path> <runtime-id>
  config revoke-runtime --repo <path> <runtime-id>
  config revoke-isolation --repo <path> <acceptance-id>
  config revoke-selftest --repo <path> <confirmation-id>

Delegated fixes
  fix review     [--repo <path>] [--no-pager]
  fix show       <run-id> [<proposal>] [--repo <path>]
  fix confirm    <run-id> <proposal> --repo <path>
  fix reject     <run-id> <proposal> --repo <path>
  fix reconcile  <run-id> [--restore | --leave]

Global options: --home <data dir>  --git <git executable>  --config <file>
Exit codes: 0 ok, 1 error, 2 confirmation required, 3 cancellation requested but termination not confirmed,
4 a stop did not establish that no confirmed fix can run
```

With `--repo`, `decide`, `amend`, `loop show|stop|resume` and `fix show` act on the run as the
custodian holds it: for an operator who cannot read the implementer's run store. `decide … --repo`
shows structure only; `amend … --repo` has the custodian redact the text and hold what Codex sees.

Server: `node dist/server/main.js [--allowed-root <dir>]... [--home <dir>] [--config <file>]
[--codex <exe>] [--git <exe>] [--diagnostics]`.

## Development

```powershell
npm ci
npm run typecheck
npm run build
npm test
```

While developing, `npm run test:quick` runs the test files that are fast in CI and `npx vitest run
test/<file>.test.ts` a single file; `npm test` is the full suite a change has to pass
([docs/development.md](docs/development.md#fast-feedback-and-full-validation)).

CI (`.github/workflows/ci.yml`) runs these on Windows and Linux with Node 26, the one supported
Node.js major, for pull requests into any branch, pushes to `main` and manual runs
(`gh workflow run CI --ref <branch>`): the same nine jobs every time. A new commit on a pull request, or
a new manual run on the same branch, cancels the older run; a later merge does not cancel a `main`
run. Plain branch pushes and documentation-only changes (Markdown at the repository root and in
`docs/`; not `prompts/`, which holds the product's reviewer prompt) do not start
it. Both platforms are gates: each runs the platform-independent tests, the shared contracts
and its own platform's integration suites (real repositories, processes, links, the server over
stdio); the other platform's are reported as skipped
([docs/development.md](docs/development.md#test-classes)). Each platform and Node.js version
runs a verify job (typecheck, build, the custodian's self-tests, the install smoke test, the plugin check) and, in
parallel, test shards (four on Windows, two on Linux) that together run every test file once. Live validation with a
logged-in Codex and real Claude hosts is manual; for example
`CODEPARLEY_LIVE_CODEX=1 npx vitest run test/review-live.integration.test.ts` spends Codex quota.

The custodian (`custodian/`) is a .NET 10 service; its SDK is pinned by `custodian/global.json`.

This repository starts at 1.0.0 from a reviewed snapshot of the sources; the development history and
the release-validation evidence are kept in a private archive. How the published sources relate to
the commit the 1.0.0 artifacts were built from is in
[docs/verifying-releases.md](docs/verifying-releases.md#source-provenance).

## License

Apache-2.0: see [LICENSE](LICENSE). The release artifacts also contain third-party software under its
own licenses: see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
