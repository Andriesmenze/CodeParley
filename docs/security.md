# Security

## The claim

CodeParley 1.0 holds the authority for the protected loop and for delegated fixes in a
**custodian**: a separate service, under its own identity, with a store the implementer account
cannot write. Loop grants, budgets, the approved configuration, the operator's decisions and the
confirmation of a delegated fix live there, and the custodian decides each protected request itself.

That is the whole claim, on Windows 11 x64 and Ubuntu 24.04 x86_64, with the limits below.

**CodeParley does not claim production-secure unattended operation.** Its protected mode separates
authority from the implementer. It does not prove who produced every piece of evidence, and it does
not prove that a person was at the operator's keyboard.

Manual review has no custodian. There CodeParley trusts your local OS account, its own installation
and its run store. A process running as you can forge anything in it.

## What each party is

| Party | What it is | Trusted for | Not trusted for |
|---|---|---|---|
| **Implementer** | Claude, in the Claude Code session you started, running as a standard account | Doing the work | Anything that grants authority. Its statements are claims |
| **Reviewer** | Codex, launched by CodeParley on a sanitized snapshot, read-only under S1 | An independent opinion | Being right: findings are reported per the reviewer's evidence |
| **Operator** | A person using a separate account: an elevated administrator on Windows, a separate login on Linux | Approving configuration, grants, decisions and fix confirmations | Nothing in CodeParley can prove the person was there |
| **Custodian** | A service: `NT SERVICE\CodeParleyCustodian`, or the account `codeparley`. Store in `C:\ProgramData\CodeParley\Custodian` or `/var/lib/codeparley` | Holding authority and enforcing its own rules. It fails closed | Knowing that an engine's report is true: see below |
| **Helper** | A least-privileged service identity the custodian starts: `NT SERVICE\CodeParleyHelper`, or `codeparley-helper`. It runs the approved engine runtime and reads repositories through the readers group | Measuring and capturing a protected run | It is not a sandbox: see below |

## What the custodian protects

- **Authority cannot be created by a model.** No MCP tool, hook or model text can grant a loop,
  record a decision, approve configuration or confirm a fix. Those commands reach the custodian only
  on its operator surface, and the custodian classifies the caller by the OS, not by what the caller
  says.
- **Operator records are rendered by the custodian.** It computes what will be recorded, renders it
  and binds your typed confirmation to the digest of that rendering. A confirmation covers exactly
  what you saw.
- **Budgets are the custodian's.** Grants and their ceilings, a loop's continuations, wake-ups and
  deadline, and a run's review, check and fix budgets are counted there.
- **Approved configuration is held there.** Protected runs use the checks, capture rules and exact
  Codex file the operator approved, not the local files. A changed Codex or engine runtime is
  refused until it is approved again.
- **Completion on a protected run is derived there.** The custodian derives completion and the next
  step from the records it holds, and it refuses a continuation its own derivation does not support.
- **Evidence is bound.** Review captures are made by the helper; run records and evidence are held
  under digests the custodian checks, so a later edit is detected. This proves integrity since
  recording, not who produced the evidence.
- **A delegated fix cannot reach your tree without you.** Codex edits a disposable copy. The
  custodian validates the result against the boundary and its own baseline and holds it. A
  confirmation is single-use, expires, and is bound to the exact content. The working tree is
  re-measured before anything is written.
- **Failure closes.** Without a validated custodian, protected loops and delegated fixes are
  refused. There is no fallback to user-writable state. A client that meets an endpoint the
  custodian does not own refuses it.
- **Restores do not resurrect authority.** A rollback ends open protected runs, voids unconsumed
  confirmations, suspends grants and lapses approvals.
- **A restart resets trust.** Operator records lapse and grants suspend at every restart of the OS.

## Limits

These are the known limits of this release. They are stated as they are.

### Evidence comes from the implementer's side

- **Check outcomes and reviewer output are produced in the implementer's session.** The custodian
  measures what went in: the source, the check definition, the executable. The outcome that comes
  back (status, exit code, output digests) and the reviewer's output are the engine's report. A
  process inside the bound session can begin its own operations and record forged results, within
  the budgets. The custodian holds these records; it does not prove they are true.
- **Some environment facts are claims too:** the environment digest, whether Codex was launched as
  stated, and the contents of a self-test's rows. The custodian binds its own measurement of the
  binaries and, on Linux, of the sandbox's basis and the boot, but not the row results.
- **Process correlation is not authentication.** The custodian checks that a caller belongs to the
  session the loop is bound to, by process, not by a credential. The session's own tool commands, or
  a child that a process of the same user starts under the Claude process, pass that check, still
  only within the budgets, the binding and the deadline.
- **Checks have no isolated identity.** Approved checks run your repository's code with the
  implementer's privileges, outside any sandbox. They can modify files and use the network.
- **Evidence from before a loop started never counts as protected.** A run can be cancelled by an
  edit of its local store; that only loses the review. Deleted local artifacts cost availability and
  fail closed.

### Operator assurance

- **On Windows, operator authority is an elevated administrator token.** The custodian accepts
  operator records only from the operator account with an elevated token. It does not prove a human
  was present. An interactive terminal and a typed word are a guard, not proof. How a genuinely
  non-elevated token of the operator account is treated has not been tested on a real logon: treat
  that as unknown.
- **On Linux, operator authority is a separate login.** The custodian classifies the caller by the
  socket's peer credentials. Anyone with that login is the operator.
- **The Linux wrapper's check is a mis-installation check.** `OPERATOR_CODE_UNTRUSTED` catches a
  copied tree or a dropped environment variable. It is not a security proof. The guarantee is the
  root-owned installation's file permissions.
- Hardware-backed operator confirmation is not part of this release.

### The helper

- **The Windows helper has outbound network access.** There is no firewall rule. Code running as the
  helper can reach the Internet.
- **The Windows helper's own service profile is writable by the helper.** The workload does not use
  it, but code running as the helper could leave something there.
- The helper runs only the approved runtime, on repositories an administrator granted.

### Measurement gaps

- **Shared libraries and git helpers are not measured.** The approved `node`, `git` and Codex load
  system libraries and helpers from administrator-owned paths that the custodian does not hash.
- **A prompt template edited in place is not detected when it is loaded.** Its id, version and
  digest are recorded with each review.

### Store durability and rollback

- **Durability was verified on the tested VMs.** Acknowledged records survived one hard power-off of
  a Hyper-V guest. That exercises the guest's flush path, not physical device caches. No universal
  power-loss guarantee is claimed: recovery is what is relied on. It runs at every start in a new
  boot, and nothing restored takes effect without an operator action.
- **A rollback of files outside the installer is not closed.** If an administrator copies store
  files back, or storage loses writes the custodian had flushed, the custodian may lose the record
  that a run was protected. A process of the same user that clears the local hint then returns that
  run to attended operation, with no automation, no counted grant use and no authoritative evidence
  carried over. Use the installer's `rollback`.
- **There is no store-repair command on Linux.** A store that fails validation stays down until an
  administrator repairs it. On Windows, an administrator must take ownership to inspect a held
  export.

### Linux sandbox and service hardening

- **The AppArmor exception.** `--load-apparmor` allows user namespaces for one file, the copied
  `bwrap`. AppArmor attaches to the path, so every local user who can execute that file gets user
  namespaces, with capabilities inside them, through it, for itself and everything it starts. For
  that file this reopens the kernel attack surface the restriction exists to close. It is the same
  trade-off Ubuntu makes for Chrome and VS Code. It is an approved, machine-wide change: use it
  where that is acceptable.
- **Nested user namespaces are possible inside the sandbox.** Recorded by the self-test, neither
  passed nor failed.
- **`RestrictSUIDSGID` is off for the custodian's unit,** because it blocks `openat2`, which the
  custodian's path safety relies on. The kernel therefore does not stop the custodian process from
  creating set-user-ID files. The empty capability set, `NoNewPrivileges`, the single writable store
  path and the refusal of such files in the store at start reduce the exposure. They are not an
  identical substitute.
- **Repository identity is collision-resistant, not collision-proof.** It is built from the admitted
  filesystem, a file handle and the birth time. That those handles stay stable beyond reboots is
  inferred, not proven. Repositories must be on the root filesystem.
- **Process metadata in `/proc` is public.** Parent ids and start times are readable by local users;
  they carry no secrets, and the store is not readable that way.
- **A proposal file is readable by every local user while it exists.** `config propose` writes mode
  `0644` so the separate operator account can read it. It holds check definitions and digests; do
  not put credentials in check definitions. Delete it afterwards. Its transport is outside the
  custodian's guarantees: the custodian renders what it records.

### Delegated fixes

- **Racing writers of the same user are detected, not prevented.** The checks at use catch a
  replaced, redirected or changed target and fail or roll back. A same-user process can still race
  between the last check and the rename. A temporary file can remain after a redirected parent.
- **No atomic multi-file write.** Files are written one at a time, and a failure restores what was
  written.
- **Binary and non-UTF-8 changes cannot be reviewed.** They are rendered as sizes and hashes only,
  flagged.
- **Paths are ASCII only.**
- **The fixer sees only the exported tree,** never confidential files or history. Its result can be
  wrong for that reason.
- **The implementer can read held proposals,** with `fix show`. It cannot change or confirm them.
- **Claude cannot read a proposal's content over MCP.** `get_review_status` gives paths, kinds and
  sizes; the content is in `fix show`. Do not count on Claude's opinion of a patch it saw only as
  metadata.
- **A running `delegate_fix` cannot be cancelled over MCP.** It ends at its time limit.
- **Native confinement is scoped.** On Windows, Codex's native edits go through its own
  low-integrity file-system helper. They were observed only inside the workspace; that the OS would
  deny that helper a write outside it is inferred, not directly verified.
- **Two tamper cases were not demonstrated on Linux.** Tampering with a proposal's held content
  needs privileged access to the custodian's store, and that test was inconclusive on the test VM.
  The refusal of a proposal that re-renders successfully to a different digest than the one
  confirmed was not exercised.

### Stopping a confirmed fix

A confirmation has no withdrawal of its own in this release. It can only be stopped from outside:

- `fix reject` works only on a proposal that is still pending. It is refused on a confirmed fix.
- `loop revoke`, `loop stop` and revoking the FIX self-test confirmation do not stop a confirmed fix.
- **`config revoke --repo <path>` blocks it.** The custodian refuses the application, and the confirmation stays unused.
- **That block is a suspension, not a cancellation.** Setting the configuration again makes an original confirmation
  applicable while it is unexpired and unused, and one recorded during the revocation too. This is a stated limit, not a way
  round the confirmation: it stays single use, expires within 30 minutes, covers only the exact confirmed content, and the
  working tree must still match the baseline. Checks and a fresh review still come before `ready`.
- **Ending the run stops it for good.** The custodian then refuses every new application and removes the held content.
  The operator ends a run with the command below, which reads no run store, so a missing, corrupted or forged local
  record can neither block it nor stand in for it:

  ```text
  code-parley runs stop <full-run-id> (--close | --abort) --repo <path>
  ```

  On Linux that is `/usr/local/sbin/code-parley-operator`, as the operator account. The implementer's
  `code-parley runs stop <run> --close` ends the run too.
- **The run ends only when the custodian says so.** A stop exits 0 only on the custodian's acknowledgment. It exits 4 when
  that was not established: refused, not delivered, or an answer that was lost (it is safe to repeat). The two ids only
  locate the run: a wrong pair is refused `RUN_NOT_OPEN`, which proves nothing about any other run, so it also exits 4.
- **An application that had already begun is not recalled.** The stop reports it and exits 4, even though the end was
  acknowledged. No application can begin after the end.
- **`--close` is refused while an operation runs** (`RUN_BUSY`): use `--abort`. With `--repo`, nothing local is cancelled:
  a running operation finishes on its own, and the implementer's record catches up on its next call.
- **If the custodian cannot answer, the run has not ended.** Use `config revoke` to block applications in the meantime,
  remembering that it is a suspension: it does not withdraw a confirmation, and setting the configuration again lifts it.
  Repeat the stop once the custodian answers.

### Availability

- **One request at a time.** The custodian serves one client per surface. Right after a boot, its
  first protected request measures the engine runtime (on Windows about 13 to 55 seconds on the test
  VM), and a queued call can be refused `CUSTODIAN_BUSY`. It fails closed.
  [Recovery](troubleshooting.md#custodian_busy).
- **Measurement and capture take time on large repositories.** On Linux, 100 000 files took about
  10.4 minutes to capture; on Windows, about 15 minutes.
- **Re-confirmations are a cost of the design.** Every boot, upgrade and reinstall needs the
  operator again. `status` and `setup --resume` make that short, not absent.
- **The 15-minute loop window bounds reconnection.** After it, a new process cannot re-bind to a
  run. In a headless `claude -p` session the wake-up hook can hold a review turn for up to its
  15-minute cap.
- **One S1 confirmation per Codex binary and backend.** Two data homes on one machine using the same
  Codex cannot both have a confirmed S1 basis: the later one wins, and reviews from the other are
  refused.
- **On Windows the transport needs PowerShell 5.1 in FullLanguage mode.** A Constrained Language,
  AppLocker or WDAC policy blocks it, and it fails closed.
- **Pipe re-listen gap on Windows.** The custodian recreates its listening instance after each
  connection. A process of the same user could take the name in that gap, and the surface stops
  serving. That is a denial of service, never a bypass: clients refuse an endpoint the custodian
  does not own.

### Hosts

- **Claude Code (CLI) is the only supported host for the protected workflow.** The Claude Desktop
  delegated-fix workflow is untested, and no claim is made for it. Desktop is manual review only.
- **The plugin is not a security boundary.** Its hooks run as the implementer.

## What is not claimed

- Production-secure unattended operation.
- That `ready`, or anything else here, authorizes a commit, push, merge, tag, release or deployment.
- That findings are correct or complete, or that passing checks prove a problem absent.
- That a person was present for any operator record.
- That a compromised administrator, or root, is contained. Both are outside the boundary.
- Protection on any platform other than the two named above, including WSL2.
- That the installers verify the release signature. They check size, SHA-256 and BUILD-ID against
  the manifest; [verify the manifest's signature yourself](install.md#verify-a-release).

## Where your code goes

Codex sends what it is given, and what it reads, to OpenAI. The
[README](../README.md#what-is-sent-to-codex-and-what-is-not) lists exactly what is sent and what is
not.
