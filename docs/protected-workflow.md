# The protected workflow

A protected review is a CodeParley review whose authority does not live in the implementer's
account. The custodian, a separate service with its own store, holds the loop grants, the run's
records and budgets, the operator's decisions, and the approved configuration. It decides what is
allowed. The implementer, Claude in your Claude Code session, asks.

This page assumes a repository that `code-parley status --repo <path>` shows as `READY`
([docs/install.md](install.md)). Claude Code (CLI) is the only supported host. What is and is not
protected is in [docs/security.md](security.md).

In the commands below, *operator* means:

| | Run it as |
|---|---|
| Windows | `code-parley <command>` in an elevated terminal, as the operator account |
| Linux | `/usr/local/sbin/code-parley-operator <command>`, as the operator account, by that absolute path |

Operator records need an interactive terminal: you type the confirmation, and no flag skips it.

**Opening the operator terminal on Windows.** Sign in to Windows as the operator account, or stay in
your own session and start Windows Terminal or PowerShell with *Run as administrator*, entering the
operator account's credentials at the UAC prompt (on a standard account, UAC asks for an
administrator's credentials: give the operator account's). Check it with `whoami` (the operator
account) and that the window title says *Administrator*. A terminal that is not elevated, or another
account's, is refused by the custodian: nothing is recorded.

## The roles

| Role | Who | Can | Cannot |
|---|---|---|---|
| Implementer | Claude, in the session you started | Change code, run approved checks, request reviews, respond to findings, delegate a fix, apply a confirmed fix | Grant a loop, record a decision, confirm a fix, change the protected configuration |
| Reviewer | Codex, launched by CodeParley | Read a sanitized snapshot and report findings | Change anything; it is non-mutating |
| Operator | You, at an operator terminal | Approve configuration, grant loops, decide, amend, confirm or reject a fix | Set completion: nobody can |

There is one implementer per operation. CodeParley keeps the session that started a loop working; it
never starts, restores, forks or replaces a Claude session, and needs no second Claude login.

## How a protected run goes

Ask Claude in natural language, for example: "Create a CodeParley review run for this repository,
the goal is …, and start the review loop."

1. **Create the run.** `create_review_run` records the task and captures a baseline.
2. **Start the loop.** `start_review_loop` registers the run with the custodian and consumes one
   granted loop. The run is protected from here on. The plugin binds the loop to this session. Start
   the loop before the checks and the review: evidence from before protection never counts as
   protected evidence.
3. **Run the checks.** `run_checks` runs the approved checks the custodian holds, not local edits of
   them.
4. **Review.** `review_with_codex` has the custodian's helper capture the source and Codex review it
   under S1. Claude ends its turn while the review runs; the controller wakes the session when it
   finishes.
5. **Respond and fix.** Claude records its response to each finding and changes the code, or
   delegates a fix.
6. **Repeat** checks and review on the new source, within the limits below.
7. **Decide,** when status says a thread needs you
   ([below](#decisions-and-amendments-on-a-protected-run)).
8. **Finish.** The loop ends at `ready`. What to do with the result is yours.

`get_review_status` shows the custodian's completion and next action for a protected run, labelled
as the custodian's. If the custodian's answer is unavailable, status shows the server's own, marked
as not authoritative, and automation fails closed.

## Loop grants

A grant is the only way an automated loop can start. No tool, hook or model text creates or enlarges
one.

```text
loop allow  --repo <path> [--loops <1-8>] [--minutes <1-180>]    (operator; default 1 loop, 60 minutes)
loop revoke --repo <path>                                        (operator)
loop grants [--json]                                             (the grants and ceilings)
```

`setup` offers the same grant as its last step. The custodian renders what it will grant, you type
`allow`, and it enforces its own ceilings. Each `start_review_loop` consumes one loop; one run has
one loop, ever. A grant ends when its loops are used, when it expires, when it is revoked, or at a
restart of the OS, which suspends it for good: a new grant is needed. Revoking leaves loops already
started running; `loop stop` ends one.

## What a loop can do by itself

Within one loop the controller may, at most:

| Limit | Value |
|---|---|
| Automated continuations (keeping a turn going when Claude tries to stop) | 2 |
| Idle wake-ups when an awaited review finishes | 2 per run, 1 per review |
| Automation window | 15 minutes |

No argument can raise these. A continuation happens only for a step that is Claude's. Controller
texts start with `[CodeParley controller — automated; not the user]`: they are not you, and they
carry no decision.

The window also bounds who can reconnect. After 15 minutes the session that holds the loop keeps
working, but a **new** process cannot re-bind to the run, and its protected operations are refused
`PROCESS_IDENTITY_UNVERIFIED`. So keep the session open for a run's whole life, including while it
waits for your decision on a fix.

**Automation pauses** on:

| Reason | What ends it |
|---|---|
| You interrupted the session (Esc, for example) | `loop resume <run>` |
| A thread needs your decision | `code-parley decide`, then `loop resume <run>` |
| A condition only the operator can resolve (configuration, approvals, an isolation incident, a damaged thread) | Fix the condition; see the message |
| An operation did not complete | `loop resume <run>`; automation does not retry it |
| The session's settings changed | `loop resume <run>` |
| The session's process identity could not be verified | Nothing continues or wakes this session automatically |
| The custodian found no change since the last continuation | `loop resume <run>` |

`loop resume` is the operator's, at an interactive terminal; you type `resume`. It shows the
budgets, the decisions in force and what lapsed, and it records no decision. After a restart of the
OS it offers the configuration's re-confirmation first. While a thread still needs a decision it is
refused.

**Automation ends** at `ready`, at its budget or deadline, when the run ends, or when you stop it:

```text
code-parley loop stop <run> [--reason <text>]
```

Stopping needs no confirmation, because it only reduces automation. `loop show <run>` shows the
loop's state, budgets and binding. An operator who cannot read the implementer's run store adds
`--repo <path>` and the full run id to act on the run as the custodian holds it; on Linux that is
always the case.

## Decisions and amendments on a protected run

The meaning of each decision and amendment is in the
[README](../README.md#your-decisions-task-amendments-and-completion). On a protected run the
custodian holds them, and they are the operator's.

Windows, in an elevated terminal:

```powershell
code-parley decide <run> --home <implementer's data home>
code-parley decide <run> <thread> waive --protected --home <implementer's data home> --note "<why>"
code-parley amend <run> constraint --text "<text>" --protected --home <implementer's data home>
```

Linux, as the operator:

```bash
/usr/local/sbin/code-parley-operator decide <run-id> --repo <path>
/usr/local/sbin/code-parley-operator decide <run-id> <thread> waive --repo <path> --note "<why>"
/usr/local/sbin/code-parley-operator amend <run-id> constraint --text "<text>" --repo <path>
```

With `--repo` you act on the run as the custodian holds it. `decide` shows structure only; `amend`
has the custodian redact the text, and it shows exactly what Codex will see before you confirm.

## Delegated fixes

A delegated fix is one scoped change that Codex makes in a disposable copy. It is off by default,
and it takes a deliberate opt-in plus your confirmation of the exact content. Normal review and
Claude fixing the code itself work with it off.

### Opting in

[docs/install.md](install.md#turning-on-delegated-fixes) has the commands. Three things must be in
place:

1. A fix budget: `code-parley init --repo <path> --max-fixes <1-10>`, then restart sessions. A new
   run picks it up.
2. A FIX self-test the operator confirmed: `code-parley codex fix-selftest`, then `setup --fix`.
   This is separate from the S1 self-test; a local pass confers nothing until the operator confirms
   it.
3. A protected run: a loop started on it, with at least one finished review.

Otherwise `delegate_fix` is refused with `FIX_DELEGATION_UNAVAILABLE`,
`CODEX_ISOLATION_UNAVAILABLE`, `BUDGET_EXHAUSTED` or `EVIDENCE_NOT_HELD`, and nothing is begun.

### From request to application

**1. Claude delegates.** `delegate_fix` takes a task and a boundary, never contents or a diff:

| Boundary field | Default | Limit |
|---|---|---|
| `permitted_files`, `permitted_dirs` | None; at least one path is required | 50 files, 20 directories |
| `allow_create`, `allow_delete`, `allow_binary` | Off | |
| `max_changed_files` | 10 | 50 |
| `max_file_bytes` | 64 KiB | 256 KiB |
| `max_total_bytes` | 256 KiB | 512 KiB |
| `time_limit_seconds` | 600 | 30 to 3600 |
| `proposal_lifetime_seconds` | 3600 | 60 s to 7 days |

Files that steer another system are never changed through a permitted directory, only when the
boundary lists the exact file: `.gitmodules`, `.gitattributes`, `.lfsconfig`, `.husky/`,
`.githooks/`, `.pre-commit-config.yaml`, `.github/`, `.gitlab-ci.yml`, `.circleci/`,
`azure-pipelines.yml`, `.claude/`, `.mcp.json`, `.codex/`, `.agents/`, `CLAUDE.md`, `AGENTS.md`,
`.vscode/`, `.code-parley/`, `.ai-loop/`, `.npmrc`, `.yarnrc`, `.yarnrc.yml`.

**2. Codex edits a disposable copy.** The copy is seeded from the custodian's sanitized capture of
the latest finished review (or the one Claude names), and Codex runs under a confined writable
profile. It sees only that exported tree. **Nothing is written to your working tree.** The copy is
destroyed afterwards.

**3. The custodian validates.** It checks what Codex wrote against the boundary and its own
baseline, trusting no report from the engine. A valid change is held as a proposal, status
`proposed`; anything else is rejected with the violations listed. A proposal waiting for you is not
progress: automation waits and uses no continuation.

**4. You inspect it.** Claude sees only paths, kinds and sizes over MCP: `get_review_status`, in
`fixes`. The content is in the custodian's exact rendering, in a terminal. It lists the boundary,
each change with its pre- and postimage SHA-256, a line diff per text file, and its own digest.

```text
code-parley fix show <run>                     the run's delegated fixes
code-parley fix show <run> <proposal>          the custodian's rendering, verbatim
code-parley fix show <run-id> <proposal> --repo <path>   for an operator without the run store (Linux)
```

Binary and non-UTF-8 content appears as sizes and hashes only, flagged: you cannot review it there.

**5. You decide,** as the operator. The guided way needs no identifier or path:

```text
code-parley fix review [--repo <path>] [--no-pager]
```

It lists the delegated fixes the custodian holds, across your repositories, with what the custodian
itself knows: the repository, run, fix, files, sizes and expiry (never text the session wrote). You
choose one by its number; the number only selects. The custodian's whole rendering follows, in
CodeParley's own pager (Enter: next page, `b`: back, `g`/`G`: first and last page, `/text`: find,
`q`: leave); `--no-pager` prints it at once. Only when every page has been shown does it offer
`[c]onfirm`, `[r]eject` or `[l]eave pending`. The custodian then prepares the decision for exactly the
proposal and the rendering you reviewed (refused `SELECTION_STALE` if anything changed: review it
again), CodeParley checks that the prepared decision is that rendering, shows what the decision
does, and asks you to type the word. A fix whose repository moved is listed but not selectable: run
`fix review --repo <its new path>`, or set its configuration again at the new path. The custodian
lists at most 50 fixes, those waiting for your decision first and the soonest to expire first; when it
holds more, the listing says how many are not shown and how many of those wait for you. Decide some
of the listed ones and list again, or list one repository with `--repo`.

The same decision with the identifiers named:

```text
fix confirm <run-id> <proposal> --repo <path>     you type "confirm"
fix reject  <run-id> <proposal> --repo <path>     you type "reject"; the content is removed, nothing is applied
```

These take the full run id and name the repository, and they read nothing from the implementer's
data home. The confirmation is bound to the digest of exactly what was rendered, is single-use, and
expires. No tool can confirm.

**6. Claude applies it.** `apply_fix` consumes the confirmation. The custodian first re-measures the
working tree against the fix's baseline: if it moved, the call is refused `FIX_STALE`, nothing is
written and the confirmation stays unused. Each target is checked at use: no link or junction on its
way, the preimage unchanged, an added path absent. Only the confirmed content is written, one file
at a time; no atomic multi-file write is claimed. A failure restores what was written, and reports
`apply_failed`.

**7. Fresh checks and a separate review.** The result of an application is never `ready`. The source
changed, so the run needs fresh checks and a distinct review before it can be.

### An interrupted application

If an application is interrupted, run this as the implementer:

```text
code-parley fix reconcile <run>             reports each file's state; exit 3 means a choice is needed
code-parley fix reconcile <run> --restore   returns files at their postimage to their preimage
code-parley fix reconcile <run> --leave     keeps them; they go through checks and review
```

Either choice is recorded with the custodian and clears the application's lock. Automation stays
paused until then.

A delegation that is already running cannot be cancelled over MCP. It ends at its time limit.

### Stopping a run as the operator

```text
code-parley runs stop <full-run-id> (--close | --abort) --repo <path>
```

This asks the custodian to end the run and reads no run store. It exits 0 only on the custodian's
acknowledgment, and no fix can begin after that. See
[Stopping a confirmed fix](security.md#stopping-a-confirmed-fix) for exit 4 and what `config revoke`
does not do.

## What `ready` means

`ready` means that none of the derived blockers holds: the required checks passed on the current
source, an accepted review is current, and no thread is waiting for you, for the reviewer or for
Claude. On a protected run the custodian derives it.

`ready` lists its limitations: coverage, isolation, triage per the reviewer's evidence, and the
findings you waived or deferred, which stay open.

`ready` does **not** mean:

- that the code is correct or safe; a passing check is evidence, not proof;
- that a commit, push, merge, tag or release is authorized: it authorizes none of them, and
  CodeParley does none of them;
- that anything was decided for you: automation records no user decision.

Nobody can set it, and it starts nothing.

## Refusals you will meet

Every CLI refusal prints its cause and fix; the same text reaches Claude as `error.remedy`. The full
table is in [docs/troubleshooting.md](troubleshooting.md#refusal-codes).

| Code | What it usually means | What to do |
|---|---|---|
| `LOOP_NOT_AUTHORIZED` | No loop left in a grant, or it expired or was suspended | The operator grants one (`setup` or `loop allow`) |
| `CONFIG_LAPSED` | A restart of the OS, or a rollback | `setup --resume` |
| `CONFIG_MISMATCH` | Codex or the engine runtime changed | `setup`; after a Codex update run the self-test first |
| `CUSTODIAN_BUSY` | The custodian serves one request at a time | Wait, then retry. [Details](troubleshooting.md#custodian_busy) |
| `CUSTODIAN_UNAVAILABLE` | Not installed, stopped or starting; or this account may not use that surface | `code-parley status` names which |
| `PROCESS_IDENTITY_UNVERIFIED` | A new process after the loop's 15-minute window, or a process outside the bound session | Keep working in the bound session; otherwise start a new run |
| `RUN_ALREADY_HAS_LOOP` | One loop per run | Start a new run |
| `LOOP_START_UNRECONCILED` | A loop start's answer was lost | `code-parley loop stop <run>`, then a new run |
| `RUN_BUSY` | One operation per run at a time | Wait, or cancel the active one |
| `FIX_NOT_CONFIRMED`, `FIX_DECLINED` | No confirmation, or the operator rejected it | Nothing to apply |
| `CONFIRMATION_EXPIRED` | The confirmation expired before it was applied | The operator confirms again |
| `CONFIRMATION_CONSUMED` | It was already used | A new delegation |
| `FIX_STALE` | The working tree moved since the fix's baseline | Nothing was written; delegate again from a new review |
| `APPLY_IN_PROGRESS` | Another application is under way in this repository: one at a time | Wait for it; if it was interrupted, `code-parley fix reconcile <run>` |
| `INTERACTIVE_TERMINAL_REQUIRED` | The command ran without a terminal | Run it yourself in a terminal |
