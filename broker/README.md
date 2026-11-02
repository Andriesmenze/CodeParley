# CodeParley Broker (Windows) — Phase 3.1A

The **CodeParley Broker** is the small, trusted, privileged Windows component that launches the
autonomous **implementer worker** (Claude + Git + Node/npm) under a dedicated low-privilege identity,
confined by a restricted token, inside an isolated workspace, and owns its process tree. It is the
C2B "trusted launcher/broker" from the Phase 3.0 analysis
(`docs/validation/results/P3.0-worker-identity-c2.md`, `…-c2-workspace.md`, `…-c2b-proof.md`).

It is a **real production component**, intentionally narrow. It performs only mechanical OS launch
duties. It does **not** decide task completion, review outcomes, user authority, task state, routing,
or commit/push/merge/release — those remain the TypeScript controller's concern. The broker never
embeds orchestration logic and never becomes a generic privileged process-launch service.

## Phase 3.1C — common host-contract stabilization (current milestone)

Bring the Windows broker to the common `broker/HOST-CONTRACT.md` surface that the Linux broker proved
in Phase 3.1B, and close the two Phase 3.1A production-hardening items — without redesigning the
restricted-token / workspace / Job Object model:

- **Single-active-worker admission.** A launch is rejected (`capacity_exceeded`) while any run is
  active, decided from trusted OS state (live Job Object membership + process-exit) under an admission
  lock — not from controller scheduling. On broker/host restart the kill-on-close Job Objects are
  already gone; durable per-run records reconcile to `lost` and stale workspaces are removed before the
  next launch, so stale state or recovery can never permit overlapping workers.
- **Terminal-state parity.** The broker reports `exited` / `timed_out` / `terminated` / `interrupted` /
  `unclean` / `failed` / `lost`, derived only from its own records and OS evidence (terminate/timeout
  records, Job Object membership for descendant cleanup, the main exit code) — never from worker output.
  A broker-enforced wall-clock timer provides `timed_out`; a main that exits while descendants linger is
  `unclean` (success is never inferred from the exit code when descendant cleanup is not established).
  A pure classifier (`TerminalClassifier`) makes the mapping verifiable without elevation
  (`self-test-classify`).
- **Hardening 4A — controller identity.** The proof-time "any elevated administrator" authorization is
  replaced by an explicitly configured controller SID: `provision --controller <account|SID>` records it
  (refusing group SIDs such as Administrators/Users), the named-pipe ACL admits only that SID + SYSTEM,
  and the server requires the impersonated client SID to equal it exactly. With no controller configured
  the broker stops rather than defaulting.
- **Hardening 4B — git `safe.directory`.** The proof-time wildcard is gone; each run gets a
  worker-readable (not worker-writable) config naming only that run's exact clone as safe.
- **`Capabilities` op + fail-closed launch + broker-side verification.** A `Capabilities` verb returns
  the verified host facts (or the problems that fail it closed); a launch re-verifies the host first; and
  after a proof run the broker (SYSTEM) independently re-checks every denied directory/file.

See `docs/validation/results/P3.1C-host-contract-stabilization.md` and `broker/HOST-CONTRACT.md`.

## Phase 3.1A scope (prior milestone)

Prove the **actual production broker launch path** end to end, then stop at the
`BROKER-LAUNCH-PASS/PARTIAL/FAIL` gate for Technical Director review. No real Claude model, no Codex,
no autonomous routing, no full controller loop, no Linux, nothing pushed/merged/released.

Implemented surface (minimal):
- Windows service/broker host (LocalSystem), self-contained single-file publishable.
- Named-pipe IPC with caller authentication/authorization.
- Dedicated worker identity logon + token construction.
- **Dual restricting-SID `WRITE_RESTRICTED` model** (see below).
- Explicit worker environment.
- Isolated workspace (dedicated root + standalone clone).
- Job Object process-tree ownership (ported from the proven `spike/.../win-job.cs`).
- Deterministic Git/Node/npm launch proof + negative write-boundary checks.
- Cleanup / recovery.

## Architecture

```
operator session                         session 0 (LocalSystem)
┌─────────────────────┐   named pipe    ┌───────────────────────────────────────────┐
│ controller / test   │  (ACL: operator │ CodeParley Broker service                   │
│ harness (caller)    │──  SID + SYSTEM)─▶  validate → logon worker → build token →   │
└─────────────────────┘                 │  grant winsta/desktop → provision workspace │
                                         │  → explicit env → CreateProcessAsUser →     │
                                         │  Job Object → status/terminate/cleanup      │
                                         └───────────────┬─────────────────────────────┘
                                                         │ restricted worker token
                                                         ▼
                                         ┌───────────────────────────────────────────┐
                                         │ worker process tree (dedicated identity,    │
                                         │ WRITE_RESTRICTED): git / node / npm in the  │
                                         │ isolated standalone-clone workspace         │
                                         └───────────────────────────────────────────┘
```

### Worker token construction (PROVEN, not assumed)

The worker runs under a **`WRITE_RESTRICTED`** token. Per Microsoft's write-restricted-token model,
writes succeed only via the token's restricting SIDs (reads/execute are unaffected), so the set is:
1. the **worker account SID** — writes to the worker's own persistent profile (Claude auth, cache,
   TEMP/profile);
2. the **per-launch logon SID** (`S-1-5-5-X-Y`, from the worker's `LogonUser` token) — writes to
   **this run's** workspace only;
3. **Everyone** (`S-1-1-0`) and **WRITE RESTRICTED** (`S-1-5-33`) — the SIDs Windows' own
   write-restricted services use so a real runtime (node, git, the .NET CLR) can create the named
   kernel objects and Everyone-writable temp it needs to start. These confer no access to the
   protected surfaces: sibling repos grant **Authenticated Users** and trusted state grants
   **SYSTEM/Administrators** — none of the four restricting SIDs — so those writes stay denied (the
   workload's negative checks re-confirm this each run).

A non-admin impersonation experiment (`scratch …/p3.1a/token-identity-check.ps1`) confirmed the exact
Windows access-check behaviour with a real logon SID `S-1-5-5-0-431044`:

| `WRITE_RESTRICTED` restricting SIDs | profile (account-granted) | workspace (logon-granted) | ambient (`AuthUsers`) |
|---|---|---|---|
| `[account]` | OK | **DENIED** | **DENIED** |
| `[account, logon]` | OK | OK | **DENIED** |

So with both SIDs: the worker writes its own profile (account SID) and the current run's workspace
(logon SID); **another run's** workspace (a different logon SID — not in this token) is denied; and
ambient `Users`/`Authenticated Users`/world writes are denied — removing the cross-user ambient
exposure that an ordinary standard account otherwise has (Phase 3.0 workspace-isolation Issue 1),
without mutating any shared host ACL. Reads/traversal are unaffected (`WRITE_RESTRICTED` gates only
write-class access), so normal nested-path Git/Node semantics hold — the C1 AppContainer regression
does not recur.

### Worker environment (explicit; never inherited wholesale)

The broker builds the worker environment explicitly. At minimum these resolve to the **worker**
identity/profile, never the controller's: `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`,
`USERNAME`, `USERDOMAIN`, `HOMEDRIVE`, `HOMEPATH`. Trusted executables (Git/Node/the worker
entrypoint) are resolved by **absolute trusted paths**; no controller execution/config/module
resolution depends on any worker-writable location.

### Workspace (approved topology)

Dedicated CodeParley-controlled workspace root; per-run subdir granted to the **logon SID**;
**standalone clone** with a self-contained `.git` (no linked worktree, no shared trusted `.git`); the
worker-owned clone is untrusted and the broker/controller never runs Git against it in a trusting
context (worker-controlled hooks/config). For 3.1A the clone source is a deterministic throwaway
repository, never the real CodeParley checkout.

### Credential handling

The worker's Windows credential lives with the **broker**, never the controller. The broker's
`provision` step (run once, privileged) ensures the dedicated worker account exists, rotates it to a
random password, and stores that password as an **LSA private secret** readable only by LocalSystem;
launches retrieve it to `LogonUser`. The controller/operator never hold the worker password after
provisioning. (This is the C2B property: secret in the broker, not the controller.)

### Broker security boundary

The broker API is deliberately narrow. Every request is validated for: caller identity (pipe ACL +
client-SID allowlist = the trusted operator/controller), allowed operation (fixed verb set),
workspace/run identifier, workspace root (canonicalized, contained under the configured allowed root,
and never a trusted CodeParley path), executable selection (allowlist, not arbitrary paths),
arguments/environment (broker-constructed/validated), and worker identity (fixed, not caller-chosen).
A caller **cannot** make the broker grant the worker a trusted path, launch an arbitrary privileged
command, choose an arbitrary account/token, modify trusted state, or escape the allowed workspace
root.

### IPC

Conventional authenticated local Windows IPC: a **named pipe** whose ACL admits only the trusted
caller SID and SYSTEM; the server additionally checks the connected client's SID. JSON request/
response with an explicit `version`. Lifecycle/status is poll-based (`GetStatus` by run id);
controller restart reconnects by opening the pipe and re-querying runs the broker still owns
(Job Objects + a durable run registry).

### Production hardening (TD checkpoint — incorporated)

1. **No arbitrary workspace paths over IPC.** The caller supplies only a `runId` (strict charset, no
   separators/`..`); the broker derives the workspace as `<trusted root>\<runId>` and creates it
   itself. Validation is by **filesystem handle**, not string canonicalization: the broker opens the
   object with `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS`, rejects reparse
   points/junctions, confirms via `GetFinalPathNameByHandle` that the final path is contained under
   the (handle-verified, non-reparse, SYSTEM/Administrators-owned) trusted root, and applies the
   logon-SID ACL **to the opened handle** — closing the junction/TOCTOU window. The public IPC stays
   semantic (`Provision`/`LaunchWorkload{runId,workloadKey}`/`GetStatus`/`Terminate`/`Cleanup`); no
   generic privileged filesystem operation is exposed, and a trusted CodeParley path can never be
   presented as, or ACL-granted as, a workspace.
2. **Suspended launch, then job, then resume.** The worker is created `CREATE_SUSPENDED`, assigned to
   the broker-owned Job Object, and only then resumed — so no worker code (or descendant) can run
   before it is inside the job. The job keeps the proven posture: kill-on-close, no breakaway,
   whole-tree/descendant containment, unrelated processes untouched.
3. **Real worker profile + derived environment.** The broker `LoadUserProfile`s the worker account
   (loads its HKCU hive where persistent Claude auth/cache live), derives the base environment from
   the worker token via `CreateEnvironmentBlock`, then applies CodeParley's explicit allowlist/
   overrides. It never inherits the controller environment and never relies solely on setting
   `USERPROFILE`. The final block still explicitly ensures worker-owned `USERPROFILE`, `APPDATA`,
   `LOCALAPPDATA`, `TEMP`/`TMP`, `HOMEDRIVE`/`HOMEPATH`, `USERNAME`/`USERDOMAIN`, and leaks no
   controller secret. The profile is unloaded with the run.
4. **Private, non-interactive window station/desktop.** The broker does **not** grant the worker
   access to the operator's interactive `WinSta0\Default`. It creates a private service-session
   window station + desktop whose DACL grants only SYSTEM and the **per-launch logon SID** the
   minimal rights the worker tooling needs, points the worker's `STARTUPINFO.lpDesktop` at it, and
   destroys it with the run.

## Build / publish

Development/CI build (SDK pinned to 10.0.201 via `global.json`):

```bash
dotnet build broker/CodeParley.Broker -c Release
```

Production artifact — self-contained single-file (no .NET runtime/SDK needed on the target):

```bash
dotnet publish broker/CodeParley.Broker -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Install / run — Phase 3.1C operator proof (elevated)

From an **elevated** PowerShell (the SDK must be installed for the publish step):

```powershell
# 1. publish (self-contained single-file) + install LocalSystem service + provision
#    (worker identity + LSA secret + trusted roots + explicit controller SID) + start.
#    -Controller defaults to the current operator account; pass an account or SID to override.
broker\scripts\install-broker.ps1 -Controller "DESKTOP\operator"

# 2. drive the full stabilization matrix through the named-pipe IPC; saves an evidence bundle.
broker\scripts\proof-harness.ps1 -OutDir C:\cp-proof-evidence

# 3. tear everything down (add -Purge to also remove the ProgramData tree)
broker\scripts\uninstall-broker.ps1 -Purge
```

Step 2 writes an evidence bundle (`<step>.json` per check + `summary.json`): capability verification; a
clean `proof-battery` run with the worker's `resultJson` (Git discovery/status/log/diff + nested, Node
inline/child-spawn, npm, and the negative trusted/ambient/sibling write checks) **and** the broker's own
SYSTEM-side re-verification of the denied surfaces; single-active admission (`capacity_exceeded`); broker
`Terminate` (`terminated`); execution timeout (`timed_out`); detached straggler (`unclean`); broker
graceful shutdown (`interrupted`); simulated host crash recovery (`lost` + stale-workspace removal); and
exact-SID authorization (a non-controller elevated admin refused at the pipe). Send the bundle back for
the `HOST-CONTRACT-STABILIZED-PASS/PARTIAL/FAIL` gate.

CLI verbs (the scripts call these): `install` / `uninstall` (service); `provision --controller <acct|SID>`
/ `deprovision` (worker identity + LSA secret + trusted roots + controller config); `capabilities` (print
the host verification report; fully verified only as the LocalSystem service); `self-test-classify`
(NON-privileged terminal-state classifier check); `self-test` (exercise the launch in-process; must run
as LocalSystem).

## Status

Builds against .NET 10.0.201 (`net10.0-windows`, `Microsoft.Extensions.Hosting[.WindowsServices]`
10.0.12); self-contained single-file `win-x64` publish clean (~72 MB). Phase 3.1A proved the launch
path (`BROKER-LAUNCH-PASS`). Phase 3.1C adds single-active admission, the full terminal-state
vocabulary, the explicit controller SID + pipe ACL, the per-run `safe.directory`, the `Capabilities`
op + fail-closed launch, and broker-side post-run verification — reconciled with the Linux broker in
`broker/HOST-CONTRACT.md`. The terminal-state classifier passes its non-privileged self-test (14/14);
the full live matrix is operator-run (elevated) via `proof-harness.ps1`. The milestone ends at the
`HOST-CONTRACT-STABILIZED-PASS/PARTIAL/FAIL` gate.
