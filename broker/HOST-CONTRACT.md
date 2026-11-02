# CodeParley worker-host broker — common cross-platform contract

Phase 3.1B deliverable: the minimal **semantic** contract the trusted TypeScript controller can
depend on to launch and own an autonomous implementer worker, identically on Windows and Linux. The
controller thinks in terms of the operations below; it must **not** encode any OS mechanism. Both the
Windows broker (`CodeParley.Broker/`) and the Linux broker (`CodeParley.Broker.Linux/`) implement
this surface; only the mechanisms behind it differ.

This documents the contract and is backed by the two proven brokers. It is **not** a controller
refactor — Phase 3.1B makes only the implementation needed for the Linux proof (per the task, "do not
perform a large controller refactor yet").

## What the controller may depend on (and nothing more)

| Semantic operation | Meaning (OS-independent) |
|---|---|
| **launch run** `(runId, workloadKey[, timeout])` | Start the approved, allowlisted workload as the dedicated worker identity, in a fresh isolated workspace the broker derives from `runId`, inside an OS-owned lifetime boundary. Returns a handle (the `runId`) and an initial state. |
| **get status** `(runId)` | A settled or in-flight state (see below), the worker-written result payload (untrusted), the worker log tail (untrusted), the lifetime boundary's current members with identity, and — for a proof workload — the broker's own post-run verification of the denied surfaces. |
| **terminate run** `(runId)` | Stop the whole worker process tree now; the recorded outcome distinguishes a broker-requested termination from any other stop. |
| **cleanup run** `(runId)` | Remove the run's workspace and records; report completeness. Idempotent. |
| **query capabilities** `()` | The verified host facts, or the list of problems that make the host unfit (launch then fails closed). |

Requests carry only a strict-charset `runId` and an **allowlisted** `workloadKey` (plus an optional
bounded timeout). No path, command, environment, account, token or identity is ever caller-supplied.

## Common run states

Non-terminal: `none` · `starting` · `running` · `stopping`.

Terminal (host-execution outcomes):

| State | Meaning |
|---|---|
| `exited` | the main process exited on its own and the process tree was contained cleanly (carries the exit code; a non-zero code is a cleanly-run but failed workload) |
| `timed_out` | execution reached the run's own wall-clock limit and the tree was killed |
| `terminated` | the broker was asked to stop the run (`Terminate`/`Cleanup`) |
| `interrupted` | the run was stopped from outside the broker before its limit (broker/host shutdown, external stop) |
| `unclean` | the main process finished but host cleanup was **not** clean — descendants ignored SIGTERM and had to be force-killed after the stop timeout, or descendants remained in the tree |
| `failed` | the launch failed, or the run died unexpectedly (e.g. OOM) |
| `lost` | the host restarted mid-run; no recorded outcome |

The controller routes on these; it never parses an OS-specific status.

### Terminal-state precedence (deterministic)

The outcome is derived **only** from the service/OS exit facts recorded by the trusted broker (on
Linux: the service manager's `SERVICE_RESULT`/`EXIT_CODE`/`EXIT_STATUS` via a root hook; on Windows:
the process exit code and the broker's own terminate record) — **never** from anything the worker
wrote. Precedence, highest first:

1. **descendants remained** → `unclean` (the tree was not contained — never a clean success);
2. **broker-requested stop** (a terminate record exists) → `terminated`;
3. **ran to the run's own time limit** (elapsed ≈ the limit) → `timed_out`;
4. **main finished but stragglers were force-killed** after the stop timeout → `unclean`;
5. **stopped from outside before the limit** (main killed early, no terminate record) → `interrupted`;
6. **clean exit** (main exited, tree emptied cleanly) → `exited` (with code).

A run whose host termination was not clean, or that left descendants, is **never** reported as a clean
success. Execution timeout (the workload ran too long) is distinguished from a shutdown/cleanup
timeout (the main finished but a straggler forced a kill).

### Host execution is not task authority

**No host-execution state — not even `exited` with code 0 — is a task-level PASS, a `ready`, or any
user authorization.** It reports only that a process ran and how it ended. Task completion, review
outcomes and user authority are derived by the CodeParley engine from its own trusted evidence, never
from a broker run state, a worker exit code, or anything the worker narrated. The broker is mechanism;
authority stays with the controller/engine and the user.

## Concurrency (Phase 3: single active worker)

All worker runs share one dedicated worker identity, so cross-run isolation is provided by a
**single-active-worker invariant**, not by per-run identities. The broker enforces it in trusted state
(under its own lock): a `launch` is **rejected** (`capacity_exceeded`) while any run is active — the
controller's scheduling is not relied upon. A workspace left behind by a crash is made inaccessible to
the worker identity again (relocked) before the next worker can start. Crash safety: the broker's
operation lock is held only for the duration of a launch/terminate/cleanup and is released
automatically if the handler dies, so it can never go stale; "a run is active" is read from the OS
(the service manager / Job Object), which a dead handler cannot falsify.

## Lifecycle guarantees (what happens to a running worker)

| Event | Effect on the running worker | Recovery |
|---|---|---|
| **Broker shutdown** (socket/service stopped) | every worker run is stopped (Linux: `BindsTo` the broker socket; Windows: the Job Object closes) | the run records a terminal outcome (`interrupted`); when the broker restarts, the controller re-queries by `runId` |
| **One request-handler crash** (Linux: a per-connection handler; Windows: a call) | **none** — the worker run is owned by the OS (PID 1 / the Job Object), not by the handler, and outlives it | the next status query reflects the true OS state; a launch interrupted before it recorded is recovered from the live unit |
| **Controller disconnects** | **none** — the run is not tied to the IPC connection | the controller reconnects and calls `GetStatus`; the run is unaffected |
| **Worker exits / is killed** | the OS owner records the exit facts; the broker derives the state from them | `GetStatus` returns the terminal state; the workspace is relocked |
| **Host reboot mid-run** | the transient run is gone | status reports `lost`; a stale workspace is relocked before the next launch |

No status is ever fabricated from worker narration: states come from the OS owner, members from the
kernel (cgroup / Job Object), and boundary verification from the broker (root) checking the host.

## The invariants both brokers guarantee (mechanism-independent)

1. **Dedicated low-privilege identity.** The worker runs as an identity distinct from the controller,
   with no ambient authority to anything outside its granted surfaces.
2. **Write-containment.** The worker may write only its own run workspace and its own profile/temp.
   Trusted state, the broker/controller install, trusted configuration, the controller's own files,
   and sibling repositories are **not writable** — enforced by the OS, verified by the broker after
   the run, and independent of anything the worker claims.
3. **Normal tooling.** Git/Node/npm run as real processes with normal **nested-path** semantics and
   normal child-process spawning — no path workarounds.
4. **Standalone workspace.** A standalone clone with a self-contained repository; never a linked
   worktree into trusted Git metadata; the worker's clone/config/hooks are untrusted and the
   controller never runs Git against them in a trusting context.
5. **Explicit worker environment.** Derived from the worker identity/profile, never inherited from
   the controller; no controller or Anthropic secrets leak in.
6. **Whole-tree lifetime ownership.** Every worker descendant (including detached ones) belongs to one
   broker/OS-owned boundary that can be terminated as a unit without touching unrelated processes;
   normal exit, child, detached descendant, cancellation, timeout, broker death and unrelated-process
   survival all behave correctly; cleanup/recovery is deterministic.
7. **Authenticated local IPC.** A narrow semantic surface over an OS-authenticated local channel; the
   caller's identity is taken from the OS, never from the request; the worker identity cannot reach it.
8. **Fail closed.** If the host cannot be verified to provide the above, launch is refused, not weakened.
9. **Mechanism, not authority.** The broker performs only OS launch duties. Completion, review
   outcomes, user authority, routing and commit/push/merge/release are **never** the broker's.

## How each OS satisfies the contract (reference, not for the controller to know)

| Concern | Windows (`CodeParley.Broker`) | Linux (`CodeParley.Broker.Linux`) |
|---|---|---|
| Privileged host | LocalSystem Windows **service** | root-owned **systemd** service (socket-activated) |
| Worker identity | dedicated account `cp-worker`; **WRITE_RESTRICTED** token (restricting SIDs = account + per-launch logon + Everyone + WRITE RESTRICTED) | dedicated UID `cp-worker`, own primary group, **no supplementary groups**, not in the controller group |
| Ambient-write removal | restricting-SID set denies `Authenticated Users`/world writes | minimal GIDs → no group-derived write exists to remove |
| Credentials | broker-held password in an **LSA private secret** | **none** — `setuid` by PID 1; the broker holds no worker secret |
| Lifetime boundary | **Job Object** (kill-on-close, no breakaway) | **cgroup** via a transient unit (`KillMode=control-group`, `RuntimeMaxSec`, `BindsTo` the broker socket) |
| Wall-clock limit | **broker-enforced timer** at the deadline → `TerminateJobObject` (not controller-scheduled) | `RuntimeMaxSec` enforced by PID 1 |
| Launch | `CreateProcessAsUser(CREATE_SUSPENDED)` → assign to job → resume | `systemd-run` transient unit (PID 1 does the `setuid`/cgroup/limits) |
| Single active worker | admission reads live Job Object membership / process-exit under an admission lock; a second launch is rejected `capacity_exceeded` | admission reads the live run units from PID 1 under the broker lock; `capacity_exceeded` |
| Terminal-state evidence | the broker's own terminate/timeout records + Job Object membership (descendant cleanup) + the main exit code — never worker output | the service manager's `SERVICE_RESULT`/`EXIT_CODE`/`EXIT_STATUS` via a root `ExecStopPost` hook — never worker output |
| Workspace safety | handle-based reparse/TOCTOU checks + `GetFinalPathNameByHandle` containment | `openat2(RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV)`, or an `openat(O_NOFOLLOW)` walk + same-device check on kernels < 5.6 |
| Git clone trust | per-run `safe.directory` naming only the exact per-run clone (never `*`) | standalone clone from a broker-made git bundle, worker-owned (no `safe.directory` needed) |
| Write-containment beyond DAC | the WRITE_RESTRICTED token denies ambient/world writes everywhere | `ProtectSystem=strict` + `ReadWritePaths`=(workspace, home); private `/tmp`/`/var/tmp`/`/dev/shm`; `/run/lock`,`/var/crash`,`/dev/mqueue` inaccessible; `ProtectControlGroups` (no cgroup-escape) — proven to leak nothing to shared host locations |
| Isolation extras | private Low-IL window station/desktop | `NoNewPrivileges`, `PrivateDevices`, `ProtectHome`, `ProtectKernelTunables/Modules`, `RestrictNamespaces`, `LockPersonality`, `RestrictAddressFamilies`, `UMask=0077` (version-gated: `RestrictSUIDSGID`, `ProtectClock`, `ProtectProc`) |
| IPC | named pipe; ACL admits only the **configured controller SID** + SYSTEM; server also requires the impersonated client SID to equal exactly that controller SID | Unix socket, `root:<controller-group>` `0660` + `SO_PEERCRED` |
| Host verification (`query capabilities`) | `WindowsHostCheck` (LocalSystem, controller config, worker account, trusted tool paths not group-writable, locked roots) — fail closed | `HostCheck` (systemd ≥ 239, cgroup v2, trusted tool chain, worker identity, socket DAC) — fail closed |
| Post-run write-denial verification | the broker (SYSTEM) re-checks each denied directory/file after the run (independent of the worker's report) | the broker (root) re-checks denied directories/files + shared host locations after the run |
| Env derivation | `LoadUserProfile` + `CreateEnvironmentBlock` + explicit overrides | worker-account `HOME`/XDG/`TMPDIR`, explicit allowlist |

## Remaining platform assumptions / residuals

- **Windows:** the controller SID is pinned by install-time config (`provision --controller`) and the
  pipe ACL + impersonated-SID check admit only it; `safe.directory` is pinned to the exact per-run clone.
  One documented terminal-state asymmetry remains (see below): Windows cannot reliably attribute an
  *external* kill of the worker's own main process (someone else terminating it) to `interrupted` from
  the exit code alone, so it classifies that from Job Object evidence (`exited`/`unclean`), while an
  ungraceful **broker/host** death is `lost`; `interrupted` is reported for a **broker graceful
  shutdown** that stops an active run. Worker networking is ordinary host networking (no destination
  scoping — same posture as Linux).
- **Linux:** the controller account joins the `codeparley` group (socket DAC); worker networking is
  ordinary host networking (no destination scoping); `ptrace` is already limited to child-only by the
  worker's isolation but not otherwise narrowed; the standalone-clone source becomes the
  controller-supplied bundle in the controller-integration milestone.
- **Both:** the broker is a privileged local surface; its narrow IPC + strict validation + fail-closed
  verification are the guard. Controller-side result integration is a later milestone.

## Terminal-state parity (stabilized)

Both brokers now expose the same terminal vocabulary
(`exited`/`timed_out`/`terminated`/`interrupted`/`unclean`/`failed`/`lost`), enforce the
single-active-worker invariant from trusted OS state under an admission lock (not controller
scheduling), and never report a clean success when descendant cleanup was not established. Both verify
the host and fail closed, and both re-check the denied surfaces after the run independently of the
worker. The derivation **evidence** differs by platform (above) but the semantics the controller routes
on are identical, with one honest asymmetry: the **trigger** for `interrupted`. On Linux any external
stop (socket/service shutdown) is derived from the service manager as `interrupted`; on Windows
`interrupted` is recorded when the **broker itself** shuts down gracefully with a run active, whereas an
ungraceful broker/host death surfaces as `lost` on recovery and an external kill of the worker alone is
classified from Job Object evidence. Neither platform is weakened to match the other; the Windows
behaviour is the conservative, evidence-based choice (it never fabricates a termination reason Windows
cannot reliably recover).
