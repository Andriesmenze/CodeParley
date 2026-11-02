# CodeParley Broker (Linux) — Phase 3.1B

The **CodeParley Linux Broker** is the small, trusted, root-owned component that launches the
autonomous **implementer worker** (Claude + Git + Node/npm) under a dedicated unprivileged UID, in
an isolated workspace, and owns its process tree. It is the Linux-native equivalent of the proven
Windows C2B broker (`../CodeParley.Broker/README.md`) — the **security properties match; the OS
mechanisms differ**, as the Phase 3.1B task requires. It shares the semantic host contract in
[`../HOST-CONTRACT.md`](../HOST-CONTRACT.md) with the Windows broker.

It is a **real production component**, intentionally narrow and mechanical. It performs only OS launch
duties. It does **not** decide task completion, review outcomes, user authority, routing, or
commit/push/merge/release — those remain the TypeScript controller's concern.

## Why this shape (and why it is the *simple* one)

The conventional Linux primitive for "run a process as another user, in its own resource-controlled
lifetime boundary, owned by the init system" is a **systemd transient service unit**. Using it is
strictly simpler and more robust than hand-rolling `setuid` + `setgroups` + a private cgroup + a
process-tree reaper in the broker, and it reuses **PID 1** as the durable lifetime owner — the exact
Linux parallel of the Windows broker reusing the LocalSystem service + Job Object. So the broker does
**not** fork/exec the worker itself; it asks the service manager to, and PID 1 owns the result.

Per the Technical Director's direction, this uses **normal Linux primitives only** — UID/GID, mode,
systemd, cgroup v2, a Unix socket, `openat2` — and introduces **no** bubblewrap, user namespaces or
other extra isolation layer, because the integrity property is already met without one.

## Architecture

```
controller / harness (the configured non-root uid)
   └─ connect() AF_UNIX  /run/codeparley-broker.sock   (root:codeparley 0660)
        └─ systemd socket activation (Accept=yes)
             └─ codeparley-broker@<conn>.service  — handler, root, ONE request then exits
                  authenticate peer by SO_PEERCRED (uid ∈ {0, controller}) BEFORE reading the request
                  LaunchWorkload(runId, workloadKey):
                    verify host (fail closed) → provision workspace (openat2, root) →
                    standalone clone from a broker-made git bundle → chown tree to the worker →
                    systemd-run a transient unit:  User=cp-worker  NoNewPrivileges  PrivateTmp
                       KillMode=control-group  RuntimeMaxSec  BindsTo=codeparley-broker.socket
                         └─ worker process tree in ONE cgroup (PID 1-owned):
                              git / node / npm in the standalone clone
```

The worker run unit is an **independent, PID 1-owned** unit, not a child of the short-lived handler;
it outlives the handler and is driven afterwards by `GetStatus` / `Terminate` / `Cleanup`.

## Worker integrity model (Linux-native, not a WRITE_RESTRICTED port)

Unlike Windows, Linux does not need a restricted token. The worker's write authority is exactly its
**UID + GID + supplementary groups**, so the broker makes those minimal and lets ordinary DAC do the
rest:

- a dedicated system account `cp-worker` with **its own primary group** and, verified live, **no
  supplementary groups** and **not a member of the controller group** — so it has no ambient,
  group-derived write anywhere (the Linux analogue of the Windows "ambient `Authenticated Users`"
  problem, closed by construction rather than by a restricting SID);
- trusted state (`/var/lib/codeparley-broker/{state,runs}` `0700`), the workspace parent
  (`work` `0711`: traverse to a named child, no list/create), the install tree (`/opt/...`,
  root-owned, `go-w` stripped) and `/etc/codeparley-broker` are all **root-owned and not writable**
  by the worker — DAC denies the worker by default, no deny rule needed;
- the worker is given write only to **its own run workspace** (the run dir is handed over root-owned
  with the worker's primary group, `0770`; its contents are chowned to the worker) and its own
  `HOME`/`TMPDIR`.

Beyond UID/GID DAC, the worker unit is sandboxed by **systemd** (the smallest conventional
write-containment, no bubblewrap/userns) so the worker can write **only** its workspace, its home and
its own isolated temp — nothing shared on the host (verified on a real kernel to leak nothing):

- `ProtectSystem=strict` + `ReadWritePaths=`(run workspace, worker home) — the whole filesystem is
  read-only except those two;
- `PrivateTmp=yes` (private `/tmp`, `/var/tmp`) + `TemporaryFileSystem=/dev/shm:mode=1777` (a private
  `/dev/shm`) — the worker's temp writes are isolated, never the shared host ones (plain
  `ProtectSystem=strict` leaves `/dev/shm` writable; this is the fix);
- `InaccessiblePaths=/run/lock,/var/crash,/dev/mqueue` — the world-writable tmpfs spots
  `ProtectSystem=strict` does not cover;
- `ProtectControlGroups=yes` (the cgroup tree is read-only — no cgroup-escape write), `PrivateDevices`,
  `ProtectHome`, `ProtectKernelTunables/Modules`, `RestrictNamespaces`, `LockPersonality`,
  `RestrictRealtime`, `RestrictAddressFamilies=AF_UNIX/AF_INET/AF_INET6`;
- `NoNewPrivileges=yes` (no setuid escalation), `UMask=0077`.
- version-gated where the host's systemd supports them: `RestrictSUIDSGID` (242+), `ProtectClock`
  (245+), `ProtectProc=invisible` (247+). **Not** used: `MemoryDenyWriteExecute` (breaks the V8 JIT)
  and `ProcSubset=pid` (hides `/proc/cpuinfo`, which libuv needs). The broker requires systemd **239+**
  (RHEL 8 / Debian 10 / Ubuntu 20.04 and up), which guarantees the containment directives.

Reads/traversal are unrestricted (the integrity goal is write-containment, not confidentiality), so
normal **nested-path** Git/Node/npm semantics hold with no workarounds. The proof battery writes a
canary to every protected and shared-writable location and the broker confirms, **on the host**, that
none escaped the sandbox.

## Concurrency (single active worker)

All runs share one worker UID, so cross-run isolation is the **single-active-worker** invariant, not
per-run identities. The broker rejects a launch (`capacity_exceeded`) while any run is active,
enforced in trusted state under the broker lock — not by controller scheduling. A workspace left by a
crash is relocked to root `0700` (worker-inaccessible) before the next worker can start; the broker's
operation lock is `flock`-based and released automatically if a handler dies, so it never goes stale.

## Terminal states

Derived only from the service manager's own `SERVICE_RESULT`/`EXIT_CODE`/`EXIT_STATUS` (recorded by a
root `ExecStopPost` hook), never from worker output: `exited` (clean, with code), `timed_out`
(execution reached `RuntimeMaxSec`), `terminated` (broker-requested), `interrupted` (stopped from
outside before the limit — e.g. broker-socket shutdown), `unclean` (the main finished but descendants
were SIGKILLed after the stop timeout, or descendants remained — **never** a clean success), `failed`,
`lost`. See `../HOST-CONTRACT.md` for the precedence and the rule that no host state is ever a
task-level PASS/`ready`/authorization.

## Workspace / Git

A per-run workspace `…/work/<runId>` derived by the broker from the `runId` (never a caller path),
created root-only, filled while no other principal can reach it, then handed over. The repository is a
**standalone clone** from a broker-made **git bundle** (a bundle carries objects + refs only — no
config, no hooks — so the clone inherits nothing executable), with a self-contained `.git`, `origin`
removed, and the template hooks suppressed (`--template=`). No linked worktree, no shared trusted
`.git`. The worker-owned clone is untrusted; the controller never runs Git against it in a trusting
context. For 3.1B the clone source is a deterministic throwaway repository, never a real checkout.

## Filesystem safety (no path-prefix string checks)

Every path the broker touches beneath a worker-writable location is resolved **descriptor-relative**:
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` on Linux
5.6+, and on older kernels an equivalent **component-by-component `openat(O_NOFOLLOW)` walk with a
same-device check**. No symlink in any component (including the last), no `..`, no `/proc` magic link,
no mount crossing is ever followed. Trusted roots and config are additionally checked for
root-ownership and non-writability along the whole path, sshd-`StrictModes`-style. Removal is
descriptor-relative and never follows a link out of the tree. The resolver and these properties are
exercised by `codeparley-broker selftest-fs` (runs both resolver paths, including a live
rename/symlink-swap race and, as root, a no-follow ownership hand-over).

## IPC and caller authorization

A Unix-domain stream socket at `/run/codeparley-broker.sock`, owned `root:codeparley` mode `0660`, via
**systemd socket activation** (`Accept=yes`, one handler instance per connection). Two layers:
the socket **DAC** admits only root and the controller group; the handler then authenticates the peer
by **`SO_PEERCRED`** (kernel-verified uid) and serves only uid 0 or the configured controller uid —
*before reading a byte of the request*. The worker UID is in neither, so it cannot reach the broker at
all (verified: `connect()` → `EACCES`). The protocol is one JSON request line (≤64 KiB, 10 s) and one
JSON response; unknown fields are rejected; the verb set is fixed
(`Ping`/`Capabilities`/`LaunchWorkload`/`GetStatus`/`Terminate`/`Cleanup`); no generic privileged
path/process operation is exposed; the caller supplies only a strict-charset `runId` and an
allowlisted `workloadKey`.

## Process-tree ownership (the Job Object equivalent)

Each run is one transient unit = one **cgroup**. `KillMode=control-group` + `SendSIGKILL=yes` +
`TimeoutStopSec` terminate the **whole** cgroup (every descendant, including detached/`setsid` ones
that a parent-PID or session kill would miss); `RuntimeMaxSec` is the wall-clock limit enforced by PID
1; `BindsTo=codeparley-broker.socket` means **stopping the broker (its socket) stops every worker
run**. Membership is read from the cgroup with per-PID identities, not by process name. An
`ExecStopPost=+` hook (root) records the service manager's own `SERVICE_RESULT`/`EXIT_CODE`/
`EXIT_STATUS` and relocks the workspace — so the recorded outcome is the kernel/PID-1 truth, never
anything the worker wrote.

## Host verification (fail closed)

Every request re-measures the host; `LaunchWorkload` is refused (`host_unverified`) unless all hold:
systemd is PID 1 and ≥ 235; cgroup v2 (or hybrid/v1, detected); the broker/node/git/systemctl/
systemd-run/workload scripts all resolve through root-owned, non-writable paths; the state tree has
the expected owners/modes; the worker identity passes (non-root, non-controller, no supplementary
groups, private owned `HOME`); the socket is `root:<controller-group>` without world access; the
controller uid/group exist. **WSL is rejected as a worker host** (interop and drvfs bridge any Linux
uid into the Windows user) unless the root-owned config sets `testOnlyAllowWslHost` — a development
switch that every capability report labels as *test-only, not a security proof*.

## Build / publish

Distro-neutral, dependency-free, self-contained single file (no .NET runtime needed on the target):

```bash
dotnet publish broker/CodeParley.Broker.Linux -c Release -r linux-x64 \
  --self-contained true -p:PublishSingleFile=true
# or linux-arm64; both architectures are supported (open(2) flag differences handled).
```

## Install / run (Phase 3.1B operator proof)

```bash
# 1. (root) install: worker account + codeparley group + /opt + /etc + /var/lib + systemd units
sudo scripts/install-broker.sh --controller <you> --payload <publish-dir> \
     --node <nodedir> --git /usr/bin/git [--sibling <repo> ...] [--allow-wsl]

# 2a. (as the controller) drive one proof-battery run through the socket; saves the result JSON
scripts/proof-harness.sh --workload proof-battery

# 2b. (root) full lifecycle / concurrency / terminal-state / boundary proof with evidence capture
sudo scripts/lifecycle-proof.sh --controller <you> --out <evidence-dir>

# 3. (root) remove everything
sudo scripts/uninstall-broker.sh --purge
```

`codeparley-broker capabilities` (root) prints the live verification report at any time. The host
verification fails closed and requires systemd **239+**.

## Scope (Phase 3.1B)

Prove the production-shaped launch path and stop at the
`LINUX-BROKER-LAUNCH-PASS/PARTIAL/FAIL` gate. No real Claude model, no Codex, no routing, no full
controller loop, nothing pushed/merged/released.
