#!/bin/sh
# CodeParley Linux broker — proof harness (Phase 3.1B operator step 2/3). Run as the CONTROLLER
# account (not root): the broker authorizes the caller by SO_PEERCRED, so this proves a normal,
# non-root controller can drive it while the privileged work happens in the broker.
#
#   proof-harness.sh [--workload proof-battery|lifecycle-tree|lifecycle-detached]
#                    [--terminate-after <sec>] [--timeout <sec>] [--out <file>] [--keep]
#
# Default: run proof-battery to completion, print + save the status (identity, tooling, denied-write
# results, broker-side verification), then Cleanup. Send the saved JSON back for the gate.
set -eu

SOCK=/run/codeparley-broker.sock
NODE=/opt/codeparley-broker/toolchain/node/bin/node
CLIENT="$(cd "$(dirname "$0")" && pwd)/broker-client.js"
WORKLOAD=proof-battery
TERMINATE_AFTER=
TIMEOUT=
KEEP=false
OUT=

while [ $# -gt 0 ]; do
  case "$1" in
    --workload) WORKLOAD=$2; shift 2 ;;
    --terminate-after) TERMINATE_AFTER=$2; shift 2 ;;
    --timeout) TIMEOUT=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --keep) KEEP=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
[ -x "$NODE" ] || { echo "broker toolchain node not found at $NODE" >&2; exit 1; }
[ -S "$SOCK" ] || { echo "broker socket $SOCK not present (is codeparley-broker.socket running?)" >&2; exit 1; }
[ -n "$OUT" ] || OUT="$HOME/linux-broker-$WORKLOAD-result.json"
RUNID="proof$(date +%Y%m%d%H%M%S)"

call() { "$NODE" "$CLIENT" "$SOCK" "$1"; }

echo "== ping =="
call '{"version":1,"op":"Ping"}'
echo "== capabilities =="
call '{"version":1,"op":"Capabilities"}' > "$HOME/linux-broker-capabilities.json" || true
"$NODE" -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).capabilities||{};console.log(JSON.stringify({verified:c.verified,problems:c.problems,systemd:c.lifecycle,worker:c.workerIdentity&&{user:c.workerIdentity.user,uid:c.workerIdentity.uid,gid:c.workerIdentity.gid,supplementaryGroups:c.workerIdentity.supplementaryGroups,verified:c.workerIdentity.verified},resolver:c.filesystem&&c.filesystem.resolver},null,1))' "$HOME/linux-broker-capabilities.json"

echo "== launch $WORKLOAD ($RUNID) =="
req="{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$RUNID\",\"workloadKey\":\"$WORKLOAD\""
[ -n "$TIMEOUT" ] && req="$req,\"timeoutSeconds\":$TIMEOUT"
req="$req}"
call "$req"

if [ -n "$TERMINATE_AFTER" ]; then
  echo "== waiting ${TERMINATE_AFTER}s, then Terminate =="
  sleep "$TERMINATE_AFTER"
  echo "-- status just before terminate (cgroup members) --"
  call "{\"version\":1,\"op\":\"GetStatus\",\"runId\":\"$RUNID\"}"
  echo "-- terminate --"
  call "{\"version\":1,\"op\":\"Terminate\",\"runId\":\"$RUNID\"}"
fi

echo "== poll to terminal state =="
STATUS='{}'
i=0
while [ "$i" -lt 180 ]; do
  STATUS=$(call "{\"version\":1,\"op\":\"GetStatus\",\"runId\":\"$RUNID\"}")
  STATE=$("$NODE" -e 'process.stdout.write((JSON.parse(process.argv[1]).state)||"?")' "$STATUS" 2>/dev/null || echo '?')
  echo "  state=$STATE"
  # running/starting/stopping are non-terminal: keep polling until a settled state (a unit that
  # ignores SIGTERM sits in "stopping" through its stop timeout before the cgroup SIGKILL).
  case "$STATE" in running|starting|stopping) ;; *) break ;; esac
  sleep 2
  i=$((i + 1))
done

printf '%s\n' "$STATUS" | "$NODE" -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s),null,2)))'
printf '%s\n' "$STATUS" > "$OUT"
echo "saved -> $OUT"

if ! $KEEP; then
  echo "== cleanup =="
  call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$RUNID\"}"
fi
echo "done. Send $OUT (and linux-broker-capabilities.json) back for the LINUX-BROKER-LAUNCH gate."
