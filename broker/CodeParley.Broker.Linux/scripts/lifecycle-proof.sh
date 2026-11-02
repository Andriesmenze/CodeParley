#!/bin/bash
# CodeParley Linux broker — full lifecycle / concurrency / terminal-state / boundary proof
# (Phase 3.1B, TD review round 1). Run as ROOT after install-broker.sh; broker calls are made AS the
# controller (SO_PEERCRED-authenticated) via runuser, the privileged steps (socket stop, orphan forge)
# as root. Writes raw results and systemd evidence under --out for the Technical Director.
#
#   sudo scripts/lifecycle-proof.sh [--controller <user>] [--out <dir>]
#
# Exercises: capabilities; proof-battery (tooling + nested paths + denied writes + shared-host
# leak check, broker-verified); single-active concurrency rejection; terminal states
# exited/timed_out/unclean/terminated/interrupted; whole-tree + detached-descendant containment;
# unrelated-process survival; workspace relock; orphaned-workspace recovery. Each run is cleaned up.
set -u
CONTROLLER="${SUDO_USER:-}"
OUT=""
while [ $# -gt 0 ]; do case "$1" in
  --controller) CONTROLLER=$2; shift 2;;
  --out) OUT=$2; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 64;;
esac; done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -n "$CONTROLLER" ] || { echo "--controller <user> required (or run via sudo)" >&2; exit 64; }
id "$CONTROLLER" >/dev/null 2>&1 || { echo "controller '$CONTROLLER' not found" >&2; exit 1; }
[ -n "$OUT" ] || OUT="$(getent passwd "$CONTROLLER" | cut -d: -f6)/cp-linux-proof-evidence"
mkdir -p "$OUT"; : > "$OUT/summary.txt"

NODE=/opt/codeparley-broker/toolchain/node/bin/node
CLIENT_SRC="$(cd "$(dirname "$0")" && pwd)/broker-client.js"
CLIENT=/opt/codeparley-broker/broker-client.js
[ -r "$CLIENT" ] || install -m 0755 -o root -g root "$CLIENT_SRC" "$CLIENT" 2>/dev/null || CLIENT="$CLIENT_SRC"
SOCK=/run/codeparley-broker.sock
CGRP=/var/lib/codeparley-broker/work

say() { echo "$@"; echo "$@" >> "$OUT/summary.txt"; }
call() { runuser -u "$CONTROLLER" -g "$CONTROLLER" -G codeparley -- "$NODE" "$CLIENT" "$SOCK" "$1"; }
jget() { "$NODE" -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{let v=JSON.parse(s);for(const k of process.argv[1].split("."))v=(v==null?v:v[k]);process.stdout.write(v==null?"":typeof v==="object"?JSON.stringify(v):String(v))}catch(e){process.stdout.write("")}})' "$1"; }
alive() { kill -0 "$1" 2>/dev/null && echo yes || echo no; }
wait_terminal() { local S st; for i in $(seq 1 30); do S=$(call "{\"version\":1,\"op\":\"GetStatus\",\"runId\":\"$1\"}"); st=$(printf '%s' "$S" | jget state); case "$st" in running|starting|stopping) sleep 2;; *) printf '%s' "$S"; return;; esac; done; printf '%s' "$S"; }
evidence() { journalctl --no-pager -o short-iso "_SYSTEMD_UNIT=codeparley-run-$1.service" > "$OUT/journal-$1.txt" 2>/dev/null || true; }

say "# CodeParley Linux broker lifecycle proof @ $(date -Is)"
say "controller=$CONTROLLER  host=$(. /etc/os-release; echo "$PRETTY_NAME") kernel=$(uname -r)"

say "## capabilities"
call '{"version":1,"op":"Capabilities"}' > "$OUT/capabilities.json"
say "verified=$(jget capabilities.verified < "$OUT/capabilities.json")  wslTestOverride=$(jget capabilities.testOnlyWslHost < "$OUT/capabilities.json" | head -c 20)"

say "## proof-battery (tooling, denied writes, shared-host leak check)"
R="pb$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"proof-battery\"}" >/dev/null
S=$(wait_terminal "$R"); printf '%s' "$S" > "$OUT/proof-battery.json"; evidence "$R"
say "  state=$(printf '%s' "$S" | jget state) summary=$(printf '%s' "$S" | jget resultJson | jget summary)"
say "  verification=$(printf '%s' "$S" | jget verification)"
call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null

say "## single-active concurrency"
A="ca$(date +%H%M%S)"; B="cb$(date +%H%M%S)"
call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$A\",\"workloadKey\":\"lifecycle-tree\"}" >/dev/null; sleep 3
say "  B while A active: $(call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$B\",\"workloadKey\":\"lifecycle-tree\"}" | jget errorCode) (expect capacity_exceeded)"
call "{\"version\":1,\"op\":\"Terminate\",\"runId\":\"$A\"}" >/dev/null; call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$A\"}" >/dev/null
say "  B after A cleaned: $(call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$B\",\"workloadKey\":\"lifecycle-tree\"}" | jget state) (expect running)"
call "{\"version\":1,\"op\":\"Terminate\",\"runId\":\"$B\"}" >/dev/null; call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$B\"}" >/dev/null

say "## terminal states"
R="td$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"lifecycle-detached\"}" >/dev/null
S=$(wait_terminal "$R"); evidence "$R"; say "  detached-descendant -> $(printf '%s' "$S" | jget state) (expect unclean)"; call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null
R="tt$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"lifecycle-tree\",\"timeoutSeconds\":5}" >/dev/null
S=$(wait_terminal "$R"); evidence "$R"; say "  RuntimeMaxSec -> $(printf '%s' "$S" | jget state) (expect timed_out)"; call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null
R="te$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"proof-battery\"}" >/dev/null
S=$(wait_terminal "$R"); say "  clean exit -> $(printf '%s' "$S" | jget state) code=$(printf '%s' "$S" | jget exitCode) (expect exited 0)"; call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null

say "## whole-tree + detached containment, unrelated survives"
setsid bash -c 'exec sleep 300' </dev/null >/dev/null 2>&1 & UNREL=$!
R="lt$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"lifecycle-tree\"}" >/dev/null; sleep 3
MEM=$(call "{\"version\":1,\"op\":\"GetStatus\",\"runId\":\"$R\"}" | jget members); say "  cgroup members (worker tree): $(printf '%s' "$MEM" | $NODE -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(String(JSON.parse(s).length))}catch(e){process.stdout.write("?")}})') processes"
call "{\"version\":1,\"op\":\"Terminate\",\"runId\":\"$R\"}" >/dev/null; sleep 1
say "  unrelated process after Terminate: alive=$(alive "$UNREL") (expect yes)"; kill -9 "$UNREL" 2>/dev/null
call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null

say "## broker death (stop the socket) stops bound runs"
R="bd$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"lifecycle-tree\"}" >/dev/null; sleep 3
P=$(call "{\"version\":1,\"op\":\"GetStatus\",\"runId\":\"$R\"}" | jget members | $NODE -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(String(JSON.parse(s)[0]||"").replace(/\D/g,"").slice(0,0)||JSON.parse(s)[0].match(/pid=(\d+)/)[1])}catch(e){process.stdout.write("")}})')
systemctl stop codeparley-broker.socket; sleep 2
say "  bound run unit after socket stop: $(systemctl show codeparley-run-$R.service -p ActiveState --value)/$(systemctl show codeparley-run-$R.service -p LoadState --value) (expect inactive/not-found); worker pid alive=$(alive "${P:-0}") (expect no)"
systemctl start codeparley-broker.socket; sleep 1
say "  broker after restart: $(call '{"version":1,"op":"Ping"}' | jget state)"
S=$(call "{\"version\":1,\"op\":\"GetStatus\",\"runId\":\"$R\"}"); evidence "$R"; say "  run final state: $(printf '%s' "$S" | jget state) (expect interrupted)"
call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null

say "## workspace relock + orphan recovery"
ORPH="orphan00000000"; install -d -o root -g cp-worker -m 0770 "$CGRP/$ORPH"
R="or$(date +%H%M%S)"; call "{\"version\":1,\"op\":\"LaunchWorkload\",\"runId\":\"$R\",\"workloadKey\":\"proof-battery\"}" >/dev/null
say "  forged orphan after a launch: $(stat -c '%A' "$CGRP/$ORPH") (expect drwx------)"
wait_terminal "$R" >/dev/null
say "  own workspace after terminal: $(stat -c '%A' "$CGRP/$R" 2>/dev/null) (expect drwx------)"
call "{\"version\":1,\"op\":\"Cleanup\",\"runId\":\"$R\"}" >/dev/null; rm -rf "$CGRP/$ORPH"

say "## filesystem-resolver self-test"
say "  $(/opt/codeparley-broker/bin/codeparley-broker selftest-fs 2>&1 | tail -1)"
say ""
say "Evidence saved under $OUT (capabilities.json, proof-battery.json, journal-*.txt, summary.txt)."
chown -R "$CONTROLLER" "$OUT" 2>/dev/null || true
echo "DONE"
