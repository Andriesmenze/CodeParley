#!/bin/sh
# CodeParley Linux broker — installer (Phase 3.1B operator step 1/3). Idempotent and distro-neutral:
# uses only POSIX sh, coreutils, useradd/groupadd and systemctl. Run as root.
#
#   install-broker.sh --controller <user> --payload <dir> [--node <nodedir>] [--git <path>]
#                     [--sibling <path> ...] [--allow-wsl]
#
# --payload   directory holding the published broker binary (codeparley-broker) + workloads/
# --node      a Node.js install dir (containing bin/node); copied into the install tree root-owned.
#             If omitted, the directory of `command -v node` is used.
# --controller the (non-root) account that may call the broker; added to the codeparley group.
# --sibling   a repo path the proof battery should confirm the worker CANNOT write (repeatable).
# --allow-wsl set testOnlyAllowWslHost (development on WSL only; never a security proof).
set -eu

INSTALL_ROOT=/opt/codeparley-broker
CONFIG_DIR=/etc/codeparley-broker
STATE_ROOT=/var/lib/codeparley-broker
UNIT_DIR=/etc/systemd/system
WORKER_USER=cp-worker
GROUP=codeparley

CONTROLLER=; PAYLOAD=; NODE_DIR=; GIT_PATH=; ALLOW_WSL=false
SIBLINGS=
while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER=$2; shift 2 ;;
    --payload) PAYLOAD=$2; shift 2 ;;
    --node) NODE_DIR=$2; shift 2 ;;
    --git) GIT_PATH=$2; shift 2 ;;
    --sibling) SIBLINGS="$SIBLINGS $2"; shift 2 ;;
    --allow-wsl) ALLOW_WSL=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
[ -n "$CONTROLLER" ] || { echo "--controller <user> is required" >&2; exit 64; }
[ -n "$PAYLOAD" ] && [ -x "$PAYLOAD/codeparley-broker" ] || { echo "--payload must hold an executable codeparley-broker" >&2; exit 64; }
[ -d "$PAYLOAD/workloads" ] || { echo "--payload must contain workloads/" >&2; exit 64; }
command -v systemctl >/dev/null 2>&1 || { echo "systemctl not found (systemd is required)" >&2; exit 1; }
CONTROLLER_UID=$(id -u "$CONTROLLER") || { echo "controller '$CONTROLLER' not found" >&2; exit 1; }
[ "$CONTROLLER_UID" != 0 ] || { echo "the controller must not be root" >&2; exit 1; }

if [ -z "$NODE_DIR" ]; then
  NODE_BIN=$(command -v node || true)
  [ -n "$NODE_BIN" ] || { echo "no --node given and node not on PATH" >&2; exit 64; }
  NODE_DIR=$(dirname "$(dirname "$(readlink -f "$NODE_BIN")")")
fi
[ -x "$NODE_DIR/bin/node" ] || { echo "no bin/node under $NODE_DIR" >&2; exit 64; }
if [ -z "$GIT_PATH" ]; then GIT_PATH=$(command -v git || true); fi
[ -x "$GIT_PATH" ] || { echo "git not found (pass --git)" >&2; exit 1; }

echo "== accounts =="
getent group "$GROUP" >/dev/null || groupadd --system "$GROUP"
if ! getent passwd "$WORKER_USER" >/dev/null; then
  useradd --system --create-home --home-dir "/var/lib/$WORKER_USER" \
          --shell /usr/sbin/nologin --comment "CodeParley worker (managed)" "$WORKER_USER"
fi
# The worker must have NO supplementary groups and must NOT be in the controller group.
usermod -G "" "$WORKER_USER" 2>/dev/null || true
gpasswd -d "$WORKER_USER" "$GROUP" 2>/dev/null || true
WORKER_HOME=$(getent passwd "$WORKER_USER" | cut -d: -f6)
install -d -m 0700 -o "$WORKER_USER" -g "$WORKER_USER" "$WORKER_HOME"
# The controller account may call the broker.
id -nG "$CONTROLLER" | tr ' ' '\n' | grep -qx "$GROUP" || usermod -a -G "$GROUP" "$CONTROLLER"

echo "== install tree (root-owned, not group/other-writable) =="
install -d -m 0755 -o root -g root "$INSTALL_ROOT" "$INSTALL_ROOT/bin" "$INSTALL_ROOT/workloads" "$INSTALL_ROOT/toolchain"
install -m 0755 -o root -g root "$PAYLOAD/codeparley-broker" "$INSTALL_ROOT/bin/codeparley-broker"
rm -f "$INSTALL_ROOT/workloads"/*.js
for f in "$PAYLOAD/workloads"/*.js; do install -m 0644 -o root -g root "$f" "$INSTALL_ROOT/workloads/"; done
[ -f "$PAYLOAD/README.md" ] && install -m 0644 -o root -g root "$PAYLOAD/README.md" "$INSTALL_ROOT/README.md" || true
# Resolve a symlinked node dir to the real tree, and copy its CONTENTS into a real root-owned
# directory (so no component of .../toolchain/node is a symlink the trust-chain check would refuse).
NODE_DIR=$(readlink -f "$NODE_DIR")
[ -x "$NODE_DIR/bin/node" ] || { echo "no bin/node under the resolved node dir $NODE_DIR" >&2; exit 64; }
rm -rf "$INSTALL_ROOT/toolchain/node"
install -d -m 0755 -o root -g root "$INSTALL_ROOT/toolchain/node"
cp -a "$NODE_DIR/." "$INSTALL_ROOT/toolchain/node/"
chown -R root:root "$INSTALL_ROOT/toolchain/node"
chmod -R go-w "$INSTALL_ROOT"

echo "== state tree =="
install -d -m 0755 -o root -g root "$STATE_ROOT"
install -d -m 0700 -o root -g root "$STATE_ROOT/state" "$STATE_ROOT/runs"
install -d -m 0711 -o root -g root "$STATE_ROOT/work"

echo "== config =="
install -d -m 0755 -o root -g root "$CONFIG_DIR"
siblings_json=$(printf '%s' "$SIBLINGS" | awk '{for(i=1;i<=NF;i++) printf "%s\"%s\"", (i>1?",":""), $i}')
umask 022
cat > "$CONFIG_DIR/broker.json" <<EOF
{
  "controllerUid": $CONTROLLER_UID,
  "controllerGroup": "$GROUP",
  "workerUser": "$WORKER_USER",
  "gitPath": "$GIT_PATH",
  "maxConcurrentRuns": 1,
  "maxTimeoutSeconds": 3600,
  "testOnlyAllowWslHost": $ALLOW_WSL,
  "proofSiblings": [${siblings_json:-}]
}
EOF
chown root:root "$CONFIG_DIR/broker.json"; chmod 0644 "$CONFIG_DIR/broker.json"

echo "== systemd units =="
SELF=$(cd "$(dirname "$0")" && pwd)
UNIT_SRC="$SELF/../systemd"
[ -f "$UNIT_SRC/codeparley-broker.socket" ] || UNIT_SRC="$PAYLOAD/systemd"
install -m 0644 -o root -g root "$UNIT_SRC/codeparley-broker.socket" "$UNIT_DIR/codeparley-broker.socket"
install -m 0644 -o root -g root "$UNIT_SRC/codeparley-broker@.service" "$UNIT_DIR/codeparley-broker@.service"
systemctl daemon-reload
systemctl enable --now codeparley-broker.socket

echo
echo "installed. verify:  sudo $INSTALL_ROOT/bin/codeparley-broker capabilities"
echo "the controller '$CONTROLLER' must start a new login session for its new group membership."
