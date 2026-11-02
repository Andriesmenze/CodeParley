#!/bin/sh
# CodeParley Linux broker — uninstaller (Phase 3.1B operator step 3/3). Idempotent. Run as root.
#   uninstall-broker.sh [--purge]
# --purge also removes the state tree (/var/lib/codeparley-broker) and the worker account + home.
set -eu

INSTALL_ROOT=/opt/codeparley-broker
CONFIG_DIR=/etc/codeparley-broker
STATE_ROOT=/var/lib/codeparley-broker
UNIT_DIR=/etc/systemd/system
WORKER_USER=cp-worker
GROUP=codeparley

PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }

echo "== stop any live runs and the socket =="
# Stopping the socket releases every worker run bound to it; then stop any stragglers by name.
systemctl stop 'codeparley-run-*.service' 2>/dev/null || true
systemctl disable --now codeparley-broker.socket 2>/dev/null || true
systemctl reset-failed 'codeparley-broker*' 'codeparley-run-*' 2>/dev/null || true

echo "== remove units =="
rm -f "$UNIT_DIR/codeparley-broker.socket" "$UNIT_DIR/codeparley-broker@.service"
systemctl daemon-reload

echo "== remove install tree and config =="
rm -rf "$INSTALL_ROOT"
rm -rf "$CONFIG_DIR"

if $PURGE; then
  echo "== purge state and worker account =="
  rm -rf "$STATE_ROOT"
  if getent passwd "$WORKER_USER" >/dev/null; then userdel --remove "$WORKER_USER" 2>/dev/null || userdel "$WORKER_USER" || true; fi
  getent group "$GROUP" >/dev/null && { getent group "$GROUP" | cut -d: -f4 | grep -q . || groupdel "$GROUP" 2>/dev/null || true; } || true
  echo "purged."
else
  echo "left in place: $STATE_ROOT, the '$WORKER_USER' account and the '$GROUP' group (use --purge to remove)."
fi
