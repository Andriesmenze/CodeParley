#!/usr/bin/env bash
# Phase 6 Increment 1 (contract §3.6, OI-3 / P-f): the local Linux test mirror for T1 validation. A WSL2 (or any Linux)
# checkout of exactly one commit, WITH its .git, on an ext4 filesystem: the suites refuse drvfs/9p by design, and tests
# that run git in the repository (test/scope.integration.test.ts) need the repository, not a copy of its files.
#
#   bash scripts/ci/linux-mirror.sh <source repository or git dir> <full commit id> [<mirror, default ~/src/CodeParley-ci>]
#
# From WSL the source is the Windows checkout's common git directory (a worktree's .git file names a Windows path
# Linux git cannot follow), e.g. /mnt/l/Repositories/CodeParley/.git. The mirror is fetched to the commit, checked out
# detached, cleaned (node_modules kept), and must be clean afterwards; the commit is printed with its signature status.
set -euo pipefail

src=${1:?usage: linux-mirror.sh <source repository> <commit> [<mirror>]}
sha=${2:?usage: linux-mirror.sh <source repository> <commit> [<mirror>]}
dest=${3:-$HOME/src/CodeParley-ci}
if ! [[ $sha =~ ^[0-9a-f]{40}$ ]]; then
  echo "linux-mirror: the commit must be a full 40-character id, not '$sha'" >&2
  exit 2
fi
mkdir -p "$(dirname "$dest")"
fs=$(stat -f -c %T "$(dirname "$dest")")
if [ "$fs" != "ext2/ext3" ]; then
  echo "linux-mirror: $(dirname "$dest") is on '$fs', not ext4: the Linux suites need an ext4 checkout" >&2
  exit 2
fi
# The source is the owner's own checkout, read across the WSL boundary (its files belong to another uid).
g() { git -c safe.directory='*' "$@"; }
if [ ! -d "$dest/.git" ]; then
  g clone -q --no-checkout "$src" "$dest"
fi
g -C "$dest" fetch -q "$src" "$sha"
g -C "$dest" -c advice.detachedHead=false checkout -q --force --detach "$sha"
g -C "$dest" clean -q -ffdx -e node_modules
head=$(g -C "$dest" rev-parse HEAD)
if [ "$head" != "$sha" ]; then
  echo "linux-mirror: the mirror is at $head, not $sha" >&2
  exit 1
fi
if [ -n "$(g -C "$dest" status --porcelain)" ]; then
  echo "linux-mirror: the mirror is not clean after checkout" >&2
  g -C "$dest" status --short | head -20 >&2
  exit 1
fi
echo "linux-mirror: $dest at $sha (clean, with .git; $(df -T "$dest" | awk 'NR==2 {print $2}'))"
