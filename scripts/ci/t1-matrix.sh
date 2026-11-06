#!/usr/bin/env bash
# Phase 6 Increment 1 (contract §4.1, T1): one full local matrix run of .github/workflows/ci.yml on the exact signed
# commit, sequentially (the process-tree tests are load-sensitive): Windows, then Linux (WSL2) in an ext4 mirror with
# .git, on the one supported Node.js major (package.json engines; the single-runtime policy), then the identity job. Run
# from Git Bash on Windows, in the checkout to validate, with a clean tree at the commit. Each platform runs the verify
# job and then the test job with the whole suite (CP_TEST_SHARD empty): one machine runs all of its CI shards (Step 6).
#
#   bash scripts/ci/t1-matrix.sh --sha <full commit id> --out <run dir> [--node <node.exe>] [--wsl-node <major>]
#        [--compare-node <node.exe>] [--compare-wsl-node <major>] [--min-free-gb <n>]
#
# --node is the Windows node.exe (default: the node on PATH); --wsl-node the WSL Node.js under ~/.local/opt/node<major>
# (default 26). --compare-node / --compare-wsl-node add a run on another Node.js only for a targeted comparison (a
# suspected regression of the supported major); the default run has none.
#
# Disk guard (an earlier run exhausted C:): before each job it removes the test fixtures THIS run left in %TEMP% (the
# suites' arl-*, cp-*, cps-* folders created since the run started and idle for 2 minutes — nothing older, nothing
# else) and stops the run when C: has less than --min-free-gb free (default 1). The Linux jobs remove their /tmp
# fixtures the same way. Every free-space reading is logged in <run dir>/driver.log; a stopped or failed job keeps its
# logs (an invalid environmental run is evidence, not discarded).
#
# WSL has no .NET SDK here, so the Linux custodian is cross-built on Windows from the same clean commit with the pinned
# SDK and placed where the workflow's self-test step runs it; the runner records "Build the Linux custodian" and
# "Versions" as substituted.
set -u
SHA="" OUT="" NODE="" WSL_NODE=26 COMPARE_NODE="" COMPARE_WSL="" MIN_FREE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --sha) SHA=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --node) NODE=$2; shift 2 ;;
    --wsl-node) WSL_NODE=$2; shift 2 ;;
    --compare-node) COMPARE_NODE=$2; shift 2 ;;
    --compare-wsl-node) COMPARE_WSL=$2; shift 2 ;;
    --min-free-gb) MIN_FREE=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ $SHA =~ ^[0-9a-f]{40}$ ]] || { echo "--sha must be a full 40-character commit id" >&2; exit 2; }
[ -n "$OUT" ] || { echo "--out is required" >&2; exit 2; }
for m in "$WSL_NODE" ${COMPARE_WSL:+"$COMPARE_WSL"}; do [[ $m =~ ^[0-9]+$ ]] || { echo "a WSL Node.js is given by its major" >&2; exit 2; }; done
REPO=$(git rev-parse --show-toplevel)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -W)
wslpath_of() { MSYS_NO_PATHCONV=1 wsl.exe -e wslpath -a "$1" | tr -d '\r'; }
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/driver.log"; }
START=$(date +"%Y-%m-%d %H:%M:%S")

guard() {
  local free
  free=$(powershell.exe -NoProfile -Command "\$s=[datetime]'$START'; Get-ChildItem \$env:TEMP -Directory -ErrorAction SilentlyContinue | Where-Object { \$_.Name -match '^(arl-|cp-|cps-)' -and \$_.CreationTime -ge \$s -and \$_.LastWriteTime -lt (Get-Date).AddMinutes(-2) } | Remove-Item -Recurse -Force -Confirm:\$false -ErrorAction SilentlyContinue; [math]::Round((Get-PSDrive C).Free/1GB,2)" | tr -d '\r')
  log "C: free $free GB"
  awk -v f="$free" -v m="$MIN_FREE" 'BEGIN { exit !(f + 0 >= m + 0) }' || { log "STOP: less than $MIN_FREE GB free on C:"; exit 3; }
}

cd "$REPO" || exit 1
log "T1 on $SHA in $REPO; HEAD $(git rev-parse HEAD); $(git status --porcelain | wc -l) changed path(s)"
[ "$(git rev-parse HEAD)" = "$SHA" ] || { log "HEAD is not $SHA"; exit 1; }
[ -z "$(git status --porcelain)" ] || { log "the checkout is not clean"; exit 1; }

# The Windows test job's CP_TEST_GIT, as the workflow computes it (test/test-git.ts finds Git for Windows' own binary).
WIN_TEST_GIT=auto
windows() { # <node.exe or empty for the node on PATH> <label>
  local job
  for job in verify test; do
    guard; log "$job windows $2 ($("${1:-node}" --version))"
    node scripts/ci/run-workflow-local.mjs --job $job --expect "$SHA" --set VERIFIED_SHA="$SHA" --set CP_TEST_SHARD= --set CP_TEST_GIT="$WIN_TEST_GIT" ${1:+--node "$1"} --log "$OUT/windows-$2-$job" >> "$OUT/driver.log" 2>&1; log "exit $?"
  done
}
windows "$NODE" node
[ -z "$COMPARE_NODE" ] || windows "$COMPARE_NODE" compare

guard; log "linux custodian cross-build"
rm -rf "$OUT/linux-cust"
dotnet publish custodian/CodeParley.Custodian.Linux/CodeParley.Custodian.Linux.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o "$OUT/linux-cust" -nologo -v q >> "$OUT/driver.log" 2>&1; log "exit $?"

W_OUT=$(wslpath_of "$OUT"); W_REPO=$(wslpath_of "$REPO"); W_GIT=$(wslpath_of "$(cd "$(git rev-parse --git-common-dir)" && pwd -W)")
cat > "$OUT/linux.sh" <<EOF
set -u
M=\$HOME/src/CodeParley-ci
bash "$W_REPO/scripts/ci/linux-mirror.sh" "$W_GIT" $SHA "\$M" || exit 1
cd "\$M"
for v in $WSL_NODE $COMPARE_WSL; do
  mkdir -p custodian/CodeParley.Custodian.Linux/bin/Release/net10.0
  install -m 755 "$W_OUT/linux-cust/codeparley-custodian" custodian/CodeParley.Custodian.Linux/bin/Release/net10.0/codeparley-custodian
  for job in verify test; do
    echo "[\$(date +%H:%M:%S)] \$job linux node\$v"
    PATH="\$HOME/.local/opt/node\$v/bin:\$PATH" node scripts/ci/run-workflow-local.mjs --job \$job --expect $SHA --set VERIFIED_SHA=$SHA --set CP_TEST_SHARD= --set CP_TEST_GIT= --log "$W_OUT/linux-node\$v-\$job" \\
      --substitute "Versions=no .NET SDK in WSL: node, npm, git and the custodian's version verb are recorded in the run summary and the self-test step" \\
      --substitute "Build the Linux custodian=cross-built on Windows from the same clean commit with the pinned SDK (dotnet publish -r linux-x64 --self-contained), placed at the path the self-test step uses"
    echo "[\$(date +%H:%M:%S)] exit \$?"
  done
  find /tmp -maxdepth 1 -newer "\$M/package.json" \\( -name 'arl-*' -o -name 'cp-*' -o -name 'cps-*' \\) -exec rm -rf {} + 2>/dev/null
done
echo "[\$(date +%H:%M:%S)] identity (Linux)"
PATH="\$HOME/.local/opt/node$WSL_NODE/bin:\$PATH" node scripts/ci/run-workflow-local.mjs --job identity --expect $SHA --log "$W_OUT/identity-linux" --set EXPECTED_SHA=$SHA --set REQUESTED_SHA=$SHA --set MERGE=
echo "[\$(date +%H:%M:%S)] exit \$?"
EOF
guard; log "linux runs"
MSYS_NO_PATHCONV=1 wsl.exe -e bash "$W_OUT/linux.sh" >> "$OUT/driver.log" 2>&1; log "exit $?"
rm -rf "$OUT/linux-cust"
guard; log "done; HEAD $(git rev-parse HEAD); $(git status --porcelain | wc -l) changed path(s)"
