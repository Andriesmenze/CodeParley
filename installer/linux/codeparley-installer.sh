#!/bin/bash
# CodeParley Linux installer (Phase 6 Increment 2; contract §6.1, §6.4, §8 A-5). Run as root. It installs the custodian,
# its sockets and the helper units, and the engine runtime, from the staged release artifacts, checking every one
# against the release manifest first; no .NET SDK or Node.js is needed on this machine.
#
#   codeparley-installer.sh install   --release <dir> --implementer <login> --operator <login> [--codex <dir>] [--load-apparmor]
#   codeparley-installer.sh upgrade   --release <dir>        (backs the store up, migrates it)
#   codeparley-installer.sh upgrade   --resume
#   codeparley-installer.sh rollback                         (the kept previous build and the backup taken for it)
#   codeparley-installer.sh uninstall                        (keeps the store, backups, trusted configuration, accounts, grants)
#   codeparley-installer.sh purge     --confirm-store /var/lib/codeparley
#   codeparley-installer.sh grant-repository  --path <repository>
#   codeparley-installer.sh revoke-repository --path <repository>
#   codeparley-installer.sh status
#
# <dir> holds release-manifest.json and the artifacts it lists. The owner verifies the manifest's signature first
# (A-4/A-5); this script verifies the size and SHA-256 of every artifact it installs, and the BUILD-ID inside.
# --codex <dir> copies the administrator's Codex (bin/codex, codex-resources/bwrap) to /opt/codeparley-codex/<version>/;
# --load-apparmor then loads the profile for its bwrap — a machine-wide change the owner approves. It installs the
# implementer's command /usr/local/bin/code-parley and the operator's /usr/local/sbin/code-parley-operator. The installer
# never approves a runtime or a configuration on the operator's behalf.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

OPT=/opt/codeparley
STORE=/var/lib/codeparley
BACKUPS=/var/lib/codeparley-backups
RECORD_DIR=/var/lib/codeparley-install
RECORD=$RECORD_DIR/record.json
ETC=/etc/codeparley
MARKER=$ETC/restore-marker.json
PROFILE=/etc/apparmor.d/codeparley-codex-bwrap
CUST=codeparley
HELPER=codeparley-helper
GROUPS_=(codeparley-impl codeparley-op codeparley-read codeparley-readers)
SOCKETS=(codeparley-implementer.socket codeparley-operator.socket codeparley-helper.socket)
UNITS=(codeparley-implementer.socket codeparley-operator.socket codeparley-custodian.service codeparley-helper.socket codeparley-helper@.service)

die() { echo "codeparley-installer: $*" >&2; exit 1; }
step() { echo "- $*"; }
[ "$(id -u)" = 0 ] || die "run as root"
command -v python3 >/dev/null || die "python3 is required (it reads the release manifest and the install record)"

VERB=${1-}; shift || true
RELEASE= IMPLEMENTER= OPERATOR= CODEX= LOAD_APPARMOR=0 RESUME=0 REPO= CONFIRM=
while [ $# -gt 0 ]; do
  case $1 in
    --release) RELEASE=$2; shift 2 ;;
    --implementer) IMPLEMENTER=$2; shift 2 ;;
    --operator) OPERATOR=$2; shift 2 ;;
    --codex) CODEX=$2; shift 2 ;;
    --load-apparmor) LOAD_APPARMOR=1; shift ;;
    --resume) RESUME=1; shift ;;
    --path) REPO=$2; shift 2 ;;
    --confirm-store) CONFIRM=$2; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done

# ---- the install record (root 0600) ----
record_get() { [ -f "$RECORD" ] && python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else (json.dumps(v) if isinstance(v,(list,dict)) else v))' "$RECORD" "$1" || true; }
record_set() { # <key> <json value>
  install -d -o root -g root -m 0700 "$RECORD_DIR"
  python3 -I - "$RECORD" "$1" "$2" <<'PY'
import json, os, sys
path, key, value = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
o = json.load(open(path)) if os.path.exists(path) else {"schema": "codeparley.install-record.v1", "items": [], "repositories": [], "backups": []}
o[key] = value
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(o, f, indent=1); f.write("\n"); f.flush(); os.fsync(f.fileno())
os.chmod(tmp, 0o600); os.replace(tmp, path)
PY
}
record_append() { # <list key> <json object> [<match key>]: replace any entry with the same <match key>
  local cur; cur=$(record_get "$1"); [ -n "$cur" ] || cur='[]'
  record_set "$1" "$(python3 -I -c 'import json,sys; l=json.loads(sys.argv[1]); e=json.loads(sys.argv[2]); k=sys.argv[3]; l=[x for x in l if not k or x.get(k)!=e.get(k)]; l.append(e); print(json.dumps(l))' "$cur" "$2" "${3-}")"
}

# ---- artifacts: checked against the manifest before anything is installed (A-5) ----
manifest() { # prints "<version> <commit> <releaseCandidate>"
  [ -n "$RELEASE" ] || die "--release <dir with release-manifest.json> is required"
  [ -f "$RELEASE/release-manifest.json" ] || die "no release-manifest.json in $RELEASE"
  python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); assert m["schema"]=="codeparley.release-manifest.v1", "not a CodeParley release manifest"; print(m["version"], m["commit"], str(m["releaseCandidate"]).lower())' "$RELEASE/release-manifest.json"
}
artifact() { # <name>: verifies it and prints its path
  local line file size sha
  line=$(python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); e=[a for a in m["artifacts"] if a["name"]==sys.argv[2]]; print(e[0]["file"], e[0]["size"], e[0]["sha256"]) if len(e)==1 else sys.exit(1)' "$RELEASE/release-manifest.json" "$1") || die "the manifest lists no artifact $1"
  read -r file size sha <<<"$line"
  [[ $file =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "the manifest names an unexpected file for $1"
  [ -f "$RELEASE/$file" ] && [ ! -L "$RELEASE/$file" ] || die "$file is missing from $RELEASE"
  [ "$(stat -c %s "$RELEASE/$file")" = "$size" ] || die "$file is not the size the manifest says; nothing was installed"
  echo "$sha  $RELEASE/$file" | sha256sum --strict -c --quiet - || die "$file does not have the SHA-256 the manifest says; nothing was installed"
  echo "$RELEASE/$file"
}
unpack() { # <archive> <destination> <artifact name> <version> <commit>: a root-owned tree, no group/other write
  rm -rf "$2"; install -d -o root -g root -m 0755 "$2"
  tar -C "$2" --no-same-owner --no-same-permissions -xzf "$1"
  [ -z "$(find "$2" ! -type f ! -type d -print -quit)" ] || { rm -rf "$2"; die "$1 holds a link or special file"; }
  chown -R root:root "$2"; chmod -R u=rwX,go=rX "$2"
  python3 -I -c 'import json,sys; b=json.load(open(sys.argv[1])); sys.exit(0 if (b["artifact"],b["version"],b["commit"])==(sys.argv[2],sys.argv[3],sys.argv[4]) else 1)' "$2/BUILD-ID" "$3" "$4" "$5" || { rm -rf "$2"; die "the BUILD-ID inside $1 does not match the manifest"; }
}

# The system libraries the bundled Node.js needs (its ELF DT_NEEDED entries), read from the verified engine archive in
# memory and resolved against the dynamic linker's cache, before anything is changed. Conditional on the runtime by
# construction: a Node.js 25 or later official build needs libatomic.so.1 (not installed by default on a minimal Ubuntu),
# a Node.js 24 build does not. The installer never installs packages itself.
check_runtime_libraries() { # <engine archive>
  local needed lib missing=() cache
  needed=$(python3 -I - "$1" <<'PY'
import struct, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as t:
    m = next((m for m in t.getmembers() if m.name in ("./node", "node")), None)
    if m is None or not m.isreg():
        sys.exit("the engine archive has no node at its root")
    b = t.extractfile(m).read()
if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
    sys.exit("the bundled node is not a 64-bit little-endian ELF image")
phoff, = struct.unpack_from("<Q", b, 0x20)
phentsize, phnum = struct.unpack_from("<HH", b, 0x36)
loads, dyn = [], None
for i in range(phnum):
    p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", b, phoff + i * phentsize)
    if p_type == 1: loads.append((p_vaddr, p_offset, p_filesz))
    if p_type == 2: dyn = (p_offset, p_filesz)
if dyn is None:
    sys.exit("the bundled node has no dynamic section")
def off(vaddr):
    for v, o, n in loads:
        if v <= vaddr < v + n: return o + vaddr - v
    sys.exit("the bundled node's string table is outside its loaded segments")
strtab, needs = None, []
for i in range(dyn[0], dyn[0] + dyn[1], 16):
    tag, val = struct.unpack_from("<qQ", b, i)
    if tag == 0: break
    if tag == 5: strtab = val
    if tag == 1: needs.append(val)
if strtab is None:
    sys.exit("the bundled node has no string table")
base = off(strtab)
for n in needs:
    s = b[base + n:b.index(b"\0", base + n)].decode("ascii")
    print(s)
PY
) || die "cannot read the bundled Node.js's library needs from $1; nothing was changed"
  [ -n "$needed" ] || die "the bundled Node.js in $1 names no library; nothing was changed"
  cache=$(ldconfig -p 2>/dev/null) || die "ldconfig -p failed: the libraries the bundled Node.js needs cannot be checked; nothing was changed"
  while read -r lib; do
    # ldconfig -p lists "<tab><soname> (libc6,x86-64[, OS ABI: ...]) => <path>".
    grep -qF -- $'\t'"$lib (libc6,x86-64" <<<"$cache" || missing+=("$lib")
  done <<<"$needed"
  [ ${#missing[@]} = 0 ] && return 0
  for lib in "${missing[@]}"; do
    case $lib in
      libatomic.so.1) echo "codeparley-installer: the bundled Node.js needs $lib, which is not installed (apt install libatomic1)" >&2 ;;
      *) echo "codeparley-installer: the bundled Node.js needs $lib, which is not installed" >&2 ;;
    esac
  done
  die "nothing was changed"
}
# The bundled Node.js starts, as the helper account with an empty environment, and is the version its BUILD-ID names.
manifest_node() { # <artifact name>: the node version the manifest's BUILD-ID of that artifact names
  python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); e=[a for a in m["artifacts"] if a["name"]==sys.argv[2]]; print(e[0]["buildId"]["node"]) if len(e)==1 and e[0].get("buildId",{}).get("node") else sys.exit(1)' "$RELEASE/release-manifest.json" "$1"
}
runtime_starts() { # <engine dir> <expected version>
  local got; got=$(runuser -u "$HELPER" -- env -i "$1/node" --version 2>/dev/null) || return 1
  [ "$got" = "$2" ]
}

custodian_of() { echo "$OPT/custodian/$1/codeparley-custodian"; }
# As the custodian's account and with the service's umask (UMask=0027): a store file the migration writes is then the
# custodian's, group-readable at most, as its own start-time check requires.
as_custodian() { runuser -u "$CUST" -- /bin/sh -c 'umask 0027; exec "$@"' sh "$@"; }
store_status() { as_custodian "$1" store-status; }
assert_servable() { # L-1, before an upgrade, rollback or uninstall
  local kind; kind=$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["kind"])' "$1")
  case $kind in newer) die "the store is newer than this build: $1 (install the matching build, or roll back to it)" ;; unreadable) die "the store's format marker is unreadable: $1" ;; esac
}
stop_all() { systemctl stop codeparley-custodian.service 'codeparley-helper@*' "${SOCKETS[@]}" >/dev/null 2>&1 || true; }
# Earlier failed starts (a refused store, an interrupted upgrade) leave the units failed and rate-limited: cleared first,
# so the next connection starts the custodian again.
start_all() {
  systemctl daemon-reload
  systemctl reset-failed codeparley-custodian.service "${SOCKETS[@]}" >/dev/null 2>&1 || true
  systemctl enable "${SOCKETS[@]}" >/dev/null 2>&1
  systemctl start "${SOCKETS[@]}"
}

deploy_units() { # <custodian dir>
  local d=$1/deploy u
  for u in "${UNITS[@]}"; do install -o root -g root -m 0644 "$d/systemd/$u" "/etc/systemd/system/$u"; done
  # The service runs the installed build through the current link.
  sed -i "s#^ExecStart=.*#ExecStart=$OPT/custodian/current/codeparley-custodian#" /etc/systemd/system/codeparley-custodian.service
  sed -i "s#^ExecStart=.*#ExecStart=$OPT/custodian/current/codeparley-custodian helper#" /etc/systemd/system/codeparley-helper@.service
  install -o root -g root -m 0644 "$d/tmpfiles.d/codeparley.conf" /etc/tmpfiles.d/codeparley.conf
  install -o root -g root -m 0755 "$d/operator/code-parley-operator" /usr/local/sbin/code-parley-operator
  install -o root -g root -m 0755 "$d/operator/code-parley" /usr/local/bin/code-parley
  systemd-tmpfiles --create /etc/tmpfiles.d/codeparley.conf
}

install_codex() { # the administrator's Codex, copied root-owned; its bwrap's AppArmor profile staged (loaded only on request)
  [ -n "$CODEX" ] || return 0
  [ -f "$CODEX/bin/codex" ] && [ -f "$CODEX/codex-resources/bwrap" ] || die "--codex $CODEX has no bin/codex and codex-resources/bwrap"
  local v; v=$("$CODEX/bin/codex" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "cannot read the Codex version from $CODEX/bin/codex"
  local dest=/opt/codeparley-codex/$v
  install -d -o root -g root -m 0755 /opt/codeparley-codex
  rm -rf "$dest"; install -d -o root -g root -m 0755 "$dest"
  tar -C "$CODEX" -cf - bin codex-resources | tar -C "$dest" --no-same-owner -xf -
  chown -R root:root "$dest"; chmod -R u=rwX,go=rX "$dest"; chmod 0755 "$dest/bin/codex" "$dest/codex-resources/bwrap"
  sed "s#@CODEX_VERSION@#$v#" "$1/deploy/apparmor/codeparley-codex-bwrap.in" > "$OPT/codeparley-codex-bwrap.profile"
  if [ "$LOAD_APPARMOR" = 1 ]; then
    install -o root -g root -m 0644 "$OPT/codeparley-codex-bwrap.profile" "$PROFILE"
    apparmor_parser -r "$PROFILE" || { rm -f "$PROFILE"; die "apparmor_parser refused the profile (removed)"; }
    step "loaded the AppArmor profile for $dest/codex-resources/bwrap"
  else
    step "staged the AppArmor profile at $OPT/codeparley-codex-bwrap.profile (not loaded: --load-apparmor, with the owner's approval)"
  fi
  record_append items "{\"kind\":\"codex\",\"name\":\"$dest\"}" name
  echo "Codex $v: $dest/bin/codex"
}

new_backup() { # <version> <store format>: prints the backup's SHA-256 (L-4: root-only 0700; the last two kept)
  install -d -o root -g root -m 0700 "$BACKUPS"
  local f; f="$BACKUPS/store-$(date -u +%Y%m%dT%H%M%SZ)-$1.tar.gz"
  tar --xattrs --acls --numeric-owner -C /var/lib -czpf "$f" codeparley
  chmod 0600 "$f"
  local sha; sha=$(sha256sum "$f" | cut -c1-64)
  record_append backups "{\"file\":\"$f\",\"sha256\":\"$sha\",\"version\":\"$1\",\"storeFormat\":$2,\"takenAt\":\"$(date -u +%FT%TZ)\"}" file
  local all; all=$(record_get backups)
  record_set backups "$(python3 -I -c 'import json,os,sys; l=json.loads(sys.argv[1]); [os.remove(x["file"]) for x in l[:-2] if os.path.exists(x["file"])]; print(json.dumps(l[-2:]))' "$all")"
  echo "$sha"
}

do_install() {
  # Every tool a later step needs, before anything is changed.
  local t; for t in findmnt dumpe2fs setfacl getfacl runuser systemctl systemd-tmpfiles useradd groupadd usermod; do
    command -v "$t" >/dev/null || die "$t is required (setfacl/getfacl: apt install acl; dumpe2fs: apt install e2fsprogs); nothing was changed"
  done
  [ ! -f "$RECORD" ] || [ -z "$(record_get version)" ] || die "CodeParley is already installed here; use upgrade (or uninstall first)"
  [ ! -e "$OPT/custodian/codeparley-custodian" ] || die "a test-arrangement install is present (/opt/codeparley/custodian/codeparley-custodian): remove it first"
  [ -n "$IMPLEMENTER" ] && [ -n "$OPERATOR" ] || die "install needs --implementer <login> and --operator <login>"
  [ "$IMPLEMENTER" != "$OPERATOR" ] || die "the operator must be a separate account from the implementer"
  id "$IMPLEMENTER" >/dev/null 2>&1 && id "$OPERATOR" >/dev/null 2>&1 || die "both human accounts must exist (the installer never creates them)"
  local version commit rc; read -r version commit rc < <(manifest)
  [ "$rc" = true ] || echo "warning: this manifest is NOT a release candidate (a dry run)" >&2
  local cust engine; cust=$(artifact custodian-linux-x64); engine=$(artifact engine-runtime-linux-x64)
  local node; node=$(manifest_node engine-runtime-linux-x64) || die "the manifest's engine runtime names no Node.js version; nothing was changed"
  check_runtime_libraries "$engine"
  for g in "${GROUPS_[@]}"; do getent group "$g" >/dev/null || groupadd --system "$g"; done
  id "$CUST" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group "$CUST"
  id "$HELPER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group --groups codeparley-readers "$HELPER"
  usermod -aG codeparley-impl,codeparley-read "$IMPLEMENTER"
  usermod -aG codeparley-op,codeparley-read "$OPERATOR"
  record_set implementer "\"$IMPLEMENTER\""; record_set operator "\"$OPERATOR\""
  install -d -o root -g root -m 0755 "$OPT" "$OPT/custodian" "$OPT/engine" "$ETC"
  unpack "$cust" "$OPT/custodian/$version" custodian-linux-x64 "$version" "$commit"
  chmod 0755 "$(custodian_of "$version")"
  ln -sfn "$version" "$OPT/custodian/current"
  unpack "$engine" "$OPT/engine/$version" engine-runtime-linux-x64 "$version" "$commit"
  chmod 0755 "$OPT/engine/$version/node"
  runtime_starts "$OPT/engine/$version" "$node" || { rm -rf "${OPT:?}/engine/$version" "${OPT:?}/custodian/$version" "$OPT/custodian/current"; die "the bundled Node.js does not start as $HELPER or is not $node; its version directories were removed and no service was set up"; }
  ln -sfn "$version" "$OPT/engine/current"
  deploy_units "$OPT/custodian/$version"
  printf '{"implementer": "%s", "operator": "%s", "helper": "%s", "codexProfile": "%s"}\n' "$IMPLEMENTER" "$OPERATOR" "$HELPER" "$PROFILE" > "$ETC/custodian.json"
  chmod 0644 "$ETC/custodian.json"
  [ -f "$ETC/filesystems.json" ] || { echo '{"filesystems": []}' > "$ETC/filesystems.json"; chmod 0644 "$ETC/filesystems.json"; }
  # The custodian serves only from a store on an admitted filesystem (its host check): admit the store's own.
  admit_filesystem "$STORE" "$version"
  install_codex "$OPT/custodian/$version"
  record_set version "\"$version\""; record_set previousVersion null
  start_all
  step "installed CodeParley $version; the sockets listen and the custodian starts at the first connection"
  echo "Next: each protected repository - the implementer runs code-parley init --repo <repository>; this installer's grant-repository --path <repository>; the operator account: /usr/local/sbin/code-parley-operator setup --repo <repository> --proposal-file <the implementer's proposals>"
  echo "Each protected repository: codeparley-installer.sh grant-repository --path <repository> (its filesystem is admitted then)"
}

do_upgrade() {
  if [ "$RESUME" = 1 ]; then
    local v; v=$(record_get version); [ -n "$v" ] || die "nothing is installed by this installer to resume"
    stop_all
    as_custodian "$(custodian_of "$v")" store-upgrade --resume || die "the store upgrade did not complete; repair it and run upgrade --resume again, or rollback"
    start_all; step "the store upgrade completed"; return
  fi
  local cur; cur=$(record_get version); [ -n "$cur" ] || die "nothing is installed by this installer: use install"
  local version commit rc; read -r version commit rc < <(manifest)
  [ "$version" != "$cur" ] || die "CodeParley $version is already installed"
  local cust engine; cust=$(artifact custodian-linux-x64); engine=$(artifact engine-runtime-linux-x64)
  local node; node=$(manifest_node engine-runtime-linux-x64) || die "the manifest's engine runtime names no Node.js version; nothing was changed"
  check_runtime_libraries "$engine"
  assert_servable "$(store_status "$(custodian_of "$cur")")"
  unpack "$cust" "$OPT/custodian/$version" custodian-linux-x64 "$version" "$commit"; chmod 0755 "$(custodian_of "$version")"
  unpack "$engine" "$OPT/engine/$version" engine-runtime-linux-x64 "$version" "$commit"; chmod 0755 "$OPT/engine/$version/node"
  runtime_starts "$OPT/engine/$version" "$node" || { rm -rf "${OPT:?}/engine/$version" "${OPT:?}/custodian/$version"; die "the bundled Node.js does not start as $HELPER or is not $node; its version directories were removed; $cur still runs and the store is unchanged"; }
  local before; before=$(store_status "$(custodian_of "$version")")
  assert_servable "$before"
  stop_all
  local sha; sha=$(new_backup "$cur" "$(python3 -I -c 'import json,sys; o=json.loads(sys.argv[1]); print(o["format"] or o["serves"])' "$before")")
  step "backed the store up (SHA-256 $sha)"
  record_set previousVersion "\"$cur\""; record_set version "\"$version\""
  ln -sfn "$version" "$OPT/custodian/current"; ln -sfn "$version" "$OPT/engine/current"
  deploy_units "$OPT/custodian/$version"
  # The migration writes the store as the custodian's account, so every file stays the custodian's.
  as_custodian "$(custodian_of "$version")" store-upgrade --backup-sha256 "$sha" || die "the store upgrade did not complete; the service stays stopped: run upgrade --resume, or rollback"
  for d in "$OPT/custodian" "$OPT/engine"; do
    # Version directories only: the `current` link (which a "*/" glob also matches) is never removed.
    for v in "$d"/*/; do [ -L "${v%/}" ] && continue; v=$(basename "$v"); [ "$v" = "$version" ] || [ "$v" = "$cur" ] || rm -rf "${d:?}/$v"; done
  done
  start_all
  step "upgraded to CodeParley $version"
  echo "The engine runtime changed: the operator approves it again (/usr/local/sbin/code-parley-operator setup --resume --repo <repository>; code-parley status --repo <repository> shows what else is needed); protected reviews are refused until then."
}

do_rollback() {
  local prev cur; prev=$(record_get previousVersion); cur=$(record_get version)
  [ -n "$prev" ] || die "there is no kept previous build to roll back to"
  [ -x "$(custodian_of "$prev")" ] || die "the previous build $(custodian_of "$prev") is missing"
  local line file sha
  line=$(python3 -I -c 'import json,sys; l=[b for b in json.loads(sys.argv[1]) if b["version"]==sys.argv[2]]; print(l[-1]["file"], l[-1]["sha256"]) if l else sys.exit(1)' "$(record_get backups)" "$prev") || die "there is no backup taken for $prev (L-6: a rollback is only to the build that matches the backup)"
  read -r file sha <<<"$line"
  echo "$sha  $file" | sha256sum --strict -c --quiet - || die "the backup $file does not have its recorded SHA-256: it is never restored"
  # A rollback target must serve the backup's store format; anything else is refused before the store is touched.
  local bfmt serves
  bfmt=$(python3 -I -c 'import json,sys; l=[b for b in json.loads(sys.argv[1]) if b["file"]==sys.argv[2]]; print(l[-1].get("storeFormat",""))' "$(record_get backups)" "$file")
  serves=$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["serves"])' "$(store_status "$(custodian_of "$prev")")")
  [ -n "$bfmt" ] && [ "$bfmt" = "$serves" ] || die "the backup holds store format ${bfmt:-unknown}, the previous build $prev serves format $serves: not a compatible rollback target; nothing was changed"
  # The archive is read whole before anything is changed: one that cannot be read leaves the store as it is.
  tar -tzf "$file" >/dev/null || die "the backup $file cannot be read; the store is unchanged"
  # The previous engine still starts (a library removed since it was installed would stop it): checked before anything
  # is stopped.
  local pnode; pnode=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["node"])' "$OPT/engine/$prev/BUILD-ID") || die "the previous engine's BUILD-ID names no Node.js version; nothing was changed"
  runtime_starts "$OPT/engine/$prev" "$pnode" || die "the previous engine's Node.js ($OPT/engine/$prev/node) does not start as $HELPER or is not $pnode; nothing was changed"
  stop_all
  step "restoring the store from $file"
  find "$STORE" -mindepth 1 -delete
  tar --xattrs --acls --numeric-owner --same-owner -C /var/lib -xzpf "$file"
  # Without its session marker the restored store is recovered by any build at its next start.
  rm -f "$STORE/session.json"
  local format; format=$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["format"])' "$(store_status "$(custodian_of "$prev")")")
  # L-5: the restore marker, root-owned in /etc/codeparley; the custodian applies the restored epoch once.
  local id; id="rst-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf '{"restoreId": "%s", "restoredAt": "%s", "backupSha256": "%s", "storeFormat": %s}\n' "$id" "$(date -u +%FT%T.0000000Z)" "$sha" "$format" > "$MARKER"
  chown root:root "$MARKER"; chmod 0644 "$MARKER"
  ln -sfn "$prev" "$OPT/custodian/current"; ln -sfn "$prev" "$OPT/engine/current"
  deploy_units "$OPT/custodian/$prev"
  record_set version "\"$prev\""; record_set previousVersion null
  start_all
  step "rolled back from $cur to $prev (restore $id)"
  echo "At its start the custodian ends every open protected run (restored), voids every unconsumed confirmation, suspends every grant and lapses every approval: the operator re-confirms what is still wanted."
}

remove_installed() { # [--purge]
  local v; v=$(record_get version)
  if [ "${1-}" != --purge ] && [ -n "$v" ] && [ -x "$(custodian_of "$v")" ]; then assert_servable "$(store_status "$(custodian_of "$v")")"; fi
  systemctl disable --now codeparley-custodian.service "${SOCKETS[@]}" >/dev/null 2>&1 || true
  systemctl stop 'codeparley-helper@*' >/dev/null 2>&1 || true
  for u in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$u"; done
  [ ! -e "$PROFILE" ] || apparmor_parser -R "$PROFILE" >/dev/null 2>&1 || true
  rm -f /etc/tmpfiles.d/codeparley.conf /usr/local/sbin/code-parley-operator /usr/local/bin/code-parley "$PROFILE"
  rm -rf "$OPT" /opt/codeparley-codex /run/codeparley /run/codeparley-helper
  systemctl daemon-reload
}

do_uninstall() {
  remove_installed
  record_set version null; record_set previousVersion null
  step "uninstalled: the units, the binaries, the engine runtime, both commands, the Codex copy and the AppArmor profile are removed"
  echo "Kept (each removed by: codeparley-installer.sh purge --confirm-store $STORE):"
  echo "  the protected store        $STORE"
  echo "  the backups                $BACKUPS"
  echo "  the trusted configuration  $ETC"
  echo "  the accounts and groups    $CUST $HELPER ${GROUPS_[*]}"
  python3 -I -c 'import json,sys; [print("  the repository grant       "+r["path"]+"   (revoke: codeparley-installer.sh revoke-repository --path "+r["path"]+")") for r in json.loads(sys.argv[1] or "[]")]' "$(record_get repositories)"
}

acl_repo() { # grant <repository> (prints the ancestors it gave a traverse entry) | revoke <repository> [<ancestors...>]
  command -v setfacl >/dev/null || die "setfacl is required (apt install acl)"
  local repo=$2 p
  if [ "$1" = grant ]; then
    # Traverse only where others cannot already search (a home directory 0750, say), and only those are recorded.
    p=$(dirname "$repo")
    while [ "$p" != / ]; do
      if [ $(( 0$(stat -c %a "$p") & 1 )) -eq 0 ]; then setfacl -m "u:$CUST:--x,g:codeparley-readers:--x" "$p"; echo "$p"; fi
      p=$(dirname "$p")
    done
    setfacl -m "u:$CUST:r-x" "$repo"
    setfacl -R -m g:codeparley-readers:rX "$repo"
    find "$repo" -type d -exec setfacl -d -m g:codeparley-readers:rX {} +
  else
    for p in "${@:3}"; do setfacl -x "u:$CUST,g:codeparley-readers" "$p" 2>/dev/null || true; done
    setfacl -x "u:$CUST" "$repo" 2>/dev/null || true
    setfacl -R -x g:codeparley-readers "$repo" 2>/dev/null || true
    find "$repo" -type d -exec setfacl -d -x g:codeparley-readers {} + 2>/dev/null || true
  fi
}

admit_filesystem() { # <path> [<version>]: its ext4 filesystem (metadata_csum, 256-byte inodes, D-L1), recorded in filesystems.json
  local mnt source fstype hdr fsid; mnt=$(findmnt -n -o TARGET -T "$1"); read -r source fstype < <(findmnt -n -o SOURCE,FSTYPE -M "$mnt")
  [ "$fstype" = ext4 ] || die "$1 is on $fstype, not ext4 (only ext4 is admitted)"
  hdr=$(dumpe2fs -h "$source" 2>/dev/null) || die "dumpe2fs -h $source failed"
  grep -q '^Filesystem features:.* metadata_csum' <<<"$hdr" || die "$mnt has no metadata_csum: not admitted"
  [ "$(sed -n 's/^Inode size:[[:space:]]*//p' <<<"$hdr")" -ge 256 ] || die "$mnt has inodes smaller than 256 bytes: not admitted"
  fsid=$(as_custodian "$(custodian_of "${2:-$(record_get version)}")" fsid "$mnt" | python3 -I -c 'import json,sys; o=json.load(sys.stdin); print(o["fsid"] if o.get("ok") else "")')
  [[ $fsid =~ ^[0-9a-f]{16}$ ]] || die "the custodian could not read the fsid of $mnt"
  python3 -I - "$ETC/filesystems.json" "$fsid" <<'PY'
import json, os, sys
path, fsid = sys.argv[1], sys.argv[2]
o = json.load(open(path))
o["filesystems"] = [f for f in o.get("filesystems", []) if f.get("fsid") != fsid] + [{"fsid": fsid, "metadataCsum": True, "inodeSize": 256}]
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(o, f, indent=1); f.write("\n"); f.flush(); os.fsync(f.fileno())
os.chmod(tmp, 0o644); os.replace(tmp, path)
PY
}

do_grant() {
  [ -n "$REPO" ] || die "grant-repository needs --path <repository>"
  [ -n "$(record_get version)" ] || die "CodeParley is not installed by this installer"
  local repo; repo=$(readlink -f "$REPO"); [ -d "$repo" ] && [ "$repo" = "$REPO" ] || die "$REPO must be a plain existing directory (no link)"
  admit_filesystem "$repo"
  local ancestors; ancestors=$(acl_repo grant "$repo" | python3 -I -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
  record_append repositories "{\"path\":\"$repo\",\"ancestors\":$ancestors,\"grantedAt\":\"$(date -u +%FT%TZ)\"}" path
  step "granted the custodian and the helper read on $repo (recorded); restart the custodian to admit its filesystem: systemctl restart codeparley-custodian.service"
}

do_revoke() {
  [ -n "$REPO" ] || die "revoke-repository needs --path <repository>"
  local anc=(); mapfile -t anc < <(python3 -I -c 'import json,sys; [print(a) for r in json.loads(sys.argv[1] or "[]") if r["path"]==sys.argv[2] for a in r.get("ancestors",[])]' "$(record_get repositories)" "$REPO")
  acl_repo revoke "$REPO" "${anc[@]}"
  record_set repositories "$(python3 -I -c 'import json,sys; print(json.dumps([r for r in json.loads(sys.argv[1] or "[]") if r["path"]!=sys.argv[2]]))' "$(record_get repositories)" "$REPO")"
  step "revoked the grants on $REPO"
}

do_purge() {
  [ "$CONFIRM" = "$STORE" ] || die "purge removes the protected store, its backups, the accounts and every grant: confirm by naming the store exactly: --confirm-store $STORE"
  local repos impl op; repos=$(record_get repositories); impl=$(record_get implementer); op=$(record_get operator)
  remove_installed --purge
  local problems=()
  while IFS=$'\t' read -r r a; do [ -z "$r" ] || acl_repo revoke "$r" $a || problems+=("the grant on $r"); done < <(python3 -I -c 'import json,sys; [print(r["path"]+"\t"+" ".join(r.get("ancestors",[]))) for r in json.loads(sys.argv[1] or "[]")]' "$repos")
  for u in "$impl" "$op"; do [ -z "$u" ] || for g in "${GROUPS_[@]}"; do gpasswd -d "$u" "$g" >/dev/null 2>&1 || true; done; done
  rm -rf "$STORE" "$BACKUPS" "$ETC" "$RECORD_DIR" || problems+=("a store, backup or configuration directory")
  for u in "$HELPER" "$CUST"; do id "$u" >/dev/null 2>&1 && { userdel "$u" || problems+=("the account $u"); }; done
  for g in "${GROUPS_[@]}" "$CUST" "$HELPER"; do getent group "$g" >/dev/null && { groupdel "$g" || problems+=("the group $g"); }; done
  [ ${#problems[@]} -eq 0 ] || die "purge could not remove: ${problems[*]}"
  step "purged: everything the installer created is removed"
}

do_status() {
  local v; v=$(record_get version)
  systemctl --no-pager --lines=0 status codeparley-custodian.service "${SOCKETS[@]}" 2>/dev/null | grep -E '^●|Active:' || true
  echo "installed version  ${v:-none} (previous: $(record_get previousVersion))"
  [ -z "$v" ] || echo "store              $(store_status "$(custodian_of "$v")" 2>&1)"
  python3 -I -c 'import json,sys; [print("backup             "+b["file"]+" ("+b["version"]+", SHA-256 "+b["sha256"]+")") for b in json.loads(sys.argv[1] or "[]")]; [print("repository grant   "+r["path"]) for r in json.loads(sys.argv[2] or "[]")]' "$(record_get backups)" "$(record_get repositories)"
}

case $VERB in
  install) do_install ;;
  upgrade) do_upgrade ;;
  rollback) do_rollback ;;
  uninstall) do_uninstall ;;
  purge) do_purge ;;
  grant-repository) do_grant ;;
  revoke-repository) do_revoke ;;
  status) do_status ;;
  *) die "usage: codeparley-installer.sh install|upgrade|rollback|uninstall|purge|grant-repository|revoke-repository|status [options] (see the header)" ;;
esac
