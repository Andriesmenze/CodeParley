# Releasing CodeParley

How a release goes from a qualified build to a published GitHub release. Tools do the building, copying and checking;
**only the owner signs**, with the release key on a YubiKey, and only the owner publishes. No tool in this repository
signs, pushes a tag or creates, edits or publishes a GitHub release: each prints the command for the owner instead.

Users verify a release with [verifying-releases.md](verifying-releases.md).

## Trust boundaries

| Stage | Where | Who | Tools | Produces |
|---|---|---|---|---|
| 1. Build | A build machine (it may run model sessions) | Maintainer | `scripts/package/stage-release.mjs` | The staged artifacts and the unsigned manifest |
| 2. Qualify | The release gates | Maintainer, then the TD | The release gates | The **accepted manifest SHA-256** |
| 3. Prepare | The build machine | Maintainer | `scripts/package/prepare-signing.mjs` | A signing package outside the repository |
| 4. Sign | The owner's Windows machine, model sessions closed, a fresh clone | **Owner only** | `gpg`, `git tag -s`; checked by `verify-release.mjs` | `release-manifest.json.asc`, the tag |
| 5. Publish | The same, after the owner's explicit authorization | **Owner only** | `git push`, `gh release`; checked by `verify-release.mjs` | The GitHub release |

What each stage trusts:

- **Prepare** copies the staged files byte for byte (nothing is rebuilt after qualification) and refuses anything that
  does not match the accepted digest.
- **Sign and publish** trust only three things: the values from the TD's acceptance (version, commit, manifest SHA-256),
  typed on the command line; the release key pinned in `scripts/package/lib/release-verify.mjs` and in the source
  commit's `docs/codeparley-release-key.asc`; and what the verifier recomputes. The verifier runs from a fresh clone,
  not from the build machine, and checks signatures in a temporary GnuPG home holding only the pinned public key, with
  smart cards disabled. The package's own `signing-request.json` is cross-checked, never trusted.

## Keys

| Key | Fingerprint | Signs |
|---|---|---|
| Release key, primary (certification only) | `7CC498583C78D63448E0EFA45E1FB31A78518E8C` | Nothing directly |
| Release signing subkey, on each of the owner's YubiKeys | `EFD68E181281081CBFA601EC35208A9E3684E6C9` | The release manifest and the release tag |
| Commit-signing key (`.github/ci/commit-signing-key.asc`) | `261E3060E70B4904615F17BD026A2C3E92B42B25` | Commits only |

The two identities never stand in for each other: the verifier refuses a manifest or tag signed by the commit key, a
commit that is not signed by the commit key, and a commit-key file that contains the release key.

Rules for the release key: no private key export; the PIN and touch are entered by the owner on the device, never by a
tool; no model session (Claude Code, Codex) runs on the machine while the YubiKey is inserted; the key's recovery
backup never goes onto a development machine.

## The signing package

`prepare-signing.mjs` writes it outside the repository. Exactly these files, nothing else:

| File | From | Released |
|---|---|---|
| `release-manifest.json` and the nine artifacts it lists | `stage-release.mjs`, copied | Yes |
| `code-parley-<v>.tgz.BUILD-ID`, `codeparley-installer.ps1.BUILD-ID`, `codeparley-installer.sh.BUILD-ID` | `stage-release.mjs`, copied | No (the manifest holds the same BUILD-IDs) |
| `signing-request.json`, `SIGNING-REQUEST.md` | `prepare-signing.mjs` | No |
| `TAG-MESSAGE.txt` | `prepare-signing.mjs`: `CodeParley <v>`, a blank line, `Release manifest SHA-256: <digest>` | No (it is the tag's message) |
| `release-manifest.json.asc` | The owner | Yes |
| `codeparley-release-key.asc` | `verify-release.mjs payload`, from the source commit | Yes |
| `release-payload.json`, `RELEASE-NOTES.md` | `verify-release.mjs payload` | No (the notes become the release text) |
| `verified-<step>.json`, `RELEASE-REPORT.md` | `verify-release.mjs` | No (the records) |

The GitHub release is exactly twelve files: the manifest, its signature, the release key and the nine artifacts.

## The procedure

`<v>`, `<commit>` and `<digest>` are the version, the source commit and the manifest SHA-256 **from the TD's
acceptance**. `SIGNING-REQUEST.md` in the package has every command below with the values filled in.

### 1–3. Build, qualify, prepare (maintainer)

```powershell
node scripts/package/stage-release.mjs --node-win <node.exe> --node-linux <node> --out <staged> --gpg 'C:/Program Files/GnuPG/bin/gpg.exe'
# ...the release gates, then the TD accepts the manifest's SHA-256...
node scripts/package/prepare-signing.mjs --staged <staged> --out <package> --version <v> --commit <commit> --manifest-sha256 <digest> --gpg 'C:\Program Files\GnuPG\bin\gpg.exe'
```

`prepare-signing.mjs` checks the commit (signed by the commit key, `package.json` at that version, pinning the release
key), the manifest (the accepted digest, the version and commit, a clean build of a verified commit, unsigned, each
artifact once in order) and every artifact (size, SHA-256, and the BUILD-ID inside the archive or beside it, which must
equal the manifest's; one toolchain and one build time for all). Run again with the same arguments, it leaves a
complete package as it is, even after signing; a package that differs is refused and left alone. An interrupted run
leaves a `<package>.partial-*` directory, which the next run removes.

### 4. Sign (owner)

Close every Claude Code and Codex session, open PowerShell 7 outside the Claude app, then follow
`SIGNING-REQUEST.md`. In short:

```powershell
$gpg = 'C:\Program Files\GnuPG\bin\gpg.exe'
$pkg = '<package>'
$clone = '<a fresh clone of https://github.com/vanderMerkProjects/CodeParley>'
git -C $clone fetch origin
git -C $clone checkout --detach origin/main
git -C $clone -c "gpg.program=$gpg" verify-commit HEAD     # the verifier's own commit, by the commit key
$v = @('--dir', $pkg, '--version', '<v>', '--commit', '<commit>', '--manifest-sha256', '<digest>', '--gpg', $gpg, '--repo', $clone)

node "$clone\scripts\package\verify-release.mjs" package @v
& $gpg --card-status                                        # the signature key must be EFD68E18…E6C9
Set-Location -LiteralPath $pkg
& $gpg --armor --detach-sign --local-user 'EFD68E181281081CBFA601EC35208A9E3684E6C9!' --output release-manifest.json.asc release-manifest.json
node "$clone\scripts\package\verify-release.mjs" signature @v
git -C $clone -c "gpg.program=$gpg" -c "user.signingkey=EFD68E181281081CBFA601EC35208A9E3684E6C9!" tag -s v<v> <commit> -F "$pkg\TAG-MESSAGE.txt"
node "$clone\scripts\package\verify-release.mjs" tag @v
```

Then remove the YubiKey. The `!` makes GnuPG use exactly that subkey. GnuPG asks for the PIN in its own window, and
for a touch if the card's signature touch policy is on. `gpg --card-status` shows it as `UIF setting ......: Sign=on`;
the owner turns it on with `gpg --card-edit`, `admin`, `uif 1 on` (the Admin PIN is needed), on each YubiKey.

`signature` passes only for one good signature, by the pinned subkey of the pinned primary key, over the manifest with
the accepted digest. `tag` passes only for an annotated tag `v<v>` on exactly `<commit>`, with exactly the message in
`TAG-MESSAGE.txt`, signed the same way.

### 5. Publish (owner, each command only after authorizing it)

```powershell
node "$clone\scripts\package\verify-release.mjs" payload @v     # adds the release key; lists the twelve files
gh api repos/vanderMerkProjects/CodeParley --jq .id              # must print 1443307878
git -C $clone push origin refs/tags/v<v>
gh release create v<v> --repo vanderMerkProjects/CodeParley --draft --verify-tag --title "CodeParley <v>" --notes-file "$pkg\RELEASE-NOTES.md" <the twelve files, as payload prints them>
node "$clone\scripts\package\verify-release.mjs" remote @v      # the draft: repository ID, tag object, every file's size and digest
gh release edit v<v> --repo vanderMerkProjects/CodeParley --draft=false
node "$clone\scripts\package\verify-release.mjs" remote @v --published
node "$clone\scripts\package\verify-release.mjs" report @v      # RELEASE-REPORT.md, for the TD
```

`remote` only reads from GitHub (`gh api`): the repository must have ID `1443307878` and be public; GitHub's tag must
be the verified tag object; the release must be a draft (or, with `--published`, published), not a pre-release, with
exactly the twelve files, each uploaded with the payload's size and `sha256:` digest.

## When a check fails

Stop. Do not edit, re-stage or re-sign around it. The step's `verified-<step>.json` says what failed.

- A package or manifest mismatch: a new build is a new candidate, which goes through the gates again.
- A bad signature or tag: delete only what the owner just made (`release-manifest.json.asc`, or the local tag with
  `git tag -d v<v>`, before it is pushed) and repeat that step.
- A remote mismatch: delete the draft release's wrong file in GitHub and upload it again; a pushed tag is never moved.

## Rehearsal

`stage-release.mjs --test-version <v>-rehearsal.<n>` stages a test build from a clean, signed commit; `--rehearsal`
on both scripts accepts only such a build, marks the package and every record as a rehearsal, and checks `package.json`
against the version before the suffix. A rehearsal package is signed only with a disposable test key: the verifier
then reports that the signature is not the release key's, as it should. `test/release-signing.test.ts` runs the whole
procedure with disposable keys.
