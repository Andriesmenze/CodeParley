# Releasing CodeParley

How a release goes from a qualified build to a published GitHub release. Tools do the building, copying and checking;
**only the owner signs**, with the release key on a YubiKey, and only the owner publishes. No tool in this repository
signs, pushes a tag or creates, edits or publishes a GitHub release.

Users verify a release with [verifying-releases.md](verifying-releases.md). CodeParley **1.0.0** was signed and
published with its original eleven-file procedure (its records are in the private archive); this workflow and its
twelve-file verifier apply from 1.0.1 on. 1.0.0 is verified with `verifying-releases.md` alone.

## Trust boundaries

| Stage | Where | Who | Tools | Produces |
|---|---|---|---|---|
| 1. Build | A build machine (it may run model sessions) | Maintainer | `scripts/package/stage-release.mjs` | The staged artifacts and the unsigned manifest |
| 2. Qualify | The release gates | Maintainer, then the TD | The release gates | The TD's acceptance record: version, source commit, **manifest SHA-256** |
| 3. Prepare | The build machine | Maintainer | `scripts/package/prepare-signing.mjs` | A signing package outside the repository |
| 4. Sign | The owner's Windows machine, model sessions closed, a fresh clone | **Owner only** | `gpg`, `git tag -s`; checked by `verify-release.mjs` | `release-manifest.json.asc`, the tag |
| 5. Publish | The same, after the owner's explicit authorization | **Owner only** | `git push`, `gh release`; checked by `verify-release.mjs` and by hand | The GitHub release |

What each stage trusts:

- **Prepare** copies the staged files byte for byte (nothing is rebuilt after qualification) and refuses anything that
  does not match the accepted digest.
- **Sign and publish** trust only:
  - the version, source commit and manifest SHA-256 that **the owner types from the TD's acceptance record**;
  - the release key pinned in `scripts/package/lib/release-verify.mjs` and in the source commit's
    `docs/codeparley-release-key.asc`;
  - what the verifier recomputes.

  The verifier runs from a fresh clone, not from the build machine. It checks signatures in a temporary GnuPG home
  holding only the pinned public key, with smart cards disabled; every GnuPG call it makes, `--version` included, uses
  such a home.
- **The package is never an authority.** Its `SIGNING-REQUEST.md` is a comparison sheet with no commands. Its
  `signing-request.json` must agree with the owner's values, and can only narrow a check: the approved subkey it names
  must be the one that signed.
- **The owner chooses the GnuPG executable:** Gpg4win's `C:\Program Files\GnuPG\bin\gpg.exe`, signed by `g10 Code GmbH`.

## Keys

| Key | Fingerprint | Signs |
|---|---|---|
| Release key, primary (certification only) | `7CC498583C78D63448E0EFA45E1FB31A78518E8C` | Nothing directly |
| Release signing subkey, **current**, on each of the owner's YubiKeys, expires 2028-10-31 | `EFD68E181281081CBFA601EC35208A9E3684E6C9` | The release manifest and the release tag (from 1.0.0) |
| Commit-signing key (`.github/ci/commit-signing-key.asc`) | `261E3060E70B4904615F17BD026A2C3E92B42B25` | Commits only |

The two identities never stand in for each other. The verifier refuses:
- a manifest or tag signed by the commit key;
- a commit that is not signed by the commit key;
- a commit-key file that contains the release key.

Rules for the release key:
- no private key is exported;
- the PIN and touch are entered by the owner on the device, never by a tool;
- no model session (Claude Code, Codex) runs on the machine while the YubiKey is inserted;
- the key's recovery backup never goes onto a development machine.

**The approved subkeys** (`RELEASE_KEY.subkeys` in `scripts/package/lib/release-verify.mjs`) are an append-only
history, with exactly one current subkey.

| Situation | What the tools do |
|---|---|
| A new signing request | `prepare-signing.mjs` names the current subkey, and refuses if the source commit's key file lacks it, or if it is expired or revoked |
| A signature or tag | Must be by the subkey the request names, which must be approved, of the pinned primary |
| The published key file | May carry no signing subkey that is not approved |

**Expiry, rotation and revocation:**

- **A key that expired after signing:** GnuPG reports `EXPKEYSIG` instead of `GOODSIG`. The verifier accepts it only
  for an approved subkey, with a cryptographically valid signature (`VALIDSIG`), whose stated signing time lies inside
  the subkey's validity (not before its creation, before its expiry).
  - That time is the signer's own claim, so the check only rejects inconsistent signatures. It proves nothing about
    when the signing happened.
  - A release's identity rests on the manifest SHA-256 in the TD's acceptance record, which the verifier always checks.
  - GnuPG itself refuses to make a signature with an expired subkey.
- **Failures, always, for any release:** an expired *signature* (`EXPSIG`), a bad signature, an unknown key and a
  GnuPG failure.
- **A revoked key** (`REVKEYSIG`, or a key file showing the primary revoked) is an automatic FAIL, historical
  releases included. An exception needs a separate, explicit decision of the TD and the owner, after assessing why the
  key was revoked.
- **Extending the expiry** (`gpg --quick-set-expire 7CC4…8E8C <period> EFD6…E6C9`, the owner, on the offline key)
  keeps the fingerprint. It needs no pin change, only the updated public key in a reviewed commit.
- **Rotating to a new subkey** is a separately reviewed change. The owner creates the subkey and puts it on the
  YubiKeys. Then one commit:
  - appends the new subkey to `RELEASE_KEY.subkeys`, marks it current and unmarks the old one;
  - replaces `docs/codeparley-release-key.asc` with the export carrying **all** subkeys;
  - updates the table above and `verifying-releases.md`.

  No subkey is ever removed from the history or from the key file, so earlier releases still verify.

## The signing package

`prepare-signing.mjs` writes it outside the repository. Exactly these files, nothing else:

| File | From | Released |
|---|---|---|
| `release-manifest.json` and the nine artifacts it lists | `stage-release.mjs`, copied | Yes |
| `code-parley-<v>.tgz.BUILD-ID`, `codeparley-installer.ps1.BUILD-ID`, `codeparley-installer.sh.BUILD-ID` | `stage-release.mjs`, copied | No (the manifest holds the same BUILD-IDs) |
| `signing-request.json`, `SIGNING-REQUEST.md` (comparison only) | `prepare-signing.mjs` | No |
| `release-manifest.json.asc` | The owner | Yes |
| `codeparley-release-key.asc` | `verify-release.mjs payload`, from the source commit | Yes |
| `release-payload.json`, `RELEASE-NOTES.md` | `verify-release.mjs payload` | No (the notes become the release text) |
| `verified-<step>.json`, `RELEASE-REPORT.md` | `verify-release.mjs` | No (the records) |

The GitHub release is exactly twelve files: the manifest, its signature, the release key and the nine artifacts.

**Records:**
- A step first deletes its own old record. It then records its result, the values it ran with and the release state
  it checked: the hashes of every package file, the signature, the local tag object, the key file and the payload list.
  An error is recorded as a FAIL.
- `verify-release.mjs report` recomputes that state. A step counts as verified only when all of these hold:
  - its record passed;
  - it was made with exactly the report's version, commit, digest and mode;
  - the state it checked is unchanged.

  Anything else is FAIL or "not verified". The report's verdict names the last step reached without a gap. It is
  never the TD's acceptance.

## The procedure

### 1–3. Build, qualify, prepare (maintainer)

```powershell
node scripts/package/stage-release.mjs --node-win <node.exe> --node-linux <node> --out <staged> --gpg 'C:/Program Files/GnuPG/bin/gpg.exe'
# ...the release gates, then the TD records its acceptance: version, source commit, manifest SHA-256...
node scripts/package/prepare-signing.mjs --staged <staged> --out <package> --version <v> --commit <commit> --manifest-sha256 <digest> --gpg 'C:\Program Files\GnuPG\bin\gpg.exe'
```

`prepare-signing.mjs` checks:
- **The commit:** signed by the commit key; `package.json` at that version; pinning the release key with the current
  subkey, unexpired.
- **The manifest:** the accepted digest; the version and commit; a clean build of a verified commit; unsigned; each
  artifact once, in order.
- **Every artifact:** size; SHA-256; and the BUILD-ID inside the archive or beside it, which must equal the
  manifest's. All artifacts must share one toolchain and one build time.

Running it again with the same arguments leaves a complete package as it is, even after signing. A package that
differs is refused and left alone. An interrupted run leaves a `<package>.partial-*` directory, which the next run
removes.

### 4. Sign (owner)

Close every Claude Code and Codex session and open PowerShell 7 outside the Claude app. Type the three values from the
**TD's acceptance record**, not from the package or its `SIGNING-REQUEST.md`; then compare them with that sheet.

```powershell
$gpg = 'C:\Program Files\GnuPG\bin\gpg.exe'
$s = Get-AuthenticodeSignature $gpg; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'CN=g10 Code GmbH') { throw 'STOP: not Gpg4win' }
$clone = Read-Host 'A fresh clone of https://github.com/vanderMerkProjects/CodeParley'
git -C $clone fetch origin
git -C $clone checkout --detach origin/main
git -C $clone -c "gpg.program=$gpg" verify-commit HEAD          # a good signature by the commit key 261E3060…2B25
$version = Read-Host 'Version, from the TD acceptance record'
$commit  = Read-Host 'Source commit (40 hex), from the TD acceptance record'
$digest  = Read-Host 'Manifest SHA-256 (64 hex), from the TD acceptance record'
$pkg     = Read-Host 'The signing package directory'
$v = @('--dir', $pkg, '--version', $version, '--commit', $commit, '--manifest-sha256', $digest, '--gpg', $gpg, '--repo', $clone)
node "$clone\scripts\package\verify-release.mjs" package @v
```

Insert the YubiKey. Check that `--card-status` lists the signature key `EFD68E18…E6C9`. Then sign, re-checking the
manifest's hash in the same command:

```powershell
& $gpg --card-status
if ((Get-FileHash -Algorithm SHA256 -LiteralPath "$pkg\release-manifest.json").Hash.ToLowerInvariant() -cne $digest) { throw 'STOP: the manifest is not the accepted one' }
& $gpg --armor --detach-sign --local-user 'EFD68E181281081CBFA601EC35208A9E3684E6C9!' --output "$pkg\release-manifest.json.asc" "$pkg\release-manifest.json"
node "$clone\scripts\package\verify-release.mjs" signature @v
$msg = Join-Path $env:TEMP "codeparley-tag-$version.txt"
[IO.File]::WriteAllText($msg, "CodeParley $version`n`nRelease manifest SHA-256: $digest`n")
git -C $clone -c "gpg.program=$gpg" -c "user.signingkey=EFD68E181281081CBFA601EC35208A9E3684E6C9!" tag -s "v$version" $commit -F $msg
node "$clone\scripts\package\verify-release.mjs" tag @v
```

Then remove the YubiKey.
- The `!` makes GnuPG use exactly the current subkey. GnuPG asks for the PIN in its own window, and for a touch if the
  card's signature touch policy is on.
- `gpg --card-status` shows the touch policy as `UIF setting ......: Sign=on`. The owner turns it on with
  `gpg --card-edit`, `admin`, `uif 1 on` (the Admin PIN is needed), on each YubiKey.
- The tag message comes from the owner's typed values; no file in the package supplies it.

### 5. Publish (owner, each command only after authorizing it)

```powershell
node "$clone\scripts\package\verify-release.mjs" payload @v     # adds the release key; lists the twelve files
gh api repos/vanderMerkProjects/CodeParley --jq .id              # must print 1443307878
git -C $clone push origin "refs/tags/v$version"
$files = (Get-Content -Raw "$pkg\release-payload.json" | ConvertFrom-Json).files | ForEach-Object { Join-Path $pkg $_.name }
gh release create "v$version" --repo vanderMerkProjects/CodeParley --draft --verify-tag --title "CodeParley $version" --notes-file "$pkg\RELEASE-NOTES.md" @files
node "$clone\scripts\package\verify-release.mjs" remote @v      # GitHub-REPORTED sizes and digests of the draft
```

`remote` reads only, through `gh api`. It checks:
- the repository has ID `1443307878` and is public;
- GitHub's tag is the verified tag object;
- the release is a draft (or, with `--published`, published), not a pre-release;
- it has exactly the twelve files, each uploaded with the payload's size and `sha256:` digest **as GitHub reports
  them**.

These are server-reported values, not an independent download-and-hash check, so the owner also checks a downloaded
copy, of the draft, before publishing:

```powershell
$dl = Join-Path $env:TEMP "codeparley-$version-download"; if (Test-Path $dl) { throw 'STOP: choose an empty directory' }
New-Item -ItemType Directory $dl | Out-Null
gh release download "v$version" --repo vanderMerkProjects/CodeParley --dir $dl
$want = (Get-Content -Raw "$pkg\release-payload.json" | ConvertFrom-Json).files
if (Compare-Object ($want.name | Sort-Object) ((Get-ChildItem -LiteralPath $dl).Name | Sort-Object)) { throw 'STOP: the downloaded files are not the payload' }
foreach ($f in $want) { if ((Get-FileHash -Algorithm SHA256 -LiteralPath "$dl\$($f.name)").Hash.ToLowerInvariant() -cne $f.sha256) { throw "STOP: $($f.name) differs" } }
if ((Get-FileHash -Algorithm SHA256 -LiteralPath "$dl\release-manifest.json").Hash.ToLowerInvariant() -cne $digest) { throw 'STOP: not the accepted manifest' }
$h = Join-Path $env:TEMP ("codeparley-verify-" + [guid]::NewGuid()); New-Item -ItemType Directory $h | Out-Null
& $gpg --homedir $h --batch --import "$clone\docs\codeparley-release-key.asc"
$st = & $gpg --homedir $h --batch --status-fd 1 --verify "$dl\release-manifest.json.asc" "$dl\release-manifest.json"
& (Join-Path (Split-Path $gpg) 'gpgconf.exe') --homedir $h --kill all; Remove-Item -Recurse -Force $h
if (-not ($st -match '^\[GNUPG:\] GOODSIG ') -or -not ($st -match '^\[GNUPG:\] VALIDSIG EFD68E181281081CBFA601EC35208A9E3684E6C9 .* 7CC498583C78D63448E0EFA45E1FB31A78518E8C$')) { throw 'STOP: not a good signature by the release key' }
'PASS: the downloaded draft is the verified payload, and its manifest is the accepted one, signed by the release key'
```

That is the user's check of `verifying-releases.md`, done on GitHub's copy: the files compared with the owner's
verified package, the manifest with the accepted digest, and the signature with the release key from the verified
clone. `gh release download` finds a draft by its pending tag (an authenticated lookup) and downloads its uploaded
files, according to the GitHub CLI's source (`pkg/cmd/release/shared/fetch.go`, `download/download.go`). **It was not
tested on a draft**, because no draft could be created while this workflow was built. If the download fails, stop:
publishing without this check needs the owner's explicit, recorded decision.

```powershell
gh release edit "v$version" --repo vanderMerkProjects/CodeParley --draft=false
node "$clone\scripts\package\verify-release.mjs" remote @v --published
node "$clone\scripts\package\verify-release.mjs" report @v      # RELEASE-REPORT.md, for the TD
```

## When a check fails

Stop. Do not edit, re-stage or re-sign around it. The step's `verified-<step>.json` says what failed.

- **A package or manifest mismatch:** a new build is a new candidate, which goes through the gates again.
- **A bad signature or tag:** delete only what the owner just made, then repeat that step. That is
  `release-manifest.json.asc`, or the local tag with `git tag -d v<v>` before it is pushed.
- **A remote or download mismatch:** delete the draft release's wrong file in GitHub and upload it again. A pushed tag
  is never moved.

## Rehearsal

- **Staging:** `stage-release.mjs --test-version <v>-rehearsal.<n>` stages a test build from a clean, signed commit.
- **`--rehearsal`,** on both scripts:
  - accepts only such a build;
  - marks the package and every record as a rehearsal;
  - checks `package.json` against the version before the suffix.
- **Signing:** a rehearsal package is signed only with a disposable test key, and the verifier then reports that the
  signature is not the release key's, as it should.
- **Tests:** `test/release-signing.test.ts` runs the whole procedure with disposable keys, including expiry, rotation
  and revocation.
