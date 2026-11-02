# Verifying a release

A CodeParley release is a set of artifacts and a release manifest, `release-manifest.json`, that lists each artifact
with its size and SHA-256. The manifest is signed with the project's release key. The installers check every artifact
against the manifest, but they do **not** check the manifest's signature: verify it yourself first, or those checks
prove nothing. [install.md](install.md#verify-a-release) has the commands.

## The release key

| | |
|---|---|
| Primary key fingerprint | `7CC4 9858 3C78 D634 48E0  EFA4 5E1F B31A 7851 8E8C` |
| Signing subkey | `EFD6 8E18 1281 081C BFA6  01EC 3520 8A9E 3684 E6C9` (expires 2028-10-31) |
| Public key | [`codeparley-release-key.asc`](codeparley-release-key.asc) in this folder, and attached to each public release |

Check the key before you import it:

```bash
gpg --show-keys --with-subkey-fingerprints codeparley-release-key.asc
```

`gpg --verify` names the subkey that made the signature and prints the `Primary key fingerprint` of its key. Compare
both with this table, character by character. `Good signature` alone only says that some key in your keyring signed
the file.

The release key is not the key that signs this repository's commits.

## What the manifest says

Each manifest entry carries a BUILD-ID: the version, the commit the artifact was built from, the toolchain (the .NET
SDK, Node.js and npm versions) and whether the build was a release candidate (`"releaseCandidate": true`: built from a
clean commit whose signature verified).

## The 1.0.0 release

CodeParley 1.0.0 was released privately. Its binaries are kept in the project's private archive and are **not**
published here. The first public binary release is planned as 1.0.1, built from this repository, with its own
manifest and signatures. For the record, the 1.0.0 release is:

| | |
|---|---|
| Version | `1.0.0` |
| Manifest SHA-256 | `b7b95a07509eaa26f1ff37b930d16f27c6ab27123cf022a4a21184e9d9e2d51f` |
| Built from commit | `f9935276512aa7ef7d167c8a9665abb61d8e9575` |
| Toolchain | .NET SDK 10.0.201, Node.js v24.11.0, npm 11.6.1 |
| Signed tag | `v1.0.0`, tag object `4c74f28ed628df0e66161ae45f3dd25ac60bd370`, in the private archive |

## Source provenance

This repository starts at 1.0.0 from a reviewed snapshot of the sources. The development history, including the commit
`f993527` that the 1.0.0 artifacts were built from and the signed tag that names it, is kept in a private archive,
together with the release-validation evidence. **You cannot resolve `f993527` in this repository.**

What links this repository to the 1.0.0 build is git's own content addressing. A git tree ID is a hash over the names,
modes and contents of every file below a directory, so two directories with the same tree ID hold exactly the same
files. The table below lists the tree IDs that the shipped directories had in `f993527`. Check them against this
repository's first commit, the clean source import; the second commit, a dependency update, already differs:

```bash
c=<first commit>
for d in src prompts installer plugin custodian/CodeParley.Custodian custodian/CodeParley.Custodian.Core \
         custodian/CodeParley.Custodian.Linux custodian/linux/apparmor custodian/linux/operator \
         custodian/linux/systemd custodian/linux/tmpfiles.d scripts/package third-party; do
  echo "$(git rev-parse "$c:$d")  $d"
done
```

The directories the artifacts are built from have the same tree IDs in both:

| Directory | Tree ID | What it builds |
|---|---|---|
| `src` | `f6f8880e598db7e20cc62492c104fab172aa08d6` | the engine (npm tarball, engine runtimes) |
| `prompts` | `670b02c8c7f9ac880fcd55d6fb40690a4d3ddf9a` | the reviewer prompt |
| `installer` | `ca32397b434e27b4da970aa1c471199d4c6cfdf2` | both installers (shipped as they are) |
| `plugin` | `209d3bd774e7d826b575696bc0731823113a6751` | the plugin tarballs |
| `custodian/CodeParley.Custodian` | `a844c420c40374f42fa039605c0f8e3153ecfebb` | the Windows custodian |
| `custodian/CodeParley.Custodian.Core` | `25c0ddc56297a460afc7ad7b7b06bc7c0a7fc355` | both custodians |
| `custodian/CodeParley.Custodian.Linux` | `fbf9c49d75203e5d1942a131e34d19eb359e2fcb` | the Linux custodian |
| `custodian/linux/apparmor` | `2436fd26efed69d279c8184d3553215a9a2ad253` | the Linux custodian's `deploy/` |
| `custodian/linux/operator` | `cd99af899d7e1fbd8be0136906dd3c251b1e149b` | the Linux custodian's `deploy/` |
| `custodian/linux/systemd` | `4715eb9d3b5056d5fa8097ed181d1419ecea3a8b` | the Linux custodian's `deploy/` |
| `custodian/linux/tmpfiles.d` | `206c30f5d2b55e47771d136a076a3d266a040fad` | the Linux custodian's `deploy/` |
| `scripts/package` | `044e63c9b65ad5e7f1d98d61fff6f136137c049b` | the packaging and staging scripts |
| `third-party` | `1e435c387ef95135ad4055ad522a80dc96a8700f` | the bundled licence notices |

The files these builds read at the repository root and in `custodian/` are byte-identical too, and the statement gives
their blob IDs: `package.json` (`b90d0575a305579262d3469faee9228a4aee3aab`), `package-lock.json`
(`2051654162d515eb6ee645288f8fbc1d01fe4ebb`), `tsconfig.json`, `custodian/Directory.Build.props`, `custodian/global.json`
and `custodian/CodeParley.Custodian.slnx`. So are `LICENSE`, `THIRD-PARTY-NOTICES.md`, `broker/`, `.github/` and
`.codacy/`.

What differs from `f993527` in the first commit:

- **`README.md`** has a download location and links to the documents below. It is a build input of the npm tarball,
  so a tarball built from this repository differs from the released one in `README.md`.
- **`docs/install.md`** has the download location, a link here and one sentence on what `releaseCandidate` means.
- **New files:** this file, `docs/development.md`, `SECURITY.md`, `CONTRIBUTING.md` and the release key's public part,
  `docs/codeparley-release-key.asc`.
- **Tests and CI scripts:** `test/custodian-pipe.test.ts` and `scripts/ci/run-with-user-owner.ps1` carry a later
  correction that lets the Windows pipe test run on an elevated CI token. `test/scope.integration.test.ts` uses `src/`
  instead of an unpublished folder as its example subdirectory. No artifact contains them.
- **Not published:** the development-history documents, the validation evidence, the drivers of the qualification
  runs on dedicated test machines, the Linux test-machine privilege tooling and the early feasibility spikes. No
  artifact contains them, and nothing in this repository needs them to build or test. Some source comments still name
  documents that are not published.

### What this does and does not prove

- Equal tree IDs show that the shipped directories of this repository's first commit hold exactly the sources of
  `f993527`'s. They rest on git's SHA-1 object hashing, which git hardens against known collision attacks.
- `f993527` itself, and the build of the 1.0.0 artifacts from it, cannot be checked here: the commit, the signed tag,
  the manifest's signature and the validation records are in the private archive. The tree IDs above are the project's
  own record of that commit; this repository does not make the private commit publicly reproducible.
- Before this repository was created, the engine was rebuilt from these sources with the 1.0.0 toolchain: the compiled
  modules matched the 1.0.0 npm package byte for byte, and both plugin builds matched its plugin contents. The custodian
  binaries and the bundled runtimes were not rebuilt byte for byte.
- From 1.0.1 on, releases are built from this repository's own commits, so their BUILD-IDs and manifests name commits
  you can check here.
