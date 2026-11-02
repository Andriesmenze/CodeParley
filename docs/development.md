# Development

## Requirements

- Node.js `^22.12.0 || ^24.0.0` (the range in `package.json` `engines`) with npm, and git.
- The .NET SDK pinned by `custodian/global.json` (10.0.403, later feature bands allowed), for the custodian.
- Windows 11 or Ubuntu 24.04 for the platform-specific suites. Each platform runs its own integration tests and skips
  the other's.

## Build and test

```bash
npm ci
npm run typecheck
npm run build
npm test
```

The custodians and their self-tests, as CI runs them:

```bash
dotnet build custodian/CodeParley.Custodian/CodeParley.Custodian.csproj -c Release            # Windows custodian
dotnet build custodian/CodeParley.Custodian.Linux/CodeParley.Custodian.Linux.csproj -c Release # Linux custodian
node scripts/ci/custodian-selftests.mjs --host windows --exe custodian/CodeParley.Custodian/bin/Release/net10.0-windows/CodeParley.Custodian.exe
node scripts/ci/custodian-selftests.mjs --host linux --exe custodian/CodeParley.Custodian.Linux/bin/Release/net10.0/codeparley-custodian
```

Packaging, without publishing anything:

```bash
npm run package:pack     # the npm tarball, under the content policy in scripts/package/lib/policy.mjs
npm run package:smoke    # installs that tarball into a clean prefix and starts it (uses the npm registry)
node plugin/build-plugin.mjs --out <dir> && node plugin/verify-plugin.mjs <dir>
```

`scripts/package/stage-release.mjs` stages every release artifact and the unsigned manifest from a clean commit whose
signature verifies against `.github/ci/commit-signing-key.asc`; `--allow-dirty` makes a dry run marked
`releaseCandidate: false`. It signs and publishes nothing.

## Test classes

Every test file belongs to one of four classes. A test that does not apply to the platform it runs on is **skipped
and says so**; nothing is silently absent. The gates `supported`, `win` and `linux` are exported by
`test/helpers/git-fixture.ts`.

| Class | Meaning | Runs on |
|---|---|---|
| Platform-independent | Pure logic, or both platforms' rules tested explicitly through a parameter | every platform |
| Shared contract | One behaviour, one test, with a fixture per platform; where the outcome legitimately differs, the test states both | Windows and Linux |
| Windows-specific | `.cmd` shims and `cmd.exe` quoting, junctions, 8.3 names, alternate data streams, `subst` drives, MXC, `taskkill`, named pipes | Windows |
| Linux-specific | sessions and process groups, the session reaper, `/proc`, symbolic links, FIFOs, mount points, XDG locations, data-home permissions, bubblewrap | Linux |

Some cases depend on what the machine has and skip visibly without it: `git-lfs`, the real `npm` shim, `unshare -rm`
for the mount-point cases, and a WSL `/mnt/c` drive for the drvfs refusals.

Opt-in suites:

- `CODEPARLEY_LIVE_CODEX=1 npx vitest run test/review-live.integration.test.ts` runs a real Codex review. It needs a
  logged-in Codex and spends quota.
- `test/compat-fixtures.generate.test.ts` wrote the compatibility stores under `test/fixtures/compat/` by compiling an
  earlier release's sources from its git tag (`CODEPARLEY_GEN_COMPAT`). Those releases' history is not in this
  repository, so the existing stores cannot be regenerated here; they are kept byte for byte and are never edited by
  hand. The compatibility tests that load them run as usual.

## CI

`.github/workflows/ci.yml` runs on pull requests, pushes to `main` and manual runs. A pull request tests Linux on
Node 22 and 24 and Windows on Node 24; `main` and manual runs test the full Windows and Linux by Node 22 and 24 matrix.
Each job typechecks, builds, builds and self-tests both custodians, runs `npm test`, the install smoke test and the
plugin build.

The first job, **Commit identity**, verifies that the commit under test is the expected one and that it is signed by
the key in `.github/ci/commit-signing-key.asc`. Every other job depends on it, so a commit that is not signed with that
key gets no test run (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

The jobs run on GitHub-hosted runners. The repository variables `CP_LINUX_RUNNER` and `CP_WINDOWS_RUNNER` can name
other runners; they are not set for this repository.

## What CI does not cover

Validation that needs a logged-in Codex, real Claude Code and Claude Desktop hosts, an installed custodian service or
separate implementer and operator accounts is not part of CI. For 1.0.0 it was done on dedicated Windows 11 and
Ubuntu 24.04 test machines through the installed artifacts. Those qualification drivers and their evidence are kept
with the project's private records and are not in this repository. [security.md](security.md) states what is claimed
and what is not.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | The engine: MCP server, CLI, capture, Codex isolation, the protected loop's client side |
| `prompts/` | The reviewer prompt, loaded at run time |
| `custodian/` | The .NET custodian service: shared core, Windows service, Linux service, and the Linux deployment files |
| `installer/` | The Windows and Linux installers |
| `plugin/` | The Claude Code plugin builder and template |
| `scripts/package/` | Packaging, release staging and installation checks |
| `scripts/ci/` | CI helpers: commit identity, custodian self-tests, the local workflow runner |
| `test/` | The automated test suite and its fixtures |
| `broker/` | An earlier Windows broker design, kept for reference; not built or shipped |
| `third-party/` | Licence notices for bundled third-party software |
