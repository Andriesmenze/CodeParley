# Development

## Requirements

- Node.js `^26.13.0` (the range in `package.json` `engines`: Node.js 26 LTS, the one supported major) with its
  bundled npm, and git. On Linux the official Node.js 26 build needs `libatomic1`.
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

### Fast feedback and full validation

| Command | What it runs |
|---|---|
| `npm run typecheck` | Both TypeScript projects (`src/`, and `src/` with `test/`) |
| `npm run test:quick` | The quick tier: the test files that took at most 2 s in CI on each platform, and new files |
| `npx vitest run test/<file>.test.ts [-t "<test name>"]` | One test file, or the tests whose name matches |
| `npm run test:changed` | The test files that import, directly or not, a file changed since the last commit |
| `npm test` | The whole suite: what a change has to pass |
| `CP_TEST_SHARD=2/3 npm test` | One of CI's shards (PowerShell: `$env:CP_TEST_SHARD='2/3'; npm test`) |

The quick tier is a selection by recorded duration, not a test class: it holds pure logic and schema tests as well as
fast platform and contract tests, and leaves out the integration suites that build repositories and run processes.
`test:changed` follows vitest's module graph: the suites that run `src/` compiled in a child process, and the files a
test reads at run time, are invisible to it. Neither replaces `npm test`.

`test/durations.json` records each test file's duration in CI, per platform. `test/schedule.ts` uses it to deal the
files to CI's shards, to start the longest files first in CI and to pick the quick tier; what a test asserts never
depends on it. A stale entry makes a shard or the quick tier slower, never smaller: every file is dealt to a shard, a
shard only excludes the files dealt to the others, and a file with no entry stays in the quick tier. After large test
changes, refresh it from the logs of CI's test jobs (all shards of a platform; each log lists its files' durations),
or from full-suite runs with the JSON reporter:

```bash
gh api repos/vanderMerkProjects/CodeParley/actions/jobs/<job id>/logs > job-1.log
node scripts/ci/test-durations.mjs --platform win32 --source "<which runs>" --log job-1.log --log job-2.log [--prune]
npx vitest run --reporter=json --outputFile=report.json
node scripts/ci/test-durations.mjs --platform linux --source "<which runs>" report.json
```

CI's runners are what the shards are balanced for, so their logs are the better source: a development machine is
slower or faster file by file, and may run tests a runner skips.

The fixtures (repositories, data homes, scratch folders) are made under the system temporary directory and removed
after each test file by `test/setup-temp-dirs.ts`, without following links: fixtures hold junctions and symbolic
links on purpose. A test that makes a temporary directory takes it from `tempDir()` (`test/helpers/git-fixture.ts`) or
wraps it in `trackTemp()` (`test/helpers/temp-dirs.ts`). `CP_TEST_KEEP_TMP=1` keeps them, to inspect a run.

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

`.github/workflows/ci.yml` runs on pull requests, pushes to `main` and manual runs, the same nine jobs each time:
Windows and Linux on Node 26, the one supported Node.js major (`test/ci-workflow.test.ts` keeps the matrix on the major
`package.json` `engines` names). Each platform runs as one verify job and the test job's shards, at the same time:

- `windows · Node 26.x · verify` typechecks, builds, builds and self-tests the platform's custodian, runs the Windows
  diagnostic (the custodian's run corpus on its own), the install smoke test and the plugin build;
- `windows · Node 26.x · tests 1/4` to `4/4` (on Linux `1/2` and `2/2`) each build the custodian, which the suite's
  real-custodian contract tests run, and run a part of the test files (`CP_TEST_SHARD`), dealt by their recorded
  durations so that the parts take about as long. Together they run every test file once. On Windows the shards
  set `CP_TEST_GIT=auto`: `test/test-git.ts` finds Git for Windows' own binary in the installation of the git on
  PATH (`mingw64\bin\git.exe` up to 2.55, `ucrt64\bin\git.exe` from 2.56), checks it against the stable
  `cmd\git.exe` and puts it first on PATH, so the suite runs git without the launcher (a second process per call),
  as a local run from Git Bash does. The log's `test git:` line names the binary; if none is verified, the suite runs
  the git on PATH and the line says `FALLBACK`. An explicit path is checked and refused if it is not that
  installation's git. The verify job keeps the runner's PATH.

A platform and Node.js version has passed only when its verify job and all its shards have.

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
