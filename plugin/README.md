# CodeParley Claude Code plugin

The plugin is how the protected loop reaches a Claude Code session. It contains:

- the **CodeParley MCP server** (`.mcp.json` → `bin/server.mjs`), and
- **thin hooks** (`hooks/hooks.json` → `bin/hook.mjs` → `app/dist/hooks/adapter.js`) that forward host
  facts to CodeParley's engine (`app/dist/engine/continuation.js`), which makes every decision.

Nothing is written into the target repository's `.claude/` directory.

Claude Code (CLI) is the only supported host for the protected workflow and delegated fixes. Claude
Desktop is manual review only, with the server entry in
[docs/install.md](../docs/install.md#manual-review-any-platform).

## Install from a release

The release has one archive per platform. Each is a local marketplace whose server and hooks run the
**installed** engine runtime's Node, so install the product first
([docs/install.md](../docs/install.md)). Do this as the implementer, once per account.

Windows:

```powershell
New-Item -ItemType Directory <dir>
tar -xzf <release dir>\plugin-windows.tar.gz -C <dir>
claude plugin marketplace add <dir>
claude plugin install code-parley@code-parley-local --scope user
```

Linux:

```bash
mkdir -p <dir>
tar -xzf <release dir>/plugin-linux.tar.gz -C <dir>
claude plugin marketplace add <dir>
claude plugin install code-parley@code-parley-local --scope user
```

Keep `<dir>`: a CLI session runs the marketplace folder in place. Start a new session afterwards; a
session keeps what it loaded until it ends.

To remove it:

```bash
claude plugin uninstall code-parley@code-parley-local --scope user
claude plugin marketplace remove code-parley-local
```

The product's `uninstall` and `purge` do not touch the plugin: remove it yourself.

## After an upgrade

| Platform | What to do |
|---|---|
| Windows | Reinstall the plugin from the new release's `plugin-windows` archive after every upgrade or rollback: remove it as above, extract the archive to a new directory, add and install it. Its hooks and server name the versioned engine path. |
| Linux | Nothing. The plugin runs `/opt/codeparley/engine/current/node`, which follows upgrades and rollbacks. |

## Automation starts only with a grant

The plugin starts nothing by itself. The operator first allows automated loops for a repository, typed
at an operator terminal:

Windows, in an elevated terminal as the operator account:

```powershell
code-parley loop allow --repo <path>
```

Linux, as the operator account:

```bash
/usr/local/sbin/code-parley-operator loop allow --repo <path>
```

`code-parley setup` offers the same grant. Each `start_review_loop` consumes one granted loop. Without
the plugin a started loop stays unbound and nothing continues automatically.

## What the hooks do

| Event | Adapter event | What the engine does |
|---|---|---|
| `SessionStart` | `session-start` | A resumed session re-binds its loop in a new epoch; a bound session gets the controller's status as context. |
| `SessionEnd` | `session-end` | Closes the binding when the host delivers it. This is not the only termination signal: the process identity is also checked. |
| `UserPromptSubmit` | `user-prompt-submit` | Tells a user's prompt apart from a host task notification. A user prompt supersedes armed wakes. The host's interrupt marker pauses automation. |
| `PreToolUse` on `mcp__plugin_code-parley_code-parley__.*` | `pre-tool-use` | Correlation only, with no side effects: a call on a run live-bound to another session is denied. |
| `PostToolUse` on `start_review_loop` | `post-tool-use` | Binds the loop. The host supplies the session id and the result supplies the one-time nonce. The first binding wins. |
| `PostToolUse` on `review_with_codex` (`asyncRewake`) | `wake` | The idle-wake waiter: exits 2 once to wake the same idle session when the review it awaits finishes. |
| `Stop` | `stop` | Continues the turn only for an implementer step, within the loop's budget and deadline. |
| `ConfigChange` | `config-change` | During live automation, blocks the change for the running session (exit 2) and pauses the loop. |

A session with no CodeParley binding exits at once, before the engine loads.

## Build from source

```bash
npm run build
node plugin/build-plugin.mjs --out <dir>
```

Add `--home`, `--allowed-root`, `--git`, `--codex` or `--config` to record launch arguments for both
the server and the hooks in `launch.json`. A default build has none, so the default data home and the
default configuration apply.

`--marketplace <dir>` writes the plugin to `<dir>/code-parley` beside a local marketplace manifest.
`--node <executable>` names the Node the plugin runs; `--node-path <path>` names one on the target host
(the release archives use the installed engine runtime's). `--dist <dir>` takes compiled sources from
another directory.

`--test-fake-codex` is for **testing only**. It wires CodeParley's scripted fake Codex into the server
instead of Codex, and it requires `--home` and `--test-scenario-dir`.

The build prints its version and content digest. `node plugin/verify-plugin.mjs <dir> [--against
<dir>] [--expect <digest|version>]` checks any copy of a build (see below).

For one CLI session, without installing anything:

```bash
claude --plugin-dir <dir>
```

## Where a host runs the plugin from, and what an update changes

Measured with Claude Code 2.1.289 (CLI) and 2.1.293 (bundled in Claude Desktop 2.26454.2.0), in an
isolated `CLAUDE_CONFIG_DIR`:

| Step | What happens |
|---|---|
| `plugin install` from a local directory marketplace | Copies the plugin into `<config>/plugins/cache/<marketplace>/<plugin>/<version>/` and records that copy as `installPath` in `installed_plugins.json`. `plugin list` still says "Read from: <the marketplace folder>". |
| A CLI session | Runs the marketplace **folder** in place. |
| Rebuild with the **same** version, then `plugin update` (with or without `plugin marketplace update`) | "read from its folder … nothing to update": the cached copy is **not** refreshed. |
| Rebuild with a **new** version, then `plugin marketplace update` and `plugin update` | A new cache directory for the new version; `installPath` moves to it. |
| Uninstall | Every cached version stays, marked `.orphaned_at`; Claude Code's documented background cleanup removes them about 14 days later. A session that loaded one keeps it until it ends. |

So every build carries its content in its version: `build-plugin.mjs` sets the version to the
template's base version plus a digest of the plugin's files (for this release `1.0.1-b<12 hex>`), and
`build-info.json` records that digest, each file's hash, the source commit and whether the tree had
uncommitted changes. A changed build therefore always gets a new cache directory, and the same build
anywhere has the same identity. After a rebuild:

```bash
claude plugin marketplace update code-parley-local
claude plugin update code-parley@code-parley-local
```

Then start a **new** session. To prove which build a session runs:

1. Find its plugin root: the MCP server's command line (`node <root>/bin/server.mjs`, a child of the
   session's Claude process), or the idle-wake waiter's (`node <root>/bin/hook.mjs wake …`) while a
   review runs.
2. `node plugin/verify-plugin.mjs <root> --against <the intended build>`: the copy is intact (exactly
   the files its build recorded), its version carries its digest, and it is the intended build.

The hooks and the server always run from the same root (`${CLAUDE_PLUGIN_ROOT}`). Nothing that changes
at run time lives in the plugin directory: state is in the data home. An older copy still loaded by an
older session keeps running its own engine code against the same store until that session ends.

## Trust

The plugin is a packaging unit, not a security boundary. Its hooks run as the implementer. A process
running as the same user can replace the hook scripts or call the adapter with forged input; what it
cannot do is create authority, which the custodian holds. See [docs/security.md](../docs/security.md).
