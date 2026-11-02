# Third-party notices

CodeParley is licensed under the Apache License 2.0 (`LICENSE`). Its release artifacts also contain the software below,
under these components' own licenses. The full texts are in `third-party/` next to this file, and each npm package keeps
its own license file in `node_modules/`.

| Component | Where it ships | License | Full text |
|---|---|---|---|
| Node.js | the engine runtime bundles | MIT, with the bundled components its license file lists | `third-party/node.LICENSE` |
| .NET runtime and libraries | the custodian bundles (self-contained) | MIT, with the third-party components its notices list | `third-party/dotnet.LICENSE.txt`, `third-party/dotnet.ThirdPartyNotices.txt` |
| `@modelcontextprotocol/server`, `@modelcontextprotocol/core` | the engine (npm dependency) | Apache-2.0 | `node_modules/@modelcontextprotocol/*/LICENSE` |
| `zod` | the engine (npm dependency) | MIT | `node_modules/zod/LICENSE` |

CodeParley does not ship Codex, Claude Code or Git: they are installed and licensed separately. The Linux installer
copies an administrator-supplied Codex into `/opt/codeparley-codex`; it stays under Codex's own license.
