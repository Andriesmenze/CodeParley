// Phase 5 F-3 (contract §4.5, D5-B): on Linux the separate operator account cannot read the implementer's data home or
// the repository, so the implementer writes the configuration payload it proposes (`config propose`,
// `config propose-selftest`) and the operator passes the file to `config set` / `config confirm-selftest`
// (`--proposal-file`). The reader accepts exactly the proposal shape, of the expected kind, for the repository the
// operator named, from a regular file that is not a link; the payload itself is the custodian's to validate. The real
// commands are exercised on the VM.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONFIG_PROPOSAL_SCHEMA, readConfigProposal } from "../src/cli/config-commands.js";

const ROOT = "/home/cpimpl-l/repo";
const proposal = (over: Record<string, unknown> = {}) => ({
  schema: CONFIG_PROPOSAL_SCHEMA,
  recordKind: "repository",
  repositoryRoot: ROOT,
  payload: { codexPath: "/opt/codeparley-codex/0.160.0/bin/codex" },
  createdAt: "2026-10-21T10:00:00.000Z",
  ...over,
});

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cp-proposal-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function file(content: unknown, name = "p.json"): Promise<string> {
  const p = join(dir, name);
  await writeFile(p, typeof content === "string" ? content : JSON.stringify(content));
  return p;
}

describe("Phase 5 F-3: the configuration proposal file", () => {
  it("returns the payload of a proposal of the expected kind for the named repository", async () => {
    expect(await readConfigProposal(await file(proposal()), "repository", ROOT)).toEqual({ codexPath: "/opt/codeparley-codex/0.160.0/bin/codex" });
  });

  it("refuses another kind, another repository, another schema, extra or missing fields, and a payload that is not an object", async () => {
    const cases: [unknown, RegExp][] = [
      [proposal({ recordKind: "selftest_confirmation" }), /proposes a selftest_confirmation record, not a repository record/],
      [proposal({ repositoryRoot: "/home/cpimpl-l/other" }), /written for the repository "\/home\/cpimpl-l\/other", not "\/home\/cpimpl-l\/repo"/],
      [proposal({ schema: "arl.config-proposal.v0" }), /is not a arl.config-proposal.v1 proposal/],
      [proposal({ note: "x" }), /expected exactly the fields/],
      [(({ createdAt: _c, ...rest }) => rest)(proposal()), /expected exactly the fields/],
      [proposal({ payload: [1] }), /carries no payload object/],
      ["not json", /not JSON/],
      [[proposal()], /expected exactly the fields/],
    ];
    for (const [content, msg] of cases) {
      const err = await readConfigProposal(await file(content, `c${cases.findIndex((c) => c[0] === content)}.json`), "repository", ROOT).catch((e: Error) => e);
      expect(err, String(msg)).toBeInstanceOf(Error);
      expect((err as Error).message).toMatch(msg);
      expect((err as Error).message).toMatch(/Nothing was recorded/);
    }
  });

  it("refuses a file larger than 1 MiB and a directory", async () => {
    await expect(readConfigProposal(await file("x".repeat((1 << 20) + 1)), "repository", ROOT)).rejects.toThrow(/not a proposal file/);
    await expect(readConfigProposal(dir, "repository", ROOT)).rejects.toThrow(/not a proposal file|cannot be read/);
  });

  it.runIf(process.platform !== "win32")("refuses a proposal reached through a symbolic link", async () => {
    const target = await file(proposal(), "target.json");
    const link = join(dir, "link.json");
    await symlink(target, link);
    await expect(readConfigProposal(link, "repository", ROOT)).rejects.toThrow(/cannot be read .*not a link/);
  });
});
