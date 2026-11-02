// P3.4C-5 Increment 2 (contract §2.1, N5-6): the operator's configuration workflow for the engine runtime the custodian's
// helper runs — `code-parley config approve-runtime | reconfirm-runtime | revoke-runtime`, and `config show` — through the
// real CLI on the operator pipe against the simulated custodian (which measures the tree as the custodian does: every
// file hashed, node.exe and git native images, the helper entry, no link). Interactive and typed, like every
// configuration change; global; it lapses after a restart of the OS and is re-confirmed only as it was approved.

import { describe, it, expect } from "vitest";
import { appendFileSync, copyFileSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, operatorIo, protectConfig, syntheticRuntime, SYNTHETIC_RUNTIME_GIT, type ContFixture } from "./helpers/continuation-fixture.js";

interface ShownRuntime {
  runtimeId: string;
  root: string;
  treeDigest: string;
  nodeSha256: string;
  gitRelative?: string;
  gitPath?: string;
  fileCount: number;
  revoked: boolean;
  lapsed: boolean;
  usable: boolean;
}

async function shown(f: ContFixture): Promise<ShownRuntime | null> {
  const r = await cli(f, ["config", "show", "--repo", f.repo, "--json"]);
  expect(r.code).toBe(0);
  return (JSON.parse(r.out) as { engineRuntime?: ShownRuntime | null }).engineRuntime ?? null;
}

describe.skipIf(!supported)("P3.4C-5 — the operator approves the engine runtime the custodian's helper runs", () => {
  it("approve-runtime: the custodian measures and renders the tree; the operator confirms by typing; show reports it", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await protectConfig(f); // approves the fixture's synthetic runtime as part of the protected configuration
    const rt = (await shown(f))!;
    expect(rt).toMatchObject({ gitRelative: SYNTHETIC_RUNTIME_GIT, revoked: false, lapsed: false, usable: true });
    expect(rt.treeDigest).toMatch(/^[0-9a-f]{64}$/);
    const text = await cli(f, ["config", "show", "--repo", f.repo]);
    expect(text.out).toContain(`engine runtime ${rt.runtimeId}`);

    // Not confirmed: nothing is recorded. Non-interactive: refused with the interactive-terminal remedy.
    const other = await syntheticRuntime(join(f.scratch, "second"));
    const declined = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", other, "--runtime-git", SYNTHETIC_RUNTIME_GIT], operatorIo("no"));
    expect(declined.code).toBe(2);
    expect((await shown(f))!.runtimeId).toBe(rt.runtimeId);
    const scripted = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", other, "--runtime-git", SYNTHETIC_RUNTIME_GIT], operatorIo("confirm", false));
    expect(scripted.code).not.toBe(0);
    expect((await shown(f))!.runtimeId).toBe(rt.runtimeId);

    // A new approval supersedes the earlier one (one runtime in force).
    const approved = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", other, "--runtime-git", SYNTHETIC_RUNTIME_GIT], operatorIo("confirm"));
    expect(approved.code).toBe(0);
    expect(approved.out).toContain("Approve the CodeParley engine runtime");
    expect((await shown(f))!.runtimeId).not.toBe(rt.runtimeId);
  }, 180_000);

  it("Phase 6 §7 b: a runtime without bundled Git — an installed git outside the tree, named with --runtime-git-path, measured but not hashed with the tree", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await protectConfig(f);
    const bundled = (await shown(f))!;
    const runtime = await syntheticRuntime(join(f.scratch, "no-git"));
    const installed = join(f.scratch, "installed-git", "mingw64", "bin");
    mkdirSync(installed, { recursive: true });
    copyFileSync(join(runtime, ...SYNTHETIC_RUNTIME_GIT.split("/")), join(installed, "git.exe"));
    rmSync(join(runtime, "git"), { recursive: true, force: true });
    const both = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", runtime, "--runtime-git", SYNTHETIC_RUNTIME_GIT, "--runtime-git-path", join(installed, "git.exe")], operatorIo("confirm"));
    expect(both.code).not.toBe(0); // exactly one git
    const approved = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", runtime, "--runtime-git-path", join(installed, "git.exe")], operatorIo("confirm"));
    expect(approved.code).toBe(0);
    expect(approved.out).toContain("installed outside the runtime");
    const rt = (await shown(f))!;
    expect(rt.gitRelative).toBeUndefined();
    expect(rt.gitPath?.toLowerCase()).toContain("installed-git");
    expect(rt.fileCount).toBe(bundled.fileCount - 1); // the tree hashed per launch no longer holds git
    expect(rt.usable).toBe(true);
  }, 180_000);

  it("N5-6: a tree without the helper entry, a git outside it, or a linked component is refused; nothing is recorded", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await protectConfig(f);
    const before = (await shown(f))!.runtimeId;
    const bad = await syntheticRuntime(join(f.scratch, "bad"));
    const noGit = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", bad, "--runtime-git", "../git.exe"], operatorIo("confirm"));
    expect(noGit.code).not.toBe(0);
    const missing = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", bad, "--runtime-git", "git/bin/git.exe"], operatorIo("confirm"));
    expect(missing.code).not.toBe(0);
    let linked: string | null = join(f.scratch, "linked-runtime");
    try {
      symlinkSync(bad, linked, "junction");
    } catch {
      linked = null; // a host that cannot create the junction skips this case
    }
    if (linked) {
      const viaLink = await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", linked, "--runtime-git", SYNTHETIC_RUNTIME_GIT], operatorIo("confirm"));
      expect(viaLink.code).not.toBe(0);
    }
    expect((await shown(f))!.runtimeId).toBe(before);
  }, 180_000);

  it("U4b: the approval lapses after a restart of the OS; reconfirm-runtime restores it only for the unchanged tree; revoke-runtime ends it", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await protectConfig(f);
    const rt = (await shown(f))!;
    f.custodian.simulateRecoveryAfterNewBoot();
    expect((await shown(f))!).toMatchObject({ runtimeId: rt.runtimeId, lapsed: true, usable: false });
    expect((await cli(f, ["config", "show", "--repo", f.repo])).out).toContain(`config reconfirm-runtime --repo`);

    // A changed tree is not re-confirmed (CONFIG_MISMATCH): the operator approves it again as it is now.
    const entry = join(rt.root, "dist", "helper", "main.js");
    appendFileSync(entry, "// changed\n");
    const refused = await cli(f, ["config", "reconfirm-runtime", "--repo", f.repo, rt.runtimeId], operatorIo("confirm"));
    expect(refused.code).not.toBe(0);
    expect((await shown(f))!.lapsed).toBe(true);
  }, 180_000);

  it("reconfirm-runtime of an unchanged tree clears the lapse; revoke-runtime ends the approval", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await protectConfig(f);
    const rt = (await shown(f))!;
    f.custodian.simulateRecoveryAfterNewBoot();
    const ok = await cli(f, ["config", "reconfirm-runtime", "--repo", f.repo, rt.runtimeId], operatorIo("confirm"));
    expect(ok.code).toBe(0);
    expect((await shown(f))!).toMatchObject({ lapsed: false, usable: true });
    const revoked = await cli(f, ["config", "revoke-runtime", "--repo", f.repo, rt.runtimeId], operatorIo("confirm"));
    expect(revoked.code).toBe(0);
    expect((await shown(f))!).toMatchObject({ revoked: true, usable: false });
  }, 180_000);
});
