// The offline isolation self-test credits a denial only when its positive control succeeds
// (PR #2 review): a sandboxed write that "failed" proves nothing if the same write also fails
// outside the sandbox. Runs the real self-test with the scripted fake Codex sandbox (which
// denies every write) and in-process controls — on Windows (MXC) and Linux (bubblewrap).

import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { runSelfTest } from "../src/agents/codex/selftest.js";
import type { CodexProbe } from "../src/agents/codex/probe.js";
import { fakeSelfTestDeps, makeReviewFixture } from "./helpers/review-fixture.js";
import { supported, win } from "./helpers/git-fixture.js";

// The user-profile write probe and the variable that names its target, per platform.
const backend = win ? "mxc" : "bwrap";
const homeRow = win ? "write_userprofile" : "write_home";
const homeVar = win ? "USERPROFILE" : "HOME";

describe.skipIf(!supported)("self-test positive controls", () => {
  it("a write denial whose control also fails is inconclusive and S1 is not available", async () => {
    const f = await makeReviewFixture();
    const probe = { version: "0.160.0", installDir: f.fakeDir, compat: { webSearchDisabledValue: "disabled" } } as unknown as CodexProbe;
    const run = () => runSelfTest({ probe, backend, mode: "S1", dataHome: f.dataHome, deps: fakeSelfTestDeps(f) });

    // Baseline: every control works, every probe is denied — S1 is available.
    const ok = await run();
    expect(ok.rows.find((r) => r.name === homeRow)).toMatchObject({ sandbox: "denied", positive_control: "ok", pass: true });
    expect(ok.rows.filter((r) => !r.pass)).toEqual([]);
    expect(ok.s1_available).toBe(true);

    // The user-profile target cannot be written even outside the sandbox.
    const saved = process.env[homeVar];
    process.env[homeVar] = join(f.dataHome, "no-such-profile");
    try {
      const rec = await run();
      expect(rec.rows.find((r) => r.name === homeRow)).toMatchObject({ sandbox: "denied", positive_control: "failed", pass: false, inconclusive: true });
      expect(rec.s1_available).toBe(false);
    } finally {
      process.env[homeVar] = saved;
    }
  }, 120_000);
});
