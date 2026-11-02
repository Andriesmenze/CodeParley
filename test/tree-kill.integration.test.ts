// The process layer records every tree kill it performs (F3 round 3): explicit
// cancellation, wall timeout and idle timeout all produce a `treeKill` record with the
// reason, the pre-kill evidence (`beforeTreeKill`) and the kill outcome; no kill, no record.

import { describe, it, expect } from "vitest";
import { runProcess } from "../src/process/spawn.js";
import { supported } from "./helpers/git-fixture.js";

const node = process.execPath;
const hang = ["-e", "setInterval(() => {}, 1000)"];

describe.skipIf(!supported)("process-layer tree-kill records", () => {
  it("wall timeout: reason, pre-kill evidence, kill issued and confirmed (taskkill on Windows, the session gone on Linux)", async () => {
    const r = await runProcess(node, hang, { wallMs: 700, beforeTreeKill: async () => ({ snapshot: "pre" }) });
    await r.treeKillSettled;
    expect(r.timedOut).toBe(true);
    expect(r.treeKill).toMatchObject({ reason: "wall_timeout", evidence: { snapshot: "pre" }, killIssued: true, killOk: true });
  });
  it("idle timeout", async () => {
    const r = await runProcess(node, hang, { wallMs: 30_000, idleMs: 700, beforeTreeKill: async () => "pre" });
    await r.treeKillSettled;
    expect(r.idleTimedOut).toBe(true);
    expect(r.treeKill).toMatchObject({ reason: "idle_timeout", evidence: "pre", killIssued: true });
  });
  it("explicit cancellation", async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 400);
    const r = await runProcess(node, hang, { wallMs: 30_000, signal: ac.signal, beforeTreeKill: async () => "pre" });
    await r.treeKillSettled;
    expect(r.cancelled).toBe(true);
    expect(r.treeKill).toMatchObject({ reason: "cancelled", evidence: "pre", killIssued: true });
  });
  it("no kill, no record; a child that exits while the pre-kill evidence is taken is not killed", async () => {
    const ok = await runProcess(node, ["-e", "1"], { beforeTreeKill: async () => "never" });
    expect(ok.treeKill).toBeNull();
    const r = await runProcess(node, ["-e", "setTimeout(() => {}, 1200)"], {
      wallMs: 400,
      beforeTreeKill: () => new Promise((res) => setTimeout(() => res("slow"), 2500)),
    });
    await r.treeKillSettled;
    expect(r.treeKill).toMatchObject({ reason: "wall_timeout", evidence: "slow", killIssued: false, killOk: null });
  });
});
