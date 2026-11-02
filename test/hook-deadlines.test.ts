// Phase 6 (contract §7 a): the custodian client's busy waits are bounded by the calling hook's deadline. The deadlines
// the hook runner uses are the ones the plugin configures (plugin/build-plugin.mjs), and the runner sets them.

import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { HOOK_DEADLINE_MARGIN_MS, HOOK_DEADLINE_S, HOOK_EVENTS, runHook } from "../src/hooks/adapter.js";
import { custodianClientDeadline, setCustodianClientDeadline } from "../src/custodian/transport.js";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");

describe("Phase 6 §7 a: hook deadlines", () => {
  afterEach(() => setCustodianClientDeadline(null));

  it("match the plugin's hook timeouts (SessionEnd: the host's 60 s default), for every event the runner knows", () => {
    const plugin = readFileSync(join(root, "plugin", "build-plugin.mjs"), "utf8");
    const configured = new Map<string, number>();
    for (const m of plugin.matchAll(/cmd\("([a-z-]+)"(?:, \[[^\]]*\])?(?:, \{([^}]*)\})?\)/g)) {
      const timeout = /timeout: (\d+)/.exec(m[2] ?? "");
      configured.set(m[1]!, timeout ? Number(timeout[1]) : 60);
    }
    expect([...configured.keys()].sort()).toEqual(Object.keys(HOOK_EVENTS).sort());
    for (const [event, seconds] of configured) expect([event, HOOK_DEADLINE_S[event]]).toEqual([event, seconds]);
  });

  it("the runner sets the custodian client's deadline to the event's deadline minus the margin", async () => {
    const t0 = Date.now();
    await runHook(["stop"], { stdin: "{}", env: {}, out: () => {}, err: () => {} });
    const d = custodianClientDeadline();
    expect(d).not.toBeNull();
    expect(d! - t0).toBeGreaterThanOrEqual(120_000 - HOOK_DEADLINE_MARGIN_MS);
    expect(d! - Date.now()).toBeLessThanOrEqual(120_000 - HOOK_DEADLINE_MARGIN_MS);
  });
});
