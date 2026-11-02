// P3.4C-3 (contract §5.4): whether the custodian service is registered with the host's service manager decides
// whether the engine must ask the custodian which records are authoritative. The answer is three-valued and only the
// service manager's explicit "does not exist" (ERROR_SERVICE_DOES_NOT_EXIST, 1060) is "absent"; every other outcome
// is "unknown", which the engine treats as registered (fail closed). The parsing and the test seam are pure; the
// last case asks this Windows host's own service manager.

import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { custodianServicePresence, presenceOf, type ServiceQueryResult } from "../src/custodian/service-presence.js";
import { custodianPresence } from "../src/custodian/protected-loops.js";

const ran = (status: number | null): ServiceQueryResult => ({ status, spawnError: false, timedOut: false });

describe("P3.4C-3: is the custodian service registered? (three-valued; contract §5.4)", () => {
  it("only the service manager's explicit 'does not exist' (1060) is absent; every other outcome is unknown", () => {
    expect(presenceOf(ran(0))).toBe("registered");
    expect(presenceOf(ran(1060))).toBe("absent");
    // Access denied, RPC server unavailable, the service did not respond, a truncated code, other failures.
    for (const status of [5, 1722, 1053, 36, 1, -1, 2]) expect(presenceOf(ran(status)), String(status)).toBe("unknown");
    expect(presenceOf(ran(null))).toBe("unknown");
    expect(presenceOf({ status: 1060, spawnError: true, timedOut: false })).toBe("unknown");
    expect(presenceOf({ status: 1060, spawnError: false, timedOut: true })).toBe("unknown");
  });

  it("a host other than Windows or Linux has no custodian: absent, and nothing is queried", async () => {
    let asked = 0;
    const query = async (): Promise<ServiceQueryResult> => {
      asked++;
      return ran(0);
    };
    expect(await custodianServicePresence({ platform: "darwin", query })).toBe("absent");
    expect(await custodianServicePresence({ platform: "freebsd", query })).toBe("absent");
    expect(asked).toBe(0);
  });

  it("Linux (Phase 5): registered when root installed the socket unit; absent when there is none; unknown otherwise — the Windows query is never run", async () => {
    let asked = 0;
    const query = async (): Promise<ServiceQueryResult> => {
      asked++;
      return ran(0);
    };
    const dir = mkdtempSync(join(tmpdir(), "cp-presence-"));
    try {
      expect(await custodianServicePresence({ platform: "linux", query, unitPath: join(dir, "missing.socket") })).toBe("absent");
      const unit = join(dir, "codeparley-implementer.socket");
      writeFileSync(unit, "[Socket]\n");
      // A unit not owned by root (only root installs one; the test's file is the test user's unless it runs as root;
      // Windows reports uid 0 for every file).
      const rootOwned = process.platform === "win32" || process.getuid?.() === 0;
      expect(await custodianServicePresence({ platform: "linux", query, unitPath: unit })).toBe(rootOwned ? "registered" : "unknown");
      expect(await custodianServicePresence({ platform: "linux", query, unitPath: dir })).toBe("unknown"); // not a file
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(asked).toBe(0);
  });

  it("an absent answer is never kept: a custodian installed later is seen at the next query", async () => {
    let status = 1060;
    const query = async (): Promise<ServiceQueryResult> => ran(status);
    expect(await custodianServicePresence({ platform: "win32", query })).toBe("absent");
    status = 0;
    expect(await custodianServicePresence({ platform: "win32", query })).toBe("registered");
    status = 5;
    expect(await custodianServicePresence({ platform: "win32", query })).toBe("unknown");
  });

  it("under test, only what the test injected: no custodian hook is absent (the host is never asked); a hook on win32 is registered unless it says otherwise", async () => {
    expect(await custodianPresence(true, undefined)).toBe("absent");
    expect(await custodianPresence(true, { platform: "darwin" })).toBe("absent");
    expect(await custodianPresence(true, { platform: "linux" })).toBe("registered");
    expect(await custodianPresence(true, { platform: "win32" })).toBe("registered");
    expect(await custodianPresence(true, { platform: "win32", presence: "unknown" })).toBe("unknown");
    expect(await custodianPresence(true, { platform: "win32", presence: "absent" })).toBe("absent");
  });

  it.skipIf(process.platform !== "win32")("this Windows host's service manager answers (registered or absent, never unknown on a healthy host)", async () => {
    expect(["registered", "absent"]).toContain(await custodianServicePresence());
  });

  it("the acceptance harness's seam: presence 'host' asks the host's own service manager, as production does", async () => {
    expect(await custodianPresence(true, { platform: "win32", presence: "host" })).toBe(await custodianServicePresence());
  });
});
