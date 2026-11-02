import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRun, readMeta, readState, commitState } from "../src/store/state-store.js";
import { runPaths, type RunPaths } from "../src/store/paths.js";
import { newStateRecord, type RunMeta } from "../src/schemas/run-state.js";
import { selfOwner } from "../src/store/owner.js";

let home: string;
let paths: RunPaths;
const owner = selfOwner();

function meta(runId: string): RunMeta {
  return {
    schema_version: 1,
    run_id: runId,
    created_at: new Date().toISOString(),
    repository_root: "C:\\src\\repo",
    versions: { node: process.version },
    scope: { allowed_snapshot: ["C:\\src"], client_roots_snapshot: [] },
  };
}

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "arl-store-"));
  paths = runPaths(home, "repokey", "run-1");
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

describe("createRun / read", () => {
  it("writes immutable meta and an initial state at revision 0", async () => {
    await createRun(paths, meta("run-1"), newStateRecord("run-1", "PREPARING"));
    const m = await readMeta(paths);
    expect(m.run_id).toBe("run-1");
    const s = await readState(paths);
    expect(s.revision).toBe(0);
    expect(s.state).toBe("PREPARING");
  });

  it("refuses to create the same run twice", async () => {
    await createRun(paths, meta("run-1"), newStateRecord("run-1"));
    await expect(createRun(paths, meta("run-1"), newStateRecord("run-1"))).rejects.toThrowError();
  });

  it("readState throws RUN_NOT_FOUND when absent", async () => {
    await expect(readState(paths)).rejects.toSatisfy((e) => (e as { code: string }).code === "RUN_NOT_FOUND");
  });

  it("rejects a newer schema_version as read-only (STORE_VERSION_UNSUPPORTED)", async () => {
    await createRun(paths, meta("run-1"), newStateRecord("run-1"));
    const doc = { ...newStateRecord("run-1"), schema_version: 999 };
    await writeFile(paths.stateJson, JSON.stringify(doc), "utf8");
    await expect(readState(paths)).rejects.toSatisfy((e) => (e as { code: string }).code === "STORE_VERSION_UNSUPPORTED");
  });
});

describe("commitState (single commit point)", () => {
  beforeEach(async () => {
    await createRun(paths, meta("run-1"), newStateRecord("run-1", "PREPARING"));
  });

  it("increments the revision and applies the mutation", async () => {
    const committed = await commitState(paths, owner, (cur) => ({ ...cur, state: "IDLE" }));
    expect(committed.revision).toBe(1);
    expect(committed.state).toBe("IDLE");
    const reread = await readState(paths);
    expect(reread.revision).toBe(1);
    expect(reread.state).toBe("IDLE");
  });

  it("cannot be tricked into keeping the old revision", async () => {
    const committed = await commitState(paths, owner, (cur) => ({ ...cur, revision: 0 /* ignored */, state: "IDLE" }));
    expect(committed.revision).toBe(1);
  });

  it("serializes concurrent commits without losing updates", async () => {
    const pushEvent = (tag: string) => (cur: ReturnType<typeof newStateRecord>) => {
      const seq = (cur.events.at(-1)?.seq ?? 0) + 1;
      return {
        ...cur,
        events: [...cur.events, { seq, ts: new Date().toISOString(), type: "test", actor: "engine", summary: tag }],
      };
    };
    await Promise.all([
      commitState(paths, owner, pushEvent("a")),
      commitState(paths, owner, pushEvent("b")),
      commitState(paths, owner, pushEvent("c")),
    ]);
    const s = await readState(paths);
    expect(s.revision).toBe(3);
    expect(s.events).toHaveLength(3);
    expect(s.events.map((e) => e.summary).sort()).toEqual(["a", "b", "c"]);
  });
});
