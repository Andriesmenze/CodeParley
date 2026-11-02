import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atomicWriteFile, writeFileSynced, writeFileExclusive, readTextIfExists } from "../src/store/atomic.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "arl-atomic-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("atomicWriteFile", () => {
  it("creates then replaces a file in place", async () => {
    const p = join(dir, "state.json");
    await atomicWriteFile(p, "one");
    expect(await readFile(p, "utf8")).toBe("one");
    await atomicWriteFile(p, "two");
    expect(await readFile(p, "utf8")).toBe("two");
  });

  it("leaves no .tmp- files behind after a successful write", async () => {
    const p = join(dir, "state.json");
    await atomicWriteFile(p, "data");
    const { readdir } = await import("node:fs/promises");
    const entries = await readdir(dir);
    expect(entries.filter((e) => e.startsWith(".tmp-"))).toHaveLength(0);
  });

  it("creates parent directories as needed", async () => {
    const p = join(dir, "a", "b", "c.json");
    await atomicWriteFile(p, "x");
    expect(await readFile(p, "utf8")).toBe("x");
  });
});

describe("writeFileExclusive", () => {
  it("writes when absent and refuses when present", async () => {
    const p = join(dir, "run.json");
    expect(await writeFileExclusive(p, "first")).toBe(true);
    expect(await writeFileExclusive(p, "second")).toBe(false);
    expect(await readFile(p, "utf8")).toBe("first");
  });
});

describe("writeFileSynced / readTextIfExists", () => {
  it("writes an immutable artifact and reads it back", async () => {
    const p = join(dir, "ops", "op1", "events.jsonl");
    await writeFileSynced(p, "line1\n");
    expect(await readTextIfExists(p)).toBe("line1\n");
  });
  it("readTextIfExists returns null for a missing file", async () => {
    expect(await readTextIfExists(join(dir, "nope"))).toBeNull();
  });
});
