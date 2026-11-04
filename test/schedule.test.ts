// Step 6: the test schedule (test/schedule.ts). Whatever the recorded durations say, the CI shards of a platform
// together run every test file exactly once, and the quick tier only leaves out files recorded as slow.

import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { QUICK_SECONDS, excludedByQuick, excludedByShard, excludedFiles, parseShard, partition, readDurations, startOrder, testFiles, type Durations } from "./schedule.js";
// @ts-expect-error -- a plain .mjs script without type declarations
import { formatDurations, logDurations } from "../scripts/ci/test-durations.mjs";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const files = ["test/a.test.ts", "test/b.test.ts", "test/c.test.ts", "test/d.test.ts", "test/e.test.ts", "test/f.test.ts", "test/g.test.ts"];
const durations: Durations = {
  "test/a.test.ts": { win32: 100, linux: 1 },
  "test/b.test.ts": { win32: 60, linux: 30 },
  "test/c.test.ts": { win32: 40, linux: 2 },
  "test/d.test.ts": { win32: 1.5, linux: 0 },
  "test/e.test.ts": { win32: 2, linux: 9 },
  "test/f.test.ts": { win32: 30 },
  // g has no recorded duration
};

/** Each shard's included files: the suite minus what the shard excludes. */
const included = (all: readonly string[], d: Durations, platform: NodeJS.Platform, count: number) =>
  Array.from({ length: count }, (_, i) => {
    const out = new Set(excludedByShard(all, d, platform, { index: i + 1, count }));
    return all.filter((f) => !out.has(f));
  });

describe("test schedule (Step 6)", () => {
  it("reads CP_TEST_SHARD as <index>/<count> and refuses anything else", () => {
    expect(parseShard(undefined)).toBeNull();
    expect(parseShard("")).toBeNull();
    expect(parseShard("1/1")).toEqual({ index: 1, count: 1 });
    expect(parseShard("2/3")).toEqual({ index: 2, count: 3 });
    expect(parseShard("12/12")).toEqual({ index: 12, count: 12 });
    for (const bad of ["0/3", "4/3", "1/0", "3", "1/", "/3", "a/3", "1/b", " 1/3", "1/3 ", "01/3", "1/03", "-1/3", "1/3/4", "1//3", "1.0/3", "${{ matrix.shard }}"]) {
      expect(() => parseShard(bad), bad).toThrow(/CP_TEST_SHARD must be <index>\/<count>/);
    }
  });

  it("deals every file to exactly one shard, for any shard count, and the same way whatever the input order", () => {
    for (const platform of ["win32", "linux"] as const) {
      for (let count = 1; count <= files.length + 2; count++) {
        const shards = partition(files, durations, platform, count);
        expect(shards).toHaveLength(count);
        expect(shards.flat().sort()).toEqual([...files].sort());
        expect(partition([...files].reverse(), durations, platform, count)).toEqual(shards);
        // What the shards include is exactly that partition.
        expect(included(files, durations, platform, count)).toEqual(shards);
      }
    }
    expect(() => partition(files, durations, "win32", 0)).toThrow(/positive integer/);
  });

  it("balances the shards by recorded duration, longest first; a file with none weighs the mean of the others", () => {
    const sum = (fs: string[], weight: (f: string) => number) => fs.reduce((s, f) => s + weight(f), 0);
    const known = Object.values(durations).map((d) => d.win32!);
    const mean = known.reduce((s, d) => s + d, 0) / known.length;
    const weight = (f: string) => durations[f]?.win32 ?? mean;
    const shards = partition(files, durations, "win32", 2);
    // a (100) and b (60) go to different shards; g weighs the mean (~38.9).
    expect(shards[0]).toContain("test/a.test.ts");
    expect(shards[1]).toContain("test/b.test.ts");
    const totals = shards.map((s) => sum(s, weight));
    // Longest-first dealing keeps the difference within the largest single file.
    expect(Math.max(...totals) - Math.min(...totals)).toBeLessThanOrEqual(Math.max(...files.map(weight)));
    // Another platform's durations give another partition: a shard is computed for the platform it runs on.
    expect(partition(files, durations, "linux", 2)).not.toEqual(shards);
  });

  it("the quick tier leaves out only files recorded slower than QUICK_SECONDS on some platform", () => {
    expect(QUICK_SECONDS).toBe(2);
    // e is quick on Windows but takes 9 s on Linux; f is recorded on Windows only; g, recorded nowhere, stays in.
    expect(excludedByQuick(files, durations)).toEqual(["test/a.test.ts", "test/b.test.ts", "test/c.test.ts", "test/e.test.ts", "test/f.test.ts"]);
  });

  it("a full run excludes nothing; a shard and the quick tier do not combine", () => {
    expect(excludedFiles(files, durations, "win32", { shard: undefined, quick: false })).toEqual([]);
    expect(excludedFiles(files, durations, "win32", { shard: "", quick: false })).toEqual([]);
    expect(excludedFiles(files, durations, "win32", { shard: "1/2", quick: false })).toEqual(excludedByShard(files, durations, "win32", { index: 1, count: 2 }));
    expect(excludedFiles(files, durations, "win32", { shard: undefined, quick: true })).toEqual(excludedByQuick(files, durations));
    expect(() => excludedFiles(files, durations, "win32", { shard: "1/2", quick: true })).toThrow(/does not combine/);
    expect(() => excludedFiles(files, durations, "win32", { shard: "3/2", quick: false })).toThrow(/CP_TEST_SHARD/);
  });

  it("CI starts files with no recorded duration first, then the longest first, ties by name", () => {
    expect(startOrder(files, durations, "win32")).toEqual(["test/g.test.ts", "test/a.test.ts", "test/b.test.ts", "test/c.test.ts", "test/f.test.ts", "test/e.test.ts", "test/d.test.ts"]);
    expect(startOrder(files, durations, "linux")).toEqual(["test/f.test.ts", "test/g.test.ts", "test/b.test.ts", "test/e.test.ts", "test/c.test.ts", "test/a.test.ts", "test/d.test.ts"]);
  });

  it("schedules the real suite: every test file, each in exactly one shard, and the recorded durations parse", () => {
    const suite = testFiles(root);
    expect(suite).toContain("test/schedule.test.ts");
    expect(suite.every((f) => /^test\/[^*?[\]{}()!]+\.test\.ts$/.test(f))).toBe(true);
    const recorded = readDurations(root);
    for (const [f, d] of Object.entries(recorded)) {
      for (const [p, s] of Object.entries(d)) expect(["win32", "linux"].includes(p) && typeof s === "number" && s >= 0, `${f} ${p}`).toBe(true);
    }
    for (const platform of ["win32", "linux"] as const) {
      for (const count of [1, 2, 3, 4]) {
        const shards = included(suite, recorded, platform, count);
        expect(shards.flat().sort()).toEqual(suite);
        for (const s of shards) expect(s.length).toBeGreaterThan(0);
      }
    }
  });
});

describe("refreshing the recorded durations (scripts/ci/test-durations.mjs, Step 6)", () => {
  it("reads each file's duration from a CI job log's npm test step alone, and from a terminal log", () => {
    const job = [
      "2026-11-04T11:41:12.0000000Z ##[group]Run npx vitest run test/b.test.ts",
      "2026-11-04T11:41:46.0000000Z  ✓ test/b.test.ts (34 tests) 42803ms",
      "2026-11-04T11:41:46.7811636Z ##[group]Run npm test",
      "2026-11-04T11:41:47.9351275Z  RUN  v5.1.0 D:/a/CodeParley/CodeParley",
      "2026-11-04T11:41:51.2488436Z  ✓ test/a.test.ts (26 tests | 18 skipped) 20ms",
      "2026-11-04T11:42:34.5953866Z  ✓ test/b.test.ts (34 tests) 40046ms",
      "2026-11-04T11:42:34.6130657Z      ✓ passes every scenario 19197ms",
      "2026-11-04T11:43:00.0000000Z  ↓ test/c.test.ts (5 tests | 5 skipped)",
      "2026-11-04T11:44:00.0000000Z  ❯ test/d.test.ts (3 tests | 1 failed) 1500ms",
      "2026-11-04T12:07:54.4761479Z ##[group]Run node scripts/package/smoke.mjs --mode both",
      "2026-11-04T12:09:08.0000000Z  ✓ test/e.test.ts (1 test) 5ms",
    ].join("\n");
    // The diagnostic's run of b before the step, and anything after it, are not the suite's.
    expect(logDurations(job)).toEqual({ "test/a.test.ts": 0.02, "test/b.test.ts": 40.046, "test/c.test.ts": 0, "test/d.test.ts": 1.5 });
    // A terminal capture, colours and all.
    expect(logDurations("\x1b[32m ✓\x1b[39m test/f.test.ts \x1b[2m(6 tests)\x1b[22m\x1b[32m 5\x1b[2mms\x1b[22m\x1b[39m\n")).toEqual({ "test/f.test.ts": 0.005 });
  });

  it("writes one file per line, sorted, and reads back the same durations", () => {
    const files = { "test/b.test.ts": { win32: 1.5, linux: 0 }, "test/a.test.ts": { win32: 2 } };
    const text = formatDurations("a test", files) as string;
    expect(text.split("\n").filter((l) => l.includes(".test.ts")).map((l) => l.trim().replace(/,$/, ""))).toEqual(['"test/a.test.ts": {"win32": 2}', '"test/b.test.ts": {"win32": 1.5, "linux": 0}']);
    expect(JSON.parse(text)).toMatchObject({ source: "a test", files });
  });
});
