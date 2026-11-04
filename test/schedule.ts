// Test scheduling (Step 6): which test files a run leaves out, and in what order CI starts them. Nothing here decides
// whether a test passes. Every choice is over whole files, and it only ever EXCLUDES files from vitest's include
// pattern: a file this module does not know about still runs.
//
//  - CI shards (CP_TEST_SHARD=<index>/<count>, set by .github/workflows/ci.yml on its Test step): the files are dealt
//    to `count` shards by their recorded duration, longest first, each to the shard with the least so far; a shard
//    excludes the files dealt to the others. Every file is dealt to exactly one shard, so the shards of one platform
//    and Node.js version together run the whole suite.
//  - The quick tier (`npm run test:quick`): excludes the files recorded at more than QUICK_SECONDS on any platform.
//    Files with no recorded duration stay in. It is for fast feedback while developing; the full suite is the gate.
//  - CI's start order: the longest recorded file first, so a long file does not start last and hold up the end.
//
// The recorded durations (test/durations.json: seconds per platform, from CI; scripts/ci/test-durations.mjs refreshes
// them) only balance the shards, order the files and pick the quick tier. A stale or missing entry makes a shard or
// the quick tier slower, never smaller.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Seconds per platform for one test file (repository-relative, forward slashes). */
export type Durations = Record<string, Partial<Record<"win32" | "linux", number>>>;

export interface Shard {
  index: number;
  count: number;
}

/** The longest CI duration (seconds, on any platform) of a file in the quick tier. */
export const QUICK_SECONDS = 2;

const SHARD = /^([1-9]\d*)\/([1-9]\d*)$/;

/** CP_TEST_SHARD: unset or empty is the whole suite; otherwise exactly `<index>/<count>`, 1 <= index <= count. */
export function parseShard(value: string | undefined): Shard | null {
  if (value === undefined || value === "") return null;
  const m = SHARD.exec(value);
  const index = m ? Number(m[1]) : NaN;
  const count = m ? Number(m[2]) : NaN;
  if (!m || index > count) throw new Error(`CP_TEST_SHARD must be <index>/<count> with 1 <= index <= count, not '${value}'`);
  return { index, count };
}

/** The suite's test files under `root`/test, as `test/<path>.test.ts`, sorted: what vitest's `test/**\/*.test.ts`
 * matches (not inside node_modules or a directory whose name starts with a dot). */
export function testFiles(root: string): string[] {
  const files = (readdirSync(join(root, "test"), { recursive: true }) as string[])
    .map((p) => p.replaceAll("\\", "/"))
    .filter((p) => p.endsWith(".test.ts") && !p.split("/").some((seg) => seg.startsWith(".") || seg === "node_modules"))
    .map((p) => `test/${p}`)
    .sort();
  // The files become vitest `exclude` patterns: a name with a glob character would match something else.
  const glob = files.find((p) => /[*?[\]{}()!]/.test(p));
  if (glob) throw new Error(`test file name '${glob}' contains a glob character; it cannot be scheduled by name`);
  return files;
}

export function readDurations(root: string): Durations {
  return (JSON.parse(readFileSync(join(root, "test", "durations.json"), "utf8")) as { files: Durations }).files;
}

/** The recorded duration of `file` on `platform`, or null when there is none. */
export function durationOf(durations: Durations, file: string, platform: NodeJS.Platform): number | null {
  const d = durations[file]?.[platform as "win32" | "linux"];
  return typeof d === "number" && Number.isFinite(d) && d >= 0 ? d : null;
}

/** Longest first; ties by name, so every job computes the same order. */
function longestFirst(weight: (file: string) => number): (a: string, b: string) => number {
  return (a, b) => weight(b) - weight(a) || (a < b ? -1 : a > b ? 1 : 0);
}

/** Deal `files` to `count` shards: each file, longest first, to the shard with the least total so far (the lowest
 * index on a tie). A file with no recorded duration weighs the mean of the recorded ones. Returns each shard's files,
 * sorted by name. */
export function partition(files: readonly string[], durations: Durations, platform: NodeJS.Platform, count: number): string[][] {
  if (!Number.isInteger(count) || count < 1) throw new Error(`a shard count must be a positive integer, not ${count}`);
  const known = files.map((f) => durationOf(durations, f, platform)).filter((d): d is number => d !== null);
  const mean = known.length > 0 ? known.reduce((s, d) => s + d, 0) / known.length : 1;
  const weight = (f: string) => durationOf(durations, f, platform) ?? mean;
  const shards = Array.from({ length: count }, () => ({ files: [] as string[], total: 0 }));
  for (const f of [...files].sort(longestFirst(weight))) {
    const target = shards.reduce((best, s) => (s.total < best.total ? s : best));
    target.files.push(f);
    target.total += weight(f);
  }
  return shards.map((s) => s.files.sort());
}

/** What one shard leaves out: the files dealt to the other shards. */
export function excludedByShard(files: readonly string[], durations: Durations, platform: NodeJS.Platform, shard: Shard): string[] {
  return partition(files, durations, platform, shard.count).flatMap((s, i) => (i === shard.index - 1 ? [] : s));
}

/** What the quick tier leaves out: the files recorded at more than QUICK_SECONDS on any platform. Not only this one:
 * what a CI runner skips can run on a development machine (the GnuPG tests skip on Windows CI, whose only GnuPG is Git's
 * MSYS build, and take minutes where Gpg4win is installed), and a file slow only on the other platform skips here. */
export function excludedByQuick(files: readonly string[], durations: Durations): string[] {
  return files.filter((f) => Math.max(0, ...Object.values(durations[f] ?? {}).filter((d) => typeof d === "number" && Number.isFinite(d))) > QUICK_SECONDS);
}

/** What a run leaves out, for vitest's `exclude`: CP_TEST_SHARD's other shards, or the quick tier's slow files; nothing
 * for a full run. The two do not combine: a shard is a part of the full suite. */
export function excludedFiles(files: readonly string[], durations: Durations, platform: NodeJS.Platform, run: { shard: string | undefined; quick: boolean }): string[] {
  const shard = parseShard(run.shard);
  if (shard && run.quick) throw new Error("CP_TEST_SHARD selects a part of the full suite; it does not combine with the quick tier");
  if (shard) return excludedByShard(files, durations, platform, shard);
  return run.quick ? excludedByQuick(files, durations) : [];
}

/** CI's start order: files with no recorded duration first (they may be long), then the longest recorded first. */
export function startOrder(files: readonly string[], durations: Durations, platform: NodeJS.Platform): string[] {
  const unknown = files.filter((f) => durationOf(durations, f, platform) === null).sort();
  const known = files.filter((f) => durationOf(durations, f, platform) !== null);
  return [...unknown, ...known.sort(longestFirst((f) => durationOf(durations, f, platform)!))];
}
