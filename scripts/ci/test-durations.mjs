#!/usr/bin/env node
// Step 6: refresh test/durations.json, the recorded duration of each test file per platform (test/schedule.ts balances
// the CI shards, orders the files and picks the quick tier by it), from vitest JSON reports of full-suite runs:
//
//   npx vitest run --reporter=json --outputFile=<report.json>      (one run on one platform; CI uses 4-core runners)
//   node scripts/ci/test-durations.mjs --platform win32|linux --source "<where the runs come from>" <report.json>...
//        [--file <durations.json>] [--prune]
//
// A file's new duration on that platform is the median over the reports that ran it; its other platform's entry is
// kept. --prune drops the entries of files that no longer exist. Only the relative durations matter: a machine
// faster or slower than CI's runners scales every file alike.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PLATFORMS = ["win32", "linux"];
export const ABOUT =
  "Recorded duration in seconds of each test file, per platform, from full-suite runs on CI's runners. test/schedule.ts uses them only to balance the CI shards, order the files and pick the quick tier; a stale entry makes a shard slower, never smaller. Refresh with scripts/ci/test-durations.mjs.";

/** The durations file's text: one file per line, sorted, so a refresh diffs line by line. */
export function formatDurations(source, files) {
  const entries = Object.keys(files)
    .sort()
    .map((f) => {
      const d = Object.fromEntries(PLATFORMS.filter((p) => typeof files[f][p] === "number").map((p) => [p, files[f][p]]));
      return `    ${JSON.stringify(f)}: {${Object.entries(d).map(([p, s]) => `${JSON.stringify(p)}: ${s}`).join(", ")}}`;
    });
  return `{\n  "about": ${JSON.stringify(ABOUT)},\n  "source": ${JSON.stringify(source)},\n  "files": {\n${entries.join(",\n")}\n  }\n}\n`;
}

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
};

/** Per-file seconds from one vitest JSON report (paths made repository-relative). */
export function reportDurations(report, root = ROOT) {
  const out = {};
  for (const t of report.testResults ?? []) {
    const rel = relative(root, t.name).replaceAll("\\", "/");
    if (!rel.startsWith("test/") || !rel.endsWith(".test.ts")) continue;
    if (typeof t.startTime === "number" && typeof t.endTime === "number" && t.endTime >= t.startTime) out[rel] = (t.endTime - t.startTime) / 1000;
  }
  return out;
}

function main(argv) {
  const o = { platform: null, source: null, file: join(ROOT, "test", "durations.json"), prune: false, reports: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--platform") o.platform = argv[++i];
    else if (a === "--source") o.source = argv[++i];
    else if (a === "--file") o.file = resolve(argv[++i]);
    else if (a === "--prune") o.prune = true;
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else o.reports.push(resolve(a));
  }
  if (!PLATFORMS.includes(o.platform) || !o.source || o.reports.length === 0) throw new Error("usage: test-durations.mjs --platform win32|linux --source <text> <report.json>... [--file <durations.json>] [--prune]");
  const current = JSON.parse(readFileSync(o.file, "utf8"));
  const files = { ...current.files };
  const samples = {};
  for (const r of o.reports) for (const [f, s] of Object.entries(reportDurations(JSON.parse(readFileSync(r, "utf8"))))) (samples[f] ??= []).push(s);
  for (const [f, xs] of Object.entries(samples)) files[f] = { ...files[f], [o.platform]: Math.round(median(xs) * 10) / 10 };
  if (o.prune) for (const f of Object.keys(files)) if (!existsSync(join(ROOT, f))) delete files[f];
  writeFileSync(o.file, formatDurations(o.source, files));
  console.log(`${relative(ROOT, o.file)}: ${Object.keys(samples).length} file(s) updated for ${o.platform} from ${o.reports.length} report(s); ${Object.keys(files).length} file(s) recorded`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error(`test-durations: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }
}
