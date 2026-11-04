#!/usr/bin/env node
// Step 6: refresh test/durations.json, the recorded duration of each test file per platform (test/schedule.ts balances
// the CI shards, orders the files and picks the quick tier by it), from full-suite runs: vitest JSON reports, or the
// logs of CI's test jobs (vitest's default reporter, which prints each file's duration).
//
//   npx vitest run --reporter=json --outputFile=<report.json>                    (a run on one platform)
//   gh api repos/vanderMerkProjects/CodeParley/actions/jobs/<job id>/logs > <job.log>   (a CI test job, every shard)
//   node scripts/ci/test-durations.mjs --platform win32|linux --source "<where the runs come from>"
//        [<report.json>...] [--log <job.log>]... [--file <durations.json>] [--prune]
//
// A file's new duration on that platform is the median over the runs that ran it; its other platform's entry is
// kept. --prune drops the entries of files that no longer exist. Only the relative durations matter: CI's runners are
// what the shards are balanced for, so their logs are the better source; a development machine is slower or faster
// file by file (it may run tests a runner skips).
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

/** A file's line in vitest's default reporter, with a GitHub Actions timestamp or without: ` ✓ test/x.test.ts (3 tests)
 * 120ms` (no duration: all skipped). */
const LOG_FILE = /^(?:\d{4}-\d\d-\d\dT[\d:.]+Z)?\s+[✓↓×❯]\s+(test\/\S+\.test\.ts)\s+\([^)]*\)(?:\s+(\d+)ms)?\s*$/u;

/** Per-file seconds from a default-reporter log. In a GitHub Actions job log, only the `npm test` step counts: the
 * Windows diagnostic runs one file on its own before it. */
export function logDurations(text) {
  const lines = text.replace(/\x1b\[[0-9;]*m/g, "").split(/\r?\n/);
  const step = lines.findIndex((l) => /##\[group\]Run npm test$/.test(l));
  const out = {};
  for (const l of step >= 0 ? lines.slice(step + 1) : lines) {
    if (step >= 0 && /##\[group\]Run /.test(l)) break;
    const m = LOG_FILE.exec(l);
    if (m) out[m[1]] = Number(m[2] ?? 0) / 1000;
  }
  return out;
}

function main(argv) {
  const o = { platform: null, source: null, file: join(ROOT, "test", "durations.json"), prune: false, reports: [], logs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--platform") o.platform = argv[++i];
    else if (a === "--source") o.source = argv[++i];
    else if (a === "--file") o.file = resolve(argv[++i]);
    else if (a === "--log") o.logs.push(resolve(argv[++i]));
    else if (a === "--prune") o.prune = true;
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else o.reports.push(resolve(a));
  }
  if (!PLATFORMS.includes(o.platform) || !o.source || o.reports.length + o.logs.length === 0) throw new Error("usage: test-durations.mjs --platform win32|linux --source <text> [<report.json>...] [--log <job.log>]... [--file <durations.json>] [--prune]");
  const current = JSON.parse(readFileSync(o.file, "utf8"));
  const files = { ...current.files };
  const samples = {};
  const runs = [...o.reports.map((r) => reportDurations(JSON.parse(readFileSync(r, "utf8")))), ...o.logs.map((l) => logDurations(readFileSync(l, "utf8")))];
  for (const run of runs) for (const [f, s] of Object.entries(run)) (samples[f] ??= []).push(s);
  if (Object.keys(samples).length === 0) throw new Error("no test file durations in the given reports and logs");
  for (const [f, xs] of Object.entries(samples)) files[f] = { ...files[f], [o.platform]: Math.round(median(xs) * 10) / 10 };
  if (o.prune) for (const f of Object.keys(files)) if (!existsSync(join(ROOT, f))) delete files[f];
  writeFileSync(o.file, formatDurations(o.source, files));
  console.log(`${relative(ROOT, o.file)}: ${Object.keys(samples).length} file(s) updated for ${o.platform} from ${runs.length} run(s); ${Object.keys(files).length} file(s) recorded`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error(`test-durations: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }
}
