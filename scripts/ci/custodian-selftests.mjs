#!/usr/bin/env node
// Phase 6 Increment 1: run the custodian's self-tests the way CI does, on any machine (T1 local validation runs
// exactly this). Each verb runs the built custodian executable; a non-zero exit or a missing "passed" line fails.
//
//   node scripts/ci/custodian-selftests.mjs --host windows|linux --exe <custodian executable> [--json <report>]
//
// Windows: every self-test that needs no service installation (the ledger, IPC, identity, digest, no-follow,
// content-key and the three shared corpora, and the helper channel). Linux: the ones that run unprivileged on ext4
// (the durable store, the repository identity, the isolation basis, content-key and the three shared corpora); the
// host check needs the provisioned system and is verified on the native VM, not here. The `version` verb's identity
// is recorded first.
//
// A CI Windows runner's token is elevated, and an elevated token's default owner is Administrators. The helper channel
// self-test authenticates its in-process pipe as owned by the identity that hosts it, so it runs with the default owner set
// to the token's user (run-with-user-owner.ps1). Its agent cases need node.exe and git.exe, and skip themselves without
// them: that is a failure here, never a pass.
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const host = opt("host");
const exe = opt("exe");
const jsonOut = opt("json");
if ((host !== "windows" && host !== "linux") || !exe) {
  console.error("usage: custodian-selftests.mjs --host windows|linux --exe <custodian executable> [--json <report>]");
  process.exit(2);
}
const fixtures = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "test", "fixtures");
const corpus = (name) => ["--corpus", join(fixtures, `${name}.json`)];
const shared = [
  ["self-test-content-key", ...corpus("amendment-content-key-corpus")],
  ["self-test-store-format"],
  ["self-test-store-upgrade"],
  ["self-test-runtime-git"],
  ["self-test-loop-corpus", ...corpus("loop-transition-corpus")],
  ["self-test-run-corpus", ...corpus("run-transition-corpus")],
  ["self-test-config-corpus", ...corpus("config-digest-corpus")],
];
const verbs =
  host === "windows"
    ? [["self-test-digest"], ["self-test-ledger"], ["self-test-nofollow"], ["self-test-identity"], ["self-test-ipc"], ...shared, ["self-test-helper-channel"]]
    : [["self-test-durable"], ["self-test-identity"], ["self-test-isolation-basis"], ...shared];

// The IPC and helper-channel self-tests host the custodian's own pipe names in process: an installed custodian
// service that is running owns them, and the self-tests' clients would reach the service instead.
const SERVICE_PIPE = "\\\\.\\pipe\\CodeParley.Custodian.v1.implementer";
if (host === "windows" && existsSync(SERVICE_PIPE)) {
  console.error(`${SERVICE_PIPE} exists: an installed custodian service is running here; stop it for the self-tests (they host its pipe names)`);
  process.exit(2);
}

// The Linux self-tests write under TMPDIR: give them their own directory on the machine's filesystem.
const tmp = mkdtempSync(join(tmpdir(), "cp-selftests-"));
const env = { ...process.env, TMPDIR: tmp };
const spawned = (command, argv) => spawnSync(command, argv, { encoding: "utf8", env, windowsHide: true, timeout: 900_000, maxBuffer: 64 * 1024 * 1024 });
const HELPER_CHANNEL = "self-test-helper-channel";
const ownerWrapper = join(fileURLToPath(new URL(".", import.meta.url)), "run-with-user-owner.ps1");
const run = (argv) =>
  host === "windows" && argv[0] === HELPER_CHANNEL
    ? spawned("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ownerWrapper, "-Exe", exe, "-Verb", HELPER_CHANNEL])
    : spawned(exe, argv);

const report = { host, exe, version: null, results: [] };
const v = run(["version"]);
if (v.status === 0) report.version = JSON.parse(v.stdout.trim());
console.log(`custodian ${report.version ? JSON.stringify(report.version) : `version unavailable (exit ${v.status})`}`);

let failed = 0;
for (const argv of verbs) {
  const t0 = Date.now();
  const r = run(argv);
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`.trim();
  const last = out.split(/\r?\n/).pop() ?? "";
  const lines = out.split(/\r?\n/);
  const skipped = lines.filter((l) => l.startsWith("[skip]"));
  const agentCasesSkipped = argv[0] === HELPER_CHANNEL && skipped.some((l) => l.includes("agent cases"));
  const ok = r.status === 0 && !/\bFAIL\b/.test(out) && !agentCasesSkipped;
  if (!ok) failed++;
  report.results.push({ verb: argv[0], exit: r.status, ok, seconds: (Date.now() - t0) / 1000, last, skipped });
  console.log(`${ok ? "PASS" : "FAIL"} ${argv[0].padEnd(26)} exit ${r.status} (${((Date.now() - t0) / 1000).toFixed(1)} s): ${last.slice(0, 160)}`);
  for (const l of [...lines.filter((x) => x.startsWith("token user ")), ...skipped]) console.log(`  ${l}`);
  if (!ok) console.log(lines.filter((l) => /FAIL|Exception|error/i.test(l)).slice(0, 20).join("\n"));
}
rmSync(tmp, { recursive: true, force: true });
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(report, null, 2));
console.log(`${verbs.length - failed}/${verbs.length} custodian self-tests passed`);
process.exit(failed === 0 && report.version !== null ? 0 : 1);
