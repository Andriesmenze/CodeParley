#!/usr/bin/env node
// Build CodeParley's local distributable package (Phase 5): an npm tarball made from a clean build
// of the checkout's tracked files, checked against the package content policy, with a report.
//
//   node scripts/package/pack.mjs [--out <dir>] [--require-clean] [--reproducible] [--keep-stage]
//                                 [--npm-cli <npm-cli.js>] [--json]
//
// 1. Stage: copy every file git tracks (with its working-tree content) into
//    .tmp-package/stage-<id>/ inside the repository, so the build resolves the repository's
//    node_modules; untracked files and an existing dist/ are not copied.
// 2. Build: `tsc -p <stage>/tsconfig.json`, exactly `npm run build` but on the clean stage.
// 3. Pack: `npm pack --ignore-scripts` in the stage; package.json `files` decides the content.
// 4. Check: read the tarball itself (lib/tar-lite.mjs) and apply the content policy
//    (lib/policy.mjs): only allowlisted files, every entry point, a compiled module for every
//    source module, every prompt template, no compiled module without a source.
// 5. Report: <out>/<name>-<version>.pack.json beside the tarball (sha256, npm integrity, the
//    source commit, whether the tree had changes, the file list and the policy result).
//
// --require-clean refuses a tree whose build inputs have uncommitted or untracked changes (release
// use); otherwise the report records them. --reproducible builds and packs twice from separate
// stages and requires identical tarballs. Nothing is installed or published. Exit status: 0 packed
// and compliant, 1 a policy or reproducibility failure (the tarball is kept for inspection), 2 an
// error (build, npm, git, usage).

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packageFiles } from "./lib/tar-lite.mjs";
import { checkPackageContent, sourceInventory } from "./lib/policy.mjs";
import { lockfileProduction, npmCli, runOk, sha256File, sourceIdentity, toolVersions } from "./lib/tools.mjs";

export const PACK_SCHEMA = "codeparley.pack-report.v1";
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
/** What a package build reads: a change to any of these makes the source "dirty". */
const BUILD_INPUTS = ["src", "prompts", "package.json", "package-lock.json", "tsconfig.json", "README.md"];

function parse(argv) {
  const o = { out: join(REPO, ".tmp-package"), requireClean: false, reproducible: false, keepStage: false, npmCli: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => {
      const x = argv[++i];
      if (x === undefined) throw new Error(`${a} requires a value`);
      return x;
    };
    if (a === "--out") o.out = resolve(v());
    else if (a === "--npm-cli") o.npmCli = resolve(v());
    else if (a === "--require-clean") o.requireClean = true;
    else if (a === "--reproducible") o.reproducible = true;
    else if (a === "--keep-stage") o.keepStage = true;
    else if (a === "--json") o.json = true;
    else throw new Error(`unknown option ${a}`);
  }
  return o;
}

/** Copy the tracked files of the checkout into a fresh stage inside the repository. */
function stage(repo) {
  const dir = join(repo, ".tmp-package", `stage-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  const listed = runOk("git", ["-C", repo, "ls-files", "-z", "--cached"], { label: "git ls-files" }).stdout.split("\0").filter(Boolean);
  let copied = 0;
  for (const rel of listed) {
    const from = join(repo, ...rel.split("/"));
    if (!existsSync(from) || rel === "dist" || rel.startsWith("dist/")) continue;
    cpSync(from, join(dir, ...rel.split("/")));
    copied++;
  }
  return { dir, copied };
}

function buildAndPack(o, npm, outDir) {
  const st = stage(REPO);
  try {
    runOk(process.execPath, [join(REPO, "node_modules", "typescript", "bin", "tsc"), "-p", join(st.dir, "tsconfig.json")], { cwd: st.dir, label: "tsc (clean build)" });
    mkdirSync(outDir, { recursive: true });
    const r = runOk(process.execPath, [npm, "pack", "--json", "--ignore-scripts", "--pack-destination", outDir], { cwd: st.dir, label: "npm pack" });
    const npmReport = JSON.parse(r.stdout.slice(r.stdout.indexOf("[")))[0];
    return { stage: st, npmReport, tarball: join(outDir, npmReport.filename), inventory: sourceInventory(st.dir) };
  } finally {
    if (!o.keepStage) rmSync(st.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

/** Compare npm's own file list with the tarball's real content. */
function listAgreement(npmReport, files) {
  const npmPaths = new Set(npmReport.files.map((f) => f.path));
  const tarPaths = new Set(files.keys());
  const onlyNpm = [...npmPaths].filter((p) => !tarPaths.has(p));
  const onlyTar = [...tarPaths].filter((p) => !npmPaths.has(p));
  return { agree: onlyNpm.length === 0 && onlyTar.length === 0, only_in_npm_report: onlyNpm, only_in_tarball: onlyTar };
}

export function pack(o) {
  const npm = npmCli(process.execPath, o.npmCli);
  const source = sourceIdentity(REPO, BUILD_INPUTS);
  if (o.requireClean && source.dirty) throw new Error(`the build inputs have uncommitted or untracked changes (--require-clean):\n  ${source.changes.join("\n  ")}`);
  const first = buildAndPack(o, npm, o.out);
  const pkg = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8"));
  const files = packageFiles(readFileSync(first.tarball));
  const policy = checkPackageContent([...files.keys()], { pkg, inventory: first.inventory });
  const sha256 = sha256File(first.tarball);
  let reproducible = null;
  if (o.reproducible) {
    const second = buildAndPack(o, npm, join(o.out, "repro-check"));
    const sha2 = sha256File(second.tarball);
    reproducible = { identical: sha2 === sha256, second_sha256: sha2 };
    rmSync(join(o.out, "repro-check"), { recursive: true, force: true });
  }
  const report = {
    schema: PACK_SCHEMA,
    package: { name: first.npmReport.name, version: first.npmReport.version },
    tarball: { file: first.tarball, bytes: first.npmReport.size, unpacked_bytes: first.npmReport.unpackedSize, sha256, npm_integrity: first.npmReport.integrity, npm_shasum: first.npmReport.shasum },
    source: { repository: REPO, commit: source.commit, dirty: source.dirty, changes: source.changes, staged_files: first.stage.copied },
    // What the development lockfile pins; an installation resolves the declared ranges afresh.
    lockfile_production: lockfileProduction(JSON.parse(readFileSync(join(REPO, "package-lock.json"), "utf8"))),
    tools: { ...toolVersions(process.execPath, npm), platform: `${process.platform}-${process.arch}` },
    files: [...files.values()].map((f) => ({ path: f.path, bytes: f.size, mode: f.mode.toString(8) })).sort((a, b) => a.path.localeCompare(b.path)),
    npm_list_agreement: listAgreement(first.npmReport, files),
    policy,
    reproducible,
    created_at: new Date().toISOString(),
  };
  report.ok = policy.ok && report.npm_list_agreement.agree && (reproducible === null || reproducible.identical);
  writeFileSync(first.tarball.replace(/\.tgz$/, ".pack.json"), `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

function summary(r) {
  const lines = [`packed ${r.package.name} ${r.package.version}: ${r.tarball.file}`, `  ${r.files.length} files, ${r.tarball.bytes} bytes (${r.tarball.unpacked_bytes} unpacked); sha256 ${r.tarball.sha256}`, `  source ${r.source.commit}${r.source.dirty ? " WITH UNCOMMITTED CHANGES" : ""}; node ${r.tools.node}, npm ${r.tools.npm}, ${r.tools.platform}`];
  if (!r.npm_list_agreement.agree) lines.push(`  FAIL npm's file list and the tarball disagree: ${JSON.stringify(r.npm_list_agreement)}`);
  for (const u of r.policy.unexpected) lines.push(`  FAIL not allowed in the package: ${u.path} — ${u.why}`);
  for (const m of r.policy.missing) lines.push(`  FAIL missing from the package: ${m.path} — ${m.why}`);
  for (const p of r.policy.orphans) lines.push(`  FAIL compiled module without a tracked source: ${p}`);
  if (r.reproducible) {
    const sha2 = r.reproducible.second_sha256;
    const outcome = r.reproducible.identical ? "PASS reproducible: a second clean build gave the identical tarball" : `FAIL reproducible: a second clean build differs (sha256 ${sha2})`;
    lines.push(`  ${outcome}`);
  }
  lines.push(r.ok ? "pack: OK (content policy satisfied)" : "pack: FAILED");
  return lines;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const o = parse(process.argv.slice(2));
    const r = pack(o);
    process.stdout.write(o.json ? `${JSON.stringify(r, null, 2)}\n` : `${summary(r).join("\n")}\n`);
    process.exitCode = r.ok ? 0 : 1;
  } catch (e) {
    process.stderr.write(`pack: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  }
}
