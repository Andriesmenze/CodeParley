#!/usr/bin/env node
// Step 4, stage 3 of the release-signing workflow (docs/releasing.md): turn a staged release (stage-release.mjs) whose
// manifest the TD accepted into a signing package outside the repository, for the owner. Nothing is rebuilt (A-1): the
// files are copied byte for byte and checked again. Nothing is signed (A-4), and nothing here is an authority for the
// owner: SIGNING-REQUEST.md is a comparison sheet without commands. The owner runs the commands of docs/releasing.md
// from a verified clone, with the version, commit and manifest digest typed from the TD's acceptance record.
//
//   node scripts/package/prepare-signing.mjs --staged <dir> --out <dir> --version <v> --commit <sha>
//        --manifest-sha256 <accepted digest> [--gpg <gpg>] [--rehearsal]
//
// Checks, all fail-closed: the accepted manifest digest; the manifest and every BUILD-ID (version, commit, a clean build
// of a verified commit, one toolchain); every artifact's size, SHA-256 and carried BUILD-ID; nothing else in the staged
// directory; the commit signed by the owner's commit key and carrying the version; the release key the commit pins,
// with the CURRENT approved signing subkey in it, unexpired and unrevoked (the request names that subkey).
// Repeating the command with the same inputs leaves a complete package as it is (also after the owner signed it); a
// package that differs is refused, never overwritten. An interrupted run leaves only a `<out>.partial-*` directory,
// which the next run removes. --rehearsal prepares a --test-version build, marked so throughout, for a signing
// rehearsal with a disposable key; the release key never signs one.
// Exit status: 0 prepared (or already prepared); 1 a check failed; 2 a usage or tool error.

import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MANIFEST, PUBLIC_REPO, RELEASE_KEY, REQUEST, REQUEST_SCHEMA, SIGNATURE, canonical, commitProblems, currentSubkey,
  defaultGpg, expectationProblems, fileAt, git, listKeys, packageCheck, releaseKeyProblems, sidecarOf, tagName, withKeyring,
} from "./lib/release-verify.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function parse(argv) {
  const o = { staged: null, out: null, version: null, commit: null, manifestSha256: null, gpg: null, rehearsal: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => argv[++i] ?? (() => { throw new Error(`${a} requires a value`); })();
    if (a === "--staged") o.staged = resolve(v());
    else if (a === "--out") o.out = resolve(v());
    else if (a === "--version") o.version = v();
    else if (a === "--commit") o.commit = v();
    else if (a === "--manifest-sha256") o.manifestSha256 = v();
    else if (a === "--gpg") o.gpg = v();
    else if (a === "--rehearsal") o.rehearsal = true;
    else throw new Error(`unknown argument ${a}`);
  }
  const p = expectationProblems(o);
  if (!o.staged || !o.out) p.push("--staged <dir> and --out <dir> are required");
  if (p.length) throw new Error(p.join("; "));
  return o;
}

const inside = (child, parent) => {
  const r = relative(parent, child);
  return r === "" || (!r.startsWith("..") && !isAbsolute(r));
};

/** The machine-readable request: what the owner is asked to sign. preparedAt and preparedWith are not compared. */
function request(o, manifest, digest, size, repo, pins) {
  return {
    schema: REQUEST_SCHEMA,
    rehearsal: o.rehearsal,
    version: o.version,
    commit: o.commit,
    tag: tagName(o.version),
    manifest: { file: MANIFEST, size, sha256: digest },
    releaseKey: { primary: pins.primary, signingSubkey: currentSubkey(pins) },
    publicRepository: PUBLIC_REPO,
    artifacts: manifest.artifacts.map((a) => ({ name: a.name, file: a.file, size: a.size, sha256: a.sha256 })),
    preparedAt: new Date().toISOString(),
    preparedWith: { toolCommit: git(repo, ["rev-parse", "HEAD"]).stdout.trim(), node: process.version },
  };
}
const comparable = (r) => canonical({ ...r, preparedAt: null, preparedWith: null });

/** The comparison sheet. It holds values to compare and no command: the commands come from docs/releasing.md in the
 *  owner's verified clone, and the values the owner types come from the TD's acceptance record, never from here. */
function comparisonSheet(r, out) {
  return `# CodeParley ${r.version}: what this package asks to be signed${r.rehearsal ? " (REHEARSAL)" : ""}

${r.rehearsal ? "**REHEARSAL: sign this package only with a disposable test key, never with the release key or a YubiKey.**\n\n" : ""}A comparison sheet, written by the build machine. **It is not an authority and holds no commands.** Follow
\`docs/releasing.md\` in a fresh, verified clone of https://github.com/${PUBLIC_REPO.name}, and type the version, the
source commit and the manifest SHA-256 from the TD's acceptance record. Then compare them with this table: any
difference is a STOP.

| | This package says |
|---|---|
| Version | \`${r.version}\` |
| Source commit | \`${r.commit}\` |
| Tag | \`${r.tag}\` |
| Manifest | \`${MANIFEST}\`, ${r.manifest.size} bytes |
| Manifest SHA-256 | \`${r.manifest.sha256}\` |
| Release key, primary | \`${r.releaseKey.primary}\` |
| Signing subkey (the current approved one) | \`${r.releaseKey.signingSubkey}\` |
| Package directory | \`${out}\` |

Nothing here has been signed.
`;
}

export function prepare(argv, { pins = RELEASE_KEY, repo = REPO, log = (s) => process.stdout.write(s), now } = {}) {
  const o = parse(argv);
  const gpg = o.gpg ?? defaultGpg();
  const problems = [];
  if (inside(o.out, repo)) problems.push(`--out ${o.out} is inside the repository: the signing package lives outside it`);
  if (inside(o.out, o.staged) || inside(o.staged, o.out)) problems.push("--out and --staged must be separate directories");
  if (!existsSync(o.staged)) problems.push(`--staged ${o.staged} does not exist`);
  problems.push(...commitProblems({ repo, commit: o.commit, version: o.version, gpg, pins, rehearsal: o.rehearsal }));
  try {
    const key = fileAt(repo, o.commit, RELEASE_KEY.file);
    problems.push(...withKeyring(gpg, [key], (kr) => releaseKeyProblems(listKeys(kr), pins, { forSigning: true, ...(now ? { now } : {}) })));
  } catch (e) {
    problems.push(e instanceof Error ? e.message : String(e));
  }
  const expect = { version: o.version, commit: o.commit, manifestSha256: o.manifestSha256, rehearsal: o.rehearsal };
  const staged = existsSync(o.staged) ? packageCheck(o.staged, { ...expect, allowed: [] }) : { problems: [] };
  problems.push(...staged.problems.map((s) => `staged: ${s}`));
  if (problems.length) return fail(log, problems);

  const want = request(o, staged.manifest, staged.manifestSha256, staged.manifestSize, repo, pins);
  const parent = dirname(o.out);
  mkdirSync(parent, { recursive: true });
  for (const e of readdirSync(parent)) if (e.startsWith(`${basename(o.out)}.partial-`)) rmSync(join(parent, e), { recursive: true, force: true });
  if (existsSync(o.out)) {
    const have = packageCheck(o.out, expect);
    const p = [...have.problems];
    try {
      if (comparable(JSON.parse(readFileSync(join(o.out, REQUEST), "utf8"))) !== comparable(want)) p.push(`${REQUEST} differs from this request`);
    } catch {
      p.push(`${REQUEST} is missing or unreadable`);
    }
    if (p.length) return fail(log, [`${o.out} exists and is not this package; it is left unchanged`, ...p]);
    log(`already prepared, unchanged: ${o.out}${existsSync(join(o.out, SIGNATURE)) ? ` (it holds ${SIGNATURE})` : ""}\n  manifest SHA-256 ${want.manifest.sha256}\n`);
    return 0;
  }

  const part = `${o.out}.partial-${process.pid}-${Date.now()}`;
  mkdirSync(part);
  try {
    for (const f of [MANIFEST, ...staged.manifest.artifacts.flatMap((a) => [a.file, sidecarOf(a.file)]).filter(Boolean)]) copyFileSync(join(o.staged, f), join(part, f));
    writeFileSync(join(part, REQUEST), `${JSON.stringify(want, null, 2)}\n`);
    writeFileSync(join(part, "SIGNING-REQUEST.md"), comparisonSheet(want, o.out));
    const copy = packageCheck(part, expect);
    if (copy.problems.length) return fail(log, copy.problems.map((s) => `copy: ${s}`));
    renameSync(part, o.out);
  } finally {
    rmSync(part, { recursive: true, force: true });
  }
  log(`prepared ${o.rehearsal ? "a REHEARSAL " : ""}signing package: ${o.out}\n  version ${o.version}, commit ${o.commit}\n  manifest SHA-256 ${want.manifest.sha256}\n  signing subkey ${want.releaseKey.signingSubkey}\n  next: the owner follows docs/releasing.md in a verified clone; SIGNING-REQUEST.md is only for comparison\n`);
  return 0;
}

function fail(log, problems) {
  log(`prepare-signing: FAIL\n${problems.map((s) => `  - ${s}`).join("\n")}\n`);
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = prepare(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`prepare-signing: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  }
}
