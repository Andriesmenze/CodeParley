#!/usr/bin/env node
// Step 4, stage 1 of the release-signing workflow (docs/releasing.md): turn a staged release (stage-release.mjs) whose
// manifest the TD accepted into a signing package outside the repository, for the owner. Nothing is rebuilt (A-1): the
// files are copied byte for byte and checked again. Nothing is signed: the package holds the owner's signing request
// and the exact tag message; the owner signs with the release key (A-4).
//
//   node scripts/package/prepare-signing.mjs --staged <dir> --out <dir> --version <v> --commit <sha>
//        --manifest-sha256 <accepted digest> [--gpg <gpg>] [--rehearsal]
//
// Checks, all fail-closed: the accepted manifest digest; the manifest and every BUILD-ID (version, commit, a clean build
// of a verified commit, one toolchain); every artifact's size, SHA-256 and carried BUILD-ID; nothing else in the staged
// directory; the commit signed by the owner's commit key and carrying the version; the release key the commit pins.
// Repeating the command with the same inputs leaves a complete package as it is (also after the owner signed it); a
// package that differs is refused, never overwritten. An interrupted run leaves only a `<out>.partial-*` directory,
// which the next run removes. --rehearsal prepares a --test-version build, marked so throughout, for a signing
// rehearsal with a disposable key; the release key never signs one.
// Exit status: 0 prepared (or already prepared); 1 a check failed; 2 a usage or tool error.

import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MANIFEST, PUBLIC_REPO, RELEASE_KEY, REQUEST, REQUEST_SCHEMA, SIGNATURE, canonical, commitProblems, defaultGpg,
  expectationProblems, fileAt, git, listKeys, packageCheck, releaseKeyProblems, sidecarOf, tagMessage, tagName, withKeyring,
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
function request(o, manifest, digest, size, repo) {
  return {
    schema: REQUEST_SCHEMA,
    rehearsal: o.rehearsal,
    version: o.version,
    commit: o.commit,
    tag: tagName(o.version),
    manifest: { file: MANIFEST, size, sha256: digest },
    releaseKey: { primary: RELEASE_KEY.primary, subkey: RELEASE_KEY.subkey },
    publicRepository: PUBLIC_REPO,
    artifacts: manifest.artifacts.map((a) => ({ name: a.name, file: a.file, size: a.size, sha256: a.sha256 })),
    preparedAt: new Date().toISOString(),
    preparedWith: { toolCommit: git(repo, ["rev-parse", "HEAD"]).stdout.trim(), node: process.version },
  };
}
const comparable = (r) => canonical({ ...r, preparedAt: null, preparedWith: null });

/** The owner's instructions, with this release's values filled in (docs/releasing.md has the reasoning). */
function instructions(r, out) {
  const ps = (s) => s.replaceAll("'", "''");
  const verify = (step) => `node "$clone\\scripts\\package\\verify-release.mjs" ${step} --dir $pkg --version ${r.version} --commit ${r.commit} --manifest-sha256 ${r.manifest.sha256} --gpg $gpg${r.rehearsal ? " --rehearsal" : ""}`;
  return `# CodeParley ${r.version}: signing request${r.rehearsal ? " (REHEARSAL)" : ""}

${r.rehearsal ? "**REHEARSAL: sign this package only with a disposable test key, never with the release key or a YubiKey.**\n\n" : ""}For the owner, in a PowerShell 7 window outside the Claude app, with every Claude Code and Codex session closed
before the YubiKey goes in. Nothing here has been signed. This file is a copy of the request; the values to trust are
the ones in the TD's acceptance, which you compare in step 1.

| | |
|---|---|
| Version | \`${r.version}\` |
| Source commit | \`${r.commit}\` |
| Tag | \`${r.tag}\` |
| Manifest | \`${MANIFEST}\`, ${r.manifest.size} bytes |
| Manifest SHA-256 | \`${r.manifest.sha256}\` |
| Release key | primary \`${r.releaseKey.primary}\`, signing subkey \`${r.releaseKey.subkey}\` |

**Stop at the first FAIL.** Do not edit, rebuild or re-stage anything: a changed file is a new candidate.

## 0. Set up (once per window)

\`\`\`powershell
$gpg = 'C:\\Program Files\\GnuPG\\bin\\gpg.exe'
$pkg = '${ps(out)}'
$clone = '<a fresh clone of https://github.com/${PUBLIC_REPO.name}>'
git -C $clone fetch origin
git -C $clone checkout --detach origin/main
git -C $clone -c "gpg.program=$gpg" verify-commit HEAD
\`\`\`

The verifier runs from that clone, not from the machine or checkout that built the package. \`verify-commit\` must
report a good signature by the commit key \`261E3060E70B4904615F17BD026A2C3E92B42B25\`.

## 1. Verify the package (no YubiKey needed)

Check that the manifest SHA-256 in the command is the one the TD accepted, character by character.

\`\`\`powershell
${verify("package")}
\`\`\`

## 2. Sign the manifest (YubiKey)

\`\`\`powershell
& $gpg --card-status
\`\`\`

The card must list the signature key \`${r.releaseKey.subkey}\`. Then:

\`\`\`powershell
Set-Location -LiteralPath $pkg
& $gpg --armor --detach-sign --local-user '${r.releaseKey.subkey}!' --output ${SIGNATURE} ${MANIFEST}
\`\`\`

GnuPG asks for the card's PIN in its own window, and for a touch if the card requires one.

## 3. Verify the signature

\`\`\`powershell
${verify("signature")}
\`\`\`

## 4. Sign the tag (YubiKey), in the clone

\`\`\`powershell
git -C $clone -c "gpg.program=$gpg" -c "user.signingkey=${r.releaseKey.subkey}!" tag -s ${r.tag} ${r.commit} -F "$pkg\\TAG-MESSAGE.txt"
${verify("tag")} --repo $clone
\`\`\`

Remove the YubiKey now. Signing authorizes nothing else: pushing the tag and the release are separate decisions,
covered in docs/releasing.md, "5. Publish".
`;
}

export function prepare(argv, { pins = RELEASE_KEY, repo = REPO, log = (s) => process.stdout.write(s) } = {}) {
  const o = parse(argv);
  const gpg = o.gpg ?? defaultGpg();
  const problems = [];
  if (inside(o.out, repo)) problems.push(`--out ${o.out} is inside the repository: the signing package lives outside it`);
  if (inside(o.out, o.staged) || inside(o.staged, o.out)) problems.push("--out and --staged must be separate directories");
  if (!existsSync(o.staged)) problems.push(`--staged ${o.staged} does not exist`);
  problems.push(...commitProblems({ repo, commit: o.commit, version: o.version, gpg, pins, rehearsal: o.rehearsal }));
  try {
    const key = fileAt(repo, o.commit, RELEASE_KEY.file);
    problems.push(...withKeyring(gpg, [key], (kr) => releaseKeyProblems(listKeys(kr), pins)));
  } catch (e) {
    problems.push(e instanceof Error ? e.message : String(e));
  }
  const expect = { version: o.version, commit: o.commit, manifestSha256: o.manifestSha256, rehearsal: o.rehearsal };
  const staged = existsSync(o.staged) ? packageCheck(o.staged, { ...expect, allowed: [] }) : { problems: [] };
  problems.push(...staged.problems.map((s) => `staged: ${s}`));
  if (problems.length) return fail(log, problems);

  const want = request(o, staged.manifest, staged.manifestSha256, staged.manifestSize, repo);
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

  const part =`${o.out}.partial-${process.pid}-${Date.now()}`;
  mkdirSync(part);
  try {
    for (const f of [MANIFEST, ...staged.manifest.artifacts.flatMap((a) => [a.file, sidecarOf(a.file)]).filter(Boolean)]) copyFileSync(join(o.staged, f), join(part, f));
    writeFileSync(join(part, REQUEST), `${JSON.stringify(want, null, 2)}\n`);
    writeFileSync(join(part, "TAG-MESSAGE.txt"), tagMessage(o.version, want.manifest.sha256));
    writeFileSync(join(part, "SIGNING-REQUEST.md"), instructions(want, o.out));
    const copy = packageCheck(part, expect);
    if (copy.problems.length) return fail(log, copy.problems.map((s) => `copy: ${s}`));
    renameSync(part, o.out);
  } finally {
    rmSync(part, { recursive: true, force: true });
  }
  log(`prepared ${o.rehearsal ? "a REHEARSAL " : ""}signing package: ${o.out}\n  version ${o.version}, commit ${o.commit}\n  manifest SHA-256 ${want.manifest.sha256}\n  next: the owner follows ${join(o.out, "SIGNING-REQUEST.md")}\n`);
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
