#!/usr/bin/env node
// Step 4, the owner's verifier of the release-signing workflow (docs/releasing.md). Run from a fresh clone of the
// public repository, not from the machine that built the release: it trusts only the values on its command line (from
// the TD's acceptance), the release key pinned here and in the source commit, and what it recomputes. It never signs,
// never pushes and never creates or edits a GitHub release; each step only reads and writes its record into the package.
//
//   node scripts/package/verify-release.mjs <step> --dir <signing package> --version <v> --commit <sha>
//        --manifest-sha256 <accepted digest> [--repo <clone>] [--gpg <gpg>] [--rehearsal] [--published]
//
//   package    the commit (signed by the commit key, carrying the version, pinning the release key), the manifest's
//              digest and content, every artifact's size, SHA-256 and BUILD-ID, nothing unexpected in the package
//   signature  package, then release-manifest.json.asc: one good signature by the release signing subkey
//   tag        signature, then the tag v<version> in --repo: annotated, on the commit, the exact message, signed by the
//              release key
//   payload    tag, then the exact GitHub release payload: the release key (from the commit) beside the manifest, its
//              signature and the artifacts; release-payload.json; the commands to push and upload, for the owner
//   remote     payload's files, then GitHub: the repository's ID, the pushed tag object, and the release's files, sizes
//              and SHA-256 digests (a draft; --published after the owner published it)
//   report     RELEASE-REPORT.md from the steps' records
// Exit status: 0 PASS; 1 FAIL (the record says why); 2 a usage or tool error.

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  KEY_FILE, MANIFEST, PUBLIC_REPO, RECORD_SCHEMA, RELEASE_KEY, REQUEST, SIGNATURE, commitProblems, defaultGpg,
  expectationProblems, fileAt, git, listKeys, packageCheck, payloadFiles, releaseKeyProblems, remoteReleaseProblems,
  sha256, tagName, tagProblems, verifyDetached, withKeyring,
} from "./lib/release-verify.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const STEPS = ["package", "signature", "tag", "payload", "remote", "report"];

function parse(argv) {
  const [step, ...rest] = argv;
  if (!STEPS.includes(step)) throw new Error(`the first argument is the step: ${STEPS.join(", ")}`);
  const o = { step, dir: null, version: null, commit: null, manifestSha256: null, repo: null, gpg: null, rehearsal: false, published: false };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const v = () => rest[++i] ?? (() => { throw new Error(`${a} requires a value`); })();
    if (a === "--dir") o.dir = resolve(v());
    else if (a === "--version") o.version = v();
    else if (a === "--commit") o.commit = v();
    else if (a === "--manifest-sha256") o.manifestSha256 = v();
    else if (a === "--repo") o.repo = resolve(v());
    else if (a === "--gpg") o.gpg = v();
    else if (a === "--rehearsal") o.rehearsal = true;
    else if (a === "--published") o.published = true;
    else throw new Error(`unknown argument ${a}`);
  }
  const p = expectationProblems(o);
  if (!o.dir) p.push("--dir <signing package> is required");
  if (p.length) throw new Error(p.join("; "));
  return o;
}

const githubApi = (path) => {
  const r = spawnSync("gh", ["api", path], { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`gh api ${path} failed: ${(r.stderr || r.error?.message || "").trim().split("\n")[0]}`);
  return JSON.parse(r.stdout);
};

/** The checks of each step, cumulative: a later step re-runs the earlier ones, so no step trusts an old record. */
function checks(o, ctx) {
  const { pins, gpg, repo, github, repoPin } = ctx;
  const details = {};
  const problems = [];
  const expect = { version: o.version, commit: o.commit, manifestSha256: o.manifestSha256, rehearsal: o.rehearsal };
  const order = STEPS.indexOf(o.step);

  // package
  problems.push(...commitProblems({ repo, commit: o.commit, version: o.version, gpg, pins, rehearsal: o.rehearsal }));
  let keyArmored = null;
  try {
    keyArmored = fileAt(repo, o.commit, RELEASE_KEY.file);
    const keys = withKeyring(gpg, [keyArmored], (kr) => listKeys(kr));
    problems.push(...releaseKeyProblems(keys, pins));
    details.releaseKey = { primary: keys[0]?.primary ?? null, subkeys: keys[0]?.subkeys.map((s) => s.fpr) ?? [] };
  } catch (e) {
    problems.push(e instanceof Error ? e.message : String(e));
  }
  const pkg = packageCheck(o.dir, expect);
  problems.push(...pkg.problems);
  details.manifest = { sha256: pkg.manifestSha256 ?? null, size: pkg.manifestSize ?? null, artifacts: pkg.manifest?.artifacts?.length ?? 0 };
  try {
    const req = JSON.parse(readFileSync(join(o.dir, REQUEST), "utf8"));
    if (req.version !== o.version || req.commit !== o.commit || req.manifest?.sha256 !== o.manifestSha256 || req.rehearsal !== o.rehearsal) problems.push(`${REQUEST} asks for another release than the command line (${req.version} at ${req.commit}, ${req.manifest?.sha256})`);
  } catch {
    problems.push(`${REQUEST} is missing or unreadable`);
  }
  if (order < 1 || problems.length) return { problems, details };

  // signature
  if (!existsSync(join(o.dir, SIGNATURE))) return { problems: [`${SIGNATURE} is missing: the owner has not signed the manifest`], details };
  const sig = verifyDetached({ gpg, keyArmored, pins, signatureFile: join(o.dir, SIGNATURE), dataFile: join(o.dir, MANIFEST) });
  problems.push(...sig.problems);
  details.signature = { sha256: sha256(readFileSync(join(o.dir, SIGNATURE))), status: sig.status };
  if (order < 2 || problems.length) return { problems, details };

  // tag
  const tag = tagProblems({ repo, version: o.version, commit: o.commit, manifestSha256: o.manifestSha256, gpg, pins, keyArmored });
  problems.push(...tag.problems);
  details.tag = { name: tagName(o.version), object: tag.tagObject ?? null, tagger: tag.tagger ?? null, status: tag.status ?? null };
  if (order < 3 || problems.length) return { problems, details };

  // payload
  const keyPath = join(o.dir, KEY_FILE);
  if (o.step === "payload" && !existsSync(keyPath)) writeFileSync(keyPath, keyArmored);
  if (!existsSync(keyPath) || readFileSync(keyPath, "utf8") !== keyArmored) problems.push(`${KEY_FILE} in the package is not the release key file of commit ${o.commit}`);
  const files = payloadFiles(pkg.manifest).map((name) => {
    const data = existsSync(join(o.dir, name)) ? readFileSync(join(o.dir, name)) : null;
    return { name, size: data?.length ?? 0, sha256: data ? sha256(data) : null };
  });
  for (const f of files) if (f.sha256 === null) problems.push(`${f.name} is missing from the payload`);
  details.payload = files;
  if (problems.length) return { problems, details };
  if (o.step === "payload") {
    const payload = { tag: tagName(o.version), repository: repoPin, rehearsal: o.rehearsal, files };
    writeFileSync(join(o.dir, "release-payload.json"), `${JSON.stringify(payload, null, 2)}\n`);
    if (!existsSync(join(o.dir, "RELEASE-NOTES.md"))) writeFileSync(join(o.dir, "RELEASE-NOTES.md"), notes(o, files));
  }
  if (order < 4) return { problems, details };

  // remote
  try {
    const r = github(`repos/${repoPin.name}`);
    if (r.id !== repoPin.id) problems.push(`${repoPin.name} has ID ${r.id}, not ${repoPin.id}`);
    if (r.private !== false && !o.rehearsal) problems.push(`${repoPin.name} is not public`);
    const ref = github(`repos/${repoPin.name}/git/ref/tags/${tagName(o.version)}`);
    if (ref?.object?.type !== "tag" || ref.object.sha !== details.tag.object) problems.push(`GitHub's ${tagName(o.version)} is ${ref?.object?.type} ${ref?.object?.sha}, not the verified tag object ${details.tag.object}`);
    const release = (github(`repos/${repoPin.name}/releases?per_page=100`) ?? []).find((x) => x.tag_name === tagName(o.version));
    problems.push(...remoteReleaseProblems(release, { tag: tagName(o.version), files, published: o.published }));
    details.remote = { repository: repoPin, release: release ? { id: release.id, draft: release.draft, url: release.html_url } : null, published: o.published };
  } catch (e) {
    problems.push(e instanceof Error ? e.message : String(e));
  }
  return { problems, details };
}

function notes(o, files) {
  return `CodeParley ${o.version}, built from \`${o.commit}\`.

Verify before installing: the release manifest's signature, then every file against the manifest
([docs/verifying-releases.md](https://github.com/${PUBLIC_REPO.name}/blob/main/docs/verifying-releases.md)).

| | |
|---|---|
| Release manifest SHA-256 | \`${o.manifestSha256}\` |
| Release key | primary \`${RELEASE_KEY.primary}\`, signing subkey \`${RELEASE_KEY.subkey}\` |

${files.map((f) => `- \`${f.name}\`: ${f.size} bytes, SHA-256 \`${f.sha256}\``).join("\n")}
`;
}

function report(o, log) {
  // A step's record is its latest run. A run with other arguments (another version, commit, digest or mode) is shown
  // as such and never counts for this release.
  const all = readdirSync(o.dir).filter((f) => /^verified-[a-z]+\.json$/.test(f)).map((f) => JSON.parse(readFileSync(join(o.dir, f), "utf8")));
  const ours = (r) => r.version === o.version && r.commit === o.commit && r.manifestSha256 === o.manifestSha256 && r.rehearsal === o.rehearsal;
  const records = all.filter(ours);
  const by = (s) => records.find((r) => r.step === s);
  const rows = STEPS.slice(0, 5).map((s) => {
    const r = by(s);
    const foreign = all.find((x) => x.step === s && !ours(x));
    return `| ${s} | ${r ? r.result : foreign ? "not run with these arguments (the latest run had others)" : "not run"} | ${r?.checkedAt ?? ""} | ${r?.verifier?.head ?? ""} |`;
  });
  const last = records.filter((r) => r.result === "PASS").sort((a, b) => STEPS.indexOf(b.step) - STEPS.indexOf(a.step))[0];
  const remote = by("remote")?.details?.remote;
  const md = `# CodeParley ${o.version}: release verification report${o.rehearsal ? " (REHEARSAL)" : ""}

| | |
|---|---|
| Version | \`${o.version}\` |
| Source commit | \`${o.commit}\` |
| Tag | \`${tagName(o.version)}\`${last?.details?.tag?.object ? `, tag object \`${last.details.tag.object}\`` : ""} |
| Manifest SHA-256 | \`${o.manifestSha256}\` |
| Signature SHA-256 | ${last?.details?.signature?.sha256 ? `\`${last.details.signature.sha256}\`` : "not verified"} |
| Release key | primary \`${RELEASE_KEY.primary}\`, signing subkey \`${RELEASE_KEY.subkey}\` |
| GitHub release | ${remote?.release?.url ? `${remote.release.url} (${remote.published ? "published" : "draft"}, ${by("remote").result})` : "not checked"} |

| Step | Result | Checked at | Verifier commit |
|---|---|---|---|
${rows.join("\n")}

${records.filter((r) => r.result !== "PASS").map((r) => `**${r.step} FAILED:**\n${r.problems.map((p) => `- ${p}`).join("\n")}`).join("\n\n")}
${last?.details?.payload ? `\nPayload:\n\n${last.details.payload.map((f) => `- \`${f.name}\`: ${f.size} bytes, \`${f.sha256}\``).join("\n")}\n` : ""}`;
  writeFileSync(join(o.dir, "RELEASE-REPORT.md"), md);
  log(`wrote ${join(o.dir, "RELEASE-REPORT.md")}\n`);
  return 0;
}

export function verify(argv, { pins = RELEASE_KEY, repoPin = PUBLIC_REPO, github = githubApi, log = (s) => process.stdout.write(s) } = {}) {
  const o = parse(argv);
  if (o.step === "report") return report(o, log);
  const ctx = { pins, repoPin, github, gpg: o.gpg ?? defaultGpg(), repo: o.repo ?? REPO };
  const { problems, details } = checks(o, ctx);
  const gpgVersion = spawnSync(ctx.gpg, ["--version"], { encoding: "utf8", windowsHide: true }).stdout?.split("\n")[0] ?? null;
  const record = {
    schema: RECORD_SCHEMA,
    step: o.step,
    result: problems.length ? "FAIL" : "PASS",
    rehearsal: o.rehearsal,
    version: o.version,
    commit: o.commit,
    tag: tagName(o.version),
    manifestSha256: o.manifestSha256,
    problems,
    details,
    checkedAt: new Date().toISOString(),
    verifier: { repo: ctx.repo, head: git(REPO, ["rev-parse", "HEAD"]).stdout.trim(), node: process.version, gpg: gpgVersion },
  };
  if (existsSync(o.dir)) writeFileSync(join(o.dir, `verified-${o.step}.json`), `${JSON.stringify(record, null, 2)}\n`);
  if (problems.length) {
    log(`verify-release ${o.step}: FAIL${o.rehearsal ? " (rehearsal)" : ""}\n${problems.map((s) => `  - ${s}`).join("\n")}\n`);
    return 1;
  }
  log(`verify-release ${o.step}: PASS${o.rehearsal ? " (REHEARSAL)" : ""}\n  ${o.version} at ${o.commit}\n  manifest SHA-256 ${o.manifestSha256}\n  release key ${pins.primary} / signing subkey ${pins.subkey}\n`);
  if (details.signature) log(`  signature SHA-256 ${details.signature.sha256}\n`);
  if (details.tag) log(`  tag ${details.tag.name}, object ${details.tag.object}, tagger ${details.tag.tagger}\n`);
  if (o.step === "payload") log(nextCommands(o, details.payload, repoPin));
  return 0;
}

/** What the owner runs after `payload`, each only after authorizing it. */
function nextCommands(o, files, repoPin) {
  const tag = tagName(o.version);
  return `
The payload is ${files.length} files (release-payload.json). After the owner authorizes publication, in the clone:

  gh api repos/${repoPin.name} --jq .id          # must print ${repoPin.id}
  git -C <clone> push origin refs/tags/${tag}
  gh release create ${tag} --repo ${repoPin.name} --draft --verify-tag --title "CodeParley ${o.version}" --notes-file "${join(o.dir, "RELEASE-NOTES.md")}" ${files.map((f) => `"${join(o.dir, f.name)}"`).join(" ")}
  node scripts/package/verify-release.mjs remote ...the same arguments...
  gh release edit ${tag} --repo ${repoPin.name} --draft=false     # publishes: only on the owner's explicit approval
  node scripts/package/verify-release.mjs remote ...the same arguments... --published
`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = verify(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`verify-release: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  }
}
