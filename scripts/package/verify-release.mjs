#!/usr/bin/env node
// Step 4, the owner's verifier of the release-signing workflow (docs/releasing.md). Run from a fresh clone of the
// public repository, not from the machine that built the release: it trusts only the values on its command line (typed
// by the owner from the TD's acceptance record), the release key pinned here and in the source commit, and what it
// recomputes. The package's signing-request.json can only narrow a check (which approved subkey must have signed), never
// supply a value. It never signs, never pushes and never creates or edits a GitHub release; each step only reads, and
// writes its record into the package.
//
//   node scripts/package/verify-release.mjs <step> --dir <signing package> --version <v> --commit <sha>
//        --manifest-sha256 <accepted digest> [--repo <clone>] [--gpg <gpg>] [--rehearsal] [--published]
//
//   package    the commit (signed by the commit key, carrying the version, pinning the release key), the manifest's
//              digest and content, every artifact's size, SHA-256 and BUILD-ID, nothing unexpected in the package
//   signature  package, then release-manifest.json.asc: one good signature by an approved release signing subkey (the
//              one the request names), or one of a key expired since, inside the subkey's validity
//   tag        signature, then the tag v<version> in --repo: annotated, on the commit, the exact message, signed the same way
//   payload    tag, then the exact GitHub release payload: the release key (from the commit) beside the manifest, its
//              signature and the artifacts; release-payload.json and RELEASE-NOTES.md
//   remote     payload's files, then GitHub's REPORT of its copy: the repository's ID, the pushed tag object, and the
//              release's files with the sizes and SHA-256 digests GitHub reports (a draft; --published after publishing).
//              Server-reported values, not a download: docs/releasing.md has the independent check
//   report     RELEASE-REPORT.md: each step's record, counted only while the package still has the state it checked
// A step first removes its old record, and records FAIL on any error, so no earlier PASS outlives a later attempt.
// Exit status: 0 PASS; 1 FAIL (the record says why); 2 a usage error.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  KEY_FILE, MANIFEST, PUBLIC_REPO, RECORD_SCHEMA, RELEASE_KEY, REMOTE_SOURCE, REQUEST, SIGNATURE, STEPS, approvedSubkeys,
  canonical, commitProblems, defaultGpg, expectationProblems, fileAt, git, gpgVersion, listKeys, packageCheck, payloadFiles,
  releaseKeyProblems, releaseState, remoteReleaseProblems, sha256, tagName, tagProblems, verifyDetached, withKeyring,
} from "./lib/release-verify.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COMMANDS = [...STEPS, "report"];
const record = (step) => `verified-${step}.json`;

function parse(argv) {
  const [step, ...rest] = argv;
  if (!COMMANDS.includes(step)) throw new Error(`the first argument is the step: ${COMMANDS.join(", ")}`);
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

/** The values a record was made with: a report counts it only for exactly these. */
const argsOf = (o) => ({ version: o.version, commit: o.commit, manifestSha256: o.manifestSha256, rehearsal: o.rehearsal, ...(o.step === "remote" ? { published: o.published } : {}) });

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
  // The request is never a source of values: it must agree with the owner's command line, and the subkey it names
  // must be an approved one, which then must have made the signatures.
  let expectSubkey = null;
  try {
    const req = JSON.parse(readFileSync(join(o.dir, REQUEST), "utf8"));
    if (req.version !== o.version || req.commit !== o.commit || req.manifest?.sha256 !== o.manifestSha256 || req.rehearsal !== o.rehearsal) problems.push(`${REQUEST} asks for another release than the command line (${req.version} at ${req.commit}, ${req.manifest?.sha256})`);
    expectSubkey = req.releaseKey?.signingSubkey ?? null;
    if (req.releaseKey?.primary !== pins.primary || !approvedSubkeys(pins).includes(expectSubkey)) problems.push(`${REQUEST} names the key ${req.releaseKey?.primary} / ${expectSubkey}, not the pinned primary with an approved signing subkey`);
  } catch {
    problems.push(`${REQUEST} is missing or unreadable`);
  }
  details.signingSubkey = expectSubkey;
  if (order < 1 || problems.length) return { problems, details };

  // signature
  if (!existsSync(join(o.dir, SIGNATURE))) return { problems: [`${SIGNATURE} is missing: the owner has not signed the manifest`], details };
  const sig = verifyDetached({ gpg, keyArmored, pins, signatureFile: join(o.dir, SIGNATURE), dataFile: join(o.dir, MANIFEST), expectSubkey });
  problems.push(...sig.problems);
  details.signature = { sha256: sha256(readFileSync(join(o.dir, SIGNATURE))), keyExpiredSince: sig.keyExpired, status: sig.status };
  if (order < 2 || problems.length) return { problems, details };

  // tag
  const tag = tagProblems({ repo, version: o.version, commit: o.commit, manifestSha256: o.manifestSha256, gpg, pins, keyArmored, expectSubkey });
  problems.push(...tag.problems);
  details.tag = { name: tagName(o.version), object: tag.tagObject ?? null, tagger: tag.tagger ?? null, keyExpiredSince: tag.keyExpired ?? false, status: tag.status ?? null };
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
  const payload = { tag: tagName(o.version), repository: repoPin, rehearsal: o.rehearsal, files };
  if (o.step === "payload") {
    writeFileSync(join(o.dir, "release-payload.json"), `${JSON.stringify(payload, null, 2)}\n`);
    if (!existsSync(join(o.dir, "RELEASE-NOTES.md"))) writeFileSync(join(o.dir, "RELEASE-NOTES.md"), notes(o, files, pins, expectSubkey));
  }
  let written = null;
  try { written = JSON.parse(readFileSync(join(o.dir, "release-payload.json"), "utf8")); } catch { /* reported below */ }
  if (canonical(written) !== canonical(payload)) problems.push("release-payload.json does not list exactly the verified files");
  if (order < 4 || problems.length) return { problems, details };

  // remote: GitHub's own report of its copy (REMOTE_SOURCE)
  details.remote = { source: REMOTE_SOURCE, repository: repoPin, release: null, published: o.published };
  try {
    const r = github(`repos/${repoPin.name}`);
    if (r.id !== repoPin.id) problems.push(`${repoPin.name} has ID ${r.id}, not ${repoPin.id}`);
    if (r.private !== false && !o.rehearsal) problems.push(`${repoPin.name} is not public`);
    const ref = github(`repos/${repoPin.name}/git/ref/tags/${tagName(o.version)}`);
    if (ref?.object?.type !== "tag" || ref.object.sha !== details.tag.object) problems.push(`GitHub's ${tagName(o.version)} is ${ref?.object?.type} ${ref?.object?.sha}, not the verified tag object ${details.tag.object}`);
    const release = (github(`repos/${repoPin.name}/releases?per_page=100`) ?? []).find((x) => x.tag_name === tagName(o.version));
    problems.push(...remoteReleaseProblems(release, { tag: tagName(o.version), files, published: o.published }));
    details.remote.release = release ? { id: release.id, draft: release.draft, url: release.html_url } : null;
  } catch (e) {
    problems.push(e instanceof Error ? e.message : String(e));
  }
  return { problems, details };
}

function notes(o, files, pins, subkey) {
  return `CodeParley ${o.version}, built from \`${o.commit}\`.

Verify before installing: the release manifest's signature, then every file against the manifest
([docs/verifying-releases.md](https://github.com/${PUBLIC_REPO.name}/blob/main/docs/verifying-releases.md)).

| | |
|---|---|
| Release manifest SHA-256 | \`${o.manifestSha256}\` |
| Release key | primary \`${pins.primary}\`, signing subkey \`${subkey}\` |

${files.map((f) => `- \`${f.name}\`: ${f.size} bytes, SHA-256 \`${f.sha256}\``).join("\n")}
`;
}

/** Each step's standing now: { status: PASS | FAIL | not verified, why, record }. */
function standing(o, ctx) {
  const now = releaseState(o.dir, ctx.repo, o.version);
  const out = {};
  for (const s of STEPS) {
    const path = join(o.dir, record(s));
    let r = null;
    try { r = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null; } catch { out[s] = { status: "not verified", why: "its record is unreadable" }; continue; }
    const absent = s === "signature" && !existsSync(join(o.dir, SIGNATURE)) ? " (the manifest is not signed yet)" : s === "tag" && !now.tag.tagObject ? " (there is no tag yet)" : "";
    if (!r) out[s] = { status: "not verified", why: `no record${absent}` };
    else if (r.schema !== RECORD_SCHEMA || r.step !== s) out[s] = { status: "not verified", why: "its record is not a record of this step" };
    else if (canonical(r.args) !== canonical(s === "remote" ? { ...argsOf({ ...o, step: s }), published: r.args?.published } : argsOf({ ...o, step: s }))) out[s] = { status: "not verified", why: "recorded with other values than this report's", record: r };
    else if (r.result !== "PASS") out[s] = { status: "FAIL", why: (r.problems ?? []).join("; "), record: r };
    else if (canonical(r.state) !== canonical(now[s])) {
      const changed = Object.keys(now[s]).filter((k) => canonical(now[s][k]) !== canonical(r.state?.[k]));
      out[s] = { status: "not verified", why: `stale: ${changed.join(", ") || "the state"} changed since${absent}`, record: r };
    } else out[s] = { status: "PASS", why: s === "remote" ? `GitHub-reported sizes and digests, ${r.args.published ? "published" : "draft"}` : "", record: r };
  }
  // Each step re-ran the earlier ones, and its state contains theirs: a current PASS of a later step covers an earlier
  // step that is only unverified (no record, stale, other values). An earlier step's own FAIL is never covered.
  for (let i = STEPS.length - 1; i > 0; i--) {
    const later = out[STEPS[i]];
    if (later.status !== "PASS") continue;
    for (const s of STEPS.slice(0, i)) if (out[s].status === "not verified") out[s] = { status: "PASS", why: `covered by the ${STEPS[i]} check, which re-ran it`, record: later.record };
  }
  return out;
}

/** The overall verdict: the steps that pass now, in order, stopping at the first that does not. */
function verdict(st) {
  const through = STEPS.findIndex((s) => st[s].status !== "PASS");
  const last = through === -1 ? STEPS.length - 1 : through - 1;
  if (last < 0) return "NOT VERIFIED: the package itself has no current PASS";
  if (last === STEPS.length - 1) {
    if (st.remote.record.args.published) return "VERIFIED THROUGH remote, published: every step passes now (GitHub-reported sizes and digests; the independent download check is the owner's, docs/releasing.md). This is verification, not the TD's acceptance";
    return "VERIFIED THROUGH remote, draft only: the release is not published, so this is not a verified release";
  }
  return `VERIFIED THROUGH ${STEPS[last]} only: ${STEPS.slice(last + 1).map((s) => `${s} ${st[s].status === "FAIL" ? "failed" : "not verified"}`).join(", ")}. This is not a verified release`;
}

function report(o, ctx, log) {
  const st = standing(o, ctx);
  const sig = st.signature.status === "PASS" ? st.signature.record.details.signature : null;
  const tag = st.tag.status === "PASS" ? st.tag.record.details.tag : null;
  const remote = st.remote.status === "PASS" ? st.remote.record.details.remote : null;
  const md = `# CodeParley ${o.version}: release verification report${o.rehearsal ? " (REHEARSAL)" : ""}

**${verdict(st)}.**

| | |
|---|---|
| Version | \`${o.version}\` |
| Source commit | \`${o.commit}\` |
| Manifest SHA-256 | \`${o.manifestSha256}\` |
| Signature | ${sig ? `SHA-256 \`${sig.sha256}\`${sig.keyExpiredSince ? " (the signing key has expired since)" : ""}` : "not verified"} |
| Tag | ${tag ? `\`${tag.name}\`, tag object \`${tag.object}\`` : "not verified"} |
| GitHub release | ${remote?.release?.url ? `${remote.release.url} (${remote.published ? "published" : "draft"}; GitHub-reported sizes and digests)` : "not verified"} |

| Step | Standing | Why | Checked at | Verifier commit |
|---|---|---|---|---|
${STEPS.map((s) => `| ${s} | ${st[s].status} | ${st[s].why.replaceAll("|", "\\|")} | ${st[s].record?.checkedAt ?? ""} | ${st[s].record?.verifier?.head ?? ""} |`).join("\n")}

The state of the package (every file, the signature, the local tag) was recomputed for this report; a record counts
only while that state is unchanged and only for the version, commit, manifest digest and mode above.
`;
  writeFileSync(join(o.dir, "RELEASE-REPORT.md"), md);
  log(`${verdict(st)}\nwrote ${join(o.dir, "RELEASE-REPORT.md")}\n`);
  return 0;
}

export function verify(argv, { pins = RELEASE_KEY, repoPin = PUBLIC_REPO, github = githubApi, log = (s) => process.stdout.write(s) } = {}) {
  const o = parse(argv);
  const ctx = { pins, repoPin, github, gpg: o.gpg ?? defaultGpg(), repo: o.repo ?? REPO };
  if (o.step === "report") return report(o, ctx, log);
  const at = join(o.dir, record(o.step));
  if (existsSync(o.dir)) rmSync(at, { force: true });
  let problems;
  let details = {};
  try {
    ({ problems, details } = checks(o, ctx));
  } catch (e) {
    problems = [`the verification stopped with an error: ${e instanceof Error ? e.message : String(e)}`];
  }
  let state = null;
  try { state = releaseState(o.dir, ctx.repo, o.version)[o.step]; } catch (e) { problems.push(`the release state cannot be read: ${e instanceof Error ? e.message : String(e)}`); }
  const rec = {
    schema: RECORD_SCHEMA,
    step: o.step,
    result: problems.length ? "FAIL" : "PASS",
    args: argsOf(o),
    state,
    problems,
    details,
    checkedAt: new Date().toISOString(),
    verifier: { repo: ctx.repo, head: git(REPO, ["rev-parse", "HEAD"]).stdout.trim(), node: process.version, gpg: gpgVersion(ctx.gpg) },
  };
  if (existsSync(o.dir)) writeFileSync(at, `${JSON.stringify(rec, null, 2)}\n`);
  if (problems.length) {
    log(`verify-release ${o.step}: FAIL${o.rehearsal ? " (rehearsal)" : ""}\n${problems.map((s) => `  - ${s}`).join("\n")}\n`);
    return 1;
  }
  log(`verify-release ${o.step}: PASS${o.rehearsal ? " (REHEARSAL)" : ""}\n  ${o.version} at ${o.commit}\n  manifest SHA-256 ${o.manifestSha256}\n  release key ${pins.primary} / signing subkey ${details.signingSubkey}\n`);
  if (details.signature) log(`  signature SHA-256 ${details.signature.sha256}${details.signature.keyExpiredSince ? " (good, by a key that has expired since; inside its validity)" : ""}\n`);
  if (details.tag) log(`  tag ${details.tag.name}, object ${details.tag.object}, tagger ${details.tag.tagger}\n`);
  if (o.step === "payload") log(`  payload: ${details.payload.length} files (release-payload.json); next: docs/releasing.md, "5. Publish"\n`);
  if (o.step === "remote") log(`  checked against GitHub's REPORTED sizes and digests (nothing downloaded); the independent download check is in docs/releasing.md\n`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = verify(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`verify-release: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  }
}
