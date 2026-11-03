// Step 4 (contract §8, A-1 to A-5): the checks of the release-signing workflow, shared by the preparation script
// (scripts/package/prepare-signing.mjs), the owner's verifier (scripts/package/verify-release.mjs) and their tests.
// Nothing here signs: signing the manifest and the tag stays the owner's, with the release key on a YubiKey (A-4).
// Every check returns problems instead of throwing, so a caller reports all of them and fails closed on any.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { ARTIFACTS, BUILD_ID_SCHEMA, MANIFEST_SCHEMA } from "./release-manifest.mjs";
import { readTarGz } from "./tar-lite.mjs";

/** The release key (docs/verifying-releases.md). Distinct from the commit-signing key in .github/ci/. */
export const RELEASE_KEY = Object.freeze({
  primary: "7CC498583C78D63448E0EFA45E1FB31A78518E8C",
  subkey: "EFD68E181281081CBFA601EC35208A9E3684E6C9",
  file: "docs/codeparley-release-key.asc",
});
export const COMMIT_KEY_FILE = ".github/ci/commit-signing-key.asc";
/** The public repository the releases are published from: its numeric ID, which a rename does not change. */
export const PUBLIC_REPO = Object.freeze({ name: "vanderMerkProjects/CodeParley", id: 1443307878 });

export const MANIFEST = "release-manifest.json";
export const SIGNATURE = "release-manifest.json.asc";
export const KEY_FILE = "codeparley-release-key.asc";
export const REQUEST = "signing-request.json";
export const REQUEST_SCHEMA = "codeparley.signing-request.v1";
export const RECORD_SCHEMA = "codeparley.release-verification.v1";
/** Files the workflow itself writes into a signing package; anything not listed, or not an artifact, is refused. */
export const PACKAGE_FILES = Object.freeze({
  request: [REQUEST, "SIGNING-REQUEST.md", "TAG-MESSAGE.txt"],
  owner: [SIGNATURE],
  publication: [KEY_FILE, "release-payload.json", "RELEASE-NOTES.md"],
  records: ["verified-package.json", "verified-signature.json", "verified-tag.json", "verified-payload.json", "verified-remote.json", "RELEASE-REPORT.md"],
});

const HEX64 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const FPR = /^[0-9A-F]{40}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/;

export const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
export const tagName = (version) => `v${version}`;
/** The exact message of the release tag: it binds the tag to the manifest the owner signed. */
export const tagMessage = (version, manifestSha256) => `CodeParley ${version}\n\nRelease manifest SHA-256: ${manifestSha256}\n`;
/** The files of a GitHub release, in upload order: the manifest, its signature, the release key, the artifacts. */
export const payloadFiles = (manifest) => [MANIFEST, SIGNATURE, KEY_FILE, ...manifest.artifacts.map((a) => a.file)];
/** The BUILD-ID sidecar of an artifact that cannot carry one inside (the npm tarball, the installers). */
export const sidecarOf = (file) => (file.endsWith(".tar.gz") ? null : `${file}.BUILD-ID`);

/** JSON with sorted keys, so two equal objects compare equal however their keys were ordered. */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/** Usage checks shared by both scripts: a version, a full commit id and a manifest digest, each exact. */
export function expectationProblems({ version, commit, manifestSha256 }) {
  const p = [];
  if (!VERSION.test(version ?? "")) p.push("--version must be a version such as 1.0.1");
  if (!COMMIT.test(commit ?? "")) p.push("--commit must be the full 40-character id of the release source commit");
  if (!HEX64.test(manifestSha256 ?? "")) p.push("--manifest-sha256 must be the 64 lower-case hex digits of the accepted manifest");
  return p;
}

/**
 * The manifest against what the release must be (A-2, A-3): the version, the commit, a clean build of a verified
 * commit, unsigned, every artifact once in order with a plain file name, and BUILD-IDs that agree with the manifest and
 * with each other (one toolchain, one build time). A rehearsal accepts only a --test-version build, so a rehearsal
 * package is never mistaken for a release and a release is never verified as a rehearsal.
 */
export function manifestProblems(m, { version, commit, rehearsal = false }) {
  const p = [];
  if (!m || typeof m !== "object" || m.schema !== MANIFEST_SCHEMA) return ["not a CodeParley release manifest"];
  const top = ["schema", "version", "commit", "signature", "dirty", "testBuild", "releaseCandidate", "signed", "artifacts"];
  for (const k of Object.keys(m)) if (!top.includes(k)) p.push(`the manifest has an unexpected field ${k}`);
  if (m.version !== version) p.push(`the manifest is for version ${m.version}, not ${version}`);
  if (m.commit !== commit) p.push(`the manifest names commit ${m.commit}, not ${commit}`);
  if (m.signature !== "verified") p.push(`the manifest says the commit signature was ${m.signature}`);
  if (m.dirty !== false) p.push("the manifest says the build tree had changes");
  if (m.signed !== false) p.push("the manifest's signed field is not false (the signature is the separate .asc)");
  if (rehearsal) {
    if (m.testBuild !== true || m.releaseCandidate !== false) p.push("a rehearsal needs a --test-version build (testBuild, not a release candidate)");
  } else if (m.releaseCandidate !== true || "testBuild" in m) p.push("the manifest is not a release candidate");
  if (!Array.isArray(m.artifacts)) return [...p, "the manifest lists no artifacts"];
  const names = m.artifacts.map((a) => a?.name);
  if (canonical(names) !== canonical(ARTIFACTS.map((a) => a.name))) p.push(`the manifest lists ${names.join(", ")}, not exactly ${ARTIFACTS.map((a) => a.name).join(", ")}`);
  const files = new Set();
  let toolchain = null;
  let builtAt = null;
  for (const a of m.artifacts) {
    const at = a?.name ?? "?";
    for (const k of Object.keys(a ?? {})) if (!["name", "file", "size", "sha256", "buildId"].includes(k)) p.push(`${at}: unexpected field ${k}`);
    if (!SAFE_NAME.test(a?.file ?? "") || a.file.includes("..")) p.push(`${at}: the file name ${JSON.stringify(a?.file)} is not a plain file name`);
    else if (files.has(a.file) || a.file === MANIFEST || Object.values(PACKAGE_FILES).flat().includes(a.file)) p.push(`${at}: the file name ${a.file} is used twice`);
    else files.add(a.file);
    if (!Number.isInteger(a?.size) || a.size <= 0) p.push(`${at}: size must be a positive integer`);
    if (!HEX64.test(a?.sha256 ?? "")) p.push(`${at}: sha256 must be 64 lower-case hex digits`);
    const b = a?.buildId ?? {};
    const allowed = ["schema", "artifact", "version", "commit", "signature", "dirty", "testBuild", "releaseCandidate", "toolchain", "builtAt", ...(at.startsWith("engine-runtime-") ? ["node"] : [])];
    for (const k of Object.keys(b)) if (!allowed.includes(k)) p.push(`${at}: BUILD-ID has an unexpected field ${k}`);
    if (b.schema !== BUILD_ID_SCHEMA) p.push(`${at}: BUILD-ID schema ${b.schema}`);
    if (b.artifact !== a?.name) p.push(`${at}: BUILD-ID names the artifact ${b.artifact}`);
    if (b.version !== m.version || b.commit !== m.commit) p.push(`${at}: BUILD-ID names ${b.version} at ${b.commit}, not the manifest's version and commit`);
    if (b.signature !== m.signature || b.dirty !== m.dirty || b.releaseCandidate !== m.releaseCandidate || Boolean(b.testBuild) !== Boolean(m.testBuild)) p.push(`${at}: BUILD-ID's signature, dirty, testBuild or releaseCandidate differs from the manifest`);
    if (at.startsWith("engine-runtime-") && !/^v\d+\.\d+\.\d+$/.test(b.node ?? "")) p.push(`${at}: BUILD-ID names no bundled Node.js version`);
    const tc = canonical(b.toolchain ?? null);
    if (!b.toolchain || ["dotnetSdk", "node", "npm"].some((k) => typeof b.toolchain[k] !== "string" || !b.toolchain[k])) p.push(`${at}: BUILD-ID has no complete toolchain`);
    else if (toolchain === null) toolchain = tc;
    else if (tc !== toolchain) p.push(`${at}: BUILD-ID toolchain ${tc} differs from the other artifacts' ${toolchain}`);
    if (typeof b.builtAt !== "string" || Number.isNaN(Date.parse(b.builtAt))) p.push(`${at}: BUILD-ID has no build time`);
    else if (builtAt === null) builtAt = b.builtAt;
    else if (b.builtAt !== builtAt) p.push(`${at}: BUILD-ID build time ${b.builtAt} differs from the other artifacts' ${builtAt}`);
  }
  return p;
}

/** The entries of a signing package that the workflow does not know: everything must be a known regular file. */
export function inventoryProblems(dir, manifest, { allowed = Object.values(PACKAGE_FILES).flat() } = {}) {
  const known = new Set([MANIFEST, ...allowed, ...manifest.artifacts.flatMap((a) => [a.file, sidecarOf(a.file)]).filter(Boolean)]);
  const p = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (!known.has(e.name)) p.push(`unexpected entry ${e.name} in ${dir}`);
    else if (!e.isFile() || lstatSync(join(dir, e.name)).isSymbolicLink()) p.push(`${e.name} is not a regular file`);
  }
  return p;
}

/** Each artifact's size and SHA-256, recomputed (A-1), and the BUILD-ID it carries inside or beside it (A-2). */
export function artifactProblems(dir, manifest) {
  const p = [];
  for (const a of manifest.artifacts) {
    const path = join(dir, a.file);
    if (!existsSync(path)) { p.push(`${a.file} is missing`); continue; }
    const data = readFileSync(path);
    if (data.length !== a.size) p.push(`${a.file} is ${data.length} bytes, the manifest says ${a.size}`);
    const h = sha256(data);
    if (h !== a.sha256) p.push(`${a.file} has SHA-256 ${h}, the manifest says ${a.sha256}`);
    let carried;
    const side = sidecarOf(a.file);
    try {
      if (side) carried = JSON.parse(readFileSync(join(dir, side), "utf8"));
      else {
        const ids = readTarGz(data, { data: true }).filter((e) => e.type === "file" && e.path.replace(/^\.\//, "") === "BUILD-ID");
        if (ids.length !== 1) { p.push(`${a.file} carries ${ids.length} BUILD-ID files, not one`); continue; }
        carried = JSON.parse(ids[0].data.toString("utf8"));
      }
    } catch (e) {
      p.push(`${a.file}: its BUILD-ID ${side ? `(${side}) ` : ""}cannot be read: ${e instanceof Error ? e.message : String(e)}`);
      continue;
    }
    if (canonical(carried) !== canonical(a.buildId)) p.push(`${a.file}: the BUILD-ID it carries differs from the manifest's`);
  }
  return p;
}

/** The checks of a whole package, in order; reading the manifest is the first. Returns { manifest, problems }. */
export function packageCheck(dir, { version, commit, manifestSha256, rehearsal = false, allowed } = {}) {
  const path = join(dir, MANIFEST);
  if (!existsSync(path)) return { manifest: null, problems: [`${MANIFEST} is missing from ${dir}`] };
  const bytes = readFileSync(path);
  const problems = [];
  const digest = sha256(bytes);
  if (digest !== manifestSha256) problems.push(`${MANIFEST} has SHA-256 ${digest}, not the accepted ${manifestSha256}`);
  let manifest;
  try { manifest = JSON.parse(bytes.toString("utf8")); } catch { return { manifest: null, problems: [...problems, `${MANIFEST} is not JSON`] }; }
  problems.push(...manifestProblems(manifest, { version, commit, rehearsal }));
  if (problems.length === 0 || Array.isArray(manifest?.artifacts)) {
    try {
      problems.push(...inventoryProblems(dir, manifest, allowed ? { allowed } : {}));
      problems.push(...artifactProblems(dir, manifest));
    } catch (e) {
      problems.push(`the package cannot be read: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { manifest, problems, manifestSha256: digest, manifestSize: bytes.length };
}

// ---- OpenPGP, with a keyring of its own -----------------------------------------------------------------------------

/** The default GnuPG: GnuPG for Windows (Gpg4win) by its full path, or `gpg` elsewhere. */
export function defaultGpg() {
  const win = "C:\\Program Files\\GnuPG\\bin\\gpg.exe";
  return process.platform === "win32" && existsSync(win) ? win : "gpg";
}

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: opts.encoding ?? "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 64 * 1024 * 1024, ...opts });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error?.message ?? null };
}

/**
 * Run `fn(gpgArgs)` with a fresh GnuPG home holding only `keys` (armored public keys), with smart cards disabled: it
 * never sees the owner's keyring, agent or YubiKey, so verification does not depend on the machine's trust settings.
 */
export function withKeyring(gpg, keys, fn) {
  const home = mkdtempSync(join(tmpdir(), "cp-relkeys-"));
  try {
    writeFileSync(join(home, "gpg-agent.conf"), "disable-scdaemon\n");
    // An existing common.conf keeps GnuPG 2.4+ from switching a new home to keyboxd (one daemon fewer to stop).
    writeFileSync(join(home, "common.conf"), "");
    const base = ["--homedir", home, "--batch", "--no-tty"];
    keys.forEach((k, i) => {
      const f = join(home, `import-${i}.asc`);
      writeFileSync(f, k);
      const r = sh(gpg, ["--homedir", home, "--batch", "--no-tty", "--import", f]);
      if (r.status !== 0) throw new Error(`gpg could not import key ${i} (${r.error ?? r.stderr.trim().split("\n")[0]})`);
    });
    return fn({ gpg, home, base, env: { ...process.env, GNUPGHOME: home } });
  } finally {
    const gpgconf = gpg.includes("/") || gpg.includes("\\") ? join(dirname(gpg), `gpgconf${process.platform === "win32" ? ".exe" : ""}`) : "gpgconf";
    sh(gpgconf, ["--homedir", home, "--kill", "all"]);
    rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

/** The keys of a keyring: [{ primary, subkeys: [{ fpr, capabilities }] }]. */
export function listKeys(kr) {
  const r = sh(kr.gpg, [...kr.base, "--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys"]);
  const keys = [];
  // An "fpr" record gives the fingerprint of the "pub" or "sub" record just before it.
  let owner = null;
  for (const line of r.stdout.split(/\r?\n/)) {
    const f = line.split(":");
    if (f[0] === "pub") {
      owner = { primary: null, capabilities: f[11] ?? "", subkeys: [] };
      keys.push(owner);
    } else if (f[0] === "sub" && keys.length) {
      owner = { fpr: null, capabilities: f[11] ?? "" };
      keys.at(-1).subkeys.push(owner);
    } else if (f[0] === "fpr" && FPR.test(f[9] ?? "") && owner) {
      if ("primary" in owner && owner.primary === null) owner.primary = f[9];
      else if ("fpr" in owner && owner.fpr === null) owner.fpr = f[9];
      owner = null;
    }
  }
  return keys;
}

/** The release key file holds exactly the pinned primary key, with the pinned signing subkey. */
export function releaseKeyProblems(keys, pins) {
  if (keys.length !== 1) return [`the release key file holds ${keys.length} keys, not one`];
  const p = [];
  if (keys[0].primary !== pins.primary) p.push(`the release key file's primary key is ${keys[0].primary}, not the pinned ${pins.primary}`);
  const sub = keys[0].subkeys.find((s) => s.fpr === pins.subkey);
  if (!sub) p.push(`the release key file has no subkey ${pins.subkey}`);
  else if (!sub.capabilities.includes("s")) p.push(`the subkey ${pins.subkey} cannot sign`);
  return p;
}

/**
 * gpg --status-fd output of verifying ONE detached signature: exactly one signature, good, valid, made by the pinned
 * signing subkey of the pinned primary key, a signature over a binary document (class 00), and nothing expired,
 * revoked or bad. A good signature by any other key fails.
 */
export function signatureStatusProblems(status, exitCode, pins) {
  const lines = status.split(/\r?\n/).filter((l) => l.startsWith("[GNUPG:] ")).map((l) => l.slice(9).trim().split(" "));
  const count = (k) => lines.filter((f) => f[0] === k).length;
  const p = [];
  if (exitCode !== 0) p.push(`gpg --verify exited with ${exitCode}`);
  if (count("NEWSIG") !== 1) p.push(`the file holds ${count("NEWSIG")} signatures, not one`);
  for (const bad of ["BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"]) if (count(bad)) p.push(`gpg reports ${bad}`);
  if (count("GOODSIG") !== 1) p.push("gpg reports no good signature");
  const valid = lines.filter((f) => f[0] === "VALIDSIG");
  if (valid.length !== 1) p.push(`gpg reports ${valid.length} valid signatures, not one`);
  else {
    const v = valid[0];
    if (v[1] !== pins.subkey) p.push(`the signature was made by ${v[1]}, not the release signing subkey ${pins.subkey}`);
    if (v.at(-1) !== pins.primary) p.push(`the signing key's primary key is ${v.at(-1)}, not the release key ${pins.primary}`);
    if (v[9] !== "00") p.push(`the signature class is ${v[9]}, not a signature over a document (00)`);
  }
  return p;
}

/** Verify a detached signature with only the release key: { problems, status, keys }. */
export function verifyDetached({ gpg, keyArmored, pins, signatureFile, dataFile }) {
  return withKeyring(gpg, [keyArmored], (kr) => {
    const keys = listKeys(kr);
    const problems = releaseKeyProblems(keys, pins);
    const sig = readFileSync(signatureFile, "utf8");
    if (!/^-----BEGIN PGP SIGNATURE-----\r?\n[\s\S]*\r?\n-----END PGP SIGNATURE-----\r?\n?$/.test(sig)) problems.push(`${basename(signatureFile)} is not one ASCII-armored detached signature`);
    const r = sh(gpg, [...kr.base, "--status-fd", "1", "--verify", signatureFile, dataFile]);
    problems.push(...signatureStatusProblems(r.stdout, r.status, pins));
    return { problems, status: r.stdout.trim(), keys };
  });
}

// ---- git: the source commit and the release tag ---------------------------------------------------------------------

export const git = (repo, args, opts = {}) => sh("git", ["-C", repo, ...args], opts);

/** A file at a commit, from git's object store (not the working tree): the trusted copy of a pinned key. */
export function fileAt(repo, commit, path) {
  const r = git(repo, ["show", `${commit}:${path}`]);
  if (r.status !== 0) throw new Error(`${path} is not in commit ${commit} (${r.stderr.trim().split("\n")[0]})`);
  return r.stdout;
}

/**
 * The release source commit: it exists, its package.json carries the version (for a rehearsal's --test-version build,
 * the version before its pre-release suffix), and it is signed by the owner's COMMIT key (its own
 * .github/ci/commit-signing-key.asc), which shares no key with the release key.
 */
export function commitProblems({ repo, commit, version, gpg, pins, rehearsal = false }) {
  const p = [];
  if (git(repo, ["cat-file", "-e", `${commit}^{commit}`]).status !== 0) return [`commit ${commit} is not in ${repo}`];
  try {
    const v = JSON.parse(fileAt(repo, commit, "package.json")).version;
    const want = rehearsal ? version.replace(/-.*$/, "") : version;
    if (v !== want) p.push(`package.json at ${commit} is version ${v}, not ${want}`);
  } catch (e) {
    p.push(e instanceof Error ? e.message : String(e));
  }
  let commitKey;
  try { commitKey = fileAt(repo, commit, COMMIT_KEY_FILE); } catch (e) { return [...p, e instanceof Error ? e.message : String(e)]; }
  withKeyring(gpg, [commitKey], (kr) => {
    const keys = listKeys(kr);
    const fprs = keys.flatMap((k) => [k.primary, ...k.subkeys.map((s) => s.fpr)]);
    if (fprs.includes(pins.primary) || fprs.includes(pins.subkey)) p.push("the commit-signing key file contains the release key: the two identities must stay separate");
    const owner = keys[0]?.primary;
    if (!owner) { p.push(`${COMMIT_KEY_FILE} at ${commit} holds no key`); return; }
    if (sh(kr.gpg, [...kr.base, "--import-ownertrust"], { input: `${owner}:6:\n` }).status !== 0) p.push("the commit key cannot be trusted in the temporary keyring");
    const r = git(repo, ["-c", `gpg.program=${gpg}`, "log", "-1", "--format=%G?%n%GF%n%GP", commit], { env: kr.env });
    const [status = "", signer = "", primary = ""] = r.stdout.trim().split("\n");
    if (status !== "G" || !(fprs.includes(signer) || primary === owner)) p.push(`commit ${commit} is not signed by the owner's commit key (signature ${status || "?"} by ${signer || "no key"})`);
  });
  return p;
}

/** A raw annotated tag object: { object, type, tag, tagger, message, payload, signature } or null. */
export function parseTag(raw) {
  const blank = raw.indexOf("\n\n");
  if (blank < 0) return null;
  const headers = Object.fromEntries(raw.slice(0, blank).split("\n").map((l) => [l.slice(0, l.indexOf(" ")), l.slice(l.indexOf(" ") + 1)]));
  const at = raw.indexOf("-----BEGIN PGP SIGNATURE-----");
  return {
    object: headers.object,
    type: headers.type,
    tag: headers.tag,
    tagger: headers.tagger,
    message: at < 0 ? raw.slice(blank + 2) : raw.slice(blank + 2, at),
    payload: at < 0 ? raw : raw.slice(0, at),
    signature: at < 0 ? null : raw.slice(at),
  };
}

/** The release tag: annotated, named v<version>, on exactly the source commit, with the exact message, signed by
 *  the release key. Returns { problems, tagObject, tagger, status }. */
export function tagProblems({ repo, version, commit, manifestSha256, gpg, pins, keyArmored }) {
  const name = tagName(version);
  const ref = `refs/tags/${name}`;
  const p = [];
  const id = git(repo, ["rev-parse", "--verify", "--quiet", ref]).stdout.trim();
  if (!id) return { problems: [`there is no tag ${name} in ${repo}`] };
  if (git(repo, ["cat-file", "-t", id]).stdout.trim() !== "tag") return { problems: [`${name} is a lightweight tag, not a signed annotated tag`], tagObject: id };
  const t = parseTag(git(repo, ["cat-file", "tag", id]).stdout);
  if (!t) return { problems: [`${name} cannot be read as a tag object`], tagObject: id };
  if (t.object !== commit || t.type !== "commit") p.push(`${name} points to ${t.type} ${t.object}, not commit ${commit}`);
  const peeled = git(repo, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]).stdout.trim();
  if (peeled !== commit) p.push(`${name} resolves to ${peeled || "nothing"}, not ${commit}`);
  if (t.tag !== name) p.push(`the tag object is named ${t.tag}, not ${name}`);
  if (t.message !== tagMessage(version, manifestSha256)) p.push(`the tag message is not exactly the one in TAG-MESSAGE.txt (it must name the manifest SHA-256 ${manifestSha256})`);
  if (!t.signature) return { problems: [...p, `${name} is not signed`], tagObject: id, tagger: t.tagger };
  const dir = mkdtempSync(join(tmpdir(), "cp-reltag-"));
  try {
    writeFileSync(join(dir, "payload"), t.payload);
    writeFileSync(join(dir, "payload.asc"), t.signature);
    const v = verifyDetached({ gpg, keyArmored, pins, signatureFile: join(dir, "payload.asc"), dataFile: join(dir, "payload") });
    return { problems: [...p, ...v.problems], tagObject: id, tagger: t.tagger, status: v.status };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---- GitHub: the uploaded release -----------------------------------------------------------------------------------

/**
 * A GitHub release (the REST object) against the payload: the tag, draft or published as expected, and exactly the
 * payload's files, each with its size and SHA-256 digest. `files` is [{ name, size, sha256 }].
 */
export function remoteReleaseProblems(release, { tag, files, published }) {
  if (!release) return [`there is no release for ${tag}`];
  const p = [];
  if (release.tag_name !== tag) p.push(`the release is for ${release.tag_name}, not ${tag}`);
  if (published ? release.draft !== false : release.draft !== true) p.push(published ? "the release is still a draft" : "the release is not a draft: verify before publishing");
  if (release.prerelease) p.push("the release is marked as a pre-release");
  const assets = release.assets ?? [];
  const names = assets.map((a) => a.name).sort();
  if (canonical(names) !== canonical(files.map((f) => f.name).sort())) p.push(`the release has ${names.join(", ") || "no files"}; the payload is ${files.map((f) => f.name).join(", ")}`);
  for (const f of files) {
    const a = assets.find((x) => x.name === f.name);
    if (!a) continue;
    if (a.state !== "uploaded") p.push(`${f.name} is ${a.state}, not uploaded`);
    if (a.size !== f.size) p.push(`${f.name} is ${a.size} bytes on GitHub, ${f.size} in the payload`);
    if (a.digest !== `sha256:${f.sha256}`) p.push(`${f.name} has digest ${a.digest ?? "none"} on GitHub, the payload has sha256:${f.sha256}`);
  }
  return p;
}
