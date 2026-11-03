#!/usr/bin/env node
// Phase 6 Increment 1 (contract §4.2 step 4): CI verifies its own input. The checked-out HEAD must be the expected
// commit, and its signature must verify against the owner's PUBLIC commit-signing key committed in this repository
// (.github/ci/commit-signing-key.asc), in a keyring of its own that holds nothing else. A mismatch or a bad, missing
// or foreign signature exits 1.
//
//   node scripts/ci/verify-commit-identity.mjs [--expect <sha>] [--requested <sha>] [--allow-github-merge]
//        [--gpg <gpg executable>]
//
// --requested (a manual run's expected_sha): when not empty, HEAD must also be that commit; it is an assertion on the
// commit CI selected, never a selection. Both checks come before anything about the signature, which is always checked.
//
// --allow-github-merge (pushes to main only): a merge GitHub made on the web carries GitHub's signature, not the
// owner's. It is accepted when HEAD is a merge committed by GitHub whose merged head (second parent) verifies against
// the owner's key; GitHub's own signature is not verified here, and the output says so.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const expect = opt("expect")?.toLowerCase();
const requested = opt("requested")?.toLowerCase();
const allowMerge = args.includes("--allow-github-merge");
const gpg = opt("gpg") ?? "gpg";
const keyFile = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", ".github", "ci", "commit-signing-key.asc");
const GITHUB_COMMITTER = "GitHub <noreply@github.com>";
const FPR = /^[0-9A-F]{40}$/;

const home = mkdtempSync(join(tmpdir(), "cp-identity-"));
const env = { ...process.env, GNUPGHOME: home };
const sh = (cmd, argv, input) => {
  const r = spawnSync(cmd, argv, { encoding: "utf8", env, input, windowsHide: true, timeout: 120_000 });
  return { status: r.status, out: (r.stdout ?? "").trim(), err: (r.stderr ?? "").trim() };
};
const git = (...a) => sh("git", ["-c", `gpg.program=${gpg}`, ...a]);
const fail = (msg) => {
  console.error(`commit identity: FAIL: ${msg}`);
  rmSync(home, { recursive: true, force: true });
  process.exit(1);
};

const head = git("rev-parse", "HEAD").out;
console.log(`HEAD ${head}`);
if (!/^[0-9a-f]{40}$/.test(head)) fail("HEAD is not a commit");
if (expect !== undefined && head !== expect) fail(`HEAD ${head} is not the expected commit ${expect}`);
if (requested && head !== requested) fail(`HEAD ${head} is not the requested commit ${requested}`);

// The owner's key, alone in a fresh keyring, trusted there so that a good signature reads G (not U).
const shown = sh(gpg, ["--batch", "--with-colons", "--import-options", "show-only", "--import", keyFile]);
// --with-colons: an "fpr" record carries the fingerprint in its tenth field.
const fprs = shown.out.split("\n").map((l) => l.split(":")).filter((f) => f[0] === "fpr" && FPR.test(f[9] ?? "")).map((f) => f[9]);
const primary = fprs[0];
if (!primary) fail(`no key in ${keyFile} (${shown.err.split("\n")[0] ?? ""})`);
if (sh(gpg, ["--batch", "--import", keyFile]).status !== 0) fail("the owner's public key does not import");
if (sh(gpg, ["--batch", "--import-ownertrust"], `${primary}:6:\n`).status !== 0) fail("the owner's key cannot be trusted in the temporary keyring");

/** Whether `rev` carries a good signature by the owner's key (primary or subkey). */
function ownerSigned(rev) {
  const [status = "", signer = "", primaryOfSigner = ""] = git("log", "-1", "--format=%G?%n%GF%n%GP", rev).out.split("\n");
  const ok = status === "G" && (fprs.includes(signer) || primaryOfSigner === primary);
  return { ok, detail: `signature ${status || "?"} by ${signer || "no key"}` };
}

const own = ownerSigned("HEAD");
if (own.ok) {
  console.log(`commit identity: OK: ${head} is the expected commit, signed by the owner's key ${primary} (${own.detail})`);
} else if (allowMerge) {
  const parents = git("rev-list", "--parents", "-n", "1", "HEAD").out.split(" ").slice(1);
  const committer = git("log", "-1", "--format=%cn <%ce>", "HEAD").out;
  if (parents.length < 2 || committer !== GITHUB_COMMITTER) fail(`HEAD is not owner-signed (${own.detail}) and is not a merge committed by GitHub (committer ${committer}, ${parents.length} parent(s))`);
  const merged = ownerSigned(parents[1]);
  if (!merged.ok) fail(`HEAD is a GitHub merge, but its merged head ${parents[1]} is not owner-signed (${merged.detail})`);
  console.log(`commit identity: OK: ${head} is a merge committed by GitHub (its signature is GitHub's, not verified here); the merged head ${parents[1]} is signed by the owner's key ${primary}`);
} else {
  fail(`${head} is not signed by the owner's key ${primary} (${own.detail})`);
}
rmSync(home, { recursive: true, force: true });
