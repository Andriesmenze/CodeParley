// Step 4: the release-signing workflow (scripts/package/prepare-signing.mjs, verify-release.mjs and
// lib/release-verify.mjs), end to end with DISPOSABLE keys made for the test in a GnuPG home of its own, with smart
// cards disabled: never the release key, never a YubiKey. A fixture repository carries the files the real one pins (the
// commit key in .github/ci/, the release key in docs/), so the scripts run their production checks with only the pinned
// fingerprints replaced. Platform-independent; skipped where no GnuPG is installed.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { appendFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { commitAll, git, initRepo, tempDir, writeFiles } from "./helpers/git-fixture.js";

interface Pins { primary: string; subkey: string }
type Log = (s: string) => void;
interface Release { tag_name: string; draft: boolean; prerelease: boolean; id: number; html_url: string; assets: { name: string; size: number; digest: string; state: string }[] }
const lib = (await import(new URL("../scripts/package/lib/release-verify.mjs", import.meta.url).href)) as {
  defaultGpg(): string; sha256(b: Buffer | string): string; tagMessage(v: string, d: string): string;
};
const manifestLib = (await import(new URL("../scripts/package/lib/release-manifest.mjs", import.meta.url).href)) as {
  ARTIFACTS: { name: string }[]; buildId(i: Record<string, unknown>): Record<string, unknown>; buildManifest(i: Record<string, unknown>): Record<string, unknown> & { artifacts: { file: string }[] };
};
const { prepare } = (await import(new URL("../scripts/package/prepare-signing.mjs", import.meta.url).href)) as { prepare(argv: string[], deps: { pins: Pins; repo: string; log: Log }): number };
const { verify } = (await import(new URL("../scripts/package/verify-release.mjs", import.meta.url).href)) as {
  verify(argv: string[], deps: { pins: Pins; repoPin?: { name: string; id: number }; github?: (p: string) => unknown; log: Log }): number;
};

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const gpg = lib.defaultGpg();
const haveGpg = spawnSync(gpg, ["--version"], { windowsHide: true }).status === 0;
const VERSION = "1.0.1";
const REHEARSAL = "1.0.1-rehearsal.1";

let base = "";
let home = "";
let repo = "";
let commit = "";
let other = "";
const keys = { commit: "", release: "", releaseSub: "", releaseSub2: "", stranger: "", strangerSub: "" };
const pub: Record<string, string> = {};

const g = (args: string[], input?: string) => {
  const r = spawnSync(gpg, ["--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", ...args], { encoding: "utf8", windowsHide: true, input, timeout: 120_000 });
  if (r.status !== 0) throw new Error(`gpg ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
};
const fprOf = (uid: string, which: "pub" | "sub") => {
  const lines = g(["--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys", uid]).split(/\r?\n/);
  const at = lines.findIndex((l) => l.startsWith(`${which}:`));
  return lines.slice(at).find((l) => l.startsWith("fpr:"))!.split(":")[9]!;
};
const sign = (key: string, file: string, out: string) => g(["--yes", "--armor", "--detach-sign", "--local-user", `${key}!`, "--output", out, file]);
const gitEnv = () => ({ GNUPGHOME: home });
const gpgProgram = () => gpg.replaceAll("\\", "/");
const pins = (): Pins => ({ primary: keys.release, subkey: keys.releaseSub });
const quiet = () => {
  const out: string[] = [];
  return { log: (s: string) => void out.push(s), text: () => out.join("") };
};

/** A gzip-compressed ustar archive of `files`, like stage-release's `tar -czf … -C dir .`. */
function tarGz(files: Record<string, string>): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(name, 0, 100);
    h.write("0000644\0", 100);
    h.write("0000000\0", 108);
    h.write("0000000\0", 116);
    h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    h.write("00000000000\0", 136);
    h.write("        ", 148);
    h.write("0", 156);
    h.write("ustar\0", 257);
    h.write("00", 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

/** A staged release as stage-release.mjs writes it; `tweak` changes a BUILD-ID before anything is written. */
function stage(dir: string, o: { version?: string; commit?: string; testBuild?: boolean; tweak?: (name: string, id: Record<string, unknown>) => void; insideId?: (name: string, id: Record<string, unknown>) => void } = {}): string {
  const version = o.version ?? VERSION;
  const at = o.commit ?? commit;
  mkdirSync(dir, { recursive: true });
  const entries = manifestLib.ARTIFACTS.map(({ name }) => {
    const id = manifestLib.buildId({ artifact: name, version, commit: at, signature: "verified", dirty: false, testBuild: o.testBuild ?? false, toolchain: { dotnetSdk: "10.0.403", node: "v24.11.0", npm: "11.6.1" }, builtAt: "2026-11-03T12:00:00.000Z" });
    if (name.startsWith("engine-runtime-")) id.node = "v24.21.0";
    o.tweak?.(name, id);
    const carried = JSON.parse(JSON.stringify(id)) as Record<string, unknown>;
    o.insideId?.(name, carried);
    const sidecar = name === "npm-tarball" || name.startsWith("installer-");
    const file = name === "npm-tarball" ? `code-parley-${version}.tgz` : name === "installer-windows" ? "codeparley-installer.ps1" : name === "installer-linux" ? "codeparley-installer.sh" : `${name}.tar.gz`;
    const data = sidecar ? Buffer.from(`${name} ${version}\n`) : tarGz({ "./BUILD-ID": `${JSON.stringify(carried, null, 2)}\n`, "./payload.txt": `${name}\n` });
    writeFileSync(join(dir, file), data);
    if (sidecar) writeFileSync(join(dir, `${file}.BUILD-ID`), `${JSON.stringify(carried, null, 2)}\n`);
    return { name, file, size: data.length, sha256: lib.sha256(data), buildId: id };
  });
  const m = manifestLib.buildManifest({ version, commit: at, signature: "verified", dirty: false, entries, testBuild: o.testBuild ?? false });
  const text = `${JSON.stringify(m, null, 2)}\n`;
  writeFileSync(join(dir, "release-manifest.json"), text);
  return lib.sha256(text);
}

const args = (dir: string, digest: string, o: { version?: string; commit?: string; rehearsal?: boolean } = {}) => [
  "--version", o.version ?? VERSION, "--commit", o.commit ?? commit, "--manifest-sha256", digest, "--gpg", gpg, ...(o.rehearsal ? ["--rehearsal"] : []),
  ...(dir ? ["--dir", dir] : []),
];
const runPrepare = (staged: string, out: string, digest: string, o: { version?: string; commit?: string; rehearsal?: boolean } = {}) => {
  const q = quiet();
  const code = prepare(["--staged", staged, "--out", out, ...args("", digest, o)], { pins: pins(), repo, log: q.log });
  return { code, out: q.text() };
};
const runVerify = (step: string, dir: string, digest: string, o: { version?: string; commit?: string; rehearsal?: boolean; github?: (p: string) => unknown; published?: boolean } = {}) => {
  const q = quiet();
  const code = verify([step, ...args(dir, digest, o), "--repo", repo, ...(o.published ? ["--published"] : [])], { pins: pins(), repoPin: { name: "example/CodeParley", id: 42 }, github: o.github ?? (() => { throw new Error("no network in this test"); }), log: q.log });
  return { code, out: q.text() };
};
/** A fresh signing package of a fresh staged release: { pkg, digest }. */
let n = 0;
function prepared(o: { rehearsal?: boolean } = {}) {
  const dir = join(base, `case-${++n}`);
  const staged = join(dir, "staged");
  const digest = o.rehearsal ? stage(staged, { version: REHEARSAL, testBuild: true }) : stage(staged);
  const pkg = join(dir, "pkg");
  const r = runPrepare(staged, pkg, digest, o.rehearsal ? { version: REHEARSAL, rehearsal: true } : {});
  if (r.code !== 0) throw new Error(r.out);
  return { pkg, digest, staged };
}
const tag = (name: string, target: string, message: string, key = keys.releaseSub) => {
  const msg = join(base, `tag-${++n}.txt`);
  writeFileSync(msg, message);
  git(repo, ["-c", `gpg.program=${gpgProgram()}`, "-c", `user.signingkey=${key}!`, "tag", "-s", name, target, "-F", msg], { env: gitEnv() });
};
const remove = (name: string) => git(repo, ["tag", "-d", name], { allowFail: true });

describe.skipIf(!haveGpg)("Step 4: release-signing workflow, with disposable keys", { timeout: 120_000 }, () => {
  beforeAll(async () => {
    base = await tempDir("cp-relsign-");
    home = join(base, "gnupg");
    mkdirSync(home);
    writeFileSync(join(home, "gpg-agent.conf"), "disable-scdaemon\nallow-loopback-pinentry\n");
    writeFileSync(join(home, "common.conf"), "");
    g(["--quick-gen-key", "Disposable Commit <commit@example.invalid>", "ed25519", "sign", "1d"]);
    g(["--quick-gen-key", "Disposable Release <release@example.invalid>", "ed25519", "cert", "1d"]);
    keys.release = fprOf("Disposable Release", "pub");
    g(["--quick-add-key", keys.release, "ed25519", "sign", "1d"]);
    g(["--quick-gen-key", "Disposable Stranger <stranger@example.invalid>", "ed25519", "cert", "1d"]);
    keys.stranger = fprOf("Disposable Stranger", "pub");
    g(["--quick-add-key", keys.stranger, "ed25519", "sign", "1d"]);
    keys.commit = fprOf("Disposable Commit", "pub");
    keys.releaseSub = fprOf("Disposable Release", "sub");
    // A second signing subkey of the same primary: a good signature by it is still not the pinned subkey's.
    g(["--quick-add-key", keys.release, "ed25519", "sign", "1d"]);
    const subs = g(["--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys", keys.release]).split(/\r?\n/).filter((l, i, all) => l.startsWith("fpr:") && all[i - 1]?.startsWith("sub:")).map((l) => l.split(":")[9]!);
    keys.releaseSub2 = subs.find((s) => s !== keys.releaseSub)!;
    keys.strangerSub = fprOf("Disposable Stranger", "sub");
    for (const k of ["commit", "release", "stranger"] as const) pub[k] = g(["--armor", "--export", keys[k]]);
    repo = await initRepo(join(base, "repo"));
    await writeFiles(repo, { "package.json": `${JSON.stringify({ name: "code-parley", version: VERSION })}\n`, ".github/ci/commit-signing-key.asc": pub.commit!, "docs/codeparley-release-key.asc": pub.release! });
    const signed = (msg: string) => {
      git(repo, ["add", "-A"]);
      git(repo, ["-c", `gpg.program=${gpgProgram()}`, "-c", `user.signingkey=${keys.commit}`, "commit", "-q", "-S", "--allow-empty", "-m", msg], { env: gitEnv() });
      return git(repo, ["rev-parse", "HEAD"]).stdout.trim();
    };
    commit = signed("release source");
    other = signed("a later commit");
  });

  afterAll(() => {
    const gpgconf = /[\\/]/.test(gpg) ? join(dirname(gpg), process.platform === "win32" ? "gpgconf.exe" : "gpgconf") : "gpgconf";
    if (home) spawnSync(gpgconf, ["--homedir", home, "--kill", "all"], { windowsHide: true });
    if (base) rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  describe("prepare-signing", () => {
    it("copies a staged release byte for byte into a package with the request and the exact tag message", () => {
      const { pkg, digest, staged } = prepared();
      for (const f of readdirSync(staged)) expect(readFileSync(join(pkg, f)).equals(readFileSync(join(staged, f)))).toBe(true);
      expect(readFileSync(join(pkg, "TAG-MESSAGE.txt"), "utf8")).toBe(lib.tagMessage(VERSION, digest));
      const req = JSON.parse(readFileSync(join(pkg, "signing-request.json"), "utf8")) as Record<string, unknown>;
      expect(req).toMatchObject({ version: VERSION, commit, tag: "v1.0.1", rehearsal: false, manifest: { sha256: digest } });
      const md = readFileSync(join(pkg, "SIGNING-REQUEST.md"), "utf8");
      expect(md).toContain(digest);
      expect(md).toContain(`--local-user 'EFD68E181281081CBFA601EC35208A9E3684E6C9!'`);
      expect(md).not.toMatch(/REHEARSAL/);
      expect(existsSync(join(pkg, "release-manifest.json.asc"))).toBe(false);
    });

    it("is idempotent: a repeat, after an interruption or after signing, leaves the package unchanged", () => {
      const { pkg, digest, staged } = prepared();
      const before = readFileSync(join(pkg, "signing-request.json"), "utf8");
      mkdirSync(`${pkg}.partial-1-2`);
      writeFileSync(join(`${pkg}.partial-1-2`, "junk"), "x");
      const again = runPrepare(staged, pkg, digest);
      expect(again).toMatchObject({ code: 0 });
      expect(again.out).toContain("already prepared, unchanged");
      expect(existsSync(`${pkg}.partial-1-2`)).toBe(false);
      sign(keys.releaseSub, join(pkg, "release-manifest.json"), join(pkg, "release-manifest.json.asc"));
      expect(runPrepare(staged, pkg, digest).out).toContain("it holds release-manifest.json.asc");
      expect(readFileSync(join(pkg, "signing-request.json"), "utf8")).toBe(before);
    });

    it("never overwrites a package that differs, and leaves it as it was", () => {
      const { pkg, digest, staged } = prepared();
      appendFileSync(join(pkg, "codeparley-installer.sh"), "#");
      const r = runPrepare(staged, pkg, digest);
      expect(r.code).toBe(1);
      expect(r.out).toContain("exists and is not this package");
      expect(readFileSync(join(pkg, "codeparley-installer.sh"), "utf8").endsWith("#")).toBe(true);
    });

    it("fails closed on the digest, the commit, the version, the package location and unexpected content", () => {
      const dir = join(base, `refuse-${++n}`);
      const staged = join(dir, "staged");
      const digest = stage(staged);
      const out = join(dir, "pkg");
      expect(runPrepare(staged, out, "0".repeat(64)).out).toContain("not the accepted");
      expect(runPrepare(staged, out, digest, { commit: other }).out).toContain(`names commit ${commit}, not ${other}`);
      expect(runPrepare(staged, out, digest, { version: "1.0.2" }).out).toMatch(/package\.json at .* is version 1\.0\.1, not 1\.0\.2/);
      expect(runPrepare(staged, join(repo, "pkg"), digest).out).toContain("is inside the repository");
      expect(runPrepare(staged, out, digest, { rehearsal: true }).out).toContain("a rehearsal needs a --test-version build");
      writeFileSync(join(staged, "extra.txt"), "x");
      expect(runPrepare(staged, out, digest).out).toContain("unexpected entry extra.txt");
      expect(existsSync(out)).toBe(false);
    });

    it("fails closed on an altered artifact and on inconsistent BUILD-IDs", () => {
      const dir = join(base, `ids-${++n}`);
      const cases: [string, Parameters<typeof stage>[1], RegExp][] = [
        ["toolchain", { tweak: (name, id) => { if (name === "plugin-linux") (id.toolchain as Record<string, string>).dotnetSdk = "10.0.201"; } }, /plugin-linux: BUILD-ID toolchain .* differs/],
        ["built", { tweak: (name, id) => { if (name === "custodian-linux-x64") id.builtAt = "2026-11-03T13:00:00.000Z"; } }, /custodian-linux-x64: BUILD-ID build time .* differs/],
        ["inside", { insideId: (name, id) => { if (name === "custodian-windows-x64") id.commit = "b".repeat(40); } }, /custodian-windows-x64\.tar\.gz: the BUILD-ID it carries differs/],
        ["sidecar", { insideId: (name, id) => { if (name === "installer-linux") id.version = "9.9.9"; } }, /codeparley-installer\.sh: the BUILD-ID it carries differs/],
        ["candidate", { tweak: (name, id) => { if (name === "npm-tarball") id.releaseCandidate = false; } }, /npm-tarball: BUILD-ID's signature, dirty, testBuild or releaseCandidate differs/],
      ];
      for (const [label, o, want] of cases) {
        const staged = join(dir, label);
        const digest = stage(staged, o);
        expect(runPrepare(staged, join(dir, `${label}-pkg`), digest).out).toMatch(want);
      }
      const staged = join(dir, "altered");
      const digest = stage(staged);
      appendFileSync(join(staged, "engine-runtime-linux-x64.tar.gz"), "x");
      expect(runPrepare(staged, join(dir, "altered-pkg"), digest).out).toMatch(/engine-runtime-linux-x64\.tar\.gz is \d+ bytes.*\n.*has SHA-256/);
    });
  });

  describe("verify-release", () => {
    it("package: passes on the prepared package; fails on an altered artifact, an unexpected file or another pinned key", () => {
      const { pkg, digest } = prepared();
      expect(runVerify("package", pkg, digest)).toMatchObject({ code: 0 });
      expect(JSON.parse(readFileSync(join(pkg, "verified-package.json"), "utf8"))).toMatchObject({ result: "PASS", step: "package" });
      const q = quiet();
      expect(verify(["package", ...args(pkg, digest), "--repo", repo], { pins: { primary: keys.stranger, subkey: keys.strangerSub }, log: q.log })).toBe(1);
      expect(q.text()).toContain(`the release key file's primary key is ${keys.release}, not the pinned ${keys.stranger}`);
      expect(JSON.parse(readFileSync(join(pkg, "verified-package.json"), "utf8"))).toMatchObject({ result: "FAIL" }); // a failure is recorded too
      const copy = `${pkg}-altered`;
      cpSync(pkg, copy, { recursive: true });
      appendFileSync(join(copy, "plugin-windows.tar.gz"), "x");
      expect(runVerify("package", copy, digest).out).toContain("plugin-windows.tar.gz has SHA-256");
      const extra = `${pkg}-extra`;
      cpSync(pkg, extra, { recursive: true });
      writeFileSync(join(extra, "notes.txt"), "x");
      expect(runVerify("package", extra, digest).out).toContain("unexpected entry notes.txt");
    });

    it("signature: passes for the release subkey; fails on an altered manifest, a stranger's key and the commit key", () => {
      const { pkg, digest } = prepared();
      expect(runVerify("signature", pkg, digest).out).toContain("the owner has not signed the manifest");
      const manifest = join(pkg, "release-manifest.json");
      sign(keys.releaseSub, manifest, join(pkg, "release-manifest.json.asc"));
      const ok = runVerify("signature", pkg, digest);
      expect(ok).toMatchObject({ code: 0 });
      expect(ok.out).toContain(`signing subkey ${keys.releaseSub}`);

      // The manifest changed after signing (and the command names the changed manifest's digest): a bad signature.
      const altered = `${pkg}-altered`;
      cpSync(pkg, altered, { recursive: true });
      const text = readFileSync(join(altered, "release-manifest.json"), "utf8").replace('"signed": false', '"signed": false ');
      writeFileSync(join(altered, "release-manifest.json"), text);
      const req = JSON.parse(readFileSync(join(altered, "signing-request.json"), "utf8")) as { manifest: { sha256: string } };
      req.manifest.sha256 = lib.sha256(text);
      writeFileSync(join(altered, "signing-request.json"), JSON.stringify(req));
      const changed = runVerify("signature", altered, lib.sha256(text));
      expect(changed.code).toBe(1);
      expect(changed.out).toMatch(/BADSIG|no good signature/);

      const others: [string, string, RegExp][] = [
        ["stranger", keys.strangerSub, /NO_PUBKEY|not the release signing subkey/],
        ["commit", keys.commit, /NO_PUBKEY|not the release signing subkey/],
        ["other subkey", keys.releaseSub2, new RegExp(`signature was made by ${keys.releaseSub2}, not the release signing subkey`)],
      ];
      for (const [label, key, want] of others) {
        const copy = `${pkg}-${label}`;
        cpSync(pkg, copy, { recursive: true });
        sign(key, join(copy, "release-manifest.json"), join(copy, "release-manifest.json.asc"));
        const r = runVerify("signature", copy, digest);
        expect(r.code).toBe(1);
        expect(r.out).toMatch(want);
      }

      // Two signatures in one file are refused even when one of them is the release key's.
      const two = `${pkg}-two`;
      cpSync(pkg, two, { recursive: true });
      g(["--armor", "--detach-sign", "--local-user", `${keys.releaseSub}!`, "--local-user", `${keys.strangerSub}!`, "--output", join(two, "release-manifest.json.asc"), "--yes", join(two, "release-manifest.json")]);
      expect(runVerify("signature", two, digest).out).toContain("signatures, not one");
    });

    it("tag: passes for the exact signed tag on the commit; fails on another commit, another message, the commit key or a lightweight tag", () => {
      const { pkg, digest } = prepared();
      sign(keys.releaseSub, join(pkg, "release-manifest.json"), join(pkg, "release-manifest.json.asc"));
      const message = readFileSync(join(pkg, "TAG-MESSAGE.txt"), "utf8");
      const cases: [string, () => void, RegExp | null][] = [
        ["exact", () => tag("v1.0.1", commit, message), null],
        ["other commit", () => tag("v1.0.1", other, message), /points to commit .*, not commit/],
        ["other message", () => tag("v1.0.1", commit, "CodeParley 1.0.1\n"), /tag message is not exactly/],
        ["commit key", () => tag("v1.0.1", commit, message, keys.commit), /NO_PUBKEY|not the release signing subkey/],
        ["lightweight", () => git(repo, ["tag", "v1.0.1", commit]), /lightweight tag/],
        ["missing", () => undefined, /there is no tag v1\.0\.1/],
      ];
      for (const [label, make, want] of cases) {
        remove("v1.0.1");
        make();
        const r = runVerify("tag", pkg, digest);
        if (want === null) expect(r, label).toMatchObject({ code: 0 });
        else {
          expect(r.code, label).toBe(1);
          expect(r.out, label).toMatch(want);
        }
      }
      remove("v1.0.1");
    });

    it("payload and remote: the exact twelve files, then GitHub's copy checked without changing anything there", () => {
      const { pkg, digest } = prepared();
      sign(keys.releaseSub, join(pkg, "release-manifest.json"), join(pkg, "release-manifest.json.asc"));
      remove("v1.0.1");
      tag("v1.0.1", commit, readFileSync(join(pkg, "TAG-MESSAGE.txt"), "utf8"));
      const p = runVerify("payload", pkg, digest);
      expect(p, p.out).toMatchObject({ code: 0 });
      expect(p.out).toContain("gh release create v1.0.1 --repo example/CodeParley --draft --verify-tag");
      expect(readFileSync(join(pkg, "codeparley-release-key.asc"), "utf8")).toBe(pub.release);
      const payload = JSON.parse(readFileSync(join(pkg, "release-payload.json"), "utf8")) as { files: { name: string; size: number; sha256: string }[] };
      expect(payload.files.map((f) => f.name)).toEqual(["release-manifest.json", "release-manifest.json.asc", "codeparley-release-key.asc", "code-parley-1.0.1.tgz", "plugin-windows.tar.gz", "plugin-linux.tar.gz", "custodian-windows-x64.tar.gz", "custodian-linux-x64.tar.gz", "engine-runtime-windows-x64.tar.gz", "engine-runtime-linux-x64.tar.gz", "codeparley-installer.ps1", "codeparley-installer.sh"]);
      const again = runVerify("payload", pkg, digest);
      expect(again, again.out).toMatchObject({ code: 0 }); // repeated: unchanged

      const tagObject = git(repo, ["rev-parse", "refs/tags/v1.0.1"]).stdout.trim();
      const release = (o: Partial<Release> = {}): Release => ({ tag_name: "v1.0.1", draft: true, prerelease: false, id: 7, html_url: "https://example.invalid/r/7", assets: payload.files.map((f) => ({ name: f.name, size: f.size, digest: `sha256:${f.sha256}`, state: "uploaded" })), ...o });
      const calls: string[] = [];
      const github = (r: Release, ref = tagObject, id = 42) => (path: string) => {
        calls.push(path);
        if (path === "repos/example/CodeParley") return { id, private: false };
        if (path === "repos/example/CodeParley/git/ref/tags/v1.0.1") return { object: { type: "tag", sha: ref } };
        if (path === "repos/example/CodeParley/releases?per_page=100") return [r];
        throw new Error(`unexpected ${path}`);
      };
      expect(runVerify("remote", pkg, digest, { github: github(release()) })).toMatchObject({ code: 0 });
      expect(runVerify("remote", pkg, digest, { github: github(release({ draft: false })), published: true })).toMatchObject({ code: 0 });
      const bad: [string, (p: string) => unknown, RegExp, boolean?][] = [
        ["published too early", github(release({ draft: false })), /not a draft/],
        ["still a draft", github(release()), /still a draft/, true],
        ["size", github(release({ assets: release().assets.map((a, i) => (i === 4 ? { ...a, size: a.size + 1 } : a)) })), /bytes on GitHub/],
        ["digest", github(release({ assets: release().assets.map((a, i) => (i === 1 ? { ...a, digest: `sha256:${"0".repeat(64)}` } : a)) })), /release-manifest\.json\.asc has digest/],
        ["extra file", github(release({ assets: [...release().assets, { name: "extra.zip", size: 1, digest: "sha256:00", state: "uploaded" }] })), /the release has/],
        ["missing file", github(release({ assets: release().assets.slice(1) })), /the release has/],
        ["tag object", github(release(), "c".repeat(40)), /not the verified tag object/],
        ["repository", github(release(), tagObject, 43), /has ID 43, not 42/],
      ];
      for (const [label, gh, want, published] of bad) {
        const r = runVerify("remote", pkg, digest, { github: gh, published });
        expect(r.code, label).toBe(1);
        expect(r.out, label).toMatch(want);
      }
      expect(new Set(calls)).toEqual(new Set(["repos/example/CodeParley", "repos/example/CodeParley/git/ref/tags/v1.0.1", "repos/example/CodeParley/releases?per_page=100"]));

      expect(verify(["report", ...args(pkg, digest)], { pins: pins(), log: () => undefined })).toBe(0);
      const report = readFileSync(join(pkg, "RELEASE-REPORT.md"), "utf8");
      expect(report).toContain(digest);
      expect(report).toContain(tagObject);
      remove("v1.0.1");
    });

    it("a rehearsal package is marked so and never verifies as a release (nor a release as a rehearsal)", () => {
      const { pkg, digest } = prepared({ rehearsal: true });
      expect(readFileSync(join(pkg, "SIGNING-REQUEST.md"), "utf8")).toContain("REHEARSAL: sign this package only with a disposable test key");
      expect(runVerify("package", pkg, digest, { version: REHEARSAL, rehearsal: true })).toMatchObject({ code: 0 });
      expect(runVerify("package", pkg, digest, { version: REHEARSAL }).out).toContain("is not a release candidate");
      // That last run had other arguments (no --rehearsal): the rehearsal's report does not count it.
      expect(verify(["report", ...args(pkg, digest, { version: REHEARSAL, rehearsal: true })], { pins: pins(), log: () => undefined })).toBe(0);
      expect(readFileSync(join(pkg, "RELEASE-REPORT.md"), "utf8")).toContain("| package | not run with these arguments (the latest run had others)");
      const real = prepared();
      expect(runVerify("package", real.pkg, real.digest, { rehearsal: true }).out).toContain("a rehearsal needs a --test-version build");
    });
  });
});

// The gpg status rules one at a time, on synthetic status output: each condition fails on its own, even where a real
// gpg run would also trip another one.
describe("Step 4: the detached-signature status rules", () => {
  const P = { primary: "A".repeat(40), subkey: "B".repeat(40) };
  const status = (o: { valid?: string; extra?: string[] } = {}) =>
    ["NEWSIG", `GOODSIG ${P.subkey.slice(24)} Owner`, o.valid ?? `VALIDSIG ${P.subkey} 2026-11-03 1 0 4 0 22 10 00 ${P.primary}`, ...(o.extra ?? [])].map((l) => `[GNUPG:] ${l}`).join("\n");
  const rules = (async () => (await import(new URL("../scripts/package/lib/release-verify.mjs", import.meta.url).href)) as { signatureStatusProblems(s: string, code: number | null, p: typeof P): string[] })();

  it("accepts exactly one good, valid signature by the pinned subkey of the pinned primary, over a document", async () => {
    expect((await rules).signatureStatusProblems(status(), 0, P)).toEqual([]);
  });

  it("refuses each deviation on its own", async () => {
    const { signatureStatusProblems: f } = await rules;
    expect(f(status(), 1, P)).toEqual(["gpg --verify exited with 1"]);
    expect(f(status({ valid: `VALIDSIG ${P.subkey} 2026-11-03 1 0 4 0 22 10 00 ${"C".repeat(40)}` }), 0, P)).toEqual([`the signing key's primary key is ${"C".repeat(40)}, not the release key ${P.primary}`]);
    expect(f(status({ valid: `VALIDSIG ${"D".repeat(40)} 2026-11-03 1 0 4 0 22 10 00 ${P.primary}` }), 0, P)).toEqual([`the signature was made by ${"D".repeat(40)}, not the release signing subkey ${P.subkey}`]);
    expect(f(status({ valid: `VALIDSIG ${P.subkey} 2026-11-03 1 0 4 0 22 10 01 ${P.primary}` }), 0, P)).toEqual(["the signature class is 01, not a signature over a document (00)"]);
    for (const bad of ["EXPKEYSIG X Owner", "REVKEYSIG X Owner", "EXPSIG X Owner"]) expect(f(status({ extra: [bad] }), 0, P)).toEqual([`gpg reports ${bad.split(" ")[0]}`]);
  });
});

// Static: the workflow's code never signs, pushes or changes a GitHub release; those commands appear only as text for
// the owner. Template literals (the instructions) and comments are removed before the check.
describe("Step 4: the release tooling has no signing or publication side effects", () => {
  it("contains no signing, push or release-changing invocation", () => {
    for (const f of ["scripts/package/prepare-signing.mjs", "scripts/package/verify-release.mjs", "scripts/package/lib/release-verify.mjs"]) {
      const code = readFileSync(join(root, f), "utf8").replace(/`(?:\\[\s\S]|\$\{(?:[^{}]|\{[^{}]*\})*\}|[^`\\])*`/g, "``").replace(/^\s*\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
      expect(code, f).not.toMatch(/detach-sign|clearsign|"--sign"|"-s"|"push"|"tag",\s*"-s"|release",\s*"(create|edit|upload|delete)"|--method|"-X"|--passphrase|--pinentry|export-secret|card-edit|"(?:ykman|gpg-connect-agent)"/);
      expect(code, f).not.toMatch(/spawnSync\("gh",\s*\[(?!"api", path\])/);
    }
  });
});
