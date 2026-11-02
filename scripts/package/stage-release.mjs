#!/usr/bin/env node
// Phase 6 Increment 2 (contract §8, A-1 to A-3): stage CodeParley's release artifacts from one clean, signed commit,
// each carrying its BUILD-ID, and the unsigned release manifest that lists them. Nothing is signed, installed or
// published (A-4 is the owner's).
//
//   node scripts/package/stage-release.mjs --node-win <node.exe> --node-linux <node> [--out <dir>] [--gpg <gpg>] [--allow-dirty]
//
// The artifacts (each a .tar.gz with a BUILD-ID at its root, except the npm tarball and the installers, whose BUILD-ID
// is beside them):
//   npm-tarball                  scripts/package/pack.mjs --require-clean (the content policy applies)
//   plugin-windows, plugin-linux plugin/build-plugin.mjs --marketplace over a clean build, running the installed runtime's Node
//   custodian-windows-x64        dotnet publish, self-contained (no .NET on the target)
//   custodian-linux-x64          dotnet publish, self-contained single file
//   engine-runtime-windows-x64   Node (the given node.exe) + the engine (dist, production node_modules, prompts);
//   engine-runtime-linux-x64     Git is not bundled: it is approved separately (§7 b, --runtime-git-path)
//   installer-windows            installer/windows/codeparley-installer.ps1
//   installer-linux              installer/linux/codeparley-installer.sh
// The Linux custodian bundle also carries deploy/: its systemd units, tmpfiles.d, the operator wrapper and the AppArmor
// profile template the installer deploys.
// The Node binaries are the administrator's choice, never downloaded here: their version must satisfy package.json
// `engines`, and each must be its platform's native image. The commit's signature is verified against the owner's
// committed public key (scripts/ci/verify-commit-identity.mjs). --allow-dirty stages from a tree with changes or an
// unverified commit for a dry run: every BUILD-ID and the manifest then say releaseCandidate: false. --test-version <v>
// stages under another version (the VM gates' upgrade and rollback need two): such a build is marked testBuild and is
// never a release candidate.
// Exit status: 0 staged; 1 a check failed; 2 a usage or tool error.

import { cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, closeSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { execFileSync, execSync } from "node:child_process";
import { dirname, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { buildId, buildManifest } from "./lib/release-manifest.mjs";
import { satisfies } from "./lib/semver-lite.mjs";
import { npmCli, runOk, sha256File } from "./lib/tools.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const WIN = process.platform === "win32";

function parse(argv) {
  const o = { out: null, nodeWin: null, nodeLinux: null, gpg: null, allowDirty: false, testVersion: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") o.out = resolve(argv[++i] ?? "");
    else if (a === "--node-win") o.nodeWin = resolve(argv[++i] ?? "");
    else if (a === "--node-linux") o.nodeLinux = resolve(argv[++i] ?? "");
    else if (a === "--gpg") o.gpg = argv[++i] ?? "";
    else if (a === "--allow-dirty") o.allowDirty = true;
    else if (a === "--test-version") o.testVersion = argv[++i] ?? "";
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.nodeWin || !o.nodeLinux) throw new Error("--node-win <node.exe> and --node-linux <node> are required (the Node runtimes the engine bundles carry)");
  return o;
}

const git = (...a) => execFileSync("git", ["-C", REPO, ...a], { encoding: "utf8", windowsHide: true }).trim();

/** The Node binary's version (it is run to ask, on its own platform only) or its declared version file. */
function nodeVersion(path, platform) {
  if (!existsSync(path)) throw new Error(`${path} does not exist`);
  const magic = Buffer.alloc(4);
  const fd = openSync(path, "r");
  try { readSync(fd, magic, 0, 4, 0); } finally { closeSync(fd); }
  const pe = magic[0] === 0x4d && magic[1] === 0x5a;
  const elf = magic[0] === 0x7f && magic.toString("latin1", 1, 4) === "ELF";
  if (platform === "windows" ? !pe : !elf) throw new Error(`${path} is not a ${platform === "windows" ? "Windows PE" : "Linux ELF"} image`);
  const runnable = (platform === "windows") === WIN;
  if (runnable) return execFileSync(path, ["--version"], { encoding: "utf8", windowsHide: true }).trim();
  // A binary of the other platform is not run here: its version comes from the distribution it was taken from.
  const declared = join(dirname(path), "..", "include", "node", "node_version.h");
  if (!existsSync(declared)) throw new Error(`cannot tell the version of ${path} without running it: give a node from an unpacked Node.js distribution (with include/node/node_version.h)`);
  const h = readFileSync(declared, "utf8");
  const n = (k) => /#define\s+NODE_(MAJOR|MINOR|PATCH)_VERSION\s+(\d+)/g;
  const v = {};
  for (const m of h.matchAll(n())) v[m[1]] = m[2];
  if (!v.MAJOR || !v.MINOR || !v.PATCH) throw new Error(`${declared} names no Node.js version`);
  return `v${v.MAJOR}.${v.MINOR}.${v.PATCH}`;
}

function archive(dir, file) {
  mkdirSync(dirname(file), { recursive: true });
  const tar = WIN ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe") : "tar";
  execFileSync(tar, ["-czf", file, "-C", dir, "."], { stdio: "inherit", windowsHide: true });
}

function productionPackages() {
  const out = execSync("npm ls --omit=dev --all --parseable", { cwd: REPO, encoding: "utf8" });
  const nm = join(REPO, "node_modules") + sep;
  return out.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith(nm)).map((l) => relative(join(REPO, "node_modules"), l)).filter((rel) => !rel.includes(`${sep}node_modules${sep}`));
}

function hasNativeAddon(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory() ? hasNativeAddon(p) : e.name.endsWith(".node")) return true;
  }
  return false;
}

function main() {
  const o = parse(process.argv.slice(2));
  const pkg = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8"));
  if (o.testVersion !== null && !/^\d+\.\d+\.\d+-[a-z0-9.]+$/.test(o.testVersion)) throw new Error("--test-version must be a prerelease version such as 0.4.0-vm.1");
  const testBuild = o.testVersion !== null;
  const version = o.testVersion ?? pkg.version;
  const commit = git("rev-parse", "HEAD");
  const dirty = git("status", "--porcelain", "--untracked-files=all").length > 0;
  let signature = "unverified";
  try {
    execFileSync(process.execPath, [join(REPO, "scripts", "ci", "verify-commit-identity.mjs"), "--expect", commit, ...(o.gpg ? ["--gpg", o.gpg] : [])], { stdio: "pipe", windowsHide: true });
    signature = "verified";
  } catch (e) {
    process.stderr.write(`stage-release: the commit's signature did not verify against the committed key:\n${String(e.stdout ?? "")}${String(e.stderr ?? "")}\n`);
  }
  if ((dirty || signature !== "verified") && !o.allowDirty) {
    process.stderr.write(`stage-release: refusing: ${dirty ? "the tree has changes" : ""}${dirty && signature !== "verified" ? " and " : ""}${signature !== "verified" ? "the commit's signature did not verify" : ""} (a release candidate is staged only from a clean, signed commit; --allow-dirty stages a dry run)\n`);
    return 1;
  }
  const nodeWin = nodeVersion(o.nodeWin, "windows");
  const nodeLinux = nodeVersion(o.nodeLinux, "linux");
  for (const [p, v] of [[o.nodeWin, nodeWin], [o.nodeLinux, nodeLinux]])
    if (!satisfies(v.replace(/^v/, ""), pkg.engines.node)) throw new Error(`${p} is Node.js ${v}, outside package.json engines ${pkg.engines.node}`);
  const npm = npmCli(process.execPath);
  const toolchain = {
    dotnetSdk: execFileSync("dotnet", ["--version"], { cwd: join(REPO, "custodian"), encoding: "utf8", windowsHide: true }).trim(),
    node: process.version,
    npm: npm ? execFileSync(process.execPath, [npm, "--version"], { encoding: "utf8", windowsHide: true }).trim() : "unknown",
  };
  const out = o.out ?? join(REPO, ".tmp-release", `${version}-${commit.slice(0, 12)}`);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const work = mkdtempSync(join(tmpdir(), "cp-release-"));
  const builtAt = new Date().toISOString();
  const entries = [];
  const id = (artifact, extra = {}) => ({ ...buildId({ artifact, version, commit, signature, dirty, toolchain, builtAt, testBuild }), ...extra });
  const add = (name, file, bid) => {
    const path = join(out, file);
    entries.push({ name, file, size: statSync(path).size, sha256: sha256File(path), buildId: bid });
    process.stdout.write(`staged ${name}: ${file}\n`);
  };
  const bundle = (name, dir, extra) => {
    const bid = id(name, extra);
    writeFileSync(join(dir, "BUILD-ID"), `${JSON.stringify(bid, null, 2)}\n`);
    // Every bundle carries the license and the notices of what it redistributes.
    cpSync(join(REPO, "LICENSE"), join(dir, "LICENSE"));
    cpSync(join(REPO, "THIRD-PARTY-NOTICES.md"), join(dir, "THIRD-PARTY-NOTICES.md"));
    cpSync(join(REPO, "third-party"), join(dir, "third-party"), { recursive: true });
    archive(dir, join(out, `${name}.tar.gz`));
    add(name, `${name}.tar.gz`, bid);
  };
  try {
    // A clean build of the engine, outside the checkout's own dist/.
    const dist = join(work, "dist");
    runOk(process.execPath, [join(REPO, "node_modules", "typescript", "bin", "tsc"), "-p", join(REPO, "tsconfig.json"), "--outDir", dist], { cwd: REPO, label: "tsc (clean build)" });

    // npm tarball (the package content policy applies).
    const packOut = join(work, "pack");
    runOk(process.execPath, [join(REPO, "scripts", "package", "pack.mjs"), "--out", packOut, ...(o.allowDirty ? [] : ["--require-clean"])], { cwd: REPO, label: "pack" });
    const tgz = readdirSync(packOut).find((f) => f.endsWith(".tgz"));
    if (!tgz) throw new Error("pack produced no tarball");
    cpSync(join(packOut, tgz), join(out, tgz));
    const npmId = id("npm-tarball");
    writeFileSync(join(out, `${tgz}.BUILD-ID`), `${JSON.stringify(npmId, null, 2)}\n`);
    add("npm-tarball", tgz, npmId);

    // The Claude Code plugin, one per platform: a local marketplace (Phase 6 Increment 3: the documented plugin step is
    // `claude plugin marketplace add <dir>` + `claude plugin install code-parley@code-parley-local --scope user`) whose
    // hooks and server run the INSTALLED engine runtime's Node (codeparley-installer: <ProgramFiles>\CodeParley\engine\<version>,
    // /opt/codeparley/engine/current).
    for (const [name, nodePath] of [["plugin-windows", `C:\\Program Files\\CodeParley\\engine\\${version}\\node.exe`], ["plugin-linux", "/opt/codeparley/engine/current/node"]]) {
      const market = join(work, name);
      runOk(process.execPath, [join(REPO, "plugin", "build-plugin.mjs"), "--marketplace", market, "--node-path", nodePath, "--dist", dist], { cwd: REPO, label: `build-plugin ${name}` });
      bundle(name, market);
    }

    // The custodians, self-contained.
    for (const [name, project, rid, single] of [["custodian-windows-x64", "CodeParley.Custodian", "win-x64", false], ["custodian-linux-x64", "CodeParley.Custodian.Linux", "linux-x64", true]]) {
      const dir = join(work, name);
      runOk("dotnet", ["publish", join(REPO, "custodian", project, `${project}.csproj`), "-c", "Release", "-r", rid, "--self-contained", "true", ...(single ? ["-p:PublishSingleFile=true"] : []), "-p:DebugType=none", "-o", dir, "-nologo", "-v", "q"], { cwd: join(REPO, "custodian"), label: `dotnet publish ${rid}` });
      if (rid === "linux-x64") for (const d of ["systemd", "tmpfiles.d", "operator", "apparmor"]) cpSync(join(REPO, "custodian", "linux", d), join(dir, "deploy", d), { recursive: true });
      bundle(name, dir);
    }

    // The engine runtimes: Node and the engine (no Git: §7 b).
    const prod = productionPackages();
    for (const [name, nodePath, nodeName, nodeV] of [["engine-runtime-windows-x64", o.nodeWin, "node.exe", nodeWin], ["engine-runtime-linux-x64", o.nodeLinux, "node", nodeLinux]]) {
      const dir = join(work, name);
      cpSync(dist, join(dir, "dist"), { recursive: true, filter: (s) => !/\.(d\.ts|js\.map|d\.ts\.map)$/.test(s) });
      for (const rel of prod) cpSync(join(REPO, "node_modules", rel), join(dir, "node_modules", rel), { recursive: true });
      if (hasNativeAddon(join(dir, "node_modules"))) throw new Error("a production dependency carries a native addon: the engine runtime would differ per platform");
      cpSync(join(REPO, "prompts"), join(dir, "prompts"), { recursive: true });
      writeFileSync(join(dir, "package.json"), `${JSON.stringify({ name: pkg.name, version, private: true, type: "module" }, null, 2)}\n`);
      cpSync(nodePath, join(dir, nodeName));
      if (!existsSync(join(dir, "dist", "helper", "main.js"))) throw new Error("the build has no helper entry dist/helper/main.js");
      bundle(name, dir, { node: nodeV });
    }

    // The installers, as they are (each verifies the other artifacts against this manifest).
    for (const [name, rel] of [["installer-windows", ["installer", "windows", "codeparley-installer.ps1"]], ["installer-linux", ["installer", "linux", "codeparley-installer.sh"]]]) {
      const file = rel.at(-1);
      cpSync(join(REPO, ...rel), join(out, file));
      const bid = id(name);
      writeFileSync(join(out, `${file}.BUILD-ID`), `${JSON.stringify(bid, null, 2)}\n`);
      add(name, file, bid);
    }

    const manifest = buildManifest({ version, commit, signature, dirty, entries, testBuild });
    const manifestPath = join(out, "release-manifest.json");
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    process.stdout.write(`\nrelease manifest: ${manifestPath}\n  SHA-256 ${sha256File(manifestPath)}\n  ${manifest.releaseCandidate ? "a release candidate (clean, signed commit); unsigned until the owner signs it" : testBuild ? "a TEST build (--test-version): NOT a release candidate" : "NOT a release candidate (dry run: changes or an unverified commit)"}\n`);
    return 0;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

try {
  process.exitCode = main();
} catch (e) {
  process.stderr.write(`stage-release: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 2;
}
