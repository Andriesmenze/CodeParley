// Fixture helpers for capture tests. Fixture SETUP runs git directly with an isolated
// configuration (no system/global config) so fixtures are identical on every machine;
// hostile configuration is installed afterwards. Capture itself runs through src/.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, linkSync, readdirSync, readFileSync, readlinkSync, statSync, lstatSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { resolveNativeExecutable } from "../../src/process/native-resolve.js";
import { runCapture, computeSourceIdentity, type CaptureOptions, type CaptureRulesInput, type CaptureResult } from "../../src/capture/capture.js";
import { runPaths, type RunPaths } from "../../src/store/paths.js";
import { selfOwner } from "../../src/store/owner.js";
import { parseUserConfig } from "../../src/schemas/config.js";
import { uuidv7 } from "../../src/common/ids.js";
import { listFiles } from "../../src/capture/export-writer.js";
import { trackTemp } from "./temp-dirs.js";

/**
 * Platform classification of the suite (M1.6 CI; Linux milestone, plan §1.13):
 *  - platform-independent: policy, schemas, identities, the confidentiality scanner, the store's
 *    records — run everywhere, no gate;
 *  - SHARED CONTRACT (`describe.skipIf(!supported)`): real repositories, processes, checks,
 *    reviews, the store and the MCP server over stdio — the same assertions run against each
 *    supported platform's implementation (Windows and Linux), with platform-specific fixtures
 *    where the platforms legitimately differ (`win` / `linux` branches inside);
 *  - Windows-specific (`skipIf(!win)`): junctions, 8.3 names, `.cmd` shims, PowerShell/WMI,
 *    the MXC backend; Linux-specific (`skipIf(!linux)`): sessions and process groups, /proc,
 *    symlinks and mount points, bubblewrap.
 */
export const win = process.platform === "win32";
export const linux = process.platform === "linux";
/** A platform CodeParley supports (plan §22.5): Windows and Linux. */
export const supported = win || linux;

let gitExeCache: string | null = null;
export async function gitExe(): Promise<string> {
  if (!gitExeCache) {
    const r = await resolveNativeExecutable("git");
    if (!r.ok || !r.path) throw new Error("git not found");
    gitExeCache = r.path;
  }
  return gitExeCache;
}

/** A new directory under the system temporary directory (its final path), removed after the test file. */
export async function tempDir(prefix: string): Promise<string> {
  return trackTemp(await realpath(await mkdtemp(join(tmpdir(), prefix))));
}

let emptyGlobal: string | null = null;
function emptyGlobalConfig(): string {
  if (!emptyGlobal) {
    emptyGlobal = join(tmpdir(), `arl-empty-gitconfig-${process.pid}`);
    if (!existsSync(emptyGlobal)) writeFileSync(emptyGlobal, "");
    // Removed after the test file, like the fixtures (helpers/temp-dirs.ts); a later file in this process writes it again.
    trackTemp(emptyGlobal);
  }
  return emptyGlobal;
}

export function setupEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const keep = win ? ["SystemRoot", "windir", "PATH", "PATHEXT", "TEMP", "TMP", "ComSpec", "USERPROFILE"] : ["PATH", "HOME", "TMPDIR", "LANG"];
  for (const k of keep) if (process.env[k]) env[k] = process.env[k];
  env["GIT_CONFIG_NOSYSTEM"] = "1";
  env["GIT_CONFIG_GLOBAL"] = emptyGlobalConfig();
  env["GIT_TERMINAL_PROMPT"] = "0";
  env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "Fixture";
  env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "fixture@example.invalid";
  return { ...env, ...extra };
}

export interface GitRun {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Run git for fixture setup / positive controls (NOT via the capture code). */
export function git(cwd: string, args: string[], opts: { env?: Record<string, string>; input?: string | Buffer; allowFail?: boolean } = {}): GitRun {
  const exe = gitExeCache ?? "git";
  const r = spawnSync(exe, ["-c", "core.autocrlf=false", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", ...args], {
    cwd,
    env: setupEnv(opts.env),
    input: opts.input,
    encoding: "utf8",
    windowsHide: true,
  });
  const out = { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  if (!opts.allowFail && r.status !== 0) throw new Error(`git ${args.join(" ")} failed (${r.status}): ${out.stderr}`);
  return out;
}

export async function initRepo(dir: string, opts: { objectFormat?: "sha1" | "sha256" } = {}): Promise<string> {
  await mkdir(dir, { recursive: true });
  git(dir, ["init", "-q", ...(opts.objectFormat === "sha256" ? ["--object-format=sha256"] : [])]);
  git(dir, ["config", "core.autocrlf", "false"]);
  return dir;
}

export async function writeFiles(root: string, files: Record<string, string | Buffer>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, ...rel.split("/"));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content);
  }
}

/** Stage everything and commit it. Step 6: the fixture builders, which never read the new commit's id, skip the extra
 * `git rev-parse` that commitAll() spends on it (one process per fixture). */
export function commitFiles(dir: string, msg = "commit"): void {
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-q", "--allow-empty", "-m", msg]);
}

/** Stage everything, commit it, and return the new commit's id. */
export function commitAll(dir: string, msg = "commit"): string {
  commitFiles(dir, msg);
  return git(dir, ["rev-parse", "HEAD"]).stdout.trim();
}

/** Forward-slash path for use inside sh commands run by git. */
export function shPath(p: string): string {
  return p.replace(/\\/g, "/");
}

/** A shell snippet (run by git via sh) that appends `tag` to the marker file. */
export function markerCmd(marker: string, tag: string, then = ""): string {
  return `echo ${tag} >> '${shPath(marker)}'${then ? `; ${then}` : ""}`;
}

export function readMarker(marker: string): string {
  return existsSync(marker) ? readFileSync(marker, "utf8") : "";
}

/** Snapshot every file under `dir`: relative path -> size:sha256 (dirs recorded as "dir"). */
export function snapshotTree(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (abs: string, rel: string) => {
    for (const ent of readdirSync(abs, { withFileTypes: true })) {
      const a = join(abs, ent.name);
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      const st = lstatSync(a);
      if (st.isSymbolicLink()) out.set(r, "link");
      else if (ent.isDirectory()) {
        out.set(r, "dir");
        // Do not descend into junctions (lstat reports them as directories on some Node versions).
        if (!isJunction(a)) walk(a, r);
        else out.set(r, "junction");
      } else {
        const buf = readFileSync(a);
        out.set(r, `${buf.length}:${createHash("sha256").update(buf).digest("hex")}`);
      }
    }
  };
  walk(dir, "");
  return out;
}

function isJunction(p: string): boolean {
  try {
    readlinkSync(p);
    return true;
  } catch {
    return false;
  }
}

export function diffSnapshots(a: Map<string, string>, b: Map<string, string>): string[] {
  const diffs: string[] = [];
  for (const [k, v] of a) if (b.get(k) !== v) diffs.push(`changed/removed: ${k}`);
  for (const k of b.keys()) if (!a.has(k)) diffs.push(`added: ${k}`);
  return diffs;
}

export const DEFAULT_RULES: CaptureRulesInput = {
  // Exactly the shipped configuration defaults (plan §7.4), so tests exercise what users get.
  ...parseUserConfig({}).capture,
};

export interface Harness {
  dataHome: string;
  runPaths: RunPaths;
}

export async function harness(): Promise<Harness> {
  const dataHome = await tempDir("arl-store-");
  const rp = runPaths(dataHome, "repokey", uuidv7());
  await mkdir(rp.opsDir, { recursive: true });
  return { dataHome, runPaths: rp };
}

export type CaptureArgs = Partial<Omit<CaptureOptions, "repoRoot" | "runPaths" | "lock" | "gitExe" | "rules">> & { rules?: Partial<CaptureRulesInput> };

export async function capture(h: Harness, repoRoot: string, args: CaptureArgs = {}): Promise<CaptureResult> {
  const operationId = args.operationId ?? uuidv7();
  return runCapture({
    kind: args.kind ?? "review",
    repoRoot,
    gitExe: await gitExe(),
    target: args.target ?? { kind: "uncommitted" },
    rules: { ...DEFAULT_RULES, ...(args.rules ?? {}) },
    runPaths: h.runPaths,
    operationId,
    lock: { dataHome: h.dataHome, owner: selfOwner() },
    fsync: false,
    ...(args.baseline ? { baseline: args.baseline } : {}),
    ...(args.testHooks ? { testHooks: args.testHooks } : {}),
    ...(args.gitEnvOverrides ? { gitEnvOverrides: args.gitEnvOverrides } : {}),
    ...(args.signal ? { signal: args.signal } : {}),
  });
}

export async function sourceIdentity(h: Harness, repoRoot: string, rules: Partial<CaptureRulesInput> = {}, gitEnvOverrides?: Record<string, string>) {
  return computeSourceIdentity({
    repoRoot,
    gitExe: await gitExe(),
    rules: { ...DEFAULT_RULES, ...rules },
    lock: { dataHome: h.dataHome, owner: selfOwner() },
    operationId: uuidv7(),
    ...(gitEnvOverrides ? { gitEnvOverrides } : {}),
  });
}

/** Every byte of every file in an export, concatenated with names (for leak scans). */
export async function exportCorpus(dir: string): Promise<string> {
  const parts: string[] = [];
  for (const rel of await listFiles(dir)) {
    parts.push(rel);
    parts.push(readFileSync(join(dir, ...rel.split("/"))).toString("latin1"));
  }
  return parts.join("\n");
}

export function exportFileList(dir: string): string[] {
  const out: string[] = [];
  const walk = (abs: string, rel: string) => {
    for (const ent of readdirSync(abs, { withFileTypes: true })) {
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) walk(join(abs, ent.name), r);
      else out.push(r);
    }
  };
  walk(dir, "");
  return out.sort();
}

export async function cleanup(...dirs: string[]): Promise<void> {
  for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => undefined);
}

export function fileSha256(p: string): string {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

export function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/** A directory link: a junction on Windows, a symbolic link on Linux. */
export function mklinkJunction(link: string, target: string): boolean {
  if (!win) return trySync(() => symlinkSync(target, link, "dir"));
  const r = spawnSync(process.env["ComSpec"] ?? "cmd.exe", ["/c", "mklink", "/J", link, target], { windowsHide: true });
  return r.status === 0;
}
/** A file symbolic link (Windows needs Developer Mode or elevation; Linux always works). */
export function mklinkFile(link: string, target: string): boolean {
  if (!win) return trySync(() => symlinkSync(target, link, "file"));
  const r = spawnSync(process.env["ComSpec"] ?? "cmd.exe", ["/c", "mklink", link, target], { windowsHide: true });
  return r.status === 0;
}
/** A hard link. */
export function mklinkHard(link: string, target: string): boolean {
  if (!win) return trySync(() => linkSync(target, link));
  const r = spawnSync(process.env["ComSpec"] ?? "cmd.exe", ["/c", "mklink", "/H", link, target], { windowsHide: true });
  return r.status === 0;
}

function trySync(f: () => void): boolean {
  try {
    f();
    return true;
  } catch {
    return false;
  }
}

/** Kill a process now, by PID (test cleanup; Windows: taskkill /F [/T], Linux: SIGKILL). */
export function hardKill(pid: number, tree = false): void {
  if (win) {
    spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(pid), ...(tree ? ["/T"] : []), "/F"], { windowsHide: true });
    return;
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    /* already gone */
  }
}
