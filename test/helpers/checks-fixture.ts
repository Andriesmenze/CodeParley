// Fixtures for M1.3 check tests: a real git repository with node check scripts, approval
// through the real CLI (`checks approve --file … --confirm <digest>`), and runs created
// with their verification floor in run.json.

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli, type CliIo } from "../../src/cli/cli.js";
import { createRun } from "../../src/store/state-store.js";
import { canonicalPathKey, runPaths, storeLayout } from "../../src/store/paths.js";
import { selfOwner } from "../../src/store/owner.js";
import { newStateRecord, type RunMeta } from "../../src/schemas/run-state.js";
import { parseUserConfig } from "../../src/schemas/config.js";
import { uuidv7 } from "../../src/common/ids.js";
import { loadTrustedState, type ChecksEngineContext } from "../../src/engine/checks-operation.js";
import { resolveRunFloor } from "../../src/policy/verification-floor.js";
import { commitAll, gitExe, initRepo, tempDir, writeFiles } from "./git-fixture.js";

export const SCRIPTS: Record<string, string> = {
  // exit 0, print a marker
  "scripts/pass.js": "process.stdout.write('PASS ' + process.argv.slice(2).join(' '));\n",
  // fail when flag.txt says "bad"
  "scripts/flag.js": "const fs=require('fs'); const v=fs.readFileSync('flag.txt','utf8').trim(); process.stdout.write('flag='+v); process.exit(v==='bad'?1:0);\n",
  // print an environment variable
  "scripts/env.js": "process.stdout.write(String(process.env[process.argv[2]]));\n",
  // sleep N ms
  "scripts/sleep.js": "setTimeout(()=>{ process.stdout.write('woke'); }, Number(process.argv[2]));\n",
  // write a file (repository code changing the tree during a check)
  "scripts/write.js": "require('fs').mkdirSync(require('path').dirname(process.argv[2]),{recursive:true}); require('fs').writeFileSync(process.argv[2], 'generated ' + Date.now());\n",
  // fail the first time (counter file outside the repository), pass afterwards
  "scripts/flaky.js": "const fs=require('fs'); const f=process.argv[2]; const n=fs.existsSync(f)?Number(fs.readFileSync(f,'utf8')):0; fs.writeFileSync(f,String(n+1)); process.exit(n===0?1:0);\n",
  // flood stdout
  "scripts/flood.js": "const b=Buffer.alloc(65536,121); for(let i=0;i<64;i++) process.stdout.write(b); process.stdout.write('END');\n",
  // spawn a DETACHED long-lived grandchild (outside libuv's kill-on-close job), record its
  // pid, then sleep (MR-C: the server dies while this check runs)
  "scripts/spawn-gc.js":
    "const {spawn}=require('child_process'); const g=spawn(process.execPath,['-e','setTimeout(()=>{},300000)'],{detached:true,stdio:'ignore',windowsHide:true}); g.unref(); require('fs').writeFileSync(process.argv[2], String(g.pid)); setTimeout(()=>{},300000);\n",
  // repository code that edits trusted configuration (append a check definition)
  "scripts/edit-trust.js":
    "const fs=require('fs'); const p=process.argv[2]; const j=JSON.parse(fs.readFileSync(p,'utf8')); for (const k of Object.keys(j)) { j[k].checks.injected={argv:['cmd','/c','echo pwned']}; } fs.writeFileSync(p, JSON.stringify(j));\n",
};

export interface Fixture {
  dataHome: string;
  repo: string;
  git: string;
  trustProjectsPath: string;
  scratch: string;
}

export async function makeFixture(prefix = "arl-checks-"): Promise<Fixture> {
  const base = await tempDir(prefix);
  const repo = join(base, "repo");
  const dataHome = join(base, "home");
  const scratch = join(base, "scratch");
  await mkdir(dataHome, { recursive: true });
  await mkdir(scratch, { recursive: true });
  await initRepo(repo);
  await writeFiles(repo, { ...SCRIPTS, "flag.txt": "good\n", ".gitignore": "deps/\nbuild/\n", "src/app.js": "module.exports = 1;\n" });
  commitAll(repo, "init");
  return { dataHome, repo, git: await gitExe(), trustProjectsPath: storeLayout(dataHome).trustProjects, scratch };
}

export interface CapturedIo extends CliIo {
  lines: string[];
  errors: string[];
}

export function captureIo(): CapturedIo {
  const lines: string[] = [];
  const errors: string[] = [];
  return { lines, errors, out: (l) => lines.push(l), err: (l) => errors.push(l), prompt: null, env: process.env, cwd: process.cwd() };
}

export interface ApprovalFile {
  checks: Record<string, unknown>;
  profiles?: Record<string, string[]>;
  required_profiles?: string[];
  no_required_checks?: boolean;
  test_globs?: string[];
}

/** Approve definitions through the real CLI: show (exit 2), then confirm the shown digest. */
export async function approve(f: Fixture, defs: ApprovalFile, extraArgs: string[] = []): Promise<string> {
  const file = join(f.scratch, `defs-${uuidv7()}.json`);
  await writeFile(file, JSON.stringify(defs));
  const args = ["checks", "approve", "--repo", f.repo, "--file", file, "--home", f.dataHome, "--git", f.git, ...extraArgs];
  const show = captureIo();
  const code = await runCli(args, show);
  if (code !== 2) throw new Error(`approve (show) exit ${code}: ${show.errors.join("\n")}`);
  const digest = show.lines.find((l) => l.startsWith("approval digest: "))?.slice("approval digest: ".length);
  if (!digest) throw new Error("no digest shown");
  const conf = captureIo();
  const code2 = await runCli([...args, "--confirm", digest.slice(0, 16)], conf);
  if (code2 !== 0) throw new Error(`approve (confirm) exit ${code2}: ${conf.errors.join("\n")}`);
  return digest;
}

export interface RunOptions {
  additionalRequired?: string[];
  maxExecutions?: number;
  sourceEnv?: NodeJS.ProcessEnv;
}

/** Create a run (IDLE) whose verification floor is fixed from trusted configuration now. */
export async function newRun(f: Fixture, o: RunOptions = {}): Promise<ChecksEngineContext> {
  const runId = uuidv7();
  const paths = runPaths(f.dataHome, canonicalPathKey(f.repo), runId);
  const meta: RunMeta = {
    schema_version: 1,
    run_id: runId,
    created_at: new Date().toISOString(),
    repository_root: f.repo,
    versions: {},
    scope: { allowed_snapshot: [f.repo], client_roots_snapshot: [] },
  };
  const base: ChecksEngineContext = {
    dataHome: f.dataHome,
    trustProjectsPath: f.trustProjectsPath,
    runPaths: paths,
    meta,
    gitExe: f.git,
    rules: parseUserConfig({}).capture,
    owner: selfOwner(),
    budgets: { max_check_executions_per_run: o.maxExecutions ?? 20 },
    sourceEnv: o.sourceEnv ?? { ...process.env },
    testHooks: { sweep: null },
  };
  const trusted = await loadTrustedState(base);
  const floor = resolveRunFloor(trusted.view, o.additionalRequired ?? []);
  if (!floor.ok) throw Object.assign(new Error(floor.errors.map((e) => e.detail).join("; ")), { errors: floor.errors });
  const withFloor: RunMeta = { ...meta, verification_floor: { ...floor.floor, approval_digest: trusted.evaluation.approval?.digest ?? null } };
  await createRun(paths, withFloor, newStateRecord(runId, "IDLE"));
  return { ...base, meta: withFloor };
}

export const node = process.execPath;
