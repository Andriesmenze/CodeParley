// Phase 6 Increment 3 (contract §3.2, §5; [[D-41]]): the setup experience.
//
//   init    --repo <path> [--max-fixes <0-10>] [--dry-run]   (the implementer) the repository in config.json's allowed roots
//                                                            and the fix budget; then what is left, in order
//   status  [--repo <path>] [--json]                         (anyone) the custodian's state and, for a repository, each
//                                                            operator record with the one command that restores it
//   setup   --repo <path> [--resume] [--fix] …               (the operator) the existing operator steps, in order
//
// No new authority. `init` writes only the implementer's own config.json. `status` is a read-only display (see
// engine/protected-status.ts). `setup` runs the EXISTING commands — config set / reconfirm / confirm-selftest /
// approve-runtime / reconfirm-runtime and loop allow — one at a time: each one has the custodian render its record and
// asks for its own typed confirmation exactly as when it is run alone, so no confirmation covers a record it did not
// render (O-8) and nothing is confirmed by anyone but the operator at the terminal. It skips what is in force, stops at
// the first step the operator does not confirm, and re-reads the custodian's records after every step.

import { readFile } from "node:fs/promises";
import { DomainError, isDomainError } from "../common/errors.js";
import { remedyLines } from "../common/remedies.js";
import { atomicWriteFile, readTextIfExists } from "../store/atomic.js";
import { parseUserConfig } from "../schemas/config.js";
import { loadEngine, gitExeOf, type Loaded } from "../engine/engine-env.js";
import { BUSY_LIMITATION, LINUX_ENGINE_CURRENT, installedEngineRuntime, operatorCli, protectedStatus, type ProtectedStatus, type RecordState } from "../engine/protected-status.js";
import { canonicalizePath, isContainedIn } from "../workspace/paths.js";
import { resolveGitTopLevel } from "../workspace/git-toplevel.js";
import { loadTrustProjects } from "../config/trusted-projects.js";
import { evaluateProject } from "../checks/project-config.js";
import { readRootCommit } from "../capture/root-commit.js";
import { selfOwner } from "../store/owner.js";
import { linuxOperatorRepo } from "./operator-trust.js";
import { runConfigCli } from "./config-commands.js";
import { runLoopCli } from "./loop-commands.js";
import type { CliIo } from "./cli.js";

export interface SetupArgs {
  group: "init" | "status" | "setup";
  one(flag: string): string | undefined;
  many(flag: string): string[];
  has(flag: string): boolean;
}

const DISPLAY_ONLY = "status is a display: it grants, confirms and changes nothing, and the custodian decides each protected request itself.";

function launchOf(a: SetupArgs) {
  return {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
}

export async function runSetupCli(a: SetupArgs, io: CliIo): Promise<number> {
  const le = await loadEngine({ launch: launchOf(a), sourceEnv: io.env, owner: selfOwner(), custodianReadSurface: "operator", ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  if (a.group === "init") return init(le, a, io);
  if (a.group === "status") return status(le, a, io);
  return setup(le, a, io);
}

/** The repository as this account can name it: its git top level, or on Linux (the operator cannot read it) the plain path. */
async function repositoryOf(le: Loaded, raw: string): Promise<string> {
  try {
    return await resolveGitTopLevel(await canonicalizePath(raw), { gitExe: await gitExeOf(le) });
  } catch (e) {
    if (process.platform === "linux" && !le.env.testHooks) return linuxOperatorRepo(raw);
    throw e;
  }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

const RECORD_LABEL: Record<RecordState["record"], string> = {
  engine_runtime: "engine runtime",
  repository: "repository configuration",
  isolation: "Codex isolation (S1)",
  fix_confirmation: "FIX confirmation",
  loop_grant: "loop grant",
};

export function renderStatus(s: ProtectedStatus): string[] {
  const out: string[] = [];
  out.push(`CodeParley status — engine ${s.engine.version} (custodian protocol ${s.engine.protocol}), ${s.platform}`);
  out.push(`custodian service: ${s.service.presence}${s.service.manager_state ? ` (${s.service.manager_state})` : ""}`);
  for (const x of s.surfaces) {
    const id = x.identity;
    const ident = id ? ` — custodian ${id.version ?? "release unknown"}${id.build ? ` build ${id.build.slice(0, 12)}` : ""}, protocol ${id.protocol ?? "unknown"}` : "";
    out.push(`  ${x.surface} surface: ${x.result}${ident}${x.detail && x.result !== "answers" ? ` (${x.detail})` : ""}`);
  }
  out.push(`state: ${s.state.toUpperCase().replace("_", " ")}`);
  for (const e of s.explanation) out.push(`  ${e}`);
  if (s.repository) {
    const r = s.repository;
    out.push(`repository ${r.root}: ${r.state.toUpperCase()}${r.read_on ? ` (the custodian's records, read on the ${r.read_on} surface)` : ""}`);
    if (r.state === "unknown" && !r.records.length) out.push("  the custodian must answer before its records can be shown");
    for (const x of r.records) {
      const tag = x.state === "in_force" ? "in force" : x.state.toUpperCase().replace("_", " ");
      out.push(`  ${RECORD_LABEL[x.record].padEnd(25)} ${tag.padEnd(9)} ${x.detail}${x.required ? "" : " [optional]"}`);
      if (x.restore) out.push(`  ${"".padEnd(25)} ${"".padEnd(9)} → ${x.restore}`);
    }
  }
  if (s.next.length) {
    out.push("next:");
    s.next.forEach((n, i) => out.push(`  ${i + 1}. ${n}`));
  }
  out.push(DISPLAY_ONLY);
  return out;
}

async function status(le: Loaded, a: SetupArgs, io: CliIo): Promise<number> {
  const raw = a.one("--repo");
  const root = raw ? await repositoryOf(le, raw) : null;
  const s = await protectedStatus(le, { repositoryRoot: root });
  if (a.has("--json")) io.out(JSON.stringify(s, null, 2));
  else renderStatus(s).forEach((l) => io.out(l));
  return s.state === "ready" && (!s.repository || s.repository.state === "ready") ? 0 : 1;
}

// ---------------------------------------------------------------------------
// init (the implementer)
// ---------------------------------------------------------------------------

async function init(le: Loaded, a: SetupArgs, io: CliIo): Promise<number> {
  const raw = a.one("--repo");
  if (!raw) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley init --repo <path> [--max-fixes <0-10>] [--dry-run]");
  const root = await resolveGitTopLevel(await canonicalizePath(raw), { gitExe: await gitExeOf(le) });
  const maxFixesRaw = a.one("--max-fixes");
  const maxFixes = maxFixesRaw === undefined ? null : Number(maxFixesRaw);
  if (maxFixes !== null && !(Number.isInteger(maxFixes) && maxFixes >= 0 && maxFixes <= 10)) throw new DomainError("INVALID_ARGUMENT", "--max-fixes must be an integer from 0 to 10");

  // The implementer's own config.json, merged: nothing in it is replaced except what init sets, and a file it cannot
  // parse is never overwritten.
  const path = le.cfg.launch.configFile ?? le.layout.configFile;
  const text = await readTextIfExists(path);
  let json: Record<string, unknown> = {};
  if (text !== null) {
    try {
      const o = JSON.parse(text) as unknown;
      if (typeof o !== "object" || o === null || Array.isArray(o)) throw new Error("not an object");
      json = o as Record<string, unknown>;
    } catch (e) {
      throw new DomainError("CONFIG_INVALID", `${path} is not valid JSON (${(e as Error).message}); init does not overwrite it: fix or remove it first`);
    }
  }
  const covered = le.allowedRoots.some((r) => isContainedIn(root, r));
  const roots = Array.isArray(json["allowed_roots"]) ? [...(json["allowed_roots"] as unknown[])] : [];
  const changes: string[] = [];
  if (!covered) {
    roots.push(root);
    changes.push(`allowed_roots += ${root}`);
  }
  const budgets = (typeof json["budgets"] === "object" && json["budgets"] !== null ? { ...(json["budgets"] as Record<string, unknown>) } : {}) as Record<string, unknown>;
  // The fix budget: what the implementer names, else what is configured, else 0 written explicitly (delegated fixes off).
  const fixes = maxFixes ?? (typeof budgets["max_fixes_per_run"] === "number" ? (budgets["max_fixes_per_run"] as number) : 0);
  if (budgets["max_fixes_per_run"] !== fixes) {
    budgets["max_fixes_per_run"] = fixes;
    changes.push(`budgets.max_fixes_per_run = ${fixes}`);
  }
  const next = { ...json, allowed_roots: roots, budgets };
  parseUserConfig(next); // the merged file must validate before anything is written
  if (changes.length && !a.has("--dry-run")) await atomicWriteFile(path, `${JSON.stringify(next, null, 2)}\n`);
  io.out(`config.json (${path}): ${changes.length ? `${a.has("--dry-run") ? "would set" : "set"} ${changes.join("; ")}` : "already covers this repository"}.`);
  io.out(`delegated fixes per protected run: ${fixes}${fixes === 0 ? " (off; `code-parley init --repo <path> --max-fixes <n>` enables them)" : ""}. A Claude Code session reads config.json when it starts: restart open sessions.`);

  // What is left, in order: the implementer's local steps with their state, then the operator's.
  const steps: string[] = [];
  const ev = evaluateProject(await loadTrustProjects(le.layout.trustProjects), root, await readRootCommit({ gitExe: await gitExeOf(le), repoRoot: root }).catch(() => null));
  steps.push(ev.status === "approved"
    ? `checks: approved (${[...ev.checks.keys()].sort().join(", ") || "none"})`
    : `checks: ${ev.status} — review and approve them: code-parley checks list --repo ${root}; code-parley checks approve --repo ${root} --from-proposals`);
  steps.push(`Codex self-test (S1) on this account and boot: code-parley codex selftest${process.platform === "win32" ? " (in an interactive desktop session)" : ""}${fixes > 0 ? "; for delegated fixes also: code-parley codex fix-selftest" : ""}`);
  const linux = process.platform === "linux";
  if (linux) {
    steps.push(`the proposals the operator confirms (the operator cannot read your data home): code-parley config propose --repo ${root} --out <file>; code-parley config propose-selftest --repo ${root} --out <file2>${fixes > 0 ? `; code-parley config propose-selftest --fix --repo ${root} --out <file3>` : ""}`);
  }
  steps.push(linux
    ? `an administrator, once per repository: sudo bash codeparley-installer.sh grant-repository --path ${root}`
    : `an administrator, once per repository: codeparley-installer.ps1 grant-repository -Path "${root}" (elevated PowerShell)`);
  const op = operatorCli();
  const installedRuntime = le.env.testHooks ? null : await installedEngineRuntime();
  steps.push(linux
    ? `the operator account: ${op} setup --repo ${root} --proposal-file <file> --proposal-file <file2>${fixes > 0 ? " --proposal-file <file3>" : ""} [--loops <1-8> --minutes <1-180>]`
    // On Windows the operator's setup reads this account's approved checks and stored self-tests from its data home.
    : `the operator, in an elevated terminal: ${op} setup --repo ${root} --home "${le.dataHome}"${fixes > 0 ? " --fix" : ""} --runtime "${installedRuntime ?? `${process.env["ProgramFiles"] ?? "C:\\Program Files"}\\CodeParley\\engine\\<version>`}" --runtime-git-path <installed git.exe> [--loops <1-8> --minutes <1-180>]`);
  steps.push(`the plugin, once per account: extract the release's plugin-${linux ? "linux" : "windows"} archive to <dir>, then: claude plugin marketplace add <dir>; claude plugin install code-parley@code-parley-local --scope user (and again after each upgrade)`);
  steps.push(`check: code-parley status --repo ${root}`);
  io.out("Next, in order:");
  steps.forEach((s, i) => io.out(`  ${i + 1}. ${s}`));
  io.out("init records no authority: every protected record is confirmed by the operator, typed at the operator's own terminal.");
  return 0;
}

// ---------------------------------------------------------------------------
// setup (the operator)
// ---------------------------------------------------------------------------

interface Proposals {
  repository: string | null;
  s1: string | null;
  fix: string | null;
}

/** Route each --proposal-file by what it proposes (the step's own reader validates it fully). */
async function proposalsOf(files: readonly string[]): Promise<Proposals> {
  const p: Proposals = { repository: null, s1: null, fix: null };
  for (const f of files) {
    let o: { recordKind?: unknown; payload?: { mode?: unknown } };
    try {
      o = JSON.parse(await readFile(f, "utf8")) as typeof o;
    } catch (e) {
      throw new DomainError("INVALID_ARGUMENT", `the proposal file ${f} cannot be read as a proposal (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}). Nothing was recorded.`);
    }
    const slot = o.recordKind === "repository" ? "repository" : o.recordKind === "selftest_confirmation" ? (o.payload?.mode === "FIX" ? "fix" : "s1") : null;
    if (!slot) throw new DomainError("INVALID_ARGUMENT", `${f} is not a configuration proposal (repository or self-test confirmation). Nothing was recorded.`);
    if (p[slot]) throw new DomainError("INVALID_ARGUMENT", `two proposal files propose the same record (${p[slot]} and ${f}). Nothing was recorded.`);
    p[slot] = f;
  }
  return p;
}

type Step = { key: string; title: string; run: () => Promise<number> } | { key: string; title: string; blocked: string };

/** The next step for the records as the custodian reports them now, or null when nothing is left. */
function nextStep(le: Loaded, a: SetupArgs, io: CliIo, root: string, s: ProtectedStatus, props: Proposals, installed: string | null): Step | null {
  const recs = s.repository!.records;
  const rec = (n: RecordState["record"]) => recs.find((r) => r.record === n)!;
  const resume = a.has("--resume");
  const linux = process.platform === "linux" && !le.env.testHooks;
  const flags = (m: Record<string, string | undefined>, bools: string[] = []) => ({
    one: (f: string) => (f in m ? m[f] : a.one(f)),
    has: (f: string) => bools.includes(f),
  });
  const config = (cmd: string, m: Record<string, string | undefined>, refs: string[] = [], bools: string[] = []) => () =>
    runConfigCli({ cmd, refs, ...flags({ "--repo": root, ...m }, bools) }, io);
  // In --resume, a record that was never set up is named, not created.
  const wanted = (r: RecordState) => r.state !== "in_force" && (!resume || r.resumable);

  const repo = rec("repository");
  const runtime = rec("engine_runtime");
  const iso = rec("isolation");
  // A runtime an upgrade replaced is approved anew FIRST: a re-confirmation covering it would be refused (CONFIG_MISMATCH).
  const approveRuntime = wanted(runtime) && runtime.state !== "lapsed";
  // A lapsed repository record is re-confirmed with every lapsed global record it rests on, in one rendering.
  if (!approveRuntime && repo.state === "lapsed") return { key: "reconfirm", title: "re-confirm the repository's configuration (and the global records that lapsed with it)", run: config("reconfirm", {}) };
  if (runtime.state === "lapsed") {
    const id = /runtime (\S+)/.exec(runtime.detail)?.[1];
    return { key: "reconfirm-runtime", title: "re-confirm the engine runtime approval", run: config("reconfirm-runtime", {}, id ? [id] : []) };
  }
  if (approveRuntime) {
    // The installed engine runtime's versioned directory by default (on Linux never the `current` link: the custodian
    // does not follow links); the custodian renders what it measured there for the operator's confirmation.
    const dir = a.one("--runtime") ?? installed ?? undefined;
    const gitPath = a.one("--runtime-git-path") ?? (linux && !a.one("--runtime-git") ? "/usr/bin/git" : undefined);
    const git = a.one("--runtime-git");
    if (!dir && linux) return { key: "approve-runtime", title: "approve the engine runtime", blocked: `${LINUX_ENGINE_CURRENT} names no installed engine runtime: install it (codeparley-installer.sh install), or name it: ${operatorCli()} setup --repo ${root} --runtime /opt/codeparley/engine/<version>` };
    if (!dir || (!gitPath && !git)) return { key: "approve-runtime", title: "approve the engine runtime", blocked: `name it: ${operatorCli()} setup --repo ${root} --runtime <the installed engine directory, e.g. ${process.env["ProgramFiles"] ?? "C:\\Program Files"}\\CodeParley\\engine\\<version>> --runtime-git-path <installed git.exe>` };
    return { key: "approve-runtime", title: "approve the engine runtime the custodian's helper runs (the custodian measures every file; this takes a while)", run: config("approve-runtime", { "--runtime": dir, "--runtime-git-path": gitPath, "--runtime-git": git }) };
  }
  if (wanted(repo) || repo.state === "changed") {
    if (resume && repo.state === "missing") return null;
    if (linux && !props.repository) return { key: "set", title: "set the repository's protected configuration", blocked: `the implementer writes its proposal first (code-parley config propose --repo ${root} --out <file>); pass it with --proposal-file <file>` };
    return { key: "set", title: "set the repository's protected configuration (the approved checks, the capture rules and the Codex installation)", run: config("set", { "--proposal-file": props.repository ?? undefined, "--codex": a.one("--codex") }) };
  }
  if (wanted(iso)) {
    if (linux && !props.s1) return { key: "confirm-selftest", title: "confirm the S1 self-test", blocked: `the implementer runs \`code-parley codex selftest\` and writes its proposal (code-parley config propose-selftest --repo ${root} --out <file>); pass it with --proposal-file <file>` };
    // On Windows a lapsed S1 confirmation is re-confirmed with the repository's record; one still lapsed alone is confirmed anew.
    return { key: "confirm-selftest", title: "confirm the stored S1 self-test (the basis of Codex's isolation in protected reviews)", run: config("confirm-selftest", { "--proposal-file": props.s1 ?? undefined, "--backend": a.one("--backend"), "--codex": a.one("--codex") }) };
  }
  if (a.has("--fix") && wanted(rec("fix_confirmation"))) {
    if (linux && !props.fix) return { key: "confirm-fix", title: "confirm the FIX self-test", blocked: `the implementer runs \`code-parley codex fix-selftest\` and writes its proposal (code-parley config propose-selftest --fix --repo ${root} --out <file>); pass it with --proposal-file <file>` };
    return { key: "confirm-fix", title: "confirm the stored FIX self-test (delegated fixes)", run: config("confirm-selftest", { "--proposal-file": props.fix ?? undefined, "--backend": a.one("--backend"), "--codex": a.one("--codex") }, [], props.fix ? [] : ["--fix"]) };
  }
  const grant = rec("loop_grant");
  if (!a.has("--no-grant") && grant.state !== "in_force" && (!resume || grant.resumable)) {
    return { key: "allow", title: "grant automated loops for this repository (the originating Claude Code session keeps working on its own within the grant)", run: () => runLoopCli({ cmd: "allow", refs: [], ...flags({ "--repo": root }) }, io) };
  }
  return null;
}

async function setup(le: Loaded, a: SetupArgs, io: CliIo): Promise<number> {
  const raw = a.one("--repo");
  if (!raw) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley setup --repo <path> [--resume] [--fix] [--codex <exe>] [--backend <b>] [--proposal-file <file>]... [--runtime <dir> --runtime-git-path <git>] [--loops <n> --minutes <m> | --no-grant]");
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", "setup records the operator's records, each confirmed by typing at an interactive terminal: run it yourself in a terminal (no flag skips the confirmations). Nothing was recorded.");
  const root = await repositoryOf(le, raw);
  const props = await proposalsOf(a.many("--proposal-file"));
  io.out(`Setting up ${root} for protected runs${a.has("--resume") ? " (resume: only what lapsed, changed or was suspended)" : ""}. Each step shows the custodian's rendering of one record and asks for your typed confirmation; anything but "confirm" stops here and records nothing further.`);
  const done = new Set<string>();
  let n = 0;
  for (;;) {
    const s = await protectedStatus(le, { repositoryRoot: root });
    if (s.state !== "ready") {
      s.explanation.forEach((l) => io.err(l));
      if (s.state === "busy") io.err(`Run setup again when the custodian answers (\`code-parley status\`).`);
      remedyLines(s.state === "busy" ? "CUSTODIAN_BUSY" : s.state === "untrusted" ? "SERVER_NOT_TRUSTED" : "CUSTODIAN_UNAVAILABLE").forEach((l) => io.err(l));
      return 1;
    }
    if (s.repository?.read_on === "operator" && s.repository.records.length === 0) {
      // The custodian could not read this repository's records: there is nothing to step through.
      s.explanation.forEach((l) => io.err(l));
      io.err("Nothing was recorded.");
      return 1;
    }
    if (s.repository?.read_on !== "operator") {
      io.err(`setup records the operator's records on the operator surface, which this account does not reach. Run it as the operator: ${operatorCli()} setup --repo ${root}${process.platform === "win32" ? " in an elevated terminal" : ""}.`);
      return 1;
    }
    const step = nextStep(le, a, io, root, s, props, le.env.testHooks ? null : await installedEngineRuntime());
    if (!step) break;
    if (done.has(step.key)) {
      // A step that completed must change what the custodian reports; if it did not, stop rather than loop.
      io.err(`The custodian still reports the record of step "${step.title}" as not in force after it was recorded. Stopping; \`code-parley status --repo ${root}\` shows the records.`);
      return 1;
    }
    n++;
    io.out("");
    io.out(`Step ${n}: ${step.title}.`);
    if ("blocked" in step) {
      io.out(`  Not possible yet: ${step.blocked}. Nothing further was recorded.`);
      return 2;
    }
    let code: number;
    try {
      code = await step.run();
    } catch (e) {
      if (isDomainError(e)) {
        io.err(`error ${e.code}: ${e.message}`);
        remedyLines(e.code, process.platform, e.message).forEach((l) => io.err(l));
        io.err("Stopped here; the steps before this one stay recorded.");
        return 1;
      }
      throw e;
    }
    if (code !== 0) {
      io.out(code === 2 ? "Stopped: not confirmed. Nothing further was recorded; run setup again to continue." : "Stopped here; the steps before this one stay recorded.");
      return code;
    }
    done.add(step.key);
  }
  const s = await protectedStatus(le, { repositoryRoot: root });
  io.out("");
  renderStatus(s).forEach((l) => io.out(l));
  if (s.repository?.state === "ready") io.out(`${root} is set up for protected runs. ${n === 0 ? "Nothing needed recording." : ""}`.trim());
  if (s.state === "busy") io.out(BUSY_LIMITATION);
  return s.repository?.state === "ready" ? 0 : 1;
}
