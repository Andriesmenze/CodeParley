// `code-parley` CLI (plan §5.1, §14.2, §16.4). The CLI is the ONLY channel through which
// checks are approved or revoked and an unresolved worktree lock is released: there is no
// MCP tool and no elicitation for either (M1). I/O is injected so the commands are testable.
//
//   checks list    --repo <path>
//   checks approve --repo <path> (--from-proposals | --file <defs.json>)
//                  [--required-profile <name>]... [--no-required-checks] [--test-glob <g>]...
//                  [--confirm <digest-prefix>]
//   checks revoke  --repo <path> [--confirm <digest-prefix>]
//   lock show      --repo <path>
//   lock release   --repo <path> [--confirm <operation-id-prefix>] [--force]
//   codex probe | selftest | accept-reduced-isolation | revoke-reduced-isolation (codex-commands.ts)
//   runs list | show | stop | purge (runs-commands.ts; M1.6)
//   decide | amend (user-commands.ts; Phase 2.3): the user's own decisions and task amendments,
//                  recorded only at an interactive terminal (no flag skips the typed confirmation)
//   config show | set | reconfirm | revoke | accept-isolation | confirm-selftest | revoke-isolation | revoke-selftest | approve-runtime | reconfirm-runtime | revoke-runtime
//                  (config-commands.ts; P3.4C-4): the configuration the custodian holds for protected runs
//   loop grants | allow | revoke | show | stop | resume (loop-commands.ts; Phase 3.3a): the
//                  operator's channel for same-session continuation (allow/resume: interactive only;
//                  P3.4C-0: grants are held by the Windows custodian, allow/revoke need its operator
//                  surface — an elevated terminal — and every other platform is refused)
//   global:        --home <dir>  --git <git.exe>
//
// Approval shows every argv, cwd, environment, passthrough name, freshness input and the
// executable each command resolves to now, states what approval means, and is bound to the
// digest of exactly what was shown: a non-interactive approval must quote that digest
// (`--confirm`), so definitions that change between display and approval are refused.

import { readFile } from "node:fs/promises";
import type { EngineTestHooks } from "../engine/engine-env.js";
import { DomainError, isDomainError } from "../common/errors.js";
import { TOOL_VERSION } from "../common/version.js";
import { resolveDataHome, storeLayout, worktreeLockPath, canonicalPathKey } from "../store/paths.js";
import { selfOwner, classifyOwnerLiveness, OWNER_LIVENESS_DEPS } from "../store/owner.js";
import { clearWorktreeOwnership, readWorktreeLock, type WorktreeLockInfo } from "../store/locks.js";
import { resolveNativeExecutable } from "../process/native-resolve.js";
import { describeKind, resolveCommand, displayCommandLine, printable } from "../process/command.js";
import { snapshotProcessTable, findDescendants } from "../process/proc-table.js";
import { buildChildEnv, lookupEnv } from "../process/env.js";
import { ticksOfIdentity } from "../process/linux-proc.js";
import { canonicalizePath, pathKey } from "../workspace/paths.js";
import { loadConfig } from "../config/load-config.js";
import { resolveGitTopLevel } from "../workspace/git-toplevel.js";
import { readRootCommit } from "../capture/root-commit.js";
import { loadTrustProjects, trustKeyFor, updateTrustProjects } from "../config/trusted-projects.js";
import {
  buildApprovedEntry,
  evaluateProject,
  pendingApprovals,
  type ProjectEvaluation,
} from "../checks/project-config.js";
import { ApprovalInputSchema, type CheckDefinition } from "../schemas/checks.js";
import { runCodexCli } from "./codex-commands.js";
import { runRunsCli } from "./runs-commands.js";
import { runUserCli } from "./user-commands.js";
import { runLoopCli } from "./loop-commands.js";
import { runConfigCli, runConfigProposeCli } from "./config-commands.js";
import { runFixCli } from "./fix-commands.js";
import { runSetupCli } from "./setup-commands.js";
import { doctor, protectedDoctor } from "../engine/doctor.js";
import { renderStatus } from "./setup-commands.js";
import { ensurePrivateDataHome, gitExeOf, loadEngine } from "../engine/engine-env.js";
import { selfOwner as ownerForDoctor } from "../store/owner.js";
import { readRepoProposals } from "../checks/proposals.js";
import { assertOperatorCodeTrusted, isOperatorCommand } from "./operator-trust.js";
import { custodianServicePresence } from "../custodian/service-presence.js";
import { remedyLines } from "../common/remedies.js";

export interface CliIo {
  out(line: string): void;
  err(line: string): void;
  /** Ask the user; null when there is no interactive terminal. */
  prompt: ((question: string) => Promise<string>) | null;
  /**
   * Phase 2.3: stdin AND stdout are terminals (absent: not). User decisions and amendments are
   * recorded only then, with the confirmation typed there (P2.3-1).
   */
  interactive?: boolean;
  env: NodeJS.ProcessEnv;
  cwd: string;
  /**
   * TEST ONLY: engine test hooks for the commands that load the engine (P3.4C-0: a simulated grant
   * custodian). The CLI's own entry point never sets this, and nothing in configuration or the
   * environment can.
   */
  engineTestHooks?: EngineTestHooks;
}

export const APPROVAL_STATEMENT =
  "Approving lets these commands run this repository's code, including future changes to that code, with your user privileges. " +
  "They can modify or delete files and use the network. Approval is ongoing permission to execute these configured project commands; " +
  "it is not a judgement that future repository code is safe. Checks run outside any sandbox.";

interface Parsed {
  positional: string[];
  flags: Map<string, string[]>;
}

const VALUE_FLAGS = new Set(["--max-fixes", "--out", "--proposal-file", "--repo", "--file", "--required-profile", "--test-glob", "--confirm", "--home", "--git", "--codex", "--backend", "--acceptance", "--config", "--allowed-root", "--operation", "--reason", "--wait", "--older-than", "--events", "--note", "--request-id", "--text", "--text-file", "--thread", "--replaces", "--loops", "--minutes", "--runtime", "--runtime-git", "--runtime-git-path"]);
const BOOL_FLAGS = new Set(["--resume", "--no-grant", "--from-proposals", "--no-required-checks", "--force", "--json", "--abort", "--close", "--dry-run", "--retention", "--reveal-withheld", "--protected", "--fix", "--restore", "--leave", "--help"]);

function parseArgs(argv: readonly string[]): Parsed {
  const out: Parsed = { positional: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (VALUE_FLAGS.has(a)) {
      const v = argv[++i];
      if (v === undefined) throw new DomainError("INVALID_ARGUMENT", `${a} requires a value`);
      out.flags.set(a, [...(out.flags.get(a) ?? []), v]);
    } else if (BOOL_FLAGS.has(a)) {
      out.flags.set(a, ["true"]);
    } else if (a.startsWith("--")) {
      throw new DomainError("INVALID_ARGUMENT", `unknown option: ${a}`);
    } else out.positional.push(a);
  }
  return out;
}

const one = (p: Parsed, f: string): string | undefined => p.flags.get(f)?.at(-1);
const many = (p: Parsed, f: string): string[] => p.flags.get(f) ?? [];
const has = (p: Parsed, f: string): boolean => p.flags.has(f);

export const USAGE = [
  "usage: code-parley <command> [options]",
  "  init           --repo <path> [--max-fixes <0-10>] [--dry-run]   (the implementer: config.json's allowed roots and fix budget, then the steps left, in order)",
  "  status         [--repo <path>] [--json]   (anyone: the custodian's state; for a repository, each operator record and the command that restores it)",
  "  setup          --repo <path> [--resume] [--fix] [--codex <exe>] [--backend <b>] [--proposal-file <file>]... [--runtime <dir> --runtime-git-path <git>] [--loops <n> --minutes <m> | --no-grant]",
  "                 (the operator, interactive: the existing operator steps in order, each record rendered by the custodian and confirmed by you)",
  "  checks list    --repo <path>",
  "  checks approve --repo <path> (--from-proposals | --file <defs.json>) [--required-profile <name>]... [--no-required-checks] [--test-glob <glob>]... [--confirm <digest>]",
  "  checks revoke  --repo <path> [--confirm <digest>]",
  "  lock show      --repo <path>",
  "  lock release   --repo <path> [--confirm <operation-id>] [--force]",
  "  codex probe    [--codex <codex executable>]",
  "  codex selftest [--backend mxc|elevated|unelevated (Windows) | bwrap (Linux)] [--codex <codex executable>]",
  "  codex fix-selftest [--backend mxc (Windows)] [--codex <codex executable>]   (the writable cp_fix fixer profile, for delegated fixes)",
  "  codex accept-reduced-isolation --backend <b> [--confirm <digest>]",
  "  codex revoke-reduced-isolation [--acceptance <id>]",
  "  doctor         [--protected [--repo <path>]] [--codex <codex executable>] [--config <file>] [--allowed-root <dir>]... [--json]",
  "  runs list      [--repo <path>] [--json]",
  "  runs show      <run-id> [--events <n>] [--reveal-withheld] [--json]",
  "  runs stop      <run-id> --operation <operation-id> [--reason <text>] [--wait <seconds>]",
  "  runs stop      <run-id> --abort [--operation <operation-id>] [--reason <text>]",
  "  runs stop      <run-id> --close [--reason <text>]",
  "  runs stop      <full-run-id> (--close | --abort) --repo <path> [--reason <text>]   (operator: ends the run at the custodian, reading no run store)",
  "  runs purge     (<run-id>... | --older-than <days> | --retention) [--repo <path>] [--dry-run] [--confirm <token>] [--json]",
  "  decide         <run-id> [<thread> [require-resolution | waive | defer | revoke]] [--note <text>] [--protected] [--request-id <id>] [--json]",
  "  decide         <run-id> … --repo <path>   (a protected run as the custodian holds it: structure only; the record is protected)",
  "  amend          <run-id> … --repo <path>   (a protected run as the custodian holds it: the custodian redacts the text and holds what Codex sees)",
  "  amend          <run-id> [scope | constraint | acceptance-criteria | priority | clarification | withdrawal] (--text <text> | --text-file <file>) [--thread <thread>]... [--replaces <A-n>] [--protected] [--request-id <id>] [--json]",
  "  (decide and amend record only at an interactive terminal, with the confirmation typed by you; listings work anywhere)",
  "  loop grants    [--json]   (the custodian's grants and ceilings)",
  "  loop allow     --repo <path> [--loops <n, 1-8>] [--minutes <m, 1-180>] [--request-id <id>]   (elevated, interactive terminal only)",
  "  loop revoke    --repo <path>   (elevated terminal)",
  "  loop show      <run-id> [--repo <path>] [--json]",
  "  loop stop      <run-id> [--repo <path>] [--reason <text>]   (also acknowledges an unreconciled loop start)",
  "  (loop grants are held by the CodeParley custodian on Windows and Linux; without a validated custodian they are refused)",
  "  loop resume    <run-id> [--repo <path>]   (interactive terminal only; after a restart of the OS it offers the configuration's re-confirmation first)",
  "  (with --repo the run is the one the custodian holds for that repository: for an operator who cannot read the implementer's run store)",
  "  config show    --repo <path> [--json]   (the configuration the custodian holds for protected runs)",
  "  config set     --repo <path> [--codex <codex.exe> | --proposal-file <file>]   (import the approved checks, capture rules and Codex installation; elevated, interactive)",
  "  config propose --repo <path> --out <file> [--codex <exe>] | config propose-selftest [--fix] --repo <path> --out <file> [--backend <b>] [--codex <exe>]",
  "                 (the implementer writes the payload the operator passes with --proposal-file; Linux: the operator cannot build it)",
  "  config reconfirm --repo <path>   (after a restart of the OS; elevated, interactive)",
  "  config revoke  --repo <path>   (elevated, interactive)",
  "  config accept-isolation --repo <path> --backend <b> [--codex <exe>] | config confirm-selftest [--fix] --repo <path> (--backend <b> [--codex <exe>] | --proposal-file <file>)",
  "  config approve-runtime --repo <path> --runtime <dir> (--runtime-git <rel git.exe> | --runtime-git-path <installed git.exe>)   (approve the engine runtime the custodian's helper runs; elevated, interactive)",
  "  config reconfirm-runtime | revoke-runtime --repo <path> <runtime-id>",
  "  config revoke-isolation --repo <path> <acceptance-id> | config revoke-selftest --repo <path> <confirmation-id>",
  "  fix show       <run-id> [<proposal>] [--repo <path>]   (a delegated fix: the custodian's exact rendering of its proposal; with --repo, the run as the custodian holds it)",
  "  fix confirm    <run-id> <proposal> --repo <path>   (confirm exactly the rendered content, single use; operator, interactive)",
  "  fix reject     <run-id> <proposal> --repo <path>   (close the proposal; operator, interactive)",
  "  fix reconcile  <run-id> [--restore | --leave]   (an interrupted application: report, then restore or leave and record it)",
  "  global options: --home <data dir>  --git <git executable>  --config <file>",
  "  exit codes: 0 ok, 1 error, 2 confirmation required, 3 cancellation requested but termination not confirmed, 4 the stop did not establish that no confirmed fix can run",
];

/** Run the CLI; returns the process exit code (0 ok, 1 error, 2 confirmation required). */
export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  let p: Parsed;
  try {
    p = parseArgs(argv);
  } catch (e) {
    io.err((e as Error).message);
    USAGE.forEach((l) => io.err(l));
    return 1;
  }
  const [group, cmd, ...rest] = p.positional;
  if (group === undefined || group === "help" || has(p, "--help")) {
    USAGE.forEach((l) => io.out(l));
    return group === undefined && !has(p, "--help") ? 1 : 0;
  }
  try {
    // Phase 5 G-OP: on a Linux host WITH the custodian installed, an operator command runs only from the approved runtime with
    // the wrapper's clean environment, checked before anything else ("unknown" presence counts as installed: fail closed).
    // Without a custodian, decide/amend remain the Phase 2.3 local interface (D-14: manual review stays available
    // everywhere). A test passes its injected custodian instead; the entry point never does.
    if (process.platform === "linux" && isOperatorCommand(group, cmd, one(p, "--repo") !== undefined) && !io.engineTestHooks && (await custodianServicePresence()) !== "absent") assertOperatorCodeTrusted(io.env);
    // Linux: the data home is private (0700) before any command writes into it (plan §1.13).
    if (process.platform === "linux") await ensurePrivateDataHome(resolveDataHome({ home: one(p, "--home") ?? null, env: io.env }).dataHome);
    if (group === "runs") return await runRunsCli({ cmd, refs: rest, one: (f) => one(p, f), has: (f) => has(p, f) }, io);
    if (group === "loop") return await runLoopCli({ cmd, refs: rest, one: (f) => one(p, f), has: (f) => has(p, f) }, io);
    // Phase 5 F-3: the implementer writes a configuration proposal (no custodian contact); the operator's config commands take it.
    if (group === "config" && (cmd === "propose" || cmd === "propose-selftest")) return await runConfigProposeCli({ cmd, refs: rest, one: (f) => one(p, f), has: (f) => has(p, f) }, io);
    if (group === "config") return await runConfigCli({ cmd, refs: rest, one: (f) => one(p, f), has: (f) => has(p, f) }, io);
    // Phase 4 Increment 3: a delegated fix's show / confirm / reject (operator) and reconcile (implementer).
    if (group === "fix") return await runFixCli({ cmd, refs: rest, one: (f) => one(p, f), has: (f) => has(p, f) }, io);
    if (group === "decide" || group === "amend") return await runUserCli({ group, refs: [cmd, ...rest].filter((x): x is string => x !== undefined), one: (f) => one(p, f), many: (f) => many(p, f), has: (f) => has(p, f) }, io);
    if (group === "checks" && cmd === "list") return await checksList(p, io);
    if (group === "checks" && cmd === "approve") return await checksApprove(p, io);
    if (group === "checks" && cmd === "revoke") return await checksRevoke(p, io);
    if (group === "lock" && cmd === "show") return await lockShow(p, io);
    if (group === "lock" && cmd === "release") return await lockRelease(p, io);
    if (group === "doctor") return await doctorCmd(p, io);
    // Phase 6 Increment 3: setup, status and init (setup-commands.ts). They take no subcommand: `cmd` would be a stray word.
    if (group === "init" || group === "status" || group === "setup") {
      if (cmd !== undefined) throw new DomainError("INVALID_ARGUMENT", `${group} takes no subcommand (got "${cmd}")`);
      return await runSetupCli({ group, one: (f) => one(p, f), many: (f) => many(p, f), has: (f) => has(p, f) }, io);
    }
    if (group === "codex") {
      return await runCodexCli({ cmd, home: one(p, "--home"), codex: one(p, "--codex"), backend: one(p, "--backend"), confirm: one(p, "--confirm"), acceptance: one(p, "--acceptance") }, io);
    }
    USAGE.forEach((l) => io.err(l));
    return 1;
  } catch (e) {
    io.err(isDomainError(e) ? `error ${e.code}: ${e.message}` : `error: ${(e as Error).message}`);
    // Phase 6 Increment 3: the cause and the fix, from the remediation catalog (wording only).
    if (isDomainError(e)) remedyLines(e.code, process.platform, e.message).forEach((l) => io.err(l));
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Shared context
// ---------------------------------------------------------------------------

interface RepoContext {
  repoRoot: string;
  rootCommit: string | null;
  gitExe: string;
  trustProjectsPath: string;
  dataHome: string;
  /** The trusted confidentiality exclusions (capture.exclude_globs), as the server applies them. */
  excludeGlobs: string[];
}

async function repoContext(p: Parsed, io: CliIo): Promise<RepoContext> {
  const { dataHome, configFile } = resolveDataHome({ home: one(p, "--home") ?? null, env: io.env });
  const layout = storeLayout(dataHome, configFile);
  // The same configuration the server loads: a repository preferences file that the user's
  // exclusions classify as confidential is neither read nor printed here either (PR #2 review).
  // An invalid configuration fails the command rather than reading without exclusions.
  const cfg = await loadConfig({ allowedRoots: [], diagnostics: false, ...(one(p, "--home") ? { home: one(p, "--home")! } : {}), ...(one(p, "--config") ? { configFile: one(p, "--config")! } : {}) }, io.env);
  const g = await resolveNativeExecutable("git", { configured: one(p, "--git") ?? null, env: buildChildEnv({ source: io.env }).env });
  if (!g.ok || !g.path) throw new DomainError("GIT_NOT_FOUND", g.error ?? "git not found");
  const raw = one(p, "--repo") ?? io.cwd;
  const canon = await canonicalizePath(raw);
  const repoRoot = await resolveGitTopLevel(canon, { gitExe: g.path });
  const rootCommit = await readRootCommit({ gitExe: g.path, repoRoot });
  return { repoRoot, rootCommit, gitExe: g.path, trustProjectsPath: layout.trustProjects, dataHome, excludeGlobs: cfg.config.capture.exclude_globs };
}

async function evaluate(rc: RepoContext): Promise<ProjectEvaluation> {
  return evaluateProject(await loadTrustProjects(rc.trustProjectsPath), rc.repoRoot, rc.rootCommit);
}

function confirmMatches(given: string | undefined, digest: string): boolean {
  return !!given && given.length >= 12 && digest.startsWith(given.toLowerCase());
}

// ---------------------------------------------------------------------------
// checks list
// ---------------------------------------------------------------------------

async function checksList(p: Parsed, io: CliIo): Promise<number> {
  const rc = await repoContext(p, io);
  const ev = await evaluate(rc);
  io.out(`repository: ${rc.repoRoot}`);
  io.out(`root commit: ${rc.rootCommit ?? "(none: unborn HEAD)"}`);
  io.out(`trusted configuration: ${ev.status}${ev.approval ? ` (approved ${ev.approval.at}, digest ${ev.approval.digest.slice(0, 16)})` : ""}`);
  for (const pr of ev.problems) io.out(`  problem: ${pr}`);
  for (const c of [...ev.checks.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    io.out(`  check ${c.name} [${c.state}]${c.definition ? `: ${JSON.stringify(c.definition.argv)}` : ""}`);
    for (const pr of c.problems) io.out(`    problem: ${pr}`);
  }
  for (const r of ev.removed) io.out(`  check ${r} [removed since approval]`);
  for (const [name, list] of Object.entries(ev.profiles)) io.out(`  profile ${name}: ${list.join(", ")}`);
  io.out(`verification floor: ${ev.noRequiredChecks ? "explicitly none (no_required_checks)" : ev.requiredProfiles.length ? `required profiles ${ev.requiredProfiles.join(", ")}` : "NOT CONFIGURED"}`);
  const proposals = await readRepoProposals(rc.repoRoot, { excludeGlobs: rc.excludeGlobs });
  if (proposals) {
    for (const w of proposals.warnings) io.out(`  proposal warning: ${w}`);
    for (const pa of pendingApprovals(proposals, ev)) io.out(`  pending approval (${pa.state}): ${pa.name} ${JSON.stringify(pa.argv_preview)}${pa.problems.length ? ` — ${pa.problems.join("; ")}` : ""}`);
  }
  const lock = await readWorktreeLock(worktreeLockPath(rc.dataHome, canonicalPathKey(rc.repoRoot)));
  if (lock) io.out(`worktree lock: ${lock.kind} operation ${lock.operation_id}${lock.ownership_unresolved ? " — OWNERSHIP UNRESOLVED (see `lock show`)" : ""}`);
  return 0;
}

// ---------------------------------------------------------------------------
// checks approve
// ---------------------------------------------------------------------------

async function checksApprove(p: Parsed, io: CliIo): Promise<number> {
  const fromProposals = has(p, "--from-proposals");
  const file = one(p, "--file");
  if (fromProposals === (file !== undefined)) {
    io.err("choose exactly one source: --from-proposals or --file <defs.json>");
    return 1;
  }
  const rc = await repoContext(p, io);
  const current = await evaluate(rc);

  let checks: Record<string, unknown>;
  let profiles: Record<string, string[]> = {};
  let fileFloor: { required?: string[]; none?: boolean } = {};
  let testGlobs: string[] | undefined;
  if (file !== undefined) {
    let json: unknown;
    try {
      json = JSON.parse(await readFile(file, "utf8"));
    } catch (e) {
      io.err(`cannot read ${file}: ${(e as Error).message}`);
      return 1;
    }
    const parsed = ApprovalInputSchema.safeParse(json);
    if (!parsed.success) {
      io.err(`invalid definitions file: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
      return 1;
    }
    checks = parsed.data.checks;
    profiles = parsed.data.profiles;
    fileFloor = { ...(parsed.data.required_profiles ? { required: parsed.data.required_profiles } : {}), ...(parsed.data.no_required_checks !== undefined ? { none: parsed.data.no_required_checks } : {}) };
    testGlobs = parsed.data.test_globs;
  } else {
    const proposals = await readRepoProposals(rc.repoRoot, { excludeGlobs: rc.excludeGlobs });
    if (!proposals || Object.keys(proposals.checks).length === 0) {
      io.err("the repository proposes no checks (.code-parley/config.json proposed_checks)");
      return 1;
    }
    for (const w of proposals.warnings) io.out(`proposal warning: ${w}`);
    checks = proposals.checks;
    profiles = proposals.profiles;
  }

  // The verification floor comes from the user (flags or the user's own file). Repository
  // proposals cannot set it (plan §7.1 layer 7); otherwise the existing floor is kept.
  let required = many(p, "--required-profile");
  let none = has(p, "--no-required-checks");
  if (required.length === 0 && !none) {
    if (fileFloor.required || fileFloor.none !== undefined) {
      required = fileFloor.required ?? [];
      none = fileFloor.none === true;
    } else if (current.status !== "no_entry") {
      required = current.requiredProfiles;
      none = current.noRequiredChecks;
    }
  }
  const globs = many(p, "--test-glob").length ? many(p, "--test-glob") : (testGlobs ?? current.testGlobs);

  const built = buildApprovedEntry(
    { canonicalRoot: rc.repoRoot, rootCommit: rc.rootCommit, checks, profiles, requiredProfiles: required, noRequiredChecks: none, testGlobs: globs },
    new Date().toISOString(),
    TOOL_VERSION,
  );
  if (!built.ok) {
    io.err("cannot approve:");
    for (const pr of built.problems) io.err(`  - ${pr}`);
    return 1;
  }

  showApprovalPlan(io, rc, current, built.definitions, profiles, required, none, globs, built.digest);

  const confirm = one(p, "--confirm");
  let approved = confirmMatches(confirm, built.digest);
  if (confirm !== undefined && !approved) {
    io.err(`--confirm does not match the digest of what is shown (${built.digest.slice(0, 16)}); nothing was approved`);
    return 2;
  }
  if (!approved && io.prompt) approved = (await io.prompt('Type "approve" to approve exactly the definitions above: ')).trim() === "approve";
  if (!approved) {
    io.out(`Not approved. To approve exactly what is shown, re-run with --confirm ${built.digest.slice(0, 16)}`);
    return 2;
  }
  const owner = selfOwner();
  await updateTrustProjects(rc.trustProjectsPath, owner, (cur) => {
    const key = trustKeyFor(cur, rc.repoRoot);
    const next = { ...cur };
    for (const k of Object.keys(next)) if (pathKey(k) === pathKey(key) && k !== key) delete next[k];
    next[key] = built.entry;
    return next;
  });
  io.out(`approved ${Object.keys(built.definitions).length} check(s) for ${rc.repoRoot} (digest ${built.digest.slice(0, 16)})`);
  return 0;
}

function showApprovalPlan(
  io: CliIo,
  rc: RepoContext,
  current: ProjectEvaluation,
  defs: Record<string, CheckDefinition>,
  profiles: Record<string, string[]>,
  required: string[],
  none: boolean,
  globs: string[],
  digest: string,
): void {
  const env = buildChildEnv({ source: io.env }).env;
  io.out(`repository: ${rc.repoRoot}`);
  io.out(`root commit: ${rc.rootCommit ?? "(none: unborn HEAD)"}`);
  io.out("");
  io.out(APPROVAL_STATEMENT);
  io.out("");
  for (const [name, d] of Object.entries(defs)) {
    const cur = current.checks.get(name);
    const state = !cur ? "new" : cur.definition && JSON.stringify(cur.definition) === JSON.stringify(d) && cur.state === "approved" ? "unchanged" : "changed";
    const r = resolveCommand(d.argv[0]!, { relativeBase: rc.repoRoot, pathValue: lookupEnv({ ...env, ...d.env }, "PATH"), pathext: lookupEnv({ ...env, ...d.env }, "PATHEXT") });
    io.out(`check ${name} [${state}]`);
    io.out(`  argv:        ${JSON.stringify(d.argv)}`);
    io.out(`  as typed:    ${printable(displayCommandLine(d.argv))}`);
    io.out(`  resolves to: ${r.ok ? `${printable(r.command.path)} (${describeKind(r.command)})` : `NOT RESOLVABLE NOW: ${printable(r.reason)}`}`);
    io.out(`  cwd:         ${d.cwd}`);
    io.out(`  timeout:     ${d.timeout_seconds}s`);
    io.out(`  env:         ${Object.keys(d.env).length ? Object.entries(d.env).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" ") : "(none)"}`);
    io.out(`  passthrough: ${d.env_passthrough.length ? d.env_passthrough.join(", ") : "(none)"}`);
    io.out(`  freshness:   ${d.freshness_inputs.length ? d.freshness_inputs.join(", ") : "(none)"}`);
  }
  const removed = [...current.checks.keys(), ...current.removed].filter((n) => !(n in defs));
  for (const n of new Set(removed)) io.out(`check ${n} [will be REMOVED]`);
  for (const [n, list] of Object.entries(profiles)) io.out(`profile ${n}: ${list.join(", ")}`);
  io.out(`verification floor: ${none ? "explicitly none (no required checks)" : `required profiles ${required.join(", ")}`}`);
  if (globs.length) io.out(`test globs: ${globs.join(", ")}`);
  io.out(`approval digest: ${digest}`);
}

// ---------------------------------------------------------------------------
// checks revoke
// ---------------------------------------------------------------------------

async function checksRevoke(p: Parsed, io: CliIo): Promise<number> {
  const rc = await repoContext(p, io);
  const projects = await loadTrustProjects(rc.trustProjectsPath);
  const ev = evaluateProject(projects, rc.repoRoot, rc.rootCommit);
  if (ev.status === "no_entry") {
    io.out(`no trusted configuration for ${rc.repoRoot}`);
    return 0;
  }
  const token = ev.approval?.digest ?? "0".repeat(64);
  io.out(`revoking trusted checks for ${rc.repoRoot}: ${[...ev.checks.keys()].join(", ") || "(none)"}`);
  io.out("Existing runs keep their verification floor; removed required checks are reported as removed, never dropped.");
  let ok = confirmMatches(one(p, "--confirm"), token);
  if (!ok && io.prompt) ok = (await io.prompt('Type "revoke" to revoke: ')).trim() === "revoke";
  if (!ok) {
    io.out(`Not revoked. Re-run with --confirm ${token.slice(0, 16)}`);
    return 2;
  }
  await updateTrustProjects(rc.trustProjectsPath, selfOwner(), (cur) => {
    const next = { ...cur };
    for (const k of Object.keys(next)) if (pathKey(k) === pathKey(rc.repoRoot)) delete next[k];
    return next;
  });
  io.out("revoked");
  return 0;
}

// ---------------------------------------------------------------------------
// lock show / release (MR-C)
// ---------------------------------------------------------------------------

interface LockInspection {
  lock: WorktreeLockInfo;
  ownerLiveness: string;
  liveChildren: { pid: number; command_line: string }[];
  descendants: { pid: number; name: string; of: number }[];
  scanOk: boolean;
}

async function inspectLock(lock: WorktreeLockInfo): Promise<LockInspection> {
  const ownerLiveness = await classifyOwnerLiveness(lock.owner, OWNER_LIVENESS_DEPS);
  const liveChildren: LockInspection["liveChildren"] = [];
  for (const c of lock.children ?? []) {
    const l = await classifyOwnerLiveness({ serverInstanceId: "child", pid: c.pid, startedAtMs: c.startedAtMs, ...(c.startIdentity ? { startIdentity: c.startIdentity } : {}) }, { ...OWNER_LIVENESS_DEPS, toleranceMs: 3000 });
    if (l !== "dead") liveChildren.push({ pid: c.pid, command_line: c.command_line });
  }
  const table = await snapshotProcessTable();
  const descendants: LockInspection["descendants"] = [];
  if (table) {
    for (const c of lock.children ?? []) {
      // Linux: the child's exact start ticks, so a newer process holding its PID is never taken for it.
      const ticks = ticksOfIdentity(c.startIdentity);
      for (const d of findDescendants(table, { pid: c.pid, startedAtMs: c.startedAtMs - 1000, ...(ticks !== null ? { startTicks: ticks } : {}) })) descendants.push({ pid: d.pid, name: d.name, of: c.pid });
    }
  }
  return { lock, ownerLiveness, liveChildren, descendants, scanOk: table !== null };
}

function printInspection(io: CliIo, x: LockInspection): void {
  const l = x.lock;
  io.out(`worktree lock: kind ${l.kind}, operation ${l.operation_id}`);
  io.out(`  owner: server ${l.owner.serverInstanceId}, pid ${l.owner.pid} (${x.ownerLiveness})`);
  io.out(`  acquired ${l.acquired_at}, last heartbeat ${l.heartbeat_at}`);
  io.out(`  ownership unresolved: ${l.ownership_unresolved ? "YES" : "no"}`);
  for (const c of l.command_lines ?? []) io.out(`  recorded command: ${c}`);
  for (const c of l.children ?? []) io.out(`  recorded child: pid ${c.pid} started ${new Date(c.startedAtMs).toISOString()} ${c.command_line}`);
  for (const c of x.liveChildren) io.out(`  STILL RUNNING (recorded child): pid ${c.pid} ${c.command_line}`);
  for (const d of x.descendants) io.out(`  STILL RUNNING (descendant of ${d.of}): pid ${d.pid} ${d.name}`);
  if (!x.scanOk) io.out("  (the process table could not be read; descendants were not checked)");
  io.out("  Note: a descendant whose parent already exited cannot be linked to the check; inspect the recorded commands before releasing.");
}

async function lockShow(p: Parsed, io: CliIo): Promise<number> {
  const rc = await repoContext(p, io);
  const lock = await readWorktreeLock(worktreeLockPath(rc.dataHome, canonicalPathKey(rc.repoRoot)));
  if (!lock) {
    io.out(`no worktree lock for ${rc.repoRoot}`);
    return 0;
  }
  printInspection(io, await inspectLock(lock));
  return 0;
}

async function lockRelease(p: Parsed, io: CliIo): Promise<number> {
  const rc = await repoContext(p, io);
  const path = worktreeLockPath(rc.dataHome, canonicalPathKey(rc.repoRoot));
  const lock = await readWorktreeLock(path);
  if (!lock) {
    io.out(`no worktree lock for ${rc.repoRoot}`);
    return 0;
  }
  const x = await inspectLock(lock);
  printInspection(io, x);
  if (!lock.ownership_unresolved && x.ownerLiveness !== "dead") {
    io.err("the lock is held by a live (or unconfirmed) owner; it is not released. Stop that operation instead.");
    return 1;
  }
  if ((x.liveChildren.length > 0 || x.descendants.length > 0) && !has(p, "--force")) {
    io.err("processes started by the check are still running; end them first, or pass --force to release anyway");
    return 1;
  }
  let ok = confirmMatches(one(p, "--confirm")?.replace(/-/g, ""), lock.operation_id.replace(/-/g, ""));
  if (!ok && io.prompt) ok = (await io.prompt(`Type the operation id (${lock.operation_id}) to release: `)).trim() === lock.operation_id;
  if (!ok) {
    io.out(`Not released. After inspecting the commands above, re-run with --confirm ${lock.operation_id}`);
    return 2;
  }
  const cur = await readWorktreeLock(path);
  if (!cur || cur.operation_id !== lock.operation_id) {
    io.err("the lock changed while it was being inspected; nothing was released");
    return 1;
  }
  await clearWorktreeOwnership(path);
  io.out(`released the worktree lock of operation ${lock.operation_id}`);
  return 0;
}

// ---------------------------------------------------------------------------
// doctor (plan §2.2 #10; M1.5): setup diagnostics, read-only and offline
// ---------------------------------------------------------------------------

async function doctorCmd(p: Parsed, io: CliIo): Promise<number> {
  const launch = {
    allowedRoots: many(p, "--allowed-root"),
    diagnostics: false,
    ...(one(p, "--home") ? { home: one(p, "--home")! } : {}),
    ...(one(p, "--config") ? { configFile: one(p, "--config")! } : {}),
    ...(one(p, "--codex") ? { codex: one(p, "--codex")! } : {}),
    ...(one(p, "--git") ? { git: one(p, "--git")! } : {}),
  };
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: ownerForDoctor(), ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  const r = await doctor(le);
  // Phase 6 Increment 3: --protected adds the custodian's state, the repository's operator records and the host facts.
  if (has(p, "--repo") && !has(p, "--protected")) throw new DomainError("INVALID_ARGUMENT", "doctor --repo needs --protected");
  const repoRaw = one(p, "--repo");
  const prot = has(p, "--protected") ? await protectedDoctor(le, repoRaw ? await resolveGitTopLevel(await canonicalizePath(repoRaw), { gitExe: await gitExeOf(le) }) : null) : null;
  const ok = r.ok && (!prot || prot.problems.length === 0);
  if (has(p, "--json")) {
    io.out(JSON.stringify(prot ? { ...r, ok, protected: prot } : r, null, 2));
    return ok ? 0 : 1;
  }
  io.out(`code-parley ${r.tool_version} — node ${r.node.version} (${r.node.exec_path}), ${r.node.platform}`);
  io.out(`data home: ${r.data_home.path}${r.data_home.localappdata_fallback ? " (LOCALAPPDATA missing: USERPROFILE fallback)" : ""}${r.data_home.exists ? "" : " (not created yet)"}`);
  io.out(`config: ${r.config.path}; client roots ${r.config.client_roots}; waits ${r.config.waits.default_seconds}s default / ${r.config.waits.max_seconds}s max`);
  io.out(`allowed roots (effective): ${r.allowed_roots.effective.length ? r.allowed_roots.effective.join("; ") : "NONE"}`);
  io.out(`git: ${r.git.path ?? "not found"}${r.git.version ? ` (${r.git.version})` : ""}${r.git.error ? ` — ${r.git.error}` : ""}`);
  io.out(`codex: ${r.codex.path ?? "not found"}${r.codex.version ? ` ${r.codex.version} (${r.codex.supported ? "supported" : "UNSUPPORTED"})` : ""}${r.codex.error ? ` — ${r.codex.error}` : ""}`);
  for (const b of r.codex.backends) {
    io.out(`  backend ${b.backend}${b.preferred ? " (preferred)" : ""}: Gate A ${b.gate_a ?? "n/a"}; self-test ${b.selftest.stored ? `${b.selftest.s1_available ? "S1 AVAILABLE" : "S1 not available"}${b.selftest.failed_rows.length ? ` (failed: ${b.selftest.failed_rows.join(", ")})` : ""} at ${b.selftest.at}` : "not run yet"}`);
  }
  io.out(`  user hooks present: ${r.codex.user_hooks_present === null ? "unknown" : r.codex.user_hooks_present ? "YES" : "no"}; reduced-isolation acceptances: ${r.codex.reduced_isolation_acceptances}`);
  io.out(`store: ${r.store.runs} run(s), ${r.store.unreadable_runs} unreadable, ${r.store.running_operations} running operation(s), ${r.store.worktree_locks.length} worktree lock(s)`);
  const lp = r.retention.last_pass;
  io.out(`retention: ${r.retention.max_age_days} day(s), purge at server start ${r.retention.purge_on_startup ? "on" : "OFF"}; last pass ${lp ? `${lp.at}: ${lp.deleted} deleted, ${lp.kept} kept, ${lp.skipped} skipped, ${lp.incomplete} incomplete${lp.error ? `, ERROR ${lp.error}` : ""}` : "none recorded"}`);
  for (const n of r.notes) io.out(`note: ${n}`);
  io.out(`environment variables present (names only): ${r.environment_names_present.join(", ")}`);
  for (const pr of r.problems) io.out(`PROBLEM: ${pr}`);
  if (prot) {
    io.out("--- protected (the custodian; a display: it decides nothing) ---");
    renderStatus(prot.status).slice(0, -1).forEach((l) => io.out(l));
    if (prot.readers_grant) io.out(`repository readers grant: ${prot.readers_grant.present === null ? "unknown" : prot.readers_grant.present ? "present" : "MISSING"} (${prot.readers_grant.detail})`);
    if (prot.linux) io.out(`linux: admitted filesystems ${prot.linux.admitted_filesystems ?? "unknown"}; Codex bubblewrap AppArmor profile file ${prot.linux.apparmor_profile_file ? "installed" : "not installed"}`);
    for (const pr of prot.problems) io.out(`PROBLEM: ${pr}`);
  }
  const count = r.problems.length + (prot?.problems.length ?? 0);
  io.out(ok ? "doctor: OK" : `doctor: ${count} problem(s)`);
  return ok ? 0 : 1;
}
