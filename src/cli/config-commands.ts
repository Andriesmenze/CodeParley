// `code-parley config …` (P3.4C-4): the operator's channel for the configuration the custodian holds for PROTECTED runs.
//
//   config show             --repo <path> [--json]          the repository's record and the global records (read-only)
//   config set              --repo <path> [--codex <exe>]   import the approved local check configuration, the capture
//                                                           rules and the Codex installation (elevated, interactive)
//   config reconfirm        --repo <path>                   re-confirm after a restart of the OS (elevated, interactive)
//   config revoke           --repo <path>                   revoke the repository's record (elevated, interactive)
//   config accept-isolation --repo <path> --backend <b> [--codex <exe>]   accept reduced isolation (S2) for protected reviews
//   config confirm-selftest --repo <path> --backend <b> [--codex <exe>]   confirm the stored S1 self-test record by digest
//   config confirm-selftest --fix --repo <path> --backend <b> [--codex <exe>]   (Phase 4) confirm the stored cp_fix self-test
//                                                           record for delegated fixes (FIX; separate from S1)
//   config revoke-isolation --repo <path> <acceptance-id>   /   config revoke-selftest --repo <path> <confirmation-id>
//   config approve-runtime  --repo <path> --runtime <dir> --runtime-git <relative git.exe>   (P3.4C-5) approve the engine
//                                                           runtime the custodian's helper runs (the custodian measures it)
//   config reconfirm-runtime --repo <path> <runtime-id>  /  config revoke-runtime --repo <path> <runtime-id>
//   config propose          --repo <path> --out <file> [--codex <exe>]          (Phase 5 F-3; the IMPLEMENTER, not the
//   config propose-selftest [--fix] --repo <path> --out <file> [--backend <b>] [--codex <exe>]   operator) write the payload
//                                                           `config set` / `config confirm-selftest --proposal-file` takes
//
// Every change is the custodian's two-phase operator action: the custodian validates the proposal, computes every digest,
// measures the Codex installation through its own handle and renders the complete change; the operator confirms it by
// typing at an interactive terminal (no flag skips that — layering, not the boundary: the custodian accepts the change
// only from the elevated operator token, assurance L1). Attended runs are not affected: they keep the local files.

import { chmod, open, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { DomainError, isDomainError } from "../common/errors.js";
import { hostOperatorAssurance } from "../schemas/user-authority.js";
import { loadEngine, gitExeOf, type Loaded } from "../engine/engine-env.js";
import {
  acceptancePayload, codexInstallationPath, commitConfigChange, operatorConfigSection, prepareConfigChange, repositoryPayload, selftestPayload,
} from "../engine/config-authority.js";
import { REDUCED_ISOLATION_STATEMENT } from "../agents/codex/isolation.js";
import { fixSelftestPayload } from "../engine/fix-confirmation.js";
import { backendsFor, type SandboxBackend } from "../agents/codex/argv.js";
import type { ConfigAction, ConfigRecordKind, ConfigSection, PreparedConfigRecord } from "../custodian/protocol.js";
import { selfOwner } from "../store/owner.js";
import { canonicalizePath } from "../workspace/paths.js";
import { resolveGitTopLevel } from "../workspace/git-toplevel.js";
import { linuxOperatorRepo } from "./operator-trust.js";
import type { CliIo } from "./cli.js";

export interface ConfigArgs {
  cmd: string | undefined;
  refs: string[];
  one(flag: string): string | undefined;
  has(flag: string): boolean;
}

export const CONFIG_NOT_INTERACTIVE =
  "Protected configuration is recorded only at an interactive terminal, with the confirmation typed by you: run this command yourself in a terminal (stdin and stdout must be a terminal; there is no flag that skips this). Nothing was recorded.";

const NOT_ELEVATED =
  "The CodeParley custodian accepts configuration changes only from the operator surface with an elevated operator token: run this command in an elevated terminal (Run as administrator) as the operator account. Nothing was recorded.";

export async function runConfigCli(a: ConfigArgs, io: CliIo): Promise<number> {
  const launch = {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
  // P3.4C-4: the config commands are the operator's channel: a protected run's configuration is read on the OPERATOR surface (the
  // pipe the operator account reaches), as its user records are (P3.4C-3 asOperator).
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), custodianReadSurface: "operator", ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  if (a.has("--confirm")) throw new DomainError("INVALID_ARGUMENT", "config has no --confirm: you confirm by typing at an interactive terminal (nothing skips that)");
  try {
    switch (a.cmd) {
      case "show":
        return await show(le, a, io);
      case "set":
        return await set(le, a, io);
      case "reconfirm":
        return await reconfirmCmd(le, a, io);
      case "revoke":
        return await change(le, io, await repoRoot(le, a.one("--repo")), "repository", "revoke", null);
      case "accept-isolation":
        return await acceptIsolation(le, a, io);
      case "confirm-selftest":
        return await confirmSelftest(le, a, io);
      case "revoke-isolation":
        return await change(le, io, await repoRoot(le, a.one("--repo")), "isolation_acceptance", "revoke", recordRef(a));
      case "revoke-selftest":
        return await change(le, io, await repoRoot(le, a.one("--repo")), "selftest_confirmation", "revoke", recordRef(a));
      case "approve-runtime":
        return await approveRuntime(le, a, io);
      case "reconfirm-runtime":
        return await change(le, io, await repoRoot(le, a.one("--repo")), "engine_runtime", "reconfirm", recordRef(a, "reconfirm-runtime"));
      case "revoke-runtime":
        return await change(le, io, await repoRoot(le, a.one("--repo")), "engine_runtime", "revoke", recordRef(a, "revoke-runtime"));
      default:
        throw new DomainError("INVALID_ARGUMENT", "usage: code-parley config (show | set | reconfirm | revoke | accept-isolation | confirm-selftest | revoke-isolation | revoke-selftest | approve-runtime | reconfirm-runtime | revoke-runtime) --repo <path> … (see code-parley --help)");
    }
  } catch (e) {
    if (isDomainError(e) && e.code === "CALLER_NOT_AUTHORIZED") throw new DomainError("CALLER_NOT_AUTHORIZED", `${NOT_ELEVATED} (${e.message})`);
    throw e;
  }
}

async function repoRoot(le: Loaded, raw: string | undefined): Promise<string> {
  if (!raw) throw new DomainError("INVALID_ARGUMENT", "--repo <path> is required");
  // Phase 5 G-OP: the separate Linux operator account cannot read the repository; the custodian resolves it.
  if (process.platform === "linux") return linuxOperatorRepo(raw);
  return resolveGitTopLevel(await canonicalizePath(raw), { gitExe: await gitExeOf(le) });
}

function recordRef(a: ConfigArgs, cmd = "revoke-isolation|revoke-selftest"): string {
  const id = a.refs[0];
  if (!id) throw new DomainError("INVALID_ARGUMENT", `name the record: code-parley config ${cmd} --repo <path> <id>`);
  return id;
}

function backendOf(a: ConfigArgs): SandboxBackend {
  const allowed = backendsFor();
  const b = a.one("--backend") ?? allowed[0];
  if (!b || !(allowed as readonly string[]).includes(b)) throw new DomainError("INVALID_ARGUMENT", `--backend must be one of ${allowed.join(", ") || "(no Codex sandbox backend on this platform)"}`);
  return b as SandboxBackend;
}

// ---- Phase 5 F-3 (contract §4.5, D5-B): the proposal handoff ----
//
// On Linux the operator is a separate account that cannot read the implementer's data home or the repository, so it
// cannot build a configuration payload itself. The implementer writes the payload it proposes to a file (`config
// propose`, `config propose-selftest`); the operator passes that file to `config set` / `config confirm-selftest`
// (`--proposal-file`). Nothing changes at the custodian: the payload was always a claim — the custodian validates it,
// measures the Codex installation (and on Linux the sandbox basis) itself and renders the complete change, and the
// operator confirms that rendering by typing. The operator never needs access to the implementer's home.

export const CONFIG_PROPOSAL_SCHEMA = "arl.config-proposal.v1";
const MAX_PROPOSAL_BYTES = 1 << 20;
type ProposalKind = "repository" | "selftest_confirmation";

/** The command the operator runs with a proposal of this kind, in this platform's terms. */
function operatorCommandFor(kind: ProposalKind, root: string, file: string, fix: boolean): string {
  const cli = process.platform === "linux" ? "code-parley-operator" : "code-parley";
  return kind === "repository" ? `${cli} config set --repo ${root} --proposal-file ${file}` : `${cli} config confirm-selftest${fix ? " --fix" : ""} --repo ${root} --proposal-file ${file}`;
}

/**
 * Read a proposal the implementer wrote: a regular file (never through a link), at most 1 MiB, exactly the proposal
 * shape, of the expected kind and for the repository the operator named. The payload itself is the custodian's to
 * validate (unknown fields are refused there).
 */
export async function readConfigProposal(path: string, kind: ProposalKind, root: string): Promise<Record<string, unknown>> {
  let text: string;
  try {
    const fh = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const st = await fh.stat();
      if (!st.isFile() || st.size > MAX_PROPOSAL_BYTES) throw new DomainError("INVALID_ARGUMENT", `${path} is not a proposal file (a regular file of at most ${MAX_PROPOSAL_BYTES} bytes)`);
      text = await fh.readFile("utf8");
    } finally {
      await fh.close();
    }
  } catch (e) {
    if (isDomainError(e)) throw e;
    throw new DomainError("INVALID_ARGUMENT", `the proposal file ${path} cannot be read (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}); it must be a regular file, not a link. Nothing was recorded.`);
  }
  let o: unknown;
  try {
    o = JSON.parse(text);
  } catch {
    throw new DomainError("INVALID_ARGUMENT", `${path} is not a proposal (not JSON). Nothing was recorded.`);
  }
  const keys = ["createdAt", "payload", "recordKind", "repositoryRoot", "schema"];
  if (typeof o !== "object" || o === null || Array.isArray(o) || Object.keys(o).sort().join(",") !== keys.join(","))
    throw new DomainError("INVALID_ARGUMENT", `${path} is not a proposal (expected exactly the fields ${keys.join(", ")}). Nothing was recorded.`);
  const p = o as Record<string, unknown>;
  if (p["schema"] !== CONFIG_PROPOSAL_SCHEMA) throw new DomainError("INVALID_ARGUMENT", `${path} is not a ${CONFIG_PROPOSAL_SCHEMA} proposal. Nothing was recorded.`);
  if (p["recordKind"] !== kind) throw new DomainError("INVALID_ARGUMENT", `${path} proposes a ${String(p["recordKind"])} record, not a ${kind} record. Nothing was recorded.`);
  if (p["repositoryRoot"] !== root) throw new DomainError("INVALID_ARGUMENT", `${path} was written for the repository ${JSON.stringify(p["repositoryRoot"])}, not ${JSON.stringify(root)}. Nothing was recorded.`);
  const payload = p["payload"];
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) throw new DomainError("INVALID_ARGUMENT", `${path} carries no payload object. Nothing was recorded.`);
  return payload as Record<string, unknown>;
}

// On a real Linux host (a test injects its simulated custodian and runs as one account) the operator takes a proposal.
const LINUX_PROPOSAL_REQUIRED = (kind: ProposalKind, root: string): string =>
  `on Linux the operator account cannot read the implementer's data home or the repository, so it does not build this payload itself: the implementer runs \`code-parley config ${kind === "repository" ? "propose" : "propose-selftest"} --repo ${root} --out <file>\`, and you pass that file here with --proposal-file <file> (the custodian validates and renders it; you confirm the rendering). Nothing was recorded.`;

/** `config propose` / `config propose-selftest`: the implementer writes the payload it proposes. Contacts no custodian. */
export async function runConfigProposeCli(a: ConfigArgs, io: CliIo): Promise<number> {
  const launch = {
    allowedRoots: [],
    diagnostics: false,
    ...(a.one("--home") ? { home: a.one("--home")! } : {}),
    ...(a.one("--config") ? { configFile: a.one("--config")! } : {}),
    ...(a.one("--git") ? { git: a.one("--git")! } : {}),
  };
  const le = await loadEngine({ launch, sourceEnv: io.env, owner: selfOwner(), ...(io.engineTestHooks ? { testHooks: io.engineTestHooks } : {}) });
  const out = a.one("--out");
  const raw = a.one("--repo");
  if (!raw || !out) throw new DomainError("INVALID_ARGUMENT", `usage: code-parley config ${a.cmd} --repo <path> --out <file> …: the file the operator then passes with --proposal-file`);
  const root = await resolveGitTopLevel(await canonicalizePath(raw), { gitExe: await gitExeOf(le) });
  let kind: ProposalKind;
  let payload: Record<string, unknown>;
  let fix = false;
  if (a.cmd === "propose") {
    const codex = await codexInstallationPath(le, a.one("--codex") ?? null);
    io.out(`Codex installation proposed: ${codex.path} (${codex.how}). On protected runs CodeParley launches exactly this file.`);
    kind = "repository";
    payload = await repositoryPayload(le, root, codex.path);
  } else {
    const backend = backendOf(a);
    fix = a.has("--fix");
    kind = "selftest_confirmation";
    payload = fix ? await fixSelftestPayload(le, backend, a.one("--codex") ?? null) : await selftestPayload(le, backend, a.one("--codex") ?? null);
  }
  const text = `${JSON.stringify({ schema: CONFIG_PROPOSAL_SCHEMA, recordKind: kind, repositoryRoot: root, payload, createdAt: new Date().toISOString() }, null, 2)}\n`;
  // A new file only (O_EXCL: never through an existing name or link, e.g. in /tmp), readable by the operator account.
  try {
    await writeFile(out, text, { flag: "wx", mode: 0o644 });
  } catch (e) {
    throw new DomainError("INVALID_ARGUMENT", `the proposal cannot be written to ${out} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}): name a new file the operator account can read`);
  }
  await chmod(out, 0o644);
  io.out(`Wrote the proposed ${kind === "repository" ? "protected configuration" : fix ? "FIX self-test confirmation" : "self-test confirmation"} to ${out} (readable by every local user; it holds no secret, only what the custodian will render). Nothing is recorded until the operator confirms it:`);
  io.out(`  ${operatorCommandFor(kind, root, out, fix)}`);
  return 0;
}

const requireInteractive = (io: CliIo): void => {
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", CONFIG_NOT_INTERACTIVE);
};

/** Show the custodian's rendering of a prepared change, ask for the typed confirmation, commit it. */
export async function confirmAndCommit(le: Loaded, io: CliIo, prepared: PreparedConfigRecord, what: string): Promise<number> {
  io.out(`The CodeParley custodian prepared this ${what} (nothing is recorded until you confirm):`);
  for (const line of prepared.rendering.split("\n")) io.out(`  ${line}`);
  io.out(`This confirmation expires at ${prepared.expiresAt}. It applies to PROTECTED (automated) runs only; attended runs keep using the local files. It authorizes no commit, push, merge, tag or release.`);
  const answer = (await io.prompt!('Type "confirm" to record this (anything else cancels): ')).trim().toLowerCase();
  if (answer !== "confirm") {
    io.out("Not recorded (the prepared authorization expires unused).");
    return 2;
  }
  const out = await commitConfigChange(le, prepared.authorizationRequestId);
  io.out(`Recorded by the custodian: ${out.recordKind} ${out.action}${out.configRevision !== null ? `, configuration revision ${out.configRevision}` : ""}${out.recordId ? `, record ${out.recordId}` : ""}${out.globalsReconfirmed ? `; ${out.globalsReconfirmed} lapsed global record(s) re-confirmed with it` : ""} (assurance ${hostOperatorAssurance()}).`);
  return 0;
}

async function set(le: Loaded, a: ConfigArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  requireInteractive(io);
  const file = a.one("--proposal-file");
  let payload: Record<string, unknown>;
  if (file) {
    payload = await readConfigProposal(file, "repository", root);
    io.out(`The implementer's proposal ${file}: the custodian validates it and measures the Codex installation it names itself.`);
  } else {
    if (process.platform === "linux" && !io.engineTestHooks) throw new DomainError("INVALID_ARGUMENT", LINUX_PROPOSAL_REQUIRED("repository", root));
    const codex = await codexInstallationPath(le, a.one("--codex") ?? null);
    io.out(`Codex installation to approve: ${codex.path} (${codex.how}). On protected runs CodeParley launches exactly this file.`);
    payload = await repositoryPayload(le, root, codex.path);
  }
  const section = await operatorConfigSection(le, root);
  const prepared = await prepareConfigChange(le, { repositoryRoot: root, recordKind: "repository", action: "set", payload, baseRevision: section.repository?.configRevision ?? 0 }, a.one("--request-id") ?? undefined);
  return confirmAndCommit(le, io, prepared, "protected configuration");
}

/**
 * Re-confirm the repository's configuration after a restart of the OS (D4-E): one rendering of the record as it
 * survived, with every lapsed global record it rests on, bound by its digest; one commit clears all of them.
 */
export async function reconfirmRepository(le: Loaded, io: CliIo, root: string, section: ConfigSection): Promise<number> {
  const prepared = await prepareConfigChange(le, { repositoryRoot: root, recordKind: "repository", action: "reconfirm", baseRevision: section.repository?.configRevision ?? 0 });
  return confirmAndCommit(le, io, prepared, "re-confirmation");
}

async function reconfirmCmd(le: Loaded, a: ConfigArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  requireInteractive(io);
  return reconfirmRepository(le, io, root, await operatorConfigSection(le, root));
}

async function change(le: Loaded, io: CliIo, root: string, recordKind: ConfigRecordKind, action: ConfigAction, recordId: string | null): Promise<number> {
  requireInteractive(io);
  const section = await operatorConfigSection(le, root);
  const base = recordKind === "repository" ? (section.repository?.configRevision ?? 0) : section.globalRevision;
  const prepared = await prepareConfigChange(le, { repositoryRoot: recordKind === "repository" ? root : null, recordKind, action, recordId, baseRevision: base });
  return confirmAndCommit(le, io, prepared, `${action} of the ${recordKind.replace("_", " ")}`);
}

async function acceptIsolation(le: Loaded, a: ConfigArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  requireInteractive(io);
  const backend = backendOf(a);
  io.out(REDUCED_ISOLATION_STATEMENT);
  const section = await operatorConfigSection(le, root);
  const prepared = await prepareConfigChange(le, { repositoryRoot: null, recordKind: "isolation_acceptance", action: "set", payload: await acceptancePayload(le, backend, a.one("--codex") ?? null), baseRevision: section.globalRevision });
  return confirmAndCommit(le, io, prepared, "acceptance of reduced isolation");
}

async function confirmSelftest(le: Loaded, a: ConfigArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  requireInteractive(io);
  const file = a.one("--proposal-file");
  let fix = a.has("--fix");
  let payload: Record<string, unknown>;
  if (file) {
    payload = await readConfigProposal(file, "selftest_confirmation", root);
    fix = payload["mode"] === "FIX";
    if (a.has("--fix") && !fix) throw new DomainError("INVALID_ARGUMENT", `${file} proposes an S1 self-test confirmation, not a FIX one. Nothing was recorded.`);
  } else {
    if (process.platform === "linux" && !io.engineTestHooks) throw new DomainError("INVALID_ARGUMENT", LINUX_PROPOSAL_REQUIRED("selftest_confirmation", root));
    const backend = backendOf(a);
    payload = fix ? await fixSelftestPayload(le, backend, a.one("--codex") ?? null) : await selftestPayload(le, backend, a.one("--codex") ?? null);
  }
  const section = await operatorConfigSection(le, root);
  const prepared = await prepareConfigChange(le, { repositoryRoot: null, recordKind: "selftest_confirmation", action: "set", payload, baseRevision: section.globalRevision });
  return confirmAndCommit(le, io, prepared, fix ? "FIX self-test confirmation (delegated fixes)" : "self-test confirmation");
}

/**
 * P3.4C-5 (contract §2.1, D5-A): approve the engine runtime the custodian's helper runs — the administrator-installed
 * directory with node.exe, the built engine (its dist/helper/main.js) and the approved git. The custodian measures the
 * tree itself (every file's hash, node.exe and git as native images, the administrator-only ACLs) and renders what it
 * measured; the operator confirms it by typing. Global (one runtime in force); `--repo` only locates the custodian's
 * configuration view. The approval lapses after a restart of the OS (re-confirm it with `config reconfirm-runtime`,
 * or with the repository's `config reconfirm`).
 */
async function approveRuntime(le: Loaded, a: ConfigArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  const runtime = a.one("--runtime");
  const git = a.one("--runtime-git");
  // Phase 6 (§7 b): an administrator-installed git outside the runtime, measured as Codex is (not hashed with the tree).
  const gitPath = a.one("--runtime-git-path");
  if (!runtime || (git === undefined) === (gitPath === undefined)) throw new DomainError("INVALID_ARGUMENT", "usage: code-parley config approve-runtime --repo <path> --runtime <runtime directory> (--runtime-git <git.exe relative to it, e.g. git/mingw64/bin/git.exe> | --runtime-git-path <an installed git.exe outside it>)");
  requireInteractive(io);
  const section = await operatorConfigSection(le, root);
  const prepared = await prepareConfigChange(le, { repositoryRoot: null, recordKind: "engine_runtime", action: "set", payload: gitPath !== undefined ? { path: runtime, gitPath } : { path: runtime, git }, baseRevision: section.globalRevision }, a.one("--request-id") ?? undefined);
  return confirmAndCommit(le, io, prepared, "engine runtime approval");
}

async function show(le: Loaded, a: ConfigArgs, io: CliIo): Promise<number> {
  const root = await repoRoot(le, a.one("--repo"));
  const s = await operatorConfigSection(le, root);
  if (a.has("--json")) {
    io.out(JSON.stringify(s, null, 2));
    return 0;
  }
  const r = s.repository;
  if (!r) io.out(`no protected configuration is held for ${root} (protected runs there are refused: code-parley config set --repo <path>)`);
  else {
    io.out(`protected configuration of ${root}: revision ${r.configRevision} (${r.action}, ${r.recordedAt}); ${r.revoked ? "REVOKED" : r.lapsed ? `LAPSED after a restart of the OS — re-confirm: code-parley config reconfirm --repo ${root}` : "in force"}`);
    io.out(`  checks: ${Object.keys(r.checks).sort().join(", ") || "(none)"}; floor: ${r.noRequiredChecks ? "no required checks" : `required profiles ${r.requiredProfiles.join(", ")}`}`);
    io.out(`  capture rules digest ${r.captureRulesDigest}; configuration digest ${r.configDigest}`);
    io.out(r.codexInstallation ? `  Codex installation: ${r.codexInstallation.path} (SHA-256 ${r.codexInstallation.sha256}, ${r.codexInstallation.size} bytes)` : "  Codex installation: none (protected reviews are refused)");
  }
  for (const x of s.acceptances) io.out(`isolation acceptance ${x.acceptanceId}: ${x.backend}, Codex ${x.codexVersionRange}x; ${x.revoked ? "revoked" : x.lapsed ? "LAPSED" : "in force"}`);
  for (const x of s.selftestConfirmations) io.out(`self-test confirmation ${x.confirmationId}: self-test ${x.selftestId}, Codex ${x.codexVersion}, ${x.backend}; ${x.revoked ? "revoked" : x.lapsed ? "LAPSED" : "in force"}`);
  const rt = s.engineRuntime ?? null;
  io.out(rt
    ? `engine runtime ${rt.runtimeId}: ${rt.root} (${rt.fileCount} files, tree digest ${rt.treeDigest}); ${rt.revoked ? "REVOKED — approve one again: code-parley config approve-runtime" : rt.lapsed ? `LAPSED after a restart of the OS — re-confirm: code-parley config reconfirm-runtime --repo ${root} ${rt.runtimeId}` : "in force"}`
    : "engine runtime: none approved (protected reviews are refused: code-parley config approve-runtime --repo <path> --runtime <dir> --runtime-git <rel>)");
  return 0;
}
