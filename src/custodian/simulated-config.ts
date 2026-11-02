// The simulated custodian's trusted configuration (P3.4C-4): a faithful TypeScript re-implementation of the custodian's
// custodian/…/Ledger/ConfigRecords.cs and GrantLedger.Config.cs (and Security/CodexImage.cs for the installation's
// measurement), for the in-process SimulatedCustodianTransport — a test stand-in only test code constructs. Held to the
// real ledger by the shared corpora (test/fixtures/run-transition-corpus.json, config-digest-corpus.json).
//
// Simulation limit (documented): the real custodian is Windows-only and accepts a Windows PE image; this simulator also
// accepts an ELF image so the engine suite runs on a Linux test host (where protected loops are refused in production,
// D-14). Its file identity is the device and inode, not FILE_ID_INFO.

import { createHash, randomUUID } from "node:crypto";
import { closeSync, lstatSync, openSync, readdirSync, readFileSync, readSync, realpathSync, statSync } from "node:fs";
import { basename, extname, isAbsolute, join, sep } from "node:path";
import { sha256OfCanonicalJson } from "../common/hash.js";
import { captureRulesConfigDigest, definitionDigest, repositoryConfigDigest, type HeldCaptureRules, type HeldDefinition } from "./config-digests.js";
import { SimLoopInvalid, SimLoopRefusal } from "./simulated-loops.js";

// ---------------------------------------------------------------------------
// The records (ConfigRecords.cs; the custodian's JSON field names)
// ---------------------------------------------------------------------------

export interface SimRecordedBy {
  role: string;
  channel: string;
  assurance: string;
  proofDigest: string;
  requestId: string;
}

export interface SimCodexInstallation {
  path: string;
  form: string;
  fileId: string;
  size: number;
  sha256: string;
}

export interface SimRepositoryConfig {
  repoKey: string;
  repositoryRoot: string;
  configRevision: number;
  recordedAt: string;
  recordedBy: SimRecordedBy;
  requestId: string;
  action: string;
  rootCommit: string | null;
  checks: Record<string, { definition: HeldDefinition; definitionDigest: string }>;
  profiles: Record<string, string[]>;
  requiredProfiles: string[];
  noRequiredChecks: boolean;
  testGlobs: string[];
  captureRules: HeldCaptureRules;
  captureRulesDigest: string;
  codexInstallation: SimCodexInstallation | null;
  configDigest: string;
  revokedAt: string | null;
  supersededAt: string | null;
  lapsedAtRecoveryId: string | null;
  lastRecoveryId: string | null;
}

export interface SimAcceptance {
  acceptanceId: string;
  globalRevision: number;
  recordedAt: string;
  recordedBy: SimRecordedBy;
  requestId: string;
  accepted: string[];
  backend: string;
  codexVersionRange: string;
  statementSha256: string;
  revokedAt: string | null;
  lapsedAtRecoveryId: string | null;
  lastRecoveryId: string | null;
}

export interface SimSelftestConfirmation {
  confirmationId: string;
  globalRevision: number;
  recordedAt: string;
  recordedBy: SimRecordedBy;
  requestId: string;
  selftestId: string;
  codexVersion: string;
  backend: string;
  mode: string;
  profileDigest: string;
  s1Available: boolean;
  rowsSummary: { total: number; passed: number; failed: string[] };
  recordDigest: string;
  /** Phase 4 Increment 2: a FIX confirmation's Codex binary (null on an S1 confirmation). */
  codexSha256?: string | null;
  revokedAt: string | null;
  supersededAt: string | null;
  lapsedAtRecoveryId: string | null;
  lastRecoveryId: string | null;
}

/** P3.4C-5 (§2.1): the operator's approval of the engine runtime the helper runs (EngineRuntimeRecord): what the custodian
 * measured, global, one in force at a time. */
export interface SimEngineRuntime {
  runtimeId: string;
  globalRevision: number;
  recordedAt: string;
  recordedBy: SimRecordedBy;
  requestId: string;
  measured: Record<string, unknown>;
  revokedAt: string | null;
  supersededAt: string | null;
  lapsedAtRecoveryId: string | null;
  lastRecoveryId: string | null;
}

export interface SimConfigFile {
  version: 1;
  globalRevision: number;
  repositories: SimRepositoryConfig[];
  acceptances: SimAcceptance[];
  selftestConfirmations: SimSelftestConfirmation[];
  /** P3.4C-5: absent in stores written before it. */
  engineRuntimes?: SimEngineRuntime[];
}

/** The runtime approval in force (the latest not superseded), if any (ConfigRecordsFile.CurrentRuntime). */
export const currentRuntime = (f: SimConfigFile): SimEngineRuntime | null => [...(f.engineRuntimes ?? [])].reverse().find((r) => r.supersededAt === null) ?? null;
const runtimeUsable = (r: SimEngineRuntime): boolean => r.revokedAt === null && r.supersededAt === null && r.lapsedAtRecoveryId === null;

export const emptyConfig = (): SimConfigFile => ({ version: 1, globalRevision: 0, repositories: [], acceptances: [], selftestConfirmations: [] });

export const currentOf = (f: SimConfigFile, repoKey: string): SimRepositoryConfig | null => [...f.repositories].reverse().find((r) => r.repoKey === repoKey && r.supersededAt === null) ?? null;
const repoUsable = (r: SimRepositoryConfig): boolean => r.supersededAt === null && r.revokedAt === null && r.lapsedAtRecoveryId === null;
const accUsable = (a: SimAcceptance): boolean => a.revokedAt === null && a.lapsedAtRecoveryId === null;
const confUsable = (c: SimSelftestConfirmation): boolean => c.revokedAt === null && c.supersededAt === null && c.lapsedAtRecoveryId === null;

const KINDS = new Set(["repository", "isolation_acceptance", "selftest_confirmation", "engine_runtime"]);
const ACTIONS = new Set(["set", "revoke", "reconfirm"]);
const REDUCED = new Set(["unrestricted_reads", "advisory_network"]);
export const CONFIG_CAPS = Object.freeze({ checks: 64, argv: 64, env: 64, freshnessInputs: 128, globs: 256, acceptances: 64, selftestConfirmations: 256, engineRuntimes: 64, profiles: 64, profileEntries: 64, repositoryVersions: 256, text: 500, pathChars: 1024, maxCaptureBytes: 2 ** 40 });

const invalid = (m: string): SimLoopInvalid => new SimLoopInvalid(m);
const refuse = (code: string, m: string): SimLoopRefusal => new SimLoopRefusal(code, m);
const cap = (what: string, limit: number): SimLoopRefusal => refuse("BUDGET_EXHAUSTED", `${what}: at most ${limit}`);
const stale = (why: string): SimLoopRefusal => refuse("STALE_CONFIG", `${why}; nothing was recorded — prepare it again against the current configuration`);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

// ---------------------------------------------------------------------------
// Validation (ConfigValidation)
// ---------------------------------------------------------------------------

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_.()-]{0,127}$/;
const SECRET_SHAPED = /(^|_)(API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PASSWORD|PASSWD|TOKEN)($|_)/i;
const CODEX_AUTH = new Set(["CODEX_HOME", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"]);
const DOS_DEVICES = new Set(["CON", "PRN", "AUX", "NUL", ...[1, 2, 3, 4, 5, 6, 7, 8, 9].flatMap((n) => [`COM${n}`, `LPT${n}`]), "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"]);
const CHECK_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const str = (v: unknown, p: string): string => {
  if (typeof v !== "string") throw invalid(`${p} must be a string`);
  return v;
};
const checkName = (v: unknown, p: string): string => {
  const s = str(v, p);
  if (!CHECK_NAME.test(s)) throw invalid(`${p} must be a check name (1-64 of [A-Za-z0-9._-], starting alphanumeric)`);
  return s;
};
const int = (v: unknown, p: string, min: number, max: number): number => {
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw invalid(`${p} must be an integer from ${min} to ${max}`);
  return v;
};
const bool = (v: unknown, p: string): boolean => {
  if (typeof v !== "boolean") throw invalid(`${p} must be a boolean`);
  return v;
};
const hex64 = (v: unknown, p: string): string => {
  const s = str(v, p);
  if (!/^[0-9a-f]{64}$/.test(s)) throw invalid(`${p} must be 64 lowercase hex characters`);
  return s;
};
const code = (v: unknown, p: string): string => {
  const s = str(v, p);
  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(s)) throw invalid(`${p} must be a code of 1-64 of [A-Za-z0-9_.:-]`);
  return s;
};
export const versionText = (v: unknown, p: string): string => {
  const s = str(v, p);
  if (!/^[0-9A-Za-z.+-]{1,64}$/.test(s)) throw invalid(`${p} must be a version of 1-64 of [0-9A-Za-z.+-]`);
  return s;
};
const token = (v: unknown, p: string): string => {
  const s = str(v, p);
  if (s.length < 1 || s.length > 128 || s === "." || s === ".." || !/^[A-Za-z0-9_-]+$/.test(s)) throw invalid(`${p} must be 1..128 chars of [A-Za-z0-9-_]`);
  return s;
};

/** Allowlisted object keys (unknown keys MALFORMED_REQUEST, missing ones INVALID_ARGUMENT), in the rules' order. */
function shape(v: unknown, p: string, rules: Record<string, (x: unknown, q: string) => unknown>, optional: readonly string[] = []): Record<string, unknown> {
  if (!isObj(v)) throw invalid(`${p} must be an object`);
  if (Object.keys(v).some((k) => !(k in rules))) throw refuse("MALFORMED_REQUEST", `unexpected key in ${p} (no field conveys authority; unknown fields are refused, not ignored)`);
  const out: Record<string, unknown> = {};
  for (const [k, rule] of Object.entries(rules)) {
    if (!(k in v)) {
      if (optional.includes(k)) continue;
      throw invalid(`${p}.${k} is required`);
    }
    out[k] = rule(v[k], `${p}.${k}`);
  }
  return out;
}

const byLower = (a: string, b: string): number => {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x < y ? -1 : x > y ? 1 : a < b ? -1 : a > b ? 1 : 0;
};
const ordinal = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function repoRelative(v: unknown, p: string, allowRoot: boolean): string {
  const s = str(v, p);
  if (s.length === 0 || s.length > CONFIG_CAPS.pathChars) throw invalid(`${p} must be 1 to ${CONFIG_CAPS.pathChars} characters`);
  if (s === ".") {
    if (allowRoot) return s;
    throw invalid(`${p} must name a file`);
  }
  for (const seg of s.split("/")) {
    if (seg.length === 0 || seg === "." || seg === "..") throw invalid(`${p} must be a canonical repository-relative path (no empty, '.' or '..' segment)`);
    if (seg.toLowerCase() === ".git") throw invalid(`${p} must not name .git`);
    if (/[*?[\]{}]/.test(seg)) throw invalid(`${p}: wildcards are not supported`);
    if (/[\u0000-\u001f<>:"|\\]/.test(seg)) throw invalid(`${p}: a segment has a character that is not allowed`);
    if (/[ .]$/.test(seg)) throw invalid(`${p}: a segment ends with a space or dot`);
    if (DOS_DEVICES.has((seg.split(".")[0] ?? "").toUpperCase())) throw invalid(`${p}: a segment is a reserved device name`);
  }
  return s;
}

function definition(v: unknown, p: string): HeldDefinition {
  if (!isObj(v)) throw invalid(`${p} must be an object`);
  const allowed = new Set(["argv", "cwd", "timeout_seconds", "env", "env_passthrough", "freshness_inputs", "description"]);
  if (Object.keys(v).some((k) => !allowed.has(k))) throw refuse("MALFORMED_REQUEST", `unexpected key in ${p} (a definition has argv, cwd, timeout_seconds, env, env_passthrough, freshness_inputs and description only)`);
  const argv = v["argv"];
  if (!Array.isArray(argv) || argv.length === 0) throw invalid(`${p}.argv must be a non-empty array`);
  if (argv.length > CONFIG_CAPS.argv) throw cap(`${p}.argv entries`, CONFIG_CAPS.argv);
  const argvOut = argv.map((a, i) => {
    const s = str(a, `${p}.argv[${i}]`);
    if (s.length > CONFIG_CAPS.text) throw invalid(`${p}.argv[${i}] must be at most ${CONFIG_CAPS.text} characters`);
    if (s.includes("\0")) throw invalid(`${p}.argv[${i}] must not contain NUL`);
    if (i === 0 && (s.length === 0 || /["\r\n\t]/.test(s))) throw invalid(`${p}.argv[0] must be non-empty without quotes or control characters`);
    return s;
  });
  const cwd = repoRelative(v["cwd"], `${p}.cwd`, true);
  const timeout = int(v["timeout_seconds"], `${p}.timeout_seconds`, 1, 3600);
  const env = v["env"];
  if (!isObj(env)) throw invalid(`${p}.env must be an object`);
  if (Object.keys(env).length > CONFIG_CAPS.env) throw cap(`${p}.env entries`, CONFIG_CAPS.env);
  const seen = new Set<string>();
  const envOut: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (!ENV_NAME.test(name)) throw invalid(`${p}.env: invalid environment variable name`);
    if (seen.has(name.toUpperCase())) throw invalid(`${p}.env: duplicate variable (case-insensitive): ${name}`);
    seen.add(name.toUpperCase());
    if (/^ANTHROPIC_/i.test(name) || /^CLAUDE/i.test(name)) throw invalid(`${p}.env: ${name} is never passed to check commands`);
    const s = str(value, `${p}.env.${name}`);
    if (s.length > CONFIG_CAPS.text || s.includes("\0")) throw invalid(`${p}.env.${name} must be at most ${CONFIG_CAPS.text} characters without NUL`);
    envOut[name] = s;
  }
  const pass = v["env_passthrough"];
  if (!Array.isArray(pass)) throw invalid(`${p}.env_passthrough must be an array`);
  if (pass.length > CONFIG_CAPS.env) throw cap(`${p}.env_passthrough entries`, CONFIG_CAPS.env);
  let prev: string | null = null;
  const passOut = pass.map((n) => {
    const name = str(n, `${p}.env_passthrough`);
    if (!ENV_NAME.test(name)) throw invalid(`${p}.env_passthrough: invalid environment variable name`);
    if (CODEX_AUTH.has(name) || /^ANTHROPIC_/i.test(name) || /^CLAUDE/i.test(name) || SECRET_SHAPED.test(name)) throw invalid(`${p}.env_passthrough: ${name} is refused (Claude/Anthropic credential or secret-shaped name)`);
    if (seen.has(name.toUpperCase())) throw invalid(`${p}.env_passthrough: ${name} is also set in env or listed twice`);
    if (prev !== null && byLower(prev, name) >= 0) throw invalid(`${p}.env_passthrough must be sorted case-insensitively without duplicates (the engine's canonical form)`);
    seen.add(name.toUpperCase());
    prev = name;
    return name;
  });
  const fresh = v["freshness_inputs"];
  if (!Array.isArray(fresh)) throw invalid(`${p}.freshness_inputs must be an array`);
  if (fresh.length > CONFIG_CAPS.freshnessInputs) throw cap(`${p}.freshness_inputs entries`, CONFIG_CAPS.freshnessInputs);
  let prevPath: string | null = null;
  const freshOut = fresh.map((n) => {
    const path = repoRelative(n, `${p}.freshness_inputs`, false);
    if (prevPath !== null && ordinal(prevPath, path) >= 0) throw invalid(`${p}.freshness_inputs must be sorted without duplicates (the engine's canonical form)`);
    prevPath = path;
    return path;
  });
  const out: HeldDefinition = { argv: argvOut, cwd, timeout_seconds: timeout, env: envOut, env_passthrough: passOut, freshness_inputs: freshOut };
  if ("description" in v) {
    const d = str(v["description"], `${p}.description`);
    if (d.length > CONFIG_CAPS.text) throw invalid(`${p}.description must be at most ${CONFIG_CAPS.text} characters`);
    out.description = d;
  }
  return out;
}

function nameList(v: unknown, p: string, max: number, sorted: boolean): string[] {
  if (!Array.isArray(v)) throw invalid(`${p} must be an array`);
  if (v.length > max) throw cap(p, max);
  const seen = new Set<string>();
  let prev: string | null = null;
  return v.map((x, i) => {
    const s = checkName(x, `${p}[${i}]`);
    if (seen.has(s)) throw invalid(`${p} has a duplicate entry`);
    if (sorted && prev !== null && ordinal(prev, s) >= 0) throw invalid(`${p} must be sorted (the engine's canonical form)`);
    seen.add(s);
    prev = s;
    return s;
  });
}

function globs(v: unknown, p: string): string[] {
  if (!Array.isArray(v)) throw invalid(`${p} must be an array`);
  if (v.length > CONFIG_CAPS.globs) throw cap(p, CONFIG_CAPS.globs);
  return v.map((x, i) => {
    const s = str(x, `${p}[${i}]`);
    if (s.length === 0 || s.length > CONFIG_CAPS.text || /\p{Cc}/u.test(s)) throw invalid(`${p}[${i}] must be 1 to ${CONFIG_CAPS.text} characters without control characters`);
    return s;
  });
}

/** The validated repository payload (§2.2 P fields). */
export function validateRepositoryPayload(payload: unknown): Record<string, unknown> {
  if (payload === null || payload === undefined) throw invalid("payload is required for a repository set");
  const o = shape(payload, "payload", {
    rootCommit: (v, p) => {
      if (v === null) return null;
      const s = str(v, p);
      if (!/^([0-9a-f]{40}|[0-9a-f]{64})$/.test(s)) throw invalid(`${p} must be a 40- or 64-hex commit id`);
      return s;
    },
    checks: (v, p) => {
      if (!isObj(v)) throw invalid(`${p} must be an object`);
      if (Object.keys(v).length > CONFIG_CAPS.checks) throw cap("checks per repository", CONFIG_CAPS.checks);
      const out: Record<string, HeldDefinition> = {};
      for (const [name, def] of Object.entries(v)) {
        checkName(name, `${p} name`);
        out[name] = definition(def, `${p}.${name}`);
      }
      return out;
    },
    profiles: (v, p) => {
      if (!isObj(v)) throw invalid(`${p} must be an object`);
      if (Object.keys(v).length > CONFIG_CAPS.profiles) throw cap("profiles", CONFIG_CAPS.profiles);
      const out: Record<string, string[]> = {};
      for (const [name, list] of Object.entries(v)) {
        checkName(name, `${p} name`);
        const entries = nameList(list, `${p}.${name}`, CONFIG_CAPS.profileEntries, false);
        if (entries.length === 0) throw invalid(`profile ${name} is empty`);
        out[name] = entries;
      }
      return out;
    },
    requiredProfiles: (v, p) => nameList(v, p, CONFIG_CAPS.profiles, true),
    noRequiredChecks: bool,
    testGlobs: globs,
    captureRules: (v, p) =>
      shape(v, p, {
        excludeGlobs: globs,
        contextInclude: globs,
        maxFileBytes: (x, q) => int(x, q, 1, CONFIG_CAPS.maxCaptureBytes),
        maxExportBytes: (x, q) => int(x, q, 1, CONFIG_CAPS.maxCaptureBytes),
        maxDiffBytes: (x, q) => int(x, q, 1, CONFIG_CAPS.maxCaptureBytes),
      }),
    codexPath: (v, p) => {
      if (v === null) return null;
      const s = str(v, p);
      if (s.length === 0 || s.length > CONFIG_CAPS.pathChars) throw invalid(`${p} must be 1 to ${CONFIG_CAPS.pathChars} characters`);
      return s;
    },
  });
  const checks = o["checks"] as Record<string, HeldDefinition>;
  const profiles = o["profiles"] as Record<string, string[]>;
  for (const [name, list] of Object.entries(profiles)) {
    if (name in checks) throw invalid(`profile name collides with a check name: ${name}`);
    for (const c of list) if (!(c in checks)) throw invalid(`profile ${name} references an undefined check: ${c}`);
  }
  for (const r of o["requiredProfiles"] as string[]) if (!(r in profiles)) throw invalid(`required profile is not defined: ${r}`);
  const none = o["noRequiredChecks"] as boolean;
  if (none === (o["requiredProfiles"] as string[]).length > 0) throw invalid("a verification floor is required: name the required profile(s) or state that there are no required checks, not both");
  if (Object.keys(checks).length === 0 && !none) throw invalid("no checks to approve");
  return o;
}

function acceptancePayload(payload: unknown): Record<string, unknown> {
  if (payload === null || payload === undefined) throw invalid("payload is required for an isolation acceptance");
  const o = shape(payload, "payload", {
    accepted: (v, p) => {
      if (!Array.isArray(v)) throw invalid(`${p} must be an array`);
      if (v.length > 2) throw invalid(`${p} must have at most 2 entries`);
      const seen = new Set<string>();
      return v.map((x, i) => {
        const s = str(x, `${p}[${i}]`);
        if (!REDUCED.has(s)) throw invalid(`${p}[${i}] must be one of: advisory_network, unrestricted_reads`);
        if (seen.has(s)) throw invalid(`${p} has a duplicate entry (value)`);
        seen.add(s);
        return s;
      });
    },
    backend: code,
    codexVersionRange: versionText,
    statementSha256: hex64,
  });
  if ((o["accepted"] as string[]).length === 0) throw invalid("payload.accepted must name the accepted reductions");
  return o;
}

/** An absolute POSIX path: '/', at most CONFIG_CAPS.pathChars characters in all, no control character. */
function posixAbsolutePath(v: unknown, p: string): string {
  const s = str(v, p);
  if (s.length < 2 || s.length > CONFIG_CAPS.pathChars || !s.startsWith("/") || /[\u0000-\u001f\u007f-\u009f]/.test(s)) throw invalid(`${p} must be an absolute path of at most ${CONFIG_CAPS.pathChars} characters`);
  return s;
}

/** A Linux boot id (/proc/sys/kernel/random/boot_id): a lowercase hyphenated UUID. */
function bootId(v: unknown, p: string): string {
  const s = str(v, p);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) throw invalid(`${p} must be a lowercase boot id (UUID)`);
  return s;
}

function selftestPayload(payload: unknown): Record<string, unknown> {
  if (payload === null || payload === undefined) throw invalid("payload is required for a self-test confirmation");
  // Phase 4 Increment 2: a FIX confirmation (the delegated fixer's cp_fix self-test) is separate from S1 and is bound to
  // the exact Codex binary its self-test ran (codexSha256, present only on a FIX confirmation).
  const fix = isObj(payload) && payload["mode"] === "FIX";
  const o = shape(payload, "payload", {
    selftestId: token,
    codexVersion: versionText,
    backend: code,
    mode: (v, p) => {
      const m = str(v, p);
      if (m !== "S1" && m !== "FIX") throw invalid(`${p} must be one of: FIX, S1`);
      return m;
    },
    profileDigest: hex64,
    s1Available: bool,
    rowsSummary: (v, p) =>
      shape(v, p, {
        total: (x, q) => int(x, q, 0, 1000),
        passed: (x, q) => int(x, q, 0, 1000),
        failed: (x, q) => {
          if (!Array.isArray(x)) throw invalid(`${q} must be an array`);
          if (x.length > 32) throw invalid(`${q} must have at most 32 entries`);
          const seen = new Set<string>();
          return x.map((e, i) => {
            const s = code(e, `${q}[${i}]`);
            if (seen.has(s)) throw invalid(`${q} has a duplicate entry (value)`);
            seen.add(s);
            return s;
          });
        },
      }),
    recordDigest: hex64,
    // Phase 5 (§4.12): the Codex binary the self-test ran (required for FIX, optional for S1) and, on a host that binds a
    // sandbox basis, that installation's path and the boot the record was produced on (the simulator binds no basis).
    codexSha256: hex64,
    host: (v, p) => shape(v, p, { codexPath: posixAbsolutePath, bootId }),
  }, fix ? ["host"] : ["codexSha256", "host"]);
  // An S1 confirmation names its binary only with the host binding (P4: the binary binds FIX, not S1, elsewhere).
  if (!fix && "codexSha256" in o && !("host" in o)) throw refuse("MALFORMED_REQUEST", "unexpected key in payload (no field conveys authority; unknown fields are refused, not ignored)");
  if (o["s1Available"] !== true) {
    throw invalid(fix ? "only a fix self-test that established confinement can be confirmed (s1Available is false)" : "only a self-test whose S1 rows all passed can be confirmed (s1Available is false)");
  }
  return o;
}

// ---------------------------------------------------------------------------
// The Codex installation's measurement (CodexImage.cs)
// ---------------------------------------------------------------------------

const SCRIPT_EXTENSIONS = new Set([".cmd", ".bat", ".ps1", ".js", ".mjs", ".cjs", ".sh", ".vbs", ".py"]);

export interface SimMeasuredImage {
  path: string;
  form: string;
  fileId: string;
  size: number;
  sha256: string;
}

const unsupported = (why: string): SimLoopRefusal => refuse("CODEX_INSTALLATION_UNSUPPORTED", `the Codex installation is not a supported native image: ${why}`);

/** Measure the image at `path` without following any link: every component lstat'ed (a link or junction anywhere is
 * refused), one regular file with one hard link, a native image (a Windows PE; also an ELF on a non-Windows test host),
 * its size, SHA-256 and device+inode. */
export function measureCodexImage(path: string): SimMeasuredImage {
  const win = process.platform === "win32";
  if (!path || !isAbsolute(path) || (win && !/^[A-Za-z]:[\\/]/.test(path))) throw unsupported("the path must be an absolute local path");
  const native = win ? path.replace(/\//g, "\\") : path;
  const name = basename(native);
  const ext = extname(name).toLowerCase();
  if (SCRIPT_EXTENSIONS.has(ext)) throw unsupported(`'${name}' is a launcher or script, not the native executable it starts`);
  if (win && ext !== ".exe") throw unsupported(`'${name}' is not an .exe`);
  const root = win ? native.slice(0, 3) : "/";
  const parts = native.slice(root.length).split(/[\\/]/);
  let cur = root;
  for (let i = 0; i < parts.length; i++) {
    const c = parts[i]!;
    if (c === "" || c === "." || c === "..") throw unsupported(`the path has a '${c || "empty"}' component`);
    cur = cur.endsWith(sep) ? cur + c : cur + sep + c;
    let st;
    try {
      st = lstatSync(cur, { bigint: true });
    } catch {
      throw unsupported(`'${c}': it does not exist or the custodian is denied access to it`);
    }
    if (st.isSymbolicLink()) throw unsupported(`'${c}': it is a symbolic link, junction or mount point (no component may be a link)`);
    if (i < parts.length - 1 && !st.isDirectory()) throw unsupported(`'${c}': it is not a directory`);
    if (i === parts.length - 1) {
      if (!st.isFile()) throw unsupported("the path does not name a regular file");
      if (st.nlink !== 1n) throw unsupported(`the file has ${st.nlink} hard links (one is required)`);
    }
  }
  let fd: number;
  try {
    fd = openSync(native, "r");
  } catch {
    throw unsupported("the custodian cannot read the file");
  }
  try {
    const st = lstatSync(native, { bigint: true });
    const size = Number(st.size);
    const head = Buffer.alloc(Math.min(4096, size));
    readSync(fd, head, 0, head.length, 0);
    const pe = isPortableExecutable(head, size, fd);
    const elf = !win && head.length >= 4 && head.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    if (!pe && !elf) throw unsupported(win ? "the file is not a Windows PE image" : "the file is not a native (PE or ELF) image");
    const h = createHash("sha256");
    const chunk = Buffer.alloc(1 << 20);
    let total = 0;
    for (let n; (n = readSync(fd, chunk, 0, chunk.length, total)) > 0; total += n) h.update(chunk.subarray(0, n));
    if (total !== size) throw unsupported("the file changed while it was measured");
    return { path, form: pe ? "native_pe" : "native_elf", fileId: `${st.dev.toString(16)}-${st.ino.toString(16)}`, size, sha256: h.digest("hex") };
  } finally {
    closeSync(fd);
  }
}

function isPortableExecutable(head: Buffer, size: number, fd: number): boolean {
  if (head.length < 0x40 || head[0] !== 0x4d || head[1] !== 0x5a) return false;
  const lfanew = head.readUInt32LE(0x3c);
  if (lfanew < 0x40 || lfanew > size - 4) return false;
  const sig = Buffer.alloc(4);
  if (lfanew + 4 <= head.length) head.copy(sig, 0, lfanew, lfanew + 4);
  else if (readSync(fd, sig, 0, 4, lfanew) !== 4) return false;
  return sig.equals(Buffer.from([0x50, 0x45, 0, 0]));
}

// ---------------------------------------------------------------------------
// The engine runtime (Security/EngineRuntime.cs; the administrator-control ACL check is the real custodian's only)
// ---------------------------------------------------------------------------

export const RUNTIME_NODE = "node.exe";
export const RUNTIME_ENTRY = "dist/helper/main.js";
const runtimeRefused = (why: string): SimLoopRefusal => refuse("RUNTIME_NOT_APPROVED", `the engine runtime cannot be approved: ${why}`);

/** The validated relative path of the approved git inside the runtime (EngineRuntime.GitRelative). */
export function runtimeGitRelative(rel: string): string {
  const r = rel.replace(/\\/g, "/");
  const parts = r.split("/");
  if (r.length < 7 || r.length > 260 || r.startsWith("/") || parts.some((x) => x.length === 0 || x === "." || x === ".." || x.includes(":") || x.endsWith(".") || x.endsWith(" ")) || parts.at(-1)!.toLowerCase() !== "git.exe") {
    throw invalid("the runtime's git must be a relative path inside it ending in git.exe");
  }
  return r;
}

/** Measure the runtime tree at `root` (EngineRuntime.Measure): reached without following a link, every file hashed (a link
 * anywhere refuses), node.exe and git native PE images, the helper entry present, and the tree digest. */
export function measureEngineRuntime(root: string, gitRelative: string | null, gitPath: string | null = null): Record<string, unknown> {
  const git = runtimeGitArg(gitRelative, gitPath);
  const win = process.platform === "win32";
  if (!root || !isAbsolute(root) || (win && !/^[A-Za-z]:[\\/]/.test(root))) throw runtimeRefused("the path must be an absolute local path");
  const native = win ? root.replace(/\//g, "\\") : root;
  const vol = win ? native.slice(0, 3) : "/";
  const comps = native.slice(vol.length).replace(/[\\/]+$/, "").split(/[\\/]/).filter((c) => c !== "");
  if (comps.length === 0) throw runtimeRefused("the path names a volume root");
  let cur = vol;
  for (const c of comps) {
    if (c === "." || c === "..") throw runtimeRefused(`the path has a '${c}' component`);
    cur = cur.endsWith(sep) ? cur + c : cur + sep + c;
    let st;
    try {
      st = lstatSync(cur);
    } catch {
      throw runtimeRefused(`'${c}': it does not exist`);
    }
    if (st.isSymbolicLink()) throw runtimeRefused(`'${c}' is a link, junction or mount point`);
    if (!st.isDirectory()) throw runtimeRefused(`'${c}' is not a directory`);
  }
  const canonical = realpathSync.native(cur);
  const rootSt = statSync(canonical, { bigint: true });
  const files: { path: string; size: number; sha256: string }[] = [];
  let total = 0;
  const walk = (dir: string, rel: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      const full = join(dir, e.name);
      if (lstatSync(full).isSymbolicLink()) throw runtimeRefused(`'${childRel}' is a link or reparse point`);
      if (e.isDirectory()) {
        walk(full, childRel);
        continue;
      }
      if (files.length >= 100_000) throw runtimeRefused("it has more than 100000 files");
      const bytes = readFileSync(full);
      total += bytes.length;
      files.push({ path: childRel, size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
    }
  };
  walk(canonical, "");
  if (files.length === 0) throw runtimeRefused("the runtime directory is empty");
  files.sort((a, b) => ordinal(a.path, b.path));
  if (!files.some((f) => f.path === RUNTIME_NODE)) throw runtimeRefused(`it has no ${RUNTIME_NODE} at its root`);
  const entry = files.find((f) => f.path === RUNTIME_ENTRY);
  if (!entry) throw runtimeRefused(`it has no helper entry ${RUNTIME_ENTRY} (build the engine first)`);
  if (git !== null && !files.some((f) => f.path.toLowerCase() === git.toLowerCase())) throw runtimeRefused(`it has no ${git}`);
  const image = (path: string, rel: string): SimMeasuredImage => {
    try {
      return measureCodexImage(path);
    } catch (e) {
      throw runtimeRefused(`'${rel}' is not a native image (${e instanceof Error ? e.message : String(e)})`);
    }
  };
  const node = image(join(canonical, RUNTIME_NODE), RUNTIME_NODE);
  const gitImage = runtimeGitImage(canonical, git, gitPath, image);
  return {
    root: canonical, rootFileId: `${rootSt.dev.toString(16)}-${rootSt.ino.toString(16)}`, ...(git !== null ? { gitRelative: git } : { gitPath: gitImage.path }), entryRelative: RUNTIME_ENTRY,
    nodeSha256: node.sha256, nodeFileId: node.fileId, nodeSize: node.size, gitSha256: gitImage.sha256, gitFileId: gitImage.fileId, entrySha256: entry.sha256,
    treeDigest: sha256OfCanonicalJson({ schema: "arl.engine-runtime-tree.v1", files: files.map((f) => [f.path, f.size, f.sha256]) }), fileCount: files.length, totalBytes: total,
  };
}

/** How the simulated custodian measures a runtime (injectable in tests): its git inside the tree, or installed outside it. */
export type SimMeasureRuntime = (root: string, gitRelative: string | null, gitPath?: string | null) => Record<string, unknown>;

const gitOf = (o: Record<string, unknown>, key: string): string | null => (typeof o[key] === "string" ? (o[key] as string) : null);

const sameGitLocation = (held: Record<string, unknown>, now: Record<string, unknown>): boolean =>
  gitOf(held, "gitRelative") === gitOf(now, "gitRelative") && (gitOf(held, "gitPath") ?? "").toLowerCase() === (gitOf(now, "gitPath") ?? "").toLowerCase();

/** The validated in-tree git, or null for an installed git; exactly one of the two is named. */
function runtimeGitArg(gitRelative: string | null, gitPath: string | null): string | null {
  if ((gitRelative === null) === (gitPath === null)) throw runtimeRefused("the engine runtime names its git either inside the runtime or as an installed git outside it, exactly one");
  return gitRelative === null ? null : runtimeGitRelative(gitRelative);
}

/** The runtime's git image: inside the tree (hashed with it), or (Phase 6, §7 b) an installed git outside it, measured as
 * Codex is (its image), never hashed with the tree. */
function runtimeGitImage(canonical: string, git: string | null, gitPath: string | null, image: (path: string, rel: string) => SimMeasuredImage): SimMeasuredImage {
  if (git !== null) return image(join(canonical, ...git.split("/")), git);
  if (!/^git(\.exe)?$/i.test(basename(gitPath!))) throw runtimeRefused("the installed git must be a path ending in git.exe");
  return image(gitPath!, gitPath!);
}

/** What differs between a held runtime and a measurement now (EngineRuntime.Differences). */
export function runtimeDifferences(held: Record<string, unknown>, now: Record<string, unknown>): string[] {
  const d: string[] = [];
  if (String(held["root"]).toLowerCase() !== String(now["root"]).toLowerCase()) d.push("root");
  if (held["rootFileId"] !== now["rootFileId"]) d.push("root identity");
  if (!sameGitLocation(held, now)) d.push("git location");
  if (held["nodeSha256"] !== now["nodeSha256"]) d.push("node.exe");
  if (held["gitSha256"] !== now["gitSha256"]) d.push("git");
  if (held["entrySha256"] !== now["entrySha256"]) d.push("helper entry");
  if (held["treeDigest"] !== now["treeDigest"]) d.push("tree digest");
  return d;
}

const renderRuntime = (m: Record<string, unknown>): string =>
  [
    "Approve the CodeParley engine runtime the helper service runs:",
    `  root        ${String(m["root"])}  (directory id ${String(m["rootFileId"])})`,
    `  node.exe    native PE, ${String(m["nodeSize"])} bytes, SHA-256 ${String(m["nodeSha256"])}`,
    m["gitPath"] ? `  git         ${String(m["gitPath"])} (installed outside the runtime, administrator-controlled): native PE, SHA-256 ${String(m["gitSha256"])}` : `  git         ${String(m["gitRelative"])}: native PE, SHA-256 ${String(m["gitSha256"])}`,
    `  entry       ${RUNTIME_ENTRY}  SHA-256 ${String(m["entrySha256"])}`,
    `  tree        ${String(m["fileCount"])} files, ${String(m["totalBytes"])} bytes, digest ${String(m["treeDigest"])}`,
    "  The helper runs exactly this tree; any change refuses every measurement until it is approved again. (simulated)",
  ].join("\n");

function engineRuntimePayload(payload: unknown): Record<string, unknown> {
  if (!isObj(payload)) throw invalid("payload must be an object");
  for (const k of Object.keys(payload)) if (k !== "path" && k !== "git" && k !== "gitPath") throw refuse("MALFORMED_REQUEST", "unexpected key in payload (no field conveys authority; unknown fields are refused, not ignored)");
  const path = str(payload["path"], "payload.path");
  if (path.length === 0 || path.length > CONFIG_CAPS.pathChars) throw invalid(`payload.path must be 1..${CONFIG_CAPS.pathChars} characters`);
  if ((payload["git"] === undefined) === (payload["gitPath"] === undefined)) throw invalid("payload names the runtime's git inside it (git) or an installed git outside it (gitPath), exactly one");
  if (payload["gitPath"] !== undefined) {
    const gitPath = str(payload["gitPath"], "payload.gitPath");
    if (gitPath.length === 0 || gitPath.length > CONFIG_CAPS.pathChars) throw invalid(`payload.gitPath must be 1..${CONFIG_CAPS.pathChars} characters`);
    return { path, gitPath };
  }
  return { path, git: runtimeGitRelative(str(payload["git"], "payload.git")) };
}

const sameInstallation = (held: SimCodexInstallation, now: SimMeasuredImage): boolean =>
  held.form === now.form && held.fileId === now.fileId && held.size === now.size && held.sha256 === now.sha256 && held.path.toLowerCase() === now.path.toLowerCase();

// ---------------------------------------------------------------------------
// prepare / commit (GrantLedger.Config.cs)
// ---------------------------------------------------------------------------

/** What a prepared configuration change binds: its canonical args, the state digest the commit re-derives, and the
 * custodian's rendering. */
export interface SimConfigPrepared {
  args: Record<string, unknown>;
  stateDigest: string;
  rendering: string;
}

export interface SimConfigPrepareInput {
  repositoryRoot: string | null;
  recordKind: unknown;
  action: unknown;
  recordId: unknown;
  payload: unknown;
  baseRevision: unknown;
}

/** Prepare a configuration change (§3.1). `identity` resolves a repository root (null for a global record). */
export function prepareConfig(file: SimConfigFile, input: SimConfigPrepareInput, identity: (root: string) => { key: string; canonicalPath: string }, measure: (path: string) => SimMeasuredImage = measureCodexImage, measureRuntime: SimMeasureRuntime = measureEngineRuntime): SimConfigPrepared {
  const kind = str(input.recordKind, "'recordKind'");
  const action = str(input.action, "'action'");
  const base = typeof input.baseRevision === "number" && Number.isInteger(input.baseRevision) ? input.baseRevision : (() => { throw invalid("'baseRevision' must be an integer"); })();
  if (!KINDS.has(kind)) throw invalid("recordKind must be repository, isolation_acceptance, selftest_confirmation or engine_runtime");
  if (!ACTIONS.has(action)) throw invalid("action must be set, revoke or reconfirm");
  if (action !== "set" && input.payload !== null && input.payload !== undefined) throw invalid("a revoke or reconfirm carries no payload");
  if (kind === "repository") {
    if (input.repositoryRoot === null) throw invalid("repositoryRoot is required for a repository record");
    if (input.recordId !== null && input.recordId !== undefined) throw invalid("a repository record is named by its repository, not by a recordId");
    const id = identity(input.repositoryRoot);
    let content: Record<string, unknown> | null = null;
    let codex: SimMeasuredImage | null = null;
    if (action === "set") {
      const p = validateRepositoryPayload(input.payload);
      if (typeof p["codexPath"] === "string") codex = measure(p["codexPath"]);
      content = repositoryContent(p, codex);
    } else if (action === "reconfirm") {
      const held = currentOf(file, id.key)?.codexInstallation?.path;
      if (held) codex = measure(held);
    }
    const cur = currentOf(file, id.key);
    const current = cur?.configRevision ?? 0;
    if (base !== current) throw stale(`the repository's configuration changed since it was read (revision ${current}, prepared against ${base})`);
    const args: Record<string, unknown> = { recordKind: "repository", action, repositoryRoot: id.canonicalPath, repoKey: id.key, baseRevision: base };
    let rendering: string;
    if (action === "set") {
      if (cur && file.repositories.filter((r) => r.repoKey === id.key).length >= CONFIG_CAPS.repositoryVersions) throw refuse("BUDGET_EXHAUSTED", `a repository keeps at most ${CONFIG_CAPS.repositoryVersions} configuration versions`);
      args["content"] = structuredClone(content);
      rendering = `Set the protected configuration of repository:\n  ${id.canonicalPath}\n  identity ${id.key} (simulated)\n  (revision ${current} → ${current + 1}; operator-authoritative on protected runs; attended runs keep the local files)\n${renderContent(content!)}`;
    } else if (action === "revoke") {
      if (!cur || cur.revokedAt !== null) throw invalid("the repository has no configuration record in force to revoke");
      rendering = `Revoke the protected configuration of repository:\n  ${id.canonicalPath}\n  identity ${id.key}\n  (revision ${current} → ${current + 1})`;
    } else {
      if (!cur || cur.revokedAt !== null) throw invalid("the repository has no configuration record in force to re-confirm");
      if (cur.codexInstallation && !sameInstallation(cur.codexInstallation, codex!)) {
        throw refuse("CONFIG_MISMATCH", "the Codex installation measured now differs from the one held; nothing was re-confirmed — set the configuration again to approve the installation as it is now");
      }
      const globals = lapsedGlobals(file);
      if (cur.lapsedAtRecoveryId === null && globals.length === 0) throw invalid("nothing is lapsed: the repository's configuration and the global records are in force");
      args["affected"] = [recordState(cur), ...globals];
      rendering = [
        `Re-confirm the protected configuration of repository:\n  ${id.canonicalPath}\n  identity ${id.key} (simulated)`,
        "The custodian recovered after a restart of the OS; this is the configuration AS IT SURVIVED — check that it is what you expect (a restored older version is shown as it is):",
        `  revision ${cur.configRevision} (${cur.action}), recorded ${cur.recordedAt}${cur.lapsedAtRecoveryId ? `, lapsed by recovery ${cur.lapsedAtRecoveryId}` : ", in force"}`,
        renderContent(contentOf(cur)),
        cur.codexInstallation ? "The Codex installation was measured again now and is unchanged." : "",
        globals.length === 0 ? "Lapsed global records: none." : `Lapsed global records this re-confirmation also restores (${globals.length}):\n${globals.map((g) => renderGlobal(file, String(g["kind"]), String(g["id"]))).join("\n")}`,
      ].filter((l) => l !== "").join("\n");
    }
    return { args, stateDigest: configStateDigest(file, args), rendering };
  }
  if (input.repositoryRoot !== null) throw invalid(`a ${kind.replace("_", " ")} is global: it names no repository`);
  const runtime = kind === "engine_runtime";
  const validated = action === "set" ? (kind === "isolation_acceptance" ? acceptancePayload(input.payload) : runtime ? engineRuntimePayload(input.payload) : selftestPayload(input.payload)) : null;
  const recordId = input.recordId === null || input.recordId === undefined ? null : token(input.recordId, "recordId");
  if (action === "set" && recordId !== null) throw invalid("a new record's id is assigned by the custodian");
  if (action !== "set" && recordId === null) throw invalid("recordId names the record to revoke or re-confirm");
  // P3.4C-5 (§2.1): a set approves what is measured now; a re-confirmation must find the held tree unchanged.
  let measured: Record<string, unknown> | null = null;
  if (runtime && action === "set") measured = measureRuntime(String(validated!["path"]), gitOf(validated!, "git"), gitOf(validated!, "gitPath"));
  else if (runtime && action === "reconfirm") {
    const held = (file.engineRuntimes ?? []).find((r) => r.runtimeId === recordId);
    if (held) {
      measured = measureRuntime(String(held.measured["root"]), gitOf(held.measured, "gitRelative"), gitOf(held.measured, "gitPath"));
      const diff = runtimeDifferences(held.measured, measured);
      if (diff.length) throw refuse("CONFIG_MISMATCH", `the engine runtime measured now differs from the one approved (${diff.join(", ")}); nothing was re-confirmed - approve the runtime again as it is now`);
    }
  }
  if (base !== file.globalRevision) throw stale(`the global configuration records changed since they were read (revision ${file.globalRevision}, prepared against ${base})`);
  const args: Record<string, unknown> = { recordKind: kind, action, baseRevision: base };
  let rendering: string;
  if (action === "set") {
    if (kind === "isolation_acceptance" && file.acceptances.length >= CONFIG_CAPS.acceptances) throw refuse("BUDGET_EXHAUSTED", `isolation acceptances: at most ${CONFIG_CAPS.acceptances}`);
    if (kind === "selftest_confirmation" && file.selftestConfirmations.length >= CONFIG_CAPS.selftestConfirmations) throw refuse("BUDGET_EXHAUSTED", `self-test confirmations: at most ${CONFIG_CAPS.selftestConfirmations}`);
    if (runtime && (file.engineRuntimes ?? []).length >= CONFIG_CAPS.engineRuntimes) throw refuse("BUDGET_EXHAUSTED", `engine runtime approvals: at most ${CONFIG_CAPS.engineRuntimes}`);
    // An engine runtime's payload is what the custodian measured (M), never the operator's claim.
    args["payload"] = runtime ? structuredClone(measured) : structuredClone(validated);
    rendering = kind === "isolation_acceptance" ? renderAcceptance(validated!) : runtime ? renderRuntime(measured!) : renderSelftest(validated!);
  } else {
    const state = globalState(file, kind, recordId!);
    if (!state) throw invalid(`no ${kind.replace("_", " ")} ${recordId}`);
    if (state["revoked"] || state["superseded"]) throw invalid(`${kind.replace("_", " ")} ${recordId} is not in force`);
    if (action === "reconfirm" && state["lapsedAtRecoveryId"] === null) throw invalid(`${kind.replace("_", " ")} ${recordId} is not lapsed`);
    args["recordId"] = recordId;
    args["affected"] = [state];
    rendering = `${action === "revoke" ? "Revoke" : "Re-confirm after a restart of the OS"} ${kind.replace("_", " ")} ${recordId}:\n${renderGlobal(file, kind, recordId!)}`;
  }
  return { args, stateDigest: configStateDigest(file, args), rendering };
}

/** The state a prepared change is bound to (ConfigStateDigest; TD clarification I). */
export function configStateDigest(file: SimConfigFile, args: Record<string, unknown>): string {
  const kind = String(args["recordKind"]);
  const action = String(args["action"]);
  const state: Record<string, unknown> = { recordKind: kind, action };
  if (kind === "repository" && action !== "reconfirm") {
    const cur = currentOf(file, String(args["repoKey"]));
    state["repository"] = cur ? recordState(cur) : null;
  } else if (action === "set") state["globalRevision"] = file.globalRevision;
  else {
    state["affected"] = (args["affected"] as Record<string, unknown>[]).map((a) => {
      const k = String(a["kind"]);
      const missing = { kind: k, id: a["id"], missing: true };
      if (k === "repository") {
        const r = currentOf(file, String(a["id"]));
        return r ? recordState(r) : missing;
      }
      return globalState(file, k, String(a["id"])) ?? missing;
    });
  }
  return sha256OfCanonicalJson(state);
}

const recordState = (r: SimRepositoryConfig): Record<string, unknown> => ({ kind: "repository", id: r.repoKey, revision: r.configRevision, configDigest: r.configDigest, revoked: r.revokedAt !== null, superseded: r.supersededAt !== null, lapsedAtRecoveryId: r.lapsedAtRecoveryId });

function globalState(file: SimConfigFile, kind: string, id: string): Record<string, unknown> | null {
  if (kind === "engine_runtime") {
    const r = (file.engineRuntimes ?? []).find((x) => x.runtimeId === id);
    return r ? { kind, id, revision: r.globalRevision, revoked: r.revokedAt !== null, superseded: r.supersededAt !== null, lapsedAtRecoveryId: r.lapsedAtRecoveryId, treeDigest: r.measured["treeDigest"] ?? null } : null;
  }
  if (kind === "isolation_acceptance") {
    const a = file.acceptances.find((x) => x.acceptanceId === id);
    return a ? { kind, id, revision: a.globalRevision, revoked: a.revokedAt !== null, superseded: false, lapsedAtRecoveryId: a.lapsedAtRecoveryId } : null;
  }
  const c = file.selftestConfirmations.find((x) => x.confirmationId === id);
  return c ? { kind, id, revision: c.globalRevision, revoked: c.revokedAt !== null, superseded: c.supersededAt !== null, lapsedAtRecoveryId: c.lapsedAtRecoveryId } : null;
}

const lapsedGlobals = (file: SimConfigFile): Record<string, unknown>[] => [
  ...file.acceptances.filter((a) => a.revokedAt === null && a.lapsedAtRecoveryId !== null).map((a) => globalState(file, "isolation_acceptance", a.acceptanceId)!),
  ...file.selftestConfirmations.filter((c) => c.revokedAt === null && c.supersededAt === null && c.lapsedAtRecoveryId !== null).map((c) => globalState(file, "selftest_confirmation", c.confirmationId)!),
  ...(file.engineRuntimes ?? []).filter((r) => r.revokedAt === null && r.supersededAt === null && r.lapsedAtRecoveryId !== null).map((r) => globalState(file, "engine_runtime", r.runtimeId)!),
];

/** Was this request id committed as a configuration change? */
export const configRequestCommitted = (file: SimConfigFile, requestId: string): boolean =>
  file.repositories.some((r) => r.requestId === requestId) || file.acceptances.some((a) => a.requestId === requestId) || file.selftestConfirmations.some((c) => c.requestId === requestId)
  || (file.engineRuntimes ?? []).some((r) => r.requestId === requestId);

/** Commit a prepared change (ApplyConfigRecord): the caller re-derived the state digest and the directory first. */
export function applyConfig(file: SimConfigFile, args: Record<string, unknown>, requestId: string, recordedBy: SimRecordedBy, nowMs: number, measure: (path: string) => SimMeasuredImage = measureCodexImage, measureRuntime: SimMeasureRuntime = measureEngineRuntime): Record<string, unknown> {
  const kind = String(args["recordKind"]);
  const action = String(args["action"]);
  const now = new Date(nowMs).toISOString();
  const result: Record<string, unknown> = { recordKind: kind, action };
  if (kind === "repository") {
    const repoKey = String(args["repoKey"]);
    const cur = currentOf(file, repoKey);
    const next = (cur?.configRevision ?? 0) + 1;
    let version: SimRepositoryConfig;
    if (action === "set") {
      const content = args["content"] as Record<string, unknown>;
      const bound = content["codexInstallation"] as SimCodexInstallation | null;
      if (bound && !sameInstallation(bound, measure(bound.path))) throw stale("the Codex installation changed since this was prepared");
      version = fromContent(repoKey, String(args["repositoryRoot"]), next, now, recordedBy, requestId, content);
    } else if (action === "revoke") version = { ...cur!, configRevision: next, recordedAt: now, recordedBy, requestId, action, revokedAt: now };
    else {
      if (cur!.codexInstallation && !sameInstallation(cur!.codexInstallation, measure(cur!.codexInstallation.path))) throw stale("the Codex installation changed since this was prepared");
      version = cur!.lapsedAtRecoveryId !== null ? { ...cur!, configRevision: next, recordedAt: now, recordedBy, requestId, action, lapsedAtRecoveryId: null } : cur!;
    }
    if (version !== cur) {
      if (cur) cur.supersededAt = now;
      file.repositories.push(version);
    }
    result["repoKey"] = repoKey;
    result["configRevision"] = version.configRevision;
    result["configDigest"] = version.configDigest;
    if (action === "reconfirm") {
      const g = file.globalRevision + 1;
      let cleared = 0;
      for (const a of (args["affected"] as Record<string, unknown>[]).filter((x) => x["kind"] !== "repository")) {
        clearLapse(file, String(a["kind"]), String(a["id"]), g, measureRuntime);
        cleared++;
      }
      if (cleared > 0) file.globalRevision = g;
      result["globalsReconfirmed"] = cleared;
      result["globalRevision"] = file.globalRevision;
    }
    return result;
  }
  const g = file.globalRevision + 1;
  if (action === "set") {
    const p = args["payload"] as Record<string, unknown>;
    const id = randomUUID();
    if (kind === "engine_runtime") {
      // Committed only as the custodian measures it now (never one tree measured and another approved).
      if (runtimeDifferences(p, measureRuntime(String(p["root"]), gitOf(p, "gitRelative"), gitOf(p, "gitPath"))).length) throw stale("the engine runtime changed since this was prepared");
      const runtimes = (file.engineRuntimes ??= []);
      for (const r of runtimes) {
        if (r.supersededAt === null) Object.assign(r, { supersededAt: now, globalRevision: g });
      }
      runtimes.push({ runtimeId: id, globalRevision: g, recordedAt: now, recordedBy, requestId, measured: structuredClone(p), revokedAt: null, supersededAt: null, lapsedAtRecoveryId: null, lastRecoveryId: null });
    } else if (kind === "isolation_acceptance") {
      file.acceptances.push({
        acceptanceId: id, globalRevision: g, recordedAt: now, recordedBy, requestId, accepted: [...(p["accepted"] as string[])].sort(ordinal),
        backend: String(p["backend"]), codexVersionRange: String(p["codexVersionRange"]), statementSha256: String(p["statementSha256"]), revokedAt: null, lapsedAtRecoveryId: null, lastRecoveryId: null,
      });
    } else {
      const c: SimSelftestConfirmation = {
        confirmationId: id, globalRevision: g, recordedAt: now, recordedBy, requestId, selftestId: String(p["selftestId"]), codexVersion: String(p["codexVersion"]),
        backend: String(p["backend"]), mode: String(p["mode"]), profileDigest: String(p["profileDigest"]), s1Available: p["s1Available"] === true,
        rowsSummary: structuredClone(p["rowsSummary"]) as SimSelftestConfirmation["rowsSummary"], recordDigest: String(p["recordDigest"]),
        codexSha256: typeof p["codexSha256"] === "string" ? p["codexSha256"] : null,
        revokedAt: null, supersededAt: null, lapsedAtRecoveryId: null, lastRecoveryId: null,
      };
      for (const o of file.selftestConfirmations) {
        if (o.supersededAt === null && o.revokedAt === null && o.backend === c.backend && o.mode === c.mode && o.codexVersion === c.codexVersion && o.profileDigest === c.profileDigest) {
          o.supersededAt = now;
          o.globalRevision = g;
        }
      }
      file.selftestConfirmations.push(c);
    }
    result["recordId"] = id;
  } else {
    const id = String(args["recordId"]);
    if (action === "revoke") {
      if (kind === "engine_runtime") Object.assign((file.engineRuntimes ?? []).find((r) => r.runtimeId === id)!, { revokedAt: now, globalRevision: g });
      else if (kind === "isolation_acceptance") Object.assign(file.acceptances.find((a) => a.acceptanceId === id)!, { revokedAt: now, globalRevision: g });
      else Object.assign(file.selftestConfirmations.find((c) => c.confirmationId === id)!, { revokedAt: now, globalRevision: g });
    } else clearLapse(file, kind, id, g, measureRuntime);
    result["recordId"] = id;
  }
  file.globalRevision = g;
  result["globalRevision"] = g;
  return result;
}

function clearLapse(file: SimConfigFile, kind: string, id: string, g: number, measureRuntime: SimMeasureRuntime = measureEngineRuntime): void {
  if (kind === "engine_runtime") {
    // A re-confirmation clears the lapse only for the tree as approved: it is measured again here.
    const rt = (file.engineRuntimes ?? []).find((x) => x.runtimeId === id);
    if (!rt) return;
    if (runtimeDifferences(rt.measured, measureRuntime(String(rt.measured["root"]), gitOf(rt.measured, "gitRelative"), gitOf(rt.measured, "gitPath"))).length) throw stale("the engine runtime changed since this was prepared");
    Object.assign(rt, { lapsedAtRecoveryId: null, globalRevision: g });
    return;
  }
  const r = kind === "isolation_acceptance" ? file.acceptances.find((a) => a.acceptanceId === id) : file.selftestConfirmations.find((c) => c.confirmationId === id);
  if (r) Object.assign(r, { lapsedAtRecoveryId: null, globalRevision: g });
}

/** The canonical content of a repository record (P, C and M fields) with its digest. */
export function repositoryContent(p: Record<string, unknown>, codex: SimMeasuredImage | null): Record<string, unknown> {
  const checks: Record<string, unknown> = {};
  for (const [name, def] of Object.entries(p["checks"] as Record<string, HeldDefinition>)) checks[name] = { definition: structuredClone(def), definitionDigest: definitionDigest(name, def) };
  const rules = p["captureRules"] as HeldCaptureRules;
  const content: Record<string, unknown> = {
    rootCommit: p["rootCommit"] ?? null,
    checks,
    profiles: structuredClone(p["profiles"]),
    requiredProfiles: structuredClone(p["requiredProfiles"]),
    noRequiredChecks: p["noRequiredChecks"],
    testGlobs: structuredClone(p["testGlobs"]),
    captureRules: structuredClone(rules),
    captureRulesDigest: captureRulesConfigDigest(rules),
    codexInstallation: codex ? { path: codex.path, form: codex.form, fileId: codex.fileId, size: codex.size, sha256: codex.sha256 } : null,
  };
  content["configDigest"] = repositoryConfigDigest(content);
  return content;
}

function fromContent(repoKey: string, root: string, revision: number, now: string, recordedBy: SimRecordedBy, requestId: string, c: Record<string, unknown>): SimRepositoryConfig {
  return {
    repoKey, repositoryRoot: root, configRevision: revision, recordedAt: now, recordedBy, requestId, action: "set",
    rootCommit: (c["rootCommit"] ?? null) as string | null,
    checks: structuredClone(c["checks"]) as SimRepositoryConfig["checks"],
    profiles: structuredClone(c["profiles"]) as Record<string, string[]>,
    requiredProfiles: structuredClone(c["requiredProfiles"]) as string[],
    noRequiredChecks: c["noRequiredChecks"] === true,
    testGlobs: structuredClone(c["testGlobs"]) as string[],
    captureRules: structuredClone(c["captureRules"]) as HeldCaptureRules,
    captureRulesDigest: String(c["captureRulesDigest"]),
    codexInstallation: (structuredClone(c["codexInstallation"]) ?? null) as SimCodexInstallation | null,
    configDigest: String(c["configDigest"]),
    revokedAt: null, supersededAt: null, lapsedAtRecoveryId: null, lastRecoveryId: null,
  };
}

/** The held record's content as the canonical object its digest was computed over. */
function contentOf(r: SimRepositoryConfig): Record<string, unknown> {
  return {
    rootCommit: r.rootCommit, checks: structuredClone(r.checks), profiles: structuredClone(r.profiles), requiredProfiles: [...r.requiredProfiles],
    noRequiredChecks: r.noRequiredChecks, testGlobs: [...r.testGlobs], captureRules: structuredClone(r.captureRules), captureRulesDigest: r.captureRulesDigest,
    codexInstallation: r.codexInstallation ? { ...r.codexInstallation } : null, configDigest: r.configDigest,
  };
}

function renderContent(c: Record<string, unknown>): string {
  const lines: string[] = [`root commit: ${(c["rootCommit"] as string | null) ?? "(none recorded)"}`];
  const checks = c["checks"] as Record<string, { definition: HeldDefinition; definitionDigest: string }>;
  lines.push(`checks (${Object.keys(checks).length}):`);
  for (const name of Object.keys(checks).sort(ordinal)) {
    const { definition: d, definitionDigest: dd } = checks[name]!;
    lines.push(`  ${name}  (definition ${dd})`, `    argv: ${JSON.stringify(d.argv)}`, `    cwd: ${d.cwd}  timeout: ${d.timeout_seconds} s`);
    lines.push(Object.keys(d.env).length === 0 ? "    env: (none)" : `    env: ${Object.entries(d.env).map(([k, v]) => `${k}=${v}`).join(", ")}`);
    lines.push(`    passthrough names (values come from the environment at run time and are never stored): ${d.env_passthrough.length ? d.env_passthrough.join(", ") : "(none)"}`);
    lines.push(`    freshness inputs: ${d.freshness_inputs.length ? d.freshness_inputs.join(", ") : "(none)"}`);
  }
  const profiles = c["profiles"] as Record<string, string[]>;
  lines.push(`profiles: ${Object.keys(profiles).length ? Object.entries(profiles).map(([k, v]) => `${k} = ${v.join(", ")}`).join("; ") : "(none)"}`);
  lines.push(`verification floor: ${c["noRequiredChecks"] ? "no required checks" : `required profiles ${(c["requiredProfiles"] as string[]).join(", ")}`}`);
  const tests = c["testGlobs"] as string[];
  lines.push(`test globs: ${tests.length ? tests.join(", ") : "(none)"}`);
  const r = c["captureRules"] as HeldCaptureRules;
  lines.push(`capture rules (digest ${String(c["captureRulesDigest"])}):`, `  exclude: ${r.excludeGlobs.join(", ")}`, `  context include: ${r.contextInclude.length ? r.contextInclude.join(", ") : "(none)"}`, `  limits: file ${r.maxFileBytes} bytes, export ${r.maxExportBytes} bytes, diff ${r.maxDiffBytes} bytes`);
  const i = c["codexInstallation"] as SimCodexInstallation | null;
  lines.push(i ? `Codex installation (measured by the custodian now): ${i.path}\n  native image (${i.form}), ${i.size} bytes, SHA-256 ${i.sha256}, file id ${i.fileId}` : "Codex installation: none (protected reviews are refused until one is set)");
  lines.push(`configuration digest: ${String(c["configDigest"])}`);
  return lines.join("\n");
}

const renderAcceptance = (p: Record<string, unknown>): string =>
  `Accept reduced Codex isolation (S2) for protected reviews:\n  backend ${String(p["backend"])}, Codex ${String(p["codexVersionRange"])}x\n  accepted reductions: ${(p["accepted"] as string[]).join(", ")}\n  statement SHA-256 ${String(p["statementSha256"])}\n  (S1 is still used whenever a confirmed self-test passes; this applies only when it does not)`;

function renderSelftest(p: Record<string, unknown>): string {
  const rows = p["rowsSummary"] as { total: number; passed: number; failed: string[] };
  if (p["mode"] === "FIX") {
    return `Confirm the FIX self-test record for delegated fixes (separate from the S1 review confirmation):\n  self-test ${String(p["selftestId"])}: Codex ${String(p["codexVersion"])}, backend ${String(p["backend"])}, mode FIX\n  Codex binary SHA-256 ${String(p["codexSha256"])}\n  fixer profile digest ${String(p["profileDigest"])}\n  rows: ${rows.passed} of ${rows.total} passed${rows.failed.length ? `; failed: ${rows.failed.join(", ")}` : ""}; confinement established: ${p["s1Available"] ? "yes" : "no"}
  record digest ${String(p["recordDigest"])}
  (the custodian does not re-run the self-test: you confirm this record as your engine produced it; it authorizes no review and applies no patch)`;
  }
  return `Confirm the S1 self-test record for protected reviews:\n  self-test ${String(p["selftestId"])}: Codex ${String(p["codexVersion"])}, backend ${String(p["backend"])}, mode ${String(p["mode"])}\n  profile digest ${String(p["profileDigest"])}\n  rows: ${rows.passed} of ${rows.total} passed${rows.failed.length ? `; failed: ${rows.failed.join(", ")}` : ""}; S1 available: ${p["s1Available"] ? "yes" : "no"}\n  record digest ${String(p["recordDigest"])}\n  (the custodian does not re-run the self-test: you confirm this record as your engine produced it)`;
}

function renderGlobal(file: SimConfigFile, kind: string, id: string): string {
  const rt = kind === "engine_runtime" ? (file.engineRuntimes ?? []).find((x) => x.runtimeId === id) : undefined;
  if (rt) return `  engine runtime ${rt.runtimeId}: ${String(rt.measured["root"])}, tree digest ${String(rt.measured["treeDigest"])}; recorded ${rt.recordedAt}${rt.lapsedAtRecoveryId ? `; lapsed by recovery ${rt.lapsedAtRecoveryId}` : ""}`;
  const a = kind === "isolation_acceptance" ? file.acceptances.find((x) => x.acceptanceId === id) : undefined;
  if (a) return `  isolation acceptance ${a.acceptanceId}: backend ${a.backend}, Codex ${a.codexVersionRange}x, ${a.accepted.join(", ")}; recorded ${a.recordedAt}${a.lapsedAtRecoveryId ? `; lapsed by recovery ${a.lapsedAtRecoveryId}` : ""}`;
  const c = file.selftestConfirmations.find((x) => x.confirmationId === id);
  if (c) return `  self-test confirmation ${c.confirmationId}: self-test ${c.selftestId}, Codex ${c.codexVersion}, backend ${c.backend}, record digest ${c.recordDigest}; recorded ${c.recordedAt}${c.lapsedAtRecoveryId ? `; lapsed by recovery ${c.lapsedAtRecoveryId}` : ""}`;
  return `  ${kind} ${id}: not held`;
}

// ---------------------------------------------------------------------------
// The config section (ConfigSection)
// ---------------------------------------------------------------------------

export function configSection(file: SimConfigFile, repoKey: string, operatorView: boolean): Record<string, unknown> {
  const cur = currentOf(file, repoKey);
  let repository: Record<string, unknown> | null = null;
  if (cur) {
    repository = {
      ...contentOf(cur), configRevision: cur.configRevision, recordedAt: cur.recordedAt, action: cur.action, revoked: cur.revokedAt !== null,
      lapsed: cur.lapsedAtRecoveryId !== null, lapsedAtRecoveryId: cur.lapsedAtRecoveryId, usable: repoUsable(cur),
      ...(operatorView ? { repositoryRoot: cur.repositoryRoot, recordedBy: recordedByJson(cur.recordedBy), revokedAt: cur.revokedAt } : {}),
    };
  }
  return {
    globalRevision: file.globalRevision,
    repository,
    acceptances: file.acceptances.map((a) => ({
      acceptanceId: a.acceptanceId, globalRevision: a.globalRevision, recordedAt: a.recordedAt, accepted: [...a.accepted], backend: a.backend, codexVersionRange: a.codexVersionRange,
      statementSha256: a.statementSha256, revoked: a.revokedAt !== null, lapsed: a.lapsedAtRecoveryId !== null, lapsedAtRecoveryId: a.lapsedAtRecoveryId, usable: accUsable(a),
      ...(operatorView ? { recordedBy: recordedByJson(a.recordedBy), revokedAt: a.revokedAt } : {}),
    })),
    selftestConfirmations: file.selftestConfirmations.filter((c) => c.supersededAt === null).map((c) => ({
      confirmationId: c.confirmationId, globalRevision: c.globalRevision, recordedAt: c.recordedAt, selftestId: c.selftestId, codexVersion: c.codexVersion, backend: c.backend,
      mode: c.mode, profileDigest: c.profileDigest, s1Available: c.s1Available, rowsSummary: structuredClone(c.rowsSummary), recordDigest: c.recordDigest,
      ...(c.codexSha256 ? { codexSha256: c.codexSha256 } : {}),
      revoked: c.revokedAt !== null, lapsed: c.lapsedAtRecoveryId !== null, lapsedAtRecoveryId: c.lapsedAtRecoveryId, usable: confUsable(c),
      ...(operatorView ? { recordedBy: recordedByJson(c.recordedBy), revokedAt: c.revokedAt } : {}),
    })),
    engineRuntime: ((rt) => rt ? {
      ...structuredClone(rt.measured), runtimeId: rt.runtimeId, globalRevision: rt.globalRevision, recordedAt: rt.recordedAt, revoked: rt.revokedAt !== null,
      lapsed: rt.lapsedAtRecoveryId !== null, lapsedAtRecoveryId: rt.lapsedAtRecoveryId, usable: runtimeUsable(rt),
      ...(operatorView ? { recordedBy: recordedByJson(rt.recordedBy), revokedAt: rt.revokedAt } : {}),
    } : null)(currentRuntime(file)),
  };
}

const recordedByJson = (r: SimRecordedBy): Record<string, unknown> => ({ role: r.role, channel: r.channel, assurance: r.assurance, proof_digest: r.proofDigest, request_id: r.requestId });

// ---------------------------------------------------------------------------
// The checks inside the run transitions (§3.3, §4.3)
// ---------------------------------------------------------------------------

export function requireUsableConfig(file: SimConfigFile, repoKey: string, forWhat: string): SimRepositoryConfig {
  const cur = currentOf(file, repoKey);
  if (!cur || cur.revokedAt !== null) {
    throw refuse("CONFIG_NOT_HELD", `the custodian holds no protected configuration for this repository${cur ? " in force (it was revoked)" : ""}; ${forWhat} is refused — the operator sets it with \`code-parley config set --repo <path>\` (nothing was registered or consumed)`);
  }
  if (cur.lapsedAtRecoveryId !== null) {
    throw refuse("CONFIG_LAPSED", `the repository's protected configuration lapsed when the custodian recovered after a restart of the OS (recovery ${cur.lapsedAtRecoveryId}); ${forWhat} is refused until the operator re-confirms it: \`code-parley config reconfirm --repo ${cur.repositoryRoot}\` (or \`code-parley loop resume <run>\`)`);
  }
  return cur;
}

export interface SimIsolationPin {
  kind: string;
  id: string;
  globalRevision: number;
}

export function requireIsolationBasis(file: SimConfigFile, isolation: Record<string, unknown>): SimIsolationPin {
  const mode = String(isolation["mode"]);
  const backend = String(isolation["backend"]);
  const version = String(isolation["codexVersion"]);
  if (mode === "S1") {
    const selftestId = isolation["selftestId"];
    const c = selftestId === null ? undefined : [...file.selftestConfirmations].reverse().find((x) =>
      x.supersededAt === null && x.revokedAt === null && x.selftestId === selftestId && x.codexVersion === version && x.backend === backend && x.mode === "S1" && x.profileDigest === isolation["profileDigest"] && x.s1Available);
    if (!c) throw refuse("ISOLATION_NOT_ACCEPTED", "the review's S1 isolation rests on a self-test the operator has not confirmed for this Codex version, backend and profile (or the confirmation was revoked); nothing was begun");
    if (c.lapsedAtRecoveryId !== null) throw refuse("CONFIG_LAPSED", `the self-test confirmation the review's S1 isolation rests on lapsed after a restart of the OS (recovery ${c.lapsedAtRecoveryId}); the operator re-confirms it with \`code-parley config reconfirm --repo <path>\``);
    return { kind: "selftest_confirmation", id: c.confirmationId, globalRevision: c.globalRevision };
  }
  const acceptanceId = isolation["acceptanceId"];
  const a = acceptanceId === null ? undefined : file.acceptances.find((x) =>
    x.acceptanceId === acceptanceId && x.revokedAt === null && x.backend === backend && version.startsWith(x.codexVersionRange) && x.accepted.includes("unrestricted_reads") && x.accepted.includes("advisory_network"));
  if (!a) throw refuse("ISOLATION_NOT_ACCEPTED", "the review's reduced isolation (S2) rests on an acceptance the custodian does not hold for this backend and Codex version (or it was revoked); nothing was begun");
  if (a.lapsedAtRecoveryId !== null) throw refuse("CONFIG_LAPSED", `the isolation acceptance the review rests on lapsed after a restart of the OS (recovery ${a.lapsedAtRecoveryId}); the operator re-confirms it with \`code-parley config reconfirm --repo <path>\``);
  return { kind: "isolation_acceptance", id: a.acceptanceId, globalRevision: a.globalRevision };
}

/** Phase 4 Increment 2 (FIX vs S1 separation): the operator-confirmed FIX self-test a delegated fix rests on — mode FIX, for
 * this Codex version, backend, fixer profile and the approved installation's binary. An S1 confirmation never satisfies it
 * (nor a FIX confirmation an S1 review: requireIsolationBasis matches mode S1 only). */
export function requireFixBasis(file: SimConfigFile, isolation: Record<string, unknown>, approvedCodexSha256: string): SimIsolationPin {
  const selftestId = isolation["selftestId"];
  const c = [...file.selftestConfirmations].reverse().find((x) =>
    x.supersededAt === null && x.revokedAt === null && x.selftestId === selftestId && x.mode === "FIX" && x.codexVersion === String(isolation["codexVersion"])
    && x.backend === String(isolation["backend"]) && x.profileDigest === isolation["profileDigest"] && x.s1Available && x.codexSha256 === approvedCodexSha256);
  if (!c) throw refuse("ISOLATION_NOT_ACCEPTED", "the delegated fix rests on a FIX self-test the operator has not confirmed for this Codex version, binary, backend and fixer profile (an S1 confirmation does not count; or the confirmation was revoked); nothing was begun — the operator confirms it with `code-parley config confirm-selftest --fix`");
  if (c.lapsedAtRecoveryId !== null) throw refuse("CONFIG_LAPSED", `the FIX self-test confirmation the delegated fix rests on lapsed after a restart of the OS (recovery ${c.lapsedAtRecoveryId}); the operator re-confirms it with \`code-parley config reconfirm --repo <path>\``);
  return { kind: "selftest_confirmation", id: c.confirmationId, globalRevision: c.globalRevision };
}

/** The pin an operation was begun under (OperationPin). */
export interface SimOperationPin {
  configRevision: number;
  configDigest: string;
  isolationKind: string | null;
  isolationRecordId: string | null;
  isolationGlobalRevision: number | null;
  captureRulesDigest: string | null;
  codexSha256: string | null;
}

export function isolationBasisProblem(file: SimConfigFile, kind: string | null | undefined, id: string | null | undefined): string | null {
  if (!kind || !id) return "isolation_basis_revoked";
  if (kind === "isolation_acceptance") {
    const a = file.acceptances.find((x) => x.acceptanceId === id);
    return !a || a.revokedAt !== null ? "isolation_basis_revoked" : a.lapsedAtRecoveryId !== null ? "config_lapsed" : null;
  }
  const c = file.selftestConfirmations.find((x) => x.confirmationId === id);
  return !c || c.revokedAt !== null || c.supersededAt !== null ? "isolation_basis_revoked" : c.lapsedAtRecoveryId !== null ? "config_lapsed" : null;
}

export function reviewBasisProblem(file: SimConfigFile, repoKey: string, pin: SimOperationPin | null | undefined): string | null {
  if (!pin) return "isolation_basis_revoked";
  const iso = isolationBasisProblem(file, pin.isolationKind, pin.isolationRecordId);
  if (iso !== null) return iso;
  const cur = currentOf(file, repoKey);
  if (!cur || cur.revokedAt !== null) return "config_changed_since_review";
  if (cur.lapsedAtRecoveryId !== null) return "config_lapsed";
  if (cur.captureRulesDigest !== pin.captureRulesDigest || cur.codexInstallation?.sha256 !== pin.codexSha256) return "config_changed_since_review";
  return null;
}

/** Recovery U4b (§2.4): every configuration record in force lapses, once per recovery. */
export function lapseAll(file: SimConfigFile, recoveryId: string): void {
  for (const r of file.repositories) {
    if (r.supersededAt !== null || r.revokedAt !== null || r.lastRecoveryId === recoveryId) continue;
    r.lapsedAtRecoveryId = recoveryId;
    r.lastRecoveryId = recoveryId;
  }
  for (const a of file.acceptances) {
    if (a.revokedAt !== null || a.lastRecoveryId === recoveryId) continue;
    a.lapsedAtRecoveryId = recoveryId;
    a.lastRecoveryId = recoveryId;
  }
  for (const c of file.selftestConfirmations) {
    if (c.revokedAt !== null || c.supersededAt !== null || c.lastRecoveryId === recoveryId) continue;
    c.lapsedAtRecoveryId = recoveryId;
    c.lastRecoveryId = recoveryId;
  }
  for (const r of file.engineRuntimes ?? []) {
    if (r.revokedAt !== null || r.supersededAt !== null || r.lastRecoveryId === recoveryId) continue;
    r.lapsedAtRecoveryId = recoveryId;
    r.lastRecoveryId = recoveryId;
  }
}
