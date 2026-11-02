// Resolve a NATIVE executable, optionally refusing launcher shims (plan G7, D-19, X16).
//
// Windows: launching through a shim (cmd.exe -> node -> target) leaves orphan grandchildren when
// the parent is killed, so where a native exe is required we resolve the vendored .exe next to
// an npm shim and refuse shim-only installs. The PATH lookup uses `where.exe` through the
// process primitive.
//
// Linux (plan §1.13): `PATH` is searched in-process (absolute entries only, as the check runner
// does). "Native" means an ELF executable; an npm-installed `codex` is a Node launcher script
// (`<prefix>/bin/codex` -> `…/@openai/codex/bin/codex.js`), which is mapped to the ELF binary
// vendored in the platform package, so the identity that is probed, granted and launched is the
// real Codex binary. A launcher without one is refused when a native executable is required.
// This module never imports node:child_process directly.

import { accessSync, closeSync, constants, existsSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { runProcess } from "./spawn.js";

export interface ResolveOptions {
  /** Explicit path from configuration; takes precedence over PATH lookup. */
  configured?: string | null;
  /** Refuse to return a shim when no native exe can be resolved next to it. */
  refuseShim?: boolean;
  /** Candidate vendored-native locations relative to a shim's directory (Windows) or a launcher's real path (Linux). */
  shimVendorCandidates?: (shimDir: string) => string[];
  /** Environment for the PATH lookup. */
  env?: Record<string, string>;
}

export interface ResolveResult {
  ok: boolean;
  path?: string;
  how?: "configured" | "configured-shim-resolved" | "path-native" | "path-shim-resolved" | "path";
  error?: string;
}

const WIN = process.platform === "win32";

/** The npm `@openai/codex` vendored-native layout (plan X16): Windows `.exe` candidates next to a shim, or Linux ELF candidates for a launcher. */
export function codexVendorCandidates(shimDir: string): string[] {
  return WIN ? codexWindowsCandidates(shimDir) : codexLinuxCandidates(shimDir);
}

function codexWindowsCandidates(shimDir: string): string[] {
  const triples = ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"];
  const bases = [
    join(shimDir, "node_modules", "@openai", "codex", "vendor"),
    join(shimDir, "..", "node_modules", "@openai", "codex", "vendor"),
    join(shimDir, "..", "lib", "node_modules", "@openai", "codex", "vendor"),
  ];
  const out: string[] = [];
  for (const b of bases) for (const t of triples) out.push(join(b, t, "bin", "codex.exe"));
  return out;
}

/**
 * Linux: candidates for the ELF binary of an npm-installed Codex, given the directory holding the
 * launcher's REAL path (`…/@openai/codex/bin`). Codex 0.160 nests the platform package
 * (`@openai/codex/node_modules/@openai/codex-linux-x64/vendor/<triple>/bin/codex`); npm may also
 * hoist it next to `@openai/codex`; older releases vendored the binary in the main package.
 */
export function codexLinuxCandidates(launcherDir: string): string[] {
  const pkg = dirname(launcherDir);
  const out: string[] = [];
  for (const [arch, triple] of [
    ["x64", "x86_64-unknown-linux-musl"],
    ["arm64", "aarch64-unknown-linux-musl"],
  ] as const) {
    for (const platformPkg of [join(pkg, "node_modules", "@openai", `codex-linux-${arch}`), join(pkg, "..", `codex-linux-${arch}`)]) {
      out.push(join(platformPkg, "vendor", triple, "bin", "codex"));
    }
    out.push(join(pkg, "vendor", triple, "bin", "codex"), join(pkg, "vendor", triple, "codex", "codex"));
  }
  return out;
}

/** Is `p` an ELF executable (Linux "native")? */
export function isElfExecutable(p: string): boolean {
  let fd: number | null = null;
  try {
    fd = openSync(p, "r");
    const b = Buffer.alloc(4);
    return readSync(fd, b, 0, 4, 0) === 4 && b.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  } catch {
    return false;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

function isNativeExe(p: string, name: string): boolean {
  if (!WIN) return isElfExecutable(p);
  return /\.exe$/i.test(p) && basename(p).toLowerCase() === `${name.toLowerCase()}.exe`;
}

function shimToNative(shimPath: string, candidates: (dir: string) => string[]): string | null {
  // Linux: npm's bin entry is a symlink to the launcher; the vendored binary is relative to the launcher's real location.
  let dir = dirname(shimPath);
  if (!WIN) {
    try {
      dir = dirname(realpathSync(shimPath));
    } catch {
      return null;
    }
  }
  return candidates(dir).find((g) => existsSync(g) && (WIN || isElfExecutable(g))) ?? null;
}

/** Linux: every executable named `name` in the absolute PATH entries, in PATH order. */
function posixPathHits(name: string, env: Record<string, string> | NodeJS.ProcessEnv): string[] {
  const out: string[] = [];
  for (const dir of (env["PATH"] ?? "").split(":")) {
    if (!dir || !isAbsolute(dir)) continue;
    const p = join(dir, name);
    try {
      if (!statSync(p).isFile()) continue;
      accessSync(p, constants.X_OK);
      out.push(p);
    } catch {
      /* not here */
    }
  }
  return out;
}

/**
 * Resolve `name` (e.g. "git", "codex") to a native executable path.
 */
export async function resolveNativeExecutable(name: string, opts: ResolveOptions = {}): Promise<ResolveResult> {
  const candidates = opts.shimVendorCandidates ?? (() => []);

  if (opts.configured) {
    if (!existsSync(opts.configured)) return { ok: false, error: `configured ${name} not found: ${opts.configured}` };
    if (isNativeExe(opts.configured, name) || (WIN && /\.exe$/i.test(opts.configured))) {
      return { ok: true, path: opts.configured, how: "configured" };
    }
    const nat = shimToNative(opts.configured, candidates);
    if (nat) return { ok: true, path: nat, how: "configured-shim-resolved" };
    if (opts.refuseShim) return { ok: false, error: `configured ${name} is a shim and no native ${WIN ? ".exe" : "(ELF) executable"} was found: ${opts.configured}` };
    return { ok: true, path: opts.configured, how: "configured" };
  }

  let hits: string[];
  if (WIN) {
    const whereExe = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "where.exe");
    const r = await runProcess(whereExe, [name], { wallMs: 15_000, ...(opts.env ? { env: opts.env } : {}) });
    hits = r.stdout
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
  } else {
    hits = posixPathHits(name, opts.env ?? process.env);
  }
  if (hits.length === 0) return { ok: false, error: `${name} not found on PATH` };

  const native = hits.find((h) => isNativeExe(h, name));
  if (native) return { ok: true, path: native, how: "path-native" };

  for (const h of hits) {
    const nat = shimToNative(h, candidates);
    if (nat) return { ok: true, path: nat, how: "path-shim-resolved" };
  }

  if (opts.refuseShim) return { ok: false, error: `only shim(s) found for ${name}, no native ${WIN ? ".exe" : "(ELF) executable"}: ${hits.join(", ")}` };
  return { ok: true, path: hits[0]!, how: "path" };
}
