// Launch-argument parsing (plan §7.5). Launch args can ADD allowed roots and point at the
// config/data locations and executables; they can never weaken a trusted setting (that is
// enforced by how scope/verification use them, not here).

export interface LaunchArgs {
  allowedRoots: string[];
  configFile?: string;
  home?: string;
  codex?: string;
  git?: string;
  traceProtocol?: string;
  diagnostics: boolean;
}

const VALUE_FLAGS: Record<string, keyof LaunchArgs> = {
  "--config": "configFile",
  "--home": "home",
  "--codex": "codex",
  "--git": "git",
  "--trace-protocol": "traceProtocol",
};

/** Parse process-style argv (without node/script). Unknown flags throw. */
export function parseLaunchArgs(argv: readonly string[]): LaunchArgs {
  const out: LaunchArgs = { allowedRoots: [], diagnostics: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--allowed-root") {
      const v = argv[++i];
      if (v === undefined) throw new Error("--allowed-root requires a value");
      out.allowedRoots.push(v);
    } else if (a === "--diagnostics") {
      out.diagnostics = true;
    } else if (a in VALUE_FLAGS) {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} requires a value`);
      (out as unknown as Record<string, unknown>)[VALUE_FLAGS[a]!] = v;
    } else {
      throw new Error(`unknown launch argument: ${a}`);
    }
  }
  return out;
}
