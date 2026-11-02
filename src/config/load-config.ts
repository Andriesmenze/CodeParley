// Load and merge configuration (plan §7.4, §7.5, §15.1). Resolves the data home, reads and
// validates config.json (defaults applied), and merges launch-arg allowed roots. Returns raw
// root strings; canonicalization and hard exclusions happen in workspace/scope.ts.

import { DomainError } from "../common/errors.js";
import { readTextIfExists } from "../store/atomic.js";
import { resolveDataHome, storeLayout, type StoreLayout } from "../store/paths.js";
import { parseUserConfig, type UserConfig } from "../schemas/config.js";
import type { LaunchArgs } from "./launch-args.js";

export interface LoadedConfig {
  config: UserConfig;
  dataHome: string;
  usedLocalAppDataFallback: boolean;
  /** The legacy `AIReviewLoop` data folder is in use (no `CodeParley` folder yet, plan §1.12). */
  legacyDataHome: boolean;
  layout: StoreLayout;
  /** config.allowed_roots ∪ launch --allowed-root (raw, pre-canonicalization). */
  configuredRoots: string[];
  launchRoots: string[];
  launch: LaunchArgs;
}

export async function loadConfig(launch: LaunchArgs, env: NodeJS.ProcessEnv = process.env): Promise<LoadedConfig> {
  const { dataHome, configFile, usedFallback, legacyName } = resolveDataHome({ home: launch.home ?? null, env });
  const layout = storeLayout(dataHome, configFile);
  const configPath = launch.configFile ?? layout.configFile;

  const raw = await readTextIfExists(configPath);
  let parsedJson: unknown = {};
  if (raw != null) {
    try {
      parsedJson = JSON.parse(raw);
    } catch (e) {
      throw new DomainError("CONFIG_INVALID", `config.json is not valid JSON (${configPath}): ${String((e as Error).message)}`);
    }
  }

  let config: UserConfig;
  try {
    config = parseUserConfig(parsedJson);
  } catch (e) {
    throw new DomainError("CONFIG_INVALID", `config.json failed validation (${configPath}): ${String((e as Error).message)}`, {
      details: { configPath },
    });
  }

  return {
    config,
    dataHome,
    usedLocalAppDataFallback: usedFallback,
    legacyDataHome: legacyName,
    layout,
    configuredRoots: config.allowed_roots,
    launchRoots: launch.allowedRoots,
    launch,
  };
}
