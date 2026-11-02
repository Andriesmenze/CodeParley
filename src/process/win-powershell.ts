// Windows PowerShell for process facts: the process table and owner start times (M1.6-16).
//
// Every call starts a fresh powershell.exe. Using a cmdlet that is not yet loaded (for example
// Get-CimInstance) makes Windows PowerShell analyze the modules on its module path, and 5.1
// always adds `Program Files\WindowsPowerShell\Modules` to that path. With a large module set —
// GitHub's windows-latest image installs AWSPowerShell, Microsoft.Graph, SqlServer and more
// there; developer machines often have big modules too — and cold caches, that took long
// enough that every process-table read on the CI runner hit its time limit and failed.
// Measured locally with 400 freshly installed modules on the path: Get-CimInstance 5.8 s, the
// same query through .NET's WMI searcher 0.8 s, identical rows. The scripts therefore use no
// cmdlets at all: `[wmisearcher]` (System.Management) and language constructs only. The child's
// module path is also limited to Windows' own modules, so a cmdlet added later cannot bring the
// cost back unnoticed.

import { join } from "node:path";
import { buildChildEnv } from "./env.js";

function systemRoot(): string {
  return process.env["SystemRoot"] ?? "C:\\Windows";
}

/** This installation's Windows PowerShell 5.1 (never resolved through PATH). */
export function powerShellExe(): string {
  return join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/** The usual child-environment allowlist, with the module path limited to Windows' modules. */
export function powerShellEnv(): Record<string, string> {
  return { ...buildChildEnv().env, PSModulePath: join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "Modules") };
}

/** PowerShell expression: a WMI `CreationDate` (DMTF text) in `$v` as epoch milliseconds. */
export const DMTF_TO_EPOCH_MS = "([DateTimeOffset][Management.ManagementDateTimeConverter]::ToDateTime($v)).ToUnixTimeMilliseconds()";
