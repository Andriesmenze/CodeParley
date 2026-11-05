import { fixCodexExecutable } from "../src/engine/fix-operation.js";
import type { ConfigSection } from "../src/custodian/protocol.js";
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { assertArgvSafe, FORBIDDEN_SANDBOX_MODES, isolationFlags, UnsafeArgvError } from "../src/agents/codex/argv.js";

// The Phase 4 load-bearing boundaries, enforced statically against src/ so a later change cannot quietly cross them:
// (1) only apply_fix (and `fix reconcile`'s restore of verified preimages) reaches the write step, which writes through
// its verified path only; (2) no module produces a confirmation outside the operator channel (the CLI); (3) the writable
// Codex grant lives in exactly one place and the reviewer argv still cannot emit a write; (4) the delegated-fix machinery
// is unreachable from the hooks, the helper, the reaper and the review operation; (5) no MCP tool input carries
// contents, a diff, a writable surface or a confirmation.

const srcDir = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src");
const srcRel = (file: string): string => relative(srcDir, file).split(sep).join("/");

function allTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...allTsFiles(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

/** Every src/ file (relative to src/) `entryRel` reaches through relative imports, static or dynamic. */
function reachable(entryRel: string): Set<string> {
  const seen = new Set<string>();
  const stack = [entryRel];
  while (stack.length) {
    const rel = stack.pop()!;
    if (seen.has(rel)) continue;
    seen.add(rel);
    const text = readFileSync(join(srcDir, rel), "utf8");
    for (const m of text.matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)) {
      stack.push(srcRel(join(dirname(join(srcDir, rel)), m[1]! + ".ts")));
    }
  }
  return seen;
}

// Phase 4 Increment 1 made the fixer-LAUNCH modules live (the cp_fix self-test and launch gate). Increment 2 wired the
// delegation (engine/fix-operation.ts) and the operator's FIX confirmation (engine/fix-confirmation.ts, CLI only).
// Increment 3 (contract §3.1, revised deliberately here) exposes the delegation and the application as the MCP tools
// delegate_fix and apply_fix (server/tools.ts), the application's write step (engine/fix-apply.ts) and the owner's
// decision (engine/fix-decision.ts: operator surface, `code-parley fix confirm|reject`, CLI only).
const FIX_FOUNDATION_MODULES = ["policy/delegated-fix.ts", "capture/fix-scan.ts", "workspace/disposable-workspace.ts"];
const FIX_LAUNCH_MODULES = ["agents/codex/fix-profile.ts", "agents/codex/fix-selftest.ts", "agents/codex/fix-isolation.ts", "agents/codex/fix-launcher.ts"];
const FIX_DELEGATION = "engine/fix-operation.ts";
const FIX_CONFIRMATION = "engine/fix-confirmation.ts";
const FIX_WRITE = "engine/fix-apply.ts";
const FIX_DECISION = "engine/fix-decision.ts";
const FIX_MODULES = [...FIX_FOUNDATION_MODULES, ...FIX_LAUNCH_MODULES, FIX_DELEGATION, FIX_CONFIRMATION, FIX_WRITE, FIX_DECISION];
/** The entry points and modules that never reach any delegated-fix module. */
const NO_FIX_ENTRIES = ["hooks/main.ts", "hooks/adapter.ts", "process/session-reaper-main.ts", "helper/main.ts", "engine/review-operation.ts"];

/** The src/ modules that import `target` (static or dynamic relative imports). */
const importers = (target: string): string[] =>
  allTsFiles(srcDir)
    .map(srcRel)
    .filter((rel) => rel !== target && [...readFileSync(join(srcDir, rel), "utf8").matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)].some((m) => srcRel(join(dirname(join(srcDir, rel)), m[1]! + ".ts")) === target))
    .sort();

describe("Phase 4 Increment 3: only apply_fix reaches the write step, and it writes only through its verified path", () => {
  it("the P4.0 application-authorization contract and its FixConfirmation type stay unused (the custodian holds the confirmation)", () => {
    const refs: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const rel = srcRel(file);
      if (rel === "policy/delegated-fix.ts") continue; // the definitions
      if (/checkApplicationAuthorization\s*\(|\bFixConfirmation\b/.test(readFileSync(file, "utf8"))) refs.push(rel);
    }
    expect(refs).toEqual([]);
  });

  it("the write step (engine/fix-apply.ts) is imported only by the apply_fix tool and the `fix reconcile` command", () => {
    expect(importers(FIX_WRITE)).toEqual(["cli/fix-commands.ts", "server/tools.ts"]);
  });

  it("it writes the worktree only through an exclusive temporary file and one rename in a verified parent, or a verified delete", () => {
    const t = readFileSync(join(srcDir, FIX_WRITE), "utf8");
    expect(t.match(/\brename\(/g)?.length, "one rename: replaceVerified").toBe(1);
    expect(t.match(/open\(tmp, "wx"\)/g)?.length, "the temporary file is created exclusively").toBe(1);
    expect(/\bwriteFile\(|\bappendFile\(|\bcopyFile\(|\bcp\(/.test(t.replace(/fh\.writeFile\(/g, "")), "no other write primitive").toBe(false);
    // The rename follows the re-verification of the parent and the target (§3.6.1 step 5).
    expect(/await requireSameParent\(t, root\);\s*\n\s*if \(expected\) await requireAtPreimage\(root, t\.abs, expected, new Map\(\)\);\s*\n\s*else await requireAbsent\(t\.abs\);\s*\n\s*await rename\(tmp, t\.abs\);/.test(t)).toBe(true);
  });
});

describe("Phase 4 Increment 3: no module produces a confirmation outside the operator channel", () => {
  it("only the operator client sends prepare_fix_decision (the protocol names it; the simulated custodian serves it)", () => {
    const senders = allTsFiles(srcDir).filter((f) => /["']prepare_fix_decision["']/.test(readFileSync(f, "utf8"))).map(srcRel).sort();
    expect(senders).toEqual(["custodian/operator.ts", "custodian/protocol.ts", "custodian/transport.ts"]);
  });

  it("the owner's decision (engine/fix-decision.ts) is reachable from the CLI only — never from the MCP server, the hooks or the helper", () => {
    // Step 7.1: the guided review (cli/fix-review.ts, `fix review`) is the second CLI importer; it is reached from
    // cli/fix-commands.ts only.
    expect(importers(FIX_DECISION)).toEqual(["cli/fix-commands.ts", "cli/fix-review.ts"]);
    expect(importers("cli/fix-review.ts")).toEqual(["cli/fix-commands.ts"]);
    for (const entry of ["server/main.ts", "server/server.ts", "server/tools.ts", "hooks/main.ts", "hooks/adapter.ts", "helper/main.ts"]) {
      const reach = reachable(entry);
      expect(reach.has(FIX_DECISION), `${entry} reaches the owner's decision`).toBe(false);
      expect(reach.has("custodian/operator.ts"), `${entry} reaches the operator client`).toBe(false);
      expect(reach.has("cli/fix-review.ts"), `${entry} reaches fix review`).toBe(false);
    }
    expect(reachable("cli/main.ts").has(FIX_DECISION)).toBe(true);
    expect(reachable("cli/main.ts").has("cli/fix-review.ts")).toBe(true);
  });

  it("Step 7.1: only the operator client sends list_fix_proposals (the protocol names it; the simulated custodian serves it)", () => {
    const senders = allTsFiles(srcDir).filter((f) => /["']list_fix_proposals["']/.test(readFileSync(f, "utf8"))).map(srcRel).sort();
    expect(senders).toEqual(["custodian/operator.ts", "custodian/protocol.ts", "custodian/transport.ts"]);
  });
});

describe("Phase 4 foundation: the writable grant is bounded to one place", () => {
  it("only fix-profile.ts emits a Codex filesystem write grant", () => {
    const emitters: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      if (/=\s*"write"/.test(readFileSync(file, "utf8"))) emitters.push(srcRel(file));
    }
    expect(emitters).toEqual(["agents/codex/fix-profile.ts"]);
  });

  it("the reviewer argv still refuses workspace-write and danger-full-access", () => {
    expect(FORBIDDEN_SANDBOX_MODES).toContain("workspace-write");
    expect(FORBIDDEN_SANDBOX_MODES).toContain("danger-full-access");
    expect(() => assertArgvSafe(["--sandbox", "workspace-write"], "S1")).toThrow(UnsafeArgvError);
    // A real reviewer S1 flag set never contains a write grant.
    const flags = isolationFlags({ mode: "S1", backend: process.platform === "win32" ? "mxc" : "bwrap", installDir: process.platform === "win32" ? "C:\\codex" : "/opt/codex", webSearchDisabledValue: "disabled" });
    expect(flags.join(" ")).not.toContain('="write"');
  });
});

describe("Phase 4: unreachable from the hooks, the helper, the reaper and the review operation", () => {
  it("none of them reaches any delegated-fix module (foundation, launch, delegation, confirmation, decision or write)", () => {
    for (const entry of NO_FIX_ENTRIES) {
      const reach = reachable(entry);
      expect([...reach].filter((f) => FIX_MODULES.includes(f)), `${entry} reaches a delegated-fix module`).toEqual([]);
    }
  });

  it("delegated-fix.ts stays pure (no I/O, process, store, clock, engine or agent imports)", () => {
    const text = readFileSync(join(srcDir, "policy", "delegated-fix.ts"), "utf8");
    expect(/from\s+["'](node:fs|node:fs\/promises|node:child_process|node:os|\.\.\/(store|process|capture|agents|engine|server)\/)/.test(text)).toBe(false);
    expect(/Date\.now\(\)|new Date\(/.test(text)).toBe(false);
  });
});

// Every production entry point: what each may reach of the delegated-fix machinery.
describe("Phase 4: what each production entry point reaches", () => {
  // package.json bin (cli, MCP server), the hook entry, the session reaper (spawned by URL), and the modules the Claude
  // Code plugin's bin/*.mjs import directly (hooks/adapter, server/server). helper/main.ts (P3.4C-5): the custodian
  // helper's workload entry, run by the CodeParleyHelper service.
  const ENTRIES = ["cli/main.ts", "server/main.ts", "server/server.ts", "hooks/main.ts", "hooks/adapter.ts", "process/session-reaper-main.ts", "helper/main.ts"];
  const SERVER = ["server/main.ts", "server/server.ts"];

  it("the entry list names every src/ entry point", () => {
    const mains = allTsFiles(srcDir).map(srcRel).filter((f) => /(^|\/|-)main\.ts$/.test(f));
    expect(mains.filter((f) => !ENTRIES.includes(f)), "a new entry point: add it to ENTRIES").toEqual([]);
  });

  it("the MCP server reaches the delegation and the write step (delegate_fix, apply_fix); the CLI the decision, the reconciliation and the cp_fix self-test", () => {
    for (const entry of SERVER) {
      const reach = reachable(entry);
      expect(reach.has(FIX_DELEGATION) && reach.has(FIX_WRITE), `${entry} should reach delegate_fix and apply_fix`).toBe(true);
      // The delegation READS the stored cp_fix record (engine/fix-confirmation.ts storedFixSelfTest); confirming it is the
      // operator's configuration write path, which the server never reaches.
      expect(reach.has("engine/config-authority.ts"), `${entry} reaches the operator's configuration write path`).toBe(false);
    }
    const cli = reachable("cli/main.ts");
    for (const m of [FIX_DECISION, FIX_WRITE, FIX_CONFIRMATION, "agents/codex/fix-selftest.ts"]) expect(cli.has(m), m).toBe(true);
  });

  it("the operator's FIX self-test confirmation payload is built by the CLI only (the delegation only reads the stored record)", () => {
    const payloadUsers = allTsFiles(srcDir).filter((f) => /\bfixSelftestPayload\b/.test(readFileSync(f, "utf8"))).map(srcRel).sort();
    expect(payloadUsers).toEqual(["cli/config-commands.ts", "engine/fix-confirmation.ts"]);
    for (const entry of ENTRIES) if (entry !== "cli/main.ts" && !SERVER.includes(entry)) expect(reachable(entry).has(FIX_CONFIRMATION), entry).toBe(false);
  });
});

describe("Phase 4 Increment 2: the delegation's own boundaries", () => {
  const text = (rel: string): string => readFileSync(join(srcDir, rel), "utf8");

  it("the delegation reaches exactly the Increment-2 machinery: the launch gate, the workspace, the scan — and no apply step", () => {
    const reach = reachable(FIX_DELEGATION);
    for (const m of ["agents/codex/fix-launcher.ts", "workspace/disposable-workspace.ts", "capture/fix-scan.ts", "policy/delegated-fix.ts", FIX_CONFIRMATION]) expect(reach.has(m), m).toBe(true);
    // The delegation neither decides nor applies: it reaches neither the owner's decision nor the write step.
    expect(reach.has(FIX_DECISION) || reach.has(FIX_WRITE) || reach.has("custodian/operator.ts")).toBe(false);
  });

  it("the delegation never names the primary worktree as a write target: it writes only the disposable workspace", () => {
    const t = text(FIX_DELEGATION);
    // Every write is under the workspace's tree (seeding); nothing is written relative to the repository root.
    expect(t.match(/writeFile\(/g)?.length).toBe(1);
    expect(/writeFile\(target, bytes, \{ flag: "wx" \}\)/.test(t)).toBe(true);
    expect(/join\(ws\.tree, \.\.\.f\.path\.split\("\/"\)\)/.test(t)).toBe(true);
    expect(/(writeFile|rename|copyFile|rm|unlink)\([^)]*repository_root/.test(t)).toBe(false);
  });

  it("the custodian's validation (the simulated custodian) shares no code with the engine's policy: it trusts no engine claim", () => {
    const reach = reachable("custodian/simulated-fix.ts");
    expect([...reach].filter((f) => f.startsWith("policy/") || f.startsWith("engine/") || f.startsWith("capture/") || f.startsWith("agents/"))).toEqual([]);
  });
});

describe("Phase 4 Increment 3: the MCP surface carries no contents, writable surface or confirmation", () => {
  it("delegate_fix and apply_fix are the only fix tools; no tool confirms", async () => {
    const { toolDefinitions } = await import("../src/server/tools.js");
    const names = toolDefinitions(true).map((d) => d.name);
    expect(names.filter((n) => /fix|apply|delegat|confirm|patch/i.test(n)).sort()).toEqual(["apply_fix", "delegate_fix"]);
  });

  it("no MCP tool input field names a content, diff, writable, workspace or confirmation surface; proposal_id only on apply_fix, the task and boundary only on delegate_fix", async () => {
    const { toolDefinitions } = await import("../src/server/tools.js");
    const forbidden = /^(apply_patch|patch|diff|diffs|content|contents|bytes|writable|writable_dirs|workspace|workspace_dir|confirm|confirmed|confirmation|confirmation_id|approval|approved)$/i;
    const offenders: string[] = [];
    const fields = new Map<string, string[]>();
    const visit = (tool: string, schema: unknown, path: string): void => {
      if (!schema || typeof schema !== "object") return;
      for (const [k, v] of Object.entries((schema as { properties?: Record<string, unknown> }).properties ?? {})) {
        if (forbidden.test(k)) offenders.push(`${tool}: ${path}${k}`);
        if (path === "") fields.set(tool, [...(fields.get(tool) ?? []), k]);
        visit(tool, v, `${path}${k}.`);
      }
      const items = (schema as { items?: unknown }).items;
      if (items) visit(tool, items, `${path}[].`);
    };
    for (const d of toolDefinitions(true)) visit(d.name, d.inputSchema, "");
    expect(offenders).toEqual([]);
    expect([...fields].filter(([, f]) => f.includes("proposal_id")).map(([t]) => t)).toEqual(["apply_fix"]);
    expect([...fields].filter(([, f]) => f.includes("boundary") || f.includes("task")).map(([t]) => t)).toEqual(["delegate_fix"]);
    expect(fields.get("apply_fix")!.sort()).toEqual(["proposal_id", "run_id"]);
  });
});

describe("a protected fix launches the approved Codex", () => {
  it("the operator-approved installation wins over config.json and PATH (found by the first real delegated fix on an installed Linux system)", () => {
    const section = { repository: { codexInstallation: { path: "/opt/codeparley-codex/0.160.0/bin/codex", sha256: "a".repeat(64) } } } as unknown as ConfigSection;
    expect(fixCodexExecutable(section, null)).toBe("/opt/codeparley-codex/0.160.0/bin/codex");
    expect(fixCodexExecutable(section, "/home/i/other/codex")).toBe("/opt/codeparley-codex/0.160.0/bin/codex");
    expect(fixCodexExecutable({ repository: null } as unknown as ConfigSection, "/home/i/other/codex")).toBe("/home/i/other/codex");
  });
});
