import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

// Enforce plan §5.3 layering rule 4 statically: only files under src/process may import
// node:child_process. (The MCP SDK rule arrives with the server in M1.5.)

const srcDir = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src");

/** A file's path relative to src/, with "/" separators (independent of where the checkout lives). */
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

/** Every src/ file (relative to src/) the given entry reaches through relative imports, static or dynamic. */
function reachable(entryRel: string): Set<string> {
  const seen = new Set<string>();
  const stack = [entryRel];
  while (stack.length) {
    const rel = stack.pop()!;
    if (seen.has(rel)) continue;
    seen.add(rel);
    const text = readFileSync(join(srcDir, rel), "utf8");
    for (const m of text.matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)) {
      const target = join(dirname(join(srcDir, rel)), m[1]! + ".ts");
      stack.push(srcRel(target));
    }
  }
  return seen;
}

describe("layering (plan §5.3)", () => {
  it("only src/process/* imports node:child_process", () => {
    const offenders: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      if (/from\s+["']node:child_process["']|require\(\s*["']node:child_process["']\s*\)/.test(text)) {
        const norm = file.replace(/\\/g, "/");
        if (!srcRel(file).startsWith("process/")) offenders.push(norm);
      }
    }
    expect(offenders, `these files import node:child_process outside src/process/: ${offenders.join(", ")}`).toHaveLength(0);
  });

  it("only src/server/sdk.ts imports the MCP SDK (plan §5.3 rule 4, M1.5)", () => {
    const offenders: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      if (/from\s+["']@modelcontextprotocol\//.test(text)) {
        const norm = file.replace(/\\/g, "/");
        if (!norm.endsWith("/src/server/sdk.ts")) offenders.push(srcRel(file));
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the MCP layer stays thin: server/ reaches capture, checks, Codex, processes and paths only through the engine (M1.5)", () => {
    const offenders: string[] = [];
    for (const file of allTsFiles(join(srcDir, "server"))) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/from\s+["']\.\.\/(capture|checks|agents|process|workspace)\//g)) offenders.push(`${srcRel(file)}: ${m[1]}`);
      if (/node:child_process|node:fs["']|node:fs\/promises/.test(text) && !file.replace(/\\/g, "/").endsWith("/server/server.ts")) offenders.push(`${srcRel(file)}: fs/child_process`);
    }
    expect(offenders).toEqual([]);
  });

  it("no shell: nothing sets `shell: true`, and only win-command.ts builds verbatim (self-escaped) command lines (M1.3)", () => {
    const shellTrue: string[] = [];
    const verbatim: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const norm = file.replace(/\\/g, "/");
      const text = readFileSync(file, "utf8");
      if (/shell\s*:\s*true/.test(text)) shellTrue.push(norm);
      if (/windowsVerbatimArguments\s*:\s*true/.test(text)) verbatim.push(srcRel(file));
    }
    expect(shellTrue).toEqual([]);
    expect(verbatim).toEqual(["process/win-command.ts"]);
  });

  it("policy modules are pure: no I/O, process, store or clock imports (plan §5.3 rule 2, M1.4)", () => {
    const offenders: string[] = [];
    for (const file of allTsFiles(join(srcDir, "policy"))) {
      const text = readFileSync(file, "utf8");
      if (/from\s+["'](node:fs|node:fs\/promises|node:child_process|node:os|\.\.\/(store|process|capture|agents|engine)\/)/.test(text) || /Date\.now\(\)|new Date\(/.test(text)) offenders.push(srcRel(file));
    }
    expect(offenders).toEqual([]);
  });

  it("Codex is launched only by the agent adapter, probe and self-test, never with a shell (M1.4)", () => {
    const launchers: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      if (/runProcess\([^)]*launcher\.file|probe\.launcher\.file/.test(text)) launchers.push(srcRel(file));
    }
    expect(launchers.sort()).toEqual(["agents/codex/adapter.ts", "agents/codex/probe.ts", "agents/codex/selftest.ts"]);
  });

  it("enumerates every hardened git call site: each subcommand literal is allowlisted (plan §9.2)", async () => {
    const { isAllowedSubcommand } = await import("../src/capture/git-args.js");
    const sites: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/\.(?:text|run)\(\s*"([a-z-]+)"/g)) sites.push(`${srcRel(file)}:${m[1]}`);
    }
    expect(sites.length).toBeGreaterThan(10);
    const bad = sites.filter((s) => !isAllowedSubcommand(s.split(":").pop()!));
    expect(bad, `non-allowlisted git subcommands: ${bad.join(", ")}`).toEqual([]);
    expect(sites.every((s) => s.startsWith("capture/"))).toBe(true);
  });

  it("Phase 2.3 (P2.3-1): only the CLI's user commands reach the user-record writer; the MCP server has no path to it", () => {
    const importers: string[] = [];
    const serverReach: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      const rel = srcRel(file);
      if (/from\s+["'][./]+(?:engine\/)?user-authority\.js["']/.test(text) && !rel.startsWith("schemas/") && !rel.startsWith("policy/")) importers.push(rel);
      if (rel.startsWith("server/") && /from\s+["'][./]+(?:engine\/user-authority|cli\/)/.test(text)) serverReach.push(rel);
    }
    expect(importers).toEqual(["cli/user-commands.ts"]);
    expect(serverReach).toEqual([]);
  });

  it("Phase 2.3: user decisions and amendments are appended only by engine/user-authority.ts", () => {
    const writers: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      if (/\b(user_decisions|task_amendments)\.(push|unshift|splice)\(|\b(user_decisions|task_amendments)\s*=(?!=)/.test(text)) writers.push(srcRel(file));
    }
    // run-state.ts creates the empty lists of a new run; nothing else may write them.
    expect(writers.sort()).toEqual(["engine/user-authority.ts"]);
  });

  it("Phase 2.3: no MCP tool input has a field that could claim user authority or provenance", async () => {
    const { toolDefinitions } = await import("../src/server/tools.js");
    const forbidden = /^(actor|role|channel|recorded_by|provenance|authority|approved|approved_by(_user)?|approval|user|user_decision|user_decisions|decision|decided_by|waive|waiver|waived|defer_by_user|amendment|amendments|task_amendments|assurance|mark_pass|pass|completion|ready)$/i;
    const offenders: string[] = [];
    const visit = (tool: string, schema: unknown, path: string): void => {
      if (!schema || typeof schema !== "object") return;
      const props = (schema as { properties?: Record<string, unknown> }).properties ?? {};
      for (const [k, v] of Object.entries(props)) {
        if (forbidden.test(k)) offenders.push(`${tool}: ${path}${k}`);
        visit(tool, v, `${path}${k}.`);
      }
      const items = (schema as { items?: unknown }).items;
      if (items) visit(tool, items, `${path}[].`);
      for (const key of ["anyOf", "oneOf", "allOf"]) for (const s of ((schema as Record<string, unknown>)[key] as unknown[] | undefined) ?? []) visit(tool, s, path);
    };
    for (const d of toolDefinitions(true)) visit(d.name, d.inputSchema, "");
    expect(offenders).toEqual([]);
  });

  it("Phase 3.3a: only the CLI's loop commands reach the operator's grant and resume writers; the MCP server and the hooks have no path to them", () => {
    const importers: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const text = readFileSync(file, "utf8");
      if (/from\s+["'][./]+(?:engine\/)?loop-authority\.js["']/.test(text)) importers.push(srcRel(file));
    }
    expect(importers).toEqual(["cli/loop-commands.ts"]);
  });

  it("P3.4C-0: grants are minted only by the custodian; in TypeScript only custodian/operator.ts asks for one, and the MCP server and the hooks cannot reach it", () => {
    // The only TypeScript ledger is the simulated custodian (test stand-in); the engine keeps none.
    const grantWriters = allTsFiles(srcDir).filter((f) => /grants\.push\(/.test(readFileSync(f, "utf8"))).map(srcRel);
    expect(grantWriters).toEqual(["custodian/transport.ts"]);
    // The authority-creating operations are sent only by the operator module…
    const senders = allTsFiles(srcDir).filter((f) => /["'](prepare_grant|prepare_revoke|prepare_user_record|commit)["']\s*,\s*\{/.test(readFileSync(f, "utf8"))).map(srcRel);
    expect(senders).toEqual(["custodian/operator.ts"]);
    // …which only the operator's CLI paths import (loop grants, and P3.4C-1 protected decisions/amendments)…
    const operatorImporters = allTsFiles(srcDir).filter((f) => /from\s+["'][./]+(?:custodian\/)?operator\.js["']/.test(readFileSync(f, "utf8"))).map(srcRel).sort();
    // (P3.4C-4: and the operator's configuration changes, engine/config-authority.ts — `config` and `loop resume`.)
    // (Phase 4 Increment 3: and the owner's decision on a delegated fix, engine/fix-decision.ts — `fix confirm|reject`.)
    expect(operatorImporters).toEqual(["engine/config-authority.ts", "engine/fix-decision.ts", "engine/loop-authority.ts", "engine/user-authority.ts"]);
    // …and neither the MCP server's nor the hook adapter's import graph reaches it (transitively).
    for (const entry of ["server/main.ts", "server/server.ts", "server/tools.ts", "hooks/main.ts"]) {
      const reach = reachable(entry);
      expect([...reach].filter((f) => f === "custodian/operator.ts" || f === "engine/loop-authority.ts" || f === "engine/config-authority.ts" || f === "engine/fix-decision.ts" || f.startsWith("cli/")), entry).toEqual([]);
    }
    // P3.4C-4: the configuration-changing operation is sent only by the operator module (the simulated custodian, a test
    // stand-in, serves it; the protocol names it).
    const configSenders = allTsFiles(srcDir).filter((f) => /["']prepare_config_record["']/.test(readFileSync(f, "utf8"))).map(srcRel).sort();
    expect(configSenders).toEqual(["custodian/operator.ts", "custodian/protocol.ts", "custodian/transport.ts"]);
  });

  it("P3.4C-0: no weaker authority — nothing in src/ reads grants.json or constructs the simulated custodian, and only the protected-loop gate constructs the real transport", () => {
    // A path to it would need the file name as its own literal (messages that SAY there is no fallback are fine).
    const grantsFile = allTsFiles(srcDir).filter((f) => /["'`]grants\.json["'`]/.test(readFileSync(f, "utf8"))).map(srcRel);
    expect(grantsFile).toEqual([]);
    const simulators = allTsFiles(srcDir).filter((f) => /new\s+SimulatedCustodianTransport\b/.test(readFileSync(f, "utf8"))).map(srcRel);
    expect(simulators).toEqual([]);
    const pipes = allTsFiles(srcDir).filter((f) => /new\s+PipeCustodianTransport\b/.test(readFileSync(f, "utf8"))).map(srcRel);
    expect(pipes).toEqual(["custodian/protected-loops.ts"]);
    // Phase 5: the Linux transport likewise.
    const sockets = allTsFiles(srcDir).filter((f) => /new\s+UnixSocketCustodianTransport\b/.test(readFileSync(f, "utf8"))).map(srcRel);
    expect(sockets).toEqual(["custodian/protected-loops.ts"]);
    const gates = allTsFiles(srcDir).filter((f) => /protectedLoopGate\(/.test(readFileSync(f, "utf8"))).map(srcRel).sort();
    // protected-user-records.ts resolves the authoritative user records on the protected path (a READ only,
    // via CustodianGrants.listUserRecords); user-authority.ts uses the gate for the protected operator WRITE
    // (decide/amend --protected). Neither mints authority outside the custodian.
    // custodian-loop.ts (P3.4C-2) reads and transitions the custodian's loop record — requests the custodian
    // judges; it mints no authority either. custodian-evidence.ts (P3.4C-3) asks whether a run is protected and sends
    // a protected run's evidence (run_transition) — claims the custodian validates; it mints no authority.
    // P3.4C-4: protected-config.ts READS a protected run's held configuration (the config section); config-authority.ts is
    // the operator's configuration write path (CLI only). Neither mints authority outside the custodian.
    // Phase 4 Increment 2: fix-operation.ts asks the gate only whether a validated custodian is available (P4-A refuses a
    // delegated fix otherwise); its fix operation is a request the custodian judges — it mints no authority.
    // Phase 4 Increment 3: fix-apply.ts likewise (P4-A; the application is a request the custodian judges: it consumes a
    // confirmation only the operator made); fix-view.ts READS the custodian's rendering and run records (both surfaces).
    // Phase 5 G-OP: cli/fix-commands.ts takes the gate's transport for the operator's fix confirm|reject, so the decision
    // reads nothing from an engine data home; the custodian accepts it only on the operator surface — it mints no authority.
    // Phase 6 Increment 3: protected-status.ts sends only reads (ping, list_grants, the config section) for status and doctor.
    expect(gates).toEqual(["cli/fix-commands.ts", "custodian/protected-loops.ts", "engine/config-authority.ts", "engine/continuation.ts", "engine/custodian-evidence.ts", "engine/custodian-loop.ts", "engine/fix-apply.ts", "engine/fix-operation.ts", "engine/fix-view.ts", "engine/loop-authority.ts", "engine/protected-config.ts", "engine/protected-status.ts", "engine/protected-user-records.ts", "engine/user-authority.ts"]);
  });

  it("Phase 3.3a: the hook adapter is thin — it reaches the controller only through the engine and holds no routing rules", () => {
    const offenders: string[] = [];
    for (const file of allTsFiles(join(srcDir, "hooks"))) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/from\s+["']\.\.\/(policy|capture|checks|agents|process|workspace|schemas|server|cli)\//g)) offenders.push(`${srcRel(file)}: imports ${m[1]}`);
      for (const m of text.matchAll(/import\(\s*["']\.\.\/(policy|capture|checks|agents|process|workspace|schemas|server|cli)\//g)) offenders.push(`${srcRel(file)}: imports ${m[1]}`);
      // Routing vocabulary belongs to the engine and the policy, never to the adapter.
      for (const w of ["needs_user_decision", "deriveCompletion", "completion", "continuations", "wakes_per", "budget", "epoch ===", "routeFromEngine", "decideStop", "decideWake"]) if (text.includes(w)) offenders.push(`${srcRel(file)}: mentions ${w}`);
    }
    expect(offenders).toEqual([]);
  });

  it("Phase 3.3a: no MCP tool input can carry a session or binding identity, a budget or a grant", async () => {
    const { toolDefinitions } = await import("../src/server/tools.js");
    const forbidden = /^(session|session_id|sessionid|claude_session|claude_pid|pid|epoch|binding|bind_nonce|nonce|grant|grant_id|budget|budgets|continuations|wakes|deadline|max_continuations|max_wakes|loop_budget)$/i;
    const offenders: string[] = [];
    const visit = (tool: string, schema: unknown, path: string): void => {
      if (!schema || typeof schema !== "object") return;
      for (const [k, v] of Object.entries((schema as { properties?: Record<string, unknown> }).properties ?? {})) {
        if (forbidden.test(k)) offenders.push(`${tool}: ${path}${k}`);
        visit(tool, v, `${path}${k}.`);
      }
    };
    for (const d of toolDefinitions(true)) visit(d.name, d.inputSchema, "");
    expect(offenders).toEqual([]);
  });

  it("only the isolated prepared diff (and M1.1 scope resolution) spawn git outside GitQuery", () => {
    const allowed = ["/src/capture/git-query.ts", "/src/capture/prepared-diff.ts", "/src/workspace/git-toplevel.ts"];
    const offenders: string[] = [];
    for (const file of allTsFiles(srcDir)) {
      const norm = file.replace(/\\/g, "/");
      const text = readFileSync(file, "utf8");
      // A runProcess call whose first argument is a git executable variable.
      if (/runProcess\(\s*(?:o\.|opts\.|this\.opts\.)?gitExe/.test(text) && !allowed.some((a) => norm.endsWith(a))) offenders.push(norm);
    }
    expect(offenders).toEqual([]);
    const pd = readFileSync(join(srcDir, "capture", "prepared-diff.ts"), "utf8");
    expect(pd).toContain('"--no-index"');
    expect(pd).toContain('"--no-ext-diff"');
    expect(pd).toContain('"--no-textconv"');
  });
});
