// The CodeParley rename (plan §1.12; M1.6). User-facing identity changed; the
// compatibility-sensitive persisted identifiers did not (renaming them would make every M1
// capture record unreadable and invalidate every approval digest and evidence identity).
// Pure tests: they run on every platform.

import { describe, it, expect } from "vitest";
import { mkdir, mkdtemp } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DATA_DIR_NAME, LEGACY_DATA_DIR_NAME, defaultDataHomes, resolveDataHome } from "../src/store/paths.js";
import { defaultHardExclusions } from "../src/workspace/scope.js";
import { chooseRepoPreferences, LEGACY_REPO_PREFERENCES_PATH, REPO_PREFERENCES_PATH } from "../src/schemas/repo-preferences.js";
import { PRODUCT_NAME, TOOL_VERSION } from "../src/common/version.js";
import { SERVER_INSTRUCTIONS, SERVER_NAME, toolDefinitions } from "../src/server/tools.js";
import { USAGE } from "../src/cli/cli.js";
import { SOURCE_ID_SCHEMA } from "../src/capture/identity.js";
import { CHECK_SPEC_ID_SCHEMA, EXECUTION_INPUT_ID_SCHEMA } from "../src/checks/identity.js";
import { CHECK_DEFINITION_DIGEST_SCHEMA, PROJECT_APPROVAL_DIGEST_SCHEMA } from "../src/checks/project-config.js";
import { REVIEW_INPUT_ID_SCHEMA } from "../src/engine/identities.js";
import { PROFILE_NAME } from "../src/agents/codex/argv.js";
import { STATE_SCHEMA_VERSION } from "../src/schemas/run-state.js";
import { CaptureRecordSchema } from "../src/schemas/capture.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { name: string; version: string; bin: Record<string, string> };

describe("CodeParley identity", () => {
  it("package, CLI, server name and version", () => {
    expect(PRODUCT_NAME).toBe("CodeParley");
    expect(pkg.name).toBe("code-parley");
    expect(pkg.version).toBe(TOOL_VERSION);
    expect(Object.keys(pkg.bin).sort()).toEqual(["code-parley", "code-parley-mcp"]);
    expect(SERVER_NAME).toBe("code-parley");
    expect(USAGE[0]).toMatch(/^usage: code-parley /);
    expect(SERVER_INSTRUCTIONS).toMatch(/^CodeParley: /);
  });

  it("no host-facing or CLI text still names the old product", () => {
    const texts = [SERVER_INSTRUCTIONS, ...USAGE, ...toolDefinitions(true).flatMap((t) => [t.title, t.description])];
    for (const t of texts) expect(t).not.toMatch(/ai-review-loop|AI Review Loop|AIReviewLoop/);
    // The CLI that tool texts point the user to is the renamed one.
    expect(SERVER_INSTRUCTIONS).toContain("code-parley checks approve");
  });

  it("generic architecture terms are kept (the tool surface is a stable API)", () => {
    expect(toolDefinitions(false).map((t) => t.name)).toContain("stop_review_loop");
  });
});

describe("compatibility-sensitive identifiers are frozen", () => {
  it("schema and digest-domain identifiers keep the internal arl. namespace", () => {
    expect(SOURCE_ID_SCHEMA).toBe("arl.source-id.v1");
    expect(CHECK_SPEC_ID_SCHEMA).toBe("arl.check-spec-id.v1");
    expect(EXECUTION_INPUT_ID_SCHEMA).toBe("arl.execution-input-id.v1");
    expect(CHECK_DEFINITION_DIGEST_SCHEMA).toBe("arl.check-definition.v1");
    expect(PROJECT_APPROVAL_DIGEST_SCHEMA).toBe("arl.project-approval.v1");
    expect(REVIEW_INPUT_ID_SCHEMA).toBe("arl.review-input-id.v1");
    expect(STATE_SCHEMA_VERSION).toBe(1);
    // A persisted M1 capture record still parses by its schema literal.
    const probe = CaptureRecordSchema.safeParse({ schema: "arl.capture-record.v1" });
    expect(probe.success ? [] : probe.error.issues.filter((i) => i.path[0] === "schema")).toEqual([]);
  });

  it("the Codex permission-profile name stays part of the validated isolation flags", () => {
    expect(PROFILE_NAME).toBe("ai_review");
  });
});

describe("--home", () => {
  it("--home always wins, on every platform, and holds config.json too", () => {
    expect(resolveDataHome({ home: "X:\\h", env: { LOCALAPPDATA: "Y:\\l", XDG_STATE_HOME: "/s" } })).toEqual({ dataHome: "X:\\h", configFile: join("X:\\h", "config.json"), usedFallback: false, legacyName: false });
  });
});

describe.runIf(process.platform === "linux")("data and configuration on Linux: XDG base directories (plan §1.13)", () => {
  it("state under $XDG_STATE_HOME/code-parley, configuration under $XDG_CONFIG_HOME/code-parley", () => {
    expect(resolveDataHome({ env: { HOME: "/home/me", XDG_STATE_HOME: "/x/state", XDG_CONFIG_HOME: "/x/config" } })).toEqual({
      dataHome: "/x/state/code-parley",
      configFile: "/x/config/code-parley/config.json",
      usedFallback: false,
      legacyName: false,
    });
  });

  it("defaults to ~/.local/state and ~/.config; a relative XDG variable is ignored, as the specification requires", () => {
    expect(resolveDataHome({ env: { HOME: "/home/me", XDG_STATE_HOME: "relative/state" } })).toEqual({
      dataHome: "/home/me/.local/state/code-parley",
      configFile: "/home/me/.config/code-parley/config.json",
      usedFallback: false,
      legacyName: false,
    });
  });

  it("neither the data nor the configuration directory can become, or contain, an allowed root; nor can system directories or the home itself", () => {
    const env = { HOME: "/home/me" };
    const homes = defaultDataHomes(env);
    expect(homes).toEqual(["/home/me/.local/state/code-parley", "/home/me/.config/code-parley"]);
    const ex = defaultHardExclusions(env, homes[0]!, homes);
    for (const h of homes) expect(ex.containedDirs).toContain(h);
    for (const d of ["/usr", "/etc", "/proc", "/sys", "/dev", "/run", "/boot"]) expect(ex.containedDirs).toContain(d);
    expect(ex.exactDirs).toEqual(["/home/me"]);
  });
});

describe.runIf(process.platform === "win32")("data home: CodeParley, with the legacy AIReviewLoop folder still found", () => {
  async function base(): Promise<string> {
    return mkdtemp(join(tmpdir(), "cp-home-"));
  }

  it("new installs use CodeParley; an existing AIReviewLoop folder is used until CodeParley exists", async () => {
    const b = await base();
    const env = { LOCALAPPDATA: b };
    expect(resolveDataHome({ env })).toEqual({ dataHome: join(b, DATA_DIR_NAME), configFile: join(b, DATA_DIR_NAME, "config.json"), usedFallback: false, legacyName: false });
    await mkdir(join(b, LEGACY_DATA_DIR_NAME));
    expect(resolveDataHome({ env })).toEqual({ dataHome: join(b, LEGACY_DATA_DIR_NAME), configFile: join(b, LEGACY_DATA_DIR_NAME, "config.json"), usedFallback: false, legacyName: true });
    await mkdir(join(b, DATA_DIR_NAME));
    expect(resolveDataHome({ env })).toEqual({ dataHome: join(b, DATA_DIR_NAME), configFile: join(b, DATA_DIR_NAME, "config.json"), usedFallback: false, legacyName: false });
  });

  it("the USERPROFILE fallback applies to both names", async () => {
    const b = await base();
    await mkdir(join(b, "AppData", "Local", LEGACY_DATA_DIR_NAME), { recursive: true });
    expect(resolveDataHome({ env: { USERPROFILE: b } })).toEqual({ dataHome: join(b, "AppData", "Local", LEGACY_DATA_DIR_NAME), configFile: join(b, "AppData", "Local", LEGACY_DATA_DIR_NAME, "config.json"), usedFallback: true, legacyName: true });
  });

  it("neither default folder can become, or contain, an allowed root", () => {
    const env = { LOCALAPPDATA: "C:\\Users\\me\\AppData\\Local", SystemRoot: "C:\\Windows" };
    const homes = defaultDataHomes(env);
    expect(homes.map((h) => h.split(/[\\/]/).at(-1))).toEqual([DATA_DIR_NAME, LEGACY_DATA_DIR_NAME]);
    const ex = defaultHardExclusions(env, homes[0]!, homes);
    for (const h of homes) expect(ex.containedDirs).toContain(h);
    expect(ex.containedDirs.filter((d) => d === homes[0])).toHaveLength(1);
  });
});

describe("repository preferences location (.code-parley/config.json; legacy .ai-loop/config.json)", () => {
  const has = (...paths: string[]) => (p: string) => paths.includes(p);

  it("prefers the new file and says the legacy one is ignored", () => {
    expect(chooseRepoPreferences(has(REPO_PREFERENCES_PATH))).toEqual({ path: REPO_PREFERENCES_PATH, warnings: [] });
    const both = chooseRepoPreferences(has(REPO_PREFERENCES_PATH, LEGACY_REPO_PREFERENCES_PATH));
    expect(both.path).toBe(REPO_PREFERENCES_PATH);
    expect(both.warnings.join()).toMatch(/\.ai-loop\/config\.json is ignored/);
  });

  it("reads the legacy file only when the new one is absent, with a warning", () => {
    const r = chooseRepoPreferences(has(LEGACY_REPO_PREFERENCES_PATH));
    expect(r.path).toBe(LEGACY_REPO_PREFERENCES_PATH);
    expect(r.warnings.join()).toMatch(/legacy location/);
    expect(chooseRepoPreferences(has())).toEqual({ path: null, warnings: [] });
  });

  it("a file under a confidentiality exclusion is neither read nor named", () => {
    const hidden = (p: string) => p === LEGACY_REPO_PREFERENCES_PATH;
    expect(chooseRepoPreferences(has(LEGACY_REPO_PREFERENCES_PATH), hidden)).toEqual({ path: null, warnings: [] });
    expect(chooseRepoPreferences(has(REPO_PREFERENCES_PATH, LEGACY_REPO_PREFERENCES_PATH), hidden)).toEqual({ path: REPO_PREFERENCES_PATH, warnings: [] });
    expect(chooseRepoPreferences(has(REPO_PREFERENCES_PATH), (p) => p === REPO_PREFERENCES_PATH)).toEqual({ path: null, warnings: [] });
  });
});
