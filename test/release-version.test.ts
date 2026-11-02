// Phase 6 Increment 1: one release version across the engine, the plugin and both custodians. package.json is the
// source; the engine's TOOL_VERSION (also in rename.test.ts), the plugin template's base version and the custodians'
// shared Directory.Build.props must equal it. The plugin build stamps the content digest as a pre-release identifier;
// the custodian's `version` verb reports the same version with its build commit, its protocol and its host.

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { TOOL_VERSION } from "../src/common/version.js";
import { CUSTODIAN_PROTOCOL_VERSION } from "../src/custodian/protocol.js";
// @ts-expect-error -- a plain .mjs build script without type declarations
import { versionOf } from "../plugin/plugin-content.mjs";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(root, rel), "utf8");
const release = (JSON.parse(read("package.json")) as { version: string }).version;

describe("release version identity (Phase 6 Increment 1)", () => {
  it("the engine, the plugin template and the custodians carry the package's release version", () => {
    expect(release).toMatch(/^\d+\.\d+\.\d+$/);
    expect(TOOL_VERSION).toBe(release);
    expect((JSON.parse(read("plugin/template/.claude-plugin/plugin.json")) as { version: string }).version).toBe(release);
    expect(/<Version>([^<]+)<\/Version>/.exec(read("custodian/Directory.Build.props"))?.[1]).toBe(release);
  });

  it("a plugin build's version is the release version with the content digest as a pre-release identifier", () => {
    const digest = "b92ce4f4068ce0123456789abcdef";
    expect(versionOf(release, digest)).toBe(`${release}-bb92ce4f4068c`);
    expect(versionOf(`${release}-rc.1`, digest)).toBe(`${release}-rc.1.bb92ce4f4068c`);
  });

  const exe = ["Debug", "Release"].map((c) => join(root, "custodian", "CodeParley.Custodian", "bin", c, "net10.0-windows", "CodeParley.Custodian.exe")).find((p) => existsSync(p));
  it.skipIf(process.platform !== "win32" || exe === undefined)("the built Windows custodian reports the release version, its build commit, the protocol and its host", () => {
    const r = spawnSync(exe!, ["version"], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
    expect(r.status).toBe(0);
    const v = JSON.parse(r.stdout.trim()) as Record<string, unknown>;
    expect(v).toMatchObject({ product: "CodeParley Custodian", version: release, protocol: CUSTODIAN_PROTOCOL_VERSION, host: "windows" });
    expect(String(v["build"])).toMatch(/^[0-9a-f]{40}$/);
  });
});
