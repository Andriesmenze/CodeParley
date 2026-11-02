import { describe, it, expect } from "vitest";
import { buildChildEnv, isDenied } from "../src/process/env.js";

const source: NodeJS.ProcessEnv = {
  SystemRoot: "C:\\Windows",
  PATH: "C:\\Windows;C:\\tools",
  LOCALAPPDATA: "C:\\Users\\me\\AppData\\Local",
  ANTHROPIC_API_KEY: "sk-secret",
  CLAUDE_CODE_SOMETHING: "x",
  MY_API_KEY: "nope",
  CODEX_API_KEY: "codex-key",
  CODEX_HOME: "C:\\Users\\me\\.codex",
  BUILD_FLAVOR: "release",
};

const win = process.platform === "win32";

describe("buildChildEnv", () => {
  it.runIf(win)("copies Windows basics and always sets NO_COLOR", () => {
    const { env } = buildChildEnv({ source });
    expect(env["SystemRoot"]).toBe("C:\\Windows");
    expect(env["PATH"]).toBe("C:\\Windows;C:\\tools");
    expect(env["NO_COLOR"]).toBe("1");
  });

  it.runIf(!win)("copies Linux basics, never agent/IPC channels or WSL interop, and always sets NO_COLOR", () => {
    const linux: NodeJS.ProcessEnv = {
      PATH: "/usr/bin:/bin",
      HOME: "/home/me",
      LANG: "C.UTF-8",
      XDG_CONFIG_HOME: "/home/me/.config",
      SSH_AUTH_SOCK: "/run/user/1000/ssh-agent",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
      XDG_RUNTIME_DIR: "/run/user/1000",
      WSL_INTEROP: "/run/WSL/2_interop",
      SystemRoot: "C:\\Windows",
    };
    const { env } = buildChildEnv({ source: linux });
    expect(env).toEqual({ PATH: "/usr/bin:/bin", HOME: "/home/me", LANG: "C.UTF-8", XDG_CONFIG_HOME: "/home/me/.config", NO_COLOR: "1" });
    // An agent socket reaches a check only when the user lists it.
    expect(buildChildEnv({ source: linux, passthrough: ["SSH_AUTH_SOCK"] }).env["SSH_AUTH_SOCK"]).toBe("/run/user/1000/ssh-agent");
  });

  it("never passes Claude/Anthropic or secret-shaped variables, even via passthrough", () => {
    const { env, refusedPassthrough } = buildChildEnv({
      source,
      passthrough: ["ANTHROPIC_API_KEY", "CLAUDE_CODE_SOMETHING", "MY_API_KEY", "BUILD_FLAVOR"],
    });
    expect(env["ANTHROPIC_API_KEY"]).toBeUndefined();
    expect(env["CLAUDE_CODE_SOMETHING"]).toBeUndefined();
    expect(env["MY_API_KEY"]).toBeUndefined();
    expect(env["BUILD_FLAVOR"]).toBe("release"); // a benign passthrough is allowed
    expect(refusedPassthrough).toEqual(expect.arrayContaining(["ANTHROPIC_API_KEY", "CLAUDE_CODE_SOMETHING", "MY_API_KEY"]));
  });

  it("excludes Codex auth unless includeCodexAuth is set", () => {
    const without = buildChildEnv({ source });
    expect(without.env["CODEX_API_KEY"]).toBeUndefined();
    expect(without.env["CODEX_HOME"]).toBeUndefined();
    const withAuth = buildChildEnv({ source, includeCodexAuth: true });
    expect(withAuth.env["CODEX_API_KEY"]).toBe("codex-key");
    expect(withAuth.env["CODEX_HOME"]).toBe("C:\\Users\\me\\.codex");
  });

  it("CODEX auth vars cannot be smuggled in via passthrough", () => {
    const { env } = buildChildEnv({ source, passthrough: ["CODEX_API_KEY"] });
    expect(env["CODEX_API_KEY"]).toBeUndefined();
  });

  it("caller extras win last", () => {
    const { env } = buildChildEnv({ source, extra: { NO_COLOR: "0", CI: "1" } });
    expect(env["NO_COLOR"]).toBe("0");
    expect(env["CI"]).toBe("1");
  });

  it("isDenied flags the right names", () => {
    expect(isDenied("ANTHROPIC_API_KEY")).toBe(true);
    expect(isDenied("CLAUDE_X")).toBe(true);
    expect(isDenied("SOME_TOKEN")).toBe(true);
    expect(isDenied("CODEX_API_KEY")).toBe(true);
    expect(isDenied("PATH")).toBe(false);
    expect(isDenied("BUILD_FLAVOR")).toBe(false);
  });
});

describe("buildChildEnv case-insensitive overrides (M1.3)", () => {
  it.runIf(win)("an extra or passthrough name replaces an inherited variable that differs only in case", async () => {
    const { buildChildEnv } = await import("../src/process/env.js");
    const { env } = buildChildEnv({ source: { PATH: "C:\\inherited", CODEPARLEY_X: "1" }, passthrough: ["codeparley_x"], extra: { Path: "C:\\override" } });
    const pathKeys = Object.keys(env).filter((k) => k.toLowerCase() === "path");
    expect(pathKeys).toEqual(["Path"]);
    expect(env["Path"]).toBe("C:\\override");
    expect(Object.keys(env).filter((k) => k.toLowerCase() === "codeparley_x")).toEqual(["codeparley_x"]);
  });

  it.runIf(!win)("Linux names are case-sensitive: `Path` is another variable than `PATH`, and passthrough matches exactly", async () => {
    const { buildChildEnv } = await import("../src/process/env.js");
    const { env } = buildChildEnv({ source: { PATH: "/inherited", CODEPARLEY_X: "1" }, passthrough: ["codeparley_x"], extra: { Path: "/override" } });
    expect(env["PATH"]).toBe("/inherited");
    expect(env["Path"]).toBe("/override");
    expect(env["codeparley_x"]).toBeUndefined();
  });
});
