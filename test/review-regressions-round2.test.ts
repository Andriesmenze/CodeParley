// Regression tests for the bounded re-verification of the M1.4 fixes (round 2): nested
// escaping of confidential path names (F4) and `~<digit>` names judged by filesystem
// semantics rather than appearance (F1 regression). Cancellation evidence (F3) is in
// review-regressions.integration.test.ts.

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdir, realpath, rm } from "node:fs/promises";
import { join, parse } from "node:path";
import { readGrantProblem } from "../src/agents/codex/argv.js";
import { assertCanonicalGrant, resolveInstallDir } from "../src/agents/codex/probe.js";
import { assertTextConfidential, containsWithheldPath, decodedViews, DECODE_LAYERS, redactPaths } from "../src/policy/review-bundle.js";
import { mklinkJunction, tempDir, win } from "./helpers/git-fixture.js";

/** JSON-encode `s` as a string `depth` times (each layer escapes the previous one). */
function nest(s: string, depth: number): string {
  let out = s;
  for (let i = 0; i < depth; i++) out = JSON.stringify(out);
  return out;
}

describe("F4 (round 2): confidential path names through nested encodings", () => {
  const w = new Set(["config/db.env", "secrets/id_rsa", ".env"]);
  const forms = ["config/db.env", "config\\db.env", "CONFIG\\DB.ENV", "Config/Db.Env", "**config/db.env**", "`config\\db.env`", '"config/db.env"', "(config/db.env).", "_config/db.env_", "tree/config/db.env"];

  it("is detected raw, in Markdown, and through every JSON-escaping depth up to the supported bound", () => {
    for (const f of forms) {
      for (let depth = 0; depth <= DECODE_LAYERS; depth++) {
        const text = nest(`see ${f} please`, depth);
        expect(() => assertTextConfidential(text, w, new Set()), `${f} @${depth}: ${text}`).toThrow(/MR-F/);
      }
    }
  });

  it("the reported shape: JSON.stringify({payload: JSON.stringify({path: 'config\\\\db.env'})}) and deeper", () => {
    const once = JSON.stringify({ payload: JSON.stringify({ path: "config\\db.env" }) });
    const twice = JSON.stringify(once);
    const thrice = JSON.stringify(twice);
    for (const t of [once, twice, thrice]) {
      expect(containsWithheldPath(t, w), t).toBe(true); // separators: any escape depth, no decoding needed
      expect(() => assertTextConfidential(t, w, new Set())).toThrow(/MR-F/);
      const r = redactPaths(t, w, { n: 0 });
      expect(r).toContain("[withheld path]");
      expect(() => assertTextConfidential(r, w, new Set()), r).not.toThrow();
    }
  });

  it("escaped separators and escaped letters are caught (letters through bounded decoding)", () => {
    expect(() => assertTextConfidential("config\\u002fdb.env", w, new Set())).toThrow(/MR-F/);
    expect(() => assertTextConfidential("config\\\\u005cdb.env", w, new Set())).toThrow(/MR-F/);
    expect(() => assertTextConfidential("\\u0063onfig/db.env", w, new Set())).toThrow(/MR-F/); // only visible after decoding
    expect(() => assertTextConfidential(nest("\\u0063onfig/db.env", 3), w, new Set())).toThrow(/MR-F/);
  });

  it("near-miss names stay untouched at every depth", () => {
    for (const ok of ["process.env.HOME", "load .env.local", "config/db.env.ts", "config/db.envx", "myconfig/db.env", "config/db-env", "secrets/id_rsa.pub", "x.env"]) {
      for (let depth = 0; depth <= 3; depth++) {
        const text = nest(`use ${ok} here`, depth);
        expect(containsWithheldPath(text, w), `${ok} @${depth}`).toBe(false);
        expect(() => assertTextConfidential(text, w, new Set()), `${ok} @${depth}`).not.toThrow();
        expect(redactPaths(text, w, { n: 0 }), `${ok} @${depth}`).toBe(text);
      }
    }
  });

  it("decoding is bounded: fixed layer count, linear work on hostile input", () => {
    const hostile = "\\".repeat(200_000) + "u0063" + "x".repeat(100_000);
    const t0 = Date.now();
    const views = decodedViews(hostile);
    expect(views.length).toBeLessThanOrEqual(DECODE_LAYERS + 1);
    expect(() => assertTextConfidential(hostile, w, new Set())).not.toThrow();
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});

/** The 8.3 short name of an existing path, or null when 8.3 names are disabled on that volume. */
function shortNameOf(p: string): string | null {
  const r = spawnSync(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "cmd.exe"), ["/d", "/s", "/c", `"for %I in ("${p}") do @echo %~sI"`], { encoding: "utf8", windowsHide: true, windowsVerbatimArguments: true });
  const s = (r.stdout || "").trim();
  return s && s.toLowerCase() !== p.toLowerCase() ? s : null;
}

describe.skipIf(!win)("F1 regression (round 2): `~<digit>` names are judged by filesystem semantics", () => {
  it("accepts legitimate canonical names containing ~ and digits", async () => {
    expect(readGrantProblem("C:\\Tools\\Codex~2026.10")).toBeNull();
    expect(readGrantProblem("C:\\Tools\\Codex~1")).toBeNull();
    const base = await tempDir("arl-tilde-");
    for (const name of ["Codex~2026.10", "Codex~1"]) {
      await mkdir(join(base, name, "bin"), { recursive: true });
      const dir = await resolveInstallDir(join(base, name, "bin", "codex.exe"));
      expect(dir.endsWith(`\\${name}`), dir).toBe(true);
      await expect(assertCanonicalGrant(dir)).resolves.toBeUndefined();
    }
    await rm(base, { recursive: true, force: true }).catch(() => undefined);
  });

  it("a genuine 8.3 alias is expanded to its long name; the alias itself is not a canonical grant", async (ctx) => {
    const base = await tempDir("arl-short-");
    const long = join(base, "Codex Install Directory Long Name");
    await mkdir(join(long, "bin"), { recursive: true });
    const short = shortNameOf(long);
    if (!short) {
      ctx.skip(); // 8.3 names are disabled on this volume
      return;
    }
    expect(short).toMatch(/~\d/);
    const dir = await resolveInstallDir(join(short, "bin", "codex.exe"));
    expect(dir).toBe(await realpath(long));
    expect(dir.endsWith("Codex Install Directory Long Name")).toBe(true);
    await expect(assertCanonicalGrant(short)).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    await rm(base, { recursive: true, force: true }).catch(() => undefined);
  });

  it("drive-root aliases and a junction to the drive root stay refused; a normal install dir is accepted", async () => {
    const base = await tempDir("arl-roots-");
    const drive = parse(base).root;
    await expect(resolveInstallDir(`${drive}Windows\\..\\bin\\codex.exe`)).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    await expect(resolveInstallDir(`\\\\?\\${drive}x\\bin\\codex.exe`)).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    const j = join(base, "rootlink");
    expect(mklinkJunction(j, drive)).toBe(true);
    await expect(resolveInstallDir(join(j, "bin", "codex.exe"))).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    await expect(assertCanonicalGrant(j)).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    await mkdir(join(base, "Programs", "OpenAI", "Codex", "bin"), { recursive: true });
    const ok = await resolveInstallDir(join(base, "Programs", "OpenAI", "Codex", "bin", "codex.exe"));
    expect(ok.endsWith("\\Programs\\OpenAI\\Codex")).toBe(true);
    await expect(resolveInstallDir(join(base, "missing", "bin", "codex.exe"))).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    await rm(base, { recursive: true, force: true }).catch(() => undefined);
  });
});
