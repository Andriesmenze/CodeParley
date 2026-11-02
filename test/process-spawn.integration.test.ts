// runProcess (process/spawn.ts) as a SHARED CONTRACT: the same behaviour on every supported
// platform — argv without a shell, an explicit environment, line callbacks, bounds, abort,
// byte-exact output — exercised through node so the assertions do not depend on a shell.

import { describe, it, expect } from "vitest";
import { runProcess } from "../src/process/spawn.js";
import { buildChildEnv } from "../src/process/env.js";
import { supported, win } from "./helpers/git-fixture.js";

const NODE = process.execPath;
const print = (expr: string) => ["-e", `process.stdout.write(String(${expr}))`];

describe.skipIf(!supported)("runProcess", () => {
  it("runs a command and captures stdout with exit 0", async () => {
    const r = await runProcess(NODE, print("'hello-world'"), { env: buildChildEnv().env });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe("hello-world");
    expect(r.spawnError).toBeNull();
  });

  it("passes argv verbatim: no shell interprets metacharacters", async () => {
    const hostile = ["a b", "$(id)", "`id`", "; rm -rf x", "&& echo pwned", "'q'", '"dq"', "%PATH%", "*", "~"];
    const r = await runProcess(NODE, ["-e", "process.stdout.write(JSON.stringify(process.argv.slice(1)))", ...hostile], { env: buildChildEnv().env });
    expect(JSON.parse(r.stdout)).toEqual(hostile);
  });

  it("uses an explicit environment: an unlisted secret is NOT present in the child", async () => {
    const r = await runProcess(NODE, print("process.env.CODEPARLEY_TEST_SECRET"), {
      env: buildChildEnv({ source: { ...process.env, CODEPARLEY_TEST_SECRET: "leak" } }).env,
    });
    expect(r.stdout).toBe("undefined");
  });

  it("passes through caller extras", async () => {
    const r = await runProcess(NODE, print("process.env.CODEPARLEY_OK"), { env: buildChildEnv({ extra: { CODEPARLEY_OK: "present" } }).env });
    expect(r.stdout).toBe("present");
  });

  it("delivers stdout line callbacks", async () => {
    const lines: string[] = [];
    await runProcess(NODE, ["-e", "process.stdout.write('a\\nb\\r\\nc')"], { env: buildChildEnv().env, onStdoutLine: (l) => lines.push(l) });
    expect(lines).toEqual(["a", "b", "c"]);
  });

  it("enforces a wall-clock timeout and kills the tree", async () => {
    const started = Date.now();
    const r = await runProcess(NODE, ["-e", "setTimeout(() => {}, 30000)"], { env: buildChildEnv().env, wallMs: 1500 });
    expect(r.timedOut).toBe(true);
    expect(Date.now() - started).toBeLessThan(15_000);
  });

  it("cancels via AbortSignal and terminates the process", async () => {
    const ac = new AbortController();
    const p = runProcess(NODE, ["-e", "setTimeout(() => {}, 30000)"], { env: buildChildEnv().env, signal: ac.signal });
    setTimeout(() => ac.abort(), 400);
    const r = await p;
    expect(r.cancelled).toBe(true);
  });

  it("keeps multi-byte UTF-8 intact across chunk boundaries and supports raw binary stdout/stdin", async () => {
    // 200k copies of a 3-byte character: chunk boundaries fall inside characters.
    const script = "process.stdout.write('\\u6587'.repeat(200000))";
    const r = await runProcess(NODE, ["-e", script], { env: buildChildEnv().env });
    expect(r.stdout.length).toBe(200000);
    expect(r.stdout.includes("�")).toBe(false);

    const echo = "process.stdin.on('data', (b) => process.stdout.write(b))";
    const input = Buffer.from([0, 255, 10, 13, 0xe6, 0x96]);
    const b = await runProcess(NODE, ["-e", echo], { env: buildChildEnv().env, stdin: input, stdoutMode: "buffer" });
    expect(b.stdout).toBe("");
    expect(b.stdoutBuffer).toEqual(input);

    // A non-finite cap falls back to the default rather than discarding output.
    const c = await runProcess(NODE, ["-e", "process.stdout.write('ok')"], { env: buildChildEnv().env, maxStdoutBytes: Number.NaN });
    expect(c.stdout).toBe("ok");
  });

  it("caps output and reports truncation", async () => {
    const r = await runProcess(NODE, ["-e", "process.stdout.write('x'.repeat(100000))"], { env: buildChildEnv().env, maxStdoutBytes: 1000 });
    expect(r.stdout.length).toBe(1000);
    expect(r.stdoutTruncated).toBe(true);
    expect(r.stdoutBytes).toBe(100000);
  });

  it("reports a spawn error for a missing executable rather than throwing", async () => {
    const r = await runProcess(win ? "C:\\no\\such\\thing.exe" : "/no/such/thing", [], { env: buildChildEnv().env, wallMs: 5000 });
    expect(r.spawnError).not.toBeNull();
    expect(r.status).toBeNull();
  });
});
