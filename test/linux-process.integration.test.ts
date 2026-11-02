// The Linux process layer (plan §1.13), validated on a real Linux kernel: every child leads its
// own session and process group; a tree kill reaches the session, the group and linked
// descendants (SIGTERM, then SIGKILL for whatever ignores it); a descendant that left the
// session and lost its parent cannot be linked, so termination is NOT established while it
// lives; the session reaper ends a server's sessions when the server is SIGKILLed; process
// identity is exact (boot id + start ticks) and a zombie is not alive.

import { describe, it, expect, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { runProcess } from "../src/process/spawn.js";
import { killTree } from "../src/process/kill-tree.js";
import { readStatSync } from "../src/process/linux-proc.js";
import { confirmTreeTermination, findDescendants, NO_KILL, snapshotProcessTable, sweepDescendants } from "../src/process/proc-table.js";
import { classifyOwnerLiveness, identityOf, OWNER_LIVENESS_DEPS, pidAlive, startFactsOf } from "../src/store/owner.js";
import { linux } from "./helpers/git-fixture.js";
import { sharedCompiledSrc } from "./helpers/compiled-src.js";

const NODE = process.execPath;
const alive = (pid: number) => pidAlive(pid);
async function waitFor(f: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await f()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return f();
}

const dirs: string[] = [];
async function scratch(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "arl-linux-proc-"));
  dirs.push(d);
  return d;
}
afterAll(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => undefined);
});

/** A node script that starts a long-lived child (optionally in a new session) and records its pid. */
const SPAWN_CHILD = (pidFile: string, detached: boolean, exitAfter: boolean) =>
  `const {spawn}=require('child_process');const g=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:${detached},stdio:'ignore'});` +
  `require('fs').writeFileSync(${JSON.stringify(pidFile)},String(g.pid));${exitAfter ? "process.exit(0);" : "setInterval(()=>{},1000);"}`;

describe.skipIf(!linux)("Linux process layer", () => {
  it("every child leads a new session and process group (setsid)", async () => {
    let pid = 0;
    const p = runProcess(NODE, ["-e", "setTimeout(()=>{}, 3000)"], { wallMs: 10_000, onSpawn: (x) => (pid = x) });
    expect(await waitFor(() => pid > 0, 5000)).toBe(true);
    const st = readStatSync(pid)!;
    expect(st.session).toBe(pid);
    expect(st.pgrp).toBe(pid);
    expect(readStatSync(process.pid)!.session).not.toBe(pid);
    await p;
  });

  it("a tree kill ends the root, a child in its session and a grandchild in a NEW session still linked by its parent", async () => {
    const d = await scratch();
    const sameSession = join(d, "same.pid");
    const newSession = join(d, "new.pid");
    // root -> (same session) a -> (setsid) b, with a alive: b is linked through a.
    const script = `const {spawn}=require('child_process');spawn(process.execPath,['-e',${JSON.stringify(SPAWN_CHILD(newSession, true, false))}],{stdio:'ignore'}).on('spawn',function(){require('fs').writeFileSync(${JSON.stringify(sameSession)},String(this.pid))});setInterval(()=>{},1000);`;
    let root = 0;
    const run = runProcess(NODE, ["-e", script], { wallMs: 60_000, onSpawn: (x) => (root = x) });
    expect(await waitFor(() => existsSync(newSession) && existsSync(sameSession), 10_000)).toBe(true);
    const a = Number(readFileSync(sameSession, "utf8"));
    const b = Number(readFileSync(newSession, "utf8"));
    expect(readStatSync(b)!.session).not.toBe(root); // b left the session
    expect(await killTree(root)).toBe(false); // no identity of the root: nothing is signalled
    expect(alive(root) && alive(a) && alive(b)).toBe(true);
    expect(await killTree(root, 10_000, { startTicks: readStatSync(root)!.startTicks })).toBe(true);
    expect(alive(root) || alive(a) || alive(b)).toBe(false);
    await run;
  });

  it("whatever ignores SIGTERM is killed after the grace period, and the kill is confirmed", async () => {
    let root = 0;
    const run = runProcess(NODE, ["-e", "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"], { wallMs: 60_000, onSpawn: (x) => (root = x) });
    expect(await waitFor(() => root > 0 && readStatSync(root) !== null, 5000)).toBe(true);
    await new Promise((r) => setTimeout(r, 300)); // let it install the handler
    const started = Date.now();
    expect(await killTree(root, 10_000, { startTicks: readStatSync(root)!.startTicks })).toBe(true);
    expect(Date.now() - started).toBeGreaterThanOrEqual(1500);
    expect(alive(root)).toBe(false);
    await run;
  });

  it("a descendant that left the session and lost its parent cannot be linked: termination is NOT established while it lives", async () => {
    const d = await scratch();
    const orphanFile = join(d, "orphan.pid");
    let root = 0;
    const startedAtMs = Date.now();
    // The root starts an intermediate that starts a NEW-session grandchild and exits at once.
    const r = await runProcess(NODE, ["-e", `require('child_process').spawnSync(process.execPath,['-e',${JSON.stringify(SPAWN_CHILD(orphanFile, true, true))}]);`], { wallMs: 30_000, onSpawn: (x) => (root = x) });
    expect(r.status).toBe(0);
    const orphan = Number(readFileSync(orphanFile, "utf8"));
    try {
      expect(alive(orphan)).toBe(true);
      const table = (await snapshotProcessTable())!;
      expect(findDescendants(table, { pid: root, startedAtMs }).some((e) => e.pid === orphan)).toBe(false); // not linkable
      const sweep = await sweepDescendants({ pid: root, startedAtMs });
      const check = confirmTreeTermination({ pid: root, startedAtMs }, NO_KILL, await snapshotProcessTable(), sweep);
      expect(check.established).toBe(false);
      expect(check.unattributable.map((u) => u.pid)).toContain(orphan);
      expect(alive(orphan)).toBe(true); // reported, never killed
    } finally {
      process.kill(orphan, "SIGKILL");
    }
  });

  it("the session reaper ends a server's sessions when the server is SIGKILLed", async () => {
    const dist = sharedCompiledSrc(); // the shared build of src/ (test/global-setup.ts)
    expect(dist).not.toBeNull();
    if (!dist) return;
    const d = await scratch();
    const childFile = join(d, "child.pid");
    const spawnUrl = pathToFileURL(join(dist, "process", "spawn.js")).href;
    // A stand-in server: starts a long-lived child through the product's spawn primitive.
    const script =
      `const fs = await import("node:fs"); const { runProcess } = await import(${JSON.stringify(spawnUrl)});` +
      `runProcess(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { wallMs: 300000, onSpawn: (p) => fs.writeFileSync(${JSON.stringify(childFile)}, String(p)) });` +
      `setInterval(() => {}, 1000);`;
    const server = spawn(NODE, ["--input-type=module", "-e", script], { stdio: "ignore" });
    expect(await waitFor(() => existsSync(childFile), 15_000)).toBe(true);
    const child = Number(readFileSync(childFile, "utf8"));
    expect(alive(child)).toBe(true);
    server.kill("SIGKILL");
    expect(await waitFor(() => !alive(child), 15_000)).toBe(true);
  });

  // Dogfood review of the Linux milestone: a caller that sweeps after the run (checks, Codex)
  // holds the session until its sweep is done, so a server dying in between still has it ended.
  it("a held session is still ended when the server dies after the run but before its sweep; a released one is not", async () => {
    const dist = sharedCompiledSrc();
    expect(dist).not.toBeNull();
    if (!dist) return;
    const spawnUrl = pathToFileURL(join(dist, "process", "spawn.js")).href;
    const scenario = async (hold: boolean) => {
      const d = await scratch();
      const gcFile = join(d, "gc.pid");
      const readyFile = join(d, "ready");
      // The root starts a grandchild IN ITS SESSION (not detached, stdio ignored) and exits.
      const root = `const g=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});g.unref();require('fs').writeFileSync(${JSON.stringify(gcFile)},String(g.pid));`;
      const server =
        `const fs = await import("node:fs"); const { runProcess } = await import(${JSON.stringify(spawnUrl)});` +
        `await runProcess(process.execPath, ["-e", ${JSON.stringify(root)}], { wallMs: 60000, holdSession: ${hold} });` +
        `fs.writeFileSync(${JSON.stringify(readyFile)}, "ran"); setInterval(() => {}, 1000);`; // "the sweep has not run yet"
      const proc = spawn(NODE, ["--input-type=module", "-e", server], { stdio: "ignore" });
      expect(await waitFor(() => existsSync(readyFile) && existsSync(gcFile), 15_000)).toBe(true);
      const gc = Number(readFileSync(gcFile, "utf8"));
      expect(alive(gc)).toBe(true);
      proc.kill("SIGKILL");
      return gc;
    };
    const held = await scenario(true);
    expect(await waitFor(() => !alive(held), 15_000)).toBe(true);
    const released = await scenario(false);
    try {
      await new Promise((r) => setTimeout(r, 3000)); // give the reaper the time it had above
      expect(alive(released)).toBe(true); // released before the (never run) sweep: the reaper no longer knew it
    } finally {
      if (alive(released)) process.kill(released, "SIGKILL");
    }
  });

  it("process identity is exact (boot id + start ticks); a reused PID or a zombie is not the recorded owner", async () => {
    const facts = startFactsOf(process.pid, 0);
    expect(facts.startIdentity).toMatch(/^[0-9a-f-]{36}:\d+$/);
    expect(identityOf(process.pid)).toBe(facts.startIdentity);
    const me = { serverInstanceId: "s", pid: process.pid, startedAtMs: facts.startedAtMs, startIdentity: facts.startIdentity! };
    expect(await classifyOwnerLiveness(me, OWNER_LIVENESS_DEPS)).toBe("alive");
    // Same PID, different start: a reused PID — even with a matching wall-clock time.
    expect(await classifyOwnerLiveness({ ...me, startIdentity: `${facts.startIdentity!.split(":")[0]}:1` }, OWNER_LIVENESS_DEPS)).toBe("dead");
    // A zombie: `sh` execs `sleep`, which never waits for the child the shell had started.
    const parent = spawn("/bin/sh", ["-c", "sleep 0.2 & echo $!; exec sleep 5"], { stdio: ["ignore", "pipe", "ignore"] });
    const zpid = await new Promise<number>((res) => parent.stdout.once("data", (b: Buffer) => res(Number(b.toString().trim()))));
    try {
      expect(await waitFor(() => readStatSync(zpid)?.state === "Z", 5000)).toBe(true);
      expect(pidAlive(zpid)).toBe(false); // terminated, although kill(pid, 0) would still succeed
    } finally {
      parent.kill("SIGKILL");
    }
  });
});
