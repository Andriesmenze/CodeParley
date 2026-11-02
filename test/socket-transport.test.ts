// Phase 5 (contract §4.4): the Linux custodian transport trusts an endpoint only by where it is — a root-owned runtime
// directory nobody else can write in, and a socket owned by the custodian's account. The rule is pure; the exchange is
// exercised against a real Unix socket server where the platform has them (Linux, macOS).

import { describe, it, expect } from "vitest";
import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { localAccountUid, socketEndpointProblem, UnixSocketCustodianTransport } from "../src/custodian/socket-transport.js";
import { CustodianBusy, CustodianNotTrusted, CustodianUnavailable, setCustodianClientDeadline } from "../src/custodian/transport.js";

const dir = (o: Partial<{ isDirectory: boolean; uid: number; mode: number }> = {}) => ({ isDirectory: true, uid: 0, mode: 0o40755, ...o });
const sock = (o: Partial<{ isSocket: boolean; uid: number; mode: number }> = {}) => ({ isSocket: true, uid: 990, mode: 0o140660, ...o });
const expectUids = { dirUid: 0, sockUid: 990 };

describe("Phase 5: the Unix socket endpoint rule (contract §4.4)", () => {
  it("trusts a root-owned, not group/other-writable runtime directory holding a socket owned by the custodian", () => {
    expect(socketEndpointProblem(dir(), sock(), expectUids)).toBeNull();
  });

  it("an absent directory or socket is 'not present' (unavailable); anything else present but wrong is not trusted", () => {
    expect(socketEndpointProblem(null, sock(), expectUids)).toMatchObject({ present: false });
    expect(socketEndpointProblem(dir(), null, expectUids)).toMatchObject({ present: false });
    for (const [d, s] of [
      [dir({ isDirectory: false }), sock()],
      [dir({ uid: 1000 }), sock()],
      [dir({ mode: 0o40775 }), sock()],
      [dir({ mode: 0o40757 }), sock()],
      [dir(), sock({ isSocket: false })],
      [dir(), sock({ uid: 1000 })],
      [dir(), sock({ uid: 0 })],
      [dir(), sock({ mode: 0o140662 })],
    ] as const) expect(socketEndpointProblem(d, s, expectUids), JSON.stringify([d, s])).toMatchObject({ present: true });
  });

  it("reads an account's uid from a passwd file; absent or malformed is null", async () => {
    const d = mkdtempSync(join(tmpdir(), "cp-passwd-"));
    try {
      const f = join(d, "passwd");
      writeFileSync(f, "root:x:0:0:root:/root:/bin/bash\ncodeparley:x:991:991::/nonexistent:/usr/sbin/nologin\nbad:x:zz:1::/:/bin/false\n");
      expect(await localAccountUid("codeparley", f)).toBe(991);
      expect(await localAccountUid("root", f)).toBe(0);
      expect(await localAccountUid("bad", f)).toBeNull();
      expect(await localAccountUid("nobody-here", f)).toBeNull();
      expect(await localAccountUid("codeparley", join(d, "missing"))).toBeNull();
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});

describe.runIf(process.platform !== "win32")("Phase 5: the Unix socket exchange (one line each way)", () => {
  const setup = async (reply: ((line: string) => string | null | Promise<string | null>) | "close") => {
    const d = mkdtempSync(join(tmpdir(), "cp-sock-"));
    chmodSync(d, 0o755);
    const path = join(d, "implementer.sock");
    const server = createServer((c) => {
      let buf = "";
      c.on("data", (b) => {
        buf += b.toString("utf8");
        const nl = buf.indexOf("\n");
        if (nl < 0) return;
        if (reply === "close") return void c.destroy();
        void Promise.resolve(reply(buf.slice(0, nl))).then((out) => {
          if (out !== null) c.end(out + "\n");
        });
      });
    });
    await new Promise<void>((r) => server.listen(path, r));
    const uid = statSync(path).uid;
    const t = new UnixSocketCustodianTransport({ sockets: { implementer: path, operator: path }, runtimeDir: d, expectedUid: uid, runtimeDirUid: statSync(d).uid, connectMs: 2000, responseMs: 500 });
    return { t, done: () => new Promise<void>((r) => server.close(() => { rmSync(d, { recursive: true, force: true }); r(); })) };
  };

  it("sends one request line and parses the one response line", async () => {
    let seen: Record<string, unknown> | null = null;
    const { t, done } = await setup((line) => {
      seen = JSON.parse(line) as Record<string, unknown>;
      return JSON.stringify({ ok: true, data: { pong: 1 } });
    });
    try {
      const r = await t.send("implementer", "list_grants", {}, "req-1");
      expect(seen).toMatchObject({ requestId: "req-1", op: "list_grants" });
      expect(r).toMatchObject({ ok: true, data: { pong: 1 } });
    } finally {
      await done();
    }
  });

  it("a connection closed after the request is 'unknown'; no answer in time is 'unknown'", async () => {
    const closed = await setup("close");
    try {
      await expect(closed.t.send("implementer", "list_grants", {}, "r")).rejects.toMatchObject({ outcome: "unknown" });
    } finally {
      await closed.done();
    }
    const silent = await setup(() => null);
    setCustodianClientDeadline(Date.now() + 1500); // a hook with 1.5 s left
    try {
      const e = await silent.t.send("implementer", "list_grants", {}, "r").catch((x: unknown) => x);
      expect(e).toBeInstanceOf(CustodianUnavailable);
      expect(e).not.toBeInstanceOf(CustodianBusy);
      expect(e).toMatchObject({ outcome: "unknown" });
    } finally {
      setCustodianClientDeadline(null);
      await silent.done();
    }
  });

  it("Phase 6 §7 a: a queued request's answer is waited for within the hook's budget, past the usual response deadline", async () => {
    const slow = await setup(async () => {
      await new Promise((r) => setTimeout(r, 1500)); // three times the 500 ms response deadline
      return JSON.stringify({ ok: true, data: { queued: true } });
    });
    setCustodianClientDeadline(Date.now() + 10_000);
    try {
      expect(await slow.t.send("implementer", "list_grants", {}, "r")).toMatchObject({ ok: true, data: { queued: true } });
    } finally {
      setCustodianClientDeadline(null);
      await slow.done();
    }
  });

  it("Phase 6 §7 a: an absent socket fails at once, nothing delivered (it is not waited for as a busy one is)", async () => {
    const gone = await setup(() => "{}");
    const t0 = Date.now();
    await gone.done(); // the socket file is removed with its directory
    const e = await gone.t.send("implementer", "list_grants", {}, "r").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(CustodianUnavailable);
    expect(e).not.toBeInstanceOf(CustodianBusy);
    expect(e).toMatchObject({ outcome: "not_delivered" });
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("a socket owned by another account is refused before anything is sent", async () => {
    let got = 0;
    const { t, done } = await setup(() => {
      got++;
      return "{}";
    });
    try {
      const wrong = new UnixSocketCustodianTransport({
        sockets: (t as unknown as { sockets: { implementer: string; operator: string } }).sockets,
        runtimeDir: (t as unknown as { runtimeDir: string }).runtimeDir,
        runtimeDirUid: (t as unknown as { runtimeDirUid: number }).runtimeDirUid,
        expectedUid: 123456,
      });
      const e = await wrong.send("implementer", "list_grants", {}, "r").catch((x: unknown) => x);
      expect(e).toBeInstanceOf(CustodianNotTrusted);
      expect(e).toMatchObject({ outcome: "not_delivered" });
      expect(got).toBe(0);
    } finally {
      await done();
    }
  });
});
