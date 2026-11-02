// Descendant discovery under PID reuse (process/proc-table.ts; plan §14.3, M1.3-6; M1.6 fix).
// Pure: scripted process tables, every platform.

import { describe, it, expect } from "vitest";
import { findDescendants, reaperCandidates, sweepDescendants, unattributableSince, type ProcEntry } from "../src/process/proc-table.js";
import { isPipeEndpoint } from "../src/process/linux-proc.js";
import { killTreePosix } from "../src/process/kill-tree.js";

const T0 = 1_700_000_000_000;
const e = (pid: number, ppid: number, createdMs: number, name = `p${pid}`): ProcEntry => ({ pid, ppid, createdMs, name });

describe("findDescendants", () => {
  it("finds the live tree of a live root", () => {
    const table = [e(100, 1, T0), e(101, 100, T0 + 10), e(102, 101, T0 + 20), e(200, 1, T0 - 5000)];
    expect(findDescendants(table, { pid: 100, startedAtMs: T0 }).map((x) => x.pid).sort()).toEqual([101, 102]);
  });

  it("keeps orphans of an exited root (they cannot be told apart, so they count as ours)", () => {
    const table = [e(101, 100, T0 + 10), e(102, 101, T0 + 20)];
    expect(findDescendants(table, { pid: 100, startedAtMs: T0 }).map((x) => x.pid).sort()).toEqual([101, 102]);
  });

  it("excludes a process created before the root (its parent PID was an earlier process)", () => {
    const table = [e(101, 100, T0 - 60_000)];
    expect(findDescendants(table, { pid: 100, startedAtMs: T0 })).toEqual([]);
  });

  it("excludes the children of a newer process that now holds the root's PID, but keeps the root's own orphans", () => {
    const table = [
      e(101, 100, T0 + 10, "our-orphan"), // created by the root before it exited
      e(103, 101, T0 + 15, "our-grandchild"),
      e(100, 1, T0 + 30_000, "impostor"), // PID 100 reassigned 30 s later
      e(150, 100, T0 + 30_500, "impostor-child"),
      e(151, 150, T0 + 30_600, "impostor-grandchild"),
    ];
    const found = findDescendants(table, { pid: 100, startedAtMs: T0 });
    expect(found.map((x) => x.name).sort()).toEqual(["our-grandchild", "our-orphan"]);
  });

  it("a root that is alive under its own start time is not an impostor (clock tolerance)", () => {
    const table = [e(100, 1, T0 + 1500), e(101, 100, T0 + 1600)];
    expect(findDescendants(table, { pid: 100, startedAtMs: T0 }).map((x) => x.pid)).toEqual([101]);
  });
});

describe("sweepDescendants never kills a process that merely inherited the exited child's PID", () => {
  it("kills the root's orphan, not the impostor's child", async () => {
    const table = [e(101, 100, T0 + 10, "our-orphan"), e(100, 1, T0 + 30_000, "impostor"), e(150, 100, T0 + 30_500, "impostor-child")];
    const killed: number[] = [];
    let snapshots = 0;
    const r = await sweepDescendants(
      { pid: 100, startedAtMs: T0 },
      {
        snapshot: async () => (snapshots++ === 0 ? table : table.filter((x) => !killed.includes(x.pid))),
        kill: async (pid) => {
          killed.push(pid);
          return true;
        },
      },
    );
    expect(killed).toEqual([101]);
    expect(r.survivors.map((s) => s.pid)).toEqual([101]);
    expect(r.terminated).toBe(true);
  });
});

describe("sweepDescendants re-reads the table while a killed process is still in teardown (M1.6-14)", () => {
  const table = [e(100, 1, T0, "root"), e(101, 100, T0 + 10, "orphan")];
  const sweepWith = async (listedFor: number) => {
    let reads = 0;
    const r = await sweepDescendants(
      { pid: 100, startedAtMs: T0 },
      {
        // Read 1 finds the orphan; it stays listed for `listedFor` reads after the kill.
        snapshot: async () => (reads++ <= listedFor ? table.filter((x) => x.pid === 101) : []),
        kill: async () => true,
        rescanDelaysMs: [0, 0, 0],
      },
    );
    return { r, reads };
  };

  it("a process still listed right after the kill but gone on a re-read is confirmed terminated", async () => {
    const { r, reads } = await sweepWith(1);
    expect(r.terminated).toBe(true);
    expect(reads).toBe(3); // the scan, the first read after the kill, one re-read
  });

  it("a process still listed after the last re-read is reported, not assumed gone", async () => {
    const { r, reads } = await sweepWith(99);
    expect(r.terminated).toBe(false);
    expect(r.survivors.map((s) => s.pid)).toEqual([101]);
    expect(reads).toBe(5); // bounded: the scan, the read after the kill, three re-reads
  });
});

// Linux rules (tree.ts; plan §1.13), pure: a table with session data uses session/group membership.
const lx = (pid: number, ppid: number, createdMs: number, sid: number, pgid = sid, uid = 1000): ProcEntry => ({
  pid,
  ppid,
  createdMs,
  name: `p${pid}`,
  sid,
  pgid,
  uid,
  startTicks: createdMs - T0 + 1_000,
});

describe("findDescendants: Linux session and group membership", () => {
  it("links re-parented members of the root's session or group, but not older members or another session", () => {
    const table = [
      lx(100, 50, T0, 100),
      lx(101, 1, T0 + 10, 100), // re-parented to init, still in the root's session
      lx(102, 50, T0 + 20, 77, 100), // other session, the root's process group
      lx(103, 1, T0 + 30, 103), // left the session (setsid) and lost its parent
      lx(104, 1, T0 - 60_000, 100), // an older process in a session with the root's (reused) id
    ];
    expect(findDescendants(table, { pid: 100, startedAtMs: T0 }).map((x) => x.pid).sort()).toEqual([101, 102]);
  });

  it("does not take members created after a newer process took the root's PID", () => {
    const table = [lx(100, 1, T0 + 30_000, 100), lx(101, 1, T0 + 10, 100), lx(150, 1, T0 + 30_500, 100)];
    expect(findDescendants(table, { pid: 100, startedAtMs: T0 }).map((x) => x.pid)).toEqual([101]);
  });

  it("links a process holding the root's output pipes, its children and its own session (exact by start ticks)", () => {
    const holder = lx(103, 1, T0 + 30, 103);
    const table = [holder, lx(104, 103, T0 + 40, 103), lx(105, 1, T0 + 50, 103), lx(106, 1, T0 + 60, 106)];
    const root = { pid: 100, startedAtMs: T0 };
    expect(findDescendants(table, root)).toEqual([]);
    expect(findDescendants(table, { ...root, holders: [{ pid: 103, startTicks: holder.startTicks! }] }).map((x) => x.pid).sort()).toEqual([103, 104, 105]);
    // A holder record whose start ticks do not match is a different process: never linked.
    expect(findDescendants(table, { ...root, holders: [{ pid: 103, startTicks: 1 }] })).toEqual([]);
  });
});

describe("unattributableSince: Linux reapers", () => {
  // init(1) -> shell(40) -> server(50); a re-parented orphan's parent is init or an ancestor of the server.
  const base = [lx(1, 0, T0 - 600_000, 1), lx(40, 1, T0 - 500_000, 40), lx(50, 40, T0 - 400_000, 40)];
  it("reports a same-user process created since the run whose parent is a possible reaper", () => {
    const table = [...base, lx(103, 1, T0 + 30, 103), lx(104, 40, T0 + 40, 104), lx(105, 1, T0 + 50, 105, 105, 0), lx(106, 103, T0 + 60, 103), lx(107, 1, T0 - 60_000, 107)];
    expect(reaperCandidates(table, 50)).toEqual(new Set([1, 40]));
    // 105 runs as another user; 106's parent is a live non-reaper; 107 predates the run.
    expect(unattributableSince(table, T0, 2000, 50).map((x) => x.pid).sort()).toEqual([103, 104]);
  });
});

describe("sweepDescendants: Linux output-pipe holders", () => {
  it("finds and kills a holder of the exited child's output pipes that no session or parent links", async () => {
    const holder = { ...lx(103, 1, T0 + 30, 103), pid: 103 };
    const table = [lx(50, 1, T0 - 400_000, 50), holder, lx(108, 1, T0 + 80, 108)];
    const killed: number[] = [];
    const asked: { targets: string[]; candidates: number[] }[] = [];
    const deps = {
      snapshot: async () => table.filter((x) => !killed.includes(x.pid)),
      kill: async (pid: number) => {
        killed.push(pid);
        return true;
      },
      holders: async (targets: ReadonlySet<string>, candidates: readonly number[]) => {
        asked.push({ targets: [...targets], candidates: [...candidates] });
        return candidates.filter((p) => p === 103);
      },
      rescanDelaysMs: [0],
    };
    // Without endpoints nothing is linked (and nothing is asked).
    expect((await sweepDescendants({ pid: 100, startedAtMs: T0 }, deps)).survivors).toEqual([]);
    expect(asked).toEqual([]);
    const r = await sweepDescendants({ pid: 100, startedAtMs: T0 }, deps, ["socket:[123]"]);
    expect(asked[0]!.targets).toEqual(["socket:[123]"]);
    expect(asked[0]!.candidates).not.toContain(50); // created before the run
    expect(killed).toEqual([103]);
    expect(r.survivors.map((s) => s.pid)).toEqual([103]);
    expect(r.terminated).toBe(true);
  });
});

describe("isPipeEndpoint", () => {
  it("accepts anonymous pipe and socket inodes only", () => {
    for (const t of ["pipe:[10587]", "socket:[10603]"]) expect(isPipeEndpoint(t)).toBe(true);
    for (const t of ["/dev/null", "anon_inode:[eventfd]", "socket:[]", "pipe:[12a]", "/tmp/socket:[1]", "socket:[1] "]) expect(isPipeEndpoint(t)).toBe(false);
  });
});

// killTreePosix with a scripted process table (pure; every platform). Dogfood review of the
// Linux milestone: the root is matched by its exact identity, and the group only while the root
// itself still leads it.
describe("killTreePosix: exact identity", () => {
  // root 100 (session and group 100) with a child 101 in its group; ticks are identities.
  const row = (pid: number, ppid: number, ticks: number, pgid = 100, sid = 100): ProcEntry => ({ pid, ppid, createdMs: T0 + ticks, name: `p${pid}`, pgid, sid, uid: 1000, startTicks: ticks });
  const run = async (tables: (ProcEntry[] | null)[], opts: { startTicks?: number; startedAtMs?: number }, same: (e: ProcEntry) => boolean = () => true) => {
    const sent: string[] = [];
    let i = 0;
    const ok = await killTreePosix(100, {
      timeoutMs: 2000,
      graceMs: 0,
      ...opts,
      deps: {
        table: async () => tables[Math.min(i++, tables.length - 1)] ?? null,
        signal: (pid, sig) => void sent.push(`${pid}:${sig}`),
        stillSame: same,
      },
    });
    return { ok, sent };
  };

  it("never signals a process that merely holds the root's PID now, even within the creation-time tolerance", async () => {
    const impostor = { ...row(100, 1, 500), createdMs: T0 + 10 }; // other ticks, created 10 ms "after" the root
    const { ok, sent } = await run([[impostor]], { startTicks: 5, startedAtMs: T0 });
    expect(sent).toEqual([]);
    expect(ok).toBe(true); // the root is gone: nothing of its tree is left
  });

  it("without any identity of the root nothing is signalled and nothing is claimed", async () => {
    const { ok, sent } = await run([[row(100, 1, 5), row(101, 100, 6)]], {});
    expect(sent).toEqual([]);
    expect(ok).toBe(false);
  });

  it("signals the group only while the root itself leads it; after the root is gone, members one by one", async () => {
    const live = await run([[row(100, 1, 5), row(101, 100, 6)], []], { startTicks: 5, startedAtMs: T0 + 5 });
    expect(live.sent).toEqual(["-100:SIGTERM", "100:SIGTERM", "101:SIGTERM"]);
    expect(live.ok).toBe(true);
    // The root exited; its child is still in the group (an orphan, re-parented to init).
    const orphan = await run([[row(101, 1, 6)], []], { startTicks: 5, startedAtMs: T0 + 5 });
    expect(orphan.sent).toEqual(["101:SIGTERM"]);
  });

  it("re-checks every member's identity right before each signal", async () => {
    // 101's PID now belongs to another process (stillSame false): it is not signalled; the group
    // is not signalled either once the root itself fails the re-check.
    const { sent } = await run([[row(100, 1, 5), row(101, 100, 6)], []], { startTicks: 5, startedAtMs: T0 + 5 }, (e) => e.pid !== 101);
    expect(sent).toEqual(["-100:SIGTERM", "100:SIGTERM"]);
    const rootChanged = await run([[row(100, 1, 5), row(101, 100, 6)], []], { startTicks: 5, startedAtMs: T0 + 5 }, (e) => e.pid !== 100);
    expect(rootChanged.sent).toEqual(["101:SIGTERM"]);
  });
});
