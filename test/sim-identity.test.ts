// Phase 5 (contract §4.6, F5-13): the simulated custodian's POSIX repository identity is (dev, ino, generation,
// birthtimeNs), so a directory replaced at the same path is another identity whether the replacement is immediate (the
// inode number reused: the generation differs on ext4) or later (the birth time differs). Windows keeps sim1.

import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { filesystemIdentity } from "../src/custodian/transport.js";

const pause = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe.runIf(process.platform !== "win32")("Phase 5: the simulator's POSIX identity (F5-13)", () => {
  it("is sim2 with dev, ino, generation and birth time; the same directory by any spelling is one identity", () => {
    const d = mkdtempSync(join(tmpdir(), "cp-simid-"));
    try {
      const a = filesystemIdentity(d, () => 0x2an);
      expect(a.key).toMatch(/^sim2-[0-9a-f]+-[0-9a-f]+-2a-[0-9a-f]+$/);
      expect(filesystemIdentity(d + "/", () => 0x2an).key).toBe(a.key);
      expect(filesystemIdentity(d, () => null).key).toMatch(/^sim2-[0-9a-f]+-[0-9a-f]+-x-[0-9a-f]+$/);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("an immediate replacement with the same inode number is another identity through the generation", () => {
    const d = mkdtempSync(join(tmpdir(), "cp-simid-"));
    try {
      let gen = 1n;
      const before = filesystemIdentity(d, () => gen);
      gen = 2n; // what ext4 assigns a recreated inode (random per creation)
      expect(filesystemIdentity(d, () => gen).key).not.toBe(before.key);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("a replacement after a delay is refused on birth time alone (the generation forced equal)", async () => {
    const parent = mkdtempSync(join(tmpdir(), "cp-simid-"));
    try {
      const repo = join(parent, "repo");
      mkdirSync(repo);
      const btime0 = statSync(repo, { bigint: true }).birthtimeNs;
      const before = filesystemIdentity(repo, () => 7n);
      rmSync(repo, { recursive: true });
      await pause(25); // beyond the coarse-clock granularity of the birth time (1 ms on ext4)
      mkdirSync(repo);
      const after = filesystemIdentity(repo, () => 7n);
      if (btime0 === 0n) return; // a filesystem without birth time: the generation alone separates (asserted above)
      expect(after.key).not.toBe(before.key);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("the real generation, where readable, takes part: two directories differ", () => {
    const d = mkdtempSync(join(tmpdir(), "cp-simid-"));
    try {
      const a = join(d, "a");
      const b = join(d, "b");
      mkdirSync(a);
      mkdirSync(b);
      expect(filesystemIdentity(a).key).not.toBe(filesystemIdentity(b).key);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});
