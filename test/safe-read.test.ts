// Safe working-tree reads (capture/safe-read.ts): a same-size write in place while a file is
// being read is detected (PR #2 review). Size and file id stay the same; the write and change
// times do not.

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, open, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readWorkingFile } from "../src/capture/safe-read.js";
import { supported } from "./helpers/git-fixture.js";

describe.skipIf(!supported)("safe read: a same-size write in place during the read", () => {
  it("is detected; the read is repeated and returns the file as it now is, never stale or mixed bytes", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "cp-saferead-")));
    const p = join(root, "big.bin");
    const size = 3 * 1024 * 1024; // more than one 1 MiB read chunk
    await writeFile(p, Buffer.alloc(size, 0x61));
    let calls = 0;
    const r = await readWorkingFile(p, {
      root,
      objectFormat: "sha1",
      maxRetainBytes: 0,
      retain: false,
      linkCache: new Map(),
      afterFirstChunk: async () => {
        if (calls++ > 0) return; // change the file during the first attempt only
        const w = await open(p, "r+");
        await w.write(Buffer.alloc(1024, 0x62), 0, 1024, 0); // bytes the reader has already consumed
        await w.close();
      },
    });
    const now = Buffer.alloc(size, 0x61);
    now.fill(0x62, 0, 1024);
    expect(r.kind).toBe("file");
    expect((r as { sha256: string }).sha256).toBe(createHash("sha256").update(now).digest("hex"));
    expect(calls).toBe(2); // the first attempt was refused as unstable and read again
  });
});
