// The custodian helper's wire format (P3.4C-5, Amendment A §A.2).
//
// The helper service starts this runtime's dist/helper/main.js for one request. The request arrives as the first line
// of stdin; the workload answers with length-prefixed frames on stdout — `u32le header length · header (UTF-8 JSON
// object with a string "t") · u32le body length · body` — which the helper service relays to the custodian with the
// request's ticket and service instance added (Cli/HelperHost.cs; the custodian reads them with Ipc/HelperFrames.cs).
// The custodian's later notices (the published staging directory) arrive as further stdin lines. Nothing here touches
// the filesystem.

import type { Readable, Writable } from "node:stream";

/** The frame types a workload may send; the helper service relays these and nothing else. */
export type WorkloadFrameType = "file" | "stage_complete" | "result" | "failed";

/** Mirrors Ipc/HelperFrames.cs and CustodianConstants.MaxHelperHeaderBytes. */
export const MAX_HEADER_BYTES = 64 * 1024;

export function encodeFrame(header: { t: WorkloadFrameType } & Record<string, unknown>, body: Buffer = Buffer.alloc(0)): Buffer {
  const h = Buffer.from(JSON.stringify(header), "utf8");
  if (h.length === 0 || h.length > MAX_HEADER_BYTES) throw new Error(`frame header of ${h.length} bytes is outside 1..${MAX_HEADER_BYTES}`);
  const a = Buffer.alloc(4);
  a.writeUInt32LE(h.length);
  const b = Buffer.alloc(4);
  b.writeUInt32LE(body.length);
  return Buffer.concat([a, h, b, body]);
}

/** Writes frames to a stream, waiting for it to drain (stdout is a pipe the helper service reads at its own pace). */
export class FrameWriter {
  constructor(private readonly out: Writable) {}

  async write(header: { t: WorkloadFrameType } & Record<string, unknown>, body?: Buffer): Promise<void> {
    const frame = encodeFrame(header, body);
    if (!this.out.write(frame)) await new Promise<void>((resolve, reject) => {
      const onDrain = () => { this.out.off("error", onError); resolve(); };
      const onError = (e: Error) => { this.out.off("drain", onDrain); reject(e); };
      this.out.once("drain", onDrain);
      this.out.once("error", onError);
    });
  }

  async end(): Promise<void> {
    await new Promise<void>((resolve) => this.out.end(resolve));
  }
}

/** Reads newline-terminated lines (UTF-8) from a stream, one at a time; null at the end of the stream. */
export class LineReader {
  private buffer = "";
  private readonly lines: string[] = [];
  private ended = false;
  private waiter: (() => void) | null = null;

  constructor(input: Readable, private readonly maxLineBytes = 64 * 1024 * 1024) {
    input.setEncoding("utf8");
    input.on("data", (chunk: string) => {
      this.buffer += chunk;
      let i: number;
      while ((i = this.buffer.indexOf("\n")) >= 0) {
        this.lines.push(this.buffer.slice(0, i).replace(/\r$/, ""));
        this.buffer = this.buffer.slice(i + 1);
      }
      if (this.buffer.length > this.maxLineBytes) {
        this.buffer = "";
        this.ended = true;
      }
      this.wake();
    });
    input.on("end", () => {
      this.ended = true;
      this.wake();
    });
  }

  private wake(): void {
    const w = this.waiter;
    this.waiter = null;
    w?.();
  }

  async next(): Promise<string | null> {
    while (this.lines.length === 0) {
      if (this.ended) return null;
      await new Promise<void>((resolve) => (this.waiter = resolve));
    }
    return this.lines.shift() ?? null;
  }
}
