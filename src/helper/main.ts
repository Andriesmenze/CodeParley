// Entry point of the custodian helper's workload (P3.4C-5, Amendment A): `node dist/helper/main.js <capture|derive>`,
// started by the CodeParleyHelper service for one request, with the request on the first stdin line. It answers in
// frames on stdout (frames.ts) and exits; a failure is a `failed` frame and a non-zero exit. It never writes a file.

import { FrameWriter, LineReader } from "./frames.js";
import { CaptureWorkloadSchema, DeriveWorkloadSchema, HelperRequestSchema } from "./request.js";
import { captureWorkload, deriveWorkload } from "./workloads.js";

async function main(): Promise<number> {
  const frames = new FrameWriter(process.stdout);
  const lines = new LineReader(process.stdin);
  const kind = process.argv[2];
  try {
    if (kind !== "capture" && kind !== "derive") throw new Error(`unknown workload '${String(kind)}'`);
    const first = await lines.next();
    if (first === null) throw new Error("no request on stdin");
    const req = HelperRequestSchema.parse(JSON.parse(first));
    const result =
      kind === "capture"
        ? await captureWorkload(req.launch, CaptureWorkloadSchema.parse(req.workload), frames, lines)
        : await deriveWorkload(req.launch, DeriveWorkloadSchema.parse(req.workload));
    await frames.write({ t: "result" }, Buffer.from(JSON.stringify(result), "utf8"));
    await frames.end();
    return 0;
  } catch (e) {
    const err = e as { code?: unknown; message?: unknown };
    const code = typeof err.code === "string" && /^[A-Z_]{1,64}$/.test(err.code) ? err.code : "WORKLOAD_FAILED";
    const detail = String(err.message ?? e).slice(0, 2000);
    try {
      await frames.write({ t: "failed", code, detail });
      await frames.end();
    } catch {
      /* the channel is gone; the exit code reports the failure */
    }
    return 1;
  }
}

process.exitCode = await main();
// Stdin stays open (the custodian may still send a line); leave explicitly once the answer is out.
process.exit(process.exitCode);
