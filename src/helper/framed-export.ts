// The export sink of the custodian helper (P3.4C-5, Amendment A §A.2, §A.7): the capture writes its export here and
// every file goes to the custodian as a `file` frame — the helper writes nothing to disk. The bytes stay in memory
// (bounded by the capture's own caps) so the capture can read its head and base copies back. When the capture is
// ready for its prepared diff, the sink asks the custodian to publish the staging it has written so far (read-only to
// the helper) and the diff reads base/ and head/ from there. The custodian validates, hashes and publishes.

import { join } from "node:path";
import { sha256OfBytes } from "../common/hash.js";
import { caseKey } from "../workspace/paths.js";
import { exportDigestOf, exportPathProblem, ExportPathError, type ExportSink, type WrittenFile } from "../capture/export-writer.js";
import type { FrameWriter } from "./frames.js";

export class FramedExport implements ExportSink {
  readonly finalDir = "";
  private readonly written: WrittenFile[] = [];
  private readonly bytes = new Map<string, Buffer>();
  private readonly keys = new Set<string>();
  private stagedDir: string | null = null;

  /** `stage` sends the stage-complete notice and resolves with the directory the custodian published the staging in. */
  constructor(
    private readonly frames: FrameWriter,
    private readonly stage: () => Promise<string>,
  ) {}

  async init(): Promise<void> {}

  async write(area: string, repoRel: string, bytes: Buffer): Promise<WrittenFile | null> {
    const problem = exportPathProblem(repoRel);
    if (problem) throw new ExportPathError(`refusing to export path ${JSON.stringify(repoRel)}: ${problem}`);
    const rel = `${area}/${repoRel}`;
    const key = caseKey(rel);
    if (this.keys.has(key)) return null;
    this.keys.add(key);
    const f: WrittenFile = { rel, size: bytes.length, sha256: sha256OfBytes(bytes) };
    await this.frames.write({ t: "file", area, path: repoRel, size: f.size, sha256: f.sha256 }, bytes);
    this.bytes.set(rel, bytes);
    this.written.push(f);
    return f;
  }

  async writeRaw(): Promise<WrittenFile> {
    throw new ExportPathError("the helper export streams review exports only");
  }

  async read(rel: string): Promise<Buffer> {
    const b = this.bytes.get(rel);
    if (!b) throw new Error(`not in the export: ${rel}`);
    return b;
  }

  async reviewDirForDiff(): Promise<string> {
    this.stagedDir ??= await this.stage();
    return join(this.stagedDir, "review");
  }

  files(): readonly WrittenFile[] {
    return this.written;
  }

  digest(): string {
    return exportDigestOf(this.written);
  }

  /** The custodian publishes; the helper has nothing to rename. */
  async publish(): Promise<void> {}

  async abort(): Promise<void> {
    this.bytes.clear();
  }
}
