// Immutable export writing (plan §9.5, CG5, §15.3).
//
// An export is assembled in a fresh staging directory beside its final location and then
// renamed into place in one step, so `<run>\exports\<operation-id>\` either does not exist
// or is complete. Files are created exclusively (never overwritten) and fsynced before
// publication; every written path is validated as a plain relative path under the platform's
// rules (workspace/paths.ts), so a repository path can never address an alternate data stream,
// a device, or anything outside the export. There is no `.git` anywhere in an export.

import { createHash, randomBytes } from "node:crypto";
import { mkdir, open, readdir, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalize, sha256OfBytes } from "../common/hash.js";
import { caseKey, segmentProblem } from "../workspace/paths.js";
import { looksLikeShortName } from "./enumerate.js";

export interface WrittenFile {
  /** Export-relative path with "/" separators, e.g. "tree/src/a.ts". */
  rel: string;
  size: number;
  sha256: string;
}

export class ExportPathError extends Error {}

/** Validate a repository-relative path for writing under an export area. */
export function exportPathProblem(repoRel: string): string | null {
  const segs = repoRel.split("/");
  for (const s of segs) {
    const p = segmentProblem(s);
    if (p) return p;
    if (s.toLowerCase() === ".git") return ".git segment";
    if (looksLikeShortName(s)) return "possible 8.3 short-name alias";
  }
  return null;
}

/**
 * Where a capture puts its export (or baseline) while it assembles it. The disk implementation is {@link StagedExport};
 * the custodian helper (P3.4C-5, Amendment A) streams the same files to the custodian instead and writes nothing itself.
 * `read` returns bytes already written (the head copies and the EOL facts read them back); `reviewDirForDiff` is the
 * directory holding `base/` and `head/` for the prepared diff — for the helper, the custodian's read-only staging.
 */
export interface ExportSink {
  /** Where the published export ends up (empty when the custodian publishes it). */
  readonly finalDir: string;
  init(subdirs: readonly string[]): Promise<void>;
  write(area: string, repoRel: string, bytes: Buffer): Promise<WrittenFile | null>;
  writeRaw(name: string, bytes: Buffer): Promise<WrittenFile>;
  read(rel: string): Promise<Buffer>;
  reviewDirForDiff(): Promise<string>;
  files(): readonly WrittenFile[];
  digest(): string;
  publish(): Promise<void>;
  abort(): Promise<void>;
}

export class StagedExport implements ExportSink {
  readonly stagingDir: string;
  private readonly written: WrittenFile[] = [];
  private readonly keys = new Set<string>();

  constructor(
    readonly finalDir: string,
    private readonly fsync: boolean = true,
  ) {
    this.stagingDir = join(dirname(finalDir), `.staging-${randomBytes(6).toString("hex")}`);
  }

  async init(subdirs: readonly string[]): Promise<void> {
    if (await exists(this.finalDir)) throw new Error(`export already exists: ${this.finalDir}`);
    await mkdir(this.stagingDir, { recursive: true });
    for (const d of subdirs) await mkdir(join(this.stagingDir, ...d.split("/")), { recursive: true });
  }

  /** Write `bytes` at `<area>/<repoRel>`. Returns false (and writes nothing) on a duplicate (case-insensitive on Windows). */
  async write(area: string, repoRel: string, bytes: Buffer): Promise<WrittenFile | null> {
    const problem = exportPathProblem(repoRel);
    if (problem) throw new ExportPathError(`refusing to export path ${JSON.stringify(repoRel)}: ${problem}`);
    const rel = `${area}/${repoRel}`;
    const key = caseKey(rel);
    if (this.keys.has(key)) return null;
    this.keys.add(key);
    const abs = join(this.stagingDir, ...rel.split("/"));
    await mkdir(dirname(abs), { recursive: true });
    const fh = await open(abs, "wx");
    try {
      await fh.writeFile(bytes);
      if (this.fsync) await fh.sync();
    } finally {
      await fh.close();
    }
    const f: WrittenFile = { rel, size: bytes.length, sha256: sha256OfBytes(bytes) };
    this.written.push(f);
    return f;
  }

  /** Write a file at the export root (e.g. baseline.json). */
  async writeRaw(name: string, bytes: Buffer): Promise<WrittenFile> {
    const problem = exportPathProblem(name);
    if (problem || name.includes("/")) throw new ExportPathError(`refusing to write ${JSON.stringify(name)}`);
    const abs = join(this.stagingDir, name);
    const fh = await open(abs, "wx");
    try {
      await fh.writeFile(bytes);
      if (this.fsync) await fh.sync();
    } finally {
      await fh.close();
    }
    const f: WrittenFile = { rel: name, size: bytes.length, sha256: sha256OfBytes(bytes) };
    this.written.push(f);
    return f;
  }

  files(): readonly WrittenFile[] {
    return this.written;
  }

  /** Bytes already written at export-relative `rel` ("tree/a.txt"). */
  async read(rel: string): Promise<Buffer> {
    return readFile(join(this.stagingDir, ...rel.split("/")));
  }

  async reviewDirForDiff(): Promise<string> {
    return join(this.stagingDir, "review");
  }

  /** Digest over every file in the export (path, size, SHA-256). */
  digest(): string {
    return exportDigestOf(this.written);
  }

  /** Rename the staging directory into place (one step). */
  async publish(): Promise<void> {
    if (await exists(this.finalDir)) throw new Error(`export already exists: ${this.finalDir}`);
    const started = Date.now();
    for (;;) {
      try {
        await rename(this.stagingDir, this.finalDir);
        return;
      } catch (e) {
        const code = (e as { code?: string }).code ?? "";
        if ((code === "EPERM" || code === "EACCES" || code === "EBUSY") && Date.now() - started < 2000) {
          await new Promise((r) => setTimeout(r, 50));
          continue;
        }
        throw e;
      }
    }
  }

  async abort(): Promise<void> {
    await rm(this.stagingDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** The export digest: SHA-256 over every file's export-relative path, size and SHA-256. */
export function exportDigestOf(files: readonly { rel: string; size: number; sha256: string }[]): string {
  const rows = [...files].sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0)).map((f) => [f.rel, f.size, f.sha256]);
  return createHash("sha256").update(canonicalize({ schema: "arl.export-digest.v1", files: rows }), "utf8").digest("hex");
}

export interface ExportVerification {
  ok: boolean;
  problems: string[];
}

/** Engine-held identities of a published export (from the local capture record). */
export interface ExportAnchor {
  export_digest: string;
  manifest_digest: string;
}

/**
 * Verify a published review export. With an `anchor` (the engine's own record of what it
 * published, F6) every file actually present — the manifest included — is re-hashed and the
 * export digest must equal the anchored one, and the manifest's digest must equal the
 * anchored manifest digest; editing a file together with the export-local manifest is
 * therefore detected. The internal consistency of the manifest with the files is also
 * checked. Without an anchor only the internal consistency is checked (not sufficient for
 * an export handed to Codex).
 */
export async function verifyReviewExport(exportDir: string, anchor?: ExportAnchor): Promise<ExportVerification> {
  const problems: string[] = [];
  if (anchor) {
    const rows: { rel: string; size: number; sha256: string }[] = [];
    for (const rel of await listFiles(exportDir)) {
      const bytes = await readFile(join(exportDir, ...rel.split("/")));
      rows.push({ rel, size: bytes.length, sha256: sha256OfBytes(bytes) });
    }
    if (exportDigestOf(rows) !== anchor.export_digest) problems.push("export content differs from what the engine published (anchored export digest mismatch)");
  }
  let manifest: {
    manifest_digest: string;
    files: { path: string; area: string; size: number; sha256: string }[];
    review_files: { diff_patch: { size: number; sha256: string }; base: { path: string; size: number; sha256: string }[]; head: { path: string; size: number; sha256: string }[] };
  };
  try {
    manifest = JSON.parse(await readFile(join(exportDir, "review", "manifest.json"), "utf8"));
  } catch (e) {
    return { ok: false, problems: [`manifest unreadable: ${String((e as Error).message)}`] };
  }
  const { manifest_digest, ...rest } = manifest as unknown as Record<string, unknown> & { manifest_digest: string };
  if (createHash("sha256").update(canonicalize(rest), "utf8").digest("hex") !== manifest_digest) problems.push("manifest digest mismatch");
  if (anchor && manifest_digest !== anchor.manifest_digest) problems.push("manifest differs from the one the engine published (anchored manifest digest mismatch)");

  const expected = new Map<string, { size: number; sha256: string }>();
  for (const f of manifest.files) expected.set(caseKey(`${f.area}/${f.path}`), f);
  for (const f of manifest.review_files.base) expected.set(caseKey(`review/base/${f.path}`), f);
  for (const f of manifest.review_files.head) expected.set(caseKey(`review/head/${f.path}`), f);
  expected.set("review/diff.patch", manifest.review_files.diff_patch);

  const seen = new Set<string>();
  for (const rel of await listFiles(exportDir)) {
    const key = caseKey(rel);
    if (key === "review/manifest.json") continue;
    const exp = expected.get(key);
    if (!exp) {
      problems.push(`unlisted file: ${rel}`);
      continue;
    }
    seen.add(key);
    const bytes = await readFile(join(exportDir, ...rel.split("/")));
    if (bytes.length !== exp.size || sha256OfBytes(bytes) !== exp.sha256) problems.push(`content mismatch: ${rel}`);
  }
  for (const key of expected.keys()) if (!seen.has(key)) problems.push(`missing file: ${key}`);
  return { ok: problems.length === 0, problems };
}

/** All files under `dir`, as "/"-separated relative paths (no link following). */
export async function listFiles(dir: string, prefix = ""): Promise<string[]> {
  const out: string[] = [];
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...(await listFiles(join(dir, ent.name), rel)));
    else out.push(rel);
  }
  return out;
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}
