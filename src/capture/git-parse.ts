// Parsers for the NUL-terminated outputs of the allowed git queries (plan §9.2). Pure.
// Paths stay exactly as git reports them (UTF-8, "/" separators, repository-relative);
// validation happens in enumerate.ts.

import { isHexOid } from "./git-args.js";

export interface IndexEntry {
  path: string;
  mode: string;
  oid: string;
  stage: number;
  assumeUnchanged: boolean;
  skipWorktree: boolean;
}

/** `ls-files -z -v --stage --cached`: "<tag> <mode> <oid> <stage>\t<path>\0". */
export function parseLsFilesStage(out: string): IndexEntry[] {
  const entries: IndexEntry[] = [];
  for (const rec of splitZ(out)) {
    const tab = rec.indexOf("\t");
    if (tab < 0) throw new Error(`unexpected ls-files record: ${JSON.stringify(rec.slice(0, 80))}`);
    const meta = rec.slice(0, tab).split(" ");
    const path = rec.slice(tab + 1);
    if (meta.length !== 4) throw new Error(`unexpected ls-files metadata: ${rec.slice(0, tab)}`);
    const [tag, mode, oid, stage] = meta as [string, string, string, string];
    if (!isHexOid(oid) || !/^[0-7]{6}$/.test(mode)) throw new Error(`unexpected ls-files entry: ${rec.slice(0, tab)}`);
    entries.push({
      path,
      mode,
      oid,
      stage: Number(stage),
      // -v: lowercase tag = assume-unchanged; S/s = skip-worktree.
      assumeUnchanged: tag.length === 1 && tag === tag.toLowerCase() && tag !== tag.toUpperCase(),
      skipWorktree: tag.toUpperCase() === "S",
    });
  }
  return entries;
}

/** `ls-files -z --others ...`: plain paths; a trailing "/" marks a nested repository. */
export function parsePathList(out: string): string[] {
  return splitZ(out);
}

export interface TreeEntry {
  path: string;
  mode: string;
  type: "blob" | "tree" | "commit";
  oid: string;
  /** Blob size from `-l`; null for commits (gitlinks). */
  size: number | null;
}

/** `ls-tree -r -z -l --full-tree <oid>`: "<mode> <type> <oid> <size>\t<path>\0". */
export function parseLsTree(out: string): TreeEntry[] {
  const entries: TreeEntry[] = [];
  for (const rec of splitZ(out)) {
    const tab = rec.indexOf("\t");
    if (tab < 0) throw new Error(`unexpected ls-tree record: ${JSON.stringify(rec.slice(0, 80))}`);
    const meta = rec.slice(0, tab).trim().split(/ +/);
    const path = rec.slice(tab + 1);
    const [mode, type, oid, size] = meta as [string, string, string, string | undefined];
    if (!isHexOid(oid) || (type !== "blob" && type !== "tree" && type !== "commit")) {
      throw new Error(`unexpected ls-tree entry: ${rec.slice(0, tab)}`);
    }
    // A missing blob in a partial clone is listed with size "BAD" (lazy fetch is disabled).
    entries.push({ path, mode, type, oid, size: size !== undefined && /^\d+$/.test(size) ? Number(size) : null });
  }
  return entries;
}

/** `check-attr -z --stdin a b c`: "<path>\0<attr>\0<value>\0" triples. */
export function parseCheckAttr(out: string): Map<string, Record<string, string>> {
  const parts = out.split("\0");
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  if (parts.length % 3 !== 0) throw new Error("unexpected check-attr output");
  const result = new Map<string, Record<string, string>>();
  for (let i = 0; i < parts.length; i += 3) {
    const path = parts[i]!;
    let rec = result.get(path);
    if (!rec) {
      rec = {};
      result.set(path, rec);
    }
    rec[parts[i + 1]!] = parts[i + 2]!;
  }
  return result;
}

/** `config -z --get-regexp ...`: "<key>\n<value>\0" (value may be absent for bare keys). */
export function parseConfigZ(out: string): { key: string; value: string | null }[] {
  return splitZ(out).map((rec) => {
    const nl = rec.indexOf("\n");
    return nl < 0 ? { key: rec, value: null } : { key: rec.slice(0, nl), value: rec.slice(nl + 1) };
  });
}

export interface BatchObject {
  oid: string;
  type: string | null; // null = missing
  content: Buffer | null;
}

/** `cat-file --batch` output for the requested oids, in order. */
export function parseCatFileBatch(buf: Buffer, requested: readonly string[]): BatchObject[] {
  const out: BatchObject[] = [];
  let pos = 0;
  for (const want of requested) {
    const nl = buf.indexOf(0x0a, pos);
    if (nl < 0) throw new Error("truncated cat-file --batch output");
    const header = buf.subarray(pos, nl).toString("utf8");
    pos = nl + 1;
    const missing = /^(\S+) missing$/.exec(header);
    if (missing) {
      out.push({ oid: want, type: null, content: null });
      continue;
    }
    const m = /^([0-9a-f]+) (\S+) (\d+)$/.exec(header);
    if (!m || m[1] !== want) throw new Error(`unexpected cat-file --batch header: ${header}`);
    const size = Number(m[3]);
    if (pos + size + 1 > buf.length) throw new Error("truncated cat-file --batch content");
    out.push({ oid: want, type: m[2]!, content: Buffer.from(buf.subarray(pos, pos + size)) });
    pos += size + 1; // content + LF
  }
  return out;
}

/** `cat-file --batch-check` output: oid -> size, or null when missing. */
export function parseCatFileBatchCheck(out: string, requested: readonly string[]): Map<string, number | null> {
  const lines = out.split("\n");
  const result = new Map<string, number | null>();
  requested.forEach((oid, i) => {
    const line = lines[i] ?? "";
    const m = /^([0-9a-f]+) (\S+) (\d+)$/.exec(line);
    if (m && m[1] === oid) result.set(oid, Number(m[3]));
    else if (line === `${oid} missing`) result.set(oid, null);
    else throw new Error(`unexpected cat-file --batch-check line: ${line}`);
  });
  return result;
}

function splitZ(out: string): string[] {
  const parts = out.split("\0");
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  return parts;
}
