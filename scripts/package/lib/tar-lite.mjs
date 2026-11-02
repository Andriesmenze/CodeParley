// A minimal, read-only reader for the gzip-compressed tar archives `npm pack` writes (Phase 5), so
// the packaging checks read a tarball's real content instead of trusting the report of the tool
// that wrote it. It understands ustar headers (with the prefix field), pax extended headers
// (`path`) and GNU long names; it never writes anything to disk.

import { gunzipSync } from "node:zlib";

const BLOCK = 512;

function text(buf, start, len) {
  const end = buf.indexOf(0, start);
  return buf.toString("utf8", start, end === -1 || end > start + len ? start + len : end);
}

function octal(buf, start, len) {
  const s = text(buf, start, len).trim();
  return s === "" ? 0 : Number.parseInt(s, 8);
}

/** The records of a pax extended header ("<len> <key>=<value>\n" each). */
function paxRecords(data) {
  const out = {};
  let i = 0;
  while (i < data.length) {
    const space = data.indexOf(0x20, i);
    if (space === -1) break;
    const len = Number.parseInt(data.toString("utf8", i, space), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const record = data.toString("utf8", space + 1, i + len - 1);
    const eq = record.indexOf("=");
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    i += len;
  }
  return out;
}

function isZeroBlock(buf, at) {
  for (let i = at; i < at + BLOCK; i++) if (buf[i] !== 0) return false;
  return true;
}

function header(buf, at) {
  const magic = text(buf, at + 257, 6);
  return {
    name: text(buf, at, 100),
    mode: octal(buf, at + 100, 8),
    size: octal(buf, at + 124, 12),
    flag: buf[at + 156] === 0 ? "0" : String.fromCharCode(buf[at + 156]),
    prefix: magic.startsWith("ustar") ? text(buf, at + 345, 155) : "",
  };
}

const TYPES = { 0: "file", 5: "directory" };

/** The path a metadata entry (pax "x", GNU long name "L") sets for the next entry; undefined for any other entry. */
function metaPath(h, bytes, current) {
  if (h.flag === "x") return paxRecords(bytes).path ?? current;
  if (h.flag === "L") return text(bytes, 0, bytes.length);
  return undefined;
}

function entryPath(h, longPath) {
  if (longPath !== null) return longPath;
  return h.prefix ? `${h.prefix}/${h.name}` : h.name;
}

/**
 * The entries of a .tgz: { path, type ("file" | "directory" | "other"), size, mode, data? }. With
 * `{ data: true }` each file entry carries its bytes. Throws on a truncated archive.
 */
export function readTarGz(gz, options = {}) {
  const buf = gunzipSync(gz);
  const entries = [];
  let longPath = null;
  let at = 0;
  while (at + BLOCK <= buf.length && !isZeroBlock(buf, at)) {
    const h = header(buf, at);
    const body = at + BLOCK;
    if (body + h.size > buf.length) throw new Error(`truncated tar entry ${h.name}`);
    const bytes = buf.subarray(body, body + h.size);
    at = body + Math.ceil(h.size / BLOCK) * BLOCK;
    const meta = metaPath(h, bytes, longPath);
    if (meta !== undefined) {
      longPath = meta;
      continue;
    }
    if (h.flag === "g") continue;
    const entry = { path: entryPath(h, longPath), type: TYPES[h.flag] ?? "other", size: h.size, mode: h.mode };
    longPath = null;
    if (options.data === true && entry.type === "file") entry.data = Buffer.from(bytes);
    entries.push(entry);
  }
  return entries;
}

/** An npm tarball's entries relative to its `package/` root, as a Map path → entry (files only). */
export function packageFiles(gz, options) {
  const out = new Map();
  for (const e of readTarGz(gz, options)) {
    if (e.type !== "file") continue;
    const rel = e.path.startsWith("package/") ? e.path.slice("package/".length) : e.path;
    out.set(rel, { ...e, path: rel });
  }
  return out;
}
