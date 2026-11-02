// The subset of semver ranges CodeParley's packaging checks evaluate (Phase 5): `engines.node` and
// the declared ranges of runtime dependencies. Dependency-free, because the install checker must run
// on an installation whose dependencies are missing. Supported: `||` unions, space-separated
// conjunctions, the operators ^ ~ >= <= > < = and bare versions, partial versions (22, 22.12) and
// x-ranges (*, x). Anything else (hyphen ranges, prerelease ranges) is reported as unsupported
// (null), never guessed: a caller must treat null as "cannot evaluate", not as satisfied.

const VERSION = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
const PARTIAL = /^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/;
const COMPARATOR = /^(\^|~|>=|<=|>|<|=)?(.+)$/;
const WILDCARD = /^[xX*]$/;

/** A full version as [major, minor, patch, prerelease|null]; null when it is not one. */
export function parseVersion(text) {
  const m = VERSION.exec(String(text).trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3]), m[4] ?? null] : null;
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/** A partial version: the numeric parts given, up to the first wildcard. Null when it is not one. */
function parsePartial(text) {
  const m = PARTIAL.exec(text);
  if (!m) return null;
  const parts = [];
  for (const p of [m[1], m[2], m[3]]) {
    if (p === undefined || WILDCARD.test(p)) break;
    parts.push(Number(p));
  }
  return parts;
}

const pad = (parts) => [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];

/** The smallest version above every version the partial `parts` covers (22 → 23.0.0, 22.1 → 22.2.0). */
function after(parts) {
  const p = pad(parts);
  if (parts.length === 1) return [p[0] + 1, 0, 0];
  if (parts.length === 2) return [p[0], p[1] + 1, 0];
  return [p[0], p[1], p[2] + 1];
}

/** [lower bound inclusive, upper bound exclusive | null] of ^, ~ or an exact/partial version. */
function bounds(op, parts) {
  const lo = pad(parts);
  if (parts.length === 0) return [lo, null];
  if (op === "^") {
    if (lo[0] > 0 || parts.length === 1) return [lo, [lo[0] + 1, 0, 0]];
    if (lo[1] > 0 || parts.length === 2) return [lo, [0, lo[1] + 1, 0]];
    return [lo, [0, 0, lo[2] + 1]];
  }
  if (op === "~") return [lo, parts.length === 1 ? [lo[0] + 1, 0, 0] : [lo[0], lo[1] + 1, 0]];
  return [lo, after(parts)];
}

function compareOp(v, op, parts) {
  if (parts.length === 0) return op === ">=" || op === "<=" ? true : null;
  if (op === ">=") return cmp(v, pad(parts)) >= 0;
  if (op === "<") return cmp(v, pad(parts)) < 0;
  if (op === ">") return cmp(v, parts.length === 3 ? parts : after(parts)) >= (parts.length === 3 ? 1 : 0);
  return cmp(v, after(parts)) < 0;
}

function testComparator(v, token) {
  const m = COMPARATOR.exec(token);
  if (!m) return null;
  const op = m[1] ?? "";
  const parts = parsePartial(m[2]);
  if (parts === null) return null;
  if (op === ">=" || op === ">" || op === "<=" || op === "<") return compareOp(v, op, parts);
  const [lo, hi] = bounds(op, parts);
  return cmp(v, lo) >= 0 && (hi === null || cmp(v, hi) < 0);
}

/** A prerelease version satisfies only a range that names exactly it. */
function exactPrerelease(v, tokens) {
  if (tokens.length !== 1) return false;
  const t = parseVersion(tokens[0].startsWith("=") ? tokens[0].slice(1) : tokens[0]);
  return t !== null && t[3] === v[3] && cmp(v, t) === 0;
}

/**
 * Whether `version` satisfies `range`: true, false, or null when the range (or the version) uses
 * syntax this subset does not evaluate.
 */
export function satisfies(version, range) {
  const v = parseVersion(version);
  if (v === null) return null;
  const text = String(range).trim();
  if (text.includes(" - ")) return null;
  let unsupported = false;
  for (const set of (text === "" ? "*" : text).split("||")) {
    const tokens = set.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return null;
    if (v[3] !== null) {
      if (exactPrerelease(v, tokens)) return true;
      continue;
    }
    let all = true;
    for (const t of tokens) {
      const r = testComparator(v, t);
      if (r === null) unsupported = true;
      if (r !== true) all = false;
    }
    if (all) return true;
  }
  return unsupported ? null : false;
}
