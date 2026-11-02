// In-house glob matching for exclusion and context rules (plan §7.4, §9.3). Pure.
//
// Semantics (documented in the M1.2 procedure):
// - Paths are repository-relative with "/" separators.
// - Matching is case-insensitive (NTFS is; a confidentiality rule must not be bypassed by
//   renaming `.env` to `.ENV`).
// - `*` and `?` stay within one segment; `**` spans segments; `**/` may match zero
//   segments; `[...]`/`[!...]` classes and `{a,b}` alternatives are supported.
// - A pattern without "/" (other than a trailing one) matches at any depth, like
//   .gitignore (`*.pem` == `**/*.pem`).
// - A pattern that matches a directory matches everything under it, so `**/secrets`
//   also excludes `secrets/key.txt`. Both rules fail toward excluding more.

export interface CompiledGlob {
  pattern: string;
  test(path: string): boolean;
}

export function compileGlob(pattern: string): CompiledGlob {
  let p = pattern.trim().replace(/\\/g, "/");
  if (p.startsWith("./")) p = p.slice(2);
  const anchored = p.startsWith("/");
  if (anchored) p = p.slice(1);
  if (p.endsWith("/")) p = p.slice(0, -1);
  if (p.length === 0) return { pattern, test: () => false };
  if (!anchored && !p.includes("/")) p = `**/${p}`;
  const re = new RegExp(`^${globToRegexSource(p)}$`, "i");
  return {
    pattern,
    test(path: string): boolean {
      const norm = path.replace(/\\/g, "/").replace(/^\/+/, "");
      if (re.test(norm)) return true;
      // Any ancestor directory matching excludes its contents.
      let idx = norm.indexOf("/");
      while (idx !== -1) {
        if (re.test(norm.slice(0, idx))) return true;
        idx = norm.indexOf("/", idx + 1);
      }
      return false;
    },
  };
}

export function compileGlobs(patterns: readonly string[]): CompiledGlob[] {
  return patterns.map(compileGlob);
}

export function matchesAny(globs: readonly CompiledGlob[], path: string): boolean {
  return globs.some((g) => g.test(path));
}

function globToRegexSource(p: string): string {
  let out = "";
  let i = 0;
  let braceDepth = 0;
  while (i < p.length) {
    const c = p[i]!;
    if (c === "*") {
      if (p[i + 1] === "*") {
        const atSegStart = i === 0 || p[i - 1] === "/";
        const next = p[i + 2];
        if (atSegStart && next === "/") {
          out += "(?:.*/)?"; // "**/" : zero or more whole segments
          i += 3;
          continue;
        }
        if (atSegStart && next === undefined) {
          out += ".*"; // trailing "**"
          i += 2;
          continue;
        }
        out += ".*";
        i += 2;
        continue;
      }
      out += "[^/]*";
      i++;
      continue;
    }
    if (c === "?") {
      out += "[^/]";
      i++;
      continue;
    }
    if (c === "[") {
      const close = p.indexOf("]", i + 2);
      if (close === -1) {
        out += "\\[";
        i++;
        continue;
      }
      let body = p.slice(i + 1, close);
      let negate = false;
      if (body.startsWith("!") || body.startsWith("^")) {
        negate = true;
        body = body.slice(1);
      }
      body = body.replace(/\\/g, "\\\\").replace(/\//g, "");
      out += negate ? `[^/${body}]` : `[${body}]`;
      i = close + 1;
      continue;
    }
    if (c === "{") {
      braceDepth++;
      out += "(?:";
      i++;
      continue;
    }
    if (c === "}" && braceDepth > 0) {
      braceDepth--;
      out += ")";
      i++;
      continue;
    }
    if (c === "," && braceDepth > 0) {
      out += "|";
      i++;
      continue;
    }
    out += c.replace(/[.+^$()|\\{}\]]/g, "\\$&");
    i++;
  }
  while (braceDepth-- > 0) out += ")";
  return out;
}
