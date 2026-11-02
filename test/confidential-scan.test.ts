// The confidential-name scanner (policy/confidential-scan.ts): bounded time on adversarial
// input, exact name-token semantics with explicit boundaries, nested escaping, and one
// matcher shared by redaction and the invariant (MR-F; F4 round 3); bounded work under
// heavily overlapping withheld patterns and Unicode-aware case-insensitive comparison (round 4).

import { beforeAll, describe, it, expect } from "vitest";
import { canonicalize, confidentialMatcher, DECODE_LAYERS, MAX_SCAN_CANDIDATES, violates } from "../src/policy/confidential-scan.js";
import { assertTextConfidential, containsWithheldPath, redactPaths, SCAN_LIMIT_REDACTION } from "../src/policy/review-bundle.js";

const W = new Set(["config/db.env", "private dir/secret.env", ".env", "secrets/id_rsa"]);
const ms = (f: () => unknown) => {
  const t = performance.now();
  f();
  return performance.now() - t;
};
const nest = (s: string, depth: number) => {
  let out = s;
  for (let i = 0; i < depth; i++) out = JSON.stringify(out);
  return out;
};

// The character tables (fold/class, 65,536 entries) are built once per process on first use
// (~20 ms); the timings below measure scans, not that one-time initialization.
beforeAll(() => {
  canonicalize("warm", "separator");
});

describe("bounded time on adversarial input (no backtracking regex on model-controlled text)", () => {
  // The reported shape: a short text with repeated escaped separators after a name prefix.
  const repro = (n: number) => "private dir" + "\\\\u002f".repeat(n) + "x";
  // A backtracking scanner takes seconds on this shape; a linear one about a millisecond. The bound sits between with a
  // margin for a loaded machine (Phase 6 Increment 1: 56 ms was measured under T1 load against the former 50 ms).
  const BOUND_MS = 500;
  it("Codex's reproduction shape (27-30 repetitions, ~200 characters) scans in milliseconds", () => {
    for (const n of [27, 29, 30]) {
      const t = repro(n);
      expect(ms(() => redactPaths(t, W, { n: 0 })), `redact ${n}`).toBeLessThan(BOUND_MS);
      expect(ms(() => assertTextConfidential(t, W, new Set())), `assert ${n}`).toBeLessThan(BOUND_MS);
      expect(ms(() => containsWithheldPath(t, W)), `contains ${n}`).toBeLessThan(BOUND_MS);
    }
  });
  it("larger hostile variants stay fast and scale linearly", () => {
    const shapes: ((n: number) => string)[] = [
      repro,
      (n) => "config" + "\\".repeat(n) + "!",
      (n) => "config" + "\\u002f\\\\u005c/".repeat(n) + "db.envx",
      (n) => "private dir/".repeat(n) + "secret.env.ts",
      (n) => "a".repeat(n) + "\\u00".repeat(n),
      (n) => nest("config\\db.env ".repeat(Math.max(1, n / 1000)), 3),
      (n) => "_".repeat(n) + "config/db.env" + ".".repeat(n) + "x",
    ];
    const check = (t: string) => {
      try {
        assertTextConfidential(t, W, new Set([]));
      } catch {
        /* a match is fine; time is what is measured */
      }
    };
    for (const [k, shape] of shapes.entries()) {
      const small = shape(10_000);
      const large = shape(100_000);
      const ts = ms(() => check(small)) + ms(() => redactPaths(small, W, { n: 0 }));
      const tl = ms(() => check(large)) + ms(() => redactPaths(large, W, { n: 0 }));
      expect(tl, `shape ${k}: ${large.length} chars`).toBeLessThan(3000);
      // 10x the input may take at most ~40x the time plus scheduling slack under parallel test
      // load; a superlinear (let alone exponential) scanner would exceed this by far.
      expect(tl, `shape ${k} scaling (small ${ts.toFixed(1)} ms)`).toBeLessThan(ts * 40 + 1000);
    }
  });
  it("many withheld paths do not multiply the work (Aho–Corasick)", () => {
    const many = new Set(Array.from({ length: 5000 }, (_, i) => `dir${i}/file${i}.env`));
    const text = "lorem ipsum dir42/file4.envx ".repeat(20_000);
    expect(ms(() => redactPaths(text, many, { n: 0 }))).toBeLessThan(3000);
    expect(redactPaths("see dir4999/file4999.env!", many, { n: 0 })).toBe("see [withheld path]!");
  });
});

describe("exact name-token semantics with explicit boundaries", () => {
  const positives = [
    "FILE=config/db.env",
    "config/db.env#L1",
    "[link](config/db.env)",
    "[config/db.env](https://example.invalid/x)",
    "https://host/repo/blob/main/config/db.env?plain=1#L3",
    "?path=config/db.env&x=1",
    '"config/db.env"',
    "'config/db.env'",
    "(config/db.env)",
    "see config/db.env, then",
    "see config/db.env.",
    "config/db.env: line 1",
    "config/db.env;",
    "config\\db.env",
    "CONFIG/DB.ENV",
    "Config\\Db.Env",
    "**config/db.env**",
    "_config/db.env_",
    "`config/db.env`",
    "<config/db.env>",
    "tree/config/db.env",
    "./config/db.env",
    "private dir/secret.env",
    "Private Dir\\Secret.ENV",
    '"private dir/secret.env",',
    "SECRET=.env",
    "load .env now",
    "secrets/id_rsa",
  ];
  const nearMisses = [
    "config/db.env.ts",
    "config/db.env_old",
    "config/db.envx",
    "config/db.env-backup",
    "config/db.env~",
    "myconfig/db.env",
    "x_config/db.env",
    "config/db-env",
    "private dir/secret.env.ts",
    "private dir/secret.envs",
    "aprivate dir/secret.env",
    "process.env.HOME",
    "load .env.local",
    "x.env",
    "secrets/id_rsa.pub",
  ];
  it("recognizes a withheld path amid prose, Markdown, assignment, URL and fragment punctuation", () => {
    for (const t of positives) {
      expect(containsWithheldPath(t, W), t).toBe(true);
      expect(() => assertTextConfidential(t, W, new Set()), t).toThrow(/MR-F/);
      const r = redactPaths(t, W, { n: 0 });
      expect(r, t).toContain("[withheld path]");
      expect(() => assertTextConfidential(r, W, new Set()), r).not.toThrow();
    }
  });
  it("redacts exactly the name: surrounding punctuation and prefixes are kept", () => {
    expect(redactPaths("FILE=config/db.env", W, { n: 0 })).toBe("FILE=[withheld path]");
    expect(redactPaths("config/db.env#L1", W, { n: 0 })).toBe("[withheld path]#L1");
    expect(redactPaths("[x](config/db.env)", W, { n: 0 })).toBe("[x]([withheld path])");
    expect(redactPaths("**CONFIG/DB.ENV**.", W, { n: 0 })).toBe("**[withheld path]**.");
    expect(redactPaths("see private dir/secret.env, ok", W, { n: 0 })).toBe("see [withheld path], ok");
  });
  it("never matches a longer name that merely starts or ends with a withheld path", () => {
    for (const t of nearMisses) {
      expect(containsWithheldPath(t, W), t).toBe(false);
      expect(redactPaths(t, W, { n: 0 }), t).toBe(t);
      expect(() => assertTextConfidential(t, W, new Set()), t).not.toThrow();
    }
  });
  it("holds through every JSON-escaping depth up to the bound, for positives and near-misses", () => {
    for (let depth = 0; depth <= DECODE_LAYERS; depth++) {
      for (const t of ["FILE=config\\db.env", "config/db.env#L1", "private dir\\secret.env"]) {
        expect(() => assertTextConfidential(nest(t, depth), W, new Set()), `${t} @${depth}`).toThrow(/MR-F/);
      }
      for (const t of ["config\\db.env.ts", "private dir\\secret.env.ts"]) {
        expect(() => assertTextConfidential(nest(t, depth), W, new Set()), `${t} @${depth}`).not.toThrow();
      }
    }
    const reported = JSON.stringify({ payload: JSON.stringify({ path: "config\\db.env" }) });
    expect(redactPaths(reported, W, { n: 0 })).not.toMatch(/db\.env/i);
  });
  it("a JSON escape before a name does not glue it to the previous word (escape mode)", () => {
    expect(containsWithheldPath('"x\\nconfig/db.env"', W)).toBe(true);
    expect(containsWithheldPath('"x\\tsecrets\\\\id_rsa"', W)).toBe(true);
  });
});

describe("redaction and the invariant share one matcher", () => {
  const alphabet = ["config", "/", "\\", "\\\\", "db.env", ".", "#", "=", " ", "_", "u002f", "x", '"', "\\n", "private dir", "secret.env", ".ts", "CONFIG", "env"];
  it("fuzz: clean text is never altered, and redacted text never matches in the raw view", () => {
    let seed = 42;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const m = confidentialMatcher(W);
    for (let k = 0; k < 3000; k++) {
      const len = 1 + Math.floor(rnd() * 12);
      let t = "";
      for (let i = 0; i < len; i++) t += alphabet[Math.floor(rnd() * alphabet.length)];
      const redacted = redactPaths(t, W, { n: 0 });
      const rawHit = m.scan(t, "separator", true).length + m.scan(t, "escape", true).length;
      if (rawHit === 0) expect(redacted, t).toBe(t);
      expect(m.scan(redacted, "separator").length + m.scan(redacted, "escape").length, `${t} -> ${redacted}`).toBe(0);
    }
  });
  it("an encoding redaction cannot rewrite is still caught by the invariant (fail closed)", () => {
    const t = "see \\u0063onfig/db.env";
    expect(violates(t, confidentialMatcher(W))).not.toBeNull();
    expect(() => assertTextConfidential(redactPaths(t, W, { n: 0 }), W, new Set())).toThrow(/MR-F/);
  });
  it("canonicalization maps every canonical character back to its original span", () => {
    const c = canonicalize("A\\\\u002fB\\\\\\nC", "escape");
    expect(c.text).toBe("a/b c");
    expect([...c.start]).toEqual([0, 1, 8, 9, 13]);
    expect([...c.end]).toEqual([1, 8, 9, 13, 14]);
  });
});

// --- round 4: bounded overlapping matches; Unicode-aware case-insensitive comparison --------

const expectBounded = (label: string, text: string, w: ReadonlySet<string>, maxMs: number) => {
  let redacted = "";
  let error: unknown = null;
  const t = ms(() => {
    redacted = redactPaths(text, w, { n: 0 });
    try {
      assertTextConfidential(text, w, new Set());
    } catch (e) {
      error = e;
    }
    containsWithheldPath(text, w);
  });
  expect(t, `${label}: ${text.length} chars took ${t.toFixed(0)} ms`).toBeLessThan(maxMs);
  return { redacted, error };
};

describe("overlapping withheld patterns: bounded work, explicit fail-closed limit", () => {
  const underscores = (k: number) => new Set(Array.from({ length: k }, (_, i) => "_".repeat(i + 1)));

  it("Codex's exact reproduction (k overlapping `_` patterns over `_` x n) is fast and fail-closed", () => {
    // on 8844b98: 984 ms, 5293 ms and 39331 ms
    for (const [k, n] of [[50, 2000], [100, 4000], [200, 8000]] as const) {
      const { redacted, error } = expectBounded(`k=${k}`, "_".repeat(n), underscores(k), 1000);
      // every underscore run is a withheld name here: redacted span by span, or withheld whole
      expect([SCAN_LIMIT_REDACTION, "[withheld path]"], `k=${k}`).toContain(redacted);
      expect(String(error), `k=${k}`).toMatch(/MR-F/);
    }
  });

  it("larger adversarial overlaps stay bounded whatever the pattern count", () => {
    const cases: [string, string, ReadonlySet<string>][] = [
      ["2000 patterns, 1M underscores", "_".repeat(1_000_000), underscores(2000)],
      // every candidate fails its boundary check: nothing matches, yet n x k candidates exist
      ["no candidate passes", "a" + "_".repeat(200_000) + "a", underscores(1000)],
      ["spaced overlaps", "x" + " a".repeat(200_000), new Set(Array.from({ length: 500 }, (_, i) => " a".repeat(i + 1).trim()))],
      ["dotted overlaps", "x" + ".".repeat(200_000) + "x", new Set(Array.from({ length: 500 }, (_, i) => ".".repeat(i + 1)))],
    ];
    for (const [label, text, w] of cases) {
      const { redacted, error } = expectBounded(label, text, w, 3000);
      // withheld whole by redaction => rejected by the invariant (a real match or the bound)
      if (redacted === SCAN_LIMIT_REDACTION) expect(String(error), label).toMatch(/MR-F/);
    }
  });

  it("past the candidate budget the scan reports `limit`: redaction withholds the whole text, the invariant rejects it", () => {
    const w = underscores(1000);
    const text = "a" + "_".repeat(10_000) + "a"; // ~10M candidates, none a real match
    const m = confidentialMatcher(w);
    expect(m.scan(text, "separator")).toEqual([{ kind: "limit", start: 0, end: text.length }]);
    const counter = { n: 0 };
    expect(redactPaths(text, w, counter)).toBe(SCAN_LIMIT_REDACTION);
    expect(counter.n).toBe(1);
    expect(() => assertTextConfidential(text, w, new Set())).toThrow(/exceeded the confidentiality scan bound.*fail closed/);
    expect(violates(text, m)?.kind).toBe("limit");
  });

  it("overlapping withheld hashes are bounded the same way", () => {
    const hashes = new Set(Array.from({ length: 500 }, (_, i) => "0".repeat(i + 1)));
    const text = "x" + "0".repeat(500_000);
    const t = ms(() => expect(() => assertTextConfidential(text, new Set(["unused/x.env"]), hashes)).toThrow(/MR-F/));
    expect(t).toBeLessThan(3000);
  });

  it("boundary checks never rescan long runs (one pattern, every position a candidate)", () => {
    // one pattern keeps the candidates under the budget, so this exercises the O(1) boundary
    // facts alone; rescanning the run per candidate was quadratic here (~2*10^10 steps)
    const w = new Set(["_"]);
    expect(200_001).toBeLessThan(MAX_SCAN_CANDIDATES);
    for (const text of ["_".repeat(200_000) + "a", "a" + "_".repeat(200_000), "a" + ".".repeat(100_000) + "_".repeat(100_000) + "a"]) {
      const { redacted, error } = expectBounded(`run ${text.length}`, text, w, 1000);
      expect(redacted).toBe(text); // `_` glued to a name is not the withheld name `_`
      expect(error).toBeNull();
    }
  });

  it("ordinary texts with many real matches stay under the budget and are redacted span by span", () => {
    const text = "see config/db.env and CONFIG\\DB.ENV; ".repeat(20_000);
    const counter = { n: 0 };
    const r = redactPaths(text, W, counter);
    expect(r).toBe("see [withheld path] and [withheld path]; ".repeat(20_000));
    expect(counter.n).toBe(40_000);
    expect(() => assertTextConfidential(r, W, new Set())).not.toThrow();
  });
});

describe("Unicode-aware case-insensitive confidential paths (Windows)", () => {
  const U = new Set(["config/Ä.env"]);
  const positive = (w: ReadonlySet<string>, t: string) => {
    expect(containsWithheldPath(t, w), t).toBe(true);
    expect(() => assertTextConfidential(t, w, new Set()), t).toThrow(/MR-F/);
    const r = redactPaths(t, w, { n: 0 });
    expect(r, t).toContain("[withheld path]");
    expect(() => assertTextConfidential(r, w, new Set()), r).not.toThrow();
  };
  const negative = (w: ReadonlySet<string>, t: string) => {
    expect(containsWithheldPath(t, w), t).toBe(false);
    expect(redactPaths(t, w, { n: 0 }), t).toBe(t);
    expect(() => assertTextConfidential(t, w, new Set()), t).not.toThrow();
  };

  it("Codex's reproduction: `config/Ä.env` withheld, `config/ä.env` is redacted and rejected", () => {
    expect(redactPaths("see config/ä.env", U, { n: 0 })).toBe("see [withheld path]");
    for (const t of ["config/ä.env", "config/Ä.env", "CONFIG/Ä.ENV", "Config\\ä.Env", "FILE=config/ä.env#L2", "`config/ä.env`"]) positive(U, t);
  });

  it("other non-ASCII case pairs fold as Windows folds them, symmetrically", () => {
    const pairs: [string, string][] = [
      ["daten/Öl.txt", "DATEN/öL.TXT"],
      ["café/Été.env", "CAFÉ/été.ENV"],
      ["ΣΥΝΟΛΟ/Ωμέγα.key", "συνολο/ωΜΈΓΑ.KEY"],
      ["λόγος/x.env", "ΛΌΓΟΣ/X.ENV"], // final sigma folds with σ/Σ
      ["секрет/Ключ.pem", "СЕКРЕТ/ключ.PEM"],
      ["ＡＢＣ/x.env", "ａｂｃ/X.ENV"], // fullwidth Latin
      ["dir/i.env", "DIR/ı.env"], // dotless ı upper-cases to I, as on NTFS
      ["Å/x.env", "Å/x.env"], // ANGSTROM SIGN is canonically Å
    ];
    for (const [withheld, spelled] of pairs) {
      positive(new Set([withheld]), spelled);
      positive(new Set([spelled]), withheld); // withheld paths are folded the same way
    }
  });

  it("composed and decomposed spellings compare equal, in both directions", () => {
    positive(U, "config/Ä.env");
    positive(U, "config/ä.env");
    positive(new Set(["config/Ä.env"]), "config/ä.env");
    // several marks: canonical ordering and composition (ệ = e + U+0323 + U+0302)
    const V = new Set(["tiếng/việt.env"]);
    positive(V, "TIẾNG/VIỆT.ENV");
    positive(V, "tiếng/việt.env");
    positive(V, "TIẾNG/VIỆT.ENV".normalize("NFD"));
  });

  it("ASCII behaviour is unchanged", () => {
    for (const t of ["config/db.env", "CONFIG\\DB.ENV", "Config/Db.Env", "FILE=config/db.env"]) positive(W, t);
    for (const t of ["config/db.env.ts", "myconfig/db.env", "config/db.envx"]) negative(W, t);
  });

  it("near misses stay visible", () => {
    for (const t of [
      "config/ä.env.ts",
      "config/äx.env",
      "config/xä.env",
      "config/a.env", // no diaeresis: a different name
      "config/å.env",
      "config/ä́.env", // an extra combining mark is a different name
      "config/ä.envé", // a Unicode letter continues the name
      "config/ä.env́", // so does a combining mark
      "éconfig/ä.env",
      "конфиг/ä.env",
    ]) negative(U, t);
    // ß has no single-unit upper case: NTFS keeps `straße` and `STRASSE` distinct
    negative(new Set(["straße/x.env"]), "STRASSE/x.env");
    // İ (dotted capital I) is not i on NTFS either
    negative(new Set(["dİr/x.env"]), "dir/x.env");
    // supplementary-plane letters are compared as they are (NTFS does not fold them)
    negative(new Set(["\u{10400}/x.env"]), "\u{10428}/x.env");
  });

  it("Unicode punctuation and symbols delimit a name", () => {
    for (const t of ["„config/ä.env“", "«config/ä.env»", "config/ä.env。", "config/ä.env✅", "config/ä.env🔒", "【config/ä.env】"]) positive(U, t);
  });

  it("non-ASCII names hold through JSON escaping, including \\u escapes, in the invariant", () => {
    for (let depth = 0; depth <= DECODE_LAYERS; depth++) {
      expect(() => assertTextConfidential(nest("config\\ä.env", depth), U, new Set()), `@${depth}`).toThrow(/MR-F/);
      expect(() => assertTextConfidential(nest("config\\ä.env.ts", depth), U, new Set()), `@${depth}`).not.toThrow();
    }
    expect(() => assertTextConfidential('{"p":"config/\\u00e4.env"}', U, new Set())).toThrow(/MR-F/);
    expect(() => assertTextConfidential('{"p":"config/a\\u0308.env"}', U, new Set())).toThrow(/MR-F/);
  });

  it("canonical spans of a composed cluster cover the whole original cluster", () => {
    const c = canonicalize("Äx", "separator");
    expect(c.text).toBe("äx");
    expect([...c.start]).toEqual([0, 2]);
    expect([...c.end]).toEqual([2, 3]);
    // composition exclusions expand under NFC (U+0958 -> U+0915 U+093C): spans stay correct
    const e = canonicalize("क़́/x", "separator");
    expect(e.text).toBe("क़́/x");
    expect([...e.start]).toEqual([0, 0, 0, 2, 3]);
    expect(redactPaths("क़́ config/ä.env", U, { n: 0 })).toBe("क़́ [withheld path]");
  });

  it("normalization work is bounded on hostile Unicode", () => {
    const shapes = [
      "config/a" + "̈".repeat(500_000) + ".env", // one base, half a million marks
      "क़́".repeat(300_000) + "config/ä.env", // expanding clusters
      ("ä" + "Ä" + "Ä").repeat(200_000),
      "\u{10400}".repeat(300_000) + " config/ä.env",
    ];
    for (const [k, t] of shapes.entries()) expectBounded(`unicode shape ${k}`, t, U, 3000);
  });

  it("fuzz: clean text is never altered and redacted text never matches (Unicode alphabet)", () => {
    const alphabet = ["config", "CONFIG", "/", "\\", "Ä", "ä", "Ä", "ä", "̈", ".env", ".ENV", ".", "_", " ", "x", "é", "ß", "\\n", "Å"];
    let seed = 7;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const m = confidentialMatcher(U);
    for (let k = 0; k < 3000; k++) {
      const len = 1 + Math.floor(rnd() * 10);
      let t = "";
      for (let i = 0; i < len; i++) t += alphabet[Math.floor(rnd() * alphabet.length)];
      const redacted = redactPaths(t, U, { n: 0 });
      const rawHit = m.scan(t, "separator", true).length + m.scan(t, "escape", true).length;
      if (rawHit === 0) expect(redacted, t).toBe(t);
      expect(m.scan(redacted, "separator").length + m.scan(redacted, "escape").length, `${t} -> ${redacted}`).toBe(0);
    }
  });
});
