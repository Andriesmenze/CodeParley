import { describe, it, expect } from "vitest";
import { uuidv7, isUuid, shortId } from "../src/common/ids.js";
import { sha256OfString, sha256OfCanonicalJson, canonicalize, shortHash } from "../src/common/hash.js";

describe("uuidv7", () => {
  it("produces a valid, version-7 UUID", () => {
    const id = uuidv7();
    expect(isUuid(id)).toBe(true);
    expect(id[14]).toBe("7"); // version nibble
    expect(["8", "9", "a", "b"]).toContain(id[19]); // variant
  });

  it("is time-ordered: later timestamps sort after earlier ones", () => {
    const a = uuidv7(1_000_000);
    const b = uuidv7(2_000_000);
    expect(a < b).toBe(true);
  });

  it("shortId is the first 8 chars", () => {
    const id = uuidv7();
    expect(shortId(id)).toBe(id.slice(0, 8));
  });
});

describe("hash", () => {
  it("sha256 is stable and 64 hex chars", () => {
    const h = sha256OfString("hello");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).toBe(sha256OfString("hello"));
  });

  it("canonical JSON hash is key-order independent", () => {
    const a = sha256OfCanonicalJson({ b: 1, a: 2, nested: { y: 1, x: 2 } });
    const b = sha256OfCanonicalJson({ a: 2, nested: { x: 2, y: 1 }, b: 1 });
    expect(a).toBe(b);
  });

  it("canonicalize sorts keys deeply", () => {
    expect(canonicalize({ b: 1, a: [{ d: 1, c: 2 }] })).toBe('{"a":[{"c":2,"d":1}],"b":1}');
  });

  it("shortHash is the first 12 chars", () => {
    const h = sha256OfString("x");
    expect(shortHash(h)).toBe(h.slice(0, 12));
  });
});
