// Line endings, binary and large files (plan §9.6, D-30, MR-I). EOL facts come from full
// raw bytes; they are never inferred from a displayed (possibly empty or truncated) patch.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { supported, gitExe, tempDir, initRepo, writeFiles, commitAll, git, harness, capture, sourceIdentity, exportFileList, cleanup, type Harness } from "./helpers/git-fixture.js";

const lf = (lines: string[]) => lines.join("\n") + "\n";
const crlf = (lines: string[]) => lines.join("\r\n") + "\r\n";
const many = (n: number, tag = "line") => Array.from({ length: n }, (_, i) => `${tag} ${i} with some text`);

describe.skipIf(!supported)("line endings, binary and large files", () => {
  let repo: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    repo = await initRepo(join(await tempDir("arl-eol-"), "repo"));
    h = await harness();
    await writeFiles(repo, {
      ".gitattributes": "auto.txt text=auto\nraw.txt -text\nforced.txt text\n",
      "eol-only.txt": lf(["a", "b", "c"]),
      "mixed.txt": lf(["one", "two", "three"]),
      "auto.txt": lf(["x", "y"]),
      "raw.txt": lf(["p", "q"]),
      "forced.txt": lf(["m", "n"]),
      "partial.txt": lf(["k1", "k2", "k3"]),
      "bin.dat": Buffer.from([0x00, 0x0d, 0x0a, 0x41, 0x0a]),
      "big-change.txt": lf(many(400)),
      "huge.txt": lf(many(3000, "huge")),
      "omitted.txt": lf(many(50, "omit")),
    });
    commitAll(repo, "init");
    await writeFiles(repo, {
      "eol-only.txt": crlf(["a", "b", "c"]), // LF -> CRLF only
      "mixed.txt": crlf(["one", "TWO", "three"]), // code edit + LF -> CRLF
      "auto.txt": crlf(["x", "y"]), // text=auto: git's own checkout conversion -> unchanged
      "raw.txt": crlf(["p", "q"]), // -text: git does not normalize -> eol_only_change
      "forced.txt": crlf(["m", "n"]), // text: normalized -> unchanged
      "partial.txt": "k1\r\nk2\nk3\n", // one line converted -> mixed style, eol-only
      "bin.dat": Buffer.from([0x00, 0x0d, 0x0a, 0x42, 0x0d, 0x0a]),
      "big-change.txt": lf(many(400).map((l) => l + " EDITED")), // diff larger than the per-file cap
      "huge.txt": crlf(many(3000, "huge")), // larger than max_file_bytes, EOL flipped
      "omitted.txt": lf(many(50, "omit").map((l) => l + " Z")),
    });
  });
  afterAll(async () => cleanup(repo, h.dataHome));

  it("reports eol_change / eol_only_change from full bytes and treats git-normalized conversions as unchanged", async () => {
    const r = await capture(h, repo, { rules: { max_file_bytes: 50000, max_diff_bytes: 12000 } });
    const c = new Map(r.record.changes.map((x) => [x.path, x]));

    expect(c.get("eol-only.txt")?.eol).toMatchObject({ base_style: "lf", current_style: "crlf", eol_change: true, eol_only_change: true, git_eol_normalized: false });
    expect(c.get("eol-only.txt")?.diff).toBe("none"); // hidden by --ignore-cr-at-eol, reported anyway
    // MR-I acceptance: a code edit plus LF->CRLF reports both.
    expect(c.get("mixed.txt")?.eol).toMatchObject({ eol_change: true, eol_only_change: false });
    expect(c.get("mixed.txt")?.diff).toBe("included");
    expect(c.get("raw.txt")?.eol).toMatchObject({ eol_only_change: true });
    expect(c.get("partial.txt")?.eol).toMatchObject({ base_style: "lf", current_style: "mixed", eol_change: true, eol_only_change: true });

    // Git itself treats these as unmodified (text / text=auto normalization).
    expect(c.has("auto.txt")).toBe(false);
    expect(c.has("forced.txt")).toBe(false);
    expect(r.record.eol_conversion_equivalent).toEqual(expect.arrayContaining(["auto.txt", "forced.txt"]));
    // ...but their raw bytes are exported and bound into source_id.
    expect(readFileSync(join(r.exportDir!, "tree", "auto.txt"), "latin1")).toContain("\r\n");

    // Binary: no EOL facts.
    expect(c.get("bin.dat")).toMatchObject({ binary: true, eol: null });
    // Truncated diff: EOL facts still from full bytes; never "eol only".
    expect(c.get("big-change.txt")?.diff).toBe("truncated");
    expect(c.get("big-change.txt")?.eol).toMatchObject({ eol_change: false, eol_only_change: false });
    // Size-skipped: not exported, EOL never inferred.
    expect(c.get("huge.txt")).toMatchObject({ class: "size_skipped", eol: null, diff: "note" });
    expect(exportFileList(r.exportDir!)).not.toContain("tree/huge.txt");
    expect(r.manifest!.exclusions.size_skipped).toEqual(expect.arrayContaining([expect.objectContaining({ path: "huge.txt", changed: true })]));

    const patch = readFileSync(join(r.exportDir!, "review", "diff.patch"), "utf8");
    expect(patch).toContain("# eol-only.txt: line endings changed only (lf -> crlf).");
    expect(patch).toContain("diff for this file truncated");
    const lims = r.manifest!.limitations.map((l) => l.code);
    expect(lims).toEqual(expect.arrayContaining(["eol_change", "eol_only_change", "size_skipped", "diff_truncated"]));
  });

  it("an omitted diff (total cap) is never classified as eol_only", async () => {
    const r = await capture(h, repo, { rules: { max_file_bytes: 50000, max_diff_bytes: 4096 } });
    const omitted = r.record.changes.filter((x) => x.diff === "omitted");
    expect(omitted.length).toBeGreaterThan(0);
    for (const o of omitted) expect(o.eol?.eol_only_change ?? false).toBe(false);
  });

  it("core.autocrlf=true: CRLF checkouts of LF blobs are unchanged; a real edit is still detected", async () => {
    const r2 = await initRepo(join(await tempDir("arl-autocrlf-"), "repo"));
    await writeFiles(r2, { "a.txt": lf(["1", "2"]), "b.txt": lf(["3", "4"]) });
    commitAll(r2, "init");
    git(r2, ["config", "core.autocrlf", "true"]);
    await writeFiles(r2, { "a.txt": crlf(["1", "2"]), "b.txt": crlf(["3", "FOUR"]) });
    const r = await capture(h, r2);
    expect(r.record.changes.map((x) => x.path)).toEqual(["b.txt"]);
    expect(r.record.changes[0]!.eol).toMatchObject({ git_eol_normalized: true, eol_change: true, eol_only_change: false });
    expect(r.record.eol_conversion_equivalent).toEqual(["a.txt"]);
    // A pure CRLF->LF flip back is a raw change: source_id differs.
    const id1 = (await sourceIdentity(h, r2)).source_id;
    await writeFiles(r2, { "a.txt": lf(["1", "2"]) });
    expect((await sourceIdentity(h, r2)).source_id).not.toBe(id1);
    await cleanup(r2);
  });

  it("large files are size-skipped, named, hashed into source_id and never exported", async () => {
    const r3 = await initRepo(join(await tempDir("arl-large-"), "repo"));
    await writeFiles(r3, { "large.bin": Buffer.alloc(5000, 1), "small.txt": "s\n" });
    commitAll(r3, "init");
    const big = Buffer.alloc(5000, 1);
    big[4000] = 2;
    await writeFiles(r3, { "large.bin": big });
    const r = await capture(h, r3, { rules: { max_file_bytes: 1000 } });
    expect(r.record.changes.find((x) => x.path === "large.bin")).toMatchObject({ class: "size_skipped", status: "modified" });
    expect(r.manifest!.exclusions.size_skipped).toEqual([{ path: "large.bin", size: 5000, changed: true }]);
    expect(exportFileList(r.exportDir!).some((f) => f.includes("large.bin"))).toBe(false);
    const id1 = (await sourceIdentity(h, r3, { max_file_bytes: 1000 })).source_id;
    big[100] = 3;
    await writeFiles(r3, { "large.bin": big });
    expect((await sourceIdentity(h, r3, { max_file_bytes: 1000 })).source_id).not.toBe(id1);
    await cleanup(r3);
  });

  it("the export cap keeps changed files, their directories and context; drops the rest by name", async () => {
    const r4 = await initRepo(join(await tempDir("arl-cap-"), "repo"));
    await writeFiles(r4, {
      "hot/changed.txt": "v1\n",
      "hot/neighbour.txt": "n".repeat(300),
      "cold/far1.txt": "f".repeat(300),
      "cold/far2.txt": "g".repeat(300),
    });
    commitAll(r4, "init");
    await writeFiles(r4, { "hot/changed.txt": "v2\n" });
    const r = await capture(h, r4, { rules: { max_export_bytes: 500 } });
    const files = exportFileList(r.exportDir!);
    expect(files).toEqual(expect.arrayContaining(["tree/hot/changed.txt", "tree/hot/neighbour.txt"]));
    expect(files).not.toContain("tree/cold/far1.txt");
    expect(r.manifest!.exclusions.context_reduced.map((x) => x.path).sort()).toEqual(["cold/far1.txt", "cold/far2.txt"]);
    // The cap is a review-input property; source_id is unaffected by it.
    expect(r.record.source_id).toBe((await sourceIdentity(h, r4, { max_export_bytes: 500 })).source_id);
    await cleanup(r4);
  });
});
