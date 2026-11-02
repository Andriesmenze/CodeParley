import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateGitArgs, GitArgumentError } from "../src/capture/git-args.js";
import { GitQuery } from "../src/capture/git-query.js";
import { parseCatFileBatch, parseCatFileBatchCheck, parseCheckAttr, parseConfigZ, parseLsFilesStage, parseLsTree } from "../src/capture/git-parse.js";
import { emptyTreeOid, gitBlobOid, parseLfsPointer } from "../src/capture/git-object.js";
import { compareEol, eolStatsOf, eolStyleOf, gitAutoTextHeuristic, gitNormalizes, normalizeCrlf, EolStatsAccumulator } from "../src/capture/eol.js";
import { compileGlob, compileGlobs, matchesAny } from "../src/capture/globs.js";
import { computeSourceId, SOURCE_ID_SCHEMA } from "../src/capture/identity.js";
import { sha256OfCanonicalJson } from "../src/common/hash.js";
import { computeReviewInputId, type ReviewInputParts } from "../src/engine/identities.js";
import { buildLimitations, assertNoWithheldLeak, withheldPaths } from "../src/capture/manifest.js";
import { alignSections, parseNameStatusZ, rewritePatch, isolatedDiffEnv, isolatedDiffArgv } from "../src/capture/prepared-diff.js";
import { isValidRefSyntax } from "../src/capture/capture.js";
import { looksLikeShortName, pathProblem } from "../src/capture/enumerate.js";
import { exportPathProblem } from "../src/capture/export-writer.js";
import { windowsSegmentProblem } from "../src/workspace/win-paths.js";
import { parseGitVersion, versionAtLeast } from "../src/capture/repo-support.js";
import type { ChangeEntry, SourceEntry } from "../src/schemas/capture.js";

const OID1 = "a".repeat(40);
const OID256 = "b".repeat(64);

describe("git argument allowlist (plan §9.2, MR-A)", () => {
  const refuse = (sub: string, args: string[]) => expect(() => validateGitArgs(sub, args)).toThrow(GitArgumentError);
  it("refuses every subcommand that converts working-tree content or writes", () => {
    for (const sub of ["status", "diff", "add", "checkout", "hash-object", "update-index", "write-tree", "stash", "fetch", "commit", "gc", "reset", "show", "log", "diff-tree", "diff-files", "diff-index"]) {
      refuse(sub, []);
    }
  });
  it("refuses content-conversion and write flags on allowed subcommands", () => {
    refuse("cat-file", ["--filters"]);
    refuse("cat-file", ["--textconv"]);
    refuse("cat-file", ["--follow-symlinks", "--batch"]);
    refuse("cat-file", ["-p", OID1]);
    refuse("ls-files", ["-m"]);
    refuse("ls-files", ["--modified"]);
    refuse("ls-files", ["--deleted"]);
    refuse("ls-files", ["--eol"]);
    refuse("ls-files", ["--recurse-submodules"]);
    refuse("ls-files", ["--format=%(eolinfo:worktree)"]);
    refuse("config", ["--add", "x.y", "z"]);
    refuse("config", ["--unset", "x.y"]);
    refuse("config", ["x.y", "z"]);
    refuse("config", ["--file", "f", "--get", "x.y"]);
    refuse("rev-parse", ["--upload-pack=evil"]);
    refuse("rev-parse", ["--verify", "--end-of-options", "a:b"]);
    refuse("rev-parse", ["--git-path", "../../x"]);
    refuse("ls-tree", ["HEAD"]); // symbolic names must be resolved first
    refuse("merge-base", ["--fork-point", OID1]);
    refuse("check-attr", ["--source", OID1, "filter"]);
    refuse("symbolic-ref", ["HEAD", "refs/heads/x"]);
  });
  it("accepts exactly the forms capture uses", () => {
    validateGitArgs("version", []);
    validateGitArgs("ls-files", ["-z", "-v", "--stage", "--cached"]);
    validateGitArgs("ls-files", ["-z", "--others", "--ignored", "--exclude-standard"]);
    validateGitArgs("ls-tree", ["-r", "-z", "-l", "--full-tree", OID256]);
    validateGitArgs("check-attr", ["-z", "--stdin", "filter", "working-tree-encoding", "text", "eol", "crlf"]);
    validateGitArgs("cat-file", ["--batch"]);
    validateGitArgs("cat-file", ["--batch-check"]);
    validateGitArgs("rev-parse", ["--verify", "-q", "HEAD^{commit}"]);
    validateGitArgs("rev-parse", ["--verify", "-q", "--end-of-options", "origin/main^{commit}"]);
    validateGitArgs("rev-parse", ["--path-format=absolute", "--git-path", "MERGE_HEAD", "--git-path", "rebase-merge"]);
    validateGitArgs("config", ["-z", "--get-regexp", "^(core\\.(sparsecheckout|worktree)|filter\\..*)$"]);
    validateGitArgs("merge-base", [OID1, OID1]);
    validateGitArgs("symbolic-ref", ["-q", "HEAD"]);
  });
});

describe("GitQuery argv and environment invariants", () => {
  const q = new GitQuery({ gitExe: "git.exe", cwd: "C:\\repo", emptyHooksDir: "C:\\empty hooks" });
  it("hardens every call and reads in-tree attributes from the empty tree except for check-attr", () => {
    q.setAttrSourceTree(emptyTreeOid("sha1"));
    const argv = q.buildArgv("ls-files", ["-z", "--cached"]);
    for (const kv of ["core.fsmonitor=false", "core.untrackedCache=false", "protocol.allow=never", "gc.auto=0", "maintenance.auto=false", "core.hooksPath=C:\\empty hooks"]) {
      expect(argv[argv.indexOf(kv) - 1]).toBe("-c");
    }
    expect(argv[0]).toBe("--no-pager");
    expect(argv).toContain(`--attr-source=${emptyTreeOid("sha1")}`);
    expect(argv.slice(-5)).toEqual(["-C", "C:\\repo", "ls-files", "-z", "--cached"]);
    expect(q.buildArgv("check-attr", ["-z", "--stdin", "filter"]).some((a) => a.startsWith("--attr-source"))).toBe(false);
    expect(() => q.buildArgv("status" as never, [])).toThrow(GitArgumentError);
  });
  it("builds an explicit environment: no inherited GIT_* and env-based neutralization of hostile filter names", () => {
    const saved = { ...process.env };
    process.env["GIT_DIR"] = "C:\\elsewhere";
    process.env["GIT_CONFIG_PARAMETERS"] = "'core.fsmonitor=evil'";
    process.env["GIT_EXTERNAL_DIFF"] = "evil";
    try {
      q.neutralizeFilters(["lfs", "x.clean=evil;y"]);
      const env = q.buildEnv();
      expect(env["GIT_DIR"]).toBeUndefined();
      expect(env["GIT_CONFIG_PARAMETERS"]).toBeUndefined();
      expect(env["GIT_EXTERNAL_DIFF"]).toBeUndefined();
      expect(env).toMatchObject({ GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1", GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" });
      const keys = Object.entries(env).filter(([k]) => k.startsWith("GIT_CONFIG_KEY_")).map(([, v]) => v);
      expect(keys).toEqual(expect.arrayContaining(["filter.lfs.clean", "filter.lfs.process", "filter.x.clean=evil;y.smudge"]));
      // The hostile name is a key, never parsed into a value.
      const idx = Object.entries(env).find(([, v]) => v === "filter.x.clean=evil;y.clean")![0].replace("KEY", "VALUE");
      expect(env[idx]).toBe("");
      expect(env["GIT_CONFIG_COUNT"]).toBe(String(keys.length));
    } finally {
      process.env = saved;
    }
  });
});

describe("git output parsers", () => {
  it("parses ls-files -v --stage including assume-unchanged and skip-worktree tags", () => {
    const out = `H 100644 ${OID1} 0\ta b.txt\0h 100644 ${OID1} 0\tau.txt\0S 100644 ${OID1} 0\tsw.txt\0M 100644 ${OID1} 2\tconflict.txt\0`;
    const e = parseLsFilesStage(out);
    expect(e.map((x) => [x.path, x.assumeUnchanged, x.skipWorktree, x.stage])).toEqual([
      ["a b.txt", false, false, 0],
      ["au.txt", true, false, 0],
      ["sw.txt", false, true, 0],
      ["conflict.txt", false, false, 2],
    ]);
  });
  it("parses ls-tree -l, including gitlinks and partial-clone 'BAD' sizes", () => {
    const out = `100644 blob ${OID1}      12\tf.txt\x00160000 commit ${OID1}       -\tsub\x00100644 blob ${OID1}     BAD\tmissing.txt\x00`;
    expect(parseLsTree(out).map((e) => [e.path, e.type, e.size])).toEqual([
      ["f.txt", "blob", 12],
      ["sub", "commit", null],
      ["missing.txt", "blob", null],
    ]);
  });
  it("parses check-attr, config -z and cat-file batch/batch-check", () => {
    expect(parseCheckAttr("a\0filter\0lfs\0a\0text\0unset\0").get("a")).toEqual({ filter: "lfs", text: "unset" });
    expect(parseConfigZ("core.autocrlf\ntrue\0filter.lfs.clean\ngit-lfs clean\0core.bare\0")).toEqual([
      { key: "core.autocrlf", value: "true" },
      { key: "filter.lfs.clean", value: "git-lfs clean" },
      { key: "core.bare", value: null },
    ]);
    const buf = Buffer.concat([Buffer.from(`${OID1} blob 3\n`), Buffer.from([0, 10, 13]), Buffer.from(`\n${OID256} missing\n`)]);
    const objs = parseCatFileBatch(buf, [OID1, OID256]);
    expect(objs[0]!.content).toEqual(Buffer.from([0, 10, 13]));
    expect(objs[1]!.type).toBeNull();
    expect(parseCatFileBatchCheck(`${OID1} blob 7\n${OID256} missing\n`, [OID1, OID256])).toEqual(new Map([[OID1, 7], [OID256, null]]));
  });
});

describe("git object identities (no hard-coded ids)", () => {
  it("derives the empty tree id for both object formats", () => {
    expect(emptyTreeOid("sha1")).toBe("4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    expect(emptyTreeOid("sha256")).toBe("6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321");
  });
  it("computes git blob ids", () => {
    expect(gitBlobOid("sha1", Buffer.from("hello\n"))).toBe("ce013625030ba8dba906f756967f9e9ca394464a");
    expect(gitBlobOid("sha256", Buffer.alloc(0))).toBe(createHash("sha256").update("blob 0\0").digest("hex"));
  });
  it("parses LFS pointers strictly", () => {
    const sha = "c".repeat(64);
    expect(parseLfsPointer(Buffer.from(`version https://git-lfs.github.com/spec/v1\noid sha256:${sha}\nsize 42\n`))).toEqual({ sha256: sha, size: 42 });
    expect(parseLfsPointer(Buffer.from("not a pointer"))).toBeNull();
  });
});

describe("line endings (MR-I)", () => {
  it("counts CRLF/LF/lone CR across chunk boundaries", () => {
    const a = new EolStatsAccumulator();
    a.update(Buffer.from("a\r"));
    a.update(Buffer.from("\nb\rc\n"));
    const s = a.finish();
    expect([s.crlf, s.lf, s.loneCr]).toEqual([1, 1, 1]);
    expect(eolStyleOf(s)).toBe("mixed");
  });
  it("compares full contents: eol-only, eol plus substantive, binary", () => {
    expect(compareEol(Buffer.from("a\nb\n"), Buffer.from("a\r\nb\r\n"))).toMatchObject({ eol_change: true, eol_only_change: true, base_style: "lf", current_style: "crlf" });
    expect(compareEol(Buffer.from("a\nb\n"), Buffer.from("a\r\nX\r\n"))).toMatchObject({ eol_change: true, eol_only_change: false });
    expect(compareEol(Buffer.from("a\nb\n"), Buffer.from("a\nX\n"))).toMatchObject({ eol_change: false, eol_only_change: false });
    expect(compareEol(Buffer.from("a\0\n"), Buffer.from("a\0\r\n"))).toBeNull();
    expect(normalizeCrlf(Buffer.from("x\r\ny\rz\r\n")).toString()).toBe("x\ny\rz\n");
  });
  it("decides git normalization from attributes and core.autocrlf", () => {
    const text = eolStatsOf(Buffer.from("hello\r\nworld\r\n"));
    const unspecified = { text: "unspecified", eol: "unspecified", crlf: "unspecified" };
    expect(gitNormalizes(unspecified, "false", text)).toBe(false);
    expect(gitNormalizes(unspecified, "true", text)).toBe(true);
    expect(gitNormalizes(unspecified, "input", text)).toBe(true);
    expect(gitNormalizes({ ...unspecified, text: "unset" }, "true", text)).toBe(false);
    expect(gitNormalizes({ ...unspecified, text: "set" }, "false", text)).toBe(true);
    expect(gitNormalizes({ ...unspecified, eol: "crlf" }, "false", text)).toBe(true);
    expect(gitNormalizes({ ...unspecified, crlf: "unset" }, "true", text)).toBe(false);
    const binaryish = eolStatsOf(Buffer.from([1, 2, 3, 4, 5, 6, 0x0d, 0x0a]));
    expect(gitAutoTextHeuristic(binaryish)).toBe(false);
    expect(gitNormalizes({ ...unspecified, text: "auto" }, "false", binaryish)).toBe(false);
  });
});

describe("globs (case-insensitive, directory-aware)", () => {
  it("matches the default confidentiality patterns", () => {
    const g = compileGlobs(["**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*"]);
    expect(matchesAny(g, ".env")).toBe(true);
    expect(matchesAny(g, "app/.ENV")).toBe(true);
    expect(matchesAny(g, ".env.local")).toBe(true);
    expect(matchesAny(g, "certs/a/b/server.PEM")).toBe(true);
    expect(matchesAny(g, ".ssh/id_rsa.pub")).toBe(true);
    expect(matchesAny(g, "prod.env")).toBe(false); // not by this subset; the shipped defaults add **/*.env (default-exclusions.test.ts)
    expect(matchesAny(g, "src/env.ts")).toBe(false);
  });
  it("supports basename patterns at any depth, directory matches, classes and braces", () => {
    expect(compileGlob("*.key").test("a/b/c.key")).toBe(true);
    expect(compileGlob("**/secrets").test("x/secrets/inner/f.txt")).toBe(true);
    expect(compileGlob("docs/**").test("docs/a/b.md")).toBe(true);
    expect(compileGlob("docs/**").test("other/docs/a.md")).toBe(false);
    expect(compileGlob("/root-only.txt").test("sub/root-only.txt")).toBe(false);
    expect(compileGlob("f[0-9].txt").test("f7.txt")).toBe(true);
    expect(compileGlob("*.{pem,key}").test("x/y.key")).toBe(true);
    expect(compileGlob("a?c").test("a/c")).toBe(false);
  });
});

describe("identities", () => {
  const e = (path: string, sha: string): SourceEntry => ({
    path, area: "tree", class: "permitted", disposition: "exported", size: 1, sha256: sha, git_oid: null, tracked: true,
    filter: null, working_tree_encoding: null, git_eol_normalized: false,
  });
  it("source_id is order-independent and content-bound", () => {
    const a = e("a", "1".repeat(64));
    const b = e("b", "2".repeat(64));
    expect(computeSourceId([a, b])).toBe(computeSourceId([b, a]));
    expect(computeSourceId([a, { ...b, sha256: "3".repeat(64) }])).not.toBe(computeSourceId([a, b]));
    // Dispositions (review-input properties) do not affect source_id.
    expect(computeSourceId([{ ...a, disposition: "context_reduced" } as SourceEntry, b])).toBe(computeSourceId([a, b]));
  });
  it("source_id orders entries of one path by area in byte order (context before tree), whatever the input order or locale", () => {
    const t = e("a", "1".repeat(64));
    const c: SourceEntry = { ...t, area: "context", sha256: "2".repeat(64) };
    const row = (x: SourceEntry) => [x.path, x.area, x.class, x.size, x.sha256];
    const expected = sha256OfCanonicalJson({ schema: SOURCE_ID_SCHEMA, entries: [row(c), row(t)] });
    expect(computeSourceId([t, c])).toBe(expected);
    expect(computeSourceId([c, t])).toBe(expected);
  });
  it("review_input_id binds every part; evidence order does not matter", () => {
    const parts: ReviewInputParts = {
      source_id: "1".repeat(64), target: { kind: "uncommitted", ref: null }, base_id: OID1, export_manifest_digest: "2".repeat(64),
      check_execution_ids: ["x", "y"], focus: null, depth: "standard", prompt_template: { id: "codex-reviewer", version: "1" },
      output_schema_version: "1", policy_version: "1", codex: { version: "0.160.0", model: null, reasoning_effort: null },
      isolation: { mode: "S1", backend: "mxc" },
    };
    const id = computeReviewInputId(parts);
    expect(computeReviewInputId({ ...parts, check_execution_ids: ["y", "x"] })).toBe(id);
    for (const changed of [
      { ...parts, source_id: "9".repeat(64) },
      { ...parts, export_manifest_digest: "9".repeat(64) },
      { ...parts, base_id: null },
      { ...parts, check_execution_ids: ["x"] },
      { ...parts, focus: "auth" },
      { ...parts, isolation: { mode: "S2" } },
    ]) expect(computeReviewInputId(changed)).not.toBe(id);
  });
});

describe("model-facing limitations never name confidential paths (MR-F)", () => {
  const entry = (path: string, cls: SourceEntry["class"], disposition: SourceEntry["disposition"] = "exported"): SourceEntry => ({
    path, area: "tree", class: cls, disposition, size: 1, sha256: "d".repeat(64), git_oid: null, tracked: true,
    filter: null, working_tree_encoding: null, git_eol_normalized: false,
  });
  const change = (path: string, confidential: boolean, extra: Partial<ChangeEntry> = {}): ChangeEntry => ({
    path, status: "modified", confidential, class: confidential ? "excluded" : "permitted", base: null, current: null, binary: false,
    eol: null, transformation_unsupported: false, change_uncertain: false, index_flag_hidden: false, committed: null, uncommitted: true,
    in_export: { base: false, head: false }, diff: "none", ...extra,
  });
  it("keeps paths locally, counts model-side", () => {
    const entries = [entry("secret.pem", "excluded", "excluded_confidential"), entry("docs/x.md", "permitted", "excluded_repo_context"), entry("a.ts", "permitted")];
    const changes = [change("secret.pem", true, { index_flag_hidden: true }), change("a.ts", false, { index_flag_hidden: true })];
    const l = buildLimitations({
      entries, changes, instability: [{ path: "secret.pem", reason: "x" }], skipWorktreeAbsent: [], baseUnavailable: [],
      exportOverCap: false, inProgress: [], externalGitDir: false, repoPreferenceWarnings: [], diffProblem: null,
    });
    const modelText = JSON.stringify(l.model);
    expect(modelText).not.toContain("secret.pem");
    expect(modelText).not.toContain("docs/x.md");
    expect(JSON.stringify(l.local)).toContain("secret.pem");
    expect(l.model.find((x) => x.code === "index_flag_hidden")).toMatchObject({ paths: ["a.ts"], count: 2 });
    expect(l.model.find((x) => x.code === "excluded_changed_file")).toEqual({ code: "excluded_changed_file", detail: expect.any(String), count: 1 });
    const withheld = withheldPaths(entries, changes);
    expect(() => assertNoWithheldLeak({ nested: [{ p: "secret.pem" }] }, withheld, new Set())).toThrow();
    expect(() => assertNoWithheldLeak({ nested: [{ h: "d".repeat(64) }] }, withheld, new Set(["d".repeat(64)]))).toThrow();
    expect(() => assertNoWithheldLeak(l.model, withheld, new Set())).not.toThrow();
  });
});

describe("prepared diff helpers", () => {
  it("rewrites nonce prefixes and rename lines without touching content", () => {
    const A = "arl0123456789abcdefA/";
    const B = "arl0123456789abcdefB/";
    const patch = [
      `diff --git ${A}base/data/head/x ${B}head/data/head/x`,
      `--- ${A}base/data/head/x`,
      `+++ ${B}head/data/head/x`,
      "rename from base/old.txt",
      "rename to head/new.txt",
      "-a/base/ stays in content",
      "+rename from base/content",
    ].join("\n");
    expect(rewritePatch(patch, A, B).split("\n")).toEqual([
      "diff --git a/data/head/x b/data/head/x",
      "--- a/data/head/x",
      "+++ b/data/head/x",
      "rename from old.txt",
      "rename to new.txt",
      "-a/base/ stays in content",
      "+rename from base/content",
    ]);
  });
  it("parses no-index name-status and builds an isolated environment", () => {
    expect(parseNameStatusZ("M\0head/a.txt\0R080\0base/o.txt\0head/n.txt\0A\0head/x\0")).toEqual([
      { status: "M", path: "a.txt" },
      { status: "R080", path: "n.txt", oldPath: "o.txt" },
      { status: "A", path: "x" },
    ]);
    // Host-native paths: the helper is platform-neutral (git's ceiling is the export root).
    const s = join(tmpdir(), "s");
    const env = isolatedDiffEnv({ reviewDir: join(s, "export", "review"), emptyHomeDir: join(s, "home"), emptyGlobalConfig: join(s, "gitconfig") });
    expect(env).toMatchObject({ GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: join(s, "gitconfig"), GIT_ATTR_NOSYSTEM: "1", HOME: join(s, "home"), GIT_CEILING_DIRECTORIES: join(s, "export") });
    expect(env["USERPROFILE"]).toBeUndefined();
    const argv = isolatedDiffArgv("C:\\h", []);
    expect(argv).toEqual(expect.arrayContaining(["--no-index", "--no-ext-diff", "--no-textconv", "--ignore-cr-at-eol", "-M"]));
  });
});

describe("path and ref validation", () => {
  it("validates base_ref syntax", () => {
    for (const ok of ["main", "origin/main", "HEAD~2", "v1.2.3", "feature/x-y", "HEAD^", "@{u}"]) expect(isValidRefSyntax(ok), ok).toBe(true);
    for (const bad of ["--upload-pack=x", "-x", "a..b", "a:b", "a b", "", "x.lock", ".hidden", "a/.b", "a\\b", "x".repeat(300)]) expect(isValidRefSyntax(bad), bad).toBe(false);
  });
  it.runIf(process.platform === "win32")("flags git paths that cannot be captured on Windows", () => {
    expect(pathProblem("src/a.ts")).toBeNull();
    expect(pathProblem("a:b.txt")).toBe("invalid_git_path"); // drive-like: rejected even earlier
    expect(pathProblem("dir/a:b.txt")).toMatch(/alternate data stream/);
    expect(pathProblem("con.txt")).toMatch(/reserved/);
    expect(pathProblem("dir./x")).toMatch(/space or dot/);
    expect(pathProblem("x/.git/config")).toBe("invalid_git_path");
    expect(pathProblem("GIT~1/config")).toMatch(/8\.3/);
    expect(looksLikeShortName("PROGRA~1")).toBe(true);
    expect(looksLikeShortName("README~1.TXT")).toBe(true);
    expect(looksLikeShortName("notes~draft.md")).toBe(false);
    expect(exportPathProblem("a/b.txt")).toBeNull();
    expect(exportPathProblem("a/AUX/b")).not.toBeNull();
    expect(windowsSegmentProblem("ok name.txt")).toBeNull();
  });
  it.runIf(process.platform === "linux")("flags git paths that cannot be captured on Linux; Windows-only names are ordinary files there", () => {
    expect(pathProblem("src/a.ts")).toBeNull();
    expect(pathProblem("a:b.txt")).toBe("invalid_git_path"); // drive-like: refused on every platform
    expect(pathProblem("x/.git/config")).toBe("invalid_git_path");
    expect(pathProblem("x/.GIT/config")).toBe("invalid_git_path"); // case variants of .git are refused too
    // Legal Linux names that Windows cannot hold:
    expect(pathProblem("dir/a:b.txt")).toBeNull();
    expect(pathProblem("con.txt")).toBeNull();
    expect(pathProblem("dir./x")).toBeNull();
    expect(pathProblem("GIT~1/config")).toBeNull(); // no short names on Linux file systems
    expect(looksLikeShortName("PROGRA~1")).toBe(false);
    // Refused although Linux allows them: ambiguous in reports and in the confidentiality matcher.
    expect(pathProblem("dir/a\\b.txt")).toMatch(/posix_name: backslash/);
    expect(pathProblem("dir/a\nb.txt")).toMatch(/posix_name: control character/);
    expect(exportPathProblem("a/AUX/b")).toBeNull();
    expect(exportPathProblem("a/b\\c")).not.toBeNull();
  });
  it("aligns diff sections with name-status entries by exact header, skipping entries git printed no section for", () => {
    const sec = (a: string, b = a) => `diff --git ${a.startsWith('"') ? a : `a/${a}`} ${b.startsWith('"') ? b : `b/${b}`}\n@@ -1 +1 @@\n-x\n+y\n`;
    const M = (path: string, oldPath?: string) => ({ status: oldPath ? "R090" : "M", path, ...(oldPath ? { oldPath } : {}) });
    // A CR-only change is listed by --name-status but has no section (git 2.43).
    expect(alignSections([sec("x.txt"), sec("z.txt")], [M("x.txt"), M("eol-only.txt"), M("z.txt")])).toEqual([0, 2]);
    // A path that is a prefix of another must not capture the other's section.
    expect(alignSections([sec("a/b")], [M("a"), M("a/b")])).toEqual([1]);
    // Renames compare both sides; quoted paths match their quoted header.
    expect(alignSections([sec("old.txt", "new.txt"), sec('"a/q\\"uote"', '"b/q\\"uote"')], [M("new.txt", "old.txt"), M('q"uote')])).toEqual([0, 1]);
    // A section with no entry cannot be attributed: nothing is mapped.
    expect(alignSections([sec("x.txt"), sec("w.txt")], [M("x.txt")])).toBeNull();
  });
  it("parses git versions", () => {
    const v = parseGitVersion("git version 2.53.0.windows.2\n");
    expect(v).toMatchObject({ major: 2, minor: 53, patch: 0, raw: "2.53.0.windows.2" });
    expect(versionAtLeast(v, { major: 2, minor: 45 })).toBe(true);
    expect(versionAtLeast(parseGitVersion("git version 2.40.1"), { major: 2, minor: 41 })).toBe(false);
  });
});
