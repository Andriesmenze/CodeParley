// Regression tests for the Codex implementation review of M1.4 (findings F1, F4, F7, F8,
// F9 at unit level; F1 install-dir canonicalization on the real filesystem).

import { describe, it, expect } from "vitest";
import { mkdir, rm, symlink } from "node:fs/promises";
import { join, parse } from "node:path";
import { isolationFlags, readGrantProblem, grantExposes, s1FilesystemMap, UnsafeArgvError } from "../src/agents/codex/argv.js";
import { AUDIT_CAPS, CodexEventStream } from "../src/agents/codex/events.js";
import { resolveInstallDir } from "../src/agents/codex/probe.js";
import { assertBundleConfidential, assertTextConfidential, buildBundle, BundleTooLargeError, redactPaths, containsWithheldPath, type BundleInput } from "../src/policy/review-bundle.js";
import { validateEvidence, type ExportIndex } from "../src/policy/triage.js";
import { loadTemplate, renderTemplate } from "../src/prompts/render.js";
import type { ReviewManifest } from "../src/schemas/capture.js";
import type { ReviewerItem } from "../src/schemas/review.js";
import { linux, mklinkJunction, tempDir, win } from "./helpers/git-fixture.js";

const H = (c: string) => c.repeat(64);

describe("F1: S1 read grants are classified in canonical form only", () => {
  it("refuses every spelling that is or may alias a filesystem root", () => {
    const refused = [
      "L:\\", "L:", "L:\\.", "L:\\Tools\\..", "L:\\Tools\\.\\..", "L:\\Tools\\..\\", "\\\\?\\L:\\", "\\\\?\\L:\\Codex", "\\\\.\\L:\\Codex",
      "\\??\\L:\\", "\\\\?\\UNC\\srv\\share\\x", "L:/", "L:/Codex", "L:\\\\Codex", "L:\\Codex\\", "L:\\Codex.", "L:\\Codex ",
      "\\\\srv\\share", "\\\\srv\\share\\", "\\\\srv", "Codex", "\\Codex", "L:Codex", "L:\\Co:dex", "",
    ];
    for (const p of refused) {
      expect(readGrantProblem(p, "win32"), JSON.stringify(p)).not.toBeNull();
      expect(() => s1FilesystemMap(p, "win32"), JSON.stringify(p)).toThrow();
      expect(() => isolationFlags({ mode: "S1", backend: "mxc", installDir: p, webSearchDisabledValue: "disabled" }), JSON.stringify(p)).toThrow(UnsafeArgvError);
    }
  });
  it("accepts canonical non-root directories", () => {
    for (const p of ["L:\\Tools\\Codex", "C:\\Users\\u\\AppData\\Local\\Programs\\OpenAI\\Codex", "\\\\srv\\share\\Codex"]) expect(readGrantProblem(p, "win32"), p).toBeNull();
  });
  it("a grant may not contain the user profile, the run store or the repository", () => {
    const protectedPaths = ["C:\\Users\\u", "C:\\Users\\u\\AppData\\Local\\CodeParley", "D:\\src\\repo"];
    expect(grantExposes("C:\\Users", protectedPaths, "win32")).toBe("C:\\Users\\u");
    expect(grantExposes("c:\\users\\U", protectedPaths, "win32")).toBe("C:\\Users\\u");
    expect(grantExposes("D:\\src", protectedPaths, "win32")).toBe("D:\\src\\repo");
    expect(grantExposes("C:\\Users\\u\\AppData\\Local\\Programs\\OpenAI\\Codex", protectedPaths, "win32")).toBeNull();
    expect(grantExposes("D:\\src\\repo-other", protectedPaths, "win32")).toBeNull();
  });
  it("POSIX (Linux bwrap) grants: every spelling of the root or a relative path is refused; containment is exact", () => {
    for (const p of ["/", "", "relative/codex", "/opt/codex/", "/opt//codex", "/opt/./codex", "/opt/../", "/opt/codex/..", "/opt/co'dex", "/opt/co\ndex", "C:\\Codex"]) {
      expect(readGrantProblem(p, "posix"), JSON.stringify(p)).not.toBeNull();
      expect(() => isolationFlags({ mode: "S1", backend: "bwrap", installDir: p, webSearchDisabledValue: "disabled" }), JSON.stringify(p)).toThrow(UnsafeArgvError);
    }
    expect(readGrantProblem("/home/u/.local/opt/codex/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl", "posix")).toBeNull();
    const protectedPaths = ["/home/u", "/home/u/.local/state/code-parley", "/srv/repo", "/home/u/.codex"];
    expect(grantExposes("/home", protectedPaths, "posix")).toBe("/home/u");
    expect(grantExposes("/home/u/.local", protectedPaths, "posix")).toBe("/home/u/.local/state/code-parley");
    expect(grantExposes("/srv", protectedPaths, "posix")).toBe("/srv/repo");
    expect(grantExposes("/HOME", protectedPaths, "posix")).toBeNull(); // another directory on Linux
    expect(grantExposes("/srv/repo-other", protectedPaths, "posix")).toBeNull();
  });
  it("the Linux backend pins bubblewrap and never emits the Windows backend flag", () => {
    const flags = isolationFlags({ mode: "S1", backend: "bwrap", installDir: "/opt/codex", webSearchDisabledValue: "disabled" });
    expect(flags).toContain("features.use_legacy_landlock=false");
    expect(flags.join(" ")).not.toMatch(/windows\.sandbox/);
    expect(flags.join(" ")).toContain(`'/opt/codex'="read"`);
    const winFlags = isolationFlags({ mode: "S1", backend: "mxc", installDir: "C:\\Codex", webSearchDisabledValue: "disabled" });
    expect(winFlags).toContain('windows.sandbox="mxc"');
    expect(winFlags.join(" ")).not.toMatch(/use_legacy_landlock/);
  });
  it.skipIf(!win)("the probe canonicalizes the install directory with the OS before classifying it", async () => {
    const base = await tempDir("arl-installdir-");
    const drive = parse(base).root; // e.g. C:\
    // A path that spells a drive root through `..`.
    await expect(resolveInstallDir(`${drive}Windows\\..\\bin\\codex.exe`)).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    // A junction whose target is the drive root: <junction>\bin\codex.exe → install dir = drive root.
    const j = join(base, "rootlink");
    if (mklinkJunction(j, drive)) {
      await expect(resolveInstallDir(join(j, "bin", "codex.exe"))).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    }
    // A normal install directory resolves to its canonical spelling.
    await mkdir(join(base, "Codex", "bin"), { recursive: true });
    const ok = await resolveInstallDir(join(base, "Codex", ".", "bin", "codex.exe"));
    expect(ok.toLowerCase().endsWith("\\codex")).toBe(true);
    expect(readGrantProblem(ok)).toBeNull();
    await rm(base, { recursive: true, force: true }).catch(() => undefined);
  });
  it.skipIf(!linux)("the probe canonicalizes the install directory with the OS before classifying it (Linux)", async () => {
    const base = await tempDir("arl-installdir-");
    // A path that spells the root through `..`.
    await expect(resolveInstallDir("/usr/../bin/codex")).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    // A symbolic link to the root: <link>/bin/codex → install dir = /.
    const l = join(base, "rootlink");
    await symlink("/", l);
    await expect(resolveInstallDir(join(l, "bin", "codex"))).rejects.toMatchObject({ code: "CODEX_ISOLATION_UNAVAILABLE" });
    // A linked install directory resolves to its real path; the grant is that path, not the link.
    await mkdir(join(base, "real", "codex", "bin"), { recursive: true });
    await symlink(join(base, "real", "codex"), join(base, "codex-link"));
    const ok = await resolveInstallDir(join(base, "codex-link", ".", "bin", "codex"));
    expect(ok).toBe(join(base, "real", "codex"));
    expect(readGrantProblem(ok, "posix")).toBeNull();
    await rm(base, { recursive: true, force: true }).catch(() => undefined);
  });
});

describe("F4: withheld path tokens in any model-facing spelling", () => {
  const w = new Set(["config/db.env", ".env", "secrets/id_rsa"]);
  const hostile = [
    "Investigate **config/db.env** now",
    "see `config/db.env`",
    'path: "config/db.env".',
    "(config/db.env)",
    "config/db.env, then",
    "config\\db.env:",
    "tree/config/db.env",
    "./config/db.env",
    "CONFIG/DB.ENV",
    "_config/db.env_",
    "[x](config/db.env)",
    "**.env**",
    "secrets\\id_rsa!",
    "config\\/db.env",
  ];
  it("redaction removes every hostile occurrence and the invariant then passes", () => {
    for (const t of hostile) {
      const r = redactPaths(t, w, { n: 0 });
      expect(r, t).toContain("[withheld path]");
      expect(() => assertTextConfidential(r, w, new Set()), r).not.toThrow();
      expect(() => assertTextConfidential(t, w, new Set()), t).toThrow(/MR-F/);
    }
  });
  it("detects JSON-escaped forms (doubled backslashes), keys and hashes", () => {
    const rendered = JSON.stringify({ note: "look at config\\db.env and secrets\\id_rsa" }, null, 2);
    expect(rendered).toContain("config\\\\db.env");
    expect(() => assertTextConfidential(rendered, w, new Set())).toThrow(/MR-F/);
    expect(() => assertBundleConfidential({ deep: [{ k: "**config/db.env**" }] }, w, new Set())).toThrow(/MR-F/);
    expect(() => assertBundleConfidential({ ["config/db.env"]: 1 }, w, new Set())).toThrow(/MR-F/);
    expect(() => assertTextConfidential(`hash ${H("e").toUpperCase()}`, new Set(), new Set([H("e")]))).toThrow(/hash/);
  });
  it("does not match different names that merely contain a withheld token", () => {
    for (const t of ["process.env.HOME", "load .env.local", "config/db.env.ts", "config/db.envx", "myconfig/db.env-old", "x.env"]) {
      expect(containsWithheldPath(t, w), t).toBe(false);
    }
  });
});

describe("F7: evidence is validated against the version it names", () => {
  const idx: ExportIndex = {
    current: new Map([["src/a.js", { path: "src/a.js", lines: 3 }]]),
    base: new Map([
      ["src/a.js", { path: "src/a.js", lines: 50 }],
      ["src/gone.js", { path: "src/gone.js", lines: 20 }],
    ]),
    withheld: new Set(),
  };
  const ev = (path: string, s: number, e: number) => validateEvidence({ kind: "code_reference", detail: "", path, start_line: s, end_line: e }, idx);
  it("a longer base never validates an out-of-range current reference", () => {
    expect(ev("src/a.js", 40, 41)).toMatchObject({ version: "current", validation: "line_out_of_range", in_scope: false });
    expect(ev("tree/src/a.js", 40, 41)).toMatchObject({ version: "current", validation: "line_out_of_range" });
    expect(ev("review/head/src/a.js", 40, 41)).toMatchObject({ version: "current", validation: "line_out_of_range" });
  });
  it("explicit base references are validated against the base only", () => {
    expect(ev("review/base/src/a.js", 40, 41)).toMatchObject({ version: "base", validation: "valid", in_scope: true });
    expect(ev("review/base/src/a.js", 51, 52)).toMatchObject({ version: "base", validation: "line_out_of_range" });
    expect(ev("src/a.js", 2, 3)).toMatchObject({ version: "current", validation: "valid" });
    expect(ev("review/base/src/missing.js", 1, 1)).toMatchObject({ version: "base", validation: "path_not_in_export" });
  });
  it("a bare path to a deleted file is a base reference; a tree/ path to it is not in the export", () => {
    expect(ev("src/gone.js", 19, 20)).toMatchObject({ version: "base", validation: "valid" });
    expect(ev("tree/src/gone.js", 1, 1)).toMatchObject({ version: "current", validation: "path_not_in_export" });
  });
});

describe("F8: every retained audit structure is bounded", () => {
  it("caps item-type names, remembered ids, retained violations and id length; counts stay exact or over-count", () => {
    const s = new CodexEventStream({ maxStoredBytes: 1000 });
    for (let i = 0; i < 5000; i++) s.push(JSON.stringify({ type: "item.completed", item: { id: `i${i}`, type: `type-${i}-${"t".repeat(100)}` } }));
    for (let i = 0; i < 1500; i++) s.push(JSON.stringify({ type: "item.completed", item: { id: `f${i}-${"x".repeat(5000)}`, type: "file_change" } }));
    s.push(JSON.stringify({ type: "item.started", item: { type: "web_search" } })); // anonymous, never completed
    const a = s.audit();
    expect(Object.keys(a.item_types).length).toBeLessThanOrEqual(AUDIT_CAPS.itemTypes + 1);
    expect(a.item_types["other"]).toBeGreaterThan(0);
    expect(Object.keys(a.item_types).every((k) => k.length <= AUDIT_CAPS.itemTypeChars)).toBe(true);
    expect(a.file_changes).toBe(1500);
    expect(a.isolation_violations.length).toBeLessThanOrEqual(AUDIT_CAPS.violationItems);
    expect(a.web_searches).toBe(1); // an id-less violation is never missed
    expect(a.audit_truncated).toBe(true);
    const internal = s as unknown as { seenCompletedCommandIds: Set<string> };
    expect(internal.seenCompletedCommandIds.size).toBeLessThanOrEqual(AUDIT_CAPS.trackedIds);
    expect([...internal.seenCompletedCommandIds].every((k) => k.length <= AUDIT_CAPS.idChars + 32)).toBe(true);
  });
  it("past the remembered-id cap, command completions keep counting", () => {
    const s = new CodexEventStream({ maxStoredBytes: 1000 });
    for (let i = 0; i < AUDIT_CAPS.trackedIds + 50; i++) s.push(JSON.stringify({ type: "item.completed", item: { id: `c${i}`, type: "command_execution", command: "x" } }));
    expect(s.audit().commands_run).toBe(AUDIT_CAPS.trackedIds + 50);
    expect(s.audit().audit_truncated).toBe(true);
  });
});

function item(id: string, over: Partial<ReviewerItem> = {}): ReviewerItem {
  return {
    id, item_kind: "finding", review_id: "r1", round: 1, source_id: H("a"), review_input_id: H("b"), title: "t", claim_type: "defect", severity: "high", category: "correctness",
    impacts: ["correctness"], consequence: "c", confidence: "high", evidence: [], investigation: "", recommended_change: "", triage: "established_defect", basis: "reviewer_evidence",
    policy_notes: [], status: "open", related_prior_id: null, supersedes: [], superseded_by: null, assessments: [], created_at: "2026-10-04T00:00:00Z", ...over,
  };
}

const change = (path: string) => ({ path, status: "modified" as const, class: "permitted" as const, binary: false, eol: null, transformation_unsupported: false, change_uncertain: false, index_flag_hidden: false, committed: false, uncommitted: true, base_in_export: true, head_in_export: true, diff: "included" as const });

function bigInput(over: Partial<BundleInput> = {}): BundleInput {
  const m: ReviewManifest = {
    schema: "arl.review-manifest.v1", capture_id: "cap", target: { kind: "uncommitted", ref: null }, base: { kind: "commit", commit: "a".repeat(40), baseline_capture_id: null },
    head: { commit: "a".repeat(40), branch: "main" }, object_format: "sha1", source_id: H("5"), rules_digest: H("6"), limits: { max_file_bytes: 1, max_export_bytes: 1, max_diff_bytes: 1 },
    files: [], changes: Array.from({ length: 900 }, (_, k) => change(`src/f-${k}-${"y".repeat(60)}.js`)), review_files: { diff_patch: { size: 1, sha256: H("8") }, base: [], head: [] },
    exclusions: { confidential: { count: 0, changed_count: 0 }, repository_context: { count: 0 }, size_skipped: Array.from({ length: 3000 }, (_, k) => ({ path: `big/${k}-${"z".repeat(40)}.bin`, size: 1, changed: false })), context_reduced: [], link_skipped: [], path_unsupported: [], submodules: [] },
    eol_conversion_equivalent: { count: 0, paths: [] }, limitations: [], stable: true, manifest_digest: H("9"),
  };
  return {
    nonce: "n0nce", envelope: { goal: "Fix add()" }, focus: null, depth: "standard", manifest: m, diffText: "d".repeat(200_000), withheldPaths: new Set(), withheldHashes: new Set(),
    checks: { evidence: [], floor: { configured: false, satisfied_for_reviewed_source: false, missing: [], stale: [], failed: [], removed: [], unapproved: [] }, engine_conditions: [] },
    openItems: Array.from({ length: 50 }, (_, k) => item(`i${k}`, { title: "t".repeat(800) })), testsRemoved: null, instructionFiles: [{ path: "AGENTS.md", text: "a".repeat(20_000) }], ...over,
  };
}

describe("F9: the bundle cap is an invariant on the final rendered prompt", () => {
  it("every section competes for the cap, measured on the rendered prompt", async () => {
    const t = await loadTemplate();
    const measure = (s: Record<string, string>) => renderTemplate(t, s).length;
    for (const cap of [400_000, 60_000, 30_000]) {
      const b = buildBundle(bigInput({ limits: { maxBundleChars: cap } }), measure);
      expect(renderTemplate(t, b.sections).length, String(cap)).toBeLessThanOrEqual(cap);
    }
    const small = buildBundle(bigInput({ limits: { maxBundleChars: 30_000 } }), measure);
    expect(small.limitations.map((l) => l.code)).toEqual(expect.arrayContaining(["bundle_diff_truncated", "bundle_changes_truncated", "prior_items_truncated", "bundle_instructions_omitted"]));
    expect(small.prior.length + small.notPresented.length).toBe(50);
  });
  it("fails clearly when the required metadata alone does not fit", async () => {
    const t = await loadTemplate();
    const measure = (s: Record<string, string>) => renderTemplate(t, s).length;
    expect(() => buildBundle(bigInput({ envelope: { goal: "g".repeat(2000), background: "b".repeat(8000) }, limits: { maxBundleChars: 9_000 } }), measure)).toThrow(BundleTooLargeError);
  });
});
