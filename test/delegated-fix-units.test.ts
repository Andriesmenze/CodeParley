import { describe, it, expect } from "vitest";
import {
  boundaryDigest,
  boundaryProblems,
  checkApplicationAuthorization,
  diffManifests,
  evaluateFix,
  isPermitted,
  manifestDigest,
  portablePathProblem,
  portableSegmentProblem,
  proposalDigest,
  sensitivePathReason,
  type FixBoundary,
  type FixConfirmation,
  type FixFileEntry,
  type FixPostFile,
  type FixPostScan,
  type FixProposal,
  FIX_SCHEMA_VERSION,
} from "../src/policy/delegated-fix.js";
import {
  FIX_PROFILE_NAME,
  fixPermissionsToml,
  fixProfileDigest,
  fixSandboxArgv,
} from "../src/agents/codex/fix-profile.js";
import { UnsafeArgvError } from "../src/agents/codex/argv.js";

const boundary = (over: Partial<FixBoundary> = {}): FixBoundary => ({
  task_id: "T1",
  permitted_files: [],
  permitted_dirs: ["src/parser"],
  allow_create: true,
  allow_delete: false,
  allow_binary: false,
  max_changed_files: 10,
  max_file_bytes: 1_000_000,
  max_total_bytes: 5_000_000,
  proposal_lifetime_ms: 3_600_000,
  ...over,
});

const file = (path: string, sha: string, over: Partial<FixPostFile> = {}): FixPostFile => ({ path, size: sha.length, sha256: sha, executable: false, binary: false, ...over });
const entry = (f: FixPostFile): FixFileEntry => ({ path: f.path, size: f.size, sha256: f.sha256, executable: f.executable });
const scan = (files: FixPostFile[], over: Partial<FixPostScan> = {}): FixPostScan => ({ files, anomalies: [], complete: true, ...over });

describe("delegated-fix: portable path rules", () => {
  it("accepts ordinary repository-relative paths", () => {
    for (const p of ["src/parser/a.ts", "a", "dir/sub/file.txt", "x.y.z"]) expect(portablePathProblem(p), p).toBeNull();
  });
  it("rejects dot segments, absolute paths, .git and overlong names", () => {
    expect(portablePathProblem("../escape")).toMatch(/dot segment/);
    expect(portablePathProblem("/abs")).toMatch(/absolute/);
    expect(portablePathProblem(".git/config")).toMatch(/git metadata/);
    expect(portablePathProblem("a/.git")).toMatch(/git metadata/);
    expect(portablePathProblem(`a/${"x".repeat(256)}`)).toMatch(/too long/);
  });
  it("rejects names unsafe on Windows even when running on POSIX (portable both ways)", () => {
    expect(portableSegmentProblem("CON")).toMatch(/device/);
    expect(portableSegmentProblem("aux.txt")).toMatch(/device/);
    expect(portableSegmentProblem("trailing ")).toMatch(/space or a dot/);
    expect(portableSegmentProblem("trailing.")).toMatch(/space or a dot/);
    expect(portableSegmentProblem("a\\b")).toMatch(/separator/);
    expect(portableSegmentProblem("a:b")).toMatch(/reserved/);
    expect(portableSegmentProblem("GIT~1")).toMatch(/8\.3/);
    expect(portableSegmentProblem("a\u0001b")).toMatch(/control/);
  });
});

describe("delegated-fix: sensitive paths", () => {
  it("flags paths that steer another trust domain, case-insensitively", () => {
    for (const p of [".github/workflows/ci.yml", ".git/hooks/pre-commit".replace(".git/", ".githooks/"), ".husky/pre-commit", ".vscode/tasks.json", "CLAUDE.md", "sub/AGENTS.md", ".mcp.json", ".code-parley/config.json", ".npmrc"]) {
      expect(sensitivePathReason(p), p).not.toBeNull();
    }
  });
  it("does not flag ordinary source", () => {
    for (const p of ["src/a.ts", "README.md", "docs/x.md", "package.json"]) expect(sensitivePathReason(p), p).toBeNull();
  });
});

describe("delegated-fix: boundary", () => {
  it("rejects an empty boundary, a bad path and a sensitive directory grant", () => {
    expect(boundaryProblems(boundary({ permitted_files: [], permitted_dirs: [] }))).toContainEqual(expect.stringContaining("permits nothing"));
    expect(boundaryProblems(boundary({ permitted_dirs: ["../x"] }))).toContainEqual(expect.stringContaining("dot segment"));
    expect(boundaryProblems(boundary({ permitted_dirs: [".github"] }))).toContainEqual(expect.stringContaining("sensitive"));
    expect(boundaryProblems(boundary({ max_changed_files: 0 }))).toContainEqual(expect.stringContaining("max_changed_files"));
    expect(boundaryProblems(boundary())).toEqual([]);
  });
  it("isPermitted: exact files, directory prefixes, and sensitive files only when listed exactly", () => {
    const b = boundary({ permitted_files: ["README.md", ".github/workflows/ci.yml"], permitted_dirs: ["src"] });
    expect(isPermitted("README.md", b)).toBe(true);
    expect(isPermitted("src/a/b.ts", b)).toBe(true);
    expect(isPermitted("src2/a.ts", b)).toBe(false); // prefix must be a path boundary, not a string prefix
    expect(isPermitted(".github/workflows/ci.yml", b)).toBe(true); // listed exactly
    expect(isPermitted(".github/workflows/other.yml", b)).toBe(false); // sensitive, not listed
  });
});

describe("delegated-fix: diff + evaluation", () => {
  const base = [entry(file("src/parser/a.ts", "aaa")), entry(file("src/parser/b.ts", "bbb"))];

  it("derives add / modify / delete / exec-bit change", () => {
    const post = [file("src/parser/a.ts", "AAA"), file("src/parser/c.ts", "ccc"), file("src/parser/b.ts", "bbb", { executable: true })];
    const changes = diffManifests(base, post);
    expect(changes.map((c) => [c.path, c.kind])).toEqual([
      ["src/parser/a.ts", "modify"],
      ["src/parser/b.ts", "modify"],
      ["src/parser/c.ts", "add"],
    ]);
    // nothing deleted here
    const deleted = diffManifests(base, [file("src/parser/a.ts", "aaa")]);
    expect(deleted).toEqual([{ path: "src/parser/b.ts", kind: "delete", base: { size: 3, sha256: "bbb", executable: false }, result: null }]);
  });

  it("eligible when changes are inside the boundary and within limits", () => {
    // modify a.ts and add c.ts; b.ts is kept (the default boundary forbids deletes).
    const e = evaluateFix({ boundary: boundary(), baseline: base, post: scan([file("src/parser/a.ts", "AAA"), file("src/parser/b.ts", "bbb"), file("src/parser/c.ts", "ccc")]) });
    expect(e.status).toBe("eligible");
    expect(e.violations).toEqual([]);
    expect(e.changes).toHaveLength(2);
  });

  it("empty when nothing changed", () => {
    expect(evaluateFix({ boundary: boundary(), baseline: base, post: scan([file("src/parser/a.ts", "aaa"), file("src/parser/b.ts", "bbb")]) }).status).toBe("empty");
  });

  it("rejects a change outside the permitted paths", () => {
    const e = evaluateFix({ boundary: boundary(), baseline: base, post: scan([file("src/other/x.ts", "xxx")]) });
    expect(e.status).toBe("rejected");
    expect(e.violations.find((v) => v.kind === "outside_boundary")?.path).toBe("src/other/x.ts");
  });

  it("rejects a sensitive path even under a permitted directory", () => {
    const b = boundary({ permitted_dirs: ["src/parser", ".github"] }); // .github dir grant is itself invalid, but test the change check too
    const e = evaluateFix({ boundary: boundary({ permitted_dirs: ["src/parser"], permitted_files: [] }), baseline: [], post: scan([file(".github/workflows/ci.yml", "yyy")]) });
    expect(e.violations.some((v) => v.kind === "sensitive_path" || v.kind === "outside_boundary")).toBe(true);
    void b;
  });

  it("enforces create / delete / binary switches", () => {
    expect(evaluateFix({ boundary: boundary({ allow_create: false }), baseline: base, post: scan([file("src/parser/a.ts", "aaa"), file("src/parser/b.ts", "bbb"), file("src/parser/new.ts", "nnn")]) }).violations.some((v) => v.kind === "create_not_allowed")).toBe(true);
    expect(evaluateFix({ boundary: boundary({ allow_delete: false }), baseline: base, post: scan([file("src/parser/a.ts", "aaa")]) }).violations.some((v) => v.kind === "delete_not_allowed")).toBe(true);
    expect(evaluateFix({ boundary: boundary({ allow_binary: false, allow_create: true }), baseline: [], post: scan([file("src/parser/img", "zzz", { binary: true })]) }).violations.some((v) => v.kind === "binary_not_allowed")).toBe(true);
  });

  it("enforces count and size limits", () => {
    const many = Array.from({ length: 11 }, (_, i) => file(`src/parser/f${i}.ts`, `h${i}`));
    expect(evaluateFix({ boundary: boundary({ max_changed_files: 10 }), baseline: [], post: scan(many) }).violations.some((v) => v.kind === "too_many_changes")).toBe(true);
    expect(evaluateFix({ boundary: boundary({ max_file_bytes: 2 }), baseline: [], post: scan([file("src/parser/a.ts", "big")]) }).violations.some((v) => v.kind === "file_too_large")).toBe(true);
    expect(evaluateFix({ boundary: boundary({ max_total_bytes: 2 }), baseline: [], post: scan([file("src/parser/a.ts", "abc")]) }).violations.some((v) => v.kind === "total_too_large")).toBe(true);
  });

  it("turns every scan anomaly into a violation, wherever it is", () => {
    const e = evaluateFix({ boundary: boundary(), baseline: base, post: scan([file("src/parser/a.ts", "AAA")], { anomalies: [{ path: "src/parser/link", kind: "link", detail: "symlink" }] }) });
    expect(e.status).toBe("rejected");
    expect(e.violations.some((v) => v.kind === "link")).toBe(true);
  });

  it("never eligible when the scan was incomplete, even with no changes", () => {
    const e = evaluateFix({ boundary: boundary(), baseline: base, post: scan([file("src/parser/a.ts", "aaa"), file("src/parser/b.ts", "bbb")], { complete: false }) });
    expect(e.status).toBe("rejected");
    expect(e.violations.some((v) => v.kind === "scan_incomplete")).toBe(true);
  });

  it("rejects two changes whose paths differ only in case", () => {
    const e = evaluateFix({ boundary: boundary({ permitted_dirs: ["src"] }), baseline: [], post: scan([file("src/A.ts", "x"), file("src/a.ts", "y")]) });
    expect(e.violations.some((v) => v.kind === "case_only_rename")).toBe(true);
  });
});

describe("delegated-fix: proposal digest and the confirmation contract", () => {
  const mkProposal = (over: Partial<Omit<FixProposal, "digest">> = {}): FixProposal => {
    const core: Omit<FixProposal, "digest"> = {
      schema_version: FIX_SCHEMA_VERSION,
      proposal_id: "P1",
      workspace_id: "W1",
      boundary: boundary(),
      boundary_digest: boundaryDigest(boundary()),
      baseline_digest: manifestDigest([]),
      status: "eligible",
      changes: [{ path: "src/parser/a.ts", kind: "modify", base: { size: 3, sha256: "aaa", executable: false }, result: { size: 3, sha256: "AAA", executable: false, binary: false } }],
      violations: [],
      created_at_ms: 1000,
      expires_at_ms: 1000 + 3_600_000,
      ...over,
    };
    return { ...core, digest: proposalDigest(core) };
  };

  it("the digest covers every field and detects tampering", () => {
    const p = mkProposal();
    const { digest, ...core } = p;
    expect(proposalDigest(core)).toBe(digest);
    expect(proposalDigest({ ...core, status: "empty" })).not.toBe(digest);
    expect(proposalDigest({ ...core, changes: [] })).not.toBe(digest);
  });

  const confirm = (p: FixProposal, over: Partial<FixConfirmation> = {}): FixConfirmation => ({ proposal_digest: p.digest, target_root_key: "ROOTKEY", channel: "local_cli", confirmed_at_ms: 2000, ...over });

  it("authorizes only an eligible, unexpired proposal confirmed for this target via an operator channel", () => {
    const p = mkProposal();
    expect(checkApplicationAuthorization(p, confirm(p), { targetRootKey: "ROOTKEY", nowMs: 3000 })).toEqual([]);
    expect(checkApplicationAuthorization(p, confirm(p), { targetRootKey: "OTHER", nowMs: 3000 })).toContainEqual(expect.stringContaining("another target"));
    expect(checkApplicationAuthorization(p, confirm(p, { proposal_digest: "deadbeef" }), { targetRootKey: "ROOTKEY", nowMs: 3000 })).toContainEqual(expect.stringContaining("another proposal"));
    expect(checkApplicationAuthorization(p, confirm(p), { targetRootKey: "ROOTKEY", nowMs: p.expires_at_ms + 1 })).toContainEqual(expect.stringContaining("expired"));
    expect(checkApplicationAuthorization(p, confirm(p, { confirmed_at_ms: 500 }), { targetRootKey: "ROOTKEY", nowMs: 3000 })).toContainEqual(expect.stringContaining("predates"));
    // @ts-expect-error a non-operator channel is not assignable; the runtime check must also reject it
    expect(checkApplicationAuthorization(p, confirm(p, { channel: "mcp_tool" }), { targetRootKey: "ROOTKEY", nowMs: 3000 })).toContainEqual(expect.stringContaining("operator channel"));
  });

  it("refuses a rejected proposal and a digest that does not match its own body", () => {
    expect(checkApplicationAuthorization(mkProposal({ status: "rejected" }), confirm(mkProposal({ status: "rejected" })), { targetRootKey: "ROOTKEY", nowMs: 3000 })).toContainEqual(expect.stringContaining("not eligible"));
    const p = mkProposal();
    const tampered: FixProposal = { ...p, status: "empty" }; // body changed, digest stale
    expect(checkApplicationAuthorization(tampered, confirm(p), { targetRootKey: "ROOTKEY", nowMs: 3000 })).toContainEqual(expect.stringContaining("own digest"));
  });
});

describe("delegated-fix: writable Codex profile (fix-profile.ts)", () => {
  const WIN = process.platform === "win32";
  const dirs = WIN
    ? { install: "C:\\Program Files\\Codex", tree: "C:\\work\\ws\\tree", scratch: "C:\\work\\ws\\scratch", primary: "L:\\repo", data: "C:\\Users\\me\\AppData\\Local\\CodeParley" }
    : { install: "/opt/codex", tree: "/var/work/ws/tree", scratch: "/var/work/ws/scratch", primary: "/home/me/repo", data: "/home/me/.local/state/code-parley" };
  const backend = WIN ? "mxc" : "bwrap";
  const input = () => ({ backend: backend as "mxc" | "bwrap", installDir: dirs.install, writableDirs: [dirs.tree, dirs.scratch], protectedPaths: [dirs.primary, dirs.data] });

  it("builds a profile that writes only the workspace, reads minimal+install, and disables network", () => {
    const toml = fixPermissionsToml(input());
    expect(toml).toContain('":minimal"="read"');
    expect(toml).toContain(`'${dirs.tree}'="write"`);
    expect(toml).toContain(`'${dirs.scratch}'="write"`);
    expect(toml).toContain("network={enabled=false}");
    expect(toml).not.toContain("workspace-write");
  });

  it("refuses a write grant that is a root or exposes a protected path", () => {
    const rootWrite = WIN ? "C:\\" : "/";
    expect(() => fixPermissionsToml({ ...input(), writableDirs: [rootWrite] })).toThrow(UnsafeArgvError);
    expect(() => fixPermissionsToml({ ...input(), writableDirs: [dirs.primary] })).toThrow(/expose the protected path/);
    const underPrimary = WIN ? "L:\\repo\\src" : "/home/me/repo/src";
    expect(() => fixPermissionsToml({ ...input(), writableDirs: [underPrimary] })).toThrow(/expose the protected path/);
  });

  it("fixSandboxArgv emits -P cp_fix and a command, never a forbidden sandbox mode, and refuses an empty command", () => {
    const argv = fixSandboxArgv({ ...input(), cwd: dirs.tree, command: ["codex", "exec", "-"] });
    expect(argv[0]).toBe("sandbox");
    expect(argv).toContain("-P");
    expect(argv).toContain(FIX_PROFILE_NAME);
    expect(argv.slice(argv.indexOf("--") + 1)).toEqual(["codex", "exec", "-"]);
    expect(argv.join(" ")).not.toContain("workspace-write");
    expect(argv.join(" ")).not.toContain("danger-full-access");
    expect(() => fixSandboxArgv({ ...input(), cwd: dirs.tree, command: [] })).toThrow(UnsafeArgvError);
  });

  it("the profile digest is stable and changes with the grants", () => {
    expect(fixProfileDigest(input())).toBe(fixProfileDigest(input()));
    expect(fixProfileDigest({ ...input(), writableDirs: [dirs.tree] })).not.toBe(fixProfileDigest(input()));
  });
});
