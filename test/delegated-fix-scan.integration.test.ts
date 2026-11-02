import { afterEach, describe, expect, it } from "vitest";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cleanup, linux, mklinkFile, mklinkHard, mklinkJunction, supported, tempDir, win } from "./helpers/git-fixture.js";
import { baselineManifest, captureFixProposal, scanFixTree } from "../src/capture/fix-scan.js";
import {
  createDisposableWorkspace,
  destroyDisposableWorkspace,
  workspaceIdFor,
  workspaceLayout,
} from "../src/workspace/disposable-workspace.js";
import { canonicalizePath } from "../src/workspace/paths.js";
import { isDomainError } from "../src/common/errors.js";
import type { FixBoundary } from "../src/policy/delegated-fix.js";

const boundary = (over: Partial<FixBoundary> = {}): FixBoundary => ({
  task_id: "T1",
  permitted_files: [],
  permitted_dirs: ["src"],
  allow_create: true,
  allow_delete: true,
  allow_binary: false,
  max_changed_files: 50,
  max_file_bytes: 10_000_000,
  max_total_bytes: 50_000_000,
  proposal_lifetime_ms: 3_600_000,
  ...over,
});

const dirs: string[] = [];
async function scratch(): Promise<string> {
  const d = await tempDir("arl-p4-");
  dirs.push(d);
  return d;
}
afterEach(async () => {
  await cleanup(...dirs.splice(0));
});

describe.skipIf(!supported)("delegated-fix scanner (SHARED CONTRACT)", () => {
  it("scans a clean tree into files with sizes and hashes, no anomalies", async () => {
    const tree = join(await scratch(), "tree");
    await mkdir(join(tree, "src", "sub"), { recursive: true });
    await writeFile(join(tree, "src", "a.ts"), "export const a = 1;\n");
    await writeFile(join(tree, "src", "sub", "b.ts"), "export const b = 2;\n");
    const s = await scanFixTree(tree);
    expect(s.complete).toBe(true);
    expect(s.anomalies).toEqual([]);
    expect(s.files.map((f) => f.path)).toEqual(["src/a.ts", "src/sub/b.ts"]);
    expect(s.files[0]!.size).toBe(20);
    expect(s.files[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("captures an eligible proposal from a baseline to a modified tree", async () => {
    const tree = join(await scratch(), "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    await writeFile(join(tree, "src", "a.ts"), "old\n");
    await writeFile(join(tree, "src", "keep.ts"), "keep\n");
    const { files: baseline } = await baselineManifest(tree);
    // the fixer edits a.ts and adds c.ts
    await writeFile(join(tree, "src", "a.ts"), "new content\n");
    await writeFile(join(tree, "src", "c.ts"), "added\n");
    const { proposal, evaluation } = await captureFixProposal({ proposalId: "P1", workspaceId: "W1", treeDir: tree, boundary: boundary(), baseline, nowMs: 1000 });
    expect(proposal.status).toBe("eligible");
    expect(proposal.changes.map((c) => [c.path, c.kind])).toEqual([
      ["src/a.ts", "modify"],
      ["src/c.ts", "add"],
    ]);
    expect(evaluation.violations).toEqual([]);
    expect(proposal.expires_at_ms).toBe(1000 + boundary().proposal_lifetime_ms);
    expect(proposal.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("flags a file shaped like an 8.3 short name as unsafe, without reading it", async () => {
    const tree = join(await scratch(), "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    await writeFile(join(tree, "src", "GIT~1"), "payload");
    const s = await scanFixTree(tree);
    expect(s.files.find((f) => f.path === "src/GIT~1")).toBeUndefined();
    expect(s.anomalies).toContainEqual(expect.objectContaining({ path: "src/GIT~1", kind: "unsafe_name" }));
  });

  it("stops and reports when the entry budget is exceeded (incomplete scan)", async () => {
    const tree = join(await scratch(), "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    for (let i = 0; i < 6; i++) await writeFile(join(tree, "src", `f${i}.ts`), String(i));
    const s = await scanFixTree(tree, { maxEntries: 3, maxDepth: 64, maxFileBytes: 1_000_000 });
    expect(s.complete).toBe(false);
    expect(s.anomalies.some((a) => a.kind === "limit")).toBe(true);
  });

  it("a symbolic link in the tree is an anomaly, never followed", async () => {
    const base = await scratch();
    const tree = join(base, "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    const canary = join(base, "canary.txt");
    await writeFile(canary, "OUTSIDE");
    if (!mklinkFile(join(tree, "src", "link.txt"), canary)) return; // symlink creation unavailable: skip
    const s = await scanFixTree(tree);
    expect(s.files.find((f) => f.path === "src/link.txt")).toBeUndefined();
    expect(s.anomalies).toContainEqual(expect.objectContaining({ path: "src/link.txt", kind: "link" }));
  });

  it("a hard link (nlink>1) is an anomaly, never captured as content", async () => {
    const base = await scratch();
    const tree = join(base, "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    const target = join(base, "target.txt");
    await writeFile(target, "SHARED");
    if (!mklinkHard(join(tree, "src", "hard.txt"), target)) return;
    const s = await scanFixTree(tree);
    expect(s.files.find((f) => f.path === "src/hard.txt")).toBeUndefined();
    expect(s.anomalies).toContainEqual(expect.objectContaining({ path: "src/hard.txt", kind: "hard_link" }));
  });
});

describe.skipIf(!win)("delegated-fix scanner (Windows-specific)", () => {
  it("a junction directory is an anomaly and is never descended", async () => {
    const base = await scratch();
    const tree = join(base, "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    const outside = join(base, "outside");
    await mkdir(outside, { recursive: true });
    await writeFile(join(outside, "secret.txt"), "SECRET");
    if (!mklinkJunction(join(tree, "src", "j"), outside)) return;
    const s = await scanFixTree(tree);
    expect(s.files.some((f) => f.path.includes("secret"))).toBe(false);
    expect(s.anomalies).toContainEqual(expect.objectContaining({ path: "src/j", kind: "link" }));
  });
});

describe.skipIf(!linux)("delegated-fix scanner (POSIX-specific)", () => {
  it("two names differing only in case collide (case-sensitive file system)", async () => {
    const tree = join(await scratch(), "tree");
    await mkdir(join(tree, "src"), { recursive: true });
    await writeFile(join(tree, "src", "A.ts"), "1");
    await writeFile(join(tree, "src", "a.ts"), "2");
    const s = await scanFixTree(tree);
    expect(s.anomalies.some((a) => a.kind === "case_collision")).toBe(true);
  });
});

describe.skipIf(!supported)("disposable workspace lifecycle (SHARED CONTRACT)", () => {
  it("creates tree/scratch/control and reports the writable grants", async () => {
    const dataHome = await scratch();
    const primary = await canonicalizePath(await (async () => { const p = join(await scratch(), "repo"); await mkdir(p, { recursive: true }); return p; })());
    const wsId = workspaceIdFor(primary, "T1");
    const ws = await createDisposableWorkspace({ dataHome, runId: "RUN1", workspaceId: wsId, primaryWorktreeRoot: primary });
    expect(existsSync(ws.tree) && existsSync(ws.scratch) && existsSync(ws.control)).toBe(true);
    expect(ws.writableGrants).toEqual([ws.tree, ws.scratch]);
    // control is a sibling of tree, never under it (so a tree-write grant cannot reach the baseline)
    expect(ws.control.startsWith(ws.tree)).toBe(false);
  });

  it("refuses a workspace that overlaps the primary worktree (either direction)", async () => {
    const dataHome = await scratch();
    // primary == an ancestor of the workspace root
    const over = await createDisposableWorkspace({ dataHome, runId: "R", workspaceId: "W", primaryWorktreeRoot: await canonicalizePath(dataHome) }).then(() => null).catch((e) => e);
    expect(isDomainError(over) && over.code).toBe("WORKSPACE_OVERLAPS_PRIMARY");
    // primary == inside the workspace root
    const layout = workspaceLayout(dataHome, "R2", "W2");
    const inside = await createDisposableWorkspace({ dataHome, runId: "R2", workspaceId: "W2", primaryWorktreeRoot: layout.tree }).then(() => null).catch((e) => e);
    expect(isDomainError(inside) && inside.code).toBe("WORKSPACE_OVERLAPS_PRIMARY");
  });

  it("refuses to adopt a workspace directory that already exists as a link", async () => {
    const base = await scratch();
    const dataHome = join(base, "home");
    const outside = join(base, "outside");
    await mkdir(outside, { recursive: true });
    const layout = workspaceLayout(dataHome, "R", "W");
    await mkdir(join(dataHome, "work", "R"), { recursive: true });
    if (!mklinkJunction(layout.root, outside)) return; // link creation unavailable: skip
    const err = await createDisposableWorkspace({ dataHome, runId: "R", workspaceId: "W", primaryWorktreeRoot: await canonicalizePath(join(base, "repo-absent")) }).then(() => null).catch((e) => e);
    expect(isDomainError(err) && err.code).toBe("WORKSPACE_LINK_PRESENT");
  });

  it("destroys a workspace without following a link out of it", async () => {
    const base = await scratch();
    const dataHome = join(base, "home");
    const primary = await canonicalizePath(join(base, "repo-absent"));
    const ws = await createDisposableWorkspace({ dataHome, runId: "R", workspaceId: "W", primaryWorktreeRoot: primary });
    const canaryDir = join(base, "canary");
    await mkdir(canaryDir, { recursive: true });
    writeFileSync(join(canaryDir, "keep.txt"), "KEEP");
    await writeFile(join(ws.tree, "edit.ts"), "x");
    const linked = mklinkJunction(join(ws.tree, "out"), canaryDir);
    const result = await destroyDisposableWorkspace(ws);
    expect(result.failures).toEqual([]);
    expect(existsSync(ws.root)).toBe(false);
    if (linked) expect(await readFile(join(canaryDir, "keep.txt"), "utf8")).toBe("KEEP"); // target survived
  });
});
