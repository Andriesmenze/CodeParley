// Repository inspection and the M1 support matrix (plan §9.7). Unsupported states are
// refused with an explicit error rather than captured with silently different semantics.
//
// | Feature                                   | Behaviour                                         |
// |-------------------------------------------|---------------------------------------------------|
// | bare repository / not a work tree          | NOT_A_GIT_WORKTREE                                |
// | git older than 2.41                        | GIT_TOO_OLD (needed for --attr-source, MR-A)      |
// | sparse checkout / sparse index             | UNSUPPORTED_REPO_STATE                            |
// | core.worktree configured                   | UNSUPPORTED_REPO_STATE (worktree decoupled)       |
// | partial clone on git < 2.45                | UNSUPPORTED_REPO_STATE (no GIT_NO_LAZY_FETCH)     |
// | unmerged index entries                     | UNSUPPORTED_REPO_STATE (checked in capture.ts)    |
// | SHA-256 object format                      | supported; no object id is hard-coded             |
// | shallow clone                              | supported; base_ref without a merge base fails    |
// | partial clone on git >= 2.45               | supported; lazy fetch disabled, missing base blob |
// |                                            | gives BASE_UNAVAILABLE                            |
// | linked worktree / external git dir         | supported (reported)                              |
// | merge/rebase/cherry-pick without conflicts | supported (reported as in progress)               |
// | Linux: work tree on drvfs/9p, FAT, exFAT,  | UNSUPPORTED_REPO_STATE (filesystem_unsupported;   |
// | NTFS, SMB/CIFS or FUSE                     | workspace/fs-types.ts, plan §1.13)                |
// | Linux: the mount table cannot be read      | UNSUPPORTED_REPO_STATE (mount_table_unreadable:   |
// |                                            | bind mounts could not be told from directories)   |

import { existsSync } from "node:fs";
import { DomainError } from "../common/errors.js";
import { canonicalizePath, isContainedIn, PATH_RULES, samePath } from "../workspace/paths.js";
import { fsTypeOf } from "../workspace/fs-types.js";
import { mountPoints } from "../workspace/mounts.js";
import type { AutoCrlf } from "./eol.js";
import type { ObjectFormat } from "./git-object.js";
import { GitQuery, GitQueryFailed } from "./git-query.js";
import { parseConfigZ } from "./git-parse.js";

export const MIN_GIT = { major: 2, minor: 41 } as const;
export const MIN_GIT_PARTIAL_CLONE = { major: 2, minor: 45 } as const;

export interface GitVersion {
  raw: string;
  major: number;
  minor: number;
  patch: number;
}

export interface RepoState {
  root: string;
  gitDir: string;
  commonDir: string;
  objectFormat: ObjectFormat;
  gitVersion: GitVersion;
  headCommit: string | null;
  branch: string | null;
  shallow: boolean;
  partialClone: boolean;
  linkedWorktree: boolean;
  externalGitDir: boolean;
  autocrlf: AutoCrlf;
  /** Filter driver names defined in any config scope (neutralized in every query). */
  configFilterNames: string[];
  inProgress: string[];
}

export function parseGitVersion(out: string): GitVersion {
  const m = /git version (\d+)\.(\d+)\.(\d+)/.exec(out);
  if (!m) throw new DomainError("GIT_NOT_FOUND", `unrecognized git version output: ${out.trim()}`);
  return { raw: out.trim().replace(/^git version /, ""), major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

export function versionAtLeast(v: GitVersion, min: { major: number; minor: number }): boolean {
  return v.major > min.major || (v.major === min.major && v.minor >= min.minor);
}

/** Inspect the repository at `expectedRoot` (canonical) and refuse unsupported states. */
export async function inspectRepository(q: GitQuery, expectedRoot: string): Promise<RepoState> {
  const gitVersion = parseGitVersion(await q.text("version", []));
  if (!versionAtLeast(gitVersion, MIN_GIT)) {
    throw new DomainError("GIT_TOO_OLD", `git ${gitVersion.raw} is too old; capture needs ${MIN_GIT.major}.${MIN_GIT.minor} or later`, {
      details: { version: gitVersion.raw },
    });
  }

  let lines: string[];
  try {
    const out = await q.text("rev-parse", [
      "--is-bare-repository",
      "--is-inside-work-tree",
      "--is-shallow-repository",
      "--show-object-format",
      "--path-format=absolute",
      "--show-toplevel",
      "--absolute-git-dir",
      "--git-common-dir",
    ]);
    lines = out.split(/\r?\n/);
  } catch (e) {
    if (e instanceof GitQueryFailed) {
      throw new DomainError("NOT_A_GIT_WORKTREE", `not a git work tree: ${expectedRoot} (${e.stderr.trim().split(/\r?\n/).pop() ?? ""})`, {
        details: { root: expectedRoot },
      });
    }
    throw e;
  }
  const [bare, inside, shallow, format, top, gitDirRaw, commonRaw] = lines;
  if (bare === "true" || inside !== "true" || !top) {
    throw new DomainError("NOT_A_GIT_WORKTREE", `not a git work tree: ${expectedRoot}`, { details: { root: expectedRoot } });
  }
  if (format !== "sha1" && format !== "sha256") {
    throw new DomainError("UNSUPPORTED_REPO_STATE", `unsupported object format: ${String(format)}`, { details: { reason: "object_format" } });
  }
  const root = await canonicalizePath(top);
  if (!samePath(root, expectedRoot)) {
    throw new DomainError("NOT_A_GIT_WORKTREE", `git reports a different work tree root (${root}) than the resolved repository (${expectedRoot})`, {
      details: { reported: root, expected: expectedRoot },
    });
  }
  if (PATH_RULES === "posix") {
    // The capture guarantees rest on POSIX semantics (plan §1.13): refuse Windows-semantics and FUSE mounts.
    const fsType = await fsTypeOf(root);
    if (!fsType || fsType.status === "refused") {
      throw new DomainError("UNSUPPORTED_REPO_STATE", `the work tree is on a file system capture does not support on Linux: ${fsType ? fsType.name : "unknown (statfs failed)"}`, {
        details: { reasons: [`filesystem_unsupported:${fsType ? fsType.name : "unknown"}`] },
      });
    }
    // Without the mount table a bind mount inside the work tree could not be recognised.
    if (mountPoints() === null) {
      throw new DomainError("UNSUPPORTED_REPO_STATE", "the mount table (/proc/self/mountinfo) cannot be read, so mount points inside the work tree cannot be recognised", {
        details: { reasons: ["mount_table_unreadable"] },
      });
    }
  }
  const gitDir = await canonicalizePath(gitDirRaw ?? "");
  const commonDir = await canonicalizePath(commonRaw ?? "");

  const config = parseConfigZ(
    await q.text(
      "config",
      ["-z", "--get-regexp", "^(core\\.(sparsecheckout|worktree|autocrlf|bare)|index\\.sparse|extensions\\.partialclone|remote\\..*\\.promisor|filter\\..*)$"],
      { okCodes: [0, 1] },
    ),
  );
  const get = (k: string) => config.filter((c) => c.key.toLowerCase() === k).map((c) => c.value ?? "true");
  const isTrue = (v: string | undefined) => v !== undefined && /^(true|yes|on|1)$/i.test(v);

  const reasons: string[] = [];
  if (isTrue(get("core.bare").at(-1))) {
    throw new DomainError("NOT_A_GIT_WORKTREE", "repository is configured as bare (core.bare)", { details: { root } });
  }
  if (isTrue(get("core.sparsecheckout").at(-1))) reasons.push("sparse_checkout");
  if (isTrue(get("index.sparse").at(-1))) reasons.push("sparse_index");
  if (get("core.worktree").length > 0) reasons.push("core_worktree_configured");
  const partialClone = get("extensions.partialclone").length > 0 || config.some((c) => /^remote\..*\.promisor$/i.test(c.key) && isTrue(c.value ?? "true"));
  if (partialClone && !versionAtLeast(gitVersion, MIN_GIT_PARTIAL_CLONE)) reasons.push("partial_clone_requires_git_2_45");
  if (reasons.length > 0) {
    throw new DomainError("UNSUPPORTED_REPO_STATE", `repository state is not supported by capture: ${reasons.join(", ")}`, {
      details: { reasons },
    });
  }

  const autocrlfRaw = (get("core.autocrlf").at(-1) ?? "false").toLowerCase();
  const autocrlf: AutoCrlf = autocrlfRaw === "input" ? "input" : isTrue(autocrlfRaw) ? "true" : "false";

  const configFilterNames = [
    ...new Set(
      config
        .map((c) => /^filter\.(.+)\.[^.]+$/i.exec(c.key)?.[1])
        .filter((n): n is string => typeof n === "string" && n.length > 0),
    ),
  ];

  const headOut = await q.text("rev-parse", ["--verify", "-q", "HEAD^{commit}"], { okCodes: [0, 1] });
  const headCommit = headOut.trim() || null;
  const branchOut = await q.text("symbolic-ref", ["-q", "HEAD"], { okCodes: [0, 1] });
  const branch = branchOut.trim() ? branchOut.trim().replace(/^refs\/heads\//, "") : null;

  const markers = ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"];
  const markerPaths = (
    await q.text("rev-parse", ["--path-format=absolute", ...markers.flatMap((m) => ["--git-path", m])])
  ).split(/\r?\n/);
  const inProgress = markers.filter((_, i) => markerPaths[i] && existsSync(markerPaths[i]!));

  return {
    root,
    gitDir,
    commonDir,
    objectFormat: format,
    gitVersion,
    headCommit,
    branch,
    shallow: shallow === "true",
    partialClone,
    linkedWorktree: !samePath(gitDir, commonDir),
    externalGitDir: !isContainedIn(gitDir, root),
    autocrlf,
    configFilterNames,
    inProgress,
  };
}
